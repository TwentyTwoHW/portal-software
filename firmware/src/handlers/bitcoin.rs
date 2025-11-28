// Portal Hardware Wallet firmware and supporting software libraries
//
// Copyright (C) 2024 Alekos Filini
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use alloc::collections::BTreeMap;
use alloc::rc::Rc;
use alloc::string::ToString;
use alloc::vec::Vec;

use futures::prelude::*;

use tinyminiscript::bitcoin::consensus::Encodable;
use tinyminiscript::bitcoin::{bip32, ecdsa, psbt, taproot};
use tinyminiscript::bitcoin::{Address, Amount, PublicKey, XOnlyPublicKey, TapLeafHash};
use tinyminiscript::parser::keys::Wildcard;
use tinyminiscript::parser::{keys::ExtendedKey as MiniscriptExtendedKey, ParserContext};

use gui::{
    GenericTwoLinePage, LoadingPage, Page, ShowScrollingAddressPage, SummaryPage, TxOutputPage,
    TxSummaryPage,
};
use model::{
    DescriptorVariant, ExtendedKey, MultisigKey, ScriptType, SerializedDerivationPath,
    SetDescriptorVariant, WalletDescriptor,
};
use tinyminiscript::script::{build_address, build_script};

use super::*;
use crate::bitcoin_utils::{xpub_matches, SignerContext};
use crate::{bitcoin_utils::KeychainKind, checkpoint, Error};

type SecpCtx = secp256k1::Secp256k1<secp256k1::All>;

#[derive(Default)]
struct CurrentSignatures {
    partial_sigs: Vec<PublicKey>,
    tap_key_sig: bool,
    tap_script_sigs: Vec<(XOnlyPublicKey, taproot::TapLeafHash)>,
}

impl CurrentSignatures {
    fn from_psbt(psbt: &psbt::Psbt) -> Vec<Self> {
        psbt.inputs
            .iter()
            .map(|i| CurrentSignatures {
                partial_sigs: i.partial_sigs.iter().map(|(k, _)| k.clone()).collect(),
                tap_key_sig: i.tap_key_sig.is_some(),
                tap_script_sigs: i.tap_script_sigs.iter().map(|(k, _)| k.clone()).collect(),
            })
            .collect()
    }

    fn diff(sigs: &Vec<Self>, psbt: psbt::Psbt) -> Vec<SigsDiff> {
        psbt.inputs
            .into_iter()
            .zip(sigs.iter())
            .map(|(i, s)| {
                let mut sigs = SigsDiff::default();

                // We can use the binary search because `partial_sigs` and `tap_script_sigs` are populated from
                // the original PSBT, which in turn stores everything in a BTreeSet, hence when iterating the items
                // will always be sorted.
                for (k, v) in i.partial_sigs {
                    if s.partial_sigs.binary_search(&k).is_err() {
                        sigs.partial_sigs.push((k, v));
                    }
                }
                for (k, v) in i.tap_script_sigs {
                    if s.tap_script_sigs.binary_search(&k).is_err() {
                        sigs.tap_script_sigs.push((k, v));
                    }
                }

                if !s.tap_key_sig {
                    sigs.tap_key_sig = i.tap_key_sig;
                }

                sigs
            })
            .collect()
    }
}

#[derive(Default)]
struct SigsDiff {
    partial_sigs: Vec<(PublicKey, ecdsa::Signature)>,
    tap_key_sig: Option<taproot::Signature>,
    tap_script_sigs: Vec<((XOnlyPublicKey, taproot::TapLeafHash), taproot::Signature)>,
}

impl SigsDiff {
    fn serialize(&self) -> Vec<u8> {
        fn build_pair(
            type_value: u8,
            key: Option<&dyn SerializePsbt>,
            value: &dyn SerializePsbt,
        ) -> psbt::raw::Pair {
            let key = match key {
                Some(k) => k.serialize(),
                None => alloc::vec![],
            };
            psbt::raw::Pair {
                key: psbt::raw::Key { type_value, key },
                value: value.serialize(),
            }
        }

        let mut data = alloc::vec![];

        for (key, val) in &self.partial_sigs {
            data.extend(build_pair(0x02, Some(key), val).serialize());
        }
        if let Some(tap_key_sig) = &self.tap_key_sig {
            data.extend(build_pair(0x13, None, tap_key_sig).serialize());
        }
        for (key, val) in &self.tap_script_sigs {
            data.extend(build_pair(0x14, Some(key), val).serialize());
        }

        data.push(0x00);
        data
    }
}

trait SerializePsbt {
    fn serialize(&self) -> Vec<u8>;
}
impl SerializePsbt for PublicKey {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write_into(&mut buf).expect("vecs don't error");
        buf
    }
}
impl SerializePsbt for ecdsa::Signature {
    fn serialize(&self) -> Vec<u8> {
        self.to_vec()
    }
}
impl SerializePsbt for taproot::Signature {
    fn serialize(&self) -> Vec<u8> {
        self.to_vec()
    }
}
impl SerializePsbt for (XOnlyPublicKey, taproot::TapLeafHash) {
    fn serialize(&self) -> Vec<u8> {
        use model::bitcoin::hashes::Hash;

        let mut buf = Vec::with_capacity(64);
        buf.extend(self.0.serialize());
        buf.extend(self.1.as_byte_array());
        buf
    }
}
impl SerializePsbt for psbt::raw::Key {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        model::bitcoin::VarInt::from(self.key.len() + 1)
            .consensus_encode(&mut buf)
            .expect("in-memory writers don't error");

        self.type_value
            .consensus_encode(&mut buf)
            .expect("in-memory writers don't error");

        for key in &self.key {
            key.consensus_encode(&mut buf)
                .expect("in-memory writers don't error");
        }

        buf
    }
}
impl SerializePsbt for psbt::raw::Pair {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.key.serialize());
        // <value> := <valuelen> <valuedata>
        self.value.consensus_encode(&mut buf).unwrap();
        buf
    }
}

pub async fn handle_sign_request(
    wallet: &mut Rc<PortalWallet>,
    psbt: Vec<u8>,
    peripherals: &mut HandlerPeripherals,
) -> Result<CurrentState, Error> {
    log::info!("handle_sign_request");

    peripherals
        .nfc
        .send(model::Reply::DelayedReply)
        .await
        .unwrap();

    let mut psbt = psbt::Psbt::deserialize(&psbt).unwrap();

    let allow_witness_utxo = wallet.external().descriptor() == Descriptor::Tr;

    let mut total_input_value = bitcoin::Amount::ZERO;
    for (txin, input) in psbt.unsigned_tx.input.iter().zip(psbt.inputs.iter()) {
        if let Some(prev_tx) = &input.non_witness_utxo {
            if prev_tx.compute_txid() == txin.previous_output.txid
                && prev_tx.output.len() > txin.previous_output.vout as usize
            {
                total_input_value += prev_tx.output[txin.previous_output.vout as usize].value;
            } else {
                return Err(Error::Message(model::MessageError::FailedDeserialization));
            }
        } else if allow_witness_utxo && input.witness_utxo.is_some() {
            total_input_value += input.witness_utxo.as_ref().unwrap().value;
        } else {
            return Err(Error::Message(model::MessageError::FailedDeserialization));
        }
    }
    let total_output_value = psbt
        .unsigned_tx
        .output
        .iter()
        .fold(bitcoin::Amount::ZERO, |sum, utxo| sum + utxo.value);
    let fees = total_input_value
        .checked_sub(total_output_value)
        .ok_or(model::MessageError::FailedDeserialization)?
        .to_sat();

    let mut outputs = alloc::vec![];
    for (out, psbt_out) in psbt.unsigned_tx.output.iter().zip(psbt.outputs.iter()) {
        if wallet
            .internal()
            .derive_from_psbt_output(psbt_out, &wallet.secp_ctx())
            .is_none()
        {
            let address = Address::from_script(&out.script_pubkey, wallet.network()).unwrap();
            outputs.push((checkpoint::CborAddress(address), out.value.to_sat()));
        }
    }

    let current_sigs = CurrentSignatures::from_psbt(&psbt);

    for input_index in 0..psbt.inputs.len() {
        use crate::bitcoin_utils::InputSigner;
        wallet.signer().sign_input(&mut psbt, input_index, wallet.context(), &wallet.secp_ctx()).unwrap();
    }

    let diff = CurrentSignatures::diff(&current_sigs, psbt);
    let mut sig_bytes = alloc::vec![];

    for input in &diff {
        sig_bytes.extend(input.serialize());
    }

    let sign_state = checkpoint::SignPsbtState {
        fees,
        outputs,
        sig_bytes: sig_bytes.clone().into(),
    };
    let aux_data = minicbor::to_vec(&sign_state).expect("Encoding works");
    let resumable = checkpoint::Resumable::fresh();
    let checkpoint = checkpoint::Checkpoint::new(
        checkpoint::CheckpointVariant::SignPsbt,
        Some(aux_data),
        Some(resumable),
        &mut peripherals.rng,
    );
    checkpoint.commit(peripherals)?;

    Ok(CurrentState::ConfirmSignPsbt {
        wallet: Rc::clone(wallet),
        outputs: sign_state.outputs,
        fees,
        sig_bytes,
        encryption_key: (*checkpoint.encryption_key).into(),
        resumable,
    })
}

pub async fn handle_confirm_sign_psbt(
    wallet: &mut Rc<PortalWallet>,
    outputs: Vec<(checkpoint::CborAddress, u64)>,
    fees: u64,
    resumable: checkpoint::Resumable,
    sig_bytes: Vec<u8>,
    encryption_key: [u8; 24],
    mut events: impl Stream<Item = Event> + Unpin,
    peripherals: &mut HandlerPeripherals,
) -> Result<CurrentState, Error> {
    log::info!("handle_confirm_sign_psbt");

    peripherals.tsc_enabled.enable();
    let mut checkpoint = checkpoint::Checkpoint::new_with_key(
        checkpoint::CheckpointVariant::SignPsbt,
        None,
        Some(resumable),
        encryption_key.clone(),
    );

    for ((address, value), state, draw) in resumable.wrap_iter(outputs.iter()) {
        let value = Amount::from_sat(*value);

        let mut page = TxOutputPage::new(&address, value);
        page.init_display(&mut peripherals.display)?;
        page.draw_to(&mut peripherals.display)?;
        if draw {
            peripherals.display.flush()?;
        }

        manage_confirmation_loop_with_checkpoint(
            &mut events,
            peripherals,
            &mut page,
            &mut checkpoint,
            state,
        )
        .await?;
    }

    if let Some((state, draw)) = resumable.single_page_with_offset(outputs.len()) {
        let mut page = TxSummaryPage::new(Amount::from_sat(fees));
        page.init_display(&mut peripherals.display)?;
        page.draw_to(&mut peripherals.display)?;
        if draw {
            peripherals.display.flush()?;
        }

        manage_confirmation_loop_with_checkpoint(
            &mut events,
            peripherals,
            &mut page,
            &mut checkpoint,
            state,
        )
        .await?;
    }

    #[rustfmt::skip]
    let mut empty_psbt = alloc::vec![
        0x70, 0x73, 0x62, 0x74, 0xFF, // PSBT magic
            0x01, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, // Empty raw tx
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00,
            0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00 // End global map
    ];
    empty_psbt.extend(sig_bytes);

    peripherals
        .nfc
        .send(model::Reply::SignedPsbt(empty_psbt.into()))
        .await
        .unwrap();

    peripherals.nfc_finished.recv().await.unwrap();

    checkpoint.remove(&peripherals.rtc);

    Ok(CurrentState::Idle {
        wallet: Rc::clone(wallet),
    })
}

pub async fn handle_waiting_for_psbt(
    wallet: &mut Rc<PortalWallet>,
    mut events: impl Stream<Item = Event> + Unpin,
    peripherals: &mut HandlerPeripherals,
) -> Result<CurrentState, Error> {
    let page = LoadingPage::new();
    page.init_display(&mut peripherals.display)?;
    page.draw_to(&mut peripherals.display)?;
    peripherals.display.flush()?;

    peripherals.nfc.send(model::Reply::Ok).await.unwrap();
    peripherals.nfc_finished.recv().await.unwrap();

    let events = only_requests(&mut events);
    pin_mut!(events);

    match events.next().await {
        Some(model::Request::SignPsbt(psbt)) => Ok(CurrentState::SignPsbt {
            psbt: psbt.into(),
            wallet: Rc::clone(wallet),
        }),
        _ => {
            peripherals
                .nfc
                .send(model::Reply::UnexpectedMessage)
                .await
                .unwrap();
            peripherals.nfc_finished.recv().await.unwrap();

            Err(Error::BrokenProtocol)
        }
    }
}

pub async fn handle_display_address_request(
    wallet: &mut Rc<PortalWallet>,
    index: u32,
    resumable: checkpoint::Resumable,
    is_fast_boot: bool,
    mut events: impl Stream<Item = Event> + Unpin,
    peripherals: &mut HandlerPeripherals,
) -> Result<CurrentState, Error> {
    log::info!("handle_display_address_request");

    let mut checkpoint = checkpoint::Checkpoint::new_with_key(
        checkpoint::CheckpointVariant::DisplayAddress(index),
        None,
        Some(resumable),
        checkpoint::Checkpoint::gen_key(&mut peripherals.rng),
    );
    if !is_fast_boot {
        peripherals
            .nfc
            .send(model::Reply::DelayedReply)
            .await
            .unwrap();
    }

    peripherals.tsc_enabled.enable();

    if let Some((state, draw)) = resumable.single_page_with_offset(0) {
        let s = alloc::format!("Display\nAddress #{}?", index);
        let mut page = SummaryPage::new_with_threshold(&s, "HOLD BTN TO CONTINUE", 50);
        page.init_display(&mut peripherals.display)?;
        page.draw_to(&mut peripherals.display)?;
        if draw {
            peripherals.display.flush()?;
        }
        manage_confirmation_loop_with_checkpoint(
            &mut events,
            peripherals,
            &mut page,
            &mut checkpoint,
            state,
        )
        .await?;
    }

    let wallet = Rc::clone(&wallet);
    let mut descriptor = wallet.external();
    descriptor.derive(index).map_err(|_| Error::Wallet)?;
    let addr = build_address(&descriptor, wallet.network()).map_err(|_| "Invalid address").unwrap();
    let addr = addr.to_string();

    if let Some((state, draw)) = resumable.single_page_with_offset(1) {
        let message = alloc::format!("Address #{}", index);
        let mut page = ShowScrollingAddressPage::new(&addr, &message, "HOLD BTN TO EXIT");
        page.init_display(&mut peripherals.display)?;
        page.draw_to(&mut peripherals.display)?;
        if draw {
            peripherals.display.flush()?;
        }
        manage_confirmation_loop_with_checkpoint(
            &mut events,
            peripherals,
            &mut page,
            &mut checkpoint,
            state,
        )
        .await?;
    }

    peripherals
        .nfc
        .send(model::Reply::Address(addr))
        .await
        .unwrap();

    checkpoint.remove(&peripherals.rtc);

    Ok(CurrentState::Idle {
        wallet: Rc::clone(&wallet),
    })
}

pub async fn handle_public_descriptor_request(
    wallet: &mut Rc<PortalWallet>,
    resumable: checkpoint::Resumable,
    is_fast_boot: bool,
    mut events: impl Stream<Item = Event> + Unpin,
    peripherals: &mut HandlerPeripherals,
) -> Result<CurrentState, Error> {
    log::info!("handle_public_descriptor_request");

    let mut checkpoint = checkpoint::Checkpoint::new_with_key(
        checkpoint::CheckpointVariant::PublicDescriptor,
        None,
        Some(resumable),
        checkpoint::Checkpoint::gen_key(&mut peripherals.rng),
    );
    if !is_fast_boot {
        peripherals
            .nfc
            .send(model::Reply::DelayedReply)
            .await
            .unwrap();
    }

    peripherals.tsc_enabled.enable();

    if let Some((state, draw)) = resumable.single_page_with_offset(0) {
        let mut page = SummaryPage::new("Allow watch\nonly access?", "HOLD BTN TO EXPORT DESC");
        page.init_display(&mut peripherals.display)?;
        page.draw_to(&mut peripherals.display)?;
        if draw {
            peripherals.display.flush()?;
        }
        manage_confirmation_loop_with_checkpoint(
            &mut events,
            peripherals,
            &mut page,
            &mut checkpoint,
            state,
        )
        .await?;
    }

    let descriptor = wallet.external.clone();
    let internal_descriptor = wallet.internal.clone();

    peripherals
        .nfc
        .send(model::Reply::Descriptor {
            external: descriptor,
            internal: Some(internal_descriptor),
        })
        .await
        .unwrap();

    checkpoint.remove(&peripherals.rtc);

    Ok(CurrentState::Idle {
        wallet: Rc::clone(wallet),
    })
}

pub async fn handle_get_xpub_request(
    wallet: &mut Rc<PortalWallet>,
    derivation_path: bip32::DerivationPath,
    resumable: checkpoint::Resumable,
    is_fast_boot: bool,
    encryption_key: [u8; 24],
    mut events: impl Stream<Item = Event> + Unpin,
    peripherals: &mut HandlerPeripherals,
) -> Result<CurrentState, Error> {
    log::info!("handle_get_xpub_request");

    let checkpoint_state =
        minicbor::to_vec(SerializedDerivationPath::from(derivation_path.clone()))
            .expect("Serialization workds");
    let mut checkpoint = checkpoint::Checkpoint::new_with_key(
        checkpoint::CheckpointVariant::GetXpub,
        Some(checkpoint_state),
        Some(resumable),
        encryption_key.clone(),
    );
    if !is_fast_boot {
        // Commit fully to flash only once at the start
        checkpoint.commit(peripherals)?;

        peripherals
            .nfc
            .send(model::Reply::DelayedReply)
            .await
            .unwrap();
    }
    peripherals.tsc_enabled.enable();

    if let Some((state, draw)) = resumable.single_page_with_offset(0) {
        let display_path = alloc::format!("m/{}", derivation_path);
        let mut page = GenericTwoLinePage::new(
            "Export public key?",
            &display_path,
            "HOLD BTN TO CONFIRM",
            100,
        );
        page.init_display(&mut peripherals.display)?;
        page.draw_to(&mut peripherals.display)?;
        if draw {
            peripherals.display.flush()?;
        }
        manage_confirmation_loop_with_checkpoint(
            &mut events,
            peripherals,
            &mut page,
            &mut checkpoint,
            state,
        )
        .await?;
    }

    let derived = wallet
        .xprv
        .derive_priv(wallet.secp_ctx(), &derivation_path)
        .map_err(|_| Error::Wallet)?;
    let key = MiniscriptExtendedKey {
        origin: Some((wallet.xprv.fingerprint(wallet.secp_ctx()), derivation_path)),
        key: bip32::Xpub::from_priv(wallet.secp_ctx(), &derived),
        path: Default::default(),
        wildcard: Wildcard::None,
        x_only: false, // Doesn't matter for serializing to string
    };
    let xpub = key.to_string();

    let bsms = model::BsmsRound1::new(
        "1.0",
        "00",
        alloc::format!(
            "Portal {:08X}",
            u32::from_be_bytes(wallet.xprv.fingerprint(wallet.secp_ctx()).to_bytes())
        ),
        &xpub,
        &derived.private_key,
        wallet.secp_ctx(),
    );

    peripherals
        .nfc
        .send(model::Reply::Xpub { xpub, bsms })
        .await
        .unwrap();

    checkpoint.remove(&peripherals.rtc);

    Ok(CurrentState::Idle {
        wallet: Rc::clone(wallet),
    })
}

pub async fn handle_set_descriptor_request(
    wallet: &mut Rc<PortalWallet>,
    variant: SetDescriptorVariant,
    script_type: ScriptType,
    bsms: Option<model::BsmsRound2>,
    resumable: checkpoint::Resumable,
    is_fast_boot: bool,
    encryption_key: [u8; 24],
    mut events: impl Stream<Item = Event> + Unpin,
    peripherals: &mut HandlerPeripherals,
) -> Result<CurrentState, Error> {
    let is_local_key = |key: &ExtendedKey| -> Result<bool, String> {
        let xpub = key.key.as_xpub().map_err(|_| "Invalid xpub".to_string())?;

        // The network kind must match
        if xpub.network != wallet.network().into() {
            return Err("Invalid key network".to_string());
        }

        // The fingerprint should match
        let fingerprint = match key.origin.as_ref() {
            Some((fingerprint, _)) => fingerprint.clone().into(),
            _ => xpub.fingerprint(),
        };
        if fingerprint != wallet.xprv.fingerprint(wallet.secp_ctx()) {
            return Ok(false);
        }

        // The derivation path after the key cannot contain any hardened steps
        if Into::<bip32::DerivationPath>::into(key.path.clone())
            .into_iter()
            .any(|child| child.is_hardened())
        {
            return Ok(false);
        }

        // The xpub provided must match our xprv derived
        let origin_path: bip32::DerivationPath = key
            .origin
            .as_ref()
            .map(|(_, path)| path.clone().into())
            .unwrap_or_default();
        let derived = wallet
            .xprv
            .derive_priv(wallet.secp_ctx(), &origin_path)
            .map_err(|_| "Error deriving key".to_string())?;
        let derived = bip32::Xpub::from_priv(wallet.secp_ctx(), &derived);
        Ok(derived.encode() == xpub.encode())
    };

    log::info!("handle_set_descriptor_request");

    let checkpoint_state = minicbor::to_vec(checkpoint::SetDescriptorState {
        variant: variant.clone(),
        script_type: script_type.clone(),
        bsms: bsms.clone(),
    })
    .expect("Serialization works");

    let checks_result = (|| -> Result<_, String> {
        let variant = match variant {
            SetDescriptorVariant::SingleSig(key) if is_local_key(&key)? => {
                DescriptorVariant::SingleSig(key.full_path().into())
            }
            SetDescriptorVariant::SingleSig(_) => return Err("Local key missing".to_string()),
            SetDescriptorVariant::MultiSig {
                threshold,
                keys,
                is_sorted,
            } => {
                if !is_sorted {
                    return Err("Unsorted multisig descriptors are not supported yet".to_string());
                }

                if threshold > keys.len() {
                    return Err("Invalid threshold for multisig".to_string());
                }

                let keys: Vec<MultisigKey> = keys
                    .into_iter()
                    .map(|key| {
                        if is_local_key(&key)? {
                            Ok(MultisigKey::Local(key.full_path().into()))
                        } else {
                            Ok(MultisigKey::External(key))
                        }
                    })
                    .collect::<Result<_, String>>()?;

                // Make sure our key only appears somewhere
                if !keys.iter().any(|k| matches!(k, MultisigKey::Local(_))) {
                    return Err("Local key missing".into());
                }

                DescriptorVariant::MultiSig {
                    threshold,
                    keys,
                    is_sorted,
                }
            }
        };

        let mut new_config = wallet.config.clone();
        new_config.secret.descriptor = WalletDescriptor {
            variant,
            script_type,
        };

        let new_wallet =
            super::init::make_wallet_from_xprv(wallet.xprv, wallet.network(), new_config)
                .map_err(|_| "Unable to create wallet")?;
        let mut descriptor = new_wallet.external();
        descriptor.derive(0).map_err(|_| Error::Wallet).unwrap();
        let wallet_address = build_address(&descriptor, new_wallet.network()).map_err(|_| "Invalid address").unwrap();

        if let Some(bsms) = bsms {
            if bsms.first_address != wallet_address.to_string() {
                return Err("BSMS address doesn't match".to_string());
            }
        }

        Ok((new_wallet, wallet_address))
    })();

    let (new_wallet, first_address) = match checks_result {
        Ok(v) => v,
        Err(e) => {
            log::warn!("Checks failed: {}", e);

            peripherals.nfc.send(model::Reply::Error(e)).await.unwrap();
            return Ok(CurrentState::Idle {
                wallet: Rc::clone(wallet),
            });
        }
    };

    peripherals.tsc_enabled.enable();
    let mut checkpoint = checkpoint::Checkpoint::new_with_key(
        checkpoint::CheckpointVariant::SetDescriptor,
        Some(checkpoint_state),
        Some(resumable),
        encryption_key.clone(),
    );
    if !is_fast_boot {
        // Commit fully to flash only once at the start
        checkpoint.commit(peripherals)?;

        // Also send the `DelayedReply` message if this is not a resumed state
        peripherals
            .nfc
            .send(model::Reply::DelayedReply)
            .await
            .unwrap();
    }
    let mut page_counter = 0;

    if let Some((state, draw)) = resumable.single_page_with_offset(page_counter) {
        let mut page = GenericTwoLinePage::new(
            "Wallet policy",
            new_wallet.config.secret.descriptor.variant.variant_name(),
            "HOLD BTN FOR NEXT PAGE",
            50,
        );
        page.init_display(&mut peripherals.display)?;
        page.draw_to(&mut peripherals.display)?;
        if draw {
            peripherals.display.flush()?;
        }

        manage_confirmation_loop_with_checkpoint(
            &mut events,
            peripherals,
            &mut page,
            &mut checkpoint,
            state,
        )
        .await?;
    }
    page_counter += 1;

    if let Some((state, draw)) = resumable.single_page_with_offset(page_counter) {
        let mut page = GenericTwoLinePage::new(
            "Address type",
            new_wallet
                .config
                .secret
                .descriptor
                .script_type
                .display_name(),
            "HOLD BTN FOR NEXT PAGE",
            50,
        );
        page.init_display(&mut peripherals.display)?;
        page.draw_to(&mut peripherals.display)?;
        if draw {
            peripherals.display.flush()?;
        }
        manage_confirmation_loop_with_checkpoint(
            &mut events,
            peripherals,
            &mut page,
            &mut checkpoint,
            state,
        )
        .await?;
    }
    page_counter += 1;

    match &new_wallet.config.secret.descriptor.variant {
        DescriptorVariant::SingleSig(path) => {
            let path_display: bip32::DerivationPath = path.clone().into();
            let path_display = alloc::format!("m/{}", path_display);

            if let Some((state, draw)) = resumable.single_page_with_offset(page_counter) {
                let mut page = GenericTwoLinePage::new(
                    "Key derivation",
                    &path_display,
                    "HOLD BTN FOR NEXT PAGE",
                    50,
                );
                page.init_display(&mut peripherals.display)?;
                page.draw_to(&mut peripherals.display)?;
                if draw {
                    peripherals.display.flush()?;
                }
                manage_confirmation_loop_with_checkpoint(
                    &mut events,
                    peripherals,
                    &mut page,
                    &mut checkpoint,
                    state,
                )
                .await?;
            }
            page_counter += 1;
        }
        DescriptorVariant::MultiSig {
            threshold, keys, ..
        } => {
            if let Some((state, draw)) = resumable.single_page_with_offset(page_counter) {
                let threshold_display = alloc::format!("{} of {}", threshold, keys.len());
                let mut page = GenericTwoLinePage::new(
                    "Threshold",
                    &threshold_display,
                    "HOLD BTN FOR NEXT PAGE",
                    50,
                );
                page.init_display(&mut peripherals.display)?;
                page.draw_to(&mut peripherals.display)?;
                if draw {
                    peripherals.display.flush()?;
                }
                manage_confirmation_loop_with_checkpoint(
                    &mut events,
                    peripherals,
                    &mut page,
                    &mut checkpoint,
                    state,
                )
                .await?;
            }
            page_counter += 1;

            for ((i, key), state, draw) in
                resumable.wrap_iter_with_offset(page_counter, keys.iter().enumerate())
            {
                let key_name = alloc::format!("Key #{}", i + 1);

                let second_line = match key {
                    MultisigKey::Local(path) => {
                        alloc::format!(
                            "This device\nm/{}",
                            <SerializedDerivationPath as Into<bip32::DerivationPath>>::into(
                                path.clone()
                            )
                        )
                    }
                    MultisigKey::External(key) => {
                        let fingerprint = key
                            .origin
                            .as_ref()
                            .map(|(f, _)| f.clone().into())
                            .unwrap_or_else(|| key.key.as_xpub().unwrap().fingerprint());
                        alloc::format!(
                            "Key {}\nm/{}",
                            fingerprint,
                            <SerializedDerivationPath as Into<bip32::DerivationPath>>::into(
                                key.full_path()
                            )
                        )
                    }
                };

                let mut page =
                    GenericTwoLinePage::new(&key_name, &second_line, "HOLD BTN FOR NEXT PAGE", 50);
                page.init_display(&mut peripherals.display)?;
                page.draw_to(&mut peripherals.display)?;
                if draw {
                    peripherals.display.flush()?;
                }
                manage_confirmation_loop_with_checkpoint(
                    &mut events,
                    peripherals,
                    &mut page,
                    &mut checkpoint,
                    state,
                )
                .await?;
            }
            page_counter += keys.len();
        }
    }

    log::debug!("First address: {}", first_address);
    if let Some((state, draw)) = resumable.single_page_with_offset(page_counter) {
        let address_str = first_address.to_string();
        let mut page = ShowScrollingAddressPage::new(
            &address_str,
            "Confirm first address",
            "HOLD BTN FOR NEXT PAGE",
        );
        page.init_display(&mut peripherals.display)?;
        page.draw_to(&mut peripherals.display)?;
        if draw {
            peripherals.display.flush()?;
        }
        manage_confirmation_loop_with_checkpoint(
            &mut events,
            peripherals,
            &mut page,
            &mut checkpoint,
            state,
        )
        .await?;
    }
    page_counter += 1;

    if let Some((state, draw)) = resumable.single_page_with_offset(page_counter) {
        let mut page = SummaryPage::new("Save new\nconfiguration?", "HOLD BTN TO APPLY CHANGES");
        page.init_display(&mut peripherals.display)?;
        page.draw_to(&mut peripherals.display)?;
        if draw {
            peripherals.display.flush()?;
        }
        manage_confirmation_loop_with_checkpoint(
            &mut events,
            peripherals,
            &mut page,
            &mut checkpoint,
            state,
        )
        .await?;
    }

    let encrypted_config = new_wallet.config.clone().lock();
    // log::debug!("Saving new config: {:?}", encrypted_config);
    crate::config::write_config(
        &mut peripherals.flash,
        &model::Config::Initialized(encrypted_config),
    )?;
    log::debug!("Config saved!");

    peripherals.nfc.send(model::Reply::Ok).await.unwrap();
    checkpoint.remove(&peripherals.rtc);

    Ok(CurrentState::Idle {
        wallet: Rc::new(new_wallet),
    })
}

type HdKeyPaths = BTreeMap<secp256k1::PublicKey, bip32::KeySource>;
type TapKeyOrigins = BTreeMap<XOnlyPublicKey, (Vec<TapLeafHash>, bip32::KeySource)>;

// Taken from BDK
pub(crate) trait DescriptorMeta<'a> {
    fn derive_from_hd_keypaths<'s>(
        &'a self,
        hd_keypaths: &HdKeyPaths,
        secp: &'s SecpCtx,
    ) -> Option<ParserContext<'a>>;
    fn derive_from_tap_key_origins<'s>(
        &'a self,
        tap_key_origins: &TapKeyOrigins,
        secp: &'s SecpCtx,
    ) -> Option<ParserContext<'a>>;
    fn derive_from_psbt_key_origins<'s>(
        &'a self,
        key_origins: BTreeMap<bip32::Fingerprint, (&bip32::DerivationPath, secp256k1::PublicKey)>,
        secp: &'s SecpCtx,
    ) -> Option<ParserContext<'a>>;
    fn derive_from_psbt_output<'s>(
        &'a self,
        psbt_output: &psbt::Output,
        secp: &'s SecpCtx,
    ) -> Option<ParserContext<'a>>;
}

impl<'a> DescriptorMeta<'a> for ParserContext<'a> {
    fn derive_from_psbt_key_origins<'s>(
        &'a self,
        key_origins: BTreeMap<bip32::Fingerprint, (&bip32::DerivationPath, secp256k1::PublicKey)>,
        secp: &'s SecpCtx,
    ) -> Option<ParserContext<'a>> {
        // Ensure that deriving `xpub` with `path` yields `expected`
        let verify_key = |xpub: &MiniscriptExtendedKey,
                          path: &bip32::DerivationPath,
                          expected: &secp256k1::PublicKey| {
            let derived = xpub
                .key
                .derive_pub(secp, path)
                .expect("The path should never contain hardened derivation steps")
                .public_key;

            derived == *expected
        };

        let mut path_found = None;

        self.iterate_keys(|key| {
            if let Some(xpub) = key.as_extended_key() {
                // Check if the key matches one entry in our `key_origins`. If it does, `matches()` will
                // return the "prefix" that matched, so we remove that prefix from the full path
                // found in `key_origins` and save it in `derive_path`. We expect this to be a derivation
                // path of length 1 if the key is `wildcard` and an empty path otherwise.
                let root_fingerprint = match xpub.origin {
                    Some((fingerprint, _)) => fingerprint,
                    None => xpub.key.fingerprint(),
                };
                let derive_path = key_origins
                    .get_key_value(&root_fingerprint)
                    .and_then(|(fingerprint, (path, expected))| {
                        xpub_matches(&xpub, &(*fingerprint, (*path).clone()))
                            .zip(Some((path, expected)))
                    })
                    .and_then(|(prefix, (full_path, expected))| {
                        let derive_path = full_path
                            .into_iter()
                            .skip(prefix.into_iter().count())
                            .cloned()
                            .collect::<bip32::DerivationPath>();

                        // `derive_path` only contains the replacement index for the wildcard, if present, or
                        // an empty path for fixed descriptors. To verify the key we also need the normal steps
                        // that come before the wildcard, so we take them directly from `xpub` and then append
                        // the final index
                        if verify_key(
                            &xpub,
                            &xpub.path.extend(derive_path.clone()),
                            expected,
                        ) {
                            Some(derive_path)
                        } else {
                            log::debug!(
                                "Key `{}` derived with {} yields an unexpected key",
                                root_fingerprint,
                                derive_path
                            );
                            None
                        }
                    });

                match derive_path {
                    Some(path) if xpub.wildcard != Wildcard::None && path.len() == 1 => {
                        // Ignore hardened wildcards
                        if let bip32::ChildNumber::Normal { index } = path[0] {
                            path_found = Some(index);
                            return;
                        }
                    }
                    Some(path) if xpub.wildcard == Wildcard::None && path.is_empty() => {
                        path_found = Some(0);
                        return;
                    }
                    _ => {}
                }
            }
        });

        path_found.map(|index| {
            let mut copy = self.clone();
            copy.derive(index).unwrap();
            copy
        })
    }

    fn derive_from_hd_keypaths<'s>(
        &'a self,
        hd_keypaths: &HdKeyPaths,
        secp: &'s SecpCtx,
    ) -> Option<ParserContext<'a>> {
        // "Convert" an hd_keypaths map to the format required by `derive_from_psbt_key_origins`
        let key_origins = hd_keypaths
            .iter()
            .map(|(pk, (fingerprint, path))| {
                (
                    *fingerprint,
                    (path, *pk),
                )
            })
            .collect();
        self.derive_from_psbt_key_origins(key_origins, secp)
    }

    fn derive_from_tap_key_origins<'s>(
        &'a self,
        tap_key_origins: &TapKeyOrigins,
        secp: &'s SecpCtx,
    ) -> Option<ParserContext<'a>> {
        // "Convert" a tap_key_origins map to the format required by `derive_from_psbt_key_origins`
        let key_origins = tap_key_origins
            .iter()
            .map(|(pk, (_, (fingerprint, path)))| (*fingerprint, (path, pk.public_key(secp256k1::Parity::Even)))) // TODO: test parity here
            .collect();
        self.derive_from_psbt_key_origins(key_origins, secp)
    }

    fn derive_from_psbt_output<'s>(
        &'a self,
        psbt_output: &psbt::Output,
        secp: &'s SecpCtx,
    ) -> Option<ParserContext<'a>> {
        if let Some(derived) = self.derive_from_hd_keypaths(&psbt_output.bip32_derivation, secp) {
            return Some(derived);
        }
        if let Some(derived) = self.derive_from_tap_key_origins(&psbt_output.tap_key_origins, secp)
        {
            return Some(derived);
        }

        None
    }
}