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

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::rc::Rc;
use alloc::string::ToString;
use alloc::vec::Vec;

use futures::prelude::*;

use bdk::bitcoin::util::{bip32, psbt, taproot};
use bdk::bitcoin::{Address, Amount, PublicKey, TxOut, XOnlyPublicKey};
use bdk::descriptor::{
    DerivedDescriptor, DescriptorError, DescriptorXKey, ExtendedDescriptor, TapKeyOrigins, Wildcard,
};
use bdk::keys::SinglePubKey;
use bdk::miniscript::descriptor::{DescriptorType, InnerXKey};
use bdk::miniscript::{DescriptorPublicKey, ForEachKey};
use bdk::HdKeyPaths;

use gui::{LoadingPage, Page, SigningTxPage, SummaryPage, TxOutputPage, TxSummaryPage};

use super::*;
use crate::Error;

type SecpCtx = secp256k1::Secp256k1<secp256k1::All>;

#[derive(Default)]
struct CurrentSignatures {
    partial_sigs: BTreeSet<PublicKey>,
    tap_key_sig: bool,
    tap_script_sigs: BTreeSet<(XOnlyPublicKey, taproot::TapLeafHash)>,
}

impl CurrentSignatures {
    fn from_psbt(psbt: &psbt::PartiallySignedTransaction) -> Vec<Self> {
        psbt.inputs
            .iter()
            .map(|i| CurrentSignatures {
                partial_sigs: i.partial_sigs.iter().map(|(k, _)| k.clone()).collect(),
                tap_key_sig: i.tap_key_sig.is_some(),
                tap_script_sigs: i.tap_script_sigs.iter().map(|(k, _)| k.clone()).collect(),
            })
            .collect()
    }

    fn diff(sigs: &Vec<Self>, psbt: psbt::PartiallySignedTransaction) -> Vec<psbt::Input> {
        psbt.inputs
            .into_iter()
            .zip(sigs.iter())
            .map(|(mut i, s)| {
                i.partial_sigs.retain(|k, _| !s.partial_sigs.contains(k));
                i.tap_script_sigs
                    .retain(|k, _| !s.tap_script_sigs.contains(k));

                let mut input = psbt::Input::default();
                input.partial_sigs = i.partial_sigs;
                input.tap_script_sigs = i.tap_script_sigs;
                input.tap_key_sig = match (i.tap_key_sig, s.tap_key_sig) {
                    (Some(sig), false) => Some(sig),
                    _ => None,
                };

                input
            })
            .collect()
    }
}

pub async fn handle_sign_request(
    wallet: &mut Rc<bdk::Wallet>,
    psbt: &[u8],
    mut events: impl Stream<Item = Event> + Unpin,
    peripherals: &mut HandlerPeripherals,
) -> Result<CurrentState, Error> {
    log::info!("handle_sign_request");

    peripherals
        .nfc
        .send(model::Reply::DelayedReply)
        .await
        .unwrap();

    let mut psbt: psbt::PartiallySignedTransaction =
        bdk::bitcoin::consensus::encode::deserialize(&psbt).unwrap();

    let allow_witness_utxo = matches!(
        wallet
            .public_descriptor(bdk::KeychainKind::External)
            .unwrap(),
        bdk::miniscript::Descriptor::Tr(_)
    );

    let prev_utxos = psbt
        .unsigned_tx
        .input
        .iter()
        .zip(psbt.inputs.iter())
        .map(|(txin, input)| {
            if let Some(prev_tx) = &input.non_witness_utxo {
                if prev_tx.txid() == txin.previous_output.txid
                    && prev_tx.output.len() > txin.previous_output.vout as usize
                {
                    Ok(&prev_tx.output[txin.previous_output.vout as usize])
                } else {
                    Err("Invalid non_witness_utxo")
                }
            } else if allow_witness_utxo && input.witness_utxo.is_some() {
                Ok(input.witness_utxo.as_ref().unwrap())
            } else {
                Err("Missing NonWitnessUtxo")
            }
        })
        .collect::<Result<alloc::vec::Vec<_>, _>>()
        .unwrap();
    let total_input_value = prev_utxos.iter().fold(0, |sum, utxo| sum + utxo.value);
    let total_output_value = psbt
        .unsigned_tx
        .output
        .iter()
        .fold(0, |sum, utxo| sum + utxo.value);
    let fees = total_input_value.checked_sub(total_output_value).unwrap();

    peripherals.tsc_enabled.enable();

    let secp = secp256k1::Secp256k1::new();

    for (out, psbt_out) in psbt.unsigned_tx.output.iter().zip(psbt.outputs.iter()) {
        if wallet
            .get_descriptor_for_keychain(bdk::KeychainKind::Internal)
            .derive_from_psbt_output(psbt_out, Some(out), &secp)
            .is_some()
        {
            // Hide our change outputs
            continue;
        }

        let address = Address::from_script(&out.script_pubkey, wallet.network()).unwrap();
        let value = Amount::from_sat(out.value);

        let mut page = TxOutputPage::new(&address, value);
        page.init_display(&mut peripherals.display)?;
        page.draw_to(&mut peripherals.display)?;
        peripherals.display.flush()?;

        manage_confirmation_loop(&mut events, peripherals, &mut page).await?;
    }

    let mut page = TxSummaryPage::new(Amount::from_sat(fees));
    page.init_display(&mut peripherals.display)?;
    page.draw_to(&mut peripherals.display)?;
    peripherals.display.flush()?;

    manage_confirmation_loop(&mut events, peripherals, &mut page).await?;

    let page = SigningTxPage::new();
    page.init_display(&mut peripherals.display)?;
    page.draw_to(&mut peripherals.display)?;
    peripherals.display.flush()?;

    let current_sigs = CurrentSignatures::from_psbt(&psbt);

    wallet
        .sign(
            &mut psbt,
            bdk::SignOptions {
                try_finalize: false,
                ..Default::default()
            },
        )
        .unwrap();

    let diff = CurrentSignatures::diff(&current_sigs, psbt);
    let empty_tx = bdk::bitcoin::Transaction {
        input: alloc::vec![bdk::bitcoin::TxIn::default(); diff.len()],
        output: alloc::vec![],
        lock_time: bdk::bitcoin::PackedLockTime::ZERO,
        version: 0,
    };
    let mut empty_psbt =
        psbt::PartiallySignedTransaction::from_unsigned_tx(empty_tx).expect("Always succeed");
    empty_psbt.inputs = diff;

    let psbt = bdk::bitcoin::consensus::encode::serialize(&empty_psbt);

    peripherals
        .nfc
        .send(model::Reply::SignedPsbt(psbt.into()))
        .await
        .unwrap();

    peripherals.nfc_finished.recv().await.unwrap();

    Ok(CurrentState::Idle {
        wallet: Rc::clone(wallet),
    })
}

pub async fn handle_waiting_for_psbt(
    wallet: &mut Rc<bdk::Wallet>,
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
    wallet: &mut Rc<bdk::Wallet>,
    index: u32,
    mut events: impl Stream<Item = Event> + Unpin,
    peripherals: &mut HandlerPeripherals,
) -> Result<CurrentState, Error> {
    log::info!("handle_display_address_request");

    peripherals
        .nfc
        .send(model::Reply::DelayedReply)
        .await
        .unwrap();

    peripherals.tsc_enabled.enable();

    let s = alloc::format!("Display\nAddress #{}?", index);
    let mut page = SummaryPage::new(&s, "HOLD BTN TO DISPLAY ADDR");
    page.init_display(&mut peripherals.display)?;
    page.draw_to(&mut peripherals.display)?;
    peripherals.display.flush()?;

    manage_confirmation_loop(&mut events, peripherals, &mut page).await?;

    let addr = Rc::get_mut(wallet)
        .unwrap()
        .get_address(bdk::wallet::AddressIndex::Peek(index));

    peripherals
        .nfc
        .send(model::Reply::Address(addr.to_string()))
        .await
        .unwrap();

    Ok(CurrentState::Idle {
        wallet: Rc::clone(wallet),
    })
}

pub async fn handle_public_descriptor_request(
    wallet: &mut Rc<bdk::Wallet>,
    mut events: impl Stream<Item = Event> + Unpin,
    peripherals: &mut HandlerPeripherals,
) -> Result<CurrentState, Error> {
    log::info!("handle_public_descriptor_request");

    peripherals
        .nfc
        .send(model::Reply::DelayedReply)
        .await
        .unwrap();

    peripherals.tsc_enabled.enable();

    let mut page = SummaryPage::new("Export\nDescriptor?", "HOLD BTN TO EXPORT DESC");
    page.init_display(&mut peripherals.display)?;
    page.draw_to(&mut peripherals.display)?;
    peripherals.display.flush()?;

    manage_confirmation_loop(&mut events, peripherals, &mut page).await?;

    let descriptor = wallet
        .public_descriptor(bdk::KeychainKind::External)
        .unwrap();
    let descriptor = descriptor.to_string();

    let internal_descriptor = wallet
        .public_descriptor(bdk::KeychainKind::Internal)
        .unwrap();
    let internal_descriptor = internal_descriptor.to_string();

    peripherals
        .nfc
        .send(model::Reply::Descriptor {
            external: descriptor,
            internal: Some(internal_descriptor),
        })
        .await
        .unwrap();

    Ok(CurrentState::Idle {
        wallet: Rc::clone(wallet),
    })
}

// Taken from BDK
pub(crate) trait DescriptorMeta {
    fn is_witness(&self) -> bool;
    fn is_taproot(&self) -> bool;
    fn get_extended_keys(
        &self,
    ) -> Result<Vec<DescriptorXKey<bip32::ExtendedPubKey>>, DescriptorError>;
    fn derive_from_hd_keypaths<'s>(
        &self,
        hd_keypaths: &HdKeyPaths,
        secp: &'s SecpCtx,
    ) -> Option<DerivedDescriptor>;
    fn derive_from_tap_key_origins<'s>(
        &self,
        tap_key_origins: &TapKeyOrigins,
        secp: &'s SecpCtx,
    ) -> Option<DerivedDescriptor>;
    fn derive_from_psbt_key_origins<'s>(
        &self,
        key_origins: BTreeMap<bip32::Fingerprint, (&bip32::DerivationPath, SinglePubKey)>,
        secp: &'s SecpCtx,
    ) -> Option<DerivedDescriptor>;
    fn derive_from_psbt_output<'s>(
        &self,
        psbt_output: &psbt::Output,
        utxo: Option<&'s TxOut>,
        secp: &'s SecpCtx,
    ) -> Option<DerivedDescriptor>;
}

impl DescriptorMeta for ExtendedDescriptor {
    fn is_witness(&self) -> bool {
        matches!(
            self.desc_type(),
            DescriptorType::Wpkh
                | DescriptorType::ShWpkh
                | DescriptorType::Wsh
                | DescriptorType::ShWsh
                | DescriptorType::ShWshSortedMulti
                | DescriptorType::WshSortedMulti
        )
    }

    fn is_taproot(&self) -> bool {
        self.desc_type() == DescriptorType::Tr
    }

    fn get_extended_keys(
        &self,
    ) -> Result<Vec<DescriptorXKey<bip32::ExtendedPubKey>>, DescriptorError> {
        let mut answer = Vec::new();

        self.for_each_key(|pk| {
            if let DescriptorPublicKey::XPub(xpub) = pk {
                answer.push(xpub.clone());
            }

            true
        });

        Ok(answer)
    }

    fn derive_from_psbt_key_origins<'s>(
        &self,
        key_origins: BTreeMap<bip32::Fingerprint, (&bip32::DerivationPath, SinglePubKey)>,
        secp: &'s SecpCtx,
    ) -> Option<DerivedDescriptor> {
        // Ensure that deriving `xpub` with `path` yields `expected`
        let verify_key = |xpub: &DescriptorXKey<bip32::ExtendedPubKey>,
                          path: &bip32::DerivationPath,
                          expected: &SinglePubKey| {
            let derived = xpub
                .xkey
                .derive_pub(secp, path)
                .expect("The path should never contain hardened derivation steps")
                .public_key;

            match expected {
                SinglePubKey::FullKey(pk) if &PublicKey::new(derived) == pk => true,
                SinglePubKey::XOnly(pk) if &XOnlyPublicKey::from(derived) == pk => true,
                _ => false,
            }
        };

        let mut path_found = None;

        // using `for_any_key` should make this stop as soon as we return `true`
        self.for_any_key(|key| {
            if let DescriptorPublicKey::XPub(xpub) = key {
                // Check if the key matches one entry in our `key_origins`. If it does, `matches()` will
                // return the "prefix" that matched, so we remove that prefix from the full path
                // found in `key_origins` and save it in `derive_path`. We expect this to be a derivation
                // path of length 1 if the key is `wildcard` and an empty path otherwise.
                let root_fingerprint = match xpub.origin {
                    Some((fingerprint, _)) => fingerprint,
                    None => xpub.xkey.xkey_fingerprint(secp),
                };
                let derive_path = key_origins
                    .get_key_value(&root_fingerprint)
                    .and_then(|(fingerprint, (path, expected))| {
                        xpub.matches(&(*fingerprint, (*path).clone()), secp)
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
                            xpub,
                            &xpub.derivation_path.extend(derive_path.clone()),
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
                            return true;
                        }
                    }
                    Some(path) if xpub.wildcard == Wildcard::None && path.is_empty() => {
                        path_found = Some(0);
                        return true;
                    }
                    _ => {}
                }
            }

            false
        });

        path_found.map(|path| self.at_derivation_index(path))
    }

    fn derive_from_hd_keypaths<'s>(
        &self,
        hd_keypaths: &HdKeyPaths,
        secp: &'s SecpCtx,
    ) -> Option<DerivedDescriptor> {
        // "Convert" an hd_keypaths map to the format required by `derive_from_psbt_key_origins`
        let key_origins = hd_keypaths
            .iter()
            .map(|(pk, (fingerprint, path))| {
                (
                    *fingerprint,
                    (path, SinglePubKey::FullKey(PublicKey::new(*pk))),
                )
            })
            .collect();
        self.derive_from_psbt_key_origins(key_origins, secp)
    }

    fn derive_from_tap_key_origins<'s>(
        &self,
        tap_key_origins: &TapKeyOrigins,
        secp: &'s SecpCtx,
    ) -> Option<DerivedDescriptor> {
        // "Convert" a tap_key_origins map to the format required by `derive_from_psbt_key_origins`
        let key_origins = tap_key_origins
            .iter()
            .map(|(pk, (_, (fingerprint, path)))| (*fingerprint, (path, SinglePubKey::XOnly(*pk))))
            .collect();
        self.derive_from_psbt_key_origins(key_origins, secp)
    }

    fn derive_from_psbt_output<'s>(
        &self,
        psbt_output: &psbt::Output,
        utxo: Option<&'s TxOut>,
        secp: &'s SecpCtx,
    ) -> Option<DerivedDescriptor> {
        if let Some(derived) = self.derive_from_hd_keypaths(&psbt_output.bip32_derivation, secp) {
            return Some(derived);
        }
        if let Some(derived) = self.derive_from_tap_key_origins(&psbt_output.tap_key_origins, secp)
        {
            return Some(derived);
        }
        if self.has_wildcard() {
            // We can't try to bruteforce the derivation index, exit here
            return None;
        }

        let descriptor = self.at_derivation_index(0);
        match descriptor.desc_type() {
            // TODO: add pk() here
            DescriptorType::Pkh
            | DescriptorType::Wpkh
            | DescriptorType::ShWpkh
            | DescriptorType::Tr
                if utxo.is_some()
                    && descriptor.script_pubkey() == utxo.as_ref().unwrap().script_pubkey =>
            {
                Some(descriptor)
            }
            DescriptorType::Bare | DescriptorType::Sh | DescriptorType::ShSortedMulti
                if psbt_output.redeem_script.is_some()
                    && &descriptor.explicit_script().unwrap()
                        == psbt_output.redeem_script.as_ref().unwrap() =>
            {
                Some(descriptor)
            }
            DescriptorType::Wsh
            | DescriptorType::ShWsh
            | DescriptorType::ShWshSortedMulti
            | DescriptorType::WshSortedMulti
                if psbt_output.witness_script.is_some()
                    && &descriptor.explicit_script().unwrap()
                        == psbt_output.witness_script.as_ref().unwrap() =>
            {
                Some(descriptor)
            }
            _ => None,
        }
    }
}
