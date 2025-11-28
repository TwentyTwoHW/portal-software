use core::fmt;
use alloc::vec::Vec;

use bitcoin::secp256k1::Message;
use bitcoin::sighash::{EcdsaSighashType, TapSighash, TapSighashType};
use bitcoin::{ecdsa, psbt, sighash, taproot, bip32};
use bitcoin::{key::TapTweak, key::XOnlyPublicKey, secp256k1};
use bitcoin::{PrivateKey, Psbt, PublicKey};

use tinyminiscript::parser::keys::{Wildcard, ExtendedKey as MiniscriptExtendedKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeychainKind {
    External,
    Internal,
}

pub fn xpub_matches(
    xpub: &MiniscriptExtendedKey,
    keysource: &bip32::KeySource,
) -> Option<bip32::DerivationPath> {
    let (fingerprint, path) = keysource;

    let (compare_fingerprint, compare_path) = match xpub.origin {
        Some((fingerprint, ref path)) => {
            (fingerprint, path.into_iter().chain(&xpub.path).collect())
        }
        None => (
            xpub.key.fingerprint(),
            xpub.path.into_iter().collect::<Vec<_>>(),
        ),
    };

    let path_excluding_wildcard = if xpub.wildcard != Wildcard::None && !path.is_empty() {
        path.into_iter()
            .take(path.as_ref().len() - 1)
            .cloned()
            .collect()
    } else {
        path.clone()
    };

    if &compare_fingerprint == fingerprint
        && compare_path
            .into_iter()
            .eq(path_excluding_wildcard.into_iter())
    {
        Some(path_excluding_wildcard)
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerContext {
    Legacy,
    Segwitv0,
    Tap { is_internal_key: bool },
}

type SecpCtx = bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>;

/// PSBT Input signer
///
/// This trait can be implemented to provide custom signers to the wallet. If the signer supports
/// signing individual inputs, this trait should be implemented and BDK will provide automatically
/// an implementation for [`TransactionSigner`].
pub trait InputSigner {
    /// Sign a single psbt input
    fn sign_input(
        &self,
        psbt: &mut Psbt,
        input_index: usize,
        context: SignerContext,
        secp: &SecpCtx,
    ) -> Result<(), SignerError>;
}

// Taken from BDK
impl InputSigner for PrivateKey {
    fn sign_input(
        &self,
        psbt: &mut Psbt,
        input_index: usize,
        context: SignerContext,
        secp: &SecpCtx,
    ) -> Result<(), SignerError> {
        if input_index >= psbt.inputs.len() || input_index >= psbt.unsigned_tx.input.len() {
            return Err(SignerError::InputIndexOutOfRange);
        }

        if psbt.inputs[input_index].final_script_sig.is_some()
            || psbt.inputs[input_index].final_script_witness.is_some()
        {
            return Ok(());
        }

        let pubkey = PublicKey::from_private_key(secp, self);

        match context {
            SignerContext::Tap { is_internal_key } => {
                let x_only_pubkey = XOnlyPublicKey::from(pubkey.inner);

                if let Some(psbt_internal_key) = psbt.inputs[input_index].tap_internal_key {
                    if is_internal_key
                        && psbt.inputs[input_index].tap_key_sig.is_none()
                        && x_only_pubkey == psbt_internal_key
                    {
                        let (sighash, sighash_type) = compute_tap_sighash(psbt, input_index, None)?;
                        sign_psbt_schnorr(
                            &self.inner,
                            x_only_pubkey,
                            None,
                            &mut psbt.inputs[input_index],
                            sighash,
                            sighash_type,
                            secp,
                        );
                    }
                }

                if let Some((leaf_hashes, _)) =
                    psbt.inputs[input_index].tap_key_origins.get(&x_only_pubkey)
                {
                    let leaf_hashes = leaf_hashes
                        .iter()
                        .filter(|lh| {
                            !psbt.inputs[input_index]
                                    .tap_script_sigs
                                    .contains_key(&(x_only_pubkey, **lh))
                        })
                        .cloned()
                        .collect::<Vec<_>>();
                    for lh in leaf_hashes {
                        let (sighash, sighash_type) =
                            compute_tap_sighash(psbt, input_index, Some(lh))?;
                        sign_psbt_schnorr(
                            &self.inner,
                            x_only_pubkey,
                            Some(lh),
                            &mut psbt.inputs[input_index],
                            sighash,
                            sighash_type,
                            secp,
                        );
                    }
                }
            }
            SignerContext::Segwitv0 | SignerContext::Legacy => {
                if psbt.inputs[input_index].partial_sigs.contains_key(&pubkey) {
                    return Ok(());
                }

                let mut sighasher = sighash::SighashCache::new(psbt.unsigned_tx.clone());
                let (msg, sighash_type) = psbt
                    .sighash_ecdsa(input_index, &mut sighasher)
                    .map_err(SignerError::Psbt)?;

                sign_psbt_ecdsa(
                    &self.inner,
                    pubkey,
                    &mut psbt.inputs[input_index],
                    &msg,
                    sighash_type,
                    secp,
                    true,
                );
            }
        }

        Ok(())
    }
}

#[derive(Default)]
pub struct TransactionSigner {
    priv_keys: Vec<(MiniscriptExtendedKey, bip32::Xpriv)>,
}

impl TransactionSigner {
    pub fn insert(&mut self, key: MiniscriptExtendedKey, xpriv: bip32::Xpriv) {
        self.priv_keys.push((key, xpriv));
    }

    pub fn merge(a: Self, mut b: Self) -> Self {
        let mut priv_keys = a.priv_keys;
        priv_keys.append(&mut b.priv_keys);

        Self {
            priv_keys
        }
    }
}

impl InputSigner for TransactionSigner {
    fn sign_input(
        &self,
        psbt: &mut Psbt,
        input_index: usize,
        context: SignerContext,
        secp: &SecpCtx,
    ) -> Result<(), SignerError> {
        for key_tuple in self.priv_keys.iter() {
            key_tuple.sign_input(psbt, input_index, context, secp)?;
        }

        Ok(())
    }
}

impl InputSigner for (MiniscriptExtendedKey, bip32::Xpriv) {
    fn sign_input(
        &self,
        psbt: &mut Psbt,
        input_index: usize,
        context: SignerContext,
        secp: &SecpCtx,
    ) -> Result<(), SignerError> {
        if input_index >= psbt.inputs.len() {
            return Err(SignerError::InputIndexOutOfRange);
        }

        if psbt.inputs[input_index].final_script_sig.is_some()
            || psbt.inputs[input_index].final_script_witness.is_some()
        {
            return Ok(());
        }

        let (xpub, xpriv) = self;

        let tap_key_origins = psbt.inputs[input_index]
            .tap_key_origins
            .iter()
            .map(|(pk, (_, keysource))| (pk.public_key(secp256k1::Parity::Even), keysource)); // TODO: test parity here
        let (public_key, full_path) = match psbt.inputs[input_index]
            .bip32_derivation
            .iter()
            .map(|(pk, keysource)| (*pk, keysource))
            .chain(tap_key_origins)
            .find_map(|(pk, keysource)| {
                if xpub_matches(&xpub, keysource).is_some() {
                    Some((pk, keysource.1.clone()))
                } else {
                    None
                }
            }) {
            Some((pk, full_path)) => (pk, full_path),
            None => return Ok(()),
        };

        let derived_key = xpriv.derive_priv(secp, &full_path).unwrap();

        let computed_pk = secp256k1::PublicKey::from_secret_key(secp, &derived_key.private_key);
        if public_key != computed_pk {
            Err(SignerError::InvalidKey)
        } else {
            // HD wallets imply compressed keys
            let priv_key = PrivateKey {
                compressed: true,
                network: xpriv.network,
                inner: derived_key.private_key,
            };

            priv_key.sign_input(psbt, input_index, context, secp)
        }
    }
}

fn sign_psbt_ecdsa(
    secret_key: &secp256k1::SecretKey,
    pubkey: PublicKey,
    psbt_input: &mut psbt::Input,
    msg: &Message,
    sighash_type: EcdsaSighashType,
    secp: &SecpCtx,
    allow_grinding: bool,
) {
    let signature = if allow_grinding {
        secp.sign_ecdsa_low_r(msg, secret_key)
    } else {
        secp.sign_ecdsa(msg, secret_key)
    };
    secp.verify_ecdsa(msg, &signature, &pubkey.inner)
        .expect("invalid or corrupted ecdsa signature");

    let final_signature = ecdsa::Signature {
        signature,
        sighash_type,
    };
    psbt_input.partial_sigs.insert(pubkey, final_signature);
}

// Calling this with `leaf_hash` = `None` will sign for key-spend
fn sign_psbt_schnorr(
    secret_key: &secp256k1::SecretKey,
    pubkey: XOnlyPublicKey,
    leaf_hash: Option<taproot::TapLeafHash>,
    psbt_input: &mut psbt::Input,
    sighash: TapSighash,
    sighash_type: TapSighashType,
    secp: &SecpCtx,
) {
    let keypair = secp256k1::Keypair::from_seckey_slice(secp, secret_key.as_ref()).unwrap();
    let keypair = match leaf_hash {
        None => keypair
            .tap_tweak(secp, psbt_input.tap_merkle_root)
            .to_keypair(),
        Some(_) => keypair, // no tweak for script spend
    };

    let msg = &Message::from(sighash);
    let signature = secp.sign_schnorr_no_aux_rand(msg, &keypair);
    secp.verify_schnorr(&signature, msg, &XOnlyPublicKey::from_keypair(&keypair).0)
        .expect("invalid or corrupted schnorr signature");

    let final_signature = taproot::Signature {
        signature,
        sighash_type,
    };

    if let Some(lh) = leaf_hash {
        psbt_input
            .tap_script_sigs
            .insert((pubkey, lh), final_signature);
    } else {
        psbt_input.tap_key_sig = Some(final_signature);
    }
}

/// Computes the taproot sighash.
fn compute_tap_sighash(
    psbt: &Psbt,
    input_index: usize,
    extra: Option<taproot::TapLeafHash>,
) -> Result<(sighash::TapSighash, TapSighashType), SignerError> {
    if input_index >= psbt.inputs.len() || input_index >= psbt.unsigned_tx.input.len() {
        return Err(SignerError::InputIndexOutOfRange);
    }

    let psbt_input = &psbt.inputs[input_index];

    let sighash_type = psbt_input
        .sighash_type
        .unwrap_or_else(|| TapSighashType::Default.into())
        .taproot_hash_ty()
        .map_err(|_| SignerError::InvalidSighash)?;
    let witness_utxos = (psbt.inputs.iter().zip(psbt.unsigned_tx.input.iter()))
        .map(|(psbt_input, txin)| {
            psbt_input.witness_utxo.clone().or_else(|| {
                if let Some(non_witness_utxo) = &psbt_input.non_witness_utxo {
                    if non_witness_utxo.compute_txid() != txin.previous_output.txid {
                        return None;
                    }
                    non_witness_utxo.output.get(txin.previous_output.vout as usize).cloned()
                } else {
                    None
                }
            })
        })
        .collect::<alloc::vec::Vec<_>>();
    let mut all_witness_utxos = alloc::vec![];

    let mut cache = sighash::SighashCache::new(&psbt.unsigned_tx);
    let is_anyone_can_pay = psbt::PsbtSighashType::from(sighash_type).to_u32() & 0x80 != 0;
    let prevouts = if is_anyone_can_pay {
        sighash::Prevouts::One(
            input_index,
            witness_utxos[input_index]
                .as_ref()
                .ok_or(SignerError::MissingWitnessUtxo)?,
        )
    } else if witness_utxos.iter().all(Option::is_some) {
        all_witness_utxos.extend(witness_utxos.iter().filter_map(|x| x.as_ref()));
        sighash::Prevouts::All(&all_witness_utxos)
    } else {
        return Err(SignerError::MissingWitnessUtxo);
    };

    // Assume no OP_CODESEPARATOR
    let extra = extra.map(|leaf_hash| (leaf_hash, 0xFFFFFFFF));

    Ok((
        cache
            .taproot_signature_hash(input_index, &prevouts, None, extra, sighash_type)
            .map_err(SignerError::SighashTaproot)?,
        sighash_type,
    ))
}


/// Signing error
#[derive(Debug)]
pub enum SignerError {
    /// The private key is missing for the required public key
    MissingKey,
    /// The private key in use has the right fingerprint but derives differently than expected
    InvalidKey,
    /// The user canceled the operation
    UserCanceled,
    /// Input index is out of range
    InputIndexOutOfRange,
    /// The `non_witness_utxo` field of the transaction is required to sign this input
    MissingNonWitnessUtxo,
    /// The `non_witness_utxo` specified is invalid
    InvalidNonWitnessUtxo,
    /// The `witness_utxo` field of the transaction is required to sign this input
    MissingWitnessUtxo,
    /// The `witness_script` field of the transaction is required to sign this input
    MissingWitnessScript,
    /// The fingerprint and derivation path are missing from the psbt input
    MissingHdKeypath,
    /// The psbt contains a non-`SIGHASH_ALL` sighash in one of its input and the user hasn't
    /// explicitly allowed them
    ///
    /// To enable signing transactions with non-standard sighashes set
    /// [`SignOptions::allow_all_sighashes`] to `true`.
    NonStandardSighash,
    /// Invalid SIGHASH for the signing context in use
    InvalidSighash,
    /// Error while computing the hash to sign a Taproot input.
    SighashTaproot(sighash::TaprootError),
    /// PSBT sign error.
    Psbt(psbt::SignError),
    /// To be used only by external libraries implementing [`InputSigner`] or
    /// [`TransactionSigner`], so that they can return their own custom errors, without having to
    /// modify [`SignerError`] in BDK.
    External(alloc::string::String),
}

impl fmt::Display for SignerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingKey => write!(f, "Missing private key"),
            Self::InvalidKey => write!(f, "The private key in use has the right fingerprint but derives differently than expected"),
            Self::UserCanceled => write!(f, "The user canceled the operation"),
            Self::InputIndexOutOfRange => write!(f, "Input index out of range"),
            Self::MissingNonWitnessUtxo => write!(f, "Missing non-witness UTXO"),
            Self::InvalidNonWitnessUtxo => write!(f, "Invalid non-witness UTXO"),
            Self::MissingWitnessUtxo => write!(f, "Missing witness UTXO"),
            Self::MissingWitnessScript => write!(f, "Missing witness script"),
            Self::MissingHdKeypath => write!(f, "Missing fingerprint and derivation path"),
            Self::NonStandardSighash => write!(f, "The psbt contains a non standard sighash"),
            Self::InvalidSighash => write!(f, "Invalid SIGHASH for the signing context in use"),
            Self::SighashTaproot(err) => write!(f, "Error while computing the hash to sign a Taproot input: {err}"),
            Self::Psbt(err) => write!(f, "Error computing the sighash: {err}"),
            Self::External(err) => write!(f, "{err}"),
        }
    }
}