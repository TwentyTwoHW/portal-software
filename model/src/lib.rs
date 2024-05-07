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

#![cfg_attr(feature = "stm32", no_std)]

extern crate alloc;

use core::ops::Deref;

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub use minicbor::bytes::{ByteArray, ByteVec};
use minicbor::{Decode, Encode};

use noise_protocol::{Cipher, CipherState};

use aes_gcm::aead::AeadMut;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

use modular_bitfield::prelude::*;

pub use bitcoin;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::util::bip32;

pub const MAX_FRAGMENT_LEN: usize = 64;

pub const DEFAULT_PASSWORD_ITERATIONS: usize = 1024;

pub const HARDENED_FLAG: u32 = 0x80000000;

#[cfg(feature = "emulator")]
pub mod emulator;
pub mod encryption;
pub mod reg;
pub mod write_buffer;

#[derive(Debug)]
pub struct MessageFragment {
    buf: [u8; MAX_FRAGMENT_LEN],
}

impl MessageFragment {
    pub fn empty() -> Self {
        MessageFragment {
            buf: [0; MAX_FRAGMENT_LEN],
        }
    }

    pub fn new(slice: &[u8], is_last: bool) -> Self {
        assert!(slice.len() <= MAX_FRAGMENT_LEN - 2);
        // TODO: assert if !is_last => slice.len() == MAX_FRAGMENT_LEN ??

        let mut fragment = MessageFragment::empty();
        fragment.buf[0] = if is_last { 0x01 } else { 0x00 };
        fragment.buf[1] = slice.len() as u8;
        (&mut fragment.buf[2..slice.len() + 2]).copy_from_slice(slice);

        fragment
    }

    pub fn new_failed_decryption() -> Self {
        let mut fragment = MessageFragment::empty();
        fragment.buf[0] = FragmentFlags::new()
            .with_eof(Eof::LastFragment)
            .with_decryption(DecryptionStatus::Failed)
            .bytes[0];

        fragment
    }

    pub fn is_eof(&self) -> bool {
        self.flags().eof() == Eof::LastFragment
    }

    pub fn flags(&self) -> FragmentFlags {
        FragmentFlags::from_bytes([self.buf[0]])
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.buf[1] as usize
    }

    pub(crate) fn get_filled_data(&self) -> &[u8] {
        &self.buf[..self.len() + 2]
    }

    #[cfg(feature = "emulator")]
    pub fn get_raw_buf(&self) -> &[u8] {
        &self.buf
    }
}

impl AsRef<[u8]> for MessageFragment {
    fn as_ref(&self) -> &[u8] {
        &self.buf[2..2 + self.len()]
    }
}

impl From<&[u8]> for MessageFragment {
    fn from(slice: &[u8]) -> Self {
        assert!(slice.len() <= MAX_FRAGMENT_LEN);

        let mut buf = [0; MAX_FRAGMENT_LEN];
        (&mut buf[..slice.len()]).copy_from_slice(slice);
        MessageFragment { buf }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, BitfieldSpecifier)]
#[bits = 1]
pub enum Eof {
    MoreFragments,
    LastFragment,
}
#[derive(Debug, PartialEq, Eq, Clone, Copy, BitfieldSpecifier)]
#[bits = 1]
pub enum DecryptionStatus {
    Ok,
    Failed,
}
#[bitfield]
pub struct FragmentFlags {
    pub eof: Eof,
    pub decryption: DecryptionStatus,

    #[allow(dead_code)]
    reserved: B6,
}

#[derive(Debug)]
pub struct Message {
    buf: Vec<u8>,
    finished: bool,
}

impl Message {
    pub fn empty() -> Self {
        Message {
            buf: Vec::new(),
            finished: false,
        }
    }

    pub fn from_slice(data: &[u8]) -> Self {
        let buf = data.iter().copied().collect();
        Message {
            buf,
            finished: true,
        }
    }

    pub fn new_serialize<S, C>(obj: &S, cipher: &mut CipherState<C>) -> Result<Self, MessageError>
    where
        S: Encode<()>,
        C: Cipher,
    {
        let buf = minicbor::to_vec(&obj).expect("always succeed");
        let buf = cipher.encrypt_vec(&buf);
        Ok(Message {
            buf,
            finished: true,
        })
    }

    pub fn is_finished(&self) -> bool {
        self.finished
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn push_fragment(&mut self, fragment: MessageFragment) -> Result<bool, MessageError> {
        if self.finished {
            return Err(MessageError::MessageAlreadyFinished);
        }
        if fragment.flags().decryption() == DecryptionStatus::Failed {
            return Err(MessageError::CardCouldntDecrypt);
        }
        self.finished = fragment.is_eof();

        self.buf.extend_from_slice(&fragment.as_ref());

        Ok(self.finished)
    }

    pub fn deserialize<'d, T, C>(
        &self,
        decrypt_buf: &'d mut Vec<u8>,
        cipher: &mut CipherState<C>,
    ) -> Result<T, MessageError>
    where
        T: minicbor::Decode<'d, ()>,
        C: Cipher,
    {
        if !self.finished {
            return Err(MessageError::IncompleteMessage);
        }
        decrypt_buf.resize(self.buf.len().saturating_sub(16), 0x00);
        cipher
            .decrypt(&self.buf, decrypt_buf)
            .map_err(|_| MessageError::DecryptionFailed)?;

        Ok(minicbor::decode(decrypt_buf)?)
    }

    fn iter_chunks<'s>(&'s self, chunk_size: usize) -> impl Iterator<Item = (&'s [u8], bool)> + 's {
        let last_chunk = self.buf.len() / chunk_size;
        self.buf
            .chunks(chunk_size)
            .enumerate()
            .map(move |(i, chunk)| (chunk, i == last_chunk))
    }

    pub fn get_fragments(&self) -> Vec<MessageFragment> {
        self.iter_chunks(MAX_FRAGMENT_LEN - 2)
            .map(|(chunk, eof)| {
                let mut buf = [0; MAX_FRAGMENT_LEN];
                buf[0] = if eof { 0x01 } else { 0x00 };
                buf[1] = chunk.len() as u8;
                (&mut buf[2..2 + chunk.len()]).copy_from_slice(chunk);

                MessageFragment { buf }
            })
            .collect()
    }

    pub fn data(&self) -> &[u8] {
        &self.buf
    }
}

impl AsRef<[u8]> for Message {
    fn as_ref(&self) -> &[u8] {
        &self.buf
    }
}

#[derive(Debug, Encode, Decode, Clone)]
pub struct Entropy {
    #[cbor(n(0))]
    pub bytes: ByteVec,
}

#[derive(Debug, Encode, Decode, Clone)]
pub struct SerializedXprv {
    #[cbor(n(0))]
    pub bytes: [u8; 78],
}
impl SerializedXprv {
    pub fn as_xprv(&self) -> Result<bip32::ExtendedPrivKey, bitcoin::util::bip32::Error> {
        bip32::ExtendedPrivKey::decode(&self.bytes)
    }
}
impl From<bip32::ExtendedPrivKey> for SerializedXprv {
    fn from(value: bip32::ExtendedPrivKey) -> Self {
        SerializedXprv {
            bytes: value.encode(),
        }
    }
}

#[derive(Debug, Encode, Decode)]
pub enum Config {
    #[cbor(n(0))]
    Initialized(#[cbor(n(0))] InitializedConfig),
    #[cbor(n(1))]
    Unverified(#[cbor(n(0))] UnverifiedConfig),
}

#[derive(Debug, Encode, Decode)]
pub struct UnverifiedConfig {
    #[cbor(n(0))]
    pub entropy: Entropy,
    #[cbor(with = "cbor_bitcoin_network")]
    #[cbor(n(1))]
    pub network: bitcoin::Network,
    #[cbor(n(2))]
    pub pair_code: Option<String>,
    #[cbor(n(3))]
    pub descriptor: WalletDescriptor,
}

#[derive(Debug, Clone, Encode, Decode)]
#[cfg_attr(feature = "emulator", derive(serde::Serialize, serde::Deserialize))]
pub struct WalletDescriptor {
    #[cbor(n(0))]
    pub variant: DescriptorVariant,
    #[cbor(n(1))]
    pub script_type: ScriptType,
}

impl WalletDescriptor {
    pub fn make_bip84(network: bitcoin::Network) -> Self {
        let network = match network {
            bitcoin::Network::Bitcoin => 0,
            _ => 1,
        };

        WalletDescriptor {
            variant: DescriptorVariant::SingleSig(SerializedDerivationPath {
                value: alloc::vec::Vec::from([
                    HARDENED_FLAG | 84,
                    HARDENED_FLAG | network,
                    HARDENED_FLAG | 0,
                ]),
            }),
            script_type: ScriptType::NativeSegwit,
        }
    }
}

#[derive(Debug, Clone, Encode, Decode)]
#[cfg_attr(feature = "emulator", derive(serde::Serialize, serde::Deserialize))]
pub enum ScriptType {
    #[cbor(n(0))]
    Legacy,
    #[cbor(n(1))]
    WrappedSegwit,
    #[cbor(n(2))]
    NativeSegwit,
}

impl ScriptType {
    pub fn display_name(&self) -> &'static str {
        match self {
            ScriptType::Legacy => "Legacy",
            ScriptType::WrappedSegwit => "Wrapped Segwit",
            ScriptType::NativeSegwit => "Native Segwit",
        }
    }
}

#[derive(Debug, Clone, Encode, Decode)]
#[cfg_attr(feature = "emulator", derive(serde::Serialize, serde::Deserialize))]
pub struct ExtendedKey {
    #[cbor(n(0))]
    pub origin: Option<(SerializedFingerprint, SerializedDerivationPath)>,
    #[cbor(n(1))]
    pub key: SerializedXpub,
    #[cbor(n(2))]
    pub path: SerializedDerivationPath,
}

impl ExtendedKey {
    pub fn full_path(&self) -> SerializedDerivationPath {
        let mut value = self
            .origin
            .as_ref()
            .map(|(_, path)| path.value.clone())
            .unwrap_or_default();
        value.extend_from_slice(&self.path.value);

        SerializedDerivationPath { value }
    }
}

#[derive(Debug, Clone, Encode, Decode)]
#[cfg_attr(feature = "emulator", derive(serde::Serialize, serde::Deserialize))]
pub enum MultisigKey {
    #[cbor(n(0))]
    Local(#[cbor(n(0))] SerializedDerivationPath),
    #[cbor(n(1))]
    External(#[cbor(n(0))] ExtendedKey),
}

#[derive(Debug, Clone, Encode, Decode)]
#[cfg_attr(feature = "emulator", derive(serde::Serialize, serde::Deserialize))]
pub struct SerializedFingerprint {
    #[cbor(n(0))]
    pub value: [u8; 4],
}
impl Into<bip32::Fingerprint> for SerializedFingerprint {
    fn into(self) -> bip32::Fingerprint {
        bip32::Fingerprint::from(self.value.as_ref())
    }
}
impl From<bip32::Fingerprint> for SerializedFingerprint {
    fn from(value: bip32::Fingerprint) -> Self {
        SerializedFingerprint {
            value: value.into_bytes(),
        }
    }
}

#[derive(Debug, Clone, Encode, Decode)]
#[cfg_attr(feature = "emulator", derive(serde::Serialize, serde::Deserialize))]
pub struct SerializedXpub {
    #[cbor(n(0))]
    #[cfg_attr(
        feature = "emulator",
        serde(
            serialize_with = "serde_bytevec::serialize",
            deserialize_with = "serde_bytevec::deserialize_array"
        )
    )]
    pub value: Box<ByteArray<78>>,
}
impl SerializedXpub {
    pub fn as_xpub(&self) -> Result<bip32::ExtendedPubKey, bitcoin::util::bip32::Error> {
        bip32::ExtendedPubKey::decode(self.value.deref().as_ref())
    }
}
impl From<bip32::ExtendedPubKey> for SerializedXpub {
    fn from(value: bip32::ExtendedPubKey) -> Self {
        SerializedXpub {
            value: Box::new(value.encode().into()),
        }
    }
}

#[derive(Debug, Clone, Encode, Decode)]
#[cfg_attr(feature = "emulator", derive(serde::Serialize, serde::Deserialize))]
pub struct SerializedDerivationPath {
    #[cbor(n(0))]
    pub value: Vec<u32>,
}
impl Into<bip32::DerivationPath> for SerializedDerivationPath {
    fn into(self) -> bip32::DerivationPath {
        bip32::DerivationPath::from_iter(
            self.value.into_iter().map(|v| bip32::ChildNumber::from(v)),
        )
    }
}
impl From<bip32::DerivationPath> for SerializedDerivationPath {
    fn from(value: bip32::DerivationPath) -> Self {
        SerializedDerivationPath {
            value: value.into_iter().map(|&v| v.into()).collect(),
        }
    }
}

#[derive(Debug, Clone, Encode, Decode)]
#[cfg_attr(feature = "emulator", derive(serde::Serialize, serde::Deserialize))]
pub enum DescriptorVariant {
    #[cbor(n(0))]
    SingleSig(#[cbor(n(0))] SerializedDerivationPath),
    #[cbor(n(1))]
    MultiSig {
        #[cbor(n(0))]
        threshold: usize,
        #[cbor(n(1))]
        keys: Vec<MultisigKey>,
        #[cbor(n(2))]
        is_sorted: bool,
    },
}

impl DescriptorVariant {
    pub fn variant_name(&self) -> &'static str {
        match self {
            DescriptorVariant::SingleSig(_) => "Single-sig",
            DescriptorVariant::MultiSig {
                is_sorted: true, ..
            } => "Sorted multi-sig",
            DescriptorVariant::MultiSig {
                is_sorted: false, ..
            } => "Multi-sig",
        }
    }
}

#[derive(Debug, Clone, Encode, Decode)]
#[cfg_attr(feature = "emulator", derive(serde::Serialize, serde::Deserialize))]
pub enum SetDescriptorVariant {
    #[cbor(n(0))]
    SingleSig(#[cbor(n(0))] ExtendedKey),
    #[cbor(n(1))]
    MultiSig {
        #[cbor(n(0))]
        threshold: usize,
        #[cbor(n(1))]
        keys: Vec<ExtendedKey>,
        #[cbor(n(2))]
        is_sorted: bool,
    },
}

impl UnverifiedConfig {
    pub fn upgrade(
        self,
        salt: [u8; 8],
    ) -> (InitializedConfig, UnlockedConfig, bip32::ExtendedPrivKey) {
        let mnemonic = bip39::Mnemonic::from_entropy(&self.entropy.bytes).expect("Valid entropy");
        let xprv =
            bip32::ExtendedPrivKey::new_master(self.network, &mnemonic.to_seed_normalized(""))
                .expect("Valid entropy");

        let unlocked = UnlockedConfig::new(
            self.entropy,
            xprv.into(),
            self.descriptor,
            self.network,
            self.pair_code.as_deref(),
            salt,
        );

        (unlocked.clone().lock(), unlocked, xprv)
    }
}

#[derive(Debug, Encode, Decode, Clone)]
pub struct InitializedConfig {
    #[cbor(n(0))]
    pub secret: MaybeEncrypted,
    #[cbor(with = "cbor_bitcoin_network")]
    #[cbor(n(1))]
    pub network: bitcoin::Network,
    #[cbor(n(2))]
    pub pair_code: Password,
}

impl InitializedConfig {
    pub fn new(
        mnemonic: Entropy,
        cached_xprv: SerializedXprv,
        descriptor: WalletDescriptor,
        network: bitcoin::Network,
        password: Option<&str>,
        salt: [u8; 8],
    ) -> Self {
        UnlockedConfig::new(mnemonic, cached_xprv, descriptor, network, password, salt).lock()
    }

    pub fn unlock(self, password: &str) -> Result<UnlockedConfig, ()> {
        if !self.pair_code.check(password) {
            return Err(());
        }

        let (secret, encryption_key) = match self.secret {
            MaybeEncrypted::Unencrypted(inner) => (inner, None),
            MaybeEncrypted::Encrypted { data, nonce } => {
                let encryption_key = EncryptionKey::new(password, nonce);
                (
                    encryption_key.decrypt(data.deref().as_ref())?,
                    Some(encryption_key),
                )
            }
        };

        Ok(UnlockedConfig {
            secret,
            network: self.network,
            password: self.pair_code,
            encryption_key,
        })
    }
}

#[derive(Clone)]
pub struct UnlockedConfig {
    pub secret: SecretData,
    pub network: bitcoin::Network,
    pub password: Password,
    encryption_key: Option<EncryptionKey>,
}

impl UnlockedConfig {
    pub fn new(
        mnemonic: Entropy,
        cached_xprv: SerializedXprv,
        descriptor: WalletDescriptor,
        network: bitcoin::Network,
        password: Option<&str>,
        salt: [u8; 8],
    ) -> Self {
        UnlockedConfig {
            secret: SecretData {
                mnemonic,
                cached_xprv,
                descriptor,
            },
            network,
            password: password.map(|p| Password::new(p, salt)).unwrap_or_default(),
            encryption_key: password.map(|p| EncryptionKey::new(p, 0)),
        }
    }

    pub fn from_secret_data_unencrypted(secret: SecretData, network: bitcoin::Network) -> Self {
        UnlockedConfig {
            secret,
            network,
            password: Default::default(),
            encryption_key: None,
        }
    }

    pub fn lock(mut self) -> InitializedConfig {
        let secret = match self.encryption_key {
            None => MaybeEncrypted::Unencrypted(self.secret),
            Some(ref mut encryption_key) => {
                let data = minicbor::to_vec(self.secret).expect("Always serializable");
                encryption_key
                    .encrypt(&data)
                    .map(|(data, nonce)| MaybeEncrypted::Encrypted {
                        data: data.into(),
                        nonce,
                    })
                    .expect("Always ok")
            }
        };

        InitializedConfig {
            secret,
            network: self.network,
            pair_code: self.password,
        }
    }
}

mod cbor_bitcoin_network {
    use core::str::FromStr;

    use minicbor::{Decoder, Encoder};

    pub(super) fn decode<'b, Ctx>(
        d: &mut Decoder<'b>,
        _ctx: &mut Ctx,
    ) -> Result<bitcoin::Network, minicbor::decode::Error> {
        let s = d.decode::<&'b str>()?;
        bitcoin::Network::from_str(s)
            .map_err(|_| minicbor::decode::Error::message("Invalid bitcoin network").into())
    }

    pub(super) fn encode<Ctx, W: minicbor::encode::Write>(
        v: &bitcoin::Network,
        e: &mut Encoder<W>,
        _ctx: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        #[cfg(feature = "stm32")]
        use alloc::string::ToString;

        e.encode(v.to_string())?;
        Ok(())
    }
}

#[derive(Debug, Default, Encode, Decode, Clone)]
pub struct Password {
    #[cbor(n(0))]
    pub hash: [u8; 32],
    #[cbor(n(1))]
    pub salt: [u8; 8],
    #[cbor(n(2))]
    pub iterations: usize,
}

impl Password {
    pub fn new(password: &str, salt: [u8; 8]) -> Self {
        let mut hash = sha256::HashEngine::default();
        hash.input(password.as_bytes());
        hash.input(&salt);

        let mut hash = sha256::Hash::from_engine(hash);
        for _ in 0..DEFAULT_PASSWORD_ITERATIONS {
            hash = sha256::Hash::hash(&hash);
        }

        Password {
            hash: hash.into_inner(),
            salt,
            iterations: DEFAULT_PASSWORD_ITERATIONS,
        }
    }

    pub fn check(&self, password: &str) -> bool {
        let check_password = Password::new(password, self.salt.clone());
        check_password.hash == self.hash
    }
}

#[derive(Debug, Clone)]
pub struct EncryptionKey {
    key: [u8; 32],
    nonce: u32,
}

impl EncryptionKey {
    pub fn new(password: &str, nonce: u32) -> Self {
        let mut hash = sha256::Hash::hash(password.as_bytes());
        for _ in 0..DEFAULT_PASSWORD_ITERATIONS {
            hash = sha256::Hash::hash(hash.as_ref());
        }

        EncryptionKey {
            key: hash.into_inner(),
            nonce,
        }
    }

    fn get_cipher(&self) -> impl aes_gcm::AeadCore + aes_gcm::aead::AeadMut {
        Aes256Gcm::new_from_slice(&self.key).expect("Correct length")
    }

    fn get_nonce<T: aes_gcm::aes::cipher::ArrayLength<u8>>(&self) -> aes_gcm::Nonce<T> {
        let mut nonce_bytes = [0; 12];
        nonce_bytes[..4].copy_from_slice(&self.nonce.to_be_bytes());
        Nonce::clone_from_slice(&nonce_bytes)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<SecretData, ()> {
        let nonce = self.get_nonce();

        self.get_cipher()
            .decrypt(&nonce, data)
            .map_err(|_| ())
            .and_then(|data| minicbor::decode::<SecretData>(&data).map_err(|_| ()))
            .map(|config| config)
    }

    pub fn encrypt(&mut self, data: &[u8]) -> Result<(Vec<u8>, u32), ()> {
        self.nonce += 1;
        let nonce = self.get_nonce();

        self.get_cipher()
            .encrypt(&nonce, data)
            .map_err(|_| ())
            .map(|data| (data, self.nonce))
    }
}

#[derive(Debug, Encode, Decode, Clone)]
pub struct SecretData {
    #[cbor(n(0))]
    pub mnemonic: Entropy,
    #[cbor(n(1))]
    pub cached_xprv: SerializedXprv,
    #[cbor(n(2))]
    pub descriptor: WalletDescriptor,
}

#[derive(Debug, Encode, Decode, Clone)]
pub enum MaybeEncrypted {
    #[cbor(n(0))]
    Encrypted {
        #[cbor(n(0))]
        data: ByteVec,
        #[cbor(n(1))]
        nonce: u32,
    },
    #[cbor(n(1))]
    Unencrypted(#[cbor(n(0))] SecretData),
}

#[derive(Clone, Debug, Encode, Decode)]
#[cfg_attr(feature = "emulator", derive(serde::Serialize, serde::Deserialize))]
pub struct DeviceInfo {
    #[cbor(n(0))]
    pub initialized: InitializationStatus,
    #[cbor(n(1))]
    pub firmware_version: Option<String>,
}

#[derive(Clone, Debug, Encode, Decode)]
#[cfg_attr(feature = "emulator", derive(serde::Serialize, serde::Deserialize))]
pub enum InitializationStatus {
    #[cbor(n(0))]
    Uninitialized,
    #[cbor(n(1))]
    Initialized {
        #[cbor(n(0))]
        unlocked: bool,
        #[cbor(with = "cbor_bitcoin_network")]
        #[cbor(n(1))]
        network: bitcoin::Network,
    },
    #[cbor(n(2))]
    Unverified {
        #[cbor(n(0))]
        with_code: bool,
        #[cbor(with = "cbor_bitcoin_network")]
        #[cbor(n(1))]
        network: bitcoin::Network,
    },
}

impl DeviceInfo {
    pub fn new_locked_uninitialized(version: &'static str) -> Self {
        DeviceInfo {
            initialized: InitializationStatus::Uninitialized,
            firmware_version: Some(version.to_string()),
        }
    }

    pub fn new_locked_initialized(network: bitcoin::Network, version: &'static str) -> Self {
        DeviceInfo {
            initialized: InitializationStatus::Initialized {
                unlocked: false,
                network,
            },
            firmware_version: Some(version.to_string()),
        }
    }

    pub fn new_unverified_config(
        network: bitcoin::Network,
        with_code: bool,
        version: &'static str,
    ) -> Self {
        DeviceInfo {
            initialized: InitializationStatus::Unverified { with_code, network },
            firmware_version: Some(version.to_string()),
        }
    }

    pub fn new_unlocked_initialized(network: bitcoin::Network, version: &'static str) -> Self {
        DeviceInfo {
            initialized: InitializationStatus::Initialized {
                unlocked: true,
                network,
            },
            firmware_version: Some(version.to_string()),
        }
    }
}

#[derive(Copy, Clone, Debug, Encode, Decode)]
#[cfg_attr(feature = "emulator", derive(serde::Serialize, serde::Deserialize))]
pub enum NumWordsMnemonic {
    #[cbor(n(0))]
    Words12,
    #[cbor(n(1))]
    Words24,
}

#[derive(Copy, Clone, Debug, Encode, Decode)]
#[cfg_attr(feature = "emulator", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum FwVariant {
    #[cbor(n(0))]
    VANILLA,
}

#[derive(Clone, Debug, Encode, Decode)]
#[cfg_attr(feature = "emulator", derive(serde::Serialize, serde::Deserialize))]
pub struct FwUpdateHeader {
    #[cbor(n(0))]
    pub variant: FwVariant,
    #[cfg_attr(
        feature = "emulator",
        serde(
            serialize_with = "serde_bytevec::serialize",
            deserialize_with = "serde_bytevec::deserialize_array"
        )
    )]
    #[cbor(n(1))]
    pub signature: Box<ByteArray<{ bitcoin::secp256k1::constants::SCHNORR_SIGNATURE_SIZE }>>,
    #[cbor(n(2))]
    pub size: usize,
    #[cfg_attr(
        feature = "emulator",
        serde(
            serialize_with = "serde_bytevec::serialize",
            deserialize_with = "serde_bytevec::deserialize_array"
        )
    )]
    #[cbor(n(3))]
    pub first_page_midstate: Box<ByteArray<32>>,
}

#[derive(Debug, Clone, Encode, Decode)]
#[cfg_attr(feature = "emulator", derive(serde::Serialize, serde::Deserialize))]
pub enum Request {
    #[cbor(n(0))]
    GetInfo,
    #[cbor(n(1))]
    GenerateMnemonic {
        #[cbor(n(0))]
        num_words: NumWordsMnemonic,
        #[cbor(with = "cbor_bitcoin_network")]
        #[cbor(n(1))]
        network: bitcoin::Network,
        #[cbor(n(2))]
        password: Option<String>,
    },
    #[cbor(n(2))]
    SetMnemonic {
        #[cbor(n(0))]
        mnemonic: String,
        #[cbor(with = "cbor_bitcoin_network")]
        #[cbor(n(1))]
        network: bitcoin::Network,
        #[cbor(n(2))]
        password: Option<String>,
    },
    #[cbor(n(3))]
    UpdateFirmware,
    #[cbor(n(4))]
    BeginSignPsbt,
    #[cbor(n(5))]
    #[cfg_attr(feature = "emulator", serde(with = "serde_bytevec"))]
    SignPsbt(#[cbor(n(0))] ByteVec),
    #[cbor(n(6))]
    DisplayAddress(#[cbor(n(0))] u32),
    #[cbor(n(7))]
    PublicDescriptor,
    #[cbor(n(8))]
    BeginFwUpdate(#[cbor(n(0))] FwUpdateHeader),
    #[cbor(n(9))]
    #[cfg_attr(
        feature = "emulator",
        serde(
            serialize_with = "serde_bytevec::serialize",
            deserialize_with = "serde_bytevec::deserialize_array"
        )
    )]
    FwUpdateChunk(#[cbor(n(0))] Box<ByteArray<2048>>),
    #[cbor(n(10))]
    #[cfg_attr(
        feature = "emulator",
        serde(
            serialize_with = "serde_bytevec::serialize",
            deserialize_with = "serde_bytevec::deserialize_array"
        )
    )]
    CompleteFwUpdate(#[cbor(n(0))] Box<ByteArray<2048>>),
    #[cbor(n(11))]
    Unlock {
        #[cbor(n(0))]
        password: String,
    },
    #[cbor(n(12))]
    Ping,
    #[cbor(n(13))]
    Resume,
    #[cbor(n(14))]
    GetXpub(#[cbor(n(0))] SerializedDerivationPath),
    #[cbor(n(15))]
    SetDescriptor {
        #[cbor(n(0))]
        variant: SetDescriptorVariant,
        #[cbor(n(1))]
        script_type: ScriptType,
        #[cbor(n(2))]
        bsms: Option<BsmsRound2>,
    },
}

#[derive(Clone, Debug, Encode, Decode)]
#[cfg_attr(feature = "emulator", derive(serde::Serialize, serde::Deserialize))]
pub enum Reply {
    #[cbor(n(0))]
    Info(#[cbor(n(0))] DeviceInfo),
    #[cbor(n(1))]
    Ok,
    #[cbor(n(2))]
    Error(#[cbor(n(0))] String),
    #[cbor(n(3))]
    Address(#[cbor(n(0))] String),
    #[cbor(n(4))]
    Descriptor {
        #[cbor(n(0))]
        external: String,
        #[cbor(n(1))]
        internal: Option<String>,
    },
    #[cbor(n(5))]
    UnexpectedMessage,
    #[cbor(n(6))]
    Busy,
    #[cbor(n(7))]
    #[cfg_attr(feature = "emulator", serde(with = "serde_bytevec"))]
    SignedPsbt(#[cbor(n(0))] ByteVec),
    #[cbor(n(8))]
    WrongPassword,
    #[cbor(n(9))]
    DelayedReply,
    #[cbor(n(10))]
    Pong,
    #[cbor(n(11))]
    NextPage(#[cbor(n(0))] usize),
    #[cbor(n(12))]
    Locked,
    #[cbor(n(13))]
    Unverified,
    #[cbor(n(14))]
    Xpub {
        #[cbor(n(0))]
        xpub: String,
        #[cbor(n(1))]
        bsms: BsmsRound1,
    },
}

#[derive(Clone, Debug, Encode, Decode)]
#[cfg_attr(feature = "emulator", derive(serde::Serialize, serde::Deserialize))]
pub struct BsmsRound1 {
    #[cbor(n(0))]
    pub version: String,
    #[cbor(n(1))]
    pub token: String,
    #[cbor(n(2))]
    pub key_name: String,
    #[cbor(n(3))]
    #[cfg_attr(
        feature = "emulator",
        serde(
            serialize_with = "serde_bytevec::serialize",
            deserialize_with = "serde_bytevec::deserialize_array"
        )
    )]
    pub signature: Box<ByteArray<65>>,
}

impl BsmsRound1 {
    pub fn new(
        version: &str,
        token: &str,
        key_name: String,
        xpub: &str,
        private_key: &bitcoin::secp256k1::SecretKey,
        ctx: &bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>,
    ) -> Self {
        let message = alloc::format!("BSMS {}\n{}\n{}\n{}", version, token, xpub, key_name);
        let message = bitcoin::secp256k1::Message::from_slice(
            bitcoin::util::misc::signed_msg_hash(&message).as_inner(),
        )
        .expect("Valid data length");

        let signature = ctx.sign_ecdsa_recoverable(&message, &private_key);
        let signature = bitcoin::util::misc::MessageSignature::new(signature, true);
        let signature = signature.serialize();

        BsmsRound1 {
            version: version.into(),
            token: token.into(),
            key_name,
            signature: Box::new(signature.into()),
        }
    }
}

#[derive(Clone, Debug, Encode, Decode)]
#[cfg_attr(feature = "emulator", derive(serde::Serialize, serde::Deserialize))]
pub struct BsmsRound2 {
    #[cbor(n(0))]
    pub first_address: String,
}

#[cfg(feature = "emulator")]
mod serde_bytevec {
    use super::*;

    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub(crate) fn serialize<
        X: AsRef<[u8]> + ?Sized,
        Y: core::ops::Deref<Target = X>,
        T: core::ops::Deref<Target = Y>,
        S,
    >(
        bytes: &T,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let vec = bytes.deref().as_ref().to_vec();
        Serialize::serialize(&vec, serializer)
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<minicbor::bytes::ByteVec, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec: alloc::vec::Vec<u8> = Deserialize::deserialize(deserializer)?;
        Ok(vec.into())
    }
    pub(crate) fn deserialize_array<'de, D, const N: usize>(
        deserializer: D,
    ) -> Result<Box<minicbor::bytes::ByteArray<N>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec: alloc::vec::Vec<u8> = Deserialize::deserialize(deserializer)?;
        let vec_len = vec.len();
        let arr: [u8; N] = vec.try_into().map_err(|_| {
            D::Error::invalid_length(
                vec_len,
                &alloc::format!("an array of length {}", N).as_str(),
            )
        })?;
        Ok(Box::new(arr.into()))
    }
}

#[derive(Clone, Debug, Encode, Decode)]
pub enum ModelError {
    #[cbor(n(0))]
    AuthenticationFailed,
    #[cbor(n(1))]
    InvalidCurrency,
    #[cbor(n(2))]
    InvalidRequest,
    #[cbor(n(3))]
    InternalError,
}

#[derive(Debug, Clone)]
pub enum MessageError {
    MessageTooLong,
    MessageAlreadyFinished,
    IncompleteMessage,
    PartialDeserialization,
    FailedDeserialization,
    DecryptionFailed,
    CardCouldntDecrypt,
    // FailedSerialization(ciborium::ser::Error<()>),
}

impl From<minicbor::decode::Error> for MessageError {
    fn from(_: minicbor::decode::Error) -> Self {
        MessageError::FailedDeserialization
    }
}
// impl From<ciborium::ser::Error<()>> for MessageError {
//     fn from(e: ciborium::ser::Error<()>) -> Self {
//         MessageError::FailedSerialization(e)
//     }
// }
impl core::fmt::Display for MessageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_fmt(core::format_args!("{:?}", self))
    }
}
#[cfg(not(feature = "stm32"))]
impl std::error::Error for MessageError {}

#[cfg(all(test, not(feature = "stm32")))]
mod tests {
    use super::*;

    // Model tests

    // Message tests

    #[test]
    fn test_fragment_finished() {
        let f = MessageFragment::from([0x00u8, 0x05].as_slice());
        assert!(!f.is_eof());

        let f = MessageFragment::from([0x01u8, 0x05].as_slice());
        assert!(f.is_eof());
    }

    #[test]
    fn test_append_fragments() {
        let frag1 = MessageFragment::from([0x00u8, 0x01, 0x05].as_slice());
        let frag2 = MessageFragment::from([0x01u8, 0x01, 0x10].as_slice());

        let mut message = Message::empty();
        message.push_fragment(frag1).unwrap();
        assert!(!message.is_finished());

        message.push_fragment(frag2).unwrap();
        assert!(message.is_finished());

        assert_eq!(message.as_ref(), &[0x05, 0x10]);

        // Message already finished
        let frag3 = MessageFragment::from([0x01u8, 0x10].as_slice());
        assert!(message.push_fragment(frag3).is_err());
    }
}
