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

use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use async_std::channel;
use async_std::sync::Mutex;

use futures::prelude::*;
use futures::stream::Peekable;

use inner_logic::FutureError;

use miniscript::TranslatePk;

use model::bitcoin::bip32;
use model::{
    BsmsRound2, ExtendedKey, InitializationStatus, NumWordsMnemonic, Reply, Request, ScriptType,
    SetDescriptorVariant,
};

mod inner_logic;
mod psbt;

pub const MAX_READ_FRAME: usize = 16;

const MAX_RETRIES: usize = 5;

const SRAM1_BASE: u32 = 0x2000_0000;
const SRAM1_SIZE: u32 = 96 * 1024;
const SRAM1_END: u32 = SRAM1_BASE + SRAM1_SIZE;

const SRAM2_BASE: u32 = 0x1000_0000;
const SRAM2_SIZE: u32 = 32 * 1024;
const SRAM2_END: u32 = SRAM2_BASE + SRAM2_SIZE;

const FLASH_BASE: u32 = 0x0800_0000;
const FLASH_SIZE: u32 = 510 * 2048;
const FLASH_END: u32 = FLASH_BASE + FLASH_SIZE;

#[cfg(feature = "bindings")]
pub use model::bitcoin::{
    bip32::{DerivationPath, Fingerprint},
    Address, Network,
};

#[cfg_attr(feature = "bindings", derive(uniffi::Object))]
pub struct PortalSdk {
    manager: Mutex<Option<InnerManager>>,
    requests: RequestChannels,
    nfc: NfcChannels,
    stop: channel::Sender<()>,

    #[cfg(feature = "debug")]
    debug_channels: Debug,
}

#[cfg(feature = "debug")]
#[cfg_attr(feature = "bindings", derive(uniffi::Object))]
#[derive(Debug)]
pub enum DebugMessage {
    RawOut(Vec<u8>),
    Out(Request),
    In(Reply),
}

macro_rules! send_with_retry {
    ($channels:expr, $req:expr, $( $match:tt )*) => ({
        let mut i = 0;
        let mut send_ping = false;

        loop {
            if i > MAX_RETRIES {
                break Err(SdkError::CommunicationError)
            }
            let req = if !send_ping {
                $req
            } else {
                send_ping = false;
                model::Request::Ping
            };

            // Hold the lock until we have a reply
            let lock = $channels.o.lock().await;
            // Flush potential leftover replies
            while let Ok(_) = $channels.i.try_recv() {}

            // Send the request
            lock.send(req).await?;

            // Wait for the reply
            match $channels.i.recv().await? {
                $( $match )*,

                Ok(Reply::Pong) | Ok(Reply::DelayedReply) => {
                    log::trace!("Got delayed reply, sending ping");

                    // Start pinging and eventually we will get our reply
                    // TODO: count attempts for timeout
                    send_ping = true;
                },
                Ok(Reply::Busy) => {
                    async_std::task::sleep(Duration::from_millis(50)).await;
                    continue;
                },
                Ok(Reply::Error(cause)) => {
                    break Err(SdkError::DeviceError { cause })
                }
                Ok(Reply::Unverified) => {
                    break Err(SdkError::DeviceError { cause: "Unverified mnemonic".into() })
                }
                Ok(Reply::Locked) => {
                    break Err(SdkError::Locked)
                }
                Ok(Reply::UnexpectedMessage) => {
                    break Err(SdkError::UnexpectedMessage)
                }
                _ => {
                    i += 1; // Only increment when there's some kind of failure
                },
            }
        }
    })
}

#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
pub struct NfcOut {
    pub msg_index: u64,
    pub data: Vec<u8>,
}

// Required because we always have `uniffi::constructor` on `PortalSdk::new()`
#[cfg(not(feature = "bindings"))]
use dummy_uniffi as uniffi;

#[cfg_attr(feature = "bindings", uniffi::export)]
impl PortalSdk {
    #[uniffi::constructor]
    pub fn new(use_fast_ops: bool) -> Arc<Self> {
        let (manager, requests, nfc, stop, _debug_channels) = InnerManager::new(use_fast_ops);

        #[cfg(feature = "android")]
        android_logger::init_once(
            android_logger::Config::default()
                // Need to use info otherwise uniffi spams a lot (https://github.com/mozilla/uniffi-rs/issues/1702)
                .with_max_level(log::LevelFilter::Info),
        );

        Arc::new(PortalSdk {
            requests,
            nfc,
            manager: Mutex::new(Some(manager)),
            stop,

            #[cfg(feature = "debug")]
            debug_channels: _debug_channels,
        })
    }

    pub async fn poll(&self) -> Result<NfcOut, SdkError> {
        if let Some(manager) = self.manager.lock().await.take() {
            async_std::task::spawn(async move { manager.background_task().await });
        }

        let mut lock = self.nfc.i.lock().await;
        let (msg_index, data) = lock
            .as_mut()
            .peek()
            .await
            .ok_or(SdkError::ChannelError)?
            .clone();
        Ok(NfcOut { msg_index, data })
    }
    pub async fn incoming_data(&self, msg_index: u64, data: Vec<u8>) -> Result<(), SdkError> {
        // Drop message as it's finally been sent if we received an answer
        let mut lock = self.nfc.i.lock().await;
        let _ = lock.next().await;

        self.nfc.o.send((msg_index, data)).await?;
        Ok(())
    }
    pub async fn new_tag(&self) -> Result<(), SdkError> {
        self.stop.send(()).await?;

        Ok(())
    }

    pub async fn get_status(&self) -> Result<CardStatus, SdkError> {
        let device_info = send_with_retry!(self.requests, Request::GetInfo, Ok(Reply::Info(device_info)) => break Ok(device_info))?;
        match device_info.initialized {
            InitializationStatus::Initialized {
                network,
                unlocked,
                fingerprint,
                ..
            } => Ok(CardStatus {
                initialized: true,
                unverified: None,
                unlocked,
                network: Some(network),
                version: device_info.firmware_version,
                fingerprint: fingerprint.map(|bytes| bip32::Fingerprint::from(bytes)),
            }),
            InitializationStatus::Uninitialized => Ok(CardStatus {
                initialized: false,
                unverified: None,
                unlocked: true,
                network: None,
                version: device_info.firmware_version,
                fingerprint: None,
            }),
            InitializationStatus::Unverified { with_code, network } => Ok(CardStatus {
                initialized: false,
                unverified: Some(with_code),
                unlocked: true,
                network: Some(network),
                version: device_info.firmware_version,
                fingerprint: None,
            }),
        }
    }

    pub async fn generate_mnemonic(
        &self,
        num_words: GenerateMnemonicWords,
        network: model::bitcoin::Network,
        password: Option<String>,
    ) -> Result<(), SdkError> {
        let num_words = match num_words {
            GenerateMnemonicWords::Words12 => NumWordsMnemonic::Words12,
            GenerateMnemonicWords::Words24 => NumWordsMnemonic::Words24,
        };

        send_with_retry!(self.requests, Request::GenerateMnemonic { num_words, network, password: password.clone() }, Ok(Reply::Ok) => break Ok(()))?;
        Ok(())
    }

    pub async fn restore_mnemonic(
        &self,
        mnemonic: String,
        network: model::bitcoin::Network,
        password: Option<String>,
    ) -> Result<(), SdkError> {
        send_with_retry!(self.requests, Request::SetMnemonic { mnemonic: mnemonic.clone(), network, password: password.clone() }, Ok(Reply::Ok) => break Ok(()))?;
        Ok(())
    }

    pub async fn unlock(&self, password: String) -> Result<(), SdkError> {
        send_with_retry!(self.requests, Request::Unlock { password: password.clone()  }, Ok(Reply::Ok) => break Ok(()))?;
        Ok(())
    }

    pub async fn resume(&self) -> Result<(), SdkError> {
        send_with_retry!(self.requests, Request::Resume, Ok(Reply::Ok) => break Ok(()))?;
        Ok(())
    }

    pub async fn display_address(&self, index: u32) -> Result<model::bitcoin::Address, SdkError> {
        let address = send_with_retry!(self.requests, Request::DisplayAddress(index), Ok(Reply::Address(s)) => break Ok(s))?;
        let address = address
            .parse::<model::bitcoin::Address<model::bitcoin::address::NetworkUnchecked>>()
            .map_err(|_| SdkError::DeserializationError)?;
        Ok(address.assume_checked())
    }

    pub async fn sign_psbt(&self, psbt: String) -> Result<String, SdkError> {
        let psbt = base64::decode(&psbt)?;
        let mut original_psbt = model::bitcoin::psbt::Psbt::deserialize(&psbt)
            .map_err(|_| SdkError::DeserializationError)?;

        send_with_retry!(self.requests, Request::BeginSignPsbt, Ok(Reply::Ok) => break Ok(()))?;

        let psbt = send_with_retry!(self.requests, Request::SignPsbt(psbt.clone().into()), Ok(Reply::SignedPsbt(s)) => break Ok(s))?;

        // We encode the signatures in a format that's almost psbt but incompatible in some cases,
        // so we parse it manually here
        let inputs =
            psbt::PortalPsbt::parse(psbt.deref()).map_err(|_| SdkError::DeserializationError)?;
        let mut psbt =
            model::bitcoin::psbt::Psbt::from_unsigned_tx(original_psbt.unsigned_tx.clone())
                .expect("Valid unsigned tx");
        psbt.inputs = inputs.inputs;

        original_psbt
            .combine(psbt)
            .map_err(|_| SdkError::DeserializationError)?;

        Ok(base64::encode(&original_psbt.serialize()))
    }

    pub async fn get_xpub(&self, path: bip32::DerivationPath) -> Result<DeviceXpub, SdkError> {
        let (xpub, bsms) = send_with_retry!(self.requests, Request::GetXpub(path.clone().into()), Ok(Reply::Xpub { xpub, bsms }) => break Ok((xpub, bsms)))?;

        Ok(DeviceXpub {
            xpub,
            bsms: GetXpubBsmsData {
                version: bsms.version,
                token: bsms.token,
                key_name: bsms.key_name,
                signature: base64::encode(bsms.signature.deref().as_ref()),
            },
        })
    }

    pub async fn set_descriptor(
        &self,
        descriptor: String,
        bsms: Option<SetDescriptorBsmsData>,
    ) -> Result<(), SdkError> {
        use miniscript::{descriptor::*, Miniscript};
        use std::str::FromStr;

        fn map_key(pk: &DescriptorPublicKey) -> Result<ExtendedKey, SdkError> {
            let pk = match pk {
                DescriptorPublicKey::Single(_) => {
                    return Err(SdkError::UnsupportedDescriptor {
                        cause: "Single public keys are not supported".to_string(),
                    })
                }
                DescriptorPublicKey::MultiXPub(_) => {
                    return Err(SdkError::UnsupportedDescriptor {
                        cause: "Multi xpubs are not supported".to_string(),
                    })
                }
                DescriptorPublicKey::XPub(xpub) => xpub,
            };

            if pk.wildcard != Wildcard::Unhardened {
                return Err(SdkError::UnsupportedDescriptor {
                    cause: "Invalid wildcard".to_string(),
                });
            }

            Ok(ExtendedKey {
                key: pk.xkey.into(),
                origin: pk
                    .origin
                    .as_ref()
                    .map(|(f, d)| ((*f).into(), d.clone().into())),
                path: pk.derivation_path.clone().into(),
            })
        }
        fn make_multisig(
            k: usize,
            pks: &[DescriptorPublicKey],
            is_sorted: bool,
        ) -> Result<SetDescriptorVariant, SdkError> {
            if !is_sorted {
                return Err(SdkError::UnsupportedDescriptor {
                    cause: "Only `sortedmulti` descriptors are supported".into(),
                });
            }

            let keys = pks
                .into_iter()
                .map(|pk| map_key(pk))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(SetDescriptorVariant::MultiSig {
                threshold: k,
                keys,
                is_sorted,
            })
        }
        fn process_wsh(wsh: &Wsh<DescriptorPublicKey>) -> Result<SetDescriptorVariant, SdkError> {
            match wsh.as_inner() {
                WshInner::Ms(Miniscript {
                    node: miniscript::Terminal::Multi(threshold),
                    ..
                }) => make_multisig(threshold.k(), threshold.data(), false),
                WshInner::SortedMulti(sortedmulti) => {
                    make_multisig(sortedmulti.k(), sortedmulti.pks(), true)
                }
                _ => {
                    return Err(SdkError::UnsupportedDescriptor {
                        cause: "Arbitrary descriptors are not supported".to_string(),
                    })
                }
            }
        }

        let (descriptor, bsms) = if let Some(bsms) = bsms {
            if bsms.version != "1.0" {
                return Err(SdkError::UnsupportedDescriptor {
                    cause: "Unsupported BSMS version".to_string(),
                });
            }

            // We only support one specific path-restriction, which is `/0/*` for external and `/1/*` for internal
            if bsms.path_restrictions != "/0/*,/1/*" {
                return Err(SdkError::UnsupportedDescriptor {
                    cause: "Only `/0/*,/1/*` is supported as path restriction".to_string(),
                });
            }

            // If we have BSMS data we expect path restrictions in the descriptor, so we remove them here first
            let parsed = Descriptor::<String>::from_str(&descriptor).map_err(|e| {
                SdkError::InvalidDescriptor {
                    cause: e.to_string(),
                }
            })?;
            let parsed = parsed.translate_pk(&mut BsmsTranslator).map_err(|_| {
                SdkError::InvalidDescriptor {
                    cause: "Key translation error".into(),
                }
            })?;

            (
                parsed.to_string(),
                Some(BsmsRound2 {
                    first_address: bsms.first_address,
                }),
            )
        } else {
            (descriptor, None)
        };

        let parsed = Descriptor::<DescriptorPublicKey>::from_str(&descriptor).map_err(|e| {
            SdkError::InvalidDescriptor {
                cause: e.to_string(),
            }
        })?;
        let (variant, script_type) = match parsed {
            Descriptor::Wpkh(wpkh) => (
                SetDescriptorVariant::SingleSig(map_key(wpkh.as_inner())?),
                ScriptType::NativeSegwit,
            ),
            Descriptor::Pkh(pkh) => (
                SetDescriptorVariant::SingleSig(map_key(pkh.as_inner())?),
                ScriptType::Legacy,
            ),
            Descriptor::Sh(sh) => match sh.as_inner() {
                ShInner::Wpkh(wpkh) => (
                    SetDescriptorVariant::SingleSig(map_key(wpkh.as_inner())?),
                    ScriptType::WrappedSegwit,
                ),
                ShInner::Wsh(wsh) => (process_wsh(wsh)?, ScriptType::WrappedSegwit),
                ShInner::Ms(Miniscript {
                    node: miniscript::Terminal::Multi(threshold),
                    ..
                }) => (
                    make_multisig(threshold.k(), threshold.data(), false)?,
                    ScriptType::Legacy,
                ),
                ShInner::SortedMulti(sortedmulti) => (
                    make_multisig(sortedmulti.k(), sortedmulti.pks(), true)?,
                    ScriptType::Legacy,
                ),
                _ => {
                    return Err(SdkError::UnsupportedDescriptor {
                        cause: "Arbitrary descriptors are not supported".to_string(),
                    })
                }
            },
            Descriptor::Wsh(wsh) => (process_wsh(&wsh)?, ScriptType::NativeSegwit),
            _ => {
                return Err(SdkError::UnsupportedDescriptor {
                    cause: "Unsupported descriptor type".into(),
                })
            }
        };

        let request = Request::SetDescriptor {
            variant,
            script_type,
            bsms,
        };
        send_with_retry!(self.requests, request.clone(), Ok(Reply::Ok) => break Ok(()))?;

        Ok(())
    }

    pub async fn public_descriptors(&self) -> Result<Descriptors, SdkError> {
        let descriptor = send_with_retry!(self.requests, Request::PublicDescriptor, Ok(Reply::Descriptor{ external, internal }) => break Ok(Descriptors { external, internal }))?;
        Ok(descriptor)
    }

    pub async fn show_mnemonic(&self) -> Result<(), SdkError> {
        send_with_retry!(self.requests, Request::ShowMnemonic, Ok(Reply::Ok) => break Ok(()))?;
        Ok(())
    }

    pub async fn update_firmware(&self, binary: Vec<u8>) -> Result<(), SdkError> {
        // First 64 bytes are the signature, then there's the actual firmware.
        // We expect at least two pages (4K)
        if binary.len() < 64 + 4096 || binary.len() > 64 + 510 * 2048 {
            return Err(SdkError::InvalidFirmware);
        }

        let signature: [u8; 64] = binary[..64].try_into().expect("Correct length");
        let binary = &binary[64..];

        // The dword is the stack pointer. It must be within RAM
        let sp = u32::from_le_bytes(binary[..4].try_into().unwrap());
        // The dword is the reset handler. It must be within FLASH
        let reset = u32::from_le_bytes(binary[4..8].try_into().unwrap());

        match sp {
            SRAM1_BASE..=SRAM1_END | SRAM2_BASE..=SRAM2_END => {}
            _ => return Err(SdkError::InvalidFirmware),
        }
        match reset {
            FLASH_BASE..=FLASH_END => {}
            _ => return Err(SdkError::InvalidFirmware),
        }

        let get_page = |i: usize| {
            let mut buf: Box<model::ByteArray<2048>> = Box::new([0u8; 2048].into());
            if binary.len() < i * 2048 {
                return None;
            }
            let end = std::cmp::min(binary.len(), (i + 1) * 2048);
            let chunk = &binary[i * 2048..end];
            buf.deref_mut()[..chunk.len()].copy_from_slice(&chunk);

            Some(buf)
        };

        use model::bitcoin::hashes::HashEngine;
        let mut first_page_midstate = model::bitcoin::hashes::sha256::HashEngine::default();
        first_page_midstate.input(get_page(0).unwrap().deref().deref());
        let first_page_midstate = first_page_midstate.midstate();
        let header = model::FwUpdateHeader {
            variant: model::FwVariant::VANILLA,
            signature: Box::new(signature.into()),
            size: binary.len(),
            first_page_midstate: Box::new(first_page_midstate.to_byte_array().into()),
        };

        let mut page = send_with_retry!(self.requests, model::Request::BeginFwUpdate(header.clone()), Ok(Reply::NextPage(page)) => break Ok(Some(page)), Ok(Reply::Ok) => break Ok(None))?;
        while let Some(p) = page {
            let is_last = get_page(p).is_none();
            let get_req = || match get_page(p) {
                Some(data) => model::Request::FwUpdateChunk(data.clone()),
                None => model::Request::CompleteFwUpdate(get_page(0).unwrap()),
            };

            page = send_with_retry!(self.requests, get_req(), Ok(Reply::NextPage(page)) => break Ok(Some(page)), Ok(Reply::Ok) => break Ok(None))?;
            if is_last && page.is_some() {
                return Err(SdkError::UnexpectedMessage);
            }
        }

        Ok(())
    }

    #[cfg(feature = "debug")]
    pub async fn debug_wipe_device(&self) -> Result<(), SdkError> {
        send_with_retry!(self.requests, Request::WipeDevice, Ok(Reply::Ok) => break Ok(()))?;
        Ok(())
    }

    #[cfg(feature = "debug")]
    pub async fn debug_msg(&self) -> Result<DebugMessage, SdkError> {
        Ok(self.debug_channels.recv.recv().await?)
    }
    #[cfg(feature = "debug")]
    pub async fn debug_send_raw(&self, data: Vec<u8>) -> Result<(), SdkError> {
        self.debug_channels.send.send(data).await?;
        Ok(())
    }
}

struct BsmsTranslator;
impl miniscript::Translator<String, String, SdkError> for BsmsTranslator {
    fn pk(&mut self, pk: &String) -> Result<String, SdkError> {
        if pk.ends_with("/**") {
            let mut pk = pk.clone();
            pk.replace_range(pk.len() - 3.., "/*");

            Ok(pk)
        } else {
            Err(SdkError::UnsupportedDescriptor {
                cause:
                    "When using BSMS all the keys must end with descriptor template syntax (`/**`)"
                        .into(),
            })
        }
    }

    fn sha256(
        &mut self,
        sha256: &<String as miniscript::MiniscriptKey>::Sha256,
    ) -> Result<<String as miniscript::MiniscriptKey>::Sha256, SdkError> {
        Ok(sha256.clone())
    }

    fn hash256(
        &mut self,
        hash256: &<String as miniscript::MiniscriptKey>::Hash256,
    ) -> Result<<String as miniscript::MiniscriptKey>::Hash256, SdkError> {
        Ok(hash256.clone())
    }

    fn ripemd160(
        &mut self,
        ripemd160: &<String as miniscript::MiniscriptKey>::Ripemd160,
    ) -> Result<<String as miniscript::MiniscriptKey>::Ripemd160, SdkError> {
        Ok(ripemd160.clone())
    }

    fn hash160(
        &mut self,
        hash160: &<String as miniscript::MiniscriptKey>::Hash160,
    ) -> Result<<String as miniscript::MiniscriptKey>::Hash160, SdkError> {
        Ok(hash160.clone())
    }
}

struct RequestChannels {
    o: async_std::sync::Mutex<channel::Sender<Request>>,
    i: channel::Receiver<Result<Reply, FutureError>>,
}

struct NfcChannels {
    o: channel::Sender<(u64, Vec<u8>)>,
    i: Mutex<Pin<Box<Peekable<channel::Receiver<(u64, Vec<u8>)>>>>>,
}

struct IndexedChannelPair {
    counter: u64,
    nfc_out: channel::Sender<(u64, Vec<u8>)>,
    nfc_in: channel::Receiver<(u64, Vec<u8>)>,
}

impl IndexedChannelPair {
    pub async fn send(&mut self, data: Vec<u8>) -> Result<Vec<u8>, FutureError> {
        let i = self.counter;
        self.counter += 1;

        self.nfc_out.send((i, data)).await?;
        loop {
            let (c, in_data) = self.nfc_in.recv().await?;
            if c == i {
                break Ok(in_data);
            }
        }
    }
}

struct InnerManager {
    use_fast_ops: bool,

    requests: channel::Receiver<Request>,
    replies: channel::Sender<Result<Reply, FutureError>>,
    nfc: IndexedChannelPair,
    stop: channel::Receiver<()>,

    #[cfg(feature = "debug")]
    debug_out: channel::Sender<DebugMessage>,
    #[cfg(feature = "debug")]
    debug_in: channel::Receiver<Vec<u8>>,
}

#[cfg(not(feature = "debug"))]
type Debug = ();
#[cfg(feature = "debug")]
struct Debug {
    recv: channel::Receiver<DebugMessage>,
    send: channel::Sender<Vec<u8>>,
}

impl InnerManager {
    fn new(
        use_fast_ops: bool,
    ) -> (
        Self,
        RequestChannels,
        NfcChannels,
        channel::Sender<()>,
        Debug,
    ) {
        let (requests_s, requests_r) = channel::unbounded();
        let (replies_s, replies_r) = channel::unbounded();
        let (nfc_out_s, nfc_out_r) = channel::unbounded();
        let (nfc_in_s, nfc_in_r) = channel::unbounded();
        let (stop_s, stop_r) = channel::unbounded();

        #[cfg(feature = "debug")]
        let (debug_out, debug_in, debug) = {
            let (debug_msg_s, debug_msg_r) = channel::unbounded();
            let (debug_raw_s, debug_raw_r) = channel::unbounded();

            (
                debug_msg_s,
                debug_raw_r,
                Debug {
                    recv: debug_msg_r,
                    send: debug_raw_s,
                },
            )
        };
        #[cfg(not(feature = "debug"))]
        let debug = ();

        let manager = InnerManager {
            use_fast_ops,

            requests: requests_r,
            replies: replies_s,
            nfc: IndexedChannelPair {
                counter: 0,
                nfc_out: nfc_out_s,
                nfc_in: nfc_in_r,
            },
            stop: stop_r,

            #[cfg(feature = "debug")]
            debug_out,
            #[cfg(feature = "debug")]
            debug_in,
        };

        let req_channels = RequestChannels {
            o: async_std::sync::Mutex::new(requests_s),
            i: replies_r,
        };
        let nfc_channels = NfcChannels {
            o: nfc_in_s,
            i: Mutex::new(Box::pin(nfc_out_r.peekable())),
        };

        (manager, req_channels, nfc_channels, stop_s, debug)
    }

    async fn background_task(mut self) {
        loop {
            futures::select_biased! {
                result = self.stop.recv().fuse() => {
                    if result.is_err() {
                        break;
                    }

                    log::debug!("Got explicit stop, reloading inner future");
                    continue;
                },
                result = inner_logic::inner_future(
                    &self.requests,
                    &self.replies,
                    &mut self.nfc,
                    self.use_fast_ops,

                    #[cfg(feature = "debug")]
                    &self.debug_out,
                    #[cfg(feature = "debug")]
                    &self.debug_in,
                ).fuse() => {
                    log::debug!("inner_future exited with: {:?}", result);
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
pub struct CardStatus {
    pub initialized: bool,
    pub unverified: Option<bool>,
    pub unlocked: bool,
    pub network: Option<model::bitcoin::Network>,
    pub version: Option<String>,
    /// Added in version 0.3.0 of the firmware
    ///
    /// Only available when the device is initialized and unlocked
    pub fingerprint: Option<bip32::Fingerprint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
pub struct Descriptors {
    pub external: String,
    pub internal: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
pub struct GetXpubBsmsData {
    pub version: String,
    pub token: String,
    pub key_name: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
pub struct SetDescriptorBsmsData {
    pub version: String,
    pub path_restrictions: String,
    pub first_address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
pub struct DeviceXpub {
    pub xpub: String,
    pub bsms: GetXpubBsmsData,
}

#[derive(Debug)]
#[cfg_attr(feature = "bindings", derive(uniffi::Enum))]
pub enum GenerateMnemonicWords {
    Words12,
    Words24,
}

#[derive(Debug)]
#[cfg_attr(feature = "bindings", derive(uniffi::Error))]
#[cfg_attr(feature = "bindings", uniffi(flat_error))]
pub enum SdkError {
    ChannelError,
    CommunicationError,
    DifferentUid,
    UnexpectedMessage,
    DeserializationError,
    Timeout,
    Base64,
    InvalidFirmware,
    Locked,
    DeviceError { cause: String },
    InvalidDescriptor { cause: String },
    UnsupportedDescriptor { cause: String },
}

impl core::fmt::Display for SdkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{:?}", self))
    }
}

impl std::error::Error for SdkError {}

impl From<async_std::channel::RecvError> for SdkError {
    fn from(_: async_std::channel::RecvError) -> Self {
        SdkError::ChannelError
    }
}
impl<T> From<async_std::channel::SendError<T>> for SdkError {
    fn from(_: async_std::channel::SendError<T>) -> Self {
        SdkError::ChannelError
    }
}
impl<T> From<async_std::channel::TrySendError<T>> for SdkError {
    fn from(_: async_std::channel::TrySendError<T>) -> Self {
        SdkError::ChannelError
    }
}
impl From<async_std::future::TimeoutError> for SdkError {
    fn from(_: async_std::future::TimeoutError) -> Self {
        SdkError::Timeout
    }
}
impl From<FutureError> for SdkError {
    fn from(e: FutureError) -> Self {
        match e {
            FutureError::ChannelError => SdkError::ChannelError,
            FutureError::Timeout => SdkError::Timeout,
            FutureError::Message => SdkError::CommunicationError,
            FutureError::Canceled => SdkError::CommunicationError,
        }
    }
}
impl From<base64::DecodeError> for SdkError {
    fn from(_: base64::DecodeError) -> Self {
        SdkError::Base64
    }
}

#[cfg(feature = "bindings")]
#[allow(dead_code)]
mod ffi {
    use std::str::FromStr;

    use super::*;

    macro_rules! impl_custom_type_converter_str {
        ($t:ty) => {
            impl UniffiCustomTypeConverter for $t {
                type Builtin = String;

                fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
                    <$t>::from_str(&val)
                        .map_err(|_| uniffi::deps::anyhow::Error::msg("Invalid string"))
                }

                fn from_custom(obj: Self) -> Self::Builtin {
                    obj.to_string()
                }
            }
        };
    }

    impl UniffiCustomTypeConverter for Address {
        type Builtin = String;

        fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
            model::bitcoin::Address::<model::bitcoin::address::NetworkUnchecked>::from_str(&val)
                .map_err(|_| uniffi::deps::anyhow::Error::msg("Invalid string"))
                .map(|a| a.assume_checked())
        }

        fn from_custom(obj: Self) -> Self::Builtin {
            obj.to_string()
        }
    }

    impl_custom_type_converter_str!(Network);
    impl_custom_type_converter_str!(DerivationPath);
    impl_custom_type_converter_str!(Fingerprint);

    uniffi::custom_type!(Network, String);
    uniffi::custom_type!(Address, String);
    uniffi::custom_type!(DerivationPath, String);
    uniffi::custom_type!(Fingerprint, String);
}

#[cfg(feature = "bindings")]
uniffi::setup_scaffolding!();
