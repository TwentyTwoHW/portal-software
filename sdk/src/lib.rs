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
use model::{InitializationStatus, NumWordsMnemonic, Reply, Request};

mod inner_logic;

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
pub use model::bitcoin::{Address, Network};

#[cfg_attr(feature = "bindings", derive(uniffi::Object))]
pub struct PortalSdk {
    manager: Mutex<Option<InnerManager>>,
    requests: RequestChannels,
    nfc: NfcChannels,
    stop: channel::Sender<()>,

    #[cfg(feature = "debug")]
    debug_channel: channel::Receiver<DebugMessage>,
}

#[cfg(feature = "debug")]
#[cfg_attr(feature = "bindings", derive(uniffi::Object))]
pub enum DebugMessage {
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
            $channels.o.send(req).await?;

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
        let (manager, requests, nfc, stop, _debug_channel) = InnerManager::new(use_fast_ops);

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
            debug_channel: _debug_channel,
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
                network, unlocked, ..
            } => Ok(CardStatus {
                initialized: true,
                unverified: None,
                unlocked,
                network: Some(network),
            }),
            InitializationStatus::Uninitialized => Ok(CardStatus {
                initialized: false,
                unverified: None,
                unlocked: true,
                network: None,
            }),
            InitializationStatus::Unverified { with_code, network } => Ok(CardStatus {
                initialized: false,
                unverified: Some(with_code),
                unlocked: true,
                network: Some(network),
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
            .parse()
            .map_err(|_| SdkError::DeserializationError)?;
        Ok(address)
    }

    pub async fn sign_psbt(&self, psbt: String) -> Result<String, SdkError> {
        use model::bitcoin::consensus::{deserialize, serialize};

        let psbt = base64::decode(&psbt)?;
        let mut original_psbt: model::bitcoin::util::psbt::Psbt =
            deserialize(&psbt).map_err(|_| SdkError::DeserializationError)?;

        send_with_retry!(self.requests, Request::BeginSignPsbt, Ok(Reply::Ok) => break Ok(()))?;

        let psbt = send_with_retry!(self.requests, Request::SignPsbt(psbt.clone().into()), Ok(Reply::SignedPsbt(s)) => break Ok(s))?;

        let mut psbt: model::bitcoin::util::psbt::Psbt =
            deserialize(psbt.deref()).map_err(|_| SdkError::CommunicationError)?;
        psbt.unsigned_tx = original_psbt.unsigned_tx.clone();

        original_psbt
            .combine(psbt)
            .map_err(|_| SdkError::DeserializationError)?;
        let original_psbt = serialize(&original_psbt);

        Ok(base64::encode(&original_psbt))
    }

    pub async fn public_descriptors(&self) -> Result<Descriptors, SdkError> {
        let descriptor = send_with_retry!(self.requests, Request::PublicDescriptor, Ok(Reply::Descriptor{ external, internal }) => break Ok(Descriptors { external, internal }))?;
        Ok(descriptor)
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
            first_page_midstate: Box::new(first_page_midstate.into_inner().into()),
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
    pub async fn debug_msg(&self) -> Result<DebugMessage, SdkError> {
        Ok(self.debug_channel.recv().await?)
    }
}

struct RequestChannels {
    o: channel::Sender<Request>,
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
    debug: channel::Sender<DebugMessage>,
}

#[cfg(not(feature = "debug"))]
type Debug = ();
#[cfg(feature = "debug")]
type Debug = channel::Receiver<DebugMessage>;

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
        let (debug_s, debug) = channel::unbounded();
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
            debug: debug_s,
        };

        let req_channels = RequestChannels {
            o: requests_s,
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
                    &self.debug,
                ).fuse() => {
                    log::debug!("inner_future exited with: {:?}", result);

                    if result.is_err() {
                        break;
                    }
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
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "bindings", derive(uniffi::Record))]
pub struct Descriptors {
    pub external: String,
    pub internal: Option<String>,
}

#[derive(Debug)]
#[cfg_attr(feature = "bindings", derive(uniffi::Enum))]
pub enum GenerateMnemonicWords {
    Words12,
    Words24,
}

#[derive(Debug)]
#[cfg_attr(feature = "bindings", derive(uniffi::Error))]
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
            FutureError::Message(_) => SdkError::CommunicationError,
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

    impl<T: FromStr + ToString> UniffiCustomTypeConverter for T {
        type Builtin = String;

        fn into_custom(val: Self::Builtin) -> uniffi::Result<Self> {
            T::from_str(&val).map_err(|_| uniffi::deps::anyhow::Error::msg("Invalid string"))
        }

        fn from_custom(obj: Self) -> Self::Builtin {
            obj.to_string()
        }
    }

    uniffi::custom_type!(Network, String);
    uniffi::custom_type!(Address, String);
}

#[cfg(feature = "bindings")]
uniffi::setup_scaffolding!();
