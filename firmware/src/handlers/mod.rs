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

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::string::String;
use alloc::vec::Vec;
use tinyminiscript::descriptor::Descriptor;
use core::cell::RefCell;
use core::pin::Pin;

use futures::pin_mut;
use futures::prelude::*;

use tinyminiscript::bitcoin::{bip32, secp256k1, Network};

use gui::{ConfirmBarPage, ErrorPage, MainContent, Page};
use model::{FwUpdateHeader, NumWordsMnemonic, Reply};

use crate::bitcoin_utils::SignerContext;
use crate::bitcoin_utils::TransactionSigner;
use crate::{checkpoint, hw, Error};

#[allow(dead_code)]
const GIT_HASH: &'static str = fetch_git_hash::fetch_git_hash!();

pub mod bitcoin;
pub mod fwupdate;
pub mod idle;
pub mod init;

pub struct BitcoinWallet {
    external: String,
    internal: String,
    network: Network,
    secp: secp256k1::Secp256k1<secp256k1::All>,
    signer: TransactionSigner,
}

impl BitcoinWallet {
    pub fn new(
        external: String,
        internal: String,
        signer: TransactionSigner,
        network: Network,
    ) -> Self {
        let secp = secp256k1::Secp256k1::new();

        BitcoinWallet {
            external,
            internal,
            network,
            secp,
            signer,
        }
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn secp_ctx(&self) -> &secp256k1::Secp256k1<secp256k1::All> {
        &self.secp
    }

    pub fn context(&self) -> SignerContext {
        match self.external().descriptor() {
            Descriptor::Bare => SignerContext::Legacy,
            Descriptor::Pkh => SignerContext::Legacy,
            Descriptor::Sh => SignerContext::Legacy,
            Descriptor::Wpkh => SignerContext::Segwitv0,
            Descriptor::Wsh => SignerContext::Segwitv0,
            Descriptor::Tr => SignerContext::Tap { is_internal_key: true }, // TODO: fix this when implementing taproot
        }
    }

    pub fn external<'a>(&'a self) -> tinyminiscript::parser::ParserContext<'a> {
        tinyminiscript::parser::parse(&self.external).map_err(|_| "Invalid descriptor").unwrap()
    }

    pub fn internal<'a>(&'a self) -> tinyminiscript::parser::ParserContext<'a> {
        tinyminiscript::parser::parse(&self.internal).map_err(|_| "Invalid descriptor").unwrap()
    }

    pub fn signer(&self) -> &TransactionSigner {
        &self.signer
    }
}

pub struct PortalWallet {
    pub bdk: BitcoinWallet,
    pub xprv: bip32::Xpriv,
    pub config: model::UnlockedConfig,
}

impl PortalWallet {
    pub fn new(bdk: BitcoinWallet, xprv: bip32::Xpriv, config: model::UnlockedConfig) -> Self {
        PortalWallet { bdk, xprv, config }
    }
}

impl core::ops::Deref for PortalWallet {
    type Target = BitcoinWallet;
    fn deref(&self) -> &Self::Target {
        &self.bdk
    }
}
impl core::ops::DerefMut for PortalWallet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bdk
    }
}

pub enum CurrentState {
    /// Power on reset
    POR,
    /// Empty new device
    Init,
    /// Initialized but locked device
    Locked { config: model::InitializedConfig },
    /// Not yet finished to verify the config
    UnverifiedConfig { config: model::UnverifiedConfig },
    /// Generating seed
    GenerateSeed {
        num_words: NumWordsMnemonic,
        network: tinyminiscript::bitcoin::Network,
        password: Option<String>,
    },
    /// Importing seed
    ImportSeed {
        mnemonic: String,
        network: tinyminiscript::bitcoin::Network,
        password: Option<String>,
    },
    /// Show mnemonic on display
    ShowMnemonic {
        wallet: Rc<PortalWallet>,
        resumable: checkpoint::Resumable,
        is_fast_boot: bool,
    },
    /// Device ready
    Idle { wallet: Rc<PortalWallet> },
    /// Waiting to receive the PSBT
    WaitingForPsbt { wallet: Rc<PortalWallet> },
    /// Sign request
    SignPsbt {
        wallet: Rc<PortalWallet>,
        psbt: alloc::vec::Vec<u8>,
    },
    /// Confirm sign request
    ConfirmSignPsbt {
        wallet: Rc<PortalWallet>,
        outputs: alloc::vec::Vec<(checkpoint::DisplayAddress, u64)>,
        fees: u64,
        sig_bytes: alloc::vec::Vec<u8>,
        resumable: checkpoint::Resumable,
        encryption_key: [u8; 24],
    },
    /// Display an address
    DisplayAddress {
        wallet: Rc<PortalWallet>,
        index: u32,
        resumable: checkpoint::Resumable,
        is_fast_boot: bool,
    },
    /// Request the public descriptor
    PublicDescriptor {
        wallet: Rc<PortalWallet>,
        resumable: checkpoint::Resumable,
        is_fast_boot: bool,
    },
    /// Request to set a new descriptor
    SetDescriptor {
        wallet: Rc<PortalWallet>,
        variant: model::SetDescriptorVariant,
        script_type: model::ScriptType,
        bsms: Option<model::BsmsRound2>,
        resumable: checkpoint::Resumable,
        is_fast_boot: bool,
        encryption_key: [u8; 24],
    },
    /// Request a derived XPUB
    GetXpub {
        wallet: Rc<PortalWallet>,
        derivation_path: bip32::DerivationPath,
        resumable: checkpoint::Resumable,
        is_fast_boot: bool,
        encryption_key: [u8; 24],
    },
    /// Updating firmware
    UpdatingFw {
        header: FwUpdateHeader,
        fast_boot: Option<(checkpoint::FwUpdateState, [u8; 24])>,
    },
    /// Wipe device
    WipeDevice,

    /// Error
    Error,
}

#[derive(Debug)]
pub enum Event {
    Tick,
    Input(bool),
    Request(model::Request),
}

pub struct HandlerPeripherals {
    pub nfc: hw::ChannelSender<Reply>,
    pub nfc_finished: hw::ChannelReceiver<()>,
    pub display: hw::Display,
    pub rng: rand_chacha::ChaCha20Rng,
    pub flash: hw::Flash,
    pub rtc: hw::Rtc,
    pub tsc_enabled: hw::TscEnable,
}

#[allow(dead_code)]
fn only_requests(stream: impl Stream<Item = Event>) -> impl Stream<Item = model::Request> {
    stream.filter_map(|e| async move {
        match e {
            Event::Request(r) => Some(r),
            _ => None,
        }
    })
}

#[allow(dead_code)]
fn only_input<'s>(
    stream: impl Stream<Item = Event> + 's,
    nfc: &'s RefCell<&'s mut hw::ChannelSender<Reply>>,
) -> impl Stream<Item = bool> + 's {
    stream
        .zip(futures::stream::repeat(nfc))
        .filter_map(|(e, nfc)| async move {
            match e {
                Event::Request(_) => {
                    let _ = nfc.borrow_mut().send(Reply::Busy).await;
                    None
                }
                Event::Input(v) => Some(v),
                _ => None,
            }
        })
}

#[allow(dead_code)]
async fn wait_ticks<'s>(
    stream: impl Stream<Item = Event> + 's,
    nfc: &'s RefCell<&'s mut hw::ChannelSender<Reply>>,
    num_ticks: usize,
) {
    let stream = stream
        .zip(futures::stream::repeat(nfc))
        .filter_map(|(e, nfc)| async move {
            match e {
                Event::Request(_) => {
                    let _ = nfc.borrow_mut().send(Reply::Busy).await;
                    None
                }
                Event::Tick => Some(()),
                _ => None,
            }
        })
        .take(num_ticks);
    pin_mut!(stream);

    while let Some(_) = stream.next().await {}
}

pub async fn dispatch_handler<'a>(
    current_state: &'a mut CurrentState,
    events: impl Stream<Item = Event> + Unpin + 'a,
    peripherals: &'a mut HandlerPeripherals,
    fast_boot: bool,
) {
    pin_mut!(events);

    let mut moved_state = CurrentState::Init;
    core::mem::swap(&mut moved_state, current_state);

    let result = match moved_state {
        CurrentState::POR => Box::pin(init::handle_por(peripherals, fast_boot))
            as Pin<Box<dyn Future<Output = Result<CurrentState, Error>>>>,
        CurrentState::Init => Box::pin(init::handle_init(events, peripherals))
            as Pin<Box<dyn Future<Output = Result<CurrentState, Error>>>>,
        CurrentState::Locked { config } => {
            Box::pin(init::handle_locked(config, events, peripherals))
                as Pin<Box<dyn Future<Output = Result<CurrentState, Error>>>>
        }
        CurrentState::UnverifiedConfig { config } => {
            Box::pin(init::handle_unverified_config(config, events, peripherals))
                as Pin<Box<dyn Future<Output = Result<CurrentState, Error>>>>
        }
        CurrentState::GenerateSeed {
            num_words,
            network,
            password,
        } => {
            peripherals
                .nfc
                .send(model::Reply::DelayedReply)
                .await
                .unwrap();

            Box::pin(init::handle_generate_seed(
                num_words,
                network,
                password,
                events,
                peripherals,
            )) as Pin<Box<dyn Future<Output = Result<CurrentState, Error>>>>
        }
        CurrentState::ImportSeed {
            mnemonic,
            network,
            password,
        } => {
            peripherals
                .nfc
                .send(model::Reply::DelayedReply)
                .await
                .unwrap();

            Box::pin(init::handle_import_seed(
                mnemonic,
                network,
                password,
                events,
                peripherals,
            )) as Pin<Box<dyn Future<Output = Result<CurrentState, Error>>>>
        }
        CurrentState::ShowMnemonic {
            wallet,
            resumable,
            is_fast_boot,
        } => Box::pin(init::handle_show_mnemonic(
            wallet,
            events,
            peripherals,
            resumable,
            is_fast_boot,
        )) as Pin<Box<dyn Future<Output = Result<CurrentState, Error>>>>,
        CurrentState::Idle { ref mut wallet } => {
            Box::pin(idle::handle_idle(wallet, events, peripherals))
                as Pin<Box<dyn Future<Output = Result<CurrentState, Error>>>>
        }
        CurrentState::WaitingForPsbt { ref mut wallet } => Box::pin(
            bitcoin::handle_waiting_for_psbt(wallet, events, peripherals),
        )
            as Pin<Box<dyn Future<Output = Result<CurrentState, Error>>>>,
        CurrentState::SignPsbt {
            ref mut wallet,
            psbt,
        } => Box::pin(bitcoin::handle_sign_request(wallet, psbt, peripherals))
            as Pin<Box<dyn Future<Output = Result<CurrentState, Error>>>>,
        CurrentState::ConfirmSignPsbt {
            ref mut wallet,
            outputs,
            fees,
            resumable,
            sig_bytes,
            encryption_key,
        } => Box::pin(bitcoin::handle_confirm_sign_psbt(
            wallet,
            outputs,
            fees,
            resumable,
            sig_bytes,
            encryption_key,
            events,
            peripherals,
        )) as Pin<Box<dyn Future<Output = Result<CurrentState, Error>>>>,
        CurrentState::DisplayAddress {
            ref mut wallet,
            index,
            resumable,
            is_fast_boot,
        } => Box::pin(bitcoin::handle_display_address_request(
            wallet,
            index,
            resumable,
            is_fast_boot,
            events,
            peripherals,
        )) as Pin<Box<dyn Future<Output = Result<CurrentState, Error>>>>,
        CurrentState::PublicDescriptor {
            ref mut wallet,
            resumable,
            is_fast_boot,
        } => Box::pin(bitcoin::handle_public_descriptor_request(
            wallet,
            resumable,
            is_fast_boot,
            events,
            peripherals,
        )) as Pin<Box<dyn Future<Output = Result<CurrentState, Error>>>>,
        CurrentState::SetDescriptor {
            ref mut wallet,
            variant,
            script_type,
            bsms,
            resumable,
            is_fast_boot,
            encryption_key,
        } => Box::pin(bitcoin::handle_set_descriptor_request(
            wallet,
            variant,
            script_type,
            bsms,
            resumable,
            is_fast_boot,
            encryption_key,
            events,
            peripherals,
        )) as Pin<Box<dyn Future<Output = Result<CurrentState, Error>>>>,
        CurrentState::GetXpub {
            ref mut wallet,
            derivation_path,
            resumable,
            is_fast_boot,
            encryption_key,
        } => Box::pin(bitcoin::handle_get_xpub_request(
            wallet,
            derivation_path,
            resumable,
            is_fast_boot,
            encryption_key,
            events,
            peripherals,
        )) as Pin<Box<dyn Future<Output = Result<CurrentState, Error>>>>,
        CurrentState::UpdatingFw { header, fast_boot } => Box::pin(
            fwupdate::handle_begin_fw_update(header, fast_boot, events, peripherals),
        )
            as Pin<Box<dyn Future<Output = Result<CurrentState, Error>>>>,
        CurrentState::WipeDevice => Box::pin(idle::wipe_device(events, peripherals))
            as Pin<Box<dyn Future<Output = Result<CurrentState, Error>>>>,

        CurrentState::Error => {
            handle_error(Error::Unknown, peripherals);
        }
    }
    .await;

    // Save power by disabling the TSC after every handler
    peripherals.tsc_enabled.disable();

    // Clear the "finished" queue of messages
    while !peripherals.nfc_finished.is_empty() {
        let _ = peripherals.nfc_finished.recv().await;
    }

    *current_state = match result {
        Ok(new_state) => new_state,
        Err(e) => handle_error(e, peripherals),
    }
}

fn handle_error(err: Error, peripherals: &mut HandlerPeripherals) -> ! {
    #[cfg(feture = "panic-log")]
    log::error!("{:?}", _err);

    let try_draw_message = |peripherals: &mut HandlerPeripherals| -> Result<(), Error> {
        log::debug!("{:?}", err);
        let error_msg = match err {
            Error::InvalidFirmware => "Invalid Firmware",
            Error::InvalidPassword => "Invalid Pair Code",
            Error::BrokenProtocol
            | Error::HandshakeError
            | Error::LostRf
            | Error::TooManyNacks
            | Error::Message(_) => "Communication Error",
            Error::Config(_) | Error::FlashError => "Memory Error",
            Error::Display(_) | Error::I2c(_) => "Display Error",
            Error::Wallet => "Wallet Error",
            Error::Unknown => "General Failure",
        };

        let page = ErrorPage::new(error_msg);
        page.init_display(&mut peripherals.display)?;
        page.draw_to(&mut peripherals.display)?;
        peripherals.display.flush()?;

        Ok(())
    };

    let _ = try_draw_message(peripherals);

    loop {}
}

async fn manage_confirmation_loop<'s, C: MainContent>(
    events: impl Stream<Item = Event> + Unpin,
    peripherals: &mut HandlerPeripherals,
    page: &mut ConfirmBarPage<'s, C>,
) -> Result<(), crate::Error> {
    manage_confirmation_loop_with_callback(events, peripherals, page, |_, _, _| {}, 0).await
}

async fn manage_confirmation_loop_with_checkpoint<'s, C: MainContent>(
    events: impl Stream<Item = Event> + Unpin,
    peripherals: &mut HandlerPeripherals,
    page: &mut ConfirmBarPage<'s, C>,
    checkpoint: &mut checkpoint::Checkpoint,
    state: checkpoint::Resumable,
) -> Result<(), crate::Error> {
    page.add_confirm(state.progress);

    manage_confirmation_loop_with_callback(
        events,
        peripherals,
        page,
        |peripherals, progress, ticks| {
            if let Some(resumable) = &mut checkpoint.resumable {
                resumable.page = state.page;
                resumable.progress = progress;
                resumable.ticks = ticks;

                checkpoint.commit_registers(&peripherals.rtc);
            }
        },
        state.ticks,
    )
    .await
}

async fn manage_confirmation_loop_with_callback<'s, C: MainContent>(
    mut events: impl Stream<Item = Event> + Unpin,
    peripherals: &mut HandlerPeripherals,
    page: &mut ConfirmBarPage<'s, C>,
    mut progress_update: impl FnMut(&mut HandlerPeripherals, u32, usize),
    mut ticks: usize,
) -> Result<(), crate::Error> {
    #[cfg(feature = "device")]
    let mut released_first = false;
    let mut pressing = false;
    let mut draw;

    if ticks > 0 {
        #[cfg(feature = "device")]
        {
            if ticks > 0 {
                released_first = true;
            }
        }

        for _ in 0..ticks {
            page.tick();
        }
    }

    progress_update(peripherals, page.get_confirm(), ticks);

    while !page.is_confirmed() {
        draw = false;

        match events.next().await.expect("Event") {
            Event::Request(_) => {
                peripherals
                    .nfc
                    .send(Reply::DelayedReply)
                    .await
                    .expect("Send should work");
            }
            #[cfg(feature = "device")]
            Event::Input(v) if !released_first => {
                // Get stuck in here while we wait for the user to lift its finger
                released_first = !v;
            }
            Event::Input(v) if v != pressing => {
                pressing = v;
                if !v {
                    page.reset_confirm();
                    progress_update(peripherals, page.get_confirm(), ticks);
                    draw = true;
                }
            }
            Event::Tick => {
                ticks += 1;
                draw = page.tick();

                if pressing {
                    page.add_confirm(15);
                    draw = true;
                }

                progress_update(peripherals, page.get_confirm(), ticks);
            }
            _ => {}
        }

        if draw {
            page.draw_to(&mut peripherals.display)?;
            peripherals.display.flush()?;
        }
    }

    Ok(())
}
