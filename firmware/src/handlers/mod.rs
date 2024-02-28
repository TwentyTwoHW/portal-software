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

use alloc::rc::Rc;
use alloc::string::String;
use core::cell::RefCell;
use gui::ErrorPage;

use futures::pin_mut;
use futures::prelude::*;

use gui::{ConfirmBarPage, MainContent, Page};
use model::{FwUpdateHeader, NumWordsMnemonic, Reply};

use crate::{hw, hw_common, Error};

#[allow(dead_code)]
const GIT_HASH: &'static str = fetch_git_hash::fetch_git_hash!();

mod bitcoin;
mod fwupdate;
mod idle;
mod init;

#[derive(Debug)]
pub enum CurrentState {
    /// Power on reset
    POR,
    /// Empty new device
    Init,
    /// Initialized but locked devic
    Locked { config: model::InitializedConfig },
    /// Not yet finished to verify the config
    UnverifiedConfig { config: model::UnverifiedConfig },
    /// Generating seed
    GenerateSeed {
        num_words: NumWordsMnemonic,
        network: bdk::bitcoin::Network,
        password: Option<String>,
    },
    /// Importing seed
    ImportSeed {
        mnemonic: String,
        network: bdk::bitcoin::Network,
        password: Option<String>,
    },
    /// Device ready
    Idle { wallet: Rc<bdk::Wallet> },
    /// Waiting to receive the PSBT
    WaitingForPsbt { wallet: Rc<bdk::Wallet> },
    /// Sign request
    SignPsbt {
        wallet: Rc<bdk::Wallet>,
        psbt: alloc::vec::Vec<u8>,
    },
    /// Display an address
    DisplayAddress { wallet: Rc<bdk::Wallet>, index: u32 },
    /// Request the public descriptor
    PublicDescriptor { wallet: Rc<bdk::Wallet> },
    /// Updating firmware
    UpdatingFw { header: FwUpdateHeader },
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
    pub nfc: hw_common::ChannelSender<Reply>,
    pub nfc_finished: hw_common::ChannelReceiver<()>,
    pub display: hw::Display,
    pub rng: rand_chacha::ChaCha20Rng,
    pub flash: hw::Flash,
    pub tsc_enabled: hw_common::TscEnable,
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
    nfc: &'s RefCell<&'s mut hw_common::ChannelSender<Reply>>,
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
    nfc: &'s RefCell<&'s mut hw_common::ChannelSender<Reply>>,
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

pub async fn dispatch_handler(
    current_state: &mut CurrentState,
    events: impl Stream<Item = Event> + Unpin,
    peripherals: &mut HandlerPeripherals,
) {
    pin_mut!(events);

    let mut moved_state = CurrentState::Init;
    core::mem::swap(&mut moved_state, current_state);
    let result = match moved_state {
        CurrentState::POR => init::handle_por(peripherals).await,
        CurrentState::Init => init::handle_init(events, peripherals).await,
        CurrentState::Locked { config } => init::handle_locked(config, events, peripherals).await,
        CurrentState::UnverifiedConfig { config } => {
            init::handle_unverified_config(config, events, peripherals).await
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

            init::handle_generate_seed(num_words, network, password.as_deref(), events, peripherals)
                .await
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

            init::handle_import_seed(&mnemonic, network, password.as_deref(), events, peripherals)
                .await
        }
        CurrentState::Idle { ref mut wallet } => {
            idle::handle_idle(wallet, events, peripherals).await
        }
        CurrentState::WaitingForPsbt { ref mut wallet } => {
            bitcoin::handle_waiting_for_psbt(wallet, events, peripherals).await
        }
        CurrentState::SignPsbt {
            ref mut wallet,
            psbt,
        } => bitcoin::handle_sign_request(wallet, &psbt, events, peripherals).await,
        CurrentState::DisplayAddress {
            ref mut wallet,
            index,
        } => bitcoin::handle_display_address_request(wallet, index, events, peripherals).await,
        CurrentState::PublicDescriptor { ref mut wallet } => {
            bitcoin::handle_public_descriptor_request(wallet, events, peripherals).await
        }
        CurrentState::UpdatingFw { header } => {
            fwupdate::handle_begin_fw_update(&header, events, peripherals).await
        }
        CurrentState::Error => Ok(handle_error(Error::Unknown, peripherals).await),
    };

    // Save power by disabling the TSC after every handler
    peripherals.tsc_enabled.disable();

    // Clear the "finished" queue of messages
    while !peripherals.nfc_finished.is_empty() {
        let _ = peripherals.nfc_finished.recv().await;
    }

    *current_state = match result {
        Ok(new_state) => new_state,
        Err(e) => handle_error(e, peripherals).await,
    }
}

async fn handle_error(err: Error, peripherals: &mut HandlerPeripherals) -> ! {
    #[cfg(feture = "panic-log")]
    log::error!("{:?}", _err);

    let try_draw_message = |peripherals: &mut HandlerPeripherals| -> Result<(), Error> {
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
    mut events: impl Stream<Item = Event> + Unpin,
    peripherals: &mut HandlerPeripherals,
    page: &mut ConfirmBarPage<'s, C>,
) -> Result<(), crate::Error> {
    let mut pressing = false;
    let mut draw;

    while !page.is_confirmed() {
        draw = false;

        match events.next().await.expect("Event") {
            Event::Request(_) => {
                peripherals
                    .nfc
                    .send(Reply::Busy)
                    .await
                    .expect("Send should work");
            }
            Event::Input(v) if v != pressing => {
                pressing = v;
                if !v {
                    page.reset_confirm();
                    draw = true;
                }
            }
            Event::Tick => {
                draw = page.tick();

                if pressing {
                    page.add_confirm(15);
                    draw = true;
                }
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
