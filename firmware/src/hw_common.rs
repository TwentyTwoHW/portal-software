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
use core::cell::RefCell;

use model::{Reply, Request};

#[cfg(feature = "device")]
use cortex_m::peripheral::NVIC;
#[cfg(feature = "device")]
use hal::interrupt;

pub type ChannelSender<T> = rtic_sync::channel::Sender<'static, T, 1>;
pub type ChannelReceiver<T> = rtic_sync::channel::Receiver<'static, T, 1>;

pub struct NfcChannelsLocal {
    pub outgoing: ChannelReceiver<Reply>,
    pub incoming: ChannelSender<Request>,
}
pub struct NfcChannelsShared {
    pub outgoing: ChannelSender<Reply>,
    pub incoming: ChannelReceiver<Request>,
}

pub fn make_nfc_channels() -> (NfcChannelsLocal, NfcChannelsShared) {
    let (request_sender, request_receiver) = rtic_sync::make_channel!(Request, 1);
    let (reply_sender, reply_receiver) = rtic_sync::make_channel!(Reply, 1);

    let local = NfcChannelsLocal {
        outgoing: reply_receiver,
        incoming: request_sender,
    };
    let shared = NfcChannelsShared {
        outgoing: reply_sender,
        incoming: request_receiver,
    };

    (local, shared)
}

pub struct TscEnable {
    bool_ref: Rc<RefCell<bool>>,
}

impl TscEnable {
    pub fn new(bool_ref: Rc<RefCell<bool>>) -> Self {
        TscEnable { bool_ref }
    }

    pub fn enable(&self) {
        *self.bool_ref.borrow_mut() = true;

        // Trigger interrupt
        #[cfg(feature = "device")]
        NVIC::pend(interrupt::TSC);
    }
    pub fn disable(&self) {
        *self.bool_ref.borrow_mut() = false;
    }
}
