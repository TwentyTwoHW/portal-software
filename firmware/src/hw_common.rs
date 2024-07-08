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

#[cfg(feature = "emulator")]
use crate::emulator::flash;
#[cfg(feature = "device")]
use stm32l4xx_hal::flash;

pub type ChannelSender<T> = rtic_sync::channel::Sender<'static, T, 1>;
pub type ChannelReceiver<T> = rtic_sync::channel::Receiver<'static, T, 1>;

pub const PAGE_SIZE: usize = 2048;
pub const MAX_FW_PAGES: usize = 508;

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

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BankToFlash {
    pub physical: FlashBank,
}

impl BankToFlash {
    pub fn new(physical: FlashBank) -> Self {
        BankToFlash { physical }
    }

    pub fn physical_bank_page(bank: FlashBank, page: usize) -> flash::FlashPage {
        match bank {
            FlashBank::Bank1 => flash::FlashPage(page),
            FlashBank::Bank2 => flash::FlashPage(page + 256),
        }
    }

    pub fn get_logical_address(&self, which: BankStatus, page: usize) -> usize {
        let physical_bank = match which {
            BankStatus::Active => FlashBank::Bank1,
            BankStatus::Spare => FlashBank::Bank2,
        };
        Self::physical_bank_page(physical_bank, page).to_address()
    }

    pub fn get_physical_page(&self, which: BankStatus, page: usize) -> flash::FlashPage {
        let physical_bank = match which {
            BankStatus::Active => self.physical.opposite(),
            BankStatus::Spare => self.physical,
        };
        Self::physical_bank_page(physical_bank, page)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BankStatus {
    Active,
    Spare,
}

/// Flash bank to target for a read/write/erase operation
///
/// **NOTE**: unfortunately the meaning of `Bank1` and `Bank2` is not always consistent
/// in the code: specifically, when peforming an erase operation the `FlashBank` refers
/// to the actual physical bank being erased, no matter what bank is booted at the moment.
///
/// When performing a read or write operation `Bank1` refers to the currently-booted bank,
/// while `Bank2` refers to the spare bank. This is because the stm32l4xx-hal crate writes
/// directly to the flash memory address, and when using dual bank boot the "current bank"
/// is always mapped at 0x0000_0000 and 0x0800_0000, independently of which physical bank
/// is backing it.
///
/// A good rule of thumb is that when an API takes an address it uses the "relative",
/// mapping-dependent bank, while when it takes a `FlashPage` it's probably using absolute
/// addressing.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FlashBank {
    Bank1,
    Bank2,
}

impl FlashBank {
    pub fn opposite(&self) -> Self {
        match self {
            FlashBank::Bank1 => FlashBank::Bank2,
            FlashBank::Bank2 => FlashBank::Bank1,
        }
    }
}
