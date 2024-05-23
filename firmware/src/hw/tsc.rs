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

use hal::{stm32, tsc};

const TSC_THRESHOLD: u16 = 1200;

pub struct Tsc<SAMPLE_PIN, CHANNEL_PIN> {
    tsc: tsc::Tsc<SAMPLE_PIN>,
    channel_pin: CHANNEL_PIN,
    enabled: Rc<RefCell<bool>>,
}

impl<SAMPLE_PIN, CHANNEL_PIN> Tsc<SAMPLE_PIN, CHANNEL_PIN>
where
    SAMPLE_PIN: tsc::SamplePin<stm32::TSC>,
    CHANNEL_PIN: tsc::ChannelPin<stm32::TSC>,
{
    pub fn new(tsc: tsc::Tsc<SAMPLE_PIN>, channel_pin: CHANNEL_PIN) -> Self {
        Tsc {
            tsc,
            channel_pin,
            enabled: Rc::new(RefCell::new(false)),
        }
    }

    pub fn is_enabled(&self) -> bool {
        *self.enabled.borrow()
    }

    pub fn enable(&mut self) {
        *self.enabled.borrow_mut() = true;
    }
    pub fn disable(&mut self) {
        *self.enabled.borrow_mut() = false;
    }

    pub fn get_enabled_ref(&self) -> Rc<RefCell<bool>> {
        Rc::clone(&self.enabled)
    }

    pub fn start_acquisition(&mut self) {
        if !self.tsc.in_progress() {
            self.tsc.start(&mut self.channel_pin);
        }
    }

    pub fn perform_read(&self) -> bool {
        self.tsc.read_unchecked() < TSC_THRESHOLD
    }
}
