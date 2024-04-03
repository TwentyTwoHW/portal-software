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

use alloc::vec::Vec;

use core::cell::RefCell;

use cortex_m::interrupt::{free, Mutex};

use stm32f4xx_hal::prelude::*;
use stm32f4xx_hal::serial;

pub mod config;
pub mod hw;

static SERIAL: Mutex<RefCell<Option<serial::Serial<hal::pac::USART1>>>> =
    Mutex::new(RefCell::new(None));

pub(super) fn set_serial(s: serial::Serial<hal::pac::USART1>) {
    free(|cs| {
        SERIAL.borrow(cs).borrow_mut().replace(s);
    });
}

fn read_wait(serial: &mut serial::Serial<hal::pac::USART1>) -> u8 {
    loop {
        match serial.read() {
            Ok(v) => break v,
            Err(_) => continue,
        }
    }
}

pub(super) fn serial_interrupt() -> Option<PeripheralIncomingMsg> {
    free(|cs| {
        let mut serial = SERIAL.borrow(cs).borrow_mut();
        let serial = serial.as_mut().unwrap();

        if serial.is_rx_not_empty() {
            let b = read_wait(serial);
            PeripheralIncomingMsg::from_u8(b)
        } else {
            None
        }
    })
}

pub(super) fn read_serial() -> Vec<u8> {
    free(|cs| {
        let mut serial = SERIAL.borrow(cs).borrow_mut();
        let serial = serial.as_mut().unwrap();

        let mut buffer = Vec::<u8>::new();
        let len = u16::from_be_bytes([read_wait(serial), read_wait(serial)]);
        for _ in 0..len {
            let v = read_wait(serial);
            buffer.push(v);
        }

        buffer
    })
}

pub(super) fn write_serial(data: impl Iterator<Item = u8>) {
    free(|cs| {
        let mut serial = SERIAL.borrow(cs).borrow_mut();
        let serial = serial.as_mut().unwrap();

        let data = data.collect::<alloc::vec::Vec<_>>();
        serial.bwrite_all(&data).unwrap();
        serial.bflush().unwrap();
    });
}

// pub(super) fn write_serial_iter(mut i: impl Iterator<Item = u8>) {
//     free(|cs| {
//         let mut serial = SERIAL.borrow(cs).borrow_mut();
//         let serial = serial.as_mut().unwrap();
//
//         while let Some(v) = i.next() {
//             serial.bwrite_all(&[v]).unwrap();
//         }
//         serial.bflush().unwrap();
//     });
// }

#[derive(Debug, PartialEq, Eq)]
pub enum PeripheralIncomingMsg {
    Tsc,
    Nfc,
    FlashContent,
    Reset,
    Entropy,
}

impl PeripheralIncomingMsg {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(PeripheralIncomingMsg::Tsc),
            0x02 => Some(PeripheralIncomingMsg::Nfc),
            0x03 => Some(PeripheralIncomingMsg::FlashContent),
            0x04 => Some(PeripheralIncomingMsg::Reset),
            0x05 => Some(PeripheralIncomingMsg::Entropy),
            _ => None,
        }
    }
}

/// Semihosting target that writes using SYS_WRITEC
///
/// This differs from the more commonly used stdout (SYS_OPEN and then SYS_WRITE). Specifically,
/// QEMU only allows redirecting console outputs to arbitrary chardevs (like files),
/// while it always writes to stdout if the target uses it.
pub struct SemihostingConsole;

impl core::fmt::Write for SemihostingConsole {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for byte in s.as_bytes() {
            unsafe { cortex_m_semihosting::syscall!(WRITEC, *byte) };
        }

        Ok(())
    }
}

impl cortex_m_log::destination::semihosting::SemihostingComp for SemihostingConsole {}
