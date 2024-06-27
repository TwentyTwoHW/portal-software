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

use noise_protocol::CipherState;

#[derive(Debug)]
pub enum CardMessage {
    Display(alloc::vec::Vec<u16>),
    Nfc(alloc::vec::Vec<u8>),
    WriteFlash(u16, alloc::vec::Vec<u8>),
    ReadFlash(u16),
    Tick,
    FinishBoot,
    FlushDisplay,
    ReadRtcRegister(u8),
    WriteRtcRegister(u8, u32),
}

#[cfg(feature = "stm32")]
impl CardMessage {
    pub fn write_to(self) -> alloc::boxed::Box<dyn Iterator<Item = u8>> {
        match self {
            CardMessage::Display(pixels) => alloc::boxed::Box::new(
                [0x00]
                    .into_iter()
                    .chain(u16::to_be_bytes(pixels.len() as u16 * 2).into_iter())
                    .chain(
                        pixels
                            .into_iter()
                            .map(|v| [((v & 0xFF00) >> 8) as u8, (v & 0xFF) as u8])
                            .flatten(),
                    ),
            ),
            CardMessage::Nfc(reply) => alloc::boxed::Box::new(
                [0x01]
                    .into_iter()
                    .chain(u16::to_be_bytes(reply.len() as _).into_iter())
                    .chain(reply.into_iter()),
            ),
            CardMessage::Tick => alloc::boxed::Box::new([0x02].into_iter()),
            CardMessage::WriteFlash(page, data) => alloc::boxed::Box::new(
                [0x03]
                    .into_iter()
                    .chain(u16::to_be_bytes(data.len() as u16 + 2).into_iter())
                    .chain(u16::to_be_bytes(page).into_iter())
                    .chain(data.into_iter()),
            ),
            CardMessage::ReadFlash(page) => alloc::boxed::Box::new(
                [0x04, 0x00, 0x02]
                    .into_iter()
                    .chain(u16::to_be_bytes(page).into_iter()),
            ),
            CardMessage::FinishBoot => alloc::boxed::Box::new([0x05].into_iter()),
            CardMessage::FlushDisplay => alloc::boxed::Box::new([0x06].into_iter()),
            CardMessage::ReadRtcRegister(register) => {
                alloc::boxed::Box::new([0x07, 0x00, 0x01, register].into_iter())
            }
            CardMessage::WriteRtcRegister(register, value) => alloc::boxed::Box::new(
                [0x08, 0x00, 0x05, register]
                    .into_iter()
                    .chain(u32::to_be_bytes(value)),
            ),
        }
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub enum EmulatorMessage {
    Tsc(bool),
    Nfc(alloc::vec::Vec<u8>),
    FlashContent(alloc::vec::Vec<u8>),
    Reset,
    Entropy([u8; 32]),
    Rtc([u32; 32]),
}

impl EmulatorMessage {
    pub fn from_request<C: noise_protocol::Cipher>(
        req: &super::Request,
        cipher: &mut CipherState<C>,
    ) -> Self {
        let msg = crate::Message::new_serialize(req, cipher).unwrap();
        EmulatorMessage::Nfc(msg.data().to_vec())
    }

    pub fn encode(&self) -> alloc::vec::Vec<u8> {
        match self {
            EmulatorMessage::Tsc(v) => {
                alloc::vec![0x01, 0x00, 0x01, if *v { 0x01 } else { 0x00 }]
            }
            EmulatorMessage::Nfc(req) => {
                let mut v = alloc::vec![0x02];
                v.extend_from_slice(&u16::to_be_bytes(req.len() as u16));
                v.extend_from_slice(&req);
                v
            }
            EmulatorMessage::FlashContent(data) => {
                let mut v = alloc::vec![0x03];
                v.extend_from_slice(&u16::to_be_bytes(data.len() as u16));
                v.extend_from_slice(&data);
                v
            }
            EmulatorMessage::Reset => {
                alloc::vec![0x04]
            }
            EmulatorMessage::Entropy(data) => {
                let mut v = alloc::vec![0x05, 0x00, 0x20];
                v.extend_from_slice(data);
                v
            }
            EmulatorMessage::Rtc(value) => {
                let mut v = alloc::vec![0x06, 0x00, 0x80];
                v.extend(value.iter().map(|v| v.to_be_bytes()).flatten());
                v
            }
        }
    }

    pub fn to_string(&self) -> alloc::string::String {
        #[allow(unused_imports)]
        use alloc::string::ToString;

        match self {
            EmulatorMessage::Tsc(v) => alloc::format!("Tsc({})", v),
            EmulatorMessage::Reset => "Reset".to_string(),
            EmulatorMessage::Nfc(bytes) => alloc::format!("Nfc({:02X?})", bytes),
            EmulatorMessage::FlashContent(_) => "FlashContent(...)".to_string(),
            EmulatorMessage::Entropy(data) => alloc::format!("Entropy({:02X?})", data),
            EmulatorMessage::Rtc(_) => alloc::format!("Rtc"),
        }
    }
}
