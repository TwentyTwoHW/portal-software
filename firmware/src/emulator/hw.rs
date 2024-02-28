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
use alloc::vec::Vec;

use core::cell::RefCell;

use embedded_graphics_core::pixelcolor::BinaryColor;
use rand::SeedableRng;

use stm32f4xx_hal::prelude::*;
use stm32f4xx_hal::serial;

use embedded_graphics_core::geometry::OriginDimensions;
use embedded_graphics_core::prelude::*;

use model::emulator as emu_model;
use model::{reg::NS_REG, Message, MessageFragment, Reply, Request};

use super::*;
use crate::hw_common;
use crate::Error;

pub type NfcInterrupt = hw_common::ChannelSender<()>;

pub struct EmulatorChannels {
    pub tsc: hw_common::ChannelSender<bool>,
    pub flash: hw_common::ChannelSender<Vec<u8>>,
    pub emulated_nt3h: EmulatedNT3H,
}

pub fn init_peripherals(
    dp: hal::pac::Peripherals,
    cp: cortex_m::Peripherals,
) -> Result<
    (
        NfcIc,
        NfcInterrupt,
        hw_common::ChannelReceiver<()>,
        Display,
        Tsc,
        rand_chacha::ChaCha20Rng,
        Flash,
    ),
    crate::Error,
> {
    let clocks = unsafe { create_fake_clocks_pclk2_8mhz() };

    let systick_token = rtic_monotonics::create_systick_token!();
    rtic_monotonics::systick::Systick::start(cp.SYST, 168_000_000, systick_token);

    let gpioa = dp.GPIOA.split();

    let tx_pin = gpioa.pa9.into_alternate();
    let rx_pin = gpioa.pa10.into_alternate();

    let mut serial = dp
        .USART1
        .serial::<u8>(
            (tx_pin, rx_pin),
            serial::Config::default()
                .baudrate(921600.bps())
                .wordlength_8()
                .parity_none(),
            &clocks,
        )
        .unwrap();
    serial.listen(serial::Event::Rxne);
    set_serial(serial);

    let (nfc, nfc_interrupt, nfc_finished) = NfcIc::new();
    let rng = rand_chacha::ChaCha20Rng::from_seed([0u8; 32]);

    Ok((
        nfc,
        nfc_interrupt,
        nfc_finished,
        Display::new(),
        Tsc::new(),
        rng,
        Flash::new(),
    ))
}

pub struct Tsc {
    enabled: Rc<RefCell<bool>>,
}

impl Tsc {
    fn new() -> Self {
        Tsc {
            enabled: Rc::new(RefCell::new(false)),
        }
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
}

pub struct NfcIc {
    interrupt: hw_common::ChannelReceiver<()>,
    finished: hw_common::ChannelSender<()>,

    incoming_s: Option<hw_common::ChannelSender<[u8; 64]>>,
    incoming_r: hw_common::ChannelReceiver<[u8; 64]>,

    outgoing_s: hw_common::ChannelSender<[u8; 64]>,
    outgoing_r: Option<hw_common::ChannelReceiver<[u8; 64]>>,
}

type Buffer = [u8; 64];

impl NfcIc {
    fn new() -> (
        Self,
        hw_common::ChannelSender<()>,
        hw_common::ChannelReceiver<()>,
    ) {
        type Empty = ();

        let (sender, receiver) = rtic_sync::make_channel!(Empty, 1);
        let (finished, nfc_finished_receiver) = rtic_sync::make_channel!(Empty, 1);

        let (incoming_s, incoming_r) = rtic_sync::make_channel!(Buffer, 1);
        let (outgoing_s, outgoing_r) = rtic_sync::make_channel!(Buffer, 1);

        (
            NfcIc {
                interrupt: receiver,
                finished,

                incoming_r,
                incoming_s: Some(incoming_s),
                outgoing_r: Some(outgoing_r),
                outgoing_s,
            },
            sender,
            nfc_finished_receiver,
        )
    }

    async fn read_raw_message(&mut self) -> Result<Message, Error> {
        let mut msg = Message::empty();

        loop {
            let buffer = self.incoming_r.recv().await.unwrap();

            // log::debug!("buffer content: {:02X?}", self.buffer);
            let fragment = MessageFragment::from(buffer.as_ref());
            if msg.push_fragment(fragment)? {
                break;
            }
        }

        Ok(msg)
    }

    async fn write_to_mailbox<I: Iterator<Item = MessageFragment>>(
        &mut self,
        fragments: I,
    ) -> Result<(), Error> {
        for fragment in fragments.into_iter() {
            self.outgoing_s
                .send(fragment.get_raw_buf().try_into().unwrap())
                .await
                .unwrap();
            // Wait for the read
            let _ = self.interrupt.recv().await;
        }

        Ok(())
    }

    pub async fn apply_configuration(&mut self) -> Result<(), Error> {
        Ok(())
    }

    pub async fn read_handshake(&mut self) -> Result<alloc::vec::Vec<u8>, Error> {
        let msg = self.read_raw_message().await?;
        Ok(msg.data().to_vec())
    }

    pub async fn send_handshake_reply(&mut self, reply: &[u8]) -> Result<(), Error> {
        let msg = Message::from_slice(reply);
        self.write_to_mailbox(msg.get_fragments().into_iter())
            .await?;
        Ok(())
    }

    pub async fn accept_request(
        &mut self,
        decrypt: &mut ::model::encryption::CipherState,
    ) -> Result<Request, Error> {
        let msg = self.read_raw_message().await?;
        let mut decrypt_buf = alloc::vec::Vec::new();

        match msg.deserialize(&mut decrypt_buf, decrypt) {
            Ok(v) => Ok(v),
            Err(e) => {
                self.write_to_mailbox([MessageFragment::new_failed_decryption()].into_iter())
                    .await?;
                Err(e.into())
            }
        }
    }

    pub async fn send_reply(
        &mut self,
        reply: &Reply,
        encrypt: &mut ::model::encryption::CipherState,
    ) -> Result<(), Error> {
        let message = Message::new_serialize(reply, encrypt)?;
        self.write_to_mailbox(message.get_fragments().into_iter())
            .await?;

        match reply {
            Reply::Pong | Reply::DelayedReply => {}
            _ => {
                let _ = self.finished.send(()).await;
            }
        }

        Ok(())
    }
}

pub struct EmulatedNT3H {
    buffer: [u8; 64],
    status: NS_REG,
    interrupt: hw_common::ChannelSender<()>,
    incoming: hw_common::ChannelSender<[u8; 64]>,
    outgoing: hw_common::ChannelReceiver<[u8; 64]>,
}

impl EmulatedNT3H {
    pub fn new(interrupt: hw_common::ChannelSender<()>, nfc: &mut NfcIc) -> Self {
        EmulatedNT3H {
            buffer: [0; 64],
            status: NS_REG::new().with_RF_LOCKED(true),
            interrupt,

            incoming: nfc.incoming_s.take().unwrap(),
            outgoing: nfc.outgoing_r.take().unwrap(),
        }
    }

    pub fn handle_cmd(&mut self) {
        let data = super::read_serial();

        if let Ok(data) = self.outgoing.try_recv() {
            self.buffer = data;
            self.status = self.status.clone().with_SRAM_RF_READY(true);
        }

        let reply = match data[0] {
            // Read session reg
            0x30 if data[1] == 0xED => {
                alloc::vec![
                    0x00,                                // WDT_MS
                    0x00,                                // I2C_CLOCK_STR
                    self.status.clone().into_bytes()[0], // NS_REG
                    0x00,                                // RFU
                ]
            }
            // Read last page
            0x30 if data[1] == 0xFF => {
                self.status = self.status.clone().with_SRAM_RF_READY(false);
                alloc::vec![0x00; 8]
            }

            // Write SRAM
            0xA6 => {
                assert!(data[1] == 0xF0 && data[2] == 0xFF);

                self.buffer.copy_from_slice(&data[3..]);
                self.incoming
                    .try_send(self.buffer.clone())
                    .expect("Send works");

                alloc::vec![0x0a]
            }
            // Read SRAM
            0x3A => {
                assert!(data[1] == 0xF0 && data[2] == 0xFF);

                self.status = self.status.clone().with_SRAM_RF_READY(false);
                self.interrupt.try_send(()).unwrap();

                self.buffer.into()
            }

            _ => alloc::vec![0x00],
        };

        let msg = emu_model::CardMessage::Nfc(reply);
        super::write_serial(msg.write_to());
    }
}

pub fn report_tick() {
    let msg = emu_model::CardMessage::Tick;
    super::write_serial(msg.write_to());
}
pub fn report_finish_boot() {
    let msg = emu_model::CardMessage::FinishBoot;
    super::write_serial(msg.write_to());
}

pub struct Display;

impl Display {
    fn new() -> Self {
        Display
    }

    pub fn flush(&mut self) -> Result<(), crate::Error> {
        let msg = emu_model::CardMessage::FlushDisplay;
        super::write_serial(msg.write_to());
        Ok(())
    }
}

impl OriginDimensions for Display {
    fn size(&self) -> Size {
        Size::new(128, 64)
    }
}
impl DrawTarget for Display {
    type Color = BinaryColor;
    type Error = crate::Error;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        let pixels = pixels
            .into_iter()
            .map(|p| {
                let c = match p.1 {
                    BinaryColor::On => 0x80,
                    BinaryColor::Off => 0x00,
                };
                (p.0.x << 8) as u16 | (p.0.y & 0xFF) as u16 | c
            })
            .collect::<alloc::vec::Vec<u16>>();

        if !pixels.is_empty() {
            let msg = emu_model::CardMessage::Display(pixels);
            super::write_serial(msg.write_to());
        }

        Ok(())
    }
}

pub struct Flash {
    channel: RefCell<Option<hw_common::ChannelReceiver<Vec<u8>>>>,
    pub fb_mode: bool,
}

impl Flash {
    fn new() -> Self {
        Flash {
            channel: RefCell::new(None),
            fb_mode: true,
        }
    }

    pub fn set_channel(&self, channel: hw_common::ChannelReceiver<Vec<u8>>) {
        *self.channel.borrow_mut() = Some(channel);
    }

    pub async fn read(&self) -> Vec<u8> {
        let msg = emu_model::CardMessage::ReadFlash;
        super::write_serial(msg.write_to());

        self.channel
            .borrow_mut()
            .as_mut()
            .expect("The channel should be set during initialization")
            .recv()
            .await
            .expect("Channel is always alive")
    }

    pub fn write(&self, data: &[u8]) {
        let msg = emu_model::CardMessage::WriteFlash(data.to_vec());
        super::write_serial(msg.write_to());
    }
}

unsafe fn create_fake_clocks_pclk2_8mhz() -> hal::rcc::Clocks {
    const SIZE: usize = core::mem::size_of::<hal::rcc::Clocks>();

    let mut data = [0u32; SIZE / 4];
    for i in 0..SIZE {
        data[i] = 8_000_000;
        let copy = core::mem::transmute_copy::<_, hal::rcc::Clocks>(&data);
        if copy.pclk2() == 8.MHz::<1, 1>() {
            return copy;
        }
    }

    unreachable!()
}

pub fn enable_debug_during_sleep(_: &mut hal::pac::Peripherals) {}
