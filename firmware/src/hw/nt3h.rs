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

use hal::gpio;
use hal::i2c::{self, I2c};
use hal::prelude::*;

use futures::prelude::*;

use rtic_monotonics::systick::*;

use model::reg::*;
use model::write_buffer::*;
use model::{Message, MessageFragment, Reply, Request};

use crate::hw;
use crate::Error;

#[allow(dead_code)]
pub const NT3H_ADDR: u8 = 0x55;

#[allow(dead_code)]
pub const BLOCK_SESSION_REGISTERS: u8 = 0xFE;
#[allow(dead_code)]
pub const BLOCK_CONFIGURATION_REGISTERS: u8 = 0x3A;
#[allow(dead_code)]
pub const BLOCK_SRAM: u8 = 0xF8;

#[allow(dead_code)]
pub const SESSION_REG_NC_REG: u8 = 0x00;
#[allow(dead_code)]
pub const SESSION_REG_LAST_NDEF_BLOCK: u8 = 0x01;
#[allow(dead_code)]
pub const SESSION_REG_SRAM_MIRROR_BLOCK: u8 = 0x02;
#[allow(dead_code)]
pub const SESSION_REG_WDT_LS: u8 = 0x03;
#[allow(dead_code)]
pub const SESSION_REG_WDT_MS: u8 = 0x04;
#[allow(dead_code)]
pub const SESSION_REG_I2C_CLOCK_STR: u8 = 0x05;
#[allow(dead_code)]
pub const SESSION_REG_NS_REG: u8 = 0x06;

const MAX_TRIES: usize = 8;

struct HostWriteBuffer;

impl WriteBufferInit<17, 4, 0> for HostWriteBuffer {
    fn new() -> WriteBuffer<17, 4, 0> {
        let mut b0 = [0u8; 17];
        b0[0] = BLOCK_SRAM;
        let mut b1 = [0u8; 17];
        b1[0] = BLOCK_SRAM + 1;
        let mut b2 = [0u8; 17];
        b2[0] = BLOCK_SRAM + 2;
        let mut b3 = [0u8; 17];
        b3[0] = BLOCK_SRAM + 3;

        let buffer = [b0, b1, b2, b3];

        Self::init_fields(buffer)
    }
}

pub struct Nt3h<I2C, I2C_PINS> {
    i2c: I2c<I2C, I2C_PINS>,
    interrupt: hw::ChannelReceiver<()>,
    finished: hw::ChannelSender<()>,
}

impl<I2C, I2C_PINS> Nt3h<I2C, I2C_PINS>
where
    I2C: 'static,
    I2C_PINS: 'static,
    I2c<I2C, I2C_PINS>: ehal::blocking::i2c::WriteRead + ehal::blocking::i2c::Write,
    Error: From<<I2c<I2C, I2C_PINS> as ehal::blocking::i2c::WriteRead>::Error>,
    Error: From<<I2c<I2C, I2C_PINS> as ehal::blocking::i2c::Write>::Error>,
{
    pub fn new<P: gpio::ExtiPin>(
        i2c: I2c<I2C, I2C_PINS>,
        fd_pin: P,
    ) -> Result<(Self, NfcInterrupt<P>, hw::ChannelReceiver<()>), Error> {
        type Empty = ();

        let (sender, receiver) = rtic_sync::make_channel!(Empty, 1);
        let (finished, nfc_finished_receiver) = rtic_sync::make_channel!(Empty, 1);
        let nfc_interrupt = NfcInterrupt { sender, fd_pin };
        Ok((
            Nt3h {
                i2c,
                interrupt: receiver,
                finished,
            },
            nfc_interrupt,
            nfc_finished_receiver,
        ))
    }

    async fn do_exp_delay<F, A, R>(&mut self, func: F, arg: &mut A) -> Result<R, Error>
    where
        F: Fn(&mut Self, &mut A) -> Result<R, Error>,
        A: ?Sized,
    {
        let mut delay = 2;

        for _ in 0..MAX_TRIES {
            match func(self, arg) {
                Err(Error::I2c(i2c::Error::Nack)) => {
                    Systick::delay(delay.millis()).await;
                    delay *= 2;
                }
                x => return x,
            }
        }

        Err(Error::TooManyNacks)
    }

    async fn write_read_exp_delay(
        &mut self,
        addr: u8,
        reg: &[u8],
        buf: &mut [u8],
    ) -> Result<(), Error> {
        self.do_exp_delay(
            |mut_self, buf| Ok(mut_self.i2c.write_read(addr, reg, buf)?),
            buf,
        )
        .await
    }

    async fn write_exp_delay(&mut self, addr: u8, buf: &[u8]) -> Result<(), Error> {
        self.do_exp_delay(|mut_self, _| Ok(mut_self.i2c.write(addr, buf)?), &mut ())
            .await
    }

    async fn write_to_mailbox<I: Iterator<Item = MessageFragment>>(
        &mut self,
        fragments: I,
    ) -> Result<(), Error> {
        // Flip the direction
        let new_nc_reg = NC_REG::new()
            .with_TRANSFER_DIR(TransferDir::HostToNfc)
            .with_PTHRU_ON_OFF(true);
        self.write_exp_delay(
            NT3H_ADDR,
            &[
                BLOCK_SESSION_REGISTERS,
                SESSION_REG_NC_REG,
                0b01000001,
                new_nc_reg.into_bytes()[0],
            ],
        )
        .await?;

        for fragment in fragments {
            let mut buffer = HostWriteBuffer::new();
            buffer.append(&fragment);

            for part in buffer.get_data() {
                // rdbg!(&part);
                self.write_exp_delay(NT3H_ADDR, part).await?;
            }

            self.wait_for_rf_read(WaitMode::Interrupt).await?;
        }

        Ok(())
    }

    async fn read_from_mailbox<'b>(&mut self, buf: &'b mut [u8; 64]) -> Result<(), Error> {
        for i in 0usize..4 {
            self.write_read_exp_delay(
                NT3H_ADDR,
                &[BLOCK_SRAM + i as u8],
                &mut buf[(16 * i)..(16 * (i + 1))],
            )
            .await?;
        }

        Ok(())
    }
    async fn read_from_mailbox_message(&mut self) -> Result<MessageFragment, Error> {
        // TODO: ideally avoid copying
        let mut buf = [0u8; 64];

        self.read_from_mailbox(&mut buf).await?;
        let fragment = MessageFragment::from(buf.as_slice());

        Ok(fragment)
    }

    async fn wait_for(&mut self, what: WaitFor, mode: WaitMode) -> Result<(), Error> {
        macro_rules! do_wait {
            ($s:expr, $what:expr) => {
                match $what {
                    WaitFor::Read => $s.check_rf_read().await,
                    WaitFor::Write => $s.check_rf_write().await,
                }
            };
        }

        while !do_wait!(self, what)? {
            match mode {
                #[allow(deprecated)]
                WaitMode::Delay { ms } => Systick::delay(ms.millis()).await,
                WaitMode::Interrupt => self.interrupt.recv().await.expect("Should always work"),
            }
        }

        Ok(())
    }

    async fn check_rf_read(&mut self) -> Result<bool, Error> {
        Ok(!self.read_NS_REG().await?.SRAM_RF_READY())
    }

    async fn check_rf_write(&mut self) -> Result<bool, Error> {
        let ns_reg = self.read_NS_REG().await?;

        if ns_reg.SRAM_I2C_READY() {
            Ok(true)
        } else if !ns_reg.RF_LOCKED() {
            let new_nc_reg = NC_REG::new().with_PTHRU_ON_OFF(true);
            self.write_exp_delay(
                NT3H_ADDR,
                &[
                    BLOCK_SESSION_REGISTERS,
                    SESSION_REG_NC_REG,
                    0b01000000,
                    new_nc_reg.into_bytes()[0],
                ],
            )
            .await?;

            Ok(false)
        } else {
            Ok(false)
        }
    }

    #[allow(non_snake_case)]
    async fn read_NS_REG(&mut self) -> Result<NS_REG, Error> {
        let mut buffer = [0u8; 1];

        self.write_read_exp_delay(
            NT3H_ADDR,
            &[BLOCK_SESSION_REGISTERS, SESSION_REG_NS_REG],
            &mut buffer,
        )
        .await?;
        Ok(NS_REG::from_bytes(buffer))
    }

    pub async fn apply_configuration(&mut self) -> Result<(), Error> {
        let new_nc_reg = NC_REG::new()
            .with_FD_ON(FdOn::NfcDone)
            .with_FD_OFF(FdOff::HostDone);
        self.write_exp_delay(
            NT3H_ADDR,
            &[
                BLOCK_SESSION_REGISTERS,
                SESSION_REG_NC_REG,
                0b00111100,
                new_nc_reg.into_bytes()[0],
            ],
        )
        .await?;

        Ok(())
    }

    async fn wait_for_rf_read(&mut self, mode: WaitMode) -> Result<(), Error> {
        self.wait_for(WaitFor::Read, mode).await
    }

    async fn wait_for_rf_write(&mut self, mode: WaitMode) -> Result<(), Error> {
        // Set transfer direction
        let new_nc_reg = NC_REG::new()
            .with_TRANSFER_DIR(TransferDir::NfcToHost)
            .with_PTHRU_ON_OFF(true);
        self.write_exp_delay(
            NT3H_ADDR,
            &[
                BLOCK_SESSION_REGISTERS,
                SESSION_REG_NC_REG,
                0b01000001,
                new_nc_reg.into_bytes()[0],
            ],
        )
        .await?;

        self.wait_for(WaitFor::Write, mode).await
    }

    async fn read_raw_message(&mut self) -> Result<Message, Error> {
        let mut msg = Message::empty();

        loop {
            futures::select_biased! {
                v = self.wait_for_rf_write(WaitMode::Interrupt).fuse() => v?,
                _ = Systick::delay(250.millis()).fuse() => {
                    continue;
                },
            }

            if msg.push_fragment(self.read_from_mailbox_message().await?)? {
                break;
            }
        }

        Ok(msg)
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

#[derive(Debug)]
pub enum WaitMode {
    #[allow(dead_code)]
    #[deprecated(note = "Should only be used for debugging purposes")]
    Delay {
        ms: u32,
    },
    Interrupt,
}

#[derive(Debug, Clone, Copy)]
pub enum WaitFor {
    Read,
    Write,
}

pub struct NfcInterrupt<P: gpio::ExtiPin> {
    pub sender: hw::ChannelSender<()>,
    pub fd_pin: P,
}
