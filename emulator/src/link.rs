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

use std::io::SeekFrom;

use tokio::sync::mpsc;

use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics::prelude::*;

use model::emulator::{CardMessage, EmulatorMessage};

use crate::utils::{EmulatorInstance, ReadWrite};

#[derive(Debug)]
pub enum FlashMessage {
    Read(u16),
    Write(u16, Vec<u8>),
}

#[derive(Debug)]
pub enum RtcMessage {
    Read(u8),
    Write(u8, u32),
}

pub struct EmulatorStreams {
    pub display: mpsc::UnboundedReceiver<Vec<u16>>,
    pub flash: mpsc::UnboundedReceiver<FlashMessage>,
    pub rtc: mpsc::UnboundedReceiver<RtcMessage>,
    pub tick: mpsc::UnboundedReceiver<()>,
    pub finish_boot: mpsc::UnboundedReceiver<()>,
}

pub fn stream_incoming_messages(
    mut card_msgs: mpsc::UnboundedReceiver<CardMessage>,
) -> (EmulatorStreams, mpsc::UnboundedReceiver<Vec<u8>>) {
    let (nfc_s, nfc) = mpsc::unbounded_channel();
    let (display_s, display) = mpsc::unbounded_channel();
    let (flash_s, flash) = mpsc::unbounded_channel();
    let (rtc_s, rtc) = mpsc::unbounded_channel();
    let (tick_s, tick) = mpsc::unbounded_channel();
    let (finish_boot_s, finish_boot) = mpsc::unbounded_channel();

    tokio::spawn(async move {
        let mut buffer_display = vec![];

        while let Some(card_message) = card_msgs.recv().await {
            match &card_message {
                CardMessage::FlushDisplay => log::trace!("< FlushDisplay"),
                CardMessage::Display(data) => log::trace!("< Display({})", data.len()),
                CardMessage::Nfc(data) => log::trace!("< Nfc({})", data.len()),
                CardMessage::ReadFlash(page) => log::trace!("< ReadFlash(page={})", page),
                CardMessage::WriteFlash(page, data) => {
                    log::trace!("< WriteFlash(page={}, data_len={})", page, data.len())
                }
                CardMessage::Tick => log::trace!("< Tick"),
                CardMessage::FinishBoot => log::trace!("< FinishBoot"),
                CardMessage::ReadRtcRegister(reg) => log::trace!("< ReadRtcRegister({:02X})", reg),
                CardMessage::WriteRtcRegister(reg, value) => {
                    log::trace!("< WriteRtcRegister({:02X}, {:08X?})", reg, value)
                }
            }
            let result = match card_message {
                CardMessage::Display(data) => {
                    buffer_display.extend(data);
                    Ok(())
                }
                CardMessage::FlushDisplay => {
                    let result = display_s
                        .send(buffer_display.clone())
                        .map_err(|e| e.to_string());
                    if result.is_ok() {
                        buffer_display.clear();
                    }
                    result
                }
                CardMessage::Nfc(data) => nfc_s.send(data).map_err(|e| e.to_string()),
                CardMessage::ReadFlash(page) => flash_s
                    .send(FlashMessage::Read(page))
                    .map_err(|e| e.to_string()),
                CardMessage::WriteFlash(page, data) => flash_s
                    .send(FlashMessage::Write(page, data))
                    .map_err(|e| e.to_string()),
                CardMessage::Tick => tick_s.send(()).map_err(|e| e.to_string()),
                CardMessage::FinishBoot => finish_boot_s.send(()).map_err(|e| e.to_string()),
                CardMessage::ReadRtcRegister(reg) => {
                    rtc_s.send(RtcMessage::Read(reg)).map_err(|e| e.to_string())
                }
                CardMessage::WriteRtcRegister(reg, value) => rtc_s
                    .send(RtcMessage::Write(reg, value))
                    .map_err(|e| e.to_string()),
            };

            if let Err(e) = result {
                log::warn!("Stream error: {:?}", e);
                break;
            }
        }
    });

    (
        EmulatorStreams {
            display,
            flash,
            rtc,
            tick,
            finish_boot,
        },
        nfc,
    )
}

pub fn draw_pixels<DT>(
    display: &mut DT,
    pixels: impl Iterator<Item = u16>,
) -> Result<(), crate::Error>
where
    DT: DrawTarget<Color = BinaryColor>,
    crate::Error: From<<DT as DrawTarget>::Error>,
{
    display.draw_iter(pixels.into_iter().map(|v| {
        let x = (v & 0xFF00) >> 8;
        let y = v & 0x7F;
        let c = match v & 0x80 {
            0 => BinaryColor::Off,
            _ => BinaryColor::On,
        };
        Pixel(Point::new(x as i32, y as i32), c)
    }))?;

    Ok(())
}

pub async fn handle_read_flash(
    flash: &mut impl ReadWrite,
    page: u16,
    card: &mut mpsc::UnboundedSender<EmulatorMessage>,
) -> Result<(), crate::Error> {
    let mut data = [0u8; 2048];

    flash.seek(SeekFrom::Start(page as u64 * 2048))?;
    flash.read(&mut data)?;

    card.send(EmulatorMessage::FlashContent(data.to_vec()))?;

    Ok(())
}

pub fn handle_write_flash(
    flash: &mut impl ReadWrite,
    page: u16,
    data: &[u8],
) -> Result<(), crate::Error> {
    flash.seek(SeekFrom::Start(page as u64 * 2048))?;
    flash.write_all(data)?;

    Ok(())
}

pub async fn wipe_flash(
    flash: &mut impl ReadWrite,
    card: &mut mpsc::UnboundedSender<EmulatorMessage>,
) -> Result<(), crate::Error> {
    flash.seek(SeekFrom::Start(0))?;
    flash.write_all(&[])?;

    card.send(EmulatorMessage::Reset)?;

    Ok(())
}

pub fn try_pull_msg<T>(s: &mut mpsc::UnboundedReceiver<T>) -> Result<Option<T>, String> {
    match s.try_recv() {
        Ok(v) => Ok(Some(v)),
        Err(mpsc::error::TryRecvError::Empty) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

pub async fn manage_hw<F, A>(
    emulator: &mut EmulatorInstance,
    mut append_to_console: F,
    arg: &mut A,
    pull_ticks: bool,
    debug_logs: bool,
) -> Result<bool, crate::Error>
where
    for<'a> F: FnMut(&str, &'a str, &mut A),
{
    let mut updated_display = false;
    while let Some(pixels) = try_pull_msg(&mut emulator.msgs.display)? {
        draw_pixels(&mut emulator.display, pixels.into_iter())?;
        updated_display = true;
    }

    while let Some(flash_msg) = try_pull_msg(&mut emulator.msgs.flash)? {
        match flash_msg {
            FlashMessage::Read(page) => {
                append_to_console("< ", &format!("ReadFlash({})", page), arg);
                handle_read_flash(&mut emulator.flash, page, &mut emulator.card).await?;
            }
            FlashMessage::Write(page, data) => {
                append_to_console("< ", &format!("WriteFlash({})", page), arg);
                handle_write_flash(&mut emulator.flash, page, &data)?;
            }
        }
    }
    while let Some(rtc_msg) = try_pull_msg(&mut emulator.msgs.rtc)? {
        match rtc_msg {
            RtcMessage::Read(reg) => {
                append_to_console("< ", &format!("ReadReg({:02X})", reg), arg);
                emulator
                    .card
                    .send(EmulatorMessage::Rtc(emulator.rtc))
                    .unwrap();
            }
            RtcMessage::Write(reg, value) => {
                append_to_console("< ", &format!("WriteReg({:02X} = {:08X})", reg, value), arg);
                emulator.rtc[reg as usize] = value;
            }
        }
    }

    if pull_ticks {
        while let Some(_) = try_pull_msg::<()>(&mut emulator.msgs.tick)? {}
    }

    if debug_logs {
        while let Ok(l) = emulator.logs.try_recv() {
            log::debug!("{:?}", l);
        }
    }

    if let Some(_) = try_pull_msg(&mut emulator.msgs.finish_boot)? {
        log::debug!("Re-sending entropy");

        // Re-send entropy when the card resets
        emulator
            .card
            .send(EmulatorMessage::Entropy(emulator.entropy.clone()))
            .unwrap();
        emulator
            .card
            .send(EmulatorMessage::Rtc(emulator.rtc))
            .unwrap();
        emulator.sdk.new_tag().await?;
    }

    // Sleep for a little bit: in case of a single-threaded context this will let
    // the runtime move forward the other tasks a bit. Otherwise we might end up
    // in a deadlock while waiting for somewhing to happen
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;

    Ok(updated_display)
}
