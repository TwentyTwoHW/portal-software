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

#![cfg_attr(feature = "emulator", allow(dead_code, unused_variables))]

use alloc::boxed::Box;
use core::{ops::Deref, str::FromStr};

use futures::prelude::*;

use rtic_monotonics::systick::ExtU32;

#[cfg(feature = "device")]
use stm32l4xx_hal::{flash, flash::Read, flash::WriteErase, stm32};

use bitcoin_hashes::{sha256, Hash, HashEngine};

use minicbor::bytes::ByteArray;

use gui::{FwUpdateProgressPage, SingleLineTextPage, SummaryPage};

use super::*;
use crate::Error;

const FIRMWARE_SIGNING_KEY: &'static str =
    "1608bd04cf3212070b3de57f4a2ad8e5108a103af037f878ec75f4a2068de610";

const CHECKPOINT_PAGE_INTERVAL: usize = 8;

// #[cfg_attr(feature = "emulator", allow(dead_code))]
// const FLASH_OPTKEY1: u32 = 0x0819_2A3B;
// #[cfg_attr(feature = "emulator", allow(dead_code))]
// const FLASH_OPTKEY2: u32 = 0x4C5D_6E7F;

#[cfg(feature = "device")]
type UnlockedFlash<'a> = flash::FlashProgramming<'a>;
#[cfg(feature = "emulator")]
type UnlockedFlash = ();

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct BankToFlash {
    physical: FlashBank,
}

impl BankToFlash {
    pub fn new(physical: FlashBank) -> Self {
        BankToFlash { physical }
    }

    #[cfg(feature = "device")]
    fn physical_bank_page(bank: FlashBank, page: usize) -> flash::FlashPage {
        match bank {
            FlashBank::Bank1 => flash::FlashPage(page),
            FlashBank::Bank2 => flash::FlashPage(page + 256),
        }
    }

    #[cfg(feature = "device")]
    fn get_logical_address(&self, which: BankStatus, page: usize) -> usize {
        let physical_bank = match which {
            BankStatus::Active => FlashBank::Bank1,
            BankStatus::Spare => FlashBank::Bank2,
        };
        Self::physical_bank_page(physical_bank, page).to_address()
    }

    #[cfg(feature = "device")]
    fn get_physical_page(&self, which: BankStatus, page: usize) -> flash::FlashPage {
        let physical_bank = match which {
            BankStatus::Active => self.physical.opposite(),
            BankStatus::Spare => self.physical,
        };
        Self::physical_bank_page(physical_bank, page)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum BankStatus {
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
enum FlashBank {
    Bank1,
    Bank2,
}

impl FlashBank {
    fn opposite(&self) -> Self {
        match self {
            FlashBank::Bank1 => FlashBank::Bank2,
            FlashBank::Bank2 => FlashBank::Bank1,
        }
    }
}

#[derive(minicbor::Encode, minicbor::Decode)]
struct Checkpoint {
    #[cbor(n(0))]
    first_page_midstate: Box<ByteArray<32>>,
    #[cbor(n(2))]
    signature: Box<ByteArray<64>>,
    #[cbor(n(3))]
    next_page: usize,
    #[cbor(n(4))]
    midstate: Box<ByteArray<32>>,
}

#[cfg_attr(feature = "emulator", allow(dead_code))]
struct FwUpdater<'h> {
    header: &'h FwUpdateHeader,
    hash: sha256::HashEngine,
    page: usize,
    bank_to_flash: BankToFlash,
    prev_checkpoint: Option<usize>,
}

impl<'h> FwUpdater<'h> {
    #[allow(unused_variables)]
    fn new(
        flash: &mut UnlockedFlash,
        header: &'h FwUpdateHeader,
        bank_to_flash: BankToFlash,
    ) -> Result<Self, Error> {
        #[cfg(feature = "device")]
        let checkpoint: Option<Checkpoint> = {
            let mut buf = alloc::vec![0x00; 2048];
            flash.read(
                bank_to_flash.get_logical_address(BankStatus::Spare, 0),
                &mut buf,
            );

            let len = u16::from_be_bytes(buf[..2].try_into().unwrap()) as usize;
            if len >= 2048 - 2 {
                None
            } else if let Ok(ckpt) = minicbor::decode(&buf[2..2 + len]) {
                Some(ckpt)
            } else {
                None
            }
        };
        #[cfg(feature = "emulator")]
        let checkpoint: Option<Checkpoint> = None;

        let checkpoint = checkpoint.and_then(|ckpt| {
            // Verify we are still talking about the same FW
            if ckpt.first_page_midstate != header.first_page_midstate
                || ckpt.signature != header.signature
            {
                None
            } else {
                Some(ckpt)
            }
        });

        let (midstate, midstate_len) = match &checkpoint {
            Some(ckpt) => {
                log::debug!(
                    "Resuming from checkpoint at page {}, midstate {:02X?}",
                    ckpt.next_page,
                    ckpt.midstate
                );
                (ckpt.midstate.deref(), ckpt.next_page * 2048)
            }
            None => {
                // Let's use what the caller is claiming the hash to be - we will verify it later anyways
                log::debug!(
                    "Fresh update with first_page_midstate = {:02X?}",
                    header.first_page_midstate
                );
                (header.first_page_midstate.deref(), 2048)
            }
        };
        let hash = sha256::HashEngine::from_midstate(
            sha256::Midstate::from_byte_array(**midstate),
            midstate_len,
        );

        if checkpoint.is_none() {
            log::debug!("Performing mass-erase...");

            #[cfg(feature = "device")]
            {
                let cr = unsafe { &(*stm32::FLASH::ptr()).cr };
                let sr = unsafe { &(*stm32::FLASH::ptr()).sr };
                let wait = || {
                    while sr.read().bsy().bit_is_set() {}
                };
                let status = || {
                    if sr.read().bsy().bit_is_set() {
                        Err(Error::FlashError)
                    } else if sr.read().pgaerr().bit_is_set()
                        || sr.read().progerr().bit_is_set()
                        || sr.read().wrperr().bit_is_set()
                    {
                        Err(Error::FlashError)
                    } else {
                        Ok(())
                    }
                };

                // Make sure there are no flash transactions happening
                wait();
                // Perform erase
                cr.modify(|_, w| match bank_to_flash.physical {
                    FlashBank::Bank1 => w.mer1().set_bit(),
                    FlashBank::Bank2 => w.mer2().set_bit(),
                });
                cr.modify(|_, w| w.start().set_bit());
                wait();
                status()?;
                cr.modify(|_, w| match bank_to_flash.physical {
                    FlashBank::Bank1 => w.mer1().clear_bit(),
                    FlashBank::Bank2 => w.mer2().clear_bit(),
                });
                wait();
            }

            log::debug!("Mass-erase finished!");
        }

        #[cfg(feature = "device")]
        {
            const CONFIG_PAGE: usize = 255;

            let mut buf = alloc::vec![0x00; 2048];
            flash.read(
                bank_to_flash.get_logical_address(BankStatus::Active, CONFIG_PAGE),
                &mut buf,
            );

            flash
                .erase_page(bank_to_flash.get_physical_page(BankStatus::Spare, CONFIG_PAGE))
                .map_err(|_| Error::FlashError)?;
            flash
                .write(
                    bank_to_flash.get_logical_address(BankStatus::Spare, CONFIG_PAGE),
                    &buf,
                )
                .map_err(|e| Error::FlashError)?;
            log::debug!("Configuration copied successfully");
        }

        Ok(FwUpdater {
            header,
            hash,
            page: checkpoint.as_ref().map(|ckpt| ckpt.next_page).unwrap_or(1),
            bank_to_flash,
            prev_checkpoint: checkpoint.map(|ckpt| ckpt.next_page),
        })
    }

    #[cfg(feature = "device")]
    fn save_checkpoint(&self, flash: &mut UnlockedFlash) -> Result<(), Error> {
        let checkpoint = Checkpoint {
            first_page_midstate: self.header.first_page_midstate.clone(),
            signature: self.header.signature.clone(),
            next_page: self.page,
            midstate: Box::new(ByteArray::from(self.hash.midstate().to_byte_array())),
        };

        let mut data = alloc::vec![0x00, 0x00];
        let serialized = minicbor::to_vec(checkpoint).expect("always succeed");
        let len = (serialized.len() as u16).to_be_bytes();
        data.extend(serialized);
        (&mut data[..2]).copy_from_slice(&len);
        data.resize(2048, 0x00);

        flash
            .erase_page(self.bank_to_flash.get_physical_page(BankStatus::Spare, 0))
            .map_err(|_| Error::FlashError)?;
        flash
            .write(
                self.bank_to_flash.get_logical_address(BankStatus::Spare, 0),
                &data,
            )
            .map_err(|_| Error::FlashError)?;

        Ok(())
    }

    #[cfg_attr(feature = "emulator", allow(unused_variables))]
    fn chunk(&mut self, flash: &mut UnlockedFlash, data: &[u8]) -> Result<(), Error> {
        if self.page * 2048 > self.header.size {
            return Err(Error::InvalidFirmware);
        }

        log::debug!("Writing page {}...", self.page);

        #[cfg(feature = "device")]
        {
            // If we are restarting from a checkpoint we don't know exactly where the previous update
            // stopped, so we may be rewriting over existing pages. Make sure to individually erase the
            // next `CHECKPOINT_PAGE_INTERVAL` pages before writing to them
            match self.prev_checkpoint {
                Some(x) if self.page < x + CHECKPOINT_PAGE_INTERVAL => {
                    flash
                        .erase_page(
                            self.bank_to_flash
                                .get_physical_page(BankStatus::Spare, self.page),
                        )
                        .map_err(|_| Error::FlashError)?;
                }
                _ => {}
            }
            flash
                .write(
                    self.bank_to_flash
                        .get_logical_address(BankStatus::Spare, self.page),
                    data,
                )
                .map_err(|_| Error::FlashError)?;
        }

        log::debug!("Done!");

        let data_end = match ((self.page + 1) * 2048).checked_sub(self.header.size) {
            None => 2048,
            Some(x) => 2048 - x,
        };

        self.page += 1;
        self.hash.input(&data[..data_end]);

        #[cfg(feature = "device")]
        if self.page % CHECKPOINT_PAGE_INTERVAL == 0 {
            self.save_checkpoint(flash)?;
            log::debug!("Saved checkpoint");
        }

        Ok(())
    }

    fn finish(
        &mut self,
        flash: &mut UnlockedFlash,
        header: &FwUpdateHeader,
        data: &[u8],
    ) -> Result<(), Error> {
        let mut first_page_midstate = sha256::HashEngine::default();
        first_page_midstate.input(data);
        let first_page_midstate = first_page_midstate.midstate();
        log::debug!("First page midstate: {:02X?}", first_page_midstate);

        if &first_page_midstate.to_byte_array() != header.first_page_midstate.deref().deref() {
            return Err(Error::InvalidFirmware);
        }

        let hash = sha256::Hash::from_engine(self.hash.clone());
        log::debug!("FW hash: {:02X?}", hash);

        let signing_key = secp256k1::XOnlyPublicKey::from_str(FIRMWARE_SIGNING_KEY)
            .expect("Valid signing pubkey");
        let message = secp256k1::Message::from_slice(&hash.as_ref()).expect("Correct length");
        let signature = secp256k1::schnorr::Signature::from_slice(header.signature.deref().deref())
            .map_err(|_| Error::InvalidFirmware)?;
        let ctx = secp256k1::Secp256k1::verification_only();

        match ctx.verify_schnorr(&signature, &message, &signing_key) {
            Ok(_) => {
                log::info!("Valid firmware signature");
            }
            Err(_) => {
                log::warn!("Invalid signature, aborting update");
                return Err(Error::InvalidFirmware);
            }
        }

        #[cfg(feature = "device")]
        {
            // Write first page
            flash
                .erase_page(self.bank_to_flash.get_physical_page(BankStatus::Spare, 0))
                .map_err(|_| Error::FlashError)?;
            flash
                .write(
                    self.bank_to_flash.get_logical_address(BankStatus::Spare, 0),
                    data,
                )
                .map_err(|_| Error::FlashError)?;
        }

        Ok(())
    }

    fn switch_and_reboot(self, flash: &mut UnlockedFlash) -> ! {
        #[cfg(feature = "device")]
        {
            // Wipe the boot sector of the booted bank to force the switch
            let page = self.bank_to_flash.get_physical_page(BankStatus::Active, 0);
            flash.erase_page(page).unwrap();
        }

        cortex_m::peripheral::SCB::sys_reset();
    }
}

pub async fn handle_begin_fw_update(
    header: &FwUpdateHeader,
    mut events: impl Stream<Item = Event> + Unpin,
    peripherals: &mut HandlerPeripherals,
) -> Result<CurrentState, Error> {
    log::info!("handle_begin_fw_update");

    if header.size > 510 * 2048 {
        peripherals
            .nfc
            .send(model::Reply::Error("Firmware file too big".into()))
            .await
            .unwrap();
        return Err(Error::InvalidFirmware);
    }

    peripherals
        .nfc
        .send(model::Reply::DelayedReply)
        .await
        .unwrap();

    let mut page = SummaryPage::new("Update FW?", "HOLD BTN TO BEGIN");
    page.init_display(&mut peripherals.display)?;
    page.draw_to(&mut peripherals.display)?;
    peripherals.display.flush()?;

    peripherals.tsc_enabled.enable();
    manage_confirmation_loop(&mut events, peripherals, &mut page).await?;
    peripherals.tsc_enabled.disable();

    let mut page = FwUpdateProgressPage::new(header.size as u32);
    page.init_display(&mut peripherals.display)?;
    page.draw_to(&mut peripherals.display)?;
    peripherals.display.flush()?;

    let events = only_requests(&mut events);
    pin_mut!(events);

    #[cfg(feature = "device")]
    let mut lock = peripherals
        .flash
        .parts
        .keyr
        .unlock_flash(
            &mut peripherals.flash.parts.sr,
            &mut peripherals.flash.parts.cr,
        )
        .map_err(|_| Error::FlashError)?;
    #[cfg(feature = "emulator")]
    let mut lock = ();

    let bank_to_flash = match peripherals.flash.fb_mode {
        false => FlashBank::Bank2,
        true => FlashBank::Bank1,
    };
    log::debug!("Flashing to bank: {:?}", bank_to_flash);
    let mut updater = FwUpdater::new(&mut lock, header, BankToFlash::new(bank_to_flash))?;
    page.add_confirm((2048 * updater.page) as u32); // account for the potential checkpoint
    page.draw_to(&mut peripherals.display)?;
    peripherals.display.flush()?;

    peripherals
        .nfc
        .send(model::Reply::NextPage(updater.page))
        .await
        .unwrap();
    peripherals.nfc_finished.recv().await.unwrap();

    loop {
        match events.next().await {
            Some(model::Request::FwUpdateChunk(data)) => {
                updater.chunk(&mut lock, data.deref().deref())?;
                peripherals
                    .nfc
                    .send(model::Reply::NextPage(updater.page))
                    .await
                    .unwrap();
                peripherals.nfc_finished.recv().await.unwrap();

                page.add_confirm(2048);
                page.draw_to(&mut peripherals.display)?;
                peripherals.display.flush()?;
            }
            Some(model::Request::CompleteFwUpdate(data)) => {
                updater.finish(&mut lock, &header, data.deref().deref())?;
                peripherals.nfc.send(model::Reply::Ok).await.unwrap();

                break;
            }
            _ => {
                peripherals
                    .nfc
                    .send(model::Reply::UnexpectedMessage)
                    .await
                    .unwrap();
                peripherals.nfc_finished.recv().await.unwrap();

                return Err(Error::BrokenProtocol);
            }
        }
    }

    let page = SingleLineTextPage::new("UPD COMPLETE");
    page.init_display(&mut peripherals.display)?;
    page.draw_to(&mut peripherals.display)?;
    peripherals.display.flush()?;

    rtic_monotonics::systick::Systick::delay(1000_u32.millis()).await;

    peripherals.nfc_finished.recv().await.unwrap();

    updater.switch_and_reboot(&mut lock);
}
