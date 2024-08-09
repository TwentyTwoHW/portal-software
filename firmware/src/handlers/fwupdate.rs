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

use alloc::boxed::Box;
use core::{ops::Deref, str::FromStr};

use futures::prelude::*;

use rtic_monotonics::systick::ExtU32;

#[cfg(feature = "device")]
use stm32l4xx_hal::{flash, flash::Read, flash::WriteErase, stm32};

use bitcoin_hashes::{sha256, Hash, HashEngine};

use minicbor::bytes::ByteArray;

use gui::{FwUpdateProgressPage, SingleLineTextPage, SummaryPage};

use hw::{BankStatus, BankToFlash, FlashBank};

use super::*;
use crate::checkpoint;
use crate::version;
use crate::Error;

#[cfg(feature = "production")]
const FIRMWARE_SIGNING_KEY: &'static str =
    "4a02b085ae8acb13a6d5c494818baaa0798300150dc0bdb87bb6da24a8beaff4";

#[cfg(not(feature = "production"))]
const FIRMWARE_SIGNING_KEY: &'static str =
    "1608bd04cf3212070b3de57f4a2ad8e5108a103af037f878ec75f4a2068de610";

const CHECKPOINT_PAGE_INTERVAL: usize = 4;

// const FLASH_OPTKEY1: u32 = 0x0819_2A3B;
// const FLASH_OPTKEY2: u32 = 0x4C5D_6E7F;

type UnlockedFlash<'a> = flash::FlashProgramming<'a>;

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
    #[cbor(n(5))]
    tail: [u8; version::TAIL_SIZE],
    #[cbor(n(6))]
    erase_from: Option<usize>,
}

struct FwUpdater<'h> {
    header: &'h FwUpdateHeader,
    hash: sha256::HashEngine,
    page: usize,
    bank_to_flash: BankToFlash,
    erase_window_start: Option<usize>,
    tail: [u8; version::TAIL_SIZE],
}

impl<'h> FwUpdater<'h> {
    fn new(
        flash: &mut UnlockedFlash,
        header: &'h FwUpdateHeader,
        state: Option<checkpoint::FwUpdateState>,
        bank_to_flash: BankToFlash,
    ) -> Result<Self, Error> {
        let checkpoint: Option<Checkpoint> = {
            if let Some(state) = state {
                Some(Checkpoint {
                    first_page_midstate: header.first_page_midstate.clone(),
                    signature: header.signature.clone(),
                    next_page: state.next_page,
                    midstate: state.midstate,
                    tail: state.tail,
                    erase_from: None,
                })
            } else {
                let mut buf = alloc::vec![0x00; hw::PAGE_SIZE];
                flash.read(
                    bank_to_flash.get_logical_address(BankStatus::Spare, 0),
                    &mut buf,
                );

                let len = u16::from_be_bytes(buf[..2].try_into().unwrap()) as usize;
                if len >= hw::PAGE_SIZE - 2 {
                    None
                } else if let Ok(ckpt) = minicbor::decode(&buf[2..2 + len]) {
                    Some(ckpt)
                } else {
                    None
                }
            }
        };

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
                (ckpt.midstate.deref(), ckpt.next_page * hw::PAGE_SIZE)
            }
            None => {
                // Let's use what the caller is claiming the hash to be - we will verify it later anyways
                log::debug!(
                    "Fresh update with first_page_midstate = {:02X?}",
                    header.first_page_midstate
                );
                (header.first_page_midstate.deref(), hw::PAGE_SIZE)
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

            let mut buf = alloc::vec![0x00; hw::PAGE_SIZE];
            flash.read(
                bank_to_flash.get_logical_address(BankStatus::Active, crate::config::CONFIG_PAGE),
                &mut buf,
            );

            flash
                .erase_page(
                    bank_to_flash.get_physical_page(BankStatus::Spare, crate::config::CONFIG_PAGE),
                )
                .map_err(|_| Error::FlashError)?;
            flash
                .write(
                    bank_to_flash
                        .get_logical_address(BankStatus::Spare, crate::config::CONFIG_PAGE),
                    &buf,
                )
                .map_err(|_| Error::FlashError)?;
            log::debug!("Configuration copied successfully");
        }

        Ok(FwUpdater {
            header,
            hash,
            page: checkpoint.as_ref().map(|ckpt| ckpt.next_page).unwrap_or(1),
            bank_to_flash,
            erase_window_start: checkpoint.as_ref().and_then(|ckpt| ckpt.erase_from),
            tail: checkpoint
                .map(|ckpt| ckpt.tail)
                .unwrap_or([0u8; version::TAIL_SIZE]),
        })
    }

    fn save_checkpoint(&self, flash: &mut UnlockedFlash) -> Result<(), Error> {
        let checkpoint = Checkpoint {
            first_page_midstate: self.header.first_page_midstate.clone(),
            signature: self.header.signature.clone(),
            next_page: self.page,
            erase_from: Some(self.page),
            midstate: Box::new(ByteArray::from(self.hash.midstate().to_byte_array())),
            tail: self.tail,
        };

        let mut data = alloc::vec![0x00, 0x00];
        let serialized = minicbor::to_vec(checkpoint).expect("always succeed");
        let len = (serialized.len() as u16).to_be_bytes();
        data.extend(serialized);
        (&mut data[..2]).copy_from_slice(&len);
        data.resize(hw::PAGE_SIZE, 0x00);

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

    fn save_fastboot_checkpoint(&self, fb_key: [u8; 24], rtc: &mut crate::hw::Rtc) {
        let state = checkpoint::FwUpdateState {
            next_page: self.page,
            midstate: Box::new(ByteArray::from(self.hash.midstate().to_byte_array())),
            tail: self.tail,
        };
        let fb_checkpoint = checkpoint::Checkpoint::new_with_key(
            checkpoint::CheckpointVariant::UpdateFirmware { state },
            None,
            None,
            fb_key,
        );
        fb_checkpoint.commit_registers(rtc);
    }

    fn chunk(
        &mut self,
        flash: &mut UnlockedFlash,
        data: &[u8],
        rtc: &mut crate::hw::Rtc,
        fb_key: &[u8; 24],
    ) -> Result<(), Error> {
        if self.page * hw::PAGE_SIZE > self.header.size {
            return Err(Error::InvalidFirmware);
        }

        log::debug!("Writing page {}...", self.page);
        log::debug!("Content: {:02X?}", &data[..32]);

        // If we are restarting from a checkpoint we don't know exactly where the previous update
        // stopped, so we may be rewriting over existing pages. Make sure to individually erase the
        // next `CHECKPOINT_PAGE_INTERVAL` pages before writing to them
        match self.erase_window_start {
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

        log::debug!("Done!");

        let data_end = match ((self.page + 1) * hw::PAGE_SIZE).checked_sub(self.header.size) {
            None => hw::PAGE_SIZE,
            Some(x) => hw::PAGE_SIZE - x,
        };

        self.page += 1;
        self.hash.input(&data[..data_end]);

        // Update tail
        let mut tail = [0u8; version::TAIL_SIZE];
        let keep_tail = version::TAIL_SIZE.saturating_sub(data_end);
        let add_tail = data_end.saturating_sub(version::TAIL_SIZE);
        tail[0..keep_tail].copy_from_slice(&self.tail[(version::TAIL_SIZE - keep_tail)..]);
        tail[keep_tail..].copy_from_slice(&data[add_tail..data_end]);

        self.tail = tail;

        self.save_fastboot_checkpoint(fb_key.clone(), rtc);

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
        let message = secp256k1::Message::from_digest_slice(hash.as_ref()).expect("Correct length");
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

        // Check version
        let parsed = version::UpdateTail::parse(&self.tail);
        if parsed.version > version::CURRENT_VERSION && parsed.variant == version::CURRENT_VARIANT {
            log::info!(
                "FW Variant {:02X}, upgrading from {} to {}",
                version::CURRENT_VARIANT,
                version::CURRENT_VERSION,
                parsed.version
            );
        } else {
            log::warn!("Invalid version or variant: variant {:02X} vs {:02X}(current), version {} vs {}(current)", parsed.variant, version::CURRENT_VARIANT, parsed.version, version::CURRENT_VERSION);
            return Err(Error::InvalidFirmware);
        }

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

        Ok(())
    }

    fn switch_and_reboot(self, flash: &mut UnlockedFlash) -> ! {
        {
            // Wipe the boot sector of the booted bank to force the switch
            let page = self.bank_to_flash.get_physical_page(BankStatus::Active, 0);
            flash.erase_page(page).unwrap();
        }

        cortex_m::peripheral::SCB::sys_reset();
    }
}

pub async fn handle_begin_fw_update(
    header: FwUpdateHeader,
    fast_boot: Option<(checkpoint::FwUpdateState, [u8; 24])>,
    mut events: impl Stream<Item = Event> + Unpin,
    peripherals: &mut HandlerPeripherals,
) -> Result<CurrentState, Error> {
    log::info!("handle_begin_fw_update");

    let (state, fb_key) = match fast_boot {
        None => {
            if header.size > hw::MAX_FW_PAGES * hw::PAGE_SIZE {
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

            let mut page = SummaryPage::new_with_threshold("Update FW?", "HOLD BTN TO BEGIN", 70);
            page.init_display(&mut peripherals.display)?;
            page.draw_to(&mut peripherals.display)?;
            peripherals.display.flush()?;

            peripherals.tsc_enabled.enable();
            manage_confirmation_loop(&mut events, peripherals, &mut page).await?;
            peripherals.tsc_enabled.disable();

            // Save fast boot checkpoint
            let state = checkpoint::FwUpdateState {
                midstate: Box::new([0u8; 32].into()),
                next_page: 0,
                tail: [0; version::TAIL_SIZE],
            };
            let fb_checkpoint = checkpoint::Checkpoint::new(
                checkpoint::CheckpointVariant::UpdateFirmware { state },
                Some(minicbor::to_vec(&header).unwrap()),
                None,
                &mut peripherals.rng,
            );
            fb_checkpoint.commit(peripherals)?;

            (None, *fb_checkpoint.encryption_key)
        }
        Some((state, key)) if state.next_page == 0 => (None, key.into()),
        Some((state, key)) => (Some(state), key.into()),
    };
    let mut drop_next_message = state.is_some();

    let mut page = FwUpdateProgressPage::new(header.size as u32);
    page.init_display(&mut peripherals.display)?;
    page.draw_to(&mut peripherals.display)?;
    peripherals.display.flush()?;

    let events = only_requests(&mut events);
    pin_mut!(events);

    let mut lock = peripherals
        .flash
        .parts
        .keyr
        .unlock_flash(
            &mut peripherals.flash.parts.sr,
            &mut peripherals.flash.parts.cr,
        )
        .map_err(|_| Error::FlashError)?;

    let bank_to_flash = match peripherals.flash.fb_mode {
        false => FlashBank::Bank2,
        true => FlashBank::Bank1,
    };
    log::debug!("Flashing to bank: {:?}", bank_to_flash);
    let mut updater = FwUpdater::new(&mut lock, &header, state, BankToFlash::new(bank_to_flash))?;
    page.add_confirm((hw::PAGE_SIZE * updater.page) as u32); // account for the potential checkpoint
    page.draw_to(&mut peripherals.display)?;
    peripherals.display.flush()?;

    if !drop_next_message {
        // Re-request page if we are not resuming via fastboot
        peripherals
            .nfc
            .send(model::Reply::NextPage(updater.page))
            .await
            .unwrap();
        peripherals.nfc_finished.recv().await.unwrap();
    }

    loop {
        match events.next().await {
            Some(model::Request::FwUpdateChunk(data)) => {
                if !drop_next_message {
                    updater.chunk(
                        &mut lock,
                        data.deref().deref(),
                        &mut peripherals.rtc,
                        &fb_key,
                    )?;
                } else {
                    drop_next_message = false;
                }
                peripherals
                    .nfc
                    .send(model::Reply::NextPage(updater.page))
                    .await
                    .unwrap();
                peripherals.nfc_finished.recv().await.unwrap();

                page.add_confirm(hw::PAGE_SIZE as u32);
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

    let page = SingleLineTextPage::new("UPDATE COMPLETE");
    page.init_display(&mut peripherals.display)?;
    page.draw_to(&mut peripherals.display)?;
    peripherals.display.flush()?;

    rtic_monotonics::systick::Systick::delay(1000_u32.millis()).await;

    peripherals.nfc_finished.recv().await.unwrap();

    updater.switch_and_reboot(&mut lock);
}
