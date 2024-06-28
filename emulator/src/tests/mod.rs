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

use std::ops::Deref;
use std::sync::{Arc, Once, OnceLock};

use tokio::sync::mpsc;

use embedded_graphics_simulator::OutputSettingsBuilder;

use model::emulator::EmulatorMessage;

use crate::link::{manage_hw, try_pull_msg};

use crate::utils::model::*;
use crate::utils::EmulatorInstance;

mod bitcoin;
mod init;
mod set_descriptor;

pub const PORTAL_READY: &'static str = "iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAAAx0lEQVR4nO3V0Q6DMAhAUfn/j2bLqoUyWNqH2cTcvTgt0gOtKsfmHwAAAAAAAAAAAAAAAAAA+AZoBdN4Uef9WkZKHqvVwGTaZwC0jb//tl5fSbTfN6R1cUc8ymcwLawG2LErLL4lCoArbsDKWcsKoFduEF+vSWIHkg76QlY6EDvhBlyiApBPfCNAiqWU7MFdBIyJfi6BX/tzf7hkEwD3FLjdYbu6nxf3DbPH9ux4FU/vgT8Ksvn4GgIAAAAAAAAAAAAAAGA74AWxK4JB071edwAAAABJRU5ErkJggg==";
pub const LOADING: &'static str = "iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAAAj0lEQVR4nO3VsQ6AIAxFUfr/H/1UsAJhYbDAcBlsKpCeaEVLmwcAAAAAAAAAAAAAAAAAAJgDyNfJ9ygHpSa/o8pNq+t+BgwF5FXr1HOpSRBAbfEOUPIzABE9MAHIkwsA7+axB9yw6wnk/jSPWwEBTSibAQR9Bd877w6cZQcR/wIAAAAAAAAAAAAAAAAACBwX0C1tQf0U+LsAAAAASUVORK5CYII=";
pub const LOCKED: &'static str = "iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAAAfklEQVR4nO3VsQ7AIAhFUfj/j34dgFg3TVMZvC5oongSFd2aGwAAAAAAAAAAAAAAAAAAWAeo5irXZVT0XZlQe3n3Aa8NPWKNfUzUcuIvgBGnPY8CbLJ0ASJLXY1GwJVHcP4SyhufoVXl6SlE/AUAAAAAAAAAAAAAAAAA8FN7APK2WUEuePxjAAAAAElFTkSuQmCC";

pub const WPKH_EXTERNAL_DESC: &'static str = "wpkh([73c5da0a/84'/1'/0']tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/0/*)#2ag6nxcd";
pub const WPKH_INTERNAL_DESC: &'static str = "wpkh([73c5da0a/84'/1'/0']tpubDC8msFGeGuwnKG9Upg7DM2b4DaRqg3CUZa5g8v2SRQ6K4NSkxUgd7HsL2XVWbVm39yBA4LAxysQAm397zwQSQoQgewGiYZqrA9DsP4zbQ1M/1/*)#mfdmwng4";

static INIT_LOG: Once = Once::new();

async fn run_script(
    mut script: mpsc::Receiver<TestOp>,
    result_chan: mpsc::Sender<Result<(), AssertionResult>>,
    emulator: &mut EmulatorInstance,
) -> Result<TestLog, crate::Error> {
    // First always wipe the flash to start fresh
    // crate::link::wipe_flash(&mut emulator.flash, &mut emulator.card).await?;

    // And wait for bootup
    // emulator
    //     .msgs
    //     .finish_boot
    //     .recv()
    //     .await
    //     .expect("Boot finished");
    // log::debug!("Boot finished");

    let output_settings = OutputSettingsBuilder::new().scale(1).build();
    let mut log = vec![];

    let mut result = true;

    let sdk = Arc::clone(&emulator.sdk);
    sdk.new_tag().await?;

    while let Some(op) = script.recv().await {
        log::debug!("OP: {:?}", op);

        let fail = match &op {
            TestOp::Action(TestAction::WaitTicks(nticks)) => {
                let mut count = 0;
                while count < *nticks {
                    manage_hw(emulator, |_, _, _| {}, &mut (), false, false).await?;
                    while let Some(_) = try_pull_msg::<()>(&mut emulator.msgs.tick)? {
                        count += 1;
                    }
                }
                None
            }
            TestOp::Action(TestAction::Input(value)) => {
                emulator.card.send(EmulatorMessage::Tsc(*value))?;
                None
            }
            TestOp::Action(TestAction::Nfc(req)) => {
                let cloned_sdk = Arc::clone(&sdk);
                let req = req.to_owned();
                let _ = match req {
                    NfcAction::GetStatus => tokio::spawn(async move {
                        let _ = cloned_sdk.get_status().await;
                    }),
                    NfcAction::Resume => tokio::spawn(async move {
                        let _ = cloned_sdk.resume().await;
                    }),
                    NfcAction::Unlock(pwd) => tokio::spawn(async move {
                        let _ = cloned_sdk.unlock(pwd).await;
                    }),
                    NfcAction::DisplayAddress(addr) => tokio::spawn(async move {
                        let _ = cloned_sdk.display_address(addr).await;
                    }),
                    NfcAction::GenerateMnemonic(num_words, network, pair_code) => {
                        tokio::spawn(async move {
                            let num_words = match num_words {
                                model::NumWordsMnemonic::Words12 => {
                                    portal::GenerateMnemonicWords::Words12
                                }
                                model::NumWordsMnemonic::Words24 => {
                                    portal::GenerateMnemonicWords::Words24
                                }
                            };
                            let _ = cloned_sdk
                                .generate_mnemonic(num_words, network, pair_code)
                                .await;
                        })
                    }
                    NfcAction::RestoreMnemonic(words, network, pair_code) => {
                        tokio::spawn(async move {
                            let _ = cloned_sdk.restore_mnemonic(words, network, pair_code).await;
                        })
                    }
                    NfcAction::SignPsbt(psbt) => tokio::spawn(async move {
                        let signed_psbt = cloned_sdk.sign_psbt(psbt).await;
                        log::debug!("Full psbt: {:?}", signed_psbt);
                    }),
                    NfcAction::RequestDescriptors => tokio::spawn(async move {
                        let _ = cloned_sdk.public_descriptors().await;
                    }),
                    NfcAction::GetXpub(path) => tokio::spawn(async move {
                        let _ = cloned_sdk
                            .get_xpub(path.parse().expect("Valid derivation path"))
                            .await;
                    }),
                    NfcAction::SetDescriptor(desc, bsms) => tokio::spawn(async move {
                        let bsms = bsms.map(|data| portal::SetDescriptorBsmsData {
                            first_address: data.first_address,
                            version: "1.0".into(),
                            path_restrictions: "/0/*,/1/*".into(),
                        });
                        let _ = cloned_sdk.set_descriptor(desc, bsms).await;
                    }),

                    NfcAction::Raw(data) => tokio::spawn(async move {
                        let _ = cloned_sdk.debug_send_raw(data).await;
                    }),
                };
                None
            }
            TestOp::Action(TestAction::WipeFlash) => {
                crate::link::wipe_flash(&mut emulator.flash, &mut emulator.card).await?;
                None
            }
            TestOp::Action(TestAction::Reset(wipe_registers)) => {
                if *wipe_registers {
                    emulator.rtc = [0; 32];
                }
                emulator.card.send(EmulatorMessage::Reset)?;
                None
            }

            TestOp::Assertion(TestAssertion::Display {
                content,
                timeout_ticks,
            }) => {
                let start = std::time::Instant::now();
                let mut tick_counter = 0;
                let timeout = timeout_ticks.unwrap_or(16);

                let expected_fb = base64::decode(content)?;
                let expected_fb = image::load_from_memory(&expected_fb)?.to_rgb8();

                loop {
                    if manage_hw(emulator, |_, _, _| {}, &mut (), false, false).await? {
                        // Reset counter when the display is updated
                        tick_counter = 0;
                    }

                    let actual_fb = emulator.display.to_rgb_output_image(&output_settings);
                    if actual_fb.as_image_buffer().as_raw() == &expected_fb.as_raw().deref() {
                        break None;
                    }

                    while let Some(_) = try_pull_msg::<()>(&mut emulator.msgs.tick)? {
                        tick_counter += 1;
                    }

                    if tick_counter > timeout || start.elapsed().as_secs() > 5 {
                        break Some(AssertionResult::WrongDisplay(
                            emulator
                                .display
                                .to_grayscale_output_image(&output_settings)
                                .to_base64_png()?,
                        ));
                    }
                }
            }
            TestOp::Assertion(TestAssertion::NfcResponse(expected, send_ping)) => {
                'outer: loop {
                    use ::model::Reply;

                    let start = std::time::Instant::now();
                    let timeout = || Some(AssertionResult::WrongReply("<timeout>".into()));
                    let resp = loop {
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            sdk.debug_msg(),
                        )
                        .await
                        {
                            Ok(Ok(portal::DebugMessage::Out(_)))
                            | Ok(Ok(portal::DebugMessage::RawOut(_))) => continue,
                            Ok(Ok(portal::DebugMessage::In(r)))
                                if matches!(r, Reply::Pong | Reply::DelayedReply) =>
                            {
                                if *send_ping {
                                    let ping =
                                        model::minicbor::to_vec(&model::Request::Ping).unwrap();
                                    sdk.debug_send_raw(ping).await?;
                                }

                                if start.elapsed().as_secs() > 5 {
                                    break 'outer timeout();
                                } else {
                                    continue;
                                }
                            }
                            Ok(Ok(portal::DebugMessage::In(r))) => break r,

                            // Timeout
                            Err(_) => {
                                break 'outer timeout();
                            }
                            Ok(Err(e)) => {
                                log::warn!("Error {:?}", e);
                                return Err(e.into());
                            }
                        };
                    };

                    let resp = serde_json::to_string(&resp).unwrap();
                    // `Reply` doesn't impl eq
                    if resp != serde_json::to_string(expected).unwrap() {
                        break Some(AssertionResult::WrongReply(resp));
                    } else {
                        break None;
                    }
                }
            }
        };

        let pass = fail.is_none();
        if let Some(fail) = &fail {
            result_chan.send(Err(fail.clone())).await?;
        } else {
            result_chan.send(Ok(())).await?;
        }

        let log_lines = std::iter::from_fn(|| emulator.logs.try_recv().ok()).collect();
        log.push(TestLogStep {
            op,
            display: emulator.display.to_grayscale_output_image(&output_settings),
            pass,
            fail,
            log_lines,
        });

        if !pass {
            result = false;
            break;
        }
    }

    Ok(TestLog { steps: log, result })
}

pub struct Tester {
    op_sender: mpsc::Sender<TestOp>,
    res_receiver: mpsc::Receiver<Result<(), AssertionResult>>,
}

impl Tester {
    pub fn new(
        op_sender: mpsc::Sender<TestOp>,
        res_receiver: mpsc::Receiver<Result<(), AssertionResult>>,
    ) -> Self {
        Tester {
            op_sender,
            res_receiver,
        }
    }

    async fn expect_reply(&mut self) -> Result<(), crate::Error> {
        self.res_receiver.recv().await.ok_or("No reply")??;
        Ok(())
    }

    pub async fn wait_ticks(&mut self, nticks: usize) -> Result<(), crate::Error> {
        self.op_sender
            .send(TestAction::WaitTicks(nticks).into())
            .await?;
        self.expect_reply().await?;

        Ok(())
    }

    pub async fn nfc(&mut self, nfc_action: NfcAction) -> Result<(), crate::Error> {
        self.op_sender
            .send(TestAction::Nfc(nfc_action).into())
            .await?;
        self.expect_reply().await?;

        Ok(())
    }

    pub async fn nfc_assertion_raw(
        &mut self,
        assertion: model::Reply,
        send_ping: bool,
    ) -> Result<(), crate::Error> {
        self.op_sender
            .send(TestAssertion::NfcResponse(assertion, send_ping).into())
            .await?;
        self.expect_reply().await?;

        Ok(())
    }

    pub async fn nfc_assertion(&mut self, assertion: model::Reply) -> Result<(), crate::Error> {
        self.wait_ticks(1).await?;
        self.nfc_assertion_raw(assertion, false).await
    }

    pub async fn display_assertion(
        &mut self,
        content: &str,
        timeout_ticks: Option<usize>,
    ) -> Result<(), crate::Error> {
        self.op_sender
            .send(
                TestAssertion::Display {
                    content: content.to_string(),
                    timeout_ticks,
                }
                .into(),
            )
            .await?;
        self.expect_reply().await?;

        Ok(())
    }

    pub async fn tsc(&mut self, value: bool) -> Result<(), crate::Error> {
        self.op_sender.send(TestAction::Input(value).into()).await?;
        self.expect_reply().await?;

        Ok(())
    }

    pub async fn reset(&mut self) -> Result<(), crate::Error> {
        self.op_sender.send(TestAction::Reset(true).into()).await?;
        self.expect_reply().await?;
        self.wait_ticks(1).await?; // Force call to manage_hw

        Ok(())
    }

    pub async fn fast_boot_reset(&mut self) -> Result<(), crate::Error> {
        self.op_sender.send(TestAction::Reset(false).into()).await?;
        self.expect_reply().await?;
        self.wait_ticks(1).await?; // Force call to manage_hw

        Ok(())
    }
}

fn get_temp_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("REPORT_TMP_DIR") {
        let path = std::path::PathBuf::from(&dir);
        if !path.exists() {
            std::fs::create_dir_all(&path).expect("Can create the report dir");
        }

        path
    } else {
        // n.b. static items do not call [`Drop`] on program termination, but this is
        // actually good for us because it means the tempdir will be kept
        static TEMPDIR: OnceLock<tempdir::TempDir> = OnceLock::new();
        TEMPDIR
            .get_or_init(|| {
                tempdir::TempDir::new("portal-func-tests").expect("Can create temp directory")
            })
            .path()
            .to_path_buf()
    }
}

fn get_fw_path() -> &'static std::path::Path {
    static FW_PATH: OnceLock<std::path::PathBuf> = OnceLock::new();
    FW_PATH.get_or_init(|| {
        log::debug!("Building firmware...");
        let output = std::process::Command::new("cargo")
            .current_dir("../firmware")
            .args(vec![
                "build",
                "--no-default-features",
                "--features=emulator,emulator-fast-ticks",
                "--profile=emulator-fast-ticks",
            ])
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .stdin(std::process::Stdio::piped())
            .output()
            .expect("Cargo runs");

        if !output.status.success() {
            panic!("Cargo build failed");
        }

        std::path::PathBuf::from(
            "../firmware/target/thumbv7em-none-eabihf/emulator-fast-ticks/firmware",
        )
    })
}
