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

#![allow(unused_variables)]
#![allow(unused_mut)]
#![allow(unused_imports)]
#![allow(clippy::needless_update)]

use std::ops::DerefMut;
use std::sync::{Arc, Mutex, RwLock};

use embedded_graphics::pixelcolor::Gray8;
use embedded_graphics_simulator::OutputImage;

use fltk::{
    prelude::*,
    window::{DoubleWindow, Window},
    *,
};
use futures::executor::block_on;
use tokio::sync::mpsc;

use portal::{GenerateMnemonicWords, PortalSdk};

use model::FwUpdateHeader;

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub enum EmulatorMessage {
    Tsc(bool),
    Reset,
}

include!(concat!(env!("OUT_DIR"), "/autogen-gui.rs"));

pub fn init_gui(
    fb: Arc<RwLock<OutputImage<Gray8>>>,
    fb_large: Arc<RwLock<OutputImage<Gray8>>>,
    sender: mpsc::UnboundedSender<EmulatorMessage>,
    sdk: Arc<PortalSdk>,
    log: mpsc::UnboundedSender<String>,
) -> Emulator {
    let mut emulator_gui = Emulator::make_window();

    emulator_gui.num_words.add_choice("12 Words");
    emulator_gui.num_words.add_choice("24 Words");
    emulator_gui.num_words.set_value(0);

    // TODO: assert fb size is 511x255
    emulator_gui.display.draw(move |i| {
        let fb = fb_large.read().unwrap();
        let data = fb.as_image_buffer().into_raw();
        let mut image = image::RgbImage::new(&data, i.w(), i.h(), enums::ColorDepth::L8).unwrap();
        image.draw(i.x(), i.y(), i.w(), i.h());
    });

    let sdk_cloned = Arc::clone(&sdk);
    let fb_cloned = Arc::clone(&fb);
    let sender_cloned = sender.clone();
    let log_cloned = log.clone();
    emulator_gui.display.handle(move |_, ev| match ev {
        enums::Event::Push => {
            if app::event_button() == 1 {
                block_on(async {
                    sender_cloned.send(EmulatorMessage::Tsc(true)).unwrap();
                    log_cloned.send("> Tsc(true)".into()).unwrap();
                });
            }

            true
        }
        enums::Event::Released => {
            if app::event_button() == 1 {
                block_on(async {
                    sender_cloned.send(EmulatorMessage::Tsc(false)).unwrap();
                    log_cloned.send("> Tsc(false)".into()).unwrap();
                });
            } else if app::event_button() == 3 {
                log::warn!(
                    "{}",
                    fb_cloned
                        .read()
                        .unwrap()
                        .to_base64_png()
                        .expect("Can always serialize")
                );
            }

            true
        }
        _ => false,
    });

    let sdk_cloned = Arc::clone(&sdk);
    let log_cloned = log.clone();
    emulator_gui.generate_mnemonic_btn.set_callback(move |_| {
        let num_words = match app::widget_from_id::<Choice>("num_words").unwrap().value() {
            0 => GenerateMnemonicWords::Words12,
            1 => GenerateMnemonicWords::Words24,
            _ => unimplemented!(),
        };
        let password = app::widget_from_id::<Input>("generate_mnemonic_password")
            .unwrap()
            .value();
        let sdk_cloned = sdk_cloned.clone();
        let log_cloned = log_cloned.clone();
        tokio::spawn(async move {
            log_cloned
                .send(format!(
                    "> GenerateMnemonic({:?}, {:?})",
                    num_words, password
                ))
                .unwrap();
            match sdk_cloned
                .generate_mnemonic(
                    num_words,
                    model::bitcoin::Network::Signet,
                    if password.is_empty() {
                        None
                    } else {
                        Some(password)
                    },
                )
                .await
            {
                Ok(v) => log_cloned.send("< ".into()).unwrap(),
                Err(e) => log::warn!("Generate mnemonic err: {:?}", e),
            }
        });
    });

    let sdk_cloned = Arc::clone(&sdk);
    let log_cloned = log.clone();
    emulator_gui.get_info_btn.set_callback(move |_| {
        let sdk_cloned = sdk_cloned.clone();
        let log_cloned = log_cloned.clone();
        tokio::spawn(async move {
            log_cloned.send("> GetInfo".into()).unwrap();
            match sdk_cloned.get_status().await {
                Ok(v) => log_cloned.send(format!("< {:?}", v)).unwrap(),
                Err(e) => log::warn!("Get status err: {:?}", e),
            }
        });
    });
    let sdk_cloned = Arc::clone(&sdk);
    let log_cloned = log.clone();
    emulator_gui.public_descriptor_btn.set_callback(move |_| {
        let sdk_cloned = sdk_cloned.clone();
        let log_cloned = log_cloned.clone();
        tokio::spawn(async move {
            log_cloned.send("> PublicDescriptor".into()).unwrap();
            match sdk_cloned.public_descriptors().await {
                Ok(v) => log_cloned.send(format!("< {:?}", v)).unwrap(),
                Err(e) => log::warn!("Public descriptors err: {:?}", e),
            }
        });
    });

    let sender = sender.clone();
    emulator_gui.reset_btn.set_callback(move |_| {
        sender.send(EmulatorMessage::Reset).unwrap();
    });

    let sdk_cloned = Arc::clone(&sdk);
    let log_cloned = log.clone();
    emulator_gui.resume_btn.set_callback(move |_| {
        let sdk_cloned = sdk_cloned.clone();
        let log_cloned = log_cloned.clone();
        tokio::spawn(async move {
            log_cloned.send("> Resume".into()).unwrap();
            match sdk_cloned.resume().await {
                Ok(v) => log_cloned.send(format!("< {:?}", v)).unwrap(),
                Err(e) => log::warn!("Resume err: {:?}", e),
            }
        });
    });

    let (sdk_cloned, log_cloned) = (Arc::clone(&sdk), log.clone());
    emulator_gui.display_address_btn.set_callback(move |_| {
        let value = app::widget_from_id::<Input>("display_address_num")
            .unwrap()
            .value();
        let value = value.parse::<u32>().unwrap();

        let sdk_cloned = sdk_cloned.clone();
        let log_cloned = log_cloned.clone();
        tokio::spawn(async move {
            log_cloned
                .send(format!("> DisplayAddress({})", value))
                .unwrap();
            match sdk_cloned.display_address(value).await {
                Ok(v) => log_cloned.send(format!("< {}", v)).unwrap(),
                Err(e) => log::warn!("Display addr err: {:?}", e),
            }
        });
    });

    let (sdk_cloned, log_cloned) = (Arc::clone(&sdk), log.clone());
    emulator_gui.restore_mnemonic_btn.set_callback(move |_| {
        let value = app::widget_from_id::<Input>("restore_mnemonic")
            .unwrap()
            .value();
        let password = app::widget_from_id::<Input>("restore_mnemonic_password")
            .unwrap()
            .value();

        let sdk_cloned = sdk_cloned.clone();
        let log_cloned = log_cloned.clone();
        tokio::spawn(async move {
            log_cloned
                .send(format!("> RestoreMnemonic({:?}, {:?})", value, password))
                .unwrap();
            match sdk_cloned
                .restore_mnemonic(
                    value,
                    model::bitcoin::Network::Signet,
                    if password.is_empty() {
                        None
                    } else {
                        Some(password)
                    },
                )
                .await
            {
                Ok(v) => log_cloned.send(format!("< {:?}", v)).unwrap(),
                Err(e) => log::warn!("Restore mnemonic err: {:?}", e),
            }
        });
    });

    let (sdk_cloned, log_cloned) = (Arc::clone(&sdk), log.clone());
    emulator_gui.sign_psbt_btn.set_callback(move |_| {
        let value = app::widget_from_id::<Input>("sign_psbt").unwrap().value();

        let sdk_cloned = sdk_cloned.clone();
        let log_cloned = log_cloned.clone();
        tokio::spawn(async move {
            log_cloned.send(format!("> SignPsbt({})", value)).unwrap();
            match sdk_cloned.sign_psbt(value).await {
                Ok(v) => log_cloned.send(format!("< {}", v)).unwrap(),
                Err(e) => log::warn!("Sign psbt err: {:?}", e),
            }
        });
    });

    let (sdk_cloned, log_cloned) = (Arc::clone(&sdk), log.clone());
    emulator_gui.fw_path_btn.set_callback(move |_| {
        let value = app::widget_from_id::<Input>("fw_path").unwrap().value();
        let binary = std::fs::read(&value).unwrap();

        let sdk_cloned = sdk_cloned.clone();
        let log_cloned = log_cloned.clone();
        tokio::spawn(async move {
            log_cloned.send(format!("> UpdateFw({})", value)).unwrap();
            match sdk_cloned.update_firmware(binary).await {
                Ok(v) => log_cloned.send(format!("< {:?}", v)).unwrap(),
                Err(e) => log::warn!("Update fw err: {:?}", e),
            }
        });
    });

    let (sdk_cloned, log_cloned) = (Arc::clone(&sdk), log.clone());
    emulator_gui.unlock_pwd_btn.set_callback(move |_| {
        let password = app::widget_from_id::<Input>("unlock_pwd").unwrap().value();

        let sdk_cloned = sdk_cloned.clone();
        let log_cloned = log_cloned.clone();
        tokio::spawn(async move {
            log_cloned.send(format!("> Unlock({})", password)).unwrap();
            match sdk_cloned.unlock(password).await {
                Ok(v) => log_cloned.send(format!("< {:?}", v)).unwrap(),
                Err(e) => log::warn!("Unlock err: {:?}", e),
            }
        });
    });

    let (sdk_cloned, log_cloned) = (Arc::clone(&sdk), log.clone());
    emulator_gui.get_xpub_btn.set_callback(move |_| {
        let value = app::widget_from_id::<Input>("get_xpub").unwrap().value();

        let sdk_cloned = sdk_cloned.clone();
        let log_cloned = log_cloned.clone();
        tokio::spawn(async move {
            log_cloned.send(format!("> GetXpub({})", value)).unwrap();
            match sdk_cloned.get_xpub(value.parse().unwrap()).await {
                Ok(v) => log_cloned.send(format!("< {:?}", v)).unwrap(),
                Err(e) => log::warn!("Get xpub err: {:?}", e),
            }
        });
    });

    let (sdk_cloned, log_cloned) = (Arc::clone(&sdk), log.clone());
    emulator_gui.set_descriptor_btn.set_callback(move |_| {
        let value = app::widget_from_id::<Input>("set_descriptor")
            .unwrap()
            .value();

        let sdk_cloned = sdk_cloned.clone();
        let log_cloned = log_cloned.clone();
        tokio::spawn(async move {
            log_cloned
                .send(format!("> SetDescriptor({})", value))
                .unwrap();
            match sdk_cloned.set_descriptor(value, None).await {
                Ok(v) => log_cloned.send(format!("< {:?}", v)).unwrap(),
                Err(e) => log::warn!("Set descriptor err: {:?}", e),
            }
        });
    });

    emulator_gui.window.end();
    emulator_gui.window.show();

    emulator_gui
}
