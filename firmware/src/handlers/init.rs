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

use core::str::FromStr;

use alloc::string::ToString;
use futures::prelude::*;

use gui::ConfirmPairCodePage;
use gui::SingleLineTextPage;
use model::Entropy;
use model::InitializedConfig;
use model::UnverifiedConfig;
use rand::RngCore;

use bdk::bitcoin::util::bip32;
use bdk::bitcoin::Network;
use bdk::descriptor::template::DescriptorTemplate;
use bdk::descriptor::IntoWalletDescriptor;
use bdk::keys::bip39::Mnemonic;

use gui::{
    GeneratingMnemonicPage, ImportingMnemonicPage, LoadingPage, MnemonicPage, Page, WelcomePage,
};
use model::{Config, DeviceInfo};

use super::*;
use crate::config;
use crate::Error;

fn map_err_config<X>(_: X) -> config::ConfigError {
    config::ConfigError::CorruptedConfig
}

// Ignore the network check on each key: we fully control the network of our
// wallet, so it should always be coherent.
// This saves ~58KB !
struct SkipNetworkChecks<T>(T);

impl<T: DescriptorTemplate> IntoWalletDescriptor for SkipNetworkChecks<T> {
    fn into_wallet_descriptor(
        self,
        _secp: &bdk::bitcoin::secp256k1::Secp256k1<bdk::bitcoin::secp256k1::All>,
        network: Network,
    ) -> Result<
        (bdk::descriptor::ExtendedDescriptor, bdk::keys::KeyMap),
        bdk::descriptor::DescriptorError,
    > {
        let (a, b, _) = self.0.build(network)?;
        Ok((a, b))
    }
}

fn make_wallet_from_xprv(
    xprv: bip32::ExtendedPrivKey,
    network: Network,
) -> Result<bdk::Wallet, Error> {
    let descriptor = SkipNetworkChecks(bdk::descriptor::template::Bip84(
        xprv,
        bdk::KeychainKind::External,
    ));
    let descriptor_internal = SkipNetworkChecks(bdk::descriptor::template::Bip84(
        xprv,
        bdk::KeychainKind::Internal,
    ));
    let wallet = bdk::Wallet::new(descriptor, Some(descriptor_internal), (), network)?;

    Ok(wallet)
}

pub async fn handle_por(peripherals: &mut HandlerPeripherals) -> Result<CurrentState, Error> {
    let page = LoadingPage::new();
    page.init_display(&mut peripherals.display)?;
    page.draw_to(&mut peripherals.display)?;
    peripherals.display.flush()?;

    let config = match config::read_config(&mut peripherals.flash).await {
        Ok(config) => config,
        Err(e) => {
            log::warn!("Config error: {:?}", e);
            return Ok(CurrentState::Init);
        }
    };
    match config {
        Config::Initialized(InitializedConfig {
            secret: model::MaybeEncrypted::Unencrypted(secret),
            network,
            ..
        }) => {
            log::debug!("Unencrypted config loaded");

            let xprv = secret.cached_xprv.as_xprv().map_err(map_err_config)?;
            Ok(CurrentState::Idle {
                wallet: Rc::new(make_wallet_from_xprv(xprv, network)?),
            })
        }
        Config::Initialized(
            initialized @ InitializedConfig {
                secret: model::MaybeEncrypted::Encrypted { .. },
                ..
            },
        ) => Ok(CurrentState::Locked {
            config: initialized,
        }),
        Config::Unverified(unverified) => Ok(CurrentState::UnverifiedConfig { config: unverified }),
    }
}

pub async fn handle_init(
    mut events: impl Stream<Item = Event> + Unpin,
    peripherals: &mut HandlerPeripherals,
) -> Result<CurrentState, Error> {
    let page = WelcomePage::new("");
    page.init_display(&mut peripherals.display)?;
    page.draw_to(&mut peripherals.display)?;
    peripherals.display.flush()?;

    let events = only_requests(&mut events);
    pin_mut!(events);

    loop {
        match events.next().await {
            Some(model::Request::GetInfo) => {
                peripherals
                    .nfc
                    .send(model::Reply::Info(DeviceInfo::new_locked_uninitialized()))
                    .await
                    .unwrap();
                peripherals.nfc_finished.recv().await.unwrap();
                continue;
            }
            Some(model::Request::GenerateMnemonic {
                num_words,
                network,
                password,
            }) => {
                break Ok(CurrentState::GenerateSeed {
                    num_words,
                    network,
                    password,
                });
            }
            Some(model::Request::SetMnemonic {
                mnemonic,
                network,
                password,
            }) => {
                break Ok(CurrentState::ImportSeed {
                    mnemonic,
                    network,
                    password,
                });
            }
            #[cfg(feature = "emulator")]
            Some(model::Request::BeginFwUpdate(header)) => {
                break Ok(CurrentState::UpdatingFw { header });
            }
            Some(_) => {
                peripherals
                    .nfc
                    .send(model::Reply::UnexpectedMessage)
                    .await
                    .unwrap();
                peripherals.nfc_finished.recv().await.unwrap();
                continue;
            }
            _ => unreachable!(),
        }
    }
}

pub async fn handle_locked(
    config: InitializedConfig,
    mut events: impl Stream<Item = Event> + Unpin,
    peripherals: &mut HandlerPeripherals,
) -> Result<CurrentState, Error> {
    let page = SingleLineTextPage::new("LOCKED");
    page.init_display(&mut peripherals.display)?;
    page.draw_to(&mut peripherals.display)?;
    peripherals.display.flush()?;

    let events = only_requests(&mut events);
    pin_mut!(events);

    loop {
        match events.next().await {
            Some(model::Request::GetInfo) => {
                peripherals
                    .nfc
                    .send(model::Reply::Info(DeviceInfo::new_locked_initialized(
                        config.network,
                    )))
                    .await
                    .unwrap();
                peripherals.nfc_finished.recv().await.unwrap();
                continue;
            }
            Some(model::Request::Unlock { password }) => {
                if !config.pair_code.check(&password) {
                    peripherals
                        .nfc
                        .send(model::Reply::WrongPassword)
                        .await
                        .unwrap();
                    peripherals.nfc_finished.recv().await.unwrap();
                    continue;
                }

                let page = LoadingPage::new();
                page.init_display(&mut peripherals.display)?;
                page.draw_to(&mut peripherals.display)?;
                peripherals.display.flush()?;

                let unlocked = config
                    .unlock(&password)
                    .map_err(|_| Error::Config(config::ConfigError::CorruptedConfig))?;
                let xprv = unlocked
                    .secret
                    .cached_xprv
                    .as_xprv()
                    .map_err(map_err_config)?;
                peripherals.nfc.send(model::Reply::Ok).await.unwrap();

                break Ok(CurrentState::Idle {
                    wallet: Rc::new(make_wallet_from_xprv(xprv, unlocked.network)?),
                });
            }
            Some(_) => {
                peripherals.nfc.send(model::Reply::Locked).await.unwrap();
                peripherals.nfc_finished.recv().await.unwrap();
                continue;
            }
            _ => unreachable!(),
        }
    }
}

pub async fn display_mnemonic(
    config: UnverifiedConfig,
    mut events: impl Stream<Item = Event> + Unpin,
    peripherals: &mut HandlerPeripherals,
) -> Result<CurrentState, Error> {
    peripherals.tsc_enabled.enable();

    let mnemonic = Mnemonic::from_entropy(&config.entropy.bytes).map_err(map_err_config)?;
    let mnemonic_str = mnemonic.word_iter().collect::<alloc::vec::Vec<_>>();
    for (chunk_index, words) in mnemonic_str.chunks(2).enumerate() {
        let mut page = MnemonicPage::new((chunk_index * 2) as u8, &words);
        page.init_display(&mut peripherals.display)?;
        page.draw_to(&mut peripherals.display)?;
        peripherals.display.flush()?;

        manage_confirmation_loop(&mut events, peripherals, &mut page).await?;

        // TODO: store checkpoint?
    }

    if let Some(pair_code) = &config.pair_code {
        let mut page = ConfirmPairCodePage::new(pair_code);
        page.init_display(&mut peripherals.display)?;
        page.draw_to(&mut peripherals.display)?;
        peripherals.display.flush()?;

        manage_confirmation_loop(&mut events, peripherals, &mut page).await?;
    }

    let mut salt = [0; 8];
    peripherals.rng.fill_bytes(&mut salt);

    let network = config.network;
    let (initialized, xprv) = config.upgrade(salt);
    config::write_config(&mut peripherals.flash, &Config::Initialized(initialized)).await?;

    peripherals.nfc.send(model::Reply::Ok).await.unwrap();
    peripherals.nfc_finished.recv().await.unwrap();

    Ok(CurrentState::Idle {
        wallet: Rc::new(make_wallet_from_xprv(xprv, network)?),
    })
}

async fn save_unverified_config(
    unverified_config: UnverifiedConfig,
    peripherals: &mut HandlerPeripherals,
) -> Result<UnverifiedConfig, Error> {
    let config = Config::Unverified(unverified_config);
    config::write_config(&mut peripherals.flash, &config).await?;
    let unverified_config = match config {
        Config::Unverified(c) => c,
        _ => unreachable!(),
    };

    Ok(unverified_config)
}

pub async fn handle_generate_seed(
    num_words: model::NumWordsMnemonic,
    network: Network,
    password: Option<&str>,
    events: impl Stream<Item = Event> + Unpin,
    peripherals: &mut HandlerPeripherals,
) -> Result<CurrentState, Error> {
    let page = GeneratingMnemonicPage::new(num_words);
    page.init_display(&mut peripherals.display)?;
    page.draw_to(&mut peripherals.display)?;
    peripherals.display.flush()?;

    let mut entropy = [0u8; 32];
    let entropy = match num_words {
        model::NumWordsMnemonic::Words12 => &mut entropy[..16],
        model::NumWordsMnemonic::Words24 => &mut entropy[..32],
    };
    rand_chacha::rand_core::RngCore::fill_bytes(&mut peripherals.rng, entropy);

    let unverified_config = UnverifiedConfig {
        entropy: Entropy {
            bytes: alloc::vec::Vec::from(entropy).into(),
        },
        network,
        pair_code: password.map(ToString::to_string),
    };
    let unverified_config = save_unverified_config(unverified_config, peripherals).await?;
    display_mnemonic(unverified_config, events, peripherals).await
}

pub async fn handle_import_seed(
    mnemonic: &str,
    network: Network,
    password: Option<&str>,
    events: impl Stream<Item = Event> + Unpin,
    peripherals: &mut HandlerPeripherals,
) -> Result<CurrentState, Error> {
    let page = ImportingMnemonicPage::new();
    page.init_display(&mut peripherals.display)?;
    page.draw_to(&mut peripherals.display)?;
    peripherals.display.flush()?;

    let mnemonic = Mnemonic::from_str(mnemonic).map_err(map_err_config)?;
    let (entropy, len) = mnemonic.to_entropy_array();
    let entropy = &entropy[..len];

    let unverified_config = UnverifiedConfig {
        entropy: Entropy {
            bytes: alloc::vec::Vec::from(entropy).into(),
        },
        network,
        pair_code: password.map(ToString::to_string),
    };
    let unverified_config = save_unverified_config(unverified_config, peripherals).await?;
    display_mnemonic(unverified_config, events, peripherals).await
}

pub async fn handle_unverified_config(
    config: UnverifiedConfig,
    mut events: impl Stream<Item = Event> + Unpin,
    peripherals: &mut HandlerPeripherals,
) -> Result<CurrentState, Error> {
    let page = LoadingPage::new();
    page.init_display(&mut peripherals.display)?;
    page.draw_to(&mut peripherals.display)?;
    peripherals.display.flush()?;

    {
        let req_events = only_requests(&mut events);
        pin_mut!(req_events);

        loop {
            match req_events.next().await {
                Some(model::Request::GetInfo) => {
                    peripherals
                        .nfc
                        .send(model::Reply::Info(DeviceInfo::new_unverified_config(
                            config.network,
                            config.pair_code.is_some(),
                        )))
                        .await
                        .unwrap();
                    peripherals.nfc_finished.recv().await.unwrap();
                    continue;
                }
                Some(model::Request::Resume) => {
                    peripherals
                        .nfc
                        .send(model::Reply::DelayedReply)
                        .await
                        .unwrap();
                    break;
                }
                Some(_) => {
                    peripherals
                        .nfc
                        .send(model::Reply::Unverified)
                        .await
                        .unwrap();
                    peripherals.nfc_finished.recv().await.unwrap();
                    continue;
                }
                _ => unreachable!(),
            }
        }
    }

    display_mnemonic(config, events, peripherals).await
}
