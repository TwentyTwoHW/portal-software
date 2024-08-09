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

use futures::prelude::*;

use rand::RngCore;

use gui::{ConfirmPairCodePage, SingleLineTextPage};
use model::{
    Entropy, ExtendedKey, InitializedConfig, MultisigKey, ScriptType, UnlockedConfig,
    UnverifiedConfig, WalletDescriptor,
};

use bdk_wallet::bitcoin::bip32;
use bdk_wallet::bitcoin::Network;
use bdk_wallet::descriptor::IntoWalletDescriptor;
use bdk_wallet::keys::bip39::Mnemonic;
use bdk_wallet::keys::{DescriptorPublicKey, DescriptorSecretKey, ValidNetworks};
use bdk_wallet::miniscript;
use bdk_wallet::miniscript::descriptor::{DescriptorXKey, KeyMap, Wildcard};

use gui::{GeneratingMnemonicPage, LoadingPage, MnemonicPage, Page, WelcomePage};
use model::{Config, DeviceInfo};

use super::*;
use crate::config;
use crate::Error;

fn map_err_config<X>(_: X) -> crate::hw::FlashError {
    crate::hw::FlashError::CorruptedData
}

// Ignore the network check on each key: we fully control the network of our
// wallet, so it should always be coherent.
// This saves ~58KB !
#[derive(Clone)]
struct SkipNetworkChecks(bdk_wallet::template::DescriptorTemplateOut);

impl IntoWalletDescriptor for SkipNetworkChecks {
    fn into_wallet_descriptor(
        self,
        _secp: &bdk_wallet::bitcoin::secp256k1::Secp256k1<bdk_wallet::bitcoin::secp256k1::All>,
        _network: Network,
    ) -> Result<
        (bdk_wallet::descriptor::ExtendedDescriptor, KeyMap),
        bdk_wallet::descriptor::DescriptorError,
    > {
        Ok((self.0 .0, self.0 .1))
    }
}

fn build_bdk_wallet_descriptor(
    xprv: &bip32::Xpriv,
    descriptor: model::WalletDescriptor,
    keychain: bdk_wallet::KeychainKind,
) -> Result<bdk_wallet::descriptor::template::DescriptorTemplateOut, Error> {
    fn extend_path(
        path: bip32::DerivationPath,
        keychain: bdk_wallet::KeychainKind,
    ) -> bip32::DerivationPath {
        let index = if keychain == bdk_wallet::KeychainKind::External {
            0
        } else {
            1
        };

        path.extend(&[bip32::ChildNumber::Normal { index }])
    }

    fn make_local_key(
        derivation_path: bip32::DerivationPath,
        xprv: &bip32::Xpriv,
        keychain: bdk_wallet::KeychainKind,
    ) -> (DescriptorPublicKey, KeyMap) {
        let secp = secp256k1::Secp256k1::new();

        let split_position = derivation_path
            .into_iter()
            .rev()
            .take_while(|c| c.is_normal())
            .count();
        let origin_path = derivation_path[..split_position].into();
        let derivation_path = derivation_path[split_position..].into();

        let secret_key = DescriptorSecretKey::XPrv(DescriptorXKey {
            origin: Some((xprv.fingerprint(&secp), origin_path)),
            xkey: *xprv,
            derivation_path: extend_path(derivation_path, keychain),
            wildcard: Wildcard::Unhardened,
        });
        let public_key = secret_key
            .to_public(&secp)
            .expect("Multi-path is never used");

        let mut map = KeyMap::new();
        map.insert(public_key.clone(), secret_key);

        (public_key, map)
    }

    match (descriptor.variant, descriptor.script_type) {
        (model::DescriptorVariant::SingleSig(path), ScriptType::NativeSegwit) => {
            let (public_key, key_map) = make_local_key(path.into(), xprv, keychain);
            let descriptor = miniscript::Descriptor::Wpkh(
                miniscript::descriptor::Wpkh::new(public_key).map_err(|_| Error::Wallet)?,
            );
            Ok((descriptor, key_map, ValidNetworks::new()))
        }
        (model::DescriptorVariant::SingleSig(path), ScriptType::WrappedSegwit) => {
            let (public_key, key_map) = make_local_key(path.into(), xprv, keychain);
            let descriptor = miniscript::Descriptor::Sh(
                miniscript::descriptor::Sh::new_wpkh(public_key).map_err(|_| Error::Wallet)?,
            );
            Ok((descriptor, key_map, ValidNetworks::new()))
        }
        (model::DescriptorVariant::SingleSig(path), ScriptType::Legacy) => {
            let (public_key, key_map) = make_local_key(path.into(), xprv, keychain);
            let descriptor = miniscript::Descriptor::Pkh(
                miniscript::descriptor::Pkh::new(public_key).map_err(|_| Error::Wallet)?,
            );
            Ok((descriptor, key_map, ValidNetworks::new()))
        }

        (
            model::DescriptorVariant::MultiSig {
                threshold,
                keys,
                is_sorted,
            },
            script_type,
        ) => {
            fn get_keys_vector(
                keys: alloc::vec::Vec<MultisigKey>,
                xprv: &bip32::Xpriv,
                keychain: bdk_wallet::KeychainKind,
            ) -> (KeyMap, alloc::vec::Vec<DescriptorPublicKey>) {
                let mut global_map = KeyMap::new();
                let keys = keys
                    .into_iter()
                    .map(|key| match key {
                        MultisigKey::Local(path) => {
                            let (public_key, mut key_map) =
                                make_local_key(path.clone().into(), xprv, keychain);
                            global_map.append(&mut key_map);

                            public_key
                        }
                        MultisigKey::External(ExtendedKey { origin, key, path }) => {
                            DescriptorPublicKey::XPub(DescriptorXKey {
                                origin: origin
                                    .map(|(fingerprint, path)| (fingerprint.into(), path.into())),
                                xkey: key
                                    .as_xpub()
                                    .expect("The key was checked when setting the config"),
                                derivation_path: extend_path(path.into(), keychain),
                                wildcard: Wildcard::Unhardened,
                            })
                        }
                    })
                    .collect();

                assert!(global_map.len() == 1);

                (global_map, keys)
            }

            // Unfortunately we have to duplicate this piece of code because we can't create a fragment for a "sortedmulti"
            if is_sorted {
                let (key_map, keys) = get_keys_vector(keys, xprv, keychain);

                match script_type {
                    ScriptType::NativeSegwit => {
                        let descriptor = miniscript::Descriptor::Wsh(
                            miniscript::descriptor::Wsh::new_sortedmulti(threshold, keys)
                                .map_err(|_| Error::Wallet)?,
                        );
                        Ok((descriptor, key_map, ValidNetworks::new()))
                    }
                    ScriptType::WrappedSegwit => {
                        let descriptor = miniscript::Descriptor::Sh(
                            miniscript::descriptor::Sh::new_wsh_sortedmulti(threshold, keys)
                                .map_err(|_| Error::Wallet)?,
                        );
                        Ok((descriptor, key_map, ValidNetworks::new()))
                    }
                    ScriptType::Legacy => Err(Error::Config(crate::hw::FlashError::CorruptedData)),
                }
            } else {
                return Err(Error::Wallet);

                // This adds way too much size to the binary, it needs to be investigated further...

                // match script_type {
                //     ScriptType::NativeSegwit => Ok(bdk_wallet::descriptor!(wsh(multi_vec(
                //         threshold,
                //         get_keys_vector(keys, xprv, keychain)
                //     )))?),
                //     ScriptType::WrappedSegwit => Ok(bdk_wallet::descriptor!(sh(wsh(multi_vec(
                //         threshold,
                //         get_keys_vector(keys, xprv, keychain)
                //     ))))?),
                //     ScriptType::Legacy => Ok(bdk_wallet::descriptor!(sh(multi_vec(
                //         threshold,
                //         get_keys_vector(keys, xprv, keychain)
                //     )))?),
                // }
            }
        }
    }
}

pub(super) fn make_wallet_from_xprv(
    xprv: bip32::Xpriv,
    network: Network,
    config: model::UnlockedConfig,
) -> Result<PortalWallet, Error> {
    let descriptor_external = SkipNetworkChecks(build_bdk_wallet_descriptor(
        &xprv,
        config.secret.descriptor.clone(),
        bdk_wallet::KeychainKind::External,
    )?);
    let descriptor_internal = SkipNetworkChecks(build_bdk_wallet_descriptor(
        &xprv,
        config.secret.descriptor.clone(),
        bdk_wallet::KeychainKind::Internal,
    )?);

    let wallet = bdk_wallet::Wallet::create(descriptor_external, descriptor_internal)
        .network(network)
        .create_wallet_no_persist()?;

    Ok(PortalWallet::new(wallet, xprv, config))
}

pub trait TryIntoCurrentState {
    fn try_into_current_state(self, rtc: &crate::hw::Rtc) -> Result<CurrentState, Error>;
}

impl TryIntoCurrentState for Config {
    fn try_into_current_state(self, rtc: &crate::hw::Rtc) -> Result<CurrentState, Error> {
        let config = match self {
            Config::Initialized(InitializedConfig {
                secret: model::MaybeEncrypted::Unencrypted(secret),
                network,
                ..
            }) => {
                log::debug!("Unencrypted config loaded");
                UnlockedConfig::from_secret_data_unencrypted(secret, network)
            }
            Config::Initialized(
                initialized @ InitializedConfig {
                    secret: model::MaybeEncrypted::Encrypted { .. },
                    ..
                },
            ) => {
                let fast_boot_key = crate::checkpoint::get_fastboot_key(&rtc);
                match initialized.try_unlock_fast_boot(&fast_boot_key) {
                    Ok(unlock) => unlock,
                    Err(_) => {
                        return Ok(CurrentState::Locked {
                            config: initialized,
                        })
                    }
                }
            }
            Config::Unverified(unverified) => {
                return Ok(CurrentState::UnverifiedConfig { config: unverified })
            }
        };

        let xprv = config
            .secret
            .cached_xprv
            .as_xprv()
            .map_err(map_err_config)?;
        Ok(CurrentState::Idle {
            wallet: Rc::new(make_wallet_from_xprv(xprv, config.network, config)?),
        })
    }
}

pub async fn handle_por(
    peripherals: &mut HandlerPeripherals,
    fast_boot: bool,
) -> Result<CurrentState, Error> {
    if !fast_boot {
        let page = LoadingPage::new();
        page.init_display(&mut peripherals.display)?;
        page.draw_to(&mut peripherals.display)?;
        peripherals.display.flush()?;
    }

    let config = match config::read_config(&mut peripherals.flash) {
        Ok(config) => config,
        Err(e) => {
            log::warn!("Config error: {:?}", e);
            return Ok(CurrentState::Init);
        }
    };

    config.try_into_current_state(&peripherals.rtc)
}

fn read_serial() -> alloc::string::String {
    const OPTION_BYTES: usize = 0x1FFF_7000;
    const SERIAL_OFFSET: usize = 4;
    const SERIAL_LEN: usize = 20;

    let mut buf = [0u8; SERIAL_LEN];
    let mut address = (OPTION_BYTES + SERIAL_OFFSET) as *const u8;

    for i in 0..SERIAL_LEN {
        unsafe {
            buf[i] = core::ptr::read(address);
            address = address.add(1);
        }
    }

    if buf[0] == 0xFF || buf[0] == 0x00 {
        alloc::string::String::from("NO_SERIAL")
    } else {
        buf.into_iter()
            .take_while(|v| *v != 0x00)
            .map(|v| v as char)
            .collect()
    }
}

pub async fn handle_init(
    mut events: impl Stream<Item = Event> + Unpin,
    peripherals: &mut HandlerPeripherals,
) -> Result<CurrentState, Error> {
    let serial = read_serial();

    let page = WelcomePage::new(&serial);
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
                    .send(model::Reply::Info(DeviceInfo::new_locked_uninitialized(
                        env!("CARGO_PKG_VERSION"),
                    )))
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
            #[cfg(not(feature = "production"))]
            Some(model::Request::BeginFwUpdate(header)) => {
                break Ok(CurrentState::UpdatingFw {
                    header,
                    fast_boot: None,
                });
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
                        env!("CARGO_PKG_VERSION"),
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
                    .map_err(|_| Error::Config(crate::hw::FlashError::CorruptedData))?;
                let xprv = unlocked
                    .secret
                    .cached_xprv
                    .as_xprv()
                    .map_err(map_err_config)?;
                peripherals.nfc.send(model::Reply::Ok).await.unwrap();

                // Set key for fastboot
                if let Some(key) = unlocked.get_key() {
                    crate::checkpoint::write_fastboot_key(key, &peripherals.rtc);
                }

                break Ok(CurrentState::Idle {
                    wallet: Rc::new(make_wallet_from_xprv(xprv, unlocked.network, unlocked)?),
                });
            }

            #[cfg(not(feature = "production"))]
            Some(model::Request::WipeDevice) => break Ok(CurrentState::WipeDevice),

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
    mut config: UnverifiedConfig,
    mut events: impl Stream<Item = Event> + Unpin,
    peripherals: &mut HandlerPeripherals,
) -> Result<CurrentState, Error> {
    peripherals.tsc_enabled.enable();

    let mnemonic = Mnemonic::from_entropy(&config.entropy.bytes).map_err(map_err_config)?;
    let mnemonic_str = mnemonic.word_iter().collect::<alloc::vec::Vec<_>>();
    for (chunk_index, words) in mnemonic_str.chunks(2).enumerate().skip(config.page) {
        let mut page = MnemonicPage::new((chunk_index * 2) as u8, &words);
        page.init_display(&mut peripherals.display)?;
        page.draw_to(&mut peripherals.display)?;
        peripherals.display.flush()?;

        manage_confirmation_loop(&mut events, peripherals, &mut page).await?;

        config.page = chunk_index + 1;
        save_unverified_config(config.clone(), peripherals).await?;
    }

    if let Some(pair_code) = &config.pair_code {
        let mut page = ConfirmPairCodePage::new(pair_code);
        page.init_display(&mut peripherals.display)?;
        page.draw_to(&mut peripherals.display)?;
        peripherals.display.flush()?;

        manage_confirmation_loop(&mut events, peripherals, &mut page).await?;
    }

    let page = LoadingPage::new();
    page.init_display(&mut peripherals.display)?;
    page.draw_to(&mut peripherals.display)?;
    peripherals.display.flush()?;

    let mut salt = [0; 8];
    peripherals.rng.fill_bytes(&mut salt);

    let network = config.network;
    let (initialized, unlocked, xprv) = config.upgrade(salt);
    config::write_config(&mut peripherals.flash, &Config::Initialized(initialized))?;

    peripherals.nfc.send(model::Reply::Ok).await.unwrap();
    peripherals.nfc_finished.recv().await.unwrap();

    Ok(CurrentState::Idle {
        wallet: Rc::new(make_wallet_from_xprv(xprv, network, unlocked)?),
    })
}

async fn save_unverified_config(
    unverified_config: UnverifiedConfig,
    peripherals: &mut HandlerPeripherals,
) -> Result<UnverifiedConfig, Error> {
    let config = Config::Unverified(unverified_config);
    config::write_config(&mut peripherals.flash, &config)?;
    let unverified_config = match config {
        Config::Unverified(c) => c,
        _ => unreachable!(),
    };

    Ok(unverified_config)
}

pub async fn handle_generate_seed(
    num_words: model::NumWordsMnemonic,
    network: Network,
    password: Option<String>,
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

    let descriptor = WalletDescriptor::make_bip84(network);

    let unverified_config = UnverifiedConfig {
        entropy: Entropy {
            bytes: alloc::vec::Vec::from(entropy).into(),
        },
        network,
        pair_code: password,
        descriptor,
        page: 0,
    };
    let unverified_config = save_unverified_config(unverified_config, peripherals).await?;
    display_mnemonic(unverified_config, events, peripherals).await
}

pub async fn handle_import_seed(
    mnemonic: String,
    network: Network,
    password: Option<String>,
    events: impl Stream<Item = Event> + Unpin,
    peripherals: &mut HandlerPeripherals,
) -> Result<CurrentState, Error> {
    let page = LoadingPage::new();
    page.init_display(&mut peripherals.display)?;
    page.draw_to(&mut peripherals.display)?;
    peripherals.display.flush()?;

    let mnemonic = Mnemonic::from_str(&mnemonic).map_err(map_err_config)?;
    let (entropy, len) = mnemonic.to_entropy_array();
    let entropy = &entropy[..len];

    let descriptor = WalletDescriptor::make_bip84(network);

    let unverified_config = UnverifiedConfig {
        entropy: Entropy {
            bytes: alloc::vec::Vec::from(entropy).into(),
        },
        network,
        pair_code: password,
        descriptor,
        page: 0,
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
                            env!("CARGO_PKG_VERSION"),
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
