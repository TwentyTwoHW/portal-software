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

use super::*;

#[functional_test_wrapper::functional_test(
    entropy = "0000000000000000000000000000000000000000000000000000000000000000"
)]
async fn test_generate_mnemonic_12words(mut tester: Tester) -> Result<(), crate::Error> {
    tester.display_assertion(super::WELCOME, None).await?;

    tester.nfc(NfcAction::GetStatus).await?;
    tester
        .nfc_assertion(model::Reply::Info(model::DeviceInfo {
            initialized: model::InitializationStatus::Uninitialized,
            firmware_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        }))
        .await?;

    tester
        .nfc(NfcAction::GenerateMnemonic(
            model::NumWordsMnemonic::Words12,
            model::bitcoin::Network::Signet,
            None,
        ))
        .await?;
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAABbUlEQVR4nO2YURLDIAhE5f6H3nZSQTAaNbbNz/YjGW2AN4iyiaSHfwQgAAH2AHBljynnBCjPQJYiH7bvGDh85LG/yyIAlpOh0ZFjqYc8RloCgKxnoAQ2gGr+Z0tQB0bqAP0PQJrzNwDmMHSNWyA6v1oDWtZpkuCIEtfeVf+NXXBnM7IXEIAAN5sIAXrteOSoaIBw+tWaII7dKTlqx6NTsNEBxd9bGgEeeLwEcwDeeTV/aslLAKO1hBlohqXfmgPAZbHJdBcywE4GmupoLAukit/n6NfAWQuoShK/RNt6oL8LgkJpaYSJXfB9PTApy37YCzDln92QAAQgwPMAIMBpLCZ7nLRzQkTcFwmvhaybInbFbPG5JHN4BaAX5Slkmc6sBPUjOQ7yw8WiOL0GSI44AHzQ81t/D0Apkn4qKBb6B9J2BiBDAEgAyCmZysAegNnuAZjkRF2EMWIyZdgsQntDqZzyHGAvIAABCECA8HsBUJhXRmrXkc8AAAAASUVORK5CYII=", None).await?;

    const SCREENS: [&'static str; 6] = [
        "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",
        super::LOADING
    ];

    for screen in SCREENS {
        tester.release_and_press().await?;
        tester.display_assertion(screen, Some(100)).await?;
    }

    tester.display_assertion(super::PORTAL_READY, None).await?;

    tester.nfc_assertion(model::Reply::Ok).await?;

    tester.nfc(NfcAction::RequestDescriptors).await?;
    tester
        .display_assertion(super::REQUEST_DESCRIPTOR, None)
        .await?;
    tester.release_and_press().await?;
    tester
        .nfc_assertion(model::Reply::Descriptor {
            external: "wpkh([fd50dc9c/84'/1'/0']tpubDChed5aPXLWED6QsfAoHAe6bHwYqSKqFU5DTTXyojnCXxqRQpnZNpDHnrQti1s9Wd1Y4YoBfSD6My4zUdXdwSYYRekAcYZM1RWNcyazAZfL/0/*)#4hkpx387".into(),
            internal: Some("wpkh([fd50dc9c/84'/1'/0']tpubDChed5aPXLWED6QsfAoHAe6bHwYqSKqFU5DTTXyojnCXxqRQpnZNpDHnrQti1s9Wd1Y4YoBfSD6My4zUdXdwSYYRekAcYZM1RWNcyazAZfL/1/*)#yrnqmyhx".into()),
        })
        .await?;

    Ok(())
}

// mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
#[functional_test_wrapper::functional_test(flash_file = "./test-vector/initialized.bin")]
async fn test_load_config(mut tester: Tester) -> Result<(), crate::Error> {
    tester.nfc(NfcAction::GetStatus).await?;
    tester
        .nfc_assertion(model::Reply::Info(model::DeviceInfo {
            initialized: model::InitializationStatus::Initialized {
                unlocked: true,
                network: model::bitcoin::Network::Signet,
                fingerprint: Some([115, 197, 218, 10]),
            },
            firmware_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        }))
        .await?;

    Ok(())
}

// mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
#[functional_test_wrapper::functional_test(flash_file = "./test-vector/initialized-locked.bin")]
async fn test_locked(mut tester: Tester) -> Result<(), crate::Error> {
    tester.nfc(NfcAction::GetStatus).await?;
    tester
        .nfc_assertion(model::Reply::Info(model::DeviceInfo {
            initialized: model::InitializationStatus::Initialized {
                unlocked: false,
                network: model::bitcoin::Network::Signet,
                fingerprint: None,
            },
            firmware_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        }))
        .await?;

    tester.display_assertion(super::LOCKED, None).await?;

    tester.nfc(NfcAction::DisplayAddress(42)).await?;
    tester.nfc_assertion(model::Reply::Locked).await?;

    tester.nfc(NfcAction::Unlock("paircode".into())).await?;
    tester.nfc_assertion(model::Reply::Ok).await?;

    tester.display_assertion(super::PORTAL_READY, None).await?;

    tester.nfc(NfcAction::GetStatus).await?;
    tester
        .nfc_assertion(model::Reply::Info(model::DeviceInfo {
            initialized: model::InitializationStatus::Initialized {
                unlocked: true,
                network: model::bitcoin::Network::Signet,
                fingerprint: Some([115, 197, 218, 10]),
            },
            firmware_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        }))
        .await?;

    Ok(())
}

#[functional_test_wrapper::functional_test]
async fn test_restore_mnemonic(mut tester: Tester) -> Result<(), crate::Error> {
    tester.nfc(NfcAction::GetStatus).await?;
    tester
        .nfc_assertion(model::Reply::Info(model::DeviceInfo {
            initialized: model::InitializationStatus::Uninitialized,
            firmware_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        }))
        .await?;

    tester
        .nfc(NfcAction::RestoreMnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
            model::bitcoin::Network::Signet,
            None,
        ))
        .await?;
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAABJ0lEQVR4nO2Y0Q6DMAhFy/9/NNtoAalacV23ZLk+aKoFjhTLjVR+fAAAAAB4D4BHdnzLKQB8LlMqstg8Y7DYHoyJ5Ua8nwDIc6tXtdiMW2y57uaNAZjyGfAA/fjs+rEluAr0DwBjDF/jszXfj7M1oGVbLgjEa1/125rovoJ8Bm58jOgFAAAA9MASAE7BrNMDrx0wuQuu0QPJbXipHiiUW/tF7TgpiJYBaHzoAegBAAAAAAD4PgADYDdu7UyeqOyz1if/Uswq6CLrphw7ZLOop2IORwB6Uh4na3Rm5b052tYp5kL+AJnTMUDZEAeAil5frJwBKIVJB7fQB1ymM8B0CcAUAFpKUhmYAzDbOQAT89wXYYzo6vCwCE23dU6xD6AXAAAAAABAOB6LknRGg9zGfwAAAABJRU5ErkJggg==", None).await?;

    const SCREENS: [&'static str; 6] = [
        "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",
        super::LOADING
    ];

    for screen in SCREENS {
        tester.release_and_press().await?;
        tester.display_assertion(screen, None).await?;
    }

    tester.display_assertion(super::PORTAL_READY, None).await?;

    tester.nfc_assertion(model::Reply::Ok).await?;

    tester.nfc(NfcAction::RequestDescriptors).await?;
    tester
        .display_assertion(super::REQUEST_DESCRIPTOR, None)
        .await?;
    tester.release_and_press().await?;
    tester
        .nfc_assertion(model::Reply::Descriptor {
            external: super::WPKH_EXTERNAL_DESC.to_string(),
            internal: Some(super::WPKH_INTERNAL_DESC.to_string()),
        })
        .await?;

    Ok(())
}

#[functional_test_wrapper::functional_test]
async fn test_restore_mnemonic_pair_code(mut tester: Tester) -> Result<(), crate::Error> {
    tester.nfc(NfcAction::GetStatus).await?;
    tester
        .nfc_assertion(model::Reply::Info(model::DeviceInfo {
            initialized: model::InitializationStatus::Uninitialized,
            firmware_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        }))
        .await?;

    tester
        .nfc(NfcAction::RestoreMnemonic(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
            model::bitcoin::Network::Signet,
            Some("pair code".into()),
        ))
        .await?;
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAABJ0lEQVR4nO2Y0Q6DMAhFy/9/NNtoAalacV23ZLk+aKoFjhTLjVR+fAAAAAB4D4BHdnzLKQB8LlMqstg8Y7DYHoyJ5Ua8nwDIc6tXtdiMW2y57uaNAZjyGfAA/fjs+rEluAr0DwBjDF/jszXfj7M1oGVbLgjEa1/125rovoJ8Bm58jOgFAAAA9MASAE7BrNMDrx0wuQuu0QPJbXipHiiUW/tF7TgpiJYBaHzoAegBAAAAAAD4PgADYDdu7UyeqOyz1if/Uswq6CLrphw7ZLOop2IORwB6Uh4na3Rm5b052tYp5kL+AJnTMUDZEAeAil5frJwBKIVJB7fQB1ymM8B0CcAUAFpKUhmYAzDbOQAT89wXYYzo6vCwCE23dU6xD6AXAAAAAABAOB6LknRGg9zGfwAAAABJRU5ErkJggg==", None).await?;

    const SCREENS: [&'static str; 7] = [
        "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",
        super::LOADING
    ];

    for screen in SCREENS {
        tester.release_and_press().await?;
        tester.display_assertion(screen, Some(100)).await?;
    }

    tester.display_assertion(super::PORTAL_READY, None).await?;

    tester.nfc_assertion(model::Reply::Ok).await?;

    tester.nfc(NfcAction::RequestDescriptors).await?;
    tester
        .display_assertion(super::REQUEST_DESCRIPTOR, None)
        .await?;
    tester.release_and_press().await?;
    tester
        .nfc_assertion(model::Reply::Descriptor {
            external: super::WPKH_EXTERNAL_DESC.to_string(),
            internal: Some(super::WPKH_INTERNAL_DESC.to_string()),
        })
        .await?;

    Ok(())
}

// mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
#[functional_test_wrapper::functional_test(flash_file = "./test-vector/unverified.bin")]
async fn test_unverified(mut tester: Tester) -> Result<(), crate::Error> {
    tester.nfc(NfcAction::GetStatus).await?;
    tester
        .nfc_assertion(model::Reply::Info(model::DeviceInfo {
            initialized: model::InitializationStatus::Unverified {
                with_code: false,
                network: model::bitcoin::Network::Signet,
            },
            firmware_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        }))
        .await?;

    tester.display_assertion(super::LOADING, None).await?;
    tester.nfc(NfcAction::Resume).await?;

    const SCREENS: [&'static str; 7] = [
        "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",
        super::LOADING
    ];

    for screen in SCREENS {
        tester.release_and_press().await?;
        tester.display_assertion(screen, None).await?;
    }

    tester.nfc_assertion(model::Reply::Ok).await?;
    tester.display_assertion(super::PORTAL_READY, None).await?;

    tester.nfc(NfcAction::GetStatus).await?;
    tester
        .nfc_assertion(model::Reply::Info(model::DeviceInfo {
            initialized: model::InitializationStatus::Initialized {
                unlocked: true,
                network: model::bitcoin::Network::Signet,
                fingerprint: Some([115, 197, 218, 10]),
            },
            firmware_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        }))
        .await?;

    tester.wait_ticks(2).await?;

    tester.nfc(NfcAction::RequestDescriptors).await?;
    tester
        .display_assertion(super::REQUEST_DESCRIPTOR, None)
        .await?;
    tester.release_and_press().await?;
    tester
        .nfc_assertion(model::Reply::Descriptor {
            external: super::WPKH_EXTERNAL_DESC.to_string(),
            internal: Some(super::WPKH_INTERNAL_DESC.to_string()),
        })
        .await?;

    Ok(())
}

#[functional_test_wrapper::functional_test(
    entropy = "0000000000000000000000000000000000000000000000000000000000000000"
)]
async fn test_reset_during_generate_mnemonic(mut tester: Tester) -> Result<(), crate::Error> {
    tester.display_assertion(super::WELCOME, None).await?;

    tester.nfc(NfcAction::GetStatus).await?;
    tester
        .nfc_assertion(model::Reply::Info(model::DeviceInfo {
            initialized: model::InitializationStatus::Uninitialized,
            firmware_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        }))
        .await?;

    tester
        .nfc(NfcAction::GenerateMnemonic(
            model::NumWordsMnemonic::Words12,
            model::bitcoin::Network::Signet,
            None,
        ))
        .await?;
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAABbUlEQVR4nO2YURLDIAhE5f6H3nZSQTAaNbbNz/YjGW2AN4iyiaSHfwQgAAH2AHBljynnBCjPQJYiH7bvGDh85LG/yyIAlpOh0ZFjqYc8RloCgKxnoAQ2gGr+Z0tQB0bqAP0PQJrzNwDmMHSNWyA6v1oDWtZpkuCIEtfeVf+NXXBnM7IXEIAAN5sIAXrteOSoaIBw+tWaII7dKTlqx6NTsNEBxd9bGgEeeLwEcwDeeTV/aslLAKO1hBlohqXfmgPAZbHJdBcywE4GmupoLAukit/n6NfAWQuoShK/RNt6oL8LgkJpaYSJXfB9PTApy37YCzDln92QAAQgwPMAIMBpLCZ7nLRzQkTcFwmvhaybInbFbPG5JHN4BaAX5Slkmc6sBPUjOQ7yw8WiOL0GSI44AHzQ81t/D0Apkn4qKBb6B9J2BiBDAEgAyCmZysAegNnuAZjkRF2EMWIyZdgsQntDqZzyHGAvIAABCECA8HsBUJhXRmrXkc8AAAAASUVORK5CYII=", None).await?;

    tester.reset().await?;
    tester.wait_ticks(5).await?;

    // Expect an error from re-trying the "GenerateMnemonic"
    tester.nfc_assertion(model::Reply::Unverified).await?;

    tester.nfc(NfcAction::GetStatus).await?;
    tester
        .nfc_assertion(model::Reply::Info(model::DeviceInfo {
            initialized: model::InitializationStatus::Unverified {
                with_code: false,
                network: model::bitcoin::Network::Signet,
            },
            firmware_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        }))
        .await?;

    Ok(())
}

#[functional_test_wrapper::functional_test(
    entropy = "0000000000000000000000000000000000000000000000000000000000000000"
)]
async fn test_send_raw_getinfo_msg(mut tester: Tester) -> Result<(), crate::Error> {
    tester.nfc(NfcAction::Raw(vec![130, 0, 128])).await?;
    tester
        .nfc_assertion(model::Reply::Info(model::DeviceInfo {
            initialized: model::InitializationStatus::Uninitialized,
            firmware_version: Some(env!("CARGO_PKG_VERSION").to_string()),
        }))
        .await?;

    Ok(())
}
