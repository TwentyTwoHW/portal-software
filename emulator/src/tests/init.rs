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
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAABRklEQVR4nO2YURKDIAxEyf0PvR2FBNCiBOi0TtcPqVWSZ4hsQMKXDwIQgADPBcAi9h8CgAxhRBupRfwt9r8DwPlGCOprO7VaBwDEGYFoXp2kdgLAPQTmsmwzQHeCzQLUQagiMJaE3Rho5cAWi5Ec0DTuZEeV/WUrg1/BzMdILSDAHwMskEQCSK2vzjog6s6SemCbAftnwUL1ZFE94JyGG/o/Vw+4xvOuIvLXA24VOuk/8nAM1APqv4+jGfIS4KP1QDPrYQ3rAQIQgAAEeAwACHC6FtPVXO7Z0nffSykrDtPCrKYwK0ku98t4CmbwCkBPypPJEp31EhwfSX6QHs49stFrgFAQVwBpTwChfIsjgFIE3SrIPfQGwnQEILcAkAoghaQrAnMA1ncOwMpKHJOw9hhsZfA2CW3VcjDKeYBaQAACEIAA1fECvNkjRpSzZRoAAAAASUVORK5CYII=", None).await?;

    const SCREENS: [&'static str; 6] = [
        "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",
        super::LOADING
    ];

    for screen in SCREENS {
        tester.tsc(true).await?;
        tester.display_assertion(screen, Some(100)).await?;
    }

    tester.display_assertion(super::PORTAL_READY, None).await?;

    tester.nfc_assertion(model::Reply::Ok).await?;

    tester.nfc(NfcAction::RequestDescriptors).await?;
    tester.tsc(true).await?;
    tester
        .nfc_assertion(model::Reply::Descriptor {
            external: "wpkh([2bd3bdd7/84'/1'/0']tpubDCPMyXQR36y1uRVgsLGeNgN3awiqucyHGUa7pjQygcRbrbbWCMeRKnShL2hRfvE4zcQ9m9fjMMZHjSoQVatYyuwKqp6AyszbRt6s4iSXChJ/0/*)#klvmrneg".into(),
            internal: Some("wpkh([2bd3bdd7/84'/1'/0']tpubDCPMyXQR36y1uRVgsLGeNgN3awiqucyHGUa7pjQygcRbrbbWCMeRKnShL2hRfvE4zcQ9m9fjMMZHjSoQVatYyuwKqp6AyszbRt6s4iSXChJ/1/*)#8tf67xfs".into()),
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
        tester.tsc(true).await?;
        tester.display_assertion(screen, Some(100)).await?;
    }

    tester.display_assertion(super::PORTAL_READY, None).await?;

    tester.nfc_assertion(model::Reply::Ok).await?;

    tester.nfc(NfcAction::RequestDescriptors).await?;
    tester.tsc(true).await?;
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
        tester.tsc(true).await?;
        tester.display_assertion(screen, Some(100)).await?;
    }

    tester.display_assertion(super::PORTAL_READY, None).await?;

    tester.nfc_assertion(model::Reply::Ok).await?;

    tester.nfc(NfcAction::RequestDescriptors).await?;
    tester.tsc(true).await?;
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

    const SCREENS: [&'static str; 6] = [
        "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",
        super::LOADING
    ];

    for screen in SCREENS {
        tester.tsc(true).await?;
        tester.display_assertion(screen, Some(100)).await?;
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

    tester.nfc(NfcAction::RequestDescriptors).await?;
    tester.tsc(true).await?;
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
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAABRklEQVR4nO2YURKDIAxEyf0PvR2FBNCiBOi0TtcPqVWSZ4hsQMKXDwIQgADPBcAi9h8CgAxhRBupRfwt9r8DwPlGCOprO7VaBwDEGYFoXp2kdgLAPQTmsmwzQHeCzQLUQagiMJaE3Rho5cAWi5Ec0DTuZEeV/WUrg1/BzMdILSDAHwMskEQCSK2vzjog6s6SemCbAftnwUL1ZFE94JyGG/o/Vw+4xvOuIvLXA24VOuk/8nAM1APqv4+jGfIS4KP1QDPrYQ3rAQIQgAAEeAwACHC6FtPVXO7Z0nffSykrDtPCrKYwK0ku98t4CmbwCkBPypPJEp31EhwfSX6QHs49stFrgFAQVwBpTwChfIsjgFIE3SrIPfQGwnQEILcAkAoghaQrAnMA1ncOwMpKHJOw9hhsZfA2CW3VcjDKeYBaQAACEIAA1fECvNkjRpSzZRoAAAAASUVORK5CYII=", None).await?;

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
