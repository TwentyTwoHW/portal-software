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

use std::str::FromStr;

use model::bitcoin::bip32;

use super::*;

// mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
const DERIVED_BIP48_XPUB: &'static str = "[73c5da0a/48'/1'/0'/2']tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ";
// mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon knock"
const EXTERNAL_BIP48_XPUB: &'static str = "[3977ad96/48'/1'/0'/2']tpubDE2WqbYnigRFTi6h4Km571hyX5umkEUvgLUa8kuB7tWXeBD6ffvbXqM2adiWoX9cpwQC9EQakVhy82yeCvwy1RHJVzFaC1ffhNVmEphWuEk";

// mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
#[functional_test_wrapper::functional_test(flash_file = "./test-vector/initialized.bin")]
async fn test_get_xpub(mut tester: Tester) -> Result<(), crate::Error> {
    tester.display_assertion(super::PORTAL_READY, None).await?;

    tester
        .nfc(NfcAction::GetXpub("m/48'/1'/0'/2'".into()))
        .await?;

    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAAByklEQVR4nO2XiY4CIQxA6f9/dFdtoTfDbOK6idU4GUuPB7QcMD78aYAGaIAGaAANgHsihJ0YydIrJUZogsB1hDOAojlKnxIljQCk8Pg+21609I5KmyVak6z5VWu+fuxnakE9BexzUAAOQcbKLGk1+GZcUFBD//MpEEV5Wm7fGgHshFN2cb8uAeIIgOqMHYHHy+kIkFnIiVgFWQ4MnegrB8ih1jTPkAPZCJVVt68I/NXyEYL/NYBbAXop/ucAXFRSxLYM9LoX5JLyRp76qQDUkjoLztbhyAPRmg3oA02Z97MHoKW5BJDN4TrQEYCQr6BYALgeGvlGfw+AIlg+XA7YCbKONLdviSAjBZBVFVRvosPKH1r6o/gZwBpfUggOXSp6ea2fxfd6Kg+SOQ21lfWz1E/jvwEg81HHzwAgqcYBcSNC6wAh33NkM0/rvveCBmiABmiAzwNgAyQSWIdbuVzruyfgsgM5oNLfeZKe++q6kLPsEGA+hrLiN76Po+VFb8s3bK0CsilvAcbsowfgg/q6M6QAQwVTFncADkYA4RIAZZhAHbbeD7BsLcBquJWEahjtFChPwFmXJuE8zeEdgK9bB3ovaIAGaICvB/gBcI2wRnoFKhcAAAAASUVORK5CYII=", None).await?;
    tester.release_and_press().await?;

    tester.display_assertion(super::PORTAL_READY, None).await?;

    tester
        .nfc_assertion(model::Reply::Xpub {
            xpub: DERIVED_BIP48_XPUB.into(),
            bsms: model::BsmsRound1 {
                version: "1.0".into(),
                token: "00".into(),
                key_name: "Portal 73C5DA0A".into(),
                signature: Box::new(
                    [
                        32, 67, 97, 157, 182, 100, 202, 227, 110, 25, 164, 54, 201, 242, 103, 248,
                        177, 160, 159, 199, 195, 29, 216, 187, 242, 137, 120, 166, 64, 75, 102,
                        162, 60, 59, 152, 103, 86, 204, 89, 239, 53, 112, 50, 158, 130, 107, 103,
                        237, 86, 160, 189, 38, 104, 150, 232, 3, 103, 102, 26, 169, 43, 57, 223,
                        83, 52,
                    ]
                    .into(),
                ),
            },
        })
        .await?;

    Ok(())
}

// mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
#[functional_test_wrapper::functional_test(flash_file = "./test-vector/initialized.bin")]
async fn test_set_descriptor_sorted_multisig(mut tester: Tester) -> Result<(), crate::Error> {
    tester.display_assertion(super::PORTAL_READY, None).await?;

    tester
        .nfc(NfcAction::SetDescriptor(
            format!(
                "wsh(sortedmulti(1,{}/*,{}/*))",
                DERIVED_BIP48_XPUB, EXTERNAL_BIP48_XPUB
            ),
            None,
        ))
        .await?;

    let sequence = [
        "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",
    ];

    for assertion in sequence {
        tester.display_assertion(assertion, None).await?;
        tester.release_and_press().await?;
    }

    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAAB7ElEQVR4nO2YgXIDIQhE4f8/epvkBBfQa9M0bTMhMzW5E/G5olhV/vjTAA3QAA3QAFcAVA4cFRu8Te3S/HgJPQGAFoPL477JtvYRANMBivlq/Lx+Xf6mj1I72vKMHqoezW4lW3KpzDg6U3OFw4fgcKDuu9SuFIB3fivd0uyPMgMoKwyqnQC11kakHCYiyj5NNhliJQWgDwF4YLhKWhRIsWDPKmFGAoC/SZ3VWl9OGhSIMUCRJrPsjagB/gvAiN8QxipxWYuWZ5RRjAWBzeBQ+twBILnVSmfPjGrbtm82iywW220AIN8HWNjfA2Dg8Ew9RjRGNnYSzZ2Z9AFg921+HQBCezTmrob5LtbPueRZUwbwPlLH5GIzBQmgjGBhZyOAp3h71hQXCehxgCJXiAe2W/n7PYAvKRAiTGq8fAJAbUNIrGKhxgClT55Db03BEzcUl46GGBJ0WEW0WuIqOP3gqfv1KwB0Om6ABmiAJwOgAfinzrQ8cyKdJ8ahkDIh2M7+CQZlQHYQsv0GwArjmWRCtxej3Wxh2Tu2VSw8K4LqDODsGcDuG/j456fkpEq4sMF6aCTAvQpApShAU+AKJYB5sTZNfg6A7PyCqUxBcX8ehFPLNAUMJX6IY1AKwgXAaRC+6z7QuaABGqAB3h7gA9QABVWY+g8IAAAAAElFTkSuQmCC", None).await?;
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAAB9ElEQVR4nO2YgXLCMAiG4f0fmmkT4CeQOqe7eie7W6sJIV9+kKRluvivARqgARqgAe4AkjlkdGzwNr2l+WgUPgEQTga3r/sh295XAFQHYfGm+fF+u/27j9Q7x2JEh6pj2HFFS7wyMs7JWF3J8EEyHLD5Tr2VAmKTH1ezVPtxXQEYFRbodYDcqytiTBMiRp8qG02xFgWEXwKwxDCVOCmw5IJ+ZwoRCQDWskyWe+3nxEGBmAOQaeTXLkQN8DEAoYxhOofKtuk8GffQjsuRhSN5GuB3dlzaXgZw1OxRQEj3jmkjtnPPwk5wh3ZJoZz95D7Z/DsA1GgJc/jUca4A4O3uGe18dWavraFAgkFYd1gMSQ0QFNER3nZMlvyHEFQAnv0rgHC81wB+Ltj43wKYRK7oXwAw3iFUD0MQErHIAZXUpX0Qc9sHuUrCKksxe61Qic22rrr8deTMpVWpN5bicBrgfTGJ7f8DAPUjVfSlvXfDBmiABrgeQBoAP/pOR36OgXPFPPSRP4sK2ulDMJ4R0AGc2GQHoBflcTKCtxdzHBxI5nYex7IUnlmC6ghg7CuAvm8A9vVk5A7wEVzqpYEAzyogTEkBCIEptAD4izU3eR8A2NkLphSC5P48CV3LJQQIRfgQUSVhAXCahN9aB3ovaIAGaICvB/gBrTgKVXrveZIAAAAASUVORK5CYII=", None).await?;
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAAB7ElEQVR4nO2YgXIDIQhE4f8/epvkBBfQa9M0bTMhMzW5E/G5olhV/vjTAA3QAA3QAFcAVA4cFRu8Te3S/HgJPQGAFoPL477JtvYRANMBivlq/Lx+Xf6mj1I72vKMHqoezW4lW3KpzDg6U3OFw4fgcKDuu9SuFIB3fivd0uyPMgMoKwyqnQC11kakHCYiyj5NNhliJQWgDwF4YLhKWhRIsWDPKmFGAoC/SZ3VWl9OGhSIMUCRJrPsjagB/gvAiN8QxipxWYuWZ5RRjAWBzeBQ+twBILnVSmfPjGrbtm82iywW220AIN8HWNjfA2Dg8Ew9RjRGNnYSzZ2Z9AFg921+HQBCezTmrob5LtbPueRZUwbwPlLH5GIzBQmgjGBhZyOAp3h71hQXCehxgCJXiAe2W/n7PYAvKRAiTGq8fAJAbUNIrGKhxgClT55Db03BEzcUl46GGBJ0WEW0WuIqOP3gqfv1KwB0Om6ABmiAJwOgAfinzrQ8cyKdJ8ahkDIh2M7+CQZlQHYQsv0GwArjmWRCtxej3Wxh2Tu2VSw8K4LqDODsGcDuG/j456fkpEq4sMF6aCTAvQpApShAU+AKJYB5sTZNfg6A7PyCqUxBcX8ehFPLNAUMJX6IY1AKwgXAaRC+6z7QuaABGqAB3h7gA9QABVWY+g8IAAAAAElFTkSuQmCC", None).await?;
    tester.release_and_press().await?;

    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAABxklEQVR4nO2X7XaDIAyGk/u/6KyrId9OnOzYHdMfVAXCQwh5AeHmXwM0QAM0QAM0wKcD0J9T4sH4KOWNADcugQGgrbXxCYXur4/EX7hqxoGzMcBDotokwdG2KO1M9SUA7wdrOBuXL/ZBXq8C0GiuANGAGZerFgLkpc9mgwesE65vwzG0iT2KGD48nCuWBCE4P+i+qJIGmdA92MqtBQ3w+QCS8X8nTPu9eKfghIHzoqxtd3uNXDEPsGbeNYCkFE2zFB1vlfZVHRRHu4tMoO1VWGbrLqkaocmO94nO6bIVyJChSecRLPNXDGob9VQDlSDBVitUAmTLUvczwK4HSgCR7DmArTwL4HTGAxxhJw8ARGEtTju1KYjLDzY8is1bnaPEA+UuiABOl6UxpiWQOebG8ZhqAE7v8IXH9X8HsPyy1nIsJ9cnA4zLg8qazanvEvWQjxAuRuSvjtucREWCeYxZXABGAaCD8dPWKV+45CUb4OpY+20lDjQyVwmQktsUgPybgwIDAE9EJH3aA4Q7AG+bEC5jslxij8dGKaT+KoBzfAHg/YNQLoGPjRiEfkTGhjAEuHMZuhD1FEUQPj0PtBY0QAM0wOMBvgAtdbdGTwGJhgAAAABJRU5ErkJggg==", None).await?;
    tester.release_and_press().await?;

    tester.display_assertion(super::PORTAL_READY, None).await?;

    tester.nfc_assertion(model::Reply::Ok).await?;

    tester.nfc(NfcAction::RequestDescriptors).await?;
    tester
        .display_assertion(super::REQUEST_DESCRIPTOR, None)
        .await?;
    tester.release_and_press().await?;
    tester
        .nfc_assertion(model::Reply::Descriptor {
            external: "wsh(sortedmulti(1,[73c5da0a/48'/1'/0'/2']tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/0/*,[3977ad96/48'/1'/0'/2']tpubDE2WqbYnigRFTi6h4Km571hyX5umkEUvgLUa8kuB7tWXeBD6ffvbXqM2adiWoX9cpwQC9EQakVhy82yeCvwy1RHJVzFaC1ffhNVmEphWuEk/0/*))#4m4ang0j".into(),
            internal: Some("wsh(sortedmulti(1,[73c5da0a/48'/1'/0'/2']tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/1/*,[3977ad96/48'/1'/0'/2']tpubDE2WqbYnigRFTi6h4Km571hyX5umkEUvgLUa8kuB7tWXeBD6ffvbXqM2adiWoX9cpwQC9EQakVhy82yeCvwy1RHJVzFaC1ffhNVmEphWuEk/1/*))#vgxeam68".into()),
        })
        .await?;

    Ok(())
}

// mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
#[functional_test_wrapper::functional_test(flash_file = "./test-vector/initialized.bin")]
async fn test_set_descriptor_sorted_multisig_missing_key(
    mut tester: Tester,
) -> Result<(), crate::Error> {
    tester.display_assertion(super::PORTAL_READY, None).await?;

    tester
        .nfc(NfcAction::SetDescriptor(
            format!(
                "wsh(sortedmulti(1,{}/1/*,{}/*))",
                EXTERNAL_BIP48_XPUB, EXTERNAL_BIP48_XPUB
            ),
            None,
        ))
        .await?;

    tester.display_assertion(super::PORTAL_READY, None).await?;

    tester
        .nfc_assertion(model::Reply::Error("Local key missing".into()))
        .await?;

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

fn get_self_extended_key() -> model::ExtendedKey {
    model::ExtendedKey {
            origin: Some((0x73c5da0a.into(), bip32::DerivationPath::from_str("m/48'/1'/0'/2'").unwrap().into())),
            key: bip32::Xpub::from_str("tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ").unwrap().into(),
            path: bip32::DerivationPath::from_str("m").unwrap().into(),
        }
}

// mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
#[functional_test_wrapper::functional_test(flash_file = "./test-vector/initialized.bin")]
async fn test_set_descriptor_non_sorted_multisig(mut tester: Tester) -> Result<(), crate::Error> {
    use model::*;

    tester.display_assertion(super::PORTAL_READY, None).await?;

    let msg = Request::SetDescriptor {
        variant: SetDescriptorVariant::MultiSig {
            threshold: 1,
            keys: vec![get_self_extended_key()],
            is_sorted: false,
        },
        script_type: ScriptType::NativeSegwit,
        bsms: None,
    };
    let msg = model::minicbor::to_vec(&msg).unwrap();

    tester.nfc(NfcAction::Raw(msg)).await?;

    tester
        .nfc_assertion_raw(
            model::Reply::Error("Unsorted multisig descriptors are not supported yet".into()),
            true,
        )
        .await?;

    tester.display_assertion(super::PORTAL_READY, None).await?;

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
#[functional_test_wrapper::functional_test(flash_file = "./test-vector/initialized.bin")]
async fn test_set_descriptor_multisig_invalid_threshold(
    mut tester: Tester,
) -> Result<(), crate::Error> {
    use model::*;

    tester.display_assertion(super::PORTAL_READY, None).await?;

    let msg = Request::SetDescriptor {
        variant: SetDescriptorVariant::MultiSig {
            threshold: 2,
            keys: vec![get_self_extended_key()],
            is_sorted: true,
        },
        script_type: ScriptType::NativeSegwit,
        bsms: None,
    };
    let msg = model::minicbor::to_vec(&msg).unwrap();

    tester.nfc(NfcAction::Raw(msg)).await?;

    tester
        .nfc_assertion_raw(
            model::Reply::Error("Invalid threshold for multisig".into()),
            true,
        )
        .await?;

    tester.display_assertion(super::PORTAL_READY, None).await?;

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
#[functional_test_wrapper::functional_test(flash_file = "./test-vector/initialized.bin")]
async fn test_set_descriptor_pkh(mut tester: Tester) -> Result<(), crate::Error> {
    tester.display_assertion(super::PORTAL_READY, None).await?;

    tester
        .nfc(NfcAction::SetDescriptor(
            format!("pkh({}/*)", DERIVED_BIP48_XPUB),
            None,
        ))
        .await?;

    let sequence = [
        "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",
    ];

    for assertion in sequence {
        tester.display_assertion(assertion, None).await?;
        tester.release_and_press().await?;
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
            external: "pkh([73c5da0a/48'/1'/0'/2']tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/0/*)#j4l5ela5".into(),
            internal: Some("pkh([73c5da0a/48'/1'/0'/2']tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/1/*)#rp64y2dv".into()),
        })
        .await?;

    Ok(())
}

// mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
#[functional_test_wrapper::functional_test(flash_file = "./test-vector/initialized.bin")]
async fn test_set_descriptor_pkh_external_key(mut tester: Tester) -> Result<(), crate::Error> {
    tester.display_assertion(super::PORTAL_READY, None).await?;

    tester
        .nfc(NfcAction::SetDescriptor(
            format!("pkh({}/*)", EXTERNAL_BIP48_XPUB),
            None,
        ))
        .await?;

    tester.display_assertion(super::PORTAL_READY, None).await?;

    tester
        .nfc_assertion(model::Reply::Error("Local key missing".into()))
        .await?;

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

async fn common_set_descriptor_sequence(mut tester: Tester) -> Result<(), crate::Error> {
    tester
        .nfc(NfcAction::SetDescriptor(
            format!("pkh({}/*)", DERIVED_BIP48_XPUB),
            None,
        ))
        .await?;

    let sequence = [
        "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",
    ];

    for assertion in sequence {
        tester.display_assertion(assertion, None).await?;
        tester.release_and_press().await?;
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
            external: "pkh([73c5da0a/48'/1'/0'/2']tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/0/*)#j4l5ela5".into(),
            internal: Some("pkh([73c5da0a/48'/1'/0'/2']tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/1/*)#rp64y2dv".into()),
        })
        .await?;

    tester.reset().await?;

    tester.display_assertion(super::LOCKED, None).await?;

    tester.nfc(NfcAction::Unlock("paircode".into())).await?;
    tester.nfc_assertion(model::Reply::Ok).await?;

    tester.display_assertion(super::PORTAL_READY, None).await?;

    tester.nfc(NfcAction::RequestDescriptors).await?;
    tester
        .display_assertion(super::REQUEST_DESCRIPTOR, None)
        .await?;
    tester.release_and_press().await?;
    tester
        .nfc_assertion(model::Reply::Descriptor {
            external: "pkh([73c5da0a/48'/1'/0'/2']tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/0/*)#j4l5ela5".into(),
            internal: Some("pkh([73c5da0a/48'/1'/0'/2']tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJY8iCNiwTL3RWZEheQ/1/*)#rp64y2dv".into()),
        })
        .await?;

    Ok(())
}

// mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
#[functional_test_wrapper::functional_test(flash_file = "./test-vector/initialized-locked.bin")]
async fn test_set_descriptor_pkh_locked(mut tester: Tester) -> Result<(), crate::Error> {
    tester.display_assertion(super::LOCKED, None).await?;

    tester.nfc(NfcAction::Unlock("paircode".into())).await?;
    tester.nfc_assertion(model::Reply::Ok).await?;

    tester.display_assertion(super::PORTAL_READY, None).await?;

    common_set_descriptor_sequence(tester).await?;

    Ok(())
}

// mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
#[functional_test_wrapper::functional_test(flash_file = "./test-vector/initialized-locked.bin")]
async fn test_set_descriptor_fastboot_locked(mut tester: Tester) -> Result<(), crate::Error> {
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

    tester.nfc(NfcAction::Unlock("paircode".into())).await?;
    tester.nfc_assertion(model::Reply::Ok).await?;

    tester.display_assertion(super::PORTAL_READY, None).await?;

    tester.fast_boot_reset().await?;

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

    common_set_descriptor_sequence(tester).await?;

    Ok(())
}
