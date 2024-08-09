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

// mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
#[functional_test_wrapper::functional_test(flash_file = "./test-vector/initialized-locked.bin")]
async fn test_resume_locked(mut tester: Tester) -> Result<(), crate::Error> {
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

    Ok(())
}

// mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
#[functional_test_wrapper::functional_test(flash_file = "./test-vector/initialized-locked.bin")]
async fn test_resume_locked_sign_psbt(mut tester: Tester) -> Result<(), crate::Error> {
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

    tester.nfc(NfcAction::SignPsbt("cHNidP8BAFICAAAAAaBa/zzN4DufvU55XxA5Atv6Ce8IBjwQDorNb9ozNj0jAAAAAAD9////AfETAAAAAAAAFgAUow0Bk6zYJpM8neIOWSVDUI/SMw/09SoAAAEBHxAnAAAAAAAAFgAUjZMlxw1pfsKhfCwghXBAZbPAh6ABAN4CAAAAAAEB5wbexMJPm5cAOIzEZEfaBja+X6j4PCEZMdH1FqlJET8AAAAAAP3///8CECcAAAAAAAAWABSNkyXHDWl+wqF8LCCFcEBls8CHoAAyAAAAAAAAFgAUDE+Hi6xSRoQyv20NbKaqOwhiuGECRzBEAiBsNI/BcueDMnAh1tFofo3HQlABy65FIIoTOqf2d0cMygIgIvZ4UESL+JcmUUOMtACOY578cYERCc1rsz/vHY+g4z8BIQOL3i/ypht9oqUxUQ6pDwd62GxnTuslqeZGeNFnMNxo6fT1KgAiBgMZy1Vcgedg0NSvlpCWyLHYOiAh9SIP2ne8XKMYLzv1wxhzxdoKVAAAgAEAAIAAAACAAAAAACoAAAAAAA==".into())).await?;
    tester.nfc_assertion(model::Reply::Ok).await?;

    // LOADING
    tester.display_assertion(super::LOADING, None).await?;
    // Output
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAACOUlEQVR4nO2Z0baEIAhF4f8/mnsnFTiIWVNNL7bW5GiKW0Q0Ynr5WgAVQMofMSDxbPIc7QhACAH4xxoQeg2gDb2UfHKlcKu7FW75kpa5YW2XlLd8a1PlaT/s5pjJpIAslR4BLMXnpKPR51sHUV4+BQEgExg7c1WcBgBUOAH/HoBspkKVgYZuAuiEW7H732tqBIYAYEnRBg4IJG+0Zk+xPsgjv+4dA1ils2pQebR2v2ZdL7E+pxrYu044AZiyY/LuBTBN3QmwtuNfAgiXH2kSt6VjlsBwSx/PAGxln9fRv9NjdzuhAdENqbKQ+gWuAmeLYlvsrWq9NQHqZKcasKSJKTLnq7zWF7axNEGi/moXwAbaNDBun0y1AoAGSCdDJhrY+iK322m3qpBwavOzZr6QsSsbkE7G0WUo/L2xjzwpVl6OaAEsgAWwADjuxkk+T13MQAbleqKJR333GM/zkuUHaRdL6Mr9EcG/7EAlxj0jhkgmEDpEDvV3AaCfKwDaXhCg12wHkNnAFwDpyCS+q0kCegeA2+vzN+mnNfAkgHRGdTdAZoRmwWbW02XoBCfl55ahc0Sy54DcukcHE8ujI3KRt9wRrb1gASyAlwBkAXR5trgtHrE0WGLxdx8bJ4zPOsdvwWr1hPsA7QZfK+pWX2MwyCuxbamiImrQhKVXeAdAjhg/l5CKs1FEgEZBGmDSFu2B0GUNCE8BhAGgquSQBq4BaNtrAOQiQ2iE2KN9/UmN0MX4QOjyA2svgOsP93mLVbWaUNIAAAAASUVORK5CYII=", None).await?;
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAACSElEQVR4nO2Y0XLEIAhF4f8/mraJwAUxms3ubB/sdONoEI6oaGD68t8GSACS2mQVUpqYNHlZHRwnNdwedf3CPpss/iZ93gYQjLtyWgY4BqB9zsrhHlB8yGp91N4BSK2nmwIh7xx0YAcw7OXZbwQQZgPlfNV0Hkv2kbwCiMJNjLyMAGFqpASIQygNXgDMPOC7ZQRQKMgG0e0zANiVLLUtruxS71ozbJYRJs8vzLONJHpiCKBzjZPZPJdXJ2OgsnqhMLyPu+ZuKF4OTBP5lwHWQ/NE3tv3afjPAITPH1mxfq4mNfAoX88APFzc95Hwbyd/3PCAxRplIT0l/zQdCme78Ag3KtoeqsAC/NQDXqiaU+c8CjR5YR+LKhI/b68AfKDqgXH/YqoNIHiAbDJk4oHDFmGoZXdb+4fTDE+IEOM4mvIB2WSsbkPh1xd7vmHUOncg2gAbYANsAM6ncVGvS3EFMmi3Gw28yB+oIRnBUtUHZTqVina8IuCXXhBK34pFbmD2XaiXtq59CBDsPAGw/hIBes92ANUaeAGgHFlyMX6EvBcAzvretTkP8AkPfBJAukX1boBqEfoK9mU93YaguMwB3NmGEIjkKgB1uQGMNCFnkAKRgw4C0T4LNsAG+BKAbICu7rnYdMWyZAmkUiGXTjGRDIH/qJ4PC42XAPpQHidrdNaLJYs0O9KEvYcrvQYgIA4A7ZCCeF4AKAVZgsl66Auhxx4QngIIB4DmkiUPPAOwvs8ACDJDcRFGi2Q3wHIRQo4vKN1xYJ8F4e8Hs7F9VYaGGLkAAAAASUVORK5CYII=", None).await?;
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAACOUlEQVR4nO2Z0baEIAhF4f8/mnsnFTiIWVNNL7bW5GiKW0Q0Ynr5WgAVQMofMSDxbPIc7QhACAH4xxoQeg2gDb2UfHKlcKu7FW75kpa5YW2XlLd8a1PlaT/s5pjJpIAslR4BLMXnpKPR51sHUV4+BQEgExg7c1WcBgBUOAH/HoBspkKVgYZuAuiEW7H732tqBIYAYEnRBg4IJG+0Zk+xPsgjv+4dA1ils2pQebR2v2ZdL7E+pxrYu044AZiyY/LuBTBN3QmwtuNfAgiXH2kSt6VjlsBwSx/PAGxln9fRv9NjdzuhAdENqbKQ+gWuAmeLYlvsrWq9NQHqZKcasKSJKTLnq7zWF7axNEGi/moXwAbaNDBun0y1AoAGSCdDJhrY+iK322m3qpBwavOzZr6QsSsbkE7G0WUo/L2xjzwpVl6OaAEsgAWwADjuxkk+T13MQAbleqKJR333GM/zkuUHaRdL6Mr9EcG/7EAlxj0jhkgmEDpEDvV3AaCfKwDaXhCg12wHkNnAFwDpyCS+q0kCegeA2+vzN+mnNfAkgHRGdTdAZoRmwWbW02XoBCfl55ahc0Sy54DcukcHE8ujI3KRt9wRrb1gASyAlwBkAXR5trgtHrE0WGLxdx8bJ4zPOsdvwWr1hPsA7QZfK+pWX2MwyCuxbamiImrQhKVXeAdAjhg/l5CKs1FEgEZBGmDSFu2B0GUNCE8BhAGgquSQBq4BaNtrAOQiQ2iE2KN9/UmN0MX4QOjyA2svgOsP93mLVbWaUNIAAAAASUVORK5CYII=", None).await?;
    tester.tsc(true).await?;

    tester.wait_ticks(1).await?;
    tester.fast_boot_reset().await?;
    tester.tsc(true).await?;

    // Fee
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAABlUlEQVR4nO2Y0dqDIAiG4f4vmv9ZinyiUrZ/62DsYGkSvgIixfTwLwESIAESIAGmAHIdTRgvN/RwqPcywH0tAYCwvIblJYRt/BeqbaZesjMPPLUFcKgrvdK2FZW2MLrAoFWu4NX7PLdIaAHTotPpWoh75wMATFTxj3lW8XAK4NVq2yxgky8AOIqHLQs0j1f3F8e7qBgAbsVAZsIEeAbAx6n2V1fbAgRXcYqFcFwFeAIgBFkU+qtry8Z2T8jpUEpxW9aEuJODAQonF8wHU7gAoJvnDYC2aj8+WnYAmMXALgBM3ixRXNCZGKuCzwCARUyhOMWfsQDVYw6ek/8B6IJlHYTUW2AHYBaEFsFW5pxswwFgANrZhpBgJE5AQSLisRSF0JDJeJ4FCZAACZAAzwNIAkzucCv5oJ6Gl1CGegSrIXtntZoR5KB7CqB/BEpqSz9W9LyDyKFgJRcDkMJ6AH1Vt1N9UMwCHF4OLPWuBYQXAGTP1G863wXwLliDXgtC0q9V3gVuyReCcAPg5/JAngUJkAAJ8PMAfzAVrEYGEamYAAAAAElFTkSuQmCC", None).await?;
    tester.release_and_press().await?;

    tester.wait_ticks(2).await?;
    tester.fast_boot_reset().await?;
    tester.release_and_press().await?;

    tester.wait_ticks(8).await?;

    tester
        .display_assertion(super::PORTAL_READY, Some(128))
        .await?;

    tester
        .nfc_assertion(model::Reply::SignedPsbt(
            vec![
                112, 115, 98, 116, 255, 1, 0, 51, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255,
                0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 34, 2, 3, 25, 203, 85, 92, 129, 231, 96,
                208, 212, 175, 150, 144, 150, 200, 177, 216, 58, 32, 33, 245, 34, 15, 218, 119,
                188, 92, 163, 24, 47, 59, 245, 195, 71, 48, 68, 2, 32, 30, 100, 57, 213, 243, 230,
                91, 21, 255, 193, 91, 238, 114, 20, 94, 98, 79, 94, 251, 44, 151, 93, 76, 209, 1,
                102, 49, 254, 33, 44, 40, 176, 2, 32, 71, 2, 0, 250, 190, 215, 228, 69, 5, 87, 221,
                49, 166, 221, 182, 20, 78, 200, 211, 248, 105, 17, 169, 173, 214, 100, 163, 133,
                86, 74, 144, 6, 1, 0,
            ]
            .into(),
        ))
        .await?;

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

    Ok(())
}

// mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
#[functional_test_wrapper::functional_test(flash_file = "./test-vector/initialized.bin")]
async fn test_resume_ticks_display_address(mut tester: Tester) -> Result<(), crate::Error> {
    tester.nfc(NfcAction::DisplayAddress(42)).await?;
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAABmElEQVR4nO2Xi27DIAxF7f//6LstCcY2mLBCFk1ypaYhvE6uX4Xp5U8CJEACJEACJMA/AIAah3A8Pn2XGQCWnWOAUdcOgPv1/wSg6Fys8v0Q3jqQrjmq3yngrqhbmZ+j63GA6CE9D6BN0O96GqD3mo119gIYQw98oPoqju8egDJO7tooMF0sGFsUWIn9FwG04d5RAJOrZznmWFSX8NbsBNJ1hCMA6CcLAKgRCCruWP1SL8getnZuAYDL2UMAl8z0zZlyjJhNWvK5y9TF8I36AJJH1Y20WCkVZH0IPne2ReQD7ZpOunZMYKCr3+gdTOgodwNAUghuTQC1SQT8mQJ3odoqFDryvA+wTfJTPtCrCjMKtFFgotMpj3FKhZiLelpkLUiA9wGQAE27xD10mNezKUppJFXpVX6+5rIq/0fzvKhsPgAoF6K62XV30jEsL/zcc4gs8dOsi44BSBEbAH3ooAigUFDJoXVG6QAtKwC+BTiHaKJpBdYAZO4aQP3D453Q7khyPu06YTk5wi2aeSBrQQIkQAIkgPl8AThMhEZLtQvtAAAAAElFTkSuQmCC", None).await?;

    tester.tsc(true).await?;

    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAABtklEQVR4nO2YUbLCMAhFYf+L5jlNAhdC29h8+BxRJ9WWwoEQgmX68KsACqAACqAAFgCE8Sh8K26Ccm+AF+x3m+8ByEv1wcCbAF3JS98YX29S73Bs8k1rwN4GcAiqH6PtI9A+LQ67AIeUmVOj3dM8AhqH/SRMIhC8Dr8hLAv2n+XAcPUIgI4JwIKFKkQF8H8AXMmQflHc8nYCjHKhcrAedR2EXcHWBxjgqQQZQFPG03dKqh3IiZaq6KCe59TByU40KCehSwD67wmgnwl6ROOuMiBMidd6n9bk4V4CMIZTAMHqTmyz4DzupV4t86iKaNsdMwA/BUHAQmhmKMuHkCuTh0jK3kt6B+AqBy4BcJIS/QsA8xTsAEwr6ywH/FxxDiAol+eAKxmcwLplSP5uQuOoRSxJMfuzVUAwh64g2bLnrAfi8/aIV9qszb3gysBKi1G7YQEUQAF8G4AUwMUV1l3Xtjx8LMGi97tOp214vimUZwBjGDxGpg8qPK+YVpO7MXORnjlA386hH54A8N/7Y4CFCAjTeQQ+DrA9BdgTjqd+YQosCbUvTJPwEcDP1IHaCwqgAArg5wH+AME8jEZgacj+AAAAAElFTkSuQmCC", None).await?;
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAABj0lEQVR4nO2YixaDIAiG5f0fmnXyAj9iudxOnRO76JYKn4hCUbr5FQABEAABEAATAEy6ZjrtLh35XAFN6C86vwPgTfTOQIsARcgmr5bbO7XZ6TL3z1IN9jIAIDT52tpogfzJdlgF2HuJuqa0zNS3QLPDuhM6FjCzNv+VWSb0X/OBOtXdAK10ACY0xEEUAA8F4F+BDfYBi/L/AnA7qoby/w/gCesBeD8+a5TJx305Y5P8zl1SiQiq3RnPZpypm24CU4EASo4ApZ1lcD8+kX8d2wHAEpJ7HeviTX67eFs/TtbhDOBAgV8zaQBlId0+BFDr38MuAGi5QwBcN/niWqIP6DXmmgYkBDAywKLdLpAUS68xeHm3CwyF7KDqA9SCt7YW7oLZzY/W+8nh8SSAiIYBEAABcBMAB8BBiwQ4SQD1YwliicA6Q8qBzyZ2lwBqUXmErD2oQF4WqdLvRM2Be/oAJcyzztoMgL57vwwwYQGmNLbA7QDLSwDpFVsnRI2SL7pOeAngNedAxIIACIAAeD3ABwVUmkazYKuPAAAAAElFTkSuQmCC", None).await?;
    tester.wait_ticks(8).await?;
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAABlUlEQVR4nO2Yja6DIAyF6fs/dK+RAudgVYTcuGzdFg1/7cehUpyklz8BEAABEAABMACggneV2+6to947kAH/5vMZgG6mdwZZBDAjm71y3b6pzg6vuX+22mEvAxBCtY9qswL5l3VYBdh7NXfVqc3UV6DqsB6EjgLdrLsyyDLgfy4GylR3AerVARjwEBtRAHwqgI7B6foE5NywjuxSXwNQJFeotG0/31PbealeCqw113rbp0QTtPfj0RcbLPkUlChls9EcCY9PvXflCeF4VICc0CrkijNH1Hh2L8oe6imJCQI4XtMVgO/g4m6nCgiiupbCiriytOWieJ0GcCWtS2IDoYzxohx81p9jAO1ogqD2nwJJx6jnMi5ZW2OK8sNT0FGUScnz5//B/uB25Up5vgX/K0BkwwAIgAB4AUAD4KKlJS44MEIupEQJJ5+c0vsD2xRAuWBWLsnW/qhgXm1WW78bNxfh6QPYwUnxNNYB4Nv7NMCAAirpXIHXAZaXgN4TtA9C9tjOgW4QTgH8zD4QuSAAAiAAfh7gD9bMkkYJY+Z8AAAAAElFTkSuQmCC", None).await?;

    tester.fast_boot_reset().await?;
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAABlUlEQVR4nO2Yja6DIAyF6fs/dK+RAudgVYTcuGzdFg1/7cehUpyklz8BEAABEAABMACggneV2+6to947kAH/5vMZgG6mdwZZBDAjm71y3b6pzg6vuX+22mEvAxBCtY9qswL5l3VYBdh7NXfVqc3UV6DqsB6EjgLdrLsyyDLgfy4GylR3AerVARjwEBtRAHwqgI7B6foE5NywjuxSXwNQJFeotG0/31PbealeCqw113rbp0QTtPfj0RcbLPkUlChls9EcCY9PvXflCeF4VICc0CrkijNH1Hh2L8oe6imJCQI4XtMVgO/g4m6nCgiiupbCiriytOWieJ0GcCWtS2IDoYzxohx81p9jAO1ogqD2nwJJx6jnMi5ZW2OK8sNT0FGUScnz5//B/uB25Up5vgX/K0BkwwAIgAB4AUAD4KKlJS44MEIupEQJJ5+c0vsD2xRAuWBWLsnW/qhgXm1WW78bNxfh6QPYwUnxNNYB4Nv7NMCAAirpXIHXAZaXgN4TtA9C9tjOgW4QTgH8zD4QuSAAAiAAfh7gD9bMkkYJY+Z8AAAAAElFTkSuQmCC", None).await?;

    tester.release_and_press().await?;
    tester.display_assertion(&super::PORTAL_READY, None).await?;

    Ok(())
}
