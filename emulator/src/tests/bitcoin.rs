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
#[functional_test_wrapper::functional_test(flash_file = "./test-vector/initialized.bin")]
async fn test_display_address(mut tester: Tester) -> Result<(), crate::Error> {
    tester.display_assertion(super::PORTAL_READY, None).await?;

    tester.nfc(NfcAction::DisplayAddress(42)).await?;
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAABmElEQVR4nO2Xi27DIAxF7f//6LstCcY2mLBCFk1ypaYhvE6uX4Xp5U8CJEACJEACJMA/AIAah3A8Pn2XGQCWnWOAUdcOgPv1/wSg6Fys8v0Q3jqQrjmq3yngrqhbmZ+j63GA6CE9D6BN0O96GqD3mo119gIYQw98oPoqju8egDJO7tooMF0sGFsUWIn9FwG04d5RAJOrZznmWFSX8NbsBNJ1hCMA6CcLAKgRCCruWP1SL8getnZuAYDL2UMAl8z0zZlyjJhNWvK5y9TF8I36AJJH1Y20WCkVZH0IPne2ReQD7ZpOunZMYKCr3+gdTOgodwNAUghuTQC1SQT8mQJ3odoqFDryvA+wTfJTPtCrCjMKtFFgotMpj3FKhZiLelpkLUiA9wGQAE27xD10mNezKUppJFXpVX6+5rIq/0fzvKhsPgAoF6K62XV30jEsL/zcc4gs8dOsi44BSBEbAH3ooAigUFDJoXVG6QAtKwC+BTiHaKJpBdYAZO4aQP3D453Q7khyPu06YTk5wi2aeSBrQQIkQAIkgPl8AThMhEZLtQvtAAAAAElFTkSuQmCC", None).await?;

    tester.tsc(true).await?;

    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAABtklEQVR4nO2YUbLCMAhFYf+L5jlNAhdC29h8+BxRJ9WWwoEQgmX68KsACqAACqAAFgCE8Sh8K26Ccm+AF+x3m+8ByEv1wcCbAF3JS98YX29S73Bs8k1rwN4GcAiqH6PtI9A+LQ67AIeUmVOj3dM8AhqH/SRMIhC8Dr8hLAv2n+XAcPUIgI4JwIKFKkQF8H8AXMmQflHc8nYCjHKhcrAedR2EXcHWBxjgqQQZQFPG03dKqh3IiZaq6KCe59TByU40KCehSwD67wmgnwl6ROOuMiBMidd6n9bk4V4CMIZTAMHqTmyz4DzupV4t86iKaNsdMwA/BUHAQmhmKMuHkCuTh0jK3kt6B+AqBy4BcJIS/QsA8xTsAEwr6ywH/FxxDiAol+eAKxmcwLplSP5uQuOoRSxJMfuzVUAwh64g2bLnrAfi8/aIV9qszb3gysBKi1G7YQEUQAF8G4AUwMUV1l3Xtjx8LMGi97tOp214vimUZwBjGDxGpg8qPK+YVpO7MXORnjlA386hH54A8N/7Y4CFCAjTeQQ+DrA9BdgTjqd+YQosCbUvTJPwEcDP1IHaCwqgAArg5wH+AME8jEZgacj+AAAAAElFTkSuQmCC", None).await?;
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAABj0lEQVR4nO2YixaDIAiG5f0fmnXyAj9iudxOnRO76JYKn4hCUbr5FQABEAABEAATAEy6ZjrtLh35XAFN6C86vwPgTfTOQIsARcgmr5bbO7XZ6TL3z1IN9jIAIDT52tpogfzJdlgF2HuJuqa0zNS3QLPDuhM6FjCzNv+VWSb0X/OBOtXdAK10ACY0xEEUAA8F4F+BDfYBi/L/AnA7qoby/w/gCesBeD8+a5TJx305Y5P8zl1SiQiq3RnPZpypm24CU4EASo4ApZ1lcD8+kX8d2wHAEpJ7HeviTX67eFs/TtbhDOBAgV8zaQBlId0+BFDr38MuAGi5QwBcN/niWqIP6DXmmgYkBDAywKLdLpAUS68xeHm3CwyF7KDqA9SCt7YW7oLZzY/W+8nh8SSAiIYBEAABcBMAB8BBiwQ4SQD1YwliicA6Q8qBzyZ2lwBqUXmErD2oQF4WqdLvRM2Be/oAJcyzztoMgL57vwwwYQGmNLbA7QDLSwDpFVsnRI2SL7pOeAngNedAxIIACIAAeD3ABwVUmkazYKuPAAAAAElFTkSuQmCC", None).await?;
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAABtklEQVR4nO2YUbLCMAhFYf+L5jlNAhdC29h8+BxRJ9WWwoEQgmX68KsACqAACqAAFgCE8Sh8K26Ccm+AF+x3m+8ByEv1wcCbAF3JS98YX29S73Bs8k1rwN4GcAiqH6PtI9A+LQ67AIeUmVOj3dM8AhqH/SRMIhC8Dr8hLAv2n+XAcPUIgI4JwIKFKkQF8H8AXMmQflHc8nYCjHKhcrAedR2EXcHWBxjgqQQZQFPG03dKqh3IiZaq6KCe59TByU40KCehSwD67wmgnwl6ROOuMiBMidd6n9bk4V4CMIZTAMHqTmyz4DzupV4t86iKaNsdMwA/BUHAQmhmKMuHkCuTh0jK3kt6B+AqBy4BcJIS/QsA8xTsAEwr6ywH/FxxDiAol+eAKxmcwLplSP5uQuOoRSxJMfuzVUAwh64g2bLnrAfi8/aIV9qszb3gysBKi1G7YQEUQAF8G4AUwMUV1l3Xtjx8LMGi97tOp214vimUZwBjGDxGpg8qPK+YVpO7MXORnjlA386hH54A8N/7Y4CFCAjTeQQ+DrA9BdgTjqd+YQosCbUvTJPwEcDP1IHaCwqgAArg5wH+AME8jEZgacj+AAAAAElFTkSuQmCC", None).await?;

    tester.release_and_press().await?;

    tester.display_assertion(super::PORTAL_READY, None).await?;

    tester
        .nfc_assertion(model::Reply::Address(
            "tb1q3kfjt3cdd9lv9gtu9ssg2uzqvkeuppaqwr9vw5".to_string(),
        ))
        .await?;

    Ok(())
}

// mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
#[functional_test_wrapper::functional_test(flash_file = "./test-vector/initialized.bin")]
async fn test_public_descriptors(mut tester: Tester) -> Result<(), crate::Error> {
    tester.display_assertion(super::PORTAL_READY, None).await?;

    tester.nfc(NfcAction::RequestDescriptors).await?;
    tester
        .display_assertion(super::REQUEST_DESCRIPTOR, None)
        .await?;

    tester.tsc(true).await?;

    tester.display_assertion(super::PORTAL_READY, None).await?;

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
async fn test_sign_psbt(mut tester: Tester) -> Result<(), crate::Error> {
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

    // Fee
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAABlUlEQVR4nO2Y0dqDIAiG4f4vmv9ZinyiUrZ/62DsYGkSvgIixfTwLwESIAESIAGmAHIdTRgvN/RwqPcywH0tAYCwvIblJYRt/BeqbaZesjMPPLUFcKgrvdK2FZW2MLrAoFWu4NX7PLdIaAHTotPpWoh75wMATFTxj3lW8XAK4NVq2yxgky8AOIqHLQs0j1f3F8e7qBgAbsVAZsIEeAbAx6n2V1fbAgRXcYqFcFwFeAIgBFkU+qtry8Z2T8jpUEpxW9aEuJODAQonF8wHU7gAoJvnDYC2aj8+WnYAmMXALgBM3ixRXNCZGKuCzwCARUyhOMWfsQDVYw6ek/8B6IJlHYTUW2AHYBaEFsFW5pxswwFgANrZhpBgJE5AQSLisRSF0JDJeJ4FCZAACZAAzwNIAkzucCv5oJ6Gl1CGegSrIXtntZoR5KB7CqB/BEpqSz9W9LyDyKFgJRcDkMJ6AH1Vt1N9UMwCHF4OLPWuBYQXAGTP1G863wXwLliDXgtC0q9V3gVuyReCcAPg5/JAngUJkAAJ8PMAfzAVrEYGEamYAAAAAElFTkSuQmCC", None).await?;
    tester.release_and_press().await?;

    tester.display_assertion(super::PORTAL_READY, None).await?;

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

    Ok(())
}

// mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
#[functional_test_wrapper::functional_test(flash_file = "./test-vector/initialized.bin")]
async fn test_sign_psbt_ignore_change(mut tester: Tester) -> Result<(), crate::Error> {
    tester.display_assertion(super::PORTAL_READY, None).await?;

    tester.nfc(NfcAction::SignPsbt("cHNidP8BAHECAAAAAQ8frez3Qcjx1k//0U5T7AMEy/98hknL9/dp7tq3vf6tAAAAAAD9////ArAEAAAAAAAAFgAUTAqK/PDkL/W4flxbyHMCr1ZGstnECQAAAAAAABYAFKMNAZOs2CaTPJ3iDlklQ1CP0jMPAvYqAAABAR8QJwAAAAAAABYAFI2TJccNaX7CoXwsIIVwQGWzwIegAQDeAgAAAAABAU0layoF6jJiaBcPSRRFe+S3sSTZrawih0zY5PrHo6m9AAAAAAD9////AhAnAAAAAAAAFgAUjZMlxw1pfsKhfCwghXBAZbPAh6AEWwAAAAAAABYAFCwZn0sUr8SJUd3Tv0pUtEv8uE58AkcwRAIgASSAF12B3dyOj2d7QoQj15bOu1e/nf30s767sKFDlp8CICPcm3MWoJuwUArlkU+9zecDHf52oBC7M/BfWzwMHdG/ASECMxfeiqZyAkgpX0xacXC+4xsvaSBisGuJ9WrTBLbzPGsC9ioAIgYDGctVXIHnYNDUr5aQlsix2DogIfUiD9p3vFyjGC879cMYc8XaClQAAIABAACAAAAAgAAAAAAqAAAAACICA9hoZkJXpF19HOHAhDMyrerBSHtDJFGPkqtVQeTNj0t4GHPF2gpUAACAAQAAgAAAAIABAAAADwAAAAAA".into())).await?;
    tester.nfc_assertion(model::Reply::Ok).await?;

    // LOADING
    tester.display_assertion(super::LOADING, None).await?;
    // Output
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAACSUlEQVR4nO1Z27KDIAxM/v+jc84guSyES9UZX+hMtVbYLEtYBJk+/hwCbxGQBkt2ofmt+Fy+4Vr2sF8k0F7uMWBX8GqEkDbmahU111x/lx9aXoNpufac4GhwJqwIQRjkvO6XihXD2a4IdDhWhUFCaQgp01BROAlgDYrgnQIzAgRKDlsyIuD9HXDy+iMCiOMSY99P+hhkxkCDnOCQhFBAGxIAVsBtDiTJauVr7mikbhS0YzsgYW6wTAhEI+qj26gY+sDWON4Y5yOc8D+PnXWFv2M0I5yVAmc2/IyA8PUlO3Xz7NbUxHBIb68IuCP8rtG/WXI4/KBA9RxS7jbfFKQCuEr+Msi1aD0ogNZdK+Anhbkw1+5Qywt7WxRI3K5mBLyhqsC4ftLVRgAUIOsMWShQYlGwUgtrgghOoLHX3OMYQ3mDrDN2h6Hw/WQfOSYWPkZ0CBwCh8AhMFvT6/XgbI/yCtSW8ycave0VOCHQrul3lla4mOHuP3tEIH8ywAUILs3ixLGzvovB0hVxSgDu3yfgrVZlfyCQ5cAdAu3acUCAqF25vUQgPpzwBwpg4TcJyM4mQ7or9iQJPaOFaH+HI9sTuDcMg4HI1ID8sbUxloURub4DIzpzwSFwCHxEQA6B7prNV9HxyDZLfN8+7oUTzs3B+H2T25xwTkAPyseZVXZWy99aYN2riEHUTROWXvCOAAXGQKBOUsHPEwLKgoiAgIG2AtxSQHhJQBgIVEm2FHhGwOo+I0BhZwiTECP6W6M0CcMeH4AeHzhzAXz+AAjVl1XQqPTVAAAAAElFTkSuQmCC", None).await?;
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAACQklEQVR4nO2Z25LDIAhA4f8/mt1VuSlEk3Sm+0CnTZoU4UgQlSJ8+VUAbwFo0kFnKkls41v72D7mmg50Npku+AGAWPE9gAbOnem9gukax/f2heXZGMvN50BPuxEAOCPo3NmtScPOMLTuABY9AuNjgOw5IP17Y2CAOJC9crzQA1YuBQjOIYA+b/NE4vbnAATeQNSzBSCQI0hiAiEHMEHm4iJTPMdAEKwiP2KnNcgBAjc4YqM4BLCJaLUuoyJNREfj+N44393HLEW+Akj1rPdrNvxnAIT9A3Ja5tujKQrdIfx5B6CZ4b6PfpMmmsMND4zcA8wu807T1BTuBkEb7Cw6DqyA2+49oCdW03Xus8SQJ9S+sCLStHUFoB1lD+Ttg0ctAM4DIA+DNh5otsCkVDErDiGTanXGcPlXQ8kEtDyBKS7wIJ4fBnuWOakyYQEUQAEUQApA0eycn2XjyYpmOV3R6FLcLM0XgHlvf7DFcm1mObdEsPsRV1NAP2eYlif7PGss3BmHAO735wDaa/bsDYAoBp4AzHvIBABg3sF9CMAuTvALHvDCnwSgk2JDWB17E4Qa0VpF2A5DCGsDz4ahSSB0mYB02Tollk0iUv8miajmggIogC8BUAEs1yh51Wc8kGKJ1u9tTRz83GwSvxa7JRNeA/CBeZRs0Ekr/ffCt+0iomIUTZBWhy8AYIgdwJikTD4PAJgCAByAKJ0d8MgDhFsAQgcwXHLkgXcA0vYdAJjKkA9Cb1H/PQqD0NT4nNLKAzUXuNcPpFufVcuBISIAAAAASUVORK5CYII=", None).await?;
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAACSUlEQVR4nO1Z27KDIAxM/v+jc84guSyES9UZX+hMtVbYLEtYBJk+/hwCbxGQBkt2ofmt+Fy+4Vr2sF8k0F7uMWBX8GqEkDbmahU111x/lx9aXoNpufac4GhwJqwIQRjkvO6XihXD2a4IdDhWhUFCaQgp01BROAlgDYrgnQIzAgRKDlsyIuD9HXDy+iMCiOMSY99P+hhkxkCDnOCQhFBAGxIAVsBtDiTJauVr7mikbhS0YzsgYW6wTAhEI+qj26gY+sDWON4Y5yOc8D+PnXWFv2M0I5yVAmc2/IyA8PUlO3Xz7NbUxHBIb68IuCP8rtG/WXI4/KBA9RxS7jbfFKQCuEr+Msi1aD0ogNZdK+Anhbkw1+5Qywt7WxRI3K5mBLyhqsC4ftLVRgAUIOsMWShQYlGwUgtrgghOoLHX3OMYQ3mDrDN2h6Hw/WQfOSYWPkZ0CBwCh8AhMFvT6/XgbI/yCtSW8ycave0VOCHQrul3lla4mOHuP3tEIH8ywAUILs3ixLGzvovB0hVxSgDu3yfgrVZlfyCQ5cAdAu3acUCAqF25vUQgPpzwBwpg4TcJyM4mQ7or9iQJPaOFaH+HI9sTuDcMg4HI1ID8sbUxloURub4DIzpzwSFwCHxEQA6B7prNV9HxyDZLfN8+7oUTzs3B+H2T25xwTkAPyseZVXZWy99aYN2riEHUTROWXvCOAAXGQKBOUsHPEwLKgoiAgIG2AtxSQHhJQBgIVEm2FHhGwOo+I0BhZwiTECP6W6M0CcMeH4AeHzhzAXz+AAjVl1XQqPTVAAAAAElFTkSuQmCC", None).await?;
    tester.tsc(true).await?;

    // Fee
    tester.display_assertion("iVBORw0KGgoAAAANSUhEUgAAAIAAAABACAAAAAD3vSCjAAABgElEQVR4nO2Y0RqDIAiF4f0fmn1LkYMpWWvrYuxiaSH8yQktpod/CZAACZAACTAEkHU0YTxc8MOh32WA614CAGF5X5a3EbbxX6i2mbylmx4YdQpgc1d6pW13VNrCmAKDVruCV8/zeEbCGTAvGk7vhdgnHwAgUMXf4sz0cAjQu9W2zYAFnwBwpIdTM9AyXtNfEt+pYgdwSQNZCRPgGYBep9oPjrUYktO59yNw2QbwAEAIqij0gyPa7q5319wjawbeBzo9Cj6IH8K5EDcDOMdLACMNnAfQ8aqFKQA1cdwMYLlc0McXAMD+ZoBhTm8FGInQhGXbnCi4pqA5/PQxhAIihwWIQVwCYowKEezcxoUo14IESIAESICHACQBBme4ra6wn4aXUG47MluKtSvkl2ewg+4hgP4ROKkt/VjheXcmm4OZXQxACtsD6Ku6reo7xyzA0dvBTH06A8ITALIx9ZvObwH6FMxB10RI+rWqT0F3ywsiPAHwd3Ug14IESIAE+HuAF4nasUbIX0GjAAAAAElFTkSuQmCC", None).await?;
    tester.release_and_press().await?;

    tester.display_assertion(super::PORTAL_READY, None).await?;

    tester
        .nfc_assertion(model::Reply::SignedPsbt(
            vec![
                112, 115, 98, 116, 255, 1, 0, 51, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 255, 255,
                0, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 34, 2, 3, 25, 203, 85, 92, 129, 231, 96,
                208, 212, 175, 150, 144, 150, 200, 177, 216, 58, 32, 33, 245, 34, 15, 218, 119,
                188, 92, 163, 24, 47, 59, 245, 195, 71, 48, 68, 2, 32, 75, 2, 71, 97, 21, 183, 106,
                66, 96, 75, 211, 61, 65, 110, 213, 142, 250, 189, 50, 148, 215, 8, 185, 135, 168,
                201, 15, 68, 99, 67, 170, 39, 2, 32, 88, 115, 248, 127, 199, 9, 80, 54, 205, 23,
                126, 76, 218, 62, 146, 34, 129, 127, 4, 191, 106, 167, 198, 238, 167, 52, 248, 83,
                5, 40, 144, 241, 1, 0,
            ]
            .into(),
        ))
        .await?;

    Ok(())
}
