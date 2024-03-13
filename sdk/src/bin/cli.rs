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

use std::sync::Arc;
use std::time::Duration;

use portal::*;

#[tokio::main]
async fn main() -> nfc1::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    log::info!("libnfc v{}", nfc1::version());

    let mut context = nfc1::Context::new()?;
    let mut device = context.open()?;

    device.initiator_init()?;

    log::info!(
        "NFC device {:?} opened through connection {:?}",
        device.name(),
        device.connstring()
    );

    log::info!("Looking for targets...");

    let modulation = nfc1::Modulation {
        modulation_type: nfc1::ModulationType::Iso14443a,
        baud_rate: nfc1::BaudRate::Baud106,
    };
    let sdk = PortalSdk::new(false);

    // let fw_signed = std::fs::read("/dev/shm/fw-large-signed.bin").unwrap();

    let sdk_cloned = Arc::clone(&sdk);
    tokio::task::spawn(async move {
        loop {
            let _ = dbg!(sdk_cloned.get_status().await);
            // let _ = dbg!(sdk_cloned.update_firmware(fw_signed.clone()).await);
            let signed = sdk_cloned.sign_psbt("cHNidP8BAFIBAAAAAXbN96PvQ+ZKYV1cNaA3PTHmC5zWxCRAT1fW3azUJFWNAAAAAAD+////AaImAAAAAAAAFgAUnzVKEjdFtB9zsPlcaCEkNeD3fc7XZQIAAAEA3gIAAAAAAQGYEApmWClxrcZ1EfyjwlkNFrOkT8C/JXmVWapWmfLHEgAAAAAA/v///wIQJwAAAAAAABYAFJ81ShI3RbQfc7D5XGghJDXg933O/2EBEAAAAAAWABQupnNAECI8+4OvBCWLSvmtrIpSnAJHMEQCIAkWSIX+oJaN0REAHYPLnsL/3+ZIiknDckFBy0SPk0eRAiAf2z4GKnUPl6Epzu/L4Pf0sMnyP8JkrYhVDe7p1bEcLAEhA9rahMDNzfz0/e8z6E5me26cOpqBkJdi6/zJ+9YYIADT12UCAAEBHxAnAAAAAAAAFgAUnzVKEjdFtB9zsPlcaCEkNeD3fc4iBgJAd1xnM2tcqPZ6y3uXqhzmedJIlmbszYBssTh9KchsqhgLtbvoVAAAgAEAAIAAAACAAAAAACoAAAAAIgICQHdcZzNrXKj2est7l6oc5nnSSJZm7M2AbLE4fSnIbKoYC7W76FQAAIABAACAAAAAgAAAAAAqAAAAAA==".to_string()).await;
            dbg!(&signed);
            // let _ = dbg!(sdk_cloned.generate_mnemonic(GenerateMnemonicWords::Words12, model::bitcoin::Network::Bitcoin, None).await);
        }
    });
    // std::thread::spawn(move || {
    //     let _ = dbg!(sdk_cloned.get_status());
    //     std::thread::sleep(Duration::from_millis(250));
    //     // let _ = dbg!(sdk_cloned.generate_mnemonic(GenerateMnemonicWords::Words12));
    //     // let addr = sdk_cloned.display_address(0);
    //     // dbg!(&addr);
    //     // let desc = sdk_cloned.public_descriptor();
    //     // dbg!(&desc);
    //     // let signed = sdk_cloned.sign_psbt("cHNidP8BAFIBAAAAAXbN96PvQ+ZKYV1cNaA3PTHmC5zWxCRAT1fW3azUJFWNAAAAAAD+////AaImAAAAAAAAFgAUnzVKEjdFtB9zsPlcaCEkNeD3fc7XZQIAAAEA3gIAAAAAAQGYEApmWClxrcZ1EfyjwlkNFrOkT8C/JXmVWapWmfLHEgAAAAAA/v///wIQJwAAAAAAABYAFJ81ShI3RbQfc7D5XGghJDXg933O/2EBEAAAAAAWABQupnNAECI8+4OvBCWLSvmtrIpSnAJHMEQCIAkWSIX+oJaN0REAHYPLnsL/3+ZIiknDckFBy0SPk0eRAiAf2z4GKnUPl6Epzu/L4Pf0sMnyP8JkrYhVDe7p1bEcLAEhA9rahMDNzfz0/e8z6E5me26cOpqBkJdi6/zJ+9YYIADT12UCAAEBHxAnAAAAAAAAFgAUnzVKEjdFtB9zsPlcaCEkNeD3fc4iBgJAd1xnM2tcqPZ6y3uXqhzmedJIlmbszYBssTh9KchsqhgLtbvoVAAAgAEAAIAAAACAAAAAACoAAAAAIgICQHdcZzNrXKj2est7l6oc5nnSSJZm7M2AbLE4fSnIbKoYC7W76FQAAIABAACAAAAAgAAAAAAqAAAAAA==");
    // });

    'outer: loop {
        let devices = device.initiator_list_passive_targets(&modulation, 1)?;
        let target = match devices.get(0) {
            Some(t) => t,
            None => continue,
        };

        let uid = if let nfc1::target_info::TargetInfo::Iso14443a(target_info) = target.target_info
        {
            target_info.uid[..target_info.uid_len]
                .iter()
                .cloned()
                .collect::<Vec<_>>()
        } else {
            return Err(nfc1::Error::DeviceNotSupported);
        };
        if uid.is_empty() {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        }

        log::info!("Found ISO/IEC 14443-A target: {:?}", uid,);

        sdk.new_tag().await.unwrap();

        // dbg!(&uid);

        while let Ok(NfcOut { msg_index, data }) = sdk.poll().await {
            log::trace!("> {:02X?}", data);
            let in_data = match device.initiator_transceive_bytes(
                &data,
                MAX_READ_FRAME,
                nfc1::Timeout::Default,
            ) {
                Ok(v) => {
                    log::trace!("< {:02X?}", v);
                    v
                }
                Err(e) => {
                    log::warn!("{:?}", e);

                    tokio::time::sleep(Duration::from_millis(25)).await;
                    continue 'outer;
                }
            };
            sdk.incoming_data(msg_index, in_data).await.unwrap();
        }

        // tokio::time::sleep(Duration::from_millis(25));

        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
