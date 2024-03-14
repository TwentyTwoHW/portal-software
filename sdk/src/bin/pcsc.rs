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

use nfcsdk::*;

use pcsc::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let ctx = match Context::establish(Scope::User) {
        Ok(ctx) => ctx,
        Err(err) => {
            return Err(format!("Failed to establish context: {}", err).into());
            // std::process::exit(1);
        }
    };

    // List available readers.
    let mut readers_buf = [0; 2048];
    let mut readers = match ctx.list_readers(&mut readers_buf) {
        Ok(readers) => readers,
        Err(err) => {
            return Err(format!("Failed to list readers: {}", err).into());
        }
    };

    // Use the first reader.
    let reader = match readers.next() {
        Some(reader) => reader,
        None => {
            return Err("No readers found".into());
        }
    };
    log::info!("Using reader: {:?}", reader);

    log::info!("Looking for targets...");

    let sdk = PortalSdk::new(true);

    let sdk_cloned = Arc::clone(&sdk);
    tokio::task::spawn(async move {
        loop {
            let _ = dbg!(sdk_cloned.get_status().await);
            let signed = sdk_cloned.sign_psbt("cHNidP8BAFIBAAAAAXbN96PvQ+ZKYV1cNaA3PTHmC5zWxCRAT1fW3azUJFWNAAAAAAD+////AaImAAAAAAAAFgAUnzVKEjdFtB9zsPlcaCEkNeD3fc7XZQIAAAEA3gIAAAAAAQGYEApmWClxrcZ1EfyjwlkNFrOkT8C/JXmVWapWmfLHEgAAAAAA/v///wIQJwAAAAAAABYAFJ81ShI3RbQfc7D5XGghJDXg933O/2EBEAAAAAAWABQupnNAECI8+4OvBCWLSvmtrIpSnAJHMEQCIAkWSIX+oJaN0REAHYPLnsL/3+ZIiknDckFBy0SPk0eRAiAf2z4GKnUPl6Epzu/L4Pf0sMnyP8JkrYhVDe7p1bEcLAEhA9rahMDNzfz0/e8z6E5me26cOpqBkJdi6/zJ+9YYIADT12UCAAEBHxAnAAAAAAAAFgAUnzVKEjdFtB9zsPlcaCEkNeD3fc4iBgJAd1xnM2tcqPZ6y3uXqhzmedJIlmbszYBssTh9KchsqhgLtbvoVAAAgAEAAIAAAACAAAAAACoAAAAAIgICQHdcZzNrXKj2est7l6oc5nnSSJZm7M2AbLE4fSnIbKoYC7W76FQAAIABAACAAAAAgAAAAAAqAAAAAA==".to_string()).await;
            dbg!(&signed);
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
        let mut rapdu_buf = [0; 1024];

        // Connect to the card.
        let card = match ctx.connect(reader, ShareMode::Shared, Protocols::ANY) {
            Ok(card) => card,
            Err(Error::NoSmartcard) => {
                tokio::time::sleep(Duration::from_millis(25)).await;
                continue;
            }
            Err(err) => {
                log::error!("Failed to connect to card: {}", err);
                std::process::exit(1);
            }
        };

        card.transmit(&[0xFF, 0x68, 0x0E, 0x06, 0x01, 0x00], &mut rapdu_buf)?;
        // eprintln!("{:02X?}", rapdu_buf);
        // log::info!("Found ISO/IEC 14443-A target: {:?}", uid,);

        // dbg!(&uid);

        fn wrap_data(input: &[u8]) -> Vec<u8> {
            let mut data = vec![
                0xFFu8,
                0x68,
                0x0E,
                0x03,
                (10 + input.len()) as u8,
                0b0000_1111,
                0x00,
            ];
            data.extend(1000000u32.to_be_bytes());
            data.extend(0u32.to_be_bytes());
            data.extend(input);
            data.push(0x00);

            data
        }

        while let Ok(resp) = sdk.poll().await {
            match resp {
                NfcOut::Send { data } => {
                    log::trace!("> {:02X?}", data);
                    match card.transmit(&wrap_data(&data), &mut rapdu_buf) {
                        Ok(_) => {
                            sdk.ack_send().await.unwrap();
                        }
                        Err(e) => {
                            log::warn!("{:?}", e);

                            tokio::time::sleep(Duration::from_millis(25)).await;
                            continue 'outer;
                        }
                    }
                }
                NfcOut::Transceive { data } => {
                    log::trace!("> {:02X?}", data);
                    let in_data = match card.transmit(&wrap_data(&data), &mut rapdu_buf) {
                        Ok(v) => {
                            sdk.ack_send().await.unwrap();
                            log::trace!("< {:02X?}", v);
                            v
                        }
                        Err(e) => {
                            log::warn!("{:?}", e);

                            tokio::time::sleep(Duration::from_millis(25)).await;
                            continue 'outer;
                        }
                    };
                    let in_data = &in_data[2..];
                    let in_data = &in_data[..(in_data.len() - 2)];
                    sdk.incoming_data(in_data.to_vec()).await.unwrap();
                }
            }

            // tokio::time::sleep(Duration::from_millis(25));
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
