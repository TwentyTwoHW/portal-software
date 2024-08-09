use std::sync::Arc;

use portal::PortalSdk;

use tokio::sync::Mutex;
use tokio::{io, net::UnixStream};

use nt3h_emulator::{CommandStream, NT3H};

#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let i2c_socket = UnixStream::connect(
        std::env::args()
            .skip(1)
            .next()
            .expect("i2c socket argument"),
    )
    .await?;
    let interrupt_socket =
        UnixStream::connect(std::env::args().skip(2).next().expect("interrupt argument")).await?;

    let (nt3h, int_recv) = NT3H::new();
    let nt3h = Arc::new(Mutex::new(nt3h));

    let sdk = PortalSdk::new(true);

    let sdk_cloned = Arc::clone(&sdk);
    let nt3h_cloned = Arc::clone(&nt3h);
    tokio::task::spawn(async move {
        loop {
            match sdk_cloned.poll().await {
                Ok(msg) => {
                    // dbg!(&msg.data);
                    let reply = nt3h_cloned.lock().await.nfc_command(&msg.data).await;
                    // dbg!(&reply);
                    sdk_cloned
                        .incoming_data(msg.msg_index, reply)
                        .await
                        .unwrap();
                }
                Err(_) => continue,
            }
        }
    });

    tokio::task::spawn(async move {
        loop {
            dbg!(&sdk.get_status().await);
            dbg!(&sdk.sign_psbt("cHNidP8BAHUCAAAAASaBcTce3/KF6Tet7qSze3gADAVmy7OtZGQXE8pCFxv2AAAAAAD+////AtPf9QUAAAAAGXapFNDFmQPFusKGh2DpD9UhpGZap2UgiKwA4fUFAAAAABepFDVF5uM7gyxHBQ8k0+65PJwDlIvHh7MuEwAAAQD9pQEBAAAAAAECiaPHHqtNIOA3G7ukzGmPopXJRjr6Ljl/hTPMti+VZ+UBAAAAFxYAFL4Y0VKpsBIDna89p95PUzSe7LmF/////4b4qkOnHf8USIk6UwpyN+9rRgi7st0tAXHmOuxqSJC0AQAAABcWABT+Pp7xp0XpdNkCxDVZQ6vLNL1TU/////8CAMLrCwAAAAAZdqkUhc/xCX/Z4Ai7NK9wnGIZeziXikiIrHL++E4sAAAAF6kUM5cluiHv1irHU6m80GfWx6ajnQWHAkcwRAIgJxK+IuAnDzlPVoMR3HyppolwuAJf3TskAinwf4pfOiQCIAGLONfc0xTnNMkna9b7QPZzMlvEuqFEyADS8vAtsnZcASED0uFWdJQbrUqZY3LLh+GFbTZSYG2YVi/jnF6efkE/IQUCSDBFAiEA0SuFLYXc2WHS9fSrZgZU327tzHlMDDPOXMMJ/7X85Y0CIGczio4OFyXBl/saiK9Z9R5E5CVbIBZ8hoQDHAXR8lkqASECI7cr7vCWXRC+B3jv7NYfysb3mk6haTkzgHNEZPhPKrMAAAAAAAAA".into()).await);
            // dbg!(&sdk.generate_mnemonic(portal::GenerateMnemonicWords::Words12, model::bitcoin::Network::Signet, None).await);
            // dbg!(&sdk.get_status().await);
        }
    });

    let mut stream = CommandStream::new(i2c_socket, interrupt_socket, int_recv).await;

    loop {
        stream.update_nt3h(&nt3h).await?;
    }
}
