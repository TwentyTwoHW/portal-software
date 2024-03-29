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

use std::fs::File;
use std::io::{Cursor, Read, Seek, Write};
use std::process::Stdio;

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use futures::TryFutureExt;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command as ProcessCommand};
use tokio::sync::mpsc::{self};

use portal::PortalSdk;

use embedded_graphics::geometry::Size;
use embedded_graphics::pixelcolor::BinaryColor;
use embedded_graphics_simulator::SimulatorDisplay;

use ::model::emulator::{CardMessage, EmulatorMessage};

pub mod model;
pub mod report;

use crate::link::EmulatorStreams;

pub fn get_qemu_instance(
    firmware: &Path,
    join_logs: bool,
    listen_gdb: Option<u16>,
    wait_gdb: bool,
) -> Result<(ChildStdout, ChildStdin, Option<ChildStderr>, Child), crate::Error> {
    log::trace!("Spawning qemu...");

    let stderr = if join_logs {
        Stdio::inherit()
    } else {
        Stdio::piped()
    };

    let firmware = firmware.to_string_lossy();
    let mut args = vec![
        "-cpu",
        "cortex-m4",
        "-machine",
        "netduinoplus2",
        "-chardev",
        "file,id=log,path=/dev/stderr",
        "-chardev",
        "stdio,id=serial1",
        "-serial",
        "chardev:serial1",
        "-kernel",
        &firmware,
        "-semihosting-config",
        "enable=on,target=native,chardev=log",
        "-display",
        "none",
    ]
    .into_iter()
    .map(ToString::to_string)
    .collect::<Vec<_>>();

    if let Some(port) = listen_gdb {
        args.push("-gdb".to_string());
        args.push(format!("tcp::{}", port));

        if wait_gdb {
            args.push("-S".to_string());

            log::info!("Waiting for GDB to attach...");
        }
    }

    let mut child = ProcessCommand::new("qemu-system-arm")
        .kill_on_drop(true)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(stderr)
        .stdin(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().unwrap();
    let stdin = child.stdin.take().unwrap();
    let stderr = child.stderr.take();
    Ok((stdout, stdin, stderr, child))
}

async fn decode_card_message<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
) -> Result<CardMessage, crate::Error> {
    let ty = reader.read_u8().await?;
    let has_len = match ty {
        0x00 | 0x01 | 0x03 => true,
        0x02 | 0x04 | 0x05 | 0x06 => false,
        v => return Err(format!("Invalid CardMessage type {}", v).into()),
    };

    let data = if has_len {
        let len = reader.read_u16().await?;
        let mut buf = vec![0; len as usize];
        reader.read_exact(&mut buf).await?;

        buf
    } else {
        vec![]
    };

    match ty {
        0x00 => Ok(CardMessage::Display(
            data.chunks_exact(2)
                .map(|arr| u16::from_be_bytes(arr.try_into().unwrap()))
                .collect(),
        )),
        0x01 => Ok(CardMessage::Nfc(data)),
        0x02 => Ok(CardMessage::Tick),
        0x03 => Ok(CardMessage::WriteFlash(data)),
        0x04 => Ok(CardMessage::ReadFlash),
        0x05 => Ok(CardMessage::FinishBoot),
        0x06 => Ok(CardMessage::FlushDisplay),

        _ => unreachable!(),
    }
}

async fn spawn_support_tasks(
    reader: Pin<Box<dyn AsyncRead + Send>>,
    log: Option<ChildStderr>,
) -> (
    mpsc::UnboundedReceiver<CardMessage>,
    mpsc::UnboundedReceiver<String>,
) {
    let mut reader = BufReader::new(reader);

    let (sender, receiver) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let sender = sender.clone();
            match decode_card_message(&mut reader)
                .and_then(|msg| async move { Ok(sender.send(msg)?) })
                .await
            {
                Ok(_) => continue,
                Err(e) => {
                    log::error!("{:?}", e);
                    break;
                }
            }
        }
    });

    let (log_sender, log_receiver) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        if let Some(log) = log {
            let mut bufreader = BufReader::new(log);
            let mut s = String::new();
            loop {
                s.clear();
                bufreader.read_line(&mut s).await.expect("Read log line");
                if log_sender.send(s.trim().to_string()).is_err() {
                    break;
                }
            }
        }
    });

    (receiver, log_receiver)
}

pub fn get_display() -> SimulatorDisplay<BinaryColor> {
    // Create a new simulator display with 128x64 pixels.
    SimulatorDisplay::new(Size::new(128, 64))
}

pub fn get_flash_file(path: &Path) -> Result<Box<dyn ReadWrite + Send>, crate::Error> {
    Ok(Box::new(
        File::options()
            .read(true)
            .write(true)
            .create(true)
            .open(path)?,
    ))
}

pub async fn get_emulator_instance(
    run_qemu: bool,
    emulator_socket: &Path,
    firmware: &Path,
    join_logs: bool,
    flash: Option<Box<dyn ReadWrite + Send>>,
    listen_gdb: Option<u16>,
    wait_gdb: bool,
    entropy: [u8; 32],
) -> Result<EmulatorInstance, crate::Error> {
    let flash = flash.unwrap_or_else(|| Box::new(Cursor::new(Vec::new())));

    if !run_qemu {
        let (socket, nfc) = UnixStream::connect(&emulator_socket).await?.into_split();
        let (receiver, logs) = spawn_support_tasks(Box::pin(socket), None).await;
        let (msgs, nfc_r) = crate::link::stream_incoming_messages(receiver);
        let display = get_display();

        let (card, card_r) = mpsc::unbounded_channel();
        EmulatorInstance::spawn_card_writer(card_r, Box::pin(nfc));
        let sdk = EmulatorInstance::attach_sdk(nfc_r, card.clone());

        Ok(EmulatorInstance {
            card,
            logs,
            display,
            msgs,
            flash,
            sdk,

            _qemu_handle: None,
        })
    } else {
        EmulatorInstance::spawn_qemu(firmware, join_logs, listen_gdb, wait_gdb, flash, entropy)
            .await
    }
}

pub async fn list_tests(dir: &Path) -> Result<Vec<PathBuf>, crate::Error> {
    if !dir.is_dir() {
        return Err("Invalid tests_dir".into());
    }

    let mut result = vec![];
    let mut stream = tokio::fs::read_dir(dir).await?;
    while let Some(entry) = stream.next_entry().await? {
        if !entry.file_type().await?.is_file() {
            continue;
        }

        if !entry
            .file_name()
            .into_string()
            .expect("Valid file name")
            .ends_with(".json")
        {
            continue;
        }

        result.push(entry.path());
    }

    Ok(result)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum HtmlReport {
    None,
    OnlyFailing,
    All,
}

pub trait ReadWrite: Write + Read + Seek {}
impl<T: Read + Write + Seek> ReadWrite for T {}

pub struct EmulatorInstance {
    pub card: mpsc::UnboundedSender<EmulatorMessage>,
    pub logs: mpsc::UnboundedReceiver<String>,
    pub msgs: EmulatorStreams,
    pub display: SimulatorDisplay<BinaryColor>,
    pub flash: Box<dyn ReadWrite + Send>,
    pub sdk: Arc<PortalSdk>,

    pub(super) _qemu_handle: Option<Child>,
}

impl EmulatorInstance {
    pub async fn spawn_qemu(
        firmware: &Path,
        join_logs: bool,
        listen_gdb: Option<u16>,
        wait_gdb: bool,
        flash: Box<dyn ReadWrite + Send>,
        entropy: [u8; 32],
    ) -> Result<Self, crate::Error> {
        let (reader, writer, log, _qemu_handle) =
            get_qemu_instance(firmware, join_logs, listen_gdb, wait_gdb)?;
        let (receiver, logs) = spawn_support_tasks(Box::pin(reader), log).await;
        let (mut msgs, nfc) = crate::link::stream_incoming_messages(receiver);
        let display = get_display();

        let (card, card_r) = mpsc::unbounded_channel();
        Self::spawn_card_writer(card_r, Box::pin(writer));

        // Wait for bootup before attaching SDK
        tokio::time::timeout(std::time::Duration::from_secs(2), msgs.finish_boot.recv()).await?;
        // Send new entropy
        card.send(EmulatorMessage::Entropy(entropy)).unwrap();
        let sdk = Self::attach_sdk(nfc, card.clone());

        Ok(EmulatorInstance {
            card,
            logs,
            msgs,
            display,
            flash,
            sdk,
            _qemu_handle: Some(_qemu_handle),
        })
    }

    pub fn attach_sdk(
        mut nfc_r: mpsc::UnboundedReceiver<Vec<u8>>,
        nfc_w: mpsc::UnboundedSender<EmulatorMessage>,
    ) -> Arc<PortalSdk> {
        log::trace!("Attaching SDK");

        let sdk = PortalSdk::new(true);
        let cloned_sdk = Arc::clone(&sdk);
        tokio::spawn(async move {
            loop {
                let out = cloned_sdk.poll().await.unwrap();

                log::trace!("> {:02X?}", out.data);
                nfc_w.send(EmulatorMessage::Nfc(out.data)).unwrap();

                let incoming =
                    match tokio::time::timeout(std::time::Duration::from_secs(5), nfc_r.recv())
                        .await
                    {
                        Ok(Some(v)) => v,
                        Ok(None) => {
                            log::warn!("Closed NFC receiver, exiting");
                            break;
                        }
                        Err(_) => {
                            log::debug!("NFC packet timeout, trying again");
                            continue;
                        }
                    };

                log::trace!("< {:02X?}", incoming);
                cloned_sdk
                    .incoming_data(out.msg_index, incoming)
                    .await
                    .unwrap();
            }
        });

        sdk
    }

    pub fn spawn_card_writer(
        r: mpsc::UnboundedReceiver<EmulatorMessage>,
        w: Pin<Box<dyn AsyncWrite + Send>>,
    ) {
        tokio::spawn(async move {
            async fn err_wrapper(
                mut r: mpsc::UnboundedReceiver<EmulatorMessage>,
                mut w: Pin<Box<dyn AsyncWrite + Send>>,
            ) -> Result<(), crate::Error> {
                while let Some(msg) = r.recv().await {
                    match &msg {
                        EmulatorMessage::Tsc(v) => log::trace!("> Tsc({})", v),
                        EmulatorMessage::Nfc(data) => log::trace!("> Nfc({})", data.len()),
                        EmulatorMessage::FlashContent(data) => {
                            log::trace!("> FlashContent({})", data.len())
                        }
                        EmulatorMessage::Reset => log::trace!("> Reset"),
                        EmulatorMessage::Entropy(data) => log::trace!("> Entropy({:02X?})", data),
                    }

                    let encoded = msg.encode();
                    w.write(&encoded).await?;
                    w.flush().await?;
                }

                Ok(())
            }

            if let Err(e) = err_wrapper(r, w).await {
                log::warn!("Card writer error: {:?}", e);
            }
        });
    }
}
