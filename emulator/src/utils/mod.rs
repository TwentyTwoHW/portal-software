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

use std::process::Stdio;

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use embedded_graphics::pixelcolor::BinaryColor;
use futures::FutureExt;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::process::{Child, ChildStderr, Command as ProcessCommand};
use tokio::sync::{mpsc, Mutex};

use portal::PortalSdk;

use embedded_graphics::geometry::Size;
use embedded_graphics_simulator::SimulatorDisplay;

pub mod flash;
pub mod model;
pub mod report;

pub async fn get_qemu_instance(
    flash: &Path,
    join_logs: bool,
    listen_gdb: Option<u16>,
    wait_gdb: bool,
    entropy: u64,
) -> Result<
    (
        Option<ChildStderr>,
        Child,
        TcpStream,
        TcpStream,
        TcpStream,
        TcpStream,
        TcpStream,
    ),
    crate::Error,
> {
    log::trace!("Spawning qemu...");

    let stderr = if join_logs {
        Stdio::inherit()
    } else {
        Stdio::piped()
    };

    let ssd1306 = TcpListener::bind("127.0.0.1:0").await?;
    let nt3h = TcpListener::bind("127.0.0.1:0").await?;
    let nt3h_interrupt = TcpListener::bind("127.0.0.1:0").await?;
    let tsc = TcpListener::bind("127.0.0.1:0").await?;
    let monitor = TcpListener::bind("127.0.0.1:0").await?;

    let mut args = vec![
        "-cpu".into(),
        "cortex-m4".into(),
        "-machine".into(),
        "b-l475e-iot01a".into(),
        "-chardev".into(),
        "file,id=log,path=/dev/stderr".into(),
        "-chardev".into(),
        format!(
            "socket,id=tcpmon,server=off,host=127.0.0.1,port={}",
            monitor.local_addr()?.port()
        ),
        "-chardev".into(),
        format!(
            "socket,id=nt3h,server=off,host=127.0.0.1,port={}",
            nt3h.local_addr()?.port()
        ),
        "-chardev".into(),
        format!(
            "socket,id=ssd1306,server=off,host=127.0.0.1,port={}",
            ssd1306.local_addr()?.port()
        ),
        "-chardev".into(),
        format!(
            "socket,id=nt3h_int,server=off,host=127.0.0.1,port={}",
            nt3h_interrupt.local_addr()?.port()
        ),
        "-chardev".into(),
        format!(
            "socket,id=tsc,server=off,host=127.0.0.1,port={}",
            tsc.local_addr()?.port()
        ),
        "-serial".into(),
        "chardev:nt3h".into(),
        "-serial".into(),
        "chardev:ssd1306".into(),
        "-serial".into(),
        "chardev:tsc".into(),
        "-serial".into(),
        "chardev:nt3h_int".into(),
        "-semihosting-config".into(),
        "enable=on,target=native,chardev=log".into(),
        "-display".into(),
        "none".into(),
        "-monitor".into(),
        "chardev:tcpmon".into(),
        "-seed".into(),
        format!("0x{:016X}", entropy),
        "-drive".into(),
        format!("file={},format=raw,if=mtd", flash.display()),
    ]
    .into_iter()
    .collect::<Vec<_>>();

    if let Some(port) = listen_gdb {
        args.push("-gdb".to_string());
        args.push(format!("tcp::{}", port));

        if wait_gdb {
            args.push("-S".to_string());

            log::info!("Waiting for GDB to attach...");
        }
    }

    log::trace!("QEMU args: {:?}", args);

    let mut child = ProcessCommand::new("qemu-system-arm")
        .kill_on_drop(true)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(stderr)
        .spawn()?;
    let stderr = child.stderr.take();

    // Wait for qemu to connect
    let (monitor, ssd1306, nt3h, nt3h_interrupt, tsc) = futures::join!(
        monitor.accept(),
        ssd1306.accept(),
        nt3h.accept(),
        nt3h_interrupt.accept(),
        tsc.accept()
    );
    let (monitor, ssd1306, nt3h, nt3h_interrupt, tsc) =
        (monitor?.0, ssd1306?.0, nt3h?.0, nt3h_interrupt?.0, tsc?.0);

    Ok((stderr, child, monitor, ssd1306, nt3h, nt3h_interrupt, tsc))
}

trait AsyncReadWrite: AsyncRead + AsyncWrite {}
impl<T: AsyncRead + AsyncWrite> AsyncReadWrite for T {}

async fn spawn_support_tasks(
    ssd1306: Pin<Box<dyn AsyncRead + Send>>,
    nt3h: Pin<Box<dyn AsyncReadWrite + Send>>,
    nt3h_interrupt: Pin<Box<dyn AsyncReadWrite + Send>>,
    tsc: Pin<Box<dyn AsyncReadWrite + Send>>,
    log: Option<ChildStderr>,
) -> (
    mpsc::UnboundedReceiver<String>,
    Arc<Mutex<ssd1306_emulator::SRAM>>,
    mpsc::UnboundedReceiver<()>,
    Arc<Mutex<nt3h_emulator::NT3H>>,
    mpsc::UnboundedSender<bool>,
) {
    let (display_sender, display_receiver) = mpsc::unbounded_channel();

    let sram = Arc::new(Mutex::new(ssd1306_emulator::SRAM::default()));
    let mut ssd1306_command_stream = ssd1306_emulator::CommandStream(ssd1306);
    let sram_cloned = Arc::clone(&sram);
    tokio::spawn(async move {
        loop {
            match (ssd1306_command_stream.update_sram(&sram_cloned)).await {
                Err(e) => {
                    log::warn!("SSD1306 update error {:?}", e);
                    break;
                }
                Ok(false) => continue,
                Ok(true) => display_sender.send(()).unwrap(),
            }
        }
    });

    let (nt3h_instance, int_recv) = nt3h_emulator::NT3H::new();
    let nt3h_instance = Arc::new(Mutex::new(nt3h_instance));

    let mut nt3h_command_stream =
        nt3h_emulator::CommandStream::new(nt3h, nt3h_interrupt, int_recv).await;

    let nt3h_cloned = Arc::clone(&nt3h_instance);
    tokio::spawn(async move {
        while let Ok(_) = nt3h_command_stream.update_nt3h(&nt3h_cloned).await {}
    });

    let (log_sender, log_receiver) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        if let Some(log) = log {
            let mut bufreader = BufReader::new(log);
            let mut s = String::new();
            loop {
                s.clear();
                let readline = bufreader.read_line(&mut s).await.expect("Read log line");
                if readline == 0 {
                    log::warn!("Log socket closed");
                    break;
                }
                let line = s.trim().to_string();
                log::trace!("Log line: {}", line);
                if log_sender.send(line).is_err() {
                    break;
                }
            }
        }
    });

    let (tsc_s, mut tsc_r) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut v = 255u8;
        let tsc = Arc::new(Mutex::new(tsc));

        loop {
            let v_copy = v;
            let fut_a = async {
                match tsc_r.recv().await {
                    Some(true) => {
                        v = 0;
                        false
                    }
                    Some(false) => {
                        v = 255;
                        false
                    }
                    None => true,
                }
            };
            let tsc = Arc::clone(&tsc);
            let fut_b = async move {
                let mut lock = tsc.lock().await;
                let mut buf = [0u8; 1];
                match lock.read_exact(&mut buf).await {
                    Err(_) => true,
                    Ok(_) => lock.write_all(&[v_copy]).await.is_err(),
                }
            };
            let stop = futures::select! {
                v = fut_a.fuse() => v,
                v = fut_b.fuse() => v,
            };

            if stop {
                break;
            }
        }
    });

    (log_receiver, sram, display_receiver, nt3h_instance, tsc_s)
}

pub struct Display {
    pub surface: SimulatorDisplay<BinaryColor>,
    pub update: mpsc::UnboundedReceiver<()>,
    pub sram: Arc<Mutex<ssd1306_emulator::SRAM>>,
}

impl Display {
    pub fn new(
        update: mpsc::UnboundedReceiver<()>,
        sram: Arc<Mutex<ssd1306_emulator::SRAM>>,
    ) -> Self {
        Display {
            surface: SimulatorDisplay::new(Size::new(128, 64)),
            update,
            sram,
        }
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

pub struct EmulatorInstance {
    pub logs: mpsc::UnboundedReceiver<String>,
    pub display: Display,
    pub sdk: Arc<PortalSdk>,
    pub tsc: mpsc::UnboundedSender<bool>,
    pub entropy: u64,
    pub flash: flash::Flash,

    monitor: TcpStream,
    _qemu_handle: Child,
}

impl EmulatorInstance {
    pub async fn spawn_qemu(
        firmware: &Path,
        write_firmware_to_flash: bool,
        load_to_bank: usize,
        join_logs: bool,
        listen_gdb: Option<u16>,
        wait_gdb: bool,
        flash: Option<(PathBuf, bool)>,
        entropy: u64,
    ) -> Result<Self, crate::Error> {
        let flash = match flash {
            Some((path, allow_changing)) => {
                let mut flash = flash::Flash::load_from_file(&path, allow_changing).await?;
                if write_firmware_to_flash {
                    flash.write_firmware(firmware, load_to_bank).await?;
                }
                flash
            }
            None => flash::Flash::create_from_firmware(firmware, load_to_bank).await?,
        };

        let (log, qemu_handle, monitor, ssd1306, nt3h, nt3h_interrupt, tsc) =
            get_qemu_instance(flash.path(), join_logs, listen_gdb, wait_gdb, entropy).await?;

        let (logs, sram, display_update, nt3h, tsc) = spawn_support_tasks(
            Box::pin(ssd1306),
            Box::pin(nt3h),
            Box::pin(nt3h_interrupt),
            Box::pin(tsc),
            log,
        )
        .await;
        let display = Display::new(display_update, sram);

        let sdk = EmulatorInstance::attach_sdk(nt3h);

        Ok(EmulatorInstance {
            logs,
            display,
            sdk,
            entropy,
            tsc,
            flash,
            monitor,
            _qemu_handle: qemu_handle,
        })
    }

    fn attach_sdk(nt3h: Arc<Mutex<nt3h_emulator::NT3H>>) -> Arc<PortalSdk> {
        log::trace!("Attaching SDK");

        let sdk = PortalSdk::new(true);
        let cloned_sdk = Arc::clone(&sdk);
        tokio::spawn(async move {
            loop {
                let out = cloned_sdk.poll().await.unwrap();

                log::trace!("> {:02X?}", out.data);
                let incoming = match tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    nt3h.lock().await.nfc_command(&out.data),
                )
                .await
                {
                    Ok(v) => v,
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

    pub async fn reset(&mut self, wipe_registers: bool) -> tokio::io::Result<()> {
        if wipe_registers {
            self.monitor
                .write_all("system_wipe_rtc_bkpr\n".as_bytes())
                .await?;
        }
        self.monitor.write_all("system_reset\n".as_bytes()).await?;

        self.sdk
            .new_tag()
            .await
            .expect("PortalSdk::new_tag() always works");

        Ok(())
    }
}

pub fn try_pull_msg<T>(s: &mut mpsc::UnboundedReceiver<T>) -> Result<Option<T>, String> {
    match s.try_recv() {
        Ok(v) => Ok(Some(v)),
        Err(mpsc::error::TryRecvError::Empty) => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

pub async fn manage_hw(
    emulator: &mut EmulatorInstance,
    debug_logs: bool,
) -> Result<usize, crate::Error> {
    if debug_logs {
        while let Ok(l) = emulator.logs.try_recv() {
            log::debug!("{:?}", l);
        }
    }

    let mut update_count = 0;
    while let Some(_) = try_pull_msg(&mut emulator.display.update)? {
        emulator
            .display
            .sram
            .lock()
            .await
            .draw(&mut emulator.display.surface)?;
        update_count += 1;
    }

    // Sleep for a little bit: in case of a single-threaded context this will let
    // the runtime move forward the other tasks a bit. Otherwise we might end up
    // in a deadlock while waiting for somewhing to happen
    // tokio::time::sleep(std::time::Duration::from_millis(25)).await;

    Ok(update_count)
}
