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

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use model::emulator::EmulatorMessage;
use tokio::process::Command as ProcessCommand;
use tokio::sync::mpsc;

use env_logger::Env;

use fltk::{app, prelude::*};

use embedded_graphics_simulator::{BinaryColorTheme, OutputSettingsBuilder};

use clap::{Args, Parser};

use emulator::utils::try_pull_msg;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    #[clap(flatten)]
    global_opts: GlobalOpts,
}

#[derive(Debug, Args)]
struct GlobalOpts {
    #[clap(
        long,
        short = 'f',
        default_value = "./firmware/target/thumbv7em-none-eabihf/release/firmware"
    )]
    /// Path of the firmware ELF file.
    firmware: PathBuf,

    #[clap(long, short = 'b', default_value = "1")]
    /// Bank to flash the firmware file to.
    flash_to_bank: usize,

    /// Whether to print emulated firmware logs to the emulator's stderr
    #[clap(long, short = 'j', action = clap::ArgAction::SetTrue, default_value_t = false)]
    join_logs: bool,

    /// Do not recompile the firmware
    ///
    /// By default the emulator always tries to run `cargo build` in the `--firmware-src-directory` dir
    /// before launching QEMU
    #[clap(long, action = clap::ArgAction::SetTrue, default_value_t = false)]
    no_cargo_build: bool,

    /// Directory containing the firmware source code
    ///
    /// The emulator runs `cargo build` in this directory, unless `--no-cargo-build` is specified
    #[clap(long, default_value = "./firmware/")]
    firmware_src_directory: PathBuf,

    /// Port to bind the GDB server to
    #[clap(long)]
    listen_gdb: Option<u16>,

    /// Whether to wait for GDB to attach before running the firmware
    ///
    /// Must be used in conjunction with GDB enabled (--listen-gdb).
    #[clap(long, action = clap::ArgAction::SetTrue, default_value_t = false)]
    wait_gdb: bool,

    /// File backing the flash memory
    ///
    /// If unspecified the flash data will only be kept in memory temporarily.
    #[clap(long)]
    flash_file: Option<PathBuf>,

    /// Do not write firmware to flash
    ///
    /// If enabled overwrite the firmware in the given flash file
    #[clap(long, short = 'w', action = clap::ArgAction::SetTrue, default_value_t = false)]
    no_write_firmware: bool,

    /// Entropy used to seed the device
    ///
    /// If unspecified it will be generated randomly.
    #[clap(long, short = 'e')]
    entropy: Option<u64>,
}

#[tokio::main]
async fn main() -> Result<(), emulator::Error> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
    .expect("Error setting Ctrl-C handler");

    let args = CliArgs::parse();

    if !args.global_opts.no_cargo_build {
        log::info!("Building firmware...");

        let cmd_args = vec![
            "build",
            "--no-default-features",
            "--features",
            "device",
            "--release",
        ];
        log::debug!("Cardo build args: {:?}", cmd_args);

        let status = ProcessCommand::new("cargo")
            .current_dir(&args.global_opts.firmware_src_directory)
            .args(cmd_args)
            .stdin(Stdio::piped())
            .spawn()?
            .wait()
            .await?;

        if !status.success() {
            return Err("Cargo build failed".into());
        }
    }

    if !Path::new(&args.global_opts.firmware).exists() {
        return Err(format!(
            "Chosen firmware file doesn't exist: {}",
            args.global_opts.firmware.display()
        )
        .into());
    }

    let mut emulator = emulator::utils::EmulatorInstance::spawn_qemu(
        &args.global_opts.firmware,
        !args.global_opts.no_write_firmware,
        args.global_opts.flash_to_bank,
        args.global_opts.join_logs,
        args.global_opts.listen_gdb,
        args.global_opts.wait_gdb,
        args.global_opts.flash_file.map(|p| (p, true)),
        emulator::utils::model::get_entropy(&args.global_opts.entropy),
    )
    .await?;

    let output_settings = OutputSettingsBuilder::new().scale(1).build();

    let output_settings_large = OutputSettingsBuilder::new()
        .theme(BinaryColorTheme::OledWhite)
        .build();

    let output_image = emulator
        .display
        .surface
        .to_grayscale_output_image(&output_settings);
    let output_image_large = emulator
        .display
        .surface
        .to_grayscale_output_image(&output_settings_large);
    let fb = Arc::new(std::sync::RwLock::new(output_image));
    let fb_large = Arc::new(std::sync::RwLock::new(output_image_large));

    let sdk = Arc::clone(&emulator.sdk);
    let cloned_sdk = Arc::clone(&sdk);
    tokio::spawn(async move {
        while let Ok(msg) = cloned_sdk.debug_msg().await {
            match msg {
                portal::DebugMessage::RawOut(data) => log::debug!("> Raw({:02X?})", data),
                portal::DebugMessage::Out(req) => log::debug!("> {:?}", req),
                portal::DebugMessage::In(reply) => log::debug!("< {:?}", reply),
            }
        }
    });

    let (log_s, mut log_r) = mpsc::unbounded_channel::<String>();
    let (cmd_s, mut cmd_r) = mpsc::unbounded_channel();
    let app = fltk::app::App::default().with_scheme(app::Scheme::Gtk);
    let mut emulator_gui =
        emulator::gui::init_gui(fb.clone(), fb_large.clone(), cmd_s, sdk.clone(), log_s);

    app::add_idle3(move |_| {
        emulator_gui.window.redraw();
        // sleeps are necessary when calling redraw in the event loop
        app::sleep(1.0 / 60.0);
    });

    fn append_to_console(dir: &str, s: &str, console: &mut fltk::text::TextDisplay) {
        console.buffer().unwrap().append(dir);
        console.buffer().unwrap().append(s);
        console.buffer().unwrap().append("\n");
        console.scroll(i32::MAX, 0);
    }

    while app.wait() && running.load(Ordering::SeqCst) {
        // while let Some(_) = try_pull_msg(&mut emulator.msgs.finish_boot)? {
        //     log::info!("Card was reset, performing Noise handshake again...");

        //     let entropy = emulator::utils::model::get_entropy(&args.global_opts.entropy);
        //     emulator
        //         .card
        //         .send(model::emulator::EmulatorMessage::Entropy(entropy))
        //         .unwrap();
        //     emulator
        //         .card
        //         .send(model::emulator::EmulatorMessage::Rtc(emulator.rtc))
        //         .unwrap();

        //     sdk.new_tag().await.expect("New tag");
        // }

        // emulator::link::manage_hw(
        //     &mut emulator,
        //     append_to_console,
        //     &mut emulator_gui.console,
        //     true,
        //     true,
        // )
        // .await?;

        while let Some(s) = try_pull_msg::<String>(&mut log_r)? {
            append_to_console("", &s, &mut emulator_gui.console);
        }

        while let Some(_) = try_pull_msg(&mut emulator.display.update)? {
            emulator
                .display
                .sram
                .lock()
                .await
                .draw(&mut emulator.display.surface)?;
        }

        while let Some(msg) = try_pull_msg(&mut cmd_r)? {
            match msg {
                EmulatorMessage::Tsc(v) => emulator.tsc.send(v)?,
                EmulatorMessage::Reset => {
                    emulator.reset(false).await?;
                    emulator.sdk.new_tag().await?;
                }
                _ => {}
            }
        }

        let mut fb = fb.write().unwrap();
        fb.update(&emulator.display.surface);
        let mut fb_large = fb_large.write().unwrap();
        fb_large.update(&emulator.display.surface);
    }

    Ok(())
}
