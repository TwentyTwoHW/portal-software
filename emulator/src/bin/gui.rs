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
use std::sync::Arc;

use tokio::process::Command as ProcessCommand;
use tokio::sync::mpsc;

use env_logger::Env;

use fltk::{app, prelude::*};

use embedded_graphics_simulator::{BinaryColorTheme, OutputSettingsBuilder};

use clap::{Args, Parser};

use emulator::link::try_pull_msg;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    #[clap(flatten)]
    global_opts: GlobalOpts,
}

#[derive(Debug, Args)]
struct GlobalOpts {
    /// Path for the UNIX socket of QEMU's serial port
    ///
    /// Used only when `--no-auto-qemu` is enabled, otherwise an instance of QEMU
    /// is spawned internall
    #[clap(long, short = 's', default_value = "./firmware/serial1.socket")]
    emulator_socket: PathBuf,

    #[clap(
        long,
        short = 'f',
        default_value = "./firmware/target/thumbv7em-none-eabihf/debug/firmware"
    )]
    /// Path of the firmware ELF file
    ///
    /// Used when spawning a QEMU instance internally
    firmware: PathBuf,

    /// Do not launch QEMU internally
    ///
    /// This will make the emulator connect to the UNIX socket specified with `--emulator-socket`
    #[clap(long, action = clap::ArgAction::SetTrue, default_value_t = false)]
    no_auto_qemu: bool,

    /// Whether to print emulated firmware logs to the emulator's stderr
    ///
    /// This only has an effect when spawning QEMU internally
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
    ///
    /// Only used when QEMU is spawned internally
    #[clap(long)]
    listen_gdb: Option<u16>,

    /// Whether to wait for GDB to attach before running the firmware
    ///
    /// Only used when QEMU is spawned internally for a gui session with
    /// GDB enabled (--listen-gdb).
    #[clap(long, action = clap::ArgAction::SetTrue, default_value_t = false)]
    wait_gdb: bool,

    /// File backing the flash memory
    ///
    /// If unspecified the flash data will only be kept in memory temporarily.
    #[clap(long)]
    flash_file: Option<PathBuf>,

    /// Entropy used to seed the device
    ///
    /// If unspecified it will be generated randomly. Must be a 32-byte hex string
    #[clap(long, short = 'e', value_parser = emulator::utils::model::parse_entropy)]
    entropy: Option<emulator::utils::model::Entropy>,
}

#[tokio::main]
async fn main() -> Result<(), emulator::Error> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let args = CliArgs::parse();

    if !args.global_opts.no_cargo_build {
        log::info!("Building firmware...");

        let cmd_args = vec!["build"];

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

    let mut emulator = emulator::utils::get_emulator_instance(
        !args.global_opts.no_auto_qemu,
        &args.global_opts.emulator_socket,
        &args.global_opts.firmware,
        args.global_opts.join_logs,
        args.global_opts
            .flash_file
            .and_then(|f| Some(emulator::utils::get_flash_file(&f)))
            .transpose()?,
        args.global_opts.listen_gdb,
        args.global_opts.wait_gdb,
        emulator::utils::model::get_entropy(&args.global_opts.entropy),
    )
    .await?;

    let output_settings = OutputSettingsBuilder::new().scale(1).build();

    let output_settings_large = OutputSettingsBuilder::new()
        .theme(BinaryColorTheme::OledWhite)
        .build();

    let output_image = emulator.display.to_grayscale_output_image(&output_settings);
    let output_image_large = emulator
        .display
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
    let app = fltk::app::App::default().with_scheme(app::Scheme::Gtk);
    let mut emulator_gui = emulator::gui::init_gui(
        fb.clone(),
        fb_large.clone(),
        emulator.card.clone(),
        sdk.clone(),
        log_s,
    );

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

    while app.wait() {
        while let Some(_) = try_pull_msg(&mut emulator.msgs.finish_boot)? {
            log::info!("Card was reset, performing Noise handshake again...");

            let entropy = emulator::utils::model::get_entropy(&args.global_opts.entropy);
            emulator
                .card
                .send(model::emulator::EmulatorMessage::Entropy(entropy))
                .unwrap();

            sdk.new_tag().await.expect("New tag");
        }

        emulator::link::manage_hw(
            &mut emulator,
            append_to_console,
            &mut emulator_gui.console,
            true,
            true,
        )
        .await?;

        while let Some(s) = try_pull_msg::<String>(&mut log_r)? {
            append_to_console("", &s, &mut emulator_gui.console);
        }

        let mut fb = fb.write().unwrap();
        fb.update(&emulator.display);
        let mut fb_large = fb_large.write().unwrap();
        fb_large.update(&emulator.display);
    }

    Ok(())
}
