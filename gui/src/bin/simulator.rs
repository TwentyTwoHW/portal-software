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

use std::{str::FromStr, time::Duration};

use embedded_graphics::{pixelcolor::BinaryColor, prelude::*};
use embedded_graphics_simulator::{
    BinaryColorTheme, OutputSettingsBuilder, SimulatorDisplay, SimulatorEvent, Window,
};

use gui::*;

fn main() -> Result<(), std::convert::Infallible> {
    // Create a new simulator display with 128x64 pixels.
    let mut display: SimulatorDisplay<BinaryColor> = SimulatorDisplay::new(Size::new(128, 64));

    let output_settings = OutputSettingsBuilder::new()
        .theme(BinaryColorTheme::OledWhite)
        .build();
    let mut window = Window::new("portal GUI Simulator", &output_settings);

    let page = std::env::args()
        .nth(1)
        .expect("Please select a page to display");
    match page.as_str() {
        "welcome" => welcome_page(&mut window, &mut display)?,
        "initial" => initial_page(&mut window, &mut display)?,
        "summary" => summary_page(&mut window, &mut display)?,
        "fwupdate" => fwupdate_page(&mut window, &mut display)?,
        "error" => error_page(&mut window, &mut display)?,
        "mnemonic" => mnemonic_page(&mut window, &mut display)?,
        "output" => output_page(&mut window, &mut display)?,
        "tx_summary" => tx_summary_page(&mut window, &mut display)?,
        p => panic!("Invalid page selected: {}", p),
    }

    Ok(())
}

fn welcome_page(
    window: &mut Window,
    display: &mut SimulatorDisplay<BinaryColor>,
) -> Result<(), std::convert::Infallible> {
    let p = WelcomePage::new("version");
    p.init_display(display)?;

    loop {
        p.draw_to(display)?;
        window.update(&display);

        for event in window.events() {
            match event {
                SimulatorEvent::Quit => std::process::exit(0),
                SimulatorEvent::MouseButtonDown { .. } => return Ok(()),
                _ => {}
            }
        }
    }
}

fn initial_page(
    window: &mut Window,
    display: &mut SimulatorDisplay<BinaryColor>,
) -> Result<(), std::convert::Infallible> {
    let p = InitialPage::new("Welcome", "version");
    p.init_display(display)?;
    p.draw_to(display)?;

    loop {
        window.update(&display);

        for event in window.events() {
            match event {
                SimulatorEvent::Quit => std::process::exit(0),
                SimulatorEvent::MouseButtonDown { .. } => return Ok(()),
                _ => {}
            }
        }
    }
}

fn confirm_bar_page<'s, P, C>(
    window: &mut Window,
    display: &mut SimulatorDisplay<BinaryColor>,
    mut p: P,
) -> Result<(), std::convert::Infallible>
where
    P: std::ops::DerefMut<Target = ConfirmBarPage<'s, C>>,
    C: MainContent,
{
    p.init_display(display)?;

    let mut is_loading = false;
    let mut redraw = true;

    'running: loop {
        window.update(&display);

        for event in window.events() {
            match event {
                SimulatorEvent::Quit => std::process::exit(0),
                SimulatorEvent::MouseButtonDown { .. } => {
                    is_loading = true;
                }
                SimulatorEvent::MouseButtonUp { .. } => {
                    is_loading = false;
                    redraw = true;
                    p.reset_confirm();
                }
                _ => {}
            }
        }

        if is_loading {
            if p.is_confirmed() {
                break 'running;
            }

            p.add_confirm(1);
            redraw = true;
        }
        if redraw {
            p.draw_to(display)?;
            redraw = false;
        }
    }

    Ok(())
}

fn summary_page(
    window: &mut Window,
    display: &mut SimulatorDisplay<BinaryColor>,
) -> Result<(), std::convert::Infallible> {
    let p = SummaryPage::new("Export\nDescriptor?", "HOLD BTN TO CONFIRM");
    confirm_bar_page(window, display, p)
}

fn mnemonic_page(
    window: &mut Window,
    display: &mut SimulatorDisplay<BinaryColor>,
) -> Result<(), std::convert::Infallible> {
    let mnemonic = "pass portion ordinary salon dwarf tuna cheap pole three surge gallery bulk"
        .split(" ")
        .collect::<Vec<_>>();
    let p = MnemonicPage::new(0, &mnemonic);
    confirm_bar_page(window, display, p)
}

fn output_page(
    window: &mut Window,
    display: &mut SimulatorDisplay<BinaryColor>,
) -> Result<(), std::convert::Infallible> {
    let address = model::bitcoin::Address::from_str(
        "bc1q0hzrflaz2988h6zrne85tnq47k2grgarycgjrke7qje92wfxdzxq0ymtq9",
    )
    .unwrap();
    let value = model::bitcoin::Amount::from_sat(30004732);
    let mut p = TxOutputPage::new(&address, value);

    loop {
        std::thread::sleep(Duration::from_millis(250));
        p.next();

        window.update(&display);

        for event in window.events() {
            match event {
                SimulatorEvent::Quit => std::process::exit(0),
                _ => {}
            }
        }

        p.draw_to(display)?;
    }
}
fn tx_summary_page(
    window: &mut Window,
    display: &mut SimulatorDisplay<BinaryColor>,
) -> Result<(), std::convert::Infallible> {
    let value = model::bitcoin::Amount::from_sat(1230);
    let p = TxSummaryPage::new(value);
    confirm_bar_page(window, display, p)
}

fn fwupdate_page(
    window: &mut Window,
    display: &mut SimulatorDisplay<BinaryColor>,
) -> Result<(), std::convert::Infallible> {
    let mut p = FwUpdatePage::new();
    p.init_display(display)?;

    loop {
        window.update(&display);
        p.add_progress(1);

        for event in window.events() {
            match event {
                SimulatorEvent::Quit => std::process::exit(0),
                _ => {}
            }
        }

        p.draw_to(display)?;
    }
}

fn error_page(
    window: &mut Window,
    display: &mut SimulatorDisplay<BinaryColor>,
) -> Result<(), std::convert::Infallible> {
    let p = ErrorPage::new("Error Messaage Here");
    p.init_display(display)?;

    loop {
        window.update(&display);

        for event in window.events() {
            match event {
                SimulatorEvent::Quit => std::process::exit(0),
                _ => {}
            }
        }

        p.draw_to(display)?;
    }
}
