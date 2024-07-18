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

use futures::prelude::*;

use gui::{Page, SummaryPage};

use super::*;
use crate::Error;

pub async fn wipe_device(
    mut events: impl Stream<Item = Event> + Unpin,
    peripherals: &mut HandlerPeripherals,
) -> Result<CurrentState, Error> {
    let mut page = SummaryPage::new_with_threshold("Wipe device?", "HOLD BTN TO WIPE", 70);
    page.init_display(&mut peripherals.display)?;
    page.draw_to(&mut peripherals.display)?;
    peripherals.display.flush()?;

    peripherals.tsc_enabled.enable();
    manage_confirmation_loop(&mut events, peripherals, &mut page).await?;
    peripherals.tsc_enabled.disable();

    crate::hw::write_flash(&mut peripherals.flash, crate::config::CONFIG_PAGE, &[])?;

    peripherals.nfc.send(model::Reply::Ok).await.unwrap();
    peripherals.nfc_finished.recv().await.unwrap();

    cortex_m::peripheral::SCB::sys_reset();
}
