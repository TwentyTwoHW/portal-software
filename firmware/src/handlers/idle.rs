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

use alloc::rc::Rc;

use futures::prelude::*;

use gui::InitialPage;
use model::{DeviceInfo, Reply};

use super::*;
use crate::Error;

pub async fn handle_idle(
    wallet: &mut Rc<bdk::Wallet>,
    mut events: impl Stream<Item = Event> + Unpin,
    peripherals: &mut HandlerPeripherals,
) -> Result<CurrentState, Error> {
    log::info!("handle_idle");

    let page = InitialPage::new("Portal ready", "");
    page.init_display(&mut peripherals.display)?;
    page.draw_to(&mut peripherals.display)?;
    peripherals.display.flush()?;

    let events = only_requests(&mut events);
    pin_mut!(events);

    loop {
        match events.next().await {
            Some(model::Request::GetInfo) => {
                peripherals
                    .nfc
                    .send(Reply::Info(DeviceInfo::new_unlocked_initialized(
                        wallet.network(),
                    )))
                    .await
                    .unwrap();
                peripherals.nfc_finished.recv().await.unwrap();
                continue;
            }
            Some(model::Request::DisplayAddress(index)) => {
                break Ok(CurrentState::DisplayAddress {
                    index,
                    wallet: Rc::clone(wallet),
                });
            }
            Some(model::Request::BeginSignPsbt) => {
                break Ok(CurrentState::WaitingForPsbt {
                    wallet: Rc::clone(wallet),
                });
            }
            Some(model::Request::PublicDescriptor) => {
                break Ok(CurrentState::PublicDescriptor {
                    wallet: Rc::clone(wallet),
                });
            }
            Some(model::Request::BeginFwUpdate(header)) => {
                break Ok(CurrentState::UpdatingFw { header });
            }
            Some(_) => {
                peripherals
                    .nfc
                    .send(model::Reply::UnexpectedMessage)
                    .await
                    .unwrap();
                peripherals.nfc_finished.recv().await.unwrap();
                continue;
            }
            _ => unreachable!(),
        }
    }
}
