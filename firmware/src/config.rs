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

use model::Config;

use crate::hw::PAGE_SIZE;
use crate::hw::{Flash, FlashError};

pub const CONFIG_PAGE: usize = 255;

pub fn read_config(flash: &mut Flash) -> Result<Config, FlashError> {
    let mut buf = [0u8; PAGE_SIZE];
    let buf = crate::hw::read_flash(flash, CONFIG_PAGE, &mut buf)?;
    let config = minicbor::decode(buf)?;
    Ok(config)
}

pub fn write_config(flash: &mut Flash, config: &Config) -> Result<(), FlashError> {
    let serialized = minicbor::to_vec(config).expect("always succeed");
    crate::hw::write_flash(flash, CONFIG_PAGE, &serialized)
}
