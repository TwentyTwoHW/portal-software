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

use super::hw::Flash;

use model::Config;

pub async fn read_config(flash: &mut Flash) -> Result<Config, super::hw::FlashError> {
    let flash = flash.read().await;
    Ok(minicbor::decode(&flash).map_err(|_| ConfigError::CorruptedConfig)?)
}

pub async fn write_config(flash: &mut Flash, config: &Config) -> Result<(), super::hw::FlashError> {
    let buf = minicbor::to_vec(config).unwrap();
    flash.write(&buf);
    Ok(())
}