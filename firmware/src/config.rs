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

use hal::flash::{self, Read, WriteErase};

use model::Config;

use crate::hw::Flash;

const PAGE_SIZE: usize = 2048;
const CONFIG_PAGE: usize = 255;

pub async fn read_config(flash: &mut Flash) -> Result<Config, ConfigError> {
    let flash = &mut flash.parts;

    let prog = flash.keyr.unlock_flash(&mut flash.sr, &mut flash.cr)?;

    let last_page = flash::FlashPage(CONFIG_PAGE).to_address();

    let mut buf = [0u8; PAGE_SIZE];
    prog.read(last_page, &mut buf);
    let len = u16::from_be_bytes(buf[..2].try_into().unwrap()) as usize;
    if len >= PAGE_SIZE - 2 {
        return Err(ConfigError::CorruptedConfig);
    }

    let config = minicbor::decode(&buf[2..2 + len])?;
    Ok(config)
}

pub async fn write_config(flash: &mut Flash, config: &Config) -> Result<(), ConfigError> {
    let flash = &mut flash.parts;

    let mut prog = flash.keyr.unlock_flash(&mut flash.sr, &mut flash.cr)?;

    let mut data = alloc::vec![0x00, 0x00];
    let serialized = minicbor::to_vec(config).expect("always succeed");

    if serialized.len() > PAGE_SIZE - 2 {
        return Err(ConfigError::CorruptedConfig);
    }

    let len = (serialized.len() as u16).to_be_bytes();
    data.extend(serialized);
    (&mut data[..2]).copy_from_slice(&len);
    data.resize(PAGE_SIZE, 0x00);

    let page = flash::FlashPage(CONFIG_PAGE);
    prog.erase_page(page)?;
    prog.erase_page(flash::FlashPage(CONFIG_PAGE + 256))?; // Erase on both banks
    prog.write(page.to_address(), &data)?;

    Ok(())
}

#[derive(Debug)]
pub enum ConfigError {
    CorruptedConfig,
    Deserialization,

    Flash(flash::Error),
}

impl From<minicbor::decode::Error> for ConfigError {
    fn from(_: minicbor::decode::Error) -> Self {
        ConfigError::Deserialization
    }
}
impl From<flash::Error> for ConfigError {
    fn from(e: flash::Error) -> Self {
        ConfigError::Flash(e)
    }
}
