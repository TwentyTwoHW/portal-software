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

#![allow(non_snake_case)]

use core::fmt;

use modular_bitfield::prelude::*;

#[derive(Debug, PartialEq, Eq, Clone, Copy, BitfieldSpecifier)]
#[bits = 2]
pub enum FdOff {
    Nothing,
    TagHalted,
    LastNdefRead,
    HostDone,
}
#[derive(Debug, PartialEq, Eq, Clone, Copy, BitfieldSpecifier)]
#[bits = 2]
pub enum FdOn {
    FieldOn,
    ValidSoC,
    TagSelected,
    NfcDone,
}
#[derive(Debug, PartialEq, Eq, Clone, Copy, BitfieldSpecifier)]
#[bits = 1]
pub enum TransferDir {
    HostToNfc,
    NfcToHost,
}

#[allow(non_camel_case_types)]
#[bitfield]
pub struct NC_REG {
    pub TRANSFER_DIR: TransferDir,
    pub SRAM_MIRROR_ON_OFF: bool,
    pub FD_ON: FdOn,
    pub FD_OFF: FdOff,
    pub PTHRU_ON_OFF: bool,
    pub NFCS_I2C_RST_ON_OFF: bool,
}
impl fmt::Debug for NC_REG {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NC_REG")
            .field("TRANSFER_DIR", &self.TRANSFER_DIR())
            .field("SRAM_MIRROR_ON_OFF", &self.SRAM_MIRROR_ON_OFF())
            .field("FD_ON", &self.FD_ON())
            .field("FD_OFF", &self.FD_OFF())
            .field("PTHRU_ON_OFF", &self.PTHRU_ON_OFF())
            .field("NFCS_I2C_RST_ON_OFF", &self.NFCS_I2C_RST_ON_OFF())
            .finish()
    }
}

#[allow(non_camel_case_types)]
#[bitfield]
pub struct I2C_CLOCK_STR {
    pub I2C_CLOCK_STR: bool,
    pub RFU: B7,
}

#[allow(non_camel_case_types)]
#[bitfield]
pub struct REG_LOCK {
    pub REG_LOCK_NFC: bool,
    pub REG_LOCK_I2C: bool,
    pub RFU: B6,
}

#[allow(non_camel_case_types)]
#[bitfield]
#[derive(Clone)]
pub struct NS_REG {
    pub RF_FIELD_PRESENT: bool,
    pub EEPROM_WR_BUSY: bool,
    pub EEPROM_WR_ERR: bool,
    pub SRAM_RF_READY: bool,
    pub SRAM_I2C_READY: bool,
    pub RF_LOCKED: bool,
    pub I2C_LOCKED: bool,
    pub NDEF_DATA_READ: bool,
}
impl fmt::Debug for NS_REG {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NS_REG")
            .field("RF_FIELD_PRESENT", &self.RF_FIELD_PRESENT())
            .field("EEPROM_WR_BUSY", &self.EEPROM_WR_BUSY())
            .field("EEPROM_WR_ERR", &self.EEPROM_WR_ERR())
            .field("SRAM_RF_READY", &self.SRAM_RF_READY())
            .field("SRAM_I2C_READY", &self.SRAM_I2C_READY())
            .field("RF_LOCKED", &self.RF_LOCKED())
            .field("I2C_LOCKED", &self.I2C_LOCKED())
            .field("NDEF_DATA_READ", &self.NDEF_DATA_READ())
            .finish()
    }
}
