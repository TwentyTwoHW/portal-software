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

impl fmt::Debug for REG_LOCK {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("REG_LOCK")
            .field("REG_LOCK_NFC", &self.REG_LOCK_NFC())
            .field("REG_LOCK_I2C", &self.REG_LOCK_I2C())
            .finish()
    }
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

#[allow(non_camel_case_types)]
#[bitfield]
pub struct AUTH0 {
    pub AUTH0: u8,
}

impl fmt::Debug for AUTH0 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AUTH0")
            .field("AUTH0", &self.AUTH0())
            .finish()
    }
}

#[allow(non_camel_case_types)]
#[bitfield]
pub struct ACCESS {
    pub AUTHLIM: B3,
    _RFU1: B2,
    pub NFC_DIS_SEC1: bool,
    _RFU2: B1,
    pub NFC_PROT: bool,
}

impl fmt::Debug for ACCESS {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ACCESS")
            .field("AUTHLIM", &self.AUTHLIM())
            .field("NFC_DIS_SEC1", &self.NFC_DIS_SEC1())
            .field("NFC_PROT", &self.NFC_PROT())
            .finish()
    }
}

#[allow(non_camel_case_types)]
#[bitfield]
pub struct DYNAMIC_LOCK_BYTES {
    _BYTE3: B8,

    pub BL_16_47: bool,
    pub BL_48_79: bool,
    pub BL_80_111: bool,
    pub BL_112_143: bool,
    pub BL_144_175: bool,
    pub BL_176_207: bool,
    pub BL_208_225: bool,
    _RFUI1: B1,

    pub LOCK_PAGE_144_159: bool,
    pub LOCK_PAGE_160_175: bool,
    pub LOCK_PAGE_176_191: bool,
    pub LOCK_PAGE_192_207: bool,
    pub LOCK_PAGE_208_223: bool,
    pub LOCK_PAGE_224_225: bool,
    _RFUI2: B1,
    _RFUI3: B1,
    pub LOCK_PAGE_16_31: bool,
    pub LOCK_PAGE_32_47: bool,
    pub LOCK_PAGE_48_63: bool,
    pub LOCK_PAGE_64_79: bool,
    pub LOCK_PAGE_80_95: bool,
    pub LOCK_PAGE_96_111: bool,
    pub LOCK_PAGE_112_127: bool,
    pub LOCK_PAGE_128_143: bool,
}

impl fmt::Debug for DYNAMIC_LOCK_BYTES {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DYNAMIC_LOCK_BYTES")
            .field("BL_16_47", &self.BL_16_47())
            .field("BL_48_79", &self.BL_48_79())
            .field("BL_80_111", &self.BL_80_111())
            .field("BL_112_143", &self.BL_112_143())
            .field("BL_144_175", &self.BL_144_175())
            .field("BL_176_207", &self.BL_176_207())
            .field("BL_208_225", &self.BL_208_225())
            .field("LOCK_PAGE_144_159", &self.LOCK_PAGE_144_159())
            .field("LOCK_PAGE_160_175", &self.LOCK_PAGE_160_175())
            .field("LOCK_PAGE_176_191", &self.LOCK_PAGE_176_191())
            .field("LOCK_PAGE_192_207", &self.LOCK_PAGE_192_207())
            .field("LOCK_PAGE_208_223", &self.LOCK_PAGE_208_223())
            .field("LOCK_PAGE_224_225", &self.LOCK_PAGE_224_225())
            .field("LOCK_PAGE_16_31", &self.LOCK_PAGE_16_31())
            .field("LOCK_PAGE_32_47", &self.LOCK_PAGE_32_47())
            .field("LOCK_PAGE_48_63", &self.LOCK_PAGE_48_63())
            .field("LOCK_PAGE_64_79", &self.LOCK_PAGE_64_79())
            .field("LOCK_PAGE_80_95", &self.LOCK_PAGE_80_95())
            .field("LOCK_PAGE_96_111", &self.LOCK_PAGE_96_111())
            .field("LOCK_PAGE_112_127", &self.LOCK_PAGE_112_127())
            .field("LOCK_PAGE_128_143", &self.LOCK_PAGE_128_143())
            .finish()
    }
}