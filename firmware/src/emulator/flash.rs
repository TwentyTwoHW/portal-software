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

#[derive(Debug)]
pub struct FlashPage(pub usize);

impl FlashPage {
    pub fn to_address(&self) -> usize {
        self.0 as usize
    }
}

pub struct UnlockedFlash<'f> {
    pub(super) flash: &'f super::hw::Flash,
}

impl<'s> UnlockedFlash<'s> {
    pub fn read(&self, address: usize, buf: &mut [u8]) {
        let data = self.flash.read(address as u16);
        buf.copy_from_slice(&data[..buf.len()]);
    }

    pub fn write(&self, address: usize, buf: &[u8]) -> Result<(), ()> {
        self.flash.write(address as u16, buf);
        Ok(())
    }

    pub fn erase_page(&self, page: FlashPage) -> Result<(), ()> {
        self.flash.write(page.to_address() as u16, &alloc::vec![0xFF; crate::hw_common::PAGE_SIZE]);
        Ok(())
    }

    pub fn mass_erase(&self, bank: usize) -> Result<(), ()> {
        let offset = if bank == 0 { 0 } else { 256 };
        for i in 0..255 {
            self.erase_page(FlashPage(i + offset))?;
        }

        Ok(())
    }
}