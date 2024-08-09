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

use std::{
    io::SeekFrom,
    path::{Path, PathBuf},
};

use tempdir::TempDir;
use tokio::{
    fs,
    io::{self, AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    process,
};

pub struct Flash {
    path: PathBuf,
    _tmpdir: Option<TempDir>,
}

impl Flash {
    fn get_tempdir() -> TempDir {
        TempDir::new("portal-qemu-flash").expect("Couldn't create temporary directory")
    }

    fn get_temp_file() -> (PathBuf, TempDir) {
        let tempdir = Self::get_tempdir();
        (tempdir.path().join("flash.bin"), tempdir)
    }

    pub async fn load_from_file(path: &Path, allow_changes: bool) -> io::Result<Self> {
        if allow_changes {
            Ok(Flash {
                path: path.into(),
                _tmpdir: None,
            })
        } else {
            let (temp_path, tmpdir) = Self::get_temp_file();
            tokio::fs::copy(path, &temp_path).await?;
            Ok(Flash {
                path: temp_path,
                _tmpdir: Some(tmpdir),
            })
        }
    }

    pub async fn empty_temp_flash() -> io::Result<Self> {
        let (path, tempdir) = Self::get_temp_file();

        let mut flash = fs::File::create(&path).await?;
        flash.write_all(&vec![0x00u8; 2048 * 512]).await?;

        Ok(Flash {
            path,
            _tmpdir: Some(tempdir),
        })
    }

    pub async fn create_from_firmware(
        firmware_path: &Path,
        load_to_bank: usize,
    ) -> io::Result<Self> {
        let mut flash = Self::empty_temp_flash().await?;
        flash.write_firmware(firmware_path, load_to_bank).await?;

        Ok(flash)
    }

    pub async fn write_firmware(
        &mut self,
        firmware_path: &Path,
        load_to_bank: usize,
    ) -> io::Result<()> {
        let tempdir = self._tmpdir.get_or_insert_with(Self::get_tempdir);
        let bin_file = tempdir.path().join("firmware.bin");

        process::Command::new("arm-none-eabi-objcopy")
            .args(&[
                "-O",
                "binary",
                firmware_path.as_os_str().to_str().unwrap(),
                bin_file.as_os_str().to_str().unwrap(),
            ])
            .output()
            .await
            .expect("Unable to extract firmware binary");

        log::debug!("Extracted firmware binary to path {}", bin_file.display());

        let mut firmware_content = vec![];
        fs::File::open(&bin_file)
            .await?
            .read_to_end(&mut firmware_content)
            .await?;

        let mut flash = fs::File::options().write(true).open(&self.path).await?;
        if load_to_bank != 0 {
            flash.seek(SeekFrom::Start(2048 * 256)).await?;
        }
        flash.write_all(&firmware_content).await?;

        log::debug!(
            "Firmware loaded into bank {} of file {}",
            load_to_bank,
            self.path.display()
        );

        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}
