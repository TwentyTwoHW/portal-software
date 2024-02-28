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

extern crate proc_macro;
use proc_macro::TokenStream;

use std::process::Command;

fn get_hash() -> Option<String> {
    let stdout = Command::new("git")
        .args(&["rev-parse", "--short=8", "HEAD"])
        .output()
        .ok()?
        .stdout;
    let hash = String::from_utf8(stdout).ok()?.trim().to_owned();
    Some(hash)
}

fn is_clean() -> Option<bool> {
    Some(
        Command::new("git")
            .args(&["diff-index", "--quiet", "HEAD"])
            .output()
            .ok()?
            .status
            .success(),
    )
}

#[proc_macro]
pub fn fetch_git_hash(_item: TokenStream) -> TokenStream {
    let dirty = if is_clean().unwrap_or(true) {
        ""
    } else {
        "-dirty"
    };
    format!("\"{}{}\"", get_hash().unwrap_or("unknown".into()), dirty)
        .parse()
        .unwrap()
}
