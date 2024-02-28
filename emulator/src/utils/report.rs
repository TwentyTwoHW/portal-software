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

use std::fs::File;
use std::path::Path;

use handlebars::Handlebars;

pub const HB_TEMPLATE: &'static str = include_str!("../../report.hb");

pub fn render_report(to: &Path, log: &super::model::TestLog) -> Result<(), crate::Error> {
    let mut hb = Handlebars::new();
    hb.register_template_string("report", HB_TEMPLATE)?;

    let writer = File::create(to)?;
    hb.render_to_write("report", log, writer)?;

    log::info!("Rendered report to: {}", to.display());

    Ok(())
}
