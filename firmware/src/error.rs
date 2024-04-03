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

use hal::i2c;

use crate::config;

#[derive(Debug)]
pub enum Error {
    InvalidPassword,

    LostRf,

    TooManyNacks,

    HandshakeError,
    BrokenProtocol,
    InvalidFirmware,

    Wallet,
    Unknown,

    FlashError,
    I2c(i2c::Error),
    // State(state::StateError),
    Config(config::ConfigError),
    Message(model::MessageError),
    Display(display_interface::DisplayError),
}

impl From<i2c::Error> for Error {
    fn from(e: i2c::Error) -> Self {
        Error::I2c(e)
    }
}
// impl From<state::StateError> for Error {
//     fn from(e: state::StateError) -> Self {
//         Error::State(e)
//     }
// }
impl From<config::ConfigError> for Error {
    fn from(e: config::ConfigError) -> Self {
        Error::Config(e)
    }
}
impl From<model::MessageError> for Error {
    fn from(e: model::MessageError) -> Self {
        Error::Message(e)
    }
}
impl From<display_interface::DisplayError> for Error {
    fn from(e: display_interface::DisplayError) -> Self {
        Error::Display(e)
    }
}
impl From<bdk::descriptor::DescriptorError> for Error {
    fn from(_: bdk::descriptor::DescriptorError) -> Self {
        Error::Wallet
    }
}
impl<T> From<bdk::wallet::NewError<T>> for Error {
    fn from(_: bdk::wallet::NewError<T>) -> Self {
        Error::Wallet
    }
}
