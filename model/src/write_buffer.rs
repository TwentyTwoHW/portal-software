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

use crate::MessageFragment;

pub struct WriteBuffer<const DATA_LEN: usize, const NUM_BUFS: usize, const PREFIX_LEN: usize> {
    _prefix: [u8; PREFIX_LEN],
    buffer: [[u8; DATA_LEN]; NUM_BUFS],
    cursor: usize,
}

impl<const DATA_LEN: usize, const NUM_BUFS: usize, const PREFIX_LEN: usize>
    WriteBuffer<DATA_LEN, NUM_BUFS, PREFIX_LEN>
{
    pub fn append(&mut self, fragment: &MessageFragment) {
        let mut data_iter = fragment.get_filled_data().iter();

        for i in 0usize..NUM_BUFS {
            let left = (DATA_LEN * (i + 1)).saturating_sub(self.cursor);
            for b in data_iter.by_ref().take(left) {
                self.buffer[i][self.cursor % DATA_LEN] = *b;
                self.cursor += 1;
            }

            if self.cursor % DATA_LEN == 0 {
                // Skip the prefix + the address byte
                self.cursor += PREFIX_LEN + 1;
            }
        }
    }

    pub fn get_data(&self) -> impl Iterator<Item = &[u8; DATA_LEN]> {
        // Take as many buffers as necessary plus the last one which is the terminator
        // and always needs to be written to complete the transaction

        let take = self.cursor / DATA_LEN + 1;

        self.buffer
            .iter()
            .enumerate()
            .filter_map(move |(i, b)| match i {
                i if i < take || i == NUM_BUFS - 1 => Some(b),
                _ => None,
            })
    }
}

pub trait WriteBufferInit<const DATA_LEN: usize, const NUM_BUFS: usize, const PREFIX_LEN: usize> {
    fn new() -> WriteBuffer<DATA_LEN, NUM_BUFS, PREFIX_LEN>;

    fn init_fields(
        buffer: [[u8; DATA_LEN]; NUM_BUFS],
    ) -> WriteBuffer<DATA_LEN, NUM_BUFS, PREFIX_LEN> {
        WriteBuffer {
            _prefix: [0; PREFIX_LEN],
            buffer,
            cursor: 1 + PREFIX_LEN,
        }
    }
}
