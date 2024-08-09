use ssd1306::command;
use tokio::sync::Mutex;

pub type Column = [bool; 8];

pub struct Page {
    pub com: [Column; 128],
}

impl Default for Page {
    fn default() -> Self {
        let row = [false; 8];
        Page { com: [row; 128] }
    }
}

pub struct Bounds {
    start: usize,
    end: usize,
}

pub struct SRAM {
    pub col_addr: usize,
    pub page_addr: usize,
    pub page_bounds: Bounds,
    pub page: [Page; 8],
}

impl Default for SRAM {
    fn default() -> Self {
        SRAM {
            col_addr: 0,
            page_addr: 0,
            page_bounds: Bounds { start: 0, end: 8 },
            page: Default::default(),
        }
    }
}

const fn byte_to_bits(b: u8) -> [bool; 8] {
    let mut i = 0;
    let mut bits = [false; 8];
    loop {
        if i == 8 {
            break;
        }

        bits[i] = (b & (1 << i)) > 0;

        i += 1;
    }

    bits
}

impl SRAM {
    pub fn read_data(&mut self, data: &[u8]) -> bool {
        let mut reset = false;

        for byte in data {
            self.page[self.page_addr].com[self.col_addr] = byte_to_bits(*byte);
            self.col_addr += 1;
            if self.col_addr == 128 {
                self.col_addr = 0;
                self.page_addr += 1;
            }
            if self.page_addr == (self.page_bounds.end + 1) {
                self.page_addr = self.page_bounds.start;
                reset = true;
            }
        }

        reset
    }

    #[inline(always)]
    pub fn pixel(&self, page: usize, col: usize, pixel: usize) -> bool {
        self.page[page].com[col][pixel]
    }

    pub fn slice_pixels<'b>(&mut self, buf: &'b mut [(i32, i32); 128 * 64]) -> &'b [(i32, i32)] {
        let mut count = 0;

        for page in 0..8 {
            for column in 0..128 {
                for pixel in 0..8 {
                    if self.pixel(page, column, pixel) {
                        buf[count] = (column as i32, page as i32 * 8 + pixel as i32);
                        count += 1;
                    }
                }
            }
        }

        &buf[..count]
    }

    pub fn draw<S: SSD1306Surface>(
        &mut self,
        surface: &mut S,
    ) -> Result<(), <S as SSD1306Surface>::Error> {
        let mut buf = [(0, 0); 128 * 64];
        surface.draw_pixels(self.slice_pixels(&mut buf))
    }
}

pub struct CommandStream<R: tokio::io::AsyncRead>(pub R);

impl<R: tokio::io::AsyncRead + std::marker::Unpin> CommandStream<R> {
    pub async fn update_sram(&mut self, sram: &Mutex<SRAM>) -> tokio::io::Result<bool> {
        use tokio::io::AsyncReadExt;

        let mut data = [0; 16];
        self.0.read_exact(&mut data[..1]).await?;

        if data[0] == 0x00 {
            self.0.read_exact(&mut data[..1]).await?;

            if data[0] == 0x00 {
                return Ok(false);
            }
            let len = command::Command::command_len(data[0]);
            self.0.read_exact(&mut data[1..len]).await?;

            let (cmd, _) = command::Command::parse_next(&data);
            log::trace!("{:?}", cmd);
            if let command::Command::PageAddress(start, stop) = cmd {
                let mut lock = sram.lock().await;
                lock.page_addr = start as usize;
                lock.page_bounds.start = start as usize;
                lock.page_bounds.end = stop as usize;
            }
            if let command::Command::ColumnAddress(start, _) = cmd {
                sram.lock().await.col_addr = start as usize;
            }

            Ok(false)
        } else if data[0] == 0x40 {
            self.0.read_exact(&mut data[..16]).await?;

            let mut sram = sram.lock().await;
            Ok(sram.read_data(&data))
        } else {
            Ok(false)
        }
    }
}

pub trait ParseCommand: Sized {
    // Ignore error handling, panic on errors
    fn parse_next(data: &[u8]) -> (Self, &[u8]);

    fn command_len(byte: u8) -> usize;
}

impl ParseCommand for command::Command {
    fn parse_next(data: &[u8]) -> (Self, &[u8]) {
        use command::Command::*;

        match data[0] {
            0x81 => (Contrast(data[1]), &data[2..]),
            0xa4 | 0xa5 => (AllOn((data[0] & 1) > 0), &data[1..]),
            0xa6 | 0xa7 => (Invert((data[0] & 1) > 0), &data[1..]),
            0xae | 0xaf => (DisplayOn((data[0] & 1) > 0), &data[1..]),
            0x26..=0x2C | 0xA3 => unimplemented!("Scroll commands not supported"),
            0x2E | 0x2F => (EnableScroll(data[0] & 1 > 0), &data[1..]),
            0xF0..=0xFF | 0x10..=0x1F => unimplemented!("Col start commands not supported"),
            0x20 => {
                let mode = match data[1] {
                    0b00 => command::AddrMode::Horizontal,
                    0b01 => command::AddrMode::Vertical,
                    0b10 => command::AddrMode::Page,
                    _ => unimplemented!(),
                };
                (AddressMode(mode), &data[2..])
            }
            0x21 => (ColumnAddress(data[1], data[2]), &data[3..]),
            0x22 => (
                PageAddress(
                    command::Page::from(data[1] * 8),
                    command::Page::from(data[2] * 8),
                ),
                &data[3..],
            ),
            0xB0..=0xBF => (PageStart(command::Page::from(data[0] & 0xF)), &data[1..]),
            0x40..=0x7F => (StartLine(data[0] & 0x3F), &data[1..]),
            0xA0 | 0xA1 => (SegmentRemap((data[0] & 1) > 0), &data[1..]),
            0xA8 => (Multiplex(data[1]), &data[2..]),
            0xC0 | 0xC8 => (ReverseComDir((data[0] & (1 << 3)) > 0), &data[1..]),
            0xD3 => (DisplayOffset(data[1]), &data[2..]),
            0xDA => (
                ComPinConfig((data[1] & (1 << 4)) > 0, (data[1] & (1 << 5)) > 0),
                &data[2..],
            ),
            0xD5 => (
                DisplayClockDiv((data[1] & 0xF0) >> 4, data[1] & 0xF),
                &data[2..],
            ),
            0xD9 => (
                PreChargePeriod(data[1] & 0xF, (data[1] & 0xF0) >> 4),
                &data[2..],
            ),
            0xDB => {
                let level = match data[1] >> 4 {
                    0b001 => command::VcomhLevel::V065,
                    0b010 => command::VcomhLevel::V077,
                    0b011 => command::VcomhLevel::V083,
                    0b100 => command::VcomhLevel::Auto,
                    _ => unimplemented!("Invalid level"),
                };
                (VcomhDeselect(level), &data[2..])
            }
            0xE3 => (Noop, &data[1..]),
            0x8D => (ChargePump((data[1] & (1 << 2)) > 0), &data[2..]),
            0xAD => (
                InternalIref((data[1] & (1 << 4)) > 0, (data[1] & (1 << 5)) > 0),
                &data[2..],
            ),

            _ => unimplemented!("Invalid command"),
        }
    }

    fn command_len(byte: u8) -> usize {
        match byte {
            0x81 => 2,
            0xa4 | 0xa5 => 1,
            0xa6 | 0xa7 => 1,
            0xae | 0xaf => 1,
            0x26..=0x2C | 0xA3 => unimplemented!("Scroll commands not supported"),
            0x2E | 0x2F => 1,
            0xF0..=0xFF | 0x10..=0x1F => unimplemented!("Col start commands not supported"),
            0x20 => 2,
            0x21 => 3,
            0x22 => 3,
            0xB0..=0xBF => 1,
            0x40..=0x7F => 1,
            0xA0 | 0xA1 => 1,
            0xA8 => 2,
            0xC0 | 0xC8 => 1,
            0xD3 => 2,
            0xDA => 2,
            0xD5 => 2,
            0xD9 => 2,
            0xDB => 2,
            0xE3 => 1,
            0x8D => 2,
            0xAD => 2,

            _ => unimplemented!("Invalid command"),
        }
    }
}

pub trait SSD1306Surface {
    type Error;

    fn draw_pixels(&mut self, pixels: &[(i32, i32)]) -> Result<(), Self::Error>;
}

#[cfg(feature = "sdl")]
use sdl2::render::{Canvas, RenderTarget};
#[cfg(feature = "sdl")]
impl<T: RenderTarget> SSD1306Surface for Canvas<T> {
    type Error = String;

    fn draw_pixels(&mut self, pixels: &[(i32, i32)]) -> Result<(), Self::Error> {
        self.set_draw_color(sdl2::pixels::Color::BLACK);
        self.clear();
        self.set_draw_color(sdl2::pixels::Color::WHITE);

        for (x, y) in pixels {
            self.draw_point((*x, *y))?;
        }

        Ok(())
    }
}

#[cfg(feature = "eg-simulator")]
impl SSD1306Surface
    for embedded_graphics_simulator::SimulatorDisplay<embedded_graphics::pixelcolor::BinaryColor>
{
    type Error = String;

    fn draw_pixels(&mut self, pixels: &[(i32, i32)]) -> Result<(), Self::Error> {
        use embedded_graphics::pixelcolor::BinaryColor;
        use embedded_graphics::prelude::*;
        use embedded_graphics::primitives::{PrimitiveStyle, Rectangle};

        let on_style = PrimitiveStyle::with_fill(BinaryColor::On);
        let off_style = PrimitiveStyle::with_fill(BinaryColor::Off);

        Rectangle::new(Point::new(0, 0), Size::new(128, 64))
            .into_styled(off_style)
            .draw(self)
            .map_err(|e| e.to_string())?;

        for (x, y) in pixels {
            Rectangle::new(Point::new(*x, *y), Size::new(1, 1))
                .into_styled(on_style)
                .draw(self)
                .map_err(|e| e.to_string())?;
        }

        Ok(())
    }
}
