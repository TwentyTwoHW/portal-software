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

use alloc::rc::Rc;
use core::cell::RefCell;

use cortex_m::peripheral::NVIC;

use hal::flash::{self, Read, WriteErase};
use hal::i2c::{self, I2c};
use hal::prelude::*;
use hal::rcc::{Enable, MsiFreq};
use hal::{gpio, interrupt, rtc, stm32};

use rand::prelude::*;

#[cfg(feature = "device")]
use ssd1306::{mode::BufferedGraphicsMode, prelude::*, I2CDisplayInterface, Ssd1306};

use model::{Reply, Request};

pub mod nt3h;
pub mod tsc;

use nt3h::Nt3h;

use crate::checkpoint;
use crate::hw;

pub type AltOpenDrain<const A: u8> = gpio::Alternate<gpio::OpenDrain, A>;
pub type AltPushPull<const A: u8> = gpio::Alternate<gpio::PushPull, A>;
pub type FloatingInput = gpio::Input<gpio::Floating>;

pub use rtc::Rtc;

pub type ChannelSender<T> = rtic_sync::channel::Sender<'static, T, 1>;
pub type ChannelReceiver<T> = rtic_sync::channel::Receiver<'static, T, 1>;

pub const PAGE_SIZE: usize = 2048;
pub const MAX_FW_PAGES: usize = 508;

pub fn enable_debug_during_sleep(dp: &mut stm32::Peripherals) {
    // Allow debugging during sleep
    dp.DBGMCU.cr.modify(|_, w| {
        w.dbg_sleep().set_bit();
        w.dbg_standby().set_bit();
        w.dbg_stop().set_bit()
    });
    dp.RCC.ahb1enr.modify(|_, w| w.dma1en().set_bit());
}

// pub fn start_tsc_acquisition() {
//     free(|cs| {
//         let mut tsc = TSC.borrow(cs).borrow_mut();
//
//     });
// }

pub type Tsc = tsc::Tsc<gpio::gpiob::PB7<AltOpenDrain<9>>, gpio::gpiob::PB5<AltPushPull<9>>>;
pub type NfcIc = Nt3h<
    stm32::I2C1,
    (
        gpio::gpiob::PB8<AltOpenDrain<4>>,
        gpio::gpiob::PB9<AltOpenDrain<4>>,
    ),
>;
pub type Display = Ssd1306<
    I2CInterface<
        I2c<
            stm32::I2C2,
            (
                gpio::gpiob::PB13<AltOpenDrain<4>>,
                gpio::gpiob::PB14<AltOpenDrain<4>>,
            ),
        >,
    >,
    DisplaySize128x64,
    BufferedGraphicsMode<DisplaySize128x64>,
>;
pub type NfcInterrupt = nt3h::NfcInterrupt<gpio::gpioa::PA6<FloatingInput>>;

pub fn init_peripherals(
    mut dp: stm32::Peripherals,
    cp: cortex_m::Peripherals,
) -> Result<
    (
        NfcIc,
        NfcInterrupt,
        hw::ChannelReceiver<()>,
        Display,
        Tsc,
        rand_chacha::ChaCha20Rng,
        Flash,
        Rtc,
        bool,
    ),
    crate::Error,
> {
    let mut rcc = dp.RCC.constrain();
    let mut pwr = dp.PWR.constrain(&mut rcc.apb1r1);

    let mut gpioa = dp.GPIOA.split(&mut rcc.ahb2);
    let mut gpiob = dp.GPIOB.split(&mut rcc.ahb2);

    let rtc = rtc::Rtc::rtc(
        dp.RTC,
        &mut rcc.apb1r1,
        &mut rcc.bdcr,
        &mut pwr.cr1,
        rtc::RtcConfig::default(),
    );
    let fast_boot = rtc.read_backup_register(checkpoint::MAGIC_REGISTER) == Some(checkpoint::MAGIC);
    if !fast_boot {
        rtc.write_backup_register(checkpoint::MAGIC_REGISTER, checkpoint::MAGIC);
    }

    // Put display in RESET while we initialize stuff
    let mut display_reset = gpiob.pb12.into_push_pull_output_in_state(
        &mut gpiob.moder,
        &mut gpiob.otyper,
        PinState::High,
    );
    if !fast_boot {
        display_reset.set_low();
    }

    // Seed the RNG *before* we switch to LPR. LPR works at most with MSI 2MHz
    // and the PLL needs at least MSI 4MHz to work (which is the default after reset)
    let rng = {
        // Generate the 48MHz clock using PLL48M1CLK

        let rcc_reg = unsafe { &*hal::pac::RCC::ptr() };

        // Disable PLL
        rcc_reg.cr.modify(|_, w| w.pllon().clear_bit());
        while rcc_reg.cr.read().pllrdy().bit_is_set() {}

        rcc_reg.pllcfgr.modify(|_, w| unsafe {
            w.pllsrc()
                .bits(0b01) // Set source as MSI
                .pllm()
                .bits(0b000) // Set "M" divider to 1
                .pllq()
                .bits(0b00) // Set "Q" divider to 2
                .plln()
                .bits(24) // Set "N" multiplier to 24
        });

        // Enable PLL and wait
        rcc_reg.cr.modify(|_, w| w.pllon().set_bit());
        while rcc_reg.cr.read().pllrdy().bit_is_clear() {}

        // Enable PLL48M1CLK
        rcc_reg.pllcfgr.modify(|_, w| w.pllqen().set_bit());

        // Use PLL48M1CLK as 48MHz clock source
        rcc_reg
            .ccipr
            .modify(|_, w| unsafe { w.clk48sel().bits(0b10) });

        let clocks = unsafe { create_fake_clocks_with_hsi48_on() };

        let mut stm32_rng = dp.RNG.enable(&mut rcc.ahb2, clocks);

        let mut seed = [0u8; 32];
        stm32_rng.fill_bytes(&mut seed);

        hal::stm32::RNG::disable(&mut rcc.ahb2);

        // Disable PLL
        rcc_reg.cr.modify(|_, w| w.pllon().clear_bit());
        while rcc_reg.cr.read().pllrdy().bit_is_set() {}

        rand_chacha::ChaCha20Rng::from_seed(seed)
    };

    // Switch to MSI 24MHz
    let mut flash = dp.FLASH.constrain();
    let clocks = rcc
        .cfgr
        .msi(MsiFreq::RANGE24M)
        .freeze(&mut flash.acr, &mut pwr);

    let flash = Flash {
        parts: flash,
        fb_mode: dp.SYSCFG.memrmp.read().fb_mode().bit(),
    };

    // Init systick
    let systick_token = rtic_monotonics::create_systick_token!();
    rtic_monotonics::systick::Systick::start(cp.SYST, clocks.sysclk().raw(), systick_token);

    let scl =
        gpiob
            .pb8
            .into_alternate_open_drain(&mut gpiob.moder, &mut gpiob.otyper, &mut gpiob.afrh);

    let sda =
        gpiob
            .pb9
            .into_alternate_open_drain(&mut gpiob.moder, &mut gpiob.otyper, &mut gpiob.afrh);
    let i2c1 = I2c::i2c1(
        dp.I2C1,
        (scl, sda),
        i2c::Config::new(100.kHz(), clocks),
        &mut rcc.apb1r1,
    );
    let mut gpo = gpioa
        .pa6
        .into_floating_input(&mut gpioa.moder, &mut gpioa.pupdr);
    gpo.make_interrupt_source(&mut dp.SYSCFG, &mut rcc.apb2);
    gpo.enable_interrupt(&mut dp.EXTI);
    gpo.trigger_on_edge(&mut dp.EXTI, gpio::Edge::RisingFalling);
    let (nt3h, nfc_interrupt, nfc_finished) = Nt3h::new(i2c1, gpo)?;

    let scl =
        gpiob
            .pb13
            .into_alternate_open_drain(&mut gpiob.moder, &mut gpiob.otyper, &mut gpiob.afrh);
    let sda =
        gpiob
            .pb14
            .into_alternate_open_drain(&mut gpiob.moder, &mut gpiob.otyper, &mut gpiob.afrh);
    let i2c2 = I2c::i2c2(
        dp.I2C2,
        (scl, sda),
        i2c::Config::new(100.kHz(), clocks),
        &mut rcc.apb1r1,
    );

    let interface = I2CDisplayInterface::new(i2c2);

    display_reset.set_high();

    let mut display = Ssd1306::new(interface, DisplaySize128x64, DisplayRotation::Rotate180)
        .into_buffered_graphics_mode();
    if !fast_boot {
        display.init()?;
        display.set_brightness(Brightness::DIMMEST)?;
    } else {
        display.set_addr_mode(ssd1306::command::AddrMode::Horizontal)?;
    }

    let sample_pin =
        gpiob
            .pb7
            .into_alternate_open_drain(&mut gpiob.moder, &mut gpiob.otyper, &mut gpiob.afrl);
    let channel_pin =
        gpiob
            .pb5
            .into_alternate_push_pull(&mut gpiob.moder, &mut gpiob.otyper, &mut gpiob.afrl);

    let mut tsc = hal::tsc::Tsc::tsc(
        dp.TSC,
        sample_pin,
        &mut rcc.ahb1,
        Some(hal::tsc::Config {
            clock_prescale: Some(hal::tsc::ClockPrescaler::HclkDiv2),
            max_count_error: Some(hal::tsc::MaxCountError::U2047),
            charge_transfer_high: Some(hal::tsc::ChargeDischargeTime::C2),
            charge_transfer_low: Some(hal::tsc::ChargeDischargeTime::C2),
            spread_spectrum_deviation: None,
        }),
    );
    tsc.listen(hal::tsc::Event::EndOfAcquisition);

    let tsc = Tsc::new(tsc, channel_pin);

    Ok((
        nt3h,
        nfc_interrupt,
        nfc_finished,
        display,
        tsc,
        rng,
        flash,
        rtc,
        fast_boot,
    ))
}

pub struct Flash {
    pub parts: flash::Parts,
    pub fb_mode: bool,
}

pub fn read_flash<'b>(
    flash: &mut Flash,
    page: usize,
    buf: &'b mut [u8; 2048],
) -> Result<&'b [u8], FlashError> {
    let flash = &mut flash.parts;

    let prog = flash.keyr.unlock_flash(&mut flash.sr, &mut flash.cr)?;

    let page_to_read = flash::FlashPage(page).to_address();

    prog.read(page_to_read, buf);
    let len = u16::from_be_bytes(buf[..2].try_into().unwrap()) as usize;
    if len >= hw::PAGE_SIZE - 2 {
        return Err(FlashError::CorruptedData);
    }

    Ok(&buf[2..2 + len])
}

pub fn write_flash(flash: &mut Flash, page: usize, serialized: &[u8]) -> Result<(), FlashError> {
    let running_bank = match flash.fb_mode {
        true => hw::FlashBank::Bank2,
        false => hw::FlashBank::Bank1,
    };
    let erase_page = match running_bank {
        hw::FlashBank::Bank1 => page,
        hw::FlashBank::Bank2 => page + 256,
    };

    let flash = &mut flash.parts;
    let mut prog = flash.keyr.unlock_flash(&mut flash.sr, &mut flash.cr)?;

    if serialized.len() > super::hw::PAGE_SIZE - 2 {
        return Err(FlashError::CorruptedData);
    }

    let mut data = alloc::vec![];
    let len = (serialized.len() as u16).to_be_bytes();
    data.extend_from_slice(&len);
    data.extend(serialized);
    data.resize(super::hw::PAGE_SIZE, 0x00);

    prog.erase_page(flash::FlashPage(erase_page))?;
    let write_page = flash::FlashPage(page);
    prog.write(write_page.to_address(), &data)?;

    Ok(())
}

pub struct NfcChannelsLocal {
    pub outgoing: ChannelReceiver<Reply>,
    pub incoming: ChannelSender<Request>,
}
pub struct NfcChannelsShared {
    pub outgoing: ChannelSender<Reply>,
    pub incoming: ChannelReceiver<Request>,
}

pub fn make_nfc_channels() -> (NfcChannelsLocal, NfcChannelsShared) {
    let (request_sender, request_receiver) = rtic_sync::make_channel!(Request, 1);
    let (reply_sender, reply_receiver) = rtic_sync::make_channel!(Reply, 1);

    let local = NfcChannelsLocal {
        outgoing: reply_receiver,
        incoming: request_sender,
    };
    let shared = NfcChannelsShared {
        outgoing: reply_sender,
        incoming: request_receiver,
    };

    (local, shared)
}

pub struct TscEnable {
    bool_ref: Rc<RefCell<bool>>,
}

impl TscEnable {
    pub fn new(bool_ref: Rc<RefCell<bool>>) -> Self {
        TscEnable { bool_ref }
    }

    pub fn enable(&self) {
        *self.bool_ref.borrow_mut() = true;

        // Trigger interrupt
        #[cfg(feature = "device")]
        NVIC::pend(interrupt::TSC);
    }
    pub fn disable(&self) {
        *self.bool_ref.borrow_mut() = false;
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BankToFlash {
    pub physical: FlashBank,
}

impl BankToFlash {
    pub fn new(physical: FlashBank) -> Self {
        BankToFlash { physical }
    }

    pub fn physical_bank_page(bank: FlashBank, page: usize) -> flash::FlashPage {
        match bank {
            FlashBank::Bank1 => flash::FlashPage(page),
            FlashBank::Bank2 => flash::FlashPage(page + 256),
        }
    }

    pub fn get_logical_address(&self, which: BankStatus, page: usize) -> usize {
        let physical_bank = match which {
            BankStatus::Active => FlashBank::Bank1,
            BankStatus::Spare => FlashBank::Bank2,
        };
        Self::physical_bank_page(physical_bank, page).to_address()
    }

    pub fn get_physical_page(&self, which: BankStatus, page: usize) -> flash::FlashPage {
        let physical_bank = match which {
            BankStatus::Active => self.physical.opposite(),
            BankStatus::Spare => self.physical,
        };
        Self::physical_bank_page(physical_bank, page)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BankStatus {
    Active,
    Spare,
}

/// Flash bank to target for a read/write/erase operation
///
/// **NOTE**: unfortunately the meaning of `Bank1` and `Bank2` is not always consistent
/// in the code: specifically, when peforming an erase operation the `FlashBank` refers
/// to the actual physical bank being erased, no matter what bank is booted at the moment.
///
/// When performing a read or write operation `Bank1` refers to the currently-booted bank,
/// while `Bank2` refers to the spare bank. This is because the stm32l4xx-hal crate writes
/// directly to the flash memory address, and when using dual bank boot the "current bank"
/// is always mapped at 0x0000_0000 and 0x0800_0000, independently of which physical bank
/// is backing it.
///
/// A good rule of thumb is that when an API takes an address it uses the "relative",
/// mapping-dependent bank, while when it takes a `FlashPage` it's probably using absolute
/// addressing.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FlashBank {
    Bank1,
    Bank2,
}

impl FlashBank {
    pub fn opposite(&self) -> Self {
        match self {
            FlashBank::Bank1 => FlashBank::Bank2,
            FlashBank::Bank2 => FlashBank::Bank1,
        }
    }
}

#[derive(Debug)]
pub enum FlashError {
    CorruptedData,
    Deserialization,

    Flash(flash::Error),
}

impl From<minicbor::decode::Error> for FlashError {
    fn from(_: minicbor::decode::Error) -> Self {
        FlashError::Deserialization
    }
}
impl From<flash::Error> for FlashError {
    fn from(e: flash::Error) -> Self {
        FlashError::Flash(e)
    }
}

unsafe fn create_fake_clocks_with_hsi48_on() -> hal::rcc::Clocks {
    // TODO: try to get the offset of `hsi48` from the compiler instead of guessing it
    const SIZE: usize = core::mem::size_of::<hal::rcc::Clocks>();

    let mut data = [0u8; SIZE];
    for i in 0..SIZE {
        data[i] = 0xFF;
        let copy = core::mem::transmute_copy::<_, hal::rcc::Clocks>(&data);
        if copy.hsi48() {
            return copy;
        }
    }

    unreachable!()
}
