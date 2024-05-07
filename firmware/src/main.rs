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

#![no_std]
#![no_main]
#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

extern crate alloc;
extern crate cortex_m;

#[cfg(feature = "device")]
extern crate embedded_hal_02 as ehal;
#[cfg(feature = "emulator")]
extern crate embedded_hal_1 as ehal;

#[cfg(all(feature = "device", feature = "emulator"))]
compile_error!("Cannot enable both the `device` and `emulator` features at the same time");

#[cfg(feature = "emulator")]
extern crate stm32f4xx_hal as hal;
#[cfg(feature = "device")]
extern crate stm32l4xx_hal as hal;

#[cfg(feature = "device")]
mod config;
#[cfg(feature = "emulator")]
pub use emulator::config;
#[cfg(feature = "emulator")]
mod emulator;
mod error;
mod handlers;
#[cfg(feature = "device")]
mod hw;
mod hw_common;
mod version;
#[cfg(feature = "emulator")]
pub use emulator::*;

use core::cell::RefCell;
use core::mem::MaybeUninit;
use core::ops::DerefMut;

use embedded_alloc::Heap;

use rand::RngCore;

use futures::prelude::*;
use futures::{pin_mut, select_biased};

use rtic_monotonics::systick::ExtU32;

use crate::handlers::*;
pub use error::Error;
use model::*;

#[cfg(not(feature = "emulator-fast-ticks"))]
const TIMER_TICK_MILLIS: u32 = 500;
#[cfg(feature = "emulator-fast-ticks")]
const TIMER_TICK_MILLIS: u32 = 50;

// TODO: https://gist.github.com/andresv/d2d3a13402055d94fcb5f658dc190c1a

#[cfg(feature = "emulator")]
use cortex_m_log::{log::Logger, modes::InterruptFree, printer::semihosting::Semihosting};
#[cfg(feature = "emulator")]
type SemihostingLogger = Logger<Semihosting<InterruptFree, emulator::SemihostingConsole>>;
// #[cfg(feature = "emulator")]
// extern crate panic_semihosting;
#[cfg(feature = "emulator")]
static mut LOGGER: MaybeUninit<SemihostingLogger> = MaybeUninit::uninit();

#[global_allocator]
static HEAP: Heap = Heap::empty();

// #[cfg(feature = "device")]
// use panic_probe as _;

pub mod unified_hal {
    #[cfg(feature = "emulator")]
    pub use stm32f4xx_hal::pac::*;
    #[cfg(feature = "device")]
    pub use stm32l4xx_hal::pac::*;

    pub mod interrupt {
        #[cfg(feature = "emulator")]
        pub use stm32f4xx_hal::interrupt::*;
        #[cfg(feature = "emulator")]
        #[derive(Clone, Copy)]
        pub struct TSC;
        #[cfg(feature = "emulator")]
        unsafe impl cortex_m::interrupt::Nr for TSC {
            fn nr(&self) -> u8 {
                0
            }
        }

        #[cfg(feature = "device")]
        pub use stm32l4xx_hal::interrupt::*;
    }
}

pub struct KeyDebugWrapper(model::encryption::Sensitive<[u8; 32]>);

impl core::fmt::Debug for KeyDebugWrapper {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Sensitive<[u8; 32]>")
    }
}

#[rtic::app(device = unified_hal, peripherals = true, dispatchers = [CAN1_RX0, CAN1_RX1])]
mod app {
    use crate::hw_common::TscEnable;

    use super::*;

    #[shared]
    struct Shared {}

    #[local]
    struct Local {
        nfc: (hw::NfcIc, hw_common::NfcChannelsLocal),
        nfc_interrupt: hw::NfcInterrupt,
        tsc: (hw::Tsc, hw_common::ChannelSender<bool>),
        current_state: CurrentState,
        events: (
            RefCell<hw_common::ChannelReceiver<Request>>,
            RefCell<hw_common::ChannelReceiver<bool>>,
            RefCell<hw_common::ChannelReceiver<()>>,
        ),
        timer_sender: hw_common::ChannelSender<()>,
        peripherals: handlers::HandlerPeripherals,

        #[cfg(feature = "emulator")]
        emulator_channels: hw::EmulatorChannels,
    }

    #[init]
    fn init(cx: init::Context) -> (Shared, Local) {
        #[cfg(feature = "device")]
        rtt_log::init();
        #[cfg(feature = "emulator")]
        unsafe {
            let logger = Logger {
                inner: Semihosting::new(emulator::SemihostingConsole),
                level: log::LevelFilter::Trace,
            };
            *LOGGER.as_mut_ptr() = logger;
            let logger_ref = &*LOGGER.as_ptr();

            cortex_m_log::log::init(logger_ref).expect("To set logger");
        };

        log::info!("Hello, world!");

        // Initialize heap global allocator
        {
            const HEAP_SIZE: usize = 96 * 1024;
            #[link_section = ".heap"]
            static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
            unsafe { HEAP.init(HEAP_MEM.as_ptr() as usize, HEAP_SIZE) }
        }

        let cp = cx.core;
        let mut dp = cx.device;

        // #[cfg(debug_assertions)]
        hw::enable_debug_during_sleep(&mut dp);

        // TODO: move this somewhere else
        dp.RCC.apb2enr.write(|w| w.syscfgen().set_bit());

        #[allow(unused_mut)]
        let (mut nfc, nfc_interrupt, nfc_finished, display, tsc, mut rng, flash) =
            hw::init_peripherals(dp, cp).unwrap();

        let tsc_enabled = TscEnable::new(tsc.get_enabled_ref());

        type Empty = ();
        let (nfc_local, nfc_shared) = hw_common::make_nfc_channels();
        let (tsc_sender, tsc_receiver) = rtic_sync::make_channel!(bool, 1);
        let (timer_sender, timer_receiver) = rtic_sync::make_channel!(Empty, 1);

        let mut noise_rng = rng.clone();
        noise_rng.set_stream(0xFF);

        nfc_read_loop::spawn(noise_rng).unwrap();
        timer_ticking::spawn().unwrap();
        main_task::spawn().unwrap();

        #[cfg(feature = "emulator")]
        let emulator_channels = {
            use crate::hw::EmulatedNT3H;
            use rand::SeedableRng;

            let (flash_sender, flash_receiver) = rtic_sync::make_channel!(alloc::vec::Vec::<u8>, 1);
            flash.set_channel(flash_receiver);

            hw::report_finish_boot();

            // A bit hacky but at this point serial interrupts aren't setup yet so we have to wait for the entropy here
            loop {
                match crate::emulator::serial_interrupt() {
                    None => continue,
                    Some(val) => {
                        assert_eq!(val, crate::emulator::PeripheralIncomingMsg::Entropy);
                        break;
                    }
                }
            }
            let entropy = crate::emulator::read_serial();
            log::debug!("Seeding rng with {:02X?}", entropy);
            rng = rand_chacha::ChaCha20Rng::from_seed(entropy.try_into().unwrap());

            hw::EmulatorChannels {
                tsc: tsc_sender.clone(),
                emulated_nt3h: EmulatedNT3H::new(nfc_interrupt.clone(), &mut nfc),
                flash: flash_sender,
            }
        };

        (
            Shared {},
            Local {
                nfc: (nfc, nfc_local),
                nfc_interrupt,
                tsc: (tsc, tsc_sender),
                current_state: CurrentState::POR,
                events: (
                    RefCell::new(nfc_shared.incoming),
                    RefCell::new(tsc_receiver),
                    RefCell::new(timer_receiver),
                ),
                timer_sender,
                peripherals: HandlerPeripherals {
                    display,
                    rng,
                    flash,
                    nfc: nfc_shared.outgoing,
                    nfc_finished,
                    tsc_enabled,
                },

                #[cfg(feature = "emulator")]
                emulator_channels,
            },
        )
    }

    #[idle]
    fn idle(_: idle::Context) -> ! {
        loop {
            cortex_m::asm::wfi();
        }
    }

    #[task(priority = 1, local = [current_state, peripherals, events])]
    async fn main_task(cx: main_task::Context) {
        let stream = futures::stream::repeat(&cx.local.events);
        let stream = stream.then(|(nfc_incoming, last_tsc_read, timer)| async move {
            let mut nfc_incoming = nfc_incoming.borrow_mut();
            let mut last_tsc_read = last_tsc_read.borrow_mut();
            let mut timer = timer.borrow_mut();

            let input = last_tsc_read.recv().fuse();
            let request = nfc_incoming.recv().fuse();
            let timer = timer.recv().fuse();

            pin_mut!(input);
            pin_mut!(request);
            pin_mut!(timer);

            select_biased! {
                v = request => Event::Request(v.unwrap()),
                v = input => Event::Input(v.unwrap()),
                _ = timer => Event::Tick,
            }
        });

        pin_mut!(stream);

        loop {
            dispatch_handler(cx.local.current_state, &mut stream, cx.local.peripherals).await;
        }
    }

    #[task(priority = 2, local = [nfc])]
    async fn nfc_read_loop(cx: nfc_read_loop::Context, mut noise_rng: rand_chacha::ChaCha20Rng) {
        let (ref mut nfc, ref mut nfc_channels) = cx.local.nfc;

        nfc.apply_configuration()
            .await
            .expect("Initial config should work");

        loop {
            let (mut decrypt, mut encrypt) = loop {
                async fn do_handshake<R: RngCore>(
                    noise_rng: &mut R,
                    nfc: &mut hw::NfcIc,
                ) -> Result<
                    (
                        model::encryption::CipherState,
                        model::encryption::CipherState,
                    ),
                    Error,
                > {
                    log::info!("Starting Noise handshake...");

                    let mut ephemeral_key = model::encryption::wrap_sensitive([0; 32]);
                    noise_rng.fill_bytes(ephemeral_key.deref_mut());

                    let handshake_incoming = nfc.read_handshake().await?;
                    let mut handshake_state =
                        model::encryption::handhake_state_responder(ephemeral_key);
                    let _ = handshake_state
                        .read_message_vec(&handshake_incoming)
                        .map_err(|_| Error::HandshakeError)?;
                    let reply = handshake_state
                        .write_message_vec(&[])
                        .map_err(|_| Error::HandshakeError)?;
                    nfc.send_handshake_reply(&reply).await?;

                    if !handshake_state.completed() {
                        Err(Error::HandshakeError)
                    } else {
                        log::info!("Handshake completed");
                        Ok(handshake_state.get_ciphers())
                    }
                }

                match do_handshake(&mut noise_rng, nfc).await {
                    Ok(v) => break v,
                    Err(e) => {
                        log::warn!("Handshake error: {:?}", e);
                        continue;
                    }
                }
            };

            'inner: loop {
                let req = match nfc.accept_request(&mut decrypt).await {
                    Ok(req) => req,
                    Err(e) => {
                        // `accept_request` sends a special packet back to the RF side to
                        // let them know we couldn't decrypt the message, so we don't reply
                        // explicitly.

                        log::error!("Error reading request: {:?}", e);
                        break 'inner;
                    }
                };

                // Manage pings here transparently
                if let model::Request::Ping = req {
                    let reply = select_biased! {
                        reply = nfc_channels.outgoing.recv().fuse() => reply.expect("Receive should work"),
                        _ = rtic_monotonics::systick::Systick::delay(1000.millis()).fuse() => model::Reply::Pong,
                    };

                    if let Err(e) = nfc.send_reply(&reply, &mut encrypt).await {
                        log::error!("Error writing pong reply: {:?}", e);
                    }

                    continue 'inner;
                }

                nfc_channels
                    .incoming
                    .send(req)
                    .await
                    .expect("Send should work");
                let reply = nfc_channels
                    .outgoing
                    .recv()
                    .await
                    .expect("Receive should work");

                if let Err(e) = nfc.send_reply(&reply, &mut encrypt).await {
                    log::error!("Error writing reply: {:?}", e);
                }
            }
        }
    }

    #[task(priority = 2, local = [timer_sender])]
    async fn timer_ticking(cx: timer_ticking::Context) {
        loop {
            rtic_monotonics::systick::Systick::delay(TIMER_TICK_MILLIS.millis()).await;
            let _ = cx.local.timer_sender.try_send(());

            // Report the tick to the emulator to synchronize tests
            #[cfg(feature = "emulator")]
            hw::report_tick();

            #[cfg(feature = "trace_memory")]
            log::trace!("mem stats: {} used, {} free", HEAP.used(), HEAP.free());
        }
    }

    #[task(binds = USART1, local = [emulator_channels])]
    fn emulator_hook(_cx: emulator_hook::Context) {
        #[cfg(feature = "emulator")]
        match emulator::serial_interrupt() {
            Some(emulator::PeripheralIncomingMsg::Nfc) => {
                _cx.local.emulator_channels.emulated_nt3h.handle_cmd();
            }
            Some(emulator::PeripheralIncomingMsg::Tsc) => {
                let data = emulator::read_serial();
                let v = data[0] == 0x01;

                let _ = _cx.local.emulator_channels.tsc.try_send(v);
            }
            Some(emulator::PeripheralIncomingMsg::Reset) => {
                cortex_m::peripheral::SCB::sys_reset();
            }
            Some(emulator::PeripheralIncomingMsg::FlashContent) => {
                let data = emulator::read_serial();
                let _ = _cx.local.emulator_channels.flash.try_send(data);
            }
            _ => {}
        }
    }

    #[task(binds = EXTI9_5, local = [nfc_interrupt])]
    fn nfc_interrupt(_cx: nfc_interrupt::Context) {
        #[cfg(feature = "device")]
        {
            use hal::gpio::ExtiPin;

            _cx.local.nfc_interrupt.fd_pin.clear_interrupt_pending_bit();
            let _ = _cx.local.nfc_interrupt.sender.try_send(());
        }
    }

    #[task(binds = TSC, local = [tsc])]
    fn tsc_interrupt(_cx: tsc_interrupt::Context) {
        #[cfg(feature = "device")]
        {
            let (ref mut tsc, ref mut channel) = _cx.local.tsc;

            if tsc.is_enabled() {
                let _ = channel.try_send(tsc.perform_read());
                tsc.start_acquisition();
            }
        }
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    log::error!("PANIC LOCATION: {:?}", info.location());

    // NOTE: this adds a ton of extra code, probably to debug-format errors
    #[cfg(feature = "panic-log")]
    log::error!("PANIC: {:?}", info);

    #[cfg(feature = "emulator")]
    {
        cortex_m::peripheral::SCB::sys_reset();
    }

    #[cfg(not(feature = "emulator"))]
    loop {}
}
