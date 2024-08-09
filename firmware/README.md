# firmware

This directory contains the source code of the firmware: it's entirely written in Rust and designed to work on the STM32L476 MCU.

## Hardware Components

The card is built with the following components:

- STM32L476 ARM MCU
- NXP NT3H2111 ISO14443A NFC IC
- SSD1306 128x64 OLED Display
- A small capacitive touch button (driven by the TSC controller of the STM32)

When emulated, only the MCU is actually "emulated", while all the other peripherals are implemented externally in the `emulator` binary (more details in the emulator README).

## Code Overview

The firmware is built on the [rtic.rs](https://rtic.rs) framework: it's designed to be "asynchronous" as much as possible, i.e. driven by software and hardware interrupts, so that the CPU can go to sleep while waiting for something to happen.

There are essentially three interrupt sources that can wake up the CPU and trigger something to happen:

- An internal timer that ticks periodically (currently every 500ms)
- A new measurement of the TSC (Touch Sense Controller) button - either a "true" reading (the button is being pressed) or a "false" reading (not pressed)
- A new message from the NFC IC

These three sources of interrupts are modeled as Rust async `Stream`s, and merged together in a single stream of `Event` enums (see the `main_task` in `main.rs`). This stream is then fed to the specific handler based on whatever `CurrentState` the device is in. The handler returns the new state once finished, and the loop repeats.

### Handlers

The handlers are implemented in the `handlers` module: in the `mod.rs` file there's the main "entry point" (`dispatch_handler`), which will check the current state, run the correct handler, and update the state afterwards. Some utilities functions are present in this module, and they are available to all the handler functions to manage the event stream and more.

When writing new handlers always make sure to add them to the main `match` clause in `dispatch_handler`, otherwise they will never run.

### Hardware

The `hw` module contains the code to initialize all the hardware peripherals, and exposes a "high level" interface to communicate with them (for example, to send a message via NFC or to draw something to the display).

The real hardware initialization sequence is the following:

1. Enable the `PLL48M1CLK` by configuring the PLL to source the `MSI` clock (set at 4MHz at boot), with a `Q` divider of `2` and an `N` multiplier of `24`. This produces a 48MHz internal clock, which we can feed to the `TRNG` section of the MCU.
2. Once the `TRNG` is stabilized we use it to produce 32 bytes of entropy, which will seed a `ChaCha20` RNG.
3. After seeding the RNG we disable the `TRNG`, disable the PLL and lower the `MSI` clock to 2MHz, which is the highest clock allowed in `LPR` (low-power-run) mode, which we enable immediately afterwards.
4. Then we initialize `I2C1` which is connected to the NFC IC, together with PA6 which is connected to the interrupt line
5. Then we initialize `I2C2` which is connected to the display, together with PC13 which is connected to the `RESET` line of the display, and is quickly pulled low and then back high to power cycle the controller.
6. Finally we initialize the `TSC` using pin PB7 for sampling and pin PB5 as the "channel" pin. We also tie PC6 to low with an internall pull-down resistor, to tie the shield area to ground.

### Persistent Configuration

The `config` module contains code to write a persistent configuration to the internal STM32 flash.

The STM32L476 has a total of 1024K bytes of flash, which is divided in two 512K banks to allow for safe firmware updates (if the newly flashed firmware is corrupted the bootloader will simply boot the previous version still present in the other bank).

We also reserve 2K at the end of each bank for the configuration page, which leaves 510K free for the whole firmware binary.

### Logging

When running in the emulator we use the ARM Semihosting feature to print logs: we actually use a custom implementation that logs with the `SYS_WRITEC` syscall, so that the output goes to the "console" rather than "stdout" (as it normally does when written with `SYS_OPEN`/`SYS_WRITE`). The main difference is that when writing to stdout QEMU also writes the output to stdout, with no way to redirect the logs anywhere except with convoluted shell pipelines. When logging to "console" instead, we can use the `--semihosting-config` flag to redirect the output somewhere else, which allows us to capture it when running the emulator.

When running on the real hardware we use [RTT](https://github.com/probe-rs/rtt-target) (Real Time Transfer), which makes it much faster than using Semihosting through a debug probe.