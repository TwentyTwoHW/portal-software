# emulator

This directory contains the code for the binary that emulates the hardware peripherals of the Portal: while the CPU itself is emulated by QEMU, the display, NFC IC and touch sensitive button are emulated by this binary and the events sent to QEMU via a serial interface.

## Docker Image

If you'd like to play with the emulator without rebuilding everything from scratch you can use our Docker image: it contains a pre-build emulator and firmware, plus all the required dependencies. It spawns the emulator in a virtual X environment, which is then exposed via VNC or from a web client.

To run the emulator pull the image and start it as follows:

```
docker image pull afilini/portal-emulator:latest
docker run -it --publish 2222:2222 --publish 5900:5900 --rm afilini/portal-emulator:latest
```

### Run a custom firmware

Using the Docker image you can also run a custom firmware file by changing the command slightly so that it loads the firmware from a different path. You can then mount a local `target` directory which is written to by the dockerized development environment. For more details checkout the README at the root of this project.

## Protocol

When running in the emulator the firmware opens the `UART1` port and uses that as a communication channel with this binary.

The embedde firmware sends over serial messages of type `CardMessage` (defined in the `model` crate). Essentially it can send:

1. A new frame to display to the simulated screen. This is sent as a stream of pixel coordinates and pixel color ("on" or "off").
2. An NFC response to a command
3. Whenever a `Tick` of the periodic timer happens (this is sometimes used to synchronize the tests, instead of using the clock time - useful if a debugger is attached!).
4. Requests to read or write the flash
5. A notification that the boot has finished
6. A notification that the current display content has been completely flushed (this is also used to synchronize the tests)

The host side sends messages of type `EmulatorMessage`, so either:

1. A `Tsc` (touch sense controller) measurement - either `true` if the button is pressed or `false` if it isn't.
2. A NFC command that will be processed by the emulated NT3H21111
3. A `Reset` signal to reset the CPU.
4. A `FlashContent` message in response to a `ReadFlash` request

### Encoding

The messages are encoded as a stream of bytes in the form: `<prefix byte> <optional u16 big-endian len> <message bytes...>`.

The prefixes used are:

- `0x00` for a `CardMessage::Display` message
- `0x01` for a `CardMessage::Nfc` message
- `0x02` for a `CardMessage::Tick` message
- `0x03` for a `CardMessage::WriteFlash` message
- `0x04` for a `CardMessage::ReadFlash` message
- `0x05` for a `CardMessage::FinishBoot` message
- `0x06` for a `CardMessage::FlushDisplay` message

- `0x01` for an `EmulatorMessage::Tsc` message
- `0x02` for an `EmulatorMessage::Nfc` message
- `0x03` for an `EmulatorMessage::FlashContent` message
- `0x04` for an `EmulatorMessage::Reset` message

## Command Line Options

```
Usage: emulator [OPTIONS]

Options:
  -s, --emulator-socket <EMULATOR_SOCKET>
          Path for the UNIX socket of QEMU's serial port
          
          Used only when `--no-auto-qemu` is enabled, otherwise an instance of QEMU is spawned internall
          
          [default: ./firmware/serial1.socket]

  -f, --firmware <FIRMWARE>
          Path of the firmware ELF file
          
          Used when spawning a QEMU instance internally
          
          [default: ./firmware/target/thumbv7em-none-eabihf/debug/firmware]

      --no-auto-qemu
          Do not launch QEMU internally
          
          This will make the emulator connect to the UNIX socket specified with `--emulator-socket`

  -j, --join-logs
          Whether to print emulated firmware logs to the emulator's stderr
          
          This only has an effect when spawning QEMU internally

      --no-cargo-build
          Do not recompile the firmware
          
          By default the emulator always tries to run `cargo build` in the `--firmware-src-directory` dir before launching QEMU

      --firmware-src-directory <FIRMWARE_SRC_DIRECTORY>
          Directory containing the firmware source code
          
          The emulator runs `cargo build` in this directory, unless `--no-cargo-build` is specified
          
          [default: ./firmware/]

      --listen-gdb <LISTEN_GDB>
          Port to bind the GDB server to
          
          Only used when QEMU is spawned internally

      --wait-gdb
          Whether to wait for GDB to attach before running the firmware
          
          Only used when QEMU is spawned internally for a gui session with GDB enabled (--listen-gdb).

      --flash-file <FLASH_FILE>
          File backing the flash memory
          
          If unspecified the flash data will only be kept in memory temporarily.

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

## Development GUI

When started as a binary the emulator will launch a GUI built on FLTK (which you will have to install to be able to compile the project with the `gui` feature enabled). The GUI will be "attached" to the QEMU instance, either to an instance already running (if `--no-auto-qemu` is enabled), or to a freshly spawned emulator (specify `--join-logs` to see the firmware logs in the terminal that spawned the GUI). The `--flash-file` option can be used to specify a file backing the device's flash memory, which stores the seed and user preferences.

From the GUI you can see the display, send button inputs (by clicking/releasing on the display area) and NFC messages, using the provided buttons.

At the bottom of the window there's a log with all the events sent/received by the GUI (with the exception of the `CardMessage::Tick` messages because they come in pretty often).

<p align="center"><img src="screenshots/gui.png" width="30%" /></p>

## Tests

You can run the functional tests for the firmware by simply running `cargo test` on this package. The tests are defined in `./src/tests` and will run in parallel according to the flags specified by Cargo.