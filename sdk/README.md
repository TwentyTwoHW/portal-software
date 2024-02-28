# SDK

The goal of the SDK is to provide a very simple interface for our downstream users, in multiple languages through uniffi bindings.

## Architecture

The SDK is divided into a `CardManager`, which is not exposed to the final user and implements the low-level functionality of the protocol, and a `PortalSdk` which is what the user will need to interface with.

The user only needs to implement the code required to receive and send raw (byte arrays) messages from/to the NFC card. This could be done in many different ways depending on the specific platform: in this repo an example implementation uses libnfc, which should work on all common desktop platforms.

Afterwards, the user will need to spawn a thread* which repeatedly calls `sdk.wait()` in a loop: this method will return an `Option<NfcOut>`, which tells the user whether there's a command to send via NFC: The `Transceive` variant means that the user should send the message and expect a reply from the card (which he should then give to the sdk with `sdk.push_incoming(data)`). The `Send` variant means that the user should just send the data via NFC.

Calling `wait()` repeatedly will drive the internal state machine and drive the communication with the NFC card, so it's very important to always keep doing that.

`PortalSdk` exposes methods to send commands to the card, like `get_status()` to get the device status, `generate_mnemonic(num_words)` to make the device generate a new mnemonic, etc. Since the `PortalSdk` structure is thread-safe, these calls could be made from any other thread, while the main loop keeps calling `wait()`.

\* Note that it's not actually strictly required to spawn a new thread, although it makes the code easier to manage. It's technically possible to interleave calls to `wait()` with calls to all the other methods of `PortalSdk` in the same thread.

## CLI

This crate also has a binary target that uses `libnfc` to connect to a supported NFC reader and talk to the portal. To try it out use the following command:

```
cargo run --features=libnfc --bin=cli
```