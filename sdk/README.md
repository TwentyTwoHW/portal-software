# SDK

The goal of the SDK is to provide a very simple interface for our downstream users, in multiple languages through uniffi bindings.

## Architecture

The SDK is divided into a `CardManager`, which is not exposed to the final user and implements the low-level functionality of the protocol, and a `PortalSdk` which is what the user will need to interface with.

The user only needs to implement the code required to receive and send raw (byte arrays) messages from/to the NFC card. This could be done in many different ways depending on the specific platform: in this repo an example implementation uses libnfc, which should work on all common desktop platforms.

Afterwards, the user will need to spawn a task which repeatedly calls `sdk.poll()` in a loop: this method will return an `NfcOut` struct, which is composed of a byte array message and a numeric message id. The message should be sent via NFC and then the reply provided back to the library with `sdk.incoming_data()`.

`PortalSdk` exposes methods to send commands to the card, like `get_status()` to get the device status, `generate_mnemonic(num_words)` to make the device generate a new mnemonic, etc. Since the `PortalSdk` structure is thread-safe, these calls could be made from any other task or thread, while the main task keeps calling `poll()`.

## CLI

This crate also has a binary target that uses `libnfc` to connect to a supported NFC reader and talk to the portal. To try it out use the following command:

```
cargo run --features=libnfc --bin=cli
```
