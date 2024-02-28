# portal-software

This repository contains the source code for all the software components of the Portal. It's composed of a workspace, plus a separate project (the `firmware`) since at the time of writing `cargo` doesn't really like having projects with different targets in the same workspace.

The [`firmware`](./firmware) directory contains the source code of the firmware itself. The firmware depends on both the `gui` and `model` crates from the main workspace.

The workspace contains the following crates:

* [`emulator`](./emulator): The emulator is a binary that can connect to a QEMU instance emulating the firmware and act as either a development UI (emulating display, buttons, etc) or a headless test runner. All the tests for the firmware are actually contained in this crate, in the `tests/` subdirectory.
* [`gui`](./gui): The GUI crate contains the implementation of the UI for the Portal. It's based on the `embedded-graphics` crate, and it also contains a small binary called `simulator` that allows rendering the UI screens on a computer (useful for iterating quickly!).
* [`model`](./model): The model crate contains the definition of all the structs that are sent/received by the Portal in a single package that can be used on both the embedded and host side.
* [`sdk`](./sdk): The SDK crate implements the communication protocol with the Portal from the host side. It also include an example cli that uses `libnfc`, so any reader supported by the library should work with it.

There are also a few supporting, secondary crates:
* [`functional-test-wrapper`](./functional-test-wrapper/): This crate implements a very simple proc-macro to wrap the functional tests for the firmware with all the scaffolding required.
* [`fetch-git-hash`](./fetch-git-hash/): This crate is a very simple proc-macro that expands to the current git hash. It can be used to embed the git hash anywhere in the firmware or SDK.
* [`dummy-uniffi`](./dummy-uniffi/): This is a crate we need to make the compiler happy when building the SDK *without* the bindings enabled.

## Getting Started

To get started you can try running the firmware on the emulator. You should check the documentation under the [`emulator`](./emulator) directory for all the details, but if you have all the required dependencies installed it should be as easy as running:

```
cargo emu-dev
```

from the root directory of the project (this is very important because relative paths are used throughout the codebase!).

This command should first compile the emulator, then the firmware, and then launch a QEMU instance and attach the development GUI to it.

The dependencies you'll need are:

* **nightly** `cargo` with both the native (local) and `thumbv7em-none-eabihf` targets installed
* The C toolchain for ARM-v7 (`arm-none-eabi-*`)
* `qemu-system-arm` to emulate the firmware
* FLTK to run the emulator GUI
* SDL2 to run the GUI simulator (`cargo gui-sim`)
* `probe-run` to flash the firmware to a physical card

If you have NixOS or the nix package manager installed you can get a shell with everything installed by running `nix-shell` in the root directory of the project.

### Running the Tests

To run the integration tests you can use the command:

```
cargo emu-test
```

This will compile emulator and firmware (if it hasn't been done yet) and then run the tests defined in [`emulator/src/tests`](./emulator/src/tests). In case of failure it will also create a "report" HTML file that can be inspected in a browser to figure out exactly what went wrong to cause the test to fail.

## Building the mobile bindings

### Android

#### Setup

To build the Android bindings first load the nix shell with the `fullAndroid` option enabled. From the root of the project execute:

```
nix-shell --arg fullAndroid true
```

Alternatively you can install manually Rust with a tool like rustup, plus the following targets and `cargo-ndk`:

```
rustup target add \
    aarch64-linux-android \
    armv7-linux-androideabi \
    x86_64-linux-android \
    i686-linux-android

cargo install cargo-ndk
```

##### Build

Build the library and publish it to the local Maven repo using the following command:

```
cd ./sdk/libportal-android
./gradlew publishToMavenLocal --exclude-task signMavenPublication
```

##### Use

To use the library simply include it in your gradle build file:

```kotlin
repositories {
    mavenLocal()
}

dependencies { 
    implementation("xyz.twenty_two:libportal-android:<version>")
}
```

### iOS

To build the iOS bindings load the nix shell with the `withIos` option enabled. From the root of the project execute:

```
nix-shell --arg withIos true
```

Alternatively you can install manually Rust with a tool like rustup, plus the following targets:

```
rustup target add \
    aarch64-apple-ios \
    aarch64-apple-ios-sim \
    x86_64-apple-ios
```

##### Build

Build the library using the following script:

```
cd ./sdk/libportal-ios
./build-local-swift.sh
```

##### Use

To use the library include the `libportal-ios` folder as a package dependency. Once this is done you should be able to add the `LibPortal` library using Xcode. Click on the `+` button to add a new framework/library and search for `LibPortal`, which should appear under the `libportal-ios` package. 

## React Native

A React Native module is available at `./sdk/libportal-react-native`. It depends on the native Kotlin and Swift libraries, so you should build these two first.

## Licensing

This project is licensed under GPL 3.0 or later. You can find a full copy of the license in the LICENSE file. For any questions regarding derivative work you can contact us
at [contact@twenty-two.xyz](mailto:contact@twenty-two.xyz)
