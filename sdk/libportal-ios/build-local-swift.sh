#!/bin/bash
# This script builds local Swift language bindings and corresponding portalFFI.xcframework.
# The results of this script can be used for locally testing your SPM package adding a local package
# to your application pointing at the libportal-ios directory.

set -xeo pipefail

# Run the script from the libportal-ios root directory, ie: ./build-local-swift.sh

# rustup install 1.73.0
# rustup component add rust-src
# rustup target add aarch64-apple-ios      # iOS ARM64
# rustup target add x86_64-apple-ios       # iOS x86_64
# rustup target add aarch64-apple-ios-sim  # simulator mac M1

mkdir -p ./Sources/LibPortal

pushd ../

cargo build --features ios,bindings --release --target aarch64-apple-ios
cargo build --features ios,bindings --release --target x86_64-apple-ios
cargo build --features ios,bindings --release --target aarch64-apple-ios-sim

cargo run --bin uniffi-bindgen --features bindings generate --library ../target/aarch64-apple-ios-sim/release/libportal.a --out-dir ./libportal-ios/Sources/LibPortal --language swift --no-format

mkdir -p ../target/lipo-ios-sim/release
lipo ../target/aarch64-apple-ios-sim/release/libportal.a ../target/x86_64-apple-ios/release/libportal.a -create -output ../target/lipo-ios-sim/release/libportal.a

popd

mv Sources/LibPortal/portal.swift Sources/LibPortal/LibPortal.swift
cp Sources/LibPortal/portalFFI.h portalFFI.xcframework/ios-arm64/portalFFI.framework/Headers
cp Sources/LibPortal/portalFFI.h portalFFI.xcframework/ios-arm64_x86_64-simulator/portalFFI.framework/Headers
cp ../../target/aarch64-apple-ios/release/libportal.a portalFFI.xcframework/ios-arm64/portalFFI.framework/portalFFI
cp ../../target/lipo-ios-sim/release/libportal.a portalFFI.xcframework/ios-arm64_x86_64-simulator/portalFFI.framework/portalFFI
rm Sources/LibPortal/portalFFI.h
rm Sources/LibPortal/portalFFI.modulemap

PACKAGE=${PACKAGE-'0'}
if [ "$PACKAGE" -eq '1' ]; then
  find ./portalFFI.xcframework -name ".DS_Store" -exec rm {} \; 
  rm portalFFI.xcframework.zip || true
  zip -9 -r portalFFI.xcframework.zip portalFFI.xcframework
fi
