#!/usr/bin/env bash

set -xeo pipefail

BASE_DIR=$(dirname -- "$(readlink -f -- "$BASH_SOURCE")")
VERSION=$(cat "$BASE_DIR/../Cargo.toml" | grep "^version" | awk '{ print $3 }' | tr -d '"')
VERSION_HEX=$(echo "$VERSION" | awk -F. '{ print $3 + $2 * 100 + $1 * 100**2}' | xargs printf "%08X00") # hardcoded to variant 0x00 (last byte)

arm-none-eabi-objcopy -O binary "$BASE_DIR/../target/thumbv7em-none-eabihf/release/firmware" /dev/shm/fw.bin
echo -n "$VERSION_HEX" | xxd -r -p >> /dev/shm/fw.bin
hal key schnorr-sign $(cat "$BASE_DIR/../../../FW_SIGNING_KEY") $(cat /dev/shm/fw.bin | sha256sum | awk '{ print $1 }') | xxd -r -p > /dev/shm/fw-signed.bin && cat /dev/shm/fw.bin >> /dev/shm/fw-signed.bin
