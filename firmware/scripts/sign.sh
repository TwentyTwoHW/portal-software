#!/usr/bin/env bash

set -xeo pipefail

BASE_DIR=$(dirname -- "$(readlink -f -- "$BASH_SOURCE")")

objcopy -O binary "$BASE_DIR/../target/thumbv7em-none-eabihf/release/firmware" /dev/shm/fw.bin
echo -n "000000C800" | xxd -r -p >> /dev/shm/fw.bin
hal key schnorr-sign $(cat "$BASE_DIR/../../../FW_SIGNING_KEY") $(cat /dev/shm/fw.bin | sha256sum | awk '{ print $1 }') | xxd -r -p > /dev/shm/fw-signed.bin && cat /dev/shm/fw.bin >> /dev/shm/fw-signed.bin
