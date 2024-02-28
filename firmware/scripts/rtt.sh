#!/usr/bin/env bash

set -xeo pipefail

RTT_ADDR=$(objdump ./target/thumbv7em-none-eabihf/release/firmware -t | grep _SEGGER_RTT | awk '{ print $1 }')
cat <<EOF | nc -N 127.0.0.1 4444
rtt server stop 9999
rtt setup 0x$RTT_ADDR 1024 "SEGGER RTT"
rtt start
rtt server start 9999 0
EOF

nc 127.0.0.1 9999