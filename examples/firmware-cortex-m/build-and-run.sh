#!/bin/sh
# Build the freestanding Cortex-M3 image and run it under QEMU, capturing the
# probe stream the shim emits through the board's UART.
#
# Run inside WSL Debian (see README.md); needs gcc-arm-none-eabi and
# qemu-system-arm. Writes <outdir>/firmware.elf and <outdir>/capture.jsonl.
#
#   ./build-and-run.sh [outdir]
set -e

here=$(cd "$(dirname "$0")" && pwd)
out=${1:-$here/build}
mkdir -p "$out"

# Compiled from this directory with a *relative* source path on purpose. The
# shim stamps __FILE__ into every record, so the path the compiler was given is
# the path the engine correlates against — compile with an absolute path and
# every coverage record names a location no finding has.
cd "$here"

arm-none-eabi-gcc \
  -mcpu=cortex-m3 -mthumb -O1 -g -std=c11 -Wall -Wextra \
  -ffreestanding -nostdlib -fno-builtin -fno-common \
  -DSDA_PROBE_ENABLED -DSDA_PROBE_NO_FLOAT -DSDA_PROBE_CUSTOM_SINK \
  -I ../../shim \
  -T link.ld \
  -o "$out/firmware.elf" \
  src/main.c

echo "built $out/firmware.elf"
arm-none-eabi-size "$out/firmware.elf"

# -semihosting because the image asks the emulator to stop when it is done. A
# harness that instead kills QEMU on a timeout cannot tell a finished run from a
# hung one, and would report the same capture either way.
qemu-system-arm \
  -machine lm3s6965evb \
  -nographic \
  -semihosting \
  -kernel "$out/firmware.elf" \
  > "$out/capture.jsonl"

echo "captured $(wc -l < "$out/capture.jsonl") line(s) to $out/capture.jsonl"
