# A Cortex-M image that actually runs

`examples/firmware/` is a project with deliberate MISRA violations and a
`fake_instrumented.bat` that **writes probe records by hand**. This directory is
the same idea with the simulation taken out: a freestanding Cortex-M3 image,
linked with `-nostdlib` and no compiler runtime, executed on an emulated
Stellaris LM3S6965, emitting the shim's records through the board's UART.

That closes the gap `HANDOFF.md` called the highest-value one. The shim's own
header said the freestanding path "has been read carefully but never assembled";
the images had been *linked* for four architectures and never *run*. Everything
past the link step was claim-by-construction.

## What it needs

Inside WSL Debian:

```bash
wsl -d Debian -u root -- apt-get install -y qemu-system-arm gcc-arm-none-eabi
```

Verified against `qemu-system-arm` 10.0.11 (Debian 1:10.0.11+ds-0+deb13u1) and
`arm-none-eabi-gcc` 14.2.1 20241119 (Debian 15:14.2.rel1-1).

## Build, run, capture

```bash
wsl -d Debian -- bash -lc \
  'cd /mnt/c/<project>/examples/firmware-cortex-m && sh build-and-run.sh'
```

Writes `build/firmware.elf` (about 2.2 KB of text, 8 bytes of bss, no `.data`)
and `build/capture.jsonl`. Both are gitignored; the capture is kept as a fixture
at `crates/sda-engine/tests/fixtures/qemu-lm3s6965-cortex-m3.jsonl`.

Then feed it back on the Windows side:

```bash
sda scan examples/firmware-cortex-m \
    --observation examples/firmware-cortex-m/build/capture.jsonl
```

`--observation` is for exactly this case: the program ran somewhere this host
cannot run it, and all that came back is what the shim emitted.

## What the program is arranged to produce

Three outcomes, so the run is worth correlating rather than a wall of coverage.

* `decode` is called four times, three in range and one past the end, so the
  capture carries a **real `bounds` fault** — the fourth call — at a line a
  static rule also has an opinion about.
* `recovery` is **never called**. Its lines appear in no coverage record, which
  is what lets the engine say *unreached* rather than *clean*.
* `checksum` runs to completion and reports its result, so a finding about it is
  answered by evidence rather than by silence.

The capture is twelve records and every one of them can be checked by hand: the
buffer is `i * 3` for `i` in 0..8, so `checksum` is 84; `decoded` is
`0 + 12 + 21 + (-1)` = 32; line 64 is covered four times and line 69 three, the
missing one being the call that returned early through the bounds check.

The twelfth is `stack_bytes`, and it is **measured**. It used to be
`SDA_MARK("stack_bytes", 1024)` — a number the program had been told, reported as
though it had been observed, which is the defect this whole toolkit exists to
stop. `Reset_Handler` now fills the unused stack with `0xC0DEC0DE` after `.bss`
is zeroed and before anything else runs; `main` reports the lowest address still
holding the pattern, so the figure is a high-water mark for the entire run.

It comes back as **632** at `-O1` and **704** at `-O0`, which is the check worth
doing: a number that moves with the compiler's frames is a measurement, and one
that does not is a constant wearing a measurement's name. The painter leaves its
own frame unpainted, so the figure carries a 32-byte margin.

This is still not a claim about silicon. Interrupt frames pushed by a real NVIC,
a vendor startup path and a different optimisation level all move it. What it
reports is what *this* image did on this machine.

## Three things that cost time

**The compiler is invoked from this directory with a relative source path.** The
shim stamps `__FILE__` into every record, so the path the compiler was given is
the path the engine correlates against. Build with an absolute path and every
coverage record names a location no finding has — a capture that parses, looks
right, and correlates with nothing.

**The vector table has to be first in flash.** The core reads the initial stack
pointer from word 0 and the reset vector from word 1 before any code runs. Get
that wrong and QEMU faults immediately with no output, which reads as a UART
problem.

**The image asks the emulator to stop, through ARM semihosting.** Killing QEMU on
a timeout instead would produce the same capture whether the program finished or
hung, and a harness that cannot tell those apart is the failure this repository
is about. `SYS_EXIT` via `bkpt #0xAB` needs `-semihosting` on the QEMU command
line.
