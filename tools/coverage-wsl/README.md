# Driving the external dynamic path end to end

`examples/coverage/main.c` exists to produce three correlation verdicts in one
run, with **every piece of runtime evidence coming from an external tool**: gcov
supplies the execution counts, Memcheck supplies the defect, and nothing is
instrumented with the SDA probe shim. Its header comment names the three lines
and what each is for.

This directory is a README and no code, because unlike `tools/valgrind-wsl/`
nothing had to be built to make it work — gcc and gcov run inside WSL and write
files Windows can read. The commands below are the ones that produced
`crates/sda-engine/tests/fixtures/gcov-14.2.0.gcov` and
`crates/sda-engine/tests/fixtures/valgrind-3.24.0-coverage.txt`, against gcc and
gcov 14.2.0 (Debian 14.2.0-19) and Valgrind 3.24.0.

## Build, run, and collect the counts

```bash
wsl -d Debian -- bash -lc '
  cd /mnt/c/<project>/examples/coverage &&
  gcc -g -O0 --coverage -c main.c -o build/main.o &&
  gcc --coverage -o build/prog build/main.o &&
  (cd build && ./prog >/dev/null) &&
  gcov -o build main.c && mv -f main.c.gcov build/'
```

**Compile from the source directory, not from `build/`.** `gcov` records the
source path it was given and reads the source back when it annotates. Invoked
where it can find its `.gcda` but not the source, it writes a well-formed
four-line file with a `Source:` header and *no records*, while printing
`Lines executed:66.67% of 15` to the terminal — a coverage report that parses,
measures nothing, and looks on screen exactly like one that worked. That is the
case `an_empty_report_is_an_error_not_an_empty_measurement` exists for, and it is
easy to walk into: it happened again while capturing these fixtures.

Naming the binary `prog` and the object `main.o` also matters. `gcc --coverage -o
prog main.c` in one step writes `prog-main.gcda`, which `gcov -o build main.c`
does not look for.

## Add the defect

```bash
wsl -d Debian -- bash -lc '
  cd /mnt/c/<project>/examples/coverage/build &&
  valgrind --leak-check=full --show-leak-kinds=all ./prog >/dev/null'
```

Memcheck writes to stderr; the leak is reported at `main.c:30`.

## The whole thing through the CLI

`tools/valgrind-wsl/README.md` explains the `.exe` shim and `SDA_VG_BAT`. With
those in place:

```powershell
sda scan examples/coverage `
  --with ext.valgrind=<...>/tools/valgrind-wsl/valgrind-wsl.exe `
  --artifact C:\<project>\examples\coverage\build\prog `
  --coverage examples/coverage/build
```

which reports `confirmed: 2, refuted: 1, unreached: 4, inconclusive: 3`.

**Give `--artifact` an absolute Windows path.** The batch file translates the
final argument with `wslpath` only when it looks like one; a relative path is
passed through unchanged and Valgrind exits 127 with "No such file or directory".
The adapter reports that correctly — as a provider that failed, not as one that
ran clean — which is how it was noticed.

`--coverage` accepts the build directory: gcov writes one `.gcov` per translation
unit, so pointing at a directory is the normal case, and PowerShell does not glob
arguments the way a POSIX shell does.

## What this does not establish

The counts describe *the run that produced the `.gcov`*, not necessarily the run
Memcheck inspected — two executions of the same program with the same input, but
still two. The report says so in `NOT CHECKED` rather than letting a reader
assume one run. Reproducing that properly means collecting both from a single
execution, which Memcheck's own instrumentation does not provide.
