# Driving `ext.valgrind` from Windows

Memcheck cannot execute a Windows binary, so verifying this adapter end to end
means building the target inside WSL and presenting WSL's Valgrind to the Windows
adapter as if it were a local tool. That is what these two files do.

This is a **verification harness, not a shipping feature.** It exists because the
adapter's process handling — `{artifact}` substitution, the stderr capture, the
exit-code rule — cannot be checked any other way on this machine, and because
`ext.valgrind` once shipped with four defects and no way to notice.

## Why there are two files

`valgrind-wsl.bat` does the real work: it passes flags through unchanged,
translates the final argument with `wslpath` when it looks like a Windows path,
and runs `wsl -d Debian -- valgrind`. Memcheck's output goes to stderr and its
exit status survives the hop, because the adapter reads the first and judges on
the second.

`vgwrap.c` compiles to the `.exe` the adapter actually spawns. **Windows
`CreateProcess` cannot execute a `.bat`**, so `Command::new("valgrind-wsl.bat")`
fails with "program not found" and the adapter reports Valgrind as absent while
it sits there working. The `.exe` is a three-line shim that re-invokes the batch
file through `cmd` and returns its exit code.

The path check in the batch file matters for the same reason: the availability
probe calls `--version` with no artifact, and handing that to `wslpath` yields an
empty target and a failed probe.

## Use

```bash
clang -D_CRT_SECURE_NO_WARNINGS -o valgrind-wsl.exe vgwrap.c
export SDA_VG_BAT="<absolute windows path to valgrind-wsl.bat>"

# build the target inside WSL, into a directory Windows can see
wsl -d Debian -- bash -lc "cd /mnt/c/<project> && gcc -g -O0 -o prog main.c"

sda scan <project> --artifact <project>/prog --with ext.valgrind=<...>/valgrind-wsl.exe
```

Expect Valgrind's findings at `AnalysisPhase::Dynamic`, with CWEs, located in the
program's own frames rather than in Valgrind's `malloc` interceptor.

The native dynamic engine will still fail to launch the Linux binary — `%1 is not
a valid Win32 application` — and that is correct. The run continues static-only
and says so under *NOT CHECKED*; it used to abort the entire scan and discard
every finding, which is how that behaviour was found.
