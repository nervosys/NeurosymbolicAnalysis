#!/usr/bin/env bash
#
# The whole gate, as one command that fails as a unit.
#
#     tools/verify.sh && git commit -F -
#
# Everything this repository asks of a commit is four steps: the workspace
# tests, the GUI crate's tests, clippy over all targets, and the three
# self-scans. Running them as four commands means sequencing them correctly
# every time, and on 2026-09-16 that went wrong — `cargo test --workspace` and
# `git commit` in one shell line, with nothing between them, so exit 101 and two
# failures went past while the commit succeeded. The same batching mistake had
# already been made twice earlier in that session and written up both times.
#
# A checklist you follow by hand is a check that did not happen, presented as one
# that did. That is the failure this whole codebase is organised against, and it
# applies to the process as readily as to the analyzer.
#
# Prints the test and binary counts at the end, because `HANDOFF.md` states them
# and a test holds it to what the tree contains. Summed with `awk` and not `bc`:
# this machine has no `bc`, and the first version printed `OK  tests across 65
# binaries` with the number silently missing — a blank where a count belongs is
# the failure this script exists to prevent, arriving in the script itself.
set -u

fail() { printf '\nFAILED: %s\n' "$1" >&2; exit 1; }

: "${CARGO_TARGET_DIR:=}"
if [ -z "$CARGO_TARGET_DIR" ]; then
  printf 'note: CARGO_TARGET_DIR is unset, so this uses the shared one.\n'
  printf '      See *This machine* in HANDOFF.md — other projects wipe it mid-link.\n\n'
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root" || fail "cannot enter $root"
out="$(mktemp)"
trap 'rm -f "$out"' EXIT

# A commit must not invent a top-level entry.
#
# `wsl -d Debian -- sh -lc "... $HOME ..."` from PowerShell expands `$HOME` on
# the Windows side, so the distro was handed the literal `C:Usersadamm` as
# CARGO_TARGET_DIR and cargo built a target directory of that name *inside this
# repository*. Five cargo lock files reached a commit, and the only reason anyone
# noticed was that git's line-ending warning happened to print the path.
#
# Everything else in this script asks whether the code is right. This asks
# whether the repository still has the shape it had, which is the question that
# catches an accident rather than a mistake — and an accident is what put build
# artifacts in a commit.
#
# Adding a top-level directory is rare and deliberate. Adding it here too is the
# whole cost.
KNOWN='.git .gitattributes .github .gitignore .sda CHANGELOG.md Cargo.lock Cargo.toml HANDOFF.md LICENSE README.md SECURITY.md crates examples gui shim tools'

printf '0/5  repository shape\n'
unexpected=''
for entry in $(ls -A); do
  case " $KNOWN " in
    *" $entry "*) ;;
    *) unexpected="$unexpected $entry" ;;
  esac
done
if [ -n "$unexpected" ]; then
  printf '     unexpected at the top level:%s\n' "$unexpected"
  fail "the repository grew a top-level entry nobody listed. If it belongs, add it to KNOWN in this script; if a tool put it there, it does not belong in a commit"
fi

# And the same question below the top level, where the check above could not see.
#
# It was written after a `target/` directory appeared beside `Cargo.toml`, so it
# looks at the top level only — and a `.pyc` from one of the oracle scripts in
# `tools/` had been sitting in the tree, committed, the whole time. Found by
# accident again, while adding a script next to it. Twice is a pattern: the
# artifacts that get committed are the ones nobody thinks to look at.
#
# Tracked files only. An artifact that is merely present is the working copy's
# business and `.gitignore`'s; one that is *committed* ships to everyone who
# clones, and that is what this refuses.
generated=$(git ls-files | grep -E '(^|/)(__pycache__|node_modules|\.pytest_cache)/|\.(pyc|pyo|o|obj|rlib|rmeta)$' || true)
if [ -n "$generated" ]; then
  printf '     generated files are tracked:\n%s\n' "$generated"
  fail "a build artifact is committed. Remove it with \`git rm --cached\`, and add it to .gitignore so the next one does not follow it in"
fi

# A non-zero cargo exit is not by itself a failed test.
#
# On this machine the workspace run intermittently dies after a test binary has
# printed every one of its tests as `ok` and before it prints its `test result:`
# line — no diagnostic, no failure, exit 127 or 1. The heaviest process-spawning
# binary (`sda-adapters`, which starts and kills real child processes) is always
# where it stops, and that same binary passes 66 of 66 standalone, six runs out
# of six, piped or redirected. Two causes were proposed — the output being a pipe,
# and machine load — and neither survived: this same command later passed ten
# times out of ten at thirteen concurrent cargo processes and 100% CPU. There is
# no reliable reproduction and no surviving hypothesis. Either way it is not a
# result about your code, which is all this classifier needs to know.
#
# Reporting that as "workspace tests failed" would be this codebase's own error
# inverted: an inability to check, presented as a check that came back bad. So
# the output is read. A real failure names itself — `test result: FAILED`,
# `error[`, `could not compile`. Anything else, with every test reporting `ok`,
# is the harness dying: retried once, then reported as what it is.
# Did the compiler itself fall over?
#
# `rustc` crashing prints `error: could not compile`, exactly as a type error
# does, so every classifier below would call an internal compiler error a defect
# in this code. Seen once, live: `STATUS_STACK_BUFFER_OVERRUN` (0xc0000409) with
# a backtrace through `rustc_hir_typeck`, compiling a crate nothing in the commit
# had touched, and the gate reported `FAILED: gui/src-tauri tests`.
#
# That reading sends somebody to debug code that is fine, which is this
# repository's own error inverted — an inability to check, presented as a check
# that came back bad. It is the same argument the workspace classifier below
# already makes about a harness that dies, applied to the layer under it.
#
# Structural rather than statistical: one crash is one observation, but the
# script's inability to tell the two apart is in the script and can be read.
compiler_crashed() {
  grep -qE 'STATUS_STACK_BUFFER_OVERRUN|internal compiler error|error: rustc interrupted by|thread .rustc. panicked' "$1"
}

# The build could not be attempted, as distinct from attempted and failed.
#
# `LNK1140` is the linker giving up on a program database that grew past its
# format limit across many incremental rebuilds in a long-lived target
# directory; `cargo clean -p <crate>` fixes it and nothing in the source does.
# `LNK1104` is usually the shared target directory being written by another
# project mid-link. A full disk speaks for itself. All three print
# `error: could not compile`, which the classifier below reads as the compiler
# rejecting this code -- so the gate printed `FAILED: workspace tests` about a
# tree whose tests it had never run. That is this repository's own failure mode
# living in the gate that exists to catch it: an inability to check, reported
# as a check that came back negative.
build_was_not_possible() {
  grep -qE 'LNK1140|LNK1104|database or disk is full|No space left on device' "$1"
}

# What to do about it, since the linker's own advice -- `link with /PDB:NONE` --
# is not actionable from here.
not_possible_advice() {
  if grep -q 'LNK1140' "$1"; then
    printf 'the linker hit its program-database limit (LNK1140). The target directory has accumulated debug info across many rebuilds; `cargo clean -p <crate>` on the crate named above clears it. Nothing in this code caused it, and no test was run'
  elif grep -q 'LNK1104' "$1"; then
    printf 'the linker could not open an output file (LNK1104), which on this machine is usually another project writing the shared target directory mid-link. See *This machine* in HANDOFF.md. No test was run'
  else
    printf 'the build ran out of disk. No test was run, so this says nothing about the code'
  fi
}

run_workspace_tests() {
  cargo test --workspace > "$out" 2>&1 && return 0
  # `test result: FAILED` is a test that failed; `error[E0308]` and
  # `could not compile` are the compiler. Cargo's own
  # `error: test failed, to rerun pass ...` is neither — it prints that whenever
  # a test binary exits non-zero, which is exactly what the harness flake does,
  # so matching it made this classifier call the flake a real failure. That is
  # the defect this classifier exists to prevent, written into the classifier.
  if compiler_crashed "$out"; then
    return 3
  fi
  if build_was_not_possible "$out"; then
    return 4
  fi
  if grep -qE 'test result: FAILED|error\[E[0-9]+\]|could not compile' "$out"; then
    return 1
  fi
  return 2
}

report_test_failure() {
  grep -E 'test result: FAILED|^error|panicked at|^---- ' "$out" | head -20
  fail "workspace tests"
}

printf '1/5  cargo test --workspace\n'
run_workspace_tests
case $? in
  0) ;;
  1) report_test_failure ;;
  3) grep -E 'STATUS_STACK_BUFFER_OVERRUN|internal compiler error|thread .rustc. panicked' "$out" | head -3
     fail "the Rust compiler crashed while building the workspace. That is a toolchain fault, not a result about this code — rerun, and if it repeats, report it upstream with the backtrace above" ;;
  4) grep -E 'LNK1140|LNK1104|database or disk is full|No space left on device' "$out" | head -3
     fail "$(not_possible_advice "$out")" ;;
  *) printf '     harness aborted with no failure reported; retrying once\n'
     run_workspace_tests
     case $? in
       0) ;;
       1) report_test_failure ;;
       *) tail -5 "$out"
          fail "the harness aborted twice without reporting a failure. Every test it reached passed; see *This machine* in HANDOFF.md. This is not a result about your code" ;;
     esac ;;
esac
passed=$(grep -oE 'test result: ok\. [0-9]+ passed' "$out" | grep -oE '[0-9]+' | awk '{s += $1} END {print s + 0}')
bins=$(grep -cE '^running ' "$out")

printf '2/5  cargo test (gui/src-tauri)\n'
( cd gui/src-tauri && cargo test ) > "$out" 2>&1 || {
  if compiler_crashed "$out"; then
    grep -E 'STATUS_STACK_BUFFER_OVERRUN|internal compiler error|thread .rustc. panicked' "$out" | head -3
    fail "the Rust compiler crashed while building gui/src-tauri. That is a toolchain fault, not a result about this code — rerun, and if it repeats, report it upstream with the backtrace above"
  fi
  if build_was_not_possible "$out"; then
    grep -E 'LNK1140|LNK1104|database or disk is full|No space left on device' "$out" | head -3
    fail "building gui/src-tauri: $(not_possible_advice "$out")"
  fi
  tail -40 "$out"
  fail "gui/src-tauri tests"
}
gui=$(grep -oE 'test result: ok\. [0-9]+ passed' "$out" | grep -oE '[0-9]+' | awk '{s += $1} END {print s + 0}')

printf '3/5  cargo clippy --workspace --all-targets\n'
cargo clippy --workspace --all-targets > "$out" 2>&1 || { tail -40 "$out"; fail "clippy exited non-zero"; }
n=$(grep -cE '^(warning|error)' "$out" || true)
[ "$n" -eq 0 ] || { grep -E '^(warning|error)' "$out" | head -20; fail "$n clippy diagnostic(s)"; }

printf '4/5  self-scan: crates, shim, tools\n'
cargo build -p sda-cli > "$out" 2>&1 || { tail -20 "$out"; fail "building sda"; }
# Ask cargo where it built, because on this machine the shared target directory
# comes from `~/.cargo/config.toml` rather than the environment, and assuming
# `target` made an unset CARGO_TARGET_DIR fail here after every test had passed.
# `sed` because jq is not installed; the JSON doubles Windows backslashes.
target_dir=$(cargo metadata --format-version 1 --no-deps \
  | grep -oE '"target_directory":"[^"]*"' \
  | sed -e 's/^"target_directory":"//' -e 's/"$//' -e 's/\\\\/\//g')
[ -n "$target_dir" ] || fail "cargo metadata did not name a target directory"
sda="$target_dir/debug/sda"
[ -x "$sda" ] || sda="$sda.exe"
[ -x "$sda" ] || fail "no sda binary at $sda"
for t in crates shim tools; do
  "$sda" scan "$t" > "$out" 2>&1 || fail "scan $t exited non-zero"
  grep -q '^No findings at the requested severity' "$out" || {
    grep -E '^[^ ].*:[0-9]+:[0-9]+:' "$out" | head -20
    fail "scan $t is not clean"
  }
done

printf '\nOK  %s tests across %s binaries, %s more in gui/src-tauri\n' "$passed" "$bins" "$gui"
printf '    clippy clean; crates, shim and tools scan clean\n'
