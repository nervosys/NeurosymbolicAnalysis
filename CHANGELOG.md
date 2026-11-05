# Changelog

What changed for someone running `sda`, the workbench, or the MCP server, newest
first. The format follows [Keep a Changelog](https://keepachangelog.com/). How
each claim was checked, and what has not been, is in `HANDOFF.md`.

The release workflow takes a tag's notes from its section here, so a heading
must read exactly `## [<version>]`.

## [Unreleased]

MISRA C findings change in both directions, so a baseline taken on 1.0.1 may need
refreshing.

### Fixed
- False positives no longer reported:
  - 15.2 for a label of the same name in another function
  - 17.10 for `_Noreturn static inline void`, `void _Noreturn`, and void functions
    marked `__attribute__((noreturn))` or `[[noreturn]]`
  - 8.10 with an attribute between `static` and `inline`
  - Dir 4.10 for an `#if !defined(X)` guard
  - 11.10 for `_Atomic(void *)`
  - 20.1 for the contents of `#if 0`
  - 6.2 for a ternary in a function
  - 8.16 for `alignas(0 + 16)`
  - 20.10 for a `#` in a string, character constant or comment
  - Dir 4.9 for a macro that uses a parameter as `(T *)`
- Violations now reported:
  - 17.10 for `_Noreturn void *f`
  - 6.3 for a width written as a macro or in parentheses
  - 8.2 for a lone typedef name or struct tag as a parameter, prototypes inside a
    function, and old-style definitions
  - 16.6 for `case 1: case 2:` with no other clause
  - 17.1 for the `__builtin_va_*` spellings
  - 2.6 for a label whose only `goto` is in another function
  - 20.14 for a second `#else`, or an `#elif` after one
  - 8.16 for `alignas(0u)`
  - 20.10 for the digraphs `%:` and `%:%:`
- More false positives no longer reported:
  - 13.3 for a control header and the statement after it, as in
    `for (i = 0; i < n; i++) sum += a[i];`
  - 8.11 for a parameter's `[]` or the next declaration's
  - 12.3 for declarations led by an attribute, `__typeof__` or a macro
  - 13.4 and 13.6 for a designator's `=`, and 13.6 for `offsetof` and `my_t (*)[4]`
  - 15.4 for a `goto` whose label is in the same loop
  - Dir 4.6 for `typedef unsigned int u32_t;`
- More violations now reported:
  - 8.11 on a declaration with long specifiers
  - 13.6 for `sizeof a[i++]`
  - 15.4 for a `goto` leaving the loop from a nested `switch` or loop
  - Dir 4.12 for `&malloc` and `{ malloc }`
  - 21.6, 21.10 and 21.12 for a parenthesised call such as `(printf)("x")`
- 13.3 reports a violation in a loop or `if` body on its own line, not the header's.
- 17.10 no longer fires on `krb5_error_code f(...) __attribute__((noreturn));`,
  because the return type is a typedef name it cannot read.
- The 5.4 message said 31 significant characters where the check compares 63.

## [1.0.1] - 2026-11-04

The same code as 1.0.0, built by the release workflow rather than on one machine.

### Added
- macOS CLI archives for arm64 and x86_64. The arm64 one is run in CI; the x86_64
  one is built and not run. The macOS GUI is still not shipped.

### Changed
- The `.deb` is built on Ubuntu 22.04, and is installed and run there in CI. It
  needs glibc 2.34, where 1.0.0's needed 2.39.
- CI builds the workspace on the minimum supported Rust version, 1.88.
- `v*` tags can be created only by repository admins, and a release needs a
  reviewer's approval.

### Fixed
- CI checks out full history, which a test needs. CI had never run before the
  repository went public, so this had not been seen.

## [1.0.0] - 2026-11-03

rc.4 plus a MISRA C audit, a capability file for the workbench, and the first
public release.

Built on one machine, unsigned, because the release workflow has not run yet:

- There are no macOS artifacts.
- The `.deb` and AppImage need glibc 2.39, so Ubuntu 24.04 or later. On older
  Linux, use the static CLI.
- The FreeBSD CLI was checked by file type and not run on FreeBSD.

### Changed
- A release's notes are its section of this file, and the release workflow
  refuses a tag that has none.
- MISRA C 21.1, 6.2, 11.9, 2.5 and Dir 4.3 are `partial`, not `native`:
  - 21.1 misses standard-library names;
  - 6.2 misses typedef'd bit-field types;
  - 11.9 misses `p == 0`;
  - 2.5 misses unused macros in headers;
  - Dir 4.3 misses short functions that mix assembly with C.

  `sda rules audit` now claims conformance evidence for 65 MISRA C
  guidelines, down from 70.

### Security
- `SECURITY.md` says how to report a vulnerability: privately, through the
  repository's Security tab.
- `sda build compile-commands` refuses to write through a symlinked
  `compile_commands.json`, so a checkout cannot redirect the write.
- The workbench's Content Security Policy adds `form-action 'none'` and
  `frame-src 'none'`.
- The workbench window may call only the app's own commands; Tauri's window,
  webview, event and other core APIs are refused at the IPC boundary.

### Fixed
- The workbench's coverage gutter shows the execution counts a run measured.
  It looked for them on the finding rather than on its correlation, so it had
  been blank on every scan.
- Twelve MISRA C checks passed code that breaks their guideline:
  - 16.3 treated a `break` inside an `if` as ending the clause.
  - 16.2 accepted a `case` in a plain block inside a nested switch.
  - 15.4 counted the `while` of a `do` loop as a loop.
  - 12.3 looked only in control headers.
  - 13.4 and 13.3 knew only some compound assignments, and 13.4 skipped
    do-while conditions.
  - 13.6 missed `sizeof` without parentheses.
  - 17.6 missed `[const static N]`.
  - 18.5 missed qualifiers between the `*`s.
  - Dir 4.12 missed an allocator taken by address.
  - 8.14 missed GCC's `__restrict__`.
  - 21.6 missed most of `<stdio.h>` called without the header.

  A switch nested inside another switch is now checked; the scan used to skip
  past the outer switch's body, so the inner one's clauses were never read.

  15.4 no longer loses count after a nested loop without braces, and a
  `break` under one no longer counts against the outer loop.

  A comma between declarators in a `for` header is no longer reported as an
  operator.
- The workbench bundles Monaco's editor worker, so the editor no longer warns at
  startup and no longer runs diffing and word scanning on the UI thread.

## [1.0.0-rc.4] - 2026-11-02

rc.3 plus the audit's open items. It replaces rc.3.

### Security
- The workbench's Content Security Policy no longer allows inline script, and
  adds `object-src 'none'` and `base-uri 'self'`.
- Writes under `.sda/` (triage, baseline, SWE sessions, fuzz reproducers) refuse a
  symlinked `.sda`, directory or file, so a scanned repository cannot redirect
  them.
- Every action in both GitHub workflows is pinned to a commit SHA.

### Fixed
- The old CSP blocked Tauri's IPC endpoint, so every workbench command quietly
  fell back to postMessage. `connect-src` now allows it.
- Fuzz seeds spend the same run and time budget as the mutation loop; a large
  corpus used to run in full whatever the budget.

## [1.0.0-rc.3] - 2026-11-02

A security audit of the workbench and installer, the MCP server, untrusted-input
parsing, and CI.

### Added
- `sda scan --ignore-project-config` scans code whose own deviations should not
  count.

### Changed
- The MCP tool descriptions say which tools run code.
- The minimum supported Rust version is 1.88, which `zip` 9.2.2 needs.

### Fixed
- Hostile input no longer ends a scan: a pickle with a length of 2^64-1, deeply
  nested GGUF arrays, a 20,000-deep call chain, and a comment cut inside a UTF-8
  character.
- A wrapped safetensors offset no longer hides the overflow it exists to report,
  and a pickle can no longer hide `os.system` behind its memo.
- Rule 17.2 no longer reports a call to a recursive function as recursion.
- Builds and dynamic runs drain their output while the child runs. They used to
  read it only after exit, so a build with more than a pipe's worth of output
  hung until timeout.
- Build child processes no longer read the MCP server's JSON-RPC stdin.

### Security
- The workbench no longer has an unused command that wrote any file the page
  named, and its "external tools" checkbox says it runs the project's build code.
- Every git call a scan makes disables `core.fsmonitor`, filter drivers and
  signature checking, so a checkout's own `.git/config` cannot run commands
  through them.
- The installer hands the install path to its PowerShell script in an
  environment variable, so a quote in the path is no longer run as code.
- A project's `.sda/` catalogue can no longer lower a Mandatory rule or claim
  native coverage; imports keep what is already known.
- `zip` is 9.2.2, up from 2.4.2, which carried four advisories.

## [1.0.0-rc.2] - 2026-11-02

### Added
- One tag builds Windows, macOS, Linux and FreeBSD artifacts into a draft
  release. The workflow has not yet run in CI.
- `tools/package-cli.sh` packages the CLI with its licence and that target's
  third-party notices.

### Changed
- The Linux CLI is a static musl binary, and the `.deb` is built on Ubuntu 22.04,
  so neither needs a recent glibc.
- The macOS GUI is built only when asked for: the objc2 crates it links question
  whether they may be redistributed.

### Fixed
- The `.deb` includes the licence text.
- The icon set is generated from a 1024 px design; the single 16x16 `.ico` was
  refused by the AppImage and macOS bundlers.

## [1.0.0-rc.1] - 2026-11-01

The first release candidate, for Windows, unsigned.

### Added
- Native static analysis for C, C++ and Rust against the MISRA C:2023 and MISRA
  C++:2023 catalogues. The catalogues carry rule numbers and classification, not
  titles; `sda rules import` adds the text for a holder of the documents.
- Adapters for external analyzers, including cppcheck, clang-tidy, Miri and
  CodeQL.
- A probe shim that records runtime evidence, run on a Cortex-M3 image under
  QEMU, and a correlation engine that marks each static finding confirmed,
  refuted, unreached, unpredicted or inconclusive.
- Deductive proof evidence checked by `sda verify`.
- AI model artifact scanning and behavioural probes.
- `sda hotspots`, `sda impact`, `sda build compile-commands` and
  `sda build detect`.
- Reports record the revision they describe; SARIF 2.1.0 output.
- `sda mcp`, an MCP server for agents.
- The Tauri workbench, and a Windows installer that puts `sda` on PATH.
