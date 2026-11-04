# Handoff

State of the toolkit, how to run it, what is actually verified, and where the
bodies are buried. `README.md` is the product description; this is the note to
whoever picks it up next.

If you read only one section, read **The failure mode this codebase keeps
having**. Everything else is detail; that is the thing that will bite you.

## The latest session, 2026-11-02

* **A security audit, and what it changed.** Four read-only agents covered the GUI
  and installer, the MCP server, untrusted-input parsing, and CI. Each finding was
  checked in the code before it was fixed, and each fix has a test that first shows
  the attack working:
  * Scanning a checkout ran its `.git/config`: `core.fsmonitor` and filter drivers on
    `git status`, and `gpg.program` on `git log` under `log.showSignature`. Every git
    call now goes through `vcs::command` in `crates/sda-engine/src/vcs.rs`, which
    turns those off and skips submodules. This was code execution on one Scan click.
  * The NSIS hook quoted `$INSTDIR` into a PowerShell script, so a `'` in the path
    ran the rest as code. The path now travels in an environment variable, and a
    failed PATH edit is reported in the install log.
  * Hostile inputs ended a scan: a pickle length of 2^64-1, nested GGUF arrays, a
    20,000-deep C call chain, a comment cut inside a UTF-8 character. A safetensors
    offset that wrapped hid the out-of-bounds read it exists to report. A pickle
    could hide `os.system` behind the memo.
  * 17.2 reported any cycle reachable from a function against that function, so
    `f` calling a recursive `g` read as "`f` calls itself". It now uses strongly
    connected components.
  * Builds and dynamic runs read their pipes only after exit, so a build printing
    more than a pipe buffer hung until its 900-second timeout. Build children also
    inherited the MCP server's stdin, which is the JSON-RPC channel.
  * A project's `.sda/` catalogue could make a Mandatory rule's findings Low and claim
    native coverage. `Catalog::import` now keeps the coverage of known numbers, and
    the obligation and decidability of confirmed ones. `sda scan
    --ignore-project-config` scans code whose own deviations should not count.
  * `zip` 2.4.2 had four advisories (none reachable: nothing here extracts). It is
    now 9.2.2, which needs Rust 1.88, so the MSRV is 1.88. The GUI lockfile moved
    `quick-xml`, `time` and `tokio` past their advisories; `cargo audit` reports no
    vulnerabilities in either lockfile, only unmaintained-crate warnings under Tauri.
  * Release jobs get a read-only token, and only `draft` can write. Checkouts do not
    keep credentials, and `.gitignore` covers key files.
  * MCP tool descriptions now say which tools run code and which read any path. The
    GUI's unused `save_document` command, which wrote any path, is gone.

  Then, in rc.4:
  * The GUI's CSP no longer allows inline script, and gains `object-src 'none'`
    and `base-uri 'self'`. Checked in a running window over the DevTools
    protocol: Monaco and the terminal render, an injected inline script is
    refused, and `scan` over IPC returns the 20 findings the CLI does. The same
    check found the old policy had always blocked Tauri's IPC endpoint, so every
    command fell back to `postMessage`; `connect-src` now allows it.
  * Every action in both workflows is pinned to a commit SHA, with the tag as a
    comment.
  * Writes under `.sda/` go through `sda_core::safe_write`, which refuses a
    symlinked `.sda`, directory or file. Windows here cannot create symlinks
    without Developer Mode, so its test skips those cases; it was run on Linux
    in WSL, where all three ran and passed.
  * Fuzz seeds spend the same `runs` and time budget as the mutation loop.

  Still open: MCP tools accept any path, with the user's own reach. (The Tauri
  capability file this list also named was added after rc.4; see *1.0.0, and what is still open*.)
* **GitHub Actions runs now.** Billing stopped every job until the repository went
  public on 2026-11-03. `verify.yml` then passed on Windows and Ubuntu, once it
  stopped checking out shallow.
* **MISRA titles are gone.** The built-in catalogues hold numbers and classification
  only: 241 titles removed, as cppcheck also ships none. They had been rewritten
  without the licensed text, so nobody could say they were safe to ship. A finding
  still explains itself in its own message; its headline reads `MISRA C:2023 16.3`.
  The cost is that `sda rules find goto` no longer matches. `sda rules import` puts
  titles back for anyone who holds the document, and git history has the old ones.
* **`sda verify` exits 3** when there is no declaration or no obligation. It used
  to print "not a clean result" and exit 0.
* **The bundled notices are per target.** `tools/stage-sda-sidecar.sh` passes
  `--target` to `tools/third-party-notices.py`, so each artifact's notices cover
  what that binary links. For Windows that is 282 crates and 4 JavaScript packages with no exception left.
  All 23 remaining exceptions belong to other platforms; 19 are the objc2 family,
  whose `LICENSE.md` questions redistribution, so a macOS release reopens that. `unic`
  is dual-licensed and Apache-2.0 is complete, which settles its MIT copy having no
  copyright line. `selectors` carries Mozilla's MPL-2.0 text and `ra-ap-rustc_lexer`
  rust-lang/rust's files, each saying why in its `SOURCE.txt`. The codicon font is
  CC-BY-4.0 upstream; monaco-editor records no version of it. None of this has had
  legal review.
* **`1.0.0-rc.4` is prepared for four platforms, unsigned, in a private repository.**
  It is rc.2 plus the audit above, rebuilt the same way; rc.3 lacked the items under "Then, in rc.4".
  `.github/workflows/release.yml` builds every artifact from a tag into a draft
  release, and had not run when rc.4 was built, because CI was blocked by billing.
  What was built and tested on this machine, from the tag, is in `E:\sda-release`:
  * Windows: the NSIS installer and a CLI zip. rc.4 was installed silently into a
    directory named with a `'`, put `sda` on PATH, ran, and on uninstall left the
    user's PATH byte-identical to before. The installed workbench was driven over
    the DevTools protocol: it renders, refuses inline script, and scans over IPC.
    The CLI zip was extracted and run.
  * Linux: a `.deb` and an AppImage built in WSL Debian 13, and the CLI as a static
    musl binary, which runs on any x86_64 Linux. The `.deb` needs glibc 2.39; the
    workflow builds it on Ubuntu 22.04 (glibc 2.35) instead. All three were run:
    the `.deb` installed, scanned and removed cleanly; the AppImage's `sda`
    scanned and its workbench stayed up (WSL has no FUSE, so it was extracted).
  * FreeBSD: the CLI, cross-linked against the 14.5-RELEASE sysroot with clang and
    lld. Never run on FreeBSD; the workflow builds and runs it in a FreeBSD VM. No
    GUI: Tauri does not support the BSDs.
  * macOS: not built, because that needs a Mac. The workflow builds the CLI for both
    architectures, and the GUI only when asked, because the objc2 crates it links
    are derived from Apple's SDKs and their own `LICENSE.md` says it is unclear
    whether they may be distributed. Their licence texts are now vendored; that
    question is not answered by them.
  The icons were a single 16x16 `.ico`, which Linux and macOS bundles refuse. The
  same two-colour design is now drawn at 1024 in `gui/src-tauri/icons/source` and
  the set is generated from it with `tauri icon`; it is still a placeholder.
  CI never having run and no signing are why this is a candidate and not 1.0.
* **History was rewritten on 2026-11-01** to remove a committed `.pyc`: 80 of 159
  commits have new hashes, the tree is unchanged, and older clones must be replaced.
* **The installer was run end to end.** `tools/stage-sda-sidecar.sh`, then add
  `--config src-tauri/tauri.installer.conf.json` to the build: 5.3 MB, with `sda.exe`
  and the notices. On this machine, unsigned: the AGPL page shows, cancelling leaves
  nothing, a silent install puts `sda` on the user PATH and `sda --version` answers,
  the workbench opens, and a silent uninstall removes everything and restores the
  registry PATH byte for byte. `externalBin` is not in `tauri.conf.json` because it
  fails the build when the file is absent, which would break `cargo test` on a fresh
  checkout. The packages with no licence text appear in the notices as recorded
  exceptions.
* **`{files}` tools run once per file,** on every core, with
  `ExternalAdapter::timeout` bounding the whole run. A crash costs that file and is
  named under NOT CHECKED. Paths are absolute; the first real run lost every file
  to `src/src/...`, which a fake tool in a test had not shown.
* **clang-tidy's exit status now means something.** The adapter passes
  `--warnings-as-errors=-*` and `-Wno-error`: PX4's `WarningsAsErrors: '*'` and
  `-Werror` turned GCC's `-Wlogical-op` into a location-less error, so 947 checked
  files looked failed. The cost is that a project's promoted findings arrive as
  warnings. A file reporting `clang-diagnostic-error` now counts as not fully checked.
* **clang-tidy runs only on files with a compile line.** Others had flags guessed from
  a neighbour, and 4,146 of 5,120 PX4 files stopped at a compile error and left partial
  parses reading as findings. The report states how many were left out.
* **`CompilationDatabase::for_file` matched too loosely.** It ignored `directory` and
  compared raw string suffixes, so `bar.c` covered `foobar.c`. Fixed, which also
  corrects the coverage figures for databases with relative entries.
* **`ArchitectureDeclaration::warnings()` had no caller but tests**, so a mistyped
  flow edge left the proof silently. It reaches the report now, as do `parameters`,
  `sequence_bound` and `input_region` where nothing reads them, and an imported
  rule's `s = "system"`. `Deviation::raised` now appears in the citation.
* **The README's artifact example** is `fake_instrumented.bat`, which writes probe
  records by hand, and now says so. The real-binary paragraph after it describes an
  MSVC build that is not in this repository.

## 1.0.0, and what is still open

**1.0.0 is the first public release, built on this machine and unsigned.** The
release workflow had not run (billing blocked it), so the artifacts were built
locally by the recipe the release candidates used. They were uploaded with `gh`,
with a `SHA256SUMS` file.
There are no macOS artifacts, the `.deb` and AppImage need glibc 2.39 because they
were built on Debian 13 rather than the workflow's Ubuntu 22.04, and the FreeBSD
CLI was not run on FreeBSD. The README and the release notes say so.

**The public history starts at 1.0.0.** Until rc.1 the MISRA catalogues carried
a `t =` title for every guideline, 210 for C and 54 for C++. The header called
them paraphrases; nobody had compared them with the licensed text, and many read
as guideline sentences. 163 of the 180 commits held them. The owner chose to
publish a single root commit holding the 1.0.0 tree instead. The old history,
with the rc.1-rc.4 tags, is kept off GitHub in `E:\sda-release\history\`, as a
git bundle and a local branch. Before the flip, a pre-publication audit also:
* reworded the four headline-shaped quotations left in the tree;
* found no credential anywhere in the history;
* found nothing a fork's pull request can reach in either workflow;
* added `SECURITY.md`, which routes reports to GitHub's private vulnerability
  reporting.

`CHANGELOG.md` exists, the release workflow takes each tag's notes from it, and
`the_changelog_has_the_version_being_built.rs` fails the gate when the version
being built has no section, rather than four platforms into a release run.

**Only the owner can do these:**
* **Signing.** A Windows certificate, and an Apple Developer ID with
  notarisation for macOS.
* **macOS.** A decision on the objc2
  redistribution question before the GUI ships there; the CLI does not link
  objc2.
* **A security contact beyond GitHub's private reporting**, if one is wanted.
* **Legal review of the bundled notices**, and a real icon.
* **Repository settings** the tree cannot hold: a `v*` tag ruleset and a
  `release` environment for `release.yml`'s write job, and approval for
  outside contributors' workflow runs.

**Checks that need a machine this one is not:** the FreeBSD CLI on FreeBSD,
the AppImage under FUSE rather than extracted, and the firmware on real silicon
rather than QEMU.

**Engineering an agent can do, none of it blocking:** the oracle gaps under
*Suggested next steps*. The workbench's panes and buttons are all driven by a
harness now, including unassigning (an emptied Assignment field) and the
`agent` button. What none drives is setting `sda.me`, which no control writes
(it is read from localStorage only).

**The coverage gutter had never shown anything.** `coverage_for` read the
`executions` metric from each finding's evidence, and the correlation engine
puts it on the correlation (`correlate.rs`, beside `adjust`), so every scan
served an empty list and the gutter stayed blank, including scans whose probe
had measured the very lines with findings. A third harness,
`gui/tools/drive-panes.mjs`, found it: written by an agent to cover grouping,
the terminal pane and the gutter, it failed on the gutter against the release
build. `coverage_lines` now reads the correlation and finds the location through
its finding id; a GUI test pins measured, measured-at-zero, unmeasured and
other-file cases. The harness's probe is a batch file writing `cov` records, so
the measurement is synthetic and everything after it is the real path. It now
passes; its three expectations were each broken once and seen to fail.

**The workbench has a capability file now.** `gui/src-tauri/build.rs` names the
18 commands in an app manifest and `gui/src-tauri/capabilities/main.json` grants exactly those
to the `main` window, with no core-plugin permission at all. Probed over CDP on
the release build: `baseline_info`, `terminal_start` and `terminal_read` answer;
`plugin:app|version`, `plugin:window|set_title`,
`plugin:webview|create_webview_window` and an unknown command come back "not
allowed by ACL". Both harnesses pass. A GUI test fails if `generate_handler!`,
the manifest and the grants ever disagree; it was seen to fail with one grant
removed. `permissions/autogenerated/` and `gen/schemas/` are written by the
build and committed, as `gen/` already was.

**Fourteen `native` MISRA C guidelines passed code that breaks them.** Each
was found by writing the plainest violation the check's own code did not
anticipate, and scanning it with `--min-severity info`. Two checks firing on
their ordinary cases served as the control. Ten were structural bugs and are
fixed, each with a firing fixture and a near-miss:
* 16.3 took any `break` in a clause as its end;
* 16.2 let any enclosing `switch` legitimise a label;
* 15.4 counted a do-while's `while` as a loop;
* 12.3 looked only in control headers;
* 13.3 and 13.4 knew five assignment operators of eleven, and 13.4 never read a
  do-while condition;
* 13.6 read only a parenthesised operand;
* 17.6 missed `[const static N]`;
* 18.5 counted only adjacent stars;
* Dir 4.12 saw only calls.

Five checks would need machinery the engine lacks. They are `partial` now, so
the native count is 65:
* 21.1 needs the standard library's full list of reserved names;
* 6.2 needs typedef resolution;
* Dir 4.3 uses a two-statement threshold for "isolated";
* 11.9 needs operand types to see `p == 0`;
* 2.5 never judges a header's macros, and nothing looks across the project.

A second pass over eight more candidates fixed two omissions:
* 8.14 now knows GCC's `__restrict__`;
* 21.6 now knows the rest of `<stdio.h>`'s functions, except `remove` and
  `rename`, which are too often something else.

Two candidates were left alone:
* 21.12 on `fegetround`, because the guideline may cover only the exception
  features;
* 21.10 and 21.3 on a function taken by address, because `time`, `free` and
  `clock` are common variable names and the engine has no scope analysis.

Two behaviour changes came with the fixes:
* the comma between declarators in `for (int i = 0, j = 0; ...)` is no longer a
  12.3 finding;
* 12.3 now reports `expressions.c:25`, which cppcheck's capture does not, so
  `misra_agrees_with_cppcheck.rs` lists it as this engine reporting more.

Scans before and after the change found no other difference. The trees
scanned were the repository's C (examples, `gui/tools`, the shim, the MISRA
corpus), Assimp, CMake's modules and the C in the npm cache. The scans also
caught one false positive, which is fixed: an `__attribute__((section(..),
used))` list.

Known limits:
* 15.4 counts only braced loop bodies; an unbraced one is a 15.6 finding;
* 12.3 cannot see a typedef-name cast;
* 21.3 has the same call-only gap that Dir 4.12 had.

**Release mechanics for the next version:** bump the version in
`Cargo.toml`, `gui/src-tauri/Cargo.toml`, `gui/src-tauri/tauri.conf.json`,
`gui/package.json`, `gui/package-lock.json` and both `Cargo.lock`s, and in the
README's install and security sections; `git grep -n` for the old version finds every one.
Rename `[Unreleased]` to `[1.0.0]` with the date, run `bash tools/verify.sh`,
tag, push the tag, and publish the draft the workflow makes.

## What the last session did, in one page

**One method: find a claim nothing checks, then check it.** The session before
held components to the real implementations they claim to match. This one turned
the same question on everything in the system that *asserts* something — the
document's own numbers, the conformance record, the public API, the report's
promise about what it did not do, and finally the rules themselves.

It found fourteen defects, then seventeen more when the same question was turned
on the report, on the document, and on the toolkit's own public interface, and
then ten more again after two features were added and the question was turned on
those. Thirteen more followed from one narrower question: which of the
project's own recorded decisions reach this command, and which stop at the scan.

**Claims nothing re-derived.** Three catalogue standings were wrong at once —
MISRA C++ said twelve compared where it was fourteen, Rust nine where it was
eight, the MISRA C tier table fifty-six where it was fifty-five — and each error
left a mark on the page: the C++ sentence named seven rules and filled the gap
with "and two others", the Rust sentence said "nine … the eight left" and listed
eight, which adds to seventeen and hid a missing `UNSAFE.3`. The verification
instructions were **280 tests low**, telling the next session to expect
`803 tests across 41 binaries`, against which a real regression reads as a
surplus. All of it is derived from the fixtures and the tree now.

**Things that computed an answer nobody consulted.** `DeviationRegister::is_expired`
and `expired()` were correct, unit-tested, and never called, so an acceptance that
lapsed in 2020 went on hiding its finding — a register with expiry dates told a
safety team its acceptances lapse when none ever would. `coverage_gaps` said a
coverage hole "belongs on a different work queue" and was on no queue at all, and
was wrong besides: it paired correlations with findings by position, and the two
stop being parallel at the first suppressed finding. Three files recording a
human decision were read without checking — a project's own catalogue override
discarded both its read and its import error, so `rules audit` described a
catalogue the project had tried to replace, and the workbench turned a corrupt
review file into an empty one, which is the state that gets a finding dismissed
twice. One unreadable file zeroed the whole C analysis: both native analyzers
read sources with `?`, so a single file that is not valid UTF-8 — a Latin-1 `©`
in a copyright line, ordinary in legacy C — failed the entire provider.

**Rules that fired on code that conforms.** The fixtures prove a guideline fires;
nothing proved one stays quiet, and a rule that fires on everything passes its
fixture. Near-misses — sources that look like a violation and are not — found
five: `D4.9` told `#define STRINGIFY(x) #x` to become a function, which the
language cannot express; `FFI.1` judged the extern *block* and not the
declarations inside it, so documenting each function where it is written did not
count while one comment above the block covered several undocumented ones;
`8.2.3` reported a `const_cast` that *adds* const, which the guideline permits,
putting a deviation for an unviolated rule into a conformance argument;
`21.10.2` read an identifier without looking at the token before it, so
`b.signal(1)` — and `logger.printf(..)`, and every driver op table in embedded C
— was a library call; and `DEP.2` called `src/build.rs` a build script, which
Cargo never runs.

**The instruments were wrong more often than the code was.**
`uncalled-api-sweep.py` needed calibrating twice — first reporting 1 uncalled
function of 654 because every definition counted as its own caller, then five
*wired* tool parsers as dead because an indented `#[cfg(test)]` made it read half
a file as tests. One bug said *nothing is wrong*, the other *something is wrong
that isn't*. The count test written to catch a hand-count did not check the
hand-count. The unused-deviation notice was twice the exact error it was written
to prevent. Three near-miss drafts were secretly violations, which would have
"found" defects that do not exist and silenced rules that work. **Only running
each against a known answer told them apart**, and nothing here should be
believed before that is done to it.

**Then the report, which is the product.** A scan that finds everything and says
it badly has failed at the only thing this tool sells. Configuration the project
asked for and did not get — a rejected architecture component, a scope rule, a
catalogue that would not parse — was printed as a `warning:` on stderr and went
nowhere else, so `--format json` saved a run with no trace of it and an
interposition proof over a graph one node smaller than the declaration. An empty
interposition result was rendered "no model reaches a declared effector by any
declared path" for a declaration naming no model: a claim about models and paths
made of neither. SARIF told a CI system that `sda.interposition` "did not run"
when it had run and concluded nothing — the difference between a check skipped
and a check with nothing to say, asserted wrongly in the format meant for
machines. `report.query` counted its matches *after* a two-hundred cap, so five
hundred matches answered `200`, to an agent that cannot glance at a summary to
catch it. And the text report listed five hundred findings and stopped: on PX4
that is **77,711 dropped in silence**, twenty lines above a block that already
wrote `(+N more)` and got it right.

**Two of those were the section itself becoming unreadable**, which is the same
failure wearing the opposite mask: nothing concealed, just said sixty times.
`sda.unmapped` was one paragraph per unmapped file — sixty of seventy-seven lines
on a small fixture — and `sda.taint-untraced` one per taint finding. Both are
counted now, and both were found by asking the question of *every* notice rather
than the one that hurt: `tools/notice-bounds.py` reports the loop enclosing each
push, and the two that scale with the input stand out from the thirty-one that
are bounded by something a person wrote.

**The instruments were wrong again, twice.** The test that guards the document's
own test count failed correctly when the tree outgrew it, and failed with
`attempt to subtract with overflow` — true, useless, and silent about which of
four numbers to change. The invariant test written for the interposition work
passed under mutation, because it checked that *something* was said rather than
that the right thing was: a vacuous entry satisfied it. That is the failure this
document catalogues, committed inside a test written to catch it. Sixth and
seventh instruments to be wrong the first time they met a real answer.

**Then the document, which is the handover.** Eighteen measurements were dated
"this session", written across five sessions between 2026-09-03 and 2026-09-16
and all reading as current — which is how a PX4 figure of 15,528 came to look
like a contradiction of the 78,211 the same tree produces now. A baseline read
`HEAD~13`, which pointed somewhere else after the next commit. The first page
said the remaining gaps needed an `apt` password, two thousand lines from the
body explaining that they never did. All three are the document's own failure
mode: information that existed, thrown away on the way to the reader in favour of
something true only at the moment of writing. All three now have a test.

**And what the document got right, recorded because a clean result is a result.**
Every one of fifty-four file paths it names exists. Seventy-nine of eighty symbol
paths resolve, and the one that does not is a rename the document is *describing*.
Both figures for PX4 reproduce exactly — 78,211 raw and 73,401 distinct — which
also proves that seventeen commits of report-layer work moved nothing in the
analysis across 20,287 files.

**Last, the toolkit's own interface.** A file that would not tokenise was a
finding rather than a gap: `plain.c` yields three MISRA findings and the same
function behind an unclosed `/*` yields none, with *NOT CHECKED* silent. Rust was
quieter still — no finding either, and the lexer had been computing the fact
needed to report it since the day it was written. Two of `RunOptions`' three
knobs were honoured by nothing, one of them documented as a wall-clock budget.

**Then two features, and the method turned on them immediately.**
[repowise](https://github.com/repowise-dev/repowise) answers *where do I start*
and *what else is downstream*, which a scan of PX4 answers not at all: 78,211
findings sorted by severity, confidence and then path. `sda hotspots` ranks
findings by churn; `sda impact` lists what names a file's symbols. Both reach
agents over MCP, and both carry their limits in the payload rather than in a tool
description read once when the list was assembled.

Each refuses something a naive version would assert. `git log` **succeeds** on a
shallow clone — measured, one commit naming 288 files — so a churn count built
from it calls the whole project settled; depth is asked before anything is
counted. A blast radius found by matching names misses every call through a
function pointer, so the answer is published as a floor, and the test fixture
contains the caller it cannot see.

**And then the method found seven more, four of them in code written that same
afternoon.** Show the tool something it has not been shown: a Rust file, a tree
nothing reads, an empty plan, a failed artifact, an untracked file, a header.
`sda impact` answered *"No other file names any of them"* about a Rust file while
a caller two files away called the function by name — **the defect it was built to
refuse, one commit after shipping, with six passing tests and a mutation-checked
caveat already in place.** A suite measures what somebody thought to ask.

**Two claims in this document were falsified while it was being written**, and
both cost a table row rather than a retraction because of how they had been
written down. The harness flake's retry "had never once worked, four times for
four" — the forty-sixth run retried and passed. And `rustc` crashed mid-session,
which the gate reported as failing GUI tests, because a crashing compiler prints
`error: could not compile` exactly as a type error does. Numbers recorded as
measurements with no mechanism attached survive being wrong; explanations do not.

**The project's declared position reached two commands out of six.** `.sda/`
is where a project records what it has decided: `.sda/scope.toml` names
directories outside analysis, each with a reason and a named approver, and
`.sda/deviations.toml` records findings that were reviewed and accepted. `sda
scan` honours both. Six commands run their own discovery, and the declaration
reached two of them.

So `sda hotspots` ranked a file the project had formally excluded **first** —
under a heading offering the files worth looking at first — because it carried
the most findings, findings the scan refuses to report at all. The same command
counted accepted findings as live: two files with four live findings each ranked
**8 against 4**, the deviated one on top. `sda plan`, whose entire job is to say
what the run will do, promised a C++ analysis step for a project whose only C++
was excluded. A fuzzing campaign's verdict table re-raised precisely what the
deviation register had settled, past a refusal written into `correlate` for that
purpose — which never fired, because nothing in that run was ever marked
suppressed.

None of these is a missing caveat. Each is a second view overruling a recorded
decision, and the overruling view is the one that looks actionable.

**The helper existed, and its own doc comment said why.** `project_setup` was
written after two call sites drifted apart, and it says so: *shared rather than
repeated, because the two call sites drifted precisely while nobody was
comparing them*. Three call sites written afterwards repeated it anyway, each
picking up part of the project and not the rest. The diagnosis was correct,
recorded in the right place, and prevented nothing — the same relationship
between prose and checking that this document keeps finding elsewhere, here
between a comment and the code beneath it. There are now guards for both
shapes: a run over a project loads the register or goes through the helper, and
a command that discovers its own files either applies the scope or is named,
with its reason, in a list that has to be edited deliberately.

**Sweeps, not instances.** Four are in `tools/` now — uncalled functions, unread
fields, unbounded notices, and the symbols this document names — because the same
defect keeps being found by accident, and the third time is the signal to go
looking. Each needed calibrating against a known-bad answer before it was worth
reading, and each found something real once it was. **The count of instruments
that were wrong the first time they met a real answer reached ten.** Nothing here
should be believed before that has been done to it.

**What holds the work up.** Every narrowing was checked against the pre-session
binary over three real trees — `llama.cpp/src`, `bibutils`, `PX4-Autopilot/src`,
20,620 files and 83,684 findings. 478 findings disappeared and **none appeared**;
all 478 were verified, the 429 macro ones mechanically. Eighteen checks that fired
zero times on PX4 were each put in front of their construct and shown to work.
The near-miss table covers every implemented check or says why it cannot, and a
test enforces that.

**And the process.** A commit went in with a failing suite, for the third time in
one session, having been written up twice. `tools/verify.sh` runs the five checks
this repository asks of a commit and fails as a unit; it refused a commit within
minutes of existing, and has refused several since. A checklist you follow by hand is a check that did not
happen, presented as one that did.

**This page has now gone stale four times in one session**, and has been rewritten
four times to match. That is not a complaint about the writing: it is a derived
value maintained by hand, sitting on top of the most-edited document in the
repository, and every other derived value here that could be checked by a test
eventually was. The counts, the dates, the cross-references, the file paths and
the failure-mode total all have one. This summary does not, and the reason it
keeps rotting is that nothing objects when it does.

Whoever reads this next and finds it wrong again: that is the expected behaviour
of an unchecked claim, described by the document it is at the top of.

**What is left.** Not much that effort can buy. The remaining gaps need the
licensed MISRA text, a third MISRA tool, or real silicon. *Not* an `apt`
password: this page said that, and it was the same misreading the body corrects
twice — `wsl -u root` needs no password, cppcheck and clang-tidy were only ever
waiting on somebody asking, and both are installed. A first page that contradicts
its own document is worse than one that says less.

The cheap defects are in places this codebase asserts something and nothing
re-derives it — and after this session most of those places have a test standing
over them. The report layer was the largest such place and has now been swept;
the sweeps themselves are in `tools/` and are the cheapest thing here to run
again.

### The session before that, held to the real implementations


**One method, applied until it stopped paying: take a component whose
correctness rests on agreeing with something else, and ask that something else.**

Sessions before it ran the toolkit against real *inputs*. That one ran its parts
against the real *implementations* they claim to match — clang, rustc, Monaco,
the SARIF reference validator, the MCP reference client — and against scale and
hardware the earlier work had left as claims.

What that found, in order of how badly it would have hurt:

* **The Rust lexer disagreed with rustc four times**, on ordinary Rust: C string
  literals (`c"..."`), signed float exponents (`1.0e-3`), raw identifiers (`r#fn`,
  whose `fn` was then classified as the *keyword*), and non-ASCII identifiers
  (`café`). Every native Rust finding rests on that lexer.
* **The C++ lexer got `<::` wrong**, so `std::vector<::Foo>` lexed as
  `vector[:Foo>`.
* **The Monaco port disagreed with Monaco three times**: a trailing newline does
  open a final line, columns are UTF-16 and were characters, and `Stickiness` had
  three names but two behaviours.
* **`sda build compile-commands` could not produce a compilation database at
  all** on a default Windows install — CMake ignores the export flag for the
  Visual Studio generator — and `sda build detect` printed that same command to
  the user as the fix.
* **The SARIF `$schema` had been a 404** since the OASIS repository renamed its
  branch, and the source snippet the engine already collects was dropped at the
  boundary, so every other tool saw a line number and no code.
* **`ExternalAdapter::timeout` was never read.** A public field with a ten-minute
  default whose entire purpose is to bound a hung tool, while `analyze` called
  `Command::output()`, which waits forever.
* **A tool's account of its own degraded analysis was filed as findings.**
  cppcheck said 321 times that it could not resolve an include or had checked 12
  of 17 configurations; all of it landed as `information`-severity findings, which
  the first filter anyone applies throws away, while *NOT CHECKED* stayed empty.
* **A quiet dynamic tool went unnamed whenever coverage was supplied**, so 492
  findings came back `refuted` with nothing saying which tool had looked.

And what it established that had only been claimed:

* **The instrumentation runs on a Cortex-M3.** A freestanding image, `-nostdlib`,
  no compiler runtime, 2.2 KB of text, executed under QEMU; the records it wrote
  to the board's UART are correlated by the engine. That needed a new ingestion
  path — `--observation` — because none existed: `--artifact` *executes* a
  program, which is the one thing a host cannot do with firmware.
* **All three of item 12's scale gaps**, none of them with PX4: cppcheck and
  clang-tidy over 184 real C++ files, a 217-entry compilation database configured
  out of tree, and a full statodynamic run over `bibutils` — 6,881 findings,
  refuted 492, unreached 5,501.
* **The MCP surface passed the reference client on first contact**, the only
  component to manage it.
* **The MISRA rules met a second implementation — and the coverage
  classification, which `sda rules audit`'s conformance claim rests on, was
  wrong once.** cppcheck's MISRA addon has the type information this toolkit does
  not. On the first two files every guideline it found and this one missed was
  already classified `semantics`; widening the corpus by two twenty-line files
  found **12.1 marked `native` while checking two operator pairs of an
  open-ended guideline** — `sizeof cmd - strlen(cmd)` read clean. It is now
  `partial`, and covers that trap. Nothing has audited the classification itself;
  this was found by a second implementation happening to look at a file.

**The base rate, updated.** Ten of eleven adapters failed their first meeting with
a real tool. This session: the SARIF exporter, both lexers, the Monaco port and
`sda build compile-commands` all failed theirs; MCP and the multi-cursor edit path
passed. A component that has never met the thing it claims to match has not been
tested, however green its own suite is — and *its own suite is written by whoever
held the misunderstanding*.

**Where the method stopped.** The last three oracles — MISRA 15.5's return
counting against clang's AST, and then the whole MISRA rule set against
cppcheck's addon — found nothing wrong. The yield is falling, and the items still
open are blocked on things effort cannot buy. The only numbered item still open
is **22**: nothing has run on silicon. Outside the numbered list, settling the
one remaining MISRA disagreement (`21.6` on `#include <stdio.h>`) needs the
licensed document. The cheap move still on the table is *more
corpus*, not more oracles: two C files exercise a dozen guidelines out of
hundreds.

**It said three things that had stopped being true.** Monaco's validating
`TextModel` layer was listed as needing a DOM; item 24 is struck through and
says in terms that *the reason it was thought impossible was wrong* — the DOM is
not needed, no position code touches it, and the dependency-injection container
turned out to be three stubs the compared methods never call. That refutation is
written at the top of `gui/tools/monaco-model-oracle.mjs`, which exists because
of it.

**And it said PX4, long after PX4 was built.** All 21 submodules were
initialised and the SITL configuration completed; item 23 records it in detail,
including the 744-entry database it produced. The sentence above went on naming
it as *uninitialised in a checkout this project does not own*, which had been
the reason and had stopped being true.

**The third is worth the most.** Item 22 filed an already-fixed defect as open
work under a heading marked *blocked on hardware* — the stack figure, which had
been measured under QEMU and whose high-water mark the failure-mode table
records. Filing a solved problem behind a blocker is the most effective way
there is to stop anyone looking at it.

None of the three was wrong when written. A *blocked* label is a measurement with no
mechanism attached, and this document's own argument says those are the ones
that rot: nothing re-reads them, because the label is precisely a promise that
re-reading is pointless. They are checked now the only way they can be, by
somebody distrusting the word and trying it — which is how the SARIF fidelity
gap came off this list an hour earlier, using a validator this document names
twice.

### And the one before, whose lessons the sessions since have repeated

Two things, and the second was not planned. The **workbench became a review tool**
rather than a results viewer, and the **backlog of "run it against the real thing"**
items was worked to the end — which cost ten defects, every one of them in code
that was green.

#### Every adapter has now met its tool, and none of them survived

`ext.miri` and `ext.codeql` were the last two that had never been run. Both were
wrong, in the same shape the others were:

* **Miri writes its findings to stderr, in prose.** The spec declared
  `ClippyJson` on **stdout**, because `cargo miri test --message-format=json`
  looks like `cargo clippy --message-format=json`. It is not: that flag governs
  *cargo's build* messages, while the undefined-behaviour report is produced at
  **run** time by the interpreter. A real run writes `"success":true` to stdout
  and the violation to stderr. New `OutputFormat::MiriText` and `parse_miri`;
  `parse_gcc_like` would not have worked either, since rustc puts the location on
  the line *after* the message. It also invoked `cargo miri` on the default
  toolchain, where Miri cannot exist — now `cargo +nightly miri`.
* **CodeQL does not read `-` as stdout.** The spec asked for `--output=-`; CodeQL
  creates a **file literally named `-`** in the working directory, writes the
  SARIF there, prints a prose coverage line to stdout, and exits 0. So the adapter
  parsed that sentence as SARIF, could never produce a finding, and littered the
  repository on every run. Now `--output={output}`, and a spec-level test forbids
  any adapter from naming `-` as an output destination.

Chasing the second one found a **general** defect: `{target}` was substituted with
the path as the user typed it, while the child is spawned with
`current_dir(&target.root)` — so `sda scan crates` ran the tool from inside
`crates` and told it to analyse `crates/crates`. **Every `{target}` adapter was
broken for a relative path**, which is the ordinary way to invoke the CLI; the
earlier real-tool runs all happened to use an absolute path or `.`. Now
`std::path::absolute`, deliberately not `canonicalize`, whose Windows `\\?\C:\...`
form several of these tools mishandle.

**Fixture provenance is now data, not a comment** — `Provenance::Captured(version)`
or `Reconstructed` on every entry, with tests that a Python-CLI adapter may not
rest on a reconstruction and that the reconstructed set is **empty**. Comments
about provenance have been wrong twice in this repository, and it is the single
fact this file most needs to state accurately.

The tally to carry forward: **ten of eleven real-tool encounters found a defect,
eight in adapters that were fully green, fixture-tested and passing a clean
self-scan.** That is the base rate. It is not a run of bad luck and it is not a
statement about these particular tools.

#### The workbench

The findings list rendered every finding as a full-message card — about seven rows
visible, and PX4's 14,284 findings would have been two thousand screens with no way
to narrow them. It now has faceted filters with live counts, grouping, a windowed
list, keyboard navigation (`j`/`k`, `1`-`4` to triage, `/` to filter), resizable
panes, and a severity *letter* beside the colour so the cue survives a screenshot.

Filtering is a **view**: `findings` is never mutated, the header count always
reports what the scan produced, and nothing a filter does reaches a report.

**The detail pane shows the evidence.** `UiFinding` carried fourteen fields and
none of them was evidence, so the engine computed CodeQL dataflow paths, Miri's
created/invalidated chain and the Memcheck event behind a `confirmed` verdict —
and the UI could render a coloured chip and nothing else. A reader could see the
conclusion and had no way to ask why. It now carries the CWEs, the remediation, the
**correlation rationale**, and flattened evidence, with taint steps as a numbered
clickable path that jumps the editor.

**Three files, shared by people and agents.** All under `.sda/`, all diffable, all
written by the workbench *and* by an agent over MCP:

| file | what it holds | MCP tool |
|---|---|---|
| `triage.toml` | review state, assignee, discussion | `analysis.triage` |
| `baseline.toml` | the findings a previous run produced | `analysis.baseline` |
| `deviations.toml` | approved departures (pre-existing) | — |

A person and an agent are the same kind of thing to the store — `a.erickson` and
`agent:triage-bot` — so a human can hand a batch to an agent and read back what it
concluded, in the file they are already looking at. There is no server between
them, which is what makes the review arrive in a pull request beside the code.

#### The invariants that cost the most to get right

* **Triage annotates; it never hides.** A triaged finding still appears in every
  report and still counts toward every exit code. Suppression is a *deviation*,
  which needs an approver, a rationale and a catalogue check.
* **Assigning and commenting conclude nothing.** An assigned finding is still
  unreviewed. A distributed queue is not a reviewed queue.
* **A verdict never eats the discussion.** `set` replaced the record wholesale,
  discarding the assignee and the whole thread the moment anybody pressed a
  button. It now merges.
* **A baseline is never written automatically.** One refreshed by every scan
  reports zero new findings forever and looks like it is working.
* **No baseline means *unknown*, not *not new*.** `is_new` is `None`, the MCP field
  is `null` rather than `0`, and the UI disables the facet and says so. A
  comparison nobody made must not be reported as one that came back clean.
* **`fixed` is not a triage state.** Whether a defect is gone is decided by the
  next scan, not a checkbox. Records whose finding vanished are reported **stale**
  rather than deleted, because *fixed* and *moved and now unreviewed* are
  indistinguishable from here.

#### Three things that session got wrong, and how they were caught

Worth reading, because each was a *confident* wrong answer that survived a while.

1. **The GUI harness was driving a five-week-old binary.** Its default path was
   `gui/src-tauri/target/release/`, which is not where cargo writes on a machine
   with a shared `CARGO_TARGET_DIR`. Every GUI run earlier in the session —
   *including two "cold start" runs recorded as evidence that engine changes had
   not moved a glyph* — tested a binary from 12 August. Worse, a bare
   `cargo build --release` does not embed the frontend at all; it loads the Vite
   dev URL. The workbench must be built with `npx tauri build --no-bundle`. The
   harness now resolves the binary through `cargo metadata`, prints it with its
   mtime, and **refuses one older than the frontend sources**. Pointing it at a
   current binary immediately found a regression the UI rewrite had introduced:
   `className` had become `inlineClassName`, losing every squiggle.
2. **A flaky test was blamed on a stale build.** `external_dynamic_refutes.rs`
   shares one temp directory across four tests that `cargo test` runs in parallel,
   so they overwrote each other and a different subset failed each run. It was
   written off twice — once as a slow scan, once as a stale artifact — before
   being read properly. A failure that appears only in a parallel run is *more*
   likely a shared-fixture race than a build problem, and "it passed when I ran it
   alone" is the symptom, not the refutation.
3. **`Stop-Process -Name cargo,rustc -Force` was run against other people's
   work.** See *Do not kill cargo processes on this machine*. The build-lock wait
   was normal; the processes belonged to unrelated repositories in other sessions.

#### What was deliberately not built

* **No server.** Coverity and SonarQube keep owner and thread state in a database
  behind a web UI, and multi-user access is what that buys. A file in `.sda/` buys
  something else: the review is diffable, arrives with the code, and `git log`
  already answers *who said this*. Concurrent edits merge the way every other text
  file does. Revisit only if someone needs live presence or cross-repository
  dashboards.
* **No assignment validation.** There is no user directory to check a name
  against, and inventing one would put a server between a team and a file they can
  already review.
* **`analysis.statodynamic` still builds no project registry of its own** — it now
  shares `project_setup` with `analysis.scan`, so it gets catalogues, deviations,
  scope and architecture, but the MCP surface has no separate registry story.

## Where it stands

The third column says **when the measurement was last actually taken**, and it is
worth reading rather than skimming. Every row used to say "this session", which
was true when the table was written and became false the moment the document was
restructured for a new one — a green figure attached to a date that had moved
under it. Rows marked *in the suite* are re-checked by `cargo test` on every run,
so their date is always today; rows marked with an earlier date were measured
once, by hand, against a tool or a corpus that is not part of the suite.

| | | measured |
|---|---|---|
| Workspace tests | 1,101 across 90 binaries, all passing (1,099 `#[test]` functions and 2 doctests) | 2026-11-03 |
| GUI backend tests | 19, all passing (separate crate, `gui/src-tauri`) | 2026-11-02 |
| `sda-editor` tests | 49 unit + 17 against real Monaco, all passing | in the suite |
| Compiler warnings | 0 | 2026-10-30 |
| Self-scan (`sda scan crates`) | clean — 0 unsuppressed, 4 deviations | 2026-11-02 |
| Self-scan (`sda scan crates --with ext.clippy`) | clean — 0 unsuppressed, 4 suppressed | 2026-11-02 |
| Self-scan (`sda scan shim --min-severity info`) | clean | 2026-11-02 |
| Self-scan (`sda scan tools`) | clean — the whole tree is declared out of scope; see below | 2026-11-02 |
| GUI harness (`node gui/tools/drive-cdp.mjs`) | PASS, against a binary rebuilt the same day | 2026-11-02 |
| GUI harness (`node gui/tools/drive-review.mjs`) | PASS, against the same binary, now including assignment, `mine` and comments | 2026-11-03 |
| GUI harness (`node gui/tools/drive-panes.mjs`) | PASS: grouping by file, rule and verdict, a typed terminal command, and the coverage gutter against `coverage_for` and the probe | 2026-11-02 |
| Cortex-M3 image, run under QEMU | 12 records captured and correlated; `stack_bytes` 632 at `-O1`, rebuilt with `arm-none-eabi-gcc` 14.2.1 | 2026-10-31 |
| `sda` built for Linux | first non-Windows build; 4.8 MB, 38 s in WSL Debian with dependencies already fetched | 2026-10-30 |
| PX4 scanned on both OSes (all submodules, `--min-severity high`) | 15,528 findings each, 0 rules differing; predates later rule changes, so not comparable to today's 18,949 on Windows | 2026-09-14 |
| `PX4-Autopilot/src` on both OSes | 78,211 findings each, all four severity counts identical; 73,401 distinct | 2026-10-30 |
| `PX4-Autopilot/src`, after the 4.2, 6.3 and 21.3 changes | 78,196 findings, 73,386 distinct: 129 6.3 removed, 114 added from macro bodies, 0 trigraphs. Windows and Linux binaries at `760cea7` agree on every count | 2026-10-31 |
| PX4 `src` on the Linux filesystem, native scan | 35 s and 206 s on two runs against 2.2 GB in `/home/test/PX4-native`, the second with other work on the machine; same counts as the Windows scan | 2026-10-31 |
| PX4 compilation database (WSL, SITL) | 744 entries reproduced, configure 110.7 s; covers 474 of 3,238 sources under `src`. The 538 of 12,463 whole-tree figure is from 2026-09-14 and was not re-measured | 2026-10-31 |
| Type-aware PX4 from Linux (`control_allocator/ControlAllocation`) | `ext.clang-tidy` 81 findings with the SITL database, 0 without — provider refuses and says so | 2026-10-31 |
| Type-aware PX4, all of `src` | completes, 31 min on 8 threads against the SITL database with generated headers built (`make -k -j8`, targets for uORB, mavlink, version, events and micro-xrce; `empy` pinned to 3.3.4 in the WSL venv, since PX4 allows 4.x, which breaks its generators). clang-tidy 19.1.7 ran on the 474 files with a compile line: **473 finished, 1 did not compile (PX4's SMBus driver, `expected class name`), none crashed, none timed out.** 99,177 findings in 491 files, 54,595 distinct by rule, file and line. The other 4,646 of 5,120 C/C++ files have no compile line and were not run. PX4's `.clang-tidy` applied, so most are style (`hicpp-uppercase-literal-suffix` 74,647). None were reviewed |
| `ext.cppcheck` on Linux vs Windows (`bibutils`) | native 8,552 = 8,552, 0 differing; cppcheck 956 vs 925, every difference a tool-version change | 2026-09-16 |
| Narrowings checked against `65e5c83` | 3 trees, 20,620 files, 83,684 findings; 478 removed, 0 added, all verified | 2026-09-16 |
| MISRA rules vs cppcheck 2.21.0 | 26 files, 267 cppcheck findings; ten defects found. 6.3, 7.6, 8.16, 8.17, 17.10, 21.24 and 21.25 are not in the addon, so nothing second has looked at them | in the suite |
| Cross-file 5.1/D4.5 (PX4, 697 C files) | 4 findings, all confirmed by hand; 0 false positives | 2026-09-14 |
| `sda-editor` vs real Monaco 0.52.2 | buffer, model validation, stickiness and edits: 4 oracles | in the suite |
| `RUST-2024-PANIC` vs clippy 0.1.98 | 7 sites; one defect, one difference written up | in the suite |
| `RUST-2024` unsafe/edition vs rustc | 6 guidelines; 5 agree line for line, 1 written up | in the suite |
| MISRA C++ vs clang-tidy 21.1.6 | 12 guidelines; one defect, three differences written up | in the suite |
| MISRA C++ 5.7.1 / 5.7.2 vs clang | the C oracle, taught which catalogue it is reading | in the suite |
| MISRA 2.6 / 3.1 / 3.2 / 11.10 vs clang 21.1.6 | warnings and one constraint error, line for line | in the suite |
| `sda-syntax` vs real clang 22.1.8 | 13 lexical corpora, token for token | in the suite |
| `sda-syntax` vs rustc's own lexer | 14 lexical corpora; four defects found | in the suite |
| `CFunction::returns` vs clang's AST | 10 cases, returns per function | in the suite |
| `rstruct` vs syn | 26 cases: `unsafe` extents, item kinds, attributes, panic sites | in the suite |
| Directive extents vs clang | 11 cases, including two continuations | in the suite |
| Scale (`llama.cpp/src`, 184 files) | cppcheck 1,453 findings / 4 min; clang-tidy 7,752 / 36 min | 2026-09-07 |
| The same scan, re-measured | cppcheck **1,130** / 3 min — 1,453 less the 322 notices now routed to *NOT CHECKED*; the count reproduced | 2026-10-30 |
| The same scan, on Linux | cppcheck 2.17.1: 873; native engine identical to Windows, 0 differing | 2026-09-16 |
| Statodynamic at scale (`bibutils`, 105 files) | 6,881 findings; refuted 492, unreached 5,501 | 2026-09-07 |
| `sda build compile-commands` (llama.cpp) | 380 translation units, 61% of 574 files | 2026-09-07 |
| SARIF, validated by the reference tool | 0 errors, 0 warnings; 48 stated `note`s | 2026-09-07 |
| SARIF, repeated | `@microsoft/sarif-multitool validate` on a scan of `examples/firmware` (20 results): "Analysis completed successfully". That run printed no error, warning or note counts, and the version `npx` fetched was not recorded | 2026-11-01 |
| MCP, driven by the reference client | handshake, 21 tools, a call to `analysis.impact` carrying its floor, and both error paths | 2026-09-21 |
| MCP, repeated | `@modelcontextprotocol/inspector --cli` `tools/list` returns 21 tools. The `analysis.impact` call and the error paths were not repeated | 2026-11-01 |
| Rust edition / MSRV | 2024 / 1.88 | |

**The `tools` row is clean again, and for a stated reason rather than by
accident.** It used to report twenty findings, every one of them correct:
`tools/valgrind-wsl/three-sins/main.c` commits three memory-safety sins on
purpose, `vgwrap.c` calls `system()` by design, and `tools/codeql-taint-cpp/`
exists to give CodeQL a command injection to find. That was prose here, which is
to say a reader had to be told; `.sda/scope.toml` now says it, and the run prints
the claim and the number of files it removed in *NOT CHECKED*.

**Read that line rather than the clean summary.** A clean `sda scan tools` is now
a statement about the boundary of the product, not about the code in it — which
is exactly the distinction scope exists to make, and exactly the shape of thing
this codebase gets wrong when nobody prints it. Keep `crates` and `shim` clean on
their own merits.

The toolkit analyses itself and its own C shim, and `.sda/deviations.toml` carries
nine approved entries, all against catalogued guidelines. The one against an
external tool, `clippy::needless_range_loop`, was removed on 2026-10-31: the two
sites it excused no longer exist, so it matched nothing. The register still
accepts external ids.

Every figure above was measured, in this order, and re-measuring takes a few
minutes. **Do not kill a cargo process to get the lock** — see the section on it.

```bash
cargo test -p sda-editor                                               # 49
cd gui/src-tauri && cargo test && cd ../..                             # 19
cargo test --workspace                                                 # 1,101 / 90 binaries
cargo build --release                                                  # 0 warnings

# `$SDA` because the target dir is not ./target on this machine — one shared
# CARGO_TARGET_DIR serves every Rust project here. Python rather than jq: jq is
# not installed, and a documented command that does not run is worse than none.
SDA=$(cargo metadata --format-version 1 --no-deps \
  | python -c "import sys,json;print(json.load(sys.stdin)['target_directory'])")/release/sda
"$SDA" scan crates                                     # must stay clean
"$SDA" scan crates --with ext.clippy                   # must stay clean
"$SDA" scan shim --min-severity info                   # must stay clean
"$SDA" scan tools                                      # clean; read its NOT CHECKED line

# Scale, against someone else's checkout and read-only. cppcheck lives at the
# path in *This machine*; the database is configured out of tree so llama.cpp is
# untouched. clang-tidy over 184 files takes about 36 minutes.
CPPCHECK='C:\Users\adamm\tools\cppcheck-2.21.0\PFiles\Cppcheck\cppcheck.exe'
"$SDA" scan ~/dev/llama.cpp/src --with "ext.cppcheck=$CPPCHECK"       # ~1,450 findings
cmake -S ~/dev/llama.cpp -B /tmp/llama-cc -G "NMake Makefiles" \
      -DCMAKE_EXPORT_COMPILE_COMMANDS=ON                              # needs vcvars64
"$SDA" scan ~/dev/llama.cpp/src --with ext.clang-tidy \
      --compile-commands /tmp/llama-cc/compile_commands.json \
      --tool-timeout 3600                                             # ~7,750 findings

# The Cortex-M run, which needs WSL Debian with qemu-system-arm and
# gcc-arm-none-eabi. Rebuilds the image and the capture; both are gitignored.
wsl -d Debian -- bash -lc   'cd /mnt/c/<project>/examples/firmware-cortex-m && sh build-and-run.sh'
"$SDA" scan examples/firmware-cortex-m   --observation examples/firmware-cortex-m/build/capture.jsonl

# The workbench must be built by the Tauri CLI. A bare `cargo build --release`
# produces a binary that loads the Vite dev URL and embeds no frontend at all.
cd gui && npx tauri build --no-bundle && cd ..
node gui/tools/drive-cdp.mjs                           # PASS / FAIL, exit code set
node gui/tools/drive-review.mjs                        # the review surface; same contract
node gui/tools/drive-panes.mjs                         # grouping, terminal, coverage gutter
```

The two harnesses share `gui/tools/workbench.mjs` — launch, the staleness guard
and the confirmed scan click — so neither can drift into testing a different
binary from the other. They both bind the CDP port, so run them one at a time.

The harness resolves its own binary through `cargo metadata` and **refuses to run
one older than the frontend sources**. If it stops with `is older than
gui/src/main.js`, that is the guard working: rebuild rather than reaching for the
argument that overrides it. It exists because the harness spent this session
happily driving a five-week-old build and reporting PASS.

Count the total and assert it. Do not grep the log for "failed" — every `0 failed`
line matches, and that has produced a false alarm here twice. See *Verifying the
instrument*.

## Layout

```
crates/sda-core       findings, severity, taxonomy, SARIF, the Analyzer trait
crates/sda-syntax     C/C++/Rust lexers, line index, token spans
crates/sda-engine     native analyzers, correlation, dynamic engine, fuzzer
crates/sda-rules      guideline catalogues, deviations, project config (.sda/)
crates/sda-adapters   industry tools behind the same Analyzer trait
crates/sda-build      toolchain probing, compile_commands.json, diagnostics
crates/sda-probe      Rust probe instrumentation
crates/sda-ontology   the queryable tool ontology
crates/sda-ai         model artifact scanning, LLM risk taxonomy, probe suite
crates/sda-agent      MCP surface, deterministic planner, autonomous SWE loop
crates/sda-editor     Monaco's text model, ported to Rust
crates/sda-cli        the `sda` binary
shim/sda_probe.h      single-header C instrumentation for targets
gui/                  Tauri workbench: Monaco + embedded PTY terminal
gui/tools/            CDP harness that drives the built workbench and asserts
tools/valgrind-wsl/   harness for driving ext.valgrind from Windows via WSL
examples/firmware     a project with deliberate violations and a deviation file
```

## Running things

```bash
tools/verify.sh                             # the whole gate, as one command
cargo build --release                       # sda binary; NOT ./target — see below
cargo test --workspace                      # 1,101 tests across 90 binaries
cd gui/src-tauri && cargo test              # 16 more; not in the workspace run

sda scan examples/firmware                          # static only
sda scan <proj> --artifact <exe>                    # statodynamic, all four verdicts
sda scan <proj> --with ext.clang-tidy=<path>        # a specific external binary
sda fuzz <exe> --path <proj> --corpus <dir>         # coverage-guided campaign
sda swe <proj>                                      # one autonomous loop iteration
sda ai scan <dir>                                   # model artifacts
sda tools status                                    # what is installed, honestly
sda mcp                                             # JSON-RPC 2.0 over stdio
sda rules audit                                     # coverage, and the deviation split
```

Review state and the baseline are files, and both surfaces write the same ones:

```bash
# over MCP, as an agent
analysis.triage   {path, id?, state?, assign?, comment?, by?, note?}
analysis.baseline {path, set?, note?}
```

`.sda/triage.toml` holds review state, assignee and discussion; `.sda/baseline.toml`
holds the findings a previous run produced. Neither is written automatically and
neither hides anything — suppression is `deviations.toml`, which needs an approver.

The GUI needs `npm install` once in `gui/`, then `npx tauri build --no-bundle`.
**Do not** use `cargo build --release` in `src-tauri` to test the bundle: it sets
`cfg(dev)` and the window loads `http://localhost:5173/` (a dead dev server)
rather than the built assets. That mistake invalidated a "bundle loads" claim once,
and then did it again this session — the second time it was the harness rather than
a person that was fooled, for five weeks of binary age. The binary lands in the
shared target dir, not `gui/src-tauri/target/`.

## Do not kill cargo processes on this machine

`.cargo/config.toml` sets a **shared** `CARGO_TARGET_DIR` (`~/.cargo-target`) for
every Rust project on this box — written after a survey found 1.33 TB of build
artifacts across 79 target directories. One consequence is easy to forget and
expensive to relearn: **every Rust project here contends for one build lock**, so
`Blocking waiting for file lock on build directory` is the normal state of a busy
machine, not a symptom of anything.

During this session that was misread as stale processes left by a timed-out job,
and `Stop-Process -Name cargo,rustc -Force` was run twice. It killed builds and
test runs belonging to unrelated projects — `cyb0rg-server`, `tabinator-core`,
`robotcontrolleros-drivers`, `avatar-api` and others — none of which had anything
to do with this repository. Cargo recovers from an interrupted build, so the cost
was other people's time rather than a corrupted target directory, but the cost was
real and none of it was necessary.

Two rules follow. **Wait for the lock; never clear it.** A single `cargo test`
blocks and then proceeds on its own. And **never poll it with a loop that itself
runs cargo** — `until ! (cargo build | grep -q Blocking)` spawns a new competitor
on every iteration and makes the contention it is waiting on worse.

If a build genuinely seems wedged, look at *what* the processes are before acting:
`Get-CimInstance Win32_Process -Filter "Name='cargo.exe'"` prints the command
line, and on this machine most of them will belong to something else.

## This machine

Facts that cost time to rediscover.

* **MSVC** — installed at `C:\Program Files\Microsoft Visual Studio\18\Community`.
  `cl`, `nmake` and `msbuild` are **never on `PATH`** until you run
  `VC\Auxiliary\Build\vcvars64.bat` and import the environment. Checking `PATH`
  and concluding "no C toolchain" is wrong, and was concluded twice.
* **LLVM 22.1.8** at `C:\Program Files\LLVM` — `clang`, `clang-tidy`, `ld.lld`,
  `llvm-nm`, `llvm-objdump`. `clang-tidy` has **no built-in default check set**:
  with no `.clang-tidy` and no `-checks=` it exits 1 with "no checks enabled" and
  analyses nothing. The adapter supplies a default itself now — that is why.
* **Clippy is installed** (`clippy 0.1.98`); **Miri is not** — `rustup component
  add miri` fails with "unavailable for download for channel 'stable'". Both
  adapters run `cargo`, so `cargo --version` says nothing about either.
* **cppcheck 2.21.0 lives at `C:\Users\adamm\tools\cppcheck-2.21.0\PFiles\Cppcheck\cppcheck.exe`,
  durably this time.** `winget download --id Cppcheck.Cppcheck --download-directory
  <dir>` fetches the MSI without elevation and without installing, and
  `msiexec /a <msi> TARGETDIR=<dir> /qn` extracts it. The previous extraction went
  under `%TEMP%` and Windows removed it between sessions, which is why this one
  did not.
* **QEMU and an ARM cross-compiler are in WSL Debian** — `qemu-system-arm`
  10.0.11 and `arm-none-eabi-gcc` 14.2.1, both `apt-get install`. See
  `examples/firmware-cortex-m/`.
* **The shared target directory is not only contended, it is *destroyed*.**
  During this session another project on this machine cleaned it while a build
  was in progress: `release/deps` went to zero entries and `sda.exe` and
  `sda-workbench.exe` vanished, three times, each time mid-link and with cargo
  exiting 127 or -1 and printing nothing. `Get-CimInstance Win32_Process -Filter
  "Name='cargo.exe'"` showed a dozen unrelated projects building at once. This
  is not the lock, and waiting does not fix it. When it happens, build into a
  private `CARGO_TARGET_DIR` for the duration — the numbers in *Where it stands*
  were taken that way — and still **do not kill anything**.

  **A private target directory reduces this but does not end it.** A later
  `cargo test --workspace`, in a private directory under `%TEMP%`, failed to
  compile six test binaries with `exit code: 1` and *no diagnostic at all* — not
  127 this time, and not the shared directory. The immediate re-run was clean and
  the tree was untouched. So the rule is about diagnosis rather than prevention:
  **a rustc failure that prints no error is not a fact about your code.** Re-run
  once before reading it as anything. Only a failure that reproduces, with a
  message, is yours.

  **And a long-lived private directory eventually hits `LNK1140`.** On
  2026-09-21 every binary in `sda-cli` stopped linking with `LINK : fatal error
  LNK1140: limit exceeded for program database` — debug info accumulated across
  hundreds of incremental rebuilds until the `.pdb` passed what the format
  allows. `cargo clean -p sda-cli` (245 MB, 205 files) fixed it in one step and
  the rebuild took seven seconds. The linker's own advice, *link with
  `/PDB:NONE`*, is not actionable from a cargo build. This is worth knowing
  chiefly because of how it presents: it prints `error: could not compile`, so
  `tools/verify.sh` reported **FAILED: workspace tests** for a tree whose tests
  it had never run, and two full gate runs went into diagnosing it. The gate now
  classifies it separately and says which crate to clean.
* **CMake** is installed; its only working generator here is `NMake Makefiles`
  (no `make`, `ninja`, `msbuild` on `PATH`).
* **WSL Debian is installed and running.** `wsl -d Debian -u root -- ...` gets
  root **without a password**, which is how Valgrind was installed after `sudo`
  inside the distro asked for one — and how cppcheck and clang-tidy were, later.
  `gcc` is already there. `/tmp` is **unreliable** between `wsl` invocations: it
  survived several in a row and then vanished mid-session, taking a built binary
  with it. Build to `/home/test` and it stays; or do the compile, the run and the
  capture in a single command.

  **Single-quote the whole `sh -lc` string, or Windows eats your variables.**
  `wsl -d Debian -- sh -lc "... \$HOME ..."` from PowerShell expands `$HOME` on
  the *Windows* side first, so the distro receives the literal `C:Usersadamm`.
  Handed that as `CARGO_TARGET_DIR`, cargo created a directory of that name
  **inside this repository** — colon and all, which Windows stores as `C…`
  — and five cargo lock files were committed before anyone noticed. Use
  `sh -lc '...'` with single quotes, or write the path out in full.
* **Four tools were installed to check their adapters against reality.** This is
  the cheapest defect-finding this codebase has — see *Not verified*.
  * `modelscan` 0.8.8 — `pip install modelscan`.
  * `semgrep` 1.172.0 — `pip install semgrep`. There **is** a native Windows
    wheel; the "semgrep needs WSL" folklore is out of date. Set
    `PYTHONIOENCODING=utf-8` or it fails on its own banner.
  * `valgrind` 3.24.0 — inside WSL, driven from Windows through
    `tools/valgrind-wsl/`.
  * `cppcheck` 2.21.0 — **not** installed system-wide. `winget install` needs
    elevation and dies with exit 1602 (a cancelled UAC prompt) in a
    non-interactive shell. `winget download` needs neither, and
    `msiexec /a <msi> TARGETDIR=<dir> /qn` extracts without admin. Use that for
    any other MSI-packaged tool. The first extraction went under `%TEMP%` and
    Windows removed it between sessions; it now lives somewhere durable — see
    *This machine* above.
* **Absent**: CodeQL as an installed tool, a JTAG probe, any real board. MSYS2
  exists at `C:\msys64` but is a bare install. QEMU and an ARM cross-compiler
  are no longer absent: both are in WSL Debian.
* PowerShell has no `` `x `` hex escape — build binary test data with byte arrays.
* **`C:` runs out of space, and it fails in confusing ways.** It hit 0 bytes free
  mid-session: a file write returned `ENOSPC`, and separately a directory under
  `%TEMP%` had been left with an **empty DACL** by a killed process, which reads
  as a permissions bug rather than a disk one. Recover with
  `icacls <dir> /grant "$env:USERNAME:(OI)(CI)F"` — the owner keeps `WRITE_DAC`
  even when the DACL grants nothing, which is the only reason it is fixable
  without an administrator. The two `target/` directories are **8.3 GB together**
  (3.9 workspace, 4.5 `gui/src-tauri`); `cargo clean` is the cheapest reclaim.
  **If a write fails, check `(Get-PSDrive C).Free` before debugging anything
  else.**

## What is verified, and how

The distinction between "tested" and "tested *the way it is actually used*"
matters more here than anywhere. Everything below was driven end to end.

* **Correlation, native** — a C program compiled with `cl`, linking the shim, run
  by the dynamic engine, correlated against its own static findings. All four
  verdicts: `confirmed 2`, `refuted 1`, `unpredicted 1`, `unreached 82`.
* **Correlation, external** — real Memcheck confirming real MISRA findings, with
  no native observation anywhere in the run. Its own section below.
* **MCP** — the shipped `sda mcp` binary over real stdin/stdout. `initialize`,
  `tools/list` (21 tools), `analysis.scan`, `rules.audit`, tool-level errors,
  clean exit on stdin close.
* **SWE loop** — Rust (Cargo) and C (CMake + MSVC) projects that genuinely did
  not compile, patched between iterations. Stall and thrash detection both fire.
* **Fuzzer** — A/B on MSVC binaries: without `SDA_CMP_EQ`, 2000 runs found
  nothing behind a 3-byte magic prefix; with it, the bug in four locations, with
  a reproducer that reproduces.
* **Model scanning** — hand-assembled protocol-3 and protocol-4 pickles, a real
  PyTorch zip, a safetensors with an out-of-range offset, plus hostile inputs
  (2⁶⁴−1 header, `u64::MAX` counts, truncation): no panic, no hang, 69 ms. Byte
  locations verified against a purpose-built protocol-4 pickle whose `GLOBAL
  os.system` sits 282 bytes in, behind 8 memoised strings: reported as
  `payload.pkl@0x11a` in text, `byte_start: 282` in JSON, `byteOffset: 282` with
  no `startLine` in SARIF. The first attempt failed usefully — a file padded with
  raw `A`s is not a valid pickle, and the scanner said so ("unknown opcode 0x41
  at byte 2 … must be treated as unscanned rather than clean") instead of
  scanning 2 of 528 bytes and calling it clean.
* **Shim** — links into freestanding images for Cortex-M4, Cortex-M0, RISC-V 32
  and AArch64 with `-nostdlib` and **no compiler runtime**, using
  `SDA_PROBE_NO_FLOAT`, and one of them now *runs*: see below.
* **A Cortex-M image that runs** — its own section below.
* **The availability probe** — `sda tools status` was checked line by line
  against ground truth established independently, across eight adapters, two of
  which changed state mid-session (`modelscan` and `semgrep` went absent →
  installed) and were tracked correctly. This subsystem once reported
  `ext.miri — installed` because only `cargo` was probed; it now names the
  missing *subcommand* rather than blaming a `cargo` that is plainly present.

### The lexer has met clang

Token boundaries and columns are the foundation under every native C and C++
finding: a rule that fires on the wrong token underlines the wrong code. The
14,284-finding PX4 run could only check locations for *plausibility* — that no
line ran past end of file and no column past end of line — which an off-by-one
token boundary satisfies happily. Nothing had ever checked them against a
compiler.

`clang -cc1 -dump-raw-tokens` is clang's own lexer with the preprocessor switched
off, which is the right layer: every token, its spelling, its 1-based line and
column, and a comment reported as one token exactly as this crate does.
`tools/clang-lex-oracle.py` captures it over a corpus of lexical corners — raw
strings, digit separators, wide and UTF prefixes, line splices, tabs, text above
ASCII, a block comment spanning three lines — against clang 22.1.8.

**One defect, and it is real C++.** `a<::b` lexed as the digraph `<:` then `:`;
clang lexes `<` then `::`. C++ [lex.pptoken]/3.2 makes this the single exception
to maximal munch, so that `std::vector<::Foo>` — a template argument naming
something at global scope — reads as anyone would read it. Without it that lexes
as `vector[:Foo>`. Not exotic C++, and every rule downstream saw the wrong
tokens. Fixed, and the exception is kept narrow: `a<:3:>` is still `a[3]`, and C,
which has no `::`, is untouched.

**Two differences are not defects, and the test says which.** Clang reports a
token's *spliced* spelling — `spl\`+newline+`it` is `split` — while this crate
reports the bytes the token actually covers, because a linter has to be able to
point at the source; the test compares the despliced text, which asserts the real
claim rather than skipping the case. And clang's raw dump silently drops a `//`
comment that a splice continued, where this crate reports it; the comparison is
aligned by position rather than by index for exactly that reason, and anything
extra on our side is asserted to be a comment.

**A defect I nearly reported and did not.** An early experiment appeared to show
every token after a continued `#define` landing one line early — which would have
been serious, since multi-line macros are everywhere in embedded C. It was an
artefact of the shell eating a backslash, so the test source was not what it
looked like. Written from Python instead, the lexer is exactly right. *Verify the
instrument* applies to the thing under test as much as to the tool.

**What this does not cover.** The corpus carries no preprocessing directives:
this crate emits a whole `#...` line as one token and clang tokenizes inside it,
a difference of layer rather than of lexing, and mixing it in would bury the
comparison under a known disagreement.

### `rstruct` has met syn, and the brace walk holds

Item 26, and the one I expected to pay — four lexer defects sit directly beneath
this code. The oracle is `syn`, the parser every procedural macro is built on,
called rather than captured for the same reason `rustc_lexer` is.

**The claim with teeth is `UnsafeRegion::end_line`.** It exists so
`correlate::near` can decide that a runtime defect reported below an `unsafe`
keyword is *inside the region the finding is about* — that is what turned a real
Miri stacked-borrows violation into a `confirmed` `RUST-2024-UNSAFE.1` — and it is
found by walking braces by hand. A matcher that miscounts inside a string or a
comment attributes a Miri violation to the wrong block, or to none.

**It holds**, on all eleven cases, including a `}` inside a string, a character
literal, a line comment, a block comment and a raw string, plus nested blocks,
two blocks in one function, an `unsafe` block inside an `unsafe fn`, and a block
written on one line.

The reason it holds is worth naming, because it was a design choice rather than
luck: the walk runs over **code tokens** and compares token *text*, so a `}`
inside a string is a `String` token whose text is `"}"` and never a brace. A
matcher over raw source would need to re-solve lexing to get this right. Watched
failing by making the walk match any token *containing* a brace — the naive form
— which closes `brace-in-string` two lines early.

Item kinds are compared too, at the top level only: syn nests an impl's methods
inside the impl and this crate lists them flat, so comparing everything would
compare shapes rather than findings.

**What this does not reach.** `PanicSite`, the `RUST-2024-PANIC` rules' input, and
the item *spans* — only kinds and the unsafe regions are asserted. And syn parses
what it can prove is Rust: a corpus case has to be valid, so nothing here says
what either side does with input that does not compile.

### One layer up: the returns MISRA 15.5 counts

The lexers now have oracles; the structure analyser above them did not. MISRA C
Rule 15.5 is about how many points a function can exit from, and
`CFunction::exit_points` derives that from `CFunction::returns`, found by walking
tokens. It is among the most frequently fired rules on real code — it appears in
this repository's own `tools/` scan and throughout llama.cpp — and the count had
never been checked against anything that parses C.

`clang -Xclang -ast-dump=json` is that check, captured by
`tools/clang-returns-oracle.py`: a `ReturnStmt` inside a `FunctionDecl` is a
return, established by a compiler rather than by brace counting.

**It passed, on all ten cases**, including the two that would embarrass a naive
scanner: `/* return 99; */` and `"return 5;"` are not returns, and this crate
already knew. Watched failing, by making the collector keep only the first return
per function.

Two things about it are worth keeping.

**The delta encoding nearly made the oracle useless.** clang omits `line` from a
location when it is unchanged from the one before, so a naive reader puts every
return after the first on line `null` — and the comparison then quietly passes
against nothing. The walker threads the last seen line through the tree in
emission order. A capture that looks fine and measures nothing is the failure this
repository has a table of, arriving in the instrument rather than the subject.

**Only the returns are compared, not `exit_points`.** The exit count adds one for
a body that can fall off the end, which is this toolkit's reading of the
guideline rather than something clang reports; asserting it would compare a
judgement against a reimplementation of the same judgement. What clang states as
fact is what gets asserted.

### How far a directive reaches, according to clang

Item 25. Neither lexer oracle covered directives, because this crate emits a
whole `#...` line as one token while clang tokenizes inside it — a difference of
layer. That left `parse_directives` unchecked, and the interesting part of it is
where a hand-written rule goes wrong: a directive continued by a trailing
backslash, where getting the extent wrong swallows the line beneath or stops
short of the body. A multi-line `#define` is not a corner case in embedded C.

**The oracle is clang's own account, not a rule restated in the test.**
`-dump-raw-tokens` marks a token `[StartOfLine]` when it begins a *logical* line,
and a line splice does not begin one: in a continued `#define`, the tokens on the
second physical line do not carry the flag. So a directive runs from a `hash`
carrying `[StartOfLine]` to just before the next token that carries it. That
property was checked against clang before it was relied on — the alternative was
to reimplement the splice rule in the test and compare this crate against a second
copy of the thing being tested.

**It passed**, on eleven cases: one and two continuations, an include guard,
nested conditionals, `#  define` with the hash separated from its name, a
directive with a trailing block comment and one with a trailing line comment, and
a continued `#if`. Watched failing by disabling the splice skip, which closes
`continued-define` at 1:19 instead of 2:28.

### The Rust lexer has met rustc, and lost four times

The same question asked of the other half, and the Rust side was in worse shape
than the C one. The oracle is `ra-ap-rustc_lexer`, the rust-analyzer team's
automatically published mirror of the compiler's own lexer — the same code rustc
runs. There is **no fixture**: clang is an external program that may not be
installed, so its answers are captured, but a Rust crate is fetched by cargo like
any other dependency, so the oracle is simply called and the comparison is always
against the version in `Cargo.lock`.

Four defects, every one of them ordinary Rust:

* **C string literals.** `c"cstr"` lexed as the identifier `c` followed by a
  separate string. `c"..."` and `cr"..."` were stabilised in 1.77, this crate
  targets Rust 2024, and they are increasingly the normal way to write an FFI
  constant.
* **Signed float exponents.** `1.0e-3f64` lexed as `1.0e`, `-`, `3f64` — three
  tokens, one of them an operator that is not in the source. `1e-9` is ordinary
  in numeric code. The fix is deliberately narrow: only after an exponent marker,
  and not for a hex, binary or octal literal, because `0xE-1` really is `0xE`
  minus one.
* **Raw identifiers.** `r#fn` lexed as `r`, `#`, `fn` — and that last token was
  then classified as the **keyword** `fn`, which is precisely the reading a raw
  identifier exists to rule out. `r#type` and friends are everywhere in generated
  bindings.
* **Non-ASCII identifiers.** `café` lexed as `caf` and an unknown byte. Legal
  Rust since 1.53, and the fragments reached every rule that counts or matches
  identifiers.

**Punctuation is compared as runs, and that is not laziness.** `rustc_lexer` is a
raw lexer: it emits `-` and `>` and leaves gluing them into `->` to the parser,
while this crate produces the compound punctuator. Comparing token-for-token
would report a disagreement on every arrow, shift and range operator in the
language. What survives collapsing is the claim that matters — every identifier,
literal, lifetime and comment at the same offset with the same text and kind, and
the punctuation between any two of them spelling the same. A punctuator that
swallowed part of a literal still shows up, because the literal's offset moves.

**One limit is stated rather than fixed.** rustc decides identifier characters by
the Unicode XID properties; this accepts any byte outside ASCII, because carrying
an XID table into a lexer that only needs token boundaries is not worth the
weight. The two agree on every *valid* identifier and differ on input that is
not: rustc calls an emoji `InvalidIdent`, this lexes it as part of a name. That
is the safe direction — an unparseable name stays one token rather than
shattering the tokens around it — and the corpus stays inside valid identifiers,
because that is the claim being made.

### The port has met Monaco, and disagreed with it

`sda-editor` describes itself as "a Rust-native port of Monaco's text model".
Until now that claim rested entirely on the porter's own expectations: 49 tests,
every one asserting what the author believed Monaco does. Nobody had asked
Monaco.

`gui/tools/monaco-oracle.mjs` asks it. Monaco's `TextModel` class needs its
dependency-injection container and a DOM, but the *buffer* underneath it — where
positions, offsets and line lengths actually live — is the same code the editor
runs and stands up headless in node. The answers are captured to
`crates/sda-editor/tests/fixtures/monaco-answers.json`, so
`agrees_with_monaco.rs` is hermetic; re-run the oracle when Monaco is upgraded,
and expect the diff to be interesting.

**Two disagreements, and the first is on the most ordinary input there is.**

* **A trailing newline opens a final empty line, and this crate said it did
  not.** The comment even said why: *"a trailing newline does not create a
  phantom line, as every editor presents it"*. Monaco presents it — it is where
  the cursor sits when you press End on a file that ends properly — so a
  three-line C file is four lines, and every line count, clamp and end-of-document
  position was off by one on nearly every file in existence.
* **Columns were characters, and the documentation said UTF-16.** `Position`
  states its column is "measured in UTF-16 code units, as Monaco and the Language
  Server Protocol both do, so that positions round-trip through a JavaScript host
  unchanged" — and `line_length` counted `chars()`, `offset_of` did arithmetic in
  rope character indices. On any line holding an emoji or a rarer CJK glyph every
  column past it was short by one per character, and the round trip the doc
  promises did not happen. The doc was right and the code was wrong.

  Worse than a plain mismatch: for `"a😀b"`, Monaco's `getOffsetAt(1,4)` and ours
  both returned **3**, and the two threes meant different places — before `b` and
  after it. Equal numbers denoting different positions is the hardest kind of
  disagreement to notice, and it is what a differential test is for.

Both are fixed, four existing unit tests moved to Monaco's answers, and both
reverts were watched failing.

**One difference is deliberate and stated rather than matched.** Monaco's buffer
is raw arithmetic — `getOffsetAt(1, 20)` on a three-character line returns 19,
past the end of the document — while `TextModel.getOffsetAt` validates first.
`offset_of` here is the model-level operation and validates, so an offset that
falls *between* the halves of a CRLF pair does not round-trip: `position_of`
matches the raw buffer and yields a column inside the terminator, which
validation then pulls back. Every position a cursor can occupy round-trips. The
test skips exactly that case and says so, because asserting it would be comparing
our model against Monaco's buffer, which are different layers.

**And the next disagreement was where that was predicted.** Stickiness is the
second oracle, and it found a third defect.

`Stickiness`'s three variants carry Monaco's names, so a reader is entitled to
Monaco's meanings. Two of the three doc comments described the **opposite** of
what Monaco does, and the code implemented a third thing again: `adjust` consulted
stickiness only at the *end* edge, so `GrowsOnlyWhenTypingBefore` — whose entire
purpose is the start edge — was indistinguishable from
`NeverGrowsWhenTypingAtEdges` for every input. One of the three names was a lie
and the enum had two members where it claimed three.

Monaco's `nodeAcceptEdit` is exported, takes plain offsets and runs headless, so
the semantics are read off the implementation rather than off the name:
`gui/tools/monaco-stickiness.mjs`, captured to
`crates/sda-editor/tests/fixtures/monaco-stickiness.json`. The oracle guards itself — stickiness
lives in bits 3-4 of a bit-packed `metadata` field whose setter is
module-private, and with the wrong mask all four values behave identically and
the fixture looks fine while testing nothing. That is what the first attempt did,
and the capture now refuses to write unless the four differ.

`adjust` now asks stickiness at both edges, the doc comments say what Monaco
does, and the test asserts the three are actually distinguishable — the one
assertion that would have caught the original defect on its own.

**One divergence is deliberate and is asserted as such.** Monaco keeps a
decoration whose text was deleted, collapsed to a point; this crate drops it,
because an anchor left on whatever moved into that position points a reviewer at
code that has nothing to do with the finding. The test reads that case from the
fixture and asserts the difference, so it stays a decision rather than becoming
a surprise.

**Multi-cursor editing was the third oracle, and it passed.** `applyEdits` is
also on the buffer, so `gui/tools/monaco-edits.mjs` asks Monaco what a set of
edits does: twelve cases including three cursors at once, edits given out of
document order, adjacent ranges, a replacement spanning lines, CRLF, and an
astral character. `apply_all` agrees with Monaco on every one, which means its
central claim — every range is stated against the text as the caller last saw it
— holds. Checked that the oracle can fail: sorting the edits front-to-back
instead of back-to-front breaks `same-line-two-inserts` immediately.

Overlapping ranges are refused by both, and the capture records that rather than
leaving it to memory. Monaco throws; `apply_all` returns no events. The mechanism
differs because the languages do, and the part a caller depends on is the same
and is what the test pins: **neither applies half of it**.

**What is still not covered.** The change-event stream — `ChangeEvent` and
Monaco's `IInternalModelContentChange` are different shapes by design, and
comparing them would compare structures rather than behaviour, so what the two
must agree on (the resulting text, and where a decoration lands) is covered by
the other three oracles instead. And every comparison here is against the
**buffer**; `TextModel`'s validating layer above it needs Monaco's
dependency-injection container and a DOM, so the CRLF-interior case documented
above is compared no further than that.

### The MCP surface has met a real client

`sda mcp` had been driven over real stdin and stdout, but only by hand-written
JSON-RPC — by the same person who wrote the server, which tests agreement with an
idea rather than with the protocol. It has now been driven by
`@modelcontextprotocol/inspector --cli`, the reference client:

```bash
npx @modelcontextprotocol/inspector --cli <sda> mcp --method tools/list
npx @modelcontextprotocol/inspector --cli <sda> mcp --method tools/call \
    --tool-name rules.audit --tool-arg standard=misra-c-2023
```

**It passed, first contact, with nothing to fix** — the first component in this
file to do so. The handshake negotiates, all nineteen tools list with schemas the
client accepts, a call returns its result, an unknown tool is rejected by the
client against the published list, and a missing argument comes back as
`isError: true` with a readable message rather than as a JSON-RPC error, which is
what the protocol asks for.

A negative result is still a result, and the reason it is worth writing down is
that it is *not* the base rate: ten of eleven adapters, the SARIF exporter and
`sda build compile-commands` all failed their first meeting with a real
implementation.

**What the audit did leave behind is a test.** `tools/list` is the only thing an
agent has to go on — it cannot read the dispatcher — so a schema that disagrees
with its handler is a tool the agent calls wrongly. Checking that by hand once is
worth little; `published_schemas_match_handlers.rs` does it on the surface the
server actually publishes, so adding a tool brings it under the test with no
further work. It drives every declared-required argument by omitting exactly that
one and asserting the refusal names it, which catches the direction that costs
most: a schema marking something required that the handler ignores sends an agent
looking for a value nobody needs, and the call then *succeeds* on fiction.
Watched failing, by marking `rules.lookup`'s optional `standard` required.

### The SARIF has met a real consumer

The toolkit emits SARIF so that *other* tools can read it, and until now no other
tool ever had. It has now been handed to the SARIF reference implementation —
`@microsoft/sarif-multitool validate` 5.7.0, the same code path GitHub's ingestion
uses — over the output of a real scan.

**Zero errors and zero warnings against the 2.1.0 schema.** The instrument was
checked before the reading was trusted: deleting `runs[0].tool.driver.name` from
a copy makes it report `error JSON1002`, so silence means something.

Two defects, both found only because a real consumer looked.

* **The `$schema` URL was a 404.** It pointed at
  `raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/…`; the
  repository renamed its default branch and moved the file, so every SARIF
  document this toolkit has ever produced declared a schema location that cannot
  be fetched. Checked rather than assumed — that URL and its `main`-branch form
  both return 404, `json.schemastore.org` redirects, and
  `docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json`
  returns 200. Now the specification's own address rather than a mirror.
* **The source snippet was dropped at the boundary.** The engine collects the
  lines around every finding — it is what the text report prints under each one —
  and the SARIF exporter threw it away, so a viewer showed a file, a line number
  and no code. `SARIF2010` and `SARIF2011`, twenty times each. Now
  `region.snippet` and `contextRegion`, and evidence naming a different file is
  refused rather than borrowed.

**Forty-eight notes remain, and they are decisions rather than a backlog.**

* `SARIF2012` (17) — a rule's `helpUri` is present exactly when the rule carries
  a CWE, because that is the only public document there is. MISRA's normative
  text is licensed; inventing a link to a document the reader must buy would be
  worse than omitting one.
* `SARIF2009` (10) — the friendly `name` is the id with separators stripped
  (`MISRAC2023216`), which the validator would prefer in Pascal case. Checked for
  the failure that would make it a defect rather than a preference: across all
  296 catalogued guidelines, no two ids collide after stripping `-` and `.`.
* `SARIF2002` (20) — message arguments. Our messages are complete prose, not
  templates with holes, so there is nothing to parameterise.
* `SARIF2006` (1) — the `repositoryUri` is the checkout's real `origin`, and the
  validator cannot reach it anonymously. Reporting the remote a checkout actually
  has is correct; whether a stranger can fetch it is not this tool's business.

`SARIF2003` — `versionControlProvenance` — **was** on this list and is now done;
see below.

### What revision a report describes

A conformance report that cannot say what it looked at is weaker than one that
can, so `Report` now carries a `VcsProvenance` and every surface renders it:
`sda scan` prints it under the timestamp, the JSON carries it, and SARIF emits
`versionControlProvenance`. It is asked in `run::analyze` rather than in the CLI,
so the workbench and both MCP paths report the same revision the command line
does.

**The hard part is not the revision, it is the tree.** *"These findings describe
commit abc123"* becomes false the moment somebody edits a file, and SARIF has
fields for the revision, the branch and the repository and **none** for whether
the working tree matched. A consumer reading `revisionId` alone would therefore
be told a specific falsehood by a report that was trying to be more precise than
before.

So the revision and the state of the tree are recorded together and neither is
emitted without the other: `properties.sda/workingTreeClean` in SARIF, and one
sentence in the text report that says, when it applies, *"the working tree had
uncommitted changes when this ran — these findings describe what was on disk,
which is not that commit"*. Untracked files count as dirty, because a new source
file is analysed and is not in the commit.

Three smaller decisions in it:

* **Absent rather than guessed.** A target that is not a checkout gets no
  provenance object at all — `revisionId` is required wherever the object
  appears, and plenty of real targets are unpacked tarballs or scratch
  directories.
* **A failed `git status` means no provenance**, not a clean tree. Reporting
  `false` on the strength of a check that did not run is the shape of defect this
  file has a table of.
* **`git -C <target>`, always.** Asking git without it reports *this* repository's
  revision for a scan of somebody else's directory — a report confidently naming
  the wrong commit, which is worse than naming none. There is a test for it.

Adding the provenance immediately produced a **warning**, which is how the next
gap surfaced: `SARIF2007`, wanting `mappedTo.uriBaseId`. Result paths were
relative — `src/main.c` — and nothing said what they were relative *to*, so a
consumer had to guess and could not connect a finding to a file in the repository
just named. There is now a `SRCROOT` base id, declared on the run, referenced by
every relative location and by `mappedTo`. It is declared **without a `uri`**
deliberately: writing `file:///C:/Users/...` into every report would pin one
machine's layout into a document meant to travel. An absolute path — an external
tool reporting inside a system header — is not given the base id, because it does
not lie under the source root.

### A Cortex-M image that runs

Every other dynamic claim in this file is about a program *this machine*
executed. This one is not, and it is the one the toolkit is named for.

`examples/firmware-cortex-m/` is a freestanding image — `-nostdlib`, no compiler
runtime, 2,160 bytes of text and 8 bytes of bss — built from `shim/sda_probe.h`
with `SDA_PROBE_ENABLED`, `SDA_PROBE_NO_FLOAT` and `SDA_PROBE_CUSTOM_SINK`, its
sink writing a byte at a time to the LM3S6965's UART transmit register. It runs
on `qemu-system-arm` 10.0.11's `lm3s6965evb` (Cortex-M3), built by
`arm-none-eabi-gcc` 14.2.1, both installed inside WSL Debian.

Twelve records came back, and every one can be checked by hand against the
source: `checksum` is 84 because the buffer is `i * 3` for `i` in 0..8;
`decoded` is `0 + 12 + 21 + (-1)` = 32; line 60 is covered four times and line 65
three, the missing one being the call that returned early through the bounds
check; and the `bounds` fault at line 62 is the fourth `decode`, handed an index
past the end of an eight-byte buffer. `recovery` appears nowhere, because it is
never called — which is the distinction the whole toolkit exists to make.

The capture is pinned as
`crates/sda-engine/tests/fixtures/qemu-lm3s6965-cortex-m3.jsonl` behind
`hardware_capture_correlates.rs`, and the scan reports the fault as
`SDA-DYN-MEMORY`, critical, `confidence certain`, phase `dynamic`,
`unpredicted` — correct, since no static rule sits on that line.

**Three things this cost, all of them the same shape as everything else here.**

* **There was no way to feed a captured stream in at all.** `--artifact`
  *executes* a program, which is the one thing a host cannot do with firmware.
  The suggested-next-step that named this as the highest-value gap said to use
  it, and had been read many times. New `--observation <FILE>`.
* **`executions = 0` was being asserted about lines nobody measured.** See item 1
  and *Never measured is not measured-and-empty* — this is that principle
  surviving in the prose and failing in the structured evidence beside it.
* **The compiler must be invoked with a relative source path.** The shim stamps
  `__FILE__` into every record, so the path the compiler was given is the path
  the engine correlates against. An absolute path yields a capture that parses,
  looks right, and correlates with nothing.

**What it does not establish.** Nothing about silicon: no clock configuration,
no flash wait states, no interrupt latency, no brown-out, and a UART QEMU models
rather than one wired to a pin. One target, one toolchain. The emulator closed
the *never executed* gap, not the *never ran on a real part* one.

### External adapters against their real tools

**All nine adapters have now met the tool they wrap, and no fixture is a
reconstruction any more.** Ten of the eleven encounters found a defect — `clippy`
is the only one that passed clean — and eight of the ten were in adapters that
were fully green, fixture-tested and passing a clean self-scan at the time.

That is the number to carry forward. It is not a run of bad luck and it is not a
statement about these particular tools: a spec that compiles and a spec that works
are different claims, and only the tool's own bytes settle the second one.

* **`clang-tidy`** — against a real clang compilation database, returning
  `clang-analyzer-core.NullDereference`, and later a use-after-free, an unbounded
  `strcpy` and `cert-err34-c` on a purpose-built C project with no `.clang-tidy`.
  With a project `.clang-tidy` present, *only* the project's own checks fire,
  which is the decisive test: the injected default set excludes
  `misc-use-internal-linkage`, so had it been appended rather than substituted,
  the project's own findings would have vanished.
* **`clippy`** — on a Cargo project, returning `clippy::needless_range_loop` with
  rustc's own span.
* **`modelscan` 0.8.8** — a directory holding a backdoored pickle and a corrupt
  one, returning `MODELSCAN-PickleUnsafeOpScan-system` (critical) and
  `MODELSCAN-NOT-SCANNED` for the file it could not read.
* **`cppcheck` 2.21.0** — nine findings on a purpose-built C file, at the right
  lines with the right CWEs, on stderr as the spec expects.
* **`semgrep` 1.172.0** — a Python file, returning `subprocess-shell-true` at
  `high` with `CWE-78`, span intact.
* **`valgrind` 3.24.0** — end to end through `tools/valgrind-wsl/`: the adapter
  spawned the real Memcheck, substituted `{artifact}`, captured stderr, honoured
  the exit code, and produced the invalid write and the leak at the right lines
  with the right CWEs, at `AnalysisPhase::Dynamic`. Later, the same tool drove
  the correlation work below.

**Every adapter has a fixture**, in `crates/sda-adapters/tests/`, parsed through
`parse_output_channels` — the same dispatch the adapter runs, not a copy of it. A spec
with no fixture fails the suite. All but `ext.codeql` are now captured from the
real tool rather than reconstructed from documentation.

**A stub proves the parser and nothing else.** The older stub technique — a
`.bat` printing a payload we believed the tool emits, pointed at with `--with
ext.x=<path>` — cannot catch us believing wrong, and that is exactly how
`ext.modelscan` passed while being unable to read a single real run. Stubs are
still worth fifteen minutes for a tool you cannot install; just do not mistake
what they establish. Two traps in building them: bash `printf` eats `\v` in
`...\stub\valgrind.txt` and turns it into a vertical tab, and the tool's own
`--version` probe has to be answered or the adapter is reported absent before it
ever runs.

### External dynamic evidence confirms static findings

For most of this project's life, the toolkit's central claim — runtime evidence
confirming a static suspicion — was **unavailable to every external dynamic tool
it ships an adapter for**. A real Valgrind witness sat beside the static finding
it corroborated and did nothing. That is now wired, and was driven end to end
against real Memcheck 3.24.0 before it was believed.

**The demonstration.** A C program whose only defect is a leaked `malloc` on line
9. The static side flags that line twice — MISRA C 21.3 and D4.12, both carrying
`CWE-401` — and Memcheck reports `16 bytes in 1 blocks are definitely lost` at
`main.c:9`, the allocation site. Same line, same weakness class. The identical
command, before and after, on the same program and the same binary:

```
before   main.c:9:15: MISRA-C-2023-21.3   (medium)                 no Correlation section
after    main.c:9:15: MISRA-C-2023-21.3   (high) [confirmed]       confirmed: 2
         main.c:7:5:  MISRA-C-2023-15.5   (low)  [inconclusive]    inconclusive: 1
```

Severity `medium → high`, confidence `high → certain`, phase `static →
statodynamic`, and the Memcheck `leak` event travels *on the finding* in the
JSON — not only in the correlation record — so whoever opens it sees the proof
without cross-referencing anything.

**Verified negatively, which is the part that means anything.** The same program
with `free(p)` added: Valgrind runs, reports nothing, and the findings stay
`medium` with no confirmation. The confirmation tracks the runtime evidence, not
the mere presence of the adapter. The `15.5` finding on line 7 is a second
negative control *inside* the positive run — a different line, so it stays
`inconclusive` while its neighbours are confirmed.

**Four defects, all of the usual family.**

* **An external dynamic finding carried no runtime event.** Correlation asks
  `same_defect_class` whether a witness is the same *kind* of thing as the
  suspicion, and that reads `RuntimeEventKind` off the witness's evidence. An
  external finding carried only a `Note` naming its provider, so relatedness
  could not be established and the confirmation was dropped in silence. The
  phase fix recorded last session had put the finding on the correct side of
  correlation, where it was then discarded for a different reason. **A
  precondition reported as a fix is its own hazard**: the finding was in the
  right place, looked right in the report, and still could not confirm anything.
  The adapter now derives the event kind from the CWE the tool itself stated.
* **The two weakness tables disagreed.** `RuntimeEventKind::from_cwe` maps a
  stated CWE to an event kind; `related_weaknesses` maps an event kind back to
  the CWEs it could be an instance of. They were written for different purposes
  and drifted: `from_cwe(416)` said `MemoryError`, and `MemoryError`'s list held
  no 416 — so Memcheck witnessing a use-after-free could not confirm a
  *predicted* use-after-free. The same CWE on both sides, and no correlation.
  415, 416, 761 and 762 were all in that hole.
  `every_weakness_class_confirms_its_own_cwe` now walks every CWE the map knows
  and asserts the round trip, so the two cannot drift apart silently again.
* **`correlate` was reachable only through an `Observation`,** which only the
  native probe engine produces, so the wiring never ran at all for a tool like
  Valgrind. This is the one worth reading twice, because **the obvious fix is
  wrong**: handing `correlate` an empty `Observation` compiles, confirms
  correctly, and then reports every unconfirmed finding as `Unreached` — "no line
  of this file produced a coverage record" — which is a claim about the *code*
  manufactured out of a fact about the *instrument*. Valgrind reports defects and
  no coverage at all. See *Never measured is not measured-and-empty*.
* **A dynamic tool that ran clean was reported as a static-only run**, found by
  the negative control above. Memcheck executed the program, found nothing, and
  the report said `no runtime observation was supplied … this is a static-only
  result` without naming Valgrind at all — the usual failure inverted: a check
  that *did* happen, presented as one that did not. It errs toward
  under-claiming, which is the safe direction, but it reads as "the adapter never
  ran" and would send someone to debug a working tool. The report now names the
  tools that executed the program and says plainly that a quiet dynamic run is
  not a clean bill of health, because no coverage was measured and a dynamic tool
  reports only the defect classes it checks for.

**The harness itself was broken, and that is a finding too.** `ext.valgrind` was
reported *not found on PATH* while Valgrind sat there working:
`tools/valgrind-wsl/valgrind-wsl.bat` had LF-only line endings and UTF-8 em
dashes in its comments, and `cmd.exe` — which parses a `.bat` in the OEM
codepage — desynchronised and died with `'M' is not recognized`, the tail of a
`REM` keyword. It is now pure ASCII with CRLF, and the conversion asserted that
rather than hoping. **Keep it that way.** A comment written with an em dash
disables the verification harness for the adapter that has produced more defects
than any other, and it fails by reporting the tool as *absent* — which reads as a
missing install, not a broken file.

What this does **not** do is give the external path coverage. Nothing can be
refuted or shown unreached through Valgrind, because Valgrind counts no lines,
and the report says so in *NOT CHECKED*. See *Suggested next steps*.

### The GUI, over CDP

Driven against the running window; `window.__sda` exposes the editor state for
exactly this. The harness lives at **`gui/tools/drive-cdp.mjs`** with its fixture
at `gui/tools/fixtures/glyph.c`:

```bash
cargo build --release && cd gui && npm run tauri build -- --no-bundle && cd ..
node gui/tools/drive-cdp.mjs                       # PASS / FAIL, exit code set
node gui/tools/drive-cdp.mjs "" "" shot.png        # and the pixels
```

It **asserts** rather than printing: the expected glyph per line and the total
inline-squiggle count are written down, so a regression fails instead of
producing output someone has to read correctly. It was verified negatively —
one extra violation in the fixture makes it report both the unexpected glyph and
the changed squiggle count. It checks squiggles as well as glyphs deliberately: a
glyph is a summary, and glyph-only checking would not notice five of six findings
disappearing.

The last run: a 7-line C fixture with 1 finding on line 2, 3 on line 3 and 2 on
line 4 (per `sda scan --format json`) produced exactly `sda-info-glyph` with no
count class, `sda-info-glyph sda-count-3`, and `sda-warning-glyph sda-count-2`,
plus 6 inline squiggles for 6 findings. A screenshot confirms the badges render
as a plain dot, a blue **3** and an amber **2** — a class name in a model is not
a pixel.

**How to drive it, and three traps that each produce a confident false pass.**
Launch the built `sda-workbench.exe` with
`WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=9222`; WebView2
then speaks CDP on that port. `http://127.0.0.1:9222/json/list` gives the
targets, `Runtime.evaluate` with `awaitPromise` and `returnByValue` does the
work, `Page.captureScreenshot` gives pixels. Node 24 has `fetch` and `WebSocket`
built in, so the harness needs no dependencies. All three traps below were hit
*again* on a re-drive, because the first harness lived in a scratch directory and
did not survive the session that wrote it:

1. `/json/list` returns an `about:blank` target while the webview is still
   starting. Take it and you drive an empty page. **Match on `tauri.localhost`**
   and assert the URL — `localhost:5173` means a dev build and you are testing
   nothing.
2. `window.__sda` is installed when `main.js` *finishes*, well after
   `DOMContentLoaded`, because Monaco is large. The DOM answers before the app
   does, so `getElementById('scan').click()` succeeds against a half-loaded app.
   **Poll for `window.__sda` before driving anything.**
3. The root input listens for **`change`, not `input`**. Dispatch `input` and
   `projectRoot` keeps its default, so the app cheerfully scans the repo instead
   of your fixture and reports 136 findings that all look plausible. **Check the
   *files* in the result, not just the count.**

### The document now counts itself

Auditing HANDOFF's tables found the "measured" column lying and the workbench
binary missing. Auditing its *prose* found the same class of thing one level in:

**The failure-mode table's own count was wrong.** The sentence above it says how
many defects it holds, and that number has to be incremented by hand whenever a
row is added. It said sixty-seven against sixty-six actual rows. A document whose
entire argument is that unchecked claims rot is a poor place to keep an unchecked
claim.

**A cross-reference pointed at a section that had been renamed.**
`See *External dynamic evidence*` — the heading had become *External dynamic
evidence confirms static findings* and the pointer stayed behind. One other named
a prefix of its heading rather than the whole of it.

That sentence is itself the reason the checker understands code spans. Written
plainly, the worked example *is* a live broken reference, and the first version
of the test failed on it — correctly. Rewording the prose around the tool was the
wrong fix and was recorded as such; the checker now skips anything inside
backticks, because a pointer being demonstrated is not a pointer being followed.

**And the first attempt at that skip did nothing, while passing both checks
meant to prove it worked.** It reassigned the scan cursor and then asked whether
`cursor + at` lay inside a code span — a position in neither coordinate system.
The one reference that should have been skipped landed inside some span by
accident; the deliberately broken pointer used to prove the check still bit was
appended at the end of the file, past every span. Two green lights over a
function doing nothing. The lesson is about where a negative test is placed: a
broken pointer injected into the *middle* of the document catches it, and one at
the end does not, so both positions are exercised now.

`crates/sda-cli/tests/handoff_counts_what_it_claims.rs` now checks both on every
`cargo test`: the spelled-out number against the row count, and every `see
*Title*` against the headings that exist. It found the renamed reference on its
first run, which is the only reason this paragraph can name it.

**Then the same treatment was given to the numbers that matter most, and all
three were wrong at once.** This document says how far each catalogue has been
compared, against sixty-five MISRA C guidelines, twenty-one C++ ones and seventeen
Rust ones. Every one of those counts was arrived at by hand, and reading a phrase
like "`N` of the twenty-one" is how the checker below finds them.
MISRA C++ said twelve and the answer was fourteen; Rust said
nine and the answer was eight; the MISRA C tier table said fifty-six and the
answer was fifty-five.

Each error left a mark on the page. The C++ sentence named seven rules and
claimed nine, filling the gap with "and two others" — a phrase where a number
should have been, and the two did not exist. The count had been taken from the
clang-tidy fixture by someone who never opened the clang one, where `5.7.1` and
`5.7.2` had been compared all along. The Rust sentence said "nine ... the eight
left" and listed eight: eight and nine add to seventeen, so the arithmetic
vouched for itself while `UNSAFE.3` sat in neither the compared set nor the list.
**A page can add up and still be missing something.**

These are derived now rather than counted. A guideline is compared when a
committed oracle fixture records the *second implementation's own* finding for
it — what this engine reports about itself is not evidence that anyone checked
it, which is precisely the mistake `misra-evidence-tiers.py` was making with
`13.6`. The tiers table has to add to the catalogue, each unmet tier has to name
its members, and the members have to be exactly the rules no fixture mentions.

**And the first version of that test passed over the defect it was written for.**
It checked the sentence naming the rules left over and never the count standing
beside it, so changing `Fourteen` to `Thirteen` stayed green. Written to catch a
hand-count, it was checking everything except the hand-count. Five mutations are
exercised against it now, including both original errors verbatim.

The failure-mode table then broke it, which is the right kind of trouble: a row
reading `the standing said twelve of twenty-one` is a confession, not a claim,
and the checker read it as current. Every cell in that table is something this
project once believed and has since disproved, so the table is blanked before
the document is scanned for live claims — and a number in backticks anywhere
else is read the same way, because quoting a wrong answer has to be possible in
the prose that explains it.

**Then the same question was put to the rest of the page: what else here is
maintained by hand?** Five more, and the worst of them was in the instructions
for checking the work. Two places told the next session that
`cargo test --workspace` prints `803 tests across 41 binaries`. It prints 923
across 62. A baseline that low does not merely mislead — twelve test binaries
died with exit 127 mid-run earlier in this project, and measured against 803 that
failure reads as a comfortable surplus. **The number you check a regression
against is worth more than the number you report.**

The summary table was one session behind at 919. `Clippy is installed
(clippy 0.1.97)` was a version stale, contradicted by the clippy fixtures
committed beside it. And the MCP surface was described as `tools/list`
publishing sixteen tools in the walkthrough and nineteen in the summary table,
four hundred lines apart — a document disagreeing with itself about a number a
reader has no way to check.

All five are derivable, so all five are derived now. The workspace count is
stated in three places and those three must agree — which alone would have caught
it, since one site was updated and two were not — and the agreed figure must
match the tree: the summary row shows the split, `921` `#[test]` functions and
two doctests, so both halves are checkable. The tool count is compared against
`sda_agent::mcp::tools()`, the surface an agent actually sees.

**The tool count had a second problem underneath it.**
`tools_list_publishes_every_tool_with_a_schema` asserted that `tools/list`
returned `>= 14` tools against a surface of nineteen. Five could have disappeared
between the definition and the wire without a word, and what an agent can do is
exactly what that list says it can do. It now compares the published names
against `tools()` in order; watched failing with one tool dropped from the
response, which it names.

A loose bound is the quiet form of the failure this whole document is about. It
is not a check that fails to notice a defect — it is a check written so that
noticing was never possible, and it reads as diligence.

### The expiry date that did nothing

The counting work was about claims a reader can check. This one is about a claim
a *safety team* would rely on, and it was worse.

`.sda/deviations.toml` records approved departures, and a record may carry
`expires`. The field's documentation reads: *the date after which the record is
stale and no longer applies.* `DeviationRegister::is_expired` computed it
correctly. `DeviationRegister::expired()` listed them correctly. Both were
unit-tested, and the test passed.

**Neither was ever called.** `apply` suppressed through `find`, and `find`
filtered on rule and scope alone, so an acceptance that expired in 2020 went on
hiding its finding in 2026 and would have in 2036. Not an unimplemented feature —
a register carrying expiry dates tells a team that acceptances lapse and come
back for re-approval, and none of them ever would have. The editor's buffer check
suppressed through the same path, so it hid them in the one place a developer is
looking straight at the line.

The test that existed is the instructive part. `expiry_is_evaluated_against_a_
supplied_date` checked that `is_expired` answers correctly and that `expired()`
collects the right records. Both true, both green, neither touching the question
of whether an expired record still suppresses. **It tested the accessor and not
the behaviour the accessor exists for.**

`find` and `apply` take `today` now and expired records cover nothing. The date
is a parameter rather than a clock read for the reason `is_expired` already gave:
a check whose answer changes overnight without its inputs changing cannot be
reproduced from a report. Watched failing end to end — a lapsed record lets four
`15.5` findings through on the shim that a live one suppresses.

**And a finding that reappears needs explaining**, or it reads as an unexplained
regression rather than a lapsed acceptance, so expired records are named in *NOT
CHECKED*. `unused()` was in the same position — written, tested, never called —
and is reported there too.

#### Twice, that notice was the error it was written to prevent

The first version reported every record matching no finding. A scan of `crates`
duly announced all six `shim/sda_probe.h` records as dead weight. They are not
dead weight: they are about a file that scan never opened. **An absence of
evidence, reported as evidence of absence, printed by the very section of the
report that exists to stop exactly that.**

Narrowing it to records naming a file the run actually read left one:
`clippy::needless_range_loop`, on a file `crates` does read. Also wrong.
`ext.clippy` never ran, so nothing could have matched it — which says everything
about the run and nothing about the record. A record is reported as unused only
when this run both read the files it names and ran the analysis that could have
produced its finding.

Both were caught by running the thing and reading the output, not by testing it.
A notice with no assertion behind it is only as good as the last person who
looked at a report.

#### A test that failed from load, not from its subject

Found while verifying the above. `a_tool_that_finishes_keeps_every_byte_it_wrote`
checks the half of the timeout logic that matters most — a tool that *finishes*
must hand back every byte, because the pipes are drained on their own threads and
a child that fills its stdout pipe blocks until something reads it.

It generated its 200 kB with `cmd /C for /L %i in (1,1,10000) do @echo ...`, which
takes **86 seconds on an idle machine** against its own 120-second timeout. This
box is documented as running several other projects' `cargo test` at once, and
under that load it goes over and fails. It did, mid-verification.

A test that fails from machine load rather than from the property it checks is
worse than no test, because it teaches people that a red run is weather. The
bytes are written to a file and copied out with `type` now: same size through the
same pipe, 0.42 seconds instead of 86, and the timeout has three hundred times
the headroom it had.

### The function nobody calls

Three defects in this document now have the same shape. `ExternalAdapter::timeout`
was a public field nothing read. `DeviationRegister::is_expired` and `expired()`
were correct, tested, and bypassed. Each was found by accident, while looking for
something else.

Three is enough to stop finding them by accident.
`tools/uncalled-api-sweep.py` lists every `pub fn` in the workspace with no call
site outside its own definition and its own crate's tests. **A unit test cannot
catch this class: the test exercises the function directly, so it passes
precisely because it is the only caller.**

Most of what it prints is honest library surface — a workspace with a CLI on top
legitimately exposes more than it consumes — so it is a list to read, not a gate.
Sort by the test column. *A function somebody cared enough to write tests for,
that nothing calls, is the shape worth opening.*

**Calibrate it before believing it.** The first version reported one uncalled
function out of 654, which is not a plausible answer. It recorded the offset of
`pub` while the call-site pattern matched the name seven characters later, so
every definition counted as its own caller, and only generic functions — whose
`<` breaks the pattern — ever escaped. It was caught by deleting the known
`expired()` call and finding the output unchanged. **An instrument whose output
is identical with and without the defect it looks for is not evidence of
anything.** Fixed, it reported 92.

**Then it needed calibrating a second time, and the second bug invented
findings.** It treated the first `#[cfg(test)]` in a file as the start of the
test module. `crates/sda-adapters/src/lib.rs` carries an indented one on a single item
at line 275, so everything below — including the dispatch table at line 868 that
calls five of the tool parsers — was read as test code, and
`parse_cppcheck_xml`, `parse_valgrind`, `parse_miri`, `parse_clippy_json` and
`parse_modelscan_json` were all reported as called by nothing. Five external
adapters being unwired would have been the largest defect in this repository;
they were wired all along.

A module-level `#[cfg(test)] mod tests` is unindented by convention and by
rustfmt, so column zero is the discriminator. The real figure is **88 of 671**.

The lesson is not that the tool was hard to write. It is that both bugs pointed
the same way an unchecked instrument always points — the first said *nothing is
wrong*, the second said *something is wrong that isn't* — and only running it
against a known answer told them apart.

#### What it found first

`correlate::coverage_gaps` groups the lines a static provider flagged and no run
ever reached. Its doc comment has read, since it was written, that a coverage
hole "belongs on a different work queue". It was on no queue: nothing called it,
and no report has ever shown a coverage gap to a reader.

**And it was wrong.** It paired `correlations[i]` with `findings[i]`. The two are
pushed in lockstep everywhere except one branch — a suppressed finding is passed
through without a correlation, because an approved deviation is not re-litigated
— so from the first suppression onward every gap named the wrong file and line.
On a project with an approved deviation early in the list, a coverage gap would
have been reported against a line whose departure had already been accepted.

The existing tests passed a single unsuppressed finding, where a wrong pairing
and a right one are the same pairing. Matching is by finding id now, as the rest
of the codebase already did. Watched failing: the old code put the gap on
`src/accepted.c:11` instead of `src/untested.c:42`.

The gaps are reported now, which makes the comment true. `sda scan` prints them
after the correlation counts, grouped by file:

```
Correlation
  inconclusive: 5
  refuted: 1
  unreached: 4

Coverage gaps — 3 distinct line(s) flagged but never reached, in 1 file(s)
  main.c: 13, 21, 28
```

Four unreached findings and three lines, because `21.3` and `D4.12` both fire on
line 21. The heading says *distinct line(s)* for that reason: a reader comparing
the two numbers should not have to work out which is wrong.

`coverage_gaps_reach_the_report.rs` drives the real binary over
`examples/coverage`, because the half a unit test cannot reach is whether the
section arrives in front of a person. A display nothing asserts is one refactor
away from being the uncalled function again. It also checks the other direction:
a run that measured no execution prints no gap section at all, because "this line
never ran" is not a fact anyone established.

#### What it also found, which was not a defect

`Report::fails_gate` is defined, tested three ways, and never called — but
`sda scan --fail-on` uses `run::gate`, which computes the same predicate *and*
returns a sentence explaining it. The two agree. So this is a duplicate rather
than a hole, and the tempting one to reach for is the one that says nothing.
Left alone and named here, because "uncalled" and "broken" are different findings
and the sweep cannot tell them apart.

**They stopped agreeing.** `run::gate` later learned a third answer — a scan
that read nothing has no verdict to give — and a `bool` cannot carry it, so the
copy in `sda-core` went on returning *passed* for a run that never happened.
The paragraph above was correct when it was written and was still sitting there,
reassuring, after it stopped being true. A duplicate is only harmless while
something compares the copies; `the_two_gates_agree_about_stopping` compares
them now, in all three cases, because the crates cannot share the predicate —
`sda-engine` depends on `sda-core`, not the other way round.

#### And the rest of the list, read rather than left

Eighty-eight rows is a list worth reading once, and the first pass stopped at the
first hit — which is how a sweep becomes a thing you ran instead of a thing you
used. The rest, in the order the sweep prints them, fall into three kinds and
only one of them was a defect.

**Duplicates.** `Report::fails_gate` against `run::gate`. `Obligation::deviable`
against an inline `r.obligation == Obligation::Mandatory` in the deviation
validator. `Catalog::is_complete` against the `self.complete` that
`Catalog::audit` already reads and reports. `Evidence::is_defect_witness` against
the `event.is_defect()` that `dynamic.rs` calls directly. In every case both
sides agree, so nothing is broken and nothing was hidden. The validator now asks
`deviable()` — a rule about which obligations may be silenced belongs in one
place, and the copy living in a validator is the one that gets forgotten when the
definition changes. The message it prints is deliberately unchanged: `as_str()`
is lowercase, and reaching for it would have rewritten a sentence four tests and
one report assert on. **A refactor that changes what a reader sees is not a
refactor.**

**Leftovers.** `clex::count_octal_escapes` and `clex::has_lowercase_u_suffix`,
neither called, sitting beside `has_lowercase_l_suffix`, which is — one of three
siblings wired up. That looks exactly like a hole and is not one. `7.3` is the
lowercase-`l` rule and is `native`; `7.2` is the `u`-suffix rule and is classified
**`semantics`**, because deciding it needs to know a constant's type. The helper
is uncalled *because the catalogue declines to claim that rule natively*. The
honesty of the classification is visible here as dead code, which is a pleasant
way to find it. `7.1`, `7.3` and `4.1` were each confirmed firing on the corpus
rather than assumed.

**Honest surface.** The remainder — builders like `with_obligation` and
`with_assumption`, `neural`/`symbolic`/`profiled`, the editor's `delete` and
`apply_all` — are API a workspace with a CLI on top legitimately exposes without
consuming. Reading them cost twenty minutes and is the price of the one real
find.

One real defect, four duplicates, two leftovers, the rest surface. That ratio is
worth writing down: it is the argument for the sweep being a list somebody reads
once a session rather than a gate anybody enforces.

### The other direction: failures that become silence

The uncalled-API sweep finds code that computes an answer nobody consults. The
dual is code that *is* consulted and whose failure nobody hears — and for this
toolkit that is not a general code-quality point, it is the thesis. A discarded
`Result` is an inability to check, presented as a clean check, one level below
where the *NOT CHECKED* section can see it.

Swept for `let _ =`, `.ok();`, `unwrap_or_default()` and empty `Err(_)` arms in
production code: 52 sites. Most are correct — removing a scratch directory,
killing a child that has already exited, a default for a missing optional string.
Three were not, and all three were in the same business: reading a file that
records a human decision.

**A project's own catalogue override was the one `.sda/` file whose failures were
discarded.** A project may ship `.sda/misra-c-2023.toml` to supply the licensed
rule text — that is what `unconfirmed_numbers` counts down. `catalog()` read it
inside `if let Ok(text)` with no `else`, then called `let _ = catalog.import(&text)`.
An unreadable file and a malformed one both left the built-in catalogue silently
in place, and `sda rules audit` went on describing a catalogue the project had
tried to replace — a conformance argument resting on rule text nobody supplied.

Every neighbouring declaration already had the discipline. Deviations are
"rejected and reported, never silently dropped". A broken scope file pushes a
problem and leaves the scan wide. The architecture declaration reports both its
read and its parse failure. The catalogue override was the odd one out, in the
same function, twenty lines away. It is validated at load now, with the others,
through the same `problems` channel that already reaches the CLI and MCP; the
fallback to the built-in catalogue stays, because over-reporting is the
recoverable direction, and it is now a documented choice rather than a dropped
error.

**The workbench turned a corrupt review file into an empty one.**
`TriageStore::load(..).unwrap_or_default()` on the scan path. An absent file is
already `Ok(default)`, so the only thing that call could swallow was a *malformed*
store — and it turned every recorded conclusion into "nobody has looked at this",
which is the state that gets a finding dismissed a second time by the person who
already decided about it once. The five other callers propagate; only the read
path did not, so a corrupt store showed as untriaged and then errored the instant
anyone tried to triage. The argument for the right behaviour was already written
two lines below, about the baseline: *"A malformed baseline is an error rather
than an absent one, so it does not quietly become 'nothing is new'."*

`stale_triage` had the same hole with no error channel to use — it returns
`Vec<String>`, and returned an empty one when the store would not load, which is
a claim about review state made by a call that could not read it. Its return type
is a list of notices, so the failure is a notice now.

`TriageStore::parse` was already tested for malformed input. `load` was tested
only for the absent case, which is the half that does not matter; its complement
is pinned now at the level the callers actually use.

### One unreadable file zeroed the whole C analysis

The same sweep, one level up: not a discarded `Result`, but a propagated one that
took everything with it.

Both native analyzers read each source with `?`:

```rust
let src = std::fs::read_to_string(&file.path)
    .map_err(|e| sda_core::Error::io(file.path.display().to_string(), e))?;
```

so the first file that could not be read failed the entire provider, discarding
every finding from every file already analysed. On a two-file tree, **four
findings became zero**.

The trigger is not exotic, which is what makes this the worst defect found this
session. `read_to_string` requires valid UTF-8. A copyright line carrying a
Latin-1 `©` is not valid UTF-8, and is ordinary in legacy C — the kind of tree
this toolkit exists for. One such file anywhere under the scan root reduced the
whole C analysis to nothing, reported as `provider failed during analysis`. Not
silent, but a reader seeing zero findings and one line about a provider is being
told the tool broke, when in fact their other nine hundred files were analysed
and thrown away.

This is the rule the `--artifact` launch already learned, in this document, in
these words: *an inability to check must not be presented as a clean check, and
must not throw away the checks that did happen.* It had been fixed in the
dynamic path and never asked of the static one.

Per-file now. The unreadable file is skipped, every other file is analysed, and
the skip is named in *NOT CHECKED* through `take_notices` — the mechanism whose
own documentation describes this exact case, implemented by the external adapters
and by neither native analyzer until now. A file discovery counted and analysis
never read is the difference between "we looked at your tree" and "we looked at
most of your tree", and only the report can tell the reader which.

`check_manifest` had a quieter version of the same thing: an unreadable
`Cargo.toml` returned no findings and said nothing, so `ED2024.5` and `DEP.3` —
decided there and nowhere else — silently did not run. An *absent* manifest still
says nothing, because a directory of Rust files need not be a crate root.

**Fixing it deleted a test's only reason to fail.**
`a_provider_error_becomes_an_exclusion_not_a_clean_result` produced its provider
error by pointing the real C provider at a file that does not exist. That is now
a per-file skip, so the test passed for a new reason and the path it existed to
guard — a provider that genuinely fails — had no coverage left, since no stub in
that module returns `Err`. It has one now. **A test that still passes after the
behaviour under it changes is worth more suspicion than one that breaks.**

### The fixtures prove a rule fires, and nothing proves one stays quiet

Every fixture in `checks.rs` is a small source written to violate one named
guideline, and the test requires that guideline to appear. That catches a check
which does nothing — the C++ analyzer once passed every list-based test while
emitting no findings at all — and it cannot catch the opposite. **A rule that
fires on everything passes its fixture.**

That is not hypothetical here. Over-reporting is this catalogue's recurring
defect: `5.4`/`5.5` comparing 31 significant characters where the standard says
63, `11.9` matching `*revision = 0;` and producing 28 false positives on PX4,
`8.2` reading `PARAM_DEFINE_INT32(...)` as a prototype and producing 674. Every
one was found by running on somebody else's tree, and none by a test.

Writing a conforming corpus is the real answer and is not cheap — MISRA-clean C
is hard to write by accident. There is a cheaper question that uses what already
exists: **how many of the other rules' fixtures does each rule fire on?** A rule
appearing on most of them is a candidate.

Two stood out. `D4.6` fires on 39 of 80 C fixtures, and that is correct: it
objects to every plain `int`, and nearly every fixture has one. `UNSAFE.3` fired
on **twelve of fifteen** Rust fixtures.

#### `UNSAFE.3` was a claim about a crate, decided from one file

The guideline is *"a crate with no need for unsafe code shall declare
`#![forbid(unsafe_code)]`"*. The check fired on any `lib.rs` containing no
`unsafe` and no `forbid`. A crate whose root is clean and whose modules are not
satisfies both conditions exactly, so the finding appeared — and the advice was
worse than wrong:

```
src/lib.rs:1:1: RUST-2024-UNSAFE.3 (low)
  this crate root contains no `unsafe` and does not declare `#![forbid(unsafe_code)]`
```

against a crate whose `src/hw.rs` reads a memory-mapped register.
`#![forbid(unsafe_code)]` is crate-wide, so a reader who followed that advice
would not get a stricter crate; they would get one that does not compile.

It is `system` scope now, beside MISRA `5.1` and `D4.5`, and decided in `analyze`
where every source under the crate root can be consulted. A file nobody could
read counts against the claim rather than for it: an unreadable module is not
evidence that a crate is unsafe-free.

**The editor's buffer path no longer raises it at all.** One file is not evidence
about a crate, and a rule that cannot be decided from a buffer should not appear
to have been — the same divergence `check_buffer` exists to prevent, arriving
from the other direction. That makes it fixture-exempt, beside `DEP.3` and
`ED2024.5`, for exactly the reason they are: a fixture is one file.

The twelve-of-fifteen count was itself mostly an artifact — the Rust fixtures are
named `lib.rs`, so they all met the old condition. The signal was still worth
following, and no fixture could ever have caught this one.

#### Near-misses: the assertion the fixtures were missing

The gap named above is closed enough to build on. `C_NEAR_MISSES`,
`RUST_NEAR_MISSES` and `CPP_NEAR_MISSES` in `checks.rs` hold sources that *look*
like a violation and are not, and `a_near_miss_does_not_trip_the_rule_it_resembles`
requires the named rule to stay quiet on each. Fourteen to begin with, aimed at
the rules whose over-reporting this document already records: `5.4` on two macros
differing inside 63 characters, `11.9` on `*p = 0;`, `8.2` on a macro invocation
at file scope, `13.6` on a `sizeof` with no side effects, `2.6` on a label a
`goto` targets, `21.6` on a project function whose name merely contains a library
one's.

Each carries a `why`, and that field is not decoration. **A near-miss is only as
good as the reason it is conforming**, and the failure message prints the reason
so a reader can tell an over-reporting rule from a near-miss that was wrong about
the guideline. Both are worth stopping for; they are not the same finding.

All fourteen passed on the first run, which by this session's standard is when to
distrust a test rather than believe it. Calibrating it took two attempts and the
first one taught something:

* Making the **12.1** near-miss genuinely violating — `return a * b + c;`, an
  unparenthesised mixed-precedence expression — left the test green. That is not
  a broken assertion. `12.1` is `partial` and checks a couple of operator pairs
  rather than the open-ended guideline, exactly as this document records, so it
  does not fire on that expression either. **A near-miss against a `partial` rule
  proves little, because the rule barely fires.** The entry is kept with that
  caveat written into its `why`.
* Making the **D4.6** near-miss violating — a plain `int` — failed it correctly,
  naming the rule, the reason and the source.

The table is meant to grow. The rules with no near-miss are not thereby innocent;
they are unexamined, which is the distinction this whole document is about.

#### It grew by eleven, and the second batch found one

Eleven more near-misses, aimed at rules where over-firing is plausible and a
conforming case is easy to state: `7.1` on a bare `0` and a hexadecimal constant,
`7.3` on an uppercase `L` suffix and an identifier that merely contains the
letter, `D4.4` on prose that describes what the code does, `2.5` on a macro that
*is* used, `13.4` on an assignment standing as its own statement, `15.7` on a
chain that ends in `else`, `16.4` on a switch with a `default`, `21.3` on a
project function named `allocate_slot`.

Ten stayed quiet. **`D4.9` fired on `#define STRINGIFY(x) #x`.**

The guideline asks for a function *"where they are interchangeable"*, and the
check read only `if function_like`. A replacement list using `#` or `##` is not
interchangeable with anything: neither operator can be written inside a function
at all, so there is no function to prefer. Every stringising or pasting macro was
a finding — assert wrappers, logging macros, register definitions — each advised
to become something the language cannot express.

The construct was never unreported: `20.10` fires on it, and is the guideline
that actually covers `#` and `##`. Both findings appeared on that two-line file.
The exemption is written as `body.contains('#')` deliberately, because that is
exactly what `20.10` tests, so the two cannot disagree about what a stringising
macro is. They also share its imprecision — a `#` inside a string literal in the
replacement list reads as the operator — which costs a `D4.9` and never adds one,
and `20.10` already had the same blind spot.

MISRA C++ reports this guideline as `19.0.1` through the same code path, so a
near-miss is pinned in both catalogues rather than in whichever one happened to
be tested. Watched failing with the exemption removed.

**Twenty-five near-misses, one defect.** That rate is worth recording next to the
uncalled-API sweep's one-in-eighty-eight: writing the conforming case for a rule
is slower than listing uncalled functions, and pays better.

#### Two more batches: nothing in C, and `FFI.1` in Rust

Twelve more C near-misses — `12.3` on commas separating declarators and
arguments, `21.1` on a name with a trailing underscore, `20.1` on one `#include`
following another, `18.5` on two levels of pointer nesting, `19.2` on a struct,
`6.2` on an `unsigned` single-bit field, `17.2` on a function calling a different
one — and every one stayed quiet. Worth knowing, and worth writing down as a
result rather than as silence.

The Rust catalogue had two near-misses against seventeen rules, and the C++ one
two against twenty-one. Nine Rust near-misses later, **`FFI.1` fired on an
extern declaration that documents itself.**

`FFI.1` requires *every extern function declaration* to document the invariants
the foreign side must uphold. The check subjected the **block** to the rule and
never the declarations inside it, then asked for a comment "within three lines
above". Both halves were wrong, in opposite directions:

* Documenting each function where it is declared — inside the block, where
  rustdoc renders it and where a reviewer looks — puts the comment *below* the
  block's line. It did not count, so complying code was reported. And
  `unsafe extern` is the form `ED2024.3` *requires* in edition 2024, so following
  one rule in this catalogue produced a finding from another.
* One comment above a block satisfied the rule for every declaration in the
  first few lines of it. **A comment above a block cannot say what `buf` must
  point to, because it does not know which function it is describing.**

The subject is each declaration now — a `Function` item inside an extern block's
line range, or a function carrying its own ABI — and a doc comment counts when it
sits immediately above, not within a three-line window. That errs toward
reporting, since an attribute written between the comment and the declaration
defeats it; for a guideline about whether a contract is written down at all, a
spurious request to write one is the better failure.

The false negative is the one that mattered. The first direction reported
conforming code, which a reader argues with; the second reported nothing, which
nobody argues with.

**Forty-six near-misses, two defects**, and the two catalogues that had barely
been examined produced one of them on the first pass. The C list now covers 33 of
80 implemented checks, C++ 2 of 21, Rust 11 of 17.

#### And the C++ catalogue, on its first pass: `8.2.3`

Sixteen C++ near-misses, and one of them found a rule citing a guideline the code
does not break. **`8.2.3` fired on `const_cast<const S &>(s)`.**

The guideline is about `const_cast` *removing* const qualification. The check read the token and nothing else, so a cast that
**adds** const — which the guideline permits — was reported against it. In a
conformance argument that costs a deviation written for a rule nobody violated,
which is worse than a merely noisy finding: it puts a false admission into the
record.

The target type is the part this engine can read without type information, and a
cast whose target is const-qualified is not stripping const from the top level.
The residual gap is stated rather than hidden: `const_cast<const int *>(p)` where
`p` is `const int *const` strips the pointer's own const behind a const-qualified
target, and closing that needs the source type, which this engine does not have.
It is a far rarer construct than the false positive it removes.

**Writing the near-miss was itself the near-miss.** The first draft of that entry
used `const_cast<S &>(s)` on a `const S &` — which *is* a removal, and so is a
violation, not a near-miss. Caught before it ran. A near-miss that is secretly a
violation does not report a defect that exists; it manufactures one, and the
"fix" would have silenced a rule that was working.

**Sixty-two near-misses, three defects.** Coverage: C 33 of 80, C++ 18 of 21,
Rust 11 of 17.

#### Finishing the two thin catalogues found two more

Six more entries — the last three C++ rules and the three Rust rules a single
buffer can reach — and two of them fired.

**`21.10.2` fired on `b.signal(1)`.** The library-function check required the
identifier to sit in a call position and never looked at what came *before* it,
so a call through `.` or `->` reached a member of `b` and was reported as
`<csignal>`'s `signal`. The spelling is everywhere in event-driven C++, and
`logger.printf(..)` and `pool.free(..)` are the same shape — this was not one
guideline's problem but the whole `21.*` family's. A qualified name is still
reported, deliberately: `std::signal` is the library function, and this engine
cannot tell `std::` from `mylib::`.

The member *declaration* inside a class body still reports, and the near-miss
says so. Telling `void signal(int);` in a class from one at file scope needs to
know it is inside a class, which this engine does not track.

**`DEP.2` fired on `src/build.rs`.** The check asked whether the file is named
`build.rs`. Cargo runs `build.rs` only at the package root; one under `src/` is
an ordinary module it never executes, so the thing DEP.2 is about — code running
with the developer's privileges before review — is not happening. The test is on
the parent's components rather than on the whole path, so `member/build.rs` in a
workspace keeps reporting; requiring the file to sit at the scan root would have
stopped reporting every workspace build script.

**And three rules cannot have a near-miss at all.** `UNSAFE.3` is decided over
the whole crate, `ED2024.5` and `DEP.3` from `Cargo.toml`; the near-miss test
drives one buffer through the per-file checker, so an entry for any of them would
pass whatever it contained. `NEAR_MISS_EXEMPT` names them with reasons, and a
test refuses a near-miss that targets one — the same guard `FIXTURE_EXEMPT`
provides in the other direction. Listing them is cheaper than discovering later
that an entry proved nothing.

**Sixty-eight near-misses, five defects.** Coverage: C 33 of 80, C++ 21 of 21,
Rust 14 of 17 with the other three exempt — both catalogues complete. The C list
is the only one left, and two batches there have produced nothing.

#### Targeting the shape rather than the list

Five defects in, they have one shape: **a check keyed on a token or a name, with
nothing said about its surroundings.** `D4.9` read `function_like` and not the
replacement list. `8.2.3` read `const_cast` and not the target type. `21.10.2`
read the identifier and not the token before it. `DEP.2` read the file name and
not the directory. `FFI.1` read the wrong item entirely.

So the next C batch was chosen by that shape rather than by working down the
list, and probed first — seven constructs scanned in one go, which is quicker
than writing seven near-misses to find out. Six came back clean:
`asm_delay()`, a local `_x`, `extern int table[10];`, a `for` loop, a typedef'd
struct, and a `d->open()` call. The seventh, `#define IDENTITY(x) (x)`, fired
`D4.9` correctly.

**The op-table case was already fixed and nobody knew.** `o->free(p)` and
`l->printf("x")` are clean because the `.`/`->` guard added for C++ lives in the
shared library check. Function pointers named after the operation they perform
are how most embedded C is structured, so that fix was considerably broader than
the C++ near-miss that found it. Both shapes are near-misses now, in the C
catalogue, watched failing with the guard removed — a fix nobody is testing is a
fix waiting to be undone.

#### One difference recorded rather than fixed

`#include "signal.h"` reports `21.5`. The guideline names the *standard header*,
and a quoted include searches the project first, so a project with its own
`signal.h` is reported for a guideline it does not break.

It is left alone, and the reason matters more than the case. The quoted form is
genuinely ambiguous: if the project has no such header the search falls through
to the system one, and deciding which needs the include path and the file system,
neither of which a standalone file offers. Silencing it would buy a rare false
positive at the cost of a **false negative on a `native` rule** — a real
`<signal.h>` slipping through a quoted include, with `sda rules audit` still
offering a clean result as evidence of conformance. Over-reporting is the
recoverable direction, and this is the same reading already recorded for `21.6`
and `#include <stdio.h>`.

**Seventy-three near-misses, five defects**, C now 38 of 80.

#### The table is complete, and the completeness is checked

Three more probe-and-write rounds finished it. **117 near-misses: every
implemented check in all three catalogues now has one, or an exemption saying why
a single buffer cannot show one.**

`every_implemented_check_has_a_near_miss_or_an_exemption` enforces that, mirroring
`every_claimed_check_actually_fires`. One proves a rule fires on code that
violates it; the other proves somebody has written down what *conforming* code
looks like. Adding a rule now means adding both, which is the point — **the
fixture and the near-miss are two halves of one claim, and a rule with only the
first can fire on everything and still look checked.** Watched failing with a
single entry deleted.

**Probing before writing is what made the last rounds cheap**, and it caught two
mistakes that would have been expensive. `8.14` bans the `restrict` qualifier
outright, and the draft near-miss used it — a violation, not a near-miss. `D4.2`
is about assembly being *documented*, not encapsulated; the draft satisfied
`D4.3` and had no comment. Both would have "found" a defect that does not exist,
and the fix for either would have silenced a rule that was working. That is this
instrument's own failure mode, and it has now bitten three times: writing the
conforming case demands reading the guideline, not remembering it.

The `21.*` family is covered rule by rule rather than by the two that happened to
be written first, because the defect that broke it — reading an identifier
without looking at what precedes it — broke every one of them at once.

**One hundred and seventeen near-misses, five defects.** The yield fell as the
catalogues filled: the first twenty-five found one, the next twenty-one found
four, the last seventy-one found none. The last rounds bought regression cover
for fixes already made rather than new findings, which is worth having and worth
being honest about — a fix nobody is testing is a fix waiting to be undone.

#### Closing the limitation instead of leaving it written down

The `21.10.2` near-miss was narrowed when it was written, because the fix covered
the *call* through `.` and not the *declaration*:
`struct Bus { void signal(int); };` still reported. That was recorded as a
limitation and left, which is the honest thing to do once — and a poor thing to
leave, because this toolkit analyses headers standalone by design, so a header
declaring such a class was reported with no call anywhere in the file.

There is a general discriminator that needs no class tracking: **two adjacent
identifiers cannot be a call in C or C++.** A name preceded by a type or a
declaration specifier is a declarator, and the `21.*` guidelines are about
*using* a facility, not about declaring something with the same name.

`*` and `&` are deliberately excluded from that set. `void *malloc(...)` is a
declaration, but `*get_ptr()` is a call, and mistaking the second for the first
loses a real finding to save a rare one.

**The first version lost a real finding anyway, and cppcheck said so within a
minute.** The "user-defined type name" fallback matched any identifier-shaped
token, and `return` is identifier-shaped — so `return system(cmd);` in
`vgwrap.c` read as a declaration and a live `21.21` went silent.
`what_cppcheck_finds_and_this_does_not_is_what_this_says_it_cannot_check` failed
on it immediately. Keywords are excluded now.

That is the differential oracle earning its place in the direction that matters.
A near-miss can only show that a rule stopped over-reporting; only a second
implementation can show that it started under-reporting, and under-reporting on a
`native` rule is what `sda rules audit` offers as evidence of conformance.

### Every narrowing this session, checked against real code

Five fixes this session made a rule report *less*, and the `return system(cmd)`
bug showed what that can cost. The near-misses cannot catch it — they only prove
a rule stopped over-reporting — and the corpus is fifteen small files. So the
binary at the session's first commit was rebuilt from `git archive` and both were
run over three real trees, comparing finding sets.

| tree | files | before | after | disappeared | appeared |
|---|---:|---:|---:|---:|---:|
| `llama.cpp/src` (C++) | 184 | 1,256 | 1,253 | 3 | **0** |
| `bibutils` (C) | 149 | 8,555 | 8,552 | 3 | **0** |
| `PX4-Autopilot/src` | 20,287 | 73,873 | 73,401 | 472 | **0** |

**Nothing appeared, and every one of the 478 removals was checked.**

**These are counts of distinct findings, not of findings.** The comparison is
between finding *sets*, keyed on rule, file and line, because that is what makes
"disappeared" and "appeared" answerable. PX4 emits 78,211 findings and 73,401
distinct ones; two guidelines firing at different columns of one line are two
findings and one set member. Both numbers are in this document — the subsection
below counts the raw ones — and for a while nothing said they measure different
things, which is a trap for exactly the reader most worth helping: someone
re-running the scan to check for a regression finds 78,211, reads 73,401 in this
table, and concludes the tool moved by four thousand eight hundred and ten.
Measured, both, from one scan.

The 429 macro removals — `D4.9` and its C++ number `19.0.1` — were verified
mechanically rather than sampled: for each one the `#define` was re-read from
source, its backslash continuations joined, and its replacement list tested for
`#`. All 429 use `#` or `##`. They are `BMP3_SET_BITS(reg_data, bitname, data)`
and its kind — register-manipulation macros that paste a field name onto a mask
suffix, which no function can do.

The 43 library-rule removals were read one by one:

* `allocator->malloc(size)`, `ops->free(h)`, `rhc->ops->free(..)` — calls through
  function-pointer members of an allocator or ops struct, right through
  CycloneDDS. The op-table pattern, in the wild, at the scale predicted.
* `extern int snprintf(char *s, size_t n, const char *format, ...);` and
  `inline void free(CanardInstance *const ins, void *const pointer)` —
  declarations and definitions of library names, which is not *using* the
  library. One of them, in bison-generated code, carries the comment
  `/* INFRINGES ON USER NAME SPACE */` — and that is `21.2`'s business, not
  `21.3`'s.
* `int` on one line and `snprintf(` on the next, which is a definition split
  across lines. It looked like the one real call in the list until the previous
  line was read, which is the reason for reading all forty-three.

**Eighty-three thousand findings, four hundred and seventy-eight fewer, and not
one of them a finding worth having.** That is the strongest statement this
session can make about the narrowings, and it needed a second binary and three
real codebases rather than another test.

#### And the findings that stayed

The delta was verified; the 78,211 findings PX4 still produces never had been. Two
cheap questions were put to them.

**Where does the volume come from?** Five rules are half of it:

| rule | findings | share |
|---|---:|---:|
| `D4.6` a basic numerical type | 17,367 | 22.2% |
| `15.6` body is not a compound statement | 11,499 | 14.7% |
| `21.6` standard I/O | 5,301 | 6.8% |
| `13.4` the value of an assignment is used | 4,753 | 6.1% |
| `15.5` more than one point of exit | 4,272 | 5.5% |

Each was sampled against the source. `15.6` is `while (!Time_CheckTimeout(..));`
— an iteration statement whose body is an empty statement — and `for (i = 0; i <
9; i++)` with an unbraced body. `13.4` is
`if ((error = VnSensor_connect(..)) != E_NONE)`, which is the construct the
guideline names. `15.1`'s three thousand `goto`s and `8.14`'s fifteen hundred
`__restrict` qualifiers looked implausible for a C++ project and are real: PX4
vendors a great deal of C, and CycloneDDS uses both throughout. **Nothing in the
top of that distribution is an artefact.**

**Is anything reported twice?** No. 78,211 findings carry 78,211 distinct ids and
78,211 distinct rule/file/line/**column** tuples. The gap between that and the
73,401 distinct rule/file/line tuples is entirely lines holding more than one
violation — `dds_cdrstream.h:115` declares two `__restrict` parameters and is
reported twice, correctly. That matters because a duplicate is a miscount, and a
report whose whole purpose is to say *how many* is wrong about the thing it
exists to say.

#### And the rules that said nothing at all

The third question is the one a conformance report most deserves: **which
implemented checks fired zero times on twenty thousand files?** A clean result on
a rule that never fires anywhere is worth less than a clean result on one that
does, and a check that is quietly broken looks exactly like a check on a
construct nobody writes.

Sixteen of the eighty MISRA C checks were silent on PX4, and two of the C++ ones.
Every one was then put in front of the construct it exists for, and **twelve
fired immediately**: `3.1` on a nested comment opener, `6.2`, `8.16`, `8.17`,
`16.2` on a label inside a nested compound statement, `17.6` on
`int a[static 10]`, `21.11`, `21.12`, `21.21` on a real `system("ls")`, `21.25` on
`memory_order_relaxed`, and the C++ `5.7.1` and `21.10.1`.

The hypothesis going in was that the fixtures use an explicit spelling while real
code uses an implicit one — `6.2`'s fixture says `signed int flag : 1`, and real
code writes `int flag : 1`, which is also signed. **That was wrong: `6.2` fires on
both.** Worth recording precisely because it was a good guess that did not hold.

The remaining six cannot appear in code that compiles, or are already written up:
`4.2` trigraphs, which cppcheck 2.21.0 cannot read either; `11.10`, a constraint
violation the compiler rejects; `20.13`, a line beginning `#` that is not a
directive; `20.2`, a header name containing characters whose behaviour is
undefined; `20.14`, whose `#endif` must be in another file and which this
file-local check cannot see; and `5.5`, which needs two names agreeing for
sixty-three characters and differing after — an identifier *identical* to a macro
cannot occur, because the macro would expand.

**No defect came out of this round.** That is the result, and it is worth the
paragraph: eighteen silent checks are now eighteen checks known to work, rather
than eighteen open questions behind a clean report.

#### Four checks that fell between the two tests

`checks.rs` gives every catalogued rule a fixture proving it fires and a
near-miss proving it stays quiet, and both tests iterate `implemented(standard)`.
The engine also reports four things under its **own** name — `SDA-C-COMPLEXITY`,
`SDA-C-NESTING`, `SDA-C-MULTICHAR` and `SDA-C-LEXICAL` — which are in no
standard, so they fell through the middle of that pair. **`SDA-C-COMPLEXITY`
fires 1,285 times on PX4 and had no test at all.**

Being outside the catalogues is deliberate and right: they are observations
rather than guideline verdicts, which is why `D1.1` and `D4.1` are deliberately
absent from `IMPLEMENTED_C` and why a clean result on them is offered as evidence
of nothing. It is not a reason for them to be unexamined.

Two are thresholds — `complexity > 15` and `nesting > 5` — and a threshold is
where an off-by-one lives. Both edges were measured before anything was written:
fourteen decisions stays quiet and fifteen fires, five levels stays quiet and six
fires, `'ab'` is reported and `'a'` is not, an unterminated comment is reported
and a closed one is not. **All four were already correct.**
`the_engines_own_rules_have_bounds.rs` pins that rather than fixing it, and was
watched failing with both thresholds changed to `>=`.

**The same question, asked of the dynamic ids, and the first answer was wrong.**
Checking whether each `SDA-*` id is mentioned in a file that contains tests said
all twelve were covered. That is not coverage, it is proximity — the id and the
tests were in the same file. Counting only occurrences inside a `tests/` file or
after a `#[cfg(test)]` marker gave the real answer: **eight were asserted
nowhere**, including seven of the nine arms of `classify`, the function that
decides what a runtime event *becomes*.

That mapping is the whole of what a dynamic finding is. A Memcheck invalid-write
arriving as `SDA-DYN-LEAK`, or a data race at `Medium`, would be wrong in a way
nothing else here would notice — and this codebase has had a defect of exactly
that shape, in the external findings whose `AnalysisPhase` was `Static` because
nothing set it. Every kind is asserted now, through `findings_from` rather than
against `classify` directly, so the test covers what reaches a report. The
`match` in the test is exhaustive: adding a `RuntimeEventKind` will not compile
until somebody states what it becomes.

#### `SDA-DYN-INFO` cannot reach a report

Following that thread found a dead arm. `classify` maps
`Coverage | ValueObservation | Syscall` to `SDA-DYN-INFO`; its only caller
iterates `defects()`, which filters on `is_defect()`, which excludes exactly
those three. The arm exists to satisfy exhaustiveness and nothing can reach it.

It is left in place rather than made `unreachable!()`, because a panic in that
path would be worse than a dead arm. What is worth guarding is the invariant
behind it: were `is_defect` ever widened, a coverage record would quietly become
an `Info`-severity finding — **a fact about the instrument presented as a fact
about the code**, which is the failure this document is about. Watched happening:
widening `is_defect` by one variant produced a finding named `SDA-DYN-INFO` on a
line that had merely executed, and the test names it.

### External providers on Linux, and a gap closed by asking

Item 12's remaining gap read: *"Neither clang-tidy nor cppcheck is installed in
that Debian, so external providers at that scale need an apt install that has not
been asked for."* That sentence is exactly right, and it was misread twice in one
session as *blocked on a sudo password*. It is not: `wsl -d Debian -u root` gives
uid 0 with no password, which is how Valgrind was installed. **The block was
nobody having asked.** Asked, and answered: both are installed now — cppcheck
**2.17.1** and clang-tidy **19.1.7**, from Debian stable.

Worth knowing that those are not the Windows versions. Windows has cppcheck
2.21.0 and LLVM 21/22; Debian ships 2.17.1 and 19.1.7. So this bought a second
*version* of each tool as well as a second operating system.

`sda` builds for Linux in **57 seconds** to a 4.88 MB binary, and
`sda tools status` reports both correctly on the first run: `ext.cppcheck —
installed`, and `ext.clang-tidy — degraded: installed, but without a
compile_commands.json it analyses a guess at the build configuration rather than
the real one`.

#### The same adapter, two operating systems, two tool versions

`bibutils`, 149 C files, scanned on both with `--with ext.cppcheck`:

| | Windows, cppcheck 2.21.0 | Linux, cppcheck 2.17.1 |
|---|---:|---:|
| native engine findings | 8,552 | 8,552 |
| native findings differing | — | **0** |
| `ext.cppcheck` findings | 956 | 925 |
| shared | 921 | 921 |
| only on that side | 35 | 4 |

**The native half is identical, to the finding.** That reproduces the PX4
cross-OS result on a different tree and with the adapter path live, which the
earlier run did not have.

**Every difference in the other half is the tool's version, not the adapter's
behaviour.** The 35 Windows-only findings are `variableScope` (18),
`shadowVariable` (8), `constVariablePointer` (4) and a scattering of
`constParameter*` — checks cppcheck added or sharpened between 2.17 and 2.21. The
4 Linux-only findings are all `varFuncNullUB`. Nothing in either list is a
location or a rule the adapter mangled; it passes through what the tool says,
which is all it should do.

The run also put `take_notices` in front of a real tool on Linux for the first
time. cppcheck said `missingIncludeSystem` 273 times, `missingInclude` 61 and
`normalCheckLevelMaxBranches` 57 — and all of it arrived in *NOT CHECKED* as
statements about the analysis rather than as findings among the real ones, which
is the door that mechanism exists to guard.

#### The oracle is pinned to one version of itself

The committed fixture holds cppcheck **2.21.0**'s answers. Debian ships **2.17.1**
and its MISRA addon, so the same corpus could be put to both — a question the
fixture cannot ask about itself.

| | 2.21.0 | 2.17.1 |
|---|---:|---:|
| findings | 215 | 159 |
| guidelines named | 64 | 54 |
| shared findings | 152 | 152 |
| only that version | 63 | 7 |

The newer addon is broadly the better oracle, as expected: eleven guidelines are
named only by 2.21.0 — `8.7` (19 findings), `21.6`, `17.7`, `8.4`, `12.1`, `2.5`,
`21.3`, `17.6`, `20.2`, `20.3`, `11.9`, `14.2`, `15.2`, `18.5`, `20.11`, `8.10`,
`8.14` — and pinning the fixture to it was right.

**One guideline goes the other way, and it is the interesting one.** `3.2` is
reported by 2.17.1 and not by 2.21.0. This document records why 2.21.0 is silent:
`misra_3_2` is written and commented out of its own dispatch table. That is
accurate, and it was stated as though it were a property of cppcheck. It is a
property of **that release**:

```
2.21.0  addons/misra.py:4723   #self.executeCheck(302, self.misra_3_2, data.rawTokens)
2.17.1  addons/misra.py:4557    self.executeCheck(302, self.misra_3_2, data.rawTokens)
```

cppcheck **removed a working check** between those releases. And where 2.17.1
does run it, it agrees with this engine exactly: `tools/misra-corpus/lexical.c`
line 22, against `lexical.c:22:1` here. `3.2` already had clang's `-Wcomment` as
a second implementation; this makes a third, and the only one that is another
MISRA tool.

**The twelve were re-asked, and the answer is no.** Running
`misra-evidence-tiers.py` against 2.17.1's addon gives exactly the same tiers:
`6.3 7.6 8.16 8.17 17.10 21.24 21.25 D4.3 D4.6 D4.9 D4.10 D4.12` are dispatched
by neither release. So the advice above is already discharged for the only other
version available here, and the tier is not an artefact of the pin.

**What the versions actually differ in is sharpness, not coverage.** Both
dispatch the same checks — `misra_8_7` is in both tables — yet `8.7` fires
nineteen times on 2.21.0 and not once on 2.17.1. The newer release did not add
guidelines; it made existing checks find more. The single exception is `3.2`,
which is not a difference of sharpness at all but a line somebody commented out.

**What to take from it.** An oracle is a version, not a tool, and "cppcheck does
not implement this" is a sentence with a date on it. But the interesting drift is
the quieter one: a check that is present in both releases and finds nineteen
things in one of them. A fixture pinned to a version records *that* version's
thoroughness as though it were the guideline's, and nothing in this repository
would notice if the next release got sharper again. The fixture stays pinned to
2.21.0 — it finds more and the tests are written against its answers — and this
is a note about what the pin costs.

#### And the fixture had already drifted from its own corpus

`cppcheck-misra-oracle.py --drift` compares the installed cppcheck against the
committed fixture and says what a newer one would add. It is not a test and must
not become one — a finding the fixture lacks is news about cppcheck, not a defect
— but nothing was asking the question at all.

**Run against the very version the fixture is pinned to, it reported two findings
missing.** Not a version difference: `tools/misra-corpus/control_flow.c` grew an
`abandoned()` function in `ac5fa75`, to exercise `2.6` against clang, and the
fixture was never re-captured. cppcheck reports `8.4` at line 72 and `15.5` at
line 75 of code that did not exist when those answers were recorded.

Re-captured: **215 findings to 217**, and the comparison still passes, for the
right reasons in both cases. `8.4` is classified `semantics`, so it satisfies the
test's demand that anything cppcheck finds and this engine does not must be a
declared gap. `15.5` is `native` and *is* reported here — at line 72 where
cppcheck says 75, which is the anchor difference this comparison deliberately
does not compare.

The lesson is narrower than the version one and more likely to recur. **A fixture
is a photograph of two things, and only one of them is the tool.** Grow the
corpus and the photograph is stale, with nothing to say so, because the test
compares this engine against the fixture and never the fixture against the
corpus. That is what `--drift` is for; run it whenever the corpus changes.

#### So the other four fixtures were asked the same question

Every oracle fixture in the repository, re-captured from the tool installed today
and diffed against what is committed:

| fixture | captured from | installed now | drift |
|---|---|---|---:|
| `cppcheck-misra` | Cppcheck 2.21.0 | Cppcheck 2.21.0 | **2** |
| `clang-warnings` | clang 21.1.6 | clang **22.1.8** | 0 |
| `clang-tidy-cpp` | LLVM 21.1.6 | LLVM **22.1.8** | 0 |
| `clang-tidy-cpp`, again | LLVM 21.1.6 | LLVM **19.1.7** (Debian) | 0 |
| `clippy-lints` | clippy 0.1.98 | clippy 0.1.98 | 0 |
| `clippy-edition-lints` | clippy 0.1.98 | clippy 0.1.98 | 0 |

**clang and clang-tidy crossed a major version with identical answers** — same
files, same lines, same guidelines, 21.1.6 to 22.1.8.

Debian's clang-tidy **19.1.7** then made that a much stronger statement. Same
corpus, same three files: **13 findings, identical to the fixture** — same lines,
same guidelines, and the same check names. So the C++ oracle gives the same
answers across **three major versions, 19 through 22**. cppcheck's addon, across
two *minor* releases, changed 63 findings, renamed check ids, and stopped
dispatching one check entirely.

That is worth knowing when choosing what to be held to. A compiler diagnostic is
part of the compiler's contract with its users: the check names are API, and they
move slowly and loudly. A MISRA addon is a script shipped alongside one, and moves
as scripts do — `uninitMemberVar` became `uninitMemberVarNoCtor`, `shadowVariable`
became `shadowMember`, between 2.17 and 2.21. Both are second implementations and
only one of them is stable, which is an argument for the clang comparisons
carrying more weight per guideline than their count suggests.

Only `cppcheck-misra-oracle.py` grew a `--drift` mode, because only cppcheck
drifted. For the others the method is a re-capture to a temp file and a diff,
which is five minutes and is what produced the table above.

#### The scale point, on Linux, and a number that reconciles

`llama.cpp/src` is this repository's documented scale point: 184 files, and a
2026-09-07 row recording **cppcheck 1,453 findings in about four minutes**. Run
again today on Windows with the same 2.21.0 it gives **1,130**, and the checkout
has not moved — it is still at a May commit with 184 files.

The difference is not drift. It is a fix. 322 of that 1,453 were
`missingIncludeSystem` (230), `missingInclude` (58), `normalCheckLevelMaxBranches`
(32) and `checkLevelNormal` (2) — cppcheck describing its own analysis, which at
the time arrived as `information`-severity findings among the real ones. They go
to *NOT CHECKED* now, through `take_notices`. **1,453 − 322 = 1,131, against 1,130
measured.** One finding apart, which is as close as two runs a week apart get.

That is the `take_notices` mechanism validated at scale rather than on a fixture:
322 statements about the analysis, on a real 184-file tree, no longer counted as
things wrong with the code.

On Linux with cppcheck 2.17.1 the same scan gives **873**, and the native half is
identical to Windows to the finding — 1,276 raw, 1,253 once lines carrying more
than one violation are collapsed, **0 differing**. That is the cross-OS result
reproduced on a second tree, now with the external adapter live.

The two cppcheck versions also disagree about *names*, not only counts. 2.21.0
reports `uninitMemberVarNoCtor` 167 times and `shadowMember` 75; 2.17.1 reports
`uninitMemberVar` 40 and `shadowVariable` 48. **An external deviation is keyed on
the tool's rule id**, so a project that accepted `shadowVariable` and then
upgraded would find its deviation matching nothing — silently, before this
session. The unused-deviation notice added here is what now says so, and this is
the case it was written for without knowing it existed.

#### clang-tidy refuses, then runs

On Linux, `--with ext.clang-tidy` with no database reports
`provider failed during analysis: this tool needs a compile_commands.json to
resolve types; generate one with 'sda build compile-commands' and re-run`, and
appears in *NOT CHECKED* rather than contributing silence. `sda build
compile-commands --synthesize` then answers that it makes **87 MISRA C guidelines
requiring type information reachable**, and the next run completes with
clang-tidy absent from *NOT CHECKED* — which is how the report says a provider
actually ran.

Two Linux-side behaviours came along for free, neither of which had been seen off
Windows: the deviation register suppressed three findings and **rejected a
deviation for `MISRA-C-2023-9.1` because it is Mandatory**, both reported.

### The gate is one command now, because a checklist is not a check

Everything this repository asks of a commit is four steps: the workspace tests,
the GUI crate's tests, clippy over all targets, and the three self-scans. Run as
four commands they have to be sequenced correctly every time, and on 2026-09-16
that went wrong: `cargo test --workspace` and `git commit` on one shell line with
nothing between them, so **exit 101 and two failures went past while the commit
succeeded**. The same batching mistake had been made twice earlier in the same
session and written up both times, which is the clearest evidence available that
writing it up does not fix it.

`tools/verify.sh` runs the four and fails as a unit:

```bash
tools/verify.sh && git commit -F -
```

**A checklist you follow by hand is a check that did not happen, presented as one
that did** — the failure this whole codebase is organised against, applied to the
process rather than to the analyzer.

It earned its place on the first run. `cargo test --workspace` returned **exit
127 with no diagnostic**, and the script refused; the manual sequence would have
committed straight through it.

What the failure looks like is worth knowing, because it looks like nothing. The
workspace run dies *after* a test binary has printed every one of its tests as
`ok` and *before* it prints its `test result:` line — no diagnostic, no failing
test, exit 127 or 1. It stops at `sda-adapters`, the binary that starts and kills
real child processes, and that binary passes 66 of 66 standalone, six runs out of
six, piped or redirected. **The tests are not failing; the harness is dying.**

**Two causes were proposed for it and neither survived.** This paragraph has been
rewritten twice, which is the useful part of it.

The first draft said the failure recurred with the machine idle, on the strength
of a `tasklist` count taken *after* the run — a crude proxy that counts cargo and
not rustc and says nothing about disk. The second said the cause was load, on the
strength of six consecutive passes once the machine went quiet. Then
`cargo test -p sda-adapters --lib`, which had just failed this way, passed **ten
times out of ten at thirteen concurrent cargo processes and 100% CPU**. Load does
not explain it either.

What is actually known, and it is short:

* It has only ever been seen through cargo. The binary passes 66 of 66 run
  directly — three times piped, three redirected — so it is not the tests and not
  the output being a pipe.
* It stops after a binary prints every test as `ok` and before its
  `test result:` line, at `sda-adapters`, the one that starts and kills real
  child processes.
* There is no reliable reproduction. Ten consecutive attempts under heavy load
  did not produce it.

**No hypothesis is left standing, and the honest thing is to say so rather than
offer a third.** The gate does not need one: it reads the harness's words instead
of the exit code, so it tells this apart from a failing test without knowing why
it happens.

**A rate, and one fact about the retry.** Twenty-four gate runs in one session,
on one machine, over one afternoon:

| | runs |
|---|---:|
| clean | 41 |
| aborted twice, reported as the flake | 4 |
| aborted once, then retried successfully | 1 |

Five aborts in forty-six runs, which is the rate this document has.

**The last row used to read zero, and the way it was written down is the point.**
At twenty-four runs it was three and nought: the retry had never once worked,
three times for three, and that looked like a fact about the failure rather than
a small sample. It went in as a measurement with no mechanism attached — and that
is the only reason it cost nothing when the forty-sixth run retried and passed.

The honest reading is now weaker than the one available two hundred lines ago:
the retry usually does not help, and sometimes does. **A claim that survived four
observations did not survive five.**

That is stated as measurement and nothing more. It names no mechanism — elapsed
time and a fresh process cannot be told apart from these numbers — and the
temptation to read one into it is exactly what produced the two hypotheses this
section already retracted.

**The gate was deliberately left alone, and that decision aged better than the
observation behind it.** A retry that had failed three times for three cost a full
workspace run whenever the flake hit, and removing it looked like the obvious
saving; three samples was not enough to change the tool that decides whether a
commit is allowed. Twenty-two runs later the retry recovered one — which it could
not have done had the saving been taken.

The next session has the numbers and can add to them; `grep -l 'retrying once'`
and `grep -l 'harness aborted twice'` over a session's gate logs is how they were
counted, and the difference between those two greps is the row that changed.

**The layer under it had the same problem, and it happened live.** `rustc` itself
crashed while building `gui/src-tauri` — `STATUS_STACK_BUFFER_OVERRUN`
(`0xc0000409`), a backtrace through `rustc_hir_typeck`, compiling a crate nothing
in the commit had touched. The gate reported `FAILED: gui/src-tauri tests`, which
reads as *your GUI tests are broken*, and would have sent somebody to debug code
that is fine. The rerun passed.

A crashing compiler prints `error: could not compile`, exactly as a type error
does, so **both** compiling steps called it a defect in this code — step 1's
careful classifier included, since `could not compile` is one of the three
patterns it treats as a real failure.

`compiler_crashed` now asks first, in both steps, and fails with what actually
happened: a toolchain fault, rerun it, and report it upstream with the backtrace
if it repeats.

The justification is structural rather than statistical, which matters two
paragraphs after a claim in this section was falsified by a fifth observation.
One crash is one observation and proves nothing about frequency. That the script
could not tell a crashing compiler from failing code is in the script, and was
read there. Calibrated against the captured log of the real crash, and against a
clean run for the false positive.

Calling it "workspace tests failed" would be this codebase's own error inverted:
**an inability to check, presented as a check that came back bad.** The script
reads the output instead. A real failure names itself — `test result: FAILED`,
`error[E0308]`, `could not compile` — and anything else with every test reporting
`ok` is retried once and then reported as the flake it is. Both directions are
exercised: a deliberately wrong count in this table fails the gate and names the
test.

**The first classifier had the defect it was written to prevent.** It also
matched `^error:`, and cargo prints `error: test failed, to rerun pass …`
whenever a test binary exits non-zero — which is precisely what the flake does.
So the gate called the flake a real failure, on a run where all 66 adapter tests
printed `ok` and no `test result:` line appeared at all. The discriminator has to
be the *test harness's* words, not cargo's: `test result: FAILED` for a failing
test and `error[E…]` for the compiler, neither of which the flake produces.

#### The gate also checks the repository's shape

Everything else it runs asks whether the code is right. Step 0 asks whether the
repository still looks like itself: a top-level entry that is not on a short
known list fails the gate.

That is there because `wsl … sh -lc "… $HOME …"` built a cargo target directory
*inside this repository*, and five lock files reached a commit with nothing to
stop them — the tests all passed, clippy was clean, the scans were clean, and the
only reason anyone noticed was that git's line-ending warning happened to print
the path. **The other four steps catch mistakes; this one catches accidents**,
and it was an accident that put build artifacts in a commit. Watched refusing
`C:Usersadamm`.

**And it looked only at the top level, so it missed one that was already there.**
`tools/__pycache__/cppcheck-misra-oracle.cpython-310.pyc` — compiled bytecode
from one of the oracle scripts — was committed and had been in the tree the whole
time, one directory below where the check could see. Found by accident again,
while adding a sweep script next to it and running `ls`.

Twice by accident is a pattern worth naming: **the artifacts that get committed
are the ones nobody thinks to look at**, which is exactly why a check for them
must not depend on anybody looking.

Step 0 now also asks git what it is tracking, and refuses a committed
`__pycache__`, `node_modules`, `.pyc`, `.o`, `.rlib` and the rest of that family
anywhere in the tree. Tracked files only — an artifact merely sitting in a
working copy is `.gitignore`'s business, while one that is committed ships to
everyone who clones.

Calibrated before being believed, which this session has had to learn six times:
run against `HEAD` it names the `.pyc`, and against the fixed index it finds
nothing. A check that reports zero on a repository known to contain one is not a
clean result.

**The README quotes tool output, and that is checked too.** `README.md` shows
`sda rules audit`'s summary as the evidence for its central claim — a clean
result means conformance for a *stated* subset. That sentence is generated from
the catalogue, so every reclassification changes it, and it changed three times
in one session: 74 provable guidelines, then 72, then 70. Each time the README
was corrected by hand, because nothing would have noticed otherwise. A number in
the first document a reader trusts is the worst place to keep an unchecked copy.
`readme_quotes_real_output.rs` compares the quoted block against what
`Catalog::audit().caveat()` produces; watched failing with one guideline
reclassified.

It also gives `sda-cli` its first tests. That crate had none, which is why the
compilation-database coverage check earlier in the session was put in `sda-build`
rather than in `main.rs` — a check that lives only in the CLI is one nothing can
test and the other surfaces do not get.

### The workbench harness had nothing to test

HANDOFF's own table said both GUI harnesses had passed **this session**, against
"a binary built this session". Neither claim was true, and checking cost less
than believing them would have.

**The binary did not exist.** It had been built into the shared
`CARGO_TARGET_DIR`, which other projects on this machine wipe — the hazard this
document already warns about, one layer up. A row asserting PASS against an
artifact that is gone is the same defect as a clean check that could not check.

**And the guard that exists to prevent exactly this was watching the wrong
half.** `refuseStaleBinary` was written because the harness once drove a
five-week-old build and reported PASS. It aged the binary against `main.js`, the
stylesheet and the HTML — its own doc comment said "the frontend is embedded in
the binary", as though that were all of it. The workbench also links
`sda-core`, `sda-engine`, `sda-editor`, `sda-rules`, `sda-ai` and `sda-adapters`.
This session changed `sda-editor`'s position validation; the guard would have
passed a binary built before it without a word.

It now ages the binary against the Rust it actually links: `.rs` under
`crates/*/src` and `gui/src-tauri/src`, plus the manifests.

**The first version of that widening aged it against `crates/` entire**, which
includes `tests/`. Those compile into test binaries and never into the
workbench, so every test edit demanded a twelve-minute Tauri rebuild. That is the
same defect wearing the other hat: a guard that cries wolf is ignored, then
deleted, and the widening would have destroyed the check it was meant to
strengthen.

**Both edges are now exercised by `gui/tools/stale-guard-check.mjs`**, against a
synthetic binary whose timestamp is set deliberately — so it needs no build and
touches nothing. It was written after a widening elsewhere in this session turned
out to be inert while passing both checks meant to prove it worked: a guard that
never fires looks exactly like a tree that is never stale, and only a test that
asserts the *refusal* can tell them apart.

**Rebuilt and re-run, both harnesses pass** — and that is worth more than
restoring a green row. `drive-cdp.mjs` asserts *the editor model agrees with the
CLI*, so it is the first evidence that this session's changes to
`Position::new`, `Position::clamped` and `Range::clamped` behave correctly in the
real workbench rather than only against a captured Monaco fixture. The workbench
also compiled against them, which the Rust suite alone does not check: `gui/`
is a separate crate outside the workspace.

### The C++ rules meet clang-tidy

Twenty-one MISRA C++:2023 guidelines are classified `native` — a clean result on
one offered as evidence of conformance — and not one had ever been compared with
anything. The C sweep cost seven defects and the Rust sweep cost one. There was
no reason to expect this catalogue to be in better shape, only a reason nobody
had looked.

clang-tidy's `cppcoreguidelines` module decides five of them, and the mapping is
close to exact because both are restating the same C++ Core Guidelines: 8.2.1 the
C-style cast, 8.2.2 `reinterpret_cast`, 8.2.3 `const_cast`, 9.6.1 `goto`, 21.6.1
dynamic allocation.

**8.2.1 needed the right check to compare against.**
`cppcoreguidelines-pro-type-cstyle-cast` fires only on casts that remove
constness; `google-readability-casting` is the one that flags every C-style cast.
Picking the wrong one would have produced a tool that "agreed" by not looking —
the same trap as running clippy without `--all-targets`.

**And it found a defect on the first run.** `8.2.1` did not fire on
`return (int)v;`. `is_c_style_cast` refused any parenthesis preceded by `return`,
in a guard that runs *before* the contents are examined for a type — so the place
a cast most often sits in C++ was the one place the rule could not look. The
guard was also redundant: `return (x);` has no type in its parentheses and is
rejected by the type check on its own merits. `sizeof`, `alignof`, `decltype` and
`catch` stay on that list, because their parentheses legitimately contain a type
and the check below genuinely cannot tell.

**79 real casts on PX4**, every one of the form `return (Type *)NULL;`, every one
read by hand. No false positives.

**5.7.1 and 5.7.2 came next, and they needed the oracle to learn something.**
`-Wcomment` says *exactly* the same thing about a spliced `//` comment in
`lexical.c` and in `comments.cpp`. What differs is which guideline that sentence
violates: 3.1 and 3.2 in MISRA C, 5.7.1 and 5.7.2 in MISRA C++. The compiler has
no opinion about which catalogue is being applied, so
`tools/clang-warning-oracle.py` now decides from the file's language — and
compiles a `.cpp` as C++, because a C++ file fed to a C front end yields a parse
error rather than a diagnostic. Both fire, both agree, and a test asserts the two
numberings are disjoint so that a C number appearing against a C++ file fails
rather than passing quietly.

**Three more followed, and one of them repeated a shape seen in the Rust
sweep.** `19.6.1` (include guards) against `llvm-header-guard` and `19.0.1`
(function-like macros) against `cppcoreguidelines-macro-usage` agree exactly.
`12.2.1` does not, and the reason is familiar: `cppcoreguidelines-pro-type-union-access`
objects to *reading* a union member, while the guideline objects to the union
existing. Both fire on the same file, in different places, because they prohibit
different things.

**That is the second time in one session** — Rust's `UNSAFE.4` against
`static_mut_refs` was the first — and it is worth naming as a pattern rather than
an accident: **a lint fires at the use, a MISRA rule fires at the declaration.**
A line-for-line comparison of the two is the wrong test, and a comparison that
simply drops the rule lets it rot. Both are asserted for *presence and order*
instead: the declaration comes first, and both tools have something to say.

`llvm-header-guard` needed `-x c++-header` to have an opinion at all. A header
compiled as a translation unit is still a header, and without the flag the check
is silent — another tool that agrees by not looking.

**Four more, and the two differences they produced were already in this
document.** `9.4.1` (unbraced body) against `readability-braces-around-statements`
and `9.4.3` (missing `default`) against `-Wswitch-default` agree exactly. The
other two do not, and neither is new:

* **9.4.2** — this engine reports the statement that should have carried a
  `break`; clang reports the label fallen *into*. That is precisely the
  disagreement recorded for **MISRA C 16.3** against cppcheck, where the
  conclusion was that neither the guideline nor the standard fixes where a
  finding belongs.
* **21.10.1** — this engine flags the `#include <csetjmp>` as well as the
  `longjmp` call; clang-tidy flags only the call. The same broader reading
  recorded for **MISRA C 21.6** and `#include <stdio.h>`.

**That the C++ catalogue reproduces the C catalogue's differences is the outcome
to hope for.** It says the two were implemented with the same presentational
choices rather than drifting apart, and it means the open question about 21.6 —
whether flagging the header is a claim the guideline supports — is one question
about both catalogues rather than two.

Three of the twelve comparisons are now compiler warnings surfaced through
clang-tidy's `clang-diagnostic-*` names, so the second implementation for them is
the compiler rather than a linter's opinion.

**Fourteen of twenty-one compared**, and the fourteenth pair took no work at all:
`5.7.1` and `5.7.2` are the C++ numbers for the spliced and nested comments, and
they were already being compared by `misra_agrees_with_clang_warnings.rs` against
`-Wcomment`. This section said twelve for a session because whoever counted read
the clang-tidy fixture and not the clang one. The seven left are `5.13.1 5.13.2
11.3.1 19.3.1 21.10.2 24.5.1 30.0.1`: literal, declaration and library rules that
no general C++ tool implements.

The old sentence ended "and two others", which is the shape of the error rather
than an aside. Seven rules were named, nine were claimed, and the gap was filled
with a phrase instead of a number — the two do not exist. A count nobody can
reconstruct from the page is a count nobody checked.

### The Rust rules meet clippy

Everything this session did to the MISRA C rules — hold them to cppcheck, then to
clang — left the `RUST-2024` rules where they were: **seventeen classified
`native`**, meaning a clean result is offered as evidence of conformance, and not
one ever compared with anything. The C sweep cost seven defects. There was no
reason to expect this half to be in better shape, only a reason nobody had
looked.

Clippy ships with rustup, so there is nothing to install, and two guidelines map
onto its restriction lints exactly: **PANIC.1** onto `unwrap_used` and
`expect_used`, **PANIC.2** onto `panic`, `unreachable`, `todo` and
`unimplemented`. `tools/rust-panic-corpus/` is a crate that exists to be
complained about — `[workspace]` empty and present, so the workspace above never
builds it.

**Captured with `--all-targets`, and that is the whole design.** Without it
clippy does not compile `#[cfg(test)]` code at all, so it would agree with this
engine about test modules *by not looking* rather than by deciding — agreement
that means nothing. With it the two genuinely differ: clippy's restriction lints
fire everywhere, and this engine exempts test code because a panic in a test is
the test working. Both readings are defensible, and
`what_clippy_reports_and_this_engine_does_not_is_test_code` pins the difference
to exactly that.

**One defect, and it surfaced while verifying the instrument rather than from
the comparison itself.** Breaking the test exemption made this engine report
`PANIC.2` at a line where clippy reported `PANIC.1` — because
`RUST-2024-PANIC.2` also flags `assert!`, `assert_eq!` and `assert_ne!`, which
its own title did not mention:

> panic! unreachable! todo! and unimplemented! shall not appear in shipped code
> paths

Four macros named, seven flagged. Whoever was told they had violated *that* rule
for writing `assert_eq!` was told something untrue about which guideline their
code broke. The behaviour is right for the rule's domain — an assert that fails
in flight is a crash — so the **title** was corrected rather than the check, and
the corpus now carries a shipped `assert!` so the difference is exercised instead
of latent. Clippy has no restriction lint for the assert family, which is why the
comparison allows it through by name.

**And then six more, using lints the compiler itself ships.** For an *edition*
rule rustc is not merely a second opinion, it is the authority on what the
edition did. `tools/rust-edition-corpus/` is kept at **edition 2021** on purpose:
most of these are hard errors at 2024, a crate containing them does not compile,
and a refusal to compile is not a diagnostic. At 2021 the compiler will say
where.

| guideline | lint |
|---|---|
| `UNSAFE.1` | `clippy::undocumented_unsafe_blocks` |
| `UNSAFE.2` | `clippy::missing_safety_doc` |
| `UNSAFE.4` | `static_mut_refs` |
| `ED2024.1` | `keyword_idents_2024` |
| `ED2024.3` | `missing_unsafe_on_extern` |
| `ED2024.4` | `unsafe_attr_outside_unsafe` |

`UNSAFE.2` was not on the list of five that looked reachable — it turned up
because the corpus provoked `clippy::missing_safety_doc` without being asked to,
which is an argument for writing a corpus and running the tools over it rather
than reasoning about which lints exist.

**Five of the six agree line for line. The sixth is a difference of rule.**
`UNSAFE.4` reads "static mut shall not be used"; `static_mut_refs` fires on a
*reference* to one. So this engine flags the declaration and rustc flags the
borrow — and on a `static mut` nobody ever references, this engine reports it and
rustc says nothing at all, which was checked rather than assumed. Ours is the
broader rule and matches its own title. What follows is worth stating plainly:
**rustc's silence about `static mut` is not evidence of conformance with
UNSAFE.4**, and the test asserts the shape of the difference instead of comparing
two line numbers and failing.

**Eight of the seventeen `native` Rust rules are now compared**, against clippy
and rustc. The nine left are `CONC.1 DEP.2 DEP.3 ED2024.5 EMB.1 FFI.1 MODEL.1
MODEL.3 UNSAFE.3` — dependency, embedded-profile, concurrency and model-artifact
rules, which no general-purpose Rust tool implements.

This read "nine ... the eight left" for a session, and eight and nine add to
seventeen, so the arithmetic vouched for itself. `UNSAFE.3` was in neither the
compared set nor the list: a rule can go missing from a page that adds up. The same question is still worth putting to
the twenty-one `native` MISRA C++ rules, which have never met anything.

### What counts as test code

`PanicSite::in_test` decides whether a panic is a defect or the intended way for
a test to fail, so the permissive direction does not merely lose information — it
**suppresses real findings and the report comes back clean.** HANDOFF named
`PanicSite` as the part of `rstruct` no oracle had ever looked at. Looking found
three defects in one heuristic.

The rule was: a `mod` whose name *contains* the substring `test`. Nothing else.

* **`mod latest` was test code.** So were `attestation`, `testbed`, `protest`.
  Every panic inside them was excused.
* **`#[test] fn` was not test code** — the canonical way to write a unit test,
  and the old function's own doc comment claimed the case was handled.
* **`#[cfg(test)] mod checks` was not test code** either, which is the idiom
  whenever the module is not literally named `tests`.

**And the sites themselves have now met syn too**, which was the original point
of looking: `panics_agree_with_syn.rs` compares `(operation, line)` over the
whole corpus. They agree everywhere, including a panic inside a closure and the
several-on-one-line case, and both correctly find nothing in
`"v.unwrap() and panic!()"` or in a comment saying the same. Watched failing with
`todo` removed from `PANIC_MACROS`.

**One difference, asserted rather than excused.** syn parses a macro
invocation's arguments as an opaque token stream and does not walk them, so
`assert!(v.unwrap() > 0)` is one site to syn and two here — and *this* crate is
the one that is right, because the `unwrap` is there and it can panic. A rule
built on syn would miss it. Pinned in its own test rather than filtered out of
the comparison.

It now reads `#[test]`, `#[cfg(test)]` and `#[cfg(all(test, …))]` off the item,
and the item's extent decides what is inside it. Both of those became possible
only because the attribute work earlier in the session populated
`RustItem::attributes` — which had never been written to — and this added
`RustItem::end_line`, closing the other half of the "item spans are not modelled"
gap.

`#[cfg(feature = "testing")]` is **not** test code: string literals are stripped
before the word is looked for. A module named exactly `tests` is still accepted
without an attribute, because that convention is near-universal and demanding the
attribute would trade the old false positive for a new false negative.

**A test in this repository was resting on the defect.**
`the_same_code_under_src_is_still_reported` asserted that a pickle path and a
panic in `src/lib.rs` are reported — using a `#[test] fn` as its fixture. It
passed only because `#[test]` was not recognised. Its intent was right and its
fixture was test code; the fixture is now ordinary production code and the test
asserts what it always meant to.

### The same analyzer, on two operating systems

`sda` had only ever been built for Windows. It builds for Linux — in WSL Debian,
90 seconds, a 4.8 MB binary — and that made a comparison available that nobody
had run: **the same analyzer over the same source tree, on two operating
systems.**

PX4-Autopilot, all submodules initialised, `--min-severity high`:

| | Windows | Linux (WSL) |
|---|---|---|
| Findings | 15,528 | 15,528 |
| Rules whose counts differ | — | **0** |
| Identical `(file, line, rule)` | 14,862 | 14,862 |
| Wall clock | 33 s | ~18 min (the tree is on `/mnt/c`, over 9p) |

Every rule fires the same number of times on both. That is a stronger statement
about this engine than any single-platform suite can make, and it had never been
checked.

**The 666 findings that did not match reduce to 69 that actually differ**, and
they were a defect: `sda.ai.artifact` reported **absolute** paths where every
other provider reports relative to the target root —
`C:/Users/.../boards/...` against `/mnt/c/Users/.../boards/...`, the same
findings wearing the scanning machine's layout. An absolute path is a baseline
entry that will not match on another machine, a triage record that will not
match either, and somebody's directory structure in a report they may share.
`scan_file_as` now lets the provider report the path the scan gives it, while
`scan_file` still names what it is handed, because `sda ai scan <file>` has no
root to be relative to. Zero absolute paths afterwards, same 15,528 findings.

The remaining 597 are the same finding at the same place with separators the
comparison normalises — native separators on each platform, which is the
existing convention and is handled at the SARIF and MCP boundaries.

### MISRA, against a second implementation

The rules themselves were the last thing in this repository never compared with
anything. Everything else verified sits *beneath* them — the lexer finds the
right tokens, the structure analyser finds the right returns, the adapters parse
their tools — while whether `MISRA-C-2023-15.5` implements what 15.5 *says* rests
on a paraphrase in `crates/sda-rules/data/`, because the normative text is
licensed and not in this repository.

The document is still not available. What is available is a second
implementation: cppcheck's MISRA addon reports rule *numbers* without the
licensed texts, so the guidelines it fires can be compared with ours.
`tools/cppcheck-misra-oracle.py` captures it; the answers from **Cppcheck
2.21.0** over four C files — `examples/firmware/src/main.c`,
`examples/coverage/main.c`, `tools/valgrind-wsl/three-sins/main.c` and
`tools/valgrind-wsl/vgwrap.c` — are pinned as
`crates/sda-engine/tests/fixtures/cppcheck-misra.json`, behind
`crates/sda-engine/tests/misra_agrees_with_cppcheck.rs`.

**This is a comparison, not an oracle, and the file says so.** The addon targets
MISRA C:2012 and this toolkit targets 2023; the numbering carries over for most
rules and not for all. A disagreement means one of the two is wrong *or* the
editions differ, and nothing here says which. What the test does is fail when the
disagreements change, so somebody looks.

**On the first two files it found nothing, which is worth stating plainly because
the base rate in this repository runs the other way.** Every guideline cppcheck
reported and this toolkit did not — 8.4, 17.7, 11.5 — is classified `semantics`
in `crates/sda-rules/data/misra-c-2023.toml`, meaning the catalogue already
declares it needs type information this toolkit does not have. That
classification is what `sda rules audit`'s central claim rests on: that a clean
result is evidence of conformance *for a stated subset*. It had never been
checked against a tool that does have the type information. It held.

**Then the corpus was widened by two files of twenty-odd lines each, and it
stopped holding.** `tools/valgrind-wsl/` was added to the capture and produced
two disagreements immediately:

* **MISRA 12.1 was marked `native` and covered two operator pairs.** The
  guideline, which asks for operator precedence to be made explicit, is open-ended: every pair of operators of differing precedence is in
  scope. The engine checked `&&` mixed with `||`, and a shift mixed with `+`/`-`.
  cppcheck fired 12.1 four times on `vgwrap.c`, on
  `strncat(cmd, " \"", sizeof cmd - strlen(cmd) - 1)`, where `sizeof` binds
  tighter than every binary operator and its unparenthesized operand therefore
  ends at the `-`. Two changes followed. The check now covers that case (with a
  unit test in `checks.rs` asserting the parenthesized form clears it, because a
  check that fires on the fix is noise). And **12.1 is now `partial`, not
  `native`** — `partial` means "checked natively with known gaps; a clean result
  does not establish conformance", which is the truth about an open-ended
  advisory guideline whose implementation covers three traps. Marking it `native`
  claimed a clean 12.1 meant conformance, and that was the fifth kind of thing
  this repository has a table of.

  **The sweep happened immediately, and found one more.** The catalogue records
  each guideline's MISRA *decidability* beside its coverage class, and the two
  fields contradict each other in one place: `Decidability::Undecidable` is
  documented as "no analyzer can settle this in general; a clean result is not a
  proof", while `Coverage::Native` is the class where a clean result *is*
  evidence of conformance. **D4.4**, about code left commented out, decided by a heuristic that tells code from prose about code — was marked
  both. It is now `partial`, and
  `nothing_undecidable_claims_a_clean_result_proves_conformance` in
  `crates/sda-rules/src/lib.rs` fails the build if any guideline in any catalogue
  ever claims both again. That is the class of mistake made impossible rather
  than fixed once.

  `sda rules audit` now reports 70 guidelines where a clean result is evidence of
  conformance, not 74 — an honest reduction of two, and the README's quoted
  output was updated with it.

  **A third sweep, from the same catalogue, found two more.** Beside decidability
  each entry records *scope*: `single` for a guideline judged per translation
  unit, `system` for one judged across the whole program. The C analyzer's entry
  point is `check_source(path, source)` — one file, no memory of the others — so
  a `system`-scope guideline marked `native` is a claim worth testing. Three were:
  **2.5**, **5.1** and **D4.5**.

  `crates/sda-engine/tests/system_scope_needs_the_whole_program.rs` builds
  two-file projects whose violation spans the two files and asserts what the
  engine finds. **5.1** — external identifiers distinct within the linker's
  significant length — misses a collision between two files, which is the only
  case that matters, because a collision inside one file is a compile error long
  before MISRA is consulted; its own doc comment says so ("a linker-scope check
  across the whole program is a system-scope provider's job") while the catalogue
  said `native`. **D4.5** misses `lookup1` in one file against `l00kup1` in
  another. Both are now `partial`. **2.5** keeps `native` with a stated reason: a
  macro unused across the whole program is also unused in the file that defines
  it, so the per-file check cannot miss one — its error runs the other way, a
  false positive on a header macro used only elsewhere.

  The third test in that file generalises it: a `system`-scope guideline may keep
  `native` only if it is listed there with a reason why one file at a time
  suffices. Deliberately weak — it does not construct a cross-file violation for
  each — but it stops the reasoning from being forgotten.

  **And then the fix, which is the point.** Downgrading a classification tells the
  truth; it does not check anything. `Analyzer::analyze` already receives the
  whole target, so a second pass now accumulates external function definitions
  across files and compares them — the first whole-program check this toolkit has.
  What it needed first was `CFunction::internal_linkage`, recorded by
  `sda-syntax` for the first time: two `static` functions with the same name in
  different files are correct C, and a cross-file check that cannot tell internal
  linkage from external reports every one of them. The scan walks back from the
  function name to the end of the previous declaration, so an attribute ahead of
  the storage class (`__attribute__((unused)) static int f(void)`) still counts;
  that and the `;`/`}` stopping conditions are unit-tested in `cstruct.rs`.

  **It only compares translation units, and the reason is not a technicality.** A
  header is not a translation unit — it is text included into one — and this
  toolkit analyses headers standalone on purpose, which is what lets it run on
  code that does not build. That attributes a header's definitions to the header
  rather than to each unit including it, and comparing across those attributions
  manufactures pairs no linker ever sees. Found on PX4: `virtual void run()` in
  one C++ header against `Run` in another, neither of them a C function with
  external linkage.

  **Measured on PX4-Autopilot, 697 C files: three findings, no false positives.**
  `modalai_print_usage_con_gpio_test_v2` against `..._v1` — thirty-six characters
  that agree for the first thirty-one, which is all a conforming linker must
  consider, and a real 5.1 violation nothing had reported before. And
  `Timer_Start`/`Timer_Stop` in a Broadcom driver against `timer_start`/
  `timer_stop` in the NuttX bootloader, differing only in case across the whole
  program. All three are non-`static` definitions in `.c` files, checked by hand.

  **Then file-scope objects, because 5.1 is about identifiers and an object with
  external linkage is one.** `CStructure::objects` and `cstruct::parse_objects`
  are new: the pass walks declarations at brace depth zero and reads a declarator
  *only* when its shape is unambiguous. `int counter;`, `char buf[32];`,
  `struct S s;`, `int a = 1, b = 2;` are read. `extern int x;` (a declaration, not
  a definition), `typedef`, `struct S;`, `int f(void);`, `int (*handler)(void);`,
  `struct S { int a; } g;` and `int table[] = { 1, 2 };` are **refused** — not
  misread, refused. Anything containing a parenthesis or a brace is skipped by one
  rule rather than by telling the cases apart.

  That asymmetry is the design. The names go into a whole-program comparison, so
  a name read wrongly becomes a conformance finding against code that has done
  nothing wrong; a name not read leaves the status quo, which was that no object
  was recorded at all. `file_scope_objects_are_read_or_refused_but_never_guessed`
  in `cstruct.rs` pins every case above, refusals included.

  Re-measured on PX4's 697 C files afterwards: **still exactly three findings,
  still no false positives.**

  **Then the declarator parser, which was the named next step.** The shape-matching
  version refused anything containing a parenthesis — one rule that removed every
  function declaration, and every *function-pointer object* with it.
  `cstruct::parse_objects` now reads C declarators by the language's own rule: the
  declared name is the first identifier in the **declarator**, once the
  declaration specifiers are out of the way, and the declaration is a function's
  rather than an object's when a `(` follows that name directly.

  | written | specifiers | declarator | name | object? |
  |---|---|---|---|---|
  | `struct S s;` | `struct S` | `s` | `s` | yes |
  | `int (*handler)(void);` | `int` | `(*handler)(void)` | `handler` | yes |
  | `int (*fp[3])(void);` | `int` | `(*fp[3])(void)` | `fp` | yes |
  | `struct S { int a; } g;` | `struct S {…}` | `g` | `g` | yes |
  | `int f(void);` | `int` | `f(void)` | `f` | **no** |
  | `void (*signal(int))(int);` | `void` | `(*signal(int))(int)` | `signal` | **no** |

  Reading braces properly was the part that needed thought: a `{` preceded by `)`
  closes a *function body*, so the next declaration starts after it; any other
  brace — a struct, union or enum body, or a braced initializer — belongs to the
  declaration being read, so the scan jumps it and carries on. That is what lets
  `struct S { int a; } g;` be read at all.

  **Two refusals were then bought with false positives on PX4, both the same
  shape: a macro invocation is not a declaration, and nothing here expands
  macros.**

  1. `PARAM_DEFINE_INT32(TEST_1, 2);` read as a declaration declares an object
     called `TEST_1`, which collided with `TEST_I` in another file under D4.5 —
     a finding against code that has done nothing wrong. A parenthesised
     declarator must *contain a declarator*: `(*handler)` qualifies, `(TEST_1, 2)`
     is a parameter list.
  2. PX4 wraps its headers in `__BEGIN_DECLS`, which has no semicolon, so the
     following declaration runs on from it: `__BEGIN_DECLS size_t
     px4_get_secure_random(...)` offered `size_t` as a declared object, and
     `__BEGIN_DECLS __EXPORT int px4_clock_gettime(...)` offered `__EXPORT`.
     Twenty-six of those. Two names in a row cannot both belong to one object
     declarator, so seeing one means the specifier boundary landed in the wrong
     place — refuse rather than guess.

  **Measured on PX4-Autopilot's 697 C files afterwards: one added finding, zero
  removed, no false positives.** The addition is genuine —
  `const float32_t __logf_lut_f32[8] = {…}` in a vendored CMSIS table, a
  file-scope object with a name reserved to the implementation, which MISRA 21.2
  is exactly about.

  **Both stay `partial` anyway, and that is not a hedge.** The parser refuses what
  it cannot read, and one refusal still hides external identifiers:
  `int x __attribute__((unused));` trips the two-names-in-a-row rule, which is the
  same rule that keeps a macro invocation from being read as a declaration. The
  two cases are indistinguishable without a preprocessor. A clean 5.1 result is
  therefore still not evidence of conformance, and
  `the_remaining_gap_is_declarators_carrying_something_unreadable` asserts both
  halves: the gap is real, and the classification admits it. **Closing the last of
  it needs macro expansion, which is a different tool from the one this is.**

  **What none of these sweeps cover.** All three are objective: they catch a
  guideline whose own catalogue entry contradicts itself, or whose scope the
  engine's architecture cannot honour. None says anything about a *decidable*,
  *single*-scope guideline whose check merely samples it — which is what 12.1
  was, and that one was found only because a second implementation happened to
  look at a file.

  **How much evidence actually stands behind the 65, exactly.** This used to read
  "70 `native` rules have had neither a second implementation nor a reading",
  which is true and nearly useless: it does not say which, so nobody can act on it
  and nobody can tell when it improves. `tools/misra-evidence-tiers.py` splits
  them, and as of this session:

  | | | |
  |---|---:|---|
  | **compared** | 53 | a second implementation runs the same guideline and the two are held to each other |
  | **the reference tool under-reports** | 1 | `13.6` |
  | **no second implementation** | 11 | `6.3 7.6 8.16 8.17 17.10 21.24 21.25 D4.6 D4.9 D4.10 D4.12` |

  The two unreached are not laziness, and as of 2026-10-31 there are none: **4.2**
  and **20.14** moved to compared. cppcheck reports `syntaxError` on `??=define`
  and runs its addon over nothing, but it reads a trigraph in a string, and that
  case found this engine was blind to trigraphs in strings. cppcheck's 20.14 on
  `conditionals.c` comes with a `syntaxError` for the stray `#endif`, so it may
  rest on that and not on a real reading of the guideline.

  **The reference tool that says nothing.** `13.6` sat in the `compared` tier for
  a session without cppcheck ever having reported it. The tool that builds this
  table counted a guideline as compared when *either* side fired it, which let
  this engine's own finding stand in for the oracle's — a comparison needs two
  opinions, and that arrangement was content with one. It is fixed: only the
  second implementation's own fixture can put a guideline in the first tier.

  The distinction the new tier draws is worth keeping separate from *comparable,
  not reached*. For `4.2` and `20.14` the construct is not in the corpus, and
  writing it is the whole job. For `13.6` the construct **is** there —
  `sizeof(g(a))` at `tools/misra-corpus/expressions.c:49` — and the addon looks
  straight at it and says nothing, because `countSideEffectsRecursive` counts
  assignments and `++`/`--` and carries `# Todo: Check function calls`
  (addons/misra.py, 2.21.0). No amount of corpus fixes that. The two absences
  look identical in a diff of findings and have nothing else in common: one is
  our work to do, the other needs a different tool.

  **Two of the fifteen turned out not to need cppcheck at all.** `2.6` is a label
  nothing jumps to and `3.2` is line-splicing in a `//` comment — both are things
  a *compiler* diagnoses, and clang was already an oracle here for the lexer and
  for `CFunction::returns`. `misra_agrees_with_clang_warnings.rs` compares them
  against `-Wunused-label` and `-Wcomment`, line for line: these are lexical and
  structural guidelines, so unlike the cppcheck comparison there is no reason for
  the two to anchor them differently, and comparing lines is fair. They agreed on
  the first run; watched failing with the 2.6 check disabled.

  That is not a coincidence of wording. Both guidelines exist because the
  construct misleads a reader about what the program does, which is why a
  compiler warns, and both are decidable from the token stream. **The question to
  ask of the rest is the same one: does any tool already installed decide this?**

  **So it was asked, instead of answered from the armchair.** Every one of the
  remaining thirteen fixtures went through `clang -std=c23 -Weverything`, and the
  claim that none of them is a compiler diagnostic turned out to be wrong by one.
  **11.10** — `_Atomic` applied to the incomplete type `void` — is not a style
  guideline a compiler happens to mention: it is a constraint violation, and
  clang rejects the translation unit outright with
  `_Atomic cannot be applied to incomplete type 'void'`. The oracle captures
  errors as well as warnings now, and 11.10 is compared.

  Checking it here still earns its place. This toolkit's premise is that it runs
  on code that does not build, and code that does not build is exactly where a
  compiler has no opinion to offer.

  The other twelve produced nothing under `-Weverything`, which is now a measured
  statement rather than an assumption.

  `3.1` came along for it. `-Wcomment` reports `'/*' within block comment` as
  well, which is 3.1 and not 3.2 — keying the oracle on the *flag* rather than the
  *message* would have asserted a 3.2 wherever clang found the other one, a
  comparison failing for the wrong reason.

  The twelve are the real remainder. Each has a fixture in `checks.rs` proving
  the check exists and fires; nothing independent has ever disagreed with what it
  *decides*. Five are directives, which no free tool implements. Closing those
  needs the licensed text or a third tool.

  The tool is not a test, because the addon is not in this repository and its
  version decides the answer — `misra_3_2` is written and commented out of the
  dispatch table, which is how the overlap was once counted as 62 when it is 61.

* **21.8 is an edition difference, not a defect.** cppcheck's `misra_21_8` fires
  on `abort`, `exit` and **`getenv`** (`addons/misra.py`, 2.21.0). MISRA C:2012
  named specific functions; C:2023 restates 21.8 as "the Standard Library
  *termination* functions of `<stdlib.h>`", and `getenv` does not terminate
  anything. This engine implements the 2023 reading, and adding `getenv` to match
  cppcheck would make it wrong for the edition it targets. Recorded in
  `edition_difference()` with the reasoning, which is the only place the test
  allows a difference through without it being a declared gap.

**Then the corpus was built on purpose, and it cost five more.** Four files that
happened to be in the repository exercised about twenty guidelines; the two tools
implement **sixty-two of the same ones**. `tools/misra-corpus/` is eight files
written from the guideline *titles* in `crates/sda-rules/data/`, deliberately
without reading the checks in `crates/sda-engine/` — writing them from the
implementation would have produced a corpus that agrees with it by construction.
Twelve files now, reaching about fifty guidelines. `tools` is already declared out
of the delivered product, beside `valgrind-wsl/three-sins` and `codeql-taint-cpp`,
which exist for the same reason.

Five defects, and the first runs the *opposite* way to everything else in the
failure-mode table:

* **5.4 and 5.5 used the wrong significant length, and over-reported.** C23
  §5.2.4.1 gives two limits: **31** significant initial characters in an
  *external* identifier, **63** in an internal identifier or a **macro name**.
  This engine used 31 for all three rules. 5.1 is about external identifiers, so
  31 is right there; 5.4 and 5.5 are about macro names, so they were calling
  distinct macros indistinct. Fifteen findings on PX4, every one of them against
  conforming code. cppcheck uses 63 for anything past C89 and declined to report
  the corpus pair, which is what surfaced it. **Worth internalising: the
  instrument found a false positive, not a false negative.** Every other entry in
  that table is an inability to check dressed as a clean check; this was a check
  that fired on code with nothing wrong with it, and it is the same root cause —
  a number nobody had traced back to the standard.

* **8.2 never saw a declaration.** The check reads `CStructure::functions`, which
  holds *definitions*. A prototype in a header — where 8.2 matters most, and
  where `int f();` silently disables argument checking for every caller — was
  never looked at. There is now a file-scope declaration scan, and the
  unnamed-parameter half of the guideline as well as the empty-list half. Nine
  real findings on PX4, all in headers, all `int f();`.

* **11.9 checked the rare spelling and not the common one.** `(void *)0` was
  detected; `int *head = 0;` was not.

* **12.3 scanned `if`, `while` and `switch` conditions only.** The comma operator
  in a `for` header — `for (i = 0; i < n; i++, other++)` — read clean, and a
  `for` header is where the comma operator actually turns up.

* **13.4 looked only at the outermost level of a condition.** That is the right
  place to answer "was `==` meant"; it is not the guideline, which is that an
  assignment's *result* must not be used. `if ((b = g(a)) != 0)` read clean.
  191 real findings on PX4 once fixed, the majority `while ((c = read()) != EOF)`.

**Every extension was measured against PX4-Autopilot before it was kept, and four
of the five needed a guard the corpus never would have shown.** In order of how
badly each would have hurt:

1. **`*revision = 0;` is not a declaration.** The first 11.9 extension matched
   `* IDENT = 0 ;` and reported 28 dereference-assignments on PX4 — ordinary C,
   storing an integer through a pointer. The token *before* the `*` settles it: a
   declarator has a type ahead of it, a statement has a `;`, `}` or `)`.
   `DECLARATION_HEADS` is deliberately not "any keyword", because `else *p = 0;`
   and `return *p = 0;` are statements.
2. **A file-scope `IDENT(...);` is not always a prototype.** PX4 has hundreds of
   `PARAM_DEFINE_INT32(SLNK_RADIO_CHAN, 80);`, whose `80` then reads as an
   unnamed parameter. A declaration has declaration specifiers before the name;
   a bare macro invocation has nothing. That guard alone removed 674 findings.
3. **C++ in a header read as C.** `SPI::DRDY drdy_gpio = {}`,
   `decltype(&C::instantiate)` and `const char (&name)[N]` are named parameters
   in a language this pass is not reading. It now refuses to judge a parameter
   containing `::`, `&`, `=` or `<` rather than calling it unnamed.
4. **A function-pointer parameter is named, and splitting on commas tears it in
   half.** `void (*callback)(void)` was reported as unnamed, and
   `void param_foreach(void (*func)(void *arg, param_t param), ...)` produced the
   nonsense parameter `param_t param)`. Any parameter carrying a parenthesis is
   now refused.

The pattern is the one this repository keeps meeting from the other side: a check
that has only ever seen its own fixture is not a check that works. Every one of
these four was correct against `tools/misra-corpus/` and wrong against a real
codebase, and the corpus could not have told the difference.

**Then the last twelve comparable guidelines the corpus was not reaching.** A
second pass added `identifiers.c`, `directives.c` and `include_form.c`, fixed the
constructs in `lexical.c` that were not violations at all (`"\x123abc"` is a
*terminated* hex escape — `"\x12g"` is the one both tools flag), and gave `5.4`
and `5.5` names of the right length now that the length is right. Fifteen files,
reaching about fifty guidelines. Two more things were fixed and four differences
run down:

* **5.1 and 21.2 now see file-scope objects, not only functions.** Both read
  `CStructure::functions`; `CStructure::objects` had just been added for the
  whole-program check and neither rule had been pointed at it. 21.2's own doc
  comment said "checked partially, over the function definitions this unit
  provides", and the catalogue already said `partial`, so this is a widening
  rather than a correction — but `int _Claimed_object = 0;` read clean, and it is
  exactly what the guideline is about.

* **`trigraphs.c` had to be removed from the corpus.** cppcheck 2.21.0 reports
  `syntaxError` on `??=define`, so the addon runs over nothing. The oracle script
  refuses a capture for a file with no MISRA findings, which is what made this
  visible rather than a file silently contributing agreement. 4.2 therefore has
  no second implementation to be checked against.

**Four differences where this engine reports and cppcheck does not, each chased
to its source in the addon rather than assumed:**

* **13.6** — `sizeof(g(a))`. The guideline is about an operand containing an
  expression with *potential* side effects, and a call to a function defined
  elsewhere has them by definition. cppcheck's `countSideEffectsRecursive` counts
  assignments and `++`/`--` and carries the comment `# Todo: Check function
  calls`.
* **3.2** — cppcheck has `misra_3_2` written and **commented out of its own
  dispatch table**: `#self.executeCheck(302, self.misra_3_2, ...)`,
  `addons/misra.py:4723`. Line-splicing a `//` comment swallows the line after
  it, so this engine keeps checking it. *This also corrected the count of
  guidelines both tools implement, from 62 to 61 — the first count was taken by
  grepping for `self.misra_*` and caught the commented-out line.*
* **5.1** — the mirror image of the 5.4/5.5 defect, in the other tool.
  `get_num_significant_naming_chars` returns 63 past C89 and cppcheck uses that
  for 5.1 too, but 63 is the *internal* identifier limit; an external identifier
  gets 31. Two thirty-two-character externals collide for a linker and cppcheck
  does not look. Having just made that mistake here, it was easy to recognise.
* **21.2** — cppcheck covers macro names matching `_+BUILTIN_.*` and functions
  whose names are standard-library identifiers. The general reserved-identifier
  shape — a leading underscore before a capital, a double underscore anywhere —
  is not implemented there.

All four are in `this_engine_reports_more()` with the addon line that proves
each, which is the only place the test lets a difference through in that
direction.

**One file could not be added, and the reason is the reference tool's.**
`examples/firmware-cortex-m/src/main.c` uses GCC explicit register variables —
`register uint32_t r0 __asm__("r0")` — for the semihosting exit, and cppcheck
2.21.0 reports `syntaxError` on it and runs the addon over nothing. The oracle
script refuses to write a capture for a file that produced no MISRA findings, so
this surfaced as a failure rather than as a file silently contributing an empty
comparison.

**Two things it did not settle, recorded rather than asserted:**

1. **Line anchors differ and are not compared.** Both tools fire 16.3 on the same
   switch and 15.7 on the same `if` chain, four lines apart — cppcheck points at
   the clause that falls through, this toolkit at the statement that should have
   been followed by a `break`. Neither the guideline nor the standard fixes where
   a finding belongs, so asserting line-for-line would pin one tool's
   presentation choice as truth. The test compares *which guidelines a file
   violates* instead.
2. **One genuine difference of reading: `21.6` on `#include <stdio.h>`.** The
   guideline prohibits the standard I/O *functions*; cppcheck flags the calls,
   and this toolkit also flags the header, with a message saying "`stdio.h` is
   not permitted in this profile" — a broader claim than 21.6 makes. Whether the
   citation should be narrowed, or the message reworded to a profile rule that
   cites nothing, needs the licensed text. It is allowed through by name so that
   any *other* new disagreement fails the test.

Everything else this toolkit reports and cppcheck does not is a directive
(`D4.4`, `D4.6`, `D4.12`) its addon does not implement.

A third test asserts the corpus disagrees in both directions and overlaps in at
least three guidelines — without it the two tests above would pass on an empty
comparison, which is this repository's signature failure.

### The warning that never reached the artifact

Found by asking which *NOT CHECKED* providers any test actually names — counting
only occurrences inside a `tests/` file or after a `#[cfg(test)]` marker, because
a provider mentioned in a file that happens to contain tests is proximity, not
coverage. Five came back with nothing.

Two of those five were the method's own false negatives, and worth stating
because the same method will be used again: `sda.deviations` and
`sda.architecture` *are* asserted, by their consequence rather than by their
provider string. A search keyed on a name has the opposite bias to a search keyed
on a reason, and neither is coverage on its own.

Three were real. `--coverage` and `--observation` pointed at a file that is not
there now have end-to-end tests through the real binary. `--compile-commands`
turned out not to emit a notice at all: it refuses the run, exit `1`, naming the
command that generates a database. That is the right asymmetry — coverage and
observations are evidence a run can do without, while a compile database decides
which guidelines are reachable at all — but it was undocumented and untested, so
all three behaviours are pinned now.

Then the same question, asked of the report rather than of the providers.

`.sda/` can declare deviations, a scope, an architecture and a replacement
catalogue. Every one can be *partly* refused — a component whose boundary is not
one of the three words, a scope rule that owns the analysis root, a catalogue
that will not parse — and `ProjectConfig::discover` collected each refusal into
`problems`, under a doc comment that already stated the principle: *never
silently swallowed*.

They were swallowed. `problems` was printed by the CLI as a `warning:` on stderr
and went nowhere else. `sda scan --format json > report.json` keeps `exclusions`
and throws stderr away, so the saved artifact — the one piped into a build,
attached to a review, read six months later — had no trace of them.

Measured on a two-component declaration whose second component is a neural guard,
refused because a guard that is itself a model moves the premise rather than
discharging it:

```
warning: architecture entry `llm-judge` rejected: a guard that is itself a
         model moves the premise rather than discharging it
$ grep -c llm-judge report.json
```

No match. The report carried an interposition result computed over a graph with
one fewer node than the declaration describes, and said nothing about the missing
node. That is this codebase's signature failure with its own configuration as the
subject.

Two lines below where those warnings were printed sits the comment
``scope_notices`` must reach the report — see `apply_scope`. Somebody had already
made this exact argument for one kind of notice. The configuration loader never
got it.

**The fix had to distinguish two kinds of problem**, because routing all of them
is the mistake in the other direction — this session already produced one notice
that was twice the error it prevented. A rejected *deviation* is already in
*NOT CHECKED*, put there by the engine from the register it was handed, on a path
that also serves callers who never built a `ProjectConfig`. An accepted
declaration's advisory warnings are re-derived downstream by the layer they
affect: *no component is declared an effector* arrives as
`sda.interposition: sda.no-effector` from the layer that could not ask the
question. Both would have been said twice, in different words, in the one section
a reader must not learn to skim.

So `discover` no longer pushes to `problems` directly anywhere. It calls
`dropped` — something did not take effect and nothing downstream says so, which
reaches the report as `sda.config` — or `advisory`, which does not, and every
site states which and why. Ten and two. The helpers exist so the next declaration
kind added here has to answer the question rather than inherit an answer.

The four tests were mutation-checked: with the routing removed, three fail. The
fourth asserts an *absence* and passes either way, which is stated here rather
than papered over — its other half, that `sda.interposition` still says what it
could not check, is what gives it teeth.

**And the gate caught the rest of it, badly.** Adding those seven tests made
`the_workspace_test_count_is_what_the_tree_contains` fail, which is the test
doing its job — the document claimed a total the tree had outgrown. But it failed
with `attempt to subtract with overflow`. It computed `stated_tests - functions`
to derive the doctest count, and on the one case it exists for — a session adds
tests and the document still says the old number — that subtraction goes
negative. True, useless, and silent about which of the four figures to change.

It now checks the direction first and names both numbers and every site to
update. Sixth instrument this codebase has had that was wrong the first time it
was pointed at a real answer, and the fourth whose failure was that it could not
report what it had found. The pattern is stable enough to plan around: *write the
instrument, then make it fail on purpose and read what it says.* A green
instrument has told you nothing until you have seen its red.

### An empty proof is not a proof that found nothing

The same question as the section above, asked of the interposition result, and it
gave the same answer.

`verify` builds one proof obligation per model/effector pair. When `obligations`
comes back empty, `summarize` reported:

> Interposition: not checked — no model reaches a declared effector by any
> declared path.

That sentence makes a claim about models and about paths. There are three ways to
reach it, and only one of them justifies the claim:

* **No effector declared.** Already handled — an early return with
  `sda.no-effector`, "this is not a clean result, it is the absence of a
  question". The care taken here is what made the other two visible.
* **No model declared.** The pair loop never runs. There was no notice at all,
  so the summary sentence was the only thing said — a statement about models and
  paths, made of a declaration containing neither. The reassuring reading and the
  empty one are word for word the same. A component that *is* a model and was
  declared `symbolic` lands here, and that is a judgement rather than a typo, so
  the parser cannot catch it.
* **Both declared, nothing connecting them.** `paths.is_empty()` did a bare
  `continue`. No obligation, no notice. A flow section missing an edge and a
  system where the model genuinely cannot reach the effector are indistinguishable
  in the output, and only one of them is safe.

Now: `sda.no-model` mirrors `sda.no-effector` and returns early, which also stops
`sda.no-guard` firing behind it — "every path from a model to an effector is
therefore a bypass" is vacuous in a system with no models, and vacuous entries are
what teach people to skim the section. `sda.flow-disconnected[a -> b]` names the
pair. And `summarize` no longer asserts anything about paths; it says no pair was
available and sends the reader to *NOT CHECKED*, which now holds a reason in all
three cases.

That last part is why the third fix was not optional. Changing the summary to
promise that *NOT CHECKED* names the missing part creates a debt, and the silent
`continue` was the case that would not have paid it.

**The invariant test was weaker than it looked.** It asserted that an empty proof
leaves *some* `sda.`-prefixed entry, and under mutation it passed — the vacuous
`sda.no-guard` satisfied it. Checking that something was said rather than that the
right thing was said, which is the failure this document spends a hundred rows on,
committed in a test written to catch it. Each case now names the marker it must
produce. Its doc comment also says what it cannot do: nothing here is an
exhaustive match, so a fourth `continue` added later would go unnoticed.

### "did not run" was the wrong verb for two thirds of them

The same question again, asked of the machine-readable surface this time, which
is the one a CI system acts on without a human reading it.

Every entry in *NOT CHECKED* reaches SARIF as a tool execution notification —
the right place for it, and a downstream dashboard can tell a partial run from a
clean one. Each was rendered:

> provider `X` did not run: *reason*

That was written when the only exclusions were external tools that were not
installed, and for the nine `ext.*` entries it is still exactly right. It is
false for most of the rest. On one small scan, six of fifteen:

* `sda.interposition` **ran**, and found no model/effector pair to prove anything
  about.
* `sda.neurosymbolic` **ran**, and adjudicated a component as vacuous — that is a
  result, not an absence.
* `sda.correlate` **ran**, without a runtime observation to correlate against.
* `sda.config` is not a provider at all. It is configuration the project asked
  for and did not get, added earlier in this session.

The distinction between *a check that was skipped* and *a check that came back
with nothing to say* is the one this toolkit exists to keep, and `correlate.rs`
states it in as many words a few hundred lines away: "`Unreached` must never
assert that code did not run." The serializer asserted it, of everything, in the
output format meant for machines.

An `Exclusion` carries a provider and a reason. It does not record whether
anything executed, so the serializer cannot know and must not say. Notifications
now read `NOT CHECKED — \`provider\`: reason`, which maps onto the report's own
section and claims nothing further.

`descriptor.id` was deliberately left as `sda/providerExcluded`. That is the key
a consumer matches on and the wording is not; renaming a stable machine contract
to fix an English sentence is the worse trade. The type's own doc comment —
"providers that did not run, and why" — is where the framing started, and now
says what the field actually holds.

### Sixty paragraphs saying one thing

Not the failure mode in the table below, and deliberately not added to it — that
census counts an inability to check presented as a clean check, and this is close
to the opposite. Nothing here was hidden. It was said sixty times, which had the
same effect.

`sda.unmapped` marks a file carrying findings that belongs to no declared
component, so nothing in it can be attributed to a proof or an assumption. It
pushed one paragraph per distinct path. Measured on a sixty-one file project with
a declaration covering one directory:

| | *NOT CHECKED* lines | of which `sda.unmapped` |
|---|---|---|
| before | 77 | 60 |
| after | 18 | 1 |

Sixty near-identical paragraphs, and everything else in the section underneath
them. On a real tree it is thousands. This section is the product's central
promise and the only one a reader must not stop before; an entry that appears
hundreds of times teaches people to scroll past exactly where the two that matter
are sitting.

This is a defect this repository has already had and already fixed once.
`ExternalCoverage::provenance_of_many` exists because gcov writes one `.gcov` per
translation unit, a real 105-file project produced fifty-nine of them, and
fifty-nine near-identical paragraphs went into *NOT CHECKED*. The fix there was
to collect and say once. This one scales per *source file* rather than per
coverage file, so it is worse, and it sat a crate away from the cure.

Collapsed the same way, and the count is kept because at scale the count is the
finding: one unmapped file is an oversight somebody can go and fix, six hundred
means the declaration describes a corner of the tree and the interposition proof
is about that corner. Three or fewer are still named one by one — naming them is
what makes the notice actionable, and three lines bury nothing.

The deduplication also changed. It compared each formatted line against every
line already collected, a linear scan of a growing vector per finding, on runs
that reach eighty thousand findings. A `BTreeSet` does the same work and fixes the
order, so the same scan twice produces the same report.

**Then the same question asked of every other notice**, rather than waiting to
trip over the next one. `tools/notice-bounds.py` finds each `not_checked.push`,
`notices.push` and `exclusions.push` in the workspace and reports the innermost
`for` loop enclosing it, by brace depth. Thirty-three sites, every one inside a
loop — which sounds alarming and mostly is not: iterating the provider list, the
declared components, the deviations in a register or the paths named on the
command line is bounded by something a person wrote, and a person can read back
what they wrote.

Two iterate something that scales with the input instead. One was
`sda.unmapped`. The other is `sda.taint-untraced`, one entry per taint finding
that lands on a declared effector with no dataflow trace — so a CodeQL report
sets the length of the section. Measured at four on a three-file fixture, which
is small, and bounded only by the size of the report, which is not.

It is also the case where the collapsed sentence already existed: the paragraph
directly above the list said "4 taint finding(s) landed on an effector with no
dataflow trace", and then *NOT CHECKED* said it again four times. Bounded the
same way, and `unevaluable_taint` still carries every line on the struct for a
programmatic caller, so only the projection into the report is shortened.

**The first version of that collapsed line was worse than what it replaced.** It
quoted the first full entry inside itself, so the new line carried two
`sda.taint-untraced` prefixes and the explanation twice. One long unreadable
line in place of four readable ones is not an improvement. It is built from the
findings now — count, reason, then three named by rule and location — which is
what the notice was for.

### The list that ended without saying it had stopped

The text report prints findings, then a `Summary` with the counts. It printed the
first five hundred and stopped.

Measured on a 200-file project: 800 findings in the report, 500 lines in the
list, and nothing anywhere saying the other 300 existed. On PX4 it is not 300:
the scan reports 78,211 findings and the page showed five hundred, so **77,711
were dropped in silence**. The counts below are
right — `low: 800` — so a reader who compares two numbers can work it out. A
reader who scrolls to the end of a list and finds that it ended believes they
have seen the list.

Twenty lines further down the same function, the coverage-gaps block takes twelve
lines per file and writes `(+N more)`. The obligation was understood in one place
and not in the other, in the same screenful of code, which is worth remembering
before assuming a codebase that gets something right gets it right everywhere.

The severity filter had the milder version of it. `--min-severity high` on a tree
of eight hundred low findings printed "No findings at the requested severity" and
nothing else above the summary — true, and it reads far too much like a clean
scan. It now says how many are below the threshold, so the empty list and the
reason for it arrive together.

Both are stated at the list rather than in *NOT CHECKED*, deliberately: those
findings **were** checked. Nothing is missing from the analysis, only from the
page, and filing a display limit under "not checked" would make that section mean
two different things.

**Then every other `take(` in the workspace**, the same way the notice sweep
went. Most are not display limits at all — a GGUF header reader taking four
bytes, an identifier truncated to the thirty-one characters MISRA 5.1 compares,
a parser bounding its own lookahead. Of those that do cut a list short for a
reader, two on the MCP surface already did it properly: `report_json` publishes
`total` beside `shown`, and the baseline response carries the true `new` count
next to a capped `new_findings`.

One did not. `report.query` — filter a report by severity and correlation
verdict — computed its `matched` field **after** the two-hundred cap:

```rust
.take(200)
...
Ok(json!({ "matched": findings.len(), "findings": findings }))
```

A query selecting five hundred findings answered `matched: 200`. That is not an
omitted total, it is a wrong one, and it is worse than the text report's silence
for two reasons. The caller is an agent, which cannot glance at a summary block
and notice the numbers disagree — the test directly below this one in
`dispatch.rs` was written for exactly that asymmetry, and says so. And two
hundred is a round number with nothing about it to arouse suspicion.

`matched` is now counted before the cap and `shown` published beside it, which is
the convention the same file already used a few hundred lines up. Mutation-checked
by putting the old expression back: the test reports `matched: 200` against 250.

### This session's changes, against twenty thousand files

Most of what this session fixed is in the reporting layer — which notices are
emitted, how they are worded, how many are printed — and the rest adds notices
without changing what any rule decides. None of it should move a finding, and
"should" is not a measurement.

`PX4-Autopilot/src`, 20,287 files:

* **78,211 findings**, which is what the subsection *And the findings that
  stayed* recorded.
* **73,401 distinct** by rule, file and line, which is what the comparison table
  recorded.

Both figures reproduced exactly, from one scan, against two numbers written down
before any of this session's work — and the two documented numbers are now known
to be two views of one scan rather than a contradiction.

**Run twice, thirteen commits apart.** The first was after seven commits of pure
report changes. The second came after thirteen more that reach further in: a
notice in the C analyzer, a notice in the Rust analyzer, three new entries in
`RuntimeEventKind::from_cwe`, and two in the engine's own run loop. Both times
78,211 and 73,401, to the digit.

That second run is the one worth keeping, because the first only established that
report-layer edits are report-layer edits. The second says that changes inside
both analyzers and inside the CWE map added exactly what they were meant to add —
one `sda.static.c` notice about `test_identity.h`, and twelve exclusions where
there were eleven — and moved nothing else across 20,287 files.

The run also exercises the new code on something other than a fixture. The
truncation notice reads "and 77711 more finding(s) not shown" — the defect's
actual size, against the 300 the fixture showed. *NOT CHECKED* came back twelve
entries, every one of them a distinct cause, which is the state the collapse work
was for: on a tree this size it is a section a person can read.

### "This session" stopped being a date the moment the session ended

Chasing the PX4 figures turned up a second one that looked like a contradiction:
`PX4 scanned on both OSes | 15,528 findings each` sits a few rows above a table
saying the same tree yields 73,401, and the subsection below that says 78,211.
Three numbers, one tree.

The third column said **this session**. So did seventeen other rows. `git blame`
puts them between **2026-09-03 and 2026-09-16** — at least five different
sessions — and a reader today reads all eighteen as current. 15,528 was measured
on 2026-09-14, two sessions and one growing rule set ago, and is not comparable
to a number measured today. Nothing on the page said so.

It is the document's own failure mode, aimed at itself: the information existed
(git has always known), and it was thrown away on the way to the reader in favour
of a label that was true when typed and wrong immediately afterwards. "This
session" is the natural thing to write while writing. That is exactly why it
needs a test rather than a resolution to be careful.

All eighteen now carry the date `git blame` gives for the line, which for a row
whose cell is a measurement is when that measurement was taken — a row
re-measured today dates to today, correctly rather than by accident. And
`no_measurement_is_dated_relative_to_whoever_wrote_it` fails on "this session",
"last session", "today" and "yesterday" in any table row, because the one-pass fix
does not survive the next person typing the natural thing.

**A baseline decays the same way a date does.** One row read *narrowings checked
against `HEAD~13`*. When it was written that resolved to `65e5c83`; ten commits
later it resolves to something else entirely, so a reader following the row
compares against the wrong binary and gets numbers that look perfectly
reasonable. It names the sha now, and the same test rejects `HEAD~` and `HEAD^`
in any table row — in rows only, because `git diff HEAD~1` in prose, telling
somebody to look at their own last commit, is a relative reference that means
exactly what it says.

**What did reconcile, and it is the better half.** Two figures were checked
against the trees themselves rather than against git:

| tree | raw findings | distinct by rule/file/line | table says |
|---|---:|---:|---:|
| `PX4-Autopilot/src` | 78,211 | 73,401 | 73,401 |
| `bibutils` (149 C files) | 9,150 | 8,552 | 8,552 |

Exact, on both. The comparison table counts *distinct* findings, the prose counts
raw ones, and that convention is now verified on two independent trees rather
than assumed from one. `bibutils` also settles its own file count: 149 C files,
matching the table; the 105-file row is dated 2026-09-07 and measured something
else.

**What did not reconcile**, said plainly rather than quietly rewritten: PX4's
15,528 and the workbench section's 14,284 could not be reproduced today from the
full tree, from `src/modules`, `src/drivers`, `src/lib`, or from any language
split of the current scan. The likeliest explanation is that both predate rules
added since, which the dates now make visible. They were left as they are, with
their dates, because a number nobody can reproduce should not be quietly replaced
by one somebody can — the replacement would look like corroboration.

### Every file this document names

Same question as the dates, asked of the paths. A handbook this long pointing at
`crates/sda-engine/src/checks.rs` is making a checkable claim, and a renamed file
leaves a reference that still reads as authoritative — worse than no reference,
because a reader trusts it and goes looking.

Fifty-four repository paths named, and **none of them missing**. A clean result,
and worth recording as one: the document's pointers have not rotted.

Eight resolved only by guessing a `crates/` prefix: they were written from the
crate down rather than from the repository root, so
`crates/sda-agent/src/dispatch.rs` appeared with its first component missing.
Those were rewritten repo-relative rather than taught to the checker, so the test
could stay a plain existence check and so a reader can paste the path into an
editor and arrive.

Writing that sentence is what failed the gate. The first draft quoted the broken
form as an example, in backticks, and the test does not care why a path is there
— it is a path this repository does not have, printed in a document that names
paths to be followed. Third time this session prose has tripped an instrument
written in the same session, after a spelled-out number and a quoted count. The
rule the repository already had covers it: **a backticked thing is a claim, so
quote a bad example by describing it, not by writing it.**

Three kinds of backticked path are deliberately not repository files, and each is
excluded by name rather than by a pattern loose enough to hide a real miss: files
in a user's own project (`.sda/triage.toml`), files belonging to another tool
(cppcheck's `addons/misra.py`), and illustrative paths inside a rule's
explanation (`src/build.rs`, which `DEP.2` wrongly called a build script).

**The test caught itself being wrong, which is the part worth keeping.** It also
asserts that it examined more than forty paths, and the first version tripped
that: it split the whole document on backticks and took the odd-numbered spans,
but a fenced block opens with three backticks and flips the parity for everything
after it. Thirty-six paths where the same logic outside Rust found fifty-four —
a check quietly examining two thirds of its subject and passing. **A test that
asserts it looked at something is the cheapest defence against the failure this
document spends a hundred rows on**, and it cost one line.

### And every symbol it names

The paths sweep has a sibling: the document is dense with `ProjectConfig::discover`
and `ExternalCoverage::provenance_of_many`, and a renamed function leaves
guidance that reads as authoritative and sends a reader after something gone.

`tools/handoff-symbols.py`. **Seventy-nine symbol paths, and the one it reports is
correct as written**: the document names a method that was renamed, in the
sentence explaining that it was renamed. Two others needed a human to classify
and were also right — a proof obligation's id is not a Rust path.

That last point is why this is **a list to read and not a gate**, unlike the
paths check next to it. A path has no equivalent case; a symbol does, and the
only honest way to permit it in a test is a list of exceptions that grows until
it hides a real miss. `uncalled-api-sweep.py` is in `tools/` for the same reason.

**It took four passes to become worth reading**, each found by calibration rather
than by inspection:

| what it missed | why |
|---|---|
| `NoSuchType::at_all` caught, a renamed *method* not | it passed a path when either end resolved, and the type survived |
| `ProjectConfig::problems` called missing | struct fields are named `Type::field` in prose too |
| `sda_engine::interposition` called missing | a module is a file, not a `fn` |
| three `clippy::` lints called missing | lint names belong to clippy |

The second one is the instructive one. **A method renamed under a surviving type
is the likeliest rot of all**, and the first version was blind to exactly that
while catching the case that almost never happens.

### A file that would not lex was a finding, not a gap

`SDA-C-LEXICAL` fires when a block comment or a literal is never closed. It was
the only thing reported, and it is not enough.

An unterminated comment on line 1 swallows the rest of the file. Measured on one
six-line function:

| file | contents | MISRA findings |
|---|---|---|
| `plain.c` | the function | 3 |
| `early.c` | `/*` and then the same function | **0** |

Identical code, three guideline violations gone. And the finding said *every
structural finding in this file is now suspect*, which is the wrong word: they
were not suspect, they were **absent**. A reader who sees that message, looks for
the file's other findings and sees none concludes "suspect, but clean" — the
opposite of what happened.

*NOT CHECKED* said nothing about the file. The provider already had the
machinery and was already using it for a file it could not **read**; a file it
could read but not tokenise went down a different path with no notice at all. The
distinction that mattered to the code was I/O, and the distinction that matters
to a reader is whether the file was analysed.

Both halves are fixed: the file reaches *NOT CHECKED* naming what swallowed it
and from which line, and the finding says the guidelines below it *were not
checked at all*.

**On PX4 this is one file in 20,287** — `test_identity.h`, a literal running to
end of file — and the run still produces 78,211 findings, unchanged to the digit.
One real hole that had been sitting inside a 78,000-finding report, reported as
one finding among them.

**Rust had the same hole and was quieter about it.** No finding either: a file
behind an unclosed `/*` left the analysis with nothing at all to show it had been
skipped. Measured on a file holding an `unsafe fn` and an index expression — one
finding normally, and behind an unterminated comment, no finding and no notice.
A file that was never checked, presented as a file with nothing wrong, which is
this codebase's failure mode with no mitigation at all.

`RustLexed::unterminated_block_comments` had been computed since it was written
and read by nothing outside the lexer's own tests. **The fact needed to report
the hole was already in hand** — the fourth time this document has recorded an
answer computed and never consulted, after `ExternalAdapter::timeout`,
`DeviationRegister::expired` and `coverage_gaps`. `uncalled-api-sweep.py` exists
because three was enough to stop finding them by accident; it lists `pub fn`, and
a public *field* nobody reads is the same defect wearing a different hat.

The Rust side gets the notice and no finding, deliberately. A finding needs a rule
id, and an id in this engine carries catalogue obligations — a fixture, a
near-miss, a place in `implemented()`. The notice closes the hole; the finding
would be symmetry for its own sake.

That measurement is also why the notice is **not** collapsed the way
`sda.unmapped` and `sda.taint-untraced` were two commits earlier. It is one entry
per file and therefore the same unbounded shape, which is worth saying out loud
rather than leaving for someone to notice: at one in twenty thousand, naming
every file is worth more than a count, because each one is rare and individually
actionable. If a tree ever shows otherwise the collapse pattern is sitting in the
two files next to it.

### Two of three knobs did nothing

`RunOptions` is the public struct every caller passes to `analyze`. It has three
fields:

| field | what it says | who reads it |
|---|---|---|
| `disabled_rules` | rules to skip | three providers |
| `timeout_secs` | "wall-clock budget for the whole provider, in seconds" | **nobody** |
| `settings` | "provider-specific settings, keyed by provider id" | **nobody** |

`timeout_secs` appears exactly once in the workspace: its own declaration. So
does the `max_runs` example in `RunOptions::get`'s doc comment, which names a
setting that has never existed. A library caller sets a budget, gets none, and is
told nothing — the public API promising a capability it does not have, which is
this repository's failure mode pointed at its own interface.

**Neither is wired up, and that is a decision.** A wall-clock budget across
native providers needs cancellation this engine does not have, and inventing a
setting for a provider that never asked for one would be worse than the gap. What
can be done honestly is refuse the instruction out loud: a set budget and
supplied settings now reach *NOT CHECKED*, with the count, and both doc comments
say they are not honoured. **The difference between "your timeout did nothing"
and silence is the whole of what that section is for.**

A fourth test asserts `disabled_rules` still filters, so the other three cannot
quietly become a description of an engine where no knob works.

**How it was found, and what it says about the sweep.** By listing public
*fields* nothing reads, after `RustLexed::unterminated_block_comments` turned out
to be one. `uncalled-api-sweep.py` could not have found either: it lists `pub fn`.

Worse, it misses `RunOptions::get` and `set` — the accessors for the dead
`settings` map — even though they are exactly `pub fn` with no call site. **A
name-based sweep cannot see a dead method whose name is common**: `get` is called
everywhere in any Rust workspace, so a `get` that nobody calls on *this* type
looks heavily used. The sweep reports three other functions in the same file and
walks past these two.

That is worth knowing before trusting its output again. It finds dead functions
with distinctive names, which is most of them and not all of them.

`tools/unread-field-sweep.py` is the companion, committed because it found three
real things in one run. Same contract: a list to read, not a gate. Of 353 public
field names, 147 are never read outside the file declaring them, and **most of
that is honest** — serde serialises `Report`'s fields to `--format json` without
ever writing `.field`, patterns destructure rather than access, and `sda-syntax`
exists to expose structure a consumer takes two fields of six from.

Two shapes in that list are worth opening, and both have already been real here:

* **A field never populated with anything but a default.** `RustItem::attributes`
  was never written to, so `#[test]` and `#[no_mangle]` read as absent
  everywhere. `UnsafeRegion::enclosing_item` was always `None`, read by nothing,
  and the one field in its struct with no doc comment — deleted this session
  rather than left as a trap for the next check that trusts its name. Nothing
  read it, so it cost nothing yet; `attributes` is what it costs later.
* **A field whose doc comment makes a promise.** `timeout_secs` said "wall-clock
  budget" and bounded nothing.

**Not everything it prints is a defect, and checking cost less than assuming.**
`RustItem::is_async` and `is_const` looked like the same bug — computed into
local variables and then written as literal `false`. They are correct: that
struct literal is the `extern "C" { }` arm, where neither can apply, and the
general arm two lines down uses the computed values. Read the site before
believing the pattern.

### Two maps between the same two things, disagreeing

`RuntimeEventKind` and CWE are mapped in both directions, in two crates:

* `correlate::related_weaknesses` — kind to the CWEs a witness of that kind can
  confirm.
* `RuntimeEventKind::from_cwe` — CWE to the kind an external tool's finding
  becomes.

They agreed everywhere except one class. `related_weaknesses` has claimed
`ModelBehavior => [506, 502, 74]` since it was written; `from_cwe` mapped none of
the three.

**What that cost.** `sda-adapters` turns an external dynamic tool's findings into
runtime events by CWE, falling back to `SanitizerReport` when `from_cwe` returns
nothing. So a CWE-502 finding — unsafe deserialisation, exactly what modelscan
reports about a pickled model — became a `SanitizerReport` event. `SanitizerReport`
relates back to `[787, 125, 758, 362, 401]`, which does not include 502. **A static
CWE-502 finding and a runtime witness of CWE-502 did not correlate.**

That is word for word the failure the existing test names in its own assertion
message: *"a witness and a static finding carrying the same CWE would not
correlate"*. It could not see this one.

`every_weakness_class_confirms_its_own_cwe` walks CWE 1 to 2000 and skips every
number `from_cwe` returns `None` for. It checks that what the reverse map knows,
the forward map agrees with — and a CWE the reverse map has never heard of is
`continue`d past in silence. **A one-directional test over a two-directional
relation, and the gap was exactly the direction it could not look.**

`ModelBehavior` was also the only `RuntimeEventKind` nothing in production ever
constructed, which is how this was found: sweeping for enum variants no code path
produces, after the sweeps for dead functions and unread fields. The variant was
unreachable *because* of the missing mapping, not beside it.

Both directions are checked now. The new test is exhaustive over the kinds, so a
new one has to be listed before the file compiles, and it fails with the CWE and
the consequence rather than with a number. Mutation-checked by removing the three
mappings again: the new test fails and **the old one still passes**, which is the
proof that they are two tests rather than one written twice.

### Four hand-written `all()` lists, and what they decide

The sibling question to the two CWE maps: where else does this workspace keep two
hand-maintained descriptions of one thing? An `all()` returning a slice literal is
exactly that — the enum is written by hand, the list is written by hand, and
nothing compares them.

Four enums have one, and **all four lists are complete**. Recorded as a clean
result, because two of them decide something:

* `Capability::parse` scans `Capability::all()`, so a variant missing from the
  list is unparseable however correct `as_str` is. A provider declaring that
  capability over MCP would come back `None` — the capability reading as one this
  toolkit does not have.
* `ProjectConfig::discover` iterates `Standard::all()` to find a project's
  catalogue overrides. A standard missing from the list means
  `.sda/misra-c-2023.toml` is never looked for, the built-in catalogue stays
  silently in place, and the conformance argument rests on rule text nobody
  supplied — which is a defect this document already records once, from the other
  direction.

Both now have a test whose `match` is the forcing function: a new variant does
not compile until it is named there, and naming it there is the prompt to add it
to `all()`. A length check catches drift the other way. Mutation-checked by
dropping one variant from each list.

**The sweep needed correcting first, and the shape of its wrong answer is the
tell.** It reported `ProviderOrigin::all()` and `AnalyzerKind::all()` as omitting
*every* variant they have — because neither enum has an `all()`, and the script
had attributed the next one in the file to them. **"Omits 2 of 2" is what a
mis-attribution looks like; a real drift omits one of sixteen.** Requiring the
`all()` to sit inside that enum's own `impl` fixed it, and the four real lists
came back clean.

### The probe stream has two sides and nothing compared them

A contract written in two languages, in two directories: `shim/sda_probe.h`
emits JSON lines, `ProbeRecord` in `crates/sda-engine/src/dynamic.rs` reads them.
Five record types, and **they agree exactly**:

| record | keys the shim writes | keys the parser expects |
|---|---|---|
| `cov` | `f`, `l`, `n` | `f`, `l`, `n` |
| `fault` | `f`, `l`, `k`, `m` | `f`, `l`, `k`, `m` |
| `val` | `f`, `l`, `k`, `v` | `f`, `l`, `k`, `v` |
| `cmp` | `f`, `l`, `a`, `b` | `f`, `l`, `a`, `b` |
| `mark` | `k`, `v` | `k`, `v` |

Nothing checked that. It is the shape that had `related_weaknesses` and
`from_cwe` disagreeing about one class for as long as both existed, and the
QEMU run in the table above is a measurement of one afternoon rather than a test
that runs again.

**Drift here would be quiet.** A renamed key does not crash anything: serde
reports a missing field, the line is dropped, and a capture taken off a board
arrives thinner than the run that produced it — or empty, which reads as a
program that executed nothing rather than as a stream nobody could read.

`the_c_shim_and_the_parser_agree.rs` reads the header itself, recovers the keys
each record emits *in the order the C code emits them*, builds a line to that
shape and hands it to the parser. **No compiler is involved**, which is the point:
the interesting targets for this header are the ones this machine cannot build
for, and a contract test that only runs where a cross-compiler is installed is a
contract test that does not run.

A second test asserts the header emits no record type the first has not listed,
so a sixth record cannot leave the first passing on the five it already knows.

**The Rust emitter had the same contract and four fifths of a test.**
`sda-probe` is the second writer of this stream, and
`the_emitter_and_the_engines_parser_agree` already round-trips it through the
engine's parser — the right test, written for the right reason, with a comment
saying it is "the only way to know the shim is not writing something the engine
quietly discards".

It exercised `cov`, `fault`, `mark` and `value`. The section is headed *every
record type survives the round trip* and `cmp` was not in it: emitted by a public
function and a macro, parsed into `Observation::comparisons`, asserted nowhere.

It works — this closed a coverage hole rather than a defect, which is worth
saying plainly. Calibrated by renaming the emitter's `a` key: the comparison set
comes back empty and the test says so. Empty is what this drift looks like from
the outside, and it is indistinguishable from a program that compared nothing.

**And the variable that finds the file had never been run.** `SDA_PROBE_OUT` is
the mechanism the whole statodynamic claim rests on: the engine sets it before
launching a target, the target's instrumentation reads it when its session first
initialises, and the records come back as coverage. Without it nothing can be
confirmed, refuted or called unreached, and the result is a static one wearing a
dynamic name.

No test exercised it. The unit tests *cannot* — the session is a process-global
`OnceLock`, and their `rebind` helper points the already-initialised session at a
fresh file, deliberately going around the env-var path. `run_once`, which sets the
variable, is called by the runner and the fuzzer and by no test. It was verified
by hand once, as the Cortex-M3 row in the metrics table above: a measurement of
an afternoon rather than a check that runs again.

An integration test is its own binary and therefore its own process, with its own
`OnceLock`. One test in that file, setting the variable before anything touches
the session, is the only ordering under which the real path can be observed.

Its first assertion is `is_enabled`, and that is not ceremony. A session whose
stream failed to open is *disabled*, every emitter becomes a no-op, and every
later assertion then fails as though the emitters were broken — the unit tests
say so about their own harness. Calibrated by removing the `set_var`: it fails
there, naming the reason, rather than three assertions later on a symptom.

What it does not catch is stated in the file: a key *added* to the header, since
serde ignores unknown fields. Calibrated in the direction that matters by
renaming `fault`'s `k` to `kd` in the C source — the parser rejects the line and
the test says so.

### The rule punished the better justification

Writing the test above tripped the gate's self-scan: `RUST-2024-UNSAFE.1`, "this
`unsafe` block has no `// SAFETY:` comment". It had one — four lines of it.

The lookback was a fixed three lines above the keyword, and Rust style puts
`// SAFETY:` on the *first* line of a comment and continues below it. So a
justification long enough to explain a subtle invariant moves its own marker out
of the window. Measured on one file holding two `unsafe` blocks identical apart
from the length of their reasoning:

| block | justification | reported |
|---|---|---|
| `short` | one line | no |
| `thorough` | four lines | **yes** |

**A toolkit whose whole claim is that the justification is the only evidence left
once the compiler stops checking, rewarding the terse one.** The rule fired
precisely where somebody had done the work.

The lookback now climbs the contiguous run of comment lines ending just above the
keyword, however long it is, with the old three-line reach kept as a floor so a
`/* */` block — which the lexer reports at its opening line only — loses nothing.

**Widening a check is how a check stops checking, and widening it alone was
wrong.** The rustc differential caught that within the hour: `UNSAFE.2` at line 44
of the corpus vanished. The corpus documents its own cases in prose — *"an unsafe
block with no SAFETY comment above it"* — so a long doc comment that merely
*mentions* the word began silencing the rule it was describing. One real finding
gone, and nothing about the change looked wrong.

So a marker is required — and there are **two**, because the language has two
conventions, which the first correction got wrong as well. An `unsafe` *block* is
justified by `// SAFETY:` with its colon, which sixteen of the nineteen
occurrences in this workspace write. An `unsafe fn` documents its contract under a
rustdoc `# Safety` heading, which is what clippy's `missing_safety_doc` asks for
and what has no colon in it anywhere.

Requiring only the colon made `UNSAFE.2` fire on a function documented exactly as
the guideline asks. **The near-miss corpus caught that**, the same way the rustc
differential caught the one before it — by holding a conforming source and
insisting the rule stay quiet on it. Two instruments, two corrections, neither
found by reading the code.

Prose satisfies neither marker, which is the point: *"an unsafe block with no
SAFETY comment above it"* is a sentence about safety, not a contract.

Four negatives are asserted, each measured firing first: no comment at all, a
comment that says nothing about the invariants, a `SAFETY:` further up with a
blank line and two statements in between, and the prose case the differential
caught. Two positives are asserted beside them — a four-line `// SAFETY:` block
and a `# Safety` heading — because this rule now has two shapes to get right and
each correction here broke the other one. Mutation-checked by restoring the fixed
window.

Worth noting where both halves came from. The defect was not found by reading the
rule — the gate refused a commit, and the commit it refused was a test written for
something else entirely. The regression in the fix was not found by reading
either: a differential oracle against a real toolchain found it, which is the
argument for keeping oracles that this document makes at length elsewhere, paid
back inside a single afternoon.

### Somewhere to start, taken from repowise

PX4 reports 78,211 findings. `triage_order` sorts by severity, then confidence,
then *path* — so the forty-two thousand `low` ones come out alphabetically, which
is no order at all for somebody deciding where to spend an afternoon. The scan
answers "what is wrong" completely and "where do I start" not at all.

[repowise](https://github.com/repowise-dev/repowise) is a codebase-intelligence
platform built around that second question: a dependency graph, git analytics,
health detectors, blast radius, served to agents over MCP. Much of it this
toolkit already has in its own idiom — coverage correlation *is* impacted-tests,
`uncalled-api-sweep.py` *is* dead code, `SDA-C-COMPLEXITY` *is* a health
detector. What it has and this did not is **history**: churn, ownership,
recency.

`sda hotspots <path>` joins findings to churn and ranks by their product. On this
repository it is a three-line table; the shape it is for is PX4.

**Churn is not a defect, and the output says so twice.** No rule emits a finding
for it, nothing gains severity for being edited, and the closing line states that
the findings are measured and the order is not. A number like this is one step
from becoming a risk score, which is a claim about code assembled from facts
about a team — and the step is short enough that a test asserts the framing
survives editing.

**What made this worth building here rather than installing there.** `git log`
on a shallow clone *succeeds*. Exit zero, no warning, nothing on stderr. Measured
on a `--depth 1` clone of this repository: one commit, naming 288 files. A churn
count built from that says those 288 files changed exactly once, by one author,
on one day — and every other file in the project changed **never**. Uniform,
confident, and wrong in the direction that reads as *settled*. CI clones shallow
by default, so this is the ordinary case.

`vcs::detect` had already written the rule down, about a different question:
reporting `dirty: false` from a status query that failed "would assert a clean
tree on the strength of a check that did not run". A count of zero commits, from
a clone with no commits to show, is that sentence again. So depth is asked before
anything is counted, and the result is `History::Unavailable` carrying a reason —
two variants rather than an empty map, because an empty map is exactly what a
caller misreads.

It shows in the table too. A file absent from a history that *was* read has `0`
commits and that is a measurement; a file in a tree whose history could not be
read has `—`, because `0` there is a number nobody counted, sitting in a column a
reader scans rather than reads.

**And the same distinction was missed one case over, in this code, the next day.**
A file git has never seen is also absent from `files`, so an *untracked* file
printed `0 commits` — beside `—` for its date, contradicting itself inside one
row. `get` returns `None` for both a file with no commits in the window and a file
git has never heard of, and those are different facts: the first is a count of
zero, the second the absence of a count.

`History::knows` is the question `get` cannot answer, and both surfaces ask it
now. Three states, all measured on this repository:

| file | commits | meaning |
|---|---|---|
| tracked, changed in the window | `4` | a count |
| tracked, no commit in the window | `0` | also a count — git looked |
| untracked | `—` | git was never asked |

Found by pointing `sda hotspots` at an untracked file, which is the method that
found `sda impact` answering for a language it cannot read. **Writing the
distinction down once did not make it apply itself to the next case.** The caveat prints **above** the table rather than
below it: *NOT CHECKED* is last in a scan report because a reader must not stop
before it, but here the caveat governs the rows underneath, and saying it
afterwards would be saying it to somebody who has already read the list.

**And the other half of what repowise sells: blast radius.** `sda impact <path>
--file <rel>` lists the files naming the external symbols a file defines —
what else is downstream of a change.

**The answer is a floor, and the fixture contains the file it misses.** Reach is
found by matching identifier tokens against the names the subject defines, which
finds every caller that spells the name and misses every one that does not: a
call through a function pointer, a name the preprocessor assembles, a linker
alias, a `dlsym` lookup. The test fixture holds four files, and `indirect.c`
calls whatever `get()` returns — a real path into the subject that spells
nothing, absent from the answer by construction.

That direction is the dangerous one, and it is why this does not use repowise's
own phrasing. Over-reporting costs a reviewer an afternoon. **Under-reporting
tells them a change is contained when it is not**, and "change it safely" is
precisely the promise a blast radius is bought to make. So the output says *at
least these* and never *only these*, states it before the list rather than after,
and takes the wording from `Impact::floor_caveat` in the engine — so the MCP
surface, when it grows this, cannot render the rows without it.

When a compile database *is* present the honest answer is a different one:
`ext.clang-tidy` and `ext.codeql` resolve this with a real front end behind them
and are already wired. This is the answer available from source alone, offered as
what it is.

**A header gets a refusal that is true of headers**, which the first version did
not. `sda impact --file src/lib.h` answered *"this reads C only — C++ overloads
and templates, and Rust's modules and traits, need a front end rather than a
lexer"*. A `.h` file is C. The sentence explained something else entirely, with
the confidence of one that fits, in answer to *change this header, what breaks?*
— the likeliest question anyone brings to a blast radius.

The refusal itself is right and the reason is now the real one: `CFunction`
records a body and a declaration has none, so a declaration-only header yields no
symbols, and a search built on them would find nothing while looking like it had
looked. The message says to ask about the `.c` that defines the symbols instead.

**Headers are a real gap rather than a design decision**, and the message says so.
Supporting them means collecting declarations as well as definitions, which
`cstruct` does not expose today. Worth doing: a header is where a change's reach
is widest and where a reviewer most wants the question answered.

**And the first version of it committed the defect it was built to refuse.**
Pointed at a Rust file, `sda impact` printed *"No other file names any of them"*
— while a caller two files away called the function by name. Two things had gone
wrong and neither was visible in the output: `analyze_c` had been run over a
`.rs` file and had found `compute` in `pub fn compute(x: i32) -> i32`, a
plausible answer assembled by a parser reading a language it does not know; and
then the search covered the tree's C files, of which there were none.

Zero files searched, reported as a clean negative. **An inability to check
presented as a clean check, inside the feature whose entire selling point is
refusing that**, one commit after shipping it.

The floor caveat did not save it and could not: it explains why a list might be
*short*, and this was a list that was never built. So the subject's language is
checked before anything is parsed, `searched` is published beside
`referenced_by`, and `nothing_searched_notice` prints *before* the floor —
because a floor is a caveat about a list and this is a caveat about whether there
is one. The MCP payload carries `files_searched` for the same reason a human gets
the sentence.

Worth keeping for the next person tempted to trust a green suite: the feature had
six passing tests and a mutation-checked caveat when it shipped. None of them
pointed it at a language it could not read.

**Two of the seven tests were written wrong first**, both in the way this
document keeps describing. The shallow-clone test builds a real `--depth 1` clone
rather than describing one, and its mutation prints the number it would have
reported: *"a shallow clone produced 288 file histories"*. The CLI test asserted
a row "contains a dash" and **passed** when the commits column was turned back
into a `0` — because the `last` column carries a dash regardless. It counts three
now.

### Both new tools reach the agent, with their caveats in the payload

repowise's thesis is not that a dependency graph is interesting; it is that an
agent should be handed one instead of rediscovering it. `sda hotspots` and
`sda impact` were terminal commands, which meant the surface this toolkit
publishes to agents did not have them. `analysis.hotspots` and `analysis.impact`
do now — twenty-one tools where there were nineteen.

**The caveat is a field of the response, not a line in the description.** A tool
description is read once, by whatever assembled the list, possibly weeks before
the call. The payload is read every time and is what the agent acts on. The test
beside this one has made the argument since it was written: *"an agent cannot see
a narrowed scan the way a human reading a terminal can, so the MCP surface has to
say what it skipped in the payload itself."*

So `analysis.impact` publishes `floor: true` beside `referenced_by`, and the
reason — the function pointer, the assembled name, the linker alias — in
`not_checked`. `Impact::floor_caveat` lives in the engine precisely so this
handler could not render the rows without it, which was written down as a promise
before there was a second caller to keep it to.

**`analysis.hotspots` publishes `null`, never `0`.** When the history cannot be
read, every count in every row is JSON null and `history_available` is false. A
zero would be a number nobody counted, handed to a caller with no terminal to
read a caveat from — and `git log` succeeds on a shallow clone, so the zero would
arrive looking like a finished measurement of a settled project. Mutation-checked
by putting the zero back.

**Re-measured rather than re-labelled.** The metrics row above says the reference
client drove the surface, and it said nineteen tools, dated. Editing that number
to twenty-one would have asserted a client run that never happened — so the run
happened instead: `@modelcontextprotocol/inspector --cli` lists 21, and a
`tools/call` to `analysis.impact` comes back with `floor: true`, `compute` as the
defined symbol, `src/app.c` as the only caller, and the fixture's
function-pointer caller correctly absent. The row is dated today.

### A scan that read nothing reported a clean result

Found by pointing every subcommand at a directory it could not use — the method
that had just caught `sda impact` answering for a language it cannot read.

`sda scan` on a tree with nothing in it for any provider produced a report with
no findings, no `languages`, and nine `ext.*` notices about providers that were
not enabled. Indistinguishable from a clean scan of a real codebase, and
considerably more reassuring than one. `discover::inventory` does say `no
analyzable files found` — on **stderr**, which `--format json > report.json`
throws away. The same defect as the configuration problems that were stderr-only
until earlier in this session, and the same fix.

**The obvious condition was the wrong one.** `target.files.is_empty()` catches an
empty directory, which is the rare case. Discovery counts `.md` and `.txt` among
plenty else, so a documentation tree is *not* empty: it prints `1 md, 1 txt` —
telling the operator two files were analysed — and then reports nothing, with
nothing to say about why. That is commoner and reads worse, because the stderr
line reassures.

The condition is now *no enabled provider reads any language found here*, and the
message says which of the two happened: `no file was found under X`, or `N
file(s) were found and no enabled provider reads any of their languages`. A
reader chasing a mistyped path needs the second half.

The ways to arrive here are ordinary rather than exotic: a mistyped path, a build
directory, a scan rooted one level too deep, a tree in a language this does not
read. Each produced zero findings from nothing read, which is the most confident
possible way to say nothing.

**The planner had the quieter version of the same thing.** `sda plan` over that
tree printed `Steps:` and then nothing, and the only entry under *Not covered by
this plan* was a remark about runtime evidence — a caveat about a different
subject. `Steps:` followed by a blank reads as *there is nothing to do*; the truth
is *nothing here can be done*.

`plan.create` returns that same text over MCP, so an agent asking what to run on
a project gets an empty list and no reason for it. The line is in `Plan::render`,
which both surfaces share, and it names the languages it found: *no analysis step
applies to the language(s) found here (md, txt)*. A second test asserts a plan
with steps does not carry it, because a line on every plan is one people stop
reading.

### Sweeping the CLI's stderr for the third time

Three defects this session were the same shape: a limitation stated on stderr and
absent from the report, which `--format json > report.json` throws away. Refused
configuration, a tree nothing read, and a file that would not lex. Three is the
point at which this repository stops finding a thing by accident, so the CLI's
eighteen `eprintln!` sites were read against one question: does the report carry
what this says?

Most do, and some were fixed earlier today. One was worse than missing — it was
**wrong**.

A run given `--artifact broken.bin`, on a file that is not an executable, reports
two things:

* `sda.dynamic`: the artifact could not be launched. Correct, and already there.
* `sda.correlate`: *no runtime observation was supplied*. **False.** One was
  supplied. It failed.

The two sat in the same section, contradicting each other, and only one of them
could be right. The distinction is not pedantry: *you did not supply one* sends a
reader to build the artifact, *yours did not run* sends them to fix it. A report
carrying both sends them nowhere, and teaches them that one of these sections is
unreliable — which is expensive in the section whose whole value is that it can
be trusted.

The wording is *no runtime observation reached this run*, which is true whether
none was supplied or one failed, and `sda.dynamic` carries the cause when there
is one. Mutation-checked by putting the old sentence back.

### The discovery notice reaches all four surfaces, and one question it raised

The notice added when nothing was analysed went into `run::analyze` rather than
into the CLI, so every surface carries it without being told to. Checked, not
assumed:

| surface | carries it |
|---|---|
| text report | yes |
| `--format json` | yes |
| `--format sarif` | yes, as a tool execution notification |
| `analysis.scan` over MCP, driven by the reference client | yes |

That is the argument for putting a notice in the engine rather than in whichever
caller noticed the gap, and it is worth re-reading next time one is added a layer
too high.

**And a fidelity question it raised, left open deliberately.** Every SARIF
notification this emits is `level: "note"` — `cppcheck not enabled (native-first
policy)`, `the artifact you supplied could not be launched`, and `nothing was
analysed` alike. SARIF has four levels and this uses one, which is the same
flattening as the `did not run` wording fixed earlier today: distinct situations
collapsed into one representation.

A defensible line exists. A policy exclusion — an external tool nobody enabled —
is genuinely a note. Something the operator asked for that did not happen, or a
result that covers less than it appears to, is a warning.

**It was not changed, and the reason is worth more than the change.** A
notification's `level` is machine semantics, not prose. The earlier SARIF fix
altered a sentence; this would alter what a CI system does — and some fail a
build on a `warning`-level notification. This document records that the SARIF has
met a real consumer, which is a compatibility result that a level change could
invalidate without anything here noticing.

So: a real gap, a clear proposal, and no measurement of the consumer side
available from this machine. Whoever has a pipeline to test against should make
the change and watch what it does. Guessing at it from here would be the
confident-change-that-breaks-something-unseen this document has a table of.

### The workbench said "no baseline" about a corrupt one

The least-examined surface in the repository, read with the lens the rest of this
session used. `gui/src-tauri/src/main.rs` is 561 lines and carries the principle
explicitly, in a comment on its scan path:

> A malformed baseline is an error rather than an absent one, so it does not
> quietly become "nothing is new".

One hundred and forty lines further down, `baseline_info` — the command behind
the panel that *describes* the baseline — read the same file with `.ok()??`, so a
corrupt baseline arrived as `None`, which the UI renders as no baseline recorded.

`sda-rules` had it right the whole way: `Baseline::load` returns `Ok(None)` for
an absent file and `Err` for a malformed one, and there is a test named for
exactly that distinction. **The crate preserved it and the caller discarded it.**

The cost is not the panel. A reader told no baseline is recorded records one, and
the set of findings somebody had already accepted is gone — while the scan path,
two commands away, refuses to run against the same file.

**Both read paths in this file have now lost this distinction once**, a hundred
and forty lines apart, with the reasoning written down in between. The triage read
did it first and turned every recorded conclusion into "nobody has looked at
this". So the guard is on the class rather than either instance:
`no_store_read_in_this_file_swallows_its_error` reads the file and fails on a
`Baseline::load` or `TriageStore::load` whose error is dropped — a source-level
check, because these are `#[tauri::command]`s taking `State` and because what
keeps coming back is the shape, not the line. Calibrated by inserting one.

## Not verified

The numbered form of this list, with what each would take, is *Suggested next
steps* items 22-27. This section is the prose.

**Nothing has been executed on silicon.** An emulated Cortex-M3 now runs the
instrumented image end to end — see *A Cortex-M image that runs* below and
`examples/firmware-cortex-m/` — so the freestanding path is no longer
claim-by-construction. What that does **not** establish is anything about a real
part: no clock configuration, no flash wait states, no interrupt latency, no
brown-out, and a UART QEMU models rather than one wired to a pin. Timing and
memory behaviour on a board remain untested.

**One part of that sentence was not about silicon and has been fixed.**
`SDA_MARK("stack_bytes", 1024)` reported a number the program had been told, as
though it had been observed. The image now fills the unused stack with
`0xC0DEC0DE` after `.bss` is zeroed and before anything else runs, and reports
the lowest address still holding it — a high-water mark for the whole run. It
comes back as **632** bytes at `-O1` and **704** at `-O0`, which is the check
worth doing: a figure that moves with the compiler's frames is a measurement,
and one that does not is a constant wearing a measurement's name.

**This section was itself stale, which is the joke.** Three of the four entries
below had been closed a session earlier and went on claiming otherwise, sitting
directly under a heading that says *Not verified* and directly above one that says
what is. A reader trusting it would have re-done work, or — worse — believed the
toolkit was weaker than it is and quietly declined to rely on it. Keep this
section honest before adding to it: an out-of-date "not verified" is the same
defect as a clean check that could not check, pointed the other way.

Closed since, and moved to *What is verified*: `ext.codeql` and `ext.miri` have
both met their tools (and cost four defects between them); the C++ analyzer has
run over PX4-Autopilot's 2,270 files with zero location defects; and external
dynamic coverage refutes end to end against Memcheck 3.24.0 and gcov 14.2.0.

**PX4 is built, its database is real, and it has now been used — from Linux.**
The submodules are initialised and PX4's SITL configuration completes in WSL,
emitting a `compile_commands.json` of 744 entries covering 4.3% of the tree,
because a board configuration compiles one board. What it describes is a *Linux*
toolchain: `/usr/bin/c++`, and generated headers under `/home/test/px4-build`
that the Windows analyzer cannot reach.

That entry used to end "the remaining step is a Linux `sda`", and **it was stale
within hours of being written** — the Linux build landed later the same day, in
the next commit but one. Exactly what the paragraph above this one warns about,
in the section that carries the warning. See *This session's changes, against
twenty thousand files* for the dates.

Done now, and measured rather than assumed:

| run | `ext.clang-tidy` findings |
|---|---:|
| Linux `sda`, with the SITL database | **81** |
| the same directory, no database | **0**, and the provider refuses |

The 81 are `misc-header-include-cycle` across `src/lib/matrix/**` — headers
reached *transitively through the database's include paths*, which a run without
it cannot see at all. That is the difference type-awareness makes, on a
cross-built project, next to the build that produced it.

The second row matters as much. Without a database the provider does not return
zero and look clean: it reports itself unavailable — *"this tool needs a
compile_commands.json to resolve types"* — and the run carries that in
*NOT CHECKED*. The central principle, on a real cross-built tree.

**What this does not establish**, since the temptation is to round it up: one
module was scanned, not the tree. The database covered 3 of its 4 C/C++ sources
and the report named the fourth. Scanning PX4 whole this way is slow for a dull
reason — the sources sit on `/mnt/c` and WSL reads them over 9p — so the honest
next step is a checkout inside the Linux filesystem, not a bigger timeout.

### What installing the real tools found

Recorded in detail because it is the strongest available argument for installing
the next one.

**ModelScan — the adapter could not have parsed a single real run.** The
reconstruction had every *per-issue* field right (`description`, `operator`,
`source`, `scanner`, `severity`). Everything around them was wrong:
`total_issues`, `modelscan_version`, `timestamp` and `input_path` are nested
under `summary`, not top-level; two lines of progress chatter precede the JSON;
and the fatal one — **ModelScan renders its JSON through `rich`, which hard-wraps
at 80 columns even when redirected to a file, breaking lines in the middle of
string literals.** Its stdout is not valid JSON and cannot be made valid by
skipping a prefix. A fixture-passing, self-scanning, fully green adapter that
could not read one byte of what the tool emits.

The fix is the `{output}` placeholder: the adapter names a temp file, the tool
writes a clean report into it, and the adapter reads the file instead of a
stream. An **empty report file is now a failure**, not a clean scan — every JSON
parser here returns "no findings" for empty input, so a tool that created its
report and died before writing would be indistinguishable from a clean run. That
was observed once and never reproduced, which is the worst kind of bug to leave
unguarded.

**Cppcheck — correct as written**, the first adapter to survive the encounter
unchanged. Its real output carried three shapes the reconstruction lacked:
several `<location>` elements per error (the first is the defect, the rest are
the trail), `<symbol>` children, and `checkersReport`, an entry with **no
location at all** emitted on every run. The parser dropped location-less entries
silently; it now falls back to the `file0` translation unit first, so a real
error without a location survives while the metadata still does not.

**Semgrep — two defects of a kind already fixed for other adapters.**

* **Every real Semgrep finding arrived as `Medium`.** Semgrep omits `level` on
  its results, and SARIF says the severity then comes from the rule's
  `defaultConfiguration.level`. The parser had a comment saying exactly that, and
  then defaulted to `Medium` anyway — an `error` rule and a `note` were
  indistinguishable. It now looks the rule up by `ruleId`, since Semgrep emits no
  `ruleIndex` and an index-only lookup found nothing.
* **No Semgrep finding carried a CWE**, so none could ever be *confirmed* by
  runtime evidence — the same defect fixed for Cppcheck one adapter over. Semgrep
  states it in `properties.tags` as `CWE-78: ...`. Verified live: that finding
  went from `medium` with no taxonomy to `high` with `CWE-78`.

Both fixes are in `parse_sarif`, so `ext.codeql` inherits them.

Two things to know before trusting a quiet Semgrep run. **Its OSS rule set found
nothing in C** — 1074 rules loaded, zero results on a file with a live buffer
overflow, uninitialised read and memory leak, all of which Cppcheck found
immediately. The adapter declares C/C++/Rust support and that is true of the
*engine*, not of the free rules. And its banner says "only git-tracked", which
reads as "untracked files are skipped"; it is not what happens —
`--use-git-ignore` excludes untracked files *that gitignore matches*, the same
intent as this toolkit's own skip list, so it was left alone.

**Valgrind — the one to watch, and its parser passed.** This adapter shipped with
four defects and had never once been run. Against Memcheck 3.24.0, on a program
written to commit exactly three sins, all three parsed correctly on the first
attempt: the invalid write at the store rather than at Valgrind's `malloc`
interceptor, the uninitialised conditional jump, and the leak at its allocation
site, each with the right CWE, and the `LEAK SUMMARY` block not double-counted
against the loss record it summarises. That is worth as much as a defect would
have been — it says the four earlier fixes were fixes and not just changes.

**But driving it end to end found two more defects, which a parser test never
could have.**

* **Every external adapter's findings were `AnalysisPhase::Static`** — Valgrind's
  and Miri's included. `parse::finding` sees text, not the spec, so it cannot
  know, and nothing downstream set it either. `run::analyze` sorts findings onto
  the static or dynamic side of correlation by exactly that field, and its own
  comment claims the provider's declared kind decides. It did not. A Memcheck
  invalid-write — witnessed in a running process — was filed as a static
  suspicion, and so could never serve as the runtime evidence that confirms one.
  The adapter now stamps the phase from `spec.kind`.
* **A failed artifact launch aborted the entire scan.** `--artifact` runs the
  native dynamic engine, and `engine.observe()?` propagated, so handing it a
  Linux binary threw away the completed static analysis *and* every external
  adapter queued behind it. The inverse of this codebase's rule is still the
  rule: an inability to check must not be presented as a clean check, and must
  not destroy the checks that did succeed. The run now continues static-only with
  a *NOT CHECKED* entry naming the launch failure.

Both were preconditions for correlation rather than correlation itself, which is
why the gap survived them — see *External dynamic evidence confirms static
findings*, which took four more.

## The failure mode this codebase keeps having

Worth internalising before changing anything. **One hundred and thirty-two defects are the same
shape**: the code knew something one layer down and threw the knowledge away on
the way to the user, so an *inability to check* was presented as a *clean check*.

| Where | What it said | What was true |
|---|---|---|
| **`Position::new(0, 12)`** | line 0 is not a line, so use line 1 | Monaco discards the column too and goes to the document start; the column survived, putting the finding eleven columns in |
| **`Position::clamped`** | Monaco's `validatePosition` | two independent clamps, and no surrogate step — a caret could sit inside an astral character |
| **`Range::clamped`** | Monaco's `validateRange` | each end clamped alone: pulled inward over a surrogate pair instead of expanding outward, so a highlight ended mid-character |
| **`RuntimeEventKind::from_cwe`** | the CWE an external tool reports becomes the matching event kind | three CWEs its own forward map claims were missing, so a CWE-502 witness became a sanitizer report and confirmed nothing |
| **`RunOptions::timeout_secs`** | "wall-clock budget for the whole provider, in seconds" | read by nothing; a caller who set a budget got an unbounded run and no indication of it |
| **`RunOptions::settings`** | provider settings, with `get`/`set` and a worked example in the doc | consumed by nothing, and the example names a setting that has never existed |
| **`RustLexed::unterminated_block_comments`** | the lexer records every unclosed `/*` | read by nothing outside its own tests, so a Rust file behind one left the scan with no finding and no notice — checked nowhere, reported nowhere |
| **`SDA-C-LEXICAL`** | "every structural finding in this file is now suspect" | they were absent, not suspect — an unclosed comment on line 1 took all three of a file's findings, and *NOT CHECKED* did not name the file |
| **`report.query`** | `matched`, the number of findings matching the query | counted after the 200 cap, so a query selecting 500 answered `200` — to an agent, which cannot glance at a summary to catch it |
| **`render_text`** | a list of findings, then the counts | the list stopped at five hundred and said nothing; 800 findings became 500 lines, with the difference left for the reader to notice |
| **SARIF notifications** | "provider `X` did not run" | true of the nine absent external tools and false of the six others in the same list, which had run and reached no conclusion — asserted in the format a CI system parses |
| **`interposition::summarize`** | "not checked — no model reaches a declared effector by any declared path" | a claim about models and paths, printed for a declaration that named no model at all; nothing else in the run said so |
| **`paths.is_empty()`** | a model/effector pair with nothing between them is nothing to prove | reported as neither an obligation nor a notice, so a flow section missing an edge looked exactly like a system where the model cannot reach the effector |
| **`the_workspace_test_count…`** | it would say the document was stale and which number to fix | on exactly that case `stated - functions` underflowed, so it panicked `attempt to subtract with overflow` and named neither figure |
| **`ProjectConfig::problems`** | "never silently swallowed: a deviation register that failed to load must not look like a project with no deviations" | swallowed from the *report*: every problem was an stderr `warning:` and nothing more, so a saved JSON run whose architecture component had been rejected carried no trace of it |
| **`RustItem::attributes`** | "attributes written immediately above this item" | never written to; every item carried an empty list, so `#[test]` and `#[no_mangle]` read as absent everywhere |
| **MISRA 5.1** | external identifiers are distinct | only functions were compared; two file-scope objects colliding within 31 characters read clean |
| **MISRA 21.2** | no reserved identifier is declared | same: `int _Claimed_object = 0;` was never looked at |
| **`refuseStaleBinary`** | the workbench binary is current | it aged the binary against the *frontend* only; `sda-editor` changed underneath it and the guard that exists for exactly this went on passing |
| **The "measured" column** | every figure was taken this session | most were inherited from an earlier one; the label was true when written and false the moment the document was restructured |
| **MISRA C++ 8.2.1** | no C-style cast is used | `is_c_style_cast` refused any `(` preceded by `return`, before ever checking the contents for a type — so the place a cast most often sits in C++ was the one place the rule could not look |
| **`RUST-2024-PANIC.2`** | "panic! unreachable! todo! and unimplemented!" | the check also flags `assert!`, `assert_eq!` and `assert_ne!`, so a user told they violated that rule for writing `assert_eq!` was told something untrue |
| **`mod latest { … }`** | test code, so a panic in it is intentional | the rule matched any `mod` whose name *contained* "test"; `latest`, `attestation`, `testbed` all silently excused every panic inside them |
| **`#[test] fn` at file scope** | production code | it is a unit test — the canonical way to write one; its own doc comment claimed this case was handled |
| **`#[cfg(test)] mod checks`** | production code | the canonical idiom whenever the module is not literally named `tests` |
| **`sda.ai.artifact` locations** | a file, like every other provider reports it | absolute, not relative to the target root: a baseline that cannot match on another machine, and the scanner's own directory layout in the report |
| **`SDA_MARK("stack_bytes", 1024)`** | the image used 1024 bytes of stack | nothing measured it; the figure was a constant the program had been told, and the real high-water mark is 632 |
| **`scan --compile-commands`** | a database was supplied, so type-aware analysis is configured | only the file's *existence* was checked; one covering none of the tree — built in a container, or under WSL, where entries read `/mnt/c/...` — was accepted in silence |
| **MISRA 8.2** | every function is in prototype form | the check read `CStructure::functions`, which holds *definitions*; a prototype in a header — where 8.2 matters most — was never looked at |
| **MISRA 11.9** | `NULL` is the only null pointer constant used | only the `(void *)0` cast was checked; `int *head = 0;`, the common form, read clean |
| **MISRA 12.3** | the comma operator is not used | only `if`/`while`/`switch` conditions were scanned; `for (i = 0; i < n; i++, other++)` read clean |
| **MISRA 13.4** | no assignment result is used | only an assignment at the *outermost* level of a condition; `if ((b = g(a)) != 0)` read clean |
| **MISRA 5.1, marked `native`** | a clean result means external identifiers are distinct | the guideline is `system` scope; the check compares the functions of one file, so a link-time collision between two files is invisible |
| **MISRA D4.5, marked `native`** | a clean result means no ambiguous identifier pair | same: `lookup1` in one file and `l00kup1` in another are never compared |
| **MISRA D4.4, marked `native`** | a clean D4.4 result is evidence of conformance | the guideline is marked **undecidable** in the same catalogue entry, which the enum documents as "a clean result is not a proof" |
| **MISRA 12.1, marked `native`** | a clean 12.1 result is evidence of conformance | the check covered two operator pairs of an open-ended guideline; `sizeof cmd - strlen(cmd)` read clean |
| **The C++ lexer on `a<::b`** | the digraph `<:`, then `:` | `<` then `::`; `std::vector<::Foo>` lexed as `vector[:Foo>` |
| **The Rust lexer on `c"s"`** | the identifier `c`, then a string | one C string literal, stable since 1.77 |
| **The Rust lexer on `1.0e-3`** | `1.0e`, `-`, `3` | one float; the `-` was an operator that is not there |
| **The Rust lexer on `r#fn`** | `r`, `#`, and the **keyword** `fn` | one raw identifier, which exists to stop that reading |
| **The Rust lexer on `café`** | `caf` and an unknown byte | one identifier; Unicode names are legal since 1.53 |
| **The Monaco port's line count** | a three-line C file has three lines | Monaco says four; a trailing newline opens one |
| **The Monaco port's columns** | UTF-16 code units, per its own doc | characters; every column past an emoji short by one |
| **`Stickiness`** | three distinct edge behaviours | two: the start edge was never consulted, and two doc comments were inverted |
| **SARIF `$schema`** | a URL naming the 2.1.0 schema | 404 since the repo renamed its branch; every file we emitted cited nothing |
| **SARIF locations** | a file and a line | the engine had the source and the exporter dropped it |
| **A quiet dynamic tool, with coverage** | *nothing at all* | Memcheck ran and found nothing; 492 findings read as `refuted` with no tool named |
| **`sda build compile-commands`** | *Generating done*, exit 0 | no database written; CMake ignores the export flag for the Visual Studio generator |
| **A failed build command** | `CMakeTestCCompiler.cmake:65` | the reason was six lines further down; stderr was cut to its first five |
| **`--observation` unreached lines** | `executions = 0` | nothing measured them; hand-placed probes leave most lines unmeasured |
| **clang-tidy `note:` lines** | 307 findings, rule id `note` | continuations of the diagnostic above, whose trail they were removed from |
| **cppcheck's own limits** | 321 `information` findings | the tool saying it could not resolve 288 includes; NOT CHECKED stayed empty |
| **`ExternalAdapter::timeout`** | a ten-minute default | never read; `analyze` called `output()`, which waits forever |
| Build diagnostics | "the build produced no diagnostics" | build failed; MSVC output parsed as GCC-like |
| Correlation | "`x.c:12` was never executed" | line had no probe; the file demonstrably ran |
| Fuzzer | "a 1-byte input reproduces it" (critical) | replayed 5×, exit 0 in 30 ms |
| Probe suite | "1 probe ran and 0 fired" | divergence probe had no baseline; nothing measured |
| External adapter | *silence*, exit 0 | `clang-tidy` printed usage and analysed nothing |
| Shim | "cross-compiles clean" | objects don't resolve symbols; it didn't link |
| Availability probe | "`ext.miri` — installed" | `cargo miri` exits 1; only `cargo` was probed |
| Provider dedup | "2 findings" | one lint, emitted twice by `--all-targets` |
| Valgrind adapter | *silence*, 0 findings | output declared `GccLike`; memcheck emits none of it |
| Valgrind arguments | — | handed the project *directory* as the program to execute |
| `--artifact` | — | never reached `Target::artifact`; no external dynamic adapter could see it |
| ModelScan adapter | *parse error* | output declared `Sarif`; ModelScan emits its own JSON |
| Rust analyzer | "16 findings in `tests/`" | integration tests are test code; only `mod tests` was recognised |
| Glyph margin | one marker on the line | three findings there; two silently discarded |
| Glyph CSS | classes requested per finding | no rule for any of them existed; the margin drew nothing |
| **`sda-probe`'s own test harness** | "repeat hits aggregate: left 0, right 2" | the stream never opened; `.ok()` disabled the session, so every emitter no-opped |
| **ModelScan, again** | fixture passes, adapter ships green | real stdout is `rich`-wrapped mid-string; no real run could ever have parsed |
| **Empty report file** | a clean scan | the tool died before writing; every JSON parser reads empty as "no findings" |
| **SARIF severity** | every Semgrep finding "medium" | Semgrep omits `level`; the rule's `defaultConfiguration` said `error`, never read |
| **SARIF taxonomy** | Semgrep findings with no CWE | the CWE is in `properties.tags`; without it none could ever be runtime-confirmed |
| **Cppcheck location-less errors** | dropped silently | fine for `checkersReport` metadata, but a real error with no `<location>` vanished too |
| **External dynamic findings** | phase `static` | Valgrind *executed the program*; a witnessed defect was filed as a suspicion |
| **A failed artifact launch** | *the whole report* | the completed static analysis was discarded because the dynamic engine could not start |
| **External dynamic witness** | *no correlation at all* | phase was right and CWEs matched; the witness carried no runtime *event*, so relatedness could not be established |
| **The two weakness tables** | `from_cwe(416) = MemoryError` | `MemoryError` did not relate back to 416; identical CWEs on both sides, and no confirmation |
| **A quiet dynamic tool** | "this is a static-only result" | Valgrind executed the program and reported clean; the run was not static, and the tool was not named |
| **`ext.valgrind` absent** | "not found on PATH" | the harness `.bat` was LF-only UTF-8; `cmd` died on its own comment while Valgrind worked |
| **`misra-evidence-tiers.py`** | `13.6` is compared against cppcheck | cppcheck has never reported `13.6`; the tool counted a guideline as compared when *either* side fired it, so this engine's own finding stood in for the oracle's |
| **The MISRA C++ standing** | `twelve of twenty-one` compared | fourteen; `5.7.1` and `5.7.2` are compared by the clang test, and the count was taken from the clang-tidy fixture alone |
| **The C++ sentence's "and two others"** | nine rules left, seven named | seven left; the two were a phrase written where a number should have been, and did not exist |
| **The Rust standing** | `nine` compared, `eight` left | eight and nine; the arithmetic added to seventeen either way, and `UNSAFE.3` was in neither the compared set nor the list |
| **The first version of the count test** | the standing claims are now checked | it read the sentence naming the rules left over and never the count beside it, so `Fourteen` -> `Thirteen` passed green |
| **The verification instructions** | `cargo test --workspace` prints `803` tests across `41` binaries | 923 across 62; the baseline a reader checks a regression against was two hundred and eighty tests low, in two places |
| **The summary table's test count** | `919` across 62 binaries | 921, then 923; one session behind, and the row nobody rereads |
| **`Clippy is installed`** | `clippy 0.1.97` | `0.1.98`, which the committed clippy fixtures already recorded |
| **The MCP surface** | `tools/list` publishes `16` tools | 19; the same document said 19 four hundred lines away |
| **`tools_list_publishes_every_tool_with_a_schema`** | the published surface is checked | it asserted `>= 14` against a surface of nineteen, so five tools could vanish between definition and wire |
| **`DeviationRegister::apply`** | `expires` is the date after which a record "no longer applies" | it filtered on rule and scope alone, so a lapsed acceptance suppressed its finding forever; `is_expired` and `expired()` existed, were unit-tested, and were never called |
| **The first unused-deviation notice** | this record is dead weight | six of them were about `shim/sda_probe.h` during a scan of `crates`, a file that run never opened — an absence of evidence reported as evidence of absence, printed by the section that exists to prevent it |
| **The second unused-deviation notice** | this record is dead weight | `clippy::needless_range_loop` matched nothing because `ext.clippy` never ran; that says everything about the run and nothing about the record |
| **`a_tool_that_finishes_keeps_every_byte_it_wrote`** | a finishing tool keeps its output | it generated 200 kB with `cmd /C for /L ... @echo`, taking 86 s of a 120 s timeout on an *idle* machine, and failing whenever the suite ran in parallel |
| **`correlate::coverage_gaps`** | a coverage hole "belongs on a different work queue" | it was on no queue at all: nothing called it, so no report ever showed a coverage gap to anyone |
| **`coverage_gaps`, again** | these lines were flagged and never reached | it zipped `correlations[i]` with `findings[i]`; a suppressed finding produces no correlation, so after the first approved deviation every gap named the wrong line — including a line whose departure had already been accepted |
| **The sweep that found them** | 1 uncalled public function of 654 | 88; it anchored on `pub` while matching the name seven characters later, so every definition counted as its own caller and only generic functions escaped |
| **The sweep, second calibration** | five tool parsers are called by nothing | all five are wired at `lib.rs:868`; an *indented* `#[cfg(test)]` at line 275 made the sweep read the rest of the file as test code |
| **A project catalogue override** | the project's own rule text is in force | `catalog()` dropped the read error and the import error; a malformed `.sda/misra-c-2023.toml` left the built-in catalogue silently in place and `rules audit` described a catalogue the project had tried to replace |
| **The workbench's triage read** | these findings are unreviewed | `TriageStore::load(..).unwrap_or_default()` turned a corrupt review file into an empty one, so recorded conclusions vanished and a finding already dismissed once came back as untouched |
| **`stale_triage`** | no recorded conclusion has gone stale | it returned an empty list when the store could not be read — a claim about review state, made by a call that could not read it |
| **Both native analyzers** | these are the findings for your tree | `read_to_string(..)?` per file, so one source that is not valid UTF-8 — a Latin-1 `©` in a copyright line — failed the whole provider; four findings on a two-file tree became zero |
| **`check_manifest`** | ED2024.5 and DEP.3 were checked | an unreadable `Cargo.toml` returned no findings and said nothing, so two rules decided nowhere else silently did not run |
| **`a_provider_error_becomes_an_exclusion_not_a_clean_result`** | a failing provider is reported | it produced its failure by pointing the C provider at a missing file; fixing the per-file behaviour left the provider-failure path with no coverage at all, since no stub in the module returned `Err` |
| **`UNSAFE.3`** | this crate needs no `unsafe`, so declare `#![forbid(unsafe_code)]` | decided from `lib.rs` alone, so a crate whose *modules* use `unsafe` was told to add a crate-wide attribute that would not compile |
| **The rule fixtures** | every native rule fires, and is checked | they are positive-only: each proves a rule fires on violating code, and nothing proves any rule stays silent on code that does not violate it |
| **The first calibration of the near-miss test** | the assertion bites | it was aimed at `12.1`, which is `partial` and does not fire on an unparenthesised expression either, so a genuinely violating source left the test green |
| **`D4.9`** | a function would serve in place of this macro | it read only `if function_like`, so `#define STRINGIFY(x) #x` was told to become a function — and `#` cannot be written in one |
| **`FFI.1`** | every extern declaration documents its contract | it judged the *block*, not the declarations, and accepted any comment within three lines above — so one block comment covered several undocumented declarations, while documenting each one where it is written did not count |
| **`8.2.3`** | `const_cast` was used to remove const qualification | it fired on the token, so a cast that *adds* const — which the guideline permits — was reported against it, putting a deviation for an unviolated rule into a conformance argument |
| **The `21.*` library checks** | this call reaches a standard library function | they looked only at the token *after* the identifier, so `b.signal(1)`, `logger.printf(..)` and `pool.free(..)` were all reported as library calls |
| **`DEP.2`** | this file is a build script Cargo executes | it asked only whether the file is named `build.rs`; one under `src/` is an ordinary module Cargo never runs |
| **The `21.*` checks, again** | this declaration uses a library facility | a name followed by `(` was read as a call, so `struct Bus { void signal(int); };` reported `<csignal>` in a header with no call in it |
| **The first declaration guard** | declarations are not calls | its identifier fallback matched `return`, so `return system(cmd);` read as a declaration and a live `21.21` went silent — caught by cppcheck, not by any near-miss |
| **The document's own test count** | every count claim in `HANDOFF.md` is checked | the walk that counts `#[test]` functions stopped at `crates/`, so the GUI backend row — a separate crate the gate runs as its own step — was outside every check, and read **16** for eighteen days after a seventeenth test was added |
| **`tools/verify.sh`, again** | these tests failed | the linker gave up on an over-grown program database (`LNK1140`), which prints `error: could not compile` exactly as a type error does, so the gate reported **FAILED: workspace tests** about a tree whose tests it had never run |
| **The single-file scan** | this file could not be read, and here is which one | paths are reported relative to the target root, and scanning one file makes the root *equal to* the file, so the exclusion read ``` `` was discovered as a source file and could not be read``` — the refusal was right and named nothing |
| **`sda.discovery`** | nothing was found under this path | a path that does not exist got the empty-directory sentence, which describes looking inside a place, and advice about which languages the toolkit reads — a typo sent somewhere else. The test file named “a mistyped path” twice in prose and asserted it nowhere |
| **`sda plan`** | no analysis step applies here, and why | the reason was a noun-phrase slot, and the no-language branch filled it with a clause: *No analysis step applies to no recognised language was found*. The one sentence that has to be read carefully was the one that did not parse |
| **`sda hotspots`** | these are the files worth looking at first | it ran the same `analyze` a scan does, read `report.findings`, and dropped `report.exclusions` — so a scan that read nothing printed a heading, a true remark about git, and an empty ranking |
| **`analysis.baseline`** | this is the accepted state of the project | `set: true` recorded a baseline from whatever the scan returned, so a mistyped path wrote the empty set into `.sda/baseline.toml` and every later run reported nothing new against it — the only failure of this kind here that does not expire |
| **Four `analyze` callers** | here is what the scan found | each computed a report for part of an answer, rendered that part, and dropped `report.exclusions`. Found one at a time over two sessions, which is the argument for checking the class instead of the instance |
| **`sda hotspots`, again** | these are the files worth looking at first | it ran its own discovery and never applied the declared scope, so it analyzed and ranked files the project had formally excluded. On a tree excluding `legacy/`: the scan reported 4 findings in `src/`, the ranking reported 12 and put the worst excluded file **first** |
| **`sda plan`, again** | this is what the run will do | it planned over the unscoped tree, so a project whose only C++ was excluded got `Languages: c, cpp` and a second step the scan would never run. The MCP copy of the same command had applied scope since it was written, with the reason in a comment |
| **`fuzz` and `ai scan`** | this is what was analyzed | both ran their own discovery and never applied the declared scope: verdicts about files the scan refuses to report on, and digests for artifacts under an excluded directory |
| **`sda hotspots`, a third time** | these files carry the most findings | it built its `RunConfig` from `default()`, so the deviation register never reached it and formally accepted findings were counted as live. Two files of four live findings each ranked **8** against **4**, the deviated one first |
| **`fuzz` and `fuzz.campaign`** | the campaign confirmed or refuted these findings | neither loaded the deviation register, so nothing was marked suppressed and `correlate`'s refusal to re-raise a settled finding never fired. `project_setup` already existed, and its doc comment already said why |
| **`--fail-on`** | this build passed the gate | a mistyped path produced zero findings, `gate: no findings at or above low`, and **exit 0** — the trap the README records about `verus` exiting 0 on a failed proof, in this toolkit's own gate and in the one output a pipeline consumes |
| **The SARIF invocation** | this run succeeded, and here are some notes | `executionSuccessful` was hardcoded `true` and every notification was `note`, so a run that read nothing exited **3** and told a SARIF consumer it had gone fine — the same run saying two different things to two machines |
| **The `blocked` list** | these items need things this project does not have | three of its four entries had stopped being true — one refuted in a file written to refute it, one contradicted by the item it summarises, one an already-fixed defect filed as open work behind a hardware blocker |
| **`report.query`** | this stored report matched nothing | it loaded a report and published its findings while dropping its exclusions, so a stored scan carrying eleven caveats — the first that every count in it is a count of nothing — came back as `matched: 0` with none of them |
| **A commit on 2026-09-16** | the suite passed | `cargo test --workspace` and `git commit` on one line with nothing between them: exit 101 and two failures went past while the commit succeeded, for the third time in one session |

The pattern: a narrow check (parse succeeded, count is zero, exit code ignored,
object compiled) stands in for a broad claim (nothing wrong here). The fixes are
all the same shape too — distinguish *measured and clean* from *could not
measure*, and say the second out loud.

**The `sda-probe` row is the one to read twice.** It is not in the product at
all. It is in the *test harness of the crate whose entire job is recording what
actually happened at runtime*, and it presented the failure as a specific,
plausible, wholly fictional bug in the code under test — anyone chasing that
message would have gone looking in `flush_coverage`. A `%TEMP%` directory left
with an empty DACL made every open fail; `rebind` used `.ok()`, so a failed open
became `out: None`, which disables the session, which makes every emitter a
silent no-op. It now opens before taking the lock, `unwrap`s, and asserts
`is_enabled()` before a test may emit. The guard was then verified the only way
that means anything — by stripping the DACL again and confirming the failure
names itself. **This pattern does not stay in the parts of a codebase you are
watching.**

**The last four rows are one feature**, and they compound in a way worth
studying: the phase was fixed, then the evidence was missing; the evidence was
added, then the two weakness tables disagreed; the tables were reconciled, then
correlation was never reached; correlation was reached, and then a *clean* run
misreported itself. Each fix was real and each left the user-visible behaviour
exactly as wrong as before. **Nothing short of running it to the end would have
found any of them**, and four of the five checks along the way were green.

**Most of these were found by doing nothing cleverer than running the thing.**
The suggested next step "exercise more adapters" has now paid for itself many
times over, and every one of these had been sitting in a shipped, tested,
self-scanning codebase.

The four earlier Valgrind rows are one adapter that had never once been run, and
they compound the same way: its arguments named a directory where a program was
wanted, there was no `{artifact}` placeholder with which to write the template
correctly, `--artifact` never populated `Target::artifact` anyway, and even given
all that its output format was declared `GccLike` — which matches not one line
Memcheck emits. Four separate breaks in a row, each individually invisible,
because *nothing had ever asked the adapter to produce a finding*. A spec that
compiles and a spec that works are different claims, and the type system checks
only the first.

The consolation is that the honest-failure work held. The adapter did not report
a clean run; it said "exited with 1 and produced no findings, so this run
establishes nothing about what it checks" — exactly what was true, and what made
the defect findable in one command instead of never.

When you add a provider, a checker, or a report field, the question to ask is not
"does it work" but **"what does it print when it cannot work, and does that read
as success?"**

### The structural fix, and the one test to keep

`crates/sda-adapters/tests/every_adapter_parses.rs` is the answer to this whole
class. Each spec has a recorded sample of its tool's real output, run through
`parse_output_channels` — *the same dispatch the adapter uses* — and asserted to produce a
stated number of findings, at a stated rule, file and line, with the sample's
worst severity intact. A spec with no fixture fails the suite, so adding an
adapter means adding one.

Three things about it are deliberate and worth preserving:

* It was **checked against the bug it exists for**. Reverting `ext.valgrind` to
  `GccLike` makes it fail with "declared GccLike, parsed its tool's real output,
  and found nothing"; removing a fixture entry makes the completeness test name
  the uncovered adapter. A guard that has never been seen to fail is not known to
  work.
* It asserts **location and severity**, not just a non-zero count. A parser that
  returns the right number of findings while mislocating all of them is the next
  version of this bug, and a count alone would pass it.
* Its fixtures are now **captured, not reconstructed**. That upgrade is what
  turned it from a test of our beliefs into a test of the tools.

Note what it still cannot catch: it proves a parser, not a pipeline. Every one of
the four correlation defects above lived downstream of `parse_output_channels`, in a green
suite, with this test passing.

### The instinct to be suspicious of

One of the rows above was found because a *new test file* tripped the toolkit's
own self-scan: 16 findings in `every_adapter_parses.rs`, every `assert!` a
production panic site and every fixture filename a shipped model artifact. The
tempting fix is a deviation entry, and it would have been wrong. The analyzer
recognised test code only as `mod tests { … }`, which an integration test does
not have, because Cargo says the whole file is test code by virtue of living in
`tests/`. That is not a quirk of this repository — it is what the analyzer would
say about any Rust project with a `tests/` directory, which is most of them. Same
for `MODEL.1`, which did not exempt test lines while `MODEL.3` did.

Both are fixed in the analyzer, and both fixes ship with a **negative** test
asserting the same code under `src/` is still reported. That pairing is the
point: without it, "the self-scan is clean again" is indistinguishable from
having quietly switched two rules off to make one's own code pass.

## Verifying the instrument

**Verify the instrument before trusting the reading.** Several wrong conclusions
came from bad measurement, not bad code:

* Querying `.view-line` when Monaco renders decorations in `view-overlays`.
* A regex where `\bsda-info\b` matched `sda-info-glyph`.
* A `Select-String` that is case-insensitive by default, so `0 failed` matched
  `FAILED`.
* A PowerShell string where `` `x8c `` produced a literal `x`.
* Piping `cargo test --workspace` through `tail` before capturing it, then
  counting "passed" in the capture and getting 2 out of 556 — the filter ran
  before the record, not after it.
* `grep -iE 'failed'` over the log, which matches every `0 failed` line and so
  reports failures in a run that had none. **Count the total and assert it,
  rather than grepping for the absence of a word.**
* `wsl -- bash -lc '... echo $?'` from Git Bash reports the **outer** shell's
  status, because Git Bash expands `$?` before the string reaches Linux. It read
  a clean `0` twice from a Valgrind run that had actually exited `1`; the tell
  was a sibling `$ec` coming back empty. Escape it (`\$?`) or use a script file.
  The same applies to `${PIPESTATUS[0]}`, which came back empty for the same
  reason.
* A Windows path passed through `wslpath` from Git Bash loses its backslashes to
  shell escaping before `wslpath` ever sees them. Build the `/mnt/c/...` path
  directly instead of translating one.
* **A `.bat` harness that `cmd` cannot parse reports the tool it wraps as
  absent.** Nothing about the message points at the file. See *External dynamic evidence confirms
  static findings*.

The last two are the pattern in miniature: the instrument was measuring itself,
and it looked exactly like a result.

## Design decisions worth preserving

Kept because the *reasoning* is the part that would be expensive to rediscover.

### Scope is not a deviation

`.sda/scope.toml` declares what is **not part of the delivered product**;
`.sda/deviations.toml` records **accepted violations**. A deviation says "this
rule is violated and we accept it"; scope says "this rule does not apply, because
this file is not in the product". MISRA draws that distinction and a compliance
report has to keep it — collapsing them would let a project make its report clean
by declaring its problems out of scope, indistinguishable from a project that
genuinely ships less code.

This began as a claim that the C analyzer had "the same defect" as the Rust one —
a C test harness scanned as firmware. **It does not, and the difference matters
more than the original observation.** The Rust exemption follows from a fact about
the build system: Cargo compiles `tests/` only for `cargo test`, so nothing there
ships. There is no equivalent fact in C. A file under `tests/` may be delivered,
MISRA applies to delivered source, and a tool that skipped it on the strength of
a directory name would be silently narrowing a compliance scan while still
calling the result clean. "Consistency with the Rust fix" would have been the
argument that talked someone into it. *The same symptom in two languages is not
the same defect*, and a fix justified by symmetry rather than by a fact about the
language is worth distrusting.

Three judgement calls in what shipped:

* **Matching is prefix-on-segment-boundaries, not `DeviationScope::Path`'s
  `contains`** — a deliberate break from the original design, which said to reuse
  the existing matcher rather than invent a second path dialect. `contains` is
  wrong here: a rule reading `tests/` would also match `src/unittests/parser.c`.
  A deviation that matches too much over-reports an accepted violation; a scope
  rule that matches too much **deletes evidence**. The asymmetry in consequence
  justifies the asymmetry in matching, and a test pins it.
* **Filtering is at discovery** (`discover::apply_scope`), so no analyzer ever
  sees an excluded file. Filtering findings afterwards would let coverage and
  correlation be computed over files the report then claims it did not read.
* **Paths are relative to the declaration, not to the scan root.** `.sda/` is
  found by searching *upward*, so the two differ the moment anyone scans a
  subdirectory, and matching against the scan root made a rule silently stop
  applying while the report still said it had been honoured. The anchor is
  `ProjectConfig::root()`; a file outside it is left **in** scope rather than
  matched against its full path, because a rule reading `tools` would otherwise
  exclude anything whose absolute path passes through a directory of that name.
* **The count is the safety property.** Each rule produces an `Exclusion` under
  provider `sda.scope` stating how many files it removed. "`tests/` excluded"
  invites the reader to assume the directory was empty; "2 files under `tests/`"
  cannot be misread. A rule that removed *nothing* says which of three things
  happened — it names nothing in the project (stale), it lies outside this scan,
  or it was scanned and holds no analyzable file — because once rules are anchored
  at the project, "does not apply here" is the common case and calling all three
  "stale" teaches the reader to skip the message.
  Validation matches the deviation register's: `reason` and `approver` required
  and non-empty, rejected rules reported rather than honoured, a malformed file a
  problem rather than an empty scope, and a rule resolving to the root rejected
  outright.

**The trap, recorded because it nearly repeated itself.** This feature's whole
purpose is to make findings not appear — the exact shape of every defect in the
table above. Three call paths build a run: the CLI, the workbench, and the MCP
surface. `.sda/deviations.toml` was once honoured by the first and ignored by the
second, and a scope file diverging the same way would remove *files* rather than
annotate findings. So `project_setup` and `target_for` return the target
alongside the config, making it impossible to analyse an unscoped target with a
scoped configuration; and `ai.scan_model` no longer answers "no model artifacts
were found" when scope is why it found none.

All three paths reach correlation through `run::analyze`, which is the only
caller of `correlate`. Check that this is still true before adding a fourth.

### Never measured is not measured-and-empty

`correlate` takes `Option<&Observation>`, and the `Option` is the whole point.

* `Some(Observation::default())` — execution **was measured** and nothing was
  recorded. That is a coverage hole, a static finding on such a line is
  `Unreached`, and it belongs on the test-suite work queue.
* `None` — execution was **never measured**. Valgrind ran the program and
  reported its faults; it counts no lines and never will.

The two are the same empty data and mean opposite things. Collapsing them is the
tempting fix — pass `&Observation::default()` and everything compiles, and
confirmation even works — but it manufactures a claim about the *code* out of a
fact about the *instrument*: every unconfirmed finding is reported as a line no
run reached, on the strength of a tool that was never going to say. So under
`None`, confirmation works (a witness is a witness) while `Refuted` and
`Unreached` are simply unavailable, and the report states in *NOT CHECKED* that
no line's execution was measured. `coverage_gaps` stays empty rather than
inventing a hole nothing looked for.

Putting it in the type system rather than a policy flag is deliberate: this is a
fact about the run, not tuning, and it is the distinction the whole codebase is
about — *measured and clean* versus *could not measure*. A `bool` on
`CorrelationPolicy` would have sat beside `refutation_threshold` and read as
something a user might tune.

Both directions are pinned by tests, and both were **checked by breaking them**:
collapsing `None` into an empty `Observation` makes
`measured_and_empty_is_not_the_same_as_never_measured` and its sibling fail by
name.

### A witness must state its weakness class

Confirmation is the strongest claim this toolkit makes, and it rests on
`same_defect_class` — proximity is necessary and not sufficient, because a bounds
fault two lines away does not confirm an advisory about typedef width.

An external dynamic tool does not speak `RuntimeEventKind`; it reports a defect
and names a CWE. `RuntimeEventKind::from_cwe` is that translation, and it returns
`Option` **on purpose**: a CWE it does not know yields `None`, not a guess. The
adapter then labels the event `SanitizerReport` — the honest bucket for "a
dynamic checking tool reported this", and the same one the native ASan path uses
— rather than inventing a specific weakness class the tool never claimed.

The inverse map, `related_weaknesses`, is deliberately *broader* than a bijection
(`Crash` relates to many classes, because a crash can be almost anything), so the
two tables are not simply inverses of each other. But one invariant must hold:
**every CWE the forward map knows must relate back to itself**, or a tool's own
stated CWE fails to confirm a static finding carrying that identical CWE. That is
`every_weakness_class_confirms_its_own_cwe`, and it walks the whole range rather
than a written-down list so the two cannot drift again.

### One glyph per line, decided once

Monaco draws one glyph per line, so three findings on line 42 asked for three
glyphs in one margin cell, drew one, and discarded the other two with no rule
about which survived — a critical could sit invisibly behind an info. The policy
lives in `crates/sda-editor/src/markers.rs`, not in a shell, because *which
finding owns a shared line* is an analysis judgement: a runtime-confirmed defect
outranks a higher raw severity, an approved deviation never hides a live finding,
a line of nothing but deviations is a deviated line. Two shells answering it
separately would draw different pictures of one report. **The editor crate
decides what a marker says; the shell decides how it looks.**

That also deleted the shell's duplicate ranking, which ranked *CSS class names*
and so could not tell `Critical` from `High`, both being `sda-error`. Relatedly,
`UiFinding` carries `confirmed` explicitly rather than the shell recovering it
from `css_class`: a class is a *rendering* of a fact, and recovering a fact from
its rendering is lossy the moment two facts produce one class — a finding both
witnessed at runtime and covered by a deviation renders as suppressed, and its
confirmation silently vanished.

### A byte offset is not a line

`Location` carries `byte_start`/`byte_end` because a pickle opcode has a position
and it is an offset. A model finding is located at the offset it *already cited
as evidence* — `ScanCx::push` reads it out of the `Evidence::ModelArtifact` it is
about to attach, so location and evidence cannot disagree, which is precisely how
they got out of step before (`model.pkl:1:1` beside "offset 4128"). Rendering
follows: `path@0x11a` in text, a SARIF `byteOffset`/`byteLength` region with **no**
`startLine`, and `diagnostics_for` skips byte-located findings entirely — claiming
line 1 told every SARIF consumer to highlight the first line of a file with no
lines, and put a pickle's opcode on line 1 of whatever text buffer was open.

### Spans only where the information exists

Token extents are taken wherever a tool states them — SARIF `region` ends,
rustc's `line_end`/`column_end`, cppcheck's XML — and **`dynamic::span_against_source`
deliberately refuses to span a finding whose column is 1**, because the probe
stream has no column field and the parser writes 1 there. Bracketing the line's
first token would be a confident claim about text nothing measured. Formats that
state no extent still report a point.

## Suggested next steps

**Items 1-21 are all closed.** They are kept struck through rather than deleted
because the reasoning in them is most of what this file is for — several were
closed by discovering the instruction itself was wrong, and that is the part worth
reading. **What is actually open is 22 onward.**

Two of those are blocked on things this project does not have rather than on
effort, and the rest are the gaps the oracles left, each stated where the oracle
that found them lives.

22. **Nothing has run on silicon.** Item 1 closed the *never executed* gap with
    QEMU; a real part is a different claim. No clock configuration, no flash wait
    states, no interrupt latency, no brown-out, and a UART the emulator models
    rather than one wired to a pin. `examples/firmware-cortex-m/` is ready to
    flash: it needs a board, a programmer, and a UART capture fed to
    `sda scan --observation`.

    **The stack figure was the part of this that was never blocked**, and this
    entry went on saying it was. It read that `stack_bytes` reports a number the
    program was told rather than one it measured, *worth fixing when there is a
    real stack to measure* — and it had already been fixed, under QEMU, with the
    high-water mark painted and scanned the way embedded systems have always
    done it. The failure-mode table two thousand lines above records the fix and
    the figure. This list went on offering the same defect as open work, filed
    under an item marked *blocked on hardware*, which is the most effective way
    to stop anyone looking at it.

    Re-measured while writing this, rather than copied from the table: a fresh
    build and QEMU run reports **632 bytes**, which is what the table says. What
    remains blocked here is only the claim about silicon — interrupt frames from
    a real NVIC, a vendor startup path, a different optimisation level. An
    open-work list is a derived value like any other, and *blocked* is the label
    on it that nothing ever re-reads.

23. ~~**PX4 is still scanned rather than built.**~~ **Built. The submodules were
    the blocker and are no longer; what the build produced is a database this
    machine cannot use, and the reason is worth more than the database.**

    All 21 submodules initialised (NuttX alone is 219 MB), and PX4's SITL
    configuration completes in WSL Debian — cmake 3.31.6, gcc 14.2.0,
    `-G "Unix Makefiles"` because that Debian has no ninja, PX4's Python
    generators in a venv, 747 seconds of configure. It emits a real
    `compile_commands.json`: **744 entries**, 697 `.cpp`, 46 `.c`, 1 `.cxx`.

    **The first useful number: it covers 538 of the 12,463 C/C++ sources in the
    tree — 4.3%.** A board configuration compiles one board. The rest is the
    other twenty-odd boards, the simulation bridges, vendored submodule code and
    tests, and no compilation database will ever describe them all at once. That
    is not a defect; it is what "type-aware analysis of PX4" actually costs, and
    it had never been measured.

    **The second: a database is a description of a toolchain, not just a list of
    files.** This one names `/usr/bin/c++` as the compiler, and 204 of its
    entries are *generated* sources under `/home/test/px4-build` that exist only
    on the Linux side. Rewriting `/mnt/c/...` to `C:/...` makes the 540
    host-visible entries resolve — that is where 538 comes from — and gets no
    further: clang-tidy 21.1.6 given the rewritten database dies with
    `LLVM ERROR: Cannot chdir into "/home/test/px4-build/src/lib/adsb"`, because
    the entry's working directory is where the generated headers are. Copying
    the build tree across would still leave `/usr/include`.

    ~~**The remaining step is a Linux `sda`, which needs a Rust toolchain in
    WSL — a fresh install rather than a fetch.**~~ **Done, and both halves of that
    sentence were wrong.** Rust was already installed in that Debian; `sda`
    builds for Linux in ninety seconds, 4.8 MB, and it is the first time this
    toolkit has been built for anything but Windows.

    **And running it there corrected the paragraph above.** Coverage from the
    machine that produced the database, with the database exactly as the build
    wrote it, is **538 of 12,463 — identical to the rewritten-database run on
    Windows.** So the 4.3% was never about path format: the path rewrite had
    already recovered all of it, and the limit is the board configuration alone.
    What the clang-tidy crash showed is narrower than it first appeared — it is
    about the *build tree* directories an external tool wants to `chdir` into,
    not about coverage.

    Item 12's third gap (dynamic evidence at PX4 scale) is still open. Neither
    clang-tidy nor cppcheck was installed in that Debian, so external providers
    at that scale needed an apt install that had not been asked for. **Both are
    installed now** — see *External providers on Linux, and a gap closed by
    asking*. Note what that sentence did and did not say: `wsl -u root` needs no
    password, so this was never blocked on credentials, only on consent.

    **And it has now been used, which is what the item was for.** A Linux `sda`
    against that database, on `src/modules/control_allocator/ControlAllocation`:
    `ext.clang-tidy` returns **81 findings with the database and 0 without**,
    where the no-database run refuses outright — *"this tool needs a
    compile_commands.json to resolve types"* — and carries that refusal in *NOT
    CHECKED* rather than returning a clean zero. The findings are
    `misc-header-include-cycle` across `src/lib/matrix/**`: headers reached
    *through the database's include paths*, which a run without it cannot see at
    all. The numbers are in *Not verified*, which carries the table, and in the
    metrics table above, dated.

    That is consistent with the narrowing above rather than in tension with it.
    clang-tidy runs here; what it could not do was `chdir` into build-tree
    directories at whole-tree scope. One module is not the tree, and the honest
    next step is a checkout inside the Linux filesystem — the sources sit on
    `/mnt/c` and WSL reads them over 9p, which is slow for a dull reason rather
    than a deep one.

    **What this cost on the way in, and it is the better half of the item:**
    `sda scan --compile-commands` checked that the file *existed* and nothing
    more. Handed this database it reported 744 entries covering **0** of 12,463
    files, and said nothing at all — the run looked exactly like one with no
    database, except that the operator believed type-aware analysis had become
    possible. Found by testing the instrument on a synthetic WSL-path database
    *before* the real one finished building. See the failure-mode table.

24. ~~**The Monaco comparison stops at the buffer.**~~ **Done, and the reason it
    was thought impossible was wrong.** This item said `TextModel`'s validating
    layer "needs a DOM and Monaco's dependency-injection container". The DOM is
    not needed — no position code touches it — and the container turned out to be
    three small stubs: an undo-redo service, a language service and a language
    configuration service, none of which the compared methods ever call.
    `gui/tools/monaco-model-oracle.mjs` constructs a **real `TextModel`** in node
    and asks it; `crates/sda-editor/tests/model_layer_agrees_with_monaco.rs`
    compares. Hermetic, like every other Monaco oracle here.

    **Three defects, and they compound.**

    * **`Position::new` clamped `0` up to `1` on construction.** That looks
      defensive and is not: it made line 0 unrepresentable, so `clamped` could
      never see it. Monaco sends a position above the document to the very start
      and one below it to the very end, *discarding the column*, because a caret
      off the document has no column to keep. A finding arriving at line 0
      column 12 — which is what an off-by-one in an external tool produces —
      landed eleven columns into line 1 instead of at the start of the file.
      `Position::new` now holds what it is given, as Monaco's own `Position`
      does, and validation happens where the line lengths are known.
    * **`Position::clamped` was two independent clamps.** Monaco's
      `_validatePosition` is ordered: out-of-range line first, and the column
      does not survive it. Same root cause as above, in the other half.
    * **There are two validation modes and this port had one.** `getOffsetAt`
      validates `Relaxed`; `validatePosition` additionally moves a column that
      lands between the halves of an astral character back before the pair.
      `clamped` is now the second and `clamped_relaxed` the first, and
      `offset_of` uses the relaxed one — measuring where a position is must not
      move it.
    * **`Range::clamped` validated each end on its own.** Monaco's
      `validateRange` validates both ends relaxed and then **expands outward**
      over any surrogate pair an end would split, never inward; an empty range is
      *moved* rather than expanded, because expanding it would turn a caret into
      a selection. Clamping the ends separately pulls an end backwards into the
      middle of the range and can collapse it — on a line with an emoji before
      the finding, the workbench drew a highlight one code unit short and ending
      inside a character.

    Watched failing: with the surrogate expansion disabled, `(1,3,1,3)` on the
    astral case validates to itself instead of `(1,2,1,2)`.

    Still uncovered there: everything that genuinely does need a DOM. Two items
    this list used to name are not gaps, as checked on 2026-11-03: the port has
    no `modifyPosition` to compare, and `TextModel::tokens` is a thin wrap over
    the C and Rust lexers, which have clang and rustc as oracles, with no caller
    in the workspace. Monaco's Monarch tokenizer is a different lexer, so
    comparing with it would measure the difference between two grammars.

25. ~~**Neither lexer oracle covers directives or attributes.**~~ **Done, and
    the attribute half cost a defect.**
    C directives now have one — their *extent*, which is the part a hand-written
    rule gets wrong, derived from clang's own `[StartOfLine]` flags rather than
    from the splice rule restated in a test. See *How far a directive reaches,
    according to clang*. It passed on eleven cases.

    Rust **attributes** still have none. `#[...]` is captured whole here and
    tokenized by rustc, and the same trick does not transfer: `rustc_lexer` has no
    logical-line flag, because Rust has no line splices. Comparing would need syn,
    which parses attributes into structure rather than reporting their extent.

26. ~~**`rstruct` has no oracle at all.**~~ **Done, and it held.** `syn` now
    checks the `unsafe { }` regions and the top-level item kinds; the brace walk
    survives a `}` in a string, a character literal, either kind of comment and a
    raw string, because it walks *code tokens* and compares token text rather
    than scanning source. Watched failing against the naive form. See
    *`rstruct` has met syn, and the brace walk holds*.

    Item spans are covered too, since 2026-11-03:
    `item_spans_agree_with_syn.rs` compares every top-level item's kind, start
    line and body-end line with syn's. Written by an agent, it agreed on the
    existing corpus and noted that `body_end_line` took the first `{` or `;` it
    met. Two corpus cases confirmed that on the old code: `use a::{..};`,
    `const`/`static` initialisers with a struct literal all reported the
    line of an inner `}`, and `fn f(x: [u8; 4]) { }` and `fn g() -> [u8; 2] { }`
    lost their body end at the array length's `;`. Fixed by kind (those items
    never have a body) and by ignoring `;` and `{` inside `( )` and `[ ]`. The
    one reader in the workspace is the `#[cfg(test)]` module extent, which a
    module cannot trip, so no finding was wrong; the public field was. With
    that, kinds, item spans, the unsafe regions, the attributes and (in
    `panics_agree_with_syn.rs`, see *What counts as test code*) `PanicSite`
    all have syn as an oracle. syn also parses only valid Rust, so nothing says what either side
    does with input that does not compile.

    **The attribute half is closed, by a different route than this item
    imagined.** It said the clang trick "does not transfer", which is true — and
    irrelevant, because syn parses attributes and `rstruct` already had syn as an
    oracle. What the comparison found was not a wrong extent but an empty one:
    `RustItem::attributes` was a public field, documented as "attributes written
    immediately above this item", that **nothing ever wrote to**. Every item
    carried an empty list. A consumer asking whether a function is `#[test]` or
    `#[no_mangle]` was told no, for all of them.

    `attach_attributes` now fills it, positionally, the way the language does: an
    attribute applies to the next item and only whitespace and comments may
    stand between. `crates/sda-syntax/tests/attributes_agree_with_syn.rs`
    compares attribute *paths* per item against syn — the argument text is
    formatting, and syn normalises it while this crate keeps it verbatim — over
    nine new corpus cases aimed at where a positional attacher goes wrong: a `]`
    inside a string inside an attribute, an inner `#![...]` above an item, a
    comment between an attribute and its item, an attribute spanning several
    lines, and an unattributed item directly after an attributed one. Watched
    failing with the gap check disabled, where a `derive` leaks onto the `fn`
    below.

    **One difference is recorded rather than resolved:** syn turns `/// text`
    into a synthesised `#[doc = " text"]` attribute and this crate lexes it as a
    comment, which it is. Neither reading is wrong, so the comparison keeps only
    attributes whose source actually begins with `#`.

27. ~~**The MISRA rule *implementations* have never been checked against the
    guidelines.**~~ **Done, as far as it can be done without the document.** The
    normative text is still licensed and absent, so the paraphrases in
    `crates/sda-rules/data/` remain unverified against it. What is now checked is
    the second-best thing: cppcheck's MISRA addon, which reports rule numbers
    without the licensed texts, fires the same set of guidelines on the corpus
    except the ones this toolkit *declares* it cannot check. See *MISRA, against
    a second implementation*.

      ~~**Growing the corpus is the cheapest defect-finding move left.**~~ **Done,
    and it was.** `tools/misra-corpus/` is eleven files written from the guideline
    *titles* — not from the checks, which would have produced a corpus that
    agrees by construction — aimed at the **61 guidelines both tools implement**.
    Fifteen files now, reaching about fifty guidelines. It cost seven defects;
    see *MISRA, against a second implementation*.
    `examples/firmware-cortex-m/src/main.c` still cannot join them, because
    cppcheck 2.21.0 cannot parse GCC explicit register variables.

    Still open there: the `21.6`-on-`#include` reading, which needs the document;
    the line anchors the two choose differently, deliberately not compared; and
    **an audit of the coverage classification itself** — 12.1 will not be the
    only open-ended guideline marked `native`, and nothing checks that claim
    except a second implementation happening to disagree.


1. ~~**Run on hardware.**~~ **Done under emulation, and the instruction was
   wrong about the last step.** A freestanding Cortex-M3 image built from
   `shim/sda_probe.h` with `SDA_PROBE_NO_FLOAT` and a UART sink now runs on an
   emulated Stellaris LM3S6965 under `qemu-system-arm` 10.0.11 and the engine
   correlates what it emitted. `examples/firmware-cortex-m/` holds the image, the
   linker script and the build-and-run script; the capture is pinned as
   `crates/sda-engine/tests/fixtures/qemu-lm3s6965-cortex-m3.jsonl` behind
   `hardware_capture_correlates.rs`.

   **There was no way to feed a captured probe stream in.** This item said to use
   `sda scan --artifact`; `--artifact` *executes* a program, which is the one
   thing a host cannot do with firmware. `--coverage` takes LCOV and gcov, and
   `--probe-responses` is the AI probe surface. So the toolkit's central embedded
   claim had no ingestion path at all, and the item that named it as the top
   priority had been read many times without anyone noticing. New
   `--observation <FILE>`, which is the case where the program ran on a board,
   under an emulator, or on another machine, and all that came back is what the
   shim wrote.

   **It cost a defect, in the usual shape.** Fourteen of the fifteen findings
   came back `unreached` carrying `executions = 0` — a *metric*, asserting a
   count nobody had taken. The rationale beside it has always said the honest
   thing ("produced no coverage record … either it did not execute or it is not
   instrumented"), so the prose half was right and the structured half, which is
   the half a machine reads, was not. Probe instrumentation is hand-placed, so
   almost every line of a shim-instrumented program is unmeasured rather than
   measured-at-zero; nothing had made that distinction visible before because
   every previous dynamic run used gcov or LCOV, where a zero **is** a
   measurement. `Observation::measured` now separates them and correlation emits
   a note instead of a fabricated count.

   **What is still not closed.** No silicon: no clock setup, no flash wait
   states, no interrupt latency, and a UART QEMU models rather than one wired to
   a pin. One target, one toolchain.
2. ~~**Give the external dynamic path coverage, so it can refute.**~~ **Done,
   and driven end to end.** `--coverage` (LCOV `.info` and gcov `.gcov`, not
   callgrind — its cost column is instructions retired, not executions) was
   already wired and its parsers were already tested against real gcov 14.2.0 and
   LCOV 2.0-1 output. What had never happened was the whole path in one run. It
   now has: `sda scan examples/coverage --with ext.valgrind --artifact ...    --coverage examples/coverage/build` reports **confirmed 2, refuted 1,
   unreached 4, inconclusive 3** against Memcheck 3.24.0 and gcov 14.2.0, with no
   SDA instrumentation anywhere in it. Captured as
   `crates/sda-engine/tests/external_dynamic_refutes.rs` plus a real Memcheck
   fixture, and documented in `tools/coverage-wsl/README.md` — a path
   `examples/coverage/main.c` had been citing for a directory that did not exist.

   Two traps found by doing it. `gcov` invoked where it cannot read the source
   writes a well-formed file with no records while printing
   `Lines executed:66.67% of 15` — a coverage report that parses, measures
   nothing, and looks right on screen; the existing empty-report guard caught it.
   And `--artifact` must be an *absolute* Windows path or the WSL harness's
   `wslpath` translation is skipped and Valgrind exits 127; the adapter reported
   that as a provider that failed rather than one that ran clean, which is how it
   was noticed.
3. ~~**`ext.codeql` is the last reconstructed fixture.** Assume CodeQL's is wrong
   until a real database says otherwise.~~ **Done, and the pessimism was
   justified.** CodeQL 2.26.4 was installed and run (`tools/codeql-taint/`), and
   it found two defects: `parse_sarif` never read `codeFlows` at all, and CodeQL
   writes CWEs as `external/cwe/cwe-078` where the tag reader only knew
   `CWE-78:`, so no real CodeQL finding could ever have been *confirmed*.

   The running tally is now **ten of eleven real-tool encounters found a defect,
   eight in adapters that were fully green** — `ext.miri` was wrong about the
   stream, the format and the toolchain at once, and `ext.codeql`'s own invocation
   was wrong about what `-` means. Treat that as the base rate, not as a run of
   bad luck. Every adapter has now met its tool; the rule generalises to the next
   *change*, not just the next adapter.

   `ext.codeql.txt` itself is *still* a reconstruction. But the C++ `codeFlows`
   result this asked for now exists: `tools/codeql-taint-cpp/` and
   `crates/sda-engine/tests/fixtures/codeql-2.26.4-cpp-taint.sarif`, from
   `cpp/command-line-injection` over a C++ program with the same four components
   as the Python one. It cost two more defects — see item 10 and *Recent
   changes*.
4. ~~**`ext.miri` has never been run.**~~ **Done, and it cost three defects.**
   The instruction here was also stale: nightly was already installed, and
   `rustup component add miri --toolchain nightly` succeeds. `sda scan <crate>
   --with ext.miri` now reports a stacked-borrows violation at `src/lib.rs:11:9`,
   high, `confidence certain`, `dynamic`. See *Recent changes*.

   It arrives as `unpredicted` rather than `confirmed`, and that is correct
   rather than a gap: the native `UNSAFE.1` finding is on the `unsafe` block at
   line 8 and the violation is the read at line 11, so nothing was confirmed and
   the report says a dynamic tool found something no static rule anticipated.
   Whether an `unsafe` *block* should carry the span of its contents is a real
   question, and a separate one — do not fix it by loosening correlation to match
   on nearness, which is the thing `same_defect_class` exists to stop.
5. ~~**Watch for other `rich`-rendered tools.**~~ **Discharged for the current
   adapter set, and mechanized for the next one.** The ModelScan defect was not a
   ModelScan bug — it is what `rich` does to any Python CLI that prints JSON
   through it, and it survives redirection, which is why it looked safe. Semgrep,
   also Python, writes clean SARIF, so it is not universal either.

   The population at risk is small and now enumerated: of the nine shipped
   adapters, exactly two wrap a Python CLI (`semgrep`, `modelscan`), and both have
   been captured from real runs. The rest wrap C++, Rust or native binaries.

   Rather than leave it as a caution nobody re-reads, fixture provenance is now
   **data** — `Provenance::Captured(version)` or `Reconstructed` on every entry in
   `every_adapter_parses.rs` — with three tests over it: a Python-CLI adapter may
   not rest on a reconstruction, the reconstructed set must be exactly
   `["ext.codeql"]`, and a capture must name its version. Verified to fail when
   flipped, rather than assumed to work. Adding an adapter now forces the
   question instead of inviting a comment.
6. ~~**Run the C++ analyzer against a large real C++ codebase.**~~ **Done, and it
   held.** PX4-Autopilot (`src/`, 1,625 `.cpp`/`.hpp` and 645 `.c`/`.h`, commit
   `e90e8ae0ea`): **14,284 findings across 68 rules in 1,305 files**, no crash, no
   hang. 17 MISRA C++:2023 rules fired for 5,777 findings — the first time the
   C++ analyzer has seen a real codebase — alongside 49 MISRA C rules and the two
   native complexity checks.

   **Zero location defects.** Every finding was checked against the file it names:
   no line past end-of-file, no column past end-of-line, no inverted span. That is
   the class of bug this run was most likely to expose and it exposed none.

   Spot-checks were all true positives, including two that discriminate: the
   analyzer flagged `#define static_assert` in `o1heap.c` — where the line above
   it reads *"Intentional violation of MISRA"* — and it did **not** mistake
   `#ifndef ADC_CHANNELS` in the middle of `ADC.hpp` for an include guard, while
   correctly reporting that the header has none.

   Timing, release build, warm: **2.3-2.7 s for 2,270 files**, about a millisecond
   each, and the debug and release runs produce byte-identical finding ids.

   What it did *not* cover: this is the file-oriented path only. Nothing here
   built PX4, so no external provider, no compilation database, and no dynamic
   evidence — those remain untested at this scale.
7. ~~**Housekeeping.** The repository root holds `m.c`, `main.c`, `p`, `prog`
   and `vg.txt`.~~ **Done, and the instruction was wrong about one file.**
   `main.c` was the source the `ext.valgrind` fixture was recorded from — its
   assertions name lines 5, 6, 12 and 17-19 of it — so deleting it would have
   left a captured fixture with no reproducible source, which is how a fixture
   quietly becomes a reconstruction again. It lives at
   `tools/valgrind-wsl/three-sins/main.c`, basename intact because the fixture's
   stack frames say so. The other four were genuine junk and are gone.

8. ~~**Wire the neurosymbolic checks into `sda scan`.**~~ **Done.** `RunConfig`
   carries the declaration and `run::analyze` runs both engines, so all four run
   paths get it at once — CLI, workbench, MCP `analysis.scan`, and MCP
   `analysis.statodynamic`, which discovers no project config at all and still
   does not (it has no deviations or catalogues either; that gap is now the
   remaining one). See *Recent changes* for the two judgements it needed.

9. ~~**Re-run the GUI harness.**~~ **Done, and it passes** — glyphs and squiggle
   count agree with the CLI.

   **Correction.** This item previously claimed the pass had been "re-verified
   after the correlation and C-parser changes, including two consecutive cold
   starts". It had not: the harness was resolving a binary from 12 August, so
   those runs tested none of this session's work. See *Recent changes*. The claim
   above now rests on runs against a binary built by the Tauri CLI from current
   sources, with the harness refusing anything older than the frontend.

   **The harness itself had a defect, and it took three diagnoses to get right.**
   The first run after a fresh build reliably failed with `FINDINGS 0`, then
   passed on every run after. It was written off first as a slow scan, then as a
   stale build artifact. It was neither: `window.__sda` and the Scan button both
   exist before the app is necessarily listening to them, so the click landed on
   nothing and the harness went on to fail two steps later on the file it never
   listed — which reads as a decoration defect and is not one.

   The fix confirms the click by a **positive** signal and retries until it takes.
   An intermediate version compared the status against a snapshot taken at
   readiness and was fooled by the app settling into its idle text a moment later
   — *"different from before"* is not the same claim as *"the thing happened"*,
   which is the same distinction this codebase makes about coverage. The app
   writes `scanning...`, `scan complete: N` or `scan failed: ...`, all of which
   start with "scan", while the idle text does not.

10. ~~**A `codeFlows` fixture from a second producer.**~~ **Done, and the
    prediction was right twice over.** CodeQL 2.26.4 over `tools/codeql-taint-cpp/`
    — the C++ twin of the Python program — exposed two defects in code that was
    green, documented, and had a reason written next to it.

    **Three code flows, and the first one crosses the guard.** The Python result
    carries one `codeFlow`; the C++ result carries three, ordered
    guarded / bypass / guarded. `parse_sarif` read `codeFlows[0]` and
    `taint_bypasses` read the first `Trace` on the finding, each documented as
    deliberate — "additional ones are alternative routes, and a consumer that
    needs every route needs the SARIF". That is right for rendering and wrong for
    refutation, which is what the traces are *for*: interposition fails if **any**
    route reaches the effector unguarded, so keeping one route made the verdict
    depend on emission order. The engine would have reported a clean proof from a
    report containing its own counterexample. Both layers now keep every flow, and
    bypasses that reduce to the same component path are deduplicated — the C++
    result's first and third flows differ only by a step through a system header.

    **The flow does not start inside the model.** CodeQL's Python source is
    `request` in `policy/serve.py`, so that trace began in the neural component,
    and `taint_bypasses` required exactly that. The C++ source is `argv`, entering
    at `main`, outside every declared component — so the same claim arrived as a
    trace the check skipped in silence. Refutation now anchors on the *last visit
    to a neural component*, which is what the claim actually says; what happens
    before the model is how data reached it, a different question.

    Neither is visible from the SARIF specification. Both needed a second output
    that exercised a shape the first did not have — which is exactly what this
    item said, and it applied to the analysis as much as to the parser.

11. ~~**`analysis.statodynamic` over MCP discovers no project configuration.**~~
    **Done.** Both MCP scan paths now go through one `project_setup`, which
    discovers the project once and returns the target, a project registry and a
    configured `RunConfig` — catalogues, deviations, scope and architecture
    together. An agent calling `analysis.statodynamic` no longer sees findings a
    human running `sda scan` has suppressed.

    Shared rather than repeated, for the reason the defect existed: the two call
    sites drifted precisely while nobody was comparing them, and neither report
    could reveal it alone — each is internally consistent and neither states what
    it was configured with. `crates/sda-agent/tests/mcp_paths_agree.rs` compares
    them, and was checked by restoring the old body and watching it fail.

12. ~~**PX4 was scanned, not built.**~~ **All three gaps discharged, none of them
    with PX4.** The 2,270-file run is the file-oriented path
    only: no compilation database, no external provider, no dynamic evidence. The
    C engine's `compile_commands.json` path, `ext.cppcheck` and `ext.clang-tidy`
    at that scale, and correlation over a real embedded binary are all still
    untested against anything that large.

    **Properly blocked, and worse than it looks.** PX4's submodules are not
    initialised in the local checkout (`git submodule status` shows every entry
    prefixed `-`, and `src/lib/cdrstream/cyclonedds` and friends are empty
    directories), so building it means a large fetch *into someone else's
    repository* plus the ARM toolchain. That is a change to a checkout this
    project does not own, which is why it was left alone rather than attempted.

    **Partially discharged from a different direction.** An external provider has
    now been run over a whole real workspace: `sda scan crates --with ext.clippy`
    — 77 Rust files across twelve crates — returns 19 findings over 13 lints,
    **all distinct**. That last word is the point: `cargo clippy --all-targets`
    compiles every crate twice, once as itself and once as its test harness, and
    emits every diagnostic for both. The de-duplication that was added for a
    nine-line program holds on a real workspace, which is the thing scale was
    going to break. It also confirms `cargo` walks up to the workspace manifest,
    so the adapter's reliance on `current_dir` rather than a `{manifest}` argument
    is sound for the repository's own documented self-scan command.

    **Discharged from a third direction, and PX4 was never the only route.** The
    three uncovered things were a compilation database, a C or C++ external tool,
    and dynamic evidence — all at scale. Two of the three are now done against
    `llama.cpp/src`: 184 real C++ files, someone else's checkout, **read only**.

    * **A C++ external tool at scale.** cppcheck 2.21.0 over those 184 files:
      **1,453 findings in about four minutes**, every id distinct, no crash and
      no hang. The 47 pairs sharing a `(file, line, rule)` were checked and are
      genuinely different — five uninitialised members reported at one
      constructor's line — so the de-duplication is not collapsing real findings
      either.
    * **A compilation database at scale, and clang-tidy on it.** 217 entries for
      llama.cpp, from `cmake -S <repo> -B <scratchpad> -G "NMake Makefiles"
      -DCMAKE_EXPORT_COMPILE_COMMANDS=ON`, configured **out of tree** so the
      checkout is untouched. That is the ordinary way to build and the only way
      to build a repository you must not write into — and it is exactly the case
      the toolkit could not see.

      clang-tidy then ran against it: **7,752 findings over 201 files in about
      36 minutes**, every id distinct. The decisive detail is that llama.cpp has
      its own `.clang-tidy`, and only its checks fired — `misc-include-cleaner`
      alone is 6,992 of the findings, which is llama.cpp's choice and not ours.
      The default-check-set *substitution* therefore holds at scale, which is the
      thing this run was most likely to break: had the injected default been
      appended rather than substituted, the project's own configuration would
      have been diluted by ours on every file.

    * **Dynamic evidence at scale.** `bibutils` — 105 C files, a real
      bibliography-format converter — built under WSL with `--coverage`, its own
      unit tests plus five converter binaries run, 59 gcov listings covering
      **11,060 measured lines of which 2,903 executed**, and Memcheck executing
      the program through `tools/valgrind-wsl/`. The scan returns **6,881
      findings and 6,881 correlations: unreached 5,501, inconclusive 888,
      refuted 492**, in nine seconds.

      This is the shape the toolkit is for. A quarter of the code was exercised,
      so three quarters of the findings are *untested* rather than clean, and the
      report says which is which — with the caveat that the counts come from the
      run that produced them and not provably from the run Memcheck inspected.

    All three of item 12's gaps are therefore discharged, none of them with PX4,
    whose submodules are still uninitialised.

    **It cost six defects, and the first two are the same one at different
    layers.**

    * **A tool's account of its own degraded analysis was filed as findings.**
      321 of the 1,453 — 22% — were `missingIncludeSystem`, `missingInclude`,
      `toomanyconfigs` and `normalCheckLevelMaxBranches`: cppcheck saying it
      could not resolve 288 includes and had analysed 12 of 17 preprocessor
      configurations in one file. It was right, and it mattered — those results
      were produced with incomplete information. As findings they achieved the
      reverse of what they say: all are `information` severity, so the first
      thing anyone does with a report that size, raise the floor to `medium`,
      discards them and what remains reads as a completed analysis. Meanwhile
      *NOT CHECKED* — the section this repository built precisely so an inability
      to check cannot be mistaken for a clean check — said nothing, because
      nothing had told it. New `Analyzer::take_notices`, drained in
      `run::analyze` so the CLI, the workbench and both MCP paths get it at once.
    * **There was no way to point at a compilation database.**
      `find_compile_commands` looks in five fixed places beneath the scan root,
      so an out-of-tree build is invisible and every type-aware provider reports
      itself as needing a database that exists. New `--compile-commands <FILE>`,
      which overrides discovery rather than supplementing it and says so when the
      two disagree.
    * **307 `note:` lines were being reported as findings.** clang-tidy emits a
      diagnostic and then continuation lines — the call frame, the "declared
      here", the macro expansion trail — and `parse_gcc_like` turned each into a
      standalone finding with the rule id `note`, which is not a rule. Two harms
      at once: 4% of the report was phantom, and *the trail was detached from the
      diagnostic it explains*, so a `bugprone-exception-escape` lost its frames
      while seven unrelated "findings" appeared inside MSVC's `<map>`. Notes are
      now evidence on the finding above them; an orphan note is dropped, because
      it is the second half of a sentence whose first half is not there.

      The captured fixture's expected count went from 5 to 3 — it had been
      pinning the defect. A count that goes *down* is allowed only when the
      report got more accurate, which is exactly this.
    * **A dynamic tool that ran and found nothing went unnamed whenever coverage
      was supplied.** The report has said "X executed the program and reported no
      defects. That is not a clean bill of health" since a Memcheck run exposed
      the need for it — but only in the branch that fires when there is *no*
      observation, and `--coverage` creates one. So the bibutils scan returned
      492 findings marked `refuted` with nothing anywhere saying which dynamic
      tool had looked, or that one had. "Refuted" then reads as stronger evidence
      than it is.

      That is a row already in the failure-mode table, reintroduced through the
      door the coverage seam opened. Who executed the program is a fact about the
      run and is now stated unconditionally. The test was watched failing against
      the old code; the existing test for the same property had to be loosened
      from "this notice contains the name" to "some notice does", because it was
      pinning an implementation rather than the property.
    * **59 near-identical provenance paragraphs.** gcov writes one `.gcov` per
      translation unit, so `--coverage <dir>` is the ordinary case, and the
      per-file notice put 59 copies of the same sentence into *NOT CHECKED* —
      the one section of the report that must be read — each naming a long
      absolute path and burying the two entries that mattered. Now one notice
      with the totals: `provenance_of_many`.
    * **`ExternalAdapter::timeout` was never read.** A public field, defaulting
      to ten minutes, whose entire purpose is to bound a hung tool — and `analyze`
      called `Command::output()`, which waits forever. Invisible for as long as
      every adapter run was over a handful of files. `run_with_timeout` now
      enforces it, draining both pipes on their own threads because a child that
      fills its stdout pipe blocks until someone reads it, and cppcheck emits
      megabytes of XML on a real tree.

      **The first version of that fix was wrong, and the test caught it rather
      than the reasoning.** It joined the reader threads after killing the child,
      and killing a `.bat` wrapper kills `cmd` while the grandchild keeps the
      write end of the pipe — so `TimedOut` was reported after 59.6 seconds
      against a 0.4-second deadline. This repository ships exactly such a
      wrapper: `tools/valgrind-wsl/valgrind-wsl.bat`.

      A limit that fires on ordinary work is worse than none, because the honest
      "it was stopped, so this establishes nothing" becomes the normal outcome
      and people learn to skip it. Hence `--tool-timeout <SECONDS>`, and the
      message naming it.

13. ~~**Should an `unsafe` block's finding span its contents?**~~ **Decided: yes,
    by span — and it is not the same as widening the tolerance.** `UnsafeRegion`
    now carries the block's `end_line` (measured by the same brace walk
    `mark_test_sites` uses; `None` when the brace never closes, and no span is
    claimed then), `UNSAFE.1` states that extent, and `correlate::near` treats a
    runtime defect *inside a stated region* as a match.

    The two things are kept apart deliberately. `line_tolerance` is a
    **measurement** allowance — compilers and sanitizers disagree about which line
    an operation belongs to — and raising it to cover a construct would loosen
    matching for every rule and every tool at once. An `end_line` is a **claim**:
    the finding said it is about a region. Only findings that state an extent are
    affected, and one is stated only where something measured it.

    The confirmation rationale now says which of the two matched. It read "within
    2 line(s) of this static finding" for every confirmation, which is untrue of a
    match made by span — and that sentence is the evidence a reader is given for
    the strongest claim this engine makes.

    See item 15: the span works and is tested, but the Miri case still does not
    confirm, for a different reason.

14. ~~**`ext.codeql`'s own fixture is still the last reconstruction.**~~ **Done,
    and the base rate held for the tenth time.** Running the adapter's *own argv*
    against a real database found that `--output=-` does not mean stdout to
    CodeQL: it creates a **file literally named `-`** in the working directory,
    writes the SARIF there, prints a prose coverage line to stdout, and exits 0.
    The adapter parsed that sentence as SARIF, could never have produced a
    finding, and left a junk file in the user's repository on every run — the
    `ext.modelscan` shape a third time. Now `--output={output}`, and
    **every shipped adapter rests on a capture; there are no reconstructions
    left.**

    The reconstruction was wrong in three further ways it could not have known:
    it named a rule the default suite does not produce, it carried
    `"level": "error"` where real CodeQL emits **no `level` at all**, and it had
    no `properties.tags`, so it could not have exercised the CWE path that the
    `external/cwe/cwe-078` form once broke.

15. ~~**`RUST-2024-UNSAFE.1` is catalogued as `cwe = 1108`.**~~ **Done, and the
    citation was wrong.** Checked against the published list rather than from
    memory, which is what the third commitment requires:

    * `cwe.mitre.org/data/definitions/1108.html` — **"Excessive Reliance on Global
      Variables"**. Unrelated to this rule.
    * `cwe.mitre.org/data/definitions/758.html` — **"Reliance on Undefined,
      Unspecified, or Implementation-Defined Behavior"**. Which is what an
      `unsafe` block is: the compiler has stopped checking, and the justification
      is the only remaining evidence that the assumed properties hold.

    It was not merely wrong on its face. `same_defect_class` matches a runtime
    witness against the static finding's CWE, and 1108 is in no runtime event's
    related set — so a sanitizer or interpreter reporting undefined behaviour
    inside an unjustified `unsafe` block **could never confirm this rule**, and
    nothing said so. With `cwe = 758` and item 13's span, a real Miri run now
    reports `RUST-2024-UNSAFE.1` as `confirmed`, `medium → high`,
    `confidence certain`, `static → statodynamic`, with the rationale *"inside the
    region this finding is about (lines 8-12)"*.

    The test builds its finding from the shipped catalogue rather than carrying
    its own copy of the number, so a fixture cannot keep passing after the
    catalogue changes underneath it — which is how this stayed invisible.

16. ~~**The toolkit's own code has 19 clippy lints.**~~ **Fixed, 17 of them.** The
    two that remain are `clippy::needless_range_loop` in
    `crates/sda-syntax/src/cstruct.rs`, and they are a decision rather than a backlog:
    both push the loop *index* (`semis.push(k)`, `return Some(k)`), so the
    iterator form is `code.iter().enumerate().take(close).skip(open)` — three
    adaptors expressing a half-open range the loop already states, with a
    `skip`/`take` pair whose argument order is a classic off-by-one. The four
    sibling loops in the same file that used only the token were converted, which
    is where the advice pays.

    A second opinion is a second opinion, not an authority — which is the same
    stance the README takes about every external provider.

17. ~~**The deviation register only accepts catalogued guideline ids.**~~
    **Done.** A deviation whose rule id carries no known standard's prefix is
    accepted as an external one; anything that *claims* to be a guideline is still
    held to the catalogue, so `MISRA-C-2023-99.9` is rejected as loudly as before
    and Mandatory guidelines are still absolute. `sda rules audit` prints the
    split — `Deviations on record: 10 (9 against catalogued guidelines, 1 against
    external tools)` — because a conformance argument resting on a tool's opinion
    is a different argument from one resting on a guideline.

    External is decided by **namespace, not by a list of tool names**: a list would
    need editing every time an adapter is added, and would have been one more
    place to forget.

    The residual gap, stated rather than hidden: a *mistyped prefix*
    (`MISRAC2023-15.5`) reads as external and is accepted. It fails safe — it
    matches no finding, so nothing is suppressed and the finding stays visible —
    and it is counted in the external total the audit prints, which is where an
    unexpected number shows up. There is a test for exactly that.

18. ~~**Nothing is committed.**~~ **Committed, as one commit rather than the
    suggested seven — and the reason is worth recording.** The themes cross-cut
    files. `apply_scope` changed signature for the scope work, and its four call
    sites live in `crates/sda-cli/src/main.rs`, `crates/sda-agent/src/dispatch.rs` and
    `gui/src-tauri/src/main.rs`, each of which also carries unrelated work from
    the previous session. Any split at file granularity therefore produces commits
    that do not compile, and a bisectable history is the only thing a split buys.

    So: one commit whose message names the themes, taken with the workspace green,
    the release build warning-free and all four self-scans clean. If a future
    session wants the split, it has to be at hunk granularity, and it should be
    done before the next body of work lands on top.

19. ~~**The workbench has no test of its own beyond the CDP harness.**~~ **Done.**
    `gui/tools/drive-review.mjs` drives the other three panels: the filter bar
    (every severity facet's badge against the list it actually produces, the
    absent facet that must not be offered, the text filter, Reset), the detail
    pane (rule, line, severity, the Review and Assignment sections), the queue
    (`next` lands on the next *visible* finding), the triage buttons, and the
    baseline facet.

    Three decisions in it are worth keeping.

    **It builds its own project in the OS temp directory.** Triage and the
    baseline are *files* under the project root. Pointing the harness at
    `gui/tools/fixtures` would leave `.sda/triage.toml` in the working tree and —
    worse — let the second run start from the first run's state and pass for the
    wrong reason. A temp root is also outside this repository's `.sda/`, which is
    discovered by searching upward, so the counts do not depend on the project's
    own deviations or its scope declaration.

    **It asserts relationships, not magic numbers.** "Filtering to `low` leaves
    exactly the findings whose severity is low" survives the analyzer improving;
    "leaves 4" does not, and a harness edited every time the engine gets better is
    a harness people edit without reading. The one count it does check is the
    chip's badge against the view it filters to — those are computed by different
    code (`countBy` over every finding, `passes` over each one) and can disagree
    silently.

    **It checks the file, not just the screen.** A conclusion recorded in the
    UI's own memory and nowhere else is the failure this pane exists not to have,
    so `.sda/triage.toml` is read back and must name the finding, the state and
    the rule, and `.sda/baseline.toml` must contain every finding id.

    The launch, staleness and scan-click guards moved to `gui/tools/workbench.mjs`
    rather than being copied. Each was paid for by a run that reported PASS while
    testing nothing, and a second copy is a second copy that drifts — which is the
    defect `mcp_paths_agree.rs` exists for, one surface over.

    **Watched failing, not assumed to work.** `renderChips` was changed to badge
    `n + 1`, the workbench rebuilt through the Tauri CLI, and the harness run: it
    reported `severity chip \`medium\` badges 6, but 5 findings have it`, the same
    for `low`, and the triage chip too — three named failures rather than a bare
    exit code. Restored and re-run, both harnesses pass.

    Grouping, the terminal pane and the coverage gutter are covered by
    `gui/tools/drive-panes.mjs` since 2026-11-02. Since 2026-11-03
    `drive-review.mjs` also drives assignment, the `me` button, the `mine`
    filter and a comment, checks each against `.sda/triage.toml` read by its
    own parser, and checks the comment survives a re-scan. That re-scan exposed
    a harness weakness: `scan()` in `workbench.mjs` took the status line's
    "scan complete" from the previous run as this one having started. It now
    waits for the findings array to be replaced.

21. ~~**The SARIF names no revision.**~~ **Done, and the decision it needed was
    the whole of it.** A revision alone is a specific falsehood on a dirty tree,
    and SARIF has no field for the difference — so the revision and the state of
    the working tree are recorded together, in both halves of the report, and
    neither is emitted without the other. See *What revision a report describes*.

    Adding it produced a warning rather than silence, which is how the next gap
    surfaced: result paths were relative and nothing said what to. There is now a
    `SRCROOT` base id, declared without a machine path.

20. ~~**`sda scan tools` is not clean and the reason should be encoded, not
    remembered.**~~ **Done: scope, not deviations — and it cost a defect in the
    scope machinery on the way.**

    **Why scope.** Deviations were the other candidate and are the wrong
    instrument here. Most of the twenty findings are not deliberate sins at all:
    they are `D4.6` on a plain `int` and `15.5` on a second `return`, in throwaway
    harness programs. A deviation for those would have to be justified as "not
    delivered product", which is the scope claim written in the wrong file — and
    twenty records against catalogued guidelines would then travel in this
    project's conformance argument, which describes the crates that ship.

    One rule, in the repository's own `.sda/scope.toml`, naming `tools`. Nothing
    is hidden: the run prints the reason, the approver and the file count in
    *NOT CHECKED*.

    **What it gives up, stated rather than glossed.** `sda scan tools` no longer
    checks that the deliberately-defective fixtures are still defective. That was
    a real property and it is gone; what remains is `every_adapter_parses.rs`,
    which pins the *captured tool output*, and that is the guarantee those files
    exist to support.

    **The defect it exposed.** A scope declaration is found by searching
    **upward**, but `apply_scope` matched its rules against paths relative to
    `target.root` — the directory the user happened to type. The two are the same
    only when the scan root is the project root. `sda scan tools/valgrind-wsl`
    loaded this repository's declaration, compared its `tools/...` rule against
    paths beginning `three-sins/`, matched nothing, reported the rule as
    *possibly stale*, and analysed every file it names. A scope rule that quietly
    stops applying when you scan a subdirectory is worse than no rule at all,
    because the report still carries the sentence saying it was honoured.

    Rules are now anchored at `ProjectConfig::root()` — the parent of the `.sda/`
    they were loaded from — in all four call paths, and a file outside that anchor
    is left *in* scope rather than matched against the full path. Two tests pin
    it, and both were watched failing against the old behaviour.

    **And the "stale" message had to be split three ways.** Once rules are
    anchored at the project, most of them legitimately do not apply to any given
    scan: `sda scan crates` loads a declaration whose only rule names `tools`.
    Reporting that as "it may be stale" on the repository's own must-stay-clean
    command trains a reader to skip past the one message that matters. A rule that
    removed nothing now says which of three things happened — it names nothing in
    the project (stale), it lies outside this scan, or it was scanned and holds no
    analyzable file.

## Recent changes

* **Three sweeps of the coverage classification, and it was wrong four times.**
  12.1 (open-ended, checked two operator pairs), D4.4 (undecidable *and*
  `native`), and 5.1 and D4.5 (judged across the program, checked one file at a
  time). All four claimed that a clean result was evidence of conformance and
  none could support it. `sda rules audit` reports 70 provable guidelines now
  rather than 74, and two invariant tests make the last three kinds of mistake
  fail the build. Nothing had ever audited that classification, and it is what
  the toolkit's conformance claim rests on.

* **`sda` now builds for Linux, and the two platforms agree exactly.** The first
  non-Windows build of this toolkit, which made a comparison available that had
  never been run: the same analyzer over PX4 on Windows and in WSL gives 15,528
  findings each, with **every rule's count identical**. It found one defect —
  `sda.ai.artifact` reported absolute paths where every other provider reports
  relative to the target root, so a baseline made on one machine could not match
  on another. It also corrected the PX4 write-up: coverage is 538 of 12,463 on
  *both* machines, so the 4.3% was never about path format.

* **A supplied compilation database was never measured.** `sda scan
  --compile-commands` checked that the file existed and nothing more. A database
  naming files this machine does not have — from a container, another checkout
  path, or WSL, where every entry reads `/mnt/c/...` while the analyzer sees
  `C:/...` — was accepted in silence, and the run then looked exactly like one
  with no database, except that the operator believed type-aware analysis had
  become possible. `sda_build::supplied_coverage` now measures it, the count goes
  to stderr, and any shortfall is a `NOT CHECKED` notice. Found while preparing
  item 23, by testing the instrument before the real run.

* **A real C declarator parser, and the last of 5.1/D4.5 that tokens can reach.**
  The shape-matching version refused anything with a parenthesis, which removed
  every function-pointer object along with every function declaration.
  `parse_objects` now follows the declarator. Two refusals were bought with false
  positives on PX4 — `PARAM_DEFINE_INT32(TEST_1, 2);` is a macro invocation, not
  an object, and `__BEGIN_DECLS` with no semicolon runs the next declaration on
  from it — and both reduce to "nothing here expands macros". One added finding
  on 697 real C files, genuine, zero false positives.

* **The Monaco port's validating layer, which had never met anything.** Item 24
  said `TextModel` needs "a DOM and a dependency-injection container": it needs
  neither for this, and the container is three stubs. A real `TextModel` now runs
  in node. Three defects, all in how an out-of-range or mid-character position is
  validated — `Position::new` clamped 0 up to 1 on *construction*, so line 0 was
  unrepresentable and `clamped` never saw it; `clamped` was two independent
  clamps where Monaco's is ordered; and `Range::clamped` pulled an end inward
  over a surrogate pair where Monaco expands outward, so a highlight could end
  inside a character.

* **A purpose-built MISRA corpus, and seven more defects.** The cppcheck
  comparison ran over four files that happened to be in the repository;
  `tools/misra-corpus/` is eight more, written from the guideline titles rather
  than from the checks, aimed at the sixty-two guidelines both tools implement.
  It found 5.4/5.5 using the external-identifier significant length (31) where
  the standard gives macro names 63 — fifteen **false positives** on PX4 — and
  four `native` rules that had only ever seen their own fixture: 8.2 never looked
  at a declaration, 11.9 only at `(void *)0`, 12.3 only at `if`/`while`/`switch`,
  13.4 only at the outermost level of a condition. **Each extension was then
  measured against PX4 and four of the five needed a guard the corpus could not
  have shown** — `*revision = 0;` is not a declaration, `PARAM_DEFINE_INT32(X, 80);`
  is not a prototype. A second pass reached the twelve comparable guidelines the
  corpus was still missing and found two more: 5.1 and 21.2 read only function
  definitions, never file-scope objects.

* **The first whole-program check.** 5.1 and D4.5 are now compared across
  translation units — function definitions *and* file-scope objects — which
  needed two new things from `sda-syntax`: `CFunction::internal_linkage`, because
  two `static` functions with the same name in different files are correct C, and
  `CStructure::objects`, which reads a file-scope declarator only when its shape
  is unambiguous and refuses the rest rather than guessing. On PX4-Autopilot's 697
  C files it finds three violations, all confirmed by hand, and no false
  positives; one is a pair of thirty-six-character names that agree for the
  thirty-one characters a conforming linker must consider.

* **An undecidable guideline can no longer claim a clean result proves
  conformance.** The catalogue records MISRA's own decidability beside the
  coverage class, and D4.4 was marked `undecidable` and `native` at once — the
  first field says a clean result is not a proof, the second offers it as one.
  Reclassified `partial`, and an invariant test now fails the build if any
  guideline in any catalogue says both. Found by sweeping for the class of
  mistake 12.1 turned out to be. `sda rules audit` reports 72 provable
  guidelines now rather than 74.

* **The MISRA rules met a second implementation, and it cost a defect.** Item
  27, as far as it goes without the licensed document: cppcheck's MISRA addon
  reports rule numbers without the rule texts, so the guidelines it fires can be
  compared with ours, over four C files. On the first two it agreed except where
  the catalogue already declares a gap. Widening it found **12.1 marked `native`
  while checking two operator pairs of an open-ended guideline** — the engine read
  `sizeof cmd - strlen(cmd) - 1` clean, where `sizeof` binds tighter than every
  binary operator. 12.1 is now `partial` and covers that trap. Line anchors are
  deliberately not compared (neither the guideline nor the standard fixes where a
  finding belongs); `21.8` is recorded as an edition difference with the addon
  source that proves it; and `21.6` on `#include <stdio.h>` is recorded as a
  reading disagreement the licensed text would have to settle. See *MISRA,
  against a second implementation*.

* **Directive extents now have clang behind them.** Item 25, half of it: a
  `#define` continued by a trailing backslash is where a hand-written directive
  scanner goes wrong, and multi-line macros are everywhere in embedded C. The
  oracle is clang's `[StartOfLine]` flag — a splice does not begin a logical line,
  checked against clang before being relied on — so the extent is clang's account
  rather than the splice rule restated in a test. Passed on eleven cases, watched
  failing with the splice skip disabled. Rust attributes remain without an oracle;
  the same trick does not transfer.

* **`rstruct` met syn, and the brace walk held.** Item 26: `UnsafeRegion::end_line`
  is what lets correlation place a Miri violation inside the `unsafe` block it
  belongs to, and it is found by hand-walking braces. It survives a `}` in a
  string, a character literal, both kinds of comment and a raw string — because
  the walk runs over code tokens and compares token text, so a brace inside a
  string is never a brace. Watched failing against the naive form.

* **The returns MISRA 15.5 counts now have a compiler behind them.** One layer up
  from the lexers: `CFunction::returns` is compared against clang's `ReturnStmt`
  nodes over ten cases, and it passed — including `return` inside a comment and
  inside a string literal. The oracle's own delta-encoded line numbers were the
  hard part, and getting them wrong would have produced a capture that measures
  nothing. See *One layer up: the returns MISRA 15.5 counts*.

* **The Rust lexer had never been compared with rustc, and lost four times.** C
  string literals (`c"..."`), signed float exponents (`1.0e-3`), raw identifiers
  (`r#fn`, whose `fn` was then classified as the keyword) and non-ASCII
  identifiers (`café`) were all mis-lexed — every one of them ordinary Rust that
  this crate claims to support. The oracle is `ra-ap-rustc_lexer`, the
  compiler's own lexer, called directly rather than captured. See *The Rust lexer
  has met rustc, and lost four times*.

* **The C/C++ lexer had never been compared with a compiler, and got `<::`
  wrong.** `a<::b` lexed as the digraph `<:` then `:` where clang lexes `<` then
  `::` — C++'s one exception to maximal munch, which exists so that
  `std::vector<::Foo>` reads as written. `tools/clang-lex-oracle.py` captures
  clang 22.1.8's own raw token stream and `agrees_with_clang.rs` asserts it. See
  *The lexer has met clang*.

* **The Monaco port had never been compared with Monaco. Three oracles later, it
  disagreed three times and agreed once.** A trailing newline opens a final empty line — the crate said it did
  not, so a three-line C file was three lines instead of four — and columns were
  characters where the documentation promised UTF-16, so every column past an
  emoji was short by one. `gui/tools/monaco-oracle.mjs` captures the real
  answers, `agrees_with_monaco.rs` asserts them, and both reverts were watched
  failing. A second oracle then found the third: two of the three `Stickiness`
  doc comments described the opposite of Monaco, and `adjust` never consulted
  stickiness at the start edge at all, so `GrowsOnlyWhenTypingBefore` was
  indistinguishable from `NeverGrowsWhenTypingAtEdges`. A third, over multi-cursor
  edits, found nothing: `apply_all` agrees with Monaco on all twelve cases, and
  both refuse overlapping ranges. See *The port has met Monaco, and disagreed
  with it*.

* **The MCP surface met the reference client and passed.** Driven by
  `@modelcontextprotocol/inspector --cli` rather than by hand-written JSON-RPC:
  handshake, all twenty-one tools, a real call, and both error paths. Nothing to
  fix — which is worth recording precisely because it is not the base rate. The
  hand audit behind it is now a test: `published_schemas_match_handlers.rs`
  drives the published surface and pins every `required` argument against the
  handler that reads it.

* **A report now says which revision it describes — and whether that is true.**
  `VcsProvenance` on `Report`, rendered by the text, JSON and SARIF surfaces and
  probed in `run::analyze` so all four paths agree. The difficulty was never the
  revision: SARIF has no field for whether the working tree matched it, so a
  consumer reading `revisionId` on a dirty scan would be told a specific
  falsehood by a report trying to be more precise. Revision and tree state travel
  together or not at all. Doing it surfaced a second gap — result paths were
  relative with nothing saying what to — now a `SRCROOT` base id declared without
  a machine path. See item 21.

* **The SARIF exporter met a real consumer for the first time.** Handed to
  `@microsoft/sarif-multitool validate` — the reference implementation behind
  GitHub's ingestion — a real scan is schema-valid with zero errors and zero
  warnings, verified by breaking a copy first so silence means something. It cost
  two defects: the `$schema` URL had been a 404 since the OASIS repository
  renamed its default branch, and the source snippet the engine already collects
  was being dropped at the boundary, so every other tool saw a line number and no
  code. Forty-eight `note`-level observations remain and each is a stated
  decision; one of them, `versionControlProvenance`, is worth doing. See *The
  SARIF has met a real consumer*.

* **Dynamic evidence at scale, and the last of item 12.** `bibutils` — 105 real C
  files — built under WSL with `--coverage`, exercised by its own test suite and
  five of its converter binaries, then scanned with gcov's counts and Memcheck
  executing the program: **6,881 findings, 6,881 correlations, unreached 5,501 /
  inconclusive 888 / refuted 492**, in nine seconds. A quarter of the code ran,
  so three quarters of the findings are reported as untested rather than clean.

  Two defects, both in what the report *says* rather than what it computes.
  A quiet dynamic tool went unnamed whenever coverage was supplied — the sentence
  naming it lived only in the no-observation branch, and `--coverage` creates an
  observation — so 492 refutations arrived with no statement that Memcheck had
  looked. And 59 gcov listings produced 59 near-identical provenance paragraphs
  in *NOT CHECKED*, burying the two entries that mattered. See item 12.

* **`sda build compile-commands` had never been run, and could not have worked
  on this machine.** It is the command the toolkit points at whenever a
  type-aware provider is blocked, and `sda build detect` prints its recipe as the
  fix. Both named `cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON` with
  **no generator**.

  CMake honours that variable for the Makefile and Ninja generators only and
  ignores it in silence for every other one. The default generator on a Windows
  install is Visual Studio. Verified against CMake 4.4 and "Visual Studio 18
  2026" on a two-file project: configure succeeds, prints *Generating done*,
  exits 0, and **no `compile_commands.json` appears**. So the one command this
  module exists to run could not produce the one artefact it exists to produce,
  and the advice printed to the user was the same command.

  Noticed only because the previous piece of work needed a database and I
  generated one with CMake directly, working *around* the shipped command
  without running it. The base rate holds: a component that has never met
  reality has never been tested.

  Fixed by naming a generator — Ninja if present, else the platform's make — in
  both the recipe and the command, with a test that the two agree, because they
  are separate code and drifted the moment one was changed.

  Two more, from the same run:

  * **The failure was truncated at exactly the wrong place.** `outcome.stderr`
    was cut to its first five lines, and a build tool states the failure first
    and the reason afterwards — so the report named `CMakeTestCCompiler.cmake:65`
    and stopped, which is the least useful true thing available. It now shows the
    **tail**, says how many lines were elided, and on Windows adds the fact that
    is not in anything CMake prints: `cl` is never on `PATH` until `vcvars64.bat`
    has run.
  * **"Reported success but no database appeared" did not say why.** It advised
    checking the build directory. It now names the generator rule, which is the
    actual cause every time.

  Driven end to end afterwards: from a developer shell it produces **380
  translation units for llama.cpp**, and reports that this covers 61% of the 574
  source files found, naming the ones it does not cover. A database that covers
  61% being reported as covering 61% is the part that was already right.

* **A real C++ project at scale, and four defects for it.** cppcheck 2.21.0 and
  clang-tidy over 184 files of `llama.cpp/src`, the second against a real
  217-entry compilation database configured out of tree. See item 12. The four:
  a tool's account of its own degraded analysis filed as `information` findings
  while *NOT CHECKED* stayed empty (new `Analyzer::take_notices`); no way to name
  a compilation database outside the scan root (new `--compile-commands`); 307
  `note:` continuation lines reported as findings, detaching every trail from the
  diagnostic it explains; and `ExternalAdapter::timeout` — a public field with a
  ten-minute default whose entire purpose is to bound a hung tool — never being
  read at all.

* **A Cortex-M3 image runs the instrumentation, and the engine reads what it
  wrote.** The highest-value gap in this file, closed under emulation. It needed
  a new ingestion path (`sda scan --observation <FILE>`, for a program that ran
  somewhere the host cannot run it) because none existed, and it found the
  `executions = 0` defect described in item 1. `shim/sda_probe.h`'s own status
  paragraph said the freestanding path had "never been assembled"; it has now,
  and says so.

* **`tools/` is declared out of scope, and the declaration was not being applied
  where it was read.** See item 20. The short version: `apply_scope` matched
  project-relative rules against scan-root-relative paths, which is the same thing
  only when the two roots coincide. Anchoring at `ProjectConfig::root()` fixes it
  in the CLI, the workbench and both MCP paths at once; the zero-match notice now
  distinguishes *stale* from *does not apply to this scan* from *scanned and
  empty*; and the repository's own `.sda/scope.toml` names `tools`, so
  `sda scan tools`, `sda scan .` and `sda scan tools/valgrind-wsl` all reach the
  same answer instead of three.

* **A second GUI harness, and a shared launcher.** `gui/tools/drive-review.mjs`
  covers the filter bar, the detail pane, the triage buttons and the baseline
  facet — the three panels `drive-cdp.mjs` never looked at — and asserts the
  files those buttons write, not just the screen they redraw. The launch,
  staleness and scan-click guards moved into `gui/tools/workbench.mjs` so the two
  cannot drift into driving different binaries. See item 19.

* **Assignment and discussion threads, shared by people and agents.** A
  `TriageRecord` now carries an `assignee` and an append-only list of comments,
  each with an author and a time. The workbench has an assignee field with `me`
  and `agent` shortcuts, a thread with an add box, a `mine` facet, and per-row
  `@owner` and remark-count badges; `analysis.triage` gained `assign` and
  `comment` so an agent does the same operations on the same file.

  **One namespace for people and agents** is the point, not a shortcut:
  `a.erickson` and `agent:triage-bot` are the same kind of thing to the store, so
  a human can hand a batch to an agent, the agent works it over MCP, and the
  conclusions land back in the file the human is reading. There is no server
  between them, which is what makes the review arrive in a pull request next to
  the code it is about.

  Two invariants, both tested because both are easy to lose:

  * **Assigning and commenting conclude nothing.** A distributed queue is not a
    reviewed queue, and an assigned finding still counts as unreviewed. Collapsing
    the two would let a backlog look triaged because it had been handed out.
  * **A verdict never eats the discussion.** `set` used to replace the record
    wholesale, which discarded the assignee and the whole thread the moment
    anybody pressed a verdict button. It now merges, and clearing a verdict keeps
    a record that still holds an assignment or a thread — while one holding
    neither still disappears, so an untouched finding stays distinguishable from
    one somebody opened and walked away from.

  A write against an id that is not in the current scan is refused, whichever kind
  of write it is, and an id with no verb is an error rather than a silent listing.

* **What was deliberately not built: a server.** Coverity and SonarQube keep owner
  and thread state in a database behind a web UI, and multi-user access is what
  that buys. The file in `.sda/` buys something else — the review is diffable,
  arrives with the code in a pull request, and `git log` already answers "who
  said this". Concurrent edits are handled the way the rest of the project's state
  is handled: by merging a text file. That is a real trade, and worth revisiting
  only if someone needs live presence or cross-repository dashboards.

* **A baseline, so the question is "what did we just add".** `sda_rules::Baseline`
  records a run's finding ids in `.sda/baseline.toml`; the workbench shows a `NEW`
  badge, a `new` facet and a "Set baseline" button, and `analysis.baseline` gives
  an agent the same read and the same write. Stable content-addressed finding ids
  are what make it work at all.

  Three things it deliberately refuses to do. It is **never written automatically**
  — a baseline refreshed by every scan reports zero new findings forever and looks
  like it is working. An **absent baseline means unknown, not "not new"**: `is_new`
  is `None`, the MCP field is `null` rather than `0`, and the UI disables the facet
  and says "no baseline" instead of filtering to an empty list. And **reading never
  moves the line**, which has its own test, because that is the same failure
  arriving by a slower route.

  `new` means absent from the recorded set and nothing more — not a claim about a
  commit or an author, since a finding can be new because a rule was added or a
  provider enabled. `resolved` counts what the line held and this run did not
  produce, and the tool says out loud that it cannot tell *fixed* from *moved* from
  *filtered out by a scope change*.

  Driven end to end: 20 findings recorded, a defect added, 22 in the scan and
  exactly 2 new, both located in the added code.

* **The GUI harness was driving a five-week-old binary, and I said otherwise.**
  Its default path was `gui/src-tauri/target/release/`, which is not where cargo
  writes on a machine with a shared `CARGO_TARGET_DIR` — so every GUI run earlier
  in this session, *including the two "cold start" runs recorded as evidence that
  the correlation and C-parser changes had not moved a glyph*, exercised a binary
  from 12 August. Those runs proved nothing about this session's work. The claim
  has been corrected here and in item 9.

  Worse, a bare `cargo build --release` does not embed the frontend at all: the
  binary it produces loads the Vite dev URL, so it silently serves whatever is on
  `localhost:5173` or nothing. The workbench has to be built with the Tauri CLI
  (`npx tauri build --no-bundle`).

  The harness now resolves the binary through `cargo metadata`, prints which one
  it is with its mtime, and **refuses to run one older than `gui/src/main.js`,
  `style.css`, `index.html` or `dist/index.html`**. A test that silently runs the
  wrong artifact is worse than no test, because it produces confidence rather than
  doubt — which is this repository's own thesis, turned on its tooling.

  Pointing it at a current binary immediately found a real regression: the UI
  rewrite had replaced `className` with `inlineClassName` and lost every squiggle,
  along with the decoration generation guard and the minimap colour. All three are
  restored from the shipped version, verbatim.

* **The workbench is a review queue, not a list.** Faceted filters (severity,
  verdict, review state, free text) with live counts, grouping by file/rule/
  verdict, a windowed list that renders only what is on screen, keyboard
  navigation (`j`/`k`, `1`-`4` to triage, `/` to filter), resizable panes, and a
  severity *letter* beside the colour so the cue survives a screenshot. The list
  used to render every finding as a full-message card: about seven rows visible,
  and PX4's 14,284 findings would have been two thousand screens of scrolling
  with no way to narrow them.

  Filtering is a **view**. `findings` is never mutated, the header count always
  reports what the scan produced, and nothing a filter does reaches a report.

* **The detail pane shows the evidence, which is the product.** `UiFinding`
  carried fourteen fields and none of them was evidence, so the engine computed
  CodeQL dataflow paths, Miri's created/invalidated chain and the Memcheck event
  that confirmed a finding, and the workbench could render a coloured chip and
  nothing else. A reader could see `confirmed` and had no way to ask why. It now
  carries the title, the CWEs, the remediation, the **correlation rationale**, and
  the flattened evidence — with dataflow steps as a numbered, clickable path that
  jumps the editor. `to_ui_evidence` lives in Rust so a second shell renders the
  same thing by construction rather than by agreement.

* **Triage: one review state for humans and agents.** `sda_rules::TriageStore`
  writes `.sda/triage.toml`; the workbench writes it from the detail pane, and the
  new `analysis.triage` MCP tool reads and writes the same file. Driven both ways:
  a click in the GUI is visible to the agent with rule, location and counts, and
  an agent's `accepted` with a note shows up in the file the human reads.

  Four states, and `fixed` is deliberately not one of them — whether a defect is
  gone is decided by the next scan, not by a checkbox. `open` *removes* the record
  rather than storing it, so "nobody looked" and "someone looked and moved on"
  cannot be confused. Records whose finding vanished are reported as **stale**
  rather than deleted: the code moved under a conclusion somebody reached, and
  "fixed" cannot be told from "moved and now unreviewed". Recording against an id
  that is not in the current scan is refused outright.

  **Triage annotates; it never hides.** A triaged finding still appears in every
  report and still counts toward every gate. Suppression remains a deviation, with
  an approver, a rationale, and a catalogue check. Both the tool description and
  the pane say so.

* **The `NOT CHECKED` banner is proportionate without being dismissible.**
  Registering every external adapter so the report can name them — the right fix,
  made earlier this session — turned the banner into nine identical sentences
  filling a quarter of the window, which is a banner people learn to scroll past.
  The repetitive class now folds into one line that still states the count and
  still lists every name when opened; anything that is *not* routine stays spelled
  out. Collapsing is not hiding.

* **The GUI harness no longer fails on its first run after a build.** It clicked
  Scan before the app was listening and then reported a decoration failure for a
  file that was never scanned. It now waits for the app's own `scanning...` and
  retries the click, and was verified against two consecutive cold starts — the
  condition that previously failed every time. The engine changes made later in
  the session are confirmed not to have moved a single glyph.

* **An external tool's finding can be deviated.** The register accepted only
  catalogued guideline ids, so a project running `--with ext.clippy` in CI had two
  options for a finding it had examined and accepted: change the code, or read the
  finding forever. It now accepts an id in no standard's namespace, still rejects
  a mistyped guideline number, still refuses Mandatory guidelines, and `sda rules
  audit` reports the two counts separately. `sda scan crates --with ext.clippy` is
  now clean: 0 unsuppressed, 6 suppressed, and the register's first external entry
  is the one this session declined to fix.

* **Seventeen of the toolkit's nineteen clippy lints are fixed**, from
  `sda scan crates --with ext.clippy`. Four `needless_range_loop` sites in
  `cstruct.rs` that used only the token became slice iteration; two that push the
  loop *index* were left, because clippy's rewrite there is
  `enumerate().take().skip()` reconstructing a range the loop already states. Also
  a seven-element tuple given a name, a manual `Default` derived, a `loop`/`else
  break` turned into `while let`, and the usual `format!` with no arguments.
* **The deviation register cannot record an approved departure from an external
  tool's finding.** Discovered trying to record those two declined lints the way
  this repository records every other accepted finding: the entry was rejected —
  `clippy::needless_range_loop` is not a known guideline in any loaded catalogue —
  and the rejection was reported, which is the register working as designed. But
  it means a project running `--with ext.clippy` in CI has exactly two options for
  a finding it has examined and accepted: fix it, or let it be reported forever.
  See *Suggested next steps* item 17.

* **`RUST-2024-UNSAFE.1` cited CWE-1108, "Excessive Reliance on Global
  Variables".** It is now CWE-758, checked against cwe.mitre.org. A CWE no
  runtime event relates to silently disables confirmation for the whole rule, so
  this was not a cosmetic error: with item 13's span already in place, Miri's
  undefined-behaviour report and the `unsafe` block it happened inside were still
  reported as two unrelated claims. Both now resolve to one `confirmed` finding.

* **`UNSAFE.1` states the extent of the block it is about**, and `correlate::near`
  confirms a runtime defect that lands inside a *stated* region. Kept strictly
  separate from `line_tolerance`, which is a measurement allowance and not a
  scoping mechanism — see *Suggested next steps* item 13. The rationale now
  reports which of the two matched, because "within 2 line(s)" was printed for
  every confirmation and is false of a span match.
* **`external_dynamic_refutes.rs` raced against itself**, and the first diagnosis
  was wrong. Its four tests shared one fixed temp directory, and `cargo test` runs
  them in parallel threads — so each was removing, recreating and writing the
  directory underneath the others. A different subset failed on each run, which
  looked like a correlation defect and was written off once as a stale build
  artifact. It was neither. Each test now gets its own directory; verified over
  three consecutive runs.

  Worth stating because the wrong explanation is the tempting one: a failure that
  appears only in a parallel run is *more* likely to be a shared-fixture race than
  a build problem, and "it passed when I ran it alone" is the symptom, not the
  refutation.

* **Both MCP scan paths share one `project_setup`.** `analysis.statodynamic` used
  to build a bare `default_registry()` and read no project configuration at all,
  so an agent driving it saw different citations and different suppressions from a
  human running `sda scan` over the same project — the one thing the agent surface
  exists not to do, and invisible from either report alone. The new test asserts
  the two agree rather than asserting either is right, because the defect was a
  *difference*; it was verified by putting the old body back and watching it fail.

* **`ext.codeql` asked for `--output=-` and got a file called `-`.** CodeQL does
  not read a dash as stdout: it writes the SARIF to a file of that literal name in
  the working directory, prints a prose coverage sentence to stdout, and exits 0.
  So the adapter parsed the sentence as SARIF and littered the repository on every
  run. Now `--output={output}`, the same file-reading path ModelScan needed, and a
  spec-level test forbids any adapter from naming `-` as an output destination:
  the convention is a convention, and a tool that does not honour it fails in a
  way that looks like success.
* **`{target}` was substituted with the path as the user typed it**, while the
  child is spawned with `current_dir(&target.root)` — so `sda scan crates` ran the
  tool from inside `crates` and told it to analyze `crates/crates`. **Every
  `{target}` adapter was broken for a relative path**, which is the ordinary way
  to invoke the CLI; the earlier real-tool runs all happened to use an absolute
  path or `.`. Now `std::path::absolute`, deliberately not `canonicalize`, whose
  Windows `\?\C:\...` form several of these tools mishandle. An existing test had
  pinned the defective behaviour by asserting the argument equalled `/proj`.
* **A missing report now quotes the tool.** "could not be read" named our file and
  our io error, describing our side of a failure that happened on theirs — and it
  hid the CodeQL diagnosis above for an hour. The message now carries the exit
  code and the last lines the tool wrote to stderr.
* **No adapter fixture is a reconstruction any more.** `Provenance` records what
  each was captured from, and the test that used to allow `["ext.codeql"]` now
  requires the set to be empty.

* **Fixture provenance is data, not a comment.** `Provenance::Captured(version)`
  or `Reconstructed` on every entry in `every_adapter_parses.rs`, with three tests
  over it: an adapter wrapping a Python CLI may not rest on a reconstruction, the
  reconstructed set must be exactly `["ext.codeql"]`, and a capture must name its
  version. The guards were checked by flipping `ext.semgrep` and watching two
  tests fail, rather than assumed to work. Comments about provenance have been
  wrong twice — `ext.modelscan` carried a note calling a real capture a
  reconstruction — and it is the one fact this repository most needs to state
  accurately.
* **The self-scan is still clean** after all of the above: `sda scan crates`
  reports no unsuppressed findings and the same four `PANIC.2` deviations. Its
  `NOT CHECKED` section now names all nine external providers, which is the
  default-run fix visible in the toolkit's own report.

* **The refutation channel kept one dataflow path out of three.** A real C++
  `cpp/command-line-injection` result carries three `codeFlows`, the first through
  the guard and the second around it, and both the SARIF parser and
  `interposition::taint_bypasses` read only the first. Refutation is existential —
  one unguarded route to the effector is a counterexample — so reading the first
  made the verdict a function of the producer's emission order. See *Suggested
  next steps* item 10; the Python capture has one flow, so nothing there could
  have caught it.
* **And refutation no longer requires the flow to begin inside the model.** It
  anchors on the last visit to a neural component instead. The old requirement
  held only because CodeQL's Python taint source sits inside `policy/serve.py`;
  the C++ source is `argv` at `main`, and the bypass was skipped in silence.
* **`tools/codeql-taint-cpp/`** — the C++ twin of the Python taint program, with
  the commands and the two `cmd.exe`/`wslpath`-class traps written down.
  `tools/codeql-taint/README.md` now exists too: `.gitignore` had been citing it
  for the database path since before it was written.

* **A default `sda scan` said less about what it had skipped than a scan that
  asked for a tool.** The external adapters were registered only when `--with`
  was given, and `analyze` can only exclude a provider the registry was handed —
  so a plain scan named none of the nine external providers it had not run, while
  `--with ext.miri` listed the other eight. Exactly inverted: the run that
  enables nothing is the run whose reader most needs telling, and it is the run a
  first-time user makes. Found on the PX4 scan below, whose report carried a
  `NOT CHECKED` section with one line in it. They are now registered on every
  path and enabled only on request, which costs nothing — `Registry::select`
  applies the policy before it probes availability, so a disabled adapter never
  spawns a process.

* **`ext.miri` has met its real tool, and was wrong about everything that
  mattered.** It declared `OutputFormat::ClippyJson` on **stdout**, because
  `cargo miri test --message-format=json` looks like `cargo clippy
  --message-format=json`, and its fixture was a reconstruction that agreed. It is
  wrong: `--message-format=json` governs *cargo's build* messages, while Miri's
  undefined-behaviour report is produced at **run** time by the interpreter and
  written to stderr as rustc prose. A real run over a stacked-borrows violation
  writes two `compiler-artifact` lines and `"success":true` to stdout and not one
  `compiler-message`. The adapter was fully green and could not have reported a
  single real finding — the `ext.valgrind` failure again, in a different tool.
  New `OutputFormat::MiriText` and `parse::parse_miri`; `parse_gcc_like` would
  not have worked either, since rustc puts the location on the line *after* the
  message.
* **And it could not have run at all.** The spec invoked `cargo miri` on the
  default toolchain. Miri is a nightly-only component, so on a stable default the
  availability probe reported "the subcommand is not installed" — true, and
  indistinguishable from a machine where miri is genuinely absent, on a machine
  where it was installed and working. Now `cargo +nightly miri`.
* **Miri's `help:` blocks are kept as the finding's trace.** For an aliasing
  violation, where the pointer was created and where it was invalidated is the
  whole explanation; a finding naming only the read cannot say why the read is
  wrong. They are one diagnostic and not three findings. Cargo's own
  `error: test failed` and `error: aborting due to 1 previous error` are on the
  same stream and are not findings: they carry no `-->`, which is the tool's own
  distinction between a defect in the code and a fact about the process.

* **The neurosymbolic checks run in a plain `sda scan`.** `RunConfig` carries the
  `.sda/architecture.toml` declaration and `run::analyze` runs interposition and
  adjudication itself, so the CLI, the workbench, and both MCP scan tools get it
  from one place. Two judgements were needed and neither is plumbing. **Deduction
  runs before correlation**, and only `Adjudication::unadjudicated` reaches
  `correlate` — its doc comment already said why, and wiring the two in parallel
  would have let `Unreached` ("we never tried") overwrite a finding a proof had
  settled. And **a bypass is a `Finding`, not a summary string**: `sda verify`
  prints prose a human reads, but a scan emits JSON and SARIF, and a refuted
  safety case that lived only in prose would pass the CI gate that reads them.
  `interposition::findings_from` renders each bypass as a critical
  `SDA-INTERPOSE-01` located at the declaration — what is wrong is the claim, and
  for a bypass read off the declared graph there is no source line that is wrong.
* **Those bypass findings pass through neither engine.** Adjudicating the
  deduction's own output asks which component owns `.sda/architecture.toml`;
  nothing does, and the answer arrived in the report as `sda.unmapped` — a true
  statement about a file that is not part of the system, filed as a gap in the
  analysis of one. Caught by reading a real run's output, not by a test, and now
  held by one.
* **A project that ships a model and declares no architecture is told so**, and
  one that ships no model is not. The notice lives in `analyze` so every path
  gets it, and it is conditional for the reason the probe runner's registration
  is: a notice that appears on every scan in the world is one people learn to
  skip past.
* **The external dynamic path produces all four verdicts, driven end to end.**
  Memcheck 3.24.0 supplies the defect, gcov 14.2.0 supplies the counts, and
  nothing is instrumented with the probe shim — see *Suggested next steps* item 2
  for the numbers and the two traps. `as_runtime_evidence` was split out of
  `ExternalAdapter::analyze` so the regression test replays a captured Memcheck
  run through the *shipping* phase-and-event logic rather than a copy of it; that
  seam has already been wrong twice, and a test carrying its own version of it
  would be testing the test.

* **External dynamic evidence confirms static findings** — the toolkit's central
  claim, previously unavailable to every external dynamic adapter it ships.
  Driven end to end against Memcheck 3.24.0: a leaked `malloc` witnessed at
  `main.c:9` confirms the two MISRA rules flagged on that line, `medium → high`,
  `high → certain`, `static → statodynamic`, with the leak event attached to the
  finding itself. Verified negatively by fixing the leak. Cost four defects — the
  witness carried no runtime event; `from_cwe` and `related_weaknesses` disagreed
  about 415/416/761/762; `correlate` was reachable only through a native
  `Observation`; and a dynamic tool that ran clean was reported as a static-only
  run without being named.
* **`correlate` takes `Option<&Observation>`** — `None` means execution was never
  measured, which is not the same as measured and empty. See *Design decisions worth preserving*.
* **`RuntimeEventKind::from_cwe`** in `sda-core`, with an exhaustive round-trip
  test against `related_weaknesses`.
* **The Valgrind harness `.bat` is ASCII + CRLF**, because `cmd` parsed its UTF-8
  em dashes into `'M' is not recognized` and the adapter then reported Valgrind
  as absent while it worked.
* **`ext.valgrind` runs end to end**, via `tools/valgrind-wsl/` — a `.bat` that
  calls WSL's Valgrind plus a tiny `.exe` shim, because **`CreateProcess` cannot
  spawn a `.bat`**: `Command::new` on one fails and the adapter reports the tool
  as absent while it sits there working. Exposed two defects (external dynamic
  findings labelled `static`; a failed artifact launch discarding the whole
  report), both fixed with tests.
* **Valgrind's parser met Memcheck 3.24.0 and needed no changes.** Fixture now
  captured rather than written.
* **Cppcheck and Semgrep met their real tools.** Cppcheck was correct as written,
  though its parser now falls back to `file0` so a location-less real error is
  not dropped with the `checkersReport` metadata. Semgrep cost two fixes in
  `parse_sarif`, both inherited by `ext.codeql`.
* **ModelScan met its real tool, and the adapter was broken.** New `{output}`
  placeholder and file-reading path; an empty report file is now a failure.
* **`.sda/scope.toml`** — the analysis-scope declaration, wired through all three
  run paths (CLI, workbench, MCP). See *Design decisions worth preserving*; `README.md` has the
  user-facing shape.
* **`sda-probe`'s test harness fails as itself** rather than reporting a
  fictional aggregation bug.
* **The CDP harness is in the repo** at `gui/tools/drive-cdp.mjs`, and asserts
  rather than prints.
* **The glyph margin tells the truth about how many findings a line has**, with
  the policy in `sda-editor` and a numbered badge capped at `9+`. Two things
  turned up doing it: the `-glyph` CSS classes the decoration code had always
  asked for **were defined nowhere**, so `glyphMargin: true` reserved a column
  and drew nothing in it; and `applyDecorations` became async, so two debounced
  runs could race — it now carries a generation guard.
* **Byte locations** for model artifacts, in text, JSON and SARIF.
* **Token extents** everywhere a tool states them.
* **`clang-tidy` is useful with no configuration** — a bug-finding check set is
  injected only when no `.clang-tidy` is found, searching upward from each source
  file the way clang-tidy's own search does, because `--checks` is *appended* to a
  config file's `Checks` key rather than replacing it.
* **CERT ids survive from `clang-tidy`** — an aliased check arriving as
  `[bugprone-x,cert-err34-c]` becomes one rule plus a `Cert` taxonomy reference,
  not one run-on id that nothing could match.
* **`{artifact}` placeholder**, and `sda scan --artifact` now populates
  `Target::artifact`, which it never did.
* **`tests/`, `benches/` and `examples/` are test code** to the Rust analyzer,
  and `MODEL.1` exempts test lines the way `MODEL.3` always did — both with
  negative tests proving the same code under `src/` is still reported.
* **Deductive verification, and the seam between it and the inductive half.**
  `crates/sda-core/src/verification.rs` (`Modality`, `Boundary`, `ProofObligation`,
  `Assumption`, `AssumptionSupport`, `VerificationLedger`) plus
  `crates/sda-engine/src/neurosymbolic.rs` (`SystemMap`, `adjudicate`, `summarize`) and
  two new verdicts, `Proved` and `Assumed`. The design and its rationale are in
  `README.md` under *Deductive and inductive evidence*; the short version is
  that the two modalities are joined by assume-guarantee across a declared
  boundary and are **never averaged**, and that a discharged obligation resting
  on a premise only a probe campaign supports is demoted to `Assumed` rather
  than promoted to `Proved`.

  Three things worth knowing before extending it:

  - `Evidence::is_proof` **was renamed to `is_defect_witness`**. It always meant
    "a runtime observation that demonstrates a real defect" — an existential
    claim — and that name became actively misleading beside `Evidence::Proof`,
    which carries universal ones. `is_discharged_proof` is the new predicate for
    the other direction.
  - A proof settles a finding only when the obligation **names the rule**
    (`ProofObligation::settling`). Location overlap is not enough, for the same
    reason `correlate` demands CWE agreement before a runtime fault may confirm
    a static finding: `Proved` is the strongest verdict the toolkit issues and
    must not be awarded for a coincidence.
  - Deduction runs **before** correlation, and only `Adjudication::unadjudicated`
    is handed on. Merging both engines' answers would let `Unreached` overwrite
    `Proved` on any proved line that also happens to be cold.

  `sda scan crates` caught an `unreachable!` in the first draft of
  `not_checked_lines` — a genuine `RUST-2024-PANIC.2`, fixed by matching in
  place rather than deviated. The self-scan earning its keep on new code.

  **Deliberately not done:** no adapter parses any prover's output. `ext.verus`,
  `ext.kani`, `ext.creusot`, `ext.marabou` and `ext.abcrown` are in the ontology
  with their real limits, and that is all. Writing a parser from documentation
  is how `ext.modelscan` shipped fully green while unable to read a byte of what
  its tool wrote, and both coverage parsers found their real producers diverging
  from the published format — so each of these waits for output captured from a
  real run, the way `crates/sda-engine/tests/fixtures/` already does. Also not
  done: no CLI surface (`sda verify` or similar), no MCP tool, and the GUI has
  verdict styling for the two new verdicts but no ledger view.
* **The target scale is 10^6 to 10^12+ parameters**, which settles a question the
  neurosymbolic design left open and narrows it usefully. No catalogued verifier
  reaches that: complete methods handle thousands of neurons, bound propagation
  handles convolutional networks around `DEDUCTIVELY_TRACTABLE_PARAMETERS`
  (10^6), and nothing handles attention at any size. So **the symbolic guard is
  the entire safety case**, and three things follow, all now in code:

  - A neural `Component` carries an optional parameter count, and one above the
    ceiling gets an `sda.intractable[...]` line in `NOT CHECKED` naming the size
    and the reason. An omitted check and a passed one look identical in a
    report, and at this scale it can never pass. **An unstated count is treated
    as intractable, not as small** — the only place in the module where a
    missing value could have been read optimistically, and it is not.
  - `AssumptionSupport::Inductive` now records a `SearchStrategy`
    (`Random` / `Adversarial` / `ExhaustiveOverRegion`) beside the trial count.
    Over an unbounded input space the count alone is close to meaningless, and
    the report prints what the search was worth rather than just how many.
  - `ext.marabou` and `ext.abcrown` stay in the ontology with their scale limits
    spelled out, so `sda tools gaps` answers *why* nothing covers the model
    instead of appearing to offer a tool that cannot run.

  **Worth doing next, and not done:** `guard::interposed` — that every model
  output reaches the effector through the guard — is now carrying almost the
  whole claim, and it is currently an `AssumptionSupport::RuntimeGuard`. It is
  an architectural reachability property, which is a *statically checkable*
  question and one the toolkit already has a capability for
  (`Capability::TaintAnalysis`). Discharging it from a taint result rather than
  trusting it would move the single most load-bearing premise in an LLM-scale
  system from assumed to proved.
* **Neural tractability is decided by architecture, not size** — a correction to
  the entry above, which gated on a single `DEDUCTIVELY_TRACTABLE_PARAMETERS`
  ceiling and said "no method handles attention at any size". **That claim was
  wrong.** Small transformers have been verified (Shi et al. 2020; DeepT), over
  epsilon-balls in *embedding* space — which is a real result and not the one a
  reader assumes, since a bound over an embedding ball says nothing about the
  tokens that map into it. The constant is gone and `NeuralProfile` replaces it.

  What actually decides reach is the operator set. Affine, ReLU and max-pool are
  piecewise-linear, so bounds are exact between kinks and a complete method can
  decide rather than bound. Softmax, `tanh`, a product of two input-dependent
  tensors, and unbounded recurrence each cost precision or decidability. So a
  four-million-parameter CNN is in reach, an MLP of the same size is not, and a
  transformer of the same size is neither — three answers from one number, which
  is why the number was the wrong gate. There is a test asserting exactly that.

  `NeuralProfile { architecture, parameters, sequence_bound, input_region }`
  yields a `Tractability` of `Reachable` / `Underspecified` / `Decompose` /
  `ResearchOnly` / `OutOfReach`, and `adjudicate` turns each into its own
  `NOT CHECKED` line. The five are distinguished because they call for different
  responses:

  - `Underspecified` is closable **today**, by the user, and is the case worth
    surfacing hardest: no declared input region (every neural verifier bounds a
    *region*, not a network), or a recurrent net with no horizon to unroll to.
    That horizon is the same shape of caveat as CBMC's unwinding bound, and is
    worded to match.
  - `Decompose` is the VAE/GAN answer. The pair is not one function and a
    sampling step is not a function at all, but the decoder or the generator on
    its own is an ordinary feed-forward network that can be bounded over a latent
    region. Declaring that half as its own component is the move.
  - `ResearchOnly` (transformer) and `OutOfReach` (Mamba/SSM, oversized, or an
    unclassified `Architecture::Other`) cannot be closed and should stop being
    carried as pending work.
  - An undescribed neural component gets `sda.undescribed`. An unmeasured model
    is not a small one — the only place in the design a missing value could have
    been read optimistically, and it is not.

  `ext.nnenum` joins the ontology (complete for ReLU feed-forward and
  convolutional nets, thousands of neurons, returns a concrete counterexample);
  `ext.marabou` and `ext.abcrown` had their limits corrected to match the above,
  including the embedding-space caveat that the earlier wording denied outright.

  **Still true, and now carrying more weight:** for the 10^6-10^12+ range the
  guard remains the entire safety case, so `guard::interposed` discharged from a
  taint result rather than trusted is still the highest-value next piece.
* **`guard::interposed` is proved rather than trusted** — the piece the two
  entries above both named as highest-value, now in `crates/sda-engine/src/interposition.rs`.
  A `FlowGraph` of declared component-to-component dataflow plus `Role::Guard` /
  `Role::Effector` on `Component`, and `verify()` walks every simple path from
  each neural component to each effector, emitting a discharged or failed
  `ProofObligation` per pair with the bypassing path as the counterexample.

  **Read the claim carefully, because it is deliberately weaker than it looks.**
  This does not make interposition unconditional. It swaps one large premise —
  *the guard is interposed* — for a smaller and much more checkable one: *this
  declaration matches the code*. That residual premise is emitted as
  `interposition::FAITHFULNESS`, `Undischarged` on purpose. Reporting the swap
  as a finished proof would be the laundering `neurosymbolic` refuses elsewhere.

  - **Taint refutes, never confirms.** A taint flow from a model to an effector
    that crosses no guard fails the obligation outright, whatever the declaration
    said — there is a test where the declaration alone reports interposed and the
    observed flow overturns it. A clean taint run establishes nothing: the
    catalogued taint providers are heuristic, and this is the same asymmetry
    `sda_ai::probe` has always stated about probes. A taint finding with no
    `Evidence::Trace` is skipped rather than guessed at.
  - **`unpaid_premises` walks the proved-by chain**, and this was a genuine hole
    the interposition work exposed rather than a hypothetical. `adjudicate` used
    to check only an obligation's *direct* assumptions, so a guard proof citing
    an interposition proof citing an unverified declaration would have come back
    `Proved`. It now comes back `Assumed`, and there is a test asserting the
    direct check sees nothing wrong in exactly that setup — plus one asserting a
    cycle between two proofs terminates.
  - Absent guards and absent effectors are reported before any path is walked
    (`sda.no-guard`, `sda.no-effector` — the latter worded as "the absence of a
    question", not a clean answer), an edge naming an undeclared component is
    reported because a typo there removes a path silently, and enumeration past
    `MAX_PATHS` reports NOT established rather than concluding from the paths it
    happened to visit first.

  **Not done:** the flow graph is built in code, with no `.sda/architecture.toml`
  to declare it from and no CLI surface. That is the natural next step and is
  mostly plumbing — the analysis underneath it is complete and tested. Also still
  true: no adapter parses any prover's or taint tool's output into these types;
  `verify()` takes `&[Finding]` and the existing `ext.codeql` / `ext.semgrep`
  SARIF path already produces `Evidence::Trace`, so that seam is ready but
  unwired.
* **`.sda/architecture.toml` and `sda verify`** — the plumbing the entry above
  listed as not done. `sda_rules::ArchitectureDeclaration` parses it beside
  `deviations.toml` and `scope.toml` in `ProjectConfig::discover`;
  `sda_engine::from_declaration` converts it to a `SystemMap` and `FlowGraph`;
  `sda verify [path] [--taint <report>]` runs the proof and exits non-zero when
  it is refuted, because a bypass is a failed safety case rather than a warning.

  Validation follows the scope register's discipline, and the stakes are why: a
  bad scope rule over-excludes and under-reports, while a bad architecture entry
  produces a *proof* about a system nobody is shipping. So a component with no
  path, an unknown `boundary`, a duplicate name, a `path = "."`, an
  `architecture` on a symbolic component, or a self-edge is rejected and
  reported. A `boundary = "neural"` component with `role = "guard"` is refused
  outright — a guard that is itself a model moves the premise rather than
  discharging it. An edge naming an undeclared component is *kept* and warned
  about, because dropping it would hide the typo that removed a path.

  **A real ordering bug turned up running it end to end**, and it was in the
  advice rather than the analysis. A 7B transformer with no declared input
  region came back `sda.underspecified` — "declare an input region" — because
  the missing-input check ran before the size ceiling. That advertises a fix
  that does not exist: no region makes a 7B transformer tractable. Size is now
  checked first, it reports `sda.intractable`, and there is a test pinning the
  order. An actionable-looking line that leads nowhere is worse than a blunt one.

  **Still not done:** no adapter runs a taint tool for you — `--taint` reads a
  report you already have, as SARIF or an `sda` JSON report, and the
  `ext.codeql` / `ext.semgrep` SARIF path already produces the
  `Evidence::Trace` frames `verify` reads. Nor is any prover's output parsed
  into `ProofObligation`s; the ledger is still built in code. Both wait on
  fixtures captured from real runs, for the reason the whole `tests/fixtures/`
  directory exists.
* **The taint refutation channel met the real Semgrep, and it was inert.** This
  is the entry the two above were building toward, and it went the way
  `ext.modelscan` went — except caught before shipping rather than after.

  `sda_engine::interposition` refutes from a taint *flow*: the endpoint alone
  cannot say whether a guard was crossed. SARIF has `codeFlows` for that, and
  `semgrep --dataflow-traces` documents itself as "only affects text and SARIF
  output". **Real Semgrep OSS 1.176.0 prints the trace in its text output and
  emits no `codeFlows` whatsoever in its SARIF** — `properties` is `{}`, and
  `--json` carries no `dataflow_trace` either. Verified by running it: install
  with `python3 -m venv ~/sgvenv && ~/sgvenv/bin/pip install semgrep`, program
  and rule in `tools/semgrep-taint/`, fixture at
  `crates/sda-engine/tests/fixtures/semgrep-1.176.0-taint.sarif`.

  Two things followed, and the first is the serious one.

  - **`parse_sarif` never read `codeFlows`, so every real taint finding reached
    `verify` with no trace and was silently skipped — producing a clean
    interposition proof from a report that could not be read.** I built that
    seam two entries ago and described it as "ready but unwired"; it was worse
    than unwired, it was quietly wrong. A traceless finding landing on an
    effector is now `sda.taint-untraced`, a report where every finding is like
    that is `sda.taint-inert`, and `sda verify --taint` prints findings loaded
    *and* findings carrying a trace, always both. `summarize` says "a proof that
    a blind instrument did not contradict is not a proof that was tested".
  - **`codeFlows` parsing is still unwritten, deliberately.** Writing it from the
    SARIF specification would have produced a parser that is correct, complete,
    and never exercised by the canonical free provider — the exact shape of the
    `ext.modelscan` defect. It waits for a fixture from a provider *observed* to
    emit the field. CodeQL is the likely candidate.

  Note for anyone reproducing: WSL clears `/tmp` when the distro restarts, so the
  venv lives in `~`. And Semgrep OSS taint is intra-procedural — a flow through a
  module-level global across two functions is not tracked, and produces zero
  findings rather than an untraced one.
* **Verus met its real prover, and the obvious integration was blind.** The
  deductive side had never touched a real tool until now; it has, and the result
  is the third fixture-vindication in this file.

  `tools/verus-guard/guard.rs` is written so the prover must both succeed and
  fail — `clamp` satisfies its postcondition, `unchecked` declares the same one
  without the guard and cannot. Verus 0.2026.08.30.b432e82 on rustc 1.97.1,
  WSL Debian; install steps and the captured output are in that directory's
  README. Fixtures: `crates/sda-adapters/tests/fixtures/ext.verus.{json,txt}`.

  Three findings, and they compose into one:

  - **Verus exits 0 on a failed proof.** `verification results:: 3 verified, 1
    errors`, `error: aborting due to 1 previous error`, `$? == 0`.
  - **`--output-json` records that something failed and never which thing.** Its
    `func-details` map has `obligation_proof_notes` and `failed_proof_notes` per
    function, and `guard::unchecked` — the one that failed — carries
    `failed_proof_notes: []`, identical to every function that passed. The only
    failure signal in the JSON is the aggregate `"errors": 1`.
  - **The failing obligation's message and location are stderr-only.**

  So a failed proof is invisible from every direction an integrator would look:
  exit code clean, per-function JSON clean, and only an aggregate integer and an
  unstructured text stream saying otherwise. `parse_verus(json, diagnostics)`
  therefore takes both channels and *reports* their disagreements rather than
  reconciling them — errors that cannot be located, a `success: true`
  contradicted by a diagnostic, an error count of zero on a failed run (a crash,
  not a verification result). `sda verify --proofs <json> --proof-log <stderr>`
  exits 1 where the prover exits 0, and says so in the output.

  **Only failures become `ProofObligation`s**, deliberately. Verus names what it
  could not prove and only counts what it could; three anonymous `Discharged`
  obligations would be claims no tool made. Pairing a discharged obligation with
  a rule still requires someone to write `settling(...)` by hand, which is the
  right place for a human to be in the loop.

  Reproduction notes: Verus pins an exact rustc (`rustup install
  1.97.1-x86_64-unknown-linux-gnu`) and will not run without it. The release zip
  is ~300 MB. Also fixed in passing: the `<...>` placeholders in the semgrep and
  three-sins repro commands are gone — `wsl` starts in the translated working
  directory, so `cd tools/...` just works, and both commands were re-run to
  confirm they do.

  **Still unwritten:** `codeFlows` parsing, waiting on a provider observed to
  emit it; and no adapter *invokes* Verus — `--proofs` reads output you already
  have, the way `--taint` does.
* **`codeFlows` is parsed, and the whole loop now closes on real bytes.** The
  last two "still unwritten" items from the entries above are done, and getting
  there cost two real bugs.

  CodeQL 2.26.4 (855 MB bundle, `codeql database create` + the stock
  `Security/CWE-078/CommandInjection.ql`) over `tools/codeql-taint/` — a program
  split into `policy/`, `guard/`, `telemetry/` and `actuator/` with one guarded
  path and one bypass. It reports a **twelve-step interprocedural flow** through
  the relay and correctly does not report the guarded route. Fixture:
  `crates/sda-adapters/tests/fixtures/ext.codeql-taint.sarif`, shared with
  `crates/sda-engine/tests/fixtures/codeql-2.26.4-taint.sarif`.

  - **`parse_sarif` never read `codeFlows`.** Every taint finding arrived as an
    endpoint and `interposition` skipped it. The pre-existing `ext.codeql.txt`
    fixture contains **zero** `codeFlows` and Semgrep emits none, so nothing in
    the repository could have exercised the field — which is exactly why the seam
    stayed broken through two entries that described it as ready.
  - **CodeQL writes CWEs as `external/cwe/cwe-078`**, lowercase and zero-padded,
    not the `CWE-78:` form `cwe_from_tags` knew. Correlation matches a runtime
    witness to a static finding through the CWE, so **no real CodeQL finding
    could ever have been confirmed** — the identical defect that function already
    carried a comment about for Cppcheck and Semgrep, sitting one convention
    away. Both forms are now recognised, with a test that they agree and one that
    a CWE mentioned in prose is still not a claim.

  Two false starts worth recording, because both produced *zero results* rather
  than an error: `sys.argv` is not a `RemoteFlowSource` for that query, so the
  program needed a real remote entry point; and CodeQL follows imports to track
  flow between files, so a layout where `from policy.serve import ...` does not
  resolve yields nothing at all.

  `crates/sda-engine/tests/codeql_refutes_interposition.rs` runs the chain
  end to end — declaration proves interposition, real CodeQL refutes it, the
  bypass is named — parsing the fixture through the same `parse_sarif` a user's
  report goes through rather than hand-building a `Finding`, which is the failure
  this seam already walked into once. `sda verify --taint` exits 1.

  Also in passing: `parse_verus_findings` turns failed obligations into
  `Finding`s so they reach reports and SARIF, emitting none for the obligations
  that passed (Verus names none of them). And `OutputFormat::ModelScanJson`
  carried a stale doc comment saying its fixture was written from documentation
  and never checked against the real tool — the fixture *is* real, captured from
  modelscan 0.8.8, and the test says so. A note that tells a reader a real
  fixture is a reconstruction is the worst kind of stale, given what the rest of
  this file is about.

  **Still not done:** no `AdapterSpec` invokes Verus. The framework carries one
  output channel per adapter (`output_on_stderr: bool`) and Verus needs both, and
  `{target}` is an analysis root while Verus wants a file — so a spec would be a
  tool that cannot run, which is the shape of defect this project exists to
  avoid. `--proofs`/`--proof-log` read output you already have.
* **`analysis.verify` is on the MCP surface.** The neurosymbolic work had built a
  CLI and left the agent surface behind, which is a gap in the project's own
  central claim — "agentic-first" means a capability that only exists as a
  subcommand is half-shipped.

  `dispatch("analysis.verify", {path, taint?, proofs?, proof_log?})` returns the
  interposition result, any bypasses with their paths, the prover summary, and
  `not_checked`. Three design points, all about what an agent can and cannot
  infer from JSON alone:

  - **An undeclared project returns `interposed: null`, not a boolean.** `false`
    would read as a refutation and `true` as a proof, and neither happened. This
    is the case an agent is most likely to misread, and there is a test for it.
  - **The tool description publishes the premise its own result rests on** —
    `flow::declaration-faithful`, that a taint report can only refute, and that
    `null` is not a pass. An agent has no source to check the answer against,
    only the JSON and the description, so anything not in one of those two is not
    available to it. A test asserts the description carries all three.
  - **`taint_findings` and `taint_findings_with_flow` are both returned.** A
    report whose findings carry no dataflow trace cannot refute anything, and one
    number without the other lets an inert instrument read as a check that passed
    — the same failure the CLI already guards.

  `crates/sda-agent/tests/verify_over_mcp.rs` drives the real dispatch path
  against the same CodeQL fixture the engine and adapter tests use. Also fixed:
  the README said "Sixteen tools" and there are seventeen; counted rather than
  incremented.

  **Deliberately still not done: no `AdapterSpec` invokes Verus**, and on
  reflection it should not until two framework facts change. `AdapterSpec` has
  `output_on_stderr: bool` — one channel — and Verus needs both, since its JSON
  counts failures and its stderr names them. And `{target}` is an analysis root
  while Verus wants a crate root file with its own toolchain pin, so a spec would
  run the prover over every `.rs` file in a project and fail on nearly all of
  them. Shipping that would be a tool that cannot run, dressed as coverage. The
  honest prerequisite is an `OutputChannel::Both` mode and per-crate targeting;
  until then `--proofs`/`--proof-log` and `analysis.verify` read output you
  already have.
* **`ext.verus` is a real adapter, and building it needed the framework change I
  said it needed.** The two entries above listed this as deliberately not done
  and named the prerequisites; both are now met, and running the prover the
  second way cost another bug.

  - **`AdapterSpec::output_on_stderr: bool` became
    `OutputChannel::{Stdout, Stderr, Both}`**, with `parse_output_channels`
    taking both texts. Verus is the first tool here where neither stream is a
    result on its own — the JSON counts the failures and the diagnostics name
    them — and the two are kept apart rather than concatenated, so a parser can
    tell which of them is silent.
  - **Targeting turned out to be a non-problem, and only reading the tool showed
    that.** `cargo-verus` ships in the release, and `cargo verus verify
    --manifest-path {manifest} -- --output-json` is the crate-level entry point —
    the same shape as `cargo clippy` and `cargo miri`, which the framework
    already handled. The earlier worry about running the prover over every `.rs`
    file was about the standalone binary, not the tool people actually use. A
    `{manifest}` placeholder was added; pointing a cargo subcommand at a
    directory makes it walk upward and analyse whatever crate it lands in.
  - **A new bug, found by driving the same prover the other way.** Standalone
    `verus` ends its stderr with `error: aborting due to 1 previous error`, which
    the parser skipped. `cargo verus verify` ends with ``error: could not compile
    `vnew` (bin "vnew") due to 1 previous error`` instead — also an `error:`
    line, also not a proof obligation, and **not** skipped. Every failing
    cargo-driven run gained a phantom unlocated failure. Fixed, with a symmetric
    guard (`failures > errors`) that would have caught it, and a second fixture
    `ext.verus-cargo.{json,txt}` captured from a real `cargo verus` run.

  **A correction to the entry above.** It says flatly that "Verus exits 0 on a
  failed proof". That is true of the **standalone binary** and false of
  `cargo verus verify`, which exits 101. The trap is real and depends on how the
  prover is driven; stating it unconditionally would send someone to add a
  workaround they do not need. Corrected in `README.md`, the CLI note,
  `parse_verus`'s doc comment and `tools/verus-guard/README.md`.

  **Also:** a crate with no specifications is now reported as vacuous rather than
  clean — `cargo verus verify` on ordinary Rust builds it, verifies nothing and
  exits successfully, which the adapter would otherwise have surfaced as a clean
  deductive result. And the repo's own `every_spec_has_a_fixture_behind_it` test
  caught the new spec immediately, which is the discipline working: the fixture
  harness grew a `secondary` field rather than the spec shipping uncovered.
