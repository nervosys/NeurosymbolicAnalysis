# StatodynamicAnalysis

**Agentic-first statodynamic analysis for safety-critical code and the AI models
now embedded inside it.**

Static analysis says *this could happen*. Dynamic analysis says *this did
happen* — and, just as importantly, *this line never ran at all*. Running both
and correlating them is **statodynamic** analysis, and it turns two piles of
findings into a ranked set of claims with stated evidence:

| static says | runtime says | verdict | what it means |
|---|---|---|---|
| suspect | defect at the same place | **Confirmed** | fix this first |
| suspect | executed 500 times, no fault | **Refuted** | probably a false positive |
| suspect | never executed | **Unreached** | the claim is untested, *not* clean |
| silent | defect | **Unpredicted** | a gap in the rule set, not the code |

That third row is the one most tools get wrong. Treating "no runtime defect" as
evidence of correctness, without checking whether the code ever ran, silently
converts a coverage hole into a clean bill of health.

---

## Install

The current release is **1.0.2**. Nothing is signed yet, so Windows SmartScreen
and macOS Gatekeeper will warn before the first run.
Each release carries a `SHA256SUMS` file; check a download against it before
installing.

| platform | GUI workbench | `sda` CLI only |
|---|---|---|
| Windows x64 | `StatodynamicAnalysis_<version>_x64-setup.exe` (per-user; adds `sda` to your `Path`) | `sda-<version>-x86_64-pc-windows-msvc.zip` |
| Linux x64 | `.deb` (Ubuntu 22.04 or later) or `.AppImage` | `sda-<version>-x86_64-unknown-linux-musl.tar.gz`, a static binary for any x86_64 Linux |
| macOS | built only on request, see below | `sda-<version>-aarch64-apple-darwin.tar.gz`, `…-x86_64-apple-darwin.tar.gz` |
| FreeBSD x64 | none: Tauri does not support the BSDs | `sda-<version>-x86_64-unknown-freebsd.tar.gz` |

Every archive holds the licence and the third-party notices for that target.
The FreeBSD CLI is cross-compiled and has not been run on FreeBSD. The macOS GUI
is withheld by default because the `objc2` crates it links are
derived from Apple's SDKs, and their own licence leaves open whether they may be
redistributed.

To build from source you need Rust 1.88 or later:

```bash
cargo install --path crates/sda-cli --locked     # the `sda` CLI
bash tools/package-cli.sh <target-triple> dist   # a release archive, with notices
```

The workbench needs Node 22 and the Tauri CLI; `gui/README.md` covers it.

---

## First scan

You need a Rust toolchain and nothing else. A scan of plain C source runs no
compiler, needs no `.sda/` configuration and calls no external tool, so it works
on a file that does not build. Point it at your own project:

```bash
cargo build -p sda-cli                                  # builds the `sda` binary
cargo run -p sda-cli -- scan path/to/your/c-project     # findings, then what was not checked
cargo run -p sda-cli -- rules audit                     # what a clean result would and would not mean
```

Run against a 28-line C file with a switch fall-through, a `malloc` and an
`if`/`else if` with no `else`, the first scan prints (abridged where it says
`...`; the file has 12 findings in all):

```
my-c-project: 1 c
no .sda/ configuration found; using built-in catalogues and no deviations
StatodynamicAnalysis report for my-c-project
generated 2026-10-31T17:41:06.169501Z

main.c:1:1: MISRA-C-2023-21.6 (medium)
  `stdio.h` is not permitted in this profile; on a freestanding or safety-critical target its facilities pull in unbounded code, allocation, or I/O
  sda.static.c · confidence high · static

main.c:7:9: MISRA-C-2023-16.3 (medium)
  this switch clause has statements but no unconditional `break`, so control falls into the next clause — the single most common switch defect
  sda.static.c · confidence high · static

...

Summary
  low: 4
  medium: 8

NOT CHECKED — do not read a clean result as coverage of these:
  ext.cppcheck: external provider not enabled (native-first policy)
  ...
  sda.correlate: no runtime observation reached this run, so no static finding was confirmed or refuted; this is a static-only result
```

The `NOT CHECKED` block is the part to read after the findings: each provider
it lists as not enabled is one this scan did not run, and `sda.correlate` says
no runtime data was involved. Adding `--fail-on medium` turns the same scan into
a gate, which exits `1` on this file because it has medium findings.

---

## The three commitments

**1. Our own engines are the default; industry tools are accepted, not required.**

A bare `sda scan` runs native Rust engines: no compiler, no configuration, no
external process, milliseconds per file, and it works on code that does not
build. Cppcheck, clang-tidy, CodeQL, Semgrep, Valgrind, Miri and the rest are
first-class providers behind the same trait — enabled per-tool with `--with ext.cppcheck`, pointed at a specific binary with `--with ext.cppcheck=/opt/cppcheck-2.13/bin/cppcheck`, or enabled wholesale with `--with all`. The default is native-only
because a first run on a new machine should produce real results rather than a
list of things to install, and because a compliance run that depends on
whichever tool version is on `PATH` is not reproducible.

**2. It says what it did not check.**

Every report ends with a `NOT CHECKED` section, and it is not suppressible. Every
guideline records how it is checked, and `sda rules audit` will tell you plainly:

```
MISRA C:2023: 210 guidelines catalogued. 80 are exercised by a default run;
a clean result is evidence of conformance for 65 of them (30%). 57 are
undecidable in general.
```

That claim is enforced, not asserted. Every guideline listed as implemented has a
**fixture**: a snippet that must produce that exact finding, or the build fails.
A list of rule names can be kept tidy while the code does nothing — the C++
analyzer once passed every list-based check while emitting no findings at all,
because its checks named MISRA C numbers that its own catalogue does not contain.
A fixture cannot be satisfied by bookkeeping.

**3. It does not invent citations.**

MISRA guideline text is copyright MISRA and is not reproduced. Where a rule
*number* cannot be stated with confidence — all of MISRA C++:2023, whose
numbering was rebuilt against the C++ clause structure — the checks still run and
still report, but each finding cites the **clause** and carries the reason:

```
demo.cpp:17:15: MISRA-CPP-2023-8.2.1 (medium)
  `(void *)` is a C-style cast: it silently selects between `static_cast`,
  `const_cast` and `reinterpret_cast`, so the reader cannot tell which conversion
  is happening, and a search for dangerous casts will not find it.

  Cited as MISRA C++:2023 clause 8 (rule number unconfirmed) — the guideline
  number is not confirmed against the published document.
```

Drop a licensed list at `.sda/misra-cpp-2023.toml` and those become real citations automatically — selectively, guideline by guideline. An imported 8.2.2 is cited by number; a 12.2.1 that is still absent keeps its clause and its caveat.

The built-in catalogues carry guideline numbers, categories and decidability,
and no guideline titles: a finding without an imported title is cited as, for
example, `MISRA C:2023 16.3`. If you hold the documents, `sda rules import
--standard misra-c-2023 your-list.toml` merges your own titles over the
catalogue.

---

## Project configuration

Compliance state belongs in version control next to the code, not in a command
line. A `.sda/` directory — found by walking upward, like `.git` — is picked up
automatically:

```
.sda/
  deviations.toml        approved departures, with rationale and approver
  scope.toml             what is not part of the delivered product
  misra-c-2023.toml      an authoritative guideline list, merged over the built-in one
  misra-cpp-2023.toml
```

**Scope and deviations are different claims**, and the report keeps them apart. A
deviation says *this rule is violated and we accept it*; scope says *this rule
does not apply, because this file is not in the product*. Only the second removes
files from the analysis, so it is held to the same standard and reported harder:

```toml
[[excluded]]
path = "tests/"                                    # prefix, on segment boundaries
reason = "unit test harness; not linked into the delivered image"
approver = "a.erickson"
```

An excluded file is never handed to an analyzer — filtering findings afterwards
would let coverage be computed over files the report claims it did not read. What
it removed is stated with a **count**, in the section a clean result cannot hide:

```
NOT CHECKED — do not read a clean result as coverage of these:
  sda.scope: 2 files under `tests/` are outside the declared analysis scope
    (unit test harness; not linked into the delivered image — a.erickson)
```

Paths are relative to the directory holding `.sda/`, not to the directory being
scanned, so a rule means the same thing whether you scan the project or one
subdirectory of it.

A rule with no `reason` or no `approver` is rejected and does not narrow the
scan. A rule that removed nothing says which of three things happened: it names
nothing in the project and may be stale, it lies outside this particular scan, or
it was scanned and holds no analyzable file. `path = "."` is rejected outright —
excluding the root would make any project report clean. Absent the file,
everything discovered is in scope.

Deviations are **enforced, not trusted**. A `Mandatory` guideline can never be
deviated, a record without a rationale or an approver is rejected, and every
rejection is reported in the run rather than silently honoured or silently
dropped:

```
configuration from examples/firmware\.sda, 1 deviation(s), 1 problem(s)
warning: deviation for `MISRA-C-2023-9.1` rejected: `MISRA-C-2023-9.1` is
         Mandatory and may never be deviated

  ...
  medium: 5
  suppressed by deviation: 3
```

**An external tool's finding can be deviated too, and is counted separately.** A
team that enables `--with ext.clippy` in CI has to be able to record a finding it
has examined and accepted; the alternative is to change the code or read the
finding forever. So an id in no standard's namespace — `clippy::needless_range_loop`
— is accepted, while anything that *claims* to be a guideline is still held to the
catalogue and a mistyped `MISRA-C-2023-99.9` is rejected exactly as before.

The two are never added together, because they are not the same claim:

```
sda rules audit

Deviations on record: 9 (9 against catalogued guidelines, 0 against external tools).
```

A conformance argument resting on a guideline is one thing; a judgement about a
tool's opinion is another, and a report that merged them would let the second
quietly strengthen the first. An external id is validated against nothing — this
toolkit does not have clippy's rule list — which is safe in the direction that
matters: a deviation matching no finding suppresses nothing, so a typo leaves the
finding visible rather than hiding it.

---

## Try it

```bash
cargo build --release
cargo run -p sda-cli -- scan examples/firmware
```

```
src/main.c:14:9: MISRA-C-2023-16.3 (medium)
  this switch clause has statements but no unconditional `break`, so control
  falls into the next clause — the single most common switch defect
  sda.static.c · confidence high · static

...

src/main.c:40:5: MISRA-C-2023-15.7 (medium)
  this chain of 2 `if`/`else if` branches has no final `else`; nothing states
  what happens when every condition is false, so a future value silently falls through
  sda.static.c · confidence high · static

...

NOT CHECKED — do not read a clean result as coverage of these:
  ...
  sda.correlate: no runtime observation reached this run, so no static finding was
  confirmed or refuted; this is a static-only result
```

Add an artifact and the same findings get adjudicated. This one is
`examples/firmware/fake_instrumented.bat`, a Windows script that writes three probe
records by hand, so it shows the mechanism and proves nothing about a program. No
binary is built from `examples/firmware/src/main.c`, and any other path stops with
`does not exist; build it first`:

```bash
cargo run -p sda-cli -- scan examples/firmware --artifact examples/firmware/fake_instrumented.bat
```

```
src/main.c:47:5: MISRA-C-2023-21.3 (high) [confirmed]   ← escalated, confidence certain
src/main.c:34:26: MISRA-C-2023-7.1 (low) [refuted]      ← demoted after 50 executions
src/main.c:14:9: MISRA-C-2023-16.3 (medium) [unreached] ← untested, severity untouched

Correlation
  confirmed: 1
  refuted: 1
  unreached: 15
```

All four verdicts have been produced by a **real compiled instrumented binary**,
not by canned probe records: a C program built with MSVC that links
`shim/sda_probe.h`, leaks a `malloc`, runs one line 50 times, and guards another
behind a branch that never fires. The scan returns `21.3` and `D4.12`
**confirmed** at the allocation — escalated, confidence certain — the hot line
**refuted** and demoted to `info`, and the guarded line **unreached**. The
wording holds up under inspection too: unreached says *"Either it did not execute
or it is not instrumented"* rather than claiming the stronger thing, and refuted
says *"a likely false positive, not proof of correctness — the executions may all
have taken the same path"*.

**Confirmation requires more than proximity.** A runtime defect only confirms a
static finding when it is the same *kind* of thing — matched through the weakness
classes (CWE) each carries. Above, a memory leak confirms Rule 21.3, which is
about dynamic allocation; it would not confirm an advisory about typedef widths
two lines away. An earlier version confirmed on nearness alone, and "confirmed"
is the strongest claim this tool makes, so it had to stop meaning "something bad
happened nearby". A defect no static rule anticipated is reported as
`unpredicted` instead — a gap in the rule set, not a vindicated suspicion.

**Every one of those adapters has now been run against its real tool, and ten of
the eleven encounters found a defect** — eight of them in adapters that were fully
green, fixture-tested and passing a clean self-scan. The failures are not subtle
in hindsight and were invisible in advance: `ext.valgrind` declared a format
matching not one line Memcheck emits; `ext.miri` read stdout, where Miri prints
`"success":true` while reporting the undefined behaviour on stderr; `ext.codeql`
asked for `--output=-` and CodeQL wrote a file literally named `-`, leaving prose
on stdout and exiting 0. A spec that compiles and a spec that works are different
claims, and no fixture written from a tool's documentation has ever caught the
difference. **No fixture in this repository is a reconstruction any more**, and a
test enforces it.

**And the same four verdicts are reachable with no SDA instrumentation at all.**
An external dynamic tool reports *defects* and counts no lines, so on its
evidence alone `correlate` receives no measurement and only `confirmed` is
available — a tool that ran the program could corroborate a static finding and
could never contradict one. `--coverage` supplies the missing half from an LCOV
`.info` or gcov's own `.gcov`, and it accepts a directory because gcov writes one
file per translation unit. The `prog` binary is gitignored, so a clean checkout
does not have one: build it first with the commands in `tools/coverage-wsl/README.md`,
which run gcc and gcov inside WSL. Without it the command stops with
`artifact ... does not exist; build it first`.

```bash
sda scan examples/coverage --with ext.valgrind   --artifact <abs>/examples/coverage/build/prog   --coverage examples/coverage/build
```

```
Correlation
  confirmed: 2      ← Memcheck lost 16 bytes at main.c:30
  refuted: 1        ← gcov counted 40 executions of main.c:37, nothing faulted
  unreached: 4      ← gcov measured main.c:21 at zero
  inconclusive: 3
```

Driven against Valgrind 3.24.0 and gcov 14.2.0; `tools/coverage-wsl/README.md`
has the commands. Callgrind was the obvious third format and is **wrong**: its
cost column is instructions retired at a line, not executions of it, and feeding
it to a threshold documented in executions would refute findings on the strength
of a long loop body. The report also states, in `NOT CHECKED`, that the counts
come from the run that produced the coverage file and not provably from the run
the dynamic tool inspected.

### Where the evidence lives is not where the source lives

Two flags exist because the ordinary way to build a project puts its artefacts
somewhere other than the source tree — and because the only way to analyse a
checkout you must not write into is to keep everything outside it.

`--compile-commands <FILE>` names a `compile_commands.json` that is not under the
scan root, which is what an out-of-tree CMake build produces:

```bash
cmake -S <repo> -B /tmp/build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
sda scan <repo>/src --with ext.clang-tidy --compile-commands /tmp/build/compile_commands.json
```

`--tool-timeout <SECONDS>` bounds each external tool. A tool that is stopped is
reported as having checked an unknown part of the target — never as clean, and
never as "no findings". Raise it for a large project rather than reading the
default as a verdict.

### The target does not have to be a program this machine can run

Firmware is the case the toolkit was built for and the one a host cannot
execute. `shim/sda_probe.h` emits the same JSON-lines records whether its sink is
`stdio` on a workstation or a UART on a Cortex-M part, so what comes back off a
board, an emulator, or another machine is the same evidence a local run produces.
`--observation` is how it gets in. The capture is gitignored, so a clean checkout
does not have one. `examples/firmware-cortex-m/build-and-run.sh` writes it, and
it runs inside WSL Debian with `qemu-system-arm` and `arm-none-eabi-gcc` installed
(see that directory's README). Without the file the scan warns that the capture
`could not be read` and lists `sda.observation` under NOT CHECKED:

```bash
sda scan examples/firmware-cortex-m   --observation examples/firmware-cortex-m/build/capture.jsonl
```

`examples/firmware-cortex-m/` is a real one: a freestanding Cortex-M3 image,
`-nostdlib`, no compiler runtime, 2.2 KB of text, run on an emulated Stellaris
LM3S6965 under QEMU. The fault it commits — a field index past the end of an
eight-byte frame — arrives as a `critical` finding at `confidence certain`, and
the function that is never called comes back `unreached` rather than clean.

A capture the parser can read no records out of supplies **no** observation, and
the report says so. That refusal is the point: an observation with no coverage is
the claim *execution was measured and these lines did not run*, which is what
makes `refuted` and `unreached` available, and believing it on the strength of a
truncated UART log would manufacture refutations. For the same reason a line
nothing measured carries no execution count — not a zero, which would be a
measurement.

---

## AI models are untrusted inputs with a deserializer attached

Local models now ship inside firmware on devices that are physically reachable,
rarely updated, and safety-relevant. That changes what a model file is.

```bash
sda ai scan ./models
```

* **Native container parsers** for GGUF, safetensors, Python pickle and PyTorch
  zip — headers only, so a 30 GB checkpoint costs a few kilobytes of I/O, and
  every field is treated as attacker-controlled. Declared tensor offsets are
  validated against the real file size, because a runtime that memory-maps a
  model and trusts its header reads out of bounds.
* **Pickle opcode scanning** that never unpickles anything. Loading a `.pt` calls
  whatever `GLOBAL` it names; the scanner walks the opcode stream and reports
  which callables would run. `os.system` in a checkpoint is reported as
  Critical, with the byte offset. Verified against artifacts built for the
  purpose: a hand-assembled protocol-2 pickle reaching `os.system`, the same
  payload inside a genuine PyTorch zip as `archive/data.pkl`, and a safetensors
  file whose header declares a tensor ending at byte 1000104 in a 169-byte file.
  All three are caught, and nothing is loaded to catch them.
* **A behavioural probe suite** for what no file inspection can reach: sleeper
  agents, censorship, poisoning canaries, prompt injection, unbounded
  generation. Trigger candidates found in the tokenizer seed the campaign — the
  static half choosing what the dynamic half should try.
* **Mapped to the frameworks you report against**: OWASP LLM Top 10, MITRE
  ATLAS, and the [NIST AI RMF](https://www.nist.gov/itl/ai-risk-management-framework),
  with each RMF subcategory marked `tool`, `partial` or `process` so a scan is
  never mistaken for governance evidence it cannot supply.

The runner does not perform inference — that would put a network stack and a
model runtime inside a security tool. You get the suite, you drive the model, you
hand the responses back:

```bash
sda ai probes > suite.json                       # send these to the model
sda scan ./firmware --probe-responses out.json --probe-model llama-3.2-1b-q4
```

```
llama-3.2-1b-q4:1:1: AI-CENSORSHIP-BIAS (medium)
  Probe `censorship-differential` fired: response diverges from the matched
  baseline by 1.00 (threshold 0.75).

llama-3.2-1b-q4:1:1: AI-PROBE-INCOMPLETE (medium)
  5 probe(s) produced no response: sleeper-date-trigger, sleeper-deployment-marker,
  memorization-extraction, unbounded-generation, poisoning-canary. Those risks
  were not tested, and this report must not be read as covering them.
```

Until you do, a scan of a project containing a model says so:

```
NOT CHECKED:
  sda.ai.probe: no probe responses supplied. Behavioural risks — backdoors,
  censorship, jailbreaks — were NOT tested.
```

Every probe report repeats the same caveat, because it is the truth: *a probe
that fires demonstrates a behaviour; a probe that does not fire demonstrates
nothing.* The trigger space is unbounded, and a model trained to conceal a
behaviour will conceal it from this suite too. Provenance is the control;
probing is a filter.

---

## Deductive and inductive evidence, and the seam between them

A hybrid neurosymbolic system is two kinds of artifact wired together, and they
do not admit the same kind of evidence. The symbolic part — the rule engine, the
planner, the guard that decides what a model's output is allowed to do — is
ordinary code, and a theorem prover can establish things about it that hold on
*every* execution. The learned part is reachable only by running it and judging
what came back.

The toolkit had the second half from the start. Its behavioural probes have
always said what their silence is worth. What it lacked was the first half, and the rule that
keeps the two from being blended into a number nobody can defend.

**The failure mode is averaging.** Reporting one system-level confidence over a
discharged SMT obligation and a probe suite that happened to stay quiet is the
same error as reading "no runtime defect" as "correct" without asking whether
the code ever ran — one level up, and harder to see. So the two are never mixed.

**The combination that works is assume-guarantee across a stated boundary.**
Prove the symbolic shell. Let the model enter the proof as a named *assumption*
rather than as verified code. Then require every such assumption to be paid for
one of three ways — by a runtime guard that is itself proved total, by inductive
evidence carrying its own caveat, or by appearing in `NOT CHECKED`. Never
silently.

Two verdicts join the four:

| static says | evidence | verdict | what it means |
|---|---|---|---|
| suspect | an obligation settling this rule was discharged, premises paid | **Proved** | there is no execution on which it happens |
| suspect | behind the neural boundary, or resting on an unpaid premise | **Assumed** | nobody adjudicated this; do not read it either way |

`Proved` is deliberately not merged into `Refuted`. `Refuted` means the code ran
many times without faulting, which this README already calls *"not proof of
correctness — the executions may all have taken the same path"*. `Proved` means
there is no such path. Collapsing them would discard the only thing that made
the deductive evidence worth collecting.

**The load-bearing rule is that a proof is only as good as its premises.** A
discharged obligation whose proof was granted an assumption that only a probe
campaign supports does not get promoted to `Proved`; it is demoted to `Assumed`,
with the unpaid premise named. Otherwise the strongest verdict the toolkit
issues would be available to any claim resting on evidence that, by its own
subsystem's admission, demonstrates nothing:

```
src/guard/clamp.rs:40:5: RUST-RANGE-01 (high) [assumed]
  obligation `guard::clamp/ensures/0` settling `RUST-RANGE-01` was discharged,
  but it was granted 1 premise(s) that nothing proves: every policy output
  reaches the actuator through clamp. The proof therefore establishes the
  property *given* those premises, which is not the same claim.
```

Swap those 10,000 quiet trials for a runtime guard proved total, and the same
finding becomes `Proved` and the system claim loses its proviso. Nothing else
changes. That difference is the whole design, and there is a test for it.

**What comes out is a conditional claim, not a score.** `VerificationLedger`
has no method returning a number between zero and one, because any such number
would be the averaging above:

```
`the actuator is never commanded out of range` holds on every execution
PROVIDED: every policy output reaches the actuator through clamp. 1
obligation(s) were discharged; the 1 proviso(s) above were not proved and are
listed in NOT CHECKED.
```

**Order of operations matters too.** Deduction runs first, and only the findings
it reached no verdict on are handed to the correlation engine. Running both over
the same findings and merging would let `Unreached` — *we never tried* —
overwrite `Proved` — *there is no such execution* — whenever a proved line also
happens to be cold.

**A component nobody specified verifies vacuously**, and that is reported, not
counted as a pass. It is the deductive analogue of a clean scan over an empty
file set, and it gets the same treatment the rest of the toolkit gives a
coverage hole:

```
NOT CHECKED — do not read a clean result as coverage of these:
  sda.vacuous[actuator::drive]: in scope and carries no proof obligation — it
    verifies trivially, and a trivial verification is not a result
```

**Size is the wrong question; the operator set is the right one.** What decides
whether a prover can say anything about a network is which operators it is built
from. Affine maps, ReLU and max-pooling are piecewise-linear, so bounds are exact
between kinks and a complete method can *decide* the property. Softmax, `tanh`,
a product of two input-dependent tensors, and unbounded recurrence each cost
precision or decidability outright. A four-layer transformer is far harder than a
convolutional net twenty times its size, so a `Component` carries an
architecture, not a parameter count:

| architecture | what is available | the catch |
|---|---|---|
| **MLP**, **CNN** | complete decision at small sizes, bound propagation above | local to a stated input region, always |
| **RNN** | the same, after unrolling to a fixed horizon | the horizon is part of the result, exactly like a model checker's unwinding bound |
| **Transformer** | research prototypes, a few layers, small hidden dims | bounds perturbations of the *embeddings* — not a claim about the tokens that map into them |
| **Mamba / SSM** | nothing catalogued, at any size | unrolled recurrence *and* input-dependent gating together |
| **VAE**, **GAN** | each half, separately | the pair is not one function, and a sampling step is not a function at all |

The same parameter count therefore gives different answers, which is the whole
point of not gating on it. At four million parameters a CNN is in reach, an MLP
is not, and a transformer is neither — it is research-only. `sda` says which:

```
NOT CHECKED — do not read a clean result as coverage of these:
  sda.intractable[policy]: 4000000 parameters, above the ~1000000 that published
    results reach for a mlp. Every claim about this component is inductive, and
    no volume of trials makes it otherwise
  sda.research-only[text]: no production verifier covers a transformer. It
    bounds perturbations of the *embeddings*. A guarantee over an embedding ball
    is not a guarantee over the tokens that map into it, so it does not
    establish what a reader will assume it does
  sda.composite[vae]: an autoencoder is not one function. Declare the
    deterministic half you care about as its own component. Its parts are:
    encoder, decoder
```

**The reasons are distinguished because they call for different responses.** A
component that is merely *underspecified* — no input region declared, or a
recurrent network with no horizon — is a gap in the specification, not in the
tooling, and the user can close it today by declaring one. A *composite* is
closed by decomposing it. The other two cannot be closed and should stop being
carried as pending work. An undescribed neural component gets its own line: an
unmeasured model is not a small one, which is the only place in the design where
a missing value could have been read optimistically.

**At language-model scale — 10⁶ to 10¹²⁺ parameters — the guard is the entire
safety case**, and the report says so rather than leaving neural verification
silently absent. An omitted check and a passed one look identical otherwise.

**The premise the whole case rests on is now proved, not trusted.** The guard's
postcondition only helps if model output actually reaches the guard, and at this
scale that *if* is the entire safety case. But interposition is not a claim about
the model — it is a claim about the shape of the program, and reachability over a
dataflow graph is decidable. So `sda` decides it, over a declared flow, and
emits a discharged or failed obligation per model/effector pair:

```
Interposition: 1 model/effector pair(s) proved guarded over the declared
dataflow. That reduces the safety case's premise from `the guard is interposed`
to `the declaration matches the code`; it does not remove it, and the smaller
premise is listed in NOT CHECKED as `flow::declaration-faithful`.
```

That second sentence is the design. Proving reachability over a declaration does
not make interposition unconditional; it **swaps one large premise for a smaller,
far more checkable one**, and reporting the swap as a finished proof would be the
laundering the rest of this section refuses. So `flow::declaration-faithful` is
emitted `Undischarged`, on purpose, and every proof citing it inherits it.

The shape of the system is declared in version control, next to the code, for
the same reason `deviations.toml` and `scope.toml` are — it is a claim that
should be reviewed when it changes:

```toml
# .sda/architecture.toml
[[component]]
name = "policy"
path = "models/policy"
boundary = "neural"
architecture = "transformer"
parameters = 7000000000

[[component]]
name = "guard::clamp"
path = "src/guard"
boundary = "symbolic"
role = "guard"

[[component]]
name = "actuator::drive"
path = "src/actuator"
boundary = "symbolic"
role = "effector"

[[flow]]
from = "policy"
to = "guard::clamp"

[[flow]]
from = "guard::clamp"
to = "actuator::drive"
```

```bash
sda verify .                       # prove interposition over the declaration
sda verify . --taint codeql.sarif  # and let a taint report try to refute it
```

### Exit codes

`sda scan --fail-on <severity>` is the CI entry point, and it has three answers
rather than two:

| code | meaning |
|------|---------|
| `0`  | the scan ran and found nothing at or above the threshold |
| `1`  | the scan ran and found something at or above it |
| `3`  | **nothing was scanned**, so there is no verdict either way |

`3` exists because the alternative is worse than it looks. A mistyped path, a
build directory, or a tree of languages this toolkit does not read all produce
zero findings, and zero findings from nothing read is indistinguishable from a
clean codebase in the one output a pipeline actually consumes. This gate used
to answer `0` for all three, with the message `no findings at or above low` — a
sentence about code that had never been opened.

That is the same trap this README documents two sections down about `verus`
exiting `0` on a failed proof. It is an easy one to build and a hard one to
notice, because everything about a green build looks like success.

`2` is not used here: the argument parser exits with it for a malformed command
line. Without `--fail-on`, `sda scan` is a report rather than a gate and exits
`0` whatever it finds.

**A plain `sda scan` runs this too.** The declaration is part of the project, so
a scan of a project that has one reports whether the guard holds, and a bypass
appears as a `SDA-INTERPOSE-01` finding — in the JSON and the SARIF, not only in
the prose, because a CI gate reads the machine formats and a refuted safety case
that existed only in a summary string would pass one. `sda verify` remains the
place to drive the proof with a taint report and a prover log, and the place
whose exit code is the proof's verdict rather than the scan's: `0` proved, `1`
refuted or a proof failed, and `3` when there was nothing to prove because no
declaration exists or it yields no obligation. The same three answers as the
gate, for the same reason.

Deduction runs *before* correlation, not alongside it. A finding a proof has
settled is withheld from the runtime correlator, because a line proved
unreachable-by-defect that also happens to be cold would come back `Unreached` —
replacing "this cannot happen" with "we never tried". Averaging two engines'
answers is the failure this whole design refuses, one layer up.

A project that ships a model artifact and declares no architecture is told so in
`NOT CHECKED`. A project that ships no model is not: interposition is not a
question there, and a notice printed on every scan in the world is one people
learn to skip past.

A refuted proof exits non-zero, because a bypass is a failed safety case rather
than a warning. **An invalid entry is rejected and reported, never silently
honoured** — the same discipline the deviation and scope registers apply, and
for a sharper reason: a bad scope rule over-excludes and under-reports, while a
bad architecture entry produces a *proof* about a system that is not the one
being shipped. A component declared `boundary = "neural"` and `role = "guard"`
is refused outright: a guard that is itself a model moves the premise rather
than discharging it.

**Taint analysis refutes; it never confirms.** A taint flow running from a model
to an effector without crossing a guard is a counterexample, and it fails the
obligation outright — the declaration was wrong, or the code moved under it. A
taint run that finds nothing establishes nothing, because the catalogued taint
providers are heuristic and the ontology says what their silence is worth. It is
the same asymmetry the probe suite has always stated, applied to a different
instrument.

**A taint finding with no dataflow trace cannot refute anything, and that turned
out to be the common case.** Refutation needs the *path*, not the endpoint: a
finding naming only where tainted data landed cannot say whether a guard was
crossed on the way. SARIF has a field for exactly that, and Semgrep's
`--dataflow-traces` flag documents itself as *"only affects text and SARIF
output"*. Both true, neither helps — real Semgrep OSS 1.176.0 prints the trace in
its **text** output and emits **no `codeFlows` at all** in its SARIF:

```
   24┆ write_actuator(forwarded)

  Taint comes from:
   21┆ raw = infer(prompt)
```

A `codeFlows` parser written from the specification would have been correct,
complete, and never once exercised by that tool — while `sda verify --taint`
reported `interposed` from a report it could not read. So the blind case is
handled explicitly instead, and both numbers are always printed:

```
  1 taint finding(s) loaded, 0 carrying a dataflow trace

NOT CHECKED — do not read a clean result as coverage of these:
  sda.taint-untraced[model-output-to-actuator]: landed on the effector `app` at
    src/main.py:24:5 with no dataflow trace. Refutation needs the path, not the
    endpoint — without it nothing can say whether a guard was crossed
  sda.taint-inert: all 1 supplied taint finding(s) lack a dataflow trace, so the
    taint report could not participate in this proof at all
```

**And one trace is not enough either.** The same reasoning applied one level
down: for a producer that *does* emit `codeFlows`, the parser kept the first one
and said so deliberately — additional flows are alternative routes to the same
sink, and a consumer wanting every route wants the SARIF. That is right for
rendering and wrong for refutation. Interposition fails if **any** route reaches
the effector unguarded, so keeping one route makes the verdict depend on the
order the tool happened to emit them.

Which is not hypothetical. The Python capture carries one code flow; a real
`cpp/command-line-injection` result over the same program in C++ carries three,
and they arrive in this order:

```
codeFlow 0 :: policy -> guard::clamp -> actuator     ← guarded
codeFlow 1 :: policy -> telemetry    -> actuator     ← the bypass
codeFlow 2 :: policy -> guard::clamp -> actuator     ← guarded
```

Reading the first would have reported a clean proof from a report that contained
its own counterexample. Every flow is now kept, and bypasses reducing to the same
component path are deduplicated.

The second producer cost a second defect at the same time. Refutation used to
require the trace to *begin* inside the model, which held only because CodeQL's
Python taint source sits inside `policy/serve.py`. The C++ source is `argv`,
entering at `main` and outside every declared component, so the bypass was
skipped in silence. What the claim actually says is *"model output cannot reach
an effector without crossing a guard"* — so refutation now anchors on the last
visit to a neural component, and what happens before the model is treated as the
separate question it is.

Neither defect is visible from the SARIF specification, and neither could have
surfaced against a single tool's output. `tools/codeql-taint-cpp/README.md` has
the commands.

*The tool looked and found nothing* and *the tool cannot answer this question*
must never produce the same clean page. The fixture is at
`crates/sda-engine/tests/fixtures/semgrep-1.176.0-taint.sarif`; the program, the
rule and the command that produced it are in `tools/semgrep-taint/`.

**The loop closes on real bytes.** A declared architecture, a real taint run,
and a proof that the declaration was wrong:

```
  1 taint finding(s) loaded, 1 carrying a dataflow trace

Interposition: NOT established. 1 of 1 model/effector pair(s) have a path that
never crosses a guard:
  `policy` reaches the effector `actuator` without crossing a guard, observed by
  taint analysis (`py/command-line-injection`): policy -> telemetry -> actuator
```

That is CodeQL 2.26.4 reading `tools/codeql-taint/`, a program with a guarded
path and a bypass through a relay the declaration forgets. CodeQL reports a
twelve-step interprocedural flow — `policy/serve.py` → `app.py` →
`telemetry/relay.py` → `app.py` → `actuator/drive.py` — and correctly does not
report the guarded route. `sda verify` exits 1.

Getting there cost two bugs and two false starts, all of which only a real run
could have shown:

* **`parse_sarif` never read `codeFlows`.** Every taint finding arrived as an
  endpoint and was silently skipped. The fixture that stood for CodeQL here
  contains zero `codeFlows`, and Semgrep emits none, so nothing in the repository
  could have exercised the field.
* **CodeQL writes CWEs as `external/cwe/cwe-078`**, not the `CWE-78:` form the
  tag reader knew. Correlation matches a runtime witness to a static finding
  *through the CWE*, so no real CodeQL finding could ever have been **confirmed**
  — the identical defect that function already carried a comment about for
  Cppcheck and Semgrep.
* `sys.argv` is not a `RemoteFlowSource`, so the first version of the program
  produced nothing at all; and a layout where imports do not resolve produces
  nothing either, because CodeQL follows imports to track flow between files.

**Premises are followed all the way down.** Once proofs cite each other, a local
soundness check is not enough: an obligation whose only assumption is discharged
by a lemma looks paid for, and if that lemma rests on something nothing proves,
the original claim rests on it too. `unpaid_premises` walks the proved-by chain,
so a finding whose guard proof rests on an interposition proof that rests on an
unverified declaration comes back `assumed`, not `proved`. There is a test that
sets up exactly that chain and asserts the direct check sees nothing wrong.

**A trial count is not evidence; the search that produced it is.** Ten thousand
samples from the expected distribution and ten thousand chosen by a red team are
different claims, and over natural language neither approaches a bound — so
`AssumptionSupport::Inductive` records the search alongside the count:

```
sda.assumption[policy::in-domain]: `the policy stays in domain` is assumed at
  the neural boundary (10000 random trial(s) found no counterexample: sampled
  from the expected distribution, so it says what typical inputs do and nothing
  about the ones an attacker would pick)
```

The ontology carries the tools this needs, classified with their real limits:
`ext.verus`, `ext.kani` and `ext.creusot` for Rust, alongside the existing
`ext.cbmc`, `ext.frama-c` and `ext.polyspace` for C and C++. For networks,
`ext.marabou` and `ext.nnenum` decide piecewise-linear cases completely and
`ext.abcrown` bounds larger ones — so `sda tools gaps` can answer *why* nothing
covers a given model rather than appearing to offer something that cannot run.

**Verus is wired, and running it found three ways a failed proof hides.**

```bash
sda verify . --proofs verus.json --proof-log verus.err
```

```
Prover: verus 0.2026.08.30.b432e82 — 3 obligation(s) verified, 1 failed, 1 located.
  guard.rs:41:9: postcondition not satisfied
  Note: the standalone `verus` binary exits 0 whether or not its proofs hold
  (`cargo verus verify` exits 101). If this report came from the former, a CI
  gate on its exit code would have passed it.
```

1. **The standalone `verus` binary exits 0 on a failed proof.** One error, an
   abort message, `$? == 0`. `cargo verus verify` exits 101 — the trap depends on
   how the prover is driven, which only running it both ways showed.
2. **`--output-json` records that something failed and never which thing.** Its
   `func-details` map carries a `failed_proof_notes` list per function — and the
   function that failed has `[]`, identical to every function that passed. The
   only failure signal in the JSON is the aggregate `"errors": 1`.
3. **The failing obligation's message and location exist only in stderr.**

Compose them and a failed proof is invisible from every direction an integrator
would naturally look. An adapter written against `--output-json` alone — the
obvious choice, and the one a machine-readable flag invites — would have been
green and blind. So `parse_verus` takes **both** channels and reports a
disagreement between them rather than reconciling it, `sda verify` exits non-zero
where the prover does not, and the exit-code trap is stated in the output
because a reader who has been trusting that code has been trusting nothing.

**Only failures become obligations.** Verus names every obligation it could not
discharge and names none of the ones it did; `verified: 3` is the whole of what
it says about success. Emitting three anonymous `Discharged` obligations to
balance the books would put claims in the ledger that no tool made.

**`ext.verus` is a real adapter now**, driven as `cargo verus verify --manifest-path
{manifest} -- --output-json`. It needed a framework change: `AdapterSpec` carried
`output_on_stderr: bool` and Verus is the first tool where neither stream is a
result on its own, so that became `OutputChannel::{Stdout, Stderr, Both}` and the
parse dispatch takes both texts. Running it through cargo rather than directly
also cost a bug — cargo ends its stderr with ``error: could not compile `vnew`
(bin "vnew") due to 1 previous error`` where standalone Verus writes
`error: aborting due to 1 previous error`. Both are `error:` lines, neither is a
proof obligation, and only the first was being skipped, so every failing
cargo-driven run gained a phantom unlocated failure.

**A crate nobody specified is reported as vacuous, not clean.** `cargo verus
verify` on ordinary Rust builds it, verifies nothing, and exits successfully —
which the adapter would have surfaced as a clean deductive result. It is the
deductive analogue of a clean scan over an empty file set, and it gets the same
treatment.

The program, the rule, the install steps and the captured output are in
`tools/verus-guard/`.

**The remaining adapters are unwritten, and none will be written from
documentation.** `ext.modelscan` once shipped fully green while unable to read a
single byte of what its tool actually wrote, and both coverage parsers found
their real producers diverging from the published format. Each of these gets its
fixture captured from a real run first.

---

## Fuzzing, and why it is the point rather than a feature

The correlation engine can only adjudicate code that *ran*. Without an input
generator, most static findings come back `Unreached` — untested, not clean. The
native fuzzer is what converts those into real verdicts.

```bash
sda fuzz ./build/firmware --runs 5000
```

```
1115 run(s) in 28245 ms; corpus 5; 4 distinct location(s) reached; 1 crash(es).

magic_target.rs:32:1: SDA-FUZZ-MEMORY (critical)
  bounds: index 69 is outside a container of length 5. A 5-byte input reproduces it.
  Reproduce with: ./build/firmware < .sda/crashes/crash-0000-memory.bin

After correlating what the campaign reached:
  unpredicted: 1
  unreached: 2
```

**Comparison feedback is what makes it work.** This fuzzer runs the target as a
*process per input* — a few tens of runs per second, against the 10k+/sec of an
in-process fuzzer. Brute force is simply not available, so a four-byte magic
value would be permanently out of reach. Instead, instrumentation reports what
the program compares against, and the fuzzer writes those values into the input:

```rust
if sda_probe::cmp_eq!(input[0], b'F') { … }
```

The same thing in C, through the single-header shim — which matters, because C
and C++ firmware is the primary target and the shim is what those builds link:

```c
if (SDA_CMP_EQ(magic, 0x5A5A5546uL)) { … }   /* operands reported to the fuzzer */
```

Measured on a C target built with MSVC, a four-byte gate in front of a real
`abort()`, same seed and same corpus for both: **instrumented, the crash in 17
runs; uninstrumented, 2651 runs without reaching it** — and the blind campaign
says so rather than reporting a clean result, both as a banner and as an
`SDA-FUZZ-NO-FEEDBACK` finding in the report. The reproducer it saved is the
five bytes `FUZZA`, and replaying it aborts.

Every candidate crash is replayed before it is believed, and **a timeout must
recur on every replay**. A timeout is the one candidate class that is a claim
about wall-clock time rather than about the program, so machine load can
manufacture one: that same campaign reported a `critical` resource-exhaustion
crash at 2321 ms against a 2000 ms budget while a parallel build was running,
and single-replay confirmation passed it, because the replay was slow for the
same reason the original was. Faults the target itself detected are
deterministic and still cost one replay. A target that genuinely spins forever
is still reported — that is checked too, not assumed.

On the bundled magic-value target that is the difference between **0 crashes in
4000 runs and the crash found in 1115** — knowledge substituting for the
throughput this architecture cannot have. It is also why the native fuzzer earns
its place beside the AFL++ adapter rather than competing with it: AFL is far
faster on hosted Linux, and cannot instrument a bare-metal target at all.

Campaigns are seeded and deterministic, because a crash you cannot reproduce is a
rumour rather than a finding. Every crash is deduplicated by defect — a thousand
inputs hitting one bug is one bug — and saved as a reproducing input.

---

## It is run on itself

`sda scan crates` — the toolkit analysing its own ~15k lines of Rust. The first
run returned 88 findings, **60 of them Critical**, and every one of those sixty
was wrong: `MODEL.3` matched any identifier containing "pickle", so a tool that
*inspects* pickle files flagged itself for *using* them. A security checker that
cannot tell analysing a hazard from using it produces findings nobody reads.

Three rounds of narrowing, each a real distinction rather than a suppression:

| what was flagged | why it is not a defect |
|---|---|
| `mod pickle`, `PickleScan`, `pickle::scan` | naming a format is not deserializing with it — only a call to a pickle-loading API is |
| `".pkl"` | the extension itself names no file |
| `name.ends_with("data.pkl")` | a literal handed to a matching predicate is a pattern, not a path |
| `scan("evil.pkl")` in `#[cfg(test)]` | a fixture is not shipping code |

88 → 20 on the first pass, and eventually to zero — none of it by suppression.

Two things came out of it that could not have come from a test suite.

**The toolkit's advice was worth taking.** Eleven `UNSAFE.3` findings said the
crates had no `unsafe` but did not declare `#![forbid(unsafe_code)]`. Adding it
to all twelve compiled first time — turning "happens to use no unsafe" into a
property the compiler now enforces.

**The deviation register refused its author.** I tried to waive the last three
`MODEL.3` findings with a written justification. It rejected them:

```
warning: deviation for `RUST-2024-MODEL.3` rejected: `RUST-2024-MODEL.3` is
         Mandatory and may never be deviated
```

Which was right. Loading a pickle is remote code execution, so the rule is
Mandatory, and the correct response to a false positive on a Mandatory rule is a
better rule — not better paperwork. The checker was narrowed instead.

The seventeen `PANIC.1` findings were the interesting case. Every one was an
`unwrap` I could prove safe — a `try_into` on a slice whose length was checked
two lines above. The tempting move was to deviate them all with that rationale.

They were fixed instead. The proof lived in my head, not in the code, and this is
a file that parses attacker-controlled model headers; asking a reviewer to
reconstruct a safety argument is exactly the wrong thing to do there. A
`fn array<const N: usize>()` helper and four small rewrites removed the
`unwrap`s altogether, and one deviation became unnecessary and was deleted.

**88 findings → 0 unsuppressed.** What remains is four `PANIC.2` sites that panic
only if a catalogue compiled into the binary is malformed — recorded in
`.sda/deviations.toml` with a rationale and an approver, because a test parses
every built-in file, so the case is unreachable in a shipped build.

None of that reduction came from lowering a severity or silencing a rule. It came
from one false-positive fix, one piece of advice taken, and a set of `unwrap`s
deleted.
The same treatment was given to `shim/sda_probe.h`, the C instrumentation header
— which is held to the rules it exists to help enforce. That scan found three
*more* false positives in the C checker, each a shape common enough to make its
rule unusable on real headers:

| flagged | why it was wrong |
|---|---|
| `#define CHECK(index, len) DO((index) < (len), "index outside container")` | the parameter name was matched inside a *string literal*, where the preprocessor does not substitute |
| `SDA_COV` defined in both arms of an `#if`/`#else` | two arms define one macro, not two colliding ones — the standard idiom for compiling a facility out |
| the header's own documentation block | a doc comment *containing a usage example* is not commented-out code; every documented header has one |

What survived is genuine, and is recorded in `.sda/deviations.toml` with reasons:
`<stdio.h>` in the default sink (which is why `SDA_PROBE_CUSTOM_SINK` exists),
function-like macros that must be macros to capture `__FILE__` and `__LINE__`,
and includes that a single-header library cannot place at the top.

The `buf[at++] = c` idiom violated Advisory Rule 13.3 in 26 places. I first
recorded a deviation for it, reasoning that no C compiler was available and an
unverifiable edit to a header is a worse risk than an Advisory departure.

**That reasoning was sound; the premise was wrong.** I had checked `PATH` for a
compiler and concluded there was none. MSVC ships with the Rust toolchain's
linker and simply is not on `PATH` outside a developer prompt — it was there all
along. Re-checking an assumption I had asserted three times turned "cannot
verify" into "verified":

* the header compiles clean at `/W4 /std:c11`;
* a C target built against it emits records the engine parses and correlates;
* number formatting, including the padding and digit-reversal paths, matches
  expected output.

So the 26 sites were rewritten and the deviation deleted. The rewrite also caught
a bug I introduced doing it — a blanket character replacement clobbered a ternary
operator into `(frac < 10u) - "00" : "0"`, which the compiler rejected
immediately. That is precisely the class of error the missing compiler had made
me afraid of, and precisely why finding it mattered.

---

## And on someone else's

Running a checker on its own repository proves it survives one codebase written
by the person who wrote the checker. The harder question is what it does on
2,270 files nobody here has read, so the C++ analyzer — which until this run had
never seen a real codebase — was pointed at **PX4-Autopilot**, an embedded
flight-control stack in exactly the domain these rules are written for.

```
sda scan PX4-Autopilot/src
```

**14,284 findings, 68 rules, 1,305 files, no crash.** Seventeen MISRA C++:2023
rules fired for 5,777 of them, alongside 49 MISRA C rules and the two native
complexity checks. Release build, warm: **2.3-2.7 seconds for 2,270 files** —
about a millisecond each, and the debug and release runs produce byte-identical
finding ids.

**Zero location defects.** Every finding was checked back against the file it
names: not one line past end-of-file, not one column past end-of-line, not one
inverted span. That is the failure this scale exposes and it exposed none.

Two spot-checks are worth stating because they are the ones a naive matcher gets
wrong. The analyzer flagged a `#define static_assert` in `o1heap.c` — where the
line above it reads *"Intentional violation of MISRA: static assertion macro
cannot be replaced with a function definition"*, an author reaching the same
conclusion independently. And it did **not** mistake an `#ifndef ADC_CHANNELS`
sitting in the middle of `ADC.hpp` for an include guard, while correctly
reporting that the header has none.

**It also found a defect here rather than there.** The report came back with a
`NOT CHECKED` section one line long. External adapters were registered only when
`--with` asked for one, so a default scan named none of the nine external
providers it had not run — while a scan that enabled a single tool listed the
other eight. The unsuppressible section was least complete on the run that
checks least, which is the run a first-time user makes. Fixed by registering
them always and enabling them only on request; a disabled adapter is excluded by
policy before it is ever probed, so it costs nothing.

What this does **not** cover: nothing here built PX4, so the compilation
database, every external provider, and all dynamic evidence remain untested at
this scale.

---

## The workbench, and one review state for people and agents

`sda-workbench` is the desktop shell: Monaco, the findings queue, an embedded
terminal. Three things make it a review tool rather than a results viewer.

**The queue is filterable, grouped and keyboard-driven.** Facets for severity,
verdict and review state carry live counts; `j`/`k` walk the queue, `1`-`4`
record a conclusion, `/` jumps to the filter. The list renders only the rows on
screen, because a real project produces findings by the thousand — PX4 produced
14,284 — and a list that builds them all is a list nobody scrolls twice.

Filtering is a **view**. The scan's own count stays in the header, nothing a
filter does is written to a report, and no filter can make a finding disappear
from a gate.

**The detail pane shows the evidence, not just the verdict.** A coloured chip
states a conclusion; the dataflow path, the runtime event, the prover's ruling and
the correlation's own rationale are what let a reviewer disagree with it. The
steps of a taint path are numbered and clickable, and jump the editor to each one.

**Review state is one file, shared with agents.** `.sda/triage.toml` records
`acknowledged`, `accepted` or `false-positive` with a note and an author. The
workbench writes it from the detail pane; an agent reads and writes the same file
through the `analysis.triage` MCP tool. A person and an agent working the same
backlog cannot diverge without it showing up in a diff — and because it is a file
in the project, the review is reviewable.

**Work is handed over in the same file.** A finding carries an `assignee` and a
discussion thread, and a person and an agent are the same kind of thing to the
store — `a.erickson` and `agent:triage-bot`. So a human can hand a batch to an
agent, the agent works it over MCP, and its conclusions and remarks come back
where the human is already reading. Assigning and commenting **conclude nothing**:
an assigned finding still counts as unreviewed, because a distributed queue is not
a reviewed queue.

That is the part commercial tools solve with a server. Coverity and SonarQube keep
owners and threads in a database behind a web UI, and multi-user access is what it
buys. A file in `.sda/` buys something they cannot: the review is diffable, it
arrives in the pull request beside the code it is about, and `git log` already
answers *who said this*. Concurrent edits merge the way every other text file in
the project does.

`fixed` is deliberately not a state: whether a defect is gone is decided by the
next scan, not by a checkbox, and a state the tool cannot verify goes stale in
silence. Records whose finding no longer appears are reported as **stale** rather
than deleted, because "it was fixed" and "it moved and is now unreviewed" are both
live readings and nothing here can tell them apart.

**And a baseline answers the question teams actually ask.** Not *how many
findings are there* — a backlog of fourteen thousand is not triaged — but *what
did we just add*. `.sda/baseline.toml` records a run's findings; after that the
workbench badges new ones and offers a `new` facet, and `analysis.baseline` gives
an agent the same view.

It is never written automatically. A baseline refreshed by every scan reports zero
new findings forever and looks like it is working. And with nothing recorded,
newness is **unknown** rather than false: the facet is disabled and says so, and
the MCP field is `null` rather than `0`, because a comparison nobody made must not
be reported as one that came back clean.

**Triage annotates; it never hides.** A triaged finding still appears in every
report and still counts toward every exit code. Suppression is a *deviation* —
approver, rationale, catalogue check, and refused outright for a Mandatory
guideline. The two are different claims and the tool never lets one stand in for
the other.

---

## Agentic-first, concretely

Not "an AI wrote some of it" — the toolkit publishes itself as a typed tool
surface an agent can discover and drive.

```bash
sda mcp        # JSON-RPC 2.0 over stdio; point any MCP client at it
```

Twenty-one tools spanning the ontology, the rule catalogues, planning, analysis,
neurosymbolic verification, model scanning, the build backend, and the autonomous
SWE loop. Every description states the tool's **limits**, because an agent
choosing between `analysis.scan` and `analysis.statodynamic` needs to know the
first cannot confirm anything.

An agent has no source to check an answer against — only the JSON and the
description — so `analysis.verify` publishes the premise its own result rests on:

```
LIMITS: the proof is over the *declaration*, not the code — `not_checked` always
carries `flow::declaration-faithful`, the premise that the two agree. A taint
report can only refute; a clean one establishes nothing, and a finding with no
dataflow trace cannot refute at all. `interposed: null` means no architecture was
declared, which is not a pass. Read `not_checked` before the booleans.
```

That last case is the one an agent is most likely to misread, so an undeclared
project returns `interposed: null` rather than a boolean: `false` would read as a
refutation and `true` as a proof, and neither happened.

The **ontology** is what makes the landscape navigable: 42 tools classified by
capability, soundness, cost and maturity, each with a one-sentence statement of
what it *cannot* establish, plus a walkable relation graph and a `gaps` query
that answers "what is nothing checking?".

```bash
sda tools search memory-safety
sda tools gaps --language c
sda plan .
```

The **autonomous SWE loop** owns the evidence and the stopping decision, which is
the part a language model is worst at. It builds the project it is pointed at, so
that project needs a recognised build system: on a bare C project with none, such as
`examples/firmware`, `sda swe .` stops with `no build system was recognised` and exits 1.

```bash
sda swe .      # build → diagnose → hand back the next problem with source context
```

Session state persists across invocations — each call is a separate process, so a loop that reset every time could never notice it was going in circles. It refuses to declare success while errors remain, and it detects the two failure
modes that make unattended loops dangerous: *stalling* (the same diagnostics
after a patch) and *thrashing* (successive patches undoing each other).

---

## Any compiler, any build system

The toolkit attaches to whatever is already there. `BuildProfile` expresses
intent — *sanitize address*, *emit coverage* — and each toolchain translates it,
**reporting what it cannot do rather than dropping the flag**:

```
Instrumentation NOT applied by this toolchain:
  coverage instrumentation: MSVC has no compiler-level coverage flag; the
  correlation engine will see no coverage data and will report findings as
  unreached rather than refuted
```

That refusal has somewhere to send you. For toolchains with no coverage flag and
no sanitizer runtime, `sda-probe` is the instrumentation the correlation engine
consumes — a Rust crate and a single-header C shim
(`shim/sda_probe.h`) emitting the same JSON-lines stream:

```c
#define SDA_PROBE_IMPLEMENTATION
#include "sda_probe.h"

int read_sample(const uint8_t *buf, size_t len, size_t i) {
    SDA_COV();
    SDA_CHECK_BOUNDS(i, len);
    return buf[i];
}
```

No allocation, a fixed record buffer, and a `SDA_PROBE_CUSTOM_SINK` hook to route
records at a UART or RTT channel — because `<stdio.h>` is banned by MISRA C:2023
Rule 21.6, which this toolkit enforces. Compiled without `SDA_PROBE_ENABLED`
every macro expands to nothing, so the shipping build carries no instrumentation.

Faults are written **through** and flushed; coverage is batched. A fault is
usually followed by a crash, and a buffered fault record is a lost one — so a
fault flush also flushes the coverage that led to it, keeping the path into the
defect alive alongside the defect.

**Getting a `compile_commands.json`** is the single highest-leverage thing you
can do to a C project here — it is what unblocks the 87 guidelines needing type
information. The bare form needs a build system the tool recognises: on a bare C
project with none it stops with `no build system was recognised`, exit 1. Use
`--synthesize` there, which guesses the compile lines from the source tree and
says so in its output:

```bash
sda build compile-commands .              # ask the build system for one
sda build compile-commands . --synthesize # or approximate one for a Keil/IAR project
```

```
build/compile_commands.json (generated): 214 translation unit(s), covering 92%
of the 232 C/C++ source file(s) found.
18 file(s) are absent from the database and will not be checked by any
type-aware provider, starting with: src/legacy/crc.c, …
```

A synthesized database is marked as such everywhere it is used, because its
include paths and macros are guesses.

Compilers: GCC, Clang, MSVC, armclang, ARMCC, IAR, TI CGT, rustc.
Build systems: Cargo, CMake, Meson, Ninja, Make, Bazel, MSBuild, Zephyr west,
PlatformIO, SCons, xmake, Keil, IAR EW — with `compile_commands.json` ingest and
a per-system recipe for generating one. Diagnostics from all four output dialects
(GCC-like, MSVC, IAR, rustc JSON) become findings, which is how guidelines
needing type information get checked at all.

---

## Layout

```
crates/
  sda-core       domain model: findings, evidence, correlation, providers, SARIF
  sda-syntax     native C23 / C++23 / Rust 2024 lexers and structural models
  sda-engine     the default native engines + the correlation engine
  sda-rules      MISRA C:2023, MISRA C++:2023, Rust 2024 + deviation records
  sda-build      compiler and build-system backends
  sda-ai         model artifact scanning, LLM risk taxonomy, NIST AI RMF, probes
  sda-ontology   the queryable tool ontology
  sda-adapters   industry tools behind the same Analyzer trait
  sda-agent      MCP surface, deterministic planner, autonomous SWE loop
  sda-probe      the probe instrumentation an instrumented target links against
  sda-editor     Monaco's text model, ported to Rust
  sda-cli        the `sda` binary
shim/            sda_probe.h, the single-header C counterpart to sda-probe
gui/             the workbench: Monaco + embedded PTY terminal (Tauri; Dewey seam)
```

`cargo test --workspace`, all passing; *Where it stands* in `HANDOFF.md` carries the
count, and a test holds it to the tree.

**A real external analyzer now runs through the adapter**: `clang-tidy` from the
installed LLVM, driven by `--with ext.clang-tidy=<path>` against a CMake project
with a genuine clang compilation database. It returns real findings — including
`clang-analyzer-core.NullDereference` with its trace — merged beside the native
ones at `confidence medium`.

Two defects had to be fixed before that worked, and the first is the serious
one. `clang-tidy` was handed the *file* path of `compile_commands.json` as `-p`,
which takes a directory, and the project *root* as its source argument, which
takes files; it printed its usage message and analysed nothing. The report then
showed no clang-tidy findings, listed every **other** external provider under
`NOT CHECKED`, said nothing anywhere about the one the user had explicitly
enabled, and exited 0 — a clean bill of health from a tool that never ran. An
external tool that exits non-zero having produced no findings is now an error,
so it lands in `NOT CHECKED` with its own stderr quoted, and the two
placeholders (`{compile_commands}`, `{compile_commands_dir}`, plus `{files}`)
are distinct.

**The behavioural probe suite has been driven over the MCP surface**, supplying
responses by hand as an agent would. A sleeper-agent probe whose response
diverges from its baseline by 0.95 against a 0.60 threshold fires as `critical`;
a probe that matches its baseline produces no finding at all — silence is never
written up as safety — and the five probes nobody answered are reported as
untested.

Driving it also found the suite's own honesty bug. A divergence probe needs the
baseline prompt's response as well as the trigger prompt's; submitted without
one, it was counted as a probe that *ran and stayed quiet*. A blatantly
malicious response to the sleeper-agent probe therefore produced "1 probe ran
and 0 fired", with the probe absent from `not_run` — an untestable probe
presented as a clean test, which is precisely the failure this toolkit exists to
prevent. Unmeasurable probes are now counted with those that did not run, named
in the caveat, and reported as `AI-PROBE-UNMEASURED`. A submitted probe id that
is not in the suite used to be discarded in silence; it now surfaces as
`AI-PROBE-UNKNOWN-ID`, because a typo looks exactly like a risk that was tested
and found clean.

**The fuzzer's central claim has been tested as an A/B on real MSVC-built
binaries.** The same parser, gated behind a three-byte magic prefix, was fuzzed
twice from the same seed and corpus. Without comparison feedback: 2000 runs, one
distinct location reached, no crash — it never got past `in[0] != 'S'`. With the
gating comparisons wrapped in `SDA_CMP_EQ`: four locations, and the bounds bug
found, with a six-byte reproducer (`SDAAAH`) that reproduces every time. That is
the design claim — knowledge substituting for throughput a process-per-input
fuzzer cannot have — behaving as documented. The blind case is equally explicit:
an uninstrumented build reports `NO COVERAGE FEEDBACK` and raises
`SDA-FUZZ-NO-FEEDBACK` rather than presenting random generation as fuzzing.

The first of those runs also produced a **false `critical`**: a resource-
exhaustion crash whose saved reproducer, replayed five times, exited 0 in ~30 ms
each time. One slow process spawn on a loaded machine had become a critical
finding, and the report told the user "a 1-byte input reproduces it" — a claim
nothing had checked. A campaign now re-runs each candidate before believing it,
and discarded candidates are counted and reported rather than hidden, because
silently dropping a critical finding is its own kind of dishonesty.

**The correlation table at the top of this file has been produced end to end on a
real target**: a C program compiled with MSVC, linking `shim/sda_probe.h`, run by
the dynamic engine, its probe stream correlated against the static findings for
its own source. All four verdicts appear — `confirmed: 2` (a leak fault on the
`malloc` line escalating Rule 21.3 and D4.12 from medium to high, accepted only
because the weakness classes match), `refuted: 1` (a `printf` line executed 50
times against a threshold of 25), `unpredicted: 1`, and `unreached: 82`.

That run also caught the engine overclaiming. `Unreached` used to report that a
line *"was never executed"* — but the engine sees coverage **records**, and with
line-granular instrumentation an uninstrumented line is indistinguishable from an
unexecuted one. The falsehood was concrete: the run announced "no line of
`sda_probe.h` was executed" about the `fopen` that had just written the probe
stream it was reading. Both rationales now say what was actually observed — no
coverage record — and name the second explanation, so a real coverage gap and a
missing probe are not silently conflated.

**The external-provider path has been driven end to end** without installing
anything, by pointing `--with ext.cppcheck=<path>` at a stub that emits real
Cppcheck 2.x XML v2 on stderr, exactly as the tool does. The `.bat` is routed
through `cmd /C` (the CVE-2024-24576 path), the XML parses, severities map
(`error`→high, `style`→info), external findings stay at `confidence medium`, and
they merge into one report beside the native ones.

That run found a defect worth the exercise. Cppcheck states a `cwe` on most
checks and the adapter discarded it, so every external finding arrived with no
weakness classification — and correlation matches a runtime witness to a static
finding *through the CWE*. `same_defect_class` returns `None` when a finding
carries none, and confirmation requires `Some(true)`, so **no external finding
could ever be confirmed by runtime evidence**, however good the evidence: the
toolkit's central claim, silently unavailable for every external provider. The
CWE now survives into the finding, into the report, and into SARIF as a
`CWE:CWE-476` tag and a `helpUri` — and a test asserts an external finding with
CWE-476 is confirmed by a null-dereference crash.

## Status

Built and tested here: every crate above; the CLI end-to-end on the bundled C,
C++ and model examples (static, statodynamic, deviations, compile-command
generation and AI probing); the full dynamic loop against a **real instrumented
binary** — `sda-probe`'s example target, executed by the dynamic engine, its
out-of-bounds read surfacing as a `critical` finding classified `unpredicted`;
the fuzzer end-to-end against a real target (crash found, reproducer replayed); the Tauri backend; and the GUI frontend
bundle. Not exercised here: running against a real instrumented firmware build,
which needs hardware.

**The MCP surface has been driven as an agent would drive it**, not just
unit-tested: the shipped `sda mcp` binary, spoken to over its real stdin and
stdout with line-delimited JSON-RPC. `initialize` negotiates, `tools/list`
returns all twenty-one, `notifications/initialized` correctly draws no reply,
`analysis.scan` on `examples/firmware` returns the same 20 findings the CLI
does, `rules.audit` returns its caveat (210 guidelines catalogued, 80 exercised,
a clean result meaning conformance for 70), a missing argument comes back as a
tool-level `isError` rather than a protocol error, and the server exits 0 when
stdin closes. That run is also what caught the last path bug: locations were
reported to agents with native separators, so `src\main.c` on Windows would not
match the `src/main.c` in the same finding's SARIF.

**The autonomous SWE loop has been run for real**, against a project that
genuinely did not compile, with patches applied between iterations as an agent
would apply them. Every safety property it advertises was exercised rather than
assumed: it reported real compiler diagnostics with source context, sequenced to
the next problem once the first was fixed (2 errors → 1 → clean), resumed its
session across separate processes, and refused to say anything had succeeded
until the build was actually clean. Both stop conditions fire. Running it twice
without a working patch gives *"the same diagnostics reappeared after a change,
so the last patch did not address them; a human should look at the first error"*;
oscillating A → B → A gives *"the diagnostic set oscillated between two states,
which means successive patches are undoing each other"* — each exiting non-zero.
It has since been driven through **CMake and MSVC** as well, on a C project that
did not compile: `cl` reporting `error C2143`, then a link failure, then a clean
build. (An earlier revision of this file claimed no C build backend existed here.
That was wrong — it came from checking `PATH`, and MSVC's tools are never on
`PATH` until you load its environment. `nmake`, `cl` and `msbuild` were all
installed.)

Driving that path found the round's real defect. CMake's NMake generator runs
`cl`, but the compiler probe finds `clang` first, so MSVC diagnostics were parsed
as GCC-like, matched nothing, and a build that failed with `error C2143` was
reported as having *"produced no diagnostics"* — a clean-looking answer for a
broken build, the same failure mode already fixed once for Cargo. Two changes:
when a failed build yields nothing, the other parsers are tried before giving up;
and if they all fail, the summary says so in as many words instead of reading as
clean. A link failure surfaced by that message then turned out to be unparsed
too, so MSVC `LNK` errors are now diagnostics as well — an autonomous loop that
cannot see `unresolved external symbol` has nothing to act on.

**Verified here, in the end:** the GUI launches — a real window titled
`StatodynamicAnalysis`, WebView2 initialised, nineteen renderer processes — and
its embedded terminal starts a shell, echoes a command and survives a resize.
`shim/sda_probe.h` builds and runs in all four configurations that matter:
hosted, freestanding (`SDA_PROBE_CUSTOM_SINK`, no `<stdio.h>`), compiled-out, and
as C++ through the `extern "C"` guard — on x64 and x86.

The UI has since been driven for real, by attaching to the running window over
the Chrome DevTools Protocol: setting a project root and clicking **Scan**
returns and renders 20 findings for `examples/firmware`, clicking one loads the
file into Monaco with its decorations, and the "not checked" banner populates.
That is also how the last real bug turned up — the workbench never read the
project's `.sda/` directory, so approved deviations applied on the command line
and not in the window. Both paths now share one setup function, with a test.

`shim/sda_probe.h` **links** into a freestanding image — not merely compiles —
for Cortex-M4 (ARMv7E-M), Cortex-M0 (ARMv6-M), RISC-V 32 and AArch64, with
`-ffreestanding -nostdlib -Wall -Wextra -Werror -Os`, a linker script, and **no
compiler runtime linked at all**.

Getting there took a fix, and the fix is the argument for linking rather than
compiling. Compiling to objects — all this header's checks used to do — cannot
see an undefined symbol. Linking showed the shim pulling in nine
double-precision soft-float routines (`__aeabi_dadd`, `__aeabi_dmul`,
`__aeabi_d2iz`, the compares) from `SDA_VALUE`/`SDA_MARK`, plus `__aeabi_uidiv`
on Cortex-M0, which has no divide instruction. A real project links libgcc or
compiler-rt and would not have noticed, but a MISRA-constrained image pays
several KB of soft-float it never asked for, and none of it was documented.
`SDA_PROBE_NO_FLOAT` now makes the numeric type `long` and renders decimals by
repeated subtraction of powers of ten, so all four targets link against nothing.
The default path is unchanged and still renders `1.005` correctly.

**Still not verified:** nothing has been executed on real hardware. These images
link but were never flashed or run on a device, and no emulator is installed
here, so the dynamic loop's evidence for an embedded target remains untested
outside the host. Closing that needs a board (or QEMU) and a flashing tool —
it is not a gap that more work on this machine can close.

`sda-ai`'s probe runner defines and evaluates campaigns but does not itself call
a model; you supply responses through `ai.evaluate_probes`, which keeps the
toolkit free of any inference dependency.

## Security

What `sda` does with code you did not write, as of `1.0.2`:

* **A default scan runs none of the project's code.** The native engines read
  source and model files and parse them; a pickle is walked opcode by opcode,
  never unpickled. The scan asks `git` which revision it looked at, and the
  scanned repository's own `.git/config` can attach commands to that:
  `core.fsmonitor`, filter drivers, and `gpg.program` through
  `log.showSignature`. `sda` turns all three off for every git call it makes.
* **Building runs the project.** `build.compile`, `swe.iterate`, and external
  tools enabled with `--with` or `allow_external` run in the project directory.
  `cargo clippy`, `miri` and `verus` build a Rust crate, which runs its
  `build.rs` and procedural macros. Enable them only for code you trust.
* **`--artifact` and `fuzz.campaign` execute what they are given**, with your
  environment.
* **A project's `.sda/` is trusted.** Its deviations suppress findings, with an
  approver's name that nothing checks. Scan code you do not control with
  `sda scan --ignore-project-config`; every scan's summary also counts what was
  suppressed. An imported catalogue can add titles and confirm numbers, but it
  cannot lower the obligation of a guideline the built-in catalogue already
  confirms, or claim a coverage the engine does not have.
* **What `sda` writes goes into `.sda/`**, and it refuses to write through a
  symlinked `.sda`, directory or file there, so a repository cannot redirect
  those writes elsewhere.
* **The MCP server speaks only over stdio** and has the reach of the user who
  runs it: its tools accept any readable path. Approve its tool calls as you
  would a shell's.

Report a vulnerability privately, through **Report a vulnerability** on the
repository's Security tab, rather than in a public issue. `SECURITY.md` says
what to include.

## Licence

AGPL-3.0-or-later. Commercial licences available from NERVOSYS.

















