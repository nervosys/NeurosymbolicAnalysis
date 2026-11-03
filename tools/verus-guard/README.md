# A real Verus run, and three ways it hides a failed proof

`crates/sda-adapters/tests/fixtures/ext.verus.json` and `ext.verus.txt` were
captured from `guard.rs` in this directory. The program is written so the prover
must both succeed and fail: `clamp` satisfies its postcondition, `unchecked`
declares the same postcondition without the guard and cannot. A fixture where
everything passes could not show what a refutation looks like, and a refutation
is what becomes a `Confirmed` verdict on the `sda` side.

## Reproducing

Verus ships its own toolchain pin; `rustup` must have that exact version.

```bash
# Run from the repository root. `wsl` starts in the translated working directory.
wsl -d Debian -- bash -lc 'mkdir -p ~/verus && cd ~/verus && \
  curl -sLO "https://github.com/verus-lang/verus/releases/download/release%2F0.2026.08.30.b432e82/verus-0.2026.08.30.b432e82-x86-linux.zip" && \
  unzip -q -o verus-*.zip'
wsl -d Debian -- bash -lc 'rustup install 1.97.1-x86_64-unknown-linux-gnu'
wsl -d Debian -- bash -lc 'cd tools/verus-guard && \
  ~/verus/verus-x86-linux/verus guard.rs --output-json > verus.json 2> verus-stderr.txt'
```

Verus 0.2026.08.30.b432e82, rustc 1.97.1, WSL Debian.

## What the run reports

```
error: postcondition not satisfied
  --> guard.rs:41:9
   |
41 |         in_range(result),
   |         ^^^^^^^^^^^^^^^^ failed this postcondition

verification results:: 3 verified, 1 errors
error: aborting due to 1 previous error
```

## The three findings

**1. The standalone `verus` binary exits 0 on a failed proof.** One error, an
abort message, and `$? == 0`. A CI gate keyed on that exit code passes a build
whose proof failed.

`cargo verus verify` **does** exit 101, so the trap depends on how the prover was
driven — which only running it both ways revealed. The two paths differ in their
diagnostics too: standalone ends with `error: aborting due to 1 previous error`
and cargo with ``error: could not compile `vnew` (bin "vnew") due to 1 previous
error``. Both are `error:` lines and neither is a proof obligation; the second
was parsed as a phantom failure until a real `cargo verus` run was captured.

**2. `--output-json` records that something failed and never which thing.** Its
`func-details` map has an entry per function carrying `obligation_proof_notes`
and `failed_proof_notes` lists — and `guard::unchecked`, the function that
failed, has `"failed_proof_notes": []`, identical to every function that passed.
The only failure signal in the JSON is the aggregate `"errors": 1`.

**3. The failing obligation's message and location exist only in stderr.**

Compose them and a failed proof is invisible from every direction an integrator
would naturally look: the exit code is clean, the per-function JSON is clean, and
only an aggregate integer and an unstructured text stream say otherwise. An
adapter written against `--output-json` alone — the obvious choice, and the one a
machine-readable flag invites — would have been green and blind.

So `parse_verus` takes **both** channels, and reports a disagreement between them
rather than reconciling it: errors the diagnostics cannot locate, a `success:
true` contradicted by a diagnostic, and an error count of zero on a failed run
(which is a crash or a toolchain problem, not a verification result).

## What is deliberately not claimed

Only failures become `ProofObligation`s. Verus names every obligation it could
not discharge and names none of the ones it did — `verified: 3` is the whole of
what it says about success. Emitting three anonymous `Discharged` obligations to
balance the books would put claims in the ledger that no tool made.
