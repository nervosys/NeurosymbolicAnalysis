# A C++ `codeFlows` capture, and why one language was not enough

`tools/codeql-taint/` is the Python version of this program and came first. This
is the same shape in C++ — the same four components, the same guarded route and
the same relay the architecture declaration forgets — and it exists because
`crates/sda-engine/tests/real_taint_report.rs` had already established that
Semgrep OSS emits no `codeFlows` at all. The refutation channel therefore rested
on **one capture, from one tool, in one language**, and a parser with one witness
is a parser that fits one tool.

It found two defects on first contact, both in code documented as deliberate.

## What the second producer changed

**Three code flows, not one.** The Python result carries a single `codeFlow`. The
C++ result carries three, and *the first one goes through the guard*:

```
codeFlow 0: 20 steps :: app.cpp -> policy -> app.cpp -> guard     -> app.cpp -> actuator
codeFlow 1: 20 steps :: app.cpp -> policy -> app.cpp -> telemetry -> app.cpp -> actuator
codeFlow 2: 24 steps :: app.cpp -> policy -> app.cpp -> guard     -> ...     -> actuator
```

`parse_sarif` read `codeFlows[0]` and `taint_bypasses` read the first trace on
the finding, each with a comment explaining why that was enough. For rendering it
is. For refutation it is not: interposition fails if **any** route reaches the
effector without crossing a guard, so keeping one route makes the verdict depend
on the order the producer happened to emit them. Here that order would have
reported a clean proof from a report that contained its own counterexample.

**The flow does not start inside the model.** CodeQL's Python source is `request`
inside `policy/serve.py`, so that trace began in the neural component, and
`taint_bypasses` required exactly that. The C++ source is `argv`, which enters at
`main` — outside every declared component — so the same claim arrived as a trace
the check silently skipped. The claim being tested is *"model output cannot reach
an effector without crossing a guard"*, so what matters is the segment from the
last visit to a neural component onward; anything before it is how data reached
the model, which is a different question.

Neither defect is visible from the SARIF specification. Both required a second
tool output that exercised a shape the first one did not have.

## Reproducing the capture

CodeQL is not installed by this repository. Fetch the bundle (~700 MB, includes
the C++ query pack — the CLI alone cannot run the queries):

```bash
curl -sSL -o bundle.tar.gz \
  https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.26.4/codeql-bundle-win64.tar.gz
tar xzf bundle.tar.gz          # unpacks ./codeql/
```

Build the database. **Give `--command` a relative output path**: CodeQL runs the
build through `cmd.exe`, which does not understand an MSYS `/c/...` path and
fails the link with `LNK1104` while the compiler itself is fine.

```bash
codeql/codeql database create tools/codeql-taint-cpp/db \
  --language=cpp --source-root=tools/codeql-taint-cpp \
  --command="clang++ -std=c++17 -I. -o tainted.exe app.cpp policy/serve.cpp \
             guard/clamp.cpp telemetry/relay.cpp actuator/drive.cpp"
```

```bash
codeql/codeql database analyze tools/codeql-taint-cpp/db \
  codeql/cpp-queries:Security/CWE/CWE-078/ExecTainted.ql \
  --format=sarif-latest --output=cpp-taint.sarif
```

The result is `crates/sda-engine/tests/fixtures/codeql-2.26.4-cpp-taint.sarif`,
edited only to replace the absolute path of the unpacked bundle with
`<codeql-bundle>`. The database and `tainted.exe` are gitignored.

`argv` is the taint source on purpose: it is one CodeQL's own C++ libraries
model, which makes this a test of the tool rather than of a hand-written flow.
