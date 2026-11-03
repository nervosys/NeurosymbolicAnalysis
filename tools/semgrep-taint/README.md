# A real taint run, and what its SARIF does not contain

`crates/sda-engine/tests/fixtures/semgrep-1.176.0-taint.sarif` was captured from
this directory. The program has two paths from the model to the actuator:
`guarded()` clamps, `bypass()` forwards through `relay` and does not. The rule
declares `infer(...)` a source, `write_actuator(...)` a sink, and `clamp(...)` a
sanitizer, so a correct run reports exactly one finding — the bypass.

```bash
# Run from the repository root. `wsl` starts in the translated working
# directory, so the path needs no hand-editing and no `wslpath`.
wsl -d Debian -- bash -lc 'cd tools/semgrep-taint && \
  ~/sgvenv/bin/semgrep --config model-output-to-actuator.yaml \
    --sarif --dataflow-traces --metrics=off --output taint.sarif .'
```

Semgrep OSS 1.176.0, installed with `python3 -m venv ~/sgvenv && ~/sgvenv/bin/pip
install semgrep`.

## The finding this exists to record

`sda_engine::interposition` refutes an interposition proof from a taint *flow*,
because refutation needs the path: a finding that names only where tainted data
landed cannot say whether a guard was crossed on the way. SARIF has a field for
exactly that — `codeFlows` — and `--dataflow-traces` documents itself as
"Explain how non-local values reach the location of a finding (only affects text
and SARIF output)".

**The text output does explain it. The SARIF does not contain it.**

```
    src/main.py
   ❯❯❱ model-output-to-actuator
           24┆ write_actuator(forwarded)

          Taint comes from:
           21┆ raw = infer(prompt)

          Taint flows through these intermediate variables:
```

The SARIF for the same run has no `codeFlows` key, `properties` is `{}`, and the
`--json` output carries no `dataflow_trace` either. The finding arrives with a
sink location and nothing else.

## Why it is recorded rather than worked around

A `codeFlows` parser written from the SARIF specification would have been
correct, complete, and never once exercised by this tool — while
`sda verify --taint` reported `interposed` from a report it could not read. That
is `ext.modelscan` again: an adapter fully green and unable to parse a byte of
what its tool actually wrote.

So the traceless case is handled explicitly instead. A finding that lands on an
effector with no flow is reported as `sda.taint-untraced`, and a report where
every finding is like that gets `sda.taint-inert` — because "the tool looked and
found nothing" and "the tool cannot answer this question" must not produce the
same clean page.

`codeFlows` parsing is still unwritten. It waits for a fixture from a provider
observed to emit it.
