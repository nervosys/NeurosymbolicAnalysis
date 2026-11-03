# The Python `codeFlows` capture

The program `sda verify --taint` was first driven against end to end: a declared
architecture that proves interposition, and a real CodeQL run that refutes it.
`policy/serve.py` stands in for the model, `guard/clamp.py` is the shield,
`actuator/drive.py` is the effector, and `telemetry/relay.py` is the relay the
declaration forgets.

This README is written after the fact — `.gitignore` referenced it for the
database path before it existed — so the commands below are the reproduction, not
the original transcript.

```bash
codeql/codeql database create tools/codeql-taint/db \
  --language=python --source-root=tools/codeql-taint

codeql/codeql database analyze tools/codeql-taint/db \
  codeql/python-queries:Security/CWE-078/CommandInjection.ql \
  --format=sarif-latest --output=taint.sarif
```

The capture is `crates/sda-engine/tests/fixtures/codeql-2.26.4-taint.sarif`, and
`crates/sda-adapters/tests/fixtures/ext.codeql-taint.sarif` is the same bytes
serving the adapter's parser test.

**What it cost when it was first run.** Two defects, both in code that was green:
`parse_sarif` never read `codeFlows` at all, and CodeQL writes CWEs as
`external/cwe/cwe-078` where the tag reader only knew `CWE-78:` — so no real
CodeQL finding could ever have been *confirmed*.

**What it could not show.** This result carries exactly one `codeFlow`, and its
flow begins inside `policy/serve.py`. Both are accidents of the language and the
query, and both hid a defect until `tools/codeql-taint-cpp/` produced a result
with three flows starting at `argv`. See that README.

`ext.codeql.txt` — the fixture behind the *adapter* spec rather than this taint
path — is still a reconstruction. A C++ result with a real `codeFlows` block now
exists, which is what the second directory is for.
