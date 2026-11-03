"""Public functions the workspace defines and never calls in production.

    python tools/uncalled-api-sweep.py

This codebase keeps producing one particular defect: a function that computes the
right answer, carries a doc comment describing when it matters, is unit-tested,
and is called by nothing at the one place it would matter. Three confirmed
instances before this tool existed —

* `ExternalAdapter::timeout`, a public field nothing read, so a hung tool ran
  forever;
* `DeviationRegister::is_expired` and `expired()`, both correct and both
  bypassed, so an acceptance that lapsed in 2020 still suppressed its finding;
* `correlate::coverage_gaps`, whose own comment said a coverage hole "belongs on
  a different work queue" and which no report ever showed — and which was
  additionally wrong, pairing correlations with findings by position when the
  two stop being parallel at the first suppressed finding.

A unit test does not catch this. The test exercises the function directly, so it
passes precisely because it is the only caller.

Output is one row per `pub fn` with no call site outside its own definition and
its own crate's tests. Most rows are honest library surface — a workspace with a
CLI on top legitimately exposes more than it consumes — so this is a list to read,
not a gate to enforce. Sort by the test column: a function somebody cared enough
to test, and nothing calls, is the shape worth opening.

**Calibrate it before believing it.** The first version reported 1 row of 654,
because it recorded the offset of `pub` while the call-site pattern matches the
name seven characters later, so every definition counted as its own caller and
only generic functions (whose `<` breaks the pattern) ever escaped. It was caught
by deleting the known `expired()` call site and finding that the output did not
change. An instrument whose output is identical with and without the defect it
looks for is not evidence of anything. Re-run that check after editing this file.
"""
import io, os, re

SRC_DIRS = ['crates', 'gui/src-tauri/src']
SEP = chr(92)  # backslash, written this way to survive shell heredocs


def rs_files(roots):
    for root in roots:
        for dirpath, _, names in os.walk(root):
            for n in names:
                if n.endswith('.rs'):
                    yield os.path.join(dirpath, n).replace(SEP, '/')


files = sorted(set(rs_files(SRC_DIRS)))
text = {f: io.open(f, encoding='utf8', errors='replace').read() for f in files}


def test_span(src):
    """Byte range of the file's test module: a `#[cfg(test)]` in column zero.

    Matching the first `#[cfg(test)]` anywhere is wrong, and wrong in the
    direction that invents findings. `sda-adapters/src/lib.rs` carries an
    indented one on a single item at line 275, so everything below it — including
    the dispatch table at line 868 that calls five of the tool parsers — was read
    as test code, and those five parsers were reported as called by nothing.

    A module-level `#[cfg(test)] mod tests` is unindented by convention and by
    rustfmt, so column zero is the discriminator.
    """
    m = re.search(r'^#\[cfg\(test\)\]', src, re.M)
    return (m.start(), len(src)) if m else (len(src), len(src))


# Definitions: pub fn NAME in a src/ file, outside that file's test module.
defs = []
for f in files:
    if '/tests/' in f or '/benches/' in f:
        continue
    ts, te = test_span(text[f])
    for m in re.finditer(r'\bpub(?:\(crate\))?\s+fn\s+([a-z_][a-z0-9_]*)\s*[(<]', text[f]):
        if ts <= m.start() < te:
            continue
        defs.append((m.group(1), f, m.start(1)))

counts = {}
for name, f, at in defs:
    prod = 0
    testonly = 0
    pat = re.compile(r'(?<![A-Za-z0-9_])' + re.escape(name) + r'\s*[(:]')
    for g in files:
        ts, te = test_span(text[g])
        for m in pat.finditer(text[g]):
            if g == f and m.start() == at:
                continue  # the definition itself
            if '/tests/' in g or (ts <= m.start() < te):
                testonly += 1
            else:
                prod += 1
    counts[(name, f)] = (prod, testonly)

rows = [(n, f, p, t) for (n, f), (p, t) in counts.items() if p == 0]
print('%-34s %-48s %5s %5s' % ('fn', 'defined in', 'prod', 'test'))
for n, f, p, t in sorted(rows, key=lambda r: (-r[3], r[0])):
    print('%-34s %-48s %5d %5d' % (n, f.replace('crates/', ''), p, t))
print()
print('pub fns with no production call site: %d of %d' % (len(rows), len(defs)))
