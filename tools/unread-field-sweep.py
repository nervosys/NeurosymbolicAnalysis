"""Public fields nothing reads.

The companion to `uncalled-api-sweep.py`, and it exists because that one has a
blind spot this found the hard way.

`RustLexed::unterminated_block_comments` was computed on every Rust file and read
by nothing outside the lexer's own tests, so a file behind an unclosed `/*` left
the scan with no finding and no notice. `uncalled-api-sweep.py` could not have
found it: that sweep lists `pub fn`, and this was a public *field*. Running this
one then found `RunOptions::timeout_secs`, documented as a wall-clock budget and
honoured by nothing, and `RunOptions::settings`, a whole provider-configuration
mechanism no provider consults.

**A list to read, not a gate**, for the same reason as the `pub fn` sweep. Three
kinds of entry here are honest:

  * fields that serde serialises -- every `Report` field is "unread" by this
    measure and reaches the user through `--format json`;
  * fields destructured by pattern rather than accessed by name;
  * parser surface. `sda-syntax` exists to expose structure, and a consumer
    taking two fields of six is the crate working as intended, not a defect.

What is worth opening is a field that is **never populated with anything but a
default**, or one whose *doc comment makes a promise*. Both have been real here:
`RustItem::attributes` was never written to, so `#[test]` and `#[no_mangle]` read
as absent everywhere, and `UnsafeRegion::enclosing_item` was always `None`, read
by nothing, and the one field in its struct with no doc comment at all -- deleted
rather than left as a trap for the next check that trusts its name.

Reading the output: `reads` counts `.field` accesses in production code, `foreign`
counts those outside the file that declares it, `tests` counts accesses in test
code. Sort by `foreign`. **A field with tests and no production reads is the
shape worth opening** -- somebody cared enough to assert on it and nothing uses
the answer.

**Calibrate before believing it.** The first version reported zero fields in the
whole workspace, because `^\\s*pub` was compiled without `re.MULTILINE` and
matched only at the start of a file. A sweep that finds nothing looks exactly
like a sweep that looks at nothing.
"""
import io
import os
import re

SEP = chr(92)

FIELD = re.compile(r'^\s*pub\s+([a-z_][a-z0-9_]*)\s*:\s*[^=]', re.M)
TEST_MARK = re.compile(r'^#\[cfg\(test\)\]', re.M)


def test_start(text):
    """Where the file's own test module begins, or the end of the file.

    Anchored at column zero: an indented `#[cfg(test)]` inside a function made an
    earlier sweep read half a file as tests and call five wired parsers dead.
    """
    m = TEST_MARK.search(text)
    return m.start() if m else len(text)


def main():
    files = []
    for root, _, names in os.walk('crates'):
        for n in names:
            if n.endswith('.rs'):
                files.append(os.path.join(root, n).replace(SEP, '/'))

    src = {f: io.open(f, encoding='utf8', errors='replace').read() for f in files}

    declared = {}
    for f, text in src.items():
        for m in FIELD.finditer(text[:test_start(text)]):
            declared.setdefault(m.group(1), set()).add(f)

    rows = []
    for name, where in declared.items():
        prod = foreign = tests = 0
        # `.name` not followed by `(`, which is what separates a field read from
        # a method call.
        pat = re.compile(r'\.' + re.escape(name) + r'\b(?!\s*\()')
        for f, text in src.items():
            cut = test_start(text)
            for m in pat.finditer(text):
                if '/tests/' in f or m.start() >= cut:
                    tests += 1
                else:
                    prod += 1
                    if f not in where:
                        foreign += 1
        rows.append((foreign, prod, -tests, name, sorted(where)))

    rows.sort()

    print('%-32s %6s %8s %6s  %s' % ('pub field', 'reads', 'foreign', 'tests', 'declared in'))
    unread = 0
    for foreign, prod, negtests, name, where in rows:
        if foreign:
            continue
        unread += 1
        print('%-32s %6d %8d %6d  %s'
              % (name, prod, foreign, -negtests, ', '.join(w.split('/')[-1] for w in where[:2])))

    print()
    if not rows:
        print('No public fields found at all, which is not the same as none being unread.')
        return
    print('%d public field name(s); %d never read outside the file that declares them.'
          % (len(rows), unread))


if __name__ == '__main__':
    main()
