"""Ask clang about the guidelines cppcheck's MISRA addon does not implement.

    python tools/clang-warning-oracle.py <out.json> <clang.exe> <file>...

Fifteen `native` guidelines had no second implementation at all: cppcheck's
addon does not run them, so `misra_agrees_with_cppcheck.rs` cannot hold this
engine to anything. Two of the fifteen are things a *compiler* diagnoses, and
clang is already an oracle in this repository for the lexer and for
`CFunction::returns`.

| guideline | clang |
|---|---|
| **2.6** a label nothing jumps to | `-Wunused-label` |
| **3.2** line-splicing in a `//` comment | `-Wcomment`, "multi-line // comment" |

That is not a coincidence of wording. Both guidelines exist because the
construct misleads a reader about what the program does, which is the same
reason a compiler warns, and both are decidable from the token stream — so
disagreeing with clang here means one of the two is wrong about the code rather
than about the guideline.

The remaining thirteen stay unmet: `6.3 7.6 8.16 8.17 11.10 17.10 21.24 21.25`
and five directives. Compilers do not diagnose them, and cppcheck's addon does
not implement them.

Output is a fixture, committed next to the Rust test, so the comparison runs
without clang installed. Re-run to refresh when clang moves.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

# `warning: <text> [-Wflag]` and `error: <text>`, with the line clang reports.
#
# Errors count. 11.10 is not a style guideline a compiler happens to mention —
# `_Atomic(void)` is a constraint violation, and clang rejects the translation
# unit. A guideline the language itself forbids still needs checking here,
# because this toolkit's premise is that it runs on code that does not build,
# and code that does not build is exactly where a compiler has no opinion to
# offer.
DIAGNOSTIC = re.compile(
    r'^(?P<file>.+?):(?P<line>\d+):\d+: (?:warning|error): (?P<text>.*?)(?:\s*\[-W[a-z-]+\])?$')

# Mapped on the *message*, not the flag. `-Wcomment` covers two different
# guidelines — `'/*' within block comment` is 3.1 and `multi-line // comment` is
# 3.2 — and keying on the flag would have asserted a 3.2 wherever clang found
# the other one, which is a comparison that fails for the wrong reason.
MESSAGES = [
    ('unused label', '2.6'),
    ('multi-line // comment', '3.2'),
    ("'/*' within block comment", '3.1'),
    ('_Atomic cannot be applied to incomplete type', '11.10'),
]

# The same clang message names a different guideline depending on the language.
# `'/*' within block comment` is MISRA C 3.1 and MISRA C++ 5.7.1; the compiler
# has no opinion about which catalogue is being applied, so the oracle has to
# know what it is reading before it can name the rule.
CPP_NUMBERING = {'3.1': '5.7.1', '3.2': '5.7.2'}
CPP_SUFFIXES = ('.cpp', '.cxx', '.cc', '.c++')


def guideline_for(text: str, path: str):
    for fragment, number in MESSAGES:
        if fragment not in text:
            continue
        if path.lower().endswith(CPP_SUFFIXES):
            # A C-only guideline has no C++ counterpart here; saying nothing is
            # better than asserting a number this catalogue does not contain.
            return CPP_NUMBERING.get(number)
        return number
    return None


def std_for(path: str) -> str:
    """A C++ file compiled as C produces a parse error, not a diagnostic."""
    return '-std=c++17' if path.lower().endswith(CPP_SUFFIXES) else '-std=c23'


def warnings_of(clang: str, path: str):
    out = subprocess.run(
        [clang, '-fsyntax-only', std_for(path), '-Wunused-label', '-Wcomment', path],
        capture_output=True, text=True, encoding='utf-8', errors='replace',
    )
    found = []
    for line in (out.stdout + out.stderr).splitlines():
        m = DIAGNOSTIC.match(line.strip())
        if not m:
            continue
        guideline = guideline_for(m.group('text'), path)
        if guideline:
            found.append({'line': int(m.group('line')), 'guideline': guideline})
    found.sort(key=lambda f: (f['line'], f['guideline']))
    return found


def main() -> int:
    if len(sys.argv) < 4:
        print('usage: clang-warning-oracle.py <out.json> <clang> <file>...', file=sys.stderr)
        return 2
    out_path, clang = sys.argv[1], sys.argv[2]
    files = sys.argv[3:]

    version = subprocess.run([clang, '--version'], capture_output=True, text=True).stdout
    version = version.splitlines()[0].strip() if version else 'unknown'

    cases = []
    for f in files:
        found = warnings_of(clang, f)
        if not found:
            # A corpus file that provokes nothing contributes an empty
            # comparison, which is indistinguishable from agreement.
            print(f'{f}: clang warned about none of the guidelines asked for', file=sys.stderr)
            return 1
        cases.append({'path': Path(f).as_posix(), 'warnings': found})

    Path(out_path).write_text(
        json.dumps({'clang': version, 'cases': cases}, indent=1) + '\n', encoding='utf-8')
    total = sum(len(c['warnings']) for c in cases)
    print(f'{version}: {total} warning(s) over {len(cases)} file(s) -> {out_path}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
