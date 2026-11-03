"""Ask clang-tidy about the MISRA C++ guidelines it also decides.

    python tools/clang-tidy-oracle.py <out.json> <clang-tidy.exe> <file>...

Twenty-one MISRA C++:2023 guidelines are classified `native` in this catalogue —
a clean result on one is offered as evidence of conformance — and not one had
ever been compared with anything. The MISRA C sweep cost seven defects and the
Rust sweep cost one; there was no reason to expect this catalogue to be in better
shape, only a reason nobody had looked.

clang-tidy's `cppcoreguidelines` module decides five of them, and the mapping is
close to exact because both are restating the same C++ Core Guidelines:

| guideline | check |
|---|---|
| **8.2.1** no C-style cast | `google-readability-casting` |
| **8.2.2** no `reinterpret_cast` | `cppcoreguidelines-pro-type-reinterpret-cast` |
| **8.2.3** no `const_cast` | `cppcoreguidelines-pro-type-const-cast` |
| **9.6.1** no `goto` | `cppcoreguidelines-avoid-goto` |
| **21.6.1** no dynamic allocation | `cppcoreguidelines-no-malloc` |

8.2.1 needs `google-readability-casting` rather than the cppcoreguidelines cast
check, which only fires on casts that remove constness — a difference worth
knowing before concluding that a tool disagrees.

Output is a fixture committed next to the Rust test, so the comparison runs
without clang-tidy installed.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

CHECKS = {
    'google-readability-casting': '8.2.1',
    'cppcoreguidelines-pro-type-reinterpret-cast': '8.2.2',
    'cppcoreguidelines-pro-type-const-cast': '8.2.3',
    'cppcoreguidelines-avoid-goto': '9.6.1',
    'cppcoreguidelines-no-malloc': '21.6.1',
    'llvm-header-guard': '19.6.1',
    'cppcoreguidelines-macro-usage': '19.0.1',
    # Matched to 12.2.1 with a caveat the test states: this check is about
    # *accessing* a union member and the guideline is about *declaring* one, so
    # the two fire in different places. The same shape as Rust's UNSAFE.4 against
    # `static_mut_refs` — a lint objects to the use, a MISRA rule to the thing.
    'cppcoreguidelines-pro-type-union-access': '12.2.1',
    'readability-braces-around-statements': '9.4.1',
    'cert-err52-cpp': '21.10.1',
    # Compiler warnings, which clang-tidy surfaces under `clang-diagnostic-*`.
    # Worth having: for these the second implementation is the compiler itself
    # rather than a linter's opinion about style.
    'clang-diagnostic-switch-default': '9.4.3',
    'clang-diagnostic-implicit-fallthrough': '9.4.2',
}

# Warnings clang does not enable by default, needed for the `clang-diagnostic-*`
# checks above to have anything to report.
EXTRA_WARNINGS = ['-Wimplicit-fallthrough', '-Wswitch-default']

DIAGNOSTIC = re.compile(r'^(?P<file>.+?):(?P<line>\d+):\d+: warning: .*\[(?P<check>[a-z0-9-]+)\]$')

HEADER_SUFFIXES = ('.hpp', '.hh', '.hxx', '.h++')


def tidy(clang_tidy: str, path: str):
    # A header compiled as a translation unit is still a header: without
    # `-x c++-header`, `llvm-header-guard` has nothing to say about it.
    language = ['-x', 'c++-header'] if path.lower().endswith(HEADER_SUFFIXES) else []
    out = subprocess.run(
        [clang_tidy, '--quiet', f'--checks=-*,{",".join(sorted(CHECKS))}', path,
         '--', '-std=c++17', *EXTRA_WARNINGS, *language],
        capture_output=True, text=True, encoding='utf-8', errors='replace',
    )
    found = {}
    for line in (out.stdout + out.stderr).splitlines():
        m = DIAGNOSTIC.match(line.strip())
        if not m:
            continue
        guideline = CHECKS.get(m.group('check'))
        if not guideline:
            continue
        key = (int(m.group('line')), guideline)
        found[key] = {'line': key[0], 'guideline': guideline, 'check': m.group('check')}
    return [found[k] for k in sorted(found)]


def main() -> int:
    if len(sys.argv) < 4:
        print('usage: clang-tidy-oracle.py <out.json> <clang-tidy> <file>...', file=sys.stderr)
        return 2
    out_path, clang_tidy = sys.argv[1], sys.argv[2]

    version = subprocess.run([clang_tidy, '--version'], capture_output=True, text=True).stdout
    version = ' '.join(version.split())[:80] if version else 'unknown'

    cases = []
    for f in sys.argv[3:]:
        found = tidy(clang_tidy, f)
        if not found:
            print(f'{f}: clang-tidy reported none of the checks asked for', file=sys.stderr)
            return 1
        cases.append({'path': Path(f).as_posix(), 'findings': found})

    Path(out_path).write_text(
        json.dumps({'clang_tidy': version, 'cases': cases}, indent=1) + '\n', encoding='utf-8')
    total = sum(len(c['findings']) for c in cases)
    print(f'{version}: {total} finding(s) over {len(cases)} file(s) -> {out_path}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
