"""Ask clippy where a Rust crate can panic.

    python tools/clippy-lint-oracle.py <out.json> <crate-dir>

The `RUST-2024` rules gate the Rust half of this toolkit and had never been
compared with anything. The MISRA C rules got a second implementation this
session and it cost seven defects; the same question had not been put to these.

Clippy is the obvious second opinion, and it ships with rustup, so there is
nothing to install. Two guidelines map onto its restriction lints exactly:

| guideline | clippy |
|---|---|
| **PANIC.1** `unwrap` and `expect` | `unwrap_used`, `expect_used` |
| **PANIC.2** the diverging macros | `panic`, `unreachable`, `todo`, `unimplemented` |

Captured with `--all-targets`, which matters: without it clippy does not compile
`#[cfg(test)]` code at all, so it would agree with this engine about test modules
by not looking rather than by deciding. With it, the two genuinely disagree
there, and the disagreement is the interesting part.

Output is a fixture committed next to the Rust test, so the comparison runs
without cargo or clippy. Re-run when the corpus or clippy moves.
"""
import json
import subprocess
import sys
from pathlib import Path

LINTS = {
    # Clippy restriction lints.
    'clippy::unwrap_used': 'PANIC.1',
    'clippy::expect_used': 'PANIC.1',
    'clippy::panic': 'PANIC.2',
    'clippy::unreachable': 'PANIC.2',
    'clippy::todo': 'PANIC.2',
    'clippy::unimplemented': 'PANIC.2',
    'clippy::undocumented_unsafe_blocks': 'UNSAFE.1',
    'clippy::missing_safety_doc': 'UNSAFE.2',
    # rustc's own edition lints. These are hard errors at edition 2024, so the
    # corpus that provokes them is kept at 2021 — a refusal to compile is not a
    # diagnostic, and an oracle needs a diagnostic.
    'static_mut_refs': 'UNSAFE.4',
    'missing_unsafe_on_extern': 'ED2024.3',
    'unsafe_attr_outside_unsafe': 'ED2024.4',
    'keyword_idents_2024': 'ED2024.1',
}


def clippy(crate: Path):
    out = subprocess.run(
        ['cargo', 'clippy', '--all-targets', '--message-format=json', '--quiet', '--']
        + [f'-W{lint}' for lint in sorted(set(LINTS))],
        cwd=crate, capture_output=True, text=True, encoding='utf-8', errors='replace',
    )
    found = {}
    for line in out.stdout.splitlines():
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        message = record.get('message') or {}
        code = (message.get('code') or {}).get('code', '')
        guideline = LINTS.get(code)
        if not guideline:
            continue
        for span in message.get('spans', []):
            if not span.get('is_primary'):
                continue
            key = (span['line_start'], guideline)
            found[key] = {'line': span['line_start'], 'guideline': guideline, 'lint': code}
    return [found[k] for k in sorted(found)]


def main() -> int:
    if len(sys.argv) != 3:
        print('usage: clippy-lint-oracle.py <out.json> <crate-dir>', file=sys.stderr)
        return 2
    out_path, crate = Path(sys.argv[1]), Path(sys.argv[2])

    version = subprocess.run(['cargo', 'clippy', '--version'], capture_output=True,
                             text=True).stdout.strip()
    sites = clippy(crate)
    if not sites:
        # A corpus clippy says nothing about is an empty comparison, which reads
        # exactly like agreement.
        print(f'{crate}: clippy reported none of the lints asked for', file=sys.stderr)
        return 1

    Path(out_path).write_text(
        json.dumps({'clippy': version, 'crate_dir': crate.as_posix(), 'sites': sites}, indent=1)
        + '\n',
        encoding='utf-8')
    print(f'{version}: {len(sites)} site(s) -> {out_path}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
