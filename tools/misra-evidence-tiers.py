"""How much evidence stands behind each `native` MISRA C guideline.

    python tools/misra-evidence-tiers.py <cppcheck-addon-misra.py> <corpus-scan.json>

`native` is the strongest claim this catalogue makes: a clean result on such a
guideline is offered as evidence of conformance. HANDOFF used to summarise the
standing of those rules as "70 have had neither a second implementation nor a
reading", which is true and nearly useless — it does not say *which*, so nobody
can act on it and nobody can tell when it improves.

This splits them four ways:

* **compared** — a committed oracle fixture records *the second implementation's*
  own finding for that guideline, so `misra_agrees_with_cppcheck.rs` (or the
  clang comparison) is actually holding the two to each other.
* **comparable, not reached** — the addon implements it, and neither tool fires:
  no corpus file contains the construct. Actionable: write it.
* **the reference tool under-reports** — the addon implements it and the corpus
  *does* contain the construct, but the addon stays silent, so there is nothing
  to compare against. Knowing why matters: for `13.6` the addon's
  `countSideEffectsRecursive` carries `# Todo: Check function calls`.
* **no second implementation** — the addon does not implement it at all. A
  fixture in `checks.rs` proves the check exists and fires; nothing independent
  has ever disagreed with what it decides. These need the licensed text, or a
  third tool.

**What `compared` must not mean.** This tool once counted a guideline as compared
when *either* side fired it, which let this engine's own finding stand in for the
oracle's: `13.6` was reported as compared for a whole session while cppcheck had
never said a word about it. A comparison needs two opinions, so only the oracle's
fixture can put a guideline in the first tier.

Not a test, because the addon is not in this repository and its version decides
the answer. Run it when the numbers in HANDOFF need refreshing, and pass the
`--format json` output of a scan over the corpus as the second argument.

**That scan cannot be taken from this checkout.** `.sda/scope.toml` excludes
`tools/` as developer harness, so `sda scan tools/misra-corpus` reports
"no analyzable files found" and this tool would then place every guideline in a
tier for want of evidence. Copy the corpus somewhere without a `.sda/` and scan
that. The counts HANDOFF states are checked on every `cargo test` by
`crates/sda-cli/tests/handoff_counts_what_it_claims.rs`, which reads the fixtures
directly and needs neither the addon nor a scan; this tool exists to say *why* a
guideline is unmet, which is the part only the addon can answer.
"""
import io
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def cppcheck_implements(addon: Path) -> set:
    """Guidelines the addon actually dispatches, ignoring commented-out lines.

    `misra_3_2` is written and commented out of the dispatch table; counting it
    overstates the overlap, which is how the figure of 62 shared guidelines was
    once arrived at when the truth is 61.
    """
    found = set()
    for line in io.open(addon, encoding='utf8'):
        stripped = line.strip()
        if stripped.startswith('#'):
            continue
        m = re.search(r'self\.executeCheck\(\s*\d+\s*,\s*self\.misra_(\d+)_(\d+)[a-z]?\b', stripped)
        if m:
            found.add(f'{m.group(1)}.{m.group(2)}')
    return found


def coverage_classes() -> dict:
    text = io.open(REPO / 'crates/sda-rules/data/misra-c-2023.toml', encoding='utf8').read()
    out = {}
    for block in text.split('[[rule]]')[1:]:
        get = lambda k: (re.search(rf'^{k} = "(.*?)"', block, re.M) or [None, None])[1]
        if get('n'):
            out[get('n')] = get('c')
    return out


def clang_covers() -> set:
    """Guidelines a compiler diagnoses, from the captured clang warnings.

    cppcheck's addon is not the only second implementation available. Two
    guidelines it does not run — 2.6 and 3.2 — are things clang warns about, and
    `misra_agrees_with_clang_warnings.rs` holds this engine to it. Counting only
    cppcheck would keep reporting them as unmet.
    """
    path = REPO / 'crates/sda-engine/tests/fixtures/clang-warnings.json'
    if not path.exists():
        return set()
    captured = json.load(io.open(path, encoding='utf8'))
    return {w['guideline'] for case in captured['cases'] for w in case['warnings']}


def oracle_reported() -> set:
    """Guidelines the *second implementation* itself reported, from its fixture.

    This is the only thing that can make a guideline `compared`. What this engine
    reports is not evidence that anyone checked it.
    """
    captured = json.load(
        io.open(REPO / 'crates/sda-engine/tests/fixtures/cppcheck-misra.json', encoding='utf8'))
    return {rule.rsplit('-', 1)[-1]
            for case in captured['cases'] for rule in (f['rule'] for f in case['findings'])}


def we_reported(scan: Path) -> set:
    """Guidelines this engine fires on the corpus.

    Used only to tell "the construct is not in the corpus" from "the construct is
    there and the addon said nothing" — two very different reasons for an absent
    comparison, which the old three-way split ran together.
    """
    return {f['rule'].rsplit('-', 1)[-1]
            for f in json.load(io.open(scan, encoding='utf8'))['findings']
            if f['rule'].startswith('MISRA-C-2023-')}


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__.splitlines()[2].strip(), file=sys.stderr)
        return 2
    addon, scan = Path(sys.argv[1]), Path(sys.argv[2])

    by_clang = clang_covers()
    implemented = cppcheck_implements(addon) | by_clang
    classes = coverage_classes()
    # A guideline clang covers is compared by its own test, whose fixture holds
    # the compiler's own answers — the same standard applied to cppcheck below.
    compared = oracle_reported() | by_clang
    ours = we_reported(scan)

    native = [n for n, c in classes.items() if c == 'native']
    order = lambda n: (n.startswith('D'), [int(p) for p in re.sub(r'^D', '', n).split('.')])
    pick = lambda f: sorted((n for n in native if f(n)), key=order)

    tiers = {
        'compared': pick(lambda n: n in compared),
        'comparable, not reached':
            pick(lambda n: n not in compared and n in implemented and n not in ours),
        'the reference tool under-reports':
            pick(lambda n: n not in compared and n in implemented and n in ours),
        'no second implementation': pick(lambda n: n not in compared and n not in implemented),
    }

    print(f'{len(native)} guidelines are classified `native`.')
    for name, rules in tiers.items():
        print(f'  {name:<32} {len(rules):>3}  {" ".join(rules) if len(rules) <= 20 else ""}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
