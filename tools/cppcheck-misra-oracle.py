"""Ask cppcheck's MISRA addon which guidelines a file violates.

    python tools/cppcheck-misra-oracle.py <out.json> <cppcheck.exe> <file>...
    python tools/cppcheck-misra-oracle.py --drift <cppcheck.exe> <file>...

Everything verified so far sits *beneath* the rules: the lexer finds the right
tokens, the structure analyser finds the right returns, the adapters parse their
tools. Whether `MISRA-C-2023-15.5` implements what 15.5 *says* rests on a
paraphrase, because the normative text is licensed and not in this repository.

This is the one check available without the document: **a second implementation
to disagree with.** cppcheck's MISRA addon reports rule *numbers* without the
licensed rule texts — `--rule-texts` only supplies the prose — so the set of
guidelines it fires, and where, can be compared with ours.

# What this is not

An oracle. Neither tool is authoritative, and the addon targets MISRA C:**2012**
while this toolkit targets **2023**; the numbering carries over for most rules and
not for all. A disagreement means at least one of the two is wrong, or the two
editions differ — it does not say which. That is still worth having, and it is
what item 27 asks for.
"""
import json
import re
import subprocess
import sys
from pathlib import Path

LINE = re.compile(r"^(.*?):(\d+): (misra-c2012-[0-9.]+)$")


def misra_of(cppcheck: str, path: str):
    out = subprocess.run(
        [
            cppcheck,
            "--addon=misra",
            "--enable=all",
            "--template={file}:{line}: {id}",
            path,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    found = []
    for line in (out.stdout + out.stderr).splitlines():
        m = LINE.match(line.strip())
        if m:
            found.append({"line": int(m.group(2)), "rule": m.group(3)})
    found.sort(key=lambda f: (f["line"], f["rule"]))
    return found


FIXTURE = Path(__file__).resolve().parent.parent / "crates/sda-engine/tests/fixtures/cppcheck-misra.json"


def drift(cppcheck: str, files) -> int:
    """Compare the installed cppcheck against the committed fixture.

    The fixture exists so the comparison runs without cppcheck installed, and
    that is what makes it a floor: it records one release's *thoroughness* as
    though it were the guideline's. cppcheck 2.21.0 fires `8.7` nineteen times on
    this corpus where 2.17.1 fires it none — same check, same dispatch table, a
    sharper implementation. Nothing in the suite would notice the next release
    getting sharper again, because the suite is written against these answers.

    So this says what a newer cppcheck would add. It is not a test and must not
    become one: a finding the fixture lacks is news about cppcheck, not a defect,
    and deciding what to do with it needs a person.
    """
    recorded = json.loads(FIXTURE.read_text(encoding="utf-8"))
    was = {
        (c["path"].replace("\\", "/"), f["line"], f["rule"])
        for c in recorded["cases"]
        for f in c["findings"]
    }

    now = set()
    for f in files:
        for finding in misra_of(cppcheck, f):
            now.add((Path(f).as_posix(), finding["line"], finding["rule"]))

    version = subprocess.run([cppcheck, "--version"], capture_output=True, text=True).stdout.strip()
    gained, lost = now - was, was - now
    print(f"fixture : {recorded['cppcheck']}, {len(was)} finding(s)")
    print(f"installed: {version}, {len(now)} finding(s)")
    print(f"  it now finds that the fixture lacks : {len(gained)}")
    print(f"  the fixture has that it no longer finds: {len(lost)}")

    for label, s in (("GAINED", gained), ("LOST", lost)):
        by_rule = {}
        for _, _, rule in s:
            by_rule[rule] = by_rule.get(rule, 0) + 1
        if by_rule:
            top = sorted(by_rule.items(), key=lambda kv: -kv[1])[:10]
            print(f"  {label}: " + " ".join(f"{r} x{n}" for r, n in top))

    if gained:
        print("\nA newer cppcheck finding more is not a defect here. It means the fixture")
        print("records a floor, and somebody should decide whether to re-capture it.")
    return 0


def main() -> int:
    if sys.argv[1:2] == ["--drift"]:
        return drift(sys.argv[2], sys.argv[3:])
    out_path, cppcheck = sys.argv[1], sys.argv[2]
    files = sys.argv[3:]
    version = subprocess.run([cppcheck, "--version"], capture_output=True, text=True).stdout.strip()

    cases = []
    for f in files:
        findings = misra_of(cppcheck, f)
        if not findings:
            print(f"{f}: the addon reported no MISRA violations", file=sys.stderr)
            return 1
        cases.append({"path": Path(f).as_posix(), "findings": findings})

    Path(out_path).write_text(
        json.dumps({"cppcheck": version, "cases": cases}, indent=1) + "\n", encoding="utf-8"
    )
    print(f"{version}: {sum(len(c['findings']) for c in cases)} finding(s) -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
