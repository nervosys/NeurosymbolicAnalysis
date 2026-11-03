"""Ask clang how a C or C++ file lexes, so the native lexer can be compared.

    python tools/clang-lex-oracle.py <corpus.json> <out.json> [clang.exe]

`clang -cc1 -dump-raw-tokens` is the compiler's own lexer with the preprocessor
switched off: every token, its spelling and its 1-based line:column. That is the
right oracle for `sda-syntax`, whose token boundaries and columns are the
foundation under every native C and C++ finding — the PX4 run checked locations
for *plausibility*, that no line ran past end of file, but nothing had ever
checked them against a compiler.

Whitespace arrives as `unknown` tokens and is dropped here; everything else is
kept, including comments, which the raw lexer reports as single tokens exactly as
`sda-syntax` does.

Output is a fixture committed next to the Rust test, so the comparison is
hermetic and needs neither clang nor this script to run. Re-run it when clang is
upgraded.
"""
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

LOC = re.compile(r"^(\S+) '(.*)'\s*(\[[^\]]*\]\s*)?Loc=<.*?:(\d+):(\d+)>$", re.S)


def tokens_of(clang: str, text: str, dialect: str):
    suffix = ".cpp" if dialect == "cpp" else ".c"
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / ("t" + suffix)
        p.write_text(text, encoding="utf-8", newline="")
        out = subprocess.run(
            [clang, "-cc1", "-dump-raw-tokens", "-x", "c++" if dialect == "cpp" else "c", str(p)],
            capture_output=True,
            text=True,
            encoding="utf-8",
        ).stderr

    tokens = []
    # A token's spelling may contain newlines (a block comment, a continued
    # line), so the dump is split on the `Loc=<...>` terminator rather than on
    # line breaks — splitting on lines silently truncates exactly the tokens
    # this corpus exists to test.
    for chunk in re.findall(r"(?s)(.*?Loc=<[^>]*>)", out):
        m = LOC.match(chunk.strip())
        if not m:
            continue
        kind, spelling, flags, line, col = m.groups()
        if kind == "unknown" and spelling.strip() == "":
            continue  # whitespace
        if kind == "eof":
            continue
        # `[StartOfLine]` marks the start of a *logical* line, and a line splice
        # does not begin one: in a continued `#define`, the tokens on the second
        # physical line do not carry it. That is what makes a directive's extent
        # readable from this dump rather than from a rule reimplemented here —
        # checked against clang before it was relied on.
        tokens.append({
            "kind": kind,
            "text": spelling,
            "line": int(line),
            "column": int(col),
            "startOfLine": "StartOfLine" in (flags or ""),
        })
    return tokens


def main() -> int:
    corpus_path, out_path = sys.argv[1], sys.argv[2]
    clang = sys.argv[3] if len(sys.argv) > 3 else r"C:\Program Files\LLVM\bin\clang.exe"

    version = subprocess.run([clang, "--version"], capture_output=True, text=True).stdout
    version = version.splitlines()[0].strip() if version else "unknown"

    corpus = json.loads(Path(corpus_path).read_text(encoding="utf-8"))
    cases = []
    for c in corpus:
        toks = tokens_of(clang, c["text"], c["dialect"])
        if not toks:
            print(f"{c['name']}: clang produced no tokens", file=sys.stderr)
            return 1
        cases.append({**c, "tokens": toks})

    Path(out_path).write_text(
        json.dumps({"clang": version, "cases": cases}, indent=1, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"{version}: {len(cases)} case(s) -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
