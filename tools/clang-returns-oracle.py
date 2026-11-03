"""Ask clang where every `return` is, per function.

    python tools/clang-returns-oracle.py <corpus.json> <out.json> [clang.exe]

MISRA C Rule 15.5 is about the number of points at which a function can exit, and
`CFunction::exit_points` is how this toolkit counts them: returns found by walking
tokens, plus one if control can fall off the end. It is among the most frequently
fired rules on real code — and the count had never been checked against anything
that parses C.

clang's JSON AST is that check. `ReturnStmt` nodes inside a `FunctionDecl` are
the returns, established by a compiler rather than by brace counting.

# The delta encoding, which is easy to get wrong

clang omits `line` from a location when it is unchanged from the location before
it, and omits `file` likewise. Read naively, every `return` after the first on a
new line lands on line `None` and the comparison quietly comes out empty. The
walk below threads the last seen line through the whole tree, in document order,
which is the order clang emits.
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def walk(node, state, out_returns, current_fn):
    """Depth-first in emission order, threading the last seen line."""
    for key in ("loc", "begin", "end"):
        pass  # locations are handled below, per node

    def line_of(loc):
        if not isinstance(loc, dict):
            return None
        if "line" in loc:
            state["line"] = loc["line"]
        # `expansionLoc` appears for anything inside a macro; its line is the
        # one a reader sees, which is what a finding must cite.
        exp = loc.get("expansionLoc")
        if isinstance(exp, dict) and "line" in exp:
            state["line"] = exp["line"]
        return state.get("line")

    kind = node.get("kind")
    rng = node.get("range") or {}
    line_of(node.get("loc"))
    line_of(rng.get("begin"))

    if kind == "FunctionDecl":
        current_fn = node.get("name")
        if current_fn is not None and node.get("inner"):
            out_returns.setdefault(current_fn, [])
    elif kind == "ReturnStmt" and current_fn is not None:
        out_returns.setdefault(current_fn, []).append(state.get("line"))

    for child in node.get("inner", []) or []:
        walk(child, state, out_returns, current_fn)

    line_of(rng.get("end"))
    return out_returns


def analyse(clang, text):
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "t.c"
        p.write_text(text, encoding="utf-8", newline="")
        out = subprocess.run(
            [clang, "-Xclang", "-ast-dump=json", "-fsyntax-only", "-ffreestanding", str(p)],
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    tree = json.loads(out.stdout)
    returns = {}
    # Only the top level of the translation unit: everything clang pulls in from
    # elsewhere has a `file` on its location and is not this corpus.
    for n in tree.get("inner", []):
        walk(n, {"line": None}, returns, None)
    return {k: sorted(v) for k, v in returns.items()}


def main() -> int:
    corpus_path, out_path = sys.argv[1], sys.argv[2]
    clang = sys.argv[3] if len(sys.argv) > 3 else r"C:\Program Files\LLVM\bin\clang.exe"
    version = subprocess.run([clang, "--version"], capture_output=True, text=True).stdout
    version = version.splitlines()[0].strip() if version else "unknown"

    corpus = json.loads(Path(corpus_path).read_text(encoding="utf-8"))
    cases = []
    for c in corpus:
        functions = analyse(clang, c["text"])
        if not functions:
            print(f"{c['name']}: clang found no functions", file=sys.stderr)
            return 1
        cases.append({**c, "functions": functions})

    Path(out_path).write_text(
        json.dumps({"clang": version, "cases": cases}, indent=1, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"{version}: {len(cases)} case(s) -> {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
