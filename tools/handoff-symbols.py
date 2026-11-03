"""Does every code symbol HANDOFF names still exist?

The document is dense with `ProjectConfig::discover`, `ExternalCoverage::
provenance_of_many`, `RuntimeEventKind`. Each is a checkable claim, and a renamed
function leaves guidance that still reads as authoritative and sends a reader
looking for something that is gone.

**A list to read, not a gate**, for the same reason `uncalled-api-sweep.py` is
one — and for a sharper reason of its own. The document legitimately names
symbols that no longer exist, when the subject *is* the rename:

    `Evidence::is_proof` **was renamed to `is_defect_witness`**

A test would have to permit that, and the only honest way to permit it is a list
of exceptions that grows until it hides a real miss. `every_file_the_document_
names_exists` is a gate because a path has no equivalent case; this does not.

Run it after renaming anything public:

    python tools/handoff-symbols.py

Reading the output: anything printed is a symbol the sweep could not resolve,
which means either the document is stale or the sweep is. Both have happened.

**Calibrate before believing it.** Insert a symbol that does not exist and check
it is reported; a sweep that finds nothing looks identical to a sweep that looks
at nothing. Doing that here found the first version passing
`ProjectConfig::no_such_method`, because it accepted a path when *either* end
resolved and the type still existed — which is the likelier rot, a method renamed
under a surviving type. Two further passes were needed before the noise was real
signal: struct fields (`ProjectConfig::problems` is a field, and the sweep called
it missing) and module paths (`sda_engine::interposition` is a file).

Last swept: 81 symbol paths, all resolved; two needed a human and both were
correct as written — the rename above, and `guard::interposed`, which is a proof
obligation's id rather than a Rust path.
"""
import io
import os
import re

SEP = chr(92)
DOC = 'HANDOFF.md'

# Standard library, external crates, and namespaces that are not Rust paths.
FOREIGN_HEADS = {
    'std', 'core', 'alloc', 'serde', 'serde_json', 'toml', 'clap', 'anyhow',
    'walkdir', 'Vec', 'String', 'Option', 'Result', 'Box', 'Arc', 'Mutex',
    'HashMap', 'BTreeMap', 'BTreeSet', 'Path', 'PathBuf', 'Iterator', 'Self',
    'clippy',   # lint names belong to clippy
    'Command',  # std::process::Command
    'flow', 'guard',  # proof obligation ids, not Rust paths
}

PATHY = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)+$')

DEFINITION = re.compile(
    r'\b(?:fn|struct|enum|trait|type|const|static|macro_rules!)\s+([A-Za-z_][A-Za-z0-9_]*)'
)
VARIANT = re.compile(r'^\s{4}([A-Z][A-Za-z0-9_]*)\s*[({,]', re.M)
FIELD = re.compile(
    r'^\s*(?:pub\s+(?:\([^)]*\)\s*)?)?([a-z_][a-z0-9_]*)\s*:\s*[A-Za-z&<\[]', re.M
)
MODULE = re.compile(r'\bmod\s+([a-z_][a-z0-9_]*)')


def workspace_symbols():
    """Every name this workspace defines: items, enum variants, fields, modules."""
    out = set()
    for root, _, names in os.walk('.'):
        r = root.replace(SEP, '/')
        if any(p in r for p in ('/target', '/node_modules', '/.git', '/dist')):
            continue
        for n in names:
            if not n.endswith('.rs'):
                continue
            src = io.open(os.path.join(root, n), encoding='utf8', errors='replace').read()
            for pat in (DEFINITION, VARIANT, FIELD, MODULE):
                out.update(m.group(1) for m in pat.finditer(src))
            out.add(n[:-3])
            out.add(os.path.basename(root).replace('-', '_'))
    return out


def named_in_document(text):
    """Backticked spans shaped like a Rust path, outside fenced blocks.

    A bare identifier in prose is too easily an English word, so only `A::b`
    forms count. Fenced blocks are skipped because they quote code verbatim,
    including code being described as wrong.
    """
    found = {}
    in_fence = False
    for i, line in enumerate(text.split('\n')):
        if line.lstrip().startswith('```'):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for j, span in enumerate(line.split('`')):
            if j % 2 == 0:
                continue
            sp = span.strip().rstrip('()').rstrip(',;:')
            if PATHY.match(sp) and sp.split('::')[0] not in FOREIGN_HEADS:
                found.setdefault(sp, i + 1)
    return found


def main():
    defined = workspace_symbols()
    candidates = named_in_document(io.open(DOC, encoding='utf8').read())

    missing = []
    for sym, line in sorted(candidates.items()):
        head, last = sym.split('::')[0], sym.split('::')[-1]
        # A lower-case tail is a function, field or module and must exist by that
        # name. Accepting the head alone lets a renamed method pass under a type
        # that survived it.
        if last[:1].islower():
            if last not in defined:
                missing.append((sym, line))
        elif last not in defined and head not in defined:
            missing.append((sym, line))

    print('%d symbol path(s) named, %d unresolved' % (len(candidates), len(missing)))
    if not candidates:
        print('\nNothing was examined, which is not the same as nothing being wrong.')
        return
    for sym, line in missing:
        print('  UNRESOLVED  %-52s (line %d)' % (sym, line))


if __name__ == '__main__':
    main()
