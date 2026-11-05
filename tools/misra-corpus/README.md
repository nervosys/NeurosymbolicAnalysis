# A MISRA corpus, written to be disagreed with

These files exist for one test: `crates/sda-engine/tests/misra_agrees_with_cppcheck.rs`,
which compares this toolkit's MISRA C implementation against cppcheck's MISRA
addon — the only second implementation available without the licensed document.

The comparison was previously run over four files that happened to be in the
repository, and they exercised about twenty guidelines. cppcheck's addon and this
toolkit both claim to implement **62** of the same ones. These files are written
to reach the rest.

## How they were written

One construct per guideline, from a description of what each guideline is
about and without reading the checks in `crates/sda-engine/`. Writing them from
the implementation would have produced a corpus that agrees with it by
construction, which is the failure this repository has a table of.

The guideline text is licensed and is not in this repository, so a construct
may miss what the guideline actually says. That is a limitation of the
corpus and not of the comparison: a construct neither tool flags simply
contributes nothing.

## They are not example code

Every file violates guidelines on purpose. `tools` is declared out of the
delivered product in `.sda/scope.toml`, alongside `valgrind-wsl/three-sins` and
`codeql-taint-cpp`, which exist for the same reason. Nothing here is compiled or
shipped.

## Refreshing the capture

```sh
python tools/cppcheck-misra-oracle.py \
    crates/sda-engine/tests/fixtures/cppcheck-misra.json \
    '<tools>\cppcheck-2.21.0\PFiles\Cppcheck\cppcheck.exe' \
    examples/firmware/src/main.c examples/coverage/main.c \
    tools/valgrind-wsl/three-sins/main.c tools/valgrind-wsl/vgwrap.c \
    $(ls tools/misra-corpus/*.c | grep -v atomic_void.c)
```

A file cppcheck cannot parse produces no MISRA findings at all, and the oracle
script refuses to write a capture for one — an empty comparison that looks like
agreement is exactly what must not happen quietly.
