# The program the `ext.valgrind` fixture was recorded from

`main.c` commits exactly three sins — an invalid write past an allocation, a
conditional jump on an uninitialised value, and a leak — one for each shape
Memcheck reports differently. `crates/sda-adapters/tests/fixtures/ext.valgrind.txt`
is the captured output of running Memcheck 3.24.0 against it, and that fixture's
assertions name **lines 5, 6, 12 and 17-19 of this file**.

It sat loose in the repository root, outside both self-scan paths, and was listed
for deletion as leftover clutter. It is not: deleting it would leave a captured
fixture with no reproducible source, which is how a fixture quietly becomes a
reconstruction again. Keep the basename `main.c` — the fixture's frames say so.

```bash
# Run from the repository root. `wsl` starts in the translated working
# directory, so the path needs no hand-editing.
wsl -d Debian -- bash -c 'cd tools/valgrind-wsl/three-sins && \
  gcc -g -O0 -o prog main.c && valgrind --leak-check=full --error-exitcode=1 ./prog'
```
