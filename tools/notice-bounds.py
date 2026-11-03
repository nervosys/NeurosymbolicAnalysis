"""Which NOT CHECKED notices can be pushed an unbounded number of times?

One entry per declared component or per provider is bounded by the declaration:
a reader can see all of them. One entry per source file or per finding is bounded
only by the size of the tree, and at that size the section stops being read --
which is what `sda.unmapped` did, at sixty of seventy-seven lines.

For each push site this reports the innermost enclosing `for` loop, by matching
brace depth. Judgement about which collections are large is left to the reader;
the point is to see every site's loop at once instead of one at a time.
"""
import io
import os
import re

SEP = chr(92)
PUSH = re.compile(r'(not_checked|notices|exclusions)\.push')
FOR = re.compile(r'^\s*for\s+(.+?)\s*\{')

files = []
for root, _, names in os.walk('crates'):
    if '/tests/' in root.replace(SEP, '/') or root.replace(SEP, '/').endswith('/tests'):
        continue
    for n in names:
        if n.endswith('.rs'):
            files.append(os.path.join(root, n).replace(SEP, '/'))

rows = []
for f in files:
    src = io.open(f, encoding='utf8', errors='replace').read()
    lines = src.split('\n')

    # Brace depth per line start, so an enclosing `for` is one at lower depth.
    depth = 0
    depths = []
    for ln in lines:
        depths.append(depth)
        code = re.sub(r'//.*', '', ln)
        depth += code.count('{') - code.count('}')

    for i, ln in enumerate(lines):
        if not PUSH.search(ln):
            continue
        # Walk back for the innermost `for` at strictly lower depth.
        loop = None
        for j in range(i - 1, -1, -1):
            if depths[j] < depths[i] and FOR.match(lines[j]):
                loop = lines[j].strip()
                break
            if depths[j] == 0 and j < i - 1 and lines[j].startswith(('fn ', 'pub fn ')):
                break
        rows.append((f, i + 1, loop))

print('%-44s %6s  %s' % ('file', 'line', 'innermost enclosing for-loop'))
unbounded = 0
for f, line, loop in rows:
    if loop:
        unbounded += 1
    print('%-44s %6d  %s' % (f.replace('crates/', ''), line, loop or '(not in a loop)'))
print()
print('%d site(s), %d inside a loop' % (len(rows), unbounded))
