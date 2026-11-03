// Ask Monaco how a decoration's range reacts to text inserted at its edges.
//
//   node gui/tools/monaco-stickiness.mjs <out.json>
//
// `nodeAcceptEdit` is the function Monaco runs on every decoration when the text
// under it changes. It is exported, it takes plain offsets, and it stands up
// headless — so the stickiness semantics can be read off the real implementation
// instead of off its name.
//
// The names matter here more than usual: `sda-editor`'s enum uses Monaco's, and
// two of its three doc comments described the opposite of what this prints.
import { writeFileSync } from 'node:fs';

const it = await import('monaco-editor/esm/vs/editor/common/model/intervalTree.js');

// Monaco keeps stickiness in bits 3-4 of a bit-packed `metadata` field, and the
// setter is module-private. Reproduced from the module's own
// `_setNodeStickiness`, and checked rather than assumed: with the wrong mask all
// four values behave identically, which is what the first attempt did.
const setStickiness = (node, s) => {
  node.metadata = (node.metadata & 231) | (s << 3);
};

const STICKINESS = [
  ['always-grows-when-typing-at-edges', 0],
  ['never-grows-when-typing-at-edges', 1],
  ['grows-only-when-typing-before', 2],
  ['grows-only-when-typing-after', 3],
];

const node = (start, end, stickiness) => {
  const n = new it.IntervalNode(null, start, end);
  setStickiness(n, stickiness);
  n.cachedAbsoluteStart = start;
  n.cachedAbsoluteEnd = end;
  return n;
};

const cases = [];
for (const [name, value] of STICKINESS) {
  for (const [what, start, end, len] of [
    ['insert at the range start', 5, 5, 3],
    ['insert at the range end', 10, 10, 3],
    ['insert strictly inside', 7, 7, 3],
    ['insert strictly before', 2, 2, 3],
    ['insert strictly after', 12, 12, 3],
    ['replace the whole range', 5, 10, 2],
    ['delete the whole range', 5, 10, 0],
  ]) {
    const n = node(5, 10, value);
    it.nodeAcceptEdit(n, start, end, len, false);
    cases.push({ stickiness: name, edit: what, editStart: start, editEnd: end, insertedLength: len, start: n.start, end: n.end });
  }
}

// A guard on the capture itself: if the mask were wrong every stickiness would
// give the same answers, and the fixture would look fine while testing nothing.
const distinct = new Set(cases.map((c) => `${c.edit}|${c.start},${c.end}`)).size;
if (distinct <= cases.length / STICKINESS.length) {
  console.error('every stickiness behaved identically — the metadata mask is wrong');
  process.exit(1);
}

writeFileSync(process.argv[2], JSON.stringify({ note: 'range [5,10) before each edit', cases }, null, 1) + '\n');
console.log(`${cases.length} case(s) -> ${process.argv[2]}`);
