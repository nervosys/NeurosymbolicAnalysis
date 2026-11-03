// Ask Monaco what a set of edits does to a buffer.
//
//   node gui/tools/monaco-edits.mjs <corpus.json> <out.json>
//
// `TextModel.applyEdits` is the multi-cursor path: several ranges, all stated
// against the text as the caller last saw it, applied at once. `sda-editor`
// claims the same contract, and until this existed the claim was tested only
// against the author's own expectation of it.
//
// The buffer's `applyEdits` is the real implementation and is reachable
// headless. What is captured is the resulting text, because that is the
// observable both sides have to agree on; the change records Monaco returns
// alongside it are a different shape from this crate's `ChangeEvent` by design,
// and comparing them would be comparing structures rather than behaviour.
import { readFileSync, writeFileSync } from 'node:fs';

const { createTextBuffer } = await import(
  'monaco-editor/esm/vs/editor/common/model/textModel.js'
);
const { Range } = await import('monaco-editor/esm/vs/editor/common/core/range.js');
const { version } = JSON.parse(
  readFileSync(new URL('../node_modules/monaco-editor/package.json', import.meta.url), 'utf8'),
);

const corpus = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const cases = corpus.map((c) => {
  const b = createTextBuffer(c.text, 1).textBuffer;
  const ops = c.edits.map((e) => ({
    range: new Range(e.sl, e.sc, e.el, e.ec),
    text: e.text,
    forceMoveMarkers: false,
  }));
  b.applyEdits(ops, false, false);
  // `getLinesContent` rather than a join: the terminator a buffer chose is its
  // own business, and asserting on it here would test EOL normalisation instead
  // of edit application.
  return { name: c.name, text: c.text, edits: c.edits, resultLines: b.getLinesContent() };
});

// Overlapping ranges have no joint meaning, and what a buffer does about that is
// worth recording rather than remembering. Monaco throws; `apply_all` returns no
// events and leaves the text alone. Same judgement, different mechanism — and the
// part that matters to a caller is that neither applies half of it.
const overlapping = (() => {
  const b = createTextBuffer('abcdef\n', 1).textBuffer;
  const ops = [
    { range: new Range(1, 2, 1, 5), text: 'X', forceMoveMarkers: false },
    { range: new Range(1, 3, 1, 6), text: 'Y', forceMoveMarkers: false },
  ];
  try {
    b.applyEdits(ops, false, false);
    return { refused: false, resultLines: b.getLinesContent() };
  } catch (e) {
    return { refused: true, how: 'throws', message: e.message, resultLines: b.getLinesContent() };
  }
})();

writeFileSync(
  process.argv[3],
  JSON.stringify({ monaco: version, cases, overlapping }, null, 1) + '\n',
);
console.log(`monaco ${version}: ${cases.length} case(s) -> ${process.argv[3]}`);
