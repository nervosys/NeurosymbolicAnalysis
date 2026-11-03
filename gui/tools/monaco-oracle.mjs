// Ask real Monaco what its text model says, so the Rust port can be compared
// against the thing it is a port of.
//
//   node gui/tools/monaco-oracle.mjs <corpus.json> <out.json>
//
// `sda-editor` calls itself "a Rust-native port of Monaco's text model". Until
// this existed, that claim rested entirely on the porter's own expectations:
// forty-nine tests, every one of them asserting what the author believed Monaco
// does. This asks Monaco.
//
// It loads `monaco-editor/esm/vs/editor/common/model/textModel.js` directly and
// uses `createTextBuffer`, not `new TextModel`. The model class needs Monaco's
// dependency-injection container and a DOM; the *buffer* underneath it is where
// positions, offsets and line lengths actually live, is the same code the editor
// runs, and stands up headless. Using the real implementation rather than a
// hand-written idea of it is the entire point.
//
// Output is a fixture, committed next to the Rust test, so the comparison is
// hermetic and does not need node or a checkout of Monaco to run. Re-run this to
// refresh it when Monaco is upgraded — and expect the diff to be interesting.
import { readFileSync, writeFileSync } from 'node:fs';

const [, , corpusPath, outPath] = process.argv;
if (!corpusPath || !outPath) {
  console.error('usage: monaco-oracle.mjs <corpus.json> <out.json>');
  process.exit(2);
}

const { createTextBuffer } = await import(
  'monaco-editor/esm/vs/editor/common/model/textModel.js'
);
const { version } = JSON.parse(
  readFileSync(new URL('../node_modules/monaco-editor/package.json', import.meta.url), 'utf8'),
);

const corpus = JSON.parse(readFileSync(corpusPath, 'utf8'));
const cases = corpus.map((c) => {
  // `1` is DefaultEndOfLine.LF: the buffer normalises only where the text does
  // not say, and every case here says.
  const b = createTextBuffer(c.text, 1).textBuffer;

  const lines = [];
  for (let l = 1; l <= b.getLineCount(); l++) {
    lines.push({ line: l, content: b.getLineContent(l), length: b.getLineLength(l) });
  }

  // Every offset, not a sample. The interesting disagreements are at the seams —
  // the code unit after an astral character, the position of the final offset —
  // and a sample chosen by the person who wrote the port would miss exactly
  // those.
  const offsets = [];
  for (let o = 0; o <= b.getLength(); o++) {
    const p = b.getPositionAt(o);
    offsets.push([o, p.lineNumber, p.column]);
  }

  return { name: c.name, text: c.text, lineCount: b.getLineCount(), length: b.getLength(), lines, offsets };
});

writeFileSync(outPath, JSON.stringify({ monaco: version, cases }, null, 1) + '\n');
console.log(`monaco ${version}: ${cases.length} case(s) -> ${outPath}`);
