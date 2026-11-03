// Ask a real Monaco `TextModel` — not its buffer — what it says.
//
//   node gui/tools/monaco-model-oracle.mjs <corpus.json> <out.json>
//
// `monaco-oracle.mjs` compares the *buffer*: raw arithmetic over lines and
// offsets. Above it sits the model, and the difference between the two is a
// validating layer. `TextModel.getOffsetAt` validates its argument first, so a
// column past the end of a line comes back clamped; the buffer cheerfully
// returns an offset past the end of the document. `sda-editor` is a port of the
// *model*, and until this existed the layer that makes it a model had never been
// compared with anything.
//
// HANDOFF item 24 said this needed "a DOM and Monaco's dependency-injection
// container". The DOM is not needed — none of the position code touches it — and
// the container turned out to be three small stubs, below. The methods compared
// here never reach them; the stubs exist only to get the constructor to return.
// If Monaco ever starts calling into them from this code path, the stubs will
// throw rather than quietly answer, which is the behaviour to want.
//
// Output is a fixture, committed next to the Rust test, so the comparison is
// hermetic. Re-run to refresh when Monaco is upgraded.
import { readFileSync, writeFileSync } from 'node:fs';

const [, , corpusPath, outPath] = process.argv;
if (!corpusPath || !outPath) {
  console.error('usage: monaco-model-oracle.mjs <corpus.json> <out.json>');
  process.exit(2);
}

const { TextModel } = await import('monaco-editor/esm/vs/editor/common/model/textModel.js');
const { version } = JSON.parse(
  readFileSync(new URL('../node_modules/monaco-editor/package.json', import.meta.url), 'utf8'),
);

const noop = () => {};
// Deliberately minimal: anything the compared methods actually needed would
// fail loudly here rather than return a plausible-looking wrong answer.
const undoRedoService = {
  removeElements: noop,
  pushElement: noop,
  getLastElement: () => null,
  setElementsValidFlag: noop,
};
const languageSelection = { languageId: 'plaintext', onDidChange: () => ({ dispose: noop }) };
const languageService = {
  languageIdCodec: { encodeLanguageId: () => 1, decodeLanguageId: () => 'plaintext' },
  requestRichLanguageFeatures: noop,
  onDidRequestRichLanguageFeatures: () => ({ dispose: noop }),
};
const languageConfigurationService = {
  onDidChange: () => ({ dispose: noop }),
  getLanguageConfiguration: () => ({}),
};
const inert = () =>
  new Proxy(function () {}, {
    get: (_t, k) => (k === 'then' ? undefined : inert()),
    apply: () => inert(),
    construct: () => inert(),
  });
const instantiationService = { createInstance: () => inert() };

function model(text) {
  return new TextModel(
    text,
    languageSelection,
    TextModel.DEFAULT_CREATION_OPTIONS,
    null,
    undoRedoService,
    languageService,
    languageConfigurationService,
    instantiationService,
  );
}

const corpus = JSON.parse(readFileSync(corpusPath, 'utf8'));
const cases = corpus.map((c) => {
  const m = model(c.text);
  const lineCount = m.getLineCount();

  // Every position a caller could hand in, valid or not: one line below the
  // document and one above it, one column before the start of a line and two
  // past its end. The out-of-range ones are the point — in range, the model and
  // the buffer agree, which is what the existing comparison already shows.
  const probes = [];
  for (let line = 0; line <= lineCount + 1; line++) {
    const max = line >= 1 && line <= lineCount ? m.getLineMaxColumn(line) : 1;
    for (let column = 0; column <= max + 2; column++) {
      const v = m.validatePosition({ lineNumber: line, column });
      probes.push({
        line,
        column,
        valid: [v.lineNumber, v.column],
        offset: m.getOffsetAt({ lineNumber: line, column }),
      });
    }
  }

  // Ranges, including reversed and out of range, because `getValueInRange` is
  // what the workbench calls to show a finding's snippet.
  const corners = [
    [0, 0, 0, 0],
    [1, 1, 1, 1],
    [1, 1, lineCount + 5, 99],
    [lineCount + 5, 99, 1, 1],
    [2, 0, 2, 99],
    [1, 99, 2, 1],
  ];

  // And ranges whose ends land between the halves of an astral character.
  // `validateRange` expands outward over a surrogate pair rather than slicing
  // through it, and that branch is unreachable without a case that needs it.
  for (let line = 1; line <= lineCount; line++) {
    const content = m.getLineContent(line);
    for (let i = 0; i < content.length; i++) {
      const code = content.charCodeAt(i);
      if (code < 0xd800 || code > 0xdbff) continue;
      const inside = i + 2; // one-based column between the two halves
      corners.push([line, inside, line, inside]);
      corners.push([line, 1, line, inside]);
      corners.push([line, inside, line, content.length + 1]);
      corners.push([line, inside, line, inside + 1]);
      break;
    }
  }
  const ranges = corners.map(([sl, sc, el, ec]) => {
    const r = m.validateRange({
      startLineNumber: sl,
      startColumn: sc,
      endLineNumber: el,
      endColumn: ec,
    });
    return {
      asked: [sl, sc, el, ec],
      valid: [r.startLineNumber, r.startColumn, r.endLineNumber, r.endColumn],
      text: m.getValueInRange({
        startLineNumber: sl,
        startColumn: sc,
        endLineNumber: el,
        endColumn: ec,
      }),
    };
  });

  m.dispose();
  return { name: c.name, text: c.text, lineCount, probes, ranges };
});

writeFileSync(
  outPath,
  JSON.stringify({ monaco: `monaco-editor ${version} (TextModel)`, cases }, null, 1) + '\n',
);
const probes = cases.reduce((n, c) => n + c.probes.length, 0);
console.log(`monaco-editor ${version}: ${cases.length} case(s), ${probes} position(s) -> ${outPath}`);
