// Drive the built sda-workbench over CDP and check three panes that no other
// harness covers: the grouping of the findings list, the terminal, and the
// coverage gutter in the editor.
//
//   node gui/tools/drive-panes.mjs [exe]
//
// Run from the repository root. Shaped like drive-review.mjs: the launch,
// staleness and scan-click guards come from workbench.mjs, and the result is
// PASS (exit 0) or FAIL (exit 1).
//
// # Where each check gets its truth
//
// Grouping: the header counts are compared with counts this file computes from
// `window.__sda.findings` using its own key functions. `groupKey` in main.js is
// never called, so a wrong key there cannot make its own counts agree with
// themselves. The rows are read from the DOM, which is virtualised, so the
// check first confirms that every finding row is actually drawn.
//
// Terminal: the marker is typed as real key events into xterm's helper textarea,
// the same route a keystroke takes to `term.onData`. It must appear in the
// rendered rows at least twice: once as the echoed command and once as its
// output. One occurrence is the echo alone and proves nothing.
//
// Coverage: the scan runs with a probe artifact. The artifact is a batch file
// that writes the JSON Lines records the native probe shim writes
// (`ProbeRecord::Cov`, crates/sda-engine/src/dynamic.rs), so the measurement is
// synthetic. Everything after it is the real path: probe, correlation, the
// `coverage_for` command, and the gutter. Two things are compared. The gutter
// must match what `coverage_for` returns, and `coverage_for` must match what the
// probe measured. The gutter is read from the DOM, because main.js does not
// expose line decorations on `window.__sda` (modelDecorations() omits
// linesDecorationsClassName).
//
// # Why a temp project
//
// The scan root is a copy of gui/tools/fixtures/glyph.c plus a second file, in
// the OS temp directory, for the same reason drive-review gives: a project under
// gui/ inherits the repository's `.sda/` settings, and the counts would then
// depend on them.
import { mkdtempSync, writeFileSync, copyFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { launch, scan, status, sleep } from './workbench.mjs';

const failures = [];
const check = (ok, what) => { if (!ok) failures.push(what); return ok; };

// --- the project and the probe ----------------------------------------------

const ROOT = mkdtempSync(join(tmpdir(), 'sda-panes-'));
const ART = mkdtempSync(join(tmpdir(), 'sda-probe-'));
const cleanup = () => { for (const d of [ROOT, ART]) { try { rmSync(d, { recursive: true, force: true }); } catch {} } };

copyFileSync('gui/tools/fixtures/glyph.c', join(ROOT, 'glyph.c'));
// The same second file drive-review uses, so grouping has more than one file.
writeFileSync(join(ROOT, 'other.c'), `#include <stdlib.h>
int g(int n) {
    int *p = malloc(4);
    if (n > 0) { return 1; }
    free(p);
    return 0;
}
`);

// What the probe "measured" in glyph.c. Lines 2, 3 and 4 are the lines that
// carry findings (see drive-cdp.mjs). `n` is an execution count, so 0 means the
// line was measured and never ran.
const PROBE = [
  { f: 'glyph.c', l: 2, n: 1 },
  { f: 'glyph.c', l: 3, n: 5 },
  { f: 'glyph.c', l: 4, n: 0 },
];
const artifact = join(ART, 'probe.bat');
writeFileSync(artifact, [
  '@echo off',
  ...PROBE.map((r) => `echo {"t":"cov","f":"${r.f}","l":${r.l},"n":${r.n}}>>"%SDA_PROBE_OUT%"`),
  '',
].join('\r\n'));

const { evaluate, send, close } = await launch({ exe: process.argv[2] });
const bail = (msg) => { close(); cleanup(); console.log('FAIL:', msg); process.exit(1); };
const parse = async (expr) => JSON.parse(await evaluate(expr));

// The Scan button reads the artifact field when it runs, so it is set first.
await evaluate(`document.getElementById('artifact').value = ${JSON.stringify(artifact)}`);
const { started, findings: found } = await scan(evaluate, ROOT);
if (!started) bail(`the Scan button never took — ${JSON.stringify(await status(evaluate))}`);
if (!found) bail(`the scan produced no findings — ${JSON.stringify(await status(evaluate))}`);
// `scan` returns as soon as findings exist; the status line says the run is over
// only after the list has been rendered.
for (let i = 0; i < 40 && !(await status(evaluate)).startsWith('scan complete'); i++) await sleep(250);
console.log('FINDINGS', found);

const findings = await parse('JSON.stringify(window.__sda.findings)');

// --- grouping ---------------------------------------------------------------

// Each key is written here from the finding's fields, not read from main.js.
const KEY = {
  file: (f) => f.file,
  rule: (f) => f.rule,
  verdict: (f) => f.verdict ?? 'inconclusive',
};

const setGroupBy = async (value) => {
  await evaluate(`(() => {
    const s = document.getElementById('groupby');
    s.value = ${JSON.stringify(value)};
    s.dispatchEvent(new Event('change', { bubbles: true }));
  })()`);
  await sleep(150);
};

// Rows in the order they are drawn: a header, then the rows it owns.
const rowsInDom = () => parse(`JSON.stringify([...document.querySelectorAll('#findings .group-head, #findings .finding')]
  .map(e => e.classList.contains('group-head') ? { head: e.textContent } : { id: e.dataset.id }))`);

// A header reads `label · count`. The label is escaped in the page, and
// textContent gives the unescaped text back.
const splitHead = (text) => {
  const i = text.lastIndexOf(' · ');
  return { label: text.slice(0, i), count: Number(text.slice(i + 3)) };
};

const options = await parse(`JSON.stringify([...document.getElementById('groupby').options].map(o => o.value))`);
const modes = options.filter((v) => v !== 'none');
check(modes.length > 0, 'the group-by select offers nothing besides `none`');

const byId = new Map(findings.map((f) => [f.id, f]));

for (const mode of modes) {
  const key = KEY[mode];
  if (!key) {
    failures.push(`group by ${mode}: the select offers it, and this harness has no independent key for it`);
    continue;
  }
  await setGroupBy(mode);
  const rows = await rowsInDom();
  const heads = rows.filter((r) => 'head' in r).map((r) => splitHead(r.head));
  const drawn = rows.filter((r) => 'id' in r);

  // Every finding must be in the DOM, or the header counts cannot be checked
  // against all of them and a missing group would go unnoticed.
  if (!check(drawn.length === findings.length,
    `group by ${mode}: ${drawn.length} of ${findings.length} finding rows are drawn, so the headers cannot be checked against all of them`)) {
    continue;
  }

  const want = new Map();
  for (const f of findings) want.set(key(f), (want.get(key(f)) ?? 0) + 1);
  const labels = heads.map((h) => h.label);
  const wantLabels = [...want.keys()].sort((a, b) => a.localeCompare(b));
  console.log(`GROUP ${mode}`, JSON.stringify(heads.map((h) => `${h.label} · ${h.count}`)));

  check(new Set(labels).size === labels.length,
    `group by ${mode}: header labels are not distinct: ${JSON.stringify(labels)}`);
  check(JSON.stringify(labels) === JSON.stringify([...labels].sort((a, b) => a.localeCompare(b))),
    `group by ${mode}: headers are not sorted: ${JSON.stringify(labels)}`);
  check(JSON.stringify(labels) === JSON.stringify(wantLabels),
    `group by ${mode}: headers are ${JSON.stringify(labels)}, but the findings have ${JSON.stringify(wantLabels)}`);
  for (const h of heads) {
    check(h.count === want.get(h.label),
      `group by ${mode}: header \`${h.label}\` says ${h.count}, the findings say ${want.get(h.label)}`);
  }
  const sum = heads.reduce((a, h) => a + h.count, 0);
  check(sum === findings.length, `group by ${mode}: headers sum to ${sum}, not ${findings.length}`);

  // Membership: each row must sit under a header for its own key, and every
  // finding must be drawn exactly once.
  let current = null;
  let misfiled = 0;
  const seen = new Map();
  for (const r of rows) {
    if ('head' in r) { current = splitHead(r.head).label; continue; }
    const f = byId.get(r.id);
    seen.set(r.id, (seen.get(r.id) ?? 0) + 1);
    if (!f || key(f) !== current) misfiled++;
  }
  check(misfiled === 0, `group by ${mode}: ${misfiled} row(s) sit under a header for a different key`);
  check(seen.size === findings.length && [...seen.values()].every((v) => v === 1),
    `group by ${mode}: ${seen.size} distinct findings drawn for ${findings.length}, or some drawn twice`);
}

await setGroupBy('none');
const headsLeft = await evaluate(`document.querySelectorAll('#findings .group-head').length`);
check(headsLeft === 0, `after group by none, ${headsLeft} group header(s) remain`);
check((await rowsInDom()).length === findings.length, 'after group by none, not every finding row is drawn');

// --- the coverage gutter ----------------------------------------------------

// The row click is the same route a person takes to open a file.
const clicked = await evaluate(`(() => {
  const el = [...document.querySelectorAll('#findings .finding')].find(e => (e.textContent || '').includes('glyph.c'));
  if (!el) return false;
  el.click();
  return true;
})()`);
check(clicked, 'no finding row for glyph.c to open');

let current = null;
for (let i = 0; i < 40 && !current; i++) {
  await sleep(250);
  const c = await evaluate('window.__sda.currentFile');
  if (c && c.endsWith('glyph.c')) current = c;
}
check(!!current, 'glyph.c never opened in the editor');
// openFile does not await applyCoverage, so the gutter is given time to land.
await sleep(2000);

// The string the app passes to coverage_for: the finding's own `file` field.
const glyphFile = findings.find((f) => f.file.endsWith('glyph.c')).file;
const served = await parse(`(async () => JSON.stringify(
  await window.__TAURI_INTERNALS__.invoke('coverage_for', { file: ${JSON.stringify(glyphFile)} })
))()`);

const gutter = await parse(`JSON.stringify([...document.querySelectorAll('#editor .margin-view-overlays > div')]
  .flatMap(row => {
    const line = Number(row.querySelector('.line-numbers')?.textContent);
    return [...row.querySelectorAll('.sda-covered, .sda-uncovered')]
      .map(d => ({ line, state: d.classList.contains('sda-covered') ? 'covered' : 'uncovered' }));
  }))`);

const asSet = (xs) => [...new Set(xs.map((x) => `${x.line}:${x.state}`))].sort();
const fromServed = served.map((c) => ({ line: c.line, state: c.hits > 0 ? 'covered' : 'uncovered' }));
const fromProbe = PROBE.map((r) => ({ line: r.l, state: r.n > 0 ? 'covered' : 'uncovered' }));

console.log('COVERAGE_FOR', JSON.stringify(asSet(fromServed)));
console.log('PROBE', JSON.stringify(asSet(fromProbe)));
console.log('GUTTER', JSON.stringify(asSet(gutter)));

check(JSON.stringify(asSet(gutter)) === JSON.stringify(asSet(fromServed)),
  `the gutter shows ${JSON.stringify(asSet(gutter))}, but coverage_for returned ${JSON.stringify(asSet(fromServed))}`);
check(JSON.stringify(asSet(fromServed)) === JSON.stringify(asSet(fromProbe)),
  `coverage_for returned ${JSON.stringify(asSet(fromServed))} for glyph.c, but the probe measured ${JSON.stringify(asSet(fromProbe))} and every one of those lines carries a finding`);

// --- the terminal -----------------------------------------------------------

const marker = `SDA_TERM_${randomBytes(4).toString('hex')}`;
await evaluate(`document.querySelector('#terminal .xterm-helper-textarea').focus()`);
const focused = await evaluate(`document.activeElement?.classList.contains('xterm-helper-textarea') === true`);
check(focused, 'the terminal input did not take focus, so no keystroke would reach the shell');

const press = (ev) => send('Input.dispatchKeyEvent', ev);
for (const ch of `echo ${marker}`) {
  await press({ type: 'keyDown', key: ch, text: ch, unmodifiedText: ch });
  await press({ type: 'keyUp', key: ch });
}
await press({ type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, nativeVirtualKeyCode: 13, text: '\r', unmodifiedText: '\r' });
await press({ type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, nativeVirtualKeyCode: 13 });

const occurrences = () => evaluate(`(document.querySelector('#terminal .xterm-rows')?.textContent ?? '')
  .split(${JSON.stringify(marker)}).length - 1`);
let seen = 0;
for (let i = 0; i < 20 && seen < 2; i++) {
  await sleep(500);
  seen = Number(await occurrences());
}
console.log('TERMINAL', marker, 'occurrences', seen);
check(seen >= 2,
  `the marker ${marker} appears ${seen} time(s) in the terminal within 10 s; expected 2 (the echoed command and its output)`);

close();
cleanup();

if (failures.length) {
  console.log('FAIL');
  for (const f of failures) console.log('  ' + f);
  process.exit(1);
}
console.log('PASS: the findings grouping, the terminal and the coverage gutter agree with their sources');
process.exit(0);
