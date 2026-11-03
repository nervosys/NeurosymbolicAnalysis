// Drive the built sda-workbench over CDP and check the *model's* decorations
// against what the CLI reports for the same fixture.
//
//   node gui/tools/drive-cdp.mjs [exe] [root] [screenshot.png]
//
// Defaults to the release binary and gui/tools/fixtures.
//
// Reads the model rather than the DOM deliberately: the DOM shows Monaco's
// *rendering* of decorations, which is not the same thing, and reasoning from it
// produced two wrong conclusions before window.__sda existed.
//
// The launch, staleness and scan-click guards live in `workbench.mjs`, shared
// with `drive-review.mjs`. Each of them was paid for by a run that reported PASS
// while testing nothing; see the comments there.
import { writeFileSync } from 'node:fs';
import { launch, scan, status, sleep } from './workbench.mjs';

const ROOT = process.argv[3] ?? 'gui/tools/fixtures';
const SHOT = process.argv[4];

// What gui/tools/fixtures/glyph.c must produce, from `sda scan --format json`:
// one low on line 2, three lows on line 3, two mediums on line 4. Line 2 has no
// count class because a count of 1 is the ordinary case and must not be badged.
const EXPECTED_GLYPHS = {
  2: 'sda-info-glyph',
  3: 'sda-info-glyph sda-count-3',
  4: 'sda-warning-glyph sda-count-2',
};
const EXPECTED_SQUIGGLES = 6;

const { evaluate, send, close } = await launch({ exe: process.argv[2] });

const { started, findings } = await scan(evaluate, ROOT);
if (!started) {
  console.log('FAIL: the Scan button never took —', JSON.stringify(await status(evaluate)));
  close();
  process.exit(1);
}

console.log('FINDINGS', findings);
// The app reports a failed scan in its own status line and nothing else does, so
// a run that started and produced nothing says why rather than printing a bare 0.
if (findings === 0) console.log('STATUS', await status(evaluate));

console.log('FILES', await evaluate('JSON.stringify([...new Set(window.__sda.findings.map(f => f.file))])'));

// click the file in the findings list
const opened = await evaluate(`(async () => {
  const el = [...document.querySelectorAll('#findings .finding')]
    .find(e => (e.textContent || '').includes('glyph.c'));
  if (!el) return null;
  el.click();
  await new Promise(r => setTimeout(r, 1500));
  return window.__sda.currentFile;
})()`);
console.log('OPENED', opened);

if (!opened) { console.log('FAIL: the fixture never opened in the editor'); close(); process.exit(1); }

await sleep(1500);
const decos = JSON.parse(await evaluate('JSON.stringify(window.__sda.modelDecorations())'));

// --- check the model against what the CLI says, rather than printing it ---
const failures = [];
const glyphs = {};
for (const d of decos) {
  if (!d.glyph) continue;
  // Monaco leaves a trailing space when the count class is empty.
  glyphs[d.range[0]] = d.glyph.trim().replace(/\s+/g, ' ');
}
for (const [line, want] of Object.entries(EXPECTED_GLYPHS)) {
  if (glyphs[line] !== want) failures.push(`line ${line}: glyph ${JSON.stringify(glyphs[line] ?? null)}, expected ${JSON.stringify(want)}`);
}
for (const line of Object.keys(glyphs)) {
  if (!(line in EXPECTED_GLYPHS)) failures.push(`line ${line}: unexpected glyph ${JSON.stringify(glyphs[line])}`);
}

// A glyph is a summary; the squiggles are the findings themselves. Checking only
// the glyphs would not notice five of six findings going missing.
const squiggles = decos.filter((d) => /^sda-(info|warning|error|critical|suppressed)$/.test(d.className ?? '')).length;
if (squiggles !== EXPECTED_SQUIGGLES) failures.push(`${squiggles} inline squiggles, expected ${EXPECTED_SQUIGGLES}`);

console.log('GLYPHS', JSON.stringify(glyphs), 'SQUIGGLES', squiggles);

if (SHOT) {
  const shot = await send('Page.captureScreenshot', { format: 'png' });
  const data = shot.result?.result?.data ?? shot.result?.data;
  if (data) { writeFileSync(SHOT, Buffer.from(data, 'base64')); console.log('SHOT', SHOT); }
  else console.log('SHOT_FAILED');
}

close();

if (failures.length) {
  console.log('FAIL');
  for (const f of failures) console.log('  ' + f);
  process.exit(1);
}
console.log('PASS: the editor model agrees with the CLI');
process.exit(0);
