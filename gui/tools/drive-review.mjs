// Drive the built sda-workbench over CDP and check the *review* surface: the
// filter bar, the detail pane, the triage buttons, the assignment and comment
// controls, and the baseline facet.
//
//   node gui/tools/drive-review.mjs [exe]
//
// `drive-cdp.mjs` checks the editor's decorations against what the CLI reports.
// That is the thing that used to drift, and it is one panel of four. Everything
// this file exercises was driven by hand through `window.__sda` in the session
// that built it, which is another way of saying it was untested.
//
// # Why it builds its own project rather than using gui/tools/fixtures
//
// Triage and the baseline are *files*: `.sda/triage.toml` and
// `.sda/baseline.toml`, written under the project root. Pointing this at a
// fixture inside the repository would leave those files behind in the working
// tree, and — worse — a second run would start from the first run's state and
// could pass for the wrong reason. So the project is built in the OS temp
// directory, scanned, and removed.
//
// A temp root is also outside this repository's `.sda/`, which is discovered by
// searching *upward*: a project under `gui/` would inherit the repository's
// deviations and scope declaration, and the counts asserted here would depend on
// them.
//
// # What it asserts, and what it deliberately does not
//
// Relationships, not magic numbers. "Filtering to `low` leaves exactly the
// findings whose severity is low" survives an analyzer improving; `leaves 4`
// does not, and a harness that has to be edited every time the engine gets
// better is a harness people start editing without reading.
//
// The one place it does check a count is the *chip* against the *view*: a facet
// whose badge disagrees with what it filters to is the defect this pane can have
// that nothing else would notice.
//
// # Assignment and discussion
//
// Both are driven through the controls a person uses: a name typed into the
// Assignment field and committed with Enter, the `me` button, a remark typed
// into the discussion box and posted with Comment. Nothing calls `invoke`.
//
// Each is then checked against `.sda/triage.toml` read by this file with its own
// line parser, not through the Rust store that wrote it. The assignee must be on
// the record for the finding and in the row the list draws. The `mine` filter
// must admit exactly the findings the file assigns to the identity the UI acts
// as; that identity is read back from the file after the `me` button is pressed,
// because nothing in the UI sets it (`sda.me` is only read from localStorage). A
// remark must be recorded under that same identity, shown in the detail pane,
// and still shown after a re-scan, which rebuilds every finding from the file.
//
// Clearing the Assignment field (empty, committed with Enter) unassigns, and the
// `agent` button assigns `agent:triage-bot`. Both are checked against the file,
// the detail pane and the list row, and the cleared state is checked after a
// re-scan too.
import { mkdtempSync, writeFileSync, rmSync, existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { launch, scan, status, sleep } from './workbench.mjs';

const failures = [];
const check = (ok, what) => { if (!ok) failures.push(what); return ok; };

// --- a project of our own ---------------------------------------------------

const ROOT = mkdtempSync(join(tmpdir(), 'sda-review-'));
// The same fixture drive-cdp.mjs uses: two severities on four lines, which is
// enough for the severity facet to have something to separate.
writeFileSync(join(ROOT, 'glyph.c'), `#include <string.h>
void f(char *d, char *s, int n) {
    if (n = strlen(s)) { goto done; } else { n = n++; }
    char b[4]; strcpy(b, s); sprintf(b, "%s", s); system(s);
done:
    return;
}
`);
// A second file, so grouping and the file column have more than one answer and
// the text filter has something to exclude.
writeFileSync(join(ROOT, 'other.c'), `#include <stdlib.h>
int g(int n) {
    int *p = malloc(4);
    if (n > 0) { return 1; }
    free(p);
    return 0;
}
`);

const cleanup = () => { try { rmSync(ROOT, { recursive: true, force: true }); } catch {} };
const fail = (msg) => { console.log('FAIL:', msg); cleanup(); process.exit(1); };

console.log('ROOT', ROOT);

const { evaluate, send, close } = await launch({ exe: process.argv[2] });
const bail = (msg) => { close(); fail(msg); };

const { started, findings } = await scan(evaluate, ROOT);
if (!started) bail(`the Scan button never took — ${JSON.stringify(await status(evaluate))}`);
if (!findings) bail(`the scan produced no findings — ${JSON.stringify(await status(evaluate))}`);
console.log('FINDINGS', findings);

const json = async (expr) => JSON.parse(await evaluate(`JSON.stringify(${expr})`));
const viewIds = () => json('window.__sda.view.map(f => f.id)');
const shown = () => evaluate('document.getElementById("shown").textContent');

const all = await json('window.__sda.findings');
if (new Set(all.map((f) => f.file)).size < 2) {
  bail('the fixture project produced findings in only one file; the filter assertions need two');
}

// --- the filter bar ---------------------------------------------------------

// A chip's badge and the list it produces are computed separately — `countBy`
// over every finding, and `passes` over each one. They can disagree, and the
// disagreement is invisible unless something compares them.
// Match on *any* span, not the first: a severity chip leads with an empty
// `<span class="dot">`, so `querySelector('span')` finds the swatch and every
// severity assertion silently tests nothing.
const chip = (group, key) => `[...document.querySelectorAll('#chips-${group} .chip')]` +
  `.find(b => [...b.querySelectorAll('span')].some(s => s.textContent === ${JSON.stringify(key)}))`;

const chipCount = async (group, key) =>
  Number(await evaluate(`(${chip(group, key)})?.querySelector('.n')?.textContent ?? 'NaN'`));

const clickChip = async (group, key) => {
  const hit = await evaluate(`(() => { const b = ${chip(group, key)}; if (!b) return false; b.click(); return true; })()`);
  await sleep(150);
  return hit;
};

for (const sev of [...new Set(all.map((f) => f.severity))]) {
  const want = all.filter((f) => f.severity === sev).map((f) => f.id).sort();
  const badge = await chipCount('sev', sev);
  check(badge === want.length, `severity chip \`${sev}\` badges ${badge}, but ${want.length} findings have it`);

  if (!(await clickChip('sev', sev))) { failures.push(`no severity chip for \`${sev}\``); continue; }
  const got = (await viewIds()).sort();
  check(
    JSON.stringify(got) === JSON.stringify(want),
    `filtering to \`${sev}\` shows ${got.length} findings, expected the ${want.length} of that severity`,
  );
  check(
    (await shown()).includes(`${want.length} of ${all.length}`) || want.length === all.length,
    `the "shown" label reads ${JSON.stringify(await shown())} with ${want.length} of ${all.length} visible`,
  );
  await clickChip('sev', sev); // off again, so the next facet starts clean
}

// A chip nothing matched must not be offered at all: an empty filter that
// silently yields nothing teaches people the filter is broken.
const absent = ['critical', 'high', 'medium', 'low', 'info'].find((s) => !all.some((f) => f.severity === s));
if (absent) {
  const there = await evaluate(`!!(${chip('sev', absent)})`);
  check(!there, `a chip is offered for \`${absent}\`, which no finding has`);
}

// Text filter, driven through the surface the keyboard uses. The needle is a
// file name rather than a rule id, because the answer is then something this
// harness can compute independently of how the app builds its haystack.
const needle = 'other.c';
const wantFile = all.filter((f) => f.file.includes(needle)).map((f) => f.id).sort();
await evaluate(`window.__sda.search(${JSON.stringify(needle)})`);
await sleep(150);
const searched = (await viewIds()).sort();
check(wantFile.length > 0 && wantFile.length < all.length, `the fixture gives ${wantFile.length} of ${all.length} findings in ${needle}; the search assertion needs it to narrow`);
check(
  JSON.stringify(searched) === JSON.stringify(wantFile),
  `searching for \`${needle}\` shows ${searched.length} findings, expected the ${wantFile.length} in that file`,
);

// Reset must undo every facet at once, including the ones set above.
await evaluate('document.getElementById("clear").click()');
await sleep(150);
check((await viewIds()).length === all.length, 'Reset did not restore the full list');
check(
  (await evaluate('document.getElementById("q").value')) === '',
  'Reset left text in the filter box',
);

// --- the detail pane --------------------------------------------------------

// From the *view*, not from `findings`: `next` walks the visible queue, and the
// two arrays are not guaranteed to be in the same order.
const queue = await json('window.__sda.view');
if (queue.length < 2) bail('the fixture project gives fewer than two visible findings; `next` cannot be checked');
const subject = queue[0];
await evaluate(`window.__sda.select(${JSON.stringify(subject.id)})`);
await sleep(400);
const selected = await json('window.__sda.selected');
check(selected?.id === subject.id, 'selecting a finding did not make it the selected one');

const detail = await evaluate('document.getElementById("detail").textContent');
check(detail.includes(subject.rule), `the detail pane does not name the rule \`${subject.rule}\``);
check(detail.includes(String(subject.line)), 'the detail pane does not name the line');
check(detail.includes(subject.severity), 'the detail pane does not state the severity');
// The pane exists to answer "why does it say that"; the classification block is
// the part a reviewer acts on.
check(detail.includes('Review'), 'the detail pane has no Review section');
check(detail.includes('Assignment'), 'the detail pane has no Assignment section');

// `next` is the queue a reviewer actually uses.
await evaluate('window.__sda.next()');
await sleep(400);
const after = await json('window.__sda.selected');
check(after?.id === queue[1].id, `\`next\` selected ${after?.id}, expected the next finding in the visible queue`);
await evaluate(`window.__sda.select(${JSON.stringify(subject.id)})`);
await sleep(400);

// --- triage -----------------------------------------------------------------

// Clicked, not invoked: the button is the thing under test.
const clicked = await evaluate(`(() => {
  const b = document.querySelector('#detail [data-triage="accepted"]');
  if (!b) return false;
  b.click();
  return true;
})()`);
if (!clicked) failures.push('the detail pane has no `accepted` triage button');

if (clicked) {
  // The write is asynchronous through the Tauri command; wait for the state to
  // land rather than assuming a fixed delay is enough.
  let recorded = null;
  for (let i = 0; i < 20 && recorded !== 'accepted'; i++) {
    await sleep(200);
    recorded = (await json('window.__sda.selected'))?.triage ?? null;
  }
  check(recorded === 'accepted', `the finding's triage state is ${JSON.stringify(recorded)}, expected "accepted"`);

  // The facet must have grown a chip for it, and that chip must filter to it.
  const badge = await chipCount('triage', 'accepted');
  check(badge === 1, `the \`accepted\` triage chip badges ${badge}, expected 1`);
  if (await clickChip('triage', 'accepted')) {
    const got = await viewIds();
    check(
      got.length === 1 && got[0] === subject.id,
      `filtering to \`accepted\` shows ${got.length} findings, expected only the one just recorded`,
    );
    await clickChip('triage', 'accepted');
  } else {
    failures.push('no `accepted` chip appeared in the review-state facet');
  }

  // And it must be on disk, in the file an agent reads over MCP. A UI that
  // records a conclusion in its own memory and calls it review is the whole
  // failure this pane exists not to have.
  const file = join(ROOT, '.sda', 'triage.toml');
  if (!existsSync(file)) {
    failures.push('.sda/triage.toml was not written');
  } else {
    const text = readFileSync(file, 'utf8');
    check(text.includes(subject.id), '.sda/triage.toml does not name the finding');
    check(text.includes('accepted'), '.sda/triage.toml does not record the state');
    check(text.includes(subject.rule), '.sda/triage.toml does not carry the rule, so it does not read without the tool');
  }
}

// --- assignment and discussion ----------------------------------------------

// `.sda/triage.toml` as the workbench writes it: `[[record]]` tables with
// `[[record.comments]]` under them, and `key = "string"` lines. This is a parser
// for that subset, kept here rather than borrowed from the Rust store, so the
// file is read by something that did not write it.
const readTriage = () => {
  const file = join(ROOT, '.sda', 'triage.toml');
  if (!existsSync(file)) return [];
  const records = [];
  let cur = null;
  let comment = null;
  for (const raw of readFileSync(file, 'utf8').split(/\r?\n/)) {
    const line = raw.trim();
    if (line === '[[record]]') { cur = { comments: [] }; comment = null; records.push(cur); continue; }
    if (line === '[[record.comments]]') {
      if (!cur) continue;
      comment = {};
      cur.comments.push(comment);
      continue;
    }
    if (line.startsWith('[')) { cur = null; comment = null; continue; }
    const m = /^([a-z_]+) = (".*")$/.exec(line);
    if (m && cur) (comment ?? cur)[m[1]] = JSON.parse(m[2]);
  }
  return records;
};

// The write is asynchronous through the Tauri command, so the file is polled.
const waitFor = async (pred, tries = 20) => {
  let v;
  for (let i = 0; i < tries; i++) {
    v = pred();
    if (v) return v;
    await sleep(200);
  }
  return v;
};

const press = (ev) => send('Input.dispatchKeyEvent', ev);
const enter = async () => {
  await press({ type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, nativeVirtualKeyCode: 13, text: '\r', unmodifiedText: '\r' });
  await press({ type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, nativeVirtualKeyCode: 13 });
};

// Focus a field and type into it as real input, so the page sees `input` events
// exactly as it would from a keyboard.
const typeInto = async (selector, text) => {
  const focused = await evaluate(`(() => {
    const el = document.querySelector(${JSON.stringify(selector)});
    if (!el) return false;
    el.focus();
    el.select();
    return document.activeElement === el;
  })()`);
  if (!focused) return false;
  await send('Input.insertText', { text });
  await sleep(150);
  return true;
};

const clickIn = (selector) => evaluate(`(() => {
  const b = document.querySelector(${JSON.stringify(selector)});
  if (!b) return false;
  b.click();
  return true;
})()`);

// Assignment to a name nobody else uses, so a row showing it can only be this
// check's doing.
const assignee = `reviewer-${randomBytes(3).toString('hex')}`;
await evaluate(`window.__sda.select(${JSON.stringify(subject.id)})`);
await sleep(400);
check(await typeInto('#detail #assignee', assignee), 'the Assignment field did not take focus');
await enter();

const onDisk = await waitFor(() => readTriage().find((r) => r.id === subject.id && r.assignee === assignee));
const recordsFor = readTriage().filter((r) => r.id === subject.id);
check(recordsFor.length === 1, `.sda/triage.toml has ${recordsFor.length} records for the finding, expected one`);
check(!!onDisk, `.sda/triage.toml does not record assignee ${JSON.stringify(assignee)} for the finding`);
check(
  (await evaluate('document.querySelector("#detail #assignee")?.value')) === assignee,
  'the detail pane does not show the assignee after it was committed',
);
check(
  (await evaluate(`document.querySelector('#findings [data-id="${subject.id}"]')?.textContent ?? ''`)).includes(`@${assignee}`),
  `the list row for the finding does not show \`@${assignee}\``,
);

// The identity the UI acts as. Pressing `me` assigns to it, and the file says
// what it wrote, so the name is read rather than assumed.
const other = queue[1];
await evaluate(`window.__sda.select(${JSON.stringify(other.id)})`);
await sleep(400);
check(await clickIn('#detail #assign-me'), 'the detail pane has no `me` assignment button');
const meRecord = await waitFor(() => readTriage().find((r) => r.id === other.id && r.assignee));
const identity = meRecord?.assignee ?? null;
check(!!identity, `pressing \`me\` did not record an assignee for the second finding`);

// The `mine` filter, computed from the file: the findings assigned to the
// identity, restricted to those this scan actually produced.
const scanIds = new Set(all.map((f) => f.id));
const wantMine = readTriage()
  .filter((r) => r.assignee === identity && scanIds.has(r.id))
  .map((r) => r.id)
  .sort();
check(wantMine.length > 0, 'the file assigns nothing to the identity the UI acts as; the `mine` assertion needs something to admit');
check(!wantMine.includes(subject.id), 'the finding assigned to another name is in the expected `mine` set');
const mineBadge = await chipCount('mine', 'mine');
check(mineBadge === wantMine.length, `the \`mine\` chip badges ${mineBadge}, but the file assigns ${wantMine.length} findings to ${JSON.stringify(identity)}`);
if (await clickChip('mine', 'mine')) {
  const got = (await viewIds()).sort();
  check(
    JSON.stringify(got) === JSON.stringify(wantMine),
    `the \`mine\` filter shows ${got.length} findings, expected the ${wantMine.length} the file assigns to ${JSON.stringify(identity)}`,
  );
  await clickChip('mine', 'mine');
  check((await viewIds()).length === all.length, 'turning `mine` off did not restore the full list');
} else {
  failures.push('no `mine` chip appeared after assignments were recorded');
}

// The `agent` button. It assigns the fixed name `agent:triage-bot` through the
// same command as `me`, and that is all it does: nothing is launched and no
// network call is made, so it is driven here. It is pressed on `other`, whose
// assignment to the UI's identity was checked just above, and it is the last
// step that touches `other`.
await evaluate(`window.__sda.select(${JSON.stringify(other.id)})`);
await sleep(400);
check(await clickIn('#detail #assign-agent'), 'the detail pane has no `agent` assignment button');
const agentRecord = await waitFor(() => readTriage().find((r) => r.id === other.id && r.assignee === 'agent:triage-bot'));
check(!!agentRecord, `pressing \`agent\` did not record \`agent:triage-bot\` for the second finding in .sda/triage.toml`);
check(
  (await evaluate('document.querySelector("#detail #assignee")?.value')) === 'agent:triage-bot',
  'the detail pane does not show `agent:triage-bot` after `agent` was pressed',
);
check(
  (await evaluate(`document.querySelector('#findings [data-id="${other.id}"] .owner')?.textContent ?? ''`)) === '@triage-bot',
  'the list row does not show `@triage-bot` after `agent` was pressed',
);

// A remark, typed and posted. Unique text, so finding it in the file or the pane
// cannot be a leftover from anywhere else.
const remark = `SDA_REMARK_${randomBytes(6).toString('hex')}`;
await evaluate(`window.__sda.select(${JSON.stringify(subject.id)})`);
await sleep(400);
check(await typeInto('#detail #comment-text', remark), 'the discussion box did not take focus');
check(await clickIn('#detail #comment-add'), 'the detail pane has no Comment button');

const posted = await waitFor(() => readTriage()
  .filter((r) => r.id === subject.id)
  .flatMap((r) => r.comments)
  .find((c) => c.text === remark));
check(!!posted, `.sda/triage.toml does not carry the remark ${remark}`);
const postedHits = readTriage().filter((r) => r.id === subject.id).flatMap((r) => r.comments).filter((c) => c.text === remark);
check(postedHits.length === 1, `the remark is recorded ${postedHits.length} times, expected once`);
check(
  postedHits[0]?.by === identity,
  `the remark is recorded by ${JSON.stringify(postedHits[0]?.by)}, but the UI acts as ${JSON.stringify(identity)}`,
);
check(
  (await evaluate('document.querySelector("#detail .thread")?.textContent ?? ""')).includes(remark),
  'the detail pane does not show the remark after it was posted',
);

// Survival. A re-scan rebuilds every finding from the file, so a remark that
// lived only in page memory would be gone from the findings it returns.
// `scan` waits for a new findings array, so it returns only once this one ran.
const rescan = await scan(evaluate, ROOT);
check(rescan.started && rescan.findings > 0, 'the re-scan did not complete');
const after2 = await json(`window.__sda.findings.find(f => f.id === ${JSON.stringify(subject.id)}) ?? null`);
check(
  !!after2?.comments?.some((c) => c.text === remark && c.by === identity),
  `after a re-scan the finding no longer carries the remark, or carries it under another author`,
);
check(after2?.assignee === assignee, `after a re-scan the finding's assignee is ${JSON.stringify(after2?.assignee)}, expected ${JSON.stringify(assignee)}`);
await evaluate(`window.__sda.select(${JSON.stringify(subject.id)})`);
await sleep(400);
check(
  (await evaluate('document.querySelector("#detail .thread")?.textContent ?? ""')).includes(remark),
  'after a re-scan the detail pane does not show the remark',
);

// Unassigning. The UI's only control for it is the Assignment field itself: an
// empty value committed with Enter sends `assign_finding` with no `to`, which the
// store records as no assignee. Cleared from the keyboard, as a person would.
// Done after the re-scan above, because `subject` has to keep its assignee for
// those checks.
const cleared = await evaluate(`(() => {
  const el = document.querySelector('#detail #assignee');
  if (!el) return false;
  el.focus();
  el.select();
  return document.activeElement === el;
})()`);
check(cleared, 'the Assignment field did not take focus to clear it');
await press({ type: 'keyDown', key: 'Backspace', code: 'Backspace', windowsVirtualKeyCode: 8, nativeVirtualKeyCode: 8 });
await press({ type: 'keyUp', key: 'Backspace', code: 'Backspace', windowsVirtualKeyCode: 8, nativeVirtualKeyCode: 8 });
await sleep(150);
check(
  (await evaluate('document.querySelector("#detail #assignee")?.value')) === '',
  'Backspace did not empty the Assignment field',
);
await enter();

await waitFor(() => {
  const r = readTriage().find((x) => x.id === subject.id);
  return !r || !r.assignee;
});
check(
  !readTriage().some((r) => r.id === subject.id && r.assignee),
  `.sda/triage.toml still records an assignee for the finding after it was cleared`,
);
check(
  readTriage().filter((r) => r.id === subject.id).flatMap((r) => r.comments).some((c) => c.text === remark),
  'clearing the assignee lost the remark recorded on the same finding',
);
check(
  (await evaluate('document.querySelector("#detail #assignee")?.value')) === '',
  'the detail pane still shows an assignee after it was cleared',
);
check(
  !(await evaluate(`!!document.querySelector('#findings [data-id="${subject.id}"] .owner')`)),
  'the list row for the finding still shows an owner after it was cleared',
);

// Survival of the cleared state: the re-scan rebuilds the finding from the file.
const rescan2 = await scan(evaluate, ROOT);
check(rescan2.started && rescan2.findings > 0, 'the re-scan after clearing did not complete');
const after3 = await json(`window.__sda.findings.find(f => f.id === ${JSON.stringify(subject.id)}) ?? null`);
check(!!after3, 'after the re-scan following the clear, the finding is gone from the list');
check(!after3?.assignee, `after a re-scan the finding's assignee is ${JSON.stringify(after3?.assignee)}, expected none`);
await evaluate(`window.__sda.select(${JSON.stringify(subject.id)})`);
await sleep(400);
check(
  (await evaluate('document.querySelector("#detail #assignee")?.value')) === '',
  'after a re-scan the detail pane shows an assignee for a finding that was cleared',
);
check(
  !(await evaluate(`!!document.querySelector('#findings [data-id="${subject.id}"] .owner')`)),
  'after a re-scan the list row shows an owner for a finding that was cleared',
);

// --- the baseline facet -----------------------------------------------------

// Before a baseline exists, "new" is unknown rather than false, and the button
// says so instead of filtering to an empty list.
check(
  await evaluate(`!!(${chip('new', 'new')})?.disabled`),
  'the `new` facet is offered before any baseline exists; nothing can be new yet',
);
check(
  (await evaluate('document.getElementById("baseline-info").textContent')).includes('no baseline'),
  'the baseline label does not say there is no baseline',
);

await evaluate('document.getElementById("set-baseline").click()');

// Setting a baseline re-scans, so wait for the label rather than for the click.
let label = '';
for (let i = 0; i < 40; i++) {
  await sleep(300);
  label = await evaluate('document.getElementById("baseline-info").textContent');
  if (label && !label.includes('no baseline')) break;
}
console.log('BASELINE', JSON.stringify(label));
check(label.includes(`${all.length} recorded`), `the baseline label reads ${JSON.stringify(label)}, expected ${all.length} recorded`);

const baselineFile = join(ROOT, '.sda', 'baseline.toml');
if (!existsSync(baselineFile)) {
  failures.push('.sda/baseline.toml was not written');
} else {
  const text = readFileSync(baselineFile, 'utf8');
  const ids = all.filter((f) => text.includes(f.id)).length;
  check(ids === all.length, `.sda/baseline.toml records ${ids} of ${all.length} finding ids`);
}

// Every finding is now in the baseline, so the honest answer is that nothing is
// new — and the facet must be live rather than disabled, because the question is
// now answerable.
let newBadge = NaN;
for (let i = 0; i < 20; i++) {
  await sleep(200);
  newBadge = await chipCount('new', 'new');
  if (!Number.isNaN(newBadge)) break;
}
check(newBadge === 0, `the \`new\` chip badges ${newBadge} immediately after a baseline, expected 0`);
check(
  !(await evaluate(`!!(${chip('new', 'new')})?.disabled`)),
  'the `new` facet is still disabled after a baseline was recorded',
);

await evaluate('window.__sda.setOnlyNew(true)');
await sleep(200);
check((await viewIds()).length === 0, 'filtering to new findings after a baseline of everything is not empty');
await evaluate('window.__sda.setOnlyNew(false)');

close();
cleanup();

if (failures.length) {
  console.log('FAIL');
  for (const f of failures) console.log('  ' + f);
  process.exit(1);
}
console.log('PASS: the filter bar, detail pane, triage, assignment, discussion and baseline facet agree with the state they write');
process.exit(0);
