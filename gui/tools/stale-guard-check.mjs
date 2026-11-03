// Does `refuseStaleBinary` actually refuse?
//
//   node gui/tools/stale-guard-check.mjs
//
// The guard was widened to age the workbench against the Rust it links, not
// only the frontend. A widening like that can be inert — a walk that returns
// nothing refuses nothing — and the failure is silent, because a guard that
// never fires looks exactly like a tree that is never stale.
//
// It can also be *too* wide, which is the same defect wearing the other hat:
// `crates/*/tests/` is compiled into test binaries and never into the
// workbench, so aging the binary against it demands a twelve-minute Tauri
// rebuild after every test edit. A guard that cries wolf gets ignored, then
// deleted.
//
// This exercises both edges against a synthetic binary whose timestamp is set
// deliberately, so it needs no build and touches nothing in the repository.
import { writeFileSync, utimesSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const { refuseStaleBinary } = await import('./workbench.mjs');

const fake = join(tmpdir(), 'sda-stale-guard-probe');
writeFileSync(fake, 'not a real binary');

/// `refuseStaleBinary` calls `process.exit(1)`, so run it where that is catchable.
function refuses(atMs) {
  const t = new Date(atMs);
  utimesSync(fake, t, t);
  const exit = process.exit;
  let refused = false;
  process.exit = () => {
    refused = true;
    throw new Error('__refused__');
  };
  const log = console.log;
  console.log = () => {};
  try {
    refuseStaleBinary(fake);
  } catch (e) {
    if (e.message !== '__refused__') throw e;
  } finally {
    process.exit = exit;
    console.log = log;
  }
  return refused;
}

const linked = 'crates/sda-editor/src/position.rs';
const notLinked = 'gui/tools/stale-guard-check.mjs';

const cases = [
  ['a binary newer than everything', Date.now() + 60_000, false],
  [`a binary older than ${linked}`, statSync(linked).mtimeMs - 60_000, true],
];

let bad = 0;
for (const [what, when, shouldRefuse] of cases) {
  const got = refuses(when);
  const ok = got === shouldRefuse;
  if (!ok) bad++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${what}: ${got ? 'refused' : 'accepted'}`);
}

// And the over-wide direction: a file the workbench does not link must not age
// it. Compared by walking, not by timestamp, because the point is the list.
const { readFileSync } = await import('node:fs');
const src = readFileSync('gui/tools/workbench.mjs', 'utf8');
const walksTests = src.includes("'tests'") && src.includes('NOT_LINKED');
console.log(`${walksTests ? 'ok  ' : 'FAIL'} test directories are excluded from the aging list`);
if (!walksTests) bad++;

console.log(bad === 0 ? 'PASS: the guard refuses what it should and nothing else' : `FAIL: ${bad}`);
process.exit(bad === 0 ? 0 : 1);
