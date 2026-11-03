// Launching and driving the built sda-workbench over CDP.
//
// Extracted from `drive-cdp.mjs` when a second harness was added, rather than
// copied into it. Every guard below was paid for by a run that reported PASS
// while testing nothing — the stale binary, the `about:blank` target, the dev
// profile's localhost URL, the late `window.__sda`, the Scan click that lands
// before the app is listening. A second copy of that logic is a second copy that
// drifts, and this codebase has already written a test (`mcp_paths_agree.rs`)
// about exactly that failure on the MCP surface.
//
// Dependency-free: Node 24 has fetch and WebSocket built in.
import { spawn, execSync } from 'node:child_process';
import { readdirSync, statSync, existsSync } from 'node:fs';

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/// Where the binary actually is.
///
/// This defaulted to `gui/src-tauri/target/release/`, which on a machine with a
/// shared `CARGO_TARGET_DIR` is not where cargo writes — so the harness happily
/// drove a **five-week-old build** and reported PASS, including on runs taken as
/// evidence that a change to the engine had not altered the UI. A test that
/// silently runs the wrong artifact is worse than no test, because it produces
/// confidence rather than doubt.
export function resolveExe(explicit) {
  if (explicit) return explicit;
  if (process.env.SDA_WORKBENCH) return process.env.SDA_WORKBENCH;
  const candidates = ['gui/src-tauri/target/release/sda-workbench.exe'];
  try {
    // `cargo metadata` knows the real target directory, whatever config set it.
    const meta = JSON.parse(execSync('cargo metadata --format-version 1 --no-deps', {
      cwd: 'gui/src-tauri', encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
    }));
    if (meta.target_directory) {
      candidates.unshift(`${meta.target_directory}/release/sda-workbench.exe`.split('\\').join('/'));
    }
  } catch {}
  const found = candidates.filter(existsSync);
  if (!found.length) {
    console.log('FAIL: no sda-workbench binary found. Looked in:', candidates.join(', '));
    process.exit(1);
  }
  // Newest wins, so a stale copy in a directory cargo no longer writes to cannot
  // shadow the real one.
  found.sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs);
  return found[0];
}

/// Directories that hold Rust the workbench never links.
///
/// A guard that fires on changes which cannot affect the binary is not a
/// stricter guard, it is a broken one: `crates/sda-cli/tests/` is compiled into
/// test binaries and nothing else, and a harness that demands a twelve-minute
/// Tauri rebuild after every test edit gets ignored, then deleted. That is the
/// mirror of the failure this function was widened to fix.
const NOT_LINKED = new Set(['target', 'node_modules', 'tests', 'benches', 'examples', 'fixtures']);

/// Every `.rs` the workbench actually links, under a directory.
function rustSourcesUnder(dir) {
  const out = [];
  const stack = [dir];
  while (stack.length) {
    const d = stack.pop();
    let entries;
    try {
      entries = readdirSync(d, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const p = `${d}/${e.name}`;
      if (e.isDirectory()) {
        if (!NOT_LINKED.has(e.name) && !e.name.startsWith('.')) stack.push(p);
      } else if (e.name.endsWith('.rs') || e.name === 'Cargo.toml') {
        out.push(p);
      }
    }
  }
  return out;
}

/// A binary older than anything it embeds is serving something other than what
/// is on disk. Worth failing on rather than warning: it is the exact condition
/// `resolveExe` exists for.
///
/// This used to check the *frontend* only — `main.js`, the stylesheet, the HTML
/// — and its own doc comment said so, as though that were all the binary
/// contained. The workbench also links `sda-core`, `sda-engine`, `sda-editor`,
/// `sda-rules`, `sda-ai` and `sda-adapters`, and a change to any of them changes
/// what the harness is testing. In the session this was written, `sda-editor`'s
/// position validation changed while the guard went on passing a binary built
/// before it: the guard that exists because this harness once drove a
/// five-week-old build was watching the half that had not moved.
export function refuseStaleBinary(exe) {
  const binary = statSync(exe).mtimeMs;
  const frontend = ['gui/src/main.js', 'gui/src/style.css', 'gui/index.html', 'gui/dist/index.html'];
  const backend = [
    ...rustSourcesUnder('gui/src-tauri/src'),
    'gui/src-tauri/Cargo.toml',
    ...rustSourcesUnder('crates'),
  ];

  for (const src of [...frontend, ...backend]) {
    if (existsSync(src) && statSync(src).mtimeMs > binary) {
      console.log(`FAIL: ${exe} is older than ${src}. Run \`npx tauri build --no-bundle\` in gui/;`);
      console.log('      testing a stale binary is how this harness once passed against a five-week-old build.');
      process.exit(1);
    }
  }
}

/// Start the workbench and attach to its webview.
///
/// Returns `{ evaluate, send, close }`. `close` is idempotent so a failing
/// harness can call it on the way out without worrying whether it already did.
export async function launch({ exe, port = 9222 } = {}) {
  const EXE = resolveExe(exe);
  refuseStaleBinary(EXE);
  console.log('EXE', EXE, new Date(statSync(EXE).mtimeMs).toISOString());

  const child = spawn(EXE, [], {
    env: { ...process.env, WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${port}` },
    stdio: 'ignore',
    detached: false,
  });

  let target = null;
  for (let i = 0; i < 60 && !target; i++) {
    await sleep(500);
    try {
      const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      // `about:blank` appears first while the webview is still starting; taking
      // it means driving an empty page and calling that a pass.
      target = list.find((t) => t.type === 'page' && t.webSocketDebuggerUrl && t.url.includes('tauri.localhost'));
    } catch {}
  }
  if (!target) { console.log('FAIL: no tauri.localhost page target'); child.kill(); process.exit(1); }
  console.log('TARGET_URL', target.url);
  // A dev-profile build serves from localhost:5173 and would be testing nothing.
  if (!target.url.startsWith('http://tauri.localhost')) {
    console.log('FAIL: not the bundled asset server —', target.url);
    child.kill();
    process.exit(1);
  }

  const ws = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });

  let id = 0;
  const pending = new Map();
  ws.onclose = (e) => console.log('WS_CLOSED', e.code, e.reason);
  child.on('exit', (c, s) => console.log('CHILD_EXIT', c, s));
  ws.onmessage = (e) => {
    const m = JSON.parse(e.data);
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
  };
  const send = (method, params = {}) =>
    new Promise((res) => { const n = ++id; pending.set(n, res); ws.send(JSON.stringify({ id: n, method, params })); });

  async function evaluate(expression) {
    const r = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true });
    if (r.result?.exceptionDetails) throw new Error(JSON.stringify(r.result.exceptionDetails));
    return r.result?.result?.value;
  }

  let closed = false;
  const close = () => { if (closed) return; closed = true; try { ws.close(); } catch {} child.kill(); };

  // The automation surface is installed when main.js finishes executing, which is
  // well after the DOM exists. Driving before it is there means driving a
  // half-loaded app.
  let ready = false;
  for (let i = 0; i < 60 && !ready; i++) {
    ready = await evaluate('!!(window.__sda && document.getElementById("scan"))');
    if (!ready) await sleep(500);
  }
  if (!ready) { console.log('FAIL: window.__sda never appeared'); close(); process.exit(1); }

  return { evaluate, send, close, exe: EXE };
}

export const status = (evaluate) => evaluate('document.getElementById("status").textContent');

/// Set the project root and click Scan, confirming the click actually took.
///
/// `window.__sda` and the Scan button both exist before the app is necessarily
/// listening to them. On the first run after a fresh build the click lands on
/// nothing: the status line still reads its idle text, and a harness then fails
/// two steps later on the file it never listed — which reads as a decoration
/// defect and is not one. It was misread twice, once as a slow scan and once as
/// a stale build.
///
/// So the click is confirmed by a *positive* signal, not by the status merely
/// changing. The app writes `scanning...`, then `scan complete: N` or
/// `scan failed: ...` — all of which start with "scan", while the idle text
/// ("ready — set a project root and scan") does not. An earlier version compared
/// against a snapshot taken at readiness and was fooled by the app settling into
/// that idle text a moment later, which is its own lesson: "different from
/// before" is not the same claim as "the thing happened".
export async function scan(evaluate, root) {
  const clickScan = () => evaluate(`(() => {
    const r = document.getElementById('root');
    r.value = ${JSON.stringify(root)};
    // The app listens for 'change', not 'input'. Dispatching the wrong one
    // leaves projectRoot at its default and silently scans the repo instead —
    // which looks exactly like a successful run.
    r.dispatchEvent(new Event('change', { bubbles: true }));
    document.getElementById('scan').click();
    return true;
  })()`);

  // A scan replaces the findings array rather than mutating it, so a new array
  // is the one signal that this click's scan finished. The status line is not:
  // after any earlier scan it already reads "scan complete", which made a
  // re-scan look started, and finished, before it had begun.
  await evaluate('window.__sdaBefore = window.__sda.findings; true');
  const scanStarted = async () =>
    (await status(evaluate)).startsWith('scanning') ||
    (await evaluate('window.__sda.findings !== window.__sdaBefore'));

  let started = false;
  for (let attempt = 0; attempt < 10 && !started; attempt++) {
    await clickScan();
    for (let i = 0; i < 10 && !started; i++) {
      await sleep(300);
      started = await scanStarted();
    }
    if (!started) {
      console.log(`RETRY scan click (${attempt + 1}): status is ${JSON.stringify(await status(evaluate))}`);
    }
  }
  if (!started) return { started: false, findings: 0 };

  let n = 0;
  for (let i = 0; i < 120; i++) {
    n = await evaluate('window.__sda.findings !== window.__sdaBefore ? window.__sda.findings.length : 0');
    if (n > 0) break;
    await sleep(500);
  }
  return { started: true, findings: n };
}
