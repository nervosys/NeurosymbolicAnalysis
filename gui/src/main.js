// The StatodynamicAnalysis workbench frontend.
//
// Deliberately thin. Every decision — which CSS class a finding gets, what a
// verdict means, what was not checked, what evidence says — is made in Rust and
// arrives here already resolved. This file arranges pixels, filters a view, and
// forwards events; it does not know what MISRA is.
//
// Two things it does own, because they are presentation and nothing else:
// *which subset of findings is currently on screen*, and *where the keyboard is*.
// Neither is ever written back into a report. A filter is a way of looking at a
// result, not a way of changing one.

import * as monaco from 'monaco-editor';
import EditorWorker from 'monaco-editor/esm/vs/editor/editor.worker?worker';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { invoke } from '@tauri-apps/api/core';
import '@xterm/xterm/css/xterm.css';

// Monaco moves diffing and word scanning off the UI thread into a worker; without
// this it warns and runs them on the main thread. The worker is bundled as its
// own file under 'self', which the CSP's worker-src admits. The four languages
// the workbench opens are tokenized by Monarch, so no language worker is needed.
self.MonacoEnvironment = { getWorker: () => new EditorWorker() };

// --- state ------------------------------------------------------------------

let editor = null;
let currentFile = null;
let projectRoot = '.';
let decorationIds = [];
let stepDecorations = [];
let findings = []; // everything the last scan produced
let view = []; // what the filters currently admit, in display order
let selectedId = null;
// Who this workbench is acting as. Not authentication — there is no server to
// authenticate against, and this file is reviewed in a pull request where the
// commit already says who wrote it. It is attribution, so a thread reads.
let me = localStorage.getItem('sda.me') || 'me';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
const VERDICTS = ['confirmed', 'refuted', 'unreached', 'unpredicted', 'inconclusive'];
const TRIAGE = ['open', 'acknowledged', 'accepted', 'false-positive'];

// Empty set means "no constraint", which is not the same as "all selected" — it
// keeps a newly-appearing verdict visible instead of silently excluded.
const filters = { q: '', sev: new Set(), verdict: new Set(), triage: new Set(), group: 'none', onlyNew: false, mine: false };

// --- editor -----------------------------------------------------------------

function createEditor() {
  editor = monaco.editor.create(document.getElementById('editor'), {
    value: '// Open a file from the findings list, or run a scan.\n',
    language: 'c',
    theme: 'vs-dark',
    automaticLayout: true,
    minimap: { enabled: true },
    glyphMargin: true,
    renderWhitespace: 'selection',
  });

  // Re-check on idle rather than on every keystroke: the native checker runs in
  // milliseconds, but re-rendering decorations on every character is visible.
  let idle = null;
  editor.onDidChangeModelContent(() => {
    clearTimeout(idle);
    idle = setTimeout(checkCurrentBuffer, 250);
  });
}

async function checkCurrentBuffer() {
  if (!currentFile) return;
  try {
    const live = await invoke('check_buffer', {
      path: currentFile,
      text: editor.getValue(),
    });
    await applyDecorations(live);
  } catch (e) {
    setStatus(`check failed: ${e}`);
  }
}

// A finding's severity decides its glyph; its *verdict* decides its emphasis.
// That distinction is the product: a runtime-confirmed defect must not look like
// a static suspicion.
//
// Everything below here is unchanged from the version that shipped. It was
// rewritten during the UI work and quietly lost three things: the generation
// guard, the minimap colour, and — because `inlineClassName` is not `className`
// — every squiggle. The harness noticed the last of those only once it was
// pointed at a binary that was not five weeks old.
//
// The generation counter exists because two checks can be in flight at once: the
// slower of two overlapping runs wins and the editor shows decorations for text
// the user has already changed, which is the same "editor disagrees with the
// analysis" failure this function exists to fix, arriving by a different route.
let decorationGeneration = 0;

async function applyDecorations(items) {
  const generation = ++decorationGeneration;
  const mine = items.filter((f) => f.file.endsWith(baseName(currentFile)));

  // The inline squiggle is per finding, over that finding's own range. Three
  // findings on one line have three different column ranges, so these do not
  // collide and each stays individually hoverable.
  //
  // The glyph does NOT come from here. Monaco draws one glyph per line, so
  // asking for three in the same margin cell drew one and silently discarded
  // the other two — with no rule about which survived, so a critical could sit
  // invisibly behind an info. The editor was reporting three things as one and
  // disagreeing with the findings list next to it.
  const inline = mine.map((f) => ({
    range: new monaco.Range(
      f.line,
      f.column,
      f.end_line ?? f.line,
      f.end_column ?? 1000,
    ),
    options: {
      isWholeLine: false,
      className: f.css_class,
      hoverMessage: { value: hoverFor(f) },
      minimap: { color: colorFor(f), position: 1 },
    },
  }));

  // One marker per line, collapsed deliberately and countably. Which finding
  // owns a shared line is decided in Rust, so a second shell agrees.
  const markers = await invoke('glyph_markers', { findings: mine });
  if (generation !== decorationGeneration) return; // a newer run has overtaken us
  const byId = new Map(mine.map((f) => [f.id, f]));

  const glyphs = markers.map((m) => ({
    range: new monaco.Range(m.line, 1, m.line, 1),
    options: {
      isWholeLine: false,
      glyphMarginClassName: `${m.css_class}-glyph ${countClass(m.count)}`,
      hoverMessage: { value: hoverForLine(m, byId) },
    },
  }));

  decorationIds = editor.deltaDecorations(decorationIds, [...inline, ...glyphs]);
}

// Monaco takes a class name and nothing else, so the count is carried as one —
// the CSS renders it via `::after`. Capped at 9, because a two-digit badge does
// not fit the margin and "9+" is honest about there being more.
function countClass(n) {
  if (n <= 1) return '';
  return n > 9 ? 'sda-count-many' : `sda-count-${n}`;
}

// A shared line's hover lists every finding on it, worst first. This is the
// half that makes collapsing honest: the glyph says how many, and the hover
// says which — so nothing is only visible in the findings list.
function hoverForLine(m, byId) {
  const found = m.ids.map((id) => byId.get(id)).filter(Boolean);
  if (found.length === 1) return hoverFor(found[0]);

  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  found.sort((a, b) => order[a.severity] - order[b.severity]);

  return [
    `**${found.length} findings on line ${m.line}**`,
    '',
    ...found.map((f) => {
      const verdict = f.verdict ? ` · _${f.verdict}_` : '';
      const suppressed = f.suppressed_by ? ' · _suppressed_' : '';
      return `- **${f.rule}** · ${f.severity}${verdict}${suppressed}  \n  ${f.message}`;
    }),
  ].join('\n');
}

function hoverFor(f) {
  const lines = [`**${f.rule}** · ${f.severity} · confidence ${f.confidence}`];
  if (f.verdict) {
    lines.push(`**Runtime verdict: ${f.verdict}**`);
  }
  lines.push('', f.message);
  if (f.suppressed_by) {
    lines.push('', `_Suppressed: ${f.suppressed_by}_`);
  }
  return lines.join('\n');
}

function colorFor(f) {
  if (f.verdict === 'confirmed') return '#ff4d4d';
  if (f.suppressed_by) return '#666666';
  return { critical: '#ff4d4d', high: '#ff8c42', medium: '#ffd166', low: '#7cc4ff', info: '#8f9aa8' }[
    f.severity
  ];
}

async function applyCoverage(file) {
  const lines = await invoke('coverage_for', { file });
  if (!lines.length) return;
  // Executed lines get a stripe; the absence of one is the signal that matters.
  const covered = lines.map((c) => ({
    range: new monaco.Range(c.line, 1, c.line, 1),
    options: {
      isWholeLine: true,
      linesDecorationsClassName: c.hits > 0 ? 'sda-covered' : 'sda-uncovered',
    },
  }));
  editor.deltaDecorations([], covered);
}

// --- filtering --------------------------------------------------------------
//
// A view, never a mutation. `findings` is what the scan produced and is not
// touched here; the header count always reports that number, so narrowing the
// list can never make a report look cleaner than it is.

function passes(f) {
  // `is_new === null` means no baseline was recorded, so newness is unknown. A
  // "new only" filter must exclude unknown rather than treat it as new — a filter
  // that answers a question nobody asked is worse than one that returns nothing.
  if (filters.onlyNew && f.is_new !== true) return false;
  if (filters.mine && f.assignee !== me) return false;
  if (filters.sev.size && !filters.sev.has(f.severity)) return false;
  if (filters.verdict.size && !filters.verdict.has(f.verdict ?? 'inconclusive')) return false;
  if (filters.triage.size && !filters.triage.has(f.triage ?? 'open')) return false;
  if (filters.q) {
    const q = filters.q.toLowerCase();
    const hay = `${f.rule} ${f.file} ${f.title} ${f.message} ${(f.taxonomy || []).join(' ')}`.toLowerCase();
    if (!hay.includes(q)) return false;
  }
  return true;
}

// Runtime-confirmed first: the ordering is the triage advice.
function rank(f) {
  const sev = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return [f.verdict === 'confirmed' ? 0 : 1, sev[f.severity] ?? 9, f.file, f.line];
}

function cmp(a, b) {
  const x = rank(a);
  const y = rank(b);
  for (let i = 0; i < x.length; i++) {
    if (x[i] < y[i]) return -1;
    if (x[i] > y[i]) return 1;
  }
  return 0;
}

function groupKey(f) {
  switch (filters.group) {
    case 'file': return f.file;
    case 'rule': return f.rule;
    case 'verdict': return f.verdict ?? 'inconclusive';
    default: return null;
  }
}

function recomputeView() {
  view = findings.filter(passes).sort(cmp);
  if (filters.group !== 'none') {
    const groups = new Map();
    for (const f of view) {
      const k = groupKey(f);
      if (!groups.has(k)) groups.set(k, []);
      groups.get(k).push(f);
    }
    view = [];
    for (const [k, items] of [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
      view.push({ __group: k, __count: items.length });
      view.push(...items);
    }
  }
}

function countBy(fn) {
  const m = new Map();
  for (const f of findings) {
    const k = fn(f);
    m.set(k, (m.get(k) ?? 0) + 1);
  }
  return m;
}

function renderChips() {
  const bySev = countBy((f) => f.severity);
  const byVerdict = countBy((f) => f.verdict ?? 'inconclusive');
  const byTriage = countBy((f) => f.triage ?? 'open');

  const build = (host, keys, counts, set, decorate) => {
    host.innerHTML = '';
    for (const k of keys) {
      const n = counts.get(k) ?? 0;
      // A facet nothing matched is not offered. An empty filter that silently
      // yields nothing teaches people the filter is broken.
      if (!n && !set.has(k)) continue;
      const b = document.createElement('button');
      b.className = 'chip';
      b.type = 'button';
      b.setAttribute('aria-pressed', set.has(k) ? 'true' : 'false');
      b.dataset.key = k;
      b.innerHTML = `${decorate(k)}<span>${k}</span><span class="n">${n}</span>`;
      b.onclick = () => {
        set.has(k) ? set.delete(k) : set.add(k);
        render();
      };
      host.appendChild(b);
    }
  };

  build(document.getElementById('chips-verdict'), VERDICTS, byVerdict, filters.verdict, () => '');
  build(
    document.getElementById('chips-sev'),
    SEVERITIES,
    bySev,
    filters.sev,
    (k) => `<span class="dot sev-${k}"></span>`,
  );
  build(document.getElementById('chips-triage'), TRIAGE, byTriage, filters.triage, () => '');

  // The baseline toggle is one button rather than a facet, because it has three
  // states in the data (new / not new / unknown) and only one of them is a thing
  // a reviewer asks for. When no baseline exists it says so and does nothing,
  // instead of silently filtering to an empty list.
  const host = document.getElementById('chips-new');
  const known = findings.filter((f) => f.is_new !== null && f.is_new !== undefined);
  const n = findings.filter((f) => f.is_new === true).length;
  host.innerHTML = '';
  const b = document.createElement('button');
  b.className = 'chip';
  b.type = 'button';
  if (!known.length) {
    b.disabled = true;
    b.title = 'No baseline recorded, so nothing can be new yet. Use “Set baseline”.';
    b.innerHTML = '<span>new</span><span class="n">—</span>';
  } else {
    b.setAttribute('aria-pressed', filters.onlyNew ? 'true' : 'false');
    b.innerHTML = `<span>new</span><span class="n">${n}</span>`;
    b.onclick = () => {
      filters.onlyNew = !filters.onlyNew;
      render();
    };
  }
  host.appendChild(b);

  // Who holds what. One button for "mine", with every assignee and their count in
  // the tooltip, because the question after a handoff is "what came back" and
  // that is a count.
  const owners = new Map();
  for (const f of findings) {
    if (f.assignee) owners.set(f.assignee, (owners.get(f.assignee) ?? 0) + 1);
  }
  const mineHost = document.getElementById('chips-mine');
  mineHost.innerHTML = '';
  if (owners.size) {
    const m = document.createElement('button');
    m.className = 'chip';
    m.type = 'button';
    m.setAttribute('aria-pressed', filters.mine ? 'true' : 'false');
    m.title = [...owners.entries()].map(([k, v]) => k + ': ' + v).join('\n');
    m.innerHTML = `<span>mine</span><span class="n">${owners.get(me) ?? 0}</span>`;
    m.onclick = () => {
      filters.mine = !filters.mine;
      render();
    };
    mineHost.appendChild(m);
  }
}

// --- findings list ----------------------------------------------------------
//
// Rendered in a window rather than all at once. A real scan produces tens of
// thousands of findings — PX4 produced 14,284 — and building that many nodes
// freezes the window for seconds and then scrolls badly forever after.

const ROW_H = 58;
const GROUP_H = 24;
let listTop = 0;

function rowHeight(item) {
  return item.__group ? GROUP_H : ROW_H;
}

function renderList() {
  const list = document.getElementById('findings');
  const total = view.reduce((a, i) => a + rowHeight(i), 0);

  if (!view.length) {
    list.innerHTML = `<div class="empty">${
      findings.length ? 'No finding matches these filters.' : 'Run a scan to begin.'
    }</div>`;
    return;
  }

  // Which slice is on screen, plus a screen either side so scrolling never shows
  // a blank band.
  const viewportH = list.clientHeight || 600;
  const start = Math.max(0, listTop - viewportH);
  const end = listTop + viewportH * 2;

  let y = 0;
  const parts = [];
  for (const item of view) {
    const h = rowHeight(item);
    if (y + h >= start && y <= end) parts.push({ item, y, h });
    y += h;
  }

  list.innerHTML = `<div style="height:${total}px;position:relative">${parts
    .map(({ item, y, h }) =>
      item.__group
        ? `<div class="group-head" style="position:absolute;top:${y}px;left:0;right:0;height:${h}px">${escapeHtml(
            item.__group,
          )} · ${item.__count}</div>`
        : rowHtml(item, y, h),
    )
    .join('')}</div>`;

  for (const el of list.querySelectorAll('.finding')) {
    el.onclick = () => openFinding(findings.find((f) => f.id === el.dataset.id));
  }
}

function rowHtml(f, y, h) {
  const sev = (f.severity || 'info')[0].toUpperCase();
  const verdict = f.verdict ? `<span class="verdict verdict-${f.verdict}">${f.verdict}</span>` : '';
  const tri =
    f.triage && f.triage !== 'open' ? `<span class="tri tri-${f.triage}">${f.triage}</span>` : '';
  // Only when the answer is known and yes. Absent baseline shows nothing at all,
  // rather than a badge that would imply a comparison was made.
  const isNew = f.is_new === true ? '<span class="newmark" title="not in the recorded baseline">NEW</span>' : '';
  const owner = f.assignee
    ? `<span class="owner" title="assigned to ${escapeHtml(f.assignee)}">@${escapeHtml(
        f.assignee.replace(/^agent:/, ''),
      )}</span>`
    : '';
  const talk =
    f.comments && f.comments.length
      ? `<span class="talk" title="${f.comments.length} remark(s)">${f.comments.length} rem</span>`
      : '';
  const where = f.byte_offset != null ? `@${f.byte_offset.toString(16)}` : f.line;
  return `<div class="finding ${f.css_class}" role="option" data-id="${f.id}"
       aria-selected="${f.id === selectedId}"
       style="position:absolute;top:${y}px;left:0;right:0;height:${h}px">
    <span class="sevmark sev-${f.severity}" title="${f.severity}">${sev}</span>
    <div class="finding-body">
      <div class="finding-head">
        <span class="rule">${escapeHtml(f.rule)}</span>${isNew}${verdict}${tri}
      </div>
      <div class="loc">${escapeHtml(f.file)}:${where}${owner}${talk}</div>
      <div class="title">${escapeHtml(f.title || f.message)}</div>
    </div>
  </div>`;
}

function render() {
  recomputeView();
  renderChips();
  renderList();
  const real = view.filter((i) => !i.__group).length;
  document.getElementById('shown').textContent =
    real === findings.length ? `${real} shown` : `${real} of ${findings.length} shown`;
}

// --- detail pane ------------------------------------------------------------
//
// The answer to "why does it say that". A coloured chip states a conclusion; the
// evidence is what lets a reader disagree with it, and the engine has always
// produced it.

function renderDetail(f) {
  const host = document.getElementById('detail');
  if (!f) {
    host.innerHTML = `<div class="empty">Select a finding.</div>`;
    return;
  }
  const tags = (f.taxonomy || []).map((t) => `<span class="tag">${escapeHtml(t)}</span>`).join('');

  host.innerHTML = `
    <h2>${escapeHtml(f.title || f.rule)}</h2>
    <div class="sub">${escapeHtml(f.rule)} · ${escapeHtml(f.file)}:${f.line}</div>

    <section><p>${escapeHtml(f.message)}</p></section>

    ${
      f.rationale
        ? `<section><h3>Why this verdict</h3><div class="why">${escapeHtml(f.rationale)}</div></section>`
        : ''
    }

    <section>
      <h3>Classification</h3>
      <dl class="kv">
        <dt>severity</dt><dd>${f.severity}</dd>
        <dt>confidence</dt><dd>${f.confidence}</dd>
        <dt>phase</dt><dd>${f.phase}</dd>
        ${f.verdict ? `<dt>verdict</dt><dd>${f.verdict}</dd>` : ''}
        ${f.suppressed_by ? `<dt>deviation</dt><dd>${escapeHtml(f.suppressed_by)}</dd>` : ''}
      </dl>
      ${tags ? `<div style="margin-top:6px">${tags}</div>` : ''}
    </section>

    ${
      f.remediation
        ? `<section><h3>Remediation</h3><p>${escapeHtml(f.remediation)}</p></section>`
        : ''
    }

    ${evidenceHtml(f)}

    <section>
      <h3>Assignment</h3>
      <div class="triage-row">
        <input id="assignee" placeholder="nobody" value="${escapeHtml(f.assignee || '')}"
               aria-label="Assignee" />
        <button class="chip" type="button" id="assign-me">me</button>
        <button class="chip" type="button" id="assign-agent">agent</button>
      </div>
      <div class="hint">Assigning concludes nothing — an assigned finding is still
        unreviewed. A person and an agent share one namespace, so a batch can be
        handed to <code>agent:triage-bot</code> and read back here.</div>
    </section>

    <section>
      <h3>Discussion${f.comments.length ? ` (${f.comments.length})` : ''}</h3>
      ${
        f.comments.length
          ? `<ol class="thread">${f.comments
              .map(
                (c) =>
                  `<li><div class="who">${escapeHtml(c.by)} · ${escapeHtml(
                    c.at.slice(0, 16).replace('T', ' '),
                  )}</div><div>${escapeHtml(c.text)}</div></li>`,
              )
              .join('')}</ol>`
          : '<p class="hint">Nothing said yet.</p>'
      }
      <textarea id="comment-text" rows="2" placeholder="add a remark…"></textarea>
      <div class="triage-row"><button class="chip" type="button" id="comment-add">Comment</button></div>
    </section>

    <section>
      <h3>Review</h3>
      <div class="triage-row">
        ${TRIAGE.map(
          (s) =>
            `<button class="chip" type="button" data-triage="${s}" aria-pressed="${
              (f.triage ?? 'open') === s
            }">${s}</button>`,
        ).join('')}
      </div>
      <textarea id="triage-note" rows="2" placeholder="why — the point of accepted and false-positive">${escapeHtml(
        f.triage_note || '',
      )}</textarea>
      <div class="hint">
        Recorded in <code>.sda/triage.toml</code>, the same file agents read and write over MCP.
        Triage annotates and never hides: this finding stays in every report and every exit code.
        Suppression is a <em>deviation</em>, and that needs an approver.
      </div>
    </section>`;

  for (const b of host.querySelectorAll('[data-triage]')) {
    b.onclick = () => setTriage(f, b.dataset.triage);
  }
  const assignee = host.querySelector('#assignee');
  assignee.onchange = () => assign(f, assignee.value.trim());
  host.querySelector('#assign-me').onclick = () => assign(f, me);
  host.querySelector('#assign-agent').onclick = () => assign(f, 'agent:triage-bot');
  host.querySelector('#comment-add').onclick = () =>
    addComment(f, host.querySelector('#comment-text').value);
  for (const el of host.querySelectorAll('[data-step]')) {
    const [file, line, col] = el.dataset.step.split('|');
    el.onclick = () => gotoStep(file, Number(line), Number(col));
  }
}

function evidenceHtml(f) {
  if (!f.evidence || !f.evidence.length) {
    return `<section><h3>Evidence</h3><p class="hint">None recorded. That is not the same as a
      finding nothing supports — some checks state a conclusion and no artefact.</p></section>`;
  }
  const blocks = f.evidence
    .map((e) => {
      const steps = e.steps && e.steps.length
        ? `<ol class="steps">${e.steps
            .map(
              (s) =>
                `<li data-step="${escapeHtml(s.file)}|${s.line}|${s.column}">
                   <div class="where">${escapeHtml(s.file)}:${s.line}</div>
                   <div class="note">${escapeHtml(s.note)}</div>
                 </li>`,
            )
            .join('')}</ol>`
        : '';
      const detail = e.detail ? `<pre>${escapeHtml(e.detail)}</pre>` : '';
      const body = steps || detail ? `<div class="ev-body">${steps}${detail}</div>` : '';
      return `<div class="ev">
        <div class="ev-head"><span class="ev-kind">${escapeHtml(e.kind)}</span>
          <span>${escapeHtml(e.summary)}</span></div>
        ${body}
      </div>`;
    })
    .join('');
  return `<section><h3>Evidence</h3>${blocks}</section>`;
}

async function gotoStep(file, line, column) {
  await openFile(file);
  editor.revealLineInCenter(line);
  editor.setPosition({ lineNumber: line, column });
  stepDecorations = editor.deltaDecorations(stepDecorations, [
    {
      range: new monaco.Range(line, 1, line, 1),
      options: { isWholeLine: true, className: 'sda-step' },
    },
  ]);
  editor.focus();
}

async function assign(f, to) {
  try {
    await invoke('assign_finding', {
      id: f.id,
      to: to || null,
      rule: f.rule,
      location: `${f.file}:${f.line}`,
      title: f.title,
    });
    f.assignee = to || null;
    render();
    renderDetail(f);
    setStatus(to ? `assigned to ${to} — .sda/triage.toml` : 'unassigned');
  } catch (e) {
    setStatus(`could not assign: ${e}`);
  }
}

async function addComment(f, text) {
  if (!text.trim()) return;
  try {
    await invoke('comment_on_finding', {
      id: f.id,
      by: me,
      text,
      rule: f.rule,
      location: `${f.file}:${f.line}`,
      title: f.title,
    });
    f.comments = [...f.comments, { by: me, at: new Date().toISOString(), text }];
    renderDetail(f);
    render();
    setStatus('remark added — .sda/triage.toml');
  } catch (e) {
    setStatus(`could not comment: ${e}`);
  }
}

async function setTriage(f, state) {
  const note = document.getElementById('triage-note')?.value ?? '';
  try {
    await invoke('set_triage', {
      id: f.id,
      stateName: state,
      note,
      by: null,
      rule: f.rule,
      location: `${f.file}:${f.line}`,
      title: f.title,
    });
    f.triage = state === 'open' ? null : state;
    f.triage_note = note || null;
    render();
    renderDetail(f);
    setStatus(`recorded ${state} for ${f.rule} — .sda/triage.toml`);
  } catch (e) {
    setStatus(`could not record: ${e}`);
  }
}

// --- navigation -------------------------------------------------------------

async function openFinding(f) {
  if (!f) return;
  selectedId = f.id;
  renderDetail(f);
  renderList();

  if (f.byte_offset == null) {
    await openFile(f.file);
    editor.revealLineInCenter(f.line);
    editor.setPosition({ lineNumber: f.line, column: f.column });
  }

  const detail = await invoke('rule_detail', { rule: f.rule });
  if (detail) {
    // The honest bit: say whether a clean result for this rule would mean anything.
    setStatus(
      `${detail.citation} — ${detail.obligation}, ${detail.decidable ? 'decidable' : 'UNDECIDABLE'}; ` +
        (detail.clean_means_conformant
          ? 'a clean result is evidence of conformance'
          : 'a clean result does NOT establish conformance'),
    );
  }
}

function move(delta) {
  const rows = view.filter((i) => !i.__group);
  if (!rows.length) return;
  const i = rows.findIndex((f) => f.id === selectedId);
  const next = rows[Math.min(rows.length - 1, Math.max(0, (i < 0 ? -1 : i) + delta))];
  if (next) {
    openFinding(next);
    scrollTo(next);
  }
}

function scrollTo(f) {
  const list = document.getElementById('findings');
  let y = 0;
  for (const item of view) {
    if (!item.__group && item.id === f.id) break;
    y += rowHeight(item);
  }
  if (y < list.scrollTop || y + ROW_H > list.scrollTop + list.clientHeight) {
    list.scrollTop = y - list.clientHeight / 2;
  }
}

async function openFile(file) {
  const path = file.startsWith('/') || file.match(/^[A-Za-z]:/) ? file : `${projectRoot}/${file}`;
  if (currentFile === path) return;
  const doc = await invoke('open_document', { path });
  currentFile = doc.path;
  const model = monaco.editor.createModel(doc.text, monacoLanguage(doc.language));
  editor.setModel(model);
  await applyDecorations(findings);
  applyCoverage(file);
}

function monacoLanguage(language) {
  return { c: 'c', cpp: 'cpp', rust: 'rust', python: 'python' }[language] ?? 'plaintext';
}

// --- scanning ---------------------------------------------------------------

async function runScan() {
  setStatus('scanning...');
  document.getElementById('progress').hidden = false;
  try {
    const artifact = document.getElementById('artifact').value.trim();
    const items = await invoke('scan', {
      path: projectRoot,
      artifact: artifact || null,
      allowExternal: document.getElementById('external').checked,
    });
    findings = items;
    selectedId = null;
    render();
    renderDetail(null);

    renderNotChecked(await invoke('not_checked'), await invoke('stale_triage'));
    await renderBaseline();
    document.getElementById('count').textContent = `${items.length} findings`;
    setStatus(`scan complete: ${items.length} findings`);
  } catch (e) {
    setStatus(`scan failed: ${e}`);
  } finally {
    document.getElementById('progress').hidden = true;
  }
}

// What the run did not check.
//
// Never dismissible and never truncated away — but *proportionate*. Every
// external provider that was not enabled produces one line, and once they are
// all registered (so the report can name them, which is the point) that is nine
// identical sentences filling a quarter of the window. A banner that large is one
// people learn to scroll past, which costs exactly what suppressing it would.
//
// So the repetitive class is folded into one line that still states the count and
// still lists every name when opened, and anything that is *not* that class —
// a failed provider, a scope exclusion, a stale review, a refuted proof — stays
// spelled out. Collapsing is not hiding: the count is on screen either way.
function renderNotChecked(gaps, stale) {
  const banner = document.getElementById('not-checked');
  const all = [...gaps, ...stale];
  if (!all.length) {
    banner.style.display = 'none';
    return;
  }
  const NATIVE_FIRST = /external provider not enabled/;
  const routine = all.filter((g) => NATIVE_FIRST.test(g));
  const notable = all.filter((g) => !NATIVE_FIRST.test(g));

  const items = notable.map((g) => `<li>${escapeHtml(g)}</li>`).join('');
  const folded = routine.length
    ? `<li><details><summary>${routine.length} external provider(s) not enabled
         (native-first policy)</summary><ul>${routine
           .map((g) => `<li>${escapeHtml(g)}</li>`)
           .join('')}</ul></details></li>`
    : '';

  banner.style.display = 'block';
  banner.innerHTML = `<strong>Not checked by this run:</strong><ul>${items}${folded}</ul>`;
}

// What the baseline says, in the status line rather than as a badge nobody reads.
async function renderBaseline() {
  const info = await invoke('baseline_info');
  const label = document.getElementById('baseline-info');
  if (!info) {
    label.textContent = 'no baseline';
    label.title = 'Nothing recorded, so no finding can be shown as new. Set one to start comparing.';
    return;
  }
  const resolved = info.resolved ? `, ${info.resolved} resolved since` : '';
  label.textContent = `baseline ${info.taken_at.slice(0, 10)} · ${info.recorded} recorded${resolved}`;
  label.title = info.note ?? '';
}

async function setBaseline() {
  try {
    setStatus(await invoke('set_baseline', { note: null }));
    // Re-scan so `is_new` is recomputed: every finding is now in the baseline, so
    // the honest immediate answer is "nothing is new", and showing the previous
    // answer would be stale the moment the button was pressed.
    await runScan();
  } catch (e) {
    setStatus(`could not set baseline: ${e}`);
  }
}

async function showPlan() {
  const text = await invoke('plan', { path: projectRoot });
  const model = monaco.editor.createModel(text, 'plaintext');
  editor.setModel(model);
  currentFile = null;
}

// --- splitters --------------------------------------------------------------

function draggable(handle, apply) {
  handle.addEventListener('mousedown', (down) => {
    down.preventDefault();
    handle.classList.add('dragging');
    const move = (e) => apply(e);
    const up = () => {
      handle.classList.remove('dragging');
      document.removeEventListener('mousemove', move);
      document.removeEventListener('mouseup', up);
      editor?.layout();
      renderList();
    };
    document.addEventListener('mousemove', move);
    document.addEventListener('mouseup', up);
  });
}

function wireSplitters() {
  const root = document.documentElement;
  const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
  draggable(document.getElementById('split-list'), (e) =>
    root.style.setProperty('--list-w', `${clamp(e.clientX, 240, 900)}px`),
  );
  draggable(document.getElementById('split-detail'), (e) =>
    root.style.setProperty('--detail-w', `${clamp(window.innerWidth - e.clientX, 260, 900)}px`),
  );
  draggable(document.getElementById('split-term'), (e) => {
    const main = document.querySelector('main').getBoundingClientRect();
    root.style.setProperty('--term-h', `${clamp(main.bottom - e.clientY, 0, main.height - 120)}px`);
  });
}

// --- keyboard ---------------------------------------------------------------
//
// A review queue is a keyboard instrument. Reaching for the mouse between every
// finding is what makes a backlog of thousands feel like one.

function wireKeys() {
  document.addEventListener('keydown', (e) => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName ?? '');
    if (e.key === '/' && !typing) {
      e.preventDefault();
      document.getElementById('q').focus();
      return;
    }
    if (e.key === 'Escape') {
      document.getElementById('q').blur();
      editor?.focus();
      return;
    }
    if (typing) return;

    if (e.key === 'j' || e.key === 'ArrowDown') { e.preventDefault(); move(1); }
    else if (e.key === 'k' || e.key === 'ArrowUp') { e.preventDefault(); move(-1); }
    else if (['1', '2', '3', '4'].includes(e.key)) {
      const f = findings.find((x) => x.id === selectedId);
      if (f) setTriage(f, TRIAGE[Number(e.key) - 1]);
    }
  });
}

// --- helpers ----------------------------------------------------------------

function setStatus(text) {
  document.getElementById('status').textContent = text;
}
function baseName(p) {
  return (p ?? '').split(/[\\/]/).pop();
}
function escapeHtml(s) {
  return String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
}

// --- boot -------------------------------------------------------------------

function wireControls() {
  document.getElementById('scan').onclick = runScan;
  document.getElementById('plan').onclick = showPlan;
  document.getElementById('set-baseline').onclick = setBaseline;
  document.getElementById('root').addEventListener('change', (e) => {
    projectRoot = e.target.value.trim() || '.';
  });

  let debounce = null;
  document.getElementById('q').addEventListener('input', (e) => {
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      filters.q = e.target.value.trim();
      render();
    }, 120);
  });
  document.getElementById('groupby').addEventListener('change', (e) => {
    filters.group = e.target.value;
    render();
  });
  document.getElementById('clear').onclick = () => {
    filters.q = '';
    filters.sev.clear();
    filters.verdict.clear();
    filters.triage.clear();
    filters.onlyNew = false;
    filters.mine = false;
    filters.group = 'none';
    document.getElementById('q').value = '';
    document.getElementById('groupby').value = 'none';
    render();
  };

  const list = document.getElementById('findings');
  list.addEventListener('scroll', () => {
    listTop = list.scrollTop;
    renderList();
  });
}

async function startTerminal() {
  const term = new Terminal({
    fontFamily: 'Cascadia Mono, Consolas, monospace',
    fontSize: 12,
    theme: { background: '#12161c', foreground: '#d7dde5' },
  });
  const fit = new FitAddon();
  term.loadAddon(fit);
  term.open(document.getElementById('terminal'));
  fit.fit();

  await invoke('terminal_start', { cwd: projectRoot });
  term.onData((d) => invoke('terminal_write', { data: d }));
  term.onResize(({ rows, cols }) => invoke('terminal_resize', { rows, cols }));
  setInterval(async () => {
    const out = await invoke('terminal_read');
    if (out) term.write(out);
  }, 30);

  window.addEventListener('resize', () => {
    fit.fit();
    renderList();
  });
}

createEditor();
wireControls();
wireSplitters();
wireKeys();
render();
renderDetail(null);
startTerminal();
setStatus('ready — set a project root and scan');

// --- automation surface -----------------------------------------------------

// This toolkit's premise is that an agent should be able to drive the workbench
// the same way it drives the analysis, so the window state is exposed rather
// than hidden behind module scope. It is also the only way to check what the
// editor actually holds: the DOM shows Monaco's rendering of decorations, which
// is not the same thing as the decorations themselves, and reasoning from the
// DOM led to two wrong conclusions before this existed.
window.__sda = {
  get findings() {
    return findings;
  },
  /// What the filters currently admit — the list as a person sees it.
  get view() {
    return view.filter((i) => !i.__group);
  },
  get filters() {
    return { ...filters, sev: [...filters.sev], verdict: [...filters.verdict], triage: [...filters.triage] };
  },
  get selected() {
    return findings.find((f) => f.id === selectedId) ?? null;
  },
  get currentFile() {
    return currentFile;
  },
  /// Drive the queue the way the keyboard does, so a harness tests the real path.
  select(id) {
    return openFinding(findings.find((f) => f.id === id));
  },
  next() {
    move(1);
  },
  prev() {
    move(-1);
  },
  setOnlyNew(on) {
    filters.onlyNew = !!on;
    render();
  },
  search(text) {
    filters.q = text;
    document.getElementById('q').value = text;
    render();
  },
  /// Decorations as the *model* holds them, independent of what is on screen.
  modelDecorations() {
    const model = editor?.getModel();
    if (!model) return [];
    return model.getAllDecorations().map((d) => ({
      range: [d.range.startLineNumber, d.range.startColumn, d.range.endLineNumber, d.range.endColumn],
      className: d.options.className ?? null,
      glyph: d.options.glyphMarginClassName ?? null,
      inline: d.options.inlineClassName ?? null,
    }));
  },
};
