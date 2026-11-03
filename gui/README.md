# The StatodynamicAnalysis GUI

A three-pane workbench: findings on the left, an editor in the middle with
diagnostics and coverage rendered inline, and an embedded terminal below.

## Two shells, one core

The GUI logic — models, decorations, commands — lives in Rust, in `sda-editor`
and the `sda-*` analysis crates. The *shell* that renders it is pluggable, and
there are two:

| Shell | Status | Why you would pick it |
|---|---|---|
| **Tauri** (`src-tauri/`) | default | Works today on Windows, macOS and Linux with the platform webview. Uses Monaco as-is, so the editor is the one every developer already knows. |
| **Dewey** (`--features dewey`) | scaffolded, not built here | [nervosys/Dewey](https://github.com/nervosys/Dewey) is an agentic-first Rust GUI framework whose widgets expose a JSON agent protocol and a semantic ontology. That is a much better fit for this toolkit's thesis — an agent could drive the *GUI* the same way it drives the analysis — and it removes the webview entirely. |

The seam between them is `shell::Shell` in `src-tauri/src/shell.rs`: a small
trait covering "open a document", "show findings", "run a command in the
terminal". Neither shell knows anything about MISRA or model scanning.

## On "porting Monaco to Rust"

Worth being precise, because the phrase covers two very different jobs.

**Done, in `sda-editor`.** Monaco's *text model* is ported: a rope-backed buffer,
monotonic versions, a full change-event stream, Monaco's 1-based position
convention, ranges and multi-cursor selections with correct edit ordering, and
decorations with the four stickiness policies. This is the part with the
interesting semantics, and the part that must be right — a decoration that drifts
by one line after an edit puts a finding on the wrong statement. It is 42 tests
of behaviour, and it has no JavaScript in it.

**Not done, and not attempted here.** Monaco's *view* layer: the virtualised
renderer, the DOM, the input handling, IME, accessibility, the language-services
protocol, and roughly a decade of accumulated editor behaviour. Reimplementing
that is a multi-year project in its own right, and doing it badly would make the
product worse than embedding the original.

So the Tauri shell runs real Monaco in the webview and drives it from the Rust
model over the IPC bridge. The Dewey shell is where a native renderer would
plug in, against the same model, when one is worth building.

## Running it

```bash
cd gui
npm install          # fetches Monaco and xterm.js; they are vendored, not CDN-loaded
npm run tauri dev
```

Prerequisites: Rust, Node 18+, and the platform webview (WebView2 on Windows,
WebKitGTK on Linux).

> **Status, precisely.** The release binary builds and launches — a window
> titled `StatodynamicAnalysis` serving `http://tauri.localhost/`, with Monaco
> and xterm both mounted. The embedded terminal is tested directly: it starts a
> shell, echoes a command, and survives a resize.
>
> The UI has been driven end to end, by attaching to the running window over the
> Chrome DevTools Protocol and clicking for real: setting a project root and
> pressing **Scan** returns 20 findings for `examples/firmware` and renders all
> 20; clicking one loads the file into Monaco with its diagnostic decorations;
> the "not checked" banner populates. So the JavaScript half of the IPC bridge
> is exercised, not assumed.
>
> That exercise is what caught the bug worth knowing about: the workbench built
> its analyzer registry from defaults and never read the project's `.sda/`
> directory, so approved deviations applied on the command line and *not* in the
> window — one project, two answers. The same was true of `check_buffer`, the
> live-typing path, which meant the editor could underline a rule the findings
> list was greying out, in one window at one moment. Both now go through the
> engine's `check_buffer` / `project_setup`, verified over the live IPC bridge:
> `check_buffer` on `examples/firmware/src/main.c` returns 20 findings with 3
> suppressed, each carrying its citation (`ECR-4412`), matching the scan exactly.
>
> **On reading the decoration layer.** An earlier revision of this file reported
> findings going missing from the editor. That was wrong, and the way it was
> wrong is worth keeping: it was inferred by counting DOM nodes, which is not a
> valid proxy for what the editor holds. Monaco renders `className` decorations
> as one `div.cdr` per line per class in its `view-overlays` layer — not as spans
> inside `.view-line` — and several decorations sharing a line and a class
> coalesce into a single div. Measured on `main.c`: 11 `sda-info` decorations
> across 8 distinct lines produce exactly 8 divs, because line 9 carries two and
> line 26 carries three. The model holds all 20 findings, deviated ones included.
>
> One real consequence remains, and it is not data loss: a line with three
> findings looks like a line with one, so the findings list — not the editor — is
> the authority on counts.
>
> The other consequence has been fixed. Findings used to carry no extent, so each
> decoration ran from its column to the end of the line; `Location::spanning` was
> dead code called once, from a test. Findings now carry the span of the
> construct they name — taken from the lexer's own tokenisation, so a directive,
> a block comment and a prefixed string literal each span whole — and every
> fixture is checked for it by `every_fixture_finding_brackets_its_construct`.
>
> `window.__sda` exists because of this: it exposes `modelDecorations()` and
> `visibleRange()` so the editor's actual state can be read instead of guessed at
> through the DOM. It is also the automation surface an agent would drive.
>
> One requirement the terminal test uncovered: ConPTY opens by asking the
> terminal where its cursor is (`ESC [ 6 n`), and the shell waits for an answer.
> xterm.js replies automatically through `onData`, which this shell forwards
> back — but any other frontend must do the same, or the shell will appear to
> hang before its first prompt.

## What the GUI shows that the CLI cannot

* **Coverage as a gutter stripe.** Unexecuted lines are visibly different from
  executed ones, which is the fastest way to see that a "clean" area was never
  tested.
* **Confirmed versus suspected.** A finding that runtime evidence confirmed
  renders differently from one that is still a static suspicion.
* **The terminal in the same window.** Rebuild, re-run, re-correlate without
  leaving the findings list — the loop the whole toolkit is built around.

