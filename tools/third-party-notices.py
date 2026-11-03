"""Third-party notices for the binary release, from what is actually built.

    python tools/third-party-notices.py                 # notices to stdout
    python tools/third-party-notices.py NOTICES.txt     # notices to a file
    python tools/third-party-notices.py --root DIR      # another checkout (calibration)

A binary release redistributes every crate it links and every JavaScript package
the GUI bundles, and most of the licences they carry require their notice and
licence text to travel with the binary. The failure this tool exists to prevent is
a notices file that is complete-looking and silently missing a package: someone
adds a dependency, nobody regenerates the notices, and the release ships without
the attribution it owes. So this tool does not produce a partial file. If any
package has no licence expression, or no licence text can be found for it and no
reason is recorded in KNOWN_EXCEPTIONS, it names every such package on stderr,
writes nothing, and exits 1. A recorded exception appears in the file with its
reason.

What it reads:

* Rust: `cargo metadata --format-version 1 --offline` at the repository root and
  in gui/src-tauri. For each graph it takes the `resolve` nodes (the packages
  actually in the dependency graph, not merely in `packages`) that are not
  workspace members, and takes the union of the two graphs. Dev-dependency-only
  packages are included too: the union is then a superset of what ships, which
  errs in the safe direction. The licence text comes from the package's manifest
  directory in the local registry: LICENSE*, COPYING*, COPYRIGHT*, NOTICE* and
  THIRD-PARTY* files. Path packages inside this repository are first-party; they
  are listed by name and covered by the repository LICENSE, not by a text lookup.
  A path package outside the repository is third-party and needs text.
* JavaScript: gui/package.json `dependencies`, followed transitively through the
  `dependencies` field of each installed package.json under gui/node_modules,
  resolved the way Node resolves them (nearest node_modules first). devDependencies
  such as vite are not read because they do not ship in dist. A dependency that is
  declared but not installed is an error (exit 2), not a silent omission.
* Two items the packages do not carry: DOMPurify, which monaco-editor vendors
  inside itself (its header names the licence), and the codicon icon font, which
  is also shipped inside monaco-editor. The codicon section reports only what a
  file on disk states. If none states a licence for the font, the notice says so.
  It does not assert one.

Exit codes: 0 notices written; 1 at least one package has no licence expression
or no licence text (each one named, nothing written); 2 the tool could not run
(cargo metadata failed, gui/node_modules is missing, a declared dependency is not
installed).

Known exceptions are the KNOWN_EXCEPTIONS mapping below: `name version` to the
reason the package ships no licence text. An exception is printed in the notices
with its reason. An exception that no package needs is reported as stale.

--target limits the Rust graphs to what one platform builds, as a release for that
platform should: the Apple, Android, UEFI and GNU crates are in the lockfile and not
in a Windows binary. Exceptions are not checked for staleness under it, because an
exception for another platform is unused there by design.

How it was calibrated: the expected counts are 79 registry crates in the root
workspace graph and 431 in gui/src-tauri. The offline graphs give exactly those:
root 79 non-workspace packages (79 registry); gui/src-tauri 441 (431 registry,
10 first-party path crates). Their union is 451 registry crates, the 59 shared
by both graphs counted once. The JavaScript side gives 4 packages (the direct
dependencies; none of them has a transitive dependency). The first run found 42
packages with no licence file. Checking them showed that the registry tarballs
really ship none (the one miss, cesu8's COPYRIGHT-RUST.txt, led to adding
COPYRIGHT*), so they became the 41 KNOWN_EXCEPTIONS, each with its reason; most of them
have since been given upstream texts vendored under tools/licences (see VENDORED). A
missing-text check was then tested by patching a lookup through an
import-and-run wrapper: a package whose manifest directory does not exist, a
package whose licence expression is removed, and a JS package whose licence files
are hidden. Each exits 1, names the package, and writes no file. --skip-rust and
--skip-js exist so each half can be run alone; a release notice needs neither.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys

LICENCE_FILE = re.compile(r'^(LICEN[CS]E|COPYING|COPYRIGHT|NOTICE|THIRD[-_ ]?PARTY)', re.I)
RUST_GRAPHS = ['', 'gui/src-tauri']  # relative to the root; '' is the root itself
GUI_DIR = 'gui'
DOMPURIFY = 'gui/node_modules/monaco-editor/esm/vs/base/browser/dompurify/dompurify.js'
MONACO_DIR = 'gui/node_modules/monaco-editor'
CODICON_CSS = 'gui/node_modules/monaco-editor/esm/vs/base/browser/ui/codicons/codicon/codicon.css'
CODICON_JS = 'gui/node_modules/monaco-editor/esm/vs/base/browser/ui/codicons/codiconStyles.js'
CODICON_FONT = 'gui/node_modules/monaco-editor/esm/vs/base/browser/ui/codicons/codicon/codicon.ttf'

# Vendored upstream licence texts, one directory per source under tools/licences. Used only
# when the published crate ships no licence file of its own: the crate's own files always
# win. Each directory holds the upstream files byte for byte and a SOURCE.txt whose first
# line names the repository and the tag or commit they were taken from.
LICENCE_DIR = 'tools/licences'
VENDORED = {
    'alloc-stdlib 0.2.4': 'alloc-stdlib-0.2.4',
    'dlopen2 0.8.2': 'dlopen2-cc80e4a',
    'dlopen2_derive 0.4.3': 'dlopen2-cc80e4a',
    'jni-sys-macros 0.4.1': 'jni-sys-macros-0.4.1',
    'libappindicator-sys 0.9.0': 'libappindicator-sys-0.9.0',
    'selectors 0.36.1': 'selectors-0.36.1',
    'ndk 0.9.0': 'ndk-0.9.0',
    'ndk-sys 0.6.0+11769913': 'ndk-sys-0.6.0',
    'ra-ap-rustc_lexer 0.174.0': 'ra-ap-rustc_lexer-0.174.0',
    'unic-char-property 0.9.0': 'unic-0.9.0',
    'unic-char-range 0.9.0': 'unic-0.9.0',
    'unic-common 0.9.0': 'unic-0.9.0',
    'unic-ucd-ident 0.9.0': 'unic-0.9.0',
    'unic-ucd-version 0.9.0': 'unic-0.9.0',
    'wasip2 1.0.1+wasi-0.2.4': 'wasip2-1.0.1',
    'webview2-com 0.38.2': 'webview2-rs-b74dc5e',
    'webview2-com-sys 0.38.2': 'webview2-rs-b74dc5e',
    'webview2-com-macros 0.8.1': 'webview2-rs-dffa41a',
    'block2 0.6.2': 'objc2',
    'dispatch2 0.3.1': 'objc2',
    'objc2 0.6.4': 'objc2',
    'objc2-app-kit 0.3.2': 'objc2',
    'objc2-cloud-kit 0.3.2': 'objc2',
    'objc2-core-data 0.3.2': 'objc2',
    'objc2-core-foundation 0.3.2': 'objc2',
    'objc2-core-graphics 0.3.2': 'objc2',
    'objc2-core-image 0.3.2': 'objc2',
    'objc2-core-location 0.3.2': 'objc2',
    'objc2-core-text 0.3.2': 'objc2',
    'objc2-encode 4.1.0': 'objc2',
    'objc2-exception-helper 0.1.1': 'objc2',
    'objc2-foundation 0.3.2': 'objc2',
    'objc2-io-surface 0.3.2': 'objc2',
    'objc2-quartz-core 0.3.2': 'objc2',
    'objc2-ui-kit 0.3.2': 'objc2',
    'objc2-user-notifications 0.3.2': 'objc2',
    'objc2-web-kit 0.3.2': 'objc2',
}

# `name version` -> why this package ships no licence text, for the packages that still have
# none. Each was checked: its registry directory has no LICENSE, COPYING, COPYRIGHT or NOTICE
# file, and the upstream revision named in the reason was checked as stated. The licence
# expression still comes from Cargo.toml and is printed.
REFI_NO_TEXT = ('upstream repository r-efi/r-efi has no licence file at tag v5.3.0 or v6.0.0 (full trees '
                'checked); the published crate has none either')
WINAPI_NO_TEXT = ('no upstream revision is identified: retep998/winapi-rs has no 0.4.0 tag (its tags run '
                  '0.3.0 to 0.3.9) and the crate has no .cargo_vcs_info.json')
KNOWN_EXCEPTIONS = {
    'r-efi 5.3.0': REFI_NO_TEXT,
    'r-efi 6.0.0': REFI_NO_TEXT,
    'winapi-i686-pc-windows-gnu 0.4.0': WINAPI_NO_TEXT,
    'winapi-x86_64-pc-windows-gnu 0.4.0': WINAPI_NO_TEXT,
}


class Tooling(Exception):
    """The tool could not run to a verdict; exit 2."""


def manifest_dir(pkg):
    """Directory holding the package's manifest, which is where its licence files live."""
    return os.path.dirname(pkg['manifest_path'])


def read_text(path):
    with open(path, encoding='utf-8', errors='replace') as f:
        return f.read().strip('\n')


def texts_for(directory):
    """(file name, text) for each non-empty licence-type file, or None if the directory is absent."""
    if not os.path.isdir(directory):
        return None
    out = []
    for n in sorted(os.listdir(directory)):
        full = os.path.join(directory, n)
        if LICENCE_FILE.match(n) and os.path.isfile(full):
            text = read_text(full)
            if text.strip():
                out.append((n, text))
    return out


def source_of(directory):
    """First line of the SOURCE.txt beside vendored licence texts: the repository and tag or commit."""
    p = os.path.join(directory, 'SOURCE.txt')
    if not os.path.isfile(p):
        return '(no SOURCE.txt beside the vendored licence text)'
    with open(p, encoding='utf-8') as f:
        return f.readline().strip()


def licence_text(root, label, directory):
    """(files, source, exception) for a Rust package. Its own licence files win; otherwise the
    vendored upstream copy recorded in VENDORED; otherwise its KNOWN_EXCEPTIONS reason."""
    files = texts_for(directory)
    if files:
        return files, None, None
    if label in VENDORED:
        vdir = os.path.join(root, LICENCE_DIR, VENDORED[label])
        files = texts_for(vdir)
        if files:
            return files, source_of(vdir), None
    return files, None, KNOWN_EXCEPTIONS.get(label)


def inside(path, root):
    real_root = os.path.realpath(root)
    real = os.path.realpath(path)
    return real == real_root or real.startswith(real_root + os.sep)


def cargo_metadata(where, target=None):
    command = ['cargo', 'metadata', '--format-version', '1', '--offline']
    if target:
        command += ['--filter-platform', target]
    proc = subprocess.run(command, cwd=where, capture_output=True)
    if proc.returncode != 0:
        raise Tooling('cargo metadata --offline failed in %s (exit %d): %s'
                      % (where, proc.returncode, proc.stderr.decode('utf-8', 'replace').strip()))
    return json.loads(proc.stdout.decode('utf-8'))


def rust_packages(root, skip, problems, first_party, counts, target=None):
    """Records for third-party Rust packages; first-party path crates go to first_party."""
    if skip:
        return []
    graphs = {}
    for rel in RUST_GRAPHS:
        meta = cargo_metadata(os.path.join(root, rel), target)
        ws = set(meta['workspace_members'])
        by_id = {p['id']: p for p in meta['packages']}
        ids = [n['id'] for n in meta['resolve']['nodes'] if n['id'] not in ws]
        label = rel or 'repo root'
        counts.append('%s: %d non-workspace packages in resolve (%d registry, %d path)' % (
            label, len(ids),
            sum(1 for i in ids if by_id[i]['source'] is not None),
            sum(1 for i in ids if by_id[i]['source'] is None)))
        for i in ids:
            graphs.setdefault(i, (by_id[i], []))[1].append(label)

    records = []
    for pid in sorted(graphs, key=lambda i: (graphs[i][0]['name'], graphs[i][0]['version'])):
        pkg, used_by = graphs[pid]
        label = '%s %s' % (pkg['name'], pkg['version'])
        d = manifest_dir(pkg)
        if pkg['source'] is None and inside(d, root):
            first_party.append((label, pkg.get('license') or '(no license expression)'))
            continue
        files, source, exc = licence_text(root, label, d)
        if not pkg.get('license'):
            detail = 'manifest declares no license expression'
            if pkg.get('license_file'):
                detail += ' (license_file = %s)' % pkg['license_file']
            problems.append(('no licence expression', label, detail))
        if not files and not exc:
            if files is None:
                detail = 'manifest directory does not exist: %s' % d
            else:
                detail = 'no LICENSE*, COPYING*, NOTICE* or THIRD-PARTY* file in %s' % d
            problems.append(('no licence text', label, detail))
        records.append({'label': label, 'expr': pkg.get('license'), 'used_by': used_by,
                        'files': files or [], 'exception': exc, 'source': source})
    return records


def resolve_js(name, frm, gui):
    """Node-style resolution: nearest node_modules first, walking up to gui/."""
    d = os.path.normpath(frm)
    gui_n = os.path.normpath(gui)
    while True:
        cand = os.path.join(d, 'node_modules', name)
        if os.path.isfile(os.path.join(cand, 'package.json')):
            return cand
        if d == gui_n:
            break
        d = os.path.dirname(d)
    raise Tooling('dependency %s (required from %s) is not installed under gui/node_modules; '
                  'run npm ci in gui/ and try again (this tool does not install)' % (name, frm))


def js_packages(root, skip, problems):
    if skip:
        return []
    gui = os.path.join(root, GUI_DIR)
    nm = os.path.join(gui, 'node_modules')
    if not os.path.isdir(nm):
        raise Tooling('gui/node_modules is absent; run npm ci in gui/ first '
                      '(this tool reads installed packages and does not install them)')
    with open(os.path.join(gui, 'package.json'), encoding='utf-8') as f:
        top = json.load(f).get('dependencies', {})

    seen = {}
    queue = [(n, gui) for n in sorted(top)]
    while queue:
        name, frm = queue.pop()
        d = resolve_js(name, frm, gui)
        key = os.path.normcase(os.path.normpath(d))
        if key in seen:
            continue
        with open(os.path.join(d, 'package.json'), encoding='utf-8') as f:
            pj = json.load(f)
        seen[key] = (pj.get('name', name), pj, d)
        for dep in sorted(pj.get('dependencies', {})):
            queue.append((dep, d))

    records = []
    for key in sorted(seen, key=lambda k: (seen[k][0], seen[k][1].get('version', ''))):
        name, pj, d = seen[key]
        label = '%s %s' % (name, pj.get('version', '?'))
        lic = pj.get('license')
        if isinstance(lic, dict):
            lic = lic.get('type')
        files = texts_for(d)
        exc = KNOWN_EXCEPTIONS.get(label)
        if not lic:
            problems.append(('no licence expression', label, 'package.json declares no license in %s' % d))
        if not files and not exc:
            problems.append(('no licence text', label, 'no LICENSE*, COPYING*, NOTICE* or THIRD-PARTY* file in %s' % d))
        records.append({'label': label, 'expr': lic, 'used_by': ['gui'],
                        'files': files or [], 'exception': exc})
    return records


def dompurify_note(root, problems):
    p = os.path.join(root, DOMPURIFY)
    if not os.path.isfile(p):
        raise Tooling('DOMPurify is not vendored at %s; the notice cannot be written without it' % DOMPURIFY)
    with open(p, encoding='utf-8', errors='replace') as f:
        first = f.readline()
    m = re.search(r'@license\s+(.*?)\s*\*/', first)
    if not m:
        raise Tooling('DOMPurify header in %s has no @license line' % DOMPURIFY)
    licence_here = [n for n in os.listdir(os.path.dirname(p)) if LICENCE_FILE.match(n)]
    lines = [
        'DOMPurify, vendored inside monaco-editor (%s).' % DOMPURIFY,
        '  Header, verbatim: ' + m.group(1),
    ]
    if licence_here:
        lines.append('  Licence files beside it: ' + ', '.join(sorted(licence_here)))
    else:
        lines.append('  The header names the Apache License 2.0 and the Mozilla Public License 2.0 and points to')
        lines.append('  the upstream LICENSE file. No licence file is present beside the vendored copy, so this')
        lines.append('  notice carries the header and not the full texts.')
    return lines


def codicon_note(root):
    """Report only what a file on disk states about the codicon font."""
    lines = []
    font_stated = False
    if os.path.isfile(os.path.join(root, CODICON_FONT)):
        lines.append('Codicon font present: %s' % CODICON_FONT)
    else:
        lines.append('Codicon font not present under gui/node_modules (%s).' % CODICON_FONT)
    for rel in (CODICON_CSS, CODICON_JS):
        p = os.path.join(root, rel)
        if not os.path.isfile(p):
            continue
        head = read_text(p).split('\n')[:10]
        for h in head:
            if re.search(r'licen', h, re.I):
                lines.append('%s header: %s' % (os.path.basename(rel), h.strip(' *').strip()))
    for rel in (MONACO_DIR + '/ThirdPartyNotices.txt', MONACO_DIR + '/LICENSE'):
        p = os.path.join(root, rel)
        if not os.path.isfile(p):
            continue
        for ln in read_text(p).split('\n'):
            if 'codicon' in ln.lower():
                font_stated = True
                lines.append('%s names codicon: %s' % (os.path.basename(rel), ln.strip()[:200]))
    if not font_stated:
        lines.append('monaco-editor states no licence for the font itself. Its upstream does:')
        for name in ('SOURCE.txt', 'LICENSE', 'LICENSE-CODE'):
            lines.append('')
            lines.extend(read_text(os.path.join(root, 'tools', 'licences', 'codicon', name)).split('\n'))
    return lines


def build(root, skip_rust, skip_js, target=None):
    problems, first_party, counts, notes = [], [], [], []
    rust = rust_packages(root, skip_rust, problems, first_party, counts, target)
    js = js_packages(root, skip_js, problems)
    if not skip_js:
        notes = dompurify_note(root, problems)
        codicon = codicon_note(root)
    else:
        codicon = []
    used = set()
    for r in rust + js:
        if r['exception']:
            used.add(r['label'])
    # Only the Rust graphs were read in full; a --skip-js run cannot prove a JS-side
    # exception is unused, and a --skip-rust run cannot prove a Rust one is.
    checked = not skip_rust and not skip_js and not target
    stale = sorted(set(KNOWN_EXCEPTIONS) - used) if checked else []
    return {'problems': problems, 'rust': rust, 'js': js, 'first_party': first_party,
            'counts': counts, 'dompurify': notes, 'codicon': codicon, 'stale': stale}


def render(b):
    texts = {}  # tag -> (file name, text, [labels])
    def tag_for(name, text, label):
        t = 't-' + hashlib.sha256(text.encode('utf-8')).hexdigest()[:12]
        if t not in texts:
            texts[t] = (name, text, [])
        texts[t][2].append(label)
        return t

    out = ['THIRD-PARTY NOTICES',
           '',
           'Third-party software distributed with this binary, generated by tools/third-party-notices.py',
           'from the Cargo dependency graphs (repository root and gui/src-tauri) and the production',
           'dependencies under gui/node_modules. Licence texts are printed once each in section 5.',
           '']

    def section(title):
        out.append('=' * 72)
        out.append(title)
        out.append('=' * 72)

    def package_block(r):
        out.append(r['label'])
        out.append('    licence: %s' % (r['expr'] or '(none declared)'))
        if r.get('used_by'):
            out.append('    used by: %s' % ', '.join(r['used_by']))
        if r['files']:
            refs = ['%s [%s]' % (n, tag_for(n, t, r['label'])) for n, t in r['files']]
            out.append('    licence text: ' + '; '.join(refs))
        if r.get('source'):
            out.append('    licence text source: ' + r['source'])
        if r['exception']:
            out.append('    licence text: none shipped; exception: %s' % r['exception'])
        out.append('')

    section('1. RUST CRATES (%d, registry)' % sum(1 for r in b['rust']))
    out.append('')
    for r in b['rust']:
        package_block(r)

    section('2. FIRST-PARTY RUST CRATES (path dependencies in this repository)')
    out.append('These are the repository\'s own crates. They are covered by the repository LICENSE,')
    out.append('not listed as third-party.')
    out.append('')
    for label, expr in b['first_party']:
        out.append('%s  (%s)' % (label, expr))
    out.append('')

    section('3. JAVASCRIPT PACKAGES (%d, gui/node_modules, dependencies only)' % len(b['js']))
    out.append('')
    for r in b['js']:
        package_block(r)

    section('4. VENDORED INSIDE monaco-editor')
    out.append('')
    for ln in b['dompurify']:
        out.append(ln)
    out.append('')
    for ln in b['codicon']:
        out.append(ln)
    out.append('')

    section('5. LICENCE TEXTS (each distinct text once)')
    out.append('')
    for t in sorted(texts):
        name, text, labels = texts[t]
        out.append('--- [%s] %s  (referenced by %d package file(s))' % (t, name, len(labels)))
        out.append('')
        out.append(text)
        out.append('')
    return '\n'.join(out) + '\n'


def main(argv=None):
    ap = argparse.ArgumentParser(description='Generate third-party notices for the binary release.')
    ap.add_argument('output', nargs='?', help='write the notices to this path instead of stdout')
    ap.add_argument('--root', default='.', help='repository root (default: the current directory)')
    ap.add_argument('--target', help='limit the Rust graphs to this platform, e.g. x86_64-pc-windows-msvc')
    ap.add_argument('--skip-rust', action='store_true',
                    help='calibration aid: leave out the cargo graphs; a release notice needs both halves')
    ap.add_argument('--skip-js', action='store_true',
                    help='calibration aid: leave out gui/node_modules; a release notice needs both halves')
    args = ap.parse_args(argv)
    root = os.path.abspath(args.root)

    try:
        b = build(root, args.skip_rust, args.skip_js, args.target)
    except Tooling as e:
        print('third-party-notices: cannot run: %s' % e, file=sys.stderr)
        return 2

    for line in b['counts']:
        print('count: ' + line, file=sys.stderr)
    print('count: %d registry crates and %d JavaScript packages in the notice; %d first-party path crates skipped'
          % (len(b['rust']), len(b['js']), len(b['first_party'])), file=sys.stderr)
    for label in b['stale']:
        print('warning: KNOWN_EXCEPTIONS entry %s matches no package in this build (stale)' % label, file=sys.stderr)
    if b['problems']:
        print('third-party-notices: %d package(s) cannot be noticed; no notices written:' % len(b['problems']),
              file=sys.stderr)
        for kind, label, detail in b['problems']:
            print('  %s: %s -- %s' % (kind, label, detail), file=sys.stderr)
        return 1

    text = render(b)
    if args.output:
        with open(args.output, 'w', encoding='utf-8', newline='\n') as f:
            f.write(text)
        print('third-party-notices: wrote %s (%d bytes)' % (args.output, len(text.encode('utf-8'))), file=sys.stderr)
    else:
        sys.stdout.buffer.write(text.encode('utf-8'))
    return 0


if __name__ == '__main__':
    sys.exit(main())
