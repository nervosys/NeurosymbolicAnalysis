//! Output parsers for external tools.
//!
//! Every parser here is written to *skip what it cannot understand and keep
//! going*, and to report the fact rather than failing the run. A tool that
//! changes its output format between versions should cost you some findings, not
//! the whole analysis.

use crate::finding;
use sda_core::verification::{Boundary, ObligationStatus, ProofObligation};
use sda_core::{Evidence, Finding, Location, Severity, TaxonomyRef, TraceFrame};
use serde_json::Value;

/// A start position, clamped to the 1-based origin every consumer assumes.
fn at(file: &str, line: u32, column: u32) -> Location {
    Location::new(file, line.max(1), column.max(1))
}

/// Attach an end position, but only when it is one.
///
/// A tool that repeats the start as the end, or states an end before it, has
/// given no extent — and a zero-width or inverted span renders worse than none,
/// which is why the native analyzers guard the same way.
fn spanned(loc: Location, end_line: Option<u32>, end_column: Option<u32>) -> Location {
    let (Some(el), Some(ec)) = (end_line, end_column) else { return loc };
    if (el, ec) > (loc.line, loc.column) { loc.spanning(el, ec) } else { loc }
}

/// SARIF 2.1.0, which Semgrep, CodeQL and several others emit natively.
pub fn parse_sarif(text: &str, provider: &str) -> Result<Vec<Finding>, String> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("output is not valid SARIF JSON: {e}"))?;
    let mut out = Vec::new();

    let Some(runs) = v.get("runs").and_then(|r| r.as_array()) else {
        return Err("SARIF output has no `runs` array".into());
    };

    for run in runs {
        // Rule metadata is indexed separately from results.
        let rules: Vec<&serde_json::Value> = run
            .pointer("/tool/driver/rules")
            .and_then(|r| r.as_array())
            .map(|a| a.iter().collect())
            .unwrap_or_default();

        for result in run.get("results").and_then(|r| r.as_array()).into_iter().flatten() {
            let rule_id = result
                .get("ruleId")
                .and_then(|r| r.as_str())
                .map(|s| s.to_string())
                .or_else(|| {
                    result
                        .get("ruleIndex")
                        .and_then(|i| i.as_u64())
                        .and_then(|i| rules.get(i as usize))
                        .and_then(|r| r.get("id"))
                        .and_then(|r| r.as_str())
                        .map(|s| s.to_string())
                })
                .unwrap_or_else(|| "unknown".to_string());

            let message = result
                .pointer("/message/text")
                .and_then(|m| m.as_str())
                .unwrap_or("(no message)")
                .to_string();

            // The rule this result cites, by index or by id. Real Semgrep emits
            // `ruleId` and no `ruleIndex`, so an index-only lookup finds nothing
            // and every rule's metadata is lost.
            let rule = result
                .get("ruleIndex")
                .and_then(|i| i.as_u64())
                .and_then(|i| rules.get(i as usize).copied())
                .or_else(|| {
                    rules.iter().copied().find(|r| {
                        r.get("id").and_then(|i| i.as_str()) == Some(rule_id.as_str())
                    })
                });

            // SARIF makes `level` optional and says it then comes from the
            // rule's `defaultConfiguration`. This used to say exactly that in a
            // comment and then default to Medium anyway — so every real Semgrep
            // finding arrived as Medium, and an `error` rule was indistinguishable
            // from a `note`. Semgrep omits `level` on every result it emits.
            let level = result
                .get("level")
                .and_then(|l| l.as_str())
                .or_else(|| rule?.pointer("/defaultConfiguration/level")?.as_str());
            let severity = match level {
                Some("error") => Severity::High,
                Some("warning") => Severity::Medium,
                Some("note") => Severity::Low,
                Some("none") => Severity::Info,
                // Neither the result nor the rule said. "warning" is the safe
                // reading, and it is now a genuine absence rather than a lookup
                // nobody performed.
                _ => Severity::Medium,
            };

            let loc = result.pointer("/locations/0/physicalLocation");
            let file = loc
                .and_then(|l| l.pointer("/artifactLocation/uri"))
                .and_then(|u| u.as_str())
                .unwrap_or("")
                .to_string();
            let line = loc
                .and_then(|l| l.pointer("/region/startLine"))
                .and_then(|n| n.as_u64())
                .unwrap_or(1) as u32;
            let col = loc
                .and_then(|l| l.pointer("/region/startColumn"))
                .and_then(|n| n.as_u64())
                .unwrap_or(1) as u32;
            // SARIF states the extent of the offending construct, and most
            // producers fill it in. Reading only the start turned every result
            // into a point and left the editor underlining to end-of-line.
            // `endLine` defaults to `startLine` when omitted, per the spec.
            let region = loc.and_then(|l| l.pointer("/region"));
            let end_col =
                region.and_then(|r| r.get("endColumn")).and_then(|n| n.as_u64()).map(|n| n as u32);
            let end_line = region
                .and_then(|r| r.get("endLine"))
                .and_then(|n| n.as_u64())
                .map(|n| n as u32)
                .or(end_col.map(|_| line));

            if file.is_empty() {
                continue; // a result with no location cannot be acted on
            }
            let mut f = finding(
                provider,
                &rule_id,
                &message,
                severity,
                spanned(at(&file, line, col), end_line, end_col),
            );
            // Semgrep states the CWE in the rule's `properties.tags`, as
            // "CWE-78: Improper Neutralization of ...". Dropping it is the same
            // defect already fixed for Cppcheck: correlation matches a runtime
            // witness to a static finding through the CWE, so without one no
            // Semgrep finding could ever be *confirmed*, however good the
            // evidence. SARIF has no dedicated field for this, and the tag form
            // is what real producers use.
            if let Some(cwe) = rule.and_then(cwe_from_tags) {
                f = f.taxonomy(TaxonomyRef::cwe(cwe));
            }
            // The path, where the producer supplies one. `sda_engine::interposition`
            // refutes an interposition proof from a *flow* and cannot use an
            // endpoint, so a finding without this is a finding it must skip.
            for trace in code_flow_traces(result) {
                f = f.evidence(trace);
            }
            out.push(f);
        }
    }
    Ok(out)
}

/// Every dataflow path a SARIF result reports, each as an [`Evidence::Trace`].
///
/// **All of them, not the first.** This used to read `codeFlows[0]` and say so,
/// reasoning that additional flows are alternative routes to one sink and that a
/// consumer needing every route needs the SARIF. That is fine for rendering and
/// wrong for refutation, which is what the traces are actually for: interposition
/// fails if *any* route reaches the effector without crossing a guard, so keeping
/// one route makes the answer depend on the order the producer happened to emit
/// them. A real `cpp/command-line-injection` result over
/// `tools/codeql-taint-cpp/` carries three code flows — the first through the
/// guard, the second the bypass — so the parser handed the engine the guarded
/// route and the proof stood, while the tool had reported the counterexample in
/// the same result. The Python capture has exactly one code flow, which is why
/// this could not surface there.
///
/// SARIF nests this three deep — `codeFlows[].threadFlows[].locations[]` — and
/// each entry wraps the position one level further in, under `location`. Real
/// CodeQL 2.26.4 fills all of it: a `py/command-line-injection` result carries
/// one `codeFlow` with one `threadFlow` of seven steps, running
/// `request` → `raw` → `settled` → `forwarded` → the argument of `os.system`.
///
/// **Most producers supply none of it.** Semgrep OSS 1.176.0 emits no
/// `codeFlows` at all, `--dataflow-traces` notwithstanding, and the fixture that
/// used to stand for CodeQL here contained none either — so this code path had
/// nothing to exercise it until a real taint run was captured. Returning `None`
/// rather than an empty trace keeps that distinction: a finding with no path is
/// not a finding whose path is empty.
///
/// Only the first thread flow is read. Additional ones are alternative routes to
/// the same sink, and a consumer that needs every route needs the SARIF, not a
/// flattened list — so taking the first and saying so beats concatenating them
/// into a path the program never takes.
fn code_flow_traces(result: &serde_json::Value) -> Vec<Evidence> {
    let Some(flows) = result.get("codeFlows").and_then(|c| c.as_array()) else {
        return Vec::new();
    };
    flows.iter().filter_map(one_flow).collect()
}

/// One `codeFlow`'s first thread flow, as a trace.
///
/// Only the first *thread* flow is read. Thread flows within one code flow are
/// concurrent strands of a single path, and flattening several into one ordered
/// list would describe a route the program never takes.
fn one_flow(flow: &serde_json::Value) -> Option<Evidence> {
    let locations = flow
        .get("threadFlows")?
        .as_array()?
        .first()?
        .get("locations")?
        .as_array()?;

    let mut frames = Vec::new();
    for (step, entry) in locations.iter().enumerate() {
        let location = entry.get("location")?;
        let physical = location.get("physicalLocation")?;
        let file = physical.pointer("/artifactLocation/uri")?.as_str()?;
        let line =
            physical.pointer("/region/startLine").and_then(|n| n.as_u64()).unwrap_or(1) as u32;
        let column =
            physical.pointer("/region/startColumn").and_then(|n| n.as_u64()).unwrap_or(1) as u32;
        // CodeQL's step messages are internal node descriptions —
        // "ControlFlowNode for raw" — not prose written for a reader. Kept
        // verbatim anyway: a mechanical label from the tool is worth more than a
        // sentence invented here, and it is what a maintainer will grep for.
        let note = location
            .pointer("/message/text")
            .and_then(|t| t.as_str())
            .unwrap_or("dataflow step")
            .to_string();
        frames.push(sda_core::TraceFrame {
            location: at(file, line, column),
            note,
            step: step as u32,
        });
    }
    // One frame is an endpoint, not a path, and cannot say what it crossed.
    (frames.len() >= 2).then_some(Evidence::Trace { frames })
}

/// The first CWE number in a SARIF rule's `properties.tags`.
///
/// Tags are free-form strings and there is no convention, only conventions.
/// Two are recognised, because two are what real producers write:
///
/// * `CWE-78: Improper Neutralization of ...` — Semgrep.
/// * `external/cwe/cwe-078` — CodeQL, lowercase and zero-padded.
///
/// The second was not recognised until CodeQL 2.26.4 was actually run. That is
/// not a cosmetic gap: correlation matches a runtime witness to a static finding
/// *through the CWE*, so no real CodeQL finding could ever have been
/// **confirmed**, however good the evidence — the identical defect this function
/// already carried a comment about for Cppcheck and Semgrep.
///
/// A tag merely *mentioning* a CWE in prose still does not become a taxonomy
/// claim: the number must follow one of the two prefixes immediately.
fn cwe_from_tags(rule: &serde_json::Value) -> Option<u32> {
    rule.pointer("/properties/tags")?
        .as_array()?
        .iter()
        .filter_map(|t| t.as_str())
        .find_map(cwe_from_tag)
}

/// One tag, in either of the forms real producers use.
fn cwe_from_tag(tag: &str) -> Option<u32> {
    let digits = tag.strip_prefix("CWE-").or_else(|| {
        // `external/cwe/cwe-078`, and the same shape under any namespace prefix.
        let (_, last) = tag.rsplit_once('/')?;
        last.strip_prefix("cwe-")
    })?;
    let n: String = digits.chars().take_while(char::is_ascii_digit).collect();
    // Parsing strips CodeQL's zero padding, so `cwe-078` and `CWE-78` agree.
    n.parse().ok()
}

/// Cppcheck's `--xml --xml-version=2` output.
///
/// Parsed with a small scanner rather than an XML library: the schema is tiny
/// and stable, and a dependency for four attributes is not worth its weight.
pub fn parse_cppcheck_xml(text: &str, provider: &str) -> Result<Vec<Finding>, String> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    if !text.contains("<results") && !text.contains("<error") {
        return Err("output does not look like Cppcheck XML".into());
    }

    let mut out = Vec::new();
    let mut rest = text;

    while let Some(start) = rest.find("<error ") {
        rest = &rest[start..];
        let end = match rest.find("</error>").or_else(|| rest.find("/>")) {
            Some(e) => e,
            None => break,
        };
        let block = &rest[..end];

        let id = attr(block, "id").unwrap_or_else(|| "unknown".into());
        let msg = attr(block, "verbose").or_else(|| attr(block, "msg")).unwrap_or_default();
        let severity = match attr(block, "severity").as_deref() {
            Some("error") => Severity::High,
            Some("warning") => Severity::Medium,
            Some("performance") | Some("portability") => Severity::Low,
            Some("style") | Some("information") => Severity::Info,
            _ => Severity::Medium,
        };
        // The `<location>` child carries the position. Real cppcheck also emits
        // entries with no `<location>` at all — `checkersReport` ("Active
        // checkers: 113/186") is one on every run — and those are metadata, not
        // findings. `file0` names the translation unit and is present on real
        // errors even when a location is not, so it is tried before giving up:
        // an `information`-severity entry with neither is chatter, but a real
        // error with neither would be a finding this adapter silently ate.
        let file = attr(block, "file")
            .filter(|f| !f.is_empty())
            .or_else(|| attr(block, "file0"))
            .unwrap_or_default();
        let line = attr(block, "line").and_then(|l| l.parse().ok()).unwrap_or(1);
        let column = attr(block, "column").and_then(|c| c.parse().ok()).unwrap_or(1);

        if !file.is_empty() {
            // Cppcheck's XML states no end position, so this stays a point.
            let mut f =
                finding(provider, &id, &unescape_xml(&msg), severity, at(&file, line, column));
            // Cppcheck states a CWE for most checks, and correlation matches a
            // runtime witness to a static finding through exactly this. Dropping
            // it meant no external finding could ever be *confirmed* by runtime
            // evidence, however good the evidence was.
            if let Some(cwe) = attr(block, "cwe").and_then(|c| c.trim().parse::<u32>().ok()) {
                f = f.taxonomy(TaxonomyRef::cwe(cwe));
            }
            out.push(f);
        }
        rest = &rest[end + 1..];
    }
    Ok(out)
}

fn attr(block: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let start = block.find(&needle)? + needle.len();
    let end = block[start..].find('"')? + start;
    Some(block[start..end].to_string())
}

fn unescape_xml(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

/// `cargo clippy --message-format=json`, which is also what `cargo miri` emits.
pub fn parse_clippy_json(text: &str, provider: &str) -> Result<Vec<Finding>, String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue; // cargo interleaves non-diagnostic messages
        };
        // Cargo wraps rustc's diagnostic in a `message` field.
        let Some(msg) = v.get("message").filter(|m| m.is_object()) else {
            continue;
        };
        let level = msg.get("level").and_then(|l| l.as_str()).unwrap_or("");
        let severity = match level {
            "error" => Severity::High,
            "warning" => Severity::Medium,
            "note" | "help" => Severity::Info,
            _ => continue,
        };
        let rule = msg
            .pointer("/code/code")
            .and_then(|c| c.as_str())
            .unwrap_or(level)
            .to_string();
        let text_msg = msg.get("message").and_then(|m| m.as_str()).unwrap_or("").to_string();

        let Some(span) = msg
            .get("spans")
            .and_then(|s| s.as_array())
            .and_then(|a| {
                a.iter()
                    .find(|s| s.get("is_primary").and_then(|p| p.as_bool()) == Some(true))
                    .or_else(|| a.first())
            })
        else {
            continue;
        };

        let file = span.get("file_name").and_then(|f| f.as_str()).unwrap_or("").to_string();
        if file.is_empty() {
            continue;
        }
        let line_no = span.get("line_start").and_then(|l| l.as_u64()).unwrap_or(1) as u32;
        let col = span.get("column_start").and_then(|c| c.as_u64()).unwrap_or(1) as u32;
        // rustc always brackets the construct it is complaining about; the end
        // sits in the same span object and was being read past.
        let end_line = span.get("line_end").and_then(|l| l.as_u64()).map(|n| n as u32);
        let end_col = span.get("column_end").and_then(|c| c.as_u64()).map(|n| n as u32);

        out.push(finding(
            provider,
            &rule,
            &text_msg,
            severity,
            spanned(at(&file, line_no, col), end_line, end_col),
        ));
    }
    Ok(out)
}

/// `file:line:col: level: message`, emitted by clang-tidy and many others.
pub fn parse_gcc_like(text: &str, provider: &str) -> Result<Vec<Finding>, String> {
    let mut out: Vec<Finding> = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        let Some((file, line_no, col, rest)) = split_position(l) else { continue };
        let Some((level, message)) = rest.split_once(':') else { continue };
        let severity = match level.trim() {
            "error" | "fatal error" => Severity::High,
            "warning" => Severity::Medium,
            "note" | "remark" => Severity::Info,
            _ => continue,
        };
        let message = message.trim();

        // A `note:` is not a diagnostic. GCC and Clang emit it only as a
        // continuation of the one above — the call frame, the "declared here",
        // the macro expansion trail — and it belongs to that finding as
        // evidence.
        //
        // Treated as findings they did two kinds of harm at once. clang-tidy over
        // 184 files of llama.cpp produced 307 of them, 4% of the report, each
        // with the rule id `note`, which is not a rule; and the trail they carry
        // was *detached from the diagnostic it explains*, so a
        // `bugprone-exception-escape` lost its frames while seven separate
        // "findings" appeared in MSVC's `<map>`. Throwing evidence away on the
        // way to the user is the failure this codebase keeps a table of.
        //
        // `remark` is deliberately not included: `-Rpass` remarks stand alone.
        //
        // A note with nothing above it is dropped. It makes no claim by itself —
        // it is the second half of a sentence whose first half is not here — and
        // there is nothing for it to be evidence of.
        if level.trim() == "note" {
            if let Some(last) = out.last_mut() {
                last.evidence.push(Evidence::note(format!(
                    "{file}:{line_no}:{col}: {message}"
                )));
            }
            continue;
        }
        // clang-tidy appends `[check-name]`, and `[check-name,alias,…]` when the
        // check is reachable under more than one name. The bracket is required
        // to hold check names and nothing else — a prose message ending in
        // "[see above]" is a message, not a rule id.
        let bracket = match (message.rfind('['), message.ends_with(']')) {
            (Some(i), true) => {
                let inner = &message[i + 1..message.len() - 1];
                (!inner.is_empty() && !inner.contains(char::is_whitespace)).then_some((i, inner))
            }
            _ => None,
        };
        let (message, rule, aliases) = match bracket {
            Some((i, inner)) => {
                let mut names = inner.split(',').filter(|n| !n.is_empty());
                let rule = names.next().unwrap_or(inner).to_string();
                (message[..i].trim().to_string(), rule, names.collect::<Vec<_>>())
            }
            None => (message.to_string(), level.trim().to_string(), Vec::new()),
        };

        // GCC-style output states one position and no extent.
        let mut f = finding(provider, &rule, &message, severity, at(&file, line_no, col));
        // The aliases are where the compliance value is. `cert-err34-c` is not a
        // second finding — clang-tidy reports the diagnostic once and lists both
        // names — but it is the CERT rule the finding satisfies, and dropping it
        // is the same mistake that once left every external finding with no CWE
        // for the correlation engine to match on.
        for alias in aliases {
            if let Some(id) = cert_rule_id(alias) {
                f = f.taxonomy(TaxonomyRef::new(sda_core::Taxonomy::Cert, id));
            }
        }
        out.push(f);
    }
    Ok(out)
}

/// ModelScan's own JSON, as `--reporting-format json` emits it.
///
/// The shape is an `issues` array; a model artifact has no line numbers, so
/// every issue is located at the file it was found in:
///
/// ```json
/// {"summary": {...},
///  "issues": [{"description": "Use of unsafe operator 'system' from module 'posix'",
///              "operator": "system", "module": "posix", "source": "model.pkl",
///              "scanner": "modelscan.scanners.PickleUnsafeOpScan",
///              "severity": "CRITICAL"}],
///  "errors": []}
/// ```
///
/// `errors` matters as much as `issues`: a file ModelScan could not read is not
/// a file it found nothing in, and reporting only the issues would turn "we
/// could not look" into "we looked and it was fine".
///
/// Written from ModelScan's documented schema; the tool is not installed here,
/// so the field names are unverified against a real run.
/// Miri's diagnostics, as the interpreter writes them to **stderr**.
///
/// The spec used to declare [`OutputFormat::ClippyJson`] on stdout, because
/// `cargo miri test --message-format=json` looks like `cargo clippy
/// --message-format=json` and the fixture was a reconstruction that assumed so.
/// It is wrong, and the adapter could not have reported a single real Miri
/// finding. `--message-format=json` governs *cargo's build* messages; Miri's
/// undefined-behaviour report is produced at **run** time, by the interpreter
/// executing the test binary, and it goes to stderr as ordinary rustc prose. A
/// real run over a stacked-borrows violation writes three JSON lines to stdout —
/// two `compiler-artifact` and one `build-finished`, with `"success":true` — and
/// not one `compiler-message`. The tool reports UB; the stream the adapter read
/// reports that the build went fine.
///
/// The shape, which is rustc's and not GCC's — the location is on the line
/// *after* the message, so `parse_gcc_like` matches none of it either:
///
/// ```text
/// error: Undefined Behavior: attempting a read access using <142242> at alloc46271[0x0], ...
///   --> src\lib.rs:11:9
///    |
/// 11 |         *r1
///    |         ^^^ this error occurs as part of an access at alloc46271[0x0..0x1]
///    |
///    = help: this indicates a potential bug in the program: ...
/// help: <142242> was created by a SharedReadWrite retag at offsets [0x0..0x1]
///   --> src\lib.rs:6:14
/// help: <142242> was later invalidated at offsets [0x0..0x1] by a Unique retag
///   --> src\lib.rs:7:14
/// ```
///
/// The `help:` blocks are the interesting part and are kept as a
/// [`Evidence::Trace`]: for an aliasing violation, *where the pointer was created
/// and where it was invalidated* is the whole explanation, and dropping it leaves
/// a finding that names the read and cannot say why the read is wrong. They are
/// emphatically not separate findings — three lines of one diagnostic reported as
/// three defects would be the miscount `run::analyze` already dedupes for.
///
/// **A record with no `-->` is not a finding.** Cargo writes `error: test failed,
/// to rerun pass --lib` and `error: aborting due to 1 previous error` to the same
/// stream; both are true statements about the process and neither is a defect in
/// the code. Requiring a location is what separates them, and it is the tool's
/// own distinction rather than a list of strings to ignore.
///
/// No CWE is attached. Miri states none, and inventing one would be the
/// overclaiming this codebase refuses; the dynamic path already labels an
/// unclassified external witness `SanitizerReport`, whose related classes include
/// CWE-758, *reliance on undefined behaviour* — which is precisely what Miri
/// found.
pub fn parse_miri(text: &str, provider: &str) -> Result<Vec<Finding>, String> {
    /// The `  --> file:line:col` line rustc puts under a message.
    fn arrow(line: &str) -> Option<(String, u32, u32)> {
        let rest = line.trim().strip_prefix("--> ")?.trim();
        // Split from the right: a Windows path carries a drive colon, and the
        // last two colon-separated fields are the position.
        let (head, col) = rest.rsplit_once(':')?;
        let (file, line_no) = head.rsplit_once(':')?;
        Some((file.replace('\\', "/"), line_no.parse().ok()?, col.parse().ok()?))
    }

    let mut out: Vec<Finding> = Vec::new();
    let mut current: Option<(String, Severity, String)> = None; // rule, severity, message
    let mut location: Option<Location> = None;
    let mut frames: Vec<TraceFrame> = Vec::new();
    let mut pending_help: Option<String> = None;

    // `flush` is a closure over nothing, so it is a fn taking the state: the
    // record is finished by the *next* record starting or by the end of the
    // stream, and both paths must build it identically.
    fn flush(
        out: &mut Vec<Finding>,
        provider: &str,
        current: Option<(String, Severity, String)>,
        location: Option<Location>,
        frames: Vec<TraceFrame>,
    ) {
        let (Some((rule, severity, message)), Some(loc)) = (current, location) else { return };
        let mut f = finding(provider, &rule, &message, severity, loc);
        if frames.len() >= 2 {
            f = f.evidence(Evidence::Trace { frames });
        }
        out.push(f);
    }

    for raw in text.lines() {
        let line = raw.trim_end();
        let trimmed = line.trim_start();

        // A new diagnostic starts here, so the previous one is complete.
        let starts = trimmed.strip_prefix("error: ").map(|m| (Severity::High, m))
            .or_else(|| trimmed.strip_prefix("warning: ").map(|m| (Severity::Medium, m)))
            // `error[E0080]: ...` — Miri reports const-eval failures this way.
            .or_else(|| {
                let rest = trimmed.strip_prefix("error[")?;
                let (_code, m) = rest.split_once("]: ")?;
                Some((Severity::High, m))
            });

        if (line.starts_with("error") || line.starts_with("warning: "))
            && let Some((severity, message)) = starts {
                flush(&mut out, provider, current.take(), location.take(), std::mem::take(&mut frames));
                pending_help = None;
                // The rule is the category Miri names before the colon —
                // `Undefined Behavior`, `memory leaked` — because that is the
                // classification the tool itself made. Where it names none, the
                // whole message is the rule rather than a code invented here.
                let rule = match message.split_once(": ") {
                    Some((head, _)) if head.len() <= 40 => head.to_string(),
                    _ => "miri".to_string(),
                };
                current = Some((rule, severity, message.trim().to_string()));
                continue;
            }

        if trimmed.starts_with("help: ") {
            pending_help = Some(trimmed.trim_start_matches("help: ").to_string());
            continue;
        }

        if let Some((file, line_no, col)) = arrow(line) {
            let loc = at(&file, line_no, col);
            match (&location, pending_help.take()) {
                // The first arrow is the diagnostic's own location.
                (None, _) => {
                    frames.push(TraceFrame {
                        location: loc.clone(),
                        note: current.as_ref().map(|c| c.2.clone()).unwrap_or_default(),
                        step: 0,
                    });
                    location = Some(loc);
                }
                // Later arrows belong to the `help:` line above them.
                (Some(_), Some(note)) => {
                    let step = frames.len() as u32;
                    frames.push(TraceFrame { location: loc, note, step });
                }
                (Some(_), None) => {}
            }
        }
    }
    flush(&mut out, provider, current, location, frames);
    Ok(out)
}

pub fn parse_modelscan_json(text: &str, provider: &str) -> Result<Vec<Finding>, String> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let v: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| format!("output is not valid ModelScan JSON: {e}"))?;

    // A SARIF document would parse as JSON but has no `issues`; saying so names
    // the real problem rather than reporting an empty scan.
    if v.get("issues").is_none() && v.get("errors").is_none() {
        return Err("ModelScan JSON has neither an `issues` nor an `errors` key; \
                    this does not look like `modelscan --reporting-format json` output"
            .into());
    }

    let mut out = Vec::new();

    for issue in v.get("issues").and_then(|i| i.as_array()).into_iter().flatten() {
        let description =
            issue.get("description").and_then(|d| d.as_str()).unwrap_or("(no description)");
        let source = issue.get("source").and_then(|s| s.as_str()).unwrap_or("");
        if source.is_empty() {
            continue; // an issue with no artifact cannot be acted on
        }
        // The scanner is the closest thing ModelScan has to a rule id; the
        // operator is what actually distinguishes one issue from another.
        let scanner = issue
            .get("scanner")
            .and_then(|s| s.as_str())
            .unwrap_or("modelscan")
            .rsplit('.')
            .next()
            .unwrap_or("modelscan");
        let rule = match issue.get("operator").and_then(|o| o.as_str()) {
            Some(op) if !op.is_empty() => format!("MODELSCAN-{scanner}-{op}"),
            _ => format!("MODELSCAN-{scanner}"),
        };
        let severity = match issue
            .get("severity")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_ascii_uppercase()
            .as_str()
        {
            "CRITICAL" => Severity::Critical,
            "HIGH" => Severity::High,
            "MEDIUM" => Severity::Medium,
            "LOW" => Severity::Low,
            // An unrecognised severity is not an absent one. Defaulting to the
            // bottom would quietly hide a level ModelScan later adds.
            _ => Severity::Medium,
        };

        let mut f = finding(provider, &rule, description, severity, at(source, 1, 1));
        // Arbitrary code reached through deserialization of untrusted data.
        f = f.taxonomy(TaxonomyRef::cwe(502));
        out.push(f);
    }

    // A file ModelScan failed on is a gap in coverage, not a clean file.
    for err in v.get("errors").and_then(|e| e.as_array()).into_iter().flatten() {
        let source = err
            .get("source")
            .and_then(|s| s.as_str())
            .or_else(|| err.get("path").and_then(|s| s.as_str()))
            .unwrap_or("");
        if source.is_empty() {
            continue;
        }
        let detail = err
            .get("description")
            .and_then(|d| d.as_str())
            .or_else(|| err.get("message").and_then(|d| d.as_str()))
            .unwrap_or("(no detail)");
        out.push(finding(
            provider,
            "MODELSCAN-NOT-SCANNED",
            &format!(
                "ModelScan could not scan this artifact, so nothing is established about it: \
                 {detail}"
            ),
            Severity::Info,
            at(source, 1, 1),
        ));
    }

    Ok(out)
}

/// Valgrind's `==pid==` text, as Memcheck writes it to stderr.
///
/// The shape is a description line, then indented stack frames:
///
/// ```text
/// ==12345== Invalid write of size 4
/// ==12345==    at 0x1091A9: main (main.c:7)
/// ==12345==  Address 0x4a9c04c is 0 bytes after a block of size 40 alloc'd
/// ```
///
/// The location is taken from the first frame that names a source file, which
/// is the frame in the user's own code rather than in Valgrind's `malloc`
/// interceptor — reporting `vg_replace_malloc.c` would point every allocation
/// error at Valgrind's own source.
///
/// Frames with no `(file:line)` are normal — Valgrind prints `(in /path/a.out)`
/// for a binary built without `-g`. A record where *no* frame carries a position
/// is dropped, because a finding needs somewhere to point; if that is every
/// record, the parse returns nothing, the tool's non-zero exit trips the
/// "produced no findings, so this establishes nothing" guard, and the run says
/// so rather than reading as clean. **Build the target with `-g` or this adapter
/// has nothing to place.**
pub fn parse_valgrind(text: &str, provider: &str) -> Result<Vec<Finding>, String> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }

    /// A record being accumulated: its description, and the best position seen.
    struct Record {
        message: String,
        severity: Severity,
        /// The first frame in the program's own code.
        own: Option<(String, u32)>,
        /// The first positioned frame of any kind, used when there is no other.
        any: Option<(String, u32)>,
    }

    let mut out = Vec::new();
    let mut current: Option<Record> = None;

    fn flush(cur: Option<Record>, provider: &str, out: &mut Vec<Finding>) {
        let Some(r) = cur else { return };
        let Some((file, line)) = r.own.or(r.any) else { return };
        let mut f =
            finding(provider, &valgrind_rule(&r.message), &r.message, r.severity, at(&file, line, 1));
        if let Some(cwe) = valgrind_cwe(&r.message) {
            f = f.taxonomy(TaxonomyRef::cwe(cwe));
        }
        out.push(f);
    }

    for raw in text.lines() {
        let Some(body) = strip_pid(raw) else { continue };
        if body.trim().is_empty() {
            // A blank line ends a record.
            flush(current.take(), provider, &mut out);
            continue;
        }

        // Every body carries one space after the marker, so indentation is
        // measured *past* it: a description is `== Invalid write`, a frame is
        // `==    at 0x…`, and a continuation like `==  Address 0x… is 0 bytes
        // after a block` sits between them. Treating the marker's own space as
        // indentation made every description look like a frame, and the parser
        // returned nothing at all for perfectly ordinary output.
        let body = body.strip_prefix(' ').unwrap_or(body);
        if body.starts_with(char::is_whitespace) {
            let t = body.trim_start();
            if (t.starts_with("at 0x") || t.starts_with("by 0x"))
                && let (Some(cur), Some(pos)) = (current.as_mut(), frame_position(t)) {
                    if cur.any.is_none() {
                        cur.any = Some(pos.clone());
                    }
                    if cur.own.is_none() && !is_valgrind_internal(&pos.0) {
                        cur.own = Some(pos);
                    }
                }
            continue;
        }

        // A new description line ends whatever came before it.
        flush(current.take(), provider, &mut out);
        if is_boilerplate(body) {
            continue;
        }
        let Some(severity) = valgrind_severity(body) else { continue };
        current = Some(Record {
            message: body.trim().to_string(),
            severity,
            own: None,
            any: None,
        });
    }
    flush(current.take(), provider, &mut out);

    Ok(out)
}

/// Strip a leading `==1234==` or `--1234--` marker, which every line carries.
///
/// Both markers appear in real output — `==` for Memcheck's own reporting and
/// `--` for tooling chatter — so each is tried in turn rather than the first
/// failure ending the search.
fn strip_pid(line: &str) -> Option<&str> {
    let l = line.trim_end();
    for marker in ['=', '-'] {
        let Some(rest) = l.strip_prefix(marker).and_then(|r| r.strip_prefix(marker)) else {
            continue;
        };
        let digits = rest.chars().take_while(|c| c.is_ascii_digit()).count();
        if digits == 0 {
            continue;
        }
        let after = &rest[digits..];
        if let Some(body) = after.strip_prefix(marker).and_then(|a| a.strip_prefix(marker)) {
            return Some(body);
        }
    }
    None
}

/// The `(file:line)` at the end of a stack frame.
fn frame_position(frame: &str) -> Option<(String, u32)> {
    let open = frame.rfind('(')?;
    let close = frame[open..].find(')')? + open;
    let inside = &frame[open + 1..close];
    // `main.c:7`, and `file.c:7` inside a path with its own colons on Windows.
    let colon = inside.rfind(':')?;
    let line: u32 = inside[colon + 1..].trim().parse().ok()?;
    let file = inside[..colon].trim();
    if file.is_empty() { None } else { Some((file.to_string(), line)) }
}

/// Valgrind's own interceptors, which are not the program's code.
fn is_valgrind_internal(file: &str) -> bool {
    file.starts_with("vg_replace_")
        || file.starts_with("vg_preloaded")
        || file == "valgrind.h"
        || file == "memcheck.h"
}

/// Banner and summary lines, which are not defects.
fn is_boilerplate(body: &str) -> bool {
    let t = body.trim();
    t.starts_with("Memcheck,")
        || t.starts_with("Copyright ")
        || t.starts_with("Using Valgrind")
        || t.starts_with("Command:")
        || t.starts_with("Parent PID:")
        || t.ends_with("SUMMARY:")
        || t.starts_with("For lists of")
        || t.starts_with("For counts of")
        || t.starts_with("total heap usage:")
        || t.starts_with("in use at exit:")
}

/// How bad the described defect is, or `None` if the line describes no defect.
///
/// `still reachable` is deliberately absent: it is not a leak, and reporting it
/// as one is the single loudest source of noise in Valgrind output.
fn valgrind_severity(body: &str) -> Option<Severity> {
    let t = body.trim();
    let lower = t.to_ascii_lowercase();
    if lower.starts_with("invalid write") || lower.starts_with("invalid read") {
        return Some(Severity::Critical);
    }
    if lower.starts_with("invalid free")
        || lower.starts_with("mismatched free")
        || lower.starts_with("double free")
        || lower.contains("jump to the invalid address")
    {
        return Some(Severity::Critical);
    }
    if lower.starts_with("use of uninitialised")
        || lower.contains("uninitialised value")
        || lower.contains("uninitialised byte")
    {
        return Some(Severity::High);
    }
    if lower.contains("definitely lost") || lower.contains("indirectly lost") {
        return Some(Severity::Medium);
    }
    if lower.contains("possibly lost") {
        return Some(Severity::Low);
    }
    if lower.contains("still reachable") {
        return None;
    }
    if lower.starts_with("syscall param") || lower.starts_with("source and destination overlap") {
        return Some(Severity::High);
    }
    None
}

/// A stable rule id, since Valgrind states a description and no code.
fn valgrind_rule(message: &str) -> String {
    let lower = message.to_ascii_lowercase();
    let slug = if lower.starts_with("invalid write") {
        "INVALID-WRITE"
    } else if lower.starts_with("invalid read") {
        "INVALID-READ"
    } else if lower.starts_with("invalid free") || lower.starts_with("double free") {
        "INVALID-FREE"
    } else if lower.starts_with("mismatched free") {
        "MISMATCHED-FREE"
    } else if lower.contains("uninitialis") {
        "UNINITIALISED"
    } else if lower.contains("definitely lost") || lower.contains("indirectly lost") {
        "LEAK"
    } else if lower.contains("possibly lost") {
        "LEAK-POSSIBLE"
    } else if lower.starts_with("syscall param") {
        "SYSCALL-PARAM"
    } else if lower.contains("overlap") {
        "OVERLAP"
    } else {
        "ERROR"
    };
    format!("VALGRIND-{slug}")
}

/// The CWE the defect maps to, so runtime evidence can confirm a static finding.
///
/// Correlation matches a witness to a static finding through the taxonomy; the
/// cppcheck adapter learned this the hard way, and a Valgrind finding with no
/// CWE would be equally unable to confirm anything.
fn valgrind_cwe(message: &str) -> Option<u32> {
    let lower = message.to_ascii_lowercase();
    if lower.starts_with("invalid write") {
        Some(787) // out-of-bounds write
    } else if lower.starts_with("invalid read") {
        Some(125) // out-of-bounds read
    } else if lower.starts_with("invalid free") || lower.starts_with("double free") {
        Some(415)
    } else if lower.starts_with("mismatched free") {
        Some(762)
    } else if lower.contains("uninitialis") {
        Some(457)
    } else if lower.contains("lost") {
        Some(401)
    } else {
        None
    }
}

/// The CERT rule id behind a `cert-*` clang-tidy check name, if it is one.
///
/// clang-tidy spells them lower-case and prefixed (`cert-err34-c`); CERT
/// publishes them upper-case and bare (`ERR34-C`). Only the ones that carry a
/// rule id are translated — `cert-*` also contains a handful of check names
/// that name no published rule, and inventing one would be worse than omitting
/// it.
fn cert_rule_id(check: &str) -> Option<String> {
    let rest = check.strip_prefix("cert-")?;
    // `err34-c`, `oop54-cpp`: three or four letters, digits, then the language.
    let (rule, lang) = rest.rsplit_once('-')?;
    if !matches!(lang, "c" | "cpp") {
        return None;
    }
    let (alpha, digits) = rule.split_at(rule.find(|c: char| c.is_ascii_digit())?);
    if alpha.is_empty() || !alpha.chars().all(|c| c.is_ascii_lowercase()) {
        return None;
    }
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some(format!("{}{}-{}", alpha.to_ascii_uppercase(), digits, lang.to_ascii_uppercase()))
}

/// Split `path:line:col:`, tolerating a Windows drive-letter colon.
fn split_position(l: &str) -> Option<(String, u32, u32, &str)> {
    let bytes = l.as_bytes();
    let mut colons = Vec::new();
    for (i, b) in bytes.iter().enumerate() {
        if *b == b':' {
            if i == 1 && bytes.first().is_some_and(|c| c.is_ascii_alphabetic()) {
                continue;
            }
            colons.push(i);
        }
        if colons.len() >= 3 {
            break;
        }
    }
    if colons.len() < 3 {
        return None;
    }
    let file = l[..colons[0]].to_string();
    let line: u32 = l[colons[0] + 1..colons[1]].trim().parse().ok()?;
    let col: u32 = l[colons[1] + 1..colons[2]].trim().parse().unwrap_or(1);
    Some((file, line, col, &l[colons[2] + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sarif_results_with_rule_and_location() {
        let sarif = r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep",
          "rules":[{"id":"c.lang.security.insecure-use-strcat"}]}},
          "results":[{"ruleIndex":0,"level":"error","message":{"text":"strcat is unbounded"},
          "locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/a.c"},
          "region":{"startLine":12,"startColumn":5}}}]}]}]}"#;
        let f = parse_sarif(sarif, "ext.semgrep").unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule.as_str(), "c.lang.security.insecure-use-strcat");
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].location.line, 12);
    }

    /// SARIF states the extent of the construct and most producers fill it in.
    /// Reading only `startLine`/`startColumn` flattened every external finding
    /// to a point, which the editor renders by underlining to end-of-line and
    /// SARIF re-export emits with no region end — information the tool had
    /// given us and we threw away between its output and ours.
    #[test]
    fn a_sarif_region_end_becomes_the_findings_extent() {
        let sarif = r#"{"runs":[{"results":[{"ruleId":"r","message":{"text":"m"},
          "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},
          "region":{"startLine":4,"startColumn":9,"endLine":4,"endColumn":21}}}]}]}]}"#;
        let f = parse_sarif(sarif, "p").unwrap();
        assert_eq!(f[0].location.end_line, Some(4));
        assert_eq!(f[0].location.end_column, Some(21));
    }

    /// `endLine` is optional and defaults to `startLine`; a single-line region
    /// stating only `endColumn` is the common case and must not be dropped.
    #[test]
    fn a_sarif_region_with_only_an_end_column_spans_its_own_line() {
        let sarif = r#"{"runs":[{"results":[{"ruleId":"r","message":{"text":"m"},
          "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.c"},
          "region":{"startLine":7,"startColumn":3,"endColumn":11}}}]}]}]}"#;
        let f = parse_sarif(sarif, "p").unwrap();
        assert_eq!(f[0].location.end_line, Some(7));
        assert_eq!(f[0].location.end_column, Some(11));
    }

    /// A degenerate region is not an extent. Recording one would make the
    /// editor draw a zero-width underline and claim more precision than the
    /// tool offered.
    #[test]
    fn a_zero_width_or_inverted_sarif_region_is_left_as_a_point() {
        for region in [
            r#"{"startLine":4,"startColumn":9,"endLine":4,"endColumn":9}"#,
            r#"{"startLine":4,"startColumn":9,"endLine":3,"endColumn":2}"#,
            r#"{"startLine":4,"startColumn":9}"#,
        ] {
            let sarif = format!(
                r#"{{"runs":[{{"results":[{{"ruleId":"r","message":{{"text":"m"}},
                "locations":[{{"physicalLocation":{{"artifactLocation":{{"uri":"a.c"}},
                "region":{region}}}}}]}}]}}]}}"#
            );
            let f = parse_sarif(&sarif, "p").unwrap();
            assert_eq!(f[0].location.end_column, None, "region {region}");
        }
    }

    /// rustc brackets every diagnostic it emits, in the same span object the
    /// start is read from.
    #[test]
    fn a_rustc_span_end_becomes_the_findings_extent() {
        // One line: cargo emits one JSON object per line and the parser reads it
        // that way.
        let json = r#"{"reason":"compiler-message","message":{"level":"warning","message":"unused","code":{"code":"unused_variables"},"spans":[{"file_name":"src/lib.rs","line_start":10,"column_start":9,"line_end":10,"column_end":14,"is_primary":true}]}}"#;
        let f = parse_clippy_json(json, "ext.clippy").unwrap();
        assert_eq!(f[0].location.end_line, Some(10));
        assert_eq!(f[0].location.end_column, Some(14));
    }

    /// Cppcheck's XML and GCC-style text state one position and no extent.
    /// Inventing one would be worse than reporting a point.
    #[test]
    fn formats_that_state_no_extent_report_a_point_rather_than_a_guess() {
        let xml = r#"<results><error id="x" severity="warning" msg="m" file="a.c" line="3" column="5"/></results>"#;
        assert_eq!(parse_cppcheck_xml(xml, "p").unwrap()[0].location.end_column, None);

        let text = "a.c:3:5: warning: m [chk]";
        assert_eq!(parse_gcc_like(text, "p").unwrap()[0].location.end_column, None);
    }

    /// The Valgrind adapter declared `GccLike`, which matches not one line
    /// Memcheck emits. A run reporting an invalid write and a definite leak
    /// produced zero findings — the tool worked, the adapter could not read it.
    #[test]
    fn valgrind_memcheck_output_yields_findings_at_the_programs_own_frame() {
        let text = "\
==12345== Memcheck, a memory error detector
==12345== Copyright (C) 2002-2022, and GNU GPL'd, by Julian Seward et al.
==12345== Command: ./a.out
==12345==
==12345== Invalid write of size 4
==12345==    at 0x1091A9: main (main.c:7)
==12345==  Address 0x4a9c04c is 0 bytes after a block of size 40 alloc'd
==12345==    at 0x484A2F3: malloc (vg_replace_malloc.c:393)
==12345==    by 0x109199: main (main.c:6)
==12345==
==12345== 40 bytes in 1 blocks are definitely lost in loss record 1 of 1
==12345==    at 0x484A2F3: malloc (vg_replace_malloc.c:393)
==12345==    by 0x109199: main (main.c:6)
==12345==
==12345== ERROR SUMMARY: 2 errors from 2 contexts (suppressed: 0 from 0)
";
        let f = parse_valgrind(text, "ext.valgrind").unwrap();
        assert_eq!(f.len(), 2, "an invalid write and a leak: {:?}", rules(&f));

        assert_eq!(f[0].rule.as_str(), "VALGRIND-INVALID-WRITE");
        assert_eq!(f[0].severity, Severity::Critical);
        assert_eq!(f[0].location.file.to_string_lossy(), "main.c");
        assert_eq!(f[0].location.line, 7);
        assert_eq!(f[0].taxonomy_id(sda_core::Taxonomy::Cwe), Some("CWE-787"));

        // The leak's first frame is Valgrind's own malloc interceptor. Reporting
        // `vg_replace_malloc.c` would point every allocation defect at
        // Valgrind's source instead of the program's.
        assert_eq!(f[1].rule.as_str(), "VALGRIND-LEAK");
        assert_eq!(f[1].location.file.to_string_lossy(), "main.c");
        assert_eq!(f[1].location.line, 6, "the frame in the program, not the interceptor");
        assert_eq!(f[1].taxonomy_id(sda_core::Taxonomy::Cwe), Some("CWE-401"));
    }

    /// Banner and summary lines describe no defect, and `still reachable` is not
    /// a leak — reporting it as one is the loudest noise Valgrind produces.
    #[test]
    fn valgrind_banners_summaries_and_still_reachable_are_not_findings() {
        let text = "\
==1== Memcheck, a memory error detector
==1== Using Valgrind-3.22.0 and LibVEX
==1== Parent PID: 900
==1==
==1== HEAP SUMMARY:
==1==     in use at exit: 40 bytes in 1 blocks
==1==   total heap usage: 2 allocs, 1 frees, 1,064 bytes allocated
==1==
==1== 40 bytes in 1 blocks are still reachable in loss record 1 of 1
==1==    at 0x484A2F3: malloc (vg_replace_malloc.c:393)
==1==    by 0x109199: main (main.c:6)
==1==
==1== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
";
        assert!(parse_valgrind(text, "p").unwrap().is_empty(), "nothing here is a defect");
    }

    /// Without `-g` Valgrind names no source line, so there is nowhere to put a
    /// finding. Returning none lets the non-zero exit trip the "establishes
    /// nothing" guard, which is the honest outcome; inventing a location is not.
    #[test]
    fn valgrind_frames_without_debug_info_yield_no_placed_finding() {
        let text = "\
==7== Invalid read of size 1
==7==    at 0x109189: ??? (in /home/u/a.out)
==7==    by 0x4A2B0C9: ??? (in /usr/lib/libc.so.6)
";
        assert!(parse_valgrind(text, "p").unwrap().is_empty());
    }

    /// `--leak-check=full` prints each leak twice: once as a loss record with a
    /// stack, and once as a tally under `LEAK SUMMARY`. Only the record is a
    /// finding — counting the tally as well would double every leak in the
    /// report, and the tally has no stack to point at anyway.
    #[test]
    fn the_leak_summary_tally_does_not_double_count_the_loss_record() {
        let text = "\
==1== 40 bytes in 1 blocks are definitely lost in loss record 1 of 1
==1==    at 0x484A2F3: malloc (vg_replace_malloc.c:393)
==1==    by 0x109199: main (main.c:6)
==1==
==1== LEAK SUMMARY:
==1==    definitely lost: 40 bytes in 1 blocks
==1==    indirectly lost: 0 bytes in 0 blocks
==1==      possibly lost: 0 bytes in 0 blocks
==1==    still reachable: 0 bytes in 0 blocks
==1==
";
        let f = parse_valgrind(text, "p").unwrap();
        assert_eq!(f.len(), 1, "one leak, reported once: {:?}", rules(&f));
        assert_eq!(f[0].rule.as_str(), "VALGRIND-LEAK");
        assert_eq!(f[0].location.line, 6);
    }

    #[test]
    fn valgrind_uninitialised_values_are_reported_high_with_a_cwe() {
        let text = "\
==9== Use of uninitialised value of size 8
==9==    at 0x1091B2: compute (calc.c:14)
";
        let f = parse_valgrind(text, "p").unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule.as_str(), "VALGRIND-UNINITIALISED");
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].location.line, 14);
        assert_eq!(f[0].taxonomy_id(sda_core::Taxonomy::Cwe), Some("CWE-457"));
    }

    /// The same claims, against output Valgrind 3.24.0 actually produced rather
    /// than output we believed it produces. This adapter shipped with four
    /// defects and had never once met Memcheck; the test above pins the format
    /// we reconstructed, and this one pins the format that exists.
    #[test]
    fn real_memcheck_output_parses_exactly_as_the_reconstruction_predicted() {
        let f = parse_valgrind(
            include_str!("../tests/fixtures/ext.valgrind.txt"),
            "ext.valgrind",
        )
        .unwrap();
        assert_eq!(f.len(), 3, "invalid write, uninitialised read, leak: {:?}", rules(&f));

        let write = f.iter().find(|x| x.rule.as_str() == "VALGRIND-INVALID-WRITE").unwrap();
        assert_eq!(write.severity, Severity::Critical);
        assert_eq!(write.location.line, 6, "the store, not Valgrind's malloc interceptor");
        assert_eq!(write.taxonomy_id(sda_core::Taxonomy::Cwe), Some("CWE-787"));

        let uninit = f.iter().find(|x| x.rule.as_str() == "VALGRIND-UNINITIALISED").unwrap();
        assert_eq!(uninit.location.line, 12);
        assert_eq!(uninit.taxonomy_id(sda_core::Taxonomy::Cwe), Some("CWE-457"));

        let leak = f.iter().find(|x| x.rule.as_str() == "VALGRIND-LEAK").unwrap();
        assert_eq!(leak.location.line, 19, "the allocation site in the program");
        assert_eq!(leak.taxonomy_id(sda_core::Taxonomy::Cwe), Some("CWE-401"));

        // The `LEAK SUMMARY` block tallies the same 128 bytes the loss record
        // above already reported. Counting both would double every leak.
        assert_eq!(
            f.iter().filter(|x| x.rule.as_str() == "VALGRIND-LEAK").count(),
            1,
            "the leak summary must not be counted alongside the record it summarises"
        );
    }

    /// Valgrind also emits `--pid--` lines for its own tooling chatter.
    #[test]
    fn valgrind_dash_marker_lines_are_understood_too() {
        assert_eq!(strip_pid("==12345== Invalid write"), Some(" Invalid write"));
        assert_eq!(strip_pid("--12345-- Reading syms"), Some(" Reading syms"));
        assert_eq!(strip_pid("not a valgrind line"), None);
        assert_eq!(strip_pid("==abc== nope"), None);
    }

    fn rules(f: &[Finding]) -> Vec<String> {
        f.iter().map(|x| x.rule.to_string()).collect()
    }

    /// The ModelScan adapter declared `OutputFormat::Sarif`. ModelScan's JSON
    /// has an `issues` array and no `runs` key, so the SARIF parser rejects it
    /// outright — the adapter could not have read a single real result. This
    /// records the incompatibility rather than leaving it as an assertion in a
    /// commit message.
    #[test]
    fn modelscan_json_is_not_sarif_and_the_sarif_parser_says_so() {
        let ms = include_str!("../tests/fixtures/ext.modelscan.txt");
        let err = parse_sarif(ms, "ext.modelscan")
            .expect_err("ModelScan's JSON is not SARIF and must not parse as it");
        assert!(err.contains("runs"), "got: {err}");
    }

    #[test]
    fn modelscan_issues_and_unscannable_files_both_become_findings() {
        let ms = include_str!("../tests/fixtures/ext.modelscan.txt");
        let f = parse_modelscan_json(ms, "ext.modelscan").unwrap();
        assert_eq!(f.len(), 2, "one issue and one artifact that could not be scanned");

        let critical = f.iter().find(|x| x.severity == Severity::Critical).unwrap();
        assert_eq!(critical.rule.as_str(), "MODELSCAN-PickleUnsafeOpScan-system");
        assert_eq!(critical.location.file.to_string_lossy(), "backdoored.pkl");
        assert_eq!(critical.taxonomy_id(sda_core::Taxonomy::Cwe), Some("CWE-502"));

        // The unreadable artifact is the one that matters: a file ModelScan
        // could not scan is not a file it found nothing in.
        let skipped = f.iter().find(|x| x.rule.as_str() == "MODELSCAN-NOT-SCANNED").unwrap();
        assert_eq!(skipped.location.file.to_string_lossy(), "broken.pkl");
        assert!(skipped.message.contains("nothing is established"), "{}", skipped.message);
    }

    /// What modelscan 0.8.8 actually prints to stdout, reduced to the shape that
    /// matters: two lines of progress chatter, then JSON hard-wrapped at the
    /// terminal width by `rich` — which breaks *inside a string literal*, so the
    /// document is not merely prefixed, it is unparseable.
    ///
    /// This is why the adapter passes `-o {output}` and reads the file. Skipping
    /// to the first `{` would not have been enough, and a parser written to
    /// tolerate this would be reassembling text the tool tore in half.
    #[test]
    fn modelscans_stdout_is_not_json_which_is_why_the_adapter_reads_a_file() {
        let stdout = "No settings file detected at ./modelscan-settings.toml. Using defaults.\r\n\
                      \r\n\
                      Scanning /models/backdoored.pkl using modelscan.scanners.PickleUnsafeOpScan\r\n\
                      {\"summary\": {\"total_issues\": 1, \"input_path\": \r\n\
                      \"/models/a-path-long-enough-to-be-wrapped-by-rich-at-eighty-colum\r\n\
                      ns/models\"}, \"issues\": [], \"errors\": []}\r\n";

        let err = parse_modelscan_json(stdout, "ext.modelscan")
            .expect_err("modelscan's stdout is not valid JSON and must not be read as a clean scan");
        assert!(err.contains("not valid ModelScan JSON"), "got: {err}");

        // And the same content, once the newline `rich` inserted is removed, is
        // the document the tool meant to emit — the damage is real, not cosmetic.
        let json = stdout.lines().skip(3).collect::<String>();
        assert!(parse_modelscan_json(&json, "ext.modelscan").is_ok());
    }

    /// A document that is valid JSON but not ModelScan's must be named as such,
    /// not reported as a scan that found nothing.
    #[test]
    fn json_that_is_not_modelscans_is_rejected_rather_than_read_as_empty() {
        let err = parse_modelscan_json(r#"{"runs":[]}"#, "p").expect_err("not modelscan output");
        assert!(err.contains("does not look like"), "got: {err}");
        // Genuinely empty output is genuinely nothing.
        assert!(parse_modelscan_json("", "p").unwrap().is_empty());
        // A clean scan reports no issues, and that is not an error.
        assert!(parse_modelscan_json(r#"{"issues":[],"errors":[]}"#, "p").unwrap().is_empty());
    }

    #[test]
    fn sarif_results_without_a_location_are_skipped_not_mislocated() {
        let sarif = r#"{"runs":[{"results":[{"ruleId":"x","message":{"text":"m"}}]}]}"#;
        assert!(parse_sarif(sarif, "p").unwrap().is_empty());
    }

    #[test]
    fn malformed_sarif_is_an_error_rather_than_a_silent_empty_result() {
        assert!(parse_sarif("{not json", "p").is_err());
        assert!(parse_sarif(r#"{"version":"2.1.0"}"#, "p").is_err());
        // But genuinely empty output is genuinely no findings.
        assert!(parse_sarif("", "p").unwrap().is_empty());
    }

    #[test]
    fn parses_cppcheck_xml() {
        let xml = r#"<?xml version="1.0"?><results version="2"><cppcheck version="2.13"/>
          <errors>
            <error id="nullPointer" severity="error" msg="Null pointer" verbose="Null pointer dereference of p"
                   file="src/a.c" line="42" column="9"/>
            <error id="unusedVariable" severity="style" msg="Unused variable" file="src/b.c" line="7"/>
          </errors></results>"#;
        let f = parse_cppcheck_xml(xml, "ext.cppcheck").unwrap();
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].rule.as_str(), "nullPointer");
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].location.line, 42);
        assert!(f[0].message.contains("dereference"), "the verbose message is preferred");
        assert_eq!(f[1].severity, Severity::Info);
    }

    /// Three shapes only a real cppcheck run produces, none of which the
    /// reconstructed fixture had: an error with **several** `<location>`
    /// elements (the first is the defect, the rest are the trail that explains
    /// it), a `<symbol>` child, and `checkersReport` — an entry with no location
    /// at all, emitted on every run.
    #[test]
    fn real_cppcheck_multi_location_errors_land_on_the_defect_not_the_trail() {
        let xml = include_str!("../tests/fixtures/ext.cppcheck.txt");
        let f = parse_cppcheck_xml(xml, "ext.cppcheck").unwrap();

        let np = f.iter().find(|x| x.rule.as_str() == "nullPointerOutOfMemory").unwrap();
        assert_eq!(
            np.location.line, 7,
            "the dereference is the finding; lines 6 and 6 are how it got there"
        );
        assert_eq!(np.taxonomy_id(sda_core::Taxonomy::Cwe), Some("CWE-476"));

        assert!(
            !rules(&f).contains(&"checkersReport".to_string()),
            "`Active checkers: 113/186` is metadata, not a finding"
        );
        assert_eq!(f.len(), 9, "ten <error> elements, one of them metadata");
    }

    /// `checkersReport` is safe to drop because it is `information` with no
    /// location. An error carrying a real severity must survive even if cppcheck
    /// gives it no `<location>`, by falling back to the `file0` translation unit
    /// — otherwise the adapter eats it and the run looks that much cleaner.
    #[test]
    fn a_located_less_error_falls_back_to_file0_rather_than_vanishing() {
        let xml = r#"<results version="2"><errors>
            <error id="internalAstError" severity="error" msg="broken AST" file0="src/hard.c"/>
            <error id="checkersReport" severity="information" msg="Active checkers: 1/2"/>
          </errors></results>"#;
        let f = parse_cppcheck_xml(xml, "ext.cppcheck").unwrap();
        assert_eq!(f.len(), 1, "the real error survives, the metadata does not");
        assert_eq!(f[0].rule.as_str(), "internalAstError");
        assert_eq!(f[0].location.file.to_string_lossy(), "src/hard.c");
    }

    #[test]
    fn cppcheck_xml_entities_are_unescaped() {
        let xml = r#"<results><error id="x" severity="warning" verbose="a &lt; b &amp;&amp; c" file="a.c" line="1"/></results>"#;
        let f = parse_cppcheck_xml(xml, "p").unwrap();
        assert!(f[0].message.contains("a < b && c"));
    }

    /// Cppcheck states a CWE and the correlation engine matches a runtime
    /// witness to a static finding through exactly that. Dropping it meant no
    /// external finding could ever be confirmed by runtime evidence, however
    /// good the evidence was — the toolkit's central claim, silently
    /// unavailable for every external provider.
    #[test]
    fn a_cppcheck_cwe_survives_into_the_finding() {
        let xml = r#"<results version="2"><errors>
            <error id="nullPointer" severity="error" msg="Null pointer dereference: p" cwe="476" file0="src/main.c">
              <location file="src/main.c" line="5" column="12"/>
            </error>
            <error id="noCwe" severity="style" msg="no cwe attribute here" file="src/main.c" line="9"/>
        </errors></results>"#;
        let f = parse_cppcheck_xml(xml, "ext.cppcheck").unwrap();
        assert_eq!(f.len(), 2);

        assert_eq!(
            f[0].taxonomy_id(sda_core::Taxonomy::Cwe),
            Some("CWE-476"),
            "the CWE cppcheck supplied must reach the finding"
        );
        // A check without a CWE must not invent one.
        assert_eq!(f[1].taxonomy_id(sda_core::Taxonomy::Cwe), None);
    }

    #[test]
    fn output_that_is_not_cppcheck_xml_is_rejected() {
        assert!(parse_cppcheck_xml("just some text", "p").is_err());
        assert!(parse_cppcheck_xml("", "p").unwrap().is_empty());
    }

    #[test]
    fn parses_clippy_json_and_ignores_cargo_chatter() {
        let json = r#"{"reason":"compiler-artifact","package_id":"x"}
{"reason":"compiler-message","message":{"level":"warning","message":"this `if` has identical blocks","code":{"code":"clippy::if_same_then_else"},"spans":[{"file_name":"src/lib.rs","line_start":10,"column_start":5,"is_primary":true}]}}
not json at all"#;
        let f = parse_clippy_json(json, "ext.clippy").unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule.as_str(), "clippy::if_same_then_else");
        assert_eq!(f[0].location.line, 10);
    }

    #[test]
    fn parses_clang_tidy_output_with_the_check_name_as_the_rule() {
        let text = "src/a.c:12:5: warning: do not use pointer arithmetic [cppcoreguidelines-pro-bounds-pointer-arithmetic]";
        let f = parse_gcc_like(text, "ext.clang-tidy").unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule.as_str(), "cppcoreguidelines-pro-bounds-pointer-arithmetic");
        assert_eq!(f[0].severity, Severity::Medium);
    }

    /// **This assertion used to be the other way round**, and the old one was
    /// wrong: it expected the `note:` to be a second finding, with the rule id
    /// `note`, which is not a rule.
    ///
    /// A `note:` is the second half of the diagnostic above it — the call frame,
    /// the "declared here", the macro expansion trail. clang-tidy over 184 files
    /// of llama.cpp emitted 307 of them, 4% of the report, and each one both
    /// invented a finding and *removed the trail from the finding it explains*:
    /// a `bugprone-exception-escape` lost its frames while seven unrelated
    /// "findings" appeared inside MSVC's `<map>`.
    #[test]
    fn a_note_is_evidence_for_the_diagnostic_above_it_not_a_finding() {
        let text = "src/a.c:12:5: warning: do not use pointer arithmetic [cppcoreguidelines-pro-bounds-pointer-arithmetic]\n\
                    src/a.c:20:1: note: expanded from macro FOO";
        let f = parse_gcc_like(text, "ext.clang-tidy").unwrap();

        assert_eq!(f.len(), 1, "the note is not a finding of its own");
        assert!(
            f[0].evidence.iter().any(
                |e| matches!(e, Evidence::Note { text } if text.contains("expanded from macro FOO"))
            ),
            "and it must survive as evidence on the finding it explains: {:?}",
            f[0].evidence
        );
        assert!(
            f[0].evidence.iter().any(
                |e| matches!(e, Evidence::Note { text } if text.contains("src/a.c:20:1"))
            ),
            "with its own position, which is the point of a frame: {:?}",
            f[0].evidence
        );
    }

    /// A note with nothing above it makes no claim, and there is nothing for it
    /// to be evidence of. Dropping it is right; inventing a finding from it is
    /// what produced 307 of them.
    #[test]
    fn an_orphan_note_is_not_a_finding() {
        let f = parse_gcc_like("src/a.c:20:1: note: expanded from macro", "ext.clang-tidy").unwrap();
        assert!(f.is_empty());
    }

    /// clang-tidy lists every name a check is reachable under, so an aliased
    /// check arrives as `[bugprone-x,cert-err34-c]`. Taking the whole bracket as
    /// the rule id produced a rule nothing could match — not a deviation entry,
    /// not a suppression, not the catalogue — while the CERT rule the project
    /// actually has to answer for went unrecorded.
    #[test]
    fn an_aliased_check_yields_one_rule_and_the_cert_id_as_taxonomy() {
        let text = "a.c:6:13: warning: 'atoi' will not report conversion errors \
                    [bugprone-unchecked-string-to-number-conversion,cert-err34-c]";
        let f = parse_gcc_like(text, "ext.clang-tidy").unwrap();
        assert_eq!(f.len(), 1, "an alias is a second name, not a second finding");
        assert_eq!(f[0].rule.as_str(), "bugprone-unchecked-string-to-number-conversion");
        assert_eq!(f[0].taxonomy_id(sda_core::Taxonomy::Cert), Some("ERR34-C"));
    }

    #[test]
    fn cert_ids_are_translated_only_when_the_check_name_holds_one() {
        assert_eq!(cert_rule_id("cert-err34-c").as_deref(), Some("ERR34-C"));
        assert_eq!(cert_rule_id("cert-oop54-cpp").as_deref(), Some("OOP54-CPP"));
        // Not a CERT check at all.
        assert_eq!(cert_rule_id("bugprone-branch-clone"), None);
        // `cert-*` checks that name no published rule must not have one invented.
        assert_eq!(cert_rule_id("cert-dcl"), None);
        assert_eq!(cert_rule_id("cert-err34-java"), None);
    }

    /// A check name has no spaces in it. Prose that happens to end in a bracket
    /// does, and used to be silently promoted to the rule id.
    #[test]
    fn a_bracket_of_prose_is_not_mistaken_for_a_check_name() {
        let f = parse_gcc_like("a.c:1:1: warning: undefined here [see line 4]", "p").unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].rule.as_str(), "warning");
        assert!(f[0].message.contains("[see line 4]"), "the message keeps its own text");
    }

    #[test]
    fn windows_paths_are_parsed_correctly() {
        let f = parse_gcc_like("C:/proj/a.c:3:1: error: bad [chk]", "p").unwrap();
        assert_eq!(f[0].location.file.to_string_lossy(), "C:/proj/a.c");
    }

    #[test]
    fn unrecognised_lines_do_not_abort_the_parse() {
        let text = "building...\nsrc/a.c:1:1: warning: real [chk]\nlinking...";
        assert_eq!(parse_gcc_like(text, "p").unwrap().len(), 1);
    }
}

/// What one Verus run established, and what it could not say.
///
/// Verus reports its failures precisely and its successes only as a number, and
/// this type keeps that asymmetry rather than smoothing it over. See
/// [`parse_verus`] for why it takes two arguments.
#[derive(Clone, Debug, Default)]
pub struct VerusRun {
    /// Release string from the JSON, e.g. `0.2026.08.30.b432e82`.
    pub version: String,
    pub verified: usize,
    pub errors: usize,
    /// Verus's own overall judgement.
    pub success: bool,
    /// One per located failure, from the diagnostic stream.
    pub failures: Vec<ProofObligation>,
    /// Disagreements between the two channels, and anything else a reader must
    /// see before trusting the counts.
    pub problems: Vec<String>,
}

impl VerusRun {
    /// Obligations this run settles, for folding into a `VerificationLedger`.
    ///
    /// Only failures are returned, and that is not an oversight. Verus names
    /// every obligation it *could not* discharge and names none of the ones it
    /// did — `verified: 3` is the whole of what it says about success. Emitting
    /// three anonymous `Discharged` obligations to balance the books would put
    /// claims in the ledger that no tool made.
    pub fn obligations(&self) -> Vec<ProofObligation> {
        self.failures.clone()
    }
}

/// Parse a Verus run from **both** of its output channels.
///
/// Two arguments because one is not enough, which is the thing running the real
/// tool taught and no amount of reading would have:
///
/// * `json` is what `--output-json` writes to stdout. It carries the counts and
///   `success`, and a `func-details` map with an entry for every function —
///   including an `obligation_proof_notes` and a `failed_proof_notes` list. On a
///   run with one failing function, **that function's `failed_proof_notes` is
///   empty**, exactly like every other function's. The JSON records that
///   something failed and never which thing.
/// * `diagnostics` is stderr: rustc-style text, and the only place the failing
///   obligation's message and location exist.
///
/// An adapter reading `--output-json` alone — the obvious choice, and the one a
/// machine-readable flag invites — would report a failure it could not locate,
/// while `failed_proof_notes: []` positively suggested nothing was wrong with
/// any particular function. The **standalone `verus` binary also exits 0 on a
/// failed proof**, so a CI gate on its exit code passes — `cargo verus verify`
/// does exit 101, so the trap depends on which way the prover is driven, and
/// only running it both ways showed that. Those facts compose into a proof
/// failure that is invisible from every direction an integrator would naturally
/// look.
///
/// Pass `""` for `diagnostics` if the stream was not captured; the run is then
/// reported as having failures it cannot locate, rather than as clean.
pub fn parse_verus(json: &str, diagnostics: &str) -> Result<VerusRun, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("verus json: {e}"))?;
    let results = v
        .get("verification-results")
        .ok_or_else(|| "verus json has no `verification-results` object".to_string())?;

    let mut run = VerusRun {
        version: v
            .pointer("/verus/version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        verified: results.get("verified").and_then(Value::as_u64).unwrap_or(0) as usize,
        errors: results.get("errors").and_then(Value::as_u64).unwrap_or(0) as usize,
        success: results.get("success").and_then(Value::as_bool).unwrap_or(false),
        ..VerusRun::default()
    };

    run.failures = parse_verus_diagnostics(diagnostics);

    // The counts come from one channel and the locations from another, so they
    // can disagree — and a disagreement means the report is missing something
    // rather than that the numbers are wrong.
    if run.failures.len() < run.errors {
        run.problems.push(format!(
            "verus reported {} error(s) and only {} could be located. The JSON names no failing \
             function — `failed_proof_notes` is empty even for the one that failed — so the \
             difference is in a diagnostic stream that was not captured or not parsed",
            run.errors,
            run.failures.len()
        ));
    }
    if run.failures.len() > run.errors {
        run.problems.push(format!(
            "verus reported {} error(s) and {} diagnostic(s) were read as failures. The extra              ones are almost certainly a driver's summary line rather than proof obligations, and              counting them would overstate what failed",
            run.errors,
            run.failures.len()
        ));
    }
    // Nothing proved and nothing failed. `cargo verus verify` on a crate with no
    // specifications does exactly this and exits cleanly, so without saying so
    // the adapter would report a crate nobody constrained as a crate that passed
    // — the deductive analogue of a clean scan over an empty file set, and the
    // thing `Modality::Deductive::silence_means` exists to name.
    if run.success && run.verified == 0 && run.errors == 0 {
        run.problems.push(
            "verus verified 0 obligations and reported 0 errors: nothing was specified, so              nothing was checked. An unspecified crate verifies vacuously, and a vacuous              verification is not a result"
                .to_string(),
        );
    }
    if !run.success && run.errors == 0 {
        run.problems.push(
            "verus reported failure with an error count of zero; something went wrong that is \
             not a proof obligation, and the run must not be read as a verification result"
                .to_string(),
        );
    }
    if run.success && !run.failures.is_empty() {
        run.problems.push(format!(
            "verus reported success while its diagnostics carry {} failure(s); the two channels \
             contradict each other and neither should be trusted here",
            run.failures.len()
        ));
    }
    Ok(run)
}

/// Pull located failures out of Verus's rustc-style diagnostic stream.
///
/// Two summary lines are skipped, and the second was found only by running the
/// tool the other way round:
///
/// * `error: aborting due to N previous error(s)` — rustc's own summary, which
///   standalone `verus` ends with.
/// * ``error: could not compile `crate` (bin "crate") due to N previous
///   error(s)`` — cargo's summary, which `cargo verus verify` ends with instead.
///
/// Neither is a proof obligation. Counting them would inflate every failing run
/// by exactly one, and the cargo form did until a real `cargo verus` run was
/// captured: the standalone fixture never contained it, so nothing in the
/// repository could have caught it.
fn parse_verus_diagnostics(text: &str) -> Vec<ProofObligation> {
    let mut out = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let Some(message) = line.strip_prefix("error: ") else { continue };
        let message = message.trim();
        if is_summary_line(message) {
            continue;
        }
        // The location is on the following line, as `  --> file:line:col`.
        let location = lines
            .get(i + 1)
            .and_then(|l| l.trim().strip_prefix("--> "))
            .and_then(parse_rust_location);
        // A diagnostic with no span still failed something. The default is an
        // empty file, kept rather than dropped: discarding it would turn an
        // unlocatable failure into no failure at all.
        let (file, line_no, column) = location.unwrap_or_default();
        let id = if file.is_empty() {
            format!("verus/{}", out.len())
        } else {
            format!("verus/{file}:{line_no}:{column}")
        };
        let mut obligation = ProofObligation::new(
            id,
            message,
            if file.is_empty() { "<unlocated>".to_string() } else { file.clone() },
            Boundary::Symbolic,
            ObligationStatus::Failed { counterexample: None },
        )
        .proved_by("ext.verus");
        if !file.is_empty() {
            obligation = obligation.at(Location::new(file, line_no, column));
        }
        out.push(obligation);
    }
    out
}

/// True for a driver's "and that is why the build stopped" line.
fn is_summary_line(message: &str) -> bool {
    message.starts_with("aborting due to")
        // `could not compile \`vnew\` (bin "vnew") due to 1 previous error`
        || (message.starts_with("could not compile ") && message.contains("previous error"))
}

/// `guard.rs:41:9` — the tail of a rustc `-->` line.
fn parse_rust_location(s: &str) -> Option<(String, u32, u32)> {
    let s = s.trim();
    let (rest, column) = s.rsplit_once(':')?;
    let (file, line) = rest.rsplit_once(':')?;
    Some((file.to_string(), line.parse().ok()?, column.parse().ok()?))
}

/// Verus failures as [`Finding`]s, for reports that speak findings.
///
/// [`parse_verus`] produces obligations, which is the right shape for a
/// [`sda_core::verification::VerificationLedger`]. A report, a SARIF export and
/// the GUI all speak findings, and a failed proof belongs in those too — an
/// obligation the prover could not discharge is a defect claim with a location,
/// which is exactly what a finding is.
///
/// Severity is `High` and confidence `Certain`, and both are meant literally.
/// This is not a heuristic's suspicion: a prover searched and could not
/// establish the property. It is still not proof that the defect *occurs* —
/// Verus reports what it cannot show, and an unprovable postcondition can be
/// unprovable because the specification is too weak — so the message says so
/// rather than asserting a bug.
///
/// **No finding is emitted for the obligations that passed.** Verus counts its
/// successes and names none of them, so there is nothing to attach a location
/// to; inventing `verified: 3` clean findings would put three claims in a report
/// that no tool made about any particular line.
pub fn parse_verus_findings(
    json: &str,
    diagnostics: &str,
    provider: &str,
) -> Result<Vec<Finding>, String> {
    let run = parse_verus(json, diagnostics)?;
    let mut out = Vec::new();

    for o in &run.failures {
        let location = match &o.location {
            Some(l) => l.clone(),
            None => Location::new("<unlocated>", 1, 1),
        };
        let rule = format!("VERUS-{}", slug(&o.statement));
        let mut f = Finding::new(provider, rule, o.statement.clone(), Severity::High, location)
            .confidence(sda_core::Confidence::Certain)
            .message(format!(
                "{}. A prover searched and could not establish this. That is not the same as \
                 showing the defect occurs — an obligation can fail because the specification is \
                 too weak to carry it — but it is a claim the code does not currently support.",
                o.statement
            ))
            .evidence(Evidence::proof(o.clone()));
        if !run.version.is_empty() {
            f = f.evidence(Evidence::note(format!(
                "verus {} reported {} obligation(s) verified and {} failed",
                run.version, run.verified, run.errors
            )));
        }
        out.push(f);
    }

    // A run whose channels disagree, or whose failures could not be located,
    // must not simply produce fewer findings than there were errors.
    for p in &run.problems {
        out.push(
            Finding::new(
                provider,
                "VERUS-REPORT-INCOMPLETE",
                "the prover's report cannot be read at face value",
                Severity::Medium,
                Location::file_only("<verus>"),
            )
            .message(p.clone())
            .confidence(sda_core::Confidence::Certain),
        );
    }
    Ok(out)
}

/// A rule id fragment from a diagnostic message: `postcondition not satisfied`
/// becomes `POSTCONDITION-NOT-SATISFIED`.
fn slug(message: &str) -> String {
    let mut s: String = message
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c.to_ascii_uppercase() } else { '-' })
        .collect();
    while s.contains("--") {
        s = s.replace("--", "-");
    }
    s.trim_matches('-').chars().take(48).collect()
}
