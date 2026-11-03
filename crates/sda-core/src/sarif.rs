//! SARIF 2.1.0 export.
//!
//! SARIF is the lingua franca of code scanning (GitHub Advanced Security, Azure
//! DevOps, VS Code, most commercial dashboards). Emitting it is what lets this
//! toolkit slot into a pipeline that already exists rather than demanding a new one.
//!
//! Statodynamic specifics that plain SARIF has no field for — the correlation
//! verdict, the analysis phase — are carried in `properties` bags, which
//! consumers ignore safely and our own GUI reads back.

use crate::finding::{Finding, Severity};
use crate::report::Report;
use serde_json::{Value, json};
use std::collections::BTreeMap;

const SARIF_VERSION: &str = "2.1.0";
/// The **normative** schema location, at OASIS.
///
/// This used to point at `raw.githubusercontent.com/oasis-tcs/sarif-spec/master/
/// Schemata/sarif-schema-2.1.0.json`, which returns **404**: the repository
/// renamed its default branch and moved the file, so every SARIF document this
/// toolkit has ever emitted declared a schema that could not be fetched. A
/// consumer that resolves `$schema` before validating got nothing.
///
/// Found by handing real output to the SARIF reference implementation, which
/// reports it as `SARIF2006`. Checked rather than assumed: the old URL and the
/// `main`-branch form both 404, `json.schemastore.org` redirects, and this one
/// returns 200. It is also the specification's own address rather than a mirror,
/// which is the part that makes it unlikely to move again.
const SARIF_SCHEMA: &str =
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json";

/// SARIF has three result levels plus `none`; map our five-point scale onto it
/// and keep the original in a property so nothing is lost.
fn level_for(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
        Severity::Info => "none",
    }
}

/// GitHub code scanning ranks results by `security-severity` (a CVSS-like 0-10).
fn security_severity(sev: Severity) -> f32 {
    match sev {
        Severity::Critical => 9.5,
        Severity::High => 8.0,
        Severity::Medium => 5.5,
        Severity::Low => 3.0,
        Severity::Info => 1.0,
    }
}

/// The symbolic name for the root of the analysed tree.
///
/// Result URIs are relative — `src/main.c` — and until now nothing said what
/// they were relative *to*, so a consumer had to guess. SARIF's answer is a
/// `uriBaseId`, declared once on the run and referenced by every location.
///
/// It is declared **without a `uri`**, deliberately. The alternative is to write
/// `file:///C:/Users/.../project` into every report, which pins one machine's
/// layout into a document meant to travel and says nothing a consumer of a
/// checkout needs. Naming the base without resolving it is the honest half: the
/// paths are relative to the root of the scanned tree, and where that tree lives
/// is the reader's business.
const SRCROOT: &str = "SRCROOT";

/// Whether a URI is absolute, and so not relative to [`SRCROOT`].
fn is_absolute_uri(uri: &str) -> bool {
    uri.starts_with('/')
        || uri.contains("://")
        // A Windows drive letter, as `uri_for` leaves it: `C:/Users/...`.
        || uri.as_bytes().get(1) == Some(&b':')
}

fn uri_for(f: &Finding) -> String {
    // SARIF requires forward slashes regardless of host platform.
    f.location.file.to_string_lossy().replace('\\', "/")
}

/// The location a result points at, with the code around it where the engine
/// collected any. See [`snippets`].
fn physical_location(f: &Finding) -> Value {
    let (own, context) = snippets(f);
    let mut region = region(f);
    if let Some(snippet) = own {
        region["snippet"] = snippet;
    }
    let uri = uri_for(f);
    let mut artifact = json!({ "uri": uri });
    // Only where the path is relative. Saying `SRCROOT` about an absolute path
    // would be a claim that it lies under the source root, which for a finding
    // an external tool reported inside a system header is false.
    if !is_absolute_uri(artifact["uri"].as_str().unwrap_or_default()) {
        artifact["uriBaseId"] = json!(SRCROOT);
    }
    let mut loc = json!({
        "artifactLocation": artifact,
        "region": region,
    });
    if let Some(context) = context {
        loc["contextRegion"] = context;
    }
    loc
}

fn region(f: &Finding) -> Value {
    // SARIF distinguishes a text region from a binary one, and a `region` may
    // legitimately carry only `byteOffset`. Emitting `startLine: 1` for a
    // finding inside a pickle told every SARIF consumer to highlight the first
    // line of a file that has none — so a binary location is emitted as a
    // binary region, and no line is claimed.
    if let Some(start) = f.location.byte_start {
        let mut r = json!({ "byteOffset": start });
        if let Some(end) = f.location.byte_end {
            r["byteLength"] = json!(end.saturating_sub(start));
        }
        return r;
    }

    let mut r = json!({
        "startLine": f.location.line.max(1),
        "startColumn": f.location.column.max(1),
    });
    if let Some(el) = f.location.end_line {
        r["endLine"] = json!(el);
    }
    if let Some(ec) = f.location.end_column {
        r["endColumn"] = json!(ec);
    }
    r
}

/// The source the engine already collected, as SARIF's `region.snippet` and
/// `contextRegion`.
///
/// The finding carries an `Evidence::Source` with the surrounding lines and the
/// number of the first of them — that is what the text report prints under every
/// finding. The SARIF exporter dropped it, so a viewer reading the same report
/// showed a file and a line number and no code, and a reader had to go and find
/// the source themselves. Evidence held one layer down and discarded on the way
/// out is the shape of defect this repository keeps a table of; here it was
/// discarded at the boundary to every other tool.
///
/// Found by handing real output to the SARIF reference implementation, which
/// said so twenty times per file (`SARIF2010`, `SARIF2011`).
///
/// Returns `(snippet for the result's own line, contextRegion)`. Either may be
/// absent: a binary-located finding has no lines, and a finding whose evidence
/// names a different file must not borrow it.
fn snippets(f: &Finding) -> (Option<Value>, Option<Value>) {
    if f.location.byte_start.is_some() {
        return (None, None); // a binary region has no lines to quote
    }
    let source = f.evidence.iter().find_map(|e| match e {
        crate::Evidence::Source { location, first_line, text }
            if location.file == f.location.file =>
        {
            Some((*first_line, text))
        }
        _ => None,
    });
    let Some((first_line, text)) = source else { return (None, None) };

    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        return (None, None);
    }

    let context = json!({
        "startLine": first_line.max(1),
        "endLine": first_line.max(1) as usize + lines.len() - 1,
        "snippet": { "text": text },
    });

    // The result's own line, when the block actually contains it. It usually
    // does; asserting it would be claiming more than the evidence says.
    let own = f
        .location
        .line
        .checked_sub(first_line)
        .and_then(|offset| lines.get(offset as usize))
        .map(|line| json!({ "text": *line }));

    (own, Some(context))
}

/// Build the `rules` array from the distinct rules actually referenced, and a
/// map from rule id to its index (SARIF results point at rules by index).
fn rule_descriptors(report: &Report) -> (Vec<Value>, BTreeMap<String, usize>) {
    let mut index = BTreeMap::new();
    let mut rules = Vec::new();
    for f in &report.findings {
        let key = f.rule.to_string();
        if index.contains_key(&key) {
            continue;
        }
        let tags: Vec<String> = f
            .taxonomy
            .iter()
            .map(|t| t.qualified())
            .chain(std::iter::once(format!("phase/{}", f.phase.as_str())))
            .collect();
        let help_uri = f.taxonomy.iter().find_map(|t| t.url());
        let mut desc = json!({
            "id": key,
            "name": key.replace(['-', '.'], ""),
            "shortDescription": { "text": f.title },
            "fullDescription": { "text": f.message },
            "defaultConfiguration": { "level": level_for(f.severity) },
            "properties": {
                "tags": tags,
                "security-severity": security_severity(f.severity).to_string(),
                "sda/phase": f.phase.as_str(),
            }
        });
        if let Some(u) = help_uri {
            desc["helpUri"] = json!(u);
        }
        if let Some(r) = &f.remediation {
            desc["help"] = json!({ "text": r });
        }
        index.insert(key, rules.len());
        rules.push(desc);
    }
    (rules, index)
}

fn result_for(f: &Finding, rule_index: usize, report: &Report) -> Value {
    // Attach the correlation verdict, if the engine reached one about this finding.
    let verdict = report
        .correlations
        .iter()
        .find(|c| c.static_finding.as_ref() == Some(&f.id))
        .map(|c| (c.verdict.as_str(), c.rationale.clone()));

    let mut props = json!({
        "sda/findingId": f.id.to_string(),
        "sda/phase": f.phase.as_str(),
        "sda/confidence": f.confidence.as_str(),
        "sda/provider": f.provider.to_string(),
        "sda/severity": f.severity.as_str(),
    });
    if let Some((v, why)) = verdict {
        props["sda/verdict"] = json!(v);
        props["sda/verdictRationale"] = json!(why);
    }

    let mut result = json!({
        "ruleId": f.rule.to_string(),
        "ruleIndex": rule_index,
        "level": level_for(f.severity),
        "message": { "text": f.message },
        "partialFingerprints": { "sdaFingerprint/v1": f.id.to_string() },
        "locations": [{
            "physicalLocation": physical_location(f)
        }],
        "properties": props,
    });

    // Suppressed findings stay in the file but are marked, so a deviation is
    // auditable rather than invisible.
    if let Some(reason) = &f.suppressed_by {
        result["suppressions"] = json!([{ "kind": "external", "justification": reason }]);
    }

    // Traces become SARIF code flows, which viewers render as step-throughs.
    let flows: Vec<Value> = f
        .evidence
        .iter()
        .filter_map(|e| match e {
            crate::evidence::Evidence::Trace { frames } if !frames.is_empty() => {
                let locations: Vec<Value> = frames
                    .iter()
                    .map(|fr| {
                        json!({
                            "location": {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": fr.location.file.to_string_lossy().replace('\\', "/")
                                    },
                                    "region": { "startLine": fr.location.line.max(1) }
                                },
                                "message": { "text": fr.note }
                            },
                            "nestingLevel": 0,
                            "executionOrder": fr.step,
                        })
                    })
                    .collect();
                Some(json!({ "threadFlows": [{ "locations": locations }] }))
            }
            _ => None,
        })
        .collect();
    if !flows.is_empty() {
        result["codeFlows"] = json!(flows);
    }

    result
}

/// `versionControlProvenance`, when the target is a checkout.
///
/// SARIF has fields for the revision, the branch and the repository and **none**
/// for whether the working tree matched. That gap is the whole difficulty: a
/// consumer reading `revisionId` alone will say "these findings describe commit
/// abc123", which is false the moment somebody edits a file. So a dirty tree
/// carries the fact in `properties` *and* the report says it in prose, and the
/// two cannot disagree because both come from the same `dirty` flag.
fn version_control(v: &crate::VcsProvenance) -> Value {
    let mut d = json!({
        "repositoryUri": v.repository.clone().unwrap_or_else(|| ".".to_string()),
        "revisionId": v.revision,
        // What the result URIs are relative to. Without it a consumer cannot
        // connect a finding at `src/main.c` to a file in the repository this
        // names, which is the entire purpose of recording the repository.
        "mappedTo": { "uriBaseId": SRCROOT },
        "properties": {
            "sda/workingTreeClean": !v.dirty,
            "sda/summary": v.summary(),
        },
    });
    if let Some(b) = &v.branch {
        d["branch"] = json!(b);
    }
    json!([d])
}

/// Render `report` as a SARIF 2.1.0 log.
pub fn to_sarif(report: &Report) -> Value {
    let (rules, index) = rule_descriptors(report);
    let results: Vec<Value> = report
        .findings
        .iter()
        .map(|f| {
            let idx = index.get(f.rule.as_str()).copied().unwrap_or(0);
            result_for(f, idx, report)
        })
        .collect();

    // The NOT CHECKED section, as tool notifications, so a downstream dashboard
    // can tell a clean run from a partial one.
    //
    // The message deliberately does not say the provider did not run, which is
    // what it used to say of all of them. That is true of the nine `ext.*`
    // entries and false of most of the rest: `sda.interposition` ran and found
    // no model/effector pair to prove anything about, `sda.neurosymbolic` ran and
    // adjudicated a component as vacuous, `sda.correlate` ran without an
    // observation, and `sda.config` is not a provider at all — it is
    // configuration the project asked for and did not get. An `Exclusion` records
    // that something is *not covered*; it does not record whether anything
    // executed, so this must not claim to know. `correlate` already draws exactly
    // this line — "`Unreached` must never assert that code did not run" — and
    // this is the machine-readable surface, where a CI system acts on it.
    //
    // `descriptor.id` is left alone. It is the key a consumer matches on, the
    // wording is not, and renaming a stable machine contract to fix an English
    // sentence would be a worse trade than the sentence.
    // One of these is not a note.
    //
    // Every notification carried `level: "note"`, which was defensible while the
    // toolkit had no position of its own on which of them mattered. It has one
    // now: `sda scan --fail-on` exits **3** on a run that read nothing, because
    // a gate that could not run has not been passed. So the same run told a
    // pipeline *no verdict, stop* through its exit code and *note, for your
    // information* through its SARIF, and a consumer reading only the document —
    // which is the whole reason the document exists — got the softer of the two.
    //
    // The level is derived from that decision rather than from a new taxonomy.
    // `error` where the run had no verdict to give; `note` everywhere else.
    // There is an obvious middle tier — a file that could not be decoded was
    // *tried and failed*, unlike a provider that was never enabled — and it is
    // deliberately not invented here, because nothing in this codebase has yet
    // taken a position on it and a severity nobody decided is a severity nobody
    // can rely on.
    //
    // `descriptor.id` is left alone for the reason given above: it is the key a
    // consumer matches on.
    let notifications: Vec<Value> = report
        .exclusions
        .iter()
        .map(|e| {
            let level = if e.provider.as_str() == "sda.discovery" { "error" } else { "note" };
            json!({
                "level": level,
                "message": { "text": format!("NOT CHECKED — `{}`: {}", e.provider, e.reason) },
                "descriptor": { "id": "sda/providerExcluded" }
            })
        })
        .collect();

    // And the invocation did not succeed in the sense this field means: the
    // analysis it was asked for did not happen. Hardcoding `true` said it did,
    // in the field a consumer checks before reading anything else.
    let mut invocation = json!({ "executionSuccessful": !report.scanned_nothing() });
    if !notifications.is_empty() {
        invocation["toolExecutionNotifications"] = json!(notifications);
    }

    let mut run = json!({
        "tool": {
            "driver": {
                "name": "StatodynamicAnalysis",
                "informationUri": "https://github.com/nervosys/NeurosymbolicAnalysis",
                "semanticVersion": report.tool_version,
                "rules": rules,
            }
        },
        "invocations": [invocation],
        "results": results,
        "originalUriBaseIds": {
            SRCROOT: {
                "description": {
                    "text": "The root of the analysed source tree. Declared without a URI on                              purpose: the paths are relative to whatever checkout this report is                              read against, and pinning one machine's layout into the document                              would say nothing a reader needs."
                }
            }
        },
        "properties": {
            "sda/schemaVersion": report.schema_version,
            "sda/generatedAt": report.generated_at,
            "sda/target": report.target,
        }
    });
    // Omitted rather than faked when the target is not a checkout: `revisionId`
    // is required wherever this object appears, and there is no honest value.
    if let Some(v) = &report.vcs {
        run["versionControlProvenance"] = version_control(v);
    }

    json!({
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [run],
    })
}

pub fn to_sarif_string(report: &Report) -> crate::Result<String> {
    Ok(serde_json::to_string_pretty(&to_sarif(report))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{Evidence, TraceFrame};
    use crate::finding::{AnalysisPhase, Location};
    use crate::report::{Correlation, CorrelationVerdict};
    use crate::taxonomy::TaxonomyRef;

    fn report() -> Report {
        let f = Finding::new(
            "sda.static.c",
            "MISRA-C-2023-21.6",
            "use of <stdio.h> in a freestanding target",
            Severity::High,
            Location::new("src\\io.c", 12, 3),
        )
        .taxonomy(TaxonomyRef::cwe(676))
        .phase(AnalysisPhase::Static)
        .remediation("replace with the platform UART driver");
        let id = f.id.clone();
        Report::new("/proj", vec![f]).with_correlations(vec![
            Correlation::new(CorrelationVerdict::Refuted, "1200 executions, never taken").about(id),
        ])
    }

    fn vcs(dirty: bool) -> crate::VcsProvenance {
        crate::VcsProvenance {
            revision: "0123456789abcdef0123456789abcdef01234567".into(),
            branch: Some("master".into()),
            repository: Some("https://example.invalid/p.git".into()),
            dirty,
        }
    }

    /// A report that cannot say which revision it describes is weaker than one
    /// that can — and SARIF has no field for whether the tree matched, so the
    /// consumer that reads `revisionId` alone would take a dirty scan for that
    /// commit. The flag travels in `properties`, and the prose beside it says
    /// the same thing, from the same source.
    #[test]
    fn the_revision_travels_and_a_dirty_tree_is_marked() {
        let r = Report::new("proj", vec![]).with_vcs(Some(vcs(true)));
        let p = &to_sarif(&r)["runs"][0]["versionControlProvenance"][0];

        assert_eq!(p["revisionId"], vcs(true).revision);
        assert_eq!(p["branch"], "master");
        assert_eq!(p["properties"]["sda/workingTreeClean"], false);
        assert!(
            p["properties"]["sda/summary"]
                .as_str()
                .is_some_and(|t| t.contains("uncommitted changes")),
            "{p}"
        );
        // Without this a consumer cannot connect `src/main.c` to a file in the
        // repository the entry names, which is the point of naming it.
        assert_eq!(p["mappedTo"]["uriBaseId"], SRCROOT);
    }

    #[test]
    fn a_clean_tree_says_so() {
        let r = Report::new("proj", vec![]).with_vcs(Some(vcs(false)));
        let p = &to_sarif(&r)["runs"][0]["versionControlProvenance"][0];
        assert_eq!(p["properties"]["sda/workingTreeClean"], true);
    }

    /// `revisionId` is required wherever the object appears, so a target that is
    /// not a checkout gets no object rather than an invented revision.
    #[test]
    fn a_target_that_is_not_a_checkout_claims_no_revision() {
        let s = to_sarif(&Report::new("proj", vec![]));
        assert!(s["runs"][0].get("versionControlProvenance").is_none(), "{s}");
    }

    /// Relative result paths need a stated base or a consumer has to guess.
    /// Absolute ones must **not** claim one: an external tool reporting inside a
    /// system header is not reporting under the source root.
    #[test]
    fn only_relative_paths_are_declared_relative_to_the_source_root() {
        let rel = Finding::new(
            "sda.static.c",
            "R",
            "t",
            Severity::Medium,
            Location::new("src/main.c", 1, 1),
        );
        let abs = Finding::new(
            "ext.clang-tidy",
            "R",
            "t",
            Severity::Medium,
            Location::new("C:/Program Files/vendor/include/map", 1, 1),
        );
        let s = to_sarif(&Report::new("proj", vec![rel, abs]));
        let at = |i: usize| {
            s["runs"][0]["results"][i]["locations"][0]["physicalLocation"]["artifactLocation"]
                .clone()
        };
        let (a, b) = (at(0), at(1));
        let (relative, absolute) =
            if a["uri"].as_str().unwrap().starts_with("src/") { (a, b) } else { (b, a) };

        assert_eq!(relative["uriBaseId"], SRCROOT, "{relative}");
        assert!(absolute.get("uriBaseId").is_none(), "{absolute}");
        assert!(s["runs"][0]["originalUriBaseIds"][SRCROOT].is_object());
    }

    /// The schema this file names has to exist. The previous value —
    /// `raw.githubusercontent.com/oasis-tcs/sarif-spec/master/…` — returned 404
    /// after the repository renamed its default branch, so every document the
    /// toolkit emitted pointed at nothing.
    ///
    /// The assertion is on the *host*, not on reachability: a test that fetches
    /// a URL fails on an aeroplane and passes for the wrong reason behind a
    /// caching proxy. What it pins is the decision — the specification's own
    /// address rather than a mirror of a repository that can move again.
    #[test]
    fn the_schema_uri_is_the_normative_one() {
        assert!(
            SARIF_SCHEMA.starts_with("https://docs.oasis-open.org/sarif/"),
            "the schema must be cited at OASIS, not at a mirror: {SARIF_SCHEMA}"
        );
        assert!(SARIF_SCHEMA.ends_with("sarif-schema-2.1.0.json"));
        assert!(
            !SARIF_SCHEMA.contains("githubusercontent"),
            "that mirror is what 404'd"
        );
    }

    /// The engine collects the source around every finding and the text report
    /// prints it; SARIF dropped it, so a viewer showed a file, a line number and
    /// no code. Reported by the SARIF reference implementation as `SARIF2010`
    /// and `SARIF2011`, twenty times each on one real scan.
    #[test]
    fn a_finding_carries_its_source_into_sarif() {
        let mut f = Finding::new(
            "sda.static.c",
            "MISRA-C-2023-21.6",
            "no stdio",
            Severity::Medium,
            Location::new("src/main.c", 3, 1),
        );
        f.evidence.push(crate::Evidence::source(
            Location::new("src/main.c", 3, 1),
            2,
            "line two\nline three\nline four",
        ));

        let s = to_sarif(&Report::new("proj", vec![f]));
        let loc = &s["runs"][0]["results"][0]["locations"][0]["physicalLocation"];

        assert_eq!(
            loc["region"]["snippet"]["text"], "line three",
            "the result's own line: {loc}"
        );
        assert_eq!(loc["contextRegion"]["startLine"], 2);
        assert_eq!(loc["contextRegion"]["endLine"], 4);
        assert!(
            loc["contextRegion"]["snippet"]["text"]
                .as_str()
                .is_some_and(|t| t.contains("line four")),
            "the surrounding block travels too: {loc}"
        );
    }

    /// Evidence naming a different file must not be borrowed: a snippet quoted
    /// against the wrong location is worse than none, because it looks right.
    #[test]
    fn a_snippet_from_another_file_is_not_used() {
        let mut f = Finding::new(
            "sda.static.c",
            "R",
            "t",
            Severity::Medium,
            Location::new("src/main.c", 3, 1),
        );
        f.evidence.push(crate::Evidence::source(
            Location::new("src/other.c", 3, 1),
            2,
            "not this file",
        ));

        let s = to_sarif(&Report::new("proj", vec![f]));
        let loc = &s["runs"][0]["results"][0]["locations"][0]["physicalLocation"];
        assert!(loc.get("contextRegion").is_none(), "{loc}");
        assert!(loc["region"].get("snippet").is_none(), "{loc}");
    }

    #[test]
    fn emits_wellformed_sarif_envelope() {
        let s = to_sarif(&report());
        assert_eq!(s["version"], SARIF_VERSION);
        assert_eq!(s["runs"][0]["tool"]["driver"]["name"], "StatodynamicAnalysis");
        assert_eq!(s["runs"][0]["results"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn windows_paths_are_normalized_to_uri_slashes() {
        let s = to_sarif(&report());
        let uri = &s["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
            ["artifactLocation"]["uri"];
        assert_eq!(uri, "src/io.c");
    }

    #[test]
    fn correlation_verdict_survives_into_properties() {
        let s = to_sarif(&report());
        assert_eq!(s["runs"][0]["results"][0]["properties"]["sda/verdict"], "refuted");
    }

    #[test]
    fn severity_maps_onto_sarif_levels() {
        assert_eq!(level_for(Severity::Critical), "error");
        assert_eq!(level_for(Severity::Medium), "warning");
        assert_eq!(level_for(Severity::Low), "note");
        assert_eq!(level_for(Severity::Info), "none");
    }

    /// SARIF lets a region be binary. Emitting `startLine: 1` for an opcode
    /// four kilobytes into a pickle told every consumer to highlight the first
    /// line of a file that has no lines.
    #[test]
    fn a_byte_located_finding_emits_a_binary_region() {
        let f = Finding::new(
            "sda.ai.artifact",
            "AI-UNSAFE-DESERIALIZATION",
            "t",
            Severity::Critical,
            Location::file_only("model.pkl").at_bytes(0x1030, Some(0x1048)),
        );
        let s = to_sarif(&Report::new("/p", vec![f]));
        let region = &s["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"];

        assert_eq!(region["byteOffset"], 0x1030);
        assert_eq!(region["byteLength"], 0x18);
        assert!(region.get("startLine").is_none(), "no line may be claimed: {region}");
        assert!(region.get("startColumn").is_none(), "nor a column: {region}");
    }

    /// And a text finding still emits a text region, so the binary case has not
    /// been bolted on at the cost of the ordinary one.
    #[test]
    fn a_text_finding_still_emits_a_line_region() {
        let f = Finding::new(
            "p",
            "R-1",
            "t",
            Severity::High,
            Location::new("a.c", 5, 9).spanning(5, 20),
        );
        let s = to_sarif(&Report::new("/p", vec![f]));
        let region = &s["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"];
        assert_eq!(region["startLine"], 5);
        assert_eq!(region["endColumn"], 20);
        assert!(region.get("byteOffset").is_none());
    }

    #[test]
    fn rules_are_deduplicated_and_indexed() {
        let mk = || {
            Finding::new("p", "R-1", "t", Severity::Low, Location::file_only("a.c"))
        };
        let r = Report::new("/p", vec![mk(), mk()]);
        let s = to_sarif(&r);
        assert_eq!(s["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap().len(), 1);
        assert_eq!(s["runs"][0]["results"][1]["ruleIndex"], 0);
    }

    #[test]
    fn traces_become_code_flows() {
        let f = Finding::new("p", "R-1", "t", Severity::High, Location::file_only("a.c")).evidence(
            Evidence::Trace {
                frames: vec![TraceFrame {
                    location: Location::new("a.c", 5, 1),
                    note: "tainted read".into(),
                    step: 0,
                }],
            },
        );
        let s = to_sarif(&Report::new("/p", vec![f]));
        assert!(s["runs"][0]["results"][0]["codeFlows"].is_array());
    }

    /// The SARIF says what the exit code says.
    ///
    /// Every notification used to carry `level: "note"`, and the invocation
    /// carried a hardcoded `executionSuccessful: true`. That was defensible
    /// while the toolkit had no position of its own on which exclusions
    /// mattered. It has one now: `--fail-on` exits **3** on a run that read
    /// nothing, because a gate that could not run has not been passed.
    ///
    /// So one run told a pipeline two different things -- *no verdict, stop* in
    /// the exit code, *note, for information* in the document -- and a consumer
    /// reading only the document, which is the reason the document exists, got
    /// the softer of the two. This pins them together.
    #[test]
    fn a_run_that_read_nothing_is_an_error_in_the_sarif_too() {
        let r = Report::new("/p", vec![]).with_exclusions(vec![
            crate::provider::Exclusion {
                provider: "sda.discovery".into(),
                reason: "`/p` does not exist, so nothing was checked".into(),
            },
            crate::provider::Exclusion {
                provider: "ext.cppcheck".into(),
                reason: "not on PATH".into(),
            },
        ]);
        let s = to_sarif(&r);
        let inv = &s["runs"][0]["invocations"][0];

        assert_eq!(
            inv["executionSuccessful"],
            serde_json::json!(false),
            "the analysis that was asked for did not happen, and this is the field a              consumer checks before reading anything else"
        );

        let notes = inv["toolExecutionNotifications"].as_array().expect("notifications");
        let discovery = notes
            .iter()
            .find(|n| n["message"]["text"].as_str().unwrap_or("").contains("sda.discovery"))
            .expect("the discovery notice is published");
        assert_eq!(
            discovery["level"], "error",
            "the exit code calls this a stop; the document must not call it a note"
        );

        let provider = notes
            .iter()
            .find(|n| n["message"]["text"].as_str().unwrap_or("").contains("cppcheck"))
            .expect("the provider notice is published");
        assert_eq!(
            provider["level"], "note",
            "and a provider that was never enabled stays a note, or `error` means nothing"
        );
    }

    /// A run that did read something reports success, and no notification is
    /// promoted.
    #[test]
    fn a_run_that_read_something_reports_a_successful_invocation() {
        let r = Report::new("/p", vec![]).with_exclusions(vec![crate::provider::Exclusion {
            provider: "ext.clippy".into(),
            reason: "external provider not enabled".into(),
        }]);
        let s = to_sarif(&r);
        let inv = &s["runs"][0]["invocations"][0];

        assert_eq!(inv["executionSuccessful"], serde_json::json!(true));
        for n in inv["toolExecutionNotifications"].as_array().expect("notifications") {
            assert_eq!(
                n["level"], "note",
                "nothing here prevented the analysis: {n}"
            );
        }
    }

    #[test]
    fn excluded_providers_are_reported_as_notifications() {
        let r = Report::new("/p", vec![]).with_exclusions(vec![crate::provider::Exclusion {
            provider: "ext.cppcheck".into(),
            reason: "not on PATH".into(),
        }]);
        let s = to_sarif(&r);
        let n = &s["runs"][0]["invocations"][0]["toolExecutionNotifications"];
        assert!(n.as_array().unwrap()[0]["message"]["text"].as_str().unwrap().contains("cppcheck"));
    }

    /// A notification says what is not covered, not that something failed to run.
    ///
    /// Every exclusion used to be rendered `provider `X` did not run`, which was
    /// written when the only exclusions were absent external tools. It is false
    /// of a provider that ran and reached no conclusion — and that difference,
    /// between a check that was skipped and a check that came back with nothing
    /// to say, is the one this whole toolkit exists to keep.
    #[test]
    fn a_notification_does_not_claim_a_provider_failed_to_run() {
        let r = Report::new("/p", vec![]).with_exclusions(vec![
            crate::provider::Exclusion {
                provider: "sda.interposition".into(),
                reason: "no model/effector pair was available to prove anything about".into(),
            },
            crate::provider::Exclusion {
                provider: "sda.config".into(),
                reason: "architecture entry `llm-judge` rejected".into(),
            },
        ]);
        let s = to_sarif(&r);
        let n = s["runs"][0]["invocations"][0]["toolExecutionNotifications"].clone();
        let texts: Vec<String> = n
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v["message"]["text"].as_str().unwrap().to_string())
            .collect();

        for t in &texts {
            assert!(
                !t.contains("did not run"),
                "interposition ran and concluded nothing, and `sda.config` is not a provider \
                 at all: {t}"
            );
            assert!(t.contains("NOT CHECKED"), "each maps to the report's own section: {t}");
        }
        assert!(texts.iter().any(|t| t.contains("llm-judge")), "and keeps the reason: {texts:?}");

        // The machine key stays put; consumers match on it.
        assert_eq!(n[0]["descriptor"]["id"], "sda/providerExcluded");
    }
}
