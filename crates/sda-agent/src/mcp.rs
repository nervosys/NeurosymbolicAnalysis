//! An MCP tool surface over the whole toolkit.
//!
//! This is what "agentic-first" means concretely: the toolkit's capabilities are
//! published as typed, self-describing tools that any MCP-speaking agent can
//! discover and call, rather than as a CLI a model has to guess the flags for.
//!
//! Every tool's description states its limits as well as its function, because
//! an agent choosing between `analysis.scan` and `analysis.statodynamic` needs to
//! know that the first cannot confirm anything.
//!
//! The transport is JSON-RPC 2.0 over stdio, which is the MCP baseline.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{BufRead, Write};

pub const PROTOCOL_VERSION: &str = "2024-11-05";
pub const SERVER_NAME: &str = "statodynamic-analysis";

/// A tool the server publishes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ToolDef {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

fn tool(name: &str, description: &str, properties: Value, required: &[&str]) -> ToolDef {
    ToolDef {
        name: name.into(),
        description: description.into(),
        input_schema: json!({
            "type": "object",
            "properties": properties,
            "required": required,
        }),
    }
}

/// The published tool surface.
pub fn tools() -> Vec<ToolDef> {
    vec![
        tool(
            "ontology.search",
            "Search the statodynamic analysis tool ontology by capability, language, name, or \
             classification scheme. Returns each tool with its soundness, cost, and — importantly \
             — a statement of what it cannot establish. Use this before choosing an analysis \
             approach rather than guessing which tool applies.",
            json!({ "query": { "type": "string", "description": "e.g. `memory-safety`, `MISRA`, `fuzzing`" } }),
            &["query"],
        ),
        tool(
            "ontology.describe",
            "Describe one tool in full, including alternatives that provide the same capability.",
            json!({ "id": { "type": "string", "description": "tool id, e.g. `sda.static.c` or `ext.cbmc`" } }),
            &["id"],
        ),
        tool(
            "ontology.gaps",
            "Given a language and the set of installed tools, list the analysis capabilities that \
             nothing available covers. This is how to find out what a run will NOT check.",
            json!({
                "language": { "type": "string", "enum": ["c", "cpp", "rust", "model-artifact"] },
                "available": { "type": "array", "items": { "type": "string" } }
            }),
            &["language"],
        ),
        tool(
            "rules.lookup",
            "Look up a coding-standard guideline by id or search text. Returns its category, \
             whether it is decidable, how this toolkit checks it, and whether its number is \
             confirmed against the published standard.",
            json!({
                "query": { "type": "string" },
                "standard": { "type": "string", "enum": ["misra-c-2023", "misra-cpp-2023", "rust-2024"] }
            }),
            &["query"],
        ),
        tool(
            "rules.audit",
            "Report, for a standard, how many guidelines a default run actually exercises and for \
             how many a clean result constitutes evidence of conformance. Call this before \
             reporting compliance to anyone.",
            json!({ "standard": { "type": "string", "enum": ["misra-c-2023", "misra-cpp-2023", "rust-2024"] } }),
            &["standard"],
        ),
        tool(
            "plan.create",
            "Produce a deterministic analysis plan for a project: which providers to run, in what \
             order, and an explicit list of what the plan will not cover and how to close each gap.",
            json!({
                "path": { "type": "string" },
                "allow_external": { "type": "boolean", "description": "permit non-native tools (default false)" },
                "artifact": { "type": "string", "description": "path to a built binary, enabling dynamic analysis" }
            }),
            &["path"],
        ),
        tool(
            "analysis.scan",
            "Run static analysis over a project with the native engines, which read the source \
             and run none of it. The project's `.sda/` deviations apply, so a tree you did not \
             write can suppress its own findings; the summary counts what was suppressed. \
             LIMIT: static only — no finding is confirmed or refuted by execution, and code that \
             never runs is indistinguishable from code that runs correctly.",
            json!({
                "path": { "type": "string" },
                "allow_external": {
                    "type": "boolean",
                    "description": "also run installed external tools in the project (default false). cargo clippy, miri and verus build a Rust project, which runs its build scripts and macros: only for trusted code"
                },
                "severity_at_least": { "type": "string", "enum": ["info", "low", "medium", "high", "critical"] }
            }),
            &["path"],
        ),
        tool(
            "analysis.statodynamic",
            "Run static analysis, execute the built artifact, and correlate the two. Returns \
             findings ranked with runtime-confirmed defects first, plus coverage gaps. This is the \
             only mode that can confirm or refute a static finding. RUNS CODE: `artifact` may be \
             any executable, and it inherits this server's environment.",
            json!({
                "path": { "type": "string" },
                "artifact": { "type": "string", "description": "path to the built binary to execute" },
                "args": { "type": "array", "items": { "type": "string" } }
            }),
            &["path", "artifact"],
        ),
        tool(
            "analysis.triage",
            "Read or record review state for findings: `open`, `acknowledged`, `accepted`, `false-positive`. Omit `id` to list every record and the stale ones. This is the same `.sda/triage.toml` the workbench reads and writes, so a human and an agent working the same backlog see one state rather than two. LIMITS: triage annotates, it never suppresses — a finding recorded here still appears in every report and in every exit code. Suppression is a *deviation*, which needs an approver and a rationale and is refused outright for a Mandatory guideline. `accepted` here makes no compliance claim and nothing validates it against a catalogue. Records whose finding did not appear in the last run are returned as `stale` rather than deleted: the code moved under a conclusion someone reached, and `fixed` cannot be told from `moved and now unreviewed`. `assign` and `comment` are the hybrid half: a person and an agent share one namespace, so a human can hand a batch to an agent and read back what it concluded, in the same file. Both conclude nothing on their own — an assigned finding is still unreviewed.",
            json!({
                "path": { "type": "string" },
                "id": {
                    "type": "string",
                    "description": "finding id to record against; omit to list"
                },
                "state": {
                    "type": "string",
                    "enum": ["open", "acknowledged", "accepted", "false-positive"],
                    "description": "`open` removes the record rather than storing it"
                },
                "note": { "type": "string", "description": "why; the point of the other states" },
                "by": { "type": "string", "description": "who concluded it, or the agent acting" },
                "assign": {
                    "type": "string",
                    "description": "hand the finding to a person or an agent (`a.erickson`, `agent:triage-bot`); empty string unassigns. Assigning concludes nothing"
                },
                "comment": {
                    "type": "string",
                    "description": "append a remark to the finding's discussion, attributed to `by`. Append-only; commenting concludes nothing"
                }
            }),
            &["path"],
        ),
        tool(
            "analysis.baseline",
            "Report which findings are new relative to a recorded baseline, or set the baseline to this run. Omit `set` to read. LIMITS: with no baseline recorded, `new` is null for every finding — unknown, not zero; a tool that reported `not new` when nothing was recorded would be claiming a comparison it never made. The baseline is only ever written on request, because one refreshed by every scan reports zero new findings forever and looks like it is working. `new` means absent from the recorded set and nothing more: it is not a claim about a commit or an author, and a finding can be new because a rule was added or a provider was enabled. `resolved` counts what the baseline held and this run did not produce — fixed, moved, or filtered out by a scope change all look identical from here.",
            json!({
                "path": { "type": "string" },
                "set": {
                    "type": "boolean",
                    "description": "record this run as the new baseline; omit or false to read"
                },
                "note": { "type": "string", "description": "what the project was when set" }
            }),
            &["path"],
        ),
        tool(
            "analysis.verify",
            "Prove that a model's output cannot reach an effector without crossing a guard, over \
             the architecture declared in `.sda/architecture.toml`, and optionally let a taint \
             report or a prover's output refute it. LIMITS: the proof is over the *declaration*, \
             not the code — `not_checked` always carries `flow::declaration-faithful`, the premise \
             that the two agree. A taint report can only refute; a clean one establishes nothing, \
             and a finding with no dataflow trace cannot refute at all (`taint_findings_with_flow` \
             says how many could). `interposed: null` means no architecture was declared, which is \
             not a pass. Read `not_checked` before the booleans.",
            json!({
                "path": { "type": "string" },
                "taint": {
                    "type": "string",
                    "description": "SARIF or sda JSON report from a taint provider; refutes only"
                },
                "proofs": {
                    "type": "string",
                    "description": "verus --output-json stdout; pair with proof_log"
                },
                "proof_log": {
                    "type": "string",
                    "description": "verus stderr, the only place failing obligations are named"
                }
            }),
            &["path"],
        ),
        tool(
            "ai.scan_model",
            "Scan a serialized AI model artifact. Parses GGUF, safetensors, pickle and PyTorch zip \
             containers natively and reports code-execution paths, malformed offsets, missing \
             provenance and tokenizer anomalies. LIMIT: reads the container, not the weights — no \
             header inspection can reveal a backdoor. Any readable path is accepted, and the \
             response carries its size, digest and any names a pickle scan extracted.",
            json!({ "path": { "type": "string", "description": "model file or a directory to walk" } }),
            &["path"],
        ),
        tool(
            "ai.probe_suite",
            "Return the behavioural probe suite for a model, optionally seeded with trigger \
             candidates found by a prior artifact scan. Responses are supplied back through \
             `ai.evaluate_probes`; this tool does not call any model itself.",
            json!({ "triggers": { "type": "array", "items": { "type": "string" } } }),
            &[],
        ),
        tool(
            "ai.evaluate_probes",
            "Judge probe responses and produce findings. A probe that fires demonstrates a \
             behaviour; a probe that does not fire demonstrates nothing.",
            json!({
                "responses": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "probe_id": { "type": "string" },
                            "response": { "type": "string" },
                            "baseline_response": { "type": "string" }
                        },
                        "required": ["probe_id", "response"]
                    }
                },
                "model_path": { "type": "string" }
            }),
            &["responses"],
        ),
        tool(
            "analysis.impact",
            "Which files name the external symbols a file defines: what else is downstream of a change. LIMITS: the answer is a FLOOR, not the set. Reach is found by matching identifier tokens against the names the subject defines, so it finds every caller that spells the name and misses every one that does not — a call through a function pointer, a name the preprocessor assembles, a linker alias, a `dlsym` lookup. Each omission removes a file from the answer, so read `referenced_by` as *at least these* and never as *only these*; the `floor` field in every response says so and is not optional. Over-reporting would cost a reviewer an afternoon, while under-reporting tells them a change is contained when it is not, which is the direction this errs in. C translation units only: C++ overloads and templates need a front end. Where a `compile_commands.json` exists, `ext.clang-tidy` and `ext.codeql` answer this with types behind them and are the better tool. Internal linkage is excluded, because a `static` function of the same name in another file is a different function.",
            json!({
                "path": { "type": "string" },
                "file": {
                    "type": "string",
                    "description": "the file about to change, relative to `path`"
                }
            }),
            &["path", "file"],
        ),
        tool(
            "analysis.hotspots",
            "Files carrying findings, ranked by how often they change. Answers `where do I start` on a report too long to read: a scan of PX4 produces 78,211 findings ordered by severity, then confidence, then path, so the low ones arrive alphabetically. LIMITS: churn is NOT a defect and this ranking is NOT a measurement. The findings are measured; the order is findings x commits, offered as somewhere to begin, and no file is worse than another for having been edited. A number like this one step away from being read as a risk score, which would be a claim about code assembled from facts about a team. If the history cannot be read — no checkout, or a SHALLOW clone, which is what CI produces by default — `history_available` is false and every count is null rather than zero: `git log` succeeds on a shallow clone and reports one commit naming every file, so a count built from it would say the whole project is settled. A null is not a zero.",
            json!({
                "path": { "type": "string" },
                "days": {
                    "type": "integer",
                    "description": "how far back to read history; default 180"
                },
                "top": { "type": "integer", "description": "how many files to return; default 20" }
            }),
            &["path"],
        ),
        tool(
            "build.detect",
            "Detect the project's build system and compilers, and report whether semantics-level \
             analysis is currently possible and what to run if it is not.",
            json!({ "path": { "type": "string" } }),
            &["path"],
        ),
        tool(
            "build.compile",
            "Build the project, optionally with an instrumentation profile. Returns parsed \
             diagnostics and an explicit list of any instrumentation the toolchain could not \
             provide, so an 'instrumented' build that is not instrumented cannot be mistaken for \
             one that is. RUNS CODE: building runs the project's own build scripts, so call it \
             only on code you trust.",
            json!({
                "path": { "type": "string" },
                "profile": { "type": "string", "enum": ["static", "dynamic", "none"] }
            }),
            &["path"],
        ),
        tool(
            "swe.iterate",
            "Run one iteration of the autonomous loop: build, collect diagnostics, and return the \
             single most actionable next problem with its source context. Apply a patch yourself, \
             then call again. Session state persists across calls, so the loop detects when you \
             are stalling (same diagnostics after a patch) or thrashing (each fix undoing the \
             last). It refuses to declare success while errors remain. RUNS CODE: each iteration \
             builds the project, which runs its build scripts.",
            json!({
                "path": { "type": "string" },
                "max_context_lines": { "type": "integer" },
                "reset": { "type": "boolean", "description": "discard loop history and start a fresh attempt" }
            }),
            &["path"],
        ),
        tool(
            "fuzz.campaign",
            "Generate inputs to drive a built target into unexplored code, then correlate what was \
             reached against the static findings — turning `unreached` verdicts into confirmed or \
             refuted ones. Crashes are deduplicated by defect and saved as reproducing inputs. \
             LIMIT: the target must link the SDA probe instrumentation, or the campaign is blind \
             random generation rather than guided fuzzing, and the result says so. No crash found \
             never means none exists. RUNS CODE: `artifact` may be any executable, and it inherits \
             this server's environment.",
            json!({
                "artifact": { "type": "string", "description": "the instrumented binary to fuzz" },
                "path": { "type": "string", "description": "project root, for correlation" },
                "corpus": { "type": "string", "description": "directory of seed inputs" },
                "runs": { "type": "integer" },
                "seed": { "type": "integer", "description": "the same seed replays the same campaign" },
                "budget_secs": { "type": "integer" },
                "stop_on_crash": { "type": "boolean" }
            }),
            &["artifact"],
        ),
        tool(
            "report.query",
            "Query a previously produced report: filter by severity, rule, provider, or \
             correlation verdict. Any readable path is accepted.",
            json!({
                "report_path": { "type": "string" },
                "verdict": { "type": "string", "enum": ["confirmed", "refuted", "unreached", "inconclusive", "unpredicted", "proved", "assumed"] },
                "severity_at_least": { "type": "string" }
            }),
            &["report_path"],
        ),
    ]
}

// --- JSON-RPC plumbing ------------------------------------------------------

#[derive(Debug, Deserialize)]
struct Request {
    #[allow(dead_code)]
    jsonrpc: Option<String>,
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

fn ok(id: Option<Value>, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn err(id: Option<Value>, code: i32, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// Handle one request. Pure, so the whole protocol surface is testable without
/// spawning a process or opening a pipe.
pub fn handle(request: &str, dispatch: &dyn Fn(&str, &Value) -> Result<Value, String>) -> Option<Value> {
    let req: Request = match serde_json::from_str(request) {
        Ok(r) => r,
        Err(e) => return Some(err(None, -32700, &format!("parse error: {e}"))),
    };

    match req.method.as_str() {
        "initialize" => Some(ok(
            req.id,
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": { "name": SERVER_NAME, "version": env!("CARGO_PKG_VERSION") }
            }),
        )),
        // Notifications carry no id and expect no response.
        m if m.starts_with("notifications/") => None,
        "tools/list" => Some(ok(req.id, json!({ "tools": tools() }))),
        "tools/call" => {
            let name = req.params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let args = req.params.get("arguments").cloned().unwrap_or_else(|| json!({}));
            match dispatch(name, &args) {
                Ok(result) => Some(ok(
                    req.id,
                    json!({
                        "content": [{ "type": "text", "text": render(&result) }],
                        "isError": false
                    }),
                )),
                // A tool failure is reported as tool content with `isError`, not
                // as a protocol error: the agent needs to read what went wrong
                // and adapt, not see a transport fault.
                Err(e) => Some(ok(
                    req.id,
                    json!({ "content": [{ "type": "text", "text": e }], "isError": true }),
                )),
            }
        }
        "ping" => Some(ok(req.id, json!({}))),
        other => Some(err(req.id, -32601, &format!("unknown method `{other}`"))),
    }
}

/// Render a tool result as text. Strings pass through so prose stays readable;
/// anything else becomes pretty JSON.
fn render(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => serde_json::to_string_pretty(other).unwrap_or_else(|_| other.to_string()),
    }
}

/// Serve MCP over stdio until the input closes.
pub fn serve_stdio(dispatch: &dyn Fn(&str, &Value) -> Result<Value, String>) -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(response) = handle(&line, dispatch) {
            writeln!(stdout, "{response}")?;
            stdout.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stub(_name: &str, _args: &Value) -> Result<Value, String> {
        Ok(json!("stub result"))
    }

    #[test]
    fn initialize_reports_the_protocol_and_server() {
        let r = handle(r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#, &stub).unwrap();
        assert_eq!(r["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(r["result"]["serverInfo"]["name"], SERVER_NAME);
        assert_eq!(r["id"], 1);
    }

    #[test]
    fn tools_list_publishes_every_tool_with_a_schema() {
        let r = handle(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#, &stub).unwrap();
        let tools = r["result"]["tools"].as_array().unwrap();

        // Every tool `tools()` defines has to reach the wire, by name. This read
        // `>= 14` against a surface of nineteen, so five could have disappeared
        // between the definition and the response without a word — and what an
        // agent can do is exactly what this list says it can do.
        let published: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        let defined = super::tools();
        let defined: Vec<&str> = defined.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(published, defined, "`tools/list` does not publish what `tools()` defines");

        for t in tools {
            assert!(t["name"].is_string());
            assert!(t["inputSchema"]["type"] == "object");
            assert!(t["description"].as_str().unwrap().len() > 40);
        }
    }

    #[test]
    fn every_analysis_tool_states_its_limits_in_its_description() {
        // The property that makes the surface usable by an agent that cannot
        // read the source: it must be told what a tool does not establish.
        for name in ["analysis.scan", "analysis.verify", "ai.scan_model", "ai.evaluate_probes"] {
            let t = tools().into_iter().find(|t| t.name == name).unwrap();
            let d = t.description.to_lowercase();
            assert!(
                d.contains("limit") || d.contains("nothing") || d.contains("cannot"),
                "`{name}` does not state its limits"
            );
        }
    }

    /// The verify tool's description has to carry the one thing an agent cannot
    /// derive: that the proof is over a declaration, not over the code.
    #[test]
    fn the_verify_tool_publishes_the_premise_its_result_rests_on() {
        let t = tools().into_iter().find(|t| t.name == "analysis.verify").unwrap();
        assert!(
            t.description.contains("flow::declaration-faithful"),
            "an agent reading `interposed: true` must be told what it was proved over"
        );
        assert!(
            t.description.contains("can only refute"),
            "and that a clean taint run establishes nothing"
        );
        assert!(
            t.description.contains("is not a pass"),
            "and that an undeclared project is not a clean one"
        );
    }

    #[test]
    fn tool_calls_dispatch_by_name_and_return_content() {
        let r = handle(
            r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ontology.search","arguments":{"query":"fuzz"}}}"#,
            &|name, args| {
                assert_eq!(name, "ontology.search");
                assert_eq!(args["query"], "fuzz");
                Ok(json!("found"))
            },
        )
        .unwrap();
        assert_eq!(r["result"]["isError"], false);
        assert_eq!(r["result"]["content"][0]["text"], "found");
    }

    #[test]
    fn a_tool_failure_is_content_the_agent_can_read_not_a_transport_error() {
        let r = handle(
            r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"x"}}"#,
            &|_, _| Err("no compile_commands.json; run `sda build compile-commands`".into()),
        )
        .unwrap();
        assert_eq!(r["result"]["isError"], true);
        assert!(r["result"]["content"][0]["text"].as_str().unwrap().contains("compile-commands"));
        assert!(r.get("error").is_none(), "a tool failure is not a protocol failure");
    }

    #[test]
    fn notifications_get_no_response() {
        assert!(handle(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#, &stub).is_none());
    }

    #[test]
    fn malformed_input_produces_a_parse_error_rather_than_a_panic() {
        let r = handle("{not json", &stub).unwrap();
        assert_eq!(r["error"]["code"], -32700);
    }

    #[test]
    fn unknown_methods_are_rejected_with_the_standard_code() {
        let r = handle(r#"{"jsonrpc":"2.0","id":9,"method":"nope"}"#, &stub).unwrap();
        assert_eq!(r["error"]["code"], -32601);
    }

    #[test]
    fn structured_results_are_rendered_as_readable_json() {
        let r = handle(
            r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"x"}}"#,
            &|_, _| Ok(json!({ "findings": 3 })),
        )
        .unwrap();
        let text = r["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"findings\": 3"));
    }

    #[test]
    fn tool_names_are_namespaced_and_unique() {
        let names: Vec<String> = tools().into_iter().map(|t| t.name).collect();
        let unique: std::collections::BTreeSet<&String> = names.iter().collect();
        assert_eq!(names.len(), unique.len());
        assert!(names.iter().all(|n| n.contains('.')));
    }
}
