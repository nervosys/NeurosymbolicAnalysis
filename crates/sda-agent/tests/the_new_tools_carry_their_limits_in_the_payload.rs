//! `analysis.impact` and `analysis.hotspots`, over MCP, with their caveats.
//!
//! Both answer questions repowise is built around — blast radius and hotspots —
//! and both are wrong in a way a caller cannot see. A human gets the caveat
//! because `sda impact` prints it above the table. An agent gets whatever is in
//! the payload.
//!
//! The tool *description* is not enough. It is read once, by whatever assembled
//! the tool list, possibly weeks before the call; the response is read every
//! time and is what the agent acts on. `the_mcp_surface_reports_what_the_declared_scope_removed`
//! makes the same argument about a narrowed scan: "an agent cannot see a
//! narrowed scan the way a human reading a terminal can, so the MCP surface has
//! to say what it skipped in the payload itself".
//!
//! Two claims are asserted here, and each is the one its tool would be believed
//! about:
//!
//! * impact answers a **floor**, and a file reaching the subject through a
//!   function pointer is absent from it by construction;
//! * hotspots reports `null`, never `0`, when the history could not be read —
//!   because `git log` succeeds on a shallow clone and a zero there would say
//!   the whole project is settled.

use sda_agent::dispatch::dispatch;
use serde_json::json;

fn fixture(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("sda-mcp-newtools-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("a scratch project");
    std::fs::write(
        dir.join("src").join("lib.c"),
        "int compute(int x) { return x + 1; }\nstatic int helper(void) { return 0; }\n",
    )
    .expect("the subject");
    std::fs::write(
        dir.join("src").join("app.c"),
        "int compute(int x);\nint main(void) { return compute(2); }\n",
    )
    .expect("a caller by name");
    std::fs::write(
        dir.join("src").join("indirect.c"),
        "typedef int (*fn)(int);\nfn get(void);\nint go(void) { fn f = get(); return f(1); }\n",
    )
    .expect("a caller through a pointer");
    dir
}

/// The floor reaches the caller, in the payload.
#[test]
fn impact_tells_the_agent_its_answer_is_a_floor() {
    let dir = fixture("impact");
    let out = dispatch(
        "analysis.impact",
        &json!({ "path": dir.to_string_lossy(), "file": "src/lib.c" }),
    )
    .expect("the tool runs");

    assert_eq!(out["defines"], json!(["compute"]), "`helper` is static: {out:#}");
    assert!(
        out["referenced_by"].get("src/app.c").is_some(),
        "the caller that names it is found: {out:#}"
    );
    assert!(
        out["referenced_by"].get("src/indirect.c").is_none(),
        "the premise: the indirect caller is missing, which is why the floor has to be \
         published: {out:#}"
    );

    assert_eq!(out["floor"], json!(true), "a caller reading keys meets the word: {out:#}");
    let not_checked = out["not_checked"].as_array().expect("an array");
    assert!(
        not_checked.iter().any(|n| n.as_str().unwrap_or_default().contains("function pointer")),
        "and it names a way the list is short, so it reads as a fact rather than a \
         disclaimer: {out:#}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// An unreadable history is `null`, never `0`.
///
/// The fixture is not a git checkout, which reaches the same branch a shallow
/// clone does and costs no clone to build. A `0` in `commits` here would tell an
/// agent the file is settled on the strength of a query that never ran.
#[test]
fn hotspots_reports_null_rather_than_zero_when_it_cannot_read_history() {
    let dir = fixture("hotspots");
    let out = dispatch("analysis.hotspots", &json!({ "path": dir.to_string_lossy() }))
        .expect("the tool runs");

    assert_eq!(
        out["history_available"],
        json!(false),
        "the fixture is not a checkout: {out:#}"
    );

    let files = out["files"].as_array().expect("an array of rows");
    assert!(!files.is_empty(), "the fixture has findings, so it has rows: {out:#}");
    for row in files {
        assert_eq!(
            row["commits"],
            serde_json::Value::Null,
            "a zero here is a number nobody counted, and an agent has no terminal to read \
             the caveat from: {row:#}"
        );
        assert_eq!(row["authors"], serde_json::Value::Null, "{row:#}");
    }

    let not_checked = out["not_checked"].as_array().expect("an array");
    assert!(
        !not_checked.is_empty(),
        "and the reason is published rather than left to be inferred from the nulls: {out:#}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Neither tool lets its ranking pass as a measurement.
#[test]
fn hotspots_says_the_order_is_not_a_measurement() {
    let dir = fixture("limits");
    let out = dispatch("analysis.hotspots", &json!({ "path": dir.to_string_lossy() }))
        .expect("the tool runs");

    let limits = out["limits"].as_str().expect("a limits string");
    assert!(
        limits.contains("Churn is not a defect"),
        "this is one step from being read as a risk score, which would be a claim about \
         code assembled from facts about a team: {limits}"
    );
    assert!(
        limits.contains("findings are measured"),
        "and the distinction between the measured half and the offered half is the whole \
         of what keeps it honest: {limits}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// An empty ranking tells the agent that nothing was scanned.
///
/// `report_json` publishes every exclusion under `not_checked` for the scan
/// tools. `analysis.hotspots` built its own `not_checked` from the history
/// notice alone and dropped `report.exclusions`, so the engine's own
/// `sda.discovery` — *no enabled provider read anything here, every count is a
/// count of nothing* — was computed and discarded on the way out.
///
/// What an agent received for a mistyped path was `files: []`,
/// `files_with_findings: 0`, and a `not_checked` holding one true remark about
/// git. Every field correct, and nothing anywhere saying the scan read nothing.
///
/// The CLI had the same defect and was fixed first; this is its twin, and the
/// worse of the two. A person scanning a hotspots table might notice the
/// directory looked wrong on the way past. An agent has no way past.
#[test]
fn hotspots_tells_the_agent_when_nothing_was_scanned_at_all() {
    let dir = std::env::temp_dir().join("sda-mcp-hotspots-nothing-scanned");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    std::fs::write(dir.join("README.txt"), "not source\n").expect("a file");

    let out = dispatch("analysis.hotspots", &json!({ "path": dir.to_string_lossy() }))
        .expect("the tool runs");

    assert_eq!(out["files_with_findings"], json!(0), "the premise: {out:#}");

    let not_checked = out["not_checked"].as_array().expect("a not_checked array");
    let joined: String =
        not_checked.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(" | ");
    assert!(
        joined.contains("count of nothing"),
        "a zero from a scan that read nothing has to say so: {out:#}"
    );
    assert!(
        joined.contains("describes the scan, not the code"),
        "which is the whole difference between this and a quiet project: {out:#}"
    );

    // Ahead of the history remark, which is about how rows are ordered rather
    // than whether any row could have existed.
    let discovery = not_checked
        .iter()
        .position(|v| v.as_str().is_some_and(|s| s.contains("count of nothing")));
    let git = not_checked
        .iter()
        .position(|v| v.as_str().is_some_and(|s| s.contains("not a git checkout")));
    if let (Some(d), Some(g)) = (discovery, git) {
        assert!(d < g, "the reason there is nothing to rank comes first: {out:#}");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// And a project that really was scanned carries no such entry, so the tool's
/// `not_checked` stays worth reading rather than becoming furniture.
#[test]
fn hotspots_adds_no_discovery_entry_for_a_project_it_read() {
    let dir = fixture("read");
    let out = dispatch("analysis.hotspots", &json!({ "path": dir.to_string_lossy() }))
        .expect("the tool runs");

    let joined: String = out["not_checked"]
        .as_array()
        .expect("a not_checked array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>()
        .join(" | ");
    assert!(
        !joined.contains("count of nothing"),
        "this tree holds C and was read: {out:#}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A baseline is not recorded from a scan that read nothing.
///
/// Everything else in the dispatch layer reports and lets the caller decide.
/// `analysis.baseline` with `set: true` writes `.sda/baseline.toml`, and what it
/// would write is what makes refusing right: a baseline records *these findings
/// are the accepted state*, so one taken from a mistyped path records the empty
/// set, and every later run compares against it and reports nothing new. The
/// false clean result stops being this run's answer and becomes the project's.
///
/// It is the only failure of this kind in the codebase that does not expire.
#[test]
fn a_baseline_is_refused_when_the_scan_read_nothing() {
    let dir = std::env::temp_dir().join("sda-mcp-baseline-nothing-scanned");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    std::fs::write(dir.join("README.txt"), "not source\n").expect("a file");

    let err = dispatch(
        "analysis.baseline",
        &json!({ "path": dir.to_string_lossy(), "set": true }),
    )
    .expect_err("recording the empty set as the accepted state must not succeed");

    assert!(
        err.contains("read nothing"),
        "the refusal has to say what was wrong with the run: {err}"
    );
    assert!(
        err.contains("report nothing new"),
        "and what recording it would have cost later: {err}"
    );
    assert!(
        !dir.join(".sda").join("baseline.toml").exists(),
        "nothing may be written when the record would be of nothing"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// And a project that really was scanned still records one, because a
/// genuinely clean tree has every right to an empty baseline.
///
/// This is the half that keeps the refusal narrow. A guard that fires whenever
/// a baseline would be empty would block the ordinary and correct case of
/// baselining a project with nothing wrong in it.
#[test]
fn a_baseline_is_still_recorded_for_a_project_that_was_read() {
    let dir = fixture("baseline");
    let out = dispatch(
        "analysis.baseline",
        &json!({ "path": dir.to_string_lossy(), "set": true }),
    )
    .expect("a scanned project records a baseline");

    assert_eq!(out["has_baseline"], json!(true), "{out:#}");
    assert!(
        dir.join(".sda").join("baseline.toml").exists(),
        "the file is the point of the call"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The declared scope reaches the MCP ranking too.
///
/// The CLI and this had two copies of discovery, and only one of them had
/// learned about scope. Fixed by calling `discover_project` — the shared helper
/// that applies it — rather than by adding a third copy of the three steps.
#[test]
fn hotspots_does_not_rank_a_file_the_project_excluded() {
    let dir = std::env::temp_dir().join("sda-mcp-hotspots-scope");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("a scratch project");
    std::fs::create_dir_all(dir.join("legacy")).expect("the excluded directory");
    std::fs::create_dir_all(dir.join(".sda")).expect("the config directory");

    std::fs::write(
        dir.join("src").join("a.c"),
        "int f(int x) {\n  if (x == 1) { goto d; }\n  return 0;\nd:\n  return 1;\n}\n",
    )
    .expect("an in-scope file");
    std::fs::write(
        dir.join("legacy").join("old.c"),
        "int g(int x) {\n  if (x == 1) { goto d; }\n  return 0;\nd:\n  return 1;\n}\n\
         int h(int x) {\n  if (x == 2) { goto e; }\n  return 0;\ne:\n  return 1;\n}\n",
    )
    .expect("an out-of-scope file");
    std::fs::write(
        dir.join(".sda").join("scope.toml"),
        "[[excluded]]\npath = \"legacy/\"\nreason = \"vendored, not maintained here\"\n\
         approver = \"a.erickson\"\n",
    )
    .expect("the scope declaration");

    let out = dispatch("analysis.hotspots", &json!({ "path": dir.to_string_lossy() }))
        .expect("the tool runs");

    let files: Vec<&str> = out["files"]
        .as_array()
        .expect("a files array")
        .iter()
        .filter_map(|f| f["file"].as_str())
        .collect();
    assert!(
        !files.iter().any(|f| f.contains("legacy/old.c")),
        "an excluded file must not be ranked: {out:#}"
    );
    assert!(files.iter().any(|f| f.contains("src/a.c")), "the in-scope one still is: {out:#}");

    let joined: String = out["not_checked"]
        .as_array()
        .expect("a not_checked array")
        .iter()
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>()
        .join(" | ");
    assert!(
        joined.contains("outside the declared analysis scope"),
        "and the agent is told the ranking was narrowed, with the rule's reason: {out:#}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The deviation register reaches the MCP ranking too, and did not.
///
/// This handler assembled its own `RunConfig` instead of calling
/// `project_setup`, so it had neither the declared scope nor the deviation
/// register: it ranked excluded files and counted accepted findings. Fixed by
/// calling the helper, which is the whole of the project's declared position
/// in one place -- a fourth copy of those steps is what produced both defects.
#[test]
fn hotspots_does_not_rank_findings_the_project_deviated() {
    let dir = std::env::temp_dir().join("sda-mcp-hotspots-deviation");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("a scratch project");
    std::fs::create_dir_all(dir.join(".sda")).expect("the config directory");

    let four = "int g(int x) {\n  if (x == 1) { goto d; }\n  return 0;\nd:\n  return 1;\n}\n";
    std::fs::write(dir.join("src").join("a.c"), four).expect("the undeviated file");
    std::fs::write(
        dir.join("src").join("deviated.c"),
        format!(
            "{four}int h(int x) {{\n  if (x == 2) {{ goto e; }}\n  return 0;\ne:\n  return 1;\n}}\n"
        ),
    )
    .expect("the deviated file");
    std::fs::write(
        dir.join(".sda").join("deviations.toml"),
        concat!(
            "[[deviation]]\nrule = \"MISRA-C-2023-15.1\"\nscope = \"file\"\n",
            "path = \"src/deviated.c\"\nrationale = \"accepted idiom\"\n",
            "approver = \"a.erickson\"\n\n",
            "[[deviation]]\nrule = \"MISRA-C-2023-15.5\"\nscope = \"file\"\n",
            "path = \"src/deviated.c\"\nrationale = \"accepted idiom\"\n",
            "approver = \"a.erickson\"\n",
        ),
    )
    .expect("the deviation register");

    let out = dispatch("analysis.hotspots", &json!({ "path": dir.to_string_lossy() }))
        .expect("the tool runs");

    let count = |name: &str| -> u64 {
        out["files"]
            .as_array()
            .expect("a files array")
            .iter()
            .find(|f| f["file"].as_str().is_some_and(|s| s.ends_with(name)))
            .and_then(|f| f["findings"].as_u64())
            .unwrap_or_else(|| panic!("no row for {name}: {out:#}"))
    };
    assert_eq!(
        count("deviated.c"),
        count("a.c"),
        "counting accepted findings ranked the deviated file first: {out:#}"
    );
    assert_eq!(
        out["suppressed_by_deviation"],
        json!(4),
        "and what was not counted is published, so an agent can reconcile this with \
         `analysis.scan` instead of treating one of them as wrong: {out:#}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A stored report keeps its *NOT CHECKED* when it is read back.
///
/// `report.query` loads a report somebody already built. It published the
/// findings and dropped `report.exclusions`, so a stored scan of a tree
/// nothing could read -- eleven exclusions, the first saying every count in
/// it is a count of nothing -- came back as
/// `{"matched": 0, "shown": 0, "findings": []}`.
///
/// The most reassuring possible reply, to an agent, about a scan that read no
/// file. The artifact was honest; the reader was not, which is the worse of
/// the two places for it to go wrong: the artifact is what was archived and
/// this is what anybody asks.
///
/// This is also the test that catches what the source-shape guard cannot.
/// Emptying the vector leaves the identifier `not_checked` in the source and
/// that guard still passes; this one reads the payload.
#[test]
fn report_query_carries_the_stored_reports_own_not_checked() {
    let dir = std::env::temp_dir().join("sda-mcp-report-query-notices");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");

    // A report of a scan that read nothing, written the way `--output` writes
    // it, so this is the real serialised shape rather than a hand-built one.
    let report = sda_core::Report::new(
        dir.to_string_lossy().to_string(),
        Vec::new(),
    )
    .with_exclusions(vec![sda_core::Exclusion {
        provider: "sda.discovery".into(),
        reason: "no file was found, so every count in this report is a count of nothing".into(),
    }]);
    let path = dir.join("report.json");
    std::fs::write(&path, report.to_json_pretty().expect("serialises"))
        .expect("the report is written");

    let out = dispatch("report.query", &json!({ "report_path": path.to_string_lossy() }))
        .expect("the tool runs");

    assert_eq!(out["matched"], json!(0), "the premise: {out:#}");

    let not_checked = out["not_checked"]
        .as_array()
        .unwrap_or_else(|| panic!("a queried report has to carry its caveats: {out:#}"));
    assert!(
        !not_checked.is_empty(),
        "the stored report holds one and this returned none, which is the defect: {out:#}"
    );
    let joined: String = not_checked
        .iter()
        .filter_map(|e| e["reason"].as_str())
        .collect::<Vec<_>>()
        .join(" | ");
    assert!(
        joined.contains("count of nothing"),
        "`matched: 0` from a scan that read nothing must not stand alone: {out:#}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
