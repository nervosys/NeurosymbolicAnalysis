//! Handing work between a person and an agent, in one file.
//!
//! This is the half of the design that the commercial tools solve with a server:
//! Coverity has an owner field and a triage store, SonarQube has assignees and
//! comment threads, and both live in a database behind a web UI. Here they live in
//! `.sda/triage.toml`, which means the review is reviewable — it arrives in a pull
//! request next to the code it is about, and `git log` already says who wrote it.
//!
//! What that buys, and the reason a person and an agent share one namespace: a
//! human can hand a batch to `agent:triage-bot`, the agent can work it over MCP,
//! and the conclusions come back into the same file the human is reading. Neither
//! side owns the state and neither can diverge without it showing in a diff.
//!
//! Two invariants are load-bearing and easy to lose:
//!
//! * **Assigning and commenting conclude nothing.** A distributed queue is not a
//!   reviewed queue, and collapsing the two would let a backlog look triaged
//!   because it had been handed out.
//! * **A verdict never eats the discussion.** The obvious implementation replaces
//!   the record, which silently discards the assignee and the whole thread the
//!   moment somebody presses a button.

use sda_agent::dispatch::dispatch;
use serde_json::{Value, json};

fn project(name: &str) -> std::path::PathBuf {
    let root = std::env::temp_dir().join(format!("sda-handoff-{name}"));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("src/main.c"),
        "#include <stdlib.h>\nint main(void) { char *p = malloc(16); (void)p; return 0; }\n",
    )
    .unwrap();
    root
}

fn triage(path: &str, args: Value) -> Value {
    let mut a = json!({ "path": path });
    for (k, v) in args.as_object().unwrap() {
        a[k] = v.clone();
    }
    dispatch("analysis.triage", &a).expect("analysis.triage")
}

/// A real finding id from the project.
///
/// The MCP scan projection deliberately omits ids — they are machine keys, not
/// something an agent should be reading out of a report — so the test takes one
/// from the engine directly, which is also how the workbench gets it.
fn a_real_id(path: &str) -> String {
    let target = sda_engine::discover::discover(path, &Default::default());
    let report = sda_engine::run::analyze(
        &sda_engine::default_registry(),
        &target,
        &sda_engine::run::RunConfig::default(),
    );
    report.findings.first().expect("the fixture produces findings").id.to_string()
}

#[test]
fn a_human_hands_a_finding_to_an_agent_and_reads_back_its_conclusion() {
    let root = project("roundtrip");
    let path = root.to_string_lossy().to_string();
    let id = a_real_id(&path);

    // The human hands it over and asks a question.
    triage(&path, json!({ "id": id, "assign": "agent:triage-bot" }));
    triage(&path, json!({ "id": id, "comment": "is this reachable at all?", "by": "a.erickson" }));

    let handed = triage(&path, json!({}));
    let r = &handed["records"].as_array().unwrap()[0];
    assert_eq!(r["assignee"], json!("agent:triage-bot"));
    assert_eq!(r["state"], json!("open"), "assigned is not reviewed");
    assert_eq!(
        handed["unreviewed"].as_u64().unwrap(),
        handed["findings_in_scan"].as_u64().unwrap(),
        "a distributed queue is not a reviewed queue"
    );

    // The agent answers and concludes.
    triage(&path, json!({ "id": id, "comment": "no: guarded by the null check", "by": "agent:triage-bot" }));
    triage(&path, json!({ "id": id, "state": "false-positive", "note": "unreachable", "by": "agent:triage-bot" }));

    let back = triage(&path, json!({}));
    let r = &back["records"].as_array().unwrap()[0];
    assert_eq!(r["state"], json!("false-positive"));
    assert_eq!(r["by"], json!("agent:triage-bot"));
    assert_eq!(r["assignee"], json!("agent:triage-bot"), "the verdict kept the owner");

    let thread = r["comments"].as_array().unwrap();
    assert_eq!(thread.len(), 2, "the verdict kept the discussion: {thread:?}");
    assert_eq!(thread[0]["by"], json!("a.erickson"), "and kept its order");
    assert_eq!(thread[1]["by"], json!("agent:triage-bot"));
    assert!(thread[0]["at"].as_str().unwrap().contains('T'), "a remark needs a time");
}

#[test]
fn assignments_are_counted_per_owner() {
    let root = project("owners");
    let path = root.to_string_lossy().to_string();
    let id = a_real_id(&path);
    triage(&path, json!({ "id": id, "assign": "agent:triage-bot" }));

    let r = triage(&path, json!({}));
    assert_eq!(r["by_assignee"]["agent:triage-bot"], json!(1));
}

/// The tool refuses a write it cannot attach to a real finding, whichever kind of
/// write it is — a record nobody can check is worse than no record.
#[test]
fn a_write_against_an_unknown_finding_is_refused() {
    let root = project("bogus");
    let path = root.to_string_lossy().to_string();
    for args in [
        json!({ "id": "deadbeef", "assign": "someone" }),
        json!({ "id": "deadbeef", "comment": "hello" }),
        json!({ "id": "deadbeef", "state": "accepted" }),
    ] {
        let mut a = json!({ "path": path });
        for (k, v) in args.as_object().unwrap() {
            a[k] = v.clone();
        }
        let out = dispatch("analysis.triage", &a);
        assert!(out.is_err(), "accepted a write against a finding that does not exist: {args}");
    }
}

/// An id with no verb is a caller that meant to do something and did not say
/// what. Silently returning the listing would look like it worked.
#[test]
fn an_id_with_no_action_is_an_error_rather_than_a_silent_listing() {
    let root = project("noverb");
    let path = root.to_string_lossy().to_string();
    let id = a_real_id(&path);
    let out = dispatch("analysis.triage", &json!({ "path": path, "id": id }));
    assert!(out.is_err(), "an id with no state, assign or comment did nothing and said so");
}
