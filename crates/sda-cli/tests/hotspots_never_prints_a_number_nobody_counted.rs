//! `sda hotspots` orders findings by churn, and says when it could not.
//!
//! The ordering exists because a scan of PX4 produces 78,211 findings sorted by
//! severity, confidence and then *path* — so the forty-two thousand `low` ones
//! arrive alphabetically, which is no order at all for somebody deciding where
//! to start.
//!
//! Two things have to be true of the output, and they pull in opposite
//! directions:
//!
//! * it must be useful enough to act on, which means putting a ranked table in
//!   front of the reader;
//! * it must not let that table be mistaken for a measurement, because the
//!   findings are measured and the ranking is arithmetic over a team's habits.
//!
//! So the caveat is printed **above** the table rather than below it. *NOT
//! CHECKED* is last in a scan report because a reader must not stop before it;
//! here the caveat governs the rows underneath, and saying it afterwards would
//! be saying it to somebody who has already read the list.
//!
//! And an unknown history prints `—`, never `0`. On a directory with no history
//! to read, a `0` in the commits column asserts a settled file on the strength
//! of a query that never ran — the sentence `vcs::detect` refuses about
//! `dirty: false`, in a column a reader scans rather than reads.

use std::process::Command;

fn project(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("sda-hotspots-{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("a scratch project");
    // Something with findings in it, so the table has rows to get wrong.
    std::fs::write(
        dir.join("src").join("a.c"),
        "int f(int x) {\n  if (x == 1) { goto done; }\n  return 0;\ndone:\n  return 1;\n}\n",
    )
    .expect("a source file");
    dir
}

fn hotspots(dir: &std::path::Path) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_sda"))
        .args(["hotspots", &dir.to_string_lossy()])
        .output()
        .expect("the sda binary runs");
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// A directory with no history prints dashes, and says why, before the table.
#[test]
fn an_unreadable_history_prints_no_counts_and_says_so_first() {
    let dir = project("nohistory");
    let text = hotspots(&dir);

    let caveat = text
        .find("not a git checkout")
        .unwrap_or_else(|| panic!("the reason has to be stated: {text}"));
    let header = text
        .find("findings  commits")
        .unwrap_or_else(|| panic!("the table has to be there to be qualified: {text}"));
    assert!(
        caveat < header,
        "the caveat governs the rows under it; printed afterwards it reaches a reader who \
         has already read them:\n{text}"
    );

    // The rows themselves must not carry a count.
    let rows: Vec<&str> = text
        .lines()
        .filter(|l| l.contains("src/a.c") || l.contains("src\\a.c"))
        .collect();
    assert!(!rows.is_empty(), "the fixture has findings, so it has a row: {text}");
    for row in &rows {
        // Three columns are unknown — commits, authors and last — so three
        // dashes. The first draft asserted the row contained *a* dash, and it
        // passed when only the commits column was turned back into a `0`,
        // because the `last` column carries a dash regardless. A test checking
        // that something was said rather than that the right thing was, which is
        // the failure this repository keeps a table of.
        assert_eq!(
            row.matches('—').count(),
            3,
            "commits, authors and last are all unknown here, so all three print a dash. A `0` \
             in any of them is a number nobody counted, in a column a reader scans rather than \
             reads: {row}"
        );
    }

    let _ = std::fs::remove_dir_all(&dir);
}

/// An empty table says why it is empty, using the reason the engine already
/// worked out.
///
/// `hotspots` runs the same `analyze` a scan does, and read only
/// `report.findings` from the result. The report also carries
/// `sda.discovery` — the notice that says no enabled provider read anything
/// here, so every count is a count of nothing — and `sda scan` prints it under
/// NOT CHECKED. This surface computed it and dropped it.
///
/// What that produced for `sda hotspots ./srcc` was a heading, a true remark
/// about git, and an empty table. No line was false. Together they read as
/// *nothing notable in this project*, which is the one thing that was not
/// established. A ranking with no rows is the most reassuring shape an empty
/// result can take, and a `hotspots` view is exactly where somebody goes to
/// decide there is nothing to worry about.
#[test]
fn an_empty_ranking_says_that_nothing_was_scanned() {
    let dir = std::env::temp_dir().join("sda-hotspots-nothing-scanned");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a scratch directory");
    // Present but unreadable by anything here: the ordinary version of this is
    // a docs directory, or a scan rooted one level too deep.
    std::fs::write(dir.join("README.txt"), "not source\n").expect("a file");

    let text = hotspots(&dir);

    assert!(
        text.contains("count of nothing"),
        "an empty ranking has to say the zero is a count of nothing: {text}"
    );
    assert!(
        text.contains("describes the scan, not the code"),
        "which is the whole difference between this and a quiet project: {text}"
    );

    // Above the table, for the same reason the history caveat is: a reader who
    // has already looked at the rows has formed the impression.
    let notice_at = text.find("count of nothing").expect("the notice");
    let table_at = text.find("findings  commits").expect("the table header");
    assert!(
        notice_at < table_at,
        "the reason an empty table is empty belongs above it, not after: {text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// And a project that was actually scanned carries no such line, so the notice
/// stays worth reading.
#[test]
fn a_project_that_was_scanned_carries_no_discovery_notice() {
    let dir = project("scanned");
    let text = hotspots(&dir);

    assert!(
        !text.contains("count of nothing"),
        "this tree has C in it and was read; a caveat on every run is one people skip: {text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// And the output never claims the ranking is itself a finding.
///
/// The whole feature is one step from becoming a risk score, which is a claim
/// about code made out of facts about a team. The closing line is what keeps it
/// an offer, so it is asserted rather than trusted to survive editing.
#[test]
fn the_ranking_does_not_present_itself_as_a_measurement() {
    let dir = project("framing");
    let text = hotspots(&dir);

    assert!(
        text.contains("The findings are measured. The order is not"),
        "the distinction between the two is the whole of what keeps this honest: {text}"
    );
    assert!(
        text.contains("Churn is not a defect"),
        "and a file is not worse for having been edited: {text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The declared analysis scope applies to the ranking, and did not.
///
/// `sda scan` removes out-of-scope files before any provider is built, so a
/// file under an `[[excluded]]` rule is never analyzed. `hotspots` ran its own
/// discovery and skipped that step, so it analyzed those files and then ranked
/// them.
///
/// Measured on this fixture before the fix: the scan reported 4 findings, all
/// in `src/`. `sda hotspots` on the same tree reported 12 and put
/// `legacy/old.c` **first**, because it had the most.
///
/// That is not a missing caveat. It is a ranking whose top row is a file the
/// project formally declared out of scope, with a recorded reason and a named
/// approver, under a heading offering the files worth looking at first. A scope
/// rule that holds in one view and not the next is worse than no rule, because
/// the view that ignores it is the one that looks actionable.
#[test]
fn a_file_the_project_excluded_is_not_ranked_first() {
    let dir = std::env::temp_dir().join("sda-hotspots-scope");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("a scratch project");
    std::fs::create_dir_all(dir.join("legacy")).expect("the excluded directory");
    std::fs::create_dir_all(dir.join(".sda")).expect("the config directory");

    std::fs::write(
        dir.join("src").join("a.c"),
        "int f(int x) {\n  if (x == 1) { goto d; }\n  return 0;\nd:\n  return 1;\n}\n",
    )
    .expect("an in-scope file");
    // Deliberately worse, so that ignoring the scope puts it on top rather than
    // merely somewhere in the list.
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

    let text = hotspots(&dir);

    assert!(
        !text.contains("legacy/old.c"),
        "an excluded file must not be ranked at all, let alone first: {text}"
    );
    assert!(text.contains("src/a.c"), "and the in-scope file still is: {text}");

    // And the exclusion is stated rather than silently applied, with the
    // rationale and approver that travel with the rule.
    assert!(
        text.contains("outside the declared analysis scope"),
        "a narrowed ranking has to say it was narrowed: {text}"
    );
    assert!(
        text.contains("vendored, not maintained here") && text.contains("a.erickson"),
        "the reason and the approver are the point of recording them: {text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A finding the project formally deviated does not rank.
///
/// `report.findings` keeps suppressed findings in the list, marked, because a
/// compliance record has to show what was deviated rather than hide it. This
/// command counted them -- and, underneath that, never applied the deviation
/// register at all: it built its `RunConfig` from `default()`, so nothing in
/// the run was ever marked suppressed in the first place.
///
/// Measured on this fixture before the fix: two files of four findings each,
/// one file's four covered by deviations with a rationale and an approver. The
/// ranking showed **8** against **4** and put the deviated file first. Counted
/// honestly they tie.
///
/// The same shape as the scope defect this command had, and worse in one way. A
/// deviation is a recorded claim that a finding is *accepted*; ranking on it
/// sends somebody to look first at the code most recently agreed to be fine.
#[test]
fn findings_suppressed_by_deviation_are_not_ranked() {
    let dir = std::env::temp_dir().join("sda-hotspots-deviation");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("src")).expect("a scratch project");
    std::fs::create_dir_all(dir.join(".sda")).expect("the config directory");

    let four_findings = "int g(int x) {
  if (x == 1) { goto d; }
  return 0;
d:
  return 1;
}
";
    std::fs::write(dir.join("src").join("a.c"), four_findings).expect("the undeviated file");
    // Twice as many, all of them deviated, so ignoring the register puts this
    // file on top rather than merely somewhere in the list.
    std::fs::write(
        dir.join("src").join("deviated.c"),
        format!("{four_findings}int h(int x) {{
  if (x == 2) {{ goto e; }}
  return 0;
e:
  return 1;
}}
"),
    )
    .expect("the deviated file");
    std::fs::write(
        dir.join(".sda").join("deviations.toml"),
        "[[deviation]]
rule = \"MISRA-C-2023-15.1\"
scope = \"file\"
         path = \"src/deviated.c\"
rationale = \"single-exit cleanup idiom, accepted\"
         approver = \"a.erickson\"

         [[deviation]]
rule = \"MISRA-C-2023-15.5\"
scope = \"file\"
         path = \"src/deviated.c\"
rationale = \"single-exit cleanup idiom, accepted\"
         approver = \"a.erickson\"
",
    )
    .expect("the deviation register");

    let text = hotspots(&dir);

    let count_for = |name: &str| -> usize {
        text.lines()
            .find(|l| l.contains(name))
            .and_then(|l| l.split_whitespace().next())
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| panic!("no row for {name}: {text}"))
    };
    let deviated = count_for("deviated.c");
    let plain = count_for("src/a.c");

    assert_eq!(
        deviated, plain,
        "the deviated file has the same live findings as the other; counting its accepted \
         ones ranked it first: {text}"
    );

    // Not counted is not the same as not there, or this table silently
    // disagrees with the scan's summary.
    assert!(
        text.contains("suppressed by approved deviations"),
        "the deviated findings still have to be accounted for: {text}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
