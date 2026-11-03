//! `HANDOFF.md` is the deliverable the next session reads first, and it makes
//! claims about itself that rot.
//!
//! The failure-mode table's prose says how many defects it holds — a number that
//! has to be incremented by hand every time a row is added, and which drifted to
//! **sixty-seven against sixty-six actual rows** before anyone counted. A
//! document whose whole argument is that unchecked claims rot is a poor place to
//! keep an unchecked claim.
//!
//! The same for cross-references: the document points at its own sections by
//! title, in italics, and a renamed heading leaves a reader hunting.
//!
//! Neither of these is about the analyzer. They are here because this repository
//! treats its own documentation as something that can be wrong, and because the
//! CLI crate is the top of the dependency graph and had no tests at all.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn handoff() -> String {
    let path = repo_root().join("HANDOFF.md");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{} could not be read: {e}", path.display()))
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("the workspace root")
        .to_path_buf()
}

/// Collapse whitespace and drop markdown emphasis, so a title wrapped across two
/// source lines compares equal to the heading it names.
fn normalise(text: &str) -> String {
    text.chars()
        .filter(|c| !matches!(c, '`' | '*' | '~'))
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// `"sixty-six"` -> `66`. Only as much as the document needs.
fn spelled(word: &str) -> Option<u32> {
    const UNITS: &[(&str, u32)] = &[
        ("zero", 0), ("one", 1), ("two", 2), ("three", 3), ("four", 4), ("five", 5),
        ("six", 6), ("seven", 7), ("eight", 8), ("nine", 9), ("ten", 10), ("eleven", 11),
        ("twelve", 12), ("thirteen", 13), ("fourteen", 14), ("fifteen", 15), ("sixteen", 16),
        ("seventeen", 17), ("eighteen", 18), ("nineteen", 19),
    ];
    const TENS: &[(&str, u32)] = &[
        ("twenty", 20), ("thirty", 30), ("forty", 40), ("fifty", 50), ("sixty", 60),
        ("seventy", 70), ("eighty", 80), ("ninety", 90),
    ];

    let w = word.trim().to_ascii_lowercase();
    if let Some((_, n)) = UNITS.iter().find(|(s, _)| *s == w) {
        return Some(*n);
    }
    let (tens, units) = w.split_once('-').unwrap_or((w.as_str(), ""));
    let base = TENS.iter().find(|(s, _)| *s == tens).map(|(_, n)| *n)?;
    if units.is_empty() {
        return Some(base);
    }
    UNITS.iter().find(|(s, _)| *s == units).map(|(_, n)| base + n)
}

/// `["one", "hundred", "and", "four"]` -> `104`.
///
/// The table passed one hundred rows and the single-word reader stopped at
/// ninety-nine, so the claim it guards became unreadable rather than wrong. A
/// checker that cannot parse the sentence it checks fails the same way as one
/// that never looked — it just fails loudly, which is the only reason this was a
/// small fix instead of a silent gap.
fn spelled_phrase(words: &[&str]) -> Option<u32> {
    let clean: Vec<String> = words.iter().map(|w| w.trim().to_ascii_lowercase()).collect();
    let parts: Vec<&str> = clean.iter().map(String::as_str).filter(|w| !w.is_empty()).collect();

    match parts.as_slice() {
        [hundreds, "hundred"] => spelled(hundreds).map(|h| h * 100),
        [hundreds, "hundred", "and", rest] => Some(spelled(hundreds)? * 100 + spelled(rest)?),
        [one] => spelled(one),
        _ => None,
    }
}

/// Rows in the failure-mode table, excluding its header and separator.
fn failure_mode_rows(doc: &str) -> usize {
    let start = doc
        .find("## The failure mode this codebase keeps having")
        .expect("the failure-mode section");
    let rest = &doc[start + 4..];
    let end = rest.find("\n## ").map(|i| start + 4 + i).unwrap_or(doc.len());

    doc[start..end]
        .lines()
        .filter(|l| l.starts_with('|'))
        .filter(|l| !l.starts_with("|---"))
        .filter(|l| !l.starts_with("| Where "))
        .count()
}

#[test]
fn the_failure_mode_table_holds_as_many_defects_as_it_says() {
    let doc = handoff();
    let rows = failure_mode_rows(&doc);
    assert!(rows > 40, "the table should be substantial; found {rows} row(s)");

    let claim = doc
        .split_once("defects are the same")
        .map(|(before, _)| before)
        .expect("the sentence counting the table");
    // Up to four trailing words, longest first: "one hundred and four" is one
    // number written as four words, and this used to take only the last.
    let tail: Vec<&str> = claim
        .rsplit(['*', '\n', ' '])
        .filter(|w| !w.trim().is_empty())
        .take(4)
        .collect();
    let (word, stated) = (1..=tail.len())
        .rev()
        .find_map(|n| {
            let phrase: Vec<&str> = tail[..n].iter().rev().copied().collect();
            spelled_phrase(&phrase).map(|v| (phrase.join(" "), v))
        })
        .unwrap_or_else(|| panic!("no number this test can read before the phrase; saw {tail:?}"));

    assert_eq!(
        stated as usize, rows,
        "the prose says {word} ({stated}) and the table has {rows} row(s). Adding a row means \
         changing the sentence; this is the claim that drifted before the test existed"
    );
}

/// Byte ranges covered by a fenced block or an inline code span.
///
/// Prose that *demonstrates* a broken cross-reference has to be able to quote
/// one without the quotation becoming a reference itself. The first version of
/// this test could not tell the difference, so the paragraph describing the
/// renamed heading it had just found had to be written around it — a shortcoming
/// named in the document rather than hidden, and then fixed here.
fn code_spans(doc: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let bytes = doc.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        if bytes[i] != b'`' {
            i += 1;
            continue;
        }
        // How many backticks open this span; the same number must close it.
        let start = i;
        while i < bytes.len() && bytes[i] == b'`' {
            i += 1;
        }
        let ticks = i - start;
        let fence = &doc[start..i];

        match doc[i..].find(fence) {
            Some(rel) => {
                let end = i + rel + ticks;
                out.push((start, end));
                i = end;
            }
            // Unclosed: everything after it is inside, which is the safe reading.
            None => {
                out.push((start, doc.len()));
                break;
            }
        }
    }
    out
}

#[test]
fn every_cross_reference_names_a_section_that_exists() {
    let doc = handoff();
    let spans = code_spans(&doc);
    let quoted = |at: usize| spans.iter().any(|(a, b)| at >= *a && at < *b);

    let headings: Vec<String> = doc
        .lines()
        .filter(|l| l.starts_with("## ") || l.starts_with("### ") || l.starts_with("#### "))
        .map(|l| normalise(l.trim_start_matches('#')))
        .collect();

    // `see *Some Section*`, which may wrap across source lines.
    let mut checked = 0;
    let mut cursor = 0usize;
    while let Some(at) = doc[cursor..].find("ee *") {
        // Absolute position of this match, taken *before* `cursor` moves. The
        // first version of this loop reassigned `cursor` and then asked
        // `quoted(cursor + at)`, which is a position in neither coordinate
        // system — so the code-span check was reading an arbitrary offset and
        // the whole skip was inert. Both instrument checks passed anyway: the
        // one case that should have been skipped happened to land inside some
        // span by accident, and the deliberately broken pointer appended at the
        // end of the file landed past every span. Two green lights over a
        // function that was doing nothing.
        let found = cursor + at;
        let from = found + 4;
        let Some(len) = doc[from..].find('*') else { break };
        let title = normalise(&doc[from..from + len]);
        cursor = from + len;

        // A reference inside a code span is being shown, not followed.
        if quoted(found) {
            continue;
        }

        // Only titles: a `see *the note above*` style aside is not a reference.
        if title.is_empty() || title.split_whitespace().count() > 12 {
            continue;
        }
        if !title.chars().next().is_some_and(|c| c.is_uppercase() || c == '`') {
            continue;
        }
        checked += 1;
        assert!(
            headings.contains(&title),
            "`see *{title}*` names no section. Headings are renamed more often than the \
             references to them are"
        );
    }
    assert!(checked >= 10, "the document should cross-reference itself: {checked} checked");
}

// ---------------------------------------------------------------------------
// What the catalogues have actually been compared against.
//
// Three `native` catalogues are held to second implementations, and HANDOFF
// states how far that has got: so many of seventy, of twenty-one, of seventeen.
// Every one of those numbers was arrived at by hand, and on 2026-09-15 all three
// were wrong at once — C++ said twelve when the answer was fourteen, Rust said
// nine when it was eight, and the MISRA C table said fifty-six when it was
// fifty-five.
//
// Each error had a tell. The C++ sentence named seven rules and said "and two
// others", because the two did not exist: `5.7.1` and `5.7.2` are compared by
// the clang comparison rather than the clang-tidy one, and whoever counted the
// clang-tidy fixture never looked in the other file. The Rust sentence said
// "nine … the eight left are" and listed eight, which adds to seventeen and
// looks right, but `UNSAFE.3` appears in neither the compared set nor the list.
// The MISRA C table counted `13.6` as compared when cppcheck has never reported
// it: the tool building that table counted a guideline as compared when *either*
// side fired it, so this engine's own finding stood in for the oracle's.
//
// So these numbers are derived here instead of counted. A guideline is compared
// when a committed oracle fixture records the *second implementation's* own
// finding for it; what this engine reports about itself is not evidence that
// anyone checked it.

/// Every guideline named by an oracle's own answers, across all the fixtures.
///
/// The two fixture shapes disagree about the key — clang and clang-tidy write
/// `guideline`, the cppcheck capture writes `rule` with a `misra-c2012-` prefix —
/// and reading only one of them is how the C++ count went wrong.
fn oracle_named() -> BTreeSet<String> {
    let dir = repo_root().join("crates/sda-engine/tests/fixtures");
    let mut out = BTreeSet::new();

    fn walk(v: &serde_json::Value, out: &mut BTreeSet<String>) {
        match v {
            serde_json::Value::Object(map) => {
                for key in ["guideline", "rule"] {
                    if let Some(s) = map.get(key).and_then(|x| x.as_str()) {
                        out.insert(s.rsplit('-').next().unwrap_or(s).to_string());
                    }
                }
                for x in map.values() {
                    walk(x, out);
                }
            }
            serde_json::Value::Array(xs) => {
                for x in xs {
                    walk(x, out);
                }
            }
            _ => {}
        }
    }

    let entries = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{} could not be listed: {e}", dir.display()));
    let mut seen = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            let text = std::fs::read_to_string(&path).expect("a readable fixture");
            let v: serde_json::Value = serde_json::from_str(&text)
                .unwrap_or_else(|e| panic!("{} is not JSON: {e}", path.display()));
            walk(&v, &mut out);
            seen += 1;
        }
    }
    assert!(seen >= 5, "only {seen} fixture(s) found; the comparison would be understated");
    out
}

/// The `native` guidelines of a catalogue, split by whether an oracle has met them.
fn standing(standard: sda_rules::Standard) -> (BTreeSet<String>, BTreeSet<String>) {
    let named = oracle_named();
    let catalog = sda_rules::Catalog::load(standard);
    let native: BTreeSet<String> = catalog
        .by_coverage(sda_rules::Coverage::Native)
        .into_iter()
        .map(|r| r.number.clone())
        .collect();
    assert!(!native.is_empty(), "{standard:?} has no native rules to account for");

    let compared = native.intersection(&named).cloned().collect();
    let unmet = native.difference(&named).cloned().collect();
    (compared, unmet)
}

/// "the seven left are `a b c`" has to say seven and list exactly those seven.
///
/// Matched as a *set*, so the document may order the rules however it reads best
/// — `5.13.1` belongs next to `5.13.2` and not after `30.0.1`, which is where
/// sorting them as strings would put it.
fn assert_left_are(doc: &str, unmet: &BTreeSet<String>, standard: sda_rules::Standard) {
    let mut found_any = false;
    let mut cursor = 0usize;

    while let Some(rel) = doc[cursor..].find("left are `") {
        let at = cursor + rel;
        let from = at + "left are `".len();
        let Some(len) = doc[from..].find('`') else { break };
        let listed: BTreeSet<String> =
            doc[from..from + len].split_whitespace().map(str::to_string).collect();
        cursor = from + len;

        if &listed != unmet {
            continue;
        }
        found_any = true;

        let word = doc[..at]
            .rsplit([' ', '*', '\n'])
            .find(|w| !w.trim().is_empty())
            .expect("a number word before the list");
        let stated = spelled(word)
            .unwrap_or_else(|| panic!("{standard:?}: `{word}` is not a number this test can read"));
        assert_eq!(
            stated as usize,
            unmet.len(),
            "{standard:?}: the document says {word} ({stated}) but lists {}",
            unmet.len()
        );
    }

    assert!(
        found_any,
        "{standard:?}: no sentence names the {} guideline(s) that have met no oracle. \
         Expected a list of exactly: {}",
        unmet.len(),
        unmet.iter().cloned().collect::<Vec<_>>().join(" ")
    );
}

/// The document with the failure-mode table blanked out.
///
/// Every cell in that table is a statement of something this project once
/// believed and has since disproved, so none of it is a live claim. Adding the
/// row "the MISRA C++ standing said twelve of twenty-one" made the count test
/// fail against its own confession — the table is the one place where being
/// wrong on the page is the point.
///
/// Blanked rather than removed so that byte offsets still line up with the real
/// document, which is what the surrounding checks report positions against.
fn without_the_failure_mode_table(doc: &str) -> String {
    let Some(start) = doc.find("## The failure mode this codebase keeps having") else {
        return doc.to_string();
    };
    let rest = &doc[start + 4..];
    let end = rest.find("\n## ").map(|i| start + 4 + i).unwrap_or(doc.len());

    let mut out = String::with_capacity(doc.len());
    out.push_str(&doc[..start]);
    out.extend(doc[start..end].chars().map(|c| if c == '\n' { '\n' } else { ' ' }));
    out.push_str(&doc[end..]);
    out
}

/// The document with the contents of every code span blanked out.
///
/// A number inside backticks is being shown, not asserted — the same reading the
/// cross-reference checker takes of `` `see *Title*` ``. The paragraph
/// describing the failure-mode row quotes "`twelve of twenty-one`" in the middle
/// of live prose, which is a quotation of a disproved claim and not a claim.
fn without_code_spans(doc: &str) -> String {
    let mut out = String::with_capacity(doc.len());
    let mut at = 0usize;

    // Backticks are ASCII, so every span boundary is a character boundary.
    // Newlines are kept so that line numbers still line up with the file.
    for (a, b) in code_spans(doc) {
        if a < at {
            continue;
        }
        out.push_str(&doc[at..a]);
        out.extend(doc[a..b].chars().map(|c| if c == '\n' { '\n' } else { ' ' }));
        at = b;
    }
    out.push_str(&doc[at..]);
    out
}

/// "Fourteen of twenty-one compared" has to say fourteen.
///
/// The first version of this test checked only the sentence naming the rules
/// left over, and changing `Fourteen` to `Thirteen` did not trip it — the number
/// that had actually drifted was the one nothing read. Any sentence of the form
/// "<count> of <the> <total>" whose total is the size of the catalogue is a claim
/// about how far the comparison has got, and every one of them has to agree.
fn assert_compared_count(
    doc: &str,
    compared: usize,
    native: usize,
    standard: sda_rules::Standard,
) {
    let words: Vec<&str> = doc.split_whitespace().collect();
    fn clean(w: &str) -> &str {
        w.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-')
    }
    let mut checked = 0;

    for i in 1..words.len().saturating_sub(2) {
        if clean(words[i]) != "of" {
            continue;
        }
        // "of twenty-one" and "of the seventeen" both read the same way.
        let total_at = if clean(words[i + 1]) == "the" { i + 2 } else { i + 1 };
        if spelled(clean(words[total_at])) != Some(native as u32) {
            continue;
        }
        let Some(stated) = spelled(clean(words[i - 1])) else { continue };

        checked += 1;
        assert_eq!(
            stated as usize,
            compared,
            "{standard:?}: the document says {} of {}, and the fixtures support {compared}",
            clean(words[i - 1]),
            clean(words[total_at])
        );
    }

    assert!(
        checked > 0,
        "{standard:?}: no sentence says how many of the {native} native rules are compared. \
         The answer is {compared}"
    );
}

/// The C++ and Rust catalogues say how far they have got, in words.
#[test]
fn the_catalogues_name_the_rules_no_oracle_has_met() {
    let doc = without_the_failure_mode_table(&handoff());
    for standard in [sda_rules::Standard::MisraCpp2023, sda_rules::Standard::Rust2024] {
        let (compared, unmet) = standing(standard);
        assert!(!compared.is_empty(), "{standard:?}: nothing compared at all");
        let claims = without_code_spans(&doc);
        assert_compared_count(&claims, compared.len(), compared.len() + unmet.len(), standard);
        assert_left_are(&doc, &unmet, standard);
    }
}

/// And the MISRA C table accounts for all seventy, one tier each.
///
/// The table is the only place that splits the unmet rules by *why* they are
/// unmet, so it is also the only place where a rule can be quietly promoted. Its
/// rows have to add up to the catalogue, and the rules it names have to be
/// exactly the ones no oracle has met.
#[test]
fn the_misra_c_tiers_add_up_to_the_catalogue() {
    let doc = handoff();
    let (compared, unmet) = standing(sda_rules::Standard::MisraC2023);

    let start = doc.find("How much evidence actually stands behind").expect("the tier table");
    let rest = &doc[start..];
    let end = rest.find("The two unreached are not laziness").unwrap_or(rest.len());
    let table = &rest[..end];

    let mut total = 0usize;
    let mut stated_compared = None;
    let mut named: BTreeSet<String> = BTreeSet::new();

    for line in table.lines().map(str::trim).filter(|l| l.starts_with("| **")) {
        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        assert_eq!(cells.len(), 3, "a tier row has three cells: {line}");
        let label = normalise(cells[0]);
        let count: usize =
            cells[1].parse().unwrap_or_else(|_| panic!("a count in cell two: {line}"));
        total += count;

        if label == "compared" {
            stated_compared = Some(count);
            continue;
        }

        // Each unmet tier names its members, so a rule cannot leave a tier
        // without someone editing the list it is in.
        let members: Vec<String> = cells[2]
            .split('`')
            .skip(1)
            .step_by(2)
            .flat_map(|run| run.split_whitespace())
            .map(|t| t.trim_matches(',').to_string())
            .collect();
        assert_eq!(
            members.len(),
            count,
            "the `{label}` row says {count} and names {}: {line}",
            members.len()
        );
        named.extend(members);
    }

    assert_eq!(
        stated_compared,
        Some(compared.len()),
        "the table says {stated_compared:?} compared; the fixtures support {}",
        compared.len()
    );
    assert_eq!(
        total,
        compared.len() + unmet.len(),
        "the tiers add to {total}; the catalogue has {} native guidelines",
        compared.len() + unmet.len()
    );
    assert_eq!(
        named, unmet,
        "the rules the table names as unmet are not the rules no oracle has met"
    );
}

// ---------------------------------------------------------------------------
// The numbers a reader is told to expect.
//
// Fixing the catalogue standings raised the obvious next question — what *else*
// on this page is maintained by hand? — and the sweep found the worst copy of it
// in the section that tells the next session how to verify the work. Two places
// said `cargo test --workspace` prints "803 tests across 41 binaries" when it
// prints 921 across 62. A baseline that low does not merely mislead: twelve test
// binaries died with exit 127 mid-run earlier in this project's history, and
// against a stale baseline that failure reads as a comfortable surplus.
//
// The same sweep found the summary table one session behind at 919, `clippy
// 0.1.97` against the 0.1.98 that is installed, and the MCP surface described as
// 16 tools in one place and 19 in another. All five were true when written.

/// `#[test]` functions across the workspace crates.
///
/// This is exactly the workspace total less its doctests, which is why the
/// document states the split: 919 + 2 = 921, and both halves are derivable.
fn count_test_functions_under(dir: &Path) -> usize {
    fn walk(dir: &Path, found: &mut usize) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).unwrap_or_default();
                *found += text
                    .lines()
                    .filter(|l| l.trim() == "#[test]" || l.trim() == "#[tokio::test]")
                    .count();
            }
        }
    }
    let mut found = 0;
    walk(dir, &mut found);
    found
}

fn test_functions_in_tree() -> usize {
    let found = count_test_functions_under(&repo_root().join("crates"));
    assert!(found > 500, "only {found} test functions found; the walk is not reaching the tree");
    found
}

/// The document with *inline* code spans blanked, leaving fenced blocks intact.
///
/// The distinction matters here and nowhere else. Two of the three places
/// stating what `cargo test --workspace` prints are inside ```bash blocks —
/// commands a reader runs, and live claims. The paragraph explaining the stale
/// figure quotes it inline, mid-sentence. So a fenced block is an instruction
/// and a single-backtick span is a quotation, which is the reading that lets the
/// prose name a wrong answer without asserting it.
fn without_inline_code_spans(doc: &str) -> String {
    let mut out = String::with_capacity(doc.len());
    let mut at = 0usize;

    for (a, b) in code_spans(doc) {
        if a < at || !doc[a..b].starts_with('`') || doc[a..b].starts_with("``") {
            continue;
        }
        out.push_str(&doc[at..a]);
        out.extend(doc[a..b].chars().map(|c| if c == '\n' { '\n' } else { ' ' }));
        at = b;
    }
    out.push_str(&doc[at..]);
    out
}

/// Every "<tests> across <binaries>" claim in the document, however it is written.
///
/// The three sites use three spellings — a table cell, and two shell comments
/// reading `# 921 / 62 binaries` and `# 921 tests across 62 binaries` — because
/// they are written for different readers. Two of the three were stale, which is
/// what happens when one claim lives in three places and nothing compares them.
fn workspace_run_claims(doc: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let words: Vec<&str> = doc.split_whitespace().collect();

    for i in 0..words.len() {
        if !words[i].starts_with("binaries") {
            continue;
        }
        // Walk back over the few words before "binaries" collecting integers;
        // the first is the binary count and the second the test count.
        let mut numbers = Vec::new();
        for w in words[i.saturating_sub(5)..i].iter().rev() {
            let cleaned: String = w.chars().filter(|c| c.is_ascii_digit() || *c == ',').collect();
            if let Ok(n) = cleaned.replace(',', "").parse::<usize>() {
                numbers.push(n);
            }
        }
        if numbers.len() >= 2 {
            out.push((numbers[1], numbers[0]));
        }
    }
    out
}

/// What `cargo test --workspace` prints is stated three times and derived once.
#[test]
fn the_workspace_test_count_is_what_the_tree_contains() {
    let raw = handoff();
    // The failure-mode table records the stale figure it is confessing to, and
    // the prose explaining it quotes that figure inline, so both are blanked
    // before the document is read for live claims. The split below is checked
    // against the real text, because it is written with backticks itself.
    let doc = without_inline_code_spans(&without_the_failure_mode_table(&raw));
    let claims = workspace_run_claims(&doc);
    assert!(
        claims.len() >= 3,
        "the document states the workspace run in three places; found {}: {claims:?}",
        claims.len()
    );

    // All three have to agree with each other. This alone would have caught the
    // defect: one site was updated and two were not.
    let first = claims[0];
    for c in &claims {
        assert_eq!(
            *c, first,
            "the document states the workspace run differently in different places: {claims:?}"
        );
    }

    // And the agreed figure has to match the tree. `919 + 2 doctests = 921` is
    // stated in the summary row precisely so that both halves can be checked.
    let (stated_tests, stated_binaries) = first;
    let functions = test_functions_in_tree();

    // Direction first, because this subtraction used to be the whole check and
    // it underflowed on the one case this test exists for. A session adds tests,
    // the document still claims the old total, `stated_tests - functions` goes
    // negative, and the panic read `attempt to subtract with overflow` — true,
    // useless, and silent about which number to change. An instrument that
    // cannot report the failure it was built for is the defect this repository
    // is organised against; it had simply never been pointed at itself.
    assert!(
        functions <= stated_tests,
        "the tree holds {functions} `#[test]` functions and the document claims {stated_tests} \
         tests in total, which is fewer than exist. The tree grew and the document did not: \
         update all three workspace-run claims, and the `(N `#[test]` functions and M doctests)` \
         split in the summary row"
    );

    let doctests = stated_tests - functions;
    assert!(
        doctests <= 8,
        "the document claims {stated_tests} tests and the tree holds {functions} `#[test]` \
         functions, leaving {doctests} to be doctests. That gap is too wide to be doctests"
    );
    // Either spelling of the count, because the document uses a thousands
    // separator everywhere else — `78,211 findings`, `20,287 files` — and the
    // test count crossed a thousand for the first time this session. Forcing
    // `1002` into a document that writes `1,002` two lines away would be the
    // test dictating prose style rather than checking a claim, which is a
    // different job and a worse one.
    let plain = format!("({functions} `#[test]` functions and {doctests} doctests)");
    let grouped = format!("({} `#[test]` functions and {doctests} doctests)", thousands(functions));
    assert!(
        raw.contains(&plain) || raw.contains(&grouped),
        "the summary row has to show the split, so both halves are checkable: expected \
         \"{plain}\" or \"{grouped}\""
    );
    assert!(stated_binaries > 40, "{stated_binaries} test binaries is implausibly few");
}

/// No measurement is dated "this session".
///
/// The label decays. Eighteen rows carried it, written across at least five
/// sessions between 2026-09-03 and 2026-09-16, and a reader today reads all
/// eighteen as current. That is how `PX4 scanned on both OSes | 15,528 findings`
/// came to look like a contradiction of the 78,211 the same tree produces now,
/// rather than what it is: a measurement from two sessions and one growing rule
/// set ago.
///
/// Every one was replaced with the date `git blame` gives for the line, which for
/// a row whose cell is a measurement is when the measurement was taken. A row
/// re-measured today dates to today, correctly.
///
/// This test exists because the fix was one pass over the file and the habit is
/// not. Writing "this session" is the natural thing to type while writing, and it
/// is wrong the moment the session ends.
#[test]
fn no_measurement_is_dated_relative_to_whoever_wrote_it() {
    let doc = handoff();
    let offenders: Vec<&str> = doc
        .lines()
        .filter(|l| l.starts_with('|'))
        .filter(|l| {
            let lower = l.to_ascii_lowercase();
            lower.contains("| this session")
                || lower.contains("| last session")
                || lower.contains("| today")
                || lower.contains("| yesterday")
        })
        .collect();

    assert!(
        offenders.is_empty(),
        "a measurement dated relative to whoever wrote it stops being true when they \
         stop writing. Use the date — `git blame` on the line gives it:\n{}",
        offenders.join("\n")
    );

    // A baseline decays the same way a date does, and for the same reason.
    //
    // One row read "narrowings checked against HEAD~13". When it was written that
    // was `65e5c83`; thirteen commits later it is a different commit, so a reader
    // following the row compares against the wrong thing and gets numbers that
    // look fine. A measurement's baseline has to be a name that does not move.
    //
    // Table rows only. `git diff HEAD~1` in prose, telling someone to look at
    // their own last commit, is a relative reference that means what it says.
    let moving: Vec<&str> = doc
        .lines()
        .filter(|l| l.starts_with('|'))
        .filter(|l| l.contains("HEAD~") || l.contains("HEAD^"))
        .collect();

    assert!(
        moving.is_empty(),
        "a baseline written relative to HEAD points somewhere else after the next commit. \
         Pin the sha — `git rev-parse --short` on the commit that row was measured \
         against:\n{}",
        moving.join("\n")
    );
}

/// Every file the document points at is a file that exists.
///
/// A 4,400-line handbook naming `crates/sda-engine/src/checks.rs` is making a
/// checkable claim, and a renamed file leaves a reference that still reads as
/// authoritative — worse than no reference, because the reader trusts it and
/// goes looking. Same class as the decaying dates above: the information needed
/// to check it is right there and nothing was checking it.
///
/// Swept when this was written: fifty-four repository paths named, none missing,
/// and eight that resolved only by guessing a `crates/` prefix. Those eight were
/// rewritten repo-relative rather than taught to the test, so this can stay a
/// plain existence check — and so a reader can paste the path into an editor.
///
/// Three kinds of backticked path are deliberately *not* repository files, and
/// each is excluded by name rather than by a pattern loose enough to hide a real
/// miss: files in a user's own project (`.sda/triage.toml`), files belonging to
/// another tool (cppcheck's `addons/misra.py`), and illustrative paths inside a
/// rule's explanation (`src/build.rs`, which `DEP.2` wrongly called a build
/// script).
#[test]
fn every_file_the_document_names_exists() {
    const EXTENSIONS: [&str; 12] =
        [".rs", ".py", ".sh", ".toml", ".md", ".json", ".h", ".c", ".cpp", ".mjs", ".js", ".ts"];

    // Not files in this repository, and not claims about it.
    const FOREIGN_PREFIXES: [&str; 5] = [".sda/", ".cargo/", "addons/", "docs.", "http"];
    const FOREIGN_PATHS: [&str; 9] = [
        "member/build.rs",
        "src/build.rs",
        "src/hw.rs",
        "src/lib.rs",
        "src/main.c",
        "src/unittests/parser.c",
        "policy/serve.py",
        // The impact fixture, named in prose so the floor has something concrete
        // to be a floor *of*: `app.c` calls the subject by name and `lib.c` is
        // the subject.
        "src/app.c",
        "src/lib.c",
    ];

    let doc = handoff();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("the workspace root");

    let mut missing = Vec::new();
    let mut checked = 0usize;

    // Line by line, skipping fenced blocks.
    //
    // The first draft split the whole document on backticks and took the odd
    // spans. A fenced block opens with three of them, which flips the parity for
    // everything after it: the sweep found 36 paths where the same logic outside
    // Rust found 54. The `checked > 40` assertion below is what caught it, which
    // is the entire reason it is there — a check that quietly examines less than
    // it should still passes.
    //
    // An inline span never crosses a line, so per-line parity is safe.
    let mut in_fence = false;
    let spans = doc.lines().filter(|line| {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
            return false;
        }
        !in_fence
    });

    for (i, span) in spans.flat_map(|line| line.split('`').enumerate().collect::<Vec<_>>()) {
        if i % 2 == 0 {
            continue;
        }
        let path = span.trim().trim_end_matches([',', ';', ':']);
        if !path.contains('/') || path.contains(' ') || path.contains('\n') {
            continue;
        }
        if !EXTENSIONS.iter().any(|e| path.ends_with(e)) {
            continue;
        }
        if FOREIGN_PREFIXES.iter().any(|p| path.starts_with(p))
            || FOREIGN_PATHS.contains(&path)
        {
            continue;
        }

        checked += 1;
        if !root.join(path).exists() {
            missing.push(path.to_string());
        }
    }

    assert!(
        checked > 40,
        "the document names dozens of files; finding {checked} means this stopped reading \
         them, and a check that examines nothing passes forever"
    );
    assert!(
        missing.is_empty(),
        "the document points at {} file(s) that do not exist. A reference that survives the \
         file it names is worse than none, because a reader trusts it:\n  {}",
        missing.len(),
        missing.join("\n  ")
    );
}

/// `1002` -> `1,002`, the way this document writes every other large number.
fn thousands(n: usize) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// The GUI backend's test count, which nothing checked until it had drifted.
///
/// `test_functions_in_tree` walks `crates/` only, so `gui/src-tauri` — a separate
/// crate with its own `cargo test`, run as step 2 of the gate — sat outside every
/// count claim this file guards. The row said **16** from 2026-09-03 until a
/// seventeenth test was added eighteen days later and the gate printed the real
/// number beside the stale one.
///
/// That is the argument this document makes about itself, arriving on schedule:
/// a derived value with no test drifts, and the only reason this one was caught
/// is that the gate happens to print a figure nobody had promised to maintain.
#[test]
fn the_gui_backend_test_count_is_what_that_crate_contains() {
    let doc = handoff();
    let actual = count_test_functions_under(&repo_root().join("gui").join("src-tauri"));
    assert!(actual > 5, "only {actual} found; the walk is not reaching gui/src-tauri");

    let wanted = format!("| GUI backend tests | {actual}, all passing");
    assert!(
        doc.contains(&wanted),
        "the document has to state the GUI backend count; that crate holds {actual} \
         `#[test]` function(s), so the row should begin \"{wanted}\". This row is \
         maintained by hand and drifted for eighteen days because the workspace \
         count walks `crates/` only"
    );

    // The verification commands state the same number a second time, and that
    // copy went on saying 16 after the row above was corrected to 17.
    let line = doc
        .lines()
        .find(|l| l.starts_with("cd gui/src-tauri && cargo test"))
        .expect("the verification commands run the GUI crate's tests");
    assert!(
        line.trim_end().ends_with(&format!("# {actual}")),
        "the verification commands have to state the GUI backend count; that crate \
         holds {actual} `#[test]` function(s), but the line reads {line:?}"
    );
}

/// The summary of what is still open agrees with the list it summarises.
///
/// Three of the four things this document called blocked had stopped being
/// blocked, and two of the three were contradicted *by the numbered item they
/// summarised*, in the same file. Monaco was refuted in a tool written to
/// refute it; PX4 was built and item 23 records the database it produced. The
/// summary paragraph was a second copy of a status that lived somewhere else,
/// and only one copy was being maintained.
///
/// That is the shape this codebase spent the day removing from the product,
/// where the fix was to delete the copy rather than to check it. Here the copy
/// earns its place -- a reader needs the state on the first page, not two
/// thousand lines down -- so it is checked instead.
///
/// It works because the summary now names item *numbers*. It used to name
/// topics, which cannot be matched against anything; "PX4 is uninitialised" and
/// item 23 are the same claim only to a reader who knows they are.
#[test]
fn the_summary_of_open_work_names_exactly_the_items_still_open() {
    let doc = handoff();

    // The numbered list, and which entries are struck through. A done item is
    // written `23. ~~**...**~~ **Built.**`; an open one has no tildes before
    // its bold title.
    // Only the list under its own heading. A six-thousand-line document is full
    // of other enumerations, and the first draft of this test read `1.` out of
    // one of them and reported item 1 as open. An instrument with too wide a
    // field of view reports things that are not there, which is the same defect
    // as one with too narrow a field missing things that are.
    let start = doc.find("## Suggested next steps").expect("the numbered list has a heading");
    let items = &doc[start..];

    let mut open = BTreeSet::new();
    let mut seen = 0usize;
    for line in items.lines() {
        let Some((num, rest)) = line.split_once(". ") else { continue };
        let num = num.trim();
        if num.is_empty() || !num.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let Ok(n) = num.parse::<u32>() else { continue };
        seen += 1;
        if !rest.trim_start().starts_with("~~") {
            open.insert(n);
        }
    }
    assert!(seen >= 25, "only {seen} numbered item(s) found; the walk is not reaching the list");
    assert!(!open.is_empty(), "if everything is done, this test needs rewriting, not deleting");

    // What the summary claims, by number.
    let at = doc
        .find("numbered item still open")
        .or_else(|| doc.find("numbered items still open"))
        .expect("the first page has to say what is still open, by number");
    let window = &doc[at..doc.len().min(at + 400)];
    // Bold numbers only — `**22**`. Reading every digit in the window picked up
    // the `21.6` of the MISRA guideline named two sentences later and reported
    // items 21 and 6 as claimed. The document writes item numbers in bold and
    // guideline numbers in code spans, so the distinction already exists in the
    // prose; the first version of this test simply did not use it.
    let claimed: BTreeSet<u32> = window
        .split("**")
        .skip(1)
        .step_by(2)
        .filter_map(|t| t.trim().parse::<u32>().ok())
        .collect();
    assert!(
        !claimed.is_empty(),
        "the summary has to write item numbers in bold, so they can be told from guideline          numbers: {window:?}"
    );

    for n in &open {
        assert!(
            claimed.contains(n),
            "item {n} is not struck through, so it is open, and the first page does not \
             mention it. A reader deciding what to do next reads the summary: {claimed:?}"
        );
    }
    for n in &claimed {
        assert!(
            open.contains(n),
            "the first page calls item {n} still open and the item itself is struck through. \
             That is how PX4 and Monaco stayed on this list after they were done, one of \
             them refuted by a tool written to refute it"
        );
    }
}

/// The MCP surface is published, and the document says how wide it is.
///
/// It said sixteen tools in the walkthrough and nineteen in the summary table.
/// `tools()` is the surface an agent actually sees, so it settles the matter.
#[test]
fn the_mcp_tool_count_is_the_published_surface() {
    let doc = handoff();
    let published = sda_agent::mcp::tools().len();

    let wanted = format!("`tools/list` ({published} tools)");
    assert!(
        doc.contains(&wanted),
        "the document has to state the published tool count; `tools()` publishes {published}"
    );
    assert!(
        doc.contains(&format!("handshake, {published} tools")),
        "and the summary table states it too; `tools()` publishes {published}"
    );
}
