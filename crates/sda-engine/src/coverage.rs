//! Execution counts from an external coverage tool.
//!
//! An external dynamic tool — Valgrind, Miri — reports *defects*. It counts no
//! lines, so its evidence can confirm a static finding and can never refute one
//! or show it unreached. That is not a limitation of correlation: `correlate`
//! takes `Option<&Observation>` and wants a `Some` with real counts in it. This
//! module is where that `Some` comes from when the native probe shim is not in
//! play.
//!
//! # Why LCOV and gcov, and not callgrind
//!
//! `Observation::coverage` maps `(file, line)` to *the number of times that line
//! executed*, and `CorrelationPolicy::refutation_threshold` is documented in
//! exactly those units. Two formats say that and mean it:
//!
//! * **LCOV `.info`** — `DA:<line>,<count>`. The interchange format: `lcov`,
//!   `gcovr`, `llvm-cov export --format=lcov`, `grcov` and `coverage.py` all
//!   emit it, so one parser serves every producer.
//! * **gcov's own `.gcov` text** — `<count>:<line>:<source>`. Supported because
//!   it ships with gcc itself, and `lcov` frequently does not; on the machine
//!   this was developed against, `gcov` was present and `lcov` and `gcovr` were
//!   both absent.
//!
//! Callgrind was the obvious third candidate and is **wrong**. Its cost column
//! is instructions retired at a line, not executions of it. Feeding `Ir` to a
//! threshold documented as "executions of a line" would compare two different
//! quantities and refute findings on the strength of a long loop body — a claim
//! about the code manufactured out of a fact about the instrument, which is the
//! defect this codebase has a table of.
//!
//! # What an empty report means
//!
//! It means the tool failed, and this module returns an error rather than an
//! empty `Observation`. The distinction is the whole point of the `Option` in
//! `correlate`: a coverage report with no records, read as a measurement, says
//! *every instrumented line ran zero times*, which would mark every static
//! finding in the project `Unreached` on the strength of a file that measured
//! nothing. `ext.modelscan` shipped the same bug in the other direction — an
//! empty report file read as a clean scan — and it was observed once and never
//! reproduced, which is the worst kind to leave unguarded.

use crate::dynamic::Observation;
use sda_core::{Error, Result};
use std::path::Path;

/// Which format a coverage report was recognised as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoverageFormat {
    /// `lcov`/`gcovr`/`llvm-cov` tracefile: `SF:` and `DA:` records.
    Lcov,
    /// `gcov`'s annotated source listing: `<count>:<line>:<text>`.
    Gcov,
}

impl CoverageFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            CoverageFormat::Lcov => "lcov",
            CoverageFormat::Gcov => "gcov",
        }
    }
}

/// Execution counts read from an external tool, with the numbers needed to say
/// what was measured.
///
/// The counts are carried separately from the [`Observation`] because a report
/// that says "3 findings refuted" is unreadable without them: refuted *against
/// what*? A reader needs to know that 412 lines across 6 files were measured and
/// 380 of them ran, or the verdict is a bare assertion.
#[derive(Clone, Debug)]
pub struct ExternalCoverage {
    pub observation: Observation,
    pub format: CoverageFormat,
    /// Distinct source files the report carried line records for.
    pub files: usize,
    /// Lines the tool measured, executed or not. This is the denominator.
    pub lines_measured: usize,
    /// Lines the tool measured and saw execute at least once.
    pub lines_executed: usize,
    /// Records whose count field could not be read. Surfaced rather than
    /// dropped: gcov's count tokens vary between compiler versions, and a
    /// parser silently discarding two thirds of a file would present a thin
    /// measurement as a complete one.
    pub unreadable_records: usize,
}

impl ExternalCoverage {
    /// A sentence for the *NOT CHECKED* section, stating what was measured.
    ///
    /// It ends by naming the one thing a reader cannot see from the numbers: a
    /// coverage file describes *some* execution of the program, and nothing
    /// here can establish it was the same execution a dynamic tool inspected.
    /// One provenance sentence for a whole set of reports.
    ///
    /// `provenance` is right for one file and wrong for fifty-nine. gcov writes
    /// one `.gcov` per translation unit, so pointing `--coverage` at a build
    /// directory is the *ordinary* case, not a convenience — and a real project
    /// put 59 near-identical paragraphs into the one section of the report that
    /// has to be read, each naming a long absolute path and differing only in
    /// the file name. The two entries that mattered, that the artifact could not
    /// be executed and which dynamic tool had run, were buried in the middle of
    /// them.
    ///
    /// The totals are what a reader needs: how much was measured, how much of it
    /// ran, and where it came from. The per-file detail is in the files.
    pub fn provenance_of_many(reports: &[(String, ExternalCoverage)]) -> Option<String> {
        let (first, _) = reports.first()?;
        let measured: usize = reports.iter().map(|(_, c)| c.lines_measured).sum();
        let executed: usize = reports.iter().map(|(_, c)| c.lines_executed).sum();
        let files: usize = reports.iter().map(|(_, c)| c.files).sum();
        let unreadable: usize = reports.iter().map(|(_, c)| c.unreadable_records).sum();
        let mut formats: Vec<&str> = reports.iter().map(|(_, c)| c.format.as_str()).collect();
        formats.sort_unstable();
        formats.dedup();

        let source = match reports.len() {
            1 => format!("`{first}`"),
            n => format!("{n} report(s), the first of them `{first}`"),
        };
        let mut s = format!(
            "execution counts were read from {source} ({} format): {measured} line(s) measured \
             across {files} file(s), {executed} of which executed at least once. Refutation and \
             `unreached` verdicts in this report rest on those counts",
            formats.join(", ")
        );
        if unreadable > 0 {
            s.push_str(&format!(
                ". {unreadable} record(s) had a count this parser could not read and were not \
                 measured — the coverage below is thinner than the files it came from"
            ));
        }
        s.push_str(
            ". The counts describe the run that produced those files, which is not necessarily \
             the run any dynamic analyzer inspected: a line refuted here was exercised by *an* \
             execution, not provably by the one that looked for the defect",
        );
        Some(s)
    }

    pub fn provenance(&self, source: &str) -> String {
        let mut s = format!(
            "execution counts were read from `{source}` ({} format): {} line(s) measured across {} \
             file(s), {} of which executed at least once. Refutation and `unreached` verdicts in \
             this report rest on those counts",
            self.format.as_str(),
            self.lines_measured,
            self.files,
            self.lines_executed,
        );
        if self.unreadable_records > 0 {
            s.push_str(&format!(
                ". {} record(s) had a count this parser could not read and were not measured — \
                 the coverage below is thinner than the file it came from",
                self.unreadable_records
            ));
        }
        s.push_str(
            ". The counts describe the run that produced this file, which is not necessarily the \
             run any dynamic analyzer inspected: a line refuted here was exercised by *an* \
             execution, not provably by the one that looked for the defect",
        );
        s
    }
}

/// Read a coverage report from disk, detecting its format from its contents.
pub fn load(path: &Path) -> Result<ExternalCoverage> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| Error::io(path.display().to_string(), e))?;
    parse(&text).map_err(|e| match e {
        // Name the file. The error text is about a format, and a user pointing
        // at the wrong one of several `.info` files needs to know which.
        Error::Malformed { format, reason } => Error::Malformed {
            format,
            reason: format!("{}: {reason}", path.display()),
        },
        other => other,
    })
}

/// Parse a coverage report whose format is detected from its contents.
pub fn parse(text: &str) -> Result<ExternalCoverage> {
    match detect(text) {
        Some(CoverageFormat::Lcov) => parse_lcov(text),
        Some(CoverageFormat::Gcov) => parse_gcov(text),
        None => Err(Error::malformed(
            "coverage",
            format!(
                "not recognised as an lcov tracefile (no `SF:` record) or a gcov listing (no \
                 `<count>:<line>:` record). First non-empty line: {}",
                first_line(text)
            ),
        )),
    }
}

fn first_line(text: &str) -> String {
    match text.lines().map(str::trim).find(|l| !l.is_empty()) {
        Some(l) => format!("`{}`", l.chars().take(60).collect::<String>()),
        None => "the file is empty".to_string(),
    }
}

fn detect(text: &str) -> Option<CoverageFormat> {
    for line in text.lines() {
        if line.starts_with("SF:") {
            return Some(CoverageFormat::Lcov);
        }
        if gcov_record(line).is_some() {
            return Some(CoverageFormat::Gcov);
        }
    }
    None
}

/// Split a gcov listing line into its count field and line number.
///
/// Returns `None` for anything that is not `<count>:<line>:<rest>` with a
/// numeric line, which is how the format is detected as well as parsed.
fn gcov_record(line: &str) -> Option<(&str, u32, &str)> {
    let (count, rest) = line.split_once(':')?;
    let (lineno, source) = rest.split_once(':')?;
    let lineno: u32 = lineno.trim().parse().ok()?;
    Some((count.trim(), lineno, source))
}

/// Parse gcov's annotated source listing.
///
/// ```text
///         -:    0:Source:main.c
///         1:    9:    char *p = malloc(16);
///     #####:   12:    return 1;
///        25:   14:    }
/// ```
///
/// `-` marks a line with no code, which is *not* a measurement of zero and is
/// skipped. `#####` and `=====` mark an executable line that ran zero times,
/// which is a measurement and is recorded as one — the difference between "this
/// line demonstrably did not run" and "nothing here was instrumented".
fn parse_gcov(text: &str) -> Result<ExternalCoverage> {
    let mut cov = Observation::default();
    let mut file: Option<String> = None;
    let mut lines_measured = 0usize;
    let mut lines_executed = 0usize;
    let mut unreadable = 0usize;

    for line in text.lines() {
        let Some((count, lineno, source)) = gcov_record(line) else { continue };
        if lineno == 0 {
            // Metadata: `Source:`, `Graph:`, `Data:`, `Runs:`, `Programs:`.
            if let Some(name) = source.strip_prefix("Source:") {
                file = Some(name.trim().to_string());
            }
            continue;
        }
        if count == "-" {
            continue; // not code; no measurement was taken here
        }
        let Some(file) = file.clone() else {
            return Err(Error::malformed(
                "gcov",
                format!("a line record at line {lineno} appeared before any `Source:` header, so \
                         there is no file to attribute it to"),
            ));
        };
        // `#####` is an unexecuted line; `=====` is one unexecuted because of
        // exceptional control flow. Both are measurements of zero.
        let n = if count.starts_with('#') || count.starts_with('=') {
            0
        } else {
            // gcc appends `*` to a count on a line whose blocks were only
            // partially covered. The count itself is still the count.
            match count.trim_end_matches('*').parse::<u64>() {
                Ok(n) => n,
                Err(_) => {
                    unreadable += 1;
                    continue;
                }
            }
        };
        lines_measured += 1;
        if n > 0 {
            lines_executed += 1;
        }
        *cov.coverage.entry((file, lineno)).or_insert(0) += n;
    }

    finish(cov, CoverageFormat::Gcov, lines_measured, lines_executed, unreadable)
}

/// Parse an LCOV tracefile.
///
/// Only `SF:` and `DA:` matter here. `FN`/`FNDA`/`BRDA` describe functions and
/// branches, which correlation has nothing to say about, and `LF`/`LH` are
/// summaries of the `DA:` records that are recomputed rather than trusted.
fn parse_lcov(text: &str) -> Result<ExternalCoverage> {
    let mut cov = Observation::default();
    let mut file: Option<String> = None;
    let mut lines_measured = 0usize;
    let mut lines_executed = 0usize;
    let mut unreadable = 0usize;

    for line in text.lines() {
        let line = line.trim();
        if let Some(name) = line.strip_prefix("SF:") {
            file = Some(name.trim().to_string());
            continue;
        }
        if line == "end_of_record" {
            file = None;
            continue;
        }
        let Some(rest) = line.strip_prefix("DA:") else { continue };
        let Some(file) = file.clone() else {
            return Err(Error::malformed(
                "lcov",
                format!("`DA:{rest}` appeared outside any `SF:` block, so there is no file to \
                         attribute it to"),
            ));
        };
        // `DA:<line>,<count>`, optionally with a third checksum field.
        let mut parts = rest.split(',');
        let (Some(lineno), Some(count)) = (parts.next(), parts.next()) else {
            unreadable += 1;
            continue;
        };
        let (Ok(lineno), Ok(n)) = (lineno.trim().parse::<u32>(), count.trim().parse::<u64>())
        else {
            unreadable += 1;
            continue;
        };
        lines_measured += 1;
        if n > 0 {
            lines_executed += 1;
        }
        *cov.coverage.entry((file, lineno)).or_insert(0) += n;
    }

    finish(cov, CoverageFormat::Lcov, lines_measured, lines_executed, unreadable)
}

/// Reject a report that measured nothing, and assemble the summary.
///
/// This is the guard the module exists for. Every other error path here is a
/// malformed file, which is loud; a well-formed file containing no records is
/// silent, and read as a measurement it says every line in the project ran zero
/// times.
fn finish(
    observation: Observation,
    format: CoverageFormat,
    lines_measured: usize,
    lines_executed: usize,
    unreadable_records: usize,
) -> Result<ExternalCoverage> {
    if lines_measured == 0 {
        let detail = if unreadable_records > 0 {
            format!(
                "{unreadable_records} record(s) were present but none had a readable count, so \
                 this parser and the tool that wrote the file disagree about the format"
            )
        } else {
            // Both halves of this sentence were observed. A real `gcov` run
            // invoked from the build directory, where it could read its `.gcda`
            // but not the source it was annotating, wrote a four-line file
            // containing a `Source:` header and nothing else — while printing
            // "Lines executed:66.67% of 15" to the terminal, so the operator had
            // every reason to think it had worked.
            "the file parsed as this format and carried no line records at all. That is a \
             statement about the tool, not about the program: it did not finish, or it could not \
             read the source it was annotating. It is not a program that executed no lines"
                .to_string()
        };
        return Err(Error::malformed(format.as_str(), detail));
    }
    let files = observation
        .coverage
        .keys()
        .map(|(f, _)| f.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    Ok(ExternalCoverage {
        observation,
        format,
        files,
        lines_measured,
        lines_executed,
        unreadable_records,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const GCOV: &str = "        -:    0:Source:src/leaky.c\n\
                                -:    0:Graph:leaky.gcno\n\
                                -:    1:#include <stdlib.h>\n\
                                -:    2:\n\
                                1:    3:int main(void) {\n\
                               40:    4:  for (int i = 0; i < 40; i++) { work(i); }\n\
                    #####:    5:  return 1;\n\
                        1:    6:}\n";

    const LCOV: &str = "TN:\n\
                        SF:/mnt/c/proj/src/leaky.c\n\
                        FN:3,main\n\
                        DA:3,1\n\
                        DA:4,40\n\
                        DA:5,0\n\
                        DA:6,1,abc123\n\
                        LF:4\n\
                        LH:3\n\
                        end_of_record\n";

    #[test]
    fn gcov_counts_become_coverage() {
        let c = parse(GCOV).unwrap();
        assert_eq!(c.format, CoverageFormat::Gcov);
        assert_eq!(c.files, 1);
        assert_eq!(c.lines_measured, 4, "the four executable lines; `-` lines are not measured");
        assert_eq!(c.lines_executed, 3);
        assert_eq!(c.observation.covered("src/leaky.c", 4), 40);
    }

    #[test]
    fn lcov_counts_become_coverage() {
        let c = parse(LCOV).unwrap();
        assert_eq!(c.format, CoverageFormat::Lcov);
        assert_eq!(c.lines_measured, 4);
        assert_eq!(c.lines_executed, 3);
        assert_eq!(c.observation.covered("src/leaky.c", 4), 40, "matched by path suffix");
        assert_eq!(
            c.observation.covered("src/leaky.c", 6),
            1,
            "a `DA:` record with a trailing checksum field is still a record"
        );
    }

    /// The distinction the whole module is for. A line the tool measured and saw
    /// run zero times is *evidence*: the file ran, this line did not. A line the
    /// tool never mentions is an absence of evidence. Recording only the first
    /// kind — the shape every probe-stream producer has — would make them
    /// indistinguishable.
    #[test]
    fn a_line_measured_at_zero_is_recorded_as_measured() {
        let c = parse(GCOV).unwrap();
        assert_eq!(c.observation.covered("src/leaky.c", 5), 0);
        assert!(
            c.observation.coverage.contains_key(&("src/leaky.c".to_string(), 5)),
            "`#####` is a measurement of zero, not a missing record"
        );
        assert!(
            !c.observation.coverage.contains_key(&("src/leaky.c".to_string(), 1)),
            "`-` marks a line with no code; nothing was measured there"
        );
    }

    /// A file the tool measured and never entered must not read as executed.
    ///
    /// `Observation::file_executed` tested key existence, which was equivalent to
    /// execution for every producer that came before: the probe stream emits a
    /// record only for a line that ran. A coverage report emits records for lines
    /// that did *not* run, on purpose, so the old test would have called a
    /// completely unexecuted file "executed" — and correlation would then tell
    /// the user each finding in it "produced no coverage record, though other
    /// lines in the file did", about a file where no other line did anything.
    #[test]
    fn a_file_measured_and_never_entered_is_not_executed() {
        let dead = "        -:    0:Source:src/dead.c\n\
                    #####:    3:x();\n\
                    #####:    4:y();\n";
        let c = parse(dead).unwrap();
        assert_eq!(c.lines_measured, 2, "it was measured");
        assert_eq!(c.lines_executed, 0);
        assert!(
            !c.observation.file_executed("src/dead.c"),
            "records exist for this file, and every one of them is a zero"
        );

        let live = parse(GCOV).unwrap();
        assert!(live.observation.file_executed("src/leaky.c"));
    }

    /// An empty report is a tool that failed. Read as a measurement it says every
    /// line ran zero times, which would mark a whole project `Unreached`.
    #[test]
    fn an_empty_report_is_an_error_not_an_empty_measurement() {
        let empty_lcov = "TN:\nSF:/mnt/c/proj/src/leaky.c\nend_of_record\n";
        let err = parse(empty_lcov).unwrap_err().to_string();
        assert!(
            err.contains("about the tool, not about the program"),
            "it must name the tool, not the program: {err}"
        );

        let empty_gcov = "        -:    0:Source:src/leaky.c\n        -:    1:#include <stdlib.h>\n";
        assert!(parse(empty_gcov).is_err(), "no executable line was measured");
    }

    #[test]
    fn an_unrecognised_file_names_what_it_saw() {
        let err = parse("<?xml version=\"1.0\"?>\n<coverage/>\n").unwrap_err().to_string();
        assert!(err.contains("<?xml"), "quote the line so the user can see the mistake: {err}");
        assert!(err.contains("lcov") && err.contains("gcov"), "and say what was expected: {err}");
    }

    #[test]
    fn a_record_with_no_file_is_malformed_rather_than_attributed_to_nothing() {
        assert!(parse("SF:a.c\nend_of_record\nDA:4,1\n").is_err());
    }

    /// gcov's count token varies between compiler versions. A parser that
    /// silently dropped what it could not read would present a thin measurement
    /// as a complete one, so the count is carried into the provenance sentence.
    #[test]
    fn unreadable_counts_are_counted_and_stated() {
        let text = "        -:    0:Source:a.c\n     1.2k:    3:x();\n        7:    4:y();\n";
        let c = parse(text).unwrap();
        assert_eq!(c.lines_measured, 1);
        assert_eq!(c.unreadable_records, 1);
        assert!(c.provenance("a.gcov").contains("could not read"));
    }

    /// A partially-covered line still has a count; the `*` is about branches.
    #[test]
    fn a_starred_count_is_still_a_count() {
        let c = parse("        -:    0:Source:a.c\n       12*:    3:x();\n").unwrap();
        assert_eq!(c.observation.covered("a.c", 3), 12);
    }

    /// The report has to say where the numbers came from, and that they may
    /// describe a different execution than the one a dynamic tool inspected.
    /// gcov writes one `.gcov` per translation unit, so `--coverage <dir>` is
    /// the ordinary case and one notice per file is the wrong unit. A real
    /// 105-file project produced 59 of them, and 59 near-identical paragraphs
    /// went into *NOT CHECKED* — the one section that has to be read — burying
    /// the two entries that mattered.
    #[test]
    fn many_reports_produce_one_notice_carrying_the_totals() {
        let a = parse(LCOV).unwrap();
        let b = parse(LCOV).unwrap();
        let measured = a.lines_measured + b.lines_measured;

        let s = ExternalCoverage::provenance_of_many(&[
            ("first.info".to_string(), a),
            ("second.info".to_string(), b),
        ])
        .expect("two reports");

        assert!(s.contains("2 report(s)"), "the count is the point: {s}");
        assert!(s.contains("first.info"), "and one of them is named: {s}");
        assert!(
            s.contains(&format!("{measured} line(s)")),
            "totals, not one file's share: {s}"
        );
        assert!(
            s.contains("not necessarily the run any dynamic analyzer inspected"),
            "the cross-run caveat survives aggregation: {s}"
        );
    }

    /// One report still reads as one report rather than "1 report(s), the first
    /// of them".
    #[test]
    fn a_single_report_is_named_directly() {
        let s = ExternalCoverage::provenance_of_many(&[("cov.info".to_string(), parse(LCOV).unwrap())])
            .expect("one report");
        assert!(s.contains("`cov.info`"), "{s}");
        assert!(!s.contains("report(s)"), "{s}");
    }

    /// Nothing loaded is nothing to say. A notice claiming counts came from
    /// somewhere, when none did, would be the failure this section exists to
    /// prevent.
    #[test]
    fn no_reports_produce_no_notice() {
        assert!(ExternalCoverage::provenance_of_many(&[]).is_none());
    }

    #[test]
    fn provenance_states_the_cross_run_caveat() {
        let p = parse(LCOV).unwrap().provenance("cov.info");
        assert!(p.contains("cov.info") && p.contains("4 line(s)") && p.contains("1 file(s)"));
        assert!(
            p.contains("not necessarily the run any dynamic analyzer inspected"),
            "a coverage file is not proof of what the defect-finding run executed: {p}"
        );
    }
}
