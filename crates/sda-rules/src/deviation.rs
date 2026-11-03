//! Deviation records.
//!
//! Real MISRA compliance is not "zero findings" — it is "every remaining finding
//! has an approved, recorded, justified deviation". This module is that record,
//! and it enforces the two things that make it worth having:
//!
//! * A **Mandatory** guideline can never be deviated. An attempt is itself
//!   reported, not silently honoured.
//! * A deviation must carry a rationale and an approver. A blank justification
//!   is rejected at load time, not discovered during an audit.

use crate::{Catalog, Standard};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// What a deviation applies to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "kebab-case")]
pub enum DeviationScope {
    /// The whole project. Used sparingly and visible in every report.
    Project,
    /// Every file whose path contains this substring.
    Path { contains: String },
    /// One file, exactly.
    File { path: String },
    /// A specific line of a specific file.
    Line { path: String, line: u32 },
    /// A named function in a file.
    Function { path: String, name: String },
}

impl DeviationScope {
    fn matches(&self, path: &str, line: u32, function: Option<&str>) -> bool {
        // Compare with forward slashes so a record written on Linux applies on
        // Windows and vice versa.
        let p = path.replace('\\', "/");
        match self {
            DeviationScope::Project => true,
            DeviationScope::Path { contains } => p.contains(&contains.replace('\\', "/")),
            DeviationScope::File { path: f } => p.ends_with(&f.replace('\\', "/")),
            DeviationScope::Line { path: f, line: l } => {
                p.ends_with(&f.replace('\\', "/")) && *l == line
            }
            DeviationScope::Function { path: f, name } => {
                p.ends_with(&f.replace('\\', "/")) && function == Some(name.as_str())
            }
        }
    }

    /// Whether this scope names `path` at all, ignoring line and function.
    ///
    /// Used to tell "this record is dead weight" from "this record is about a
    /// file the run never looked at", which are not the same claim and must not
    /// produce the same notice.
    fn names_path(&self, path: &str) -> bool {
        let p = path.replace('\\', "/");
        match self {
            DeviationScope::Project => true,
            DeviationScope::Path { contains } => p.contains(&contains.replace('\\', "/")),
            DeviationScope::File { path: f }
            | DeviationScope::Line { path: f, .. }
            | DeviationScope::Function { path: f, .. } => p.ends_with(&f.replace('\\', "/")),
        }
    }

    /// How specific this scope is; narrower scopes are preferred when several
    /// records match, so the most deliberate justification is the one cited.
    fn specificity(&self) -> u8 {
        match self {
            DeviationScope::Project => 0,
            DeviationScope::Path { .. } => 1,
            DeviationScope::File { .. } => 2,
            DeviationScope::Function { .. } => 3,
            DeviationScope::Line { .. } => 4,
        }
    }
}

/// One approved departure from a guideline.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Deviation {
    /// Fully-qualified rule id, e.g. `MISRA-C-2023-15.5`.
    pub rule: String,
    #[serde(flatten)]
    pub scope: DeviationScope,
    /// Why this departure is acceptable. Required and non-empty.
    pub rationale: String,
    /// Who approved it. Required and non-empty.
    pub approver: String,
    /// ISO date the record was raised.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raised: Option<String>,
    /// ISO date after which the record is stale and no longer applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    /// Free-form reference into an external process (ticket, ECR, DOORS id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
}

impl Deviation {
    /// Whether this deviates an external tool's finding rather than a catalogued
    /// guideline.
    ///
    /// Decided by namespace: an id carrying a known standard's prefix is a claim
    /// about that standard and is held to it, and anything else belongs to a tool
    /// whose rule list this crate does not have. `clippy::needless_range_loop` is
    /// external; `MISRA-C-2023-99.9` is a mistyped guideline and is rejected.
    ///
    /// The residual gap is a *mistyped prefix* — `MISRAC2023-15.5` reads as
    /// external and is accepted. It suppresses nothing, because it matches no
    /// finding's rule id, so the finding stays visible; and it is counted in the
    /// external total that `sda rules audit` prints, where an unexpected number is
    /// the signal to look.
    pub fn is_external(&self) -> bool {
        !Standard::all().iter().any(|s| self.rule.starts_with(s.id_prefix()))
    }

    /// Text recorded on a suppressed finding, so a report reader can see the
    /// justification without opening a second document.
    pub fn citation(&self) -> String {
        let mut s = format!("deviation for {} approved by {}", self.rule, self.approver);
        if let Some(d) = &self.raised {
            s.push_str(&format!(" (raised {d})"));
        }
        s.push_str(&format!(": {}", self.rationale));
        if let Some(r) = &self.reference {
            s.push_str(&format!(" [{r}]"));
        }
        s
    }

    /// Whether the record has passed its expiry date, given today's ISO date.
    /// String comparison is correct for ISO-8601 dates and avoids a clock dependency.
    pub fn is_expired(&self, today: &str) -> bool {
        self.expires.as_deref().is_some_and(|e| e < today)
    }

    /// Whether any of these files is one this record could speak about.
    ///
    /// A record for `sda_probe.h` is not dead weight during a scan of `crates/`;
    /// it is about a file that run never opened. Calling it unused would be this
    /// codebase's own cardinal error — an absence of evidence reported as
    /// evidence of absence.
    pub fn could_apply_to<S: AsRef<str>>(&self, paths: &[S]) -> bool {
        paths.iter().any(|p| self.scope.names_path(p.as_ref()))
    }
}

/// A problem found while loading a deviation register.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DeviationError {
    pub rule: String,
    pub reason: String,
}

/// The project's set of deviation records.
#[derive(Clone, Debug, Default)]
pub struct DeviationRegister {
    deviations: Vec<Deviation>,
    /// Records rejected at load time, kept so the report can show them.
    rejected: Vec<DeviationError>,
}

#[derive(Debug, Deserialize)]
struct RawRegister {
    #[serde(default)]
    deviation: Vec<Deviation>,
}

impl DeviationRegister {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a register, validating every record against the catalogues.
    ///
    /// Invalid records are *rejected and reported*, never silently dropped and
    /// never silently honoured: a deviation that does not hold up is exactly the
    /// thing an audit needs to see.
    pub fn parse(text: &str) -> Result<DeviationRegister, String> {
        let raw: RawRegister = toml::from_str(text).map_err(|e| e.to_string())?;
        let catalogs: Vec<Catalog> = crate::all_catalogs();
        let mut reg = DeviationRegister::default();

        for d in raw.deviation {
            if let Err(reason) = validate(&d, &catalogs) {
                reg.rejected.push(DeviationError { rule: d.rule.clone(), reason });
                continue;
            }
            reg.deviations.push(d);
        }
        Ok(reg)
    }

    pub fn add(&mut self, d: Deviation) -> Result<(), String> {
        let catalogs = crate::all_catalogs();
        validate(&d, &catalogs)?;
        self.deviations.push(d);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.deviations.len()
    }
    pub fn is_empty(&self) -> bool {
        self.deviations.is_empty()
    }
    pub fn all(&self) -> &[Deviation] {
        &self.deviations
    }
    /// Records that failed validation, with the reason.
    pub fn rejected(&self) -> &[DeviationError] {
        &self.rejected
    }

    /// The deviation covering a finding, if any, as of `today`. When several
    /// apply, the most specific wins.
    ///
    /// **Expired records cover nothing.** `expires` is documented as the date
    /// after which a record "no longer applies", and for a long time it did
    /// apply: this filtered on rule and scope alone, so a lapsed acceptance went
    /// on suppressing its finding indefinitely. A register whose expiry dates do
    /// nothing tells a safety team that acceptances lapse and must be
    /// re-approved, when in fact none of them ever will.
    ///
    /// The date is a parameter rather than a clock read, for the reason
    /// `is_expired` gives: a check that changes its answer overnight, without the
    /// inputs changing, cannot be reproduced from a report.
    pub fn find(
        &self,
        rule: &str,
        path: &str,
        line: u32,
        function: Option<&str>,
        today: &str,
    ) -> Option<&Deviation> {
        self.deviations
            .iter()
            .filter(|d| !d.is_expired(today))
            .filter(|d| d.rule == rule && d.scope.matches(path, line, function))
            .max_by_key(|d| d.scope.specificity())
    }

    /// Mark every finding covered by an unexpired record as suppressed, in place.
    /// Returns how many were suppressed.
    pub fn apply(&self, findings: &mut [sda_core::Finding], today: &str) -> usize {
        let mut n = 0;
        for f in findings.iter_mut() {
            let path = f.location.file.to_string_lossy().to_string();
            if let Some(d) = self.find(
                f.rule.as_str(),
                &path,
                f.location.line,
                f.location.function.as_deref(),
                today,
            ) {
                f.suppressed_by = Some(d.citation());
                n += 1;
            }
        }
        n
    }

    /// Records that are never exercised by any finding — the dead weight an
    /// audit should retire.
    pub fn unused(&self, findings: &[sda_core::Finding]) -> Vec<&Deviation> {
        self.deviations
            .iter()
            .filter(|d| {
                !findings.iter().any(|f| {
                    let path = f.location.file.to_string_lossy().to_string();
                    f.rule.as_str() == d.rule
                        && d.scope.matches(&path, f.location.line, f.location.function.as_deref())
                })
            })
            .collect()
    }

    /// Count of records per standard, for the compliance summary.
    pub fn by_standard(&self) -> BTreeMap<String, usize> {
        let mut m = BTreeMap::new();
        for d in &self.deviations {
            let s = Standard::all()
                .iter()
                .find(|s| d.rule.starts_with(s.id_prefix()))
                .map(|s| s.title().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            *m.entry(s).or_default() += 1;
        }
        m
    }

    /// How many accepted records deviate an external tool's finding.
    ///
    /// Reported by `sda rules audit` rather than folded into the total: a
    /// conformance argument resting on a tool's opinion is a different argument
    /// from one resting on a guideline, and a reader is entitled to see the split.
    pub fn external(&self) -> usize {
        self.deviations.iter().filter(|d| d.is_external()).count()
    }

    /// Records past their expiry date as of `today`.
    pub fn expired(&self, today: &str) -> Vec<&Deviation> {
        self.deviations.iter().filter(|d| d.is_expired(today)).collect()
    }
}

fn validate(d: &Deviation, catalogs: &[Catalog]) -> Result<(), String> {
    if d.rationale.trim().is_empty() {
        return Err("rationale is empty; a deviation without a justification is not a deviation".into());
    }
    if d.approver.trim().is_empty() {
        return Err("approver is empty; a deviation must be attributable to a person".into());
    }
    // A finding from an external tool can be deviated too. The register used to
    // accept only catalogued guideline ids, so a project running
    // `--with ext.clippy` in CI had exactly two options for a finding it had
    // examined and accepted: change the code, or read the finding forever.
    //
    // What is *not* relaxed is validation of anything that claims to be a
    // guideline. An id carrying a known standard's prefix must exist in that
    // standard, so a mistyped MISRA number is still rejected loudly — which is
    // the check that matters, because a silently-ignored deviation of a real rule
    // is a suppression nobody approved.
    //
    // An external id is validated against nothing, because nothing here has the
    // tool's rule list. That is safe in the direction that counts: a deviation
    // matching no finding suppresses nothing, so a typo leaves the finding
    // visible rather than hiding it. `sda rules audit` reports how many
    // deviations are external, because a conformance argument resting on a tool's
    // opinion is a different argument from one resting on a guideline.
    if d.is_external() {
        return Ok(());
    }
    let rule = catalogs.iter().find_map(|c| c.get_by_id(&d.rule));
    match rule {
        None => Err(format!("`{}` is not a known guideline in any loaded catalogue", d.rule)),
        // Asked through `Obligation::deviable`, which exists to answer exactly
        // this and was being duplicated here. The two agreed, so nothing was
        // broken — but a rule about which obligations may be silenced belongs in
        // one place, and the copy in a validator is the one that gets forgotten
        // when the definition changes.
        // The wording is deliberately unchanged. `Obligation::as_str` is
        // lowercase, and reaching for it here would have quietly rewritten a
        // message four tests and one report assert on — a refactor that changes
        // what a reader sees is not a refactor.
        Some(r) if !r.obligation.deviable() => Err(format!(
            "`{}` is Mandatory and may never be deviated",
            d.rule
        )),
        Some(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A date every record in these tests is still live on. Fixed rather
    /// than read from a clock: a suite whose answers change overnight is
    /// not a suite.
    const TODAY: &str = "2026-01-01";
    use sda_core::{Finding, Location, Severity};

    fn dev(rule: &str, scope: DeviationScope) -> Deviation {
        Deviation {
            rule: rule.into(),
            scope,
            rationale: "hardware register access requires this form".into(),
            approver: "a.erickson".into(),
            raised: Some("2026-01-15".into()),
            expires: None,
            reference: Some("ECR-4412".into()),
        }
    }

    fn finding(rule: &str, file: &str, line: u32) -> Finding {
        Finding::new("sda.static.c", rule, "t", Severity::Medium, Location::new(file, line, 1))
    }

    #[test]
    fn a_mandatory_guideline_can_never_be_deviated() {
        let mut reg = DeviationRegister::new();
        // MISRA C 9.1 is Mandatory.
        let err = reg
            .add(dev("MISRA-C-2023-9.1", DeviationScope::Project))
            .unwrap_err();
        assert!(err.contains("Mandatory"));
        assert!(reg.is_empty());
    }

    #[test]
    fn required_and_advisory_guidelines_can_be_deviated() {
        let mut reg = DeviationRegister::new();
        assert!(reg.add(dev("MISRA-C-2023-15.5", DeviationScope::Project)).is_ok());
        assert!(reg.add(dev("MISRA-C-2023-21.6", DeviationScope::Project)).is_ok());
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn a_deviation_without_justification_is_rejected() {
        let mut d = dev("MISRA-C-2023-15.5", DeviationScope::Project);
        d.rationale = "   ".into();
        assert!(DeviationRegister::new().add(d).unwrap_err().contains("rationale"));

        let mut d2 = dev("MISRA-C-2023-15.5", DeviationScope::Project);
        d2.approver = String::new();
        assert!(DeviationRegister::new().add(d2).unwrap_err().contains("approver"));
    }

    #[test]
    fn an_unknown_guideline_is_rejected() {
        let err = DeviationRegister::new()
            .add(dev("MISRA-C-2023-99.99", DeviationScope::Project))
            .unwrap_err();
        assert!(err.contains("not a known guideline"));
    }

    #[test]
    fn rejected_records_are_reported_not_silently_dropped() {
        let reg = DeviationRegister::parse(
            "[[deviation]]\nrule = \"MISRA-C-2023-9.1\"\nscope = \"project\"\n\
             rationale = \"we would rather not\"\napprover = \"someone\"\n",
        )
        .unwrap();
        assert!(reg.is_empty(), "the record must not take effect");
        assert_eq!(reg.rejected().len(), 1);
        assert!(reg.rejected()[0].reason.contains("Mandatory"));
    }

    #[test]
    fn scopes_narrow_correctly() {
        let mut reg = DeviationRegister::new();
        reg.add(dev(
            "MISRA-C-2023-15.5",
            DeviationScope::File { path: "src/hal.c".into() },
        ))
        .unwrap();

        assert!(reg.find("MISRA-C-2023-15.5", "proj/src/hal.c", 10, None, TODAY).is_some());
        assert!(reg.find("MISRA-C-2023-15.5", "proj/src/app.c", 10, None, TODAY).is_none());
        assert!(reg.find("MISRA-C-2023-15.6", "proj/src/hal.c", 10, None, TODAY).is_none());
    }

    #[test]
    fn path_separators_do_not_defeat_a_record() {
        let mut reg = DeviationRegister::new();
        reg.add(dev("MISRA-C-2023-15.5", DeviationScope::File { path: "src/hal.c".into() }))
            .unwrap();
        assert!(reg.find("MISRA-C-2023-15.5", "proj\\src\\hal.c", 1, None, TODAY).is_some());
    }

    #[test]
    fn the_most_specific_record_wins() {
        let mut reg = DeviationRegister::new();
        let mut broad = dev("MISRA-C-2023-15.5", DeviationScope::Project);
        broad.rationale = "broad".into();
        let mut narrow = dev(
            "MISRA-C-2023-15.5",
            DeviationScope::Line { path: "src/hal.c".into(), line: 42 },
        );
        narrow.rationale = "narrow".into();
        reg.add(broad).unwrap();
        reg.add(narrow).unwrap();

        let found = reg.find("MISRA-C-2023-15.5", "src/hal.c", 42, None, TODAY).unwrap();
        assert_eq!(found.rationale, "narrow");
    }

    #[test]
    fn function_scope_requires_the_function_name() {
        let mut reg = DeviationRegister::new();
        reg.add(dev(
            "MISRA-C-2023-15.5",
            DeviationScope::Function { path: "src/hal.c".into(), name: "hal_reset".into() },
        ))
        .unwrap();
        assert!(reg.find("MISRA-C-2023-15.5", "src/hal.c", 1, Some("hal_reset"), TODAY).is_some());
        assert!(reg.find("MISRA-C-2023-15.5", "src/hal.c", 1, Some("hal_init"), TODAY).is_none());
        assert!(reg.find("MISRA-C-2023-15.5", "src/hal.c", 1, None, TODAY).is_none());
    }

    #[test]
    fn applying_a_register_marks_findings_with_the_justification() {
        let mut reg = DeviationRegister::new();
        reg.add(dev("MISRA-C-2023-15.5", DeviationScope::File { path: "src/hal.c".into() }))
            .unwrap();

        let mut findings = vec![
            finding("MISRA-C-2023-15.5", "src/hal.c", 10),
            finding("MISRA-C-2023-15.5", "src/app.c", 10),
        ];
        assert_eq!(reg.apply(&mut findings, TODAY), 1);
        assert!(findings[0].is_suppressed());
        assert!(findings[0].suppressed_by.as_ref().unwrap().contains("a.erickson"));
        assert!(findings[0].suppressed_by.as_ref().unwrap().contains("ECR-4412"));
        assert!(!findings[1].is_suppressed());
    }

    /// `raised` is parsed from the register and was read by nothing, so a
    /// record's date of approval never reached the report that cites it.
    #[test]
    fn the_date_a_deviation_was_raised_is_in_its_citation() {
        let mut reg = DeviationRegister::new();
        reg.add(dev("MISRA-C-2023-15.5", DeviationScope::Project)).unwrap();

        let mut findings = vec![finding("MISRA-C-2023-15.5", "src/hal.c", 10)];
        assert_eq!(reg.apply(&mut findings, TODAY), 1);
        let cite = findings[0].suppressed_by.clone().unwrap();
        assert!(cite.contains("raised 2026-01-15"), "the citation must carry the raise date: {cite}");
        assert!(cite.contains("a.erickson") && cite.contains("ECR-4412"), "{cite}");
    }

    #[test]
    fn unused_records_are_surfaced_for_retirement() {
        let mut reg = DeviationRegister::new();
        reg.add(dev("MISRA-C-2023-15.5", DeviationScope::File { path: "src/gone.c".into() }))
            .unwrap();
        let findings = vec![finding("MISRA-C-2023-15.5", "src/hal.c", 1)];
        assert_eq!(reg.unused(&findings).len(), 1);
    }

    #[test]
    fn expiry_is_evaluated_against_a_supplied_date() {
        let mut d = dev("MISRA-C-2023-15.5", DeviationScope::Project);
        d.expires = Some("2026-01-01".into());
        assert!(d.is_expired("2026-08-04"));
        assert!(!d.is_expired("2025-12-31"));

        let mut reg = DeviationRegister::new();
        reg.add(d).unwrap();
        assert_eq!(reg.expired("2026-08-04").len(), 1);
        assert_eq!(reg.expired("2025-01-01").len(), 0);
    }

    /// The behaviour the expiry date is *for*.
    ///
    /// The test above checked that `is_expired` and `expired()` answer
    /// correctly, and both did. Nothing checked that a lapsed record stops
    /// suppressing, and it did not: `find` filtered on rule and scope alone, so
    /// an acceptance that expired in 2026 went on hiding its finding in 2030.
    ///
    /// That is worse than an unimplemented feature. A register carrying expiry
    /// dates tells a safety team its acceptances lapse and come back for
    /// re-approval. None of them ever would have.
    #[test]
    fn an_expired_deviation_suppresses_nothing() {
        let mut d = dev("MISRA-C-2023-15.5", DeviationScope::Project);
        d.expires = Some("2026-01-01".into());
        let mut reg = DeviationRegister::new();
        reg.add(d).unwrap();

        let mut before = vec![finding("MISRA-C-2023-15.5", "src/hal.c", 10)];
        assert_eq!(reg.apply(&mut before, "2025-12-31"), 1, "still live the day before");
        assert!(before[0].is_suppressed());

        let mut after = vec![finding("MISRA-C-2023-15.5", "src/hal.c", 10)];
        assert_eq!(reg.apply(&mut after, "2026-06-01"), 0, "lapsed, so it covers nothing");
        assert!(
            !after[0].is_suppressed(),
            "an expired acceptance left the finding hidden, which is the whole defect"
        );
    }

    #[test]
    fn register_round_trips_through_toml() {
        let reg = DeviationRegister::parse(
            "[[deviation]]\n\
             rule = \"MISRA-C-2023-21.6\"\n\
             scope = \"path\"\n\
             contains = \"tests/\"\n\
             rationale = \"test harness prints diagnostics\"\n\
             approver = \"a.erickson\"\n",
        )
        .unwrap();
        assert_eq!(reg.len(), 1);
        assert!(reg.find("MISRA-C-2023-21.6", "proj/tests/main.c", 1, None, TODAY).is_some());
        assert!(reg.find("MISRA-C-2023-21.6", "proj/src/main.c", 1, None, TODAY).is_none());
    }

    /// The whole point of relaxing validation: a finding from a tool this crate
    /// has no catalogue for can still be examined, approved and recorded.
    #[test]
    fn an_external_tools_finding_can_be_deviated() {
        let mut reg = DeviationRegister::new();
        assert!(reg.add(dev("clippy::needless_range_loop", DeviationScope::Project)).is_ok());
        assert_eq!(reg.external(), 1);
    }

    /// And the guarantee that relaxation must not cost: an id that *claims* to be
    /// a catalogued guideline is still held to the catalogue, so a mistyped MISRA
    /// number fails loudly instead of becoming a silent external deviation.
    #[test]
    fn a_mistyped_guideline_number_is_still_rejected() {
        let mut reg = DeviationRegister::new();
        let err = reg.add(dev("MISRA-C-2023-99.9", DeviationScope::Project)).unwrap_err();
        assert!(err.contains("not a known guideline"), "{err}");
        assert_eq!(reg.len(), 0);
    }

    /// Mandatory guidelines are still absolute. Deviating one is refused whatever
    /// else changed here — the rule that refused this file's own author once.
    #[test]
    fn a_mandatory_guideline_is_still_refused() {
        let mut reg = DeviationRegister::new();
        let err = reg.add(dev("RUST-2024-MODEL.3", DeviationScope::Project)).unwrap_err();
        assert!(err.contains("Mandatory"), "{err}");
    }

    /// External is decided by namespace, not by a list of tool names — a list
    /// would need editing every time an adapter is added.
    #[test]
    fn external_is_decided_by_namespace() {
        assert!(dev("clippy::needless_range_loop", DeviationScope::Project).is_external());
        assert!(dev("arrayIndexOutOfBounds", DeviationScope::Project).is_external());
        assert!(!dev("MISRA-C-2023-15.5", DeviationScope::Project).is_external());
        assert!(!dev("RUST-2024-PANIC.2", DeviationScope::Project).is_external());
    }

    /// An unvalidated id suppresses nothing when it matches nothing, which is why
    /// accepting it is safe in the direction that matters.
    #[test]
    fn an_external_deviation_that_matches_no_finding_hides_nothing() {
        let mut reg = DeviationRegister::new();
        reg.add(dev("clippy::a_lint_that_does_not_exist", DeviationScope::Project)).unwrap();
        let mut findings = vec![Finding::new(
            "ext.clippy",
            "clippy::needless_range_loop",
            "t",
            Severity::Medium,
            Location::new("src/lib.rs", 1, 1),
        )];
        reg.apply(&mut findings, TODAY);
        assert!(!findings[0].is_suppressed(), "a typo must not suppress a real finding");
    }
}
