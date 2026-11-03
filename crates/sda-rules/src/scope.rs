//! The declared analysis scope: which files are part of the product.
//!
//! # Why this is not a deviation
//!
//! A deviation says *this rule is violated and we accept it*. Scope says *this
//! rule does not apply, because this file is not in the product*. MISRA draws
//! that distinction and a compliance report has to keep it: the first is a
//! decision about a defect, the second is a statement about the boundary of the
//! thing being certified. Collapsing them would let a project make its report
//! clean by declaring its problems out of scope, with no visible difference from
//! a project that genuinely ships less code.
//!
//! # Why this is the most dangerous module here
//!
//! Its entire purpose is to make findings not appear, which is the exact shape
//! of every defect in the failure-mode table in `HANDOFF.md`. Two things keep it
//! honest, and neither is optional:
//!
//! * Every rule carries a `reason` and an `approver`, validated non-empty at
//!   load time exactly as [`crate::Deviation`] validates its own.
//! * Every exclusion is reported with **the number of files it removed**, in the
//!   *NOT CHECKED* section. `tests/ excluded` invites the reader to assume it was
//!   empty; `14 files excluded` cannot be misread. A rule matching zero files is
//!   reported too, because a stale scope rule is worth knowing about.

use serde::{Deserialize, Serialize};

/// One declared exclusion from the analysis scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeRule {
    /// A path prefix, relative to the analysis root. `/`-normalised.
    pub path: String,
    /// Why this is not part of the delivered product.
    pub reason: String,
    /// Who says so. An unattributed scope claim is worthless in an audit.
    pub approver: String,
}

impl ScopeRule {
    /// Whether `relative` — a `/`-normalised path relative to the analysis root
    /// — falls under this rule.
    ///
    /// **Prefix matching on segment boundaries, deliberately not
    /// [`crate::DeviationScope::Path`]'s `contains`.** Reusing `contains` was the
    /// original plan, on the principle of not inventing a second path dialect,
    /// and it is wrong here: `contains("tests/")` also matches
    /// `src/unittests/parser.c`, silently removing a source file nobody meant to
    /// exclude. A deviation that matches too much over-reports a known accepted
    /// violation; a scope rule that matches too much *deletes evidence*. The
    /// asymmetry in consequences justifies the asymmetry in matching.
    pub fn matches(&self, relative: &str) -> bool {
        let rel = normalize(relative);
        let pat = normalize(&self.path);
        if pat.is_empty() {
            return false;
        }
        if rel == pat {
            return true; // the rule names a single file
        }
        // A directory rule matches everything beneath it, and only beneath it:
        // `tests` must match `tests/a.c` but never `tests-helpers/a.c`.
        let dir = if pat.ends_with('/') { pat } else { format!("{pat}/") };
        rel.starts_with(&dir)
    }
}

/// Normalise separators and strip a leading `./` so the two sides compare.
///
/// A path that reduces to nothing — `.`, `/`, `./` — normalises to the empty
/// string, which [`validate`] rejects. It is the analysis root, and a rule
/// excluding the root excludes the product.
fn normalize(p: &str) -> String {
    let s = p.replace('\\', "/");
    let s = s.trim();
    let s = s.strip_prefix("./").unwrap_or(s).trim_start_matches('/');
    if s == "." { String::new() } else { s.trim_end_matches('/').to_string() }
}

/// A rule rejected at load time, kept so the report can show it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeError {
    pub path: String,
    pub reason: String,
}

/// The declared scope of a project.
///
/// An absent register means **everything discovered is in scope**, which is the
/// behaviour before this existed and must remain the default: a first run on an
/// unfamiliar project cannot require a manifest before it will say anything.
#[derive(Clone, Debug, Default)]
pub struct ScopeRegister {
    excluded: Vec<ScopeRule>,
    rejected: Vec<ScopeError>,
}

#[derive(Debug, Deserialize)]
struct RawScope {
    #[serde(default)]
    excluded: Vec<RawRule>,
}

#[derive(Debug, Deserialize)]
struct RawRule {
    path: String,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    approver: String,
}

impl ScopeRegister {
    /// Parse a scope declaration, validating every rule.
    ///
    /// Invalid rules are *rejected and reported*, never silently honoured — the
    /// same discipline [`crate::DeviationRegister::parse`] applies, for the same
    /// reason. A rule that does not hold up must not narrow the scan.
    pub fn parse(text: &str) -> Result<ScopeRegister, String> {
        let raw: RawScope = toml::from_str(text).map_err(|e| e.to_string())?;
        let mut reg = ScopeRegister::default();
        for r in raw.excluded {
            let rule = ScopeRule { path: r.path, reason: r.reason, approver: r.approver };
            match validate(&rule) {
                Err(reason) => reg.rejected.push(ScopeError { path: rule.path, reason }),
                Ok(()) => reg.excluded.push(rule),
            }
        }
        Ok(reg)
    }

    pub fn rules(&self) -> &[ScopeRule] {
        &self.excluded
    }

    pub fn rejected(&self) -> &[ScopeError] {
        &self.rejected
    }

    pub fn len(&self) -> usize {
        self.excluded.len()
    }

    pub fn is_empty(&self) -> bool {
        self.excluded.is_empty()
    }

    /// The first rule excluding `relative`, if any.
    pub fn excluding(&self, relative: &str) -> Option<&ScopeRule> {
        self.excluded.iter().find(|r| r.matches(relative))
    }
}

fn validate(r: &ScopeRule) -> Result<(), String> {
    if r.path.trim().is_empty() {
        return Err("path is empty; a scope rule must name something".into());
    }
    if normalize(&r.path).is_empty() {
        return Err(format!(
            "`{}` resolves to the analysis root; excluding everything is not a scope declaration",
            r.path
        ));
    }
    if r.reason.trim().is_empty() {
        return Err(
            "reason is empty; declaring code out of scope without saying why is not auditable"
                .into(),
        );
    }
    if r.approver.trim().is_empty() {
        return Err("approver is empty; a scope claim must be attributable to a person".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
[[excluded]]
path = "tests/"
reason = "unit test harness; not linked into the delivered image"
approver = "a.erickson"
"#;

    #[test]
    fn a_directory_rule_excludes_what_is_beneath_it() {
        let r = ScopeRegister::parse(GOOD).unwrap();
        assert_eq!(r.len(), 1);
        assert!(r.excluding("tests/harness.c").is_some());
        assert!(r.excluding("tests/deep/nested/a.c").is_some());
        assert!(r.excluding("src/main.c").is_none());
    }

    /// `contains`-style matching — which is what deviations use — would exclude
    /// `src/unittests/parser.c` for a rule reading `tests/`. A deviation that
    /// matches too much over-reports an accepted violation; a scope rule that
    /// matches too much deletes evidence.
    #[test]
    fn a_rule_does_not_match_a_path_that_merely_contains_it() {
        let r = ScopeRegister::parse(GOOD).unwrap();
        assert!(
            r.excluding("src/unittests/parser.c").is_none(),
            "`tests/` must not swallow `unittests/`"
        );
        assert!(r.excluding("src/tests_helper.c").is_none());
    }

    #[test]
    fn a_directory_rule_without_a_trailing_slash_still_means_the_directory() {
        let r = ScopeRegister::parse(
            "[[excluded]]\npath = \"tests\"\nreason = \"harness\"\napprover = \"a\"\n",
        )
        .unwrap();
        assert!(r.excluding("tests/a.c").is_some());
        assert!(r.excluding("tests-helpers/a.c").is_none(), "a sibling directory is not inside");
    }

    #[test]
    fn a_rule_may_name_a_single_file() {
        let r = ScopeRegister::parse(
            "[[excluded]]\npath = \"src/generated.c\"\nreason = \"machine-written\"\napprover = \"a\"\n",
        )
        .unwrap();
        assert!(r.excluding("src/generated.c").is_some());
        assert!(r.excluding("src/generated_helper.c").is_none());
    }

    #[test]
    fn separators_and_leading_dot_slash_do_not_change_the_answer() {
        let r = ScopeRegister::parse(
            "[[excluded]]\npath = \"tests\\\\unit\"\nreason = \"harness\"\napprover = \"a\"\n",
        )
        .unwrap();
        assert!(r.excluding("tests/unit/a.c").is_some());
        assert!(r.excluding("./tests/unit/a.c").is_some());
    }

    /// The whole feature exists to remove findings, so an unjustified or
    /// unattributed rule must not take effect. Rejected, reported, not honoured.
    #[test]
    fn a_rule_without_a_reason_or_an_approver_is_rejected_not_honoured() {
        let r = ScopeRegister::parse(
            "[[excluded]]\npath = \"tests/\"\napprover = \"a\"\n\n\
             [[excluded]]\npath = \"vendor/\"\nreason = \"third party\"\n",
        )
        .unwrap();
        assert_eq!(r.len(), 0, "neither rule may narrow the scan");
        assert_eq!(r.rejected().len(), 2);
        assert!(r.rejected()[0].reason.contains("reason is empty"));
        assert!(r.rejected()[1].reason.contains("approver is empty"));
    }

    /// Excluding the root excludes the product, which is not a scope
    /// declaration — it is a way to make any project report clean.
    #[test]
    fn a_rule_naming_the_root_is_rejected() {
        for path in ["", ".", "/", "./"] {
            let text = format!(
                "[[excluded]]\npath = \"{path}\"\nreason = \"r\"\napprover = \"a\"\n"
            );
            let r = ScopeRegister::parse(&text).unwrap();
            assert_eq!(r.len(), 0, "`{path}` must not be honoured");
            assert_eq!(r.rejected().len(), 1, "`{path}` must be reported");
        }
    }

    #[test]
    fn a_malformed_declaration_is_an_error_not_an_empty_scope() {
        assert!(ScopeRegister::parse("this is not toml {{{").is_err());
    }

    #[test]
    fn an_absent_declaration_excludes_nothing() {
        let r = ScopeRegister::default();
        assert!(r.is_empty());
        assert!(r.excluding("anything/at/all.c").is_none());
    }
}
