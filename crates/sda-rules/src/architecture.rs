//! `.sda/architecture.toml` — the declared shape of a hybrid system.
//!
//! The interposition proof in `sda_engine::interposition` decides reachability
//! over a declared dataflow. Building that declaration in code was fine for a
//! test and useless for a project: the shape of a system is exactly the kind of
//! claim that belongs in version control next to the code, reviewed when it
//! changes, for the same reason `deviations.toml` and `scope.toml` do.
//!
//! ```toml
//! [[component]]
//! name = "policy"
//! path = "models/policy"
//! boundary = "neural"
//! architecture = "transformer"
//! parameters = 7_000_000_000
//!
//! [[component]]
//! name = "guard::clamp"
//! path = "src/guard"
//! boundary = "symbolic"
//! role = "guard"
//!
//! [[component]]
//! name = "actuator::drive"
//! path = "src/actuator"
//! boundary = "symbolic"
//! role = "effector"
//!
//! [[flow]]
//! from = "policy"
//! to = "guard::clamp"
//!
//! [[flow]]
//! from = "guard::clamp"
//! to = "actuator::drive"
//! ```
//!
//! **An invalid entry is rejected and reported, never silently honoured.** This
//! file decides which paths a proof walks, so a component with no `path` or a
//! flow edge naming nothing would quietly shrink the analysis — and a shrunken
//! interposition proof concludes `interposed` from the paths that survived. The
//! same discipline [`crate::ScopeRegister::parse`] applies, and for a sharper
//! reason: a bad scope rule over-excludes and under-reports, while a bad
//! architecture entry produces a *proof* about a system that is not the one
//! being shipped.
//!
//! An absent file means no interposition claim is attempted at all, which is
//! reported rather than passing as clean.

use serde::{Deserialize, Serialize};

/// One declared component, in the file's own vocabulary.
///
/// Deliberately stringly-typed at this layer: `sda-rules` sits below the engine
/// and does not know `SystemMap`. The engine converts, and the conversion is
/// where an unknown `boundary` or `architecture` becomes a reported problem
/// rather than a parse failure that loses the rest of the file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentDecl {
    pub name: String,
    pub path: String,
    /// `symbolic`, `neural`, or `environment`.
    pub boundary: String,
    /// `ordinary` (default), `guard`, or `effector`.
    #[serde(default)]
    pub role: String,
    /// For a neural component: `mlp`, `cnn`, `rnn`, `transformer`,
    /// `state-space`, `autoencoder`, `gan`, or any other name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<u64>,
    /// Steps a recurrence is unrolled to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence_bound: Option<u32>,
    /// The input region a property would be proved over.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_region: Option<String>,
}

/// One declared dataflow edge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowDecl {
    pub from: String,
    pub to: String,
}

/// An entry rejected at load time, kept so the report can show it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArchitectureError {
    /// What was named, for the operator to find it by.
    pub subject: String,
    pub reason: String,
}

/// The declared architecture of a project.
#[derive(Clone, Debug, Default)]
pub struct ArchitectureDeclaration {
    components: Vec<ComponentDecl>,
    flows: Vec<FlowDecl>,
    rejected: Vec<ArchitectureError>,
}

#[derive(Debug, Deserialize)]
struct RawArchitecture {
    #[serde(default)]
    component: Vec<RawComponent>,
    #[serde(default)]
    flow: Vec<RawFlow>,
}

#[derive(Debug, Deserialize)]
struct RawComponent {
    #[serde(default)]
    name: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    boundary: String,
    #[serde(default)]
    role: String,
    #[serde(default)]
    architecture: Option<String>,
    #[serde(default)]
    parameters: Option<u64>,
    #[serde(default)]
    sequence_bound: Option<u32>,
    #[serde(default)]
    input_region: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawFlow {
    #[serde(default)]
    from: String,
    #[serde(default)]
    to: String,
}

const BOUNDARIES: [&str; 3] = ["symbolic", "neural", "environment"];
const ROLES: [&str; 3] = ["ordinary", "guard", "effector"];

impl ArchitectureDeclaration {
    /// Parse a declaration, validating every entry.
    pub fn parse(text: &str) -> Result<ArchitectureDeclaration, String> {
        let raw: RawArchitecture = toml::from_str(text).map_err(|e| e.to_string())?;
        let mut decl = ArchitectureDeclaration::default();

        for c in raw.component {
            let subject = if c.name.trim().is_empty() {
                format!("component with path `{}`", c.path)
            } else {
                c.name.clone()
            };
            if let Err(reason) = validate_component(&c) {
                decl.rejected.push(ArchitectureError { subject, reason });
                continue;
            }
            if decl.components.iter().any(|e| e.name == c.name) {
                decl.rejected.push(ArchitectureError {
                    subject,
                    reason: "a component with this name is already declared; two components \
                             sharing a name make every flow edge naming it ambiguous"
                        .into(),
                });
                continue;
            }
            decl.components.push(ComponentDecl {
                name: c.name,
                path: c.path,
                boundary: c.boundary.to_ascii_lowercase(),
                role: if c.role.trim().is_empty() {
                    "ordinary".to_string()
                } else {
                    c.role.to_ascii_lowercase()
                },
                architecture: c.architecture,
                parameters: c.parameters,
                sequence_bound: c.sequence_bound,
                input_region: c.input_region,
            });
        }

        for f in raw.flow {
            let subject = format!("{} -> {}", f.from, f.to);
            if f.from.trim().is_empty() || f.to.trim().is_empty() {
                decl.rejected.push(ArchitectureError {
                    subject,
                    reason: "a flow edge needs both `from` and `to`".into(),
                });
                continue;
            }
            if f.from == f.to {
                decl.rejected.push(ArchitectureError {
                    subject,
                    reason: "a self-edge adds no path and no component; it is almost certainly a \
                             typo for a real edge that is now missing"
                        .into(),
                });
                continue;
            }
            decl.flows.push(FlowDecl { from: f.from, to: f.to });
        }

        Ok(decl)
    }

    pub fn components(&self) -> &[ComponentDecl] {
        &self.components
    }
    pub fn flows(&self) -> &[FlowDecl] {
        &self.flows
    }
    pub fn rejected(&self) -> &[ArchitectureError] {
        &self.rejected
    }
    pub fn is_empty(&self) -> bool {
        self.components.is_empty()
    }
    pub fn len(&self) -> usize {
        self.components.len()
    }

    /// What the file says that the proof does not act on.
    ///
    /// Separate from [`Self::rejected`] because nothing was thrown away: the
    /// entry is kept, and a part of what it declares has no effect.
    pub fn ignored(&self) -> Vec<String> {
        let mut out = Vec::new();
        let named: Vec<&str> = self.components.iter().map(|c| c.name.as_str()).collect();
        for f in &self.flows {
            for end in [&f.from, &f.to] {
                if !named.contains(&end.as_str()) {
                    out.push(format!(
                        "flow edge `{} -> {}` names `{end}`, which is not a declared component; \
                         the edge is kept, but a typo here removes a path from the interposition \
                         proof without failing it",
                        f.from, f.to
                    ));
                }
            }
        }
        // A warning and not a rejection: a refused component leaves the proof, and
        // dropping an effector over a stray key would delete its obligation.
        for c in &self.components {
            if c.parameters.is_none() && c.sequence_bound.is_none() && c.input_region.is_none() {
                continue;
            }
            if c.boundary != "neural" {
                out.push(format!(
                    "`{}` is not neural but declares parameters, a sequence bound or an input \
                     region; those describe a neural model, so they were ignored",
                    c.name
                ));
            } else if c.architecture.is_none() {
                out.push(format!(
                    "`{}` declares parameters, a sequence bound or an input region but no \
                     architecture; the profile they describe is built only for a named \
                     architecture, so they were ignored",
                    c.name
                ));
            }
        }
        out
    }

    /// Everything in [`Self::ignored`], and the claims the declaration cannot support.
    ///
    /// The second half the interposition layer states itself, so it is advisory
    /// to the loader.
    pub fn warnings(&self) -> Vec<String> {
        let mut out = self.ignored();
        if !self.components.iter().any(|c| c.role == "effector") {
            out.push(
                "no component is declared an effector, so interposition cannot be checked. That \
                 is the absence of a question, not a clean answer"
                    .to_string(),
            );
        }
        if !self.components.iter().any(|c| c.role == "guard")
            && self.components.iter().any(|c| c.boundary == "neural")
        {
            out.push(
                "a neural component is declared with no guard anywhere; every path from it to an \
                 effector is a bypass by construction"
                    .to_string(),
            );
        }
        out
    }
}

fn validate_component(c: &RawComponent) -> Result<(), String> {
    if c.name.trim().is_empty() {
        return Err("name is empty; a component must be nameable by a flow edge".into());
    }
    if c.path.trim().is_empty() {
        return Err(format!(
            "`{}` declares no path, so no finding could ever be attributed to it",
            c.name
        ));
    }
    if c.path.trim() == "." || c.path.trim() == "/" {
        return Err(format!(
            "`{}` owns the analysis root; one component owning everything makes every other \
             declaration unreachable",
            c.name
        ));
    }
    if !BOUNDARIES.contains(&c.boundary.to_ascii_lowercase().as_str()) {
        return Err(format!(
            "`{}` has boundary `{}`; expected one of {}. Guessing which side of the seam a \
             component is on would decide what evidence it can carry",
            c.name,
            c.boundary,
            BOUNDARIES.join(", ")
        ));
    }
    let role = c.role.to_ascii_lowercase();
    if !role.is_empty() && !ROLES.contains(&role.as_str()) {
        return Err(format!(
            "`{}` has role `{}`; expected one of {}",
            c.name,
            c.role,
            ROLES.join(", ")
        ));
    }
    if c.boundary.eq_ignore_ascii_case("neural") && role == "guard" {
        return Err(format!(
            "`{}` is declared a neural guard. A guard is what constrains a model's output, and \
             nothing about a learned model can be proved at the scale this is for — a guard that \
             is itself a model moves the premise rather than discharging it",
            c.name
        ));
    }
    if !c.boundary.eq_ignore_ascii_case("neural") && c.architecture.is_some() {
        return Err(format!(
            "`{}` is not neural but declares an architecture; one of the two is wrong, and \
             picking which would be a guess",
            c.name
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
[[component]]
name = "policy"
path = "models/policy"
boundary = "neural"
architecture = "transformer"
parameters = 7000000000

[[component]]
name = "guard::clamp"
path = "src/guard"
boundary = "symbolic"
role = "guard"

[[component]]
name = "actuator::drive"
path = "src/actuator"
boundary = "symbolic"
role = "effector"

[[flow]]
from = "policy"
to = "guard::clamp"

[[flow]]
from = "guard::clamp"
to = "actuator::drive"
"#;

    #[test]
    fn a_well_formed_declaration_loads_with_nothing_rejected() {
        let d = ArchitectureDeclaration::parse(GOOD).unwrap();
        assert_eq!(d.len(), 3);
        assert_eq!(d.flows().len(), 2);
        assert!(d.rejected().is_empty());
        assert!(d.warnings().is_empty());
        assert_eq!(d.components()[1].role, "guard");
        assert_eq!(d.components()[0].parameters, Some(7_000_000_000));
    }

    #[test]
    fn a_stray_profile_field_warns_and_keeps_the_component() {
        let d = ArchitectureDeclaration::parse(
            "[[component]]\nname = \"act\"\npath = \"a\"\nboundary = \"symbolic\"\n\
             role = \"effector\"\nsequence_bound = 64\n",
        )
        .expect("well-formed");
        assert!(d.rejected().is_empty(), "an effector must not leave the proof over this");
        assert_eq!(d.len(), 1);
        assert!(d.ignored().iter().any(|w| w.contains("`act` is not neural")));
    }

    #[test]
    fn a_component_with_no_path_is_rejected_rather_than_carried() {
        let d = ArchitectureDeclaration::parse(
            "[[component]]\nname = \"ghost\"\nboundary = \"symbolic\"\n",
        )
        .unwrap();
        assert_eq!(d.len(), 0);
        assert_eq!(d.rejected().len(), 1);
        assert!(d.rejected()[0].reason.contains("no finding could ever be attributed"));
    }

    #[test]
    fn an_unknown_boundary_is_rejected_rather_than_guessed_at() {
        let d = ArchitectureDeclaration::parse(
            "[[component]]\nname = \"x\"\npath = \"src/x\"\nboundary = \"probably-symbolic\"\n",
        )
        .unwrap();
        assert_eq!(d.rejected().len(), 1);
        assert!(d.rejected()[0].reason.contains("decide what evidence it can carry"));
    }

    #[test]
    fn a_neural_guard_is_refused_because_it_moves_the_premise_rather_than_paying_it() {
        let d = ArchitectureDeclaration::parse(
            "[[component]]\nname = \"llm-judge\"\npath = \"models/judge\"\nboundary = \
             \"neural\"\nrole = \"guard\"\n",
        )
        .unwrap();
        assert_eq!(d.len(), 0);
        assert!(d.rejected()[0].reason.contains("moves the premise rather than discharging it"));
    }

    #[test]
    fn a_duplicate_name_is_rejected_because_it_makes_every_edge_ambiguous() {
        let text = "[[component]]\nname = \"a\"\npath = \"src/a\"\nboundary = \"symbolic\"\n\
                    [[component]]\nname = \"a\"\npath = \"src/b\"\nboundary = \"symbolic\"\n";
        let d = ArchitectureDeclaration::parse(text).unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(d.rejected().len(), 1);
        assert!(d.rejected()[0].reason.contains("ambiguous"));
    }

    #[test]
    fn a_component_owning_the_root_is_refused() {
        let d = ArchitectureDeclaration::parse(
            "[[component]]\nname = \"all\"\npath = \".\"\nboundary = \"symbolic\"\n",
        )
        .unwrap();
        assert!(d.rejected()[0].reason.contains("makes every other declaration unreachable"));
    }

    #[test]
    fn an_architecture_on_a_symbolic_component_is_a_contradiction_not_a_default() {
        let d = ArchitectureDeclaration::parse(
            "[[component]]\nname = \"x\"\npath = \"src/x\"\nboundary = \"symbolic\"\n\
             architecture = \"cnn\"\n",
        )
        .unwrap();
        assert!(d.rejected()[0].reason.contains("picking which would be a guess"));
    }

    #[test]
    fn an_edge_to_an_undeclared_component_warns_without_discarding_it() {
        let text = format!("{GOOD}\n[[flow]]\nfrom = \"policy\"\nto = \"shadow\"\n");
        let d = ArchitectureDeclaration::parse(&text).unwrap();
        assert_eq!(d.flows().len(), 3, "kept: dropping it would hide the mistake");
        assert!(d.warnings().iter().any(|w| w.contains("removes a path")));
    }

    #[test]
    fn a_self_edge_is_rejected_as_a_probable_typo() {
        let d = ArchitectureDeclaration::parse("[[flow]]\nfrom = \"a\"\nto = \"a\"\n").unwrap();
        assert!(d.flows().is_empty());
        assert!(d.rejected()[0].reason.contains("typo for a real edge that is now missing"));
    }

    #[test]
    fn a_declaration_with_no_effector_says_the_question_is_absent() {
        let d = ArchitectureDeclaration::parse(
            "[[component]]\nname = \"policy\"\npath = \"models/policy\"\nboundary = \"neural\"\n",
        )
        .unwrap();
        let w = d.warnings();
        assert!(w.iter().any(|w| w.contains("absence of a question, not a clean answer")));
        assert!(w.iter().any(|w| w.contains("bypass by construction")), "and no guard either");
    }

    #[test]
    fn malformed_toml_is_an_error_rather_than_an_empty_declaration() {
        assert!(ArchitectureDeclaration::parse("[[component]\nname =").is_err());
    }
}
