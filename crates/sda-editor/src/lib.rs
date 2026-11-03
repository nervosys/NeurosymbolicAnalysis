//! A Rust-native port of Monaco's text model.
//!
//! # Scope, stated plainly
//!
//! Monaco is a large editor: a text model, a view layer, a DOM renderer, a
//! language-services protocol, and a great deal of accumulated behaviour. This
//! crate ports **the model**, which is the part with the interesting semantics
//! and the part every other layer is defined against:
//!
//! * a rope-backed buffer with O(log n) edits ([`TextModel`]),
//! * a monotonic version counter and full [`ChangeEvent`] stream,
//! * position/offset conversion with Monaco's 1-based line, 1-based column
//!   convention,
//! * ranges, cursors and selections with correct multi-cursor edit ordering,
//! * decorations with the stickiness semantics that make them survive edits,
//! * diagnostics projected from [`sda_core::Finding`]s.
//!
//! What it does not port: rendering, the DOM, the view controller, and the
//! language-services protocol. In the GUI those are supplied by the shell —
//! Monaco itself in a webview today, a native renderer later. The model is the
//! piece that has to be right, because a decoration that drifts by one line
//! after an edit puts a finding on the wrong statement.

#![forbid(unsafe_code)]

pub mod decorations;
pub mod markers;
pub mod model;
pub mod position;

pub use decorations::{Decoration, DecorationKind, Stickiness};
pub use markers::{LineMarker, MarkerInput, line_markers};
pub use model::{ChangeEvent, TextEdit, TextModel};
pub use position::{Position, Range, Selection};

/// Project findings onto a model as diagnostic decorations.
///
/// Deliberately separate from [`TextModel`]: the model knows nothing about
/// analysis, and analysis knows nothing about editing. This function is the only
/// place the two meet.
///
/// Byte-located findings are skipped. A finding inside a model artifact carries
/// an offset rather than a line — its `line`/`column` are the `1`/`1` filler
/// every [`sda_core::Location`] has — so decorating it would put a pickle's
/// opcode on line 1 of whatever text buffer happened to be open. That is the
/// same fiction the text, SARIF and UI renderings were fixed to stop telling.
/// Rendering a byte range needs a hex view, which this crate does not have; when
/// one exists, this is where it hooks in.
pub fn diagnostics_for(
    model: &TextModel,
    findings: &[sda_core::Finding],
) -> Vec<Decoration> {
    findings
        .iter()
        .filter(|f| !f.is_suppressed())
        .filter(|f| !f.location.is_byte_located())
        .map(|f| {
            let start = Position::new(f.location.line, f.location.column);
            let end = Position::new(
                f.location.end_line.unwrap_or(f.location.line),
                f.location.end_column.unwrap_or_else(|| {
                    // Without an end column, underline to the end of the line:
                    // a zero-width squiggle is invisible and useless.
                    model.line_length(f.location.line).max(1) + 1
                }),
            );
            Decoration {
                id: f.id.to_string(),
                range: Range::new(start, end).clamped(model),
                kind: DecorationKind::Diagnostic {
                    severity: f.severity,
                    // Runtime-confirmed findings read differently from suspicions,
                    // and the editor should show that.
                    confirmed: f.has_runtime_evidence(),
                },
                message: f.message.clone(),
                stickiness: Stickiness::GrowsOnlyWhenTypingBefore,
                source: f.provider.to_string(),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sda_core::{Evidence, Finding, Location, RuntimeEvent, RuntimeEventKind, Severity};

    #[test]
    fn findings_become_decorations_over_the_right_range() {
        let m = TextModel::new("int main(void) {\n    return 0;\n}\n");
        let f = Finding::new(
            "sda.static.c",
            "MISRA-C-2023-15.5",
            "t",
            Severity::Low,
            Location::new("a.c", 2, 5),
        );
        let d = diagnostics_for(&m, &[f]);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].range.start, Position::new(2, 5));
        assert_eq!(d[0].range.end.line, 2);
        assert!(d[0].range.end.column > 5, "a zero-width diagnostic is invisible");
    }

    #[test]
    fn suppressed_findings_do_not_decorate() {
        let m = TextModel::new("int x;\n");
        let mut f =
            Finding::new("p", "r", "t", Severity::High, Location::new("a.c", 1, 1));
        f.suppressed_by = Some("deviation D-1".into());
        assert!(diagnostics_for(&m, &[f]).is_empty());
    }

    #[test]
    fn runtime_confirmed_findings_are_marked_as_such() {
        let m = TextModel::new("int x;\n");
        let f = Finding::new("p", "r", "t", Severity::High, Location::new("a.c", 1, 1))
            .evidence(Evidence::Runtime {
                event: RuntimeEvent::new(RuntimeEventKind::MemoryError, "oob"),
            });
        match diagnostics_for(&m, &[f])[0].kind {
            DecorationKind::Diagnostic { confirmed, .. } => assert!(confirmed),
            _ => panic!("expected a diagnostic decoration"),
        }
    }

    /// A model-artifact finding has an offset, not a line. Decorating it would
    /// put a pickle's opcode on line 1 of whatever text file is open — the
    /// fiction the text, SARIF and UI renderings were already fixed to stop
    /// telling. A hex view could render it; a text model cannot.
    #[test]
    fn a_byte_located_finding_does_not_decorate_a_text_buffer() {
        let m = TextModel::new("int main(void) {\n    return 0;\n}\n");
        let artifact = Finding::new(
            "sda.ai.artifact",
            "AI-UNSAFE-DESERIALIZATION",
            "t",
            Severity::Critical,
            Location::file_only("model.pkl").at_bytes(0x11a, None),
        );
        assert!(
            diagnostics_for(&m, &[artifact]).is_empty(),
            "an offset is not a line, and line 1 is not where it is"
        );

        // A text finding at the same nominal position still decorates.
        let text = Finding::new(
            "sda.static.c",
            "MISRA-C-2023-15.5",
            "t",
            Severity::Low,
            Location::file_only("a.c"),
        );
        assert_eq!(diagnostics_for(&m, &[text]).len(), 1);
    }

    #[test]
    fn a_finding_past_the_end_of_the_buffer_is_clamped_not_dropped() {
        let m = TextModel::new("int x;\n");
        let f = Finding::new("p", "r", "t", Severity::High, Location::new("a.c", 999, 1));
        let d = diagnostics_for(&m, &[f]);
        assert_eq!(d.len(), 1, "a stale finding must still be visible somewhere");
        assert!(d[0].range.start.line <= m.line_count());
    }
}
