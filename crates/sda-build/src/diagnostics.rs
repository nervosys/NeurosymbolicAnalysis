//! Unified compiler-diagnostic parsing.
//!
//! Every compiler already performs a great deal of static analysis and then
//! prints it in its own format. Parsing that output turns any toolchain — GCC,
//! MSVC, IAR, rustc — into an analysis provider, and it is the route by which
//! guidelines needing type information get checked at all.
//!
//! It is also the feedback channel for the autonomous SWE loop: a structured
//! diagnostic with a file, a line, and a message is what an agent needs to
//! propose a patch and know whether the patch worked.

use crate::toolchain::DiagnosticFormat;
use sda_core::{Confidence, Evidence, Finding, Location, Severity};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Error,
    Warning,
    Note,
}

impl Level {
    pub fn severity(&self) -> Severity {
        match self {
            Level::Error => Severity::High,
            Level::Warning => Severity::Medium,
            Level::Note => Severity::Info,
        }
    }
    fn parse(s: &str) -> Option<Level> {
        match s.trim().to_ascii_lowercase().as_str() {
            "error" | "fatal error" => Some(Level::Error),
            "warning" => Some(Level::Warning),
            "note" | "remark" | "info" => Some(Level::Note),
            _ => None,
        }
    }
}

/// One diagnostic, normalized across compilers.
/// Compiler output carries the host's separators; everything downstream — SARIF
/// URIs, deviation scopes, correlation matching and the agent-facing `location`
/// strings — is `/`. Normalising as diagnostics are parsed stops one project
/// being described two ways depending on which machine ran the build.
fn uri_path(s: &str) -> String {
    s.replace('\\', "/")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub level: Level,
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub message: String,
    /// The compiler's own code, e.g. `-Wunused-variable`, `C4996`, `Pe177`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// End of the construct the diagnostic is about, when the compiler said.
    ///
    /// Only rustc's JSON states one. GCC-style, MSVC and IAR output give a
    /// position and nothing more, and these stay `None` for them rather than
    /// being guessed at — a fabricated extent would underline the wrong text
    /// with the same confidence as a real one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_column: Option<u32>,
}

impl Diagnostic {
    /// Convert to a finding attributed to the compiler that produced it.
    pub fn to_finding(&self, compiler: &str) -> Finding {
        let rule = self
            .code
            .clone()
            .map(|c| format!("COMPILER-{c}"))
            .unwrap_or_else(|| format!("COMPILER-{}", self.level_str()));
        let mut loc = Location::new(&self.file, self.line, self.column);
        if let (Some(el), Some(ec)) = (self.end_line, self.end_column) {
            // A degenerate extent is not one; the native analyzers guard the
            // same way rather than render a zero-width underline.
            if (el, ec) > (self.line, self.column) {
                loc = loc.spanning(el, ec);
            }
        }
        Finding::new(
            format!("ext.compiler.{compiler}"),
            rule,
            self.message.clone(),
            self.level.severity(),
            loc,
        )
        .message(self.message.clone())
        // The compiler resolved the types; it is not guessing.
        .confidence(Confidence::High)
        .evidence(Evidence::note(format!("reported by {compiler}")))
    }

    fn level_str(&self) -> &'static str {
        match self.level {
            Level::Error => "ERROR",
            Level::Warning => "WARNING",
            Level::Note => "NOTE",
        }
    }
}

/// Parse compiler output in the given format.
pub fn parse(text: &str, format: DiagnosticFormat) -> Vec<Diagnostic> {
    match format {
        DiagnosticFormat::GccLike => parse_gcc_like(text),
        DiagnosticFormat::Msvc => parse_msvc(text),
        DiagnosticFormat::Iar => parse_iar(text),
        DiagnosticFormat::RustcJson => parse_rustc_json(text),
    }
}

/// `path:line:col: level: message [-Wflag]`
fn parse_gcc_like(text: &str) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        // Split off the level, which is the first `: word: ` after the position.
        let Some((position, rest)) = split_position(l) else { continue };
        let Some((level_str, message)) = rest.split_once(':') else { continue };
        let Some(level) = Level::parse(level_str) else { continue };

        let (file, line_no, col) = position;
        let message = message.trim();
        // Trailing `[-Wflag]` is the diagnostic's identity.
        let (message, code) = match (message.rfind('['), message.ends_with(']')) {
            (Some(i), true) => (message[..i].trim(), Some(message[i + 1..message.len() - 1].to_string())),
            _ => (message, None),
        };

        out.push(Diagnostic {
            level,
            file: uri_path(&file),
            line: line_no,
            column: col,
            message: message.to_string(),
            code,
            end_line: None,
            end_column: None,
        });
    }
    out
}

/// Split `path:line:col:` off the front, tolerating Windows drive letters.
fn split_position(l: &str) -> Option<((String, u32, u32), &str)> {
    // Walk colons from the left, skipping a drive-letter colon at index 1.
    let bytes = l.as_bytes();
    let mut colons = Vec::new();
    for (i, b) in bytes.iter().enumerate() {
        if *b == b':' {
            if i == 1 && bytes.first().is_some_and(|c| c.is_ascii_alphabetic()) {
                continue; // `C:` drive prefix
            }
            colons.push(i);
        }
        if colons.len() >= 3 {
            break;
        }
    }
    if colons.len() < 3 {
        return None;
    }
    let file = l[..colons[0]].to_string();
    let line: u32 = l[colons[0] + 1..colons[1]].trim().parse().ok()?;
    // The column is optional in some GCC output; fall back to 1.
    let col: u32 = l[colons[1] + 1..colons[2]].trim().parse().unwrap_or(1);
    Some(((file, line, col), &l[colons[2] + 1..]))
}

/// `path(line,col): level Cnnnn: message`
fn parse_msvc(text: &str) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim();

        // Link failures carry no source position, so they do not match the
        // shape above — and an autonomous loop that cannot see
        // `unresolved external symbol` has nothing to act on. Reported at the
        // artifact that failed to link, with no line, because there is none.
        if let Some(d) = parse_msvc_link(l) {
            out.push(d);
            continue;
        }

        let Some(open) = l.find('(') else { continue };
        let Some(close) = l[open..].find(')').map(|i| i + open) else { continue };
        let position = &l[open + 1..close];
        let (line_no, col) = match position.split_once(',') {
            Some((a, b)) => (a.trim().parse().ok(), b.trim().parse().unwrap_or(1)),
            None => (position.trim().parse().ok(), 1u32),
        };
        let Some(line_no) = line_no else { continue };

        let rest = l[close + 1..].trim_start_matches(':').trim();
        // `warning C4996: 'x': deprecated`
        let mut parts = rest.splitn(2, ':');
        let head = parts.next().unwrap_or("").trim();
        let message = parts.next().unwrap_or("").trim();
        let mut head_words = head.split_whitespace();
        let Some(level) = head_words.next().and_then(Level::parse) else { continue };
        let code = head_words.next().map(|s| s.to_string());

        out.push(Diagnostic {
            level,
            file: uri_path(&l[..open]),
            line: line_no,
            column: col,
            message: message.to_string(),
            code,
            end_line: None,
            end_column: None,
        });
    }
    out
}

/// `main.obj : error LNK2019: unresolved external symbol foo`
/// `LINK : fatal error LNK1120: 1 unresolved externals`
fn parse_msvc_link(l: &str) -> Option<Diagnostic> {
    let at = l.find(" LNK")?;
    // Everything before the level word, which is the artifact that failed.
    let (before, after) = l.split_at(at);
    let mut head = before.rsplitn(2, ':');
    let level_part = head.next()?.trim(); // `error`, `fatal error`, `warning`
    let file = head.next().unwrap_or("LINK").trim();

    let level = Level::parse(level_part.split_whitespace().next_back()?)?;
    let mut rest = after.trim().splitn(2, ':');
    let code = rest.next()?.trim().to_string();
    let message = rest.next()?.trim().to_string();
    if message.is_empty() {
        return None;
    }

    Some(Diagnostic {
        level,
        file: uri_path(if file.is_empty() { "LINK" } else { file }),
        line: 1,
        column: 1,
        message,
        code: Some(code),
        end_line: None,
        end_column: None,
    })
}

/// `"path",line  Level[Tag]: message`
fn parse_iar(text: &str) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if !l.starts_with('"') {
            continue;
        }
        let Some(end_quote) = l[1..].find('"').map(|i| i + 1) else { continue };
        let file = l[1..end_quote].to_string();
        let rest = l[end_quote + 1..].trim_start_matches(',').trim();
        let mut it = rest.splitn(2, char::is_whitespace);
        let Some(line_no) = it.next().and_then(|s| s.trim().parse::<u32>().ok()) else { continue };
        let tail = it.next().unwrap_or("").trim();

        // `Warning[Pe177]: message`
        let (head, message) = match tail.split_once(':') {
            Some((h, m)) => (h.trim(), m.trim()),
            None => continue,
        };
        let (level_str, code) = match head.split_once('[') {
            Some((lv, c)) => (lv, Some(c.trim_end_matches(']').to_string())),
            None => (head, None),
        };
        let Some(level) = Level::parse(level_str) else { continue };

        out.push(Diagnostic {
            level,
            file: uri_path(&file),
            line: line_no,
            column: 1,
            message: message.to_string(),
            code,
            end_line: None,
            end_column: None,
        });
    }
    out
}

/// rustc's `--error-format=json`, and cargo's `--message-format=json`.
///
/// Cargo wraps each rustc diagnostic in `{"reason":"compiler-message","message":{…}}`
/// and interleaves build-progress records that carry no diagnostic at all. A
/// parser that only understood raw rustc output silently returned nothing for
/// every Cargo project — a broken build reported as zero errors.
fn parse_rustc_json(text: &str) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with('{') {
            continue;
        }
        let Ok(raw) = serde_json::from_str::<serde_json::Value>(line) else { continue };

        // Unwrap the cargo envelope when present; a bare rustc diagnostic has
        // its `level` at the top level already.
        let v = match raw.get("message").filter(|m| m.is_object()) {
            Some(inner) => inner.clone(),
            None => raw,
        };

        let Some(level) = v.get("level").and_then(|l| l.as_str()).and_then(Level::parse) else {
            continue;
        };
        let message = v.get("message").and_then(|m| m.as_str()).unwrap_or("").to_string();
        let code = v
            .get("code")
            .and_then(|c| c.get("code"))
            .and_then(|c| c.as_str())
            .map(|s| s.to_string());

        // Use the primary span; a diagnostic with no span is a summary line.
        let span = v
            .get("spans")
            .and_then(|s| s.as_array())
            .and_then(|a| a.iter().find(|s| s.get("is_primary").and_then(|p| p.as_bool()) == Some(true)))
            .or_else(|| v.get("spans").and_then(|s| s.as_array()).and_then(|a| a.first()));
        let Some(span) = span else { continue };

        out.push(Diagnostic {
            level,
            file: uri_path(span.get("file_name").and_then(|f| f.as_str()).unwrap_or("")),
            line: span.get("line_start").and_then(|l| l.as_u64()).unwrap_or(1) as u32,
            column: span.get("column_start").and_then(|c| c.as_u64()).unwrap_or(1) as u32,
            message,
            code,
            // rustc brackets what it is complaining about, in the same span
            // object the start is read from. Reading past it cost every rustc
            // diagnostic its extent for no reason at all.
            end_line: span.get("line_end").and_then(|l| l.as_u64()).map(|n| n as u32),
            end_column: span.get("column_end").and_then(|c| c.as_u64()).map(|n| n as u32),
        });
    }
    out
}

/// Summarize diagnostics for the SWE loop: what failed, and where to start.
pub fn summarize(diags: &[Diagnostic]) -> String {
    let errors = diags.iter().filter(|d| d.level == Level::Error).count();
    let warnings = diags.iter().filter(|d| d.level == Level::Warning).count();
    if errors == 0 && warnings == 0 {
        return "the build produced no diagnostics".into();
    }
    let first = diags.iter().find(|d| d.level == Level::Error).or_else(|| diags.first());
    match first {
        Some(d) => format!(
            "{errors} error(s) and {warnings} warning(s). First: {}:{}:{} — {}",
            d.file, d.line, d.column, d.message
        ),
        None => format!("{errors} error(s) and {warnings} warning(s)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An agent reads these paths out of `swe.iterate` and compares them with
    /// the `location` strings a scan produces, which are always `/`. A build on
    /// Windows used to report `src\main.rs` for the same file a scan called
    /// `src/main.rs`, so the two could not be matched up.
    #[test]
    fn diagnostic_paths_are_normalised_whatever_the_compiler_emitted() {
        let gcc = parse("src\\drivers\\uart.c:4:9: error: boom", DiagnosticFormat::GccLike);
        assert_eq!(gcc[0].file, "src/drivers/uart.c");

        // Cargo emits one JSON object per line; keep it on one line.
        let cargo = parse(
            r#"{"reason":"compiler-message","message":{"level":"error","message":"boom","spans":[{"is_primary":true,"file_name":"src\\main.rs","line_start":3,"column_start":5}]}}"#,
            DiagnosticFormat::RustcJson,
        );
        assert_eq!(cargo[0].file, "src/main.rs");

        let msvc = parse("src\\app\\win.c(9,3): error C2065: boom", DiagnosticFormat::Msvc);
        assert_eq!(msvc[0].file, "src/app/win.c");
    }

    /// Found by running the SWE loop against a real CMake+MSVC project: the
    /// compile succeeded and the *link* failed, which has no source position,
    /// so nothing parsed and the loop had no actionable item to hand back.
    #[test]
    fn msvc_link_failures_are_diagnostics_too() {
        let text = "main.obj : error LNK2019: unresolved external symbol missing_helper referenced in function main\n\
                    C:\\build\\swe_c.exe : fatal error LNK1120: 1 unresolved externals";
        let d = parse(text, DiagnosticFormat::Msvc);
        assert_eq!(d.len(), 2, "got {d:?}");
        assert_eq!(d[0].level, Level::Error);
        assert_eq!(d[0].file, "main.obj");
        assert_eq!(d[0].code.as_deref(), Some("LNK2019"));
        assert!(d[0].message.contains("unresolved external symbol missing_helper"));
        assert_eq!(d[1].file, "C:/build/swe_c.exe");
        assert_eq!(d[1].code.as_deref(), Some("LNK1120"));
    }

    /// The compiler-diagnostic shape must keep working alongside it.
    #[test]
    fn link_parsing_does_not_disturb_compiler_diagnostics() {
        let d = parse("src\\a.c(7,3): error C2143: syntax error", DiagnosticFormat::Msvc);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].line, 7);
        assert_eq!(d[0].column, 3);
        assert_eq!(d[0].code.as_deref(), Some("C2143"));
    }

    #[test]
    fn parses_gcc_diagnostics_with_flags() {
        let text = "src/main.c:12:5: warning: unused variable 'x' [-Wunused-variable]\n\
                    src/main.c:20:1: error: expected ';' before '}' token";
        let d = parse(text, DiagnosticFormat::GccLike);
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].level, Level::Warning);
        assert_eq!((d[0].line, d[0].column), (12, 5));
        assert_eq!(d[0].code.as_deref(), Some("-Wunused-variable"));
        assert_eq!(d[1].level, Level::Error);
    }

    #[test]
    fn windows_drive_letters_do_not_break_position_parsing() {
        let d = parse(
            "C:/proj/src/main.c:7:3: warning: comparison is always true",
            DiagnosticFormat::GccLike,
        );
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].file, "C:/proj/src/main.c");
        assert_eq!(d[0].line, 7);
    }

    #[test]
    fn parses_msvc_diagnostics() {
        let text = "C:\\proj\\main.c(12,5): warning C4996: 'strcpy': This function may be unsafe\n\
                    C:\\proj\\main.c(20): error C2143: syntax error";
        let d = parse(text, DiagnosticFormat::Msvc);
        assert_eq!(d.len(), 2);
        assert_eq!(d[0].code.as_deref(), Some("C4996"));
        assert_eq!((d[0].line, d[0].column), (12, 5));
        assert_eq!(d[1].level, Level::Error);
        assert_eq!(d[1].column, 1, "MSVC may omit the column");
    }

    #[test]
    fn parses_iar_diagnostics() {
        let text = "\"C:\\proj\\src\\main.c\",42  Warning[Pe177]: variable \"x\" was declared but never referenced";
        let d = parse(text, DiagnosticFormat::Iar);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].level, Level::Warning);
        assert_eq!(d[0].line, 42);
        assert_eq!(d[0].code.as_deref(), Some("Pe177"));
        assert!(d[0].message.contains("never referenced"));
    }

    #[test]
    fn parses_rustc_json_using_the_primary_span() {
        let text = r#"{"message":"unused variable: `x`","code":{"code":"unused_variables"},"level":"warning","spans":[{"file_name":"src/lib.rs","line_start":3,"column_start":9,"is_primary":true}]}
{"message":"aborting due to previous error","level":"error","spans":[]}"#;
        let d = parse(text, DiagnosticFormat::RustcJson);
        assert_eq!(d.len(), 1, "a span-less summary line is not a located diagnostic");
        assert_eq!(d[0].file, "src/lib.rs");
        assert_eq!((d[0].line, d[0].column), (3, 9));
        assert_eq!(d[0].code.as_deref(), Some("unused_variables"));
    }

    /// rustc states where the offending construct ends, in the same span object
    /// the start comes from. Reading only the start flattened every rustc
    /// diagnostic to a point, so the editor underlined to end-of-line and the
    /// SARIF region had no end — an extent the compiler had already computed.
    #[test]
    fn a_rustc_span_end_reaches_the_finding() {
        let text = r#"{"message":"mismatched types","code":{"code":"E0308"},"level":"error","spans":[{"file_name":"src/main.rs","line_start":4,"column_start":13,"line_end":4,"column_end":22,"is_primary":true}]}"#;
        let d = parse(text, DiagnosticFormat::RustcJson);
        assert_eq!((d[0].end_line, d[0].end_column), (Some(4), Some(22)));

        let f = d[0].to_finding("rustc");
        assert_eq!(f.location.end_line, Some(4));
        assert_eq!(f.location.end_column, Some(22));
    }

    /// GCC-style, MSVC and IAR output state a position and no extent. Nothing
    /// may invent one, and a degenerate span from any source is dropped rather
    /// than rendered as a zero-width underline.
    #[test]
    fn compilers_that_state_no_extent_yield_a_point_not_a_guess() {
        let gcc = parse("src/a.c:3:5: warning: unused [-Wunused]", DiagnosticFormat::GccLike);
        assert_eq!(gcc[0].end_column, None);
        assert_eq!(gcc[0].to_finding("gcc").location.end_column, None);

        let msvc = parse(r"a.c(7,2): warning C4996: deprecated", DiagnosticFormat::Msvc);
        assert_eq!(msvc[0].end_column, None);

        let degenerate = Diagnostic {
            end_line: Some(4),
            end_column: Some(13),
            ..parse(
                r#"{"message":"m","level":"error","spans":[{"file_name":"a.rs","line_start":4,"column_start":13,"is_primary":true}]}"#,
                DiagnosticFormat::RustcJson,
            )
            .remove(0)
        };
        assert_eq!(
            degenerate.to_finding("rustc").location.end_column,
            None,
            "an end equal to the start is not an extent"
        );
    }

    #[test]
    fn cargos_json_envelope_is_unwrapped() {
        // Cargo wraps rustc's diagnostic and interleaves progress records. A
        // parser that only understood raw rustc output reported zero errors for
        // every Cargo project that failed to build.
        let text = r#"{"reason":"compiler-artifact","package_id":"broken 0.1.0"}
{"reason":"compiler-message","message":{"message":"mismatched types","code":{"code":"E0308"},"level":"error","spans":[{"file_name":"src/main.rs","line_start":1,"column_start":26,"is_primary":true}]}}
{"reason":"build-finished","success":false}"#;
        let d = parse(text, DiagnosticFormat::RustcJson);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].level, Level::Error);
        assert_eq!(d[0].code.as_deref(), Some("E0308"));
        assert_eq!((d[0].line, d[0].column), (1, 26));
        assert_eq!(d[0].file, "src/main.rs");
    }

    #[test]
    fn unparseable_lines_are_skipped_without_losing_the_rest() {
        let text = "make: entering directory\n\
                    src/a.c:1:1: error: bad\n\
                    ld: cannot find -lfoo";
        assert_eq!(parse(text, DiagnosticFormat::GccLike).len(), 1);
    }

    #[test]
    fn diagnostics_become_findings_attributed_to_the_compiler() {
        let d = &parse("a.c:1:2: error: boom [-Wboom]", DiagnosticFormat::GccLike)[0];
        let f = d.to_finding("gcc");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.confidence, Confidence::High);
        assert_eq!(f.provider.as_str(), "ext.compiler.gcc");
        assert_eq!(f.rule.as_str(), "COMPILER--Wboom");
    }

    #[test]
    fn the_summary_names_the_first_error_for_the_swe_loop() {
        let d = parse(
            "a.c:1:1: warning: w\nb.c:9:4: error: expected ';'",
            DiagnosticFormat::GccLike,
        );
        let s = summarize(&d);
        assert!(s.contains("1 error(s)"));
        assert!(s.contains("b.c:9:4"));
        assert_eq!(summarize(&[]), "the build produced no diagnostics");
    }
}
