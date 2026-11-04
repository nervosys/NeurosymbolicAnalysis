//! A structural model of a C/C++ translation unit, built from the token stream.
//!
//! This is not a parse tree. It is the set of *structural facts* that the bulk of
//! MISRA's rules are actually written about: which directives appear and how they
//! nest, where functions begin and end, whether a control statement's body is
//! braced, whether every switch clause terminates, where `goto` jumps go.
//!
//! Building facts rather than a tree keeps the pass linear, keeps it working on
//! code that does not compile, and — importantly — keeps it honest: every field
//! here is something the token stream genuinely determines.

use crate::clex::{CToken, CTokenKind, Lexed};
use crate::span::{Pos, Span};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DirectiveKind {
    Include,
    Define,
    Undef,
    If,
    Ifdef,
    Ifndef,
    Elif,
    /// C23 / C++23 `#elifdef`.
    Elifdef,
    /// C23 / C++23 `#elifndef`.
    Elifndef,
    Else,
    Endif,
    Pragma,
    Error,
    /// C23 `#warning`.
    Warning,
    Line,
    /// C23 `#embed`.
    Embed,
    /// `#` alone (a null directive).
    Null,
    Unknown,
}

impl DirectiveKind {
    fn parse(word: &str) -> DirectiveKind {
        use DirectiveKind::*;
        match word {
            "include" | "include_next" | "import" => Include,
            "define" => Define,
            "undef" => Undef,
            "if" => If,
            "ifdef" => Ifdef,
            "ifndef" => Ifndef,
            "elif" => Elif,
            "elifdef" => Elifdef,
            "elifndef" => Elifndef,
            "else" => Else,
            "endif" => Endif,
            "pragma" => Pragma,
            "error" => Error,
            "warning" => Warning,
            "line" => Line,
            "embed" => Embed,
            "" => Null,
            _ => Unknown,
        }
    }

    /// Opens a new conditional nesting level.
    pub fn opens_conditional(&self) -> bool {
        use DirectiveKind::*;
        matches!(self, If | Ifdef | Ifndef)
    }
    /// Continues the current level without changing depth.
    pub fn continues_conditional(&self) -> bool {
        use DirectiveKind::*;
        matches!(self, Elif | Elifdef | Elifndef | Else)
    }
    pub fn closes_conditional(&self) -> bool {
        matches!(self, DirectiveKind::Endif)
    }

    pub fn as_str(&self) -> &'static str {
        use DirectiveKind::*;
        match self {
            Include => "include",
            Define => "define",
            Undef => "undef",
            If => "if",
            Ifdef => "ifdef",
            Ifndef => "ifndef",
            Elif => "elif",
            Elifdef => "elifdef",
            Elifndef => "elifndef",
            Else => "else",
            Endif => "endif",
            Pragma => "pragma",
            Error => "error",
            Warning => "warning",
            Line => "line",
            Embed => "embed",
            Null => "null",
            Unknown => "unknown",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Directive {
    pub kind: DirectiveKind,
    pub span: Span,
    pub pos: Pos,
    /// For `#define`/`#undef`, the macro name. For `#include`, the header as
    /// written including its `<>` or `""`.
    pub name: Option<String>,
    /// Everything after the directive keyword, trimmed.
    pub body: String,
    /// Conditional nesting depth *inside* this directive's region.
    pub depth: u32,
    /// True for a function-like `#define`, i.e. `#define M(x)`.
    pub function_like: bool,
}

impl Directive {
    /// For `#include`, whether the header was written in angle brackets.
    pub fn is_system_include(&self) -> bool {
        self.kind == DirectiveKind::Include && self.name.as_deref().is_some_and(|n| n.starts_with('<'))
    }
    /// Header name with its quoting removed.
    pub fn include_target(&self) -> Option<&str> {
        let n = self.name.as_deref()?;
        Some(n.trim_matches(|c| c == '<' || c == '>' || c == '"'))
    }
}

/// A `#if`/`#endif` region.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConditionalBlock {
    pub open: Pos,
    /// `None` when the block is never closed.
    pub close: Option<Pos>,
    pub depth: u32,
    /// Condition text as written, for `#if`/`#elif`.
    pub condition: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlKind {
    If,
    Else,
    For,
    While,
    DoWhile,
    Switch,
}

impl ControlKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            ControlKind::If => "if",
            ControlKind::Else => "else",
            ControlKind::For => "for",
            ControlKind::While => "while",
            ControlKind::DoWhile => "do",
            ControlKind::Switch => "switch",
        }
    }
}

/// One control-flow statement and the facts MISRA asks about it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControlStatement {
    pub kind: ControlKind,
    pub pos: Pos,
    /// Span of the controlling keyword.
    pub span: Span,
    /// True when the statement's body is a compound statement `{ ... }`.
    /// MISRA C Rule 15.6 and C++ equivalents require this unconditionally.
    pub body_braced: bool,
    /// Span of the parenthesized condition, when the form has one.
    pub condition: Option<Span>,
    /// True when the condition contains a bare `=` at paren depth 1 — nearly
    /// always a typo for `==`.
    pub assignment_in_condition: bool,
    /// True when the body is empty (`;` or `{}`).
    pub empty_body: bool,
    /// Span of the braced body, when there is one. Rules about what may appear
    /// *inside* a loop (MISRA C Rule 15.4's break count) need this.
    pub body: Option<Span>,
    /// Index of the enclosing function in [`CStructure::functions`], if inside one.
    pub function: Option<usize>,
}

/// A `switch` and its clause structure.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwitchStatement {
    pub pos: Pos,
    pub span: Span,
    pub has_default: bool,
    /// Number of `case` labels.
    pub case_count: usize,
    /// Number of clauses: runs of labels with nothing between them count once,
    /// so `case 1: case 2: g(); break;` is one clause, not two.
    pub clauses: usize,
    /// `default` appears somewhere other than the final clause.
    pub default_not_last: bool,
    /// Positions of non-empty clauses that fall through to the next label
    /// without `break`/`return`/`continue`/`goto`/`throw`.
    pub fallthrough_clauses: Vec<Pos>,
    /// `case`/`default` labels nested inside a block within the switch body
    /// rather than directly in it — MISRA C Rule 16.2's target, and a classic
    /// source of jumps into the middle of a construct.
    pub misplaced_labels: Vec<Pos>,
    pub function: Option<usize>,
}

/// A function definition. Declarations (no body) are not recorded.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CFunction {
    pub name: String,
    pub pos: Pos,
    /// Span from the name through the closing brace of the body.
    pub span: Span,
    pub body: Span,
    /// Text between the declarator parentheses, as written.
    pub params: String,
    /// Positions of every `return` statement in the body.
    pub returns: Vec<Pos>,
    /// Number of exit points: `return`s, plus 1 for falling off the end of a
    /// body that does not end in `return`. MISRA C Rule 15.5 is about this.
    pub exit_points: usize,
    /// Deepest block nesting within the body.
    pub max_nesting: u32,
    /// McCabe cyclomatic complexity, counting decision points.
    pub cyclomatic: u32,
    /// Statement count, approximated by top-level `;` and `}` in the body.
    pub statements: usize,
    pub line_count: u32,
    /// True when the definition is preceded by `static`, giving it internal
    /// linkage.
    ///
    /// The distinction only matters across translation units, which is why it
    /// went unrecorded until a cross-file check needed it: two `static`
    /// functions with the same name in different files are correct C, and a
    /// whole-program identifier check that does not know the difference reports
    /// them.
    #[serde(default)]
    pub internal_linkage: bool,
}

/// A file-scope object definition — a variable at the outermost level.
///
/// Recorded because MISRA 5.1 and D4.5 are about *external identifiers*, and an
/// object with external linkage is one. Until this existed the whole-program
/// check compared function names only, which is most of the linker's namespace
/// and not all of it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CObject {
    pub name: String,
    pub pos: Pos,
    /// True when the definition is `static`, so the linker never sees the name.
    pub internal_linkage: bool,
}

/// Everything the structural pass learned about one translation unit.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CStructure {
    pub directives: Vec<Directive>,
    pub conditionals: Vec<ConditionalBlock>,
    /// Positions of `#endif` with no matching opener, and unclosed openers.
    pub unbalanced_conditionals: Vec<Pos>,
    /// Positions of `#else`, `#elif`, `#elifdef` or `#elifndef` that come after
    /// the `#else` of their own level. The preprocessor takes one `#else`, last.
    pub after_else: Vec<Pos>,
    pub max_conditional_depth: u32,
    pub functions: Vec<CFunction>,
    pub controls: Vec<ControlStatement>,
    pub switches: Vec<SwitchStatement>,
    pub gotos: Vec<(String, Pos)>,
    pub labels: Vec<(String, Pos)>,
    /// Identifiers that appear as `#define`d macro names.
    pub macros: Vec<(String, Pos)>,
    /// File-scope object definitions, in source order.
    ///
    /// Deliberately incomplete, and precision is the reason: see
    /// [`parse_objects`]. A declarator this pass cannot read with certainty is
    /// skipped rather than guessed at, because the consumer compares these names
    /// across files and a wrong name there is a finding against innocent code.
    #[serde(default)]
    pub objects: Vec<CObject>,
    /// True when the token stream had unbalanced braces, meaning the structural
    /// facts below are best-effort. Consumers should downgrade confidence.
    pub brace_imbalance: i32,
}

impl CStructure {
    pub fn function_at(&self, line: u32) -> Option<&CFunction> {
        self.functions
            .iter()
            .find(|f| f.pos.line <= line && line <= f.pos.line + f.line_count)
    }
    pub fn includes(&self) -> impl Iterator<Item = &Directive> {
        self.directives.iter().filter(|d| d.kind == DirectiveKind::Include)
    }
    /// True when structural facts should be trusted; false when braces did not
    /// balance and the pass had to guess.
    pub fn is_reliable(&self) -> bool {
        self.brace_imbalance == 0
    }
}

/// Build the structural model for an already-lexed translation unit.
pub fn analyze_c(src: &str, lexed: &Lexed) -> CStructure {
    let mut st = CStructure::default();
    parse_directives(src, lexed, &mut st);

    let code: Vec<&CToken> = lexed.code_tokens().collect();
    parse_functions(src, &code, &mut st);
    parse_controls(src, &code, &mut st);
    parse_switches(src, &code, &mut st);
    parse_jumps(src, &code, &mut st);
    parse_objects(src, &code, &mut st);
    st
}

// --- directives -----------------------------------------------------------

fn parse_directives(src: &str, lexed: &Lexed, st: &mut CStructure) {
    let mut depth: u32 = 0;
    // Stack of (open position, condition text, `#else` seen at this level) for
    // open conditionals. Each level keeps its own state, so a nested
    // conditional's `#else` says nothing about the level around it.
    let mut open: Vec<(Pos, String, bool)> = Vec::new();

    for tok in lexed.directives() {
        let text = tok.text(src);
        let after_hash = text.strip_prefix('#').unwrap_or(text).trim_start();
        let word: String =
            after_hash.chars().take_while(|c| c.is_ascii_alphabetic() || *c == '_').collect();
        let kind = DirectiveKind::parse(&word);
        let body = after_hash[word.len()..].trim().to_string();

        // Depth is recorded as the depth *inside* the directive: an `#if` at
        // top level reports depth 1, its `#endif` reports 1 as well.
        let recorded_depth = match kind {
            k if k.opens_conditional() => {
                depth += 1;
                open.push((tok.pos, body.clone(), false));
                depth
            }
            // Only one `#else` per level, and nothing may follow it at that
            // level: a second `#else`, or any `#elif`/`#elifdef`/`#elifndef`,
            // has no partner the preprocessor will accept.
            k if k.continues_conditional() => {
                if let Some(level) = open.last_mut() {
                    if level.2 {
                        st.after_else.push(tok.pos);
                    }
                    if kind == DirectiveKind::Else {
                        level.2 = true;
                    }
                }
                depth
            }
            k if k.closes_conditional() => {
                let d = depth;
                match open.pop() {
                    Some((open_pos, cond, _)) => {
                        st.conditionals.push(ConditionalBlock {
                            open: open_pos,
                            close: Some(tok.pos),
                            depth: d,
                            condition: cond,
                        });
                        depth = depth.saturating_sub(1);
                    }
                    None => st.unbalanced_conditionals.push(tok.pos),
                }
                d
            }
            _ => depth,
        };
        st.max_conditional_depth = st.max_conditional_depth.max(depth);

        let (name, function_like) = match kind {
            DirectiveKind::Define => {
                let n: String =
                    body.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
                let fl = body[n.len()..].starts_with('(');
                if !n.is_empty() {
                    st.macros.push((n.clone(), tok.pos));
                }
                (Some(n), fl)
            }
            DirectiveKind::Undef => (
                Some(body.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect()),
                false,
            ),
            DirectiveKind::Include => {
                let target = body.split_whitespace().next().unwrap_or("").to_string();
                (Some(target), false)
            }
            _ => (None, false),
        };

        st.directives.push(Directive {
            kind,
            span: tok.span,
            pos: tok.pos,
            name,
            body,
            depth: recorded_depth,
            function_like,
        });
    }

    // Anything still open at end of file is unbalanced.
    for (pos, cond, _) in open {
        st.unbalanced_conditionals.push(pos);
        st.conditionals.push(ConditionalBlock { open: pos, close: None, depth: 0, condition: cond });
    }
}

// --- functions ------------------------------------------------------------

/// Keywords that can be followed by `(` without being a function definition.
const NOT_A_FUNCTION_NAME: &[&str] = &[
    "if", "for", "while", "switch", "return", "sizeof", "catch", "throw", "alignof", "decltype",
    "noexcept", "static_assert", "_Static_assert", "_Generic", "requires", "typeof",
    "typeof_unqual", "and", "or", "not", "do", "else", "case", "default",
];

fn parse_functions(src: &str, code: &[&CToken], st: &mut CStructure) {
    let mut depth: i32 = 0;
    let mut i = 0usize;

    while i < code.len() {
        let t = code[i];
        let text = t.text(src);

        if text == "{" {
            depth += 1;
            i += 1;
            continue;
        }
        if text == "}" {
            depth -= 1;
            st.brace_imbalance = st.brace_imbalance.min(depth);
            i += 1;
            continue;
        }

        // Any nesting level may hold a definition — a C++ member function sits
        // inside its class brace. What must *not* hold one is a function body,
        // and that is guaranteed structurally: on a match the scan jumps past
        // the whole body, so nothing inside it is ever examined here.
        if matches!(t.kind, CTokenKind::Identifier)
            && !NOT_A_FUNCTION_NAME.contains(&text)
            && i + 1 < code.len()
            && code[i + 1].is(src, "(")
            && let Some(close) = matching(src, code, i + 1, "(", ")") {
                // Skip trailing specifiers: `const`, `noexcept`, `override`,
                // `-> T`, attributes, and a base-initializer list.
                let mut j = close + 1;
                let mut saw_init_list = false;
                while j < code.len() {
                    let s = code[j].text(src);
                    match s {
                        "const" | "volatile" | "noexcept" | "override" | "final" | "&" | "&&"
                        | "mutable" | "constexpr" | "consteval" | "inline" => j += 1,
                        "throw" | "requires" => {
                            j += 1;
                            if j < code.len() && code[j].is(src, "(") {
                                j = matching(src, code, j, "(", ")").map(|k| k + 1).unwrap_or(j);
                            }
                        }
                        "->" => {
                            // Trailing return type runs until `{` or `;`.
                            j += 1;
                            while j < code.len()
                                && !code[j].is(src, "{")
                                && !code[j].is(src, ";")
                            {
                                j += 1;
                            }
                        }
                        ":" if !saw_init_list => {
                            // Constructor initializer list, up to the body brace.
                            saw_init_list = true;
                            j += 1;
                            while j < code.len() && !code[j].is(src, "{") {
                                if code[j].is(src, "(") {
                                    j = matching(src, code, j, "(", ")").map(|k| k + 1).unwrap_or(j + 1);
                                } else if code[j].is(src, ";") {
                                    break;
                                } else {
                                    j += 1;
                                }
                            }
                        }
                        _ => break,
                    }
                }

                if j < code.len() && code[j].is(src, "{")
                    && let Some(body_end) = matching(src, code, j, "{", "}") {
                        let body = Span::new(code[j].span.start, code[body_end].span.end);
                        let f = build_function(
                            src,
                            code,
                            text.to_string(),
                            t,
                            i + 1,
                            close,
                            j,
                            body_end,
                            body,
                        );
                        st.functions.push(f);
                        // Resume after the body; nested definitions (lambdas)
                        // are not treated as top-level functions.
                        i = body_end + 1;
                        continue;
                    }
            }
        i += 1;
    }
    if depth != 0 {
        st.brace_imbalance = depth;
    }
}

/// Whether `static` appears in this definition's own declaration specifiers.
///
/// The scan walks back from the function name to the end of whatever came
/// before — a `;`, or the `{`/`}` of a surrounding block or previous body — so
/// it sees the specifiers of this declaration and nothing else. It deliberately
/// does not stop at `)`, because an attribute may sit ahead of the storage
/// class: `__attribute__((visibility("default"))) static void f(void)`.
fn has_internal_linkage(src: &str, code: &[&CToken], name_idx: usize) -> bool {
    let mut k = name_idx;
    while k > 0 {
        k -= 1;
        match code[k].text(src) {
            ";" | "{" | "}" => return false,
            "static" => return true,
            _ => {}
        }
    }
    false
}

#[allow(clippy::too_many_arguments)]
fn build_function(
    src: &str,
    code: &[&CToken],
    name: String,
    name_tok: &CToken,
    params_open: usize,
    params_close: usize,
    body_open: usize,
    body_close: usize,
    body: Span,
) -> CFunction {
    let params = if params_close > params_open + 1 {
        Span::new(code[params_open + 1].span.start, code[params_close - 1].span.end)
            .slice(src)
            .to_string()
    } else {
        String::new()
    };

    let mut returns = Vec::new();
    let mut nesting: u32 = 0;
    let mut max_nesting: u32 = 0;
    let mut cyclomatic: u32 = 1;
    let mut statements = 0usize;

    for t in &code[(body_open + 1)..body_close] {
        let s = t.text(src);
        match s {
            "{" => {
                nesting += 1;
                max_nesting = max_nesting.max(nesting);
            }
            "}" => nesting = nesting.saturating_sub(1),
            ";" => statements += 1,
            "return" => returns.push(t.pos),
            // Each decision point adds a linearly independent path.
            "if" | "for" | "while" | "case" | "catch" | "&&" | "||" | "?" => cyclomatic += 1,
            _ => {}
        }
    }

    // Falling off the end of a body whose last statement is not `return` is
    // itself an exit point — the case MISRA C Rule 15.5 is really about.
    let exit_points =
        returns.len() + usize::from(!body_ends_with_return(src, code, body_open, body_close));

    let start = name_tok.span.start;
    let end = code[body_close].span.end;
    let line_count = code[body_close].pos.line.saturating_sub(name_tok.pos.line);

    CFunction {
        name,
        pos: name_tok.pos,
        span: Span::new(start, end),
        body,
        params,
        returns,
        exit_points,
        max_nesting,
        cyclomatic,
        statements,
        line_count,
        internal_linkage: has_internal_linkage(src, code, params_open.saturating_sub(1)),
    }
}

/// Whether the last statement of a function body is an unconditional `return`.
///
/// A body ending in a closing brace (an `if`, a loop, a nested block) is *not*
/// counted: control can fall out of it, which is exactly the extra exit point
/// we want to charge the function for.
fn body_ends_with_return(src: &str, code: &[&CToken], body_open: usize, body_close: usize) -> bool {
    if body_close <= body_open + 1 {
        return false; // empty body
    }
    // Step back over the final statement's semicolons.
    let mut end = body_close - 1;
    while end > body_open && code[end].is(src, ";") {
        end -= 1;
    }
    if end == body_open || code[end].is(src, "}") {
        return false;
    }
    // Walk back to the first token of that statement.
    let mut start = end;
    while start > body_open + 1 {
        let prev = code[start - 1].text(src);
        if matches!(prev, ";" | "{" | "}" | ":") {
            break;
        }
        start -= 1;
    }
    code[start].is(src, "return")
}

// --- control statements ---------------------------------------------------

fn parse_controls(src: &str, code: &[&CToken], st: &mut CStructure) {
    for i in 0..code.len() {
        let text = code[i].text(src);
        let kind = match text {
            "if" => ControlKind::If,
            "for" => ControlKind::For,
            "switch" => ControlKind::Switch,
            "do" => ControlKind::DoWhile,
            "else" => ControlKind::Else,
            "while" => {
                // `while` closing a do/while is not its own statement.
                if i > 0 && code[i - 1].is(src, "}") {
                    continue;
                }
                ControlKind::While
            }
            _ => continue,
        };
        // `else if` is reported through the `if`, not twice.
        if kind == ControlKind::Else && i + 1 < code.len() && code[i + 1].is(src, "if") {
            continue;
        }

        let (condition, body_start) = if kind == ControlKind::Else || kind == ControlKind::DoWhile {
            (None, i + 1)
        } else if i + 1 < code.len() && code[i + 1].is(src, "(") {
            match matching(src, code, i + 1, "(", ")") {
                Some(close) => (
                    Some(Span::new(code[i + 1].span.start, code[close].span.end)),
                    close + 1,
                ),
                None => (None, i + 1),
            }
        } else {
            (None, i + 1)
        };

        let body_braced = body_start < code.len() && code[body_start].is(src, "{");
        let empty_body = body_start < code.len()
            && (code[body_start].is(src, ";")
                || (body_braced
                    && body_start + 1 < code.len()
                    && code[body_start + 1].is(src, "}")));

        // `for (i = 0; i < n; i++)` assigns in its *initialiser*, which is the
        // whole point of the clause. Only the controlling expression — between
        // the two semicolons — can hold an accidental `=`.
        let assignment_in_condition = if kind == ControlKind::DoWhile {
            do_while_condition(src, code, i)
                .is_some_and(|(open, close)| has_bare_assignment(src, code, open, close))
        } else {
            condition.is_some()
                && matching(src, code, i + 1, "(", ")").is_some_and(|close| {
                    let (from, to) = if kind == ControlKind::For {
                        match for_condition_clause(src, code, i + 1, close) {
                            Some(span) => span,
                            None => return false,
                        }
                    } else {
                        (i + 1, close)
                    };
                    has_bare_assignment(src, code, from, to)
                })
        };

        let body = if body_braced {
            matching(src, code, body_start, "{", "}")
                .map(|close| Span::new(code[body_start].span.start, code[close].span.end))
        } else {
            None
        };

        st.controls.push(ControlStatement {
            kind,
            pos: code[i].pos,
            span: code[i].span,
            body_braced,
            condition,
            assignment_in_condition,
            empty_body,
            body,
            function: None,
        });
    }
    assign_functions(st);
}

/// Token indices bracketing a `for` header's controlling expression, i.e. the
/// clause between the two top-level semicolons. Returns a range usable by
/// [`has_bare_assignment`], which expects the opening bracket at `from`.
fn for_condition_clause(
    src: &str,
    code: &[&CToken],
    open: usize,
    close: usize,
) -> Option<(usize, usize)> {
    let mut depth = 0i32;
    let mut semis = Vec::new();
    for (k, t) in code.iter().enumerate().take(close).skip(open) {
        match t.text(src) {
            "(" | "[" => depth += 1,
            ")" | "]" => depth -= 1,
            ";" if depth == 1 => semis.push(k),
            _ => {}
        }
    }
    match semis.as_slice() {
        [first, second, ..] => Some((*first, *second)),
        _ => None,
    }
}

/// Every assignment operator, plain and compound. Each lexes as one token, so
/// a comparison such as `==` or `<=` never matches one of these.
pub const ASSIGNMENT_OPERATORS: &[&str] =
    &["=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>="];

/// An assignment operator at the outermost level of `(open, close)`, exclusive
/// of both ends.
///
/// `==`, `!=`, `<=` and friends lex as single tokens of their own, so a token
/// from [`ASSIGNMENT_OPERATORS`] is exactly the typo being looked for. Nesting
/// matters: an assignment inside a call argument, `if (h(a = 1))`, is a
/// different construct and is not reported here.
fn has_bare_assignment(src: &str, code: &[&CToken], open: usize, close: usize) -> bool {
    let mut depth = 0i32;
    for t in &code[(open + 1)..close] {
        match t.text(src) {
            "(" | "[" => depth += 1,
            ")" | "]" => depth -= 1,
            s if depth == 0 && ASSIGNMENT_OPERATORS.contains(&s) => return true,
            _ => {}
        }
    }
    false
}

/// The parenthesised condition of a braced `do` loop, as its opening and
/// closing bracket.
///
/// `parse_controls` skips the `while` that closes a braced body, because it is
/// not a loop of its own, so the condition is found from the `do` instead.
fn do_while_condition(src: &str, code: &[&CToken], do_idx: usize) -> Option<(usize, usize)> {
    let body_open = do_idx + 1;
    if !code.get(body_open)?.is(src, "{") {
        return None;
    }
    let body_close = matching(src, code, body_open, "{", "}")?;
    if !code.get(body_close + 1)?.is(src, "while") {
        return None;
    }
    let open = body_close + 2;
    let close = matching(src, code, open, "(", ")")?;
    Some((open, close))
}

// --- switch clauses -------------------------------------------------------

/// Statement starters that end a switch clause.
const CLAUSE_TERMINATORS: &[&str] = &["break", "return", "continue", "goto", "throw"];

fn parse_switches(src: &str, code: &[&CToken], st: &mut CStructure) {
    let mut i = 0usize;
    while i < code.len() {
        if !code[i].is(src, "switch") {
            i += 1;
            continue;
        }
        let cond_open = i + 1;
        let body_open = match matching(src, code, cond_open, "(", ")") {
            Some(c) if c + 1 < code.len() && code[c + 1].is(src, "{") => c + 1,
            _ => {
                i += 1;
                continue;
            }
        };
        let body_close = match matching(src, code, body_open, "{", "}") {
            Some(c) => c,
            None => {
                i += 1;
                continue;
            }
        };

        // Collect clause label positions at the switch body's own depth.
        let mut labels: Vec<(usize, bool)> = Vec::new(); // (index of `case`/`default`, is_default)
        let mut misplaced_labels = Vec::new();
        let mut depth = 0i32;
        for k in (body_open + 1)..body_close {
            let s = code[k].text(src);
            match s {
                "{" => depth += 1,
                "}" => depth -= 1,
                "case" if depth == 0 => labels.push((k, false)),
                "default" if depth == 0 => labels.push((k, true)),
                // A label deeper than the switch body is legitimate only when
                // the innermost brace around it is the body of a switch, which
                // then owns the label. An enclosing `switch` further out does
                // not make it so: `case 3` in `switch (a) { case 1: switch (a)
                // { default: break; } { case 3: ... } }` sits in a plain block.
                "case" | "default"
                    if depth > 0 && !innermost_brace_is_switch_body(src, code, body_open + 1, k) =>
                {
                    misplaced_labels.push(code[k].pos);
                }
                _ => {}
            }
        }

        let case_count = labels.iter().filter(|(_, d)| !*d).count();
        // A clause starts at a label unless the label follows the previous one
        // with nothing between them but that label's own `:`: `case 1: case 2:`
        // is one clause with two labels. Any `;`, `{` or `}` between two labels
        // means a statement sits between them, so they are separate clauses.
        let clauses = labels
            .iter()
            .enumerate()
            .filter(|(n, (idx, _))| {
                *n == 0 || {
                    let prev = labels[*n - 1].0;
                    (prev..*idx).any(|k| matches!(code[k].text(src), ";" | "{" | "}"))
                }
            })
            .count();
        let has_default = labels.iter().any(|(_, d)| *d);
        let default_not_last = labels.iter().position(|(_, d)| *d).is_some_and(|p| p + 1 < labels.len());

        // A clause falls through when its body is non-empty and does not end in
        // an unconditional jump. Consecutive labels (`case 1: case 2:`) are an
        // explicitly permitted empty clause.
        let mut fallthrough = Vec::new();
        for (n, (idx, _)) in labels.iter().enumerate() {
            let clause_start = *idx;
            let clause_end = labels.get(n + 1).map(|(j, _)| *j).unwrap_or(body_close);
            // Everything after the label's `:`.
            let colon = (clause_start..clause_end)
                .find(|&k| code[k].is(src, ":"))
                .unwrap_or(clause_start);
            let stmts_start = (colon + 1).min(clause_end);
            let meaningful = (stmts_start..clause_end)
                .any(|k| !code[k].is(src, ";") && !code[k].is(src, "}"));
            if !meaningful {
                continue; // empty clause, permitted
            }
            if !clause_ends_in_jump(src, code, stmts_start, clause_end) {
                fallthrough.push(code[clause_start].pos);
            }
        }

        st.switches.push(SwitchStatement {
            pos: code[i].pos,
            span: code[i].span,
            has_default,
            case_count,
            clauses,
            default_not_last,
            fallthrough_clauses: fallthrough,
            misplaced_labels,
            function: None,
        });
        // Advance one token, not past the body: a switch nested in this body is
        // a switch too, and needs its own clause checks. Pushes stay in the
        // order of the `switch` token, so an outer switch precedes its inner ones.
        i += 1;
    }
    assign_switch_functions(st);
}

/// Whether the innermost `{` enclosing token `k`, searching back no further than
/// `lower`, opens the body of a `switch`.
fn innermost_brace_is_switch_body(src: &str, code: &[&CToken], lower: usize, k: usize) -> bool {
    let mut depth = 0i32;
    for m in (lower..k).rev() {
        match code[m].text(src) {
            "}" => depth += 1,
            "{" if depth == 0 => return brace_follows_switch_head(src, code, lower, m),
            "{" => depth -= 1,
            _ => {}
        }
    }
    false
}

/// Whether the `{` at `brace` directly follows the `(...)` of a `switch`.
fn brace_follows_switch_head(src: &str, code: &[&CToken], lower: usize, brace: usize) -> bool {
    if brace == 0 || !code[brace - 1].is(src, ")") {
        return false;
    }
    let mut depth = 0i32;
    for m in (lower..brace).rev() {
        match code[m].text(src) {
            ")" => depth += 1,
            "(" => {
                depth -= 1;
                if depth == 0 {
                    return m > 0 && code[m - 1].is(src, "switch");
                }
            }
            _ => {}
        }
    }
    false
}

/// Whether the statements in `from..to` end, as a whole, in an unconditional
/// jump. The last statement is what counts: a `break` inside an `if` that the
/// clause can skip past does not terminate it.
fn clause_ends_in_jump(src: &str, code: &[&CToken], from: usize, to: usize) -> bool {
    statements(src, code, from, to)
        .last()
        .is_some_and(|&(start, end)| statement_ends_in_jump(src, code, start, end))
}

/// Whether the single statement `start..end` is an unconditional jump, or a
/// block or `if`/`else` whose every path ends in one.
fn statement_ends_in_jump(src: &str, code: &[&CToken], start: usize, end: usize) -> bool {
    let first = code[start].text(src);
    if CLAUSE_TERMINATORS.contains(&first) {
        return true;
    }
    match first {
        "{" => matching(src, code, start, "{", "}")
            .is_some_and(|close| clause_ends_in_jump(src, code, start + 1, close)),
        // `if (...) S1 else S2` jumps only when both arms do. Without an
        // `else`, the false path falls through.
        "if" => {
            let open = start + 1;
            if open >= end || !code[open].is(src, "(") {
                return false;
            }
            let Some(close) = matching(src, code, open, "(", ")") else {
                return false;
            };
            let then_end = statement_end(src, code, close + 1, end);
            then_end < end
                && code[then_end].is(src, "else")
                && statement_ends_in_jump(src, code, close + 1, then_end)
                && statement_ends_in_jump(src, code, then_end + 1, end)
        }
        _ => false,
    }
}

/// The statements in `from..to` as `(start, end)` token ranges. Empty
/// statements (`;`) are skipped.
fn statements(src: &str, code: &[&CToken], from: usize, to: usize) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut k = from;
    while k < to {
        if code[k].is(src, ";") {
            k += 1;
            continue;
        }
        let end = statement_end(src, code, k, to).max(k + 1);
        out.push((k, end));
        k = end;
    }
    out
}

/// One past the last token of the statement that begins at `start`, never
/// running beyond `limit`.
///
/// Structural, not brace-counting: a `for`, `while`, `switch` or `if` runs
/// through its `(...)` head and its body, which is either a braced block or a
/// single statement (so `while (a) y++;` ends at its `;`). A `do` runs through
/// its `while (cond);` tail. A `;`-terminated simple statement ends at the `;`.
pub fn statement_end(src: &str, code: &[&CToken], start: usize, limit: usize) -> usize {
    if start >= limit {
        return limit;
    }
    match code[start].text(src) {
        "{" => matching(src, code, start, "{", "}").map_or(limit, |close| close + 1),
        "if" | "for" | "while" | "switch" => {
            let open = start + 1;
            if open >= limit || !code[open].is(src, "(") {
                return limit;
            }
            let Some(close) = matching(src, code, open, "(", ")") else {
                return limit;
            };
            let body_end = statement_end(src, code, close + 1, limit);
            if code[start].is(src, "if") && body_end < limit && code[body_end].is(src, "else") {
                statement_end(src, code, body_end + 1, limit)
            } else {
                body_end
            }
        }
        // `do S while (cond);`
        "do" => {
            let body_end = statement_end(src, code, start + 1, limit);
            let open = body_end + 1;
            if body_end < limit && code[body_end].is(src, "while") && open < limit {
                matching(src, code, open, "(", ")").map_or(limit, |close| {
                    if close + 1 < limit && code[close + 1].is(src, ";") {
                        close + 2
                    } else {
                        close + 1
                    }
                })
            } else {
                body_end
            }
        }
        _ => {
            let mut depth = 0i32;
            for (k, t) in code.iter().enumerate().take(limit).skip(start) {
                match t.text(src) {
                    "(" | "[" | "{" => depth += 1,
                    ")" | "]" | "}" => {
                        depth -= 1;
                        if depth < 0 {
                            return k;
                        }
                    }
                    ";" if depth == 0 => return k + 1,
                    _ => {}
                }
            }
            limit
        }
    }
}

// --- jumps ----------------------------------------------------------------

fn parse_jumps(src: &str, code: &[&CToken], st: &mut CStructure) {
    for i in 0..code.len() {
        if code[i].is(src, "goto") && i + 1 < code.len() {
            st.gotos.push((code[i + 1].text(src).to_string(), code[i].pos));
        }
        // A label is `identifier :` where the identifier starts a statement.
        if code[i].kind == CTokenKind::Identifier
            && i + 1 < code.len()
            && code[i + 1].is(src, ":")
            && i > 0
            && matches!(code[i - 1].text(src), ";" | "{" | "}" | ":")
            // `a ? b : c` and `case X:` are not labels.
            && !code[i + 1].is(src, "::")
        {
            st.labels.push((code[i].text(src).to_string(), code[i].pos));
        }
    }
}

// --- helpers --------------------------------------------------------------

/// Index of the token closing the bracket that `open_idx` opens.
///
/// Public because the rule engine needs the same bracket walk to scope its
/// checks, and two implementations of bracket matching would eventually disagree.
pub fn matching(src: &str, code: &[&CToken], open_idx: usize, open: &str, close: &str) -> Option<usize> {
    if !code.get(open_idx)?.is(src, open) {
        return None;
    }
    let mut depth = 0i32;
    for (k, t) in code.iter().enumerate().skip(open_idx) {
        let s = t.text(src);
        if s == open {
            depth += 1;
        } else if s == close {
            depth -= 1;
            if depth == 0 {
                return Some(k);
            }
        }
    }
    None
}

fn assign_functions(st: &mut CStructure) {
    let ranges: Vec<(usize, Span)> =
        st.functions.iter().enumerate().map(|(i, f)| (i, f.span)).collect();
    for c in &mut st.controls {
        c.function = ranges
            .iter()
            .find(|(_, s)| s.contains(c.span.start))
            .map(|(i, _)| *i);
    }
}

fn assign_switch_functions(st: &mut CStructure) {
    let ranges: Vec<(usize, Span)> =
        st.functions.iter().enumerate().map(|(i, f)| (i, f.span)).collect();
    for s in &mut st.switches {
        s.function = ranges.iter().find(|(_, sp)| sp.contains(s.span.start)).map(|(i, _)| *i);
    }
}

// --- file-scope objects ---------------------------------------------------

/// Storage-class specifiers and type qualifiers: they may appear anywhere in the
/// specifier run and say nothing about where the declarator begins.
const SPECIFIER_NOISE: &[&str] =
    &["static", "extern", "register", "auto", "inline", "const", "volatile", "restrict", "_Atomic",
      "_Thread_local", "thread_local", "constexpr"];

/// Type specifiers that are keywords rather than names.
const BUILTIN_TYPES: &[&str] = &[
    "void", "char", "short", "int", "long", "float", "double", "signed", "unsigned", "_Bool",
    "bool", "_Complex", "_Imaginary",
];

/// Specifiers that mean the run declares something other than an object.
const NOT_AN_OBJECT_DEFINITION: &[&str] = &[
    // Not a definition: no storage is allocated and the name belongs to another
    // translation unit, so counting it would attribute the same identifier twice.
    "extern",
    // Declares a type, not an object.
    "typedef",
    // C++ constructs whose declarators this pass has no business reading.
    "using",
    "namespace",
    "template",
    "class",
    "operator",
    "friend",
];

/// File-scope object definitions.
///
/// This reads C declarators rather than pattern-matching the easy ones. The
/// first attempt refused anything containing a parenthesis, which removed every
/// function declaration by one rule — and every *function-pointer object* with
/// it. `int (*handler)(void);` is an external identifier a linker sees, and MISRA
/// 5.1 and D4.5 are about external identifiers.
///
/// The rule is the language's own: the declared name is the first identifier in
/// the **declarator**, once the declaration specifiers are out of the way, and
/// the declaration is a function's rather than an object's when a `(` follows
/// that name directly.
///
/// | written | specifiers | declarator | name | object? |
/// |---|---|---|---|---|
/// | `int counter;` | `int` | `counter` | `counter` | yes |
/// | `struct S s;` | `struct S` | `s` | `s` | yes |
/// | `int (*handler)(void);` | `int` | `(*handler)(void)` | `handler` | yes |
/// | `int (*fp[3])(void);` | `int` | `(*fp[3])(void)` | `fp` | yes |
/// | `struct S { int a; } g;` | `struct S {…}` | `g` | `g` | yes |
/// | `int f(void);` | `int` | `f(void)` | `f` | **no** |
/// | `void (*signal(int))(int);` | `void` | `(*signal(int))(int)` | `signal` | **no** |
fn parse_objects(src: &str, code: &[&CToken], st: &mut CStructure) {
    let mut depth = 0i32;
    let mut start = 0usize;
    let mut i = 0usize;
    while i < code.len() {
        match code[i].text(src) {
            "{" => {
                // A brace preceded by `)` closes a function definition: the run
                // before it declared a function, not an object, and the next
                // declaration starts after the body. Any other brace — a struct,
                // union or enum body, or a braced initializer — is part of the
                // declaration being read, so the scan jumps it and carries on.
                let body = matching(src, code, i, "{", "}").unwrap_or(code.len() - 1);
                let is_function_body = i > 0 && code[i - 1].is(src, ")");
                if is_function_body {
                    start = body + 1;
                }
                i = body + 1;
                continue;
            }
            "}" => {
                depth -= 1;
                start = i + 1;
            }
            ";" if depth == 0 => {
                if i > start {
                    read_declaration(src, code, start, i, st);
                }
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
}

/// Index just past the declaration specifiers, and whether a type was named.
///
/// A run with no type specifier is not a declaration this pass understands, and
/// saying so is the difference between reading a declarator and guessing at one.
fn end_of_specifiers(src: &str, code: &[&CToken], start: usize, end: usize) -> (usize, bool) {
    let mut k = start;
    let mut typed = false;
    while k < end {
        let t = code[k].text(src);
        if SPECIFIER_NOISE.contains(&t) {
            k += 1;
        } else if BUILTIN_TYPES.contains(&t) {
            typed = true;
            k += 1;
        } else if matches!(t, "struct" | "union" | "enum") {
            k += 1;
            if k < end && code[k].kind == CTokenKind::Identifier {
                k += 1; // the tag
            }
            if k < end && code[k].is(src, "{") {
                match matching(src, code, k, "{", "}") {
                    Some(close) if close < end => k = close + 1,
                    // An unbalanced body means the token stream is damaged; a
                    // guess here becomes a finding against innocent code.
                    _ => return (end, false),
                }
            }
            typed = true;
        } else if !typed && code[k].kind == CTokenKind::Identifier {
            // A typedef name. Only the first identifier can be one: the next is
            // the thing being declared.
            typed = true;
            k += 1;
        } else {
            break;
        }
    }
    (k, typed)
}

/// One `;`-terminated declaration at file scope, `start..end` exclusive of the
/// semicolon.
fn read_declaration(src: &str, code: &[&CToken], start: usize, end: usize, st: &mut CStructure) {
    let toks = &code[start..end];
    if toks.iter().any(|t| NOT_AN_OBJECT_DEFINITION.contains(&t.text(src))) {
        return;
    }
    let (first, typed) = end_of_specifiers(src, code, start, end);
    if !typed || first >= end {
        return;
    }
    let internal_linkage = code[start..first].iter().any(|t| t.is(src, "static"));

    for (from, to) in top_level_commas(src, &code[first..end]) {
        let run = &code[first + from..first + to];
        if let Some((name, pos)) = declared_name(src, run) {
            st.objects.push(CObject { name, pos, internal_linkage });
        }
    }
}

/// Split a declarator list on the commas that separate declarators, ignoring the
/// ones inside a parameter list, an array bound or a braced initializer.
fn top_level_commas(src: &str, run: &[&CToken]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut from = 0usize;
    for (i, t) in run.iter().enumerate() {
        match t.text(src) {
            "(" | "[" | "{" => depth += 1,
            ")" | "]" | "}" => depth -= 1,
            "," if depth == 0 => {
                out.push((from, i));
                from = i + 1;
            }
            _ => {}
        }
    }
    out.push((from, run.len()));
    out
}

/// The identifier a declarator declares, when it declares an object.
///
/// `None` for a function declarator, for an abstract declarator with no name,
/// and for anything the scan cannot read.
fn declared_name(src: &str, run: &[&CToken]) -> Option<(String, Pos)> {
    // An initializer is not part of the declarator, and `int a = f(b)` would
    // otherwise offer `f` as a second identifier.
    let mut depth = 0i32;
    let mut stop = run.len();
    for (i, t) in run.iter().enumerate() {
        match t.text(src) {
            "(" | "[" | "{" => depth += 1,
            ")" | "]" | "}" => depth -= 1,
            "=" if depth == 0 => {
                stop = i;
                break;
            }
            _ => {}
        }
    }
    let declarator = &run[..stop];

    // A declarator that opens with `(` is a parenthesised declarator, and what
    // follows the paren has to be one: `(*handler)(void)`, `(*fp[3])(void)`.
    // `(TEST_1, 2)` is a parameter list, which means the run is a function
    // declarator with no return type — or, at file scope and far more often, a
    // macro invocation. PX4 has `PARAM_DEFINE_INT32(TEST_1, 2);` in its test
    // parameters, and reading it as an object declares `TEST_1`.
    if declarator.first().is_some_and(|t| t.is(src, "("))
        && !declarator.get(1).is_some_and(|t| t.is(src, "*") || t.is(src, "("))
    {
        return None;
    }

    let at = declarator.iter().position(|t| t.kind == CTokenKind::Identifier)?;
    // `f(void)` declares a function; `(*handler)(void)` declares a pointer to
    // one. The token after the name is the whole difference.
    if declarator.get(at + 1).is_some_and(|t| t.is(src, "(")) {
        return None;
    }
    // Two names in a row cannot both belong to one object declarator, so seeing
    // one means the boundary between specifiers and declarator was put in the
    // wrong place — and at file scope the usual reason is a macro invocation
    // with no semicolon after it. PX4 wraps its headers in `__BEGIN_DECLS`, so
    // `__BEGIN_DECLS size_t px4_get_secure_random(...)` reads as one run and
    // offers `size_t` as a declared object. Nothing here expands macros; refusing
    // is the only honest answer.
    if declarator
        .get(at + 1)
        .is_some_and(|t| matches!(t.kind, CTokenKind::Identifier | CTokenKind::Keyword))
    {
        return None;
    }
    Some((declarator[at].text(src).to_string(), declarator[at].pos))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clex::{Dialect, lex};

    fn c(src: &str) -> CStructure {
        analyze_c(src, &lex(src, Dialect::C23))
    }
    fn cpp(src: &str) -> CStructure {
        analyze_c(src, &lex(src, Dialect::Cpp23))
    }

    /// File-scope objects, by reading the declarator rather than matching a
    /// shape.
    ///
    /// The consumer compares these names across translation units for MISRA 5.1
    /// and D4.5, so a name read wrongly becomes a conformance finding against
    /// innocent code. Each case is either a declarator that must be read or one
    /// that must be refused; the refusals matter at least as much.
    #[test]
    fn file_scope_objects_are_read_by_following_the_declarator() {
        let names = |src: &str| -> Vec<String> {
            c(src).objects.iter().map(|o| o.name.clone()).collect::<Vec<_>>()
        };

        // The ordinary shapes.
        assert_eq!(names("int counter;\n"), ["counter"]);
        assert_eq!(names("static int hidden;\n"), ["hidden"]);
        assert_eq!(names("unsigned long total = 0;\n"), ["total"]);
        assert_eq!(names("const char *name = \"x\";\n"), ["name"]);
        assert_eq!(names("char buf[32];\n"), ["buf"]);
        assert_eq!(names("struct S s;\n"), ["s"], "the tag is not the object");
        assert_eq!(names("int a = 1, b = 2;\n"), ["a", "b"]);
        assert_eq!(names("MyType value;\n"), ["value"], "a typedef name is a type specifier");

        // Declarators the first version of this pass refused rather than read.
        // A function pointer at file scope is an external identifier like any
        // other, and 5.1 is about external identifiers.
        assert_eq!(names("int (*handler)(void);\n"), ["handler"]);
        assert_eq!(names("int (*fp[3])(void);\n"), ["fp"]);
        assert_eq!(names("char *const *p;\n"), ["p"]);
        assert_eq!(names("struct S { int a; } g;\n"), ["g"]);
        assert_eq!(names("int table[] = { 1, 2 };\n"), ["table"]);
        assert_eq!(names("int a, *b, c[2];\n"), ["a", "b", "c"]);

        // A macro invocation at file scope is not a declaration, and nothing
        // here expands macros. `(TEST_1, 2)` is a parameter list, not a
        // parenthesised declarator: the token after the `(` decides.
        assert!(names("PARAM_DEFINE_INT32(TEST_1, 2);\n").is_empty());
        assert!(names("EXPORT_SYMBOL(foo);\n").is_empty());
        // ...and a declaration following one that had no semicolon is refused
        // rather than misread, because two names in a row cannot both belong to
        // one object declarator.
        assert!(names("__BEGIN_DECLS\nsize_t px4_get_secure_random(int a);\n").is_empty());
        assert!(names("__BEGIN_DECLS\n__EXPORT int px4_clock_gettime(int a);\n").is_empty());

        // Still refused, because they declare something other than an object.
        assert!(names("extern int elsewhere;\n").is_empty(), "a declaration, not a definition");
        assert!(names("typedef int word;\n").is_empty(), "declares a type");
        assert!(names("struct S;\n").is_empty(), "a tag with no declarator");
        assert!(names("struct S { int a; };\n").is_empty(), "a type definition with no declarator");
        assert!(names("int f(void);\n").is_empty(), "a function declaration");
        assert!(
            names("void (*signal(int, void (*)(int)))(int);\n").is_empty(),
            "a function returning a function pointer is still a function"
        );

        // A function *definition* declares no object, and what follows it must
        // not be swallowed into the same declaration.
        assert_eq!(
            names("int f(void) { int local; return local; }\nint after;\n"),
            ["after"],
            "the body is skipped and the next declaration still read"
        );

        // Linkage, which is the whole reason the type exists.
        let st = c("static int hidden;\nint shared;\n");
        assert!(st.objects[0].internal_linkage);
        assert!(!st.objects[1].internal_linkage);
    }

    /// `static` is what separates a name the linker sees from one it does not.
    ///
    /// Recorded because a whole-program identifier check needs it: two `static`
    /// functions with the same name in different translation units are correct
    /// C. The scan walks back from the function name to the end of the previous
    /// declaration, so it must not be confused by what precedes that.
    #[test]
    fn internal_linkage_is_recorded_for_static_definitions() {
        let st = c("static int a(void) { return 0; }\nint b(void) { return 1; }\n");
        assert!(st.functions[0].internal_linkage, "`static int a` has internal linkage");
        assert!(!st.functions[1].internal_linkage, "`int b` does not");

        // The `static` belongs to the *previous* declaration; `b` is external.
        let st = c("static int x;\nint b(void) { return 1; }\n");
        assert!(!st.functions[0].internal_linkage, "the scan must stop at the `;`");

        // And the definition before it must not leak either.
        let st = c("static int a(void) { return 0; }\nint b(void) { return 1; }\n");
        assert!(!st.functions[1].internal_linkage, "the scan must stop at the previous closing brace");

        // An attribute may sit ahead of the storage class, which is why the
        // scan does not stop at a closing parenthesis.
        let st = c("__attribute__((unused)) static int a(void) { return 0; }\n");
        assert!(st.functions[0].internal_linkage, "`static` behind an attribute still counts");

        // `inline` and a return type in between change nothing.
        let st = c("static inline unsigned long a(void) { return 0; }\n");
        assert!(st.functions[0].internal_linkage);
    }

    #[test]
    fn parses_include_and_define_directives() {
        let st = c("#include <stdio.h>\n#include \"local.h\"\n#define MAX 10\n#define F(x) ((x)+1)\n");
        assert_eq!(st.directives.len(), 4);
        assert!(st.directives[0].is_system_include());
        assert_eq!(st.directives[0].include_target(), Some("stdio.h"));
        assert!(!st.directives[1].is_system_include());
        assert_eq!(st.directives[2].name.as_deref(), Some("MAX"));
        assert!(!st.directives[2].function_like);
        assert!(st.directives[3].function_like, "`#define F(x)` is function-like");
    }

    #[test]
    fn tracks_conditional_nesting_depth() {
        let st = c("#if A\n#if B\n#endif\n#endif\n");
        assert_eq!(st.max_conditional_depth, 2);
        assert!(st.unbalanced_conditionals.is_empty());
        assert_eq!(st.conditionals.len(), 2);
    }

    #[test]
    fn reports_unbalanced_conditionals_both_ways() {
        assert_eq!(c("#endif\n").unbalanced_conditionals.len(), 1);
        assert_eq!(c("#if A\nint x;\n").unbalanced_conditionals.len(), 1);
        assert!(c("#ifdef A\n#else\n#endif\n").unbalanced_conditionals.is_empty());
    }

    #[test]
    fn finds_function_definitions_but_not_declarations() {
        let st = c("int declared(void);\nint defined(int a) { return a; }\n");
        assert_eq!(st.functions.len(), 1);
        assert_eq!(st.functions[0].name, "defined");
        assert_eq!(st.functions[0].params, "int a");
    }

    #[test]
    fn control_keywords_are_not_mistaken_for_functions() {
        let st = c("void f(void) { if (1) { } while (0) { } switch (2) { default: break; } }\n");
        assert_eq!(st.functions.len(), 1);
        assert_eq!(st.functions[0].name, "f");
    }

    #[test]
    fn counts_exit_points_for_misra_15_5() {
        let single = c("int f(int a) { return a; }\n");
        assert_eq!(single.functions[0].exit_points, 1);

        let multi = c("int f(int a) { if (a) { return 1; } return 0; }\n");
        assert_eq!(multi.functions[0].returns.len(), 2);
        assert_eq!(multi.functions[0].exit_points, 2);

        // Falling off the end of a void function is itself an exit point.
        let implicit = c("void f(int a) { if (a) { return; } }\n");
        assert_eq!(implicit.functions[0].exit_points, 2);
    }

    #[test]
    fn computes_cyclomatic_complexity_from_decision_points() {
        let st = c("int f(int a, int b) { if (a && b) { return 1; } for (;;) { } return 0; }\n");
        // 1 base + if + && + for
        assert_eq!(st.functions[0].cyclomatic, 4);
    }

    #[test]
    fn detects_unbraced_control_bodies() {
        let st = c("void f(void) { if (a) g(); else h(); while (b) i(); }\n");
        let unbraced: Vec<&ControlStatement> =
            st.controls.iter().filter(|c| !c.body_braced).collect();
        assert_eq!(unbraced.len(), 3, "if, else and while all lack braces");
    }

    #[test]
    fn statement_end_spans_unbraced_loops_and_do_while() {
        let src = "void f(void) { while (a) y++; do { } while (c); }\n";
        let lexed = lex(src, Dialect::C23);
        let code: Vec<&CToken> = lexed.code_tokens().collect();
        let at = |t: &str| code.iter().position(|k| k.text(src) == t).unwrap();
        // The unbraced `while` ends after its `;`, which is where `do` begins.
        assert_eq!(statement_end(src, &code, at("while"), code.len()), at("do"));
        // The `do` runs through `while (c);`, which is where the function's `}` is.
        assert_eq!(statement_end(src, &code, at("do"), code.len()), code.len() - 1);
    }

    #[test]
    fn else_if_is_reported_once_as_an_if() {
        let st = c("void f(void) { if (a) { } else if (b) { } }\n");
        let kinds: Vec<ControlKind> = st.controls.iter().map(|c| c.kind).collect();
        assert_eq!(kinds, [ControlKind::If, ControlKind::If]);
    }

    #[test]
    fn do_while_closer_is_not_a_second_loop() {
        let st = c("void f(void) { do { g(); } while (x); }\n");
        let kinds: Vec<ControlKind> = st.controls.iter().map(|c| c.kind).collect();
        assert_eq!(kinds, [ControlKind::DoWhile]);
    }

    #[test]
    fn flags_assignment_used_as_a_condition() {
        let st = c("void f(void) { if (x = g()) { } if (x == g()) { } if (h(a = 1)) { } }\n");
        assert!(st.controls[0].assignment_in_condition);
        assert!(!st.controls[1].assignment_in_condition, "`==` is a comparison");
        assert!(
            !st.controls[2].assignment_in_condition,
            "an assignment nested in a call argument is a different construct"
        );
    }

    #[test]
    fn a_for_loops_initialiser_is_not_an_assignment_in_its_condition() {
        // The whole point of the first clause is to assign; only the middle
        // clause can hold an accidental `=`.
        let st = c("void f(void) { for (i = 0; i < n; i++) { g(); } }\n");
        assert!(!st.controls[0].assignment_in_condition);

        let bad = c("void f(void) { for (i = 0; n = next(); i++) { g(); } }\n");
        assert!(bad.controls[0].assignment_in_condition, "an `=` in the controlling clause counts");

        let no_clauses = c("void f(void) { for (;;) { g(); } }\n");
        assert!(!no_clauses.controls[0].assignment_in_condition);
    }

    #[test]
    fn a_compound_assignment_in_a_condition_is_an_assignment() {
        let st = c("void f(int n) { if ((n -= 1) > 0) { } if (n == 2) { } if (n >>= 1) { } }\n");
        assert!(!st.controls[0].assignment_in_condition, "nested in a comparison's parentheses");
        assert!(!st.controls[1].assignment_in_condition, "`==` is a comparison");
        assert!(st.controls[2].assignment_in_condition, "`>>=` at the top level of the condition");
    }

    #[test]
    fn a_do_while_condition_is_read_for_assignment() {
        let bad = c("int next(void); void f(void) { int n = 0; do { n = 1; } while (n = next()); }\n");
        let do_loop = bad.controls.iter().find(|c| c.kind == ControlKind::DoWhile).expect("the do");
        assert!(do_loop.assignment_in_condition, "`=` in the condition of a do-while");

        let good = c("int next(void); void f(void) { int n = 0; do { n = 1; } while (n == next()); }\n");
        let do_loop = good.controls.iter().find(|c| c.kind == ControlKind::DoWhile).expect("the do");
        assert!(!do_loop.assignment_in_condition, "`==` is a comparison");
    }

    #[test]
    fn switch_clause_analysis_matches_misra_16_expectations() {
        let st = c(
            "void f(int x) { switch (x) { case 1: g(); case 2: h(); break; case 3: case 4: i(); break; default: j(); break; } }\n",
        );
        let sw = &st.switches[0];
        assert_eq!(sw.case_count, 4);
        assert!(sw.has_default);
        assert!(!sw.default_not_last);
        assert_eq!(sw.fallthrough_clauses.len(), 1, "only `case 1:` falls through");
        assert_eq!(sw.fallthrough_clauses[0].line, 1);
    }

    #[test]
    fn switch_without_default_is_visible() {
        let st = c("void f(int x) { switch (x) { case 1: break; } }\n");
        assert!(!st.switches[0].has_default);
    }

    #[test]
    fn nested_switch_braces_do_not_confuse_clause_depth() {
        let st = c("void f(int x) { switch (x) { case 1: { int y = 0; break; } default: break; } }\n");
        assert_eq!(st.switches[0].case_count, 1);
        assert!(st.switches[0].fallthrough_clauses.is_empty());
    }

    #[test]
    fn a_switch_nested_in_a_switch_body_is_analysed_too() {
        let st = c("void g(int); void f(int a, int b){ switch(a){ case 1: switch(b){ case 2: g(2); case 3: g(3); break; default: break; } break; default: break; } }\n");
        assert_eq!(st.switches.len(), 2);
        // Pushed in source order: the outer switch first.
        assert!(st.switches[0].pos.column < st.switches[1].pos.column);
        assert!(st.switches[0].fallthrough_clauses.is_empty(), "outer clauses all jump");
        assert_eq!(st.switches[1].fallthrough_clauses.len(), 1, "only the inner `case 2:` falls through");
        assert!(st.switches[1].misplaced_labels.is_empty());
        assert!(st.switches[0].misplaced_labels.is_empty());
    }

    #[test]
    fn a_clause_is_terminated_by_its_last_statement_not_by_any_break() {
        // The `break` sits inside an `if` the clause can skip past.
        let skippable = c("void f(int x, int c) { switch (x) { case 1: if (c) { break; } g(1); case 2: break; } }\n");
        assert_eq!(skippable.switches[0].fallthrough_clauses.len(), 1, "`case 1:` falls through");

        // Both arms of the `if` jump, and a braced block ending in a jump does too.
        let both_arms = c("void f(int x, int c) { switch (x) { case 1: if (c) { g(); break; } else { break; } case 2: { g(); return; } default: break; } }\n");
        assert!(both_arms.switches[0].fallthrough_clauses.is_empty());
    }

    #[test]
    fn a_case_label_belongs_to_the_innermost_switch_body_around_it() {
        // `case 3` is in a plain block inside the outer switch, not in a switch body.
        let misplaced = c("void g(void); void f(int a) { switch (a) { case 1: switch (a) { default: break; } { case 3: g(); break; } default: break; } }\n");
        assert_eq!(misplaced.switches[0].misplaced_labels.len(), 1);

        // Its own switch's body is where a label belongs, however deep that switch is.
        let owned = c("void g(void); void f(int a) { switch (a) { case 1: switch (a) { case 2: g(); break; default: break; } break; default: break; } }\n");
        assert!(owned.switches[0].misplaced_labels.is_empty());
    }

    #[test]
    fn records_gotos_and_labels() {
        let st = c("void f(void) { goto done; done: return; }\n");
        assert_eq!(st.gotos[0].0, "done");
        assert_eq!(st.labels[0].0, "done");
    }

    #[test]
    fn ternary_colon_is_not_a_label() {
        let st = c("void f(void) { int a = b ? c : d; }\n");
        assert!(st.labels.is_empty());
    }

    #[test]
    fn cpp_member_functions_with_trailing_specifiers_are_found() {
        let st = cpp("struct S { int get() const noexcept { return x_; } int x_; };\n");
        assert_eq!(st.functions.len(), 1);
        assert_eq!(st.functions[0].name, "get");
    }

    #[test]
    fn cpp_constructor_init_lists_are_skipped() {
        let st = cpp("struct S { S(int a) : x_(a), y_(0) { init(); } int x_, y_; };\n");
        assert_eq!(st.functions.len(), 1);
        assert_eq!(st.functions[0].name, "S");
    }

    #[test]
    fn cpp_trailing_return_types_are_skipped() {
        let st = cpp("auto add(int a, int b) -> int { return a + b; }\n");
        assert_eq!(st.functions.len(), 1);
        assert_eq!(st.functions[0].name, "add");
    }

    #[test]
    fn brace_imbalance_is_reported_so_callers_can_lower_confidence() {
        assert!(c("void f(void) { if (a) { }\n").brace_imbalance != 0);
        assert!(c("void f(void) { }\n").is_reliable());
    }

    #[test]
    fn structure_survives_code_that_does_not_compile() {
        // Unknown types, missing includes, undeclared identifiers: still analyzable.
        let st = c("undeclared_t f(mystery m) { if (m) { return frob(m); } return 0; }\n");
        assert_eq!(st.functions.len(), 1);
        assert_eq!(st.functions[0].exit_points, 2);
    }
}
