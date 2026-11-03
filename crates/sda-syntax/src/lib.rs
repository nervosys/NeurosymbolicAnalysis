//! Native front-ends for the languages the toolkit checks.
//!
//! Deliberately zero-dependency and compiler-free. Two consequences follow, and
//! both are intentional:
//!
//! * **Analysis runs on unbuildable code.** A half-migrated driver, a header with
//!   an unresolvable include, a snippet pasted into the GUI — all still lex, so
//!   the lexical and structural rules still fire.
//! * **Claims are bounded.** Nothing here pretends to know types or resolve
//!   overloads. Rules that genuinely need semantics are marked as such in
//!   `sda-rules` and routed to a real compiler via `sda-build`.

#![forbid(unsafe_code)]

pub mod clex;
pub mod cstruct;
pub mod rlex;
pub mod rstruct;
pub mod span;

pub use clex::{CToken, CTokenKind, Dialect, LexNote, LexNoteKind, Lexed, lex};
pub use cstruct::{CFunction, CObject, CStructure, ConditionalBlock, Directive, DirectiveKind, analyze_c};
pub use rlex::{RToken, RTokenKind, RustLexed, lex_rust};
pub use rstruct::{RustItem, RustItemKind, RustStructure, analyze_rust};
pub use span::{LineIndex, Pos, Span, token_end_column};
