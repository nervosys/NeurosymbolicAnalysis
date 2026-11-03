//! Where the `return`s are, according to a compiler.
//!
//! MISRA C Rule 15.5 is about the number of points at which a function can exit,
//! and `CFunction::exit_points` counts them from `CFunction::returns`, which is
//! found by walking tokens. It is among the most frequently fired rules on real
//! code — 15.5 appears in this repository's own `tools/` scan and throughout
//! llama.cpp — and the count had never been checked against anything that parses
//! C.
//!
//! `clang -Xclang -ast-dump=json` is that check: a `ReturnStmt` inside a
//! `FunctionDecl` is a return, established by a compiler rather than by brace
//! counting. Captured by `tools/clang-returns-oracle.py`.
//!
//! # What is compared, and what is not
//!
//! The **returns**, because those are a fact clang states. `exit_points` adds one
//! for a body that can fall off the end, which is this toolkit's own reading of
//! the guideline rather than something clang reports; comparing it would be
//! comparing a judgement against a reimplementation of the same judgement.

use sda_syntax::{Dialect, analyze_c, lex};

const FIXTURE: &str = include_str!("fixtures/c-returns.json");

#[derive(serde::Deserialize)]
struct Fixture {
    clang: String,
    cases: Vec<Case>,
}

#[derive(serde::Deserialize)]
struct Case {
    name: String,
    text: String,
    /// Function name to the line of every `return` in it.
    functions: std::collections::BTreeMap<String, Vec<u32>>,
}

fn fixture() -> Fixture {
    serde_json::from_str(FIXTURE).expect("the captured clang answers")
}

#[test]
fn the_oracle_covers_the_ways_a_return_can_hide() {
    let f = fixture();
    assert!(f.clang.contains("clang version"), "captured from: {}", f.clang);
    assert!(
        f.cases.iter().any(|c| c.text.contains("/* return 99; */")),
        "a `return` inside a comment, which is not one"
    );
    assert!(
        f.cases.iter().any(|c| c.text.contains("\"return 5;\"")),
        "and one inside a string literal, which is not one either"
    );
    assert!(
        f.cases.iter().any(|c| c.functions.len() > 1),
        "and a file with more than one function, so returns must be attributed"
    );
}

#[test]
fn every_function_has_the_returns_clang_found() {
    for c in fixture().cases {
        let lexed = lex(&c.text, Dialect::C23);
        let st = analyze_c(&c.text, &lexed);

        let mut ours: std::collections::BTreeMap<String, Vec<u32>> = Default::default();
        for f in &st.functions {
            ours.insert(f.name.clone(), f.returns.iter().map(|p| p.line).collect());
        }

        assert_eq!(
            ours.keys().collect::<Vec<_>>(),
            c.functions.keys().collect::<Vec<_>>(),
            "case `{}`: the functions found",
            c.name
        );
        for (name, theirs) in &c.functions {
            let mine = ours.get(name).expect("checked above");
            assert_eq!(
                mine, theirs,
                "case `{}`: `{}` — clang puts its return(s) at {:?}",
                c.name, name, theirs
            );
        }
    }
}
