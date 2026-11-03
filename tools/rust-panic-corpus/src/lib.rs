//! Panic sites, written for two tools to disagree about.
//!
//! `RUST-2024-PANIC.1` covers `unwrap` and `expect`; `PANIC.2` covers the
//! diverging macros. Clippy has a restriction lint for each. Neither tool has
//! ever been compared with the other, and this is the corpus that lets them be.

/// PANIC.1: both spellings, in ordinary shipped code.
pub fn takes_the_value(v: Option<u8>) -> u8 {
    let a = v.unwrap();
    let b = v.expect("the caller promised");
    a + b
}

/// PANIC.2: the diverging macros.
pub fn refuses(n: u8) -> u8 {
    if n == 0 {
        panic!("zero");
    }
    if n == 1 {
        unreachable!();
    }
    if n == 2 {
        todo!();
    }
    if n == 3 {
        unimplemented!();
    }
    n
}

/// PANIC.2 again, on the assert family — which clippy has no restriction lint
/// for, so this is the one place the two tools differ about shipped code.
pub fn checks_an_invariant(n: u8) -> u8 {
    assert!(n > 0);
    assert_eq!(n % 2, 1);
    n
}

/// Neither: a panic spelled inside a string is not a panic.
pub fn innocent() -> &'static str {
    "v.unwrap() and panic!()"
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In test code a panic is the intended way to fail, and both tools should
    /// say so — this engine through `in_test`, clippy through the lint being
    /// allowed in `#[cfg(test)]`... which it is not, by default. That is the
    /// interesting disagreement rather than a defect in either.
    #[test]
    fn a_panic_here_is_the_test_working() {
        let v: Option<u8> = Some(1);
        assert_eq!(v.unwrap(), 1);
    }
}
