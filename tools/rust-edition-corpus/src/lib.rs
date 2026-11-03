//! Constructs edition 2024 changed, written for rustc to complain about.
//!
//! Each one is a `RUST-2024` guideline this toolkit checks natively and nothing
//! had ever disagreed with. At edition 2021 the compiler still has an opinion,
//! which is what makes it usable as a second implementation; at 2024 most of
//! these are hard errors and a refusal to compile is not a diagnostic.

/// UNSAFE.4 / `static_mut_refs`.
pub static mut COUNTER: u32 = 0;

/// Taking a *reference* to `static mut` is what the lint is about — a bare
/// read-modify-write does not trip it.
pub fn peek() -> u32 {
    unsafe {
        let r: &u32 = &COUNTER;
        *r
    }
}

// ED2024.3 / `missing_unsafe_on_extern`: a bare `extern` block, which edition
// 2024 requires to be written `unsafe extern`.
extern "C" {
    pub fn abs(n: i32) -> i32;
}

/// ED2024.4 / `unsafe_attr_outside_unsafe`: an unsafe attribute in its safe
/// form. Edition 2024 wants `#[unsafe(no_mangle)]`.
#[no_mangle]
pub extern "C" fn exported() -> i32 {
    0
}

/// ED2024.1 / `keyword_idents_2024`: `gen` becomes a keyword in edition 2024.
pub fn gen() -> u8 {
    0
}

/// UNSAFE.1 / `clippy::undocumented_unsafe_blocks`: an unsafe block with no
/// SAFETY comment above it.
///
/// Declared `unsafe fn` so that clippy's deny-by-default
/// `not_unsafe_ptr_arg_deref` does not turn the file into a hard error — the
/// point here is the missing comment, not the signature.
pub unsafe fn reads_raw(p: *const u8) -> u8 {
    unsafe { *p }
}
