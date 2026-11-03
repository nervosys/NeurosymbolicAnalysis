/* 11.10: the `_Atomic` qualifier applied to the incomplete type `void`.
 *
 * On its own because it is not merely a guideline violation — it is a constraint
 * violation, and clang rejects the translation unit outright:
 *
 *     error: _Atomic cannot be applied to incomplete type 'void'
 *
 * That makes clang a second implementation for this guideline, which is why the
 * file exists; see `crates/sda-engine/tests/misra_agrees_with_clang_warnings.rs`.
 * It also means the file cannot sit in the cppcheck corpus: a file that does not
 * parse produces no MISRA findings at all, and an empty comparison is
 * indistinguishable from agreement.
 *
 * Checking it here is still worth something. This toolkit's premise is that it
 * runs on code that does not build, and code that does not build is exactly
 * where a compiler's opinion is unavailable. */
_Atomic(void) x;
