// MISRA C++:2023 5.7.1 and 5.7.2, which the compiler diagnoses.
//
// The same two constructs as `tools/misra-corpus/lexical.c`, in C++, where the
// catalogue numbers them differently: 3.1 and 3.2 become 5.7.1 and 5.7.2. The
// clang messages are identical, which is why the oracle has to know which
// language it is reading before it can name the guideline.

/* 5.7.1: a comment sequence inside a comment. /* like this */
int after_nested = 1;

// 5.7.2: this line comment is spliced into the next one \
int swallowed = 2;
int kept = 3;
