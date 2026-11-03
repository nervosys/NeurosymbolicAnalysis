/* Literals: 4.2, 7.6.
 *
 * Each guideline has a violating form and a conforming form in this file. */
#include <stdint.h>

/* 4.2: a three-character trigraph sequence inside a string literal. Trigraphs
 * are replaced before tokenisation in the older language editions, so this
 * string holds a different character than it appears to. */
const char *marker_violating = "??=";

/* 4.2, conforming: the character written directly. */
const char *marker_conforming = "#";

/* 7.6: the small-width variants of the minimum-width constant macros. */
int8_t narrow_violating = INT8_C(5);
uint16_t wide_violating = UINT16_C(7);

/* 7.6, conforming: the variants whose width is at least that of `int`. */
int32_t fits_conforming = INT32_C(5);
uint64_t fits_wide_conforming = UINT64_C(7);
