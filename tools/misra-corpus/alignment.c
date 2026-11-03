/* Alignment: 8.16, 8.17.
 *
 * Each guideline has a violating form and a conforming form in this file. */

/* 8.16: an alignment specification of zero on an object declaration. */
_Alignas(0) int zero_violating;

/* 8.16, conforming: a nonzero alignment. */
_Alignas(4) int four_conforming;

/* 8.17: two explicit alignment specifiers on one declaration. */
_Alignas(4) _Alignas(8) int doubled_violating;

/* 8.17, conforming: two declarations in a row, each carrying one specifier.
 * The second declaration is not part of the first. */
_Alignas(4) int first_conforming;
_Alignas(8) int second_conforming;

/* 8.17: a declaration that follows a structure body and carries two
 * alignment specifiers. The structure body is not the thing being counted. */
struct tagged_violating {
    int member;
} _Alignas(4) _Alignas(8) tagged_violating_object;

/* 8.17, conforming: alignment on the members of the structure body, and one
 * specifier on the object declared after the closing brace. */
struct tagged_conforming {
    _Alignas(4) int member;
    _Alignas(8) int other_member;
} _Alignas(16) tagged_conforming_object;
