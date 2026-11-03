/* Identifier distinctness: 5.1, 5.4, 5.5, and 21.2.
 *
 * The significant lengths are not the same number. C23 5.2.4.1 guarantees 31
 * characters in an external identifier and 63 in an internal identifier or a
 * macro name, so a pair has to be built to the right length for each rule or
 * the construct is not a violation at all. */

/* 5.4: two macro names agreeing for all 63 significant characters. */
#define AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1 1
#define AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA2 2

/* 5.5: an identifier not distinct from a macro name, same length. */
#define VALUE_THAT_IS_QUITE_LONG_INDEED_AND_THEN_SOME_MORE_TO_REACH_SIX 3
int VALUE_THAT_IS_QUITE_LONG_INDEED_AND_THEN_SOME_MORE_TO_REACH_SIXX = 4;

/* 5.1: two external identifiers agreeing for all 31 significant characters.
 * Thirty-one is the linker's limit, not the compiler's. */
int eeeeeeeeeeeeeeeeeeeeeeeeeeeeeee1(void) { return 0; }
int eeeeeeeeeeeeeeeeeeeeeeeeeeeeeee2(void) { return 1; }

/* 5.1 again, over objects rather than functions. External linkage belongs to
 * both, and the linker cannot tell these two apart either. */
int ooooooooooooooooooooooooooooooo1 = 0;
int ooooooooooooooooooooooooooooooo2 = 1;

/* 21.2: declaring names the implementation has reserved — a leading underscore
 * followed by a capital, and a double underscore anywhere. */
int _Claimed(void) { return 0; }
int also__claimed(void) { return 1; }
int _Claimed_object = 0;

int uses_macros(void)
{
    return AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1 + AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA2 + VALUE_THAT_IS_QUITE_LONG_INDEED_AND_THEN_SOME_MORE_TO_REACH_SIX + VALUE_THAT_IS_QUITE_LONG_INDEED_AND_THEN_SOME_MORE_TO_REACH_SIXX;
}
