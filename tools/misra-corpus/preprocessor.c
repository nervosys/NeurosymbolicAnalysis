/* The preprocessor: 2.5, 5.4, 5.5, 20.1, 20.4, 20.5, 20.7, 20.10, 20.11, 21.1. */

/* 20.4: a macro named after a keyword. */
#define while for

/* 21.1: #define on a reserved identifier. */
#define __LINE_COUNT__ 4

/* 5.4: two macro names that are not distinct within the significant length. */
#define AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1 1
#define AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA2 2

/* 2.5: defined and never used. */
#define NEVER_REFERENCED 99

/* 20.7: a macro parameter used without parentheses. */
#define SCALE(x) x * 2

/* 20.10 and 20.11: the # and ## operators, and # immediately before ##. */
#define NAME_OF(x) #x
#define JOIN(a, b) a##b
#define BOTH(a, b) #a##b

/* 20.5: #undef. */
#undef NEVER_REFERENCED

/* 20.1: an #include preceded by something other than a directive or comment. */
int already_declared = 0;
#include <stddef.h>

/* 5.5: an identifier not distinct from a macro name within the significant
 * length. The macro is exactly 31 characters. */
#define VALUE_THAT_IS_QUITE_LONG_INDEED 1
int VALUE_THAT_IS_QUITE_LONG_INDEEDX = 2;

int scaled(int v)
{
    return SCALE(v + 1);
}

const char *named(void)
{
    return NAME_OF(scaled);
}
