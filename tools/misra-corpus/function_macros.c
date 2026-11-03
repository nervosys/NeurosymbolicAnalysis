/* Function-like macros: D4.9.
 *
 * Each directive has a violating form and a conforming form in this file. */
#include <stdlib.h>

/* D4.9, violating: a function-like macro whose work a function could do just
 * as well. It takes a value and expands to a statement, so the same release
 * can be written as a function taking the pointer. */
#define FREE_IF(p) if (p) { free(p); }

void release_violating(void *buf)
{
    FREE_IF(buf);
}

/* D4.9, conforming: this macro takes a type, and a function cannot receive a
 * type as an argument, so no function can stand in for it. */
#define ZERO_OF(T) ((T){0})

struct point {
    int x;
    int y;
};

struct point origin_conforming(void)
{
    return ZERO_OF(struct point);
}

/* D4.9, conforming: the same kind of work written as a function. */
static int twice_conforming(int x)
{
    return x * 2;
}

int use_twice_conforming(int x)
{
    return twice_conforming(x);
}
