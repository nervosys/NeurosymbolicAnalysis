/* Random number generation: 21.24.
 *
 * Each guideline has a violating form and a conforming form in this file. */
#include <stdlib.h>

/* 21.24: the standard library's seeding and drawing functions. */
int roll_violating(void)
{
    srand(1u);
    return rand() % 6;
}

/* 21.24, conforming: a generator written in the file, which calls no
 * function from the standard library. */
unsigned int next_conforming(unsigned int state)
{
    return (state * 1103515245u) + 12345u;
}
