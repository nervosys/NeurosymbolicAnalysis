/* 21.2 and 21.11: reserved identifiers, and <tgmath.h>. */
#include <tgmath.h>

/* 21.2: declaring a reserved identifier. Names beginning with an underscore
 * followed by a capital, and names containing a double underscore, belong to
 * the implementation. */
int _Reserved = 0;
int also__reserved = 1;

double scaled_root(double v)
{
    return sqrt(v) * 2.0;
}
