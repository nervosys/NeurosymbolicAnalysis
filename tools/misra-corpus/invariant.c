/* Invariant controlling expressions: 14.3.
 *
 * Each guideline has a violating form and a conforming form in this file. */

/* 14.3: a controlling expression whose value is fixed at translation time, so
 * the test always takes the same branch. */
int constant_test_violating(void)
{
    int r = 0;
    if (3 < 5) {
        r = 1;
    }
    return r;
}

/* 14.3, conforming: the same test against a value the function was given, so
 * the controlling expression varies with the caller. */
int constant_test_conforming(int limit)
{
    int r = 0;
    if (limit < 5) {
        r = 1;
    }
    return r;
}
