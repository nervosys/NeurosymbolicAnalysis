/* Noreturn: 17.10.
 *
 * Each guideline has a violating form and a conforming form in this file. */

/* 17.10: a function marked as never returning that is declared to return a
 * value. The marking says there is no return to deliver the value through. */
_Noreturn int loops_violating(void)
{
    for (;;) {
    }
}

/* 17.10, conforming: the same function with a void return type. */
_Noreturn void loops_conforming(void)
{
    for (;;) {
    }
}
