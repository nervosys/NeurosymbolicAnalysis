/* Assembly: D4.3.
 *
 * Each directive has a violating form and a conforming form in this file. */

/* D4.3, violating: an assembly instruction written in the middle of ordinary
 * arithmetic, so the assembly is not isolated from the code around it. */
int timed_violating(int x)
{
    int r = x * 2;
    __asm__ volatile ("nop");
    return r;
}

/* D4.3, conforming: the assembly sits alone in a function that does nothing
 * else, so the assembly is encapsulated and its callers never see it. */
static void settle_conforming(void)
{
    __asm__ volatile ("nop");
}
