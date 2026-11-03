/* A program written to produce three correlation verdicts in one run.
 *
 * It exists to exercise the path where every piece of runtime evidence comes
 * from an external tool: Memcheck supplies the defect, gcov supplies the
 * execution counts, and nothing here is instrumented with the SDA probe shim.
 *
 *   line 21  allocation in dead code, gcov measures it at zero  -> unreached
 *   line 30  leaked allocation, Memcheck reports the loss       -> confirmed
 *   line 37  library call in a hot loop, executed 40 times      -> refuted
 *
 * See tools/coverage-wsl/README.md for the commands that drive it.
 */
#include <stdio.h>
#include <stdlib.h>

/* Never called. gcov records these lines as executable and unexecuted, which is
 * what makes `unreached` a claim about this code rather than about the
 * instrument. */
static void never(void)
{
    char *q = malloc(8);
    (void)q;
}

int main(void)
{
    int s = 0;
    int i;

    char *p = malloc(16);
    if (p == NULL) {
        return 1;
    }

    for (i = 0; i < 40; i++) {
        s += i * 2;
        printf(".");
    }
    if (s < 0) {
        never();
    }
    printf("\n%d\n", s);
    /* p is never freed: this is the defect Memcheck witnesses. */
    return 0;
}
