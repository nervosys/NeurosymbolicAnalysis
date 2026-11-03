/* The standard library: 17.1, 17.2, 21.3 through 21.12, 21.21.
 *
 * Each header is included so that the functions below are declared; the
 * inclusion is itself what several of these guidelines are about. */
#include <stdarg.h>
#include <stdlib.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <fenv.h>

/* 17.1: the features of <stdarg.h>. */
int total(int count, ...)
{
    va_list ap;
    int sum = 0;
    int i;
    va_start(ap, count);
    for (i = 0; i < count; i++) {
        sum += va_arg(ap, int);
    }
    va_end(ap);
    return sum;
}

/* 17.2: direct recursion. */
int factorial(int n)
{
    if (n <= 1) {
        return 1;
    }
    return n * factorial(n - 1);
}

/* 21.3: allocation and deallocation. */
int *make(unsigned long n)
{
    return (int *)malloc(n * sizeof(int));
}

void unmake(int *p)
{
    free(p);
}

/* 21.4 and 21.5: <setjmp.h> and <signal.h>. */
static jmp_buf env;

void bail(void)
{
    longjmp(env, 1);
}

void on_signal(int sig)
{
    (void)sig;
}

void arm(void)
{
    (void)signal(2, on_signal);
}

/* 21.6: standard I/O. */
void announce(const char *what)
{
    (void)printf("%s\n", what);
}

/* 21.7: atoi and friends. */
int as_number(const char *s)
{
    return atoi(s);
}

/* 21.8: termination. */
void stop(void)
{
    exit(1);
}

/* 21.9: bsearch and qsort. */
static int compare(const void *a, const void *b)
{
    return *(const int *)a - *(const int *)b;
}

void order(int *values, unsigned long n)
{
    qsort(values, n, sizeof(int), compare);
}

/* 21.10: time and date. */
long now(void)
{
    return (long)time(NULL);
}

/* 21.12: <fenv.h>. */
int cleared(void)
{
    return feclearexcept(FE_ALL_EXCEPT);
}

/* 21.21: system. */
int run(const char *cmd)
{
    return system(cmd);
}
