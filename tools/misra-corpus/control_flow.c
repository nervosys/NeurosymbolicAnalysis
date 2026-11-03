/* Control flow: 14.2, 15.1, 15.2, 15.4, 15.5, 15.6, 15.7.
 *
 * Written from the guideline titles. Every construct here is deliberate. */

extern int g(int x);
extern int h(void);

/* 15.6: the body of a selection statement must be a compound statement.
 * 15.7: an if/else-if chain must end in an else. */
int classify(int v)
{
    if (v < 0)
        return -1;
    else if (v == 0)
        return 0;

    return 1; /* 15.5: more than one point of exit */
}

/* 14.2: a for loop must be well-formed — the increment clause here has a
 * side effect on something other than the loop counter. */
int sum_to(int n)
{
    int total = 0;
    int i;
    int other = 0;
    for (i = 0; i < n; i++, other++) {
        total += g(i);
    }
    return total + other;
}

/* 15.1 and 15.2: goto at all, and a goto that jumps backwards. */
int retry(void)
{
    int attempts = 0;
again:
    attempts++;
    if (attempts < 3) {
        goto again;
    }
    return attempts;
}

/* 15.4: more than one break terminating the same loop. */
int scan(int n)
{
    int i;
    for (i = 0; i < n; i++) {
        if (g(i) == 1) {
            break;
        }
        if (g(i) == 2) {
            break;
        }
    }
    return i;
}

/* 15.6 again, on an iteration statement. */
int spin(int n)
{
    int i = 0;
    while (i < n)
        i++;
    return i;
}

/* 2.6: a label nothing jumps to. The `goto` above uses `again`; this one is
 * reachable only by falling into it, which makes the label a comment that looks
 * like control flow. clang says the same thing as `-Wunused-label`. */
int abandoned(int n)
{
    if (n > 0) {
        return n;
    }
cleanup:
    return 0;
}
