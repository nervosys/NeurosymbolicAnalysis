/* Switches: 16.1, 16.2, 16.3, 16.4, 16.5, 16.6. */

extern void act(int x);
extern int h(void);

/* 16.3: a clause without a break falls through.
 * 16.4: no default label. */
int route(int v)
{
    int out = 0;
    switch (v) {
        case 1:
            out = 1;
        case 2:
            out = 2;
            break;
    }
    return out;
}

/* 16.5: a default label that is neither first nor last.
 * 16.6: fewer than two clauses is covered by `only_one` below. */
int middle(int v)
{
    int out = 0;
    switch (v) {
        case 1:
            out = 1;
            break;
        default:
            out = -1;
            break;
        case 2:
            out = 2;
            break;
    }
    return out;
}

/* 16.6: a switch with a single clause. */
int only_one(int v)
{
    int out = 0;
    switch (v) {
        default:
            out = 9;
            break;
    }
    return out;
}

/* 16.2: a switch label inside a compound statement that is not the switch
 * body — a device known as Duff's, and prohibited. */
int nested_label(int v)
{
    int out = 0;
    switch (v) {
        case 1:
            if (h() != 0) {
                case 2:
                    out = 2;
            }
            break;
        default:
            out = 0;
            break;
    }
    return out;
}

/* 16.1: a switch statement that is not well-formed — a statement between the
 * switch's opening brace and its first label can never be reached. */
int unreachable_prologue(int v)
{
    int out = 0;
    switch (v) {
            out = -1;
        case 1:
            out = 1;
            break;
        default:
            out = 0;
            break;
    }
    return out;
}
