/* Expressions: 11.9, 12.1, 12.3, 13.3, 13.4, 13.6. */

extern int g(int x);
extern int *lookup(void);

/* 11.9: NULL is the only permitted integer null pointer constant. */
int *head = 0;

/* 12.1: mixed precedence left implicit. */
int mixed(int a, int b, int c)
{
    return a && b || c;
}

/* 12.1 again, with a shift: `+` binds tighter than `<<`. */
unsigned int shifted(unsigned int a, unsigned int b)
{
    return a + b << 2u;
}

/* 12.3: the comma operator. */
int comma(int a, int b)
{
    int r;
    r = (a++, b);
    return r;
}

/* 13.3: a full expression with an increment and another side effect. */
int side_effects(int a)
{
    int r = a++ + g(a);
    return r;
}

/* 13.4: the result of an assignment used. */
int assignment_value(int a)
{
    int b;
    if ((b = g(a)) != 0) {
        return b;
    }
    return 0;
}

/* 13.6: sizeof over an expression with side effects. */
unsigned long measured(int a)
{
    return (unsigned long)sizeof(g(a));
}
