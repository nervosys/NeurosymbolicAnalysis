/* Declarations: 6.2, 8.2, 8.10, 8.11, 8.14, 17.6, 18.5, 19.2. */

/* 6.2: a single-bit named bit-field of signed type. */
struct flags {
    signed int enabled : 1;
    unsigned int mode : 2;
};

/* 19.2: the union keyword. */
union word {
    unsigned long whole;
    unsigned char bytes[4];
};

/* 8.2: a prototype without named parameters. */
extern int older(int, int);

/* 8.11: an array with external linkage and no explicit size. */
extern int table[];

/* 8.10: an inline function that is not static. */
inline int doubled(int x)
{
    return x * 2;
}

/* 8.14: the restrict qualifier. */
void copy_over(int *restrict to, const int *restrict from, unsigned int n)
{
    unsigned int i;
    for (i = 0u; i < n; i++) {
        to[i] = from[i];
    }
}

/* 17.6: static between the brackets of an array parameter. */
int first_of(int values[static 1])
{
    return values[0];
}

/* 18.5: more than two levels of pointer nesting. */
int deep(int ***p)
{
    return ***p;
}
