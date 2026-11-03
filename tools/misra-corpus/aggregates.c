/* Aggregates: 6.3.
 *
 * Each guideline has a violating form and a conforming form in this file. */

/* 6.3: a bit-field declared directly as a member of a union. */
union packed_violating {
    unsigned int whole;
    unsigned int flag : 1;
};

/* 6.3, conforming: the same bit-field, as a member of a structure. */
struct packed_conforming {
    unsigned int whole;
    unsigned int flag : 1;
};

/* 6.3, conforming: a bit-field inside a structure that is itself a member of
 * a union. The bit-field's enclosing declaration is the structure. */
union nested_conforming {
    struct {
        unsigned int flag : 1;
    } bits;
    unsigned int raw;
};
