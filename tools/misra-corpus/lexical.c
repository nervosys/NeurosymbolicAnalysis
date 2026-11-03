/* Lexical matter: 3.1, 3.2, 4.1, 7.1, 7.3.
 *
 * Several of these are about characters the compiler reads differently from
 * the way a person does, so the file is deliberately small. */

/* 3.1: a comment sequence inside a comment. /* like this */
/* 3.1 again, the other direction: // inside a block comment */

/* 7.1: an octal constant. */
int permissions = 0777;

/* 7.3: a lowercase l suffix, which reads as a 1. */
long count = 100l;

/* 4.1: a hexadecimal escape that is not terminated. The escape consumes hex
 * digits greedily, so where it stops depends on what follows it. */
const char *hex = "\x12g";

/* 4.1 again, octal: four digits where an escape takes at most three. */
const char *octal = "\1238";

// 3.2: this line comment is spliced into the next one \
int swallowed = 1;
int kept = 2;
