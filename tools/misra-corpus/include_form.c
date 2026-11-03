/* 20.3: the `#include` directive must be followed by `<filename>` or
 * `"filename"`.
 *
 * On its own: a malformed include stops the preprocessor reading the file, so
 * anything after it would contribute nothing to the comparison. */
int before = 1;

/* 20.2: a header name carrying a character whose behaviour the standard leaves
 * undefined. A backslash means whatever the implementation decides, and on one
 * of the two obvious platforms that is a path separator. */
#include "dir\name.h"

#include stddef.h

int after = 2;
