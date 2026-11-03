/* 20.13: a line whose first token is `#` must be a valid preprocessing
 * directive.
 *
 * On its own because an unrecognised directive is a hard error for some
 * preprocessors and a warning for others, and either way it changes what the
 * rest of the file means. */
int before = 1;

#this_is_not_a_directive

int after = 2;
