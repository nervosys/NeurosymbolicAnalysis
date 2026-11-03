/* Conditional inclusion: 20.14.
 *
 * Each form has a violating and a conforming version in this file. */

/* 20.14, violating: the #if is opened in conditional_open.h, and the matching
 * #endif is written here, in a different file. */
#include "conditional_open.h"
int feature_two_violating = 2;
#endif

/* 20.14, conforming: the #if and its #endif are both written in this file. */
#if defined(FEATURE_ONE)
int feature_one_conforming = 1;
#endif
