/* Opens a conditional block whose #endif is written in the file that includes
 * this one. That split is the 20.14 violation in conditionals.c. */
#if defined(FEATURE_TWO)
