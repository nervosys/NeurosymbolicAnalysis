#include "serve.h"

/* argv is a taint source CodeQL's C++ libraries model, which is what makes this
 * program a test of the *tool* rather than of a hand-written flow. */
std::string command(int argc, char **argv)
{
    return argc > 1 ? std::string(argv[1]) : std::string("status");
}
