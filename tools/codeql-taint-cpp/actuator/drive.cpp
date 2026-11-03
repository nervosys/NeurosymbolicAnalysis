#include "drive.h"
#include <cstdlib>

void write_actuator(const std::string &value)
{
    const std::string cmd = "actuator " + value;
    /* The sink. `cpp/command-line-injection` reports a path that reaches here. */
    system(cmd.c_str());
}
