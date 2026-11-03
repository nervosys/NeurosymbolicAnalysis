#include "clamp.h"

std::string clamp(const std::string &value)
{
    if (value == "status" || value == "stop" || value == "start") {
        return value;
    }
    return std::string("status");
}
