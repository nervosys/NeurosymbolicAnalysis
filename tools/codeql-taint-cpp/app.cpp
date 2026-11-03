/* One guarded path and one bypass, crossing component boundaries.
 *
 * The C++ counterpart of `tools/codeql-taint/`, deliberately the same shape: the
 * same four components, the same guarded route and the same relay the
 * architecture declaration forgets. Two producers of the same claim are worth
 * more than two different claims, and the declaration in
 * `crates/sda-engine/tests/` is written against this shape.
 */
#include "actuator/drive.h"
#include "guard/clamp.h"
#include "policy/serve.h"
#include "telemetry/relay.h"

#include <cstring>

static void guarded(int argc, char **argv)
{
    const std::string raw = command(argc, argv);
    write_actuator(clamp(raw));
}

static void bypass(int argc, char **argv)
{
    const std::string raw = command(argc, argv);
    write_actuator(relay(raw));
}

int main(int argc, char **argv)
{
    if (argc > 2 && strcmp(argv[2], "guarded") == 0) {
        guarded(argc, argv);
    } else {
        bypass(argc, argv);
    }
    return 0;
}
