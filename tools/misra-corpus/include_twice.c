/* Header inclusion: D4.10.
 *
 * The unguarded header is included twice; the guarded one is included twice
 * too, and the comparison sees the difference only through the header files. */
#include "unguarded.h"
#include "unguarded.h"
#include "guarded.h"
#include "guarded.h"

int use_headers(void)
{
    return shared_value + guarded_value;
}
