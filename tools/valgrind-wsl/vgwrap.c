/* Present WSL's Valgrind to the Windows adapter as a real executable.
 *
 * CreateProcess cannot run a .bat, so Rust's Command::new could not spawn the
 * batch wrapper. This is an .exe, so it can. It rebuilds the command line for
 * cmd, which can run the batch file, and returns its exit status unchanged --
 * the adapter judges on that. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    char cmd[32768];
    const char *bat = getenv("SDA_VG_BAT");
    if (!bat) { fprintf(stderr, "SDA_VG_BAT is unset\n"); return 127; }
    snprintf(cmd, sizeof cmd, "\"\"%s\"", bat);
    for (int i = 1; i < argc; i++) {
        strncat(cmd, " \"", sizeof cmd - strlen(cmd) - 1);
        strncat(cmd, argv[i], sizeof cmd - strlen(cmd) - 1);
        strncat(cmd, "\"", sizeof cmd - strlen(cmd) - 1);
    }
    strncat(cmd, "\"", sizeof cmd - strlen(cmd) - 1);
    return system(cmd);
}
