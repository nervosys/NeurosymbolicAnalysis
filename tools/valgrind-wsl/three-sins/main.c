#include <stdlib.h>
#include <string.h>

static void invalid_write(void) {
    int *a = malloc(4 * sizeof(int));
    a[4] = 1;
    free(a);
}

static int uninit_read(void) {
    int x;
    if (x == 42) return 1;
    return 0;
}

int main(void) {
    invalid_write();
    (void)uninit_read();
    char *leaked = malloc(128);
    strcpy(leaked, "never freed");
    return 0;
}
