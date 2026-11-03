/* Example firmware with deliberate MISRA C:2023 violations, used by the
   README walkthrough and the integration test. */
#include <stdio.h>
#include <stdlib.h>

#define MAX_RETRIES 3
#define UNUSED_MACRO 42

static int lookup(int key)
{
    int result;
    /* result = compute(key); */
    switch (key) {
        case 1:
            result = 10;
        case 2:
            result = 20;
            break;
        default:
            result = 0;
            break;
    }
    return result;
}

int process(int *buffer, int count)
{
    int i;
    int total = 0;
    if (count > 0)
        total = buffer[0];

    for (i = 0; i < count; i++) {
        if (buffer[i] == 0777) {
            goto cleanup;
        }
        total += buffer[i];
    }

    if (total > 100) {
        printf("large\n");
    } else if (total > 10) {
        printf("medium\n");
    }

cleanup:
    free(buffer);
    return total;
}
