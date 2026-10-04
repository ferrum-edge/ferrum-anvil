/* Hosted regression fixture: every invocation records that the input ran. */
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    const char *path = getenv("RELEASE_CHECK_RUNTIME_SENTINEL");
    if (path == NULL) {
        return 1;
    }
    FILE *sentinel = fopen(path, "w");
    if (sentinel == NULL) {
        return 1;
    }
    fputs("untrusted AppImage runtime executed\n", sentinel);
    return fclose(sentinel) != 0;
}
