/* Hosted regression fixture for the separately requested runtime probe. */
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    puts("com.ferrumedge.anvil __TAURI_INTERNALS__");
    const char *path = getenv("RELEASE_CHECK_DESKTOP_SENTINEL");
    if (path == NULL) {
        return 1;
    }
    FILE *sentinel = fopen(path, "w");
    if (sentinel == NULL) {
        return 1;
    }
    fputs("extracted desktop launched\n", sentinel);
    if (fclose(sentinel) != 0) {
        return 1;
    }
    if (getenv("RELEASE_CHECK_CREATE_PROFILE") != NULL) {
        char profiles[4096];
        char profile[4096];
        const char *data = getenv("ANVIL_DATA_DIR");
        if (data == NULL) {
            return 1;
        }
        snprintf(profiles, sizeof(profiles), "%s/profiles", data);
        snprintf(profile, sizeof(profile), "%s/profiles/unexpected", data);
        if (mkdir(profiles, 0700) != 0 || mkdir(profile, 0700) != 0) {
            return 1;
        }
    }
    if (getenv("RELEASE_CHECK_EXIT_EARLY") != NULL) {
        return 0;
    }
    for (;;) {
        pause();
    }
}
