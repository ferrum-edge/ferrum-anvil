/* Hosted regression fixture for the separately requested runtime probe. */
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
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
    const char *shared = getenv("RELEASE_CHECK_SHARED_LOCK");
    if (shared != NULL) {
        /* Like the WebView2 user data folder on Windows: every launch shares
           one lock, held by a helper process the app starts. The helper is
           not this executable (so no path match finds it) and ignores
           SIGTERM; the lock lasts until the helper is gone. */
        int fd = open(shared, O_RDWR | O_CREAT, 0600);
        if (fd < 0) {
            return 1;
        }
        if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
            fputs("shared lock is in use\n", stderr);
            return 3;
        }
        pid_t helper = fork();
        if (helper < 0) {
            return 1;
        }
        if (helper == 0) {
            /* Optionally leave the app's session and process group, as a
               detached helper would. */
            if (getenv("RELEASE_CHECK_SETSID_HELPER") != NULL && setsid() < 0) {
                _exit(126);
            }
            signal(SIGTERM, SIG_IGN);
            const char *pids = getenv("RELEASE_CHECK_HELPER_PIDS");
            FILE *list = pids == NULL ? NULL : fopen(pids, "a");
            if (list != NULL) {
                fprintf(list, "%ld\n", (long)getpid());
                fclose(list);
            }
            execl("/bin/sleep", "sleep", "300", (char *)NULL);
            _exit(127);
        }
    }
    if (getenv("RELEASE_CHECK_EXIT_EARLY") != NULL) {
        return 0;
    }
    /* Exit early on the first launch only: the marker file records it. */
    const char *once = getenv("RELEASE_CHECK_EXIT_EARLY_ONCE");
    if (once != NULL) {
        int marker = open(once, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (marker >= 0) {
            close(marker);
            return 0;
        }
    }
    for (;;) {
        pause();
    }
}
