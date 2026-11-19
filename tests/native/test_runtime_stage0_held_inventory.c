/* Real local FD/socket structure checks only. No preparer, GO or resources. */
#define _GNU_SOURCE
#ifdef NDEBUG
#error "Held inventory fixtures require active assertions"
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../../automation/native/runtime_stage0_admission.h"

static void scenario(int fault)
{
    alarm(5);
    struct rnr_stage0_admission_error error;
    assert(rnr_stage0_admit_preparation_fds(&error) == 0);
    int pair[2], extra = -1;
    if (fault != 1) {
        int type = (fault == 3 ? SOCK_DGRAM : SOCK_SEQPACKET) | SOCK_CLOEXEC;
        if (fault != 4) type |= SOCK_NONBLOCK;
        assert(socketpair(AF_UNIX, type, 0, pair) == 0);
        assert(pair[0] == 3 && pair[1] == 4);
        if (fault != 2) assert(close(pair[0]) == 0);
        if (fault == 5) assert(fcntl(4, F_SETFD, 0) == 0);
        if (fault == 6) {
            assert(close(4) == 0);
            int replacement = open("/dev/null", O_RDWR | O_CLOEXEC | O_NONBLOCK);
            assert(replacement == 3);
            assert(dup3(replacement, 4, O_CLOEXEC) == 4);
            assert(close(replacement) == 0);
        }
        if (fault == 7) { extra = fcntl(4, F_DUPFD_CLOEXEC, 5); assert(extra == 5); }
    }
    int result = rnr_stage0_admit_held_fds(&error);
    assert(fault == 0 ? result == 0 : result == -1);
    /* Structural validation never repairs or consumes a caller's handles. */
    if (fault != 1) assert(fcntl(4, F_GETFD) >= 0);
    if (extra >= 0) assert(fcntl(extra, F_GETFD) >= 0);
    if (fault == 2) assert(fcntl(3, F_GETFD) >= 0);
    else { errno = 0; assert(fcntl(3, F_GETFD) == -1 && errno == EBADF); }
    if (fault == 0) {
        assert(rnr_stage0_admit_preparation_fds(&error) == -1);
        assert(fcntl(4, F_GETFD) >= 0);
        assert(close(4) == 0);
        assert(rnr_stage0_admit_preparation_fds(&error) == 0);
    }
    _exit(0);
}

int main(void)
{
    for (int fault = 0; fault < 8; ++fault) {
        pid_t child = fork(); assert(child >= 0);
        if (child == 0) scenario(fault);
        int status;
        assert(waitpid(child, &status, 0) == child);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    return 0;
}
