/* Real local socket/FD inventory with an EOF-boundary mutation. No preparer. */
#define _GNU_SOURCE
#define RNR_STAGE0_PRIVATE_QUALIFICATION 1
#ifdef NDEBUG
#error "Held mutation fixture requires active assertions"
#endif
#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
static long scan_syscall(long, int, void *, size_t);
#define syscall(c, f, b, n) scan_syscall(c, f, b, n)
#include "../../automation/native/runtime_stage0_admission.c"
#undef syscall
static int fault, armed, mutated;
static long scan_syscall(long call, int fd, void *buffer, size_t count)
{
    assert(call == SYS_getdents64);
    long result = syscall(call, fd, buffer, count);
    if (result == 0 && armed && fault && !mutated) {
        mutated = 1;
        if (fault == 1) assert(fcntl(4, F_SETFL, O_RDWR) == 0);
        else assert(fcntl(4, F_SETFD, 0) == 0);
    }
    return result;
}
int main(void)
{
    for (fault = 0; fault < 3; ++fault) {
        pid_t child = fork(); assert(child >= 0);
        if (child == 0) {
            alarm(5);
            struct rnr_stage0_admission_error error;
            assert(rnr_stage0_admit_preparation_fds(&error) == 0);
            int pair[2];
            assert(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC,
                              0, pair) == 0 && pair[0] == 3 && pair[1] == 4);
            assert(close(3) == 0);
            armed = 1;
            int result = rnr_stage0_admit_held_fds(&error);
            armed = 0;
            assert(fault ? (mutated && result == -1) : result == 0);
            assert(close(4) == 0);
            assert(rnr_stage0_admit_preparation_fds(&error) == 0);
            _exit(0);
        }
        int status;
        assert(waitpid(child, &status, 0) == child);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    return 0;
}
