/* Dormant Linux PID1 guardian. No Store, daemon, network or release authority.
 * Build/transport/image/host containment must be independently qualified.
 * Userspace deadlines are not hard real-time under kernel/scheduler failure.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/capability.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define BUFFER_SIZE 131072U
#define FRAME_SIZE 65536U
#define OUTPUT_LIMIT 16777216U

struct buffer { unsigned char bytes[BUFFER_SIZE]; size_t used; };

static _Noreturn void terminal(void) { _exit(120); }

static int parse_number(const char *s, int64_t *out) {
    uint64_t n = 0;
    if (!s || s[0] < '1' || s[0] > '9') return 0;
    for (size_t i = 0; s[i]; i++) {
        if (i >= 19 || s[i] < '0' || s[i] > '9') return 0;
        unsigned digit = (unsigned)(s[i] - '0');
        if (n > ((uint64_t)INT64_MAX - digit) / 10) return 0;
        n = n * 10 + digit;
    }
    *out = (int64_t)n;
    return 1;
}

static int64_t clock_now(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_BOOTTIME, &now) || now.tv_sec < 0 ||
        now.tv_sec > INT64_MAX / 1000000000 || now.tv_nsec < 0 || now.tv_nsec >= 1000000000)
        terminal();
    int64_t seconds = (int64_t)now.tv_sec * 1000000000;
    if (seconds > INT64_MAX - now.tv_nsec) terminal();
    return seconds + now.tv_nsec;
}

static void check_time(int64_t captured, int64_t deadline) {
    int64_t now = clock_now();
    if (now < captured || now >= deadline) terminal();
}

static void identity(const char *boot, int64_t device, int64_t inode) {
    if (strlen(boot) != 36) terminal();
    for (size_t i = 0; i < 36; i++) {
        int hyphen = i == 8 || i == 13 || i == 18 || i == 23;
        if (hyphen ? boot[i] != '-' : !((boot[i] >= '0' && boot[i] <= '9') ||
                                      (boot[i] >= 'a' && boot[i] <= 'f'))) terminal();
    }
    int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) terminal();
    char raw[38];
    ssize_t n = read(fd, raw, sizeof(raw));
    if (close(fd) || n != 37 || raw[36] != '\n' || memcmp(raw, boot, 36)) terminal();
    struct stat ns;
    if (stat("/proc/thread-self/ns/time", &ns) ||
        (uint64_t)ns.st_dev != (uint64_t)device || (uint64_t)ns.st_ino != (uint64_t)inode)
        terminal();
}

static void signals(void) {
    sigset_t empty;
    if (sigemptyset(&empty) || sigprocmask(SIG_SETMASK, &empty, NULL)) terminal();
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    if (sigemptyset(&action.sa_mask)) terminal();
    for (int sig = 1; sig < NSIG; sig++) {
        if (sig == SIGKILL || sig == SIGSTOP) continue;
        /* glibc reserves its two internal realtime signals. */
        if (sigaction(sig, &action, NULL) && !(errno == EINVAL && (sig == 32 || sig == 33)))
            terminal();
    }
}

static int ambient_empty(int last) {
    if (last < 0 || last > 63) return 0;
    for (int i = 0; i <= last; i++)
        if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, i, 0, 0) != 0) return 0;
    return 1;
}

static void security(void) {
    uid_t r, e, s;
    gid_t gr, ge, gs;
    if (getpid() != 1 || getresuid(&r, &e, &s) || getresgid(&gr, &ge, &gs) ||
        !r || r != e || e != s || !gr || gr != ge || ge != gs ||
        prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) terminal();
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct caps[2];
    if (syscall(SYS_capget, &header, caps)) terminal();
    for (int i = 0; i < 2; i++)
        if (caps[i].effective || caps[i].permitted || caps[i].inheritable) terminal();
    int fd = open("/proc/sys/kernel/cap_last_cap", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    char raw[8]; int64_t last;
    if (fd < 0) terminal();
    ssize_t n = read(fd, raw, sizeof(raw));
    if (close(fd) || n < 2 || n >= (ssize_t)sizeof(raw) || raw[n-1] != '\n') terminal();
    raw[n-1] = '\0';
    if (!parse_number(raw, &last) || last > 63 || !ambient_empty((int)last)) terminal();
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) || prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0)
        terminal();
}

static void nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK)) terminal();
}

static int stream_fd(int fd) {
    struct stat info;
    if (fstat(fd, &info)) return 0;
    if (S_ISFIFO(info.st_mode)) return 1;
    int kind; socklen_t size = sizeof(kind);
    return S_ISSOCK(info.st_mode) &&
        !getsockopt(fd, SOL_SOCKET, SO_TYPE, &kind, &size) &&
        size == sizeof(kind) && kind == SOCK_STREAM;
}

static void close_fd(int fd) { if (close(fd)) terminal(); }

static void consume(struct buffer *buffer, size_t n) {
    if (n > buffer->used) terminal();
    buffer->used -= n;
    memmove(buffer->bytes, buffer->bytes + n, buffer->used);
}

static int queue_frame(struct buffer *buffer, unsigned char kind,
                       const unsigned char *payload, size_t n, uint64_t quota, uint64_t *total) {
    if (n > FRAME_SIZE || buffer->used > BUFFER_SIZE || n + 5 > BUFFER_SIZE - buffer->used)
        return 0;
    int app = kind == 'O' || kind == 'E';
    if (app && (*total > quota || n > quota - *total)) return 0;
    unsigned char *dst = buffer->bytes + buffer->used;
    dst[0] = kind;
    for (unsigned i = 0; i < 4; i++) dst[i+1] = (unsigned char)(n >> (24 - 8*i));
    memcpy(dst+5, payload, n);
    buffer->used += n+5;
    if (app) *total += n;
    return 1;
}

static int input_frame(struct buffer *wire, struct buffer *app) {
    if (!wire->used) return 0;
    if (wire->bytes[0] != 'I') return -1;
    if (wire->used < 5) return 0;
    uint32_t n = 0;
    for (unsigned i = 1; i < 5; i++) n = (n << 8) | wire->bytes[i];
    if (n > FRAME_SIZE) return -1;
    if (wire->used < (size_t)n + 5) return 0;
    if (app->used > BUFFER_SIZE || n > BUFFER_SIZE - app->used) return -1;
    memcpy(app->bytes + app->used, wire->bytes + 5, n);
    app->used += n;
    consume(wire, (size_t)n + 5);
    return 1;
}

static size_t input_room(const struct buffer *wire, const struct buffer *app) {
    if (wire->used > BUFFER_SIZE || app->used > BUFFER_SIZE - wire->used) return 0;
    return BUFFER_SIZE - wire->used - app->used;
}

static void write_buffer(int fd, struct buffer *buffer) {
    size_t count = buffer->used < FRAME_SIZE ? buffer->used : FRAME_SIZE;
    if (!count) return;
    ssize_t n = write(fd, buffer->bytes, count);
    if (n > 0) consume(buffer, (size_t)n);
    else if (n == 0 || (errno != EAGAIN && errno != EINTR)) terminal();
}

static void read_app(int *fd, unsigned char kind, struct buffer *output, uint64_t quota, uint64_t *total) {
    unsigned char payload[FRAME_SIZE];
    ssize_t n = read(*fd, payload, sizeof(payload));
    if (n > 0) {
        if (!queue_frame(output, kind, payload, (size_t)n, quota, total)) terminal();
    } else if (!n) {
        close_fd(*fd); *fd = -1;
    } else if (errno != EAGAIN && errno != EINTR) terminal();
}

static _Noreturn void child(int input, int output, int error, int gate, int64_t captured, int64_t deadline) {
    if (dup2(input, 0) < 0 || dup2(output, 1) < 0 || dup2(error, 2) < 0) terminal();
    if (gate != 3 && dup3(gate, 3, O_CLOEXEC) < 0) terminal();
    if (syscall(SYS_close_range, 4U, UINT_MAX, 0)) terminal();
    unsigned char release;
    if (read(3, &release, 1) != 1 || release != 'G') terminal();
    close_fd(3);
    signals();
    if (chdir("/")) terminal();
    char *const env[] = {"HOME=/rnr/home", "CODEX_HOME=/rnr/home", "LANG=C.UTF-8", NULL};
#ifdef RNR_TEST_BUILD
    char *const argv[] = {RNR_TEST_CHILD_PATH, "app-server", "--listen", "stdio://", NULL};
#else
    char *const argv[] = {"/rnr/codex", "app-server", "--listen", "stdio://", NULL};
#endif
    check_time(captured, deadline);
    execve(argv[0], argv, env);
    terminal();
}

int main(int argc, char **argv) {
    int64_t device, inode, captured, deadline, quota;
    if (getpid() != 1 || argc != 7 ||
        !parse_number(argv[2], &device) || !parse_number(argv[3], &inode) ||
        !parse_number(argv[4], &captured) || !parse_number(argv[5], &deadline) ||
        !parse_number(argv[6], &quota) || deadline <= captured || quota > OUTPUT_LIMIT) terminal();
    /* Only stdio is an inherited endpoint. No soft-rlimit fd scan. */
    if (!stream_fd(0) || !stream_fd(1) || fcntl(2, F_GETFD) < 0 ||
        syscall(SYS_close_range, 3U, UINT_MAX, 0)) terminal();
    signals(); security();
    identity(argv[1], device, inode); check_time(captured, deadline);
    nonblock(0); nonblock(1);
    struct sigaction ignored;
    memset(&ignored, 0, sizeof(ignored)); ignored.sa_handler = SIG_IGN;
    if (sigemptyset(&ignored.sa_mask) || sigaction(SIGPIPE, &ignored, NULL)) terminal();
    int timer = timerfd_create(CLOCK_BOOTTIME, TFD_CLOEXEC | TFD_NONBLOCK);
    struct itimerspec expiry = {{0, 0}, {deadline / 1000000000, deadline % 1000000000}}, armed;
    if (timer < 0 || timerfd_settime(timer, TFD_TIMER_ABSTIME, &expiry, NULL) ||
        timerfd_gettime(timer, &armed) || armed.it_interval.tv_sec || armed.it_interval.tv_nsec ||
        (!armed.it_value.tv_sec && !armed.it_value.tv_nsec)) terminal();
    identity(argv[1], device, inode); check_time(captured, deadline);
    int input[2], output[2], error[2], gate[2];
    if (pipe2(input, O_CLOEXEC) || pipe2(output, O_CLOEXEC) ||
        pipe2(error, O_CLOEXEC) || pipe2(gate, O_CLOEXEC)) terminal();
    nonblock(input[1]); nonblock(output[0]); nonblock(error[0]); nonblock(gate[1]);
    static struct buffer to_host, from_host, to_child;
    uint64_t total = 0;
    if (!queue_frame(&to_host, 'S', (const unsigned char *)"ARMED", 5, (uint64_t)quota, &total)) terminal();
    pid_t pid = fork();
    if (pid < 0) terminal();
    if (!pid) child(input[0], output[1], error[1], gate[0], captured, deadline);
    close_fd(input[0]); close_fd(output[1]); close_fd(error[1]); close_fd(gate[0]);
    check_time(captured, deadline);
    if (write(gate[1], "G", 1) != 1) terminal();
    close_fd(gate[1]);
    if (!queue_frame(&to_host, 'S', (const unsigned char *)"CHILD_RELEASED", 14, (uint64_t)quota, &total)) terminal();
    for (;;) {
        check_time(captured, deadline);
        int status;
        pid_t waited = waitpid(pid, &status, WNOHANG);
        if (waited == pid || waited < 0) terminal();
        int parsed = input_frame(&from_host, &to_child);
        if (parsed < 0) terminal();
        struct pollfd fds[] = {{timer, POLLIN, 0}, {0, POLLIN, 0},
            {1, to_host.used ? POLLOUT : 0, 0}, {input[1], to_child.used ? POLLOUT : 0, 0},
            {output[0], POLLIN, 0}, {error[0], POLLIN, 0}};
        int64_t remaining = deadline - clock_now();
        if (remaining <= 0) terminal();
        int timeout = remaining / 1000000 > 100 ? 100 : (int)(remaining / 1000000);
        if (parsed) timeout = 0;
        int ready = poll(fds, 6, timeout);
        check_time(captured, deadline);
        if (ready < 0) { if (errno == EINTR) continue; terminal(); }
        if (fds[0].revents) terminal();
        for (int i = 1; i <= 3; i++)
            if (fds[i].revents & (POLLHUP | POLLERR | POLLNVAL)) terminal();
        for (int i = 4; i <= 5; i++)
            if (fds[i].revents & (POLLERR | POLLNVAL)) terminal();
        if (fds[1].revents & POLLIN) {
            size_t room = input_room(&from_host, &to_child);
            if (!room) terminal();
            if (room > FRAME_SIZE) room = FRAME_SIZE;
            ssize_t n = read(0, from_host.bytes + from_host.used, room);
            if (n > 0) from_host.used += (size_t)n;
            else if (!n || (errno != EAGAIN && errno != EINTR)) terminal();
        }
        if (fds[2].revents & POLLOUT) write_buffer(1, &to_host);
        if (fds[3].revents & POLLOUT) write_buffer(input[1], &to_child);
        if (fds[4].revents & (POLLIN | POLLHUP)) read_app(&output[0], 'O', &to_host, (uint64_t)quota, &total);
        if (fds[5].revents & (POLLIN | POLLHUP)) read_app(&error[0], 'E', &to_host, (uint64_t)quota, &total);
    }
}
