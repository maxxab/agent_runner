/* OFFLINE NEGATIVE-TEST SOURCE ONLY: not built or run.
 * All module syscalls are substituted at preprocessing time in this test
 * translation unit. Production exposes no injectable operations table.
 * Building/executing this test needs separate explicit authorization.
 */
#define _GNU_SOURCE
#ifdef NDEBUG
#error "Mock admission tests require active assertions; do not define NDEBUG"
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int fixture_open(const char *, int);
static int fixture_fstat(int, struct stat *);
static int fixture_stat(const char *, struct stat *);
static int fixture_fcntl(int, int);
static long fixture_syscall(long, ...);
static int fixture_close(int);

#define open(path, flags) fixture_open(path, flags)
#define fstat(fd, info) fixture_fstat(fd, info)
#define stat(path, info) fixture_stat(path, info)
#define fcntl(fd, command) fixture_fcntl(fd, command)
#define syscall(...) fixture_syscall(__VA_ARGS__)
#define close(fd) fixture_close(fd)
#include "../../automation/native/runtime_stage0_admission.c"
#undef open
#undef fstat
#undef stat
#undef fcntl
#undef syscall
#undef close

enum { OWNED_FD = 50 };
static struct stat descriptors[64], null_fixture;
static int flags_fixture[3], stat_calls[64];
static unsigned char payload[4096];
static size_t payload_size, payload_offset;
static int missing_fd, changed_fd, changed_at, open_error, null_error;
static int read_error, close_error, oversized_read, one_record_reads;
static int read_calls, open_calls, close_calls, caller_close_calls, null_regular;
static int fcntl_error_fd;

static void append_name(const char *name)
{
    size_t length = strlen(name);
    uint16_t size = (uint16_t)((19 + length + 1 + 7) & ~(size_t)7);
    assert(payload_size + size <= sizeof(payload));
    memset(payload + payload_size, 0, size);
    memcpy(payload + payload_size + 16, &size, sizeof(size));
    memcpy(payload + payload_size + 19, name, length);
    payload_size += size;
}

static void reset_fixture(void)
{
    memset(descriptors, 0, sizeof(descriptors));
    memset(stat_calls, 0, sizeof(stat_calls));
    memset(payload, 0, sizeof(payload));
    memset(&null_fixture, 0, sizeof(null_fixture));
    for (int fd = 0; fd < 64; ++fd) {
        descriptors[fd].st_dev = 1;
        descriptors[fd].st_ino = (ino_t)(fd + 100);
        descriptors[fd].st_mode = S_IFREG | 0600;
    }
    descriptors[OWNED_FD].st_mode = S_IFDIR | 0500;
    null_fixture.st_mode = S_IFCHR | 0666;
    null_fixture.st_rdev = 123;
    flags_fixture[0] = O_RDONLY;
    flags_fixture[1] = flags_fixture[2] = O_WRONLY;
    missing_fd = changed_fd = fcntl_error_fd = -1;
    changed_at = 2;
    open_error = null_error = read_error = close_error = 0;
    oversized_read = one_record_reads = null_regular = 0;
    read_calls = open_calls = close_calls = caller_close_calls = 0;
    payload_size = payload_offset = 0;
    append_name(".");
    append_name("..");
    for (int fd = 0; fd < 9; ++fd) {
        char name[2] = {(char)('0' + fd), 0};
        append_name(name);
    }
    append_name("50");
}

static int fixture_open(const char *path, int flags)
{
    ++open_calls;
    assert(strcmp(path, "/proc/self/fd") == 0);
    assert(flags == (O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (open_error) {
        errno = open_error;
        return -1;
    }
    return OWNED_FD;
}

static int fixture_fstat(int fd, struct stat *info)
{
    assert((fd >= 0 && fd <= 8) || fd == OWNED_FD);
    ++stat_calls[fd];
    if (fd == missing_fd) {
        errno = EBADF;
        return -1;
    }
    *info = descriptors[fd];
    if (fd == changed_fd && stat_calls[fd] >= changed_at)
        ++info->st_ino;
    return 0;
}

static int fixture_stat(const char *path, struct stat *info)
{
    assert(strcmp(path, "/dev/null") == 0);
    if (null_error) {
        errno = null_error;
        return -1;
    }
    *info = null_fixture;
    if (null_regular)
        info->st_mode = S_IFREG | 0600;
    return 0;
}

static int fixture_fcntl(int fd, int command)
{
    assert(fd >= 0 && fd < 3 && command == F_GETFL);
    if (fd == fcntl_error_fd) {
        errno = EIO;
        return -1;
    }
    return flags_fixture[fd];
}

static long fixture_syscall(long number, ...)
{
    va_list args;
    int fd;
    void *buffer;
    size_t capacity, amount;
    ++read_calls;
    assert(number == SYS_getdents64);
    va_start(args, number);
    fd = va_arg(args, int);
    buffer = va_arg(args, void *);
    capacity = va_arg(args, size_t);
    va_end(args);
    assert(fd == OWNED_FD && capacity == 4096);
    if (read_error) {
        errno = read_error;
        return -1;
    }
    if (oversized_read)
        return (long)capacity + 1;
    amount = payload_size - payload_offset;
    if (one_record_reads && amount) {
        uint16_t size;
        memcpy(&size, payload + payload_offset + 16, sizeof(size));
        assert(size > 0 && size <= amount);
        amount = size;
    }
    assert(amount <= capacity);
    memcpy(buffer, payload + payload_offset, amount);
    payload_offset += amount;
    return (long)amount;
}

static int fixture_close(int fd)
{
    ++close_calls;
    if (fd != OWNED_FD)
        ++caller_close_calls;
    assert(fd == OWNED_FD);
    if (close_error) {
        errno = close_error;
        return -1; /* uncertainty: caller must not retry */
    }
    return 0;
}

static struct rnr_stage0_admission_error expect(
    enum rnr_stage0_admission_code code, int expected_closes)
{
    struct rnr_stage0_admission_error error;
    int result = rnr_stage0_admit_initial_fds(&error);
    assert(result == (code == RNR_STAGE0_ADMISSION_OK ? 0 : -1));
    assert(error.code == code);
    assert(close_calls == expected_closes);
    assert(caller_close_calls == 0);
    assert(read_calls <= 13);
    return error;
}

static void preparation_fixture(void)
{
    reset_fixture();
    payload_size = payload_offset = 0;
    append_name(".");
    append_name("..");
    append_name("0");
    append_name("1");
    append_name("2");
    append_name("50");
}

static void preparation_admission(void)
{
    struct rnr_stage0_admission_error error;
    preparation_fixture();
    one_record_reads = 1;
    assert(rnr_stage0_admit_preparation_fds(&error) == 0);
    assert(error.code == RNR_STAGE0_ADMISSION_OK && read_calls == 7);
    assert(close_calls == 1 && caller_close_calls == 0);
    /* A preparation caller carrying even one final role is rejected, never
     * repaired by closing it. Missing final3..8 is intentional in this mode. */
    for (int fd = 3; fd <= 8; ++fd) {
        preparation_fixture();
        payload_size -= 24;
        char name[] = {(char)('0' + fd), 0};
        append_name(name);
        append_name("50");
        assert(rnr_stage0_admit_preparation_fds(&error) == -1);
        assert(error.code == RNR_STAGE0_ADMISSION_INVENTORY);
        assert(close_calls == 1 && caller_close_calls == 0);
    }
    for (int fd = 0; fd < 3; ++fd) {
        preparation_fixture();
        missing_fd = fd;
        assert(rnr_stage0_admit_preparation_fds(&error) == -1);
        assert(error.code == RNR_STAGE0_ADMISSION_INPUT && close_calls == 0);
    }
    preparation_fixture();
    flags_fixture[0] = O_WRONLY;
    assert(rnr_stage0_admit_preparation_fds(&error) == -1);
    assert(error.code == RNR_STAGE0_ADMISSION_STDIO && open_calls == 0);
    preparation_fixture();
    changed_fd = 2;
    assert(rnr_stage0_admit_preparation_fds(&error) == -1);
    assert(error.code == RNR_STAGE0_ADMISSION_IDENTITY && close_calls == 1);
    preparation_fixture();
    read_error = EIO;
    close_error = EINTR;
    assert(rnr_stage0_admit_preparation_fds(&error) == -1);
    assert(error.code == RNR_STAGE0_ADMISSION_READ && error.system_errno == EIO);
    assert(error.cleanup_errno == EINTR && close_calls == 1 && caller_close_calls == 0);
    preparation_fixture();
    assert(rnr_stage0_admit_preparation_fds(NULL) == -1 && errno == EINVAL);
    assert(open_calls == 0 && close_calls == 0);
}

int main(void)
{
    struct rnr_stage0_admission_error error;
    const char *bad_names[] = {"", "00", "01", "-1", "+1", "x",
                              "2147483648", "99999999999"};
    uint16_t short_record;
    size_t last;

    reset_fixture();
    expect(RNR_STAGE0_ADMISSION_OK, 1);
    assert(read_calls == 2);
    for (int fd = 0; fd < 9; ++fd)
        assert(stat_calls[fd] == 3);

    reset_fixture();
    one_record_reads = 1;
    expect(RNR_STAGE0_ADMISSION_OK, 1);
    assert(read_calls == 13);

    reset_fixture();
    flags_fixture[0] = O_RDWR;
    descriptors[1].st_mode = S_IFIFO | 0600;
    descriptors[2].st_mode = S_IFCHR | 0600;
    descriptors[2].st_rdev = null_fixture.st_rdev;
    expect(RNR_STAGE0_ADMISSION_OK, 1);

    reset_fixture();
    assert(rnr_stage0_admit_initial_fds(NULL) == -1 && errno == EINVAL);
    assert(open_calls == 0 && close_calls == 0);

    for (int fd = 0; fd < 9; ++fd) {
        reset_fixture();
        missing_fd = fd;
        error = expect(RNR_STAGE0_ADMISSION_INPUT, 0);
        assert(error.system_errno == EBADF && open_calls == 0);
    }
    reset_fixture();
    flags_fixture[0] = O_PATH;
    expect(RNR_STAGE0_ADMISSION_STDIO, 0);
    reset_fixture();
    flags_fixture[0] = O_WRONLY;
    expect(RNR_STAGE0_ADMISSION_STDIO, 0);
    reset_fixture();
    flags_fixture[1] = O_RDONLY;
    expect(RNR_STAGE0_ADMISSION_STDIO, 0);
    reset_fixture();
    descriptors[0].st_mode = S_IFSOCK | 0600;
    expect(RNR_STAGE0_ADMISSION_STDIO, 0);
    reset_fixture();
    descriptors[2].st_mode = S_IFCHR | 0600;
    descriptors[2].st_rdev = null_fixture.st_rdev + 1;
    expect(RNR_STAGE0_ADMISSION_STDIO, 0);
    reset_fixture();
    fcntl_error_fd = 1;
    error = expect(RNR_STAGE0_ADMISSION_STDIO, 0);
    assert(error.system_errno == EIO);
    reset_fixture();
    null_error = ENOENT;
    error = expect(RNR_STAGE0_ADMISSION_STDIO, 0);
    assert(error.system_errno == ENOENT);
    reset_fixture();
    null_regular = 1;
    expect(RNR_STAGE0_ADMISSION_STDIO, 0);

    reset_fixture();
    open_error = EACCES;
    error = expect(RNR_STAGE0_ADMISSION_OPEN, 0);
    assert(error.system_errno == EACCES);
    reset_fixture();
    missing_fd = OWNED_FD;
    error = expect(RNR_STAGE0_ADMISSION_DIRECTORY, 1);
    assert(error.system_errno == EBADF);
    reset_fixture();
    descriptors[OWNED_FD].st_mode = S_IFREG | 0600;
    expect(RNR_STAGE0_ADMISSION_DIRECTORY, 1);
    reset_fixture();
    read_error = EINTR;
    error = expect(RNR_STAGE0_ADMISSION_READ, 1);
    assert(error.system_errno == EINTR && read_calls == 1);

    for (size_t i = 0; i < sizeof(bad_names) / sizeof(bad_names[0]); ++i) {
        reset_fixture();
        payload_size = 0;
        append_name(bad_names[i]);
        expect(RNR_STAGE0_ADMISSION_RECORD, 1);
    }
    reset_fixture();
    payload_size = 0; /* premature EOF */
    expect(RNR_STAGE0_ADMISSION_INVENTORY, 1);
    reset_fixture();
    payload_size -= 24; /* own enumeration FD omitted */
    expect(RNR_STAGE0_ADMISSION_INVENTORY, 1);
    reset_fixture();
    last = payload_size - 24;
    payload[last + 19] = '8';
    payload[last + 20] = 0; /* duplicate required FD */
    expect(RNR_STAGE0_ADMISSION_INVENTORY, 1);
    reset_fixture();
    payload[payload_size - 24 + 20] = '1'; /* unexpected51; caller never closed */
    expect(RNR_STAGE0_ADMISSION_INVENTORY, 1);
    reset_fixture();
    append_name("51"); /* exceeds total record bound */
    expect(RNR_STAGE0_ADMISSION_RECORD, 1);
    reset_fixture();
    payload[24 + 20] = 0; /* second dot entry, rather than dot-dot */
    expect(RNR_STAGE0_ADMISSION_RECORD, 1);

    reset_fixture();
    short_record = 0;
    memcpy(payload + 16, &short_record, sizeof(short_record));
    expect(RNR_STAGE0_ADMISSION_RECORD, 1);
    reset_fixture();
    short_record = 16;
    memcpy(payload + 16, &short_record, sizeof(short_record));
    expect(RNR_STAGE0_ADMISSION_RECORD, 1);
    reset_fixture();
    short_record = 25; /* unaligned record */
    memcpy(payload + 16, &short_record, sizeof(short_record));
    expect(RNR_STAGE0_ADMISSION_RECORD, 1);
    reset_fixture();
    short_record = 4096; /* extends beyond actual response */
    memcpy(payload + 16, &short_record, sizeof(short_record));
    expect(RNR_STAGE0_ADMISSION_RECORD, 1);
    reset_fixture();
    memset(payload + 19, 'x', 5); /* no NUL within first record */
    expect(RNR_STAGE0_ADMISSION_RECORD, 1);
    reset_fixture();
    payload_size = 18;
    expect(RNR_STAGE0_ADMISSION_RECORD, 1);
    reset_fixture();
    oversized_read = 1;
    expect(RNR_STAGE0_ADMISSION_RECORD, 1);

    for (int fd = 0; fd <= 9; ++fd) {
        for (int at = 2; at <= 3; ++at) {
            reset_fixture();
            changed_fd = fd == 9 ? OWNED_FD : fd;
            changed_at = at;
            expect(RNR_STAGE0_ADMISSION_IDENTITY, 1);
        }
    }
    reset_fixture();
    close_error = EINTR;
    error = expect(RNR_STAGE0_ADMISSION_CLEANUP, 1);
    assert(error.system_errno == EINTR && error.cleanup_errno == EINTR);
    reset_fixture();
    read_error = EIO;
    close_error = EINTR;
    error = expect(RNR_STAGE0_ADMISSION_READ, 1);
    assert(error.system_errno == EIO && error.cleanup_errno == EINTR);
    preparation_admission();
    return 0;
}
