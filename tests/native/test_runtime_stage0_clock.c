/* Fixture test SOURCE. Compile-only until this exact artifact is authorized. */
#define _GNU_SOURCE
#ifdef NDEBUG
#error "Clock fixtures require active assertions"
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "../../automation/native/runtime_stage0_clock.h"

static int fake_open(const char *, int);
static ssize_t fake_read(int, void *, size_t);
static int fake_close(int);
static int fake_stat(const char *, struct stat *);
static int fake_time(clockid_t, struct timespec *);
static pid_t fake_pid(void);
static pid_t fake_tid(void);
static int fake_admission(struct rnr_stage0_admission_error *);
#define open(p, f) fake_open(p, f)
#define read(f, b, n) fake_read(f, b, n)
#define close(f) fake_close(f)
#define stat(p, s) fake_stat(p, s)
#define clock_gettime(c, t) fake_time(c, t)
#define getpid() fake_pid()
#define gettid() fake_tid()
#define rnr_stage0_admit_initial_fds(e) fake_admission(e)
#include "../../automation/native/runtime_stage0_clock.c"
#undef open
#undef read
#undef close
#undef stat
#undef clock_gettime
#undef getpid
#undef gettid
#undef rnr_stage0_admit_initial_fds

static int64_t boot, wall;
static int opened, closed, reads, identity_calls, namespace_drift;
static int read_error, close_error, short_read, extra_read, bad_uuid, bad_time;
static int open_error, namespace_error, time_error, second_extra;
static int admission_calls, admission_failure, after_advance, after_close_error;
static pid_t owner, thread;
static void reset(void)
{
    boot = 1000000000000LL; wall = 1700000000000000000LL;
    opened = closed = reads = identity_calls = namespace_drift = 0;
    read_error = close_error = short_read = extra_read = bad_uuid = bad_time = 0;
    open_error = namespace_error = time_error = second_extra = 0;
    admission_calls = admission_failure = after_advance = after_close_error = 0;
    owner = thread = 100;
}
static int fake_open(const char *path, int flags)
{
    assert(strcmp(path, "/proc/sys/kernel/random/boot_id") == 0);
    assert(flags == (O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
    if (open_error) { errno = open_error; return -1; }
    ++opened; reads = 0; return 50;
}
static ssize_t fake_read(int fd, void *buffer, size_t size)
{
    static const char uuid[] = "12345678-1234-1234-1234-123456789abc\n!";
    assert(fd == 50);
    if (read_error) { errno = read_error; return -1; }
    if (reads++ != 0) { assert(size == 1); return second_extra ? 1 : 0; }
    assert(size == 38);
    memcpy(buffer, uuid, 38);
    if (bad_uuid) ((char *)buffer)[0] = 'G';
    return short_read ? 36 : extra_read ? 38 : 37;
}
static int fake_close(int fd)
{
    assert(fd == 50); ++closed;
    if (close_error) { errno = close_error; return -1; }
    return 0;
}
static int fake_stat(const char *path, struct stat *info)
{
    assert(strcmp(path, "/proc/thread-self/ns/time") == 0);
    if (namespace_error) { errno = namespace_error; return -1; }
    memset(info, 0, sizeof(*info));
    info->st_dev = 1; info->st_ino = 2;
    if (++identity_calls == 2 && namespace_drift) ++info->st_ino;
    return 0;
}
static int fake_time(clockid_t kind, struct timespec *value)
{
    int64_t sample = kind == CLOCK_BOOTTIME ? boot : wall;
    assert(kind == CLOCK_BOOTTIME || kind == CLOCK_REALTIME);
    if (time_error) { errno = time_error; return -1; }
    value->tv_sec = sample / 1000000000;
    value->tv_nsec = bad_time ? 1000000000 : sample % 1000000000;
    return 0;
}
static pid_t fake_pid(void) { return owner; }
static pid_t fake_tid(void) { return thread; }
static int fake_admission(struct rnr_stage0_admission_error *error)
{
    ++admission_calls;
    *error = (struct rnr_stage0_admission_error){0};
    if (after_advance) boot += 15000000000LL;
    if (after_close_error) close_error = EINTR;
    if (admission_failure) {
        error->code = RNR_STAGE0_ADMISSION_READ;
        error->system_errno = EIO; error->cleanup_errno = EINTR;
        return -1;
    }
    return 0;
}
static struct rnr_stage0_clock active(void)
{
    struct rnr_stage0_clock state = {0};
    struct rnr_stage0_clock_error error;
    assert(rnr_stage0_clock_capture(&state, wall + 90000000000LL, &error) == 0);
    assert(state.setup_end_ns == 1015000000000LL);
    assert(state.deadline_boottime_ns == 1090000000000LL);
    assert(opened == 2 && closed == 2);
    return state;
}
/* New two-phase cases use only mocked identities and clock samples. */
static struct rnr_stage0_clock prepared(void)
{
    struct rnr_stage0_clock state = {0};
    struct rnr_stage0_clock_error error;
    assert(rnr_stage0_clock_prepare(&state, &error) == 0);
    assert(state.phase == RNR_STAGE0_CLOCK_PREPARING);
    assert(state.captured_boottime_ns == boot && state.sampled_wall_ns == wall);
    assert(state.setup_end_ns == boot + 15000000000LL);
    assert(state.deadline_boottime_ns == boot + 120000000000LL);
    assert(state.wall_deadline_ns == wall + 120000000000LL);
    assert(opened == 2 && closed == 2);
    return state;
}
static void preparation_regressions(void)
{
    struct rnr_stage0_clock state;
    struct rnr_stage0_clock_error error;
    struct rnr_stage0_clock_admission_result result;
    int64_t origin_boot, origin_wall;
    reset(); state = prepared(); origin_boot = boot; origin_wall = wall;
    boot += 3000000000LL; wall += 4000000000LL;
    assert(rnr_stage0_clock_check_setup(&state, &error) == 0);
    assert(rnr_stage0_clock_bind_cutoff(&state, origin_wall + 90000000000LL, &error) == 0);
    assert(state.phase == RNR_STAGE0_CLOCK_ACTIVE);
    assert(state.captured_boottime_ns == origin_boot && state.sampled_wall_ns == origin_wall);
    assert(state.last_boottime_ns == boot && state.last_wall_ns == wall);
    assert(state.setup_end_ns == origin_boot + 15000000000LL);
    assert(state.deadline_boottime_ns == origin_boot + 90000000000LL);
    --wall;
    assert(rnr_stage0_clock_check_setup(&state, &error) == -1);
    assert(error.code == RNR_STAGE0_CLOCK_CUTOFF && state.phase == RNR_STAGE0_CLOCK_FAILED);

    reset(); state = prepared(); origin_boot = boot; origin_wall = wall;
    boot += 2000000000LL; wall += 2000000000LL;
    assert(rnr_stage0_clock_bind_cutoff(&state, origin_wall + 8000000000LL, &error) == 0);
    assert(state.setup_end_ns == origin_boot + 8000000000LL);
    assert(state.deadline_boottime_ns == origin_boot + 8000000000LL);
    boot = origin_boot + 8000000000LL;
    assert(rnr_stage0_clock_check_setup(&state, &error) == -1);
    assert(error.code == RNR_STAGE0_CLOCK_CUTOFF);

    for (int scenario = 0; scenario < 6; ++scenario) {
        int64_t deadline;
        reset(); state = prepared(); origin_wall = wall;
        boot += 1000000000LL; wall += 2000000000LL;
        deadline = scenario == 0 ? 0 : scenario == 1 ? -1 :
            scenario == 2 ? origin_wall : scenario == 3 ? wall :
            scenario == 4 ? origin_wall + 120000000001LL : INT64_MAX;
        assert(rnr_stage0_clock_bind_cutoff(&state, deadline, &error) == -1);
        assert(error.code == RNR_STAGE0_CLOCK_RANGE && state.phase == RNR_STAGE0_CLOCK_FAILED);
        assert(opened == closed && admission_calls == 0);
    }
    for (int overflow = 0; overflow < 2; ++overflow) {
        reset(); memset(&state, 0, sizeof(state));
        if (overflow) boot = INT64_MAX - 120000000000LL + 1;
        else wall = INT64_MAX - 120000000000LL + 1;
        assert(rnr_stage0_clock_prepare(&state, &error) == -1);
        assert(error.code == RNR_STAGE0_CLOCK_RANGE && state.phase == RNR_STAGE0_CLOCK_FAILED);
        assert(opened == closed);
    }
    reset(); state = prepared(); origin_wall = wall;
    boot += 15000000000LL;
    assert(rnr_stage0_clock_bind_cutoff(&state, origin_wall + 90000000000LL, &error) == -1);
    assert(error.code == RNR_STAGE0_CLOCK_CUTOFF && admission_calls == 0);
    assert(state.phase == RNR_STAGE0_CLOCK_FAILED);

    /* Shortening below elapsed boot time must fail in the post-bind check. */
    reset(); state = prepared(); origin_wall = wall;
    boot += 10000000000LL; wall += 1000000000LL;
    assert(rnr_stage0_clock_bind_cutoff(&state, origin_wall + 8000000000LL, &error) == -1);
    assert(error.code == RNR_STAGE0_CLOCK_CUTOFF && state.phase == RNR_STAGE0_CLOCK_FAILED);

    reset(); state = prepared(); origin_wall = wall;
    assert(rnr_stage0_clock_bind_cutoff(&state, origin_wall + 90000000000LL, &error) == 0);
    assert(rnr_stage0_clock_bind_cutoff(&state, origin_wall + 100000000000LL, &error) == -1);
    assert(error.code == RNR_STAGE0_CLOCK_STATE && state.phase == RNR_STAGE0_CLOCK_FAILED);
    assert(state.wall_deadline_ns == origin_wall + 90000000000LL);

    reset(); state = prepared();
    assert(rnr_stage0_admit_with_clock(&state, &result) == -1);
    assert(result.before.code == RNR_STAGE0_CLOCK_STATE && !result.admission_called);
    assert(admission_calls == 0 && state.phase == RNR_STAGE0_CLOCK_FAILED);
    reset(); state = prepared(); --boot;
    assert(rnr_stage0_clock_bind_cutoff(&state, wall + 90000000000LL, &error) == -1);
    assert(error.code == RNR_STAGE0_CLOCK_CUTOFF);
    reset(); state = prepared(); owner = thread = 101;
    assert(rnr_stage0_clock_bind_cutoff(&state, wall + 90000000000LL, &error) == -1);
    assert(error.code == RNR_STAGE0_CLOCK_IDENTITY);
}
int main(void)
{
    struct rnr_stage0_clock state;
    struct rnr_stage0_clock_error error;
    struct rnr_stage0_clock_admission_result result;
    reset(); state = active();
    boot += 1; wall += 2;
    assert(rnr_stage0_clock_check_setup(&state, &error) == 0);
    assert(state.last_boottime_ns == 1000000000001LL && state.last_wall_ns == 1700000000000000002LL);
    --wall;
    assert(rnr_stage0_clock_check_setup(&state, &error) == -1);
    assert(error.code == RNR_STAGE0_CLOCK_CUTOFF && state.phase == RNR_STAGE0_CLOCK_FAILED);
    wall += 100;
    assert(rnr_stage0_clock_check_setup(&state, &error) == -1);

    reset(); state = active();
    assert(rnr_stage0_clock_capture(&state, wall + 90000000000LL, &error) == -1);
    assert(state.phase == RNR_STAGE0_CLOCK_FAILED);
    reset(); state = active(); boot += 15000000000LL;
    assert(rnr_stage0_clock_check_setup(&state, &error) == -1);
    reset(); state = active(); --boot;
    assert(rnr_stage0_clock_check_setup(&state, &error) == -1);
    reset(); state = active(); owner = thread = 101;
    assert(rnr_stage0_clock_check_setup(&state, &error) == -1);
    assert(error.code == RNR_STAGE0_CLOCK_IDENTITY);

    for (int scenario = 0; scenario < 14; ++scenario) {
        int64_t deadline;
        reset(); memset(&state, 0, sizeof(state)); deadline = wall + 90000000000LL;
        if (scenario == 0) short_read = 1;
        if (scenario == 1) extra_read = 1;
        if (scenario == 2) bad_uuid = 1;
        if (scenario == 3) { read_error = EIO; close_error = EINTR; }
        if (scenario == 4) close_error = EINTR;
        if (scenario == 5) namespace_drift = 1;
        if (scenario == 6) bad_time = 1;
        if (scenario == 7) deadline = wall;
        if (scenario == 8) deadline = wall + 120000000001LL;
        if (scenario == 9) boot = INT64_MAX - 1;
        if (scenario == 10) open_error = EACCES;
        if (scenario == 11) namespace_error = ENOENT;
        if (scenario == 12) time_error = EIO;
        if (scenario == 13) second_extra = 1;
        assert(rnr_stage0_clock_capture(&state, deadline, &error) == -1);
        assert(state.phase == RNR_STAGE0_CLOCK_FAILED && closed == opened);
        if (scenario == 3) assert(error.system_errno == EIO && error.cleanup_errno == EINTR);
        assert(rnr_stage0_clock_capture(&state, deadline, &error) == -1);
    }
    reset(); state = active();
    assert(rnr_stage0_admit_with_clock(&state, &result) == 0);
    assert(result.admission_called && admission_calls == 1);
    assert(rnr_stage0_admit_with_clock(&state, &result) == -1 && admission_calls == 1);
    assert(state.phase == RNR_STAGE0_CLOCK_FAILED);
    reset(); state = active(); boot += 15000000000LL;
    assert(rnr_stage0_admit_with_clock(&state, &result) == -1 && admission_calls == 0);
    reset(); state = active(); after_advance = 1;
    assert(rnr_stage0_admit_with_clock(&state, &result) == -1);
    assert(result.admission_called && result.admission.code == RNR_STAGE0_ADMISSION_OK);
    assert(result.after.code == RNR_STAGE0_CLOCK_CUTOFF && state.phase == RNR_STAGE0_CLOCK_FAILED);
    reset(); state = active(); admission_failure = 1;
    assert(rnr_stage0_admit_with_clock(&state, &result) == -1);
    assert(result.admission.code == RNR_STAGE0_ADMISSION_READ && result.after.code == RNR_STAGE0_CLOCK_OK);
    assert(result.admission.system_errno == EIO && result.admission.cleanup_errno == EINTR);
    assert(state.phase == RNR_STAGE0_CLOCK_FAILED);
    for (int cleanup = 0; cleanup <= 1; ++cleanup) {
        reset(); state = active(); admission_failure = 1;
        after_advance = !cleanup; after_close_error = cleanup;
        assert(rnr_stage0_admit_with_clock(&state, &result) == -1);
        assert(result.admission_called && admission_calls == 1);
        assert(result.admission.code == RNR_STAGE0_ADMISSION_READ);
        assert(result.admission.system_errno == EIO && result.admission.cleanup_errno == EINTR);
        assert(result.after.code == (cleanup ? RNR_STAGE0_CLOCK_CLEANUP : RNR_STAGE0_CLOCK_CUTOFF));
        if (cleanup) assert(result.after.cleanup_errno == EINTR);
        assert(state.phase == RNR_STAGE0_CLOCK_FAILED && opened == closed);
    }
    preparation_regressions();
    return 0;
}
