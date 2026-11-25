/* Dormant original-clock prerequisite. No main/exec/Store/root operation. */
#define _GNU_SOURCE
#include "runtime_stage0_clock.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#ifdef RNR_STAGE0_PRIVATE_QUALIFICATION
#include <poll.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <stdatomic.h>
#if RNR_STAGE0_PRIVATE_QUALIFICATION != 1
#error "RNR_STAGE0_PRIVATE_QUALIFICATION must be exactly 1"
#endif
#endif

#if !defined(__linux__) || !defined(__x86_64__)
#error "Native clock preparation supports Linux x86_64 only"
#endif
#define NS 1000000000LL
#define SETUP (15 * NS)
#define MAX_WINDOW (120 * NS)

struct clock_identity {
    pid_t pid, tid;
    char boot_id[37];
    uint64_t device, inode;
};
static void reject_clock(struct rnr_stage0_clock_error *error,
                         enum rnr_stage0_clock_code code, int system_errno)
{
    if (error->code == RNR_STAGE0_CLOCK_OK) {
        error->code = code; error->system_errno = system_errno;
    }
}
static int acquire_identity(struct clock_identity *identity,
                            struct rnr_stage0_clock_error *error)
{
    char raw[38], extra;
    struct stat info;
    int fd = -1;
    ssize_t amount;
    identity->pid = getpid(); identity->tid = gettid();
    if (identity->pid <= 0 || identity->tid != identity->pid) {
        reject_clock(error, RNR_STAGE0_CLOCK_OWNER, 0); return -1;
    }
    fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        reject_clock(error, RNR_STAGE0_CLOCK_BOOT, errno); return -1;
    }
    amount = read(fd, raw, sizeof(raw));
    if (amount < 0) { reject_clock(error, RNR_STAGE0_CLOCK_BOOT, errno); goto cleanup; }
    if (amount != 37 || raw[36] != '\n') {
        reject_clock(error, RNR_STAGE0_CLOCK_BOOT, 0); goto cleanup;
    }
    for (int i = 0; i < 36; ++i) {
        int separator = i == 8 || i == 13 || i == 18 || i == 23;
        if (separator ? raw[i] != '-' :
            !((raw[i] >= '0' && raw[i] <= '9') || (raw[i] >= 'a' && raw[i] <= 'f'))) {
            reject_clock(error, RNR_STAGE0_CLOCK_BOOT, 0); goto cleanup;
        }
    }
    amount = read(fd, &extra, 1);
    if (amount < 0) { reject_clock(error, RNR_STAGE0_CLOCK_BOOT, errno); goto cleanup; }
    if (amount != 0) { reject_clock(error, RNR_STAGE0_CLOCK_BOOT, 0); goto cleanup; }
    memcpy(identity->boot_id, raw, 36); identity->boot_id[36] = 0;
cleanup:
    {
        int owned = fd; fd = -1;
        if (close(owned) != 0) {
            int failure = errno;
            error->cleanup_errno = failure;
            reject_clock(error, RNR_STAGE0_CLOCK_CLEANUP, failure);
        }
    }
    if (error->code != RNR_STAGE0_CLOCK_OK) return -1;
    /* Namespace links are intentionally followed in the trusted proc view. */
    if (stat("/proc/thread-self/ns/time", &info) != 0) {
        reject_clock(error, RNR_STAGE0_CLOCK_NAMESPACE, errno); return -1;
    }
    if ((uintmax_t)info.st_dev == 0 || (uintmax_t)info.st_dev > INT64_MAX ||
        (uintmax_t)info.st_ino == 0 || (uintmax_t)info.st_ino > INT64_MAX) {
        reject_clock(error, RNR_STAGE0_CLOCK_NAMESPACE, 0); return -1;
    }
    identity->device = (uint64_t)info.st_dev; identity->inode = (uint64_t)info.st_ino;
    if (getpid() != identity->pid || gettid() != identity->tid) {
        reject_clock(error, RNR_STAGE0_CLOCK_OWNER, 0); return -1;
    }
    return 0;
}
static int same_clock_identity(const struct clock_identity *a, const struct clock_identity *b)
{
    return a->pid == b->pid && a->tid == b->tid && a->device == b->device &&
           a->inode == b->inode && memcmp(a->boot_id, b->boot_id, 37) == 0;
}
static int sample_clock(clockid_t kind, int64_t *sample,
                        struct rnr_stage0_clock_error *error)
{
    struct timespec value;
    if (clock_gettime(kind, &value) != 0) {
        reject_clock(error, RNR_STAGE0_CLOCK_SAMPLE, errno); return -1;
    }
    if (value.tv_sec < 0 || (uintmax_t)value.tv_sec > INT64_MAX / NS ||
        value.tv_nsec < 0 || value.tv_nsec >= NS ||
        (int64_t)value.tv_sec * NS > INT64_MAX - value.tv_nsec) {
        reject_clock(error, RNR_STAGE0_CLOCK_RANGE, 0); return -1;
    }
    *sample = (int64_t)value.tv_sec * NS + value.tv_nsec;
    if (*sample <= 0) { reject_clock(error, RNR_STAGE0_CLOCK_RANGE, 0); return -1; }
    return 0;
}
static int terminal(struct rnr_stage0_clock *state)
{
    if (state != NULL) state->phase = RNR_STAGE0_CLOCK_FAILED;
    return -1;
}
static int capture_clock(struct rnr_stage0_clock *state, int64_t deadline, int preparing,
                            struct rnr_stage0_clock_error *error)
{
    struct clock_identity first, last;
    int64_t boot, wall, delta;
    if (state == NULL || error == NULL) { errno = EINVAL; return terminal(state); }
    *error = (struct rnr_stage0_clock_error){0};
    if (state->phase != RNR_STAGE0_CLOCK_UNINITIALIZED || state->admission_attempted != 0 ||
        state->fork_attempted != 0 || state->cutoff_bound != 0) {
        reject_clock(error, RNR_STAGE0_CLOCK_STATE, 0); return terminal(state);
    }
    /* Reserve capture irreversibly before fallible acquisition. */
    state->phase = RNR_STAGE0_CLOCK_FAILED;
    if (acquire_identity(&first, error) != 0 ||
        sample_clock(CLOCK_BOOTTIME, &boot, error) != 0 ||
        sample_clock(CLOCK_REALTIME, &wall, error) != 0 ||
        acquire_identity(&last, error) != 0) return -1;
    if (!same_clock_identity(&first, &last)) {
        reject_clock(error, RNR_STAGE0_CLOCK_IDENTITY, 0); return -1;
    }
    if (preparing) {
        if (wall > INT64_MAX - MAX_WINDOW) {
            reject_clock(error, RNR_STAGE0_CLOCK_RANGE, 0); return -1;
        }
        deadline = wall + MAX_WINDOW;
    }
    if (deadline <= wall) { reject_clock(error, RNR_STAGE0_CLOCK_RANGE, 0); return -1; }
    delta = deadline - wall; /* both positive signed64, no subtraction overflow */
    if (delta > MAX_WINDOW || boot > INT64_MAX - delta) {
        reject_clock(error, RNR_STAGE0_CLOCK_RANGE, 0); return -1;
    }
    state->pid = first.pid; state->tid = first.tid;
    memcpy(state->boot_id, first.boot_id, 37);
    state->time_ns_device = first.device; state->time_ns_inode = first.inode;
    state->captured_boottime_ns = state->last_boottime_ns = boot;
    state->sampled_wall_ns = state->last_wall_ns = wall;
    state->wall_deadline_ns = deadline; state->deadline_boottime_ns = boot + delta;
    state->setup_end_ns = boot + (delta < SETUP ? delta : SETUP);
    state->cutoff_bound = !preparing;
    state->phase = preparing ? RNR_STAGE0_CLOCK_PREPARING : RNR_STAGE0_CLOCK_ACTIVE;
    return 0;
}
int rnr_stage0_clock_capture(struct rnr_stage0_clock *state, int64_t deadline,
                            struct rnr_stage0_clock_error *error)
{
    return capture_clock(state, deadline, 0, error);
}
int rnr_stage0_clock_prepare(struct rnr_stage0_clock *state,
                            struct rnr_stage0_clock_error *error)
{
    return capture_clock(state, 0, 1, error);
}
int rnr_stage0_clock_bind_cutoff(struct rnr_stage0_clock *state, int64_t deadline,
                                struct rnr_stage0_clock_error *error)
{
    if (state == NULL || error == NULL) { errno = EINVAL; return terminal(state); }
    *error = (struct rnr_stage0_clock_error){0};
    if ((state->phase != RNR_STAGE0_CLOCK_PREPARING &&
         state->phase != RNR_STAGE0_CLOCK_ADMISSION) ||
        state->admission_attempted != 0 || state->cutoff_bound != 0) {
        reject_clock(error, RNR_STAGE0_CLOCK_STATE, 0); return terminal(state);
    }
    int held = state->phase == RNR_STAGE0_CLOCK_ADMISSION;
    /* Reserve the one narrowing before fallible sampling. Admission stays
     * held even after successful binding; only verified placement/GO may
     * eventually permit the fixed positive continuation. */
    state->cutoff_bound = 1;
    if (rnr_stage0_clock_check_setup(state, error) != 0) return -1;
    if (deadline <= state->last_wall_ns || deadline > state->wall_deadline_ns) {
        reject_clock(error, RNR_STAGE0_CLOCK_RANGE, 0); return terminal(state);
    }
    int64_t delta = deadline - state->sampled_wall_ns;
    state->wall_deadline_ns = deadline;
    state->deadline_boottime_ns = state->captured_boottime_ns + delta;
    state->setup_end_ns = state->captured_boottime_ns + (delta < SETUP ? delta : SETUP);
    state->phase = held ? RNR_STAGE0_CLOCK_ADMISSION : RNR_STAGE0_CLOCK_ACTIVE;
    return rnr_stage0_clock_check_setup(state, error);
}
static int sample_owned_clock(struct rnr_stage0_clock *state,
                               struct rnr_stage0_clock_error *error)
{
    struct clock_identity first, last, expected;
    int64_t boot, wall;
    if (state == NULL || error == NULL) { errno = EINVAL; return terminal(state); }
    *error = (struct rnr_stage0_clock_error){0};
    expected.pid = state->pid; expected.tid = state->tid;
    expected.device = state->time_ns_device; expected.inode = state->time_ns_inode;
    memcpy(expected.boot_id, state->boot_id, 37);
    if (acquire_identity(&first, error) != 0) return terminal(state);
    if (!same_clock_identity(&expected, &first)) {
        reject_clock(error, RNR_STAGE0_CLOCK_IDENTITY, 0); return terminal(state);
    }
    if (sample_clock(CLOCK_BOOTTIME, &boot, error) != 0 ||
        sample_clock(CLOCK_REALTIME, &wall, error) != 0 ||
        acquire_identity(&last, error) != 0) return terminal(state);
    if (!same_clock_identity(&expected, &last)) {
        reject_clock(error, RNR_STAGE0_CLOCK_IDENTITY, 0); return terminal(state);
    }
    if (boot < state->last_boottime_ns || wall < state->last_wall_ns) {
        reject_clock(error, RNR_STAGE0_CLOCK_CUTOFF, 0); return terminal(state);
    }
    state->last_boottime_ns = boot; state->last_wall_ns = wall;
    return 0;
}
static int check_setup_samples(struct rnr_stage0_clock *state,
                                struct rnr_stage0_clock_error *error)
{
    if (sample_owned_clock(state, error) != 0) return -1;
    if (state->last_boottime_ns >= state->setup_end_ns ||
        state->last_boottime_ns >= state->deadline_boottime_ns ||
        state->last_wall_ns >= state->wall_deadline_ns) {
        reject_clock(error, RNR_STAGE0_CLOCK_CUTOFF, 0); return terminal(state);
    }
    return 0;
}
int rnr_stage0_clock_check_setup(struct rnr_stage0_clock *state,
                                struct rnr_stage0_clock_error *error)
{
    if (state == NULL || error == NULL) { errno = EINVAL; return terminal(state); }
    *error = (struct rnr_stage0_clock_error){0};
    if (state->phase != RNR_STAGE0_CLOCK_ACTIVE && state->phase != RNR_STAGE0_CLOCK_PREPARING &&
        state->phase != RNR_STAGE0_CLOCK_ADMISSION) {
        reject_clock(error, RNR_STAGE0_CLOCK_STATE, 0); return terminal(state);
    }
    return check_setup_samples(state,error);
}
int rnr_stage0_admit_with_clock(struct rnr_stage0_clock *state,
                               struct rnr_stage0_clock_admission_result *result)
{
    if (state == NULL || result == NULL) { errno = EINVAL; return terminal(state); }
    *result = (struct rnr_stage0_clock_admission_result){0};
    if (state->phase != RNR_STAGE0_CLOCK_ACTIVE || state->admission_attempted != 0) {
        reject_clock(&result->before, RNR_STAGE0_CLOCK_STATE, 0); return terminal(state);
    }
    state->admission_attempted = 1;
    if (rnr_stage0_clock_check_setup(state, &result->before) != 0) return -1;
    result->admission_called = 1;
    result->admission_result = rnr_stage0_admit_initial_fds(&result->admission);
    /* Preserve admission code/system/cleanup errors even when postcheck fails. */
    if (rnr_stage0_clock_check_setup(state, &result->after) != 0) return -1;
    if (result->admission_result != 0 || result->admission.code != RNR_STAGE0_ADMISSION_OK)
        return terminal(state);
    return 0;
}

#ifdef RNR_STAGE0_PRIVATE_QUALIFICATION
/* Private fork gate; deliberately no production GO path yet. The future keeper
 * must acquire/verify the positive cgroup and negative controls before GO.
 * No pointer/PID/FD from a caller selects this channel or its peer. */
static atomic_int fork_reserved = ATOMIC_VAR_INIT(0);
static int fork_parent_gate = -1;
static pid_t fork_parent_pid;
static struct rnr_stage0_clock *fork_parent_clock;
static struct rnr_stage0_fork_result *fork_parent_result;
static int fork_admission_route, fork_single_owner;
static int fork_child_gate=-1;
static pid_t fork_child_parent;
static struct rnr_stage0_clock *fork_child_clock;
static struct rnr_stage0_fork_result *fork_child_result;

/* Trusted immutable no-thread/no-reaper launch is a source prerequisite.
 * Observe the kernel's thread count before fork; refuse unknown/truncation.
 * No caller selector, arbitrary path or thread-discovery callback. */
static int admission_single_owner(struct rnr_stage0_clock_error *error)
{
    char raw[16384], extra; int count=0;
    int fd=open("/proc/self/status",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0){reject_clock(error,RNR_STAGE0_CLOCK_OWNER,errno);return -1;}
    ssize_t n=read(fd,raw,sizeof(raw));
    int failure=n<0?errno:0;
    if(n>0 && n<(ssize_t)sizeof(raw)){
        ssize_t tail=read(fd,&extra,1);
        if(tail!=0){failure=tail<0?errno:0;n=-1;}
    }else n=-1;
    if(close(fd)!=0){error->cleanup_errno=errno;reject_clock(error,RNR_STAGE0_CLOCK_CLEANUP,errno);return -1;}
    if(n<=0){reject_clock(error,RNR_STAGE0_CLOCK_OWNER,failure);return -1;}
    for(ssize_t at=0;at<n;){
        ssize_t end=at;while(end<n&&raw[end]!='\n')++end;
        if(end==n){reject_clock(error,RNR_STAGE0_CLOCK_OWNER,0);return -1;}
        if(end-at>=8&&!memcmp(raw+at,"Threads:",8)){
            ssize_t value=at+8;
            while(value<end&&(raw[value]==' '||raw[value]=='\t'))++value;
            if(value+1!=end||raw[value]!='1'){reject_clock(error,RNR_STAGE0_CLOCK_OWNER,0);return -1;}
            ++count;
        }
        at=end+1;
    }
    if(count!=1||getpid()!=gettid()){reject_clock(error,RNR_STAGE0_CLOCK_OWNER,0);return -1;}
    return 0;
}
static int negative_admission_sample(struct rnr_stage0_clock *state,
                                     struct rnr_stage0_clock_error *error)
{
    if(state->phase!=RNR_STAGE0_CLOCK_NEGATIVE)return -1;
    if(sample_owned_clock(state,error)!=0)return -1;
    if(state->captured_boottime_ns<=0||state->captured_boottime_ns>INT64_MAX-90*NS){
        reject_clock(error,RNR_STAGE0_CLOCK_RANGE,0);return terminal(state);
    }
    int64_t stop=state->captured_boottime_ns+90*NS;
    if(state->deadline_boottime_ns<stop)stop=state->deadline_boottime_ns;
    if(state->last_boottime_ns>=stop||state->last_wall_ns>=state->wall_deadline_ns){
        reject_clock(error,RNR_STAGE0_CLOCK_CUTOFF,0);return terminal(state);
    }
    return 0;
}
/* Positive setup expiration is not negative expiry. Never restore state after
 * sample_owned_clock has invalidated identity/high-water/negative ownership. */
static int fork_setup_sample(struct rnr_stage0_clock *state,
                              struct rnr_stage0_clock_error *error)
{
    if(!fork_admission_route||state->phase!=RNR_STAGE0_CLOCK_NEGATIVE)
        return check_setup_samples(state,error);
    if(negative_admission_sample(state,error)!=0)return -1;
    if(state->last_boottime_ns>=state->setup_end_ns){
        reject_clock(error,RNR_STAGE0_CLOCK_CUTOFF,0);return -1;
    }
    return 0;
}

static int keeper_owner(struct rnr_stage0_clock *state)
{
    return state == fork_parent_clock && state != NULL &&
        state->phase == RNR_STAGE0_CLOCK_NEGATIVE &&
        fork_parent_pid == getpid() && gettid() == getpid() &&
        fork_parent_result != NULL && fork_parent_result->child_armed == 1 &&
        fork_parent_result->child_pid > 0 && fork_parent_result->child_pidfd >= 3;
}
int rnr_stage0_clock_check_keeper(struct rnr_stage0_clock *state,
                                 struct rnr_stage0_keeper_tick *tick,
                                 struct rnr_stage0_clock_error *error)
{
    if (tick != NULL) *tick = (struct rnr_stage0_keeper_tick){0};
    if (state == NULL || tick == NULL || error == NULL) {
        errno = EINVAL; return terminal(state);
    }
    *error = (struct rnr_stage0_clock_error){0};
    if (!keeper_owner(state)) {
        reject_clock(error, RNR_STAGE0_CLOCK_OWNER, 0); return terminal(state);
    }
    if (state->captured_boottime_ns <= 0 ||
        state->captured_boottime_ns > INT64_MAX - 90 * NS) {
        reject_clock(error, RNR_STAGE0_CLOCK_RANGE, 0); return terminal(state);
    }
    tick->stop_ns = state->captured_boottime_ns + 90 * NS;
    if (state->deadline_boottime_ns < tick->stop_ns)
        tick->stop_ns = state->deadline_boottime_ns;
    tick->trigger_ns = state->captured_boottime_ns + 60 * NS;
    if (tick->trigger_ns > tick->stop_ns) tick->trigger_ns = tick->stop_ns;
    if (sample_owned_clock(state, error) != 0) return -1;
    if (state->last_boottime_ns >= tick->stop_ns ||
        state->last_wall_ns >= state->wall_deadline_ns) {
        reject_clock(error, RNR_STAGE0_CLOCK_CUTOFF, 0); return terminal(state);
    }
    tick->setup_expired = state->last_boottime_ns >= state->setup_end_ns;
    tick->trigger_due = state->last_boottime_ns >= tick->trigger_ns;
    return 0;
}
int rnr_stage0_clock_bind_keeper_cutoff(struct rnr_stage0_clock *state, int64_t cutoff,
                                       struct rnr_stage0_clock_error *error)
{
    struct rnr_stage0_keeper_tick tick;
    if (state == NULL || error == NULL) { errno = EINVAL; return terminal(state); }
    *error = (struct rnr_stage0_clock_error){0};
    if (!keeper_owner(state)) {
        reject_clock(error, RNR_STAGE0_CLOCK_OWNER, 0); return terminal(state);
    }
    if (state->cutoff_bound) {
        reject_clock(error, RNR_STAGE0_CLOCK_STATE, 0); return -1;
    }
    state->cutoff_bound = 1; /* consume before any sample or cutoff rejection */
    if (cutoff <= state->sampled_wall_ns || cutoff > state->wall_deadline_ns) {
        reject_clock(error, RNR_STAGE0_CLOCK_RANGE, 0); return -1;
    }
    int64_t delta = cutoff - state->sampled_wall_ns;
    state->wall_deadline_ns = cutoff;
    state->deadline_boottime_ns = state->captured_boottime_ns + delta;
    state->setup_end_ns = state->captured_boottime_ns + (delta < SETUP ? delta : SETUP);
    /* Never import the declaration's last samples: retain the keeper's floors. */
    if (rnr_stage0_clock_check_keeper(state, &tick, error) != 0) return -1;
    if (tick.setup_expired) {
        reject_clock(error, RNR_STAGE0_CLOCK_CUTOFF, 0); return -1;
    }
    /* No admission without a strict original60..stop containment interval.
     * Even a rejected short/late declaration retains its narrower bounds;
     * failure containment can never regain the prior longer lease. */
    if (tick.trigger_ns >= tick.stop_ns) {
        reject_clock(error, RNR_STAGE0_CLOCK_RANGE, 0); return -1;
    }
    return 0;
}

static int fork_close(int *slot,struct rnr_stage0_fork_result *result,
                       struct rnr_stage0_clock_error *error)
{
    int fd=*slot;*slot=-1;
    if(fd>=0 && close(fd)!=0){
        int failure=errno;
        if(result->cleanup_count<6){
            int index=result->cleanup_count++;
            result->cleanup_errors[index].fd=fd;
            result->cleanup_errors[index].system_errno=failure;
        }
        if(!error->cleanup_errno)error->cleanup_errno=failure;
        reject_clock(error,RNR_STAGE0_CLOCK_CLEANUP,failure);return -1;
    }
    return 0;
}
static int fork_parent_live(pid_t parent,struct rnr_stage0_clock_error *error)
{
    int installed=0;
    if(getppid()!=parent){reject_clock(error,RNR_STAGE0_CLOCK_OWNER,0);return -1;}
    if(prctl(PR_GET_PDEATHSIG,&installed,0UL,0UL,0UL)!=0){
        reject_clock(error,RNR_STAGE0_CLOCK_OWNER,errno);return -1;
    }
    if(installed!=SIGKILL || getppid()!=parent){
        reject_clock(error,RNR_STAGE0_CLOCK_OWNER,0);return -1;
    }
    return 0;
}
/* Initial admission packet only. Credentials bind the original direct fork
 * sender under the fixed immutable/root/no-injection launch assumptions; they
 * do not authenticate a declaration, executable or positive continuation. */
static int admission_sample_after(struct rnr_stage0_clock *state,
                                  struct rnr_stage0_fork_result *result,
                                  struct rnr_stage0_clock_error *error)
{
    struct rnr_stage0_clock_error sampled={0};
    int value=state->phase==RNR_STAGE0_CLOCK_NEGATIVE?
        fork_setup_sample(state,&sampled):rnr_stage0_clock_check_setup(state,&sampled);
    if(value!=0&&result->admission_clock.code==RNR_STAGE0_CLOCK_OK)
        result->admission_clock=sampled;
    if(error->code==RNR_STAGE0_CLOCK_OK)*error=sampled;
    else if(!error->cleanup_errno)error->cleanup_errno=sampled.cleanup_errno;
    return value!=0||error->code!=RNR_STAGE0_CLOCK_OK?-1:0;
}
static int admission_passcred(int fd,struct rnr_stage0_clock *state,
                              struct rnr_stage0_fork_result *result,
                              struct rnr_stage0_clock_error *error)
{
    int enabled=1,observed=0;socklen_t length=sizeof(observed);
    if(rnr_stage0_clock_check_setup(state,error)!=0)return -1;
    int value=setsockopt(fd,SOL_SOCKET,SO_PASSCRED,&enabled,sizeof(enabled));
    int failure=value<0?errno:0;
    if(value!=0)reject_clock(error,RNR_STAGE0_CLOCK_GATE,failure);
    if(admission_sample_after(state,result,error)!=0)return -1;
    value=getsockopt(fd,SOL_SOCKET,SO_PASSCRED,&observed,&length);
    failure=value<0?errno:0;
    if(value!=0||length!=sizeof(observed)||observed!=1){
        reject_clock(error,RNR_STAGE0_CLOCK_GATE,failure);
    }
    return admission_sample_after(state,result,error);
}
static int admission_buffer(int fd,int option,struct rnr_stage0_clock *state,
                            struct rnr_stage0_fork_result *result,
                            struct rnr_stage0_clock_error *error)
{
    int requested=131072,observed=0;socklen_t length=sizeof(observed);
    if(rnr_stage0_clock_check_setup(state,error)!=0)return -1;
    int value=setsockopt(fd,SOL_SOCKET,option,&requested,sizeof(requested));
    int failure=value<0?errno:0;
    if(value!=0)reject_clock(error,RNR_STAGE0_CLOCK_GATE,failure);
    if(admission_sample_after(state,result,error)!=0)return -1;
    value=getsockopt(fd,SOL_SOCKET,option,&observed,&length);
    failure=value<0?errno:0;
    if(value!=0||length!=sizeof(observed)||observed!=262144)
        reject_clock(error,RNR_STAGE0_CLOCK_GATE,failure);
    return admission_sample_after(state,result,error);
}
static int admission_armed(int fd,struct rnr_stage0_clock *state,
                           struct rnr_stage0_clock_error *error)
{
    _Static_assert(sizeof(struct ucred)==12&&sizeof(struct cmsghdr)==16&&
                   CMSG_SPACE(sizeof(struct ucred))==32&&sizeof(int)==4,
                   "Fixed Linux x86-64 ancillary layout required");
    unsigned char raw[8];
    union {struct cmsghdr alignment;unsigned char bytes[32];} control={0};
    struct rnr_stage0_fork_result *result=fork_parent_result;
    if(!result||result->child_pid<=0||result->child_pidfd<3||fd!=fork_parent_gate){
        reject_clock(error,RNR_STAGE0_CLOCK_OWNER,0);return -1;
    }
    if(fork_setup_sample(state,error)!=0)return -1;
    int64_t remaining=state->setup_end_ns-state->last_boottime_ns;
    int64_t wall_remaining=state->wall_deadline_ns-state->last_wall_ns;
    if(wall_remaining<remaining)remaining=wall_remaining;
    struct pollfd ready[2]={{.fd=fd,.events=POLLIN},
                           {.fd=result->child_pidfd,.events=POLLIN}};
    int value=poll(ready,2,(int)((remaining+999999)/1000000));
    int failure=value<0?errno:0;
    if(value!=1||ready[1].revents||ready[0].revents!=POLLIN){
        reject_clock(error,RNR_STAGE0_CLOCK_GATE,failure);
    }
    if(admission_sample_after(state,result,error)!=0)return -1;
    struct iovec vector={.iov_base=raw,.iov_len=sizeof(raw)};
    struct msghdr message={.msg_iov=&vector,.msg_iovlen=1,
        .msg_control=control.bytes,.msg_controllen=sizeof(control.bytes)};
    ssize_t amount=recvmsg(fd,&message,MSG_DONTWAIT|MSG_TRUNC|MSG_CMSG_CLOEXEC);
    failure=amount<0?errno:0;
    if(amount<0)reject_clock(error,RNR_STAGE0_CLOCK_GATE,failure);
    /* Adopt/dispose installed rights before any clock or liveness call. The
     * trusted kernel normalizes cmsg headers; never index beyond returned bytes. */
    size_t bytes=message.msg_controllen;
    if(bytes>sizeof(control.bytes)){
        reject_clock(error,RNR_STAGE0_CLOCK_GATE,0);bytes=sizeof(control.bytes);
    }
    unsigned int credentials=0;
    for(size_t offset=0;offset<bytes;){
        if(bytes-offset<sizeof(struct cmsghdr)){
            reject_clock(error,RNR_STAGE0_CLOCK_GATE,0);break;
        }
        struct cmsghdr header;memcpy(&header,control.bytes+offset,sizeof(header));
        if(header.cmsg_len<CMSG_LEN(0)||header.cmsg_len>bytes-offset){
            reject_clock(error,RNR_STAGE0_CLOCK_GATE,0);break;
        }
        size_t count=header.cmsg_len-CMSG_LEN(0);
        const unsigned char *data=control.bytes+offset+CMSG_LEN(0);
        if(header.cmsg_level==SOL_SOCKET&&header.cmsg_type==SCM_RIGHTS){
            reject_clock(error,RNR_STAGE0_CLOCK_GATE,0);
            for(size_t at=0;at+sizeof(int)<=count;at+=sizeof(int)){
                int owned;memcpy(&owned,data+at,sizeof(owned));
                if(owned<0||owned==fd||owned==result->child_pidfd){
                    reject_clock(error,RNR_STAGE0_CLOCK_GATE,0);continue;
                }
                (void)fork_close(&owned,result,error);
            }
        }else if(header.cmsg_level==SOL_SOCKET&&header.cmsg_type==SCM_CREDENTIALS&&
                 count==sizeof(struct ucred)){
            struct ucred sender;memcpy(&sender,data,sizeof(sender));++credentials;
            if(credentials!=1||sender.pid!=result->child_pid||sender.uid||sender.gid)
                reject_clock(error,RNR_STAGE0_CLOCK_GATE,0);
        }else reject_clock(error,RNR_STAGE0_CLOCK_GATE,0);
        size_t next=CMSG_ALIGN(header.cmsg_len);
        if(next>bytes-offset){
            if(header.cmsg_len!=bytes-offset)reject_clock(error,RNR_STAGE0_CLOCK_GATE,0);
            break;
        }
        offset+=next;
    }
    if(amount!=8||message.msg_flags&~MSG_CMSG_CLOEXEC||credentials!=1||
       (amount==8&&memcmp(raw,"RNRKARM1",8)))
        reject_clock(error,RNR_STAGE0_CLOCK_GATE,failure);
    /* Clock helpers initialize their output. Preserve the initiating protocol
     * and cleanup capsule while independently checking negative identity/time. */
    if(admission_sample_after(state,result,error)!=0)return -1;
    struct pollfd alive={.fd=result->child_pidfd,.events=POLLIN};
    value=poll(&alive,1,0);failure=value<0?errno:0;
    if(value!=0||alive.revents)reject_clock(error,RNR_STAGE0_CLOCK_GATE,failure);
    return admission_sample_after(state,result,error);
}
static int fork_packet(int fd,const char wanted[8],struct rnr_stage0_clock *state,
                         struct rnr_stage0_clock_error *error)
{
    if(fork_admission_route&&state==fork_parent_clock)
        return admission_armed(fd,state,error);
    unsigned char raw[8];
    if(fork_setup_sample(state,error)!=0)return -1;
    int64_t remaining=state->setup_end_ns-state->last_boottime_ns;
    int64_t wall_remaining=state->wall_deadline_ns-state->last_wall_ns;
    if(wall_remaining<remaining)remaining=wall_remaining;
    /* Bounds follow the original15-second setup window; ceiling never rounds
     * a live sub-ms interval down to a spurious zero-time nonblocking probe. */
    int timeout=(int)((remaining+999999)/1000000);
    struct pollfd ready={.fd=fd,.events=POLLIN};
    int value=poll(&ready,1,timeout);
    int failure=value<0?errno:0;
    if(value!=1 || (ready.revents&(POLLERR|POLLNVAL)) || !(ready.revents&POLLIN)){
        reject_clock(error,RNR_STAGE0_CLOCK_GATE,failure);return -1;
    }
    if(fork_setup_sample(state,error)!=0)return -1;
    struct iovec vector={.iov_base=raw,.iov_len=sizeof(raw)};
    struct msghdr message={.msg_iov=&vector,.msg_iovlen=1};
    ssize_t amount=recvmsg(fd,&message,MSG_DONTWAIT|MSG_TRUNC|MSG_CMSG_CLOEXEC);
    failure=amount<0?errno:0;
    if(amount!=8 || (message.msg_flags&~MSG_CMSG_CLOEXEC) ||
       memcmp(raw,wanted,8)!=0){
        reject_clock(error,RNR_STAGE0_CLOCK_GATE,failure);return -1;
    }
    return fork_setup_sample(state,error);
}
static int fork_clock(struct rnr_stage0_clock *state,
                          struct rnr_stage0_fork_result *result,
                          struct rnr_stage0_clock_error *error, int admission_route)
{
    if(state==NULL || result==NULL || error==NULL){
        atomic_store_explicit(&fork_reserved,1,memory_order_release);errno=EINVAL;
        return fork_admission_route&&state==fork_parent_clock?-1:terminal(state);
    }
    *error=(struct rnr_stage0_clock_error){0};
    if(atomic_exchange_explicit(&fork_reserved,1,memory_order_acq_rel) || state->fork_attempted || state->admission_attempted ||
       state->phase!=RNR_STAGE0_CLOCK_PREPARING){
        state->fork_attempted=1;
        reject_clock(error,RNR_STAGE0_CLOCK_STATE,0);
        return fork_admission_route&&state==fork_parent_clock?-1:terminal(state);
    }
    /* A losing/invalid repeated call NEVER replaces retained child ownership. */
    state->fork_attempted=1;
    *result=(struct rnr_stage0_fork_result){.child_pidfd=-1};
    fork_admission_route=admission_route;
    int channels[2]={-1,-1};
    struct rnr_stage0_admission_error admission={0};
    struct sigaction disposition;
    if(rnr_stage0_clock_check_setup(state,error)!=0)goto failed;
    /* Initial0..2 observation occurs AFTER T0 and BEFORE gate creation. Child
     * must close its gate before unchanged preparer initial admission. */
    if(rnr_stage0_admit_preparation_fds(&admission)!=0){
        reject_clock(error,RNR_STAGE0_CLOCK_FORK,admission.system_errno);
        error->cleanup_errno=admission.cleanup_errno;goto failed;
    }
    if(rnr_stage0_clock_check_setup(state,error)!=0)goto failed;
    if(sigaction(SIGCHLD,NULL,&disposition)!=0){
        reject_clock(error,RNR_STAGE0_CLOCK_FORK,errno);goto failed;
    }
    if(disposition.sa_handler!=SIG_DFL || (disposition.sa_flags&SA_NOCLDWAIT)){
        reject_clock(error,RNR_STAGE0_CLOCK_FORK,0);goto failed;
    }
    if(admission_route){
        if(getuid()!=0||geteuid()!=0||getgid()!=0||getegid()!=0){
            reject_clock(error,RNR_STAGE0_CLOCK_OWNER,0);goto failed;
        }
        if(admission_single_owner(error)!=0)goto failed;
        fork_single_owner=1;
    }
    if(rnr_stage0_clock_check_setup(state,error)!=0)goto failed;
    if(socketpair(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK,0,channels)!=0){
        reject_clock(error,RNR_STAGE0_CLOCK_GATE,errno);goto failed;
    }
    /* Exact0..2 was admitted before this allocation; the held child scanner
     * relies on closing original endpoint3 and retaining original gate4.
     * Unexpected allocation is rejected, never repaired or adopted. */
    if(channels[0]!=3 || channels[1]!=4){
        reject_clock(error,RNR_STAGE0_CLOCK_GATE,0);goto failed;
    }
    if(rnr_stage0_clock_check_setup(state,error)!=0)goto failed;
    if(admission_route&&(admission_passcred(channels[0],state,result,error)!=0||
                         admission_passcred(channels[1],state,result,error)!=0||
                         admission_buffer(channels[0],SO_SNDBUF,state,result,error)!=0||
                         admission_buffer(channels[0],SO_RCVBUF,state,result,error)!=0||
                         admission_buffer(channels[1],SO_SNDBUF,state,result,error)!=0||
                         admission_buffer(channels[1],SO_RCVBUF,state,result,error)!=0))goto failed;
    pid_t parent=state->pid;
    result->fork_entered=1;
    pid_t child=fork();
    int failure=child<0?errno:0;
    result->fork_returned=1;
    if(child<0){reject_clock(error,RNR_STAGE0_CLOCK_FORK,failure);goto failed;}
    if(child==0){
        /* The child cannot return to preparation until the original keeper GO.
         * Parent loss before prctl is caught by both copied-parent checks. */
        state->phase=RNR_STAGE0_CLOCK_HELD;
        if(fork_close(&channels[0],result,error)!=0 || getppid()!=parent ||
           prctl(PR_SET_PDEATHSIG,(unsigned long)SIGKILL,0UL,0UL,0UL)!=0 ||
           fork_parent_live(parent,error)!=0)goto child_failed;
        struct rnr_stage0_clock transitioned=*state;
        pid_t own=getpid();
        if(own<=0 || own==parent || gettid()!=own)goto child_failed;
        transitioned.pid=transitioned.tid=own;
        /* Only this branch of the actual fork can change execution ownership.
         * Samples/identity are checked on a copy before publishing the change;
         * every origin, cutoff and previous high-water value is preserved. */
        if(check_setup_samples(&transitioned,error)!=0)goto child_failed;
        *state=transitioned;
        if(fork_parent_live(parent,error)!=0)goto child_failed;
        ssize_t amount=send(channels[1],"RNRKARM1",8,MSG_DONTWAIT|MSG_NOSIGNAL);
        if(amount!=8)goto child_failed; /* one send, never replayed */
        if(admission_route){
            fork_child_gate=channels[1];channels[1]=-1;
            fork_child_parent=parent;fork_child_clock=state;fork_child_result=result;
            state->phase=RNR_STAGE0_CLOCK_ADMISSION;
            return 0; /* only the fixed launch wrapper may consume this branch */
        }
        if(fork_packet(channels[1],"RNRKGO01",state,error)!=0 ||
           fork_parent_live(parent,error)!=0 ||
           fork_close(&channels[1],result,error)!=0 ||
           fork_parent_live(parent,error)!=0 ||
           check_setup_samples(state,error)!=0)goto child_failed;
        state->phase=RNR_STAGE0_CLOCK_PREPARING;
        return 0;
child_failed:
        (void)fork_close(&channels[0],result,error);
        (void)fork_close(&channels[1],result,error);
        (void)terminal(state);
        _exit(125);
    }
    /* Retain exact direct-child identity BEFORE close, pidfd_open or a sample.
     * SIGCHLD was default/no auto-reap; no wait is performed before pidfd_open.
     * Private immutable single-owner/no-handler launch context is required. */
    result->child_pid=child;
    state->phase=RNR_STAGE0_CLOCK_NEGATIVE;
    fork_parent_pid=parent;fork_parent_clock=state;fork_parent_result=result;
    fork_parent_gate=channels[0];channels[0]=-1;
    if(fork_close(&channels[1],result,error)!=0)goto failed;
    result->child_pidfd=(int)syscall(SYS_pidfd_open,child,0);
    if(result->child_pidfd<0){reject_clock(error,RNR_STAGE0_CLOCK_FORK,errno);goto failed;}
    if(fork_packet(fork_parent_gate,"RNRKARM1",state,error)!=0)goto failed;
    result->child_armed=1;
    return 1; /* negative ownership, NEVER positive placement/readiness */
failed:
    (void)fork_close(&channels[0],result,error);
    (void)fork_close(&channels[1],result,error);
    if(admission_route && fork_parent_clock==state){
        result->primary=*error;
        /* Independently validate remaining negative lease. No restoration of
         * FAILED state after an identity/sample/rollback failure. */
        struct rnr_stage0_clock_error negative={0};
        if(state->phase==RNR_STAGE0_CLOCK_NEGATIVE)
            (void)negative_admission_sample(state,&negative);
        return -1;
    }
    if(fork_parent_clock==state)(void)fork_close(&fork_parent_gate,result,error);
    return terminal(state);
}
int rnr_stage0_clock_fork(struct rnr_stage0_clock *s,
    struct rnr_stage0_fork_result *r,struct rnr_stage0_clock_error *e)
{return fork_clock(s,r,e,0);}
int rnr_stage0_clock_fork_admission(struct rnr_stage0_clock *s,
    struct rnr_stage0_fork_result *r,struct rnr_stage0_clock_error *e)
{return fork_clock(s,r,e,1);}
int rnr_stage0_clock_check_admission(struct rnr_stage0_clock *state,
    struct rnr_stage0_clock_error *error)
{
    if(error==NULL){errno=EINVAL;return terminal(state);}
    *error=(struct rnr_stage0_clock_error){0};
    if(!fork_admission_route||state==NULL||state!=fork_child_clock||
       state->phase!=RNR_STAGE0_CLOCK_ADMISSION||fork_child_gate!=4||
       state->pid!=getpid()||getpid()!=gettid()||
       fork_parent_live(fork_child_parent,error)!=0){
        reject_clock(error,RNR_STAGE0_CLOCK_OWNER,0);return terminal(state);
    }
    return check_setup_samples(state,error);
}
int rnr_stage0_clock_abandon_admission(struct rnr_stage0_clock *state,
    struct rnr_stage0_fork_result *result,struct rnr_stage0_clock_error *error)
{
    if(!state||!result||!error){errno=EINVAL;return -1;}
    *error=(struct rnr_stage0_clock_error){0};
    if(!fork_admission_route||getpid()!=gettid())goto wrong;
    if(state==fork_child_clock&&result==fork_child_result&&state->pid==getpid()&&fork_child_gate>=0)
        return fork_close(&fork_child_gate,result,error);
    if(state==fork_parent_clock&&result==fork_parent_result&&fork_parent_pid==getpid()&&fork_parent_gate>=0)
        return fork_close(&fork_parent_gate,result,error);
wrong:
    reject_clock(error,RNR_STAGE0_CLOCK_OWNER,0);return -1;
}
int rnr_stage0_clock_contain_original_child(struct rnr_stage0_clock *state,
    struct rnr_stage0_fork_result *result,struct rnr_stage0_clock_error *error)
{
    if(!state||!result||!error){errno=EINVAL;return -1;}
    *error=(struct rnr_stage0_clock_error){0};
    if(!fork_admission_route||state!=fork_parent_clock||result!=fork_parent_result||
       result->child_pid<=0||result->signal_attempted){reject_clock(error,RNR_STAGE0_CLOCK_OWNER,0);return -1;}
    if(fork_parent_pid!=getpid()||gettid()!=getpid()){
        reject_clock(error,RNR_STAGE0_CLOCK_OWNER,0);return terminal(state);
    }
    if(state->phase!=RNR_STAGE0_CLOCK_NEGATIVE){reject_clock(error,RNR_STAGE0_CLOCK_STATE,0);return -1;}
    if(result->child_pidfd<0){
        struct sigaction disposition;
        if(!fork_single_owner){reject_clock(error,RNR_STAGE0_CLOCK_OWNER,0);return terminal(state);}
        if(sigaction(SIGCHLD,NULL,&disposition)!=0){
            reject_clock(error,RNR_STAGE0_CLOCK_OWNER,errno);return terminal(state);
        }
        if(disposition.sa_handler!=SIG_DFL||(disposition.sa_flags&SA_NOCLDWAIT)){
            reject_clock(error,RNR_STAGE0_CLOCK_OWNER,0);return terminal(state);
        }
    }else if(result->child_pidfd<3){
        reject_clock(error,RNR_STAGE0_CLOCK_OWNER,0);return terminal(state);
    }
    if(negative_admission_sample(state,error)!=0)return -1;
    result->signal_attempted=1; /* reserve independently before sole syscall */
    long value=result->child_pidfd>=0?
        syscall(SYS_pidfd_send_signal,result->child_pidfd,SIGKILL,NULL,0):
        syscall(SYS_kill,result->child_pid,SIGKILL);
    result->signal_result=(int)value;result->signal_errno=value<0?errno:0;
    if(value!=0){reject_clock(error,RNR_STAGE0_CLOCK_FORK,result->signal_errno);return -1;}
    return 0;
}
int rnr_stage0_clock_abandon_gate(struct rnr_stage0_clock *state,
                                  struct rnr_stage0_fork_result *result,
                                  struct rnr_stage0_clock_error *error)
{
    if(state==NULL || result==NULL || error==NULL){errno=EINVAL;return -1;}
    *error=(struct rnr_stage0_clock_error){0};
    if(gettid()!=getpid() || fork_parent_pid!=getpid() ||
       fork_parent_clock!=state || fork_parent_result!=result || fork_parent_gate<0){
        reject_clock(error,RNR_STAGE0_CLOCK_OWNER,0);return -1;
    }
    (void)terminal(state);
    return fork_close(&fork_parent_gate,result,error);
}
#endif
