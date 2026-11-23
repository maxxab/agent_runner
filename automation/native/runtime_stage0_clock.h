/* Private dormant clock data, not a receipt or authenticated exec handoff. */
#ifndef RNR_RUNTIME_STAGE0_CLOCK_H
#define RNR_RUNTIME_STAGE0_CLOCK_H
#include <stdint.h>
#include <sys/types.h>
#include "runtime_stage0_admission.h"

enum rnr_stage0_clock_phase {
    RNR_STAGE0_CLOCK_UNINITIALIZED = 0,
    RNR_STAGE0_CLOCK_ACTIVE,
    RNR_STAGE0_CLOCK_FAILED,
    RNR_STAGE0_CLOCK_PREPARING,
    RNR_STAGE0_CLOCK_HELD,
    RNR_STAGE0_CLOCK_NEGATIVE,
    /* Fixed held input reader only; cutoff binding never grants ACTIVE. */
    RNR_STAGE0_CLOCK_ADMISSION
};
enum rnr_stage0_clock_code {
    RNR_STAGE0_CLOCK_OK = 0, RNR_STAGE0_CLOCK_STATE,
    RNR_STAGE0_CLOCK_OWNER, RNR_STAGE0_CLOCK_BOOT,
    RNR_STAGE0_CLOCK_NAMESPACE, RNR_STAGE0_CLOCK_SAMPLE,
    RNR_STAGE0_CLOCK_RANGE, RNR_STAGE0_CLOCK_IDENTITY,
    RNR_STAGE0_CLOCK_CUTOFF, RNR_STAGE0_CLOCK_CLEANUP,
    RNR_STAGE0_CLOCK_FORK, RNR_STAGE0_CLOCK_GATE
};
struct rnr_stage0_clock_error {
    enum rnr_stage0_clock_code code;
    int system_errno, cleanup_errno;
};
struct rnr_stage0_clock {
    enum rnr_stage0_clock_phase phase;
    int admission_attempted, fork_attempted, cutoff_bound;
    pid_t pid, tid;
    char boot_id[37];
    uint64_t time_ns_device, time_ns_inode;
    int64_t captured_boottime_ns, sampled_wall_ns;
    int64_t wall_deadline_ns, deadline_boottime_ns, setup_end_ns;
    int64_t last_boottime_ns, last_wall_ns;
};
struct rnr_stage0_clock_admission_result {
    int admission_called, admission_result;
    struct rnr_stage0_admission_error admission;
    struct rnr_stage0_clock_error before, after;
};
/* Use a zero-initialized, exclusively owned state for ONE new future run.
 * No reset, earlier-anchor import, caller authority or operational entry.
 * Fixed future trusted configuration must supply the absolute wall cutoff.
 * A previous run/anchor may NEVER be replaced by calling capture here.
 * Linux x86_64 trusted proc, single owner and replacement exclusion assumed.
 * All failure is terminal. Future exec integration must carry original AND
 * last samples; Python must not capture anew or drop these high-water marks.
 */
/* Prepare before reading fixed launch configuration. Bind once, deriving every
 * cutoff from the original samples. PREPARING grants no admission or handoff. */
int rnr_stage0_clock_prepare(struct rnr_stage0_clock *, struct rnr_stage0_clock_error *);
int rnr_stage0_clock_bind_cutoff(struct rnr_stage0_clock *, int64_t,
                               struct rnr_stage0_clock_error *);
int rnr_stage0_clock_capture(struct rnr_stage0_clock *, int64_t,
                            struct rnr_stage0_clock_error *);
int rnr_stage0_clock_check_setup(struct rnr_stage0_clock *,
                                struct rnr_stage0_clock_error *);
/* One attempt, original setup cutoff before AND after admission. */
int rnr_stage0_admit_with_clock(struct rnr_stage0_clock *,
                               struct rnr_stage0_clock_admission_result *);
#ifdef RNR_STAGE0_PRIVATE_QUALIFICATION
/* Dormant keeper prerequisite, NOT a complete supervisor or invocation route.
 * The module performs the sole physical fork before inputs/effects. Return1
 * transfers exact unreaped-child negative ownership to the original parent;
 * return0 is possible ONLY in the protected child after a future keeper GO.
 * Post-fork child failures _exit(125), never return into input preparation.
 * The parent's original clock becomes NEGATIVE and cannot bind/admit/launch.
 * All origin/cutoff/high-water values survive the child's ownership change.
 * No release/GO API is supplied until authenticated positive placement and
 * retained negative controls are implemented. Existing main is UNCHANGED.
 * Parent must preserve result on errors, including failed pidfd acquisition.
 * Descriptor closure/child exit NEVER proves absence of host resources.
 */
struct rnr_stage0_fork_result {
    pid_t child_pid;
    int child_pidfd, fork_entered, fork_returned, child_armed;
    int signal_attempted, signal_result, signal_errno;
    struct rnr_stage0_clock_error primary;
    /* Independent post-syscall clock failure, without replacing primary. */
    struct rnr_stage0_clock_error admission_clock;
    int cleanup_count;
    /* Two socket ends plus at most four installed ancillary rights. */
    struct { int fd, system_errno; } cleanup_errors[6];
};
/* Fail-closed held reader route, sharing the physical one-shot fork. Trusted
 * immutable native launch must contain no thread creation, callbacks, signal
 * handlers, wait/reaper or concurrent disposition changes. The fixed proc
 * observation establishes one thread before fork; it cannot freeze future code.
 * No GO or positive continuation. Preserve result/clock for recovery. */
int rnr_stage0_clock_fork_admission(struct rnr_stage0_clock *,
    struct rnr_stage0_fork_result *, struct rnr_stage0_clock_error *);
int rnr_stage0_clock_check_admission(struct rnr_stage0_clock *,
    struct rnr_stage0_clock_error *);
int rnr_stage0_clock_abandon_admission(struct rnr_stage0_clock *,
    struct rnr_stage0_fork_result *, struct rnr_stage0_clock_error *);
int rnr_stage0_clock_contain_original_child(struct rnr_stage0_clock *,
    struct rnr_stage0_fork_result *, struct rnr_stage0_clock_error *);
int rnr_stage0_clock_fork(struct rnr_stage0_clock *,
                          struct rnr_stage0_fork_result *,
                          struct rnr_stage0_clock_error *);
/* Original retained fork-parent only. This is negative timing DATA, not
 * permission for an effect. Each eventual containment effect needs a fresh
 * successful negative check; expiry/unknown timing permits no new write.
 * Retained child/controls/original bounds survive errors for recovery. */
struct rnr_stage0_keeper_tick {
    int setup_expired, trigger_due;
    int64_t trigger_ns, stop_ns;
};
int rnr_stage0_clock_check_keeper(struct rnr_stage0_clock *,
                                 struct rnr_stage0_keeper_tick *,
                                 struct rnr_stage0_clock_error *);
/* Once-only declaration DATA narrowing before original setup expires. The
 * fixed receiver must validate/consume the declaration first. Invalid or
 * repeated binding fences that exchange, never renews the original clock.
 * A binding/protocol error alone does not destroy a valid negative clock.
 * A structurally valid narrowing survives short/late admission rejection.
 * Admission requires a strict original60..stop negative interval. */
int rnr_stage0_clock_bind_keeper_cutoff(struct rnr_stage0_clock *, int64_t,
                                       struct rnr_stage0_clock_error *);
/* Original negative parent ONLY; closes its held gate exactly once. Does not
 * signal/reap/close the retained pidfd, release resources or renew clocks. */
int rnr_stage0_clock_abandon_gate(struct rnr_stage0_clock *,
                                  struct rnr_stage0_fork_result *,
                                  struct rnr_stage0_clock_error *);
#endif
#endif
