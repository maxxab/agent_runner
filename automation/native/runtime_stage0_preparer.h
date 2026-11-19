/* Fixed original-clock preparation owner; NOT a complete native preparer/entry. */
#ifndef RNR_RUNTIME_STAGE0_PREPARER_H
#define RNR_RUNTIME_STAGE0_PREPARER_H
#include "runtime_stage0_launch.h"
enum rnr_stage0_preparer_code {
    RNR_STAGE0_PREPARER_OK, RNR_STAGE0_PREPARER_ATTEMPT,
    RNR_STAGE0_PREPARER_OWNER, RNR_STAGE0_PREPARER_CLOCK,
    RNR_STAGE0_PREPARER_ADMISSION, RNR_STAGE0_PREPARER_OPEN,
    RNR_STAGE0_PREPARER_METADATA, RNR_STAGE0_PREPARER_READ,
    RNR_STAGE0_PREPARER_DECODE, RNR_STAGE0_PREPARER_IDENTITY,
    RNR_STAGE0_PREPARER_CLEANUP, RNR_STAGE0_PREPARER_VIEW,
    RNR_STAGE0_PREPARER_TASKS, RNR_STAGE0_PREPARER_PID1,
    RNR_STAGE0_PREPARER_CLAIM, RNR_STAGE0_PREPARER_JOURNAL,
    RNR_STAGE0_PREPARER_LOOP, RNR_STAGE0_PREPARER_DM, RNR_STAGE0_PREPARER_MOUNT, RNR_STAGE0_PREPARER_MEDIA,
    RNR_STAGE0_PREPARER_ROOT, RNR_STAGE0_PREPARER_FINAL
};
enum rnr_stage0_claim_disposition { RNR_STAGE0_CLAIM_NOT_ATTEMPTED,
    RNR_STAGE0_CLAIM_UNKNOWN, RNR_STAGE0_CLAIM_CREATED, RNR_STAGE0_CLAIM_COLLISION };
struct rnr_stage0_preparer_error {
    enum rnr_stage0_preparer_code code;
    int system_errno, unadopted_fd;
    unsigned int cleanup_count;
    struct { int fd, system_errno; } cleanup_errors[80];
    int cleanup_overflow;
    enum rnr_stage0_claim_disposition claim_disposition;
    int mkdir_errno;
    struct rnr_stage0_launch_error launch;
    struct rnr_stage0_admission_error admission;
};
/* ONE attempt: captures original operational T0 first, admits ONLY0..2, reads
 * fixed protected installation/task paths, retains private data+5 original FDs.
 * Returns0 only for input ownership, NEVER readiness/root authentication.
 * No caller paths/origins/FDs/data/callbacks, getters/reset or main/exec/Store.
 * The original module writer clock survives. Launch kernel media/final roles
 * and independent supervision are incomplete; public Python stays disabled.
 * Trusted proc/dev/root maintenance exclusion and fixed fresh native main
 * process/no callbacks/signals are prerequisites, not established by reads.
 */
int rnr_stage0_prepare_inputs(struct rnr_stage0_preparer_error *);
/* Same original owner/clock; retains22 original proc/PID1/typed ns roles.
 * This is pre-effect view ownership, not host authentication or readiness.
 * No caller data/paths/origin, namespace mutation, helper, Store or exec.
 */
int rnr_stage0_prepare_host_view(struct rnr_stage0_preparer_error *);
/* Fixed unique namespace/header stage, only after original inputs+view.
 * Creates consumed attempt directory and diagnostic journal under /run.
 * No replay/adoption/unlink or host resource cleanup; external supervisor
 * must reconcile uncertainty. Not a completed preparer/operational entry.
 */
int rnr_stage0_claim_preparation(struct rnr_stage0_preparer_error *);
/* Fixed next stage: retain installation-derived runtime media and two atomic
 * readonly loop bindings under SAME original clock. Not runtime authentication,
 * mapping/mount/helper/supervisor completion or permission for host invocation.
 * All failures retain consumed journal/operation uncertainty; closes ONLY.
 */
int rnr_stage0_prepare_runtime_loops(struct rnr_stage0_preparer_error *);
/* Next fixed original-clock stage: unique readonly verity mapping from the
 * retained original runtime loops and installation. No mount/helper/entry.
 * No caller selector; uncertainty preserves the mapping for external recovery.
 */
int rnr_stage0_prepare_runtime_mapping(struct rnr_stage0_preparer_error *);
/* Fixed runtime SquashFS mount and original /run bind/remount under same
 * owner and clock. No helper/chroot/entry or complete operational readiness.
 */
int rnr_stage0_prepare_runtime_mount(struct rnr_stage0_preparer_error *);
/* Same original owner/clock: fixed launch source and two authenticated
 * pre-Store helpers, pad/seal and diagnostic output. No launch mapping, final
 * entry or supervision; incomplete source MUST NOT be invoked on the host. */
int rnr_stage0_prepare_launch_media(struct rnr_stage0_preparer_error *);
/* Same original clock and completed private media: two fixed readonly
 * launch loop bindings. No launch mapping/mount/final entry or readiness. */
int rnr_stage0_prepare_launch_loops(struct rnr_stage0_preparer_error *);
/* Same original clock and private launch loops: fixed readonly verity mapping.
 * No mount/final entry or readiness; incomplete source MUST NOT run on host. */
int rnr_stage0_prepare_launch_mapping(struct rnr_stage0_preparer_error *);
/* Same original clock: fixed launch SquashFS mount and exact original
 * launch.bin view. No remaining binds/chroot/final roles or readiness. */
int rnr_stage0_prepare_launch_mount(struct rnr_stage0_preparer_error *);
/* Fixed fourteen host-interface binds after accepted launch root; same original
 * owner/clock, descriptor-only abandonment. No chroot/final roles/readiness. */
int rnr_stage0_prepare_fixed_binds(struct rnr_stage0_preparer_error *);
/* Same original owner/clock: process-local root transition, once-close all
 * preparation handles and exact final3..8. Public entry remains disabled. */
int rnr_stage0_prepare_final_roles(struct rnr_stage0_preparer_error *);
/* Consumes final-role ownership into SAME disabled operational writer; every
 * return is terminal failure. Writer alone owns launch/context FD9. */
int rnr_stage0_finish_prepared_operational(struct rnr_stage0_preparer_error *);
/* Negative ONLY: exact original root/main owner may atomically abandon
 * quiescent retained inputs/view even after clock expiry. Active acquisition only
 * fences and retains its own unwind; repeats/null/foreign never drain slots.
 * All numeric slots invalidate before single close, uncertainty never retries.
 * Use exclusive error buffers; retain original failure before subsequent calls.
 */
int rnr_stage0_abandon_preparation_inputs(struct rnr_stage0_preparer_error *);
#endif
