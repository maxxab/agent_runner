/* Private dormant handoff profiles. No main or operational authority. */
#ifndef RNR_RUNTIME_STAGE0_LAUNCH_H
#define RNR_RUNTIME_STAGE0_LAUNCH_H
#include "runtime_stage0_clock.h"
enum rnr_stage0_launch_code {
    RNR_STAGE0_LAUNCH_OK = 0, RNR_STAGE0_LAUNCH_ATTEMPT,
    RNR_STAGE0_LAUNCH_OWNER, RNR_STAGE0_LAUNCH_CONFIG,
    RNR_STAGE0_LAUNCH_CLEANUP, RNR_STAGE0_LAUNCH_CLOCK,
    RNR_STAGE0_LAUNCH_ADMISSION, RNR_STAGE0_LAUNCH_INHERIT,
    RNR_STAGE0_LAUNCH_CONTEXT, RNR_STAGE0_LAUNCH_EXEC
};
struct rnr_stage0_launch_error {
    enum rnr_stage0_launch_code code;
    int system_errno, cleanup_errno;
    struct rnr_stage0_clock_error capture, final;
    struct rnr_stage0_clock_admission_result admission;
#ifdef RNR_STAGE0_PRIVATE_QUALIFICATION
    struct rnr_stage0_clock_error containment, gate_cleanup;
#endif
};
/* ONE module-owned attempt, always failure if it returns. No caller paths,
 * argv, environment, reset, receipt, main, Store or positive dispatch. Future
 * authenticated immutable root is an external prerequisite, not proven here.
 * Clock origin precedes fixed launchfile preparation; binding cannot renew
 * the original setup deadline. Final native
 * setup check precedes header/sealing/exec; Python validates the outer floor
 * and initial setup separately. Future positive dispatch must recheck setup.
 * Incoming0..8 untouched on failure; owned launch/context FDs close once.
 */
/* Split trusted SAME-process preparation. prepare returns 0 on success only;
 * finish and convenience launch always fail if returned. Between the calls,
 * the fixed trusted preparer may work under the SAME original clock. This
 * API supplies no supervision for stalled intervening work. No caller origin.
 * Calls need exclusive error buffers. Each buffer describes its invocation;
 * save the first failure capsule before calling again. Later ATTEMPT does not
 * reconstruct it. Null sets EINVAL; invalid/repeated calls permanently fence.
 * Validation destination/FD inventories/wire are unchanged, not operational.
 */
int rnr_stage0_prepare_validation(struct rnr_stage0_launch_error *);
int rnr_stage0_finish_validation(struct rnr_stage0_launch_error *);
int rnr_stage0_launch_validation(struct rnr_stage0_launch_error *);
/* Distinct fixed operational profile; Python _entry remains disabled. The
 * independently trusted same-process preparer captures before ALL per-attempt
 * work and calls check around bounded steps. Sequential checks are permitted;
 * concurrent/null/cross-mode/invalid calls fence the shared one-shot writer.
 * Mode provenance belongs to that authenticated control flow, not FD9 bytes.
 * No trusted preparer, root installation or lifecycle supervision supplied.
 */
int rnr_stage0_prepare_operational(struct rnr_stage0_launch_error *);
int rnr_stage0_check_operational_preparation(struct rnr_stage0_launch_error *);
/* Trusted private preparer supplies original protected task cutoff DATA once,
 * after T0/decoding and before any mutable preparation. Narrows SAME clock;
 * no caller origin/reset/renewal. Operational finish requires early binding
 * and exact immutable launch cutoff equality, never binds a second time.
 * Validation profile is unchanged. Invalid/duplicate/cross-mode/null fences.
 */
int rnr_stage0_bind_operational_preparation_cutoff(int64_t,
                                                 struct rnr_stage0_launch_error *);
int rnr_stage0_finish_operational(struct rnr_stage0_launch_error *);
#ifdef RNR_STAGE0_PRIVATE_QUALIFICATION
struct rnr_stage0_preparer_error;
struct rnr_stage0_installation;
struct rnr_stage0_task;
struct rnr_stage0_launch_declaration;
/* Fixed held-input boundary only; every returning parent path fails and every
 * child reader outcome abandons descriptors and _exit(125). No GO/main route. */
int rnr_stage0_supervised_inputs(struct rnr_stage0_preparer_error *);
int rnr_stage0_check_admission_preparation(struct rnr_stage0_launch_error *);
int rnr_stage0_bind_admission_inputs(const struct rnr_stage0_installation *,
    const struct rnr_stage0_task *,const struct rnr_stage0_launch_declaration *,
    struct rnr_stage0_launch_error *);
#endif
#endif
