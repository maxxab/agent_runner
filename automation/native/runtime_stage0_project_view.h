/* Private G1 location only. No declaration, policy or resource authority. */
#ifndef RNR_STAGE0_PROJECT_VIEW_H
#define RNR_STAGE0_PROJECT_VIEW_H
#include "runtime_stage0_launch.h"
#ifdef RNR_STAGE0_PRIVATE_QUALIFICATION
enum rnr_stage0_project_code { RNR_STAGE0_PROJECT_OK, RNR_STAGE0_PROJECT_ATTEMPT,
    RNR_STAGE0_PROJECT_OWNER, RNR_STAGE0_PROJECT_CLOCK, RNR_STAGE0_PROJECT_SYSCALL,
    RNR_STAGE0_PROJECT_IDENTITY, RNR_STAGE0_PROJECT_RECORD, RNR_STAGE0_PROJECT_CLEANUP };
struct rnr_stage0_project_error {
    enum rnr_stage0_project_code code;
    int system_errno, unadopted_fd;
    struct rnr_stage0_launch_error clock;
    unsigned int cleanup_count;
    struct {int fd,system_errno;} cleanup_errors[29];
};
/* Fixed original launch child AFTER the negative guard. Original setup clock,
 * trusted immutable bootstrap/kernel/root, stable namespaces and exclusive host
 * maintenance remain premises. Keeps exactly28 roles, compares peers serially
 * with one temporary. Output is location ONLY, cleared on failure, never a grant.
 * The root output borrows the one original root until abandon; the caller must
 * never close it. The original child, keeper and PID1 executable descriptors
 * are also borrowed in that order; this view remains their sole closer. All
 * outputs are published only on successful capture. The keeper PID is the
 * original captured parent, valid only while this view remains held.
 * No caller path/PID/FD/origin/reset; repeated/cross-owner calls fence. */
int rnr_stage0_capture_project_view(char [65],int *,int [3],pid_t *,struct rnr_stage0_project_error *);
int rnr_stage0_check_project_view(struct rnr_stage0_project_error *);
/* Original owner, once-close only, including after expiry; no host cleanup. */
int rnr_stage0_abandon_project_view(struct rnr_stage0_project_error *);
#endif
#endif
