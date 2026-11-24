/* Private negative privilege observation, never a host/project admission grant. */
#ifndef RNR_RUNTIME_STAGE0_BOOTSTRAP_H
#define RNR_RUNTIME_STAGE0_BOOTSTRAP_H
#include "runtime_stage0_launch.h"
#ifdef RNR_STAGE0_PRIVATE_QUALIFICATION
enum rnr_stage0_bootstrap_code {
    RNR_STAGE0_BOOTSTRAP_OK, RNR_STAGE0_BOOTSTRAP_ATTEMPT,
    RNR_STAGE0_BOOTSTRAP_OWNER, RNR_STAGE0_BOOTSTRAP_CLOCK,
    RNR_STAGE0_BOOTSTRAP_SYSCALL, RNR_STAGE0_BOOTSTRAP_IDENTITY,
    RNR_STAGE0_BOOTSTRAP_LINK, RNR_STAGE0_BOOTSTRAP_CLEANUP
};
struct rnr_stage0_bootstrap_error {
    enum rnr_stage0_bootstrap_code code;
    int system_errno, unadopted_fd;
    struct rnr_stage0_launch_error clock;
    unsigned int cleanup_count;
    struct { int fd, system_errno; } cleanup_errors[10];
};
/* Original held launch child only, ONE attempt, fixed paths and original setup15.
 * Trusted installer/bootstrap/kernel/stable namespaces/no privileged injection
 * and immutable no-thread/no-reaper code are prerequisites. Returns0 only after
 * negative observations and once-closing every local FD. Not host authentication,
 * project location/authority, persistence or readiness. No outputs grant access. */
int rnr_stage0_check_bootstrap(struct rnr_stage0_bootstrap_error *);
#endif
#endif
