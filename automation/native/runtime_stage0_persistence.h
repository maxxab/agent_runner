/* Private storage preparation only; no receipt, effect or positive authority. */
#ifndef RNR_RUNTIME_STAGE0_PERSISTENCE_H
#define RNR_RUNTIME_STAGE0_PERSISTENCE_H
#include <stddef.h>
#include <sys/types.h>
#ifdef RNR_STAGE0_PRIVATE_QUALIFICATION
#include "runtime_stage0_launch.h"
enum rnr_stage0_persistence_code {
    RNR_STAGE0_PERSISTENCE_OK, RNR_STAGE0_PERSISTENCE_ARGUMENT,
    RNR_STAGE0_PERSISTENCE_ATTEMPT, RNR_STAGE0_PERSISTENCE_OWNER,
    RNR_STAGE0_PERSISTENCE_CLOCK, RNR_STAGE0_PERSISTENCE_BINDING,
    RNR_STAGE0_PERSISTENCE_OPEN, RNR_STAGE0_PERSISTENCE_IDENTITY,
    RNR_STAGE0_PERSISTENCE_READ, RNR_STAGE0_PERSISTENCE_CREATE,
    RNR_STAGE0_PERSISTENCE_WRITE, RNR_STAGE0_PERSISTENCE_SYNC,
    RNR_STAGE0_PERSISTENCE_CLEANUP
};
enum rnr_stage0_persistence_creation {
    RNR_STAGE0_PERSISTENCE_UNATTEMPTED,
    RNR_STAGE0_PERSISTENCE_UNKNOWN,
    RNR_STAGE0_PERSISTENCE_COLLISION,
    RNR_STAGE0_PERSISTENCE_CREATED
};
struct rnr_stage0_persistence_error {
    enum rnr_stage0_persistence_code code;
    int system_errno;
    enum rnr_stage0_persistence_creation latch, claim;
    /* Once-only write/sync observations: latch write/file/parent, claim same. */
    unsigned int entered, returned;
    long results[6];
    int operation_errno[6];
    unsigned int cleanup_count;
    struct { int fd, system_errno; } cleanup[11];
    struct rnr_stage0_launch_error launch;
};
/* NOT INVOCABLE operationally: future fixed F2 owner must authenticate original
 * binding/policy/lineage before this storage-only call. No launch caller exists.
 * Immutable raw bytes for entire call; exclusive non-overlapping error output.
 * No borrowed pointer survives return. Fixed paths, original setup15 only,
 * no callback/clock/FD/path/reset/retry/append/receipt/retirement API.
 * HELD storage does not grant declaration, resources, GO or ordinary preparation.
 * Every outcome retains active/claim on disk, including successful preparation.
 */
int rnr_stage0_prepare_persistent_claim(const unsigned char *, size_t,
                                       struct rnr_stage0_persistence_error *);
/* Exact quiescent original owner only; close FDs once, even after expiry.
 * Reentry fences in-progress acquisition; it cannot drain another active call.
 * Never removes consumption or proves resource absence. */
int rnr_stage0_abandon_persistent_claim(struct rnr_stage0_persistence_error *);
#endif
#endif
