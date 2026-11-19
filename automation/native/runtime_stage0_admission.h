/* Dormant Linux x86_64 stage0 prerequisite. Not an entry point or authority. */
#ifndef RNR_RUNTIME_STAGE0_ADMISSION_H
#define RNR_RUNTIME_STAGE0_ADMISSION_H

enum rnr_stage0_admission_code {
    RNR_STAGE0_ADMISSION_OK = 0,
    RNR_STAGE0_ADMISSION_ARGUMENT,
    RNR_STAGE0_ADMISSION_INPUT,
    RNR_STAGE0_ADMISSION_STDIO,
    RNR_STAGE0_ADMISSION_OPEN,
    RNR_STAGE0_ADMISSION_DIRECTORY,
    RNR_STAGE0_ADMISSION_READ,
    RNR_STAGE0_ADMISSION_RECORD,
    RNR_STAGE0_ADMISSION_INVENTORY,
    RNR_STAGE0_ADMISSION_IDENTITY,
    RNR_STAGE0_ADMISSION_CLEANUP
};

struct rnr_stage0_admission_error {
    enum rnr_stage0_admission_code code;
    int system_errno;
    int cleanup_errno;
};

/*
 * Fixed layout: stdio 0..2, six externally established input roles 3..8.
 * Returns 0 on structural admission, -1 on rejection. No caller FD is
 * consumed, repaired or authenticated. The error object must be non-NULL.
 *
 * Future authenticated entry must call before Python, bracket with its
 * ORIGINAL owner/clock checks, and provide trusted proc/dev views and a
 * single-owner environment. This module captures/renews no deadline.
 * Source is dormant, unintegrated and not operationally qualified.
 */
int rnr_stage0_admit_initial_fds(struct rnr_stage0_admission_error *error);

/* Fixed preparation profile: ONLY stdio0..2 plus the local scanner. Call
 * after original native T0, before opening any preparation inputs. Unexpected
 * FDs reject without consumption or repair. Same structural/TCB limitations. */
int rnr_stage0_admit_preparation_fds(struct rnr_stage0_admission_error *error);

#ifdef RNR_STAGE0_PRIVATE_QUALIFICATION
/* Fixed held child structure: stdio0..2, original socketpair gate4, scanner3.
 * Caller supplies no FD/whitelist. Socket structure is NOT fork/peer authority;
 * only the fixed original-clock fork owner may use this before input reads. */
int rnr_stage0_admit_held_fds(struct rnr_stage0_admission_error *error);
#endif

#endif
