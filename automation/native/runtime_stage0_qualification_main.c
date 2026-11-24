/* PRIVATE fail-closed qualification artifact: real host syscalls if executed.
 * NEVER RUN until whole-lifecycle and immutable startup closure are accepted.
 * This entry supervises held-input admission only, with no GO or host media
 * preparation. It is not a supported startup or operational qualification.
 */
#if !defined(RNR_STAGE0_PRIVATE_QUALIFICATION) || RNR_STAGE0_PRIVATE_QUALIFICATION != 1
#error "Private qualification entry requires RNR_STAGE0_PRIVATE_QUALIFICATION=1"
#endif
#include "runtime_stage0_preparer.h"
#include <unistd.h>

int main(void)
{
    struct rnr_stage0_preparer_error error = {0};
    /* The supervisor alone captures original T0, forks the fixed child and
     * owns its parent's containment attempt/gate cleanup. The child abandons
     * held input/gate ownership and exits125 without returning here. */
    (void)rnr_stage0_supervised_inputs(&error);
    /* Every parent return is terminal, even an unexpected zero. No repeated
     * cleanup, reaping claim, legacy preparation, persistence or continuation. */
    _exit(125);
}
