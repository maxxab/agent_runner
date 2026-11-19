/* PRIVATE qualification artifact: real host syscalls if executed, NEVER RUN
 * until whole-lifecycle supervision and current immutable closure are accepted.
 * Compile the linked writer with RNR_STAGE0_PRIVATE_QUALIFICATION=1. There is
 * no runtime selector and no alternate clock/writer/cleanup/replay route.
 */
#include "runtime_stage0_preparer.h"
#include <unistd.h>

int main(void)
{
    struct rnr_stage0_preparer_error error = {0};
    /* FIRST per-attempt action captures T0 inside the existing input owner.
     * Every nonzero return stops; each stage retains its own failure/uncertainty.
     */
    if(rnr_stage0_prepare_inputs(&error)==0 &&
       rnr_stage0_prepare_host_view(&error)==0 &&
       rnr_stage0_claim_preparation(&error)==0 &&
       rnr_stage0_prepare_runtime_loops(&error)==0 &&
       rnr_stage0_prepare_runtime_mapping(&error)==0 &&
       rnr_stage0_prepare_runtime_mount(&error)==0 &&
       rnr_stage0_prepare_launch_media(&error)==0 &&
       rnr_stage0_prepare_launch_loops(&error)==0 &&
       rnr_stage0_prepare_launch_mapping(&error)==0 &&
       rnr_stage0_prepare_launch_mount(&error)==0 &&
       rnr_stage0_prepare_fixed_binds(&error)==0 &&
       rnr_stage0_prepare_final_roles(&error)==0)
        (void)rnr_stage0_finish_prepared_operational(&error);
    /* Successful exec belongs to the fixed Python consumer. Every return fails.
     * Exit does not reconcile mounts/devices/helpers or prove descendants gone.
     */
    _exit(125);
}
