/* VALIDATION artifact only. Real syscalls/exec if executed; execution is NOT
 * authorized by this source or its build. Positive Python dispatch is disabled.
 */
#include "runtime_stage0_launch.h"
#include <unistd.h>

int main(void)
{
    struct rnr_stage0_launch_error error = {0};
    (void)rnr_stage0_launch_validation(&error);
    /* Any writer return fails. Successful exec belongs to Python thereafter. */
    _exit(125);
}
