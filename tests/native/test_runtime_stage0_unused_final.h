/* Unexercised final APIs must never escape older isolated mock boundaries. */
static int unused_final_admit(struct rnr_stage0_admission_error *e)
{(void)e;assert(0);return -1;}
static int unused_final_finish(struct rnr_stage0_launch_error *e)
{(void)e;assert(0);return -1;}
#define rnr_stage0_admit_initial_fds(e) unused_final_admit(e)
#define rnr_stage0_finish_operational(e) unused_final_finish(e)
