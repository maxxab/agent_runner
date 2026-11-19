/* Real unprivileged fork/gate ABORT only. Never runs a preparer or sends GO. */
#define _GNU_SOURCE
#ifdef NDEBUG
#error "Fork abort fixture requires active assertions"
#endif
#include <assert.h>
#include <poll.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "../../automation/native/runtime_stage0_clock.h"
int main(void)
{
    struct rnr_stage0_clock clock={0};
    struct rnr_stage0_clock_error error={0};
    struct rnr_stage0_fork_result child={0};
    assert(rnr_stage0_clock_prepare(&clock,&error)==0);
    int64_t origin=clock.captured_boottime_ns,wall=clock.sampled_wall_ns;
    /* The real child must stay inside the gate and exit125 on our EOF. */
    int branch=rnr_stage0_clock_fork(&clock,&child,&error);
    if(branch==0)_exit(126); /* A return in the child would violate the gate. */
    assert(branch==1&&child.child_pid>0&&child.child_pidfd>=3&&child.child_armed==1);
    assert(clock.phase==RNR_STAGE0_CLOCK_NEGATIVE&&clock.pid==getpid());
    assert(clock.captured_boottime_ns==origin&&clock.sampled_wall_ns==wall);
    assert(clock.setup_end_ns==origin+15000000000LL);
    assert(rnr_stage0_clock_abandon_gate(&clock,&child,&error)==0);
    struct timespec now;
    assert(clock_gettime(CLOCK_BOOTTIME,&now)==0);
    int64_t left=clock.setup_end_ns-(int64_t)now.tv_sec*1000000000LL-now.tv_nsec;
    assert(left>0);
    struct pollfd done={.fd=child.child_pidfd,.events=POLLIN};
    assert(poll(&done,1,(int)((left+999999)/1000000))==1&&(done.revents&POLLIN));
    int status=0;
    assert(waitpid(child.child_pid,&status,WNOHANG)==child.child_pid);
    assert(WIFEXITED(status)&&WEXITSTATUS(status)==125);
    int owned=child.child_pidfd;child.child_pidfd=-1;
    assert(close(owned)==0);
    /* Prove all fork gate/pidfd descriptors are gone, unchanged exact0..2. */
    struct rnr_stage0_admission_error admission;
    assert(rnr_stage0_admit_preparation_fds(&admission)==0);
    assert(rnr_stage0_clock_abandon_gate(&clock,&child,&error)==-1);
    return 0;
}
