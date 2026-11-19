/* Isolated unprivileged parent-loss check. No GO, preparer or host resources. */
#define _GNU_SOURCE
#ifdef NDEBUG
#error "Parent-loss fixture requires active assertions"
#endif
#include <assert.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../../automation/native/runtime_stage0_clock.h"
static void exited(pid_t pid,int expected)
{
    int fd=(int)syscall(SYS_pidfd_open,pid,0);assert(fd>=3);
    struct pollfd done={.fd=fd,.events=POLLIN};
    assert(poll(&done,1,15000)==1&&(done.revents&POLLIN));
    int status=0;assert(waitpid(pid,&status,WNOHANG)==pid);
    if(expected==0)assert(WIFEXITED(status)&&WEXITSTATUS(status)==0);
    else assert((WIFSIGNALED(status)&&WTERMSIG(status)==SIGKILL)||
                (WIFEXITED(status)&&WEXITSTATUS(status)==125));
    assert(close(fd)==0);
}
int main(int argc,char **argv)
{
    if(argc==2){
        assert(!strcmp(argv[1],"parent"));
        struct rnr_stage0_clock state={0};struct rnr_stage0_clock_error error={0};
        struct rnr_stage0_fork_result child={0};
        assert(rnr_stage0_clock_prepare(&state,&error)==0);
        int branch=rnr_stage0_clock_fork(&state,&child,&error);
        if(branch==0)_exit(126); /* Child preparation is forbidden without GO. */
        assert(branch==1&&child.child_armed==1&&state.phase==RNR_STAGE0_CLOCK_NEGATIVE);
        assert(write(STDOUT_FILENO,&child.child_pid,sizeof(child.child_pid))==sizeof(child.child_pid));
        _exit(0); /* Lose original parent, its private gate and retained pidfd. */
    }
    assert(argc==1);
    /* This affects only the isolated fixture process, never the Python host. */
    assert(prctl(PR_SET_CHILD_SUBREAPER,1UL,0UL,0UL,0UL)==0);
    int channel[2];assert(pipe2(channel,O_CLOEXEC)==0);
    pid_t original=getpid(),parent=fork();assert(parent>=0);
    if(parent==0){
        if(getppid()!=original||prctl(PR_SET_PDEATHSIG,(unsigned long)SIGKILL,0UL,0UL,0UL)!=0||
           getppid()!=original)_exit(127);
        assert(dup2(channel[1],STDOUT_FILENO)==STDOUT_FILENO);
        assert(close(channel[0])==0&&close(channel[1])==0);
        char *const args[]={argv[0],"parent",NULL};
        char *const env[]={"LC_ALL=C","TZ=UTC",NULL};
        execve(args[0],args,env);_exit(127);
    }
    assert(close(channel[1])==0);
    struct pollfd report={.fd=channel[0],.events=POLLIN};
    assert(poll(&report,1,15000)==1&&(report.revents&POLLIN));
    pid_t child=0;assert(read(channel[0],&child,sizeof(child))==sizeof(child)&&child>0);
    assert(close(channel[0])==0);
    exited(parent,0);
    exited(child,1); /* Original unreaped direct/adopted child, never a replay. */
    struct rnr_stage0_admission_error admission;
    assert(rnr_stage0_admit_preparation_fds(&admission)==0);
    return 0;
}
