/* Controlled original-clock fork fixtures. ALL process/IPC calls mocked. */
#define _GNU_SOURCE
#define RNR_STAGE0_PRIVATE_QUALIFICATION 1
#ifdef NDEBUG
#error "Fork fixtures require active assertions"
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <setjmp.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/stat.h>
#include "../../automation/native/runtime_stage0_clock.h"
static int gate_socketpair(int,int,int,int[2]);
static int gate_sigaction(int,const struct sigaction *,struct sigaction *);
static pid_t gate_fork(void),gate_ppid(void);
static int gate_prctl(int,...),gate_poll(struct pollfd *,nfds_t,int);
static long gate_syscall(long,...);
static ssize_t gate_send(int,const void *,size_t,int),gate_recvmsg(int,struct msghdr *,int);
static int gate_admission(struct rnr_stage0_admission_error *);
static int gate_close(int);
static int fixture_open(const char *,int),fixture_stat(const char *,struct stat *);
static ssize_t fixture_read(int,void *,size_t);
static int fixture_time(clockid_t,struct timespec *);
static pid_t fixture_pid(void),fixture_tid(void);
static _Noreturn void gate_exit(int);
#define socketpair gate_socketpair
#define sigaction(s,a,o) gate_sigaction(s,a,o)
#define fork gate_fork
#define getppid gate_ppid
#define prctl(option,arg,...) ((void)sizeof(char[_Generic((arg),unsigned long:1,int *:1,default:-1)]),gate_prctl(option,arg,__VA_ARGS__))
#define poll gate_poll
#define syscall gate_syscall
#define send gate_send
#define recvmsg gate_recvmsg
#define _exit gate_exit
#define open fixture_open
#define read fixture_read
#define close gate_close
#define stat(p,s) fixture_stat(p,s)
#define clock_gettime fixture_time
#define getpid fixture_pid
#define gettid fixture_tid
#define rnr_stage0_admit_preparation_fds gate_admission
#define rnr_stage0_admit_initial_fds gate_admission
#include "../../automation/native/runtime_stage0_clock.c"
#undef open
#undef read
#undef close
#undef stat
#undef clock_gettime
#undef getpid
#undef gettid
#undef rnr_stage0_admit_initial_fds
#undef rnr_stage0_admit_preparation_fds
#undef socketpair
#undef sigaction
#undef fork
#undef getppid
#undef prctl
#undef poll
#undef syscall
#undef send
#undef recvmsg
#undef _exit

static int64_t boot,wall;
static pid_t owner,thread;
static int identity_reads;
static int gate_fault;
static int fixture_open(const char *p,int flags)
{assert(!strcmp(p,"/proc/sys/kernel/random/boot_id")&&flags==(O_RDONLY|O_NOFOLLOW|O_CLOEXEC));identity_reads=0;return 50;}
static ssize_t fixture_read(int fd,void *b,size_t n)
{assert(fd==50);if(identity_reads++){assert(n==1);return 0;}assert(n==38);memcpy(b,"12345678-1234-1234-1234-123456789abc\n!",38);return 37;}
static int fixture_stat(const char *p,struct stat *s)
{assert(!strcmp(p,"/proc/thread-self/ns/time"));memset(s,0,sizeof(*s));s->st_dev=1;s->st_ino=gate_fault==28&&owner==101?3:2;return 0;}
static int fixture_time(clockid_t c,struct timespec *t)
{int64_t n=c==CLOCK_BOOTTIME?boot:wall;t->tv_sec=n/1000000000;t->tv_nsec=n%1000000000;return 0;}
static pid_t fixture_pid(void){return owner;}
static pid_t fixture_tid(void){return thread;}
static struct rnr_stage0_clock prepared(void)
{struct rnr_stage0_clock s={0};struct rnr_stage0_clock_error e;assert(rnr_stage0_clock_prepare(&s,&e)==0);return s;}
static jmp_buf exited;
static int side,attempts,sockets,signals,admitted,gate_closes,pidfd_calls,sends,receives;
static int exit_status,wait_calls,armed_signal,parent_checks;
static void gate_reset(int child)
{
    atomic_store(&fork_reserved,0);fork_parent_gate=-1;fork_parent_pid=0;fork_parent_clock=NULL;fork_parent_result=NULL;boot=1000000000000LL;wall=1700000000000000000LL;owner=thread=100;side=child;attempts=sockets=signals=admitted=gate_closes=0;
    pidfd_calls=sends=receives=gate_fault=exit_status=wait_calls=armed_signal=parent_checks=0;
}
static int gate_socketpair(int domain,int type,int protocol,int fds[2])
{
    assert(domain==AF_UNIX&&type==(SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK)&&protocol==0);
    assert(admitted==1);++sockets;
    if(gate_fault==1){errno=EMFILE;return -1;}fds[0]=60;fds[1]=61;return 0;
}
static int gate_sigaction(int sig,const struct sigaction *action,struct sigaction *old)
{
    assert(sig==SIGCHLD&&action==NULL&&old!=NULL);++signals;
    if(gate_fault==2){errno=EIO;return -1;}
    memset(old,0,sizeof(*old));old->sa_handler=gate_fault==3?SIG_IGN:SIG_DFL;
    old->sa_flags=gate_fault==4?SA_NOCLDWAIT:0;return 0;
}
static pid_t gate_fork(void)
{
    assert(sockets==1&&signals==1);++attempts;
    if(gate_fault==5){errno=EAGAIN;return -1;}
    if(side){owner=thread=101;if(gate_fault==26)--boot;if(gate_fault==27)--wall;return 0;}return 101;
}
static pid_t gate_ppid(void){++parent_checks;return gate_fault==6||(gate_fault==24&&parent_checks>=2)||(gate_fault==25&&parent_checks>=5)?1:100;}
static int gate_prctl(int option,...)
{
    va_list args;va_start(args,option);
    if(gate_fault==7){va_end(args);errno=EPERM;return -1;}
    if(option==PR_SET_PDEATHSIG){assert(va_arg(args,unsigned long)==(unsigned long)SIGKILL);armed_signal=SIGKILL;}
    else {assert(option==PR_GET_PDEATHSIG);*va_arg(args,int *)=gate_fault==8?0:armed_signal;}
    va_end(args);return 0;
}
static long gate_syscall(long call,...)
{
    va_list args;va_start(args,call);assert(call==SYS_pidfd_open);
    assert(va_arg(args,int)==101&&va_arg(args,int)==0);++pidfd_calls;va_end(args);
    if(gate_fault==9){errno=EMFILE;return -1;}return 62;
}
static int gate_poll(struct pollfd *fds,nfds_t count,int timeout)
{
    assert(count==1&&fds[0].fd==(side?61:60));assert(timeout>0&&timeout<=15000);++wait_calls;
    if(gate_fault==10){errno=EINTR;return -1;}
    if(gate_fault==11)return 0;
    fds[0].revents=gate_fault==12?POLLHUP:POLLIN;
    if(gate_fault==13)boot+=15000000000LL;
    return 1;
}
static ssize_t gate_send(int fd,const void *packet,size_t size,int flags)
{
    assert(side&&fd==61&&size==8&&flags==(MSG_DONTWAIT|MSG_NOSIGNAL));
    assert(memcmp(packet,"RNRKARM1",8)==0);++sends;
    if(gate_fault==14){errno=EAGAIN;return -1;}
    if(gate_fault==15)return 7;
    return 8;
}
static ssize_t gate_recvmsg(int fd,struct msghdr *msg,int flags)
{
    assert(fd==(side?61:60)&&msg->msg_iovlen==1&&msg->msg_iov[0].iov_len==8);
    assert(flags==(MSG_DONTWAIT|MSG_TRUNC|MSG_CMSG_CLOEXEC));++receives;
    assert(msg->msg_control==NULL&&msg->msg_controllen==0);
    memcpy(msg->msg_iov[0].iov_base,side?"RNRKGO01":"RNRKARM1",8);
    if(gate_fault==16){errno=EAGAIN;return -1;}
    if(gate_fault==17)return 0;
    if(gate_fault==18)return 7;
    if(gate_fault==19){memcpy(msg->msg_iov[0].iov_base,"WRONG001",8);}
    if(gate_fault==20)msg->msg_flags=MSG_TRUNC;
    if(gate_fault==21)msg->msg_flags=MSG_CTRUNC;
    if(gate_fault==22)boot+=15000000000LL;
    return 8;
}
static int gate_admission(struct rnr_stage0_admission_error *e)
{++admitted;memset(e,0,sizeof(*e));if(gate_fault==29){e->code=RNR_STAGE0_ADMISSION_INPUT;e->system_errno=EBADF;return -1;}return 0;}
static int gate_close(int fd)
{
    if(fd==50)return 0;
    assert(fd==60||fd==61);++gate_closes;
    if(gate_fault==23){errno=EINTR;return -1;}return 0;
}
static _Noreturn void gate_exit(int code){exit_status=code;longjmp(exited,1);}

int main(void)
{
    static struct rnr_stage0_clock s;
    static struct rnr_stage0_clock_error e;
    static struct rnr_stage0_fork_result result;
    gate_reset(0);s=prepared();
    assert(rnr_stage0_clock_fork(&s,&result,&e)==1);
    assert(s.phase==RNR_STAGE0_CLOCK_NEGATIVE&&s.fork_attempted==1);
    assert(result.child_pid==101&&result.child_pidfd==62&&result.child_armed==1);
    assert(result.fork_entered==1&&result.fork_returned==1&&gate_closes==1);
    assert(s.pid==100&&s.captured_boottime_ns==1000000000000LL);
    assert(rnr_stage0_clock_abandon_gate(&s,&result,&e)==0&&gate_closes==2);
    assert(result.child_pidfd==62&&result.child_pid==101);
    assert(rnr_stage0_clock_abandon_gate(&s,&result,&e)==-1&&gate_closes==2);
    assert(rnr_stage0_clock_bind_cutoff(&s,wall+90000000000LL,&e)==-1);
    assert(s.phase==RNR_STAGE0_CLOCK_FAILED);

    gate_reset(1);s=prepared();boot+=2;wall+=2;
    assert(rnr_stage0_clock_fork(&s,&result,&e)==0);
    assert(s.phase==RNR_STAGE0_CLOCK_PREPARING&&s.pid==101&&s.tid==101);
    assert(s.fork_attempted==1&&s.captured_boottime_ns==1000000000000LL);
    assert(s.sampled_wall_ns==1700000000000000000LL&&s.last_boottime_ns==boot&&s.last_wall_ns==wall);
    assert(s.setup_end_ns==1015000000000LL&&s.deadline_boottime_ns==1120000000000LL);
    assert(sends==1&&receives==1&&gate_closes==2);
    assert(rnr_stage0_clock_fork(&s,&result,&e)==-1&&attempts==1);

    for(int fault=1;fault<=29;++fault){
        for(int child=0;child<=1;++child){
            if((!child&&((fault>=6&&fault<=8)||fault==14||fault==15||(fault>=24&&fault<=28)))||(child&&fault==9))continue;
            gate_reset(child);s=prepared();gate_fault=fault;
            if(!setjmp(exited)){
                int value=rnr_stage0_clock_fork(&s,&result,&e);
                assert(value==-1);assert(s.phase==RNR_STAGE0_CLOCK_FAILED);
                if(child&&attempts==1&&fault!=5)assert(0); /* postfork child NEVER returns failure */
            }else{assert(child&&exit_status==125);}
            assert(s.fork_attempted==1);
            int before=attempts;
            assert(rnr_stage0_clock_fork(&s,&result,&e)==-1&&attempts==before);
        }
    }
    return 0;
}
