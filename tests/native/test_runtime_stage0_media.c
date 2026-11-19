/* Only fixed helper boundaries are exercised. All relevant kernel/clock
 * calls are mocked: no real fork, helper, protected read or host operation. */
#define _GNU_SOURCE
#include <assert.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "../../automation/native/runtime_stage0_preparer.h"
static int absent_result,absent_errno,absent_calls,clock_calls,clock_fail;
static int wait_calls,read_calls,poll_calls,scenario;
static size_t produced;
static int closed_ids[128],close_calls;
static int fixture_close(int);
static int fixture_absence(int,const char *,struct stat *,int);
static int fixture_clock(struct rnr_stage0_launch_error *);
static ssize_t fixture_read(int,void *,size_t);
static pid_t fixture_wait(pid_t,int *,int);
static int fixture_poll(struct pollfd *,nfds_t,int);
#define close(d) fixture_close(d)
#define fstatat(d,p,s,f) fixture_absence(d,p,s,f)
#define read(d,p,n) fixture_read(d,p,n)
#define waitpid(p,s,f) fixture_wait(p,s,f)
#define poll(p,n,t) fixture_poll(p,n,t)
#define rnr_stage0_check_operational_preparation(e) fixture_clock(e)
#include "../../automation/native/runtime_stage0_preparer.c"
#undef fstatat
#undef read
#undef waitpid
#undef poll
#undef rnr_stage0_check_operational_preparation
static int fixture_close(int fd)
{assert(fd>=3&&fd<128&&!closed_ids[fd]);closed_ids[fd]=1;++close_calls;errno=EINTR;return -1;}
static int fixture_clock(struct rnr_stage0_launch_error *e)
{(void)e;return ++clock_calls==clock_fail?-1:0;}
static int fixture_absence(int fd,const char *name,struct stat *s,int flags)
{
    memset(s,0,sizeof(*s));assert(fd==input_owner.journal_fds[1]);assert(flags==AT_SYMLINK_NOFOLLOW);
    assert(!strcmp(name,"launch.squashfs")||!strcmp(name,"launch.verity")||!strcmp(name,"launch.root"));
    ++absent_calls;errno=absent_errno;return absent_result;
}
static ssize_t fixture_read(int fd,void *p,size_t n)
{
    assert(fd==100||fd==101);assert(n>0&&n<=4096);++read_calls;
    if(scenario==2){errno=EINTR;return -1;}
    if(scenario==3||scenario==4||scenario==8||scenario==14||scenario==15){errno=EAGAIN;return -1;}
    if(scenario==13)return (ssize_t)n+1;
    size_t cap=scenario==1?65537:scenario==5?65536:0;
    size_t take=cap-produced;if(take>n)take=n;
    memset(p,0,take);produced+=take;return (ssize_t)take;
}
static pid_t fixture_wait(pid_t p,int *s,int flags)
{
    assert(p==123&&flags==WNOHANG&&input_owner.media_steps[40].entered);++wait_calls;
    if(scenario==3||(scenario==10&&wait_calls<4))return 0;
    if(scenario==11)clock_fail=clock_calls+1;
    if(scenario==12)return 124;
    if(scenario==6){errno=EINTR;return -1;}
    *s=scenario==7?256:0;return 123;
}
static int fixture_poll(struct pollfd *p,nfds_t n,int t)
{
    assert(n>=1&&n<=3&&t==1);++poll_calls;
    for(nfds_t j=0;j<n;++j){assert(p[j].events==POLLIN);p[j].revents=scenario==8?POLLERR:0;}
    if(scenario==14){errno=EINTR;return -1;}
    if(scenario==15)return (int)n+1;
    return scenario==8?1:0;
}
static void reset_media(void)
{
    input_owner=(struct preparer_owner){0};
    for(int j=0;j<12;++j)input_owner.media_fds[j]=-1;
    input_owner.media_fds[7]=102;input_owner.media_fds[8]=100;input_owner.media_fds[10]=101;
    input_owner.child_pid=123;
    atomic_store(&preparer_state,PREPARER_MEDIA_ACQUIRING);
    clock_calls=clock_fail=absent_calls=wait_calls=read_calls=poll_calls=0;produced=0;
}
int main(void)
{
    struct rnr_stage0_preparer_error e;
    for(int helper=0;helper<2;++helper)for(int outcome=0;outcome<5;++outcome){
        reset_media();e=(struct rnr_stage0_preparer_error){0};
        absent_result=outcome==1?0:-1;
        absent_errno=outcome==0?ENOENT:outcome==2?EACCES:outcome==3?EIO:EINTR;
        assert((media_absent(helper,&e)==0)==(outcome==0));
        assert(absent_calls==(outcome==0?helper+1:1));
    }
    for(scenario=0;scenario<=15;++scenario){
        reset_media();e=(struct rnr_stage0_preparer_error){0};
        assert((media_collect(&e)==0)==(scenario==0||scenario==5||scenario==9||scenario==10));
        if(scenario!=3&&scenario!=10)assert(wait_calls<=1);
        if(scenario==11)assert(input_owner.child_reaped&&input_owner.child_status==0);
        if(scenario==4){assert(input_owner.child_reaped);assert(wait_calls==1);}
        assert(produced<=65537&&poll_calls<=15000);
    }
    scenario=5;reset_media();e=(struct rnr_stage0_preparer_error){0};
    assert(media_collect(&e)==0);int clocks=clock_calls;
    for(int i=1;i<=clocks;++i){reset_media();clock_fail=i;e=(struct rnr_stage0_preparer_error){0};
        assert(media_collect(&e)==-1&&wait_calls<=1);}
    reset_media();input_owner.media_initialized=1;int fd=3;
    for(int j=0;j<5;++j)input_owner.fds[j]=fd++;
    input_owner.view_count=22;for(int j=0;j<22;++j)input_owner.view_fds[j]=fd++;
    input_owner.journal_count=3;for(int j=0;j<3;++j)input_owner.journal_fds[j]=fd++;
    input_owner.runtime_count=15;for(int j=0;j<15;++j)input_owner.runtime_fds[j]=fd++;
    for(int j=0;j<12;++j)input_owner.media_fds[j]=(j==3||j==4)?-1:fd++;
    int temporary=fd;e=(struct rnr_stage0_preparer_error){0};
    close_input(&temporary,&e);drain_inputs(&e);
    assert(e.cleanup_count==56&&!e.cleanup_overflow&&close_calls==56&&temporary==-1);
    drain_inputs(&e);assert(close_calls==56);
    return 0;
}
