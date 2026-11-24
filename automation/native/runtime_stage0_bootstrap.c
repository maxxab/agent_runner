/* See the bootstrap privilege guard plan for the deliberately narrow theorem.
 * Kernel/source behavior and actual host acceptance require separate qualification. */
#define _GNU_SOURCE
#include "runtime_stage0_bootstrap.h"
#ifdef RNR_STAGE0_PRIVATE_QUALIFICATION
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/nsfs.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>
#if !defined(__linux__) || !defined(__x86_64__)
#error "Bootstrap observations require Linux x86-64"
#endif
enum bootstrap_phase {BOOTSTRAP_NEW,BOOTSTRAP_CHECKING,BOOTSTRAP_DONE,BOOTSTRAP_FENCED};
static atomic_int bootstrap_state=ATOMIC_VAR_INIT(BOOTSTRAP_NEW);
struct bootstrap_object {struct stat s;uint64_t mount;long fs;};
static struct {
    pid_t pid;
    int fds[9];
    struct bootstrap_object objects[9];
    char tgid[11],tid[11],thread_link[32];size_t thread_length;
} bootstrap_owner;
static void reject(struct rnr_stage0_bootstrap_error *e,enum rnr_stage0_bootstrap_code code,int failure)
{if(e->code==RNR_STAGE0_BOOTSTRAP_OK){e->code=code;e->system_errno=failure;}}
static int live(struct rnr_stage0_bootstrap_error *e)
{
    struct rnr_stage0_launch_error c;
    if(atomic_load_explicit(&bootstrap_state,memory_order_acquire)!=BOOTSTRAP_CHECKING){
        reject(e,RNR_STAGE0_BOOTSTRAP_ATTEMPT,0);return -1;
    }
    if(rnr_stage0_check_admission_preparation(&c)!=0)goto clock_failed;
    pid_t pid=getpid();
    if(pid<=0 || (bootstrap_owner.pid && pid!=bootstrap_owner.pid) ||
       syscall(SYS_gettid)!=(long)pid || getuid()!=0 || geteuid()!=0 || getgid()!=0 || getegid()!=0){
        reject(e,RNR_STAGE0_BOOTSTRAP_OWNER,0);return -1;
    }
    if(rnr_stage0_check_admission_preparation(&c)!=0)goto clock_failed;
    if(atomic_load_explicit(&bootstrap_state,memory_order_acquire)!=BOOTSTRAP_CHECKING){
        reject(e,RNR_STAGE0_BOOTSTRAP_ATTEMPT,0);return -1;
    }
    return 0;
clock_failed:
    if(e->clock.code==RNR_STAGE0_LAUNCH_OK)e->clock=c;
    reject(e,RNR_STAGE0_BOOTSTRAP_CLOCK,c.system_errno);return -1;
}
/* Preserve the initiating errno BEFORE the required post-call original-clock
 * check; terminal unwind may then close without further positive observations. */
static int failed_syscall(struct rnr_stage0_bootstrap_error *e,int failure)
{
    reject(e,RNR_STAGE0_BOOTSTRAP_SYSCALL,failure);
    (void)live(e);return -1;
}
static void close_slot(int *slot,struct rnr_stage0_bootstrap_error *e)
{
    int fd=*slot;if(fd<0)return;
    int checking=e->code==RNR_STAGE0_BOOTSTRAP_OK;
    if(checking&&live(e)!=0)checking=0;
    *slot=-1;
    if(close(fd)!=0){
        int failure=errno;
        if(e->cleanup_count<10){unsigned int n=e->cleanup_count++;
            e->cleanup_errors[n].fd=fd;e->cleanup_errors[n].system_errno=failure;}
        reject(e,RNR_STAGE0_BOOTSTRAP_CLEANUP,failure);
    }
    if(checking)(void)live(e);
}
static int acquire(int parent,const char *name,int role,int *slot,struct rnr_stage0_bootstrap_error *e)
{
    if(live(e)!=0)return -1;
    int flags=role==2||role==7?O_PATH|O_NOFOLLOW|O_CLOEXEC:
              role==8?O_RDONLY|O_CLOEXEC:O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC;
    int fd=parent<0?open(name,flags):openat(parent,name,flags);
    if(fd<0){return failed_syscall(e,errno);}
    if(fd<3){e->unadopted_fd=fd;reject(e,RNR_STAGE0_BOOTSTRAP_IDENTITY,0);(void)live(e);return -1;}
    *slot=fd;return live(e);
}
static int object(int fd,int role,struct bootstrap_object *o,struct rnr_stage0_bootstrap_error *e)
{
    struct statx x={0};struct statfs fs;
    if(live(e)!=0)return -1;
    if(fstat(fd,&o->s)!=0){return failed_syscall(e,errno);}
    if(live(e)!=0)return -1;
    if(statx(fd,"",AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW,STATX_MNT_ID,&x)!=0){
        return failed_syscall(e,errno);}
    if(live(e)!=0)return -1;
    if(fstatfs(fd,&fs)!=0){return failed_syscall(e,errno);}
    if(live(e)!=0)return -1;
    o->mount=x.stx_mnt_id;o->fs=fs.f_type;
    const struct stat *s=&o->s;
    if(!(x.stx_mask&STATX_MNT_ID)||!o->mount||!s->st_ino||s->st_uid||s->st_gid)goto identity;
    if(role==8){
        if(!S_ISREG(s->st_mode)||!s->st_dev||s->st_ino!=UINT64_C(0xeffffffd)||o->fs!=0x6e736673)goto identity;
        if(live(e)!=0)return -1;
        int kind=ioctl(fd,NS_GET_NSTYPE);
        if(kind<0){return failed_syscall(e,errno);}
        if(live(e)!=0)return -1;
        if(kind!=CLONE_NEWUSER)goto identity;
    }else{
        int link=role==2||role==7;
        if(link?!S_ISLNK(s->st_mode):(!S_ISDIR(s->st_mode)||(s->st_mode&022)))goto identity;
        if(role){
            if(o->fs!=0x9fa0)goto identity;
            if(role==1){if(s->st_ino!=1)goto identity;}
            else if(o->mount!=bootstrap_owner.objects[1].mount||s->st_dev!=bootstrap_owner.objects[1].s.st_dev)goto identity;
        }
    }
    return 0;
identity:
    reject(e,RNR_STAGE0_BOOTSTRAP_IDENTITY,0);return -1;
}
static int same(const struct bootstrap_object *a,const struct bootstrap_object *b,int role)
{
    const struct stat *x=&a->s,*y=&b->s;
    if(a->mount!=b->mount||a->fs!=b->fs||x->st_dev!=y->st_dev||x->st_ino!=y->st_ino||
       x->st_mode!=y->st_mode||x->st_uid!=y->st_uid||x->st_gid!=y->st_gid||
       x->st_rdev!=y->st_rdev||x->st_nlink!=y->st_nlink)return 0;
    return (role!=2&&role!=7&&role!=8)||(x->st_size==y->st_size&&
        x->st_mtim.tv_sec==y->st_mtim.tv_sec&&x->st_mtim.tv_nsec==y->st_mtim.tv_nsec&&
        x->st_ctim.tv_sec==y->st_ctim.tv_sec&&x->st_ctim.tv_nsec==y->st_ctim.tv_nsec);
}
static int read_link(int fd,char *b,size_t *length,struct rnr_stage0_bootstrap_error *e)
{
    if(live(e)!=0)return -1;
    ssize_t n=readlinkat(fd,"",b,32);
    if(n<0){return failed_syscall(e,errno);}
    if(live(e)!=0)return -1;
    if(n<=0||n>=32){reject(e,RNR_STAGE0_BOOTSTRAP_LINK,0);return -1;}
    *length=(size_t)n;return 0;
}
static int decimal(const char *b,size_t n,char *result,pid_t expected)
{
    if(!n||n>10||b[0]=='0')return -1;
    unsigned int value=0;
    for(size_t i=0;i<n;++i){
        if(b[i]<'0'||b[i]>'9')return -1;
        unsigned int digit=(unsigned int)(b[i]-'0');
        if(value>((unsigned int)INT_MAX-digit)/10)return -1;
        value=value*10+digit;
    }
    if(value!=(unsigned int)expected)return -1;
    memcpy(result,b,n);result[n]=0;return 0;
}
static int original_links(struct rnr_stage0_bootstrap_error *e)
{
    char b[32];size_t n;
    if(read_link(bootstrap_owner.fds[2],b,&n,e)!=0)return -1;
    size_t slash=0;while(slash<n&&b[slash]!='/')++slash;
    if(slash+6>=n||memcmp(b+slash,"/task/",6)||
       decimal(b,slash,bootstrap_owner.tgid,bootstrap_owner.pid)!=0||
       decimal(b+slash+6,n-slash-6,bootstrap_owner.tid,bootstrap_owner.pid)!=0){
        reject(e,RNR_STAGE0_BOOTSTRAP_LINK,0);return -1;
    }
    memcpy(bootstrap_owner.thread_link,b,n);bootstrap_owner.thread_length=n;return 0;
}
static int check_link(int fd,int role,struct rnr_stage0_bootstrap_error *e)
{
    char b[32];size_t n;static const char user[]="user:[4026531837]";
    if(read_link(fd,b,&n,e)!=0)return -1;
    const char *expected=role==2?bootstrap_owner.thread_link:user;
    size_t length=role==2?bootstrap_owner.thread_length:sizeof(user)-1;
    if(n!=length||memcmp(b,expected,n)){reject(e,RNR_STAGE0_BOOTSTRAP_LINK,0);return -1;}
    return 0;
}
static int recheck(int role,struct rnr_stage0_bootstrap_error *e)
{
    static const int parents[9]={-1,0,1,1,3,4,5,6,6};
    const char *names[9]={"/","proc","thread-self",bootstrap_owner.tgid,"task",bootstrap_owner.tid,"ns","user","user"};
    int fd=bootstrap_owner.fds[role],temporary=-1;
    struct bootstrap_object held,named;
    if(object(fd,role,&held,e)!=0)return -1;
    if(!same(&held,&bootstrap_owner.objects[role],role)){
        reject(e,RNR_STAGE0_BOOTSTRAP_IDENTITY,0);return -1;
    }
    if((role==2||role==7)&&check_link(fd,role,e)!=0)return -1;
    int parent=parents[role]<0?-1:bootstrap_owner.fds[parents[role]];
    if(acquire(parent,names[role],role,&temporary,e)!=0)goto done;
    if(object(temporary,role,&named,e)!=0)goto done;
    if(!same(&named,&bootstrap_owner.objects[role],role)){
        reject(e,RNR_STAGE0_BOOTSTRAP_IDENTITY,0);goto done;
    }
    if(role==2||role==7)(void)check_link(temporary,role,e);
done:
    close_slot(&temporary,e);return e->code==RNR_STAGE0_BOOTSTRAP_OK?0:-1;
}
int rnr_stage0_check_bootstrap(struct rnr_stage0_bootstrap_error *e)
{
    int expected=BOOTSTRAP_NEW;
    int claimed=atomic_compare_exchange_strong_explicit(&bootstrap_state,&expected,BOOTSTRAP_CHECKING,
                        memory_order_acq_rel,memory_order_acquire);
    if(!e){atomic_store(&bootstrap_state,BOOTSTRAP_FENCED);errno=EINVAL;return -1;}
    *e=(struct rnr_stage0_bootstrap_error){.unadopted_fd=-1};
    if(!claimed){atomic_store(&bootstrap_state,BOOTSTRAP_FENCED);reject(e,RNR_STAGE0_BOOTSTRAP_ATTEMPT,0);return -1;}
    for(int i=0;i<9;++i)bootstrap_owner.fds[i]=-1;
    if(live(e)!=0)goto done;
    bootstrap_owner.pid=getpid();
    if(live(e)!=0)goto done;
    if(acquire(-1,"/",0,&bootstrap_owner.fds[0],e)!=0||object(bootstrap_owner.fds[0],0,&bootstrap_owner.objects[0],e)!=0)goto done;
    if(acquire(bootstrap_owner.fds[0],"proc",1,&bootstrap_owner.fds[1],e)!=0||object(bootstrap_owner.fds[1],1,&bootstrap_owner.objects[1],e)!=0)goto done;
    if(acquire(bootstrap_owner.fds[1],"thread-self",2,&bootstrap_owner.fds[2],e)!=0||object(bootstrap_owner.fds[2],2,&bootstrap_owner.objects[2],e)!=0||original_links(e)!=0)goto done;
    const char *names[6]={bootstrap_owner.tgid,"task",bootstrap_owner.tid,"ns","user","user"};
    const int parents[6]={1,3,4,5,6,6};
    for(int role=3;role<9;++role){
        if(role==8&&recheck(7,e)!=0)goto done;
        if(acquire(bootstrap_owner.fds[parents[role-3]],names[role-3],role,&bootstrap_owner.fds[role],e)!=0||
           object(bootstrap_owner.fds[role],role,&bootstrap_owner.objects[role],e)!=0)goto done;
        if(role==7&&check_link(bootstrap_owner.fds[7],7,e)!=0)goto done;
        if(role==8&&recheck(7,e)!=0)goto done;
    }
    for(int role=0;role<9;++role){
        if(role==8&&recheck(7,e)!=0)goto done;
        if(recheck(role,e)!=0)goto done;
        if(role==8&&recheck(7,e)!=0)goto done;
    }
    (void)live(e);
done:
    for(int role=8;role>=0;--role)close_slot(&bootstrap_owner.fds[role],e);
    expected=BOOTSTRAP_CHECKING;
    int result=e->code==RNR_STAGE0_BOOTSTRAP_OK?BOOTSTRAP_DONE:BOOTSTRAP_FENCED;
    if(!atomic_compare_exchange_strong_explicit(&bootstrap_state,&expected,result,memory_order_release,memory_order_relaxed)){
        reject(e,RNR_STAGE0_BOOTSTRAP_ATTEMPT,0);return -1;
    }
    return result==BOOTSTRAP_DONE?0:-1;
}
#endif
