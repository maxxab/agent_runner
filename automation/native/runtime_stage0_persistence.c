/* Uninvoked storage-only prerequisite. No keeper disk I/O or release authority. */
#define _GNU_SOURCE
#include "runtime_stage0_persistence.h"
#ifdef RNR_STAGE0_PRIVATE_QUALIFICATION
#if RNR_STAGE0_PRIVATE_QUALIFICATION != 1
#error "private qualification must equal 1"
#endif
#include "runtime_stage0_records.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <unistd.h>

enum { NEW, ACQUIRING, HELD, FENCED_ACQUIRING, FENCED_HELD, DRAINING, DRAINED };
enum { DIRECTORIES=7, INSTANCE=7, LATCH=8, CLAIM=9, ROLES=10, MAX_BINDING=131840 };
static atomic_int persistence_phase=ATOMIC_VAR_INIT(NEW);
static _Atomic pid_t persistence_pid;
static struct {
    int fds[ROLES], temporary;
    struct stat identities[ROLES];
    uint64_t mounts[ROLES];
    struct rnr_stage0_installation installation;
    char project[65], task[33];
    struct rnr_stage0_persistence_error observations;
} persistence;

static void reject(struct rnr_stage0_persistence_error *e,
                   enum rnr_stage0_persistence_code code,int failure)
{if(e->code==RNR_STAGE0_PERSISTENCE_OK){e->code=code;e->system_errno=failure;}}
static void fence(void)
{
    int p=atomic_load(&persistence_phase);
    for(;;){
        int next=p==NEW?DRAINED:p==ACQUIRING?FENCED_ACQUIRING:p==HELD?FENCED_HELD:p;
        if(next==p||atomic_compare_exchange_weak(&persistence_phase,&p,next))return;
    }
}
static int live(struct rnr_stage0_persistence_error *e)
{
    if(atomic_load(&persistence_phase)!=ACQUIRING){
        reject(e,RNR_STAGE0_PERSISTENCE_ATTEMPT,0);return -1;
    }
    if(getpid()!=atomic_load(&persistence_pid)||gettid()!=getpid()||geteuid()!=0||getegid()!=0){
        reject(e,RNR_STAGE0_PERSISTENCE_OWNER,0);return -1;
    }
    if(rnr_stage0_check_admission_preparation(&e->launch)!=0){
        reject(e,RNR_STAGE0_PERSISTENCE_CLOCK,e->launch.system_errno);return -1;
    }
    return 0;
}
static uint64_t le(const unsigned char *p,unsigned int n)
{uint64_t v=0;for(unsigned int j=0;j<n;++j)v|=(uint64_t)p[j]<<(j*8);return v;}
static int zero(const unsigned char *p,size_t n)
{for(size_t j=0;j<n;++j)if(p[j])return 0;return 1;}
static void hex(char *out,const unsigned char *raw,size_t n)
{const char digits[]="0123456789abcdef";for(size_t j=0;j<n;++j){out[2*j]=digits[raw[j]>>4];out[2*j+1]=digits[raw[j]&15];}out[n*2]=0;}
static int overlap(const void *a,size_t n,const void *b,size_t m)
{
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return n>UINTPTR_MAX-x||m>UINTPTR_MAX-y||(x<y+m&&y<x+n);
}
static int binding(const unsigned char *raw,size_t size)
{
    if(!raw||size<770||size>MAX_BINDING||memcmp(raw,"RNRBIND1",8)||
       le(raw+8,4)!=1||le(raw+12,4)!=size||le(raw+220,4)!=448||
       !zero(raw+232,24))return -1;
    size_t task_size=(size_t)le(raw+224,4),policy_size=(size_t)le(raw+228,4);
    if(task_size<65||task_size>65600||policy_size<1||policy_size>65536||
       size!=256+448+task_size+policy_size)return -1;
    /* Every PID/start/clock/inode field is positive signed64 DATA only. */
    for(unsigned int off=80;off<=176;off+=8)
        if(!le(raw+off,8)||le(raw+off,8)>INT64_MAX)return -1;
    struct rnr_stage0_task task;
    struct rnr_stage0_launch_declaration declaration;
    struct rnr_stage0_installation *i=&persistence.installation;
    if(rnr_stage0_decode_installation(raw+256,448,i)!=0||i->version!=2||
       rnr_stage0_decode_task(raw+704,task_size,&task)!=0||
       rnr_stage0_decode_launch_declaration(task.payload,task.payload_bytes,&declaration)!=0||
       memcmp(raw+16,i->project_id,32)||memcmp(raw+48,i->store_instance,16)||
       memcmp(raw+64,task.task_id,16)||memcmp(raw+184,i->boot_id,36)||
       memcmp(declaration.allocation,task.task_id,16)||
       memcmp(declaration.asset_root,i->asset_root,32)||
       memcmp(declaration.execution_root,i->execution_root,32)||
       memcmp(i->runtime.root,i->execution_root,32)||
       le(raw+160,8)!=(uint64_t)task.wall_cutoff_ns)return -1;
    hex(persistence.project,i->project_id,32);hex(persistence.task,task.task_id,16);
    return 0;
}
static const char *name(int role)
{
    static const char *const names[]={"/","var","lib","rnr","projects"};
    return role<5?names[role]:role==5?persistence.project:role==6?"consumed":
        role==INSTANCE?"instance":role==LATCH?"active":persistence.task;
}
static int parent(int role)
{return role<DIRECTORIES?role-1:role==INSTANCE||role==LATCH?5:6;}
static void close_slot(int *slot,struct rnr_stage0_persistence_error *e)
{
    int fd=*slot;*slot=-1;
    if(fd>=0&&close(fd)!=0){
        int failure=errno;
        if(e->cleanup_count<11){unsigned int j=e->cleanup_count++;e->cleanup[j].fd=fd;e->cleanup[j].system_errno=failure;}
        reject(e,RNR_STAGE0_PERSISTENCE_CLEANUP,failure);
    }
}
static void drain(struct rnr_stage0_persistence_error *e)
{close_slot(&persistence.temporary,e);for(int j=ROLES-1;j>=0;--j)close_slot(&persistence.fds[j],e);}
static int metadata(int fd,struct stat *s,uint64_t *mount,struct rnr_stage0_persistence_error *e)
{
    if(live(e)!=0)return -1;
    int result=fstat(fd,s),failure=result<0?errno:0;
    if(live(e)!=0)return -1;
    if(result!=0){reject(e,RNR_STAGE0_PERSISTENCE_IDENTITY,failure);return -1;}
    struct statx x={0};
    if(live(e)!=0)return -1;
    result=statx(fd,"",AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW,STATX_MNT_ID,&x);failure=result<0?errno:0;
    if(live(e)!=0)return -1;
    if(result!=0||!(x.stx_mask&STATX_MNT_ID)||!x.stx_mnt_id){
        reject(e,RNR_STAGE0_PERSISTENCE_IDENTITY,failure);return -1;
    }
    *mount=x.stx_mnt_id;return 0;
}
static int same(const struct stat *a,const struct stat *b,int directory)
{
    return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_mode==b->st_mode&&
        a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&a->st_rdev==b->st_rdev&&
        (directory||(a->st_nlink==b->st_nlink&&a->st_size==b->st_size&&
        a->st_mtim.tv_sec==b->st_mtim.tv_sec&&a->st_mtim.tv_nsec==b->st_mtim.tv_nsec&&
        a->st_ctim.tv_sec==b->st_ctim.tv_sec&&a->st_ctim.tv_nsec==b->st_ctim.tv_nsec));
}
static int opened(int role,int flags,int *slot,struct rnr_stage0_persistence_error *e)
{
    if(live(e)!=0)return -1;
    int p=parent(role);
    int fd=p<0?open("/",flags):openat(persistence.fds[p],name(role),flags);
    int failure=fd<0?errno:0;
    *slot=fd; /* Adopt returned handle before clock/metadata checks. */
    if(live(e)!=0)return -1;
    if(fd<0){reject(e,RNR_STAGE0_PERSISTENCE_OPEN,failure);return -1;}
    if(fd<3||fd==4){reject(e,RNR_STAGE0_PERSISTENCE_IDENTITY,0);return -1;}
    return 0;
}
static int capture(int role,struct rnr_stage0_persistence_error *e)
{
    struct stat *s=&persistence.identities[role];
    if(metadata(persistence.fds[role],s,&persistence.mounts[role],e)!=0)return -1;
    if(s->st_uid||s->st_gid||!s->st_ino||
       (role<DIRECTORIES?(!S_ISDIR(s->st_mode)||(s->st_mode&022)||
        (role>=5&&(s->st_mode&07777)!=0700)):
        (!S_ISREG(s->st_mode)||s->st_nlink!=1||(s->st_mode&07777)!=(role==INSTANCE?0400:0600)||
         s->st_size!=(role==INSTANCE?128:0)))){
        reject(e,RNR_STAGE0_PERSISTENCE_IDENTITY,0);return -1;
    }
    if(role>=INSTANCE){int p=parent(role);
        if(s->st_dev!=persistence.identities[p].st_dev||persistence.mounts[role]!=persistence.mounts[p]){
            reject(e,RNR_STAGE0_PERSISTENCE_IDENTITY,0);return -1;
        }
    }
    return 0;
}
static int recheck(int role,struct rnr_stage0_persistence_error *e)
{
    struct stat s;uint64_t mount;
    if(metadata(persistence.fds[role],&s,&mount,e)!=0)return -1;
    if(!same(&s,&persistence.identities[role],role<DIRECTORIES)||mount!=persistence.mounts[role])goto bad;
    if(opened(role,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC|(role<DIRECTORIES?O_DIRECTORY:0),
              &persistence.temporary,e)!=0)return -1;
    if(metadata(persistence.temporary,&s,&mount,e)!=0)return -1;
    if(!same(&s,&persistence.identities[role],role<DIRECTORIES)||mount!=persistence.mounts[role])goto bad;
    close_slot(&persistence.temporary,e);
    return e->code==RNR_STAGE0_PERSISTENCE_OK?live(e):-1;
bad:reject(e,RNR_STAGE0_PERSISTENCE_IDENTITY,0);return -1;
}
static int filesystem(int role,struct statfs *s,struct rnr_stage0_persistence_error *e)
{
    if(live(e)!=0)return -1;
    int result=fstatfs(persistence.fds[role],s),failure=result<0?errno:0;
    if(live(e)!=0)return -1;
    if(result!=0||s->f_type!=0xef53||(s->f_flags&ST_RDONLY)){
        reject(e,RNR_STAGE0_PERSISTENCE_IDENTITY,failure);return -1;
    }
    return 0;
}
static int store_identity(struct rnr_stage0_persistence_error *e)
{
    struct statfs project,consumed;
    struct rnr_stage0_installation *i=&persistence.installation;
    if(filesystem(5,&project,e)!=0||filesystem(6,&consumed,e)!=0)return -1;
    if(persistence.identities[5].st_dev!=persistence.identities[6].st_dev||
       persistence.mounts[5]!=persistence.mounts[6]||
       memcmp(&project.f_fsid,&consumed.f_fsid,sizeof(project.f_fsid))||
       (uint64_t)persistence.identities[6].st_dev!=i->store_device||
       (uint64_t)persistence.identities[6].st_ino!=i->store_inode||
       memcmp(&consumed.f_fsid,i->filesystem_id,8)){
        reject(e,RNR_STAGE0_PERSISTENCE_IDENTITY,0);return -1;
    }
    return 0;
}
static int instance(struct rnr_stage0_persistence_error *e)
{
    unsigned char raw[128],extra;
    struct rnr_stage0_installation *i=&persistence.installation;
    if(live(e)!=0)return -1;
    ssize_t n=pread(persistence.fds[INSTANCE],raw,128,0);int failure=n<0?errno:0;
    if(live(e)!=0)return -1;
    if(n!=128){reject(e,RNR_STAGE0_PERSISTENCE_READ,failure);return -1;}
    if(live(e)!=0)return -1;
    n=pread(persistence.fds[INSTANCE],&extra,1,128);failure=n<0?errno:0;
    if(live(e)!=0)return -1;
    if(n!=0){reject(e,RNR_STAGE0_PERSISTENCE_READ,failure);return -1;}
    if(memcmp(raw,"RNRINST1",8)||le(raw+8,4)!=1||!zero(raw+12,4)||
       memcmp(raw+16,i->project_id,32)||memcmp(raw+48,i->store_instance,16)||
       le(raw+64,8)!=i->store_device||le(raw+72,8)!=i->store_inode||
       memcmp(raw+80,i->filesystem_id,8)||memcmp(raw+88,i->boot_id,36)||!zero(raw+124,4)){
        reject(e,RNR_STAGE0_PERSISTENCE_IDENTITY,0);return -1;
    }
    return recheck(INSTANCE,e);
}
static int recheck_originals(struct rnr_stage0_persistence_error *e)
{
    for(int j=0;j<=INSTANCE;++j)if(recheck(j,e)!=0)return -1;
    return store_identity(e);
}
static int create(int role,struct rnr_stage0_persistence_error *e)
{
    if(live(e)!=0)return -1;
    enum rnr_stage0_persistence_creation *disposition=role==LATCH?&e->latch:&e->claim;
    *disposition=RNR_STAGE0_PERSISTENCE_UNKNOWN;
    int fd=openat(persistence.fds[parent(role)],name(role),
        O_WRONLY|O_CREAT|O_EXCL|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC,0600);
    int failure=fd<0?errno:0;
    persistence.fds[role]=fd;
    *disposition=fd>=0?RNR_STAGE0_PERSISTENCE_CREATED:failure==EEXIST?
        RNR_STAGE0_PERSISTENCE_COLLISION:RNR_STAGE0_PERSISTENCE_UNKNOWN;
    if(live(e)!=0)return -1;
    if(fd<0){reject(e,RNR_STAGE0_PERSISTENCE_CREATE,failure);return -1;}
    if(fd<3||fd==4){reject(e,RNR_STAGE0_PERSISTENCE_IDENTITY,0);return -1;}
    return capture(role,e);
}
static int persist(int role,const unsigned char *raw,size_t size,struct rnr_stage0_persistence_error *e)
{
    unsigned int base=role==LATCH?0:3;
    for(unsigned int step=0;step<3;++step){
        unsigned int index=base+step;
        if(live(e)!=0)return -1;
        e->entered|=1U<<index;
        long result=step==0?(long)pwrite(persistence.fds[role],raw,size,0):
            fsync(persistence.fds[step==1?role:parent(role)]);
        int failure=result<0?errno:0;
        e->returned|=1U<<index;e->results[index]=result;e->operation_errno[index]=failure;
        if(live(e)!=0)return -1;
        if(result!=(step==0?(long)size:0)){
            reject(e,step==0?RNR_STAGE0_PERSISTENCE_WRITE:RNR_STAGE0_PERSISTENCE_SYNC,failure);return -1;
        }
    }
    /* File size/timestamps change from our one write; identity/mode may not. */
    struct stat s;uint64_t mount;
    if(metadata(persistence.fds[role],&s,&mount,e)!=0)return -1;
    struct stat expected=persistence.identities[role];
    expected.st_size=s.st_size;expected.st_mtim=s.st_mtim;expected.st_ctim=s.st_ctim;
    if(s.st_size!=(off_t)size||!same(&s,&expected,0)||mount!=persistence.mounts[role]){
        reject(e,RNR_STAGE0_PERSISTENCE_IDENTITY,0);return -1;
    }
    persistence.identities[role]=s;
    return recheck(role,e);
}
int rnr_stage0_prepare_persistent_claim(const unsigned char *raw,size_t size,struct rnr_stage0_persistence_error *e)
{
    int expected=NEW;
    if(!e){fence();errno=EINVAL;return -1;}
    if(raw&&overlap(raw,size,e,sizeof(*e))){fence();errno=EINVAL;return -1;}
    *e=(struct rnr_stage0_persistence_error){0};
    if(!atomic_compare_exchange_strong(&persistence_phase,&expected,ACQUIRING)){
        reject(e,RNR_STAGE0_PERSISTENCE_ATTEMPT,0);fence();return -1;
    }
    for(int j=0;j<ROLES;++j)persistence.fds[j]=-1;
    persistence.temporary=-1;
    atomic_store(&persistence_pid,getpid());
    if(live(e)!=0)goto failed;
    if(binding(raw,size)!=0){reject(e,RNR_STAGE0_PERSISTENCE_BINDING,0);goto failed;}
    for(int j=0;j<DIRECTORIES;++j)
        if(opened(j,O_RDONLY|O_DIRECTORY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC,&persistence.fds[j],e)!=0||capture(j,e)!=0)goto failed;
    if(store_identity(e)!=0||opened(INSTANCE,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC,&persistence.fds[INSTANCE],e)!=0||
       capture(INSTANCE,e)!=0||instance(e)!=0||recheck_originals(e)!=0)goto failed;
    if(create(LATCH,e)!=0||persist(LATCH,raw,size,e)!=0||recheck_originals(e)!=0||
       create(CLAIM,e)!=0||persist(CLAIM,raw,size,e)!=0||recheck_originals(e)!=0||
       recheck(LATCH,e)!=0||recheck(CLAIM,e)!=0||live(e)!=0)goto failed;
    expected=ACQUIRING;
    if(!atomic_compare_exchange_strong(&persistence_phase,&expected,HELD)){
        reject(e,RNR_STAGE0_PERSISTENCE_ATTEMPT,0);goto failed;
    }
    persistence.observations=*e;
    return 0;
failed:
    fence();drain(e);persistence.observations=*e;
    atomic_store(&persistence_phase,DRAINED);
    return -1;
}
int rnr_stage0_abandon_persistent_claim(struct rnr_stage0_persistence_error *e)
{
    if(!e){fence();errno=EINVAL;return -1;}
    *e=(struct rnr_stage0_persistence_error){0};
    if(getpid()!=atomic_load(&persistence_pid)||gettid()!=getpid()||geteuid()!=0||getegid()!=0){
        reject(e,RNR_STAGE0_PERSISTENCE_OWNER,0);fence();return -1;
    }
    int phase=atomic_load(&persistence_phase);
    for(;;){
        if(phase!=HELD&&phase!=FENCED_HELD){reject(e,RNR_STAGE0_PERSISTENCE_ATTEMPT,0);fence();return -1;}
        if(atomic_compare_exchange_weak(&persistence_phase,&phase,DRAINING))break;
    }
    *e=persistence.observations;
    drain(e);persistence.observations=*e;atomic_store(&persistence_phase,DRAINED);
    return e->code==RNR_STAGE0_PERSISTENCE_OK?0:-1;
}
#endif
