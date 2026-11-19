/* Dormant fixed handoff profiles: NO main, Store, fork or root setup.
 * Public Python destinations remain disabled. The immutable authenticated root,
 * interpreter/import TCB and original launch authority are external gates.
 */
#define _GNU_SOURCE
#include "runtime_stage0_launch.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* Separate externally selected binary; never a runtime argument or wire mode.
 * This profile is NOT INVOCABLE until the complete private Python lifecycle,
 * immutable closure and independent original-deadline supervisor are reviewed.
 */
#if defined(RNR_STAGE0_PRIVATE_QUALIFICATION) && RNR_STAGE0_PRIVATE_QUALIFICATION != 1
#error "RNR_STAGE0_PRIVATE_QUALIFICATION must be absent or exactly 1"
#endif

enum { HEADER_BYTES=144, PREFIX_BYTES=16, MAX_PAYLOAD=65536, CHUNK_BYTES=32768 };
enum launch_phase { LAUNCH_NEW, LAUNCH_PREPARING, LAUNCH_PREPARED, LAUNCH_CHECKING,
                    LAUNCH_FINISHING, LAUNCH_FENCED };
enum launch_mode { LAUNCH_VALIDATION, LAUNCH_OPERATIONAL };
static atomic_int launch_state = ATOMIC_VAR_INIT(LAUNCH_NEW);
/* Published only after prepare succeeds; exclusively used by winning stages.
 * Losing callers touch neither this clock nor another caller's error buffer. */
static struct rnr_stage0_clock prepared_clock;
static enum launch_mode prepared_mode;
static int64_t prepared_cutoff; /* Original task data, never a clock origin. */
static const int required_seals = F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL;

static void reject_launch(struct rnr_stage0_launch_error *e,
                          enum rnr_stage0_launch_code code, int system_errno)
{
    if(e->code==RNR_STAGE0_LAUNCH_OK){e->code=code;e->system_errno=system_errno;}
}
static void close_owned(int *fd, struct rnr_stage0_launch_error *e)
{
    int owned=*fd;*fd=-1;
    if(owned>=0&&close(owned)!=0){
        int failure=errno;
        e->cleanup_errno=failure;
        reject_launch(e,RNR_STAGE0_LAUNCH_CLEANUP,failure);
    }
}
static uint64_t decode_u64(const unsigned char *p)
{
    uint64_t value=0;
    for(unsigned int i=0;i<8;++i)value|=(uint64_t)p[i]<<(8*i);
    return value;
}
static void encode_u64(unsigned char *p,uint64_t value)
{
    for(unsigned int i=0;i<8;++i)p[i]=(unsigned char)(value>>(8*i));
}
static int same_file(const struct stat *a,const struct stat *b)
{
    return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_mode==b->st_mode&&
        a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&a->st_nlink==b->st_nlink&&
        a->st_size==b->st_size&&a->st_mtim.tv_sec==b->st_mtim.tv_sec&&
        a->st_mtim.tv_nsec==b->st_mtim.tv_nsec&&a->st_ctim.tv_sec==b->st_ctim.tv_sec&&
        a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;
}
static int phase_live(struct rnr_stage0_launch_error *e,enum launch_phase phase)
{
    if(atomic_load_explicit(&launch_state,memory_order_acquire)==(int)phase)return 0;
    reject_launch(e,RNR_STAGE0_LAUNCH_ATTEMPT,0);
    return -1;
}
static int launch_live(struct rnr_stage0_launch_error *e)
{return phase_live(e,LAUNCH_FINISHING);}
/* Never reset a recorded launch or clock failure during cleanup. */
static int check_preparation(struct rnr_stage0_clock *clock, struct rnr_stage0_launch_error *e)
{
    struct rnr_stage0_clock_error failure={0};
    if(launch_live(e)!=0)return -1;
    if(rnr_stage0_clock_check_setup(clock,&failure)==0)return launch_live(e);
    e->final=failure;
    reject_launch(e,RNR_STAGE0_LAUNCH_CLOCK,failure.system_errno);
    return -1;
}
static int read_launch(unsigned char *payload,size_t *size,int64_t *cutoff,
                       struct rnr_stage0_clock *clock, struct rnr_stage0_launch_error *e)
{
    unsigned char raw[PREFIX_BYTES+MAX_PAYLOAD],extra;
    struct stat first,last;
    int fd=-1;
    if(check_preparation(clock,e)!=0)return -1;
    fd=open("/rnr/launch.bin",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0){reject_launch(e,RNR_STAGE0_LAUNCH_CONFIG,errno);return -1;}
    if(check_preparation(clock,e)!=0)goto done;
    if(fstat(fd,&first)!=0){reject_launch(e,RNR_STAGE0_LAUNCH_CONFIG,errno);goto done;}
    if(check_preparation(clock,e)!=0)goto done;
    if(!S_ISREG(first.st_mode)||(first.st_mode&07777)!=0444||first.st_uid!=0||
        first.st_gid!=0||first.st_nlink!=1||first.st_size<=PREFIX_BYTES||
        first.st_size>PREFIX_BYTES+MAX_PAYLOAD){
        reject_launch(e,RNR_STAGE0_LAUNCH_CONFIG,0);goto done;
    }
    for(size_t offset=0;offset<(size_t)first.st_size;){
        size_t count=(size_t)first.st_size-offset;
        if(count>CHUNK_BYTES)count=CHUNK_BYTES;
        if(check_preparation(clock,e)!=0)goto done;
        ssize_t amount=pread(fd,raw+offset,count,(off_t)offset);
        if(amount<0){reject_launch(e,RNR_STAGE0_LAUNCH_CONFIG,errno);goto done;}
        if(check_preparation(clock,e)!=0)goto done;
        if((size_t)amount!=count){reject_launch(e,RNR_STAGE0_LAUNCH_CONFIG,0);goto done;}
        offset+=count;
    }
    if(check_preparation(clock,e)!=0)goto done;
    ssize_t amount=pread(fd,&extra,1,first.st_size);
    if(amount<0){reject_launch(e,RNR_STAGE0_LAUNCH_CONFIG,errno);goto done;}
    if(check_preparation(clock,e)!=0)goto done;
    if(amount!=0){reject_launch(e,RNR_STAGE0_LAUNCH_CONFIG,0);goto done;}
    if(fstat(fd,&last)!=0){reject_launch(e,RNR_STAGE0_LAUNCH_CONFIG,errno);goto done;}
    if(check_preparation(clock,e)!=0)goto done;
    uint64_t wall=decode_u64(raw+8);
    if(!same_file(&first,&last)||memcmp(raw,"RNRL0001",8)!=0||wall==0||wall>INT64_MAX){
        reject_launch(e,RNR_STAGE0_LAUNCH_CONFIG,0);goto done;
    }
    *cutoff=(int64_t)wall;*size=(size_t)first.st_size-PREFIX_BYTES;
    memcpy(payload,raw+PREFIX_BYTES,*size);
done:
    if(e->code==RNR_STAGE0_LAUNCH_OK)(void)check_preparation(clock,e);
    close_owned(&fd,e);
    if(e->code==RNR_STAGE0_LAUNCH_OK)(void)check_preparation(clock,e);
    return e->code==RNR_STAGE0_LAUNCH_OK?0:-1;
}
static int encode_context(unsigned char *raw,size_t payload_size,const struct rnr_stage0_clock *s)
{
    if(payload_size==0||payload_size>MAX_PAYLOAD||s->phase!=RNR_STAGE0_CLOCK_ACTIVE||
        s->admission_attempted!=1||s->pid<=0||s->tid!=s->pid||
        (uintmax_t)s->pid>INT32_MAX||s->boot_id[36]!=0)return -1;
    for(int i=0;i<36;++i){
        int dash=i==8||i==13||i==18||i==23;
        if(dash?s->boot_id[i]!='-':!((s->boot_id[i]>='0'&&s->boot_id[i]<='9')||
            (s->boot_id[i]>='a'&&s->boot_id[i]<='f')))return -1;
    }
    if(s->time_ns_device==0||s->time_ns_device>INT64_MAX||
        s->time_ns_inode==0||s->time_ns_inode>INT64_MAX||
        s->captured_boottime_ns<=0||s->sampled_wall_ns<=0||
        s->wall_deadline_ns<=s->sampled_wall_ns)return -1;
    int64_t delta=s->wall_deadline_ns-s->sampled_wall_ns;
    if(delta>120000000000LL||s->captured_boottime_ns>INT64_MAX-delta||
        s->deadline_boottime_ns!=s->captured_boottime_ns+delta||
        s->setup_end_ns!=s->captured_boottime_ns+(delta<15000000000LL?delta:15000000000LL)||
        s->last_boottime_ns<s->captured_boottime_ns||s->last_boottime_ns>=s->setup_end_ns||
        s->last_wall_ns<s->sampled_wall_ns||s->last_wall_ns>=s->wall_deadline_ns)return -1;
    const uint64_t values[]={s->time_ns_device,s->time_ns_inode,
        (uint64_t)s->captured_boottime_ns,(uint64_t)s->sampled_wall_ns,
        (uint64_t)s->wall_deadline_ns,(uint64_t)s->deadline_boottime_ns,
        (uint64_t)s->setup_end_ns,(uint64_t)s->last_boottime_ns,(uint64_t)s->last_wall_ns};
    memset(raw,0,HEADER_BYTES);memcpy(raw,"RNRH0001",8);
    for(unsigned int i=0;i<4;++i)raw[8+i]=(unsigned char)(payload_size>>(8*i));
    encode_u64(raw+16,(uint64_t)s->pid);encode_u64(raw+24,(uint64_t)s->tid);
    memcpy(raw+32,s->boot_id,36);
    for(unsigned int i=0;i<9;++i)encode_u64(raw+72+8*i,values[i]);
    return 0;
}
static int write_part(int fd,const unsigned char *p,size_t count,off_t offset,
                      struct rnr_stage0_launch_error *e)
{
    if(launch_live(e)!=0)return -1;
    ssize_t amount=pwrite(fd,p,count,offset);
    if(amount<0){reject_launch(e,RNR_STAGE0_LAUNCH_CONTEXT,errno);return -1;}
    if((size_t)amount!=count){reject_launch(e,RNR_STAGE0_LAUNCH_CONTEXT,0);return -1;}
    return 0;
}
static int verify_context(int fd,size_t size,struct rnr_stage0_launch_error *e)
{
    struct stat info;
    if(launch_live(e)!=0)return -1;
    if(fstat(fd,&info)!=0){reject_launch(e,RNR_STAGE0_LAUNCH_CONTEXT,errno);return -1;}
    if(launch_live(e)!=0)return -1;
    int flags=fcntl(fd,F_GETFL);
    if(flags<0){reject_launch(e,RNR_STAGE0_LAUNCH_CONTEXT,errno);return -1;}
    if(launch_live(e)!=0)return -1;
    int seals=fcntl(fd,F_GET_SEALS);
    if(seals<0){reject_launch(e,RNR_STAGE0_LAUNCH_CONTEXT,errno);return -1;}
    if(!S_ISREG(info.st_mode)||(info.st_mode&07777)!=0400||info.st_uid!=0||info.st_gid!=0||
        info.st_nlink!=0||info.st_size!=(off_t)size||(flags&O_ACCMODE)!=O_RDWR||
        (flags&O_PATH)||seals!=required_seals){
        reject_launch(e,RNR_STAGE0_LAUNCH_CONTEXT,0);return -1;
    }
    return 0;
}
static int prepare_launch(struct rnr_stage0_launch_error *error,enum launch_mode mode)
{
    int expected=LAUNCH_NEW;
    if(error==NULL){
        atomic_store_explicit(&launch_state,LAUNCH_FENCED,memory_order_release);
        errno=EINVAL;return -1;
    }
    *error=(struct rnr_stage0_launch_error){0};
    if(!atomic_compare_exchange_strong_explicit(&launch_state,&expected,LAUNCH_PREPARING,
                                                memory_order_acq_rel,memory_order_acquire)){
        atomic_store_explicit(&launch_state,LAUNCH_FENCED,memory_order_release);
        reject_launch(error,RNR_STAGE0_LAUNCH_ATTEMPT,0);return -1;
    }
    if(geteuid()!=0||getegid()!=0){reject_launch(error,RNR_STAGE0_LAUNCH_OWNER,0);goto failed;}
    if(rnr_stage0_clock_prepare(&prepared_clock,&error->capture)!=0){
        reject_launch(error,RNR_STAGE0_LAUNCH_CLOCK,error->capture.system_errno);goto failed;
    }
    prepared_mode=mode;
    prepared_cutoff=0;
    expected=LAUNCH_PREPARING;
    if(!atomic_compare_exchange_strong_explicit(&launch_state,&expected,LAUNCH_PREPARED,
                                                memory_order_release,memory_order_relaxed)){
        reject_launch(error,RNR_STAGE0_LAUNCH_ATTEMPT,0);goto failed;
    }
    return 0;
failed:
    atomic_store_explicit(&launch_state,LAUNCH_FENCED,memory_order_release);
    return -1;
}
static int finish_launch(struct rnr_stage0_launch_error *error,enum launch_mode mode)
{
    int expected=LAUNCH_PREPARED;
    if(error==NULL){
        atomic_store_explicit(&launch_state,LAUNCH_FENCED,memory_order_release);
        errno=EINVAL;return -1;
    }
    *error=(struct rnr_stage0_launch_error){0};
    if(!atomic_compare_exchange_strong_explicit(&launch_state,&expected,LAUNCH_FINISHING,
                                                memory_order_acq_rel,memory_order_acquire)){
        atomic_store_explicit(&launch_state,LAUNCH_FENCED,memory_order_release);
        reject_launch(error,RNR_STAGE0_LAUNCH_ATTEMPT,0);return -1;
    }
    unsigned char payload[MAX_PAYLOAD],header[HEADER_BYTES];
    size_t size=0;int64_t cutoff=0;
    int context=-1;
    struct rnr_stage0_clock *clock=&prepared_clock;
    if(prepared_mode!=mode){reject_launch(error,RNR_STAGE0_LAUNCH_ATTEMPT,0);goto done;}
    if(geteuid()!=0||getegid()!=0){reject_launch(error,RNR_STAGE0_LAUNCH_OWNER,0);goto done;}
    if(mode==LAUNCH_OPERATIONAL && prepared_cutoff==0){
        reject_launch(error,RNR_STAGE0_LAUNCH_CONFIG,0);goto done;
    }
    /* read_launch checks original owner/setup BEFORE its first open. */
    if(read_launch(payload,&size,&cutoff,clock,error)!=0)goto done;
    if(launch_live(error)!=0)goto done;
    if(mode==LAUNCH_OPERATIONAL){
        if(cutoff!=prepared_cutoff){reject_launch(error,RNR_STAGE0_LAUNCH_CONFIG,0);goto done;}
        if(check_preparation(clock,error)!=0)goto done;
    }else if(rnr_stage0_clock_bind_cutoff(clock,cutoff,&error->final)!=0){
        reject_launch(error,RNR_STAGE0_LAUNCH_CLOCK,error->final.system_errno);goto done;
    }
    if(launch_live(error)!=0)goto done;
    if(rnr_stage0_admit_with_clock(clock,&error->admission)!=0){
        reject_launch(error,RNR_STAGE0_LAUNCH_ADMISSION,0);goto done;
    }
    for(int fd=0;fd<9;++fd){
        if(launch_live(error)!=0)goto done;
        int flags=fcntl(fd,F_GETFD);
        if(flags<0){reject_launch(error,RNR_STAGE0_LAUNCH_INHERIT,errno);goto done;}
        if(flags&FD_CLOEXEC){reject_launch(error,RNR_STAGE0_LAUNCH_INHERIT,0);goto done;}
    }
    if(launch_live(error)!=0)goto done;
    if(chdir("/")!=0){reject_launch(error,RNR_STAGE0_LAUNCH_CONTEXT,errno);goto done;}
    if(launch_live(error)!=0)goto done;
    context=memfd_create("rnr-stage0-context",MFD_ALLOW_SEALING|MFD_CLOEXEC);
    if(context<0){reject_launch(error,RNR_STAGE0_LAUNCH_CONTEXT,errno);goto done;}
    if(context!=9){reject_launch(error,RNR_STAGE0_LAUNCH_CONTEXT,0);goto done;}
    if(launch_live(error)!=0)goto done;
    if(fchmod(context,0400)!=0){
        reject_launch(error,RNR_STAGE0_LAUNCH_CONTEXT,errno);goto done;
    }
    if(launch_live(error)!=0)goto done;
    if(ftruncate(context,(off_t)(HEADER_BYTES+size))!=0){
        reject_launch(error,RNR_STAGE0_LAUNCH_CONTEXT,errno);goto done;
    }
    for(size_t offset=0;offset<size;){
        size_t count=size-offset;if(count>CHUNK_BYTES)count=CHUNK_BYTES;
        if(write_part(context,payload+offset,count,(off_t)(HEADER_BYTES+offset),error)!=0)goto done;
        offset+=count;
    }
    if(rnr_stage0_clock_check_setup(clock,&error->final)!=0){
        reject_launch(error,RNR_STAGE0_LAUNCH_CLOCK,error->final.system_errno);goto done;
    }
    /* No subsequent native clock sample may be omitted from this header.
     * Python checks OUTER cutoffs at bind and initial setup at validation;
     * positive public dispatch remains disabled; private original preparation
     * rechecks setup before effects.
     */
    if(encode_context(header,size,clock)!=0){reject_launch(error,RNR_STAGE0_LAUNCH_CONTEXT,0);goto done;}
    if(write_part(context,header,HEADER_BYTES,0,error)!=0)goto done;
    if(launch_live(error)!=0)goto done;
    if(fcntl(context,F_ADD_SEALS,required_seals)!=0){reject_launch(error,RNR_STAGE0_LAUNCH_CONTEXT,errno);goto done;}
    if(verify_context(context,HEADER_BYTES+size,error)!=0)goto done;
    if(launch_live(error)!=0)goto done;
    int flags=fcntl(context,F_GETFD);
    if(flags<0){reject_launch(error,RNR_STAGE0_LAUNCH_INHERIT,errno);goto done;}
    if(flags!=FD_CLOEXEC){reject_launch(error,RNR_STAGE0_LAUNCH_INHERIT,0);goto done;}
    if(launch_live(error)!=0)goto done;
    if(fcntl(context,F_SETFD,0)!=0){reject_launch(error,RNR_STAGE0_LAUNCH_INHERIT,errno);goto done;}
    char *program=mode==LAUNCH_OPERATIONAL?
        "import sys;sys.path[:]=['/rnr/project','/usr/lib/python3.12','/usr/lib/python3.12/lib-dynload'];"
#ifdef RNR_STAGE0_PRIVATE_QUALIFICATION
        "from automation.control_runtime_qualification import _entry;_entry()":
#else
        "from automation.control_runtime_operational import _entry;_entry()":
#endif
        "import sys;sys.path[:]=['/rnr/project','/usr/lib/python3.12','/usr/lib/python3.12/lib-dynload'];"
        "from automation.control_runtime_handoff import _validate_entry;_validate_entry()";
    char *const argv[]={"/usr/bin/python3.12","-I","-S","-B","-c",program,NULL};
    char *const validation_env[]={"LC_ALL=C",NULL};
#ifdef RNR_STAGE0_PRIVATE_QUALIFICATION
    char *const qualification_env[]={"LC_ALL=C","TZ=UTC",NULL};
    char *const *env=mode==LAUNCH_OPERATIONAL?qualification_env:validation_env;
#else
    char *const *env=validation_env;
#endif
    if(launch_live(error)!=0)goto done;
    (void)execve(argv[0],argv,env);
    reject_launch(error,RNR_STAGE0_LAUNCH_EXEC,errno); /* EVERY exec return fails. */
done:
    close_owned(&context,error);
    atomic_store_explicit(&launch_state,LAUNCH_FENCED,memory_order_release);
    return -1;
}
int rnr_stage0_prepare_validation(struct rnr_stage0_launch_error *error)
{return prepare_launch(error,LAUNCH_VALIDATION);}
int rnr_stage0_finish_validation(struct rnr_stage0_launch_error *error)
{return finish_launch(error,LAUNCH_VALIDATION);}
int rnr_stage0_prepare_operational(struct rnr_stage0_launch_error *error)
{return prepare_launch(error,LAUNCH_OPERATIONAL);}
int rnr_stage0_finish_operational(struct rnr_stage0_launch_error *error)
{return finish_launch(error,LAUNCH_OPERATIONAL);}
static int check_or_bind_operational(struct rnr_stage0_launch_error *error,
                                      int binding,int64_t cutoff)
{
    int expected=LAUNCH_PREPARED;
    if(error==NULL){
        atomic_store_explicit(&launch_state,LAUNCH_FENCED,memory_order_release);
        errno=EINVAL;return -1;
    }
    *error=(struct rnr_stage0_launch_error){0};
    if(!atomic_compare_exchange_strong_explicit(&launch_state,&expected,LAUNCH_CHECKING,
                                                memory_order_acq_rel,memory_order_acquire)){
        reject_launch(error,RNR_STAGE0_LAUNCH_ATTEMPT,0);goto failed;
    }
    if(prepared_mode!=LAUNCH_OPERATIONAL){reject_launch(error,RNR_STAGE0_LAUNCH_ATTEMPT,0);goto failed;}
    if(geteuid()!=0||getegid()!=0){reject_launch(error,RNR_STAGE0_LAUNCH_OWNER,0);goto failed;}
    if(phase_live(error,LAUNCH_CHECKING)!=0)goto failed;
    if(rnr_stage0_clock_check_setup(&prepared_clock,&error->final)!=0){
        reject_launch(error,RNR_STAGE0_LAUNCH_CLOCK,error->final.system_errno);goto failed;
    }
    if(binding){
        if(prepared_cutoff!=0){reject_launch(error,RNR_STAGE0_LAUNCH_ATTEMPT,0);goto failed;}
        if(phase_live(error,LAUNCH_CHECKING)!=0)goto failed;
        if(rnr_stage0_clock_bind_cutoff(&prepared_clock,cutoff,&error->final)!=0){
            reject_launch(error,RNR_STAGE0_LAUNCH_CLOCK,error->final.system_errno);goto failed;
        }
        if(phase_live(error,LAUNCH_CHECKING)!=0)goto failed;
        prepared_cutoff=cutoff;
    }
    expected=LAUNCH_CHECKING;
    if(!atomic_compare_exchange_strong_explicit(&launch_state,&expected,LAUNCH_PREPARED,
                                                memory_order_release,memory_order_relaxed)){
        reject_launch(error,RNR_STAGE0_LAUNCH_ATTEMPT,0);goto failed;
    }
    return 0;
failed:
    atomic_store_explicit(&launch_state,LAUNCH_FENCED,memory_order_release);
    return -1;
}
int rnr_stage0_check_operational_preparation(struct rnr_stage0_launch_error *error)
{return check_or_bind_operational(error,0,0);}
int rnr_stage0_bind_operational_preparation_cutoff(int64_t cutoff,
                                                 struct rnr_stage0_launch_error *error)
{return check_or_bind_operational(error,1,cutoff);}
int rnr_stage0_launch_validation(struct rnr_stage0_launch_error *error)
{
    if(rnr_stage0_prepare_validation(error)!=0)return -1;
    return rnr_stage0_finish_validation(error);
}
