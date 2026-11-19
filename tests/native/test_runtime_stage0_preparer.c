/* All file/clock/admission syscalls substituted; no protected host effects. */
#define _GNU_SOURCE
#ifdef NDEBUG
#error "Preparer fixtures require active assertions"
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "../../automation/native/runtime_stage0_preparer.h"

static int fake_open(const char *,int);
static int fake_openat(int,const char *,int);
static int fake_fstat(int,struct stat *);
static int fake_statx(int,const char *,int,unsigned int,struct statx *);
static int fake_fstatfs(int,struct statfs *);
static ssize_t fake_pread(int,void *,size_t,off_t);
static int fake_close(int);
static int fake_prepare(struct rnr_stage0_launch_error *);
static int fake_check(struct rnr_stage0_launch_error *);
static int fake_bind_cutoff(int64_t,struct rnr_stage0_launch_error *);
static int fake_admit(struct rnr_stage0_admission_error *);
static pid_t fake_pid(void);
static long fake_syscall(long,...);
static uid_t fake_uid(void);
static gid_t fake_gid(void);
#define open(p,f) fake_open(p,f)
#define openat(d,p,f,...) fake_openat(d,p,f)
#define fstat(d,s) fake_fstat(d,s)
#define statx(d,p,f,m,s) fake_statx(d,p,f,m,s)
#define fstatfs(d,s) fake_fstatfs(d,s)
#define pread(d,p,n,o) fake_pread(d,p,n,o)
#define close(d) fake_close(d)
#define getpid() fake_pid()
#define geteuid() fake_uid()
#define getegid() fake_gid()
#define syscall(...) fake_syscall(__VA_ARGS__)
#define rnr_stage0_prepare_operational(e) fake_prepare(e)
#define rnr_stage0_check_operational_preparation(e) fake_check(e)
#define rnr_stage0_bind_operational_preparation_cutoff(d,e) fake_bind_cutoff(d,e)
#define rnr_stage0_admit_preparation_fds(e) fake_admit(e)
#include "test_runtime_stage0_unused_final.h"
#include "../../automation/native/runtime_stage0_preparer.c"
#undef open
#undef openat
#undef fstat
#undef statx
#undef fstatfs
#undef pread
#undef close
#undef getpid
#undef geteuid
#undef getegid
#undef syscall
#undef rnr_stage0_prepare_operational
#undef rnr_stage0_check_operational_preparation
#undef rnr_stage0_bind_operational_preparation_cutoff
#undef rnr_stage0_admit_preparation_fds

static unsigned char install_raw[128],task_raw[66];
static int live[32],closes[32],opens,prepare_calls,admit_calls,clock_calls;
static int writer_fenced,prepare_bad,admit_bad,clock_bad_at,open_bad_at;
static int bad_fd,short_read,extra_eof,read_errno,statx_missing,named_mount_change;
static int named_identity_change,bad_task_size,close_bad,reenter_open,reenter_check;
static int foreign,abandon_calls,abandon_saw_closes,bind_calls,bind_bad;
enum metadata_fault { DIR_WRITABLE=1, UID_CHANGED, GID_CHANGED, MODE_CHANGED,
    NLINK_CHANGED, SIZE_CHANGED, MTIME_CHANGED, CTIME_CHANGED, DEV_CHANGED,
    INODE_CHANGED, RDEV_CHANGED };
static int metadata_fd,metadata_fault,metadata_after,stat_calls[32];
static int fstat_error_fd,statx_error_fd,statfs_error_fd;
static void le(unsigned char *p,uint64_t n,int bytes)
{for(int j=0;j<bytes;++j)p[j]=(unsigned char)(n>>(8*j));}
static void reset(void)
{
    atomic_store(&preparer_state,PREPARER_NEW);
    atomic_store(&input_owner_pid,0);
    input_owner=(struct preparer_owner){.fds={-1,-1,-1,-1,-1}};
    memset(install_raw,0,128);memcpy(install_raw,"RNRI0001",8);install_raw[8]=1;
    install_raw[16]=1;install_raw[48]=2;install_raw[96]=3;
    le(install_raw+80,129,8);le(install_raw+88,3,8);
    memset(task_raw,0,66);memcpy(task_raw,"RNRT0001",8);task_raw[8]=1;
    task_raw[16]=4;le(task_raw+32,123456789,8);task_raw[40]=2;memcpy(task_raw+64,"{}",2);
    memset(live,0,sizeof(live));memset(closes,0,sizeof(closes));
    opens=prepare_calls=admit_calls=clock_calls=writer_fenced=prepare_bad=admit_bad=0;
    clock_bad_at=open_bad_at=0;bad_fd=-1;
    short_read=extra_eof=read_errno=statx_missing=named_mount_change=0;
    named_identity_change=bad_task_size=close_bad=reenter_open=reenter_check=0;
    foreign=abandon_calls=abandon_saw_closes=bind_calls=bind_bad=0;
    metadata_fd=fstat_error_fd=statx_error_fd=statfs_error_fd=-1;
    metadata_fault=metadata_after=0;memset(stat_calls,0,sizeof(stat_calls));
}
static int close_total(void)
{int n=0;for(int j=0;j<32;++j)n+=closes[j];return n;}
static void attempt_abandon(void)
{
    struct rnr_stage0_preparer_error e;
    int before=close_total();++abandon_calls;
    assert(rnr_stage0_abandon_preparation_inputs(&e)==-1);
    abandon_saw_closes+=close_total()-before;
}
static int opened(int role)
{
    ++opens;
    assert(prepare_calls==1 && admit_calls==1);
    if(opens==open_bad_at){errno=ELOOP;return -1;}
    int fd=role+10;
    if(live[fd]) fd+=10;
    assert(fd<32 && !live[fd]);live[fd]=1;
    if(opens==reenter_open)attempt_abandon();
    return fd;
}
static int fake_open(const char *path,int flags)
{
    assert(strcmp(path,"/")==0);
    assert(flags==(O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
    return opened(0);
}
static int fake_openat(int parent,const char *path,int flags)
{
    assert(parent>=10 && parent<=12 && live[parent]);
    int role;
    if(parent==10){assert(strcmp(path,"etc")==0);role=1;}
    else if(parent==11){assert(strcmp(path,"rnr")==0);role=2;}
    else if(strcmp(path,"installation.bin")==0)role=3;
    else{assert(strcmp(path,"task.bin")==0);role=4;}
    int want=O_RDONLY|O_NOFOLLOW|O_CLOEXEC|(role<3?O_DIRECTORY:O_NONBLOCK);
    assert(flags==want);
    return opened(role);
}
static int fake_fstat(int fd,struct stat *s)
{
    assert(fd>=10 && fd<25 && live[fd]);int role=fd%10;
    ++stat_calls[fd];
    if(fd==fstat_error_fd){errno=EIO;return -1;}
    memset(s,0,sizeof(*s));s->st_dev=1;s->st_ino=100+role;
    s->st_mode=role<3?S_IFDIR|0755:S_IFREG|0444;s->st_nlink=1;
    s->st_size=role==3?128:66;
    if(fd==bad_fd)s->st_mode=S_IFIFO|0444;
    if(named_identity_change && fd==23)++s->st_ino;
    if(bad_task_size && role==4)s->st_size=65601;
    if(fd==metadata_fd && stat_calls[fd]>=metadata_after){
        switch(metadata_fault){
        case DIR_WRITABLE:s->st_mode|=0020;break;
        case UID_CHANGED:s->st_uid=1;break;
        case GID_CHANGED:s->st_gid=1;break;
        case MODE_CHANGED:s->st_mode=S_IFREG|0555;break;
        case NLINK_CHANGED:s->st_nlink=2;break;
        case SIZE_CHANGED:++s->st_size;break;
        case MTIME_CHANGED:++s->st_mtim.tv_nsec;break;
        case CTIME_CHANGED:++s->st_ctim.tv_nsec;break;
        case DEV_CHANGED:++s->st_dev;break;
        case INODE_CHANGED:++s->st_ino;break;
        case RDEV_CHANGED:++s->st_rdev;break;
        default:assert(0);
        }
    }
    return 0;
}
static int fake_statx(int fd,const char *path,int flags,unsigned int mask,struct statx *s)
{
    assert(live[fd] && !strcmp(path,""));
    assert(flags==(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW) && mask==STATX_MNT_ID);
    if(fd==statx_error_fd){errno=EIO;return -1;}
    memset(s,0,sizeof(*s));s->stx_mask=statx_missing?0:STATX_MNT_ID;
    s->stx_mnt_id=1000+fd%10;
    if(named_mount_change && fd==20)++s->stx_mnt_id;
    return 0;
}
static int fake_fstatfs(int fd,struct statfs *s)
{
    assert(live[fd]);
    if(fd==statfs_error_fd){errno=EIO;return -1;}
    memset(s,0,sizeof(*s));s->f_type=0xef53;return 0;
}
static ssize_t fake_pread(int fd,void *buf,size_t count,off_t offset)
{
    assert(live[fd] && (fd==13 || fd==14) && count<=32768 && offset>=0);
    size_t n=fd==13?128:66;unsigned char *raw=fd==13?install_raw:task_raw;
    if(read_errno){errno=read_errno;return -1;}
    if((size_t)offset==n){if(extra_eof){*(char *)buf='x';return 1;}return 0;}
    assert((size_t)offset+count<=n);memcpy(buf,raw+offset,count);
    return (ssize_t)count-(short_read?1:0);
}
static int fake_close(int fd)
{
    assert(fd>=10 && fd<25 && live[fd]);
    ++closes[fd];live[fd]=0;assert(closes[fd]==1);
    if(close_bad){errno=EINTR;return -1;}return 0;
}
static int fake_prepare(struct rnr_stage0_launch_error *e)
{
    ++prepare_calls;assert(opens==0);memset(e,0,sizeof(*e));
    if(prepare_bad){e->code=RNR_STAGE0_LAUNCH_CLOCK;return -1;}return 0;
}
static int fake_admit(struct rnr_stage0_admission_error *e)
{
    ++admit_calls;assert(prepare_calls==1 && opens==0);memset(e,0,sizeof(*e));
    if(admit_bad){e->code=RNR_STAGE0_ADMISSION_INVENTORY;return -1;}return 0;
}
static int fake_bind_cutoff(int64_t cutoff,struct rnr_stage0_launch_error *e)
{
    assert(cutoff==123456789 && opens==5 && prepare_calls==1 && !bind_calls);
    ++bind_calls;memset(e,0,sizeof(*e));
    if(bind_bad){e->code=RNR_STAGE0_LAUNCH_CLOCK;return -1;}return 0;
}
static int fake_check(struct rnr_stage0_launch_error *e)
{
    if(!e){writer_fenced=1;errno=EINVAL;return -1;}
    ++clock_calls;memset(e,0,sizeof(*e));
    if(clock_calls==reenter_check)attempt_abandon();
    if(writer_fenced || clock_calls==clock_bad_at){e->code=RNR_STAGE0_LAUNCH_CLOCK;return -1;}
    return 0;
}
static pid_t fake_pid(void){return 100;}
static long fake_syscall(long n,...){assert(n==SYS_gettid);return foreign?101:100;}
static uid_t fake_uid(void){return 0;}
static gid_t fake_gid(void){return 0;}
static void drained(void)
{for(int fd=0;fd<32;++fd)assert(!live[fd] && closes[fd]<=1);}
int main(void)
{
    struct rnr_stage0_preparer_error e,other;
    reset();assert(rnr_stage0_prepare_inputs(&e)==0);int count=clock_calls;
    assert(input_owner.installation.runtime.data_blocks==129);
    assert(input_owner.task.payload==input_owner.task_raw+64 && input_owner.task.payload_bytes==2);
    assert(prepare_calls==1 && opens==10 && bind_calls==1);
    for(int fd=10;fd<15;++fd)assert(live[fd]);
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    int before=close_total();live[10]=1; /* caller's reused number */
    assert(rnr_stage0_abandon_preparation_inputs(&e)==-1 && close_total()==before && live[10]);

    reset();prepare_bad=1;assert(rnr_stage0_prepare_inputs(&e)==-1 && !opens && !admit_calls);drained();
    reset();bind_bad=1;assert(rnr_stage0_prepare_inputs(&e)==-1 && e.code==RNR_STAGE0_PREPARER_CLOCK && opens==5 && bind_calls==1);drained();
    reset();admit_bad=1;assert(rnr_stage0_prepare_inputs(&e)==-1 && !opens);drained();
    reset();assert(rnr_stage0_prepare_inputs(NULL)==-1 && !opens && !prepare_calls);
    assert(rnr_stage0_prepare_inputs(&e)==-1 && !prepare_calls);drained();
    for(int j=1;j<=count;++j){
        reset();clock_bad_at=j;assert(rnr_stage0_prepare_inputs(&e)==-1);drained();
        assert(rnr_stage0_prepare_inputs(&other)==-1 && prepare_calls==1);drained();
    }
    for(int j=1;j<=10;++j){
        reset();open_bad_at=j;assert(rnr_stage0_prepare_inputs(&e)==-1);drained();
        reset();reenter_open=j;assert(rnr_stage0_prepare_inputs(&e)==-1);drained();
        assert(abandon_calls==1 && abandon_saw_closes==0);
    }
    reset();reenter_check=count;assert(rnr_stage0_prepare_inputs(&e)==-1);drained();
    assert(abandon_calls==1 && abandon_saw_closes==0);
    reset();bad_fd=13;assert(rnr_stage0_prepare_inputs(&e)==-1);drained();
    reset();bad_task_size=1;assert(rnr_stage0_prepare_inputs(&e)==-1);drained();
    reset();short_read=1;assert(rnr_stage0_prepare_inputs(&e)==-1);drained();
    reset();read_errno=EINTR;assert(rnr_stage0_prepare_inputs(&e)==-1 && e.system_errno==EINTR);drained();
    reset();extra_eof=1;assert(rnr_stage0_prepare_inputs(&e)==-1);drained();
    reset();statx_missing=1;assert(rnr_stage0_prepare_inputs(&e)==-1);drained();
    reset();named_mount_change=1;assert(rnr_stage0_prepare_inputs(&e)==-1);drained();
    reset();named_identity_change=1;assert(rnr_stage0_prepare_inputs(&e)==-1);drained();
    reset();install_raw[8]=2;assert(rnr_stage0_prepare_inputs(&e)==-1);drained();
    reset();task_raw[40]=3;assert(rnr_stage0_prepare_inputs(&e)==-1);drained();
    reset();close_bad=1;assert(rnr_stage0_prepare_inputs(&e)==-1);
    assert(e.cleanup_count==6 && e.code==RNR_STAGE0_PREPARER_CLEANUP);drained();

    /* Each mutation would admit unsafe/replaced inputs if production dropped
     * the corresponding capture/full-signature check. Expected faults are
     * independent kernel-record edits, never computed by the reader. */
    for(int fd=10;fd<=12;++fd){
        for(int fault=DIR_WRITABLE;fault<=GID_CHANGED;++fault){
            reset();metadata_fd=fd;metadata_fault=fault;metadata_after=1;
            assert(rnr_stage0_prepare_inputs(&e)==-1);
            assert(e.code==RNR_STAGE0_PREPARER_METADATA);drained();
        }
    }
    for(int fd=13;fd<=14;++fd){
        for(int fault=UID_CHANGED;fault<=NLINK_CHANGED;++fault){
            reset();metadata_fd=fd;metadata_fault=fault;metadata_after=1;
            assert(rnr_stage0_prepare_inputs(&e)==-1);
            assert(e.code==RNR_STAGE0_PREPARER_METADATA);drained();
        }
        for(int fault=UID_CHANGED;fault<=RDEV_CHANGED;++fault){
            reset();metadata_fd=fd;metadata_fault=fault;metadata_after=2;
            assert(rnr_stage0_prepare_inputs(&e)==-1);
            assert(e.code==RNR_STAGE0_PREPARER_IDENTITY);drained();
            reset();metadata_fd=fd+10;metadata_fault=fault;metadata_after=1;
            assert(rnr_stage0_prepare_inputs(&e)==-1);
            assert(e.code==RNR_STAGE0_PREPARER_IDENTITY);drained();
        }
    }
    const int metadata_handles[]={10,11,12,13,14,20,21,22,23,24};
    for(unsigned int j=0;j<sizeof(metadata_handles)/sizeof(metadata_handles[0]);++j){
        reset();fstat_error_fd=metadata_handles[j];
        assert(rnr_stage0_prepare_inputs(&e)==-1);
        assert(e.code==RNR_STAGE0_PREPARER_METADATA && e.system_errno==EIO);drained();
        reset();statx_error_fd=metadata_handles[j];
        assert(rnr_stage0_prepare_inputs(&e)==-1);
        assert(e.code==RNR_STAGE0_PREPARER_METADATA && e.system_errno==EIO);drained();
    }
    for(int fd=10;fd<=20;fd+=10){
        reset();statfs_error_fd=fd;
        assert(rnr_stage0_prepare_inputs(&e)==-1);
        assert(e.code==RNR_STAGE0_PREPARER_METADATA && e.system_errno==EIO);drained();
    }
    reset();fstat_error_fd=14;close_bad=1;
    assert(rnr_stage0_prepare_inputs(&e)==-1);
    assert(e.code==RNR_STAGE0_PREPARER_METADATA && e.system_errno==EIO && e.cleanup_count==5);
    for(unsigned int j=0;j<e.cleanup_count;++j)assert(e.cleanup_errors[j].system_errno==EINTR);
    drained();before=close_total();live[14]=1;
    assert(rnr_stage0_abandon_preparation_inputs(&other)==-1 && close_total()==before && live[14]);

    reset();assert(rnr_stage0_prepare_inputs(&e)==0);before=close_total();
    assert(rnr_stage0_prepare_inputs(&other)==-1 && close_total()==before);
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    reset();assert(rnr_stage0_prepare_inputs(&e)==0);foreign=1;before=close_total();
    assert(rnr_stage0_abandon_preparation_inputs(&e)==-1 && close_total()==before);
    foreign=0;assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    reset();assert(rnr_stage0_prepare_inputs(&e)==0);before=close_total();
    assert(rnr_stage0_abandon_preparation_inputs(NULL)==-1 && close_total()==before);
    close_bad=1;assert(rnr_stage0_abandon_preparation_inputs(&e)==-1 && e.cleanup_count==5);drained();
    before=close_total();assert(rnr_stage0_abandon_preparation_inputs(&e)==-1 && close_total()==before);
    return 0;
}
