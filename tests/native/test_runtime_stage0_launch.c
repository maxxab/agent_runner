/* Mock fixture SOURCE. No generated execution without a fresh exact grant. */
#define _GNU_SOURCE
#ifdef NDEBUG
#error "Native launch fixtures require active assertions"
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../../automation/native/runtime_stage0_launch.h"
static int fake_open(const char *, int);
static int fake_fstat(int, struct stat *);
static ssize_t fake_pread(int, void *, size_t, off_t);
static ssize_t fake_pwrite(int, const void *, size_t, off_t);
static int fake_close(int);
static int fake_fcntl(int, int, ...);
static int fake_memfd(const char *, unsigned int);
static int fake_fchmod(int, mode_t);
static int fake_truncate(int, off_t);
static int fake_chdir(const char *);
static __attribute__((noinline)) int fake_exec(const char *, char *const [], char *const []);
static uid_t fake_uid(void);
static gid_t fake_gid(void);
static int fake_prepare(struct rnr_stage0_clock *, struct rnr_stage0_clock_error *);
static int fake_bind(struct rnr_stage0_clock *, int64_t, struct rnr_stage0_clock_error *);
static int fake_admit(struct rnr_stage0_clock *, struct rnr_stage0_clock_admission_result *);
static int fake_final(struct rnr_stage0_clock *, struct rnr_stage0_clock_error *);
#define open(p,f) fake_open(p,f)
#define fstat(f,s) fake_fstat(f,s)
#define pread(f,b,n,o) fake_pread(f,b,n,o)
#define pwrite(f,b,n,o) fake_pwrite(f,b,n,o)
#define close(f) fake_close(f)
#define fcntl(...) fake_fcntl(__VA_ARGS__)
#define memfd_create(n,f) fake_memfd(n,f)
#define fchmod(f,m) fake_fchmod(f,m)
#define ftruncate(f,n) fake_truncate(f,n)
#define chdir(p) fake_chdir(p)
#define execve(p,a,e) fake_exec(p,a,e)
#define geteuid() fake_uid()
#define getegid() fake_gid()
#define rnr_stage0_clock_prepare(s,e) fake_prepare(s,e)
#define rnr_stage0_clock_bind_cutoff(s,d,e) fake_bind(s,d,e)
#define rnr_stage0_admit_with_clock(s,e) fake_admit(s,e)
#define rnr_stage0_clock_check_setup(s,e) fake_final(s,e)
#include "../../automation/native/runtime_stage0_launch.c"
#undef open
#undef fstat
#undef pread
#undef pwrite
#undef close
#undef fcntl
#undef memfd_create
#undef fchmod
#undef ftruncate
#undef chdir
#undef execve
#undef geteuid
#undef getegid
#undef rnr_stage0_clock_prepare
#undef rnr_stage0_clock_bind_cutoff
#undef rnr_stage0_admit_with_clock
#undef rnr_stage0_clock_check_setup

/* Independent accepted wire-spec bytes: pid/tid100, final14s/104s. */
static const unsigned char expected_header[144]={
    0x52,0x4e,0x52,0x48,0x30,0x30,0x30,0x31,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x64,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x64,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x2d,0x31,0x31,0x31,0x31,0x2d,0x31,0x31,
    0x31,0x31,0x2d,0x31,0x31,0x31,0x31,0x2d,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,
    0x31,0x31,0x31,0x31,0x00,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x7b,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xe4,0x0b,0x54,0x02,0x00,0x00,0x00,
    0x00,0xe8,0x76,0x48,0x17,0x00,0x00,0x00,0x00,0x98,0x05,0x39,0x33,0x00,0x00,0x00,
    0x00,0x94,0x9a,0x44,0x1e,0x00,0x00,0x00,0x00,0xba,0x1d,0xd2,0x05,0x00,0x00,0x00,
    0x00,0x0c,0x77,0x42,0x03,0x00,0x00,0x00,0x00,0x10,0xe2,0x36,0x18,0x00,0x00,0x00,
};
static unsigned char launch[65552], context[65680];
static size_t launch_size, context_size;
static int opened, launch_closed, context_closed, captures, admissions, finals, execs;
static int fail_open, fail_close_launch, fail_close_context, fail_read, short_read, extra;
static int drift, bad_mode, bad_owner, bad_context, fail_memfd, returned_fd;
static int fail_write, short_write, fail_seal, bad_seals, fail_final, fail_capture, fail_admit;
static int fail_chdir, fail_chmod, fail_truncate, fail_getfd, fail_setfd, cloexec_fd, nonroot;
static int sealed, inherited, payload_written, header_written, stats, reads, writes;
static int fail_bind, binds, late_read, late_close, preparation_expired;
static int preparation_failures, before_close_checks, after_close_checks;
static int interrupt_prepare, interrupt_finish;
static int operational_expected;
static void reset_fixture(void)
{
    /* Test-only access to the included module. No reset API in production. */
    atomic_store(&launch_state, LAUNCH_NEW);
    memset(launch,0,sizeof(launch)); memset(context,0,sizeof(context));
    launch_size=18; context_size=0;
    memcpy(launch,"RNRL0001",8); launch[16]='{'; launch[17]='}';
    for (int i=0;i<8;++i) launch[8+i]=(unsigned char)((220000000000ULL>>(8*i))&255U);
    opened=launch_closed=context_closed=captures=admissions=finals=execs=0;
    fail_bind=binds=late_read=late_close=preparation_expired=0;
    preparation_failures=before_close_checks=after_close_checks=0;
    interrupt_prepare=interrupt_finish=0;
    operational_expected=0;
    fail_open=fail_close_launch=fail_close_context=fail_read=short_read=extra=0;
    drift=bad_mode=bad_owner=bad_context=fail_memfd=0;returned_fd=9;
    fail_write=short_write=fail_seal=bad_seals=fail_final=fail_capture=fail_admit=0;
    fail_chdir=fail_chmod=fail_truncate=fail_setfd=nonroot=0;fail_getfd=cloexec_fd=-1;
    sealed=inherited=payload_written=header_written=stats=reads=writes=0;
}
static int fake_open(const char *path,int flags)
{
    assert(strcmp(path,"/rnr/launch.bin")==0);
    assert(flags==(O_RDONLY|O_NOFOLLOW|O_CLOEXEC));
    assert(captures==1);
    ++opened;if(fail_open){errno=EIO;return -1;}return 40;
}
static int fake_fstat(int fd,struct stat *info)
{
    assert(fd==40||fd==9);memset(info,0,sizeof(*info));
    info->st_dev=1;info->st_ino=fd==40?100:101;
    info->st_mode=S_IFREG|(fd==40?0444:0400);
    info->st_nlink=fd==40?1:0;info->st_size=(off_t)(fd==40?launch_size:context_size);
    info->st_mtim.tv_sec=1;info->st_ctim.tv_sec=1;
    if(fd==40){if(drift&&++stats==2)++info->st_ino;
        if(bad_mode)info->st_mode=S_IFREG|0644;
        if(bad_owner)info->st_uid=1;}
    else if(bad_context)info->st_nlink=1;
    return 0;
}
static ssize_t fake_pread(int fd,void *buffer,size_t count,off_t offset)
{
    assert(fd==40&&offset>=0);
    ++reads;
    if(late_read)preparation_expired=1;
    if(fail_read){errno=EIO;return -1;}
    if((size_t)offset==launch_size)return extra?1:0;
    assert((size_t)offset+count<=launch_size);memcpy(buffer,launch+offset,count);
    return (ssize_t)(short_read?count-1:count);
}
static ssize_t fake_pwrite(int fd,const void *buffer,size_t count,off_t offset)
{
    assert(fd==9&&!sealed&&offset>=0&&(size_t)offset+count<=context_size);
    ++writes;
    if(fail_write){errno=EIO;return -1;}
    if(offset==0){assert(finals==1&&payload_written);header_written=1;}
    else{assert(offset>=144&&finals==0);payload_written=1;}
    memcpy(context+offset,buffer,count);return (ssize_t)(short_write?count-1:count);
}
static int fake_close(int fd)
{
    if(fd==40){assert(launch_closed==0);++launch_closed;
        if(late_close)preparation_expired=1;
        if(fail_close_launch){errno=EINTR;return -1;}}
    else{assert(fd==returned_fd);++context_closed;if(fail_close_context){errno=EINTR;return -1;}}
    return 0;
}
static int fake_fcntl(int fd,int op,...)
{
    va_list args;int value;
    if(op==F_GETFD){if(fd==fail_getfd){errno=EIO;return -1;}
        return fd<9?(fd==cloexec_fd?FD_CLOEXEC:0):FD_CLOEXEC;}
    assert(fd==9);
    if(op==F_GETFL)return O_RDWR;
    if(op==F_GET_SEALS)return bad_seals?0:sealed;
    va_start(args,op);value=va_arg(args,int);va_end(args);
    if(op==F_ADD_SEALS){assert(header_written);if(fail_seal){errno=EIO;return -1;}sealed=value;return 0;}
    assert(op==F_SETFD&&value==0&&sealed);if(fail_setfd){errno=EIO;return -1;}inherited=1;return 0;
}
static int fake_memfd(const char *name,unsigned int flags)
{
    assert(strcmp(name,"rnr-stage0-context")==0);
    assert(flags==(MFD_ALLOW_SEALING|MFD_CLOEXEC));assert(admissions==1&&launch_closed==1);
    if(fail_memfd){errno=EIO;return -1;}return returned_fd;
}
static int fake_fchmod(int fd,mode_t mode)
{assert(fd==9&&mode==0400);if(fail_chmod){errno=EIO;return -1;}return 0;}
static int fake_truncate(int fd,off_t size)
{assert(fd==9&&size>144&&size<=65680);if(fail_truncate){errno=EIO;return -1;}context_size=(size_t)size;return 0;}
static int fake_chdir(const char *path)
{assert(strcmp(path,"/")==0);if(fail_chdir){errno=EIO;return -1;}return 0;}
static uid_t fake_uid(void){return nonroot?1:0;}
static gid_t fake_gid(void){return nonroot?1:0;}
static int fake_prepare(struct rnr_stage0_clock *s,struct rnr_stage0_clock_error *e)
{
    assert(opened==0&&launch_closed==0);++captures;
    if(interrupt_prepare){
        struct rnr_stage0_launch_error other;
        assert(rnr_stage0_finish_validation(&other)==-1&&other.code==RNR_STAGE0_LAUNCH_ATTEMPT);
    }
    if(fail_capture){e->code=RNR_STAGE0_CLOCK_SAMPLE;e->system_errno=EIO;return -1;}
    *s=(struct rnr_stage0_clock){.phase=RNR_STAGE0_CLOCK_PREPARING,.pid=100,.tid=100,
        .time_ns_device=4,.time_ns_inode=123,.captured_boottime_ns=10000000000LL,
        .sampled_wall_ns=100000000000LL,.wall_deadline_ns=220000000000LL,
        .deadline_boottime_ns=130000000000LL,.setup_end_ns=25000000000LL,
        .last_boottime_ns=12000000000LL,.last_wall_ns=102000000000LL};
    memcpy(s->boot_id,"11111111-1111-1111-1111-111111111111",37);return 0;
}
static int fake_bind(struct rnr_stage0_clock *s,int64_t cutoff,struct rnr_stage0_clock_error *e)
{
    assert(cutoff==220000000000LL&&s->phase==RNR_STAGE0_CLOCK_PREPARING);
    if(operational_expected)assert(opened==0&&launch_closed==0);
    else assert(launch_closed==1&&before_close_checks>0&&after_close_checks==1);
    ++binds;
    if(fail_bind){s->phase=RNR_STAGE0_CLOCK_FAILED;e->code=RNR_STAGE0_CLOCK_RANGE;return -1;}
    s->phase=RNR_STAGE0_CLOCK_ACTIVE;return 0;
}
static int fake_admit(struct rnr_stage0_clock *s,struct rnr_stage0_clock_admission_result *e)
{assert(s->phase==RNR_STAGE0_CLOCK_ACTIVE);++admissions;s->admission_attempted=1;if(fail_admit){e->admission.code=RNR_STAGE0_ADMISSION_READ;e->admission.system_errno=EIO;e->admission.cleanup_errno=EINTR;return -1;}return 0;}
static int fake_final(struct rnr_stage0_clock *s,struct rnr_stage0_clock_error *e)
{if(s->phase==RNR_STAGE0_CLOCK_PREPARING || (operational_expected&&!payload_written)){
    if(interrupt_finish){
        struct rnr_stage0_launch_error other;
        interrupt_finish=0;
        assert(rnr_stage0_finish_validation(&other)==-1&&other.code==RNR_STAGE0_LAUNCH_ATTEMPT);
    }
    assert(!payload_written&&!header_written);
    if(launch_closed)++after_close_checks;else ++before_close_checks;
    if(preparation_expired){++preparation_failures;s->phase=RNR_STAGE0_CLOCK_FAILED;
        e->code=RNR_STAGE0_CLOCK_CUTOFF;e->system_errno=ETIMEDOUT;return -1;}
    return 0;}
 assert(payload_written&&!header_written);++finals;if(fail_final){e->code=RNR_STAGE0_CLOCK_CUTOFF;return -1;}s->last_boottime_ns=14000000000LL;s->last_wall_ns=104000000000LL;return 0;}
static int fake_exec(const char *path,char *const argv[],char *const env[])
{
    assert(sealed&&inherited&&header_written);++execs;
    assert(strcmp(path,"/usr/bin/python3.12")==0);
    assert(strcmp(argv[0],path)==0&&strcmp(argv[1],"-I")==0&&strcmp(argv[2],"-S")==0&&strcmp(argv[3],"-B")==0&&strcmp(argv[4],"-c")==0&&argv[6]==NULL);
    const char *expected_program=operational_expected?
        "import sys;sys.path[:]=['/rnr/project','/usr/lib/python3.12','/usr/lib/python3.12/lib-dynload'];"
#ifdef RNR_STAGE0_PRIVATE_QUALIFICATION
        "from automation.control_runtime_qualification import _entry;_entry()":
#else
        "from automation.control_runtime_operational import _entry;_entry()":
#endif
        "import sys;sys.path[:]=['/rnr/project','/usr/lib/python3.12','/usr/lib/python3.12/lib-dynload'];"
        "from automation.control_runtime_handoff import _validate_entry;_validate_entry()";
    assert(strcmp(argv[5],expected_program)==0);
    assert(strcmp(env[0],"LC_ALL=C")==0);
#ifdef RNR_STAGE0_PRIVATE_QUALIFICATION
    if(operational_expected)assert(env[1]!=NULL&&strcmp(env[1],"TZ=UTC")==0&&env[2]==NULL);
    else assert(env[1]==NULL);
#else
    assert(env[1]==NULL);
#endif
    unsigned char expected[144];memcpy(expected,expected_header,144);
    if(launch_size==65552){expected[8]=0;expected[10]=1;assert(reads==4&&writes==3);}
    assert(memcmp(context,expected,144)==0);
    assert(memcmp(context+144,launch+16,launch_size-16)==0);
    for(int i=12;i<16;++i)assert(context[i]==0);
    for(int i=68;i<72;++i)assert(context[i]==0);
    assert(decode_u64(context+128)==14000000000ULL&&decode_u64(context+136)==104000000000ULL);
    errno=ENOENT;return -1;
}
/* These cases exercise launch control flow through clock mocks, not time. */
static void preparation_regressions(void)
{
    struct rnr_stage0_launch_error error;
    reset_fixture(); fail_bind=1;
    assert(rnr_stage0_launch_validation(&error)==-1);
    assert(error.code==RNR_STAGE0_LAUNCH_CLOCK&&error.final.code==RNR_STAGE0_CLOCK_RANGE);
    assert(captures==1&&binds==1&&launch_closed==1&&admissions==0&&execs==0&&context_closed==0);
    for(int cleanup=0;cleanup<=1;++cleanup){
        reset_fixture();late_read=1;fail_close_launch=cleanup;
        assert(rnr_stage0_launch_validation(&error)==-1);
        assert(error.code==RNR_STAGE0_LAUNCH_CLOCK&&error.system_errno==ETIMEDOUT);
        assert(error.final.code==RNR_STAGE0_CLOCK_CUTOFF&&error.final.system_errno==ETIMEDOUT);
        assert(error.cleanup_errno==(cleanup?EINTR:0));
        assert(preparation_failures==1&&reads==1&&launch_closed==1&&after_close_checks==0);
        assert(binds==0&&admissions==0&&execs==0&&context_closed==0);
    }
    reset_fixture();late_close=1;
    assert(rnr_stage0_launch_validation(&error)==-1);
    assert(error.code==RNR_STAGE0_LAUNCH_CLOCK&&error.final.code==RNR_STAGE0_CLOCK_CUTOFF);
    assert(error.system_errno==ETIMEDOUT&&error.cleanup_errno==0);
    assert(preparation_failures==1&&after_close_checks==1&&launch_closed==1);
    assert(binds==0&&admissions==0&&execs==0&&context_closed==0);
    /* A close error is retained; no later clock check may replace it. */
    reset_fixture();late_close=1;fail_close_launch=1;
    assert(rnr_stage0_launch_validation(&error)==-1);
    assert(error.code==RNR_STAGE0_LAUNCH_CLEANUP&&error.system_errno==EINTR&&error.cleanup_errno==EINTR);
    assert(after_close_checks==0&&preparation_failures==0&&launch_closed==1);
    assert(binds==0&&admissions==0&&execs==0);
    reset_fixture();
    struct rnr_stage0_clock state={0};struct rnr_stage0_clock_error clock_error={0};
    unsigned char header[144];
    assert(fake_prepare(&state,&clock_error)==0);
    state.admission_attempted=1; /* Isolate PREPARING rejection from attempt gating. */
    assert(encode_context(header,2,&state)==-1);
}
/* Split preparation must not recapture origin or reopen after expiry. */
static void split_preparation_regressions(void)
{
    struct rnr_stage0_launch_error error;
    reset_fixture();
    assert(rnr_stage0_prepare_validation(&error)==0);
    assert(captures==1&&opened==0&&admissions==0&&execs==0);
    assert(rnr_stage0_finish_validation(&error)==-1);
    assert(error.code==RNR_STAGE0_LAUNCH_EXEC&&captures==1&&execs==1);
    assert(launch_closed==1&&context_closed==1);
    assert(rnr_stage0_finish_validation(&error)==-1);
    assert(error.code==RNR_STAGE0_LAUNCH_ATTEMPT&&execs==1&&opened==1);

    reset_fixture();
    assert(rnr_stage0_prepare_validation(&error)==0);
    preparation_expired=1;
    assert(rnr_stage0_finish_validation(&error)==-1);
    assert(error.code==RNR_STAGE0_LAUNCH_CLOCK&&error.final.code==RNR_STAGE0_CLOCK_CUTOFF);
    assert(captures==1&&opened==0&&admissions==0&&execs==0);
    preparation_expired=0;
    assert(rnr_stage0_finish_validation(&error)==-1&&opened==0);

    reset_fixture();
    assert(rnr_stage0_finish_validation(&error)==-1);
    assert(error.code==RNR_STAGE0_LAUNCH_ATTEMPT&&captures==0&&opened==0);
    assert(rnr_stage0_prepare_validation(&error)==-1&&captures==0);

    reset_fixture();
    assert(rnr_stage0_prepare_validation(&error)==0);
    assert(rnr_stage0_prepare_validation(&error)==-1);
    assert(error.code==RNR_STAGE0_LAUNCH_ATTEMPT);
    assert(rnr_stage0_finish_validation(&error)==-1&&captures==1&&opened==0);

    reset_fixture();
    assert(rnr_stage0_prepare_validation(&error)==0);nonroot=1;
    assert(rnr_stage0_finish_validation(&error)==-1);
    assert(error.code==RNR_STAGE0_LAUNCH_OWNER&&opened==0&&admissions==0&&execs==0);
    nonroot=0;
    assert(rnr_stage0_finish_validation(&error)==-1&&opened==0);

    reset_fixture();interrupt_prepare=1;
    assert(rnr_stage0_prepare_validation(&error)==-1);
    assert(error.code==RNR_STAGE0_LAUNCH_ATTEMPT&&captures==1&&opened==0);
    assert(rnr_stage0_finish_validation(&error)==-1&&opened==0);
    reset_fixture();
    assert(rnr_stage0_prepare_validation(&error)==0);interrupt_finish=1;
    assert(rnr_stage0_finish_validation(&error)==-1);
    assert(error.code==RNR_STAGE0_LAUNCH_ATTEMPT&&captures==1&&opened==0&&admissions==0&&execs==0);
    assert(rnr_stage0_finish_validation(&error)==-1&&opened==0);

    reset_fixture();fail_capture=1;
    assert(rnr_stage0_prepare_validation(&error)==-1);
    assert(error.code==RNR_STAGE0_LAUNCH_CLOCK&&error.capture.system_errno==EIO);
    assert(rnr_stage0_finish_validation(&error)==-1&&captures==1&&opened==0);

    reset_fixture();
    assert(rnr_stage0_prepare_validation(NULL)==-1);
    assert(rnr_stage0_finish_validation(&error)==-1&&captures==0&&opened==0);
    reset_fixture();
    assert(rnr_stage0_prepare_validation(&error)==0);
    assert(rnr_stage0_finish_validation(NULL)==-1);
    assert(rnr_stage0_finish_validation(&error)==-1&&captures==1&&opened==0);
}
static void operational_preparation_regressions(void)
{
    struct rnr_stage0_launch_error error;
    reset_fixture();operational_expected=1;
    assert(rnr_stage0_prepare_operational(&error)==0);
    assert(rnr_stage0_bind_operational_preparation_cutoff(220000000000LL,&error)==0);
    assert(captures==1&&binds==1&&opened==0);
    assert(rnr_stage0_check_operational_preparation(&error)==0);
    assert(rnr_stage0_check_operational_preparation(&error)==0);
    assert(captures==1&&opened==0&&admissions==0&&execs==0);
    assert(rnr_stage0_finish_operational(&error)==-1);
    assert(error.code==RNR_STAGE0_LAUNCH_EXEC&&execs==1&&captures==1&&binds==1);
    assert(rnr_stage0_check_operational_preparation(&error)==-1&&opened==1);

    reset_fixture();assert(rnr_stage0_prepare_operational(&error)==0);
    assert(rnr_stage0_finish_operational(&error)==-1&&opened==0&&binds==0);
    reset_fixture();operational_expected=1;assert(rnr_stage0_prepare_operational(&error)==0);
    assert(rnr_stage0_bind_operational_preparation_cutoff(220000000000LL,&error)==0);
    launch[8]^=1;
    assert(rnr_stage0_finish_operational(&error)==-1&&opened==1&&binds==1&&admissions==0&&execs==0);
    reset_fixture();operational_expected=1;assert(rnr_stage0_prepare_operational(&error)==0);
    assert(rnr_stage0_bind_operational_preparation_cutoff(220000000000LL,&error)==0);
    assert(rnr_stage0_bind_operational_preparation_cutoff(220000000000LL,&error)==-1&&binds==1);
    assert(rnr_stage0_finish_operational(&error)==-1&&opened==0);
    reset_fixture();assert(rnr_stage0_prepare_validation(&error)==0);
    assert(rnr_stage0_bind_operational_preparation_cutoff(220000000000LL,&error)==-1&&binds==0);
    reset_fixture();operational_expected=1;assert(rnr_stage0_prepare_operational(&error)==0);fail_bind=1;
    assert(rnr_stage0_bind_operational_preparation_cutoff(220000000000LL,&error)==-1&&binds==1);
    assert(rnr_stage0_finish_operational(&error)==-1&&opened==0);
    reset_fixture();assert(rnr_stage0_bind_operational_preparation_cutoff(220000000000LL,&error)==-1);
    assert(rnr_stage0_prepare_operational(&error)==-1&&captures==0);
    reset_fixture();assert(rnr_stage0_prepare_operational(&error)==0);
    assert(rnr_stage0_bind_operational_preparation_cutoff(220000000000LL,NULL)==-1);
    assert(rnr_stage0_finish_operational(&error)==-1&&opened==0);
    reset_fixture();assert(rnr_stage0_prepare_operational(&error)==0);nonroot=1;
    assert(rnr_stage0_bind_operational_preparation_cutoff(220000000000LL,&error)==-1&&binds==0);
    reset_fixture();assert(rnr_stage0_prepare_operational(&error)==0);interrupt_finish=1;
    assert(rnr_stage0_bind_operational_preparation_cutoff(220000000000LL,&error)==-1&&binds==0);
    reset_fixture();operational_expected=1;assert(rnr_stage0_prepare_operational(&error)==0);
    assert(rnr_stage0_bind_operational_preparation_cutoff(220000000000LL,&error)==0);preparation_expired=1;
    assert(rnr_stage0_check_operational_preparation(&error)==-1);
    assert(rnr_stage0_finish_operational(&error)==-1&&opened==0&&captures==1&&binds==1);
    reset_fixture();assert(rnr_stage0_prepare_validation(&error)==0);
    assert(rnr_stage0_finish_operational(&error)==-1&&opened==0&&admissions==0&&execs==0);
    assert(rnr_stage0_finish_validation(&error)==-1&&opened==0);
    reset_fixture();assert(rnr_stage0_prepare_operational(&error)==0);
    assert(rnr_stage0_finish_validation(&error)==-1&&opened==0);
    assert(rnr_stage0_finish_operational(&error)==-1&&opened==0);

    reset_fixture();assert(rnr_stage0_prepare_validation(&error)==0);
    assert(rnr_stage0_check_operational_preparation(&error)==-1&&opened==0);
    assert(rnr_stage0_finish_validation(&error)==-1&&opened==0);
    reset_fixture();assert(rnr_stage0_check_operational_preparation(&error)==-1);
    assert(rnr_stage0_prepare_operational(&error)==-1&&captures==0);

    reset_fixture();assert(rnr_stage0_prepare_operational(&error)==0);preparation_expired=1;
    assert(rnr_stage0_check_operational_preparation(&error)==-1);
    assert(error.code==RNR_STAGE0_LAUNCH_CLOCK&&captures==1&&opened==0);
    preparation_expired=0;
    assert(rnr_stage0_finish_operational(&error)==-1&&opened==0);
    reset_fixture();assert(rnr_stage0_prepare_operational(&error)==0);
    assert(rnr_stage0_check_operational_preparation(NULL)==-1);
    assert(rnr_stage0_finish_operational(&error)==-1&&opened==0);

    reset_fixture();assert(rnr_stage0_prepare_operational(&error)==0);interrupt_finish=1;
    assert(rnr_stage0_check_operational_preparation(&error)==-1);
    assert(rnr_stage0_finish_operational(&error)==-1&&opened==0&&captures==1);
}
int main(void)
{
    /* An inherited locale/timezone/loader value must never enter exec env. */
    assert(setenv("LC_ALL","hostile-locale",1)==0);
    assert(setenv("TZ","hostile-timezone",1)==0);
    assert(setenv("SOURCE_DATE_EPOCH","123",1)==0);
    assert(setenv("PYTHONPATH","/untrusted",1)==0);
    struct rnr_stage0_launch_error error;
    reset_fixture();assert(rnr_stage0_launch_validation(&error)==-1);
    assert(error.code==RNR_STAGE0_LAUNCH_EXEC&&error.system_errno==ENOENT&&error.cleanup_errno==0);
    assert(execs==1&&launch_closed==1&&context_closed==1);
    assert(rnr_stage0_launch_validation(&error)==-1&&error.code==RNR_STAGE0_LAUNCH_ATTEMPT&&opened==1);
    reset_fixture();assert(rnr_stage0_launch_validation(NULL)==-1);
    assert(rnr_stage0_launch_validation(&error)==-1&&error.code==RNR_STAGE0_LAUNCH_ATTEMPT&&opened==0);
    reset_fixture();nonroot=1;assert(rnr_stage0_launch_validation(&error)==-1&&opened==0);
    reset_fixture();fail_read=1;fail_close_launch=1;
    assert(rnr_stage0_launch_validation(&error)==-1&&error.system_errno==EIO&&error.cleanup_errno==EINTR&&captures==1&&launch_closed==1);
    reset_fixture();fail_close_context=1;
    assert(rnr_stage0_launch_validation(&error)==-1&&error.system_errno==ENOENT&&error.cleanup_errno==EINTR&&context_closed==1);
    reset_fixture();launch_size=65552;memset(launch+16,'x',65536);
    assert(rnr_stage0_launch_validation(&error)==-1&&execs==1&&context_closed==1&&launch_closed==1);
    for(int kind=0;kind<25;++kind){
        reset_fixture();
        switch(kind){case 0:fail_open=1;break;case 1:short_read=1;break;case 2:extra=1;break;
        case 3:drift=1;break;case 4:bad_mode=1;break;case 5:bad_owner=1;break;
        case 6:fail_capture=1;break;case 7:fail_admit=1;break;case 8:cloexec_fd=3;break;
        case 9:fail_memfd=1;break;case 10:returned_fd=10;break;case 11:fail_write=1;break;
        case 12:short_write=1;break;case 13:fail_seal=1;break;case 14:bad_seals=1;break;
        case 15:fail_final=1;break;case 16:fail_chdir=1;break;case 17:fail_chmod=1;break;
        case 18:fail_truncate=1;break;case 19:fail_getfd=3;break;case 20:fail_setfd=1;break;
        case 21:bad_context=1;break;case 22:launch[0]='X';break;case 23:launch[15]=255;break;
        case 24:launch_size=16;break;}
        assert(rnr_stage0_launch_validation(&error)==-1&&error.code!=RNR_STAGE0_LAUNCH_OK&&execs==0);
        assert(launch_closed<=1&&context_closed<=1);
        if(fail_admit)assert(error.admission.admission.system_errno==EIO&&error.admission.admission.cleanup_errno==EINTR);
    }
    preparation_regressions();
    split_preparation_regressions();
    operational_preparation_regressions();
    return 0;
}
