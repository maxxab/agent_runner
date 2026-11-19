/* Real clock algorithm nested in synthetic preparer; ALL clock syscalls mocked. */
#define RNR_FIXED_CLOCK_FLOW
#include "test_runtime_stage0_fixed_binds.c"
#undef read
#include <time.h>

static int nested_open(const char *,int);
static ssize_t nested_read(int,void *,size_t);
static int nested_close(int);
static int nested_stat(const char *,struct stat *);
static int nested_time(clockid_t,struct timespec *);
static int nested_admit(struct rnr_stage0_admission_error *);
#define open(p,f) nested_open(p,f)
#define read(f,b,n) nested_read(f,b,n)
#define close(f) nested_close(f)
#define stat(p,s) nested_stat(p,s)
#define clock_gettime(c,t) nested_time(c,t)
#define getpid() 100
#define gettid() 100
#define rnr_stage0_admit_initial_fds(e) nested_admit(e)
#include "../../automation/native/runtime_stage0_clock.c"
#undef open
#undef read
#undef close
#undef stat
#undef clock_gettime
#undef getpid
#undef gettid
#undef rnr_stage0_admit_initial_fds

static struct rnr_stage0_clock nested_clock;
static int nested_live,nested_reads,nested_opens,nested_closes,nested_peak;
static int nested_failure,nested_trigger,nested_failed_fd,nested_cleanup_all;
static const int64_t nested_boot=1000000000000LL,nested_wall=1700000000000000000LL;
static int nested_count(void)
{int n=0;for(int j=0;j<RNR_TEST_HANDLES;++j)n+=handles[j].live;return n;}
static int nested_open(const char *path,int flags)
{
    assert(!nested_live&&!strcmp(path,"/proc/sys/kernel/random/boot_id"));
    assert(flags==(O_RDONLY|O_NOFOLLOW|O_CLOEXEC));
    nested_live=1;nested_reads=0;++nested_opens;
    int n=nested_count()+1;if(n>nested_peak)nested_peak=n;
    /* Trigger only once at the actual common-owner maximum. */
    if(nested_failure&&!nested_trigger&&n==81){
        nested_trigger=1;nested_failed_fd=nested_opens;
        if(nested_cleanup_all)bind_close_all=1;
    }
    return RNR_TEST_HANDLES+7;
}
static ssize_t nested_read(int fd,void *buffer,size_t size)
{
    assert(nested_live&&fd==RNR_TEST_HANDLES+7);
    if(nested_failure==2&&nested_failed_fd==nested_opens){errno=EIO;return -1;}
    if(nested_reads++){assert(size==1);return 0;}
    assert(size==38);memcpy(buffer,"12345678-1234-1234-1234-123456789abc\n",37);return 37;
}
static int nested_close(int fd)
{
    assert(nested_live&&fd==RNR_TEST_HANDLES+7);nested_live=0;++nested_closes;
    if(nested_failed_fd==nested_opens){errno=EINTR;return -1;}return 0;
}
static int nested_stat(const char *path,struct stat *s)
{assert(!nested_live&&!strcmp(path,"/proc/thread-self/ns/time"));memset(s,0,sizeof(*s));s->st_dev=1;s->st_ino=2;return 0;}
static int nested_time(clockid_t kind,struct timespec *s)
{assert(!nested_live&&(kind==CLOCK_BOOTTIME||kind==CLOCK_REALTIME));int64_t n=kind==CLOCK_BOOTTIME?nested_boot:nested_wall;s->tv_sec=n/1000000000LL;s->tv_nsec=n%1000000000LL;return 0;}
static int nested_admit(struct rnr_stage0_admission_error *e)
{(void)e;assert(0);return -1;}
static int nested_clock_check(struct rnr_stage0_launch_error *e)
{
    if(rnr_stage0_clock_check_setup(&nested_clock,&e->final)==0)return 0;
    e->code=RNR_STAGE0_LAUNCH_CLOCK;e->system_errno=e->final.system_errno;return -1;
}
static void nested_start(int failure)
{
    nested_clock_enabled=0;bind_start();nested_clock=(struct rnr_stage0_clock){0};
    nested_live=nested_reads=nested_opens=nested_closes=nested_peak=0;
    nested_failure=nested_trigger=nested_failed_fd=0;
    struct rnr_stage0_clock_error e;
    assert(rnr_stage0_clock_prepare(&nested_clock,&e)==0);
    assert(rnr_stage0_clock_bind_cutoff(&nested_clock,nested_wall+90000000000LL,&e)==0);
    nested_failure=failure;nested_clock_enabled=1;
}
int main(void)
{
    (void)fixed_bind_fixture_main;
    for(int scenario=0;scenario<=4;++scenario){
        int failure=scenario>2?scenario-2:scenario;nested_cleanup_all=scenario>2;
        nested_start(failure);struct rnr_stage0_preparer_error e;
        int result=rnr_stage0_prepare_fixed_binds(&e);
        assert(nested_peak==81&&nested_opens==nested_closes&&!nested_live);
        assert(nested_clock.captured_boottime_ns==nested_boot&&nested_clock.sampled_wall_ns==nested_wall);
        assert(nested_clock.wall_deadline_ns==nested_wall+90000000000LL&&nested_clock.setup_end_ns==nested_boot+15000000000LL);
        if(!failure){assert(result==0&&nested_count()==78);nested_clock_enabled=0;assert(rnr_stage0_abandon_preparation_inputs(&e)==0);}
        else{
            assert(result==-1&&nested_trigger&&nested_failed_fd==nested_opens);
            assert(e.code==RNR_STAGE0_PREPARER_CLOCK&&e.launch.code==RNR_STAGE0_LAUNCH_CLOCK);
            assert(e.launch.final.cleanup_errno==EINTR&&nested_clock.phase==RNR_STAGE0_CLOCK_FAILED);
            assert(e.launch.final.code==(failure==1?RNR_STAGE0_CLOCK_CLEANUP:RNR_STAGE0_CLOCK_BOOT));
            assert(e.launch.final.system_errno==(failure==1?EINTR:EIO));
            assert(e.cleanup_count==(nested_cleanup_all?80U:0U)&&!e.cleanup_overflow);
        }
        drained();
    }
    puts("real-clock algorithm mocked: peak81 nonstdio; once-close EINTR and primary EIO preserved; no retry/renewal");
    return 0;
}
