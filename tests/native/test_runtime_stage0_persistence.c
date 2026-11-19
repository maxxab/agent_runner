/* Actual storage module, ALL filesystem/process identity boundaries simulated. */
#define _GNU_SOURCE
#define RNR_STAGE0_PRIVATE_QUALIFICATION 1
#ifdef NDEBUG
#error "Assertions required"
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
#include <sys/statvfs.h>
#include <unistd.h>
#include "../../automation/native/runtime_stage0_persistence.h"
#include "../../automation/native/runtime_stage0_records.h"
static int fake_open(const char *,int);
static int fake_openat(int,const char *,int,...);
static int fake_fstat(int,struct stat *);
static int fake_statx(int,const char *,int,unsigned int,struct statx *);
static int fake_fstatfs(int,struct statfs *);
static ssize_t fake_pread(int,void *,size_t,off_t);
static ssize_t fake_pwrite(int,const void *,size_t,off_t);
static int fake_fsync(int);
static int fake_close(int);
static pid_t fake_pid(void);
static pid_t fake_tid(void);
static uid_t fake_uid(void);
static gid_t fake_gid(void);
static int fake_check(struct rnr_stage0_launch_error *);
#define open fake_open
#define openat fake_openat
#define fstat fake_fstat
#define statx(...) fake_statx(__VA_ARGS__)
#define fstatfs fake_fstatfs
#define pread fake_pread
#define pwrite fake_pwrite
#define fsync fake_fsync
#define close fake_close
#define getpid fake_pid
#define gettid fake_tid
#define geteuid fake_uid
#define getegid fake_gid
#define rnr_stage0_check_admission_preparation fake_check
#include "../../automation/native/runtime_stage0_persistence.c"
#undef open
#undef openat
#undef fstat
#undef statx
#undef fstatfs
#undef pread
#undef pwrite
#undef fsync
#undef close
#undef getpid
#undef gettid
#undef geteuid
#undef getegid
#undef rnr_stage0_check_admission_preparation

static unsigned char input[65536],raw[MAX_BINDING],instance_raw[128];
static size_t raw_size,input_size;
static int fd_roles[64],fd_live[64],fd_closed[64];
static int original_opens[10],named_opens[10],create_count[2],exists[2];
static int clocks,clock_fail,clock_expired,foreign,wrong_thread,nonroot;
static int io_calls,io_fail,write_calls,sync_calls,close_calls,close_fail;
static int collision_role,short_write,late_write,late_sync,reentry,open_reentry;
static int wrong_role,bad_mode,bad_uid,bad_links,bad_inode,bad_mount,bad_fs,readonly_fs;
static int named_change,instance_change,short_read,extra_read;
static int trace[6],trace_size,stored[2];
static void encode(unsigned char *p,uint64_t v,unsigned int n)
{for(unsigned int j=0;j<n;++j)p[j]=(unsigned char)(v>>(8*j));}
static void setup(void)
{
    atomic_store(&persistence_phase,NEW);atomic_store(&persistence_pid,0);
    memset(&persistence,0,sizeof(persistence));
    memset(fd_live,0,sizeof(fd_live));memset(fd_closed,0,sizeof(fd_closed));
    memset(original_opens,0,sizeof(original_opens));memset(named_opens,0,sizeof(named_opens));
    memset(create_count,0,sizeof(create_count));memset(exists,0,sizeof(exists));memset(stored,0,sizeof(stored));
    clocks=clock_fail=clock_expired=foreign=wrong_thread=nonroot=0;
    io_calls=io_fail=write_calls=sync_calls=close_calls=close_fail=0;
    collision_role=-1;short_write=late_write=late_sync=reentry=open_reentry=0;
    wrong_role=-1;bad_mode=bad_uid=bad_links=bad_inode=bad_mount=bad_fs=readonly_fs=0;
    named_change=instance_change=short_read=extra_read=0;trace_size=0;
    memset(raw,0,sizeof(raw));memcpy(raw,"RNRBIND1",8);encode(raw+8,1,4);
    memset(raw+16,0x22,32);memset(raw+48,0x33,16);memset(raw+64,0xaa,16);
    for(int off=80;off<=176;off+=8)encode(raw+off,100+off,8);
    encode(raw+160,90000000000ULL,8);
    memcpy(raw+184,"11111111-1111-1111-1111-111111111111",36);
    encode(raw+220,448,4);encode(raw+224,64+input_size,4);encode(raw+228,1,4);
    raw_size=256+448+64+input_size+1;encode(raw+12,raw_size,4);
    unsigned char *i=raw+256;
    memcpy(i,"RNRI0002",8);encode(i+8,2,4);i[16]=1;i[48]=2;
    encode(i+80,129,8);encode(i+88,3,8);memset(i+96,0xff,32);
    memcpy(i+128,raw+16,32);memcpy(i+160,raw+48,16);
    encode(i+176,11,8);encode(i+184,106,8);encode(i+192,12,4);encode(i+196,13,4);
    memcpy(i+200,raw+184,36);memset(i+240,4,96);memset(i+336,0x11,32);memset(i+368,6,32);
    unsigned char *t=raw+704;
    memcpy(t,"RNRT0001",8);encode(t+8,1,4);memcpy(t+16,raw+64,16);
    encode(t+32,90000000000ULL,8);encode(t+40,input_size,4);memcpy(t+64,input,input_size);
    memset(instance_raw,0,128);memcpy(instance_raw,"RNRINST1",8);encode(instance_raw+8,1,4);
    memcpy(instance_raw+16,i+128,32);memcpy(instance_raw+48,i+160,16);
    memcpy(instance_raw+64,i+176,24);memcpy(instance_raw+88,i+200,36);
}
static int call(void)
{++io_calls;if(io_fail==io_calls){errno=EIO;return -1;}return 0;}
static int role_of(int fd)
{assert(fd>=10&&fd<64&&fd_live[fd]);return fd_roles[fd];}
static int allocate(int role)
{
    for(int fd=10;fd<64;++fd)if(!fd_live[fd]){fd_live[fd]=1;fd_roles[fd]=role;return fd;}
    assert(0);return -1;
}
static void attempt_reentry(void)
{
    struct rnr_stage0_persistence_error e;
    int closes=close_calls;
    assert(rnr_stage0_abandon_persistent_claim(&e)==-1);assert(close_calls==closes);
}
static int fake_open(const char *path,int flags)
{
    assert(!strcmp(path,"/"));assert(flags==(O_RDONLY|O_DIRECTORY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC));
    if(call()!=0)return -1;
    if(original_opens[0]++)++named_opens[0];
    return allocate(0);
}
static int fake_openat(int parentfd,const char *path,int flags,...)
{
    int p=role_of(parentfd),role=-1;
    if(p<5)role=p+1;
    else if(p==5)role=!strcmp(path,"consumed")?6:!strcmp(path,"instance")?7:!strcmp(path,"active")?8:-1;
    else if(p==6)role=9;
    assert(role>=0&&!strcmp(path,name(role)));
    if(call()!=0)return -1;
    if(flags&O_CREAT){
        assert(role>=8);assert(flags==(O_WRONLY|O_CREAT|O_EXCL|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC));
        va_list args;va_start(args,flags);assert(va_arg(args,int)==0600);va_end(args);
        ++create_count[role-8];
        if(collision_role==role||exists[role-8]){errno=EEXIST;return -1;}
        exists[role-8]=1;
    }else{
        assert(flags==(O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC|(role<7?O_DIRECTORY:0)));
        if(original_opens[role]++)++named_opens[role];
    }
    int fd=allocate(role);
    if(open_reentry) {open_reentry=0;attempt_reentry();}
    return fd;
}
static int fake_fstat(int fd,struct stat *s)
{
    int role=role_of(fd);if(call()!=0)return -1;
    *s=(struct stat){.st_dev=11,.st_ino=100+(ino_t)role,
        .st_mode=role<7?S_IFDIR|(role>=5?0700:0755):S_IFREG|(role==7?0400:0600),
        .st_nlink=role<7?2:1,.st_size=role==7?128:role>=8?stored[role-8]:0};
    if(role==wrong_role){
        if(bad_mode)s->st_mode^=0020;
        if(bad_uid)s->st_uid=1;
        if(bad_links)s->st_nlink=2;
        if(bad_inode)++s->st_ino;
        if(named_change&&named_opens[role])++s->st_ino;
    }
    return 0;
}
static int fake_statx(int fd,const char *path,int flags,unsigned int mask,struct statx *s)
{
    int role=role_of(fd);assert(!strcmp(path,"")&&flags==(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW)&&mask==STATX_MNT_ID);
    if(call()!=0)return -1;
    *s=(struct statx){.stx_mask=STATX_MNT_ID,.stx_mnt_id=77};
    if(role==wrong_role&&bad_mount)s->stx_mnt_id=78;
    return 0;
}
static int fake_fstatfs(int fd,struct statfs *s)
{
    int role=role_of(fd);assert(role==5||role==6);if(call()!=0)return -1;
    *s=(struct statfs){.f_type=0xef53};s->f_fsid.__val[0]=12;s->f_fsid.__val[1]=13;
    if(role==wrong_role){if(bad_fs)s->f_type=0x01021994;if(readonly_fs)s->f_flags|=ST_RDONLY;}
    return 0;
}
static ssize_t fake_pread(int fd,void *out,size_t n,off_t offset)
{
    assert(role_of(fd)==7);if(call()!=0)return -1;
    if(offset==0){assert(n==128);memcpy(out,instance_raw,128);if(instance_change)((unsigned char *)out)[16]^=1;return short_read?127:128;}
    assert(offset==128&&n==1);return extra_read?1:0;
}
static ssize_t fake_pwrite(int fd,const void *data,size_t n,off_t offset)
{
    int role=role_of(fd);assert(role>=8&&n==raw_size&&offset==0&&!memcmp(data,raw,n));
    assert(trace_size<6);trace[trace_size++]=role==8?0:3;++write_calls;
    if(call()!=0)return -1;
    stored[role-8]=(int)n;
    if(late_write==write_calls)clock_expired=1;
    if(reentry){reentry=0;attempt_reentry();}
    return short_write==write_calls?(ssize_t)n-1:(ssize_t)n;
}
static int fake_fsync(int fd)
{
    int role=role_of(fd),step;
    assert(trace_size<6);
    step=trace_size;assert(role==(step==1?8:step==2?5:step==4?9:6));
    trace[trace_size++]=step;++sync_calls;
    if(call()!=0)return -1;
    if(late_sync==sync_calls)clock_expired=1;
    return 0;
}
static int fake_close(int fd)
{
    role_of(fd);fd_live[fd]=0;++fd_closed[fd];++close_calls;
    if(close_fail){errno=EIO;return -1;}return 0;
}
static pid_t fake_pid(void){return foreign?101:100;}
static pid_t fake_tid(void){return wrong_thread?102:fake_pid();}
static uid_t fake_uid(void){return nonroot?1:0;}
static gid_t fake_gid(void){return 0;}
static int fake_check(struct rnr_stage0_launch_error *e)
{
    *e=(struct rnr_stage0_launch_error){0};++clocks;
    if(clock_expired||clock_fail==clocks){e->code=RNR_STAGE0_LAUNCH_CLOCK;return -1;}return 0;
}
static void all_closed(void)
{for(int fd=10;fd<64;++fd)assert(!fd_live[fd]);}
static void rejected(void)
{
    struct rnr_stage0_persistence_error e;
    assert(rnr_stage0_prepare_persistent_claim(raw,raw_size,&e)==-1);
    assert(e.code!=RNR_STAGE0_PERSISTENCE_OK);all_closed();
    int writes=write_calls,syncs=sync_calls,calls=io_calls;
    assert(rnr_stage0_prepare_persistent_claim(raw,raw_size,&e)==-1);
    assert(rnr_stage0_abandon_persistent_claim(&e)==-1);
    assert(write_calls==writes&&sync_calls==syncs&&io_calls==calls);
    assert(create_count[0]<=1&&create_count[1]<=1);
}
int main(void)
{
    ssize_t n=read(0,input,sizeof(input));assert(n>0&&n<65536);input_size=(size_t)n;
    struct rnr_stage0_persistence_error e;
    setup();assert(rnr_stage0_prepare_persistent_claim(raw,raw_size,&e)==0);
    assert(e.entered==63&&e.returned==63&&trace_size==6);
    for(int j=0;j<6;++j)assert(trace[j]==j);
    assert(e.latch==RNR_STAGE0_PERSISTENCE_CREATED&&e.claim==RNR_STAGE0_PERSISTENCE_CREATED);
    assert(exists[0]&&exists[1]&&stored[0]==(int)raw_size&&stored[1]==(int)raw_size);
    int total_clocks=clocks,total_io=io_calls;
    clock_expired=1;assert(rnr_stage0_abandon_persistent_claim(&e)==0);all_closed();
    assert(exists[0]&&exists[1]);
    int prior_close=close_calls;assert(rnr_stage0_abandon_persistent_claim(&e)==-1);assert(close_calls==prior_close);
    /* Inject every metadata/I/O failure and every before/after clock boundary. */
    for(int j=1;j<=total_clocks;++j){setup();clock_fail=j;rejected();}
    for(int j=1;j<=total_io;++j){setup();io_fail=j;rejected();}
    for(int role=8;role<=9;++role){setup();collision_role=role;rejected();assert(create_count[role-8]==1);}
    setup();short_write=1;rejected();assert(write_calls==1&&sync_calls==0&&exists[0]);
    setup();late_write=1;rejected();assert(write_calls==1&&sync_calls==0&&exists[0]);
    setup();late_sync=1;rejected();assert(write_calls==1&&sync_calls==1&&exists[0]);
    setup();short_write=2;rejected();assert(write_calls==2&&sync_calls==2&&exists[0]&&exists[1]);
    setup();late_write=2;rejected();assert(write_calls==2&&sync_calls==2&&exists[1]);
    for(int j=2;j<=4;++j){setup();late_sync=j;rejected();assert(sync_calls==j);}
    setup();reentry=1;rejected();assert(write_calls==1&&sync_calls==0);
    setup();open_reentry=1;rejected();assert(write_calls==0);
    for(int role=0;role<10;++role){setup();wrong_role=role;bad_mode=1;rejected();}
    for(int role=0;role<10;++role){setup();wrong_role=role;bad_uid=1;rejected();}
    for(int role=7;role<10;++role){setup();wrong_role=role;bad_links=1;rejected();}
    setup();wrong_role=6;bad_inode=1;rejected();assert(write_calls==0);
    setup();wrong_role=6;bad_mount=1;rejected();assert(write_calls==0);
    setup();wrong_role=7;bad_mount=1;rejected();assert(write_calls==0);
    for(int role=5;role<=6;++role){setup();wrong_role=role;bad_fs=1;rejected();assert(write_calls==0);}
    for(int role=5;role<=6;++role){setup();wrong_role=role;readonly_fs=1;rejected();assert(write_calls==0);}
    for(int role=0;role<8;++role){setup();wrong_role=role;named_change=1;rejected();}
    setup();instance_change=1;rejected();assert(write_calls==0);
    setup();short_read=1;rejected();assert(write_calls==0);
    setup();extra_read=1;rejected();assert(write_calls==0);
    setup();nonroot=1;rejected();assert(io_calls==0);
    setup();wrong_thread=1;rejected();assert(io_calls==0);
    setup();assert(rnr_stage0_prepare_persistent_claim(raw,raw_size,&e)==0);
    foreign=1;prior_close=close_calls;assert(rnr_stage0_abandon_persistent_claim(&e)==-1);assert(close_calls==prior_close);
    foreign=0;assert(rnr_stage0_abandon_persistent_claim(&e)==0);all_closed();
    setup();close_fail=1;rejected();assert(close_calls>0&&write_calls==0);
    setup();assert(rnr_stage0_prepare_persistent_claim(raw,raw_size,&e)==0);
    close_fail=1;assert(rnr_stage0_abandon_persistent_claim(&e)==-1);all_closed();assert(e.cleanup_count==10);
    prior_close=close_calls;assert(rnr_stage0_abandon_persistent_claim(&e)==-1);assert(close_calls==prior_close);
    setup();raw[16]^=1;rejected();assert(io_calls==0);
    setup();raw[232]=1;rejected();assert(io_calls==0);
    setup();encode(raw+224,65601,4);rejected();assert(io_calls==0);
    setup();encode(raw+228,65537,4);rejected();assert(io_calls==0);
    setup();memcpy(raw+184,"22222222",8);rejected();assert(io_calls==0);
    setup();encode(raw+80,0,8);rejected();assert(io_calls==0);
    setup();raw[704+16]^=1;rejected();assert(io_calls==0);
    setup();assert(rnr_stage0_prepare_persistent_claim(NULL,raw_size,&e)==-1);assert(io_calls==0);
    setup();unsigned char copy[256];memcpy(copy,raw,256);
    assert(rnr_stage0_prepare_persistent_claim(raw,raw_size,(void *)(raw+16))==-1);
    assert(!memcmp(copy,raw,256)&&io_calls==0);
    setup();assert(rnr_stage0_prepare_persistent_claim(raw,raw_size,NULL)==-1);assert(io_calls==0);
    return 0;
}
