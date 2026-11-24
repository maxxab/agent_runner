/* All kernel/launch boundaries replaced, including fortified libc aliases.
 * No host proc/namespace opens, qualification binary or real fork executes. */
#define _GNU_SOURCE
#define RNR_STAGE0_PRIVATE_QUALIFICATION 1
#ifdef NDEBUG
#error "Assertions required"
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/nsfs.h>
#include <sched.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "../../automation/native/runtime_stage0_launch.h"
static int mock_check(struct rnr_stage0_launch_error *);
static int mock_open(const char *,int);
static int mock_openat(int,const char *,int);
static int mock_fstat(int,struct stat *);
static int mock_statx(int,const char *,int,unsigned int,struct statx *);
static int mock_fstatfs(int,struct statfs *);
static ssize_t mock_readlinkat(int,const char *,char *,size_t);
static int mock_ioctl(int,unsigned long);
static int mock_close(int);
static pid_t mock_pid(void);
static long mock_syscall(long);
static uid_t mock_uid(int);
#define rnr_stage0_check_admission_preparation(e) mock_check(e)
#define open(p,f) mock_open(p,f)
#define openat(d,p,f) mock_openat(d,p,f)
#define fstat(d,s) mock_fstat(d,s)
#define statx(d,p,f,m,s) mock_statx(d,p,f,m,s)
#define fstatfs(d,s) mock_fstatfs(d,s)
#define readlinkat(d,p,b,n) mock_readlinkat(d,p,b,n)
#define ioctl(d,r) mock_ioctl(d,r)
#define close(d) mock_close(d)
#define getpid() mock_pid()
#define getuid() mock_uid(0)
#define geteuid() mock_uid(1)
#define getgid() mock_uid(2)
#define getegid() mock_uid(3)
#define syscall(n) mock_syscall(n)
#include "../../automation/native/runtime_stage0_bootstrap.c"
#undef open
#undef openat
#undef fstat
#undef statx
#undef fstatfs
#undef readlinkat
#undef ioctl
#undef close
#undef getpid
#undef getuid
#undef geteuid
#undef getgid
#undef getegid
#undef syscall
static int fd_live[64],roles[64],closed[64],ops,checks,prior_checks,peak,held;
static int fail_at,late_at,clock_failed,close_errors,uid_bad,pid_bad,tid_bad;
static int drift_role,drift_kind,reentrant_at,inside_reentry,unadopted;
static int link_kind,metadata_calls[9],named_drift;
static int close_at,close_late_at,close_count;
static int readlink_calls[9];
static const char *thread_text="101/task/101",*user_text="user:[4026531837]";
static void reset(void)
{
 atomic_store(&bootstrap_state,BOOTSTRAP_NEW);
 memset(&bootstrap_owner,0,sizeof(bootstrap_owner));
 for(int i=0;i<9;++i)bootstrap_owner.fds[i]=-1;
 memset(fd_live,0,sizeof(fd_live));memset(roles,0,sizeof(roles));memset(closed,0,sizeof(closed));
 memset(metadata_calls,0,sizeof(metadata_calls));memset(readlink_calls,0,sizeof(readlink_calls));
 ops=checks=prior_checks=peak=held=fail_at=late_at=clock_failed=close_errors=uid_bad=pid_bad=tid_bad=0;
 drift_role=-1;drift_kind=reentrant_at=inside_reentry=unadopted=link_kind=named_drift=0;
 close_at=close_late_at=close_count=0;
 thread_text="101/task/101";user_text="user:[4026531837]";
}
static int observe(void)
{
 assert(!clock_failed);assert(checks>=prior_checks+2);prior_checks=checks;++ops;
 if(ops==reentrant_at&&!inside_reentry){
  inside_reentry=1;struct rnr_stage0_bootstrap_error e;int before=held;
  assert(rnr_stage0_check_bootstrap(&e)==-1&&held==before);inside_reentry=0;
 }
 if(ops==late_at)clock_failed=1;
 if(ops==fail_at){errno=EIO;return -1;}return 0;
}
static int mock_check(struct rnr_stage0_launch_error *e)
{++checks;memset(e,0,sizeof(*e));if(clock_failed){e->code=RNR_STAGE0_LAUNCH_CLOCK;e->system_errno=ETIMEDOUT;return -1;}return 0;}
static pid_t mock_pid(void){return pid_bad?102:101;}
static long mock_syscall(long n){assert(n==SYS_gettid);return tid_bad?102:101;}
static uid_t mock_uid(int kind){return uid_bad==kind+1?1000:0;}
static int allocate(int role)
{
 if(unadopted)return 2;
 int fd;for(fd=10;fd<64&&fd_live[fd];++fd){}assert(fd<64);
 fd_live[fd]=1;roles[fd]=role;closed[fd]=0;++held;if(held>peak)peak=held;
 assert(held<=10);return fd;
}
static int mock_open(const char *p,int f)
{assert(!strcmp(p,"/")&&f==(O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));if(observe())return -1;return allocate(0);}
static int mock_openat(int d,const char *p,int f)
{
 assert(fd_live[d]);int parent=roles[d],role=-1;
 if(parent==0){assert(!strcmp(p,"proc"));role=1;}
 if(parent==1){if(!strcmp(p,"thread-self"))role=2;else{assert(!strcmp(p,"101"));role=3;}}
 if(parent==3){assert(!strcmp(p,"task"));role=4;}
 if(parent==4){assert(!strcmp(p,"101"));role=5;}
 if(parent==5){assert(!strcmp(p,"ns"));role=6;}
 if(parent==6){assert(!strcmp(p,"user"));role=f&O_NOFOLLOW?7:8;}
 assert(role>=0);int expected=role==2||role==7?O_PATH|O_NOFOLLOW|O_CLOEXEC:
  role==8?O_RDONLY|O_CLOEXEC:O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC;
 assert(f==expected);if(observe())return -1;return allocate(role);
}
static int mock_fstat(int fd,struct stat *s)
{
 assert(fd_live[fd]);if(observe())return -1;int role=roles[fd];++metadata_calls[role];
 memset(s,0,sizeof(*s));s->st_dev=role==0?1:role==8?3:2;s->st_ino=role==1?1:role==8?UINT64_C(0xeffffffd):(uint64_t)(100+role);
 s->st_mode=role==2||role==7?S_IFLNK|0777:role==8?S_IFREG|0444:S_IFDIR|0555;
 s->st_nlink=role==8?1:2;s->st_size=role==2?strlen(thread_text):role==7?strlen(user_text):0;
 if(role==drift_role && (!named_drift||metadata_calls[role]>=3)){
  switch(drift_kind){
   case 1:s->st_dev++;break;case 2:s->st_ino++;break;case 3:s->st_uid=1;break;
   case 4:s->st_gid=1;break;case 5:s->st_mode=S_IFREG|0444;break;
   case 6:s->st_mode|=0020;break;case 7:s->st_nlink++;break;
   case 8:s->st_ctim.tv_nsec++;break;
   case 14:s->st_size++;break;case 15:s->st_mtim.tv_nsec++;break;
  }
 }
 return 0;
}
static int mock_statx(int fd,const char *p,int f,unsigned int m,struct statx *s)
{assert(fd_live[fd]&&!strcmp(p,"")&&f==(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW)&&m==STATX_MNT_ID);if(observe())return -1;
 memset(s,0,sizeof(*s));int role=roles[fd];s->stx_mask=STATX_MNT_ID;s->stx_mnt_id=role==0?10:role==8?30:20;
 if(role==drift_role&&drift_kind==9)++s->stx_mnt_id;
 if(role==drift_role&&drift_kind==10)s->stx_mask=0;
 if(role==drift_role&&drift_kind==11)s->stx_mnt_id=0;
 return 0;}
static int mock_fstatfs(int fd,struct statfs *s)
{assert(fd_live[fd]);if(observe())return -1;memset(s,0,sizeof(*s));int role=roles[fd];s->f_type=role==0?0xef53:role==8?0x6e736673:0x9fa0;
 if(role==drift_role&&drift_kind==12)s->f_type=0xef53;
 return 0;}
static ssize_t mock_readlinkat(int fd,const char *p,char *b,size_t cap)
{assert(fd_live[fd]&&!strcmp(p,"")&&cap==32);if(observe())return -1;int role=roles[fd];assert(role==2||role==7);++readlink_calls[role];
 const char *s=role==2?thread_text:user_text;size_t n=strlen(s);if(n>cap)n=cap;memcpy(b,s,n);
 if(link_kind==1&&readlink_calls[role]>1)b[0]^=1;
 if(link_kind==3)b[n/2]=0;
 if(link_kind==2){memset(b,'x',cap);n=cap;}
 return (ssize_t)n;}
static int mock_ioctl(int fd,unsigned long request)
{assert(fd_live[fd]&&roles[fd]==8&&request==NS_GET_NSTYPE);if(observe())return -1;return drift_role==8&&drift_kind==13?CLONE_NEWNET:CLONE_NEWUSER;}
static int mock_close(int fd)
{assert(fd>=10&&fd<64&&fd_live[fd]&&!closed[fd]);fd_live[fd]=0;closed[fd]=1;--held;++close_count;
 if(close_count==close_late_at)clock_failed=1;
 /* In combined cases, inject cleanup errors only after the selected initiating syscall. */
 if((close_errors&&(!fail_at||ops>=fail_at))||close_count==close_at){errno=EBADF;return -1;}return 0;}
static void rejected(struct rnr_stage0_bootstrap_error *e)
{assert(rnr_stage0_check_bootstrap(e)==-1);assert(e->code!=RNR_STAGE0_BOOTSTRAP_OK&&held==0);}
int main(void)
{
 struct rnr_stage0_bootstrap_error e;reset();assert(rnr_stage0_check_bootstrap(&e)==0&&held==0&&peak==10);
 int total=ops,total_closes=close_count;assert(total>100);assert(rnr_stage0_check_bootstrap(&e)==-1&&held==0);
 for(int i=1;i<=total;++i){reset();fail_at=i;rejected(&e);assert(e.system_errno==EIO);}
 for(int i=1;i<=total;++i){reset();late_at=i;rejected(&e);assert(e.code==RNR_STAGE0_BOOTSTRAP_CLOCK);}
 for(int i=1;i<=total;++i){reset();fail_at=late_at=i;rejected(&e);assert(e.system_errno==EIO&&e.clock.code==RNR_STAGE0_LAUNCH_CLOCK&&e.clock.system_errno==ETIMEDOUT);}
 for(int i=1;i<=total;++i){reset();reentrant_at=i;rejected(&e);}
 for(int i=1;i<=4;++i){reset();uid_bad=i;rejected(&e);assert(ops==0);}
 reset();tid_bad=1;rejected(&e);assert(ops==0);
 reset();pid_bad=1;rejected(&e); /* thread-self must match syscall PID */
 const char *bad[]={"","0/task/0","0101/task/101","101/task/0101","101/task/102","102/task/101","101/task/101/","101/tasks/101","2147483648/task/101","101/task/-1"};
 for(unsigned int i=0;i<sizeof(bad)/sizeof(*bad);++i){reset();thread_text=bad[i];rejected(&e);}
 reset();user_text="user:[1]";rejected(&e);
 for(int i=1;i<=3;++i){reset();link_kind=i;rejected(&e);}
 for(int role=0;role<9;++role)for(int kind=1;kind<=13;++kind){
  if(kind==1&&(role==0||role==8))continue; /* chosen host root is not authenticated here */
  if(kind==2&&role!=1&&role!=8)continue; /* no fixed generic inode pin */
  if(kind==5&&(role==8))continue;
  if(kind==6&&(role==2||role==7||role==8))continue;
  if(kind==7||kind==8)continue; /* drift on later observations below */
  if(kind==9&&(role==0||role==1||role==8))continue;
  if((kind==12&&role==0)||(kind==13&&role!=8))continue;
  if(kind==13&&role==8){reset();drift_role=role;drift_kind=kind;rejected(&e);continue;}
  if(kind>12)continue;
  reset();drift_role=role;drift_kind=kind;rejected(&e);
 }
 for(int role=0;role<9;++role){
  const int kinds[]={1,2,7,8,14,15};
  for(unsigned int k=0;k<sizeof(kinds)/sizeof(*kinds);++k){
   if((kinds[k]==8||kinds[k]==14||kinds[k]==15)&&role!=2&&role!=7&&role!=8)continue;
   reset();drift_role=role;drift_kind=kinds[k];named_drift=1;rejected(&e);
  }
 }
 for(int n=1;n<=total_closes;++n){
  reset();close_at=n;rejected(&e);assert(e.code==RNR_STAGE0_BOOTSTRAP_CLEANUP&&e.system_errno==EBADF&&e.cleanup_count==1);
  reset();close_late_at=n;rejected(&e);assert(e.code==RNR_STAGE0_BOOTSTRAP_CLOCK&&e.clock.code==RNR_STAGE0_LAUNCH_CLOCK);
  reset();close_at=close_late_at=n;rejected(&e);assert(e.code==RNR_STAGE0_BOOTSTRAP_CLEANUP&&e.system_errno==EBADF&&e.clock.code==RNR_STAGE0_LAUNCH_CLOCK);
 }
 unsigned int max_cleanup=0;
 for(int i=1;i<=total;++i){reset();fail_at=late_at=i;close_errors=1;rejected(&e);
  assert(e.system_errno==EIO&&e.clock.code==RNR_STAGE0_LAUNCH_CLOCK&&e.cleanup_count<=10);
  if(e.cleanup_count>max_cleanup)max_cleanup=e.cleanup_count;
 }
 assert(max_cleanup==10);
 reset();close_errors=1;rejected(&e);assert(e.cleanup_count>0);
 reset();fail_at=40;close_errors=1;rejected(&e);assert(e.system_errno==EIO&&e.cleanup_count>0);
 reset();unadopted=1;rejected(&e);assert(e.unadopted_fd==2);
 reset();assert(rnr_stage0_check_bootstrap(NULL)==-1&&ops==0);rejected(&e);
 return 0;
}
