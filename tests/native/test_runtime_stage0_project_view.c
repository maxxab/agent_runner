/* Original own/keeper/PID1 objects are simulated; no host syscall escapes. */
#define _GNU_SOURCE
#define RNR_STAGE0_PRIVATE_QUALIFICATION 1
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/nsfs.h>
#include <sched.h>
#include <poll.h>
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
static int check(struct rnr_stage0_launch_error *);
static int op_open(const char *,int);
static int op_openat(int,const char *,int);
static int op_stat(int,struct stat *);
static int op_statx(int,const char *,int,unsigned int,struct statx *);
static int op_statfs(int,struct statfs *);
static ssize_t op_link(int,const char *,char *,size_t);
static ssize_t op_read(int,void *,size_t,off_t);
static int op_ioctl(int,unsigned long);
static int op_poll(struct pollfd *,nfds_t,int);
static int op_close(int);
static long op_syscall(long,...);
static pid_t op_pid(void);
static pid_t op_parent(void);
static int inject_reentry;
static int test_compare_exchange(atomic_int *,int *,int,memory_order,memory_order);
static int real_compare_exchange(atomic_int *p,int *expected,int desired,memory_order success,memory_order failure)
{return atomic_compare_exchange_strong_explicit(p,expected,desired,success,failure);}
#undef atomic_compare_exchange_strong_explicit
#define atomic_compare_exchange_strong_explicit(p,e,d,s,f) test_compare_exchange(p,e,d,s,f)
#define rnr_stage0_check_admission_preparation(e) check(e)
#define rnr_stage0_match_admission_time_namespace(d,i,e) check(e)
#define open(p,f) op_open(p,f)
#define openat(d,p,f) op_openat(d,p,f)
#define fstat(d,s) op_stat(d,s)
#define statx(d,p,f,m,s) op_statx(d,p,f,m,s)
#define fstatfs(d,s) op_statfs(d,s)
#define readlinkat(d,p,b,n) op_link(d,p,b,n)
#define pread(d,b,n,o) op_read(d,b,n,o)
#define ioctl(d,r) op_ioctl(d,r)
#define poll(p,n,t) op_poll(p,n,t)
#define close(d) op_close(d)
#define syscall(...) op_syscall(__VA_ARGS__)
#define getpid() op_pid()
#define getppid() op_parent()
#define getuid() 0
#define geteuid() 0
#define getgid() 0
#define getegid() 0
#include "../../automation/native/runtime_stage0_project_view.c"
#undef atomic_compare_exchange_strong_explicit
#undef getpid
#undef getppid

#include "test_runtime_stage0_project_model.h"
static int test_compare_exchange(atomic_int *p,int *expected,int desired,memory_order success,memory_order failure)
{
 if(inject_reentry&&p==&project_state&&*expected==PROJECT_CHECKING&&desired==PROJECT_HELD){
  struct rnr_stage0_project_error nested;inject_reentry=0;
  assert(rnr_stage0_check_project_view(&nested)==-1&&nested.code==RNR_STAGE0_PROJECT_ATTEMPT);
 }
 return real_compare_exchange(p,expected,desired,success,failure);
}
static int check(struct rnr_stage0_launch_error *e)
{++checks;memset(e,0,sizeof(*e));if(expired){e->code=RNR_STAGE0_LAUNCH_CLOCK;e->system_errno=ETIMEDOUT;return -1;}return 0;}
static pid_t op_pid(void){return foreign?102:101;}
static pid_t op_parent(void){return parent_changed?99:100;}
static void reset(void)
{
 atomic_store(&project_state,PROJECT_NEW);memset(&project_owner,0,sizeof(project_owner));op_model_reset();inject_reentry=0;
}
int main(void)
{
 char p[65];int root,executables[3];pid_t keeper;struct rnr_stage0_project_error e;
 reset();assert(rnr_stage0_capture_project_view(p,&root,executables,&keeper,&e)==0);assert(!strcmp(p,"1111111111111111111111111111111111111111111111111111111111111111"));
 assert(count==28&&peak<=29&&root==project_owner.fds[0]&&keeper==100);
 for(int i=0;i<3;++i)assert(executables[i]==project_owner.fds[23+i]);
 int capture_ops=operations;
 assert(rnr_stage0_check_project_view(&e)==0);int total=operations;
 assert(rnr_stage0_abandon_project_view(&e)==0&&count==0);
 for(int i=1;i<=capture_ops;++i){
  reset();fail=late=i;memset(p,'x',sizeof(p));assert(rnr_stage0_capture_project_view(p,&root,executables,&keeper,&e)==-1&&count==0&&p[0]==0&&root==-1&&executables[0]==-1&&executables[1]==-1&&executables[2]==-1&&keeper==0);
  assert(e.system_errno==EIO&&e.clock.code==RNR_STAGE0_LAUNCH_CLOCK);
 }
 for(int i=capture_ops+1;i<=total;++i){reset();assert(rnr_stage0_capture_project_view(p,&root,executables,&keeper,&e)==0);late=i;assert(rnr_stage0_check_project_view(&e)==-1);assert(rnr_stage0_abandon_project_view(&e)==0&&count==0);}
 for(int i=1;i<=3;++i){reset();malformed=i;assert(rnr_stage0_capture_project_view(p,&root,executables,&keeper,&e)==-1&&count==0);}
 reset();assert(rnr_stage0_capture_project_view(p,&root,executables,&keeper,&e)==0);malformed=2;assert(rnr_stage0_check_project_view(&e)==-1);assert(rnr_stage0_abandon_project_view(&e)==0&&count==0);
 reset();proc_nlink_drift=1;assert(rnr_stage0_capture_project_view(p,&root,executables,&keeper,&e)==0);assert(rnr_stage0_check_project_view(&e)==0);assert(rnr_stage0_abandon_project_view(&e)==0&&count==0);
 reset();drift=20;assert(rnr_stage0_capture_project_view(p,&root,executables,&keeper,&e)==-1&&count==0);
 reset();dead=1;assert(rnr_stage0_capture_project_view(p,&root,executables,&keeper,&e)==-1&&count==0);
 reset();assert(rnr_stage0_capture_project_view(p,&root,executables,&keeper,&e)==0);parent_changed=1;assert(rnr_stage0_check_project_view(&e)==-1);assert(rnr_stage0_abandon_project_view(&e)==0&&count==0);
 reset();assert(rnr_stage0_capture_project_view(p,&root,executables,&keeper,&e)==0);assert(rnr_stage0_check_project_view(NULL)==-1);assert(rnr_stage0_abandon_project_view(&e)==0&&count==0);
 reset();assert(rnr_stage0_capture_project_view(p,&root,executables,&keeper,&e)==0);inject_reentry=1;assert(rnr_stage0_check_project_view(&e)==-1&&e.code==RNR_STAGE0_PROJECT_ATTEMPT);assert(rnr_stage0_abandon_project_view(&e)==0&&count==0);
 reset();assert(rnr_stage0_capture_project_view(p,&root,executables,&keeper,&e)==0);foreign=1;assert(rnr_stage0_abandon_project_view(&e)==-1&&count==28);foreign=0;assert(rnr_stage0_abandon_project_view(&e)==0&&count==0);assert(rnr_stage0_abandon_project_view(&e)==-1&&count==0);
 reset();assert(rnr_stage0_capture_project_view(p,&root,executables,&keeper,&e)==0);assert(rnr_stage0_capture_project_view(p,&root,executables,&keeper,&e)==-1&&count==28&&root==-1);assert(rnr_stage0_abandon_project_view(&e)==0&&count==0);
 reset();assert(rnr_stage0_capture_project_view(p,&root,executables,&keeper,&e)==0);close_bad=1;assert(rnr_stage0_abandon_project_view(&e)==-1&&count==0&&e.cleanup_count==28);
 return 0;
}
