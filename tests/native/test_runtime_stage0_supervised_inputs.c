/* Actual clock+launch+preparer+records+admission objects. All reachable kernel
 * calls are linker-wrapped; no physical fork, signal, protected input or host
 * resource operation. Each invocation models one fresh immutable process. */
#define _GNU_SOURCE
#define RNR_STAGE0_PRIVATE_QUALIFICATION 1
#ifdef NDEBUG
#error "Assertions required"
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/nsfs.h>
#include <linux/openat2.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include "../../automation/native/runtime_stage0_preparer.h"
#include "test_runtime_stage0_policy_inputs.h"
#include "test_runtime_stage0_manager_vectors.h"
#include "test_runtime_stage0_cgroup_model.h"
#include "test_runtime_stage0_mountinfo_model.h"
#include "test_runtime_stage0_search_path_model.h"
static int scenario, owner=100, forked, armed, read_index, status_index, scanner;
static int scans, held_scans, opens, forks, signals, pidfds, sends, gate_closed;
static int fd_live[64], fd_closed[64], signal_kind, exit_code, status_opens;
static int executable_live[16];
static int unit_live[10];
static int manager_live,manager_phase,manager_paths_live[3];
static unsigned char manager_reply[1024];static size_t manager_reply_offset,manager_id_reply_length;static unsigned int manager_unit_ids,manager_unit_names,manager_unit_fields,manager_unit_bools,manager_unit_facts,manager_unit_dependencies,manager_unit_timeouts,manager_service_fields,manager_service_scalars,manager_service_empty,manager_service_exec,manager_cgroup_strings,manager_cgroup_scalars,manager_cgroup_arrays,manager_cgroup_ids;
static int64_t boot=10000000000LL, wall=100000000000LL;
static int passcred_mask;
static int buffer_set_mask,buffer_get_mask;
/* Independent fixed proc model for actual bootstrap.c, never host proc. */
static int guard_live[10],guard_role[10],guard_count,guard_done,guard_namespace;
static int guard_open(int role)
{
 assert(held_scans==1&&!guard_done);int i;
 for(i=0;i<10&&guard_live[i];++i){}assert(i<10);
 guard_live[i]=1;guard_role[i]=role;++guard_count;return 70+i;
}
static int guard_stat(int fd,struct stat *s)
{
 assert(fd>=70&&fd<80&&guard_live[fd-70]);int role=guard_role[fd-70];
 memset(s,0,sizeof(*s));s->st_dev=role==0?1:role==8?3:2;
 s->st_ino=role==1?1:role==8?UINT64_C(0xeffffffd):(uint64_t)(100+role);
 s->st_mode=role==2||role==7?S_IFLNK|0777:role==8?S_IFREG|0444:S_IFDIR|0555;
 s->st_nlink=1;s->st_size=role==2?12:role==7?17:0;
 if(scenario==12&&role==8)++s->st_ino;
 return 0;
}
#include "test_runtime_stage0_project_model.h"
static int project_model_active;
int __real_rnr_stage0_capture_project_view(char [65],int *,int [3],pid_t *,struct rnr_stage0_project_error *);
int __real_rnr_stage0_check_project_view(struct rnr_stage0_project_error *);
int __real_rnr_stage0_abandon_project_view(struct rnr_stage0_project_error *);
int __wrap_rnr_stage0_capture_project_view(char p[65],int *root,int executables[3],pid_t *keeper,struct rnr_stage0_project_error *e)
{project_model_active=1;int r=__real_rnr_stage0_capture_project_view(p,root,executables,keeper,e);project_model_active=0;return r;}
int __wrap_rnr_stage0_check_project_view(struct rnr_stage0_project_error *e)
{project_model_active=1;int r=__real_rnr_stage0_check_project_view(e);project_model_active=0;return r;}
int __wrap_rnr_stage0_abandon_project_view(struct rnr_stage0_project_error *e)
{project_model_active=1;int r=__real_rnr_stage0_abandon_project_view(e);project_model_active=0;return r;}
ssize_t __wrap_readlinkat(int fd,const char *p,char *b,size_t n)
{
 if(project_model_active)return op_link(fd,p,b,n);
 assert(fd>=70&&fd<80&&guard_live[fd-70]&&!strcmp(p,"")&&n==32);
 int role=guard_role[fd-70];assert(role==2||role==7);
 const char *value=role==2?(scenario==10?"102/task/101":"101/task/101"):"user:[4026531837]";
 size_t count=strlen(value);memcpy(b,value,count);return (ssize_t)count;
}
int __wrap_ioctl(int fd,unsigned long request,...)
{
 if(project_model_active)return op_ioctl(fd,request);
 assert(fd>=70&&fd<80&&guard_live[fd-70]&&guard_role[fd-70]==8&&request==NS_GET_NSTYPE);
 guard_namespace=1;if(scenario==11)boot=25000000000LL;
 return CLONE_NEWUSER;
}
static unsigned char installation[448], task[65600];static size_t task_size;
static jmp_buf exited;
static void le(unsigned char *p,uint64_t v,int n)
{for(int i=0;i<n;++i)p[i]=(unsigned char)(v>>(8*i));}
pid_t __wrap_getpid(void){return owner;}
pid_t __wrap_gettid(void){return owner;}
pid_t __wrap_getppid(void){return 100;}
uid_t __wrap_geteuid(void){return 0;}
gid_t __wrap_getegid(void){return 0;}
uid_t __wrap_getuid(void){return 0;}
gid_t __wrap_getgid(void){return 0;}
int __wrap_clock_gettime(clockid_t c,struct timespec *t)
{assert(c==CLOCK_BOOTTIME||c==CLOCK_REALTIME);int64_t n=c==CLOCK_BOOTTIME?boot:wall;t->tv_sec=n/1000000000;t->tv_nsec=n%1000000000;return 0;}
int __wrap_stat(const char *p,struct stat *s)
{memset(s,0,sizeof(*s));s->st_dev=1;s->st_ino=(scenario==24&&forked)?3:2;
 if(!strcmp(p,"/proc/thread-self/ns/time"))return 0;
 assert(!strcmp(p,"/dev/null"));s->st_mode=S_IFCHR;s->st_rdev=9;return 0;}
static int input_open(int role)
{assert(held_scans==1);++opens;int fd=role+(role>=7?20:10);if(fd_live[fd])fd+=10;assert(!fd_live[fd]);fd_live[fd]=1;return fd;}
static int input_role(int fd){return fd>=37?fd-30:fd>=27?fd-20:fd%10;}
static int executable_open(int role)
{int i=role;if(executable_live[i])i+=8;assert(i<16&&!executable_live[i]);executable_live[i]=1;++opens;return 300+i;}
static int executable_role(int fd)
{assert(fd>=300&&fd<316&&executable_live[fd-300]);return (fd-300)%8;}
static int unit_role(int fd)
{int i=fd-400;assert(i>=0&&i<10&&unit_live[i]);return i>=6?i-6:i;}
int __wrap_open(const char *p,int flags,...)
{
 if(!strcmp(p,"/proc/sys/kernel/random/boot_id")){assert(flags==(O_RDONLY|O_NOFOLLOW|O_CLOEXEC));read_index=0;return 50;}
 if(!strcmp(p,"/proc/self/status")){assert(!forked);++status_opens;status_index=0;return 51;}
 if(!strcmp(p,"/proc/self/fd")){assert(!scanner);scanner=1;++scans;if(forked){assert(owner==101);++held_scans;}return 3;}
 if(project_model_active)return op_open(p,flags);
 if(!strcmp(p,".")){assert(guard_done);return op_open("/",flags);}
 assert(!strcmp(p,"/")&&flags==(O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
 if(!guard_done)return guard_open(0);
 return op_open(p,flags);
}
ssize_t __wrap_read(int fd,void *p,size_t n)
{
 if(fd==50){if(read_index++){assert(n==1);return 0;}assert(n==38);memcpy(p,"11111111-1111-1111-1111-111111111111\n!",38);return 37;}
 assert(fd==51);if(status_index++)return 0;const char raw[]="Name:\trnr\nThreads:\t1\n";assert(n>=sizeof(raw)-1);memcpy(p,raw,sizeof(raw)-1);return sizeof(raw)-1;
}
int __wrap_openat(int parent,const char *p,int flags,...)
{
 if(project_model_active)return op_openat(parent,p,flags);
 if((parent>=100&&parent<256&&!strcmp(p,"usr"))||(parent>=300&&parent<308)){
  int r=-1;
  if(parent<256){assert(used[parent]&&role[parent]==0);r=0;}
  else if(parent==300){assert(!strcmp(p,"lib"));r=1;}
  else if(parent==301){if(!strcmp(p,"rnr"))r=2;else{assert(!strcmp(p,"systemd"));r=6;}}
  else if(parent==302){assert(!strcmp(p,"bootstraps"));r=3;}
  else if(parent==303){assert(!strcmp(p,fixture_native_hash));r=4;}
  else if(parent==304){assert(!strcmp(p,"rnr-stage0"));r=5;}
  else if(parent==306){assert(!strcmp(p,"systemd"));r=7;}
  assert(r>=0&&flags==(O_RDONLY|O_NOFOLLOW|O_CLOEXEC|((r==5||r==7)?O_NONBLOCK:O_DIRECTORY)));
  return executable_open(r);
 }
 if(parent>=70&&parent<80){
  assert(guard_live[parent-70]);int r=guard_role[parent-70],role=-1;
  if(r==0){assert(!strcmp(p,"proc"));role=1;}
  else if(r==1){if(!strcmp(p,"thread-self"))role=2;else{assert(!strcmp(p,"101"));role=3;}}
  else if(r==3){assert(!strcmp(p,"task"));role=4;}
  else if(r==4){assert(!strcmp(p,"101"));role=5;}
  else if(r==5){assert(!strcmp(p,"ns"));role=6;}
  else if(r==6){assert(!strcmp(p,"user"));role=flags&O_NOFOLLOW?7:8;}
  assert(role>=0);return guard_open(role);
 }
 int role;if(parent>=100){assert(!strcmp(p,"etc"));role=1;}
 else if(parent==11){assert(!strcmp(p,"rnr"));role=2;}
 else if(parent==12){assert(!strcmp(p,"projects"));role=5;}
 else if(parent==15){assert(!strcmp(p,"1111111111111111111111111111111111111111111111111111111111111111"));role=6;}
 else {assert(parent==16);if(scenario==-4&&!strcmp(p,"admission-policy.bin")){errno=ENOENT;return -1;}
  role=!strcmp(p,"installation.bin")?3:!strcmp(p,"task.bin")?4:!strcmp(p,"admission-policy.bin")?7:!strcmp(p,"configuration.json")?8:!strcmp(p,"enrollment.json")?9:10;assert(role!=10||!strcmp(p,"startup-manifest.json"));}
 assert(flags==(O_RDONLY|O_NOFOLLOW|O_CLOEXEC|(role<3||role==5||role==6?O_DIRECTORY:O_NONBLOCK)));return input_open(role);
}
int __wrap_fstat(int fd,struct stat *s)
{
 if(fd==740)return sp_stat(s,0);
 if(fd==741)return so_stat(s);
 if(fd>=730&&fd<=731)return mi_stat(fd,s);
 if(fd==720)return cg_file_stat(s);
 if(fd>=700&&fd<716)return cg_stat(fd,s);
 if(fd>=600){int r=fd-600;assert(r<3&&manager_paths_live[r]);memset(s,0,sizeof(*s));
  s->st_dev=4;s->st_ino=400+r;s->st_nlink=1;s->st_mode=r==2?S_IFSOCK|0700:S_IFDIR|0755;return 0;}
 if(fd>=400){int r=unit_role(fd);memset(s,0,sizeof(*s));s->st_dev=3;s->st_ino=200+r;s->st_nlink=1;
  s->st_mode=r<4?S_IFREG|0644:S_IFDIR|0755;
  if(r<4)s->st_size=(off_t)strlen(fixture_units[r]);
  return 0;}
 if(fd>=300){int r=executable_role(fd);memset(s,0,sizeof(*s));s->st_uid=s->st_gid=0;s->st_nlink=1;
  s->st_mode=(r==5||r==7?S_IFREG:S_IFDIR)|0555;s->st_dev=5;s->st_ino=r==5?123:r==7?125:200+r;
  if(r==5||r==7)s->st_size=1024;
  return 0;}
 if(fd>=100)return op_stat(fd,s);
 if(fd>=70&&fd<80)return guard_stat(fd,s);
 memset(s,0,sizeof(*s));s->st_dev=1;s->st_ino=100+fd;
 if(fd<3){s->st_mode=S_IFCHR;s->st_rdev=9;return 0;}
 if(fd==3&&scanner){s->st_mode=S_IFDIR|0500;return 0;}
 if(fd==4){s->st_mode=S_IFSOCK;return 0;}
 assert(fd>=10&&fd<41&&fd_live[fd]);int role=input_role(fd);s->st_ino=100+role;
 s->st_mode=role<3||role==5||role==6?S_IFDIR|(role==6?0700:0755):S_IFREG|0400;s->st_nlink=1;
 s->st_size=role==3?448:role==7?sizeof(fixture_policy):role==8?sizeof(fixture_config)-1:role==9?sizeof(fixture_enrollment)-1:role==10?sizeof(fixture_startup)-1:task_size;return 0;
}
int __wrap_fcntl(int fd,int cmd,...)
{if(fd<3){assert(cmd==F_GETFL);return O_RDWR;}assert(fd==4);if(cmd==F_GETFD)return FD_CLOEXEC;assert(cmd==F_GETFL);return O_RDWR|O_NONBLOCK;}
int __wrap_getsockopt(int fd,int level,int option,void *value,socklen_t *length)
{if(fd==500){assert(manager_live&&level==SOL_SOCKET);
 if(option==SO_PEERCRED){assert(*length==sizeof(struct ucred));*(struct ucred *)value=(struct ucred){.pid=scenario==-17?2:1,.uid=0,.gid=0};return 0;}
 assert((option==SO_PASSCRED||option==SO_PASSSEC||option==SO_ERROR)&&*length==sizeof(int));*(int *)value=0;return 0;}
 assert(level==SOL_SOCKET&&*length==sizeof(int));
 if(option==SO_SNDBUF||option==SO_RCVBUF){int bit=1<<((fd-3)*2+(option==SO_RCVBUF));
  assert((fd==3||fd==4)&&!forked&&(buffer_set_mask&bit)&&!(buffer_get_mask&bit));buffer_get_mask|=bit;*(int *)value=262144;return 0;}
 if(option==SO_PASSCRED){assert((fd==3||fd==4)&&!forked);*(int *)value=(passcred_mask>>(fd-3))&1;return 0;}
 assert(fd==4);*(int *)value=option==SO_DOMAIN?AF_UNIX:option==SO_TYPE?SOCK_SEQPACKET:0;return 0;}
int __wrap_setsockopt(int fd,int level,int option,const void *value,socklen_t length)
{if(fd==500){assert(manager_live&&level==SOL_SOCKET&&(option==SO_PASSCRED||option==SO_PASSSEC)&&length==sizeof(int)&&*(const int *)value==0);return 0;}
 assert(!forked&&(fd==3||fd==4)&&level==SOL_SOCKET&&length==sizeof(int));
 if(option==SO_SNDBUF||option==SO_RCVBUF){int bit=1<<((fd-3)*2+(option==SO_RCVBUF));
  assert(*(const int *)value==131072&&!(buffer_set_mask&bit));buffer_set_mask|=bit;return 0;}
 assert(option==SO_PASSCRED&&*(const int *)value==1);
 int bit=1<<(fd-3);assert(!(passcred_mask&bit));passcred_mask|=bit;return 0;}
int __wrap_statx(int fd,const char *p,int flags,unsigned int mask,struct statx *s)
{if(fd==740){assert(!strcmp(p,"")&&flags==(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW)&&mask==STATX_MNT_ID);return sp_statx(s,0);}
 if(fd==741){assert(!strcmp(p,"")&&flags==(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW)&&mask==STATX_MNT_ID);return so_statx(s);}
 if(fd>=730&&fd<=731){assert(!strcmp(p,"")&&flags==(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW)&&mask==STATX_MNT_ID);return mi_statx(fd,s);}
 if(fd==720){assert(!strcmp(p,"")&&flags==(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW)&&mask==STATX_MNT_ID);return cg_file_statx(s);}
 if(fd>=700&&fd<716){assert(!strcmp(p,"")&&flags==(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW)&&mask==STATX_MNT_ID);return cg_statx(fd,s);}
 if(fd>=600){int r=fd-600;assert(r<3&&manager_paths_live[r]&&!strcmp(p,"")&&flags==(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW)&&mask==STATX_MNT_ID);
 memset(s,0,sizeof(*s));s->stx_mask=STATX_MNT_ID;s->stx_mnt_id=4000+r;return 0;}
 if(fd>=400){int r=unit_role(fd);assert(!strcmp(p,"")&&flags==(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW)&&mask==STATX_MNT_ID);
 memset(s,0,sizeof(*s));s->stx_mask=STATX_MNT_ID;s->stx_mnt_id=3000+r;return 0;}
 if(fd>=300){int r=executable_role(fd);assert(!strcmp(p,"")&&flags==(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW)&&mask==STATX_MNT_ID);
 memset(s,0,sizeof(*s));s->stx_mask=STATX_MNT_ID;s->stx_mnt_id=(r==5||r==7)?50:200+r;return 0;}
 if(fd>=100)return op_statx(fd,p,flags,mask,s);
 if(fd>=70&&fd<80){assert(guard_live[fd-70]);memset(s,0,sizeof(*s));s->stx_mask=STATX_MNT_ID;
 int role=guard_role[fd-70];s->stx_mnt_id=role==0?10:role==8?30:20;return 0;}
 assert(fd_live[fd]&&!strcmp(p,"")&&flags==(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW)&&mask==STATX_MNT_ID);memset(s,0,sizeof(*s));s->stx_mask=STATX_MNT_ID;s->stx_mnt_id=1000+input_role(fd);return 0;}
int __wrap_fstatfs(int fd,struct statfs *s)
{if(fd>=730&&fd<=731)return mi_statfs(fd,s);
 if(fd==720)return cg_file_statfs(s);
 if(fd>=700&&fd<716)return cg_statfs(fd,s);
 if(fd>=100)return op_statfs(fd,s);
 if(fd>=70&&fd<80){assert(guard_live[fd-70]);memset(s,0,sizeof(*s));int role=guard_role[fd-70];
 s->f_type=role==0?0xef53:role==8?0x6e736673:0x9fa0;return 0;}
 assert(fd_live[fd]);memset(s,0,sizeof(*s));s->f_type=0xef53;return 0;}
ssize_t __wrap_pread(int fd,void *p,size_t n,off_t offset)
{
 if(fd==731)return mi_read(p,n,offset);
 if(fd==720)return cg_file_read(p,n,offset);
 if(project_model_active)return op_read(fd,p,n,offset);
 if(fd>=400){int r=unit_role(fd);assert(r<4&&offset>=0);size_t length=strlen(fixture_units[r]);
  if((size_t)offset==length)return 0;
  assert((size_t)offset+n<=length);memcpy(p,fixture_units[r]+offset,n);
  if(scenario==-15&&r==1&&offset==0&&n)((unsigned char *)p)[0]^=1;
  return (ssize_t)n;}
 if(fd>=300||(fd>=100&&fd<256&&used[fd]&&role[fd]>=23&&role[fd]<=25)){
  int r=fd>=300?executable_role(fd):role[fd];
  assert((fd>=300?(r==5||r==7):1)&&offset>=0&&n<=32768);
  int manager=fd>=300?r==7:r==25;const unsigned char *raw=manager?fixture_manager:fixture_native;
  if(offset==1024)return 0;
  assert((size_t)offset+n<=1024);memcpy(p,raw+offset,n);
  if(scenario==-12&&fd<256&&r==23&&offset==0&&n==1024)((unsigned char *)p)[100]^=1;
  return (ssize_t)n;
 }
 assert(fd>=0&&fd<64&&fd_live[fd]);int role=input_role(fd);assert(role==3||role==4||(role>=7&&role<=10));if(scenario==6||scenario==13){if(scenario==13)boot=25000000000LL;errno=EIO;return -1;}
 size_t total=role==3?448:role==4?task_size:role==7?sizeof(fixture_policy):role==8?sizeof(fixture_config)-1:role==9?sizeof(fixture_enrollment)-1:sizeof(fixture_startup)-1;
 const unsigned char *raw=role==3?installation:role==4?task:role==7?fixture_policy:role==8?fixture_config:role==9?fixture_enrollment:fixture_startup;
 if((size_t)offset==total){if(scenario==15){boot=25000000000LL;*(char *)p=1;return 1;}return 0;}
 assert(offset>=0&&(size_t)offset+n<=total&&n<=32768);memcpy(p,raw+offset,n);
 if(offset==0&&n&&((scenario==19&&role==7)||(scenario>=-3&&scenario<=-1&&role==7-scenario)))((unsigned char *)p)[0]^=1;
 if(scenario==4||scenario==14)boot=25000000000LL;
 return (ssize_t)n-(scenario==14?1:0);
}
int __wrap_close(int fd)
{
 if(fd==740)return sp_close();
 if(fd==741)return so_close();
 if(fd>=730&&fd<=731)return mi_close(fd);
 if(fd==720)return cg_file_close();
 if(fd>=700&&fd<716)return cg_close(fd);
 if(fd>=600){int r=fd-600;assert(r<3&&manager_paths_live[r]);manager_paths_live[r]=0;return 0;}
 if(fd==500){assert(manager_live);manager_live=0;return 0;}
 if(fd>=400){(void)unit_role(fd);unit_live[fd-400]=0;
  if(scenario==16||scenario==17){boot=25000000000LL;if(scenario==16){errno=EINTR;return -1;}}return 0;}
 if(fd>=300){(void)executable_role(fd);executable_live[fd-300]=0;return 0;}
 if(fd>=100){int r=op_close(fd);
  if(!project_model_active&&(scenario==16||scenario==17)){boot=25000000000LL;if(scenario==16){errno=EINTR;return -1;}}return r;}
 if(fd>=70&&fd<80){assert(guard_live[fd-70]);guard_live[fd-70]=0;--guard_count;
 if(!guard_count)guard_done=1;
 return 0;}
 if(fd==50||fd==51)return 0;
 if(fd==3&&scanner){scanner=0;return 0;}
 if(fd==3||fd==4){++gate_closed;return 0;}
 assert(fd>=10&&fd<41&&fd_live[fd]);fd_live[fd]=0;++fd_closed[fd];
 if(scenario==16||scenario==17){boot=25000000000LL;if(scenario==16){errno=EINTR;return -1;}}return 0;
}
int __wrap_socketpair(int domain,int type,int protocol,int fds[2])
{assert(domain==AF_UNIX&&type==(SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK)&&!protocol&&scans==1&&!scanner);fds[0]=3;fds[1]=4;return 0;}
int __wrap_socket(int domain,int type,int protocol)
{assert(domain==AF_UNIX&&type==(SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC)&&!protocol&&!manager_live);manager_live=1;return 500;}
int __wrap_connect(int fd,const struct sockaddr *address,socklen_t length)
{const struct sockaddr_un *u=(const struct sockaddr_un *)address;assert(fd==500&&manager_live&&u->sun_family==AF_UNIX&&
 !strcmp(u->sun_path,"/run/systemd/private")&&length==offsetof(struct sockaddr_un,sun_path)+sizeof("/run/systemd/private"));return 0;}
int __wrap_sigaction(int sig,const struct sigaction *action,struct sigaction *old)
{assert(sig==SIGCHLD&&!action&&old);memset(old,0,sizeof(*old));old->sa_handler=SIG_DFL;return 0;}
pid_t __wrap_fork(void)
{assert(status_opens==1&&!forked&&passcred_mask==3&&buffer_set_mask==15&&buffer_get_mask==15);++forks;forked=1;if(scenario<20){owner=101;return 0;}return 101;}
int __wrap_prctl(int option,...)
{va_list a;va_start(a,option);if(option==PR_SET_PDEATHSIG){assert(va_arg(a,unsigned long)==SIGKILL);armed=SIGKILL;}else{assert(option==PR_GET_PDEATHSIG);*va_arg(a,int *)=armed;}va_end(a);return 0;}
ssize_t __wrap_send(int fd,const void *p,size_t n,int flags)
{if(fd==500){static const char auth[]="\0AUTH EXTERNAL 30\r\n",begin[]="BEGIN\r\n";
 assert(manager_live&&flags==MSG_NOSIGNAL);
 if(!manager_phase){assert(n==sizeof(auth)-1&&!memcmp(p,auth,n));manager_phase=1;}
 else{assert(manager_phase==2&&n==sizeof(begin)-1&&!memcmp(p,begin,n));manager_phase=3;}
 return (ssize_t)n;}
 assert(owner==101&&fd==4&&n==8&&!memcmp(p,"RNRKARM1",8)&&flags==(MSG_DONTWAIT|MSG_NOSIGNAL));++sends;return 8;}
ssize_t __wrap_sendmsg(int fd,const struct msghdr *m,int flags)
{assert(fd==500&&manager_live&&flags==MSG_NOSIGNAL&&m->msg_iovlen==1&&!m->msg_control&&!m->msg_controllen);
 if((manager_phase==19&&manager_cgroup_arrays==8&&manager_reply_offset==manager_id_reply_length)||
    (manager_phase==20&&manager_reply_offset==manager_id_reply_length)){
  assert(manager_cgroup_ids<4);unsigned int role=manager_cgroup_ids;
  fixture_check_property_interface(m->msg_iov[0].iov_base,m->msg_iov[0].iov_len,role,
      role?"org.freedesktop.systemd1.Slice":"org.freedesktop.systemd1.Service","ControlGroupId",273+manager_cgroup_ids);
  manager_id_reply_length=fixture_cgroup_id_reply(manager_reply,role);
  manager_reply_offset=0;manager_phase=20;return (ssize_t)m->msg_iov[0].iov_len;}
 if((manager_phase==18&&manager_cgroup_scalars==24&&manager_reply_offset==manager_id_reply_length)||
    (manager_phase==19&&manager_reply_offset==manager_id_reply_length)){
  assert(manager_cgroup_arrays<8);unsigned int field=manager_cgroup_arrays/4,role=manager_cgroup_arrays%4;
  fixture_check_property_interface(m->msg_iov[0].iov_base,m->msg_iov[0].iov_len,role,
      role?"org.freedesktop.systemd1.Slice":"org.freedesktop.systemd1.Service",fixture_cgroup_arrays[field],265+manager_cgroup_arrays);
  manager_id_reply_length=fixture_cgroup_array_reply(manager_reply,field,role);
  manager_reply_offset=0;manager_phase=19;return (ssize_t)m->msg_iov[0].iov_len;}
 if((manager_phase==17&&manager_cgroup_strings==20&&manager_reply_offset==manager_id_reply_length)||
    (manager_phase==18&&manager_reply_offset==manager_id_reply_length)){
  assert(manager_cgroup_scalars<24);unsigned int field=manager_cgroup_scalars/4,role=manager_cgroup_scalars%4;
  fixture_check_property_interface(m->msg_iov[0].iov_base,m->msg_iov[0].iov_len,role,
      role?"org.freedesktop.systemd1.Slice":"org.freedesktop.systemd1.Service",fixture_cgroup_scalars[field],241+manager_cgroup_scalars);
  manager_id_reply_length=fixture_cgroup_scalar_reply(manager_reply,field,role,cg_distinct_policy);
  manager_reply_offset=0;manager_phase=18;return (ssize_t)m->msg_iov[0].iov_len;}
 if((manager_phase==16&&manager_service_exec==1&&manager_reply_offset==manager_id_reply_length)||
    (manager_phase==17&&manager_reply_offset==manager_id_reply_length)){
  assert(manager_cgroup_strings<20);unsigned int field=manager_cgroup_strings/4,role=manager_cgroup_strings%4;
  fixture_check_property_interface(m->msg_iov[0].iov_base,m->msg_iov[0].iov_len,role,
      role?"org.freedesktop.systemd1.Slice":"org.freedesktop.systemd1.Service",fixture_cgroup_strings[field],221+manager_cgroup_strings);
  manager_id_reply_length=fixture_cgroup_string_reply(manager_reply,field,role);
  manager_reply_offset=0;manager_phase=17;return (ssize_t)m->msg_iov[0].iov_len;}
 if(manager_phase==15&&manager_service_empty==11&&manager_reply_offset==manager_id_reply_length){
  fixture_check_property_interface(m->msg_iov[0].iov_base,m->msg_iov[0].iov_len,0,
      "org.freedesktop.systemd1.Service","ExecStartEx",220);
  manager_id_reply_length=fixture_service_exec_reply(manager_reply,100,fixture_native_hash);
  manager_reply_offset=0;manager_phase=16;return (ssize_t)m->msg_iov[0].iov_len;}
 if((manager_phase==14&&manager_service_scalars==14&&manager_reply_offset==manager_id_reply_length)||
    (manager_phase==15&&manager_reply_offset==manager_id_reply_length)){
  assert(manager_service_empty<11);fixture_check_property_interface(m->msg_iov[0].iov_base,m->msg_iov[0].iov_len,0,
      "org.freedesktop.systemd1.Service",fixture_service_empty_names[manager_service_empty],209+manager_service_empty);
  manager_id_reply_length=fixture_service_empty_reply(manager_reply,manager_service_empty);
  manager_reply_offset=0;manager_phase=15;return (ssize_t)m->msg_iov[0].iov_len;}
 if((manager_phase==13&&manager_service_fields==20&&manager_reply_offset==manager_id_reply_length)||
    (manager_phase==14&&manager_reply_offset==manager_id_reply_length)){
  assert(manager_service_scalars<14);fixture_check_property_interface(m->msg_iov[0].iov_base,m->msg_iov[0].iov_len,0,
      "org.freedesktop.systemd1.Service",fixture_service_scalar_names[manager_service_scalars],195+manager_service_scalars);
  manager_id_reply_length=fixture_service_scalar_reply(manager_reply,manager_service_scalars,100);
  manager_reply_offset=0;manager_phase=14;return (ssize_t)m->msg_iov[0].iov_len;}
 if((manager_phase==12&&manager_unit_timeouts==8&&manager_reply_offset==manager_id_reply_length)||
    (manager_phase==13&&manager_reply_offset==manager_id_reply_length)){
  assert(manager_service_fields<20);fixture_check_property_interface(m->msg_iov[0].iov_base,m->msg_iov[0].iov_len,0,
      "org.freedesktop.systemd1.Service",fixture_service_field_names[manager_service_fields],175+manager_service_fields);
  manager_id_reply_length=fixture_service_field_reply(manager_reply,manager_service_fields);
  manager_reply_offset=0;manager_phase=13;return (ssize_t)m->msg_iov[0].iov_len;}
 if((manager_phase==11&&manager_unit_dependencies==80&&manager_reply_offset==manager_id_reply_length)||
    (manager_phase==12&&manager_reply_offset==manager_id_reply_length)){
  assert(manager_unit_timeouts<8);unsigned int field=manager_unit_timeouts/4,role=manager_unit_timeouts%4;
  fixture_check_property(m->msg_iov[0].iov_base,m->msg_iov[0].iov_len,role,fixture_unit_timeout_names[field],167+manager_unit_timeouts);
  manager_id_reply_length=fixture_unit_timeout_reply(manager_reply,field,role);
  manager_reply_offset=0;manager_phase=12;return (ssize_t)m->msg_iov[0].iov_len;}
 if((manager_phase==10&&manager_unit_facts==8&&manager_reply_offset==manager_id_reply_length)||
    (manager_phase==11&&manager_reply_offset==manager_id_reply_length)){
  assert(manager_unit_dependencies<80);unsigned int field=manager_unit_dependencies/4,role=manager_unit_dependencies%4;
  fixture_check_property(m->msg_iov[0].iov_base,m->msg_iov[0].iov_len,role,fixture_unit_dependency_names[field],87+manager_unit_dependencies);
  manager_id_reply_length=fixture_unit_dependency_reply(manager_reply,field,role);
  manager_reply_offset=0;manager_phase=11;return (ssize_t)m->msg_iov[0].iov_len;}
 if((manager_phase==9&&manager_unit_bools==28&&manager_reply_offset==manager_id_reply_length)||
    (manager_phase==10&&manager_reply_offset==manager_id_reply_length)){
  assert(manager_unit_facts<8);unsigned int field=manager_unit_facts/4,role=manager_unit_facts%4;
  fixture_check_property(m->msg_iov[0].iov_base,m->msg_iov[0].iov_len,role,fixture_unit_fact_names[field],79+manager_unit_facts);
  manager_id_reply_length=fixture_unit_fact_reply(manager_reply,field,role);
  manager_reply_offset=0;manager_phase=10;return (ssize_t)m->msg_iov[0].iov_len;}
 if((manager_phase==8&&manager_unit_fields==40&&manager_reply_offset==manager_id_reply_length)||
    (manager_phase==9&&manager_reply_offset==manager_id_reply_length)){
  assert(manager_unit_bools<28);unsigned int field=manager_unit_bools/4,role=manager_unit_bools%4;
  fixture_check_property(m->msg_iov[0].iov_base,m->msg_iov[0].iov_len,role,fixture_unit_bool_names[field],51+manager_unit_bools);
  manager_id_reply_length=fixture_unit_bool_reply(manager_reply,field,role);
  manager_reply_offset=0;manager_phase=9;return (ssize_t)m->msg_iov[0].iov_len;}
 if((manager_phase==7&&manager_unit_names==4&&manager_reply_offset==manager_id_reply_length)||
    (manager_phase==8&&manager_reply_offset==manager_id_reply_length)){
  assert(manager_unit_fields<40);unsigned int field=manager_unit_fields/4,role=manager_unit_fields%4;
  fixture_check_property(m->msg_iov[0].iov_base,m->msg_iov[0].iov_len,role,fixture_unit_field_names[field],11+manager_unit_fields);
  manager_id_reply_length=fixture_unit_field_reply(manager_reply,field,role);
  manager_reply_offset=0;manager_phase=8;return (ssize_t)m->msg_iov[0].iov_len;}
 if((manager_phase==6&&manager_unit_ids==4&&manager_reply_offset==manager_id_reply_length)||
    (manager_phase==7&&manager_reply_offset==manager_id_reply_length)){
  assert(manager_unit_names<4);fixture_check_property(m->msg_iov[0].iov_base,m->msg_iov[0].iov_len,manager_unit_names,"Names",7+manager_unit_names);
  manager_id_reply_length=fixture_names_reply(manager_reply,manager_unit_names);
  manager_reply_offset=0;manager_phase=7;return (ssize_t)m->msg_iov[0].iov_len;}
 if((manager_phase==5&&manager_reply_offset==sizeof(fixture_unit_path_reply))||
    (manager_phase==6&&manager_reply_offset==manager_id_reply_length)){
  assert(manager_unit_ids<4);fixture_check_id(m->msg_iov[0].iov_base,m->msg_iov[0].iov_len,manager_unit_ids);
  manager_id_reply_length=fixture_id_reply(manager_reply,manager_unit_ids);
  manager_reply_offset=0;manager_phase=6;return (ssize_t)m->msg_iov[0].iov_len;}
 if(manager_phase==4&&manager_reply_offset==146){
  assert(m->msg_iov[0].iov_len==sizeof(fixture_unit_path_request)&&
         !memcmp(m->msg_iov[0].iov_base,fixture_unit_path_request,sizeof(fixture_unit_path_request)));
  manager_reply_offset=0;manager_phase=5;return (ssize_t)m->msg_iov[0].iov_len;}
 assert(manager_phase==3);
 fixture_check_lookup(m->msg_iov[0].iov_base,m->msg_iov[0].iov_len,100);fixture_lookup_reply(manager_reply,0);
 if(scenario==-19)manager_reply[144]^=1;
 if(scenario==-20)manager_reply[20]=2;
 manager_reply_offset=0;manager_phase=4;return (ssize_t)m->msg_iov[0].iov_len;}
int __wrap_poll(struct pollfd *p,nfds_t n,int timeout)
{if(project_model_active)return op_poll(p,n,timeout);
 if(n==1&&p->fd==500){assert(manager_live&&timeout==1);p->revents=p->events;return 1;}
 assert(owner==100);if(timeout==0){assert(n==1&&p->fd==62);return 0;}
 assert(p->fd==3&&n==2&&p[1].fd==62&&timeout>0&&timeout<=15000);if(scenario==21)return 0;if(scenario==22)boot=25000000000LL;if(scenario==25)boot=100000000000LL;p->revents=POLLIN;return 1;}
ssize_t __wrap_recvmsg(int fd,struct msghdr *m,int flags)
{if(fd==500&&(manager_phase>=6&&manager_phase<=20)){assert(manager_live&&flags==(MSG_DONTWAIT|MSG_CMSG_CLOEXEC)&&m->msg_iovlen==1&&!m->msg_control&&!m->msg_controllen);
 size_t end=manager_reply_offset<16?16:manager_id_reply_length;assert(m->msg_iov[0].iov_len==end-manager_reply_offset);
 size_t n=end-manager_reply_offset;memcpy(m->msg_iov[0].iov_base,manager_reply+manager_reply_offset,n);
 m->msg_flags=0;manager_reply_offset+=n;if(manager_reply_offset==manager_id_reply_length){if(manager_phase==6)++manager_unit_ids;else if(manager_phase==7)++manager_unit_names;else if(manager_phase==8)++manager_unit_fields;else if(manager_phase==9)++manager_unit_bools;else if(manager_phase==10)++manager_unit_facts;else if(manager_phase==11)++manager_unit_dependencies;else if(manager_phase==12)++manager_unit_timeouts;else if(manager_phase==13)++manager_service_fields;else if(manager_phase==14)++manager_service_scalars;else if(manager_phase==15)++manager_service_empty;else if(manager_phase==16)++manager_service_exec;else if(manager_phase==17)++manager_cgroup_strings;else if(manager_phase==18)++manager_cgroup_scalars;else if(manager_phase==19)++manager_cgroup_arrays;else ++manager_cgroup_ids;}return (ssize_t)n;}
 if(fd==500&&manager_phase==5){assert(manager_live&&flags==(MSG_DONTWAIT|MSG_CMSG_CLOEXEC)&&m->msg_iovlen==1&&!m->msg_control&&!m->msg_controllen);
 size_t end=manager_reply_offset<16?16:sizeof(fixture_unit_path_reply);assert(m->msg_iov[0].iov_len==end-manager_reply_offset);
 size_t n=end-manager_reply_offset;memcpy(m->msg_iov[0].iov_base,fixture_unit_path_reply+manager_reply_offset,n);
 m->msg_flags=0;manager_reply_offset+=n;return (ssize_t)n;}
 if(fd==500&&manager_phase==4){assert(manager_live&&flags==(MSG_DONTWAIT|MSG_CMSG_CLOEXEC)&&m->msg_iovlen==1&&!m->msg_control&&!m->msg_controllen);
 size_t end=manager_reply_offset<16?16:146;assert(m->msg_iov[0].iov_len==end-manager_reply_offset);
 size_t n=end-manager_reply_offset;memcpy(m->msg_iov[0].iov_base,manager_reply+manager_reply_offset,n);
 m->msg_flags=0;manager_reply_offset+=n;return (ssize_t)n;}
 if(fd==500){static const char response[]="OK 0123456789abcdef0123456789abcdef\r\n";
 assert(manager_live&&manager_phase==1&&flags==(MSG_DONTWAIT|MSG_CMSG_CLOEXEC)&&m->msg_iovlen==1&&
  m->msg_iov[0].iov_len==sizeof(response)-1&&!m->msg_control&&!m->msg_controllen);
 memcpy(m->msg_iov[0].iov_base,response,sizeof(response)-1);if(scenario==-18)((char *)m->msg_iov[0].iov_base)[3]='G';
 m->msg_flags=0;manager_phase=2;return sizeof(response)-1;}
 assert(fd==3&&m->msg_iovlen==1&&flags==(MSG_DONTWAIT|MSG_TRUNC|MSG_CMSG_CLOEXEC));
 assert(m->msg_control&&m->msg_controllen==CMSG_SPACE(sizeof(struct ucred)));
 struct cmsghdr *c=CMSG_FIRSTHDR(m);c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_CREDENTIALS;c->cmsg_len=CMSG_LEN(sizeof(struct ucred));
 struct ucred u={.pid=101,.uid=0,.gid=0};memcpy(CMSG_DATA(c),&u,sizeof(u));
 memcpy(m->msg_iov[0].iov_base,"RNRKARM1",8);return 8;}
long __wrap_syscall(long call,...)
{
 va_list a;va_start(a,call);long result=0;
 if(call==SYS_gettid){result=owner;}
 else if(call==SYS_name_to_handle_at){int fd=va_arg(a,int);const char *path=va_arg(a,const char *);
  struct file_handle *h=va_arg(a,struct file_handle *);int *mount=va_arg(a,int *);int flags=va_arg(a,int);
  assert(!strcmp(path,"")&&flags==AT_EMPTY_PATH);result=cg_handle(fd,h,mount);}
 else if(call==SYS_openat2){int parent=va_arg(a,int);const char *path=va_arg(a,const char *);
  const struct open_how *how=va_arg(a,const struct open_how *);size_t size=va_arg(a,size_t);
  int root=(parent>=100&&parent<256&&used[parent]&&role[parent]==0)?parent:-1;
  if(parent==root&&how->resolve==RESOLVE_IN_ROOT&&how->flags==(unsigned long)(O_RDONLY|O_DIRECTORY|O_CLOEXEC)){
   assert(size==sizeof(*how));result=so_open(path,0);va_end(a);return result;}
  if(parent==root&&how->resolve==RESOLVE_IN_ROOT){assert(size==sizeof(*how)&&how->flags==(unsigned long)(O_PATH|O_DIRECTORY|O_CLOEXEC));
   result=sp_open(path,0);va_end(a);return result;}
  int mi=mi_open(parent,path,root,owner);if(mi!=-2){assert(size==sizeof(*how)&&how->resolve==(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS));
   if(mi>=0)assert(how->flags==(unsigned long)(O_RDONLY|O_NOFOLLOW|O_CLOEXEC|(mi==730?O_DIRECTORY:O_NONBLOCK)));
   va_end(a);return mi;}
  int cg=cg_open(parent,path,(parent>=100&&parent<256&&used[parent]&&role[parent]==0)?parent:-1);
  if(cg!=-2){assert(size==sizeof(*how)&&how->resolve==(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS));
   if(cg>=0)assert(how->flags==(unsigned long)(O_RDONLY|O_NOFOLLOW|O_CLOEXEC|(cg==720?O_NONBLOCK:O_DIRECTORY)));
   va_end(a);return cg;}
  if(parent>=100&&parent<256){int r=!strcmp(path,"run")?0:!strcmp(path,"run/systemd")?1:!strcmp(path,"run/systemd/private")?2:-1;
   assert(used[parent]&&role[parent]==0&&r>=0&&size==sizeof(*how)&&how->resolve==(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS));
   assert(how->flags==(unsigned long)((r==2?O_PATH:O_RDONLY|O_DIRECTORY)|O_NOFOLLOW|O_CLOEXEC)&&!manager_paths_live[r]);
   manager_paths_live[r]=1;++opens;result=600+r;va_end(a);return result;}
  assert(parent==11&&fd_live[parent]&&size==sizeof(*how)&&how->resolve==(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS));
  const char *project="1111111111111111111111111111111111111111111111111111111111111111";
  int r=-1;if(!strcmp(path,"systemd"))r=4;else if(!strcmp(path,"systemd/system"))r=5;
  else{const char *const formats[]={"systemd/system/rnrc%s.service","systemd/system/rnrc%s.slice",
     "systemd/system/rnrw%s.slice","systemd/system/rnrw%s-anchor.slice"};
   for(int i=0;i<4;++i){char expected[128];snprintf(expected,sizeof(expected),formats[i],project);if(!strcmp(path,expected))r=i;}}
  assert(r>=0&&how->flags==(unsigned long)(O_RDONLY|O_CLOEXEC|O_NOFOLLOW|(r>=4?O_DIRECTORY:O_NONBLOCK)));
  ++opens;if(scenario==-16&&r==0){errno=ELOOP;result=-1;}
  else{int i=r;if(unit_live[i]){assert(r<4);i=6+r;}assert(i<10&&!unit_live[i]);unit_live[i]=1;result=400+i;}}
 else if(call==SYS_pidfd_open&&project_model_active){int pid=va_arg(a,int);int flags=va_arg(a,int);result=op_syscall(call,pid,flags);}
 else if(call==SYS_pidfd_open){assert(va_arg(a,int)==101&&va_arg(a,int)==0);++pidfds;if(scenario==23){errno=EMFILE;result=-1;}else result=62;}
 else if(call==SYS_pidfd_send_signal||call==SYS_kill){assert(va_arg(a,int)==(call==SYS_kill?101:62));assert(va_arg(a,int)==SIGKILL);++signals;signal_kind=(int)call;if(scenario==26){errno=EPERM;result=-1;}}
 else{
  assert(call==SYS_getdents64);int fd=va_arg(a,int);unsigned char *buffer=va_arg(a,unsigned char *);size_t count=va_arg(a,size_t);
  if(fd==741){result=so_scan(buffer,count,0);va_end(a);return result;}
  if(fd==715){result=cg_scan(fd,buffer,count);va_end(a);return result;}
  assert(fd==3&&count==4096);
  static int read_count;if(read_count++%2)result=0;
  else{const char *names[]={".","..","0","1","2","3","4","8"};int count=forked?(scenario==7?8:7):6;size_t offset=0;
   for(int i=0;i<count;++i){unsigned char *p=buffer+offset;memset(p,0,24);p[16]=24;memcpy(p+19,names[i],strlen(names[i]));offset+=24;}result=(long)offset;}
 }
 va_end(a);return result;
}
_Noreturn void __wrap__exit(int status){exit_code=status;longjmp(exited,1);}
/* Fortified libc aliases are also kernel boundaries. */
int __wrap___open_2(const char *p,int flags){return __wrap_open(p,flags);}
int __wrap___openat_2(int fd,const char *p,int flags){return __wrap_openat(fd,p,flags);}
ssize_t __wrap___pread_chk(int fd,void *p,size_t n,off_t off,size_t size)
{assert(n<=size);return __wrap_pread(fd,p,n,off);}
/* Unexercised native stages cannot escape to the host if a regression routes
 * the fixture into them. Link every residual host boundary to a hard stop. */
ssize_t __wrap_fgetxattr(int fd,const char *name,void *value,size_t length)
{
 assert(!strcmp(name,"security.capability")&&!value&&!length);
 if(fd>=300){int r=executable_role(fd);assert(r==5||r==7);}
 else assert(fd>=100&&fd<256&&used[fd]&&role[fd]>=23&&role[fd]<=25);
 if(scenario==-14)return 0;
 errno=scenario==-13?EOPNOTSUPP:ENODATA;return -1;
}
#define DENY(name) _Noreturn void __wrap_##name(void){assert(!"unexpected host boundary: " #name);abort();}
DENY(chdir) DENY(chroot) DENY(dup2) DENY(dup3) DENY(execve) DENY(fchdir)
DENY(fchmod) DENY(fstatat) DENY(fstatvfs) DENY(fsync) DENY(ftruncate)
DENY(getrandom) DENY(memfd_create) DENY(mkdirat) DENY(mount)
DENY(pipe2) DENY(pwrite) DENY(umask) DENY(waitpid)
int main(int argc,char **argv)
{
 op_model_reset();cg_supervised_pair=1;assert(argc==2);scenario=atoi(argv[1]);if(scenario==18)time_mismatch=1;size_t payload=fread(task+64,1,65536,stdin);assert(payload&&payload<65536);task_size=payload+64;
 memcpy(task,"RNRT0001",8);task[8]=1;memset(task+16,0xaa,16);le(task+32,scenario==2?160000000000LL:190000000000LL,8);le(task+40,payload,4);
 memcpy(installation,"RNRI0002",8);installation[8]=2;installation[16]=1;installation[48]=2;le(installation+80,129,8);le(installation+88,3,8);memset(installation+96,0xff,32);memset(installation+128,1,272);memset(installation+128,0x11,32);memset(installation+400,0,48);memcpy(installation+200,"11111111-1111-1111-1111-111111111111",36);memset(installation+236,0,4);memset(installation+336,0x11,32);
 memset(installation+16,0x11,32);
 fixture_policy_setup(installation);
 if(scenario==1)installation[200]='2';
 if(scenario==5)installation[96]^=1;
 if(scenario==9)installation[16]^=1;
 static struct rnr_stage0_preparer_error error;
 if(scenario<20){
  if(!setjmp(exited)){(void)rnr_stage0_supervised_inputs(&error);assert(0);}
  assert(exit_code==125&&forks==1&&sends==1&&signals==0&&gate_closed==2);
  assert(scans==2&&held_scans==1);
  for(int fd=10;fd<41;++fd)assert(!fd_live[fd]);
  for(int i=0;i<16;++i)assert(!executable_live[i]);
  for(int i=0;i<10;++i)assert(!unit_live[i]);
  for(int i=0;i<3;++i)assert(!manager_paths_live[i]);
  assert(!manager_live);
  if(scenario==0){assert(error.code==RNR_STAGE0_PREPARER_OK);}
  else assert(error.code!=RNR_STAGE0_PREPARER_OK);
  if(scenario==9)assert(error.code==RNR_STAGE0_PREPARER_IDENTITY);
  if(scenario==19||(scenario>=-3&&scenario<=-1))assert(error.code==RNR_STAGE0_PREPARER_IDENTITY);
  if(scenario==-12)assert(error.code==RNR_STAGE0_PREPARER_IDENTITY);
  if(scenario==-13||scenario==-14)assert(error.code==RNR_STAGE0_PREPARER_METADATA);
  if(scenario==-15)assert(error.code==RNR_STAGE0_PREPARER_IDENTITY);
  if(scenario==-16)assert(error.code==RNR_STAGE0_PREPARER_OPEN&&error.system_errno==ELOOP);
  if(scenario==-17||scenario==-18||scenario==-19||scenario==-20)assert(error.code==RNR_STAGE0_PREPARER_PID1);
  if(scenario>=-11&&scenario<=-5)assert(error.code==RNR_STAGE0_PREPARER_IDENTITY);
  if(scenario==-4)assert(error.code==RNR_STAGE0_PREPARER_OPEN&&error.system_errno==ENOENT);
  if(scenario>=10&&scenario<=12){
   assert(error.code==RNR_STAGE0_PREPARER_BOOTSTRAP&&opens==0&&guard_count==0);
   if(scenario==11)assert(error.bootstrap.code==RNR_STAGE0_BOOTSTRAP_CLOCK&&guard_namespace);
  }
  if(scenario>=13&&scenario<=17){
   assert(error.launch.code==RNR_STAGE0_LAUNCH_CLOCK&&error.launch.final.code==RNR_STAGE0_CLOCK_CUTOFF);
   assert(error.code==(scenario==16?RNR_STAGE0_PREPARER_CLEANUP:scenario==17?RNR_STAGE0_PREPARER_CLOCK:RNR_STAGE0_PREPARER_READ));
   assert(error.system_errno==(scenario==13?EIO:scenario==16?EINTR:0));
   if(scenario==16)assert(error.cleanup_count==11);
  }
  if(scenario==18)assert(error.code==RNR_STAGE0_PREPARER_BOOTSTRAP&&error.project.clock.code==RNR_STAGE0_LAUNCH_CONTEXT&&opens==0);
  if(scenario==7)assert(opens==0); /* held inventory before first input open */
  int before=opens;struct rnr_stage0_preparer_error ordinary;
  assert(rnr_stage0_prepare_host_view(&ordinary)==-1&&opens==before);
  assert(rnr_stage0_finish_prepared_operational(&ordinary)==-1);
 }else{
  assert(rnr_stage0_supervised_inputs(&error)==-1&&forks==1&&held_scans==0&&opens==0&&gate_closed==2);
  assert(signals==((scenario==24||scenario==25)?0:1));
  if(scenario==23)assert(signal_kind==SYS_kill);else if(signals)assert(signal_kind==SYS_pidfd_send_signal);
  int before=signals;assert(rnr_stage0_supervised_inputs(&error)==-1&&signals==before&&forks==1);
 }
 return 0;
}
