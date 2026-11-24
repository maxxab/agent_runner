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
#include <poll.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include "../../automation/native/runtime_stage0_preparer.h"
static int scenario, owner=100, forked, armed, read_index, status_index, scanner;
static int scans, held_scans, opens, forks, signals, pidfds, sends, gate_closed;
static int fd_live[32], fd_closed[32], signal_kind, exit_code, status_opens;
static int passcred_mask;
static int64_t boot=10000000000LL, wall=100000000000LL;
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
{assert(held_scans==1);++opens;int fd=role+10;if(fd_live[fd])fd+=10;assert(!fd_live[fd]);fd_live[fd]=1;return fd;}
int __wrap_open(const char *p,int flags,...)
{
 if(!strcmp(p,"/proc/sys/kernel/random/boot_id")){assert(flags==(O_RDONLY|O_NOFOLLOW|O_CLOEXEC));read_index=0;return 50;}
 if(!strcmp(p,"/proc/self/status")){assert(!forked);++status_opens;status_index=0;return 51;}
 if(!strcmp(p,"/proc/self/fd")){assert(!scanner);scanner=1;++scans;if(forked){assert(owner==101);++held_scans;}return 3;}
 assert(!strcmp(p,"/")&&flags==(O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));return input_open(0);
}
ssize_t __wrap_read(int fd,void *p,size_t n)
{
 if(fd==50){if(read_index++){assert(n==1);return 0;}assert(n==38);memcpy(p,"11111111-1111-1111-1111-111111111111\n!",38);return 37;}
 assert(fd==51);if(status_index++)return 0;const char raw[]="Name:\trnr\nThreads:\t1\n";assert(n>=sizeof(raw)-1);memcpy(p,raw,sizeof(raw)-1);return sizeof(raw)-1;
}
int __wrap_openat(int parent,const char *p,int flags,...)
{
 int role;if(parent==10){assert(!strcmp(p,"etc"));role=1;}
 else if(parent==11){assert(!strcmp(p,"rnr"));role=2;}
 else {assert(parent==12);role=!strcmp(p,"installation.bin")?3:4;assert(role==3||!strcmp(p,"task.bin"));}
 assert(flags==(O_RDONLY|O_NOFOLLOW|O_CLOEXEC|(role<3?O_DIRECTORY:O_NONBLOCK)));return input_open(role);
}
int __wrap_fstat(int fd,struct stat *s)
{
 memset(s,0,sizeof(*s));s->st_dev=1;s->st_ino=100+fd;
 if(fd<3){s->st_mode=S_IFCHR;s->st_rdev=9;return 0;}
 if(fd==3&&scanner){s->st_mode=S_IFDIR|0500;return 0;}
 if(fd==4){s->st_mode=S_IFSOCK;return 0;}
 assert(fd>=10&&fd<25&&fd_live[fd]);int role=fd%10;s->st_ino=100+role;
 s->st_mode=role<3?S_IFDIR|0755:S_IFREG|0444;s->st_nlink=1;s->st_size=role==3?448:task_size;return 0;
}
int __wrap_fcntl(int fd,int cmd,...)
{if(fd<3){assert(cmd==F_GETFL);return O_RDWR;}assert(fd==4);if(cmd==F_GETFD)return FD_CLOEXEC;assert(cmd==F_GETFL);return O_RDWR|O_NONBLOCK;}
int __wrap_getsockopt(int fd,int level,int option,void *value,socklen_t *length)
{assert(level==SOL_SOCKET&&*length==sizeof(int));
 if(option==SO_PASSCRED){assert((fd==3||fd==4)&&!forked);*(int *)value=(passcred_mask>>(fd-3))&1;return 0;}
 assert(fd==4);*(int *)value=option==SO_DOMAIN?AF_UNIX:option==SO_TYPE?SOCK_SEQPACKET:0;return 0;}
int __wrap_setsockopt(int fd,int level,int option,const void *value,socklen_t length)
{assert(!forked&&(fd==3||fd==4)&&level==SOL_SOCKET&&option==SO_PASSCRED&&length==sizeof(int)&&*(const int *)value==1);
 int bit=1<<(fd-3);assert(!(passcred_mask&bit));passcred_mask|=bit;return 0;}
int __wrap_statx(int fd,const char *p,int flags,unsigned int mask,struct statx *s)
{assert(fd_live[fd]&&!strcmp(p,"")&&flags==(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW)&&mask==STATX_MNT_ID);memset(s,0,sizeof(*s));s->stx_mask=STATX_MNT_ID;s->stx_mnt_id=1000+fd%10;return 0;}
int __wrap_fstatfs(int fd,struct statfs *s)
{assert(fd_live[fd]);memset(s,0,sizeof(*s));s->f_type=0xef53;return 0;}
ssize_t __wrap_pread(int fd,void *p,size_t n,off_t offset)
{
 assert((fd==13||fd==14)&&fd_live[fd]);if(scenario==6){errno=EIO;return -1;}
 size_t total=fd==13?448:task_size;if((size_t)offset==total)return 0;
 assert(offset>=0&&(size_t)offset+n<=total&&n<=32768);memcpy(p,(fd==13?installation:task)+offset,n);
 if(scenario==4)boot=25000000000LL;
 return (ssize_t)n;
}
int __wrap_close(int fd)
{
 if(fd==50||fd==51)return 0;
 if(fd==3&&scanner){scanner=0;return 0;}
 if(fd==3||fd==4){++gate_closed;return 0;}
 assert(fd>=10&&fd<25&&fd_live[fd]);fd_live[fd]=0;assert(++fd_closed[fd]==1);return 0;
}
int __wrap_socketpair(int domain,int type,int protocol,int fds[2])
{assert(domain==AF_UNIX&&type==(SOCK_SEQPACKET|SOCK_CLOEXEC|SOCK_NONBLOCK)&&!protocol&&scans==1&&!scanner);fds[0]=3;fds[1]=4;return 0;}
int __wrap_sigaction(int sig,const struct sigaction *action,struct sigaction *old)
{assert(sig==SIGCHLD&&!action&&old);memset(old,0,sizeof(*old));old->sa_handler=SIG_DFL;return 0;}
pid_t __wrap_fork(void)
{assert(status_opens==1&&!forked&&passcred_mask==3);++forks;forked=1;if(scenario<20){owner=101;return 0;}return 101;}
int __wrap_prctl(int option,...)
{va_list a;va_start(a,option);if(option==PR_SET_PDEATHSIG){assert(va_arg(a,unsigned long)==SIGKILL);armed=SIGKILL;}else{assert(option==PR_GET_PDEATHSIG);*va_arg(a,int *)=armed;}va_end(a);return 0;}
ssize_t __wrap_send(int fd,const void *p,size_t n,int flags)
{assert(owner==101&&fd==4&&n==8&&!memcmp(p,"RNRKARM1",8)&&flags==(MSG_DONTWAIT|MSG_NOSIGNAL));++sends;return 8;}
int __wrap_poll(struct pollfd *p,nfds_t n,int timeout)
{assert(owner==100);if(timeout==0){assert(n==1&&p->fd==62);return 0;}
 assert(p->fd==3&&n==2&&p[1].fd==62&&timeout>0&&timeout<=15000);if(scenario==21)return 0;if(scenario==22)boot=25000000000LL;if(scenario==25)boot=100000000000LL;p->revents=POLLIN;return 1;}
ssize_t __wrap_recvmsg(int fd,struct msghdr *m,int flags)
{assert(fd==3&&m->msg_iovlen==1&&flags==(MSG_DONTWAIT|MSG_TRUNC|MSG_CMSG_CLOEXEC));
 assert(m->msg_control&&m->msg_controllen==CMSG_SPACE(sizeof(struct ucred)));
 struct cmsghdr *c=CMSG_FIRSTHDR(m);c->cmsg_level=SOL_SOCKET;c->cmsg_type=SCM_CREDENTIALS;c->cmsg_len=CMSG_LEN(sizeof(struct ucred));
 struct ucred u={.pid=101,.uid=0,.gid=0};memcpy(CMSG_DATA(c),&u,sizeof(u));
 memcpy(m->msg_iov[0].iov_base,"RNRKARM1",8);return 8;}
long __wrap_syscall(long call,...)
{
 va_list a;va_start(a,call);long result=0;
 if(call==SYS_gettid){result=owner;}
 else if(call==SYS_pidfd_open){assert(va_arg(a,int)==101&&va_arg(a,int)==0);++pidfds;if(scenario==23){errno=EMFILE;result=-1;}else result=62;}
 else if(call==SYS_pidfd_send_signal||call==SYS_kill){assert(va_arg(a,int)==(call==SYS_kill?101:62));assert(va_arg(a,int)==SIGKILL);++signals;signal_kind=(int)call;if(scenario==26){errno=EPERM;result=-1;}}
 else{
  assert(call==SYS_getdents64&&va_arg(a,int)==3);unsigned char *buffer=va_arg(a,unsigned char *);assert(va_arg(a,size_t)==4096);
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
#define DENY(name) _Noreturn void __wrap_##name(void){assert(!"unexpected host boundary: " #name);abort();}
DENY(chdir) DENY(chroot) DENY(dup2) DENY(dup3) DENY(execve) DENY(fchdir)
DENY(fchmod) DENY(fstatat) DENY(fstatvfs) DENY(fsync) DENY(ftruncate)
DENY(getrandom) DENY(ioctl) DENY(memfd_create) DENY(mkdirat) DENY(mount)
DENY(pipe2) DENY(pwrite) DENY(umask) DENY(waitpid)
int main(int argc,char **argv)
{
 assert(argc==2);scenario=atoi(argv[1]);size_t payload=fread(task+64,1,65536,stdin);assert(payload&&payload<65536);task_size=payload+64;
 memcpy(task,"RNRT0001",8);task[8]=1;memset(task+16,0xaa,16);le(task+32,scenario==2?160000000000LL:190000000000LL,8);le(task+40,payload,4);
 memcpy(installation,"RNRI0002",8);installation[8]=2;installation[16]=1;installation[48]=2;le(installation+80,129,8);le(installation+88,3,8);memset(installation+96,0xff,32);memset(installation+128,1,272);memset(installation+400,0,48);memcpy(installation+200,"11111111-1111-1111-1111-111111111111",36);memset(installation+236,0,4);memset(installation+336,0x11,32);
 memset(installation+16,0x11,32);
 if(scenario==1)installation[200]='2';
 if(scenario==5)installation[96]^=1;
 if(scenario==9)installation[16]^=1;
 static struct rnr_stage0_preparer_error error;
 if(scenario<20){
  if(!setjmp(exited)){(void)rnr_stage0_supervised_inputs(&error);assert(0);}
  assert(exit_code==125&&forks==1&&sends==1&&signals==0&&gate_closed==2);
  assert(scans==2&&held_scans==1);
  for(int fd=10;fd<25;++fd)assert(!fd_live[fd]&&fd_closed[fd]<=1);
  if(scenario==0){assert(error.code==RNR_STAGE0_PREPARER_OK&&opens==10);}
  else assert(error.code!=RNR_STAGE0_PREPARER_OK);
  if(scenario==9)assert(error.code==RNR_STAGE0_PREPARER_IDENTITY);
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
