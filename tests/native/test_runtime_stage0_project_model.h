/* Shared kernel simulation, never real proc or peer I/O. */
static int used[256],role[256],count,peak,operations,checks,fail,late,expired;
static int drift,drift_role,malformed,foreign,parent_changed,close_bad,dead,time_mismatch,proc_nlink_drift;
static char cgroup[]="0::/rnrc1111111111111111111111111111111111111111111111111111111111111111.slice/rnrc1111111111111111111111111111111111111111111111111111111111111111.service/keeper\n";
static void op_model_reset(void)
{
 memset(used,0,sizeof(used));count=peak=operations=checks=fail=late=expired=drift=malformed=foreign=parent_changed=close_bad=dead=time_mismatch=proc_nlink_drift=0;drift_role=-1;
}
static int event(void)
{assert(!expired);++operations;if(operations==late)expired=1;if(operations==fail){errno=EIO;return -1;}return 0;}
static int allocate(int r)
{int i;for(i=100;i<256&&used[i];++i){}assert(i<256);used[i]=1;role[i]=r;++count;if(count>peak)peak=count;assert(count<=29);return i;}
static int op_open(const char *p,int f)
{assert(!strcmp(p,"/")&&f==(O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));if(event())return -1;return allocate(0);}
static int op_openat(int d,const char *p,int f)
{
 assert(used[d]);int r=role[d],next=-1;
 if(r==0){assert(!strcmp(p,"proc"));next=1;}
 else if(r==1){if(!strcmp(p,"thread-self"))next=2;else if(!strcmp(p,"101"))next=3;else if(!strcmp(p,"100"))next=7;else{assert(!strcmp(p,"1"));next=9;}}
 else if(r==3){if(!strcmp(p,"task"))next=4;else if(!strcmp(p,"exe"))next=23;else if(!strcmp(p,"cgroup"))next=26;}
 else if(r==4){assert(!strcmp(p,"101"));next=5;}
 else if(r==5){assert(!strcmp(p,"ns"));next=6;}
 else if(r==7||r==9){if(!strcmp(p,"ns"))next=r+1;else if(!strcmp(p,"exe"))next=r==7?24:25;else if(!strcmp(p,"cgroup")){assert(r==7);next=27;}}
 if(r==6||r==8||r==10){
  static const char *const labels[]={"user","pid","mnt","cgroup","time","net","uts","ipc","pid_for_children","time_for_children"};
  for(int i=0;i<10;++i)if(!strcmp(p,labels[i]))next=11+i;
 }
 if(!strcmp(p,"stat"))next=30+(r==3?0:r==7?1:2);
 if(!strcmp(p,"status"))next=33+(r==3?0:r==7?1:2);
 assert(next>=0);
 int link=f&O_PATH;
 int expected=link?O_PATH|O_NOFOLLOW|O_CLOEXEC:
  next<=10?O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC:
  next<=25?O_RDONLY|O_CLOEXEC:O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK;
 assert(f==expected);if(event())return -1;
 int fd=allocate(link?next+40:next);
 if((r==8||r==10)&&next>=11&&next<=18&&drift==20)role[fd]+=80;
 return fd;
}
static int op_stat(int fd,struct stat *s)
{
 assert(used[fd]);if(event())return -1;int r=role[fd],base=r>=80?r-80:r>=40?r-40:r;
 memset(s,0,sizeof(*s));s->st_dev=base==0?1:base>=11&&base<=20?3:base>=21&&base<=22?4:base>=23&&base<=25?5:2;
 if(r>=40&&r<80)s->st_dev=2;
 s->st_ino=base==1?1:base==11?UINT64_C(0xeffffffd):(uint64_t)(100+base);
 s->st_mode=r>=40&&r<80?S_IFLNK|0777:base<=10?S_IFDIR|0555:S_IFREG|0444;s->st_nlink=base==1&&proc_nlink_drift?(nlink_t)operations:1;
 if(r>=23&&r<=25){s->st_mode=S_IFREG|0555;s->st_size=1024;s->st_ino=r==25?125:123;}
 if(base==19)s->st_ino=112;
 if(base==15||base==20){if(!(r>=40&&r<80))s->st_dev=1;s->st_ino=time_mismatch?3:2;}
 if(r>=80)++s->st_ino;
 if(base==drift_role){if(drift==1)s->st_uid=1;if(drift==2)s->st_gid=1;if(drift==3)s->st_dev++;if(drift==4)s->st_ino++;if(drift==5)s->st_mode=S_IFIFO|0400;}
 return 0;
}
static int op_statx(int fd,const char *p,int f,unsigned int m,struct statx *s)
{assert(used[fd]&&!strcmp(p,"")&&f==(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW)&&m==STATX_MNT_ID);if(event())return -1;
 int r=role[fd];if(r>=80)r-=80;if(r>=40)r-=40;memset(s,0,sizeof(*s));s->stx_mask=STATX_MNT_ID;s->stx_mnt_id=r==0?10:r>=11&&r<=20?30:r>=23&&r<=25?50:20;
 if(role[fd]>=40&&role[fd]<80)s->stx_mnt_id=20;
 if(r==drift_role&&drift==6)s->stx_mnt_id++;
 return 0;}
static int op_statfs(int fd,struct statfs *s)
{assert(used[fd]);if(event())return -1;int r=role[fd];if(r>=80)r-=80;if(r>=40)r-=40;
 memset(s,0,sizeof(*s));s->f_type=r==0?0xef53:r>=11&&r<=20?0x6e736673:r>=23&&r<=25?0xef53:0x9fa0;
 if(role[fd]>=40&&role[fd]<80)s->f_type=0x9fa0;
 if(r==drift_role&&drift==7)s->f_type=0xef53;
 return 0;}
static ssize_t op_link(int fd,const char *p,char *b,size_t cap)
{
 assert(used[fd]&&!strcmp(p,""));if(event())return -1;int r=role[fd]-40;char raw[128];
 static const char *const labels[]={"user","pid","mnt","cgroup","time","net","uts","ipc","pid","time"};
 if(r==2)snprintf(raw,sizeof(raw),"101/task/101");
 else if(r>=11&&r<=20)snprintf(raw,sizeof(raw),"%s:[%llu]",labels[r-11],(unsigned long long)(r==11?UINT64_C(0xeffffffd):(uint64_t)(r==19?112:r==20||r==15?(time_mismatch?3:2):100+r)));
 else{assert(r>=23&&r<=25);snprintf(raw,sizeof(raw),"/usr/lib/example");}
 size_t n=strlen(raw);assert(n<cap);memcpy(b,raw,n);return (ssize_t)n;
}
static ssize_t op_read(int fd,void *b,size_t n,off_t off)
{
 assert(used[fd]&&n<=16385);if(event())return -1;int r=role[fd];char raw[4096];
 if(r==26||r==27){memcpy(raw,cgroup,sizeof(cgroup));if(malformed==1)raw[3]='x';if(malformed==2&&r==27)raw[9]='2';if(malformed==3)raw[9]='A';}
 else if(r>=30&&r<=32){
  int pid=r==30?101:r==31?100:1;int parent=r==30?100:0;
  int z=snprintf(raw,sizeof(raw),"%d (rnr test) S %d",pid,parent);
  for(int field=5;field<=52;++field)z+=snprintf(raw+z,sizeof(raw)-(size_t)z," %d",field==20?1:field==22?pid+1000:0);
  snprintf(raw+z,sizeof(raw)-(size_t)z,"\n");
 }else{
  assert(r>=33&&r<=35);int pid=r==33?101:r==34?100:1;
  snprintf(raw,sizeof(raw),"Name:\trnr\nState:\tS (sleeping)\nTgid:\t%d\nPid:\t%d\nPPid:\t%d\nTracerPid:\t0\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nThreads:\t1\nNStgid:\t%d\nNSpid:\t%d\nKthread:\t0\n",pid,pid,r==33?100:0,pid,pid);
 }
 size_t length=strlen(raw);if((size_t)off>=length)return 0;
 size_t copy=length-(size_t)off;if(copy>n)copy=n;memcpy(b,raw+off,copy);return (ssize_t)copy;
}
static int op_ioctl(int fd,unsigned long r)
{assert(used[fd]&&r==NS_GET_NSTYPE);if(event())return -1;int k=role[fd]-11;if(k>=80)k-=80;
 static const int kinds[]={CLONE_NEWUSER,CLONE_NEWPID,CLONE_NEWNS,CLONE_NEWCGROUP,CLONE_NEWTIME,CLONE_NEWNET,CLONE_NEWUTS,CLONE_NEWIPC,CLONE_NEWPID,CLONE_NEWTIME};assert(k>=0&&k<10);return kinds[k];}
static int op_poll(struct pollfd *p,nfds_t n,int t)
{assert(n==2&&t==0&&used[p[0].fd]&&used[p[1].fd]);if(event())return -1;if(dead){p[0].revents=POLLIN;return 1;}return 0;}
static int op_close(int fd)
{assert(used[fd]);used[fd]=0;--count;if(close_bad){errno=EINTR;return -1;}return 0;}
static long op_syscall(long n,...)
{if(n==SYS_gettid)return 101;assert(n==SYS_pidfd_open);va_list a;va_start(a,n);int pid=va_arg(a,int);assert(va_arg(a,int)==0);va_end(a);assert(pid==100||pid==1);if(event())return -1;return allocate(pid==100?21:22);}
