/* Fake rooted proc mountinfo; never inspect host mounts from this fixture. */
static int mi_live[2],mi_seen,mi_fault,mi_late,mi_closed[2];
static unsigned char mi_data[1048577];static size_t mi_length;
static int mi_active(void){return mi_fault&&(!mi_late||cg_after_bind);}
static void mi_build(void)
{
 int fault=mi_active()?mi_fault:0;char text[512];
 int n=snprintf(text,sizeof(text),"29 1 0:22 / /proc rw - proc proc rw\n%d %s %s %s %s rw%s - %s%s%s",
  fault==4?89:88,fault==11?"bad":"1",fault==12?"bad":fault==23?"18446744073709551616:42":"0:42",
  fault==1?"/wrong":"/",fault==2?"/sys/fs/other":"/sys/fs/cgroup",fault==15?" shared:7 master:2":"",
  fault==3?"tmpfs":"cgroup2",fault==13?" ":fault==14?" cgroup":" cgroup rw",fault==6?"":"\n");
 assert(n>0&&(size_t)n<sizeof(text));mi_length=0;
 if(fault==17){const char overflow[]="18446744073709551616 x\n";memcpy(mi_data,overflow,sizeof(overflow)-1);mi_length=sizeof(overflow)-1;}
 if(fault==19||fault==22){size_t length=fault==19?4097:4096;mi_data[0]='1';mi_data[1]=' ';
  memset(mi_data+2,'x',length-2);mi_data[length]='\n';mi_length=length+1;}
 memcpy(mi_data+mi_length,text,(size_t)n);mi_length+=(size_t)n;
 if(fault==5){static const char duplicate[]="88 1 0:42 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n";
  memcpy(mi_data+mi_length,duplicate,sizeof(duplicate)-1);mi_length+=sizeof(duplicate)-1;}
 if(fault==18)mi_data[4]=0;
 if(fault==20||fault==21){
  assert(mi_data[mi_length-1]=='\n');--mi_length;
  while((mi_length+1)%4)mi_data[mi_length++]='x';
  mi_data[mi_length++]='\n';
  while(mi_length<1048576){memcpy(mi_data+mi_length,"1 x\n",4);mi_length+=4;}
  if(fault==20)mi_data[mi_length++]='1';
 }
}
static int mi_open(int parent,const char *path,int root,int pid)
{
 if(parent!=root)return -2;
 char expected[64];snprintf(expected,sizeof(expected),"proc/%d/mountinfo",pid);
 int role=!strcmp(path,"proc")?0:!strcmp(path,expected)?1:-1;
 if(role<0)return -2;
 if(mi_active()&&((role==1&&mi_fault==10)||(role==0&&mi_fault==28))){errno=ENOENT;return -1;}
 assert(!mi_live[role]);mi_live[role]=1;mi_seen|=1<<role;if(role==1)mi_build();return 730+role;
}
static int mi_stat(int fd,struct stat *s)
{int role=fd-730;assert(role>=0&&role<2&&mi_live[role]);memset(s,0,sizeof(*s));
 s->st_mode=(role?S_IFREG|0444:S_IFDIR|0555);s->st_dev=11;s->st_ino=9000+role;s->st_nlink=1;return 0;}
static int mi_statx(int fd,struct statx *s)
{int role=fd-730;assert(role>=0&&role<2&&mi_live[role]);memset(s,0,sizeof(*s));s->stx_mask=STATX_MNT_ID;
 s->stx_mnt_id=role==1&&mi_active()&&mi_fault==8?21:20;return 0;}
static int mi_statfs(int fd,struct statfs *s)
{int role=fd-730;assert(role>=0&&role<2&&mi_live[role]);memset(s,0,sizeof(*s));
 s->f_type=role==1&&mi_active()&&mi_fault==7?0xef53:0x9fa0;return 0;}
static ssize_t mi_read(void *out,size_t count,off_t off)
{
 assert(mi_live[1]&&off>=0);if(mi_active()&&mi_fault==9){errno=EIO;return -1;}
 if((size_t)off>=mi_length)return 0;
 size_t length=mi_length-(size_t)off;if(length>count)length=count;
 if(mi_active()&&mi_fault==16&&length>7)length=7;
 memcpy(out,mi_data+off,length);return (ssize_t)length;
}
static int mi_close(int fd){int role=fd-730;assert(role>=0&&role<2&&mi_live[role]);mi_live[role]=0;++mi_closed[role];
 if(mi_active()&&((role==0&&mi_fault==24)||(role==1&&mi_fault==25))){errno=EINTR;return -1;}return 0;}
