/* UnitPath fixture: one simulated resolved directory descriptor at a time. */
static int sp_live,sp_role,sp_fault,sp_fault_role,sp_seen,sp_pass[2];
static int sp_open(const char *path,int late)
{
 int role=!strcmp(path,"/run/systemd/transient")?0:!strcmp(path,"/etc/systemd/system")?1:-1;
 assert(role>=0);sp_seen|=1<<role;sp_pass[late?1:0]|=1<<role;
 if(role==sp_fault_role&&((sp_fault==2&&late)||(sp_fault==3&&!late)||sp_fault==9||sp_fault==13)){errno=ENOENT;return -1;}
 if(role==sp_fault_role&&(sp_fault==1||sp_fault==11)){errno=EACCES;return -1;}
 if(role==sp_fault_role&&sp_fault==12)return 1;
 assert(!sp_live);sp_live=1;sp_role=role;return 740;
}
static int sp_stat(struct stat *s,int late)
{
 assert(sp_live);memset(s,0,sizeof(*s));s->st_dev=12;s->st_ino=9000+sp_role;
 s->st_mode=S_IFDIR|0755;s->st_nlink=1;
 if(sp_role==sp_fault_role&&sp_fault==4&&late)++s->st_ino;
 if(sp_role==sp_fault_role&&sp_fault==5)s->st_uid=1;
 if(sp_role==sp_fault_role&&sp_fault==6)s->st_mode|=0020;
 if(sp_role==sp_fault_role&&sp_fault==8)s->st_mode=S_IFREG|0644;
 return 0;
}
static int sp_statx(struct statx *s,int late)
{
 assert(sp_live);memset(s,0,sizeof(*s));s->stx_mask=STATX_MNT_ID;s->stx_mnt_id=90+sp_role;
 if(sp_role==sp_fault_role&&sp_fault==7&&late)++s->stx_mnt_id;
 return 0;
}
static int sp_close(void)
{assert(sp_live);sp_live=0;if(sp_fault==10){errno=EINTR;return -1;}return 0;}
/* Seven candidate drop-in scopes per search path, with no real filesystem I/O. */
#define SO_PROJECT "1111111111111111111111111111111111111111111111111111111111111111"
static int so_live,so_index,so_case,so_target,so_late,so_phase,so_records;
static unsigned int so_seen[2];
static int so_open(const char *path,int late)
{
 static const char *const roots[]={"/run/systemd/transient","/etc/systemd/system"};
 static const char *const scopes[]={"service.d","slice.d","rnrc" SO_PROJECT ".service.d",
  "rnrc" SO_PROJECT ".slice.d","rnrw" SO_PROJECT ".slice.d",
  "rnrw" SO_PROJECT "-anchor.slice.d","rnrw" SO_PROJECT "-.slice.d"};
 int index=-1;char expected[512];
 for(int r=0;r<2;++r)for(int s=0;s<7;++s){
  snprintf(expected,sizeof(expected),"%s/%s",roots[r],scopes[s]);
  if(!strcmp(path,expected))index=r*7+s;
 }
 assert(index>=0);so_seen[late?1:0]|=1U<<index;so_index=index;so_phase=so_records=0;
 int active=index==so_target&&(!so_late||late);
 if(active&&(so_case==9||so_case==10||so_case==11)){
  errno=so_case==9?ENOENT:so_case==10?ENOTDIR:EACCES;return -1;}
 if(active&&so_case==12)return 1;
 assert(!so_live);so_live=1;return 741;
}
static int so_stat(struct stat *s)
{assert(so_live);memset(s,0,sizeof(*s));s->st_dev=12;s->st_ino=10000+so_index;s->st_mode=S_IFDIR|0755;return 0;}
static int so_statx(struct statx *s)
{assert(so_live);memset(s,0,sizeof(*s));s->stx_mask=STATX_MNT_ID;s->stx_mnt_id=100+so_index;return 0;}
static long so_scan(void *out,size_t count,int late)
{
 assert(so_live&&count==4096);int active=so_index==so_target&&(!so_late||late);
 if(active&&so_case==7){errno=EIO;return -1;}
 if(active&&(so_case==14||so_case==15)){
  int total=so_case==14?512:513,remaining=total-so_records;if(!remaining)return 0;
  int batch=remaining>128?128:remaining;unsigned char *b=out;
  for(int i=0;i<batch;++i){int item=so_records+i;uint64_t inode=(uint64_t)(3000+item);int64_t next=item+1;uint16_t size=32;
   unsigned char *p=b+32*i;memset(p,0,32);memcpy(p,&inode,8);memcpy(p+8,&next,8);memcpy(p+16,&size,2);
   p[18]=8;snprintf((char *)p+19,13,"f%04d",item);}
  so_records+=batch;return batch*32;
 }
 if(active&&so_case==17)return 4097;
 if(active&&so_case==16)so_phase=0;
 if(so_phase++)return 0;
 const char *name=active&&so_case==1?"x.conf":active&&so_case==2?".hidden.conf":
  active&&so_case==3?"x.conf.bak":active&&so_case==4?"x.dpkg-old.conf":
  active&&so_case==5?"link.conf":"note.txt";
 const char *const names[]={".","..",name};unsigned char *b=out;
 for(int i=0;i<3;++i){uint64_t inode=(uint64_t)(2000+i);int64_t next=i+1;uint16_t size=64;
  unsigned char *p=b+64*i;memset(p,0,64);memcpy(p,&inode,8);memcpy(p+8,&next,8);memcpy(p+16,&size,2);
  p[18]=(unsigned char)(i<2?4:active&&so_case==5?10:8);memcpy(p+19,names[i],strlen(names[i])+1);}
 if(active&&so_case==6)b[16]=9;
 return 192;
}
static int so_close(void)
{assert(so_live);so_live=0;if(so_case==8&&so_index==so_target){errno=EINTR;return -1;}return 0;}
#undef SO_PROJECT
