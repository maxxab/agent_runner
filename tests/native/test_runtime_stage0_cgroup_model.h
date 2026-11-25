/* Fixed cgroup directory model: no host cgroup calls or effects. */
#define CG_PROJECT "1111111111111111111111111111111111111111111111111111111111111111"
static int cg_live[16],cg_seen,cg_fault,cg_fault_role,cg_fault_postbind,cg_after_bind;
static int cg_file_live,cg_file_role,cg_file_field,cg_control_fault,cg_control_role,cg_control_field,cg_control_postbind;
static int cg_distinct_policy,cg_file_fault,cg_file_stat_calls,cg_file_closes;
static unsigned int cg_control_seen[4];
static unsigned int cg_state_seen[5];static int cg_state_reverse,cg_event_role,cg_event_pop_flip,cg_event_freeze_flip,cg_event_late;
static int cg_scan_seen,cg_scan_phase,cg_scan_fault,cg_scan_late,cg_scan_records,cg_scan_closes;
static unsigned int cg_controller_seen[4];static int cg_controller_case,cg_member_case,cg_supervised_pair;
static const char *const cg_file_names[]={"cgroup.type","cpu.max","memory.max","memory.swap.max","pids.max","memory.oom.group",
 "cgroup.freeze","cgroup.events","cgroup.procs","cgroup.threads","cgroup.controllers","cgroup.subtree_control"};
static int cg_fault_active(int role){return role==cg_fault_role&&(!cg_fault_postbind||cg_after_bind);}
static int cg_role(int fd){assert(fd>=700&&fd<716&&cg_live[fd-700]);return (fd-700)%8;}
static int cg_open(int parent,const char *path,int root)
{
 int role=-1;
 if(parent==root){if(strcmp(path,"sys"))return -2;role=0;}
 else if(parent>=700&&parent<716){int p=cg_role(parent);
  for(int field=0;field<12;++field)if((p==2||p==3||p==4||p==5||p==6||p==7)&&!strcmp(path,cg_file_names[field])){
   if(field>=10&&p!=2&&p!=3&&p!=4&&p!=6)return -2;
   if(cg_file_fault==1){errno=ELOOP;return -1;}
   assert(!cg_file_live);cg_file_live=1;cg_file_role=p;cg_file_field=field;cg_file_stat_calls=0;
   if(field<6&&p!=5)cg_control_seen[p==4?0:p==3?1:p==6?2:3]|=1U<<field;
   if(field>=6&&field<10)cg_state_seen[p==4?0:p==3?1:p==6?2:p==7?3:4]|=1U<<(field-6);
   if(field>=10)cg_controller_seen[p==2?0:p==3?1:p==4?2:3]|=1U<<(field-10);
   return 720;}
  if(p==0&&!strcmp(path,"fs"))role=1;
  else if(p==1&&!strcmp(path,"cgroup"))role=2;
  else if(p==2&&!strcmp(path,"rnrc" CG_PROJECT ".slice"))role=3;
  else if(p==3&&!strcmp(path,"rnrc" CG_PROJECT ".service"))role=4;
  else if(p==4&&!strcmp(path,"keeper"))role=5;
  else if(p==2&&!strcmp(path,"rnrw" CG_PROJECT ".slice"))role=6;
  else if(p==6&&!strcmp(path,"rnrw" CG_PROJECT "-anchor.slice"))role=7;
  else return -2;
 }else return -2;
 if(cg_fault==1&&cg_fault_active(role)){errno=ELOOP;return -1;}
 int index=role;if(cg_live[index])index+=8;assert(!cg_live[index]);cg_live[index]=1;cg_seen|=1<<role;
 if(index==15){cg_scan_phase=0;cg_scan_records=0;}
 return 700+index;
}
static int cg_stat(int fd,struct stat *s)
{
 int role=cg_role(fd);memset(s,0,sizeof(*s));s->st_dev=role<2?9:10;s->st_ino=7000+role;
 s->st_nlink=1;s->st_mode=S_IFDIR|0755;
 if(cg_fault==2&&cg_fault_active(role))s->st_uid=1;
 if(cg_fault==3&&cg_fault_active(role)&&fd>=708)s->st_ino++;
 return 0;
}
static int cg_statx(int fd,struct statx *s)
{int role=cg_role(fd);memset(s,0,sizeof(*s));s->stx_mask=STATX_MNT_ID;s->stx_mnt_id=role<2?77:88;
 if(cg_fault==4&&cg_fault_active(role))++s->stx_mnt_id;
 return 0;}
static int cg_statfs(int fd,struct statfs *s)
{int role=cg_role(fd);memset(s,0,sizeof(*s));s->f_type=role<2?0x62656572:0x63677270;
 if(cg_fault==5&&cg_fault_active(role))s->f_type=0xef53;
 return 0;}
static long cg_handle(int fd,struct file_handle *h,int *mount)
{
 int role=cg_role(fd);assert(role==3||role==4||role==6||role==7);assert(h->handle_bytes==8);
 if(cg_fault==6&&cg_fault_active(role)){errno=EOPNOTSUPP;return -1;}
 uint64_t id=UINT64_C(0x1234567800001000)+(role==4?0:role==3?1:role==6?2:3);
 if(cg_fault==7&&cg_fault_active(role))++id;
 h->handle_type=0xfe;h->handle_bytes=8;memcpy(h->f_handle,&id,8);*mount=88;
 if(cg_fault==8&&cg_fault_active(role))*mount=89;
 if(cg_fault==9&&cg_fault_active(role))h->handle_bytes=4;
 if(cg_fault==10&&cg_fault_active(role))h->handle_type=0xfd;
 return 0;
}
static int cg_close(int fd){int index=fd-700;assert(index>=0&&index<16&&cg_live[index]);cg_live[index]=0;
 if(index==15&&cg_state_seen[3]==15)++cg_scan_closes;
 if(index==15&&cg_scan_phase>0&&cg_scan_fault==13&&(!cg_scan_late||cg_after_bind)){errno=EINTR;return -1;}
 return 0;}
static long cg_scan(int fd,void *out,size_t count)
{
 assert(fd==715&&cg_role(fd)==7&&count==4096);++cg_scan_seen;
 int fault=cg_scan_fault&&(!cg_scan_late||cg_after_bind)?cg_scan_fault:0;
 if(fault==7){errno=EIO;return -1;}
 if(fault==11||fault==12){
  int total=fault==11?512:513,remaining=total-cg_scan_records;if(!remaining)return 0;
  int batch=remaining>128?128:remaining;unsigned char *b=out;
  for(int i=0;i<batch;++i){int item=cg_scan_records+i;uint64_t inode=(uint64_t)(1000+item);int64_t next=item+1;uint16_t size=32;
   unsigned char *p=b+32*i;memset(p,0,32);memcpy(p,&inode,8);memcpy(p+8,&next,8);memcpy(p+16,&size,2);
   p[18]=(unsigned char)(item<2?4:8);
   if(item<2)memcpy(p+19,item?"..":".",item?3:2);
   else snprintf((char *)p+19,13,"f%04d",item);}
  cg_scan_records+=batch;++cg_scan_phase;return batch*32;
 }
 if(cg_scan_phase++){
  if((fault==9||fault==10)&&cg_scan_phase==2){unsigned char *p=out;uint64_t inode=903;int64_t next=4;uint16_t size=32;
   memset(p,0,32);memcpy(p,&inode,8);memcpy(p+8,&next,8);memcpy(p+16,&size,2);p[18]=(unsigned char)(fault==10?4:8);
   memcpy(p+19,fault==10?"child":"cpu.max",fault==10?6:8);return 32;}
  if(fault!=8)return 0;
  unsigned char *p=out;uint64_t inode=902;int64_t next=3;uint16_t size=32;
  memset(p,0,32);memcpy(p,&inode,8);memcpy(p+8,&next,8);memcpy(p+16,&size,2);p[18]=8;memcpy(p+19,"cgroup.procs",13);
  return 32;
 }
 static const char *const names[]={".","..","cgroup.procs","unexpected"};
 unsigned char *b=out;int records=fault==1?4:3;
 for(int i=0;i<records;++i){uint64_t inode=(uint64_t)(900+i);int64_t next=i+1;uint16_t size=32;
  unsigned char *p=b+32*i;memset(p,0,32);memcpy(p,&inode,8);memcpy(p+8,&next,8);memcpy(p+16,&size,2);
  p[18]=(unsigned char)(i<2||i==3?4:8);memcpy(p+19,names[i],strlen(names[i])+1);}
 if(fault==2)b[2*32+18]=0;
 if(fault==3){b[32+19]='.';b[32+20]=0;}
 if(fault==4)b[16]=9;
 if(fault==5)memset(b+2*32+19,'x',13);
 if(fault==6){b[19]='x';b[20]=0;}
 return records*32;
}
static int cg_file_stat(struct stat *s)
{assert(cg_file_live);++cg_file_stat_calls;if(cg_file_fault==7){errno=EIO;return -1;}
 memset(s,0,sizeof(*s));s->st_mode=S_IFREG|0444;s->st_dev=10;s->st_ino=8000+cg_file_role*10+cg_file_field;s->st_nlink=1;
 if(cg_file_fault==2)s->st_uid=1;
 if(cg_file_fault==3)s->st_mode|=0020;
 if(cg_file_fault==4)++s->st_dev;
 if(cg_file_fault==8&&cg_file_stat_calls>1)++s->st_ino;
 if(cg_file_fault==11)s->st_mode=S_IFIFO|0444;
 return 0;}
static int cg_file_statx(struct statx *s)
{assert(cg_file_live);memset(s,0,sizeof(*s));s->stx_mask=STATX_MNT_ID;s->stx_mnt_id=cg_file_fault==5?89:88;return 0;}
static int cg_file_statfs(struct statfs *s)
{assert(cg_file_live);memset(s,0,sizeof(*s));s->f_type=cg_file_fault==6?0xef53:0x63677270;return 0;}
static ssize_t cg_file_read(void *out,size_t count,off_t offset)
{
 static const char *const values[]={"domain\n","100000 100000\n","536870912\n","0\n","128\n","0\n","0\n","","","",
     "cpu io memory pids\n","cpu io memory pids\n"};
 assert(cg_file_live&&offset>=0);const char *value=values[cg_file_field];char distinct[64],generated[4098];size_t explicit_length=0;
 if(cg_file_field>=10){
  if(cg_controller_case==1)value="pids io cpu memory\n";
  else if(cg_controller_case==2)value="cpu memory pids cpu\n";
  else if(cg_controller_case==3)value="cpu memory pids cpU\n";
  else if(cg_controller_case==4)value="cpu memory io\n";
  else if(cg_controller_case==5)value="";
  else if(cg_controller_case==6){if((size_t)offset>=4097)return 0;size_t n=4097-(size_t)offset;if(n>count)n=count;
   memset(out,'x',n);return (ssize_t)n;}
  else if(cg_controller_case==7||cg_controller_case==8){
   static const char tail[]="abcdefghijklmnopqrstuvwxyz0123456789_";size_t used=0;
   memcpy(generated,"cpu memory pids ",16);used=16;
   for(int a=0;a<26;++a){generated[used++]=(char)('a'+a);generated[used++]=' ';}
   for(int a=0;a<26;++a)for(size_t b=0;b<sizeof(tail)-1;++b){generated[used++]=(char)('a'+a);generated[used++]=tail[b];generated[used++]=' ';}
   for(int a=0;a<26&&used+4<=4095;++a)for(int b=0;b<100&&used+4<=4095;++b){
    generated[used++]=(char)('a'+a);generated[used++]=(char)('0'+b/10);generated[used++]=(char)('0'+b%10);generated[used++]=' ';}
   while(used<4095)generated[used++]=' ';
   generated[used++]='\n';if(cg_controller_case==8)generated[used++]=' ';generated[used]=0;value=generated;
  }else if(cg_controller_case==9)value="cpu memory pids io io\n";
  else if(cg_controller_case==10)value="cpu\tmemory\v pids\r\nio\f";
  else if(cg_controller_case==11){static const char embedded[]="cpu memory pids\0io\n";value=embedded;explicit_length=sizeof(embedded)-1;}
 }
 if(cg_file_field==6)value=cg_file_role==6?"1\n":"0\n";
 if((cg_file_field==8||cg_file_field==9)&&cg_file_role==5){
  static const char *const members[]={"99\n100\n","100\n99\n","99\n99\n","99\n","99\n100\n101\n"};
  value=cg_supervised_pair?"100\n101\n":members[cg_member_case];
 }
 if(cg_file_field==7){int frozen=cg_file_role==6||cg_file_role==7;int populated=cg_file_role!=6&&cg_file_role!=7;
  if(cg_event_role==cg_file_role&&(!cg_event_late||cg_after_bind)){
   if(cg_event_pop_flip)populated=!populated;
   if(cg_event_freeze_flip)frozen=!frozen;}
  snprintf(distinct,sizeof(distinct),cg_state_reverse?"frozen %d\npopulated %d\n":"populated %d\nfrozen %d\n",
      cg_state_reverse?frozen:populated,cg_state_reverse?populated:frozen);value=distinct;}
 if(cg_distinct_policy){int role=cg_file_role==4?0:cg_file_role==3?1:cg_file_role==6?2:3;
  static const int cpu[]={900,1500,2000,2000},memory[]={400000000,600000000,700000000,700000000},pids[]={100,140,160,160};
  if(cg_file_field==1){snprintf(distinct,sizeof(distinct),"%d 100000\n",cpu[role]*100);value=distinct;}
  else if(cg_file_field==2){snprintf(distinct,sizeof(distinct),"%d\n",memory[role]);value=distinct;}
  else if(cg_file_field==4){snprintf(distinct,sizeof(distinct),"%d\n",pids[role]);value=distinct;}}
 size_t length=explicit_length?explicit_length:strlen(value);
 int fault=cg_control_fault&&cg_file_role==cg_control_role&&cg_file_field==cg_control_field&&(!cg_control_postbind||cg_after_bind);
 if(fault&&cg_control_fault==3){errno=EIO;return -1;}
 if(fault&&cg_control_fault==1&&!length&&(size_t)offset==0){assert(count);*(char *)out='1';return 1;}
 if((size_t)offset>=length){if(fault&&cg_control_fault==2&&(size_t)offset==length){assert(count);*(char *)out='x';return 1;}return 0;}
 size_t n=length-(size_t)offset;if(n>count)n=count;memcpy(out,value+offset,n);
 if(fault&&cg_control_fault==1&&n)((char *)out)[0]^=1;
 if(fault&&cg_control_fault==4&&n)--n;
 return (ssize_t)n;
}
static int cg_file_close(void)
{assert(cg_file_live);cg_file_live=0;++cg_file_closes;if(cg_file_fault==9){errno=EINTR;return -1;}return 0;}
#undef CG_PROJECT
