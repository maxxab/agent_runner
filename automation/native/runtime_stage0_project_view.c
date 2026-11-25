/* G1 original retained proc view and kernel-derived project location.
 * Does not authenticate policy, executables, PID1 transport or manager controls. */
#define _GNU_SOURCE
#include "runtime_stage0_project_view.h"
#ifdef RNR_STAGE0_PRIVATE_QUALIFICATION
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/nsfs.h>
#include <poll.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <unistd.h>
enum project_phase {PROJECT_NEW,PROJECT_CHECKING,PROJECT_HELD,PROJECT_FENCED_CHECKING,PROJECT_FENCED_HELD,PROJECT_CLOSED};
static atomic_int project_state=ATOMIC_VAR_INIT(PROJECT_NEW);
struct project_object {struct stat s;uint64_t mount;long fs;};
static struct {
    pid_t pid,keeper;
    int fds[28];
    struct project_object objects[28];
    uint64_t starts[3];
    char own[11],parent[11],project[65],cgroup[4097];
    size_t cgroup_length;
} project_owner;
static const char *const ns_names[10]={"user","pid","mnt","cgroup","time","net","uts","ipc","pid_for_children","time_for_children"};
static const int ns_kinds[10]={CLONE_NEWUSER,CLONE_NEWPID,CLONE_NEWNS,CLONE_NEWCGROUP,CLONE_NEWTIME,CLONE_NEWNET,CLONE_NEWUTS,CLONE_NEWIPC,CLONE_NEWPID,CLONE_NEWTIME};
static void project_fence(void)
{
    int phase=atomic_load(&project_state);
    for(;;){
        int fenced=phase==PROJECT_CHECKING?PROJECT_FENCED_CHECKING:
            phase==PROJECT_HELD?PROJECT_FENCED_HELD:phase==PROJECT_NEW?PROJECT_CLOSED:phase;
        if(phase==fenced||atomic_compare_exchange_weak(&project_state,&phase,fenced))return;
    }
}
static void project_reject(struct rnr_stage0_project_error *e,enum rnr_stage0_project_code c,int failure)
{if(e->code==RNR_STAGE0_PROJECT_OK){e->code=c;e->system_errno=failure;}}
static int project_live(struct rnr_stage0_project_error *e)
{
    struct rnr_stage0_launch_error c;
    if(atomic_load_explicit(&project_state,memory_order_acquire)!=PROJECT_CHECKING){
        project_reject(e,RNR_STAGE0_PROJECT_ATTEMPT,0);return -1;}
    if(rnr_stage0_check_admission_preparation(&c)!=0)goto clock;
    pid_t pid=getpid(),parent=getppid();
    int bad=pid<=1||parent<=1||parent==pid||syscall(SYS_gettid)!=(long)pid||
        getuid()!=0||geteuid()!=0||getgid()!=0||getegid()!=0||
        (project_owner.pid&&(pid!=project_owner.pid||parent!=project_owner.keeper));
    if(rnr_stage0_check_admission_preparation(&c)!=0)goto clock;
    if(bad){project_reject(e,RNR_STAGE0_PROJECT_OWNER,0);return -1;}
    if(atomic_load_explicit(&project_state,memory_order_acquire)!=PROJECT_CHECKING){
        project_reject(e,RNR_STAGE0_PROJECT_ATTEMPT,0);return -1;}
    return 0;
clock:
    if(e->clock.code==RNR_STAGE0_LAUNCH_OK)e->clock=c;
    project_reject(e,RNR_STAGE0_PROJECT_CLOCK,c.system_errno);return -1;
}
static int project_failed(struct rnr_stage0_project_error *e,int failure)
{project_reject(e,RNR_STAGE0_PROJECT_SYSCALL,failure);(void)project_live(e);return -1;}
static int project_identity(struct rnr_stage0_project_error *e)
{project_reject(e,RNR_STAGE0_PROJECT_IDENTITY,0);return -1;}
static int project_record(struct rnr_stage0_project_error *e)
{project_reject(e,RNR_STAGE0_PROJECT_RECORD,0);return -1;}
static void project_close(int *slot,struct rnr_stage0_project_error *e)
{
    int fd=*slot;if(fd<0)return;
    int checking=e->code==RNR_STAGE0_PROJECT_OK;
    if(checking&&project_live(e)!=0)checking=0;
    *slot=-1;
    if(close(fd)!=0){int failure=errno;
        if(e->cleanup_count<29){unsigned int n=e->cleanup_count++;
            e->cleanup_errors[n].fd=fd;e->cleanup_errors[n].system_errno=failure;}
        project_reject(e,RNR_STAGE0_PROJECT_CLEANUP,failure);}
    if(checking)(void)project_live(e);
}
static void project_drain(struct rnr_stage0_project_error *e)
{for(int i=27;i>=0;--i)project_close(&project_owner.fds[i],e);}
static int project_open(int parent,const char *name,int flags,int *slot,struct rnr_stage0_project_error *e)
{
    if(project_live(e)!=0)return -1;
    int fd=parent<0?open(name,flags):openat(parent,name,flags);
    if(fd<0)return project_failed(e,errno);
    if(fd<3){e->unadopted_fd=fd;project_reject(e,RNR_STAGE0_PROJECT_IDENTITY,0);(void)project_live(e);return -1;}
    *slot=fd;return project_live(e);
}
#define PROJECT_DIR (O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)
#define PROJECT_FILE (O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK)
#define PROJECT_LINK (O_PATH|O_NOFOLLOW|O_CLOEXEC)
static int project_object(int fd,int role,struct project_object *o,struct rnr_stage0_project_error *e)
{
    struct statx x={0};struct statfs fs;
    if(project_live(e)!=0)return -1;
    if(fstat(fd,&o->s)!=0)return project_failed(e,errno);
    if(project_live(e)!=0)return -1;
    if(statx(fd,"",AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW,STATX_MNT_ID,&x)!=0)return project_failed(e,errno);
    if(project_live(e)!=0)return -1;
    if(fstatfs(fd,&fs)!=0)return project_failed(e,errno);
    if(project_live(e)!=0)return -1;
    o->mount=x.stx_mnt_id;o->fs=fs.f_type;
    if(!(x.stx_mask&STATX_MNT_ID)||!o->mount||!o->s.st_ino||o->s.st_uid||o->s.st_gid)return project_identity(e);
    if(role>=11&&role<=20){
        if(!S_ISREG(o->s.st_mode)||!o->s.st_dev||o->fs!=0x6e736673)return project_identity(e);
        if(project_live(e)!=0)return -1;
        int kind=ioctl(fd,NS_GET_NSTYPE);
        if(kind<0)return project_failed(e,errno);
        if(project_live(e)!=0)return -1;
        if(kind!=ns_kinds[role-11]||(role==11&&o->s.st_ino!=UINT64_C(0xeffffffd)))return project_identity(e);
    }else if(role>=21&&role<=22){
        if(!S_ISREG(o->s.st_mode))return project_identity(e);
    }else if(role>=23&&role<=25){
        if(!S_ISREG(o->s.st_mode)||(o->s.st_mode&06000))return project_identity(e);
    }else{
        int link=role==2||role==40;
        if(link?!S_ISLNK(o->s.st_mode):role<=10?(!S_ISDIR(o->s.st_mode)||(o->s.st_mode&022)):!S_ISREG(o->s.st_mode))return project_identity(e);
        if(role){
            if(o->fs!=0x9fa0)return project_identity(e);
            if(role==1){if(o->s.st_ino!=1)return project_identity(e);}
            else if(o->mount!=project_owner.objects[1].mount||o->s.st_dev!=project_owner.objects[1].s.st_dev)return project_identity(e);
        }
    }
    return 0;
}
static int project_same(const struct project_object *a,const struct project_object *b)
{
    const struct stat *x=&a->s,*y=&b->s;
    if(a->mount!=b->mount||a->fs!=b->fs||x->st_dev!=y->st_dev||x->st_ino!=y->st_ino||
        x->st_mode!=y->st_mode||x->st_uid!=y->st_uid||x->st_gid!=y->st_gid||x->st_rdev!=y->st_rdev)return 0;
    /* proc-root link count tracks unrelated live processes. Directory contents
     * are not immutable records; compare their stable identity, as input paths do. */
    if(S_ISDIR(x->st_mode))return 1;
    return x->st_nlink==y->st_nlink&&x->st_size==y->st_size&&
        x->st_mtim.tv_sec==y->st_mtim.tv_sec&&x->st_mtim.tv_nsec==y->st_mtim.tv_nsec&&
        x->st_ctim.tv_sec==y->st_ctim.tv_sec&&x->st_ctim.tv_nsec==y->st_ctim.tv_nsec;
}
static int project_keep(int role,int parent,const char *name,int flags,struct rnr_stage0_project_error *e)
{
    return project_open(parent,name,flags,&project_owner.fds[role],e)!=0?-1:
        project_object(project_owner.fds[role],role,&project_owner.objects[role],e);
}
static int project_link(int parent,const char *name,struct project_object *o,char *text,size_t cap,struct rnr_stage0_project_error *e)
{
    int fd=-1;
    if(project_open(parent,name,PROJECT_LINK,&fd,e)!=0)goto done;
    if(project_object(fd,40,o,e)!=0||project_live(e)!=0)goto done;
    ssize_t n=readlinkat(fd,"",text,cap);
    if(n<0){(void)project_failed(e,errno);goto done;}
    if(project_live(e)!=0)goto done;
    if(!n||(size_t)n>=cap||memchr(text,0,(size_t)n)){(void)project_record(e);goto done;}
    text[n]=0;
done:
    project_close(&fd,e);return e->code==RNR_STAGE0_PROJECT_OK?0:-1;
}
/* Intentional proc magic-link follow, surrounded by nofollow named-link checks.
 * Only one temporary exists; the followed object goes straight into its owner. */
static int project_follow(int role,int parent,const char *name,int *slot,struct project_object *out,struct rnr_stage0_project_error *e)
{
    struct project_object before,after;char a[4097],b[4097];
    if(project_link(parent,name,&before,a,sizeof(a)-1,e)!=0)return -1;
    if(project_open(parent,name,O_RDONLY|O_CLOEXEC,slot,e)!=0||project_object(*slot,role,out,e)!=0)return -1;
    /* A comparison owns only the one transient slot. Its captured metadata is
     * compared after close; never nest a named-link temporary beside it. */
    if(slot!=&project_owner.fds[role]){
        project_close(slot,e);if(e->code!=RNR_STAGE0_PROJECT_OK)return -1;
    }
    if(project_link(parent,name,&after,b,sizeof(b)-1,e)!=0)return -1;
    if(!project_same(&before,&after)||strcmp(a,b))return project_identity(e);
    if(role>=11&&role<=20){
        char expected[64];int n=snprintf(expected,sizeof(expected),"%s:[%llu]",ns_names[role-11<8?role-11:role==19?1:4],(unsigned long long)out->s.st_ino);
        if(n<=0||(size_t)n>=sizeof(expected)||strcmp(a,expected))return project_identity(e);
    }else if(a[0]!='/')return project_identity(e);
    return 0;
}
static int project_read_fd(int fd,char *raw,size_t cap,size_t *length,struct rnr_stage0_project_error *e)
{
    if(project_live(e)!=0)return -1;
    ssize_t n=pread(fd,raw,cap+1,0);
    if(n<0)return project_failed(e,errno);
    if(project_live(e)!=0)return -1;
    if(n<=0||(size_t)n>cap||memchr(raw,0,(size_t)n))return project_record(e);
    if(project_live(e)!=0)return -1;
    char extra;ssize_t end=pread(fd,&extra,1,n);
    if(end<0)return project_failed(e,errno);
    if(project_live(e)!=0)return -1;
    if(end)return project_record(e);
    raw[n]=0;*length=(size_t)n;return 0;
}
static int project_read_at(int parent,const char *name,char *raw,size_t cap,size_t *length,struct rnr_stage0_project_error *e)
{
    int fd=-1;struct project_object before,after;
    if(project_open(parent,name,PROJECT_FILE,&fd,e)!=0)goto done;
    if(project_object(fd,30,&before,e)!=0||project_read_fd(fd,raw,cap,length,e)!=0||project_object(fd,30,&after,e)!=0)goto done;
    if(!project_same(&before,&after))(void)project_identity(e);
done:
    project_close(&fd,e);return e->code==RNR_STAGE0_PROJECT_OK?0:-1;
}
static int project_uint(const char *p,size_t n,uint64_t *out)
{
    uint64_t v=0;if(!n||n>20||(n>1&&*p=='0'))return -1;
    for(size_t i=0;i<n;++i){if(p[i]<'0'||p[i]>'9'||v>(UINT64_MAX-(unsigned int)(p[i]-'0'))/10)return -1;v=v*10+(unsigned int)(p[i]-'0');}
    *out=v;return 0;
}
static int project_stat_record(const char *raw,size_t length,pid_t pid,pid_t parent,uint64_t *start)
{
    char expected[16];int n=snprintf(expected,sizeof(expected),"%d (",pid);
    if(n<=0||length<=(size_t)n||memcmp(raw,expected,(size_t)n)||raw[length-1]!='\n')return -1;
    const char *end=raw+length-1,*close=NULL;
    for(const char *p=raw+n;p+2<end;++p)if(p[0]==')'&&p[1]==' ')close=p;
    if(!close||close+4>=end||close[3]!=' '||close[2]=='Z'||close[2]=='X')return -1;
    const char *p=close+4;uint64_t value;
    for(int field=4;field<=52;++field){
        const char *q=p;int negative=*q=='-';if(negative)++q;
        const char *digits=q;while(q<end&&*q>='0'&&*q<='9')++q;
        if(project_uint(digits,(size_t)(q-digits),&value)!=0)return -1;
        if(field==4&&(negative||value>(uint64_t)INT_MAX||(parent>=0&&value!=(uint64_t)parent)))return -1;
        if(field==20&&(negative||value!=1))return -1;
        if(field==22){if(negative||!value)return -1;*start=value;}
        if(field==52){if(q!=end)return -1;}else if(q==end||*q!=' ')return -1;
        p=q+1;
    }
    return 0;
}
static int project_status_record(const char *raw,size_t length,pid_t pid,pid_t parent)
{
    static const char *const keys[]={"Tgid:","Pid:","PPid:","TracerPid:","Uid:","Gid:","Threads:","NStgid:","NSpid:","Kthread:","State:"};
    unsigned int seen=0;const char *p=raw,*end=raw+length;
    while(p<end){
        const char *q=memchr(p,'\n',(size_t)(end-p));if(!q)return -1;
        for(int k=0;k<11;++k){
            size_t key=strlen(keys[k]);if((size_t)(q-p)<key||memcmp(p,keys[k],key))continue;
            if(seen&(1U<<k))return -1;
            seen|=1U<<k;
            const char *v=p+key;while(v<q&&(*v=='\t'||*v==' '))++v;
            if(k==10){if(v>=q||(*v!='S'&&*v!='R'&&*v!='D'&&*v!='I'))return -1;continue;}
            int count=k==4||k==5?4:1;
            for(int j=0;j<count;++j){
                const char *d=v;while(v<q&&*v>='0'&&*v<='9')++v;uint64_t value;
                if(project_uint(d,(size_t)(v-d),&value)!=0)return -1;
                uint64_t expected=k==0||k==1||k==7||k==8?(uint64_t)pid:k==2?(uint64_t)parent:k==6?1:0;
                if(!(k==2&&parent<0)&&value!=expected)return -1;
                if(j+1<count){if(v==q||(*v!=' '&&*v!='\t'))return -1;while(v<q&&(*v==' '||*v=='\t'))++v;}
            }
            if(v!=q)return -1;
        }
        p=q+1;
    }
    return seen==2047?0:-1;
}
static int project_peers(int capturing,struct rnr_stage0_project_error *e)
{
    const int roles[3]={3,7,9};const pid_t pids[3]={project_owner.pid,project_owner.keeper,1};
    for(int i=0;i<3;++i){
        char raw[16386];size_t n;uint64_t first=0,second=0;int fd=project_owner.fds[roles[i]];pid_t parent=i==0?project_owner.keeper:-1;
        if(project_read_at(fd,"stat",raw,4096,&n,e)!=0)return -1;
        if(project_stat_record(raw,n,pids[i],parent,&first)!=0)return project_record(e);
        if(project_read_at(fd,"status",raw,16384,&n,e)!=0)return -1;
        if(project_status_record(raw,n,pids[i],parent)!=0)return project_record(e);
        if(project_read_at(fd,"stat",raw,4096,&n,e)!=0)return -1;
        if(project_stat_record(raw,n,pids[i],parent,&second)!=0||first!=second||(!capturing&&first!=project_owner.starts[i]))return project_identity(e);
        if(capturing)project_owner.starts[i]=first;
    }
    return 0;
}
static int project_liveness(struct rnr_stage0_project_error *e)
{
    struct pollfd p[2]={{.fd=project_owner.fds[21],.events=POLLIN},{.fd=project_owner.fds[22],.events=POLLIN}};
    if(project_live(e)!=0)return -1;
    int result=poll(p,2,0);
    if(result<0)return project_failed(e,errno);
    if(project_live(e)!=0)return -1;
    if(result||p[0].revents||p[1].revents)return project_identity(e);
    return 0;
}
static int project_namespaces(struct rnr_stage0_project_error *e)
{
    for(int peer=0;peer<3;++peer)for(int i=0;i<(peer?8:10);++i){
        int fd=-1;struct project_object o;
        int dir=project_owner.fds[peer==0?6:peer==1?8:10],reference=i<8?11+i:i==8?12:15;
        if(project_follow(11+i,dir,ns_names[i],&fd,&o,e)!=0)goto done;
        if(!project_same(&o,&project_owner.objects[reference]))(void)project_identity(e);
done:
        project_close(&fd,e);if(e->code!=RNR_STAGE0_PROJECT_OK)return -1;
    }
    return 0;
}
static int project_memberships(int capturing,struct rnr_stage0_project_error *e)
{
    for(int i=0;i<2;++i){
        char raw[4098];size_t n;
        if(project_read_fd(project_owner.fds[26+i],raw,4096,&n,e)!=0)return -1;
        if(capturing&&i==0){
            /* Literal grammar is163 bytes, including the one final newline. */
            if(n!=163||memcmp(raw,"0::/rnrc",8)||memcmp(raw+72,".slice/rnrc",11)||
                memcmp(raw+147,".service/keeper\n",16)||memcmp(raw+8,raw+83,64))return project_record(e);
            for(int j=0;j<64;++j)if(!((raw[8+j]>='0'&&raw[8+j]<='9')||(raw[8+j]>='a'&&raw[8+j]<='f')))return project_record(e);
            memcpy(project_owner.project,raw+8,64);project_owner.project[64]=0;
            memcpy(project_owner.cgroup,raw,n);project_owner.cgroup_length=n;
        }else if(n!=project_owner.cgroup_length||memcmp(raw,project_owner.cgroup,n))return project_identity(e);
    }
    return 0;
}
static void project_path(int role,int *parent,const char **name,int *flags)
{
    static const int parents[11]={-1,0,1,1,3,4,5,1,7,1,9};
    const char *names[11]={"/","proc","thread-self",project_owner.own,"task",project_owner.own,"ns",project_owner.parent,"ns","1","ns"};
    if(role<=10){*parent=parents[role]<0?-1:project_owner.fds[parents[role]];*name=names[role];*flags=role==2?PROJECT_LINK:PROJECT_DIR;}
    else if(role<=20){*parent=project_owner.fds[6];*name=ns_names[role-11];*flags=O_RDONLY|O_CLOEXEC;}
    else if(role<=25){*parent=project_owner.fds[role==23?3:role==24?7:9];*name="exe";*flags=O_RDONLY|O_CLOEXEC;}
    else{*parent=project_owner.fds[role==26?3:7];*name="cgroup";*flags=PROJECT_FILE;}
}
static int project_recheck_objects(struct rnr_stage0_project_error *e)
{
    for(int i=0;i<28;++i){
        struct project_object held,named;int fd=-1,parent,flags;const char *name;
        if(project_object(project_owner.fds[i],i,&held,e)!=0)return -1;
        if(!project_same(&held,&project_owner.objects[i]))return project_identity(e);
        if(i==21||i==22)continue; /* Original syscall-created pidfds, never reopened. */
        project_path(i,&parent,&name,&flags);
        if((i>=11&&i<=20)||(i>=23&&i<=25)){
            if(project_follow(i,parent,name,&fd,&named,e)!=0)goto done;
        }else if(project_open(parent,name,flags,&fd,e)!=0||project_object(fd,i,&named,e)!=0)goto done;
        if(!project_same(&named,&project_owner.objects[i]))(void)project_identity(e);
done:
        project_close(&fd,e);if(e->code!=RNR_STAGE0_PROJECT_OK)return -1;
    }
    return 0;
}
static int project_check(int capturing,struct rnr_stage0_project_error *e)
{
    if(project_liveness(e)!=0||project_recheck_objects(e)!=0||project_peers(capturing,e)!=0||
       project_namespaces(e)!=0||project_memberships(capturing,e)!=0||project_liveness(e)!=0)return -1;
    struct rnr_stage0_launch_error c;
    if(rnr_stage0_match_admission_time_namespace(project_owner.objects[15].s.st_dev,
            project_owner.objects[15].s.st_ino,&c)!=0){
        if(e->clock.code==RNR_STAGE0_LAUNCH_OK)e->clock=c;
        project_reject(e,RNR_STAGE0_PROJECT_CLOCK,c.system_errno);return -1;
    }
    return project_live(e);
}
static void project_error_init(struct rnr_stage0_project_error *e)
{*e=(struct rnr_stage0_project_error){.unadopted_fd=-1};}
int rnr_stage0_capture_project_view(char project[65],int *root,int executables[3],pid_t *keeper,struct rnr_stage0_project_error *e)
{
    int expected=PROJECT_NEW;
    int claimed=atomic_compare_exchange_strong_explicit(&project_state,&expected,PROJECT_CHECKING,memory_order_acq_rel,memory_order_acquire);
    if(project)project[0]=0;
    if(root)*root=-1;
    if(executables)for(int i=0;i<3;++i)executables[i]=-1;
    if(keeper)*keeper=0;
    if(!e){project_fence();errno=EINVAL;return -1;}
    project_error_init(e);
    if(!claimed){project_fence();project_reject(e,RNR_STAGE0_PROJECT_ATTEMPT,0);return -1;}
    for(int i=0;i<28;++i)project_owner.fds[i]=-1;
    if(!project||!root||!executables||!keeper){project_reject(e,RNR_STAGE0_PROJECT_ATTEMPT,0);goto failed;}
    if(project_live(e)!=0)goto failed;
    project_owner.pid=getpid();project_owner.keeper=getppid();
    if(project_live(e)!=0)goto failed;
    int n=snprintf(project_owner.own,sizeof(project_owner.own),"%d",project_owner.pid);
    int m=snprintf(project_owner.parent,sizeof(project_owner.parent),"%d",project_owner.keeper);
    if(n<=0||n>=11||m<=0||m>=11){(void)project_identity(e);goto failed;}
    for(int i=0;i<11;++i){
        int parent,flags;const char *name;project_path(i,&parent,&name,&flags);
        if(project_keep(i,parent,name,flags,e)!=0)goto failed;
    }
    {char text[4097],want[32];struct project_object link;
        if(project_link(project_owner.fds[1],"thread-self",&link,text,sizeof(text)-1,e)!=0)goto failed;
        int k=snprintf(want,sizeof(want),"%d/task/%d",project_owner.pid,project_owner.pid);
        if(k<=0||(size_t)k>=sizeof(want)||strcmp(text,want)||!project_same(&link,&project_owner.objects[2])){(void)project_identity(e);goto failed;}}
    for(int i=11;i<=20;++i)
        if(project_follow(i,project_owner.fds[6],ns_names[i-11],&project_owner.fds[i],&project_owner.objects[i],e)!=0)goto failed;
    for(int i=21;i<=22;++i){
        if(project_live(e)!=0)goto failed;
        int fd=(int)syscall(SYS_pidfd_open,i==21?project_owner.keeper:1,0);
        if(fd<0){(void)project_failed(e,errno);goto failed;}
        if(fd<3){e->unadopted_fd=fd;(void)project_identity(e);(void)project_live(e);goto failed;}
        project_owner.fds[i]=fd;
        if(project_live(e)!=0||project_object(fd,i,&project_owner.objects[i],e)!=0)goto failed;
    }
    for(int i=23;i<28;++i){
        int parent,flags;const char *name;project_path(i,&parent,&name,&flags);
        if(i<=25){if(project_follow(i,parent,name,&project_owner.fds[i],&project_owner.objects[i],e)!=0)goto failed;}
        else if(project_keep(i,parent,name,flags,e)!=0)goto failed;
    }
    if(project_check(1,e)!=0)goto failed;
    expected=PROJECT_CHECKING;
    if(!atomic_compare_exchange_strong_explicit(&project_state,&expected,PROJECT_HELD,memory_order_release,memory_order_relaxed)){
        project_reject(e,RNR_STAGE0_PROJECT_ATTEMPT,0);goto failed;}
    memcpy(project,project_owner.project,65);*root=project_owner.fds[0];
    for(int i=0;i<3;++i)executables[i]=project_owner.fds[23+i];
    *keeper=project_owner.keeper;
    return 0;
failed:
    if(e->code==RNR_STAGE0_PROJECT_OK)project_reject(e,RNR_STAGE0_PROJECT_ATTEMPT,0);
    project_drain(e);atomic_store(&project_state,PROJECT_CLOSED);return -1;
}
int rnr_stage0_check_project_view(struct rnr_stage0_project_error *e)
{
    int expected=PROJECT_HELD;
    int claimed=atomic_compare_exchange_strong_explicit(&project_state,&expected,PROJECT_CHECKING,memory_order_acq_rel,memory_order_acquire);
    if(!e){
        project_fence();
        if(claimed){expected=PROJECT_FENCED_CHECKING;
            (void)atomic_compare_exchange_strong(&project_state,&expected,PROJECT_FENCED_HELD);}
        errno=EINVAL;return -1;
    }
    project_error_init(e);
    if(!claimed){project_fence();project_reject(e,RNR_STAGE0_PROJECT_ATTEMPT,0);return -1;}
    if(project_check(0,e)!=0){
        project_fence();expected=PROJECT_FENCED_CHECKING;
        (void)atomic_compare_exchange_strong(&project_state,&expected,PROJECT_FENCED_HELD);
        return -1;
    }
    expected=PROJECT_CHECKING;
    if(!atomic_compare_exchange_strong_explicit(&project_state,&expected,PROJECT_HELD,memory_order_release,memory_order_relaxed)){
        project_reject(e,RNR_STAGE0_PROJECT_ATTEMPT,0);
        expected=PROJECT_FENCED_CHECKING;
        (void)atomic_compare_exchange_strong(&project_state,&expected,PROJECT_FENCED_HELD);
        return -1;}
    return 0;
}
int rnr_stage0_abandon_project_view(struct rnr_stage0_project_error *e)
{
    if(!e){errno=EINVAL;return -1;}project_error_init(e);
    if(getpid()!=project_owner.pid||syscall(SYS_gettid)!=(long)project_owner.pid||getuid()!=0||geteuid()!=0||getgid()!=0||getegid()!=0){
        project_reject(e,RNR_STAGE0_PROJECT_OWNER,0);return -1;}
    int phase=atomic_load(&project_state);
    for(;;){
        if(phase!=PROJECT_HELD&&phase!=PROJECT_FENCED_HELD){project_reject(e,RNR_STAGE0_PROJECT_ATTEMPT,0);return -1;}
        if(atomic_compare_exchange_weak(&project_state,&phase,PROJECT_CLOSED))break;
    }
    /* Terminal ownership relinquishment never observes a positive clock. */
    struct rnr_stage0_project_error terminal={.code=RNR_STAGE0_PROJECT_ATTEMPT};
    project_drain(&terminal);
    e->cleanup_count=terminal.cleanup_count;
    memcpy(e->cleanup_errors,terminal.cleanup_errors,sizeof(e->cleanup_errors));
    if(e->cleanup_count){e->code=RNR_STAGE0_PROJECT_CLEANUP;e->system_errno=e->cleanup_errors[0].system_errno;return -1;}
    return 0;
}
#endif
