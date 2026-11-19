/* Full original input->view->journal->loop->DM->mount->media path uses
 * synthetic kernel objects. Child branches and real helpers never execute. */
#define _GNU_SOURCE
#include <signal.h>
#include <sys/random.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stddef.h>
static int flow_absent(int,const char *,struct stat *,int);
static int flow_pipe(int [2],int);
static pid_t flow_fork(void);
static pid_t flow_wait(pid_t,int *,int);
static ssize_t flow_read(int,void *,size_t);
static ssize_t flow_random(void *,size_t,unsigned int);
static int flow_chmod(int,mode_t);
static int flow_signal(int,const struct sigaction *,struct sigaction *);
#define fstatat(d,p,s,f) flow_absent(d,p,s,f)
#define pipe2(p,f) flow_pipe(p,f)
#define fork() flow_fork()
#define waitpid(p,s,f) flow_wait(p,s,f)
#define read(d,p,n) flow_read(d,p,n)
#define getrandom(p,n,f) flow_random(p,n,f)
#define fchmod(d,m) flow_chmod(d,m)
#define sigaction(s,a,o) flow_signal(s,a,o)
#define RNR_TEST_HANDLES 8192
#define RNR_MEDIA_FLOW
#define main legacy_fixture_main
#include "test_runtime_stage0_host_view.c"
#undef main
static int root_enabled,root_fault,root_mkdirs,root_mounts,root_effect_mounted,root_scans,root_closed_old;
static int mapping_enabled,mapping_fault,mapping_stage,mapping_creates,mapping_loads,mapping_resumes,mapping_queries;
static int launch_enabled,launch_free_calls,launch_configure_calls,launch_fault;
static struct loop_config launch_configured[2];
static int launch_bound[2],launch_queries[2];
static uint64_t launch_test_device,launch_test_inode;
static unsigned char flow_files[5][8192];
static size_t flow_sizes[5];
static mode_t flow_modes[5];
static int flow_forks,flow_waits,flow_absence_calls,flow_absence_fault,flow_null_fault,flow_elf_fault;
static int flow_built_fd,flow_pad_fd,flow_pad_small_fd,flow_random_calls,flow_effect_fault,flow_pipe_calls;
static int flow_open(int parent,const char *name,int flags)
{
    int object=handles[parent].object,o=-1;
    if(object==21&&!strcmp(name,"launch-source"))o=60;
    if(object==60&&!strcmp(name,"launch.bin"))o=61;
    if(object==21&&!strcmp(name,"launch.squashfs"))o=62;
    if(object==21&&!strcmp(name,"launch.verity"))o=63;
    if(object==21&&!strcmp(name,"launch.root"))o=64;
    if(object==46&&!strcmp(name,"null"))o=65;
    if(launch_enabled&&object==46){
        char name0[24],name1[24];snprintf(name0,24,"loop%d",input_owner.launch_candidates[0]);
        snprintf(name1,24,"loop%d",input_owner.launch_candidates[1]);
        if(!strcmp(name,name0))o=80;
        if(!strcmp(name,name1))o=81;
    }
    if(mapping_enabled&&object==46&&!strcmp(name,"dm-1"))o=82;
    if(root_enabled&&object==21&&!strcmp(name,"launch"))o=root_effect_mounted?84:83;
    if(root_enabled&&object==84&&!strcmp(name,"launch.bin"))o=85;
    if(o<0)return -2;
    if(o==61&&(flags&O_CREAT)){assert(flags==(O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC));assert(!flow_sizes[1]);}
    else if(o==83||o==84)assert(flags==(O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC));
    else assert(flags==((o==60?O_DIRECTORY:O_NONBLOCK)|O_RDONLY|O_NOFOLLOW|O_CLOEXEC)||
                (o==62&&flags==(O_WRONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)));
    if(o==62&&(flags&O_ACCMODE)==O_WRONLY&&flow_pad_small_fd)return 2;
    int fd=newfd(o);if(fd>=0){handles[fd].access=flags&O_ACCMODE;
        if((o>=80&&launch_fault==22)||(o==82&&mapping_fault==30))handles[fd].access=O_RDWR;
        if(o==61&&(flags&O_CREAT))flow_built_fd=fd;
        if(o==62&&(flags&O_ACCMODE)==O_WRONLY)flow_pad_fd=fd;}
    return fd;
}
static int flow_stat(int fd,struct stat *s)
{
    assert(handles[fd].live);int o=handles[fd].object;memset(s,0,sizeof(*s));
    s->st_dev=o==65||o>=80?5:o==66?makedev(253,
#ifdef RNR_FIXED_BIND_FLOW
        bind_high_minor_setup?256:
#endif
        0):4;s->st_ino=1000+o;s->st_nlink=1;
    if(o>=83){s->st_dev=o==83?4:makedev(253,1);s->st_ino=o==85?7777:1000+o;s->st_nlink=o==85?1:2;
        s->st_mode=o==85?S_IFREG|0444:S_IFDIR|0700;s->st_size=o==85?18:0;
        if(o==84){if(root_fault==11)s->st_dev=makedev(253,2);if(root_fault==15)s->st_uid=1;
            if(root_fault==16&&fd!=input_owner.launch_fds[3])++s->st_ino;
            if(root_fault==26)s->st_mode|=0020;
            if(root_fault==34&&fd!=input_owner.launch_fds[3])s->st_mtim.tv_sec=1;}
        if(o==85){if(root_fault==17)s->st_mode=S_IFREG|0644;if(root_fault==18)s->st_nlink=2;if(root_fault==19)s->st_size=17;}
    }else if(o==82){s->st_mode=S_IFBLK|0660;s->st_gid=6;s->st_rdev=makedev(253,1);
        if(mapping_fault==27)s->st_mode=S_IFREG|0444;
        if(mapping_fault==28)s->st_uid=1;
        if(mapping_fault==31)++s->st_rdev;
        if(mapping_fault==32&&fd!=input_owner.launch_fds[2])++s->st_ino;
    }else if(o>=80){s->st_mode=S_IFBLK|0660;s->st_gid=6;
        s->st_rdev=makedev(7,(unsigned int)input_owner.launch_candidates[o-80]);
        if(launch_fault==19)s->st_mode=S_IFREG|0444;
        if(launch_fault==20)s->st_uid=1;
        if(launch_fault==23)++s->st_rdev;
        if(launch_fault==24&&fd!=input_owner.launch_fds[o-80])++s->st_ino;
        if(launch_fault==32){errno=EIO;return -1;}}
    else if(o==60)s->st_mode=S_IFDIR|0700;
    else if(o==65){s->st_mode=S_IFCHR|(flow_null_fault?0600:0666);s->st_rdev=makedev(1,3);}
    else if(o==66){s->st_mode=S_IFREG|0555;s->st_size=64;}
    else{assert(o>=61&&o<=64);s->st_mode=S_IFREG|flow_modes[o-60];s->st_size=(off_t)flow_sizes[o-60];}
    return 0;
}
static ssize_t flow_pread(int fd,void *p,size_t n,off_t offset)
{
    int o=handles[fd].object;assert(handles[fd].live);
    if(o==66){assert(offset==0&&n==64);Elf64_Ehdr h={0};memcpy(h.e_ident,ELFMAG,4);
        h.e_ident[EI_CLASS]=ELFCLASS64;h.e_ident[EI_DATA]=ELFDATA2LSB;h.e_ident[EI_VERSION]=EV_CURRENT;
        h.e_type=ET_DYN;h.e_machine=EM_X86_64;h.e_version=EV_CURRENT;h.e_ehsize=64;
        if(flow_elf_fault)h.e_ident[0]=0;
        memcpy(p,&h,64);return 64;}
    if(o==85){size_t length=flow_sizes[1];if((size_t)offset>=length){if(root_fault==21){memset(p,1,n);return 1;}return 0;}
        if(n>length-(size_t)offset)n=length-(size_t)offset;
        memcpy(p,flow_files[1]+offset,n);
        if(root_fault==20&&offset==0)((unsigned char *)p)[0]^=1;
        return (ssize_t)n;}
    assert(o>=61&&o<=64);size_t length=flow_sizes[o-60];
    if((size_t)offset>=length)return 0;
    if(n>length-(size_t)offset)n=length-(size_t)offset;
    memcpy(p,flow_files[o-60]+offset,n);return (ssize_t)n;
}
static ssize_t flow_pwrite(int fd,const void *p,size_t n,off_t offset)
{
    int o=handles[fd].object;assert(handles[fd].live&&(o==61||o==62));assert((size_t)offset+n<=8192);
    if((o==61&&flow_effect_fault==1)||(o==62&&flow_effect_fault==2))return (ssize_t)n-1;
    if(o==61&&flow_effect_fault==14){errno=EINTR;return -1;}
    memcpy(flow_files[o-60]+offset,p,n);if((size_t)offset+n>flow_sizes[o-60])flow_sizes[o-60]=(size_t)offset+n;
    return (ssize_t)n;
}
static long flow_syscall(long number,va_list args)
{
    if(number==SYS_openat2){int parent=va_arg(args,int);const char *name=va_arg(args,const char *);
        const struct open_how *how=va_arg(args,const struct open_how *);size_t size=va_arg(args,size_t);
        assert(handles[parent].object==54&&size==24&&how->mode==0&&how->resolve==13&&how->flags==(O_RDONLY|O_NONBLOCK|O_CLOEXEC));
        assert(!strcmp(name,flow_forks?"usr/sbin/veritysetup":"usr/bin/mksquashfs"));return newfd(66);}
    if(number==SYS_pidfd_open){int pid=va_arg(args,int);assert(va_arg(args,int)==0);
        if(pid==1)return -2;
        assert(pid==199+flow_forks);
        if(flow_effect_fault==8){errno=ESRCH;return -1;}
        return newfd(74);}
    assert(number==SYS_getdents64);int fd=va_arg(args,int);unsigned char *b=va_arg(args,unsigned char *);
    assert(va_arg(args,size_t)==4096);int o=handles[fd].object;
    if(o==83||o==84){
        if(handles[fd].reads++)return 0;
        ++root_scans;size_t n=record(b,".",DT_DIR);n+=record(b+n,"..",DT_DIR);
        if(o==84){size_t start=n;n+=record(b+n,"launch.bin",root_fault==23?DT_LNK:DT_REG);put(b+start,root_fault==24?7778:7777,8);}
        if((root_fault==4&&o==83)||(root_fault==5&&o==83&&root_scans>=2)||(root_fault==22&&o==84))n+=record(b+n,"extra",DT_REG);
        if(o==84){
            if(root_fault==28)b[16]=0;
            if(root_fault==29)memset(b+8,0,8);
            if(root_fault==30)memset(b+19,'x',5);
            if(root_fault==31)memset(b,0,8);
            if(root_fault==32)n+=record(b+n,"launch.bin",DT_REG);
            if(root_fault==33){errno=EINTR;return -1;}
        }
        return (long)n;
    }
    if(o!=60)return -2;
    if(handles[fd].reads++)return 0;
    size_t n=record(b,".",DT_DIR);n+=record(b+n,"..",DT_DIR);
    if(flow_sizes[1]){size_t start=n;n+=record(b+n,"launch.bin",DT_REG);put(b+start,1061,8);}
    return (long)n;
}
#ifdef RNR_FIXED_BIND_FLOW
static int binds_absent(int,const char *,struct stat *,int);
#endif
static int flow_absent(int parent,const char *name,struct stat *s,int flags)
{
#ifdef RNR_FIXED_BIND_FLOW
    if(binds_enabled)return binds_absent(parent,name,s,flags);
#endif
    assert(handles[parent].object==21&&flags==AT_SYMLINK_NOFOLLOW);(void)s;
    assert(!strcmp(name,"launch.squashfs")||!strcmp(name,"launch.verity")||!strcmp(name,"launch.root"));
    ++flow_absence_calls;
    if(flow_absence_calls==flow_absence_fault){errno=EACCES;return -1;}
    errno=ENOENT;return -1;
}
static int flow_pipe(int pair[2],int flags)
{assert(flags==(O_CLOEXEC|O_NONBLOCK));++flow_pipe_calls;
 if((flow_effect_fault==5&&flow_pipe_calls==1)||(flow_effect_fault==6&&flow_pipe_calls==2)){errno=EMFILE;return -1;}
 pair[0]=newfd(70);pair[1]=newfd(71);return 0;}
static pid_t flow_fork(void)
{
    ++flow_forks;assert(flow_forks<=2);
    if(flow_effect_fault==7){errno=EAGAIN;return -1;}
    if(flow_effect_fault==12)clock_fail=clock_calls+1;
    if(flow_forks==1){flow_sizes[2]=17;memset(flow_files[2],0x5a,17);}
    else{flow_sizes[3]=4096;flow_sizes[4]=64;memset(flow_files[3],0x77,4096);memset(flow_files[4],'a',64);}
    if(flow_effect_fault==16&&flow_forks==2)flow_files[4][0]='A';
    if(flow_effect_fault==17&&flow_forks==2)--flow_sizes[3];
    if(flow_effect_fault==18&&flow_forks==2)--flow_sizes[4];
    return 199+flow_forks;
}
static pid_t flow_wait(pid_t pid,int *status,int flags)
{assert(pid==199+flow_forks&&flags==WNOHANG);++flow_waits;assert(flow_waits==flow_forks);*status=0;return pid;}
static ssize_t flow_read(int fd,void *p,size_t n)
{assert(handles[fd].live&&handles[fd].object==70&&n<=4096);(void)p;return 0;}
static ssize_t flow_random(void *p,size_t n,unsigned int flags)
{++flow_random_calls;assert(n==32&&!flags);
 if(flow_effect_fault==3)return 31;
 if(flow_effect_fault==15){errno=EINTR;return -1;}
 memset(p,0x42,n);return (ssize_t)n;}
static int flow_chmod(int fd,mode_t mode)
{assert(mode==0444&&handles[fd].live);int o=handles[fd].object;assert(o>=62&&o<=64);
 if((flow_effect_fault==9&&o==62)||(flow_effect_fault==10&&o==63)||(flow_effect_fault==11&&o==64)){errno=EPERM;return -1;}
 flow_modes[o-60]=mode;return 0;}
static int flow_signal(int signal,const struct sigaction *action,struct sigaction *old)
{assert(signal==SIGCHLD&&!action);memset(old,0,sizeof(*old));old->sa_handler=SIG_DFL;if(flow_effect_fault==4)old->sa_flags=SA_NOCLDWAIT;return 0;}
static void flow_start(void)
{
    root_enabled=root_fault=root_mkdirs=root_mounts=root_effect_mounted=root_scans=root_closed_old=0;
    mapping_enabled=mapping_fault=mapping_stage=mapping_creates=mapping_loads=mapping_resumes=mapping_queries=0;
    reset();flow_enabled=launch_enabled=launch_free_calls=launch_configure_calls=launch_fault=0;
    launch_test_device=launch_test_inode=0;memset(launch_bound,0,sizeof(launch_bound));memset(launch_queries,0,sizeof(launch_queries));memset(launch_configured,0,sizeof(launch_configured));memset(flow_files,0,sizeof(flow_files));memset(flow_sizes,0,sizeof(flow_sizes));
    for(int j=0;j<5;++j)flow_modes[j]=j==1?0444:0600;
    flow_forks=flow_waits=flow_absence_calls=flow_absence_fault=flow_null_fault=flow_elf_fault=flow_pad_small_fd=flow_random_calls=flow_effect_fault=flow_pipe_calls=0;
    struct rnr_stage0_preparer_error e;inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;
    assert(rnr_stage0_claim_preparation(&e)==0);phase4=1;assert(rnr_stage0_prepare_runtime_loops(&e)==0);
    phase5=1;assert(rnr_stage0_prepare_runtime_mapping(&e)==0);phase6=1;assert(rnr_stage0_prepare_runtime_mount(&e)==0);
    flow_enabled=1;
}
static uint64_t flow_mount(int fd)
{int o=handles[fd].object;if(o==83)return 44;if(o==84||o==85)return root_fault==13?44:root_fault==14?66:root_fault==27&&o==85?89:88;return o==82&&mapping_fault==29?99:o>=80&&launch_fault==21?99:o==65||o>=80?55:o==66?66:44;}
static int flow_close_errors(void)
{return (close_error==10&&root_enabled&&input_owner.launch_fds[4]>=3&&input_owner.journal_sequence==56)|| (close_error==9&&mapping_enabled&&input_owner.launch_fds[2]>=3&&input_owner.journal_sequence==52)|| (close_error==8&&launch_enabled&&input_owner.launch_initialized&&input_owner.launch_fds[1]>=3&&input_owner.journal_sequence==46);}
static int flow_root_mkdir(int fd,const char *path)
{
    if(!root_enabled||strcmp(path,"launch"))return -2;
    assert(handles[fd].object==21&&input_owner.journal_sequence==53);++root_mkdirs;
    if(root_fault==1){errno=EEXIST;return -1;}
    if(root_fault==2)clock_fail=clock_calls+1;
    return 0;
}
static int flow_root_mount(const char *source,const char *target,const char *fs,unsigned long flags,const void *data)
{
    if(!root_enabled)return -2;
    assert(!strcmp(source,"/dev/dm-1")&&!strcmp(target,"/run/rnr-native-04000000000000000000000000000000/launch"));
    assert(!strcmp(fs,"squashfs")&&flags==7&&!data&&input_owner.journal_sequence==55);++root_mounts;
    if(root_fault==6){errno=EIO;return -1;}
    if(root_fault==7)return 1;
    root_effect_mounted=1;if(root_fault==8)clock_fail=clock_calls+1;return 0;
}
static int flow_root_badfs(int fd)
{return root_enabled&&root_fault==10&&handles[fd].object==84;}
static int flow_root_vfs(int fd,struct statvfs *s)
{int o=handles[fd].object;if(o!=84&&o!=85)return -2;s->f_flag=root_fault==12?15:7;return 0;}
static int flow_root_close(int fd)
{if(!root_enabled||!root_effect_mounted||handles[fd].object!=83)return 0;
 ++root_closed_old;return root_fault==9;}
static int flow_root_sync(int fd)
{if(!root_enabled||handles[fd].object!=21)return -2;
 if(root_fault==3){errno=EIO;return -1;}return 0;}
static const char mapping_name[]="rnr-l-04000000000000000000000000000000";
static const char mapping_uuid[]="rnr-native-04000000000000000000000000000000-launch";
static const char mapping_params[]="1 7:5 7:6 4096 4096 2 0 sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa 4242424242424242424242424242424242424242424242424242424242424242";
static int mapping_ioctl(unsigned long cmd,struct dm_ioctl *d)
{
    /* Independent full request vector, including all zero reserved bytes. */
    union {max_align_t alignment;unsigned char bytes[4096];} wanted={0};
    struct dm_ioctl *w=(void *)wanted.bytes;w->version[0]=4;w->data_start=312;w->data_size=4096;
    unsigned int flags=cmd==DM_TABLE_LOAD?1:cmd==DM_TABLE_STATUS?d->flags:0;
    assert(flags==0||flags==1||flags==16||flags==4112);w->flags=flags;
    if(cmd!=DM_VERSION)memcpy(w->uuid,mapping_uuid,sizeof(mapping_uuid));
    if(cmd==DM_DEV_CREATE)memcpy(w->name,mapping_name,sizeof(mapping_name));
    if(cmd==DM_TABLE_LOAD){w->target_count=1;struct dm_target_spec *t=(void *)(wanted.bytes+312);
        t->length=16;memcpy(t->target_type,"verity",7);memcpy(t+1,mapping_params,sizeof(mapping_params));t->next=(40+sizeof(mapping_params)+7)&~7U;}
    assert(!memcmp(d,wanted.bytes,4096));
    if(cmd==DM_VERSION){d->version[1]=mapping_fault==1?48:50;return 0;}
    if(cmd==DM_DEV_CREATE){assert(mapping_stage==0&&input_owner.journal_sequence==47);++mapping_creates;
        if(mapping_fault==2){errno=EEXIST;return -1;}mapping_stage=1;}
    if(cmd==DM_TABLE_LOAD){assert(mapping_stage==1&&input_owner.journal_sequence==49);++mapping_loads;
        if(mapping_fault==6){errno=EFAULT;d->dev=0xfd01;((unsigned char *)(void *)d)[4095]=0x9a;return -1;}mapping_stage=2;}
    if(cmd==DM_DEV_SUSPEND){assert(mapping_stage==2&&input_owner.journal_sequence==51);++mapping_resumes;
        if(mapping_fault==38){errno=EFAULT;d->dev=0xfd01;return -1;}mapping_stage=3;}
    if(cmd==DM_DEV_STATUS||cmd==DM_TABLE_STATUS)++mapping_queries;
    int openers=0;for(int j=0;j<RNR_TEST_HANDLES;++j)if(handles[j].live&&handles[j].object==82)++openers;
    memset(d,0,4096);d->version[0]=4;d->version[1]=50;d->data_start=312;d->data_size=305;
    d->dev=0xfd01;d->open_count=openers+root_effect_mounted+(root_fault==25&&root_effect_mounted?1:0);d->event_nr=mapping_stage==3?7:0;
    memcpy(d->name,mapping_name,sizeof(mapping_name));memcpy(d->uuid,mapping_uuid,sizeof(mapping_uuid));
    d->flags=mapping_stage==1?0:mapping_stage==2?64:33;d->target_count=mapping_stage==3?1:0;
    if(cmd==DM_TABLE_STATUS){
        assert(mapping_stage>=2);d->flags=flags==4112?4177:flags==16?49:33;d->target_count=1;
        struct dm_target_spec *t=(void *)((unsigned char *)d+312);t->length=16;memcpy(t->target_type,"verity",7);
        const char *text=flags&16?mapping_params:"V";size_t n=strlen(text)+1;memcpy(t+1,text,n);
        d->data_size=352+(unsigned int)n;t->next=(40+(unsigned int)n+7)&~7U;
        if((mapping_fault==8&&flags==4112)||(mapping_fault==23&&flags==16))((char *)(t+1))[0]='x';
        if(mapping_fault==24&&!flags)((char *)(t+1))[0]='C';
        if(mapping_fault==43)++t->sector_start;
        if(mapping_fault==44)t->target_type[15]=1;
    }
    if(mapping_fault==3&&cmd==DM_DEV_CREATE)d->dev=0xfd00;
    if(mapping_fault==4&&cmd==DM_DEV_CREATE)d->uuid[0]='x';
    if(mapping_fault==5&&cmd==DM_DEV_STATUS&&mapping_stage==1)d->flags=64;
    if(mapping_fault==7&&cmd==DM_TABLE_LOAD)d->flags=65;
    if(mapping_fault==9&&cmd==DM_DEV_STATUS&&mapping_stage==2)d->target_count=1;
    if(cmd==DM_DEV_SUSPEND){
        if(mapping_fault==10)d->uuid[0]='x';
        if(mapping_fault==11)d->version[1]=48;
        if(mapping_fault==12)d->data_size=312;
        if(mapping_fault==13)d->target_count=0;
        if(mapping_fault==14)d->open_count=1;
        if(mapping_fault==15)d->dev=0xfd02;
        if(mapping_fault==16)d->flags=35;
        if(mapping_fault==17)d->flags=8225;
    }
    if((mapping_fault==19&&cmd==DM_DEV_CREATE)||(mapping_fault==20&&cmd==DM_TABLE_LOAD)||
       (mapping_fault==21&&cmd==DM_DEV_SUSPEND))clock_fail=clock_calls+1;
    if(mapping_fault==33&&cmd==DM_DEV_STATUS){errno=EIO;return -1;}
    if(mapping_fault==34&&cmd==DM_DEV_STATUS&&mapping_stage==3)++d->event_nr;
    if(mapping_fault==35&&cmd==DM_DEV_CREATE)d->version[1]=48;
    if(mapping_fault==36&&cmd==DM_DEV_CREATE)d->event_nr=1;
    if(mapping_fault==41&&cmd==DM_DEV_CREATE)d->name[0]='x';
    if(mapping_fault==42)d->padding=1;
    if(mapping_fault==45&&cmd==DM_DEV_CREATE)d->dev=1;
    return (mapping_fault==22&&cmd==DM_DEV_CREATE)||(mapping_fault==37&&cmd==DM_TABLE_LOAD)||
           (mapping_fault==39&&cmd==DM_DEV_SUSPEND)?1:0;
}
static int flow_ioctl(int fd,unsigned long cmd,va_list args)
{
    int o=handles[fd].object;
    if(mapping_enabled&&o==51){struct dm_ioctl *d=va_arg(args,struct dm_ioctl *);
        if(cmd==DM_VERSION||strstr(d->uuid,"-launch"))return mapping_ioctl(cmd,d);
        return -2;}
    if(mapping_enabled&&o==82){
        if(mapping_fault==40){errno=EIO;return -1;}
        if(cmd==BLKROGET){*va_arg(args,int *)=mapping_fault==25?0:1;return 0;}
        assert(cmd==BLKGETSIZE64);*va_arg(args,uint64_t *)=mapping_fault==26?8191:8192;return 0;
    }
    if(!launch_enabled)return -2;
    if(o==47&&cmd==LOOP_CTL_GET_FREE){
        ++launch_free_calls;assert(launch_free_calls<=2);
        assert(input_owner.journal_sequence==(launch_free_calls==1?39U:43U));
        if(launch_fault==1)return 3;
        if(launch_fault==12)return 4;
        if(launch_fault==13&&launch_free_calls==1)return 1048575;
        if(launch_fault==14){errno=EIO;return -1;}
        if(launch_fault==15)clock_fail=clock_calls+1;
        if(launch_fault==2)return launch_free_calls==2?5:5;
        if(launch_fault==3)return 1048576;
        return 4+launch_free_calls;
    }
    if(o<80||o>81)return -2;
    int i=o-80;
    if(cmd==LOOP_CONFIGURE){
        struct loop_config *c=va_arg(args,struct loop_config *);assert(!launch_bound[i]);
        assert(input_owner.journal_sequence==(i?45U:41U));
        assert(handles[c->fd].object==62+i&&c->block_size==4096&&c->info.lo_flags==1);
        assert(c->info.lo_sizelimit==(uint64_t)(i?4096:8192)&&!c->info.lo_offset);
        ++launch_configure_calls;
        if(launch_fault==4){errno=EBUSY;return -1;}
        launch_configured[i]=*c;launch_bound[i]=1;
        if(launch_fault==16)clock_fail=clock_calls+1;
        return launch_fault==17?1:0;
    }
    if(cmd==LOOP_GET_STATUS64){
        struct loop_info64 *v=va_arg(args,struct loop_info64 *);
        if(!launch_bound[i]){if(launch_fault==25)flow_files[2][0]^=1;if(launch_fault==5)return 0;errno=launch_fault==6?EIO:ENXIO;return -1;}
        ++launch_queries[i];
        *v=launch_configured[i].info;v->lo_device=launch_test_device?launch_test_device:4;v->lo_inode=launch_test_inode?launch_test_inode:(uint64_t)(1062+i);v->lo_number=(unsigned int)input_owner.launch_candidates[i];
        if(launch_fault==7)++v->lo_inode;
        if(launch_fault==8)v->lo_flags|=LO_FLAGS_AUTOCLEAR;
        if(launch_fault==9||(launch_fault==18&&!i&&launch_queries[i]>=2))v->lo_file_name[0]='x';
        if(launch_fault==26)v->lo_file_name[63]=1;
        if(launch_fault==27)v->lo_encrypt_key_size=1;
        if(launch_fault==28)v->lo_rdevice=1;
        if(launch_fault==29)v->lo_offset=1;
        if(launch_fault==30)++v->lo_number;
        return 0;
    }
    if(cmd==BLKROGET){if(launch_fault==31){errno=EINTR;return -1;}*va_arg(args,int *)=launch_fault==10?0:1;return 0;}
    if(cmd==BLKGETSIZE64){*va_arg(args,uint64_t *)=(uint64_t)(i?4096:8192)-(launch_fault==11?1:0);return 0;}
    assert(0);return -1;
}
static void launch_start(void)
{
    flow_start();struct rnr_stage0_preparer_error e;
    assert(rnr_stage0_prepare_launch_media(&e)==0);launch_enabled=1;
}
static void launch_vectors(void)
{
    for(int j=0;j<8;++j){
        int i=j/4,configure=j%4>=2,returned=j&1;
        unsigned char b[256]={0};memcpy(b,"RNRO0001",8);put(b+8,1,4);put(b+12,configure?2:1,4);
        put(b+16,39+j,8);b[24]=4;put(b+40,3+i,4);put(b+44,returned?2:1,4);
        if(returned&&!configure)put(b+48,5+i,8);
        put(b+64,4,8);put(b+72,1062+i,8);put(b+80,i?4096:8192,8);put(b+88,44,8);
        if(configure||returned)put(b+96,5+i,4);
        if(configure){put(b+100,7,4);put(b+104,5+i,4);}
        put(b+108,1,4);memcpy(b+112,i?"rnr-04000000000000000000000000000000-lh":"rnr-04000000000000000000000000000000-ld",39);
        put(b+184,i?4096:8192,8);
        assert(!memcmp(b,append_bytes+(38+j)*256,256));
    }
}
static void launch_tests(void)
{
    struct rnr_stage0_preparer_error e;launch_start();
    int first_open=calls,first_clock=clock_calls;
    assert(rnr_stage0_prepare_launch_loops(&e)==0);
    int last_open=calls,last_clock=clock_calls;
    assert(input_owner.journal_sequence==46&&launch_free_calls==2&&launch_configure_calls==2);
    launch_vectors();
    int live=0;for(int j=0;j<RNR_TEST_HANDLES;++j)live+=handles[j].live;assert(live==53);
    int before=total_closed();assert(rnr_stage0_prepare_launch_loops(&e)==-1&&total_closed()==before);
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    before=total_closed();handles[10].live=1;
    assert(rnr_stage0_abandon_preparation_inputs(&e)==-1&&handles[10].live&&total_closed()==before);handles[10].live=0;
#ifdef RNR_MEDIA_SHORT
    (void)first_open;(void)first_clock;(void)last_open;(void)last_clock;
#else
    for(int j=first_open+1;j<=last_open;++j){
        launch_start();fail_at=j;assert(rnr_stage0_prepare_launch_loops(&e)==-1);drained();
        launch_start();abandon_at=j;assert(rnr_stage0_prepare_launch_loops(&e)==-1&&!abandon_closed);drained();
    }
    for(int j=first_clock+1;j<=last_clock;++j){launch_start();clock_fail=j;
        assert(rnr_stage0_prepare_launch_loops(&e)==-1);drained();}
#endif
    launch_start();close_error=8;assert(rnr_stage0_prepare_launch_loops(&e)==-1&&e.cleanup_count==54&&!e.cleanup_overflow);drained();
    launch_start();foreign=1;before=total_closed();assert(rnr_stage0_prepare_launch_loops(&e)==-1&&total_closed()==before&&!launch_free_calls);
    foreign=0;assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    launch_start();before=total_closed();assert(rnr_stage0_prepare_launch_loops(NULL)==-1&&total_closed()==before&&!launch_free_calls);
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    launch_start();assert(rnr_stage0_prepare_launch_loops(&e)==0);
    atomic_store(&preparer_state,PREPARER_LAUNCH_LOOPS_ACQUIRING);
    input_owner.media_identities[2].st_dev=makedev(259,513);
    input_owner.media_identities[2].st_ino=UINT64_C(0x102030405060708);
    launch_test_device=UINT64_C(0x210301);launch_test_inode=UINT64_C(0x102030405060708);
    e=(struct rnr_stage0_preparer_error){0};assert(launch_loop_verify(0,&e)==0);
    launch_test_device=UINT64_C(0x210302);assert(launch_loop_verify(0,&e)==-1);
    fence_inputs();drain_inputs(&e);drained();
    for(int j=1;j<=3;++j){launch_start();if(j==3)sync_fault=1;else write_fault=j;
        assert(rnr_stage0_prepare_launch_loops(&e)==-1&&!launch_free_calls&&!launch_configure_calls);drained();}
    launch_start();input_owner.child_reaped=0;
    assert(rnr_stage0_prepare_launch_loops(&e)==-1&&e.code!=RNR_STAGE0_PREPARER_OK&&!launch_free_calls);drained();
    for(int i=1;i<=32;++i){launch_start();launch_fault=i;
        if(i==13){assert(rnr_stage0_prepare_launch_loops(&e)==0);assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();continue;}
        assert(rnr_stage0_prepare_launch_loops(&e)==-1&&e.code!=RNR_STAGE0_PREPARER_OK);drained();assert(launch_configure_calls<=2);
        if(i==18)assert(launch_free_calls==1&&launch_configure_calls==1);
        if(i==4||i==14)assert(e.code==RNR_STAGE0_PREPARER_LOOP);
        if(i==14||i==15||i==16)assert(input_owner.operation_entered&&input_owner.operation_returned&&
            input_owner.operation_result==(i==14?-1:i==15?5:0));
    }
}
static void mapping_start(void)
{
    launch_start();struct rnr_stage0_preparer_error e;assert(rnr_stage0_prepare_launch_loops(&e)==0);mapping_enabled=1;
}
static void mapping_vectors(void)
{
    for(int j=0;j<6;++j){
        unsigned char b[256]={0};int op=3+j/2,returned=j&1;
        memcpy(b,"RNRO0001",8);put(b+8,1,4);put(b+12,op,4);put(b+16,47+j,8);b[24]=4;put(b+40,6,4);put(b+44,returned?2:1,4);
        if(op==3){memcpy(b+64,mapping_name,sizeof(mapping_name));memcpy(b+112,mapping_uuid,sizeof(mapping_uuid));if(returned)put(b+176,0xfd01,8);}
        else{put(b+64,makedev(7,5),8);put(b+72,makedev(7,6),8);put(b+80,0xfd01,8);put(b+88,2,8);put(b+96,1,8);
            memset(b+104,0xaa,32);memset(b+136,0x42,32);put(b+168,16,8);put(b+176,op==4?1:0,4);}
        assert(!memcmp(b,append_bytes+(46+j)*256,256));
    }
}
static void launch_mapping_tests(void)
{
    struct rnr_stage0_preparer_error e;mapping_start();
    int first_open=calls,first_clock=clock_calls;
    assert(rnr_stage0_prepare_launch_mapping(&e)==0);
    int last_open=calls,last_clock=clock_calls;
    assert(input_owner.journal_sequence==52&&mapping_creates==1&&mapping_loads==1&&mapping_resumes==1);
    assert(input_owner.launch_mapping.dm_device==0xfd01&&input_owner.launch_mapping.dm_event==7&&input_owner.launch_mapping.dm_openers==1);
    assert(input_owner.runtime_mapping.dm_device==0xfd00&&!input_owner.runtime_mapping.dm_event&&input_owner.runtime_mapping.dm_openers==2);
    mapping_vectors();int live=0;for(int j=0;j<RNR_TEST_HANDLES;++j)live+=handles[j].live;assert(live==54);
    int before=total_closed();assert(rnr_stage0_prepare_launch_mapping(&e)==-1&&total_closed()==before);
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    handles[10].live=1;before=total_closed();assert(rnr_stage0_abandon_preparation_inputs(&e)==-1&&handles[10].live&&total_closed()==before);handles[10].live=0;
#ifndef RNR_MEDIA_SHORT
    for(int j=first_open+1;j<=last_open;++j){
        mapping_start();fail_at=j;assert(rnr_stage0_prepare_launch_mapping(&e)==-1);drained();
        mapping_start();abandon_at=j;assert(rnr_stage0_prepare_launch_mapping(&e)==-1&&!abandon_closed);drained();
    }
    for(int j=first_clock+1;j<=last_clock;++j){mapping_start();clock_fail=j;assert(rnr_stage0_prepare_launch_mapping(&e)==-1);drained();}
#else
    (void)first_open;(void)last_open;(void)first_clock;(void)last_clock;
#endif
    mapping_start();close_error=9;assert(rnr_stage0_prepare_launch_mapping(&e)==-1&&e.cleanup_count==55&&!e.cleanup_overflow);drained();
    mapping_start();foreign=1;before=total_closed();assert(rnr_stage0_prepare_launch_mapping(&e)==-1&&total_closed()==before&&!mapping_creates);
    foreign=0;assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    mapping_start();before=total_closed();assert(rnr_stage0_prepare_launch_mapping(NULL)==-1&&total_closed()==before&&!mapping_creates);
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    for(int j=1;j<=3;++j){mapping_start();if(j==3)sync_fault=1;else write_fault=j;
        assert(rnr_stage0_prepare_launch_mapping(&e)==-1&&!mapping_creates);drained();}
    for(int problem=1;problem<=45;++problem){mapping_start();mapping_fault=problem;
        if(problem==17||problem==18){assert(rnr_stage0_prepare_launch_mapping(&e)==0);assert(input_owner.launch_mapping.dm_event==7);
            assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();continue;}
        int result=rnr_stage0_prepare_launch_mapping(&e);
        if(result!=-1)fprintf(stderr,"mapping fault%d accepted\n",problem);
        assert(result==-1&&e.code!=RNR_STAGE0_PREPARER_OK);drained();
        if(problem==3||problem==4||problem==5||problem==35||problem==36||problem==41||problem==45)assert(!mapping_loads&&!mapping_resumes);
        if(problem==8||problem==9)assert(mapping_loads==1&&!mapping_resumes);
        if(problem>=10&&problem<=16){struct dm_ioctl raw;memcpy(&raw,input_owner.launch_mapping.dm_response,312);
            assert(mapping_resumes==1&&!input_owner.launch_mapping.dm_event&&raw.event_nr==7&&mapping_queries==3);}
        if(problem==3||problem==4||problem==35||problem==36||problem==41||problem==45)assert(!input_owner.launch_mapping.dm_device);
        if(problem>=19&&problem<=21){assert(input_owner.operation_entered&&input_owner.operation_returned&&!input_owner.operation_result);
            assert(mapping_creates==1&&mapping_loads==(problem>=20)&&mapping_resumes==(problem>=21));
            struct dm_ioctl raw;memcpy(&raw,input_owner.launch_mapping.dm_response,312);assert(raw.dev==0xfd01);}
        if(problem==6){assert(input_owner.launch_mapping.dm_errno==EFAULT&&input_owner.launch_mapping.dm_response[4095]==0x9a&&!mapping_resumes);}
        assert(input_owner.runtime_mapping.dm_device==0xfd00&&!input_owner.runtime_mapping.dm_event&&input_owner.runtime_mapping.dm_openers==2);
    }
}
static void launch_root_start(void)
{
    mapping_start();struct rnr_stage0_preparer_error e;assert(rnr_stage0_prepare_launch_mapping(&e)==0);root_enabled=1;
}
static void launch_mount_vectors(void)
{
    for(int j=0;j<4;++j){unsigned char b[256]={0};int returned=j&1;
        memcpy(b,"RNRO0001",8);put(b+8,1,4);put(b+12,j<2?11:6,4);put(b+16,53+j,8);b[24]=4;put(b+40,8,4);put(b+44,returned?2:1,4);
        if(j<2){put(b+64,4,8);put(b+72,1021,8);put(b+80,44,8);memcpy(b+88,"launch",7);put(b+160,0700,4);
            if(returned){put(b+136,4,8);put(b+144,1083,8);put(b+152,44,8);}}
        else{put(b+64,5,8);put(b+72,1082,8);put(b+80,55,8);put(b+88,makedev(253,1),8);
            put(b+96,4,8);put(b+104,1083,8);put(b+112,44,8);if(returned)put(b+120,88,8);
            put(b+128,7,8);memcpy(b+136,"squashfs",9);put(b+152,0xfd01,8);}
        assert(!memcmp(b,append_bytes+(52+j)*256,256));}
}
static void launch_mount_tests(void)
{
    struct rnr_stage0_preparer_error e;launch_root_start();int first_open=calls,first_clock=clock_calls;
    int result=rnr_stage0_prepare_launch_mount(&e);
    if(result)fprintf(stderr,"launch mount failed%d errno%d seq%u scans%d\n",e.code,e.system_errno,input_owner.journal_sequence,root_scans);
    assert(result==0);int last_open=calls,last_clock=clock_calls;
    assert(root_mkdirs==1&&root_mounts==1&&root_closed_old==1&&root_scans==3&&input_owner.journal_sequence==56);
    assert(input_owner.launch_mapping.dm_openers==2&&input_owner.runtime_mapping.dm_openers==2);
    assert(handles[input_owner.launch_fds[3]].object==84&&handles[input_owner.launch_fds[4]].object==85);
    assert(input_owner.launch_identities[4].st_ino==7777&&input_owner.launch_identities[4].st_ino!=input_owner.media_identities[1].st_ino);
    assert(input_owner.launch_mount_sync.entered&&!input_owner.launch_mount_sync.result&&!input_owner.launch_mount_sync.system_errno);
    launch_mount_vectors();int live=0;for(int j=0;j<RNR_TEST_HANDLES;++j)live+=handles[j].live;assert(live==56);
    int before=total_closed();assert(rnr_stage0_prepare_launch_mount(&e)==-1&&total_closed()==before);
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    handles[10].live=1;before=total_closed();assert(rnr_stage0_abandon_preparation_inputs(&e)==-1&&handles[10].live&&total_closed()==before);handles[10].live=0;
#ifndef RNR_MEDIA_SHORT
    for(int j=first_open+1;j<=last_open;++j){
        launch_root_start();fail_at=j;assert(rnr_stage0_prepare_launch_mount(&e)==-1);drained();
        launch_root_start();abandon_at=j;assert(rnr_stage0_prepare_launch_mount(&e)==-1&&!abandon_closed);drained();}
    for(int j=first_clock+1;j<=last_clock;++j){launch_root_start();clock_fail=j;assert(rnr_stage0_prepare_launch_mount(&e)==-1);drained();}
#else
    (void)first_open;(void)last_open;(void)first_clock;(void)last_clock;
#endif
    launch_root_start();close_error=10;assert(rnr_stage0_prepare_launch_mount(&e)==-1&&e.cleanup_count==57&&!e.cleanup_overflow);drained();
    launch_root_start();foreign=1;before=total_closed();assert(rnr_stage0_prepare_launch_mount(&e)==-1&&total_closed()==before&&!root_mkdirs);
    foreign=0;assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    launch_root_start();before=total_closed();assert(rnr_stage0_prepare_launch_mount(NULL)==-1&&total_closed()==before&&!root_mkdirs);
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    for(int j=1;j<=3;++j){launch_root_start();if(j==3)sync_fault=1;else write_fault=j;
        assert(rnr_stage0_prepare_launch_mount(&e)==-1&&!root_mkdirs);drained();}
    for(int problem=1;problem<=34;++problem){launch_root_start();root_fault=problem;
        int result=rnr_stage0_prepare_launch_mount(&e);if(result!=-1)fprintf(stderr,"mount fault%d accepted\n",problem);
        assert(result==-1&&e.code!=RNR_STAGE0_PREPARER_OK);drained();
        if(problem==1)assert(!root_mounts&&input_owner.launch_fds[3]==-1&&root_scans==0);
        if(problem==2||problem==8)assert(input_owner.operation_entered&&input_owner.operation_returned&&!input_owner.operation_result);
        if(problem==3)assert(input_owner.launch_mount_sync.entered&&input_owner.launch_mount_sync.result==-1&&input_owner.launch_mount_sync.system_errno==EIO);
        if(problem==4||problem==5)assert(!root_mounts&&root_scans==(problem==4?1:2));
        if(problem==7)assert(input_owner.operation_result==1&&!input_owner.launch_root_mounted);
        if(problem==9)assert(root_closed_old==1&&!input_owner.launch_root_mounted);
        if(problem>=10&&problem<=16)assert(input_owner.launch_mapping.dm_openers==1||problem==16);
        assert(input_owner.runtime_mapping.dm_openers==2);
    }
}
static void flow_vectors(void)
{
    const unsigned int ops[16]={11,11,12,12,9,9,13,13,9,9,14,14,14,14,10,10};
    const unsigned int roles[16]={8,8,8,8,23,23,8,8,24,24,4,4,25,25,25,25};
    for(int j=0;j<16;++j){
        unsigned char b[256]={0};int returned=j&1;
        memcpy(b,"RNRO0001",8);put(b+8,1,4);put(b+12,ops[j],4);put(b+16,23+j,8);
        b[24]=4;put(b+40,roles[j],4);put(b+44,returned?2:1,4);
        if(returned){int result=j==3?flow_built_fd:j==5?200:j==7?flow_pad_fd:j==9?201:0;put(b+48,(uint64_t)result,8);}
        if(j<2){put(b+64,4,8);put(b+72,1021,8);put(b+80,44,8);memcpy(b+88,"launch-source",13);put(b+160,0700,4);
            if(returned){put(b+136,4,8);put(b+144,1060,8);put(b+152,44,8);}}
        else if(j<4){put(b+64,4,8);put(b+72,1060,8);put(b+80,44,8);memcpy(b+88,"launch.bin",10);
            put(b+136,18,8);put(b+144,123456789,8);put(b+176,0444,4);
            if(returned){put(b+152,4,8);put(b+160,1061,8);put(b+168,44,8);}}
        else if(j==4||j==5||j==8||j==9){put(b+72,roles[j],4);if(returned)put(b+64,j==5?200:201,8);}
        else if(j<8){put(b+64,4,8);put(b+72,1062,8);put(b+80,44,8);put(b+88,17,8);put(b+96,8192,8);put(b+104,0444,4);}
        else if(j<14){put(b+64,4,8);put(b+72,j<12?1063:1064,8);put(b+80,44,8);put(b+88,j<12?4096:64,8);put(b+96,0444,4);}
        else{memcpy(b+64,"RNRP0001",8);put(b+72,1,4);b[80]=4;memset(b+96,0xaa,32);memset(b+128,0x42,32);
            put(b+160,2,8);put(b+168,1,8);}
        if(memcmp(b,append_bytes+(22+j)*256,256))fprintf(stderr,"media vector%d differs\n",j);
        assert(!memcmp(b,append_bytes+(22+j)*256,256));
    }
}
static void flow_close_capsules(void)
{
    for(int problem=0;problem<2;++problem){
        flow_start();atomic_store(&preparer_state,PREPARER_MEDIA_ACQUIRING);
        input_owner.media_initialized=1;for(int j=0;j<12;++j)input_owner.media_fds[j]=-1;
        for(int j=6;j<12;++j)input_owner.media_fds[j]=newfd(70);
        int first=input_owner.media_fds[11],second=input_owner.media_fds[10];
        struct rnr_stage0_preparer_error e={0};
        assert(media_helper_close(0,11,&e)==0);
        if(problem){clock_fail=clock_calls+2;}else{close_error=1;seen_calls=1;}
        assert(media_helper_close(0,10,&e)==-1);
        assert(input_owner.helper_closes[0][5].fd==first&&input_owner.helper_closes[0][5].entered&&
               input_owner.helper_closes[0][5].result==0&&!input_owner.helper_closes[0][5].system_errno);
        assert(input_owner.helper_closes[0][4].fd==second&&input_owner.helper_closes[0][4].entered&&
               input_owner.helper_closes[0][4].result==(problem?0:-1)&&
               input_owner.helper_closes[0][4].system_errno==(problem?0:EINTR));
        assert(input_owner.media_fds[11]==-1&&input_owner.media_fds[10]==-1);
        fence_inputs();drain_inputs(&e);drained();
    }
}
#ifdef RNR_FIXED_BIND_FLOW
#define main media_flow_fixture_main
#endif
int main(void)
{
    launch_mount_tests();
    launch_mapping_tests();
    launch_tests();
    flow_close_capsules();
    struct rnr_stage0_preparer_error e;flow_start();
    int first_open=calls,first_clock=clock_calls;
    int result=rnr_stage0_prepare_launch_media(&e);
    if(result)fprintf(stderr,"media failed code%d errno%d seq%d step%d\n",e.code,e.system_errno,input_owner.journal_sequence,flow_forks);
    assert(result==0);assert(input_owner.journal_sequence==38&&flow_forks==2&&flow_waits==2&&flow_absence_calls==6);
    int last_open=calls,last_clock=clock_calls;
    flow_vectors();
    assert(input_owner.media_output.launch.data_blocks==2&&input_owner.media_output.launch.hash_blocks==1);
    for(int j=6;j<12;++j)assert(input_owner.media_fds[j]==-1);
    for(int helper=0;helper<2;++helper)for(int role=0;role<6;++role){
        assert(input_owner.helper_closes[helper][role].entered);
        assert(input_owner.helper_closes[helper][role].fd>=3);
        assert(input_owner.helper_closes[helper][role].result==0);
        assert(input_owner.helper_closes[helper][role].system_errno==0);
        for(int prior=0;prior<role;++prior)
            assert(input_owner.helper_closes[helper][role].fd!=input_owner.helper_closes[helper][prior].fd);
    }
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
#ifdef RNR_MEDIA_SHORT
    (void)first_open;(void)last_open;(void)first_clock;(void)last_clock;
#else
    for(int i=first_open+1;i<=last_open;++i){
        flow_start();fail_at=i;assert(rnr_stage0_prepare_launch_media(&e)==-1);drained();
        flow_start();abandon_at=i;assert(rnr_stage0_prepare_launch_media(&e)==-1&&!abandon_closed);drained();
    }
    for(int i=first_clock+1;i<=last_clock;++i){
        flow_start();clock_fail=i;assert(rnr_stage0_prepare_launch_media(&e)==-1);drained();
    }
    #endif
    for(int i=1;i<=18;++i){
        if(i==13)continue;
        flow_start();flow_effect_fault=i;assert(rnr_stage0_prepare_launch_media(&e)==-1);drained();
        if(i==7)assert(input_owner.child_returned&&input_owner.child_pid==-1&&input_owner.child_errno==EAGAIN);
        if(i==8||i==12)assert(input_owner.child_entered&&input_owner.child_returned&&input_owner.child_pid==200&&!input_owner.child_reaped);
    }
    for(int i=1;i<=6;++i){flow_start();flow_absence_fault=i;
        assert(rnr_stage0_prepare_launch_media(&e)==-1);assert(flow_forks<=(i<=2?0:1));drained();}
    flow_start();flow_null_fault=1;assert(rnr_stage0_prepare_launch_media(&e)==-1&&!flow_forks);drained();
    flow_start();flow_pad_small_fd=1;assert(rnr_stage0_prepare_launch_media(&e)==-1&&flow_forks==1&&e.unadopted_fd==2&&!flow_random_calls);drained();
    flow_start();flow_elf_fault=1;assert(rnr_stage0_prepare_launch_media(&e)==-1&&!flow_forks);drained();
    return 0;
}

#ifdef RNR_FIXED_BIND_FLOW
#undef main
#endif
