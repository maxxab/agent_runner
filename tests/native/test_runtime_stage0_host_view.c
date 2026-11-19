/* Entire kernel/clock/admission boundary mocked. No protected host reads. */
#define _GNU_SOURCE
#ifndef RNR_TEST_HANDLES
#define RNR_TEST_HANDLES 1024
#endif
#ifdef NDEBUG
#error "Assertions required"
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <poll.h>
#include <linux/loop.h>
#include <linux/dm-ioctl.h>
#include <linux/fs.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/statvfs.h>
#include <unistd.h>
#include "../../automation/native/runtime_stage0_preparer.h"
#ifdef RNR_FIXED_BIND_FLOW
static int binds_enabled,bind_high_minor_setup;
static int binds_open(int,const char *,int);
static int binds_stat(int,struct stat *);
static uint64_t binds_mount_id(int);
static long binds_filesystem(int);
static int binds_vfs(int,struct statvfs *);
static int binds_effect(const char *,const char *,const char *,unsigned long,const void *);
static int binds_close(int);
static int bind_journal_fail,bind_journal_kind;
#endif
#ifdef RNR_MEDIA_FLOW
static int flow_open(int,const char *,int);
static int flow_ioctl(int,unsigned long,va_list);
static int flow_close_errors(void);
static int flow_root_mkdir(int,const char *);
static int flow_root_mount(const char *,const char *,const char *,unsigned long,const void *);
static int flow_root_vfs(int,struct statvfs *);
static int flow_root_badfs(int);
static int flow_root_close(int);
static int flow_root_sync(int);
static uint64_t flow_mount(int);
static int flow_stat(int,struct stat *);
static ssize_t flow_pread(int,void *,size_t,off_t);
static ssize_t flow_pwrite(int,const void *,size_t,off_t);
static long flow_syscall(long,va_list);
static int flow_enabled;
#endif
static int xopen(const char *,int);
static void runtime_loop_tests(void);
static void mapping_tests(void);
static void mount_tests(void);
static int xmount(const char *,const char *,const char *,unsigned long,const void *);
static int xvfs(int,struct statvfs *);
static int xopenat(int,const char *,int,...);
static int xstat(int,struct stat *);
static int xstatx(int,const char *,int,unsigned int,struct statx *);
static int xstatfs(int,struct statfs *);
static int xfcntl(int,int,...);
static int xioctl(int,unsigned long,...);
static int xpoll(struct pollfd *,nfds_t,int);
static int xclose(int);
static int xmkdir(int,const char *,mode_t);
static mode_t xumask(mode_t);
static ssize_t xpwrite(int,const void *,size_t,off_t);
static int xsync(int);
static ssize_t xpread(int,void *,size_t,off_t);
static long xsyscall(long,...);
static int xprepare(struct rnr_stage0_launch_error *);
static int xcheck(struct rnr_stage0_launch_error *);
#ifdef RNR_FIXED_CLOCK_FLOW
static int nested_clock_enabled;
static int nested_clock_check(struct rnr_stage0_launch_error *);
#endif
static int xbind(int64_t,struct rnr_stage0_launch_error *);
static int xadmit(struct rnr_stage0_admission_error *);
#ifdef RNR_FINAL_FLOW
static int final_enabled;
static int final_open_hook(int,const char *,int);
static int final_stat_hook(int,struct stat *);
static uint64_t final_mount_hook(int);
static long final_fs_hook(int);
static int final_vfs_hook(int,struct statvfs *);
static int final_fcntl_hook(int,int,int);
static long final_syscall_hook(long,va_list);
static int final_close_hook(int);
static int final_root_hook(int,const char *,int);
static int final_admit_hook(struct rnr_stage0_admission_error *);
static int final_finish_hook(struct rnr_stage0_launch_error *);
#define fchdir(d) final_root_hook(0,NULL,d)
#define chroot(p) final_root_hook(1,p,-1)
#define chdir(p) final_root_hook(2,p,-1)
#define rnr_stage0_admit_initial_fds(e) final_admit_hook(e)
#define rnr_stage0_finish_operational(e) final_finish_hook(e)
#else
#include "test_runtime_stage0_unused_final.h"
#endif
#define mount(s,t,f,g,d) xmount(s,t,f,g,d)
#define fstatvfs(d,s) xvfs(d,s)
#define open(p,f) xopen(p,f)
#define openat(...) xopenat(__VA_ARGS__)
#define fstat(d,s) xstat(d,s)
#define statx(d,p,f,m,s) xstatx(d,p,f,m,s)
#define fstatfs(d,s) xstatfs(d,s)
#define fcntl(...) xfcntl(__VA_ARGS__)
#define ioctl(...) xioctl(__VA_ARGS__)
#define poll(p,n,t) xpoll(p,n,t)
#define close(d) xclose(d)
#define mkdirat(d,p,m) xmkdir(d,p,m)
#define umask(m) xumask(m)
#define pwrite(d,p,n,o) xpwrite(d,p,n,o)
#define fsync(d) xsync(d)
#define pread(d,p,n,o) xpread(d,p,n,o)
#define syscall(...) xsyscall(__VA_ARGS__)
#define getpid() 100
#define geteuid() 0
#define getegid() 0
#define rnr_stage0_prepare_operational(e) xprepare(e)
#define rnr_stage0_check_operational_preparation(e) xcheck(e)
#define rnr_stage0_bind_operational_preparation_cutoff(d,e) xbind(d,e)
#define rnr_stage0_admit_preparation_fds(e) xadmit(e)
#include "../../automation/native/runtime_stage0_preparer.c"
#undef mount
#undef fstatvfs
#undef open
#undef openat
#undef fstat
#undef statx
#undef fstatfs
#undef fcntl
#undef ioctl
#undef poll
#undef close
#undef mkdirat
#undef umask
#undef pwrite
#undef fsync
#undef pread
#undef syscall
#undef getpid
#undef geteuid
#undef getegid
#undef rnr_stage0_prepare_operational
#undef rnr_stage0_check_operational_preparation
#undef rnr_stage0_bind_operational_preparation_cutoff
#undef rnr_stage0_admit_preparation_fds
#undef rnr_stage0_admit_initial_fds
#undef rnr_stage0_finish_operational
/* Object numbers:0root,1etc,2rnr,3install,4task,5proc,6own,7PID1,
 *8pidfd,9taskdir,10..17namespaces. Named reopens share only object ID. */
static struct {int live,object,closed,reads,access,bind_target;} handles[RNR_TEST_HANDLES];
static unsigned char install[128],task[66];
static int nextfd,calls,fail_at,clock_calls,clock_fail,fenced,phase2;
static int fault,task_fault,abandon_at,abandon_closed,prepare_calls,admit_calls;
static int close_error,foreign,events,mutate_role,mutate_after;
static int ns_reads[RNR_TEST_HANDLES],seen_calls,task_round,task_scan_completed,namespace_opens;
static int phase3,mkdir_calls,mkdir_error,claimed,work_opens,journal_opens;
static int write_calls,write_fault,written,sync_calls,sync_fault,claim_reenter;
static int umask_calls,journal_metadata_fault,claim_clock_after,journal_errno_object;
static unsigned char journal_bytes[256],append_bytes[65536];
static int phase4,free_calls,configure_calls,loop_bound[2],runtime_fault,append_writes,append_syncs;
static struct loop_config configured[2];
static int effect_clock_after;
static int phase5,dm_calls,dm_create_calls,dm_load_calls,dm_resume_calls,dm_fault,dm_opened;
static int phase6,mount_calls,mount_stage,mount_fault,root_created;
static int isns(int o){return (o>=10&&o<=17)||(o>=30&&o<=37);}
enum {BAD_NS_TYPE=1,BAD_NS_FS,BAD_NS_MODE,BAD_NS_FLAGS,PIDFD_MODE,
       PROC_FS,PROC_MOUNT,PROC_OWNER,MANAGER_NAMESPACE,CHILD_NAMESPACE,
       POLL_ERROR,PIDFD_ERROR,GETDENTS_ERROR,MISSING_MNT_ID,FSTAT_ERROR,
       STATX_ERROR,STATFS_ERROR,FCNTL_ERROR,IOCTL_ERROR};
static void put(unsigned char *p,uint64_t n,int size)
{for(int j=0;j<size;++j)p[j]=(unsigned char)(n>>(j*8));}
static void reset(void)
{
    atomic_store(&preparer_state,PREPARER_NEW);atomic_store(&input_owner_pid,0);
    input_owner=(struct preparer_owner){.fds={-1,-1,-1,-1,-1}};
    memset(handles,0,sizeof(handles));memset(ns_reads,0,sizeof(ns_reads));
    memset(install,0,128);memcpy(install,"RNRI0001",8);install[8]=1;
    install[16]=1;install[48]=2;install[96]=3;put(install+80,129,8);put(install+88,3,8);
    memset(task,0,66);memcpy(task,"RNRT0001",8);task[8]=1;task[16]=4;
    put(task+32,123456789,8);task[40]=2;memcpy(task+64,"{}",2);
    phase6=mount_calls=mount_stage=mount_fault=root_created=0;
    phase5=dm_calls=dm_create_calls=dm_load_calls=dm_resume_calls=dm_fault=dm_opened=0;
    phase4=free_calls=configure_calls=runtime_fault=append_writes=append_syncs=effect_clock_after=0;
    memset(loop_bound,0,sizeof(loop_bound));memset(configured,0,sizeof(configured));memset(append_bytes,0,sizeof(append_bytes));
    nextfd=10;calls=fail_at=clock_calls=clock_fail=fenced=phase2=0;
    phase3=mkdir_calls=mkdir_error=claimed=work_opens=journal_opens=0;
    write_calls=write_fault=written=sync_calls=sync_fault=claim_reenter=0;
    umask_calls=journal_metadata_fault=claim_clock_after=0;journal_errno_object=20;memset(journal_bytes,0,256);
    fault=task_fault=abandon_at=abandon_closed=prepare_calls=admit_calls=0;
    close_error=foreign=events=seen_calls=task_round=task_scan_completed=namespace_opens=0;mutate_role=-1;mutate_after=0;
}
static int total_closed(void)
{int n=0;for(int j=0;j<RNR_TEST_HANDLES;++j)n+=handles[j].closed;return n;}
static int newfd(int object)
{
    ++calls;if(phase2 && calls==fail_at){errno=EIO;return -1;}
    if(object==9)++task_round;
    int fd=nextfd++;
#ifdef RNR_FIXED_BIND_FLOW
    if(binds_enabled){for(fd=10;fd<RNR_TEST_HANDLES&&handles[fd].live;++fd){}
        assert(fd<RNR_TEST_HANDLES);memset(&handles[fd],0,sizeof(handles[fd]));}
#endif
    assert(fd<RNR_TEST_HANDLES);handles[fd].live=1;handles[fd].object=object;
    if(phase2 && calls==abandon_at){
        struct rnr_stage0_preparer_error e;int before=total_closed();
        assert(rnr_stage0_abandon_preparation_inputs(&e)==-1);
        abandon_closed+=total_closed()-before;
    }
    return fd;
}
static int xopen(const char *p,int f)
{
#ifdef RNR_FINAL_FLOW
 if(final_enabled){int r=final_open_hook(AT_FDCWD,p,f);if(r!=-2)return r;}
#endif
 assert(!strcmp(p,"/") && f==(O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));return newfd(0);}
static int xopenat(int parent,const char *name,int flags,...)
{
#ifdef RNR_FINAL_FLOW
    if(final_enabled){int r=final_open_hook(parent,name,flags);if(r!=-2)return r;}
#endif
#ifdef RNR_FIXED_BIND_FLOW
    if(binds_enabled){int r=binds_open(parent,name,flags);if(r!=-2)return r;}
#endif
    if(flags&O_CREAT){va_list modes;va_start(modes,flags);assert(va_arg(modes,int)==(!strcmp(name,"launch.bin")?0444:0600));va_end(modes);}
#ifdef RNR_MEDIA_FLOW
    if(flow_enabled){int result=flow_open(parent,name,flags);if(result!=-2)return result;}
#endif
    assert(parent>=10 && handles[parent].live);int p=handles[parent].object,o=-1;
    if(p==0 && !strcmp(name,"etc"))o=1;
    if(p==1 && !strcmp(name,"rnr"))o=2;
    if(p==2 && !strcmp(name,"installation.bin"))o=3;
    if(p==2 && !strcmp(name,"task.bin"))o=4;
    if(p==0 && !strcmp(name,"proc"))o=5;
    if(p==0 && !strcmp(name,"run"))o=20;
    if(p==20 && !strcmp(name,"rnr-native-04000000000000000000000000000000")){
        assert(claimed);++work_opens;o=21;
    }
    if(p==21 && !strcmp(name,"journal.bin")){
        assert(claimed);
        if(flags&O_CREAT){assert(!journal_opens && flags==(O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC));++journal_opens;}
        else assert(flags==(O_WRONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC));
        return newfd(22);
    }
    if(p==5 && !strcmp(name,"100"))o=6;
    if(p==5 && !strcmp(name,"1"))o=7;
    if(p==6 && !strcmp(name,"task"))o=9;
    if((p==6 || p==7) && !strncmp(name,"ns/",3)){
        assert(task_scan_completed);++namespace_opens;
        for(int j=0;j<10;++j)if(!strcmp(name+3,view_names[j]))o=10+(j>=8?(j==8?1:3):j);
        assert(o>=10);
        assert(flags==(O_RDONLY|O_CLOEXEC));
        int fd=newfd(o);
        if(fd>=0 && ((fault==MANAGER_NAMESPACE && p==7)||(fault==CHILD_NAMESPACE && strstr(name,"children"))))handles[fd].object+=20;
        return fd;
    }
    if(phase4){
        if(p==0 && !strcmp(name,"var"))o=40;
        if(p==40 && !strcmp(name,"lib"))o=41;
        if(p==41 && !strcmp(name,"rnr-qualification"))o=42;
        if(p==42 && !strcmp(name,"runtime-0100000000000000000000000000000000000000000000000000000000000000"))o=43;
        if(p==43 && !strcmp(name,"root.squashfs"))o=44;
        if(p==43 && !strcmp(name,"root.verity"))o=45;
        if(p==0 && !strcmp(name,"dev"))o=46;
        if(p==46 && !strcmp(name,"loop-control"))o=47;
        if(p==46 && !strcmp(name,"loop3"))o=48;
        if(p==46 && !strcmp(name,"loop4"))o=49;
        if(phase5){
            if(p==46 && !strcmp(name,"mapper"))o=50;
            if(p==50 && !strcmp(name,"control"))o=51;
            if(p==46 && !strcmp(name,
#ifdef RNR_FIXED_BIND_FLOW
                bind_high_minor_setup?"dm-256":
#endif
                "dm-0")){o=52;dm_opened=1;}
        }
        if(phase6){
            if(p==21 && !strcmp(name,"root")){assert(root_created);o=mount_stage?54:53;}
            if(p==54 && !strcmp(name,"run"))o=mount_stage>=2?56:55;
            if(o>=53){assert(flags==(O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC));return newfd(o);}
        }
        if(o==44||o==45||o>=47){
            if(o==50){assert(flags==(O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));return newfd(o);}
            assert(flags==(O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC));return newfd(o);}
    }
    assert(o>=0);
    int want=O_RDONLY|O_CLOEXEC|O_NOFOLLOW|((o==3||o==4)?O_NONBLOCK:O_DIRECTORY|((o>=5&&o<40)?O_NONBLOCK:0));
    assert(flags==want);return newfd(o);
}
static int xstat(int fd,struct stat *s)
{
#ifdef RNR_FINAL_FLOW
    if(final_enabled){int r=final_stat_hook(fd,s);if(r!=-2)return r;}
#endif
#ifdef RNR_FIXED_BIND_FLOW
    if(binds_enabled){int r=binds_stat(fd,s);if(r!=-2)return r;}
#endif
#ifdef RNR_MEDIA_FLOW
    if(flow_enabled&&handles[fd].object>=60)return flow_stat(fd,s);
#endif
    assert(handles[fd].live);int o=handles[fd].object;
    if(phase2 && fault==FSTAT_ERROR && o>=5 && (!phase3||o==journal_errno_object)){errno=EIO;return -1;}
    memset(s,0,sizeof(*s));s->st_dev=isns(o)?3:o>=20?4:o>=5?2:1;s->st_ino=1000+o;
    s->st_mode=(o==3||o==4||o==8||isns(o))?S_IFREG|0444:o==22?S_IFREG|0600:o==21?S_IFDIR|0700:S_IFDIR|0755;
    s->st_size=o==3?128:o==22?written:66;s->st_nlink=1;
    if(isns(o) && fault==BAD_NS_MODE)s->st_mode=S_IFDIR|0555;
    if(o==8 && fault==PIDFD_MODE)s->st_mode=S_IFDIR|0700;
    if(o>=5 && o<8 && fault==PROC_OWNER)s->st_uid=1;
    if(phase2 && o==mutate_role && ++seen_calls>=mutate_after)++s->st_ino;
    if(phase4 && o>=40){
        s->st_dev=o>=46?5:1;s->st_mode=S_IFDIR|0755;
        if(o==44||o==45){s->st_dev=makedev(259,513);s->st_ino=UINT64_C(0x102030405060708)+(unsigned int)(o-44);s->st_mode=S_IFREG|0444;s->st_size=o==44?129*4096:3*4096;}
        if(o==47){s->st_mode=S_IFCHR|0600;s->st_rdev=makedev(10,237);}
        if(o==51){s->st_mode=S_IFCHR|0600;s->st_rdev=makedev(10,236);}
        if(o==52){s->st_mode=S_IFBLK|0660;s->st_gid=6;s->st_rdev=makedev(253,
#ifdef RNR_FIXED_BIND_FLOW
            bind_high_minor_setup?256:
#endif
            0);}
        if(o==48||o==49){s->st_mode=S_IFBLK|0660;s->st_gid=6;s->st_rdev=makedev(7,o-45);}
        if(runtime_fault==6 && o==44)s->st_size--;
    }
    if(phase6 && o>=53){
        s->st_dev=o==53||o==56?4:makedev(253,
#ifdef RNR_FIXED_BIND_FLOW
            bind_high_minor_setup?256:
#endif
            0);s->st_mode=S_IFDIR|(o==53?0700:0755);
        if(o==56)s->st_ino=1020;
        if(mount_fault==5 && o==54)s->st_dev=99;
    }
    if(phase3 && o==22){
        switch(journal_metadata_fault){
        case 1:s->st_nlink=2;break;
        case 2:s->st_mode=S_IFREG|0644;break;
        case 3:s->st_uid=1;break;
        case 4:s->st_gid=1;break;
        case 5:s->st_dev=9;break;
        case 8:if(written)s->st_size=255;break;
        }
    }
    return 0;
}
static int xstatx(int fd,const char *p,int f,unsigned int m,struct statx *s)
{
    assert(handles[fd].live && !*p && f==(AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW) && m==STATX_MNT_ID);
    int o=handles[fd].object;if(phase2 && fault==STATX_ERROR && o>=5 && (!phase3||o==journal_errno_object)){errno=EIO;return -1;}
    memset(s,0,sizeof(*s));s->stx_mask=(phase2 && fault==MISSING_MNT_ID && o>=5)?0:STATX_MNT_ID;
    s->stx_mnt_id=phase4&&o>=40?(o>=46?55:11):o>=20&&!isns(o)?44:o>=5?22:11;
    if(phase6 && o>=53)s->stx_mnt_id=o==53?44:o==56?77:66;
#ifdef RNR_MEDIA_FLOW
    if(flow_enabled&&o>=60)s->stx_mnt_id=flow_mount(fd);
#endif
#ifdef RNR_FIXED_BIND_FLOW
    if(binds_enabled){uint64_t id=binds_mount_id(fd);if(id)s->stx_mnt_id=id;}
#endif
#ifdef RNR_FINAL_FLOW
    if(final_enabled){uint64_t m=final_mount_hook(fd);if(m)s->stx_mnt_id=m;}
#endif
    if(fault==PROC_MOUNT && o==6)++s->stx_mnt_id;
    if(phase3 && o==22 && journal_metadata_fault==6)++s->stx_mnt_id;
    return 0;
}
static int xstatfs(int fd,struct statfs *s)
{
    assert(handles[fd].live);int o=handles[fd].object;
    if(phase2 && fault==STATFS_ERROR && o>=5 && (!phase3||o==journal_errno_object)){errno=EIO;return -1;}
    memset(s,0,sizeof(*s));s->f_type=isns(o)?0x6e736673:o>=20?0x1021994:o>=5?0x9fa0:0xef53;
    if(phase4 && o>=40)s->f_type=o>=46?0x1021994:0xef53;
    if(phase6 && o>=53)s->f_type=o==53||o==56?0x1021994:0x73717368;
#ifdef RNR_MEDIA_FLOW
    if(flow_enabled&&o>=60)s->f_type=flow_root_badfs(fd)?0:o==66||o==84||o==85?0x73717368:0x1021994;
#endif
#ifdef RNR_FIXED_BIND_FLOW
    if(binds_enabled){long fs=binds_filesystem(fd);if(fs)s->f_type=fs;}
#endif
#ifdef RNR_FINAL_FLOW
    if(final_enabled){long fs=final_fs_hook(fd);if(fs)s->f_type=fs;}
#endif
    if((fault==BAD_NS_FS && isns(o))||(fault==PROC_FS && o==5))s->f_type=0;
    if(phase3 && o==22 && journal_metadata_fault==7)s->f_type=0;
    return 0;
}
static int xfcntl(int fd,int cmd,...)
{
#ifdef RNR_FINAL_FLOW
    if(final_enabled){va_list args;va_start(args,cmd);int value=cmd==F_SETFD?va_arg(args,int):0;va_end(args);
        int r=final_fcntl_hook(fd,cmd,value);if(r!=-2)return r;}
#endif
    assert(handles[fd].live);
    if(phase4 && runtime_fault==7 && handles[fd].object==22 && cmd==F_GETFL)return O_RDWR|O_NONBLOCK;
#ifdef RNR_MEDIA_FLOW
    if(flow_enabled&&handles[fd].object>=60&&cmd==F_GETFL)return handles[fd].access|O_NONBLOCK;
#endif
    if(cmd==F_GETFL)return (handles[fd].object==22?O_WRONLY:O_RDONLY)|O_NONBLOCK;
    assert(cmd==F_GETFD);
    if(fault==FCNTL_ERROR){errno=EIO;return -1;}
    return fault==BAD_NS_FLAGS && isns(handles[fd].object)?0:FD_CLOEXEC;
}
static int xioctl(int fd,unsigned long cmd,...)
{
    assert(handles[fd].live);int o=handles[fd].object;
#ifdef RNR_MEDIA_FLOW
    if(flow_enabled){va_list args;va_start(args,cmd);int result=flow_ioctl(fd,cmd,args);va_end(args);
        if(result!=-2)return result;}
#endif
    if(phase5 && o==51){
        va_list args;va_start(args,cmd);struct dm_ioctl *d=va_arg(args,struct dm_ioctl *);va_end(args);
        assert(d->version[0]==4 && d->version[1]==0 && d->version[2]==0 && d->data_start==312 && d->data_size==4096);
        ++dm_calls;d->version[1]=50;
        if(cmd==DM_VERSION){if(dm_fault==1)d->version[1]=48;return 0;}
        if(cmd==DM_DEV_CREATE){
            assert(!strcmp(d->name,"rnr-r-04000000000000000000000000000000"));
            assert(d->flags==0 && append_syncs==9);++dm_create_calls;
            if(dm_fault==2){errno=EEXIST;return -1;}
        }else{assert(!d->name[0] && !d->dev);}
        assert(!strcmp(d->uuid,"rnr-native-04000000000000000000000000000000-runtime"));
        if(cmd==DM_TABLE_LOAD){assert(d->flags==1 && d->target_count==1 && append_syncs==11);++dm_load_calls;}
        if(cmd==DM_DEV_SUSPEND){assert(!d->flags && append_syncs==13);++dm_resume_calls;}
        unsigned int request=d->flags;
        if(dm_fault==7 && cmd==DM_TABLE_LOAD){errno=EFAULT;return -1;}
        if(dm_fault==8 && cmd==DM_DEV_CREATE)clock_fail=clock_calls+1;
        int openers=0;for(int j=0;j<RNR_TEST_HANDLES;++j)if(handles[j].live&&handles[j].object==52)++openers;
        d->data_size=305;d->dev=
#ifdef RNR_FIXED_BIND_FLOW
            bind_high_minor_setup?0x10fd00:
#endif
            0xfd00;d->open_count=openers+(phase6&&mount_stage?1:0);d->target_count=0;d->event_nr=0;
        strcpy(d->name,"rnr-r-04000000000000000000000000000000");
        d->flags=cmd==DM_DEV_CREATE?0:cmd==DM_TABLE_LOAD?64:33;
        if(cmd==DM_TABLE_STATUS){
            d->flags=request==4112?4177:request==16?49:33;d->target_count=1;
            struct dm_target_spec *t=(void *)((unsigned char *)d+312);memset(t,0,40);t->length=1032;strcpy(t->target_type,"verity");
            char *text=(char *)(t+1);
            if(request&16)strcpy(text,"1 7:3 7:4 4096 4096 129 0 sha256 0100000000000000000000000000000000000000000000000000000000000000 0200000000000000000000000000000000000000000000000000000000000000");
            else strcpy(text,"V");
            d->data_size=352+(unsigned int)strlen(text)+1;t->next=(40+(unsigned int)strlen(text)+1+7)&~7U;
        }
        if(cmd==DM_DEV_SUSPEND||cmd==DM_DEV_STATUS)d->target_count=1;
        if(dm_fault==3)d->data_size=312;
        if(dm_fault==4)d->flags|=DM_SUSPEND_FLAG;
        if(dm_fault==5)d->uuid[0]='x';
        if(dm_fault==6 && dm_resume_calls && cmd!=DM_DEV_SUSPEND)d->event_nr=1;
        if(dm_fault>=9 && dm_fault<=13 && dm_resume_calls)d->event_nr=7;
        if(cmd==DM_DEV_SUSPEND){
            if(dm_fault==9)d->uuid[0]='x';
            if(dm_fault==10)d->data_size=312;
            if(dm_fault==11)d->version[1]=48;
            if(dm_fault==13)d->flags=8225;
        }
        return 0;
    }
    if(phase5 && o==52){
        va_list args;va_start(args,cmd);
        if(cmd==BLKROGET){int *v=va_arg(args,int *);*v=1;}
        else {assert(cmd==BLKGETSIZE64);uint64_t *v=va_arg(args,uint64_t *);*v=129*4096;}
        va_end(args);return 0;
    }
    if(phase4 && o>=47){
        va_list args;va_start(args,cmd);
        if(cmd==LOOP_CTL_GET_FREE){
            assert(o==47 && append_syncs==1+free_calls*4 && append_writes==append_syncs);
            ++free_calls;va_end(args);
            if(runtime_fault==1){errno=EINTR;return -1;}
            if(effect_clock_after)clock_fail=clock_calls+1;
            return free_calls+2;
        }
        assert(o==48||o==49);int i=o-48;
        if(cmd==LOOP_CONFIGURE){
            const struct loop_config *c=va_arg(args,const struct loop_config *);
            assert(append_syncs==3+i*4 && append_writes==append_syncs && !loop_bound[i]);
            assert(handles[c->fd].object==44+i && c->block_size==4096 && c->info.lo_flags==1);
            assert(c->info.lo_offset==0 && c->info.lo_sizelimit==(uint64_t)(i?3:129)*4096);
            ++configure_calls;
            if(runtime_fault==2){va_end(args);errno=EBUSY;return -1;}
            configured[i]=*c;loop_bound[i]=1;va_end(args);return 0;
        }
        if(cmd==LOOP_GET_STATUS64){
            struct loop_info64 *v=va_arg(args,struct loop_info64 *);va_end(args);
            if(!loop_bound[i]){errno=ENXIO;return -1;}
            *v=configured[i].info;v->lo_device=0x210301;v->lo_inode=UINT64_C(0x102030405060708)+(unsigned int)i;v->lo_number=3+i;
            if(runtime_fault==3)v->lo_inode++;
            if(runtime_fault==4)v->lo_flags|=LO_FLAGS_AUTOCLEAR;
            return 0;
        }
        if(cmd==BLKROGET){int *v=va_arg(args,int *);*v=runtime_fault==5?0:1;va_end(args);return 0;}
        if(cmd==BLKGETSIZE64){uint64_t *v=va_arg(args,uint64_t *);*v=(uint64_t)(i?3:129)*4096;va_end(args);return 0;}
        assert(0);
    }
    assert(cmd==NS_GET_NSTYPE);
    if(fault==IOCTL_ERROR){errno=EIO;return -1;}
    int index=(o>=30?o-30:o-10);assert(index>=0 && index<8);++ns_reads[fd];
    if(fault==BAD_NS_TYPE)seen_calls=1;
    return fault==BAD_NS_TYPE?0:view_kinds[index];
}
static int xpoll(struct pollfd *p,nfds_t n,int timeout)
{
    assert(n==1 && timeout==0 && handles[p->fd].live && handles[p->fd].object==8 && p->events==POLLIN);
    if(fault==POLL_ERROR){errno=EINTR;return -1;}
    p->revents=(short)events;return events?1:0;
}
static size_t record(unsigned char *p,const char *name,int type)
{
    size_t len=(19+strlen(name)+1+7)&~7UL;memset(p,0,len);
    put(p,1,8);put(p+8,1,8);put(p+16,len,2);p[18]=(unsigned char)type;
    memcpy(p+19,name,strlen(name));return len;
}
static long xsyscall(long number,...)
{
#ifdef RNR_FINAL_FLOW
    if(final_enabled){va_list args;va_start(args,number);long r=final_syscall_hook(number,args);va_end(args);if(r!=-2)return r;}
#endif
    va_list args;va_start(args,number);
#ifdef RNR_MEDIA_FLOW
    if(flow_enabled&&(number==SYS_openat2||number==SYS_pidfd_open||number==SYS_getdents64)){
        va_list copy;va_copy(copy,args);long result=flow_syscall(number,copy);va_end(copy);
        if(result!=-2){va_end(args);return result;}
    }
#endif
    if(number==SYS_gettid){va_end(args);return foreign?101:100;}
    if(number==SYS_pidfd_open){
        assert(va_arg(args,int)==1 && va_arg(args,int)==0);va_end(args);
        if(fault==PIDFD_ERROR){errno=ESRCH;return -1;}return newfd(8);
    }
    assert(number==SYS_getdents64);int fd=va_arg(args,int);unsigned char *p=va_arg(args,unsigned char *);
    assert(va_arg(args,size_t)==4096 && handles[fd].live);va_end(args);
    if(phase6 && handles[fd].object==53){
        if(handles[fd].reads++)return 0;
        size_t len=record(p,".",4);len+=record(p+len,"..",4);
        if(mount_fault==2)len+=record(p+len,"extra",8);
        return (long)len;
    }
    assert(handles[fd].object==9);
    if(fault==GETDENTS_ERROR){errno=EINTR;return -1;}
    if(handles[fd].reads++ && task_fault!=6){task_scan_completed=1;return 0;}
    size_t len=record(p,".",4);len+=record(p+len,"..",4);
    len+=record(p+len,task_fault==1?"0100":task_fault==2?"101":"100",task_fault==3?8:4);
    if(task_fault==4)len+=record(p+len,"100",4);
    if(task_fault==10 && task_round==1)len+=record(p+len,"101",4);
    if(task_fault==5)p[16]=0;
    if(task_fault==7)put(p+8,0,8);
    if(task_fault==8)memset(p,0,8);
    if(task_fault==9)memset(p+19,'x',5);
    return (long)len;
}
static ssize_t xpread(int fd,void *p,size_t n,off_t offset)
{
#ifdef RNR_MEDIA_FLOW
    if(flow_enabled&&handles[fd].object>=60)return flow_pread(fd,p,n,offset);
#endif
    assert(handles[fd].live);int o=handles[fd].object;assert(o==3||o==4);
    size_t len=o==3?128:66;if((size_t)offset==len)return 0;
    assert(offset==0 && n==len);memcpy(p,o==3?install:task,n);return (ssize_t)n;
}
static int xclose(int fd)
{
#ifdef RNR_FINAL_FLOW
    if(final_enabled){int r=final_close_hook(fd);if(r!=-2)return r;}
#endif
    assert(fd>=10 && fd<RNR_TEST_HANDLES && handles[fd].live && !handles[fd].closed);
    handles[fd].live=0;++handles[fd].closed;
#ifdef RNR_FIXED_BIND_FLOW
    if(binds_enabled&&binds_close(fd)){errno=EINTR;return -1;}
#endif
#ifdef RNR_MEDIA_FLOW
    if(flow_enabled&&flow_root_close(fd)){errno=EINTR;return -1;}
    if(flow_enabled&&flow_close_errors())seen_calls=1;
#endif
    if(close_error==2 && !phase3 && input_owner.view_count==22)seen_calls=1;
    if(close_error==6 && phase6 && input_owner.runtime_count==15 && input_owner.journal_sequence==22)seen_calls=1;
    if(mount_fault==12 && phase6 && handles[fd].object==53 && mount_stage==1){errno=EINTR;return -1;}
    if(close_error==5 && phase5 && input_owner.runtime_count==13 && input_owner.journal_sequence==14)seen_calls=1;
    if(close_error==4 && phase4 && input_owner.runtime_count==10 && input_owner.journal_sequence==8)seen_calls=1;
    if(close_error==3 && phase3 && journal_opens && sync_calls==3)seen_calls=1;
    if(close_error && phase2 && seen_calls){errno=EINTR;return -1;}return 0;
}
static mode_t xumask(mode_t mode)
{assert(mode==077 && phase3);++umask_calls;return 022;}
static int xmkdir(int fd,const char *path,mode_t mode)
{
    assert(phase3 && handles[fd].live && mode==0700);
#ifdef RNR_MEDIA_FLOW
    if(flow_enabled){int r=flow_root_mkdir(fd,path);if(r!=-2)return r;}
    if(flow_enabled&&!strcmp(path,"launch-source")){assert(handles[fd].object==21);return 0;}
#endif
    if(phase6){assert(handles[fd].object==21 && !strcmp(path,"root") && append_syncs==15);++root_created;
        if(mount_fault==1){errno=EEXIST;return -1;}return 0;}
    assert(handles[fd].object==20);
    assert(!strcmp(path,"rnr-native-04000000000000000000000000000000") && umask_calls==1);
    ++mkdir_calls;assert(mkdir_calls==1);
    if(claim_reenter){struct rnr_stage0_preparer_error e;int before=total_closed();
        assert(rnr_stage0_abandon_preparation_inputs(&e)==-1);assert(total_closed()==before);}
    if(mkdir_error){errno=mkdir_error;return -1;}claimed=1;
    if(claim_clock_after)clock_fail=clock_calls+1;
    return 0;
}
static ssize_t xpwrite(int fd,const void *data,size_t n,off_t offset)
{
#ifdef RNR_MEDIA_FLOW
    if(flow_enabled&&handles[fd].object>=60)return flow_pwrite(fd,data,n,offset);
#endif
    assert(handles[fd].live && handles[fd].object==22 && n==256);
#ifdef RNR_FIXED_BIND_FLOW
    if(binds_enabled&&offset==(off_t)bind_journal_fail*256){
        if(bind_journal_kind==1)return 255;
        if(bind_journal_kind==2){errno=EINTR;return -1;}
        if(bind_journal_kind==4)clock_fail=clock_calls+1;
    }
#endif
    if(phase4){
        assert(offset==written && offset>=256 && offset<=65536);++append_writes;
        if(write_fault==2){errno=EINTR;return -1;}
        memcpy(append_bytes+offset-256,data,n);int count=write_fault==1?255:256;written+=count;return count;
    }
    assert(offset==0 && !write_calls);++write_calls;if(write_fault==2){errno=EINTR;return -1;}
    memcpy(journal_bytes,data,n);written=write_fault==1?255:256;return written;
}
static int xsync(int fd)
{
    assert(handles[fd].live);
#ifdef RNR_FIXED_BIND_FLOW
    if(binds_enabled&&bind_journal_kind==3&&written==(bind_journal_fail+1)*256){errno=EIO;return -1;}
#endif
#ifdef RNR_MEDIA_FLOW
    if(flow_enabled){int r=flow_root_sync(fd);if(r!=-2)return r;}
    if(flow_enabled&&handles[fd].object>=60)return 0;
#endif
    if(phase6 && handles[fd].object==21)return 0;
    if(phase4){assert(handles[fd].object==22);++append_syncs;if(sync_fault){errno=EIO;return -1;}return 0;}
    assert(written==256 && sync_calls<3);
    const int order[]={22,21,20};assert(handles[fd].object==order[sync_calls]);++sync_calls;
    if(sync_calls==sync_fault){errno=EIO;return -1;}return 0;
}
static int xprepare(struct rnr_stage0_launch_error *e)
{assert(!calls);++prepare_calls;memset(e,0,sizeof(*e));return 0;}
static int xadmit(struct rnr_stage0_admission_error *e)
{assert(prepare_calls==1 && !calls);++admit_calls;memset(e,0,sizeof(*e));return 0;}
static int xbind(int64_t cutoff,struct rnr_stage0_launch_error *e)
{assert(!phase2 && cutoff==123456789 && prepare_calls==1 && calls==5);memset(e,0,sizeof(*e));return 0;}
static int xcheck(struct rnr_stage0_launch_error *e)
{
    if(!e){fenced=1;return -1;}memset(e,0,sizeof(*e));++clock_calls;
    if(fenced || clock_calls==clock_fail){e->code=RNR_STAGE0_LAUNCH_CLOCK;return -1;}
#ifdef RNR_FIXED_CLOCK_FLOW
    if(nested_clock_enabled)return nested_clock_check(e);
#endif
    return 0;
}
static void inputs(void)
{struct rnr_stage0_preparer_error e;assert(rnr_stage0_prepare_inputs(&e)==0);phase2=1;}
static void drained(void)
{for(int j=0;j<RNR_TEST_HANDLES;++j){if(handles[j].live||handles[j].closed>1)fprintf(stderr,"undrained fd%d object%d phase4%d fault%d write%d sync%d\n",j,handles[j].object,phase4,runtime_fault,write_fault,sync_fault);assert(!handles[j].live && handles[j].closed<=1);}}
int main(void)
{
    struct rnr_stage0_preparer_error e;reset();inputs();int first=calls,firstclock=clock_calls;
    assert(rnr_stage0_prepare_host_view(&e)==0);int end=calls,endclock=clock_calls;
    assert(input_owner.view_count==22 && prepare_calls==1 && admit_calls==1);
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    for(int j=first+1;j<=end;++j){
        reset();inputs();fail_at=j;assert(rnr_stage0_prepare_host_view(&e)==-1);drained();
        reset();inputs();abandon_at=j;assert(rnr_stage0_prepare_host_view(&e)==-1);drained();assert(!abandon_closed);
    }
    for(int j=firstclock+1;j<=endclock;++j){
        reset();inputs();clock_fail=j;assert(rnr_stage0_prepare_host_view(&e)==-1);drained();
    }
    for(int j=1;j<=IOCTL_ERROR;++j){
        reset();inputs();fault=j;assert(rnr_stage0_prepare_host_view(&e)==-1);drained();
    }
    const int ev[]={POLLIN,POLLHUP,POLLERR,POLLNVAL};
    for(unsigned int j=0;j<sizeof(ev)/sizeof(ev[0]);++j){
        reset();inputs();events=ev[j];assert(rnr_stage0_prepare_host_view(&e)==-1 && e.code==RNR_STAGE0_PREPARER_PID1);drained();
    }
    for(int j=1;j<=10;++j){reset();inputs();task_fault=j;assert(rnr_stage0_prepare_host_view(&e)==-1);drained();assert(namespace_opens==0);}
    reset();inputs();close_error=2;
    assert(rnr_stage0_prepare_host_view(&e)==-1 && e.code==RNR_STAGE0_PREPARER_CLEANUP && e.cleanup_count==28);drained();
    for(int o=5;o<=17;++o){
        if(o==9)continue;
        reset();inputs();mutate_role=o;mutate_after=2;
        assert(rnr_stage0_prepare_host_view(&e)==-1);drained();
    }
    reset();inputs();fault=BAD_NS_TYPE;close_error=1;
    assert(rnr_stage0_prepare_host_view(&e)==-1 && e.code==RNR_STAGE0_PREPARER_VIEW && e.cleanup_count==10);drained();
    int count=total_closed();handles[10].live=1;
    assert(rnr_stage0_abandon_preparation_inputs(&e)==-1 && total_closed()==count && handles[10].live);
    reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);count=total_closed();
    assert(rnr_stage0_prepare_host_view(&e)==-1 && total_closed()==count);
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    reset();inputs();foreign=1;count=total_closed();
    assert(rnr_stage0_prepare_host_view(&e)==-1 && total_closed()==count);foreign=0;
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    reset();inputs();assert(rnr_stage0_prepare_host_view(NULL)==-1);
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    /* Full same-owner integration: frozen inputs -> original view -> claim. */
    reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;
    int first_journal_open=calls,first_journal_clock=clock_calls;
    assert(rnr_stage0_claim_preparation(&e)==0 && mkdir_calls==1 && write_calls==1 && sync_calls==3);
    int last_journal_open=calls,last_journal_clock=clock_calls;
    assert(e.claim_disposition==RNR_STAGE0_CLAIM_CREATED && e.mkdir_errno==0);
    unsigned char expected[256]={0};memcpy(expected,"RNRJ0001",8);expected[8]=1;expected[16]=4;
    expected[32]=1;expected[64]=2;expected[96]=3;
    put(expected+128,123456789,8);put(expected+136,100,8);
    put(expected+144,4,8);put(expected+152,1021,8);put(expected+160,44,8);
    put(expected+168,4,8);put(expected+176,1020,8);put(expected+184,44,8);
    assert(!memcmp(journal_bytes,expected,256));
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    reset();inputs();phase3=1;assert(rnr_stage0_claim_preparation(&e)==-1 && !mkdir_calls);
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    for(int j=first_journal_open+1;j<=last_journal_open;++j){
        reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;fail_at=j;
        assert(rnr_stage0_claim_preparation(&e)==-1);drained();
        assert(e.claim_disposition==(mkdir_calls?RNR_STAGE0_CLAIM_CREATED:RNR_STAGE0_CLAIM_NOT_ATTEMPTED));
        reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;abandon_at=j;
        assert(rnr_stage0_claim_preparation(&e)==-1);drained();assert(!abandon_closed);
    }
    for(int j=first_journal_clock+1;j<=last_journal_clock;++j){
        reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;clock_fail=j;
        assert(rnr_stage0_claim_preparation(&e)==-1);drained();
        assert(e.claim_disposition==(mkdir_calls?RNR_STAGE0_CLAIM_CREATED:RNR_STAGE0_CLAIM_NOT_ATTEMPTED));
    }
    for(int o=20;o<=22;++o){
        reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;mutate_role=o;mutate_after=o==22?2:3;
        assert(rnr_stage0_claim_preparation(&e)==-1);drained();
        if(o==20)assert(!mkdir_calls);
        for(int kind=0;kind<3;++kind){
            reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;journal_errno_object=o;
            fault=kind==0?FSTAT_ERROR:kind==1?STATX_ERROR:STATFS_ERROR;
            assert(rnr_stage0_claim_preparation(&e)==-1 && e.system_errno==EIO);drained();
        }
    }
    reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;
    mutate_role=10;mutate_after=1;
    assert(rnr_stage0_claim_preparation(&e)==-1 && !mkdir_calls);drained();
    const int mkdir_errors[]={EEXIST,EINTR,EIO};
    for(unsigned int j=0;j<sizeof(mkdir_errors)/sizeof(mkdir_errors[0]);++j){
        reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;mkdir_error=mkdir_errors[j];
        assert(rnr_stage0_claim_preparation(&e)==-1 && mkdir_calls==1 && !work_opens && !write_calls);
        assert(e.mkdir_errno==mkdir_errors[j] && e.claim_disposition==(j==0?RNR_STAGE0_CLAIM_COLLISION:RNR_STAGE0_CLAIM_UNKNOWN));drained();
    }
    for(int j=1;j<=2;++j){
        reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;write_fault=j;
        assert(rnr_stage0_claim_preparation(&e)==-1 && write_calls==1 && !sync_calls && e.claim_disposition==RNR_STAGE0_CLAIM_CREATED);drained();
    }
    for(int j=1;j<=3;++j){
        reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;sync_fault=j;
        assert(rnr_stage0_claim_preparation(&e)==-1 && sync_calls==j && e.claim_disposition==RNR_STAGE0_CLAIM_CREATED);drained();
    }
    reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;claim_clock_after=1;
    assert(rnr_stage0_claim_preparation(&e)==-1 && !work_opens && e.claim_disposition==RNR_STAGE0_CLAIM_CREATED);drained();
    reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;claim_reenter=1;
    assert(rnr_stage0_claim_preparation(&e)==-1 && !work_opens && e.claim_disposition==RNR_STAGE0_CLAIM_CREATED);drained();
    for(int j=1;j<=8;++j){
        reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;journal_metadata_fault=j;
        assert(rnr_stage0_claim_preparation(&e)==-1 && e.claim_disposition==RNR_STAGE0_CLAIM_CREATED);drained();
        assert(j==8?write_calls==1:write_calls==0);
    }
    reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;close_error=3;
    assert(rnr_stage0_claim_preparation(&e)==-1 && e.cleanup_count==31 && !e.cleanup_overflow);drained();
    count=total_closed();handles[10].live=1;
    assert(rnr_stage0_abandon_preparation_inputs(&e)==-1 && total_closed()==count && handles[10].live);
    runtime_loop_tests();
    mapping_tests();
    mount_tests();
    return 0;
}

/* Catches omission of durable intent before GET_FREE, collision adoption,
 * lost syscall result on expiry, and sequence reuse after partial append. */
static void runtime_loop_tests(void)
{
    struct rnr_stage0_preparer_error e;
    reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;
    assert(rnr_stage0_claim_preparation(&e)==0);
    phase4=1;int first_open=calls,first_clock=clock_calls;
    assert(rnr_stage0_prepare_runtime_loops(&e)==0);
    int last_open=calls,last_clock=clock_calls;
    assert(input_owner.runtime_count==10);
    assert(input_owner.journal_sequence==8 && free_calls==2 && configure_calls==2);
    /* Independent complete first prospective request vector. */
    unsigned char expected[256]={0};memcpy(expected,"RNRO0001",8);expected[8]=1;expected[12]=1;
    expected[16]=1;expected[24]=4;expected[40]=1;expected[44]=1;
    put(expected+64,0x210301,8);put(expected+72,UINT64_C(0x102030405060708),8);put(expected+80,129*4096,8);put(expected+88,11,8);
    expected[108]=1;memcpy(expected+112,"rnr-04000000000000000000000000000000-rd",39);
    put(expected+184,129*4096,8);assert(!memcmp(append_bytes,expected,256));
    expected[16]=2;expected[44]=2;expected[48]=3;expected[96]=3;
    assert(!memcmp(append_bytes+256,expected,256));
    expected[12]=2;expected[16]=3;expected[44]=1;expected[48]=0;expected[100]=7;expected[104]=3;
    assert(!memcmp(append_bytes+512,expected,256));
    expected[16]=4;expected[44]=2;assert(!memcmp(append_bytes+768,expected,256));
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    for(int j=first_open+1;j<=last_open;++j){
        reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;
        assert(rnr_stage0_claim_preparation(&e)==0);phase4=1;fail_at=j;
        assert(rnr_stage0_prepare_runtime_loops(&e)==-1);drained();
        reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;
        assert(rnr_stage0_claim_preparation(&e)==0);phase4=1;abandon_at=j;
        assert(rnr_stage0_prepare_runtime_loops(&e)==-1 && !abandon_closed);drained();
    }
    for(int j=first_clock+1;j<=last_clock;++j){
        reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;
        assert(rnr_stage0_claim_preparation(&e)==0);phase4=1;clock_fail=j;
        assert(rnr_stage0_prepare_runtime_loops(&e)==-1);drained();
    }
    reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;
    assert(rnr_stage0_claim_preparation(&e)==0);phase4=1;close_error=4;
    assert(rnr_stage0_prepare_runtime_loops(&e)==-1 && e.cleanup_count==41 && !e.cleanup_overflow);drained();
    int count=total_closed();handles[10].live=1;
    assert(rnr_stage0_abandon_preparation_inputs(&e)==-1 && handles[10].live && total_closed()==count);
    for(int problem=1;problem<=10;++problem){
        reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;
        assert(rnr_stage0_claim_preparation(&e)==0);phase4=1;
        if(problem<=6)runtime_fault=problem;
        if(problem==7)write_fault=1;
        if(problem==8)write_fault=2;
        if(problem==9)sync_fault=1;
        if(problem==10)runtime_fault=7;
        assert(rnr_stage0_prepare_runtime_loops(&e)==-1);drained();
        assert(free_calls<=1 && configure_calls<=1);
        if(problem>=6)assert(!free_calls && !configure_calls);
    }
    reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;
    assert(rnr_stage0_claim_preparation(&e)==0);phase4=1;effect_clock_after=1;
    assert(rnr_stage0_prepare_runtime_loops(&e)==-1 && free_calls==1 && !configure_calls);
    assert(input_owner.operation_entered && input_owner.operation_returned && input_owner.operation_result==3);
    drained();
}

static void mapping_tests(void)
{
    struct rnr_stage0_preparer_error e;
    int first_open=0,last_open=0,first_clock=0,last_clock=0;
    for(int issue=0;issue<=13;++issue){
        reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;
        assert(rnr_stage0_claim_preparation(&e)==0);phase4=1;
        assert(rnr_stage0_prepare_runtime_loops(&e)==0);phase5=1;dm_fault=issue;
        if(!issue || issue==12 || issue==13){
            if(!issue){first_open=calls;first_clock=clock_calls;}
            assert(rnr_stage0_prepare_runtime_mapping(&e)==0);
            if(!issue){last_open=calls;last_clock=clock_calls;}
            assert(input_owner.runtime_count==13 && input_owner.journal_sequence==14);
            assert(input_owner.runtime_mapping.dm_event==(issue?7U:0U));
            assert(dm_create_calls==1 && dm_load_calls==1 && dm_resume_calls==1);
            unsigned char expected[256]={0};memcpy(expected,"RNRO0001",8);
            expected[8]=1;expected[12]=3;expected[16]=9;expected[24]=4;expected[40]=5;expected[44]=1;
            memcpy(expected+64,"rnr-r-04000000000000000000000000000000",39);
            memcpy(expected+112,"rnr-native-04000000000000000000000000000000-runtime",52);
            assert(!memcmp(append_bytes+2048,expected,256));
            expected[16]=10;expected[44]=2;put(expected+176,0xfd00,8);
            assert(!memcmp(append_bytes+2304,expected,256));
            memset(expected+64,0,192);expected[12]=4;expected[16]=11;expected[44]=1;
            put(expected+64,0x703,8);put(expected+72,0x704,8);put(expected+80,0xfd00,8);
            put(expected+88,129,8);put(expected+96,3,8);expected[104]=1;expected[136]=2;
            put(expected+168,1032,8);expected[176]=1;
            assert(!memcmp(append_bytes+2560,expected,256));
            expected[12]=5;expected[16]=13;expected[176]=0;
            assert(!memcmp(append_bytes+3072,expected,256));
            assert(rnr_stage0_abandon_preparation_inputs(&e)==0);
        }else {assert(rnr_stage0_prepare_runtime_mapping(&e)==-1);if(issue==1)assert(!dm_create_calls);
            if(issue>=9 && issue<=11){struct dm_ioctl raw;memcpy(&raw,input_owner.runtime_mapping.dm_response,312);
                assert(dm_calls==5 && dm_resume_calls==1 && input_owner.runtime_mapping.dm_event==0 && raw.event_nr==7);}
            if(issue==7)assert(!dm_resume_calls && input_owner.runtime_mapping.dm_errno==EFAULT && input_owner.operation_returned);
            if(issue==8){struct dm_ioctl raw;memcpy(&raw,input_owner.runtime_mapping.dm_response,312);
                assert(raw.dev==0xfd00 && input_owner.operation_returned && input_owner.operation_result==0 && !dm_load_calls);}
        }
        drained();
    }
    for(int j=first_open+1;j<=last_open;++j){
        reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;
        assert(rnr_stage0_claim_preparation(&e)==0);phase4=1;assert(rnr_stage0_prepare_runtime_loops(&e)==0);
        phase5=1;fail_at=j;assert(rnr_stage0_prepare_runtime_mapping(&e)==-1);drained();
        reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;
        assert(rnr_stage0_claim_preparation(&e)==0);phase4=1;assert(rnr_stage0_prepare_runtime_loops(&e)==0);
        phase5=1;abandon_at=j;assert(rnr_stage0_prepare_runtime_mapping(&e)==-1 && !abandon_closed);drained();
    }
    for(int j=first_clock+1;j<=last_clock;++j){
        reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;
        assert(rnr_stage0_claim_preparation(&e)==0);phase4=1;assert(rnr_stage0_prepare_runtime_loops(&e)==0);
        phase5=1;clock_fail=j;assert(rnr_stage0_prepare_runtime_mapping(&e)==-1);drained();
    }
    reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;
    assert(rnr_stage0_claim_preparation(&e)==0);phase4=1;assert(rnr_stage0_prepare_runtime_loops(&e)==0);
    phase5=1;close_error=5;assert(rnr_stage0_prepare_runtime_mapping(&e)==-1 && e.cleanup_count==44 && !e.cleanup_overflow);drained();
}

static int xvfs(int fd,struct statvfs *s)
{
#ifdef RNR_FINAL_FLOW
    if(final_enabled){int r=final_vfs_hook(fd,s);if(r!=-2)return r;}
#endif
#ifdef RNR_FIXED_BIND_FLOW
    if(binds_enabled)return binds_vfs(fd,s);
#endif
    assert(phase6 && handles[fd].live);int o=handles[fd].object;memset(s,0,sizeof(*s));
#ifdef RNR_MEDIA_FLOW
    if(flow_enabled){int r=flow_root_vfs(fd,s);if(r!=-2)return r;}
#endif
    assert(o==54||o==55||o==56||o==20);s->f_flag=o==54||o==55?ST_RDONLY|ST_NOSUID|ST_NODEV:
        o==56&&mount_stage==3?ST_NOSUID|ST_NODEV|ST_NOEXEC:0;
    if(mount_fault==6 && o==54)s->f_flag|=ST_NOEXEC;
    if(mount_fault==7 && o==56)s->f_flag|=ST_RDONLY;
    return 0;
}
static int xmount(const char *source,const char *target,const char *fs,unsigned long flags,const void *data)
{
#ifdef RNR_FIXED_BIND_FLOW
    if(binds_enabled)return binds_effect(source,target,fs,flags,data);
#endif
#ifdef RNR_MEDIA_FLOW
    if(flow_enabled){int r=flow_root_mount(source,target,fs,flags,data);if(r!=-2)return r;}
#endif
    assert(phase6 && !data);++mount_calls;assert(mount_calls<=3);
    assert(!strcmp(target,mount_calls==1?"/run/rnr-native-04000000000000000000000000000000/root":
        "/run/rnr-native-04000000000000000000000000000000/root/run"));
    assert(append_syncs==15+2*mount_calls);
    if(mount_calls==1)assert(!strcmp(source,
#ifdef RNR_FIXED_BIND_FLOW
        bind_high_minor_setup?"/dev/dm-256":
#endif
        "/dev/dm-0") && !strcmp(fs,"squashfs") && flags==7);
    else assert(!strcmp(source,"/run") && !fs && flags==(mount_calls==2?4096:4142));
    if(mount_fault==3||(mount_fault==8&&mount_calls==2)||(mount_fault==9&&mount_calls==3)){errno=EIO;return -1;}
    mount_stage=mount_calls;
    if(mount_fault==4||(mount_fault==10&&mount_calls==2)||(mount_fault==11&&mount_calls==3))clock_fail=clock_calls+1;
    return 0;
}
static void mount_tests(void)
{
    struct rnr_stage0_preparer_error e;
    int first_open=0,last_open=0,first_clock=0,last_clock=0;
    for(int issue=0;issue<=12;++issue){
        reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;
        assert(rnr_stage0_claim_preparation(&e)==0);phase4=1;
        assert(rnr_stage0_prepare_runtime_loops(&e)==0);phase5=1;
        assert(rnr_stage0_prepare_runtime_mapping(&e)==0);phase6=1;mount_fault=issue;
        if(!issue){first_open=calls;first_clock=clock_calls;}
        if(!issue){assert(rnr_stage0_prepare_runtime_mount(&e)==0);
            last_open=calls;last_clock=clock_calls;
            assert(mount_calls==3 && root_created==1 && input_owner.runtime_count==15 && input_owner.journal_sequence==22);
            unsigned char expected[256]={0};memcpy(expected,"RNRO0001",8);
            expected[8]=1;expected[12]=11;expected[16]=15;expected[24]=4;expected[40]=7;expected[44]=1;
            put(expected+64,4,8);put(expected+72,1021,8);put(expected+80,44,8);memcpy(expected+88,"root",4);put(expected+160,0700,4);
            assert(!memcmp(append_bytes+14*256,expected,256));
            expected[16]=16;expected[44]=2;put(expected+136,4,8);put(expected+144,1053,8);put(expected+152,44,8);
            assert(!memcmp(append_bytes+15*256,expected,256));
            memset(expected+64,0,192);expected[12]=6;expected[16]=17;expected[44]=1;
            put(expected+64,5,8);put(expected+72,1052,8);put(expected+80,55,8);put(expected+88,makedev(253,0),8);
            put(expected+96,4,8);put(expected+104,1053,8);put(expected+112,44,8);put(expected+128,7,8);
            memcpy(expected+136,"squashfs",8);put(expected+152,0xfd00,8);
            assert(!memcmp(append_bytes+16*256,expected,256));
            expected[16]=18;expected[44]=2;put(expected+120,66,8);assert(!memcmp(append_bytes+17*256,expected,256));
            memset(expected+64,0,192);expected[12]=7;expected[16]=19;expected[40]=10;expected[44]=1;
            put(expected+64,4,8);put(expected+72,1020,8);put(expected+80,44,8);
            put(expected+96,makedev(253,0),8);put(expected+104,1055,8);put(expected+112,66,8);put(expected+128,4096,8);
            assert(!memcmp(append_bytes+18*256,expected,256));
            expected[16]=20;expected[44]=2;put(expected+120,77,8);assert(!memcmp(append_bytes+19*256,expected,256));
            expected[12]=8;expected[16]=21;expected[44]=1;put(expected+96,4,8);put(expected+104,1020,8);
            put(expected+112,77,8);put(expected+120,0,8);put(expected+128,4142,8);
            assert(!memcmp(append_bytes+20*256,expected,256));
            expected[16]=22;expected[44]=2;put(expected+120,77,8);assert(!memcmp(append_bytes+21*256,expected,256));
            assert(rnr_stage0_abandon_preparation_inputs(&e)==0);
        }else{assert(rnr_stage0_prepare_runtime_mount(&e)==-1);
            if(issue==1||issue==2)assert(!mount_calls);
            if(issue==4)assert(mount_calls==1 && input_owner.operation_returned && input_owner.operation_result==0);
        }
        drained();
    }
    for(int j=first_open+1;j<=last_open;++j){
        reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;
        assert(rnr_stage0_claim_preparation(&e)==0);phase4=1;assert(rnr_stage0_prepare_runtime_loops(&e)==0);
        phase5=1;assert(rnr_stage0_prepare_runtime_mapping(&e)==0);phase6=1;fail_at=j;
        assert(rnr_stage0_prepare_runtime_mount(&e)==-1);drained();
        reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;
        assert(rnr_stage0_claim_preparation(&e)==0);phase4=1;assert(rnr_stage0_prepare_runtime_loops(&e)==0);
        phase5=1;assert(rnr_stage0_prepare_runtime_mapping(&e)==0);phase6=1;abandon_at=j;
        assert(rnr_stage0_prepare_runtime_mount(&e)==-1 && !abandon_closed);drained();
    }
    for(int j=first_clock+1;j<=last_clock;++j){
        reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;
        assert(rnr_stage0_claim_preparation(&e)==0);phase4=1;assert(rnr_stage0_prepare_runtime_loops(&e)==0);
        phase5=1;assert(rnr_stage0_prepare_runtime_mapping(&e)==0);phase6=1;clock_fail=j;
        assert(rnr_stage0_prepare_runtime_mount(&e)==-1);drained();
    }
    reset();inputs();assert(rnr_stage0_prepare_host_view(&e)==0);phase3=1;
    assert(rnr_stage0_claim_preparation(&e)==0);phase4=1;assert(rnr_stage0_prepare_runtime_loops(&e)==0);
    phase5=1;assert(rnr_stage0_prepare_runtime_mapping(&e)==0);phase6=1;close_error=6;
    assert(rnr_stage0_prepare_runtime_mount(&e)==-1 && e.cleanup_count==46 && !e.cleanup_overflow);drained();
}
