/* Child syscall/argv/FD trace only: longjmp replaces _exit; all child effects
 * are mocked and no chroot, fork, helper or exec is performed. */
#define _GNU_SOURCE
#include <assert.h>
#include <setjmp.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include "../../automation/native/runtime_stage0_preparer.h"
static jmp_buf exited;
static int child_step,fail_step,exec_calls,positive_calls,exit_status,which_helper;
static int parent_calls,arm_calls,query_calls,bad_signal;
static pid_t invalid_owner;
static pid_t child_parent(void);
static int child_prctl(int,...);
static int child_fchdir(int);
static int child_chroot(const char *);
static int child_chdir(const char *);
static int child_dup3(int,int,int);
static int child_dup2(int,int);
static int child_fcntl(int,int,...);
static long child_syscall(long,...);
static mode_t child_umask(mode_t);
static _Noreturn void child_exit(int);
static int child_positive(struct rnr_stage0_launch_error *);
#define fchdir(d) child_fchdir(d)
#define chroot(p) child_chroot(p)
#define chdir(p) child_chdir(p)
#define dup3(s,t,f) child_dup3(s,t,f)
#define dup2(s,t) child_dup2(s,t)
#define fcntl(...) child_fcntl(__VA_ARGS__)
#define syscall(...) child_syscall(__VA_ARGS__)
#define umask(m) child_umask(m)
#define _exit(s) child_exit(s)
#define getppid() child_parent()
#define prctl(...) child_prctl(__VA_ARGS__)
#define rnr_stage0_check_operational_preparation(e) child_positive(e)
#include "../../automation/native/runtime_stage0_preparer.c"
static int step(void){return ++child_step==fail_step?-1:0;}
static pid_t child_parent(void)
{++parent_calls;return step()?-1:77;}
static int child_prctl(int option,...)
{
    va_list args;va_start(args,option);
    if(option==PR_SET_PDEATHSIG){
        assert(parent_calls==1&&child_step==1&&!arm_calls++);
        assert(va_arg(args,unsigned long)==SIGKILL);
    }else{
        assert(option==PR_GET_PDEATHSIG&&parent_calls==2&&child_step==15&&!query_calls++);
        int *value=va_arg(args,int *);*value=bad_signal?SIGTERM:SIGKILL;
    }
    for(int i=0;i<3;++i)assert(va_arg(args,unsigned long)==0);
    va_end(args);return step();
}
static int child_positive(struct rnr_stage0_launch_error *e)
{(void)e;++positive_calls;return -1;}
static int child_fchdir(int fd){assert(fd==50);return step();}
static int child_chroot(const char *p){assert(!strcmp(p,"."));return step();}
static int child_chdir(const char *p){assert(!strcmp(p,"/"));return step();}
static int child_dup3(int from,int to,int flags)
{assert(from==60&&to==3&&flags==O_CLOEXEC);return step()?-1:3;}
static int child_dup2(int from,int to)
{assert((to==0&&from==61)||(to==1&&from==62)||(to==2&&from==63));return step()?-1:to;}
static int child_fcntl(int fd,int command,...)
{
    assert(fd==1||fd==2);
    if(command==F_GETFL)return step()?-1:O_WRONLY|O_NONBLOCK;
    assert(command==F_SETFL);va_list args;va_start(args,command);assert(va_arg(args,int)==O_WRONLY);va_end(args);
    return step();
}
static long child_syscall(long number,...)
{
    va_list args;va_start(args,number);
    if(number==SYS_close_range){assert(va_arg(args,unsigned int)==4);assert(va_arg(args,unsigned int)==UINT_MAX);
        assert(va_arg(args,unsigned int)==0);va_end(args);return step();}
    assert(number==SYS_execveat);assert(va_arg(args,int)==3);assert(!*va_arg(args,const char *));
    char *const *argv=va_arg(args,char *const *),*const *env=va_arg(args,char *const *);
    assert(va_arg(args,int)==AT_EMPTY_PATH);va_end(args);
    const char *const a[]={"/usr/bin/mksquashfs","/run/work/launch-source","/run/work/launch.squashfs",
        "-noappend","-processors","1","-no-progress","-no-xattrs","-all-root","-mkfs-time","0","-all-time","0",
        "-comp","gzip","-b","4096","-no-exports","-no-fragments",NULL};
    const char *const b[]={"/usr/sbin/veritysetup","format","/run/work/launch.squashfs","/run/work/launch.verity",
        "--no-superblock","--format=1","--hash=sha256","--data-block-size=4096","--hash-block-size=4096","--hash-offset=0",
        "--salt=fixed","--root-hash-file=/run/work/launch.root",NULL};
    const char *const *expected=which_helper?b:a;int j=0;
    while(expected[j]){assert(argv[j]&&!strcmp(argv[j],expected[j]));++j;}assert(!argv[j]);
    assert(!strcmp(env[0],"LC_ALL=C")&&!strcmp(env[1],"TZ=UTC")&&!env[2]);
    ++exec_calls;return -1; /* Returning exec is always terminal127. */
}
static mode_t child_umask(mode_t mode){assert(mode==077&&child_step==15);return 0;}
static _Noreturn void child_exit(int status){exit_status=status;longjmp(exited,1);}
int main(void)
{
    (void)&child_parent;(void)&child_prctl;
    input_owner.runtime_fds[13]=50;input_owner.media_fds[6]=60;input_owner.media_fds[5]=61;
    input_owner.media_fds[9]=62;input_owner.media_fds[11]=63;
    strcpy(input_owner.source_path,"/run/work/launch-source");strcpy(input_owner.data_path,"/run/work/launch.squashfs");
    strcpy(input_owner.hash_path,"/run/work/launch.verity");strcpy(input_owner.salt_arg,"--salt=fixed");
    strcpy(input_owner.rootfile_arg,"--root-hash-file=/run/work/launch.root");
    atomic_store(&input_owner_pid,77);
    for(which_helper=0;which_helper<2;++which_helper)for(fail_step=0;fail_step<=17;++fail_step){
        child_step=exec_calls=positive_calls=exit_status=parent_calls=arm_calls=query_calls=bad_signal=0;
        if(!setjmp(exited))media_child(which_helper);
        assert(exit_status==127&&!positive_calls&&exec_calls==(fail_step==0));
        if(!fail_step)assert(parent_calls==3&&arm_calls==1&&query_calls==1);
    }
    /* Invalid copied owner is rejected before parent queries or arming. */
    for(invalid_owner=-1;invalid_owner<=0;++invalid_owner){
        atomic_store(&input_owner_pid,invalid_owner);
        child_step=exec_calls=positive_calls=exit_status=parent_calls=arm_calls=query_calls=0;
        if(!setjmp(exited))media_child(0);
        assert(exit_status==127&&!child_step&&!parent_calls&&!arm_calls&&!exec_calls&&!positive_calls);
    }
    atomic_store(&input_owner_pid,77);
    child_step=exec_calls=positive_calls=exit_status=parent_calls=arm_calls=query_calls=fail_step=0;bad_signal=1;
    if(!setjmp(exited))media_child(0);
    assert(exit_status==127&&!exec_calls&&!positive_calls&&arm_calls==1&&query_calls==1);
    return 0;
}
