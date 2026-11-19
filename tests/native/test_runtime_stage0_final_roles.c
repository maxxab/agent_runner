/* Fully synthetic root transition and final FD allocation; no actual chroot. */
#define RNR_FINAL_FLOW
#include "test_runtime_stage0_fixed_binds.c"
static int final_root_state,final_root_calls,final_open_count,final_admits,final_finishes;
static int final_fault,final_fail_root,final_bad_fd,final_close_position,final_close_calls;
static int final_inherit[RNR_TEST_HANDLES],final_drain_started,final_capture_opens;
static int final_tracking,final_close_pre[78],final_close_post[78];
static int final_number(int object,int role)
{
    if(role<0){++final_capture_opens;return newfd(object);}
    int live=0;for(int j=0;j<RNR_TEST_HANDLES;++j)live+=handles[j].live;
    assert(live==role&&final_root_state==3);++final_open_count;
    if(final_fault==20&&role==final_bad_fd){errno=EIO;return -1;}
    int fd=3+role;
    if(final_fault==21&&role==final_bad_fd)fd=100;
    if(final_fault==22&&role==final_bad_fd)return 2;
    assert(!handles[fd].live);memset(&handles[fd],0,sizeof(handles[fd]));
    handles[fd].live=1;handles[fd].object=object;
    if(role==5)handles[fd].bind_target=2;
    final_inherit[fd]=FD_CLOEXEC;
    if(final_fault==23&&role==final_bad_fd)clock_fail=clock_calls+1;
    return fd;
}
static int final_open_hook(int parent,const char *name,int flags)
{
    int object=parent==AT_FDCWD?-1:handles[parent].object;
    if(parent==AT_FDCWD&&!strcmp(name,"/")){
        if(!final_root_state)return -2;
        assert(flags==(O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC));
        return final_number(54,-1);
    }
    if(object==0&&!strcmp(name,".")){
        assert(final_root_state>=2&&flags==(O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
        return final_number(0,-1);
    }
    if(object==7&&!strcmp(name,"exe")){
        assert(flags==(O_RDONLY|O_NONBLOCK|O_CLOEXEC));return final_number(125,-1);
    }
    if(object==56&&!strcmp(name,"dbus")){
        assert(flags==(O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC));
        return final_number(127,parent==3?4:-1);
    }
    if(parent==AT_FDCWD&&!strcmp(name,"/proc/1/exe")){
        assert(flags==(O_RDONLY|O_NONBLOCK|O_CLOEXEC));return final_number(125,3);
    }
    return -2;
}
static int final_stat_hook(int fd,struct stat *s)
{
    int o=handles[fd].object;
    if(final_root_state>=2&&((o==0&&(final_fault==50||final_fault==51))||(o==54&&final_fault==52))){
        int alter=final_fault==50?fd==input_owner.fds[0]:final_fault==51?fd!=input_owner.fds[0]:fd!=input_owner.runtime_fds[13];
        final_enabled=0;int r=xstat(fd,s);final_enabled=1;if(alter)s->st_ino++;return r;
    }
    if(o<125||o>127)return -2;
    assert(handles[fd].live);memset(s,0,sizeof(*s));s->st_dev=o==126?makedev(253,0):o==127?4:1;
    s->st_ino=10000+o;s->st_mode=(o==127?S_IFDIR:S_IFREG)|0755;s->st_nlink=o==127?2:1;
    s->st_size=o==127?0:4096;
    if(final_fault==30&&fd==6)s->st_ino++;
    return 0;
}
static uint64_t final_mount_hook(int fd)
{int o=handles[fd].object;
 if(final_root_state>=2&&((final_fault==53&&fd==input_owner.fds[0])||
    (final_fault==54&&o==0&&fd!=input_owner.fds[0])||(final_fault==55&&o==54&&fd!=input_owner.runtime_fds[13])))return 999;
 return o==125?11:o==126?66:o==127?77:0;}
static long final_fs_hook(int fd)
{int o=handles[fd].object;
 if(final_root_state>=2&&((final_fault==56&&fd==input_owner.fds[0])||
    (final_fault==57&&o==0&&fd!=input_owner.fds[0])||(final_fault==58&&o==54&&fd!=input_owner.runtime_fds[13])))return 0x123456;
 return o==125?0xef53:o==126?0x73717368:o==127?0x1021994:0;}
static int final_vfs_hook(int fd,struct statvfs *s)
{
    int o=handles[fd].object;
    if(final_fault==59&&final_root_state>=2&&o==54&&fd!=input_owner.runtime_fds[13]){memset(s,0,sizeof(*s));s->f_flag=15;return 0;}
    if(o<125||o>127)return -2;
    memset(s,0,sizeof(*s));s->f_flag=o==126?7:o==127?14:0;return 0;
}
static int final_fcntl_hook(int fd,int cmd,int value)
{
    if(fd>8)return -2;
    if(cmd==F_GETFL)return ((final_fault==34&&fd==4)?O_WRONLY:O_RDONLY)|O_NONBLOCK;
    if(cmd==F_GETFD)return final_fault==33&&fd==4?0:final_inherit[fd];
    assert(cmd==F_SETFD&&value==0);
    if(final_fault==31&&fd==4){errno=EIO;return -1;}
    final_inherit[fd]=0;return 0;
}
static long final_syscall_hook(long number,va_list args)
{
    if(number==SYS_openat2){
        int parent=va_arg(args,int);const char *name=va_arg(args,const char *);
        const struct open_how *how=va_arg(args,const struct open_how *);
        assert(va_arg(args,size_t)==24&&how->mode==0);
        if(parent!=AT_FDCWD){assert(handles[parent].object==54&&!strcmp(name,"usr/bin/busctl"));
            assert(how->resolve==13&&how->flags==(O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC));return final_number(126,-1);}
        assert(how->resolve==RESOLVE_NO_SYMLINKS);
        if(!strcmp(name,"/run")){assert(how->flags==(O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC));return final_number(56,0);}
        if(!strcmp(name,"/usr/bin/busctl")){assert(how->flags==(O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC));return final_number(126,1);}
        assert(!strcmp(name,"/sys/fs/cgroup")&&how->flags==(O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC));return final_number(102,5);
    }
    if(number==SYS_pidfd_open&&final_root_state==3&&input_owner.view_count==0){
        assert(va_arg(args,int)==1&&va_arg(args,int)==0);return final_number(8,2);}
    return -2;
}
static int final_close_hook(int fd)
{
    int owned=0;for(int j=0;j<RNR_TEST_HANDLES;++j)owned+=handles[j].live;
    if(final_root_state==3&&owned==78&&handles[fd].bind_target==14)final_drain_started=1;
    if(final_drain_started&&fd>=10){++final_close_calls;
        if(final_tracking){assert(final_close_calls<=78);final_close_pre[final_close_calls-1]=clock_calls;final_close_post[final_close_calls-1]=clock_calls+1;}
        if(final_fault==40&&final_close_calls==final_close_position){
            assert(handles[fd].live&&!handles[fd].closed);handles[fd].live=0;++handles[fd].closed;errno=EINTR;return -1;}}
    if(fd>8)return -2;
    assert(fd>=3&&handles[fd].live&&!handles[fd].closed);handles[fd].live=0;++handles[fd].closed;
    if(final_fault==41){errno=EINTR;return -1;}return 0;
}
static int final_root_hook(int step,const char *path,int fd)
{
    assert(final_enabled&&step==final_root_calls++);
    if(step==0)assert(handles[fd].object==54&&path==NULL);
    else assert(!strcmp(path,step==1?".":"/"));
    if(final_fail_root==step+1){errno=EIO;return -1;}
    if(final_fault==10&&step==1)return 1;
    final_root_state=step+1;
    if((final_fault==11&&step==1)||(final_fault==12&&step==0)||(final_fault==13&&step==2))clock_fail=clock_calls+1;
    return 0;
}
static int final_admit_hook(struct rnr_stage0_admission_error *e)
{
    ++final_admits;memset(e,0,sizeof(*e));assert(final_open_count==6&&input_owner.view_count==0&&input_owner.runtime_count==0&&input_owner.journal_count==0);
    if(final_fault==32){e->code=RNR_STAGE0_ADMISSION_READ;e->system_errno=EIO;return -1;}return 0;
}
static int final_finish_hook(struct rnr_stage0_launch_error *e)
{
    ++final_finishes;assert(final_admits==1);memset(e,0,sizeof(*e));e->code=RNR_STAGE0_LAUNCH_EXEC;e->system_errno=ENOEXEC;
    for(int j=0;j<9;++j)assert(final_inherit[j]==0);
    return -1;
}
static void final_start(void)
{
    final_enabled=0;bind_start();struct rnr_stage0_preparer_error e;assert(rnr_stage0_prepare_fixed_binds(&e)==0);
    final_root_state=final_root_calls=final_open_count=final_admits=final_finishes=0;
    final_fault=final_fail_root=final_bad_fd=final_close_position=final_close_calls=0;
    final_drain_started=final_capture_opens=0;memset(final_inherit,0,sizeof(final_inherit));final_enabled=1;
}
int main(void)
{
    (void)fixed_bind_fixture_main;struct rnr_stage0_preparer_error e;
    final_start();final_tracking=1;int r=rnr_stage0_prepare_final_roles(&e);
    if(r)fprintf(stderr,"final failure%d errno%d root%d calls%d opens%d\n",e.code,e.system_errno,final_root_state,final_root_calls,final_open_count);
    assert(r==0&&final_root_calls==3&&final_admits==1&&final_open_count==6&&final_close_calls==78);final_tracking=0;
    assert(rnr_stage0_finish_prepared_operational(&e)==-1&&final_finishes==1&&e.launch.system_errno==ENOEXEC);drained();
    for(int step=1;step<=3;++step){final_start();final_fail_root=step;assert(rnr_stage0_prepare_final_roles(&e)==-1&&!final_open_count);drained();}
    for(int kind=10;kind<=13;++kind){final_start();final_fault=kind;assert(rnr_stage0_prepare_final_roles(&e)==-1&&!final_open_count);
        if(kind!=12)assert(input_owner.root_steps[1].entered&&input_owner.root_steps[1].returned&&input_owner.root_steps[1].result==(kind==10?1:0));
        else assert(input_owner.root_steps[0].returned&&!input_owner.root_steps[1].entered);
        drained();}
    for(int kind=20;kind<=23;++kind)for(int role=0;role<6;++role){final_start();final_fault=kind;final_bad_fd=role;
        assert(rnr_stage0_prepare_final_roles(&e)==-1&&final_open_count==role+1);
        if(kind==22)assert(e.unadopted_fd==2&&!handles[2].live);
        drained();}
    for(int kind=30;kind<=34;++kind){final_start();final_fault=kind;assert(rnr_stage0_prepare_final_roles(&e)==-1);drained();}
    for(int kind=50;kind<=59;++kind){final_start();final_fault=kind;assert(rnr_stage0_prepare_final_roles(&e)==-1&&!final_open_count);drained();}
    for(int index=0;index<78;++index){
        final_start();final_fault=40;final_close_position=index+1;
        assert(rnr_stage0_prepare_final_roles(&e)==-1&&!final_open_count&&e.cleanup_count==1&&final_close_calls==78);drained();
        for(int after=0;after<2;++after){final_start();clock_fail=after?final_close_post[index]:final_close_pre[index];
            assert(rnr_stage0_prepare_final_roles(&e)==-1&&!final_open_count&&e.code==RNR_STAGE0_PREPARER_CLOCK);drained();}
    }
    final_start();assert(rnr_stage0_prepare_final_roles(&e)==0);final_fault=41;
    assert(rnr_stage0_abandon_preparation_inputs(&e)==-1&&e.cleanup_count==6&&!e.cleanup_overflow);drained();
    final_start();int closed=total_closed();assert(rnr_stage0_prepare_final_roles(NULL)==-1&&total_closed()==closed&&!final_root_calls);
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    final_start();foreign=1;closed=total_closed();assert(rnr_stage0_prepare_final_roles(&e)==-1&&total_closed()==closed&&!final_root_calls);
    foreign=0;assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    final_start();assert(rnr_stage0_prepare_final_roles(&e)==0);closed=total_closed();
    assert(rnr_stage0_prepare_final_roles(&e)==-1&&total_closed()==closed);
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    handles[3].live=1;closed=total_closed();assert(rnr_stage0_abandon_preparation_inputs(&e)==-1&&handles[3].live&&total_closed()==closed);handles[3].live=0;
    final_start();assert(rnr_stage0_prepare_final_roles(&e)==0);closed=total_closed();assert(rnr_stage0_finish_prepared_operational(NULL)==-1&&total_closed()==closed);
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    puts("synthetic finalroot distinct host/runtime, exact3..8, samewriter ownership and failure vectors passed");return 0;
}
