/* Fully mocked integration. No protected paths, native lifecycle or mounts. */
#define RNR_FIXED_BIND_FLOW
#define RNR_MEDIA_SHORT
#include "test_runtime_stage0_media_flow.c"
static struct {int parent,object,target;char name[80];} bind_edges[128];
static int bind_edge_count,bind_state[14],bind_calls,bind_fault,optional_mode;
static int bind_fail_effect,bind_covered_fd,bind_close_fault,bind_close_all,bind_saturate;
static int first_bind_open,last_bind_open,first_bind_clock,last_bind_clock;
static int bind_sources[14]={5,102,103,104,65,51,52,82,107,114,111,113,85,115};
static const char *const bind_paths[14]={"proc","sys/fs/cgroup","sys/dev","sys/devices","dev/null","dev/mapper/control","dev/dm-0","dev/dm-1",
    "var/lib/rnr/assets/0300000000000000000000000000000000000000000000000000000000000000","etc/systemd","usr/lib/systemd/system","usr/local/lib","rnr/launch.bin","dev/dm-2"};
static const unsigned int bind_roles[14]={9,11,12,13,14,15,16,17,18,19,20,21,22,26};
static int target_object(int);
static const unsigned long bind_flags[14]={15,14,15,15,11,11,11,11,7,7,7,7,7,11};
static void edge(int parent,const char *name,int object,int target)
{assert(bind_edge_count<128);int j=bind_edge_count++;bind_edges[j].parent=parent;bind_edges[j].object=object;bind_edges[j].target=target;strcpy(bind_edges[j].name,name);}
static int edge_find(int parent,const char *name)
{for(int j=0;j<bind_edge_count;++j)if(bind_edges[j].parent==parent&&!strcmp(bind_edges[j].name,name))return j;return -1;}
static void bind_tree(void)
{
    bind_edge_count=0;
    edge(0,"proc",5,-1);edge(0,"etc",1,-1);edge(1,"systemd",114,-1);
    edge(0,"sys",100,-1);edge(100,"fs",101,-1);edge(101,"cgroup",102,-1);edge(100,"dev",103,-1);edge(100,"devices",104,-1);
    edge(0,"var",40,-1);edge(40,"lib",41,-1);edge(41,"rnr",105,-1);edge(105,"assets",106,-1);edge(106,strrchr(bind_paths[8],'/')+1,107,-1);
    edge(0,"usr",108,-1);edge(108,"lib",109,-1);edge(109,"systemd",110,-1);edge(110,"system",111,-1);
    edge(108,"local",112,-1);edge(112,"lib",113,-1);
    edge(0,"dev",46,-1);edge(46,"mapper",50,-1);edge(50,"control",51,-1);edge(46,"null",65,-1);
    edge(46,"dm-0",52,-1);edge(46,"dm-1",82,-1);edge(46,"dm-2",115,-1);
    edge(0,"run",20,-1);edge(20,input_owner.work_name,21,-1);edge(21,"launch",84,-1);edge(84,"launch.bin",85,-1);
    edge(114,"system.control",116,-1);edge(114,"system",117,-1);edge(114,"system.attached",118,-1);
    if(optional_mode){edge(113,"systemd",119,-1);if(optional_mode==2)edge(119,"system",120,-1);}
    if(bind_fault==25)edge(46,"dm-256",115,-1);
    int next=200;
    for(int i=0;i<14;++i){int parent=54;char path[160];strcpy(path,bind_paths[i]);char *name=strtok(path,"/");
        while(name){char *following=strtok(NULL,"/");int j=edge_find(parent,name);
            if(j<0){int object=next++;edge(parent,name,object,following?-1:i);j=bind_edge_count-1;}
            parent=bind_edges[j].object;name=following;}}
}
static int binds_open(int parent,const char *name,int flags)
{
    int j=edge_find(handles[parent].object,name);if(j<0)return -2;
    if((bind_fault==17&&handles[parent].object==46&&!strcmp(name,"dm-2"))||
       (bind_fault==18&&bind_edges[j].target==4)){errno=ENOENT;return -1;}
    int i=bind_edges[j].target,o=bind_edges[j].object;
    if(i>=0&&bind_state[i])o=bind_sources[i];
    assert(flags==(O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)||flags==(O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)||
        flags==(O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
    int fd=newfd(o);if(fd>=0){handles[fd].access=O_RDONLY;handles[fd].bind_target=i>=0&&bind_state[i]?i+1:handles[parent].bind_target;}
    return fd;
}
static int binds_stat(int fd,struct stat *s)
{
    int o=handles[fd].object;if(o<100)return -2;
    assert(handles[fd].live);memset(s,0,sizeof(*s));s->st_dev=1;s->st_ino=10000+o;s->st_nlink=2;s->st_mode=S_IFDIR|0755;
    if(o>=200){s->st_dev=makedev(253,0);s->st_mode=S_IFDIR|0555;
        for(int j=0;j<bind_edge_count;++j)if(bind_edges[j].object==o&&bind_edges[j].target>=0){int i=bind_edges[j].target;
            if(i==4||i==5||i==6||i==7||i==12||i==13){s->st_mode=S_IFREG|(i==12?0444:0);s->st_nlink=1;}
            if(bind_fault==1&&i==12)s->st_mode=S_IFREG|0000;
        }
    }else if(o>=100&&o<=104){s->st_dev=6;if(o==102)s->st_dev=7;}
    else if(o==107){s->st_dev=makedev(253,bind_fault==10?0:bind_fault==25?256:2);s->st_mode=S_IFDIR|0555;}
    else if(o==115){s->st_dev=5;s->st_mode=S_IFBLK|0660;s->st_gid=6;s->st_rdev=makedev(253,bind_fault==25?256:2);s->st_nlink=1;}
    if(bind_fault==2&&o==103)s->st_uid=1;
    if(bind_fault==22&&o==100&&bind_calls)s->st_ino++;
    if(bind_fault==24&&o==target_object(3)&&bind_calls)s->st_mtim.tv_sec=1;
    if(bind_fault==15&&o==116)s->st_mode=S_IFLNK|0777;
    if(bind_fault==3&&o==102)s->st_mode=S_IFREG|0444;
    if(bind_fault==12&&o==104)s->st_dev=9;
    return 0;
}
static uint64_t binds_mount_id(int fd)
{
    int o=handles[fd].object,t=handles[fd].bind_target;
    if(t){if(bind_fault==19&&t==1)return 22;
        if(bind_fault==20&&t==1)return 66;
        if(bind_fault==21&&t==2)return 201;
        return (bind_fault==5&&o==117)?999:200+(unsigned int)t;}
    if(o>=200)return 66;
    if(o>=100&&o<=104)return o==102?122:120;
    if(o==107)return 130;
    if(o==115)return 55;
    if(o>=105&&o<=120)return bind_fault==4&&o==117?999:11;
    return 0;
}
static long binds_filesystem(int fd)
{
    int o=handles[fd].object;
    if(o>=200||o==107)return 0x73717368;
    if(o>=100&&o<=104)return o==102?(bind_fault==11?0:0x63677270):0x62656572;
    if(o==115)return 0x1021994;
    return o>=105&&o<=120?0xef53:0;
}
static int binds_vfs(int fd,struct statvfs *s)
{
    memset(s,0,sizeof(*s));int o=handles[fd].object,t=handles[fd].bind_target;
    if(t){int i=t-1;s->f_flag=bind_state[i]==2?bind_flags[i]:input_owner.binds[i].source.flags;
        if(bind_fault==6&&i==6)s->f_flag|=4;
        return 0;}
    if(o==54||o==55||o==84||o==85||o>=200||o==107)s->f_flag=7;
    else if(o==56)s->f_flag=14;
    if(bind_fault==23&&o==102&&bind_calls)s->f_flag=8;
    return 0;
}
static int binds_absent(int parent,const char *name,struct stat *s,int flags)
{
    assert(flags==AT_SYMLINK_NOFOLLOW);if(bind_fault==16){errno=EACCES;return -1;}int j=edge_find(handles[parent].object,name);
    if(j<0){errno=ENOENT;return -1;}
    int fd=RNR_TEST_HANDLES-1;assert(!handles[fd].live);handles[fd].live=1;handles[fd].object=bind_edges[j].object;
    int r=binds_stat(fd,s);memset(&handles[fd],0,sizeof(handles[fd]));assert(r==0);return 0;
}
static int binds_effect(const char *source,const char *target,const char *fs,unsigned long flags,const void *data)
{
    int i=bind_calls/2,remount=bind_calls%2;assert(i<14&&!fs&&!data);assert(input_owner.operation_role==bind_roles[i]);assert(flags==(4096UL|(remount?32|bind_flags[i]:0)));
    char expected[256];snprintf(expected,256,"%s/%s",input_owner.root_path,bind_paths[i]);assert(!strcmp(target,expected));
    if(i==12)snprintf(expected,256,"/run/%s/launch/launch.bin",input_owner.work_name);else snprintf(expected,256,"/%s",bind_paths[i]);
    assert(!strcmp(source,expected));assert(input_owner.journal_sequence==(unsigned int)(57+4*i+2*remount));++bind_calls;
    bind_covered_fd=input_owner.binds[i].target_fd;
    if(bind_calls==bind_fail_effect&&bind_fault==7){errno=EIO;return -1;}
    if(bind_calls==bind_fail_effect&&bind_fault==8)return 1;
    bind_state[i]=remount?2:1;
    if(bind_fault==9&&bind_calls==bind_fail_effect)clock_fail=clock_calls+1;
    return 0;
}
static int binds_close(int fd)
{
    if(bind_close_fault==bind_calls&&fd==bind_covered_fd)return 1;
    if(bind_saturate&&input_owner.journal_sequence==112){int n=0;for(int j=0;j<RNR_TEST_HANDLES;++j)n+=handles[j].live;
        if(n==79)bind_close_all=1;}
    return bind_close_all;
}
static void bind_start(void)
{
    binds_enabled=0;optional_mode=0;bind_fault=bind_calls=0;bind_fail_effect=1;bind_covered_fd=-1;bind_close_fault=-1;bind_close_all=bind_saturate=0;bind_journal_fail=bind_journal_kind=0;memset(bind_state,0,sizeof(bind_state));
    launch_root_start();struct rnr_stage0_preparer_error e;assert(rnr_stage0_prepare_launch_mount(&e)==0);
    bind_tree();binds_enabled=1;
}
static int target_object(int i)
{
    int parent=54;char path[160];strcpy(path,bind_paths[i]);char *name=strtok(path,"/");
    while(name){int j=edge_find(parent,name);assert(j>=0);parent=bind_edges[j].object;name=strtok(NULL,"/");}
    return parent;
}
static void bind_vectors(void)
{
    static const uint64_t devs[14]={2,7,6,6,5,5,5,5,0,1,1,1,0,5};
    static const uint64_t inos[14]={1005,10102,10103,10104,1065,1051,1052,1082,10107,10114,10111,10113,7777,10115};
    static const uint64_t mounts[14]={22,122,120,120,55,55,55,55,130,11,11,11,88,55};
    for(int i=0;i<14;++i)for(int j=0;j<4;++j){
        int returned=j&1,remount=j>=2;unsigned char b[256]={0};
        memcpy(b,"RNRO0001",8);put(b+8,1,4);put(b+12,remount?8:7,4);put(b+16,57+4*i+j,8);b[24]=4;
        put(b+40,bind_roles[i],4);put(b+44,returned?2:1,4);
        uint64_t device=i==8?makedev(253,2):i==12?makedev(253,1):devs[i];
        uint64_t rdev=i==4?makedev(1,3):i==5?makedev(10,236):i==6?makedev(253,0):i==7?makedev(253,1):i==13?makedev(253,2):0;
        put(b+64,device,8);put(b+72,inos[i],8);put(b+80,mounts[i],8);put(b+88,rdev,8);
        put(b+96,remount?device:makedev(253,0),8);put(b+104,remount?inos[i]:(uint64_t)(10000+target_object(i)),8);
        put(b+112,remount?201+i:66,8);if(returned)put(b+120,201+i,8);
        put(b+128,4096UL|(remount?32|bind_flags[i]:0),8);
        if(i==6||i==7||i==13)put(b+152,0xfd00+(i==6?0:i==7?1:2),8);
        assert(!memcmp(b,append_bytes+(56+4*i+j)*256,256));
    }
}
static void bind_success(int optional)
{
    struct rnr_stage0_preparer_error e;bind_start();optional_mode=optional;bind_tree();
    int first_open=calls,first_clock=clock_calls;
    int r=rnr_stage0_prepare_fixed_binds(&e);
    if(!optional){first_bind_open=first_open;last_bind_open=calls;first_bind_clock=first_clock;last_bind_clock=clock_calls;}
    if(r)fprintf(stderr,"bind failure%d errno%d seq%d calls%d\n",e.code,e.system_errno,input_owner.journal_sequence,bind_calls);
    assert(r==0&&input_owner.journal_sequence==112&&bind_calls==28);bind_vectors();
    int count=0;for(int j=0;j<RNR_TEST_HANDLES;++j)count+=handles[j].live;assert(count==78);
    assert(input_owner.runtime_mapping.dm_openers==3&&input_owner.launch_mapping.dm_openers==3);
    int before=total_closed();assert(rnr_stage0_prepare_fixed_binds(&e)==-1&&total_closed()==before);
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    handles[10].live=1;before=total_closed();assert(rnr_stage0_abandon_preparation_inputs(&e)==-1&&handles[10].live&&total_closed()==before);handles[10].live=0;
}
#if defined(RNR_FIXED_CLOCK_FLOW) || defined(RNR_FINAL_FLOW)
static int fixed_bind_fixture_main(void)
#else
int main(void)
#endif
{
    (void)media_flow_fixture_main;
    for(int j=0;j<3;++j)bind_success(j);
    struct rnr_stage0_preparer_error e;
    for(int j=1;j<=16;++j){if(j==13||j==14)continue;bind_start();bind_fault=j;
        assert(rnr_stage0_prepare_fixed_binds(&e)==-1&&e.code!=RNR_STAGE0_PREPARER_OK);drained();
        if(j<=4||j>=10)assert(!bind_calls);
        if(j==7||j==8||j==9)assert(bind_calls==1&&input_owner.operation_entered&&input_owner.operation_returned);
    }
    for(int problem=17;problem<=24;++problem){bind_start();bind_fault=problem;
        assert(rnr_stage0_prepare_fixed_binds(&e)==-1);drained();
        assert(bind_calls==(problem<=18?0:problem==21?3:1));
        if(problem>=19)assert(input_owner.operation_returned&&input_owner.operation_result==0);
    }
    bind_start();bind_fault=25;bind_tree();assert(rnr_stage0_prepare_fixed_binds(&e)==-1&&!bind_calls);drained();
    binds_enabled=0;bind_calls=bind_fault=0;bind_high_minor_setup=1;launch_root_start();
    assert(rnr_stage0_prepare_launch_mount(&e)==0);bind_tree();binds_enabled=1;
    assert(rnr_stage0_prepare_fixed_binds(&e)==-1&&!bind_calls);drained();bind_high_minor_setup=0;
    for(int position=1;position<=28;++position){
        for(int kind=7;kind<=9;++kind){bind_start();bind_fail_effect=position;bind_fault=kind;
            assert(rnr_stage0_prepare_fixed_binds(&e)==-1&&bind_calls==position&&input_owner.operation_returned);drained();}
        bind_start();bind_close_fault=position;assert(rnr_stage0_prepare_fixed_binds(&e)==-1&&bind_calls==position);drained();
    }
    for(int seq=57;seq<=112;++seq)for(int kind=1;kind<=4;++kind){
        bind_start();bind_journal_fail=seq;bind_journal_kind=kind;
        assert(rnr_stage0_prepare_fixed_binds(&e)==-1&&input_owner.journal_sequence<(unsigned int)seq);drained();
    }
    for(int index=0;index<=64;++index){
        int open_position=first_bind_open+1+(last_bind_open-first_bind_open-1)*index/64;
        int clock_position=first_bind_clock+1+(last_bind_clock-first_bind_clock-1)*index/64;
        bind_start();fail_at=open_position;assert(rnr_stage0_prepare_fixed_binds(&e)==-1);drained();
        bind_start();abandon_at=open_position;assert(rnr_stage0_prepare_fixed_binds(&e)==-1&&!abandon_closed);drained();
        bind_start();clock_fail=clock_position;assert(rnr_stage0_prepare_fixed_binds(&e)==-1);drained();
    }
    bind_start();bind_saturate=1;assert(rnr_stage0_prepare_fixed_binds(&e)==-1&&e.cleanup_count==80&&!e.cleanup_overflow);drained();
    bind_start();int before=total_closed();assert(rnr_stage0_prepare_fixed_binds(NULL)==-1&&total_closed()==before&&!bind_calls);
    assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    bind_start();foreign=1;before=total_closed();assert(rnr_stage0_prepare_fixed_binds(&e)==-1&&total_closed()==before&&!bind_calls);
    foreign=0;assert(rnr_stage0_abandon_preparation_inputs(&e)==0);drained();
    printf("fixed-bind vectors56, effects28, journal failures224, sampled open/abandon/clock65 each; new opens%d clocks%d\n",last_bind_open-first_bind_open,last_bind_clock-first_bind_clock);
    return 0;
}
