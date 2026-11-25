/* Same-parent original-clock input/view/claim/journal, fixed readonly runtime
 * and pre-Store launch-media helpers. No complete supervisor/entry/Store/main.
 */
#define _GNU_SOURCE
#include "runtime_stage0_preparer.h"
#include "runtime_stage0_records.h"
#ifdef RNR_STAGE0_PRIVATE_QUALIFICATION
#include "libmd/sha2.h"
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <limits.h>
#include <poll.h>
#include <linux/nsfs.h>
#include <linux/openat2.h>
#include <elf.h>
#include <dirent.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <linux/loop.h>
#include <linux/dm-ioctl.h>
#include <stddef.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <sys/sysmacros.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/statvfs.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/xattr.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__)
#error "Fixed native preparation requires Linux x86-64"
#endif
enum preparer_phase { PREPARER_NEW, PREPARER_ACQUIRING,
    PREPARER_FENCED_ACQUIRING, PREPARER_INPUTS_HELD, PREPARER_FENCED_HELD,
    PREPARER_ADMISSION_ACQUIRING, PREPARER_FENCED_ADMISSION_ACQUIRING,
    PREPARER_ADMISSION_INPUTS_HELD, PREPARER_FENCED_ADMISSION_HELD,
    PREPARER_ADMISSION_ABANDONING,
    PREPARER_VIEW_ACQUIRING, PREPARER_FENCED_VIEW_ACQUIRING,
    PREPARER_VIEW_HELD, PREPARER_FENCED_VIEW_HELD,
    PREPARER_JOURNAL_ACQUIRING, PREPARER_FENCED_JOURNAL_ACQUIRING,
    PREPARER_JOURNAL_HELD, PREPARER_FENCED_JOURNAL_HELD,
    PREPARER_RUNTIME_ACQUIRING, PREPARER_FENCED_RUNTIME_ACQUIRING,
    PREPARER_RUNTIME_HELD, PREPARER_FENCED_RUNTIME_HELD,
    PREPARER_DM_ACQUIRING, PREPARER_FENCED_DM_ACQUIRING,
    PREPARER_DM_HELD, PREPARER_FENCED_DM_HELD,
    PREPARER_MOUNT_ACQUIRING, PREPARER_FENCED_MOUNT_ACQUIRING,
    PREPARER_ROOT_HELD, PREPARER_FENCED_ROOT_HELD,
    PREPARER_MEDIA_ACQUIRING, PREPARER_FENCED_MEDIA_ACQUIRING,
    PREPARER_MEDIA_HELD, PREPARER_FENCED_MEDIA_HELD,
    PREPARER_LAUNCH_LOOPS_ACQUIRING, PREPARER_FENCED_LAUNCH_LOOPS_ACQUIRING,
    PREPARER_LAUNCH_LOOPS_HELD, PREPARER_FENCED_LAUNCH_LOOPS_HELD,
    PREPARER_LAUNCH_DM_ACQUIRING, PREPARER_FENCED_LAUNCH_DM_ACQUIRING,
    PREPARER_LAUNCH_DM_HELD, PREPARER_FENCED_LAUNCH_DM_HELD,
    PREPARER_LAUNCH_MOUNT_ACQUIRING, PREPARER_FENCED_LAUNCH_MOUNT_ACQUIRING,
    PREPARER_LAUNCH_ROOT_HELD, PREPARER_FENCED_LAUNCH_ROOT_HELD,
    PREPARER_BINDS_ACQUIRING, PREPARER_FENCED_BINDS_ACQUIRING,
    PREPARER_BINDS_HELD, PREPARER_FENCED_BINDS_HELD,
    PREPARER_FINAL_ACQUIRING, PREPARER_FENCED_FINAL_ACQUIRING,
    PREPARER_FINAL_ROLES_HELD, PREPARER_FENCED_FINAL_ROLES_HELD,
    PREPARER_FINAL_FINISHING, PREPARER_FENCED_FINAL_FINISHING,
    PREPARER_ABANDONING, PREPARER_FAILED_DRAINED, PREPARER_ABANDONED };
static atomic_int preparer_state = ATOMIC_VAR_INIT(PREPARER_NEW);
static _Atomic pid_t input_owner_pid;
/* Closed private profiles share ABI parsing, never caller authority. */
enum mapping_kind { MAPPING_RUNTIME, MAPPING_LAUNCH };
struct mapping_owner {
    uint64_t dm_device;
    uint32_t dm_event;
    int dm_openers;
    char dm_name[128],dm_uuid[129],dm_node[24],dm_params[512];
    unsigned char dm_response[4096];
    int dm_result,dm_errno;
};
struct fixed_object { struct stat s; uint64_t mount; long fs; unsigned long flags; };
struct fixed_path { char name[160]; unsigned int count; struct fixed_object steps[8]; };
struct fixed_binding {
    int source_fd,target_fd,bound;
    struct fixed_path source_path,target_path;
    struct fixed_object source,target;
};
struct preparer_owner {
    int final_initialized,final_fds[6];
    struct fixed_object final_expected[7];
    struct {int entered,returned,result,system_errno;} root_steps[3];
    int binds_initialized;
    struct fixed_binding binds[14];
    struct fixed_object optional[5];
    int optional_present[5];
    int fds[11];
    int project_executables[3]; /* borrowed from the original project view */
#ifdef RNR_STAGE0_PRIVATE_QUALIFICATION
    int executable_fds[8];
    struct stat executable_identities[8];
    uint64_t executable_mounts[8];
    int executables_initialized;
    char native_hash[65];
    int unit_fds[4],units_initialized;
    struct stat unit_identities[6];
    uint64_t unit_mounts[6];
    char unit_paths[4][128];
    struct stat search_identities[32];
    uint64_t search_mounts[32];
    unsigned char search_present[32];
    int manager_fd,manager_initialized;
    unsigned int manager_receives,manager_polls,manager_serial;
    unsigned char manager_invocations[4][16];
    uint64_t manager_cgroup_ids[4]; /* observations; kernel correlation remains mandatory */
    int cgroup_fds[8],cgroup_initialized;
    struct stat cgroup_identities[8];
    uint64_t cgroup_mounts[8];
    struct stat manager_identities[3];
    uint64_t manager_mounts[3];
#endif
    int project_route,project_held;
    pid_t original_keeper;
    char project[65];
    int view_fds[22];
    unsigned int view_count;
    struct stat view_identities[22];
    uint64_t proc_mount;
    int launch_fds[5],launch_candidates[2],launch_initialized;
    struct stat launch_identities[5];
    uint64_t launch_mounts[5];
    char launch_names[2][24],launch_tags[2][64];
    int launch_root_mounted;
    char launch_mount_path[64],launch_dm_path[32];
    struct {int entered,result,system_errno;} launch_mount_sync;
    int media_fds[12];
    int media_initialized;
    struct stat media_identities[7];
    uint64_t media_mounts[7];
    unsigned char launch_bytes[65552], data_bytes[4194304], hash_bytes[36864], root_bytes[64];
    size_t launch_length, data_length, hash_length;
    struct rnr_stage0_output media_output;
    struct {int fd,entered,result,system_errno;} helper_closes[2][6];
    pid_t child_pid;
    int child_entered, child_errno, child_returned, child_reaped, child_status;
    struct {int kind,entered;int64_t result;int system_errno;} media_steps[48];
    char source_path[104], data_path[104], hash_path[104], rootfile_arg[128], salt_arg[72];
    int runtime_fds[15];
    unsigned int runtime_count;
    struct stat runtime_identities[15];
    uint64_t runtime_mounts[15];
    unsigned int journal_sequence, operation, operation_role;
    unsigned char operation_payload[192];
    int operation_entered, operation_returned, operation_errno;
    ssize_t journal_write_result;
    int journal_write_errno, journal_sync_entered, journal_sync_result, journal_sync_errno;
    int64_t operation_result;
    int loop_candidates[2];
    char runtime_name[73], loop_names[2][24], loop_tags[2][64];
    struct mapping_owner runtime_mapping,launch_mapping;
    int root_mounted,run_bound,run_remounted;
    unsigned long original_run_flags;
    char root_path[64],run_path[72],dm_path[32];
    int journal_fds[3];
    unsigned int journal_count;
    struct stat journal_identities[3];
    uint64_t journal_mounts[3];
    char work_name[44];
    enum rnr_stage0_claim_disposition claim_disposition;
    int mkdir_errno;
    struct stat identities[11];
    uint64_t mounts[11];
    long root_filesystem;
    unsigned char installation_raw[448], task_raw[65600];
#ifdef RNR_STAGE0_PRIVATE_QUALIFICATION
    unsigned char policy_raw[9728], policy_chunk[32768];
    struct rnr_stage0_policy policy;
#endif
    struct rnr_stage0_installation installation;
    struct rnr_stage0_task task;
    struct rnr_stage0_preparer_error original_error, abandon_error;
};
static struct preparer_owner input_owner = { .fds = {-1,-1,-1,-1,-1} };

static void reject_input(struct rnr_stage0_preparer_error *e,
                         enum rnr_stage0_preparer_code code, int failure)
{ if(e->code==RNR_STAGE0_PREPARER_OK){e->code=code;e->system_errno=failure;} }

/* Losing calls touch atomic state only, never unpublished FD/data ownership.
 * No unconditional store may override acquisition/abandonment ownership. */
static int admission_phase(int phase)
{
    return phase==PREPARER_ADMISSION_ACQUIRING || phase==PREPARER_FENCED_ADMISSION_ACQUIRING ||
        phase==PREPARER_ADMISSION_INPUTS_HELD || phase==PREPARER_FENCED_ADMISSION_HELD ||
        phase==PREPARER_ADMISSION_ABANDONING;
}
static void fence_inputs(void)
{
    int phase=atomic_load_explicit(&preparer_state,memory_order_acquire);
    for(;;){
        int fenced;
        switch(phase){
        case PREPARER_NEW:fenced=PREPARER_FAILED_DRAINED;break;
        case PREPARER_ADMISSION_ACQUIRING:fenced=PREPARER_FENCED_ADMISSION_ACQUIRING;break;
        case PREPARER_ADMISSION_INPUTS_HELD:fenced=PREPARER_FENCED_ADMISSION_HELD;break;
        case PREPARER_ACQUIRING:fenced=PREPARER_FENCED_ACQUIRING;break;
        case PREPARER_INPUTS_HELD:fenced=PREPARER_FENCED_HELD;break;
        case PREPARER_VIEW_ACQUIRING:fenced=PREPARER_FENCED_VIEW_ACQUIRING;break;
        case PREPARER_VIEW_HELD:fenced=PREPARER_FENCED_VIEW_HELD;break;
        case PREPARER_JOURNAL_ACQUIRING:fenced=PREPARER_FENCED_JOURNAL_ACQUIRING;break;
        case PREPARER_JOURNAL_HELD:fenced=PREPARER_FENCED_JOURNAL_HELD;break;
        case PREPARER_RUNTIME_ACQUIRING:fenced=PREPARER_FENCED_RUNTIME_ACQUIRING;break;
        case PREPARER_RUNTIME_HELD:fenced=PREPARER_FENCED_RUNTIME_HELD;break;
        case PREPARER_DM_ACQUIRING:fenced=PREPARER_FENCED_DM_ACQUIRING;break;
        case PREPARER_DM_HELD:fenced=PREPARER_FENCED_DM_HELD;break;
        case PREPARER_MOUNT_ACQUIRING:fenced=PREPARER_FENCED_MOUNT_ACQUIRING;break;
        case PREPARER_ROOT_HELD:fenced=PREPARER_FENCED_ROOT_HELD;break;
        case PREPARER_MEDIA_ACQUIRING:fenced=PREPARER_FENCED_MEDIA_ACQUIRING;break;
        case PREPARER_MEDIA_HELD:fenced=PREPARER_FENCED_MEDIA_HELD;break;
        case PREPARER_LAUNCH_LOOPS_ACQUIRING:fenced=PREPARER_FENCED_LAUNCH_LOOPS_ACQUIRING;break;
        case PREPARER_LAUNCH_LOOPS_HELD:fenced=PREPARER_FENCED_LAUNCH_LOOPS_HELD;break;
        case PREPARER_LAUNCH_DM_ACQUIRING:fenced=PREPARER_FENCED_LAUNCH_DM_ACQUIRING;break;
        case PREPARER_LAUNCH_DM_HELD:fenced=PREPARER_FENCED_LAUNCH_DM_HELD;break;
        case PREPARER_LAUNCH_MOUNT_ACQUIRING:fenced=PREPARER_FENCED_LAUNCH_MOUNT_ACQUIRING;break;
        case PREPARER_LAUNCH_ROOT_HELD:fenced=PREPARER_FENCED_LAUNCH_ROOT_HELD;break;
        case PREPARER_BINDS_ACQUIRING:fenced=PREPARER_FENCED_BINDS_ACQUIRING;break;
        case PREPARER_BINDS_HELD:fenced=PREPARER_FENCED_BINDS_HELD;break;
        case PREPARER_FINAL_ACQUIRING:fenced=PREPARER_FENCED_FINAL_ACQUIRING;break;
        case PREPARER_FINAL_ROLES_HELD:fenced=PREPARER_FENCED_FINAL_ROLES_HELD;break;
        case PREPARER_FINAL_FINISHING:fenced=PREPARER_FENCED_FINAL_FINISHING;break;
        default:goto writer;
        }
        if(atomic_compare_exchange_weak_explicit(&preparer_state,&phase,fenced,
                memory_order_acq_rel,memory_order_acquire))break;
    }
writer:
    /* Mode comes only from published atomic phase, never unpublished owner data.
     * Terminal states have already fenced their route and cannot revive it. */
#ifdef RNR_STAGE0_PRIVATE_QUALIFICATION
    if(admission_phase(phase)){(void)rnr_stage0_check_admission_preparation(NULL);return;}
#endif
    if(phase!=PREPARER_FAILED_DRAINED && phase!=PREPARER_ABANDONED)
        (void)rnr_stage0_check_operational_preparation(NULL);
}
static int active_preparation(void)
{
    int phase=atomic_load_explicit(&preparer_state,memory_order_acquire);
    return phase==PREPARER_ADMISSION_ACQUIRING || phase==PREPARER_ACQUIRING || phase==PREPARER_VIEW_ACQUIRING ||
           phase==PREPARER_JOURNAL_ACQUIRING || phase==PREPARER_RUNTIME_ACQUIRING || phase==PREPARER_DM_ACQUIRING || phase==PREPARER_MOUNT_ACQUIRING || phase==PREPARER_MEDIA_ACQUIRING || phase==PREPARER_LAUNCH_LOOPS_ACQUIRING || phase==PREPARER_LAUNCH_DM_ACQUIRING || phase==PREPARER_LAUNCH_MOUNT_ACQUIRING || phase==PREPARER_BINDS_ACQUIRING || phase==PREPARER_FINAL_ACQUIRING || phase==PREPARER_FINAL_FINISHING;
}
static int live_input(struct rnr_stage0_preparer_error *e)
{
    if(!active_preparation()){
        reject_input(e,RNR_STAGE0_PREPARER_ATTEMPT,0);return -1;
    }
    struct rnr_stage0_launch_error clock_error={0};
    int result;
#ifdef RNR_STAGE0_PRIVATE_QUALIFICATION
    int phase=atomic_load_explicit(&preparer_state,memory_order_acquire);
    if(admission_phase(phase))result=rnr_stage0_check_admission_preparation(&clock_error);
    else
#endif
        result=rnr_stage0_check_operational_preparation(&clock_error);
    if(result!=0){
        if(e->launch.code==RNR_STAGE0_LAUNCH_OK)e->launch=clock_error;
        reject_input(e,RNR_STAGE0_PREPARER_CLOCK,clock_error.system_errno);return -1;
    }
    if(!active_preparation()){
        reject_input(e,RNR_STAGE0_PREPARER_ATTEMPT,0);return -1;
    }
    return 0;
}
/* A failed syscall still needs its post-call clock observation. Preserve the
 * initiating failure before that check, with the first clock capsule separate. */
static int failed_input(struct rnr_stage0_preparer_error *e,
                        enum rnr_stage0_preparer_code code,int failure)
{
    reject_input(e,code,failure);
    (void)live_input(e);
    return -1;
}
static void close_input(int *slot,struct rnr_stage0_preparer_error *e)
{
    int fd=*slot;
    int phase=atomic_load_explicit(&preparer_state,memory_order_acquire);
    int checking=fd>=0 && e->code==RNR_STAGE0_PREPARER_OK &&
        (phase==PREPARER_ADMISSION_ACQUIRING || phase==PREPARER_FINAL_ACQUIRING);
    if(checking && live_input(e)!=0)checking=0;
    *slot=-1;
    if(fd>=0 && close(fd)!=0){
        int failure=errno;
        /* G5 reserves 96 preparation cleanup entries. */
        if(e->cleanup_count<96){
            e->cleanup_errors[e->cleanup_count].fd=fd;
            e->cleanup_errors[e->cleanup_count++].system_errno=failure;
        }else e->cleanup_overflow=1;
        reject_input(e,RNR_STAGE0_PREPARER_CLEANUP,failure);
    }
    if(checking)(void)live_input(e);
}
static void drain_inputs(struct rnr_stage0_preparer_error *e)
{
#ifdef RNR_STAGE0_PRIVATE_QUALIFICATION
    if(input_owner.cgroup_initialized)
        for(int role=7;role>=0;--role)close_input(&input_owner.cgroup_fds[role],e);
    if(input_owner.manager_initialized)close_input(&input_owner.manager_fd,e);
    if(input_owner.units_initialized)
        for(int role=3;role>=0;--role)close_input(&input_owner.unit_fds[role],e);
    if(input_owner.executables_initialized)
        for(int role=7;role>=0;--role)close_input(&input_owner.executable_fds[role],e);
#endif
    if(input_owner.final_initialized)
        for(int i=5;i>=0;--i)close_input(&input_owner.final_fds[i],e);
    if(input_owner.binds_initialized){
        for(int i=13;i>=0;--i)close_input(&input_owner.binds[i].target_fd,e);
        for(int i=13;i>=0;--i)close_input(&input_owner.binds[i].source_fd,e);
    }
    if(input_owner.launch_initialized)
        for(int role=4;role>=0;--role)close_input(&input_owner.launch_fds[role],e);
    if(input_owner.media_initialized)
        for(int role=11;role>=0;--role)close_input(&input_owner.media_fds[role],e);
    while(input_owner.runtime_count){
        unsigned int role=--input_owner.runtime_count;
        close_input(&input_owner.runtime_fds[role],e);
    }
    while(input_owner.journal_count){
        unsigned int role=--input_owner.journal_count;
        close_input(&input_owner.journal_fds[role],e);
    }
    while(input_owner.view_count){
        unsigned int role=--input_owner.view_count;
        close_input(&input_owner.view_fds[role],e);
    }
    for(int role=input_owner.project_route?10:4;role>=0;--role){
        if(role==0&&input_owner.project_route)input_owner.fds[0]=-1; /* borrowed */
        else close_input(&input_owner.fds[role],e);
    }
#ifdef RNR_STAGE0_PRIVATE_QUALIFICATION
    if(input_owner.project_held){
        input_owner.project_held=0;
        if(rnr_stage0_abandon_project_view(&e->project_cleanup)!=0)
            reject_input(e,RNR_STAGE0_PREPARER_CLEANUP,e->project_cleanup.system_errno);
    }
#endif
}

static int open_input(int parent,const char *name,int directory,int *slot,
                      struct rnr_stage0_preparer_error *e)
{
    if(live_input(e)!=0)return -1;
    int flags=O_RDONLY|O_NOFOLLOW|O_CLOEXEC|(directory?O_DIRECTORY:O_NONBLOCK);
    int fd=parent<0?open(name,flags):openat(parent,name,flags);
    if(fd<0)return failed_input(e,RNR_STAGE0_PREPARER_OPEN,errno);
    if(fd<3){
        /* This contradicts admitted stdio/single-owner assumptions. Do not
         * repair by adopting/closing a standard-stream slot. Retain evidence. */
        e->unadopted_fd=fd;return failed_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);
    }
    *slot=fd; /* register BEFORE any post-open clock or metadata observation */
    return live_input(e);
}
static int stat_input(int fd,struct stat *s,struct rnr_stage0_preparer_error *e)
{
    if(live_input(e)!=0)return -1;
    if(fstat(fd,s)!=0)return failed_input(e,RNR_STAGE0_PREPARER_METADATA,errno);
    return live_input(e);
}
static int mount_input(int fd,uint64_t *mount,struct rnr_stage0_preparer_error *e)
{
    struct statx s={0};
    if(live_input(e)!=0)return -1;
    if(statx(fd,"",AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW,STATX_MNT_ID,&s)!=0){
        return failed_input(e,RNR_STAGE0_PREPARER_METADATA,errno);
    }
    if(live_input(e)!=0)return -1;
    if(!(s.stx_mask&STATX_MNT_ID) || !s.stx_mnt_id){
        reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;
    }
    *mount=s.stx_mnt_id;return 0;
}
static int filesystem_input(int fd,long *type,struct rnr_stage0_preparer_error *e)
{
    struct statfs s;
    if(live_input(e)!=0)return -1;
    if(fstatfs(fd,&s)!=0)return failed_input(e,RNR_STAGE0_PREPARER_METADATA,errno);
    if(live_input(e)!=0)return -1;
    *type=s.f_type;return 0;
}
static int same_input(const struct stat *a,const struct stat *b,int directory)
{
    if(a->st_dev!=b->st_dev || a->st_ino!=b->st_ino || a->st_mode!=b->st_mode ||
       a->st_uid!=b->st_uid || a->st_gid!=b->st_gid || a->st_rdev!=b->st_rdev)return 0;
    return directory || (a->st_nlink==b->st_nlink && a->st_size==b->st_size &&
        a->st_mtim.tv_sec==b->st_mtim.tv_sec && a->st_mtim.tv_nsec==b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec==b->st_ctim.tv_sec && a->st_ctim.tv_nsec==b->st_ctim.tv_nsec);
}
static int capture_input(int role,struct rnr_stage0_preparer_error *e)
{
    struct stat *s=&input_owner.identities[role];int fd=input_owner.fds[role];
    if(stat_input(fd,s,e)!=0 || mount_input(fd,&input_owner.mounts[role],e)!=0)return -1;
    if(s->st_uid!=0 || s->st_gid!=0 ||
       (role<3||role==5||role==6?(!S_ISDIR(s->st_mode)||(s->st_mode&022)||
            (role==6&&(s->st_mode&07777)!=0700)):
        (!S_ISREG(s->st_mode)||(s->st_mode&07777)!=(input_owner.project_route?0400:0444)||s->st_nlink!=1))){
        reject_input(e,RNR_STAGE0_PREPARER_METADATA,0);return -1;
    }
    if(role==0 && filesystem_input(fd,&input_owner.root_filesystem,e)!=0)return -1;
    return 0;
}
static int read_input(int role,unsigned char *bytes,size_t minimum,size_t maximum,
                      struct rnr_stage0_preparer_error *e)
{
    const struct stat *s=&input_owner.identities[role];int fd=input_owner.fds[role];
    if(s->st_size<(off_t)minimum || s->st_size>(off_t)maximum){
        reject_input(e,RNR_STAGE0_PREPARER_METADATA,0);return -1;
    }
    size_t length=(size_t)s->st_size;
    for(size_t offset=0;offset<length;){
        size_t count=length-offset;if(count>32768)count=32768;
        if(live_input(e)!=0)return -1;
        ssize_t n=pread(fd,bytes+offset,count,(off_t)offset);
        if(n<0)return failed_input(e,RNR_STAGE0_PREPARER_READ,errno);
        if((size_t)n!=count)return failed_input(e,RNR_STAGE0_PREPARER_READ,0);
        if(live_input(e)!=0)return -1;
        offset+=count;
    }
    unsigned char extra;struct stat after;uint64_t mount;
    if(live_input(e)!=0)return -1;
    ssize_t n=pread(fd,&extra,1,(off_t)length);
    if(n<0)return failed_input(e,RNR_STAGE0_PREPARER_READ,errno);
    if(n!=0)return failed_input(e,RNR_STAGE0_PREPARER_READ,0);
    if(live_input(e)!=0)return -1;
    if(stat_input(fd,&after,e)!=0 || mount_input(fd,&mount,e)!=0)return -1;
    if(!same_input(s,&after,0) || mount!=input_owner.mounts[role]){
        reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;
    }
    return 0;
}
static int recheck_input(int role,struct rnr_stage0_preparer_error *e)
{
    const char *const names[]={"/","etc","rnr","installation.bin","task.bin","projects",input_owner.project,
        "admission-policy.bin","configuration.json","enrollment.json","startup-manifest.json"};
    const int parents[]={-1,0,1,input_owner.project_route?6:2,input_owner.project_route?6:2,2,5,6,6,6,6};
    int directory=role<3||role==5||role==6;
    int fd=input_owner.fds[role],temporary=-1;struct stat held,named;uint64_t mount;
    if(stat_input(fd,&held,e)!=0 || mount_input(fd,&mount,e)!=0)return -1;
    if(!same_input(&held,&input_owner.identities[role],directory) || mount!=input_owner.mounts[role]){
        reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;
    }
    int postroot=input_owner.root_steps[1].entered && input_owner.root_steps[1].returned && input_owner.root_steps[1].result==0;
    int parent=role?input_owner.fds[parents[role]]:postroot?input_owner.fds[0]:-1;
    if(role==0 && postroot){long fs;
        if(filesystem_input(fd,&fs,e)!=0)return -1;
        if(fs!=input_owner.root_filesystem){reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;}
    }
    if(open_input(parent,role==0&&postroot?".":names[role],directory,&temporary,e)!=0)goto done;
    if(stat_input(temporary,&named,e)!=0 || mount_input(temporary,&mount,e)!=0)goto done;
    if(!same_input(&named,&input_owner.identities[role],directory) || mount!=input_owner.mounts[role]){
        reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);goto done;
    }
    if(role==0){
        long fs;
        if(filesystem_input(temporary,&fs,e)!=0)goto done;
        if(fs!=input_owner.root_filesystem){reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);goto done;}
    }
    (void)live_input(e);
done:
    close_input(&temporary,e);
    if(e->code==RNR_STAGE0_PREPARER_OK)(void)live_input(e);
    return e->code==RNR_STAGE0_PREPARER_OK?0:-1;
}
static int read_fixed_inputs(size_t installation_size,struct rnr_stage0_preparer_error *e)
{
    if(!input_owner.project_route&&open_input(-1,"/",1,&input_owner.fds[0],e)!=0)return -1;
    if(capture_input(0,e)!=0)return -1;
    if(open_input(input_owner.fds[0],"etc",1,&input_owner.fds[1],e)!=0 || capture_input(1,e)!=0)return -1;
    if(open_input(input_owner.fds[1],"rnr",1,&input_owner.fds[2],e)!=0 || capture_input(2,e)!=0)return -1;
    int parent=input_owner.fds[2];
    if(input_owner.project_route){
        if(open_input(parent,"projects",1,&input_owner.fds[5],e)!=0||capture_input(5,e)!=0||
           open_input(input_owner.fds[5],input_owner.project,1,&input_owner.fds[6],e)!=0||capture_input(6,e)!=0)return -1;
        parent=input_owner.fds[6];
    }
    if(open_input(parent,"installation.bin",0,&input_owner.fds[3],e)!=0 ||
       capture_input(3,e)!=0 || read_input(3,input_owner.installation_raw,installation_size,installation_size,e)!=0)return -1;
    if(open_input(parent,"task.bin",0,&input_owner.fds[4],e)!=0 ||
       capture_input(4,e)!=0 || read_input(4,input_owner.task_raw,65,65600,e)!=0)return -1;
    if(live_input(e)!=0)return -1;
    if(rnr_stage0_decode_installation(input_owner.installation_raw,installation_size,&input_owner.installation)!=0)
        return failed_input(e,RNR_STAGE0_PREPARER_DECODE,0);
    if(live_input(e)!=0)return -1;
    if(rnr_stage0_decode_task(input_owner.task_raw,(size_t)input_owner.identities[4].st_size,&input_owner.task)!=0)
        return failed_input(e,RNR_STAGE0_PREPARER_DECODE,0);
    return live_input(e);
}
#ifdef RNR_STAGE0_PRIVATE_QUALIFICATION
/* Fixed protected policy/reference files. Digests cover the bytes actually
 * read under the original clock; these checks do not establish installer trust. */
static int digest_policy_bytes(const unsigned char *bytes,size_t size,unsigned char out[32],
                               struct rnr_stage0_preparer_error *e)
{
    SHA2_CTX context;
    if(live_input(e)!=0)return -1;
    SHA256Init(&context);
    if(live_input(e)!=0)return -1;
    for(size_t offset=0;offset<size;){
        size_t n=size-offset;if(n>32768)n=32768;
        if(live_input(e)!=0)return -1;
        SHA256Update(&context,bytes+offset,n);
        if(live_input(e)!=0)return -1;
        offset+=n;
    }
    if(live_input(e)!=0)return -1;
    SHA256Final(out,&context);
    return live_input(e);
}
static int digest_file(int fd,const struct stat *identity,uint64_t original_mount,
                       size_t length,const unsigned char expected[32],
                       struct rnr_stage0_preparer_error *e)
{
    struct stat after;uint64_t mount;unsigned char digest[32],extra;
    SHA2_CTX context;
    if(identity->st_size!=(off_t)length){reject_input(e,RNR_STAGE0_PREPARER_METADATA,0);return -1;}
    if(live_input(e)!=0)return -1;
    SHA256Init(&context);
    if(live_input(e)!=0)return -1;
    for(size_t offset=0;offset<length;){
        size_t n=length-offset;if(n>sizeof(input_owner.policy_chunk))n=sizeof(input_owner.policy_chunk);
        if(live_input(e)!=0)return -1;
        ssize_t got=pread(fd,input_owner.policy_chunk,n,(off_t)offset);
        if(got<0)return failed_input(e,RNR_STAGE0_PREPARER_READ,errno);
        if((size_t)got!=n)return failed_input(e,RNR_STAGE0_PREPARER_READ,0);
        if(live_input(e)!=0)return -1;
        SHA256Update(&context,input_owner.policy_chunk,n);
        if(live_input(e)!=0)return -1;
        offset+=n;
    }
    if(live_input(e)!=0)return -1;
    ssize_t got=pread(fd,&extra,1,(off_t)length);
    if(got<0)return failed_input(e,RNR_STAGE0_PREPARER_READ,errno);
    if(got!=0)return failed_input(e,RNR_STAGE0_PREPARER_READ,0);
    if(live_input(e)!=0)return -1;
    SHA256Final(digest,&context);
    if(live_input(e)!=0)return -1;
    if(stat_input(fd,&after,e)!=0||mount_input(fd,&mount,e)!=0)return -1;
    if(!same_input(&after,identity,0)||mount!=original_mount||memcmp(digest,expected,32)){
        reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;
    }
    return 0;
}
static int read_project_policy(struct rnr_stage0_preparer_error *e)
{
    static const char *const names[]={"admission-policy.bin","configuration.json","enrollment.json","startup-manifest.json"};
    unsigned char digest[32];
    if(open_input(input_owner.fds[6],names[0],0,&input_owner.fds[7],e)!=0||capture_input(7,e)!=0||
       read_input(7,input_owner.policy_raw,9728,9728,e)!=0||
       digest_policy_bytes(input_owner.policy_raw,9728,digest,e)!=0)return -1;
    if(memcmp(digest,input_owner.installation.unit_policy_digest,32)){
        reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;
    }
    if(live_input(e)!=0)return -1;
    if(rnr_stage0_decode_policy(input_owner.policy_raw,9728,&input_owner.policy)!=0)
        return failed_input(e,RNR_STAGE0_PREPARER_DECODE,0);
    if(live_input(e)!=0)return -1;
    const struct rnr_stage0_policy *p=&input_owner.policy;
    const struct rnr_stage0_installation *i=&input_owner.installation;
    if(memcmp(p->project_id,i->project_id,32)||memcmp(p->store_instance,i->store_instance,16)||
       memcmp(p->boot_id,i->boot_id,37)||memcmp(p->configuration_digest,i->configuration_digest,32)||
       memcmp(p->enrollment_digest,i->enrollment_digest,32)||memcmp(p->startup_digest,i->startup_digest,32)||
       memcmp(p->execution_root,i->execution_root,32)||memcmp(p->asset_root,i->asset_root,32)){
        reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;
    }
    const size_t lengths[]={p->configuration_bytes,p->enrollment_bytes,p->startup_bytes};
    const unsigned char *const pins[]={p->configuration_digest,p->enrollment_digest,p->startup_digest};
    for(int n=0;n<3;++n){int role=8+n;
        if(open_input(input_owner.fds[6],names[n+1],0,&input_owner.fds[role],e)!=0||
           capture_input(role,e)!=0||digest_file(input_owner.fds[role],&input_owner.identities[role],input_owner.mounts[role],lengths[n],pins[n],e)!=0)return -1;
    }
    return 0;
}
/* The original process handles are borrowed from project_view. Only the
 * fixed installed ancestry is newly owned here; neither is a trust source. */
static int executable_profile(int fd,int directory,struct stat *s,uint64_t *mount,
                              struct rnr_stage0_preparer_error *e)
{
    if(stat_input(fd,s,e)!=0||mount_input(fd,mount,e)!=0)return -1;
    if(s->st_uid||s->st_gid||(s->st_mode&022)||
       (directory?!S_ISDIR(s->st_mode):(!S_ISREG(s->st_mode)||(s->st_mode&06000)||!(s->st_mode&0111)||!s->st_nlink))){
        reject_input(e,RNR_STAGE0_PREPARER_METADATA,0);return -1;
    }
    if(!directory){
        if(live_input(e)!=0)return -1;
        ssize_t n=fgetxattr(fd,"security.capability",NULL,0);int failure=n<0?errno:0;
        if(n>=0||failure!=ENODATA){
            return failed_input(e,RNR_STAGE0_PREPARER_METADATA,failure);
        }
        if(live_input(e)!=0)return -1;
    }
    return 0;
}
static int executable_header(int fd,struct rnr_stage0_preparer_error *e)
{
    Elf64_Ehdr h;
    if(live_input(e)!=0)return -1;
    ssize_t n=pread(fd,&h,sizeof(h),0);
    if(n<0)return failed_input(e,RNR_STAGE0_PREPARER_READ,errno);
    if(n!=(ssize_t)sizeof(h))return failed_input(e,RNR_STAGE0_PREPARER_READ,0);
    if(live_input(e)!=0)return -1;
    if(memcmp(h.e_ident,ELFMAG,SELFMAG)||h.e_ident[EI_CLASS]!=ELFCLASS64||h.e_ident[EI_DATA]!=ELFDATA2LSB||
       h.e_ident[EI_VERSION]!=EV_CURRENT||(h.e_type!=ET_EXEC&&h.e_type!=ET_DYN)||
       h.e_machine!=EM_X86_64||h.e_version!=EV_CURRENT||h.e_ehsize!=sizeof(h)){
        reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;
    }
    return 0;
}
static int executable_path(int role,int *parent,const char **name)
{
    static const int parents[8]={-1,0,1,2,3,4,1,6};
    const char *names[8]={"usr","lib","rnr","bootstraps",input_owner.native_hash,"rnr-stage0","systemd","systemd"};
    if(role<0||role>=8)return -1;
    *parent=parents[role]<0?input_owner.fds[0]:input_owner.executable_fds[parents[role]];
    *name=names[role];return 0;
}
static int executable_recheck(struct rnr_stage0_preparer_error *e)
{
    for(int role=0;role<8;++role){
        int parent,temporary=-1,directory=role!=5&&role!=7;const char *name;
        struct stat s;uint64_t mount;
        if(executable_profile(input_owner.executable_fds[role],directory,&s,&mount,e)!=0)return -1;
        if(!same_input(&s,&input_owner.executable_identities[role],directory)||mount!=input_owner.executable_mounts[role]){
            reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;
        }
        (void)executable_path(role,&parent,&name);
        if(open_input(parent,name,directory,&temporary,e)!=0)goto done;
        if(executable_profile(temporary,directory,&s,&mount,e)!=0)goto done;
        if(!same_input(&s,&input_owner.executable_identities[role],directory)||mount!=input_owner.executable_mounts[role])
            reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);
done:
        close_input(&temporary,e);
        if(e->code!=RNR_STAGE0_PREPARER_OK)return -1;
    }
    for(int i=0;i<3;++i){
        struct stat s;uint64_t mount;int role=i==2?7:5;
        if(executable_profile(input_owner.project_executables[i],0,&s,&mount,e)!=0)return -1;
        if(!same_input(&s,&input_owner.executable_identities[role],0)||mount!=input_owner.executable_mounts[role]){
            reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;
        }
    }
    return 0;
}
static int authenticate_executables(struct rnr_stage0_preparer_error *e)
{
    static const char hex[]="0123456789abcdef";
    for(int i=0;i<32;++i){unsigned int b=input_owner.policy.native_digest[i];
        input_owner.native_hash[2*i]=hex[b>>4];input_owner.native_hash[2*i+1]=hex[b&15];}
    input_owner.native_hash[64]=0;
    for(int i=0;i<8;++i)input_owner.executable_fds[i]=-1;
    input_owner.executables_initialized=1;
    for(int role=0;role<8;++role){
        int parent,directory=role!=5&&role!=7;const char *name;
        (void)executable_path(role,&parent,&name);
        if(open_input(parent,name,directory,&input_owner.executable_fds[role],e)!=0||
           executable_profile(input_owner.executable_fds[role],directory,&input_owner.executable_identities[role],
                              &input_owner.executable_mounts[role],e)!=0)return -1;
    }
    for(int i=0;i<5;++i){
        int role=i==2?5:i==4?7:i==3?7:5;
        int fd=i==2||i==4?input_owner.executable_fds[role]:input_owner.project_executables[i==3?2:i];
        const unsigned char *digest=role==5?input_owner.policy.native_digest:input_owner.policy.manager_digest;
        size_t length=(size_t)(role==5?input_owner.policy.native_bytes:input_owner.policy.manager_bytes);
        struct stat s;uint64_t mount;
        if(fd<3){reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;}
        if(executable_profile(fd,0,&s,&mount,e)!=0)return -1;
        if(!same_input(&s,&input_owner.executable_identities[role],0)||mount!=input_owner.executable_mounts[role]){
            reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;
        }
        if(executable_header(fd,e)!=0||digest_file(fd,&s,mount,length,digest,e)!=0)return -1;
    }
    return 0;
}
/* Unit names are fixed derivations. Directory observations use one serialized
 * temporary under the retained /etc; the four file descriptors remain held. */
static int open_beneath(int parent,const char *path,uint64_t flags,int *slot,struct rnr_stage0_preparer_error *e)
{
    const struct open_how how={.flags=flags,.resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS};
    if(live_input(e)!=0)return -1;
    long fd=syscall(SYS_openat2,parent,path,&how,sizeof(how));
    if(fd<0)return failed_input(e,RNR_STAGE0_PREPARER_OPEN,errno);
    if(fd<3||fd>INT_MAX){if(fd<=INT_MAX)e->unadopted_fd=(int)fd;return failed_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);}
    *slot=(int)fd;
    return live_input(e);
}
static int unit_open(const char *path,int directory,int *slot,struct rnr_stage0_preparer_error *e)
{return open_beneath(input_owner.fds[1],path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|(directory?O_DIRECTORY:O_NONBLOCK),slot,e);}
/* Observe the original manager search paths serially. These identities do not
 * establish the contents, alias map or overlay inventory of the directories. */
static int unit_search_directories(int capture,struct rnr_stage0_preparer_error *e)
{
    const struct open_how how={.flags=O_PATH|O_DIRECTORY|O_CLOEXEC,.resolve=RESOLVE_IN_ROOT};
    for(size_t i=0;i<input_owner.policy.unit_path_count;++i){
        const struct rnr_stage0_text_view *v=&input_owner.policy.unit_paths[i];
        char path[249];int fd=-1;struct stat s;uint64_t mount;
        if(!v->length||v->length>=sizeof(path)){reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;}
        memcpy(path,v->bytes,v->length);path[v->length]=0;
        if(live_input(e)!=0)return -1;
        long result=syscall(SYS_openat2,input_owner.fds[0],path,&how,sizeof(how));
        int failure=result<0?errno:0;
        if(result<0&&failure!=ENOENT)return failed_input(e,RNR_STAGE0_PREPARER_OPEN,failure);
        if(result>=0){
            if(result<3||result>INT_MAX){if(result<=INT_MAX)e->unadopted_fd=(int)result;return failed_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);}
            fd=(int)result;
        }
        if(live_input(e)!=0)goto done;
        if(result<0){
            if(capture)input_owner.search_present[i]=0;
            else if(input_owner.search_present[i]){reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;}
            continue;
        }
        if(stat_input(fd,&s,e)!=0||mount_input(fd,&mount,e)!=0)goto done;
        if(!S_ISDIR(s.st_mode)||!s.st_dev||!s.st_ino||s.st_uid||s.st_gid||(s.st_mode&022)){
            reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);goto done;
        }
        if(capture){input_owner.search_present[i]=1;input_owner.search_identities[i]=s;input_owner.search_mounts[i]=mount;}
        else if(!input_owner.search_present[i]||!same_input(&s,&input_owner.search_identities[i],1)||mount!=input_owner.search_mounts[i])
            reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);
done:
        close_input(&fd,e);
        if(e->code!=RNR_STAGE0_PREPARER_OK)return -1;
    }
    return 0;
}
/* Partial .conf inventory for the fixed names, type scopes and anchor prefix.
 * This is not an alias or dependency-directory inventory. */
static int unit_conf_overlays(struct rnr_stage0_preparer_error *e)
{
    char scopes[7][96]={{0}};
    const char *const formats[]={"service.d","slice.d","rnrc%s.service.d","rnrc%s.slice.d",
        "rnrw%s.slice.d","rnrw%s-anchor.slice.d","rnrw%s-.slice.d"};
    for(size_t i=0;i<7;++i){
        int n=i<2?snprintf(scopes[i],sizeof(scopes[i]),"%s",formats[i]):
            snprintf(scopes[i],sizeof(scopes[i]),formats[i],input_owner.project);
        if(n<=0||(size_t)n>=sizeof(scopes[i])){reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;}
    }
    const struct open_how how={.flags=O_RDONLY|O_DIRECTORY|O_CLOEXEC,.resolve=RESOLVE_IN_ROOT};
    for(size_t i=0;i<input_owner.policy.unit_path_count;++i)for(size_t scope=0;scope<7;++scope){
        const struct rnr_stage0_text_view *v=&input_owner.policy.unit_paths[i];
        char path[384];int fd=-1,eof=0;struct stat before,after;uint64_t mount,after_mount;unsigned int records=0;
        int n=snprintf(path,sizeof(path),"%.*s/%s",(int)v->length,(const char *)v->bytes,scopes[scope]);
        if(n<=0||(size_t)n>=sizeof(path)){reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;}
        if(live_input(e)!=0)return -1;
        long result=syscall(SYS_openat2,input_owner.fds[0],path,&how,sizeof(how));int failure=result<0?errno:0;
        if(result<0&&failure!=ENOENT&&failure!=ENOTDIR)return failed_input(e,RNR_STAGE0_PREPARER_OPEN,failure);
        if(result>=0){
            if(result<3||result>INT_MAX){if(result<=INT_MAX)e->unadopted_fd=(int)result;return failed_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);}
            fd=(int)result;
        }
        if(live_input(e)!=0)goto done;
        if(result<0)continue;
        if(stat_input(fd,&before,e)!=0||mount_input(fd,&mount,e)!=0)goto done;
        if(!S_ISDIR(before.st_mode)||!before.st_dev||!before.st_ino||before.st_uid||before.st_gid||(before.st_mode&022)){
            reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);goto done;
        }
        for(unsigned int reads=0;reads<17;++reads){
            unsigned char bytes[4096];if(live_input(e)!=0)goto done;
            long got=syscall(SYS_getdents64,fd,bytes,sizeof(bytes));
            if(got<0){(void)failed_input(e,RNR_STAGE0_PREPARER_READ,errno);goto done;}
            if(live_input(e)!=0)goto done;
            if(!got){eof=1;break;}
            if(got>(long)sizeof(bytes)){reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);goto done;}
            for(size_t off=0;off<(size_t)got;){
                uint16_t size;if(++records>512||(size_t)got-off<24)goto malformed;
                memcpy(&size,bytes+off+16,2);
                if(size<24||size%8||size>(size_t)got-off)goto malformed;
                const unsigned char *name=bytes+off+19,*end=memchr(name,0,size-19);
                if(!end||end==name||memchr(name,'/',(size_t)(end-name)))goto malformed;
                size_t length=(size_t)(end-name);
                if(name[0]!='.'&&length>=5&&!memcmp(end-5,".conf",5))goto malformed;
                off+=size;continue;
malformed:
                reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);goto done;
            }
        }
        if(!eof){reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);goto done;}
        if(stat_input(fd,&after,e)!=0||mount_input(fd,&after_mount,e)!=0)goto done;
        if(!same_input(&before,&after,1)||mount!=after_mount)reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);
done:
        close_input(&fd,e);
        if(e->code!=RNR_STAGE0_PREPARER_OK)return -1;
    }
    return 0;
}
/* Retain the fixed kernel directories. Mount-root provenance and control files
 * are separate required G1 checks; these observations alone grant no authority. */
static int cgroup_path(unsigned int role,int *parent,char name[96])
{
    static const int parents[]={-1,0,1,2,3,4,2,6};
    static const char *const names[]={"sys","fs","cgroup","rnrc%s.slice","rnrc%s.service","keeper","rnrw%s.slice","rnrw%s-anchor.slice"};
    if(role>=8)return -1;
    *parent=parents[role]<0?input_owner.fds[0]:input_owner.cgroup_fds[parents[role]];
    int n=role==3||role==4||role==6||role==7?snprintf(name,96,names[role],input_owner.project):snprintf(name,96,"%s",names[role]);
    return n>0&&n<96?0:-1;
}
static int cgroup_profile(unsigned int role,int fd,struct stat *s,uint64_t *mount,struct rnr_stage0_preparer_error *e)
{
    long filesystem;
    if(stat_input(fd,s,e)!=0||mount_input(fd,mount,e)!=0||filesystem_input(fd,&filesystem,e)!=0)return -1;
    if(!S_ISDIR(s->st_mode)||!s->st_dev||!s->st_ino||s->st_uid||s->st_gid||(s->st_mode&022)||
       filesystem!=(role<2?SYSFS_MAGIC:CGROUP2_SUPER_MAGIC)){
        reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;
    }
    return 0;
}
static int cgroup_kernel_ids(struct rnr_stage0_preparer_error *e)
{
    /* Linux kernfs encodes an eight-byte ID as FILEID_KERNFS (0xfe):
     * include/linux/exportfs.h and fs/kernfs/mount.c. */
    enum { RNR_FILEID_KERNFS=0xfe };
    static const unsigned int roles[]={4,3,6,7};
    for(unsigned int i=0;i<4;++i){
        union {struct file_handle handle;unsigned char bytes[sizeof(struct file_handle)+8];} h={0};
        unsigned int role=roles[i];int mount=-1;uint64_t id;
        h.handle.handle_bytes=8;
        if(live_input(e)!=0)return -1;
        if(syscall(SYS_name_to_handle_at,input_owner.cgroup_fds[role],"",&h.handle,&mount,AT_EMPTY_PATH)!=0)
            return failed_input(e,RNR_STAGE0_PREPARER_IDENTITY,errno);
        if(live_input(e)!=0)return -1;
        memcpy(&id,h.handle.f_handle,sizeof(id));
        if(h.handle.handle_type!=RNR_FILEID_KERNFS||h.handle.handle_bytes!=8||input_owner.cgroup_mounts[role]>UINT_MAX||
           (uint32_t)mount!=(uint32_t)input_owner.cgroup_mounts[role]||id!=input_owner.manager_cgroup_ids[i]){
            reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;
        }
    }
    return 0;
}
/* Only the held cgroup mount's exact mountinfo row is authority here. Other
 * rows are traversed solely to establish that its mount ID occurs once. */
static int mountinfo_decimal(const char *text)
{
    uint64_t value=0;if(!*text)return -1;
    for(;*text;++text){
        if(*text<'0'||*text>'9')return -1;
        unsigned int digit=(unsigned int)(*text-'0');
        if(value>(UINT64_MAX-digit)/10)return -1;
        value=value*10+digit;
    }
    return 0;
}
static char *mountinfo_token(char **rest)
{
    char *start=*rest;if(!start||!*start||*start==' ')return NULL;
    char *p=start;while(*p&&*p!=' ')++p;
    if(*p){*p++=0;if(!*p||*p==' ')return NULL;*rest=p;}
    else *rest=NULL;
    return start;
}
static int cgroup_mountinfo_line(char *line,uint64_t target,unsigned int *matches)
{
    char *p=line;uint64_t id=0;
    if(*p<'0'||*p>'9')return -1;
    while(*p>='0'&&*p<='9'){
        unsigned int digit=(unsigned int)(*p++-'0');
        if(id>(UINT64_MAX-digit)/10)return -1;
        id=id*10+digit;
    }
    if(*p!=' ')return -1;
    if(id!=target)return 0;
    if(++*matches!=1)return -1;
    char *fields[6];p=line;
    for(unsigned int i=0;i<6;++i)if(!(fields[i]=mountinfo_token(&p)))return -1;
    char *colon=strchr(fields[2],':');
    if(!colon||strchr(colon+1,':'))return -1;
    *colon++=0;
    if(mountinfo_decimal(fields[1])!=0||mountinfo_decimal(fields[2])!=0||mountinfo_decimal(colon)!=0||
       strcmp(fields[3],"/")||strcmp(fields[4],"/sys/fs/cgroup"))return -1;
    char *token;
    do{token=mountinfo_token(&p);if(!token)return -1;}while(strcmp(token,"-"));
    char *type=mountinfo_token(&p),*source=mountinfo_token(&p),*options=mountinfo_token(&p);
    return type&&source&&options&&!p&&!strcmp(type,"cgroup2")?0:-1;
}
static int cgroup_mount_root(struct rnr_stage0_preparer_error *e)
{
    int fd=-1;struct stat before,after;uint64_t proc_mount,mount;long filesystem;
    if(rnr_stage0_check_project_view(&e->project)!=0){reject_input(e,RNR_STAGE0_PREPARER_BOOTSTRAP,e->project.system_errno);return -1;}
    if(open_beneath(input_owner.fds[0],"proc",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC,&fd,e)!=0)goto done;
    if(stat_input(fd,&before,e)!=0||mount_input(fd,&proc_mount,e)!=0||filesystem_input(fd,&filesystem,e)!=0)goto done;
    if(!S_ISDIR(before.st_mode)||!before.st_ino||before.st_uid||before.st_gid||(before.st_mode&022)||filesystem!=PROC_SUPER_MAGIC){
        reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);goto done;}
    close_input(&fd,e);if(e->code!=RNR_STAGE0_PREPARER_OK)return -1;
    char path[64];int n=snprintf(path,sizeof(path),"proc/%ld/mountinfo",(long)getpid());
    if(n<=0||(size_t)n>=sizeof(path)){reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;}
    if(open_beneath(input_owner.fds[0],path,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC,&fd,e)!=0)goto done;
    if(stat_input(fd,&before,e)!=0||mount_input(fd,&mount,e)!=0||filesystem_input(fd,&filesystem,e)!=0)goto done;
    if(!S_ISREG(before.st_mode)||!before.st_ino||before.st_uid||before.st_gid||(before.st_mode&022)||
       mount!=proc_mount||filesystem!=PROC_SUPER_MAGIC){reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);goto done;}
    char line[4097],chunk[4096];size_t used=0,total=0;unsigned int matches=0;
    for(;;){
        size_t want=sizeof(chunk);if(want>1048577-total)want=1048577-total;
        if(live_input(e)!=0)goto done;
        ssize_t got=pread(fd,chunk,want,(off_t)total);
        if(got<0){(void)failed_input(e,RNR_STAGE0_PREPARER_READ,errno);goto done;}
        if(live_input(e)!=0)goto done;
        if(!got)break;
        if((size_t)got>1048576-total){reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);goto done;}
        total+=(size_t)got;
        for(ssize_t i=0;i<got;++i){
            unsigned char c=(unsigned char)chunk[i];
            if(!c){reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);goto done;}
            if(c=='\n'){
                line[used]=0;if(!used||cgroup_mountinfo_line(line,input_owner.cgroup_mounts[2],&matches)!=0){
                    reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);goto done;}
                used=0;
            }else{
                if(used==sizeof(line)-1){reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);goto done;}
                line[used++]=(char)c;
            }
        }
    }
    if(used||matches!=1){reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);goto done;}
    if(stat_input(fd,&after,e)!=0||mount_input(fd,&mount,e)!=0)goto done;
    if(!same_input(&before,&after,1)||mount!=proc_mount)reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);
done:
    close_input(&fd,e);
    if(e->code!=RNR_STAGE0_PREPARER_OK)return -1;
    if(rnr_stage0_check_project_view(&e->project)!=0){reject_input(e,RNR_STAGE0_PREPARER_BOOTSTRAP,e->project.system_errno);return -1;}
    return 0;
}
static int cgroup_read_contents(unsigned int role,const char *name,char actual[4097],size_t *length,
                                struct rnr_stage0_preparer_error *e)
{
    char extra;int fd=-1;struct stat before,after;uint64_t mount;long filesystem;
    *length=0;
    if(open_beneath(input_owner.cgroup_fds[role],name,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC,&fd,e)!=0)goto done;
    if(stat_input(fd,&before,e)!=0||mount_input(fd,&mount,e)!=0||filesystem_input(fd,&filesystem,e)!=0)goto done;
    if(!S_ISREG(before.st_mode)||!before.st_ino||before.st_uid||before.st_gid||(before.st_mode&022)||
       before.st_dev!=input_owner.cgroup_identities[role].st_dev||mount!=input_owner.cgroup_mounts[role]||
       filesystem!=CGROUP2_SUPER_MAGIC){reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);goto done;}
    if(live_input(e)!=0)goto done;
    ssize_t read_count=pread(fd,actual,4097,0);
    if(read_count<0){(void)failed_input(e,RNR_STAGE0_PREPARER_READ,errno);goto done;}
    if(live_input(e)!=0)goto done;
    if(read_count>4096){reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);goto done;}
    if(live_input(e)!=0)goto done;
    ssize_t end=pread(fd,&extra,1,(off_t)read_count);
    if(end<0){(void)failed_input(e,RNR_STAGE0_PREPARER_READ,errno);goto done;}
    if(live_input(e)!=0)goto done;
    if(end!=0){reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);goto done;}
    if(stat_input(fd,&after,e)!=0||mount_input(fd,&mount,e)!=0)goto done;
    if(!same_input(&before,&after,1)||mount!=input_owner.cgroup_mounts[role])reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);
    else *length=(size_t)read_count;
done:
    close_input(&fd,e);return e->code==RNR_STAGE0_PREPARER_OK?0:-1;
}
static int cgroup_read_expected(unsigned int role,const char *name,const char *const *expected,size_t count,
                                struct rnr_stage0_preparer_error *e)
{
    char actual[4097];size_t length;
    if(cgroup_read_contents(role,name,actual,&length,e)!=0)return -1;
    for(size_t i=0;i<count;++i){size_t n=strlen(expected[i]);
        if(length==n&&!memcmp(actual,expected[i],n))return 0;}
    reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;
}
static int controller_space(unsigned char c)
{return c==' '||c=='\n'||c=='\t'||c=='\r'||c=='\v'||c=='\f';}
static int cgroup_controller_tokens(const char *bytes,size_t length)
{
    uint16_t offsets[2048],sizes[2048];size_t pos=0,count=0;unsigned int required=0;
    while(pos<length){
        while(pos<length&&controller_space((unsigned char)bytes[pos]))++pos;
        if(pos==length)break;
        size_t start=pos;if(bytes[pos]<'a'||bytes[pos]>'z')return -1;
        while(pos<length&&!controller_space((unsigned char)bytes[pos])){
            unsigned char c=(unsigned char)bytes[pos++];
            if(!((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='_'))return -1;
        }
        size_t n=pos-start;if(count==2048)return -1;
        for(size_t i=0;i<count;++i)if(sizes[i]==n&&!memcmp(bytes+offsets[i],bytes+start,n))return -1;
        offsets[count]=(uint16_t)start;sizes[count++]=(uint16_t)n;
        if(n==3&&!memcmp(bytes+start,"cpu",3))required|=1;
        else if(n==6&&!memcmp(bytes+start,"memory",6))required|=2;
        else if(n==4&&!memcmp(bytes+start,"pids",4))required|=4;
    }
    return required==7?0:-1;
}
static int cgroup_controllers(struct rnr_stage0_preparer_error *e)
{
    static const unsigned int roles[]={2,3,4,6};
    static const char *const names[]={"cgroup.controllers","cgroup.subtree_control"};
    for(size_t role=0;role<4;++role)for(size_t field=0;field<2;++field){
        char actual[4097];size_t length;
        if(cgroup_read_contents(roles[role],names[field],actual,&length,e)!=0)return -1;
        if(cgroup_controller_tokens(actual,length)!=0){reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;}
    }
    return 0;
}
static int cgroup_controls(struct rnr_stage0_preparer_error *e)
{
    static const unsigned int roles[]={4,3,6,7};
    static const char *const names[]={"cgroup.type","cpu.max","memory.max","memory.swap.max","pids.max","memory.oom.group"};
    for(unsigned int unit=0;unit<4;++unit)for(unsigned int field=0;field<6;++field){
        const struct rnr_stage0_policy_unit *p=&input_owner.policy.units[unit];
        unsigned int role=roles[unit];char expected[80];int n;
        if(field==0)n=snprintf(expected,sizeof(expected),"domain\n");
        else if(field==1)n=snprintf(expected,sizeof(expected),"%llu %llu\n",(unsigned long long)(p->cpu_millis*100),
                                     (unsigned long long)p->cpu_period_us);
        else if(field==2)n=snprintf(expected,sizeof(expected),"%llu\n",(unsigned long long)p->memory_bytes);
        else if(field==3)n=snprintf(expected,sizeof(expected),"%llu\n",(unsigned long long)p->swap_bytes);
        else if(field==4)n=snprintf(expected,sizeof(expected),"%llu\n",(unsigned long long)p->pids);
        else n=snprintf(expected,sizeof(expected),"0\n");
        if(n<=0||(size_t)n>=sizeof(expected)){reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;}
        const char *values[]={expected};
        if(cgroup_read_expected(role,names[field],values,1,e)!=0)return -1;
    }
    const char *keeper_oom[]={"0\n"};
    return cgroup_read_expected(5,"memory.oom.group",keeper_oom,1,e);
}
static int cgroup_state(struct rnr_stage0_preparer_error *e)
{
    static const unsigned int roles[]={4,3,6,7,5};
    static const char *const thawed[]={"populated 1\nfrozen 0\n","frozen 0\npopulated 1\n"};
    static const char *const frozen[]={"populated 0\nfrozen 1\n","frozen 1\npopulated 0\n",
                                       "populated 1\nfrozen 1\n","frozen 1\npopulated 1\n"};
    static const char *const empty[]={""};
    for(unsigned int i=0;i<5;++i){
        const char *freeze=roles[i]==6?"1\n":"0\n";
        if(cgroup_read_expected(roles[i],"cgroup.freeze",&freeze,1,e)!=0)return -1;
        const char *const *events=roles[i]==6||roles[i]==7?frozen:thawed;
        size_t count=roles[i]==6?4:2;
        if(cgroup_read_expected(roles[i],"cgroup.events",events,count,e)!=0)return -1;
    }
    if(cgroup_read_expected(7,"cgroup.procs",empty,1,e)!=0||cgroup_read_expected(7,"cgroup.threads",empty,1,e)!=0)return -1;
    return 0;
}
static int cgroup_membership(struct rnr_stage0_preparer_error *e)
{
    static const unsigned int empty_roles[]={3,4,6};
    static const char *const names[]={"cgroup.procs","cgroup.threads"};
    static const char *const empty[]={""};
    char keeper_first[64],child_first[64];
    long child=(long)getpid(),keeper=(long)input_owner.original_keeper;
    int a=snprintf(keeper_first,sizeof(keeper_first),"%ld\n%ld\n",keeper,child);
    int b=snprintf(child_first,sizeof(child_first),"%ld\n%ld\n",child,keeper);
    if(child<=1||keeper<=1||child==keeper||a<=0||b<=0||
       (size_t)a>=sizeof(keeper_first)||(size_t)b>=sizeof(child_first)){
        reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;
    }
    const char *members[]={keeper_first,child_first};
    for(size_t field=0;field<2;++field){
        for(size_t role=0;role<3;++role)
            if(cgroup_read_expected(empty_roles[role],names[field],empty,1,e)!=0)return -1;
        if(cgroup_read_expected(5,names[field],members,2,e)!=0)return -1;
    }
    return 0;
}
static int cgroup_anchor_empty(struct rnr_stage0_preparer_error *e)
{
    int parent,fd=-1,eof=0;char name[96];struct stat s;uint64_t mount;unsigned int seen=0,records=0;
    if(cgroup_path(7,&parent,name)!=0){reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;}
    if(open_beneath(parent,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC,&fd,e)!=0)goto done;
    if(cgroup_profile(7,fd,&s,&mount,e)!=0)goto done;
    if(!same_input(&s,&input_owner.cgroup_identities[7],1)||mount!=input_owner.cgroup_mounts[7]){
        reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);goto done;}
    for(unsigned int reads=0;reads<17;++reads){
        unsigned char bytes[4096];if(live_input(e)!=0)goto done;
        long n=syscall(SYS_getdents64,fd,bytes,sizeof(bytes));
        if(n<0){(void)failed_input(e,RNR_STAGE0_PREPARER_READ,errno);goto done;}
        if(live_input(e)!=0)goto done;
        if(!n){eof=1;break;}
        if(n>(long)sizeof(bytes)){reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);goto done;}
        for(size_t off=0;off<(size_t)n;){
            uint16_t size;uint64_t inode;int64_t next;
            if(++records>512||(size_t)n-off<24)goto malformed;
            memcpy(&inode,bytes+off,8);memcpy(&next,bytes+off+8,8);memcpy(&size,bytes+off+16,2);
            if(!inode||next<=0||size<24||size%8||size>(size_t)n-off)goto malformed;
            const unsigned char *entry=bytes+off+19,*end=memchr(entry,0,size-19);
            if(!end||end==entry||memchr(entry,'/',(size_t)(end-entry)))goto malformed;
            unsigned int bit=0;
            if(end-entry==1&&entry[0]=='.')bit=1;
            else if(end-entry==2&&entry[0]=='.'&&entry[1]=='.')bit=2;
            if(bit){if(bytes[off+18]!=DT_DIR||(seen&bit))goto malformed;seen|=bit;}
            else if(bytes[off+18]!=DT_REG)goto malformed;
            off+=size;continue;
malformed:
            reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);goto done;
        }
    }
    if(!eof||seen!=3)reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);
done:
    close_input(&fd,e);
    if(e->code!=RNR_STAGE0_PREPARER_OK)return -1;
    if(cgroup_profile(7,input_owner.cgroup_fds[7],&s,&mount,e)!=0)return -1;
    if(!same_input(&s,&input_owner.cgroup_identities[7],1)||mount!=input_owner.cgroup_mounts[7]){
        reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;}
    return 0;
}
static int cgroup_recheck(struct rnr_stage0_preparer_error *e)
{
    for(unsigned int role=0;role<8;++role){
        int parent,fd=-1;char name[96];struct stat s;uint64_t mount;
        if(cgroup_path(role,&parent,name)!=0){reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;}
        if(cgroup_profile(role,input_owner.cgroup_fds[role],&s,&mount,e)!=0)return -1;
        if(!same_input(&s,&input_owner.cgroup_identities[role],1)||mount!=input_owner.cgroup_mounts[role]){
            reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;}
        if(open_beneath(parent,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC,&fd,e)!=0)goto done;
        if(cgroup_profile(role,fd,&s,&mount,e)!=0)goto done;
        if(!same_input(&s,&input_owner.cgroup_identities[role],1)||mount!=input_owner.cgroup_mounts[role])
            reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);
done:
        close_input(&fd,e);
        if(e->code!=RNR_STAGE0_PREPARER_OK)return -1;
    }
    if(cgroup_mount_root(e)!=0||cgroup_kernel_ids(e)!=0)return -1;
    if(cgroup_controls(e)!=0)return -1;
    if(cgroup_controllers(e)!=0)return -1;
    if(cgroup_state(e)!=0)return -1;
    if(cgroup_membership(e)!=0)return -1;
    return cgroup_anchor_empty(e);
}
static int cgroup_capture(struct rnr_stage0_preparer_error *e)
{
    for(int i=0;i<8;++i)input_owner.cgroup_fds[i]=-1;
    input_owner.cgroup_initialized=1;
    for(unsigned int role=0;role<8;++role){
        int parent;char name[96];
        if(cgroup_path(role,&parent,name)!=0){reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;}
        if(open_beneath(parent,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC,&input_owner.cgroup_fds[role],e)!=0||
           cgroup_profile(role,input_owner.cgroup_fds[role],&input_owner.cgroup_identities[role],&input_owner.cgroup_mounts[role],e)!=0)return -1;
        if((role==1&&(input_owner.cgroup_mounts[role]!=input_owner.cgroup_mounts[0]||
                      input_owner.cgroup_identities[role].st_dev!=input_owner.cgroup_identities[0].st_dev))||
           (role>2&&(input_owner.cgroup_mounts[role]!=input_owner.cgroup_mounts[2]||
                     input_owner.cgroup_identities[role].st_dev!=input_owner.cgroup_identities[2].st_dev))){
            reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;}
    }
    return cgroup_recheck(e);
}
static int unit_profile(int fd,int directory,struct stat *s,uint64_t *mount,
                        struct rnr_stage0_preparer_error *e)
{
    if(stat_input(fd,s,e)!=0||mount_input(fd,mount,e)!=0)return -1;
    if(s->st_uid||s->st_gid||(s->st_mode&022)||
       (directory?!S_ISDIR(s->st_mode):(!S_ISREG(s->st_mode)||!s->st_nlink||s->st_size<0))){
        reject_input(e,RNR_STAGE0_PREPARER_METADATA,0);return -1;
    }
    return 0;
}
static int unit_directories(int capture,struct rnr_stage0_preparer_error *e)
{
    static const char *const paths[]={"systemd","systemd/system"};
    for(int i=0;i<2;++i){
        int fd=-1;struct stat s;uint64_t mount;
        if(unit_open(paths[i],1,&fd,e)!=0)goto done;
        if(unit_profile(fd,1,&s,&mount,e)!=0)goto done;
        if(capture){input_owner.unit_identities[4+i]=s;input_owner.unit_mounts[4+i]=mount;}
        else if(!same_input(&s,&input_owner.unit_identities[4+i],1)||mount!=input_owner.unit_mounts[4+i])
            reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);
done:
        close_input(&fd,e);
        if(e->code!=RNR_STAGE0_PREPARER_OK)return -1;
    }
    return 0;
}
static int unit_recheck(struct rnr_stage0_preparer_error *e)
{
    if(unit_directories(0,e)!=0)return -1;
    for(int i=0;i<4;++i){
        int fd=-1;struct stat s;uint64_t mount;
        if(unit_profile(input_owner.unit_fds[i],0,&s,&mount,e)!=0)return -1;
        if(!same_input(&s,&input_owner.unit_identities[i],0)||mount!=input_owner.unit_mounts[i]){
            reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;}
        if(unit_open(input_owner.unit_paths[i],0,&fd,e)!=0)goto done;
        if(unit_profile(fd,0,&s,&mount,e)!=0)goto done;
        if(!same_input(&s,&input_owner.unit_identities[i],0)||mount!=input_owner.unit_mounts[i])
            reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);
done:
        close_input(&fd,e);
        if(e->code!=RNR_STAGE0_PREPARER_OK)return -1;
    }
    return 0;
}
static int authenticate_unit_fragments(struct rnr_stage0_preparer_error *e)
{
    static const char *const formats[]={"systemd/system/rnrc%s.service","systemd/system/rnrc%s.slice",
        "systemd/system/rnrw%s.slice","systemd/system/rnrw%s-anchor.slice"};
    for(int i=0;i<4;++i)input_owner.unit_fds[i]=-1;
    input_owner.units_initialized=1;
    if(unit_directories(1,e)!=0)return -1;
    for(int i=0;i<4;++i){
        int n=snprintf(input_owner.unit_paths[i],sizeof(input_owner.unit_paths[i]),formats[i],input_owner.project);
        if(n<=0||(size_t)n>=sizeof(input_owner.unit_paths[i])){reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;}
        if(unit_open(input_owner.unit_paths[i],0,&input_owner.unit_fds[i],e)!=0||
           unit_profile(input_owner.unit_fds[i],0,&input_owner.unit_identities[i],&input_owner.unit_mounts[i],e)!=0)return -1;
        size_t length=(size_t)input_owner.unit_identities[i].st_size;
        if((uintmax_t)length!=(uintmax_t)input_owner.unit_identities[i].st_size){reject_input(e,RNR_STAGE0_PREPARER_METADATA,0);return -1;}
        if(digest_file(input_owner.unit_fds[i],&input_owner.unit_identities[i],input_owner.unit_mounts[i],
                       length,input_owner.policy.units[i].fragment_digest,e)!=0)return -1;
    }
    return 0;
}
/* Absolute manager paths must resolve from the same original root. */
static int original_working_directory(struct rnr_stage0_preparer_error *e)
{
    int fd=-1;struct stat s;uint64_t mount;
    if(recheck_input(0,e)!=0)return -1;
    if(open_input(-1,".",1,&fd,e)!=0)goto done;
    if(stat_input(fd,&s,e)!=0||mount_input(fd,&mount,e)!=0)goto done;
    if(!same_input(&s,&input_owner.identities[0],1)||mount!=input_owner.mounts[0])
        reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);
done:
    close_input(&fd,e);
    return e->code==RNR_STAGE0_PREPARER_OK?0:-1;
}
/* Fixed original manager socket. A successfully authenticated peer is still
 * not admission: properties, kernel controls and the final sweep remain open. */
static int manager_paths(int capture,struct rnr_stage0_preparer_error *e)
{
    static const char *const paths[]={"run","run/systemd","run/systemd/private"};
    for(int i=0;i<3;++i){
        int fd=-1;struct stat s;uint64_t mount;
        uint64_t flags=(i==2?O_PATH:O_RDONLY|O_DIRECTORY)|O_NOFOLLOW|O_CLOEXEC;
        if(open_beneath(input_owner.fds[0],paths[i],flags,&fd,e)!=0)goto done;
        if(stat_input(fd,&s,e)!=0||mount_input(fd,&mount,e)!=0)goto done;
        if(s.st_uid||s.st_gid||(s.st_mode&022)||(i==2?!S_ISSOCK(s.st_mode):!S_ISDIR(s.st_mode))){
            reject_input(e,RNR_STAGE0_PREPARER_METADATA,0);goto done;}
        if(capture){input_owner.manager_identities[i]=s;input_owner.manager_mounts[i]=mount;}
        else if(!same_input(&s,&input_owner.manager_identities[i],i!=2)||mount!=input_owner.manager_mounts[i])
            reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);
done:
        close_input(&fd,e);
        if(e->code!=RNR_STAGE0_PREPARER_OK)return -1;
    }
    return 0;
}
static int manager_peer(struct rnr_stage0_preparer_error *e)
{
    struct ucred peer;socklen_t size=sizeof(peer);
    if(live_input(e)!=0)return -1;
    if(getsockopt(input_owner.manager_fd,SOL_SOCKET,SO_PEERCRED,&peer,&size)!=0)
        return failed_input(e,RNR_STAGE0_PREPARER_PID1,errno);
    if(live_input(e)!=0)return -1;
    if(size!=sizeof(peer)||peer.pid!=1||peer.uid||peer.gid){reject_input(e,RNR_STAGE0_PREPARER_PID1,0);return -1;}
    return 0;
}
static int manager_option(int option,struct rnr_stage0_preparer_error *e)
{
    int value=0;socklen_t size=sizeof(value);
    if(live_input(e)!=0)return -1;
    if(setsockopt(input_owner.manager_fd,SOL_SOCKET,option,&value,sizeof(value))!=0)
        return failed_input(e,RNR_STAGE0_PREPARER_PID1,errno);
    if(live_input(e)!=0)return -1;
    if(getsockopt(input_owner.manager_fd,SOL_SOCKET,option,&value,&size)!=0)
        return failed_input(e,RNR_STAGE0_PREPARER_PID1,errno);
    if(live_input(e)!=0)return -1;
    if(size!=sizeof(value)||value){reject_input(e,RNR_STAGE0_PREPARER_PID1,0);return -1;}
    return 0;
}
static int manager_poll(short events,struct rnr_stage0_preparer_error *e)
{
    struct pollfd p={.fd=input_owner.manager_fd,.events=events};
    if(++input_owner.manager_polls>4096){reject_input(e,RNR_STAGE0_PREPARER_PID1,0);return -1;}
    if(live_input(e)!=0)return -1;
    int result=poll(&p,1,1);
    if(result<0)return failed_input(e,RNR_STAGE0_PREPARER_PID1,errno);
    if(live_input(e)!=0)return -1;
    if(result!=1||p.revents!=events){reject_input(e,RNR_STAGE0_PREPARER_PID1,0);return -1;}
    return 0;
}
static int manager_send(const void *bytes,size_t length,struct rnr_stage0_preparer_error *e)
{
    if(live_input(e)!=0)return -1;
    ssize_t n=send(input_owner.manager_fd,bytes,length,MSG_NOSIGNAL);
    if(n<0)return failed_input(e,RNR_STAGE0_PREPARER_PID1,errno);
    if((size_t)n!=length)return failed_input(e,RNR_STAGE0_PREPARER_PID1,0);
    return live_input(e);
}
static int manager_authenticate(struct rnr_stage0_preparer_error *e)
{
    static const char auth[]="\0AUTH EXTERNAL 30\r\n",begin[]="BEGIN\r\n";
    unsigned char response[37];size_t offset=0;unsigned int fragments=0,polls=0;
    if(manager_send(auth,sizeof(auth)-1,e)!=0)return -1;
    while(offset<sizeof(response)){
        struct iovec iov={.iov_base=response+offset,.iov_len=sizeof(response)-offset};
        struct msghdr message={.msg_iov=&iov,.msg_iovlen=1};
        if(++input_owner.manager_receives>4096){reject_input(e,RNR_STAGE0_PREPARER_PID1,0);return -1;}
        if(live_input(e)!=0)return -1;
        ssize_t n=recvmsg(input_owner.manager_fd,&message,MSG_DONTWAIT|MSG_CMSG_CLOEXEC);int failure=n<0?errno:0;
        if(n<0&&failure!=EAGAIN&&failure!=EWOULDBLOCK)return failed_input(e,RNR_STAGE0_PREPARER_PID1,failure);
        if(live_input(e)!=0)return -1;
        if(n<0){
            if(++polls>128){reject_input(e,RNR_STAGE0_PREPARER_PID1,0);return -1;}
            if(manager_poll(POLLIN,e)!=0)return -1;
            continue;
        }
        if(!n||(size_t)n>sizeof(response)-offset||++fragments>37||
           (message.msg_flags&(MSG_CTRUNC|MSG_TRUNC))){reject_input(e,RNR_STAGE0_PREPARER_PID1,0);return -1;}
        offset+=(size_t)n;
    }
    if(memcmp(response,"OK ",3)||response[35]!='\r'||response[36]!='\n'){
        reject_input(e,RNR_STAGE0_PREPARER_PID1,0);return -1;}
    for(int i=3;i<35;++i)if(!((response[i]>='0'&&response[i]<='9')||(response[i]>='a'&&response[i]<='f'))){
        reject_input(e,RNR_STAGE0_PREPARER_PID1,0);return -1;}
    return manager_send(begin,sizeof(begin)-1,e);
}
static int manager_begin(struct rnr_stage0_preparer_error *e)
{
    input_owner.manager_fd=-1;input_owner.manager_initialized=1;
    if(manager_paths(1,e)!=0||original_working_directory(e)!=0)return -1;
    if(rnr_stage0_check_project_view(&e->project)!=0){reject_input(e,RNR_STAGE0_PREPARER_BOOTSTRAP,e->project.system_errno);return -1;}
    if(live_input(e)!=0)return -1;
    int fd=socket(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    if(fd<0)return failed_input(e,RNR_STAGE0_PREPARER_PID1,errno);
    if(fd<3){e->unadopted_fd=fd;return failed_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);}
    input_owner.manager_fd=fd;
    if(live_input(e)!=0||manager_option(SO_PASSCRED,e)!=0||manager_option(SO_PASSSEC,e)!=0)return -1;
    struct sockaddr_un address={.sun_family=AF_UNIX,.sun_path="/run/systemd/private"};
    if(live_input(e)!=0)return -1;
    int result=connect(fd,(struct sockaddr *)&address,offsetof(struct sockaddr_un,sun_path)+sizeof("/run/systemd/private"));
    int failure=result<0?errno:0;
    if(result<0&&failure!=EINPROGRESS)return failed_input(e,RNR_STAGE0_PREPARER_PID1,failure);
    if(live_input(e)!=0)return -1;
    if(result<0){int error=0;socklen_t size=sizeof(error);
        if(manager_poll(POLLOUT,e)!=0||live_input(e)!=0)return -1;
        if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&size)!=0)return failed_input(e,RNR_STAGE0_PREPARER_PID1,errno);
        if(live_input(e)!=0)return -1;
        if(size!=sizeof(error)||error){reject_input(e,RNR_STAGE0_PREPARER_PID1,error);return -1;}}
    if(original_working_directory(e)!=0||manager_paths(0,e)!=0||manager_peer(e)!=0)return -1;
    if(rnr_stage0_check_project_view(&e->project)!=0){reject_input(e,RNR_STAGE0_PREPARER_BOOTSTRAP,e->project.system_errno);return -1;}
    if(manager_authenticate(e)!=0||manager_peer(e)!=0||manager_paths(0,e)!=0||original_working_directory(e)!=0)return -1;
    if(rnr_stage0_check_project_view(&e->project)!=0){reject_input(e,RNR_STAGE0_PREPARER_BOOTSTRAP,e->project.system_errno);return -1;}
    return 0;
}
static void manager_put_u32(unsigned char *p,uint32_t n)
{for(int i=0;i<4;++i)p[i]=(unsigned char)(n>>(8*i));}
static uint32_t manager_u32(const unsigned char *p)
{return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
static int64_t manager_i32(const unsigned char *p)
{
    uint32_t value=manager_u32(p);
    return value<=INT32_MAX?(int64_t)value:(int64_t)value-INT64_C(4294967296);
}
static uint64_t manager_cgroup_limit(const struct rnr_stage0_policy_unit *unit,unsigned int field)
{
    switch(field){case 1:return unit->cpu_millis*1000;case 2:return unit->cpu_period_us;
        case 3:return unit->memory_bytes;case 4:return unit->swap_bytes;case 5:return unit->pids;default:return 0;}
}
static uint32_t manager_reserve_serial(struct rnr_stage0_preparer_error *e)
{
    if(input_owner.manager_serial>=512){reject_input(e,RNR_STAGE0_PREPARER_PID1,0);return 0;}
    return ++input_owner.manager_serial;
}
static int manager_receive(unsigned char *buffer,size_t length,unsigned int *fragments,
                           struct rnr_stage0_preparer_error *e)
{
    size_t offset=0;
    while(offset<length){
        struct iovec iov={.iov_base=buffer+offset,.iov_len=length-offset};
        struct msghdr message={.msg_iov=&iov,.msg_iovlen=1};
        if(++input_owner.manager_receives>4096){reject_input(e,RNR_STAGE0_PREPARER_PID1,0);return -1;}
        if(live_input(e)!=0)return -1;
        ssize_t n=recvmsg(input_owner.manager_fd,&message,MSG_DONTWAIT|MSG_CMSG_CLOEXEC);int failure=n<0?errno:0;
        if(n<0&&failure!=EAGAIN&&failure!=EWOULDBLOCK)return failed_input(e,RNR_STAGE0_PREPARER_PID1,failure);
        if(live_input(e)!=0)return -1;
        if(n<0){
            if(manager_poll(POLLIN,e)!=0)return -1;
            continue;
        }
        if(!n||(size_t)n>length-offset||++*fragments>512||(message.msg_flags&(MSG_CTRUNC|MSG_TRUNC))){
            reject_input(e,RNR_STAGE0_PREPARER_PID1,0);return -1;}
        offset+=(size_t)n;
    }
    return 0;
}
/* The only initial query is GetUnitByPID(original keeper). The fixed request
 * and the two permitted reply-header orders are not a general D-Bus API. */
static int manager_lookup_keeper(struct rnr_stage0_preparer_error *e)
{
    static const char path[]="/org/freedesktop/systemd1",interface[]="org.freedesktop.systemd1.Manager",member[]="GetUnitByPID";
    unsigned char fields_a[15]={5,1,'u',0,0,0,0,0,8,1,'g',0,1,'o',0};
    unsigned char fields_b[16]={8,1,'g',0,1,'o',0,0,5,1,'u',0,0,0,0,0};
    unsigned char request[140]={0},reply[146];char expected[128];
    if(input_owner.original_keeper<=1){reject_input(e,RNR_STAGE0_PREPARER_PID1,0);return -1;}
    int n=snprintf(expected,sizeof(expected),"/org/freedesktop/systemd1/unit/rnrc%s_2eservice",input_owner.project);
    if(n!=109){reject_input(e,RNR_STAGE0_PREPARER_PID1,0);return -1;}
    uint32_t serial=manager_reserve_serial(e);if(!serial)return -1;
    manager_put_u32(fields_a+4,serial);manager_put_u32(fields_b+12,serial);
    request[0]='l';request[1]=1;request[2]=2;request[3]=1;
    manager_put_u32(request+4,4);manager_put_u32(request+8,serial);manager_put_u32(request+12,119);
    request[16]=1;request[17]=1;request[18]='o';manager_put_u32(request+20,sizeof(path)-1);memcpy(request+24,path,sizeof(path)-1);
    request[56]=2;request[57]=1;request[58]='s';manager_put_u32(request+60,sizeof(interface)-1);memcpy(request+64,interface,sizeof(interface)-1);
    request[104]=3;request[105]=1;request[106]='s';manager_put_u32(request+108,sizeof(member)-1);memcpy(request+112,member,sizeof(member)-1);
    request[128]=8;request[129]=1;request[130]='g';request[132]=1;request[133]='u';
    manager_put_u32(request+136,(uint32_t)input_owner.original_keeper);
    struct iovec iov={.iov_base=request,.iov_len=sizeof(request)};
    struct msghdr message={.msg_iov=&iov,.msg_iovlen=1};
    if(manager_peer(e)!=0||live_input(e)!=0)return -1;
    ssize_t sent=sendmsg(input_owner.manager_fd,&message,MSG_NOSIGNAL);
    if(sent<0)return failed_input(e,RNR_STAGE0_PREPARER_PID1,errno);
    if((size_t)sent!=sizeof(request))return failed_input(e,RNR_STAGE0_PREPARER_PID1,0);
    if(live_input(e)!=0)return -1;
    unsigned int fragments=0;
    if(manager_receive(reply,16,&fragments,e)!=0)return -1;
    uint32_t body=manager_u32(reply+4),reply_serial=manager_u32(reply+8),fields=manager_u32(reply+12);
    if(reply[0]!='l'||reply[1]!=2||reply[2]!=1||reply[3]!=1||!reply_serial||body!=114||(fields!=15&&fields!=16)){
        reject_input(e,RNR_STAGE0_PREPARER_PID1,0);return -1;}
    if(manager_receive(reply+16,sizeof(reply)-16,&fragments,e)!=0)return -1;
    if((fields==15&&(memcmp(reply+16,fields_a,sizeof(fields_a))||reply[31]))||
       (fields==16&&memcmp(reply+16,fields_b,sizeof(fields_b)))||manager_u32(reply+32)!=(uint32_t)n||
       memcmp(reply+36,expected,(size_t)n+1)){
        reject_input(e,RNR_STAGE0_PREPARER_PID1,0);return -1;}
    if(manager_peer(e)!=0||manager_paths(0,e)!=0||original_working_directory(e)!=0)return -1;
    if(rnr_stage0_check_project_view(&e->project)!=0){reject_input(e,RNR_STAGE0_PREPARER_BOOTSTRAP,e->project.system_errno);return -1;}
    return 0;
}
/* UnitPath is a fixed query, not a caller-selected D-Bus operation. */
static int manager_unit_path(struct rnr_stage0_preparer_error *e)
{
    static const char path[]="/org/freedesktop/systemd1";
    static const char properties[]="org.freedesktop.DBus.Properties";
    static const char manager[]="org.freedesktop.systemd1.Manager";
    unsigned char fields_a[15]={5,1,'u',0,0,0,0,0,8,1,'g',0,1,'v',0};
    unsigned char fields_b[16]={8,1,'g',0,1,'v',0,0,5,1,'u',0,0,0,0,0};
    unsigned char request[173]={0},reply[16+16+16384];
    uint32_t serial=manager_reserve_serial(e);if(!serial)return -1;
    manager_put_u32(fields_a+4,serial);manager_put_u32(fields_b+12,serial);
    request[0]='l';request[1]=1;request[2]=2;request[3]=1;
    manager_put_u32(request+4,53);manager_put_u32(request+8,serial);manager_put_u32(request+12,104);
    request[16]=1;request[17]=1;request[18]='o';manager_put_u32(request+20,sizeof(path)-1);memcpy(request+24,path,sizeof(path)-1);
    request[56]=2;request[57]=1;request[58]='s';manager_put_u32(request+60,sizeof(properties)-1);memcpy(request+64,properties,sizeof(properties)-1);
    request[96]=3;request[97]=1;request[98]='s';manager_put_u32(request+100,3);memcpy(request+104,"Get",3);
    request[112]=8;request[113]=1;request[114]='g';request[116]=2;request[117]='s';request[118]='s';
    manager_put_u32(request+120,sizeof(manager)-1);memcpy(request+124,manager,sizeof(manager)-1);
    manager_put_u32(request+160,8);memcpy(request+164,"UnitPath",8);
    struct iovec iov={.iov_base=request,.iov_len=sizeof(request)};
    struct msghdr message={.msg_iov=&iov,.msg_iovlen=1};
    if(manager_peer(e)!=0||live_input(e)!=0)return -1;
    ssize_t sent=sendmsg(input_owner.manager_fd,&message,MSG_NOSIGNAL);
    if(sent<0)return failed_input(e,RNR_STAGE0_PREPARER_PID1,errno);
    if((size_t)sent!=sizeof(request))return failed_input(e,RNR_STAGE0_PREPARER_PID1,0);
    if(live_input(e)!=0)return -1;
    unsigned int fragments=0;
    if(manager_receive(reply,16,&fragments,e)!=0)return -1;
    uint32_t body=manager_u32(reply+4),fields=manager_u32(reply+12);
    if(reply[0]!='l'||reply[1]!=2||reply[2]!=1||reply[3]!=1||!manager_u32(reply+8)||
       body<8||body>16384||(fields!=15&&fields!=16))goto invalid;
    if(manager_receive(reply+16,16+(size_t)body,&fragments,e)!=0)return -1;
    if((fields==15&&(memcmp(reply+16,fields_a,sizeof(fields_a))||reply[31]))||
       (fields==16&&memcmp(reply+16,fields_b,sizeof(fields_b))))goto invalid;
    const unsigned char *b=reply+32;
    if(b[0]!=2||b[1]!='a'||b[2]!='s'||b[3]||manager_u32(b+4)!=body-8||body-8>8192)goto invalid;
    size_t pos=8;
    for(size_t i=0;i<input_owner.policy.unit_path_count;++i){
        while(pos%4){if(pos>=body||b[pos++])goto invalid;}
        if(pos>body||body-pos<4)goto invalid;
        uint32_t n=manager_u32(b+pos);pos+=4;
        if(n!=input_owner.policy.unit_paths[i].length||n>248||n>=body-pos||
           memcmp(b+pos,input_owner.policy.unit_paths[i].bytes,n)||b[pos+n])goto invalid;
        pos+=(size_t)n+1;
    }
    if(pos!=body)goto invalid;
    if(manager_peer(e)!=0||manager_paths(0,e)!=0||original_working_directory(e)!=0)return -1;
    if(rnr_stage0_check_project_view(&e->project)!=0){reject_input(e,RNR_STAGE0_PREPARER_BOOTSTRAP,e->project.system_errno);return -1;}
    return 0;
invalid:
    reject_input(e,RNR_STAGE0_PREPARER_PID1,0);return -1;
}
static int manager_check_unit_identities(struct rnr_stage0_preparer_error *e)
{
    static const char *const objects[]={"/org/freedesktop/systemd1/unit/rnrc%s_2eservice",
        "/org/freedesktop/systemd1/unit/rnrc%s_2eslice","/org/freedesktop/systemd1/unit/rnrw%s_2eslice",
        "/org/freedesktop/systemd1/unit/rnrw%s_2danchor_2eslice"};
    static const char *const names[]={"rnrc%s.service","rnrc%s.slice","rnrw%s.slice","rnrw%s-anchor.slice"};
    static const char *const fields[]={"LoadState","ActiveState","SubState","FragmentPath","SourcePath",
        "CollectMode","JobTimeoutAction","FailureAction","SuccessAction","StartLimitAction"};
    static const char *const boolean_fields[]={"NeedDaemonReload","Transient","DefaultDependencies",
        "RefuseManualStart","RefuseManualStop","IgnoreOnIsolate","StopWhenUnneeded"};
    static const char *const identity_fields[]={"InvocationID","Job"};
    static const char *const dependency_fields[]={"DropInPaths","Requires","Requisite","BindsTo","PartOf","ConsistsOf",
        "Conflicts","ConflictedBy","Before","After","OnFailure","OnSuccess","PropagatesStopTo","StopPropagatedFrom",
        "Triggers","TriggeredBy","RequiresMountsFor","Upholds","OnFailureOf","OnSuccessOf"};
    static const char *const timeout_fields[]={"JobTimeoutUSec","JobRunningTimeoutUSec"};
    static const char *const service_fields[]={"Type","ExitType","Restart","RestartMode","OOMPolicy","NotifyAccess","PIDFile",
        "TimeoutStartFailureMode","TimeoutStopFailureMode","User","Group","RootDirectory","RootImage","WorkingDirectory",
        "StandardInput","StandardOutput","StandardError","PAMName","BusName","KillMode"};
    static const char *const service_values[]={"exec","cgroup","no","normal","continue","none","",
        "terminate","terminate","root","root","","","","null","null","null","","","process"};
    static const char *const service_scalar_fields[]={"RemainAfterExit","DynamicUser","SendSIGKILL","SendSIGHUP",
        "RuntimeMaxUSec","RuntimeRandomizedExtraUSec","WatchdogUSec","LimitNOFILE","LimitNOFILESoft",
        "MainPID","ControlPID","NRestarts","FileDescriptorStoreMax","NFileDescriptorStore"};
    static const char service_scalar_types[]="bbbbtttttuuuuu";
    static const char *const service_empty_fields[]={"Environment","EnvironmentFiles","PassEnvironment","UnsetEnvironment",
        "RestartForceExitStatus","ExecConditionEx","ExecStartPreEx","ExecStartPostEx","ExecReloadEx","ExecStopEx","ExecStopPostEx"};
    static const char *const cgroup_string_fields[]={"Slice","ControlGroup","DelegateSubgroup","ManagedOOMSwap","ManagedOOMMemoryPressure"};
    static const char *const cgroup_scalar_fields[]={"Delegate","CPUQuotaPerSecUSec","CPUQuotaPeriodUSec","MemoryMax","MemorySwapMax","TasksMax"};
    static const char *const cgroup_array_fields[]={"DelegateControllers","DisableControllers"};
    static const char properties[]="org.freedesktop.DBus.Properties";
    for(unsigned int phase=0;phase<103;++phase)for(unsigned int role=0;role<(phase<43||phase>=89?4U:1U);++role){
        char object[160],unit[96],expected[192];unsigned char request[384]={0},reply[316];
        const char *property=phase<2?(phase?"Names":"Id"):phase<12?fields[phase-2]:phase<19?boolean_fields[phase-12]:
                             phase<21?identity_fields[phase-19]:phase<41?dependency_fields[phase-21]:phase<43?timeout_fields[phase-41]:
                             phase<63?service_fields[phase-43]:phase<77?service_scalar_fields[phase-63]:phase<88?service_empty_fields[phase-77]:
                             phase==88?"ExecStartEx":phase<94?cgroup_string_fields[phase-89]:phase<100?cgroup_scalar_fields[phase-94]:phase<102?cgroup_array_fields[phase-100]:"ControlGroupId";
        const char *interface=phase<43?"org.freedesktop.systemd1.Unit":phase>=89&&role?"org.freedesktop.systemd1.Slice":"org.freedesktop.systemd1.Service";
        size_t property_length=strlen(property);
        int on=snprintf(object,sizeof(object),objects[role],input_owner.project);
        int un=snprintf(unit,sizeof(unit),names[role],input_owner.project),en;
        if(on<=0||(size_t)on>=sizeof(object)||un<=0||(size_t)un>=sizeof(unit))goto invalid;
        if(phase>=94){expected[0]=0;en=0;
        }else if(phase>=89){
            if(phase==89)en=role==0?snprintf(expected,sizeof(expected),names[1],input_owner.project):
                role==3?snprintf(expected,sizeof(expected),names[2],input_owner.project):snprintf(expected,sizeof(expected),"-.slice");
            else if(phase==90){
                if(role==0)en=snprintf(expected,sizeof(expected),"/rnrc%s.slice/rnrc%s.service",input_owner.project,input_owner.project);
                else if(role==3)en=snprintf(expected,sizeof(expected),"/rnrw%s.slice/rnrw%s-anchor.slice",input_owner.project,input_owner.project);
                else en=snprintf(expected,sizeof(expected),"/%s",unit);
            }else en=snprintf(expected,sizeof(expected),"%s",phase==91?(role?"":"keeper"):"auto");
        }else if(phase>=63){expected[0]=0;en=0;}
        else if(phase>=43)en=snprintf(expected,sizeof(expected),"%s",service_values[phase-43]);
        else if(phase<2)en=snprintf(expected,sizeof(expected),"%s",unit);
        else if(phase==2)en=snprintf(expected,sizeof(expected),"loaded");
        else if(phase==3)en=snprintf(expected,sizeof(expected),"active");
        else if(phase==4)en=snprintf(expected,sizeof(expected),"%s",role?"active":"running");
        else if(phase==5)en=snprintf(expected,sizeof(expected),"/etc/systemd/system/%s",unit);
        else if(phase==6)en=snprintf(expected,sizeof(expected),"%s","");
        else if(phase==7)en=snprintf(expected,sizeof(expected),"inactive");
        else if(phase<12)en=snprintf(expected,sizeof(expected),"none");
        else if(phase<21){expected[0]=0;en=0;}
        else if(phase<41){
            unsigned int dep=phase-21;const char *format=NULL;
            if(dep==1||dep==9){if(role==0)format=names[1];else if(role==3)format=names[2];}
            else if(dep==8){if(role==1)format=names[0];else if(role==2)format=names[3];}
            if(format)en=snprintf(expected,sizeof(expected),format,input_owner.project);
            else if((dep==1||dep==9)&&(role==1||role==2))en=snprintf(expected,sizeof(expected),"-.slice");
            else{expected[0]=0;en=0;}
        }else{expected[0]=0;en=0;}
        if(en<0||(size_t)en>=sizeof(expected)||(size_t)en+((phase==1||(phase>=21&&phase<41))?45:41)>sizeof(reply))goto invalid;
        uint32_t serial=manager_reserve_serial(e);if(!serial)return -1;
        size_t p=16;request[p++]=1;request[p++]=1;request[p++]='o';++p;
        manager_put_u32(request+p,(uint32_t)on);p+=4;memcpy(request+p,object,(size_t)on+1);p+=(size_t)on+1;
        while(p%8)++p;
        request[p++]=2;request[p++]=1;request[p++]='s';++p;
        manager_put_u32(request+p,sizeof(properties)-1);p+=4;memcpy(request+p,properties,sizeof(properties));p+=sizeof(properties);
        request[p++]=3;request[p++]=1;request[p++]='s';++p;
        manager_put_u32(request+p,3);p+=4;memcpy(request+p,"Get",4);p+=4;
        while(p%8)++p;
        request[p++]=8;request[p++]=1;request[p++]='g';++p;request[p++]=2;request[p++]='s';request[p++]='s';++p;
        size_t fields=p-16,body_start=p,interface_length=strlen(interface);
        manager_put_u32(request+p,(uint32_t)interface_length);p+=4;memcpy(request+p,interface,interface_length+1);p+=interface_length+1;
        while(p%4)++p;
        manager_put_u32(request+p,(uint32_t)property_length);p+=4;memcpy(request+p,property,property_length+1);p+=property_length+1;
        request[0]='l';request[1]=1;request[2]=2;request[3]=1;
        manager_put_u32(request+4,(uint32_t)(p-body_start));manager_put_u32(request+8,serial);manager_put_u32(request+12,(uint32_t)fields);
        struct iovec iov={.iov_base=request,.iov_len=p};struct msghdr message={.msg_iov=&iov,.msg_iovlen=1};
        if(manager_peer(e)!=0||live_input(e)!=0)return -1;
        ssize_t sent=sendmsg(input_owner.manager_fd,&message,MSG_NOSIGNAL);
        if(sent<0)return failed_input(e,RNR_STAGE0_PREPARER_PID1,errno);
        if((size_t)sent!=p)return failed_input(e,RNR_STAGE0_PREPARER_PID1,0);
        if(live_input(e)!=0)return -1;
        unsigned int fragments=0;
        if(manager_receive(reply,16,&fragments,e)!=0)return -1;
        uint32_t body=manager_u32(reply+4),header=manager_u32(reply+12);
        if(reply[0]!='l'||reply[1]!=2||reply[2]!=1||reply[3]!=1||!manager_u32(reply+8)||
           body!=(phase==102?16:phase>=100?(phase==100&&role==0?37:8):phase>=94?(phase==94?8:16):phase>=89?(uint32_t)en+9:phase==88?284:phase>=77?((phase==78||phase==81)?16:phase>=82?24:8):phase>=63?(service_scalar_types[phase-63]=='t'?16:8):phase>=43?(uint32_t)en+9:phase>=41?16:phase>=21?(en?(uint32_t)en+13:8):phase==19?24:phase==20?18:phase>=12?8:
                  (uint32_t)en+(phase==1?13:9))||(header!=15&&header!=16))goto invalid;
        if(manager_receive(reply+16,16+(size_t)body,&fragments,e)!=0)return -1;
        unsigned char a[15]={5,1,'u',0,0,0,0,0,8,1,'g',0,1,'v',0};
        unsigned char b[16]={8,1,'g',0,1,'v',0,0,5,1,'u',0,0,0,0,0};
        manager_put_u32(a+4,serial);manager_put_u32(b+12,serial);
        if((header==15&&(memcmp(reply+16,a,sizeof(a))||reply[31]))||
           (header==16&&memcmp(reply+16,b,sizeof(b))))goto invalid;
        if(phase==102){
            static const unsigned char type[]={1,'t',0,0,0,0,0,0};
            if(memcmp(reply+32,type,sizeof(type)))goto invalid;
            uint64_t id=0;for(size_t i=0;i<8;++i)id|=(uint64_t)reply[40+i]<<(8*i);
            if(!id)goto invalid;
            input_owner.manager_cgroup_ids[role]=id;
        }else if(phase>=100){
            static const unsigned char empty[]={2,'a','s',0,0,0,0,0};
            static const unsigned char controllers[]={2,'a','s',0,29,0,0,0,3,0,0,0,'c','p','u',0,
                6,0,0,0,'m','e','m','o','r','y',0,0,4,0,0,0,'p','i','d','s',0};
            if(phase==100&&role==0){if(memcmp(reply+32,controllers,sizeof(controllers)))goto invalid;}
            else if(memcmp(reply+32,empty,sizeof(empty)))goto invalid;
        }else if(phase>=94){
            unsigned int field=phase-94;char type=field?'t':'b';
            uint64_t value=field?manager_cgroup_limit(&input_owner.policy.units[role],field):(role==0);
            if(reply[32]!=1||reply[33]!=(unsigned char)type||reply[34]||reply[35])goto invalid;
            size_t start=field?40:36,count=field?8:4;
            if(field&&(reply[36]||reply[37]||reply[38]||reply[39]))goto invalid;
            for(size_t i=0;i<count;++i)if(reply[start+i]!=(unsigned char)(value>>(8*i)))goto invalid;
        }else if(phase>=89){
            if(reply[32]!=1||reply[33]!='s'||reply[34]||reply[35]||manager_u32(reply+36)!=(uint32_t)en||
               memcmp(reply+40,expected,(size_t)en+1))goto invalid;
        }else if(phase==88){
            static const unsigned char start[]={15,'a','(','s','a','s','a','s','t','t','t','t','u','i','i',')',0,0,0,0,4,1,0,0};
            static const char prefix[]="/usr/lib/rnr/bootstraps/",suffix[]="/rnr-stage0",hex[]="0123456789abcdef";
            char executable[100];memcpy(executable,prefix,sizeof(prefix)-1);
            for(size_t i=0;i<32;++i){unsigned int byte=input_owner.policy.native_digest[i];
                executable[sizeof(prefix)-1+2*i]=hex[byte>>4];executable[sizeof(prefix)+2*i]=hex[byte&15];}
            memcpy(executable+sizeof(prefix)-1+64,suffix,sizeof(suffix));
            if(memcmp(reply+32,start,sizeof(start))||manager_u32(reply+56)!=99||memcmp(reply+60,executable,sizeof(executable))||
               manager_u32(reply+160)!=104||manager_u32(reply+164)!=99||memcmp(reply+168,executable,sizeof(executable))||
               manager_u32(reply+268)!=0||manager_u32(reply+304)!=(uint32_t)input_owner.original_keeper)goto invalid;
            for(size_t i=288;i<304;++i)if(reply[i])goto invalid;
            if(manager_i32(reply+308)!=0||manager_i32(reply+312)!=0)goto invalid;
        }else if(phase>=77){
            static const unsigned char as[]={2,'a','s',0,0,0,0,0};
            static const unsigned char asb[]={5,'a','(','s','b',')',0,0,0,0,0,0,0,0,0,0};
            static const unsigned char aiai[]={6,'(','a','i','a','i',')',0,0,0,0,0,0,0,0,0};
            static const unsigned char exec[]={15,'a','(','s','a','s','a','s','t','t','t','t','u','i','i',')',0,0,0,0,0,0,0,0};
            const unsigned char *v=phase==78?asb:phase==81?aiai:phase>=82?exec:as;
            size_t n=phase==78?sizeof(asb):phase==81?sizeof(aiai):phase>=82?sizeof(exec):sizeof(as);
            if(memcmp(reply+32,v,n))goto invalid;
        }else if(phase>=63){
            unsigned int field=phase-63;char type=service_scalar_types[field];
            uint64_t value=field==4?UINT64_MAX:(field==7||field==8)?256:field==9?(uint64_t)input_owner.original_keeper:0;
            if(reply[32]!=1||reply[33]!=(unsigned char)type||reply[34]||reply[35])goto invalid;
            size_t start=type=='t'?40:36,count=type=='t'?8:4;
            if(type=='t'&&(reply[36]||reply[37]||reply[38]||reply[39]))goto invalid;
            for(size_t i=0;i<count;++i)if(reply[start+i]!=(unsigned char)(value>>(8*i)))goto invalid;
        }else if(phase>=43){
            if(reply[32]!=1||reply[33]!='s'||reply[34]||reply[35]||manager_u32(reply+36)!=(uint32_t)en||
               memcmp(reply+40,expected,(size_t)en+1))goto invalid;
        }else if(phase>=41){
            static const unsigned char infinity[]={1,'t',0,0,0,0,0,0,255,255,255,255,255,255,255,255};
            if(memcmp(reply+32,infinity,sizeof(infinity)))goto invalid;
        }else if(phase>=21){
            if(reply[32]!=2||reply[33]!='a'||reply[34]!='s'||reply[35]||
               manager_u32(reply+36)!=(en?(uint32_t)en+5:0))goto invalid;
            if(en&&(manager_u32(reply+40)!=(uint32_t)en||memcmp(reply+44,expected,(size_t)en+1)))goto invalid;
        }else if(phase==19){
            if(reply[32]!=2||reply[33]!='a'||reply[34]!='y'||reply[35]||manager_u32(reply+36)!=16)goto invalid;
            unsigned int nonzero=0;for(size_t i=0;i<16;++i)nonzero|=reply[40+i];
            if(!nonzero)goto invalid;
            memcpy(input_owner.manager_invocations[role],reply+40,16);
        }else if(phase==20){
            static const unsigned char empty_job[]={4,'(','u','o',')',0,0,0,0,0,0,0,1,0,0,0,'/',0};
            if(memcmp(reply+32,empty_job,sizeof(empty_job)))goto invalid;
        }else if(phase>=12){
            if(reply[32]!=1||reply[33]!='b'||reply[34]||reply[35]||
               manager_u32(reply+36)!=(unsigned int)(phase==16||phase==17))goto invalid;
        }else if(phase!=1){
            if(reply[32]!=1||reply[33]!='s'||reply[34]||reply[35]||manager_u32(reply+36)!=(uint32_t)en||
               memcmp(reply+40,expected,(size_t)en+1))goto invalid;
        }else if(reply[32]!=2||reply[33]!='a'||reply[34]!='s'||reply[35]||
                 manager_u32(reply+36)!=(uint32_t)en+5||manager_u32(reply+40)!=(uint32_t)en||
                 memcmp(reply+44,expected,(size_t)en+1))goto invalid;
        if(manager_peer(e)!=0||manager_paths(0,e)!=0||original_working_directory(e)!=0)return -1;
        if(rnr_stage0_check_project_view(&e->project)!=0){reject_input(e,RNR_STAGE0_PREPARER_BOOTSTRAP,e->project.system_errno);return -1;}
    }
    return 0;
invalid:
    reject_input(e,RNR_STAGE0_PREPARER_PID1,0);return -1;
}
#endif
int rnr_stage0_prepare_inputs(struct rnr_stage0_preparer_error *e)
{
    int expected=PREPARER_NEW;
    int claimed=atomic_compare_exchange_strong_explicit(&preparer_state,&expected,
                    PREPARER_ACQUIRING,memory_order_acq_rel,memory_order_acquire);
    if(e==NULL){
        fence_inputs();
        if(claimed){expected=PREPARER_FENCED_ACQUIRING;
            (void)atomic_compare_exchange_strong_explicit(&preparer_state,&expected,
                PREPARER_FAILED_DRAINED,memory_order_release,memory_order_relaxed);}
        errno=EINVAL;return -1;
    }
    *e=(struct rnr_stage0_preparer_error){.unadopted_fd=-1};
    if(!claimed){reject_input(e,RNR_STAGE0_PREPARER_ATTEMPT,0);fence_inputs();return -1;}
    /* FIRST task syscall boundary is the existing original operational
     * prepare; no installation/task observation or attempt claim predates T0. */
    if(rnr_stage0_prepare_operational(&e->launch)!=0){
        reject_input(e,RNR_STAGE0_PREPARER_CLOCK,e->launch.system_errno);goto failed;
    }
    pid_t pid=getpid();
    if(pid<=0 || syscall(SYS_gettid)!=(long)pid || geteuid()!=0 || getegid()!=0){
        reject_input(e,RNR_STAGE0_PREPARER_OWNER,0);goto failed;
    }
    atomic_store_explicit(&input_owner_pid,pid,memory_order_release);
    if(live_input(e)!=0)goto failed;
    if(rnr_stage0_admit_preparation_fds(&e->admission)!=0){
        reject_input(e,RNR_STAGE0_PREPARER_ADMISSION,e->admission.system_errno);goto failed;
    }
    if(live_input(e)!=0)goto failed;
    if(read_fixed_inputs(128,e)!=0)goto failed;
    if(live_input(e)!=0)goto failed;
    if(rnr_stage0_bind_operational_preparation_cutoff(input_owner.task.wall_cutoff_ns,&e->launch)!=0){
        reject_input(e,RNR_STAGE0_PREPARER_CLOCK,e->launch.system_errno);goto failed;
    }
    if(live_input(e)!=0)goto failed;
    for(int role=0;role<5;++role)if(recheck_input(role,e)!=0)goto failed;
    if(live_input(e)!=0)goto failed;
    expected=PREPARER_ACQUIRING;
    if(!atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_INPUTS_HELD,
            memory_order_release,memory_order_relaxed)){
        reject_input(e,RNR_STAGE0_PREPARER_ATTEMPT,0);goto failed;
    }
    /* Quiescent publication: no more private owner reads/writes in this call.
     * A later fence/abandon cannot be undone by this historical return value. */
    return 0;
failed:
    fence_inputs();drain_inputs(e);input_owner.original_error=*e;
    expected=PREPARER_FENCED_ACQUIRING;
    (void)atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_FAILED_DRAINED,
            memory_order_release,memory_order_relaxed);
    return -1;
}
#ifdef RNR_STAGE0_PRIVATE_QUALIFICATION
/* Only the fixed launch wrapper enters this partial DATA boundary. There is
 * no ordinary stage publication, declaration authority, persistence or GO. */
int rnr_stage0_prepare_held_inputs(struct rnr_stage0_preparer_error *e)
{
    int expected=PREPARER_NEW;
    int claimed=atomic_compare_exchange_strong_explicit(&preparer_state,&expected,
        PREPARER_ADMISSION_ACQUIRING,memory_order_acq_rel,memory_order_acquire);
    if(!e){
        fence_inputs();
        if(claimed){expected=PREPARER_FENCED_ADMISSION_ACQUIRING;
            (void)atomic_compare_exchange_strong_explicit(&preparer_state,&expected,
                PREPARER_FAILED_DRAINED,memory_order_release,memory_order_relaxed);}
        errno=EINVAL;return -1;
    }
    *e=(struct rnr_stage0_preparer_error){.unadopted_fd=-1};
    if(!claimed){reject_input(e,RNR_STAGE0_PREPARER_ATTEMPT,0);fence_inputs();return -1;}
    /* Admission clock identity is checked before any protected input syscall;
     * unlike legacy preparation, this route never captures a new origin. */
    if(live_input(e)!=0)goto failed;
    pid_t pid=getpid();
    if(pid<=0 || syscall(SYS_gettid)!=(long)pid || geteuid()!=0 || getegid()!=0){
        reject_input(e,RNR_STAGE0_PREPARER_OWNER,0);goto failed;
    }
    atomic_store_explicit(&input_owner_pid,pid,memory_order_release);
    if(live_input(e)!=0)goto failed;
    if(rnr_stage0_admit_held_fds(&e->admission)!=0){
        reject_input(e,RNR_STAGE0_PREPARER_ADMISSION,e->admission.system_errno);goto failed;
    }
    if(live_input(e)!=0)goto failed;
    if(rnr_stage0_check_bootstrap(&e->bootstrap)!=0){
        reject_input(e,RNR_STAGE0_PREPARER_BOOTSTRAP,e->bootstrap.system_errno);goto failed;
    }
    input_owner.project_route=1;for(int role=5;role<=10;++role)input_owner.fds[role]=-1;
    if(rnr_stage0_capture_project_view(input_owner.project,&input_owner.fds[0],input_owner.project_executables,&input_owner.original_keeper,&e->project)!=0){
        reject_input(e,RNR_STAGE0_PREPARER_BOOTSTRAP,e->project.system_errno);goto failed;
    }
    input_owner.project_held=1;
    if(rnr_stage0_check_project_view(&e->project)!=0){
        reject_input(e,RNR_STAGE0_PREPARER_BOOTSTRAP,e->project.system_errno);goto failed;
    }
    if(live_input(e)!=0 || read_fixed_inputs(448,e)!=0)goto failed;
    static const char hex[]="0123456789abcdef";
    for(int i=0;i<32;++i){
        unsigned int b=input_owner.installation.project_id[i];
        if(input_owner.project[2*i]!=hex[b>>4]||input_owner.project[2*i+1]!=hex[b&15]){
            reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);goto failed;
        }
    }
    if(read_project_policy(e)!=0||authenticate_executables(e)!=0||authenticate_unit_fragments(e)!=0)goto failed;
    for(int role=0;role<11;++role)if(recheck_input(role,e)!=0)goto failed;
    if(executable_recheck(e)!=0)goto failed;
    if(unit_recheck(e)!=0)goto failed;
    if(rnr_stage0_check_project_view(&e->project)!=0){
        reject_input(e,RNR_STAGE0_PREPARER_BOOTSTRAP,e->project.system_errno);goto failed;
    }
    if(manager_begin(e)!=0||manager_lookup_keeper(e)!=0||manager_unit_path(e)!=0||unit_search_directories(1,e)!=0||unit_conf_overlays(e)!=0||manager_check_unit_identities(e)!=0||
       cgroup_capture(e)!=0)goto failed;
    struct rnr_stage0_launch_declaration declaration;
    if(live_input(e)!=0)goto failed;
    if(rnr_stage0_decode_launch_declaration(input_owner.task.payload,input_owner.task.payload_bytes,&declaration)!=0){
        (void)failed_input(e,RNR_STAGE0_PREPARER_DECODE,0);goto failed;
    }
    if(live_input(e)!=0)goto failed;
    if(input_owner.installation.version!=2 ||
       memcmp(declaration.allocation,input_owner.task.task_id,16) ||
       memcmp(declaration.asset_root,input_owner.installation.asset_root,32) ||
       memcmp(declaration.execution_root,input_owner.installation.execution_root,32) ||
       memcmp(input_owner.installation.runtime.root,input_owner.installation.execution_root,32) ||
       memcmp(declaration.tool_digest,input_owner.policy.tool_digest,32) ||
       memcmp(declaration.daemon_digest,input_owner.policy.daemon_digest,32) ||
       memcmp(declaration.manager_digest,input_owner.policy.manager_digest,32) ||
       declaration.cpu_millis>input_owner.policy.units[2].cpu_millis ||
       declaration.memory_bytes>input_owner.policy.units[2].memory_bytes ||
       declaration.pids>input_owner.policy.units[2].pids ||
       declaration.swap_bytes!=input_owner.policy.units[2].swap_bytes ||
       declaration.unit_path_count!=input_owner.policy.unit_path_count){
        reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);goto failed;
    }
    for(size_t n=0;n<declaration.unit_path_count;++n){
        if(declaration.unit_paths[n].length!=input_owner.policy.unit_paths[n].length||
           memcmp(declaration.unit_paths[n].bytes,input_owner.policy.unit_paths[n].bytes,declaration.unit_paths[n].length)){
            reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);goto failed;
        }
    }
    if(live_input(e)!=0)goto failed;
    if(rnr_stage0_bind_admission_inputs(&input_owner.installation,&input_owner.task,&declaration,&e->launch)!=0){
        reject_input(e,RNR_STAGE0_PREPARER_CLOCK,e->launch.system_errno);goto failed;
    }
    if(live_input(e)!=0)goto failed;
    for(int role=0;role<11;++role)if(recheck_input(role,e)!=0)goto failed;
    if(executable_recheck(e)!=0)goto failed;
    if(unit_recheck(e)!=0)goto failed;
    if(rnr_stage0_check_project_view(&e->project)!=0){
        reject_input(e,RNR_STAGE0_PREPARER_BOOTSTRAP,e->project.system_errno);goto failed;
    }
    if(manager_peer(e)!=0||manager_paths(0,e)!=0||original_working_directory(e)!=0||unit_search_directories(0,e)!=0||unit_conf_overlays(e)!=0||cgroup_recheck(e)!=0)goto failed;
    if(live_input(e)!=0)goto failed;
    expected=PREPARER_ADMISSION_ACQUIRING;
    if(!atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_ADMISSION_INPUTS_HELD,
            memory_order_release,memory_order_relaxed)){
        reject_input(e,RNR_STAGE0_PREPARER_ATTEMPT,0);goto failed;
    }
    /* Borrowed task/ASCII views refer only to private original static bytes.
     * The fixed wrapper must immediately abandon both inputs and gate, exit125. */
    return 0;
failed:
    fence_inputs();drain_inputs(e);input_owner.original_error=*e;
    expected=PREPARER_FENCED_ADMISSION_ACQUIRING;
    (void)atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_FAILED_DRAINED,
        memory_order_release,memory_order_relaxed);
    return -1;
}
#endif
int rnr_stage0_abandon_preparation_inputs(struct rnr_stage0_preparer_error *e)
{
    if(e==NULL){fence_inputs();errno=EINVAL;return -1;}
    *e=(struct rnr_stage0_preparer_error){.unadopted_fd=-1};
    pid_t pid=getpid();
    if(pid<=0 || syscall(SYS_gettid)!=(long)pid || geteuid()!=0 || getegid()!=0 ||
       atomic_load_explicit(&input_owner_pid,memory_order_acquire)!=pid){
        reject_input(e,RNR_STAGE0_PREPARER_OWNER,0);fence_inputs();return -1;
    }
    int phase=atomic_load_explicit(&preparer_state,memory_order_acquire);
    for(;;){
        if(phase!=PREPARER_ADMISSION_INPUTS_HELD && phase!=PREPARER_FENCED_ADMISSION_HELD &&
           phase!=PREPARER_INPUTS_HELD && phase!=PREPARER_FENCED_HELD &&
           phase!=PREPARER_VIEW_HELD && phase!=PREPARER_FENCED_VIEW_HELD &&
           phase!=PREPARER_JOURNAL_HELD && phase!=PREPARER_FENCED_JOURNAL_HELD &&
           phase!=PREPARER_RUNTIME_HELD && phase!=PREPARER_FENCED_RUNTIME_HELD &&
           phase!=PREPARER_DM_HELD && phase!=PREPARER_FENCED_DM_HELD &&
           phase!=PREPARER_ROOT_HELD && phase!=PREPARER_FENCED_ROOT_HELD &&
           phase!=PREPARER_MEDIA_HELD && phase!=PREPARER_FENCED_MEDIA_HELD &&
           phase!=PREPARER_LAUNCH_LOOPS_HELD && phase!=PREPARER_FENCED_LAUNCH_LOOPS_HELD &&
           phase!=PREPARER_LAUNCH_DM_HELD && phase!=PREPARER_FENCED_LAUNCH_DM_HELD &&
           phase!=PREPARER_LAUNCH_ROOT_HELD && phase!=PREPARER_FENCED_LAUNCH_ROOT_HELD &&
           phase!=PREPARER_BINDS_HELD && phase!=PREPARER_FENCED_BINDS_HELD &&
           phase!=PREPARER_FINAL_ROLES_HELD && phase!=PREPARER_FENCED_FINAL_ROLES_HELD){
            reject_input(e,RNR_STAGE0_PREPARER_ATTEMPT,0);fence_inputs();return -1;
        }
        int abandoning=admission_phase(phase)?PREPARER_ADMISSION_ABANDONING:PREPARER_ABANDONING;
        if(atomic_compare_exchange_weak_explicit(&preparer_state,&phase,abandoning,
                memory_order_acq_rel,memory_order_acquire))break;
    }
    e->claim_disposition=input_owner.claim_disposition;e->mkdir_errno=input_owner.mkdir_errno;
    fence_inputs();drain_inputs(e);input_owner.abandon_error=*e;
    int expected=admission_phase(phase)?PREPARER_ADMISSION_ABANDONING:PREPARER_ABANDONING;
    (void)atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_ABANDONED,
            memory_order_release,memory_order_relaxed);
    return e->code==RNR_STAGE0_PREPARER_OK?0:-1;
}

/* Fixed graph under original host invocation/maintenance exclusion. These
 * comparisons do not discover an external host from an arbitrary container. */
static const char *const view_names[10]={"mnt","pid","user","time","cgroup",
    "net","ipc","uts","pid_for_children","time_for_children"};
static const int view_kinds[10]={0x20000,0x20000000,0x10000000,0x80,0x2000000,
    0x40000000,0x8000000,0x4000000,0x20000000,0x80};
static int same_view(const struct stat *a,const struct stat *b)
{ return a->st_dev==b->st_dev && a->st_ino==b->st_ino && a->st_mode==b->st_mode; }
static int view_object(int fd,int kind,struct stat *s,struct rnr_stage0_preparer_error *e)
{
    long fs;int flags;
    if(stat_input(fd,s,e)!=0 || filesystem_input(fd,&fs,e)!=0)return -1;
    if(live_input(e)!=0)return -1;
    flags=fcntl(fd,F_GETFD);
    if(flags<0){reject_input(e,RNR_STAGE0_PREPARER_VIEW,errno);return -1;}
    if(live_input(e)!=0)return -1;
    if(!(flags&FD_CLOEXEC) || !s->st_dev || !s->st_ino ||
       (kind?(!S_ISREG(s->st_mode)||fs!=0x6e736673):
             (!S_ISDIR(s->st_mode)||fs!=0x9fa0||s->st_uid||s->st_gid))){
        reject_input(e,RNR_STAGE0_PREPARER_VIEW,0);return -1;
    }
    if(kind){
        if(live_input(e)!=0)return -1;
        int actual=ioctl(fd,NS_GET_NSTYPE);
        if(actual<0){reject_input(e,RNR_STAGE0_PREPARER_VIEW,errno);return -1;}
        if(live_input(e)!=0)return -1;
        if(actual!=kind){reject_input(e,RNR_STAGE0_PREPARER_VIEW,0);return -1;}
    }else{
        uint64_t mount;
        if(mount_input(fd,&mount,e)!=0)return -1;
        if(input_owner.view_count==1)input_owner.proc_mount=mount;
        else if(mount!=input_owner.proc_mount || s->st_dev!=input_owner.view_identities[0].st_dev){
            reject_input(e,RNR_STAGE0_PREPARER_VIEW,0);return -1;
        }
    }
    return 0;
}
static int view_open(int parent,const char *name,int kind,int *slot,
                     struct rnr_stage0_preparer_error *e)
{
    if(live_input(e)!=0)return -1;
    int flags=O_RDONLY|O_CLOEXEC|(kind?0:O_DIRECTORY|O_NONBLOCK|O_NOFOLLOW);
    int fd=openat(parent,name,flags);
    if(fd<0){reject_input(e,RNR_STAGE0_PREPARER_OPEN,errno);return -1;}
    if(fd<3){e->unadopted_fd=fd;reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;}
    *slot=fd;
    return live_input(e);
}
static int keep_view(int parent,const char *name,int kind,
                     struct rnr_stage0_preparer_error *e)
{
    unsigned int role=input_owner.view_count++;
    /* Count reserves ownership BEFORE open; failure leaves a -1 slot. */
    input_owner.view_fds[role]=-1;
    if(view_open(parent,name,kind,&input_owner.view_fds[role],e)!=0)return -1;
    return view_object(input_owner.view_fds[role],kind,&input_owner.view_identities[role],e);
}
static int pid1_live(struct rnr_stage0_preparer_error *e)
{
    int fd=input_owner.view_fds[3];struct stat s;int flags;
    if(stat_input(fd,&s,e)!=0)return -1;
    if(!S_ISREG(s.st_mode) || !s.st_dev || !s.st_ino ||
       !same_view(&s,&input_owner.view_identities[3])){
        reject_input(e,RNR_STAGE0_PREPARER_PID1,0);return -1;
    }
    if(live_input(e)!=0)return -1;
    flags=fcntl(fd,F_GETFD);
    if(flags<0){reject_input(e,RNR_STAGE0_PREPARER_PID1,errno);return -1;}
    if(live_input(e)!=0)return -1;
    if(!(flags&FD_CLOEXEC)){reject_input(e,RNR_STAGE0_PREPARER_PID1,0);return -1;}
    struct pollfd watched={.fd=fd,.events=POLLIN};
    if(live_input(e)!=0)return -1;
    int n=poll(&watched,1,0);
    if(n<0){reject_input(e,RNR_STAGE0_PREPARER_PID1,errno);return -1;}
    if(live_input(e)!=0)return -1;
    if(n!=0 || watched.revents){reject_input(e,RNR_STAGE0_PREPARER_PID1,0);return -1;}
    return 0;
}
static int single_task(struct rnr_stage0_preparer_error *e)
{
    int fd=-1,eof=0;unsigned int seen=0,records=0;struct stat s;
    char pid[16];int length=snprintf(pid,sizeof(pid),"%d",atomic_load(&input_owner_pid));
    if(length<=0 || (size_t)length>=sizeof(pid)){
        reject_input(e,RNR_STAGE0_PREPARER_TASKS,0);return -1;
    }
    if(view_open(input_owner.view_fds[1],"task",0,&fd,e)!=0)goto done;
    if(view_object(fd,0,&s,e)!=0)goto done;
    for(int reads=0;reads<5;++reads){
        unsigned char bytes[4096];
        if(live_input(e)!=0)goto done;
        long n=syscall(SYS_getdents64,fd,bytes,sizeof(bytes));
        if(n<0){reject_input(e,RNR_STAGE0_PREPARER_TASKS,errno);goto done;}
        if(live_input(e)!=0)goto done;
        if(n==0){eof=1;break;}
        if(n>4096){reject_input(e,RNR_STAGE0_PREPARER_TASKS,0);goto done;}
        for(size_t off=0;off<(size_t)n;){
            uint16_t size;uint64_t ino;int64_t next;
            if(++records>4 || (size_t)n-off<24)goto malformed;
            memcpy(&size,bytes+off+16,2);memcpy(&ino,bytes+off,8);memcpy(&next,bytes+off+8,8);
            if(size<24 || size%8 || size>(size_t)n-off || !ino || next<=0 || bytes[off+18]!=4)goto malformed;
            const unsigned char *name=bytes+off+19,*end=memchr(name,0,size-19);
            if(!end)goto malformed;
            size_t len=(size_t)(end-name);unsigned int bit;
            if(len==1 && name[0]=='.')bit=1;
            else if(len==2 && name[0]=='.' && name[1]=='.')bit=2;
            else if(len==(size_t)length && !memcmp(name,pid,len))bit=4;
            else goto malformed;
            if(seen&bit)goto malformed;
            seen|=bit;off+=size;continue;
malformed:
            reject_input(e,RNR_STAGE0_PREPARER_TASKS,0);goto done;
        }
    }
    if(!eof || seen!=7 || records!=3)reject_input(e,RNR_STAGE0_PREPARER_TASKS,0);
done:
    close_input(&fd,e);
    if(e->code==RNR_STAGE0_PREPARER_OK)(void)live_input(e);
    return e->code==RNR_STAGE0_PREPARER_OK?0:-1;
}
static int recheck_view(struct rnr_stage0_preparer_error *e)
{
    char own[16];int length=snprintf(own,sizeof(own),"%d",atomic_load(&input_owner_pid));
    if(length<=0 || (size_t)length>=sizeof(own)){
        reject_input(e,RNR_STAGE0_PREPARER_VIEW,0);return -1;
    }
    if(pid1_live(e)!=0 || single_task(e)!=0)return -1;
    for(unsigned int role=0;role<22;++role){
        if(role==3)continue;
        int kind=0,parent;char ns[40];const char *name;struct stat held,named;
        if(role==0){parent=input_owner.fds[0];name="proc";}
        else if(role==1 || role==2){parent=input_owner.view_fds[0];name=role==1?own:"1";}
        else{
            unsigned int index=role>=20?role-12:(role-4)%8;
            kind=view_kinds[index];parent=input_owner.view_fds[role>=12 && role<20?2:1];
            (void)snprintf(ns,sizeof(ns),"ns/%s",view_names[index]);name=ns;
        }
        if(view_object(input_owner.view_fds[role],kind,&held,e)!=0)return -1;
        if(!same_view(&held,&input_owner.view_identities[role])){
            reject_input(e,RNR_STAGE0_PREPARER_VIEW,0);return -1;
        }
        int fd=-1;
        if(view_open(parent,name,kind,&fd,e)==0 && view_object(fd,kind,&named,e)==0 &&
           !same_view(&named,&input_owner.view_identities[role]))reject_input(e,RNR_STAGE0_PREPARER_VIEW,0);
        close_input(&fd,e);
        if(e->code!=RNR_STAGE0_PREPARER_OK || live_input(e)!=0)return -1;
    }
    return single_task(e)==0?pid1_live(e):-1;
}
int rnr_stage0_prepare_host_view(struct rnr_stage0_preparer_error *e)
{
    if(!e){fence_inputs();errno=EINVAL;return -1;}
    *e=(struct rnr_stage0_preparer_error){.unadopted_fd=-1};
    pid_t pid=getpid();
    if(pid<=0 || syscall(SYS_gettid)!=(long)pid || geteuid()!=0 || getegid()!=0 ||
       atomic_load_explicit(&input_owner_pid,memory_order_acquire)!=pid){
        reject_input(e,RNR_STAGE0_PREPARER_OWNER,0);fence_inputs();return -1;
    }
    int expected=PREPARER_INPUTS_HELD;
    if(!atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_VIEW_ACQUIRING,
            memory_order_acq_rel,memory_order_acquire)){
        reject_input(e,RNR_STAGE0_PREPARER_ATTEMPT,0);fence_inputs();return -1;
    }
    char own[16];int length=snprintf(own,sizeof(own),"%d",pid);
    if(length<=0 || (size_t)length>=sizeof(own)){
        reject_input(e,RNR_STAGE0_PREPARER_VIEW,0);goto failed;
    }
    if(live_input(e)!=0)goto failed;
    for(int role=0;role<5;++role)if(recheck_input(role,e)!=0)goto failed;
    if(keep_view(input_owner.fds[0],"proc",0,e)!=0 ||
       keep_view(input_owner.view_fds[0],own,0,e)!=0 ||
       keep_view(input_owner.view_fds[0],"1",0,e)!=0)goto failed;
    input_owner.view_fds[3]=-1;input_owner.view_count=4;
    if(live_input(e)!=0)goto failed;
    int fd=(int)syscall(SYS_pidfd_open,1,0);
    if(fd<0){reject_input(e,RNR_STAGE0_PREPARER_PID1,errno);goto failed;}
    if(fd<3){e->unadopted_fd=fd;reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);goto failed;}
    input_owner.view_fds[3]=fd;
    if(stat_input(fd,&input_owner.view_identities[3],e)!=0 || pid1_live(e)!=0)goto failed;
    if(single_task(e)!=0)goto failed; /* BEFORE namespace acquisition. */
    for(unsigned int role=4;role<22;++role){
        unsigned int index=role>=20?role-12:(role-4)%8;
        char name[40];(void)snprintf(name,sizeof(name),"ns/%s",view_names[index]);
        int parent=input_owner.view_fds[role>=12 && role<20?2:1];
        if(keep_view(parent,name,view_kinds[index],e)!=0)goto failed;
        unsigned int original=role>=20?(role==20?5:7):role-8;
        if(role>=12 && !same_view(&input_owner.view_identities[role],&input_owner.view_identities[original])){
            reject_input(e,RNR_STAGE0_PREPARER_VIEW,0);goto failed;
        }
    }
    if(recheck_view(e)!=0 || live_input(e)!=0)goto failed;
    expected=PREPARER_VIEW_ACQUIRING;
    if(!atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_VIEW_HELD,
            memory_order_release,memory_order_relaxed)){
        reject_input(e,RNR_STAGE0_PREPARER_ATTEMPT,0);goto failed;
    }
    return 0;
failed:
    fence_inputs();drain_inputs(e);input_owner.original_error=*e;
    expected=PREPARER_FENCED_VIEW_ACQUIRING;
    (void)atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_FAILED_DRAINED,
            memory_order_release,memory_order_relaxed);
    return -1;
}

static int journal_object(int fd,unsigned int role,off_t size,struct stat *s,
                           uint64_t *mount,struct rnr_stage0_preparer_error *e)
{
    long fs;
    if(stat_input(fd,s,e)!=0 || mount_input(fd,mount,e)!=0 || filesystem_input(fd,&fs,e)!=0)return -1;
    if(!s->st_dev || !s->st_ino || s->st_uid || s->st_gid || fs!=0x1021994 ||
       (role==2?(!S_ISREG(s->st_mode)||(s->st_mode&07777)!=0600||s->st_nlink!=1||s->st_size!=size):
                (!S_ISDIR(s->st_mode)||(role?(s->st_mode&07777)!=0700:(s->st_mode&022)!=0))) ||
       (role && (s->st_dev!=input_owner.journal_identities[0].st_dev || *mount!=input_owner.journal_mounts[0]))){
        reject_input(e,RNR_STAGE0_PREPARER_JOURNAL,0);return -1;
    }
    return 0;
}
static int keep_journal(unsigned int role,struct rnr_stage0_preparer_error *e)
{
    int parent=role?input_owner.journal_fds[role-1]:input_owner.fds[0];
    const char *name=role==0?"run":role==1?input_owner.work_name:"journal.bin";
    input_owner.journal_fds[role]=-1;input_owner.journal_count=role+1;
    if(live_input(e)!=0)return -1;
    int flags=O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK|(role==2?O_WRONLY|O_CREAT|O_EXCL:O_RDONLY|O_DIRECTORY);
    int fd=role==2?openat(parent,name,flags,0600):openat(parent,name,flags);
    if(fd<0){reject_input(e,RNR_STAGE0_PREPARER_OPEN,errno);return -1;}
    if(fd<3){e->unadopted_fd=fd;reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;}
    input_owner.journal_fds[role]=fd;
    if(live_input(e)!=0)return -1;
    return journal_object(fd,role,0,&input_owner.journal_identities[role],&input_owner.journal_mounts[role],e);
}
static int recheck_journal_dir(unsigned int role,struct rnr_stage0_preparer_error *e)
{
    struct stat held,named;uint64_t mount;int fd=-1;
    if(journal_object(input_owner.journal_fds[role],role,0,&held,&mount,e)!=0)return -1;
    if(!same_input(&held,&input_owner.journal_identities[role],1) || mount!=input_owner.journal_mounts[role]){
        reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;
    }
    int parent=role?input_owner.journal_fds[0]:input_owner.fds[0];
    const char *name=role?input_owner.work_name:"run";
    if(view_open(parent,name,0,&fd,e)==0 && journal_object(fd,role,0,&named,&mount,e)==0 &&
       (!same_input(&named,&input_owner.journal_identities[role],1)||mount!=input_owner.journal_mounts[role]))
        reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);
    close_input(&fd,e);
    if(e->code==RNR_STAGE0_PREPARER_OK)(void)live_input(e);
    return e->code==RNR_STAGE0_PREPARER_OK?0:-1;
}
static void journal_u64(unsigned char *p,uint64_t value)
{for(unsigned int j=0;j<8;++j)p[j]=(unsigned char)(value>>(j*8));}
static void initial_journal(unsigned char bytes[256])
{
    memset(bytes,0,256);memcpy(bytes,"RNRJ0001",8);bytes[8]=1;
    memcpy(bytes+16,input_owner.task.task_id,16);
    memcpy(bytes+32,input_owner.installation.runtime.root,32);
    memcpy(bytes+64,input_owner.installation.runtime.salt,32);
    memcpy(bytes+96,input_owner.installation.asset_root,32);
    journal_u64(bytes+128,(uint64_t)input_owner.task.wall_cutoff_ns);
    journal_u64(bytes+136,(uint64_t)atomic_load(&input_owner_pid));
    for(unsigned int role=0;role<2;++role){
        size_t offset=role==1?144:168;
        journal_u64(bytes+offset,(uint64_t)input_owner.journal_identities[role].st_dev);
        journal_u64(bytes+offset+8,(uint64_t)input_owner.journal_identities[role].st_ino);
        journal_u64(bytes+offset+16,input_owner.journal_mounts[role]);
    }
}
int rnr_stage0_claim_preparation(struct rnr_stage0_preparer_error *e)
{
    if(!e){fence_inputs();errno=EINVAL;return -1;}
    *e=(struct rnr_stage0_preparer_error){.unadopted_fd=-1};
    pid_t pid=getpid();
    if(pid<=0 || syscall(SYS_gettid)!=(long)pid || geteuid()!=0 || getegid()!=0 ||
       atomic_load_explicit(&input_owner_pid,memory_order_acquire)!=pid){
        reject_input(e,RNR_STAGE0_PREPARER_OWNER,0);fence_inputs();return -1;
    }
    int expected=PREPARER_VIEW_HELD;
    if(!atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_JOURNAL_ACQUIRING,
            memory_order_acq_rel,memory_order_acquire)){
        reject_input(e,RNR_STAGE0_PREPARER_ATTEMPT,0);fence_inputs();return -1;
    }
    if(live_input(e)!=0)goto failed;
    for(int role=0;role<5;++role)if(recheck_input(role,e)!=0)goto failed;
    if(recheck_view(e)!=0 || keep_journal(0,e)!=0 || recheck_journal_dir(0,e)!=0)goto failed;
    memcpy(input_owner.work_name,"rnr-native-",11);
    static const char hex[]="0123456789abcdef";
    for(unsigned int j=0;j<16;++j){
        input_owner.work_name[11+2*j]=hex[input_owner.task.task_id[j]>>4];
        input_owner.work_name[12+2*j]=hex[input_owner.task.task_id[j]&15];
    }
    input_owner.work_name[43]=0;
    if(live_input(e)!=0)goto failed;
    (void)umask(077);
    if(live_input(e)!=0)goto failed;
    input_owner.claim_disposition=RNR_STAGE0_CLAIM_UNKNOWN;
    int result=mkdirat(input_owner.journal_fds[0],input_owner.work_name,0700);
    int failure=result==0?0:errno;
    input_owner.mkdir_errno=failure;
    input_owner.claim_disposition=result==0?RNR_STAGE0_CLAIM_CREATED:
        failure==EEXIST?RNR_STAGE0_CLAIM_COLLISION:RNR_STAGE0_CLAIM_UNKNOWN;
    if(result!=0){reject_input(e,RNR_STAGE0_PREPARER_CLAIM,failure);goto failed;}
    if(live_input(e)!=0 || recheck_journal_dir(0,e)!=0 || keep_journal(1,e)!=0 ||
       recheck_journal_dir(1,e)!=0 || keep_journal(2,e)!=0)goto failed;
    unsigned char bytes[256];initial_journal(bytes);
    if(live_input(e)!=0)goto failed;
    ssize_t amount=pwrite(input_owner.journal_fds[2],bytes,256,0);
    if(amount<0){reject_input(e,RNR_STAGE0_PREPARER_JOURNAL,errno);goto failed;}
    if(live_input(e)!=0)goto failed;
    if(amount!=256){reject_input(e,RNR_STAGE0_PREPARER_JOURNAL,0);goto failed;}
    for(int role=2;role>=0;--role){
        if(live_input(e)!=0)goto failed;
        if(fsync(input_owner.journal_fds[role])!=0){reject_input(e,RNR_STAGE0_PREPARER_JOURNAL,errno);goto failed;}
        if(live_input(e)!=0)goto failed;
    }
    struct stat after;uint64_t mount;
    if(journal_object(input_owner.journal_fds[2],2,256,&after,&mount,e)!=0)goto failed;
    if(!same_input(&after,&input_owner.journal_identities[2],1)||mount!=input_owner.journal_mounts[2]){
        reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);goto failed;
    }
    if(recheck_journal_dir(1,e)!=0 || recheck_journal_dir(0,e)!=0)goto failed;
    for(int role=0;role<5;++role)if(recheck_input(role,e)!=0)goto failed;
    if(recheck_view(e)!=0 || live_input(e)!=0)goto failed;
    e->claim_disposition=input_owner.claim_disposition;e->mkdir_errno=input_owner.mkdir_errno;
    expected=PREPARER_JOURNAL_ACQUIRING;
    if(!atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_JOURNAL_HELD,
            memory_order_release,memory_order_relaxed)){
        reject_input(e,RNR_STAGE0_PREPARER_ATTEMPT,0);goto failed;
    }
    return 0;
failed:
    e->claim_disposition=input_owner.claim_disposition;e->mkdir_errno=input_owner.mkdir_errno;
    fence_inputs();drain_inputs(e);input_owner.original_error=*e;
    expected=PREPARER_FENCED_JOURNAL_ACQUIRING;
    (void)atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_FAILED_DRAINED,
            memory_order_release,memory_order_relaxed);
    return -1;
}

/* Append is private to the exclusively held active preparation frame. No
 * journal parser/import or caller-selected operation API exists. */
static void journal_u32(unsigned char *p,uint32_t value)
{for(unsigned int j=0;j<4;++j)p[j]=(unsigned char)(value>>(j*8));}
static int preparation_access(int fd,int access,struct rnr_stage0_preparer_error *e)
{
    if(live_input(e)!=0)return -1;
    int descriptor=fcntl(fd,F_GETFD),failure=descriptor<0?errno:0;
    if(descriptor<0){reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,failure);return -1;}
    if(live_input(e)!=0)return -1;
    int status=fcntl(fd,F_GETFL);failure=status<0?errno:0;
    if(status<0){reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,failure);return -1;}
    if(live_input(e)!=0)return -1;
    if(!(descriptor&FD_CLOEXEC)||(status&O_PATH)||(status&O_ACCMODE)!=access){
        reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;
    }
    return 0;
}
static int check_operation_journal(off_t size,struct rnr_stage0_preparer_error *e)
{
    struct stat held,named;uint64_t mount;int fd=-1;
    if(preparation_access(input_owner.journal_fds[2],O_WRONLY,e)!=0 ||
       journal_object(input_owner.journal_fds[2],2,size,&held,&mount,e)!=0)return -1;
    if(!same_input(&held,&input_owner.journal_identities[2],1)||mount!=input_owner.journal_mounts[2])
        reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);
    if(e->code!=RNR_STAGE0_PREPARER_OK || live_input(e)!=0)return -1;
    fd=openat(input_owner.journal_fds[1],"journal.bin",O_WRONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(fd<0){reject_input(e,RNR_STAGE0_PREPARER_OPEN,errno);return -1;}
    if(fd<3){e->unadopted_fd=fd;reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;}
    if(live_input(e)==0 && preparation_access(fd,O_WRONLY,e)==0 && journal_object(fd,2,size,&named,&mount,e)==0 &&
       (!same_input(&named,&input_owner.journal_identities[2],1)||mount!=input_owner.journal_mounts[2]))
        reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);
    close_input(&fd,e);
    return e->code==RNR_STAGE0_PREPARER_OK?live_input(e):-1;
}
static int append_operation(int returned,const unsigned char payload[192],
                            struct rnr_stage0_preparer_error *e)
{
    unsigned int sequence=input_owner.journal_sequence+1;
    if(sequence>256 || (returned && (!input_owner.operation_entered||!input_owner.operation_returned))){
        reject_input(e,RNR_STAGE0_PREPARER_JOURNAL,0);return -1;
    }
    off_t offset=(off_t)sequence*256;
    if(check_operation_journal(offset,e)!=0)return -1;
    input_owner.journal_sync_entered=0;
    unsigned char bytes[256]={0};memcpy(bytes,"RNRO0001",8);bytes[8]=1;
    journal_u32(bytes+12,input_owner.operation);journal_u64(bytes+16,sequence);
    memcpy(bytes+24,input_owner.task.task_id,16);journal_u32(bytes+40,input_owner.operation_role);
    journal_u32(bytes+44,returned?2:1);
    if(returned){journal_u64(bytes+48,(uint64_t)input_owner.operation_result);
        journal_u32(bytes+56,(uint32_t)input_owner.operation_errno);}
    memcpy(bytes+64,payload,192);
    if(live_input(e)!=0)return -1;
    ssize_t n=pwrite(input_owner.journal_fds[2],bytes,256,offset);
    int failure=n<0?errno:0;
    input_owner.journal_write_result=n;input_owner.journal_write_errno=failure;
    if(n!=256){reject_input(e,RNR_STAGE0_PREPARER_JOURNAL,failure);return -1;}
    if(live_input(e)!=0)return -1;
    input_owner.journal_sync_entered=1;
    int result=fsync(input_owner.journal_fds[2]);failure=result<0?errno:0;
    input_owner.journal_sync_result=result;input_owner.journal_sync_errno=failure;
    if(result!=0){reject_input(e,RNR_STAGE0_PREPARER_JOURNAL,failure);return -1;}
    if(live_input(e)!=0 || check_operation_journal(offset+256,e)!=0)return -1;
    input_owner.journal_sequence=sequence;return 0;
}
static int loop_intent(unsigned int operation,unsigned int role,const unsigned char payload[192],
                       struct rnr_stage0_preparer_error *e)
{
    /* Fixed phase order: GET_FREE then CONFIGURE for data then hash. Reserve
     * space for BOTH records before even an allocation-candidate request. */
    unsigned int step=input_owner.journal_sequence;
    if(step>=8 || step%2 || input_owner.journal_sequence>254 ||
       role!=1+step/4 || operation!=(step%4?2:1)){
        reject_input(e,RNR_STAGE0_PREPARER_JOURNAL,0);return -1;
    }
    input_owner.operation=operation;input_owner.operation_role=role;
    input_owner.operation_entered=input_owner.operation_returned=input_owner.operation_errno=0;
    input_owner.operation_result=0;memcpy(input_owner.operation_payload,payload,192);
    return append_operation(0,payload,e);
}
static int runtime_object(int fd,unsigned int role,struct stat *s,uint64_t *mount,
                           struct rnr_stage0_preparer_error *e)
{
    if(preparation_access(fd,O_RDONLY,e)!=0 || stat_input(fd,s,e)!=0 || mount_input(fd,mount,e)!=0)return -1;
    if(!s->st_dev||!s->st_ino||s->st_uid || (role<4||role==6||role==10?
       (!S_ISDIR(s->st_mode)||s->st_gid||(s->st_mode&022)):
       role==4||role==5?(!S_ISREG(s->st_mode)||s->st_gid||s->st_nlink!=1||
       (s->st_mode&07777)!=0444||s->st_size!=(off_t)(role==4?input_owner.installation.runtime.data_blocks:
                                                        input_owner.installation.runtime.hash_blocks)*4096):
       role==7||role==11?(!S_ISCHR(s->st_mode)||s->st_gid||(s->st_mode&022)||s->st_rdev!=makedev(10,role==7?237:236)):
       role==12?(!S_ISBLK(s->st_mode)||s->st_rdev!=makedev((input_owner.runtime_mapping.dm_device>>8)&4095,
             (input_owner.runtime_mapping.dm_device&255)|((input_owner.runtime_mapping.dm_device>>12)&0xfff00))):
       (!S_ISBLK(s->st_mode)||s->st_rdev!=makedev(7,(unsigned int)input_owner.loop_candidates[role-8])))){
        reject_input(e,RNR_STAGE0_PREPARER_LOOP,0);return -1;
    }
    if(role>=6){long fs;
        if(filesystem_input(fd,&fs,e)!=0)return -1;
        if(fs!=0x1021994 || (role>6 && (*mount!=input_owner.runtime_mounts[6]||s->st_dev!=input_owner.runtime_identities[6].st_dev))){
            reject_input(e,RNR_STAGE0_PREPARER_LOOP,0);return -1;
        }
    }
    return 0;
}
static int runtime_parent(unsigned int role)
{
    if(role==10||role==12)return input_owner.runtime_fds[6];
    if(role==11)return input_owner.runtime_fds[10];
    if(role==0||role==6)return input_owner.fds[0];
    if(role==4||role==5)return input_owner.runtime_fds[3];
    return input_owner.runtime_fds[role>=7?6:role-1];
}
static const char *runtime_name(unsigned int role)
{
    static const char *const fixed[]={"var","lib","rnr-qualification",NULL,
                                      "root.squashfs","root.verity","dev","loop-control"};
    if(role>=10)return role==10?"mapper":role==11?"control":input_owner.runtime_mapping.dm_node;
    return role==3?input_owner.runtime_name:role>=8?input_owner.loop_names[role-8]:fixed[role];
}
static int keep_runtime(unsigned int role,struct rnr_stage0_preparer_error *e)
{
    input_owner.runtime_count=role+1;input_owner.runtime_fds[role]=-1;
    if(open_input(runtime_parent(role),runtime_name(role),role<4||role==6||role==10,&input_owner.runtime_fds[role],e)!=0)return -1;
    return runtime_object(input_owner.runtime_fds[role],role,&input_owner.runtime_identities[role],&input_owner.runtime_mounts[role],e);
}
static int recheck_runtime(unsigned int role,struct rnr_stage0_preparer_error *e)
{
    struct stat held,named;uint64_t mount;int fd=-1,dir=role<4||role==6||role==10;
    if(runtime_object(input_owner.runtime_fds[role],role,&held,&mount,e)!=0)return -1;
    if(!same_input(&held,&input_owner.runtime_identities[role],dir)||mount!=input_owner.runtime_mounts[role]){
        reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;
    }
    if(open_input(runtime_parent(role),runtime_name(role),dir,&fd,e)==0 &&
       runtime_object(fd,role,&named,&mount,e)==0 &&
       (!same_input(&named,&input_owner.runtime_identities[role],dir)||mount!=input_owner.runtime_mounts[role]))
        reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);
    close_input(&fd,e);
    return e->code==RNR_STAGE0_PREPARER_OK?live_input(e):-1;
}
static int loop_observe(int fd,unsigned long command,void *value,struct rnr_stage0_preparer_error *e)
{
    if(live_input(e)!=0)return -1;
    int result=ioctl(fd,command,value),failure=result<0?errno:0;
    if(result!=0){reject_input(e,RNR_STAGE0_PREPARER_LOOP,failure);return -1;}
    return live_input(e);
}
static int verify_loop(unsigned int i,struct rnr_stage0_preparer_error *e)
{
    struct loop_info64 info={0};int ro=0;uint64_t size=0;
    int fd=input_owner.runtime_fds[8+i];const struct stat *back=&input_owner.runtime_identities[4+i];
    if(loop_observe(fd,LOOP_GET_STATUS64,&info,e)!=0 || loop_observe(fd,BLKROGET,&ro,e)!=0 ||
       loop_observe(fd,BLKGETSIZE64,&size,e)!=0)return -1;
    unsigned int maj=major(back->st_dev),min=minor(back->st_dev);
    uint64_t kernel_dev=(min&255U)|((uint64_t)maj<<8)|((uint64_t)(min&~255U)<<12);
    if(maj>=4096||min>=1048576||info.lo_device!=kernel_dev || info.lo_inode!=back->st_ino || info.lo_rdevice ||
       info.lo_number!=(unsigned int)input_owner.loop_candidates[i] || info.lo_offset ||
       info.lo_sizelimit!=(uint64_t)back->st_size || info.lo_flags!=LO_FLAGS_READ_ONLY ||
       info.lo_encrypt_type||info.lo_encrypt_key_size || memcmp(info.lo_file_name,input_owner.loop_tags[i],64) ||
       ro!=1 || size!=(uint64_t)back->st_size){
        reject_input(e,RNR_STAGE0_PREPARER_LOOP,0);return -1;
    }
    return 0;
}
static int configure_runtime_loop(unsigned int i,struct rnr_stage0_preparer_error *e)
{
    unsigned char payload[192]={0};const struct stat *back=&input_owner.runtime_identities[4+i];
    journal_u64(payload,(uint64_t)back->st_dev);journal_u64(payload+8,back->st_ino);
    journal_u64(payload+16,(uint64_t)back->st_size);journal_u64(payload+24,input_owner.runtime_mounts[4+i]);
    journal_u32(payload+44,LO_FLAGS_READ_ONLY);memcpy(payload+48,input_owner.loop_tags[i],64);
    journal_u64(payload+120,(uint64_t)back->st_size);
    for(unsigned int role=0;role<8+i;++role)if(recheck_runtime(role,e)!=0)return -1;
    if(loop_intent(1,i+1,payload,e)!=0 || live_input(e)!=0)return -1;
    input_owner.operation_entered=1;
    int candidate=ioctl(input_owner.runtime_fds[7],LOOP_CTL_GET_FREE,0);
    input_owner.operation_result=candidate;input_owner.operation_errno=candidate<0?errno:0;
    input_owner.operation_returned=1;
    if(candidate<0){reject_input(e,RNR_STAGE0_PREPARER_LOOP,input_owner.operation_errno);return -1;}
    input_owner.loop_candidates[i]=candidate; /* retain before post-clock */
    if(live_input(e)!=0)return -1;
    journal_u32(payload+32,(uint32_t)candidate);
    if(append_operation(1,payload,e)!=0)return -1;
    int n=snprintf(input_owner.loop_names[i],24,"loop%d",candidate);
    if(n<=0||n>=24){reject_input(e,RNR_STAGE0_PREPARER_LOOP,0);return -1;}
    if(keep_runtime(8+i,e)!=0)return -1;
    struct loop_info64 prior={0};
    if(live_input(e)!=0)return -1;
    int result=ioctl(input_owner.runtime_fds[8+i],LOOP_GET_STATUS64,&prior),failure=result<0?errno:0;
    if(live_input(e)!=0)return -1;
    if(result!=-1||failure!=ENXIO){reject_input(e,RNR_STAGE0_PREPARER_LOOP,failure);return -1;}
    if(recheck_runtime(4+i,e)!=0 || recheck_runtime(6,e)!=0 || recheck_runtime(7,e)!=0 || recheck_runtime(8+i,e)!=0)return -1;
    journal_u32(payload+36,7);journal_u32(payload+40,(uint32_t)candidate);
    if(loop_intent(2,i+1,payload,e)!=0 || live_input(e)!=0)return -1;
    struct loop_config config={0};config.fd=(uint32_t)input_owner.runtime_fds[4+i];config.block_size=4096;
    config.info.lo_flags=LO_FLAGS_READ_ONLY;config.info.lo_sizelimit=(uint64_t)back->st_size;
    memcpy(config.info.lo_file_name,input_owner.loop_tags[i],64);
    input_owner.operation_entered=1;
    result=ioctl(input_owner.runtime_fds[8+i],LOOP_CONFIGURE,&config);
    input_owner.operation_result=result;input_owner.operation_errno=result<0?errno:0;
    input_owner.operation_returned=1;
    if(result!=0){reject_input(e,RNR_STAGE0_PREPARER_LOOP,input_owner.operation_errno);return -1;}
    if(live_input(e)!=0 || append_operation(1,payload,e)!=0)return -1;
    return verify_loop(i,e);
}
int rnr_stage0_prepare_runtime_loops(struct rnr_stage0_preparer_error *e)
{
    if(!e){fence_inputs();errno=EINVAL;return -1;}
    *e=(struct rnr_stage0_preparer_error){.unadopted_fd=-1};pid_t pid=getpid();
    if(pid<=0||syscall(SYS_gettid)!=(long)pid||geteuid()||getegid()||atomic_load(&input_owner_pid)!=pid){
        reject_input(e,RNR_STAGE0_PREPARER_OWNER,0);fence_inputs();return -1;
    }
    int expected=PREPARER_JOURNAL_HELD;
    if(!atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_RUNTIME_ACQUIRING,
       memory_order_acq_rel,memory_order_acquire)){
        reject_input(e,RNR_STAGE0_PREPARER_ATTEMPT,0);fence_inputs();return -1;
    }
    if(live_input(e)!=0)goto failed;
    for(int role=0;role<5;++role)if(recheck_input(role,e)!=0)goto failed;
    if(recheck_view(e)!=0||recheck_journal_dir(0,e)!=0||recheck_journal_dir(1,e)!=0||check_operation_journal(256,e)!=0)goto failed;
    static const char hex[]="0123456789abcdef";memcpy(input_owner.runtime_name,"runtime-",8);
    for(int j=0;j<32;++j){input_owner.runtime_name[8+2*j]=hex[input_owner.installation.runtime.root[j]>>4];
        input_owner.runtime_name[9+2*j]=hex[input_owner.installation.runtime.root[j]&15];}
    input_owner.runtime_name[72]=0;
    for(int i=0;i<2;++i){memcpy(input_owner.loop_tags[i],"rnr-",4);
        for(int j=0;j<16;++j){input_owner.loop_tags[i][4+2*j]=hex[input_owner.task.task_id[j]>>4];
            input_owner.loop_tags[i][5+2*j]=hex[input_owner.task.task_id[j]&15];}
        memcpy(input_owner.loop_tags[i]+36,i?"-rh":"-rd",4);
    }
    for(unsigned int role=0;role<8;++role)if(keep_runtime(role,e)!=0)goto failed;
    for(unsigned int i=0;i<2;++i)if(configure_runtime_loop(i,e)!=0)goto failed;
    for(unsigned int role=0;role<10;++role)if(recheck_runtime(role,e)!=0)goto failed;
    for(int role=0;role<5;++role)if(recheck_input(role,e)!=0)goto failed;
    if(verify_loop(0,e)!=0||verify_loop(1,e)!=0||recheck_view(e)!=0||
       recheck_journal_dir(0,e)!=0||recheck_journal_dir(1,e)!=0||
       check_operation_journal((off_t)(input_owner.journal_sequence+1)*256,e)!=0||live_input(e)!=0)goto failed;
    e->claim_disposition=input_owner.claim_disposition;e->mkdir_errno=input_owner.mkdir_errno;
    expected=PREPARER_RUNTIME_ACQUIRING;
    if(!atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_RUNTIME_HELD,
       memory_order_release,memory_order_relaxed)){reject_input(e,RNR_STAGE0_PREPARER_ATTEMPT,0);goto failed;}
    return 0;
failed:
    e->claim_disposition=input_owner.claim_disposition;e->mkdir_errno=input_owner.mkdir_errno;
    fence_inputs();drain_inputs(e);input_owner.original_error=*e;expected=PREPARER_FENCED_RUNTIME_ACQUIRING;
    (void)atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_FAILED_DRAINED,
        memory_order_release,memory_order_relaxed);return -1;
}

_Static_assert(sizeof(struct dm_ioctl)==312 && offsetof(struct dm_ioctl,data)==305 &&
               offsetof(struct dm_ioctl,dev)==40 && sizeof(struct dm_target_spec)==40,
               "Fixed Linux x86-64 DM ioctl layout required");
static int dm_reject(struct rnr_stage0_preparer_error *e,int failure)
{reject_input(e,RNR_STAGE0_PREPARER_DM,failure);return -1;}
static int launch_loop_originals(unsigned int,struct rnr_stage0_preparer_error *);
static int mapping_intent(enum mapping_kind kind,unsigned int op,const unsigned char payload[192],struct rnr_stage0_preparer_error *e)
{
    if(op<3||op>5||input_owner.journal_sequence!=(kind==MAPPING_RUNTIME?8U:46U)+2*(op-3))return dm_reject(e,0);
    input_owner.operation=op;input_owner.operation_role=kind==MAPPING_RUNTIME?5:6;
    input_owner.operation_entered=input_owner.operation_returned=input_owner.operation_errno=0;
    input_owner.operation_result=0;memcpy(input_owner.operation_payload,payload,192);
    return append_operation(0,payload,e);
}
/* Each request starts fresh; returned numeric/header data never selects a
 * second object. UUID-only lookups always leave name and dev initially zero. */
static int mapping_exchange(enum mapping_kind kind,unsigned long command,unsigned int flags,int effect,
                       unsigned char payload[192],struct rnr_stage0_preparer_error *e)
{
    struct mapping_owner *m=kind==MAPPING_RUNTIME?&input_owner.runtime_mapping:&input_owner.launch_mapping;
    const struct rnr_stage0_image_record *image=kind==MAPPING_RUNTIME?&input_owner.installation.runtime:&input_owner.media_output.launch;
    if(recheck_runtime(6,e)!=0||recheck_runtime(10,e)!=0||recheck_runtime(11,e)!=0)return -1;
    if(effect&&kind==MAPPING_LAUNCH){
        if(launch_loop_originals(2,e)!=0)return -1;
    }else if(effect){
        for(int role=0;role<5;++role)if(recheck_input(role,e)!=0)return -1;
        for(unsigned int role=0;role<input_owner.runtime_count;++role)if(recheck_runtime(role,e)!=0)return -1;
        if(recheck_view(e)!=0||verify_loop(0,e)!=0||verify_loop(1,e)!=0)return -1;
    }
    union {max_align_t alignment;unsigned char bytes[4096];} request={0};
    struct dm_ioctl *d=(void *)request.bytes;
    d->version[0]=4;d->data_start=312;d->data_size=4096;d->flags=flags;
    if(command!=DM_VERSION)memcpy(d->uuid,m->dm_uuid,129);
    if(command==DM_DEV_CREATE)memcpy(d->name,m->dm_name,128);
    if(command==DM_TABLE_LOAD){
        d->target_count=1;struct dm_target_spec *t=(void *)(request.bytes+312);
        t->length=image->data_blocks*8;
        memcpy(t->target_type,"verity",7);size_t n=strlen(m->dm_params)+1;
        t->next=(uint32_t)((40+n+7)&~(size_t)7);memcpy(t+1,m->dm_params,n);
    }
    if(effect && mapping_intent(kind,(unsigned int)effect,payload,e)!=0)return -1;
    if(live_input(e)!=0)return -1;
    if(effect)input_owner.operation_entered=1;
    int result=ioctl(input_owner.runtime_fds[11],command,d),failure=result<0?errno:0;
    /* Preserve output/result even after EFAULT or an expired post-clock: the
     * kernel may already have changed state. No interpretation grants replay. */
    m->dm_result=result;m->dm_errno=failure;
    memcpy(m->dm_response,request.bytes,4096);
    if(effect){input_owner.operation_result=result;input_owner.operation_errno=failure;input_owner.operation_returned=1;}
    if(result!=0)return dm_reject(e,failure);
    if(live_input(e)!=0)return -1;
    if(effect){
        if(effect==3)journal_u64(payload+112,d->dev);
        if(append_operation(1,payload,e)!=0)return -1;
    }
    return recheck_runtime(11,e);
}
static int mapping_header_event(enum mapping_kind kind,unsigned int flags,unsigned int count,int header_only,int first,
                           uint32_t expected_event,struct rnr_stage0_preparer_error *e)
{
    struct mapping_owner *m=kind==MAPPING_RUNTIME?&input_owner.runtime_mapping:&input_owner.launch_mapping;
    struct dm_ioctl d;memcpy(&d,m->dm_response,sizeof(d));
    if(d.version[0]!=4||d.version[1]!=50||d.version[2]||d.data_start!=312||
       (header_only?d.data_size!=305:(d.data_size<=352||d.data_size>4096))||
       d.padding||d.flags!=flags||d.target_count!=count||d.open_count!=m->dm_openers||
       memcmp(d.name,m->dm_name,128)||memcmp(d.uuid,m->dm_uuid,129)||
       !d.dev||d.dev>UINT32_MAX||!((d.dev>>8)&4095))return dm_reject(e,0);
    if(first){
        if(d.event_nr)return dm_reject(e,0);
        if(kind==MAPPING_LAUNCH){
            dev_t node=makedev((d.dev>>8)&4095,(d.dev&255)|((d.dev>>12)&0xfff00));
            if(d.dev==input_owner.runtime_mapping.dm_device||node==input_owner.runtime_identities[12].st_rdev)
                return dm_reject(e,0);
        }
        m->dm_device=d.dev;
    }
    else if(d.dev!=m->dm_device||d.event_nr!=expected_event)return dm_reject(e,0);
    return 0;
}
static int mapping_header(enum mapping_kind kind,unsigned int flags,unsigned int count,int header_only,int first,
                     struct rnr_stage0_preparer_error *e)
{
    struct mapping_owner *m=kind==MAPPING_RUNTIME?&input_owner.runtime_mapping:&input_owner.launch_mapping;
    return mapping_header_event(kind,flags,count,header_only,first,m->dm_event,e);
}
static int mapping_table(enum mapping_kind kind,int inactive,int information,struct rnr_stage0_preparer_error *e)
{
    struct mapping_owner *m=kind==MAPPING_RUNTIME?&input_owner.runtime_mapping:&input_owner.launch_mapping;
    const struct rnr_stage0_image_record *image=kind==MAPPING_RUNTIME?&input_owner.installation.runtime:&input_owner.media_output.launch;
    unsigned int query=inactive?DM_QUERY_INACTIVE_TABLE_FLAG|DM_STATUS_TABLE_FLAG:
                                      information?0:DM_STATUS_TABLE_FLAG;
    if(mapping_exchange(kind,DM_TABLE_STATUS,query,0,NULL,e)!=0 ||
       mapping_header(kind,inactive?4177:information?33:49,1,0,0,e)!=0)return -1;
    struct dm_target_spec t;memcpy(&t,m->dm_response+312,40);
    struct dm_ioctl d;memcpy(&d,m->dm_response,312);
    const char *text=information?"V":m->dm_params;size_t length=strlen(text)+1;
    static const char target_kind[16]="verity";
    if(d.data_size!=352+length||t.sector_start||t.length!=image->data_blocks*8||
       t.status||t.next!=((40+length+7)&~(size_t)7)||312+t.next>4096||
       memcmp(t.target_type,target_kind,16)||memcmp(m->dm_response+352,text,length))return dm_reject(e,0);
    return 0;
}
/* Existing runtime flow keeps a fixed profile through these wrappers. */
static int dm_exchange(unsigned long c,unsigned int f,int effect,unsigned char p[192],struct rnr_stage0_preparer_error *e)
{return mapping_exchange(MAPPING_RUNTIME,c,f,effect,p,e);}
static int dm_header_event(unsigned int f,unsigned int n,int h,int first,uint32_t event,struct rnr_stage0_preparer_error *e)
{return mapping_header_event(MAPPING_RUNTIME,f,n,h,first,event,e);}
static int dm_header(unsigned int f,unsigned int n,int h,int first,struct rnr_stage0_preparer_error *e)
{return mapping_header(MAPPING_RUNTIME,f,n,h,first,e);}
static int dm_table(int inactive,int info,struct rnr_stage0_preparer_error *e)
{return mapping_table(MAPPING_RUNTIME,inactive,info,e);}
int rnr_stage0_prepare_runtime_mapping(struct rnr_stage0_preparer_error *e)
{
    if(!e){fence_inputs();errno=EINVAL;return -1;}
    *e=(struct rnr_stage0_preparer_error){.unadopted_fd=-1};pid_t pid=getpid();
    if(pid<=0||syscall(SYS_gettid)!=(long)pid||geteuid()||getegid()||atomic_load(&input_owner_pid)!=pid){
        dm_reject(e,0);fence_inputs();return -1;
    }
    int expected=PREPARER_RUNTIME_HELD;
    if(!atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_DM_ACQUIRING,
        memory_order_acq_rel,memory_order_acquire)){dm_reject(e,0);fence_inputs();return -1;}
    if(live_input(e)!=0)goto failed;
    for(int role=0;role<5;++role)if(recheck_input(role,e)!=0)goto failed;
    for(unsigned int role=0;role<10;++role)if(recheck_runtime(role,e)!=0)goto failed;
    if(recheck_view(e)!=0||recheck_journal_dir(0,e)!=0||recheck_journal_dir(1,e)!=0||
       check_operation_journal(2304,e)!=0||verify_loop(0,e)!=0||verify_loop(1,e)!=0)goto failed;
    /* Fixed task-derived name/UUID and installed root/salt, no caller input. */
    char taskhex[33],root[65],salt[65];static const char hex[]="0123456789abcdef";
    for(int j=0;j<16;++j){taskhex[2*j]=hex[input_owner.task.task_id[j]>>4];taskhex[2*j+1]=hex[input_owner.task.task_id[j]&15];}
    taskhex[32]=0;
    for(int j=0;j<32;++j){root[2*j]=hex[input_owner.installation.runtime.root[j]>>4];root[2*j+1]=hex[input_owner.installation.runtime.root[j]&15];
        salt[2*j]=hex[input_owner.installation.runtime.salt[j]>>4];salt[2*j+1]=hex[input_owner.installation.runtime.salt[j]&15];}
    root[64]=salt[64]=0;
    (void)snprintf(input_owner.runtime_mapping.dm_name,128,"rnr-r-%s",taskhex);
    (void)snprintf(input_owner.runtime_mapping.dm_uuid,129,"rnr-native-%s-runtime",taskhex);
    int n=snprintf(input_owner.runtime_mapping.dm_params,512,"1 7:%d 7:%d 4096 4096 %llu 0 sha256 %s %s",
        input_owner.loop_candidates[0],input_owner.loop_candidates[1],
        (unsigned long long)input_owner.installation.runtime.data_blocks,root,salt);
    if(n<=0||n>=512){dm_reject(e,0);goto failed;}
    if(keep_runtime(10,e)!=0||keep_runtime(11,e)!=0||dm_exchange(DM_VERSION,0,0,NULL,e)!=0)goto failed;
    struct dm_ioctl version;memcpy(&version,input_owner.runtime_mapping.dm_response,312);
    if(version.version[0]!=4||version.version[1]!=50||version.version[2]){dm_reject(e,0);goto failed;}
    unsigned char payload[192]={0};memcpy(payload,input_owner.runtime_mapping.dm_name,48);memcpy(payload+48,input_owner.runtime_mapping.dm_uuid,64);
    /* CREATE actual request flags at offset184 are0; result dev at176. */
    if(dm_exchange(DM_DEV_CREATE,0,3,payload,e)!=0||dm_header(0,0,1,1,e)!=0)goto failed;
    memset(payload,0,192);
    journal_u64(payload,(uint64_t)input_owner.runtime_identities[8].st_rdev);
    journal_u64(payload+8,(uint64_t)input_owner.runtime_identities[9].st_rdev);
    journal_u64(payload+16,input_owner.runtime_mapping.dm_device);journal_u64(payload+24,input_owner.installation.runtime.data_blocks);
    journal_u64(payload+32,input_owner.installation.runtime.hash_blocks);
    memcpy(payload+40,input_owner.installation.runtime.root,32);memcpy(payload+72,input_owner.installation.runtime.salt,32);
    journal_u64(payload+104,input_owner.installation.runtime.data_blocks*8);journal_u32(payload+112,1);
    if(dm_exchange(DM_TABLE_LOAD,1,4,payload,e)!=0||dm_header(64,0,1,0,e)!=0||dm_table(1,0,e)!=0)goto failed;
    journal_u32(payload+112,0);
    if(dm_exchange(DM_DEV_SUSPEND,0,5,payload,e)!=0)goto failed;
    struct dm_ioctl resumed;memcpy(&resumed,input_owner.runtime_mapping.dm_response,312);
    if(resumed.event_nr<input_owner.runtime_mapping.dm_event||(resumed.flags!=33&&resumed.flags!=8225)){dm_reject(e,0);goto failed;}
    if(dm_header_event(resumed.flags,1,1,0,resumed.event_nr,e)!=0)goto failed;
    input_owner.runtime_mapping.dm_event=resumed.event_nr;
    if(dm_table(0,0,e)!=0||dm_table(0,1,e)!=0)goto failed;
    n=snprintf(input_owner.runtime_mapping.dm_node,24,"dm-%u",(unsigned int)((input_owner.runtime_mapping.dm_device&255)|((input_owner.runtime_mapping.dm_device>>12)&0xfff00)));
    if(n<=0||n>=24){dm_reject(e,0);goto failed;}
    if(keep_runtime(12,e)!=0)goto failed;
    input_owner.runtime_mapping.dm_openers=1;
    int ro=0;uint64_t size=0;
    if(loop_observe(input_owner.runtime_fds[12],BLKROGET,&ro,e)!=0||
       loop_observe(input_owner.runtime_fds[12],BLKGETSIZE64,&size,e)!=0)goto failed;
    if(ro!=1||size!=input_owner.installation.runtime.data_blocks*4096){dm_reject(e,0);goto failed;}
    for(unsigned int role=0;role<13;++role)if(recheck_runtime(role,e)!=0)goto failed;
    if(verify_loop(0,e)!=0||verify_loop(1,e)!=0||dm_exchange(DM_DEV_STATUS,0,0,NULL,e)!=0||
       dm_header(33,1,1,0,e)!=0||dm_table(0,0,e)!=0||dm_table(0,1,e)!=0||recheck_view(e)!=0||
       recheck_journal_dir(0,e)!=0||recheck_journal_dir(1,e)!=0||check_operation_journal(3840,e)!=0||live_input(e)!=0)goto failed;
    e->claim_disposition=input_owner.claim_disposition;e->mkdir_errno=input_owner.mkdir_errno;
    expected=PREPARER_DM_ACQUIRING;
    if(!atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_DM_HELD,
       memory_order_release,memory_order_relaxed)){dm_reject(e,0);goto failed;}
    return 0;
failed:
    e->claim_disposition=input_owner.claim_disposition;e->mkdir_errno=input_owner.mkdir_errno;
    fence_inputs();drain_inputs(e);input_owner.original_error=*e;expected=PREPARER_FENCED_DM_ACQUIRING;
    (void)atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_FAILED_DRAINED,
        memory_order_release,memory_order_relaxed);return -1;
}

static int mount_reject(struct rnr_stage0_preparer_error *e,int failure)
{reject_input(e,RNR_STAGE0_PREPARER_MOUNT,failure);return -1;}
static int mount_vfs(int fd,unsigned long *flags,struct rnr_stage0_preparer_error *e)
{
    struct statvfs s;
    if(live_input(e)!=0)return -1;
    if(fstatvfs(fd,&s)!=0)return mount_reject(e,errno);
    if(live_input(e)!=0)return -1;
    *flags=s.f_flag;return 0;
}
/* Roles13/14 deliberately reopen the named postmount view. A covered target
 * FD is never evidence about the filesystem mounted on top of it. */
static int mount_object(int fd,unsigned int role,struct stat *s,uint64_t *mnt,
                        struct rnr_stage0_preparer_error *e)
{
    long fs;unsigned long flags;
    if(preparation_access(fd,O_RDONLY,e)!=0||stat_input(fd,s,e)!=0||mount_input(fd,mnt,e)!=0||
       filesystem_input(fd,&fs,e)!=0)return -1;
    if(!S_ISDIR(s->st_mode)||s->st_uid||s->st_gid||(s->st_mode&022)||!s->st_dev||!s->st_ino)
        return mount_reject(e,0);
    if(role==13&&!input_owner.root_mounted){
        if((s->st_mode&07777)!=0700||fs!=0x1021994||
           s->st_dev!=input_owner.journal_identities[1].st_dev||*mnt!=input_owner.journal_mounts[1])return mount_reject(e,0);
    }else if(role==14&&input_owner.run_bound){
        if(fs!=0x1021994||!same_input(s,&input_owner.journal_identities[0],1)||
           *mnt==input_owner.journal_mounts[0]||*mnt==input_owner.runtime_mounts[13]||mount_vfs(fd,&flags,e)!=0)return mount_reject(e,0);
        if(input_owner.run_remounted?(flags&15)!=14:flags!=input_owner.original_run_flags)return mount_reject(e,0);
    }else{
        dev_t device=makedev((input_owner.runtime_mapping.dm_device>>8)&4095,
                            (input_owner.runtime_mapping.dm_device&255)|((input_owner.runtime_mapping.dm_device>>12)&0xfff00));
        if(fs!=0x73717368||s->st_dev!=device||*mnt==input_owner.journal_mounts[1]||
           (role==14&&*mnt!=input_owner.runtime_mounts[13])||mount_vfs(fd,&flags,e)!=0||(flags&15)!=7)return mount_reject(e,0);
    }
    return 0;
}
static int mount_open(unsigned int role,int *slot,struct rnr_stage0_preparer_error *e)
{
    if(live_input(e)!=0)return -1;
    int fd=openat(role==13?input_owner.journal_fds[1]:input_owner.runtime_fds[13],role==13?"root":"run",
                  O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(fd<0){reject_input(e,RNR_STAGE0_PREPARER_OPEN,errno);return -1;}
    if(fd<3){e->unadopted_fd=fd;return mount_reject(e,0);}
    *slot=fd;return live_input(e);
}
static int mount_keep(unsigned int role,struct rnr_stage0_preparer_error *e)
{
    input_owner.runtime_count=role+1;input_owner.runtime_fds[role]=-1;
    return mount_open(role,&input_owner.runtime_fds[role],e)!=0?-1:
        mount_object(input_owner.runtime_fds[role],role,&input_owner.runtime_identities[role],&input_owner.runtime_mounts[role],e);
}
static int mount_recheck(unsigned int role,struct rnr_stage0_preparer_error *e)
{
    struct stat s;uint64_t m;int fd=-1;
    if(mount_object(input_owner.runtime_fds[role],role,&s,&m,e)!=0)return -1;
    if(!same_input(&s,&input_owner.runtime_identities[role],1)||m!=input_owner.runtime_mounts[role])return mount_reject(e,0);
    if(mount_open(role,&fd,e)==0&&mount_object(fd,role,&s,&m,e)==0&&
       (!same_input(&s,&input_owner.runtime_identities[role],1)||m!=input_owner.runtime_mounts[role]))mount_reject(e,0);
    close_input(&fd,e);return e->code==RNR_STAGE0_PREPARER_OK?live_input(e):-1;
}
static int mount_originals(struct rnr_stage0_preparer_error *e)
{
    unsigned long flags;
    for(int j=0;j<5;++j)if(recheck_input(j,e)!=0)return -1;
    if(recheck_view(e)!=0||recheck_journal_dir(0,e)!=0||recheck_journal_dir(1,e)!=0||
       mount_vfs(input_owner.journal_fds[0],&flags,e)!=0)return -1;
    if(flags!=input_owner.original_run_flags)return mount_reject(e,0);
    for(unsigned int j=0;j<13;++j)if(recheck_runtime(j,e)!=0)return -1;
    if(verify_loop(0,e)!=0||verify_loop(1,e)!=0||dm_exchange(DM_DEV_STATUS,0,0,NULL,e)!=0||
       dm_header(33,1,1,0,e)!=0||dm_table(0,0,e)!=0||dm_table(0,1,e)!=0)return -1;
    for(unsigned int j=13;j<input_owner.runtime_count;++j)if(mount_recheck(j,e)!=0)return -1;
    return check_operation_journal((off_t)(input_owner.journal_sequence+1)*256,e);
}
static int mount_intent(unsigned int operation,unsigned int role,const unsigned char payload[192],
                        struct rnr_stage0_preparer_error *e)
{
    unsigned int seq=input_owner.journal_sequence;
    if(!((seq==14&&operation==11&&role==7)||(seq==16&&operation==6&&role==7)||
         (seq==18&&operation==7&&role==10)||(seq==20&&operation==8&&role==10)))return mount_reject(e,0);
    input_owner.operation=operation;input_owner.operation_role=role;
    input_owner.operation_entered=input_owner.operation_returned=input_owner.operation_errno=0;
    input_owner.operation_result=0;memcpy(input_owner.operation_payload,payload,192);
    return append_operation(0,payload,e);
}
static int empty_root(struct rnr_stage0_preparer_error *e)
{
    unsigned int seen=0,records=0;int eof=0;
    for(int j=0;j<4;++j){
        unsigned char b[4096];if(live_input(e)!=0)return -1;
        long n=syscall(SYS_getdents64,input_owner.runtime_fds[13],b,sizeof(b));int failure=n<0?errno:0;
        if(n<0)return mount_reject(e,failure);
        if(live_input(e)!=0)return -1;
        if(!n){eof=1;break;}if(n>4096)return mount_reject(e,0);
        for(size_t off=0;off<(size_t)n;){
            uint16_t size;uint64_t ino;int64_t next;
            if(++records>3||(size_t)n-off<24)return mount_reject(e,0);
            memcpy(&ino,b+off,8);memcpy(&next,b+off+8,8);memcpy(&size,b+off+16,2);
            if(!ino||next<=0||size<24||size%8||size>(size_t)n-off||b[off+18]!=4)return mount_reject(e,0);
            const unsigned char *name=b+off+19,*end=memchr(name,0,size-19);unsigned int bit;
            if(!end)return mount_reject(e,0);
            if(end-name==1&&name[0]=='.')bit=1;
            else if(end-name==2&&name[0]=='.'&&name[1]=='.')bit=2;
            else return mount_reject(e,0);
            if(seen&bit)return mount_reject(e,0);
            seen|=bit;off+=size;
        }
    }
    return eof&&seen==3&&records==2?0:mount_reject(e,0);
}
static void mount_payload(unsigned char payload[192],unsigned int role,unsigned long flags,const char *fs)
{
    memset(payload,0,192);
    const struct stat *source=role==13?&input_owner.runtime_identities[12]:&input_owner.journal_identities[0];
    journal_u64(payload,source->st_dev);journal_u64(payload+8,source->st_ino);
    journal_u64(payload+16,role==13?input_owner.runtime_mounts[12]:input_owner.journal_mounts[0]);
    journal_u64(payload+24,source->st_rdev);journal_u64(payload+32,input_owner.runtime_identities[role].st_dev);
    journal_u64(payload+40,input_owner.runtime_identities[role].st_ino);journal_u64(payload+48,input_owner.runtime_mounts[role]);
    journal_u64(payload+64,flags);if(fs)memcpy(payload+72,fs,strlen(fs));
    journal_u64(payload+88,role==13?input_owner.runtime_mapping.dm_device:0);
}
static int mount_once(unsigned int role,unsigned int operation,unsigned long flags,struct rnr_stage0_preparer_error *e)
{
    unsigned char payload[192];const char *fs=role==13?"squashfs":NULL;
    if(mount_originals(e)!=0)return -1;
    mount_payload(payload,role,flags,fs);
    if(mount_intent(operation,role==13?7:10,payload,e)!=0||live_input(e)!=0)return -1;
    input_owner.operation_entered=1;
    int result=mount(role==13?input_owner.dm_path:"/run",role==13?input_owner.root_path:input_owner.run_path,fs,flags,NULL);
    int failure=result<0?errno:0;
    input_owner.operation_result=result;input_owner.operation_errno=failure;input_owner.operation_returned=1;
    if(result!=0)return mount_reject(e,failure);
    if(live_input(e)!=0)return -1;
    uint64_t previous=input_owner.runtime_mounts[role];
    close_input(&input_owner.runtime_fds[role],e);
    if(e->code!=RNR_STAGE0_PREPARER_OK)return -1;
    if(role==13)input_owner.root_mounted=1;
    else if(operation==7)input_owner.run_bound=1;
    else input_owner.run_remounted=1;
    /* Preserve the complete inventory when replacing role13 while role14 is
     * not yet acquired, or replacing role14 at bind/remount. */
    if(mount_keep(role,e)!=0)return -1;
    uint64_t current=input_owner.runtime_mounts[role];
    if(operation==8?current!=previous:current==previous)return mount_reject(e,0);
    if(role==13)input_owner.runtime_mapping.dm_openers=2;
    journal_u64(payload+56,current);
    if(append_operation(1,payload,e)!=0)return -1;
    return mount_originals(e);
}
int rnr_stage0_prepare_runtime_mount(struct rnr_stage0_preparer_error *e)
{
    if(!e){fence_inputs();errno=EINVAL;return -1;}
    *e=(struct rnr_stage0_preparer_error){.unadopted_fd=-1};pid_t pid=getpid();
    if(pid<=0||syscall(SYS_gettid)!=(long)pid||geteuid()||getegid()||atomic_load(&input_owner_pid)!=pid){
        reject_input(e,RNR_STAGE0_PREPARER_OWNER,0);fence_inputs();return -1;}
    int expected=PREPARER_DM_HELD;
    if(!atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_MOUNT_ACQUIRING,
        memory_order_acq_rel,memory_order_acquire)){reject_input(e,RNR_STAGE0_PREPARER_ATTEMPT,0);fence_inputs();return -1;}
    if(mount_vfs(input_owner.journal_fds[0],&input_owner.original_run_flags,e)!=0||mount_originals(e)!=0)goto failed;
    int n=snprintf(input_owner.root_path,sizeof(input_owner.root_path),"/run/%s/root",input_owner.work_name);
    if(n<=0||(size_t)n>=sizeof(input_owner.root_path)){mount_reject(e,0);goto failed;}
    n=snprintf(input_owner.run_path,sizeof(input_owner.run_path),"%s/run",input_owner.root_path);
    if(n<=0||(size_t)n>=sizeof(input_owner.run_path)){mount_reject(e,0);goto failed;}
    n=snprintf(input_owner.dm_path,sizeof(input_owner.dm_path),"/dev/%s",input_owner.runtime_mapping.dm_node);
    if(n<=0||(size_t)n>=sizeof(input_owner.dm_path)){mount_reject(e,0);goto failed;}
    unsigned char payload[192]={0};journal_u64(payload,input_owner.journal_identities[1].st_dev);
    journal_u64(payload+8,input_owner.journal_identities[1].st_ino);journal_u64(payload+16,input_owner.journal_mounts[1]);
    memcpy(payload+24,"root",4);journal_u32(payload+96,0700);
    if(mount_intent(11,7,payload,e)!=0||live_input(e)!=0)goto failed;
    input_owner.operation_entered=1;
    int result=mkdirat(input_owner.journal_fds[1],"root",0700),failure=result<0?errno:0;
    input_owner.operation_result=result;input_owner.operation_errno=failure;input_owner.operation_returned=1;
    if(result!=0){mount_reject(e,failure);goto failed;}
    if(live_input(e)!=0||mount_keep(13,e)!=0||empty_root(e)!=0||live_input(e)!=0)goto failed;
    result=fsync(input_owner.journal_fds[1]);failure=result<0?errno:0;
    if(result!=0){mount_reject(e,failure);goto failed;}
    if(live_input(e)!=0)goto failed;
    journal_u64(payload+72,input_owner.runtime_identities[13].st_dev);
    journal_u64(payload+80,input_owner.runtime_identities[13].st_ino);journal_u64(payload+88,input_owner.runtime_mounts[13]);
    if(append_operation(1,payload,e)!=0||mount_once(13,6,7,e)!=0||mount_keep(14,e)!=0||
       mount_once(14,7,MS_BIND,e)!=0||mount_once(14,8,MS_BIND|MS_REMOUNT|MS_NOSUID|MS_NODEV|MS_NOEXEC,e)!=0||
       mount_originals(e)!=0||live_input(e)!=0)goto failed;
    e->claim_disposition=input_owner.claim_disposition;e->mkdir_errno=input_owner.mkdir_errno;
    expected=PREPARER_MOUNT_ACQUIRING;
    if(!atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_ROOT_HELD,
        memory_order_release,memory_order_relaxed)){mount_reject(e,0);goto failed;}
    return 0;
failed:
    e->claim_disposition=input_owner.claim_disposition;e->mkdir_errno=input_owner.mkdir_errno;
    fence_inputs();drain_inputs(e);input_owner.original_error=*e;expected=PREPARER_FENCED_MOUNT_ACQUIRING;
    (void)atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_FAILED_DRAINED,
        memory_order_release,memory_order_relaxed);return -1;
}

/* Fixed launch-source/helper phase. No caller-selected name, executable,
 * environment, imported state, reset, clock origin or positive Store exists. */
static int media_reject(struct rnr_stage0_preparer_error *e,int failure)
{reject_input(e,RNR_STAGE0_PREPARER_MEDIA,failure);return -1;}
static int media_absent(int helper,struct rnr_stage0_preparer_error *e)
{
    static const char *const names[]={"launch.squashfs","launch.verity","launch.root"};
    for(int j=helper?1:0;j<(helper?3:1);++j){
        struct stat s={0};if(live_input(e)!=0)return -1;
        int result=fstatat(input_owner.journal_fds[1],names[j],&s,AT_SYMLINK_NOFOLLOW);
        int failure=result<0?errno:0; /* retain before clock/other libc calls */
        if(result!=-1||failure!=ENOENT)return media_reject(e,failure);
        if(live_input(e)!=0)return -1;
    }
    return 0;
}
static int media_collect(struct rnr_stage0_preparer_error *e)
{
    int eof[2]={0,0};size_t total=0;
    for(unsigned int iteration=0;iteration<15000;++iteration){
        for(int stream=0;stream<2;++stream)if(!eof[stream]){
            unsigned char bytes[4096];size_t capacity=65537-total;
            if(capacity>sizeof(bytes))capacity=sizeof(bytes);
            if(!capacity)return media_reject(e,0);
            if(live_input(e)!=0)return -1;
            ssize_t n=read(input_owner.media_fds[stream?10:8],bytes,capacity);
            int failure=n<0?errno:0;
            if(live_input(e)!=0)return -1;
            if(n<0){if(failure!=EAGAIN)return media_reject(e,failure);}
            else if((size_t)n>capacity)return media_reject(e,0);
            else if(!n)eof[stream]=1;
            else{total+=(size_t)n;if(total>65536)return media_reject(e,0);}
        }
        if(!input_owner.child_reaped){
            int status=0;if(live_input(e)!=0)return -1;
            input_owner.media_steps[40].entered=1;
            pid_t result=waitpid(input_owner.child_pid,&status,WNOHANG);
            int failure=result<0?errno:0;
            input_owner.media_steps[40].result=result;
            input_owner.media_steps[40].system_errno=failure;
            if(result==input_owner.child_pid){
                /* Consumed BEFORE postclock, even if a pipe is still open. */
                input_owner.child_status=status;input_owner.child_reaped=1;
            }
            if(result<0)return media_reject(e,failure);
            if(live_input(e)!=0)return -1;
            if(result && (result!=input_owner.child_pid||!WIFEXITED(status)||WEXITSTATUS(status)))return media_reject(e,0);
        }
        if(eof[0]&&eof[1]&&input_owner.child_reaped)return 0;
        struct pollfd fds[3];nfds_t count=0;
        for(int stream=0;stream<2;++stream)if(!eof[stream])
            fds[count++]=(struct pollfd){.fd=input_owner.media_fds[stream?10:8],.events=POLLIN};
        if(!input_owner.child_reaped)fds[count++]=(struct pollfd){.fd=input_owner.media_fds[7],.events=POLLIN};
        if(live_input(e)!=0)return -1;
        int result=poll(fds,count,1),failure=result<0?errno:0;
        if(result<0)return media_reject(e,failure);
        if(live_input(e)!=0)return -1;
        if((nfds_t)result>count)return media_reject(e,0);
        for(nfds_t j=0;j<count;++j)if(fds[j].revents&~(POLLIN|POLLHUP))return media_reject(e,0);
    }
    return media_reject(e,0);
}
static int media_step(unsigned int slot,int64_t result,int failure,struct rnr_stage0_preparer_error *e)
{
    input_owner.media_steps[slot].result=result;
    input_owner.media_steps[slot].system_errno=failure;
    if(result<0)return media_reject(e,failure);
    return live_input(e);
}
static int media_sync(int fd,unsigned int slot,struct rnr_stage0_preparer_error *e)
{
    if(live_input(e)!=0)return -1;
    input_owner.media_steps[slot].entered=1;
    int result=fsync(fd),failure=result<0?errno:0;
    return media_step(slot,result,failure,e);
}
static int media_close(int *fd,unsigned int slot,struct rnr_stage0_preparer_error *e)
{
    if(live_input(e)!=0)return -1;
    int original=*fd;*fd=-1;
    if(original<0)return 0;
    input_owner.media_steps[slot].entered=1;
    int result=close(original),failure=result<0?errno:0;
    /* Ordinary drain retains the same exact close uncertainty, without retry. */
    if(result<0){
        if(e->cleanup_count<96){e->cleanup_errors[e->cleanup_count].fd=original;
            e->cleanup_errors[e->cleanup_count++].system_errno=failure;}
        else e->cleanup_overflow=1;
    }
    return media_step(slot,result,failure,e);
}
static int media_bytes(int fd,unsigned char *bytes,size_t length,int capture,
                       struct rnr_stage0_preparer_error *e)
{
    for(size_t offset=0;offset<length;){
        unsigned char b[32768];size_t count=length-offset;if(count>sizeof(b))count=sizeof(b);
        if(live_input(e)!=0)return -1;
        ssize_t n=pread(fd,b,count,(off_t)offset);int failure=n<0?errno:0;
        if(n!=(ssize_t)count)return media_reject(e,failure);
        if(live_input(e)!=0)return -1;
        if(capture)memcpy(bytes+offset,b,count);
        else if(memcmp(bytes+offset,b,count))return media_reject(e,0);
        offset+=count;
    }
    unsigned char extra;if(live_input(e)!=0)return -1;
    ssize_t n=pread(fd,&extra,1,(off_t)length);int failure=n<0?errno:0;
    if(n!=0)return media_reject(e,failure);
    return live_input(e);
}
static int media_object(int fd,int role,struct stat *s,uint64_t *m,struct rnr_stage0_preparer_error *e)
{
    long fs;
    if(preparation_access(fd,O_RDONLY,e)!=0||stat_input(fd,s,e)!=0||mount_input(fd,m,e)!=0||filesystem_input(fd,&fs,e)!=0)return -1;
    if(s->st_uid||s->st_gid||!s->st_dev||!s->st_ino)return media_reject(e,0);
    if(role==5){
        if(s->st_mode!=(S_IFCHR|0666)||s->st_rdev!=makedev(1,3)||fs!=0x1021994||
           s->st_dev!=input_owner.runtime_identities[6].st_dev||*m!=input_owner.runtime_mounts[6])return media_reject(e,0);
    }else if(role==6){
        if(!S_ISREG(s->st_mode)||s->st_nlink!=1||(s->st_mode&06022)||!(s->st_mode&0111)||
           s->st_size<64||s->st_size>67108864||fs!=0x73717368||
           s->st_dev!=input_owner.runtime_identities[13].st_dev||*m!=input_owner.runtime_mounts[13])return media_reject(e,0);
    }else{
        if(fs!=0x1021994||s->st_dev!=input_owner.journal_identities[1].st_dev||*m!=input_owner.journal_mounts[1])return media_reject(e,0);
        if(role==0){if(!S_ISDIR(s->st_mode)||(s->st_mode&07777)!=0700)return media_reject(e,0);}
        else if(!S_ISREG(s->st_mode)||s->st_nlink!=1||(s->st_mode&06022)||s->st_size<1||
                s->st_size>(role==1?65552:role==2?4194304:role==3?36864:64))return media_reject(e,0);
        if(role==1&&((s->st_mode&07777)!=0444||s->st_size!=(off_t)input_owner.launch_length))return media_reject(e,0);
    }
    return 0;
}
static const char *media_name(int role)
{
    static const char *const names[]={"launch-source","launch.bin","launch.squashfs","launch.verity","launch.root","null"};
    return names[role];
}
static int media_parent(int role)
{return role==1?input_owner.media_fds[0]:role==5?input_owner.runtime_fds[6]:input_owner.journal_fds[1];}
static int media_open(int role,int *slot,struct rnr_stage0_preparer_error *e)
{
    return open_input(media_parent(role),media_name(role),role==0,slot,e);
}
static int media_keep(int role,struct rnr_stage0_preparer_error *e)
{
    return media_open(role,&input_owner.media_fds[role],e)!=0?-1:
        media_object(input_owner.media_fds[role],role,&input_owner.media_identities[role],&input_owner.media_mounts[role],e);
}
static int media_recheck(int role,struct rnr_stage0_preparer_error *e)
{
    struct stat s;uint64_t m;int temporary=-1;
    if(media_object(input_owner.media_fds[role],role,&s,&m,e)!=0)return -1;
    if(!same_input(&s,&input_owner.media_identities[role],role==0)||m!=input_owner.media_mounts[role])return media_reject(e,0);
    if(media_open(role,&temporary,e)==0&&media_object(temporary,role,&s,&m,e)==0&&
       (!same_input(&s,&input_owner.media_identities[role],role==0)||m!=input_owner.media_mounts[role]))media_reject(e,0);
    close_input(&temporary,e);
    return e->code==RNR_STAGE0_PREPARER_OK?live_input(e):-1;
}
/* A fresh named directory FD is the only temporary while enumerating. */
static int media_source_inventory(int populated,struct rnr_stage0_preparer_error *e)
{
    int fd=-1;unsigned int seen=0,records=0;int eof=0;
    if(media_open(0,&fd,e)!=0)goto done;
    struct stat s;uint64_t m;
    if(media_object(fd,0,&s,&m,e)!=0)goto done;
    if(!same_input(&s,&input_owner.media_identities[0],1)||m!=input_owner.media_mounts[0]){media_reject(e,0);goto done;}
    for(int j=0;j<5;++j){
        unsigned char b[4096];if(live_input(e)!=0)goto done;
        long n=syscall(SYS_getdents64,fd,b,sizeof(b));int failure=n<0?errno:0;
        if(n<0){media_reject(e,failure);goto done;}
        if(live_input(e)!=0)goto done;
        if(!n){eof=1;break;}if(n>4096){media_reject(e,0);goto done;}
        for(size_t off=0;off<(size_t)n;){
            uint16_t size;uint64_t ino;int64_t next;unsigned int bit=0;
            if(++records>4||(size_t)n-off<24){media_reject(e,0);goto done;}
            memcpy(&ino,b+off,8);memcpy(&next,b+off+8,8);memcpy(&size,b+off+16,2);
            if(!ino||next<=0||size<24||size%8||size>(size_t)n-off){media_reject(e,0);goto done;}
            const unsigned char *name=b+off+19,*end=memchr(name,0,size-19);
            if(!end){media_reject(e,0);goto done;}
            size_t len=(size_t)(end-name);
            if(len==1&&name[0]=='.'&&b[off+18]==DT_DIR)bit=1;
            else if(len==2&&!memcmp(name,"..",2)&&b[off+18]==DT_DIR)bit=2;
            else if(populated&&len==10&&!memcmp(name,"launch.bin",10)&&b[off+18]==DT_REG&&ino==input_owner.media_identities[1].st_ino)bit=4;
            if(!bit||(seen&bit)){media_reject(e,0);goto done;}
            seen|=bit;off+=size;
        }
    }
    if(!eof||seen!=(populated?7U:3U)||records!=(populated?3U:2U))media_reject(e,0);
    /* Close enumeration before any named recheck; only one temporary. */
done:
    close_input(&fd,e);return e->code==RNR_STAGE0_PREPARER_OK?media_recheck(0,e):-1;
}
static int media_graph(struct rnr_stage0_preparer_error *e)
{
    if(mount_originals(e)!=0)return -1;
    for(int j=0;j<6;++j)if(input_owner.media_fds[j]>=0&&media_recheck(j,e)!=0)return -1;
    if(input_owner.media_fds[1]>=0&&(media_bytes(input_owner.media_fds[1],input_owner.launch_bytes,input_owner.launch_length,0,e)!=0||
       media_source_inventory(1,e)!=0))return -1;
    if(input_owner.media_fds[2]>=0&&media_bytes(input_owner.media_fds[2],input_owner.data_bytes,input_owner.data_length,0,e)!=0)return -1;
    if(input_owner.media_fds[3]>=0&&media_bytes(input_owner.media_fds[3],input_owner.hash_bytes,input_owner.hash_length,0,e)!=0)return -1;
    if(input_owner.media_fds[4]>=0&&media_bytes(input_owner.media_fds[4],input_owner.root_bytes,64,0,e)!=0)return -1;
    return live_input(e);
}
static int media_intent(unsigned int op,unsigned int role,const unsigned char payload[192],struct rnr_stage0_preparer_error *e)
{
    unsigned int seq=input_owner.journal_sequence;
    if(!((seq==22&&op==11&&role==8)||(seq==24&&op==12&&role==8)||
         (seq==26&&op==9&&role==23)||(seq==28&&op==13&&role==8)||
         (seq==30&&op==9&&role==24)||(seq==32&&op==14&&role==4)||
         (seq==34&&op==14&&role==25)||(seq==36&&op==10&&role==25)))return media_reject(e,0);
    input_owner.operation=op;input_owner.operation_role=role;
    input_owner.operation_entered=input_owner.operation_returned=input_owner.operation_errno=0;
    input_owner.operation_result=0;memcpy(input_owner.operation_payload,payload,192);
    return append_operation(0,payload,e);
}
static int media_result(int64_t result,int failure,struct rnr_stage0_preparer_error *e)
{
    input_owner.operation_result=result;input_owner.operation_errno=failure;input_owner.operation_returned=1;
    if(result<0)return media_reject(e,failure);
    return live_input(e);
}
static int media_build_source(struct rnr_stage0_preparer_error *e)
{
    unsigned char payload[192]={0};
    journal_u64(payload,input_owner.journal_identities[1].st_dev);
    journal_u64(payload+8,input_owner.journal_identities[1].st_ino);journal_u64(payload+16,input_owner.journal_mounts[1]);
    memcpy(payload+24,"launch-source",13);journal_u32(payload+96,0700);
    if(media_graph(e)!=0||media_intent(11,8,payload,e)!=0||live_input(e)!=0)return -1;
    input_owner.operation_entered=1;
    int result=mkdirat(input_owner.journal_fds[1],"launch-source",0700),failure=result<0?errno:0;
    if(media_result(result,failure,e)!=0||result!=0||media_keep(0,e)!=0||media_source_inventory(0,e)!=0||
       media_sync(input_owner.journal_fds[1],0,e)!=0)return -1;
    journal_u64(payload+72,input_owner.media_identities[0].st_dev);journal_u64(payload+80,input_owner.media_identities[0].st_ino);
    journal_u64(payload+88,input_owner.media_mounts[0]);
    if(append_operation(1,payload,e)!=0)return -1;
    input_owner.launch_length=16+input_owner.task.payload_bytes;
    memcpy(input_owner.launch_bytes,"RNRL0001",8);journal_u64(input_owner.launch_bytes+8,(uint64_t)input_owner.task.wall_cutoff_ns);
    memcpy(input_owner.launch_bytes+16,input_owner.task.payload,input_owner.task.payload_bytes);
    memset(payload,0,sizeof(payload));journal_u64(payload,input_owner.media_identities[0].st_dev);
    journal_u64(payload+8,input_owner.media_identities[0].st_ino);journal_u64(payload+16,input_owner.media_mounts[0]);
    memcpy(payload+24,"launch.bin",10);journal_u64(payload+72,input_owner.launch_length);
    journal_u64(payload+80,(uint64_t)input_owner.task.wall_cutoff_ns);journal_u32(payload+112,0444);
    if(media_graph(e)!=0||media_intent(12,8,payload,e)!=0||live_input(e)!=0)return -1;
    input_owner.operation_entered=1;
    result=openat(input_owner.media_fds[0],"launch.bin",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC,0444);
    failure=result<0?errno:0;
    if(result>=3)input_owner.media_fds[1]=result;
    else if(result>=0)e->unadopted_fd=result;
    if(media_result(result,failure,e)!=0||result<3)return media_reject(e,failure);
    struct stat created,after;uint64_t mount;
    if(preparation_access(result,O_WRONLY,e)!=0||stat_input(result,&created,e)!=0||mount_input(result,&mount,e)!=0)return -1;
    if(!S_ISREG(created.st_mode)||(created.st_mode&07777)!=0444||created.st_uid||created.st_gid||created.st_nlink!=1||created.st_size||
       created.st_dev!=input_owner.media_identities[0].st_dev||mount!=input_owner.media_mounts[0])return media_reject(e,0);
    if(live_input(e)!=0)return -1;
    input_owner.media_steps[1].entered=1;
    ssize_t n=pwrite(result,input_owner.launch_bytes,input_owner.launch_length,0);failure=n<0?errno:0;
    if(media_step(1,n,failure,e)!=0||n!=(ssize_t)input_owner.launch_length)return media_reject(e,failure);
    if(media_sync(result,2,e)!=0||media_sync(input_owner.media_fds[0],3,e)!=0||
       stat_input(result,&after,e)!=0||mount_input(result,&mount,e)!=0)return -1;
    if(!same_input(&created,&after,1)||after.st_nlink!=1||after.st_size!=(off_t)input_owner.launch_length||mount!=input_owner.media_mounts[0])return media_reject(e,0);
    if(media_close(&input_owner.media_fds[1],4,e)!=0||media_keep(1,e)!=0)return -1;
    if(!same_input(&after,&input_owner.media_identities[1],0)||mount!=input_owner.media_mounts[1]||
       media_bytes(input_owner.media_fds[1],input_owner.launch_bytes,input_owner.launch_length,0,e)!=0||media_source_inventory(1,e)!=0)return media_reject(e,0);
    journal_u64(payload+88,after.st_dev);journal_u64(payload+96,after.st_ino);journal_u64(payload+104,mount);
    if(append_operation(1,payload,e)!=0)return -1;
    return media_graph(e);
}
static int media_elf_open(int helper,int *slot,struct rnr_stage0_preparer_error *e)
{
    static const char *const paths[]={"usr/bin/mksquashfs","usr/sbin/veritysetup"};
    const struct open_how how={.flags=O_RDONLY|O_NONBLOCK|O_CLOEXEC,
        .resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_XDEV};
    _Static_assert(sizeof(struct open_how)==24,"fixed Linux openat2 ABI");
    if(live_input(e)!=0)return -1;
    long result=syscall(SYS_openat2,input_owner.runtime_fds[13],paths[helper],&how,sizeof(how));int failure=result<0?errno:0;
    if(result>=3&&result<=INT_MAX)*slot=(int)result;
    else if(result>=0&&result<=INT_MAX)e->unadopted_fd=(int)result;
    if(result<3||result>INT_MAX)return media_reject(e,failure);
    return live_input(e);
}
static int media_elf_header(int fd,struct rnr_stage0_preparer_error *e)
{
    Elf64_Ehdr h;if(live_input(e)!=0)return -1;
    ssize_t n=pread(fd,&h,sizeof(h),0);int failure=n<0?errno:0;
    if(n!=sizeof(h))return media_reject(e,failure);
    if(live_input(e)!=0)return -1;
    if(memcmp(h.e_ident,ELFMAG,SELFMAG)||h.e_ident[EI_CLASS]!=ELFCLASS64||h.e_ident[EI_DATA]!=ELFDATA2LSB||
       h.e_ident[EI_VERSION]!=EV_CURRENT||(h.e_type!=ET_EXEC&&h.e_type!=ET_DYN)||h.e_machine!=EM_X86_64||
       h.e_version!=EV_CURRENT||h.e_ehsize!=64)return media_reject(e,0);
    return 0;
}
static int media_elf_recheck(int helper,struct rnr_stage0_preparer_error *e)
{
    struct stat s;uint64_t m;int fd=-1;
    if(media_object(input_owner.media_fds[6],6,&s,&m,e)!=0||media_elf_header(input_owner.media_fds[6],e)!=0)return -1;
    if(!same_input(&s,&input_owner.media_identities[6],0)||m!=input_owner.media_mounts[6])return media_reject(e,0);
    if(media_elf_open(helper,&fd,e)==0&&media_object(fd,6,&s,&m,e)==0&&media_elf_header(fd,e)==0&&
       (!same_input(&s,&input_owner.media_identities[6],0)||m!=input_owner.media_mounts[6]))media_reject(e,0);
    close_input(&fd,e);return e->code==RNR_STAGE0_PREPARER_OK?live_input(e):-1;
}
/* Copied child never calls the positive owner or clock and never returns. */
static _Noreturn void media_child(int helper)
{
    /* Fork clears PDEATHSIG. Bind this copied helper to its ORIGINAL positive
     * owner before root/FD work; checking after arming closes the lost-parent
     * race. The independent observer intentionally uses a different lifetime.
     * This is not transitive descendant containment. Preservation across exec
     * also requires the actual immutable helper's no-credential-change audit.
     */
    pid_t parent=atomic_load_explicit(&input_owner_pid,memory_order_acquire);
    int death_signal=0;
    if(parent<=0 || getppid()!=parent ||
       prctl(PR_SET_PDEATHSIG,(unsigned long)SIGKILL,0UL,0UL,0UL) ||
       getppid()!=parent)_exit(127);
    char *const env[]={"LC_ALL=C","TZ=UTC",NULL};
    char *const squash[]={"/usr/bin/mksquashfs",input_owner.source_path,input_owner.data_path,
        "-noappend","-processors","1","-no-progress","-no-xattrs","-all-root","-mkfs-time","0","-all-time","0",
        "-comp","gzip","-b","4096","-no-exports","-no-fragments",NULL};
    char *const verity[]={"/usr/sbin/veritysetup","format",input_owner.data_path,input_owner.hash_path,
        "--no-superblock","--format=1","--hash=sha256","--data-block-size=4096","--hash-block-size=4096","--hash-offset=0",
        input_owner.salt_arg,input_owner.rootfile_arg,NULL};
    if(fchdir(input_owner.runtime_fds[13])||chroot(".")||chdir("/")||
       dup3(input_owner.media_fds[6],3,O_CLOEXEC)!=3||dup2(input_owner.media_fds[5],0)!=0||
       dup2(input_owner.media_fds[9],1)!=1||dup2(input_owner.media_fds[11],2)!=2)_exit(127);
    for(int fd=1;fd<=2;++fd){int flags=fcntl(fd,F_GETFL);
        if(flags<0||fcntl(fd,F_SETFL,flags&~O_NONBLOCK))_exit(127);}
    if(syscall(SYS_close_range,4U,UINT_MAX,0U))_exit(127);
    (void)umask(077);
    if(prctl(PR_GET_PDEATHSIG,&death_signal,0UL,0UL,0UL) ||
       death_signal!=SIGKILL || getppid()!=parent)_exit(127);
    (void)syscall(SYS_execveat,3,"",helper?verity:squash,env,AT_EMPTY_PATH);
    _exit(127);
}
static int media_helper_close(int helper,int role,struct rnr_stage0_preparer_error *e)
{
    int fd=input_owner.media_fds[role];
    if(fd<0)return 0; /* already consumed write end: never overwrite evidence */
    if(live_input(e)!=0)return -1;
    input_owner.media_fds[role]=-1;
    input_owner.helper_closes[helper][role-6].fd=fd;
    input_owner.helper_closes[helper][role-6].entered=1;
    int result=close(fd),failure=result<0?errno:0;
    input_owner.helper_closes[helper][role-6].result=result;
    input_owner.helper_closes[helper][role-6].system_errno=failure;
    if(result<0){
        if(e->cleanup_count<96){e->cleanup_errors[e->cleanup_count].fd=fd;
            e->cleanup_errors[e->cleanup_count++].system_errno=failure;}
        else e->cleanup_overflow=1;
        return media_reject(e,failure);
    }
    return live_input(e);
}
static int media_helper(int helper,struct rnr_stage0_preparer_error *e)
{
    if(media_graph(e)!=0||media_absent(helper,e)!=0||media_elf_open(helper,&input_owner.media_fds[6],e)!=0||
       media_object(input_owner.media_fds[6],6,&input_owner.media_identities[6],&input_owner.media_mounts[6],e)!=0||
       media_elf_header(input_owner.media_fds[6],e)!=0||media_elf_recheck(helper,e)!=0)return -1;
    struct sigaction action={0};if(live_input(e)!=0)return -1;
    int result=sigaction(SIGCHLD,NULL,&action),failure=result<0?errno:0;
    if(result||action.sa_handler!=SIG_DFL||(action.sa_flags&SA_NOCLDWAIT))return media_reject(e,failure);
    if(live_input(e)!=0)return -1;
    unsigned char payload[192]={0};journal_u32(payload+8,(unsigned int)helper+23);
    if(media_intent(9,(unsigned int)helper+23,payload,e)!=0)return -1;
    for(int stream=0;stream<2;++stream){
        int pair[2]={-1,-1};if(live_input(e)!=0)return -1;
        result=pipe2(pair,O_CLOEXEC|O_NONBLOCK);failure=result<0?errno:0;
        if(result)return media_reject(e,failure);
        if(pair[0]>=3)input_owner.media_fds[stream?10:8]=pair[0];else e->unadopted_fd=pair[0];
        if(pair[1]>=3)input_owner.media_fds[stream?11:9]=pair[1];else e->unadopted_fd=pair[1];
        if(live_input(e)!=0)return -1;
        if(pair[0]<3||pair[1]<3||pair[0]==pair[1])return media_reject(e,0);
    }
    if(media_graph(e)!=0||media_elf_recheck(helper,e)!=0||media_absent(helper,e)!=0||live_input(e)!=0)return -1;
    input_owner.child_entered=1;input_owner.child_returned=input_owner.child_reaped=0;input_owner.child_pid=0;
    input_owner.operation_entered=1;
    pid_t child=fork();failure=child<0?errno:0;
    if(!child)media_child(helper);
    input_owner.child_pid=child;input_owner.child_errno=failure;input_owner.child_returned=1;
    if(media_result(child,failure,e)!=0||child<=0)return media_reject(e,failure);
    if(live_input(e)!=0)return -1;
    long fd=syscall(SYS_pidfd_open,child,0);failure=fd<0?errno:0;
    if(fd>=3&&fd<=INT_MAX)input_owner.media_fds[7]=(int)fd;
    else if(fd>=0&&fd<=INT_MAX)e->unadopted_fd=(int)fd;
    if(fd<3||fd>INT_MAX)return media_reject(e,failure);
    if(live_input(e)!=0||media_helper_close(helper,9,e)!=0||
       media_helper_close(helper,11,e)!=0||media_collect(e)!=0)return -1;
    for(int j=11;j>=6;--j)if(media_helper_close(helper,j,e)!=0)return -1;
    journal_u64(payload,(uint64_t)child);journal_u32(payload+12,(uint32_t)input_owner.child_status);
    if(media_graph(e)!=0||append_operation(1,payload,e)!=0)return -1;
    return 0;
}
static int media_same_object(const struct stat *a,const struct stat *b)
{
    return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_rdev==b->st_rdev&&
        a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&a->st_nlink==1&&b->st_nlink==1&&
        (a->st_mode&S_IFMT)==(b->st_mode&S_IFMT);
}
static int media_pad(struct rnr_stage0_preparer_error *e)
{
    if(media_keep(2,e)!=0)return -1;
    size_t original=(size_t)input_owner.media_identities[2].st_size;
    size_t padded=(original+4095)&~(size_t)4095;if(padded<8192)padded=8192;
    if(padded>4194304||padded-original>8191)return media_reject(e,0);
    input_owner.data_length=original;
    if(media_bytes(input_owner.media_fds[2],input_owner.data_bytes,original,1,e)!=0||media_graph(e)!=0)return -1;
    unsigned char payload[192]={0};struct stat before=input_owner.media_identities[2],after;uint64_t m;
    journal_u64(payload,before.st_dev);journal_u64(payload+8,before.st_ino);journal_u64(payload+16,input_owner.media_mounts[2]);
    journal_u64(payload+24,original);journal_u64(payload+32,padded);journal_u32(payload+40,0444);
    if(media_intent(13,8,payload,e)!=0||live_input(e)!=0)return -1;
    int fd=-1;input_owner.operation_entered=1;
    int result=openat(input_owner.journal_fds[1],"launch.squashfs",O_WRONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    int failure=result<0?errno:0;
    if(result>=3)fd=result;else if(result>=0)e->unadopted_fd=result;
    if(media_result(result,failure,e)!=0)goto done;
    if(result<3){media_reject(e,0);goto done;}
    if(preparation_access(fd,O_WRONLY,e)!=0||stat_input(fd,&after,e)!=0||mount_input(fd,&m,e)!=0)goto done;
    if(!same_input(&before,&after,0)||m!=input_owner.media_mounts[2]){media_reject(e,0);goto done;}
    memset(input_owner.data_bytes+original,0,padded-original);
    if(padded>original){
        if(live_input(e)!=0)goto done;
        input_owner.media_steps[22].entered=1;
        ssize_t n=pwrite(fd,input_owner.data_bytes+original,padded-original,(off_t)original);failure=n<0?errno:0;
        if(media_step(22,n,failure,e)!=0||n!=(ssize_t)(padded-original)){media_reject(e,failure);goto done;}
    }
    if(live_input(e)!=0)goto done;
    input_owner.media_steps[23].entered=1;
    result=fchmod(fd,0444);failure=result<0?errno:0;
    if(media_step(23,result,failure,e)!=0||media_sync(fd,24,e)!=0||media_sync(input_owner.journal_fds[1],25,e)!=0)goto done;
    if(media_close(&fd,26,e)!=0)goto done;
    if(media_object(input_owner.media_fds[2],2,&after,&m,e)!=0)goto done;
    if(!media_same_object(&before,&after)||m!=input_owner.media_mounts[2]||after.st_size!=(off_t)padded||
       (after.st_mode&07777)!=0444){media_reject(e,0);goto done;}
    if(media_bytes(input_owner.media_fds[2],input_owner.data_bytes,padded,0,e)!=0)goto done;
    /* Only these explicitly authorized size/mode/time changes become baseline. */
    input_owner.media_identities[2]=after;input_owner.data_length=padded;
    if(media_graph(e)!=0||append_operation(1,payload,e)!=0)goto done;
done:
    close_input(&fd,e);return e->code==RNR_STAGE0_PREPARER_OK?live_input(e):-1;
}
static int media_salt(struct rnr_stage0_preparer_error *e)
{
    if(live_input(e)!=0)return -1;
    input_owner.media_steps[27].entered=1;
    ssize_t result=getrandom(input_owner.media_output.launch.salt,32,0);int failure=result<0?errno:0;
    if(media_step(27,result,failure,e)!=0||result!=32)return media_reject(e,failure);
    unsigned int nonzero=0;static const char hex[]="0123456789abcdef";
    memcpy(input_owner.salt_arg,"--salt=",7);
    for(int j=0;j<32;++j){unsigned char c=input_owner.media_output.launch.salt[j];nonzero|=c;
        input_owner.salt_arg[7+2*j]=hex[c>>4];input_owner.salt_arg[8+2*j]=hex[c&15];}
    input_owner.salt_arg[71]=0;
    return nonzero?0:media_reject(e,0);
}
static int media_seal(int role,struct rnr_stage0_preparer_error *e)
{
    struct stat before=input_owner.media_identities[role],after;uint64_t m;
    unsigned char payload[192]={0};journal_u64(payload,before.st_dev);journal_u64(payload+8,before.st_ino);
    journal_u64(payload+16,input_owner.media_mounts[role]);journal_u64(payload+24,(uint64_t)before.st_size);journal_u32(payload+32,0444);
    if(media_graph(e)!=0||media_intent(14,role==3?4:25,payload,e)!=0||live_input(e)!=0)return -1;
    input_owner.operation_entered=1;
    int result=fchmod(input_owner.media_fds[role],0444),failure=result<0?errno:0;
    if(media_result(result,failure,e)!=0||media_sync(input_owner.media_fds[role],28+(unsigned int)role,e)!=0||
       media_sync(input_owner.journal_fds[1],32+(unsigned int)role,e)!=0||
       media_object(input_owner.media_fds[role],role,&after,&m,e)!=0)return -1;
    if(!media_same_object(&before,&after)||before.st_size!=after.st_size||m!=input_owner.media_mounts[role]||
       (after.st_mode&07777)!=0444||before.st_mtim.tv_sec!=after.st_mtim.tv_sec||before.st_mtim.tv_nsec!=after.st_mtim.tv_nsec)return media_reject(e,0);
    if(media_bytes(input_owner.media_fds[role],role==3?input_owner.hash_bytes:input_owner.root_bytes,
       role==3?input_owner.hash_length:64,0,e)!=0)return -1;
    input_owner.media_identities[role]=after;
    if(media_graph(e)!=0||append_operation(1,payload,e)!=0)return -1;
    return 0;
}
static int media_outputs(struct rnr_stage0_preparer_error *e)
{
    if(media_keep(3,e)!=0||media_keep(4,e)!=0)return -1;
    uint64_t blocks=input_owner.data_length/4096,n=blocks,total=0;
    do{n=(n+127)/128;total+=n;}while(n>1);
    input_owner.hash_length=(size_t)total*4096;
    if(input_owner.media_identities[3].st_size!=(off_t)input_owner.hash_length||input_owner.media_identities[4].st_size!=64)return media_reject(e,0);
    if(media_bytes(input_owner.media_fds[3],input_owner.hash_bytes,input_owner.hash_length,1,e)!=0||
       media_bytes(input_owner.media_fds[4],input_owner.root_bytes,64,1,e)!=0)return -1;
    unsigned int nonzero=0;
    for(int j=0;j<32;++j){unsigned int v=0;
        for(int k=0;k<2;++k){unsigned char c=input_owner.root_bytes[2*j+k];
            if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')))return media_reject(e,0);
            v=16*v+(c<='9'?c-'0':c-'a'+10);}
        input_owner.media_output.launch.root[j]=(unsigned char)v;nonzero|=v;
    }
    if(!nonzero)return media_reject(e,0);
    input_owner.media_output.launch.data_blocks=blocks;input_owner.media_output.launch.hash_blocks=total;
    memcpy(input_owner.media_output.task_id,input_owner.task.task_id,16);
    if(media_seal(3,e)!=0||media_seal(4,e)!=0||media_graph(e)!=0)return -1;
    unsigned char payload[192]={0},*raw=payload;
    memcpy(raw,"RNRP0001",8);journal_u32(raw+8,1);memcpy(raw+16,input_owner.task.task_id,16);
    memcpy(raw+32,input_owner.media_output.launch.root,32);memcpy(raw+64,input_owner.media_output.launch.salt,32);
    journal_u64(raw+96,blocks);journal_u64(raw+104,total);
    struct rnr_stage0_output decoded;
    if(rnr_stage0_decode_output(raw,128,&decoded)!=0)return media_reject(e,0);
    if(media_intent(10,25,payload,e)!=0||live_input(e)!=0)return -1;
    input_owner.operation_entered=1;
    if(media_result(0,0,e)!=0||append_operation(1,payload,e)!=0)return -1;
    return media_graph(e);
}
int rnr_stage0_prepare_launch_media(struct rnr_stage0_preparer_error *e)
{
    if(!e){fence_inputs();errno=EINVAL;return -1;}
    *e=(struct rnr_stage0_preparer_error){.unadopted_fd=-1};pid_t pid=getpid();
    if(pid<=0||syscall(SYS_gettid)!=(long)pid||geteuid()||getegid()||atomic_load(&input_owner_pid)!=pid){
        reject_input(e,RNR_STAGE0_PREPARER_OWNER,0);fence_inputs();return -1;}
    int expected=PREPARER_ROOT_HELD;
    if(!atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_MEDIA_ACQUIRING,
        memory_order_acq_rel,memory_order_acquire)){reject_input(e,RNR_STAGE0_PREPARER_ATTEMPT,0);fence_inputs();return -1;}
    for(int j=0;j<12;++j)input_owner.media_fds[j]=-1;
    input_owner.media_initialized=1;
    static const char *const suffix[]={"launch-source","launch.squashfs","launch.verity","launch.root"};
    char *const paths[]={input_owner.source_path,input_owner.data_path,input_owner.hash_path};
    for(int j=0;j<3;++j){int n=snprintf(paths[j],104,"/run/%s/%s",input_owner.work_name,suffix[j]);
        if(n<=0||n>=104){media_reject(e,0);goto failed;}}
    int n=snprintf(input_owner.rootfile_arg,sizeof(input_owner.rootfile_arg),"--root-hash-file=/run/%s/%s",input_owner.work_name,suffix[3]);
    if(n<=0||(size_t)n>=sizeof(input_owner.rootfile_arg)){media_reject(e,0);goto failed;}
    if(media_build_source(e)!=0||media_keep(5,e)!=0||media_helper(0,e)!=0||media_pad(e)!=0||
       media_salt(e)!=0||media_helper(1,e)!=0||media_outputs(e)!=0||live_input(e)!=0)goto failed;
    e->claim_disposition=input_owner.claim_disposition;e->mkdir_errno=input_owner.mkdir_errno;
    expected=PREPARER_MEDIA_ACQUIRING;
    if(!atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_MEDIA_HELD,
        memory_order_release,memory_order_relaxed)){media_reject(e,0);goto failed;}
    return 0;
failed:
    e->claim_disposition=input_owner.claim_disposition;e->mkdir_errno=input_owner.mkdir_errno;
    fence_inputs();drain_inputs(e);input_owner.original_error=*e;expected=PREPARER_FENCED_MEDIA_ACQUIRING;
    (void)atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_FAILED_DRAINED,
        memory_order_release,memory_order_relaxed);return -1;
}

static int launch_loop_object(int fd,unsigned int i,struct stat *s,uint64_t *m,
                              struct rnr_stage0_preparer_error *e)
{
    long fs;
    if(preparation_access(fd,O_RDONLY,e)!=0||stat_input(fd,s,e)!=0||mount_input(fd,m,e)!=0||filesystem_input(fd,&fs,e)!=0)return -1;
    if(!S_ISBLK(s->st_mode)||s->st_uid||!s->st_dev||!s->st_ino||
       s->st_rdev!=makedev(7,(unsigned int)input_owner.launch_candidates[i])||fs!=0x1021994||
       s->st_dev!=input_owner.runtime_identities[6].st_dev||*m!=input_owner.runtime_mounts[6]){
        reject_input(e,RNR_STAGE0_PREPARER_LOOP,0);return -1;}
    return 0;
}
static int launch_loop_recheck(unsigned int i,struct rnr_stage0_preparer_error *e)
{
    struct stat s;uint64_t m;int temporary=-1;
    if(launch_loop_object(input_owner.launch_fds[i],i,&s,&m,e)!=0)return -1;
    if(!same_input(&s,&input_owner.launch_identities[i],0)||m!=input_owner.launch_mounts[i]){
        reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);return -1;}
    if(open_input(input_owner.runtime_fds[6],input_owner.launch_names[i],0,&temporary,e)==0&&
       launch_loop_object(temporary,i,&s,&m,e)==0&&
       (!same_input(&s,&input_owner.launch_identities[i],0)||m!=input_owner.launch_mounts[i]))
        reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);
    close_input(&temporary,e);return e->code==RNR_STAGE0_PREPARER_OK?live_input(e):-1;
}
static int launch_loop_verify(unsigned int i,struct rnr_stage0_preparer_error *e)
{
    struct loop_info64 info={0};int ro=0;uint64_t size=0;
    int fd=input_owner.launch_fds[i];const struct stat *back=&input_owner.media_identities[2+i];
    if(loop_observe(fd,LOOP_GET_STATUS64,&info,e)!=0||loop_observe(fd,BLKROGET,&ro,e)!=0||loop_observe(fd,BLKGETSIZE64,&size,e)!=0)return -1;
    unsigned int maj=major(back->st_dev),min=minor(back->st_dev);
    uint64_t kernel_dev=(min&255U)|((uint64_t)maj<<8)|((uint64_t)(min&~255U)<<12);
    if(maj>=4096||min>=1048576||info.lo_device!=kernel_dev||info.lo_inode!=back->st_ino||info.lo_rdevice||
       info.lo_number!=(unsigned int)input_owner.launch_candidates[i]||info.lo_offset||info.lo_sizelimit!=(uint64_t)back->st_size||
       info.lo_flags!=LO_FLAGS_READ_ONLY||info.lo_encrypt_type||info.lo_encrypt_key_size||memcmp(info.lo_file_name,input_owner.launch_tags[i],64)||
       ro!=1||size!=(uint64_t)back->st_size){reject_input(e,RNR_STAGE0_PREPARER_LOOP,0);return -1;}
    return launch_loop_recheck(i,e);
}
static int launch_loop_originals(unsigned int ready,struct rnr_stage0_preparer_error *e)
{
    if(media_graph(e)!=0)return -1;
    for(unsigned int i=0;i<ready;++i)if(launch_loop_verify(i,e)!=0)return -1;
    return live_input(e);
}
static int launch_loop_intent(unsigned int op,unsigned int i,const unsigned char payload[192],
                              struct rnr_stage0_preparer_error *e)
{
    unsigned int seq=input_owner.journal_sequence;
    if(i>1||(op!=1&&op!=2)||seq!=38+4*i+(op==2?2U:0U)){
        reject_input(e,RNR_STAGE0_PREPARER_JOURNAL,0);return -1;}
    input_owner.operation=op;input_owner.operation_role=3+i;
    input_owner.operation_entered=input_owner.operation_returned=input_owner.operation_errno=0;
    input_owner.operation_result=0;memcpy(input_owner.operation_payload,payload,192);
    return append_operation(0,payload,e);
}
static int launch_loop_result(int result,int failure,struct rnr_stage0_preparer_error *e)
{
    input_owner.operation_result=result;input_owner.operation_errno=failure;input_owner.operation_returned=1;
    if(result<0){reject_input(e,RNR_STAGE0_PREPARER_LOOP,failure);return -1;}
    return live_input(e);
}
static int launch_configure_loop(unsigned int i,struct rnr_stage0_preparer_error *e)
{
    unsigned char payload[192]={0};const struct stat *back=&input_owner.media_identities[2+i];
    journal_u64(payload,back->st_dev);journal_u64(payload+8,back->st_ino);journal_u64(payload+16,(uint64_t)back->st_size);
    journal_u64(payload+24,input_owner.media_mounts[2+i]);journal_u32(payload+44,LO_FLAGS_READ_ONLY);
    memcpy(payload+48,input_owner.launch_tags[i],64);journal_u64(payload+120,(uint64_t)back->st_size);
    if(launch_loop_originals(i,e)!=0||launch_loop_intent(1,i,payload,e)!=0||live_input(e)!=0)return -1;
    input_owner.operation_entered=1;
    int candidate=ioctl(input_owner.runtime_fds[7],LOOP_CTL_GET_FREE,0),failure=candidate<0?errno:0;
    input_owner.launch_candidates[i]=candidate; /* retain even refused/expired */
    if(launch_loop_result(candidate,failure,e)!=0)return -1;
    if(candidate>1048575||candidate==input_owner.loop_candidates[0]||candidate==input_owner.loop_candidates[1]||
       (i&&candidate==input_owner.launch_candidates[0])){reject_input(e,RNR_STAGE0_PREPARER_LOOP,0);return -1;}
    journal_u32(payload+32,(uint32_t)candidate);
    if(append_operation(1,payload,e)!=0)return -1;
    int n=snprintf(input_owner.launch_names[i],24,"loop%d",candidate);
    if(n<=0||n>=24){reject_input(e,RNR_STAGE0_PREPARER_LOOP,0);return -1;}
    if(open_input(input_owner.runtime_fds[6],input_owner.launch_names[i],0,&input_owner.launch_fds[i],e)!=0||
       launch_loop_object(input_owner.launch_fds[i],i,&input_owner.launch_identities[i],&input_owner.launch_mounts[i],e)!=0)return -1;
    struct loop_info64 prior={0};if(live_input(e)!=0)return -1;
    int result=ioctl(input_owner.launch_fds[i],LOOP_GET_STATUS64,&prior);failure=result<0?errno:0;
    if(live_input(e)!=0)return -1;
    if(result!=-1||failure!=ENXIO){reject_input(e,RNR_STAGE0_PREPARER_LOOP,failure);return -1;}
    if(launch_loop_originals(i,e)!=0||launch_loop_recheck(i,e)!=0)return -1;
    journal_u32(payload+36,7);journal_u32(payload+40,(uint32_t)candidate);
    if(launch_loop_intent(2,i,payload,e)!=0||live_input(e)!=0)return -1;
    struct loop_config config={0};config.fd=(uint32_t)input_owner.media_fds[2+i];config.block_size=4096;
    config.info.lo_flags=LO_FLAGS_READ_ONLY;config.info.lo_sizelimit=(uint64_t)back->st_size;
    memcpy(config.info.lo_file_name,input_owner.launch_tags[i],64);
    input_owner.operation_entered=1;
    result=ioctl(input_owner.launch_fds[i],LOOP_CONFIGURE,&config);failure=result<0?errno:0;
    if(launch_loop_result(result,failure,e)!=0)return -1;
    if(result!=0){reject_input(e,RNR_STAGE0_PREPARER_LOOP,0);return -1;}
    if(append_operation(1,payload,e)!=0||launch_loop_originals(i+1,e)!=0)return -1;
    return 0;
}
int rnr_stage0_prepare_launch_loops(struct rnr_stage0_preparer_error *e)
{
    if(!e){fence_inputs();errno=EINVAL;return -1;}
    *e=(struct rnr_stage0_preparer_error){.unadopted_fd=-1};pid_t pid=getpid();
    if(pid<=0||syscall(SYS_gettid)!=(long)pid||geteuid()||getegid()||atomic_load(&input_owner_pid)!=pid){
        reject_input(e,RNR_STAGE0_PREPARER_OWNER,0);fence_inputs();return -1;}
    int expected=PREPARER_MEDIA_HELD;
    if(!atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_LAUNCH_LOOPS_ACQUIRING,
        memory_order_acq_rel,memory_order_acquire)){reject_input(e,RNR_STAGE0_PREPARER_ATTEMPT,0);fence_inputs();return -1;}
    for(int i=0;i<5;++i)input_owner.launch_fds[i]=-1;
    for(int i=0;i<2;++i)input_owner.launch_candidates[i]=-1;
    input_owner.launch_initialized=1;
    for(int i=6;i<12;++i)if(input_owner.media_fds[i]!=-1){reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);goto failed;}
    if(!input_owner.child_reaped||!WIFEXITED(input_owner.child_status)||WEXITSTATUS(input_owner.child_status)){
        reject_input(e,RNR_STAGE0_PREPARER_IDENTITY,0);goto failed;}
    if(media_graph(e)!=0)goto failed;
    static const char hex[]="0123456789abcdef";
    for(int i=0;i<2;++i){memcpy(input_owner.launch_tags[i],"rnr-",4);
        for(int j=0;j<16;++j){input_owner.launch_tags[i][4+2*j]=hex[input_owner.task.task_id[j]>>4];
            input_owner.launch_tags[i][5+2*j]=hex[input_owner.task.task_id[j]&15];}
        memcpy(input_owner.launch_tags[i]+36,i?"-lh":"-ld",4);
    }
    for(unsigned int i=0;i<2;++i)if(launch_configure_loop(i,e)!=0)goto failed;
    if(launch_loop_originals(2,e)!=0||check_operation_journal(12032,e)!=0||live_input(e)!=0)goto failed;
    e->claim_disposition=input_owner.claim_disposition;e->mkdir_errno=input_owner.mkdir_errno;
    expected=PREPARER_LAUNCH_LOOPS_ACQUIRING;
    if(!atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_LAUNCH_LOOPS_HELD,
        memory_order_release,memory_order_relaxed)){reject_input(e,RNR_STAGE0_PREPARER_ATTEMPT,0);goto failed;}
    return 0;
failed:
    e->claim_disposition=input_owner.claim_disposition;e->mkdir_errno=input_owner.mkdir_errno;
    fence_inputs();drain_inputs(e);input_owner.original_error=*e;expected=PREPARER_FENCED_LAUNCH_LOOPS_ACQUIRING;
    (void)atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_FAILED_DRAINED,
        memory_order_release,memory_order_relaxed);return -1;
}

/* Launch mapping is a second closed owner, never a parsed journal handle. */
static int launch_mapping_object(int fd,struct stat *s,uint64_t *m,struct rnr_stage0_preparer_error *e)
{
    long fs;uint64_t device=input_owner.launch_mapping.dm_device;
    dev_t node=makedev((device>>8)&4095,(device&255)|((device>>12)&0xfff00));
    if(preparation_access(fd,O_RDONLY,e)!=0||stat_input(fd,s,e)!=0||mount_input(fd,m,e)!=0||filesystem_input(fd,&fs,e)!=0)return -1;
    if(!S_ISBLK(s->st_mode)||s->st_uid||!s->st_dev||!s->st_ino||s->st_rdev!=node||
       s->st_rdev==input_owner.runtime_identities[12].st_rdev||fs!=0x1021994||
       s->st_dev!=input_owner.runtime_identities[6].st_dev||*m!=input_owner.runtime_mounts[6])return dm_reject(e,0);
    return 0;
}
static int launch_mapping_recheck(struct rnr_stage0_preparer_error *e)
{
    struct stat s;uint64_t m;int temporary=-1;
    if(launch_mapping_object(input_owner.launch_fds[2],&s,&m,e)!=0)return -1;
    if(!same_input(&s,&input_owner.launch_identities[2],0)||m!=input_owner.launch_mounts[2])return dm_reject(e,0);
    if(open_input(input_owner.runtime_fds[6],input_owner.launch_mapping.dm_node,0,&temporary,e)==0&&
       launch_mapping_object(temporary,&s,&m,e)==0&&
       (!same_input(&s,&input_owner.launch_identities[2],0)||m!=input_owner.launch_mounts[2]))dm_reject(e,0);
    close_input(&temporary,e);return e->code==RNR_STAGE0_PREPARER_OK?live_input(e):-1;
}
static int launch_mapping_status(unsigned int flags,unsigned int count,struct rnr_stage0_preparer_error *e)
{
    return mapping_exchange(MAPPING_LAUNCH,DM_DEV_STATUS,0,0,NULL,e)!=0?-1:
        mapping_header(MAPPING_LAUNCH,flags,count,1,0,e);
}
int rnr_stage0_prepare_launch_mapping(struct rnr_stage0_preparer_error *e)
{
    if(!e){fence_inputs();errno=EINVAL;return -1;}
    *e=(struct rnr_stage0_preparer_error){.unadopted_fd=-1};pid_t pid=getpid();
    if(pid<=0||syscall(SYS_gettid)!=(long)pid||geteuid()||getegid()||atomic_load(&input_owner_pid)!=pid){
        dm_reject(e,0);fence_inputs();return -1;
    }
    int expected=PREPARER_LAUNCH_LOOPS_HELD;
    if(!atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_LAUNCH_DM_ACQUIRING,
        memory_order_acq_rel,memory_order_acquire)){dm_reject(e,0);fence_inputs();return -1;}
    if(launch_loop_originals(2,e)!=0||check_operation_journal(12032,e)!=0)goto failed;
    struct mapping_owner *m=&input_owner.launch_mapping;
    const struct rnr_stage0_image_record *image=&input_owner.media_output.launch;
    char taskhex[33],root[65],salt[65];static const char hex[]="0123456789abcdef";
    for(int j=0;j<16;++j){taskhex[2*j]=hex[input_owner.task.task_id[j]>>4];taskhex[2*j+1]=hex[input_owner.task.task_id[j]&15];}
    taskhex[32]=0;
    for(int j=0;j<32;++j){root[2*j]=hex[image->root[j]>>4];root[2*j+1]=hex[image->root[j]&15];
        salt[2*j]=hex[image->salt[j]>>4];salt[2*j+1]=hex[image->salt[j]&15];}
    root[64]=salt[64]=0;
    (void)snprintf(m->dm_name,128,"rnr-l-%s",taskhex);
    (void)snprintf(m->dm_uuid,129,"rnr-native-%s-launch",taskhex);
    int n=snprintf(m->dm_params,512,"1 7:%d 7:%d 4096 4096 %llu 0 sha256 %s %s",
        input_owner.launch_candidates[0],input_owner.launch_candidates[1],(unsigned long long)image->data_blocks,root,salt);
    if(n<=0||n>=512){dm_reject(e,0);goto failed;}
    if(mapping_exchange(MAPPING_LAUNCH,DM_VERSION,0,0,NULL,e)!=0)goto failed;
    struct dm_ioctl version;memcpy(&version,m->dm_response,312);
    if(version.version[0]!=4||version.version[1]!=50||version.version[2]){dm_reject(e,0);goto failed;}
    unsigned char payload[192]={0};memcpy(payload,m->dm_name,48);memcpy(payload+48,m->dm_uuid,64);
    if(mapping_exchange(MAPPING_LAUNCH,DM_DEV_CREATE,0,3,payload,e)!=0||
       mapping_header(MAPPING_LAUNCH,0,0,1,1,e)!=0||launch_mapping_status(0,0,e)!=0)goto failed;
    memset(payload,0,192);
    journal_u64(payload,(uint64_t)input_owner.launch_identities[0].st_rdev);
    journal_u64(payload+8,(uint64_t)input_owner.launch_identities[1].st_rdev);
    journal_u64(payload+16,m->dm_device);journal_u64(payload+24,image->data_blocks);journal_u64(payload+32,image->hash_blocks);
    memcpy(payload+40,image->root,32);memcpy(payload+72,image->salt,32);journal_u64(payload+104,image->data_blocks*8);journal_u32(payload+112,1);
    if(mapping_exchange(MAPPING_LAUNCH,DM_TABLE_LOAD,1,4,payload,e)!=0||
       mapping_header(MAPPING_LAUNCH,64,0,1,0,e)!=0||mapping_table(MAPPING_LAUNCH,1,0,e)!=0||
       launch_mapping_status(64,0,e)!=0)goto failed;
    journal_u32(payload+112,0);
    if(mapping_exchange(MAPPING_LAUNCH,DM_DEV_SUSPEND,0,5,payload,e)!=0)goto failed;
    struct dm_ioctl resumed;memcpy(&resumed,m->dm_response,312);
    if(resumed.event_nr<m->dm_event||(resumed.flags!=33&&resumed.flags!=8225)){dm_reject(e,0);goto failed;}
    if(mapping_header_event(MAPPING_LAUNCH,resumed.flags,1,1,0,resumed.event_nr,e)!=0)goto failed;
    m->dm_event=resumed.event_nr;
    if(mapping_table(MAPPING_LAUNCH,0,0,e)!=0||mapping_table(MAPPING_LAUNCH,0,1,e)!=0||launch_mapping_status(33,1,e)!=0)goto failed;
    n=snprintf(m->dm_node,24,"dm-%u",(unsigned int)((m->dm_device&255)|((m->dm_device>>12)&0xfff00)));
    if(n<=0||n>=24){dm_reject(e,0);goto failed;}
    if(open_input(input_owner.runtime_fds[6],m->dm_node,0,&input_owner.launch_fds[2],e)!=0||
       launch_mapping_object(input_owner.launch_fds[2],&input_owner.launch_identities[2],&input_owner.launch_mounts[2],e)!=0)goto failed;
    m->dm_openers=1;
    int ro=0;uint64_t size=0;
    if(loop_observe(input_owner.launch_fds[2],BLKROGET,&ro,e)!=0||
       loop_observe(input_owner.launch_fds[2],BLKGETSIZE64,&size,e)!=0)goto failed;
    if(ro!=1||size!=image->data_blocks*4096){dm_reject(e,0);goto failed;}
    if(launch_loop_originals(2,e)!=0||launch_mapping_recheck(e)!=0||launch_mapping_status(33,1,e)!=0||
       mapping_table(MAPPING_LAUNCH,0,0,e)!=0||mapping_table(MAPPING_LAUNCH,0,1,e)!=0||
       check_operation_journal(13568,e)!=0||live_input(e)!=0)goto failed;
    e->claim_disposition=input_owner.claim_disposition;e->mkdir_errno=input_owner.mkdir_errno;
    expected=PREPARER_LAUNCH_DM_ACQUIRING;
    if(!atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_LAUNCH_DM_HELD,
       memory_order_release,memory_order_relaxed)){dm_reject(e,0);goto failed;}
    return 0;
failed:
    e->claim_disposition=input_owner.claim_disposition;e->mkdir_errno=input_owner.mkdir_errno;
    fence_inputs();drain_inputs(e);input_owner.original_error=*e;expected=PREPARER_FENCED_LAUNCH_DM_ACQUIRING;
    (void)atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_FAILED_DRAINED,
        memory_order_release,memory_order_relaxed);return -1;
}

static int launch_mapping_originals(struct rnr_stage0_preparer_error *e)
{
    int ro=0;uint64_t bytes=0;
    if(launch_loop_originals(2,e)!=0||launch_mapping_recheck(e)!=0||
       loop_observe(input_owner.launch_fds[2],BLKROGET,&ro,e)!=0||
       loop_observe(input_owner.launch_fds[2],BLKGETSIZE64,&bytes,e)!=0)return -1;
    if(ro!=1||bytes!=input_owner.media_output.launch.data_blocks*4096)return dm_reject(e,0);
    return launch_mapping_status(33,1,e)!=0||mapping_table(MAPPING_LAUNCH,0,0,e)!=0||
        mapping_table(MAPPING_LAUNCH,0,1,e)!=0?-1:live_input(e);
}
static int launch_root_object(int fd,unsigned int role,struct stat *s,uint64_t *m,
                              struct rnr_stage0_preparer_error *e)
{
    long fs;unsigned long flags;
    if(preparation_access(fd,O_RDONLY,e)!=0||stat_input(fd,s,e)!=0||mount_input(fd,m,e)!=0||filesystem_input(fd,&fs,e)!=0)return -1;
    if(s->st_uid||s->st_gid||!s->st_dev||!s->st_ino)return mount_reject(e,0);
    if(role==4){
        if(!S_ISREG(s->st_mode)||(s->st_mode&07777)!=0444||s->st_nlink!=1||s->st_size!=(off_t)input_owner.launch_length||
           s->st_dev!=input_owner.launch_identities[3].st_dev||*m!=input_owner.launch_mounts[3])return mount_reject(e,0);
    }else if(!S_ISDIR(s->st_mode)||(s->st_mode&022))return mount_reject(e,0);
    if(!input_owner.launch_root_mounted){
        if(role!=3||(s->st_mode&07777)!=0700||fs!=0x1021994||s->st_dev!=input_owner.journal_identities[1].st_dev||
           *m!=input_owner.journal_mounts[1])return mount_reject(e,0);
    }else{
        uint64_t device=input_owner.launch_mapping.dm_device;
        if(fs!=0x73717368||s->st_dev!=makedev((device>>8)&4095,(device&255)|((device>>12)&0xfff00))||
           *m==input_owner.journal_mounts[1]||*m==input_owner.runtime_mounts[13]||
           mount_vfs(fd,&flags,e)!=0||(flags&15)!=7)return mount_reject(e,0);
    }
    return 0;
}
static int launch_root_open(unsigned int role,int *slot,struct rnr_stage0_preparer_error *e)
{
    if(live_input(e)!=0)return -1;
    int fd=openat(role==3?input_owner.journal_fds[1]:input_owner.launch_fds[3],role==3?"launch":"launch.bin",
                  O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC|(role==3?O_DIRECTORY:0));
    if(fd<0)return mount_reject(e,errno);
    if(fd<3){e->unadopted_fd=fd;return mount_reject(e,0);}
    *slot=fd;return live_input(e);
}
static int launch_root_keep(unsigned int role,struct rnr_stage0_preparer_error *e)
{
    return launch_root_open(role,&input_owner.launch_fds[role],e)!=0?-1:
        launch_root_object(input_owner.launch_fds[role],role,&input_owner.launch_identities[role],&input_owner.launch_mounts[role],e);
}
static int launch_root_recheck(unsigned int role,struct rnr_stage0_preparer_error *e)
{
    struct stat s;uint64_t m;int temporary=-1;
    if(launch_root_object(input_owner.launch_fds[role],role,&s,&m,e)!=0)return -1;
    if(!same_input(&s,&input_owner.launch_identities[role],role==3&&!input_owner.launch_root_mounted)||m!=input_owner.launch_mounts[role])return mount_reject(e,0);
    if(launch_root_open(role,&temporary,e)==0&&launch_root_object(temporary,role,&s,&m,e)==0&&
       (!same_input(&s,&input_owner.launch_identities[role],role==3&&!input_owner.launch_root_mounted)||m!=input_owner.launch_mounts[role]))mount_reject(e,0);
    close_input(&temporary,e);return e->code==RNR_STAGE0_PREPARER_OK?live_input(e):-1;
}
static int launch_root_scan(int fd,int populated,struct rnr_stage0_preparer_error *e)
{
    unsigned int seen=0,records=0;int eof=0;
    for(int reads=0;reads<5;++reads){
        unsigned char b[4096];if(live_input(e)!=0)return -1;
        long n=syscall(SYS_getdents64,fd,b,sizeof(b));int failure=n<0?errno:0;
        if(n<0)return mount_reject(e,failure);
        if(live_input(e)!=0)return -1;
        if(!n){eof=1;break;}if(n>4096)return mount_reject(e,0);
        for(size_t off=0;off<(size_t)n;){
            uint16_t size;uint64_t ino;int64_t next;
            if(++records>4||(size_t)n-off<24)return mount_reject(e,0);
            memcpy(&ino,b+off,8);memcpy(&next,b+off+8,8);memcpy(&size,b+off+16,2);
            if(!ino||next<=0||size<24||size%8||size>(size_t)n-off)return mount_reject(e,0);
            const unsigned char *name=b+off+19,*end=memchr(name,0,size-19);unsigned int bit=0;
            if(!end)return mount_reject(e,0);
            if(end-name==1&&name[0]=='.'&&b[off+18]==DT_DIR)bit=1;
            else if(end-name==2&&!memcmp(name,"..",2)&&b[off+18]==DT_DIR)bit=2;
            else if(populated&&end-name==10&&!memcmp(name,"launch.bin",10)&&b[off+18]==DT_REG&&ino==input_owner.launch_identities[4].st_ino)bit=4;
            if(!bit||(seen&bit))return mount_reject(e,0);
            seen|=bit;off+=size;
        }
    }
    return eof&&seen==(populated?7U:3U)&&records==(populated?3U:2U)?0:mount_reject(e,0);
}
static int launch_root_inventory(int populated,struct rnr_stage0_preparer_error *e)
{
    struct stat s;uint64_t m;int scanner=-1;
    if(launch_root_recheck(3,e)!=0)return -1;
    if(launch_root_open(3,&scanner,e)!=0)goto done;
    if(launch_root_object(scanner,3,&s,&m,e)!=0)goto done;
    if(!same_input(&s,&input_owner.launch_identities[3],!input_owner.launch_root_mounted)||m!=input_owner.launch_mounts[3]){mount_reject(e,0);goto done;}
    (void)launch_root_scan(scanner,populated,e);
done:
    /* Enumeration is closed before another named/task/namespace temporary. */
    close_input(&scanner,e);return e->code==RNR_STAGE0_PREPARER_OK?launch_root_recheck(3,e):-1;
}
static int launch_mount_intent(unsigned int op,const unsigned char p[192],struct rnr_stage0_preparer_error *e)
{
    if(!((op==11&&input_owner.journal_sequence==52)||(op==6&&input_owner.journal_sequence==54)))return mount_reject(e,0);
    input_owner.operation=op;input_owner.operation_role=8;
    input_owner.operation_entered=input_owner.operation_returned=input_owner.operation_errno=0;
    input_owner.operation_result=0;memcpy(input_owner.operation_payload,p,192);return append_operation(0,p,e);
}
int rnr_stage0_prepare_launch_mount(struct rnr_stage0_preparer_error *e)
{
    if(!e){fence_inputs();errno=EINVAL;return -1;}
    *e=(struct rnr_stage0_preparer_error){.unadopted_fd=-1};pid_t pid=getpid();
    if(pid<=0||syscall(SYS_gettid)!=(long)pid||geteuid()||getegid()||atomic_load(&input_owner_pid)!=pid){
        mount_reject(e,0);fence_inputs();return -1;}
    int expected=PREPARER_LAUNCH_DM_HELD;
    if(!atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_LAUNCH_MOUNT_ACQUIRING,
        memory_order_acq_rel,memory_order_acquire)){mount_reject(e,0);fence_inputs();return -1;}
    if(launch_mapping_originals(e)!=0||check_operation_journal(13568,e)!=0)goto failed;
    int n=snprintf(input_owner.launch_mount_path,64,"/run/%s/launch",input_owner.work_name);
    if(n<=0||n>=64){mount_reject(e,0);goto failed;}
    n=snprintf(input_owner.launch_dm_path,32,"/dev/%s",input_owner.launch_mapping.dm_node);
    if(n<=0||n>=32){mount_reject(e,0);goto failed;}
    unsigned char payload[192]={0};journal_u64(payload,input_owner.journal_identities[1].st_dev);
    journal_u64(payload+8,input_owner.journal_identities[1].st_ino);journal_u64(payload+16,input_owner.journal_mounts[1]);
    memcpy(payload+24,"launch",7);journal_u32(payload+96,0700);
    if(launch_mount_intent(11,payload,e)!=0||live_input(e)!=0)goto failed;
    input_owner.operation_entered=1;
    int result=mkdirat(input_owner.journal_fds[1],"launch",0700),failure=result<0?errno:0;
    input_owner.operation_result=result;input_owner.operation_errno=failure;input_owner.operation_returned=1;
    if(result!=0){mount_reject(e,failure);goto failed;}
    if(live_input(e)!=0||launch_root_keep(3,e)!=0||launch_root_scan(input_owner.launch_fds[3],0,e)!=0||live_input(e)!=0)goto failed;
    input_owner.launch_mount_sync.entered=1;
    result=fsync(input_owner.journal_fds[1]);failure=result<0?errno:0;
    input_owner.launch_mount_sync.result=result;input_owner.launch_mount_sync.system_errno=failure;
    if(result!=0){mount_reject(e,failure);goto failed;}
    if(live_input(e)!=0)goto failed;
    journal_u64(payload+72,input_owner.launch_identities[3].st_dev);journal_u64(payload+80,input_owner.launch_identities[3].st_ino);
    journal_u64(payload+88,input_owner.launch_mounts[3]);
    if(append_operation(1,payload,e)!=0||launch_root_inventory(0,e)!=0||launch_mapping_originals(e)!=0||launch_root_recheck(3,e)!=0)goto failed;
    memset(payload,0,192);journal_u64(payload,input_owner.launch_identities[2].st_dev);
    journal_u64(payload+8,input_owner.launch_identities[2].st_ino);journal_u64(payload+16,input_owner.launch_mounts[2]);
    journal_u64(payload+24,input_owner.launch_identities[2].st_rdev);journal_u64(payload+32,input_owner.launch_identities[3].st_dev);
    journal_u64(payload+40,input_owner.launch_identities[3].st_ino);journal_u64(payload+48,input_owner.launch_mounts[3]);
    journal_u64(payload+64,7);memcpy(payload+72,"squashfs",9);journal_u64(payload+88,input_owner.launch_mapping.dm_device);
    if(launch_mount_intent(6,payload,e)!=0||live_input(e)!=0)goto failed;
    input_owner.operation_entered=1;
    result=mount(input_owner.launch_dm_path,input_owner.launch_mount_path,"squashfs",7,NULL);failure=result<0?errno:0;
    input_owner.operation_result=result;input_owner.operation_errno=failure;input_owner.operation_returned=1;
    if(result!=0){mount_reject(e,failure);goto failed;}
    if(live_input(e)!=0)goto failed;
    uint64_t previous=input_owner.launch_mounts[3];close_input(&input_owner.launch_fds[3],e);
    if(e->code!=RNR_STAGE0_PREPARER_OK)goto failed;
    input_owner.launch_root_mounted=1;
    if(launch_root_keep(3,e)!=0||input_owner.launch_mounts[3]==previous){mount_reject(e,0);goto failed;}
    input_owner.launch_mapping.dm_openers=2;
    journal_u64(payload+56,input_owner.launch_mounts[3]);
    if(append_operation(1,payload,e)!=0||launch_mapping_originals(e)!=0||launch_root_keep(4,e)!=0||
       launch_root_recheck(3,e)!=0||launch_root_recheck(4,e)!=0||
       media_bytes(input_owner.launch_fds[4],input_owner.launch_bytes,input_owner.launch_length,0,e)!=0||
       launch_root_inventory(1,e)!=0||launch_mapping_originals(e)!=0||launch_root_recheck(3,e)!=0||launch_root_recheck(4,e)!=0||
       media_bytes(input_owner.launch_fds[4],input_owner.launch_bytes,input_owner.launch_length,0,e)!=0||
       check_operation_journal(14592,e)!=0||live_input(e)!=0)goto failed;
    e->claim_disposition=input_owner.claim_disposition;e->mkdir_errno=input_owner.mkdir_errno;
    expected=PREPARER_LAUNCH_MOUNT_ACQUIRING;
    if(!atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_LAUNCH_ROOT_HELD,
       memory_order_release,memory_order_relaxed)){mount_reject(e,0);goto failed;}
    return 0;
failed:
    e->claim_disposition=input_owner.claim_disposition;e->mkdir_errno=input_owner.mkdir_errno;
    fence_inputs();drain_inputs(e);input_owner.original_error=*e;expected=PREPARER_FENCED_LAUNCH_MOUNT_ACQUIRING;
    (void)atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_FAILED_DRAINED,
        memory_order_release,memory_order_relaxed);return -1;
}

/* Closed fourteen-row host view. Existing slots are borrowed directly; only
 * source_fd entries actually opened by this phase enter its drain. */
static const struct {unsigned int role;const char *path;int directory,borrow;unsigned long flags;} fixed_profiles[14]={
    {9,"proc",1,0,15},{11,"sys/fs/cgroup",1,-1,14},
    {12,"sys/dev",1,-1,15},{13,"sys/devices",1,-1,15},
    {14,"dev/null",0,1,11},{15,"dev/mapper/control",0,2,11},
    {16,NULL,0,3,11},{17,NULL,0,4,11},{18,NULL,1,-1,7},
    {19,"etc/systemd",1,-1,7},{20,"usr/lib/systemd/system",1,-1,7},
    {21,"usr/local/lib",1,-1,7},{22,"rnr/launch.bin",0,5,7},{26,NULL,0,-1,11}
};
static int fixed_source_fd(unsigned int i)
{
    switch(fixed_profiles[i].borrow){
    case 0:return input_owner.view_fds[0];case 1:return input_owner.media_fds[5];
    case 2:return input_owner.runtime_fds[11];case 3:return input_owner.runtime_fds[12];
    case 4:return input_owner.launch_fds[2];case 5:return input_owner.launch_fds[4];
    default:return input_owner.binds[i].source_fd;
    }
}
static int fixed_observe(int fd,struct fixed_object *o,struct rnr_stage0_preparer_error *e)
{
    return preparation_access(fd,O_RDONLY,e)!=0||stat_input(fd,&o->s,e)!=0||
        mount_input(fd,&o->mount,e)!=0||filesystem_input(fd,&o->fs,e)!=0||mount_vfs(fd,&o->flags,e)!=0?-1:0;
}
static int fixed_equal(const struct fixed_object *a,const struct fixed_object *b,int mounts,int flags)
{
    return same_input(&a->s,&b->s,S_ISDIR(b->s.st_mode)&&b->fs!=0x73717368)&&a->fs==b->fs&&
        (!mounts||a->mount==b->mount)&&(!flags||a->flags==b->flags);
}
static int fixed_directory(const struct fixed_object *o,int immutable,struct rnr_stage0_preparer_error *e)
{
    if(!S_ISDIR(o->s.st_mode)||o->s.st_uid||o->s.st_gid||(o->s.st_mode&022)||!o->s.st_dev||!o->s.st_ino)
        return mount_reject(e,0);
    if(immutable&&(o->fs!=0x73717368||o->s.st_dev!=input_owner.runtime_identities[13].st_dev||
        o->mount!=input_owner.runtime_mounts[13]||(o->flags&15)!=7))return mount_reject(e,0);
    return 0;
}
/* Two walk slots at most, both registered before post-open checks. No graph
 * call while either exists. A failed close invalidates and never retries. */
static int fixed_walk(int root,struct fixed_path *path,int directory,int capture,
                      int target,int *result,struct rnr_stage0_preparer_error *e)
{
    int parent=-1,child=-1;size_t offset=0;unsigned int index=0;
    while(path->name[offset]){
        const char *slash=strchr(path->name+offset,'/');size_t n=slash?(size_t)(slash-path->name-offset):strlen(path->name+offset);
        char name[80];int last=!slash;
        if(!n||n>=sizeof(name)||index>=8){mount_reject(e,0);goto done;}
        memcpy(name,path->name+offset,n);name[n]=0;
        if(live_input(e)!=0)goto done;
        int fd=openat(parent<0?root:parent,name,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC|(!last||directory?O_DIRECTORY:0));
        if(fd<0){mount_reject(e,errno);goto done;}
        if(fd<3){e->unadopted_fd=fd;mount_reject(e,0);goto done;}
        child=fd;
        if(live_input(e)!=0)goto done;
        struct fixed_object observed;
        if(fixed_observe(child,&observed,e)!=0)goto done;
        if(!last){
            if(fixed_directory(&observed,target,e)!=0)goto done;
            if(capture)path->steps[index]=observed;
            else if(index>=path->count||!fixed_equal(&observed,&path->steps[index],1,1)){mount_reject(e,0);goto done;}
        }else if(capture)path->steps[index]=observed;
        ++index;
        close_input(&parent,e);if(e->code!=RNR_STAGE0_PREPARER_OK)goto done;
        if(last){
            if(capture)path->count=index;
            else if(index!=path->count){mount_reject(e,0);goto done;}
            *result=child;child=-1;return 0;
        }
        parent=child;child=-1;offset+=(n+1);
    }
    mount_reject(e,0);
done:
    close_input(&child,e);close_input(&parent,e);return -1;
}
static int fixed_source_profile(unsigned int i,const struct fixed_object *o,struct rnr_stage0_preparer_error *e)
{
    if(!o->s.st_dev||!o->s.st_ino||o->s.st_uid)return mount_reject(e,0);
    if(fixed_profiles[i].directory&&fixed_directory(o,0,e)!=0)return -1;
    if(i==0&&(o->fs!=0x9fa0||o->s.st_dev!=input_owner.view_identities[0].st_dev||o->mount!=input_owner.proc_mount))return mount_reject(e,0);
    if(i==1&&(o->fs!=0x63677270||(o->flags&1)))return mount_reject(e,0);
    if((i==2||i==3)&&o->fs!=0x62656572)return mount_reject(e,0);
    if(i==3&&(o->s.st_dev!=input_owner.binds[2].source.s.st_dev||o->mount!=input_owner.binds[2].source.mount))return mount_reject(e,0);
    if(i==8){
        const struct fixed_path *p=&input_owner.binds[i].source_path;
        if(o->fs!=0x73717368||!(o->flags&1)||p->count<2||o->mount==p->steps[p->count-2].mount||
           !major(o->s.st_dev)||minor(o->s.st_dev)>255||
           o->s.st_dev==input_owner.runtime_identities[12].st_rdev||o->s.st_dev==input_owner.launch_identities[2].st_rdev)return mount_reject(e,0);
    }
    if(i==12&&(!S_ISREG(o->s.st_mode)||(o->s.st_mode&07777)!=0444||o->s.st_gid||o->s.st_nlink!=1||
        o->s.st_size!=(off_t)input_owner.launch_length||o->fs!=0x73717368))return mount_reject(e,0);
    if(i==4||i==5||i==6||i==7||i==13){
        dev_t device=i==4?makedev(1,3):i==5?makedev(10,236):i==6?input_owner.runtime_identities[12].st_rdev:
            i==7?input_owner.launch_identities[2].st_rdev:input_owner.binds[8].source.s.st_dev;
        if((i<=5?!S_ISCHR(o->s.st_mode):!S_ISBLK(o->s.st_mode))||o->s.st_rdev!=device||
            o->fs!=0x1021994||o->s.st_dev!=input_owner.runtime_identities[6].st_dev||o->mount!=input_owner.runtime_mounts[6])return mount_reject(e,0);
        if(i==4?((o->s.st_mode&07777)!=0666||o->s.st_gid):i==5?((o->s.st_mode&022)||o->s.st_gid):0)return mount_reject(e,0);
    }
    return 0;
}
static int fixed_placeholder(unsigned int i,const struct fixed_object *o,struct rnr_stage0_preparer_error *e)
{
    if(o->fs!=0x73717368||o->s.st_dev!=input_owner.runtime_identities[13].st_dev||
       o->mount!=input_owner.runtime_mounts[13]||(o->flags&15)!=7)return mount_reject(e,0);
    if(fixed_profiles[i].directory)return fixed_directory(o,1,e);
    if(!S_ISREG(o->s.st_mode)||o->s.st_uid||o->s.st_gid||o->s.st_nlink!=1||o->s.st_size||
        (o->s.st_mode&07777)!=(i==12?0444:0))return mount_reject(e,0);
    return 0;
}
static int fixed_named(unsigned int i,int target,int capture,struct rnr_stage0_preparer_error *e)
{
    struct fixed_binding *b=&input_owner.binds[i];struct fixed_object o;int fd=-1;
    if(fixed_walk(target?input_owner.runtime_fds[13]:input_owner.fds[0],target?&b->target_path:&b->source_path,
        fixed_profiles[i].directory,capture,target,&fd,e)!=0)goto done;
    if(fixed_observe(fd,&o,e)!=0)goto done;
    if(target){
        if(!b->bound){if(fixed_placeholder(i,&o,e)!=0)goto done;}
        else if(!fixed_equal(&o,&b->source,0,0)||o.mount!=b->target.mount||
                 (b->bound==2?(o.flags&15)!=fixed_profiles[i].flags:o.flags!=b->source.flags)){mount_reject(e,0);goto done;}
    }else if(fixed_source_profile(i,&o,e)!=0)goto done;
    if(capture){
        if(target){b->target=o;b->target_fd=fd;fd=-1;}
        else{b->source=o;if(fixed_profiles[i].borrow<0){b->source_fd=fd;fd=-1;}}
    }else if(!fixed_equal(&o,target?&b->target:&b->source,1,1))mount_reject(e,0);
done:
    close_input(&fd,e);return e->code==RNR_STAGE0_PREPARER_OK?0:-1;
}
/* Optional leaves have distinct host and new-bind mount expectations. */
static int fixed_optional_one(int parent,const char *name,unsigned int index,int capture,int target,
                              const struct fixed_object *base,int *opened,struct rnr_stage0_preparer_error *e)
{
    struct stat s={0};if(live_input(e)!=0)return -1;
    int result=fstatat(parent,name,&s,AT_SYMLINK_NOFOLLOW),failure=result<0?errno:0;
    if(live_input(e)!=0)return -1;
    if(result<0){
        if(failure!=ENOENT)return mount_reject(e,failure);
        if(capture)input_owner.optional_present[index]=0;
        else if(input_owner.optional_present[index])return mount_reject(e,0);
        return 0;
    }
    if(result!=0||!S_ISDIR(s.st_mode)||s.st_uid||s.st_gid||(s.st_mode&022))return mount_reject(e,0);
    if(!capture&&!input_owner.optional_present[index])return mount_reject(e,0);
    if(live_input(e)!=0)return -1;
    int fd=openat(parent,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(fd<0)return mount_reject(e,errno);
    if(fd<3){e->unadopted_fd=fd;return mount_reject(e,0);}
    *opened=fd;if(live_input(e)!=0)return -1;
    struct fixed_object o;
    if(fixed_observe(fd,&o,e)!=0||fixed_directory(&o,0,e)!=0)return -1;
    if(!same_input(&s,&o.s,1)||o.mount!=base->mount||o.s.st_dev!=base->s.st_dev||o.fs!=base->fs||o.flags!=base->flags)return mount_reject(e,0);
    if(capture){input_owner.optional_present[index]=1;input_owner.optional[index]=o;}
    else if(!fixed_equal(&o,&input_owner.optional[index],!target,!target))return mount_reject(e,0);
    return 0;
}
static int fixed_optionals(int capture,int target,struct rnr_stage0_preparer_error *e)
{
    static const char *const names[]={"system.control","system","system.attached"};
    int fd=-1,child=-1;
    struct fixed_binding *etc=&input_owner.binds[9],*local=&input_owner.binds[11];
    if(!target||etc->bound){
        for(unsigned int j=0;j<3;++j){
            if(fixed_optional_one(target?etc->target_fd:fixed_source_fd(9),names[j],j,capture,target,target?&etc->target:&etc->source,&fd,e)!=0)goto done;
            close_input(&fd,e);if(e->code!=RNR_STAGE0_PREPARER_OK)goto done;
        }
    }
    if(!target||local->bound){
        if(fixed_optional_one(target?local->target_fd:fixed_source_fd(11),"systemd",3,capture,target,target?&local->target:&local->source,&fd,e)!=0)goto done;
        if(fd>=0){
            if(fixed_optional_one(fd,"system",4,capture,target,target?&local->target:&local->source,&child,e)!=0)goto done;
        }else if(capture)input_owner.optional_present[4]=0;
        else if(input_owner.optional_present[4])mount_reject(e,0);
    }
done:
    close_input(&child,e);close_input(&fd,e);return e->code==RNR_STAGE0_PREPARER_OK?0:-1;
}
static int fixed_original_graph(struct rnr_stage0_preparer_error *e)
{
    return launch_mapping_originals(e)!=0||launch_root_recheck(3,e)!=0||launch_root_recheck(4,e)!=0||
        media_bytes(input_owner.launch_fds[4],input_owner.launch_bytes,input_owner.launch_length,0,e)!=0||
        launch_root_inventory(1,e)!=0?-1:0;
}
static int fixed_graph(struct rnr_stage0_preparer_error *e)
{
    if(fixed_original_graph(e)!=0)return -1;
    for(unsigned int i=0;i<14;++i){
        struct fixed_binding *b=&input_owner.binds[i];struct fixed_object o;
        if(fixed_observe(fixed_source_fd(i),&o,e)!=0||!fixed_equal(&o,&b->source,1,1)||fixed_named(i,0,0,e)!=0)return mount_reject(e,0);
        if(fixed_observe(b->target_fd,&o,e)!=0||!fixed_equal(&o,&b->target,1,1)||fixed_named(i,1,0,e)!=0)return mount_reject(e,0);
    }
    return fixed_optionals(0,0,e)!=0||fixed_optionals(0,1,e)!=0?-1:live_input(e);
}
static int fixed_effect(unsigned int i,int remount,struct rnr_stage0_preparer_error *e)
{
    struct fixed_binding *b=&input_owner.binds[i];unsigned int sequence=56+4*i+(remount?2:0);
    if(input_owner.journal_sequence!=sequence||fixed_graph(e)!=0)return mount_reject(e,0);
    unsigned char p[192]={0};journal_u64(p,b->source.s.st_dev);journal_u64(p+8,b->source.s.st_ino);
    journal_u64(p+16,b->source.mount);journal_u64(p+24,b->source.s.st_rdev);
    journal_u64(p+32,b->target.s.st_dev);journal_u64(p+40,b->target.s.st_ino);journal_u64(p+48,b->target.mount);
    unsigned long flags=MS_BIND|(remount?MS_REMOUNT|fixed_profiles[i].flags:0);journal_u64(p+64,flags);
    if(i==6||i==7||i==13)journal_u64(p+88,((uint64_t)(minor(b->source.s.st_rdev)&255)|((uint64_t)major(b->source.s.st_rdev)<<8)|((uint64_t)(minor(b->source.s.st_rdev)&~255U)<<12)));
    input_owner.operation=remount?8:7;input_owner.operation_role=fixed_profiles[i].role;
    input_owner.operation_entered=input_owner.operation_returned=input_owner.operation_errno=0;input_owner.operation_result=0;
    memcpy(input_owner.operation_payload,p,192);
    if(append_operation(0,p,e)!=0||live_input(e)!=0)return -1;
    char source[168],target[256];int n=snprintf(source,sizeof(source),"/%s",b->source_path.name);
    if(n<=0||(size_t)n>=sizeof(source))return mount_reject(e,0);
    n=snprintf(target,sizeof(target),"%s/%s",input_owner.root_path,b->target_path.name);
    if(n<=0||(size_t)n>=sizeof(target))return mount_reject(e,0);
    input_owner.operation_entered=1;
    int result=mount(source,target,NULL,flags,NULL),failure=result<0?errno:0;
    input_owner.operation_result=result;input_owner.operation_errno=failure;input_owner.operation_returned=1;
    if(result!=0)return mount_reject(e,failure);
    if(live_input(e)!=0)return -1;
    uint64_t previous=b->target.mount;close_input(&b->target_fd,e);if(e->code!=RNR_STAGE0_PREPARER_OK)return -1;
    int fd=-1;struct fixed_object observed;
    if(fixed_walk(input_owner.runtime_fds[13],&b->target_path,fixed_profiles[i].directory,0,1,&fd,e)!=0)goto failed;
    /* Move the new leaf into its owned slot BEFORE observing or clock checks. */
    b->target_fd=fd;fd=-1;
    if(fixed_observe(b->target_fd,&observed,e)!=0)return -1;
    if(!fixed_equal(&observed,&b->source,0,0)||(remount?observed.mount!=previous:
        observed.mount==previous||observed.mount==b->source.mount||observed.mount==input_owner.runtime_mounts[13])||
        (remount?(observed.flags&15)!=fixed_profiles[i].flags:observed.flags!=b->source.flags))return mount_reject(e,0);
    if(!remount)for(unsigned int j=0;j<i;++j)if(observed.mount==input_owner.binds[j].target.mount)return mount_reject(e,0);
    b->target=observed;b->bound=remount?2:1;
    if(i==6)input_owner.runtime_mapping.dm_openers=3;
    if(i==7)input_owner.launch_mapping.dm_openers=3;
    journal_u64(p+56,observed.mount);
    if(append_operation(1,p,e)!=0)return -1;
    return fixed_graph(e);
failed:
    close_input(&fd,e);return -1;
}
int rnr_stage0_prepare_fixed_binds(struct rnr_stage0_preparer_error *e)
{
    if(!e){fence_inputs();errno=EINVAL;return -1;}
    *e=(struct rnr_stage0_preparer_error){.unadopted_fd=-1};pid_t pid=getpid();
    if(pid<=0||syscall(SYS_gettid)!=(long)pid||geteuid()||getegid()||atomic_load(&input_owner_pid)!=pid){
        reject_input(e,RNR_STAGE0_PREPARER_OWNER,0);fence_inputs();return -1;}
    int expected=PREPARER_LAUNCH_ROOT_HELD;
    if(!atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_BINDS_ACQUIRING,
        memory_order_acq_rel,memory_order_acquire)){mount_reject(e,0);fence_inputs();return -1;}
    for(unsigned int i=0;i<14;++i)input_owner.binds[i].source_fd=input_owner.binds[i].target_fd=-1;
    input_owner.binds_initialized=1;
    if(fixed_original_graph(e)!=0||input_owner.journal_sequence!=56||
        minor(input_owner.runtime_identities[12].st_rdev)>255||minor(input_owner.launch_identities[2].st_rdev)>255){mount_reject(e,0);goto failed;}
    for(unsigned int i=0;i<14;++i){
        struct fixed_binding *b=&input_owner.binds[i];int n;
        if(fixed_profiles[i].path)n=snprintf(b->target_path.name,160,"%s",fixed_profiles[i].path);
        else if(i==6||i==7)n=snprintf(b->target_path.name,160,"dev/%s",i==6?input_owner.runtime_mapping.dm_node:input_owner.launch_mapping.dm_node);
        else if(i==8){
            char hex[65];for(int j=0;j<32;++j)snprintf(hex+2*j,3,"%02x",input_owner.installation.asset_root[j]);
            n=snprintf(b->target_path.name,160,"var/lib/rnr/assets/%s",hex);
        }else n=snprintf(b->target_path.name,160,"dev/dm-%u",minor(input_owner.binds[8].source.s.st_dev));
        if(n<=0||n>=160){mount_reject(e,0);goto failed;}
        if(i==12)n=snprintf(b->source_path.name,160,"run/%s/launch/launch.bin",input_owner.work_name);
        else n=snprintf(b->source_path.name,160,"%s",b->target_path.name);
        if(n<=0||n>=160||fixed_named(i,0,1,e)!=0||fixed_named(i,1,1,e)!=0)goto failed;
        struct fixed_object source;
        if(fixed_observe(fixed_source_fd(i),&source,e)!=0||!fixed_equal(&source,&b->source,1,1)){mount_reject(e,0);goto failed;}
    }
    if(fixed_optionals(1,0,e)!=0||fixed_graph(e)!=0)goto failed;
    for(unsigned int i=0;i<14;++i)if(fixed_effect(i,0,e)!=0||fixed_effect(i,1,e)!=0)goto failed;
    if(fixed_graph(e)!=0||check_operation_journal(28928,e)!=0||live_input(e)!=0)goto failed;
    e->claim_disposition=input_owner.claim_disposition;e->mkdir_errno=input_owner.mkdir_errno;
    expected=PREPARER_BINDS_ACQUIRING;
    if(!atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_BINDS_HELD,
        memory_order_release,memory_order_relaxed)){mount_reject(e,0);goto failed;}
    return 0;
failed:
    e->claim_disposition=input_owner.claim_disposition;e->mkdir_errno=input_owner.mkdir_errno;
    fence_inputs();drain_inputs(e);input_owner.original_error=*e;expected=PREPARER_FENCED_BINDS_ACQUIRING;
    (void)atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_FAILED_DRAINED,
        memory_order_release,memory_order_relaxed);return -1;
}

/* Final process-root/FD transition, still a disabled operational destination. */
static int final_reject(struct rnr_stage0_preparer_error *e,int failure)
{reject_input(e,RNR_STAGE0_PREPARER_FINAL,failure);return -1;}
static int final_register(int fd,int expected,int *slot,struct rnr_stage0_preparer_error *e)
{
    if(fd<0)return final_reject(e,errno);
    if(fd<3){e->unadopted_fd=fd;return final_reject(e,0);}
    *slot=fd; /* Actual ownership precedes every post-open check. */
    if(live_input(e)!=0)return -1;
    return expected>=0&&fd!=expected?final_reject(e,0):0;
}
static int final_openat2(int parent,const char *path,int directory,int beneath,
                         int expected,int *slot,struct rnr_stage0_preparer_error *e)
{
    struct open_how how={.flags=O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC|(directory?O_DIRECTORY:0),
        .resolve=RESOLVE_NO_SYMLINKS|(beneath?RESOLVE_BENEATH|RESOLVE_NO_XDEV:0)};
    if(live_input(e)!=0)return -1;
    int fd=(int)syscall(SYS_openat2,parent,path,&how,sizeof(how));
    return final_register(fd,expected,slot,e);
}
static int final_openat(int parent,const char *name,int directory,int magic,
                        int expected,int *slot,struct rnr_stage0_preparer_error *e)
{
    int flags=O_RDONLY|O_NONBLOCK|O_CLOEXEC|(directory?O_DIRECTORY:0)|(magic?0:O_NOFOLLOW);
    if(live_input(e)!=0)return -1;
    int fd=parent==AT_FDCWD?open(name,flags):openat(parent,name,flags);
    return final_register(fd,expected,slot,e);
}
static int final_executable(const struct fixed_object *o,int packaged,struct rnr_stage0_preparer_error *e)
{
    if(!S_ISREG(o->s.st_mode)||o->s.st_uid||o->s.st_gid||(o->s.st_mode&022)||
       !(o->s.st_mode&0111)||o->s.st_size<=0||o->s.st_size>32*1024*1024)return final_reject(e,0);
    if(packaged&&(o->fs!=0x73717368||o->s.st_dev!=input_owner.runtime_identities[13].st_dev||
       o->mount!=input_owner.runtime_mounts[13]||(o->flags&15)!=7))return final_reject(e,0);
    return 0;
}
static int final_capture(struct rnr_stage0_preparer_error *e)
{
    struct fixed_object *v=input_owner.final_expected;int fd=-1;
    if(fixed_observe(input_owner.runtime_fds[14],v,e)!=0||
       fixed_observe(input_owner.binds[1].target_fd,v+5,e)!=0||
       fixed_observe(input_owner.runtime_fds[13],v+6,e)!=0||
       stat_input(input_owner.view_fds[3],&v[2].s,e)!=0)return -1;
    if(final_openat2(input_owner.runtime_fds[13],"usr/bin/busctl",0,1,-1,&fd,e)!=0)goto done;
    if(fixed_observe(fd,v+1,e)!=0||final_executable(v+1,1,e)!=0)goto done;
    close_input(&fd,e);if(e->code!=RNR_STAGE0_PREPARER_OK)goto done;
    if(final_openat(input_owner.runtime_fds[14],"dbus",1,0,-1,&fd,e)!=0)goto done;
    if(fixed_observe(fd,v+4,e)!=0||fixed_directory(v+4,0,e)!=0)goto done;
    if(v[4].fs!=v[0].fs||v[4].s.st_dev!=v[0].s.st_dev||v[4].mount!=v[0].mount||
       v[4].flags!=v[0].flags){final_reject(e,0);goto done;}
    close_input(&fd,e);if(e->code!=RNR_STAGE0_PREPARER_OK)goto done;
    if(final_openat(input_owner.view_fds[2],"exe",0,1,-1,&fd,e)!=0)goto done;
    if(fixed_observe(fd,v+3,e)!=0||final_executable(v+3,0,e)!=0)goto done;
done:
    close_input(&fd,e);return e->code==RNR_STAGE0_PREPARER_OK?live_input(e):-1;
}
static int final_current_root(struct rnr_stage0_preparer_error *e)
{
    int fd=-1;struct fixed_object now;
    if(final_openat(AT_FDCWD,"/",1,0,-1,&fd,e)==0&&fixed_observe(fd,&now,e)==0&&
       !fixed_equal(&now,input_owner.final_expected+6,1,1))final_reject(e,0);
    close_input(&fd,e);return e->code==RNR_STAGE0_PREPARER_OK?live_input(e):-1;
}
static int final_root_step(int step,struct rnr_stage0_preparer_error *e)
{
    if(live_input(e)!=0)return -1;
    input_owner.root_steps[step].entered=1;
    int result=step==0?fchdir(input_owner.runtime_fds[13]):step==1?chroot("."):chdir("/");
    int failure=result<0?errno:0;
    input_owner.root_steps[step].result=result;input_owner.root_steps[step].system_errno=failure;
    input_owner.root_steps[step].returned=1;
    if(live_input(e)!=0)return -1;
    if(result!=0){reject_input(e,RNR_STAGE0_PREPARER_ROOT,failure);return -1;}
    return 0;
}
static int final_profile(int role,struct rnr_stage0_preparer_error *e)
{
    int fd=input_owner.final_fds[role];struct fixed_object now;
    if(role==2){
        struct stat s;if(stat_input(fd,&s,e)!=0)return -1;
        if(!S_ISREG(s.st_mode)||!same_view(&s,&input_owner.final_expected[2].s))return final_reject(e,0);
        if(live_input(e)!=0)return -1;
        int flags=fcntl(fd,F_GETFD);if(flags<0)return final_reject(e,errno);
        if(live_input(e)!=0)return -1;
        if(flags!=FD_CLOEXEC)return final_reject(e,0);
        struct pollfd p={.fd=fd,.events=POLLIN};
        if(live_input(e)!=0)return -1;
        int result=poll(&p,1,0);int failure=result<0?errno:0;
        if(live_input(e)!=0)return -1;
        return result!=0||p.revents?final_reject(e,failure):0;
    }
    if(fixed_observe(fd,&now,e)!=0)return -1;
    if(!fixed_equal(&now,input_owner.final_expected+role,1,1))return final_reject(e,0);
    return 0;
}
static int final_owned_call(struct rnr_stage0_preparer_error *e,int source,int active)
{
    if(!e){fence_inputs();errno=EINVAL;return -1;}
    *e=(struct rnr_stage0_preparer_error){.unadopted_fd=-1};pid_t pid=getpid();
    if(pid<=0||syscall(SYS_gettid)!=(long)pid||geteuid()||getegid()||atomic_load(&input_owner_pid)!=pid){
        reject_input(e,RNR_STAGE0_PREPARER_OWNER,0);fence_inputs();return -1;}
    int expected=source;
    if(!atomic_compare_exchange_strong_explicit(&preparer_state,&expected,active,
        memory_order_acq_rel,memory_order_acquire)){final_reject(e,0);fence_inputs();return -1;}
    return 0;
}
static int final_failed(struct rnr_stage0_preparer_error *e,int phase)
{
    e->claim_disposition=input_owner.claim_disposition;e->mkdir_errno=input_owner.mkdir_errno;
    fence_inputs();drain_inputs(e);input_owner.original_error=*e;
    (void)atomic_compare_exchange_strong_explicit(&preparer_state,&phase,PREPARER_FAILED_DRAINED,
        memory_order_release,memory_order_relaxed);return -1;
}
int rnr_stage0_prepare_final_roles(struct rnr_stage0_preparer_error *e)
{
    if(final_owned_call(e,PREPARER_BINDS_HELD,PREPARER_FINAL_ACQUIRING)!=0)return -1;
    for(int j=0;j<6;++j)input_owner.final_fds[j]=-1;
    input_owner.final_initialized=1;
    if(fixed_graph(e)!=0||check_operation_journal(28928,e)!=0||final_capture(e)!=0||fixed_graph(e)!=0)goto failed;
    for(int j=0;j<3;++j)if(final_root_step(j,e)!=0)goto failed;
    if(final_current_root(e)!=0||fixed_graph(e)!=0||final_current_root(e)!=0)goto failed;
    /* No final descriptors until every preparation slot has been consumed. */
    drain_inputs(e);if(e->code!=RNR_STAGE0_PREPARER_OK||live_input(e)!=0)goto failed;
    if(final_openat2(AT_FDCWD,"/run",1,0,3,&input_owner.final_fds[0],e)!=0||final_profile(0,e)!=0)goto failed;
    if(final_openat2(AT_FDCWD,"/usr/bin/busctl",0,0,4,&input_owner.final_fds[1],e)!=0||final_profile(1,e)!=0)goto failed;
    if(live_input(e)!=0)goto failed;
    int pidfd=(int)syscall(SYS_pidfd_open,1,0);
    if(final_register(pidfd,5,&input_owner.final_fds[2],e)!=0||final_profile(2,e)!=0)goto failed;
    if(final_openat(AT_FDCWD,"/proc/1/exe",0,1,6,&input_owner.final_fds[3],e)!=0||final_profile(3,e)!=0)goto failed;
    if(final_openat(3,"dbus",1,0,7,&input_owner.final_fds[4],e)!=0||final_profile(4,e)!=0)goto failed;
    if(final_openat2(AT_FDCWD,"/sys/fs/cgroup",1,0,8,&input_owner.final_fds[5],e)!=0||final_profile(5,e)!=0)goto failed;
    if(live_input(e)!=0)goto failed;
    if(rnr_stage0_admit_initial_fds(&e->admission)!=0){reject_input(e,RNR_STAGE0_PREPARER_ADMISSION,e->admission.system_errno);goto failed;}
    if(live_input(e)!=0)goto failed;
    for(int fd=0;fd<9;++fd){
        if(live_input(e)!=0)goto failed;
        int flags=fcntl(fd,F_GETFD);if(flags<0){final_reject(e,errno);goto failed;}
        if(live_input(e)!=0)goto failed;
        if(flags!=0&&flags!=FD_CLOEXEC){final_reject(e,0);goto failed;}
        if(fd>=3&&flags!=FD_CLOEXEC){final_reject(e,0);goto failed;}
        if(flags){
            if(live_input(e)!=0)goto failed;
            if(fcntl(fd,F_SETFD,0)!=0){final_reject(e,errno);goto failed;}
            if(live_input(e)!=0)goto failed;
        }
        if(live_input(e)!=0)goto failed;
        flags=fcntl(fd,F_GETFD);if(flags<0){final_reject(e,errno);goto failed;}
        if(live_input(e)!=0)goto failed;
        if(flags!=0){final_reject(e,0);goto failed;}
    }
    if(live_input(e)!=0)goto failed;
    e->claim_disposition=input_owner.claim_disposition;e->mkdir_errno=input_owner.mkdir_errno;
    int expected=PREPARER_FINAL_ACQUIRING;
    if(!atomic_compare_exchange_strong_explicit(&preparer_state,&expected,PREPARER_FINAL_ROLES_HELD,
        memory_order_release,memory_order_relaxed)){final_reject(e,0);goto failed;}
    return 0;
failed:return final_failed(e,PREPARER_FENCED_FINAL_ACQUIRING);
}
int rnr_stage0_finish_prepared_operational(struct rnr_stage0_preparer_error *e)
{
    if(final_owned_call(e,PREPARER_FINAL_ROLES_HELD,PREPARER_FINAL_FINISHING)!=0)return -1;
    if(live_input(e)!=0)return final_failed(e,PREPARER_FENCED_FINAL_FINISHING);
    (void)rnr_stage0_finish_operational(&e->launch);
    reject_input(e,RNR_STAGE0_PREPARER_FINAL,e->launch.system_errno);
    return final_failed(e,PREPARER_FENCED_FINAL_FINISHING);
}
