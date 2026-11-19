/* Test only the fixed orchestration: ALL preparer/syscall effects replaced. */
#ifdef NDEBUG
#error "Qualification main fixture requires active assertions"
#endif
#include <assert.h>
#include <setjmp.h>
#include <unistd.h>
#include "../../automation/native/runtime_stage0_preparer.h"
static jmp_buf terminal;
static int calls,fail_at,stage_return,exit_code;
static struct rnr_stage0_preparer_error *original;
static int step(int id,struct rnr_stage0_preparer_error *e)
{
    /* A wrong stage/order or a successor after a failed stage is observable. */
    assert(id==calls++ && (fail_at<0||id<=fail_at));
    if(id==0){assert(e->code==RNR_STAGE0_PREPARER_OK);original=e;}
    assert(e==original);
    if(id==fail_at){e->code=RNR_STAGE0_PREPARER_CLOCK;return stage_return;}
    return 0;
}
#define rnr_stage0_prepare_inputs(e) step(0,e)
#define rnr_stage0_prepare_host_view(e) step(1,e)
#define rnr_stage0_claim_preparation(e) step(2,e)
#define rnr_stage0_prepare_runtime_loops(e) step(3,e)
#define rnr_stage0_prepare_runtime_mapping(e) step(4,e)
#define rnr_stage0_prepare_runtime_mount(e) step(5,e)
#define rnr_stage0_prepare_launch_media(e) step(6,e)
#define rnr_stage0_prepare_launch_loops(e) step(7,e)
#define rnr_stage0_prepare_launch_mapping(e) step(8,e)
#define rnr_stage0_prepare_launch_mount(e) step(9,e)
#define rnr_stage0_prepare_fixed_binds(e) step(10,e)
#define rnr_stage0_prepare_final_roles(e) step(11,e)
#define rnr_stage0_finish_prepared_operational(e) step(12,e)
static _Noreturn void stopped(int code){exit_code=code;longjmp(terminal,1);}
#define _exit(c) stopped(c)
#define main qualification_main
#include "../../automation/native/runtime_stage0_qualification_main.c"
#undef main
#undef _exit
static void run_case(int stage,int result)
{
    calls=0;fail_at=stage;stage_return=result;exit_code=0;original=NULL;
    if(!setjmp(terminal)){(void)qualification_main();assert(0);}
    assert(calls==fail_at+1&&exit_code==125);
}
int main(void)
{
    const int returns[]={-1,1,125};
    for(int i=0;i<12;++i)for(unsigned int j=0;j<3;++j)run_case(i,returns[j]);
    const int finish_returns[]={-1,0,1,125};
    for(unsigned int j=0;j<4;++j)run_case(12,finish_returns[j]);
    return 0;
}
