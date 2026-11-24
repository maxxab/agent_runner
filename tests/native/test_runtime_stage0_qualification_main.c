/* Orchestration only: ALL supervision, legacy effects and exits substituted. */
#ifdef NDEBUG
#error "Qualification main fixture requires active assertions"
#endif
#include <assert.h>
#include <setjmp.h>
#include <unistd.h>
#include "../../automation/native/runtime_stage0_preparer.h"
static jmp_buf terminal;
static int calls,stage_return,child_exit,exit_code,exit_calls;
static _Noreturn void stopped(int code)
{++exit_calls;exit_code=code;longjmp(terminal,1);}
static int supervised(struct rnr_stage0_preparer_error *e)
{
    assert(calls++==0&&e&&e->code==RNR_STAGE0_PREPARER_OK);
    if(child_exit)stopped(125);
    return stage_return;
}
#define rnr_stage0_supervised_inputs(e) supervised(e)
#define FORBIDDEN(e) (assert(!"unsupervised preparation is forbidden"), (void)(e), -1)
#define rnr_stage0_prepare_inputs(e) FORBIDDEN(e)
#define rnr_stage0_prepare_host_view(e) FORBIDDEN(e)
#define rnr_stage0_claim_preparation(e) FORBIDDEN(e)
#define rnr_stage0_prepare_runtime_loops(e) FORBIDDEN(e)
#define rnr_stage0_prepare_runtime_mapping(e) FORBIDDEN(e)
#define rnr_stage0_prepare_runtime_mount(e) FORBIDDEN(e)
#define rnr_stage0_prepare_launch_media(e) FORBIDDEN(e)
#define rnr_stage0_prepare_launch_loops(e) FORBIDDEN(e)
#define rnr_stage0_prepare_launch_mapping(e) FORBIDDEN(e)
#define rnr_stage0_prepare_launch_mount(e) FORBIDDEN(e)
#define rnr_stage0_prepare_fixed_binds(e) FORBIDDEN(e)
#define rnr_stage0_prepare_final_roles(e) FORBIDDEN(e)
#define rnr_stage0_finish_prepared_operational(e) FORBIDDEN(e)
#define _exit(c) stopped(c)
#define main qualification_main
#include "../../automation/native/runtime_stage0_qualification_main.c"
#undef main
#undef _exit
static void run_case(int result,int child)
{
    calls=exit_calls=exit_code=0;stage_return=result;child_exit=child;
    if(!setjmp(terminal)){(void)qualification_main();assert(0);}
    assert(calls==1&&exit_calls==1&&exit_code==125);
}
int main(void)
{
    const int returns[]={-1,0,1,125};
    for(unsigned int i=0;i<4;++i)run_case(returns[i],0);
    run_case(0,1);
    return 0;
}
