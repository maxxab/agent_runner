/* Admission-only clock permissions. All clock/identity/FD syscalls substituted;
 * a constructed phase exercises checks, not actual fork/placement authority. */
#define main original_clock_fixture_main
#include "test_runtime_stage0_clock.c"
#undef main

int main(void)
{
    struct rnr_stage0_clock state;
    struct rnr_stage0_clock_error error;
    struct rnr_stage0_clock_admission_result admitted;

    reset(); state = prepared();
    state.phase = RNR_STAGE0_CLOCK_ADMISSION;
    boot += 3000000000LL; wall += 4000000000LL;
    assert(rnr_stage0_clock_check_setup(&state, &error) == 0);
    assert(rnr_stage0_clock_bind_cutoff(&state, 1700000090000000000LL, &error) == 0);
    /* Narrowing is data binding, never permission to admit/launch. */
    assert(state.phase == RNR_STAGE0_CLOCK_ADMISSION);
    assert(state.captured_boottime_ns == 1000000000000LL);
    assert(state.sampled_wall_ns == 1700000000000000000LL);
    assert(state.setup_end_ns == 1015000000000LL);
    assert(state.deadline_boottime_ns == 1090000000000LL);
    assert(state.last_boottime_ns == 1003000000000LL);
    assert(state.last_wall_ns == 1700000004000000000LL);
    assert(rnr_stage0_admit_with_clock(&state, &admitted) == -1);
    assert(admission_calls == 0 && admitted.admission_called == 0);

    reset(); state = prepared();
    state.phase = RNR_STAGE0_CLOCK_ADMISSION;
    assert(rnr_stage0_clock_bind_cutoff(&state, 1700000090000000000LL, &error) == 0);
    assert(rnr_stage0_clock_bind_cutoff(&state, 1700000080000000000LL, &error) == -1);
    assert(state.phase == RNR_STAGE0_CLOCK_FAILED);
    assert(state.wall_deadline_ns == 1700000090000000000LL);

    /* An admission reader stalled at the original setup boundary cannot resume
     * by narrowing its cutoff or trying to capture another origin. */
    reset(); state = prepared(); state.phase = RNR_STAGE0_CLOCK_ADMISSION;
    boot = 1015000000000LL;
    assert(rnr_stage0_clock_bind_cutoff(&state, 1700000090000000000LL, &error) == -1);
    assert(error.code == RNR_STAGE0_CLOCK_CUTOFF);
    assert(rnr_stage0_clock_prepare(&state, &error) == -1);

    /* Rollback, foreign owner and namespace drift still fence admission. */
    for (int fault = 0; fault < 3; ++fault) {
        reset(); state = prepared(); state.phase = RNR_STAGE0_CLOCK_ADMISSION;
        if (fault == 0) --wall;
        if (fault == 1) owner = thread = 101;
        if (fault == 2) { identity_calls = 0; namespace_drift = 1; }
        assert(rnr_stage0_clock_check_setup(&state, &error) == -1);
        assert(state.phase == RNR_STAGE0_CLOCK_FAILED && admission_calls == 0);
    }
    return 0;
}
