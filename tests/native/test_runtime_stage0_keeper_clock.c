/* Negative-clock checks through the real clock module's mocked original fork.
 * All process/identity/clock/IPC syscalls substituted; no keeper/resource runs. */
#define main original_fork_fixture_main
#include "test_runtime_stage0_fork.c"
#undef main

static struct rnr_stage0_clock keeper_clock;
static struct rnr_stage0_fork_result keeper_child;
static struct rnr_stage0_clock_error keeper_error;

static void parent_clock(void)
{
    gate_reset(0); keeper_clock = prepared();
    assert(rnr_stage0_clock_fork(&keeper_clock, &keeper_child, &keeper_error) == 1);
}

int main(void)
{
    struct rnr_stage0_keeper_tick tick;
    parent_clock();
    boot = 1015000000000LL; wall += 15000000000LL;
    assert(rnr_stage0_clock_check_keeper(&keeper_clock, &tick, &keeper_error) == 0);
    assert(tick.setup_expired && !tick.trigger_due);
    assert(tick.trigger_ns == 1060000000000LL && tick.stop_ns == 1090000000000LL);
    assert(keeper_clock.phase == RNR_STAGE0_CLOCK_NEGATIVE);
    /* No declaration cannot renew setup, but must not disarm negative time. */
    assert(rnr_stage0_clock_bind_keeper_cutoff(&keeper_clock, 1700000100000000000LL,
                                              &keeper_error) == -1);
    assert(keeper_error.code == RNR_STAGE0_CLOCK_CUTOFF);
    assert(keeper_clock.phase == RNR_STAGE0_CLOCK_NEGATIVE);
    boot = 1060000000000LL; wall = 1700000060000000000LL;
    assert(rnr_stage0_clock_check_keeper(&keeper_clock, &tick, &keeper_error) == 0);
    assert(tick.trigger_due && tick.setup_expired);
    boot = 1089999999999LL; wall = 1700000089999999999LL;
    assert(rnr_stage0_clock_check_keeper(&keeper_clock, &tick, &keeper_error) == 0);
    boot = 1090000000000LL; wall = 1700000090000000000LL;
    assert(rnr_stage0_clock_check_keeper(&keeper_clock, &tick, &keeper_error) == -1);
    assert(keeper_error.code == RNR_STAGE0_CLOCK_CUTOFF);
    assert(keeper_clock.phase == RNR_STAGE0_CLOCK_FAILED);
    assert(keeper_child.child_pid == 101 && keeper_child.child_pidfd == 62);

    parent_clock();
    boot += 2000000000LL; wall += 3000000000LL;
    assert(rnr_stage0_clock_bind_keeper_cutoff(&keeper_clock, 1700000080000000000LL,
                                              &keeper_error) == 0);
    assert(keeper_clock.captured_boottime_ns == 1000000000000LL);
    assert(keeper_clock.sampled_wall_ns == 1700000000000000000LL);
    assert(keeper_clock.last_boottime_ns == 1002000000000LL);
    assert(keeper_clock.last_wall_ns == 1700000003000000000LL);
    assert(keeper_clock.setup_end_ns == 1015000000000LL);
    assert(rnr_stage0_clock_check_keeper(&keeper_clock, &tick, &keeper_error) == 0);
    assert(tick.stop_ns == 1080000000000LL && tick.trigger_ns == 1060000000000LL);
    /* A protocol/binding error keeps the original negative clock usable. */
    assert(rnr_stage0_clock_bind_keeper_cutoff(&keeper_clock, 1700000070000000000LL,
                                              &keeper_error) == -1);
    assert(keeper_error.code == RNR_STAGE0_CLOCK_STATE);
    assert(keeper_clock.wall_deadline_ns == 1700000080000000000LL);
    assert(rnr_stage0_clock_check_keeper(&keeper_clock, &tick, &keeper_error) == 0);
    /* Wall expiry is independent of slower boottime progress. */
    wall = 1700000080000000000LL;
    assert(rnr_stage0_clock_check_keeper(&keeper_clock, &tick, &keeper_error) == -1);
    assert(keeper_error.code == RNR_STAGE0_CLOCK_CUTOFF);

    parent_clock();
    assert(rnr_stage0_clock_bind_keeper_cutoff(&keeper_clock, 0, &keeper_error) == -1);
    assert(keeper_error.code == RNR_STAGE0_CLOCK_RANGE);
    assert(rnr_stage0_clock_bind_keeper_cutoff(&keeper_clock, 1700000080000000000LL,
                                              &keeper_error) == -1);
    assert(keeper_error.code == RNR_STAGE0_CLOCK_STATE);
    assert(rnr_stage0_clock_check_keeper(&keeper_clock, &tick, &keeper_error) == 0);

    parent_clock();
    assert(rnr_stage0_clock_bind_keeper_cutoff(&keeper_clock, 1700000008000000000LL,
                                              &keeper_error) == -1);
    assert(keeper_error.code == RNR_STAGE0_CLOCK_RANGE);
    /* Rejected admission still retains the earlier live failure-containment
     * lease. It cannot fall back to the original, longer unbound window. */
    assert(rnr_stage0_clock_check_keeper(&keeper_clock, &tick, &keeper_error) == 0);
    assert(tick.stop_ns == 1008000000000LL && tick.trigger_ns == 1008000000000LL);
    assert(keeper_clock.setup_end_ns == 1008000000000LL);
    boot = 1008000000000LL;
    assert(rnr_stage0_clock_check_keeper(&keeper_clock, &tick, &keeper_error) == -1);

    const struct { int64_t wall_cutoff, stop; int accepted; } boundaries[] = {
        {1700000059999999999LL, 1059999999999LL, 0},
        {1700000060000000000LL, 1060000000000LL, 0},
        {1700000060000000001LL, 1060000000001LL, 1}
    };
    for (unsigned int i = 0; i < sizeof(boundaries) / sizeof(boundaries[0]); ++i) {
        parent_clock();
        int result = rnr_stage0_clock_bind_keeper_cutoff(&keeper_clock,
            boundaries[i].wall_cutoff, &keeper_error);
        assert(result == (boundaries[i].accepted ? 0 : -1));
        assert(keeper_clock.wall_deadline_ns == boundaries[i].wall_cutoff);
        assert(rnr_stage0_clock_check_keeper(&keeper_clock, &tick, &keeper_error) == 0);
        assert(tick.stop_ns == boundaries[i].stop);
        if (boundaries[i].accepted) {
            boot = 1060000000000LL; wall = 1700000060000000000LL;
            assert(rnr_stage0_clock_check_keeper(&keeper_clock, &tick, &keeper_error) == 0);
            assert(tick.trigger_due);
        } else {
            assert(rnr_stage0_clock_bind_keeper_cutoff(&keeper_clock,
                1700000090000000000LL, &keeper_error) == -1);
            assert(keeper_clock.wall_deadline_ns == boundaries[i].wall_cutoff);
        }
    }

    /* A declaration arriving after setup still narrows negative time. */
    parent_clock(); boot = 1016000000000LL; wall = 1700000016000000000LL;
    assert(rnr_stage0_clock_bind_keeper_cutoff(&keeper_clock, 1700000080000000000LL,
                                              &keeper_error) == -1);
    assert(keeper_error.code == RNR_STAGE0_CLOCK_CUTOFF);
    assert(keeper_clock.phase == RNR_STAGE0_CLOCK_NEGATIVE);
    assert(keeper_clock.deadline_boottime_ns == 1080000000000LL);
    assert(rnr_stage0_clock_check_keeper(&keeper_clock, &tick, &keeper_error) == 0);
    assert(tick.stop_ns == 1080000000000LL && tick.setup_expired);

    parent_clock(); boot = 1016000000000LL; wall = 1700000016000000000LL;
    assert(rnr_stage0_clock_bind_keeper_cutoff(&keeper_clock, 1700000010000000000LL,
                                              &keeper_error) == -1);
    assert(keeper_error.code == RNR_STAGE0_CLOCK_CUTOFF);
    assert(keeper_clock.phase == RNR_STAGE0_CLOCK_FAILED);
    assert(keeper_clock.deadline_boottime_ns == 1010000000000LL);

    parent_clock(); boot = 1003000000000LL; wall = 1700000003000000000LL;
    assert(rnr_stage0_clock_bind_keeper_cutoff(&keeper_clock, 1700000002000000000LL,
                                              &keeper_error) == -1);
    assert(keeper_error.code == RNR_STAGE0_CLOCK_CUTOFF);
    assert(keeper_clock.deadline_boottime_ns == 1002000000000LL);
    assert(keeper_clock.phase == RNR_STAGE0_CLOCK_FAILED);

    /* A copied clock is data, never the retained original-parent authority. */
    parent_clock();
    struct rnr_stage0_clock copied = keeper_clock;
    assert(rnr_stage0_clock_check_keeper(&copied, &tick, &keeper_error) == -1);
    assert(keeper_error.code == RNR_STAGE0_CLOCK_OWNER);
    assert(rnr_stage0_clock_check_keeper(&keeper_clock, &tick, &keeper_error) == 0);
    for (int fault = 0; fault < 4; ++fault) {
        parent_clock();
        if (fault == 0) --boot;
        if (fault == 1) --wall;
        if (fault == 2) owner = thread = 102;
        if (fault == 3) gate_fault = 30;
        assert(rnr_stage0_clock_check_keeper(&keeper_clock, &tick, &keeper_error) == -1);
        assert(keeper_clock.phase == RNR_STAGE0_CLOCK_FAILED);
        assert(keeper_child.child_pid == 101 && keeper_child.child_pidfd == 62);
    }
    return 0;
}
