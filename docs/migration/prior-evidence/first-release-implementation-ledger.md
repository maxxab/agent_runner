# First-release implementation ledger — canonical plan: docs/superpowers/plans/2026-11-09-shared-ai-development-workflow.html

2026-11-19, existing main abcd705. User requested complete first release and local WSL activation. Main sole implementation owner; same report-only reviewer136. One confirmed compaction retained; advance visibility unavailable. Scoped authority unchanged.

## Controlled native fork/gate prerequisite (R1/R3/R8), IN PROGRESS

Spec: E/keeper-design119.md plus independent report136. This is a prerequisite, not the whole keeper. Fixed original T0,15s setup and immutable original cutoffs/high-water remain. No actual native preparer invocation, GO path or activation before complete keeper/placement/recovery/profile/entry/closure qualification.

Pre-flight: current prepare_inputs captures its own original clock; it cannot follow a new captured fork unchanged. Main leaves that caller unchanged in this bounded step. Future integration MUST add an already-captured child continuation, never recapture. Parent clock must have a distinct negative role; current positive bind/admit/setup must reject it. Parent gate/pidfd never enter resumed child initial-FD inventory.

Ruling: implement controlled fork inside the clock module with an internal held child and no exported GO/release operation until real positive-cgroup placement/negative controls exist. The original parent retains exact direct-child PID/pidfd and private gate. This permits source/fixture validation of the fork boundary without creating an invocable incomplete supervisor. Cost: full keeper integration remains explicitly unfinished.

Trace before tests: prepare original clock -> exact0..2 descriptor admission -> reserve fork attempt -> verify no auto-reap -> private bounded gate -> physical fork -> parent retains exact child/pidfd and waits ARMED under original setup -> child arms/verifies parent-death protection and changes only execution identity while preserving origins -> child sends ARMED and stays HELD -> only a future verified keeper can issue GO -> child rechecks/once-closes gate -> original PREPARING continuation. EOF/malformed/timeout/parent loss exits child125; parent errors preserve negative ownership and never authorize child. No cleanup outcome inferred from gate closure or process exit.

Verification plan: native syscall-substituted tests for both branches, fixed packet framing, parent death/prctl failure, rollback/namespace drift/cutoff, duplicate/foreign calls, descriptor closes and pidfd failure. Existing native clock suite + related native compile/run fixtures; broad Python suite after source integration. Actual positive placement and real lifecycle NOT covered by these fixtures.

### Controlled fork prerequisite checkpoint

Implemented clock_fork (private qualification build only), private held gate, exact original-parent/child identity, NEGATIVE parent role, monotonic original-clock transition, no exported GO, and negative-only once-close abandon. prepare_inputs and native main unchanged; no invocable complete keeper.

RED: new native fork fixture could not compile because the function/result/roles were absent. Corrected fixture-only macro/declaration issues before implementation; final RED was missing feature declarations only. GREEN: mocked positive/negative branches and29 failure modes; legacy clock vectors pass. Two real unprivileged process cases abort at the held gate (EOF and original-parent loss); neither invokes the preparer or sends GO. Parent-loss fixture accepts125 orSIGKILL and does not distinguish the two mechanisms/every pre-arm race.

Reviewer137 requested unsigned-long width for PR_SET_PDEATHSIG. Added a fixture _Generic compile-time argument-type check: RED negative-array-size at the original int call, then GREEN cast and unsigned-long va_arg. Reviewer140 independently accepts the correction and bounded prerequisite, no corrective findings.

Final verification: focused4tests PASS2.285s; full Python/source suite1536tests205.454s OK8skips, process0, first-release-fork-suite-final.log. Earlier1535-test pass200.485s is superseded by final source evidence. Strict gcc13/C11/Werror/O2 compilation/link of actual validation and private-qualification artifacts also passed; both artifacts NEVER RUN (native-keeper-fork140/build-checks.json).

New design finding from reviewer138: ObserverLaunch forks from Main and inherits the positive leaf, so killing/freezing that leaf would also stop the supposedly independent observer. Separate negative-observer placement and actual service lifecycle semantics are required before Store/readiness. Whole R1/R2/R3/R8 and all five release gates remain OPEN.

Review139 conditionally supports separate negative leaf, with unresolved refinements: persistent task consumption vs pre-input leaf creation order; exact expected observer identity before accepting a new post-fork SO_PEERCRED connection; explicit parent/child/keeper normal/failure FD peaks. KillMode=process is only a candidate; actual unit lifecycle/restart/controller effects unverified. No source integration or host cgroup/unit/loop/DM/mount/Store/candidate/qualification operation occurred. Main continues engineering; no new approval required.

### Design143 selection after checkpoint

Reports141/142's separate input+journal workers are superseded by143: original Main performs a fixed ADMISSION subphase inside the gate while native keeper independently watches its exact pidfd. It may validate inputs and persist negative consumption/intents, but cannot create descendants/resources or return to normal main before verified placement+GO. Declaration/cutoff precedes disk writes. This is simpler and preserves the original clock/containment contract; reviewer143 accepts the bounded direction. Whole implementation still OPEN. Current E/keeper-design119.md contains the selected contract; historical119 preserved below it.

Publication: SSH normal push128 connection timeout. Bounded read-only HTTPS query using existing local credential also timed out; no HTTPS push attempted. No lingering owned Git/credential-helper processes. Local commits retained; last confirmed remote e0b02d5. No successful publication or activation claimed.

### Safe rollover143

# Safe rollover after controlled-fork prerequisite — 2026-11-19T00:15:34.596275+00:00

NOT LIVE. First release incomplete, all five gates OPEN. Chat01a1f083-5306-7643-8f93-9d1838760296 had unexpected second compaction (count2); no advance warning observed. POLICY requires this safe stop; no claim that the limit was enforced. Main ceases implementation after checkpoint documentation. Reviewer143 is report-only and idle. No owned native preparer, keeper, workload, qualification, cgroup/unit/loop/DM/mount or publication operation remains. Final docs session6698 completed exit0, including standards check. Product source unchanged since85d7b2a. Latest pre-rollover docs HEAD33b4d74, clean worktree before this checkpoint. Final checkpoint docs commits may follow; verify Git log/status rather than assuming this is final HEAD.

Verification: first-release-fork-suite-final.log1536tests205.454s PASS8skips exit0; focused4PASS; strict actual native artifact builds in native-keeper-fork140/build-checks.json, both NEVER RUN. Bounded review140 accepted source fix; selected keeper design143 accepted direction only. Source gate has no exported GO, native main/prepare_inputs unchanged. All essential integration/real entry/profile/closure/actual qualification remains. Review136–143 and design/ledger preserve feedback; no dependency on predecessor agent access.

Publication: last confirmed remote e0b02d5e51fb815fb4d0fd5a928a03008f730b8e; SSH push failed128, HTTPS read-only query timed out and no HTTPS push attempted. Current remote UNKNOWN; no success. Existing normal push authority persists. No lingering owned Git/credential-helper process.

Automatic successor unavailable: catalog has no create_thread/handoff_thread; daemon version check fails missing /home/faris/.codex/app-server-control/app-server-control.sock. No daemon started/config changed; no chat created/dispatched. Prepared prompt continuation-fork143.txt. Same WSL checkout, requested Sol Medium and Full Access must be established by supported successor controls. Teamwork canonical skills/teamwork/SKILL.md; same run RNR-D00, numeric ownership/next Issue Lead counter remains UNKNOWN where historical records are unknown, never reset/invent. Main writer stopping confirmed at this checkpoint; predecessor agents are historical only. New chat fresh count0.

Next: read selected143 at top of keeper-design119.md, verify current state, implement fixed original-child admission/protocol under original clocks; complete keeper and independent negative observer, actual private entry/workload/profile/immutable startup closure and integrated qualification before activation. See continuation-fork143.txt for complete authorization/limits and reading order.
