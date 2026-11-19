# RNR-D00 selected143 admission — implementation interface review

Status: bounded clock/inventory implementation reviewed; whole integration OPEN.
This is a review package for the next source change, not a second product backlog,
accepted implementation, qualification result or permission to execute native code.

## Scope and authority

Continue the first dependable local WSL release on existing main. Main is the sole
writer; one fresh report-only reviewer was explicitly authorized and started. Preserve RNR-D00 IDs/naming, unknown Main
ownership version/IssueLead counter, and reviewer v1-to-v2 migration history.
The migration allowance was exhausted; the user supplied a new scoped allowance
for reviewer v3. No further agents are authorized; predecessors are historical only.

Spec: [selected143](../../migration/prior-evidence/keeper-design119.md), selected
sequence and observer independence sections, plus the
[accepted product plan](2026-11-09-shared-ai-development-workflow.html).
Source baseline: b76fbd6027b7d0eeffa6f16f743030298563d679, clean main, observed remote
equality on 19 November 2026. Migration is complete; all five release gates are OPEN.
Canonical workflow: /home/faris/development-standards/docs/development-document-workflow.md.

This package refines selected143's fixed original-child admission direction.
It does not reopen the rejected helper141/142 approach or authorize extra features,
new profiles, UI, public publishing, global adoption or general deployment.

## Current source trace and established gaps

1. `runtime_stage0_qualification_main.c:main` directly calls `prepare_inputs`,
   then host-view/claim/media/device/mount/final-role stages. It has no keeper.
2. `runtime_stage0_preparer.c:rnr_stage0_prepare_inputs` reserves its one-shot
   owner, then calls `rnr_stage0_prepare_operational` before opening protected
   installation/task inputs. It retains five original descriptors, decodes fixed
   binary records and binds the task cutoff. It always captures its own clock.
3. `runtime_stage0_launch.c:prepare_launch` owns the private `prepared_clock`.
   Checks, early cutoff binding, final context encoding and exec use that same
   clock. An imported clock or public adoption setter would break this ownership.
4. `runtime_stage0_clock.c:rnr_stage0_clock_fork` preserves original samples,
   transfers only execution identity in the child, arms SIGKILL PDEATHSIG,
   retains the unreaped child's pidfd in its negative parent, and holds the child.
   It returns the parent after ARMED. There is no production GO sender. The child
   presently waits for GO without reading inputs or performing admission.
5. `rnr_stage0_claim_preparation` requires the host-view stage and journals under
   `/run/rnr-native-<TaskID>`. This existing diagnostic claim must not be relabeled
   as selected143's independently supervised persistent admission consumption.
6. `RootEntry._prepare` creates the emergency target, forks the observer, waits
   for readiness and opens the sole Store, then reports `STORE_READY_ONLY`.
   `ObserverLaunch` inherits Main's cgroup. Positive-leaf placement would therefore
   also contain the observer unless its independent negative placement is added.
7. `automation.control_runtime_qualification` is absent. Public operational
   `_entry` explicitly rejects. Neither source tests nor migration receipts close
   the missing actual workload/profile/startup closure or acceptance gates.

These are source-review findings. No new native artifact, consumer, Store,
service, cgroup, device, mount or qualification was executed in this chat.

## Proposed ownership and interfaces to challenge before implementation

Keep the original capture in the launch owner. Add a private, compile-time-fixed
qualification preparation route that captures there once and calls the physical
clock fork with that exact internal state. Do not export a clock getter, importer,
caller-selected phase, callback, path, pidfd or reset operation.

The child's fixed ADMISSION routine must be called from inside the held fork
branch. Refactor the existing fixed input reader into shared internal reading
steps; the held route must never call the unchanged `prepare_inputs` wrapper or
the clock-capturing launch preparation again. The unqualified validation route
must retain its existing behavior. No new externally selectable runtime mode.

Use an explicit admission-only clock/preparer state. It permits original-budget
checks, fixed input decoding, one cutoff narrowing, gate exchanges and consumed
claim/journal writes. It rejects host-view continuation, helpers/descendants,
Store, Engine/systemd, loops, DM and mounts. Ordinary input ownership can be
published only after actual placement, final GO, once-closing authentication and
storage temporaries, and a fresh original-budget check of the retained inputs.

Keeper owns its gate, exact unreaped Main PID/pidfd and negative clock role.
Main owns input descriptors/data and persistent production of durable receipts.
The keeper must poll its original clock and retained pidfd while Main performs
storage I/O; it must not open/read/fsync storage to validate a producer receipt.
Every protocol operation is reserved before its sole send/effect. No retries,
reconnects, adoption or clock renewal after malformed/partial/lost/late exchanges.

Before any blocking persistence, Main sends the complete validated original
installation/task declaration, original capture/cutoff/high-water and actual
launch/outer identity binding. Keeper validates exact expected fork identity,
correlates the unchanged origin, consumes the declaration once, narrows its own
bound and acknowledges the exact operation/sequence. It cannot learn an expected
owner from the first arbitrary peer. Binary record decoding alone is not proof
of launch payload semantic correlation or actual immutable outer-unit identity.

Persist exclusive TaskID consumption and the full original invocation binding
in authenticated project-owned external storage. Existing/uncertain consumption
rejects; do not adopt, move, remove or replay historical records. Installation's
fixed storage binding and recovery format must be reviewed before choosing or
creating a new path. A diagnostic tmpfs journal or a successful `pwrite` alone
does not meet this contract. Check the original budget after each potentially
blocking syscall before any next write, packet or effect. Late completion remains
consumed/UNKNOWN, with no positive continuation.

Progress irreversibly through declaration, durable consumption, durable leaf
intents, acquired positive/negative leaves, durable placement intent, verified
placement, durable GO intent and final GO. Replies bind the exact operation,
sequence and acquisition identity. Match each resource effect to its prior
accepted durable intent. Keep the keeper outside both leaves. Before placement,
its exact pidfd is the kill authority; after placement it retains actual negative
controls. Containment cannot wait for another journal write.

For observer independence, preserve both original emergency-target phases:
precreation intent/late tracking, then actual held acquisition. Register the
original observer fork PID/pidfd with the same keeper before arming the observer's
new connection. Match actual PID/start/parent/thread, move/read back its singleton
negative leaf once, close authentication temporaries, then permit Observer READY
and Store. An inherited socketpair peer credential is not observer authentication.
Actual service lifecycle must preserve the observer when the keeper dies;
`KillMode=process` remains a proposal requiring evidence.

## Change boundaries and required checks

Main owns all source/docs/Git and host mutations. Proposed source boundaries:

- `automation/native/runtime_stage0_clock.{c,h}`: original fork lineage,
  admission-only checks and fixed gate transport. Never expose a naked GO API.
- `automation/native/runtime_stage0_launch.{c,h}`: private capture/fork ownership,
  original early cutoff and retained clock into final handoff.
- `automation/native/runtime_stage0_preparer.{c,h}`: shared fixed input reads,
  admission-only retention, exclusive storage production and post-GO continuation.
- A focused native keeper unit, if needed: negative polling/control ownership and
  exact consumed protocol progression, separate from the 2,800-line preparer.
  Adding native resources requires updating packaging/installed-build checks;
  do not alter the historical migration manifest to pretend they were imported.
- Python root/provisioner/bootstrap/prefork/observer integration: the two target
  phases and expected-observer registration/negative placement before READY/Store.
- Private qualification entry, actual runtime profile and immutable startup closure:
  necessary dependent release work, not optional follow-ups to an accepted release.

For each boundary, add and observe a meaningful failing check before source edits,
then implement and verify it. Required focused cases include:

- Capture occurs once before inputs; original cutoffs/high-water survive the fork
  and every input/claim exchange. Recapture, duplicate binding, rollback, foreign
  clock owner and late completion cannot recover positive authority.
- No ordinary continuation/descendant/effect before verified placement plus GO;
  EOF, parent death, partial/oversize/ancillary/wrong-phase packets and lost ACKs
  fence without resend. Keep real process fixtures abort-only until the complete
  qualification artifact is independently accepted for actual execution.
- Collision, uncertain creation, short write, sync failure and stalls at every
  storage boundary retain consumption and trigger keeper action independently
  of blocked Main. No keeper persistence syscall enters its polling path.
- Death/ACK loss at every leaf intent/acquisition/placement/GO boundary preserves
  exact negative ownership and UNKNOWN; leaf disappearance/recreation rejects.
- Observer construction/registration/connection/placement/READY failure cannot
  open Store or release a workload. Keeper death after observer readiness leaves
  the observer able to contain the exact target.
- Role-by-role normal/failure descriptor peaks include proc/namespace/executable/
  pidfd/authentication/storage/scanner temporaries: native256, observer64,
  Python prefork53+5+2=60. No generic allowance or premature handle closure.

Follow focused checks with the affected native/Python integration tests. Compile
actual artifacts strictly without executing them until all operational gates
permit it. Rebuild the wheel and check installed source/resources outside both
checkouts when packaging/native linkage changes. Reuse unchanged migration
evidence only for its exact scope; final actual success/failure/recovery needs
new integrated evidence tied to the full immutable executable/startup closure.

## Review request and continuation

Required first review: independently challenge these implementation boundaries,
the persistent binding/format and one-shot protocol before dependent source work.
The reviewer is report-only: no source, Git, host, runtime, test/build or child-agent
operations. Review findings and decisions must be saved, not left in a chat-only
reply. Main remains sole implementer/writer. Source review cannot authorize live
qualification or replace the later independent validation/actual acceptance gates.

User authorized one fresh report-only reviewer for this RNR-D00 keeper assignment
on 19 November 2026. Known reviewer ownership transfers v2 to v3; Main remains
sole writer. No additional agent allowance is implied. The initial review produced V3-F1..F5 below. Bounded follow-up acceptance does
not close the whole integration findings. Do not reuse migration reviewer v2's
closed findings for new interfaces or code.

All five release gates remain OPEN. Local activation is conditional on actual
acceptance. Production validation NEVER RUN.

## Reviewer v3 findings and staged resolutions

Initial independent source/design review identified five P1 findings; none is
closed merely by accepting its recommendation. Full report is saved by Main at
/home/faris/.local/state/agent-runner/first-release-20261119-01a1f150/review-v3-initial.md.

| ID | Finding | Current disposition |
| --- | --- | --- |
| V3-F1 | Installation lacks persistent project/store identity and torn-record recovery contract | Accepted; persistent admission remains gated |
| V3-F2 | Envelope decoding does not define pre-GO semantic declaration validation | Accepted; declaration/GO remains gated |
| V3-F3 | Setup15 checks cannot supervise original60/90 | Accepted; separate negative-clock contract proposed below |
| V3-F4 | Existing exact-stdio admission rejects a held gate | Accepted; exact held-role contract proposed below |
| V3-F5 | Late target/observer transition and service survival guarantees incomplete | Accepted; actual lifecycle/GO remains gated |

The following separable clock/inventory work does not choose a persistent store,
emit an operational packet, expose GO or invoke the qualification artifact.
Main implemented only the already-selected admission-only clock permissions:
cutoff narrowing stays ADMISSION and is one-shot, setup/identity/high-water checks
remain enforced, positive FD admission rejects. The phase is not yet entered by
production control flow. New constructed-state fixture failed on the absent phase,
then all five native clock/fork checks passed in3.756s. The new fixture does not
claim actual fork-to-admission/placement integration. Actual native artifacts NEVER RUN.

### V3-F3 proposed private negative-clock interface

Add `rnr_stage0_clock_check_keeper(state, tick, error)` under the existing private
qualification build. It accepts only the exact original retained fork-parent clock
and owner, with its held result/child identity; a copied/foreign/child clock rejects.
No caller deadline, origin, phase selector or arbitrary clock adoption. A successful
tick contains `setup_expired`, `trigger_due`, `trigger_ns`, `stop_ns` and current
unchanged-origin high-water samples retained on the clock itself.

Setup/admission checks still expire at `min(T0+15s, task cutoff)`. A negative tick
continues after setup15, reports `setup_expired`, reports `trigger_due` at
`min(T0+60s, stop)`, and rejects at `stop=min(T0+90s, original task boottime cutoff)`
or the original task wall cutoff. Both identity checks and both clocks retain
the original nondecreasing floors. An independent source check accepted the
admission-only permissions and this separate negative-clock direction. Tick
expiry or loss of a valid original time/identity bound permits no new effect:
retain UNKNOWN and original controls/bounds for recovery. A protocol failure
while a fresh negative check still establishes a live lease may trigger guarded
containment. Each individual effect requires a fresh successful negative check,
using the original negative stop rather than setup15. A tick is data, never
resource/release authority. Binding/exchange errors alone do not destroy a valid
negative clock; actual time/identity failures fence it without erasing ownership.

Add `rnr_stage0_clock_bind_keeper_cutoff(state, cutoff, error)` with the same exact
retained-parent identity requirement. This is distinct from the positive binder,
which continues rejecting NEGATIVE. It consumes one narrowing attempt, preserves
the parent's original samples and its own high-water marks, and cannot extend any
bound. A declaration arriving at/after setup expiry rejects; the negative actor
still needs containment on that failed exchange. The wire receiver must validate
and consume the full declaration before this private data-binding call.

Tests must exercise the actual mocked fork-parent route, original15 boundary,
continued negative monitoring after15, trigger at60, rejection at90 and earlier
task cutoffs, duplicate binding, rollback, namespace/owner change, copied clocks,
and unchanged origins/high-water after binding. No real process runs past a held
gate and no resource operation is introduced by these tests.

### V3-F4 proposed fixed held inventory

Initial exact0..2 admission remains unchanged before creating the socketpair.
Under that exclusive launch ownership, socketpair creates3/4; the child closes3
and retains gate4. Enforce those numbers in the physical-fork implementation,
rejecting an unexpected allocation without repair/duplication. Add a fixed private
held-role structural wrapper accepting only stdio0..2 plus socket4 and its local
scanner (normally3). The gate must be AF_UNIX, SOCK_SEQPACKET, O_RDWR, NONBLOCK,
CLOEXEC. This wrapper authenticates no peer; original fork lineage and the
retained gate owner supply that separate binding. No caller FD/whitelist argument.

Factor the scanner's internal role lookup to support that one closed sparse set;
existing preparation0..2 and final0..8 wrappers retain their exact sets. Unknown,
aliased, disappeared/replaced or extra descriptors reject. Storage/input handles
must not exist yet when this held initial inventory runs. After GO, recheck
retained input identities without re-running initial-stdio admission or recapture.

The exact native fork/gate baseline peak is stdio3 + two gate endpoints2 + one
clock identity temporary1 =6; the parent closes the child endpoint before opening
the retained child pidfd, retaining the same peak6 during ARMED checks. The held
child peak is stdio3 + gate1 + scanner1 =5 for its initial scanner. These are only
these stages, not a complete native256/storage/containment budget. Final budget
closure remains required for every later normal/failure path. Python prefork
53+5+2=60 and observer64 remain unchanged.

## Bounded source checkpoint

The proposed F3/F4 interfaces above are now implemented in the private native
clock/admission modules, with original-fork and held-inventory fixtures. Reviewer
v3 accepted their bounded source, not whole negative authority or integration.
A further F3a finding required retaining narrowed bounds even when admission
rejects a cutoff at/below original60; admission requires trigger strictly before
stop. Corrected source passed8focused checks in4.698s and independent exact-hash
review. Source snapshot: protected review-v3-window-snapshot.json. The prior
1431-test full pass applies to the pre-F3a snapshot only; post-fix verification
passed1431tests in183.714s/7skips. Offline wheel/sdist and two installed disposable
consumer checks plus three strict native builds passed, native artifacts NEVER RUN. All five release gates remain OPEN.
