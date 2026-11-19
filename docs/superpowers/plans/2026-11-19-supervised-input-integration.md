# RNR-D00 supervised-input integration and release execution

Stage: resumed release engineering after completed extraction. Existing accepted
RNR-D00 assignment and plans remain the task source; available searches returned
no matching GitHub issue in either repository. No URL/counter is invented or new issue published.
This plan's first implementation boundary is the supervised native held-input
vertical, not a blanket assignment to implement unrelated features.

Spec: selected143 in docs/migration/prior-evidence/keeper-design119.md; current
persistent-admission-contract.md and selected143-admission-review.md; canonical
workflow /home/faris/development-standards/docs/development-document-workflow.md.
Baseline fca3dfd882a8b3be86b8fd27af3ca0249defbdd7; Main's current uncommitted
changes are release ownership notes in first-release handoff and migration/ownership.
Permissions danger-full-access / approval never. Existing main only, no worktree/
branch/reset/force push. Protected state and historical consumed attempts untouched.

## Contract and acceptance before source

Main owns architecture/interfaces, handoffs, Git and any host operations. The user
approved one fresh implementation lead with two task owners plus independent
review/QA; no recursive child delegation. Reviewer v4 is report-only for design,
then receives concrete review/QA scope. Parent model/effort ceilings are inherited
through the supported full-fork contract; no stronger override. Historical numeric
Main/next IssueLead counter UNKNOWN. Reserve unique local identity
rnr-d00-release-(ILead-UNKNOWN-20261119), native rnr_d00_release_ilead_unknown_20261119,
without resetting or asserting a numeric counter. Actual creation ID follows.

Reused design: original capture remains private in launch.c. All supervision
fork routes share the one atomic clock fork reservation, and all legacy/validation/
supervised preparation routes share launch and preparer reservations. No caller
clock, callback, path, mode selector, gate getter, naked GO sender or origin adopter.
The fixed private wrapper is the only source control flow allowed to enter held
admission. Ordinary preparer main and all media/Store/manager/resource stages remain
barred until a later complete placement+GO protocol.

A private launch-owned supervised wrapper captures exactly once, physically forks
through clock.c, and in its original child calls only the fixed held-input reader.
Its clock/result storage is static, never an escaped local pointer. Child arms/
checks original PDEATHSIG, retains exact gate4, transfers execution PID/TID only,
sends ARMED once and enters ADMISSION. The no-GO precursor retains its prior
behavior and shares reservation; no second fork path is possible.

Held reader shares internal fixed read/recheck steps with legacy reader, without
calling clock-capturing prepare_inputs or initial-stdio scan. It consumes the same
preparer attempt, admits exact held inventory and uses a distinct admission-only
state. Legacy128-byte read remains unchanged; supervised reader requires exactly
448-byte installation-v2 and original task bytes. Correlate only concretely
available original facts: decoded allocation/task ID, installation asset/execution
roots, original boot/clock/cutoff and Store44 versus outer60–90. Full store/unit/
policy/enrollment identity is NOT inferred from structural DATA. Missing trusted
comparisons bar declaration and all persistence/positive continuation.

Cross-module contract: Main freezes purpose/invariants here; implementation lead
proposes exact C signatures in this plan for independent review before source.
Clock/launch owns held timing/check/binding and gate state; preparer owns fixed
input reading/retention and semantic comparisons. No getter exports the private
clock, raw gate, mutable owner or authority token. A held-input return is private
to the fixed wrapper and MUST NOT publish ordinary INPUTS_HELD or enable later
stages. Gate/storage/auth closures and original checks remain necessary before
future ordinary publication. At this first boundary the wrapper always fences/
abandons and exits without GO; no runnable main is redirected yet. It supplies
no API for a caller to resume ordinary preparation after a held return.

Parent retains its exact original unreaped child pidfd/gate, negative clock and
error/recovery context. Any fail-closed collection must target only that original
child, check the original negative lease before a new signal, consume action once,
never infer child exit from closed gate, and not abandon storage/control authority.
There are no task resources in this first boundary; real post-effect keeper loop
comes only with reviewed durable intent/placement protocol.

## Exclusive ownership and integration

| Task / owner | Exclusive source and checks | Starts after | Acceptance |
| --- | --- | --- | --- |
| NATIVE-A / lead's fresh task owner | clock.c/h, launch.c/h; focused new clock/launch native fixtures and their dedicated Python drivers | Exact signatures + independent contract review | Original capture/fork ownership, shared reservation, child held route, static parent lifetime, no GO/effects/ordinary success |
| NATIVE-B / lead's fresh task owner | preparer.c/h; focused new held-input fixtures/driver | Same signatures; A input timing seam usable or exact link fixture | Shared fixed reader, v2-only held route, original data correlation, distinct phase/fence/once-close and no legacy recapture |
| Lead / integration | This plan's implementation details and evidence, proposed fixture/helper link commands; no root-owned handoff/Git writes | Both owners report stable snapshots | Two substantive task outputs, integrated focused checks, all feedback retained |
| Main | README/handoffs/ownership, package/install/CI if boundary requires it; all Git index/commit/push and host mutations | Reviewed scoped results | Coherent integrated snapshot and honest release-gate status |
| Reviewer v4 | Read-only design/code challenge, later separately authorized focused QA | Stable design/source snapshot, test resources free | Independent findings and closure evidence |

Shared checkout: child files are disjoint. Lead must itself spawn the two task
owners, record native/canonical identities and supervisor mapping, and enforce
no child-to-Main/sibling communication. Child reports go through Lead. No child
spawns. Reserve root+Lead+two owners within four active slots; reviewer executes
in a separate wave after ownership/results are stable. Do not treat an idle
agent as a released slot without supported tool evidence. All tests bounded,
outputs under new private release-resume evidence directory. No actual native
qualification binary may be executed; unit fixtures/mock syscalls and compile
checks only at this boundary. Main alone authorizes any later whole-candidate
physical qualification after actual reviewed prerequisites.

## Verification and remaining dependency order

Trace before testing; add tests exposing missing original-held route/reader,
then implement minimal reviewed code. Cover null/repeated/cross-mode attempts,
foreign owner, FD inventory, changed inputs, v1 refusal in held route, malformed
v2/v3, original cutoff/boot/root/ID mismatch, late/blocking read, once-close errors,
parent/child exit and no success/resource/GO publication. Existing source fixtures
may substitute syscalls; clearly separate them from physical qualification.
Inspect full integrated diff and source hashes before independent review. Broaden
tests only for changed boundaries; package consumers must remain advisory.

Later reviewed waves, owned by the same bounded RNR-D00 release team as suitable:
exact F1 durable latch/claim/intent/recovery bytes + F2 authenticated finite messages
+ F5 actual hierarchy/placement/GO; observer negative commit/READY; real private
Python session/rnr_command and protected authenticated inference route; immutable
closure; actual finite success/failure/recovery, then explicit local activation.
No whole release gate closes from this first fail-closed integration. Provider
transport/pinned binary/credential custody/internal retry inventory remain to be
frozen and independently challenged before dependent provider code or account use.

## Exact interface freeze and independent design decision

Main adopts the lead's exact C signatures/semantics in the protected
release-resume-20261119/ilead-unknown-20261119/contract-proposal.md as the first
NATIVE-A/B contract, with all six mandatory v4 refinements in
release-resume-20261119/review-v4-native-contract.md. That saved proposal and report
are accessible to both owners and contain no predecessor-only context.
This is conditional independent acceptance for the fail-closed boundary ONLY.
A/B source implementation is released with those refinements mandatory; missing
trusted F1/F2/F5 comparisons still prevent declaration/persistence/placement/GO.
The implementation lead must preserve legacy behavior, actual-source integration
fixtures and exact failed-child lifetime ownership; source checks do not authorize
actual native artifact execution. Main retains all Git/host/doc authority.

Producer signatures: prepare_held_inputs(preparer_error*); caller is only the fixed
launch supervised_inputs(preparer_error*) wrapper. Launch owns private check and
bind_admission_inputs(installation*,task*,launch_declaration*,launch_error*) DATA
comparison, no caller origin/authority. Clock owns fork_admission, check_admission,
abandon_admission and contain_original_child with exact original state/result.
All declarations private qualification-only. No naked GO, clock/gate getter,
caller callback/mode/path, main change or ordinary positive continuation.

## Implementation checkpoint — bounded source only

Lead actually created fresh NATIVE-A and NATIVE-B task owners, both supervised
only through Lead, ownership v1; exact native/canonical creation mappings,
acknowledgements and settings limitations are preserved in protected
`release-resume-20261119/ilead-unknown-20261119/coordination.md`. Historical numeric
counter remains UNKNOWN. A owns clock/launch and actual-module integration fixture;
B owns shared fixed reader, admission phases and held-reader fixture. No child
delegation, Git/host/account/credential/runtime operation or writer overlap.

The exact reviewed private signatures above are implemented. Six native source/
header files and six new test files constitute this boundary. Both child outcomes
remain mandatory exit125; no ordinary main redirection/GO/persistence/declaration
or resource success. A/B retained original one-shot ownership and distinct
admission states; valid negative timing survives positive setup-only expiry,
with no clock revival after identity/time failure. Numeric pre-pidfd containment
uses the explicit immutable single-thread/no-reaper precondition, bounded trusted
Threads:1 observation and fresh disposition/time checks; failed pidfd signaling
never falls back. Static parent clock/result preserve original child ownership.

Owner-focused checks pass, including16 actual-five-module integration scenarios
with syscall boundaries simulated, legacy mocked regressions and strict native
compile-only checks. Lead also strictly linked actual validation/qualification
sets without execution, and audited the corrected integration fixture's unresolved
imports: no host-effect syscall remained outside its boundary wrappers. A test
portability finding was corrected and independently rechecked by reviewer v4.
The first integration harness attempt missed fortified open interception, opened
the root directory read-only then immediately rejected at mocked metadata; no
mutation/physical fork/signal occurred. Corrected final fixture uses fortified
aliases and denies unexercised host boundaries; the failed attempt is preserved.

Exact source snapshot/diff, source traces, owner reports, check commands/results
and limitations are in protected
`release-resume-20261119/ilead-unknown-20261119/integration/report.md`. Concrete
reviewer v4 matched all17 hashes, accepted the bounded source, independently
passed all three mocked drivers (9.560s), including16 integrated scenarios,
strictly linked both actual native sets without execution and independently
audited fixture symbols. All six mandatory refinements and the portability
correction are satisfied within this boundary. Evidence is protected
`release-resume-20261119/reviewer-v4-native/review.md`. Main accepts this bounded
component subject to the broader regression/package checks recorded in the release
handoff. No whole release gate closes. Actual artifacts NEVER RUN, existing
qualification main unchanged and still barred.
