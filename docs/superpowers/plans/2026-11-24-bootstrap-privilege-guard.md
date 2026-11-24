# Original-child bootstrap privilege guard implementation plan

Main implements; the one successor reviewer independently challenges the interface
and integrated source. No implementation delegation. RNR-D00, existing main;
canonical workflow /home/faris/development-standards/docs/development-document-workflow.md.
Spec: [coupled F1/F2/F5 contract](2026-11-19-persistent-admission-contract.md),
[requirements](../../requirements.md), current release handoff. This is an integrated
negative prerequisite, not whole bootstrap/project admission or a released guard.

Goal: reject mapped-user-namespace privilege and proc-component substitutions in
the original held child before installation/task I/O. The existing unconditional
abandon/exit125 stays. No project locator, input authority, persistence or GO is
added. Legacy validation/preparer paths retain their current historical contract.
Architecture: fixed private bootstrap.c/h, called only by prepare_held_inputs after
exact initial held-FD inventory; fixed launch admission check owns the clock.
Linux x86_64 C11/GCC13; stdlib-only Python native fixture drivers.

## Trust and alternatives

Installer-established immutable native entry and original launch/root context,
trusted kernel, stable namespaces, no privileged mount/credential injection, no
threads/callbacks/reaper/disposition changes are explicit premises. The guard does
not establish these premises by reading /etc or hashing its own executable.
Initial user namespace + actual root IDs rejects mapped-root impostors under those
premises; it does not authenticate a chosen host root, PID1, project or manager.
Dynamic WSL PID/mount/cgroup namespaces remain valid. Exact running-build support
and actual guard behavior require later physical qualification, not tag/uname
agreement. The reserved user inode is supported-target policy, not a portable API.

Rejected: uid_map/root IDs alone (insufficient); per-boot compiled host anchors
(additional repinning and pre-T0 trust/I/O); moving the existing INPUTS_HELD hostview
earlier (violates its state/ordering). Later manager/policy/root authentication,
both keeper+child cgroup correlation and per-project reader remain mandatory.

## Fixed interface and traversal

Private-qualification-only `int rnr_stage0_check_bootstrap(struct
rnr_stage0_bootstrap_error *)`, no path, clock, callback, FD, result identity or
project selector. One atomic attempt; NEW -> CHECKING -> DONE or FENCED, no reset.
Only winning original PID/TID owns slots; a losing/foreign/reentrant call fences
without draining an active owner's FDs. Winning owner detects fence and unwinds.
Null first call consumes attempt but opens nothing. Exclusive error output.
Fixed check is rnr_stage0_check_admission_preparation, never a captured/imported
clock. Call it before/after every syscall except terminal cleanup after failure.
Guard-owned observations are bracketed with the existing launch-clock primitive;
its internal syscalls are not recursively wrapped. Sample real/effective UID/GID0
and getpid==gettid>0 BETWEEN two original-clock checks at each live boundary;
mismatch fences before the next observation. This adds no claim about new
per-internal-syscall clock bracketing in the existing primitive.

Retain exactly nine roles, slot invalid until successful open then registered
BEFORE any post-open check. Initial baseline stdio3 + gate1; never close/repair a
returned FD<3, report it as unadopted. Kernel valid open returns distinct unused
FDs under exclusive ownership; no arbitrary FD scanning/repair.

| Role | Fixed resolution and expected kind |
| --- | --- |
| 0 | `/`, O_RDONLY DIRECTORY NOFOLLOW CLOEXEC, root:root directory without group/other write |
| 1 | `proc` from0, same flags, procfs0x9fa0 directory, inode1, root:root |
| 2 | `thread-self` from1, O_PATH NOFOLLOW CLOEXEC; genuine proc symlink |
| 3 | canonical decimal TGID from role2 link, from1, readonly directory |
| 4 | `task` from3, readonly directory |
| 5 | canonical decimal TID from role2 link, from4, readonly directory |
| 6 | `ns` from5, readonly directory |
| 7 | `user` from6, O_PATH NOFOLLOW CLOEXEC; genuine proc symlink |
| 8 | `user` from6, O_RDONLY CLOEXEC intentionally follows ONLY this checked proc namespace link |

Read role2 through readlinkat(held_link,"",buffer,32), once. Require exact
`<TGID>/task/<TID>`, canonical positive decimal <=INT_MAX, no extra/truncated/NUL/
empty/leading-zero bytes, both numbers equal current getpid/gettid. Proc mount PID
view must agree with the syscall PID view for this fixed runtime. Read role7 once
using a32-byte buffer, exact `user:[4026531837]`. Link strings are not authority.

For roles1..7, require fstatfs procfs, same st_dev and STATX_MNT_ID as retained
role1, nonzero inode; directory/symlink types exact, UID/GID0. Directories must have no group/other
write; proc symlink permissions (normally0777) do not authorize anything and are
not tested as writable-directory permissions.
Role1 must have inode1. Check statx mask includes MNT_ID and value nonzero.
No component permits following a symlink except intentional role8 namespace open.
A bind/overlay at any proc component/link changes the mount identity and rejects.
Root->proc is the one permitted mount boundary; proc mount IDs need not be static.
Role8 requires NSFS0x6e736673, regular file, inode0xeffffffd, nonzero device,
NS_GET_NSTYPE==CLONE_NEWUSER. Do not infer initial pid/mount namespaces or accept a
readlink string in place of the followed kernel namespace handle.

Before success, recheck each held role and reopen its original named reference
from the retained parent, one temporary at a time, with the same flags/kind/fs/
mount constraints. Compare dev/inode/mode/uid/gid/rdev/nlink, and immutable link
size/mtime/ctime; directory metadata ignores size/timestamps. For role8 re-open
intentional namespace link and repeat NSFS/type/inode/ioctl; compare full held
namespace identity including dev+inode with the original role8. Recheck role7
named-link continuity immediately before and after the intentional role8 follow
using the same single temporary slot; close each temporary before the next open. Re-read exact role2/7
link bytes through the held links during recheck; every read is bounded once.
Root named recheck opens `/` and must equal original root. No rebase to a new root,
proc mount, namespace or replacement entry. Recheck IDs and original clock after
all retained/named comparisons, then once-close roles8..0 before returning0.

Cleanup invalidates before close; never retries. Attempt every owned close even
on error or setup expiry, recording up to10 errors (nine roles + one temporary),
first primary error/errno and separate first launch-clock failure capsule. Record
failed syscall errno before post-call clock checks, including a failed observation
or a close entered after a valid live check; preserve simultaneous clock failure
in its separate capsule. Terminal failure unwind is exempt only after this
initiating postcheck; no cleanup error erases the first error.
Success closes have live checks before/after; any late/error/fenced return becomes
terminal failure and remaining slots drain without further positive observations.
Return0 means narrow negative observations succeeded and all guard FDs closed;
no readiness/grant. Current fixed reader still abandons/exit125 on either result.

Peak: baseline4+nine guard roles+one named temporary+one original clock proc
handle=15, including failure unwind. No rights/transferred FD/heap/thread/helper,
retry, wait, directory scan, namespace mutation, manager/socket or store access.
This local15 does not close whole native256/Python60/observer64 inventories.

## Review focus and implementation sequence

Main owns bootstrap.c/h, preparer call/error integration, driver/fixture, package
native build source lists and docs; reviewer owns only reports. The existing main
and previous evidence remain; no actual native artifact is executed.

- [x] Independent exact-interface challenge: reviewer accepted the narrow theorem
      subject to directory-only mode checks, explicit clock-helper boundary and
      full namespace identity/link continuity. All three incorporated before source.
      Protected bootstrap-review-successor-contract.md preserves report/decisions.
- [x] RED actual guard fixture and held-reader ordering regression. Substitute and
      audit every host-effect import BEFORE fixture execution. Test a valid trace,
      every acquisition/metadata/link/namespace syscall failure, post-call expiry,
      overlay/dev/inode/mount/type/ownership drift, canonical decimal/malformed link,
      wrong nsfs/type/inode/ioctl, both real/effective IDs, foreign/reentry/null/
      repeat and once-only cleanup including simultaneous errors.
- [x] Main implement minimal fixed stage and integrate after held inventory/before
      any installation/task open. Preserve separate primary/cleanup evidence.
- [x] Focused actual-module integration with mocked boundaries; late/failing guard
      forbids protected reads, binding, persistence and all ordinary continuation.
- [x] Independent source snapshot recheck and strict installed compile/link NEVER RUN;
      offline wheel/sdist and two installed consumers PASS.
- [x] Full Access restored; default suite1446tests202.246s PASS,7skips. The
      earlier restricted failure is retained below as separate environment evidence.
- [ ] Return to the whole coupled admission contract; no positive wrapper change
      before complete F1/F2/F5 acceptance. Actual build/manager/profile/provider/
      lifecycle/recovery and separate project adoption remain release gates.

## Current evidence and limits

Original negative guard and actual held-reader ordering regressions observed RED.
Source review then found that failed syscalls/close skipped the required post-call
clock check, dropping a simultaneous expiry capsule. The new error+expiry fixture
reproduced that omission before correction. `failed_syscall` now preserves the
initiating errno before the original-clock check; successful pre-close checking
retains a post-close check even if close fails. Once-only cleanup remains terminal.

Focused guard/held-reader/actual-six-module checks passed3tests in10.815s. These
exercise substituted syscall boundaries, not actual host/native qualification.
Replacement independent source review matched all11snapshot hashes and found no
blocking issue; it performed no execution/QA. User expressly authorized that one
replacement after the first reviewer was lost during an intentional interruption.
The first reviewer's initial/source findings remain retained, not erased.

Current permissions changed mid-work to workspace-write/approval never: `.git` and
the original protected evidence root are read-only; socket option observations/
PASSCRED are denied errno1. The fresh default run finished1446tests in231.346s with
10failures/267errors/7skips. All267errors are PermissionError errno1; some indirect
failure attribution remains unisolated. No tests or socket checks were weakened.
The earlier interrupted run had no final result. Historical1445PASS evidence is
for the predecessor source, not this change. Fresh offline wheel/sdist build and
two isolated installed consumers/three native compile-only builds PASS; no native
artifact ran. Current wheel SHA256
`bb45c6b7dcf1f2695b859ddad01d4c29b0751f9a30096421b250e24d04560518`.

New evidence is temporarily protected under
`/tmp/rnr-d00-bootstrap-review-ts1e2k15` (0700), pending a copy into the established
external evidence root when writes are restored. Historical evidence stays in
place. Source remains uncommitted on existing main; no push or activation occurred.
The [successor checkpoint](../../handoffs/2026-11-24-bootstrap-progress.md) records
precise ownership, permissions, evidence and remaining whole-release work.

### Full Access recovery

The user restored danger-full-access/approval never and requested continuation.
All reviewed executable/test hashes were rechecked unchanged; protected predecessor
stop receipts remained intact. Owned socket PASSCRED set/readback and SO_DOMAIN now
succeed. Temporary evidence was copied with every-file hash verification into
`/home/faris/.local/state/agent-runner/release-admission-20261119/bootstrap-successor-01a20b1c`,
with historical files and the original temporary copy retained. The fresh full
suite passed1446tests in202.246s,7skips (`full-access-suite.log`). No test/guard was
weakened, and package/consumer results remain applicable to unchanged source.
The previous permission checkpoint is historical; coupled admission and operational
release work remain unfinished. Current execution thread01a20b29 has a separate
protected ownership-resume receipt and preserves UNKNOWN Main/counter values.


## Shared held-reader clock correction under the reviewed G contract

The next actual bootstrap/project-input flow reuses common preparer input helpers.
Source trace found those helpers returned before post-call original-clock checks
on failed open/fstat/statx/fstatfs/pread. A simultaneous syscall error and expiry
therefore lost the separate clock capsule. Admission temporary closes similarly
omitted a required post-check, and final acquisition suppressed it after close
failure. This is a prerequisite correction in the existing actual held-input flow,
not another DATA codec or complete project/host admission claim.

One private failed_input helper preserves initiating code/errno, observes the
original clock, and returns failure. Short/extra-EOF reads follow the same rule.
live_input retains the first clock capsule; later fencing cannot overwrite it.
Admission/final acquisition close registers invalidation first and observes the
clock after a failed close; terminal drain remains once-only without fresh positive
checks. No path, clock, receipt, producer, protocol, Store or activation API added.

RED: new held fixture failed at its separate-clock-capsule assertion before source
correction. GREEN: focused3tests PASS10.322s, including seven simultaneous input-
error/expiry cases, two close cases and five added actual six-module scenarios.
The actual-module driver audits imported host interfaces before execution and now
covers25scenarios total. Same authorized replacement reviewer source PASS with
exact four-file hashes; no reviewer execution. Protected evidence:
release-admission-20261119/input-clock-successor-01a20b29. Full-suite/package evidence
and final publication are recorded in the handoff when complete.

The private wrapper still abandons/exits125. G1 actual bootstrap/project/policy/
manager authentication and G2-G6 operational integration remain unfinished.
