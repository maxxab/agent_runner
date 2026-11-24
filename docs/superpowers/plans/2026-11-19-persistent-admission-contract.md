# RNR-D00 persistent admission and late containment contract

Status: coupled admission remains a proposal; Revision B storage preparation is
implemented and independently reviewed, but uninvoked. No operational path, unit
or runtime effect is authorized by this document. Main is sole writer.
Canonical workflow: /home/faris/development-standards/docs/development-document-workflow.md.
Refines F1/F2/F5 in the selected143 admission review; all five release gates OPEN.
Existing historical stores and attempts remain untouched at their original paths.

Current contract map (latest direction wins over superseded proposal paragraphs):
Revision B is implemented storage preparation ONLY, published5c423e7/97ae696, uninvoked.
Candidate C defines direct PID1 framing, conditionally challenged/corrected by v5.
Candidate D defines effective units plus permanent empty controller-demand anchor;
its post-review Manager.UnitPath addition makes316total requests, not314/128.
Correction E defines single-claim view and one-way producer handover direction.
Candidate F defines proposed9728-byte protected policy and per-project input locator.
C/D/E/F are NOT full source release. Still freeze/challenge complete policy semantic
projection/renderer/bootstrap lineage, IPC and capsule byte/ACK/opcode inventory,
all normal/failure FD peaks, and sole offline retirement/recovery evidence. No
additional startup/provider/account/lifecycle action is accepted by these designs.

The [requirements index](../../requirements.md) maps the product acceptance IDs
and current evidence boundaries. Authorized prerequisites may be implemented in
dependency order after their affected interface is challenged. The complete
coupled contract remains mandatory before positive declaration/GO or activation.
Earlier investigation of arbitrary dual-actor loss and post-capsule clock samples
does not establish additional acceptance requirements or a current clock defect;
the index records those corrections.

## F1: project identity and persistent consumption

A separately authorized installation creates a fresh project-specific store only
for an explicitly opted-in repository and host. Installation is outside an attempt;
it cannot manufacture approvals or migrate/reset prior consumption. The immutable
installation record pins a 256-bit project identity, a 128-bit store-instance nonce,
the root filesystem identity, store directory device/inode, repository/configuration
binding and startup-closure digest. These additions require a versioned installation
format; the old128-byte version is insufficient for operational admission.

The fixed derived path is /var/lib/rnr/projects/<64 lowercase project hex>/consumed.
No task-provided path, alternate store, fallback directory or implicit initialization.
Each component is traversed nofollow from a retained trusted root. Project/store
ancestors must be root-owned directories, not group/other writable; the project and
consumed directories are0700. Only supported local persistent ext4 is admitted for
this first WSL release. Actual mount/filesystem identity, directory identities and
a fixed root-owned0400 instance record must match the installation pins. tmpfs,
network filesystems, replaced stores, missing instance records or unknown mount
semantics fail closed. Installation/recovery requires exclusive host maintenance;
no privileged actor may replace/delete store data while attempts are admitted.

A TaskID is exactly16 nonzero bytes, rendered as32 lowercase hex for a single
fixed filename. Admission creates that attempt file O_CREAT|O_EXCL|O_NOFOLLOW,
O_CLOEXEC, mode0600 in the retained consumed directory. Any existing entry rejects,
regardless of file type, size, contents or previous outcome. A partial/corrupt file
is consumed/UNKNOWN, never overwritten, truncated, renamed, removed or resumed.
The new file records a versioned bounded original declaration and invocation
binding, then fsync(file), then fsync(consumed directory). No resource receipt may
be emitted until BOTH successful returns and a fresh original setup check. The
file and directory handles remain held for subsequent intent append/sync operations.

The trusted filesystem durability assumption is explicit: a successful file and
directory fsync preserves that entry/content across supported host failure. Before
both successful returns no resource action is allowed. A crash before either
return can leave a surviving consumed partial record or no entry; neither case
can have a resource effect from that attempt. A completed durable claim remains
consumed even if its receipt/ACK is lost. Unexpected disappearance after recorded
success contradicts the storage assumption: quarantine the store, retain UNKNOWN,
and require offline reconciliation; do not create a replacement store or retry.
This is not protection against privileged deletion, dishonest storage or rollback
of the whole filesystem. Those are excluded operationally, not inferred safe.

Intent records are finite, fixed-schema, monotonically sequenced append-only
frames. Each includes project/store/TaskID/origin binding, operation, exact target
and prior record identity. The producer performs one full bounded write attempt
then fsync, checking original setup/time after every blocking call. A short write,
failed sync, malformed tail or late return fences the attempt; no completion or
retry append. Recovery never interprets an incomplete record as an action grant.
Only a successful sync followed by a fresh budget check allows the one receipt.
The exact byte layout and finite record maximum must be frozen before code.

The original held Main is the sole trusted receipt producer. Keeper authenticates
its exact original child and the finite operation sequence, consumes each receipt
before effects, and NEVER opens/reads/writes/fsyncs persistent storage to verify it.
Producer code, immutable installation and authenticated original lineage establish
that a receipt follows durable sync; receipt data alone is not independent proof.
Keeper can contain without any new storage action. Failed/late I/O cannot renew
T0, erase consumption or delay keeper timing. Recovery is a separate offline
inspection with no old clock adoption, replay, release or automatic cleanup.

## F2: native declaration semantics before any persistence

The actual private launch accepts a single current schema, not every historical
inert fixture format. Native admission must validate the full bounded JSON grammar,
duplicate-key exclusion, closed root keys and relevant primitive types before
claiming a declaration. It must correlate allocation to binary TaskID, the separate outer task wall cutoff and Store.run.deadline predicates, exact asset/execution roots to installation pins,
project/store/configuration binding, exact derived emergency target and protected
ancestor, and quota/controller policy to actual immutable launch context.

The outer task cutoff must be strictly after original wall+60 seconds, no later
than the original captured upper bound; negative stop is min(original90, outer
cutoff). Store.run.deadline is a DISTINCT positive cutoff: later than the fresh
admission wall sample, no later than min(outer cutoff, original wall+44 seconds).
Native and Python must preserve both values without substituting either origin.
The first profile will require the Store deadline to be an integral number of
seconds that converts exactly to signed64 nanoseconds; reject fractional/overflow
representations instead of approximate floating-point comparison. Retain original
payload bytes, and include their full bounded bytes in the authenticated declaration
and durable claim rather than relying on a weak or unimplemented checksum. Keeper
must compare the original origin/identity/bounds and derived target fields before
one-shot cutoff narrowing. No resources before complete declaration validation.

Detailed Store commands/policy/files content checks may remain in the existing
canonical Python decoder only if they cannot change the already-bound identity,
cutoff, targets, quota or startup roots, and still complete before Store/workload.
The existing preparer does have media effects before Python; these must be limited
to the fully declared immutable installation/task binding. The minimal validator
must explicitly enumerate all deferred checks; calling envelope decode a semantic
validation is forbidden. JSON parsing/record bytes are inert data, never authority.
The exact schema/token limits and source trace need review before implementation.

## F5: preexisting protective ancestor, no post90 watcher

The first proposal placed Main under a positive ancestor and relied on freezing
it after failure. Reviewer rejected the incomplete keeper-death fallback and
process-owned invocation lock. The revised direction below is authoritative for
further design: workload ancestor starts frozen, Main preparation leaf is a
sibling, durable latch survives process death, and sole thaw ownership transitions
to observer negative authority before READY. Neither the initial nor revised
proposal is whole F5 acceptance. Exact hierarchy/lifecycle remains OPEN.

Keep both consumed emergency target phases (precreation intent and actual held
acquisition), expected original observer authentication/negative placement, native256,
observer64 and Python prefork53+5+2=60. The original table is a failure coverage
checklist; its held-ancestor entries now refer to the initially frozen workload
ancestor, and preparation-leaf/helper coverage requires the explicit additional
contract below.

| Boundary failure | Required retained state / consequence |
| --- | --- |
| Before durable claim | Exact original child can be killed; no task resource permitted |
| Claim or intent I/O blocked/late | Keeper never waits for disk; original child kill/held ancestor controls; consumed/UNKNOWN |
| Leaf intent accepted, create/readback fails | Consumed intent; no replacement/recreation; held ancestor containment |
| Placement intent accepted, move/ACK lost | Exact child and actual ancestor controls retained; no GO |
| GO intent/GO lost | No resend; exact membership/controls and consumed history retained |
| Emergency phase1 queued, Main dies | Held protective ancestor contains even late target; no Store |
| Phase2 acquired, observer registration fails | Target and ancestor held; no Store; no second observer |
| Observer registered, arm/new connection/placement ACK fails | Expected original observer identity retained; no READY/Store; contain positive branch |
| Observer placed, READY/Store construction fails | Independent observer and keeper retain target controls; no replacement |
| Keeper dies before independently placed observer | Actual launch fallback must contain; remains a qualification blocker until proven |
| Keeper dies after independent observer READY | Actual service lifecycle must preserve observer and its original negative lease |
| Original90 or clock identity/time unknown | No fresh effects or active watcher; retained UNKNOWN/holds; offline recovery only |

This proposal closes no finding on its own. Required next output is independent
challenge of F1 durability/recovery, F2 minimum semantics and F5 containment gaps;
then exact byte/schema/unit contracts and source implementation in dependency order.

## v3 challenge decisions — revised direction, not acceptance

The reviewer accepted the sync-before-effect safety reasoning only under the stated
storage assumption. An absent entry is never proof of an unused TaskID. Pin an
installation epoch to the actual boot ID; boot mismatch or any known unclean epoch
disables admission until explicit offline reconciliation, which bars uncertain IDs
without replay/reset/deletion. Create an exclusive persistent project-wide active
latch from the held Main, synchronize latch and parent before any claim receipt
permits resources. Existing/corrupt/partial latch rejects every subsequent attempt.
Retain the latch on all uncertain outcomes including process death; a flock/pidfd
is only concurrent-operation exclusion, never the durable recovery hold. Precise
clean completion/reconciliation authorization must be frozen before source work.

F2's formerly ambiguous cutoff correlation is corrected above: positive Store44
and negative outer60/90 are distinct. Full phase/effect schema remains OPEN.

For F5, challenge this alternative to adding a new fallback process: initialize
a per-project WORKLOAD ancestor frozen in trusted installation/launch context,
before any task resource exists. Never put the original Main preparer under that
frozen ancestor: Main's singleton positive preparation leaf is a sibling. The
original keeper stays outside both. Every eventual Docker/emergency target is a
descendant of the frozen workload ancestor. Thus late manager creation remains
frozen even if keeper dies before observer registration. Original Main uses its
existing kernel PDEATHSIG; native helper parent-death closure must be proven.
Filesystem/loop/DM/mount objects remain consumed/UNKNOWN, not inferred absent.

Historical proposal (SUPERSEDED by the sole-thaw serialization below; do not
implement READY-before-thaw): Keep workload ancestor frozen through both emergency
target exchanges and the observer registration/arm/new-connection/negative
placement/READY sequence. Extend
the same observer's held controls to the exact workload ancestor BEFORE READY.
Do not thaw until keeper has authenticated that independently placed observer is
armed with the same original clocks and ancestor controls. Thaw is one consumed
intent/effect only, after durable intent and READY; no workload before ACK. After
thaw the surviving observer covers both the emergency target and workload ancestor,
and keeper covers Main's preparation leaf plus that ancestor. Observer cannot be
in Main's positive leaf when counted READY. No extra fallback process is proposed.

Keeper death kills Main via its original PDEATHSIG. Before sole thaw the workload
ancestor remains frozen. Between sole thaw and committed READY, the already
PREPARED exact observer must detect death of its original held keeper pidfd and
enter permanent negative containment; frozen state is NOT assumed in that interval.
After READY the independent observer retains original negative ancestor authority.
Main death during construction before sole thaw leaves no thaw; afterward keeper
and the same observer retain negative coverage. Lost READY/thaw ACK is fenced
with no resend/replacement; held controls and durable latch remain. Kernel effects from already-armed PDEATHSIG do not introduce a new userspace
lease. Timed containment remains original60/90, no effects after expiry/unknown.
Actual unit lifetime must preserve the observer, and every native helper's actual
parent-death/resource path must be mapped before accepting this direction.

This revised direction changes the proposed ancestor coverage: it encloses workload
targets rather than Main's preparation leaf. It needs explicit same-task independent
review against selected143 before any dependent code or host changes. Initial
review saved at the protected review-v3-persistent-contract.md.

### Proposed thaw serialization to challenge

Observer construction yields PREPARED, not READY. Before negative commitment it
may not write workload-ancestor controls while keeper is live. On any own failure
it reports/fences or exits; original keeper monitors its exact registered pidfd
and is the sole ancestor writer. If keeper's exact pidfd reports death, all its
userspace writes have ceased; observer can immediately enter permanent negative
containment without waiting for a packet. This is the only precommit exception.

Keeper consumes one durable thaw intent and performs its sole thaw while it is
the exclusive writer; checks exact registered observer state/pidfd before/after.
It then irreversibly enters NO_MORE_THAW before sending NEGATIVE_COMMIT. No retry,
second thaw or replacement exists on ANY failure path. Observer consumes that
commit, permanently gains negative ancestor authority and sends authenticated
READY bound to the original control objects. Only that READY permits Store and
workload. Stale PREPARED never grants workload. Lost thaw/commit/READY ACK fences
without resend; keeper may contain, never thaw again. An observer that fails
precommit while keeper lives never freezes for keeper to undo. On keeper death,
its pidfd cannot indicate full death before its final syscall completes, so the
observer's post-death containment follows any in-progress thaw. Exact semantics
need source/host verification and independent challenge, not liveness sampling
as permission to thaw after a READY packet.

Manager helper coverage needs a fixed immutable native exec shim (not Python
preexec callbacks). It must know the original positive parent PID before fork,
check parent before/after arming SIGKILL PDEATHSIG, inherit only the held busctl
ELF descriptor plus stdio, validate its finite fixed manager command schema,
then execveat the exact held ELF with no credential transition. Native media
helpers already arm/check PDEATHSIG, but actual helper transitive behavior and
no-credential-change immutable closure still require qualification. This is a
proposal; no helper binary was created or executed.

## Exact next inert prerequisite: installation-v2 data envelope

The next separable source change is DATA decoding only. No reader path, receipt,
persistence, gate, effect or operational admission changes. Keep the legacy128-byte
v1 decoder for inert historical fixtures; a future actual route must explicitly
require v2 after all trust checks. Extending data decoding does not qualify a store.

Version2 is exactly448 bytes, little-endian integers, magic RNRI0002 at0, uint32
version2 at8, reserved zero at12. Offsets16..127 retain the exact v1 runtime-image
record and asset root layout/validation. Additional fields:

| Offset | Bytes | Data |
| --- | --- | --- |
| 128 | 32 | nonzero project identity |
| 160 | 16 | nonzero store-instance nonce |
| 176 | 8 | store directory st_dev (unsigned64 representation) |
| 184 | 8 | nonzero store directory st_ino |
| 192 | 8 | local filesystem statfs f_fsid raw two32 little-endian words, not pathname/mount ID |
| 200 | 36 | canonical lowercase boot UUID, exact hyphens, nonzero UUID |
| 236 | 4 | reserved zero |
| 240 | 32 | nonzero committed owner configuration SHA256 |
| 272 | 32 | nonzero exact private enrollment record SHA256 |
| 304 | 32 | nonzero immutable startup-closure manifest SHA256 |
| 336 | 32 | nonzero execution-generation root |
| 368 | 32 | nonzero exact installed unit/controller-policy manifest SHA256 |
| 400 | 48 | reserved zero |

st_dev and f_fsid may contain zeros as legitimate data; the decoder does not
pretend to authenticate their meaning or prove ext4/durability. Actual installation
must compare every pinned field against held protected inputs/current host and
fail closed on device/inode/filesystem/boot changes. These metadata can change on
reboot; only explicit offline reconciliation/new reviewed installation can repin,
never runtime fallback. Nonzero digests are structural values, not signatures or
proof that their referenced manifests are complete or trusted. Retain separate
version in decoded data. Clear output on every rejection and reject overlapping
raw/output memory before decoding, preserving current decoder behavior.

Required bounded fixture: valid v1/v2; exact bytes/version/magic; truncation and
extra bytes; each mandatory zero identity/digest; zero inode; malformed/uppercase/
zero boot UUID; all reserved regions; image invariants; aliased input/output;
legacy output extension fields zero. No filesystem/native artifact execution.
Independent challenge of this exact envelope precedes its implementation.

### Installation-v2 implemented boundary

Main implemented only the inert448-byte envelope in runtime_stage0_records.{c,h}.
Independent v3 review matched all four source/test hashes and reported no actionable
findings. Existing128-byte reader and actual preparer/main unchanged. RED fixture
failed on absent extension fields; GREEN two compiled inert checks passed1.081s.
An existing fully mocked preparer fixture also compiled under strict GCC13 and
returned0; no protected inputs/native entry/resources were accessed. Broad and
installed verification are recorded separately. This closes only the data-codec
review, never F1/durable identity or actual admission.

## Proposed F2 implementation split and phase/effect matrix

Native media source trace: installation runtime root/salt/geometry select the
fixed runtime media and verity mapping; TaskID selects fixed work names/tags; task
outer cutoff is copied into the launch context. Task payload bytes are copied into
launch.bin. Its policy/commands/paths do not select native helper argv or media
paths: those remain compile-time-fixed. Asset root and execution root must match
installation pins before any persistence/leaf/resource permission. This source
trace is not actual input authentication or successful admission.

| Phase | Fields/pins that must be validated before its effects | Deferred checks |
| --- | --- | --- |
| Held original input reads | Protected fixed ancestry/metadata/retained identity, exact v2 envelope and task framing, original clock | No effects except bounded read/close |
| Declaration | Complete bounded payload grammar/schema; TaskID/allocation; separate positive44/outer60–90; installation asset/execution roots; full original origin; actual immutable launch unit/outer policy; project/store/epoch/config/enrollment pins | Downstream observed facts cannot grant authority here |
| Project latch/consumption | Declaration accepted once; actual protected ext4 store/instance/dev/inode/fsid/boot matched; exact finite byte format and original-budget checks | No task leaf/media/manager/descendant/Store |
| Native leaf placement/GO | Durable exact operation intents; current original keeper/child identities; exact retained leaf controls and actual singleton membership; original setup15 | No renewal; no normal preparer before GO |
| Native media/immutable roots | Retained original input binding; runtime Merkle root/salt/geometry; allocation names; asset/execution roots; fixed helper closure/parent-death containment | Python-specific Store configuration digest/policy fingerprint may be computed later; cannot change prior resource selectors |
| Python seal/manager before observer | Canonical full decoder; exactly seven files and actual content pins; actual asset/execution generations; tool/manager digests and original PID1/bus TCB; actual UnitPath; full exact quota/controller policy; new hierarchy and inherited frozen state | No Store/Docker workload |
| Observer preparation/commit/READY | Exact expected observer registration/arm/new-connection/placement; held target+ancestor identities; original negative lease; exclusive sole thaw/commit ordering; actual service survival | No Store until committed READY |
| Sole Store and workload | Complete run/policy/resource limits/configuration digest; bound real session/rnr_command; full actual Codex profile/original worker membership, immutable executable/dependencies/config/startup closure | No fixture/synthetic path substitutes for actual qualification |

For a small auditable native decoder, propose accepting a strict subset of the
existing canonical version3 payload: all strings must be unescaped printable ASCII,
all numbers canonical nonnegative signed64 integers, including integral seconds
for the Store deadline. No Unicode/escape/float/NaN/constant/negative-number form
is accepted by the native private route. This is a conservative first-release
input restriction, not a second selectable runtime profile. Historical inert Python
fixtures keep their existing full schema behavior. Real model/effort/run IDs and
fixed paths can be generated within this subset without losing the intended use.

Within that subset, enforce exact byte agreement with Python canonical encoding:
no whitespace/trailing bytes, lexically sorted unique object keys, exact separators,
no leading zeros, exact closed nested schemas. Enforce the existing raw65536-byte,
depth12/node2048/string4096-byte bounds; types distinguish strings/integers/lists/
objects, booleans cannot pass as integers. Native output is retained DATA only;
actual origin/installation/current-host correlation stays in the fixed admission
owner, never supplied as a caller-created authority. Differential fixtures compare
accepted/rejected representative bytes against the existing canonical Python decoder.
The broader admission and deferred-check matrix still needs independent challenge;
no parser implementation is authorized by this proposal's wording alone.

### Exact inert launch-declaration decoder contract

Implement one fixed v3 decoder in runtime_stage0_records, with no selected schema,
clock, installation, file or caller-supplied authority. It returns version/allocation,
asset/execution/tool/manager/daemon digest bytes, positive Store deadline nanoseconds,
run allowances, policy allowances, resource limits, quota, seven file digests/sizes
and borrowed model/effort/run/epoch/UnitPath string views. Caller must retain the
original immutable raw payload for every view's lifetime; no reconstructed payload.
No allocation/Store/lookup/clock/effect occurs. Enlarge-output overlap checking
precedes reads/fail-clear; output remains entirely zero on rejection. Successful
output contains DATA only, not actual identity, origin correlation or admission.

All object schemas below are exact, lexically ordered keys (the order shown):

- root: allocation, asset_root, daemon_digest, execution_root, files,
  manager_digest, quota, store, tool_digest, unit_paths, version.
- Store: policy, queue_bound, resources, run, run_id, supervisor_epoch.
- policy: effort, input_bytes, item_text_bytes, model, turn_items.
- resources: reviewer_reserve, runtime_slots, workload_slots.
- run: capacity, commands, deadline, turn_capacity, turns.
- quota: cpu_millis, memory_bytes, output_bytes, pids, scratch_bytes, swap_bytes.
- each file: bytes, content_digest, target.

Strings contain only bytes32..126 excluding quote/backslash, and no escapes.
All digests are exactly64 lowercase hex; allocation32 lowercase hex. Model, effort,
run ID and epoch are nonempty<=256bytes. All numbers are canonical nonnegative
signed64 integers; Store deadline>0 converts to nanoseconds without overflow.
Run/policy/queue/runtime/workload allowances are1..1000000; workload slots equal
run capacity; reviewer reserve is nonnegative and less than runtime slots. Quota
fields positive except swap=0; CPU is divisible by10 and <=INT64_MAX/1000000.
This validates current inert value rules within the conservative numeric subset,
not observed quotas. Installed native leaf/ancestor policy must be checked before
native leaf creation; task runtime quota must be checked before manager mutation.

Files are exactly the seven targets in current sorted _DESTINATIONS order, with
matching exact target strings. Config/catalog size0..2MiB; codex/guardian size1..1GiB.
UnitPath list1..32, unique; exact current normalized absolute ASCII path rules,
<=256bytes, <=16 slash-separated components including leading empty component,
no empty/dot/dotdot component; includes /run/systemd/transient. Raw<=65536,
string<=4096, nested container depth<=12, total value+key nodes<=2048. Use fixed
parser storage<=65536bytes plus bounded recursion/output; no heap. Decode all
integers with checked accumulation before multiplication. Reject all other JSON
primitive forms and extra/trailing bytes. Preserve Python byte canonical order.

Differential checks distinguish agreement with _json syntax/canonical acceptance
from full _decode_launch semantic acceptance under a valid inert original origin.
Native data validation cannot check Store44/original sampled-wall relationship
without that origin: this remains the fixed admission owner's mandatory comparison.
A mismatched root/allocation/current-host declaration can decode as DATA but cannot
be admitted. This is the reviewed separable prerequisite boundary, not F2 closure.

Correction to source trace: native media embeds launch.bin, not launch.bin.

### Inert declaration implementation checkpoint

The recorded decoder contract is implemented in runtime_stage0_records.{c,h};
reviewer v3 independently matched all four source/test hashes and reported no
actionable findings. Five focused compiled/differential checks passed1.048s,
including128 seeded byte mutations. This is a finite sample, not exhaustive parser
proof. Exact snapshot/report at protected review-v3-declaration-{snapshot.json,
acceptance.md}; full-suite1438PASS185.677s/7skips and offline build/two installed consumers/three
strict native builds PASS are recorded in declaration-verification.json. Actual
native artifacts NEVER RUN. Actual
reader/main untouched; complete F2 and all release gates remain OPEN.

## Next supervised-child integration interface to challenge

Current launch owner must remain the only original capture owner. Add a fixed
private supervised-preparation wrapper in launch.c which captures that clock once,
physically forks, then in its child calls the fixed held-input admission routine
and gate protocol before returning to qualification main. No caller callback,
clock getter/importer/phase setter, selected path or descendant helper. Ordinary
preparer stages remain barred until verified placement+GO. Current unsupervised
qualification main must not be invoked as a substitute.

Refactor clock.c physical fork internals behind TWO compile-time-fixed private
wrappers: existing no-GO precursor behavior unchanged, and fixed admission begin.
They share the same one-shot global fork reservation (never both per invocation).
Admission child arms/checks original PDEATHSIG, transfers only execution PID/TID
while retaining original origin/high-water, sends original ARMED once, retains its
original gate4 privately and enters ADMISSION. Return only into the launch owner's
fixed ADMISSION wrapper, never ordinary main/preparation. The negative parent
retains the same exact unreaped child PID/pidfd/gate and original clock.

No raw gate getter or naked GO sender. Fixed declaration, durable-claim/intent and
placement/GO exchanges later validate exact private original-child ownership and
consume each state before any send/effect. The held input reader shares internal
fixed read/recheck steps; it MUST NOT invoke the existing clock-capturing
prepare_inputs or initialstdio scanner while holding gate4. It starts with exact
held inventory, retains the existing original inputs after adding v2 size support,
then validates DATA plus actual trusted binding before declaration/persistence.
Publish INPUTS_HELD only after GO and gate/storage/auth temporary closure plus
fresh retained identity/time checks. Until whole protocol/persistence/lifecycle
contracts are implemented there is no operational route returning success.

The fail-closed held-input part is now implemented and independently accepted
in the linked supervised-input plan. Full declaration/persistence/placement/GO
and operational continuation remain unimplemented and unaccepted.
FD counts remain to be closed for held reader/input/transport/store/control phases;
existing local6/5 fork/initial-scanner peaks alone do not close native256.

## Resumed release execution

The user explicitly authorized the bounded RNR-D00 implementation team after the
extraction audit. Current source/ownership and the first supervised-input vertical
are coordinated in [supervised-input integration](2026-11-19-supervised-input-integration.md).
Reviewer v4's initial independent report is saved under protected
/home/faris/.local/state/agent-runner/release-resume-20261119/review-v4-initial.md.
The accepted direction is reused; exact F1/F2/F5 and provider contracts still need
concrete independent challenge before their dependent implementation. No release
gate closes from the execution plan or the team authorization.

## Successor admission contract freeze — 19 November, revision A

Main resumes from clean4861726 on WSL Ubuntu24.04, with implementation in Main
and at most one fresh reviewer. RNR-D00 is the retained local assignment; no issue
URL or numeric Main/IssueLead counter is invented. Predecessors released ownership
and are historical only. This section is a proposal for independent challenge,
not permission to run the native artifact. Existing fail-closed wrapper stays.

The next outcome is ONE coupled admission boundary: authenticated declaration,
durable claim and enumerated intents, held hierarchy/placement and final GO.
Implementation may proceed in dependency order, but no intermediate codec, store
or protocol component can grant declaration authority or positive continuation.
Do not replace the accepted fixed fork owner, clocks or initially frozen ancestor.
Main owns all source, tests, docs, Git and host operations. Reviewer is read-only
until explicitly assigned bounded mocked QA. No account or physical qualification.

### F1 exact proposed inventory

All integers below are unsigned little endian; signed clock values must first
validate positive signed64. Reserved bytes are zero. No C struct wire layout.
Use full original bytes, not a newly selected hash dependency. Project directory
is /var/lib/rnr/projects/<project64>; consumed is its child; active is a fixed
project-directory entry. Traverse every component nofollow, retain identities,
reject writable/non-root ancestry and unexpected mounts. Project and consumed
are0700. Require persistent ext4, matched installation dev/inode/fsid/boot and a
read-only128-byte instance record (0400, root:root, nlink1). Instance framing:
magic RNRINST1 at0, version1 u32 at8, zero12..15, project32 at16, instance16 at48,
consumed dev/ino u64 at64/72, fsid two u32 at80, boot UUID36 at88, zero124..127.
The installation's store dev/ino refer to consumed; filesystem ID refers to that
same held directory. Reject any inconsistent meaning rather than repin silently.
Instance metadata/content must be unchanged before and after reading and before
any latch/claim creation. No runtime creation of missing directories/instance.

Proposed durable binding is a fixed256-byte header plus original installation448,
original task framing (65..65600) and original trusted launch-policy bytes (bounded
separately; exact F2 schema must be accepted before source integration). Header:
magic RNRBIND1 at0, version1 u32 at8, total bytes u32 at12; project32 at16;
instance16 at48; task16 at64; original keeper PID/start u64 at80/88; original Main
PID/start u64 at96/104; original T0 boot/wall u64 at112/120; original setup/positive/
trigger/negative-stop boot cutoffs u64 at128/136/144/152; outer wall cutoff u64 at160;
original time namespace dev/ino u64 at168/176; boot UUID36 at184; installation/task/
policy lengths u32 at220/224/228; zero232..255. Explicitly retain original sampled
origins and exact full declaration, including separate Store44 and outer60–90.
No digest alone authenticates a supplied policy. Wire length caps and offsets
must be checked without overflow before copying. Claim and latch both contain
this exact binding, so a surviving latch identifies even a missing/torn claim.

Order: fully validate declaration and obtain keeper declaration ACK FIRST. Then
create active O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC mode0600; consume create
before syscall; retain UNKNOWN on every uncertain return. Validate created object
root:root regular0600 nlink1, perform one bounded write, fsync(active), fsync(project),
with the original SETUP15 admission predicate before/after every metadata/I/O
syscall and before each next syscall, packet or effect. A late return fences
positive work; it never switches to the Store44 predicate. Then create consumed/task32
with the same flags/mode; one binding write, fsync(claim), fsync(consumed). Only after
all four successful fsyncs, unchanged named/held identities and fresh setup check
may Main emit CLAIM_SYNCED. Any existing active or task entry rejects regardless
of type/content. Short write/EINTR/error/late result never retries, truncates,
replaces, appends repair, removes latch or emits receipt. Keeper never touches disk.
FD closes are once-only and do not remove consumption. No receipt on lost ACK.

Intent frames follow the binding in the held claim: fixed256 bytes, at most64
frames (maximum16384 append bytes), no repair/truncation/retry. Proposed layout:
magic RNRINT01 at0; version1 u32 at8; operation u32 at12; sequence u64 at16;
previous sequence u64 at24 (zero for first); project32 at32; instance16 at64;
task16 at80; exact original keeper/Main PID and start values u64 at96..127;
original T0 boot/wall u64 at128/136; target kind u32 at144; target role u32 at148;
held target dev/ino/mount u64 at152/160/168; reserved176..255 zero. Target kind and
role are closed constants, never paths. Before acquisition, expected targets are
fixed derived hierarchy names pinned in the complete binding; metadata fields
must be zero. After acquisition, exact held object identities must be nonzero and
match keeper-held controls. Every frame has a fixed predecessor/opcode transition,
not caller-selected sequence. Reserve append before one pwrite at the exact prior
length; require full write, fsync(claim), exact new size and fresh budget before
receipt. No future frame or receipt can excuse an unknown preceding operation.

Latch retirement is NEVER an attempt cleanup. No online unlink/rename API is
released by this boundary. Retain active even after successful attempt completion
until the eventual independent negative actor has finished and all late manager
operations and resource holdings have been reconciled. The sole future retirement
route is exclusive offline maintenance: disable admission, retain all records,
verify original installation/store and active binding, inventory every consumed
intent and actual target/helper/manager job, prove no live/queued/recreatable
resource remains, quarantine every uncertain task ID durably, then retire the
exact active entry and sync project before repinning a new reviewed epoch.
Missing/partial/corrupt active, changed boot/store, inability to prove closure or
any incomplete reconciliation forbids retirement. This route needs an exact
finite evidence/authorization format and independent review before implementation;
no general administrator cleanup command is implied. Absent records prove nothing.

### F2 and F5 coupled gates still to freeze

The new binding cannot be populated by arbitrary decoded values: the fixed
original owner must read/compare the complete installed unit/controller manifest,
owner config/enrollment/startup-closure bytes, current unit/cgroup/boot/store and
original lineage before declaration. Existing installation digests are only DATA.
The trusted policy needs exact paths/byte grammar, file size caps/digests, kernel/
manager observations and expected launch identity; compare actual values rather
than echoing nonzero pins. The keeper must authenticate a finite full declaration
from its exact original fork child, preserve original identity/high-water and
narrow cutoff once. No SO_PEERCRED learned from inherited socketpair substitutes
for SCM_CREDENTIALS/current original process identity validation.

Enumerated durable effects must include positive preparation-leaf creation,
negative observer-leaf creation/acquisition, Main placement and GO, both emergency
target phases, expected observer registration/arm/new connection/negative placement,
sole thaw and irreversible NO_MORE_THAW/negative commit/READY. Workload ancestor
starts frozen before the attempt; Main preparation leaf is a sibling; keeper
remains outside both. Actual unit must preserve negative observer survival, and
all helper descendants need actual immutable parent-death closure. Exact cgroup
paths/control identity checks, protocol packet schemas/finite bounds, every
operation's previous/next state and whole normal/failure FD peaks must be frozen
and challenged before any dependent positive code. Until then the original
wrapper always drains/abandons and exits125; no persistence is called from it.

### Implementation and verification order

- [ ] Independent review of exact F1 inventory and unresolved F2/F5 contracts;
      settle findings before affected source. Save report outside Git.
- [ ] Freeze remaining trusted policy/protocol/hierarchy/helper/latch-retirement
      contracts and exact finite operation inventory in this same document.
- [ ] Add meaningful red fixtures, then implement Main-owned native persistence,
      trusted comparisons and fixed keeper exchanges in dependency order.
- [ ] Integrate actual modules with mocked syscall boundaries, test each blocked/
      short/late/failure/death/ACK-loss/collision/replacement case and no GO leak.
- [ ] Independent snapshot review/QA, strict actual link without execution,
      package closure and applicable broader regression checks.
- [ ] Only the fully reviewed coupled boundary may change the fail-closed wrapper;
      whole release/private entry/provider/profile/closure/qualification gates remain.


### Revision B: bounded persistence preparation, no new admission authority

Independent reviewer v5 requires four corrections before coupled integration:
full opcode/operand/ACK inventory; actual trusted-policy schema and authenticated
finite declaration transport; unambiguous SETUP15 checks; sole-thaw-before-commit
ordering. First and second remain OPEN. The setup wording is corrected above;
the historical READY-before-thaw proposal is explicitly superseded. Canonical
order is PREPARED -> sole durable thaw intent/sole thaw -> NO_MORE_THAW ->
NEGATIVE_COMMIT -> committed READY -> Store. Only exact keeper death permits
observer precommit negative takeover. No positive implementation is released.

Proceed with the substantive F1 persistence preparation permitted by v5, as a
private module not called by the existing fail-closed wrapper. This is not a
codec milestone and supplies no protocol receipt or resource authority. Exact
private API takes only the already-frozen original binding byte buffer, its
length and an exclusive error object; decode installation448 from that buffer; no caller path, clock,
callback, FD, opcode, reset, retirement or effect selector. Installation/raw
binding authentication belongs to the fixed future F2 caller and remains OPEN.
Binding bytes remain immutable throughout acquisition, do not overlap the exclusive
error output (reject overlap before clearing), and are not borrowed after return.
The module always calls the fixed launch admission check before/after each
syscall, including metadata and cleanup-independent comparisons. It cannot
capture/import/extend a clock. A standalone caller without the existing original
held launch owner fails before any storage access. No Main/keeper packet is sent.

Implementation file runtime_stage0_persistence.{c,h}, private-qualification only.
Use one atomic reservation and one process/thread owner. NEW -> ACQUIRING -> HELD
or terminal FENCED; rejection/reentry can never restore state. Abandon only the
original quiescent owner, invalidate FD slots before once-close, never unlink,
rename, repair, retry or claim resource absence. Always preserve first error,
operation-entered/returned results, latch/claim creation disposition, and cleanup
errors. A failed acquisition drains its own FDs and retains UNKNOWN data; no losing
or reentrant caller drains another in-progress operation. Checked close failures
remain terminal; cleanup may close owned FDs after setup expiry without storage
mutation. No keeper storage syscall exists.

Freeze the bounded byte contract for this preparation independently of unfinished
F2 policy semantics: exact header256, installation448, task65..65600, policy1..65536;
maximum131840 bytes. Validate magic/version/total/lengths/reserved bytes, exact
installation448 against decoded installation-v2 and exact task framing/v3 DATA,
project/instance/task/boot correlation before traversal. Persist the complete
supplied immutable buffer without reconstructing it. These checks are structural
and equality checks, never authentication of policy or original origin. Header
PID/start/origin/cutoff fields must be positive signed64; exact original lineage/
clock/actual policy comparison is explicitly the unreleased future caller's gate.
No intent-append API until the complete operation inventory is frozen. This
preparation creates/synchronizes the exact latch and initial claim only.

Instance is exactly project/instance. Hold seven ancestry directories: /, var,
lib, rnr, projects, project64, consumed; validate root:root protected directories,
project/consumed0700. Reject mount changes via per-role statx MNT_ID, before/after
held/named device/inode/mode/owner checks, and consumed ext4/dev/ino/fsid matches. Project and consumed must share the
same supported writable ext4 device, fsid and mount ID: a mount boundary between
these two is rejected, so active and claim share the pinned durable filesystem.
Read instance once with bounded pread128 plus EOF1; verify root:root0400 regular
nlink1, exact format/values, stable timestamps/size/names and same filesystem as
consumed. Read-only or unsupported filesystem rejects. All ancestors remain held
through claim sync; external privileged mutation/rollback remains excluded.
New active/claim must be regular0600 root:root nlink1, exact zero initial size,
same device/mount as their respective retained parent. One full pwrite at0,
one fsync(file), one fsync(parent), exact post-write size/identity and original
SETUP15 checks; no write retries even EINTR. Recheck all original paths/instance
and both created files before returning HELD. HELD is storage-only result, never
permission to emit CLAIM_SYNCED absent F2/F5. Both files remain on every outcome.

Role peak for this preparation: existing held input5 + stdio3 + gate1 =9;
seven directory FDs + instance + latch + claim =10; one named-recheck temporary
+ one launch-clock identity temporary =2; total21 below native256. Count holds
on failure too; no descriptor alias/stdio overwrite is accepted. This does not
close later protocol/hierarchy/native/helper or Python/observer budgets.

Focused fixture: wholly mocked syscalls and actual persistence module; exact
success write/sync ordering; collision at each create; wrong fs/boot/instance/
metadata/mount/named identity; missing instance; short/failed/late writes and syncs;
clock failure before/after every operation; reentry/foreign/duplicate owner;
no subsequent write/receipt or deletion on failure; once-only descriptor cleanup.
The fixture must audit host-effect imports and never touch a real store or fork.
Strict compile-only actual source and installed-resource checks follow. Full
coupled integration remains the next outcome; do not relabel this preparation
as F1 closure, release readiness or activation. Active persists after success;
no second attempt until separately reviewed offline reconciliation/retirement.


### Revision B implemented checkpoint

Main implemented only runtime_stage0_persistence.{c,h}, a private storage owner
with no caller in the launch/preparer/qualification route. Independently reviewed
snapshot and mocked QA are at protected release-admission-20261119/reviewer-v5/;
Main preserves source-snapshot.json and review-v5-{contract,source}.md alongside.
RED fixture first failed on the absent header, then actual source passed the
fully mocked failure matrix. Reviewer v5 matched all six frozen hashes and passed
one focused fixture (1.153s), strict -Wpedantic compile and full actual private
source link without execution. Optional fixture-import hardening was strengthened
to an exact allowed-import set, independently rechecked (1.243s, driver SHA256
b27b72e890cc25b3555ff9ad7dad3e8b21ea942646bf8687b1f98877751e9356).
Four Main native drivers passed10.084s. Broader verification recorded in handoff.
No physical filesystem durability, real-store invocation, GO, recovery or whole
release acceptance is claimed. New packaged native resource count is15.

Manual trace before checks: fixed original launch check first (no new capture),
then bounded binding DATA/alias validation; nofollow root/var/lib/rnr/projects/
project/consumed retained traversal; same writable ext4/dev/fsid/mount and exact
instance record; one active creation/write/file-sync/project-sync; same one-shot
claim sequence with consumed sync; held/named originals and files rechecked.
Every operation has before/after setup15 checks. Blocked/late/error/reentry fences
positive progress and drains only original owned FDs; consumption is never removed.
Storage HELD does not authorize the next native or keeper stage. Source has no
keeper persistence path, packet/receipt sender, intent append, resource mutation,
retirement or route to ordinary preparation. Test syscall substitutes are not
actual durability qualification; exact allowed imports are audited before fixture
execution, including fortified syscall aliases through rejection of unknown imports.

Next coupled design work: F2 must choose exact protected policy bytes and trusted
unit/controller/enrollment/config/closure comparison sources BEFORE declaration.
F5 must update all existing root-target assumptions consistently: current
slice_recipe/verify_recipe_snapshot, bootstrap _target_metadata, provisioner target
acquisition and frozen runtime all bind /sys/fs/cgroup/rnr<TaskID>.slice at the root.
Putting a new frozen ancestor in only the keeper would leave manager-created targets
outside it. Full parent/Slice/ControlGroup/late-job attribution and observer-sibling
placement must be frozen together; no source shortcut is authorized by the storage
checkpoint. Preserve both emergency target phases and exact original expected
observer/new-connection authentication. Full intent opcodes remain unfrozen.

## F2 direct-manager transport freeze candidate C — not released for source

Reviewer v5 challenged the post-T0 actual unit/controller comparison requirement.
A direct root/PID1 connection at /run/systemd/private is supported by systemd255's
own bus-util.c. Both of its fallback-to-system-bus branches are forbidden here.
No pre-T0 task work, new launcher, broker route or helper process is introduced.
However, unmodified public sd-bus API bracketing is REJECTED for this boundary:
start/process may perform several internal I/O calls after a late return without
an intervening original setup check, and typed16KiB rejection after allocation
does not impose a16KiB allocation bound. Patching all library I/O, authentication,
allocation and queues is larger than a fixed read-only peer framer. This decision
does not relax selected143 or release any general-purpose D-Bus implementation.
Protected review-v5-f2-f5.md and native-source-research/ retain source evidence;
follow-up transport verdict is preserved alongside. Downloaded matching development
headers were extracted privately only; no system package or library was installed
or executed, and no libsystemd dependency has been adopted into runner source.

Candidate C is a CLOSED native wire implementation inside the eventual fixed F2
policy owner, with no caller-selected endpoint, method/property, schema, FD,
callback, clock or retry. No standalone codec or operational acceptance milestone.
Source remains blocked until the whole property/policy/lineage/control comparison
matrix below is complete and independently accepted. Reviewer v5 conditionally
accepted this transport direction with the corrections recorded below; that is
not full F2/F5 source release.

Fixed transport and authentication:

- Original held Main only, fixed setup15 check before/after each open/stat/read/
  connect/poll/getsockopt/sendmsg/recvmsg boundary. Keeper never performs a blocking
  manager/library call; it continues original negative polling while Main works.
- Traverse /, run, systemd nofollow from retained genuine host root; protected
  root:root ancestry, socket identity and root PID1 peer must be checked before
  negotiation. Retain actual original PID1 pidfd/start/executable/boot/namespaces;
  SO_PEERCRED must be PID1/root:root on the SAME connected socket and rechecked
  around exchanges. Disconnect/reexec/changed identity fences without replacement.
- One AF_UNIX SOCK_STREAM NONBLOCK/CLOEXEC socket; one fixed connect attempt and
  bounded completion observation, no alternative address or environment helper.
  Any connection uncertainty forbids authentication and later reads/effects.
- Root EXTERNAL transcript only: send exactly NUL + AUTH EXTERNAL 30 + CRLF once;
  accept only OK + space +32lowerhex GUID + CRLF (37bytes), then BEGIN + CRLF
  once (7bytes). No challenge/DATA/REJECTED alternative, CANCEL, Hello, registration,
  FD negotiation or service activation. Each send must return its full size;
  short/error/EINTR fences, with no remainder send/resend/reconnect. All sends
  use MSG_NOSIGNAL; no signal-disposition assumption substitutes for it.
- Authentication receive uses fixed37-byte storage and forward-only accumulation;
  at most37positive fragments and128bounded readiness polls. Stream fragmentation
  is not logical replay. Each receive requests exactly the remaining transcript
  length; no overread or general input queue. EOF/error/EINTR and extra/premature
  bytes WHEN OBSERVED fence, with no dispatch/adoption. A37-byte receive does not
  prove no additional bytes remain queued. The first binary header rejects an
  observed trailing auth line; there is no speculative unbounded drain. Fixed
  fresh-setup checks never renew the origin.

Binary exchange and parser limits:

- Exactly one outstanding read-only request. First Manager.GetUnitByPID(u original
  keeper PID) binds its actual original launch unit; reply signature o must equal
  the canonical project-specific installed unit object path. Then only the frozen
  Properties.Get(ss interface/property) inventory is allowed. Object paths are
  derived by D-Bus unit-name byte escaping, not merely replacing the final dot.
- D-Bus protocol1, little-endian, method calls with NO_AUTO_START and without
  interactive-authorization. Positive serials1..512 (Candidate D inventory supersedes128), consume each operation before
  its one complete sendmsg. No retry on unknown send/reply; no mutation method,
  introspection, signal subscription or arbitrary object/method name.
- Receive fixed16-byte header FIRST, then validate body/header-array lengths and
  checked eight-byte padding before receiving any variable bytes. Header fields
  <=1024, body<=16384, complete message<=17424. All additions/alignment are checked
  against those caps and fixed buffers. Reject unsupported endianness/version/
  type/flags (method-return requires systemd255 NO_REPLY_EXPECTED=1 only),
  zero serial, length overflow, duplicate header fields, invalid
  terminators/signatures/padding and nonzero UNIX_FDS. Accept only exact correlated
  method-return type2 and reply serial; method-error, signal, unsolicited or
  wrong-phase messages fence rather than being dispatched.
- Fixed typed reply forms only: o for unit lookup; v containing the independently
  frozen property's exact s/b/u/t/as/ay/(uo)/a(sasbttttuii) type. Bound strings,
  arrays, variants and nesting from their schema BEFORE copying/iterating. Closed
  types, canonical boolean0/1, exact array ends and no trailing bytes. No generic
  signature interpreter, recursive user-selected schema or heap allocation.
- At most512positive recv fragments per binary reply,4096total transport receive
  operations and4096readiness polls per attempt; each wait<=1ms and original
  setup checks surround it. EINTR/EOF/timeout/protocol error fences. A bounded
  incomplete stream only advances the current offset, never starts another call.
- Freeze and read back SO_PASSCRED=0 and SO_PASSSEC=0 on the original socket;
  ancillary credentials/security labels are never authority. SO_PEERCRED remains
  mandatory. Receive with msg_control=NULL/msg_controllen=0, rejecting observed
  MSG_CTRUNC/TRUNC before another protocol step. Linux automatically closes
  excess/absent-buffer SCM_RIGHTS (unix(7)); no received FD becomes caller-owned.
  This does NOT prove the sender supplied no credentials: disabled options can
  suppress their delivery. The protected sacrificial socket test passed1/2/253
  rights on kernel6.18.58.1 with unchanged original FD inventory; reviewer v5
  reviewed, but did not rerun, that result. It is supporting kernel evidence,
  not qualification of future native receive code or a PID1 exchange. All
  normal/failure FD peaks count, including protocol rejection.

Remaining complete F2 policy decisions (source still blocked):

1. Exact protected policy/config/enrollment/startup bytes, section size caps,
   original hash comparisons and actual immutable dependencies, with no nonzero
   digest echo substituting for referenced trusted bytes. If policy closure exceeds
   storage preparation's65536-byte policy cap, revise/version the uninvoked binding
   explicitly; do not truncate or silently claim the current cap covers it.
2. Full per-property table, expected signatures/values, actual launch-unit lookup,
   PID/start/ns/original-clock correlations, retained control identities, kernel
   controller/limit/membership comparison and observation lifetime. Compare runtime
   image root to actual execution-generation root; duplicated pins need correlation.
3. Two DISTINCT project branches: unfrozen control rnrc<Project64>.slice with
   launch service rnrc<Project64>.service/keeper and later prep/negative leaves;
   frozen workload rnrw<Project64>.slice with transient
   rnrw<Project64>-<Task32>.slice. Exact full paths, root caps and ownership remain
   to freeze. Service Slice must NEVER refer to the frozen workload branch.
4. Candidate service Type=exec/ExitType=cgroup/Restart=no/KillMode=process/
   SendSIGKILL=no/OOMPolicy=continue/MemoryOOMGroup=false/DelegateSubgroup=keeper,
   no auxiliary Exec phases, no watchdog/runtime/failure/dependency stop trigger
   that can invalidate observer survival. Effective readback and actual lifecycle
   qualification mandatory; ExitType=cgroup is direction, not physical acceptance.
5. Complete fixed opcode/operand/result/ACK table, same original expected observer,
   both emergency phases, sole thaw/negative commitment and offline retirement.
   Native leaves need core controls plus inherited caps; no per-attempt controller
   enabling fallback. Workload-parent enabled controllers are installation-owned.

Primary wire reference: https://dbus.freedesktop.org/doc/dbus-specification.html
(v0.43), and systemd255 sources already retained privately. Parser risk requires
malformed/duplicate/truncated/fragmented/oversized/ancillary/late fixtures against
independently constructed wire expectations plus actual-module integration. No
live connection/native artifact execution or whole release acceptance follows.

### Candidate C reply framing corrections after v5 challenge

These are proposed closed wire rules, not a general D-Bus compatibility promise.
A direct peer reply has REQUIRED fields5(REPLY_SERIAL, variant u) and8(SIGNATURE,
variant g), exactly once each, in either order. The signature is exactly o for
GetUnitByPID, otherwise v. Fields1/2/3/4/6/7/9 and unknown codes are rejected.
In particular, sender/destination are absent: calls omit destination/sender on this
unregistered direct connection. systemd255 message_new_reply adds destination
only when the call has sender; no bus-broker identity claim is accepted. Actual
selected-manager reply compatibility still needs physical qualification; unexpected
optional fields fence rather than broadening the contract at runtime.

Offsets/alignment are relative to byte0 of the WHOLE message. Each header entry
starts on its next eight-byte boundary and contains one code byte, exact variant
signature (length byte01, one ASCII type byte, NUL), alignment for that type
and its value. Field5 begins05 01 75 00; field8 begins08 01 67 00.
Only required minimal padding is allowed; every padding byte must be zero. Header
array size counts entry bytes/padding between entries, excludes the16-byte fixed
header and final body-alignment padding. Body starts at align8(16+header_size).
No trailing header padding may disguise another entry; no trailing body bytes.
Binary recvmsg requests exactly16-header_received, then exactly the remaining
validated header/body length; never a full-capacity speculative read. Each positive
read advances only that phase's offset. A remaining-byte request cannot establish
absence of further queued messages: any subsequently observed unsolicited byte
fences and is never adopted as another logical reply.

All strings are a little-endian u32 BYTE length, exact bytes and one NUL; no
embedded NUL. Property strings in the first fixed profile use printable ASCII
0x20..0x7e only; this is a valid strict UTF8 subset, not arbitrary UTF8 conversion.
Object paths use ASCII / or /-separated nonempty [A-Za-z0-9_]+ components, no
trailing / except root, at most255bytes; expected equality further narrows them.
Signature values use one-byte length, exact fixed signature and NUL, no generic
signature grammar. Array byte length excludes its own length and element-alignment
padding; empty arrays still perform required element alignment. End offset must
match exactly after at most the property's frozen element count. Booleans are
u32exact0/1. Variant alignment is relative to the whole message, not its payload.
Scalar/array/struct schemas must be derived from the final property table before
code. No unsupported signed-i decoder or new composite is implied by this draft.

Readiness is bounded progress observation only: each recvmsg gets one attempt;
EAGAIN/EWOULDBLOCK consumes one original-budget poll<=1ms before another receive
of the same remaining bytes. Every receive AND poll consumes its attempt-global
counter, with before/after original setup checks; poll timeout, EINTR, EOF, HUP,
ERR or NVAL fences. No polling after an uncertain send. NONBLOCK connect either
succeeds or yields EINPROGRESS followed by one bounded POLLOUT observation and
SO_ERROR=0; every other result fences. Request sendmsg gets ONE syscall; EAGAIN
also fences. Authentication uses the same bounded receive rule and its stricter
37-positive-fragment/128-poll ceilings. No counter resets per wait or reconnect.

### F2/F5 effective-unit inventory candidate D — source still blocked

Same direct PID1 connection, exact original keeper/Main lineage and original15.
This candidate closes the property NAMES, INTERFACES and type choice for challenge;
native policy acceptance, unit
renderer and normal/failure FD inventory must still be completed. It cannot be
implemented as a permissive optional-property probe. Missing/error/unsupported
property fences. No property is selected by task data or a downloaded manifest.

The fixed objects are launch service rnrc<Project64>.service, control slice
rnrc<Project64>.slice, frozen workload slice rnrw<Project64>.slice and the
installation-established empty demand anchor rnrw<Project64>-anchor.slice. Unit names
are derived from the authenticated installation project, never caller strings.
GetUnitByPID(original keeper PID) must identify exactly that service object; the
other three object paths are fixed derivations and actual identity/state/cgroup
comparisons are mandatory. Actual service MainPID must be original keeper, not
Main child or a replacement process. InvocationID is retained as16actual bytes (reject an all-zero ID, not individual
zero bytes),
not supplied as authority by an environment variable. Original PID/start/held
pidfd/proc/executable/namespace checks remain separate from these manager facts.

| Interface/objects | Exact property inventory | Expected rule / finite type |
| --- | --- | --- |
| .Manager, manager | UnitPath | as<=32, each absolute canonical path<=248bytes; EXACT ORDER because lookup precedence matters; must equal both protected policy and task unit_paths |
| .Unit, all4 | Id, Names | s exact derived unit; as exactly1same name, no aliases |
| .Unit, all4 | LoadState, ActiveState, SubState | s loaded/active; running for service, active for slices |
| .Unit, all4 | FragmentPath, SourcePath, DropInPaths | s exact /etc/systemd/system/unit, s empty, as empty; separately retain/hash actual fragment and inventory overlays/search paths |
| .Unit, all4 | NeedDaemonReload, Transient, DefaultDependencies, RefuseManualStart, RefuseManualStop, IgnoreOnIsolate, StopWhenUnneeded | b respectively0/0/0/0/1/1/0 |
| .Unit, all4 | CollectMode, InvocationID, Job | s inactive; ay exactly16actual bytes with all-zero ID rejected; (uo) exactly0 and / |
| .Unit, all4 | Requires, Requisite, BindsTo, PartOf, ConsistsOf, Conflicts, ConflictedBy, Before, After, OnFailure, OnSuccess, PropagatesStopTo, StopPropagatedFrom, Triggers, TriggeredBy, RequiresMountsFor, Upholds, OnFailureOf, OnSuccessOf | as exact closed expected dependencies; automatic parent Requires/After and inverse edges must be accounted for, not assumed absent; all additional stop/failure/trigger/maintainer edges prohibited |
| .Unit, all4 | JobTimeoutUSec, JobRunningTimeoutUSec | t UINT64_MAX; no queued job at admission |
| .Unit, all4 | JobTimeoutAction, FailureAction, SuccessAction, StartLimitAction | s none |
| .Service, service | Type, ExitType, Restart, RestartMode, OOMPolicy, NotifyAccess, PIDFile | s exec/cgroup/no/normal/continue/none/empty |
| .Service, service | RuntimeMaxUSec, RuntimeRandomizedExtraUSec, WatchdogUSec | t UINT64_MAX/0/0 |
| .Service, service | RemainAfterExit, MainPID, ControlPID, NRestarts, FileDescriptorStoreMax, NFileDescriptorStore | b0; u original keeper/0/0/0/0 |
| .Service, service | TimeoutStartFailureMode, TimeoutStopFailureMode | s terminate/terminate; service already running with no pending control/start job |
| .Service, service | RestartForceExitStatus | (aiai), both arrays empty; Restart=no alone is insufficient |
| .Service, service | ExecStartEx | a(sasasttttuii), exactly1command, exact installed static native ELF path, argv exactly1same path, flags array empty; running command PID equals original keeper, end times/status fields zero |
| .Service, service | ExecConditionEx, ExecStartPreEx, ExecStartPostEx, ExecReloadEx, ExecStopEx, ExecStopPostEx | same command-array type, exactly empty; do not omit ExecCondition or accept legacy flag-losing ExecStart |
| .Service, service | User, Group, DynamicUser, RootDirectory, RootImage, WorkingDirectory | s root/root; b0; s empty/empty/empty (WorkingDirectory unset; actual original cwd must be host root) |
| .Service, service | StandardInput, StandardOutput, StandardError, PAMName, BusName | s null/null/null/empty/empty; exclude journald socket and PAM/activation helpers; actual0..2 inventory still mandatory |
| .Service, service | Environment, EnvironmentFiles, PassEnvironment, UnsetEnvironment | Environment/PassEnvironment/UnsetEnvironment as empty; EnvironmentFiles a(sb) empty; manager-injected environment is NOT proven absent by Environment alone; static entry must not consume loader/config/auth environment and all later exec environments remain fixed |
| .Service, service | LimitNOFILE, LimitNOFILESoft, KillMode, SendSIGKILL, SendSIGHUP | t256/256; s process; b0/0 |
| .Service or .Slice, respective objects | Slice, ControlGroup, ControlGroupId | s exact parent unit/canonical kernel path; t actual cgroup ID correlated with retained kernel metadata, never substitute for it |
| .Service or .Slice, respective objects | Delegate, DelegateControllers, DelegateSubgroup | service b1/as exact cpu,memory,pids/s keeper; slices b0/as empty/s empty, subject to actual selected-manager support; a slice is not a delegated service |
| .Service or .Slice, respective objects | CPUQuotaPerSecUSec, CPUQuotaPeriodUSec, MemoryMax, MemorySwapMax, TasksMax | t exact finite per-project installation policy; swap0; actual kernel values and inherited ancestors separately checked; no invented historical cap |
| .Service or .Slice, respective objects | DisableControllers | as empty; no inherited cpu/memory/pids exclusion |
| .Service or .Slice, respective objects | ManagedOOMSwap, ManagedOOMMemoryPressure | s auto/auto; no oomd action is assumed disabled merely from OOMPolicy |

Compare dependency/name arrays as exact bounded SETS, rejecting duplicate and
unexpected members without runtime sorting. DelegateControllers must match the
fixed controller-enumeration order cpu,memory,pids. Singletons/empty arrays still
require exact counts. Array wire order is not a new dependency identity.

The .Unit interface gets generic unit properties ONLY. Actual v255 dbus.c481–497
registers the unit-cgroup/cgroup vtables under .Service and .Slice, and exec/kill
under .Service. Calling .Unit for ControlGroup/Slice/limits would be wrong despite
the internal name bus_unit_cgroup_vtable. MemoryOOMGroup is NOT exported by v255;
read actual memory.oom.group=0 at relevant kernel ancestors/leaves. Inspect
manager-controlled oomd/dependency behavior and parent lifetime separately.

Wire schema ceilings for this table: s<=512bytes (exact equality still required),
as<=32elements each<=255bytes and<=8192encoded bytes; ay exactly16 for InvocationID;
(uo) object path<=255; ExecStartEx command path<=512/argv1<=512/flags0/commandcount1;
auxiliary command arrays and (aiai)/a(sb) are EMPTY ONLY. Explicitly decode the two
signed32status words in ExecStartEx and require0; never permit declaration signed64
rules to reject legitimate t infinity. All arrays enforce declared byte ends,
alignment and exact trailing-byte exhaustion. No generic composite decoder.
The largest positive expected reply must fit the16KiB body cap; validate that from
the finalized expected arrays, not only from per-element caps. In particular an
as array may not combine all individually permitted maximal strings if encoding
would exceed its8192-byte cap. Unrecognized signatures/property replies reject.

The final draft table contains275Properties.Get calls per snapshot: manager1,
service103, control57, workload57 and anchor57, with no duplicate object/interface/property
triples (protected candidate-d-flat-inventory.json). The first unit lookup adds1.
The draft128serial cap is INSUFFICIENT and superseded by512totalserials, no resets.
Immediately before durable claim, repeat GetUnitByPID and .Unit Id/LoadState/
ActiveState/SubState/InvocationID/Job on all4objects, .Service MainPID/ControlPID,
type-specific Slice/ControlGroup/ControlGroupId on all4objects, and Manager.UnitPath:
40additional requests,316total including first lookup/snapshot. Every reply must match retained
originals and final expected state. Recheck held kernel/path/clock observations
as well; no new root/pidfd/object substitutes. This is finite arithmetic, not
selected-manager compatibility or an atomic manager snapshot. Trusted exclusive
installation/manager maintenance covers the entire attempt, including persistence.
Unexpected queued job/autonomous action still fences; no logical retry/new pass.

Fixed initial dependency arrays, now including the anchor:

| Unit | Requires and After (each exact singleton) | Before | All other enumerated dependency arrays |
| --- | --- | --- | --- |
| launch service | control slice | empty | empty |
| control slice | -.slice | launch service | empty |
| workload slice | -.slice | anchor slice | empty |
| anchor slice | workload slice | empty | empty |

This derives from unit_add_slice_dependencies in retained systemd-v255-unit.c
(lines1516–1535 in that downloaded file; provenance pins its bytes), including
implicit parent Requires/After and inverse Before edges. Web-rendered line numbers
may differ; function plus retained hash is the evidence locator. WorkingDirectory, RootDirectory/RootImage, directory-creation directives,
RequiresMountsFor, journal stdio, sockets, PAM, notify/bus activation and all explicit
dependencies are absent. Nondefault root mount/namespace dependencies reject rather
than silently extending the matrix. Full exact unit bytes and all manager search/
overlay/type/dash-prefix inventories must establish these absences; readback then
checks actual effects. The selected Ubuntu build and actual installed unit must
be qualified against these exact expected sets; upstream source alone is not proof.

Reviewer v5 confirmed ordinary systemd reconciliation may REMOVE manually enabled
subtree bits: a slice's children-enable mask comes from member demand, not its own
accounting/limits. Freeze one permanent installation-owned empty active anchor
slice, with explicit finite CPUQuota, MemoryMax and TasksMax demanding cpu/memory/
pids under workload parent. No new process or watcher. Anchor has the same pinned
no-stop/no-action/dependency policy above, no descendants/procs/threads, and exact
parent/kernel identity/control files. Its local freeze request is0; effective
frozen state before task admission comes from workload parent1. Static anchor name
cannot collide with32hex TaskIDs. It is included in unit/drop-in and recovery
inventories, but is never a per-task resource or automatically retired.

Installation must establish/verify active anchor, all4unit identities, actual
supported/enabled cpu/memory/pids at relevant ancestors and parent subtree_control
before attempts; admission only reads/checks. No per-attempt enabling, repair,
anchor start/recreation or fallback. Missing/replaced/inactive/changed anchor or
kernel bits fences. Actual manager reconcile, no-process persistence, failure/
keeper-death/OOM/stop and reboot/reconciliation cases require physical qualification.
Configuration demand can fail to enable controllers while slice startup still
succeeds, so active unit status alone is explicitly insufficient. Parent/sibling
caps remain exact finite values from separate per-project owner installation;
no historical numeric CPU/memory cap is invented by this design.

Bootstrap trust remains explicit: root-owned protected installation policy is
trusted because the opted-in owner/installer established it under exclusive
maintenance, not because native code can hash its own current executable. Native
must read/hash the actual referenced config/enrollment/startup/unit bytes and
compare complete pins/identity with installation and task; a hash echo or nonzero
field cannot replace that. Also require runtime image Merkle root to equal the
execution-generation root actually used by _ExecutionRoot after the native root
transition. The2026-11-24 held-input and persistent-binding guards now reject any
installation runtime/execution root mismatch before binding or persistence I/O.
This byte equality does not prove physical mapping or mount identity. Candidate F
below proposes binary policy/layout and paths/size caps; acceptance
of those bytes and provenance of owner-approved semantics remains OPEN. No arbitrary projection of config
or enrollment, new approval, or current account material is authorized by this
candidate. Full startup/member verification may occur in its explicitly named
later authenticated phase; no untrusted helper/entry runs before its own closure.

### Cross-exec durable producer correction E — coupled source remains blocked

Main's source trace found that the storage-only C owner cannot supply late Python
observer receipts through its current private globals/FDs. Current final transition
drains preparation handles, retains exactly0..8, creates sealed origin/taskFD9,
and execs Python; current _Context has no persistence handover. Reopening an arbitrary
old claim, introducing another Store or silently adding finalFD10 is forbidden.
This is an integration gap in unfinished admission, not a live storage incident.

Same-task reviewer v5 recommends a narrower capability than a whole-project view:
one RW bind of the exact already-durable claim file, no active/instance/other tasks
or directory mutation exposure. Future appends need file fsync only because the
claim entry and its consumed parent were already durable. Keep native persistence
FDs inside native256 through GO and the necessary media/view construction. Close
them once at the explicit final handover before unchanged final0..9 inventory.
No persistence getter or generic pathname/reopen API is introduced.

The fixed visible name is /run/rnr-native-<Task32>/admission.claim, located through
existing authenticated finalFD3. It must be mounted IN THE ACTUAL prepared-root
/run mount tree. Current preparer uses nonrecursive MS_BIND of /run; a submount
made below host /run is not automatically cloned into that bind. Do not change
/run to recursive bind or assume propagation. Create one exclusive root0600empty
mountpoint file in the already-consumed0700native task directory within the
prepared-root view; collision rejects. Mount the held claim, then separately
remount that bind RW|nodev|nosuid|noexec. Plain MS_BIND ignores the extra flags.
Each resource step needs its durable intent before entry; a partial/late bind or
remount fences, with UNKNOWN retained and no replacement, unmount or cleanup claim.
Verify same source file dev/ino/type/owner/mode/size, exact new mount ID, flags and
all named/held ancestry. Later chroot and /run verification must retain that exact
view. Source-store identity is authenticated natively before handover; the bound
view has its OWN expected mount ID, not the old source mount ID. Native diagnostic
journal under tmpfs remains distinct and is never called persistent consumption.

Native-to-Python producer ownership is a consumed state transition:

1. Native completes its last durable append, rereads/verifies the full committed
   prefix under original setup15, and sends the SAME keeper a one-shot handover:
   full binding/prefix digests and lengths, claim source and view identities,
   last sequence/opcode and next fixed transition, project/instance/task, original
   PID/start/credentials, original clock/namespace/boot and unit InvocationID.
2. Keeper authenticates the exact original Main, consumes native producer closure
   before ACK, retains these facts and permanently rejects further native-phase
   receipts. Keeper NEVER reads the file or waits for a sync. ACK loss leaves no
   Python authority; no resend/reconnect/alternate producer or native continuation.
3. Native closes persistence/auth temporaries once, emits a VERSIONED sealed
   context including that exact handover, and executes only the pinned immutable
   Python entry with the fixed permitted credential transition. PID/start continuity
   alone is insufficient: keeper also checks executable/namespace/credentials and
   the expected native->Python stage. Existing RNRH0001 does not establish this;
   preserve it as inert historical format, no silent ABI extension or mode switch.
4. Python authenticates the same expected keeper and original entry, obtains its
   sole initial writer grant, opens only the fixed view through finalFD3, and
   verifies exact complete binding/committed prefix against the keeper's retained
   length/digests/sequence. It must NOT discover a sequence from a tail, repair,
   truncate, import an old clock or resume another invocation. Changed/trailing/
   incomplete bytes reject before append; metadata/mount/source identities are
   checked before/after each bounded read and one full pwrite/fsync.
5. Python completes pre-fork target intents, then consumes INITIAL_WRITER_CLOSED,
   closes EVERY storage/auth temporary before _PreforkInventory and inherits no
   writable file into the observer. Parent-only postfork writer acquisition is
   a SECOND DISTINCT fixed phase, allowed once for same original Main only.
   Failure in either acquisition cannot retry/reopen that phase. Observer has no
   writer API, store path action or receipt role. Closing inherited FDs is not a
   pathname-access theorem: immutable observer code in the same namespace must
   contain no storage path; restriction flags do not prevent root reads/writes.
6. Last READY-related append closes the Python admission producer permanently.
   Workload mount inventories must exclude the claim view and its parent path.
   No producer, observer or broker can use this admission mechanism for arbitrary
   later records; any separate turn/subrequest durability needs its own accepted
   Store contract rather than silently enlarging this one.

All these appends/reopen/readback/fsync steps use original SETUP15, not a newly
captured session or Store44 allowance. Original keeper negative60/90 continues
independently. Sealed FD9 currently carries original origin AND a native floor
snapshot, but not producer metadata or the exact final post-seal floor. Freeze a
complete versioned layout and original high-water transfer before source: a final
native floor cannot be inferred merely from PID continuity or a later Python
sample. A narrowly authored fixed exec-argument floor (pure encoding after the
last native clock check) is a candidate, not a generic argv clock authority; it
would need exact original-entry/keeper provenance and rejection of caller-created
contexts. No reinitialization to a fresh high-water or T0 is allowed. Do not claim
the existing structural decoder already solves this coupled boundary.

Main's next byte/protocol freeze must include exact native->Python capsule,
allowed executable/credential transition, fixed IPC endpoint/credential phases,
producer sequences, per-operation intents and full normal/failure peaks. Native
root transition, claim-view mountpoint/bind/remount, Python initial/pre-fork close/
postfork acquisition and observer registration/arm/new-connection/placement each
need explicit death/late/ACK-loss tests before changing the fail-closed wrapper.
Reviewer v5 conditionally supports this single-file direction only; full acceptance
and physical mount/producer qualification remain OPEN. No view or runtime created.

### F2 protected policy bytes candidate F — needs whole-boundary challenge

The unit table also requires Manager.UnitPath, exact ORDER matching task and
protected policy; bounded sets are wrong for search precedence. This raises the
final draft inventory to275snapshot+1lookup+40final=316requests, within512. Read and
retain relevant path/overlay inventories; no optional fallback to default UnitPath.

The following fixes the native policy representation without embedding the full
1MiB execution manifest into the65536-byte persistent-policy field. Policy is
exactly9728bytes, little-endian byte decoding, magic RNRPOL01/version1. It is read
at fixed /etc/rnr/projects/<Project64>/admission-policy.bin through original
retained protected ancestry (project locator direction below),
root:root0400regular nlink1 with exact size and stable named/held dev/ino/mount/
mtime/ctime. Its SHA256 must equal installation.unit_policy_digest. It is not an
untrusted task parameter. Header1024, four128-byte unit records, then32fixed256-byte
ordered UnitPath slots. All unused/reserved/padding bytes zero.

| Header offset | Bytes | Exact data/comparison |
| --- | --- | --- |
| 0/8/12 | 8/4/4 | RNRPOL01 / version1 / total9728 |
| 16/48/64 | 32/16/36 | project / store instance / canonical boot UUID, equal original installation |
| 100 | 4 | flags exactly1: explicit per-project admission opt-in, no task/approval grant |
| 104/136/168 | 32each | configuration/enrollment/startup digests, equal installation pins AND actual held referenced bytes |
| 200/232/264 | 32each | native bootstrap ELF / actual PID1 ELF / permitted Python ELF hashes |
| 296/328 | 32each | execution/runtime Merkle root / asset root; equal installation.runtime.root AND execution_root, and installation.asset_root respectively |
| 360/392 | 32each | exact busctl tool / Docker daemon expected hashes, equal task declaration; actual closure/daemon verification remains required before their use |
| 424/428 | 4/32 | approved Git object ID length20or32/raw bytes, unused tail zero, matching independently established owner base revision; raw SHA1 is an object identifier, not an authorization signature |
| 460/464 | 4/256 | repository byte length1..256 / ASCII owner/project string, exact separately approved config/enrollment repository, unused tail zero |
| 720/724 | 4/256 | runner_host byte length1..256 / ASCII exact owner-approved host and current uname nodename, unused tail zero |
| 980/988/996 | 8each | exact positive native/PID1/Python ELF byte sizes; each<=32MiB |
| 1004/1008/1012 | 4each | exact configuration/enrollment/startup byte sizes:1..131072/1..131072/1..1048576 |
| 1016/1020 | 4/4 | UnitPath count1..32 / zero reserved |

Each unit record, in fixed service/control/workload/anchor order at1024+128*i:
fragmentSHA25632 at0; cpu_millis u64at32; memory_bytes at40; swap_bytes at48(always0);
pids at56; CPUQuotaPeriodUSec at64(always100000);72..127zero. Values are exact
finite separately approved per-project caps, not invented historical defaults.
CPU divisible10, positive, and all arithmetic for quota/period/conversion checked;
memory/pids positive in supported kernel ranges. Service caps do not exceed control
caps, task quota does not exceed workload caps; anchor caps equal workload caps
and demand all three controllers despite empty membership. Map per-second CPU
to cpu_millis*1000microseconds and kernel100ms quota to cpu_millis*100, rejecting
overflow. Full kernel limits/hierarchy/state must match; manager echoes alone do
not establish them. Slot identities and native filenames are fixed derivations,
not configurable path strings or dynamic record kinds.

Each UnitPath slot at1536+256*i: u32length1..248 at0, zero4..7, exact canonical
absolute ASCII path at8, zero remainder. No empty/dot/dotdot component, double/
trailing slash, escape or NUL. Unused slots zero. The permitted order is installed,
compared with actual PID1, and equal task unit_paths; the policy parser does not
invent default paths or silently truncate declarations allowing larger strings.

Read/hash exact referenced root:root0400regular nlink1 protected copies at
/etc/rnr/projects/<Project64>/configuration.json, enrollment.json and
startup-manifest.json. Original
owner files/enrollment permissions/locations remain untouched; no links, credentials
or other-project material are copied by an attempt. Read exact declared size in
bounded32768-byte chunks, check original setup15 before/after every file operation,
metadata/name recheck and computation chunk; require EOF and exact digest/size.
No repair/reread/retry on short/changed/late input. Hash only actual retained bytes.
Policy bytes themselves are the persistent binding's policy, not a digest echo.
Config/enrollment/startup referenced bytes are authenticated by actual hash equality,
not claimed to be embedded in that binding. This representation fits its existing
65536-byte cap; no cap increase or truncate is proposed.

Installer trust is a prerequisite, NOT a new runtime authorization shortcut. A
separate explicitly opted-in owner installation must validate approved base Git
config and exact private enrollment under existing schemas, host/repository/config
binding and scope/expiry/dependency rules, preserve all original bytes and publish
this reviewed native policy plus exact rendered unit fragments under exclusive
maintenance. automation.config.load_context is currently ADVISORY ONLY and cannot
by itself authorize execution; no implementation may relabel its result as a grant.
Policy flags1 supplies only the separately established per-project native-admission
opt-in. Issue/command approval and project product selection remain fully enforced
before later workload effects. No installation or approval is created in this chat.
The exact owner workflow/renderer and proof of approved semantic projection still
need acceptance; native hash checks cannot prove human authorship or bootstrap trust.

Before declaration, compare the actual original native executable (held proc magic
link plus protected installed named file) with policy hash/size, original PID/start/
root/credentials and immutable installed artifact. Actual PID1 executable/identity/
peer must match manager hash, task manager_digest and retained kernel observations.
The native bootstrap path is a fixed installation-derived content-addressed filename;
freeze its exact grammar with the renderer before source. No root supplied by the
current worktree becomes trusted merely by self-hashing. Native bootstrap must be
separately established trusted code before T0. Static libmd Init/Update/Final is the
conditionally preferred computation-only digest implementation, pending matching
source/object/header/license and final static ELF/link-map closure acceptance.

Actual Python, busctl, native media helper and imported/runtime members execute only
from the later authenticated runtime verity root/complete startup closure. The
native phase correlates all declared roots/hash pins and actual bootstrap/manager
facts; it does not claim to have read every image member before mapping. Later
native/Python phases must authenticate actual mappings/mounts, exact complete
manifest/member and transitive-loader/config closure BEFORE the corresponding
helper/entry/Store action. No deferred check may change a prior selector, grant
resource authority retrospectively or replace a failed earlier comparison.

#### Per-project input location correction — part of candidate F

Existing held-input source uses singleton /etc/rnr/installation.bin and task.bin.
That uninvoked fail-closed prerequisite is not a multi-project installation model.
Do not implement project isolation by overwriting those files for each project,
sharing policy/enrollment, or introducing a per-attempt argv/environment/path knob.
Unit RootDirectory/BindPaths/PrivateMounts projection would also alter the original
host namespace contract; no such workaround is proposed.

Propose one fixed derived-location routine, AFTER original T0/fork/ARMED and BEFORE
protected installation/task reads: read genuine /proc/self/cgroup bounded4096bytes,
under typed proc/root/PID1/user/pid/cgroup/mount/time namespace checks. Require one
canonical unified0:: entry with exact path
/rnrc<Project64>.slice/rnrc<Project64>.service/keeper, repeating the same lowercase
64hex project value. Native keeper and original child initially share this exact
service keeper subgroup. Reject extra/malformed/hybrid/alternate/suffix paths.
This kernel string is a LOCATION ONLY, never a grant. Read fixed nofollow
/etc/rnr/projects/<Project64> inputs/policy/referenced copies; project directory
root:root0700, file rules above. No fallback to singleton or another project's
files. Exact installation/policy project must equal the locator, and authenticated
actual PID1.GetUnitByPID(original keeper) must equal the same project service.
Retain/recheck original kernel identity/membership before declaration; keeper also
checks its own actual original cgroup against the declaration before resource
effects without opening policy/store disk. Private project resource/identity/input
scope thus follows actual trusted launch unit and explicit opt-in; no request path
or another project's enrollment can choose it.

This needs independent challenge and a fixed original bootstrap/proc trust stage;
existing host-view API is currently INPUTS_HELD-only and cannot simply be called
early. Do not capture a new clock or treat an untrusted proc string as identity.
Before any authority, verify genuine host views against protected installed native
code and actual root/PID1 peer/namespaces; unprivileged user-namespace root or
forged proc/root must fail. Original v2 decode remains DATA only. The positive
integration must update every input ancestry/retained-inventory fixture and reader
coherently; current fail-closed /etc/rnr fixture path is historical and is not
silently called project-isolated. No existing inputs/enrollments were read/moved.

Policy/locator review refinements (v5): derive location once; compare BOTH original
child and retained original keeper cgroup records before project reads and again
before declaration/effects. Genuine-proc bootstrap must precede file access; two
matching namespace links alone are not independent host-provenance proof. Do not
reuse current later INPUTS_HELD-only host-view acquisition out of order. Deeper
project ancestry changes retained input FD count/index mappings; source and every
normal/failure inventory must be updated together, with no historical fallback.

Installer validation permits only the explicitly opted-in per-project native
admission/resource-preparation policy. Current issue/command/scope/expiry/dependency
validity remains action-time mandatory before workload; an install-time expiry
check does NOT satisfy it. Preserve exact historical referenced config/enrollment/
startup/unit-policy bytes outside Git across any repinning/replacement so consumed
claims' hashes remain interpretable. Publish per-project task.bin exclusively;
never rewrite it while any invocation/pending/uncertain active binding exists.
A new task publication is not a consumption reset or permission to retire active.
No current owner data was read or materialized while designing these bytes.

#### Candidate F structural decoder prerequisite (2026-11-24)

Implement the exact9728-byte policy framing as DATA ONLY in records.c/h, with no
reader, renderer, installer, runtime call site or admission grant. Main owns all
source/tests/Git; the existing sole reviewer independently challenges the interface
and integrated diff. This does not accept the whole candidate F boundary.

Freeze the structural ambiguities as follows. Repository uses the existing
owner/project grammar `[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+`, excluding `.`/`..`
components, exact case. Host is1..256ASCII bytes (1..127), contains at least one
byte other than ASCII whitespace (09..0d or20), and has no NUL or normalization; the eventual
installer must prove exact config/enrollment/uname equality. This parser must not
invent DNS-label or lowercase rules. The chosen ASCII byte range includes control
bytes and DEL; it is not a printable-hostname promise. All identity/digest fields and Git object
IDs must contain a nonzero byte; boot UUID follows the existing canonical
lowercase, nonzero UUID decoder. Flags exactly1 do not prove owner opt-in.

UnitPath enforces the intersection with the existing declaration parser:1..32
ordered unique paths, each<=248bytes, `[A-Za-z0-9_.-]` components, no empty/dot/
dotdot component, at most16 entries when split on slash (including the leading
empty entry), and exactly one `/run/systemd/transient` member. This is canonical
structure, not proof of actual PID1 search paths. Preserve order and case.

All caps are positive signed64 DATA except swap exactly0; CPU multiples10 are
bounded by INT64_MAX/1000 so both specified microsecond conversions are safe.
Memory and pids are bounded by INT64_MAX for representation only; this is NOT
proof of supported physical kernel ranges. Later kernel correlation must enforce
actual target limits. Policy parent caps may exceed the task decoder's stricter
INT64_MAX/1000000 CPU bound; the task keeps that bound and must be <=workload caps.
Service CPU/memory/pids must each be <=control; anchor equals workload in numeric
caps and period, not their different fragment digests.
No claim is made that these relationships establish inherited effective limits.

The decoded policy owns fixed fields and borrows repository/host/path views from
unchanged caller bytes, as the declaration does. Reject input/output overlap and
clear the complete non-NULL output on every rejection. Validate exact header,
size, every reserved/unused/tail byte, all size bounds and conversions before
publishing the output. No file/clock/heap/Store/process operation. Verification:
valid field/ordered-view checks, every reserved-byte mutation, zero/padding/size/
integer/path/duplicate tests, truncation at every length, null/alias clearing,
strict GCC warnings and undefined-import audit before running the inert fixture;
then independent review, broader regression/build/installed-consumer checks.


The structural decoder is now implemented without any runtime call site. The same
sole reviewer found no blocking issue in its frozen interface or integrated source,
without independently running tests. Strict inert policy/legacy-record/declaration
checks passed8tests in4.807s; additional accepted maximum-size/path-count cases
passed the policy fixture separately. Full regression/package outcomes are recorded
in the[2026-11-24 admission checkpoint](2026-11-24-admission-armed-authentication.md):
1444tests passed,7skips; wheel/sdist and2installedconsumers/3compile-onlynative
builds passed. No actual native entry ran. All five operational gates remain open.
