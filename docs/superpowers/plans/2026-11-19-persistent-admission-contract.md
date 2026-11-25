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
its historical316-request inventory is amended below to324, not314/128.
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

**25 November 2026 amendment:** The user authorized four initial and four final
`.Unit.Wants` reads after review found this dependency missing from the fixed
inventory. The initial property inventory is now 279 reads, plus the first lookup;
the final sweep is 44 reads and the total is 324, still under the original
512-serial cap without reset. The expected exact `Wants` sets for all four units
must be established from the installed unit semantics and selected manager before
acceptance; do not infer empty sets merely from this amendment. This supplements,
rather than replaces, filesystem inventory of `.wants` directories. The older
275/40/316 figures below and in earlier evidence are historical.

Further source trace illustrates why those sets cannot simply be assumed empty.
For a system manager, an execution context with `PrivateTmp` can attempt both
`After` and `Wants` on `tmp.mount`. A separate branch can add both for
`systemd-oomd.service` when default dependencies and managed-OOM kill are enabled;
the required `DefaultDependencies=false` and managed-OOM `auto` each exclude that
particular branch under the observed settings. A device-policy branch can attempt
both for three modprobe services when `RootImage` **or** `MountImages` is set;
the required empty `RootImage` does not itself establish empty `MountImages`.
`PrivateTmp` and `MountImages` are not in the accepted property table. A retained,
distinct unexpected `After` would be rejected by that table, but these examples
are not an exhaustive list of `Wants` producers and do not prove the four sets,
the loaded manager state, or the outcome of an attempted addition. Exact original
unit bytes, relevant source semantics and selected-manager evidence remain needed.

The draft128serial cap is INSUFFICIENT and superseded by512totalserials, no resets.
Immediately before durable claim, repeat GetUnitByPID and .Unit Id/LoadState/
ActiveState/SubState/InvocationID/Job on all4objects, .Service MainPID/ControlPID,
type-specific Slice/ControlGroup/ControlGroupId on all4objects, and Manager.UnitPath:
40additional requests before the Wants amendment above. Every reply must match retained
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
historical draft to316requests; the Wants amendment gives279snapshot+1lookup+44final=324,
within512. Read and
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

#### SHA-256 dependency source audit checkpoint (2026-11-24)

The matching libmd1.1.0-2build1.1 source is now available. The configured Ubuntu
noble-updates InRelease signature was verified against the installed archive
keyring; its SHA256-pinned Sources index binds the exact upstream archive, Debian
source metadata and Debian archive. All three downloaded hashes/sizes match.
No Debian patch series is present. The upstream sha2.h is byte-identical to the
previously verified/extracted SDK header. The packaged sha2.o and a strict GCC13
compile of matching sha2.c import only memcpy and __stack_chk_fail and have no
constructor sections. Different compiler flags mean byte-equivalent objects are
NOT claimed. Existing computation-only vector evidence remains separate.

Protected source, license text, signed payload/index, hashes and object/import/
section audit are retained at
/home/faris/.local/state/agent-runner/release-admission-20261119/libmd-source/
(source-object-audit.json). This clears the earlier missing-source obstacle. It
does not adopt/link a dependency, install global SDK packages, run a native entry
or close final static ELF/link-map/transitive startup closure acceptance. Retain
the source/header copyright, BSD-3-clause conditions and disclaimer with any future
distribution that uses the corresponding code.


#### Bootstrap trust-order correction and integrated negative guard (24 November)

The installer-established immutable original bootstrap, launch and root context is
a prerequisite; protected files discovered through an arbitrary current root cannot
establish that prerequisite by hashing themselves. Candidate F's earlier ordering
must not be read as circularly authenticating a root against policy first learned
from that root. Initial-user-namespace/root IDs alone do not identify the chosen
host, PID1, manager, cgroup root or project. Dynamic WSL PID/mount namespaces remain
allowed under the fixed qualified context; no initial PID/mount namespace rule.

The [original-child guard plan](2026-11-24-bootstrap-privilege-guard.md) now has
an integrated private negative check before historical singleton input reads.
It rejects mapped-user-namespace/proc substitutions under its explicit bootstrap/
kernel/stable-namespace/no-privileged-injection premises. It returns no retained
root, project selector or authority. The supervised wrapper still abandons and
exits125. No per-project reader, declaration, persistence, GO, producer handover
or operational path is released by that check. Both-original-cgroup comparison,
actual host/PID1/policy authentication and the complete C/D/E/F coupled contract
remain mandatory. Do not relabel the singleton inputs as project-isolated.

### Proposed explicit selected143 authentication-lifetime amendment

Status: the user explicitly answered “Allow this scoped amendment” on24November.
The selected143 closure point is superseded ONLY for the two roles below; all
other constraints remain. Complete byte/FD/death contracts and independent review
still precede dependent observer/positive source. Same Main implements;
existing sole replacement reviewer challenges the same RNR-D00 coupled contract.

Selected143 currently says `placementACK -> close all auth temporaries -> original
Observer factory/READY`. Later sole-thaw serialization supersedes READY-before-thaw,
but does not explicitly supersede that descriptor-closure point. Current factory
contains on rejection and `arm` sends READY immediately; neither is PREPARED.
Closing the only original keeper connection before PREPARED leaves no accepted
transport for PREPARED/NEGATIVE_COMMIT/committed READY. Reconnect is not a repair.

Proposed narrow exception: in the independently placed original observer ONLY,
retain its one already-authenticated original keeper session socket and original
keeper-death pidfd through PREPARED/sole-thaw/negative commitment. No new connection,
actor, retry, selected FD, extra allowance or extended clock is introduced. Close
all authentication scratch handles before PREPARED. Keep Main's storage/auth closure
before prefork exactly unchanged, including53+5+2=60. Observer remains <=64 and
keeper/native <=256; the complete role inventory is still a source-release gate.

Exact progression to be frozen in byte/protocol tables:

1. Original Main registers the exact original observer PID/start/pidfd, receives
   registration ACK and delivers one arm token on the original parent channel.
2. That observer makes its sole NEW keeper connection; same keeper authenticates
   expected PID/start/parent/thread/credentials, consumes negative placement and
   sends placement ACK. No peer learned from the first arbitrary connection.
3. Close temporary namespace/proc/executable authentication handles. Keep the same
   session socket and keeper-death pidfd; construct PREPARED with both emergency
   target and frozen workload-ancestor controls and original clocks.
4. PREPARED cannot write workload-ancestor controls while keeper is live, including
   factory/arm/parent-channel/close/clock-failure paths. It fences/reports/exits on
   own failure. Exact keeper pidfd death is the sole precommit negative takeover;
   no clock/identity failure creates a fresh lease or permits an expired write.
5. Keeper accepts PREPARED for that same live original observer; consumes durable
   sole-thaw intent, performs its one thaw, checks original observer/controls,
   irrevocably enters NO_MORE_THAW, then sends NEGATIVE_COMMIT once.
6. Observer consumes commit, permanently enables negative containment, sends its
   committed-ready fact on the same authenticated keeper session and receives a
   terminal ACK. ACK loss fences; no resend/replacement. Keeper can contain but
   can never thaw again. Precommit keeper-death takeover remains permanent.
7. Observer once-closes that session/pidfd and all remaining auth temporaries,
   then emits the final READY on its existing original parent channel. Any cleanup
   uncertainty prevents this final READY; permanent negative authority remains.
8. Main accepts that exact SCM_CREDENTIALS-authenticated original-observer final
   READY. Main's later one-shot report to keeper means only: Main received that
   exact final original-parent-channel READY after keeper's committed-ready ACK.
   It is not an observer packet synthesized by Main. The fixed report must bind
   original observer, prior commit sequence and the already-kept target identities;
   loss/mismatch/late report or ACK forbids Store, never replacement/replay.
9. Final durable READY-related producer append/closure and original setup checks
   precede Store. Observer owns no claim writer and Store cannot inherit the view.

Observer local role proposal, not whole-budget acceptance: after the fixed child
exclusion there are stdio3 + original parent channel/pidfd2 + cgroup-root/target2
=7. Add the original keeper session/pidfd2 and exact workload-ancestor directory1
=10 persistent roles through commit. Authentication/identity/scanner/control-file
opens must be serialized and explicitly mapped before source; no temporary is
hidden in the10. After terminal close the2 keeper-session roles disappear before
final parent-channel READY. Parent prefork receives neither new role. Existing
all-phase observer64/native256 limits are not relaxed by this exception.

This proposal preserves both emergency-target intent/acquisition exchanges, exact
expected observer lineage and negative placement, initially frozen workload and
sole-thaw/NO_MORE_THAW/NEGATIVE_COMMIT order. Actual manager service survival and
integrated failure/late/death/ACK-loss/cleanup checks remain mandatory. It is not
whole F1/F2/F5 acceptance, physical containment evidence or live activation.

## Integrated coupled freeze candidate G — challenge before positive source

Candidate G received a contract-only independent review PASS on2026-11-24 after
closing the recorded producer/fork/terminal, arm-token, helper, full-DM-operand,
namespace/view and typed-identity findings. It is the implementation contract;
source proofs, integrated review and physical acceptance remain required. This is
not source release, positive-wrapper acceptance or operational acceptance.
It retains C/D's direct PID1 transport and amended324 requests, F's exact9728-byte policy,
original T0/setup15/positive44/negative60–90, separate project opt-in/store, both
emergency phases, and the user-authorized observer-lifetime amendment above.
It supersedes A's unimplemented64x256 intent proposal ONLY where explicitly stated.
Revision B's implemented initial binding/claim preparation remains unchanged and
uninvoked until its fixed authenticating caller and whole protocol are reviewed.
No additional inert codec-only implementation milestone is proposed.

### G1: bootstrap premise, location and actual authority in order

The opted-in installer establishes the immutable static native bootstrap, original
launch/root/namespace context and exclusive host maintenance before T0. Runtime
must not derive this trust from a project worktree or from newly discovered files.
The installed bootstrap name is fixed `/usr/lib/rnr/bootstraps/<NativeSHA64>/rnr-stage0`;
NativeSHA64 is lower-case full ELF SHA256 and must equal protected policy200..231.
This is a comparison/name derivation, not self-authentication. Shared immutable
code bytes are allowed; project identity/enrollment/consumption/state never shared.
Final static startup/environment/import/init/link closure is mandatory before any
actual artifact is qualified; static linking alone is not proof of that closure.

Original child after ARMED/held-inventory/negative guard acquires one retained
bootstrap view. No existing INPUTS_HELD-only API is moved earlier or recaptures T0.
The fixed owner reads original getppid between original admission-clock checks;
that clock's retained fork-parent/PDEATHSIG check must match before/after every
observation. Parent PID is not learned from a packet or environment. Read its
start from genuine retained proc once, while exact parent identity remains live;
retain original keeper pidfd/start plus PID1 pidfd/start and original child start.
No reaping/thread/disposition/namespace/credential/privileged replacement permitted.

Every proc component is separately nofollow/mount/type checked, with typed followed
NSFS handles and retained named/held rechecks. Reuse the existing `_ProcView` pattern:
retain ONE original own8 namespace reference set and compare keeper/PID1 serially
through one temporary typed handle; never refresh the reference. Separate original
pidfds/start and before/after named/held checks bind each peer. Sixteen duplicate
peer handles add no equality proof under the unchanged stable-namespace premise
and are omitted. Compare own/keeper/PID1 user,pid,mnt,
cgroup,time,net,uts,ipc namespace dev/inode/type; own pid_for_children and
 time_for_children must match own current pid/time. Root user namespace required;
dynamic actual WSL pid/mnt/cgroup namespaces allowed. Require actual proc PID view
matches syscall PID view. Compare original boot/time namespace/status samples with
this view, retaining original T0 and high-water; mismatch fences, never resamples
an origin. Clock values come from actual kernel clock calls, not proc text.

Read bounded original child AND original keeper `cgroup` files through their
retained genuine proc directories: one unified canonical0:: record,4096-byte cap,
exact `/rnrc<Project64>.slice/rnrc<Project64>.service/keeper` plus newline, same
lowercase64hex value repeated, no extra/hybrid/suffix record. Derive Project64
ONCE, retain both original files/identities/bytes, and compare before project reads
and again before declaration/effects. This chooses location only. Typed namespaces,
root premise, current PID1/private peer, manager unit and actual cgroup controls
remain independent gates; a matching string or namespace pair grants nothing.

Traverse retained `/`, `etc`, `rnr`, `projects`, Project64 separately nofollow.
Root/ancestors root:root protected directories; project0700. Operational installation
and task are root:root0400regular nlink1, installation exactly448/v2, task65..65600.
Their project/task/roots/boot/configuration/enrollment/closure/policy/instance facts
must match the original location, policy and declaration. Legacy0444/singleton
reader stays historical only; there is no fallback or overwrite for another project.
Policy/referenced files retain F's0400 modes and bounded exact size/hash/EOF checks.

Before declaration, hash actual original native/keeper executable handles and their
protected installed name, actual PID1 executable and `/usr/lib/systemd/systemd`,
actual four installed unit fragments and referenced configuration/enrollment/startup
bytes; compare exact lengths and F pins. Check executable headers/file metadata,
no setuid/setgid/file capabilities, stable named/held identities and readback. The
native phase pins Python and later immutable members but cannot execute them until
actual verity root/member/dependency checks pass in the named later phase.

Installer validates owner base revision/config/enrollment under existing schemas,
repository/host/digest/expiry/scope/dependency rules and separately acknowledged
native-admission/resource-preparation opt-in. It does not manufacture command or
issue approval. Publish protected reviewed copies and exact static unit bytes under
exclusive maintenance only; keep all historical referenced bytes content-addressed
outside Git before repinning. No runtime installer, task publication, epoch repin,
unit creation/repair or controller enabling precedes this admission. Per-project
config/enrollment/install identity is mandatory for every consumer.

C/D then authenticate root/PID1 private peer and actual effective units/kernel
hierarchy with the amended closed324-request matrix, actual manager build and
full overlay/UnitPath inventory. Actual service MainPID is original keeper, all
original PID/start/exe/namespace/root facts correlate. Kernel cgroup mount has
canonical namespace-root `/` at `/sys/fs/cgroup`; actual service/keeper path,
ControlGroup/ControlGroupId and held kernel identities match. Read exact controls,
limits, subtree bits, singleton memberships, frozen workload/empty active anchor.
No manager-echo/nonzero-digest substitute; final44-request/path/identity sweep
immediately precedes the initial latch/claim. Exclusive maintenance persists.

### G2: finite original-keeper transport

Original ARMED remains exactly8bytes with its already-reviewed credential parser.
Before fork, both original endpoints additionally set/read back SO_SNDBUF and
SO_RCVBUF requested131072/readback262144, under original setup checks. Unsupported
readback rejects before fork; no fallback. This fixed buffer choice must be
physically qualified for the maximum packet on the selected kernel before use.
No dependency on default/sysctl queue capacity is claimed. One outstanding request
per producer and exact ACK prevent a producer from queuing an arbitrary backlog.

Remaining messages use AF_UNIX SEQPACKET/NONBLOCK/CLOEXEC, SO_PASSCRED1 enabled and
read back BEFORE sends; one complete sendmsg/recvmsg attempt per logical packet,
no stream splitting/reassembly, retry, reconnect, resend, FD negotiation or heap.
Send MSG_NOSIGNAL; receive MSG_DONTWAIT|MSG_TRUNC|MSG_CMSG_CLOEXEC. Fixed aligned
32-byte ancillary buffer, exactly one original expected SCM_CREDENTIALS, no rights/
unknown/duplicate/truncated controls. Reuse reviewed bounded parsing/once-disposal
of up to4 installed rights before any clock/identity check; preserve initiating
errno, separate clock capsule and all cleanup errors. SO_PEERCRED of inherited
socketpair is not original child authority. C's separate stream/NULL-control rule
is unchanged and cannot be substituted here.

Packet =1024-byte header + exact bounded body. Maximum body131840, packet132864.
One fixed receive buffer132864; short/oversize/EOF/wrong phase or observed extra
packet fences. Header integers little-endian, no C struct layout:

| Offset | Bytes | Exact field |
| --- | --- | --- |
| 0/8/12 | 8/4/4 | RNRIPC02 / version2 / total packet bytes |
| 16/20 | 4/4 | closed opcode / connection phase0native,1Python-initial,2Python-parent,3observer |
| 24/32 | 8/8 | sender monotonic request sequence / ACK-of sequence (zero on request) |
| 40/72/88 | 32/16/16 | project / instance / TaskID |
| 104/112/120/128 | 8each | original keeper PID/start, original Main PID/start |
| 136/144 | 8each | registered original observer PID/start, zero before registration |
| 152/184 | 32each | complete initial binding SHA256 / exact committed claim-prefix SHA256; prefix zero only before initial claim durability |
| 216/224 | 8each | original actor high-water boot/wall; monotonic, no new origin |
| 232/236 | 4/4 | body bytes / exact expected frame kind, zero when no frame |
| 240 | 96 | four fixed object dev/inode/mount triples, role-specific, unused zero |
| 336/340 | 4/4 | exact protocol state / flags0 |
| 344 | 32 | exact body SHA256 (SHA256 empty bytes for empty body) |
| 376 | 648 | reserved zero |

DECL body is the complete existing binding: header256+installation448+original task
bytes+policy9728, maximum76032 for actual route. The old structural cap131840 remains
a hard upper bound, not permission to accept other operational policy sizes. Keeper
compares original clock/fork/credentials/cgroups, full structural/semantic identity
and correlated cutoff/root/binding before one irreversible declaration accept and
cutoff narrowing/ACK. Child authenticates keeper original PID/start/root/namespace/
exe and packets; no receipt from an arbitrary root peer. No persistence before ACK.

INTENT/RESULT body is exactly one1024-byte G3 record; keeper compares its full body
and fixed next transition before ACK. Native handover body is exact G4 header2048;
Python grants/observer phase facts have no arbitrary JSON/type/FD schema. All fixed
states/opcodes/targets are compiled code, not task-selected protocol selectors.
ACK means only the named consumed transition/held acquisition, never readiness or
physical absence. Unknown ACK disposition fences and retains consumption/controls.

After durable claim, an explicit durable endpoint-bind intent precedes keeper's
one bind/listen. Abstract name exactly NUL+`rnrk.`+Project64+`.`+Task32 =103bytes,
backlog3, no filesystem path or mode knob. Keeper retains original gate until native
producer handover. Exactly three later accepted sessions, in fixed phases: original
Main after native->Python exec, same original Main parent after observer fork,
registered original observer. Unexpected/duplicate/wrong-order client fences; no
replacement accept. Endpoint possession is not identity. Per-session peer pidfd,
SO_PEERCRED and every SCM_CREDENTIALS must match previously retained expected
PID/start/UID/GID/parent/thread/executable/namespace stage. Credentials stay root;
no exec transition except the explicitly pinned native->Python original Main stage.

Main's monotonic request counter survives exec and the two distinct writer phases;
cap384, no reset. Observer starts its own distinct actor counter1, maximum4requests.
Keeper reply counters do not reset across sessions, cap389 including one unsolicited
NEGATIVE_COMMIT at its exact expected phase. Attempt total packet cap1024. These
caps bound rejection too; no optional transaction discovered from traffic. One
negative poll iteration waits <=10ms and original remaining stop, capped16384waits;
actual scheduling/progress is qualified, not guaranteed by the arithmetic. Check
original clock before/after each syscall; every negative effect has its own fresh
negative check. Setup expiry fences positive protocol while original negative
containment remains allowed only until original stop. No userspace watch/effect
at/after original90 or on unknown time/identity; retain UNKNOWN and all holds.

#### G2 closed requests and forwarding on the same sessions

Use eight compiled request opcodes; do not add a second event bus, connection,
receipt service or generic RPC. ACK opcode is request|0x80000000, exact ACK-of
request sequence, empty body except where this table fixes another body. Main's
single outstanding request can wait while keeper services observer/pidfd/control
readiness under the SAME negative poll loop; waiting never suspends containment.

| Opcode | Sender / exact body / required predecessor / ACK |
| --- | --- |
| 1 DECL | native on original gate / full binding / original ARMED only / exact unchanged binding256-byte header, keeper independently narrows its own cutoffs; binding bytes never rewritten |
| 2 CLAIM | native / empty / DECL accepted and original latch+claim fully durable / original held claim dev/inode/mount in fixed triple0, full binding/prefix digests matched |
| 3 FRAME | current sole Main producer / exact G3 INTENT or RESULT1024 / exact next ordinal+kind and expected producer / empty; consumes that exact frame once |
| 4 HANDOVER | original Main / G4 header2048 for70, empty for75 / durable INTENT70 or75 respectively, exact prefix / empty; permanently fences outgoing producer before ACK |
| 5 AUTH | same Main phase1 or2 / empty / exactly one consumed handover70 or75 / empty; one grant for RESULT70 or75, respectively |
| 6 FACT | current Main / empty / one outstanding durable INTENT79,80,83 or84 / exact next G3 RESULT1024 assembled from keeper's own authenticated observation; no additional resource grant |
| 7 TERMINAL | Main phase2 / empty / durable RESULT85 / empty; consumes permanent producer fence before ACK |
| 8 OBSERVER | original registered observer / empty / its exact next local step1..4 / empty; each ACK released only at the fixed point below |

Protocol state is0ARMED,1DECL accepted/await CLAIM, then CLAIM ACK advances
directly to2 (expected INTENT1). There is no separate claim-accepted waiting state.
Frame state is `2+2*(ordinal-1)+(kind-1)` for expected next frame (ordinal1..85, kind1INTENT/2RESULT).
After RESULT85 it is172 (await terminal), then173 (permanently fenced). Frame ACK
advances state by one; requests carry current state, ACK carries resulting state.
HANDOVER/AUTH change only the compiled producer phase at the open70/75 INTENT;
no second frame/operation may interleave. Before declaration unknown binding/claim
fields are zero as applicable; CLAIM initializes prefix. Main's sequence persists
in G4 and keeper state across both transitions. Any out-of-order fact/extra packet
or unknown disposition permanently fences; no alternate continuation state.

Observer's four steps are:1authenticated connection/negative placement,
2PREPARED,3committed-ready,4terminal close. Main starts79INTENT before it permits
observer connection through original arm token. Keeper authenticates the expected
observer, performs/observes its one exact negative-leaf placement and holds its
step1 ACK. Main FACT79 obtains the exact result and durably records it. Only after
Main INTENT80 is durable does keeper release step1 ACK, permitting the observer's
construction/PREPARED work. Observer sends step2 after exact target+ancestor
verification and scratch closure. Main FACT80 obtains that fact; keeper releases
step2 ACK only after Main RESULT80 is durable, then the observer waits prepared.

The original native GO remains exactly one8-byte `RNRKGO01` packet. FRAME INTENT5
ACK first grants the one expected receive; keeper then sends that token once on
the original gate. Native checks the original credentials/keeper/clock, consumes
it once, and appends RESULT5 only after that checked receive. No preparation
starts before RESULT5 durability/ACK. The admission-only child already returns
HELD before GO in `runtime_stage0_clock.c`; do not adopt the legacy unsupervised
branch or treat a general packet ACK as GO. Lost/extra/wrong-order GO fences.

Main INTENT81 authorizes the sole thaw; keeper performs it and supplies the actual
result in that FRAME ACK's fixed object triples (not a new arbitrary body).
INTENT82 irreversibly consumes NO_MORE_THAW/NEGATIVE_COMMIT internally. Main records
RESULT82. Only after durable INTENT83 does keeper send one unsolicited opcode
0x40000008, empty body and exact new keeper sequence/ACK-of0, to that prepared
observer. It is the only unsolicited packet. Observer step3 reports committed-ready
on the same session. Main FACT83 records that authenticated fact. Only after durable
INTENT84 does keeper release step3 ACK, allowing step4. Keeper's step4 terminal ACK
and keeper-end once-close are the exact FACT84 evidence. RESULT84 does NOT assert
observer-local close; observer once-closes its own session/pidfd before final READY,
and Main's original parent-channel READY observation in85 establishes that ordering.
No Main packet may stand in for the actual original observer's parent-channel READY.

For keeper-owned effects1..4,81..82 and registration77, FRAME-INTENT ACK
contains the exact successful syscall/acquisition facts in the fixed header roles;
Main writes the corresponding RESULT only from those authenticated facts, with full
identity readback. No failure/late/unknown ACK can be converted into a RESULT. Native/
Python-owned effects produce their local RESULT after exact checked success.
78 is Main-local token preparation; its send is the first substep of79 AFTER that
INTENT is durable, so strict pair ordering cannot send the token prematurely.
Observer is neither append producer nor storage/receipt authority. The four FACT
requests are finite same-session queries, not reconnect/retry or repeated polling.
At most170 FRAME requests plus DECL/CLAIM/two HANDOVER/two AUTH/four FACT/TERMINAL
=181Main requests; observer4 and keeper186 replies including unsolicited commit,
371G packets plus exactly one original ARMED and one GO =373packets total.
Rejection caps384/389/1024 remain independent hard limits.

Header object roles are fixed, not caller-defined: DECL/HANDOVER/AUTH/TERMINAL
and observer requests leave all four triples zero; CLAIM uses triple0=claim,
1=instance file,2=consumed directory,3=active latch, with remaining project/store
ancestors already bound by the immutable binding and native persistence owner.
FRAME request triples mirror G3's primary target (160) and three extra identities
(752); no independent values. Non-effect FRAME ACK mirrors those exact identities.
For keeper effects, FRAME-INTENT ACK supplies the successful effect identities:
1primary=listener socket;2primary=prep directory;3primary=negative directory;
4primary=prep directory and extra0=original Main proc directory;
77primary=expected original observer pidfd and extra0=observer proc directory;
81/82primary=original workload ancestor directory. Other extras are zero. FACT ACK
triples mirror the returned G3 RESULT. Filesystem object roles use kernel dev/inode/mount triples. The op1 listener
socket uses fstat device/inode and mount0; op77 observer pidfd uses its fstat
device/inode and mount0, with its original PID/start, pidfdinfo and death/liveness
checks providing process correlation. Do not manufacture a filesystem mount proof
for sockets/pidfds. PID/start remain fixed header fields and G3's typed fields.
No digest, ordinal or socket name replaces an actual held/readback identity.

A successful G3 RESULT's errno is0 and flags3. For G8..63 its signed result exactly
copies full legacy record offset48 and must satisfy that existing fixed opcode's
success predicate: loop candidates G8/10/27/29 are distinct0..1048575; helper
G21/23 returns original child PID>1 with exact start/pidfd and reaped exit0;
G20/22 returns the original successful open FD>=3 with exact held object metadata,
never uses that integer as cross-process authority; every other zero-return effect
is0. Exact substep writes/syncs/waits must also satisfy their existing predicates). Other G operations use result0 only; acquired
objects/PIDs/job IDs are recorded in their typed identity fields, not generic
nonnegative-success tests. Failed/late/short operations never produce a RESULT.
INTENT result/errno/flags and unavailable identities stay0. Canonical unused header
and frame roles are zero, including mirrored roles before acquisition. Keeper's
phase/fact state validates all four triples and exact result predicate against
the single expected operation, never merely accepts nonzero identity values.

### G3: complete persistent effect progression and byte frames

Replace the unimplemented64x256 proposal with at most256 x1024-byte append frames
(262144bytes); bound initial binding131840+append262144=393984bytes. No retry/repair/
truncate/adopt/resume. Every effect consumes one INTENT before its sole effect and
one successful RESULT before any next effect; incomplete/unknown effect has no
new RESULT/next grant. Keeper never reads/writes/fsyncs claim storage. Main is sole
producer; full original binding and trusted immutable producer establish sync-before-
receipt. Each full pwrite/fsync/readback and any computation chunk uses original
setup15 before/after. Kernel-negative containment never waits for a new append.

Frames exactly1024bytes, little-endian, all unused/tails/reserved zero:

| Offset | Bytes | Exact field |
| --- | --- | --- |
| 0/8/12 | 8/4/4 | RNRINT02 / version2 / kind1INTENT or2RESULT |
| 16/24 | 8/8 | monotonic sequence1..256 / previous sequence (zero on first) |
| 32/36 | 4/4 | closed operation ordinal / producer stage1native,2Python-initial,3parent |
| 40/72/88 | 32/16/16 | original project/instance/task |
| 104/112/120/128 | 8each | original keeper PID/start, original Main PID/start |
| 136/144 | 8each | unchanged original T0 boot/wall |
| 152/156 | 4/4 | fixed target kind / role |
| 160 | 24 | held target dev/inode/mount, zero before acquisition |
| 184/192/200/208 | 8each | original observer PID/start, exact helper PID/start; unused zero |
| 216/220 | 4/4 | original manager job ID or0 / reserved0 |
| 224/232/236 | 8/4/4 | successful result signed64 / errno0 / entered-returned flags (0INTENT,3RESULT) |
| 240/272 | 32each | full binding SHA256 / previous full frame SHA256 (binding SHA256 on first) |
| 304/308 | 4/4 | legacy-native operand bytes0or256 / fixed operand-kind constant |
| 312 | 256 | full existing native diagnostic intent/result frame for operations8..63, otherwise zero |
| 568/576 | 8each | actor original high-water boot/wall |
| 584 | 32 | exact fixed resource/policy operand digest, zero if none |
| 616/620 | 4/128 | exact derived unit-name byte count<=128/name, zero tail; no pathname selection |
| 748 | 4 | reserved0 |
| 752 | 72 | three additional fixed-role object dev/inode/mount triples, unused zero |
| 824 | 32 | SHA256 of preceding committed prefix; never hash current frame into itself |
| 856 | 168 | reserved0 |

The frame contains exact operands/results, not arbitrary diagnostic text. Task-
derived names are fixed derivations; body fields cannot select a target, helper,
path, opcode or next state. Before acquisition all unavailable identity/PID/job
fields are zero; after acquisition exact original held identities are required.
Result permits only that opcode's exact success form; failed/short/late syscall,
failed sync, clock/identity uncertainty or lost ACK fences without a completion.
Once-only close evidence has separate bounded error capsules, not repair appends.

Closed operation order (one pair per ordinal, except the explicit exec/fork producer crossings70/75):

| Ordinal | Exact operation and owner |
| --- | --- |
| 1 | original keeper endpoint bind/listen after durable claim |
| 2/3 | keeper positive-prep and singleton negative-observer leaf create/acquire; collision/recreation rejects |
| 4/5 | exact original Main placement/readback, then final native GO consumed once |
| 6/7 | native fixed task directory mkdir; diagnostic journal exclusive init/full write/file+parent sync (finite init substeps) |
| 8..63 | the existing56 native operations, in exact old journal intent/result order1..112; every full256-byte old record retained as operand, exact opcode/role/payload checked against immutable existing stage, not generalized logging |
| 64/65/66 | claim-view mountpoint exclusive create, held-file bind IN actual prepared-root/run, separate RW/nodev/nosuid/noexec remount/readback |
| 67/68/69 | original root transition chdir/chroot/final fchdir, each consumed before syscall |
| 70 | native producer closure and single pinned Python exec; INTENT native, RESULT Python-initial only after exact initial grant/prefix verification |
| 71/72/73 | emergency phase1 intent/late tracking, fixed manager creation/job result, phase2 held acquisition; no prefork/Store on uncertainty |
| 74 | initial prefix sealed/verified for the one planned producer release; does NOT assert closed descriptors |
| 75 | initial producer closure, exact prefork inventory, sole original observer fork, and same-parent phase2 writer grant; INTENT initial writer, RESULT original parent only after exact prefix verification |
| 76 | confirmation of already-held phase2 producer state; no second acquisition |
| 77/78 | expected observer registration then preparation/reservation of the exact original arm token; no send yet |
| 79 | Main sends reserved original arm token once, then sole NEW expected observer connection/authenticated negative placement/readback |
| 80 | exact PREPARED observation with target+ancestor held controls; no precommit ancestor writes while keeper lives |
| 81/82 | sole keeper thaw then irreversible NO_MORE_THAW/NEGATIVE_COMMIT |
| 83/84 | original observer committed-ready session fact, terminal ACK/session+auth closure before original parent READY |
| 85 | Main's authenticated final-parent-READY observation and final successful append; terminal keeper fence/ACK and local producer closure follow, before sole Store |

85pairs=170frames, with70split across exec and75across fork;256frame ceiling leaves no selectable
additional operation. Any reserved capacity stays unused. Decl/claim ACK, fixed
connection authentication/grant and capsule sealing are finite substeps of the
named transitions, never permission for an unenumerated resource. Native helper
fork/exec and its fixed output mutations belong to its exact existing legacy
operation with closed immutable argv/output paths and original parent-death/leaf
containment; no arbitrary helper/descendant API. Every helper's actual transitive
behavior still needs immutable closure and physical qualification before execution.

The fixed legacy mapping is explicit: G8..11 runtime loop candidate/configure
pairs;12..14 runtime DM create/load/resume;15..18 runtime root mkdir/mount and run
bind/remount;19..26 launch-source mkdir/write, squash helper, padding, verity helper,
two seals and output record;27..30 launch loop pairs;31..33 launch DM create/load/
resume;34..35 launch mkdir/mount;36..63 the fourteen bind/remount pairs. This is56
operations, not56 arbitrary slots. Helper ordinals21/23 include the existing two
pipes, sole fork, child PDEATHSIG/parent checks/root and FD transitions, exact output
creates/mutations, parent pidfd acquisition, bounded collect/wait and six once-close
slots. Child has no positive clock owner and never returns into Main. Parent clocks
bracket the launch/collection/retirement boundary; do not falsely claim that every
helper-internal syscall is bracketed by Main's clock. Original capped/contained prep leaf outside the frozen workload ancestor,
keeper's independent negative controls, child PDEATHSIG and immutable helper/no-
credential-change/no-escape closure together must physically qualify the helper
boundary. An unaudited helper/descendant is a blocking premise, never permission
for execution or a new watcher after90.

New project-qualified DM names/UUIDs exceed legacy CREATE operand copies48/64.
Preserve those full old256-byte records as diagnostic evidence, but never treat
their truncated name fields as the operational identity. For DM CREATE operations
12/31, G3 operandkind1 and resourceSHA = SHA256(exact128-byte zero-padded ioctl name
||exact129-byte zero-padded UUID). Both full fields must fit without truncation,
be deterministically derived from original project/task/fixed runtime-or-launch
role, and compare in full against actual CREATE/request/readback/held device.
The frame's unit-name slot remains zero here. Other operations use operandkind0
and zero resourceSHA unless their already-fixed record explicitly supplies a
content digest. No generic new operand serialization or caller-selected digest.

The original diagnostic journal remains tmpfs evidence, never durability. Persistent
intent must precede its diagnostic intent and actual named resource syscall; result
must be durable before next operation. Diagnostic errors cannot repair a persistent
tail or bypass keeper receipt/ACK. New claim view and root-transition intents are
explicit additions, not falsely counted inside old56. Whole source trace must map
every effect to these fixed substeps; an uncovered effect blocks positive source.

### G4: native->Python capsule and final clock floor

Keep final descriptors0..9 unchanged. No FD10, generic reopen/path/clock/phase API
or caller callback. Native keeps storage inside native256 until exact claim view
and operation70INTENT are durable and prefix fully reread/hashed. It sends G2's
handover with this exact header, prefix digest/length and expected RESULT70; keeper
consumes native producer closure BEFORE ACK. Lost ACK fences permanently. Native
then closes storage/auth/gate once and creates the one sealed context FD9 as part
of the already-durable operation70. Existing RNRH0001 remains historical inert
format; actual route exclusively requires RNRH0002, no format/profile fallback.

Capsule = exact header2048 + complete unchanged original binding bytes, <=133888.
Header integers little-endian; magic RNRH0002, version2. Exact header table:

| Offset | Bytes | Exact field |
| --- | --- | --- |
| 0/8/12/16/20 | 8/4/4/4/4 | magic/version2/header2048/total/binding bytes |
| 24/32/40/44 | 8/8/4/4 | committed prefix bytes/next sequence/operation70/next kindRESULT2 |
| 48/80/112 | 32each | original binding SHA256/prefix SHA256/project |
| 144/160 | 16each | instance/task |
| 176/184/192/200 | 8each | original keeper PID/start, original Main PID/start |
| 208/244 | 36/4 | original boot UUID/reserved0 |
| 248/256 | 8each | original time namespace dev/inode |
| 264/272/280/288/296/304/312 | 8each | original T0 boot/wall/setup/positive/trigger/stop/outer-wall cutoffs |
| 320/328 | 8each | final sealed native floor A boot/wall, not falsely called post-seal final floor |
| 336 | 16 | actual original service InvocationID |
| 352/360/368 | 8each | original source claim dev/inode/mount |
| 376/384/392 | 8each | actual claim-view dev/inode/NEW mount ID |
| 400/432/464/496 | 32each | actual protected policy/native/Python/manager hashes |
| 528/532 | 4/4 | frame ceiling256 / endpoint bytes103 |
| 536 | 108 | exact103-byte abstract endpoint including initial NUL, tail zero |
| 644/648/656 | 4/8/8 | flags0/native ELF bytes/Python ELF bytes |
| 664/668 | 4each | expected root UID/GID0; no credential transition |
| 672/680/688/696/704/712/720/728 | 8each | original pid/mnt/cgroup/user namespace dev/inode pairs |
| 736 | 4 | final floor argument bytes48 |
| 740/744 | 4/8 | reserved0 / next original Main IPC request sequence (no reset across exec) |
| 752/760/768 | 8each | actual verified Python ELF dev/inode/mount |
| 776/784/792 | 8each | actual immutable execution-root dev/inode/mount |
| 800/808/816 | 8each | actual immutable asset-root dev/inode/mount |
| 824/832/840 | 8each | original keeper/native ELF dev/inode/mount |
| 848 | 1200 | reserved0 |

Sealed context contains floor A. After all sealing/metadata/FD checks, the last
native original-clock check yields floor B >=A in both clocks. Pure fixed encoding
then constructs exactly one48-byte argv argument `--rnr-floor-v2=` +16lowerhex boot
+`:`+16lowerhex wall; no syscall/format selection/clock capture between that check
and the sole execve. Exec failure is terminal exit125 with retained UNKNOWN; no
fallback or new native append. Successful exec has no returning post-check.

Exec is the exact pinned immutable root Python3.12 with fixed `-I -S -B -c` program
calling the single private qualification entry and the one fixed floor argument;
no other argv/env/config import. Native/Python real/effective/saved IDs stay root0,
no setuid/file-cap transition or executable replacement. Complete interpreter,
loader/import/config/transitive startup closure must be checked BEFORE this exec;
G's hashes alone do not establish it. No caller-created capsule/argv is authority.

Python's fixed entry structurally consumes FD9 once, validates seals/metadata/size/
exact full binding and floor B>=A/range, closes FD9 once, and authenticates the SAME
original keeper and expected original PID/start/native->Python executable/namespace
phase before any claim open or writer grant. Authentication observes actual clocks
but captures no T0; retain every Python authentication high-water above B. Only the
fixed authenticated entry may bind original origin and greatest already-observed
floor, never overwrite it with a new sample/origin. An arbitrary capsule/argv or
wrong expected exec phase fails before storage/effects; no generic origin importer.
Keeper's independent original negative clock remains in force during these reads.

Keeper retains the last native packet high-water; Python's authenticated floor
must also be >=that floor, not merely sealed A. Native verifies the actual Python
ELF/member hash and held identity before handover. Keeper correlates the new
original Main proc-exe object with that already-authenticated exact identity; it
does not perform blocking executable content hashing in its negative polling loop.
The old Main native proc-exe handle is once-replaced in this one compiled exec
phase, keeping one held slot plus one acquisition temporary; no arbitrary refresh.
After chroot, native persistence rechecks its original external ancestry through
retained original root descriptor `.`; it must never reopen new-root `/` and treat
it as the original store root. No final namespace/root transition reauthenticates
or changes the original source store.

Initial Python writer grant is once-only for expected original Main after exec.
Open fixed claim view through finalFD3, check exact source/view identity and flags,
verify complete binding and committed prefix <=393984 in bounded32768-byte reads,
EOF/digest/chain/last-sequence/expected RESULT70 against keeper's retained facts.
No tail discovery/repair/truncation/adoption. First append is RESULT70 only. Observer inherits no storage/auth handles. Operation75INTENT is the last initial-writer append. Keeper consumes the exact
prefix and irreversible phase1 producer closure before ACK; Main then once-closes
all writer/auth handles and performs exact prefork inventory and sole fork. Only
the same original parent acquires phase2 once, verifies that exact prefix ending
in INTENT75, and first appends RESULT75. Its grant cannot depend on that result.
76 confirms already-held state. Any close/inventory/fork/grant/prefix failure leaves
75 incomplete; neither phase retries. Observer has no claim path/API/receipt role.
After RESULT85 is durable and ACKed, keeper consumes the permanent terminal producer
fence and ACKs; Main once-closes writer/auth handles. Store requires both terminal
ACK and successful local closure. A close/ACK failure forbids Store, retains UNKNOWN
and cannot append a repair or retry. RESULT85 does not assert future closure.
Workload mount inventory excludes claim view and its parent path.

### G5: normal/failure descriptor accounting to challenge

All counts include live roles, unexpected rights and unwind retention, not only
successful final inventories. No alias is silently counted once unless ownership
is explicitly one role. Every acquired FD is registered before post-call checks;
all closes invalidate before one attempt and preserve all errors. All native held
role sets must be statically closed, not a generic256-slot authority allowance.

- Existing first fork/ARMED and negative guard retain their reviewed local peaks6/
  9received-rights/15guard. No new frame buffer grants an FD.
- Proposed child pre-GO bootstrap: root/proc/thread-self/own pid-task-tid-ns/keeper
  pid-ns/PID1pid-ns =11; original own8 typed namespace handles8; own child
  pid/time namespace handles2; keeper/PID1pidfds2; original own/keeper/PID1ELFs3;
  original own/keeper cgroup files2:28roles. Protected input ancestry adds4dirs
  plus installation/task/policy3=7; references3; unit fragments4; native named ELF
  plus usr/lib/rnr/bootstraps/hash directories6; manager named ELF/systemd dir2;
  retained cgroup sys/fs/root/control/service/keeper/workload/anchor8:58roles.
  Original stdio/gate4 + storage preparation10 + manager socket1 + one named
  temporary + one clock temporary + at most4bad rights =79. Do not retain a
  second named/digest input temporary outside this list.
- Before ordinary preparation, close authentication/reference/manager extras and
  map the exact retained subset to a fixed14-role operational proc view without
  reacquisition: proc root/own pid directory/PID1 pid directory/PID1 pidfd4,
  original own8 namespace references and original own child2 handles. PID1
  namespace comparisons use one serial typed temporary against those original
  references. New-route rechecks/handover must use14, not pretend to fill legacy22
  or reacquire eight duplicates. The old22-role DATA/test seam is historical only;
  no operational fallback/call to legacy hostview. Preserve7project input roles instead of old5. Existing
  fixed-binds fixture proves78preparation roles at its largest legacy graph;
  the smaller14-role route does not yet have runtime/source evidence. Conservatively
  retain78 as an upper bound and add2input ancestors to give80, plus original stdio3/gate1/storage10/claim-view
  mountpoint1/walk2/clock1/bad-rights4 =102. Helpers and final-role creation must
  have their own smaller phase trace;102 is the listed overlapping upper bound,
  not permission to hide another descriptor. Close all extras before final0..9.
- Native final-role construction can retain the conservative old80 graph bound while acquiring six
  final roles; include one sealed FD9 conservatively even though its actual phase
  follows closure. Union bound80+6+stdio3/gate1+storage10+claim-view mountpoint1+
  walk2+clock1+bad-rights4+FD9one=109, still below native256. Parent helper pipe4,
  helper ELF1 and helper pidfd1 already belong to the existing media12 array in
  that old graph, not six unlisted extras. Copied helper initially inherits the
  current graph (<109), then dup/close_range leaves exact0..3 before exec; failed
  child setup exits127 and parent retains unknown intent. Native cleanup capsules
  must cover the expanded closed roles (proposed96 preparation entries plus the
  separate11 storage and10 bootstrap entries); the source trace must demonstrate
  no acquisition temporary escapes those owners.
- Keeper fixed kernel-view27 roles are the mirrored28-role kernel view above with
  original Main pidfd owned by its negative clock, borrowed here and counted once
  separately. The own task/tid slots refer to original keeper; Main and PID1 have
  their separately retained pid/ns directories. Fixed cgroup23 roles: root/control/
  service/keeper directories4; prep dir+freeze+kill+events+procs5; negative leaf
  dir+events+procs3; workload dir+freeze+kill+events4; emergency target dir+freeze+
  kill+events4; anchor dir+events+procs3. Original stdio3/Main pidfd1/gate1/listener1/
  observer pidfd1/Main+observer sessions2 adds9: conservative union59. Gate closes
  at native handover before observer/session roles coexist; no extra keeper input,
  hash or journal descriptors remain in the negative loop. One named/file temporary
  plus one clock temporary gives61; receive with <=4rights gives63 only after both
  temporary slots are empty. All rights close before clock/auth work. Cleanup has
  fixed64 entries with explicit role tags; no heap/generic FD list authority.
- Python prefork remains exact53+5+2=60, with no producer/auth handles. Copied child
  initially inherits58 and its path-based proc scan adds one=59; close inherited
  extras once before new authentication. Original observer starts7roles:stdio3,
  parent socket/pidfd2, cgroup root/target2. Add keeper socket/pidfd2+ancestor1=10
  through commit. Authentication scratch18: proc root1; own/Main/keeper pid dirs3;
  their ns dirs3; original own8 namespace reference handles8; their exe handles3.
  Compare peer namespaces and own child namespaces serially to that reference,
  never recapture a reference. Thus held28 + one proc/control temporary + one clock
  temporary =30. All temporary
  file/clock slots are empty during receive; <=4rights then gives32, closed before
  auth. Scan after closing scratch (10+one=11), not during28-role authentication.
  All18 scratch roles close before PREPARED. Thereafter control1+clock1 gives12;
  after terminal keeper socket/pidfd close,8held+control1+clock1 gives10. Root/target/
  ancestor form ONE negative-control owner with3 FD slots; do not alias root across
  independent owners. All construction failures close/retain once under these bounds.
- Main parent after fork retains original53, parent observer socket/pidfd2 and two
  recovery root/target duplicates2 =57. Phase2 claim1+keeper socket/pidfd2 gives60.
  Reuse proc16+witness2, never recapture18 scratch roles. Open keeper pid directory
  relative to retained proc root1; retain it while serially opening ONE namespace,
  exe, status/stat or fdinfo record1; clock temporary1 gives63. Each object closes
  before opening the next. Existing `_ProcView` check/read nesting must fit this
  same three-temporary bound, not count the keeper directory as magically free.
  Close the keeper directory and file/clock temporaries BEFORE packet receive:
  60+<=4rights=64, then dispose all rights before another check. No new allowance.
  Descriptor scans occur with no authentication directory/file held (60+2=62).

These are closed prospective upper bounds, not actual kernel qualification. Full
source traces must map exact role reuse, every acquisition, nested failure/unwind,
helper/final creation and once-close before a positive entry is enabled. Neither
native256 nor observer64 is a general authority to acquire arbitrary descriptors.

### G6: sole offline retirement and retained uncertainty

There is no online retirement/cleanup/reset/unlink route. Current active remains on
all outcomes. Proposed sole positive retirement is an explicitly authorized,
exclusive per-project OFFLINE maintenance session, with admission disabled and
all original actors stopped/expired. It uses a fresh maintenance observation budget
only for inspection, never adopts/resumes an old attempt clock or action grant.

Require exact valid original installation/store/instance/active binding and matching
claim/prefix; inspect every finite intended target/helper/media alias/mount/manager
job from that attempt and all originals referenced by its prefix. Prove no live,
queued, stopped-but-recreatable, externally held or uncertain resource remains.
Service/anchor/project closure and exact manager job identity are checked, not just
PID absence or an empty cgroup. Permanent immutable installer/bootstrap files,
project configuration/state, historical consumed claims, and the fixed demand
anchor are retained and checked against expected installed identities, not erased
or falsely required absent. The absence predicate covers attempt-specific resources
and any job/process/alias capable of recreating them. No online removal of the
permanent anchor or installed project service is introduced. Missing/torn/corrupt active/claim, lost durability,
changed mount/store/boot or incomplete attribution stays quarantined UNKNOWN; no
automatic new store or consumption reset. A changed boot requires explicit owner
repinning only AFTER reconciled absence; a new boot ID is not evidence of absence.

The finite resource table derives ONLY from original binding, fixed G opcodes and
recorded results, with no directory-wide adoption of unrelated objects:

| G source | Closed recovery observations |
| --- | --- |
| 1..5 | Original keeper/Main identities and listener lifetime; original prep/negative/control/workload paths and exact memberships; sole GO disposition |
| 6..7 | Project+Task native task directory and diagnostic journal original identities |
| 8..18,27..35 | Four exact loop candidate/backing/tag identities, two DM full names/UUIDs/device/event/tables/openers, runtime/launch root mounts and run bind/remount |
| 19..26 | Fixed launch source dir/file, data/hash/root/output files, both exact helper PID/start/pidfd/status and inherited/output aliases |
| 36..63 | Each of fourteen fixed source/target bind mount IDs and remount state, including every original target alias |
| 64..70 | Exact claim-view mountpoint/bind/remount, original root transitions and original Main exec continuity; exclude persistent consumed source from deletion |
| 71..76 | Emergency unit/target, exact manager job and settled/no-queued result, parent/child fork identities, producer closure; no untracked late job |
| 77..85 | Original observer identity/negative leaf, original arm channel, workload ancestor, sole thaw/commit and final readiness; no remaining negative/positive actor or producer |

Every multi-resource row expands to its fixed role/substep observations (<=256),
not one aggregate "done" bit. Existing immutable no-escape/no-FD-passing closure
and complete kernel descendant/mount/device inventory must prove no unobserved
holder can retain/recreate a named resource. A missing record, extra alias, unknown
holder, unsettled job, unsupported inventory or bound overflow blocks closure.
Receipt records actual physical observations, never merely planned syscalls or
inferred success from clock expiry. This route only retires an already-reconciled
active latch; it does not authorize deleting mounts/devices/units or modifying
unrelated services. Any required cleanup outside original actor rights needs its
own specifically authorized fresh offline procedure before absence can be claimed.

Reuse ordinary protected files, bounded JSON and no-overwrite rename for offline
receipts; no new binary codec or runtime receipt service. Runtime never treats a
receipt as approval or resumes an old attempt. The trusted maintenance operator is
subject to the same exclusive-host/installer premise as initial provisioning.

Exact successful retirement order, every syscall under the fresh maintenance
budget and once-close/error rules:

1. Exclusively create project-state `maintenance.lock` root0600/nlink1, O_EXCL,
   nofollow. Its bounded UTF-8 JSON (<=4096bytes) names version1, original project/
   instance/task/binding SHA, current boot and explicit scoped owner maintenance
   acknowledgement reference. File fsync then project-directory fsync MUST finish
   before any retirement change. Admission checks this exact fixed lock name and
   refuses if present, malformed or uncertain; it is never a runtime repair target.
2. Validate exact original active/claim and perform the complete closed absence
   inspection above. Do not retire torn/partial/corrupt records. Exclusively create
   history directory `.retiring-<Task32>` root0700 on the SAME protected ext4 store.
   Collision means UNKNOWN. Copy the exact original committed claim prefix into
   `claim.bin` root0400/nlink1 (<=393984bytes), retaining all original binding bytes;
   reread size/EOF/hash and fsync it. No re-encoding of original records.
3. Create `receipt.json` root0400/nlink1, <=196608bytes, UTF-8 JSON, duplicate keys/
   unknown fields rejected. Fixed top-level keys: version(1), project64, instance32,
   task32, binding_sha256, prefix_sha256, prefix_bytes, original_boot_uuid,
   observed_boot_uuid, store_identity(dev/inode/mount), stop_bounds(original boot/
   wall/trigger/stop), owner_ack_reference, observations, outcome("ABSENCE_VERIFIED").
   observations is an ordinal/role/substep-sorted list of at most256 objects with exact
   keys ordinal, target_role, substep, identity, absent, detail. Each is <=512 encoded bytes;
   identity contains only the fixed resource device/inode/mount/PID/start/job ID
   appropriate to that compiled opcode; detail is a closed absence result enum,
   never commands or arbitrary authority. Every intended resource/substep/alias
   must be accounted for by its compiled ordinal/role/substep; reserved list capacity
   is not a selectable resource interface. Incomplete/multiple/uncertain attribution
   blocks retirement, not a dropped row. Zero targets are explicitly NONE; absent
   must be true for every resource. Reference hashes/full original binding retain
   old configuration/enrollment/startup bytes in protected content-addressed history.
   Serialize once using standard JSON, validate/reread the exact bytes and fsync.
4. fsync `.retiring-Task`, no-overwrite rename it to `retired-Task`, then fsync
   history. Only after that durable verified receipt exists, rename original
   `active` to `retired-Task/active` with RENAME_NOREPLACE. Retain exact old bytes;
   fsync both source project-state and destination receipt directories. Never
   unlink/truncate consumed Task files, reset the store or reuse TaskID.
5. A boot/pin change is a separate explicitly acknowledged trusted installer step,
   still under the durable maintenance lock. Preserve old installation/policy/
   instance/reference bytes in protected immutable history; publish coherent reviewed
   replacement0400 files by ordinary same-directory temporary+atomic rename, sync
   each file and parent. No auth/SDK/global project change, automatic opt-in, or
   automatic epoch/boot adoption. No lock release if any new pin is unqualified.
6. Recheck absence and all durable identities/published files. Rename the exact
   maintenance.lock into `retired-Task/maintenance.lock` with RENAME_NOREPLACE,
   then fsync both parents. This is last, after ALL receipt/active/pin syncs. No
   admission during maintenance or on any uncertain sync/rename outcome. Completed
   offline retirement permits a different fresh Task through ordinary admission;
   O_EXCL on retained consumed files still permanently rejects the old Task.

A crash before last lock retirement leaves the admission lock and blocks entry.
If the last rename is observed after a crash, every earlier required sync already
succeeded; if it did not persist, the lock still blocks. Runtime must inspect lock
and active through the SAME protected project directory, with stable named/held
checks and installer exclusion; absence of a random pathname is not closure proof.
Unexpected missing/corrupt lock, active or history during maintenance stays UNKNOWN;
no automatic roll-forward, rollback, receipt adoption or deletion. An interrupted
retirement needs a new explicitly scoped offline reconciliation, not a retry of
old live action rights. Old boot/clock expiry alone never authorizes retirement.

**G6 preclaim interface, source-design candidate:** The existing uninvoked
Revision B call keeps project directory role 5 private, validates its original
chain and immediately creates `active` in one call. An earlier check by a
separate caller opening the same pathname cannot prove it used that same held
directory. A future fixed internal sequence can acquire and retain the original
project/store/instance handles without effects; after the valid, timely keeper
declaration ACK, it must run the original final 44 manager requests and required
path/kernel/identity rechecks, including the unresolved G1 overlay and inventory
comparisons, recheck held and named store ancestry, then inspect literal
`maintenance.lock` with a nofollow lookup through that exact role-5 descriptor
and immediately perform the existing one-shot `active` creation through it.
Only a definite `ENOENT` on the verified directory passes the lock check; any
entry, including a dangling symlink or special file, and any other error or
uncertainty fences. Do not open, remove or repair the lock. Preserve the original
SETUP15 deadline with checks before and after each relevant syscall, no clock
refresh or retry, and the original 324-request total without a serial reset.
The persistence/preclaim owner remains one original owner/TID; the keeper remains
its distinct original actor. Preserve failure and once-close rules and existing
create disposition and durability observations. No caller-selected pathname,
descriptor or general callback is introduced.

Absence is not a lock: an installer or maintenance actor could create the name
after the lookup and before `active` creation. The existing trusted exclusive
maintenance premise must actually exclude those actors and manager changes
throughout the sequence; a separate enforced exclusion, or other independently
reviewed race-free protocol, would be needed if that premise cannot be established.
The precise fixed cross-module owner/phase transitions, error/FD peaks, whole
final-sweep coupling and physical exclusion evidence remain open. This candidate
does not alter Revision B, authorize runtime effects or close G6.
In particular, today's `live_input` accepts admission acquisition but not the
published `PREPARER_ADMISSION_INPUTS_HELD` phase. Existing reader helpers cannot
simply be called from the held phase for the final sweep. A future one-shot
transition must account for active/fenced/abandon states, original PID/TID and
clock ownership, concurrent fencing and cleanup, and compare against retained
original observations without overwriting them. Its interface remains to be
designed and reviewed with the persistence transition as one coupled boundary.

The fixed final schedule is 44 requests: keeper lookup and UnitPath (2), six
unit properties on each of four units (24), Slice/ControlGroup/ControlGroupId
on each (12), service MainPID/ControlPID (2), and four Wants reads (4). The
current lookup and UnitPath routines already compare against retained/derived
expectations. The other fixed status, job, slice, path and PID comparisons exist
only inside the initial monolithic reader. Its InvocationID and ControlGroupId
branches write the four retained originals, so a final reader must compare
without overwriting them. Four Wants reads and their exact expected sets remain
absent. A future fixed schedule must preserve the existing serial/receive/poll
budgets and kernel-ID correlation rather than rerun the full initial loop.
The existing 316-byte initial reply buffer and empty/singleton dependency decoder
do not establish support for the approved larger bounded Wants arrays; their
exact decoded size, storage and stack costs must be closed before implementation.
The final 44 include Wants but not Names, Requires or Upholds. Those latter
properties are checked initially; using them throughout the interval requires
the accepted unchanged-manager/maintenance and autonomous-action exclusion,
not an assertion that the final sweep rereads them.

The fixed JSON receipt is evidence for offline review, not a new acceptance source.
An owner acknowledgement alone does not prove the observed closure. Physical
recovery acceptance must show successful closed retirement AND blocking of torn,
lost, replaced, partially synced and ambiguous cases. No general administrator
cleanup command or post90 watcher is implied.

#### G1 project-scoped temporary/media identity correction

The existing uninvoked native directory/DM/loop tags use TaskID alone. Two different
opted-in projects may legitimately have the same TaskID; a global TaskID collision
must never select or expose another project's state. For the new operational route,
all native mutable names bind BOTH authenticated Project64 and Task32, with no old
fallback. This refines the user-required separate state; historical DATA fixtures
and existing consumed objects are not renamed/adopted.

Fixed native basename `rnr-native-<Project64>-<Task32>` is108bytes; path under `/run/`
is113bytes. Claim view is exactly that prepared-root path plus `/admission.claim`
(total129bytes). This explicitly supersedes E/G's old Task-only visible name for
operational source. Update every derived media/mount/output/helper/final-root path
and buffer bound coherently; filename/path buffers are fixed256bytes, no truncation,
heap or generic path parameter. Root/runtime/launch readonly content-addressed media
may be shared as immutable bytes only; mutable task outputs and receipts are not.

DM name `rnr2-<Project64>-<Task32>-runtime` (or `-launch`) and UUID
`rnr2.<r|l>.<Project64>.<Task32>` fit existing128/129byte capacities; exact whole name,
UUID/device/event/table/readback remain necessary. No adoption by matching name.
Kernel loop LO_NAME_SIZE64 cannot hold full64+32hex identity. Its fixed tag is
`rnr2.<d|h|l|m>.<Base32>`: role-specific d(runtime data),h(runtime hash),l(launch data),
m(launch hash); Base32 is52lowercase RFC4648 alphabet bytes, no padding, of SHA256
on original binary project32||Task16||one exact role byte. Tag59bytes, remaining5
bytes zero. Verify selected-kernel exact loop string storage/readback before use;
no truncation or digest-only task authority. The complete binding/original producer
and source/loop held identities remain independent. This relies on the same vetted
computation-only SHA256 dependency, not an ad-hoc checksum or new runtime library.

### G1 dependency inventory refinement — 25 November source-design candidate

Status: **candidate for independent review; no source implementation or operational
acceptance**. This resumes the existing G1 inventory requirement. It changes no
G1–G6 guarantee, manager request budget, installation authority or exit125 fence.
The independent next-step review is
`docs/reviews/2026-11-25-original-gate-next-step.md`. Retained source below lives
outside Git in `/home/faris/.local/state/agent-runner/release-admission-20261119/`;
the existing provenance and Ubuntu source-package correspondence remain the
evidence, not proof of the running PID1 or installed directory contents.

#### Source conclusions and supported scope

`systemd-v255-load-dropin-01a20fb2.c:14` calls the shared directory search for
`.wants`, `.requires` and `.upholds`, passing file_suffix=NULL. After basename
selection, it checks mask, symlink, valid unit basename and readlink. A target-name
mismatch which returns compatibility **zero only warns**; it still attempts dependency addition using the entry basename. The downstream
load/add result is not established by this call alone. A negative compatibility error does skip it.
Do not classify every mismatched target as inactive or require an `After` change.

`systemd-v255-dropin-01a20fb2.c:136,223` constructs the directory list in this order:
canonical name across ordered UnitPath, then each alias across ordered UnitPath,
then type scopes across ordered UnitPath. Each name expands to its own scope,
instance/template scope when applicable, then successively shorter dash prefixes.
This is **not** one global UnitPath-first merge across every scope. Canonical
specific entries can precede generic entries from a higher-priority UnitPath.
Alias Set iteration is not a lexical precedence contract.

`systemd-v255-conf-files-01a20fb2.c:25,149` keeps the first eligible basename in
that directory order, then sorts the selected output by basename. Here flags=0:
mask/type filtering is not done by `files_add`. A higher-priority regular/empty
file or mask can therefore occupy a basename before `process_deps` ignores it;
there is no fallback to a lower-priority symlink of that basename. Source errors
which systemd logs/ignores are not evidence of absence for this admission reader.

`systemd-v255-unit-file-01a20fb2.c:159,380,718` distinguishes aliases inside the
original plus resolved UnitPath from linked files outside it. The first map-eligible unit-name entry wins: regular files are inserted before
content/loadability checks, classified linked masks can occupy a name, and
symlink-resolution errors skip insertion. Later reverse-map construction omits
null/empty targets; it does not restore a lower-priority fragment. Alias resolution
uses at most eight map lookup iterations, including the terminal absolute-fragment
lookup (seven ordinary alias edges can succeed; eight cannot). The reverse
map supplies all names resolving to a selected fragment. A linked path or mask is
not equivalent to an alias merely because its basename resembles another unit.
The three selected slice names do not gain alias support: `unit_type_may_alias`
excludes slices. The launch service can have aliases in systemd generally, but
the accepted manager `.Names` expectation is already an exact canonical singleton.

Use that existing singleton policy to keep the operational inventory narrow:
derive the filesystem winning-name/reverse map, prove that the selected service
has only its canonical name, and fence any effective additional alias. Unrelated
host symlinks are not blanket-rejected. A chain which cannot be classified is
uncertain, never proof of absence. This avoids inventing alias iteration ordering
or expanding the accepted runtime to alias/template units. A later requirement
to admit aliases would need a separately closed algorithm and manager matrix.

#### Proposed deterministic observations

1. Use only the retained genuine root, authenticated ordered UnitPath, original
   four fragment identities and clock. Capture each resolved search directory and
   its absence/metadata/mount identity with existing named/held rechecks. Expand
   original and resolved search paths for alias-versus-linked classification.
   Scan names without importing systemd code or using a live shell/busctl helper.
2. Build the ordered winning-name map once from bounded directory observations.
   Resolve relevant service alias chains using the selected source semantics and
   eight-lookup ceiling including the terminal fragment, preserving link bytes and the reverse names of the selected
   fragment. Require the canonical four winners to match the already authenticated
   installed fragments, and the selected name sets to remain exact singletons.
   Unknown file types, uncertain relevant links, cycles or incomplete reads fence.
   Do not silently reinterpret them as missing or make a fresh authority snapshot.
3. For each `(selected unit, suffix)` separately, generate its canonical scopes
   and ordered directories above and maintain a distinct basename winner map. For these four non-template names the seven existing
   canonical/type/dash-prefix scopes suffice only **after** the singleton proof.
   Retain the first eligible winner for each basename, including regular-file and
   mask winners. Preserve lower-priority observations for drift evidence without
   promoting them to effective dependencies. Follow directory links under the
   genuine root with retained identity checks; a symlink directory is not absence.
4. Classify each winner as masked, non-symlink, invalid basename, effective
   dependency or uncertain. Reproduce the source's relevant validation decisions;
   negative read/metadata/compatibility uncertainty fences rather than mirroring
   systemd's warning-and-continue behavior. Record an attempted dependency addition by its basename even when the target
   spelling only produces a compatibility warning. Do not equate an attempted
   addition with a successfully loaded canonical edge; target resolution/addition
   must be proved before calling this an effective dependency set. Compare proved
   sets with the exact accepted expected sets, including the separately unresolved
   four `Wants` sets. Set equality rejects unexpected members but cannot detect
   duplicate observations or edges coalesced by `Unit *`. Within the same unit
   and suffix winner map, a repeated eligible basename in a lower-priority
   directory is shadowed, not automatically an error; preserve it for drift
   evidence. Do not infer shadowing across different maps or from an entry
   filtered before selection. The already accepted manager-array
   rule separately rejects duplicate wire elements. Whether multiple effective
   entry names resolving to one `Unit *` are permitted, and how their identities
   are proved, remain open; preserve all attempted additions until resolved.
   No change to the manager's 324-request budget is proposed.
5. Retain a deterministic, length-delimited record of original order, winners,
   names, required observed link bytes, classifications and named/held identities. At the existing
   post-bind point compare against those original observations; the later final
   pre-claim sweep must compare again, never replace them. Register temporary FDs
   before post-call clock checks, close serially, preserve the initiating error
   and sample the original clock on failures. No refresh/retry/new origin.

#### Finite resource proposal and remaining closure checks

Reuse the current at-most32 UnitPath bound and per-directory 4096-byte reads,
512 raw-entry limit, at-most16 nonempty reads plus one EOF read, and original
setup clock. Proposed per-pass raw-entry ceilings are 16,384 for UnitPath maps
(32×512) and 114,688 for one dependency suffix (32×7×512). This requires scanning
each logical `(UnitPath index, scope, suffix)` once per pass and sharing immutable
scan records across the distinct per-unit winner maps; no global suffix winner
map is allowed. Charge duplicate resolved directories separately by logical key
(no physical-directory deduplication optimization). Initial, post-bind and final
passes each have that ceiling; three suffixes across all three passes have a
1,032,192 raw-entry ceiling, plus 49,152 UnitPath-map entries. Direct per-unit
rescanning would instead visit nine scopes per UnitPath, 147,456 entries per
suffix/pass, and is outside this proposal. These ceilings count shadowed,
invalid and dot entries too, not merely accepted dependencies. They are refusal
ceilings, not a claim that the selected host can finish within its deadline.
Preserve byte/name/path limits without truncation. Exhaustion fences.
The same arithmetic bounds logical directory enumerations to 704 per pass
(32 name-map plus 3×32×7 suffix directories), or 2,112 over three passes.
At at most 17 `getdents64` calls per present directory, that is 35,904 such
calls across those three passes. Absences and refusals may end earlier. This
excludes the separate `.d` overlay scans already performed during initial and
post-bind checks, whose final integration or sharing remains open. It also
excludes directory opens/reopens, metadata, link resolution, sorting, manager
requests and all other work; it is not a deadline or performance guarantee.

As a sizing check only, 16 nonempty reads of at most 4096 bytes across each
logical directory give a per-pass raw-dirent byte ceiling of 2,097,152 for the
32 UnitPath scans and 14,680,064 for each 32-by-7 suffix scan: 46,137,344 bytes
for one name-map plus three suffixes, before link targets, metadata, maps, stack
or descriptor ownership. Retaining all three passes as raw bytes would have a
138,412,032-byte raw-dirent ceiling. These are arithmetic upper bounds, not
allocations, a required retention strategy, or proof that any such strategy is
acceptable. Comparing raw `getdents64` buffers is not by itself a closed
semantic comparison: enumeration order and record layout are not the desired
winning-name or identity contract. An actual design must specify bounded
canonical observations and original-versus-later comparison, with its real
peak storage, stack and FD ownership, before implementation.

A compile-only sizing baseline, independently checked, is protected at
`g1-stack-sizing-20261125/` under the evidence root. GCC 13.3.0 with the recorded
private-qualification `-O2` flags reports a 16,816-byte `manager_unit_path`
frame and a 2,864-byte dynamic-bounded `rnr_stage0_prepare_held_inputs` frame;
its `input_owner` object symbol is 4,492,320 bytes. The 16,816 already includes
that function's local buffer, and the object-wide data total already includes
`input_owner`; neither should be added twice. The compiler inlined/transformed
other functions, and these are single-object observations, not a final linked
executable, call-chain peak, runtime resident measurement, host limit or evidence
that a proposed inventory fits. Any eventual solution must measure its actual
compiled call chain and account for other translation units and runtime limits.
The existing 4 MiB media-data buffer has no current preclaim accesses, but that
alone does not authorize reusing it: original observations must survive until
the final comparison, a 4 MiB aggregate inventory cap would be stricter than
the listed per-directory ceilings, and a media helper forks before the buffer is
overwritten. Any proposed reuse needs a reviewed encoding/refusal rule, phase and
failure ownership, and a timely clearing/data-lifetime plan before that fork.
Touching or clearing preallocated pages also has unmeasured runtime cost.
For scale, one suffix's 224 logical directories could each contain 150 distinct
valid names with 200 variable prefix bytes and a `.service` suffix: 33,600 names
and 6,720,000 prefix bytes, before metadata or links, while each directory remains
within the proposed entry and read ceilings. This example is not a proof that
every exact encoding needs that many bytes; it demonstrates why a universal
4 MiB fit cannot be assumed from the local limits. The calculation does not
authorize replacing original observations.
A generic temporary-directory fixture with 150 such-length names used nine
nonempty 4096-byte `getdents64` reads and returned 34,848 bytes including dot
entries; its protected receipt is `g1-stack-sizing-20261125/synthetic-dirent-fixture.json`.
It did not exercise systemd or the runner and does not prove compression limits
or actual-host compatibility.

Before treating this as implementation-ready, close the exact fixed storage and
stack/FD peak against the accepted native budget, unit-name/ignored-dirent grammar, mask handling for dangling links
and unsafe special files, and equivalence of winner selection to the selected
Ubuntu source. In particular, never open an arbitrary FIFO/device to determine
whether it is a mask. A relevance optimization may not omit a possible alias or
shadowing winner. No numeric memory allocation or new native dependency is
authorized by the raw-entry arithmetic above. Keep actual installed name map,
contents, `Wants`, running PID1 and timing compatibility as separate evidence.

**Owner decision, 25 November:** The owner explicitly allowed a 4 MiB aggregate
inventory limit using the existing buffer, provided complete original records
survive through the final check and overflow safely refuses. This is a scoped
acceptance of an additional refusal condition, not a claim that all inputs
within the per-directory ceilings fit, nor approval to activate a runner or run
a trial. Reuse, exact encoding and index/scratch accounting, comparison,
clearing before later fork, error/fence ownership and deadline feasibility
still require a concrete independently reviewed design before implementation.

#### Four-MiB exact-observation candidate

Status: **design for challenge, not implementation approval or gate closure**.
The single original admission owner may use the existing
`input_owner.data_bytes[4194304]` as a private arena until the final comparison.
Charge directory/presence rows, original entry records, names, required nofollow
metadata and link bytes, index tables, match marks and inventory-specific byte
scratch to those same 4,194,304 bytes. Reserve scratch before admitting records;
do not hide a second data-dependent array or allocate a heap/file. Every length,
offset, alignment and count operation is checked before use; insufficient space
fences without truncation, retry or partial acceptance. Fixed syscall argument
structures and call frames must also be accounted for in the separate stack/FD
and deadline proof. Existing per-directory and total-attempt limits still apply.

During the initial pass, append complete length-delimited observations under a
stable logical directory key and original search-priority rank. Preserve original
enumeration ordinals for evidence, and retain ignored and shadowed observations
where the contract requires them; every raw dirent counts toward its directory
limit. Store exact bytes, not digest-only substitutes. Directory rows include
original presence and required named/held identity, mount and ancestry evidence;
entry rows include the name and the exact type, metadata, link and classification
facts required by their respective roles. Resolve `DT_UNKNOWN` and relevant links
without opening arbitrary FIFO or device contents; any unproved classification,
path, relevant target or identity fences. Final field definitions and the set of
observations required for each entry type are not yet closed.

Stage initial capture: first scan the UnitPath name-map directories, index
their immutable original records, resolve relevant aliases and prove the
selected singleton name sets. Only then generate and scan the seven canonical/
type/prefix dependency scopes and build separately keyed per-unit/per-suffix
winner maps. This is still one scan per logical directory key, not an extra
filesystem pass. Sort a bounded array of offsets inside the same arena by
logical directory key and exact unsigned name bytes, with a fixed in-place,
nonrecursive algorithm; reject duplicate keys or inconsistent record framing.
Retain original ordered search ranks. Do not use lexical name order as directory
precedence, share a global winner map between units or suffixes, or discard
shadowed entries. Preserve the eight-lookup alias bound and existing singleton
policy. Exact winner/alias and manager identity predicates remain open.

At each later pass, check every logical directory once under the same bounds and
original clock. An originally absent directory must remain proved absent; an
absence/presence change, access error or uncertain parent identity fences. For
each present directory, apply the same still-to-be-frozen inclusion rule, find
each included entry's original record by key, compare the required fields and
exact bytes, and set a bounded match bit; duplicate, missing, extra, changed or
uncertain included entries fence. At EOF require every original included member
matched and exact counts, then clear only match bits for the next pass, never
original records. Every raw entry still counts against scan ceilings, and no
entry potentially affecting an alias or shadowing winner may be omitted. Freeze
which filtered or irrelevant entries must be retained and compared before
implementation; do not infer they are effective winners. Original order means
recorded directory/search precedence and retained enumeration ordinals for
evidence, not equality of later `getdents64` iteration order or padding. This
does not substitute for retained manager properties, cache/identity proof or the
final coupled sweep.

**Inclusion refinement for review:** In UnitPath name-map scans, retain valid
unit-name candidates and the selected scopes' relevant full cache paths, their
search ranks, normalized eligibility and shadow observations. The first
name-map winner must be an eligible regular file or symlink; a directory or
device with a valid-looking name is not itself a unit-name winner. Resolve all
potential winning aliases needed to prove the selected singleton, including
names that initially look unrelated. Cache-directory candidates are keyed by
their full UnitPath/scope path and must not be dropped merely because a basename
is shadowed in another path. Their relative symlink targets require the separately
unclosed manager-CWD/cache analysis.

For dependency directories, `suffix=NULL` and flags zero make every non-hidden,
non-backup basename a candidate regardless of entry type. Retain those names,
directory ranks and shadow status for each applicable unit/suffix map; a regular
file, mask, directory or special node can be the first basename winner. Once
all maps are determined, capture required nofollow/target metadata, link bytes
and mask/classification facts for any entry winning at least one map. An entry
proved shadowed in every applicable map has a complete original shadow record
consisting of its exact name, logical directory key, search rank, original
enumeration ordinal and per-map shadow classification. Compare its name, key,
rank and shadow classification on later passes; keep the ordinal as evidence,
not an equality requirement. Do not read or store its link target or treat its
unneeded dirent type as a comparison field solely for that shadow. An entry
that wins any map must instead have the required complete winner details, even
if it is shadowed in another map. If that path also serves a name-map or cache
role, retain and compare all observations required by that separate role.
Recompute all applicable winner/shadow classifications on each pass; a changed
earlier winner or uncertain cache/identity result fences. The
shadow-name comparison can fence on drift even when the current manager would
ignore that shadow; this follows the existing retained-drift requirement, not
the new size limit. All raw entries still count, `DT_UNKNOWN` is resolved
before filtering as required by the source, and an unproved relevant result
fences. These rules do not establish that an uncertain winner is inert.

An entry is **not** proved shadowed merely because an earlier matching basename
exists in the current filesystem. The manager's non-NULL path cache can omit
that earlier full directory path. Until its relevant membership is established,
the later entry may be a winner and its full applicable winner facts, including
link bytes, must be retained and compared or admission must fence. For example,
an earlier filesystem mask does not prove a later symlink is ineffective if
the manager might have skipped the mask's directory. Considering every possible
cache omission is a potential conservative design. On 25 November 2026 the
owner authorized a scoped refusal when an unprovable earlier cache membership
could expose an unexpected lower dependency; some safe configurations may be
refused. This decision does not reject all symlinks. The concrete algorithm,
target identities, resource cost and full soundness remain to be established;
the decision does not prove the manager graph or authorize activation.

Grouping winner-detail reads by logical directory can avoid another `getdents`
enumeration, but reopening/chasing/statting directories and reading links are
additional bounded I/O. Account for those operations and the original deadline;
compare reopened names, mounts, ancestors and identities to the original, never
refresh the baseline. The exact fields compared for ignored entries and shadowed
entries with other roles, inode-reuse protection, held-FD peak, and exclusive-maintenance
premise remain to be closed. A reopened matching inode alone is not a general
same-object proof. None of this establishes the live manager cache or graph.

Keep the original records intact through that final comparison. After they are
no longer needed, a fixed original-owner cleanup must clear the arena before any
later media helper fork or media use, including appropriate failure/fenced paths;
it must not race an active reader or erase evidence still required downstream.
The implementation must prove the clearing is not optimized away, that the
original deadline and once-only cleanup semantics are respected, and that later
media reads cannot consume stale inventory bytes. Overflow, sorting/comparison
cost, path/metadata resolution, actual stack and descriptor peaks, and final
manager/cache correspondence all need focused tests and independent review.
No feasibility, live-host compatibility or positive admission is implied.

Independent source examples for the proposed predicate (not executed tests):

| Input under a selected unit | Selected effect | Required conclusion |
| --- | --- | --- |
| Valid symlink `extra.service` in winning `.wants`, loadable target, successful add, no ordering directive | Adds `Wants=extra.service`; `After` may stay unchanged | Unexpected dependency rejects; failed/unknown target load is not proved absence |
| Winning `missing.service` symlink, no loadable fragment, and successful add to a distinct not-found unit | A dependency edge may still exist despite the failed target load | Do not treat the missing fragment or failed load as proof of no dependency |
| Earlier canonical basename and later generic basename point at different units | Earlier canonical entry wins even across UnitPath priorities | Classify the winning basename once; retain shadowed observation |
| Earlier `extra.service -> /dev/null`, later effective-looking same basename | Mask winner occupies basename; later entry is shadowed | No dependency from either entry; preserve proved mask, never fallback |
| High-priority anchor dash-prefix entry versus low-priority exact anchor entry, same basename | High-path prefix wins because recursion occurs inside each UnitPath call | Do not globally sort exact scopes ahead of every prefix |
| Low-priority exact anchor entry versus high-priority `slice.<suffix>` entry | Exact anchor wins; type scopes come after every canonical call | Do not globally sort UnitPath ahead of type specificity |
| High-priority empty/masked unit file versus lower valid fragment | Earlier map insertion wins; reverse map may omit the empty winner | No fallback to lower valid fragment |
| Seven versus eight ordinary alias edges before a terminal fragment | Seven plus terminal uses eight lookups; eight plus terminal exceeds FOLLOW_MAX | Enforce lookup iterations, never eight edges plus terminal |
| Additional effective launch-service alias has its own dependency directory | Filesystem reverse name set exceeds canonical singleton | Reject under existing `.Names` policy before relying on seven scopes |

Review outcome and next action belong in the current handoff. Do not call this
candidate a completed inventory implementation, a closed G1 gate, or a substitute
for the actual coupled pre-claim boundary and qualification.

#### Imported helper trace and Ubuntu patch boundary

Fresh retained-source research is protected at
`g1-inventory-helper-source-20261125/manifest.json` under the evidence root above.
Both original Ubuntu source and Debian-patch archive SHA256 values were rechecked
against `ubuntu-systemd-source-package-01a20fb2.json`. Nine helper files were read
from the original source archive, with original license headers retained outside
Git; all 85 active patch paths were scanned for those files. This is source
research, not compilation, runtime evidence, or new dependency adoption.

`dirent-util.h` distinguishes `FOREACH_DIRENT_ALL` (name-map scan) from
`FOREACH_DIRENT` (dependency-directory scan). The latter excludes dot-prefixed
names, `lost+found`, `aquota.user`, `aquota.group`, trailing `~`, and the exact
backup suffix list in `path-util.c:hidden_or_backup_file`: rpmnew, rpmsave,
rpmorig, dpkg-old/new/tmp/dist/bak/backup/remove, ucf-new/old/dist, swp, bak,
old and new. `readdir_ensure_type` resolves DT_UNKNOWN with nofollow/no-automount
metadata; only a vanished entry is skipped. A native observer must preserve its
own stricter uncertainty/identity refusal rather than assume DT_UNKNOWN means
irrelevant. Raw-entry ceilings count filtered names too.
For example, `.hidden.service` can be a valid name-map entry but is filtered
before dependency-list winner selection; an ignored entry cannot shadow a
later dependency-list basename.

`unit-name.c:unit_name_is_valid` and `unit-name.h` bound names to 1..255 bytes,
require a nonempty prefix and a recognized final unit-type suffix, and restrict
prefix characters to ASCII digits/letters plus `:-_.`, backslash and `@`.
The first `@` cannot begin the name; flags distinguish plain/instance/template.
Additional `@` characters can occur in the instance: `x@a@b.service` is valid
for `UNIT_NAME_ANY`. Do not add an “exactly one @” predicate from a source
comment. The four admitted canonical names remain plain fixed names. Validity
does not prove that a named unit loads or that the runner admits its identity.

`stat-util.c:null_or_empty` considers empty regular files **or any character
device** masks; it is not limited to `/dev/null`'s device number.
`null_or_empty_path_with_root` follows/stat-checks a path (with its direct
`dev/null` special case). A negative dangling/error result is not a mask in
`process_deps`; subsequent link/add processing can still be attempted. Design
mask observations around bounded path/link metadata, never reading/opening device
or FIFO contents. Unknown/unsupported resolution fences; it must not become a
proved inert entry. A template dependency is resolved with the source unit's
instance, or its prefix when it has no instance, before manager loading. The
actual effective target and loaded-unit identity remain separate questions.

Patch scan found two active patches touching `path-util.c`:
`CVE-2026-29111-1.patch` and `CVE-2026-29111-2.patch`. Their hunks alter
`path_startswith_full` and dot-dot handling, not `hidden_or_backup_file`.
Consequently the source-derived ignored-name list above is unchanged, but alias
versus linked-path classification must be traced through the **patched** path
helpers/callers. Do not promote the earlier top-level unit-file/dropin source
correspondence to equivalence of their entire helper closure. The extracted
helper files are explicitly original-archive bytes, not a patched build tree.
Retain this as an implementation-readiness gap alongside static memory/FD and
cache/target semantics; do not implement a known-unclosed approximation.

#### Follow-up: patched prefix helper, path cache and loaded-unit boundary

The retained source-package and patch archives were rehashed against
`ubuntu-systemd-source-package-01a20fb2.json`. Source and patch-hit manifest:
`/home/faris/.local/state/agent-runner/release-admission-20261119/autonomous-gate-helper-trace-20261125/manifest.json`.
These observations constrain the design; they do not close implementation or
prove the running manager's binary, cache contents or current unit state.

- In the original `path-util.c`, `path_startswith_strv` returns the first
  non-NULL result of `path_startswith` over the ordered expanded search-path
  list. In the two active path-util patches the wrapper changes from
  `path_startswith_full(..., true)` to flags `0` after inverting the dot-dot
  flag. The two patches were also applied in order, with `git apply --check`, to
  isolated copies of `path-util.c/h`; the copied results and digests are in the
  external trace manifest. Both versions request acceptance of dot-dot components; the
  other new flag requests a leading slash and is not used by this wrapper.
  This supports that specific wrapper call's flag equivalence, not equivalence
  of every helper or a reproduced patched build. `unit_file_resolve_symlink`
  first calls `chase` with `CHASE_NOFOLLOW | CHASE_NONEXISTENT`, then uses this
  first matching path prefix to classify alias versus linked file. It validates
  alias names and returns the destination unit basename for the map; a
  no-prefix linked file instead maps to the original source path. Errors can be
  skipped by the manager during map construction. A stricter observer must
  retain uncertainty and fence; it cannot infer absence from an error.
- In the retained `chase` userspace traversal, `CHASE_MAX=32` is predecremented
  before each followed symlink: at most 31 are read and followed, and the 32nd
  returns `ELOOP` before its readlink. A final component deliberately left
  unfollowed by `CHASE_NOFOLLOW` does not consume this count. The source-link
  read in `unit_file_resolve_symlink` precedes its separate destination chase,
  so it is not one of that chase's 31 follows. Each chase has its own counter;
  this is distinct from the eight name-map lookups above. Search-path expansion,
  drop-in directory resolution, alias destination chase and the relevant
  `conf_files_list_strv` directory chase request resolved paths and enter that
  userspace traversal. Other callers use direct kernel `opendir`/`stat` paths,
  including the null/empty stat shortcut, so do not impose this one counter on
  every operation or assume one `openat2` result proves identical traversal.
  The active Ubuntu patch scan found no `chase.c`/`chase.h` changes; transitive
  helper and selected-host equivalence remain separate.
- `unit_file_build_name_map` creates a path cache alongside name maps when
  requested. Its directory-name predicate accepts valid unit names or unit
  types ending in `.wants`, `.requires`, `.upholds` or `.d`. Directory entries
  and eligible directory symlinks can enter the set; the source checks the
  symlink target with `is_dir(target, true)`. The retained `stat-util.h/c`
  implementation calls `fstatat(AT_FDCWD, target, ..., 0)`, so a relative
  target is interpreted against the manager process current directory at that
  point, not by `dirfd(d)` in that call. This source observation does not prove
  the actual manager current directory or cache membership.
  `unit_file_find_dirs` consults the
  cache using the constructed original path and calls `chase` only when the
  cache is NULL or contains that path. An observer must not assume every
  filesystem-visible path is necessarily consulted by the manager. Resolve
  relative-target interpretation, path equality and cache membership proof
  against the full supported caller/host boundary before an equivalence claim.
- The map builder may reuse its existing maps when a hash of eligible lookup
  path mtimes matches. Its timestamp scan excludes generator, transient and
  control paths and skips failed `stat` calls; it is not a comprehensive
  snapshot of every dependency directory. `unit_write_setting` can add a
  manager-created drop-in directory to an existing cache. Cache construction,
  later mutations, reloads and the selected host's current cache remain
  separate facts. Neither a timestamp hash nor a fresh external scan establishes
  the manager's effective cache or proves a concurrent stable view.
- `unit_add_dependency_by_name` resolves templates, asks `manager_load_unit`
  for the dependency and then calls `unit_add_dependency` with the returned
  `Unit`. `manager_load_unit_prepare` can return an already loaded unit without
  loading disk again; automatic retry is restricted to certain previously
  not-found stubs. For newly queued units `manager_load_unit` dispatches the load
  queue and follows a merged unit. `unit_add_dependency` follows merged units
  on both sides and drops a resulting self-edge without an error, logging a
  warning for certain dependency types; its per-type dependency map is keyed
  by `Unit *` and combines origin masks for an existing edge. Thus even
  successful processing does not imply one distinct edge per entry basename.
  A dependency entry basename, the current
  filesystem target and the manager's actual `Unit` identity are distinct
  observations. Existing manager properties and exact source/held-state
  evidence must be coupled at the original pre-claim boundary; a disk-only
  reconstruction cannot independently prove the current effective graph.
- A failed target load does not necessarily prevent an edge. The retained
  `manager_load_unit` returns an existing unit directly or queues a new one,
  invokes `manager_dispatch_load_queue` and returns success. That dispatcher
  does not propagate `unit_load`'s individual error. A failing load can leave
  the target in `UNIT_NOT_FOUND`, `UNIT_BAD_SETTING` or `UNIT_ERROR`; the
  name-based addition checks the manager call's return and then attempts
  `unit_add_dependency` without a general `UNIT_LOADED` requirement. Thus an
  edge to a distinct failed-load unit is possible if the other checks and map
  allocations succeed. `UNIT_NOT_FOUND` is a state name, not proof every
  underlying failure was `ENOENT`. During reentrant dispatch a newly queued
  target may still be a stub at addition; later loading or merging can affect
  its identity and edge. Preparation, compatibility, identity or edge-addition
  failures can also prevent an edge. This is source analysis, not an observed
  state of an installed manager.
- The selected source's D-Bus getter for `Wants`, `Requires` and `Upholds`
  iterates the corresponding dependency map and emits each target `Unit`'s
  current `id` without checking its load state. If a failed-load target remains
  a map key when that getter runs, its ID can therefore appear in the property
  reply. This does not prove an edge survives loading, merging, garbage
  collection or reload, or that any particular live property has that value.

The active Ubuntu manager patches scanned for this trace change timezone path
handling and notification logging; the active load-fragment patch changes
`patch_var_run` logging. They do not alter the quoted cache or dependency paths
in those files. Other transitive helpers, relative path semantics, cache
lifetime/observability, canonical target identity, memory/FD proof, installed
host state and the pre-claim coupling remain unresolved. No claim of a closed
G1 gate or implementation-ready inventory follows. No manager query, provider
call, host activation or executable change was performed by this trace.


#### Successor refinement: cache uncertainty without enumerating cache subsets

Status: **bounded design candidate for independent challenge; source and physical
acceptance remain open**. This specifies the owner-approved conservative refusal
more narrowly. It neither proves the manager cache nor changes the 324 requests.
Main remains the sole writer; RNR-D00 and UNKNOWN ownership/counter values persist.

For one selected unit and dependency suffix, generate the existing ordered scope
list only after the selected singleton name proof. Each logical directory has a
cache-eligibility state: proved consulted, proved skipped, or unknown. A state
requires evidence about the manager's relevant cache at this admission interval;
filesystem existence, a directory mtime or a fresh observer scan cannot establish
it. NULL cache means the source does not apply the cache-membership filter; it
does not establish successful directory resolution. Current work has no proof of
any installed cache state. Resolve presence, paths and classification separately;
any uncertain relevant observation fences as already required.

For every eligible dependency basename, walk its directory occurrences in actual
scope/search precedence. Ignore only a proved-skipped occurrence. An occurrence
in an unknown directory is a **possible first winner** unless an earlier proved-
consulted occurrence of that basename necessarily occupies the winner map. Include
that possible winner's complete applicable facts. The first proved-consulted
occurrence is itself a possible winner and ends this walk; later occurrences are
proved shadowed for this map. A filtered basename never occupies the map. The
proof that a consulted occurrence occupies the map also needs the source's actual
successful listing/classification premises; a cached directory name alone is not
that proof. Allocation/read/identity uncertainty is not an inert classification.

This is a conservative union over possible winners, computed by one ordered walk,
not a powerset of cache contents. It can admit a configuration whose cache is
unknown when every possible winning occurrence has independently proved harmless
or accepted effects. It can refuse a safe configuration when an omitted earlier
mask could expose an unexpected lower dependency, as the owner approved. A mask,
ordinary non-symlink or invalid dependency name can occupy the basename without
adding an edge under the traced source predicates; a symlink is not rejected just
because it is a symlink. A potential dependency with unproved target/addition
identity remains uncertain, including a failed-load or merged unit. Do not
substitute its basename or current filesystem target for the manager's Unit ID.

Retain every attempted addition and its independently proved possible identity
set. Before acceptance, each possible added identity must belong to that selected
unit/suffix's exact accepted expected set. This subset condition does not prove
the entire expected graph: configured/implicit dependencies may add members absent
from these directories, and masks/no-add cases may omit them. Require exact
initial equality for the original property matrix and final equality only for
the fixed 44-request matrix, whose dependency rereads are Wants only. Names,
Requires and Upholds are not reread finally; their continued validity depends on
the unchanged-manager/autonomous-action exclusion premise. Complete configuration/
automatic-addition semantics and target/loaded-unit correspondence also remain
mandatory. Several names coalescing to one Unit must
retain their distinct entry observations; wire-array duplicate refusal remains a
separate rule. No expected Wants set is invented by this procedure.

A physical entry used by multiple selected-unit maps retains the union of their
roles. Full facts are required if it is a possible winner in any map, even if it
is proved shadowed in another. Only an entry proved shadowed in every applicable
map, with no independent name-map/cache role, qualifies for the earlier compact
shadow-name record. At each later comparison recompute these classifications
against the original evidence; do not turn an unknown membership into a proved
one from the new filesystem pass. Preserve complete original observations and
refuse on changed or uncertain facts. This refinement supersedes any reading of
the earlier single-winner wording that treats an unproved earlier cache entry as
sufficient to omit a lower candidate's target facts.

| Ordered occurrences of one basename | Cache evidence | Required candidate result |
| --- | --- | --- |
| Earlier mask, lower unexpected symlink | Earlier unknown, lower not proved skipped | Retain both possible winners; the unexpected possible edge refuses |
| Earlier mask, lower unexpected symlink | Earlier proved consulted and occupying the map | Earlier mask is the only possible winner; retain lower shadow name |
| Two symlinks, each independently mapped to an accepted identity | Both unknown | Both full observations required; cache ambiguity alone does not refuse |
| Earlier filtered backup, lower unexpected symlink | Any | Backup cannot shadow; unexpected possible edge refuses |
| Earlier ordinary file, lower dangling symlink | Earlier unknown | Dangling target is not proved edge absence; uncertainty refuses |
| Same entry wins one map and is shadowed in another | Per-map evidence differs | Retain full facts and both per-map classifications |

#### Successor refinement: arena lifetime and owner cleanup

Status: **design candidate; not implemented**. Use the existing media data array,
with no heap, temporary file or second data-dependent buffer. Keep inventory
lifetime separate from `data_length`, which belongs to later media reads. Inventory
state is private to the original preparer owner: EMPTY -> BUILDING -> RETAINED ->
COMPARING -> RETAINED (post-bind only), then COMPARING -> CLEARING -> CLEARED after
the final preclaim comparison. Any failed/incomplete step fences; there is no
reset, recapture or reuse of an inventory baseline within the attempt.

All directory/entry/path facts, name/link bytes, offset indexes, match flags and
inventory scratch are charged to the same 4,194,304-byte array. Initial records
are immutable after publication; only explicitly separate comparison marks and
scratch may change. Offsets and sizes are checked before arithmetic, alignment,
index access and insertion. Refuse before any write crossing the reserved regions;
never publish a partially recorded member. Freeze exact C field layout, scratch
reservation and full path/identity evidence before code; the previous candidate
has not yet closed these and this lifetime refinement does not pretend otherwise.

After the successful final comparison, the original owner clears the WHOLE array
before first latch/claim mutation and before any later helper fork. This retires
only the in-memory inventory; it does not erase protected runtime evidence, claim
bytes, original installation/task/policy bytes or resources. Those independently
needed objects remain in their existing storage. A successful clear is a required
precondition of later media preparation; later media reads set their own length
and cannot infer inventory retirement from `data_length == 0`.

Use the existing owner/fencing/once-drain discipline. Losing, foreign or reentrant
calls may fence atomics but may not erase a buffer still used by its owner. The
owning failure/abandon path invalidates inventory continuation and clears private
bytes before it returns to the fixed abandon/exit125 wrapper. No failed, expired
or partially cleared inventory permits a media helper or another acquisition.
Clearing uses compiler-preserved writes in bounded chunks under the original
setup-clock checks on the success path. If a check expires during clearing,
retain the initiating failure, complete only private-memory/descriptor cleanup
and exit; do not treat completion of cleanup as a fresh positive grant or wait
for external work. This makes no scheduling or post-deadline resource-effect
claim. The final compiled artifact must demonstrate that erasure survives
optimization and that no fork bypasses its completed-state check.

Current-source trace: admission acquisition publishes
`PREPARER_ADMISSION_INPUTS_HELD`; the fixed wrapper immediately abandons it and
exits125. `drain_inputs` owns descriptor cleanup, while later legacy media helpers
fork before `media_pad` first fills `data_bytes`. Thus overwriting on media read
is too late to prevent inheritance. The future coupled owner must join inventory
retirement to the held-to-preclaim transition, not merely insert a memset in
`media_pad`, erase in a losing abandoner, or enable legacy preparation from the
admission-held state. Revision B storage preparation stays unchanged until that
whole authenticating boundary is closed.

Required focused proof before source acceptance: complete records survive both
comparisons; exact overflow refuses without overwrite; reordered enumeration is
accepted but missing/extra/duplicate/changed included records refuse; possible-
winner facts are retained under cache ambiguity; once-owner clearing covers
capture, comparison, expiry and abandon failure paths; and no later helper fork
can inherit inventory bytes. Stack/FD/call costs and actual original-deadline
feasibility remain open. These candidates close no G1–G6 or operational gate.
