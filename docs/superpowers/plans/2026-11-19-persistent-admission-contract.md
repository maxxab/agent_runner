# RNR-D00 persistent admission and late containment contract

Status: coupled admission remains a proposal; Revision B storage preparation is
implemented and independently reviewed, but uninvoked. No operational path, unit
or runtime effect is authorized by this document. Main is sole writer.
Canonical workflow: /home/faris/development-standards/docs/development-document-workflow.md.
Refines F1/F2/F5 in the selected143 admission review; all five release gates OPEN.
Existing historical stores and attempts remain untouched at their original paths.

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

A keeper death before READY kills Main via its original PDEATHSIG while the workload
ancestor remains frozen; after READY the independent observer retains original
negative ancestor authority. Main death during construction leaves no thaw. Lost
READY/thaw ACK is fenced with no resend/replacement; held controls and durable latch
remain. Kernel effects from already-armed PDEATHSIG do not introduce a new userspace
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
