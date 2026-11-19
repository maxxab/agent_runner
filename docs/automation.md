# Advisory automation preview

The optional `agent-runner` commands implement the source-only portion of RNR-D01 in the [runner plan](superpowers/plans/2026-11-09-shared-ai-development-workflow.html). They use Python's standard library and local Git. They do not start an agent, run checks, access GitHub, install anything, create enrollment, publish work or change credentials/settings.

```sh
agent-runner doctor --project /path/to/project --enrollment /private/operator/enrollment.json
agent-runner preview --project /path/to/project --enrollment /private/operator/enrollment.json --snapshot /path/to/snapshot.json
```

`doctor` validates pinned configuration and required documents, then reports runtime **unavailable**. `preview` reports source candidates and reasons for exclusions/blocks. Both always report `execution_enabled: false`. `selected` is always empty; `candidate_order` is a bounded advisory ordering, not authorization to dispatch. Exit 0 means a diagnostic report was generated, not that runtime or work is ready. Invalid input returns exit 2 and a JSON error on stderr.

The current private-enrollment permission check supports POSIX filesystems (tested on WSL2 Ubuntu). It fails closed on native Windows. Real GitHub behavior, other platforms, SDK dispatch and the full runner are not validated by these commands.

## JSON input boundary

Enrollment, pinned configuration, snapshots and injected GitHub response bytes
must be UTF-8 JSON. A leading UTF-8 byte-order mark remains accepted and counts
against the original byte limit; UTF-16/32 and malformed UTF-8 are rejected.
Duplicate object keys and all nonfinite numeric results are rejected, including
exponent values such as `1e400` that overflow the parser's floating-point range.
Finite floats keep Python's existing rounding/underflow behavior; schema fields
that require integers still reject them. No encoding detection or conversion of
other encodings is attempted. These checks do not authenticate input or enable
runtime execution.

## Approval boundary

The project argument must be the actual Git worktree root; subdirectories are rejected before enrollment validation. An operator supplies an existing private file outside that worktree. Its direct parent directory and file must be owned by the current operator and inaccessible to group/other users; symlink paths are rejected. The file pins a full Git commit ID and the SHA256 of the exact configuration bytes at that commit. Candidate working-tree configuration is ignored. Required documents are read from the same commit as bounded regular Git blobs, with no hooks/filters.

This is a local operator trust boundary, **not** cryptographic proof that a person approved work. A process running as that operator could alter the file. This source tranche provides no isolated execution authority. Issue content, labels, arbitrary self-generated hashes, or a closed issue cannot create approval. Production admission must establish authenticated provenance and isolation separately.

The CLI does not generate these files or approve their contents. Do not enroll a repository merely to make a diagnostic pass. The following is a schema illustration, not a valid approval.

### Configuration version 1

The approved commit contains `.agent-runner/automation.json`:

```json
{
  "schema_version": 1,
  "repository": "owner/project",
  "target_branch": "main",
  "runner_host": "exact-hostname",
  "approvers": ["maintainer-login"],
  "documents": ["docs/product/prd.md"],
  "required_checks": ["unit"],
  "selection": {
    "labels": ["ready"],
    "priorities": ["priority:high", "priority:normal"],
    "max_candidates": 1
  }
}
```

All fields are required, unknown fields are rejected, and boolean values do not count as integers. Repository and host must match enrollment and the current hostname. `documents` and `required_checks` are nonempty unique lists. Check names are declarations only: this phase does not execute or verify their results. `labels` are all-of selectors, never approval. Priority is the first matching configured label, then UTC creation time, then issue number. Candidate capacity is 1–100.

### Operator enrollment version 1

```json
{
  "schema_version": 1,
  "repository": "owner/project",
  "base_revision": "<full 40- or 64-character lowercase commit ID>",
  "config_sha256": "<64-character lowercase SHA256>",
  "runner_host": "exact-hostname",
  "approvals": [],
  "accepted_dependencies": []
}
```

Each approval requires `issue` (positive integer), `scope_sha256`, `approved_by` (in configured approvers), `acceptance_ids` (nonempty unique list), `expires_at` (explicit UTC timestamp), and `decisions_resolved` (boolean). Missing/expired approval, changed scope or unresolved product decisions block candidacy. The scope digest is SHA256 of UTF-8 JSON for `{"body": body, "title": title}`, sorted keys, compact separators and unescaped Unicode; labels/status are deliberately excluded. Approval records are unique per issue within the enrolled repository. This digest does not bind native dependency identities: preview evaluates the currently supplied graph, not an approved immutable graph.

Each accepted prerequisite requires `issue`, `scope_sha256`, `result_sha256`, `accepted_by` and `closed_at` (explicit UTC). The issue must also be observed closed with reason `completed`, identical requirement scope and identical closure time. `not_planned`, missing/inaccessible evidence, stale closure, cycles and unenrolled repositories block dependants. A result hash is an operator acceptance reference, not independently verified execution evidence. This preview never treats closure alone as acceptance.

## Normalized snapshot version 1

A snapshot is untrusted sampled data, not a live readiness guarantee. The CLI reads a bounded regular JSON file without following its final symlink. It never interprets issue text as instructions. Issue titles and bodies must be UTF-8 encodable after JSON decoding, even when the issue lacks approval or is excluded from selection. Escaped lone surrogates are rejected before dependency reads or scope hashing. Valid Unicode, decoded surrogate pairs and empty bodies retain their existing meaning and digest; no normalization or replacement is applied.

```json
{
  "schema_version": 1,
  "repository": "owner/project",
  "fetched_at": "2026-11-10T00:00:00Z",
  "issues": [
    {
      "repository": "owner/project",
      "number": 1,
      "title": "Example requirement",
      "body": "Observable acceptance requirements",
      "created_at": "2026-11-09T00:00:00Z",
      "state": "open",
      "state_reason": null,
      "closed_at": null,
      "labels": ["ready"],
      "dependencies": []
    }
  ]
}
```

All issue fields are required. Native dependency identities use `owner/project#123`. `dependencies: null` means unavailable, never no prerequisites. Include dependency nodes as well as candidates. Issue identity duplicates, malformed timestamps, future/inconsistent observations, unsupported versions and unknown fields fail closed. Limits are 1,000 issues, 10,000 total dependency edges and a 16 MiB snapshot. There is no freshness SLA in this offline preview; the report carries the sampled timestamp and cannot authorize execution. Later live dispatch must revalidate current authority and evidence.

## Read-only adapter contract

`automation.github.snapshot(repository, get, fetched_at=...)` accepts an explicitly supplied GET function returning `Response(status, body_bytes, headers)`. There is no default HTTP client or enabled credential lookup. Authorizing a later transport is separate from offline source testing.

The adapter normalizes paginated REST issue listings and native `/issues/{number}/dependencies/blocked_by` responses. It follows only the exact next page on `https://api.github.com`, retaining repository, endpoint and query scope, and stops at ten pages per endpoint. Cross-origin/scope links, loops, contradictory next/last relations, duplicate identities and malformed/incomplete responses fail closed. An advertised last page remains binding across later responses. Inaccessible dependency endpoints yield explicit unavailable evidence, including a denial after a successful earlier page. Foreign dependency identities remain visible as blockers but are never fetched. Pull requests from the issue-list endpoint are excluded.

Offline fixtures test the contract; they do not prove live endpoint access, authentication, complete current GitHub state or production isolation.

### Disabled live-preview source

`preview --live` is mutually exclusive with `--snapshot`. It validates local
context, then returns `live_not_authorized` without constructing a process backend
or accessing credentials/network. Local validation failures return
`live_context_invalid`; live errors never use the offline exception-text printer.

The synthetic path in `live_preview.py` connects the bounded context/result
contracts to the adapter and advisory selection. `github_transport.py` checks
exact repository routes, one dependency authorization callback, strict HTTP
framing, request budgets and private helper configuration. `live_io.py` drives
nonblocking primitives with short reads/writes, byte limits, original deadlines
and cleanup evidence. Failed transfers retain observed counters but discard
captured bytes; missing or invalid worker envelopes report unknown HTTP counts.
Parent scheduling and worker computation are tested separately with memory-only
peers, without claiming that a fake process proves CPU preemption.

This implementation remains self-verified. `PosixKernel` contains process,
selector, core-limit and cleanup operations; its normal constructor still denies
and no production factory exists. `PosixWorkerChannel` now implements the
worker's inherited stdin/stdout connection with bounded nonblocking I/O and
one-shot descriptor closure. Construct that channel only inside a disposable
worker, because it owns and closes descriptors 0 and 1.

The opt-in Linux qualification suite runs credential-free Python children:

```sh
RUNNER_POSIX_QUALIFICATION=1 python3 -m unittest discover -s tests -p test_automation_live_posix_qualification.py -v
```

It exercises large framed transfers, trailing-byte rejection, output overflow,
forced timeout cleanup, a separate header pipe, child-only core suppression,
and the parent/worker pipeline across real processes using synthetic GitHub data.
The default suite skips these seven operational cases. Memory-only fault tests
cover ambiguous closure and deadline crossing. These checks do not establish
all descendant/process-identity cases, production launch authorization, or
independent acceptance. Public live entry points remain disabled.

Local GitHub credentials may be kept in the ignored `.env.local` file as
`GH_TOKEN`, with owner-only permissions. It is not loaded automatically, and
must never be committed. The live transport deliberately removes token
variables from helper environments; an approved credential-provider setup is
still required. Do not copy GitHub App private keys or unrelated secrets merely
to run a read-only preview.

## Source-only cumulative observations

`automation.accounting.summarize_cumulative_usage(events, expected_streams)` is an early RNR-D03 pure projection for synthetic normalized records. It is not wired to CLI execution or an SDK and performs no I/O. The [same runner plan](superpowers/plans/2026-11-09-shared-ai-development-workflow.html#d03-usage-projection) defines its strict version-1 input contract and bounds.

It keeps each declared session's highest observed total-token counter across resumed turns and deduplicates identical event identities. Unknown observations, conflicting identities, missing sessions and lower/reordered counters stay visible; later numeric values do not erase those reasons. The sum of known maxima is named `observed_tokens`, not verified spending or a complete total. Explicit zero remains distinct from unavailable data. Declared source/session identities and supplied evidence hashes do not prove attribution, non-overlap or coverage; references are never fetched or verified by this function.

Every output has `execution_enabled: false`, `complete: false`, `total_tokens: null` and `coverage_unverified`. Deltas, mixed modes and multiple source namespaces are rejected in this first version. The function cannot clear holds, release reservations, change deadlines, decide remaining allowance or authorize retry/dispatch. Full runtime accounting and recovery remain unimplemented; the bounded source-only observation journal below preserves only a fixed declared set.

## Source-only SQLite observation journal

`automation.usage_journal` provides `initialize(connection, expected_streams)`,
`append(connection, events)` and `summarize(connection)` for a fixed declared set
of streams. The caller supplies an already-open, trusted, dedicated SQLite
connection, owns its private storage and lifecycle, and grants exclusive use
within each call. Nothing in bootstrap/CLI opens or uses a journal. This source
module adds no SDK, credentials, runtime access, billing or dispatch authority.

Initialization is explicit and rejects an existing database, even an identical
journal. Expected streams are immutable. Append validates its whole raw batch,
then the combined records before writing. Exact complete-record replay is inert;
conflicting identity variants retain first-insertion order and uncertainty.
Successful append returns `None` after commit. Summarize returns the existing
incomplete projection. Capacity is 1,000 streams and 10,000 distinct complete
records; exhaustion rejects the entire batch without pruning or resetting usage.

Every operation rejects a preexisting caller transaction without touching it,
nondefault row/text factories, attached databases, temporary objects, unsupported
schema/markers, enabled `read_uncommitted` and unsafe journal/synchronization
modes. The isolation setting is rejected before beginning a transaction, even
without shared cache. It never reconfigures those settings. Schema and canonical
persisted records are revalidated. Writes
use explicit SQLite transactions; summaries use one committed read snapshot.
SQLite shared-cache dirty reads are unsupported: uncommitted observations must
not appear in reports and then disappear after another caller rolls back.
Exceptions and interruption attempt rollback; a rollback failure preserves the original
error context. Invalid contracts raise `ValueError`; storage errors propagate.
A failed commit can leave an uncertain outcome: inspect the existing journal
before deciding whether to repeat an operation. No retry is automatic.

The journal is not a global run ledger and does not allow adding new expected
sessions, clearing a hold, releasing a reservation, extending a deadline or
claiming complete usage. Connection/schema validation is not a security boundary
against an operator forging/replacing the database. Temporary-file reopen and
rollback tests do not prove physical crash durability, trustworthy attribution,
filesystem privacy, backup recovery, network-filesystem support or cross-host
failover. Production enrollment/storage and live integration remain deferred.

## Disabled-runtime refusal callback

`automation.callbacks.reject_server_request(method, params)` is a pure,
side-effect-free helper for possible future explicit SDK callback injection.
It cancels command/file approval requests, returns an unsuccessful fixed-text
response for dynamic tool calls, and raises `UnsupportedServerRequest` for
other or malformed direct requests. It never inspects or echoes request payloads,
accepts claimed authority, calls an SDK/client, starts work or waits for a reader.
The response dictionaries are fresh each time. No running SDK is changed and no
CLI/dispatch path imports it.

This is intentionally not a complete SDK adapter or a solution to the existing
callback-reader deadlock. The pinned async client wraps the same synchronous
client, so selecting it alone would not solve that problem. The pinned SDK also
bypasses callbacks for non-string wire methods and converts non-dict parameters
to None; this helper's strict direct-input checks do not validate that wire path.
An exception or cancel response does not prove a runtime or descendant stopped,
or that its allocation was released. Those admission, lifecycle and wire-level
integration gates remain unresolved; the [existing plan](superpowers/plans/2026-11-09-shared-ai-development-workflow.html#disabled-runtime-callback)
contains the pinned source and protocol references. Tests here invoke only the
pure helper and consume no SDK/model allowance.

The [supported control proposal](superpowers/plans/2026-11-09-shared-ai-development-workflow.html#d00-supported-control-decision)
compares retaining this pinned SDK with a direct-mode app-server stdio adapter.
The source proposal was independently reviewed after two design corrections.
The user accepted the recommended source-only transport/tool topology on
14 November 2026. The integrated source evaluation is described below. The
[source implementation closeout](superpowers/plans/2026-11-09-shared-ai-development-workflow.html#source-implementation-readiness)
permits the bounded integrated source path with synthetic peers; full runtime
qualification and D02 execution remain blocked. Neither option establishes authenticated child creation,
alternate-start prevention or runtime acceptance. Execution remains disabled.

## Source-only integrated direct control

`automation.control`, `control_store`, `control_transport`, `control_bootstrap`,
`control_supervisor` and `control_workspace` provide the disabled synthetic
bootstrap-to-workload source path. The CLI does not import or activate it.
Operational constructors refuse; explicit synthetic factories accept protected
fixture operations. Caller-supplied fixtures are not authenticated runtime
identity, physical isolation or permission to start a real executor. The
[current handoff](handoffs/2026-11-09-autonomous-workflow-planning.md) records
implementation and independent acceptance status separately.

The private dispatch client supports `begin_dispatch(action)` followed by
`finish_dispatch()` so the original main thread can drive its receiver between
the two calls. The blocking `dispatch(action)` method still performs both.
Begin retains one fresh Store request and its original deadline; finish consumes
it once and validates the response, including protected result readback. Neither
phase returns a reusable dispatch capability or renews the deadline. A second
begin while pending, missing or repeated finish, uncertain send, late response
or failed readback fences the client and leaves capacity occupied.

`control_runtime_consumer._complete_retained_start(client, receiver)` joins the
existing frozen-start operations: deliver the retained historical receipt,
consume and compare its protected client result, then release the descendant.
It retains the receiver's pending request and attachment. Failure before release
prevents its invocation; failure during release retains UNKNOWN effects and
triggers containment. Client management-endpoint closure can precede containment;
receiver workload-handle cleanup follows ancestor containment. The same-thread
sequence cannot independently enforce a timeout while receiver work blocks, so
whole-lifecycle supervision remains mandatory. This private seam is not the
missing complete qualification entry or evidence of live workload acceptance.

Frozen descriptor acquisition additionally requires kernel `KCMP_FILES`
equality between the original leader and each task, before and after its
inventory. Every admitted epoll watch requires `KCMP_EPOLL_TFD` equality with
the current target descriptor. Matching inode/device metadata alone is
insufficient for anonymous files. These read-only queries add no descriptors;
denial, unsupported queries or unequal relationships reject acquisition without
a fallback. They establish relationships at observation points, while original
task provenance, freeze containment and the complete supported resource profile
remain separate requirements. Caller-owned kernel probes do not establish
permission to query the actual workload.

The frozen fdinfo parser also understands bounded Linux 6.18 inotify metadata:
at most 64 unique watch descriptors and device/inode pairs, exact event masks
and flags, and an optional export handle of at most 128 bytes. Canonical kernel
spacing and hexadecimal spelling are required. This is data parsing only;
frozen workload acquisition still rejects inotify descriptors. Matching watch
metadata does not establish filesystem ownership or grant access to a watched
object. Actual profile admission remains a first-release prerequisite.

Native launch-media helpers arm a parent-death `SIGKILL` before root/descriptor
setup and check the copied original parent's identity after arming and before
exec. They also verify the signal setting immediately before exec. A lost
parent or failed check prevents helper exec. This protection does not extend to
forked descendants; post-exec preservation requires the actual immutable helper
credential/metadata audit. The independent containment observer retains its
separate lifetime. These checks do not supply the missing whole supervisor.

Contained policy v3 supports exactly two UID/GID pairs: legacy `65534:65534`
and selected `2147483000:2147483000`. Supervised v2 remains legacy-only. Docker
User, private-home ownership and all frozen credentials must match the same
validated original policy. Legacy serialization and digests remain unchanged;
the selected identity changes its own policy digest, and older readers may
reject it. No account, reservation or isolation proof follows from that number.
The planned confined resource profile additionally needs actual outside-identity
and acquisition-route exclusion before first app exec. This policy extension
does not admit sockets, inotify descriptors, writable files or new mappings.

The Store owns one SQLite worker and transaction boundary. Schema v3 adds runtime
reservations, session bindings, ownership acknowledgements, workspaces and typed
cleanup/fence evidence to existing turn and command accounting. Existing v1/v2
stores are refused without migration or reset. Runtime and workload inventories
are separate; pending and UNKNOWN reservations occupy capacity. Reviewer capacity
is reserved through admission limits, not invented review evidence. No separate
operation/hold/usage journal becomes another admission authority.

Bootstrap reserves capacity before the supervisor receives a ticket. Its fixed
private handshake validates the reviewed initialization, effective-policy and
fresh-thread observations before Store commits a binding and assignment. An
ordinary owner must acknowledge the exact task packet, resources, role and owner
version through one charged ownership-acknowledgement turn before work is admitted.
That turn cannot run commands. Host acknowledgement is main-only. Missing or lost
bootstrap/acknowledgement evidence cannot justify another creation or replay.
The legacy direct-registration and boolean-cleanup routes refuse.

Runtime and workload policies are immutable typed records with validated digests,
normalized resource paths, fixed quotas and the original Run deadline. Supervisor
registration receives the committed full policy, not a hash needing an ambient
lookup. Runtime has no project mount; owner workloads use the declared workspace,
while reviewer workloads require a frozen read-only snapshot and separate output.
These are declared synthetic recipes, not proof of real mount or alias isolation.

The transport validates bounded UTF-8 JSONL before normalization and rejects
ambiguous envelopes, duplicate keys and nonfinite numbers. Inbound request IDs
remain separate from outbound correlation. The only custom request is
`item/tool/call` for `rnr_command` with exactly `{argv: list[str]}` arguments.
The reviewed pinned profile adds only bounded bootstrap and turn/item observations;
messages, plans and reasoning never grant authority. Unexpected effectful tools,
configuration warnings, wakes or unknown fields fence. A byte sink must consume
the complete frame and return `None` (all-or-raise) or its exact byte count;
short/invalid writes fence without retry.

Turn admission retains immutable `TurnPolicy` and separate logical turn capacity.
`start_turn(assignment_id, intent_id, text)` commits its charge and dispatch marker
before one fixed `turn/start` frame. Protected model/effort, Full Access/never,
empty environments and runtime workspace roots remain fixed. A validated correlated
response binds the server turn ID before command admission. Both legacy
`reserve_turn` routes refuse. Identical intent retries return durable status
without charging or sending again; conflicting input fences. Terminal completion
releases a logical slot once without refunding cumulative allowance or releasing
physical allocations. Conflicting evidence and stalled evidence persistence remain
visible; logical accounting never proves physical cleanup.

Each command gets a distinct workload reservation. Dispatch commitments and actual
submission observations are recorded separately: a fence cannot infer no effect
merely because submission was not observed. Complete typed cleanup evidence must
resolve every commitment and match the exact instance and supervisor epoch before
capacity is released. No-create release also requires a persisted irreversible
launch closure; an absence observation alone cannot retire a launchable ticket.
Materialized cleanup must follow the potentially effective operation receipts.
Healthy workload cleanup does not fence its runtime.
Contradictory evidence after release creates a persistent run-wide admission hold;
cleanup remains available, but there is no automatic unhold.

Workspace freeze first commits a seal closing writer admission. Store persists
supervisor fence receipts and returns references distinct from the seal transition
and supervisor-local sequence. Freeze requires the exact owner/seal, recorded
fences for every sealed writer generation, and committed release evidence for every
writer allocation. Manifest/base/configuration/plan identity is checked before the
frozen candidate becomes review input. Unrecorded fences and partial cleanup do
not authorize a snapshot. Authorized output changes produce a new retained
manifest while protected base/configuration/plan identity and the original owner
packet remain unchanged. A separate immutable reviewer authorization binds its
own packet and resources to that committed snapshot; every positive admission
rechecks it, and recovery revokes it without crediting uncertain allocations.

Negative fencing uses supervisor-local state independently of blocked Store,
output or external operations. The original deadline cannot be extended by later
registration. Store also persists generation fences before session binding, so
a delayed bootstrap completion cannot restore positive authority. Already committed operations can materialize late and remain UNKNOWN
until reconciled; source checks do not establish a physical no-late-effect guarantee.
Restart fences recovered runtime/workload authority, preserves charged allowances
and the original deadline, and never adopts or replays uncertain work. A controller
close does not erase unresolved supervisor receipts or imply completed cleanup.

Physical containment, installed-runtime policy closure, authentication, actual
usage and native child lineage remain separate qualification gates. No consumed
runtime allowance is renewed. See the
[bootstrap/supervisor contract](superpowers/plans/2026-11-09-shared-ai-development-workflow.html#d00-bootstrap-supervisor-source)
and the preserved
[turn-admission contract](superpowers/plans/2026-11-09-shared-ai-development-workflow.html#d00-turn-admission-source-plan).

## Source-only operation journal

`automation.operation_journal` preserves one recorded execution attempt for each
logical operation in a caller-owned, trusted, dedicated SQLite database. Its
`initialize(connection, run_id)`, `register(connection, intent)`,
`record(connection, receipt)` and `snapshot(connection)` functions perform no
SDK, network, CLI, dispatch or external reconciliation. The caller owns the
connection, private storage and lifecycle, and grants exclusive use during a
call. Both journals share the same connection/transaction validation helper;
the usage journal's schema and public API are unchanged.

The [canonical contract](superpowers/plans/2026-11-09-shared-ai-development-workflow.html#d03-operation-journal)
defines exact intent and receipt fields. A fixed run contains at most 1,000
intents and 10,000 receipts, each limited to 32,768 bytes of canonical JSON both
on input and reload. Inputs are captured before validation and SQLite callbacks, so later caller
dictionary changes cannot diverge from the serialized record. Request IDs bind
immutable intent. The logical key is
repository, issue, delivery-attempt ID and action; it cannot acquire a second
request ID. Receipt IDs are globally immutable. Exact replay is inert after
complete stored-history validation, including after terminal state and at
capacity. Changed reuse, malformed history and unsupported schemas fail without
repair or mutation.

An intent begins `pending`. A `start` receipt records `in_flight`; a `result`
from that state records `confirmed`, `failed` or `unknown`. A `reconciliation`
receipt can resolve `in_flight` or `unknown` to any of those three outcomes.
Unknown cannot reset to pending or in-flight, and confirmed/failed are terminal
in this version. Receipts require an existing request, and intents must match
the journal's run. Complete ordered histories survive reopen.

These states are caller-declared observations, not authenticated proof of a
remote effect. Evidence references are stored but never fetched. Snapshot
always reports `execution_enabled`, `dispatch_permitted` and `retry_permitted`
as false. In-flight/unknown operations require reconciliation before any future
retry decision. No API schedules a retry. Supporting future retries requires a
reviewed extension or migration that preserves the logical request and history;
a new delivery-attempt ID is not a workaround for an uncertain outcome.

Writes use explicit transactions and rollback on exceptions/interruption. A
failed commit can have an uncertain outcome, so read back before considering
any replay. The journal does not authenticate callers, verify request hashes or
evidence, establish physical crash durability, coordinate hosts, grant
execution authority, or renew any allowance. No runtime path uses it yet.

## Source-only hold and deadline journal

`automation.hold_journal` provides `initialize(connection, run)`,
`record(connection, event)` and `snapshot(connection)` for a trusted,
caller-owned dedicated SQLite database. The [canonical contract](superpowers/plans/2026-11-09-shared-ai-development-workflow.html#d03-hold-journal)
defines its exact normalized fields and limits. It stores the original run ID,
UTC start and deadline unchanged; there is no reset, extension or clock-based
admission API. Reinitialization of an existing database is rejected.

Each hold has an immutable ID. A release names that existing active ID and must
match its run and exact run-wide or repository/issue scope. Multiple holds for
the same scope stay independent. Releasing a run-wide hold cannot clear an issue
hold, and issue numbers in different repositories do not collide. Event IDs are
globally immutable. Exact replay is inert even after a hold was released; a new
event ID cannot recreate or release an already released hold.

The journal retains complete ordered events and derives holds in creation order
and active hold IDs. At most 10,000 events and 1,000 distinct repository/issue
pairs across all history are accepted. At the event cap, even a valid new release
is rejected and its hold stays active. Do not erase history to clear that limit.
Inputs are captured before SQLite callbacks and canonical record bytes are
bounded identically on input and reopen. Complete schema, sequence, identity and
transition validation precedes every append or snapshot. The existing shared
transaction checks and uncertain-COMMIT read-back rule apply unchanged.

These are declared observations, not authenticated human approvals or proof of
original run authority. Snapshot always reports `execution_enabled: false` and
`dispatch_permitted: false`, even with no active holds. A released hold does not
renew an expired deadline or allowance. No SDK, runtime, CLI or network route
imports the journal. It does not enforce deadlines, spending, cancellation,
resource release, caller freshness or cross-journal atomicity. A future controller
must bind trusted approvals and integrate hold/limit/ownership reservations in
one reviewed transactional store. Synthetic reopen tests are not physical
power-loss durability or end-to-end recovery acceptance.

## Source-only lifecycle fixtures

`automation.lifecycle.evaluate_lifecycle_fixture(run, allocations, observations)`
is a pure reference evaluator for synthetic stop/release evidence. The
[canonical contract](superpowers/plans/2026-11-09-shared-ai-development-workflow.html#d00-lifecycle-fixtures)
defines its exact fields, enums and bounds. It is not an admission controller,
SDK adapter, scheduler or runtime probe, and no CLI or journal calls it.

The caller supplies a fixed run and allocation inventory. Allocation generations,
container identities and opaque process-instance IDs must match exactly; an OS
PID alone is not trustworthy process identity. Every allocation requires a
nonempty process inventory. Missing or undeclared resources fail closed rather
than being silently credited to another allocation.

A successful fence starts a fresh proof window. Only subsequent successful exits
for every declared process and deletion of the exact container satisfy the
synthetic prerequisites. Container deletion never substitutes for missing exit
observations. A new fence or any reload discards the earlier cleanup proof.
Stop requests, acknowledgements, final responses, archive and unsubscribe do not
prove cleanup. Any failed or unknown observation stays unresolved throughout
version 1's supplied history, even after later success; there is no reconciliation
or uncertainty-clearing API. Exact event replay is inert, including after reload
or uncertainty. Changed event-ID reuse and malformed input are rejected before
projection. Lists and records are bounded, and inputs are never changed.

Every declared allocation remains counted in `occupied_allocations`. A true
`synthetic_release_prerequisites_satisfied` does not make capacity available.
Reports always set `execution_enabled`, `admission_permitted`, `release_permitted`
and `inventory_complete` to false. Evidence references are never fetched and
fixture order is not verified provider chronology. The function cannot establish
actual process discovery, authenticated lineage, a protected admission fence,
complete teardown, safe capacity reuse or global reservation atomicity. Runtime
acceptance and the expired live SDK allowances remain unchanged.


## Credential-free local Docker preflight

`tools/runner_container_preflight.py` is a separately invoked D00 operator
experiment. It is not imported by `automation doctor` or `preview`. It creates
small disposable containers on an explicitly selected local Unix Docker socket,
using an already present image's complete immutable ID. It never pulls an image,
uses credentials, starts the SDK, submits model work, or changes existing services.
Container execution requires operator authorization for the selected host and scope.

```sh
python3 tools/runner_container_preflight.py \
  --image sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016 \
  --socket /var/run/docker.sock \
  --evidence-dir /absolute/private/path/to/a-new-run
```

The image ID above identifies the Python image used in the local experiment;
verify an existing suitable image on the actual executor rather than pulling or
substituting one silently. The evidence directory must be new and outside the
source checkout. The tool records its requested/observed policy, role canaries,
process identities, bounded Docker receipts and cleanup observations privately.
Its independent watchdog reserves cleanup time within the original 120-second
window; creation acknowledgement has a ten-second bound and other Docker calls
retain four-second bounds, clipped to the unchanged run deadline. Docker unavailability or a timed-out mutation remains UNKNOWN, even if
an initial inspection cannot find the container. Never start another attempt to
replace an unresolved allocation; reconcile its recorded exact identity first.

A successful bounded canary is evidence for the paths it exercised. It does not
prove authenticated admission, nested agent creation, SDK callback behavior,
controller crash recovery or complete runtime compatibility. Reports always keep
agent execution disabled and no runner mode accepted. The [canonical contract](superpowers/plans/2026-11-09-shared-ai-development-workflow.html#d00-local-container-preflight)
owns scope, acceptance and unresolved gates; the [checkpoint](handoffs/2026-11-09-autonomous-workflow-planning.md)
records actual runs and their limitations.


## Private scripted runtime qualification

The separately approved v5 experiment on 14 November 2026 completed seven
scripted direct-stdio scenarios against the pinned 0.167.0 app-server in one
network-none container. Exactly thirteen local provider requests were accepted;
correlation, reader drainage, retained-tool denial and transport-death assertions
passed. The transport-death operation remains UNKNOWN with replay prohibited.
Exact container removal and watchdog completion were recorded within the original
240-second allowance. Independent receipt review and QA passed 34 consistency checks with no blocking
finding; all 108 package members and 25 external pins matched.

This private fixture is not an operational CLI mode or a real model-issued
callback. Its consumed allowance cannot be reused. Full D00/TW capability gates,
authenticated child lineage, independent fencing and complete stop/recovery
remain open; `execution_enabled` and `runtime_mode_accepted` remain false. The
[current checkpoint](handoffs/2026-11-09-autonomous-workflow-planning.md) and
[canonical runtime decision](superpowers/plans/2026-11-09-shared-ai-development-workflow.html#remaining-runtime-decision)
record exact pins, receipts, review and remaining work. Existing source/offline
acceptance is retained; no package source was changed for this experiment.

### Idle initialization notifications

`tools/runner_idle_notifications.py` is a pure validator used by the private
forced-deadline diagnostic. The pinned app-server emits
`remoteControl/status/changed` during initialization even when its status is
`disabled`. Rejecting every notification except `configWarning` incorrectly
terminated this otherwise successful startup.

The validator accepts the existing configuration warning and a structurally
valid disabled-status notification. It rejects connecting, connected, errored,
unknown or malformed status messages, server requests and unrelated workload
events. The caller still enforces frame/byte/deadline bounds and strict JSON
parsing. A disabled-status observation establishes neither managed startup
policy nor prevention of remote control; those D00 requirements remain separate.
The original frozen diagnostic is preserved, and the corrected candidate imports
an exact copy of this helper under a new manifest and fresh run allowance.

Resume119 safe rollover120: second unexpected compaction, Main stopped. Corrected broad suite1525/8skips failed one timing assertion; reviewed deterministic replacement and retained real acknowledgement both pass (2/4.332s), no current broad-suite pass. New inotify tests remain RED with parser absent and no admission extension. Local97ba410 ahead of remote2d05299; UID/test/docs edits uncommitted. Actual qualification remains UNRUN; see newest continuation handoff.
