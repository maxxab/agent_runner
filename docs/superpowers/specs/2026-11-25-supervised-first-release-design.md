# Supervised single-task first release — approved design

**Status:** Owner approved on 25 November 2026 after independent design review;
implemented, independently source-reviewed and qualified by one separately
authorized live provider run on the synthetic fixture. The
[release record](../../releases/2026-11-25-supervised-first-release.md) maps the
acceptance evidence and limits. Each project's opt-in and each run still require
explicit approval. The native wrapper remains fenced; this design does not close
RNR-D00 or the five existing operational gates.

## Outcome and choice

Give one operator a useful first end-to-end experience: explicitly choose one
task in one opted-in project, run Codex in the foreground against an
operator-supplied disposable checkout, run the project's selected checks, and
inspect the resulting changes. The operator decides what to do with the result.

Three approaches were considered:

1. Continue the current fully hardened admission and recovery contract before
   any execution. It preserves the intended guarantees, but substantial G1–G6,
   provider and physical qualification work remains.
2. **Selected:** a supervised, one-task path built on the existing Codex CLI
   and ordinary local process controls. This is smaller, but trusts the project,
   the operator's account and the host; it does not provide the hardened
   contract's isolation or recovery guarantees.
3. Release advisory `doctor` and `preview` only. This has the smallest runtime
   surface but does not yet run a task.

The owner approved approach 2 for the supervised first release. It does not
silently change the requirements for the broader autonomous runner.

## Boundary and explicit exclusions

- Linux/WSL2, one local operator, one explicitly opted-in project, one task and
  one foreground run. The operator supplies an existing, clean, disposable Git
  checkout at the intended base revision. The runner creates no branch or Git
  worktree and does not use this repository's current dirty checkout as a test
  workspace.
- The operator trusts the selected repository, task, configured checks, local
  Codex installation and sign-in environment. Project commands may access
  whatever the operating system and Codex actually allow, including network,
  credentials and files outside the checkout. A workspace sandbox is useful
  defense when supported, but is not claimed to contain hostile code or protect
  credentials from it. No provider spending cap is promised.
- The runner does not initiate unattended selection, scheduled execution,
  concurrency, automatic resume or retry, PR creation, push, merge, deployment,
  issue closure, or adoption into another project. The human reviews the result
  and handles publication separately. Codex and project commands may have
  network access and their own retry or side-effect behavior; the wrapper alone
  cannot guarantee they never retry, publish or perform external actions.
- No claim that the current native G1–G6 protocol, protected provider broker,
  keeper/observer, immutable startup closure, or offline retirement is complete.
  Their existing code and evidence remain preserved for later work.

## Operator journey

1. The operator explicitly opts in the project and supplies its existing private
   enrollment, an absolute checkout root, one local task document and a check
   configuration. The runner uses the fixed per-project run-state location
   described below; the operator cannot select a new location for each run. The
   check configuration maps the existing `required_checks` names to fixed argv
   arrays; commands are not taken from the task text and are invoked without a
   shell. It is operator-controlled and reviewed for that project.
2. The runner validates the existing project context and host, confirms the
   checkout is clean and at the specified approved base, checks the configured
   checks are unambiguous, and displays the task, checkout, commands and limits.
   Existing `load_context` validates data; it does **not** itself prove authority
   to execute or prove which repository a checkout represents. For this
   trusted-host release the operator explicitly identifies the checkout and
   reviews its absolute path, repository label, configured remote identity and
   full HEAD against the enrolled project and approved base; a mismatch, absent
   identity or ambiguous remote stops the run. Local remote configuration is a
   label, not cryptographic proof of a remote repository. Private state is bound
   to the project/enrollment, while each attempt records its selected checkout
   identity; a different checkout does not create or rebind project state. The
   operator must explicitly approve this exact run in the
   foreground after seeing the summary. No approval is inherited across
   projects or attempts. Stop if any prerequisite is unavailable or ambiguous.
   Owner decision, 25 November: before checkout inspection, obtain a separate
   foreground confirmation identifying the checkout and warning that Git may
   execute repository-configured filters with the operator's access. Declining
   stops inspection. This does not replace the detailed per-run approval.
3. Capture the bounded task bytes, check argv arrays and limits once. Show the
   task, digests, exact argv and limits for approval. Immediately before launch,
   recheck the named task/check inputs, checkout identity, clean status and HEAD;
   stop if changed. Feed the captured task bytes to Codex and use the captured
   argv/limits for checks, never replacement bytes discovered later. Run Codex
   and checks with the selected checkout as their working directory; construct
   and document the necessary non-secret environment explicitly, including the
   supported CLI sign-in mechanism, and do not log its sensitive values.
4. Acquire the project-wide live lock and durably record an exclusive attempt
   before launch in private project state, with task and check-configuration
   digests, checkout/base identity, chosen limits, and an attempt identifier.
   Recheck the same inputs and checkout once more after acquiring the lock and
   immediately before launch; a change prevents launch and is recorded. Launch
   the existing Codex CLI once using a supported workspace-write sandbox
   on the chosen checkout. The CLI's supported
   authentication is used; the runner does not parse, copy, or print account
   credentials. CLI support, authentication and actual sandbox behavior must be
   verified on the selected installation before use.
5. After the Codex process exits successfully, the runner invokes the configured
   checks once, in order, with their recorded exit statuses. A failed, timed-out,
   interrupted or unknown run stops the sequence. The runner does not itself
   repeat a task, check, model request or external operation; internal CLI or
   command retries are outside that promise and must be characterized where
   observable for the selected version.
6. Report the original base, final HEAD, index and working-tree status, tracked
   diff, untracked paths, check outcomes and log locations. A changed HEAD or
   index is flagged for human reconciliation; the runner never resets it. The
   operator inspects the full checkout, including untracked or ignored files and
   any side effects. A successful process or check is not acceptance of the task,
   and the result is not described as a frozen independently reviewed candidate.

## Limits, failure and recovery

The run is foreground-only. The operator sets a finite wall-time limit for the
Codex process and for each check. On timeout or interruption the runner asks the
process group to stop and reports what it observed. A process group does not
prove that descendants cannot escape or that all effects stopped: if termination
or an external effect is uncertain, record **UNKNOWN**, retain the attempt and
require the operator to reconcile the host and workspace before another run.
Abrupt loss of the runner is also UNKNOWN. There is no automatic cleanup or
claim that expiry proves absence. Any stronger resource limits are optional only
after the selected host mechanism has been tested and accurately documented.

On 25 November the owner reaffirmed both automatic guard clearance after a
normally observed terminal outcome and reconciliation after abrupt runner loss.
The owner did not authorize treating a durable but undisplayed terminal result as
known after such a loss. The implemented exit observer and durable state address
that clearance window; focused failure tests, the full suite and independent
source review are linked in the release record. Physical power-loss testing and
proof of escaped-descendant containment are outside this release's evidence.

The implementation retains a durable guard, stages the result without
clearing it and uses an independent observer of the actual foreground process
to publish attempt-bound clearance after terminal delivery and normal exit.
Explicit operator reconciliation publishes a separate decision. Prepared
records and uncertain clearances block admission; a status command exposes the
pending attempt where it can be validated. This Linux-specific mechanism and its
terminal, signal, filesystem and observer-lifetime prerequisites require the
focused tests, full suite, independent review and separately authorized host
qualification. A report written to a terminal is not proof a person read it.

Keep a small, private per-project attempt record and logs outside Git. A single
location is derived from the operating-system account's home directory and a
stable hash of the enrolled repository identity under the fixed owner-only
`.local/state/agent-runner/supervised-v1` root outside all checkouts. A separate
protected project registration at that fixed root binds the enrolled repository
and a generated state identifier to the state directory's device/inode; normal
runs verify that binding before taking the lock. Missing registration or state
blocks execution, and changed identity requires explicit recovery. It is the
same across that project's disposable
checkouts and is not selected through a per-run path or environment override.
Explicit opt-in creates and binds the project state once; an ordinary run never
initializes, relocates or silently rebinds it. Missing, replaced, malformed or
uncertain state blocks a run. A deliberate recovery or relocation requires
operator reconciliation and preservation of unresolved history; first-time
opt-in must not be used to erase uncertainty about prior state. This assumes a
trusted operator and protected local state; it does not defend against an operator
deliberately deleting or forging that state. The existing enrollment has no such
state-location field; the implementation derives and verifies this binding
without changing the enrollment format.

A single project-wide OS lock serializes live runs; an exclusive attempt identifier alone
is not a concurrency lock. Before launching, durably write an unresolved attempt
record under that lock. The live lock is released if its process dies, but the
unresolved record remains a separate gate: a later invocation refuses to start
even with a new identifier until the operator has reconciled the earlier
process, workspace and possible effects and explicitly recorded the outcome.
After a normally observed terminal outcome, durably record that outcome before
releasing the live lock. Use and test a local filesystem that supports the lock
and durability operations; fail closed if either is unavailable. The record
reports only observed process and check results, not proof that escaped
descendants or external effects are absent. Keep project identities, opt-ins, attempt
records and logs separate; the ordinary Codex sign-in may still be an account
shared by the operator, and is not represented as project-isolated. Logs can
contain sensitive model or command output; restrict their access and do not copy
credential material into reports. Report cost only when the provider actually
reports it for that run; otherwise say unavailable.

## Acceptance criteria

1. Configuration and authorization: wrong project/host/base, dirty checkout,
   missing, ambiguous or changed task/check inputs, absent opt-in and declined
   per-run approval all stop before launch. Test checkout/remote label matching,
   final HEAD recheck, and execution of captured task bytes and check argv.
   No other project's records are adopted.
2. One controlled, authorized end-to-end run on a disposable trusted test
   project shows exactly one task, the selected check commands, final workspace
   status and human-readable results. A separately authorized real provider call
   is required for that evidence; CLI help and mock tests are insufficient.
3. Tests cover the same project's state across checkouts, missing or replaced
   state, attempted alternate state paths, concurrent attempts, a lost live lock
   with a durable unresolved record, failed launch, nonzero exit, failed check, interruption, timeout,
   existing/uncertain attempt, changed inputs and changed HEAD/index. Inspect actual process
   and workspace state when testing failure; do not claim escaped processes or
   external effects were contained without evidence.
4. Document installation, explicit opt-in, the trusted-code/credential risk,
   stop and manual reconciliation, and how to review tracked and untracked
   results. Verify the selected CLI version, sign-in, sandbox and supported host,
   and characterize observable CLI retry/effect behavior; do not promise
   guarantees the CLI cannot expose or the wrapper cannot enforce.
5. Independent review covers the implementation and these limitations. Update
   the requirement and release records to identify the narrower version only
   after this design and its concrete contract changes are approved.

## Compatibility, sequencing and estimate

The existing [requirements](../../requirements.md) record the owner's approved
narrower first-release scope alongside the original
[admission contract](../plans/2026-11-19-persistent-admission-contract.md).
The original five gates remain open; this supervised path has its own acceptance
criteria and cannot be labeled as passing them. The
existing wrapper stays unconditional abandon/exit 125 until its whole original
boundary is valid. Existing stores, consumed records and protected evidence are
not migrated, reset or reused by the proposed path.

The implementation, focused failure tests, full suite, independent source review
and separately authorized end-to-end qualification are complete for the recorded
snapshot and host. The release record identifies the exact supported scope.
The later roadmap retains issue selection, PR delivery, parallelism, stronger
containment and broader recovery without claiming dates for them.
