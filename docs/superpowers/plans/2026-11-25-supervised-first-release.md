# Supervised Single-Task First Release Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans
> to implement this plan task-by-task. The owner has selected Main as the sole
> writer and at most the existing read-only reviewer. Steps use checkboxes.

**Goal:** Let an operator explicitly run one trusted task in one opted-in project,
observe its checks and inspect its workspace without automatic publication.

**Architecture:** Add a separate foreground supervised path to the existing
advisory CLI. Reuse its enrollment/configuration reader; use a small, protected
per-project registration plus local lock and durable unresolved-attempt record,
then one supported Codex CLI process and fixed argv checks. This is a new narrow
path with its own acceptance criteria, not the incomplete native G1–G6 path.

**Tech Stack:** Python >=3.12 standard library, Git, installed Codex CLI, Linux/
WSL2, local filesystem with `flock` and `fsync` support.

**Spec:** [approved supervised design](../specs/2026-11-25-supervised-first-release-design.md).
**Requirements:** [RNR-SUP-01–06](../../requirements.md#approved-narrower-supervised-first-release).

**Execution status, 25 November 2026:** Implemented and independently
source-reviewed. The full suite passed 1,556 tests with seven skips, and one
separately authorized live qualification completed on the synthetic fixture.
See the [release record](../../releases/2026-11-25-supervised-first-release.md)
for snapshot, artifact and limits. Historical illustrative snippets below do not
override the actual dedicated CLI entry point or the implemented exit observer.

## Global Constraints

- Main alone writes source, docs and Git; no implementation delegation, branch,
  worktree, reset, commit, push or background chat.
- The native wrapper remains unconditional abandon/exit 125; do not change its
  contract or claim RNR-D00 or the original five gates are closed.
- Keep project enrollment, opt-in, state and logs separate and outside Git; never
  move, overwrite, initialize or reuse existing runtime Stores or evidence.
- One explicit task and one operator-supplied existing clean disposable checkout;
  no scheduler, automatic retry/resume, PR, push, merge, deployment or issue close.
- Run only trusted code under a trusted operator account; Codex/project commands
  may have side effects or retries and may access credentials and network.
- No actual provider operation, project enrollment, activation or physical
  qualification is authorized by this plan; controlled real qualification needs
  separate explicit authorization. Mock child processes are not provider calls.
- Preserve current `doctor` and `preview` advisory behavior and existing private
  enrollment format. No new Python runtime dependencies.
- Completion and readiness must be supported by the acceptance and review
  evidence in the release record.

## Review Focus

1. Different checkout or new attempt ID for the same project must not bypass an
   unresolved attempt; exercise both under Task 2.
2. Replaced/missing registration or project state must never silently initialize
   during a run; exercise missing files, changed device/inode and symlinks in Task 2.
3. Approval must bind task bytes, check argv, limits and current checkout/HEAD;
   mutate each after approval and verify no child starts in Task 3.
4. A killed supervisor, timeout or escaped descendant must never be represented
   as proof of containment or permission for an automatic retry; exercise the
   durable gate and UNKNOWN reporting in Tasks 2–3.
5. Noninteractive stdin, unsafe child output and inaccessible/mismatched remote
   must not bypass review or reveal credentials; exercise them in Tasks 1 and 4.

## File map and conventions

- `automation/supervised_inputs.py`: bounded task/check parsing, checkout and
  enrollment binding, immutable approved inputs and non-secret display.
- `automation/supervised_state.py`: fixed per-account project registration,
  state identity, project lock, durable attempts and explicit reconciliation.
- `automation/supervised_run.py`: one foreground child, ordered checks, bounded
  waits, stop/UNKNOWN handling and final observation.
- `automation/supervised_observer.py`: observe the actual foreground process exit
  and publish clearance only after its flushed report and normal exit.
- `automation/cli.py`: explicit `supervised-init` and `supervised-run` commands;
  read-only `supervised-status` and confirmed `supervised-reconcile`; no automatic
  opt-in. `automation/config.py` remains the advisory reader.
- `tests/test_automation_supervised_inputs.py`,
  `tests/test_automation_supervised_state.py`,
  `tests/test_automation_supervised_run.py` and
  `tests/test_automation_supervised_cli.py`: focused standard-library fixtures.
- `docs/project-owner.md`, `docs/automation.md` and `README.md`: describe the
  new mode only when implemented; distinguish current advisory and future mode.

All tests use disposable temporary directories, fake `codex` and check binaries,
and no real account, network, services, private store or provider. Use
`PYTHONDONTWRITEBYTECODE=1 python3 -m unittest <module>` for focused checks.
Helpers are internal; the owner guide records the implemented CLI arguments.

---

### Task 1: Capture and verify the operator-selected inputs (RNR-SUP-01)

**Files:** Create `automation/supervised_inputs.py` and
`tests/test_automation_supervised_inputs.py`; reuse `automation/config.py` and
`automation/contracts.py` without weakening existing advisory validation.

**Interfaces:** `capture(project: Path, enrollment: Path, task: Path,
checks: Path, *, host: str) -> CapturedRun` returns immutable task bytes,
ordered check `(name, argv)` tuples, limits, input digests, repository identity,
checkout path/device/inode, approved base/HEAD, reviewed remote and the resolved
Codex executable path/device/inode, and the explicit child-environment allowlist. `recheck(
captured: CapturedRun) -> None` raises `ValueError` on change. The CLI displays
this captured value and passes it unchanged to Task 3.

Check configuration is bounded UTF-8 JSON (131072 bytes maximum), exactly
`schema_version: 1`, `codex_timeout_seconds`, `check_timeout_seconds` and
`checks` (object mapping each declared `required_checks` name to a nonempty
array of nonempty argv strings). Both timeout values are integers in 1..86400;
all configured required names appear exactly once and no extra name is accepted.
Task is a nonempty regular file, at most 131072 bytes. Preserve captured bytes;
do not interpret task text as configuration or shell code. Recognize only
`https://github.com/OWNER/REPO[.git]` and `git@github.com:OWNER/REPO[.git]`
for `origin`, compare repository names case-insensitively, and reject an absent,
multiple, differently hosted or mismatched origin. This is an operator-reviewed
label, not proof of remote authority. Require an existing root checkout, current
HEAD equal to enrolled base, clean index and tracked/untracked status; show
ignored paths for human inspection. Capture device/inode and recheck all inputs,
remote, HEAD, executable identity and clean status after approval and immediately
before child launch. Resolve the executable once from the operator's selected
environment, display its absolute path and invoke that path, not a later PATH lookup.
Use the existing bounded Git helper where suitable; no Git mutation or shell.

- [x] Write tests for valid input and each wrong host/project/base/remote, dirty
  index/worktree, missing/oversized/symlink task, duplicate/unknown check,
  invalid timeout and changed task/check/checkout/HEAD after capture. Assert no
  process is spawned by capture/recheck. Include replacement of the selected
  Codex executable between approval and launch.

  ```python
  def test_changed_task_fences(self):
      captured = self.capture_valid()  # fixture creates the selected checkout
      self.task.write_bytes(b"changed")
      with self.assertRaises(ValueError):
          recheck(captured)
  ```
- [x] Run `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_automation_supervised_inputs`;
  confirm the new tests fail for the missing implementation.
- [x] Implement `CapturedRun`, `capture` and `recheck` with the exact inputs,
  limits and behavior above, and rerun the focused test module to PASS.

### Task 2: Stable state, single owner and unresolved gate (RNR-SUP-02)

**Files:** Create `automation/supervised_state.py` and
`tests/test_automation_supervised_state.py`.

**Interfaces:** `initialize(context: Context, *, project: Path) -> None` is called only by explicit
`supervised-init`; `open_project(context: Context, *, project: Path) -> ProjectState` verifies an
existing registration and acquires a nonblocking exclusive live lock;
`ProjectState.begin(captured: CapturedRun) -> str` durably creates an unresolved
attempt and returns its ID, or raises `ValueError` when an unresolved attempt
already exists; `ProjectState.finish(attempt_id: str, result: dict)
-> None` durably records an observed terminal outcome; `ProjectState.close()`
releases the lock. `reconcile(context: Context, attempt_id: str, note: str, *, project: Path)
-> None` records an explicit operator reconciliation under the same lock; it
never kills processes, removes external effects or replays an attempt.

Resolve the account home via `pwd.getpwuid(os.getuid()).pw_dir`, not `$HOME` or
XDG overrides. Use owner-only `.local/state/agent-runner/supervised-v1` outside
the checkout; derive a fixed project key from SHA256 of the validated lowercase
repository name. Store one protected registration binding project/enrollment,
random state ID and the project state directory device/inode. Create registration
and state only through explicit init with exclusive creation; ordinary runs never
create or rebind them. Reject unsafe ownership, modes, links, missing/replaced
registration/state, changed enrollment binding and unsupported locking/durability.
Under the single project lock, refuse `begin` while any unresolved attempt exists,
even when another checkout or new ID is supplied. Use bounded UTF-8 JSON and
exclusive create / file and directory `fsync`; never silently repair torn records.
Successful process exit is only an observation, not proof all descendants stopped.

- [x] Write tests for explicit init and normal record/finish, same project across
  checkouts, concurrent lock contention, existing unresolved after lock-holder
  loss, changed/missing/symlink state or registration, cross-project separation,
  interrupted writes and explicit reconciliation. Assert run lookup never
  initializes, removes or rebinds state.

  ```python
  def test_unresolved_survives_reopening_project(self):
      first = open_project(self.context, project=self.captured.project)
      first.begin(self.captured)
      first.close()  # simulate loss of the live lock
      second = open_project(self.context, project=self.other_checkout_capture.project)
      self.addCleanup(second.close)
      with self.assertRaises(ValueError):
          second.begin(self.other_checkout_capture)
  ```
- [x] Run `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_automation_supervised_state`;
  confirm RED, implement the stated interfaces and rerun to PASS.

### Task 3: One foreground invocation and honest result (RNR-SUP-03–04)

**Files:** Create `automation/supervised_run.py` and
`tests/test_automation_supervised_run.py`.

**Implemented interface:** The dedicated CLI calls private `_run_cli(captured)`;
public `run(captured)` refuses embedded execution because clearance depends on
the actual foreground process exiting. Callback injection is limited to the
private test helper. The CLI first obtains a separate authorization for Git
checkout inspection, as approved in the design. It opens the project lock/state gate,
rechecks the captured values, records the attempt, rechecks immediately before
spawn, and executes the captured task and checks. `RunResult` contains `started`
(bool), optional attempt ID, observed process/check results, timeout/UNKNOWN
status and final Git observations. Declined approval returns `started=False`.

Invoke the selected `codex exec --sandbox workspace-write -C <checkout> -` once,
using the captured absolute executable, feed captured task bytes via stdin and
use the captured checkout as cwd. Use a
documented non-secret environment allowlist sufficient for the selected CLI;
never parse or print credentials. Capture output to private per-project logs;
do not pipe unbounded child output into memory. Run each captured argv once with
`shell=False` and its timeout, stopping at the first failure. On timeout or
interrupt, signal the original process group and record only observed outcomes;
timeout/interruption remains UNKNOWN and keeps the durable gate unless explicitly
reconciled. A normal exit is not proof that escaped descendants are absent.
After a normal outcome, record results durably before releasing the live lock.
Report HEAD, index, tracked diff and untracked paths; flag changed HEAD/index and
instruct the operator to inspect ignored paths. Never reset or create a branch.

- [x] With fake child executables, test exactly one invocation, stdin task bytes,
  approved check argv/cwd/order, no shell, declined/noninteractive approval,
  changed inputs immediately before launch, nonzero exit, check failure,
  interruption, timeout, changed HEAD/index, untracked and ignored paths.
  Assert no retry, no real provider call, private logs and UNKNOWN when stop is
  unproven. Test that the runner does not claim to control CLI-internal retries.

  ```python
  def test_declined_run_does_not_spawn(self):
      result = _run(self.captured, approve=lambda summary: False)  # private test helper
      self.assertFalse(result.started)
      self.assertEqual(self.fake_codex_invocations(), [])
  ```
- [x] Run `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_automation_supervised_run`;
  confirm RED, implement the interfaces and rerun to PASS.

### Task 4: CLI, operator documentation and integrated checks (RNR-SUP-05–06)

**Files:** Modify `automation/cli.py`, `README.md`, `docs/project-owner.md` and
`docs/automation.md`; create `tests/test_automation_supervised_cli.py`.

**Interfaces:** `agent-runner supervised-init --project PATH --enrollment PATH`
explicitly initializes its project state after displaying the trust assumptions;
`agent-runner supervised-run --project PATH --enrollment PATH --task PATH
--checks PATH` requires a foreground terminal and exact interactive `APPROVE`
after the task, argv, limits, base and risks are displayed. Any other answer or
nonterminal input declines. Provide `supervised-reconcile --project PATH
--enrollment PATH --attempt ID --note TEXT` with explicit foreground confirmation;
it records reconciliation, not proof or cleanup. Do not accept a per-run state
path, approval bypass flag, automatic retry flag, or credentials argument.
The CLI uses its lazy `_supervised_run` adapter to call Task 3 without importing
Linux-specific runtime modules for advisory commands.

- [x] Write CLI tests for all commands through injected fake child processes,
  exact approval and rejection of nonterminal/decline, no automatic state init,
  no path override, preserved advisory output, and no remote/provider operations.

  ```python
  def test_piped_approval_is_rejected(self):
      with patch("sys.stdin.isatty", return_value=False), patch(
              "automation.cli.supervised_run") as launch:
          self.assertNotEqual(cli.main(self.valid_run_arguments()), 0)
          launch.assert_not_called()
  ```
- [x] Run `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_automation_supervised_cli`
  and `PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_automation_cli.py`;
  confirm RED for the missing commands, implement and rerun both to PASS. The
  existing advisory fixture imports require the discovery path.
- [x] Update the operator docs with actual command syntax, explicit project
  opt-in, checkout review, trusted-code/account/network limits, finite timeout,
  UNKNOWN/reconciliation and complete workspace review. Do not call the mode
  release-ready before selected-host qualification and independent review.
- [x] Verify supervised, advisory CLI and configuration coverage, full suite and
  `git diff --check`. The final full suite passed 1,556 tests with seven skips;
  the final focused observer/PTY/CLI/strict-state run passed 31 tests. Independent
  integrated source review closed material findings. Exact evidence is in the
  release record.
- [x] Prepare the concrete disposable-project procedure, obtain the user's
  separate fixture and provider authorizations, perform exactly one foreground
  invocation, and record its output, final workspace and validated `ready`
  clearance. The CLI reported OpenAI provider and model `gpt-6.1-terra`; effective
  account and cost were not independently established. Retain the observed
  network errors and scope limits. No further run is authorized by this plan.

## Acceptance and handoff

All RNR-SUP-01–06 criteria must be supported by evidence before calling this
supervised release ready. The reviewed plan and mock integration do not close
the five original gates or authorize production. If the selected CLI cannot meet
the stated foreground, input or sandbox behavior, stop and report the observed
limitation instead of silently weakening the design or inventing a substitute.
