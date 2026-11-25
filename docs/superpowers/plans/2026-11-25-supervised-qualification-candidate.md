# Controlled supervised qualification candidate

**Execution status, 25 November 2026:** The owner separately authorized fixture
setup/opt-in and one provider invocation; both completed. The actual identities,
result, artifact and limitations are in the
[release record](../../releases/2026-11-25-supervised-first-release.md). The
reviewed procedure below is retained for traceability and does not authorize a
repeat invocation. Source tests alone do not qualify a provider, host or project.
Original RNR-D00/G1–G6 and its five gates remain open; the native wrapper is fenced.

## Scope and authorization

No enrolled supervised project was found under the fixed state root, and the
top-level local checkouts inspected have no `.agent-runner/automation.json`.
The inspected `boti-demo-20261030` is a separate trading project and is not the
proposed target. Do not borrow its enrollment or state.

The proposed target is one new synthetic Git repository at
`/home/faris/.local/state/agent-runner/release-admission-20261119/qualification-20261125/project`.
It contains only a synthetic requirements document, a runner config and an
ignore file. Its local Git `origin` is the label
`https://github.com/example/agent-runner-qualification-20261125.git`; offline
setup will not contact it, and it is not proof of a real remote. The later
provider CLI is trusted code with network access. Its independent identity is
`example/agent-runner-qualification-20261125`. The initial repository and
enrollment do not adopt any existing project or Store.

**Separate authorization 1 is needed:** permit creation of this one independent
repository, its `main` branch and one initial synthetic commit, an exception to
the user's no-branch/no-commit restriction, and explicitly opt in this named
fixture. Do not create a branch, worktree or commit in `/home/faris/agent_runner`.
If the user retains the restriction, an existing clean committed project with
its owner's explicit opt-in and matching private enrollment is required instead.

**Separate authorization 2 is needed:** after the fixture inputs and exact base
are displayed, permit one foreground `supervised-run` against this fixture and
the selected provider/account. Do not make that call merely because fixture
setup was authorized. This is one Codex CLI invocation; it is not a guarantee
of one underlying provider request or a spending cap. The runner cannot prevent
the trusted CLI or project code from using network, credentials or other host
resources. Preserve state and inspect the host and external effects on UNKNOWN.

## Selected local candidate

* Host/user: `DESKTOP-3CK36LV`, `faris`; Python 3.12.3.
* Codex: `/home/faris/.local/bin/codex`, currently resolving to
  `/home/faris/.codex/packages/standalone/releases/0.162.1-x86_64-unknown-linux-musl/bin/codex`,
  observed CLI 0.162.1; local config
  currently names model `gpt-6.1-terra` and no explicit provider. The effective
  account, provider, binary identity and model must be reverified before asking
  for the real provider call. No login or provider call has been made here.
* Offline-built wheel:
  `/home/faris/.local/state/agent-runner/release-admission-20261119/supervised-recovery-wheel-20261125/agent_runner-0.1.0.dev0-py3-none-any.whl`;
  SHA256 `9d3b86a3dd937ecb9a3d4fe6c6e463831e86c6473b0d50dd23226db8f5f6552e`.
  Its five supervised Python modules match the independently reviewed source
  hashes. A wheel is an artifact, not qualification or operational acceptance.
* Fixture private operator directory:
  `/home/faris/.local/state/agent-runner/release-admission-20261119/qualification-20261125/operator`.
  Enrollment, task and checks are owner-only files there, outside the checkout.
* Proposed task bytes: `Reply exactly QUALIFICATION_OK. Do not edit files, run
  commands, or invoke tools.\n`. This is an instruction to the model, not an
  enforcement boundary. The single `unit` check is argv
  `["/usr/bin/python3", "-c", "pass"]`; Codex timeout 120 seconds and check
  timeout 30 seconds. A normal result must show no checkout changes and the
  operator must inspect the complete output/logs and workspace.

Use UTF-8 and exactly one trailing LF byte for each input, not the literal two
characters `\n`. The 82-byte task SHA256 is
`914c620a83a6b4d3b9112d116d2c5887859241c7d1dae278f318a785aaf49797`.
The exact checks-file line below has SHA256
`4016a63f4a5650e76d72e892eaa307aa64275aa2c8924568a519f14c53bfede2`:

```json
{"schema_version":1,"codex_timeout_seconds":120,"check_timeout_seconds":30,"checks":{"unit":["/usr/bin/python3","-c","pass"]}}
```

## Offline fixture setup after authorization 1 only

Precheck the exact path does not exist; preserve any existing directory. Create
the root, `project`, `operator` and empty Git template as mode 0700. Initialize
the new repository with an initial `main` branch using the empty template; set
only its local `origin` to the label above. With system/global Git config,
hooks, signing and fsmonitor disabled, write and commit exactly these three
files. Use per-command synthetic Git identity `Agent Runner Qualification`
and `qualification@example.invalid`; do not change global Git configuration:

```text
.gitignore: .agent-runner/venv/
docs/prd.md: This synthetic fixture is for one supervised qualification only.
.agent-runner/automation.json:
{"schema_version":1,"repository":"example/agent-runner-qualification-20261125",
 "target_branch":"main","runner_host":"DESKTOP-3CK36LV",
 "approvers":["qualification-operator"],"documents":["docs/prd.md"],
 "required_checks":["unit"],"selection":{"labels":["ready"],
 "priorities":["normal"],"max_candidates":1}}
```

Read back the full initial commit ID and SHA256 of the committed configuration.
Write `operator/enrollment.json` mode 0600 with that ID/digest, repository and
host, `schema_version: 1`, `approvals: []` and `accepted_dependencies: []`.
Write the exact task and checks above as mode 0600 files. Create the fixture's
ignored `.agent-runner/venv`, install the exact wheel offline with `--no-deps`,
and verify isolated imports, CLI help, clean Git status and advisory `doctor`.
All writes are limited to this fixture and the package manager's isolated build
environment; do not update a global Python environment, push or contact GitHub.
Record the actual revision, config digest, wheel digest and created paths in
protected evidence. This preparation does not authorize provider use.

After rechecking the fixture identity, invoke its installed `agent-runner
supervised-init --project PROJECT --enrollment ENROLLMENT` by the absolute
fixture venv path in a foreground
terminal and approve its displayed inspection and opt-in summaries only within
authorization 1. Expected state is a new private registration and project state
at exactly these paths; if either already exists, stop rather than adopting it:

```text
/home/faris/.local/state/agent-runner/supervised-v1/123012ba58f67a5b25f1bff8625f3dc582c26fac629184d5b6f2cee0d9d6b5c0.json
/home/faris/.local/state/agent-runner/supervised-v1/123012ba58f67a5b25f1bff8625f3dc582c26fac629184d5b6f2cee0d9d6b5c0.state
```

No workload or provider starts during init.
Run the following in a foreground terminal, with `PROJECT` and `ENROLLMENT` set
to the exact fixture paths above:

```sh
"$PROJECT/.agent-runner/venv/bin/agent-runner" supervised-init --project "$PROJECT" --enrollment "$ENROLLMENT"
"$PROJECT/.agent-runner/venv/bin/agent-runner" supervised-status --project "$PROJECT" --enrollment "$ENROLLMENT"
```

Status should report `ready`. If it does not, stop and preserve the state rather
than reinitializing it.

## One real-provider run after authorization 2 only

Display the exact account/provider/model, CLI version/path/identity, project,
base, task bytes, check argv and timeouts, and get separate explicit approval.
Inspect account/model configuration offline only; if the effective identity
cannot be established without contacting the provider, state that limitation
and do not make a network call to fill the gap before authorization 2.
Run the fixture's installed CLI once in the foreground with `PATH` selecting the
Codex binary above. Verify that `command -v codex` resolves to
`/home/faris/.local/bin/codex` in this exact environment before the approval:

```sh
PATH=/home/faris/.local/bin:/usr/bin:/bin command -v codex
readlink -f /home/faris/.local/bin/codex
PATH=/home/faris/.local/bin:/usr/bin:/bin "$PROJECT/.agent-runner/venv/bin/agent-runner" supervised-run --project "$PROJECT" --enrollment "$ENROLLMENT" --task "$TASK" --checks "$CHECKS"
"$PROJECT/.agent-runner/venv/bin/agent-runner" supervised-status --project "$PROJECT" --enrollment "$ENROLLMENT"
```

The user approves the checkout-inspection and detailed execution summaries in
the terminal. Expected effects are one Codex CLI invocation, provider usage,
one local no-op check, private attempt/log/history records and the terminal
report. Cost is not measured or capped by this runner. After normal exit wait
for status to become `ready`, then inspect HEAD, index, tracked/untracked/ignored
files and private logs. If the result, observer, process group or external effect
is uncertain, do not rerun; inspect the original workspace/processes/provider
effects and use the separately confirmed `supervised-reconcile` only after that
inspection. Keep all state and evidence. Do not push, merge, deploy, activate a
service or declare the original five gates closed.
