# Project-owner installation and recovery

The local **0.1.0.dev0 supervised single-task release** is available for explicitly
approved runs on the qualified Linux/WSL2 host. `doctor` and `preview` remain
advisory; the original hardened runtime and service are unavailable. The
[release record](releases/2026-11-25-supervised-first-release.md) identifies the
artifact, review, passing tests and authorized live qualification. A different
project needs its own explicit opt-in, reviewed inputs and per-run approval;
the original runtime gates remain open.
Owner chat first reads /home/faris/development-standards/skills/agent-runner/SKILL.md
and canonical POLICY.md. Explicitly select one project and obtain its opt-in;
reading the skill does not authorize installation into any other project.

The [architecture guide](architecture.md) shows the complete setup, run, report,
exit and reconciliation lifecycle, including trust boundaries and private state.

## Prerequisites and ownership

Use an absolute Git worktree root, Python>=3.12, Git, uv and a reviewed local wheel.
Check permissions before changes; preserve existing files, identities and grants.
Native source checks require Linux x86_64 and GCC (GCC13 checked). Operational
systemd/Docker/cgroup/immutable-media/Codex prerequisites are not satisfied merely
by installing this wheel. No SDK, daemon, model session or host service is installed.
The owner controls config, approved documents, venv and private enrollment.
Shared standards owns policy and skill source; agent_runner owns code/resources.
Never share enrollment, Store database, logs or runtime identity between projects.

## Install and repeat installation

After explicit opt-in, set PROJECT to the actual absolute consumer Git root and
WHEEL to the reviewed absolute wheel. Before running commands, inspect
.agent-runner/venv: proceed only if absent, or positively identified as this owner's
existing environment. Apply consumer ignore rules for venv/logs/state before
installation. Preserve foreign files and resolve ownership before proceeding.
From that project:

```sh
python3 -m venv "$PROJECT/.agent-runner/venv"
uv pip install --python "$PROJECT/.agent-runner/venv/bin/python" --no-deps "$WHEEL"
"$PROJECT/.agent-runner/venv/bin/python" -I -c 'import automation; print(automation.__file__)'
"$PROJECT/.agent-runner/venv/bin/agent-runner" --help
```

The import must resolve under this project's venv, never either checkout. On a
repeat install reuse only an identified owner-managed venv and the exact same
reviewed wheel; rerun the install and checks. Do not overwrite a foreign directory.
Ignore .agent-runner/venv, logs and state in the consumer's Git rules. No editable
installs or PYTHONPATH. `uv` is a development installer; the runner doesn't import it.
If venv's pip bootstrap is unavailable, use `uv venv --python /usr/bin/python3`
with that same exact venv path; do not silently replace an existing environment.

## Explicit configuration and enrollment

Create and review committed .agent-runner/automation.json, with the schema below;
replace every example identity/check/document with the actual project values.

```json
{"schema_version":1,"repository":"owner/project","target_branch":"main",
 "runner_host":"actual-hostname","approvers":["maintainer"],
 "documents":["docs/prd.md"],"required_checks":["unit"],
 "selection":{"labels":["ready"],"priorities":["high","normal"],"max_candidates":1}}
```

Commit only the reviewed config/documents using the project's normal authorization.
Obtain the full approved commit ID and SHA256 of the config bytes in that commit.
The owner supplies a separate mode0600 private enrollment JSON outside the project,
inside an owner-only directory. Do not auto-discover or borrow another project's
credentials/enrollment. Fields are schema_version=1, repository, base_revision,
config_sha256, runner_host, approvals=[], accepted_dependencies=[]. Review
nonempty approvals/dependencies under the existing product contract; no grants are
created by installation. The exact approved commit/config digest/host/repository
must match; malformed, candidate-local or cross-project enrollments reject.
There is no implicit fallback to .development-standards/automation.json.

## Status, startup, stop and logs

```sh
"$PROJECT/.agent-runner/venv/bin/agent-runner" doctor --project "$PROJECT" --enrollment "$ENROLLMENT"
```

A valid report says configuration_valid=true and execution_enabled=false, with
runtime unavailable. Exit0 means valid advisory configuration only. Invalid config
returns2. Preview requires an explicit normalized offline snapshot; see automation.md.
There is no supported start/run/status/stop service command yet. A service startup request
must be declined with those release gates; do not invoke private qualification
binaries as a substitute. Advisory commands exit after their report, so there is
no installed service to stop. Capture each command's stdout/stderr in distinct
private project-owned log files if needed; do not put credentials/raw private
runtime evidence in Git. No global runtime log or Store is created by this package.

## Supervised single-task path

This path is separate from the original hardened runner. Only one synthetic
project has undergone the live qualification described above; a different
project requires its own explicit opt-in and authorization. It is designed for
one foreground operator and trusted project code. Codex and project commands
may access the operator's account, credentials, network and host files. The
runner cannot guarantee that Codex or those commands will not retry, publish or
cause other side effects; it does not enforce a provider spending cap. A timeout
or process-group signal does not prove that every descendant or external effect
stopped.

The current implementation uses Linux anonymous memory-backed task input and
requires the foreground runner's SIGINT and SIGTERM to be unblocked with their
normal dispositions, and SIGCHLD to have its default disposition. Other signal
settings are refused before child launch. A separate child reaper is unsupported.
The foreground process must be single-threaded. An independent Linux ptrace
observer must be allowed to attach to that exact process; an existing tracer,
security policy, unavailable `/proc`, or an unsupported filesystem can prevent
startup. The observer is invasive: it observes and reinjects signals and holds
the project's lock until it sees the foreground process exit. This requires
qualification on the actual host and a local filesystem with working file and
directory `fsync` and atomic hard links; network filesystems are not qualified.
The CLI must not change the initially observed SIGCHLD, window-change or
job-control dispositions during a run; the delivery step checks they remain
unchanged. Other delivered signals conservatively prevent automatic clearance.
Use the dedicated CLI process. Calling the runner as an embedded library or
running `cli.main()` inside a long-lived process is unsupported.

After the operator has explicitly opted in the project and separately
authorized the intended run, select that project, its existing private
enrollment and an existing **clean, disposable** checkout at the enrolled base.
The checkout's single `origin` must be the selected GitHub repository over
`https://github.com/OWNER/REPO[.git]` or `git@github.com:OWNER/REPO[.git]`;
this local label is not proof of remote identity. The operator supplies a
nonempty UTF-8 task file and an owner-controlled checks JSON file. The latter
must match the enrolled `required_checks` names exactly and contains argv arrays,
not shell command strings. The runner does not wrap argv in a shell; an explicitly
configured executable can itself be a shell and is trusted. For an enrollment
requiring only `unit`:

```json
{"schema_version":1,"codex_timeout_seconds":900,"check_timeout_seconds":300,
 "checks":{"unit":["python3","-m","unittest","discover","-s","tests"]}}
```

Each timeout must be an integer from 1 to 86400 seconds. The task and checks
files are each limited to 131072 bytes; the checks file must be operator-owned
and not group/other writable. Neither file may be a final-component symlink.
When a project requires a particular model and reasoning level, add both
`"codex_model":"gpt-6.1-sol"` and `"codex_reasoning_effort":"medium"` to the
top level of the checks JSON, replacing those example values with the project's selection.
The two fields must be supplied together. Supported effort names are `low`,
`medium`, `high`, `xhigh`, `max` and `ultra`; the actual selected model/client
may support fewer. The approval summary and final report identify these as
requested settings. The runner passes them explicitly to the CLI, without
selecting a provider, retrying or supplying a fallback. Availability and actual
effective settings still require checking the selected CLI's output. Omit both
fields to retain the CLI's existing configuration defaults.
The runner uses the selected `codex` executable and an explicit environment
allowlist: `PATH`, `HOME`, `CODEX_HOME`, `LANG`, `LC_ALL`, `TERM`,
`XDG_CONFIG_HOME`, `XDG_CACHE_HOME` and `TMPDIR` when present. It does not copy
other variables such as `OPENAI_API_KEY`, parse account credentials, or guarantee
that the selected CLI's sign-in works with this environment. Verify the chosen
CLI version, configuration and sandbox behavior during qualification.

The following commands require a foreground terminal. `supervised-init`,
`supervised-run` and `supervised-reconcile` require the exact response
`APPROVE` after the displayed summary; read-only `supervised-status` asks for no
confirmation. Before `supervised-init` or
`supervised-run` inspects a checkout, a separate confirmation warns that Git
inspection can execute repository-configured filters with the operator's access.
Approve this only for a trusted checkout. The detailed opt-in or run approval
still follows inspection. They do not create a branch or worktree:

```sh
agent-runner supervised-init --project "$PROJECT" --enrollment "$ENROLLMENT"
agent-runner supervised-run --project "$PROJECT" --enrollment "$ENROLLMENT" --task "$TASK" --checks "$CHECKS"
agent-runner supervised-status --project "$PROJECT" --enrollment "$ENROLLMENT"
agent-runner supervised-reconcile --project "$PROJECT" --enrollment "$ENROLLMENT" --attempt "$ATTEMPT" --note "$RECONCILIATION_NOTE"
```

`supervised-init` is the explicit project opt-in: it creates a fixed per-account,
per-repository state location under `.local/state/agent-runner/supervised-v1`
outside the checkout. It does not create or adopt the original runtime Store.
Do not run it again to bypass a missing, damaged or moved registration or a
previous uncertain attempt. A separate manual recovery procedure is required
when the registration or state is missing or cannot be validated.

`supervised-run` displays the captured task, check argv, limits, checkout, base,
remote, selected executable and environment before approval. It runs the captured
task once and checks in order, stores child output and tracked diff in private
project state, and reports HEAD, index, worktree status and log paths. Inspect
the complete workspace, including untracked and ignored files, and review the
actual changes yourself; a successful command is not acceptance. The runner does
not itself create a PR, push, merge or deploy. It reports cost as unavailable
when it has no provider-reported amount.

On timeout, interruption or another uncertain outcome, stop and inspect the
original checkout, processes and possible external effects. The unresolved
attempt blocks another run. Use `supervised-status` to find its identifier,
including an interrupted preparation. Only after inspecting the facts should the
operator use `supervised-reconcile` and confirm the displayed note. The command
records that decision; it does not stop processes, perform cleanup or prove
absence. An incomplete preparation is preserved in private history before its
block is cleared. Malformed or missing required state requires manual recovery;
never reinitialize to bypass uncertainty.

The terminal report precedes the foreground process's exit. After a normal exit,
the observer attempts to clear the matching guard asynchronously; an immediate status or
run can briefly report that the project lock is held. Retry status after the
observer has finished. A persistent lock, `unresolved` status, missing report,
or abrupt foreground command loss requires inspection and reconciliation, not
an automatic retry. A successful terminal write and flush means the operating
system accepted the output; it cannot prove that a person read it. `ready` means
only that this state gate permits a new attempt, not that project changes are
accepted or external effects are absent. A `ready` response can still include
the previous attempt in `pending`: its valid clearance makes that guard ready;
an `unresolved` status instead requires the inspection above. Logs may contain
sensitive command or model output; keep them private and outside Git.

## Update, uninstall and recovery

Review the new wheel/metadata/provenance and applicable checks before an update.
Install it into that same owner's venv:

```sh
uv pip install --python "$PROJECT/.agent-runner/venv/bin/python" --no-deps "$WHEEL"
```

Use
--reinstall-package agent-runner only for an explicitly requested reinstall of the
same version. Re-run isolated import, help and doctor. Retain the prior reviewed
wheel and owner receipt; a package downgrade never rolls back runtime effects.

Uninstall package code:

```sh
uv pip uninstall --python "$PROJECT/.agent-runner/venv/bin/python" agent-runner
```
Verify `importlib.util.find_spec("automation")` is None in that venv. Preserve config,
private enrollment, logs, state and consumed history. Delete an identified disposable
venv only when authorized; no blanket project-directory removal.

Failed startup recovery: capture the return code/report, check exact installed
version/import location and owner config/host/digest. `run` is expected to reject
without starting a process/service. Correct invalid advisory inputs deliberately,
then rerun doctor. Never interpret that as recovery of an actual workload. If any
real operation is uncertain, preserve UNKNOWN, hold state/consumption, reconcile
original objects and use TROUBLESHOOTING.md; no replay or automatic reset.
