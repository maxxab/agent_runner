# Project-owner installation and recovery

This guide covers the current **advisory package**, not an operational release.
Owner chat first reads /home/faris/development-standards/skills/agent-runner/SKILL.md
and canonical POLICY.md. Explicitly select one project and obtain its opt-in;
reading the skill does not authorize installation into any other project.

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
There is no supported start/run/status/stop service command yet. A startup request
must be declined with those release gates; do not invoke private qualification
binaries as a substitute. Advisory commands exit after their report, so there is
no installed service to stop. Capture each command's stdout/stderr in distinct
private project-owned log files if needed; do not put credentials/raw private
runtime evidence in Git. No global runtime log or Store is created by this package.

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
