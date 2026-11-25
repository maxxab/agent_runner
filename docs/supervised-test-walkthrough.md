# Try one supervised task, step by step

This walkthrough is for the local supervised first release on the qualified
Linux/WSL2 host. It prepares a test; writing this guide did not run a new task.
Use the existing [owner guide](project-owner.md) for installation, project setup
and recovery, and the [release record](releases/2026-11-25-supervised-first-release.md)
for completed release evidence.

## What you are testing

Ask the runner to create one small text file, run the project's existing checks,
report the result, and stop. You then read the file and decide whether to accept
it. This checks the supervised workflow without asking for a product feature.

You are the operator: the person who approves the run and reviews its result.
The runner does not choose another task, approve itself, or work unattended
through a list. That autonomous mode is deferred to v0.2.

Use these three decisions throughout the test:

| Decision | Meaning | Example |
| --- | --- | --- |
| Succeeded | The step matches its expected result. | Every agreed check passed and the new text is correct. |
| Needs review | Something is unexpected or unclear; inspect before continuing. | An extra file changed, or a test was skipped. |
| Needs improvement | You found a specific problem to fix. | The requested sentence is missing. Write down the correction before approving another run. |

## 1. Choose the approved project and checkout

Ask the project owner to identify the exact checkout, private enrollment file
and installed runner. A checkout is the project folder where the task will work.
Use an already approved clean, disposable checkout at its enrolled commit.
Do not use a project with unfinished changes or create a new checkout without
the project's authorization.

Replace these example paths with the actual approved paths. They are placeholders,
not a request to create folders or enrollment files:

```sh
PROJECT=/absolute/path/to/approved-disposable-checkout
ENROLLMENT=/absolute/private/path/to/project-enrollment.json
RUNNER="$PROJECT/.agent-runner/venv/bin/agent-runner"
TASK=/absolute/private/path/to/new-trial-task.txt
CHECKS=/absolute/private/path/to/reviewed-checks.json
```

The task and checks files must be outside the checkout, in an owner-controlled
private directory. Use a new task filename; preserve existing files and evidence.

**Verify:** the owner confirms that the paths belong to this project, the
installation/setup is complete, and the intended test is authorized. If setup
is missing, follow the owner guide first; do not guess the enrollment contents.

**Existing User Admin example:** its accepted trial is in
`/home/faris/.local/share/agent-runner-trials/user-admin-20261125`.
It already contains accepted, uncommitted documentation edits. Review those
results first; do not rerun this test there or erase the edits to make it clean.
Its earlier approval covered one run and has already been used.

## 2. Check the starting point

For a trusted checkout, inspect:

```sh
git -C "$PROJECT" status --short
git -C "$PROJECT" rev-parse HEAD
git -C "$PROJECT" remote get-url origin
"$RUNNER" doctor --project "$PROJECT" --enrollment "$ENROLLMENT"
"$RUNNER" supervised-status --project "$PROJECT" --enrollment "$ENROLLMENT"
```

Git inspection can run repository-configured filters. Inspect only a checkout
you trust. Record the starting commit shown by `rev-parse HEAD` privately.

**Verify:**

- `git status --short` is empty. The commit and remote match the reviewed enrollment.
- Doctor reports `configuration_valid: true`. Its `execution_enabled: false` and
  native runtime unavailable message are expected: doctor describes the separate
  advisory/native path, not whether the supervised test succeeded.
- Supervised status reports `ready`.
- `RUNNER_TRIAL.md` does not already exist, including as an ignored file.
- Inspect existing ignored files too; only expected environments/caches should
  be present. The owner guide explains their handling.

**Needs review:** dirty files, a wrong commit/remote, missing setup, or `unresolved`
state. Stop and ask the owner to resolve that specific issue. Do not delete state,
reset files or repeat `supervised-init` to get past it.

## 3. Prepare one clear task

Save this text as the new private file selected by `TASK`:

```text
Create RUNNER_TRIAL.md in the project root with exactly these contents:

# Runner trial

This file was created during an approved supervised runner test.

Do not change any existing file. Do not install dependencies, commit, push,
open a pull request, or deploy. Stop after creating the file and reporting it.
The runner will execute the separately approved project checks afterward.
```

**Verify:** read the task yourself. The target file is new, its contents are
clear, and there is only one requested change. Task wording guides trusted
commands; it is not a technical barrier against other effects.

## 4. Review the checks before running

Use the project's reviewed checks file. Its check names must exactly match the
enrolled `required_checks`. Do not remove a check to make the test pass.

For example, **only for a project enrolled with just `unit`**, a Python unittest
project could use:

```json
{
  "schema_version": 1,
  "codex_timeout_seconds": 900,
  "check_timeout_seconds": 300,
  "checks": {
    "unit": ["python3", "-m", "unittest", "discover", "-s", "tests"]
  }
}
```

This allows up to 15 minutes for Codex and 5 minutes per check. Replace the
example command with the project's actual approved command. A project requiring
`unit` and `links`, such as the accepted User Admin trial, needs both entries.
The command must find the correct installed project dependencies.

If a particular model/effort is required, supply both optional fields as described
in the owner guide. Then verify the CLI's actual reported settings in its log;
the requested settings alone are not proof.

**Verify:** the checks file belongs to the operator, is not writable by other
users, is not a symlink, and contains all required checks. Read the actual test
output later: exit 0 with zero tests or unexpected skips needs review.

## 5. Approve and start the single run

Use a dedicated foreground terminal where you can see prompts and stay available:

```sh
"$RUNNER" supervised-run --project "$PROJECT" --enrollment "$ENROLLMENT" --task "$TASK" --checks "$CHECKS"
run_exit=$?
echo "Runner exit code: $run_exit"
```

First read the Git-inspection warning. Then read the detailed run summary:
checkout, starting commit, task, check commands, executable and time limits.
Type `APPROVE` at each approval prompt only if the displayed information matches
what you reviewed. Otherwise decline and investigate; do not automatically answer
the prompts with a script.

**Verify:** this is exactly one intended run in the correct project. Keep the
terminal open until the command exits. Save the attempt ID and private log paths
from the report. Do not paste raw private logs into Git.

## 6. Check the command result

Read the final report and the logs it names. A normal successful result includes:

- Runner exit code `0` and report `status: completed`.
- `codex_exit: 0` and every required check listed with exit code `0`.
- `head_changed: false` and `index_changed: false`, because this task forbids commits
  and staging changes. `final_head` matches the starting commit.
- `review_required: true`. This is expected even when commands passed.

**Example:** Codex exits 0, `unit` runs the expected tests and passes, and the report
lists the new file. The command step succeeded; the file still needs your review.

**Needs review:** a failed check, missing check, unexpected skip, extra change,
or different CLI settings. Later checks stop after the first failed check, so
missing later results are not passes. If Codex fails, checks are not run.

**Uncertain result:** `unknown`, a timeout, an interrupted terminal, or a missing
complete report. Follow step 9 before considering another run.

## 7. Read the actual changes

For the same trusted checkout:

```sh
git -C "$PROJECT" status --short
git -C "$PROJECT" diff --stat
git -C "$PROJECT" diff
git -C "$PROJECT" diff --cached
git -C "$PROJECT" diff --check
git -C "$PROJECT" ls-files --others --exclude-standard
git -C "$PROJECT" status --short --ignored
git -C "$PROJECT" rev-parse HEAD
cat "$PROJECT/RUNNER_TRIAL.md"
```

**Verify:** only `RUNNER_TRIAL.md` is new, it contains exactly the requested title
and sentence, existing files are unchanged, the staged diff is empty, and HEAD
still matches the starting commit. Inspect any new ignored output too.

`git diff` does not show a new untracked file's contents. That is why you also
list untracked files and read the file with `cat`.

**Succeeded:** checks passed and your file review matches the task.
**Needs improvement:** the sentence is wrong or another file changed. Preserve
the result, describe the exact problem and arrange an approved correction.
Do not call an incorrect result accepted just because the checks passed.

## 8. Check that the runner has finished

After the foreground command exits:

```sh
"$RUNNER" supervised-status --project "$PROJECT" --enrollment "$ENROLLMENT"
```

**Verify:** `status: ready`. A brief lock immediately after exit can mean the
observer is still finishing; wait briefly and check status again. A persistent
lock or `unresolved` state needs investigation.

`ready` means the runner's state permits another attempt. It does not mean the
files were accepted, the checkout is clean, or another run is approved. A `pending`
field may still name the previous attempt after valid clearance; use the top-level
status and the owner guide to interpret it.

## 9. Handle failure or uncertainty

| What happened | What to do |
| --- | --- |
| A test failed, but there is a complete report | Read the failing check's log and inspect the changes. Identify whether the task caused the failure or the environment/test already had a problem. Do not weaken checks. |
| Text is incorrect, but tests passed | Record the exact wording correction. This is a task-quality problem; tests did not establish that the writing was correct. |
| Timeout, `unknown`, missing report, or `unresolved` | Stop. Ask the owner to inspect the original checkout, processes, logs and possible outside effects. Do not immediately retry. |
| State is missing or damaged | Use the owner guide's recovery process. Do not delete or recreate registration/state. |

Only after the facts are understood may an operator explicitly reconcile an
uncertain attempt using the owner guide. Reconciliation records a decision;
it does not stop processes or repair files. A later run needs its own approval,
a clean checkout at the enrolled base and all ordinary checks again.

## 10. Record your decision

Keep a short result in the existing project review/backlog location. Keep raw
logs, enrollment and runtime records in private storage outside Git.

```text
Task: Create RUNNER_TRIAL.md with the agreed title and sentence.
Attempt: <ID from this run>
Commands/checks: <actual result and test count>
File review: <actual files checked and whether their contents match>
Final runner status: <actual status>
Decision: Succeeded / Needs review / Needs improvement
Next action: <none, or the precise correction/investigation needed>
```

Example successful decision: “Codex and all required checks passed. Only the new
file changed; its text is correct. HEAD/index unchanged. Runner status is ready.
Accepted for this test.”

Example improvement decision: “Checks passed, but the sentence is missing.
Not accepted. Correct only the missing sentence in a separately approved task.”

Accepting the test does not commit, merge, publish or deploy its changes. The
project owner decides their disposition through the existing project workflow.
