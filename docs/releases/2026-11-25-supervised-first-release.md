# Supervised single-task first release — 0.1.0.dev0

**Decision, 25 November 2026:** Ready for local, explicitly approved foreground
supervised runs on the qualified host, with trusted project code and a clean
disposable checkout. The owner approved this narrow first release and separately
authorized the completed synthetic fixture qualification. Another project still
needs its own enrollment, opt-in, reviewed task/checks and foreground approvals.
No unattended service or autonomous task selection is offered.

## Scope freeze and implementation closure

The owner accepted closing v0.1 as the supervised runner and reserving autonomous
operation for v0.2. **Release implementation is closed** at delivered source
`27519eef206d649e0e4a50c1360f9cac82325773` and the corrected wheel identified
below. Reopen only for a demonstrated defect preventing supervised use; further
features and hardening are deferred. This v0.1 scope label does not create a tag
or change the unpublished package version `0.1.0.dev0`.

The original RNR-D00/G1–G6 requirements and five operational gates remain open in
the existing [requirements index](../requirements.md) and
[admission contract](../superpowers/plans/2026-11-19-persistent-admission-contract.md).
They are retained autonomous follow-up work, not waived requirements or claims
of v0.2 readiness. Keep the native unconditional abandon/exit-125 fence.

**First-project acceptance is complete, 26 November 2026**, for the single
authorized User Admin documentation task recorded below. The owner explicitly
approved its separate-checkout exception, local setup commit, project enrollment/
opt-in and one foreground provider invocation. The task/config remained unchanged;
immutable revision2 added only explicit `gpt-6.1-sol` / `medium` checks settings.
This closes the approved supervised v0.1 delivery scope. Further projects and
runs still require their own authorization.

## First-project acceptance — User Admin

Main reviewed and accepted the result of attempt
`115c0ffb757a222d9a0e682b4c322385`. The approved disposable clone is
`/home/faris/.local/share/agent-runner-trials/user-admin-20261125`, existing main
from `db10197fe11c1b99e24412e85db26c8305bf4f46`. Its local setup commit
`7927a1777849e81d9b0e1a9c13cb03003054d633` adds only the reviewed runner config,
ignore rules and backlog preparation entry. Private enrollment pins that commit,
host `DESKTOP-3CK36LV` and config SHA256
`35a7f5018ca18d7af78fb77371d5af56127921b6c446aff8018542d72cbcaee8`.
Offline locked dependency synchronization, isolated project runner installation/
import and advisory doctor passed. Doctor continued to report native runtime
unavailable; it did not start one. The exact corrected wheel below was used.

| Acceptance boundary | Observed evidence | Result / limits |
| --- | --- | --- |
| Explicit project and run approval | Separate checkout/opt-in summaries and captured task/checks/base/settings inspected and approved in the foreground; pre-run state `ready`; one 900s task, 180s/check | PASS; one CLI invocation, no runner retry or fallback |
| Requested and effective settings | Installed CLI 0.162.1 log reports `gpt-6.1-sol`, reasoning effort `medium`, provider `openai`, workspace-write and the selected disposable checkout | PASS for CLI-reported settings; account identity, cost and provider-side effects unaudited |
| Task and checks | Codex exit 0; ordered `unit` exit 0 (67 tests passed in 1.25s), `links` exit 0 (21 local targets, none missing) | PASS for these narrow source/link checks; no live integration qualification |
| Reviewed result | Only `docs/developer/README.md` and a new `BACKLOG.md` task entry changed; wording matches source profile/opt-in/evidence limits, correct relative review link; diff whitespace check passed; HEAD/index unchanged, no nonignored untracked files | PASS; result retained uncommitted in the disposable checkout, no User Admin push |
| Normal exit and clearance | Complete terminal report and exit 0; attempt-bound result clearance certificate; post-exit `supervised-status` returned `ready` | PASS under the previously qualified observer/filesystem limits; historical `pending` identifies the cleared attempt |
| Original work custody | Authoritative User Admin remains at db10197 with the same two original dirty file hashes and status | PASS; neither original file nor frozen proposal was changed |

Protected proposal:
`/home/faris/.local/state/agent-runner/proposals/user-admin-docs-20261125/revision2/proposal.json`.
Protected evidence:
`/home/faris/.local/state/agent-runner/release-admission-20261119/user-admin-first-use-20261125/`:
`approved-ownership.json`, `setup-result.json`, `installation.log`,
`live-operation.json`, `terminal-results.json`, `accepted-task.patch` and
`acceptance-result.json`. The latter pins private log, attempt and clearance
digests; runtime records remain at the project's separate fixed supervised-v1
state location outside Git. No unresolved attempt was erased or reinitialized.

Ignored output comprises the owned runner/product environments and pytest/Python
caches. Source review and the accepted result do not prove absence of escaped
descendants or external effects. No service, container, native qualification,
deployment, automatic activation, new branch/worktree or User Admin publication
was performed. The original autonomous gates and exit-125 fence remain intact.

## Artifact and supported environment

The source was qualified from a working snapshot of `/home/faris/agent_runner`,
branch `main`, based on HEAD `a39202b2b925d02b1d5a3a554de1bfe256d252e4`.
The protected manifests and wheel digest identify that snapshot. After the
owner authorized commit and push, the preserved native progress was committed
as `9815ba5` and the supervised implementation as `a7c5077`. Later checkpoint
documentation/changelog commits and the actual push result are recorded in
the protected `supervised-chat-checkpoint-20261125.json` receipt referenced by
the handoff. No package tag or package publication was performed. The package
retains its local development version; identify an installation by exact wheel
SHA256 as well as version.

The qualified environment is user `faris` on Linux/WSL2 host `DESKTOP-3CK36LV`,
Python 3.12.3, Codex CLI 0.162.1, model `gpt-6.1-terra` and CLI-reported provider
`openai`. The CLI binary SHA256 was
`628e35487d888a28f0427fc37501da529dd3d81fcbad7a2c3421c1e8670d92e1`.
The effective account identity was not independently verified.

The live-tested wheel is retained outside Git at
`/home/faris/.local/state/agent-runner/release-admission-20261119/supervised-recovery-wheel-20261125/agent_runner-0.1.0.dev0-py3-none-any.whl`,
SHA256 `9d3b86a3dd937ecb9a3d4fe6c6e463831e86c6473b0d50dd23226db8f5f6552e`.
The release packaging check below distinguishes that live-tested artifact from
the documentation refresh; it does not imply a second provider run.

The earlier documentation-refresh wheel is
`/home/faris/.local/state/agent-runner/release-admission-20261119/supervised-first-release-20261125/agent_runner-0.1.0.dev0-py3-none-any.whl`,
SHA256 `8b1210b63054005594da8ced62422e2279eda2fe8ea631f64e356e0b1016d871`.
It was built offline and installed into an isolated verification venv. All 102
archive entries were checked, including 24 unchanged native resources, with no
compiled objects, private environment files or state. Every packaged source
matched the checkout. Compared with the live-tested wheel, all executable source
and native resources were byte-identical except the `automation/__main__.py`
docstring; its executable AST was identical. README metadata was refreshed.
Thus the prior failure tests and independent runtime-source review remain
applicable; a second full suite or provider run was not needed for these prose
changes.

Installed isolated imports, console/module CLI help and advisory doctor passed;
the installed read-only status command reported the existing fixture `ready`.
The protected artifact directory retains `build.log` and `installed-smoke.json`.
No consumer installation was replaced by these packaging checks. The complete
two-consumer/native-build installation script was not rerun; this refresh's
verification covers the unchanged resources and the installed checks above.

## Bounded requested-model correction

The current corrected local wheel is
`/home/faris/.local/state/agent-runner/release-admission-20261119/supervised-model-fix-20261125/wheel/agent_runner-0.1.0.dev0-py3-none-any.whl`,
SHA256 `1c2306d43d4d741539a942c00d97022fc1d2d804509d9db022e3b9c289362cb7`.
It was built offline from the protected tracked working snapshot based on
`2c21124d4cc26cb590d03c32355de7cc6da4ade5`. The source snapshot precedes the final
handoff/release prose; all packaged source bytes match the reviewed checkout.
No tag or public package publication was performed; use this exact digest.

Checks JSON can now supply paired optional `codex_model` and
`codex_reasoning_effort` fields. The runner validates and captures both, includes
them in approval and final reporting as requested settings, and passes separate
fixed arguments to Codex. Omission retains CLI defaults. Changed inputs prevent
launch; a CLI rejection stops without runner retry or fallback. The state and
recovery format is unchanged. Follow the [owner guide](../project-owner.md).

| Correction criterion | Evidence, 25 November 2026 | Result / limits |
| --- | --- | --- |
| Paired validation, captured selection, exact argv and reporting | 67 focused tests passed before the final reporting-note correction; its targeted regression then passed after demonstrated failure; final default suite ran 1,562 tests in 580.338s, OK with seven skips | PASS with fake local commands; no provider call for this correction |
| Independent interface and final source review | Protected `supervised-model-fix-20261125/review-handoff.json`; all six reviewed file hashes rechecked at delivery | PASS; RNR-SUP-MODEL-R1 CLOSED, no remaining material finding in scope |
| Wheel and installed boundary | Offline build; all 102 entries inspected; 97 packaged files match current source; all 24 native resources match the live-tested wheel; offline isolated install/import, default/paired/partial parser and console/module help passed | PASS; no consumer installation replaced or native qualification repeated |
| Effective model, effort, provider and account | No live invocation of the new selection | UNKNOWN; operator must verify selected CLI output before real use |

The protected correction directory retains `source-snapshot.json`, `build.log`,
`artifact-inspection.json`, `installed-smoke.json`, `review-handoff.json`,
`delivery-trace.json`, `suite-result.json` and `full-suite.log`. The final full-suite
log SHA256 is `c3ae21040633ad602acfcca26f16f1dfaf2a9f02b0f109146389678766ddcaae`.
The successor observed the already-running suite to completion without rerunning it.
The earlier live qualification below remains evidence only for its recorded
fixture, artifact and CLI defaults. It does not qualify the new optional selection,
User Admin or another project. The corrected artifact is ready for the authorized
local source delivery within these limits; real-project opt-in and run approval
remain separate.

## Acceptance evidence

Evidence date is 25 November 2026. Main owns the release record and operator
handoff. Read-only independent review covered final source and design, not
independent execution of the live qualification.

| Criterion | Evidence | Result / scope |
| --- | --- | --- |
| RNR-SUP-01: captured inputs and foreground approval | Input/CLI tests in the full suite; live fixture's displayed checkout, base, task/check digests, selected executable and limits | PASS for the reviewed implementation and fixture |
| RNR-SUP-02: protected state and recovery | State, observer and real-PTY failure tests cover sync/restoration failures, loss after delivery token, observer death, failed output flush, concurrent/state replacement cases and reconciliation | PASS under the documented local-filesystem and Linux observer assumptions; no physical power-loss proof |
| RNR-SUP-03: one task and ordered checks | Fake-command failure/timeout tests and live attempt `9617346e686b26882f65e5013cdaa09c`: Codex exit 0, `unit` exit 0 | PASS for one runner invocation; internal provider/MCP connections are outside its retry promise |
| RNR-SUP-04: workspace and visible result | Complete foreground report, final HEAD unchanged, clean index/worktree, ignored fixture venv only, private logs, validated `ready` clearance | PASS; human review remains required for real changes |
| RNR-SUP-05: operator limits | [Owner guide](../project-owner.md), observed CLI version/model/provider/sandbox log and retained network errors | PASS for the stated limits; account, cost and external-effect audit unavailable |
| RNR-SUP-06: tests, independent review and live run | Full suite 1,556 tests / seven skips; final focused run 31 tests; independent final source/design review; separately authorized synthetic live run returned `QUALIFICATION_OK` | PASS for the recorded source and environment |
| Migration, autonomous deployment and native activation | This release neither migrates state nor starts a daemon or native wrapper | Not applicable to the supervised release; original gates stay open |

Protected evidence root:
`/home/faris/.local/state/agent-runner/release-admission-20261119/`.
The full-suite log `supervised-recovery-full-final.log` has SHA256
`5f3eb298b5a5396397ed74531cfc255b09d1ae5f39f9dad59ead6a2ed3c8a296`;
the focused log `supervised-recovery-focused-final.log` has SHA256
`a8dba3f4d820f791e9c8c5909d2f5b4bda4f0499ca92d16c2ca5a60c64babc24`.
`qualification-20261125/operator/qualification-result.json` records the actual
attempt and log/certificate digests. The
[handoff](../handoffs/2026-11-24-windows-visible-progress.md) preserves prior
review findings, corrections, authorizations and evidence history.

The canonical [architecture guide](../architecture.md) traces the implementation
with component, sequence and state diagrams. Its documentation checks are
separate from the qualification evidence above.

## Run and recovery

Follow the [owner guide](../project-owner.md): install the exact reviewed wheel
in the named project's venv, verify isolated imports and advisory `doctor`, then
use `supervised-init` once for explicit opt-in. Use `supervised-run` in a dedicated
foreground terminal and inspect `supervised-status` after exit. Only a separate
explicit authorization permits a real provider invocation; release readiness
alone grants none.

For `unknown`, an unresolved guard, lost output or abrupt runner loss, inspect
the original workspace, processes and possible external effects, then explicitly
confirm `supervised-reconcile` when the outcome has been reconciled. Retain all
records and logs. Do not reinitialize, delete state or retry to bypass a guard.
Package rollback or uninstall does not reconcile an attempt and must retain
private state; follow the owner guide's update/uninstall procedure.

## Limits retained

The process is single-threaded and depends on Linux ptrace permission, stable
signal dispositions, `/proc`, and a local filesystem supporting the documented
locking, fsync and hard-link behavior. Other hosts, network filesystems, native
Windows, physical power loss and all interactive shell job-control combinations
are unqualified. A process-group stop does not prove every descendant stopped.

The Codex run produced the expected response after model-refresh, WebSocket and
configured MCP connection/authentication errors. There was no independent audit
of provider/account effects, no measured price, and no enforced spending cap.
Task instructions to avoid tools are not an enforcement boundary. Trusted CLI
and project commands may use credentials, network and host files.

The original RNR-D00/G1–G6 work and five operational gates remain open. The
native wrapper retains its unconditional abandon/exit-125 fence. Those are
separate retained requirements; they do not prevent use of this explicitly
approved narrower foreground workflow within its documented limits.
