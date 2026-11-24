# Runner requirements and release evidence

This is the navigation and traceability index for the existing product requirements.
It does not replace their detailed contracts or create another backlog. Latest
checkpoint: [24 November release progress](handoffs/2026-11-24-release-progress.md). The current
package is advisory; operational acceptance remains incomplete.

## Authoritative sources

- [Product plan](superpowers/plans/2026-11-09-shared-ai-development-workflow.html):
  RNR-AC-01–08, TW-01–10, component contracts and RNR-D00–07 planning labels.
- [Current admission contract](superpowers/plans/2026-11-19-persistent-admission-contract.md):
  F1 durable consumption/recovery, F2 trusted inputs and protocol, F5 containment.
- [Selected admission direction](migration/prior-evidence/keeper-design119.md) and
  [interface review](superpowers/plans/2026-11-19-selected143-admission-review.md).
- [Protected provider route](superpowers/plans/2026-11-19-protected-provider-route.md):
  current proposal and remaining authentication, custody, retry and transport gates.
- [Project-owner guide](project-owner.md): separate opt-in, installation,
  configuration, enrollment, identity, state, update and recovery for each project.
- [Shared policy](/home/faris/development-standards/POLICY.md) and the single
  [runner skill](/home/faris/development-standards/skills/agent-runner/SKILL.md):
  canonical development and owner workflow. These shared instructions stay in
  development-standards; they are not Python runtime dependencies.

## Product acceptance map

| Requirement | Observable outcome | Existing implementation/evidence boundary |
| --- | --- | --- |
| RNR-AC-01 | Explain eligible, excluded and blocked work | `automation/cli.py`, `config.py`, `selection.py`; doctor and offline preview are advisory |
| RNR-AC-02 | Execute only under acknowledged current ownership and admitted limits | `control.py`, `control_store.py`, `control_bootstrap.py`, native admission; actual runtime integration open |
| RNR-AC-03 | Check and independently review the exact frozen candidate | workspace/check/review contracts; whole operational path open |
| RNR-AC-04 | Stop, preserve limits and reconcile unknown effects without replay | Store, accounting, journals, keeper and recovery contracts; integrated fault qualification open |
| RNR-AC-05 | Publish a verified delivery for human merge | controller-owned delivery/Git contracts; actual delivery acceptance open |
| RNR-AC-06 | Run independent work within capacity and resource ownership | allocation and session contracts; claimed runtime modes need actual evidence |
| RNR-AC-07 | Reconcile acceptance, closure, feedback and resource release | existing finalization contracts; integrated lifecycle acceptance open |
| RNR-AC-08 | Adopt the same package in another opted-in project | isolated advisory consumer checks exist; operational second-project demonstration open |

RNR-D00 proves required runtime capabilities; it is not the complete product.
RNR-D01–07 describe preview, local execution, recovery, publication, parallel work,
finalization and adoption. These remain local planning labels, not invented GitHub
issue numbers. Current scope and completion evidence belong to the maintained
plans and handoffs.

## Five operational release gates

All remain open until current evidence establishes:

1. The complete actual runtime profile, original process membership and isolation.
2. A real supervised private entry, bound session and `rnr_command` callback,
   including the protected authenticated provider route.
3. Whole keeper/observer containment, actual lifecycle and recovery behavior.
4. The immutable executable, configuration, catalog and dependency startup closure.
5. Integrated actual success, failure and recovery qualification for that closure.

Data decoders, mocked tests, package installation, compile-only native builds and
`STORE_READY_ONLY` do not close these gates. Preserve protected evidence, stores,
consumed attempts and account material outside Git.

## Implementation and verification rules

The product plan's `full-implementation-entry` section permits authorized work
that does not depend on a missing capability. The complete crash matrix, remote
lifecycle, cross-platform checks and adoption demonstration are acceptance work;
they are not prerequisites for every source edit. Independently challenge each
consequential interface before dependent source, and retain the complete coupled
F1/F2/F5 gate before any positive admission/GO or operational activation.

Two earlier investigation assumptions are corrected: `launch_live` checks launch
state, not clock samples, and arbitrary simultaneous loss of both negative actors
is not an explicit selected143 guarantee. Neither is established as a current
implementation defect. The documented keeper-loss/observer-survival, pre-READY
failure and original deadline requirements still apply.

## Environment and new-project requirements

The package requires Python >=3.12 and Git, has no ordinary Python runtime
dependencies, and uses a reviewed wheel with a project-local environment. Native
source verification targets Linux x86_64/GCC13. Actual Codex, Docker, systemd,
cgroup, immutable storage and provider behavior require separate runtime evidence.
No project-local `.env` is required by the current package. The shared standards
`.env.local` provides GitHub tooling authentication only; it does not supply runner
configuration, enrollment or a runtime grant. Do not copy it into consumer projects.
Installed versions alone are insufficient. [Experiment setup](experiment-setup.md)
retains historical SDK/profile pins and is not a current activation runbook.

Each project needs its own reviewed `.agent-runner/automation.json`, full approved
revision/config digest/host binding, private enrollment and separate runtime state.
Do not share enrollment, consumption, Store identity or account material between
projects. Current supported user commands are `doctor` and `preview`; see the
owner guide for exact behavior and recovery.
