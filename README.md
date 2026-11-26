# agent_runner

Dedicated runner project, extracted from development-standards. Local package
version **0.1.0.dev0** provides the supervised single-task first release for a
trusted operator on the qualified Linux/WSL2 host. It passed independent source
review, failure tests, an authorized live run on a synthetic fixture and one
approved User Admin documentation task. See the [release record](docs/releases/2026-11-25-supervised-first-release.md)
for the exact artifact, evidence and limits, and the
[owner guide](docs/project-owner.md) for project opt-in and per-run approval.
The package is unpublished; automatic service startup and the original hardened
runtime remain unavailable with their release gates open.

For a simple explanation and a small example task with a verification checklist,
use the [supervised test walkthrough](docs/supervised-test-walkthrough.md).

The [architecture guide](docs/architecture.md) explains the complete supervised
lifecycle with component, sequence and state diagrams, including normal-exit
clearance and explicit recovery.

The installed `agent-runner doctor` and `preview` commands provide read-only
advisory reports. Python >=3.12 and Git are required; ordinary Python runtime
dependencies are empty. Existing `automation` and `tools` import names and flat
native-source paths are retained for compatibility with reviewed source contracts.

Project owner chats must read the single canonical
[agent-runner skill](/home/faris/development-standards/skills/agent-runner/SKILL.md),
then follow [project-owner installation and recovery](docs/project-owner.md).
Shared policy/skills stay in development-standards; there is no runtime import from
that checkout and no copied skill in this repository. Other hosts must establish
the canonical shared skill checkout/discovery path before using that workflow.

Build/check from this checkout with `uv build` and
`python3 -m unittest discover -s tests -v`. Then run
`python3 scripts/check_installation.py dist/agent_runner-0.1.0.dev0-py3-none-any.whl`.
That check uses uv to install into separate disposable consumer environments and
builds packaged native artifacts without running them. GCC 13 on Linux x86_64 is
the checked native target; the installed package does not auto-build/activate them.

[Historical experiment setup](docs/experiment-setup.md),
[Migration/provenance](docs/migration/README.md),
[handoff](docs/handoffs/2026-11-19-extraction.md),
[accepted product plan](docs/superpowers/plans/2026-11-09-shared-ai-development-workflow.html),
[advisory contracts](docs/automation.md), [incident history](TROUBLESHOOTING.md).
The [requirements and release evidence index](docs/requirements.md) connects the
product acceptance IDs, current contracts, environment prerequisites and owner flow.
The product plan's historical placement/bootstrap instructions are superseded by
this migration and the owner guide; its acceptance IDs and safety contracts remain.

All five original autonomous-runtime release gates remain OPEN: actual complete runtime profile/original
membership; real private entry and bound session/rnr_command; whole independent
keeper/containment/recovery; immutable startup closure; actual integrated
success/failure/recovery qualification. RootEntry STORE_READY_ONLY and synthetic
or disabled paths are not a release. Production validation NEVER RUN.
The owner-approved narrower [supervised first-release design](docs/superpowers/specs/2026-11-25-supervised-first-release-design.md)
has separate acceptance criteria; it does not close these original gates.

No automatic installation, global service changes, enrollment, credential lookup,
public package publishing or cross-project activation occurs on package import.
