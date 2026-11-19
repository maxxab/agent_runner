# agent_runner

Dedicated runner project, extracted from development-standards. Proposed package
version **0.1.0.dev0**, unpublished and **NOT RELEASE READY**. No live runner,
service startup, agent workload or production acceptance is enabled.

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
The product plan's historical placement/bootstrap instructions are superseded by
this migration and the owner guide; its acceptance IDs and safety contracts remain.

All five release gates remain OPEN: actual complete runtime profile/original
membership; real private entry and bound session/rnr_command; whole independent
keeper/containment/recovery; immutable startup closure; actual integrated
success/failure/recovery qualification. RootEntry STORE_READY_ONLY and synthetic
or disabled paths are not a release. Production validation NEVER RUN.

No automatic installation, global service changes, enrollment, credential lookup,
public package publishing or cross-project activation occurs on package import.
