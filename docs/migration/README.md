# Extraction map and boundaries

See manifest.json for all 355 source tracked paths, including 214 migrated paths
and intentional retained/shared exclusions. Every migrated file has its original
SHA256 at source revision 5de59c4. Source history remains in the original repository;
this is a scoped provenance-preserving snapshot import, not unrelated history.
New packaging/CLI/consumer docs are destination-owned additions.

Compared conventions: modkit-events uses explicit Hatchling wheel/sdist packages,
Python>=3.12, packaged resources, build/installed checks and independent CI lanes;
modkit-workers declares its one-way dependency and labels incomplete resources.
We use those packaging/verification and readiness conventions. Neither project is
asserted release-qualified. Their MIT license and functionality are not copied.
Flat automation/tools layout is retained for existing native includes and frozen
source declarations. Installed checks run outside both source checkouts.

Runtime Python dependency closure is stdlib + packaged automation + packaged tools.
Native C/H resources ship in wheel/sdist, GCC/Linux x86_64 is needed to build them.
The future fixed /rnr/project, /var/lib/rnr and cgroup paths are immutable runtime
contracts, not host-checkout paths. They remain dormant and must receive a newly
qualified immutable startup closure before activation. No editable install,
PYTHONPATH or source symlink is used for consumer checks.

Shared canonical policy, teamwork and agent-runner skill remain in the standards
repository. Standards adoption is reference-mode plus managed validation tooling;
it is a development dependency, not a Python runtime dependency. Host CPython/Git,
optional GCC, and the separately qualified Codex/Docker/systemd/Linux toolchain are
explicit prerequisites, not installed automatically by this package.

Historical documents/evidence are preserved verbatim unless marked as a live
entry-point update. Historical absolute source paths and bootstrap examples must
not be executed as current instructions. Follow docs/project-owner.md instead.
The portable prior-evidence folder contains only selected checkpoint/design text;
full reports, schemas, consumed records, runtime stores, media and native binaries
stay under the original protected paths. Some historical schema tests skip when
those external schemas are unavailable; CI cannot claim those checks passed.

Protected evidence root:
/home/faris/.local/state/development-standards/runner-receiver-guard-20261117/live-completion-20261118
Never move, reinitialize, replay consumed attempts or stage that directory.
Current migration checks live separately at
/home/faris/.local/state/agent-runner/migration-20261119.

Scope differences: config now uses committed .agent-runner/automation.json;
legacy enrollments pinned to the old config path are not transparently accepted.
An owner must deliberately approve a new config/revision/digest/enrollment.
CLI is agent-runner or python -m automation, no bootstrap dependency. The
old standards automation command is removed. No other runtime behavior is enabled.

## 19 November extraction audit

The [audit handoff](../handoffs/2026-11-19-extraction-audit.md) records successor
ownership, source/dependency trace, verification and release limits. Original
manifest hashes remain the extraction snapshot; `audit_reconciliation` records
the later split of runner experiment setup from shared PC setup and the corrected
shared-skill documentation reference. Dedicated post-extraction source commits are
not folded back into historical hashes.

[External source index](external-source-index.json) identifies protected historical
qualification/diagnostic/SDK candidates and schema provenance. Only this sanitized
index is transferred; original source, frozen native resources, runtime state and
consumed grants stay in place. Their historical path/pin bindings are intentional
and do not become current package dependencies. The bounded inventory is not
whole-release qualification or an exhaustive audit of private experiment contents.
