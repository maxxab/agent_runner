# Runner extraction execution plan

Goal: move the complete runner to agent_runner on existing main; stop before feature work.
Spec: user extraction request dated 2026-11-19, source 5de59c4.
Main /root is sole writer and Git owner. No branches/worktrees, live activation, package publication or force push.

- [x] Inventory and scoped import; map every source file and protect external evidence.
- [x] Package existing automation/tools names and native sources; provide independent CLI and canonical skill.
- [x] Trace imports/config/native/consumer flow, then run relocated and installed checks.
- [x] Remove verified runner-owned source only; narrow mixed shared entry points; test shared standards.
- [x] Review migration, commit each repository, attempt normal pushes, verify remote outcomes.
- [x] Save exact handoff/new-chat request; all five release gates remain OPEN.

Layout decision: retain the flat automation/native and tools paths because the current native fixtures and frozen runtime source declarations use them. Use explicit wheel packages/resources and outside-checkout installed verification to prevent accidental source imports. This is a deliberate adaptation of modkit's packaging approach, not a claim of modkit qualification.

Trace before verification: console entry -> automation.cli -> approved immutable Git config + private enrollment -> advisory report with execution disabled. Python imports are stdlib + automation + tools only. Native fixtures include local C sources; installed build uses only packaged native sources. Historical protected runtime selectors remain fixed and are not executed. Disposable consumers have separate Git repositories, venvs, pinned config, enrollment and logs; no service startup is supported yet.

Completion: all scoped migration checks and independent corrections closed. Normal
source HTTPS push and destination SSH push succeeded. Final docs/changelog commits
may follow; external final-checkpoint.json records final observed hashes. Feature
implementation stops here; all five runner release gates remain OPEN.
