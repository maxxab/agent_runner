# Dedicated agent_runner project

Before runner work, read the single canonical
/home/faris/development-standards/skills/agent-runner/SKILL.md and canonical POLICY.md.
Use existing main; no branches/worktrees/force push. Runner migration stops before
feature implementation. Follow docs/handoffs/2026-11-19-extraction.md for current
ownership/evidence and unfinished release gates. No automatic live activation.
Project-owner workflows require explicit per-project opt-in; do not share state or
enrollment across projects. Runtime stores, consumed records and evidence stay at
protected external paths, never in Git. Preserve unrelated edits.

## Simplicity is a strict requirement

Always choose the simplest common, reliable approach that fully meets the authorized requirements. Reuse established mechanisms. Avoid speculative abstractions, extra protocols or custom machinery when a simpler supported solution fits. Add complexity only for a demonstrated requirement, explain why it is necessary, and reconsider designs that repeatedly obstruct implementation. This user instruction applies to ongoing and future work in this project.

<!-- development-standards:start -->
Development standards version: 1.3.0

The canonical development policy is at /home/faris/development-standards/POLICY.md. Read it before work.

Custom Codex skills (canonical source): /home/faris/development-standards/skills. Read the relevant SKILL.md when applicable.
Optional documentation guidance, when applicable: /home/faris/development-standards/docs/documentation-guidelines.md.
Optional shared templates: /home/faris/development-standards/templates.
<!-- development-standards:end -->
