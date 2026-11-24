# RNR-D00 release checkpoint — 24 November 2026

Current continuation handoff. Read this before historical handoffs; earlier
unchanged contracts and evidence remain applicable. **All five operational release
gates are OPEN. The runner is not yet operational for new projects.**

## Objective, rules and ownership

Complete the first dependable local WSL release, repair discovered defects, review
and test the actual complete lifecycle, then demonstrate separate opted-in project
adoption. Do not substitute advisory/package/component checks for runtime acceptance.
The user requests autonomous completion, meaningful updates, and only one review
subagent in each chat; Main implements. No additional implementation team.

Read in order:

1. `/home/faris/development-standards/POLICY.md`, this checkout's `AGENTS.md`, and
   `/home/faris/development-standards/skills/agent-runner/SKILL.md`.
2. `/home/faris/development-standards/skills/teamwork/SKILL.md` before resuming.
3. This handoff and `docs/requirements.md` (acceptance/environment/source index).
4. `docs/handoffs/2026-11-19-extraction.md`, `2026-11-19-first-release.md`,
   `docs/migration/ownership.json` and referenced extraction verification.
5. `docs/superpowers/plans/2026-11-19-persistent-admission-contract.md`, especially
   latest C/D/E/F and structural policy subsection; selected143-admission-review,
   supervised-input-integration, protected-provider-route plans in that directory;
   `docs/migration/prior-evidence/keeper-design119.md`.
6. `docs/superpowers/plans/2026-11-24-admission-armed-authentication.md`, and protected
   evidence described below. It contains final source/check boundaries.

Checkout `/home/faris/agent_runner`, existing `main` ONLY. No branches, worktrees,
reset, force push or unrelated edit loss. User authorizes scoped commits and normal
SSH pushes `git@github.com:maxxab/agent_runner.git main:main`; preserve configured
HTTPS origin. Use per-command Git identity `fares201040` /
`fares201040@hotmail.com`. Run standards staged/range checks; generate changelog
in a separate commit. No public package publishing/general deployment, global SDK
or authentication changes. Keep runtime stores, consumed records, account data and
evidence outside Git. Every project requires separate explicit opt-in/configuration/
enrollment/identity/state. No live activation before actual whole acceptance.

Original retained request:
`/home/faris/.codex/attachments/15c7b55e-9509-4fa5-8a38-97ea70062d42/Pasted text.txt`;
full assignment in attachment `a7185aca-0f34-4fa8-b458-7a8de4b79a5b/Pasted text.txt`.
The original prohibits daemon changes. Latest user reports PC restarted and asks
that services needed for continuation be restarted: this authorizes the narrowly
necessary managed development service recovery, without live runner activation,
upgrades, global settings or unrelated ERP service changes.

Same teamwork run/task RNR-D00. Historical Main chat
`01a20a9a-5f1c-7123-a682-3c14b4b10fbc`, host `remote-wsl:Ubuntu-24.04`, project
`39bb8094-20bb-4c50-8d29-55af55ec8637`. Main sole writer; sole reviewer
`/root/rnr_admission_review` completed read-only review and explicitly stopped all
operations. All review feedback preserved in reports below. Predecessor agents
are unavailable to successor; do not message/query/resume them. Create at most
one fresh reviewer where unfinished work needs it. Numeric Main ownership version
and next Issue Lead counter remain UNKNOWN from prior transfer; do not invent or
reset them. Record fresh ownership and increment known transferred versions only.
No GitHub implementation issue number was assigned; D00 is a local planning label.

## Completed changes

Initial clean/published baseline `25901b0c8c918f004919dea8501d378f99560950`.
Last source/change-log snapshot before this handoff:
`67969ac063832efda133e893d70b1bfbd65fa65d`, verified equal to SSH main.
Final documentation HEAD/remote/clean/stopping receipts are recorded externally in
`checkpoint-20261124.json` and `ownership-transfer-20261124.json`; they supersede
older similarly named unversioned files without overwriting historical evidence.

- `25f81e9`: requirements/acceptance/environment index. Shared canonical skills
  remain shared policy, not Python runtime dependencies.
- `35bbff3` (+`47575a5` changelog): admission-only original fork packet authentication.
  Real/effective root IDs, PASSCRED set/readback on both original endpoints before
  fork, bounded eight-byte packet and credential buffer, exact unreaped child PID,
  root IDs, no missing/duplicate/unknown credentials or rights/truncation, child
  pidfd liveness before/after receive. Dispose up to four installed rights once,
  preserve six cleanup errors and initiating errno using a separate clock capsule.
  Original setup/deadline and negative 60/90 leases preserved; validation unchanged.
- `4414afe`: held reader and independent persistent binding require installation
  runtime-image root == installation execution root == declaration execution root
  before input binding or any persistence I/O. Every-byte mismatch fixtures.
- `e1df773`: malformed-response Store test now has 1s IPC budget instead of 150ms;
  production and deadline-focused cases unchanged. Initial full run expired there,
  isolated case passed, then corrected suite passed.
- `173c80f` (+`b8f4289`, `e44de57` docs): bounded DATA-only policy decoder, exactly
  9728 bytes: 1024 header, four 128-byte unit records, 32 ordered 256-byte UnitPaths.
  Exact reserved/framing/zero tails, UUID/OID/digest/identifier/text/numeric/path
  bounds, unique canonical paths, required transient record, failure clearing and
  overlap rejection. Borrowed immutable text views; no runtime reader/auth/GO.
  Frozen detailed accepted rules are in the coupled contract, not this summary.
- `4af3088` (+`67969ac` changelog): private qualification entry requires compile
  flag=1, calls supervised admission once, and exits125 on every parent return.
  Removed old unsupervised preparation/hostview/claim/loop/mount/final-exec chain.
  Child supervisor already abandons/exits; no duplicate cleanup. Import-audited
  substituted fixture covers -1/0/1/125 returns and child exit. Validation entry
  unchanged. Actual native artifacts remain NEVER RUN.

No complete operational continuation, service startup/run/status/stop, real bound
provider session or second-project operational demonstration has been implemented.
Supported `doctor` and `preview` are advisory. No account/profile/cache/activation
operation was performed. POSIX tests used owned disposable Python children only.

## Verification and environment evidence

Protected evidence root (abbreviated E below):
`/home/faris/.local/state/agent-runner/release-admission-20261119`.

Latest source-applicable results, not claims of operational acceptance:

- `supervised-entry-full-suite.log`: unittest discovery, **1445 tests in232.870s,
  OK,7skipped**. Earlier root/policy combined run1444 passed; initial1443 root run
  had the documented timing failure, corrected before final passing runs.
- `posix-qualification-20261124.log`: `RUNNER_POSIX_QUALIFICATION=1 python3 -m
  unittest discover -s tests -p test_automation_live_posix_qualification.py -v`:
  **7tests in2.726s OK**, covers default skips. Real pipes, bounded transfer,
  timeout signal/reaping and child core-limit tests; no actual Codex/provider run.
- `supervised-entry-focused.log`:4tests11.011s PASS; old main failed before fix.
- `supervised-entry-flag-checks.json`: absent/zero flag reject, flag1 strictly
  compiles. Actual qualification artifact never executed.
- `supervised-entry-build.log`, `supervised-entry-dist/`: offline wheel/sdist PASS.
  `supervised-entry-installed-consumers.json`:2consumers,3strict native compile-only
  builds PASS, native_executed=false. Wheel SHA256:
  `bc3e65b621039e9975c55b91c819359cd96b20fb73e0d71d09cef14678783ea8`.
- `supervised-entry-review.json`, `policy-review.json`, `root-binding-review.md`,
  `armed-review-final.md`: same sole reviewer interface/integrated review; no
  blocking issue for completed scoped changes, reviewer did not execute tests.
- `armed-*`, `root-binding-*`, `guarded-create-*`, `policy-*` retain earlier RED/
  GREEN/compile/install/review evidence. Reuse unchanged applicable results.

`environment-20261124.json`: Python3.12.3, Git2.43.0, uv0.12.19, GCC13.3.0,
Linux x86_64 WSL2 kernel6.18.58.1-microsoft-standard-WSL2, systemd255.4-1ubuntu8.18,
cgroupv2, DockerCLI29.1.3, Codex hostCLI0.162.1; busctl, unsquashfs, mksquashfs,
veritysetup available. Installed tools are not runtime/profile qualification.
Historical isolated SDK0.167.0 is separate; no global upgrade. No project `.env`
exists or is required by advisory package. Shared standards `.env.local` has
GitHub GH_TOKEN only; its secret was not printed/copied and it grants no runner
configuration/enrollment. Do not copy it to consumer projects. Standards checkout
at `dd0356e770e33166cabc26f03c9c19e612a24c6d`, ahead1, preserved unchanged.
Memory MCP was unavailable/checkout unauthorized; no memory save claimed.

`libmd-source/source-object-audit.json`: former source retrieval blocker resolved.
Ubuntu archive2018-key-verified InRelease -> exact pinned Sources index -> libmd
1.1.0-2build1.1 .dsc/orig/Debian archive hashes/sizes verified. Source safely
extracted, no patch series, sha2.h byte-identical to verified SDK header. Packaged
sha2.o and strict locally compiled source import only memcpy/stack_chk_fail, no
constructors. Compiler flags differ: no object byte equivalence claimed. Preserve
BSD3 Aaron Gifford notice/conditions/disclaimer if adopted. No library adopted or
linked; .dsc own signature not independently verified (missing public key); signed
index hashes authenticate artifacts. Final ELF/import/init/link/startup closure open.

## Precise unfinished boundary and next actions

All five gates in `docs/requirements.md` remain open: actual runtime profile and
process isolation; supervised private session/callback/authenticated provider route;
whole containment/lifecycle/recovery; immutable executable/dependency startup
closure; integrated success/failure/recovery qualification. No missing GitHub token
or package install prevents authorized source work. Remaining work is substantial
implementation and evidence, not a permission to relax guarantees.

1. Verify new protected checkpoint/ownership receipt, clean main/remote/source
   hashes, current service recovery and no continuing predecessor writes. Invoke
   teamwork, take successor Main ownership, preserve RNR-D00/history/UNKNOWNs.
2. Finish and independently challenge the complete coupled F1/F2/F5 admission
   boundary; implement in Main with focused failing regressions first. Avoid another
   inert-codec-only milestone. Freeze bootstrap trust/project location, C transport,
   capsule/producer handover, intents, FD inventory and sole retirement together.
3. Current singleton `/etc/rnr/installation.bin` and `task.bin` must not be relabeled
   multi-project or overwritten for a new project. Candidate location is kernel
   original keeper AND child cgroup `/rnrc<Project64>.slice/rnrc<Project64>.service/
   keeper`, derived once after T0/fork/ARMED and before project reads; then protected
   `/etc/rnr/projects/<Project64>` inputs and full actual PID1/policy correlation.
   Genuine root/proc/PID1/manager provenance must precede protected authority. Existing
   hostview acquisition is INPUTS_HELD and cannot simply be moved earlier.
4. `bootstrap-review-20261124.md` retains latest narrow privilege-check review and
   rejected alternatives. Root IDs+uid_map alone are insufficient. Per-boot compiled
   host anchors were considered, not adopted. Candidate genuine-proc `thread-self`
   traversal, checked retained mount/ancestors/links and followed NSFS user handle
   + NS_GET_NSTYPE/CLONE_NEWUSER + initial inode0xeffffffd + rootIDs is only an
   independent negative privilege guard. No guard source exists or full bounded
   interface is frozen. Need no-follow traversal/rechecks, exact cleanup, original
   setup15 at every syscall and immutable no-thread/no-reaper bootstrap premise.
   Reconcile original boot/time/status samples against authenticated view without
   recapturing T0. Do not infer full host/project authority or require global initial
   PID/mount namespaces: valid WSL uses dynamic ones. No new clock defect established.
5. Reviewer conditionally found no concrete unprivileged overlay bypass under the
   stated trusted-bootstrap/kernel/stable-namespace/no-privileged-injection premises.
   Requested thread_self.c source (now saved) and exact running-build correspondence
   (still unproven). `kernel-bootstrap-source/provenance.json` pins eight official
   Microsoft files at tag linux-msft-wsl-6.18.58.1, commit
   `a989171929bed4ea681be8d77333845ce1c1732a`. thread_self.c returns current task's
   `%u/task/%u` in proc mount PID view, ENOENT if invisible. Source tag/uname match
   is not target build qualification. Keep GPL research outside project source.
6. Preserve direct PID1/root private peer, closed typed/bounded EXTERNAL/DBus,
   original clock/counters, no fallback/retry/heap/FD negotiation. Latest contract
   table has316requests under cap512. Real Ubuntu-patched manager verification
   remains separate from upstream v255 source. Update deeper hierarchy/anchor
   units/inventories coherently. Implement actual policy authentication and immutable
   historical referenced bytes, not merely nonzero field or echo checks.
7. Freeze exact native->Python keeper-consumed persistence capsule and producer
   handover, one claim RWbind in actual /run, once-only writer acquisition, observer
   never writer, original clock and failure ownership. See contract E and protected
   `next-coupled-design-notes.md` (unaccepted sketches are not authority).
8. Integrate whole positive boundary only after independent review; preserve
   fail-closed/abandon/exit125 until it is valid. Then actual protected provider and
   callback/session/profile, dependency closure, finite failure/recovery matrix and
   first/second opted-in project lifecycle before conditional live activation.

## Safe stopping and continuation

This chat started2026-11-23T22:51:09Z and observed two confirmed compactions; the
second was unexpected/platform controlled during continuation preparation. We did
not enforce a one-compaction limit. Policy now requires checkpoint, transfer or
copy-ready prompt and stop; source work is stopped. Fresh chat counts from0.
Current effective controls danger-full-access/approval never are known. After
managed recovery, supported daemon anchor metadata confirmed gpt-6.1-sol/medium
(same chat and checkout); desktop metadata alone had not exposed them. Preserve
these verified settings, never silently use helper defaults. All source/test/build/push operations completed; reviewer stopped.
Only final handoff/Git receipts and authorized development-service recovery remain
before predecessor releases ownership. No live runner service was launched.

Native creation/dispatch tools are absent. Before reboot report, managed App Server
version failed ENOENT and socket symlink was dangling. Latest user now authorizes
needed service recovery; one supported `codex app-server daemon start` attempt was
made. It initially timed out waiting for readiness; subsequent version succeeded:
managed daemon0.162.1 running. Supported thread/read confirmed the correct anchor,
checkout, model gpt-6.1-sol and effort medium. `service-recovery-20261124.json` retains
metadata. Final preflight/creation outcome is in the protected checkpoint/receipt,
not an assumption here. Failed system/user units observed include unrelated ERP jobs;
they are not runner prerequisites and were not modified. No successor exists unless
an explicit protected creation receipt proves it. Do not replay an uncertain create.
If daemon/anchor/model/permission preflight cannot establish the intended settings,
use manual continuation with same model/effort and Full Access; do not create an
unverified chat. Canonical open-codex-chat SKILL and references own the procedure.

Copy-ready continuation prompt:

```text
Continue RNR-D00 operational release in /home/faris/agent_runner on existing main.
Invoke the teamwork skill FIRST, then read /home/faris/development-standards/POLICY.md,
/home/faris/agent_runner/AGENTS.md, canonical agent-runner SKILL.md, and
/home/faris/agent_runner/docs/handoffs/2026-11-24-release-progress.md plus its required
sources. Verify protected checkpoint-20261124.json and ownership-transfer-20261124.json
under /home/faris/.local/state/agent-runner/release-admission-20261119 before writes.
Act as successor Main/Orchestrator in the same RNR-D00 run, preserve historical IDs,
UNKNOWN numeric counters and explicit stopping evidence; record fresh ownership.
Predecessor subagents are unavailable; saved reports are authoritative references,
not live owners. Use at most ONE fresh review subagent, Main implements. Completed
source has1445passing default tests and seven passing opt-in POSIX tests, package/
consumer/native compile checks; no actual native/provider qualification or live
activation occurred. All five operational gates remain open. First finish/challenge
trusted bootstrap/project admission and complete coupled F1/F2/F5 contract, then
implement the remaining whole boundary and actual lifecycle/provider/recovery/new-
project acceptance. Reuse still-valid evidence; do not repeat extraction or completed
investigation. Preserve separate explicit opt-in/state for every project, protected
external stores/evidence, existing main, scoped authorized commits/SSH normal pushes,
no branch/worktree/reset/force push, no public publishing/global SDK/auth changes.
User authorized only necessary development-service restart after PC reboot; verify
its saved outcome, no unrelated service changes or premature live activation.
Continue autonomously, fix issues with review/testing, and report actual blockers
plainly. New chat starts compaction tracking0; hand off before a second is needed.
```
