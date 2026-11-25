# RNR-D00 remaining original gate: independent next-step review

Reviewed 2026-11-25, starting from clean `main` at
`649216ce519d03d488042bc1d262c1b62b8d1951`. Reviewer
`/root/rnr_d00_gate_reviewer`, fresh ownership v1, supervisor `/root`.
Stage: continuation implementation/source review, not a new PRD. Main owns source
and Git. Historical owners, compactions, UNKNOWN Main numeric ownership and
UNKNOWN next Issue Lead counter are unchanged. This review performed no tests,
manager requests, provider calls, service actions or protected-state writes.

## Disposition

**No bounded implementation recommendation is justified yet for the examined
remaining G1 inventory/control and G6 admission-lock candidates.** These are
known incomplete gates, not newly established regressions. The next useful step
is to close one small design/evidence gap below, then implement its exact rule.
Do not add an empty `Wants` expectation, a reject-all-dependency scanner, or a
partial final sweep presented as the accepted final sweep.

**Selected next task: close the G1 dependency-directory algorithm in the existing
admission contract, using retained pinned source only.** This is authorized
independent design/source engineering; it does not require a live manager query.
Keep it one bounded outcome: a reviewed finite enumeration/classification rule
for the four existing unit names across the already authenticated UnitPath,
covering `.wants`, `.requires` and `.upholds` and the related alias-name map.
Do not restart the PRD, redesign transport or alter any runtime fence.

The deliverable should specify: (1) how ordered unit-name winners and their
aliases are derived, (2) which name/type/dash-prefix scopes are searched,
(3) precedence for colliding basenames, (4) classification of masks, symlinks,
ordinary files and invalid names, (5) finite path/entry/read/alias bounds and
overflow refusal, and (6) retained observations and second-pass comparison under
the original clock. Include a small independent truth table demonstrating an
added effective dependency with unchanged `After`, a shadowed entry, a mask and
an alias. Main should independently review that contract delta; its resulting
closed predicates select the next source change and meaningful red fixtures.

Retained source supports these algorithmic conclusions without further host
authority: `systemd-v255-unit-file-01a20fb2.c:380` (`unit_file_build_name_map`),
line 718 (`unit_file_find_fragment`),
`systemd-v255-dropin-01a20fb2.c:136` (scope/prefix expansion), line 223
(`unit_file_find_dropin_paths`), and
`systemd-v255-load-dropin-01a20fb2.c:14` (`process_deps`) / line 85
(`unit_load_dropin`), all under
`/home/faris/.local/state/agent-runner/release-admission-20261119/`.
Existing provenance and Ubuntu source correspondence
should be reused. Any source branch not yet traced stays explicit rather than
being silently approximated by reject-all logic.

Actual-host evidence is needed later to establish the installed name map,
directory contents, four effective `Wants` sets, running PID1 identity and the
selected manager's observed behavior. Those observations need a specifically
authorized read-only operational scope; this review grants none. They block
claims of installed compatibility/qualification, not the source-derived design
task above or implementation of an independently reviewed finite algorithm.

This is a scoped finding, not proof that every remaining G2–G5 source task is
blocked. A new G2–G5 implementation selection needs its own coupled-flow trace;
the accepted contract explicitly rejects another inert codec-only milestone
(persistent admission contract:1455–1461).

## Trace reviewed

1. `automation/native/runtime_stage0_qualification_main.c:13` calls the fixed
   original-clock supervisor; every return exits 125.
2. `automation/native/runtime_stage0_launch.c:456` captures the original clock,
   forks the admission child, calls the held reader, abandons both inputs and
   gate on either outcome, then exits 125 at line 479. No persistence or positive
   continuation is called.
3. `automation/native/runtime_stage0_preparer.c:1712` admits fixed descriptors,
   verifies bootstrap/project view, reads protected inputs/policy/references,
   authenticates executable/unit bytes and checks retained identities.
4. Line 1765 authenticates the PID1 socket, resolves the original keeper unit,
   compares UnitPath, observes search directories and seven fixed `.conf` scopes,
   reads the initial unit matrix and captures cgroups.
5. Lines 1770–1800 compare declaration/project roots/quotas/UnitPath and bind the
   original admission inputs. The second observation at line 1805 checks peer,
   socket paths, cwd, search directories, `.conf` scopes and cgroups; line 1808
   transitions only to `PREPARER_ADMISSION_INPUTS_HELD`.
6. Failures fence and drain inputs at lines 1815–1820. Existing helpers register
   temporary descriptors before post-call checks and preserve the first error;
   new observations must follow those conventions and the original clock.

The manager loop at line 1499 covers 274 unit properties, plus the separate
UnitPath read, and one keeper lookup: 276 initial requests. There is no `Wants`
property or final property sweep. It retains initial InvocationIDs and cgroup
IDs, but the latter readback is an assignment, not a compare-only final recheck.
Reusing the full loop for a final sweep would both issue the wrong matrix and
overwrite original identity references.

## Exact gaps and smallest unblocking inputs

| Candidate | Current evidence and missing input | Smallest justified next action |
| --- | --- | --- |
| Eight approved `Wants` reads | Contract `docs/superpowers/plans/2026-11-19-persistent-admission-contract.md:958` authorizes 279 initial properties + 1 lookup + 44 final = 324 total, unchanged 512 serial cap. It requires exact sets established from installed-unit semantics and the selected manager. `tests/native/test_runtime_stage0_policy_inputs.h:10` contains only `service\\n`, `control\\n`, `workload\\n`, `anchor\\n`; these are no installed-unit semantics. Latest handoff:543–571 preserves running PID1/actual behavior UNKNOWN. | Establish four exact expected `Wants` sets, with retained full installed unit bytes and selected-manager evidence. Record their source-derived consequences separately from actual-manager qualification. Only then add four initial comparisons and the four final comparisons in the agreed final sweep. |
| Full overlay/dependency inventory | `unit_conf_overlays` at preparer:739 scans seven `.d` scopes only. Protected `g1-dependency-directory-trace-01a20fb2.json` identifies canonical/alias/dash-prefix/type scopes for `.wants`, `.requires`, `.upholds`, basename precedence and mask/non-symlink handling. Its explicit limitation says not to reject all symlinks. `overlay-algorithm-analysis-01a20fb2.json` leaves finite caps and alias resolution open. | Freeze a compact deterministic algorithm: canonical/alias winning-name map, exact scopes, basename precedence, entry classification including masks/invalid names, bounds, retained evidence and recheck rule. Use the selected Ubuntu source already retained; do not repeat source download or mistake it for PID1 behavior. Independently review this algorithm before source. |
| Remaining ancestor/keeper controls | preparer:1011 checks six fields on four policy units; line 1029 checks keeper `memory.oom.group=0`; lines 991, 1033, 1052 cover controllers/state/initial memberships. Contract:925,938,1010 and 1536 requires inherited/relevant controls but supplies no equally closed remaining role/file/expected-value table. Root/keeper limits cannot simply inherit the four policy-unit indices; adding an exact keeper `domain` restriction was already rejected (handoff:523). | Name only the remaining required role/file/value predicates and justify their kernel semantics, including root exceptions and inherited versus local limits. Reuse current policy values where actually applicable; do not invent a root quota or keeper topology restriction. This is the smallest design clarification for a control-reader change. |
| Final 44-request sweep | Contract:967 and 1540 places it immediately before initial durable latch/claim and requires original identities/expected state plus held path/kernel/clock checks. Current held reader returns to unconditional abandonment; `runtime_stage0_persistence.c:273` separately opens state and creates latch/claim at line 291. No fixed authenticating continuation joins them. | Define the final caller and ordering between declaration ACK, same-original manager/path/kernel sweep, held protected state, lock exclusion and first claim mutation. A fresh held-reader recheck alone is not this pre-claim guarantee. Keep the exact 44 matrix, original references and serial progression without reset. |
| G6 maintenance lock | Contract:2078–2085 requires fixed lock refusal; line 2129 requires checking lock and active through the same protected project directory. Protected `g6-maintenance-lock-trace-01a20fb2.json` expressly keeps Revision B unchanged and assigns the future fixed authenticating caller. Persistence:288–292 owns that state directory and creates effects; the G1 input directory is a different tree. | Freeze the narrow held-directory/check/call interface at that authenticating boundary. Check fixed name nofollow, accept only proved absence, preserve initiating error plus clock/cleanup observations, and retain installer exclusion. Do not patch an unrelated input path or add a generic path/callback API. |

## Focused verification after a contract is selected

Existing mock seams are adequate for source behavior once expectations are
independently established. They are not physical evidence:

- `tests/native/test_runtime_stage0_held_inputs.c` and
  `test_runtime_stage0_manager_vectors.h` check exact request object/interface/
  property/serial and independently construct replies. Extend them for exact
  `Wants` sets, duplicate/unexpected members, malformed/oversized/trailing data,
  initial-versus-final identity drift and 324 total requests without serial reset.
- `tests/native/test_runtime_stage0_search_path_model.h:30` supplies serial
  directory/failure/bounds seams. A dependency inventory needs independent cases
  for precedence, aliases, masks, invalid names and unchanged effective `After`
  with an added dependency; mirroring a new scanner's output is insufficient.
- `tests/native/test_runtime_stage0_cgroup_model.h:1` and held-reader cases at
  lines 1154–1287 cover identity/control/state/clock errors and post-bind changes.
  Extend only for the agreed missing predicates, including exact role coverage,
  first-error preservation, late clocks and drained descriptors.
- Start with `python3 -m unittest tests.test_automation_native_held_inputs -v`
  (compiler/import-audited mock fixture), then the supervised-input/clock and
  project-view tests if their boundary changes. For the eventual state-lock seam,
  use the persistence fixture as well: proved absence, regular/symlink/directory
  presence, permission/error uncertainty, late clock and unchanged state identity;
  prove zero latch/claim effects on refusal. No tests were run for this review.

Selected-build source/file correspondence is preserved evidence; it does not
prove the running PID1 or an actual installed manager snapshot. Compiling or
running these fixtures cannot establish that fact, actual buffer behavior,
continuous exclusion, containment, closure or real success/failure/recovery.
All five operational gates and G1–G6 remain OPEN. The native unconditional
abandon/exit-125 fence must remain.

## Follow-up: independent challenge of the source-design candidate

Reviewed the candidate appended at persistent admission contract:2170–2289,
against retained `unit-file`, `dropin`, `load-dropin` and `conf-files` source.
This is the same reviewer/ownership v1 and source-review-only scope. No test,
manager/provider call or source implementation occurred. **Disposition: useful
source-derived refinement; not implementation-ready.** Its own open-closure
warning is necessary and must remain until the points below are resolved.

### Required corrections before dependent implementation

1. **P2 — spell out map lookup count, not an eight-symlink-hop allowance.**
   Contract:2230–2231 calls this an “eight-hop ceiling”. Retained
   `systemd-v255-unit-file-01a20fb2.c:159` loops `n < FOLLOW_MAX`, performing a
   map lookup on each iteration and returning only when that lookup yields an
   absolute terminal fragment. For ordinary non-template chains, seven alias
   edges plus the terminal lookup can succeed; eight alias edges plus a terminal
   lookup cannot. Replace the ambiguous wording with “at most eight map lookup
   iterations, including the terminal fragment lookup”, and include successful
   seven-edge / rejected eight-edge examples. Keep template fallback out of the
   admitted four-name scope; do not reimplement it by guessing.

2. **P2 — make winner maps per unit and define shared scan accounting.**
   Contract:2236–2240 must explicitly use a distinct basename winner map for
   each `(selected unit, dependency suffix)`, applying each unit's ordered scope
   list. The shared `slice.<suffix>` entries affect three different units; one
   global suffix winner map would wrongly shadow entries between units.
   The seven unique logical scopes give `32 × 7 × 512 = 114,688` raw entries
   only if each logical `(UnitPath, scope, suffix)` is physically scanned once
   per pass and reused by those unit maps. A direct per-unit implementation
   performs nine scope visits per UnitPath (2 service + 2 control + 2 workload
   + 3 anchor), giving `32 × 9 × 512 = 147,456` visits per suffix before
   deduplication. Specify which records are charged once, whether duplicate
   resolved directories share records, and that initial/post-bind/final passes
   each obey their explicit bounds. The current arithmetic is not a storage
   or whole-attempt syscall bound.

3. **P2 — replace “first loadable unit-name entry” with exact map eligibility.**
   Contract:2206–2208 can imply falling back when a first fragment cannot load.
   In `unit_file_build_name_map` at retained unit-file:543–578, an earlier mapped
   name suppresses later entries; a regular file is inserted without checking
   its contents/loadability, and a successfully classified linked mask can also
   occupy the name. Symlink-resolution errors are skipped before insertion.
   Only the later reverse-name construction at lines 584–594 checks
   `null_or_empty_path(dst) != 0` and omits those names. State this distinction
   explicitly and add a high-priority empty/masked unit versus lower valid
   fragment example. Do not conflate the UnitPath name-map eligibility with
   dependency-directory `files_add` eligibility: they use different filters.

4. **Closure gap — specify exact per-unit directory order in examples.**
   Contract:2190–2195 is directionally correct but generic “canonical wins”
   examples can conceal dash-prefix ordering. `unit_file_find_dropin_paths`
   iterates UnitPath for the canonical name; each call recursively emits that
   path's canonical/dash-prefix scopes before moving to the next UnitPath.
   Type scope is appended after all canonical-name calls. Thus a high-priority
   anchor dash-prefix entry can precede a lower-priority exact anchor entry,
   while a lower-priority exact anchor entry precedes a higher-priority type
   entry. Freeze both examples, alongside canonical-versus-type precedence.
   Within these fixed names there is only one dash-prefix scope; no alias Set
   order is needed after a correctly established singleton name set.

### Supported conclusions and remaining boundaries

The retained source supports, at design level:

- Exact singleton `.Names` is an existing admission restriction; rejecting an
  effective additional launch-service alias avoids expanding that scope. Slices
  are excluded by `unit_type_may_alias` at retained unit-file:19. This does not
  prove the actual selected service has no aliases.
- `conf-files:40–111` with suffix NULL/flags 0 selects first eligible basename
  before mask/type checks in `process_deps`; a regular/empty/mask winner can
  prevent lower-priority fallback. “Eligible” still depends on the imported
  `FOREACH_DIRENT` grammar, not merely all raw entries returned by getdents.
- `load-dropin:32–73` checks mask, symlink, unit-name validity and readlink in
  that order. Compatibility zero only warns and proceeds to
  `unit_add_dependency_by_name`; negative compatibility skips. This closes the
  target-spelling warning distinction, not all downstream target loading or
  effective canonical dependency identity semantics. The design should say
  “attempts dependency addition by entry basename” unless that latter path is
  also traced; a logged add failure is not evidence of a successfully added edge.
- The candidate honestly leaves static storage/stack/FD peak, ignored-dirent
  and unit-name grammar, special-file/dangling-link mask decisions, relevant
  cache behavior and source equivalence open. No new numeric allocation,
  filesystem policy or implementation acceptance follows from its raw-entry
  arithmetic. In particular, `FOREACH_DIRENT` versus `FOREACH_DIRENT_ALL` and
  the `unit_path_cache` eligibility must be resolved before claiming an exact
  clone of enumeration. A conservative refusal may be designed explicitly;
  it must not be described as systemd's effective set.

The smallest next action remains a source-design correction in the existing
contract: apply the four corrections above and close one deterministic scanning/
storage strategy plus the imported grammar/mask/cache predicates. Retained
pinned source can establish these rules and independent truth tables without
actual-host operation. Installed map/contents, exact `Wants`, PID1 identity,
runtime timing and qualification remain separate evidence, so their absence
does not block this design work. No original gate is closed by this review.

## Final source-design recheck: corrected candidate and helper provenance

Same RNR-D00 reviewer v1, supervisor `/root`, source-review-only scope.
Rechecked the corrected candidate and its appended “Imported helper trace and
Ubuntu patch boundary” against the original and patch archives and retained
helper files. **The prior three P2 findings and precedence clarification are
closed at design level. The candidate remains NOT implementation-ready.**

The corrected wording now counts eight map lookups including the terminal
fragment, keeps separate `(unit, suffix)` winner maps, distinguishes map insertion
from loadability, and includes both dash-prefix/UnitPath and exact/type order
examples. It also distinguishes an attempted addition from a proved effective
canonical edge. The shared logical-key scanning proposal makes the arithmetic
explicit: 114,688 raw entries per suffix/pass, 1,032,192 over three suffixes and
three passes, plus 49,152 UnitPath-map entries. Those values are correct for the
stated scan-once/reuse strategy; they remain refusal ceilings rather than a
memory, syscall-time or static descriptor proof.

Independent provenance/source checks performed, without extracting new files:

- Read both retained tar archives in memory. Their SHA256 values equal the
  helper manifest and preserved `ubuntu-systemd-source-package-01a20fb2.json`:
  original `96e75bd08c57ad401677456fb88ef54a9f05bb1695693013bc6ecce839640fd5`,
  patch archive `ec3ce620c3e072d34bbeaf9a4155cd91b5bee94eb412071bf81182f230ae2657`.
- All nine manifest members' bytes match both their original-archive members
  and listed extracted-file SHA256 values. This verifies original helper bytes,
  not a patched tree, running binary or reproducible build.
- Independently parsed the patch series and all 85 active patch diff headers
  against the nine helper paths. The only matching helper path is
  `src/basic/path-util.c`, in `CVE-2026-29111-1.patch` and
  `CVE-2026-29111-2.patch`, exactly as the manifest states. Read both patches:
  their `path-util.c` hunks modify `path_startswith_full`, its flags and dot-dot
  handling, not `hidden_or_backup_file`. They also modify paths outside the
  nine-file list, notably `path-util.h`; this scan does not establish complete
  helper/caller closure.

The new helper summaries are supported by the retained original source:

- `dirent-util.h:18–30` distinguishes ALL from filtered iteration;
  `dirent-util.c:11–36,68–92` resolves DT_UNKNOWN with nofollow/no-automount type
  metadata, skips a vanished entry and propagates other errors.
- `path-util.c:1236–1283` supplies the stated exact hidden/backup filters,
  using the suffix after the final dot. The patch hunks do not change this
  function. Raw-entry accounting before filtering remains necessary.
- `unit-name.c:24–86` / `unit-name.h:9` support the byte ceiling, recognized
  suffix/prefix grammar, first-`@` handling and flags; the code does not enforce
  an “exactly one @” predicate merely because its comment says “single”. This
  original predicate summary is verified, not every downstream name conversion.
- `stat-util.c:120–152` treats empty regular files or any character device as
  null/empty, has its direct `dev/null` path special case, and otherwise follows
  metadata via `chase_and_stat`. Combined with retained `load-dropin:32–73`, a
  negative mask check is not itself a mask; later symlink/addition work can be
  attempted. The candidate correctly avoids opening device/FIFO contents.

No new actionable P2 was found in the corrected statements. The explicit open
items still block dependent implementation approval: patched path-helper and
caller semantics (including original/resolved-path alias classification), exact
bounded representation and native stack/static-memory/FD peak, cache eligibility
and observed lifetime, safe mask/path resolution, downstream target loading and
canonical edge identity, and the final pre-claim integration boundary. Exact
installed `Wants`, actual inventory/PID1 and timing/physical qualification remain
separate evidence. This recheck closes source-design corrections only; it ran no
executable tests, manager/provider calls or service operations and grants no
new operational authority. All original gates and exit-125 fencing remain.
