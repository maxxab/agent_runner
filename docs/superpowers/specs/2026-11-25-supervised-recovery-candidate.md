# Supervised recovery: candidate design, not yet accepted

RNR-D00 retains automatic clearance after a normally completed attempt and
requires explicit reconciliation after abrupt runner loss. A stored result that
was not displayed is not sufficient. The existing `finish()` removes the only
guard before the CLI prints the report. If the subsequent directory sync and
restoration both fail, or the process is interrupted after removal, a later
attempt is admitted. The two existing state regressions reproduce these cases.

## Candidate and exact boundary

Keep an immutable pending record and make its clearance an attempt-bound,
validated certificate. The foreground command would retain an exclusive project
lock while a separate reporting worker executes the task and checks, writes the
complete report to the actual terminal, flushes it and exits. The observer
would publish the certificate only after it observes the worker's normal exit
and verifies that its terminal outcome matches the pending attempt. Timeout,
interruption, broken output, missing or malformed information, unexpected exit,
or loss of the worker before normal exit would leave the attempt unresolved.
The lock's open file description must remain held by both processes while
either can affect the project; no provider or check process may retain it.
The lock does not contain descendants or prove they stopped. An operator
reconciling an abrupt loss must inspect processes and possible external effects.

Certificate contents and the containing directory must be synced **before** a
same-directory atomic publication. There must be no later sync error described
as an UNKNOWN outcome while a published certificate is accepted. An interrupted
host can lose an unsynced publication and conservatively require reconciliation;
the previously synced pending record remains the blocking authority. No next
attempt may launch until its own replacement pending record and directory have
been synced. Explicit reconciliation records and publishes a separate
attempt-bound certificate under the same lock after operator confirmation.
Malformed, conflicting, replaced or unreadable required records fail closed.
A valid newly initialized project has no prior attempt or certificate; absence
of a record is an error only when the state protocol requires that record.
The filesystem and syscall crash guarantees must be established for the actual
supported local filesystem; arbitrary network filesystem semantics are not
assumed. A reported publication failure must not be interpreted as proof that
publication did not occur; admission and operator messages must agree on the
observed state. This rule still needs an executable design for an unreadable or
ambiguous publication result.

The important unresolved boundary is observer death after publication:
the shell-visible command could die abruptly even though the reporting worker
has already displayed its report and exited normally. Treating that case as
known would materially narrow the user's unqualified shell-visible runner-loss
requirement, and would require a new explicit scoped decision. It is not
compliant with the requirement as currently stated. A successful terminal write
and flush establishes acceptance
by the terminal interface, not that a human read the output or that display
hardware rendered it. These distinctions need a demonstrated, independently
reviewed disposition before release.

## Alternatives and tradeoffs

* Moving `fsync` before removal cannot establish that an undisplayed outcome
  was reported; prior independent review rejected it.
* Keeping a guard and requiring reconciliation after every run is simple, but
  contradicts the owner's explicit normal-clearance decision.
* An observer and prepared certificate could establish a distinct normal worker
  exit, at the cost of a second process, terminal-delivery and locking protocol,
  filesystem assumptions and the observer-loss distinction above. The mechanism
  is not implemented or verified by this document.
* An independent observer of the **actual shell-visible process** could publish
  clearance after its real normal exit. Linux ptrace is one possible avenue, but
  tracing is invasive, can change signal and job-control behavior, can be denied
  by security policy or an existing tracer, and needs a working tracer-lifetime
  and lock protocol. A pre-exit trace stop is not proof of actual normal death.
  A service manager acting as parent is another avenue, but its foreground client
  and terminal-disconnect behavior must themselves meet the stated boundary.
  Neither avenue is designed, implemented or qualified here.

## Stronger-boundary avenue to develop

A possible Linux-specific design would have the actual foreground runner start
an independent tracer before launching any task. The runner and tracer would
share the locked state descriptor; an explicit handshake would ensure tracing is
established before the runner can durably begin or launch. The runner would
send the observer a bounded attempt/result identity only after a complete,
successful terminal write and flush. The tracer would verify the real exit
status of that exact runner, not merely a ptrace pre-exit event, then publish
the matching certificate. If the tracer dies, the runner must be stopped and
the unresolved guard retained; independently surviving provider/check processes
remain an operator-reconciliation concern. If the runner dies by signal or
before report delivery, no certificate is published. The shell may regain its
prompt before publication, so an immediate next attempt can temporarily be
refused while the observer finishes. No credential or project-state identity
is shared with other projects.

A disposable same-UID fork/ptrace probe on 25 November observed the actual normal
exit status on host `DESKTOP-3CK36LV`; it did not test the runner, terminal,
signals, tracer death, guard, storage, provider, or a consumer project. Local
Yama scope was 1 and the probed process had no seccomp filter. This is not
evidence that tracing is permitted in the eventual execution environment or is
safe for this release. The implementation must explicitly establish how signals
and job control are preserved, prevent a lost tracer from leaving the task
unwatched, handle debugger/LSM/seccomp refusal before launch, and bound observer
failure and resource lifetime. It must preserve the user's literal runner-loss
rule rather than adopting the narrower worker-only boundary above. The required
publication and error ambiguity rules remain unresolved.

## Required implementation evidence

Trace CLI approval, lock acquisition, durable begin, process lifetime, terminal
reporting, worker exit, certificate publication, next begin and reconciliation.
Add real subprocess fault-injection tests for worker death before/during/after
output, observer death at each boundary, broken and partial terminal writes,
signal handling, a surviving worker after observer loss, every sync failure,
ambiguous publication and crash/reopen behavior. Preserve the original two
regressions' requirements; do not merely adjust their assertions. Verify normal
completed and failed attempts automatically admit a later attempt, and UNKNOWN
attempts do not, including across checkouts. Independently review the final code
and run the focused modules and full suite on the resulting snapshot. These
checks use isolated local fixtures, never a provider or an opted-in project.

This candidate neither closes RNR-SUP acceptance nor changes the five original
operational gates or the native wrapper's fence.
