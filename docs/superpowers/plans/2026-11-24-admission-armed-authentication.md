# Admission ARMED authentication implementation plan

Status: implemented and independently reviewed as a negative-only prerequisite.
RNR-D00; Main is
sole source/docs/Git writer on existing main. The existing review subagent is the
only reviewer in this chat. No implementation delegation or new agent is needed.

Spec: [requirements](../../requirements.md), selected143 and the
[coupled admission contract](2026-11-19-persistent-admission-contract.md).
This prerequisite authenticates the first fork-child packet. It does not
authenticate a declaration, policy, executable or complete runtime profile, and
adds no GO or positive continuation. The wrapper still abandons and exits125.

Goal: authenticate the original admission child's first packet and retain exact
failure/cleanup ownership. Architecture: admission-only socket-option setup and
bounded credential parsing in the original clock/fork owner, with external syscall
substitutes for deterministic failure tests. Stack: Linux x86_64 C11, GCC13,
standard-library Python unittest and the existing package/install checks.

## Interface and trust boundary

Preserve the eight-byte `RNRKARM1` packet and the validation fork's old wire/behavior.
Admission-only setup requires real and effective root UID/GID, enables SO_PASSCRED=1 and
reads it back on both exact original socketpair endpoints3/4 before fork/send.
Check the original setup clock around every option syscall. Option/readback/error/
expiry failure closes owned endpoints once and never forks. Immutable single-owner,
default SIGCHLD/no-auto-reap, trusted proc/PID namespace, no privileged injection,
stable credentials and original fork lineage remain explicit trust prerequisites.
Credentials do not prove executable, thread, namespace or cgroup membership.

Parent retains the exact unreaped child/pidfd before receiving. Poll gate and
child pidfd together for the one original-budget wait; any child-death/invalid
readiness rejects, including pidfd POLLIN/HUP/ERR/NVAL when the gate is also ready.
Zero readiness, EINTR and late return reject without a second wait. A liveness
observation does not promise future survival. Parent receives once using MSG_DONTWAIT|MSG_TRUNC|
MSG_CMSG_CLOEXEC, with an eight-byte data buffer and an aligned, zero-initialized
CMSG_SPACE(sizeof(struct ucred)) control buffer. Linux x86_64 ABI is fixed here:
12-byte ucred, 16-byte cmsghdr, 32-byte control buffer; at most four received FD
integers can fit if no credentials are present. Compile-time assertions enforce
those sizes. Do not assume credentials consume buffer space before rights.

Traverse only returned bounded control bytes with alignment-safe header/value
copies and checked lengths. The kernel syscall boundary is trusted to return
normalized cmsg headers and installed distinct live FD numbers. Reject malformed
headers, unexpected controls, duplicate/missing/wrong-size credentials, rights,
truncation, EOF, wrong packet/length or wrong original child PID/root UID/GID.
Dispose every discoverable installed right before any fallible clock, identity or
post-receive readiness operation, including on EOF/truncation. A corrupted kernel
cmsg layout is outside the trusted-kernel assumption; do not claim unknown bytes
prove no FD was installed. No retry or arbitrary FD-scanning repair.

Invalidate each received FD slot before its one close. Attempt all delivered FD
closes even if one fails. Retain all cleanup errors: expand the private fork
result from two to six slots (four rights plus two socket ends). Continue parsing
valid later cmsgs after a rejection so their rights are disposed. Any cleanup
uncertainty fences ARMED. Check original setup after cleanup, and perform one
zero-time child-pidfd liveness observation before setting child_armed. No extra
wait, reaping, reconnect or resend. Kernel-truncated excess rights are covered by
the current scoped pipe-EOF fixture and require actual target qualification; the
native parser is tested separately with syscall substitutes.

Record a failed option/poll/receive syscall before parsing or post-syscall clock
checks. Clock helpers initialize their output, so use a separate error capsule
and retain its first failure in the private result's `admission_clock` field.
Preserve the initiating primary error and first cleanup errno; all right/socket
close errors retain individual slots, and clock-proc cleanup has the separate
clock capsule. A failed recvmsg may leave msghdr unchanged; it must retain its
actual errno rather than a later zero-buffer parser rejection.

At receive the parent owns stdio3 + gate1 + pidfd1 = five FDs. At most four rights
bring the peak to nine; a later clock read adds one only after rights close. This
local peak does not close the whole native256 inventory. Validation packet
receives retain NULL control buffers and do not enable/read back PASSCRED.

## Failure ownership

Before fork, no child exists. After fork, preserve original child/pidfd and negative
60/90 lease on protocol/setup-only failure; actual identity/clock failure remains
terminal. Missing pidfd retains the existing immutable single-owner/no-auto-reap
numeric fallback. Received-right cleanup precedes post-receive clock validation.
The wrapper may contain the exact child once, then close the gate once; never
restore invalid clock state or infer resource absence from EOF/close.

## Implementation and verification

- [x] Independently challenge this exact bounded contract; resolve affected findings.
- [x] Extend actual supervised-clock fixtures with fully substituted option calls,
  per-endpoint before-fork ordering, credential construction and bad PID/UID/GID,
  absent/duplicate/malformed credentials, rights/CTRUNC/EOF, cleanup errors, option
  failures/readback drift, child death and clock expiry. Observe RED before source.
- [x] Implement admission-only setup/receive in clock.c/h with no wrapper/GO change.
- [x] Update the actual-module syscall boundary wrappers before running them;
  audit unresolved imports so no new host-effect syscall escapes substitutes.
- [x] Run focused native clock/fork/supervised-input/held-inventory regressions,
  strict actual native compile/link without execution, independent snapshot review,
  then affected broader suite/package checks for the changed native resources.
- [x] Record exact results and remaining release gates.
- [ ] Continue the remaining coupled admission and operational release work.

## Verification checkpoint

The first repository regression failed before source at missing pre-fork PASSCRED
setup. A later unchanged-msghdr EAGAIN regression reproduced the review finding
before its correction. The final focused native/fork/supervised-input run passed
10 tests in13.903s. The final full suite passed1443 tests in217.510s with7skips.
The actual-module fixture now checks its undefined imports against a closed
startup/assert/memory/string/stdin allowlist before execution; option and identity
syscalls are wrapped. Independent source review by the same single review agent
found no further blocking issue after the errno/clock-capsule correction; the
reviewer did not independently execute tests.

Offline wheel/sdist build passed. Installed checks passed two disposable consumers
and three strict native compile-only builds; native artifacts were not executed.
Checked wheel SHA256:
`f96314ed4eb7ec678a1a3adf9f6992bbda44bebce657232c1873c5e73ada1671`.
Detailed logs and the same-reviewer report are protected under
`/home/faris/.local/state/agent-runner/release-admission-20261119/armed-*`.
These checks apply to this prerequisite; all five operational release gates remain
open. Actual public service startup and a real private provider session are absent.

Whole runtime/profile/provider/closure/recovery and new-project operational
acceptance remain open. Ordinary doctored data or a successful first packet grants
no persistence, task resource, Store or workload authority.

## Follow-up: correlate runtime and execution roots

The held admission reader previously compared the declaration's execution root
with the installation's execution root, but omitted comparison with the runtime
image root. The persistent binding validator independently had the same omission.
Both now require all three roots to match before input binding/cutoff or any
persistence I/O. Legacy inert record decoders remain unchanged. Equality does not
prove an actual dm-verity mapping, host provenance or trusted policy.

The held-reader and persistence fixtures reject a mismatch at every one of the
32 runtime-root bytes; persistence rejection makes no I/O or record creation.
The actual-module supervised fixture checks the exact identity error and exit125.
All three regressions failed before the guards were added, then passed the focused
run (3 tests,10.183s). The same sole reviewer found no blocking issue and suggested
the exact-error assertion now included. Full-suite/package results follow below.
