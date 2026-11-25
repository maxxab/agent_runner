"""Observe the foreground runner's actual exit before clearing an attempt.

This Linux-specific helper never starts project work. Failure leaves state
unresolved; it is not a process-containment mechanism.
"""
import ctypes
import os
import re
import select
import signal
import threading


_PR_SET_PTRACER = 0x59616D61
_PTRACE_SEIZE = 0x4206
_PTRACE_CONT = 7
_PTRACE_LISTEN = 0x4208
_PTRACE_EVENT_EXIT = 6
_PTRACE_EVENT_STOP = 128
_PTRACE_O_TRACEEXIT = 0x40
_PTRACE_O_EXITKILL = 0x100000
_libc = ctypes.CDLL(None, use_errno=True)


def _call(function, *arguments):
    if function(*arguments) == -1:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def _close_other_fds(keep):
    for name in os.listdir("/proc/self/fd"):
        if name.isdecimal() and int(name) not in keep:
            try:
                os.close(int(name))
            except OSError:
                pass


def _observe(parent, state, token_fd, harmless_signals):
    interrupted = False
    while True:
        _, status = os.waitpid(parent, 0)
        if os.WIFSTOPPED(status):
            signum = os.WSTOPSIG(status)
            event = status >> 16
            if event == _PTRACE_EVENT_EXIT:
                _call(_libc.ptrace, _PTRACE_CONT, parent, 0, 0)
            elif event == _PTRACE_EVENT_STOP and signum != signal.SIGTRAP:
                _call(_libc.ptrace, _PTRACE_LISTEN, parent, 0, 0)
            else:
                if not event and signum not in harmless_signals:
                    interrupted = True
                forwarded = 0 if event else signum
                _call(_libc.ptrace, _PTRACE_CONT, parent, 0, forwarded)
            continue
        if not os.WIFEXITED(status) or interrupted:
            return
        raw = os.read(token_fd, 128)
        match = re.fullmatch(rb"([0-9a-f]{32}) (completed|failed)\n", raw)
        if not match:
            return
        attempt, outcome = (item.decode("ascii") for item in match.groups())
        if os.WEXITSTATUS(status) != (0 if outcome == "completed" else 2):
            return
        pending = state._pending(attempt)
        terminal = state._terminal(pending, reconciliation=False)
        if terminal["result"]["status"] != outcome:
            return
        state._publish_clearance(attempt, reconciliation=False)
        return


class Observer:
    def __init__(self, token_fd, harmless_dispositions):
        self._token_fd = token_fd
        self._harmless_dispositions = harmless_dispositions

    def delivered(self, attempt, status):
        if (not isinstance(attempt, str) or not re.fullmatch(r"[0-9a-f]{32}", attempt)
                or status not in ("completed", "failed") or self._token_fd < 0):
            raise ValueError("invalid terminal delivery notification")
        if any(signal.getsignal(signum) != disposition
               for signum, disposition in self._harmless_dispositions.items()):
            raise ValueError("supervised signal dispositions changed")
        message = f"{attempt} {status}\n".encode("ascii")
        if os.write(self._token_fd, message) != len(message):
            raise OSError("incomplete terminal delivery notification")
        os.close(self._token_fd)
        self._token_fd = -1


def start(state):
    """Attach an independent observer before the protected attempt begins."""
    state._live()
    if (threading.active_count() != 1 or len(os.listdir("/proc/self/task")) != 1
            or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL):
        raise ValueError("supervised recovery requires one thread and default SIGCHLD")
    harmless_signals = {signal.SIGCHLD}
    for signum in (signal.SIGWINCH, signal.SIGCONT, signal.SIGTSTP,
                   signal.SIGTTIN, signal.SIGTTOU, signal.SIGSTOP):
        if signal.getsignal(signum) in (signal.SIG_DFL, signal.SIG_IGN):
            harmless_signals.add(signum)
    harmless_dispositions = {signum: signal.getsignal(signum) for signum in harmless_signals}
    grant_r, grant_w = os.pipe2(os.O_CLOEXEC)
    ready_r, ready_w = os.pipe2(os.O_CLOEXEC)
    token_r, token_w = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
    parent = os.getpid()
    child = os.fork()
    if child == 0:
        try:
            os.setsid()
            _close_other_fds({grant_r, ready_w, token_r, state._state_fd, state._lock_fd})
            if os.read(grant_r, 1) != b"G":
                os._exit(1)
            os.close(grant_r)
            _call(_libc.ptrace, _PTRACE_SEIZE, parent, 0, _PTRACE_O_TRACEEXIT | _PTRACE_O_EXITKILL)
            state._owner = os.getpid()
            os.write(ready_w, b"R")
            os.close(ready_w)
            _observe(parent, state, token_r, harmless_signals)
        except BaseException:
            pass
        os._exit(0)
    os.close(grant_r)
    os.close(ready_w)
    os.close(token_r)
    try:
        _call(_libc.prctl, _PR_SET_PTRACER, child, 0, 0, 0)
        os.write(grant_w, b"G")
        os.close(grant_w)
        grant_w = -1
        if not select.select([ready_r], [], [], 5)[0] or os.read(ready_r, 1) != b"R":
            raise ValueError("independent exit observer is unavailable")
        os.close(ready_r)
        return Observer(token_w, harmless_dispositions)
    except BaseException:
        if grant_w >= 0:
            os.close(grant_w)
        os.close(ready_r)
        os.close(token_w)
        try:
            os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
        except (OSError, ChildProcessError):
            pass
        raise
