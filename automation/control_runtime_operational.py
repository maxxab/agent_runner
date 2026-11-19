"""Fixed original preparation seam; public operational entry stays disabled.

Only independently authenticated immutable, supervised same-process entry may
invoke the private seam. FD9 has no mode discriminator: native operational mode
provenance is an external prerequisite, never established by launch data.
Importing this module creates no Store, process, descriptor or clock origin.
"""
import os
import threading
from . import control_runtime_handoff as handoff
from . import control_runtime_clock as clock
from .control_runtime_launch_data import _decode_launch
from .control_runtime_root_entry import RootEntry,RootEntryFailure

_attempted=False
_owner=os.getpid(),threading.main_thread()


class _OriginalPreparation:
    def __init__(self,*args,**kwargs):raise RuntimeError('fixed original preparation required')


def _prepare_original():
    global _attempted
    # Reject BEFORE acquiring a cleanup ledger. Repeated calls must never
    # adopt numeric slots which have transferred or have since been reused.
    if _attempted:raise ValueError('original preparation already consumed')
    _attempted=True
    if (_owner!=(os.getpid(),threading.current_thread()) or os.geteuid()!=0 or os.getegid()!=0):
        raise ValueError('original root main preparation owner required')
    if handoff._attempted:raise ValueError('original native context already consumed')
    self=object.__new__(_OriginalPreparation)
    self._incoming=list(range(3,9));self._context=self._launch=self.entry=None
    self.original_error=None;self.cleanup_errors=()
    try:
        # FD9 belongs solely to handoff, even on an uncertain close. No raw
        # cleanup path here ever acquires or closes it.
        self._context=handoff._consume_context()
        self._launch=_decode_launch(self._context.payload,self._context.origin)
        launch=self._launch
        if launch.version!=3:raise ValueError('original operational launch version3 required')
        clock._check_native_initial_setup(self._context.origin)
        incoming,self._incoming=tuple(self._incoming),[]
        # Consuming factory owns all six roles even on rejection. Preserve its
        # original failure capsule without another close of numeric3..8.
        self.entry=RootEntry._from_original_generation_fds(incoming,launch.anchor,launch.inputs,
            launch.execution_root,launch.daemon_digest,launch.asset_root,launch.files,launch.recipe,
            launch.unit_paths,launch.name,launch.tool_digest,launch.manager_digest)
        return self
    except BaseException as error:
        self.original_error=error
        if type(error) is RootEntryFailure:self.entry=error.entry
        incoming,self._incoming=self._incoming,[]
        for fd in incoming:
            try:os.close(fd)
            except BaseException as cleanup:self.cleanup_errors+=((fd,cleanup),)
        error.original_preparation=self
        raise


def _entry():
    raise RuntimeError('public operational lifecycle disabled; trusted preparer and qualification incomplete')
