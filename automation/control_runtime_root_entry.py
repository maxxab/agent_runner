"""Dormant fixed seal -> manager -> observer -> sole Store orchestration.

No public operational entry or grant. Future fresh-process immutable inline
loader must pin Python code/imports/interpreter/libraries, establish root-system-
bus TCB/exclusion and prove no preexisting Store crossed fork. This callable
module is not evidence that such a launcher exists or was executed.
"""
from dataclasses import dataclass, asdict
import json
import fcntl
import stat
import os
import threading
from . import control_store as cs
from .control_runtime_bootstrap import _preflight
from .control_runtime_seal import Sealer, _Clock, _validate, _NAME, _DESTINATIONS
from .control_runtime_manager import PinnedBus
from .control_runtime_provisioner import Provisioner, _unit_paths
from .control_runtime_containment import validate_slice_recipe
from .control_runtime_clock import nanoseconds
from .control_runtime_assets import AssetGeneration, verify_manifest
from .control_runtime_state import RunState
from .control_runtime_original import _OriginalBaseline
from .control_runtime_prefork import _PreforkInventory


@dataclass(frozen=True)
class StoreInputs:
    run: cs.Run
    policy: cs.TurnPolicy
    queue_bound: int
    run_id: str
    resources: cs.ResourceLimits
    supervisor_epoch: str

    def validate(self, anchor):
        if type(self.run) is not cs.Run or type(self.policy) is not cs.TurnPolicy or type(self.resources) is not cs.ResourceLimits:
            raise ValueError('exact immutable Store inputs required')
        self.run.validate(); self.policy.validate(); cs.validate_record(self.resources)
        cs.positive(self.queue_bound); cs.turn_text(self.run_id); cs.turn_text(self.supervisor_epoch)
        configuration = cs.canonical(dict(asdict(self.run), policy=asdict(self.policy),
            policy_hash=self.policy.fingerprint(), run_id=self.run_id, resources=asdict(self.resources),
            supervisor_epoch=self.supervisor_epoch, runtime_clock=True))
        if (self.run_id != anchor.run or self.supervisor_epoch != anchor.supervisor_epoch or
                self.resources.workload_slots != self.run.capacity or
                cs.record_digest(configuration) != anchor.configuration_digest or
                nanoseconds(self.run.deadline) > min(anchor.wall_deadline_ns, anchor.sampled_wall_ns+44_000_000_000)):
            raise ValueError('complete original Store configuration/native deadline differs')


class RootEntryFailure(RuntimeError):
    def __init__(self, entry):
        super().__init__('root preparation UNKNOWN; nested ownership retained')
        self.entry = entry


class RootEntry:
    def __init__(self, *args, **kwargs):
        raise RuntimeError('operational root entry disabled')

    @classmethod
    def _from_fds(cls, descriptors, anchor, inputs, pins, recipe, unit_paths, name, tool_digest, manager_digest):
        return cls._prepare(descriptors,anchor,inputs,pins,recipe,unit_paths,name,tool_digest,manager_digest,
                            generation_digest=None)

    @classmethod
    def _from_generation_fds(cls,descriptors,anchor,inputs,root_digest,files,recipe,unit_paths,name,tool_digest,manager_digest):
        # This internal path still ends at STORE_READY_ONLY. Actual Docker
        # visibility, policy binding and lifecycle acquisition remain required.
        if type(root_digest) is not str:
            # Let the consuming common factory reject and close incoming FDs.
            root_digest=False
        return cls._prepare(descriptors,anchor,inputs,files,recipe,unit_paths,name,tool_digest,manager_digest,
                            generation_digest=root_digest)

    @classmethod
    def _from_original_generation_fds(cls,descriptors,anchor,inputs,execution_digest,daemon_digest,root_digest,files,recipe,unit_paths,name,tool_digest,manager_digest):
        # Internal integration still ends STORE_READY_ONLY. Trusted native
        # preparation/import history and full lifecycle acceptance remain gates.
        return cls._prepare(descriptors,anchor,inputs,files,recipe,unit_paths,name,tool_digest,manager_digest,
            generation_digest=root_digest,execution_digest=execution_digest,daemon_digest=daemon_digest,original=True)

    @classmethod
    def _prepare(cls,descriptors,anchor,inputs,pins,recipe,unit_paths,name,tool_digest,manager_digest,*,generation_digest,execution_digest=None,daemon_digest=None,original=False):
        self = object.__new__(cls)
        self._owner = os.getpid(), threading.current_thread()
        self._incoming = list(descriptors) if type(descriptors) is tuple else []
        self._sealer = self._bus = self._provisioner = self._launch = None
        self._assets = self._state = self._baseline = None
        self._prefork=None
        self.cleanup_errors = ()
        self.store = None; self.sealed_files = None; self.original_error = None
        self.manager_owner = self.failed_provisioner = self.failed_launch = self.guarded_store = None
        self.status = 'UNKNOWN'; self.root_directory = '/run/'+name if type(name) is str else None
        self.directory_state = 'PROPOSED_NOT_OBSERVED'  # never a cleanup/removal authority
        try:
            if (type(descriptors) is not tuple or len(descriptors) != 6 or
                    any(type(fd) is not int or fd < 3 for fd in descriptors) or len(set(descriptors)) != 6):
                raise ValueError('six distinct consuming root descriptors required')
            if type(inputs) is not StoreInputs: raise ValueError('exact original Store inputs required')
            if type(anchor) is not cs.RuntimeClockAnchor: raise ValueError('original outer clock required')
            cs.validate_record(anchor); inputs.validate(anchor)
            if generation_digest is None:_validate(pins)
            else:
                if type(pins) is not tuple or any(type(f) is not cs.RuntimeFile for f in pins):
                    raise ValueError('exact original generation declarations required')
                raw=cs.canonical({'version':1,'files':[{'target':f.target,'content_digest':f.content_digest,'bytes':f.bytes} for f in pins]}).encode()
                verify_manifest(raw,generation_digest,pins)
            validate_slice_recipe(recipe)
            if type(name) is not str or _NAME.fullmatch(name) is None: raise ValueError('exact new private root name required')
            cs.turn_hash(tool_digest); cs.turn_hash(manager_digest)
            if type(unit_paths) is not tuple: raise ValueError('exact frozen UnitPath required')
            # Pure shape validation only; actual authenticated manager reply is
            # compared by Provisioner before mutation, never synthesized here.
            expected = ('as '+str(len(unit_paths))+''.join(' '+json.dumps(path) for path in unit_paths)+'\n').encode()
            _unit_paths(expected, unit_paths)
            if original:
                if generation_digest is None:raise ValueError('original execution profile needs immutable generation')
                cs.turn_hash(execution_digest);cs.turn_hash(daemon_digest)
            _preflight(anchor); guard = _Clock(anchor)
            self._admit_initial_descriptors(guard)
            if original:
                self._baseline=_OriginalBaseline._capture(execution_digest,daemon_digest,generation_digest,
                    anchor,self._incoming[0],self._incoming[2])
            if generation_digest is not None:
                self._assets=AssetGeneration._open(generation_digest,pins,anchor)
                if self._baseline is not None:self._baseline._retain_generation(self._assets)
                self.directory_state='UNKNOWN'
                self._state=RunState._from_run_fd(self._take(0),name,anchor)
                self.sealed_files=self._assets.files
                self.directory_state='PRIVATE_STATE_VERIFIED'
                self._check_resources()
            else:
                self._sealer = Sealer._from_run_fd(self._take(0), anchor)
                self.directory_state = 'UNKNOWN'  # mkdir EEXIST never means we own that directory
                self.sealed_files = self._sealer.seal(name, pins)
                expected_files = {pin.file.target: pin.file for pin in pins}
                if type(self.sealed_files) is not tuple or len(self.sealed_files) != 7:
                    raise ValueError('exact seven sealed results required')
                if {file.target for file in self.sealed_files} != set(expected_files):
                    raise ValueError('exact sealed target inventory required')
                for file in self.sealed_files:
                    if type(file) is not cs.RuntimeFile: raise ValueError('exact sealed file record required')
                    cs.validate_record(file); original = expected_files[file.target]
                    if ((file.content_digest, file.bytes) != (original.content_digest, original.bytes) or
                            file.source != self.root_directory+'/'+_DESTINATIONS[file.target]):
                        raise ValueError('actual sealed result differs from original pins')
                self.directory_state = 'SEAL_RETURNED_VERIFIED_FILES'
            guard.check();self._check_resources()
            self._bus = PinnedBus._from_fds(*(self._take(index) for index in (1, 2, 3, 4)),
                anchor, tool_digest, manager_digest)
            guard.check();self._check_resources()
            bus, self._bus = self._bus, None  # consuming provisioner owns even failure
            self._provisioner = Provisioner._from_pinned_bus(bus, self._take(5), recipe, anchor, unit_paths)
            guard.check();self._check_resources()
            self._provisioner.create(); guard.check();self._check_resources()
            if self._baseline is not None:
                self._prefork=_PreforkInventory._capture(self)
                self._launch=self._provisioner.launch_observer(_inventory=self._prefork)
            else:self._launch=self._provisioner.launch_observer()
            guard.check();self._check_resources()
            self.store = self._launch._open_store(self.root_directory+'/control.db', inputs.run,
                policy=inputs.policy, queue_bound=inputs.queue_bound, run_id=inputs.run_id,
                resources=inputs.resources, supervisor_epoch=inputs.supervisor_epoch)
            if self._assets is not None:
                if self._state.path!=self.root_directory:
                    raise ValueError('original Store state parent differs')
                self._launch.ready_guard._bind_generation(self._assets,self._state)
            if self._baseline is not None:self._launch.ready_guard._bind_baseline(self._baseline)
            guard.check();self._check_resources()
            self.status = 'STORE_READY_ONLY'
            return self
        except BaseException as error:
            self.original_error = error
            # Capture all nested ownership BEFORE cleanup. These objects remain
            # reachable even if original clocks prevent any further cleanup.
            self.manager_owner = getattr(error, 'manager_owner', None)
            self.failed_provisioner = getattr(error, 'provisioner', None)
            self.failed_launch = getattr(error, 'session', None)
            self.guarded_store = getattr(error, 'guarded_store', None)
            if self._baseline is None:self._baseline=getattr(error,'original_baseline',None)
            if self._prefork is None:self._prefork=getattr(error,'prefork_inventory',None)
            self.close()
            raise RootEntryFailure(self) from error

    def _check_resources(self):
        if self._baseline is not None:self._baseline.check()
        if self._assets is not None:self._assets.check()
        if self._state is not None:self._state.check()

    def _admit_initial_descriptors(self, guard):
        """Necessary pre-effect inventory, not native loader/FD authentication.

        Supports CPython scandir(fd)'s one private directory duplicate. No
        caller whitelist or observation seam; unexpected FDs are never closed.
        Single-owner assumptions do not prove a race-free kernel FD table.
        """
        directory = iterator = None
        original_error = None

        def check():
            if self._owner != (os.getpid(), threading.current_thread()):
                raise ValueError('original descriptor-admission owner required')
            guard.check()

        def signature(fd):
            info = os.fstat(fd)
            return info.st_dev, info.st_ino, info.st_mode, info.st_rdev

        try:
            check()
            slots = tuple(self._incoming)
            if (len(slots) != 6 or any(type(fd) is not int or not 3 <= fd < 2**31 for fd in slots)
                    or len(set(slots)) != 6):
                raise ValueError('six distinct non-stdio descriptor slots required')
            required = {0, 1, 2, *slots}
            before = {}
            for fd in sorted(required):
                check(); before[fd] = signature(fd)
            null = os.stat('/dev/null')
            if not stat.S_ISCHR(null.st_mode):
                raise ValueError('original null device unavailable')
            for fd in (0, 1, 2):
                flags = fcntl.fcntl(fd, fcntl.F_GETFL)
                access = flags & os.O_ACCMODE
                allowed = (os.O_RDONLY, os.O_RDWR) if fd == 0 else (os.O_WRONLY, os.O_RDWR)
                mode = before[fd][2]
                if (flags & os.O_PATH or access not in allowed or
                        not (stat.S_ISREG(mode) or stat.S_ISFIFO(mode) or
                             (stat.S_ISCHR(mode) and before[fd][3] == null.st_rdev))):
                    raise ValueError('unsupported standard-stream role')
            check()
            directory = os.open('/proc/self/fd', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            check()
            if directory in required:
                raise ValueError('inventory directory aliases incoming slot')
            held = signature(directory)
            if not stat.S_ISDIR(held[2]):
                raise ValueError('descriptor inventory directory required')
            check()
            iterator = os.scandir(directory)
            check()
            observed = {}
            # Do not exhaust scandir before validating its still-live duplicate.
            for _ in range(11):
                check()
                try:
                    item = next(iterator)
                except StopIteration as error:
                    raise ValueError('incomplete descriptor inventory') from error
                name = item.name
                if (type(name) is not str or not 1 <= len(name) <= 10 or
                        any(c < '0' or c > '9' for c in name)):
                    raise ValueError('malformed descriptor inventory name')
                fd = int(name)
                if fd >= 2**31 or str(fd) != name or fd in observed:
                    raise ValueError('duplicate or noncanonical descriptor inventory')
                observed[fd] = signature(fd)
            expected = required | {directory}
            extra = set(observed) - expected
            if not expected <= set(observed) or len(extra) != 1:
                raise ValueError('unexpected or missing inherited descriptor')
            enumeration = observed[next(iter(extra))]
            if not stat.S_ISDIR(enumeration[2]) or enumeration[:2] != held[:2]:
                raise ValueError('unexpected descriptor is not owned enumerator')
            for fd, prior in before.items():
                check()
                if observed[fd] != prior or signature(fd) != prior:
                    raise ValueError('required descriptor changed during admission')
            if observed[directory] != held or signature(directory) != held:
                raise ValueError('owned inventory directory changed')
            check()
            try:
                next(iterator)
            except StopIteration:
                pass
            else:
                raise ValueError('descriptor inventory exceeds fixed bound')
            check()
        except BaseException as error:
            original_error = error
            raise
        finally:
            cleanup_errors = []
            owned_iterator, iterator = iterator, None
            if owned_iterator is not None:
                try: owned_iterator.close()
                except BaseException as error: cleanup_errors.append(error)
            owned_directory, directory = directory, None
            if owned_directory is not None:
                try: os.close(owned_directory)
                except BaseException as error: cleanup_errors.append(error)
            if cleanup_errors:
                if original_error is not None:
                    original_error.entry_cleanup_errors = getattr(original_error, 'entry_cleanup_errors', ()) + tuple(cleanup_errors)
                else:
                    raise cleanup_errors[0]
        check()

    def _take(self, index):
        value, self._incoming[index] = self._incoming[index], None
        return value

    def close(self):
        if self._owner != (os.getpid(), threading.current_thread()):
            raise ValueError('original root entry owner required')
        # Original guard/launch always precedes other owner cleanup. Each
        # retains its own child/process/lease capsule; no retry or new Store.
        # A provisioner owns its bus transitively. Retain the nested reference,
        # but do not run the same command cleanup twice through two capsules.
        provisioners = (self._provisioner, self.failed_provisioner)
        managed_buses = {id(getattr(owner, 'bus', None)) for owner in provisioners if owner is not None}
        manager = self.manager_owner if id(self.manager_owner) not in managed_buses else None
        owners = (('launch',self._launch),('failed_launch',self.failed_launch),('guarded_store',self.guarded_store),
            ('provisioner',self._provisioner),('failed_provisioner',self.failed_provisioner),
            ('bus',self._bus),('manager',manager),('sealer',self._sealer),('assets',self._assets),('state',self._state),('baseline',self._baseline))
        seen = set(); errors = []
        for role,owner in owners:
            if owner is not None and id(owner) not in seen:
                seen.add(id(owner))
                try: owner.close()
                except BaseException as error: errors.append((role,error))
        descriptors, self._incoming = self._incoming, []
        closed = set()
        for fd in descriptors:
            if type(fd) is int and fd >= 3 and fd not in closed:
                closed.add(fd)
                try: os.close(fd)
                except BaseException as error: errors.append(('incoming_fd_'+str(fd),error))
        self.cleanup_errors += tuple(errors)
        if errors:self.status='UNKNOWN'
