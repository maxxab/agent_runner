"""Dormant parent readiness/fencing guard; no Store, send authority or launch.

Protected bootstrap exclusively transfers original observer Channel/pidfd and
separate original-target root recovery object. Project packets/digests cannot
instantiate readiness. Future executor must invoke this necessary guard at its
fresh sole-Store effect boundary; guard success never replaces a Store claim.
"""
from dataclasses import asdict
import os
import threading
import time
from . import control_runtime_clock as clock
from . import control_runtime_containment as containment
from . import control_runtime_observer as observer
from . import control_store as cs
from .control_runtime_channel import Channel, ProcessIdentity, identity

_NS=1_000_000_000


class _Peer(observer._Peer):
    def live(self):
        channel=self.channel;channel._live()
        expected=channel._peer
        if identity(expected.pid)!=expected:raise ValueError('original observer identity differs')
        ns=os.stat('/proc/%d/ns/time'%expected.pid)
        if (ns.st_dev,ns.st_ino)!=(self.anchor.time_ns_device,self.anchor.time_ns_inode):
            raise ValueError('original observer time namespace differs')
        channel._live()


class ReadyGuard:
    def __init__(self,*args,**kwargs):raise RuntimeError('protected readiness bootstrap absent')

    @classmethod
    def for_synthetic(cls,peer,recovery,prepared,anchor):
        if any(getattr(obj,'synthetic_only',None) is not True for obj in (peer,recovery)):
            raise ValueError('explicit synthetic peer/recovery required')
        return cls._bound(peer,recovery,prepared,anchor,synthetic=True)

    @classmethod
    def _from_channel(cls,channel,recovery,prepared,anchor):
        """Consumes previously exclusive protected resources, never spawns."""
        peer=None
        try:
            if os.geteuid()!=0 or os.getegid()!=0:raise ValueError('sealed root parent required')
            containment._canonical_prepared(prepared)
            if type(channel) is not Channel or type(recovery) is not containment.NegativeTarget or recovery._role!='recovery':
                raise ValueError('original Channel and separate root recovery required')
            target=prepared.target
            expected=ProcessIdentity(target.observer_pid,0,0,target.observer_start_ticks,target.boot_id)
            if (type(channel._peer) is not ProcessIdentity or
                any(type(getattr(channel._peer,k)) is not int for k in ('pid','uid','gid','start_ticks')) or
                channel._peer!=expected or expected.pid==os.getpid()):
                raise ValueError('original root observer Channel required')
            containment._canonical_prepared(recovery._prepared)
            if cs.canonical(asdict(prepared))!=cs.canonical(asdict(recovery._prepared)):
                raise ValueError('recovery prepared context differs')
            peer=_Peer(channel,anchor)
            return cls._bound(peer,recovery,prepared,anchor,synthetic=False)
        except BaseException:
            # If _bound started it already fenced/closed resources. Objects
            # invalidate their owned descriptors before close; repeated cleanup
            # is harmless, but negative attempt must not be repeated here.
            if peer is None:
                if type(recovery) is containment.NegativeTarget:
                    try:recovery.contain()
                    except BaseException:pass
                    try:recovery.close()
                    except BaseException:pass
                if type(channel) is Channel:
                    try:channel.close()
                    except BaseException:pass
            raise

    @classmethod
    def _bound(cls,peer,recovery,prepared,anchor,*,synthetic):
        self=object.__new__(cls)
        self._peer,self._recovery,self.prepared,self.anchor=peer,recovery,prepared,anchor
        self._synthetic=synthetic;self._owner=os.getpid(),threading.current_thread()
        self._closed=False;self.ready=False;self.ready_boot_ns=self.ready_wall_ns=None
        self._store_anchor=None  # retained evidence, never a replacement outer clock
        self._generation=None;self._generation_files=None
        self._generation_binding_attempted=False
        self._baseline=None;self._baseline_binding_attempted=False
        try:
            containment._canonical_prepared(prepared)
            if type(anchor) is not cs.RuntimeClockAnchor:raise ValueError('original outer anchor required')
            cs.validate_record(anchor)
            target=prepared.target
            if ((target.run,target.configuration_digest,target.boot_id,target.time_ns_device,target.time_ns_inode)!=
                (anchor.run,anchor.configuration_digest,anchor.boot_id,anchor.time_ns_device,anchor.time_ns_inode) or
                not anchor.captured_boottime_ns<=target.armed_boottime_ns<target.lease_deadline_boottime_ns<=
                    min(anchor.deadline_boottime_ns,anchor.captured_boottime_ns+90*_NS)):
                raise ValueError('original prepared readiness context differs')
            self._wall=anchor.sampled_wall_ns;self._last_boot=anchor.captured_boottime_ns
            self._setup_end=min(anchor.captured_boottime_ns+15*_NS,target.lease_deadline_boottime_ns,anchor.deadline_boottime_ns)
            while True:
                self._check(self._setup_end);recovery._remaining();peer.live();self._check(self._setup_end)
                message=peer.poll(self._setup_end)
                self._check(self._setup_end)
                if message is None:continue
                if message!=observer.packet('READY',prepared,anchor):raise ValueError('original exact READY required')
                peer.live();recovery._remaining()
                self.ready_boot_ns=self._check(self._setup_end);self.ready_wall_ns=self._wall
                self.ready=True;return self
        except BaseException:
            self._fence();raise

    def _check(self,end):
        if self._closed or self._owner!=(os.getpid(),threading.current_thread()):raise ValueError('readiness owner lost')
        if not self._synthetic and (os.geteuid()!=0 or os.getegid()!=0):raise ValueError('root parent changed')
        now,wall=clock.sample(self.anchor,positive=False)
        if now<self._last_boot or now>=end or wall<self._wall or wall>=self.anchor.wall_deadline_ns:
            raise ValueError('original readiness cutoff/clock invalid')
        self._last_boot,self._wall=now,wall
        return now

    def _before_store(self, configuration, deadline):
        """Necessary original READY/configuration check, no Store constructor."""
        try:
            if not self.ready or type(configuration) is not str:
                raise ValueError('original readiness and canonical Store configuration required')
            cs.finite(deadline)
            end = clock.nanoseconds(deadline)
            if (cs.record_digest(configuration) != self.anchor.configuration_digest or
                    end > min(self.anchor.wall_deadline_ns, self.anchor.sampled_wall_ns+44*_NS)):
                raise ValueError('original Store configuration/native cutoff differs')
            self._check(self._setup_end)
            self._peer.live(); self._recovery._remaining(); self._peer.live()
            self._check(self._setup_end)
        except BaseException:
            self._fence(); raise

    def _after_store(self, actual, configuration, deadline):
        """Actual worker-captured anchor, never a provisional Store/clock."""
        try:
            if self._store_anchor is not None:
                raise ValueError('original Store anchor already bound')
            self._before_store(configuration, deadline)
            if type(actual) is not cs.RuntimeClockAnchor:
                raise ValueError('actual sole Store anchor required')
            cs.validate_record(actual)
            outer = self.anchor
            if ((actual.run, actual.supervisor_epoch, actual.configuration_digest, actual.boot_id,
                    actual.time_ns_device, actual.time_ns_inode) !=
                    (outer.run, outer.supervisor_epoch, outer.configuration_digest, outer.boot_id,
                    outer.time_ns_device, outer.time_ns_inode) or
                    actual.captured_boottime_ns < self.ready_boot_ns or
                    actual.sampled_wall_ns < self.ready_wall_ns or
                    actual.wall_deadline_ns != clock.nanoseconds(deadline) or
                    actual.deadline_boottime_ns > outer.captured_boottime_ns+44*_NS):
                raise ValueError('actual sole Store precedes READY or renews original window')
            clock.check(actual, positive=True)
            self._before_store(configuration, deadline)
            self._store_anchor=actual
        except BaseException:
            self._fence(); raise

    def _check_store_lifetime(self, actual):
        """Clock/owner only: never calls resources, peer or before_effect."""
        if not self.ready or actual is None or actual!=self._store_anchor:
            raise ValueError('original bound Store lifetime required')
        end=min(actual.deadline_boottime_ns,self.prepared.target.lease_deadline_boottime_ns)
        clock.check(actual,positive=True)
        now=self._check(end)
        if self._wall>=actual.wall_deadline_ns:
            raise ValueError('original Store wall deadline expired')
        return now,self._wall

    def _bind_generation(self, assets, state):
        """Necessary retained identity checks, never a new runtime origin."""
        from .control_runtime_assets import AssetGeneration
        from .control_runtime_state import RunState
        try:
            if self._generation_binding_attempted:
                raise ValueError('generation binding already consumed')
            self._generation_binding_attempted=True
            if (self._synthetic or not self.ready or self._store_anchor is None or
                    type(assets) is not AssetGeneration or type(state) is not RunState):
                raise ValueError('exact protected generation and state required')
            self._check(self._setup_end)
            self._peer.live();self._recovery._remaining()
            assets.check();state.check()
            assets._bind_store(self);state._bind_store(self)
            assets.check();state.check()
            self._peer.live();self._recovery._remaining();self._peer.live()
            self._check(self._setup_end)
            self._generation_files=assets.files
            self._generation=(assets,state)
        except BaseException:
            self._fence();raise

    def _bind_baseline(self,baseline):
        from .control_runtime_original import _OriginalBaseline
        try:
            if self._baseline_binding_attempted:raise ValueError('original baseline binding already consumed')
            self._baseline_binding_attempted=True
            if (self._synthetic or not self.ready or self._store_anchor is None or self._generation is None or
                    type(baseline) is not _OriginalBaseline or baseline.anchor is not self.anchor or
                    baseline._assets is not self._generation[0]):
                raise ValueError('same original baseline, generation and actual Store required')
            self._check(self._setup_end);self._peer.live();self._recovery._remaining()
            baseline.check();baseline._bind_store(self);baseline.check()
            self._peer.live();self._recovery._remaining();self._check(self._setup_end)
            self._baseline=baseline
        except BaseException:
            self._fence();raise

    def _check_generation(self, policy):
        if self._generation_binding_attempted and self._generation is None:
            raise ValueError('generation binding incomplete')
        if self._generation is not None:
            assets,state=self._generation
            if policy.files!=self._generation_files or assets.files!=self._generation_files:
                raise ValueError('policy differs from original admitted generation files')
            assets.check();state.check()
        if self._baseline_binding_attempted and self._baseline is None:
            raise ValueError('original baseline binding incomplete')
        if self._baseline is not None:self._baseline.check()

    def before_effect(self,policy):
        try:
            if not self.ready:raise ValueError('original readiness absent or fenced')
            containment.verify_prepared_policy(self.prepared,policy)
            a=policy.clock_anchor
            if self._store_anchor is None or a!=self._store_anchor:
                raise ValueError('original bound Store anchor required')
            if (a.supervisor_epoch!=self.anchor.supervisor_epoch or
                a.captured_boottime_ns<self.ready_boot_ns or a.sampled_wall_ns<self.ready_wall_ns or
                a.deadline_boottime_ns>self.anchor.captured_boottime_ns+44*_NS or
                a.wall_deadline_ns>self.anchor.sampled_wall_ns+44*_NS):
                raise ValueError('actual Store precedes READY or renews original native window')
            self._check_store_lifetime(a)
            self._check_generation(policy)
            self._peer.live();self._recovery._remaining()
            self._peer.live()
            self._check_store_lifetime(a)
        except BaseException:
            self._fence();raise

    def _fence(self):
        if self._closed:return
        self.ready=False
        try:self._recovery.contain()
        except BaseException:pass
        self._closed=True
        for obj in (self._peer,self._recovery):
            try:obj.close()
            except BaseException:pass

    def close(self):self._fence()
