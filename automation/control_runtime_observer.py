"""Dormant finite negative observer; no spawn, provisioning, Store or release.

Only a separately authorized sealed bootstrap may transfer descriptors into the
private child factory. Parent-side ready authentication/positive fencing and
independent early-death recovery remain required integration, not supplied here.
The active exact frozen systemd slice must outlive this process; no retirement.
"""
from dataclasses import asdict
import hashlib
import os
import select
import socket
import threading
import time
from . import control_store as cs
from . import control_runtime_clock as clock
from . import control_runtime_containment as containment
from .control_runtime_channel import Channel, ProcessIdentity

_NS=1_000_000_000


def packet(kind,prepared,anchor):
    if kind not in ('READY','CONTAIN','CONTAIN_ATTEMPTED'):raise ValueError('closed observer packet kind required')
    containment._canonical_prepared(prepared)
    if type(anchor) is not cs.RuntimeClockAnchor:raise ValueError('original outer clock required')
    cs.validate_record(anchor)
    return cs.canonical(dict(version=1,kind=kind,run=anchor.run,
        anchor_digest=cs.record_digest(anchor),
        prepared_digest=hashlib.sha256(cs.canonical(asdict(prepared)).encode()).hexdigest())).encode()


class _Peer:
    def __init__(self,channel,anchor):self.channel,self.anchor=channel,anchor
    def _budget(self,cutoff):
        clock.check(self.anchor,positive=False)
        remaining=(cutoff-time.clock_gettime_ns(time.CLOCK_BOOTTIME))/_NS
        if remaining<=0:raise ValueError('original peer wait cutoff expired')
        return min(.1,remaining)
    def send(self,data,cutoff):
        self.channel.send(data,time.monotonic()+self._budget(cutoff))
    def poll(self,cutoff):
        channel=self.channel
        channel._live()
        ready,_,_=select.select([channel._pidfd,channel._socket],[],[],self._budget(cutoff))
        channel._live()
        if channel._pidfd in ready:raise ValueError('positive owner exited')
        if channel._socket not in ready:return None
        # Idle timeouts never call receive. A ready packet failure is terminal.
        return channel.receive(time.monotonic()+self._budget(cutoff))
    def close(self):self.channel.close()


class Observer:
    """One immutable trigger/stop window, one negative attempt, no disarm."""
    def __init__(self,*args,**kwargs):raise RuntimeError('sealed observer bootstrap absent')

    @classmethod
    def for_synthetic(cls,target,peer,prepared,anchor):
        if any(getattr(obj,'synthetic_only',None) is not True for obj in (target,peer)):
            raise ValueError('explicit synthetic target/peer required')
        return cls._bound(target,peer,prepared,anchor)

    @staticmethod
    def _dispose(endpoint,descriptors):
        number=endpoint.fileno() if type(endpoint) is socket.socket else -1
        failure=None;closed=set()
        for fd in descriptors:
            if type(fd) is int and fd>=0 and fd!=number and fd not in closed:
                closed.add(fd)
                try:os.close(fd)
                except BaseException as error:failure=failure or error
        if type(endpoint) is socket.socket:
            try:endpoint.close()
            except BaseException as error:failure=failure or error
        if failure is not None:raise failure

    @classmethod
    def _from_fds(cls,endpoint,parent,parent_pidfd,rootfd,targetfd,prepared,anchor):
        """Child-only, consumes every descriptor on rejection, never spawns.

        Endpoint must be exclusively transferred by protected bootstrap with
        PASSCRED enabled before any peer packet; no later project setters.
        """
        target=peer=None;target_owned=peer_owned=False
        try:
            descriptors=(parent_pidfd,rootfd,targetfd)
            if (os.geteuid()!=0 or os.getegid()!=0 or type(endpoint) is not socket.socket or
                any(type(fd) is not int or fd<0 or fd==endpoint.fileno() for fd in descriptors) or
                len(set(descriptors))!=3):raise ValueError('distinct sealed root observer descriptors required')
            if (type(parent) is not ProcessIdentity or
                any(type(getattr(parent,k)) is not int for k in ('pid','uid','gid','start_ticks')) or
                parent.pid<=0 or parent.pid==os.getpid() or parent.start_ticks<=0 or parent.uid!=0 or parent.gid!=0 or
                type(anchor) is not cs.RuntimeClockAnchor or parent.boot_id!=anchor.boot_id):
                raise ValueError('original root positive owner required')
            # Bind independent negative ownership BEFORE any parent-dependent
            # lookup: parent may already be dead, leaving no recovery actor.
            # Factories consume on failure too; transfer ownership BEFORE call.
            target_owned=True
            target=containment.NegativeTarget._from_prepared_fds(rootfd,targetfd,prepared,anchor)
            ns=os.stat('/proc/%d/ns/time'%parent.pid)
            if (ns.st_dev,ns.st_ino)!=(anchor.time_ns_device,anchor.time_ns_inode):
                raise ValueError('original parent time namespace required')
            peer_owned=True
            peer=_Peer(Channel(endpoint,parent,parent_pidfd),anchor)
            return cls._bound(target,peer,prepared,anchor)
        except BaseException:
            # No parent/Channel failure may silently disarm an already-bound
            # child target. This factory has not returned an Observer, so this
            # is its sole negative attempt, before target descriptors close.
            if target is not None:
                try:target.contain()
                except BaseException:pass
            for obj in (target,peer):
                if obj is not None:
                    try:obj.close()
                    except BaseException:pass
            try:
                cls._dispose(None if peer_owned else endpoint,
                    (() if peer_owned else (parent_pidfd,)) + (() if target_owned else (rootfd,targetfd)))
            except BaseException:pass
            raise

    @classmethod
    def _bound(cls,target,peer,prepared,anchor):
        containment._canonical_prepared(prepared)
        if type(anchor) is not cs.RuntimeClockAnchor:raise ValueError('original outer anchor required')
        cs.validate_record(anchor)
        t=prepared.target
        if ((t.run,t.configuration_digest,t.boot_id,t.time_ns_device,t.time_ns_inode)!=
            (anchor.run,anchor.configuration_digest,anchor.boot_id,anchor.time_ns_device,anchor.time_ns_inode) or
            not anchor.captured_boottime_ns<=t.armed_boottime_ns<t.lease_deadline_boottime_ns<=anchor.deadline_boottime_ns):
            raise ValueError('prepared original observer context differs')
        self=object.__new__(cls)
        self._target,self._peer,self.prepared,self.anchor=target,peer,prepared,anchor
        # The target's own inner syscall guard must expire at our stop too.
        # Never merely shorten the polling loop around a longer-lived target.
        if t.lease_deadline_boottime_ns>anchor.captured_boottime_ns+90*_NS:
            raise ValueError('target per-write lease exceeds original observer stop')
        self.stop_ns=t.lease_deadline_boottime_ns
        self.trigger_ns=min(anchor.captured_boottime_ns+60*_NS,self.stop_ns)
        if self.trigger_ns>=self.stop_ns:raise ValueError('original negative observation window required')
        self._owner=os.getpid(),threading.current_thread();self._closed=False
        self._last_boot=anchor.captured_boottime_ns;self._wall=anchor.sampled_wall_ns
        self._armed=False;self.ready_queued=False;self.retained=True
        self.triggered=False;self.result=None;self.reason=None
        self._check();target._remaining();self._check()
        return self

    def _check(self):
        if self._closed or self._owner!=(os.getpid(),threading.current_thread()):raise ValueError('observer owner changed')
        now,wall=clock.sample(self.anchor,positive=False)
        if (now<self._last_boot or now<self.prepared.target.armed_boottime_ns or wall<self._wall or
            now>=self.stop_ns or wall>=self.anchor.wall_deadline_ns):raise ValueError('original observer cutoff/clock invalid')
        self._last_boot,self._wall=now,wall
        return now

    def _budget(self,bound):return min(.1,(bound-self._check())/_NS)

    def _contain(self,reason):
        if self.triggered:return
        self.triggered=True;self.reason=reason
        # No report or parent liveness check may precede this negative attempt.
        try:self.result=self._target.contain()
        except Exception:self.result=None
        try:self._peer.send(packet('CONTAIN_ATTEMPTED',self.prepared,self.anchor),self.stop_ns)
        except Exception:pass

    def arm(self):
        if self._armed:raise ValueError('observer is one-shot')
        self._armed=True
        try:
            self._check();self._target._remaining();self._check()
            self._peer.send(packet('READY',self.prepared,self.anchor),self.trigger_ns)
            self._check();self.ready_queued=True
        except Exception:self._contain('readiness_failed')

    def step(self):
        """At most one clipped idle wait; True means original window ended.

        No claim that a queued ready/report was consumed. Result observations
        retain their own timestamp scope; holding does not refresh an old ACK.
        """
        if not self._armed:raise ValueError('observer not armed')
        try:now=self._check()
        except Exception:
            self._contain('clock_or_cutoff');return True
        if not self.triggered:
            if now>=self.trigger_ns:self._contain('original_trigger')
            else:
                try:
                    self._check();message=self._peer.poll(self.trigger_ns)
                    now=self._check()
                    if now>=self.trigger_ns:self._contain('original_trigger')
                    elif message is not None:
                        self._contain('parent_request' if message==packet('CONTAIN',self.prepared,self.anchor) else 'invalid_packet')
                except Exception:self._contain('parent_or_channel_lost')
        else:
            # No repeated write inventory, no channel dependency after trigger.
            try:
                self._target._remaining()
                time.sleep(self._budget(self.stop_ns))
                self._check()
            except Exception:return True
        return False

    def run(self):
        try:
            self.arm()
            while not self.step():pass
            return self.result
        finally:self.close()

    def close(self):
        if self._closed:return
        # An early close fences the target, never silently disarms an observer.
        self._contain('observer_close')
        self._closed=True;error=None
        for obj in (self._peer,self._target):
            try:obj.close()
            except BaseException as failure:error=error or failure
        if error is not None:raise error
