"""Dormant systemd recipe and exact-target negative containment, no provisioner.

No manager call, target creation, thaw, deletion, Store or release authority.
Private FD binding requires a separately authorized sealed root bootstrap.
Physical target retention, controller prerequisites and placement are unqualified.
"""
from dataclasses import dataclass
import os
import re
import stat
import threading
import time
from . import control_store as cs
from . import control_runtime_clock as clock
from .control_runtime_channel import ProcessIdentity, identity

_NAME = re.compile(r'rnr[0-9a-f]{32}\.slice\Z')
_PERIOD = 100000


@dataclass(frozen=True)
class SliceRecipe:
    name: str
    quota: cs.QuotaPolicy
    properties: tuple[tuple[str, str, bool | str | int], ...]


def slice_recipe(name, quota):
    """Inert StartTransientUnit properties; no permission to call the manager.

    Future provisioner must first verify cpu/memory/pids are already enabled at
    ancestors: systemd resource settings can otherwise enable them implicitly.
    Exactly correlate this recipe to the eventual committed full policy.
    """
    if type(name) is not str or _NAME.fullmatch(name) is None or type(quota) is not cs.QuotaPolicy:
        raise ValueError('exact allocation-specific slice/quota required')
    cs.validate_record(quota)
    if quota.cpu_millis % 10 or quota.cpu_millis > (2**63-1)//1000000:
        raise ValueError('exact CPU quota without rounding required')
    props = [('StopWhenUnneeded','b',False), ('CollectMode','s','inactive'),
             ('RefuseManualStop','b',True), ('IgnoreOnIsolate','b',True),
             ('AllowIsolate','b',False), ('DefaultDependencies','b',False),
             ('CPUAccounting','b',True), ('MemoryAccounting','b',True), ('TasksAccounting','b',True),
             ('MemoryMax','t',quota.memory_bytes), ('MemorySwapMax','t',0), ('TasksMax','t',quota.pids),
             ('CPUQuotaPerSecUSec','t',quota.cpu_millis*1000), ('CPUQuotaPeriodUSec','t',_PERIOD)]
    return SliceRecipe(name, quota, tuple(sorted(props)))


@dataclass(frozen=True)
class PreparedTarget:
    """Pre-Store negative context; no readiness authentication or send authority."""
    target: cs.RuntimeContainment
    recipe: SliceRecipe


def validate_slice_recipe(recipe):
    """Return canonical properties after exact typed inert recipe validation."""
    if type(recipe) is not SliceRecipe:raise ValueError('canonical systemd recipe required')
    expected_recipe=slice_recipe(recipe.name,recipe.quota)
    if type(recipe.properties) is not tuple or len(recipe.properties)!=len(expected_recipe.properties):
        raise ValueError('closed slice properties required')
    for actual,expected in zip(recipe.properties,expected_recipe.properties):
        if (type(actual) is not tuple or len(actual)!=3 or
                any(type(a) is not type(b) or a!=b for a,b in zip(actual,expected))):
            raise ValueError('exact typed slice property required')
    return expected_recipe


def _canonical_prepared(prepared):
    if type(prepared) is not PreparedTarget or type(prepared.target) is not cs.RuntimeContainment:
        raise ValueError('exact prepared target required')
    target,recipe=prepared.target,prepared.recipe
    cs.validate_record(target)
    recipe=validate_slice_recipe(recipe)
    if (target.driver!='systemd' or recipe.name!=target.parent or
            target.memory_bytes!=recipe.quota.memory_bytes or target.pids!=recipe.quota.pids):
        raise ValueError('slice differs from prepared quota/target')
    return recipe


def verify_prepared_policy(prepared, policy):
    """Compare complete readiness context to actual policy, never authenticate it.

    Trusted bootstrap must separately authenticate the original observer's ready
    channel/pidfd and physical held target BEFORE Store/positive effects. This
    comparison is only a necessary later correlation, not positive authority.
    """
    recipe=_canonical_prepared(prepared)
    if type(policy) is not cs.ContainedRuntimePolicy:raise ValueError('full contained policy required')
    cs.validate_record(policy)
    # Both records were fully type-validated above; compare every field directly.
    # No cached validation/identity and no change to persisted digest protocols.
    if prepared.target!=policy.containment or recipe.quota!=policy.quota:
        raise ValueError('complete prepared target/full quota differs from actual policy')


def verify_slice(recipe, snapshot, policy):
    """Closed projected readback only, not lifecycle/physical authentication."""
    if type(policy) is not cs.ContainedRuntimePolicy:raise ValueError('full contained policy required')
    cs.validate_record(policy)
    prepared=PreparedTarget(policy.containment,recipe)
    verify_prepared_policy(prepared,policy)
    verify_recipe_snapshot(recipe,snapshot)


def verify_recipe_snapshot(recipe,snapshot):
    """Necessary pre-Store manager projection check; no authentication/grant."""
    expected_recipe=validate_slice_recipe(recipe)
    expected = dict((name,value) for name,_,value in expected_recipe.properties)
    expected.update(ActiveState='active',SubState='active',LoadState='loaded',Transient=True,
                    ControlGroup='/'+recipe.name,Job=[0,'/'])
    if (type(snapshot) is not dict or set(snapshot) != set(expected) or
            any(type(snapshot[key]) is not type(value) or cs.canonical(snapshot[key]) != cs.canonical(value)
                for key,value in expected.items())):
        raise ValueError('slice lifecycle/resource readback differs')


@dataclass(frozen=True)
class NegativeObservation:
    status: str
    freeze_requested: bool
    kill_requested: bool
    frozen: bool | None
    populated: bool | None
    retained: bool = True


class _TargetFS:
    """Own two root-bootstrap descriptors; negative operations only.

    A closed/deleted/changed target is never replaced by its same-name successor.
    Closing this object never removes/stops/thaws the retained unit/target.
    """
    def __init__(self, rootfd, targetfd, policy, outer_anchor, *, actor=None):
        self.rootfd,self.targetfd,self.prepared=rootfd,targetfd,policy
        self.target=policy.target
        t=self.target
        self.actor=actor if actor is not None else ProcessIdentity(t.observer_pid,0,0,t.observer_start_ticks,t.boot_id)
        self.anchor=outer_anchor;self.wall=outer_anchor.sampled_wall_ns;self.last_boot=outer_anchor.captured_boottime_ns
        self.owner=os.getpid(),threading.current_thread()

    def _check(self):
        now,wall=clock.sample(self.anchor,positive=False)
        if (now<self.last_boot or now>=self.target.lease_deadline_boottime_ns or
                wall<self.wall or wall>=self.anchor.wall_deadline_ns):
            raise ValueError('original negative descriptor lease expired')
        self.last_boot,self.wall=now,wall

    @staticmethod
    def _fdread(fd, limit):
        data=os.read(fd,limit+1)
        if len(data)>limit:raise ValueError('bounded cgroup metadata required')
        return data

    def _read(self, name):
        self._check()
        fd=os.open(name,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.targetfd)
        try:
            self._check();data=self._fdread(fd,256);self._check();return data
        finally:os.close(fd)

    def verify(self):
        self._check()
        if self.owner!=(os.getpid(),threading.current_thread()) or self.rootfd is None:
            raise ValueError('target owner closed or changed')
        target=self.target
        current=identity(os.getpid())
        if os.geteuid()!=0 or os.getegid()!=0 or current!=self.actor:
            raise ValueError('original root negative actor differs')
        for fd in (self.rootfd,self.targetfd):
            info=os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
                raise ValueError('protected target directory required')
        if os.readlink('/proc/self/fd/'+str(self.rootfd))!='/sys/fs/cgroup':
            raise ValueError('fixed held cgroup root required')
        if os.readlink('/proc/self/fd/'+str(self.targetfd))!=target.cgroup_path:
            raise ValueError('held target path changed')
        info=os.fstat(self.targetfd)
        if (info.st_dev,info.st_ino)!=(target.device,target.inode):raise ValueError('target inode differs')
        fresh=os.open(target.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW,dir_fd=self.rootfd)
        try:
            info=os.fstat(fresh)
            if (info.st_dev,info.st_ino)!=(target.device,target.inode):raise ValueError('target replaced')
        finally:os.close(fresh)
        for fd in (self.rootfd,self.targetfd):
            with open('/proc/self/fdinfo/'+str(fd),'rb') as source:data=source.read(4097)
            if len(data)>4096:raise ValueError('fd metadata bound')
            fields=dict(line.split(b':',1) for line in data.splitlines() if b':' in line)
            if int(fields.get(b'mnt_id',b'-1'))!=target.mount_id:raise ValueError('target mount differs')
        with open('/proc/self/mountinfo','rb') as source:data=source.read(1048577)
        if len(data)>1048576:raise ValueError('mount inventory bound')
        matches=[line.split() for line in data.splitlines() if line.split(maxsplit=1)[0]==str(target.mount_id).encode()]
        if len(matches)!=1:raise ValueError('exact cgroup mount required')
        fields=matches[0];separator=fields.index(b'-')
        if fields[3:5]!=[b'/',b'/sys/fs/cgroup'] or fields[separator+1]!=b'cgroup2':
            raise ValueError('original cgroup2 mount required')
        with open('/proc/self/cgroup','rb') as source:data=source.read(4097)
        if len(data)>4096 or not data.startswith(b'0::') or len(data.splitlines())!=1:
            raise ValueError('unified observer membership required')
        membership=data[3:].strip().decode('ascii');path='/'+target.parent
        if membership==path or membership.startswith(path+'/'):raise ValueError('observer inside workload target')
        self._check()

    def verify_limits(self, policy):
        if policy is not self.prepared:raise ValueError('prepared quota changed')
        if self._read('cgroup.type')!=b'domain\n':raise ValueError('domain target required')
        expected={'memory.max':policy.recipe.quota.memory_bytes,'memory.swap.max':0,'pids.max':policy.recipe.quota.pids}
        for name,value in expected.items():
            if self._read(name)!=str(value).encode()+b'\n':raise ValueError('target kernel limits differ')
        if self._read('cpu.max')!=f'{policy.recipe.quota.cpu_millis*100} {_PERIOD}\n'.encode():
            raise ValueError('exact effective CPU quota required')

    def write(self, name, data):
        if name not in ('cgroup.freeze','cgroup.kill') or data!=b'1':raise ValueError('fixed negative write required')
        self.verify()
        self._check()
        fd=os.open(name,os.O_WRONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.targetfd)
        try:
            self._check()
            if os.write(fd,data)!=1:raise ValueError('incomplete negative request')
            self._check()
        finally:os.close(fd)
        self.verify()

    def read(self, name):
        if name!='cgroup.events':raise ValueError('fixed negative observation required')
        self.verify();data=self._read(name);self.verify();return data

    def close(self):
        fds=(self.targetfd,self.rootfd);self.targetfd=self.rootfd=None
        error=None
        for fd in fds:
            if type(fd) is int and fd>=0:
                try:os.close(fd)
                except BaseException as failure:error=error or failure
        if error is not None:raise error


class NegativeTarget:
    def __init__(self,*args,**kwargs):
        raise RuntimeError('operational containment disabled; protected bootstrap absent')

    @classmethod
    def for_synthetic(cls, filesystem, policy, outer_anchor):
        if getattr(filesystem,'synthetic_only',None) is not True:raise ValueError('explicit synthetic filesystem required')
        return cls._bound(filesystem,cls._prepare_policy(policy),outer_anchor)

    @staticmethod
    def _prepare_policy(policy):
        if type(policy) is not cs.ContainedRuntimePolicy:raise ValueError('exact contained policy required')
        cs.validate_record(policy)
        return PreparedTarget(policy.containment,slice_recipe(policy.containment.parent,policy.quota))

    @classmethod
    def for_synthetic_prepared(cls, filesystem, prepared, outer_anchor):
        if getattr(filesystem,'synthetic_only',None) is not True:raise ValueError('explicit synthetic filesystem required')
        return cls._bound(filesystem,prepared,outer_anchor)

    @classmethod
    def _from_fds(cls, rootfd, targetfd, policy, outer_anchor):
        # Validation deliberately occurs inside the consuming factory.
        return cls._from_prepared_fds(rootfd,targetfd,policy,outer_anchor,_full_policy=True)

    @classmethod
    def _from_recovery_fds(cls, rootfd, targetfd, prepared, outer_anchor):
        """Sealed root fallback only; preserve original observer declaration.

        This separate actual actor can fence the original target on observer
        loss or early abort. It cannot issue/replace READY, admit Store effects,
        reset the target lease, or infer complete release from containment.
        """
        return cls._from_prepared_fds(rootfd,targetfd,prepared,outer_anchor,_recovery=True)

    @classmethod
    def _from_prepared_fds(cls, rootfd, targetfd, prepared, outer_anchor, *, _full_policy=False, _recovery=False):
        """Consumes descriptors even on rejection; no creation or grant."""
        filesystem=None
        try:
            if (type(rootfd) is not int or type(targetfd) is not int or rootfd<0 or targetfd<0 or
                    rootfd==targetfd or os.geteuid()!=0 or os.getegid()!=0):
                raise ValueError('root bootstrap-owned distinct target descriptors required')
            if _full_policy:prepared=cls._prepare_policy(prepared)
            _canonical_prepared(prepared)
            actor=None
            if _recovery:
                actor=identity(os.getpid())
                if (type(actor) is not ProcessIdentity or
                    any(type(getattr(actor,k)) is not int for k in ('pid','uid','gid','start_ticks')) or
                    actor.pid!=os.getpid() or actor.pid<=0 or actor.start_ticks<=0 or
                    actor.uid!=0 or actor.gid!=0 or actor.boot_id!=prepared.target.boot_id):
                    raise ValueError('exact internally bound root recovery actor required')
            filesystem=_TargetFS(rootfd,targetfd,prepared,outer_anchor,actor=actor)
            result=cls._bound(filesystem,prepared,outer_anchor)
            result._role='recovery' if _recovery else 'observer'
            return result
        except BaseException:
            if filesystem is not None:
                try:filesystem.close()
                except BaseException:pass
            else:
                closed=set()
                for fd in (rootfd,targetfd):
                    if type(fd) is int and fd>=0 and fd not in closed:
                        closed.add(fd)
                        try:os.close(fd)
                        except BaseException:pass
            raise

    @classmethod
    def _bound(cls, filesystem, prepared, outer_anchor):
        if type(outer_anchor) is not cs.RuntimeClockAnchor:
            raise ValueError('exact committed policy/original outer clock required')
        _canonical_prepared(prepared);cs.validate_record(outer_anchor)
        target=prepared.target
        if (target.driver!='systemd' or (target.run,target.configuration_digest,target.boot_id,target.time_ns_device,target.time_ns_inode)!=
            (outer_anchor.run,outer_anchor.configuration_digest,outer_anchor.boot_id,outer_anchor.time_ns_device,outer_anchor.time_ns_inode) or
            not outer_anchor.captured_boottime_ns<=target.armed_boottime_ns<target.lease_deadline_boottime_ns<=outer_anchor.deadline_boottime_ns):
            raise ValueError('original outer negative context differs')
        self=object.__new__(cls)
        self._fs,self._prepared,self._anchor=filesystem,prepared,outer_anchor
        self._owner=os.getpid(),threading.current_thread()
        self._role='observer'
        self._closed=False;self._wall=outer_anchor.sampled_wall_ns;self._last_boot=outer_anchor.captured_boottime_ns
        self._remaining();filesystem.verify_limits(prepared);self._remaining()
        return self

    def _timecheck(self):
        if self._closed or self._owner!=(os.getpid(),threading.current_thread()):raise ValueError('negative owner changed')
        now,wall=clock.sample(self._anchor,positive=False)
        if now<self._last_boot or now>=self._prepared.target.lease_deadline_boottime_ns or wall<self._wall or wall>=self._anchor.wall_deadline_ns:
            raise ValueError('original negative lease expired or clock moved backwards')
        self._last_boot,self._wall=now,wall

    def _remaining(self):
        self._timecheck();self._fs.verify();self._timecheck()

    def contain(self):
        """One finite freeze/kill/observe step. Never release or retire a target."""
        freeze=kill=False;frozen=populated=None
        for name in ('cgroup.freeze','cgroup.kill'):
            try:
                self._remaining();self._fs.write(name,b'1');self._remaining()
                if name=='cgroup.freeze':freeze=True
                else:kill=True
            except Exception:
                # Freeze failure does not suppress an independently safe kill.
                continue
        try:
            self._remaining();data=self._fs.read('cgroup.events');self._remaining()
            if type(data) is not bytes or len(data)>256:raise ValueError('events bound')
            lines=data.splitlines();pairs=[line.split() for line in lines]
            if len(pairs)!=2 or any(len(pair)!=2 for pair in pairs):raise ValueError('events shape')
            fields=dict(pairs)
            if set(fields)!={b'frozen',b'populated'} or any(value not in (b'0',b'1') for value in fields.values()):
                raise ValueError('events values')
            frozen,populated=fields[b'frozen']==b'1',fields[b'populated']==b'1'
        except Exception:pass
        status='FROZEN_EMPTY_OBSERVED' if freeze and kill and frozen is True and populated is False else 'UNKNOWN'
        return NegativeObservation(status,freeze,kill,frozen,populated)

    def close(self):
        if not self._closed:
            self._closed=True;self._fs.close()
