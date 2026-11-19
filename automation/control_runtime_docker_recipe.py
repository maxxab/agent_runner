"""Pure Engine API1.51 recipe compiler; no socket, effect or release authority.

A valid record is not a fresh Store claim. The eventual trusted executor must
qualify daemon identity, sealed files, process isolation and lifecycle evidence.
Config.Env removal directives are not an observation of process environment.
"""
from dataclasses import asdict, dataclass
import re
from . import control_store as cs

API = '/v1.51'
_ZERO_TIME = '0001-01-01T00:00:00Z'
_ENV_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,255}\Z')
_MASKED = ['/proc/acpi', '/proc/asound', '/proc/interrupts', '/proc/kcore',
           '/proc/keys', '/proc/latency_stats', '/proc/sched_debug', '/proc/scsi',
           '/proc/timer_list', '/proc/timer_stats', '/sys/devices/virtual/powercap', '/sys/firmware']
_READONLY = ['/proc/bus', '/proc/fs', '/proc/irq', '/proc/sys', '/proc/sysrq-trigger']
# Only these observed/documented neutral defaults may supplement the explicit
# recipe. Unknown fields reject, even if empty; compatibility is not assumed.
_NEUTRAL_HOST = {
    **dict.fromkeys(('ContainerIDFile', 'VolumeDriver', 'Cgroup', 'UsernsMode', 'Isolation',
                     'CgroupParent', 'CpusetCpus', 'CpusetMems'), ''),
    **dict.fromkeys(('OomScoreAdj', 'CpuShares', 'BlkioWeight', 'CpuPeriod', 'CpuQuota',
                     'CpuRealtimePeriod', 'CpuRealtimeRuntime', 'MemoryReservation', 'CpuCount',
                     'CpuPercent', 'IOMaximumIOps', 'IOMaximumBandwidth'), 0),
    **dict.fromkeys(('Binds', 'VolumesFrom', 'Dns', 'ExtraHosts', 'Links', 'DeviceCgroupRules',
                     'DeviceRequests', 'MemorySwappiness'), None),
    **{key: [] for key in ('DnsOptions', 'DnsSearch', 'BlkioWeightDevice', 'BlkioDeviceReadBps',
                          'BlkioDeviceWriteBps', 'BlkioDeviceReadIOps', 'BlkioDeviceWriteIOps', 'Ulimits')},
    'PortBindings': {}, 'ConsoleSize': [0, 0], 'OomKillDisable': False,
    'PublishAllPorts': False, 'Sysctls': {}, 'StorageOpt': {}, 'Annotations': {},
}
_NEUTRAL_CONFIG = {'Volumes': None, 'ExposedPorts': None, 'OnBuild': None,
                   'Shell': None, 'ArgsEscaped': False, 'NetworkDisabled': False, 'MacAddress': ''}


@dataclass(frozen=True)
class CreateRecipe:
    path: str
    body: bytes


def _bounded(value):
    count = 0
    def visit(item, depth):
        nonlocal count
        count += 1
        if count > 8192 or depth > 16:
            raise ValueError('Docker data structure bound')
        if type(item) is dict:
            if len(item) > 256 or any(type(key) is not str for key in item):
                raise ValueError('bounded Docker object required')
            for key, val in item.items():
                visit(key, depth + 1); visit(val, depth + 1)
        elif type(item) is list:
            if len(item) > 256: raise ValueError('Docker array bound')
            for val in item: visit(val, depth + 1)
        elif type(item) is str:
            if '\x00' in item or len(item.encode('utf-8')) > 32768:
                raise ValueError('Docker text bound')
        elif item is not None and type(item) not in (int, bool):
            raise ValueError('closed Docker JSON types required')
    visit(value, 0)
    if len(cs.canonical(value).encode('utf-8')) > 1048576:
        raise ValueError('Docker aggregate bound')


def _equal(actual, expected):
    return type(actual) is type(expected) and cs.canonical(actual) == cs.canonical(expected)


def _request(request):
    if type(request) is not cs.RuntimeDispatch or type(request.policy) not in (cs.SupervisedRuntimePolicy, cs.ContainedRuntimePolicy):
        raise ValueError('exact supervised dispatch required')
    cs.validate_record(request)
    ticket, policy, commit = request.ticket, request.policy, request.commit
    identity = cs.record_digest(['runtime', asdict(ticket.key), ticket.packet_digest])
    if (commit.action != 'create' or request.target is not None or commit.ticket_id != ticket.id or
            ticket.key != policy.key or ticket.launch_policy_digest != cs.record_digest(policy) or
            commit.supervisor_epoch != policy.clock_anchor.supervisor_epoch or
            ticket.deadline != policy.original_run_deadline or ticket.id != identity or
            ticket.name != 'rnr-' + identity or ticket.allocation != 'runtime-' + identity or
            ticket.labels != (('run', ticket.key.run), ('ticket', identity))):
        raise ValueError('Docker recipe dispatch correlation')
    if policy.quota.cpu_millis > (2**63-1) // 1000000:
        raise ValueError('Docker CPU range')
    return ticket, policy


def _environment(image, policy):
    _bounded(image)
    if (type(image) is not dict or image.get('Id') != 'sha256:' + policy.image_digest or
            image.get('Os') != 'linux' or image.get('Architecture') != 'amd64' or
            type(image.get('Config')) is not dict):
        raise ValueError('exact pinned Linux amd64 image required')
    config = image['Config']
    for key in ('Volumes', 'Healthcheck', 'OnBuild', 'ExposedPorts', 'Labels'):
        value = config.get(key)
        if value is not None and not (type(value) in (dict, list) and len(value) == 0):
            raise ValueError('image behavior refused')
    env = config.get('Env')
    if env is None: env = []
    if type(env) is not list or len(env) > 128:
        raise ValueError('bounded image environment required')
    names = set()
    for entry in env:
        if type(entry) is not str: raise ValueError('image environment entry')
        name = entry.split('=', 1)[0]
        if not _ENV_NAME.fullmatch(name) or name in names:
            raise ValueError('unique valid image environment names required')
        names.add(name)
    # API bare names remove inherited values, unlike CLI name-only expansion.
    return [name + '=C.UTF-8' if name == 'LANG' else name
            for name in sorted(names | {'HOME', 'HOSTNAME', 'LANG', 'PATH', 'TERM'})]


def create(request, image):
    ticket, policy = _request(request)
    environment = _environment(image, policy)
    anchor, quota = policy.clock_anchor, policy.quota
    host = dict(ReadonlyRootfs=True, NetworkMode='none', NanoCpus=quota.cpu_millis * 1000000,
        Memory=quota.memory_bytes, MemorySwap=quota.memory_bytes, PidsLimit=quota.pids,
        Privileged=False, AutoRemove=False, CapAdd=[], CapDrop=['ALL'], GroupAdd=[], Devices=[],
        SecurityOpt=['no-new-privileges'], RestartPolicy={'Name':'no', 'MaximumRetryCount':0},
        Init=False, PidMode='', UTSMode='', CgroupnsMode='private', IpcMode='none',
        Runtime='runc', ShmSize=0, LogConfig={'Type':'none', 'Config':{}},
        MaskedPaths=list(_MASKED), ReadonlyPaths=list(_READONLY),
        Tmpfs={'/scratch':f'rw,nosuid,nodev,noexec,size={quota.scratch_bytes},mode=1777',
               '/rnr/home':f'rw,nosuid,nodev,noexec,size={policy.home_bytes},mode=0700,uid={policy.uid},gid={policy.gid}'},
        Mounts=[dict(Type='bind', Source=item.source, Target=item.target, ReadOnly=True,
                     BindOptions=dict(Propagation='rprivate', NonRecursive=True, CreateMountpoint=False,
                                      ReadOnlyNonRecursive=False, ReadOnlyForceRecursive=False))
                for item in policy.files])
    if type(policy) is cs.ContainedRuntimePolicy:
        host['CgroupParent'] = policy.containment.parent
    body = dict(Image='sha256:' + policy.image_digest, User=f'{policy.uid}:{policy.gid}', Hostname='rnr-runtime',
        Domainname='', WorkingDir='/', Entrypoint=['/rnr/guardian'],
        Cmd=[anchor.boot_id, str(anchor.time_ns_device), str(anchor.time_ns_inode),
             str(anchor.captured_boottime_ns), str(anchor.deadline_boottime_ns), str(quota.output_bytes)],
        Env=environment, Labels=dict(ticket.labels), AttachStdin=True, AttachStdout=True,
        AttachStderr=True, Tty=False, OpenStdin=True, StdinOnce=True, StopSignal='SIGKILL',
        StopTimeout=0, Healthcheck={'Test':['NONE']}, HostConfig=host)
    encoded = cs.canonical(body).encode('utf-8')
    if len(encoded) > 65536: raise ValueError('Docker create body bound')
    return CreateRecipe(API + '/containers/create?name=' + ticket.name, encoded)


def _section(actual, expected, neutral, *, host=False):
    if type(actual) is not dict or not set(expected) <= set(actual) or set(actual) - set(expected) - set(neutral):
        raise ValueError('closed Docker inspection section required')
    for key, value in actual.items():
        wanted = expected[key] if key in expected else neutral[key]
        if _equal(value, wanted): continue
        # Docker may serialize empty slices as null. Only these non-authority
        # empty-array fields permit that normalization, never absent fields.
        if host and key in ('CapAdd', 'GroupAdd', 'Devices') and wanted == [] and value is None:
            continue
        # IPC=none creates no /dev/shm. Engine may retain its unused default
        # size in metadata; this is not permission for a private/shared shm mount.
        if host and key == 'ShmSize' and type(value) is int and value == 67108864 and actual['IpcMode'] == 'none':
            continue
        raise ValueError('Docker inspection field mismatch: ' + key)


def _verify_container(request, image, container_id, observed, *, running=False):
    import json
    recipe = create(request, image)
    cs.turn_hash(container_id)
    _bounded(observed)
    if type(observed) is not dict: raise ValueError('Docker inspection object required')
    body = json.loads(recipe.body)
    host = body.pop('HostConfig')
    expected_identity = dict(Id=container_id, Name='/' + request.ticket.name,
                             Image=body['Image'], Path='/rnr/guardian', Args=body['Cmd'], RestartCount=0)
    if any(key not in observed or not _equal(observed[key], val) for key,val in expected_identity.items()):
        raise ValueError('Docker instance identity mismatch')
    _section(observed.get('Config'), body, _NEUTRAL_CONFIG)
    _section(observed.get('HostConfig'), host, _NEUTRAL_HOST, host=True)
    if 'ExecIDs' not in observed or not (observed['ExecIDs'] is None or _equal(observed['ExecIDs'], [])):
        raise ValueError('no Docker exec instances allowed')
    network = observed.get('NetworkSettings')
    if (type(network) is not dict or type(network.get('Networks')) is not dict or
            set(network['Networks']) != {'none'}):
        raise ValueError('isolated Docker network required')
    endpoint = dict(IPAddress='', GlobalIPv6Address='', Gateway='', IPv6Gateway='', MacAddress='',
                    IPPrefixLen=0, GlobalIPv6PrefixLen=0, IPAMConfig=None, Links=None, Aliases=None,
                    DriverOpts=None, DNSNames=None, GwPriority=0, NetworkID='', EndpointID='')
    if not _equal(network['Networks']['none'], endpoint):
        raise ValueError('exact unconnected Docker none endpoint required')
    # API1.51 may include these deprecated root-level fields; only their exact
    # inactive values are compatible with the unconnected endpoint above.
    legacy = dict(Bridge='', HairpinMode=False, LinkLocalIPv6Address='', LinkLocalIPv6PrefixLen=0,
                  SecondaryIPAddresses=None, SecondaryIPv6Addresses=None, EndpointID='', Gateway='',
                  GlobalIPv6Address='', GlobalIPv6PrefixLen=0, IPAddress='', IPPrefixLen=0,
                  IPv6Gateway='', MacAddress='')
    expected_network = dict(Ports={}, SandboxID='', SandboxKey='', Networks={'none':endpoint})
    if running:
        # Opaque metadata only. Never resolve/open these strings or treat them
        # as network-namespace evidence; the retained process producer must do that.
        sandbox_id, sandbox_key = network.get('SandboxID'), network.get('SandboxKey')
        if type(sandbox_id) is not str or (sandbox_id and re.fullmatch('[0-9a-f]{64}',sandbox_id) is None):
            raise ValueError('bounded opaque sandbox ID required')
        if type(sandbox_key) is not str:
            raise ValueError('opaque sandbox path string required')
        if sandbox_key: cs.normalized_path(sandbox_key)
        expected_network.update(SandboxID=sandbox_id,SandboxKey=sandbox_key)
    _section(network, expected_network, legacy)
    mounts = observed.get('Mounts')
    if type(mounts) is not list or len(mounts) != len(request.policy.files):
        raise ValueError('exact seven Docker mounts required')
    expected = {item.target:item for item in request.policy.files}
    for mount in mounts:
        if type(mount) is not dict: raise ValueError('Docker mount required')
        item = expected.pop(mount.get('Destination'), None)
        if item is None: raise ValueError('duplicate or foreign Docker mount')
        required = dict(Type='bind', Source=item.source, Destination=item.target, RW=False, Propagation='rprivate')
        if (not set(required) <= set(mount) or set(mount) - set(required) - {'Mode', 'Name', 'Driver'} or
                any(not _equal(mount[key], value) for key,value in required.items()) or
                mount.get('Mode') not in ('', 'ro') or mount.get('Name', '') != '' or mount.get('Driver', '') != ''):
            raise ValueError('Docker mount mismatch')


def verify_created(request, image, container_id, observed):
    _verify_container(request,image,container_id,observed)
    state = dict(Status='created', Running=False, Paused=False, Restarting=False, OOMKilled=False,
                 Dead=False, Pid=0, ExitCode=0, Error='', StartedAt=_ZERO_TIME, FinishedAt=_ZERO_TIME)
    if not _equal(observed.get('State'),state):
        raise ValueError('never-started Docker allocation required')


def _running_started_at(value):
    # Metadata syntax only: no freshness, exec success or trusted process clock.
    from datetime import datetime
    if type(value) is not str:
        raise ValueError('running UTC timestamp required')
    match=re.fullmatch(r'([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?Z',value)
    if match is None: raise ValueError('running UTC timestamp required')
    parts=tuple(int(x) for x in match.groups()[:6])
    datetime(*parts)  # real calendar and00-59seconds, no leap-second normalization
    fraction=match.group(7)
    if parts==(1,1,1,0,0,0) and (fraction is None or not int(fraction)):
        raise ValueError('nonzero running timestamp required')


def verify_running(create_request, image, container_id, observed):
    """Validate metadata, returning a candidate PID only, never process authority.

    Later receiver integration must supply the original captured create dispatch
    and immutable image bytes. A live retained pidfd/postexec/isolation producer
    must independently establish identity before startup or delivery eligibility.
    """
    _verify_container(create_request,image,container_id,observed,running=True)
    state=observed.get('State')
    if type(state) is not dict: raise ValueError('exact running state required')
    pid=state.get('Pid')
    if type(pid) is not int or not 0<pid<=2147483647:
        raise ValueError('bounded candidate running PID required')
    started=state.get('StartedAt');_running_started_at(started)
    expected=dict(Status='running',Running=True,Paused=False,Restarting=False,OOMKilled=False,
        Dead=False,Pid=pid,ExitCode=0,Error='',StartedAt=started,FinishedAt=_ZERO_TIME)
    if not _equal(state,expected): raise ValueError('exact running state required')
    return pid
