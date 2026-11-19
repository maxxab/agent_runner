#!/usr/bin/env python3
"""Bounded, credential-free local Docker canary. Never enables runner execution."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid

CAP = 65536
HASH = re.compile(r'[0-9a-f]{64}\Z')


def validate_pin(value):
    if not value.startswith('sha256:') or not HASH.fullmatch(value[7:]):
        raise ValueError('a full immutable sha256 image ID is required')


def strict_json(value):
    if len(value.encode()) > CAP:
        raise ValueError('JSON exceeds receipt limit')
    def pairs(items):
        result = {}
        for key, val in items:
            if key in result:
                raise ValueError('duplicate JSON field')
            result[key] = val
        return result
    def invalid(value):
        raise ValueError('nonfinite JSON number')
    return json.loads(value, object_pairs_hook=pairs, parse_constant=invalid)


def validate_evidence_location(path):
    repository = Path(__file__).resolve().parents[1]
    if not path.is_absolute() or path.resolve().is_relative_to(repository):
        raise ValueError('evidence must be outside the source checkout')


def make_private(path):
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise ValueError('evidence must be a fresh absolute directory')
    path.mkdir(mode=0o700)


def write_json(path, value):
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, indent=2, allow_nan=False)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def digest(path):
    with open(path, 'rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


class Commands:
    """Drain both pipes with fixed memory and wall-clock bounds; no shell."""
    def __init__(self, executable, socket, evidence, deadline):
        self.prefix = [executable, '--host', 'unix://' + socket,
                       '--config', str(evidence / 'docker-config')]
        self.env = {'PATH': '/usr/bin:/bin', 'HOME': str(evidence / 'empty-home'),
                    'DOCKER_CONFIG': str(evidence / 'docker-config'), 'LANG': 'C.UTF-8'}
        self.evidence = evidence
        self.deadline = deadline

    def __call__(self, args, timeout=4):
        command = self.prefix + args
        end = min(time.monotonic() + timeout, self.deadline)
        receipt = {'argv': command, 'returncode': None, 'stdout': '', 'stderr': '',
                   'uncertain': False}
        buffers = {'stdout': bytearray(), 'stderr': bytearray()}
        process = None
        try:
            if time.monotonic() >= end:
                raise TimeoutError('original deadline exhausted')
            process = subprocess.Popen(command, env=self.env, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=True)
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
                selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
                while selector.get_map():
                    remaining = end - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('bounded subprocess timeout')
                    for key, _ in selector.select(min(0.1, remaining)):
                        chunk = os.read(key.fileobj.fileno(), 8192)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        target = buffers[key.data]
                        room = CAP - len(target)
                        target.extend(chunk[:room])
                        if len(chunk) > room:
                            raise ValueError('bounded output exceeded')
            receipt['returncode'] = process.wait(timeout=max(0.001, end - time.monotonic()))
        except (OSError, ValueError, TimeoutError, subprocess.TimeoutExpired) as error:
            receipt['uncertain'] = True
            receipt['error'] = str(error)
        finally:
            if process is not None:
                if receipt['uncertain'] or process.poll() is None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=1)
                process.stdout.close()
                process.stderr.close()
            for key, value in buffers.items():
                try:
                    receipt[key] = value.decode('utf-8', errors='strict')
                except UnicodeDecodeError:
                    receipt['uncertain'] = True
                    receipt['error'] = 'invalid UTF-8 supervisor output'
                    receipt[key + '_raw_hex'] = value.hex()
                    # Display is bounded; original captured bytes are retained above.
                    receipt[key] = value.decode('utf-8', errors='ignore')
            write_json(self.evidence / ('command-' + uuid.uuid4().hex + '.json'), receipt)
        return receipt


def checked(call, args, timeout=None):
    result = call(args) if timeout is None else call(args, timeout=timeout)
    if result['uncertain'] or result['returncode'] != 0:
        raise ValueError('supervisor command failed or unconfirmed: ' + args[0])
    return result['stdout']


def initial_state(root, image, executable, socket, duration):
    start = time.time()
    monotonic_start = time.monotonic()
    run_id = uuid.uuid4().hex
    return {'schema_version': 1, 'run_id': run_id, 'image': image,
            'docker': executable, 'socket': socket, 'root': str(root),
            'start_epoch': start, 'deadline_epoch': start + duration,
            'cleanup_epoch': start + duration - 30,
            'start_monotonic': monotonic_start,
            'deadline_monotonic': monotonic_start + duration,
            'cleanup_monotonic': monotonic_start + duration - 30,
            'original_start_utc': datetime.fromtimestamp(start, timezone.utc).isoformat(),
            'original_deadline_utc': datetime.fromtimestamp(start + duration, timezone.utc).isoformat(),
            'execution_enabled': False, 'runtime_mode_accepted': False,
            'source_sha256': digest(Path(__file__)), 'docker_sha256': digest(Path(executable))
            if Path(executable).is_file() else None,
            'requested_policy': {'uid':65534, 'gid':65534, 'cpus':0.5, 'memory_bytes':134217728,
                                 'memory_swap_bytes':134217728, 'pids':32, 'scratch_bytes':16777216,
                                 'readonly_root':True, 'network':'none', 'capabilities':[],
                                 'no_new_privileges':True, 'restart':'no'},
            'cleanup_started': False, 'roles': {}, 'process_tree': 'BLOCKED',
            'allocations': {role: {'name': 'rnr-d00-' + run_id + '-' + role,
                'labels': {'rnr.d00.run': run_id, 'rnr.d00.role': role,
                           'rnr.d00.owner': 'local-operator-canary-v1'},
                'id': None, 'created': False, 'uncertain': [], 'cleanup': 'NOT RUN'}
                for role in ['owner', 'reviewer']}}


def ensure_watchdog(state, watch):
    if watch.poll() is not None:
        state['watchdog_lost'] = True
        raise ValueError('independent watchdog exited before completion handshake')


def ensure_admission(state, now=None):
    if (state['cleanup_started'] or (Path(state['root']) / 'cleanup-started.json').exists()
            or (time.monotonic() if now is None else now) >= state['cleanup_monotonic']):
        raise ValueError('original cleanup fence reached')


# The script only sees synthetic paths. It never discovers host configuration.
PROBE = r'''
import json, os, pathlib, subprocess, sys, time
role, marker = sys.argv[1:]
def denied(path):
    try:
        with open(path, 'w') as f: f.write('forbidden')
    except OSError: return True
    return False
limits = {name: pathlib.Path('/sys/fs/cgroup/' + name).read_text().strip()
          for name in ['cpu.max', 'memory.max', 'memory.swap.max', 'pids.max']}
assert limits == {'cpu.max':'50000 100000', 'memory.max':'134217728',
                  'memory.swap.max':'0', 'pids.max':'32'}, limits
assert os.getuid() != 0
status = dict(line.split(':', 1) for line in pathlib.Path('/proc/self/status').read_text().splitlines())
assert status['NoNewPrivs'].strip() == '1'
assert int(status['CapEff'].strip(), 16) == 0
assert all(line.split()[0] == 'lo' for line in pathlib.Path('/proc/net/route').read_text().splitlines()[1:])
assert {p.name for p in pathlib.Path('/sys/class/net').iterdir()} <= {'lo'}
assert denied('/root-write') and denied('/git/forbidden')
for path in ['/var/run/docker.sock','/root/.codex','/controller','/otherallocation']:
    assert not os.path.exists(path), path
if role == 'owner':
    pathlib.Path('/assigned/result').write_text('owner')
else:
    assert pathlib.Path('/assigned/result').read_text() == 'owner'
    assert denied('/assigned/reviewer-write')
scratch = os.statvfs('/scratch')
assert scratch.f_blocks * scratch.f_frsize == 16777216
pathlib.Path('/scratch/test').write_text('scratch')
child = subprocess.Popen([sys.executable, '-c',
    'import subprocess,sys,time; p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(110)"]); print(p.pid,flush=True); time.sleep(110)'],
    stdout=subprocess.PIPE, text=True)
grandchild = int(child.stdout.readline())
print(json.dumps({'role':role,'marker':marker,'limits':limits,'scratch_bytes':16777216,
                  'namespace_pids':[os.getpid(),child.pid,grandchild],'assertions':'PASS'}),flush=True)
time.sleep(110)
'''


def create_args(state, role):
    item = state['allocations'][role]
    work = Path(state['root']) / 'work'
    args = ['container', 'create', '--pull=never', '--name', item['name'],
            '--user=65534:65534', '--read-only', '--cap-drop=ALL',
            '--security-opt=no-new-privileges', '--network=none', '--restart=no',
            '--cpus=0.5', '--memory=134217728', '--memory-swap=134217728',
            '--pids-limit=32', '--tmpfs=/scratch:rw,nosuid,nodev,noexec,size=16777216,mode=1777',
            '--mount', 'type=bind,src=' + str(work / 'assigned') + ',dst=/assigned' +
            (',readonly' if role == 'reviewer' else ''),
            '--mount', 'type=bind,src=' + str(work / 'git') + ',dst=/git,readonly',
            '--entrypoint=python3']
    for key, value in item['labels'].items():
        args.extend(['--label', key + '=' + value])
    return args + [state['image'], '-u', '-c', PROBE, role, state['run_id']]


def check_identity(item, obj):
    if (not isinstance(obj, dict) or not isinstance(obj.get('Id'), str)
            or not HASH.fullmatch(obj['Id']) or obj.get('Name') != '/' + item['name']
            or not isinstance(obj.get('Config'), dict)
            or obj['Config'].get('Labels') != item['labels']
            or (item['id'] is not None and obj['Id'] != item['id'])):
        raise ValueError('owned immutable identity mismatch')


def info_args():
    template = '{' + ','.join('"' + key + '":{{json .' + key + '}}'
                              for key in ['CgroupVersion', 'CgroupDriver', 'OSType']) + '}'
    return ['info', '--format', template]


def inspect_args(identity):
    host_keys = ['ReadonlyRootfs', 'NetworkMode', 'NanoCpus', 'Memory', 'MemorySwap',
                 'PidsLimit', 'Privileged', 'AutoRemove', 'RestartPolicy', 'CapDrop',
                 'CapAdd', 'SecurityOpt', 'Devices', 'DeviceRequests', 'PidMode', 'IpcMode', 'Tmpfs']
    host = '{' + ','.join('"' + k + '":{{json .HostConfig.' + k + '}}' for k in host_keys) + '}'
    template = '[{"Id":{{json .Id}},"Name":{{json .Name}},"Image":{{json .Image}},' + \
               '"Config":{"User":{{json .Config.User}},"Labels":{{json .Config.Labels}}},' + \
               '"State":{{json .State}},"Mounts":{{json .Mounts}},"HostConfig":' + host + '}]'
    return ['container', 'inspect', '--format', template, identity]


def inspect_one(item, call):
    objects = strict_json(checked(call, inspect_args(item['id'] or item['name'])))
    if not isinstance(objects, list) or len(objects) != 1:
        raise ValueError('expected exactly one container')
    check_identity(item, objects[0])
    return objects[0]


def verify_policy(state, role, obj):
    host, config = obj['HostConfig'], obj['Config']
    expected = {'ReadonlyRootfs': True, 'NetworkMode': 'none', 'NanoCpus': 500000000,
                'Memory': 134217728, 'MemorySwap': 134217728, 'PidsLimit': 32,
                'Privileged': False, 'AutoRemove': False}
    if any(host.get(k) != v for k, v in expected.items()):
        raise ValueError('container policy differs from request')
    if (obj['Image'] != state['image'] or config['User'] != '65534:65534'
            or host['RestartPolicy']['Name'] != 'no' or host['CapDrop'] != ['ALL']
            or 'no-new-privileges' not in host['SecurityOpt']
            or host.get('CapAdd') or host.get('Devices') or host.get('DeviceRequests')
            or host.get('PidMode') or host.get('IpcMode') not in ['private', '']):
        raise ValueError('unsafe container configuration')
    mounts = obj['Mounts']
    expected_mounts = {'/assigned': (str(Path(state['root']) / 'work/assigned'), role == 'owner'),
                       '/git': (str(Path(state['root']) / 'work/git'), False)}
    if len(mounts) != 2:
        raise ValueError('unexpected mount count')
    observed = {m['Destination']: (m['Source'], m['RW']) for m in mounts if m['Type'] == 'bind'}
    if observed != expected_mounts or list(host.get('Tmpfs', {})) != ['/scratch']:
        raise ValueError('unexpected mounts')


def mutation(item, call, verb, args, state=None):
    item['uncertain'].append(verb)
    if state is not None:
        write_json(Path(state['root']) / state.get('_journal_name', 'state.json'), state)
    result = call(args)
    if result['uncertain'] or result['returncode'] != 0:
        raise ValueError('unconfirmed ' + verb)
    item['uncertain'].remove(verb)
    return result['stdout']


def cleanup_one(state, role, call):
    item = state['allocations'][role]
    if item['cleanup'] == 'PASS' and not item['uncertain']:
        return
    if not item['created'] and not item['uncertain']:
        item['cleanup'] = 'PASS'
        return
    try:
        obj = inspect_one(item, call)
        item['id'] = obj['Id']
        if obj['State']['Running']:
            mutation(item, call, 'kill', ['container', 'kill', '--signal=KILL', item['id']], state)
            obj = inspect_one(item, call)
        terminal = obj['State']
        if (terminal.get('Running') is not False or terminal.get('Pid') != 0
                or terminal.get('Status') not in ['exited', 'created'] or terminal.get('Dead') is not False):
            raise ValueError('terminal container state unconfirmed')
        item['terminal'] = terminal
        # Reinspect exact identity immediately before deletion.
        inspect_one(item, call)
        mutation(item, call, 'remove', ['container', 'rm', item['id']], state)
        remaining = checked(call, ['container', 'ls', '--all', '--quiet', '--no-trunc',
                                  '--filter', 'id=' + item['id']])
        if remaining.strip():
            raise ValueError('deletion not observed')
        item['cleanup'] = 'PASS'
    except (ValueError, KeyError, TypeError, AttributeError) as error:
        item['cleanup'] = 'UNKNOWN'
        item['cleanup_error'] = str(error)


def result_status(state):
    if state.get('watchdog_lost'):
        return 'UNKNOWN'
    if any(a['uncertain'] or a['cleanup'] == 'UNKNOWN' for a in state['allocations'].values()):
        return 'UNKNOWN'
    if state.get('error'):
        return 'FAIL'
    if state['process_tree'] != 'PASS':
        return 'BLOCKED'
    if (state['roles'] == {'owner': 'PASS', 'reviewer': 'PASS'}
            and all(a['cleanup'] == 'PASS' for a in state['allocations'].values())):
        return 'PASS'
    return 'FAIL'


@contextmanager
def locked(root, deadline):
    fd = os.open(root / 'control.lock', os.O_RDWR | os.O_CREAT, 0o600)
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise TimeoutError('control lock unavailable before original deadline')
                time.sleep(0.05)
        yield
    finally:
        os.close(fd)


def process_identity(pid):
    """Read only the explicitly observed synthetic process, never general process data."""
    base = Path('/proc') / str(pid)
    raw = (base / 'stat').read_text()
    fields = raw[raw.rfind(')') + 2:].split()
    status = (base / 'status').read_text()
    ns = next(line for line in status.splitlines() if line.startswith('NSpid:'))
    return {'pid': pid, 'start_ticks': fields[19], 'namespace_pid': int(ns.split()[-1]),
            'state': fields[0]}


def observe_tree(item, obj, probe, call, marker):
    rows = checked(call, ['container', 'top', item['id'], '-eo', 'pid,ppid']).splitlines()
    pids = [int(row.split()[0]) for row in rows[1:] if row.strip()]
    identities = [process_identity(pid) for pid in pids]
    init = obj['State']['Pid']
    # Matching init marker and namespace IDs establish a shared host /proc view.
    command = (Path('/proc') / str(init) / 'cmdline').read_bytes()
    if marker.encode() not in command or init not in pids:
        raise ValueError('daemon and client process view not established')
    chosen = [p for p in identities if p['namespace_pid'] in probe['namespace_pids']]
    if {p['namespace_pid'] for p in chosen} != set(probe['namespace_pids']) or len(chosen) != 3:
        raise ValueError('synthetic process tree identities not established')
    return chosen


def tree_exited(identities):
    for old in identities:
        try:
            current = process_identity(old['pid'])
        except FileNotFoundError:
            continue
        if current['start_ticks'] == old['start_ticks']:
            return False
    return True


def watchdog(root):
    state = strict_json((root / 'state.json').read_text())
    write_json(root / 'watchdog-ready.json', {'pid': os.getpid(), 'session': os.getsid(0)})
    while time.monotonic() < state['cleanup_monotonic']:
        if (root / 'finished.json').exists():
            write_json(root / 'watchdog-finished.json', {'pid':os.getpid(), 'finished_observed':True})
            return 0
        try:
            os.kill(state['parent_pid'], 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    write_json(root / 'cleanup-started.json', {'watchdog_pid':os.getpid(),
                                              'deadline_epoch':state['deadline_epoch']})
    def assist():
        latest = strict_json((root / 'state.json').read_text())
        latest['cleanup_started'] = True
        latest['_journal_name'] = 'watchdog-state.json'
        latest['status'] = 'UNKNOWN'  # Intervention never credits a completed experiment.
        write_json(root / 'watchdog-state.json', latest)
        call = Commands(latest['docker'], latest['socket'], root, latest['deadline_monotonic'])
        for role in ['owner', 'reviewer']:
            cleanup_one(latest, role, call)
            write_json(root / 'watchdog-state.json', latest)
        write_json(root / 'watchdog-result.json', latest)
    try:
        try:
            with locked(root, min(time.monotonic() + 5, state['deadline_monotonic'] - 20)):
                assist()
        except TimeoutError:
            # Fence is independent of the main lock. Calls in flight remain UNKNOWN.
            assist()
    except (OSError, ValueError, TimeoutError) as error:
        write_json(root / 'watchdog-result.json', {'status': 'UNKNOWN', 'error': str(error)})
    return 0


def run(args):
    validate_pin(args.image)
    socket = Path(args.socket)
    if not socket.is_absolute() or not stat.S_ISSOCK(socket.stat().st_mode):
        raise ValueError('explicit local Unix Docker socket required')
    root = Path(args.evidence_dir)
    validate_evidence_location(root)
    make_private(root)
    executable = shutil.which('docker', path='/usr/bin:/bin:/usr/local/bin')
    if executable is None:
        raise ValueError('Docker executable unavailable')
    executable = str(Path(executable).resolve(strict=True))
    state = initial_state(root, args.image, executable, str(socket), 120)
    state['parent_pid'] = os.getpid()
    for name in ['docker-config', 'empty-home', 'work', 'private']:
        (root / name).mkdir(mode=0o700)
    for name in ['assigned', 'git']:
        path = root / 'work' / name
        path.mkdir(mode=0o755)
        if os.getuid() == 0:
            os.chown(path, 65534, 65534)
        elif name == 'assigned':
            path.chmod(0o777)
    (root / 'private/controller').write_text('synthetic-private-controller')
    (root / 'private/otherallocation').write_text('synthetic-other-allocation')
    for path in (root / 'private').iterdir():
        path.chmod(0o600)
    write_json(root / 'state.json', state)
    watch = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--watchdog', str(root)],
                             env={'PATH':'/usr/bin:/bin', 'LANG':'C.UTF-8'},
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, start_new_session=True)
    call = Commands(executable, str(socket), root, state['deadline_monotonic'])
    try:
        ready_end = time.monotonic() + 3
        while not (root / 'watchdog-ready.json').exists():
            if time.monotonic() >= ready_end or watch.poll() is not None:
                raise ValueError('independent watchdog unavailable')
            time.sleep(0.05)
        ready = strict_json((root / 'watchdog-ready.json').read_text())
        if ready != {'pid':watch.pid, 'session':watch.pid}:
            raise ValueError('independent watchdog session not confirmed')
        with locked(root, state['cleanup_monotonic']):
            state['daemon_version'] = strict_json(checked(call, ['version', '--format', '{{json .Server}}']))
            info = strict_json(checked(call, info_args()))
            state['daemon_cgroup'] = {k:info.get(k) for k in ['CgroupVersion','CgroupDriver','OSType']}
            if info.get('CgroupVersion') != '2' or info.get('OSType') != 'linux':
                raise ValueError('Linux cgroup-v2 daemon required')
            images = strict_json(checked(call, ['image', 'inspect', '--format', '[{{json .Id}}]', state['image']]))
            if not isinstance(images, list) or len(images) != 1 or images[0] != args.image:
                raise ValueError('immutable image identity not confirmed')
            state['image_observed'] = {'Id':images[0]}
            for role in ['owner', 'reviewer']:
                ensure_watchdog(state, watch)
                ensure_admission(state)
                item = state['allocations'][role]
                item['uncertain'].append('create')
                write_json(root / 'state.json', state)  # identity and intent precede effect
                ensure_watchdog(state, watch)
                ensure_admission(state)
                output = checked(call, create_args(state, role), timeout=10).strip()
                if not HASH.fullmatch(output):
                    raise ValueError('malformed create acknowledgement')
                item['id'], item['created'] = output, True
                item['uncertain'].remove('create')
                write_json(root / 'state.json', state)
                obj = inspect_one(item, call)
                verify_policy(state, role, obj)
                item['observed_policy'] = obj
                ensure_watchdog(state, watch)
                ensure_admission(state)
                item['uncertain'].append('start')
                write_json(root / 'state.json', state)
                ensure_watchdog(state, watch)
                ensure_admission(state)
                checked(call, ['container','start',item['id']])
                item['uncertain'].remove('start')
                write_json(root / 'state.json', state)
                while True:
                    ensure_watchdog(state, watch)
                    ensure_admission(state)
                    logs = checked(call, ['container','logs',item['id']]).strip()
                    if logs:
                        probe = strict_json(logs)
                        break
                    time.sleep(0.1)
                if (not isinstance(probe, dict) or probe.get('assertions') != 'PASS'
                        or probe.get('marker') != state['run_id'] or probe.get('role') != role):
                    raise ValueError('malformed role probe')
                item['probe'] = probe
                state['roles'][role] = 'PASS'
                obj = inspect_one(item, call)
                identities = None
                try:
                    identities = observe_tree(item, obj, probe, call, state['run_id'])
                    item['host_processes'] = identities
                except (OSError, ValueError, KeyError, StopIteration) as error:
                    item['process_observation_error'] = str(error)
                ensure_watchdog(state, watch)
                mutation(item, call, 'kill', ['container','kill','--signal=KILL',item['id']], state)
                obj = inspect_one(item, call)
                if identities is not None:
                    end = min(time.monotonic() + 2, state['cleanup_monotonic'])
                    while not tree_exited(identities) and time.monotonic() < end:
                        time.sleep(0.05)
                    item['process_tree'] = 'PASS' if tree_exited(identities) else 'UNKNOWN'
                else:
                    item['process_tree'] = 'BLOCKED'
                cleanup_one(state, role, call)
                write_json(root / 'state.json', state)
                if item['cleanup'] != 'PASS' or item['uncertain']:
                    raise ValueError('previous allocation cleanup unresolved')
            if all(a.get('process_tree') == 'PASS' for a in state['allocations'].values()):
                state['process_tree'] = 'PASS'
    except (OSError, ValueError, KeyError, TypeError, AttributeError, TimeoutError) as error:
        state['error'] = str(error)
    finally:
        try:
            with locked(root, state['deadline_monotonic'] - 20):
                state['cleanup_started'] = True
                write_json(root / 'state.json', state)
                for role in ['owner', 'reviewer']:
                    cleanup_one(state, role, call)
                write_json(root / 'state.json', state)
        except (OSError, ValueError, TimeoutError) as error:
            state['error'] = 'cleanup unavailable: ' + str(error)
            state['cleanup_unconfirmed'] = True
        if watch.poll() is not None:
            state['watchdog_lost'] = True
        state['status'] = ('UNKNOWN' if state.get('cleanup_unconfirmed')
                           or (root / 'cleanup-started.json').exists() else result_status(state))
        write_json(root / 'finished.json', {'status':state['status']})
        try:
            watch.wait(timeout=min(20, max(0.01, state['deadline_monotonic'] - time.monotonic())))
            state['watchdog_exit_code'] = watch.returncode
            acknowledgement = strict_json((root / 'watchdog-finished.json').read_text())
            if acknowledgement != {'pid':watch.pid, 'finished_observed':True}:
                raise ValueError('watchdog completion acknowledgement missing or invalid')
            if watch.returncode != 0:
                state['status'] = 'UNKNOWN'
                state['watchdog_lost'] = True
            if (root / 'cleanup-started.json').exists():
                state['status'] = 'UNKNOWN'
                state['watchdog_intervened'] = True
                write_json(root / 'report.json', state)
        except (subprocess.TimeoutExpired, OSError, ValueError):
            state['status'] = 'UNKNOWN'
            state['watchdog_exit_unconfirmed'] = True
            write_json(root / 'report.json', state)
        write_json(root / 'report.json', state)
    print(json.dumps({'status':state['status'], 'evidence_dir':str(root),
                      'execution_enabled':False, 'runtime_mode_accepted':False}))
    return 0 if state['status'] == 'PASS' else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image')
    parser.add_argument('--socket')
    parser.add_argument('--evidence-dir')
    parser.add_argument('--watchdog', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.watchdog:
        return watchdog(Path(args.watchdog))
    if not all([args.image, args.socket, args.evidence_dir]):
        parser.error('--image, --socket and --evidence-dir are required')
    try:
        return run(args)
    except (OSError, ValueError) as error:
        print(json.dumps({'status':'BLOCKED','error':str(error),
                          'execution_enabled':False,'runtime_mode_accepted':False}))
        return 1


if __name__ == '__main__':
    sys.exit(main())
