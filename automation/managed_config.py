"""Inert, pinned inputs for runtime qualification; never runtime acceptance.

No provider credentials, runtime launch, Store admission or effective-config
claims live here. Physical qualification must bind these inputs to immutable
mounts, the actual process, and observed configuration layers separately.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat

CATALOG_SHA256 = 'a7bbc2218aec9d666a1ace35cf9ad07fe373abd727b2d26d36fdad27dbf957e1'
MAX_CATALOG_BYTES = 2 * 1024 * 1024
FEATURES = ('apps', 'code_mode', 'code_mode_only', 'enable_request_compression',
            'goals', 'hooks', 'image_generation', 'memories', 'multi_agent',
            'multi_agent_v2', 'plugins', 'shell_tool', 'unbounded_connection_retries',
            'unified_exec', 'view_image')
_PROVIDER = '''model_provider = "rnr_fixture"
model_catalog_json = "/rnr/catalog.json"
'''
_TABLES = '''[model_providers.rnr_fixture]
name = "RNR qualification fixture"
base_url = "http://127.0.0.1:18765/v1"
wire_api = "responses"
requires_openai_auth = false
request_max_retries = 0
stream_max_retries = 0
supports_websockets = false
[features]
''' + ''.join(f'{key} = false\n' for key in FEATURES)
_CONFIG = ('''approval_policy = "never"
approvals_reviewer = "user"
sandbox_mode = "danger-full-access"
model = "rnr-fixture"
web_search = "disabled"
notify = []
check_for_update_on_startup = false
''' + _PROVIDER + '[mcp_servers]\n' + _TABLES).encode()
_REQUIREMENTS = ('''allowed_approval_policies = ["never"]
allowed_approvals_reviewers = ["user"]
allowed_sandbox_modes = ["read-only", "danger-full-access"]
allowed_web_search_modes = ["disabled"]
allow_managed_hooks_only = true
allow_remote_control = false
allow_browser_and_computer_use = false
allow_appshots = false
allow_login_shell = false
check_for_update_on_startup = false
''' + _PROVIDER + _TABLES).encode()
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC


def _digest(data):
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class QualificationInputs:
    files: tuple[tuple[str, bytes], ...]

    def manifest(self):
        return {'kind': 'rnr-qualification-inputs-v1',
                'files': {name: {'sha256': _digest(data), 'bytes': len(data),
                                 'mode': '0444'} for name, data in self.files}}


# A receipt is a same-process successful-call result, not a signed artifact or
# runtime authority. It cannot be recovered from a manifest after a lost ACK.
_ISSUER = object()


@dataclass(frozen=True)
class _Publication:
    bundle: QualificationInputs
    identity: tuple[int, int]
    issuer: object
    pid: int


def build_qualification(catalog: bytes) -> QualificationInputs:
    if (type(catalog) is not bytes or len(catalog) > MAX_CATALOG_BYTES
            or _digest(catalog) != CATALOG_SHA256):
        raise ValueError('qualification catalog does not match bounded frozen pin')
    return QualificationInputs((('home/config.toml', _CONFIG),
                                ('system/config.toml', b''),
                                ('system/managed_config.toml', b''),
                                ('system/requirements.toml', _REQUIREMENTS),
                                ('catalog.json', catalog)))


def _validate(bundle):
    if type(bundle) is not QualificationInputs or type(bundle.files) is not tuple:
        raise ValueError('invalid qualification inputs')
    try:
        catalog = dict(bundle.files)['catalog.json']
        valid = bundle == build_qualification(catalog)
    except (KeyError, TypeError, ValueError):
        valid = False
    if not valid:
        raise ValueError('altered qualification inputs')


def _manifest_bytes(bundle):
    return (json.dumps(bundle.manifest(), sort_keys=True, separators=(',', ':')) + '\n').encode()


@contextmanager
def _directory(path):
    # Walk every ancestor with no-follow descriptors; never resolve through a
    # symlink and later reopen its textual path for mutation.
    path = Path(os.path.abspath(path))
    fd = os.open('/', _DIR_FLAGS)
    try:
        for part in path.parts[1:]:
            next_fd = os.open(part, _DIR_FLAGS, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        yield fd
    finally:
        os.close(fd)


def _check_mode(fd, mode, directory=False):
    info = os.fstat(fd)
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (not expected_type(info.st_mode) or stat.S_IMODE(info.st_mode) != mode
            or info.st_uid != os.geteuid() or (not directory and info.st_nlink != 1)):
        raise ValueError('unexpected input type, ownership, links or permissions')


def _read_exact(fd, name, expected, mode):
    try:
        file_fd = os.open(name, _FILE_FLAGS, dir_fd=fd)
    except OSError as exc:
        raise ValueError('unreadable qualification input') from exc
    try:
        _check_mode(file_fd, mode)
        if os.fstat(file_fd).st_size != len(expected):
            raise ValueError('input size changed')
        chunks = bytearray()
        while len(chunks) <= len(expected):
            chunk = os.read(file_fd, min(65536, len(expected) + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        if bytes(chunks) != expected:
            raise ValueError('input bytes changed')
    finally:
        os.close(file_fd)


def _verify_inputs(root_fd, bundle, published):
    _check_mode(root_fd, 0o700, True)
    names = {'home', 'system', 'catalog.json'}
    if published:
        names.add('manifest.json')
    if set(os.listdir(root_fd)) != names:
        raise ValueError('unexpected qualification root entries')
    _read_exact(root_fd, 'catalog.json', dict(bundle.files)['catalog.json'], 0o444)
    for directory, mode in (('home', 0o700), ('system', 0o555)):
        try:
            fd = os.open(directory, _DIR_FLAGS, dir_fd=root_fd)
        except OSError as exc:
            raise ValueError('invalid qualification directory') from exc
        try:
            _check_mode(fd, mode, True)
            entries = {name.split('/')[1]: data for name, data in bundle.files
                       if name.startswith(directory + '/')}
            if set(os.listdir(fd)) != set(entries):
                raise ValueError('unexpected qualification directory entries')
            for name, data in entries.items():
                _read_exact(fd, name, data, 0o444)
        finally:
            os.close(fd)
    if published:
        _read_exact(root_fd, 'manifest.json', _manifest_bytes(bundle), 0o600)


def _write(fd, name, data, mode):
    file_fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                      | os.O_CLOEXEC, 0o600, dir_fd=fd)
    try:
        remaining = memoryview(data)
        while remaining:
            count = os.write(file_fd, remaining)
            if count <= 0:
                raise OSError('short qualification write')
            remaining = remaining[count:]
        os.fchmod(file_fd, mode)
        os.fsync(file_fd)
    finally:
        os.close(file_fd)


def materialize(root: Path, bundle: QualificationInputs):
    """Return a receipt only after durable publication and readback succeed.

    Failure can leave byte-valid output when cleanup also fails. Such output has
    no receipt and cannot be accepted by verify or reused by materialize.
    """
    _validate(bundle)
    root = Path(os.path.abspath(root))
    with _directory(root.parent) as parent_fd:
        os.mkdir(root.name, 0o700, dir_fd=parent_fd)
        fd = os.open(root.name, _DIR_FLAGS, dir_fd=parent_fd)
        try:
            os.fchmod(fd, 0o700)
            for name in ('home', 'system'):
                os.mkdir(name, 0o700, dir_fd=fd)
            for directory, mode in (('home', 0o700), ('system', 0o555)):
                child = os.open(directory, _DIR_FLAGS, dir_fd=fd)
                try:
                    for name, data in bundle.files:
                        if name.startswith(directory + '/'):
                            _write(child, name.split('/')[1], data, 0o444)
                    os.fchmod(child, mode)
                    os.fsync(child)
                finally:
                    os.close(child)
            _write(fd, 'catalog.json', dict(bundle.files)['catalog.json'], 0o444)
            os.fsync(fd)
            _verify_inputs(fd, bundle, False)
            try:
                _write(fd, 'manifest.json', _manifest_bytes(bundle), 0o600)
                os.fsync(fd)
                os.fsync(parent_fd)
                _verify_inputs(fd, bundle, True)
                info = os.fstat(fd)
                published = _Publication(bundle, (info.st_dev, info.st_ino), _ISSUER, os.getpid())
            except BaseException:
                # Do not expose a completion marker after a failed publication.
                try:
                    os.unlink('manifest.json', dir_fd=fd)
                except FileNotFoundError:
                    pass
                raise
        finally:
            os.close(fd)
    return published


def verify(root: Path, published):
    """Verify an acknowledged publication; never recover acceptance from disk.

    Receipts are local API results, not an authentication boundary against code
    in this Python process. Restart/lost acknowledgement requires fresh output.
    """
    if (type(published) is not _Publication or published.issuer is not _ISSUER
            or published.pid != os.getpid()):
        raise ValueError('successful local publication receipt required')
    bundle = published.bundle
    _validate(bundle)
    try:
        with _directory(root) as fd:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != published.identity:
                raise ValueError('publication directory identity changed')
            _verify_inputs(fd, bundle, True)
    except OSError as exc:
        raise ValueError('invalid qualification path') from exc
    return bundle.manifest()
