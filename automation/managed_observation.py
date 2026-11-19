"""Validate three pinned startup API views without granting runtime authority.

The caller must separately bind the channel, process and immutable mounts.
These API views omit packaged defaults and do not cover per-thread overrides.
Only fixed results and hashes leave this module; response text is never echoed.
"""
import hashlib
import json
import tomllib
from . import managed_config as mc

_REQUESTS = (
    (2, 'config/read', {'includeLayers': True, 'cwd': '/'}),
    (3, 'configRequirements/read', {}),
    (4, 'experimentalFeature/list', {'limit': 256}),
)
_PROVIDER_NULLS = (
    'auth', 'aws', 'capabilities', 'credential_file', 'env_http_headers', 'env_key',
    'env_key_instructions', 'experimental_bearer_token', 'gateway_oauth',
    'http_headers', 'location', 'model_catalog_url', 'project_id', 'query_params',
    'request_max_retries', 'stream_idle_timeout_ms', 'stream_max_retries',
    'websocket_connect_timeout_ms',
)


def requests():
    """Fresh fixed read-only requests; never a thread, turn or provider request."""
    return [{'id': ident, 'method': method, 'params': dict(params)}
            for ident, method, params in _REQUESTS]


def _encode(value):
    try:
        raw = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValueError('invalid bounded API view') from exc
    if len(raw) > 65536:
        raise ValueError('API view exceeds fixed bound')
    return raw


def _same(actual, expected):
    # JSON encoding keeps false distinct from integer zero and null from absent.
    if _encode(actual) != _encode(expected):
        raise ValueError('startup control mismatch')


def _fields(value, required, optional=()):
    if type(value) is not dict or not set(required) <= value.keys() or value.keys() - set(required) - set(optional):
        raise ValueError('unexpected API view fields')


def _layers(rows, ordinary, user_config_path):
    if type(rows) is not list or len(rows) != 3:
        raise ValueError('missing or excessive configuration layers')
    allowed = {
        'system': (0, '/etc/codex/config.toml', {}),
        'user': (1, user_config_path, ordinary),
        'legacyManagedConfigTomlFromFile': (3, '/etc/codex/managed_config.toml', {}),
    }
    previous = 4; seen = set()
    for row in rows:
        _fields(row, ('name', 'version', 'config'), ('disabledReason',))
        name = row['name']
        if type(name) is not dict or name.get('type') not in allowed:
            raise ValueError('unapproved configuration layer')
        kind = name['type']; order, path, expected = allowed[kind]
        if kind in seen or order >= previous or row.get('disabledReason') is not None:
            raise ValueError('duplicate, disabled or reordered layer')
        seen.add(kind); previous = order
        wanted = {'type': kind}
        if path is not None: wanted['file'] = path
        if kind == 'user' and 'profile' in name: wanted['profile'] = None
        _same(name, wanted)
        if type(row['version']) is not str or not 1 <= len(row['version']) <= 128:
            raise ValueError('missing bounded layer version')
        _same(row['config'], expected)
    if seen != set(allowed):
        raise ValueError('fixed configuration layer set incomplete')


def observe(bundle, config, requirements, features):
    """Check response bodies. Success is only the named startup observations."""
    return _observe(bundle, config, requirements, features, '/home/runtime/config.toml')


def observe_contained(bundle, policy, config, requirements, features):
    """Pure contained manifest/view correlation; no stream/process authority."""
    from . import control_store as cs
    if type(policy) is not cs.ContainedRuntimePolicy:
        raise ValueError('exact contained policy required')
    cs.validate_record(policy)
    mc._validate(bundle)
    if cs.runtime_config_manifest_digest(policy) != hashlib.sha256(mc._manifest_bytes(bundle)).hexdigest():
        raise ValueError('contained policy configuration manifest differs')
    return _observe(bundle, config, requirements, features, '/rnr/home/config.toml')


def _observe(bundle, config, requirements, features, user_config_path):
    mc._validate(bundle)
    encoded = [_encode(value) for value in (config, requirements, features)]
    ordinary = tomllib.loads(dict(bundle.files)['home/config.toml'].decode())
    policy = tomllib.loads(dict(bundle.files)['system/requirements.toml'].decode())
    provider = dict(ordinary['model_providers']['rnr_fixture'])
    provider.update({key: None for key in _PROVIDER_NULLS})
    provider.update(supports_websockets=False, supports_standalone_web_search=False)
    providers = {'rnr_fixture': provider}
    _fields(config, ('config', 'origins', 'layers'))
    if type(config['config']) is not dict or type(config['origins']) is not dict:
        raise ValueError('invalid configuration view')
    actual = config['config']
    for key in ('approval_policy', 'approvals_reviewer', 'sandbox_mode', 'model',
                'model_provider', 'model_catalog_json', 'web_search', 'notify',
                'mcp_servers', 'check_for_update_on_startup', 'features'):
        if key not in actual: raise ValueError('missing startup control')
        _same(actual[key], _effective_features(ordinary[key]) if key == 'features' else ordinary[key])
    _same(actual.get('model_providers'), providers)
    if actual.get('allow_login_shell') is not False or actual.get('hooks') not in (None, {}):
        raise ValueError('login shell or hooks differ')
    _layers(config['layers'], ordinary, user_config_path)

    _fields(requirements, ('requirements',), ('supportsIndependentSpeedModes',))
    if ('supportsIndependentSpeedModes' in requirements
            and requirements['supportsIndependentSpeedModes'] is not True):
        raise ValueError('unexpected requirements capability')
    required = requirements['requirements']
    if type(required) is not dict: raise ValueError('managed requirements absent')
    keys = {
        'allowed_approval_policies': 'allowedApprovalPolicies',
        'allowed_approvals_reviewers': 'allowedApprovalsReviewers',
        'allowed_sandbox_modes': 'allowedSandboxModes',
        'allowed_web_search_modes': 'allowedWebSearchModes',
        'allow_managed_hooks_only': 'allowManagedHooksOnly',
        'allow_remote_control': 'allowRemoteControl',
        'allow_browser_and_computer_use': 'allowBrowserAndComputerUse',
        'allow_appshots': 'allowAppshots', 'allow_login_shell': 'allowLoginShell',
        'check_for_update_on_startup': 'checkForUpdateOnStartup',
        'model_provider': 'modelProvider', 'model_catalog_json': 'modelCatalogJson',
        'features': 'featureRequirements',
    }
    for source, destination in keys.items():
        if destination not in required: raise ValueError('managed control absent')
        _same(required[destination], _MANAGED_CATALOG_URI if source == 'model_catalog_json' else policy[source])
    _same(required.get('modelProviders'), providers)
    for key, value in required.items():
        if key in keys.values() or key == 'modelProviders': continue
        if key == 'allowedLoginMethods': _same(value, ['api', 'chatgpt'])
        elif value is not None: raise ValueError('unexpected active managed requirement')

    _fields(features, ('data',), ('nextCursor',))
    rows = features['data']
    if features.get('nextCursor') is not None or type(rows) is not list or not 1 <= len(rows) <= 256:
        raise ValueError('incomplete or excessive normalized feature view')
    seen = set()
    for row in rows:
        _fields(row, ('name', 'enabled', 'defaultEnabled', 'stage'),
                ('displayName', 'description', 'announcement'))
        name = row['name']
        if (type(name) is not str or not 1 <= len(name) <= 128 or name in seen
                or type(row['enabled']) is not bool or type(row['defaultEnabled']) is not bool
                or row['stage'] not in ('beta', 'underDevelopment', 'stable', 'deprecated', 'removed')):
            raise ValueError('invalid normalized feature')
        seen.add(name)
        if name in mc.FEATURES and (row['enabled'] is not False or row['stage'] == 'removed'):
            raise ValueError('managed feature ignored or enabled')
        if name in _API_FEATURES:
            enabled, stage = _API_FEATURES[name]
            if row['enabled'] is not enabled or row['defaultEnabled'] is not enabled or row['stage'] != stage:
                raise ValueError('startup control mismatch')
    if not (set(mc.FEATURES) | _API_FEATURES.keys()) <= seen:
        raise ValueError('managed feature missing from normalized view')
    digests = [hashlib.sha256(raw).hexdigest() for raw in encoded]
    return {'kind': 'rnr-managed-startup-views-v1', 'config_view_digest': digests[0],
            'requirements_view_digest': digests[1], 'features_view_digest': digests[2],
            'layers_digest': hashlib.sha256(_encode(config['layers'])).hexdigest(),
            'managed_features_disabled': len(mc.FEATURES), 'runtime_accepted': False}


# Pinned rust-v0.167.0 ConfigRequestProcessor::read overlays these normalized
# feature values even when absent from TOML. memories is already in mc.FEATURES.
# These are observed defaults, not managed-disabled controls or mode acceptance.
_API_FEATURES = {
    'api_key_cyber_access_programs': (True, 'stable'),
    'api_key_model_discovery': (True, 'stable'),
    'auth_elicitation': (True, 'stable'),
    'background_paginated_rollout_migration': (False, 'underDevelopment'),
    'codex_apps_mcp_2026_07_28': (False, 'underDevelopment'),
    'mcp_2026_07_28': (False, 'underDevelopment'),
    'mcp_connection_sharing': (False, 'underDevelopment'),
    'mentions_v2': (True, 'stable'),
    'remote_control': (False, 'removed'),
    'remote_plugin': (True, 'stable'),
    'tool_suggest': (True, 'stable'),
    'windows_sandbox_service': (False, 'underDevelopment'),
}


def _effective_features(configured):
    return configured | {key: value[0] for key, value in _API_FEATURES.items()} | {'network_proxy': None}

# requirements/read maps the fixed catalog AbsolutePathBuf through PathUri;
# config/read and raw TOML retain /rnr/catalog.json. No arbitrary URI is accepted.
_MANAGED_CATALOG_URI = 'file:///rnr/catalog.json'
