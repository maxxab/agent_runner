"""Pure startup-response checks; no runtime, network or provider activity."""
import copy
import hashlib
import importlib
import json
import tomllib
import unittest
from unittest.mock import patch
from automation import managed_config as mc


# Pinned ConfigRequestProcessor overlay, independent expected fixture.
API_FEATURES = {
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


class ManagedObservationTests(unittest.TestCase):
    def setUp(self):
        pin = patch.object(mc, 'CATALOG_SHA256', hashlib.sha256(b'{"models":[]}').hexdigest())
        pin.start(); self.addCleanup(pin.stop)
        self.bundle = mc.build_qualification(b'{"models":[]}')
        self.raw = tomllib.loads(dict(self.bundle.files)['home/config.toml'].decode())
        self.provider = dict(self.raw['model_providers']['rnr_fixture'])
        for key in ('auth', 'aws', 'capabilities', 'credential_file', 'env_http_headers',
                    'env_key', 'env_key_instructions', 'experimental_bearer_token',
                    'gateway_oauth', 'http_headers', 'location', 'model_catalog_url',
                    'project_id', 'query_params',
                    'stream_idle_timeout_ms', 'websocket_connect_timeout_ms'):
            self.provider[key] = None
        self.provider.update(supports_websockets=False, supports_standalone_web_search=False)
        config = copy.deepcopy(self.raw)
        config.update(allow_login_shell=False, hooks=None)
        config['features']['network_proxy'] = None
        config['features'].update({key: value[0] for key, value in API_FEATURES.items()})
        config['model_providers'] = {'rnr_fixture': self.provider}
        self.config = {'config': config, 'origins': {}, 'layers': [
            {'name': {'type': 'user', 'file': '/home/runtime/config.toml'},
             'version': 'a'*64, 'config': self.raw}]}
        self.config['layers'].insert(0, {'name': {'type': 'legacyManagedConfigTomlFromFile', 'file': '/etc/codex/managed_config.toml'}, 'version': 'b'*64, 'config': {}})
        self.config['layers'].append({'name': {'type': 'system', 'file': '/etc/codex/config.toml'}, 'version': 'c'*64, 'config': {}})
        self.requirements = {'requirements': {
            'allowedApprovalPolicies': ['never'], 'allowedApprovalsReviewers': ['user'],
            'allowedSandboxModes': ['read-only', 'danger-full-access'], 'allowedWebSearchModes': ['disabled'],
            'allowManagedHooksOnly': True, 'allowRemoteControl': False,
            'allowBrowserAndComputerUse': False, 'allowAppshots': False,
            'allowLoginShell': False, 'checkForUpdateOnStartup': False,
            'modelProvider': 'rnr_fixture', 'modelCatalogJson': 'file:///rnr/catalog.json',
            'modelProviders': {'rnr_fixture': self.provider},
            'featureRequirements': self.raw['features']}}
        self.features = {'nextCursor': None, 'data': [
            {'name': k, 'enabled': False, 'defaultEnabled': True, 'stage': 'stable'}
            for k in mc.FEATURES] + [
            {'name': key, 'enabled': enabled, 'defaultEnabled': enabled, 'stage': stage}
            for key, (enabled, stage) in API_FEATURES.items()]}

    def check(self):
        api = importlib.import_module('automation.managed_observation')
        return api.observe(self.bundle, self.config, self.requirements, self.features)

    def test_exact_views_yield_only_digests_and_fixed_scope(self):
        result = self.check()
        self.assertEqual(result['kind'], 'rnr-managed-startup-views-v1')
        self.assertEqual(result['managed_features_disabled'], 15)
        self.assertFalse(result['runtime_accepted'])
        self.assertNotIn('http://', json.dumps(result))
        self.assertEqual(result, self.check())

    def test_missing_or_conflicting_controls_fail(self):
        mutations = [lambda: self.config['config'].update(notify=['bad']),
                     lambda: self.config['config'].update(mcp_servers={'bad': {}}),
                     lambda: self.config['config'].update(hooks={'bad': []}),
                     lambda: self.config['config'].update(allow_login_shell=True),
                     lambda: self.requirements['requirements'].pop('allowedApprovalsReviewers'),
                     lambda: self.requirements['requirements'].update(allowRemoteControl=True),
                     lambda: self.provider.update(env_key='PRIVATE_KEY'),
                     lambda: self.provider.update(base_url='http://elsewhere/v1')]
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                self.setUp(); mutate()
                with self.assertRaises(ValueError): self.check()

    def test_retry_controls_are_explicit_and_observed(self):
        # A nullable/default retry policy cannot establish a finite profile.
        self.assertIs(self.raw['features'].get('unbounded_connection_retries'), False)
        for key, expected in (('request_max_retries', 0), ('stream_max_retries', 0),
                              ('supports_websockets', False)):
            self.assertEqual(self.raw['model_providers']['rnr_fixture'].get(key), expected)
        self.check()
        for key in ('request_max_retries', 'stream_max_retries'):
            for value in (None, 1, False):
                with self.subTest(key=key, value=value):
                    self.setUp(); self.provider[key] = value
                    with self.assertRaises(ValueError): self.check()
        self.setUp()
        self.config['config']['features']['unbounded_connection_retries'] = True
        next(row for row in self.features['data']
             if row['name'] == 'unbounded_connection_retries')['enabled'] = True
        with self.assertRaises(ValueError): self.check()

    def test_unknown_changed_disabled_or_duplicate_layers_fail(self):
        for variant in ('unknown', 'config', 'disabled', 'duplicate', 'profile', 'missing'):
            with self.subTest(variant=variant):
                self.setUp(); layers = self.config['layers']
                if variant == 'unknown': layers[0]['name']['type'] = 'enterpriseManaged'
                elif variant == 'config': layers[0]['config'] = {'notify': ['bad']}
                elif variant == 'disabled': layers[0]['disabledReason'] = 'untrusted'
                elif variant == 'duplicate': layers.append(copy.deepcopy(layers[0]))
                elif variant == 'profile': layers[0]['name']['profile'] = 'other'
                else: layers.clear()
                with self.assertRaises(ValueError): self.check()

    def test_normalized_features_must_be_complete_unique_and_false(self):
        for variant in ('true', 'missing', 'duplicate', 'page', 'removed', 'integer'):
            with self.subTest(variant=variant):
                self.setUp(); data = self.features['data']
                if variant == 'true': data[0]['enabled'] = True
                elif variant == 'missing': data.pop()
                elif variant == 'duplicate': data.append(copy.deepcopy(data[0]))
                elif variant == 'page': self.features['nextCursor'] = '256'
                elif variant == 'removed': data[0]['stage'] = 'removed'
                else: data[0]['enabled'] = 0
                with self.assertRaises(ValueError): self.check()

    def test_bounded_responses_and_immutable_input_bundle(self):
        self.config['unexpected'] = 'x' * 65537
        with self.assertRaises(ValueError): self.check()
        self.setUp(); self.bundle = object()
        with self.assertRaises(ValueError): self.check()

    def test_exact_fixed_layer_stack_is_required(self):
        for index in range(3):
            with self.subTest(missing=index):
                self.setUp(); self.config['layers'].pop(index)
                with self.assertRaises(ValueError): self.check()
        self.setUp()
        self.config['layers'].insert(1, {'name': {'type': 'sessionFlags'},
                                        'version': 'd'*64, 'config': {}})
        with self.assertRaises(ValueError): self.check()

    def test_allowed_fallback_does_not_change_required_effective_mode(self):
        self.config['config']['sandbox_mode'] = 'read-only'
        with self.assertRaises(ValueError): self.check()
        self.setUp()
        self.requirements['requirements']['allowedSandboxModes'] = ['danger-full-access']
        with self.assertRaises(ValueError): self.check()
        self.setUp()
        self.requirements['requirements']['allowedSandboxModes'].append('workspace-write')
        with self.assertRaises(ValueError): self.check()

    def test_serialized_unset_network_proxy_is_exactly_null(self):
        for variant in ('missing', 'false', 'configured', 'extra'):
            with self.subTest(variant=variant):
                self.setUp(); features = self.config['config']['features']
                if variant == 'missing': features.pop('network_proxy')
                elif variant == 'false': features['network_proxy'] = False
                elif variant == 'configured': features['network_proxy'] = {'enabled': False}
                else: features['unknown'] = None
                with self.assertRaises(ValueError): self.check()

    def test_api_overlay_is_exact_and_cross_checked(self):
        original = copy.deepcopy((self.config, self.features))
        for key, (enabled, stage) in API_FEATURES.items():
            for mutation in ('missing_config', 'wrong_config', 'integer_config',
                             'missing_row', 'wrong_enabled', 'wrong_stage', 'wrong_default'):
                with self.subTest(key=key, mutation=mutation):
                    self.config, self.features = copy.deepcopy(original)
                    current = self.config['config']['features']
                    row = next(row for row in self.features['data'] if row['name'] == key)
                    if mutation == 'missing_config': del current[key]
                    elif mutation == 'wrong_config': current[key] = not enabled
                    elif mutation == 'integer_config': current[key] = int(enabled)
                    elif mutation == 'missing_row': self.features['data'].remove(row)
                    elif mutation == 'wrong_enabled': row['enabled'] = not enabled
                    elif mutation == 'wrong_stage': row['stage'] = 'beta'
                    elif mutation == 'wrong_default': row['defaultEnabled'] = not enabled
                    with self.assertRaises(ValueError): self.check()

    def test_managed_catalog_requires_exact_file_uri_only(self):
        self.check()
        for value in ('/rnr/catalog.json', 'file://localhost/rnr/catalog.json',
                      'file:///rnr/../rnr/catalog.json', 'file:///rnr/catalog.json?x=1',
                      'file:///rnr/catalog.json#x', 'https://example.invalid/catalog.json',
                      None, {'path': '/rnr/catalog.json'}):
            with self.subTest(value=value):
                self.requirements['requirements']['modelCatalogJson'] = value
                with self.assertRaises(ValueError): self.check()
        self.requirements['requirements']['modelCatalogJson'] = 'file:///rnr/catalog.json'
        self.config['config']['model_catalog_json'] = 'file:///rnr/catalog.json'
        with self.assertRaises(ValueError): self.check()
