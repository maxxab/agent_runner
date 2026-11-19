"""Strict idle-startup notifications, without runtime or model calls."""
import importlib.util
from pathlib import Path
import unittest

PATH = Path(__file__).resolve().parents[1] / 'tools/runner_idle_notifications.py'


class IdleNotificationTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(PATH.exists(), 'idle startup notification validator missing')
        spec = importlib.util.spec_from_file_location('idle_notifications', PATH)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)

    def notification(self, **updates):
        params = {'status': 'disabled', 'installationId': 'fixture-installation',
                  'serverName': 'fixture-server', 'environmentId': None}
        params.update(updates)
        return {'method': 'remoteControl/status/changed', 'params': params}

    def test_disabled_status_is_valid_without_conferring_runtime_authority(self):
        self.assertIsNone(self.module.validate_idle_notification(self.notification()))
        value = self.notification(); del value['params']['environmentId']
        self.assertIsNone(self.module.validate_idle_notification(value))

    def test_active_failed_unknown_and_mistyped_statuses_are_rejected(self):
        for status in ['connecting', 'connected', 'errored', 'unknown', None, False, {}, []]:
            with self.subTest(status=status), self.assertRaises(ValueError):
                self.module.validate_idle_notification(self.notification(status=status))

    def test_malformed_remote_status_is_rejected_without_private_echo(self):
        cases = []
        for field in ['installationId', 'serverName', 'status']:
            value = self.notification(); del value['params'][field]; cases.append(value)
        for field in ['installationId', 'serverName', 'environmentId']:
            cases.append(self.notification(**{field: 1}))
        cases += [self.notification(secret='PRIVATE'), {'method': 'remoteControl/status/changed', 'params': []}]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError) as caught:
                self.module.validate_idle_notification(value)
            self.assertNotIn('PRIVATE', str(caught.exception))

    def test_config_warning_remains_accepted_and_other_methods_rejected(self):
        self.assertIsNone(self.module.validate_idle_notification({'method': 'configWarning', 'params': {}}))
        for method in ['thread/started', 'turn/started', 'error', 'item/tool/call', 'UNKNOWN']:
            with self.subTest(method=method), self.assertRaises(ValueError):
                self.module.validate_idle_notification({'method': method, 'params': {}})

    def test_request_and_extra_envelope_fields_are_rejected(self):
        for additions in [{'id': 1}, {'extra': 'PRIVATE'}, {'jsonrpc': '1.0'}, {'emittedAtMs': True}]:
            with self.subTest(additions=additions), self.assertRaises(ValueError):
                self.module.validate_idle_notification(dict(self.notification(), **additions))
        self.assertIsNone(self.module.validate_idle_notification(dict(self.notification(), jsonrpc='2.0', emittedAtMs=1)))


if __name__ == '__main__':
    unittest.main()
