"""Pinned refusal protocol tests, not SDK/wire or process-lifecycle tests."""
import importlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
COMMAND = 'item/commandExecution/requestApproval'
FILE = 'item/fileChange/requestApproval'
DYNAMIC = 'item/tool/call'


class Trap:
    def __repr__(self):
        raise AssertionError('payload was inspected')

    def __str__(self):
        raise AssertionError('payload was inspected')

    def __eq__(self, other):
        raise AssertionError('payload was compared')


class MethodTrap(str):
    def __eq__(self, other):
        raise AssertionError('method subclass was compared')


class ParamsTrap(dict):
    def __iter__(self):
        raise AssertionError('parameter subclass was traversed')

    def __repr__(self):
        raise AssertionError('parameter subclass was formatted')


class CallbackTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue((ROOT/'automation/callbacks.py').is_file(),
                        'disabled-runtime callback is not implemented')
        self.module = importlib.import_module('automation.callbacks')
        self.reject = self.module.reject_server_request

    def test_command_and_file_approval_cancel_without_widening_authority(self):
        for method in (COMMAND, FILE):
            for params in (None, {}, {'decision': 'acceptForSession', 'role': 'owner',
                                       'approved': True, 'token': 'fixture-secret'}):
                with self.subTest(method=method, params=params):
                    self.assertEqual(self.reject(method, params), {'decision': 'cancel'})

    def test_dynamic_request_returns_only_fixed_unsuccessful_text(self):
        self.assertEqual(self.reject(DYNAMIC, {'tool': 'spawn', 'arguments': {'allowed': True}}),
                         {'success': False, 'contentItems': [
                             {'type': 'inputText', 'text': 'Runner execution is disabled.'}]})

    def test_nested_payload_is_inert_and_unchanged(self):
        trap = Trap()
        params = {'method': trap, 'arguments': [trap], 'role': trap, 'secret': trap}
        for method in (COMMAND, FILE, DYNAMIC):
            self.reject(method, params)
        self.assertIs(params['method'], trap)
        self.assertIs(params['arguments'][0], trap)
        self.assertEqual(set(params), {'method', 'arguments', 'role', 'secret'})

    def test_all_unhandled_pinned_routes_raise_without_empty_fallback(self):
        for method in ('item/tool/requestUserInput', 'mcpServer/elicitation/request',
                       'item/permissions/requestApproval', 'account/chatgptAuthTokens/refresh',
                       'attestation/generate', 'applyPatchApproval', 'execCommandApproval'):
            with self.subTest(method=method), self.assertRaises(self.module.UnsupportedServerRequest):
                self.reject(method, {'approved': True, 'secret': 'fixture-secret'})

    def test_unknown_case_whitespace_and_prefix_are_not_normalized_into_support(self):
        for method in ('', 'unknown', COMMAND.upper(), COMMAND+' ', ' '+FILE,
                       DYNAMIC+'/extra', 'x'*100000):
            with self.subTest(method=method[:40]), self.assertRaises(self.module.UnsupportedServerRequest):
                self.reject(method, None)

    def test_direct_malformed_input_rejects_exact_types_before_payload_access(self):
        for method in (None, True, 3, [], {}, Trap(), MethodTrap(COMMAND)):
            with self.assertRaises(self.module.UnsupportedServerRequest):
                self.reject(method, None)
        for params in (False, 1, '', [], Trap(), ParamsTrap(approved=True)):
            with self.assertRaises(self.module.UnsupportedServerRequest):
                self.reject(COMMAND, params)

    def test_errors_are_static_bounded_and_never_echo_method_or_payload(self):
        messages = []
        for method, params in (('fixture-secret-method', {'key': 'fixture-secret'}),
                               ('unknown', Trap()), (MethodTrap(FILE), None)):
            with self.assertRaises(self.module.UnsupportedServerRequest) as caught:
                self.reject(method, params)
            self.assertIsInstance(caught.exception, ValueError)
            message = str(caught.exception)
            self.assertLessEqual(len(message), 128)
            self.assertNotIn('fixture-secret', message)
            messages.append(message)
        self.assertEqual(len(set(messages)), 1)

    def test_fresh_responses_prevent_mutation_from_enabling_later_calls(self):
        first = self.reject(COMMAND, {})
        first['decision'] = 'accept'
        self.assertEqual(self.reject(COMMAND, {}), {'decision': 'cancel'})
        result = self.reject(DYNAMIC, {})
        result['success'] = True
        result['contentItems'][0]['text'] = 'success'
        result['contentItems'].append({'type': 'inputText', 'text': 'injected'})
        again = self.reject(DYNAMIC, {})
        self.assertEqual(again, {'success': False, 'contentItems': [
            {'type': 'inputText', 'text': 'Runner execution is disabled.'}]})

    def test_responses_are_json_serializable_without_request_data(self):
        for method in (COMMAND, FILE, DYNAMIC):
            result = self.reject(method, {'secret': Trap()})
            encoded = json.dumps(result)
            self.assertNotIn('secret', encoded)
            self.assertEqual(json.loads(encoded), result)
