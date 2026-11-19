"""Synthetic boundary checks; no child process, credentials or network."""
from dataclasses import replace
from datetime import datetime, timezone
import importlib
import json
import unittest
from concurrent.futures import ThreadPoolExecutor

from automation.config import Config, Context, Approval, AcceptedDependency

NOW = datetime(2026, 11, 15, tzinfo=timezone.utc)


def context():
    return Context(Config('example/project', 'main', 'host', ('alice',), ('doc',),
                          ('unit',), ('ready',), ('normal',), 2),
                   'a'*40, 'b'*64, (), ())


def result():
    return dict(schema_version=1, mode='advisory', execution_enabled=False,
                repository='example/project', base_revision='a'*40, config_sha256='b'*64,
                snapshot_fetched_at=NOW.isoformat(), candidate_order=[1], selected=[],
                issues=[dict(repository='example/project', number=1, status='blocked',
                             reasons=['runtime_unavailable'])],
                live=dict(source='github_rest', accounting='complete', attempts=1,
                          response_bytes=2, received_bytes=20, statuses=[200], cleanup='confirmed'))


class LiveContractsTests(unittest.TestCase):
    def setUp(self):
        self.m = importlib.import_module('automation.live_contracts')
        self.window = self.m.RunWindow('fake-run', 'example/project', self.m.Limits(), 0., 85., 90.)

    def validate(self, value):
        raw = json.dumps(value, ensure_ascii=False).encode()
        return self.m.validate_result(raw, context=context(), window=self.window,
                                      clock=lambda: 1., wall_now=NOW)

    def test_fake_permit_consumed_once_even_after_failure(self):
        m = self.m
        p = m.fake_permit(m.RunSpec('fake-run', 'example/project', m.Limits(), 0., 10., 'synthetic'))
        with ThreadPoolExecutor(2) as pool:
            def attempt(_):
                try:
                    return p.consume('example/project', now=1.)
                except m.LiveFailure:
                    return None
            values = list(pool.map(attempt, range(2)))
        self.assertEqual(sum(v is not None for v in values), 1)
        receipt = m.Receipt('unknown', None, None, None, None, 'failed', 'confirmed')
        p.finish(receipt)
        p.finish(receipt)
        with self.assertRaises(m.LiveFailure):
            p.consume('example/project', now=2.)
        with self.assertRaises(m.LiveFailure):
            m.LiveReadPermit()

    def test_context_roundtrip_and_live_only_token_limit(self):
        m = self.m
        ctx = replace(context(), approvals=(Approval(1, 'c'*64, 'alice', ('AC-1',), NOW, True),),
                      accepted_dependencies=(AcceptedDependency(2, 'c'*64, 'd'*64, 'alice', NOW),))
        self.assertEqual(m.decode_context(m.encode_context(ctx, limit=1048576), limit=1048576), ctx)
        from automation.contracts import repository
        long = 'a/' + 'b'*16381
        self.assertEqual(repository(long), long)  # existing offline validation remains unchanged
        with self.assertRaises(m.LiveFailure) as caught:
            m.encode_context(replace(ctx, config=replace(ctx.config, repository=long)), limit=1048576)
        self.assertEqual(caught.exception.code.value, 'live_context_invalid')

    def test_environment_drops_secrets_without_value_lookup(self):
        class Env(dict):
            def __getitem__(self, key):
                if key in ('GH_TOKEN', 'SSLKEYLOGFILE'):
                    raise AssertionError('removed value was read')
                return super().__getitem__(key)
        env = Env(GH_TOKEN='sentinel', SSLKEYLOGFILE='sentinel', HTTPS_PROXY='preserve',
                  CURL_CA_BUNDLE='preserve-ca')
        sanitized = self.m.sanitize_environment(env)
        self.assertNotIn('GH_TOKEN', sanitized)
        self.assertNotIn('SSLKEYLOGFILE', sanitized)
        self.assertEqual(sanitized['HTTPS_PROXY'], 'preserve')
        self.assertEqual(sanitized['GH_TELEMETRY'], 'false')

    def test_protection_marker_requires_actual_fake_protection(self):
        class Kernel:
            def protect_core(self): return False
        with self.assertRaises(self.m.LiveFailure) as caught:
            self.m.protect_worker(Kernel(), self.window)
        self.assertEqual(caught.exception.code.value, 'live_protection_unavailable')
        with self.assertRaises(self.m.LiveFailure):
            self.m.ProtectedWorker()

    def test_success_schema_and_large_dependency_reason_list(self):
        self.assertTrue(self.validate(result()).success)
        value = result()
        value['issues'][0]['reasons'] = [f'dependency_missing:example/project#{n}' for n in range(1, 1501)]
        self.assertTrue(self.validate(value).success)

    def test_invalid_candidates_rows_and_receipt_never_succeed(self):
        edits = [lambda v: v.update(candidate_order=[2]),
                 lambda v: v.update(candidate_order=[1, 1]),
                 lambda v: v['issues'][0].update(repository='foreign/project'),
                 lambda v: v['live'].update(attempts=0),
                 lambda v: v['live'].update(attempts=2),
                 lambda v: v['live'].update(received_bytes=1),
                 lambda v: v['issues'][0].update(reasons=['private sentinel']),
                 lambda v: v.update(schema_version=True)]
        for edit in edits:
            value = result(); edit(value)
            with self.subTest(edit=edit), self.assertRaises(self.m.LiveFailure):
                self.validate(value)

    def test_private_error_receipt_is_not_public_payload(self):
        value = dict(schema_version=1, execution_enabled=False, error='response_limit',
                     receipt=dict(accounting='partial', attempts=2, response_bytes=1048597,
                                  received_bytes=1048677, statuses=[200], outcome='failed', cleanup='confirmed'))
        out = self.validate(value)
        self.assertFalse(out.success)
        self.assertEqual(out.receipt.attempts, 2)
        self.assertEqual(set(json.loads(out.payload)), {'schema_version', 'execution_enabled', 'error'})

    def test_error_unknown_worker_metrics_rejected(self):
        value = dict(schema_version=1, execution_enabled=False, error='live_internal_error',
                     receipt=dict(accounting='unknown', attempts=None, response_bytes=None,
                                  received_bytes=None, statuses=None, outcome='failed', cleanup='confirmed'))
        with self.assertRaises(self.m.LiveFailure): self.validate(value)

    def test_duplicate_keys_and_bad_utf8_do_not_echo_sentinals(self):
        for raw in (b'{"private sentinel":1,"private sentinel":2}', b'\xff', b'{} trailing'):
            with self.subTest(raw=raw), self.assertRaises(self.m.LiveFailure) as caught:
                self.m.validate_result(raw, context=context(), window=self.window,
                                       clock=lambda: 1., wall_now=NOW)
            self.assertNotIn('sentinel', str(caught.exception))

    def test_parser_checks_deadline_inside_long_tokens(self):
        calls = []
        def clock():
            calls.append(1)
            return 86. if len(calls) >= 4 else 1.
        raw = b' ' * 70000 + json.dumps(result()).encode()
        with self.assertRaises(self.m.LiveFailure) as caught:
            self.m.validate_result(raw, context=context(), window=self.window, clock=clock, wall_now=NOW)
        self.assertEqual(caught.exception.code.value, 'live_deadline_exceeded')

    def test_raw_escaped_token_limit_and_depth_limit(self):
        for raw in (b'"' + b'\\u0061'*3000 + b'"', b'['*33+b'0'+b']'*33):
            with self.assertRaises(self.m.LiveFailure) as caught:
                self.m.validate_result(raw, context=context(), window=self.window,
                                       clock=lambda: 1., wall_now=NOW)
            self.assertEqual(caught.exception.code.value, 'live_result_limit')

    def test_result_encoding_enforces_exact_byte_limit(self):
        raw = self.m.encode_result(result(), limit=4194304)
        self.assertEqual(self.m.encode_result(result(), limit=len(raw)), raw)
        with self.assertRaises(self.m.LiveFailure):
            self.m.encode_result(result(), limit=len(raw)-1)

    def test_permit_invalid_eligibility_never_consumes_or_refunds(self):
        m = self.m
        spec = m.RunSpec('run', 'example/project', m.Limits(), 1., 2., 'fake')
        p = m.fake_permit(spec)
        for repository, now in [('foreign/project', 1.), ('example/project', 0.),
                                ('example/project', 2.), ('example/project', float('nan'))]:
            with self.assertRaises(m.LiveFailure): p.consume(repository, now=now)
        self.assertEqual(p.consume('example/project', now=1.).final_deadline, 91.)
        p.finish(m.Receipt('complete', 0, 0, 0, (), 'failed', 'confirmed'))
        with self.assertRaises(m.LiveFailure):
            p.finish(m.Receipt('unknown', None, None, None, None, 'failed', 'confirmed'))

    def test_private_accounting_shapes_and_overshoot_bound(self):
        m = self.m
        for receipt in (m.Receipt('complete', 0, 0, 0, (), 'failed', 'confirmed'),
                        m.Receipt('complete', 2, 50, 130, (200, 200), 'failed', 'confirmed'),
                        m.Receipt('partial', 1, 1048577, 1048617, (), 'failed', 'confirmed')):
            raw = m.private_error(m.LiveCode.LIVE_DATA_INVALID, receipt, limits=m.Limits())
            out = m.validate_result(raw, context=context(), window=self.window,
                                    clock=lambda: 1., wall_now=NOW)
            self.assertEqual(out.receipt, receipt)
        for receipt in (m.Receipt('unknown', 0, None, None, None, 'failed', 'confirmed'),
                        m.Receipt('complete', 0, 1, 1, (), 'failed', 'confirmed'),
                        m.Receipt('partial', 10, 10485762, 10485762, (), 'failed', 'confirmed'),
                        m.Receipt('complete', 1, 0, 0, (), 'succeeded', 'confirmed')):
            with self.assertRaises(m.LiveFailure):
                m.validate_receipt(receipt, limits=m.Limits(), allow_unknown=True)

    def test_context_preserves_permitted_repository_token_boundary(self):
        m = self.m
        long = 'a/' + 'b'*16380
        ctx = replace(context(), config=replace(context().config, repository=long))
        self.assertEqual(m.decode_context(m.encode_context(ctx, limit=1048576), limit=1048576), ctx)

    def test_foreign_reason_only_scope_denied_and_no_duplicate_reason(self):
        value = result()
        value['issues'][0]['reasons'] = ['dependency_scope_denied:foreign/project#2']
        self.assertTrue(self.validate(value).success)
        for reasons in (['dependency_missing:foreign/project#2'],
                        ['runtime_unavailable', 'runtime_unavailable'], ['repository_not_enrolled']):
            value['issues'][0]['reasons'] = reasons
            with self.assertRaises(self.m.LiveFailure): self.validate(value)

    def test_node_shapes_and_future_time_fail_without_freeform_error(self):
        for change in ({'snapshot_fetched_at': '2027-01-01T00:00:00Z'}, {'selected': [1]},
                       {'extra secret sentinel': True}, {'candidate_order': [True]}):
            value = result(); value.update(change)
            with self.assertRaises(self.m.LiveFailure) as caught: self.validate(value)
            self.assertNotIn('sentinel', str(caught.exception))

    def test_declared_row_and_reason_collection_limits(self):
        value = result()
        value['issues'] *= 1001
        with self.assertRaises(self.m.LiveFailure) as caught: self.validate(value)
        self.assertEqual(caught.exception.code.value, 'live_result_limit')
        value = result()
        value['issues'][0]['reasons'] = ['runtime_unavailable'] * 50001
        with self.assertRaises(self.m.LiveFailure) as caught: self.validate(value)
        self.assertEqual(caught.exception.code.value, 'live_result_limit')
