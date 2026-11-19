"""Worker computation and parent scheduling are exercised separately."""
import importlib
import io
import json
import unittest

from automation.live_contracts import (Limits, LiveCode, LiveFailure, RunSpec, RunWindow,
    WorkerInputs, encode_context, fake_permit, validate_result)
from test_automation_live_contracts import context, NOW
from test_automation_github_transport import SessionKernel
from test_automation_live_io import Kernel, Channel


class PreviewTests(unittest.TestCase):
    def setUp(self):
        self.api = importlib.import_module('automation.live_preview')
        self.transport = importlib.import_module('automation.github_transport')
        self.window = RunWindow('synthetic', 'example/project', Limits(), 0, 85, 90)
        self.inputs = WorkerInputs(encode_context(context(), limit=1048576), self.window, {})
        self.clients = self.transport.ClientPaths('/synthetic/gh', '/synthetic/curl')

    def worker(self, kernel):
        return self.api.worker_payload(self.inputs, kernel=kernel, clients=self.clients)

    def test_worker_runs_full_pipeline_with_sanitized_output(self):
        kernel = SessionKernel()
        raw = self.worker(kernel)
        output = json.loads(raw)
        self.assertEqual(output['issues'], [])
        self.assertEqual(output['selected'], [])
        self.assertFalse(output['execution_enabled'])
        self.assertEqual(output['live']['attempts'], 1)
        self.assertNotIn(b'SYNTHETIC_TOKEN', raw)

    def test_worker_errors_are_private_receipts_without_data_echo(self):
        for kernel, code in ((SessionKernel(body=b'{"PRIVATE":'), 'live_data_invalid'),
                             (SessionKernel(token=b'PRIVATE\r\n'), 'invalid_credential_output')):
            with self.subTest(code=code):
                raw = self.worker(kernel)
                value = json.loads(raw)
                self.assertEqual(value['error'], code)
                self.assertIn('receipt', value)
                self.assertNotIn(b'PRIVATE', raw)
        kernel = SessionKernel()
        kernel.protect_core = lambda: False
        value = json.loads(self.worker(kernel))
        self.assertEqual(value['error'], 'live_protection_unavailable')
        self.assertEqual(kernel.specs, [])
        self.assertEqual(value['receipt']['attempts'], 0)

    def test_parent_validates_worker_frame_and_consumes_once(self):
        raw = self.worker(SessionKernel())
        kernel = Kernel({'stdout': len(raw).to_bytes(8, 'big')+raw, 'stderr': b''})
        # Faster primitive transfer, still driven by the parent's real pump.
        kernel.read = lambda handle, stream, maximum: SessionKernel.read(kernel, handle, stream, maximum)
        kernel.write = lambda handle, data: SessionKernel.write(kernel, handle, data)
        permit = fake_permit(RunSpec('synthetic', 'example/project', Limits(), 0, 10, 'fake'))
        outcome = self.api.supervise_fake(context(), permit, kernel=kernel, environment={})
        self.assertTrue(outcome.success)
        self.assertEqual(outcome.receipt.attempts, 1)
        again = self.api.supervise_fake(context(), permit, kernel=kernel, environment={})
        self.assertFalse(again.success)
        self.assertEqual(again.code, LiveCode.PERMIT_UNAVAILABLE)
        self.assertEqual(kernel.events.count('launch'), 1)

    def test_parent_stall_and_bad_frames_have_unknown_http_accounting(self):
        for kernel in (Kernel(stall=True), Kernel({'stdout': b'PRIVATE', 'stderr': b''})):
            permit = fake_permit(RunSpec('synthetic', 'example/project', Limits(work_seconds=1), 0, 10, 'fake'))
            outcome = self.api.supervise_fake(context(), permit, kernel=kernel, environment={})
            self.assertFalse(outcome.success)
            self.assertIsNone(outcome.receipt.attempts)
            self.assertEqual(outcome.receipt.accounting, 'unknown')
            self.assertNotIn(b'PRIVATE', outcome.payload)
            self.assertLessEqual(kernel.now, 6)

    def test_worker_entry_frames_and_closes(self):
        raw = self.inputs.context_payload
        channel = Channel(len(raw).to_bytes(8, 'big')+raw)
        self.assertEqual(self.api.worker_entry(self.window, channel=channel, kernel=SessionKernel(),
                         clients=self.clients, environment={}), 0)
        length = int.from_bytes(channel.output[:8], 'big')
        self.assertEqual(length, len(channel.output)-8)
        self.assertEqual(json.loads(channel.output[8:])['live']['attempts'], 1)
        self.assertTrue(channel.closed)

    def test_production_denied_and_delivery_never_retries_work(self):
        outcome = self.api.production_preview(context())
        stdout, stderr = io.StringIO(), io.StringIO()
        self.assertEqual(self.api.deliver(outcome, stdout=stdout, stderr=stderr), 2)
        self.assertEqual(stdout.getvalue(), '')
        self.assertEqual(json.loads(stderr.getvalue())['error'], 'live_not_authorized')
        class Broken:
            def write(self, text):
                raise BrokenPipeError('PRIVATE')
        self.assertEqual(self.api.deliver(outcome, stdout=Broken(), stderr=Broken()), 2)


if __name__ == '__main__':
    unittest.main()
