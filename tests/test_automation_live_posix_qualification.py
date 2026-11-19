"""Opt-in, credential-free POSIX qualification using owned local Python children.

RUNNER_POSIX_QUALIFICATION=1 enables real pipes/processes/signals, never HTTP,
credentials, containers or model calls. It does not enable production factories.
"""
import os
from pathlib import Path
import sys
import time
import unittest

from automation import live_io
from automation.live_contracts import LiveCode, ProcessSpec


@unittest.skipUnless(os.environ.get('RUNNER_POSIX_QUALIFICATION') == '1' and
                     sys.platform == 'linux', 'explicit Linux process qualification only')
class PosixQualificationTests(unittest.TestCase):
    def setUp(self):
        # Test-owned construction only; no production factory is introduced.
        self.kernel = object.__new__(live_io.PosixKernel)
        self.kernel._tickets = {}
        self.kernel._next_identity = 0
        self.before = set(os.listdir('/proc/self/fd'))
        self.addCleanup(self.cleanup)

    def cleanup(self):
        for ticket in self.kernel._tickets.values():
            process = ticket.process
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=3)
            self.kernel.close(ticket.handle)
        self.assertEqual(set(os.listdir('/proc/self/fd')), self.before)

    def run_child(self, script, *, payload=b'', cap=1048576, seconds=3, headers=False):
        root = str(Path(__file__).resolve().parents[1])
        argv = (sys.executable, '-c', 'import sys; sys.path.insert(0, '+repr(root)+'); '+script)
        if headers:
            argv += ('{internal-header-fd}',)
        caps = (('stdout', cap), ('stderr', 8192))
        if headers:
            caps += (('headers', 8192),)
        spec = ProcessSpec('worker', argv, {'PATH': os.defpath}, payload,
                           caps, sum(v for _, v in caps),
                           frozenset({'stdout', 'headers'} if headers else {'stdout'}), True)
        started = time.monotonic()
        result = live_io.pump(self.kernel, spec, work_deadline=started+seconds,
                              final_deadline=started+seconds+2, whole_group=True)
        self.assertLess(time.monotonic()-started, seconds+2.5)
        self.assertTrue(result.cleanup.confirmed, result)
        return result

    def test_real_worker_channel_large_frame_roundtrip(self):
        self.assertTrue(hasattr(live_io, 'PosixWorkerChannel'), 'worker pipe adapter missing')
        payload = bytes(range(256))*1024
        result = self.run_child(
            'from automation.live_io import PosixWorkerChannel, read_frame, write_frame; '
            'import time; d=time.monotonic()+3; c=PosixWorkerChannel(deadline=d); '
            'p=read_frame(c, limit=1048576, deadline=d); '
            'write_frame(c, p, limit=1048576, deadline=d)',
            payload=len(payload).to_bytes(8, 'big')+payload)
        self.assertIsNone(result.code)
        self.assertEqual(result.outputs['stdout'], len(payload).to_bytes(8, 'big')+payload)

    def test_worker_channel_trailing_bytes_fail_without_output(self):
        self.assertTrue(hasattr(live_io, 'PosixWorkerChannel'), 'worker pipe adapter missing')
        result = self.run_child(
            'from automation.live_io import PosixWorkerChannel, read_frame; '
            'import time; d=time.monotonic()+2; c=PosixWorkerChannel(deadline=d); '
            'read_frame(c, limit=100, deadline=d)', payload=b'\0\0\0\0\0\0\0\1xy')
        self.assertEqual(result.code, LiveCode.TRANSPORT_UNAVAILABLE)
        self.assertEqual(result.outputs, {})

    def test_worker_pipeline_crosses_real_process_boundary(self):
        from dataclasses import replace
        from automation.live_contracts import Limits, RunSpec, fake_permit
        from automation.live_preview import supervise_fake
        from test_automation_live_contracts import context
        root = str(Path(__file__).resolve().parents[1])
        original_launch = self.kernel.launch

        def launch(handle, spec, *, work_deadline, final_deadline):
            script = (
                'import sys; sys.path[:0]='+repr([root, root+'/tests'])+'; '
                'from automation.live_io import PosixWorkerChannel; '
                'from automation.live_preview import worker_entry; '
                'from automation.live_contracts import RunWindow, Limits; '
                'from automation.github_transport import ClientPaths; '
                'from test_automation_github_transport import SessionKernel; '
                'w=RunWindow("qualification", "example/project", Limits(), 0, '+
                repr(work_deadline)+', '+repr(final_deadline)+'); '
                'sys.exit(worker_entry(w, channel=PosixWorkerChannel(deadline=w.work_deadline), '
                'kernel=SessionKernel(), clients=ClientPaths("/synthetic/gh", "/synthetic/curl"), environment={}))')
            return original_launch(handle, replace(spec, argv=(sys.executable, '-c', script)),
                                   work_deadline=work_deadline, final_deadline=final_deadline)

        self.kernel.launch = launch
        now = time.monotonic()
        permit = fake_permit(RunSpec('qualification', 'example/project',
                                    Limits(work_seconds=3, cleanup_seconds=2), now, now+5, 'test'))
        outcome = supervise_fake(context(), permit, kernel=self.kernel, environment={'PATH': os.defpath})
        self.assertTrue(outcome.success, outcome)
        self.assertEqual(outcome.receipt.attempts, 1)
        self.assertEqual(outcome.receipt.statuses, (200,))
        self.assertNotIn(b'SYNTHETIC_TOKEN', outcome.payload)
        again = supervise_fake(context(), permit, kernel=self.kernel, environment={})
        self.assertEqual(again.code, LiveCode.PERMIT_UNAVAILABLE)
        self.assertEqual(len(self.kernel._tickets), 1)

    def test_output_overflow_is_bounded_and_reaped(self):
        result = self.run_child('import os; os.write(1, b"x"*10000)', cap=100)
        self.assertEqual(result.code, LiveCode.RESPONSE_LIMIT)
        self.assertEqual(result.counts['stdout'], 101)
        self.assertEqual(result.outputs, {})

    def test_stalled_worker_ignoring_term_is_killed_and_reaped(self):
        result = self.run_child('import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)', seconds=.5)
        self.assertEqual(result.code, LiveCode.TRANSPORT_TIMEOUT)
        self.assertTrue(result.cleanup.group_absent)

    def test_separate_header_descriptor_is_delivered_and_closed(self):
        result = self.run_child('import os; f=os.open(sys.argv[1], os.O_WRONLY); os.write(f,b"header"); os.close(f); os.write(1,b"body")', headers=True)
        self.assertIsNone(result.code)
        self.assertEqual(result.outputs, {'stdout': b'body', 'headers': b'header'})

    def test_core_limit_is_applied_only_in_child(self):
        import resource
        before = resource.getrlimit(resource.RLIMIT_CORE)
        result = self.run_child('from automation.live_io import PosixKernel; import os; k=object.__new__(PosixKernel); os.write(1, str(k.protect_core()).encode())')
        self.assertIsNone(result.code)
        self.assertEqual(result.outputs['stdout'], b'True')
        self.assertEqual(resource.getrlimit(resource.RLIMIT_CORE), before)


if __name__ == '__main__':
    unittest.main()
