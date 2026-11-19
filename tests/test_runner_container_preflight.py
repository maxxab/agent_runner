"""Offline tests of the bounded operator canary; never invoke Docker."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import signal
from unittest.mock import patch, Mock, MagicMock
import sys
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[1] / 'tools/runner_container_preflight.py'


class CanaryTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(PATH.exists(), 'standalone container preflight is missing')
        spec = importlib.util.spec_from_file_location('container_preflight', PATH)
        self.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.m)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_fresh_private_evidence_refuses_existing_and_symlink(self):
        target = self.root / 'new'
        self.m.make_private(target)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o700)
        with self.assertRaises(ValueError):
            self.m.make_private(target)
        link = self.root / 'link'
        link.symlink_to(self.root)
        with self.assertRaises(ValueError):
            self.m.make_private(link)
        self.m.write_json(target / 'evidence.json', {'x': 1})
        self.assertEqual(stat.S_IMODE((target / 'evidence.json').stat().st_mode), 0o600)

    def test_pin_requires_full_hash(self):
        for value in ['python:3', 'sha256:abc', 'sha256:' + 'G' * 64]:
            with self.assertRaises(ValueError):
                self.m.validate_pin(value)
        self.m.validate_pin('sha256:' + 'a' * 64)

    def test_supervisor_queries_only_allowlisted_metadata(self):
        info = self.m.info_args()
        self.assertNotIn('{{json .}}', info)
        self.assertNotIn('.Env', ' '.join(self.m.inspect_args('a' * 64)))
        self.assertIn('CgroupVersion', info[-1])

    def test_json_is_strict_and_bounded(self):
        for value in ['{"x":1,"x":2}', '{"x":NaN}', '[] trailing', 'x' * 65537]:
            with self.assertRaises(ValueError):
                self.m.strict_json(value)
        self.assertEqual(self.m.strict_json('[1]'), [1])

    def test_create_policy_has_only_assigned_mounts_and_no_pull(self):
        state = self.state()
        for role in ['owner', 'reviewer']:
            args = self.m.create_args(state, role)
            self.assertIn('--pull=never', args)
            self.assertIn('--network=none', args)
            self.assertIn('--read-only', args)
            self.assertIn('--cap-drop=ALL', args)
            self.assertIn('--memory=134217728', args)
            self.assertIn('--memory-swap=134217728', args)
            self.assertIn('--pids-limit=32', args)
            mounts = [args[i + 1] for i, arg in enumerate(args) if arg == '--mount']
            self.assertEqual(len(mounts), 2)
            self.assertTrue(all('/work/' in x for x in mounts))
            self.assertEqual('readonly' in mounts[0], role == 'reviewer')
            self.assertIn('readonly', mounts[1])
            self.assertNotIn(str(self.root / 'private'), ' '.join(args))

    def state(self):
        return self.m.initial_state(self.root, 'sha256:' + 'a' * 64,
                                    '/usr/bin/docker', '/var/run/docker.sock', 120)

    def inspection(self, state, role='owner'):
        item = state['allocations'][role]
        return {'Id': 'b' * 64, 'Name': '/' + item['name'],
                'Config': {'Labels': item['labels']},
                'State': {'Running': False, 'Pid': 0, 'Status': 'exited', 'Dead': False}}

    def test_identity_requires_exact_name_labels_and_immutable_id(self):
        state = self.state()
        item = state['allocations']['owner']
        obj = self.inspection(state)
        self.m.check_identity(item, obj)
        item['id'] = 'b' * 64
        for key, value in [('Id', 'c' * 64), ('Name', '/reused')]:
            bad = dict(obj, **{key: value})
            with self.assertRaises(ValueError):
                self.m.check_identity(item, bad)
        obj['Config']['Labels'] = {}
        with self.assertRaises(ValueError):
            self.m.check_identity(item, obj)

    def test_malformed_supervisor_identity_fails_closed(self):
        state = self.state()
        item = state['allocations']['owner']
        for malformed in [None, [], {}, {'Id':'b' * 64, 'Name':'/' + item['name'], 'Config':[]}]:
            with self.assertRaises(ValueError):
                self.m.check_identity(item, malformed)

    def test_requested_policy_and_disabled_execution_are_explicit(self):
        state = self.state()
        self.assertIs(state['execution_enabled'], False)
        self.assertIs(state['runtime_mode_accepted'], False)
        self.assertEqual(state['requested_policy']['pids'], 32)
        self.assertEqual(state['requested_policy']['memory_bytes'], 134217728)

    def test_unknown_create_cannot_be_cleared_by_absence_or_late_identity(self):
        state = self.state()
        state['allocations']['owner']['uncertain'].append('create')
        state['allocations']['owner']['cleanup'] = 'PASS'
        state['allocations']['reviewer']['cleanup'] = 'PASS'
        state['roles'] = {'owner': 'PASS', 'reviewer': 'PASS'}
        self.assertEqual(self.m.result_status(state), 'UNKNOWN')
        self.assertEqual(state['allocations']['owner']['uncertain'], ['create'])

    def test_cleanup_refuses_changed_identity_and_failed_inspect(self):
        state = self.state()
        item = state['allocations']['owner']
        item['created'] = True
        calls = []
        def fake(args, **kw):
            calls.append(args)
            if args[:2] == ['container', 'inspect']:
                return {'returncode': 0, 'stdout': json.dumps([dict(self.inspection(state), Name='/other')]),
                        'stderr': '', 'uncertain': False}
            self.fail('must not mutate changed identity')
        self.m.cleanup_one(state, 'owner', fake)
        self.assertEqual(item['cleanup'], 'UNKNOWN')
        self.assertEqual(len(calls), 1)

    def test_cleanup_requires_terminal_state_and_successful_absence_query(self):
        state = self.state()
        item = state['allocations']['owner']
        item['created'] = True
        item['id'] = 'b' * 64
        calls = []
        def fake(args, **kw):
            calls.append(args)
            output = json.dumps([self.inspection(state)]) if args[:2] == ['container', 'inspect'] else ''
            return {'returncode': 0, 'stdout': output, 'stderr': '', 'uncertain': False}
        self.m.cleanup_one(state, 'owner', fake)
        self.assertEqual(item['cleanup'], 'PASS')
        self.assertIn(['container', 'rm', 'b' * 64], calls)
        self.assertEqual(calls[-1][:2], ['container', 'ls'])

    def test_successful_cleanup_is_not_repeated(self):
        state = self.state()
        item = state['allocations']['owner']
        item['created'] = True
        item['cleanup'] = 'PASS'
        def forbidden(*args, **kwargs):
            self.fail('confirmed deleted resource must not be operated twice')
        self.m.cleanup_one(state, 'owner', forbidden)
        self.assertEqual(item['cleanup'], 'PASS')

    def test_evidence_rejects_repository_and_symlink_parent(self):
        with self.assertRaises(ValueError):
            self.m.validate_evidence_location(PATH.parent.parent / 'new-evidence')
        link = self.root / 'repo'
        link.symlink_to(PATH.parent.parent)
        with self.assertRaises(ValueError):
            self.m.validate_evidence_location(link / 'new-evidence')
        self.m.validate_evidence_location(self.root / 'safe')

    def test_failed_absence_query_and_timedout_create_remain_unknown(self):
        for uncertain in [[], ['create']]:
            state = self.state()
            item = state['allocations']['owner']
            item['created'] = True
            item['uncertain'] = uncertain.copy()
            def fake(args, **kw):
                if args[:2] == ['container', 'inspect']:
                    output = json.dumps([self.inspection(state)])
                else:
                    output = ''
                return {'returncode': 1 if args[:2] == ['container', 'ls'] and not uncertain else 0,
                        'stdout': output, 'stderr': '', 'uncertain': False}
            self.m.cleanup_one(state, 'owner', fake)
            self.assertEqual(self.m.result_status(state), 'UNKNOWN')
            if uncertain:
                self.assertEqual(item['uncertain'], ['create'])

    def test_command_environment_is_clean_and_output_is_bounded(self):
        evidence = self.root / 'evidence'
        self.m.make_private(evidence)
        runner = self.m.Commands(sys.executable, '/var/run/docker.sock', evidence,
                                 self.m.time.monotonic() + 10)
        runner.prefix = [sys.executable]
        result = runner(['-c', 'import os; print(sorted(os.environ)); print("x"*100000)'])
        self.assertLessEqual(len(result['stdout'].encode()), 65536)
        self.assertTrue(result['uncertain'])
        self.assertNotIn('OPENAI_API_KEY', result['stdout'])
        self.assertEqual(set(runner.env), {'PATH', 'HOME', 'DOCKER_CONFIG', 'LANG'})

    def test_timeout_receipt_is_unknown(self):
        evidence = self.root / 'evidence'
        self.m.make_private(evidence)
        runner = self.m.Commands(sys.executable, '/var/run/docker.sock', evidence,
                                 self.m.time.monotonic() + 10)
        runner.prefix = [sys.executable]
        result = runner(['-c', 'import time; time.sleep(5)'], timeout=0.05)
        self.assertTrue(result['uncertain'])

    def test_independent_cleanup_sentinel_fences_stale_inmemory_state(self):
        state = self.state()
        self.m.write_json(self.root / 'cleanup-started.json', {'reason': 'watchdog'})
        with self.assertRaises(ValueError):
            self.m.ensure_admission(state, now=state['start_monotonic'])

    def test_watchdog_is_independent_session_without_docker_for_finished_run(self):
        state = self.state()
        state['parent_pid'] = os.getpid()
        self.m.write_json(self.root / 'state.json', state)
        self.m.write_json(self.root / 'finished.json', {'status':'BLOCKED'})
        process = subprocess.Popen([sys.executable, str(PATH), '--watchdog', str(self.root)],
                                   env={'PATH':'/usr/bin:/bin', 'LANG':'C.UTF-8'},
                                   start_new_session=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        output, error = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 0, error)
        ready = self.m.strict_json((self.root / 'watchdog-ready.json').read_text())
        self.assertEqual(ready, {'pid':process.pid, 'session':process.pid})
        self.assertTrue((self.root / 'watchdog-finished.json').is_file(),
                        'successful watchdog must acknowledge the completion handshake')
        self.assertEqual(list(self.root.glob('command-*.json')), [])

    def test_exact_process_instance_exit_is_observed(self):
        process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(5)'])
        try:
            identity = self.m.process_identity(process.pid)
            self.assertFalse(self.m.tree_exited([identity]))
        finally:
            process.kill()
            process.wait(timeout=2)
        self.assertTrue(self.m.tree_exited([identity]))

    def test_r1_premature_watchdog_exit_including_zero_never_healthy(self):
        for exitcode in [0, 9]:
            state = self.state()
            class DeadWatchdog:
                def poll(self):
                    return exitcode
            self.assertTrue(hasattr(self.m, 'ensure_watchdog'), 'watchdog continuity guard missing')
            with self.assertRaises(ValueError):
                self.m.ensure_watchdog(state, DeadWatchdog())
            self.assertTrue(state['watchdog_lost'])
            self.assertEqual(self.m.result_status(state), 'UNKNOWN')

    def test_r2_exited_leader_descendant_group_is_killed_on_pipe_timeout(self):
        evidence = self.root / 'evidence'
        self.m.make_private(evidence)
        runner = self.m.Commands(sys.executable, '/var/run/docker.sock', evidence,
                                 self.m.time.monotonic() + 10)
        runner.prefix = [sys.executable]
        # A new-session CLI leader exits while its child retains captured pipes.
        script = ('import os,subprocess,sys; '
                  'p=subprocess.Popen([sys.executable,"-c","import time; time.sleep(10)"]); '
                  'print(p.pid,flush=True); os._exit(0)')
        result = runner(['-c', script], timeout=0.3)
        self.assertTrue(result['uncertain'])
        pid = int(result['stdout'].strip())
        try:
            end = self.m.time.monotonic() + 1
            while self.m.time.monotonic() < end:
                try:
                    identity = self.m.process_identity(pid)
                except FileNotFoundError:
                    return
                if identity['state'] == 'Z':
                    return
                self.m.time.sleep(0.02)
            self.fail('CLI descendant survived bounded pipe timeout')
        finally:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def test_r3_invalid_utf8_is_unknown_with_original_bytes_retained(self):
        evidence = self.root / 'evidence'
        self.m.make_private(evidence)
        runner = self.m.Commands(sys.executable, '/var/run/docker.sock', evidence,
                                 self.m.time.monotonic() + 10)
        runner.prefix = [sys.executable]
        result = runner(['-c', 'import os; os.write(1,bytes([123,125,255]))'])
        self.assertTrue(result['uncertain'], 'malformed wire bytes must never become valid JSON')
        self.assertEqual(result['stdout_raw_hex'], '7b7dff')

    def test_r4_backwards_wall_clock_cannot_extend_original_monotonic_limit(self):
        state = self.state()
        self.assertIn('deadline_monotonic', state, 'original monotonic deadline missing')
        with patch.object(self.m.time, 'time', return_value=state['start_epoch'] - 3600), \
                patch.object(self.m.time, 'monotonic', return_value=state['cleanup_monotonic']):
            with self.assertRaises(ValueError):
                self.m.ensure_admission(state)
        self.assertEqual(state['deadline_monotonic'] - state['start_monotonic'], 120)

    def test_explicit_create_budget_preserves_default_for_other_commands(self):
        calls = []
        def fake(args, **kwargs):
            calls.append((args, kwargs))
            return {'returncode':0, 'stdout':'ack', 'stderr':'', 'uncertain':False}
        self.assertEqual(self.m.checked(fake, ['container','create'], timeout=10), 'ack')
        self.assertEqual(self.m.checked(fake, ['container','inspect','id']), 'ack')
        self.assertEqual(calls, [(['container','create'], {'timeout':10}),
                                 (['container','inspect','id'], {})])

    def test_slow_create_acknowledgement_uses_explicit_budget_and_original_deadline(self):
        evidence = self.root / 'evidence'
        self.m.make_private(evidence)
        runner = self.m.Commands(sys.executable, '/var/run/docker.sock', evidence,
                                 self.m.time.monotonic() + 6)
        runner.prefix = [sys.executable]
        output = self.m.checked(runner, ['-c', 'import time; time.sleep(4.1); print("ack")'],
                                timeout=10)
        self.assertEqual(output.strip(), 'ack')

    def test_original_command_cutoff_precedes_cleanup_and_slow_receipt(self):
        evidence = self.root / 'evidence'
        self.m.make_private(evidence)
        deadline = 10.05
        runner = self.m.Commands(sys.executable, '/var/run/docker.sock', evidence, deadline)
        now = [10.0]; events = []
        process = Mock(pid=123)
        selector = MagicMock()
        selector.__enter__.return_value = selector
        selector.get_map.return_value = {'pending': object()}
        def selected(timeout):
            events.append(('wait', timeout))
            now[0] = 10.06  # original cutoff passed; no new wait is permitted
            return []
        selector.select.side_effect = selected
        def killed(pid, sig): events.append(('kill', pid, sig))
        def reaped(*, timeout): events.append(('reap', timeout)); return -signal.SIGKILL
        process.wait.side_effect = reaped
        def receipt(path, value):
            events.append(('receipt',))
            now[0] = 100.0  # bookkeeping cannot renew command authority
        with patch.object(self.m.time, 'monotonic', side_effect=lambda: now[0]), \
                patch.object(self.m.subprocess, 'Popen', return_value=process), \
                patch.object(self.m.selectors, 'DefaultSelector', return_value=selector), \
                patch.object(self.m.os, 'killpg', side_effect=killed), \
                patch.object(self.m, 'write_json', side_effect=receipt):
            result = runner(['no actual command'], timeout=10)
        self.assertTrue(result['uncertain'])
        self.assertEqual(result['error'], 'bounded subprocess timeout')
        self.assertEqual(runner.deadline, deadline)
        self.assertEqual(selector.select.call_count, 1)
        self.assertAlmostEqual(events[0][1], 0.05)
        self.assertEqual(events[1:], [('kill', 123, signal.SIGKILL), ('reap', 1), ('receipt',)])
        process.stdout.close.assert_called_once()
        process.stderr.close.assert_called_once()

    def test_original_deadline_and_cleanup_fence(self):
        state = self.state()
        deadline = state['deadline_epoch']
        self.assertEqual(deadline - state['start_epoch'], 120)
        self.m.ensure_admission(state, now=state['cleanup_monotonic'] - 1)
        for now in [state['cleanup_monotonic'], state['deadline_monotonic'] + 1]:
            with self.assertRaises(ValueError):
                self.m.ensure_admission(state, now=now)
        state['cleanup_started'] = True
        with self.assertRaises(ValueError):
            self.m.ensure_admission(state, now=state['start_monotonic'])
        self.assertEqual(state['deadline_epoch'], deadline)


if __name__ == '__main__':
    unittest.main()
