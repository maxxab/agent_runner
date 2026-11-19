"""Disposable-file ownership checks; no protected factory or native effects."""
from dataclasses import replace
import fcntl
import hashlib
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
from automation import control_runtime_seal as seal
from tests import test_automation_runtime_seal as fixture


class RetainedOutputTests(unittest.TestCase):
    # Reuse fixture data only; inherited compatibility checks run separately.
    def setUp(self):
        fixture.SealTests.setUp(self)
        self.data = {target: target.encode() * 3 for target in self.data}
        self.pins = tuple(replace(pin, file=replace(pin.file, bytes=len(self.data[pin.file.target]), content_digest=hashlib.sha256(self.data[pin.file.target]).hexdigest())) for pin in self.pins)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        (root / 'home').mkdir(mode=0o700)
        (root / 'system').mkdir(mode=0o700)
        self.guard = seal._Clock(self.anchor)
        self.root = seal._RootFS(os.open(root, os.O_RDONLY | os.O_DIRECTORY), self.guard)
        self.root.workfd = os.dup(self.root.runfd)
        self.root.begin = lambda name: None
        self.root.open_source = lambda pin: fixture.Source(self.data[pin.file.target])
        self.driver = seal.Sealer._bound(self.root, self.guard)
        self.addCleanup(self.driver.close)
        self.addCleanup(patch.stopall)
        patch.object(self.root, '_protected', lambda *args: self.guard.check()).start()
        real_stat = os.fstat
        def fixture_stat(fd):
            info = real_stat(fd)
            return types.SimpleNamespace(**{
                key: (0 if key in ('st_uid', 'st_gid') else getattr(info, key))
                for key in dir(info) if key.startswith('st_')})
        patch.object(seal.os, 'fstat', fixture_stat).start()

    def test_retained_readonly_identity_content_and_writer_before_transfer(self):
        original = self.root._register_output
        registered = []
        def register(relative, entry):
            self.assertTrue(all(sink.fd is None for sink in sinks))
            self.assertEqual(fcntl.fcntl(entry.fd, fcntl.F_GETFL) & os.O_ACCMODE, os.O_RDONLY)
            self.assertTrue(fcntl.fcntl(entry.fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
            registered.append(entry)
            return original(relative, entry)
        sinks = []
        opener = self.root.open_destination
        def open_sink(relative):
            sink = opener(relative)
            sinks.append(sink)
            return sink
        self.root.open_destination = open_sink
        self.root._register_output = register
        output = self.driver.seal(self.name, self.pins)
        self.assertIs(type(output), tuple)
        self.assertEqual(len(output), 7)
        self.assertEqual(len(registered), 7)
        for entry, pin in zip(registered, self.pins):
            self.assertEqual(os.pread(entry.fd, seal.CHUNK, 0), self.data[pin.file.target])
            self.assertEqual(entry.digest, pin.file.content_digest)
        held = [entry.fd for entry in registered]
        self.driver.close()
        self.assertTrue(all(entry is None for entry in self.root._outputs))
        for fd in held:
            with self.assertRaises(OSError): os.fstat(fd)

    def test_replaced_leaf_rejects_same_bytes_different_inode(self):
        opener = self.root.open_destination
        def open_sink(relative):
            sink = opener(relative)
            finish = sink.finish
            def replace(mode):
                finish(mode)
                path = Path(self.temp.name) / relative
                data = path.read_bytes()
                path.rename(str(path) + '.original')
                path.write_bytes(data)
                path.chmod(mode)
            sink.finish = replace
            return sink
        self.root.open_destination = open_sink
        with self.assertRaisesRegex(ValueError, 'identity'):
            self.driver.seal(self.name, self.pins)
        self.assertTrue(all(item is None for item in self.root._outputs))

    def test_readonly_hash_is_mandatory(self):
        read = os.pread
        def corrupt(fd, size, offset):
            data = read(fd, size, offset)
            if data and fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY:
                return b'x' * len(data)
            return data
        with patch.object(seal.os, 'pread', corrupt):
            with self.assertRaisesRegex(ValueError, 'readback'):
                self.driver.seal(self.name, self.pins)
        self.assertTrue(all(item is None for item in self.root._outputs))

    def test_uncertain_writer_close_not_retried_or_registered(self):
        real_close = os.close
        calls = []; writers = []
        def close(fd):
            calls.append(fd)
            writable = fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDWR
            real_close(fd)
            if writable:
                writers.append(fd)
                raise OSError('uncertain writer close')
        with patch.object(seal.os, 'close', close):
            with self.assertRaisesRegex(OSError, 'uncertain writer'):
                self.driver.seal(self.name, self.pins)
        self.assertEqual(len(writers), 1)
        self.assertEqual(calls.count(writers[0]), 1)
        self.assertTrue(all(item is None for item in self.root._outputs))

    def test_registration_failure_closes_local_candidate(self):
        candidates = []
        def fail(relative, entry):
            candidates.append(entry.fd)
            raise ValueError('registration failed')
        self.root._register_output = fail
        with self.assertRaisesRegex(ValueError, 'registration failed'):
            self.driver.seal(self.name, self.pins)
        self.assertEqual(len(candidates), 1)
        with self.assertRaises(OSError): os.fstat(candidates[0])
        self.assertTrue(all(item is None for item in self.root._outputs))

    def test_clock_loss_after_writer_close_rejects(self):
        real_close = os.close
        def close(fd):
            writable = fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDWR
            real_close(fd)
            if writable:
                self.guard.end = 0
        with patch.object(seal.os, 'close', close):
            with self.assertRaisesRegex(ValueError, 'expired'):
                self.driver.seal(self.name, self.pins)
        self.assertTrue(all(item is None for item in self.root._outputs))

    def test_earlier_output_retained_after_later_failure(self):
        original = self.root.open_source
        count = 0
        def source(pin):
            nonlocal count
            count += 1
            if count == 2: raise ValueError('later source failed')
            return original(pin)
        self.root.open_source = source
        with self.assertRaisesRegex(ValueError, 'later source'):
            self.driver.seal(self.name, self.pins)
        held = [entry for entry in self.root._outputs if entry is not None]
        self.assertEqual(len(held), 1)
        os.fstat(held[0].fd)

    def test_all_slots_invalidated_before_close_and_all_errors_preserved(self):
        self.driver.seal(self.name, self.pins)
        expected = [entry.fd for entry in self.root._outputs] + [self.root.workfd, self.root.runfd]
        real_close = os.close
        calls = []
        def fail(fd):
            self.assertTrue(all(item is None for item in self.root._outputs))
            self.assertIsNone(self.root.workfd)
            self.assertIsNone(self.root.runfd)
            calls.append(fd)
            real_close(fd)
            raise OSError('cleanup ' + str(fd))
        with patch.object(seal.os, 'close', fail):
            with self.assertRaises(OSError) as raised: self.driver.close()
            self.driver.close()
        self.assertEqual(calls, expected)
        self.assertEqual(len(raised.exception.seal_cleanup_errors), 8)

    def test_initiating_error_survives_stream_cleanup_errors(self):
        original = self.root.open_source
        def broken(pin):
            source = original(pin)
            source.read = lambda size: (_ for _ in ()).throw(ValueError('initiating'))
            source.close = lambda: (_ for _ in ()).throw(OSError('source cleanup'))
            return source
        self.root.open_source = broken
        with self.assertRaisesRegex(ValueError, 'initiating') as raised:
            self.driver.seal(self.name, self.pins)
        self.assertEqual(str(raised.exception.seal_cleanup_errors[0]), 'source cleanup')



    def test_destination_child_close_failure_closes_writer_once(self):
        real_close = os.close
        real_open = os.open
        opened = []
        closed = []
        def record_open(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            opened.append(fd)
            return fd
        def fail(fd):
            closed.append(fd)
            real_close(fd)
            if fd == opened[0]: raise OSError('child close')
        with patch.object(seal.os, 'open', record_open), patch.object(seal.os, 'close', fail):
            with self.assertRaisesRegex(OSError, 'child close'):
                self.root.open_destination('system/config.toml')
        self.assertEqual(len(opened), 2)
        self.assertEqual(closed, opened)
        for fd in opened:
            with self.assertRaises(OSError): os.fstat(fd)

    def test_false_registration_is_rejection_and_candidate_closed(self):
        candidates = []
        def refuse(relative, entry):
            candidates.append(entry.fd)
            return False
        self.root._register_output = refuse
        with self.assertRaisesRegex(ValueError, 'registration failed'):
            self.driver.seal(self.name, self.pins)
        self.assertEqual(len(candidates), 1)
        with self.assertRaises(OSError): os.fstat(candidates[0])

    def test_identity_change_after_writer_close_rejects(self):
        real_close = os.close
        def close(fd):
            writable = fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDWR
            if writable: os.fchmod(fd, 0o600)
            real_close(fd)
        with patch.object(seal.os, 'close', close):
            with self.assertRaisesRegex(ValueError, 'identity'):
                self.driver.seal(self.name, self.pins)
        self.assertTrue(all(item is None for item in self.root._outputs))

if __name__ == '__main__':
    unittest.main()
