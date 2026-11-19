"""Fixture-only source-open ownership on verification and close failures."""
import errno
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from automation import control_runtime_seal as seal


class SourceCleanupTests(unittest.TestCase):
    def fixture(self, source='/leaf'):
        return seal._RootFS(None,SimpleNamespace(check=lambda:None)), \
            SimpleNamespace(file=SimpleNamespace(source=source))

    def test_directory_close_failure_does_not_orphan_verified_leaf(self):
        fs,pin=self.fixture()
        directory=OSError(errno.EINTR,'directory close uncertain')
        def close(fd):
            if fd==50:raise directory
        with patch.object(seal.os,'open',side_effect=[50,51]), \
                patch.object(seal.os,'close',side_effect=close) as closed, \
                patch.object(seal._Source,'verify'):
            with self.assertRaises(OSError) as caught:fs.open_source(pin)
        self.assertIs(caught.exception,directory)
        self.assertEqual([c.args[0] for c in closed.call_args_list],[50,51])

    def test_original_verification_error_survives_both_close_failures(self):
        fs,pin=self.fixture()
        original=ValueError('source verification failed')
        errors={50:OSError(errno.EIO,'directory close'),51:OSError(errno.EINTR,'leaf close')}
        def close(fd):raise errors[fd]
        with patch.object(seal.os,'open',side_effect=[50,51]), \
                patch.object(seal.os,'close',side_effect=close) as closed, \
                patch.object(seal._Source,'verify',side_effect=original):
            with self.assertRaises(ValueError) as caught:fs.open_source(pin)
        self.assertIs(caught.exception,original)
        self.assertEqual(set(c.args[0] for c in closed.call_args_list),{50,51})
        self.assertEqual(closed.call_count,2)
        self.assertEqual(set(original.seal_cleanup_errors),set(errors.values()))

    def test_walk_close_failure_retains_error_and_closes_new_directory_once(self):
        fs,pin=self.fixture('/fixed/leaf')
        errors={50:OSError(errno.EINTR,'old directory'),51:OSError(errno.EIO,'new directory')}
        def close(fd):raise errors[fd]
        with patch.object(seal.os,'open',side_effect=[50,51]) as opened, \
                patch.object(seal.os,'close',side_effect=close) as closed:
            with self.assertRaises(OSError) as caught:fs.open_source(pin)
        self.assertIs(caught.exception,errors[50])
        self.assertEqual(caught.exception.seal_cleanup_errors,(errors[51],))
        self.assertEqual([c.args[0] for c in closed.call_args_list],[50,51])
        self.assertEqual(opened.call_count,2)

    def test_post_cleanup_clock_failure_closes_leaf_without_publication(self):
        fs,pin=self.fixture()
        expired=False
        def close(fd):
            nonlocal expired
            if fd==50:expired=True
        def check():
            if expired:raise ValueError('original setup expired during cleanup')
        fs.guard.check=check
        with patch.object(seal.os,'open',side_effect=[50,51]), \
                patch.object(seal.os,'close',side_effect=close) as closed, \
                patch.object(seal._Source,'verify'):
            with self.assertRaisesRegex(ValueError,'original setup expired'):fs.open_source(pin)
        self.assertEqual([c.args[0] for c in closed.call_args_list],[50,51])

    def test_success_transfers_only_leaf_after_directory_cleanup(self):
        fs,pin=self.fixture()
        with patch.object(seal.os,'open',side_effect=[50,51]), \
                patch.object(seal.os,'close') as closed,patch.object(seal._Source,'verify'):
            source=fs.open_source(pin)
            closed.assert_called_once_with(50)
            self.assertEqual(source.fd,51)
            source.close();source.close()
            self.assertEqual([c.args[0] for c in closed.call_args_list],[50,51])


if __name__=='__main__':unittest.main()
