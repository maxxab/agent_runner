import contextlib
import io
import json
import unittest
from unittest.mock import patch

from automation import cli
from test_automation_live_contracts import context


class LiveCLITests(unittest.TestCase):
    def invoke(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = cli.main(['preview', '--project', '/synthetic', '--enrollment', '/synthetic/private', '--live'])
        return status, stdout.getvalue(), stderr.getvalue()

    def test_public_live_path_denied_without_backend_construction(self):
        with patch.object(cli, 'load_context', return_value=context()):
            status, stdout, stderr = self.invoke()
        self.assertEqual(status, 2)
        self.assertEqual(stdout, '')
        self.assertEqual(json.loads(stderr), {'schema_version': 1, 'execution_enabled': False, 'error': 'live_not_authorized'})

    def test_live_context_errors_and_cancellation_never_echo_private_text(self):
        for exception in (ValueError('PRIVATE'), OSError('PRIVATE'), KeyboardInterrupt('PRIVATE')):
            with self.subTest(exception=type(exception)), patch.object(cli, 'load_context', side_effect=exception):
                status, stdout, stderr = self.invoke()
            self.assertEqual(status, 2)
            self.assertEqual(stdout, '')
            self.assertEqual(json.loads(stderr)['error'], 'live_context_invalid')
            self.assertNotIn('PRIVATE', stderr)


if __name__ == '__main__':
    unittest.main()
