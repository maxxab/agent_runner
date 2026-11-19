"""Compile and run inert native record fixtures; never run a native entry."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
COMPILER = shutil.which('gcc-13') or shutil.which('gcc') or shutil.which('cc')


@unittest.skipUnless(COMPILER, 'C compiler unavailable')
class NativeRecordTests(unittest.TestCase):
    def check_fixture(self, name):
        with tempfile.TemporaryDirectory(prefix='rnr-record-fixture-') as temporary:
            executable = Path(temporary) / 'fixture'
            result = subprocess.run([COMPILER, '-std=c11', '-Wall', '-Wextra', '-Werror',
                '-O2', str(ROOT/'tests/native'/name),
                str(ROOT/'automation/native/runtime_stage0_records.c'), '-o', str(executable)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(executable)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_existing_inert_installation_task_output_contracts(self):
        self.check_fixture('test_runtime_stage0_records.c')

    def test_project_bound_installation_envelope_and_legacy_reuse(self):
        self.check_fixture('test_runtime_stage0_installation_v2.c')
