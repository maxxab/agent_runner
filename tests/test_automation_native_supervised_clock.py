"""Only fully syscall-mocked supervised clock fixtures may execute."""
from pathlib import Path
import platform
import os
import tempfile
import shutil
import subprocess
import unittest
ROOT = Path(__file__).resolve().parents[1]
COMPILER = shutil.which('gcc-13') or shutil.which('gcc') or shutil.which('cc')
SUPPORTED = platform.system() == 'Linux' and platform.machine() == 'x86_64'
@unittest.skipUnless(SUPPORTED and COMPILER, 'Linux x86_64 and C compiler required')
class SupervisedClockTests(unittest.TestCase):
    def test_mocked_supervised_clock(self):
        compiler = COMPILER
        self.assertIsNotNone(compiler)
        temporary = tempfile.TemporaryDirectory(prefix='rnr-supervised-clock-', dir=os.environ.get('RNR_NATIVE_TEST_OUTPUT_DIR'))
        self.addCleanup(temporary.cleanup)
        target = Path(temporary.name) / 'mocked-fixture'
        built = subprocess.run([compiler, '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', str(ROOT / 'tests/native/test_runtime_stage0_supervised_clock.c'), '-o', str(target)], capture_output=True, timeout=30)
        self.assertEqual(built.returncode, 0, built.stderr.decode())
        checked = subprocess.run([str(target)], capture_output=True, timeout=10)
        self.assertEqual(checked.returncode, 0, checked.stderr.decode())
