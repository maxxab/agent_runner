"""G1 retained original kernel view; only audited syscall substitutes execute."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CC = shutil.which('gcc-13') or shutil.which('gcc')


@unittest.skipUnless(CC, 'GCC required')
class ProjectViewTests(unittest.TestCase):
    def test_retained_original_peers_choose_only_their_project(self):
        with tempfile.TemporaryDirectory(prefix='rnr-project-view-', dir=os.environ.get('RNR_NATIVE_TEST_OUTPUT_DIR')) as temporary:
            binary = Path(temporary) / 'fixture'
            built = subprocess.run([CC, '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
                str(ROOT/'tests/native/test_runtime_stage0_project_view.c'), '-o', str(binary)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stderr)
            imported = subprocess.run(['nm', '-u', str(binary)], capture_output=True, text=True, timeout=10)
            self.assertEqual(imported.returncode, 0, imported.stderr)
            symbols = {line.split()[-1].split('@')[0] for line in imported.stdout.splitlines() if line.split()}
            allowed = {'_ITM_deregisterTMCloneTable', '_ITM_registerTMCloneTable', '__assert_fail',
                       '__cxa_finalize', '__errno_location', '__gmon_start__', '__libc_start_main',
                       '__stack_chk_fail', '__snprintf_chk', '__memcpy_chk', 'memcmp', 'memcpy',
                       'memset', 'memchr', 'snprintf', 'strlen', 'strcmp', 'strchr'}
            self.assertFalse(symbols - allowed, f'unmocked imports: {sorted(symbols - allowed)}')
            checked = subprocess.run([str(binary)], capture_output=True, text=True, timeout=30)
            self.assertEqual(checked.returncode, 0, checked.stderr)
