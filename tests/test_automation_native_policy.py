"""Exact policy DATA decoder; no file reader, grant or native entry execution."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
COMPILER = shutil.which('gcc-13') or shutil.which('gcc')


@unittest.skipUnless(COMPILER, 'GCC unavailable')
class NativePolicyTests(unittest.TestCase):
    def test_exact_policy_structure_bounds_and_failure_clearing(self):
        with tempfile.TemporaryDirectory(prefix='rnr-policy-') as temporary:
            executable = Path(temporary) / 'fixture'
            built = subprocess.run([COMPILER, '-std=c11', '-Wall', '-Wextra', '-Werror',
                '-O2', str(ROOT/'tests/native/test_runtime_stage0_policy.c'),
                str(ROOT/'automation/native/runtime_stage0_records.c'), '-o', str(executable)],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stderr)
            symbols = subprocess.run(['nm', '-u', executable], capture_output=True,
                text=True, check=True, timeout=10).stdout
            allowed = {'_ITM_deregisterTMCloneTable', '_ITM_registerTMCloneTable',
                '__assert_fail', '__cxa_finalize', '__gmon_start__', '__libc_start_main',
                '__memcpy_chk', '__memset_chk', '__stack_chk_fail', 'memcmp', 'memcpy', 'memmove',
                'memset', 'strcmp', 'strlen'}
            imported = {line.split()[-1].split('@')[0]
                        for line in symbols.splitlines() if line.split()}
            self.assertFalse(imported - allowed, imported - allowed)
            checked = subprocess.run([str(executable)], capture_output=True,
                text=True, timeout=15)
            self.assertEqual(checked.returncode, 0, checked.stderr)
