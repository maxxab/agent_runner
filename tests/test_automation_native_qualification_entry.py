"""Substituted entry routing only; actual private artifacts are NEVER RUN."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
COMPILER = shutil.which('gcc-13') or shutil.which('gcc')


@unittest.skipUnless(COMPILER, 'GCC unavailable')
class NativeQualificationEntryTests(unittest.TestCase):
    def test_private_entry_only_supervises_then_exits_125(self):
        with tempfile.TemporaryDirectory(prefix='rnr-private-entry-') as temporary:
            executable = Path(temporary) / 'fixture'
            built = subprocess.run([COMPILER, '-std=c11', '-Wall', '-Wextra', '-Werror',
                '-O2', '-DRNR_STAGE0_PRIVATE_QUALIFICATION=1',
                str(ROOT/'tests/native/test_runtime_stage0_qualification_main.c'),
                '-o', str(executable)], capture_output=True, text=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stderr)
            symbols = subprocess.run(['nm', '-u', executable], capture_output=True,
                text=True, check=True, timeout=10).stdout
            allowed = {'_ITM_deregisterTMCloneTable', '_ITM_registerTMCloneTable',
                '__assert_fail', '__cxa_finalize', '__gmon_start__', '__libc_start_main',
                '__stack_chk_fail', '__longjmp_chk', 'longjmp', '_setjmp', 'memset'}
            imported = {line.split()[-1].split('@')[0]
                        for line in symbols.splitlines() if line.split()}
            self.assertFalse(imported - allowed, imported - allowed)
            checked = subprocess.run([str(executable)], capture_output=True,
                text=True, timeout=10)
            self.assertEqual(checked.returncode, 0, checked.stderr)
