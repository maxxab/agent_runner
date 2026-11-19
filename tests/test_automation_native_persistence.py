"""Protected admission storage boundaries, simulated; no real store/native entry."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import unittest
from tests import test_automation_native_declaration as declaration_fixture

ROOT = Path(__file__).resolve().parents[1]
COMPILER = shutil.which('gcc-13') or shutil.which('gcc')


@unittest.skipUnless(COMPILER, 'GCC unavailable')
class NativePersistenceTests(unittest.TestCase):
    def test_durable_latch_claim_failure_matrix(self):
        with tempfile.TemporaryDirectory(prefix='rnr-persistence-',
                dir=os.environ.get('RNR_NATIVE_TEST_OUTPUT_DIR')) as temporary:
            executable = Path(temporary) / 'fixture'
            built = subprocess.run([COMPILER, '-std=c11', '-Wall', '-Wextra', '-Werror',
                '-O2', str(ROOT / 'tests/native/test_runtime_stage0_persistence.c'),
                str(ROOT / 'automation/native/runtime_stage0_records.c'),
                '-o', str(executable)], capture_output=True, text=True, timeout=30)
            self.assertEqual(built.returncode, 0, built.stderr)
            # Syscalls in persistence must all cross the fixture boundary. read
            # is the fixture's stdin only; no real file, store, process or signal.
            symbols = subprocess.run(['nm', '-u', executable], capture_output=True,
                text=True, check=True, timeout=10).stdout
            allowed = {'_ITM_deregisterTMCloneTable', '_ITM_registerTMCloneTable',
                '__assert_fail', '__cxa_finalize', '__errno_location', '__gmon_start__',
                '__libc_start_main', '__memcpy_chk', '__stack_chk_fail', 'memcmp',
                'memcpy', 'memmove', 'memset', 'read', 'strcmp', 'strlen'}
            imported = {line.split()[-1].split('@')[0]
                        for line in symbols.splitlines() if line.split()}
            self.assertFalse(imported - allowed, imported - allowed)
            data = declaration_fixture.NativeDeclarationTests()
            data.setUp()
            checked = subprocess.run([str(executable)], input=data.encode(),
                capture_output=True, timeout=15)
            self.assertEqual(checked.returncode, 0, checked.stderr.decode())
