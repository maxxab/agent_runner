"""B-only mocked held reader; exact temporary A seams, never qualification."""
from pathlib import Path
import os
import tempfile
import shutil
import subprocess
import unittest
from tests import test_automation_native_declaration as declaration_fixture

ROOT = Path(__file__).resolve().parents[1]
COMPILER = shutil.which('gcc-13') or shutil.which('gcc') or shutil.which('cc')

@unittest.skipUnless(COMPILER, 'C compiler unavailable')
class NativeHeldInputTests(unittest.TestCase):
    def test_fixed_reader_original_bytes_and_fail_closed_ownership(self):
        temporary = tempfile.TemporaryDirectory(prefix='rnr-held-input-',
            dir=os.environ.get('RNR_NATIVE_TEST_OUTPUT_DIR'))
        self.addCleanup(temporary.cleanup)
        executable = Path(temporary.name)/'fixture'
        built = subprocess.run([COMPILER, '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
            '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections',
            '-Wl,--wrap=fcntl', '-Wl,--wrap=ioctl', '-Wl,--wrap=poll', '-Wl,--wrap=fgetxattr',
            '-Wl,--wrap=socket', '-Wl,--wrap=connect', '-Wl,--wrap=setsockopt', '-Wl,--wrap=getsockopt',
            '-Wl,--wrap=send', '-Wl,--wrap=sendmsg', '-Wl,--wrap=recvmsg', '-I', str(ROOT/'automation/native/libmd'),
            str(ROOT/'tests/native/test_runtime_stage0_held_inputs.c'),
            str(ROOT/'automation/native/runtime_stage0_records.c'), str(ROOT/'automation/native/libmd/sha2.c'), '-o', str(executable)],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(built.returncode, 0, built.stderr)
        self.assertIsNotNone(shutil.which('nm'), 'binutils nm is required for the fixture audit')
        imported = subprocess.run(['nm', '-u', str(executable)], capture_output=True, text=True, timeout=10)
        self.assertEqual(imported.returncode, 0, imported.stderr)
        symbols = {line.split()[-1].split('@')[0] for line in imported.stdout.splitlines() if line.split()}
        allowed = {'_ITM_deregisterTMCloneTable', '_ITM_registerTMCloneTable', '__assert_fail',
                   '__cxa_finalize', '__errno_location', '__gmon_start__', '__libc_start_main',
                   '__memcpy_chk', '__memset_chk', '__snprintf_chk', '__stack_chk_fail',
                   'abort', 'fread', 'memchr', 'memcmp', 'memcpy', 'memset', 'puts', 'snprintf', 'strchr', 'strcmp', 'strlen'}
        self.assertFalse(symbols - allowed, f'unmocked fixture imports: {sorted(symbols - allowed)}')
        data = declaration_fixture.NativeDeclarationTests();data.setUp()
        data.doc['manager_digest'] = '116a510d8255b0b9083434537f2201f36d91d330a8e1f8e35ba9feb3575c82b2'
        checked = subprocess.run([str(executable)], input=data.encode(), capture_output=True, timeout=30)
        self.assertEqual(checked.returncode, 0, checked.stderr)
