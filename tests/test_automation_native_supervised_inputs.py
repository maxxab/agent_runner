"""Actual-module fail-closed boundary with external syscall mocks only."""
from pathlib import Path
import platform
import os
import tempfile
import shutil
import subprocess
import unittest
from tests import test_automation_native_declaration as declaration_fixture
ROOT = Path(__file__).resolve().parents[1]
COMPILER = shutil.which('gcc-13') or shutil.which('gcc') or shutil.which('cc')
SUPPORTED = platform.system() == 'Linux' and platform.machine() == 'x86_64'
@unittest.skipUnless(SUPPORTED and COMPILER, 'Linux x86_64 and C compiler required')
class SupervisedInputsTests(unittest.TestCase):
    def test_actual_modules_hold_correlate_abandon_and_exit(self):
        cc = COMPILER
        self.assertIsNotNone(cc)
        temporary = tempfile.TemporaryDirectory(prefix='rnr-supervised-inputs-', dir=os.environ.get('RNR_NATIVE_TEST_OUTPUT_DIR'))
        self.addCleanup(temporary.cleanup)
        output = Path(temporary.name) / 'mocked-fixture'
        boundary = ('getpid gettid getppid getuid getgid geteuid getegid clock_gettime stat open read openat fstat fcntl getsockopt setsockopt statx fstatfs pread close socketpair sigaction fork prctl send poll recvmsg syscall _exit __open_2 __openat_2 __pread_chk chdir chroot dup2 dup3 execve fchdir fchmod fstatat fstatvfs fsync ftruncate getrandom ioctl memfd_create mkdirat mount pipe2 pwrite umask waitpid').split()
        command = [cc, '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', '-DRNR_STAGE0_PRIVATE_QUALIFICATION=1', str(ROOT / 'tests/native/test_runtime_stage0_supervised_inputs.c')]
        command += [str(ROOT / f'automation/native/runtime_stage0_{name}.c') for name in ('clock', 'launch', 'preparer', 'records', 'admission')]
        command += [f'-Wl,--wrap={name}' for name in boundary] + ['-o', str(output)]
        built = subprocess.run(command, capture_output=True, timeout=30)
        self.assertEqual(built.returncode, 0, built.stderr.decode())
        # Newly reachable syscall helpers must not escape the external mocks.
        # This check runs before executing the fixture on simulated FD numbers.
        self.assertIsNotNone(shutil.which('nm'), 'binutils nm is required for the fixture audit')
        imported = subprocess.run(['nm', '-u', str(output)], capture_output=True,
                                  text=True, timeout=10)
        self.assertEqual(imported.returncode, 0, imported.stderr)
        symbols = {line.split()[-1].split('@')[0] for line in imported.stdout.splitlines()
                   if line.split()}
        allowed = {'_ITM_deregisterTMCloneTable', '_ITM_registerTMCloneTable',
                   '__assert_fail', '__cxa_finalize', '__errno_location', '__gmon_start__',
                   '__isoc23_strtol', 'strtol', 'atoi', '__libc_start_main', '__longjmp_chk',
                   'longjmp', '__memcpy_chk', '__snprintf_chk', '__stack_chk_fail', '_setjmp',
                   'fread', 'memchr', 'memcmp', 'memcpy', 'memset', 'snprintf', 'strchr',
                   'strcmp', 'strlen'}
        self.assertFalse(symbols - allowed, f'unmocked fixture imports: {sorted(symbols - allowed)}')
        fixture = declaration_fixture.NativeDeclarationTests();fixture.setUp()
        for scenario in list(range(10)) + list(range(20, 27)):
            with self.subTest(scenario=scenario):
                fixture.setUp()
                if scenario == 3:
                    fixture.doc['store']['run']['deadline'] = 145
                if scenario == 8:
                    fixture.doc['store']['run']['deadline'] = 100
                checked = subprocess.run([str(output), str(scenario)], input=fixture.encode(), capture_output=True, timeout=10)
                self.assertEqual(checked.returncode, 0, checked.stderr.decode())
