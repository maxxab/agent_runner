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
            str(ROOT/'tests/native/test_runtime_stage0_held_inputs.c'),
            str(ROOT/'automation/native/runtime_stage0_records.c'), '-o', str(executable)],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(built.returncode, 0, built.stderr)
        data = declaration_fixture.NativeDeclarationTests();data.setUp()
        checked = subprocess.run([str(executable)], input=data.encode(), capture_output=True, timeout=10)
        self.assertEqual(checked.returncode, 0, checked.stderr)
