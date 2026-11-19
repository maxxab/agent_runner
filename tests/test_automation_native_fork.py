"""Build the real native clock boundary; abort-only host check, no preparer."""
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
COMPILER = shutil.which('gcc-13') or shutil.which('gcc') or shutil.which('cc')
SUPPORTED = platform.system() == 'Linux' and platform.machine() == 'x86_64'


@unittest.skipUnless(SUPPORTED and COMPILER, 'Linux x86_64 and C compiler required')
class NativeForkTests(unittest.TestCase):
    def compile_and_run(self, fixture, *, linked=False):
        with tempfile.TemporaryDirectory(prefix='rnr-fork-test-') as directory:
            output = Path(directory) / 'fixture'
            command = [COMPILER, '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2']
            if linked:
                command += ['-DRNR_STAGE0_PRIVATE_QUALIFICATION=1']
            command += [str(ROOT / 'tests' / 'native' / fixture)]
            if linked:
                command += [str(ROOT / 'automation' / 'native' / name) for name in (
                    'runtime_stage0_clock.c', 'runtime_stage0_admission.c')]
            command += ['-o', str(output)]
            built = subprocess.run(command, capture_output=True, timeout=30, check=False)
            self.assertEqual(built.returncode, 0, built.stderr.decode(errors='replace'))
            # The child sees ONLY0..2, including on Python's real spawn route.
            checked = subprocess.run([str(output)], stdin=subprocess.DEVNULL,
                                     capture_output=True, close_fds=True, timeout=20,
                                     env={'LC_ALL': 'C', 'TZ': 'UTC'}, check=False)
            self.assertEqual(checked.returncode, 0, checked.stderr.decode(errors='replace'))

    def test_original_clock_regressions(self):
        self.compile_and_run('test_runtime_stage0_clock.c')

    def test_controlled_fork_failure_matrix(self):
        self.compile_and_run('test_runtime_stage0_fork.c')

    def test_admission_binding_preserves_original_clock_without_launch_authority(self):
        self.compile_and_run('test_runtime_stage0_admission_clock.c')

    def test_keeper_original_trigger_stop_and_consumed_cutoff(self):
        self.compile_and_run('test_runtime_stage0_keeper_clock.c')

    def test_real_fixed_held_inventory_rejects_missing_extra_and_wrong_gate(self):
        self.compile_and_run('test_runtime_stage0_held_inventory.c', linked=True)

    def test_held_gate_flags_are_rechecked_after_inventory_eof(self):
        self.compile_and_run('test_runtime_stage0_held_mutation.c')

    def test_real_held_child_aborts_without_preparation_and_releases_descriptors(self):
        self.compile_and_run('test_runtime_stage0_fork_abort.c', linked=True)

    def test_real_parent_loss_cannot_release_child_into_preparation(self):
        self.compile_and_run('test_runtime_stage0_fork_parent_loss.c', linked=True)
