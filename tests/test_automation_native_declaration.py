"""Differential inert declaration checks; no runtime/clock/resource operation."""
from copy import deepcopy
from pathlib import Path
import json
import os
import random
import shutil
import subprocess
import tempfile
import unittest
from automation import control_store as cs
from automation import control_runtime_clock as clock
from automation import control_runtime_launch_data as launch
from automation.control_runtime_seal import _DESTINATIONS

ROOT = Path(__file__).resolve().parents[1]
COMPILER = shutil.which('gcc-13') or shutil.which('gcc') or shutil.which('cc')


@unittest.skipUnless(COMPILER, 'C compiler unavailable')
class NativeDeclarationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='rnr-declaration-fixture-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.executable = Path(cls.temporary.name)/'fixture'
        result = subprocess.run([COMPILER, '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2',
            str(ROOT/'tests/native/test_runtime_stage0_launch_declaration.c'),
            str(ROOT/'automation/native/runtime_stage0_records.c'), '-o', str(cls.executable)],
            capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise AssertionError(result.stderr)

    def setUp(self):
        self.origin = clock._NativeClockOrigin(os.getpid(), os.getpid(),
            '11111111-1111-1111-1111-111111111111', 4, 123,
            10_000_000_000, 100_000_000_000, 220_000_000_000, 130_000_000_000,
            25_000_000_000, 14_000_000_000, 104_000_000_000)
        self.doc = dict(version=3, allocation='a'*32, asset_root='f'*64,
            execution_root='1'*64, daemon_digest='2'*64, tool_digest='d'*64, manager_digest='e'*64,
            store=dict(run=dict(deadline=140, commands=5, turns=8, capacity=2, turn_capacity=2),
                policy=dict(model='synthetic', effort='medium', input_bytes=4096,
                            turn_items=16, item_text_bytes=2048),
                resources=dict(runtime_slots=4, reviewer_reserve=1, workload_slots=2),
                queue_bound=8, run_id='run', supervisor_epoch='sup'),
            quota=dict(cpu_millis=1000, memory_bytes=536870912, swap_bytes=0,
                       pids=128, scratch_bytes=67108864, output_bytes=1048576),
            files=[dict(target=t, content_digest='c'*64,
                        bytes=1 if t in ('/rnr/guardian','/rnr/codex') else 0)
                   for t in sorted(_DESTINATIONS)],
            unit_paths=['/run/systemd/transient', '/etc/systemd/system'])

    def native(self, raw):
        result = subprocess.run([self.executable], input=raw, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def encode(self, doc=None):
        return cs.canonical(self.doc if doc is None else doc).encode()

    def test_canonical_subset_agrees_with_python_and_retains_borrowed_values(self):
        for capacity in (1, 2, 1_000_000):
            doc = deepcopy(self.doc)
            doc['store']['run']['capacity'] = capacity
            doc['store']['resources']['workload_slots'] = capacity
            raw = self.encode(doc)
            python = launch._decode_launch(raw, self.origin)
            self.assertEqual(launch._json(raw), doc)
            self.assertEqual(self.native(raw), dict(accepted=True, version=3,
                positive_wall_ns=140_000_000_000, run_capacity=python.inputs.run.capacity,
                paths=2, model=python.inputs.policy.model))

    def test_malformed_noncanonical_and_out_of_subset_bytes_reject(self):
        raw = self.encode()
        cases = [json.dumps(self.doc, separators=(',', ':')).encode(), b'', raw+b' ', b' '+raw, raw[:-1], b'{}', b'[]', raw.replace(b'"version":3', b'"version":true'),
                 raw.replace(b'"version":3', b'"version":03'), raw.replace(b'"version":3', b'"version":3.0'),
                 raw.replace(b'"version":3', b'"version":-3'), raw.replace(b'"version":3', b'"version":NaN'),
                 raw.replace(b'"version":3', b'"version":9223372036854775808'),
                 raw.replace(b'"version":3', b'"version":3,"version":3'),
                 raw.replace(b'"model":"synthetic"', b'"model":"synthe\\u0074ic"'),
                 raw.replace(b'"model":"synthetic"', b'"model":"synthe\xc3\xa9tic"'),
                 b'['*13+b'0'+b']'*13, b'['+b','.join([b'0']*2048)+b']', b'x'*65537]
        for value in cases:
            with self.subTest(raw=value[:100]):
                self.assertFalse(self.native(value)['accepted'])
        # Canonical Python accepts these forms; the native first-release subset
        # deliberately rejects them, never claims full JSON semantic equivalence.
        for value in (140.0,):
            doc = deepcopy(self.doc); doc['store']['run']['deadline'] = value
            value_raw = self.encode(doc)
            launch._decode_launch(value_raw, self.origin)
            self.assertFalse(self.native(value_raw)['accepted'])

    def test_closed_schema_value_bounds_and_resource_selectors_reject(self):
        cases = []
        def change(path, value):
            doc = deepcopy(self.doc); parent = doc
            for key in path[:-1]: parent = parent[key]
            parent[path[-1]] = value; cases.append(doc)
        for field in ('allocation','asset_root','execution_root','daemon_digest','tool_digest','manager_digest'):
            change((field,), 'A'*(32 if field=='allocation' else 64))
        change(('version',), 2)
        change(('store','run','deadline'), 9223372037)
        change(('store','run','commands'), 0)
        change(('store','run','turns'), 1000001)
        change(('store','run','capacity'), True)
        change(('store','resources','workload_slots'), 3)
        change(('store','resources','reviewer_reserve'), 4)
        change(('store','policy','model'), '')
        change(('store','policy','effort'), 'x'*257)
        change(('quota','cpu_millis'), 1001)
        change(('quota','cpu_millis'), 9223372036860)
        change(('quota','swap_bytes'), 1)
        change(('quota','pids'), 0)
        change(('files',0,'bytes'), 2097153)
        change(('files',4,'bytes'), 0)
        change(('files',5,'bytes'), 1073741825)
        change(('files',0,'target'), '/unexpected')
        change(('unit_paths',), ['/run/systemd/transient']*2)
        change(('unit_paths',), ['/etc/systemd/system'])
        change(('unit_paths',), ['/run/systemd/transient','/a/../b'])
        change(('unit_paths',), ['/run/systemd/transient','/a//b'])
        change(('unit_paths',), ['/run/systemd/transient','/a/'])
        change(('unit_paths',), ['/run/systemd/transient','/'+'/'.join(['a']*16)])
        doc = deepcopy(self.doc); del doc['store']['policy']['model']; cases.append(doc)
        doc = deepcopy(self.doc); doc['store']['policy']['unknown'] = 1; cases.append(doc)
        for doc in cases:
            with self.subTest(doc=doc):
                self.assertFalse(self.native(self.encode(doc))['accepted'])

    def test_accepted_mutated_bytes_always_agree_with_python_canonical_parser(self):
        raw = self.encode()
        generator = random.Random(143)
        for _ in range(128):
            mutated = bytearray(raw)
            index = generator.randrange(len(mutated))
            mutated[index] = generator.randrange(128)
            candidate = bytes(mutated)
            if self.native(candidate)['accepted']:
                # This is syntax/canonical agreement, deliberately distinct
                # from correlation to the caller-independent original clock.
                parsed = launch._json(candidate)
                self.assertEqual(cs.canonical(parsed).encode(), candidate)

    def test_data_decoding_does_not_claim_original_clock_correlation(self):
        doc = deepcopy(self.doc); doc['store']['run']['deadline'] = 145
        raw = self.encode(doc)
        self.assertTrue(self.native(raw)['accepted'])
        with self.assertRaises(ValueError):
            launch._decode_launch(raw, self.origin)
