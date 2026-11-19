"""Fail-closed admission of the kernel's active immutable asset mapping."""
import struct
import unittest
from unittest import mock
import os
import threading
import stat
from automation import control_runtime_verity as verity

ROOT = 'ab' * 32
HEADER = struct.Struct('=3I3Ii3IQ128s129s7s')
TARGET = struct.Struct('=QQiI16s')


def response(*, root=ROOT, options='', flags=49, count=1, kind=b'verity',
             start=0, sectors=800, params=None, event=7):
    if params is None:
        params = f'1 7:0 7:1 4096 4096 100 1 sha256 {root} -{options}'
    extent = TARGET.size + len(params.encode()) + 1
    aligned = (extent + 7) & ~7
    body = TARGET.pack(start, sectors, 0, aligned, kind) + params.encode() + b'\0'
    size = HEADER.size + len(body)
    return HEADER.pack(4, 0, 0, size, HEADER.size, count, 1, flags, event, 0,
                       64768, b'rnr-test', b'', b'') + body + b'\0'*(aligned-extent)


class ActiveVerityTableTests(unittest.TestCase):
    def test_accepts_exact_kernel_table_and_retains_event(self):
        table = verity.decode_table(response(), expected_device=64768, root_digest=ROOT)
        self.assertEqual(table.root_digest, ROOT)
        self.assertEqual(table.data_blocks, 100)
        self.assertEqual(table.event, 7)
        self.assertEqual(table.sectors, 800)

    def test_rejects_digest_mismatch_even_with_correct_metadata(self):
        with self.assertRaises(ValueError):
            verity.decode_table(response(root='cd'*32), expected_device=64768, root_digest=ROOT)

    def test_rejects_weakening_options_and_any_extra_parameters(self):
        for option in (' 1 ignore_corruption', ' 1 check_at_most_once',
                       ' 1 ignore_zero_blocks', ' 0', ' trailing'):
            with self.subTest(option=option), self.assertRaises(ValueError):
                verity.decode_table(response(options=option), expected_device=64768, root_digest=ROOT)

    def test_rejects_unusable_mapping_states(self):
        for flags in (48, 51, 49|64, 49|256, 1, 49|(1<<30)):
            with self.subTest(flags=flags), self.assertRaises(ValueError):
                verity.decode_table(response(flags=flags), expected_device=64768, root_digest=ROOT)

    def test_rejects_multiple_targets_offset_extent_and_foreign_device(self):
        for kwargs in ({'count':2}, {'kind':b'linear'}, {'start':1}, {'sectors':799}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                verity.decode_table(response(**kwargs), expected_device=64768, root_digest=ROOT)
        with self.assertRaises(ValueError):
            verity.decode_table(response(), expected_device=64769, root_digest=ROOT)

    def test_rejects_invalid_verity_geometry_or_algorithm(self):
        original = f'1 7:0 7:1 4096 4096 100 1 sha256 {ROOT} -'
        for params in (original.replace('sha256','sha1'), original.replace('4096','512',1),
                       original.replace('100','0'), original.replace('1 7:0','0 7:0'),
                       original.replace('7:0','-7:0'), original.replace('100','0100'),
                       original.replace(' -',' 123'), original.replace('100',str(2**64))):
            with self.subTest(params=params), self.assertRaises(ValueError):
                verity.decode_table(response(params=params), expected_device=64768, root_digest=ROOT)

    def test_rejects_truncated_and_oversized_responses(self):
        raw = response()
        for data in (b'', raw[:100], raw[:-1], raw+b'x'*65536):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                verity.decode_table(data, expected_device=64768, root_digest=ROOT)

    def test_rejects_caller_digest_shape_and_nonexact_types(self):
        for digest in ('', ROOT.upper(), 'x'*64, None):
            with self.subTest(digest=digest), self.assertRaises(ValueError):
                verity.decode_table(response(), expected_device=64768, root_digest=digest)
        with self.assertRaises(ValueError):
            verity.decode_table(bytearray(response()), expected_device=64768, root_digest=ROOT)

    def test_accepts_valid_salt_and_kernel_zero_padding(self):
        raw = response(params=f'1 7:0 7:1 4096 4096 100 1 sha256 {ROOT} aabb')
        table = verity.decode_table(raw+b'\0'*100, expected_device=64768, root_digest=ROOT)
        self.assertEqual(table.salt, 'aabb')

    def test_terminal_extent_is_exact_and_aligned(self):
        for next_value in (0, 41, 141, 152, 20000):
            raw=bytearray(response())
            struct.pack_into('=I',raw,HEADER.size+20,next_value)
            with self.subTest(next=next_value), self.assertRaises(ValueError):
                verity.decode_table(bytes(raw),expected_device=64768,root_digest=ROOT)
        for field_offset,value in ((16,313),(16,320),(12,HEADER.size),(12,20000)):
            raw=bytearray(response());struct.pack_into('=I',raw,field_offset,value)
            with self.subTest(field=field_offset,value=value), self.assertRaises(ValueError):
                verity.decode_table(bytes(raw),expected_device=64768,root_digest=ROOT)

    def test_detects_changed_kernel_table_in_equality(self):
        old = verity.decode_table(response(), expected_device=64768, root_digest=ROOT)
        new = verity.decode_table(response(event=8), expected_device=64768, root_digest=ROOT)
        self.assertNotEqual(old, new)


class RetainedDeviceTests(unittest.TestCase):
    def owner(self):
        owner = object.__new__(verity.VerityDevice)
        owner._owner = os.getpid(), threading.current_thread()
        owner._fds = [90, 91]
        owner._closed = owner._fenced = False
        owner._clock = mock.Mock()
        owner._identities = ('block', 'control')
        owner.table = verity.decode_table(response(), expected_device=64768, root_digest=ROOT)
        return owner

    def test_standard_root_disk_block_node_does_not_override_readonly_table(self):
        block = (1, 2, stat.S_IFBLK|0o660, 0, 6, 64768)
        control = (1, 3, stat.S_IFCHR|0o600, 0, 0, os.makedev(10,236))
        verity._admit_devices(block, control, 64768)
        for bad in ((1,3,stat.S_IFCHR|0o660,0,6,os.makedev(10,236)),
                    (1,3,stat.S_IFCHR|0o600,0,0,os.makedev(10,237))):
            with self.assertRaises(ValueError): verity._admit_devices(block,bad,64768)
        with self.assertRaises(ValueError): verity._admit_devices(block,control,64769)

    def test_partial_open_failure_closes_only_acquired_fd(self):
        with mock.patch.object(verity.os,'geteuid',return_value=0), \
             mock.patch.object(verity.os,'getegid',return_value=0), \
             mock.patch.object(verity,'ResourceClock'), \
             mock.patch('builtins.open',mock.mock_open(read_data=b'DEVNAME=dm-0\n')), \
             mock.patch.object(verity.os,'open',side_effect=[90,OSError('control unavailable')]), \
             mock.patch.object(verity.os,'close') as close:
            with self.assertRaisesRegex(OSError,'control unavailable'):
                verity.VerityDevice._open(64768,ROOT,object())
            close.assert_called_once_with(90)

    def test_ioctl_failure_retains_original_error_and_closes_both(self):
        block=(1,2,stat.S_IFBLK|0o660,0,6,64768)
        control=(1,3,stat.S_IFCHR|0o600,0,0,os.makedev(10,236))
        with mock.patch.object(verity.os,'geteuid',return_value=0), \
             mock.patch.object(verity.os,'getegid',return_value=0), \
             mock.patch.object(verity,'ResourceClock'), \
             mock.patch('builtins.open',mock.mock_open(read_data=b'DEVNAME=dm-0\n')), \
             mock.patch.object(verity.os,'open',side_effect=[90,91]), \
             mock.patch.object(verity,'_signature',side_effect=[block,control]), \
             mock.patch.object(verity.fcntl,'ioctl',side_effect=OSError('query failed')), \
             mock.patch.object(verity.os,'close',side_effect=[OSError('close uncertain'),None]) as close:
            with self.assertRaisesRegex(OSError,'query failed') as raised:
                verity.VerityDevice._open(64768,ROOT,object())
            self.assertEqual(close.call_args_list,[mock.call(91),mock.call(90)])
            self.assertEqual(str(raised.exception.verity_cleanup_error),'close uncertain')

    def test_changed_table_permanently_fences_owner(self):
        owner = self.owner()
        changed = verity.decode_table(response(event=8), expected_device=64768, root_digest=ROOT)
        with mock.patch.object(verity, '_signature', side_effect=['block','control']), \
             mock.patch.object(owner, '_query', return_value=changed):
            with self.assertRaises(ValueError): owner.check()
        with mock.patch.object(owner, '_query', return_value=owner.table) as query:
            with self.assertRaises(ValueError): owner.check()
            query.assert_not_called()

    def test_close_attempts_each_descriptor_once_even_if_first_fails(self):
        owner = self.owner()
        with mock.patch.object(verity.os, 'close', side_effect=[OSError('uncertain'), None]) as close:
            with self.assertRaises(OSError): owner.close()
            owner.close()
            self.assertEqual(close.call_args_list, [mock.call(91), mock.call(90)])
        with self.assertRaises(ValueError): owner.check()

    def test_original_clock_failure_fences_before_ioctl(self):
        owner = self.owner()
        owner._clock.check.side_effect = ValueError('expired')
        with mock.patch.object(owner, '_query') as query:
            with self.assertRaises(ValueError): owner.check()
            query.assert_not_called()
        self.assertTrue(owner._fenced)


if __name__ == '__main__':
    unittest.main()
