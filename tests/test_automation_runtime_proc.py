"""Inert supported-kernel grammar checks, not process acceptance."""
import unittest

from automation.control_runtime_proc import _parse_stat52, _parse_mountinfo


def stat_record(**changes):
    fields = ['0'] * 49  # fields4..52; synthetic values in the supported layout
    for number, value in {4: '1', 8: '-1', 18: '20', 19: '-5', 20: '3',
                          22: '123456', 25: '18446744073709551615',
                          38: '17', 39: '2', **changes}.items():
        fields[int(number)-4] = value
    return b'42 (name ) space) S ' + ' '.join(fields).encode() + b'\n'


MOUNT = b'36 35 253:0 / /rnr ro,nosuid,nodev shared:1 - squashfs /dev/mapper/root ro\n'


class StatGrammarTests(unittest.TestCase):
    def test_identity_indices_and_signed_fields(self):
        value = _parse_stat52(stat_record())
        self.assertEqual((value.pid, value.comm, value.state), (42, b'name ) space', b'S'))
        self.assertEqual((value.ppid, value.threads, value.start_ticks), (1, 3, 123456))
        self.assertEqual(value.numbers[25-4], 2**64-1)
        self.assertEqual(value.numbers[19-4], -5)

    def test_kernel_states_are_data_including_dead_and_parked(self):
        for state in b'RSDTtXZPI':
            self.assertEqual(_parse_stat52(stat_record().replace(b') S ', b') '+bytes([state])+b' ')).state,
                             bytes([state]))

    def test_malformed_and_unsupported_records(self):
        raw = stat_record()
        cases = [None, bytearray(raw), b'', raw[:-1], raw+b'\n', raw+b'0\n',
                 raw.replace(b'42 (', b'042 ('), raw.replace(b') S ', b') W '),
                 raw.replace(b') S ', b')  S '), raw.replace(b' S ', b'\x00S '),
                 raw.replace(b'42 (name ) space)', b'42 ('+b'a'*16+b')'),
                 raw.replace(b'42 (name ) space)', b'42 (bad\nname)'),
                 b'42 (comm) S '+b'0 '*47+b'0\n',  # too few fields
                 raw.replace(b' S ', b' S\t'), b'x'*4097]
        for case in cases:
            with self.subTest(case=str(case)[:80]), self.assertRaises(ValueError):
                _parse_stat52(case)

    def test_numeric_limits_and_canonical_forms(self):
        for field, token in [(4, '-1'), (4, str(2**31)), (8, str(-2**31-1)),
                             (9, str(2**32)), (10, '-1'), (10, str(2**64)),
                             (16, str(2**63)), (19, '-0'), (22, '+1'),
                             (22, '01'), (22, '1e2'), (22, '1_000'), (52, '--1')]:
            with self.subTest(field=field, token=token), self.assertRaises(ValueError):
                _parse_stat52(stat_record(**{str(field): token}))


class MountGrammarTests(unittest.TestCase):
    def test_exact_fields_and_namespace_local_ids(self):
        (value,) = _parse_mountinfo(MOUNT)
        self.assertEqual((value.mount_id, value.parent_id, value.device), (36, 35, (253, 0)))
        self.assertEqual((value.root, value.point, value.fs_type), (b'/', b'/rnr', b'squashfs'))
        self.assertEqual(value.options, (b'ro', b'nosuid', b'nodev'))
        self.assertEqual(value.optional, ((b'shared', 1),))

    def test_stacked_points_preserved_without_collapsing(self):
        records = _parse_mountinfo(MOUNT+MOUNT.replace(b'36 35 ', b'37 36 '))
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0].point, records[1].point)
        self.assertNotEqual(records[0].mount_id, records[1].mount_id)

    def test_nsfs_kernel_root_label_is_not_a_path(self):
        raw = b'562 119 0:4 net:[4026532230] /run/docker/netns/probe rw shared:245 - nsfs nsfs rw\n'
        self.assertEqual(_parse_mountinfo(raw)[0].root, b'net:[4026532230]')
        for replacement in (b'net:[04026532230]', b'net:[4294967296]', b'future:[42]', b'net:[0]'):
            with self.subTest(root=replacement), self.assertRaises(ValueError):
                _parse_mountinfo(raw.replace(b'net:[4026532230]', replacement))
        with self.assertRaises(ValueError):
            _parse_mountinfo(raw.replace(b' - nsfs ', b' - ext4 '))

    def test_paths_decode_once_and_source_need_not_be_absolute(self):
        raw = b'40 35 0:1 /with\\040space /a\\134040b rw master:2 propagate_from:3 - 9p C:\\134 rw,aname=drvfs\n'
        (value,) = _parse_mountinfo(raw)
        self.assertEqual((value.root, value.point, value.source), (b'/with space', b'/a\\040b', b'C:\\'))
        self.assertEqual(value.optional, ((b'master', 2), (b'propagate_from', 3)))
        self.assertEqual(_parse_mountinfo(MOUNT.replace(b'/dev/mapper/root', b'-'))[0].source, b'-')

    def test_source_hash_mangle_differs_from_path_escaping(self):
        raw = MOUNT.replace(b'/dev/mapper/root', b'/dev/name\\043tag')
        self.assertEqual(_parse_mountinfo(raw)[0].source, b'/dev/name#tag')
        self.assertEqual(_parse_mountinfo(MOUNT.replace(b' /rnr ', b' /rnr#tag '))[0].point, b'/rnr#tag')
        for case in (MOUNT.replace(b'/dev/mapper/root', b'/dev/name#tag'),
                     MOUNT.replace(b' /rnr ', b' /rnr\\043tag ')):
            with self.subTest(case=case), self.assertRaises(ValueError):
                _parse_mountinfo(case)

    def test_unknown_propagation_and_ambiguous_options_reject(self):
        for old, new in [(b'shared:1', b'future:1'), (b'shared:1', b'shared:1 shared:2'),
                         (b'shared:1', b'unbindable shared:1'),
                         (b'ro,nosuid,nodev', b'ro,rw'), (b'ro,nosuid,nodev', b'ro,ro'),
                         (b'ro,nosuid,nodev', b'ro,size=1,size=2'),
                         (b'ro,nosuid,nodev', b'ro,,nodev')]:
            with self.subTest(new=new), self.assertRaises(ValueError):
                _parse_mountinfo(MOUNT.replace(old, new))

    def test_malformed_bounds_duplicates_and_paths(self):
        cases = [None, bytearray(MOUNT), b'', MOUNT[:-1], MOUNT+b'\n', MOUNT+MOUNT,
                 MOUNT.replace(b'36 35', b'036 35'), MOUNT.replace(b'253:0', b'253:00'),
                 MOUNT.replace(b'253:0', b'4294967296:0'), MOUNT.replace(b' /rnr ', b' rnr '),
                 MOUNT.replace(b' /rnr ', b' /a/../rnr '), MOUNT.replace(b' /rnr ', b' /rnr//x '),
                 MOUNT.replace(b' /rnr ', b' /rnr\\000 '), MOUNT.replace(b' /rnr ', b' /rnr\\041 '),
                 MOUNT.replace(b' /rnr ', b' /rnr\x00 '), MOUNT.replace(b' - ', b'  - '),
                 MOUNT.replace(b' - ', b' - - '), MOUNT.replace(b' squashfs ', b' x/y '),
                 MOUNT.replace(b' /rnr ', b' /'+b'a'*4096+b' '), b'x'*1048577]
        for case in cases:
            with self.subTest(case=str(case)[:80]), self.assertRaises(ValueError):
                _parse_mountinfo(case)


if __name__ == '__main__':
    unittest.main()
