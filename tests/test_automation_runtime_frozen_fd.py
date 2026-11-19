"""Inert fdinfo grammars, without process observation or lifecycle authority."""
import dataclasses
import unittest

from automation import control_runtime_proc as proc


CLOEXEC = 0o2000000
NONBLOCK = 0o4000


def common(flags, inode=42):
    return f'pos:\t0\nflags:\t0{flags:o}\nmnt_id:\t5\nino:\t{inode}\n'.encode()


def watch(fd=4, events=0x19, data=0, inode=42, device=17):
    return (f'tfd: {fd:8d} events: {events:8x} data: {data:16x} '
            f' pos:0 ino:{inode:x} sdev:{device:x}\n').encode()


EVENTFD = (b'eventfd-count:                0\neventfd-id: 0\n'
           b'eventfd-semaphore: 0\n')
TIMER = (b'clockid: 7\nticks: 0\nsettime flags: 01\n'
         b'it_value: (3, 12)\nit_interval: (0, 0)\n')


class FrozenFDGrammarTests(unittest.TestCase):
    def parse(self, raw, kind):
        return proc._parse_frozen_fdinfo(raw, kind)

    def test_supported_common_roles_and_immutable_data(self):
        for flags in (0, 1, NONBLOCK, 1 | NONBLOCK,
                      NONBLOCK | CLOEXEC, 1 | NONBLOCK | CLOEXEC):
            with self.subTest(flags=flags):
                value = self.parse(common(flags), 'pipe')
                self.assertEqual((value.kind, value.flags, value.mount_id, value.inode,
                                  value.details), ('pipe', flags, 5, 42, ()))
                with self.assertRaises(dataclasses.FrozenInstanceError):
                    value.flags = 0

    def test_eventfd_counter_id_and_semaphore_exact_emitter(self):
        value = self.parse(common(2 | NONBLOCK | CLOEXEC) + EVENTFD, 'eventfd')
        self.assertEqual(value.details, (0, 0, 0))
        large = EVENTFD.replace(b'               0', b'fffffffffffffffe').replace(
            b'id: 0', b'id: 2147483647')
        self.assertEqual(self.parse(common(2 | NONBLOCK | CLOEXEC) + large,
                                    'eventfd').details, (2**64 - 2, 2**31 - 1, 0))

    def test_epoll_empty_and_bounded_watch_data(self):
        head = common(2 | CLOEXEC)
        self.assertEqual(self.parse(head, 'eventpoll').details, ())
        value = self.parse(head + watch(data=2**64 - 1, events=0xc000201d), 'eventpoll')
        self.assertEqual(value.details, ((4, 0xc000201d, 2**64 - 1, 0, 42, 17),))
        self.assertEqual(len(self.parse(head + b''.join(watch(fd=n) for n in range(64)),
                                        'eventpoll').details), 64)

    def test_guardian_timer_is_relative_data_not_deadline(self):
        value = self.parse(common(2 | NONBLOCK | CLOEXEC) + TIMER, 'timerfd')
        self.assertEqual(value.details, (7, 0, 1, 3_000_000_012, 0))
        self.assertFalse(hasattr(value, 'deadline'))
        largest = TIMER.replace(b'(3, 12)', b'(9223372036, 854775807)')
        self.assertEqual(self.parse(common(2 | NONBLOCK | CLOEXEC) + largest,
                                    'timerfd').details[3], 2**63 - 1)

    def test_common_rejects_noncanonical_missing_extra_unknown_and_bounds(self):
        good = common(0)
        bad = [None, bytearray(good), b'', good[:-1], good + b'\n', good + b'lock:\t1\n',
               good + b'ino:\t42\n', good.replace(b'pos:\t0', b'pos:\t-0'),
               good.replace(b'pos:\t0', b'pos:\t1'), good.replace(b'00\n', b'000\n'),
               good.replace(b'mnt_id:\t5', b'mnt_id:\t0'),
               good.replace(b'mnt_id:\t5', b'mnt_id:\t2147483648'),
               good.replace(b'ino:\t42', b'ino:\t0'),
               good.replace(b'ino:\t42', b'ino:\t18446744073709551616'),
               good.replace(b'ino:\t42', b'ino:\t042'), good.replace(b'\n', b'\r\n'),
               good.replace(b'\t', b' '), good + b'\0', b'x' * 16385,
               b'flags:\t00\npos:\t0\nmnt_id:\t5\nino:\t42\n']
        for raw in bad:
            with self.subTest(raw=repr(raw)[:80]), self.assertRaises(ValueError):
                self.parse(raw, 'pipe')
        for kind in ('future', '', None, b'pipe'):
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                self.parse(good, kind)

    def test_exact_role_flags_no_optional_or_unknown_bits(self):
        for kind, tail, flags in (
                ('pipe', b'', 2), ('pipe', b'', CLOEXEC),
                ('pipe', b'', 0o100000), ('eventpoll', b'', 2),
                ('eventpoll', b'', 2 | NONBLOCK | CLOEXEC),
                ('eventfd', EVENTFD, 2 | CLOEXEC),
                ('timerfd', TIMER, 2 | NONBLOCK)):
            with self.subTest(kind=kind, flags=flags), self.assertRaises(ValueError):
                self.parse(common(flags) + tail, kind)

    def test_eventfd_rejects_shape_overflow_and_semaphore(self):
        head = common(2 | NONBLOCK | CLOEXEC)
        bad = [EVENTFD + b'extra: 0\n', EVENTFD + b'eventfd-id: 0\n',
               EVENTFD.replace(b'               0', b'ffffffffffffffff'),
               EVENTFD.replace(b'               0', b'               A'),
               EVENTFD.replace(b'               0', b'0'),
               EVENTFD.replace(b'id: 0', b'id: -1'),
               EVENTFD.replace(b'id: 0', b'id: 2147483648'),
               EVENTFD.replace(b'id: 0', b'id: 00'),
               EVENTFD.replace(b'semaphore: 0', b'semaphore: 1')]
        for raw in bad:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.parse(head + raw, 'eventfd')

    def test_epoll_rejects_bad_width_duplicate_unknown_and_watch_bounds(self):
        head = common(2 | CLOEXEC)
        bad = [watch() + watch(), b''.join(watch(fd=n) for n in range(65)),
               watch(fd=-1), watch(fd=2**31), watch(events=0), watch(events=8),
               watch(events=0x10000001), watch(events=0x20000001),
               watch(events=2**32 + 1), watch(data=2**64), watch(inode=0),
               watch(inode=2**64), watch(device=2**32),
               watch().replace(b'       4', b'4'),
               watch().replace(b'ino:2a', b'ino:02a'),
               watch().replace(b'ino:2a', b'ino:2A'),
               watch().replace(b'pos:0', b'pos:1'), watch() + b'unknown: 1\n']
        for raw in bad:
            with self.subTest(raw=raw[:100]), self.assertRaises(ValueError):
                self.parse(head + raw, 'eventpoll')

    def test_guardian_timer_rejects_expired_disarmed_or_ambiguous_schema(self):
        head = common(2 | NONBLOCK | CLOEXEC)
        bad = [TIMER + b'ticks: 0\n', TIMER.replace(b'clockid: 7', b'clockid: 1'),
               TIMER.replace(b'ticks: 0', b'ticks: 1'),
               TIMER.replace(b'flags: 01', b'flags: 00'),
               TIMER.replace(b'flags: 01', b'flags: 03'),
               TIMER.replace(b'(3, 12)', b'(0, 0)'),
               TIMER.replace(b'(3, 12)', b'(3, 1000000000)'),
               TIMER.replace(b'(3, 12)', b'(9223372037, 0)'),
               TIMER.replace(b'(3, 12)', b'(9223372036, 854775808)'),
               TIMER.replace(b'(3, 12)', b'(03, 12)'),
               TIMER.replace(b'(3, 12)', b'(3,12)'),
               TIMER.replace(b'interval: (0, 0)', b'interval: (0, 1)'),
               TIMER.replace(b'interval: (0, 0)', b'interval: (1, 0)')]
        for raw in bad:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.parse(head + raw, 'timerfd')


if __name__ == '__main__':
    unittest.main()
