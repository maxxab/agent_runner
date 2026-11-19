"""Guardian frames preserve provenance; byte parsing grants no authority."""
import unittest


class GuardianProtocolTests(unittest.TestCase):
    def parser(self, **kwargs):
        from automation.control_guardian_protocol import Parser
        return Parser(**kwargs)

    @staticmethod
    def frame(kind, payload):
        return kind + len(payload).to_bytes(4, 'big') + payload

    def test_fragmented_app_bytes_cannot_mint_status(self):
        parser = self.parser(direction='output', output_limit=128)
        raw = self.frame(b'O', self.frame(b'S', b'CHILD_RELEASED'))
        parser.feed(raw[:3])
        self.assertIsNone(parser.pop())
        parser.feed(raw[3:])
        self.assertEqual(parser.pop(), (b'O', self.frame(b'S', b'CHILD_RELEASED')))
        self.assertIsNone(parser.pop())

    def test_direction_and_status_are_closed(self):
        for direction, kind, payload in [('input', b'S', b'ARMED'),
                                         ('output', b'I', b'hello'),
                                         ('output', b'S', b'EXECUTED'),
                                         ('output', b'X', b'')]:
            parser = self.parser(direction=direction, output_limit=128)
            with self.subTest(direction=direction, kind=kind), self.assertRaises(ValueError):
                parser.feed(self.frame(kind, payload))
                parser.pop()
            with self.assertRaises(ValueError):
                parser.feed(self.frame(b'O', b'valid'))

    def test_output_quota_is_cumulative(self):
        parser = self.parser(direction='output', output_limit=3)
        parser.feed(self.frame(b'O', b'ab') + self.frame(b'E', b'cd'))
        self.assertEqual(parser.pop(), (b'O', b'ab'))
        with self.assertRaises(ValueError):
            parser.pop()

    def test_incomplete_oversize_and_buffer_exhaustion_close_parser(self):
        for raw in (b'O\x00', b'O' + (65537).to_bytes(4, 'big'), b'X' * 131073):
            parser = self.parser(direction='output', output_limit=128)
            with self.subTest(size=len(raw)), self.assertRaises(ValueError):
                parser.feed(raw)
                parser.pop()
                parser.finish()
            with self.assertRaises(ValueError):
                parser.feed(b'')

    def test_one_pop_is_bounded_and_eof_is_terminal(self):
        parser = self.parser(direction='input', output_limit=128)
        parser.feed(self.frame(b'I', b'') * 100)
        for _ in range(100):
            self.assertEqual(parser.pop(), (b'I', b''))
        parser.finish()
        with self.assertRaises(ValueError):
            parser.pop()

    def test_only_exact_statuses_and_bounded_inputs(self):
        parser = self.parser(direction='output', output_limit=128)
        for status in (b'ARMED', b'CHILD_RELEASED'):
            parser.feed(self.frame(b'S', status))
            self.assertEqual(parser.pop(), (b'S', status))
        for kwargs in ({'direction': 'both', 'output_limit': 1},
                       {'direction': 'output', 'output_limit': True},
                       {'direction': 'output', 'output_limit': 16777217}):
            with self.assertRaises(ValueError):
                self.parser(**kwargs)


if __name__ == '__main__':
    unittest.main()
