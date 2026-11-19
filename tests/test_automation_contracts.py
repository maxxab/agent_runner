"""Untrusted JSON bytes obey one encoding and finite-number contract."""
import math
import unittest

from automation.contracts import load_json


class JSONContractTests(unittest.TestCase):
    def test_utf16_and_utf32_are_rejected_with_or_without_bom(self):
        for encoding in ('utf-16', 'utf-16-le', 'utf-16-be',
                         'utf-32', 'utf-32-le', 'utf-32-be'):
            for container in (bytes, bytearray):
                with self.subTest(encoding=encoding, container=container):
                    with self.assertRaises(ValueError):
                        load_json(container('{"value": 1}'.encode(encoding)))

    def test_numeric_overflow_is_rejected_at_every_json_position(self):
        for token in ('1e400', '-1e400', '1.7976931348623159e308'):
            for template in ('%s', '[%s]', '{"unused":%s}'):
                with self.subTest(token=token, template=template):
                    with self.assertRaisesRegex(ValueError, 'nonfinite'):
                        load_json((template % token).encode('utf-8'))

    def test_valid_unicode_bom_and_existing_text_input_are_preserved(self):
        document = '{"text":"مرحبا 😀", "escaped":"\\u00e9"}'
        expected = {'text': 'مرحبا 😀', 'escaped': 'é'}
        for raw in (document, document.encode('utf-8'),
                    bytearray(document.encode('utf-8')), document.encode('utf-8-sig')):
            with self.subTest(kind=type(raw)):
                self.assertEqual(load_json(raw), expected)
        with self.assertRaises(ValueError):
            load_json('\ufeff' + document)

    def test_size_limit_counts_original_bytes_including_bom(self):
        for raw in ('"é"'.encode('utf-8'), '"é"'.encode('utf-8-sig')):
            with self.subTest(raw=raw):
                self.assertEqual(load_json(raw, max_bytes=len(raw)), 'é')
                with self.assertRaisesRegex(ValueError, 'size limit'):
                    load_json(raw, max_bytes=len(raw)-1)

    def test_valid_floats_and_exact_integers_keep_existing_semantics(self):
        result = load_json(b'[1.25, -0.0, 1.7976931348623157e308, 1e-400, 9007199254740993]')
        self.assertEqual(result, [1.25, -0.0, 1.7976931348623157e308, 0.0, 9007199254740993])
        self.assertEqual(math.copysign(1, result[1]), -1)
        self.assertIs(type(result[-1]), int)
        self.assertTrue(all(math.isfinite(value) for value in result[:-1]))

    def test_duplicate_keys_nonfinite_literals_and_bad_utf8_still_fail(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":{"y":1,"y":2}}',
                    b'NaN', b'Infinity', b'-Infinity', b'"\xff"', b'"\xc0\xaf"', b'{} trailing'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                load_json(raw)
