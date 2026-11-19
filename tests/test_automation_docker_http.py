"""Closed Docker HTTP byte grammar only; no sockets/daemon/runtime."""
import json
import unittest
from automation import control_docker_http as http

CID = 'a' * 64

def response(body=b'{}', status=b'200 OK', extra=b''):
    return b'HTTP/1.1 ' + status + b'\r\nContent-Type: application/json\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n' + extra + b'\r\n' + body


def drain(parser):
    for _ in range(8192):
        if not parser.step():
            return
    raise AssertionError('bounded parser failed to drain')


class DockerHTTPTests(unittest.TestCase):
    def parser(self, operation='inspect'):
        return http.Response(http.Request(operation, 'rnr-'+CID if operation == 'create' else CID, b'{}' if operation == 'create' else b''))

    def test_closed_request_paths_and_no_arbitrary_endpoint(self):
        self.assertIn(('/v1.51/containers/' + CID + '/start').encode(), http.Request('start', CID).encode())
        wire = http.Request('attach', CID).encode()
        self.assertIn(b'logs=0&stream=1&stdin=1&stdout=1&stderr=1', wire)
        self.assertIn(b'Connection: Upgrade\r\nUpgrade: tcp\r\n', wire)
        for op, ident, body in [('exec', CID, b''), ('inspect', '../bad', b''), ('start', CID, b'x'), ('image', 'tag', b'')]:
            with self.subTest(op=op), self.assertRaises(ValueError):
                http.Request(op, ident, body).encode()

    def test_every_split_of_finite_response_and_explicit_eof(self):
        wire = response(b'{"State":{}}')
        for cut in range(len(wire)+1):
            parser = self.parser()
            parser.feed(wire[:cut]); drain(parser)
            parser.feed(wire[cut:]); drain(parser)
            self.assertEqual(parser.value(), {'State': {}})
            parser.finish()

    def test_chunked_fragmentation_and_trailer_rejection(self):
        head = b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n'
        body = b'1\r\n{\r\n1\r\n}\r\n0\r\n\r\n'
        parser = self.parser()
        for byte in head+body:
            parser.feed(bytes([byte])); drain(parser)
        self.assertEqual(parser.value(), {})
        parser.finish()
        for bad in (b'1;x=y\r\n{\r\n0\r\n\r\n', b'0\r\nX: y\r\n\r\n', b'10001\r\n', b'000000000\r\n'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                p = self.parser(); p.feed(head+bad); drain(p)

    def test_ambiguous_headers_statuses_and_encoding_are_terminal(self):
        bad = [response(extra=b'Content-Length: 2\r\n'), response(extra=b'Transfer-Encoding: chunked\r\n'),
               response(extra=b'Content-Encoding: gzip\r\n'), response(extra=b' folded: bad\r\n'),
               response(extra=b'X-Test: bad\x00\r\n'), response(status=b'302 Redirect'),
               response(status=b'100 Continue'), response(extra=b'X: a\r\nx: b\r\n')]
        for wire in bad:
            parser = self.parser()
            with self.subTest(wire=wire), self.assertRaises(ValueError):
                parser.feed(wire); drain(parser)
            with self.assertRaises(ValueError): parser.feed(b'')

    def test_upgrade_requires_pinned_multiplexed_headers_and_preserves_raw(self):
        head = b'HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.multiplexed-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n'
        parser = self.parser('attach')
        parser.feed(head+b'abc'); drain(parser)
        self.assertTrue(parser.done)
        self.assertEqual(parser.raw_chunk(), b'abc')
        parser.feed(b'def')
        self.assertEqual(parser.raw_chunk(), b'def')
        for bad in (head.replace(b'101 UPGRADED',b'200 OK'), head.replace(b'multiplexed-stream',b'raw-stream'),
                    head.replace(b'Upgrade: tcp\r\n',b''), head.replace(b'\r\n\r\n',b'\r\nContent-Length: 0\r\n\r\n')):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                p = self.parser('attach'); p.feed(bad); drain(p)

    def test_no_content_and_trailing_or_truncated_data(self):
        parser = self.parser('start'); parser.feed(b'HTTP/1.1 204 No Content\r\n\r\n'); drain(parser); parser.finish()
        for wire in (response()+b'x', response(b'{"a":1}')[:-1], b'HTTP/1.1 200 OK\r\n'):
            with self.subTest(wire=wire), self.assertRaises(ValueError):
                p = self.parser(); p.feed(wire); drain(p); p.finish()

    def test_bounded_headers_feed_body_and_chunk_inventory(self):
        for wire in (b'X'*16385, b'HTTP/1.1 200 OK\r\nX:'+b'a'*2048+b'\r\n\r\n',
                     b'HTTP/1.1 200 OK\r\n'+b''.join(('X%d: a\r\n'%i).encode() for i in range(65))+b'\r\n',
                     b'HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n'):
            with self.subTest(length=len(wire)), self.assertRaises(ValueError):
                p = self.parser(); p.feed(wire); drain(p)
        with self.assertRaises(ValueError): self.parser().feed(b'x'*32769)
        p = self.parser(); p.feed(b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n'); drain(p)
        with self.assertRaises(ValueError):
            for _ in range(4097): p.feed(b'1\r\nx\r\n'); drain(p)

    def test_negative_exact_identity_routes_do_not_accept_mutable_aliases(self):
        p=http.Response(http.Request('absence',CID))
        p.feed(response(b'{"message":"not found"}',b'404 Not Found'));drain(p)
        self.assertEqual(p.value(),{'absent':True});p.finish()
        self.assertIn(('/containers/rnr-'+CID+'/json').encode(),http.Request('locate','rnr-'+CID).encode())
        with self.assertRaises(ValueError):http.Request('locate','arbitrary-name').encode()

    def test_bootstrap_lines_use_same_closed_bounded_json_decoder(self):
        self.assertEqual(http.decode_object(b'{"id":1,"result":{}}',limit=65536),{'id':1,'result':{}})
        for data in (b'{"id":999,"id":1,"result":{}}',b'[]',b'{"id":1.0}',b'x'*65537):
            with self.subTest(data=data[:30]),self.assertRaises(ValueError):
                http.decode_object(data,limit=65536)

    def test_json_duplicates_depth_types_and_create_warnings(self):
        for body in (b'{"a":1,"a":2}', b'{"a":1.5}', b'{"a":NaN}', b'{"a":"\xff"}', b'['*18+b'0'+b']'*18):
            with self.subTest(body=body), self.assertRaises(ValueError):
                p = self.parser(); p.feed(response(body)); drain(p); p.value()
        p = self.parser('create')
        body = json.dumps({'Id':CID,'Warnings':['weakened']}).encode()
        p.feed(response(body,b'201 Created')); drain(p)
        with self.assertRaises(ValueError): p.value()
        self.assertEqual(p.created_id, CID)  # retain exact cleanup target, never no-effect


if __name__ == '__main__': unittest.main()
