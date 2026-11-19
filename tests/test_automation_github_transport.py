"""Synthetic transport boundary tests; never invoke an installed client."""
import importlib
import unittest

from automation.live_contracts import Limits, LiveCode, LiveFailure
from automation.live_contracts import RunWindow, protect_worker
from test_automation_live_io import Kernel


class SessionKernel(Kernel):
    def __init__(self, *, token=b'SYNTHETIC_TOKEN\n', unsupported=False, body=b'[]'):
        super().__init__()
        self.token, self.unsupported, self.body = token, unsupported, body
        self.specs = []

    def protect_core(self):
        return True

    def launch(self, handle, spec, **deadlines):
        self.specs.append(spec)
        self.closed = self.input_closed = self.reaped = False
        self.eof = set()
        self.input = bytearray()
        values = {'gh_probe': b'gh version '+(b'0.0.0' if self.unsupported else b'2.103.3')+b' (2026-10-26)\n',
                  'curl_probe': b'curl 8.5.0 (synthetic)\nProtocols: http https\nFeatures: AsynchDNS HTTPS-proxy\n',
                  'credential': self.token, 'http': self.body}
        self.outputs = {'stdout': bytearray(values[spec.role]), 'stderr': bytearray()}
        if spec.role == 'http':
            self.outputs['headers'] = bytearray(b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(self.body)).encode()+b'\r\n\r\n')
        return super().launch(handle, spec, **deadlines)

    def read(self, handle, stream, maximum):
        if not self.outputs[stream]:
            self.eof.add(stream)
            return b''
        data = bytes(self.outputs[stream][:maximum])
        del self.outputs[stream][:len(data)]
        return data

    def write(self, handle, data):
        self.input.extend(data)
        return len(data)


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.api = importlib.import_module('automation.github_transport')

    def reject(self, function, *args, code=LiveCode.INVALID_HTTP_RESPONSE, **kwargs):
        with self.assertRaises(LiveFailure) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)
        self.assertNotIn('PRIVATE', str(caught.exception))

    def parse(self, headers, body=b'[]', **kwargs):
        return self.api.parse_response(headers, body, exit_code=kwargs.get('exit_code', 0),
                                       limits=kwargs.get('limits', Limits()))

    def test_routes_are_exact_and_dependencies_need_authorization(self):
        route = '/repos/Owner/Repo/issues?state=all&per_page=100&page=1'
        self.assertEqual(self.api.validate_route(route, 'Owner/Repo', authorized=None),
                         'https://api.github.com'+route)
        dependency = '/repos/Owner/Repo/issues/42/dependencies/blocked_by?per_page=100&page=10'
        self.assertEqual(self.api.validate_route(dependency, 'Owner/Repo', authorized=frozenset({42})),
                         'https://api.github.com'+dependency)
        for bad in (route.replace('page=1', 'page=01'), route.replace('page=1', 'page=11'),
                    route.replace('Owner', 'owner'), route+'&extra=PRIVATE', route+'#fragment',
                    'https://api.github.com'+route, route.replace('/issues?', '/%69ssues?'),
                    dependency, dependency.replace('/42/', '/43/')):
            with self.subTest(bad=bad):
                self.reject(self.api.validate_route, bad, 'Owner/Repo', authorized=None,
                            code=LiveCode.LIVE_DATA_INVALID)

    def test_response_keeps_only_actual_link_and_representation_bytes(self):
        response = self.parse(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Private: PRIVATE\r\n\r\n')
        self.assertEqual((response.status, response.body, dict(response.headers)), (200, b'[]', {}))
        response = self.parse(b'HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\n'
                              b'Transfer-Encoding: chunked\r\nLink: <next>; rel="next"\r\n\r\n')
        self.assertEqual(dict(response.headers), {'link': '<next>; rel="next"'})
        self.assertEqual(response.body, b'[]')

    def test_rejects_ambiguous_framing_and_incomplete_transfers(self):
        fields = [b'Content-Length: 2\r\ncontent-length: 2', b'Content-Length: 02',
                  b'Content-Length: +2', b'Content-Length: 3',
                  b'Content-Length: 2\r\nTransfer-Encoding: chunked',
                  b'Transfer-Encoding: gzip', b'Content-Encoding: gzip',
                  b'Link: a\r\nLINK: b', b'X: yes\r\n folded', b'X: PRIVATE\x00',
                  b'Bad Name: value', b'Content-Encoding: identity\r\nContent-Encoding: identity']
        for field in fields:
            with self.subTest(field=field):
                self.reject(self.parse, b'HTTP/1.1 200 OK\r\n'+field+b'\r\n\r\n')
        for header in (b'HTTP/1.1 200 OK\n\n', b'HTTP/1.1 200 OK\r\n',
                       b'HTTP/1.1 200 OK\r\n\r\nLink: PRIVATE\r\n',
                       b'HTTP/1.1 101 Switching Protocols\r\n\r\n',
                       b'HTTP/1.1 100 Continue\r\n\r\n'*9+b'HTTP/1.1 200 OK\r\n\r\n',
                       b'HTTP/1.1 200 OK\r\n\r\nHTTP/1.1 200 OK\r\n\r\n'):
            with self.subTest(header=header):
                self.reject(self.parse, header)
        self.reject(self.parse, b'HTTP/1.1 200 OK\r\n\r\n', exit_code=1)

    def test_no_body_statuses_and_size_limits(self):
        for status in (204, 304):
            self.reject(self.parse, f'HTTP/1.1 {status} No body\r\n\r\n'.encode())
            self.assertEqual(self.parse(f'HTTP/1.1 {status} No body\r\n\r\n'.encode(), b'').status, status)
        self.reject(self.parse, b'HTTP/1.1 200 OK\r\n\r\n', b'123', limits=Limits(body_bytes=2),
                    code=LiveCode.RESPONSE_LIMIT)
        self.reject(self.parse, b'HTTP/1.1 200 OK\r\nLink: abc\r\n\r\n', limits=Limits(link_bytes=2),
                    code=LiveCode.RESPONSE_LIMIT)

    def test_production_entry_always_denies(self):
        self.reject(self.api.production_session, object(), code=LiveCode.LIVE_NOT_AUTHORIZED)

    def session(self, kernel, limits=Limits()):
        window = RunWindow('synthetic', 'Owner/Repo', limits, 0, 85, 90)
        return self.api.LiveReadSession(window, kernel=kernel,
            clients=self.api.ClientPaths('/synthetic/gh', '/synthetic/curl'),
            environment={'GH_TOKEN': 'PRIVATE', 'HTTPS_PROXY': 'ordinary'},
            protection=protect_worker(kernel, window))

    def test_session_uses_one_credential_and_exact_private_config(self):
        kernel = SessionKernel()
        with self.session(kernel) as session:
            response = session.get('/repos/Owner/Repo/issues?state=all&per_page=100&page=1')
            session.authorize_dependencies((42,))
            session.get('/repos/Owner/Repo/issues/42/dependencies/blocked_by?per_page=100&page=1')
            session.succeed()
        self.assertEqual(response.body, b'[]')
        self.assertEqual([s.role for s in kernel.specs], ['gh_probe', 'curl_probe', 'credential', 'http', 'http'])
        self.assertEqual(kernel.specs[2].argv, ('/synthetic/gh', 'auth', 'token', '--hostname', 'github.com', '--no-refresh'))
        for spec in kernel.specs:
            self.assertNotIn('SYNTHETIC_TOKEN', repr(spec))
            self.assertNotIn('GH_TOKEN', spec.environment)
            self.assertEqual(spec.environment['HTTPS_PROXY'], 'ordinary')
            self.assertNotIn('SYNTHETIC_TOKEN', repr(spec.argv))
        http = kernel.specs[-1]
        self.assertEqual(http.argv[1], '--disable')
        self.assertNotIn('--location', http.argv)
        self.assertIn(b'Authorization: Bearer SYNTHETIC_TOKEN', http.input_bytes)
        receipt = session.receipt()
        self.assertEqual((receipt.attempts, receipt.response_bytes, receipt.statuses), (2, 4, (200, 200)))
        self.assertEqual((receipt.accounting, receipt.outcome, receipt.cleanup), ('complete', 'succeeded', 'confirmed'))
        self.assertEqual(session.close(), receipt)

    def test_invalid_credential_and_probe_failure_never_send_http(self):
        for token in (b'', b'abc\r\n', b'abc\nPRIVATE\n', b'bad"token\n', b'a'*4097+b'\n'):
            kernel = SessionKernel(token=token)
            with self.subTest(token_length=len(token)), self.assertRaises(LiveFailure):
                with self.session(kernel):
                    self.fail('invalid credential accepted')
            self.assertNotIn('http', [s.role for s in kernel.specs])
        kernel = SessionKernel(unsupported=True)
        with self.assertRaises(LiveFailure):
            with self.session(kernel):
                self.fail('unsupported client accepted')
        self.assertEqual([s.role for s in kernel.specs], ['gh_probe'])

    def test_bad_route_callback_and_budget_are_terminal_without_retry(self):
        route = '/repos/Owner/Repo/issues?state=all&per_page=100&page=1'
        for numbers in ([1], (True,), (1, 1), (0,), (2147483648,)):
            kernel = SessionKernel()
            session = self.session(kernel)
            session.__enter__()
            self.reject(session.authorize_dependencies, numbers, code=LiveCode.LIVE_DATA_INVALID)
            self.reject(session.get, route, code=LiveCode.LIVE_DATA_INVALID)
            self.assertEqual(len(kernel.specs), 3)
            session.close()
        kernel = SessionKernel()
        session = self.session(kernel, Limits(attempts=1))
        session.__enter__()
        session.get(route)
        self.reject(session.get, route, code=LiveCode.REQUEST_BUDGET_EXHAUSTED)
        self.assertEqual(session.close().attempts, 1)
        self.assertEqual(len(kernel.specs), 4)

    def test_partial_overflow_keeps_observed_counts_but_no_response(self):
        kernel = SessionKernel(body=b'12345')
        session = self.session(kernel, Limits(body_bytes=2))
        session.__enter__()
        self.reject(session.get, '/repos/Owner/Repo/issues?state=all&per_page=100&page=1', code=LiveCode.RESPONSE_LIMIT)
        receipt = session.close()
        self.assertEqual((receipt.attempts, receipt.response_bytes, receipt.statuses), (1, 3, ()))
        self.assertEqual((receipt.accounting, receipt.outcome), ('partial', 'failed'))

    def test_empty_dependency_authorization_and_replay_are_terminal(self):
        for replay in (False, True):
            kernel = SessionKernel()
            session = self.session(kernel)
            session.__enter__()
            session.authorize_dependencies(())
            if replay:
                self.reject(session.authorize_dependencies, (), code=LiveCode.LIVE_DATA_INVALID)
            else:
                self.reject(session.get, '/repos/Owner/Repo/issues/1/dependencies/blocked_by?per_page=100&page=1',
                            code=LiveCode.LIVE_DATA_INVALID)
            self.assertEqual(session.close().attempts, 0)
            self.assertEqual(len(kernel.specs), 3)

    def test_clean_output_prefix_with_failed_exit_never_returns_response(self):
        kernel = SessionKernel()
        original = kernel.launch
        def launch(handle, spec, **deadlines):
            if spec.role == 'http':
                kernel.exit_code = 1
            return original(handle, spec, **deadlines)
        kernel.launch = launch
        session = self.session(kernel)
        session.__enter__()
        self.reject(session.get, '/repos/Owner/Repo/issues?state=all&per_page=100&page=1',
                    code=LiveCode.TRANSPORT_UNAVAILABLE)
        receipt = session.close()
        self.assertEqual((receipt.attempts, receipt.response_bytes, receipt.statuses), (1, 2, ()))
        self.assertEqual(receipt.accounting, 'complete')
        self.assertEqual(receipt.outcome, 'failed')

    def test_aggregate_body_limit_charges_only_first_overflow_byte(self):
        kernel = SessionKernel()
        session = self.session(kernel, Limits(total_body_bytes=3))
        session.__enter__()
        session.get('/repos/Owner/Repo/issues?state=all&per_page=100&page=1')
        self.reject(session.get, '/repos/Owner/Repo/issues?state=all&per_page=100&page=2',
                    code=LiveCode.RESPONSE_LIMIT)
        receipt = session.close()
        self.assertEqual((receipt.attempts, receipt.response_bytes, receipt.statuses), (2, 4, (200,)))
        self.assertEqual(receipt.accounting, 'partial')


if __name__ == '__main__':
    unittest.main()
