"""Synthetic wire tests; no installed runtime or SDK is imported."""
import importlib.util
import json
import queue
import threading
import time
import unittest


def wire(identity=1, **changes):
    params = dict(threadId='thread', turnId='turn', callId='call', tool='rnr_command',
                  arguments={'argv': ['echo', 'hello']})
    params.update(changes)
    return json.dumps({'id': identity, 'method': 'item/tool/call', 'params': params}).encode() + b'\n'


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('automation.control_transport'),
                             'strict bounded control transport is not implemented')
        from automation.control_transport import Transport, Bounds
        self.fences, self.output = [], []
        self.t = Transport(Bounds(frame_bytes=1024, argument_bytes=128, arguments=8,
                                  input_queue=4, output_queue=4, identities=20),
                           self.output.append, self.fences.append)
        self.addCleanup(self.t.close)

    def test_valid_request_retains_raw_and_identity(self):
        raw = wire()
        self.t.feed(raw[:20]); self.t.feed(raw[20:])
        event = self.t.events.get_nowait()
        self.assertEqual(event.kind, 'request')
        self.assertEqual(event.raw, raw[:-1])
        self.assertEqual(event.message['id'], 1)

    def test_strict_malformed_frames_fence_without_handoff(self):
        cases = [b'\xff\n', b'\xef\xbb\xbf{}\n', b'{"id":1,"id":2}\n',
                 b'{"id":NaN}\n', b'{"id":1e999}\n', b'[]\n', b'{}\n',
                 b'{"id":true,"method":"x","params":{}}\n',
                 b'{"id":1,"method":2,"params":{}}\n',
                 b'{"id":1,"method":"item/tool/call","params":[]}\n',
                 b'x' * 1025]
        from automation.control_transport import Transport
        for raw in cases:
            with self.subTest(raw=raw[:50]):
                fences = []
                t = Transport(self.t.bounds, lambda _: None, fences.append)
                try:
                    t.feed(raw)
                    self.assertTrue(fences)
                    self.assertTrue(t.events.empty())
                finally:
                    t.close()

    def test_argv_only_exact_and_bounded(self):
        from automation.control_transport import Transport
        for arguments in ({'argv': []}, {'argv': ['a\x00b']}, {'argv': ['a'], 'owner': 1},
                          {'argv': [2]}, {'argv': ['x' * 129]}, {'argv': ['x'] * 9}):
            fences = []
            t = Transport(self.t.bounds, lambda _: None, fences.append)
            try:
                t.feed(wire(arguments=arguments))
                self.assertTrue(fences)
                self.assertTrue(t.events.empty())
            finally:
                t.close()

    def test_inbound_and_outbound_ids_are_separate(self):
        self.t.expect_response(1)
        self.t.feed(wire())
        self.t.feed(b'{"id":1,"result":{}}\n')
        self.t.feed(b'{"method":"turn/completed","params":{}}\n')
        self.assertEqual([self.t.events.get_nowait().kind for _ in range(3)],
                         ['request', 'response', 'notification'])
        self.assertFalse(self.fences)

    def test_duplicate_inbound_and_unregistered_response_fence(self):
        self.t.feed(wire()); self.t.events.get_nowait()
        self.t.feed(wire())
        self.assertTrue(self.fences)
        self.assertTrue(self.t.events.empty())

    def test_unknown_response_fences(self):
        self.t.feed(b'{"id":7,"result":{}}\n')
        self.assertTrue(self.fences)

    def test_retained_builtin_and_unknown_tool_never_handoff(self):
        self.t.feed(b'{"id":1,"method":"item/commandExecution/requestApproval","params":{}}\n')
        self.assertTrue(self.fences)
        self.assertTrue(self.t.events.empty())

    def test_input_saturation_fences_nonblocking(self):
        for i in range(5):
            self.t.feed(wire(i, callId=str(i)))
        self.assertTrue(self.fences)
        self.assertEqual(self.t.events.qsize(), 4)

    def test_bounded_writer_and_actual_correlated_reply(self):
        self.assertTrue(self.t.reply(8, {'success': False, 'contentItems': []}))
        deadline = time.monotonic() + 1
        while not self.output and time.monotonic() < deadline:
            time.sleep(.005)
        self.assertEqual(json.loads(self.output[0]),
                         {'id': 8, 'result': {'success': False, 'contentItems': []}})

    def test_blocked_writer_deadline_and_saturation(self):
        from automation.control_transport import Transport
        entered, release = threading.Event(), threading.Event()
        def write(_):
            entered.set(); release.wait(2)
        fences = []
        t = Transport(self.t.bounds, write, fences.append)
        try:
            t.reply(1, {})
            self.assertTrue(entered.wait(1))
            self.assertFalse(t.writer_healthy(time.monotonic() + 1, .05))
            for n in range(6):
                t.reply(n + 2, {})
            self.assertTrue(fences)
        finally:
            release.set(); t.close()

    def test_pinned_saved_schema_binding(self):
        """Saved provenance only; never regenerate or launch to obtain a schema."""
        import hashlib
        import os
        from pathlib import Path
        root = Path(os.environ.get('RNR_SAVED_SCHEMA_ROOT',
            '/home/faris/.local/state/development-standards/lavish-reviews/preimplementation-x0ngvay0/cli-schema'))
        if not root.is_dir():
            self.skipTest('saved pinned schemas absent; set RNR_SAVED_SCHEMA_ROOT')
        hashes = {
            'v2/TurnStartParams.json': '062373a7dfc290b506e591bc5c2a35005211df27b3c60358cee3efed12859062',
            'v2/TurnStartResponse.json': '20e837d07826b9c01578ff40b962ab08f58a355a9984e96226733498514e9bad',
            'v2/TurnCompletedNotification.json': '69413578ec3ecd02691424bdeb9d640c7244b4ca4c5c3ef26f69a2efe7c37db8',
            'ServerNotification.json': '071ecc89ba71ce215e1ac01f6e05be509eafa533b2ba6fac43f4c05330305a83',
            'v2/ThreadStartParams.json': '80a40a7fac15b4bf70efb7f893fb353acc0a0d30c68f54aee4f01923deca85de',
            'DynamicToolCallParams.json': '401bba20cfbd95762bef0467d840430c46be53369093ad9f26425ba757e34efc',
            'DynamicToolCallResponse.json': 'abb082cad67f11fcc98ba75f2eff75d7d1723af0c657655329b83ff160451a02',
            'JSONRPCRequest.json': '31bd6f360b2dd8a7ceaf682708105d40d38cb0b9d0821357a04da67028438f73',
            'JSONRPCResponse.json': '4796738c04c74288213a08fb8d820c7b4df19e0977cdcd35b65ffcb43cfc93ab'}
        schemas = {}
        for name, digest in hashes.items():
            raw = (root / name).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(), digest)
            schemas[name] = json.loads(raw)
        from automation.control_transport import SUPPORTED_NOTIFICATIONS
        declared = {method for entry in schemas['ServerNotification.json']['oneOf']
                    for method in entry['properties']['method'].get('enum', [])}
        self.assertEqual(SUPPORTED_NOTIFICATIONS, {'turn/completed'})
        self.assertTrue(SUPPORTED_NOTIFICATIONS <= declared)
        fixture = json.loads(wire())
        self.assertEqual(set(fixture['params']), set(schemas['DynamicToolCallParams.json']['required']))
        self.assertTrue(set(schemas['JSONRPCRequest.json']['required']) <= set(fixture))
        self.assertTrue(set(fixture) <= set(schemas['JSONRPCRequest.json']['properties']))
        self.assertEqual(set(schemas['DynamicToolCallResponse.json']['required']), {'success', 'contentItems'})
        properties = schemas['v2/ThreadStartParams.json']['properties']
        self.assertIn('array', properties['environments']['type'])
        self.assertIn('array', properties['dynamicTools']['type'])
        start = schemas['v2/TurnStartParams.json']
        self.assertTrue({'threadId', 'input', 'environments', 'approvalPolicy', 'sandboxPolicy',
                         'model', 'effort', 'runtimeWorkspaceRoots'} <= set(start['properties']))
        sandbox = next(v for v in start['definitions']['SandboxPolicy']['oneOf']
                       if v['properties']['type'].get('enum') == ['dangerFullAccess'])
        self.assertEqual(set(sandbox['properties']), {'type'})
        self.assertEqual(set(schemas['v2/TurnStartResponse.json']['required']), {'turn'})
        self.assertEqual(set(schemas['v2/TurnCompletedNotification.json']['required']), {'threadId', 'turn'})
        turn = schemas['v2/TurnStartResponse.json']['definitions']['Turn']
        self.assertEqual(set(turn['required']), {'id', 'items', 'status'})
        self.assertEqual(set(turn['properties']), {'id', 'items', 'status', 'error', 'itemsView',
                                                 'rootTurnId', 'startedAt', 'completedAt', 'durationMs'})


    def test_partial_zero_and_invalid_write_completions_fence(self):
        """SR2/QA-F02: each callback must consume the complete supplied frame."""
        from automation.control_transport import Transport
        for count in (1, 0, -1, True, 'all', 10000):
            with self.subTest(count=count):
                fences, calls = [], []
                completed = threading.Event()
                def sink(raw):
                    calls.append(raw[:1]); completed.set(); return count
                t = Transport(self.t.bounds, sink, fences.append)
                try:
                    t.reply(7, {'success': True})
                    self.assertTrue(completed.wait(1))
                    deadline = time.monotonic() + .2
                    while not fences and time.monotonic() < deadline:
                        time.sleep(.002)
                    self.assertTrue(fences)
                    self.assertFalse(t.writer_healthy(time.monotonic(), 1))
                    t.reply(8, {'success': True})
                    self.assertEqual(len(calls), 1)
                finally:
                    t.close()

    def test_full_count_byte_sink_preserves_correlated_frame(self):
        from automation.control_transport import Transport
        frames, fences = [], []
        written = threading.Event()
        def sink(raw):
            frames.append(raw); written.set(); return len(raw)
        t = Transport(self.t.bounds, sink, fences.append)
        try:
            t.reply('exact', {'success': False})
            self.assertTrue(written.wait(1))
            self.assertEqual(json.loads(frames[0]), {'id': 'exact', 'result': {'success': False}})
            self.assertFalse(fences)
        finally:
            t.close()

    def test_unknown_notification_route_fences_without_handoff(self):
        self.t.feed(b'{"method":"unknown/control/route","params":{}}\n')
        self.assertTrue(self.fences)
        self.assertTrue(self.t.events.empty())


class TurnWireTests(unittest.TestCase):
    def policy(self):
        from automation.control_store import TurnPolicy
        return TurnPolicy('synthetic-model', 'synthetic-effort', 512, 2, 32)

    def test_fixed_frame_and_committed_fingerprint(self):
        from automation.control_transport import build_turn_start, Bounds
        from automation.control_store import canonical
        import hashlib
        policy = self.policy()
        ticket = dict(id='a' * 64, assignment='a', epoch=1, owner_version=1,
                      connection='c', generation='g', thread='t', intent='i', wire_id='w',
                      input_hash=hashlib.sha256(b'hello').hexdigest(),
                      policy_hash=policy.fingerprint(), deadline=100, purpose='work')
        bounds = Bounds(2048, 128, 8, 4, 4, 20)
        raw = build_turn_start(ticket, 'hello', policy, bounds)
        message = json.loads(raw)
        self.assertEqual(message, {'id': 'w', 'method': 'turn/start', 'params': {
            'threadId': 't', 'input': [{'type': 'text', 'text': 'hello', 'text_elements': []}],
            'environments': [], 'approvalPolicy': 'never',
            'sandboxPolicy': {'type': 'dangerFullAccess'}, 'model': policy.model,
            'effort': policy.effort, 'runtimeWorkspaceRoots': []}})
        for changes in ({'input_hash': 'b' * 64}, {'policy_hash': 'b' * 64}, {'thread': '\x85'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                build_turn_start(dict(ticket, **changes), 'hello', policy, bounds)
        with self.assertRaises(ValueError):
            build_turn_start(ticket, 'hello', policy, Bounds(32, 128, 8, 4, 4, 20))

    def test_closed_turn_subset_and_raw_object_fingerprint(self):
        from automation.control_transport import parse_turn_response, parse_turn_notification
        from automation.control_store import canonical
        import hashlib
        turn = {'id': 'server', 'items': [{'id': 'm', 'type': 'agentMessage', 'text': 'hi'}],
                'status': 'completed'}
        response = {'id': 'wire', 'result': {'turn': turn}}
        value = parse_turn_response(response, self.policy())
        self.assertEqual(value, ('server', 'completed', hashlib.sha256(canonical(turn).encode()).hexdigest()))
        notice = {'method': 'turn/completed', 'params': {'threadId': 'thread', 'turn': turn}}
        self.assertEqual(parse_turn_notification(notice, self.policy()), ('thread', *value))
        self.assertNotEqual(parse_turn_response({'id': 'wire', 'result': {'turn': dict(turn, itemsView='full')}},
                                              self.policy())[2], value[2])
        for changes in ({'id': True}, {'id': '\x85'}, {'id': 'é' * 129}, {'status': 'unknown'},
                        {'itemsView': 'notLoaded'}, {'durationMs': -1}, {'startedAt': True},
                        {'completedAt': 1.2}, {'rootTurnId': ''}, {'extra': None},
                        {'error': {'message': 'oops'}},
                        {'items': [{'id': 'm', 'type': 'agentMessage', 'text': 'x' * 33}]},
                        {'items': [{'id': 'm', 'type': 'agentMessage', 'text': '', 'phase': 'final'}]}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                parse_turn_response({'id': 'wire', 'result': {'turn': dict(turn, **changes)}}, self.policy())
        with self.assertRaises(ValueError):
            parse_turn_notification({'method': 'turn/completed', 'params': {
                'threadId': 'thread', 'turn': dict(turn, status='inProgress')}}, self.policy())
        with self.assertRaises(ValueError):
            parse_turn_response({'id': 'wire', 'result': {'turn': turn, 'threadId': 'forged'}}, self.policy())

    def test_failed_error_bounds_and_optional_null_fields(self):
        from automation.control_transport import parse_turn_response
        turn = {'id': 's', 'items': [], 'status': 'failed', 'error': {'message': '',
                'additionalDetails': None, 'codexErrorInfo': None, 'misalignment': None}}
        self.assertEqual(parse_turn_response({'id': 'w', 'result': {'turn': turn}}, self.policy())[1], 'failed')
        for error in ({'message': 'x' * 33}, {'message': 'x', 'codexErrorInfo': {}},
                      {'message': 'x', 'extra': None}, {'additionalDetails': None}):
            with self.subTest(error=error), self.assertRaises(ValueError):
                parse_turn_response({'id': 'w', 'result': {'turn': dict(turn, error=error)}}, self.policy())


    def test_task_nul_rejected_but_newline_tab_allowed(self):
        from automation.control_transport import bounded_text
        self.assertEqual(bounded_text('line\n\ttext', 32, nonempty=True), 'line\n\ttext')
        with self.assertRaises(ValueError):
            bounded_text('task\x00payload', 32, nonempty=True)


class ObservationProfileTests(unittest.TestCase):
    def setup_profile(self, *, events=30, text_bytes=8192, pending=8):
        import automation.control_transport as ct
        self.assertTrue(hasattr(ct, 'ObservationProfile'), 'pinned observation profile missing')
        from automation.control_store import ObservationBounds, TurnPolicy
        from tests.test_automation_control_bootstrap import fixture
        spec, responses = fixture()
        bounds = ct.Bounds(16384,1024,8,8,8,64)
        profile = ct.ObservationProfile(spec, ObservationBounds(events,text_bytes,pending),bounds)
        policy = TurnPolicy(spec.model,spec.effort,4096,8,1024)
        return ct, profile, policy, responses['thread_start']['thread']

    def event(self, method, params, **kwargs):
        from automation.control_transport import Event
        message=dict(method=method,params=params,**kwargs)
        return Event('notification',message,json.dumps(message).encode())

    def test_observations_require_committed_dispatch_then_response_binding(self):
        ct,p,policy,thread=self.setup_profile()
        p.bind_thread(thread)
        event=self.event('item/agentMessage/delta',dict(threadId='thread',turnId='turn',itemId='a',delta='hello'))
        with self.assertRaises(ValueError): ct.parse_observation(event,policy,p)
        p.dispatched('intent')
        result=ct.parse_observation(event,policy,p)
        self.assertTrue(result.pending)
        with self.assertRaises(ValueError): p.accepted('intent','wrong')
        p.accepted('intent','turn')
        self.assertFalse(ct.parse_observation(event,policy,p).pending)
        with self.assertRaises(ValueError): ct.parse_observation(self.event('turn/started',
            {'threadId':'thread','turn':{'id':'unknown','items':[],'status':'inProgress'}}),policy,p)

    def test_selected_items_terminal_fingerprint_and_optional_timestamp(self):
        ct,p,policy,thread=self.setup_profile(); p.bind_thread(thread); p.dispatched('intent'); p.accepted('intent','turn')
        items=[{'id':'u','type':'userMessage','content':[{'type':'text','text':'task','text_elements':[]}]},
               {'id':'r','type':'reasoning','summary':['a'],'content':['b']},
               {'id':'p','type':'plan','text':'plan'},
               {'id':'a','type':'agentMessage','text':'done'}]
        turn={'id':'turn','items':items,'status':'completed'}
        event=self.event('turn/completed',{'threadId':'thread','turn':turn},emittedAtMs=1)
        result=ct.parse_observation(event,policy,p)
        self.assertEqual(result.terminal,ct.parse_turn_notification(event.message,policy))
        self.assertEqual(result.terminal[-1],__import__('automation.control_store',fromlist=['record_digest']).record_digest(turn))
        duplicate=dict(turn,items=[items[0],items[0]])
        with self.assertRaises(ValueError): ct.parse_turn_response({'id':'w','result':{'turn':duplicate}},policy)

    def test_ack_dynamic_items_and_unknown_effectful_items_refused(self):
        ct,p,policy,thread=self.setup_profile(); p.bind_thread(thread); p.dispatched('intent','ownership_ack'); p.accepted('intent','turn')
        dynamic=dict(id='d',type='dynamicToolCall',tool='rnr_command',arguments={'argv':['echo']},status='inProgress')
        for item in (dynamic, {'id':'a','type':'hookPrompt'}, {'id':'a','type':'commandExecution'}):
            with self.assertRaises(ValueError): ct.parse_observation(self.event('item/started',
                dict(threadId='thread',turnId='turn',item=item,startedAtMs=1)),policy,p)

    def test_budget_warning_and_usage_monotonicity(self):
        ct,p,policy,thread=self.setup_profile(events=3); p.bind_thread(thread); p.dispatched('i'); p.accepted('i','turn')
        counts=dict(cachedInputTokens=0,inputTokens=2,outputTokens=1,reasoningOutputTokens=0,totalTokens=3)
        usage={'last':counts,'total':counts}
        event=self.event('thread/tokenUsage/updated',dict(threadId='thread',turnId='turn',tokenUsage=usage))
        parsed=ct.parse_observation(event,policy,p)
        self.assertNotIn('cacheWriteInputTokens',parsed.message['params']['tokenUsage']['total'])
        with self.assertRaises(ValueError): ct.parse_observation(self.event('thread/tokenUsage/updated',
            dict(threadId='thread',turnId='turn',tokenUsage={'last':counts,'total':dict(counts,inputTokens=1)})),policy,p)
        with self.assertRaises(ValueError): ct.parse_observation(self.event('warning',{'message':'warning'}),policy,p)
        with self.assertRaises(ValueError): ct.parse_observation(event,policy,p)

    def test_bootstrap_correlation_class_no_id_reuse_and_terminal_fastpath(self):
        ct,p,policy,thread=self.setup_profile(); p.bind_thread(thread); p.dispatched('i'); p.accepted('i','turn')
        fences=[]; terminals=[]
        t=ct.Transport(p.wire_bounds,lambda _:None,fences.append,policy=policy,observation_profile=p,
                       terminal_ingress=lambda terminal: terminals.append(terminal) or True)
        self.addCleanup(t.close)
        t.expect_response('b',kind='bootstrap')
        t.feed(b'{"id":"b","result":{}}\n')
        self.assertEqual(t.events.get_nowait().kind,'bootstrap_response')
        with self.assertRaises(ValueError): t.expect_response('b',kind='turn')
        t.feed(json.dumps(self.event('item/agentMessage/delta',dict(threadId='thread',turnId='turn',itemId='a',delta='x')).message).encode()+b'\n')
        self.assertEqual(t.events.get_nowait().kind,'notification')
        t.feed(json.dumps(self.event('turn/completed',dict(threadId='thread',turn={'id':'turn','items':[],'status':'completed'})).message).encode()+b'\n')
        self.assertEqual(len(terminals),1); self.assertFalse(fences)

    def test_profile_outbound_only_fixed_methods_and_correlated_tool_reply(self):
        ct,p,policy,thread=self.setup_profile(); fences=[]
        t=ct.Transport(p.wire_bounds,lambda _:None,fences.append,policy=policy,observation_profile=p)
        self.addCleanup(t.close)
        self.assertFalse(t.send({'method':'turn/interrupt','params':{'threadId':'thread'}}))
        self.assertTrue(fences)

    def test_purpose_required_internal_only_and_error_responses_fence(self):
        from automation.control_store import TurnPolicy
        import hashlib
        ct,p,policy,thread=self.setup_profile()
        ticket=dict(id='a'*64,assignment='a',epoch=1,owner_version=1,connection='c',generation='g',
            thread='thread',intent='i',wire_id='w',input_hash=hashlib.sha256(b'x').hexdigest(),
            policy_hash=policy.fingerprint(),deadline=100,purpose='ownership_ack')
        frame=json.loads(ct.build_turn_start(ticket,'x',policy,p.wire_bounds))
        self.assertNotIn('purpose',frame['params'])
        with self.assertRaises(ValueError): ct.build_turn_start(dict(ticket,purpose='free'), 'x',policy,p.wire_bounds)
        bad=dict(ticket); bad.pop('purpose')
        with self.assertRaises(ValueError): ct.build_turn_start(bad,'x',policy,p.wire_bounds)
        fences=[]; t=ct.Transport(p.wire_bounds,lambda _:None,fences.append)
        self.addCleanup(t.close); t.expect_response('w'); t.feed(b'{"id":"w","error":{"code":1}}\n')
        self.assertTrue(fences); self.assertTrue(t.events.empty())

    def test_wire_id_control_characters_and_utf8_byte_limit(self):
        from automation.control_transport import _identifier
        self.assertFalse(_identifier('\x85'))
        self.assertFalse(_identifier('é'*129))

    def test_idle_during_active_work_and_warning_evidence(self):
        ct,p,policy,thread=self.setup_profile(); p.bind_thread(thread); p.dispatched('i')
        with self.assertRaises(ValueError): ct.parse_observation(self.event('thread/status/changed',
            {'threadId':'thread','status':{'type':'idle'}}),policy,p)
        warning=self.event('warning',{'message':'stop','threadId':None})
        with self.assertRaises(ValueError): ct.parse_observation(warning,policy,p)
        self.assertEqual(p.warning,warning.raw)

    def test_supported_notification_roots_match_retained_schema(self):
        from pathlib import Path
        import hashlib
        import automation.control_transport as ct
        source=Path('/home/faris/.local/state/development-standards/runner-zero-model-artifacts-20261114/schemas/ServerNotification.json')
        if not source.exists(): self.skipTest('retained notification schema unavailable')
        raw=source.read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(),'071ecc89ba71ce215e1ac01f6e05be509eafa533b2ba6fac43f4c05330305a83')
        declared={method for entry in json.loads(raw)['oneOf'] for method in entry['properties']['method'].get('enum',[])}
        self.assertEqual(len(ct.PINNED_NOTIFICATIONS),14)
        self.assertTrue(ct.PINNED_NOTIFICATIONS<=declared)

    def test_all_selected_notifications_and_negative_nested_fields(self):
        ct,p,policy,thread=self.setup_profile(events=100,text_bytes=30000,pending=32)
        ct.parse_observation(self.event('thread/started',{'thread':thread}),policy,p)
        p.bind_thread(thread)
        ct.parse_observation(self.event('thread/status/changed',{'threadId':'thread','status':{'type':'idle'}}),policy,p)
        p.dispatched('i'); p.accepted('i','turn')
        base={'threadId':'thread','turnId':'turn'}
        messages=[
            ('thread/status/changed',{'threadId':'thread','status':{'type':'active','activeFlags':[]}}),
            ('turn/started',{'threadId':'thread','turn':{'id':'turn','status':'inProgress','items':[]}}),
            ('turn/plan/updated',dict(base,plan=[{'step':'test','status':'pending'}],explanation=None)),
            ('item/started',dict(base,item={'id':'a','type':'agentMessage','text':'hello'},startedAtMs=1)),
            ('item/completed',dict(base,item={'id':'a','type':'agentMessage','text':'hello'},completedAtMs=2)),
            ('item/plan/delta',dict(base,itemId='p',delta='plan')),
            ('item/reasoning/summaryTextDelta',dict(base,itemId='r',summaryIndex=0,delta='thought')),
            ('item/reasoning/summaryPartAdded',dict(base,itemId='r',summaryIndex=0)),
            ('item/reasoning/textDelta',dict(base,itemId='r',contentIndex=0,delta='thought'))]
        for method,params in messages:
            with self.subTest(method=method):
                self.assertFalse(ct.parse_observation(self.event(method,params),policy,p).pending)
                with self.assertRaises(ValueError): ct.parse_observation(self.event(method,dict(params,unknown=None)),policy,p)
        for params in (dict(base,itemId='r',summaryIndex=True,delta='x'),
                       dict(base,itemId='r',summaryIndex=8,delta='x')):
            with self.assertRaises(ValueError): ct.parse_observation(self.event('item/reasoning/summaryTextDelta',params),policy,p)

    def test_aggregate_text_and_identity_bounds(self):
        ct,p,policy,thread=self.setup_profile(text_bytes=220,pending=2)
        p.bind_thread(thread); p.dispatched('i'); p.accepted('i','turn')
        event=self.event('item/agentMessage/delta',dict(threadId='thread',turnId='turn',itemId='a',delta='x'*60))
        ct.parse_observation(event,policy,p)
        with self.assertRaises(ValueError): ct.parse_observation(event,policy,p)
        ct,p,policy,thread=self.setup_profile(pending=1);p.bind_thread(thread);p.dispatched('i');p.accepted('i','turn')
        ct.parse_observation(self.event('item/agentMessage/delta',dict(threadId='thread',turnId='turn',itemId='a',delta='x')),policy,p)
        with self.assertRaises(ValueError): ct.parse_observation(self.event('item/agentMessage/delta',dict(threadId='thread',turnId='turn',itemId='b',delta='x')),policy,p)

    def test_dynamic_observation_agrees_with_request_and_cannot_authorize_it(self):
        ct,p,policy,thread=self.setup_profile();p.bind_thread(thread);p.dispatched('i');p.accepted('i','turn')
        item=dict(id='call',type='dynamicToolCall',tool='rnr_command',arguments={'argv':['echo']},status='inProgress')
        event=self.event('item/started',dict(threadId='thread',turnId='turn',item=item,startedAtMs=1))
        ct.parse_observation(event,policy,p)
        request=dict(threadId='thread',turnId='turn',callId='call',tool='rnr_command',arguments={'argv':['echo']})
        p.command_request(request)
        with self.assertRaises(ValueError): p.command_request(dict(request,arguments={'argv':['different']}))
        for changes in ({'status':'completed','success':False},{'contentItems':[{'type':'inputImage','imageUrl':'x'}]},
                        {'durationMs':True},{'namespace':'external'}):
            with self.assertRaises(ValueError): ct.validate_item(dict(item,**changes),policy,p.wire_bounds)

    def test_pinned_profile_cannot_skip_validation_without_matching_policy(self):
        ct,p,policy,_=self.setup_profile()
        with self.assertRaises(ValueError): ct.Transport(p.wire_bounds,lambda _:None,lambda _:None,observation_profile=p)

    def test_fixed_bootstrap_output_rejects_numeric_booleans(self):
        from automation.control_bootstrap import build_bootstrap_request
        ct,p,policy,_=self.setup_profile(); fences=[]
        t=ct.Transport(p.wire_bounds,lambda _:None,fences.append,policy=policy,observation_profile=p)
        self.addCleanup(t.close);t.expect_response('w',kind='bootstrap')
        frame=json.loads(build_bootstrap_request('initialize','w',p.spec,p.wire_bounds))
        frame['params']['capabilities']['experimentalApi']=1
        self.assertFalse(t.send(frame));self.assertTrue(fences)
