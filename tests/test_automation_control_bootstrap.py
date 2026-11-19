"""Pinned bootstrap source-only tests, no runtime launches."""
import importlib.util
import json
import unittest
from dataclasses import replace
from tests.control_bootstrap_fixtures import packet_spec_policy
from automation.control_store import record_digest
from automation.control_transport import Bounds


def fixture():
    _, spec, _ = packet_spec_policy()
    config = {'model': spec.model, 'model_provider': spec.provider,
              'model_reasoning_effort': spec.effort, 'approval_policy': 'never',
              'approvals_reviewer': 'user', 'sandbox_mode': 'danger-full-access'}
    provenance = {'layers': [], 'origins': {}}
    spec = replace(spec, expected_config_digest=record_digest(config),
                   expected_layers_digest=record_digest(provenance))
    thread = dict(id='thread', sessionId='session', cliVersion=spec.cli_version,
                  createdAt=1, updatedAt=1, cwd=spec.runtime_cwd, ephemeral=True,
                  modelProvider=spec.provider, preview='', projectId=None,
                  source='appServer', status={'type': 'idle'}, turns=[], environments=[])
    responses = {
        'initialize': dict(codexHome=spec.runtime_home, platformFamily=spec.platform_family,
                           platformOs=spec.platform_os, userAgent=spec.user_agent),
        'config_read': dict(config=config, **provenance),
        'thread_start': dict(thread=thread, model=spec.model, modelProvider=spec.provider,
            cwd=spec.runtime_cwd, approvalPolicy='never', approvalsReviewer='user',
            sandbox={'type': 'dangerFullAccess'}, reasoningEffort=spec.effort,
            runtimeWorkspaceRoots=[], instructionSources=[], disabledPluginIds=[])}
    return spec, responses


class BootstrapTests(unittest.TestCase):
    def api(self):
        self.assertIsNotNone(importlib.util.find_spec('automation.control_bootstrap'),
                             'pinned bootstrap adapter missing')
        from automation import control_bootstrap
        return control_bootstrap

    def test_complete_responses_return_full_decoded_envelope(self):
        api = self.api(); spec, responses = fixture()
        for step, result in responses.items():
            envelope = {'id': 'wire', 'result': result}
            self.assertEqual(api.validate_bootstrap_response(step, json.dumps(envelope).encode(), spec), envelope)

    def test_invalid_policy_unknown_fields_and_wire_errors_reject(self):
        api = self.api(); spec, responses = fixture()
        for step, result in responses.items():
            for bad in (dict(result, unknown=None), {}):
                with self.subTest(step=step), self.assertRaises(ValueError):
                    api.validate_bootstrap_response(step, json.dumps({'id': 'w', 'result': bad}).encode(), spec)
        for field, value in [('source', 'cli'), ('environments', None), ('ephemeral', False),
                             ('sessionId', ''), ('createdAt', True), ('model', 'other'),
                             ('daybreakEnabled', False), ('extra', {}), ('turns', [{}])]:
            bad = dict(responses['thread_start'], thread=dict(responses['thread_start']['thread'], **{field: value}))
            with self.subTest(field=field), self.assertRaises(ValueError):
                api.validate_bootstrap_response('thread_start', json.dumps({'id':'w','result':bad}).encode(), spec)
        for raw in (b'{"id":"w","error":{}}', b'{"id":"w","id":"w","result":{}}', b'[]'):
            with self.assertRaises(ValueError): api.validate_bootstrap_response('initialize', raw, spec)

    def test_config_requires_exact_complete_protected_manifest(self):
        api = self.api(); spec, responses = fixture()
        good = responses['config_read']
        for bad in (dict(good, config=dict(good['config'], hooks={})),
                    dict(good, layers=None), dict(good, origins={'x': {}})):
            with self.assertRaises(ValueError):
                api.validate_bootstrap_response('config_read', json.dumps({'id':'w','result':bad}).encode(), spec)

    def test_fixed_requests_and_disabled_public_constructor(self):
        api = self.api(); spec, _ = fixture(); bounds = Bounds(16384, 1024, 8, 8, 8, 32)
        with self.assertRaises(RuntimeError): api.BootstrapAdapter()
        requests = {s: json.loads(api.build_bootstrap_request(s,'wire',spec,bounds))
                    for s in ('initialize','config_read','thread_start')}
        self.assertEqual(requests['config_read'], {'id':'wire','method':'config/read','params':{'cwd':'/','includeLayers':True}})
        self.assertEqual(requests['initialize']['params']['clientInfo'], {'name':'rnr-source','version':'3'})
        params=requests['thread_start']['params']
        self.assertEqual(params['dynamicTools'][0]['inputSchema']['properties']['argv']['maxItems'],8)
        self.assertEqual(params['environments'], [])
        self.assertNotIn('config',params)
        self.assertNotIn('effort',params)

    def test_synthetic_adapter_one_channel_pure_reducer_and_delegation(self):
        api=self.api()
        self.assertTrue(hasattr(api.BootstrapAdapter,'for_synthetic'),'synthetic adapter factory missing')
        from automation.control_store import RuntimeTicket, RuntimeEvidence, Instance
        spec,responses=fixture(); bounds=Bounds(16384,1024,8,8,8,32)
        ticket=RuntimeTicket('a'*64,spec.packet.key,record_digest(spec),spec.packet.packet_digest,
            'b'*64,'allocation','name',(('run','run'),),100,1)
        instance=Instance(ticket.allocation,ticket.name,'instance',ticket.labels)
        evidence=RuntimeEvidence(ticket.id,instance,spec.packet.key.connection,spec.packet.key.generation,'channel',())
        class Controller:
            def prepare_binding(self,s): return ('prepare',s)
            def start_ownership_ack(self,a): return ('ackturn',a)
            def acknowledge(self,a): return ('ack',a)
        class Channel:
            synthetic_only=True
            channel_ref='channel'
            runtime_evidence=evidence
            def write(self,raw): pass
            def read(self): return b''
        class Ops:
            synthetic_only=True
            def bind_channel(self,t,e): return Channel()
        adapter=api.BootstrapAdapter.for_synthetic(Controller(),Ops(),spec,bounds)
        self.assertEqual(adapter.begin(),('prepare',spec))
        self.assertEqual(adapter.start_ownership_ack(),('ackturn',spec.packet.key.assignment))
        self.assertEqual(adapter.acknowledge('evidence'),('ack','evidence'))
        channel=adapter.bind_channel(ticket,evidence)
        self.assertEqual(channel.channel_ref,'channel')
        with self.assertRaises(ValueError): adapter.bind_channel(ticket,evidence)
        action=adapter.next_action('reserved',None)
        self.assertEqual(action.step,'initialize')
        self.assertEqual(action.next_state,'initialize')
        self.assertEqual(len(action.frames),1)
        for step in ('initialize','config_read','thread_start'):
            response={'id':json.loads(action.frames[-1])['id'],'result':responses[step]}
            action=adapter.next_action(step,response)
            if step=='initialize':
                self.assertEqual(action.frames[0],b'{"method":"initialized"}\n')
                self.assertEqual(action.step,'config_read')
            elif step=='config_read': self.assertEqual(action.step,'thread_start')
            else:
                self.assertEqual(action.frames,()); self.assertEqual(action.next_state,'bound')
                self.assertEqual(action.response,response)
        with self.assertRaises(ValueError): adapter.next_action('initialize',{'id':'wrong','result':responses['initialize']})

    def test_config_declared_schema_types_even_when_manifest_hash_matches(self):
        api=self.api(); spec,responses=fixture()
        for config in ({'model':2},{'model_reasoning_effort':''}, {'tools':{'web_search':True}},
                       {'sandbox_workspace_write':{'writable_roots':[1]}}):
            result=dict(responses['config_read'],config=config)
            matching=replace(spec,expected_config_digest=record_digest(config))
            with self.subTest(config=config),self.assertRaises(ValueError):
                api.validate_bootstrap_response('config_read',json.dumps({'id':'w','result':result}).encode(),matching)

    def test_pinned_bootstrap_schema_projection_and_routes(self):
        from pathlib import Path
        import hashlib
        api=self.api()
        root=Path('/home/faris/.local/state/development-standards/lavish-reviews/preimplementation-x0ngvay0/cli-schema')
        if not root.is_dir(): self.skipTest('retained bootstrap schemas unavailable')
        pins={
            'v1/InitializeParams.json':'b55124e7c0f36a1789396daa5578217a92be67f053903696236686e59f6f212e',
            'v1/InitializeResponse.json':'62ad689c2cb6379913c1d72749cfd8de5089d35760214123518eb92eef11acc9',
            'v2/ConfigReadParams.json':'257c54a423b47c1d209ff1076765a1564d82322fd5161670fd489a2874de1bac',
            'v2/ConfigReadResponse.json':'4ec77e1a3eed746037149799c3b6bb8fe7b4b593e5930fc9f410e6282de9df50',
            'v2/ThreadStartParams.json':'80a40a7fac15b4bf70efb7f893fb353acc0a0d30c68f54aee4f01923deca85de',
            'v2/ThreadStartResponse.json':'107fe36c99ebaeb750a371580beec807a28c6451e9c8a02cd7d451a0135f1c91',
            'ClientNotification.json':'706cf248d75027c84a3c63348d0ed507182e8eba40069dd17541793de029145a'}
        for name,digest in pins.items(): self.assertEqual(hashlib.sha256((root/name).read_bytes()).hexdigest(),digest)
        def constraints(value):
            if isinstance(value,list): return [constraints(v) for v in value]
            if not isinstance(value,dict): return value
            return {k:constraints(v) for k,v in value.items() if k not in ('description','title','default','$schema')}
        schema=json.loads((root/'v2/ConfigReadResponse.json').read_bytes())
        self.assertEqual(api._CONFIG_DEFINITIONS,constraints(schema['definitions']))
        spec,responses=fixture()
        # Valid nested anyOf objects must survive recursive schema checks.
        config=dict(responses['config_read']['config'],analytics={'enabled':False})
        spec=replace(spec,expected_config_digest=record_digest(config))
        result=dict(responses['config_read'],config=config)
        self.assertEqual(api.validate_bootstrap_response('config_read',json.dumps({'id':'w','result':result}).encode(),spec)['result'],result)
