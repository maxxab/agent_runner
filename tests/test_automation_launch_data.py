"""Closed, inert launch-data decoding; no Store, files, clocks or runtime."""
from copy import deepcopy
from dataclasses import asdict, replace
import os
import unittest
from unittest.mock import patch
from automation import control_store as cs
from automation import control_runtime_clock as clock
from automation.control_runtime_seal import _DESTINATIONS


class LaunchDataTests(unittest.TestCase):
    def setUp(self):
        from automation import control_runtime_launch_data as data
        self.data=data
        self.origin=clock._NativeClockOrigin(os.getpid(),os.getpid(),
            '11111111-1111-1111-1111-111111111111',4,123,
            10_000_000_000,100_000_000_000,220_000_000_000,130_000_000_000,
            25_000_000_000,14_000_000_000,104_000_000_000)
        self.doc=dict(version=1,allocation='a'*32,
            store=dict(run=dict(deadline=140,commands=5,turns=8,capacity=2,turn_capacity=2),
                policy=dict(model='synthetic',effort='medium',input_bytes=4096,turn_items=16,item_text_bytes=2048),
                resources=dict(runtime_slots=4,reviewer_reserve=1,workload_slots=2),
                queue_bound=8,run_id='run',supervisor_epoch='sup'),
            quota=dict(cpu_millis=1000,memory_bytes=536870912,swap_bytes=0,pids=128,scratch_bytes=67108864,output_bytes=1048576),
            files=[dict(target=target,content_digest='c'*64,bytes=1 if target in ('/rnr/guardian','/rnr/codex') else 0) for target in sorted(_DESTINATIONS)],
            unit_paths=['/run/systemd/transient','/etc/systemd/system'],
            tool_digest='d'*64,manager_digest='e'*64)

    def decode(self,doc=None):
        return self.data._decode_launch(cs.canonical(self.doc if doc is None else doc).encode(),self.origin)

    def test_v2_generation_uses_only_externally_selected_root_paths(self):
        self.doc.update(version=2,asset_root='f'*64)
        result=self.decode()
        self.assertEqual(result.asset_root,'f'*64)
        self.assertEqual(tuple(f.source for f in result.files),tuple('/var/lib/rnr/assets/'+'f'*64+'/'+_DESTINATIONS[t] for t in sorted(_DESTINATIONS)))
        self.assertEqual(result.anchor.captured_boottime_ns,self.origin.captured_boottime_ns)
        self.assertEqual(result.anchor.deadline_boottime_ns,self.origin.deadline_boottime_ns)
        self.assertEqual(result.inputs.run.deadline,140)

    def test_v2_cannot_omit_or_supply_invalid_root_or_downgrade_schema(self):
        self.doc['version']=2
        with self.assertRaises(ValueError):self.decode()
        for value in (None,True,'','../x','F'*64,'f'*63):
            self.doc['asset_root']=value
            with self.subTest(value=value),self.assertRaises(ValueError):self.decode()
        self.doc.update(version=1,asset_root='f'*64)
        with self.assertRaises(ValueError):self.decode()

    def test_v3_retains_distinct_execution_daemon_and_asset_pins_with_original_anchor(self):
        self.doc.update(version=3,asset_root='f'*64,execution_root='1'*64,daemon_digest='2'*64)
        result=self.decode()
        self.assertEqual((result.version,result.execution_root,result.daemon_digest,result.asset_root),
            (3,'1'*64,'2'*64,'f'*64))
        self.assertEqual(result.anchor.captured_boottime_ns,self.origin.captured_boottime_ns)
        self.assertEqual(result.anchor.deadline_boottime_ns,self.origin.deadline_boottime_ns)

    def test_v3_requires_all_pins_and_cannot_downgrade_schema(self):
        self.doc.update(version=3,asset_root='f'*64,execution_root='1'*64,daemon_digest='2'*64)
        for key in ('asset_root','execution_root','daemon_digest'):
            doc=deepcopy(self.doc);del doc[key]
            with self.subTest(missing=key),self.assertRaises(ValueError):self.decode(doc)
            for value in (None,True,'','../x','A'*64,'a'*63):
                doc=deepcopy(self.doc);doc[key]=value
                with self.subTest(key=key,value=value),self.assertRaises(ValueError):self.decode(doc)
        for version in (1,2):
            doc=deepcopy(self.doc);doc['version']=version
            with self.subTest(version=version),self.assertRaises(ValueError):self.decode(doc)

    def test_original_anchor_and_complete_existing_configuration(self):
        result=self.decode()
        self.assertEqual(result.anchor.captured_boottime_ns,self.origin.captured_boottime_ns)
        self.assertNotEqual(result.anchor.captured_boottime_ns,self.origin.last_boottime_ns)
        self.assertEqual(result.anchor.sampled_wall_ns,self.origin.sampled_wall_ns)
        self.assertEqual(result.anchor.wall_deadline_ns,self.origin.wall_deadline_ns)
        config=dict(self.doc['store']['run'],policy=self.doc['store']['policy'],
            policy_hash=result.inputs.policy.fingerprint(),run_id='run',resources=self.doc['store']['resources'],
            supervisor_epoch='sup',runtime_clock=True)
        self.assertEqual(result.anchor.configuration_digest,cs.record_digest(cs.canonical(config)))
        result.inputs.validate(result.anchor)
        self.assertEqual(result.name,'rnr-d00-qualification-'+'a'*32)
        self.assertEqual(result.recipe.name,'rnr'+'a'*32+'.slice')

    def test_numeric_representation_preserved_for_digest(self):
        first=self.decode()
        self.doc['store']['run']['deadline']=140.0
        second=self.decode()
        self.assertIs(type(first.inputs.run.deadline),int)
        self.assertIs(type(second.inputs.run.deadline),float)
        self.assertNotEqual(first.anchor.configuration_digest,second.anchor.configuration_digest)

    def test_immutable_data_only_no_effects_or_recapture(self):
        from automation.control_runtime_root_entry import RootEntry
        with patch.object(clock,'capture',side_effect=AssertionError('no capture')), \
                patch.object(clock,'identity',side_effect=AssertionError('no lookup')), \
                patch.object(os,'open',side_effect=AssertionError('no file')), \
                patch.object(RootEntry,'_from_fds',side_effect=AssertionError('no entry')), \
                patch.object(cs,'Store',side_effect=AssertionError('no Store')):
            result=self.decode()
        self.doc['unit_paths'].append('/untrusted')
        self.doc['files'][0]['content_digest']='f'*64
        self.assertEqual(len(result.unit_paths),2)
        self.assertEqual(result.files[0].content_digest,'c'*64)
        self.assertIs(type(result.files),tuple)
        self.assertIs(type(result.recipe.properties),tuple)
        with self.assertRaises(AttributeError): result.name='different'
        self.assertEqual(tuple(f.source for f in result.files),tuple('/rnr/sources/'+_DESTINATIONS[t] for t in sorted(_DESTINATIONS)))

    def test_exact_closed_schemas_and_no_caller_paths_or_metadata(self):
        for path,key,value in (((), 'unknown',1),(('store',),'extra',1),
                (('store','run'),'now',1),(('store','policy'),'callback','bad'),
                (('store','resources'),'lease',1),(('quota',),'properties',[]),
                (('files',0),'source','/caller'),(('files',0),'inode',123)):
            doc=deepcopy(self.doc);node=doc
            for component in path:node=node[component]
            node[key]=value
            with self.subTest(path=path,key=key),self.assertRaises(ValueError):self.decode(doc)
        doc=deepcopy(self.doc);del doc['manager_digest']
        with self.assertRaises(ValueError):self.decode(doc)

    def test_exact_types_ranges_and_cross_configuration(self):
        for path,value in ((('version',),True),(('allocation',),'A'*32),
                (('store','queue_bound'),True),(('store','run','commands'),True),
                (('store','run','deadline'),True),(('store','run','deadline'),145),
                (('store','resources','workload_slots'),3),(('quota','cpu_millis'),1001),
                (('quota','swap_bytes'),1),(('tool_digest',),'not-a-hash'),
                (('unit_paths',),['/tmp']), (('unit_paths',),['/run/systemd/transient']*2)):
            doc=deepcopy(self.doc);node=doc
            for component in path[:-1]:node=node[component]
            node[path[-1]]=value
            with self.subTest(path=path,value=value),self.assertRaises(ValueError):self.decode(doc)

    def test_exact_seven_targets_and_order(self):
        for change in ('missing','duplicate','order','foreign'):
            doc=deepcopy(self.doc)
            if change=='missing':doc['files'].pop()
            if change=='duplicate':doc['files'][-1]=doc['files'][0]
            if change=='order':doc['files'].reverse()
            if change=='foreign':doc['files'][0]['target']='/tmp/caller'
            with self.subTest(change=change),self.assertRaises(ValueError):self.decode(doc)

    def test_malformed_unbounded_or_noncanonical_json(self):
        for raw in (b'',b'\xff',b'{"version":1,"version":1}',b'{"x":NaN}',
                b'{"x":Infinity}',b'{"x":1e999}',b'{"x":9223372036854775808}',
                b'['*10000+b']'*10000,b'{"x":"'+b'a'*4097+b'"}',
                b'{"x":"\\ud800"}',b' '*65537,
                cs.canonical(self.doc).encode()+b'\n',b'{'+b'"x":['+b'0,'*2048+b'0]}'):
            with self.subTest(prefix=raw[:40]),self.assertRaises(ValueError):
                self.data._decode_launch(raw,self.origin)

    def test_invalid_native_origin_never_replaced(self):
        with self.assertRaises(ValueError):
            self.data._decode_launch(cs.canonical(self.doc).encode(),replace(self.origin,deadline_boottime_ns=1))


if __name__=='__main__':unittest.main()
