"""Streaming sealed input preparation using explicit memory filesystem only."""
from dataclasses import replace
import hashlib
import unittest
from unittest.mock import patch
import time
from automation import control_runtime_seal as seal
from automation import control_runtime_clock as clock
from automation import control_store as cs

class Source:
    def __init__(self,data):self.data=data;self.offset=0;self.closed=False;self.changed=False
    def read(self,size):
        data=self.data[self.offset:self.offset+size];self.offset+=len(data);return data
    def verify(self):
        if self.changed:raise ValueError('source changed')
    def close(self):self.closed=True
class Sink:
    def __init__(self):self.data=bytearray();self.mode=0o600;self.closed=False
    def write(self,data):self.data.extend(data[:3]);return min(3,len(data))
    def verify(self,size,digest):
        if len(self.data)!=size or hashlib.sha256(self.data).hexdigest()!=digest:raise ValueError('destination differs')
    def finish(self,mode):self.mode=mode
    def close(self):self.closed=True
class FS:
    synthetic_only=True
    def __init__(self,data):self.data=data;self.begun=[];self.sources=[];self.sinks={};self.closed=False;self.mutate=False
    def begin(self,name):self.begun.append(name)
    def open_source(self,pin):
        source=Source(self.data[pin.file.target]);source.changed=self.mutate;self.sources.append(source);return source
    def open_destination(self,relative):self.sinks[relative]=Sink();return self.sinks[relative]
    def close(self):self.closed=True

class SealTests(unittest.TestCase):
    def setUp(self):
        self.data={target:(target.encode()*3 if target in ('/rnr/codex','/rnr/guardian') else b'') for target in cs._RUNTIME_FILE_TARGETS}
        self.pins=tuple(seal.SourcePin(cs.RuntimeFile('/private/'+str(i),target,hashlib.sha256(self.data[target]).hexdigest(),len(self.data[target])),
            17,i+1,1000,1000,0o600,123,456) for i,target in enumerate(sorted(self.data)))
        self.anchor=clock.capture('run','sup','a'*64,time.time()+120)
        self.fs=FS(self.data);self.name='rnr-d00-qualification-'+'b'*32
    def sealer(self):return seal.Sealer.for_synthetic(self.fs,self.anchor)
    def test_exact_seven_files_stream_and_final_modes(self):
        output=self.sealer().seal(self.name,self.pins)
        self.assertEqual(len(output),7)
        for item in output:
            self.assertTrue(item.source.startswith('/run/'+self.name+'/'))
            relative=item.source.split('/run/'+self.name+'/',1)[1];sink=self.fs.sinks[relative]
            self.assertEqual(bytes(sink.data),self.data[item.target])
            self.assertEqual(sink.mode,0o555 if item.target in ('/rnr/guardian','/rnr/codex') else 0o444)
            self.assertTrue(sink.closed)
        self.assertTrue(all(source.closed for source in self.fs.sources))
    def test_eight_mib_binary_preserves_exact_content_with_bounded_read_count(self):
        binary = bytes(range(256)) * 32768  # Literal8MiB, including non-text bytes.
        self.data['/rnr/codex'] = binary
        pins = tuple(replace(pin, file=replace(pin.file,
            bytes=len(binary), content_digest=hashlib.sha256(binary).hexdigest()))
            if pin.file.target == '/rnr/codex' else pin for pin in self.pins)
        reads = []
        original_open = self.fs.open_source
        def open_source(pin):
            source = original_open(pin)
            if pin.file.target == '/rnr/codex':
                original_read = source.read
                def read(size):
                    block = original_read(size)
                    reads.append((size, len(block)))
                    return block
                source.read = read
            return source
        class FullWriteSink(Sink):
            def write(inner, data):
                inner.data.extend(data)
                return len(data)
        def open_destination(relative):
            sink = FullWriteSink()
            self.fs.sinks[relative] = sink
            return sink
        self.fs.open_source = open_source
        self.fs.open_destination = open_destination
        driver = self.sealer()
        try:
            output = driver.seal(self.name, pins)
            self.assertEqual(len(output), 7)
            codex = self.fs.sinks['codex']
            self.assertEqual(bytes(codex.data), binary)
            self.assertEqual(codex.mode, 0o555)
            self.assertTrue(codex.closed)
            self.assertTrue(all(source.closed for source in self.fs.sources))
            self.assertTrue(reads)
            self.assertEqual(reads[-1][1], 0)  # Required final EOF read is counted.
            self.assertEqual(sum(amount for _, amount in reads), 8388608)
            self.assertLessEqual(len(reads), 9)
            self.assertTrue(all(0 < size <= 1048576 for size, _ in reads))
        finally:
            driver.close()

    def test_unknown_names_duplicates_and_metadata_reject_before_effect(self):
        for name,pins in (('../bad',self.pins),(self.name,self.pins[:-1]),(self.name,self.pins[:-1]+self.pins[:1]),
                          (self.name,(replace(self.pins[0],inode=True),)+self.pins[1:])):
            with self.assertRaises(ValueError):self.sealer().seal(name,pins)
        self.assertEqual(self.fs.begun,[])
    def test_hash_mismatch_retains_private_partial_path_without_execute_mode(self):
        self.fs.data=dict(self.data);self.fs.data[self.pins[0].file.target]=b'wrong'
        driver=self.sealer()
        with self.assertRaises(ValueError):driver.seal(self.name,self.pins)
        self.assertEqual(len(self.fs.begun),1)
        self.assertTrue(all(sink.mode==0o600 for sink in self.fs.sinks.values()))
        with self.assertRaises(ValueError):driver.seal(self.name,self.pins)
        self.assertEqual(len(self.fs.begun),1)
    def test_changed_source_identity_rejects_before_final_mode(self):
        self.fs.mutate=True
        with self.assertRaises(ValueError):self.sealer().seal(self.name,self.pins)
        self.assertTrue(all(sink.mode==0o600 for sink in self.fs.sinks.values()))
    def test_original_setup_cutoff_prevents_even_directory_creation(self):
        driver=self.sealer()
        with patch.object(seal.time,'clock_gettime_ns',return_value=self.anchor.captured_boottime_ns+15_000_000_000):
            with self.assertRaises(ValueError):driver.seal(self.name,self.pins)
        self.assertEqual(self.fs.begun,[])
    def test_operational_constructor_disabled_and_unmarked_filesystem_rejected(self):
        with self.assertRaises(RuntimeError):seal.Sealer()
        self.fs.synthetic_only=False
        with self.assertRaises(ValueError):self.sealer()

    def test_original_sampled_wall_cannot_be_reset_at_binding(self):
        with patch.object(seal.time,'time_ns',return_value=self.anchor.sampled_wall_ns-1):
            with self.assertRaises(ValueError):self.sealer()

    def test_destination_readback_mismatch_never_gets_final_modes_or_paths(self):
        original=self.fs.open_destination
        def corrupt(relative):
            sink=original(relative)
            def write(data):
                count=min(3,len(data));sink.data.extend(b'x'*count);return count
            sink.write=write;return sink
        self.fs.open_destination=corrupt
        with self.assertRaises(ValueError):self.sealer().seal(self.name,self.pins)
        self.assertEqual(self.fs.sinks['codex'].mode,0o600)
        self.assertFalse(any(sink.mode==0o555 for sink in self.fs.sinks.values()))

if __name__=='__main__':unittest.main()
