"""Closed inotify metadata grammar only, never a live resource grant."""
import unittest
from automation import control_runtime_proc as proc
from automation import control_runtime_frozen as frozen
from tests.test_automation_runtime_frozen_fd import common, CLOEXEC, NONBLOCK


def watch(wd=1, inode=42, device=65, mask=0xfc6, handle=True):
    line=f'inotify wd:{wd:x} ino:{inode:x} sdev:{device:x} mask:{mask:x} ignored_mask:0 '
    if handle:line+='fhandle-bytes:c fhandle-type:1 f_handle:eadb1ecd846a000000000000'
    return (line+'\n').encode()


class InotifyGrammarTests(unittest.TestCase):
    def parse(self, tail):
        return proc._parse_frozen_fdinfo(common(CLOEXEC|NONBLOCK)+tail,'inotify')

    def test_exact_emitter_fields_and_optional_export_handle(self):
        record=self.parse(watch())
        self.assertEqual(record.details,((1,42,65,0xfc6,(12,1,bytes.fromhex('eadb1ecd846a000000000000'))),))
        self.assertEqual(self.parse(watch(handle=False)).details,((1,42,65,0xfc6,None),))
        self.assertEqual(self.parse(b'').details,())

    def test_complete_bounded_unique_watch_inventory(self):
        self.assertEqual(len(self.parse(b''.join(watch(n,n,handle=False) for n in range(1,65))).details),64)
        for raw in (watch()+watch(),watch()+watch(wd=2),
                    b''.join(watch(n,n,handle=False) for n in range(1,66))):
            with self.subTest(raw=raw[:100]),self.assertRaises(ValueError):self.parse(raw)

    def test_flags_are_readonly_nonblocking_cloexec_only(self):
        for flags in (0,2|CLOEXEC|NONBLOCK,CLOEXEC,NONBLOCK,CLOEXEC|NONBLOCK|0o100000):
            with self.subTest(flags=flags),self.assertRaises(ValueError):
                proc._parse_frozen_fdinfo(common(flags)+watch(),'inotify')

    def test_noncanonical_or_incomplete_metadata_never_authenticates(self):
        raw=watch()
        for old,new in ((b'wd:1',b'wd:01'),(b'wd:1',b'wd:0'),(b'wd:1',b'wd:80000000'),
                (b'ino:2a',b'ino:0'),(b'sdev:41',b'sdev:0'),(b'ino:2a',b'ino:10000000000000000'),
                (b'mask:fc6',b'mask:0'),(b'mask:fc6',b'mask:1000'),(b'ignored_mask:0',b'ignored_mask:1'),
                (b'fhandle-bytes:c',b'fhandle-bytes:b'),(b'fhandle-bytes:c',b'fhandle-bytes:80'),
                (b'fhandle-type:1',b'fhandle-type:ff'),(b'fhandle-type:1',b'fhandle-type:80000000'),
                (b'f_handle:eadb',b'f_handle:EADB'),(b'f_handle:',b'unknown:'),
                (b' in',b'  in')):
            changed=raw.replace(old,new)
            if changed==raw:continue
            with self.subTest(old=old,new=new),self.assertRaises(ValueError):self.parse(changed)
        for changed in (raw[:-1],raw+b'extra\n',watch(handle=False).replace(b'0 \n',b'0\n')):
            with self.subTest(changed=changed),self.assertRaises(ValueError):self.parse(changed)

    def test_supported_event_bits_and_handle_length_are_closed(self):
        self.assertEqual(self.parse(watch(mask=0x84000fff)).details[0][3],0x84000fff)
        raw=watch().replace(b'fhandle-bytes:c',b'fhandle-bytes:80').replace(
            b'eadb1ecd846a000000000000',b'00'*128)
        self.assertEqual(len(self.parse(raw).details[0][4][2]),128)
        for changed in (raw.replace(b'fhandle-bytes:80',b'fhandle-bytes:84'),
                        raw.replace(b'00'*128,b'00'*132)):
            with self.assertRaises(ValueError):self.parse(changed)

    def test_parser_extension_does_not_enable_workload_admission(self):
        owner=object.__new__(frozen._FrozenLifecycle)
        record=frozen._FD(3,'inotify',(1,42,0),CLOEXEC|NONBLOCK,1,self.parse(watch()).details)
        with self.assertRaisesRegex(ValueError,'unsupported app extra descriptor'):
            owner._fd_relations((record,),'app')
