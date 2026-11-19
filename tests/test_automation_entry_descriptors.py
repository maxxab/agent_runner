"""Closed syscall fixtures for pre-effect FD inventory, never native authority."""
from contextlib import ExitStack
from types import SimpleNamespace
import os
import stat
import threading
import unittest
from unittest.mock import patch
from automation import control_runtime_root_entry as entry

class DescriptorAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.slots=tuple(range(10,16));self.names=[str(x) for x in (0,1,2,*self.slots,20,21)]
        self.events=[];self.flags={0:os.O_RDONLY,1:os.O_WRONLY,2:os.O_WRONLY}
        self.infos={fd:SimpleNamespace(st_dev=8,st_ino=100+fd,st_mode=stat.S_IFREG|0o600,st_rdev=0)
                    for fd in (0,1,2,*self.slots)}
        self.infos[20]=self.infos[21]=SimpleNamespace(st_dev=9,st_ino=77,st_mode=stat.S_IFDIR|0o500,st_rdev=0)
        self.null=SimpleNamespace(st_dev=1,st_ino=3,st_mode=stat.S_IFCHR|0o666,st_rdev=259)
        self.owner=object.__new__(entry.RootEntry);self.owner._incoming=list(self.slots)
        self.owner._owner=(os.getpid(),threading.current_thread());self.clock_count=0
        self.fail_clock=None;self.enum_error=None;self.close_error=False
    def invoke(self):
        method=getattr(self.owner,'_admit_initial_descriptors',None)
        self.assertTrue(callable(method),'pre-effect descriptor admission missing')
        host=self
        class Scan:
            def __init__(self):self.pos=0;self.closed=False
            def __iter__(self):return self
            def __next__(self):
                if host.enum_error and self.pos==2:raise host.enum_error
                if self.pos==len(host.names):self.closed=True;raise StopIteration
                name=host.names[self.pos];self.pos+=1;return SimpleNamespace(name=name)
            def close(self):
                self.closed=True;host.events.append('iterator-close')
                if host.close_error:raise OSError('iterator cleanup failed')
        scan=Scan()
        def fstat(fd):
            if fd==21 and scan.closed:raise OSError('iterator descriptor closed')
            if fd not in self.infos:raise OSError('missing descriptor')
            return self.infos[fd]
        def check():
            self.clock_count+=1
            if self.fail_clock==self.clock_count:raise ValueError('original clock lost')
        with ExitStack() as stack:
            stack.enter_context(patch.object(entry.os,'open',return_value=20))
            stack.enter_context(patch.object(entry.os,'scandir',return_value=scan))
            stack.enter_context(patch.object(entry.os,'fstat',side_effect=fstat))
            stack.enter_context(patch.object(entry.os,'stat',return_value=self.null))
            stack.enter_context(patch.object(entry.os,'close',side_effect=lambda fd:self.events.append(('close',fd))))
            stack.enter_context(patch.object(entry.fcntl,'fcntl',side_effect=lambda fd,op:self.flags.get(fd,os.O_RDONLY)))
            return method(SimpleNamespace(check=check))
    def test_exact_inventory_validates_enumerator_while_live(self):
        self.assertIsNone(self.invoke())
        self.assertEqual(self.events,['iterator-close',('close',20)])
    def test_missing_extra_aliased_and_duplicate_names_reject(self):
        original=list(self.names)
        for names in (original[:-1],original+['22'],original[:-1]+['20']):
            self.names=names;self.infos[22]=self.infos[20];self.events=[]
            with self.subTest(names=names),self.assertRaises(ValueError):self.invoke()
            self.assertNotIn(('close',22),self.events)
            self.assertNotIn(('close',21),self.events)
        self.names=original;del self.infos[10]
        with self.assertRaises(OSError):self.invoke()
    def test_malformed_names_and_non_directory_enumerator_reject(self):
        for name in ('01','-1','2147483648','x','١',True):
            self.names[-1]=name
            with self.subTest(name=name),self.assertRaises(ValueError):self.invoke()
        self.names[-1]='21';self.infos[21]=self.infos[10]
        with self.assertRaises(ValueError):self.invoke()
    def test_stdio_modes_and_devices_are_explicit(self):
        for fd,flags in ((0,os.O_WRONLY),(1,os.O_RDONLY),(2,os.O_PATH)):
            previous=self.flags[fd];self.flags[fd]=flags
            with self.subTest(fd=fd),self.assertRaises(ValueError):self.invoke()
            self.flags[fd]=previous
        original=self.infos[0]
        for mode,rdev in ((stat.S_IFSOCK,0),(stat.S_IFDIR,0),(stat.S_IFCHR,123)):
            self.infos[0]=SimpleNamespace(st_dev=1,st_ino=2,st_mode=mode,st_rdev=rdev)
            with self.subTest(mode=mode),self.assertRaises(ValueError):self.invoke()
        self.infos[0]=self.null;self.assertIsNone(self.invoke());self.infos[0]=original
    def test_slot_duplicates_stdio_and_owner_loss_reject(self):
        for slots in ([10]*6,[0,11,12,13,14,15]):
            self.owner._incoming=slots
            with self.assertRaises(ValueError):self.invoke()
        self.owner._incoming=list(self.slots);self.owner._owner=(-1,threading.current_thread())
        with self.assertRaises(ValueError):self.invoke()
    def test_enumeration_error_preserves_original_and_owned_cleanup(self):
        self.enum_error=ValueError('enumeration failed');self.close_error=True
        with self.assertRaises(ValueError) as caught:self.invoke()
        self.assertIs(caught.exception,self.enum_error)
        self.assertEqual(self.events,['iterator-close',('close',20)])
        self.assertTrue(caught.exception.entry_cleanup_errors)
    def test_original_clock_loss_closes_only_gate_owned_resources(self):
        self.fail_clock=15
        with self.assertRaisesRegex(ValueError,'original clock lost'):self.invoke()
        self.assertFalse(any(x==('close',fd) for x in self.events for fd in self.slots))
