"""Original-proc owner rejection and cleanup, with simulated kernel boundaries."""
import os
from types import SimpleNamespace
import threading
import unittest
from unittest.mock import patch,Mock


class ProcViewTests(unittest.TestCase):
    def module(self):
        from automation import control_runtime_proc_view as view
        return view

    def test_public_constructor_cannot_create_baseline(self):
        view=self.module()
        with self.assertRaises(RuntimeError):view._ProcView()

    def test_wrong_wire_rejected_before_open_or_close(self):
        view=self.module()
        with patch.object(view.os,'open') as opened,patch.object(view.os,'close') as closed:
            with self.assertRaises(ValueError):view._ProcView._capture(object(),5,object())
        opened.assert_not_called();closed.assert_not_called()

    def test_descriptor_close_invalidates_all_slots_and_preserves_errors(self):
        view=self.module();owner=object.__new__(view._ProcView)
        owner._owner=(os.getpid(),threading.current_thread());owner._fds=[30,31]
        owner._witness=None;owner._closed=owner._fenced=False;owner.cleanup_errors=()
        seen=[]
        def close(fd):
            self.assertEqual(owner._fds,[])
            seen.append(fd)
            if fd==30:raise OSError('uncertain close')
        with patch.object(view.os,'close',side_effect=close):
            with self.assertRaises(OSError):owner.close()
            owner.close()
        self.assertEqual(seen,[31,30]);self.assertEqual(len(owner.cleanup_errors),1)

    def test_wire_retirement_requires_original_assets_and_consumes_attempt(self):
        view=self.module();owner=object.__new__(view._ProcView)
        owner._retirement_attempted=False;owner._fenced=False;owner._witness=None
        owner.check=Mock();owner._wire=Mock();owner._assets=None
        owner.original_error=None
        with self.assertRaises(ValueError):owner._retire_wire(object())
        self.assertTrue(owner._retirement_attempted);self.assertTrue(owner._fenced)
        with self.assertRaises(ValueError):owner._retire_wire(object())

    def test_capture_rejects_nonproc_before_trusting_text_records(self):
        view=self.module()
        from automation.control_docker_credentials import CredentialWire
        wire=object.__new__(CredentialWire)
        anchor=object();wire.anchor=anchor;wire._owner=(os.getpid(),threading.current_thread())
        wire.listener=SimpleNamespace(pid=1);wire.backend=SimpleNamespace(pid=2);wire._live=Mock()
        info=SimpleNamespace(st_dev=1,st_ino=2,st_mode=0o40755)
        with patch.object(view,'ResourceClock'),patch.object(view.os,'geteuid',return_value=0),patch.object(view.os,'getegid',return_value=0), \
             patch.object(view.os,'open',return_value=30) as opened,patch.object(view.os,'close') as closed, \
             patch.object(view.os,'fstat',return_value=info),patch.object(view,'filesystem_type',return_value=0x1234), \
             patch.object(view,'_parse_mountinfo') as parsed:
            with self.assertRaisesRegex(ValueError,'genuine original procfs'):view._ProcView._capture(wire,5,anchor)
        self.assertEqual(opened.call_count,1);closed.assert_called_once_with(30);parsed.assert_not_called()

    def test_record_substitution_rejects_before_reading(self):
        view=self.module();owner=object.__new__(view._ProcView)
        owner._boundary=Mock();owner._proc_mount=7;owner._proc_identity=(1,2,0o40000)
        owner._closed=owner._fenced=False;owner.cleanup_errors=()
        with patch.object(view.os,'open',return_value=30),patch.object(view.os,'close') as closed, \
             patch.object(view,'filesystem_type',return_value=0x9fa0),patch.object(view,'_mount_id',return_value=8), \
             patch.object(view.os,'pread') as read:
            with self.assertRaisesRegex(ValueError,'genuine original procfs'):owner._read(10,'stat',4096)
        read.assert_not_called();closed.assert_called_once_with(30)

    def test_same_inode_named_proc_overmount_rejects(self):
        view=self.module();owner=object.__new__(view._ProcView)
        owner._boundary=Mock();owner._proc=10;owner._proc_mount=7
        owner._proc_identity=(1,2,0o40000);owner._fenced=False;owner.cleanup_errors=()
        info=SimpleNamespace(st_dev=1,st_ino=2,st_mode=0o40755)
        with patch.object(view.os,'open',return_value=30),patch.object(view.os,'close') as closed, \
             patch.object(view.os,'fstat',return_value=info),patch.object(view,'filesystem_type',return_value=0x9fa0), \
             patch.object(view,'_mount_id',side_effect=lambda fd:8 if fd==30 else 7):
            with self.assertRaisesRegex(ValueError,'named original proc mount'):owner._check_named_root()
        closed.assert_called_once_with(30)

    def test_loss_fences_before_recovery_of_numeric_slot(self):
        view=self.module();owner=object.__new__(view._ProcView)
        owner._owner=(os.getpid(),threading.current_thread());owner._closed=owner._fenced=False
        owner._clock=SimpleNamespace(check=Mock(side_effect=ValueError('original lost')))
        owner._wire=Mock();owner._witness=None
        with patch.object(view.os,'geteuid',return_value=0),patch.object(view.os,'getegid',return_value=0):
            with self.assertRaises(ValueError):owner._boundary()
            owner._clock.check.side_effect=None
            with self.assertRaises(ValueError):owner._boundary()
        owner._wire._live.assert_not_called()

if __name__=='__main__':unittest.main()
