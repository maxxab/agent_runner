"""Fixed-source metadata with wholly substituted filesystem and clock calls."""
import errno
import os
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch


class SourcePinTests(unittest.TestCase):
    def setUp(self):
        from automation import control_runtime_source_pins as pins
        from tests.test_automation_launch_data import LaunchDataTests
        from automation import control_store as cs
        fixture=LaunchDataTests();fixture.setUp()
        self.p=pins;self.origin=fixture.origin;self.raw=cs.canonical(fixture.doc).encode()
        self.data=fixture.decode();self.files={f.source:f for f in self.data.files}
        self.paths={};self.closed=[];self.flags=[];self.stats={};self.mode=None;self.expired=False
        self.initial=patch.object(pins,'_attempted',False);self.initial.start();self.addCleanup(self.initial.stop)

    def fixture(self):
        from contextlib import ExitStack
        stack=ExitStack();self.addCleanup(stack.close)
        def opened(path,flags,*,dir_fd=None):
            self.assertTrue(flags&os.O_PATH)
            self.assertTrue(flags&os.O_NOFOLLOW)
            self.assertTrue(flags&os.O_CLOEXEC)
            if path=='/':self.assertIsNone(dir_fd);full='/'
            else:
                self.assertIsNotNone(dir_fd)
                self.assertNotIn('/',path)
                full=self.paths[dir_fd].rstrip('/')+'/'+path
            fd=100+len(self.paths);self.paths[fd]=full;self.flags.append(flags);return fd
        def fstat(fd):
            path=self.paths[fd];self.stats[fd]=self.stats.get(fd,0)+1
            file=self.files.get(path)
            mode=stat.S_IFDIR|0o555 if file is None else stat.S_IFREG|(0o555 if file.target in ('/rnr/guardian','/rnr/codex') else 0o444)
            info=SimpleNamespace(st_dev=1,st_ino=1000+fd,st_mode=mode,st_uid=0,st_gid=0,
                st_nlink=1,st_size=0 if file is None else file.bytes,st_mtime_ns=123,st_ctime_ns=456)
            if self.mode=='ancestor' and path=='/rnr':info.st_mode|=0o020
            if self.mode=='rootowner' and path=='/':info.st_uid=1
            if file is not None:
                if self.mode=='symlink':info.st_mode=stat.S_IFLNK|0o777
                if self.mode=='device':info.st_mode=stat.S_IFCHR|0o444
                if self.mode=='owner':info.st_gid=1
                if self.mode=='leafmode':info.st_mode=stat.S_IFREG|0o644
                if self.mode=='link':info.st_nlink=2
                if self.mode=='size':info.st_size+=1
                if self.mode=='range':info.st_ino=2**63
                if self.mode=='drift' and self.stats[fd]==2:info.st_ino+=1
            return info
        def close(fd):
            self.assertNotIn(fd,self.closed)
            self.closed.append(fd)
            if self.mode in ('cleanup','both') and self.paths[fd] in self.files:
                raise OSError(errno.EINTR,'leaf close uncertain')
            if self.mode=='expiry' and self.paths[fd] in self.files:self.expired=True
        def check(*args):
            if self.expired:raise ValueError('original setup expired during cleanup')
        mocks={}
        for target,name,options in ((self.p.os,'geteuid',dict(return_value=0)),
                (self.p.os,'getegid',dict(return_value=0)),(self.p.os,'open',dict(side_effect=opened)),
                (self.p.os,'fstat',dict(side_effect=fstat)),(self.p.os,'close',dict(side_effect=close)),
                (self.p.clock,'_check_native_initial_setup',dict(side_effect=check)),
                (self.p,'_Clock',dict(return_value=SimpleNamespace(check=check)))):
            mocks[name]=stack.enter_context(patch.object(target,name,**options))
        if self.mode=='both':
            actual=mocks['fstat'].side_effect
            def broken(fd):
                info=actual(fd)
                if self.paths[fd] in self.files:raise ValueError('initiating metadata failure')
                return info
            mocks['fstat'].side_effect=broken
        return mocks

    def test_generation_data_cannot_fall_back_to_metadata_only_observation(self):
        import json
        from automation import control_store as cs
        doc=json.loads(self.raw);doc.update(version=2,asset_root='f'*64)
        mocks=self.fixture()
        with self.assertRaisesRegex(ValueError,'retained verity admission'):
            self.p._observe_fixed_sources(cs.canonical(doc).encode(),self.origin)
        mocks['open'].assert_not_called()

    def test_exact_seven_metadata_pins_without_content_reads(self):
        self.fixture()
        with patch.object(os,'read',side_effect=AssertionError('no reads')), \
                patch.object(os,'pread',side_effect=AssertionError('no reads')):
            result=self.p._observe_fixed_sources(self.raw,self.origin)
        self.assertEqual(result.data,self.data)
        self.assertIs(type(result.pins),tuple)
        self.assertEqual(tuple(p.file for p in result.pins),self.data.files)
        self.assertEqual(len(self.closed),len(self.paths))
        self.assertEqual(len(result.pins),7)
        self.assertTrue(all(p.uid==p.gid==0 for p in result.pins))
        with self.assertRaises(AttributeError):result.pins=()

    def test_malformed_or_wrong_owner_never_opens_and_attempt_is_consumed(self):
        mocks=self.fixture()
        with self.assertRaises(ValueError):self.p._observe_fixed_sources(b'{}',self.origin)
        with self.assertRaises(ValueError):self.p._observe_fixed_sources(self.raw,self.origin)
        mocks['open'].assert_not_called()
        with patch.object(self.p,'_attempted',False):
            mocks['geteuid'].return_value=1
            with self.assertRaises(ValueError):self.p._observe_fixed_sources(self.raw,self.origin)
        mocks['open'].assert_not_called()

    def test_original_setup_is_checked_before_any_open(self):
        mocks=self.fixture()
        mocks['_check_native_initial_setup'].side_effect=ValueError('original setup expired')
        with self.assertRaises(ValueError):self.p._observe_fixed_sources(self.raw,self.origin)
        mocks['open'].assert_not_called()

    def test_bad_ancestors_leaf_type_permissions_size_and_metadata_reject(self):
        for mode in ('ancestor','rootowner','symlink','device','owner','leafmode','link','size','range','drift'):
            with self.subTest(mode=mode),patch.object(self.p,'_attempted',False):
                self.mode=mode;self.paths={};self.closed=[];self.stats={}
                self.fixture()
                with self.assertRaises(ValueError):self.p._observe_fixed_sources(self.raw,self.origin)
                self.assertEqual(len(self.closed),len(self.paths))

    def test_cleanup_uncertainty_and_expiry_prevent_pin_publication(self):
        for mode in ('cleanup','expiry'):
            with self.subTest(mode=mode),patch.object(self.p,'_attempted',False):
                self.mode=mode;self.paths={};self.closed=[];self.stats={};self.expired=False
                self.fixture()
                with self.assertRaises((ValueError,OSError)):self.p._observe_fixed_sources(self.raw,self.origin)
                self.assertEqual(len(self.closed),len(self.paths))

    def test_initiating_error_survives_uncertain_leaf_close(self):
        self.mode='both';self.fixture()
        with self.assertRaisesRegex(ValueError,'initiating metadata failure') as caught:
            self.p._observe_fixed_sources(self.raw,self.origin)
        self.assertEqual(caught.exception.seal_cleanup_errors[0].errno,errno.EINTR)
        self.assertEqual(len(self.closed),len(self.paths))


if __name__=='__main__':unittest.main()
