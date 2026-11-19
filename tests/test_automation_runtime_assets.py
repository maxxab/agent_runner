"""Authenticate manifest declarations only within a retained verity generation."""
import json
import unittest
import os
import threading
from unittest import mock
from automation import control_runtime_assets as assets
from automation import control_store as cs
from automation.control_runtime_seal import _DESTINATIONS

ROOT='ab'*32
FILES=tuple(cs.RuntimeFile('/var/lib/rnr/assets/'+ROOT+'/'+_DESTINATIONS[t],t,'cd'*32,12)
            for t in sorted(_DESTINATIONS))

def manifest(files=FILES):
    return cs.canonical({'version':1,'files':[{'target':f.target,'content_digest':f.content_digest,'bytes':f.bytes} for f in files]}).encode()

class ManifestTests(unittest.TestCase):
    def test_exact_external_files_match_authenticated_manifest(self):
        self.assertEqual(assets.verify_manifest(manifest(),ROOT,FILES),FILES)

    def test_manifest_cannot_select_its_own_digest_or_target(self):
        data=json.loads(manifest());data['files'][0]['content_digest']='ef'*32
        with self.assertRaises(ValueError): assets.verify_manifest(cs.canonical(data).encode(),ROOT,FILES)
        data=json.loads(manifest());data['root_digest']=ROOT
        with self.assertRaises(ValueError): assets.verify_manifest(cs.canonical(data).encode(),ROOT,FILES)

    def test_generation_path_must_be_derived_from_external_root(self):
        with self.assertRaises(ValueError): assets.verify_manifest(manifest(), 'ef'*32, FILES)
        with self.assertRaises(ValueError): assets.verify_manifest(manifest(), '../x', FILES)

    def test_exact_seven_ordered_targets_required(self):
        for files in (FILES[:-1],FILES+(FILES[0],),tuple(reversed(FILES))):
            with self.subTest(length=len(files)),self.assertRaises(ValueError):
                assets.verify_manifest(manifest(files),ROOT,files)

    def test_duplicate_keys_and_noncanonical_bytes_rejected(self):
        for raw in (manifest()+b'\n',manifest().replace(b'"version":1',b'"version":1,"version":1'),b'x'*16385,b'{'):
            with self.subTest(size=len(raw)),self.assertRaises(ValueError):
                assets.verify_manifest(raw,ROOT,FILES)

    def test_closed_manifest_version_and_types(self):
        for value in (True,0,2,'1'):
            data=json.loads(manifest());data['version']=value
            with self.subTest(value=value),self.assertRaises(ValueError):
                assets.verify_manifest(cs.canonical(data).encode(),ROOT,FILES)


class MountTests(unittest.TestCase):
    def record(self,options='ro,nosuid,nodev',superoptions='ro',path=None,kind='squashfs',root='/'):
        path=path or '/var/lib/rnr/assets/'+ROOT
        return f'42 20 253:0 {root} {path} {options} - {kind} /dev/dm-0 {superoptions}\n'.encode()

    def test_exact_readonly_whole_filesystem_mount(self):
        assets.verify_mount(self.record(),42,os.makedev(253,0),'/var/lib/rnr/assets/'+ROOT)

    def test_rejects_writable_or_subtree_or_wrong_namespace_view(self):
        for kwargs in ({'options':'rw'},{'superoptions':'rw'},{'root':'/subdir'},
                       {'kind':'ext4'},{'path':'/other'}):
            with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):
                assets.verify_mount(self.record(**kwargs),42,os.makedev(253,0),'/var/lib/rnr/assets/'+ROOT)
        for raw in (self.record()*2,b'',self.record().replace(b'42 ',b'43 ',1),b'x'*1048577):
            with self.subTest(size=len(raw)),self.assertRaises(ValueError):
                assets.verify_mount(raw,42,os.makedev(253,0),'/var/lib/rnr/assets/'+ROOT)

    def test_rejects_stacked_and_descendant_mounts_but_allows_neighbors(self):
        root='/var/lib/rnr/assets/'+ROOT
        for path,parent in ((root,20),(root+'/home',42),(root+'/hidden',999)):
            extra=f'43 {parent} 8:1 / {path} ro - ext4 /dev/sda1 ro\n'.encode()
            with self.subTest(path=path),self.assertRaises(ValueError):
                assets.verify_mount(self.record()+extra,42,os.makedev(253,0),root)
        for path in ('/var/lib/rnr/assets',root+'0',root+'-other'):
            extra=f'43 20 8:1 / {path} ro - ext4 /dev/sda1 ro\n'.encode()
            assets.verify_mount(self.record()+extra,42,os.makedev(253,0),root)


class GenerationOwnerTests(unittest.TestCase):
    def owner(self):
        owner=object.__new__(assets.AssetGeneration)
        owner._owner=os.getpid(),threading.current_thread()
        owner._closed=owner._fenced=False
        owner._fds=[90,91];owner._clock=mock.Mock();owner._verity=mock.Mock()
        return owner

    def test_post_open_clock_failure_preserves_fd_for_cleanup(self):
        owner=self.owner();owner._rootfd=92;owner._fds=[]
        owner._clock.check.side_effect=[None,ValueError('expired')]
        with mock.patch.object(assets.os,'open',return_value=93):
            with self.assertRaisesRegex(ValueError,'expired'):owner._keep('manifest.json')
        self.assertEqual(owner._fds,[93])

    def test_mapping_failure_is_permanent(self):
        owner=self.owner();owner._verity.check.side_effect=ValueError('replaced')
        with self.assertRaisesRegex(ValueError,'replaced'):owner.check()
        owner._verity.check.reset_mock(side_effect=True)
        with self.assertRaises(ValueError):owner.check()
        owner._verity.check.assert_not_called()

    def test_same_inode_different_mount_is_rejected_and_closed(self):
        owner=self.owner();owner._mount_id=42
        with mock.patch.object(assets.os,'open',return_value=93), \
             mock.patch.object(assets.os,'fstat'), \
             mock.patch.object(assets,'_identity',return_value=('same',)), \
             mock.patch.object(assets,'_mount_id',return_value=43), \
             mock.patch.object(assets.os,'close') as close:
            with self.assertRaises(ValueError):owner._check_named('/x',('same',))
            close.assert_called_once_with(93)

    def test_nonwire_cannot_supply_daemon_authority(self):
        owner=self.owner()
        with self.assertRaises(ValueError):owner.verify_daemon_paths(mock.Mock(_verified=True))
        self.assertTrue(owner._fenced)

    def test_cleanup_attempts_all_descriptors_without_unmount(self):
        owner=self.owner();owner._verity.close.side_effect=OSError('mapping close uncertain')
        with mock.patch.object(assets.os,'close',side_effect=[OSError('fd uncertain'),None]) as close:
            with self.assertRaisesRegex(OSError,'mapping close uncertain') as raised:owner.close()
            owner.close()
            self.assertEqual(close.call_args_list,[mock.call(91),mock.call(90)])
            self.assertEqual(len(raised.exception.asset_cleanup_errors),1)

if __name__=='__main__':unittest.main()
