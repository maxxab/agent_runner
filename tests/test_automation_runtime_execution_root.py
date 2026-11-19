"""Immutable execution inventory schema, no launch/runtime authority."""
import json
import unittest
import os
import tempfile
import threading
from unittest.mock import Mock,patch
from types import SimpleNamespace


def manifest():
    names=('/usr/bin/python3.12','/usr/bin/busctl','/rnr/stage0-operational',
        '/rnr/project/automation/__init__.py','/rnr/project/automation/control_runtime_handoff.py',
        '/rnr/project/automation/control_runtime_root_entry.py','/rnr/project/automation/control_runtime_receiver.py',
        '/rnr/project/automation/control_runtime_proc_view.py','/rnr/project/tools/runner_idle_notifications.py')
    return dict(version=1,profile='rnr-d00-linux618-x86_64',files=[dict(path=p,sha256='a'*64,bytes=1,mode=0o555 if p in names[:3] else 0o444) for p in sorted(names)])


class ExecutionInventoryTests(unittest.TestCase):
    def decode(self,data):
        from automation.control_runtime_execution_root import _decode_manifest
        return _decode_manifest(json.dumps(data,sort_keys=True,separators=(',',':')).encode())
    def test_complete_inventory_preserves_pinned_declarations(self):
        rows=self.decode(manifest())
        self.assertEqual(len(rows),9)
        self.assertEqual(rows[0].path,'/rnr/project/automation/__init__.py')
        self.assertEqual(rows[0].sha256,'a'*64)
    def test_unknown_duplicate_conflicting_and_unsafe_members_reject(self):
        for change in ('unknown','duplicate','ancestor','symlinkmode','path','missing','bool','manifest'):
            data=manifest()
            if change=='unknown':data['future']=1
            elif change=='duplicate':data['files'].append(dict(data['files'][0]))
            elif change=='ancestor':data['files'].append(dict(path='/rnr/project',sha256='b'*64,bytes=1,mode=0o444))
            elif change=='symlinkmode':data['files'][0]['mode']=0o777
            elif change=='path':data['files'][0]['path']='/rnr/project/../x'
            elif change=='missing':data['files'].pop()
            elif change=='bool':data['files'][0]['bytes']=True
            elif change=='manifest':data['files'].append(dict(path='/rnr/runtime-manifest.json',sha256='b'*64,bytes=1,mode=0o444))
            data['files'].sort(key=lambda r:r['path'])
            with self.subTest(change=change),self.assertRaises(ValueError):self.decode(data)
    def test_maps_preserve_backing_identity_and_reject_ambiguous_records(self):
        from automation.control_runtime_execution_root import _parse_maps
        raw=b'00001000-00002000 r-xp 00000000 00:07 42    /usr/bin/python3.12\n00003000-00004000 r-xp 00000000 00:00 0    [vdso]\n'
        rows=_parse_maps(raw)
        self.assertEqual((rows[0].device,rows[0].inode,rows[0].path),((0,7),42,'/usr/bin/python3.12'))
        for bad in (raw[:-1],raw+raw,raw.replace(b'r-xp',b'rwxp'),raw.replace(b'/usr/bin/python3.12',b'/usr/bin/python3.12 (deleted)'),
                    raw.replace(b'42    /usr',b'042    /usr'),raw.replace(b'r-xp 00000000 00:00',b'r--p 00000000 00:00'),
                    raw.replace(b'r-xp 00000000 00:00',b'rw-p 00000000 00:00')):
            with self.subTest(raw=bad),self.assertRaises(ValueError):_parse_maps(bad)

    def test_map_consumer_rejects_backing_substitution_and_bounds(self):
        from automation.control_runtime_execution_root import _ExecutionRoot
        from automation.control_runtime_proc_view import _ProcView
        owner=object.__new__(_ExecutionRoot);proc=object.__new__(_ProcView)
        owner.anchor=proc.anchor=object();owner.check=Mock();proc._boundary=Mock();proc.check=Mock()
        owner._fenced=owner._closed=False;owner._owner=(os.getpid(),threading.current_thread())
        owner._clock=SimpleNamespace(check=Mock())
        owner._root_identity=(7,1,0,0,0,1,0,0,0);owner._mount=5;owner._mount_record=None
        owner.members=(SimpleNamespace(path='/usr/bin/python3.12'),)
        proc._dirs={'own':(11,20,None)}
        owner._members={'/usr/bin/python3.12':(7,42,0,0,0,1,1,0,0)}
        owner._elf_paths={'/usr/bin/python3.12'}
        good=b'00001000-00002000 r-xp 00000000 00:07 42    /usr/bin/python3.12\n00003000-00004000 r-xp 00000000 00:00 0    [vdso]\n'
        current=[good]
        proc._read=Mock(side_effect=lambda directory,name,limit:current[0] if name=='maps' else b'5 1 0:7 / / ro - squashfs /dev/dm-0 ro\n')
        with patch('os.geteuid',return_value=0),patch('os.getegid',return_value=0):
            self.assertEqual(len(owner._check_maps(proc)),2)
            for bad in (good.replace(b'07 42',b'07 43'),good.replace(b'00000000 00:07',b'00001000 00:07'),good.splitlines(keepends=True)[0]):
                owner._fenced=False;current[0]=bad
                with self.assertRaises(ValueError):owner._check_maps(proc)
                self.assertTrue(owner._fenced)
                current[0]=good
                with self.assertRaisesRegex(ValueError,'lost'):owner._check_maps(proc)

    def test_mount_graph_uses_original_proc_and_rejects_member_cover(self):
        from automation.control_runtime_execution_root import _ExecutionRoot
        from automation.control_runtime_proc_view import _ProcView
        owner=object.__new__(_ExecutionRoot);proc=object.__new__(_ProcView)
        owner.anchor=proc.anchor=object();owner._boundary=Mock();proc._boundary=Mock();proc.check=Mock()
        owner._root_identity=(7,1);owner._mount=5;owner._mount_record=None
        owner.members=(SimpleNamespace(path='/usr/bin/python3.12'),);proc._dirs={'own':(11,20,None)}
        root=b'5 1 0:7 / / ro - squashfs /dev/dm-0 ro\n'
        proc._read=Mock(return_value=root)
        owner._check_mount_graph(proc)
        proc._read.return_value=root+b'6 5 0:7 /usr/bin/python3.12 /usr/bin/python3.12 ro - squashfs /dev/dm-0 ro\n'
        with self.assertRaisesRegex(ValueError,'overmounted'):owner._check_mount_graph(proc)
        proc._read.reset_mock();proc.check.side_effect=ValueError('bad original proc mount')
        with self.assertRaisesRegex(ValueError,'bad original proc'):owner._check_mount_graph(proc)
        proc._read.assert_not_called()

    def test_named_root_overmount_rejects_without_proc_text_fallback(self):
        from automation import control_runtime_execution_root as root
        owner=object.__new__(root._ExecutionRoot);owner._boundary=Mock()
        owner._root=10;owner._mount=7;owner.cleanup_errors=();owner._fenced=False
        info=SimpleNamespace(st_dev=7,st_ino=42,st_mode=0o40555,st_uid=0,st_gid=0,st_nlink=1,st_size=0,st_mtime_ns=0,st_ctime_ns=0)
        owner._root_identity=root._identity(info)
        with patch.object(root.os,'open',return_value=30),patch.object(root.os,'close') as close, \
             patch.object(root.os,'fstat',return_value=info),patch.object(root.os,'fstatvfs',return_value=SimpleNamespace(f_flag=os.ST_RDONLY)), \
             patch.object(root,'filesystem_type',return_value=0x73717368),patch.object(root,'_mount_id',side_effect=lambda fd:8 if fd==30 else 7), \
             patch('builtins.open',side_effect=AssertionError('untrusted proc text used')):
            with self.assertRaisesRegex(ValueError,'named original execution mount'):owner._readonly_root()
        close.assert_called_once_with(30)

    def test_exact_inventory_rejects_unlisted_importable_file(self):
        from automation.control_runtime_execution_root import _ExecutionRoot,_identity,_mount_id,_decode_manifest
        data=manifest();asset='a'*64
        interfaces=('/proc','/run','/sys/dev','/sys/devices','/sys/fs/cgroup',
            '/etc/systemd','/usr/lib/systemd/system','/usr/local/lib',
            '/var/lib/rnr/assets/'+asset)
        special=('/dev/null','/dev/mapper/control','/rnr/launch.bin',*('/dev/dm-'+str(i) for i in range(256)))
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for path in interfaces:(root/path[1:]).mkdir(parents=True,exist_ok=True)
            for path in (*special,'/rnr/runtime-manifest.json',*(r['path'] for r in data['files'])):
                target=root/path[1:];target.parent.mkdir(parents=True,exist_ok=True);target.touch()
            for path in root.rglob('*'):
                if path.is_dir():path.chmod(0o555)
            owner=object.__new__(_ExecutionRoot);owner._boundary=Mock();owner._fenced=False;owner.cleanup_errors=()
            owner.members=_decode_manifest(json.dumps(data,sort_keys=True,separators=(',',':')).encode());owner.asset_digest=asset
            owner._root=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
            actual_fstat=os.fstat
            def root_metadata(fd):
                st=actual_fstat(fd)
                return SimpleNamespace(**{k:getattr(st,k) for k in ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')},st_uid=0,st_gid=0)
            try:
                owner._root_identity=_identity(actual_fstat(owner._root));owner._mount=_mount_id(owner._root)
                with patch('automation.control_runtime_execution_root.os.fstat',side_effect=root_metadata):
                    owner._inventory()
                    (root/'rnr').chmod(0o755);(root/'rnr/unlisted.py').touch();(root/'rnr').chmod(0o555)
                    with self.assertRaisesRegex(ValueError,'unlisted'):owner._inventory()
            finally:
                os.close(owner._root)
                for path in root.rglob('*'):
                    if path.is_dir():path.chmod(0o755)

    def test_protected_walk_uses_no_symlink_or_host_fallback(self):
        from automation.control_runtime_execution_root import _ExecutionRoot,_identity,_mount_id
        with tempfile.TemporaryDirectory() as directory:
            os.mkdir(directory+'/nested',0o755)
            with open(directory+'/nested/file','wb') as stream:stream.write(b'exact')
            os.chmod(directory+'/nested',0o555);os.chmod(directory+'/nested/file',0o444)
            os.symlink('/etc',directory+'/escape')
            owner=object.__new__(_ExecutionRoot)
            owner._boundary=Mock();owner._closed=owner._fenced=False;owner.cleanup_errors=()
            owner._root=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
            try:
                owner._root_identity=_identity(os.fstat(owner._root));owner._mount=_mount_id(owner._root)
                # Simulate only root ownership, keeping actual openat,
                # mount queries, no-follow and byte observations real.
                observed_fstat=os.fstat
                def root_metadata(fd):
                    info=observed_fstat(fd)
                    data={k:getattr(info,k) for k in ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
                    return SimpleNamespace(**data,st_uid=0,st_gid=0)
                with patch('automation.control_runtime_execution_root.os.fstat',side_effect=root_metadata):
                    fd=owner._open_member('/nested/file')
                    try:
                        self.assertEqual(os.pread(fd,6,0),b'exact')
                        owner._metadata(fd,0o444)
                    finally:os.close(fd)
                    with self.assertRaises(OSError):owner._open_member('/escape/passwd')
            finally:
                os.close(owner._root);os.chmod(directory+'/nested',0o755)

    def test_noncanonical_or_duplicate_json_rejects(self):
        from automation.control_runtime_execution_root import _decode_manifest
        raw=json.dumps(manifest(),sort_keys=True,separators=(',',':')).encode()
        for bad in (raw+b' ',raw.replace(b'"version":1',b'"version":1,"version":1')):
            with self.assertRaises(ValueError):_decode_manifest(bad)

if __name__=='__main__':unittest.main()
