"""Run directory ownership under mocked privileged filesystem boundaries."""
import os
import stat
import threading
import unittest
from types import SimpleNamespace
from unittest import mock
from automation import control_runtime_state as state


def info(inode=7,mode=0o700,uid=0):
    return SimpleNamespace(st_dev=9,st_ino=inode,st_mode=stat.S_IFDIR|mode,st_uid=uid,st_gid=0)


class StateTests(unittest.TestCase):
    def owner(self):
        obj=object.__new__(state.RunState);obj._owner=os.getpid(),threading.current_thread()
        obj._closed=obj._fenced=False;obj._fds=[90,91];obj._runfd=90;obj._fd=91
        obj._clock=mock.Mock();obj.path='/run/rnr-d00-qualification-'+'a'*32
        obj._parent=state._directory(info(6,0o755));obj._identity=state._directory(info())
        obj._parent_mount=obj._mount=42
        return obj

    def test_directory_contents_change_does_not_change_ownership_identity(self):
        before=info();after=info();before.st_size=0;after.st_size=4096
        before.st_mtime_ns=10;after.st_mtime_ns=20
        self.assertEqual(state._directory(before),state._directory(after))
        for changed in (info(uid=1000),info(mode=0o777)):
            with self.assertRaises(ValueError):state._directory(changed)

    def test_named_replacement_permanently_fences_owner(self):
        owner=self.owner()
        with mock.patch.object(state.os,'fstat',side_effect=[info(6,0o755),info()]), \
             mock.patch.object(state.os,'stat',side_effect=[info(6,0o755),info(8)]), \
             mock.patch.object(state,'_mount_id',return_value=42):
            with self.assertRaises(ValueError):owner.check()
        with self.assertRaises(ValueError):owner.check()
        self.assertTrue(owner._fenced)

    def test_existing_directory_is_not_adopted_or_deleted(self):
        with mock.patch.object(state,'ResourceClock'),mock.patch.object(state.os,'geteuid',return_value=0), \
             mock.patch.object(state.os,'getegid',return_value=0), \
             mock.patch.object(state.fcntl,'fcntl',return_value=os.O_RDONLY), \
             mock.patch.object(state.os,'fstat',return_value=info(6,0o755)), \
             mock.patch.object(state.os,'stat',return_value=info(6,0o755)), \
             mock.patch.object(state.os,'readlink',return_value='/run'), \
             mock.patch.object(state,'_mount_id',return_value=42), \
             mock.patch.object(state.os,'mkdir',side_effect=FileExistsError), \
             mock.patch.object(state.os,'open') as opened, \
             mock.patch.object(state.os,'close') as closed:
            with self.assertRaises(FileExistsError):state.RunState._from_run_fd(90,'rnr-d00-qualification-'+'a'*32,object())
            opened.assert_not_called();closed.assert_called_once_with(90)

    def test_child_fd_is_retained_when_post_open_clock_check_fails(self):
        guard=mock.Mock()
        def opened(*args,**kwargs):
            guard.check.side_effect=ValueError('expired after child open')
            return 91
        with mock.patch.object(state,'ResourceClock',return_value=guard),mock.patch.object(state.os,'geteuid',return_value=0), \
             mock.patch.object(state.os,'getegid',return_value=0), \
             mock.patch.object(state.fcntl,'fcntl',return_value=os.O_RDONLY), \
             mock.patch.object(state.os,'fstat',return_value=info(6,0o755)), \
             mock.patch.object(state.os,'stat',return_value=info(6,0o755)), \
             mock.patch.object(state.os,'readlink',return_value='/run'), \
             mock.patch.object(state,'_mount_id',return_value=42), \
             mock.patch.object(state.os,'mkdir'), \
             mock.patch.object(state.os,'open',side_effect=opened), \
             mock.patch.object(state.os,'close') as closed:
            with self.assertRaisesRegex(ValueError,'expired after child open') as raised:
                state.RunState._from_run_fd(90,'rnr-d00-qualification-'+'a'*32,object())
        self.assertTrue(raised.exception.state_owner.created)
        self.assertEqual(closed.call_args_list,[mock.call(91),mock.call(90)])

    def test_cleanup_attempts_every_owned_fd_once(self):
        owner=self.owner()
        with mock.patch.object(state.os,'close',side_effect=[OSError('uncertain'),None]) as close:
            with self.assertRaises(OSError):owner.close()
            owner.close()
        self.assertEqual(close.call_args_list,[mock.call(91),mock.call(90)])

if __name__=='__main__':unittest.main()
