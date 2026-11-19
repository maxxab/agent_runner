"""Bounded parent inventory with simulated kernel observations only."""
import os
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch


class PreforkTests(unittest.TestCase):
    def roles_owner(self):
        from automation.control_runtime_prefork import _PreforkInventory
        owner=object.__new__(_PreforkInventory)
        owner._baseline=SimpleNamespace(_root=SimpleNamespace(_fds=[3,4],_verity=SimpleNamespace(_fds=[5,6])))
        owner._proc=SimpleNamespace(_fds=list(range(7,23)),_witness=SimpleNamespace(_pidfds=(23,24)))
        owner._assets=SimpleNamespace(_fds=list(range(25,42)),_verity=SimpleNamespace(_fds=[42,43]))
        owner._state=SimpleNamespace(_fds=[44,45])
        owner._provisioner=SimpleNamespace(bus=SimpleNamespace(_fds=(46,47,48,49)),
            fs=SimpleNamespace(rootfd=50,targetfd=51,_fragmentfd=52))
        return owner

    def test_role_derivation_has_exact_original_groups_and_rejects_alias_or_loss(self):
        owner=self.roles_owner();roles=owner._roles()
        self.assertEqual(set(roles.values()),set(range(53)))
        self.assertEqual(len([name for name in roles if name.startswith('proc/')]),16)
        owner._provisioner.fs._fragmentfd=51
        with self.assertRaisesRegex(ValueError,'alias'):owner._roles()
        owner._provisioner.fs._fragmentfd=52;owner._proc._fds.pop()
        with self.assertRaisesRegex(ValueError,'count'):owner._roles()

    def test_final_launch_consumes_once_and_rejects_alias_before_scan(self):
        from automation import control_runtime_prefork as pre
        from automation.control_runtime_bootstrap import ObserverLaunch
        for alias in (False,True):
            with self.subTest(alias=alias):
                owner=self.roles_owner();owner.anchor=object()
                owner._attempted=owner._fenced=False;owner.original_error=None
                owner._check_owners=Mock(side_effect=lambda:(_ for _ in ()).throw(ValueError('fenced')) if owner._fenced else None)
                owner._proc._pidfd=Mock();owner._scan=Mock()
                def signature(fd):return (50 if fd==53 else 51 if fd==54 else fd,)
                owner._signature=Mock(side_effect=signature)
                owner._roles_at_capture=owner._roles()
                owner._signatures={fd:signature(fd) for fd in owner._roles_at_capture.values()}
                launch=object.__new__(ObserverLaunch);launch.anchor=owner.anchor;launch._rootfd=53;launch._targetfd=54
                left=SimpleNamespace(fileno=lambda:50 if alias else 55);right=SimpleNamespace(fileno=lambda:56)
                with patch.object(pre,'mount_id',return_value=7):
                    if alias:
                        with self.assertRaisesRegex(ValueError,'aliases'):owner._before_fork(launch,left,right,57)
                        owner._scan.assert_not_called()
                    else:
                        owner._before_fork(launch,left,right,57)
                        roles=owner._scan.call_args.args[0]
                        self.assertEqual(set(roles.values()),set(range(58)))
                    with self.assertRaisesRegex(ValueError,'consumed'):owner._before_fork(launch,left,right,57)
                self.assertTrue(owner._fenced)

    def test_inventory_accepts_exact_roles_and_rejects_extra_without_closing_it(self):
        from automation import control_runtime_prefork as pre
        for extra in (False,True):
            with self.subTest(extra=extra):
                owner=object.__new__(pre._PreforkInventory)
                owner._fenced=False;owner.cleanup_errors=();owner.original_error=None
                owner._owner=(os.getpid(),threading.current_thread())
                proc=SimpleNamespace(_dirs={'own':(os.getpid(),19,None)},_proc_mount=7)
                owner._proc=proc;owner._check_owners=Mock()
                roles={str(fd):fd for fd in range(53)}
                owner._signature=Mock(side_effect=lambda fd:(1,99) if fd in (70,71) else (2,fd))
                observed=[*range(53),70,71]+([72] if extra else [])
                closed=[];active=[False]
                class Scan:
                    def __iter__(self):return iter(SimpleNamespace(name=str(fd)) for fd in observed)
                    def close(self):active[0]=False;closed.append('iterator')
                def scandir(fd):active[0]=True;return Scan()
                def boundary():self.assertFalse(active[0])
                owner._check_owners.side_effect=boundary
                with patch.object(pre.os,'open',return_value=70),patch.object(pre.os,'scandir',side_effect=scandir), \
                     patch.object(pre.os,'close',side_effect=lambda fd:closed.append(fd)), \
                     patch.object(pre,'filesystem_type',return_value=0x9fa0),patch.object(pre,'mount_id',return_value=7):
                    if extra:
                        with self.assertRaisesRegex(ValueError,'unexpected parent'):owner._scan(roles)
                    else:owner._scan(roles)
                self.assertEqual(closed,['iterator',70])

    def test_inventory_close_uncertainty_preserves_primary_and_fences(self):
        from automation import control_runtime_prefork as pre
        owner=object.__new__(pre._PreforkInventory)
        owner._fenced=False;owner.cleanup_errors=();owner.original_error=None
        primary=ValueError('unexpected role');cleanup=OSError('uncertain close')
        with patch.object(pre.os,'close',side_effect=cleanup) as closed:
            owner._close_temporary(70,primary)
        self.assertTrue(owner._fenced);self.assertEqual(owner.cleanup_errors,(cleanup,))
        self.assertEqual(primary.prefork_cleanup_errors,(cleanup,));closed.assert_called_once_with(70)


if __name__=='__main__':unittest.main()
