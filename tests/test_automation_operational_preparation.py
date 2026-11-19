"""One-shot fixed-role ownership with simulated native/physical boundaries."""
from contextlib import ExitStack
import unittest
from types import SimpleNamespace
from unittest.mock import Mock,patch
from automation import control_store as cs
from tests.test_automation_launch_data import LaunchDataTests


class OperationalPreparationTests(unittest.TestCase):
    def setUp(self):
        from automation import control_runtime_operational as op
        self.op=op;fixture=LaunchDataTests();fixture.setUp();self.fixture=fixture
        fixture.doc.update(version=3,asset_root='f'*64,execution_root='1'*64,daemon_digest='2'*64)
        self.context=SimpleNamespace(origin=fixture.origin,payload=cs.canonical(fixture.doc).encode())
        self.stack=ExitStack();self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(op,'_attempted',False))
        self.stack.enter_context(patch.object(op.handoff,'_attempted',False))
        self.consume=self.stack.enter_context(patch.object(op.handoff,'_consume_context',return_value=self.context))
        self.setup=self.stack.enter_context(patch.object(op.clock,'_check_native_initial_setup'))
        self.stack.enter_context(patch.object(op.os,'geteuid',return_value=0))
        self.stack.enter_context(patch.object(op.os,'getegid',return_value=0))
        self.closed=[];self.close=self.stack.enter_context(patch.object(op.os,'close',side_effect=self.closed.append))
        self.entry=object.__new__(op.RootEntry)
        self.factory=self.stack.enter_context(patch.object(op.RootEntry,'_from_original_generation_fds',return_value=self.entry))

    def test_original_transfer_once_never_closes_transferred_or_reused_numbers(self):
        owner=self.op._prepare_original()
        self.assertIs(owner.entry,self.entry);self.assertIs(owner._context,self.context)
        self.assertEqual(self.factory.call_args.args[0],(3,4,5,6,7,8))
        self.assertEqual(self.factory.call_args.args[3:6],('1'*64,'2'*64,'f'*64))
        self.setup.assert_called_once_with(self.context.origin)
        self.assertEqual(self.closed,[])
        with self.assertRaisesRegex(ValueError,'consumed'):self.op._prepare_original()
        self.consume.assert_called_once();self.factory.assert_called_once();self.assertEqual(self.closed,[])

    def test_failed_decode_drains_originals_once_and_retains_uncertain_close(self):
        self.context.payload=b'{}';table={fd:'original' for fd in range(3,9)}
        def close(fd):
            self.closed.append(fd);del table[fd]
            if fd==4:raise OSError('close uncertain')
        self.close.side_effect=close
        with self.assertRaises(ValueError) as failure:self.op._prepare_original()
        owner=failure.exception.original_preparation
        self.assertEqual(self.closed,list(range(3,9)))
        self.assertEqual([(role,str(error)) for role,error in owner.cleanup_errors],[(4,'close uncertain')])
        self.assertEqual(owner._incoming,[]);self.factory.assert_not_called()
        table.update({fd:'reused' for fd in range(3,9)})
        with self.assertRaisesRegex(ValueError,'consumed'):self.op._prepare_original()
        self.assertEqual(table,{fd:'reused' for fd in range(3,9)})
        self.consume.assert_called_once()

    def test_context_already_consumed_never_adopts_fixed_roles(self):
        self.op.handoff._attempted=True
        with self.assertRaisesRegex(ValueError,'context'):self.op._prepare_original()
        self.consume.assert_not_called();self.factory.assert_not_called();self.close.assert_not_called()

    def test_foreign_owner_rejects_without_adopting_or_consuming(self):
        self.op._owner=(self.op.os.getpid()+1,self.op.threading.current_thread())
        self.addCleanup(setattr,self.op,'_owner',(self.op.os.getpid(),self.op.threading.current_thread()))
        with self.assertRaisesRegex(ValueError,'owner'):self.op._prepare_original()
        self.consume.assert_not_called();self.factory.assert_not_called();self.close.assert_not_called()

    def test_native_context_close_uncertainty_is_retained_and_fd9_never_retried(self):
        primary=ValueError('native context invalid');primary.cleanup_error=OSError('FD9 close uncertain')
        self.consume.side_effect=primary
        with self.assertRaises(ValueError) as failure:self.op._prepare_original()
        self.assertIs(failure.exception,primary)
        self.assertIs(primary.original_preparation.original_error,primary)
        self.assertEqual(self.closed,list(range(3,9)))
        with self.assertRaisesRegex(ValueError,'consumed'):self.op._prepare_original()
        self.consume.assert_called_once();self.assertNotIn(9,self.closed)

    def test_original_setup_expiry_closes_untransferred_roles_without_factory(self):
        self.setup.side_effect=ValueError('original setup expired')
        with self.assertRaisesRegex(ValueError,'original setup'):self.op._prepare_original()
        self.factory.assert_not_called();self.assertEqual(self.closed,list(range(3,9)))

    def test_legacy_data_rejects_before_original_factory_and_setup(self):
        for version in (1,2):
            self.op._attempted=False;self.closed.clear()
            doc=dict(self.fixture.doc,version=version)
            del doc['execution_root'];del doc['daemon_digest']
            if version==1:del doc['asset_root']
            self.context.payload=cs.canonical(doc).encode()
            with self.assertRaisesRegex(ValueError,'version3'):self.op._prepare_original()
            self.assertEqual(self.closed,list(range(3,9)))
        self.factory.assert_not_called();self.setup.assert_not_called()

    def test_consuming_rootentry_failure_retains_owner_without_raw_close(self):
        failure=self.op.RootEntryFailure(self.entry);self.factory.side_effect=failure
        with self.assertRaises(self.op.RootEntryFailure) as raised:self.op._prepare_original()
        self.assertIs(raised.exception,failure)
        self.assertIs(failure.original_preparation.entry,self.entry)
        self.assertEqual(self.closed,[])
        with self.assertRaises(ValueError):self.op._prepare_original()
        self.assertEqual(self.closed,[])

    def test_public_entry_stays_disabled_without_consumption(self):
        with self.assertRaisesRegex(RuntimeError,'disabled'):self.op._entry()
        self.consume.assert_not_called();self.factory.assert_not_called();self.close.assert_not_called()


if __name__=='__main__':unittest.main()
