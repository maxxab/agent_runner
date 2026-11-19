"""Synthetic lifecycle contracts never grant real admission or resource release."""
import copy
import importlib
import importlib.util
import unittest


def run():
    return {'schema_version': 1, 'run_id': 'run-1'}


def allocation(name='a', processes=None):
    return {'schema_version': 1, 'run_id': 'run-1', 'allocation_id': name,
            'generation': 1, 'container_id': 'container-' + name,
            'process_ids': processes if processes is not None else [name + '-p1', name + '-p2']}


def event(name, kind, target='a', resource=None, outcome='succeeded', **changes):
    if resource is None:
        resource = 'container-' + target if kind == 'container_delete' else target
    value = {'schema_version': 1, 'event_id': name, 'run_id': 'run-1',
             'allocation_id': target, 'generation': 1, 'kind': kind,
             'resource_id': resource, 'outcome': outcome,
             'evidence_ref': 'fixture:' + name, 'evidence_sha256': 'a' * 64}
    value.update(changes)
    return value


def proof(target='a', prefix=''):
    return [event(prefix + 'f', 'fence', target),
            event(prefix + 'p1', 'process_exit', target, target + '-p1'),
            event(prefix + 'p2', 'process_exit', target, target + '-p2'),
            event(prefix + 'c', 'container_delete', target)]


class LifecycleFixtureTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('automation.lifecycle'),
                             'source-only lifecycle fixture evaluator is missing')
        self.evaluate = importlib.import_module('automation.lifecycle').evaluate_lifecycle_fixture

    def report(self, observations, allocations=None):
        result = self.evaluate(run(), allocations or [allocation()], observations)
        for key in ('execution_enabled', 'admission_permitted', 'release_permitted',
                    'inventory_complete'):
            self.assertIs(result[key], False)
        self.assertEqual(result['occupied_allocations'], len(allocations or [allocation()]))
        self.assertEqual(result['mode'], 'lifecycle_fixture')
        self.assertEqual(result['schema_version'], 1)
        self.assertEqual(result['run_id'], 'run-1')
        return result

    def ready(self, observations):
        return self.report(observations)['allocations'][0]['synthetic_release_prerequisites_satisfied']

    def test_no_observations_or_noncleanup_signals_never_release(self):
        self.assertFalse(self.ready([]))
        for kind in ('stop_requested', 'stop_acknowledged', 'owner_finished', 'archive', 'unsubscribe'):
            with self.subTest(kind=kind):
                self.assertFalse(self.ready([event('only', kind)]))
                self.assertFalse(self.ready([proof()[0], event('only', kind)]))

    def test_complete_synthetic_proof_retains_real_capacity_and_denial(self):
        report = self.report(proof())
        self.assertEqual(report['allocations'], [{
            'allocation_id': 'a', 'generation': 1, 'fence_event_id': 'f',
            'exited_process_ids': ['a-p1', 'a-p2'], 'container_delete_event_id': 'c',
            'synthetic_release_prerequisites_satisfied': True, 'reasons': []}])
        self.assertEqual(report['reasons'], ['fixture_order_unverified', 'inventory_unverified', 'source_only'])

    def test_partial_process_and_container_proof_stays_incomplete(self):
        for missing in (1, 2, 3):
            with self.subTest(missing=missing):
                self.assertFalse(self.ready([item for index, item in enumerate(proof()) if index != missing]))

    def test_cleanup_before_or_without_fence_cannot_be_spliced(self):
        self.assertFalse(self.ready(proof()[1:]))
        self.assertFalse(self.ready(proof()[1:] + proof()[:1]))
        self.assertFalse(self.ready([proof()[1], proof()[0], *proof()[2:]]))

    def test_reload_invalidates_fence_and_every_prior_cleanup_observation(self):
        for insertion in (1, 2, 3, 4):
            with self.subTest(insertion=insertion):
                observations = proof()
                observations.insert(insertion, event('reload', 'reload'))
                self.assertFalse(self.ready(observations))

    def test_new_fence_and_fresh_complete_proof_recovers_after_successful_reload(self):
        self.assertTrue(self.ready(proof() + [event('reload', 'reload')] + proof(prefix='new-')))
        self.assertFalse(self.ready(proof() + [event('reload', 'reload'), event('new-f', 'fence')] + proof()[1:]))

    def test_new_distinct_fence_resets_proof_but_exact_fence_replay_does_not(self):
        self.assertFalse(self.ready(proof() + [event('new-f', 'fence')]))
        self.assertTrue(self.ready(proof() + [proof()[0]]))

    def test_any_failed_or_unknown_observation_is_sticky(self):
        for outcome in ('failed', 'unknown'):
            for kind, resource in (('fence', 'a'), ('process_exit', 'a-p1'),
                                   ('container_delete', 'container-a'), ('reload', 'a'),
                                   ('stop_acknowledged', 'a'), ('owner_finished', 'a')):
                for before in (False, True):
                    with self.subTest(outcome=outcome, kind=kind, before=before):
                        failure = event('uncertain', kind, resource=resource, outcome=outcome)
                        observations = [failure] + proof() if before else proof() + [failure]
                        result = self.report(observations)['allocations'][0]
                        self.assertFalse(result['synthetic_release_prerequisites_satisfied'])
                        self.assertIn('failed_or_unknown_observation', result['reasons'])

    def test_replay_never_revives_after_reload_or_uncertainty(self):
        self.assertTrue(self.ready(proof() * 3))
        self.assertFalse(self.ready(proof() + [event('reload', 'reload')] + proof()))
        self.assertFalse(self.ready(proof() + [event('bad', 'fence', outcome='unknown')] + proof()))
        observations = proof() + [event('reload', 'reload')] + proof(prefix='fresh-')
        self.assertTrue(self.ready(observations + [event('reload', 'reload')]))

    def test_changed_global_event_id_is_rejected_even_after_complete_proof(self):
        for changed in ({'outcome': 'failed'}, {'evidence_ref': 'different'},
                        {'evidence_sha256': 'b' * 64}, {'kind': 'reload'},
                        {'allocation_id': 'b', 'resource_id': 'b'}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.evaluate(run(), [allocation(), allocation('b')], proof() + [dict(proof()[0], **changed)])

    def test_run_allocation_generation_and_resource_identity_are_exact(self):
        for changed in ({'run_id': 'other'}, {'allocation_id': 'other'}, {'generation': 2},
                        {'resource_id': 'other'}, {'resource_id': 'a-p1'}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.evaluate(run(), [allocation()], [dict(proof()[0], **changed)])
        for kind, resource in (('process_exit', 'container-a'), ('process_exit', 'undeclared-descendant'),
                               ('container_delete', 'a-p1'), ('container_delete', 'container-b')):
            with self.subTest(kind=kind, resource=resource), self.assertRaises(ValueError):
                self.evaluate(run(), [allocation()], [event('bad', kind, resource=resource)])

    def test_mixed_allocations_have_no_cross_credit_or_hidden_occupancy(self):
        result = self.report(proof(), [allocation(), allocation('b')])
        self.assertTrue(result['allocations'][0]['synthetic_release_prerequisites_satisfied'])
        self.assertFalse(result['allocations'][1]['synthetic_release_prerequisites_satisfied'])
        with self.assertRaises(ValueError):
            self.evaluate(run(), [allocation(), allocation('b')],
                          proof() + [event('wrong', 'process_exit', 'b', 'a-p1')])
        report = self.report(proof('b') + proof(prefix='a-'), [allocation(), allocation('b')])
        self.assertTrue(all(row['synthetic_release_prerequisites_satisfied'] for row in report['allocations']))

    def test_declarations_reject_empty_duplicate_or_wrong_run_inventory(self):
        invalid = [[], [allocation(processes=[])], [allocation(), allocation()],
                   [allocation(processes=['p', 'p'])],
                   [allocation(), dict(allocation('b'), container_id='container-a')],
                   [allocation(), allocation('b', ['a-p1'])],
                   [dict(allocation(), run_id='other')]]
        for allocations in invalid:
            with self.subTest(allocations=allocations), self.assertRaises(ValueError):
                self.evaluate(run(), allocations, [])

    def test_exact_record_fields_types_versions_and_enums(self):
        cases = []
        for where in ('run', 'allocation', 'event'):
            for change in ({'schema_version': True}, {'schema_version': 2}, {'extra': 1},
                           {'run_id': 3}, {'run_id': ''}, {'run_id': '\ud800'},
                           {'run_id': 'line\nbreak'}, {1: 'bad'}):
                cases.append((where, change))
        cases.extend(('allocation', {'generation': value}) for value in (True, 0, -1, 2147483648, 1.0))
        cases.extend(('event', change) for change in (
            {'generation': True}, {'kind': []}, {'kind': 'released'}, {'outcome': True},
            {'outcome': 'complete'}, {'evidence_ref': 'x' * 1025}, {'evidence_ref': '\x00'},
            {'evidence_sha256': 'A' * 64}, {'evidence_sha256': 'a' * 63}))
        for where, change in cases:
            r, a, e = run(), allocation(), event('e', 'fence')
            {'run': r, 'allocation': a, 'event': e}[where].update(change)
            with self.subTest(where=where, change=change), self.assertRaises(ValueError):
                self.evaluate(r, [a], [e])
        for where in ('run', 'allocation', 'event'):
            r, a, e = run(), allocation(), event('e', 'fence')
            del {'run': r, 'allocation': a, 'event': e}[where]['schema_version']
            with self.subTest(missing=where), self.assertRaises(ValueError):
                self.evaluate(r, [a], [e])

    def test_plain_containers_only_and_invalid_tail_is_not_skipped(self):
        class DictSubclass(dict):
            pass
        class ListSubclass(list):
            pass
        invalid = [(DictSubclass(run()), [allocation()], []),
                   (run(), (allocation(),), []), (run(), ListSubclass([allocation()]), []),
                   (run(), [DictSubclass(allocation())], []), (run(), [allocation()], ()),
                   (run(), [allocation()], ListSubclass([])),
                   (run(), [allocation(processes=('p',))], []),
                   (run(), [allocation()], [DictSubclass(event('e', 'fence'))])]
        for args in invalid:
            with self.subTest(args=args), self.assertRaises(ValueError):
                self.evaluate(*args)
        with self.assertRaises(ValueError):
            self.evaluate(run(), [allocation()], proof() + [{'schema_version': 1}])

    def test_count_bounds_are_enforced_before_deduplication(self):
        for args in ((run(), [allocation()] * 1001, []),
                     (run(), [allocation(processes=['p'] * 1001)], []),
                     (run(), [allocation()], [event('same', 'fence')] * 10001)):
            with self.subTest(kind=len(args[2])), self.assertRaises(ValueError):
                self.evaluate(*args)
        allocations = [allocation(str(i), [f'{i}-{j}' for j in range(1000)]) for i in range(11)]
        with self.assertRaises(ValueError):
            self.evaluate(run(), allocations, [])

    def test_maximum_inventory_events_and_unicode_fields_are_accepted(self):
        allocations = [allocation(str(i), [f'{i}-{j}' for j in range(10)]) for i in range(1000)]
        observations = [event(str(i), 'stop_requested', '0') for i in range(10000)]
        result = self.evaluate(run(), allocations, observations)
        self.assertEqual(result['occupied_allocations'], 1000)
        self.assertFalse(any(row['synthetic_release_prerequisites_satisfied'] for row in result['allocations']))
        r = {'schema_version': 1, 'run_id': '😀' * 128}
        a = dict(allocation('a' * 128, ['p' * 128]), run_id=r['run_id'],
                 generation=2147483647, container_id='c' * 128)
        e = event('e' * 128, 'fence', 'a' * 128, run_id=r['run_id'],
                  generation=2147483647, evidence_ref='😀' * 1024)
        self.assertEqual(self.evaluate(r, [a], [e])['allocations'][0]['fence_event_id'], 'e' * 128)
        for target, key in ((r, 'run_id'), (a, 'container_id'), (e, 'event_id')):
            old = target[key]
            target[key] = 'x' * 129
            with self.assertRaises(ValueError):
                self.evaluate(r, [a], [e])
            target[key] = old

    def test_inputs_unchanged_outputs_fresh_and_order_deterministic(self):
        args = (run(), [allocation()], [proof()[0], proof()[2], proof()[1], proof()[3]])
        original = copy.deepcopy(args)
        result = self.evaluate(*args)
        self.assertEqual(args, original)
        self.assertEqual(result, self.evaluate(*args))
        self.assertEqual(result['allocations'][0]['exited_process_ids'], ['a-p1', 'a-p2'])
        result['allocations'][0]['exited_process_ids'].clear()
        result['allocations'][0]['reasons'].append('mutated')
        result['reasons'].clear()
        self.assertEqual(args, original)
        self.assertEqual(len(self.evaluate(*args)['allocations'][0]['exited_process_ids']), 2)


if __name__ == '__main__':
    unittest.main()
