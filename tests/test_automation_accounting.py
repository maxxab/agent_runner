"""Synthetic cumulative observations must never become charges or authority."""
import copy
import importlib
import itertools
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MAXIMUM = (1 << 63) - 1


def stream(session='s1', source='fixture'):
    return {'schema_version': 1, 'source': source, 'session_id': session}


def event(value, identity='e1', session='s1', turn='t1', **changes):
    result = {'schema_version': 1, 'source': 'fixture', 'session_id': session,
              'turn_id': turn, 'event_id': identity, 'mode': 'cumulative',
              'scope': 'session', 'metric': 'total_tokens', 'unit': 'tokens',
              'value': value, 'evidence_ref': 'fixture://observation',
              'evidence_sha256': 'f' * 64}
    result.update(changes)
    return result


class AccountingTests(unittest.TestCase):
    def module(self):
        self.assertTrue((ROOT/'automation/accounting.py').is_file(),
                        'cumulative observation projection is not implemented')
        return importlib.import_module('automation.accounting')

    def summarize(self, events, expected=None):
        return self.module().summarize_cumulative_usage(
            events, [stream()] if expected is None else expected)

    def test_empty_and_missing_history_are_unknown_not_zero(self):
        for expected in ([], [stream()]):
            result = self.summarize([], expected)
            self.assertIsNone(result['observed_tokens'])
            self.assertIsNone(result['total_tokens'])
            self.assertFalse(result['complete'])
            self.assertFalse(result['execution_enabled'])
            self.assertIn('coverage_unverified', result['reasons'])
        self.assertIn('no_expected_streams', self.summarize([], [])['reasons'])
        self.assertIn('missing_observations', self.summarize([])['streams'][0]['reasons'])

    def test_explicit_zero_is_an_observation_but_not_complete_total(self):
        result = self.summarize([event(0)])
        self.assertEqual(result['observed_tokens'], 0)
        self.assertIsNone(result['total_tokens'])
        self.assertFalse(result['complete'])
        self.assertEqual(result['mode'], 'source_projection')

    def test_identical_replay_is_counted_once(self):
        result = self.summarize([event(123), event(123)])
        self.assertEqual(result['observed_tokens'], 123)
        self.assertEqual(result['streams'][0]['unique_event_count'], 1)
        self.assertNotIn('conflicting_event_identity', result['reasons'])

    def test_conflict_keeps_maximum_and_counts_one_identity_in_both_orders(self):
        for values in ([event(100), event(300)], [event(300), event(100)]):
            result = self.summarize(values)
            self.assertEqual(result['observed_tokens'], 300)
            self.assertEqual(result['streams'][0]['unique_event_count'], 1)
            self.assertIn('conflicting_event_identity', result['reasons'])

    def test_changed_evidence_payload_is_also_an_identity_conflict(self):
        result = self.summarize([event(100), event(100, evidence_sha256='a'*64)])
        self.assertIn('conflicting_event_identity', result['reasons'])

    def test_repeated_snapshot_and_resumed_turn_do_not_add_counters(self):
        result = self.summarize([event(100), event(100, 'e2'),
                                 event(220, 'e3', turn='resumed-turn')])
        self.assertEqual(result['observed_tokens'], 220)
        self.assertEqual(result['streams'][0]['unique_event_count'], 3)

    def test_multiple_sessions_sum_maxima(self):
        result = self.summarize([event(100), event(200, 'e2'), event(50, session='s2')],
                                [stream(), stream('s2')])
        self.assertEqual(result['observed_tokens'], 250)

    def test_new_lower_counter_is_ambiguous_and_cannot_reduce_observation(self):
        result = self.summarize([event(200), event(100, 'e2')])
        self.assertEqual(result['observed_tokens'], 200)
        self.assertIn('cumulative_regression_or_reordering', result['reasons'])

    def test_unknown_and_conflict_reasons_are_sticky_and_numbers_permutation_invariant(self):
        values = [event(100), event(300), event(None, 'e2'), event(200, 'e3')]
        for permutation in itertools.permutations(values):
            result = self.summarize(list(permutation))
            self.assertEqual(result['observed_tokens'], 300)
            self.assertEqual(result['streams'][0]['unique_event_count'], 3)
            self.assertIn('unknown_observation', result['reasons'])
            self.assertIn('conflicting_event_identity', result['reasons'])
            self.assertIsNone(result['total_tokens'])
            self.assertFalse(result['execution_enabled'])

    def test_known_plus_missing_and_unknown_sessions_returns_partial_observation(self):
        result = self.summarize([event(12), event(None, session='s2')],
                                [stream(), stream('s2'), stream('s3')])
        self.assertEqual(result['observed_tokens'], 12)
        self.assertIn('unknown_observation', result['reasons'])
        self.assertIn('missing_observations', result['reasons'])
        self.assertIsNone(result['streams'][1]['observed_tokens'])
        self.assertIsNone(result['streams'][2]['observed_tokens'])

    def test_unknown_only_stays_null(self):
        self.assertIsNone(self.summarize([event(None)])['observed_tokens'])

    def test_delta_or_other_scope_metric_and_unknown_stream_are_rejected(self):
        for changes in ({'mode': 'delta'}, {'scope': 'turn'}, {'metric': 'input_tokens'},
                        {'unit': 'dollars'}, {'session_id': 'undeclared'}, {'source': 'other'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.summarize([event(1, **changes)])

    def test_negative_boolean_float_and_counter_overflow_are_rejected(self):
        for value in (-1, True, 1.5, MAXIMUM+1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.summarize([event(value)])
        with self.assertRaises(ValueError):
            self.summarize([event(MAXIMUM), event(1, session='s2')], [stream(), stream('s2')])

    def test_duplicate_expected_stream_and_multiple_namespaces_are_rejected(self):
        for expected in ([stream(), stream()], [stream(), stream('s2', 'other')]):
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                self.summarize([], expected)

    def test_schema_fields_ids_evidence_and_collection_bounds_are_checked(self):
        cases = [{'schema_version': 2}, {'schema_version': True}, {'unknown': 'field'},
                 {'turn_id': ''}, {'event_id': 'x'*129}, {'source': 'bad\nsource'},
                 {'evidence_ref': 'x'*1025}, {'evidence_sha256': 'not-a-hash'}]
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.summarize([event(1, **changes)])
        with self.assertRaises(ValueError):
            self.summarize([event(1)]*10001)
        with self.assertRaises(ValueError):
            self.summarize([], [stream(str(n)) for n in range(1001)])
        with self.assertRaises(ValueError):
            self.summarize(tuple())

    def test_inputs_are_not_changed_and_output_never_authorizes_action(self):
        events, expected = [event(100)], [stream()]
        before = copy.deepcopy((events, expected))
        result = self.summarize(events, expected)
        self.assertEqual((events, expected), before)
        self.assertFalse(result['execution_enabled'])
        self.assertFalse(result['complete'])
        self.assertIsNone(result['total_tokens'])
        self.assertNotIn('remaining_budget', result)
        self.assertNotIn('money_cost', result)

    def test_missing_nonobject_and_nonstring_field_records_are_rejected(self):
        for item in ({}, None, [], {1: 'invalid'}):
            with self.subTest(item=item), self.assertRaises(ValueError):
                self.summarize([item])
        for expected in ([{}], [None], ({'schema_version': 1},)):
            with self.subTest(expected=expected), self.assertRaises(ValueError):
                self.summarize([], expected)

    def test_control_or_surrogate_text_is_not_a_normalized_identifier(self):
        for changes in ({'event_id': 'bad\x00id'}, {'session_id': '\ud800'},
                        {'evidence_ref': 'bad\nreference'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.summarize([event(1, **changes)])
