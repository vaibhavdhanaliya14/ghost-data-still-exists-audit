"""Offline deterministic tests for Phase 5 timeline reconstruction."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType

from audit_agent.extract import (
    EvidenceExtractionResult, ExtractedObservation, ExtractionDiagnostic,
    ExtractionStatus, FileExtractionResult, IdentifierValue, ObservationTimestamp,
)
from audit_agent.identity import (
    IdentityGraph, IdentityResolution, IdentityResolutionResult, IdentitySource,
    MatchConfidence, ResolutionStatus,
)
from audit_agent.ingest import parse_timestamp
from audit_agent.models import (
    CsvRecord, CsvTable, DatasetBundle, IngestionResult, SourceLocation,
)
from audit_agent.timeline import EventCategory, build_timeline


UTC = timezone.utc


def _identity_result(observations, statuses=None):
    statuses = statuses or {}
    graph = IdentityGraph((), MappingProxyType({}), (), (), MappingProxyType({}), frozenset(), frozenset())
    resolutions = []
    for item in observations:
        status, user, candidates = statuses.get(
            item.observation_id, (ResolutionStatus.UNRESOLVED, None, ()))
        resolutions.append(IdentityResolution(
            target_id=item.observation_id, target_kind="observation", status=status,
            matched_user_id=user, candidate_user_ids=candidates,
            confidence=MatchConfidence.HIGH if user else MatchConfidence.UNRESOLVED,
            input_identifiers=item.identifiers, identifier_matches=(), conflicts=(),
            reason_codes=("synthetic_test_resolution",),
            source=IdentitySource(item.source_path, file_id=item.file_id,
                                  observation_id=item.observation_id, locator=item.locator),
        ))
    return IdentityResolutionResult(graph, (), tuple(resolutions), ())


def _observation(observation_id, raw_times, *, capture="2026-10-01T12:00:00Z",
                 system="profile", resource="r-1", raw_fields=None):
    parsed_times = tuple(ObservationTimestamp(name, raw, parse_timestamp(raw)) for name, raw in raw_times)
    fields = raw_fields or {"system_id": system, "resource_id": resource}
    return ExtractedObservation(
        observation_id, "file-1", "evidence/sample.json", "json", f"json:/{observation_id}",
        "stdlib-json", MappingProxyType(dict(fields)), MappingProxyType(dict(fields)),
        (IdentifierValue("user_id", "u-1", "u-1"),), system, resource,
        parsed_times, parse_timestamp(capture) if capture is not None else None,
    )


def _activity_rows(rows):
    headers = ("activity_id", "event_time", "event_type", "source_system", "target_system",
               "resource_id", "reported_result", "details")
    records = []
    for index, values in enumerate(rows, 1):
        fields = dict(zip(headers, values))
        typed = {"event_time": parse_timestamp(fields["event_time"])}
        records.append(CsvRecord(
            SourceLocation("system_activity.csv", index, index),
            MappingProxyType(fields), MappingProxyType(typed), tuple(values),
        ))
    table = CsvTable("system_activity", Path("system_activity.csv"),
                     headers, tuple(records), True)
    return IngestionResult(DatasetBundle({"system_activity": table}), ())


class TimelineTests(unittest.TestCase):
    def build_with_observations(self, observations, activity=(), statuses=None):
        files = tuple(FileExtractionResult(
            "file-1", "evidence/sample.json", "json", "stdlib-json", ExtractionStatus.COMPLETE,
            observation.captured_at, (observation,), (), (), (),
        ) for observation in observations)
        return build_timeline(_activity_rows(activity), EvidenceExtractionResult(files),
                             _identity_result(observations, statuses))

    def test_utc_normalization_and_inclusive_cutoff_before_at_after(self):
        obs = _observation("o1", [("timestamp", "2026-10-01T17:30:00+05:30")])
        timeline = self.build_with_observations([obs])
        event = timeline.events[0]
        self.assertEqual(event.event_time.value, datetime(2026, 10, 1, 12, 0, tzinfo=UTC))
        self.assertEqual(event.event_time.raw, "2026-10-01T17:30:00+05:30")
        self.assertEqual(len(timeline.eligible_at(datetime(2026, 10, 1, 11, 59, tzinfo=UTC))), 0)
        self.assertEqual(len(timeline.eligible_at(datetime(2026, 10, 1, 12, 0, tzinfo=UTC))), 1)
        self.assertEqual(len(timeline.eligible_at(datetime(2026, 10, 1, 12, 1, tzinfo=UTC))), 1)

    def test_late_captured_earlier_event_is_ineligible_before_capture(self):
        obs = _observation("late", [("updated_at", "2026-10-01T10:00:00Z")],
                           capture="2026-10-02T10:00:00Z")
        timeline = self.build_with_observations([obs])
        self.assertEqual(len(timeline.eligible_at(datetime(2026, 10, 1, 23, 59, tzinfo=UTC))), 0)
        self.assertEqual(len(timeline.eligible_at(datetime(2026, 10, 2, 10, 0, tzinfo=UTC))), 1)

    def test_transcribed_screenshot_inner_event_and_capture_cutoffs_are_independent(self):
        obs = _observation("image-journal", [("recorded_at", "2026-08-25T04:03:00Z")],
                           capture="2026-09-05T07:00:00Z",
                           raw_fields={"system_id": "security_service", "resource_id": "audit_record_003",
                                       "event_type": "account_closure_recorded", "user_id": "u-1"})
        timeline = self.build_with_observations([obs])
        self.assertEqual(timeline.events[0].event_time.value,
                         datetime(2026, 8, 25, 4, 3, tzinfo=UTC))
        self.assertEqual(timeline.events[0].capture_time.value,
                         datetime(2026, 9, 5, 7, 0, tzinfo=UTC))
        self.assertEqual(timeline.eligible_at(datetime(2026, 8, 25, 4, 3, tzinfo=UTC)), ())
        self.assertEqual(len(timeline.eligible_at(datetime(2026, 9, 5, 7, 0, tzinfo=UTC))), 1)

    def test_post_cutoff_occurrence_is_not_eligible(self):
        timeline = self.build_with_observations([_observation(
            "future", [("event_time", "2026-10-02T00:00:01Z")], capture="2026-10-01T12:00:00Z")])
        self.assertFalse(timeline.eligible_at(datetime(2026, 10, 2, 0, 0, tzinfo=UTC)))

    def test_missing_and_malformed_timestamps_are_retained_but_not_eligible(self):
        observations = [
            _observation("missing", [("timestamp", "")]),
            _observation("malformed", [("timestamp", "yesterday-ish")]),
        ]
        timeline = self.build_with_observations(observations)
        self.assertEqual(len(timeline.events), 2)
        self.assertEqual({event.timestamp_quality for event in timeline.events}, {"missing", "invalid"})
        self.assertEqual(timeline.eligible_at(datetime(2026, 10, 3, tzinfo=UTC)), ())

    def test_unknown_capture_time_cannot_establish_cutoff_eligibility(self):
        timeline = self.build_with_observations([_observation(
            "unknown-capture", [("timestamp", "2026-10-01T11:00:00Z")], capture=None)])
        self.assertEqual(timeline.events[0].capture_time_required, True)
        self.assertEqual(timeline.eligible_at(datetime(2026, 10, 1, 12, 0, tzinfo=UTC)), ())

    def test_equal_time_conflicting_claims_are_retained_and_reported(self):
        rows = [
            ("a1", "2026-10-01T12:00:00Z", "DELETE_RECORD", "db", "db", "r", "SUCCESS", ""),
            ("a2", "2026-10-01T12:00:00Z", "DELETE_RECORD", "db", "db", "r", "FAILED", ""),
        ]
        timeline = self.build_with_observations([], rows)
        self.assertEqual(len(timeline.events), 2)
        self.assertEqual(len(timeline.conflicts), 1)
        self.assertEqual(timeline.conflicts[0].competing_values, ("FAILED", "SUCCESS"))
        self.assertEqual({event.category for event in timeline.events}, {EventCategory.DELETION})

    def test_duplicate_events_are_stably_identifiable_without_discarding_provenance(self):
        row = ("a1", "2026-10-01T12:00:00Z", "SYNC_RECORD", "db", "replica", "r", "OK", "")
        timeline = self.build_with_observations([], [row, row])
        self.assertEqual(len(timeline.events), 2)
        self.assertEqual(timeline.events[0].duplicate_key, timeline.events[1].duplicate_key)
        self.assertNotEqual(timeline.events[0].source.record_number, timeline.events[1].source.record_number)

    def test_unresolved_identity_is_preserved_without_subject_assignment(self):
        obs = _observation("unresolved", [("timestamp", "2026-10-01T12:00:00Z")])
        timeline = self.build_with_observations([obs])
        self.assertIsNone(timeline.events[0].subject.user_id)
        self.assertEqual(timeline.events[0].subject.status, "unresolved")
        self.assertEqual(timeline.unresolved_observation_ids, ("unresolved",))

    def test_nonmatch_is_separate_from_unresolved_identity(self):
        obs = _observation("nonmatch", [("timestamp", "2026-10-01T12:00:00Z")])
        timeline = self.build_with_observations([obs], statuses={
            "nonmatch": (ResolutionStatus.NON_MATCH, None, ())})
        self.assertEqual(timeline.unresolved_observation_ids, ())
        self.assertEqual(timeline.nonmatching_observation_ids, ("nonmatch",))

    def test_confirmed_identity_and_source_provenance_are_preserved(self):
        obs = _observation("confirmed", [("created_at", "2026-10-01T12:00:00Z")])
        result = self.build_with_observations([obs], statuses={
            "confirmed": (ResolutionStatus.CONFIRMED, "u-1", ("u-1",))})
        event = result.events[0]
        self.assertEqual(event.subject.user_id, "u-1")
        self.assertEqual(event.source.file_id, "file-1")
        self.assertEqual(event.source.source_file, "evidence/sample.json")
        self.assertEqual(event.source.locator, "json:/confirmed")
        self.assertEqual(event.source.extraction_method, "stdlib-json")
        self.assertEqual(event.source.observation_id, "confirmed")

    def test_deterministic_order_for_equal_and_out_of_order_inputs(self):
        rows = [
            ("b", "2026-10-02T00:00:00Z", "UPDATE_RECORD", "db", "db", "r2", "OK", ""),
            ("a", "2026-10-01T00:00:00Z", "DELETE_RECORD", "db", "db", "r1", "OK", ""),
        ]
        forward = self.build_with_observations([], rows)
        reverse = self.build_with_observations([], list(reversed(rows)))
        self.assertEqual([event.event_id for event in forward.events], [event.event_id for event in reverse.events])

    def test_unplaced_observation_and_unresolved_activity_identity_remain_explicit(self):
        obs = _observation("no-time", [])
        row = ("activity", "2026-10-01T12:00:00Z", "DELETE_RECORD", "db", "db", "r", "OK", "opaque")
        timeline = self.build_with_observations([obs], [row])
        self.assertEqual(timeline.unplaced_observation_ids, ("no-time",))
        self.assertEqual(timeline.unplaced_observations[0].observation.raw_fields["resource_id"], "r-1")
        self.assertEqual(timeline.unplaced_observations[0].reason_code, "no_explicit_event_timestamp")
        activity = next(event for event in timeline.events if event.source.source_kind == "system_activity")
        self.assertIsNone(activity.subject.user_id)
        self.assertEqual(activity.raw_fields["details"], "opaque")

    def test_extraction_gaps_remain_explicit_in_timeline(self):
        failed = FileExtractionResult(
            "image-gap", "evidence/images/scan.png", "png", "none", ExtractionStatus.FAILED,
            parse_timestamp("2026-10-01T12:00:00Z"), (), (), (),
            (ExtractionDiagnostic("ocr_backend_unavailable", "image could not be OCR parsed"),),
        )
        timeline = build_timeline(_activity_rows(()), EvidenceExtractionResult((failed,)),
                                  _identity_result(()))
        self.assertEqual(timeline.extraction_gap_file_ids, ("image-gap",))
        self.assertEqual(timeline.extraction_gaps[0].status, "failed")
        self.assertEqual(timeline.extraction_gaps[0].diagnostic_codes, ("ocr_backend_unavailable",))

    def test_naive_audit_cutoff_is_rejected(self):
        timeline = self.build_with_observations([])
        with self.assertRaises(ValueError):
            timeline.eligible_at(datetime(2026, 10, 1))


if __name__ == "__main__":
    unittest.main()
