"""Offline synthetic tests for fail-closed Phase 6 state reconstruction."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType

from audit_agent.extract import (
    EvidenceExtractionResult, ExtractedObservation, ExtractionStatus, FileExtractionResult,
    IdentifierValue, ObservationTimestamp,
)
from audit_agent.identity import (
    IdentityGraph, IdentityResolution, IdentityResolutionResult, IdentitySource,
    MatchConfidence, ResolutionStatus,
)
from audit_agent.ingest import parse_timestamp
from audit_agent.models import CsvRecord, CsvTable, DatasetBundle, IngestionResult, SourceLocation
from audit_agent.state import (
    ResourceState, StateDomain, _case_linked_extraction_gap_ids, _unplaced_direct_evidence, reconstruct_request_states,
    reconstruct_resource_states,
)
from audit_agent.timeline import SubjectLink, UnplacedObservation, build_timeline


UTC = timezone.utc


def _build(observations=(), *, statuses=None, activity_rows=(), failed_files=()):
    files = tuple(FileExtractionResult(
        observation.file_id, observation.source_path, observation.file_format,
        observation.extraction_method, ExtractionStatus.COMPLETE, observation.captured_at,
        (observation,), (), (), (),
    ) for observation in observations) + tuple(failed_files)
    headers = ("activity_id", "event_time", "event_type", "source_system", "target_system",
               "resource_id", "reported_result", "details")
    activity_records = []
    for index, row in enumerate(activity_rows, 1):
        raw = dict(zip(headers, row))
        activity_records.append(CsvRecord(
            SourceLocation("system_activity.csv", index, index), MappingProxyType(raw),
            MappingProxyType({"event_time": parse_timestamp(raw["event_time"])}), tuple(row),
        ))
    tables = {}
    if activity_rows:
        tables["system_activity"] = CsvTable("system_activity", Path("system_activity.csv"),
                                              headers, tuple(activity_records), True)
    ingestion = IngestionResult(DatasetBundle(tables), ())
    extraction = EvidenceExtractionResult(files)
    graph = IdentityGraph((), MappingProxyType({}), (), (), MappingProxyType({}), frozenset(), frozenset())
    resolutions = []
    statuses = statuses or {}
    for observation in observations:
        status, user_id, candidates = statuses.get(
            observation.observation_id, (ResolutionStatus.CONFIRMED, "u-1", ("u-1",)))
        resolutions.append(IdentityResolution(
            observation.observation_id, "observation", status, user_id, candidates,
            MatchConfidence.HIGH if user_id else MatchConfidence.UNRESOLVED,
            observation.identifiers, (), (), ("synthetic",),
            IdentitySource(observation.source_path, file_id=observation.file_id,
                           observation_id=observation.observation_id, locator=observation.locator),
        ))
    identities = IdentityResolutionResult(graph, (), tuple(resolutions), ())
    return build_timeline(ingestion, extraction, identities)


def _obs(name, timestamp, capture, *, state_fields=None, system="account_service", resource="r-1",
         record_type="USER_PROFILE", fmt="json", timestamps_field="updated_at"):
    fields = {"user_id": "u-1", "system_id": system, "resource_id": resource,
              "record_type": record_type}
    fields.update(state_fields or {})
    raw_times = () if timestamps_field is None else ((timestamps_field, timestamp),)
    if timestamps_field is not None:
        fields[timestamps_field] = timestamp
    times = tuple(ObservationTimestamp(key, raw, parse_timestamp(raw)) for key, raw in raw_times)
    return ExtractedObservation(
        name, "f-" + name, f"evidence/{name}.{fmt}", fmt, f"{fmt}:/{name}",
        "synthetic-parser", MappingProxyType(dict(fields)), MappingProxyType(dict(fields)),
        (IdentifierValue("user_id", "u-1", "u-1"),), system, resource,
        times, parse_timestamp(capture) if capture is not None else None,
    )


def _at(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class ResourceStateTests(unittest.TestCase):
    def test_explicit_deleted_customer_reference_is_a_tombstone(self):
        obs = _obs("safe-tombstone", "2026-01-01T10:00:00Z", "2026-01-01T10:00:00Z",
            state_fields={"collection_name": "deleted_customer_references",
                          "account_status": "DELETED", "subject_reference": "u-1",
                          "name": None, "email": None, "phone": None, "email_hash": None},
            system="identity_service", resource="tombstone-1")
        state = reconstruct_resource_states(_build((obs,)), _at("2026-01-01T10:00:00Z")).find(
            "u-1", ["identity_service"], "tombstone-1", "USER_PROFILE")
        self.assertEqual(state.state, ResourceState.TOMBSTONED)
        self.assertEqual(state.evidence[-1].field_name, "account_status")
        self.assertEqual(state.evidence[-1].raw_state_value, "DELETED")

    def test_pending_deleted_customer_reference_is_not_promoted_to_tombstone(self):
        obs = _obs("pending-tombstone", "2026-01-01T10:00:00Z", "2026-01-01T10:00:00Z",
            state_fields={"collection_name": "deleted_customer_references",
                          "account_status": "DELETION_PENDING"},
            system="identity_service", resource="tombstone-2")
        state = reconstruct_resource_states(_build((obs,)), _at("2026-01-01T10:00:00Z")).find(
            "u-1", ["identity_service"], "tombstone-2", "USER_PROFILE")
        self.assertEqual(state.state, ResourceState.UNKNOWN)
        self.assertIn("explicit_unknown_state_observation", state.uncertainty)

    def test_nested_sql_record_uses_explicit_parent_origin_system_and_category(self):
        fields = {"origin_system": "profile_service", "collection_name": "customer_profiles",
                  "resource_id": "profile-7", "user_id": "u-1", "record_state": "PRESENT"}
        nested = ExtractedObservation("child-1", "file-1", "evidence/snapshot.sql", "sql",
            "table:customer_data_primary/row:1/record_json:/", "sqlite-json-field",
            MappingProxyType(fields), MappingProxyType(fields),
            (IdentifierValue("user_id", "u-1", "u-1"),), "profile_service", "profile-7", (),
            parse_timestamp("2026-10-01T10:00:00Z"), "parent-1")
        unplaced = UnplacedObservation(nested, SubjectLink("confirmed", "u-1"),
                                       "no_explicit_event_timestamp")
        result = _unplaced_direct_evidence(unplaced)
        self.assertIsNotNone(result)
        key, _domain, evidence = result
        self.assertEqual(key.system_ids, ("profile_service",))
        self.assertEqual(key.resource_id, "profile-7")
        self.assertEqual(key.resource_type, "customer_profiles")
        self.assertEqual(evidence.source.observation_id, "child-1")

    def test_creation_modification_deletion_sequence_and_stale_last_observation(self):
        observations = [
            _obs("created", "2026-01-01T09:00:00Z", "2026-01-01T10:00:00Z",
                 timestamps_field="created_at"),
            _obs("modified", "2026-01-02T09:00:00Z", "2026-01-02T10:00:00Z"),
            _obs("deleted", "2026-01-03T09:00:00Z", "2026-01-03T10:00:00Z",
                 timestamps_field="deleted_at"),
        ]
        timeline = _build(observations)
        before = reconstruct_resource_states(timeline, _at("2026-01-02T09:59:59Z")).find(
            "u-1", ["account_service"], "r-1", "USER_PROFILE")
        self.assertEqual(before.state, ResourceState.UNKNOWN)
        self.assertEqual(before.last_observed_state, ResourceState.PRESENT)
        at_modified = reconstruct_resource_states(timeline, _at("2026-01-02T10:00:00Z")).find(
            "u-1", ["account_service"], "r-1", "USER_PROFILE")
        self.assertEqual(at_modified.state, ResourceState.PRESENT)
        after = reconstruct_resource_states(timeline, _at("2026-01-03T10:00:00Z")).find(
            "u-1", ["account_service"], "r-1", "USER_PROFILE")
        self.assertEqual(after.state, ResourceState.DELETED)
        self.assertEqual(after.last_observed_state, ResourceState.DELETED)

    def test_redaction_anonymization_and_retention_are_distinct_states(self):
        states = [
            ("redacted", "redacted_at", ResourceState.REDACTED, {}),
            ("anonymous", "anonymized_at", ResourceState.ANONYMIZED, {}),
            ("retained", "updated_at", ResourceState.RETAINED, {"status": "RETAINED"}),
        ]
        for name, field, expected, extra in states:
            with self.subTest(state=expected.value):
                obs = _obs(name, "2026-01-01T10:00:00Z", "2026-01-01T10:00:00Z",
                           timestamps_field=field, state_fields=extra)
                state = reconstruct_resource_states(_build([obs]), _at("2026-01-01T10:00:00Z")).find(
                    "u-1", ["account_service"], "r-1", "USER_PROFILE")
                self.assertEqual(state.state, expected)

    def test_tombstone_preserves_its_distinct_lifecycle_state(self):
        obs = _obs("tombstone", "2026-01-01T10:00:00Z", "2026-01-01T10:00:00Z",
                   record_type="ACCOUNT_TOMBSTONE", timestamps_field="updated_at")
        state = reconstruct_resource_states(_build([obs]), _at("2026-01-01T10:00:00Z")).find(
            "u-1", ["account_service"], "r-1", "ACCOUNT_TOMBSTONE")
        self.assertEqual(state.state, ResourceState.TOMBSTONED)

    def test_same_resource_id_in_different_systems_is_not_merged(self):
        primary = _obs("primary", "2026-01-01T10:00:00Z", "2026-01-01T10:00:00Z", system="primary_db")
        replica = _obs("replica", "2026-01-01T10:00:00Z", "2026-01-01T10:00:00Z", system="read_replica")
        snapshot = reconstruct_resource_states(_build([primary, replica]), _at("2026-01-01T10:00:00Z"))
        self.assertEqual(len(snapshot.for_user("u-1")), 2)
        self.assertEqual(snapshot.find("u-1", ["primary_db"], "r-1", "USER_PROFILE").state,
                         ResourceState.PRESENT)
        self.assertEqual(snapshot.find("u-1", ["read_replica"], "r-1", "USER_PROFILE").state,
                         ResourceState.PRESENT)

    def test_missing_system_scope_does_not_merge_resource_ids_across_sources(self):
        one = _obs("systemless-a", "2026-01-01T10:00:00Z", "2026-01-01T10:00:00Z", system="")
        two = _obs("systemless-b", "2026-01-01T10:00:00Z", "2026-01-01T10:00:00Z", system="")
        snapshot = reconstruct_resource_states(_build([one, two]), _at("2026-01-01T10:00:00Z"))
        self.assertEqual(len(snapshot.for_user("u-1")), 2)
        query = snapshot.find("u-1", [], "r-1", "USER_PROFILE")
        self.assertEqual(query.state, ResourceState.UNKNOWN)
        self.assertIn("resource_scope_is_ambiguous_without_system", query.uncertainty)

    def test_flow_control_state_is_separate_from_resource_lifecycle(self):
        active = _obs("flow-on", "2026-01-01T10:00:00Z", "2026-01-01T10:00:00Z",
                      record_type="DATA_FLOW", state_fields={"enabled": True}, resource="flow-1")
        disabled = _obs("flow-off", "2026-01-02T10:00:00Z", "2026-01-02T10:00:00Z",
                        record_type="DATA_FLOW", state_fields={"enabled": False}, resource="flow-1")
        snapshot = reconstruct_resource_states(_build([active, disabled]), _at("2026-01-02T10:00:00Z"))
        control = snapshot.find("u-1", ["account_service"], "flow-1", "DATA_FLOW", StateDomain.CONTROL)
        lifecycle = snapshot.find("u-1", ["account_service"], "flow-1", "DATA_FLOW", StateDomain.LIFECYCLE)
        self.assertEqual(control.state, ResourceState.DISABLED)
        self.assertEqual(lifecycle.state, ResourceState.UNKNOWN)

    def test_restore_access_is_tracked_as_control_not_backup_lifecycle(self):
        backup = _obs("backup", "2026-01-01T10:00:00Z", "2026-01-01T10:00:00Z",
                      record_type="BACKUP_ARCHIVE", state_fields={"restore_allowed": True}, resource="backup-1")
        blocked = _obs("backup-blocked", "2026-01-02T10:00:00Z", "2026-01-02T10:00:00Z",
                       record_type="BACKUP_ARCHIVE", state_fields={"restore_allowed": False}, resource="backup-1")
        snapshot = reconstruct_resource_states(_build([backup, blocked]), _at("2026-01-02T10:00:00Z"))
        control = snapshot.find("u-1", ["account_service"], "backup-1", "BACKUP_ARCHIVE", StateDomain.CONTROL)
        self.assertEqual(control.state, ResourceState.BLOCKED)

    def test_equal_time_direct_state_conflict_is_not_flattened(self):
        present = _obs("present", "2026-01-01T10:00:00Z", "2026-01-01T10:00:00Z",
                       state_fields={"state": "PRESENT"})
        deleted = _obs("deleted", "2026-01-01T10:00:00Z", "2026-01-01T10:00:00Z",
                       state_fields={"state": "DELETED"})
        assessment = reconstruct_resource_states(_build([present, deleted]), _at("2026-01-01T10:00:00Z")).find(
            "u-1", ["account_service"], "r-1", "USER_PROFILE")
        self.assertEqual(assessment.state, ResourceState.CONFLICTING)
        self.assertEqual(assessment.conflicts[0][1], ("deleted", "present"))

    def test_event_and_capture_cutoffs_are_both_enforced(self):
        obs = _obs("late", "2026-01-01T10:00:00Z", "2026-01-01T12:00:00Z")
        timeline = _build([obs])
        before_capture = reconstruct_resource_states(timeline, _at("2026-01-01T11:59:59Z"))
        self.assertEqual(before_capture.assessments, ())
        at_capture = reconstruct_resource_states(timeline, _at("2026-01-01T12:00:00Z"))
        self.assertEqual(at_capture.find("u-1", ["account_service"], "r-1", "USER_PROFILE").state,
                         ResourceState.PRESENT)
        after = reconstruct_resource_states(timeline, _at("2026-01-01T12:00:01Z"))
        self.assertEqual(after.find("u-1", ["account_service"], "r-1", "USER_PROFILE").state,
                         ResourceState.UNKNOWN)

    def test_extraction_gap_is_case_eligible_only_at_or_after_its_capture_time(self):
        gap = FileExtractionResult("gap-1", "evidence/screen.png", "png", "no-ocr",
            ExtractionStatus.FAILED, parse_timestamp("2026-01-01T12:00:00Z"), (), (), (), ())
        timeline = _build(failed_files=(gap,))
        self.assertEqual(timeline.extraction_gap_file_ids, ("gap-1",))
        before = reconstruct_resource_states(timeline, _at("2026-01-01T11:59:59Z"))
        at = reconstruct_resource_states(timeline, _at("2026-01-01T12:00:00Z"))
        after = reconstruct_resource_states(timeline, _at("2026-01-01T12:00:01Z"))
        self.assertEqual(before.global_extraction_gap_file_ids, ())
        self.assertEqual(at.global_extraction_gap_file_ids, ("gap-1",))
        self.assertEqual(after.global_extraction_gap_file_ids, ("gap-1",))
        self.assertEqual(before.extraction_gap_file_ids, ())
        self.assertEqual(at.extraction_gap_file_ids, ())
        self.assertEqual(after.extraction_gap_file_ids, ())

    def test_extraction_gap_with_unknown_capture_time_remains_fail_closed(self):
        gap = FileExtractionResult("gap-unknown", "evidence/screen.png", "png", "no-ocr",
            ExtractionStatus.FAILED, None, (), (), (), ())
        timeline = _build(failed_files=(gap,))
        snapshot = reconstruct_resource_states(timeline, _at("2026-01-01T12:00:00Z"))
        self.assertEqual(snapshot.global_extraction_gap_file_ids, ("gap-unknown",))
        self.assertEqual(snapshot.extraction_gap_file_ids, ())

    def test_unrelated_global_gap_is_not_assigned_to_case(self):
        gap = FileExtractionResult("gap-1", "evidence/screen.png", "png", "no-ocr",
            ExtractionStatus.FAILED, parse_timestamp("2026-01-01T12:00:00Z"), (), (), (), ())
        observation = _obs("unrelated", "2026-01-01T10:00:00Z", "2026-01-01T11:00:00Z",
                           state_fields={"details": "A different evidence item was reviewed."})
        timeline = _build((observation,), failed_files=(gap,))
        snapshot = reconstruct_resource_states(timeline, _at("2026-01-01T12:00:00Z"))
        self.assertEqual(snapshot.global_extraction_gap_file_ids, ("gap-1",))
        self.assertEqual(_case_linked_extraction_gap_ids(
            timeline, "u-1", snapshot.audit_at, snapshot.global_extraction_gap_file_ids), ())

    def test_explicit_cutoff_eligible_file_reference_links_gap_to_confirmed_subject(self):
        gap = FileExtractionResult("gap-1", "evidence/screen.png", "png", "no-ocr",
            ExtractionStatus.FAILED, parse_timestamp("2026-01-01T12:00:00Z"), (), (), (), ())
        observation = _obs("linked", "2026-01-01T10:00:00Z", "2026-01-01T11:00:00Z",
                           state_fields={"details": "Related attachment gap-1."})
        timeline = _build((observation,), failed_files=(gap,))
        snapshot = reconstruct_resource_states(timeline, _at("2026-01-01T12:00:00Z"))
        self.assertEqual(_case_linked_extraction_gap_ids(
            timeline, "u-1", snapshot.audit_at, snapshot.global_extraction_gap_file_ids), ("gap-1",))

    def test_post_cutoff_reference_does_not_link_gap_to_case(self):
        gap = FileExtractionResult("gap-1", "evidence/screen.png", "png", "no-ocr",
            ExtractionStatus.FAILED, parse_timestamp("2026-01-01T12:00:00Z"), (), (), (), ())
        observation = _obs("late-link", "2026-01-01T13:00:00Z", "2026-01-01T13:00:00Z",
                           state_fields={"details": "Related attachment gap-1."})
        timeline = _build((observation,), failed_files=(gap,))
        snapshot = reconstruct_resource_states(timeline, _at("2026-01-01T12:00:00Z"))
        self.assertEqual(_case_linked_extraction_gap_ids(
            timeline, "u-1", snapshot.audit_at, snapshot.global_extraction_gap_file_ids), ())

    def test_reference_from_unresolved_subject_does_not_link_gap_to_case(self):
        gap = FileExtractionResult("gap-1", "evidence/screen.png", "png", "no-ocr",
            ExtractionStatus.FAILED, parse_timestamp("2026-01-01T12:00:00Z"), (), (), (), ())
        observation = _obs("ambiguous-link", "2026-01-01T10:00:00Z", "2026-01-01T11:00:00Z",
                           state_fields={"details": "Related attachment gap-1."})
        timeline = _build((observation,), statuses={
            "ambiguous-link": (ResolutionStatus.AMBIGUOUS, None, ("u-1",))}, failed_files=(gap,))
        snapshot = reconstruct_resource_states(timeline, _at("2026-01-01T12:00:00Z"))
        self.assertEqual(_case_linked_extraction_gap_ids(
            timeline, "u-1", snapshot.audit_at, snapshot.global_extraction_gap_file_ids), ())

    def test_missing_inner_time_uses_explicit_capture_as_snapshot_time_without_inventing_event(self):
        obs = _obs("snapshot", "", "2026-01-01T10:00:00Z", fmt="sql", timestamps_field=None)
        timeline = _build([obs])
        self.assertEqual(len(timeline.events), 0)
        snapshot = reconstruct_resource_states(timeline, _at("2026-01-01T10:00:00Z"))
        assessment = snapshot.find("u-1", ["account_service"], "r-1", "USER_PROFILE")
        self.assertEqual(assessment.state, ResourceState.PRESENT)
        self.assertEqual(assessment.evidence[0].time_basis,
                         "manifest_capture_snapshot_without_inner_timestamp")
        self.assertEqual(snapshot.unplaced_observation_ids, ("snapshot",))

    def test_missing_resource_evidence_queries_as_unknown_not_absent(self):
        snapshot = reconstruct_resource_states(_build([]), _at("2026-01-01T10:00:00Z"))
        result = snapshot.find("u-1", ["account_service"], "unknown-resource", "USER_PROFILE")
        self.assertEqual(result.state, ResourceState.UNKNOWN)
        self.assertIn("no_eligible_evidence_for_resource", result.uncertainty)

    def test_unresolved_observation_and_activity_claim_are_not_assigned(self):
        unresolved = _obs("unresolved", "2026-01-01T10:00:00Z", "2026-01-01T10:00:00Z")
        activity = ("activity-1", "2026-01-01T10:00:00Z", "DELETE_RECORD", "account_service",
                    "account_service", "r-1", "SUCCESS", "")
        timeline = _build([unresolved], statuses={
            "unresolved": (ResolutionStatus.UNRESOLVED, None, ())}, activity_rows=[activity])
        snapshot = reconstruct_resource_states(timeline, _at("2026-01-01T10:00:00Z"))
        self.assertEqual(snapshot.assessments, ())
        self.assertEqual(len(snapshot.unlinked_event_ids), 2)

    def test_unlinked_activity_conflict_is_preserved_but_not_attributed(self):
        rows = [
            ("activity-a", "2026-01-01T10:00:00Z", "DELETE_RECORD", "account_service",
             "account_service", "r-1", "SUCCESS", ""),
            ("activity-b", "2026-01-01T10:00:00Z", "DELETE_RECORD", "account_service",
             "account_service", "r-1", "FAILED", ""),
        ]
        snapshot = reconstruct_resource_states(_build(activity_rows=rows), _at("2026-01-01T10:00:00Z"))
        self.assertEqual(len(snapshot.timeline_conflicts), 1)
        self.assertEqual(len(snapshot.unlinked_conflicts), 1)
        self.assertEqual(snapshot.assessments, ())

    def test_structured_json_event_claim_does_not_become_record_presence(self):
        obs = _obs("json-event", "2026-01-01T10:00:00Z", "2026-01-01T10:00:00Z",
                   state_fields={"event": "delete_attempt"})
        assessment = reconstruct_resource_states(_build([obs]), _at("2026-01-01T10:00:00Z")).find(
            "u-1", ["account_service"], "r-1", "USER_PROFILE")
        self.assertEqual(assessment.state, ResourceState.UNKNOWN)
        self.assertEqual(len(assessment.claims), 1)

    def test_json_lookup_results_are_claims_not_direct_resource_states(self):
        for result in ("FOUND", "NOT_FOUND", "BLOCKED", "ANONYMIZED"):
            with self.subTest(result=result):
                obs = _obs(f"lookup-{result.lower()}", "2026-01-01T10:00:00Z",
                           "2026-01-01T10:00:00Z", state_fields={"result": result})
                assessment = reconstruct_resource_states(
                    _build([obs]), _at("2026-01-01T10:00:00Z")
                ).find("u-1", ["account_service"], "r-1", "USER_PROFILE")
                self.assertEqual(assessment.state, ResourceState.UNKNOWN)
                self.assertIsNone(assessment.last_observed_state)
                self.assertEqual(assessment.evidence, ())
                self.assertEqual(len(assessment.claims), 1)
                self.assertIn("claims_do_not_establish_resource_state", assessment.uncertainty)

    def test_later_lookup_claim_does_not_extend_old_snapshot_to_new_cutoff(self):
        snapshot = _obs("snapshot", "2026-01-01T10:00:00Z", "2026-01-01T10:00:00Z")
        lookup = _obs("lookup", "2026-01-02T10:00:00Z", "2026-01-02T10:00:00Z",
                      state_fields={"result": "NOT_FOUND"})
        assessment = reconstruct_resource_states(
            _build([snapshot, lookup]), _at("2026-01-02T10:00:00Z")
        ).find("u-1", ["account_service"], "r-1", "USER_PROFILE")
        self.assertEqual(assessment.state, ResourceState.UNKNOWN)
        self.assertEqual(assessment.last_observed_state, ResourceState.PRESENT)
        self.assertIn("last_snapshot_precedes_audit_cutoff", assessment.uncertainty)
        self.assertEqual(len(assessment.claims), 1)

    def test_explicit_unknown_state_is_reported_as_uncertainty(self):
        obs = _obs("explicit-unknown", "2026-01-01T10:00:00Z", "2026-01-01T10:00:00Z",
                   state_fields={"state": "UNKNOWN"})
        assessment = reconstruct_resource_states(
            _build([obs]), _at("2026-01-01T10:00:00Z")
        ).find("u-1", ["account_service"], "r-1", "USER_PROFILE")
        self.assertEqual(assessment.state, ResourceState.UNKNOWN)
        self.assertEqual(assessment.last_observed_state, ResourceState.UNKNOWN)
        self.assertIn("explicit_unknown_state_observation", assessment.uncertainty)

    def test_conflicting_identity_is_not_used_for_subject_state(self):
        ambiguous = _obs("ambiguous", "2026-01-01T10:00:00Z", "2026-01-01T10:00:00Z")
        timeline = _build([ambiguous], statuses={
            "ambiguous": (ResolutionStatus.AMBIGUOUS, None, ("u-1", "u-2"))})
        snapshot = reconstruct_resource_states(timeline, _at("2026-01-01T10:00:00Z"))
        self.assertEqual(snapshot.assessments, ())
        self.assertEqual(len(snapshot.unlinked_event_ids), 1)

    def test_deterministic_state_order_and_evidence_provenance(self):
        a = _obs("a", "2026-01-01T10:00:00Z", "2026-01-01T10:00:00Z", system="db-a")
        b = _obs("b", "2026-01-01T10:00:00Z", "2026-01-01T10:00:00Z", system="db-b")
        first = reconstruct_resource_states(_build([a, b]), _at("2026-01-01T10:00:00Z"))
        second = reconstruct_resource_states(_build([b, a]), _at("2026-01-01T10:00:00Z"))
        signature = lambda snap: [(item.key, item.state, [ev.evidence_key for ev in item.evidence])
                                  for item in snap.assessments]
        self.assertEqual(signature(first), signature(second))
        evidence = first.assessments[0].evidence[0]
        self.assertEqual(evidence.source.file_id, "f-a")
        self.assertEqual(evidence.source.observation_id, "a")
        self.assertEqual(evidence.source.locator, "json:/a")
        self.assertEqual(evidence.event_time.raw, "2026-01-01T10:00:00Z")
        self.assertEqual(evidence.capture_time.raw, "2026-01-01T10:00:00Z")

    def test_naive_cutoff_is_rejected(self):
        with self.assertRaises(ValueError):
            reconstruct_resource_states(_build([]), datetime(2026, 1, 1))

    def test_request_snapshots_use_each_case_identity_and_audit_cutoff(self):
        obs = _obs("request-resource", "2026-01-01T10:00:00Z", "2026-01-01T10:00:00Z")
        timeline = _build([obs])
        request_headers = ("case_id", "email", "requested_at", "reported_status", "reported_at",
                           "audit_at", "request_text")
        records = []
        request_resolutions = []
        graph = IdentityGraph((), MappingProxyType({}), (), (), MappingProxyType({}), frozenset(), frozenset())
        for index, (case_id, cutoff) in enumerate((
            ("case-after", "2026-01-01T10:00:00Z"),
            ("case-before", "2026-01-01T09:59:59Z"),
        ), 1):
            raw = dict.fromkeys(request_headers, "")
            raw.update({"case_id": case_id, "audit_at": cutoff})
            records.append(CsvRecord(
                SourceLocation("deletion_requests.csv", index, index), MappingProxyType(raw),
                MappingProxyType({"audit_at": parse_timestamp(cutoff)}), tuple(raw[key] for key in request_headers),
            ))
            request_resolutions.append(IdentityResolution(
                case_id, "request", ResolutionStatus.CONFIRMED, "u-1", ("u-1",),
                MatchConfidence.HIGH, (), (), (), (),
                IdentitySource("deletion_requests.csv", record_number=index, record_id=case_id),
            ))
        request_table = CsvTable("deletion_requests", Path("deletion_requests.csv"),
                                 request_headers, tuple(records), True)
        ingestion = IngestionResult(DatasetBundle({"deletion_requests": request_table}), ())
        identities = IdentityResolutionResult(graph, tuple(request_resolutions), (), ())
        cases = reconstruct_request_states(ingestion, identities, timeline)
        self.assertEqual([case.case_id for case in cases], ["case-after", "case-before"])
        self.assertEqual(cases[0].snapshot.find("u-1", ["account_service"], "r-1", "USER_PROFILE").state,
                         ResourceState.PRESENT)
        self.assertEqual(cases[1].snapshot.find("u-1", ["account_service"], "r-1", "USER_PROFILE").state,
                         ResourceState.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
