"""Offline synthetic tests for Phase 8 recreation and residual risks."""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timezone
from types import MappingProxyType

from audit_agent.extract import (
    EvidenceExtractionResult, ExtractedObservation, FileExtractionResult, ExtractionStatus,
    IdentifierValue, ObservationTimestamp,
)
from audit_agent.identity import (
    IdentityGraph, IdentityInterval, IdentityResolution, IdentityResolutionResult,
    IdentitySource, MatchConfidence, ResolutionStatus,
)
from audit_agent.ingest import parse_timestamp
from audit_agent.policy import (
    ConditionStatus, DecisionStatus, PolicyAction, PolicyCaseResult, PolicyDecision,
    PolicyEvaluation, PolicyEvidenceReference, PolicyRule,
)
from audit_agent.risks import (
    RiskAnalysis, RiskCaseResult, RiskConfidence, RiskEvidenceStatus, RiskFindingType,
    analyze_recreation_risks,
)
from audit_agent.state import (
    CaseStateSnapshot, ResourceAssessment, ResourceKey, ResourceState, StateDomain,
    StateEvidence, StateSnapshot,
)
from audit_agent.timeline import (
    EventCategory, SubjectLink, Timeline, TimelineConflict, TimelineEvent, TimelineSource,
)


UTC = timezone.utc
CUTOFF = datetime(2026, 4, 1, tzinfo=UTC)


def _at(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _observation(name: str, fields: dict[str, object], *, system: str = "profile",
                 resource: str = "r-1", capture: str = "2026-04-01T00:00:00Z",
                 timestamp_name: str = "updated_at", timestamp: str = "2026-03-31T20:00:00Z",
                 fmt: str = "json") -> ExtractedObservation:
    raw = dict(fields)
    raw.setdefault("system_id", system)
    raw.setdefault("resource_id", resource)
    if timestamp_name:
        raw[timestamp_name] = timestamp
    times = tuple(ObservationTimestamp(key, str(value), parse_timestamp(str(value)))
                  for key, value in raw.items() if key.endswith(("_at", "_time")) and value is not None)
    return ExtractedObservation(name, f"file-{name}", f"evidence/{name}.{fmt}", fmt,
        f"record:{name}", "synthetic", MappingProxyType(raw), MappingProxyType(dict(raw)),
        (IdentifierValue("user_id", "u-1", "u-1"),), system, resource, times,
        parse_timestamp(capture))


def _event(obs: ExtractedObservation, category: EventCategory, event_time: str, *,
           event_id: str | None = None, user: str | None = "u-1", role: str = "observation",
           systems: tuple[str, ...] | None = None, source_kind: str = "evidence",
           record_id: str | None = None, capture: str | None = None) -> TimelineEvent:
    source = TimelineSource(source_kind, obs.source_path if source_kind == "evidence" else "system_activity.csv",
        file_id=obs.file_id if source_kind == "evidence" else None,
        record_id=record_id, observation_id=obs.observation_id if source_kind == "evidence" else None,
        locator=obs.locator if source_kind == "evidence" else None,
        file_format=obs.file_format if source_kind == "evidence" else None)
    parsed = parse_timestamp(event_time)
    return TimelineEvent(event_id or f"event-{obs.observation_id}-{category.value}", category,
        category.value, parsed, "event_time", (),
        parse_timestamp(capture) if capture else obs.captured_at,
        source_kind == "evidence", SubjectLink("confirmed", user) if user else
        SubjectLink("unresolved", candidate_user_ids=("u-1",)),
        systems if systems is not None else ((obs.system_id,) if source_kind == "evidence" else ("profile",)),
        obs.resource_id, source, role, MappingProxyType(dict(obs.raw_fields)), (),
        f"dup-{obs.observation_id}-{category.value}")


def _harness(observations, events, states, *, cutoff=CUTOFF, final_state=None,
             status_by_obs=None, system=None, conflicts=(), domain=StateDomain.LIFECYCLE,
             gaps=(), include_assessment=True):
    status_by_obs = status_by_obs or {}
    evidence = []
    for obs, state, event in zip(observations, states, events):
        source = event.source
        evidence.append(StateEvidence(event.event_id, state, domain, source, event.event_time,
            event.capture_time, event.capture_time.value if event.capture_time and event.capture_time.status.value == "valid" else None,
            "manifest_capture_snapshot", None, None, event.category, event.role))
    systems = tuple(sorted(set(system or (observations[0].system_id,)))) if observations else ("profile",)
    resource = observations[0].resource_id if observations else "r-1"
    record_type = next((str(obs.raw_fields.get("record_type")) for obs in observations
                        if obs.raw_fields.get("record_type")), "USER_PROFILE")
    key = ResourceKey("u-1", systems, resource, record_type)
    selected_domain = domain
    assessment = ResourceAssessment(key, selected_domain, cutoff,
        final_state or (states[-1] if states else ResourceState.UNKNOWN),
        states[-1] if states else None,
        max((item.state_observed_at for item in evidence if item.state_observed_at), default=None),
        tuple(evidence), (), (), (), ())
    assessments = (assessment,) if include_assessment else ()
    snapshot = StateSnapshot(cutoff, assessments, (), (), (), tuple(gaps), tuple(conflicts), (), ())
    case = CaseStateSnapshot("case-1", "confirmed", "u-1", snapshot)
    file_results = tuple(FileExtractionResult(obs.file_id, obs.source_path, obs.file_format,
        "synthetic", ExtractionStatus.COMPLETE, obs.captured_at, (obs,), (), (), ()) for obs in observations)
    extraction = EvidenceExtractionResult(file_results)
    resolutions = []
    for obs in observations:
        status, matched, candidates = status_by_obs.get(obs.observation_id,
            (ResolutionStatus.CONFIRMED, "u-1", ("u-1",)))
        resolutions.append(IdentityResolution(obs.observation_id, "observation", status, matched,
            candidates, MatchConfidence.HIGH if matched else MatchConfidence.UNRESOLVED,
            obs.identifiers, (), (), (), IdentitySource(obs.source_path, file_id=obs.file_id,
            observation_id=obs.observation_id, locator=obs.locator)))
    interval = IdentityInterval("u-1", "email", "u1@example.test", ("u1@example.test",), None, None, ())
    graph = IdentityGraph(("u-1",), MappingProxyType({"u-1": ()}), (interval,), (),
        MappingProxyType({("email", "u1@example.test"): (interval,)}), frozenset(), frozenset())
    identities = IdentityResolutionResult(graph, (), tuple(resolutions), tuple(gaps))
    timeline = Timeline(tuple(events), tuple(conflicts), (), (), (), (), (), (), tuple(gaps))
    return case, identities, timeline, extraction


def _run(observations, events, states, **kwargs):
    case, identities, timeline, extraction = _harness(observations, events, states, **kwargs)
    return analyze_recreation_risks(identities, timeline, extraction, (case,))


class RecreationRiskTests(unittest.TestCase):
    def test_unlinked_global_gap_is_reported_without_marking_every_case_unresolved(self):
        case = RiskCaseResult("case-1", "u-1", CUTOFF, (), (), (), (), (), ())
        report = RiskAnalysis((case,), ("unlinked-gap",))
        self.assertEqual(report.global_extraction_gap_file_ids, ("unlinked-gap",))
        self.assertEqual(report.unresolved_case_ids, ())

    def test_subject_email_in_support_text_uses_record_time_alias(self):
        obs = _observation("support-text", {"record_type": "SUPPORT_MESSAGE",
            "message_text": "Please send delivery update to old@example.test. The affected order includes a lamp."},
            capture="2026-02-15T00:00:00Z", timestamp_name="updated_at",
            timestamp="2026-02-15T00:00:00Z")
        event = _event(obs, EventCategory.MODIFICATION, "2026-02-15T00:00:00Z")
        case, identities, timeline, extraction = _harness([obs], [event], [ResourceState.PRESENT])
        old = IdentityInterval("u-1", "email", "old@example.test", ("old@example.test",),
                               _at("2026-01-01T00:00:00Z"), _at("2026-03-01T00:00:00Z"), ())
        current = IdentityInterval("u-1", "email", "new@example.test", ("new@example.test",),
                                   _at("2026-03-01T00:00:00Z"), None, ())
        graph = IdentityGraph(("u-1",), MappingProxyType({"u-1": ()}), (old, current), (),
            MappingProxyType({("email", "old@example.test"): (old,),
                              ("email", "new@example.test"): (current,)}), frozenset(), frozenset())
        identities = replace(identities, graph=graph)
        key = case.snapshot.assessments[0].key
        rule = PolicyRule("rule_05", "SUPPORT_MESSAGE",
            "Conversation contains shared customer, agent, or order context that must be retained",
            PolicyAction.REDACT, "deletion_rules.csv", 5)
        decision = PolicyDecision("case-1", key, "SUPPORT_MESSAGE", rule, DecisionStatus.APPLIES,
            ConditionStatus.SATISFIED, PolicyAction.REDACT,
            ((StateDomain.LIFECYCLE, ResourceState.PRESENT),), (), (), ())
        policy_case = PolicyCaseResult("case-1", "confirmed", "u-1", CUTOFF, True,
            (decision,), (), (), (), (), (), ())
        result = analyze_recreation_risks(identities, timeline, extraction, (case,),
            PolicyEvaluation((rule,), (policy_case,), ()))
        finding = next(item for item in result.findings
                       if item.finding_type is RiskFindingType.POLICY_STATE_CONFLICT)
        self.assertEqual(finding.resource_key.resource_id, "r-1")
        self.assertTrue(any(reference.observation_id == obs.observation_id for reference in finding.evidence))

    def test_delete_then_recreate_and_present_after_delete_are_separate_evidence(self):
        deleted = _observation("deleted", {"record_type": "USER_PROFILE", "deleted_at": "2026-03-01T00:00:00Z"},
                               capture="2026-03-02T00:00:00Z", timestamp_name="deleted_at",
                               timestamp="2026-03-01T00:00:00Z")
        sync = _observation("sync", {"record_type": "USER_PROFILE", "synchronized_at": "2026-03-10T00:00:00Z"},
                            capture="2026-03-11T00:00:00Z", timestamp_name="synchronized_at",
                            timestamp="2026-03-10T00:00:00Z")
        deletion_event = _event(deleted, EventCategory.DELETION, "2026-03-01T00:00:00Z")
        sync_event = _event(sync, EventCategory.SYNCHRONIZATION, "2026-03-10T00:00:00Z")
        result = _run([deleted, sync], [deletion_event, sync_event],
                      [ResourceState.DELETED, ResourceState.PRESENT])
        findings = result.findings
        kinds = {item.finding_type for item in findings}
        self.assertIn(RiskFindingType.RESOURCE_PRESENT_AFTER_DELETE, kinds)
        self.assertIn(RiskFindingType.OBSERVED_RECREATION, kinds)
        self.assertTrue(all(item.confidence is RiskConfidence.HIGH for item in findings))
        observed = next(item for item in findings if item.finding_type is RiskFindingType.OBSERVED_RECREATION)
        self.assertEqual(observed.mechanism, EventCategory.SYNCHRONIZATION)
        self.assertEqual({ref.file_id for ref in observed.evidence}, {"file-sync"})

    def test_restore_replication_and_import_events_need_direct_presence_evidence(self):
        for category in (EventCategory.RESTORATION, EventCategory.REPLICATION, EventCategory.IMPORT):
            with self.subTest(category=category):
                obs = _observation("operation", {"record_type": "USER_PROFILE"},
                                   timestamp_name=f"{category.value}_at", timestamp="2026-03-20T00:00:00Z")
                event = _event(obs, category, "2026-03-20T00:00:00Z")
                result = _run([obs], [event], [ResourceState.PRESENT])
                self.assertEqual(len(result.findings), 1)
                self.assertEqual(result.findings[0].finding_type, RiskFindingType.OBSERVED_RECREATION)
                self.assertEqual(result.findings[0].evidence_status, RiskEvidenceStatus.DIRECT_STATE)

    def test_active_flow_and_restore_controls_are_possible_risks_not_observed_events(self):
        flow = _observation("flow", {"record_type": "DATA_FLOW", "enabled": True,
                                      "mode": "continuous_sync", "subject_selector": "u1@example.test"},
                            system="connector", resource="flow-1")
        backup = _observation("backup", {"record_type": "BACKUP_ARCHIVE", "restore_allowed": True},
                              system="backup", resource="backup-1")
        flow_event = _event(flow, EventCategory.CONTROL_STATE, "2026-04-01T00:00:00Z")
        backup_event = _event(backup, EventCategory.CONTROL_STATE, "2026-04-01T00:00:00Z")
        case, identities, timeline, extraction = _harness([flow, backup], [flow_event, backup_event],
            [ResourceState.ACTIVE, ResourceState.ACTIVE], domain=StateDomain.CONTROL,
            system=("connector",))
        # Keep separate flow and backup scope keys/assessments as they are distinct resources.
        backup_key = ResourceKey("u-1", ("backup",), "backup-1", "BACKUP_ARCHIVE")
        first = case.snapshot.assessments[0]
        second_evidence = StateEvidence(backup_event.event_id, ResourceState.ACTIVE, StateDomain.CONTROL,
            backup_event.source, backup_event.event_time, backup_event.capture_time, CUTOFF,
            "manifest_capture_snapshot", None, None, backup_event.category, backup_event.role)
        second = ResourceAssessment(backup_key, StateDomain.CONTROL, CUTOFF, ResourceState.ACTIVE,
            ResourceState.ACTIVE, CUTOFF, (second_evidence,), (), (), (), ())
        snapshot = StateSnapshot(CUTOFF, (first, second), (), (), (), (), (), (), ())
        case = CaseStateSnapshot("case-1", "confirmed", "u-1", snapshot)
        result = analyze_recreation_risks(identities, timeline, extraction, (case,))
        self.assertEqual({f.finding_type for f in result.findings}, {
            RiskFindingType.POSSIBLE_DATA_FLOW_RECREATION, RiskFindingType.POSSIBLE_RESTORE})
        self.assertTrue(all(f.confidence is RiskConfidence.MEDIUM for f in result.findings))
        self.assertTrue(all(f.evidence_status is RiskEvidenceStatus.DIRECT_CONTROL for f in result.findings))

    def test_resource_ids_in_other_systems_do_not_match(self):
        obs = _observation("known", {"record_type": "USER_PROFILE"}, system="profile")
        other = _observation("other", {"record_type": "USER_PROFILE"}, system="search")
        event = _event(other, EventCategory.SYNCHRONIZATION, "2026-03-20T00:00:00Z")
        result = _run([obs], [event], [ResourceState.PRESENT])
        self.assertEqual(result.findings, ())

    def test_event_and_capture_cutoffs_are_inclusive_and_late_evidence_is_excluded(self):
        at = _observation("at", {"record_type": "USER_PROFILE"},
                          capture="2026-04-01T00:00:00Z", timestamp_name="restored_at",
                          timestamp="2026-04-01T00:00:00Z")
        eligible = _event(at, EventCategory.RESTORATION, "2026-04-01T00:00:00Z")
        self.assertEqual(len(_run([at], [eligible], [ResourceState.PRESENT]).findings), 1)

        late = _observation("late", {"record_type": "USER_PROFILE"},
                             capture="2026-04-01T00:00:01Z", timestamp_name="restored_at",
                             timestamp="2026-04-01T00:00:00Z")
        event = _event(late, EventCategory.RESTORATION, "2026-04-01T00:00:00Z")
        result = _run([late], [event], [ResourceState.PRESENT])
        self.assertEqual(result.findings, ())
        self.assertTrue(result.cases[0].temporal_exclusions)

    def test_stale_snapshot_does_not_claim_current_residual_availability(self):
        deleted = _observation("deleted", {"record_type": "USER_PROFILE"},
                               capture="2026-02-01T00:00:00Z", timestamp_name="deleted_at",
                               timestamp="2026-01-31T00:00:00Z")
        present = _observation("present", {"record_type": "USER_PROFILE"},
                               capture="2026-02-03T00:00:00Z", timestamp_name="updated_at",
                               timestamp="2026-02-02T00:00:00Z")
        deletion_event = _event(deleted, EventCategory.DELETION, "2026-01-31T00:00:00Z")
        present_event = _event(present, EventCategory.MODIFICATION, "2026-02-02T00:00:00Z")
        result = _run([deleted, present], [deletion_event, present_event],
                      [ResourceState.DELETED, ResourceState.PRESENT], final_state=ResourceState.UNKNOWN)
        self.assertNotIn(RiskFindingType.RESOURCE_PRESENT_AFTER_DELETE,
                         {item.finding_type for item in result.findings})
        self.assertIn("resource_state_unresolved", {item.code for item in result.cases[0].uncertainties})

    def test_conflicting_state_and_timeline_claims_remain_uncertainties(self):
        one = _observation("one", {"record_type": "USER_PROFILE"})
        ev = _event(one, EventCategory.MODIFICATION, "2026-03-20T00:00:00Z")
        conflict = TimelineConflict("conflict-1", (ev.event_id,), (("profile",), "r-1"),
            _at("2026-03-20T00:00:00Z"), "event:result", ("SUCCESS", "FAILED"))
        result = _run([one], [ev], [ResourceState.CONFLICTING], final_state=ResourceState.CONFLICTING,
                      conflicts=(conflict,))
        self.assertIn("resource_state_conflicting", {item.code for item in result.cases[0].uncertainties})
        self.assertEqual(len(result.cases[0].conflicts), 1)

    def test_unlinked_operation_claim_is_reported_as_claim_only_with_scope(self):
        obs = _observation("known", {"record_type": "USER_PROFILE"}, system="profile")
        activity = _event(obs, EventCategory.SYNCHRONIZATION, "2026-03-20T00:00:00Z",
                          user=None, role="activity claim", source_kind="system_activity",
                          record_id="activity-1", systems=("profile", "replica"))
        result = _run([obs], [], [ResourceState.PRESENT])
        # Include the global claim while retaining the confirmed profile scope.
        case, identities, _, extraction = _harness([obs], [], [ResourceState.PRESENT])
        timeline = Timeline((activity,), (), (), (), (), (), (), (), ())
        result = analyze_recreation_risks(identities, timeline, extraction, (case,))
        finding = result.findings[0]
        self.assertEqual(finding.finding_type, RiskFindingType.CLAIMED_RECREATION_OPERATION)
        self.assertEqual(finding.confidence, RiskConfidence.LOW)
        self.assertEqual(finding.evidence_status, RiskEvidenceStatus.CLAIM_ONLY)
        self.assertIn("reported_operation_does_not_establish_effect", finding.uncertainty)

    def test_insufficient_identity_link_never_assigns_operation_to_subject(self):
        obs = _observation("ambiguous", {"record_type": "USER_PROFILE"})
        event = _event(obs, EventCategory.RESTORATION, "2026-03-20T00:00:00Z", user=None)
        result = _run([obs], [event], [ResourceState.PRESENT], status_by_obs={
            "ambiguous": (ResolutionStatus.AMBIGUOUS, None, ("u-1", "u-2"))
        }, include_assessment=False)
        self.assertEqual(result.findings, ())
        self.assertTrue(result.cases[0].unresolved_identity_evidence)

    def test_policy_conflict_preserves_rule_and_state_provenance(self):
        obs = _observation("present", {"record_type": "USER_PROFILE"})
        event = _event(obs, EventCategory.MODIFICATION, "2026-03-20T00:00:00Z")
        case, identities, timeline, extraction = _harness([obs], [event], [ResourceState.PRESENT])
        key = case.snapshot.assessments[0].key
        rule = PolicyRule("rule-delete", "USER_PROFILE", "always", PolicyAction.DELETE,
                          "deletion_rules.csv", 2)
        decision = PolicyDecision("case-1", key, "USER_PROFILE", rule, DecisionStatus.APPLIES,
            ConditionStatus.SATISFIED, PolicyAction.DELETE,
            ((StateDomain.LIFECYCLE, ResourceState.PRESENT),),
            (PolicyEvidenceReference("deletion_rule", "rule-delete", "deletion_rules.csv",
                                     record_number=2),), (), ())
        policy_case = PolicyCaseResult("case-1", "confirmed", "u-1", CUTOFF, True,
            (decision,), (), (), (), (), (), ())
        policy = PolicyEvaluation((rule,), (policy_case,), ())
        result = analyze_recreation_risks(identities, timeline, extraction, (case,), policy)
        finding = next(item for item in result.findings
                       if item.finding_type is RiskFindingType.POLICY_STATE_CONFLICT)
        rule_ref = next(ref for ref in finding.evidence if ref.role == "policy_rule")
        state_ref = next(ref for ref in finding.evidence if ref.role == "observation")
        self.assertEqual((rule_ref.source_kind, rule_ref.source_id), ("deletion_rule", "rule-delete"))
        self.assertEqual(state_ref.file_id, "file-present")

    def test_tombstone_with_direct_identifier_conflicts_with_redaction_policy(self):
        obs = _observation("tombstone", {"record_type": "ACCOUNT_TOMBSTONE",
                                         "email": "u1@example.test"})
        event = _event(obs, EventCategory.TOMBSTONE, "2026-03-20T00:00:00Z")
        case, identities, timeline, extraction = _harness([obs], [event], [ResourceState.TOMBSTONED],
                                                           final_state=ResourceState.TOMBSTONED)
        key = case.snapshot.assessments[0].key
        rule = PolicyRule("rule-tombstone", "ACCOUNT_TOMBSTONE", "stable_ref", PolicyAction.REDACT,
                          "deletion_rules.csv", 3)
        ref = PolicyEvidenceReference("deletion_rule", rule.rule_id, rule.source_file, record_number=3)
        decision = PolicyDecision("case-1", key, "ACCOUNT_TOMBSTONE", rule, DecisionStatus.APPLIES,
            ConditionStatus.SATISFIED, PolicyAction.REDACT,
            ((StateDomain.LIFECYCLE, ResourceState.TOMBSTONED),), (ref,), (), ())
        policy_case = PolicyCaseResult("case-1", "confirmed", "u-1", CUTOFF, True,
            (decision,), (), (), (), (), (), ())
        result = analyze_recreation_risks(identities, timeline, extraction, (case,),
            PolicyEvaluation((rule,), (policy_case,), ()))
        finding = next(item for item in result.findings
                       if item.finding_type is RiskFindingType.POLICY_STATE_CONFLICT)
        self.assertEqual(finding.state_at_cutoff, ResourceState.TOMBSTONED)


if __name__ == "__main__":
    unittest.main()
