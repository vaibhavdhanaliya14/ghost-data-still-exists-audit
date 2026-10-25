"""Offline synthetic intent and case-adjudication tests (Phase 9)."""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from types import SimpleNamespace

from audit_agent.adjudication import (
    DecisionResolution, DeletionStatus, IntentAction, IntentKind, MentionPolarity,
    _safe_tombstone, adjudicate_cases, classify_request_intent,
)
from audit_agent.extract import EvidenceExtractionResult, ExtractedObservation, FileExtractionResult, ExtractionStatus
from audit_agent.identity import (
    IdentityGraph, IdentityResolution, IdentityResolutionResult, IdentitySource,
    MatchConfidence, ResolutionStatus,
)
from audit_agent.ingest import parse_timestamp
from audit_agent.models import (
    CsvRecord, CsvTable, DatasetBundle, IngestionResult, SourceLocation,
)
from audit_agent.policy import (
    ConditionStatus, DecisionStatus, PolicyAction, PolicyCaseResult, PolicyConflict, PolicyDecision,
    PolicyEvaluation, PolicyEvidenceReference, PolicyRule,
)
from audit_agent.risks import (
    RiskAnalysis, RiskCaseResult, RiskConfidence, RiskEvidenceReference,
    RiskEvidenceStatus, RiskFinding, RiskFindingType,
)
from audit_agent.state import (
    CaseStateSnapshot, ResourceAssessment, ResourceKey, ResourceState, StateDomain,
    StateEvidence, StateSnapshot,
)
from audit_agent.timeline import EventCategory, TimelineSource


UTC = timezone.utc
CUTOFF = datetime(2026, 6, 1, tzinfo=UTC)


def _timestamp(value: datetime):
    raw = value.isoformat().replace("+00:00", "Z")
    return parse_timestamp(raw)


def _harness(text: str = "Please delete my account.", *, state: ResourceState = ResourceState.ABSENT,
             identity_status: ResolutionStatus = ResolutionStatus.CONFIRMED,
             policy_status: DecisionStatus = DecisionStatus.APPLIES,
             policy_condition: ConditionStatus | None = None,
             policy_uncertainty: tuple[str, ...] = (), gaps: tuple[str, ...] = (),
             global_gaps: tuple[str, ...] = (),
             policy_conflicts: tuple[PolicyConflict, ...] = (),
             risk_findings: tuple[RiskFinding, ...] = (), action: PolicyAction = PolicyAction.DELETE,
             assessment_uncertainty: tuple[str, ...] = (), user_id: str | None = "u-1",
             safe_tombstone: bool = True):
    case_id = "case-synthetic"
    raw = {"case_id": case_id, "request_text": text}
    typed = {"audit_at": _timestamp(CUTOFF)}
    record = CsvRecord(SourceLocation("deletion_requests.csv", 2, 2), MappingProxyType(raw),
                       MappingProxyType(typed), (case_id, text))
    table = CsvTable("deletion_requests", Path("deletion_requests.csv"),
                     ("case_id", "request_text", "audit_at"), (record,), True)
    ingestion = IngestionResult(DatasetBundle(MappingProxyType({"deletion_requests": table})), ())
    source = IdentitySource("deletion_requests.csv", record_number=2, field_name="email")
    resolution = IdentityResolution(case_id, "request", identity_status,
        user_id if identity_status is ResolutionStatus.CONFIRMED else None,
        (user_id,) if user_id else (), MatchConfidence.HIGH if user_id else MatchConfidence.UNRESOLVED,
        (), (), (), (), source)
    graph = IdentityGraph(("u-1",) if user_id else (), MappingProxyType({}), (), (),
                          MappingProxyType({}), frozenset(), frozenset())
    identities = IdentityResolutionResult(graph, (resolution,), (), ())

    extraction_observation = ExtractedObservation("obs-1", "file-1", "evidence/profile.json", "json",
        "record:1", "json", MappingProxyType({"user_id": user_id or "u-1", "record_type": "USER_PROFILE"}),
        MappingProxyType({"user_id": user_id or "u-1", "record_type": "USER_PROFILE"}), (),
        "profile", "r-1", (), _timestamp(CUTOFF))
    if not safe_tombstone:
        extraction_observation = ExtractedObservation("obs-1", "file-1", "evidence/profile.json", "json",
            "record:1", "json", MappingProxyType({"email": "u1@example.test", "record_type": "ACCOUNT_TOMBSTONE"}),
            MappingProxyType({"email": "u1@example.test", "record_type": "ACCOUNT_TOMBSTONE"}), (),
            "profile", "r-1", (), _timestamp(CUTOFF))
    extraction = EvidenceExtractionResult((FileExtractionResult("file-1", "evidence/profile.json", "json",
        "json", ExtractionStatus.COMPLETE, _timestamp(CUTOFF), (extraction_observation,), (), (), ()),))

    state_case = None
    policy_case = None
    risk_user_id = user_id
    if user_id is not None:
        key = ResourceKey(user_id, ("profile",), "r-1", "USER_PROFILE")
        snapshot_ref = TimelineSource("evidence", "evidence/profile.json", file_id="file-1",
            observation_id="obs-1", locator="record:1", file_format="json")
        evidence = StateEvidence("state-1", state, StateDomain.LIFECYCLE, snapshot_ref,
            _timestamp(CUTOFF), _timestamp(CUTOFF), CUTOFF, "capture_snapshot", "state",
            state.value, EventCategory.OBSERVATION, "observation")
        assessment = ResourceAssessment(key, StateDomain.LIFECYCLE, CUTOFF, state, state, CUTOFF,
            (evidence,), (), (), assessment_uncertainty, ())
        snapshot = StateSnapshot(CUTOFF, (assessment,), (), (), (), gaps, (), (), ())
        state_case = CaseStateSnapshot(case_id, identity_status.value, user_id, snapshot)
        rule = PolicyRule("rule-1", "USER_PROFILE", "always", action, "deletion_rules.csv", 2)
        rule_ref = PolicyEvidenceReference("deletion_rule", "rule-1", "deletion_rules.csv", record_number=2)
        decision = PolicyDecision(case_id, key, "USER_PROFILE", rule, policy_status,
            policy_condition or (ConditionStatus.SATISFIED if policy_status is DecisionStatus.APPLIES
                                 else ConditionStatus.UNKNOWN),
            action, ((StateDomain.LIFECYCLE, state),), (rule_ref,), (), policy_uncertainty)
        policy_case = PolicyCaseResult(case_id, identity_status.value, user_id, CUTOFF, True,
            (decision,), policy_conflicts, gaps, (), (), (), policy_uncertainty)
    policy_eval = PolicyEvaluation((), (policy_case,) if policy_case else (), ())
    risk_case = RiskCaseResult(case_id, risk_user_id, CUTOFF, risk_findings, (), gaps, (), (), ())
    risks = RiskAnalysis((risk_case,), global_gaps)
    return ingestion, identities, extraction, (state_case,) if state_case else (), policy_eval, risks


def _adjudicate(**kwargs):
    return adjudicate_cases(*_harness(**kwargs)).cases[0]


class IntentClassificationTests(unittest.TestCase):
    def test_explicit_deletion_phrases_include_public_sample_languages(self):
        for text in (
            "Please delete my account and personal data.",
            "Quiero eliminar mi cuenta.",
            "Je demande la suppression définitive du compte.",
            "このアカウントの完全な削除を依頼します。",
            "Solicito a exclusão permanente da conta associada a este e-mail.",
            "이 이메일 주소에 연결된 계정의 영구 삭제를 요청합니다.",
        ):
            with self.subTest(text=text):
                result = classify_request_intent(text)
                self.assertEqual(result.kind, IntentKind.DELETION)
                self.assertIs(result.deletion_authorized, True)
                self.assertTrue(result.mentions)

    def test_access_export_correction_and_optout_are_non_deletion_actions(self):
        cases = (
            ("Please give me access to a copy of my data.", IntentKind.ACCESS_EXPORT),
            ("Please correct my email address.", IntentKind.CORRECTION),
            ("Please change the email address used for this account.", IntentKind.CORRECTION),
            ("Please replace the mobile number on my profile.", IntentKind.CORRECTION),
            ("Please unsubscribe me from marketing messages.", IntentKind.OPT_OUT),
            ("No quiero recibir publicidad.", IntentKind.OPT_OUT),
        )
        for text, kind in cases:
            with self.subTest(text=text):
                result = classify_request_intent(text)
                self.assertEqual(result.kind, kind)
                self.assertIs(result.deletion_authorized, False)

    def test_negation_does_not_authorize_deletion(self):
        result = classify_request_intent("Do not delete my account; only send a copy of my data.")
        self.assertEqual(result.kind, IntentKind.ACCESS_EXPORT)
        self.assertIs(result.deletion_authorized, False)
        self.assertTrue(any(item.polarity is MentionPolarity.NEGATED for item in result.mentions))
        korean = classify_request_intent("계정을 삭제하지 마세요.")
        self.assertEqual(korean.kind, IntentKind.NON_DELETION)
        self.assertIs(korean.deletion_authorized, False)

    def test_separate_delete_and_export_actions_are_preserved(self):
        result = classify_request_intent("Delete my account, and send me an export of my data.")
        self.assertEqual(result.kind, IntentKind.MULTI_ACTION)
        self.assertIs(result.deletion_authorized, True)
        self.assertEqual(set(result.actions), {IntentAction.DELETE, IntentAction.ACCESS_EXPORT})

    def test_conflicting_and_vague_intent_remain_ambiguous(self):
        for text in (
            "Delete my account. Actually, do not delete my account.",
            "Please take me off your system.",
            "Please help me with my privacy rights.",
            "Should I delete my account?",
        ):
            with self.subTest(text=text):
                result = classify_request_intent(text)
                self.assertEqual(result.kind, IntentKind.AMBIGUOUS)
                self.assertIsNone(result.deletion_authorized)

    def test_marketing_removal_is_not_misread_as_account_deletion(self):
        result = classify_request_intent("Remove me from the marketing list, but keep my account.")
        self.assertEqual(result.kind, IntentKind.OPT_OUT)
        self.assertIs(result.deletion_authorized, False)

    def test_deletion_mentioned_in_a_negated_clause_is_not_authorized(self):
        result = classify_request_intent(
            "Can you correct my surname without removing any of my records.")
        self.assertEqual(result.kind, IntentKind.CORRECTION)
        self.assertIs(result.deletion_authorized, False)


class CaseAdjudicationTests(unittest.TestCase):
    def test_safe_tombstone_accepts_stable_subject_reference_and_rejects_direct_identifiers(self):
        source = TimelineSource("evidence", "evidence/tombstone.json", file_id="f-tombstone",
            observation_id="obs-tombstone", locator="record:1", file_format="json")
        evidence = StateEvidence("state-tombstone", ResourceState.TOMBSTONED,
            StateDomain.LIFECYCLE, source, _timestamp(CUTOFF), _timestamp(CUTOFF), CUTOFF,
            "capture_snapshot", "account_status", "DELETED", EventCategory.OBSERVATION,
            "observation")
        assessment = ResourceAssessment(
            ResourceKey("u-1", ("identity_service",), "tombstone-1", "ACCOUNT_TOMBSTONE"),
            StateDomain.LIFECYCLE, CUTOFF, ResourceState.TOMBSTONED, ResourceState.TOMBSTONED,
            CUTOFF, (evidence,), (), (), (), ())
        clean = SimpleNamespace(normalized_fields=MappingProxyType({
            "subject_reference": "u-1", "name": None, "email": None, "phone": None, "email_hash": None,
        }))
        dirty = SimpleNamespace(normalized_fields=MappingProxyType({
            "subject_reference": "u-1", "name": None, "email": "u1@example.test",
            "phone": None, "email_hash": None,
        }))
        self.assertTrue(_safe_tombstone(assessment, {"obs-tombstone": clean}))
        self.assertFalse(_safe_tombstone(assessment, {"obs-tombstone": dirty}))

    def test_each_official_status_and_unresolved_proposal(self):
        self.assertEqual(_adjudicate().deletion_status, DeletionStatus.COMPLETE)
        self.assertEqual(_adjudicate(text="Please provide access to my data.").deletion_status,
                         DeletionStatus.NOT_APPLICABLE)
        self.assertEqual(_adjudicate(state=ResourceState.PRESENT).deletion_status,
                         DeletionStatus.INCOMPLETE)
        unresolved = _adjudicate(state=ResourceState.UNKNOWN)
        self.assertIsNone(unresolved.deletion_status)
        self.assertEqual(unresolved.resolution, DecisionResolution.UNRESOLVED)

    def test_missing_identity_and_unresolved_policy_do_not_force_status(self):
        missing_identity = _adjudicate(identity_status=ResolutionStatus.AMBIGUOUS, user_id=None)
        self.assertIsNone(missing_identity.deletion_status)
        unresolved_policy = _adjudicate(policy_status=DecisionStatus.UNRESOLVED,
                                        policy_uncertainty=("condition_unknown",))
        self.assertIsNone(unresolved_policy.deletion_status)
        self.assertIn("condition_unknown", unresolved_policy.unresolved_reasons)
        inconsistent_policy = _adjudicate(policy_status=DecisionStatus.APPLIES,
                                          policy_condition=ConditionStatus.UNKNOWN)
        self.assertIsNone(inconsistent_policy.deletion_status)
        conflict = PolicyConflict("case-synthetic", ResourceKey("u-1", ("profile",), "r-1",
            "USER_PROFILE"), "USER_PROFILE", ("rule-1", "rule-2"),
            (PolicyAction.DELETE, PolicyAction.REDACT))
        conflicting_rules = _adjudicate(policy_conflicts=(conflict,))
        self.assertIsNone(conflicting_rules.deletion_status)

    def test_claim_only_operation_does_not_establish_incomplete_or_complete(self):
        claim = RiskFinding("f1", "case-synthetic", "u-1",
            ResourceKey("u-1", ("profile",), "r-1", "USER_PROFILE"),
            RiskFindingType.CLAIMED_RECREATION_OPERATION, RiskConfidence.LOW,
            RiskEvidenceStatus.CLAIM_ONLY, EventCategory.SYNCHRONIZATION, CUTOFF,
            None, None, None, (RiskEvidenceReference("system_activity", "activity-1",
                "system_activity.csv", record_id="activity-1", role="claim_only"),),
            ("reported_operation_does_not_establish_effect",))
        decision = _adjudicate(risk_findings=(claim,))
        self.assertIsNone(decision.deletion_status)
        self.assertEqual(decision.resolution, DecisionResolution.UNRESOLVED)

    def test_recreation_risk_confirms_incomplete_without_erasing_other_uncertainty(self):
        finding = RiskFinding("f2", "case-synthetic", "u-1",
            ResourceKey("u-1", ("profile",), "r-1", "USER_PROFILE"),
            RiskFindingType.POSSIBLE_DATA_FLOW_RECREATION, RiskConfidence.MEDIUM,
            RiskEvidenceStatus.DIRECT_CONTROL, EventCategory.SYNCHRONIZATION, CUTOFF,
            ResourceState.ACTIVE, None, None, (RiskEvidenceReference("evidence", "file-1",
                "evidence/flow.json", file_id="file-1", role="observation"),))
        decision = _adjudicate(risk_findings=(finding,), gaps=("ocr-gap-1",))
        self.assertEqual(decision.deletion_status, DeletionStatus.INCOMPLETE)
        self.assertIn("extraction_gap_case_relevance_unresolved", decision.unresolved_reasons)

    def test_ocr_gap_alone_is_uncertainty_not_violation_or_complete(self):
        decision = _adjudicate(gaps=("ocr-gap-1",))
        self.assertIsNone(decision.deletion_status)
        self.assertEqual(decision.resolution, DecisionResolution.UNRESOLVED)
        self.assertIn("extraction_gap_case_relevance_unresolved", decision.unresolved_reasons)

    def test_unlinked_global_gap_is_preserved_but_does_not_block_unrelated_case(self):
        report = adjudicate_cases(*_harness(global_gaps=("unlinked-gap",)))
        decision = report.cases[0]
        self.assertEqual(decision.deletion_status, DeletionStatus.COMPLETE)
        self.assertNotIn("extraction_gap_case_relevance_unresolved", decision.unresolved_reasons)
        self.assertEqual(report.global_extraction_gap_file_ids, ("unlinked-gap",))

    def test_case_linked_extraction_gap_still_blocks_unsupported_complete(self):
        decision = _adjudicate(gaps=("linked-gap",))
        self.assertIsNone(decision.deletion_status)
        self.assertEqual(decision.resolution, DecisionResolution.UNRESOLVED)
        self.assertIn("extraction_gap_case_relevance_unresolved", decision.unresolved_reasons)
        refs = [ref for reason in decision.reasons for ref in reason.evidence]
        self.assertTrue(any(ref.source_id == "linked-gap" and ref.source_kind == "manifest" for ref in refs))

    def test_redaction_presence_without_direct_identifier_evidence_is_unresolved(self):
        decision = _adjudicate(state=ResourceState.PRESENT, action=PolicyAction.REDACT)
        self.assertIsNone(decision.deletion_status)
        self.assertIn("redaction_compliance_not_proven", decision.unresolved_reasons)

    def test_supported_policy_violation_keeps_traceable_reason(self):
        decision = _adjudicate(state=ResourceState.PRESENT)
        self.assertEqual(decision.deletion_status, DeletionStatus.INCOMPLETE)
        reason = next(item for item in decision.reasons if item.code == "policy_state_violation")
        self.assertEqual(reason.evidence[0].source_kind, "deletion_rule")


if __name__ == "__main__":
    unittest.main()
