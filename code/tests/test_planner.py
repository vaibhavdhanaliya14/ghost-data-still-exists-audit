from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timezone

from audit_agent.adjudication import (
    CaseAdjudication, DecisionResolution, DeletionStatus, IntentKind, RequestIntent,
)
from audit_agent.extract import (
    EvidenceExtractionResult, ExtractedObservation, ExtractionStatus, FileExtractionResult,
)
from audit_agent.models import (
    CsvRecord, CsvTable, DatasetBundle, IngestionResult, ParsedTimestamp, SourceLocation,
    TimestampStatus,
)
from audit_agent.planner import (
    PlanResolution, PlannedStep, StepOperation, StepPhase, _DraftStep,
    _build_dependencies, _step_sort_key, plan_remediation_steps, validate_plan,
)
from audit_agent.policy import (
    ConditionStatus, DecisionStatus, PolicyAction, PolicyCaseResult, PolicyConflict,
    PolicyDecision, PolicyEvaluation, PolicyRule,
)
from audit_agent.risks import (
    RiskAnalysis, RiskCaseResult, RiskConfidence, RiskEvidenceReference,
    RiskEvidenceStatus, RiskFinding, RiskFindingType,
)
from audit_agent.state import (
    CaseStateSnapshot, ResourceAssessment, ResourceKey, ResourceState, StateDomain,
    StateEvidence, StateSnapshot,
)
from audit_agent.timeline import TimelineSource


CUTOFF = datetime(2026, 4, 1, tzinfo=timezone.utc)


def _pt(value: datetime = CUTOFF) -> ParsedTimestamp:
    return ParsedTimestamp(value.isoformat(), TimestampStatus.VALID, value)


def _fixtures(*, status=DeletionStatus.INCOMPLETE, state=ResourceState.PRESENT,
              action=PolicyAction.DELETE, operation_finding=True, flow=False,
              file_time=CUTOFF, replica_context=(), conflicts=()):
    case_id = "synthetic-case"
    key = ResourceKey("synthetic-user", ("profile",), "record-1", "profile", "")
    observation = ExtractedObservation(
        "obs-1", "file-1", "evidence/example.json", "json", "record:1", "json", {}, {}, (),
        "profile", "record-1", (), _pt(file_time))
    file_result = FileExtractionResult("file-1", observation.source_path, "json", "json",
        ExtractionStatus.COMPLETE, _pt(file_time), (observation,), (), (), ())
    extraction = EvidenceExtractionResult((file_result,))
    source = TimelineSource("evidence", observation.source_path, file_id="file-1",
                            observation_id="obs-1", locator="record:1")
    evidence = StateEvidence("state-evidence", state, StateDomain.LIFECYCLE, source,
        _pt(CUTOFF), _pt(file_time), CUTOFF, "capture_time", "state", state.value,
        None, "observation", tuple(replica_context))
    assessment = ResourceAssessment(key, StateDomain.LIFECYCLE, CUTOFF, state, state, CUTOFF,
        (evidence,), (), (), (), tuple(replica_context))
    snapshot = StateSnapshot(CUTOFF, (assessment,), (), (), (), (), (), (), ())
    case_state = CaseStateSnapshot(case_id, "confirmed", "synthetic-user", snapshot)
    rule = PolicyRule("rule-1", "PROFILE", "always", action, "deletion_rules.csv", 2)
    decision = PolicyDecision(case_id, key, "PROFILE", rule, DecisionStatus.APPLIES,
        ConditionStatus.SATISFIED, action, ((StateDomain.LIFECYCLE, state),), (), (), ())
    policy_case = PolicyCaseResult(case_id, "confirmed", "synthetic-user", CUTOFF, True,
        (decision,), tuple(conflicts), (), (), (), (), ())
    policy = PolicyEvaluation((rule,), (policy_case,), ())
    findings = []
    if operation_finding:
        findings.append(RiskFinding("finding-1", case_id, "synthetic-user", key,
            RiskFindingType.RESOURCE_PRESENT_AFTER_DELETE, RiskConfidence.HIGH,
            RiskEvidenceStatus.DIRECT_STATE, None, CUTOFF, state, "rule-1", action,
            (RiskEvidenceReference("evidence", "file-1", observation.source_path,
                file_id="file-1", observation_id="obs-1", event_time=CUTOFF,
                capture_time=file_time),)))
    if flow:
        flow_key = ResourceKey("synthetic-user", ("profile",), "sync-flow", "data_flow", "")
        findings.append(RiskFinding("finding-flow", case_id, "synthetic-user", flow_key,
            RiskFindingType.POSSIBLE_DATA_FLOW_RECREATION, RiskConfidence.HIGH,
            RiskEvidenceStatus.DIRECT_CONTROL, None, CUTOFF, ResourceState.ACTIVE,
            None, None, (RiskEvidenceReference("evidence", "file-1", observation.source_path,
                file_id="file-1", observation_id="obs-1", event_time=CUTOFF,
                capture_time=file_time),)))
    risk_case = RiskCaseResult(case_id, "synthetic-user", CUTOFF, tuple(findings), (), (), (), (), ())
    risks = RiskAnalysis((risk_case,))
    intent = RequestIntent(case_id, IntentKind.DELETION, True, (), (), "requests.csv", 2, "synthetic")
    adjudication = CaseAdjudication(case_id, CUTOFF, intent, DecisionResolution.CONFIRMED,
        status, (), (), ())
    table = CsvTable("system_activity", __import__("pathlib").Path("system_activity.csv"),
        ("activity_id", "event_time"), (), True)
    ingestion = IngestionResult(DatasetBundle({"system_activity": table}), ())
    return adjudication, case_state, policy, risks, ingestion, extraction, key


def _plan(args):
    return plan_remediation_steps([args[0]], [args[1]], args[2], args[3], args[4], args[5]).cases[0]


class PlannerTests(unittest.TestCase):
    def test_incomplete_steps_use_exact_schema_and_future_refs_are_empty(self):
        args = _fixtures()
        plan = _plan(args)
        self.assertEqual(plan.resolution, PlanResolution.READY)
        self.assertEqual([step.step_no for step in plan.steps], [1, 2, 3])
        self.assertEqual([step.operation for step in plan.steps], [
            "REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"])
        self.assertEqual(tuple(plan.steps[0].as_dict()),
                         ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"))
        self.assertEqual(plan.steps[0].evidence_id, "file-1")
        self.assertEqual(plan.steps[1].evidence_id, "")
        self.assertEqual(plan.steps[2].evidence_id, "")
        self.assertEqual(validate_plan(plan, args[4], args[5]), ())

    def test_active_flow_is_disabled_before_record_remediation(self):
        args = _fixtures(flow=True)
        plan = _plan(args)
        remediation = [step.operation for step in plan.steps if step.phase == "REMEDIATION"]
        self.assertEqual(remediation, ["DISABLE_DATA_FLOW", "DELETE_RECORD"])
        self.assertTrue(plan.dependencies)
        self.assertTrue(all(item.before_step_no < item.after_step_no for item in plan.dependencies))
        self.assertEqual(plan.resolution, PlanResolution.READY)

    def test_post_cutoff_finding_evidence_blocks_ready_plan(self):
        args = _fixtures(file_time=datetime(2026, 4, 2, tzinfo=timezone.utc))
        plan = _plan(args)
        self.assertEqual(plan.resolution, PlanResolution.UNRESOLVED)
        self.assertIn("finding_evidence_missing_or_ineligible", {d.code for d in plan.diagnostics})

    def test_policy_conflicts_prevent_resource_remediation(self):
        conflict = PolicyConflict("synthetic-case", ResourceKey("synthetic-user", ("profile",),
            "record-1", "profile", ""), "PROFILE", ("rule-1", "rule-2"),
            (PolicyAction.DELETE, PolicyAction.RETAIN))
        args = _fixtures(conflicts=(conflict,))
        plan = _plan(args)
        self.assertEqual(plan.resolution, PlanResolution.UNRESOLVED)
        self.assertNotIn("DELETE_RECORD", [step.operation for step in plan.steps])
        self.assertIn("conflicting_policy_obligations", {d.code for d in plan.diagnostics})

    def test_evidence_backed_finding_is_not_serializable_without_resolved_remediation(self):
        args = _fixtures(action=PolicyAction.REDACT, operation_finding=False)
        decision = replace(args[2].cases[0].decisions[0], status=DecisionStatus.UNRESOLVED,
                           condition_status=ConditionStatus.UNKNOWN)
        policy_case = replace(args[2].cases[0], decisions=(decision,))
        policy = replace(args[2], cases=(policy_case,))
        key = decision.resource_key
        risk = RiskFinding("pii-finding", "synthetic-case", "synthetic-user", key,
            RiskFindingType.POLICY_STATE_CONFLICT, RiskConfidence.HIGH,
            RiskEvidenceStatus.DIRECT_STATE, None, CUTOFF, ResourceState.PRESENT,
            "rule-1", PolicyAction.REDACT,
            (RiskEvidenceReference("evidence", "file-1", "evidence/example.json",
                file_id="file-1", observation_id="obs-1", event_time=CUTOFF, capture_time=CUTOFF),))
        risks = replace(args[3], cases=(replace(args[3].cases[0], findings=(risk,)),))
        plan = plan_remediation_steps([args[0]], [args[1]], policy, risks, args[4], args[5]).cases[0]
        self.assertEqual([step.operation for step in plan.steps], ["REPORT_EXPOSED_PII"])
        self.assertFalse(plan.serialization_ready)
        self.assertEqual(plan.resolution, PlanResolution.UNRESOLVED)
        self.assertIn("finding_has_no_policy_safe_remediation", {item.code for item in plan.diagnostics})
        self.assertIn("incomplete_phase_coverage_missing",
                      {item.code for item in validate_plan(plan, args[4], args[5])})

    def test_retain_never_becomes_delete_and_missing_retain_target_is_unresolved(self):
        args = _fixtures(state=ResourceState.PRESENT, action=PolicyAction.RETAIN,
                         operation_finding=False)
        plan = _plan(args)
        self.assertNotIn("DELETE_RECORD", [step.operation for step in plan.steps])
        self.assertIn("VERIFY_RECORD_PRESENT", [step.operation for step in plan.steps])
        args = _fixtures(state=ResourceState.UNKNOWN, action=PolicyAction.RETAIN,
                         operation_finding=False)
        plan = _plan(args)
        self.assertEqual(plan.resolution, PlanResolution.UNRESOLVED)

    def test_complete_requires_eligible_direct_current_evidence(self):
        args = _fixtures(status=DeletionStatus.COMPLETE, state=ResourceState.ABSENT,
                         operation_finding=False)
        plan = _plan(args)
        self.assertEqual(plan.resolution, PlanResolution.READY)
        self.assertEqual([step.operation for step in plan.steps], ["VERIFY_RECORD_ABSENT"])
        args = _fixtures(status=DeletionStatus.COMPLETE, state=ResourceState.ABSENT,
                         operation_finding=False,
                         file_time=datetime(2026, 4, 2, tzinfo=timezone.utc))
        plan = _plan(args)
        self.assertEqual(plan.resolution, PlanResolution.UNRESOLVED)

    def test_not_applicable_has_no_steps(self):
        args = _fixtures(status=DeletionStatus.NOT_APPLICABLE)
        plan = _plan(args)
        self.assertEqual(plan.steps, ())
        self.assertEqual(plan.resolution, PlanResolution.READY)

    def test_replica_dependency_that_conflicts_with_contract_order_is_explicit(self):
        source_key = ResourceKey("u", ("db",), "a-source", "record", "")
        replica_key = ResourceKey("u", ("db",), "z-copy", "replica", "")
        def assessment(key, context=()):
            return ResourceAssessment(key, StateDomain.LIFECYCLE, CUTOFF, ResourceState.PRESENT,
                ResourceState.PRESENT, CUTOFF, (), (), (), (), context)
        source = _DraftStep(StepPhase.REMEDIATION, "db", "a-source", StepOperation.DELETE_RECORD,
                            "ABSENT", "")
        replica = _DraftStep(StepPhase.REMEDIATION, "db", "z-copy", StepOperation.DELETE_RECORD,
                             "ABSENT", "")
        diagnostics = []
        dependencies = _build_dependencies({source.key: source, replica.key: replica},
            (assessment(source_key), assessment(replica_key, (("replica_of", "a-source"),))), diagnostics)
        self.assertEqual(len(dependencies), 1)
        edge = dependencies[0]
        ordered = sorted((source, replica), key=_step_sort_key)
        order = {item.key: index for index, item in enumerate(ordered)}
        self.assertGreater(order[edge.before], order[edge.after])
        self.assertFalse(diagnostics)

    def test_top_level_plan_fails_closed_when_replica_order_is_unserializable(self):
        args = _fixtures(operation_finding=False)
        original_case = args[1]
        base_assessment = original_case.snapshot.assessments[0]
        downstream = replace(base_assessment,
            key=replace(base_assessment.key, resource_id="z-copy", resource_type="replica"),
            relationship_context=(("replica_of", "a-source"),))
        source = replace(base_assessment,
            key=replace(base_assessment.key, resource_id="a-source", resource_type="profile"),
            relationship_context=())
        new_snapshot = replace(original_case.snapshot, assessments=(downstream, source))
        case = replace(original_case, snapshot=new_snapshot)
        old_decision = args[2].cases[0].decisions[0]
        downstream_decision = replace(old_decision, resource_key=downstream.key)
        source_decision = replace(old_decision, resource_key=source.key)
        policy_case = replace(args[2].cases[0], decisions=(downstream_decision, source_decision))
        policy = replace(args[2], cases=(policy_case,))
        risks = replace(args[3], cases=(replace(args[3].cases[0], findings=()),))
        plan = plan_remediation_steps([args[0]], [case], policy, risks, args[4], args[5]).cases[0]
        self.assertEqual(plan.resolution, PlanResolution.UNRESOLVED)
        self.assertFalse(plan.serialization_ready)
        self.assertIn("dependency_order_conflict", {item.code for item in plan.diagnostics})

    def test_validator_rejects_noncontract_state_and_nonconsecutive_numbers(self):
        args = _fixtures()
        plan = _plan(args)
        bad_steps = (
            PlannedStep(2, "FINDING", "profile", "record-1", "REPORT_REMAINING_RECORD", "ABSENT", "file-1"),
        )
        bad_plan = plan.__class__(plan.case_id, plan.audit_at, plan.deletion_status,
            PlanResolution.UNRESOLVED, False, bad_steps, (), ())
        codes = {issue.code for issue in validate_plan(bad_plan, args[4], args[5])}
        self.assertIn("phase_operation_state_invalid", codes)
        self.assertIn("step_numbers_not_consecutive", codes)
        bad_typed_step = replace(bad_steps[0], state=42)
        bad_typed_plan = plan.__class__(plan.case_id, plan.audit_at, plan.deletion_status,
            PlanResolution.UNRESOLVED, False, (bad_typed_step,), (), ())
        typed_codes = {issue.code for issue in validate_plan(bad_typed_plan, args[4], args[5])}
        self.assertIn("step_field_type_invalid", typed_codes)


if __name__ == "__main__":
    unittest.main()
