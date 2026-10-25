"""Contract-constrained remediation and verification planning (Phase 10).

Steps here are proposals or current verification checks. They are never claims
that remediation has already occurred, and this module does not write output.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum
from typing import Iterable, Mapping

from .adjudication import (
    CaseAdjudication, DecisionResolution, DeletionStatus, AdjudicationReference,
)
from .extract import EvidenceExtractionResult
from .identity import IdentityResolutionResult
from .models import IngestionResult, ParsedTimestamp, TimestampStatus
from .policy import DecisionStatus, PolicyAction, PolicyCaseResult, PolicyDecision, PolicyEvaluation
from .risks import RiskAnalysis, RiskCaseResult, RiskEvidenceReference, RiskFinding, RiskFindingType
from .state import CaseStateSnapshot, ResourceAssessment, ResourceKey, ResourceState, StateDomain, StateEvidence


class StepPhase(str, Enum):
    FINDING = "FINDING"
    REMEDIATION = "REMEDIATION"
    VERIFICATION = "VERIFICATION"


class StepOperation(str, Enum):
    REPORT_REMAINING_RECORD = "REPORT_REMAINING_RECORD"
    REPORT_EXPOSED_PII = "REPORT_EXPOSED_PII"
    REPORT_ACTIVE_DATA_FLOW = "REPORT_ACTIVE_DATA_FLOW"
    REPORT_RESTORE_RISK = "REPORT_RESTORE_RISK"
    DISABLE_DATA_FLOW = "DISABLE_DATA_FLOW"
    BLOCK_RESTORE = "BLOCK_RESTORE"
    DELETE_RECORD = "DELETE_RECORD"
    REDACT_RECORD = "REDACT_RECORD"
    ANONYMIZE_RECORD = "ANONYMIZE_RECORD"
    VERIFY_RECORD_ABSENT = "VERIFY_RECORD_ABSENT"
    VERIFY_RECORD_PRESENT = "VERIFY_RECORD_PRESENT"
    VERIFY_RECORD_REDACTED = "VERIFY_RECORD_REDACTED"
    VERIFY_RECORD_ANONYMIZED = "VERIFY_RECORD_ANONYMIZED"
    VERIFY_DATA_FLOW_DISABLED = "VERIFY_DATA_FLOW_DISABLED"
    VERIFY_RESTORE_BLOCKED = "VERIFY_RESTORE_BLOCKED"


class PlanResolution(str, Enum):
    READY = "ready"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class PlannedStep:
    step_no: int
    phase: str
    system_id: str
    resource_id: str
    operation: str
    state: str
    evidence_id: str

    def as_dict(self) -> dict[str, object]:
        return {
            "step_no": self.step_no,
            "phase": self.phase,
            "system_id": self.system_id,
            "resource_id": self.resource_id,
            "operation": self.operation,
            "state": self.state,
            "evidence_id": self.evidence_id,
        }


@dataclass(frozen=True)
class PlanDiagnostic:
    code: str
    message: str
    resource_id: str | None = None
    operation: str | None = None


@dataclass(frozen=True)
class PlanDependency:
    before_step_no: int
    after_step_no: int
    reason: str


@dataclass(frozen=True)
class CasePlan:
    case_id: str
    audit_at: datetime | None
    deletion_status: DeletionStatus | None
    resolution: PlanResolution
    serialization_ready: bool
    steps: tuple[PlannedStep, ...]
    dependencies: tuple[PlanDependency, ...]
    diagnostics: tuple[PlanDiagnostic, ...]


@dataclass(frozen=True)
class PlanningReport:
    cases: tuple[CasePlan, ...]

    @property
    def unresolved_cases(self) -> tuple[CasePlan, ...]:
        return tuple(case for case in self.cases if case.resolution is PlanResolution.UNRESOLVED)

    @property
    def total_steps(self) -> int:
        return sum(len(case.steps) for case in self.cases)


@dataclass(frozen=True)
class PlanValidationIssue:
    code: str
    message: str
    step_no: int | None = None


@dataclass(frozen=True)
class _DraftStep:
    phase: StepPhase
    system_id: str
    resource_id: str
    operation: StepOperation
    state: str
    evidence_id: str

    @property
    def key(self) -> tuple[str, str, str, str]:
        return self.phase.value, self.operation.value, self.system_id, self.resource_id


@dataclass(frozen=True)
class _DraftDependency:
    before: tuple[str, str, str, str]
    after: tuple[str, str, str, str]
    reason: str


_PHASE_RANK = {StepPhase.FINDING.value: 0, StepPhase.REMEDIATION.value: 1,
               StepPhase.VERIFICATION.value: 2}
_OPERATION_ORDER = {
    StepPhase.FINDING: (
        StepOperation.REPORT_REMAINING_RECORD, StepOperation.REPORT_EXPOSED_PII,
        StepOperation.REPORT_ACTIVE_DATA_FLOW, StepOperation.REPORT_RESTORE_RISK,
    ),
    StepPhase.REMEDIATION: (
        StepOperation.DISABLE_DATA_FLOW, StepOperation.BLOCK_RESTORE,
        StepOperation.DELETE_RECORD, StepOperation.REDACT_RECORD, StepOperation.ANONYMIZE_RECORD,
    ),
    StepPhase.VERIFICATION: (
        StepOperation.VERIFY_RECORD_ABSENT, StepOperation.VERIFY_RECORD_PRESENT,
        StepOperation.VERIFY_RECORD_REDACTED, StepOperation.VERIFY_RECORD_ANONYMIZED,
        StepOperation.VERIFY_DATA_FLOW_DISABLED, StepOperation.VERIFY_RESTORE_BLOCKED,
    ),
}
_ALLOWED_STATES = {
    (StepPhase.FINDING, StepOperation.REPORT_REMAINING_RECORD): "PRESENT",
    (StepPhase.FINDING, StepOperation.REPORT_EXPOSED_PII): "PRESENT",
    (StepPhase.FINDING, StepOperation.REPORT_ACTIVE_DATA_FLOW): "ACTIVE",
    (StepPhase.FINDING, StepOperation.REPORT_RESTORE_RISK): "ACTIVE",
    (StepPhase.REMEDIATION, StepOperation.DISABLE_DATA_FLOW): "DISABLED",
    (StepPhase.REMEDIATION, StepOperation.BLOCK_RESTORE): "BLOCKED",
    (StepPhase.REMEDIATION, StepOperation.DELETE_RECORD): "ABSENT",
    (StepPhase.REMEDIATION, StepOperation.REDACT_RECORD): "REDACTED",
    (StepPhase.REMEDIATION, StepOperation.ANONYMIZE_RECORD): "ANONYMIZED",
    (StepPhase.VERIFICATION, StepOperation.VERIFY_RECORD_ABSENT): "ABSENT",
    (StepPhase.VERIFICATION, StepOperation.VERIFY_RECORD_PRESENT): "PRESENT",
    (StepPhase.VERIFICATION, StepOperation.VERIFY_RECORD_REDACTED): "REDACTED",
    (StepPhase.VERIFICATION, StepOperation.VERIFY_RECORD_ANONYMIZED): "ANONYMIZED",
    (StepPhase.VERIFICATION, StepOperation.VERIFY_DATA_FLOW_DISABLED): "DISABLED",
    (StepPhase.VERIFICATION, StepOperation.VERIFY_RESTORE_BLOCKED): "BLOCKED",
}
_TREATMENT_STEPS = {
    PolicyAction.DELETE: (StepOperation.DELETE_RECORD, "ABSENT", StepOperation.VERIFY_RECORD_ABSENT),
    PolicyAction.REDACT: (StepOperation.REDACT_RECORD, "REDACTED", StepOperation.VERIFY_RECORD_REDACTED),
    PolicyAction.ANONYMIZE: (StepOperation.ANONYMIZE_RECORD, "ANONYMIZED", StepOperation.VERIFY_RECORD_ANONYMIZED),
}
_REMEDIATION_TO_VERIFICATION = {
    StepOperation.DELETE_RECORD: StepOperation.VERIFY_RECORD_ABSENT,
    StepOperation.REDACT_RECORD: StepOperation.VERIFY_RECORD_REDACTED,
    StepOperation.ANONYMIZE_RECORD: StepOperation.VERIFY_RECORD_ANONYMIZED,
    StepOperation.DISABLE_DATA_FLOW: StepOperation.VERIFY_DATA_FLOW_DISABLED,
    StepOperation.BLOCK_RESTORE: StepOperation.VERIFY_RESTORE_BLOCKED,
}
_FINDING_REMEDIATION = {
    StepOperation.REPORT_REMAINING_RECORD: StepOperation.DELETE_RECORD,
    StepOperation.REPORT_EXPOSED_PII: None,  # Chosen from the applicable policy action.
    StepOperation.REPORT_ACTIVE_DATA_FLOW: StepOperation.DISABLE_DATA_FLOW,
    StepOperation.REPORT_RESTORE_RISK: StepOperation.BLOCK_RESTORE,
}
_DIRECT_STATE_SOURCES = frozenset({"evidence"})


def _step_sort_key(step: _DraftStep) -> tuple[int, int, str, str]:
    return (_PHASE_RANK[step.phase.value], _OPERATION_ORDER[step.phase].index(step.operation),
            step.system_id, step.resource_id)


def _single_system(key: ResourceKey) -> str | None:
    return key.system_ids[0] if len(key.system_ids) == 1 and key.system_ids[0] else None


def _draft(phase: StepPhase, key: ResourceKey, operation: StepOperation,
           evidence_id: str = "") -> tuple[_DraftStep | None, PlanDiagnostic | None]:
    system_id = _single_system(key)
    if not system_id:
        return None, PlanDiagnostic("resource_system_scope_not_serializable",
            "The resource does not resolve to exactly one official system_id.", key.resource_id, operation.value)
    if not key.resource_id:
        return None, PlanDiagnostic("resource_id_missing", "The resource has no serializable resource_id.", None, operation.value)
    state = _ALLOWED_STATES.get((phase, operation))
    if state is None:
        return None, PlanDiagnostic("unsupported_phase_operation", "The phase/operation pair is not in the official contract.",
            key.resource_id, operation.value)
    return _DraftStep(phase, system_id, key.resource_id, operation, state, evidence_id), None


def _known_reference_id(reference: RiskEvidenceReference | AdjudicationReference,
                        ingestion: IngestionResult, extraction: EvidenceExtractionResult,
                        cutoff: datetime) -> str | None:
    if reference.capture_time is not None and reference.capture_time > cutoff:
        return None
    if reference.event_time is not None and reference.event_time > cutoff:
        return None
    kind = reference.source_kind.casefold()
    source_id = reference.source_id
    if kind in {"evidence", "file", "manifest"}:
        file_id = getattr(reference, "file_id", None) or source_id
        result = extraction.by_file_id.get(file_id)
        if result is None or result.status.value in {"failed", "missing", "inaccessible", "unsupported", "rejected"}:
            return None
        captured = result.captured_at
        if captured is None or captured.status is not TimestampStatus.VALID or captured.value is None or captured.value > cutoff:
            return None
        obs_id = getattr(reference, "observation_id", None)
        if obs_id:
            observation = next((item for item in result.observations if item.observation_id == obs_id), None)
            if observation is None:
                return None
            if observation.captured_at is None or observation.captured_at.status is not TimestampStatus.VALID \
                    or observation.captured_at.value is None or observation.captured_at.value > cutoff:
                return None
        return file_id
    table_names = ("system_activity",) if kind in {"system_activity", "activity", "activity_id"} else (
        ("user_audit_log",) if kind in {"user_audit_log", "audit", "audit_id"} else ())
    identifier_column = "activity_id" if table_names == ("system_activity",) else "audit_id"
    time_column = "event_time"
    for table_name in table_names:
        table = ingestion.bundle.tables.get(table_name)
        if table is None:
            continue
        for row in table.records:
            if row.raw(identifier_column) != source_id:
                continue
            parsed = row.typed(time_column)
            return source_id if isinstance(parsed, ParsedTimestamp) and parsed.status is TimestampStatus.VALID \
                and parsed.value is not None and parsed.value <= cutoff else None
    return None


def _state_evidence_source(assessment: ResourceAssessment, required_state: ResourceState | None,
                           extraction: EvidenceExtractionResult, cutoff: datetime,
                           ingestion: IngestionResult) -> str | None:
    for item in sorted(assessment.evidence, key=lambda ev: (
            ev.source.file_id or "", ev.source.locator or "", ev.evidence_key)):
        if item.state is not required_state or item.state_observed_at != assessment.last_observed_at \
                or item.state_observed_at is None or item.source.source_kind not in _DIRECT_STATE_SOURCES:
            continue
        if not item.source.file_id:
            continue
        ref = RiskEvidenceReference("evidence", item.source.file_id, item.source.source_file,
            file_id=item.source.file_id, record_id=item.source.record_id,
            observation_id=item.source.observation_id, locator=item.source.locator,
            event_time=item.event_time.value if item.event_time and item.event_time.status is TimestampStatus.VALID else None,
            capture_time=item.capture_time.value if item.capture_time and item.capture_time.status is TimestampStatus.VALID else None)
        found = _known_reference_id(ref, ingestion, extraction, cutoff)
        if found:
            return found
    return None


def _risk_evidence_id(finding: RiskFinding, ingestion: IngestionResult,
                      extraction: EvidenceExtractionResult, cutoff: datetime) -> str | None:
    refs = sorted(finding.evidence, key=lambda ref: (
        ref.source_kind != "evidence", ref.source_id, ref.locator or ""))
    for ref in refs:
        found = _known_reference_id(ref, ingestion, extraction, cutoff)
        if found:
            return found
    return None


def _assessment_index(case: CaseStateSnapshot) -> Mapping[tuple[ResourceKey, StateDomain], ResourceAssessment]:
    if case.snapshot is None:
        return {}
    return {(item.key, item.domain): item for item in case.snapshot.assessments}


def _decision_index(policy_case: PolicyCaseResult | None) -> Mapping[ResourceKey, tuple[PolicyDecision, ...]]:
    if policy_case is None:
        return {}
    grouped: dict[ResourceKey, list[PolicyDecision]] = {}
    for decision in policy_case.decisions:
        grouped.setdefault(decision.resource_key, []).append(decision)
    return {key: tuple(values) for key, values in grouped.items()}


def _evidence_for_assessment(assessment: ResourceAssessment, required_state: ResourceState,
                             ingestion: IngestionResult, extraction: EvidenceExtractionResult,
                             cutoff: datetime) -> str | None:
    for item in sorted(assessment.evidence, key=lambda value: (
            value.source.file_id or "", value.source.locator or "", value.evidence_key)):
        if item.state is not required_state or item.state_observed_at != assessment.last_observed_at \
                or item.source.source_kind != "evidence" or not item.source.file_id:
            continue
        ref = RiskEvidenceReference("evidence", item.source.file_id, item.source.source_file,
            file_id=item.source.file_id, observation_id=item.source.observation_id,
            locator=item.source.locator,
            event_time=item.event_time.value if item.event_time and item.event_time.status is TimestampStatus.VALID else None,
            capture_time=item.capture_time.value if item.capture_time and item.capture_time.status is TimestampStatus.VALID else None)
        evidence_id = _known_reference_id(ref, ingestion, extraction, cutoff)
        if evidence_id:
            return evidence_id
    return None


def _operation_for_action(action: PolicyAction) -> tuple[StepOperation, str, StepOperation] | None:
    return _TREATMENT_STEPS.get(action)


def _append_step(steps: dict[tuple[str, str, str, str], _DraftStep],
                 diagnostics: list[PlanDiagnostic], phase: StepPhase, key: ResourceKey,
                 operation: StepOperation, evidence_id: str = "") -> _DraftStep | None:
    step, issue = _draft(phase, key, operation, evidence_id)
    if issue:
        diagnostics.append(issue)
        return None
    assert step is not None
    old = steps.get(step.key)
    if old is not None:
        if old.evidence_id and evidence_id and old.evidence_id != evidence_id:
            steps[step.key] = replace(old, evidence_id=min(old.evidence_id, evidence_id))
        elif not old.evidence_id and evidence_id:
            steps[step.key] = replace(old, evidence_id=evidence_id)
    else:
        steps[step.key] = step
    return steps[step.key]


def _build_dependencies(remediation_steps: Mapping[tuple[str, str, str, str], _DraftStep],
                         assessments: Iterable[ResourceAssessment],
                         diagnostics: list[PlanDiagnostic]) -> tuple[_DraftDependency, ...]:
    edges: set[_DraftDependency] = set()
    controls = [step for step in remediation_steps.values() if step.operation in {
        StepOperation.DISABLE_DATA_FLOW, StepOperation.BLOCK_RESTORE}]
    records = [step for step in remediation_steps.values() if step.operation in {
        StepOperation.DELETE_RECORD, StepOperation.REDACT_RECORD, StepOperation.ANONYMIZE_RECORD}]
    for control in controls:
        for record in records:
            edges.add(_DraftDependency(control.key, record.key,
                "disable recreation paths before changing affected records"))

    record_by_key = {(item.key.resource_id, item.key.system_ids): item for item in assessments}
    record_steps = {step.key[2:]: step for step in records}
    relation_names = {"replica_of", "primary_resource_id", "source_resource_id"}
    for assessment in assessments:
        target = next((step for step in records if step.resource_id == assessment.key.resource_id
                       and step.system_id in assessment.key.system_ids), None)
        if target is None:
            continue
        relationships = dict(assessment.relationship_context)
        for field in sorted(relation_names.intersection(relationships)):
            source_id = relationships[field].strip()
            if not source_id or source_id.casefold() in {"true", "false", "1", "0"}:
                continue
            source_system = next((relationships[name].strip() for name in
                ("source_system", "origin_system", "primary_system") if relationships.get(name)), None)
            candidates = [step for step in records if step.resource_id == source_id
                          and step.key != target.key
                          and (source_system is None or step.system_id == source_system)]
            if len(candidates) > 1:
                diagnostics.append(PlanDiagnostic("replica_source_ambiguous",
                    "A participant-evidenced replica relationship maps to multiple remediation targets.",
                    target.resource_id, target.operation.value))
            elif candidates:
                edges.add(_DraftDependency(target.key, candidates[0].key,
                    f"downstream-before-source from {field} relationship"))
    return tuple(sorted(edges, key=lambda edge: (edge.before, edge.after, edge.reason)))


def _finding_operation(finding: RiskFinding, decisions: tuple[PolicyDecision, ...]) -> StepOperation | None:
    if finding.finding_type is RiskFindingType.POSSIBLE_DATA_FLOW_RECREATION:
        return StepOperation.REPORT_ACTIVE_DATA_FLOW
    if finding.finding_type is RiskFindingType.POSSIBLE_RESTORE:
        return StepOperation.REPORT_RESTORE_RISK
    if finding.finding_type is RiskFindingType.POLICY_STATE_CONFLICT:
        action = finding.policy_action or next((item.required_action for item in decisions
            if item.status is DecisionStatus.APPLIES), None)
        if action is PolicyAction.DELETE:
            return StepOperation.REPORT_REMAINING_RECORD
        if action in {PolicyAction.REDACT, PolicyAction.ANONYMIZE}:
            return StepOperation.REPORT_EXPOSED_PII
        return None
    if finding.finding_type in {RiskFindingType.RESOURCE_PRESENT_AFTER_DELETE,
                                RiskFindingType.OBSERVED_RECREATION}:
        if any(item.status is DecisionStatus.APPLIES and item.required_action is PolicyAction.DELETE
               for item in decisions):
            return StepOperation.REPORT_REMAINING_RECORD
    return None


def _remediation_for_finding(operation: StepOperation,
                             decisions: tuple[PolicyDecision, ...]) -> StepOperation | None:
    if operation is StepOperation.REPORT_ACTIVE_DATA_FLOW:
        return StepOperation.DISABLE_DATA_FLOW
    if operation is StepOperation.REPORT_RESTORE_RISK:
        return StepOperation.BLOCK_RESTORE
    applicable = {item.required_action for item in decisions if item.status is DecisionStatus.APPLIES}
    if operation is StepOperation.REPORT_REMAINING_RECORD and applicable == {PolicyAction.DELETE}:
        return StepOperation.DELETE_RECORD
    if operation is StepOperation.REPORT_EXPOSED_PII and applicable == {PolicyAction.REDACT}:
        return StepOperation.REDACT_RECORD
    if operation is StepOperation.REPORT_EXPOSED_PII and applicable == {PolicyAction.ANONYMIZE}:
        return StepOperation.ANONYMIZE_RECORD
    return None


def _expected_treatment(action: PolicyAction, assessment: ResourceAssessment) -> tuple[ResourceState | None, StepOperation] | None:
    if action is PolicyAction.DELETE:
        return (ResourceState.ABSENT if assessment.state is ResourceState.ABSENT else
                ResourceState.DELETED if assessment.state is ResourceState.DELETED else None,
                StepOperation.VERIFY_RECORD_ABSENT)
    if action is PolicyAction.REDACT:
        if assessment.state in {ResourceState.REDACTED, ResourceState.ANONYMIZED, ResourceState.TOMBSTONED}:
            return assessment.state, StepOperation.VERIFY_RECORD_REDACTED
        return None, StepOperation.VERIFY_RECORD_REDACTED
    if action is PolicyAction.ANONYMIZE:
        return (ResourceState.ANONYMIZED if assessment.state is ResourceState.ANONYMIZED else None,
                StepOperation.VERIFY_RECORD_ANONYMIZED)
    if action is PolicyAction.RETAIN:
        return (assessment.state if assessment.state in {ResourceState.PRESENT, ResourceState.RETAINED} else None,
                StepOperation.VERIFY_RECORD_PRESENT)
    return None


def _make_drafts(adjudication: CaseAdjudication, case: CaseStateSnapshot,
                 policy_case: PolicyCaseResult | None, risk_case: RiskCaseResult | None,
                 ingestion: IngestionResult, extraction: EvidenceExtractionResult,
                 diagnostics: list[PlanDiagnostic]) -> tuple[dict[tuple[str, str, str, str], _DraftStep],
                                                             dict[tuple[str, str, str, str], _DraftStep],
                                                             tuple[PlanDependency, ...]]:
    steps: dict[tuple[str, str, str, str], _DraftStep] = {}
    remediation_steps: dict[tuple[str, str, str, str], _DraftStep] = {}
    remediation_resource_keys: dict[tuple[str, str, str, str], ResourceKey] = {}
    if adjudication.deletion_status is DeletionStatus.NOT_APPLICABLE:
        return steps, remediation_steps, ()
    if case.snapshot is None or adjudication.audit_at is None:
        diagnostics.append(PlanDiagnostic("case_state_snapshot_missing", "No cutoff state is available for planning."))
        return steps, remediation_steps, ()
    assessments = _assessment_index(case)
    decisions_by_key = _decision_index(policy_case)
    decisions = policy_case.decisions if policy_case else ()
    conflicting_policy_keys = {item.resource_key for item in policy_case.conflicts} if policy_case else set()
    for conflict in policy_case.conflicts if policy_case else ():
        diagnostics.append(PlanDiagnostic("conflicting_policy_obligations",
            "Conflicting applicable policy actions prevent a safe operation plan.",
            conflict.resource_key.resource_id))
    cutoff = adjudication.audit_at

    if adjudication.deletion_status is DeletionStatus.COMPLETE:
        for decision in decisions:
            if decision.resource_key in conflicting_policy_keys:
                continue
            if decision.status is DecisionStatus.DOES_NOT_APPLY:
                continue
            if decision.status is not DecisionStatus.APPLIES:
                diagnostics.append(PlanDiagnostic("policy_decision_unresolved",
                    "A complete-case verification cannot be planned for an unresolved policy decision.",
                    decision.resource_key.resource_id))
                continue
            assessment = assessments.get((decision.resource_key, StateDomain.LIFECYCLE))
            if assessment is None:
                diagnostics.append(PlanDiagnostic("verification_state_missing",
                    "No lifecycle state supports the required verification.", decision.resource_key.resource_id))
                continue
            target = _expected_treatment(decision.required_action, assessment)
            if target is None:
                diagnostics.append(PlanDiagnostic("unsupported_policy_action",
                    "No official verification operation maps to this obligation.", decision.resource_key.resource_id))
                continue
            expected_state, operation = target
            evidence_id = _evidence_for_assessment(assessment, expected_state, ingestion, extraction, cutoff)
            if not evidence_id:
                diagnostics.append(PlanDiagnostic("verification_evidence_missing_or_ineligible",
                    "No direct participant evidence proves this compliant state at audit_at.",
                    decision.resource_key.resource_id, operation.value))
                continue
            _append_step(steps, diagnostics, StepPhase.VERIFICATION, decision.resource_key,
                         operation, evidence_id)
        return steps, remediation_steps, ()

    if adjudication.deletion_status is not DeletionStatus.INCOMPLETE:
        diagnostics.append(PlanDiagnostic("deletion_status_unresolved", "No official status supports step planning."))
        return steps, remediation_steps, ()

    risk_findings = risk_case.findings if risk_case else ()
    finding_keys: set[tuple[ResourceKey, StepOperation]] = set()
    for finding in risk_findings:
        if finding.resource_key in conflicting_policy_keys:
            continue
        matched_decisions = decisions_by_key.get(finding.resource_key, ())
        operation = _finding_operation(finding, matched_decisions)
        if operation is None:
            if finding.finding_type in {RiskFindingType.CLAIMED_RECREATION_OPERATION}:
                continue
            diagnostics.append(PlanDiagnostic("finding_has_no_official_operation_mapping",
                "The evidence-backed risk does not map to a permitted finding operation and state.",
                finding.resource_key.resource_id))
            continue
        evidence_id = _risk_evidence_id(finding, ingestion, extraction, cutoff)
        if not evidence_id:
            diagnostics.append(PlanDiagnostic("finding_evidence_missing_or_ineligible",
                "No participant-visible file_id, activity_id, or audit_id is eligible for this finding.",
                finding.resource_key.resource_id, operation.value))
            continue
        added = _append_step(steps, diagnostics, StepPhase.FINDING, finding.resource_key,
                             operation, evidence_id)
        if added:
            finding_keys.add((finding.resource_key, operation))
        remediation = _remediation_for_finding(operation, matched_decisions)
        if remediation is None:
            diagnostics.append(PlanDiagnostic("finding_has_no_policy_safe_remediation",
                "No permitted remediation is justified by a unique applicable policy action.",
                finding.resource_key.resource_id, operation.value))
            continue
        rem = _append_step(remediation_steps, diagnostics, StepPhase.REMEDIATION,
                           finding.resource_key, remediation)
        if rem is not None:
            remediation_resource_keys[rem.key] = finding.resource_key

    # Direct DELETE obligations with a cutoff snapshot that still says present
    # can be planned from that evidence even if a duplicate high-level risk was
    # coalesced upstream. Redaction/anonymization require Phase 8's direct PII
    # conflict finding; mere record presence is not enough to report exposed PII.
    for decision in decisions:
        if decision.resource_key in conflicting_policy_keys:
            continue
        if decision.status is DecisionStatus.DOES_NOT_APPLY:
            continue
        if decision.status is not DecisionStatus.APPLIES:
            diagnostics.append(PlanDiagnostic("policy_obligation_unresolved",
                "A conflicting or unresolved policy obligation prevents a complete remediation plan.",
                decision.resource_key.resource_id))
            continue
        assessment = assessments.get((decision.resource_key, StateDomain.LIFECYCLE))
        if assessment is None or assessment.state in {ResourceState.UNKNOWN, ResourceState.CONFLICTING}:
            diagnostics.append(PlanDiagnostic("policy_state_unresolved",
                "The policy resource state is unknown or conflicting.", decision.resource_key.resource_id))
            continue
        action = decision.required_action
        if action is PolicyAction.RETAIN:
            if assessment.state not in {ResourceState.PRESENT, ResourceState.RETAINED}:
                diagnostics.append(PlanDiagnostic("retained_record_missing_operation",
                    "The participant contract has no operation that recreates a missing retained record.",
                    decision.resource_key.resource_id))
            continue
        treatment = _operation_for_action(action)
        if treatment is None:
            diagnostics.append(PlanDiagnostic("unsupported_policy_action",
                "No allowed remediation mapping exists for the applicable action.", decision.resource_key.resource_id))
            continue
        remed_operation, remed_state, verify_operation = treatment
        if action is PolicyAction.DELETE and assessment.state not in {ResourceState.ABSENT, ResourceState.DELETED}:
            evidence_id = _state_evidence_source(assessment, assessment.state, extraction, cutoff, ingestion)
            if not evidence_id:
                diagnostics.append(PlanDiagnostic("remaining_record_evidence_missing_or_ineligible",
                    "Direct cutoff evidence does not support a remaining-record finding.", decision.resource_key.resource_id))
                continue
            find_operation = StepOperation.REPORT_REMAINING_RECORD
            if (decision.resource_key, find_operation) not in finding_keys:
                _append_step(steps, diagnostics, StepPhase.FINDING, decision.resource_key,
                             find_operation, evidence_id)
                finding_keys.add((decision.resource_key, find_operation))
            rem = _append_step(remediation_steps, diagnostics, StepPhase.REMEDIATION,
                               decision.resource_key, remed_operation)
            if rem is not None:
                remediation_resource_keys[rem.key] = decision.resource_key
        elif action in {PolicyAction.REDACT, PolicyAction.ANONYMIZE}:
            state_conflict = next((finding for finding in risk_findings
                if finding.finding_type is RiskFindingType.POLICY_STATE_CONFLICT
                and finding.resource_key == decision.resource_key and finding.policy_action is action), None)
            if state_conflict:
                operation = StepOperation.REPORT_EXPOSED_PII
                evidence_id = _risk_evidence_id(state_conflict, ingestion, extraction, cutoff)
                if not evidence_id:
                    diagnostics.append(PlanDiagnostic("exposed_identifier_evidence_missing_or_ineligible",
                        "No eligible evidence reference proves the identifying-data violation.",
                        decision.resource_key.resource_id))
                    continue
                if (decision.resource_key, operation) not in finding_keys:
                    _append_step(steps, diagnostics, StepPhase.FINDING, decision.resource_key, operation, evidence_id)
                    finding_keys.add((decision.resource_key, operation))
                rem = _append_step(remediation_steps, diagnostics, StepPhase.REMEDIATION,
                                   decision.resource_key, remed_operation)
                if rem is not None:
                    remediation_resource_keys[rem.key] = decision.resource_key

    # A confirmed INCOMPLETE decision must have a reportable finding and a
    # permitted remediation. We do not manufacture a finding for unknown state.
    if not any(step.phase is StepPhase.FINDING for step in steps.values()):
        diagnostics.append(PlanDiagnostic("incomplete_case_has_no_serializable_finding",
            "No participant-supported violation maps to an allowed finding step."))
    if not remediation_steps:
        diagnostics.append(PlanDiagnostic("incomplete_case_has_no_serializable_remediation",
            "No complete remediation plan maps to the official operation set."))

    for remediation in tuple(remediation_steps.values()):
        verify = _REMEDIATION_TO_VERIFICATION[remediation.operation]
        resource_key = remediation_resource_keys.get(remediation.key)
        if resource_key is None:
            diagnostics.append(PlanDiagnostic("verification_resource_scope_missing",
                "The planned remediation lost its resource identity before verification planning.",
                remediation.resource_id, verify.value))
            continue
        _append_step(steps, diagnostics, StepPhase.VERIFICATION, resource_key, verify)

    # Required retained records remain in place while other work is performed.
    for decision in decisions:
        if decision.status is not DecisionStatus.APPLIES or decision.required_action is not PolicyAction.RETAIN:
            continue
        if decision.resource_key in conflicting_policy_keys:
            continue
        assessment = assessments.get((decision.resource_key, StateDomain.LIFECYCLE))
        if assessment is None or assessment.state not in {ResourceState.PRESENT, ResourceState.RETAINED}:
            continue
        _append_step(steps, diagnostics, StepPhase.VERIFICATION, decision.resource_key,
                     StepOperation.VERIFY_RECORD_PRESENT)

    dependencies = _build_dependencies(remediation_steps, case.snapshot.assessments, diagnostics)
    steps.update(remediation_steps)
    return steps, remediation_steps, dependencies


def _reference_tables(ingestion: IngestionResult) -> tuple[set[str], set[str]]:
    activity = {row.raw("activity_id") or "" for row in
                ingestion.bundle.tables.get("system_activity", ()).records} if "system_activity" in ingestion.bundle.tables else set()
    audits = {row.raw("audit_id") or "" for row in
              ingestion.bundle.tables.get("user_audit_log", ()).records} if "user_audit_log" in ingestion.bundle.tables else set()
    return activity, audits


def _validate_steps(steps: tuple[PlannedStep, ...], status: DeletionStatus,
                    cutoff: datetime, ingestion: IngestionResult,
                    extraction: EvidenceExtractionResult) -> tuple[PlanValidationIssue, ...]:
    issues: list[PlanValidationIssue] = []
    activity_ids, audit_ids = _reference_tables(ingestion)
    file_ids = set(extraction.by_file_id)
    phase_rank = {value.value: index for index, value in enumerate(StepPhase)}
    operation_rank = {(phase.value, operation.value): index
        for phase, operations in _OPERATION_ORDER.items() for index, operation in enumerate(operations)}
    expected_fields = ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id")
    expected_order: list[tuple[int, int, str, str]] = []
    verifications: set[tuple[str, str, str]] = set()
    remediations: list[PlannedStep] = []
    seen_numbers: set[int] = set()
    for step in steps:
        if tuple(step.as_dict()) != expected_fields:
            issues.append(PlanValidationIssue("step_schema_invalid", "Step does not contain exactly the official seven fields.", step.step_no))
        string_fields = (step.phase, step.system_id, step.resource_id, step.operation, step.state, step.evidence_id)
        if any(not isinstance(value, str) for value in string_fields):
            issues.append(PlanValidationIssue("step_field_type_invalid",
                "All step fields except step_no must serialize as strings.", step.step_no))
        if isinstance(step.step_no, bool) or not isinstance(step.step_no, int) or step.step_no < 1:
            issues.append(PlanValidationIssue("step_number_invalid", "step_no must be a positive integer.", step.step_no))
        elif step.step_no in seen_numbers:
            issues.append(PlanValidationIssue("step_number_duplicate", "step_no must be unique.", step.step_no))
        seen_numbers.add(step.step_no)
        try:
            phase, operation = StepPhase(step.phase), StepOperation(step.operation)
        except (TypeError, ValueError):
            issues.append(PlanValidationIssue("step_phase_or_operation_invalid", "Phase or operation is not in the official contract.", step.step_no))
            continue
        expected_state = _ALLOWED_STATES.get((phase, operation))
        if expected_state != step.state:
            issues.append(PlanValidationIssue("phase_operation_state_invalid", "Phase, operation, and state must be an official triple.", step.step_no))
        if not step.system_id or not step.resource_id:
            issues.append(PlanValidationIssue("step_resource_scope_missing", "system_id and resource_id must be non-empty strings.", step.step_no))
        if status is DeletionStatus.NOT_APPLICABLE and steps:
            issues.append(PlanValidationIssue("not_applicable_has_steps", "NOT_APPLICABLE requires an empty steps array.", step.step_no))
        if status is DeletionStatus.COMPLETE and phase is not StepPhase.VERIFICATION:
            issues.append(PlanValidationIssue("complete_has_nonverification", "COMPLETE may contain only current verification steps.", step.step_no))
        if status is DeletionStatus.INCOMPLETE and phase in {StepPhase.REMEDIATION, StepPhase.VERIFICATION} \
                and step.evidence_id != "":
            issues.append(PlanValidationIssue("future_step_has_evidence", "Proposed remediation and future verification use an empty evidence_id.", step.step_no))
        if phase is StepPhase.FINDING or status is DeletionStatus.COMPLETE:
            if not step.evidence_id:
                issues.append(PlanValidationIssue("current_step_evidence_missing", "Findings and COMPLETE checks require an evidence reference.", step.step_no))
            elif step.evidence_id in file_ids:
                _eligible_reference(step.evidence_id, "evidence", None, cutoff, ingestion, extraction,
                                    issues, step.step_no)
            elif step.evidence_id in activity_ids:
                _eligible_reference(step.evidence_id, "activity", None, cutoff, ingestion, extraction,
                                    issues, step.step_no)
            elif step.evidence_id in audit_ids:
                _eligible_reference(step.evidence_id, "audit", None, cutoff, ingestion, extraction,
                                    issues, step.step_no)
            else:
                issues.append(PlanValidationIssue("evidence_reference_unknown", "Evidence ID does not resolve to a participant-visible file_id, activity_id, or audit_id.", step.step_no))
        if phase is StepPhase.REMEDIATION:
            remediations.append(step)
        elif phase is StepPhase.VERIFICATION:
            verifications.add((step.system_id, step.resource_id, step.operation))
        if phase.value in phase_rank and (phase.value, operation.value) in operation_rank:
            expected_order.append((phase_rank[phase.value], operation_rank[(phase.value, operation.value)],
                                   step.system_id, step.resource_id))
    if [step.step_no for step in steps] != list(range(1, len(steps) + 1)):
        issues.append(PlanValidationIssue("step_numbers_not_consecutive", "Steps must be numbered consecutively from 1."))
    if expected_order != sorted(expected_order):
        issues.append(PlanValidationIssue("step_order_invalid", "Steps must follow official phase, operation, system, and resource order."))
    if status is DeletionStatus.INCOMPLETE:
        present_phases = {step.phase for step in steps}
        if not {StepPhase.FINDING.value, StepPhase.REMEDIATION.value, StepPhase.VERIFICATION.value}.issubset(present_phases):
            issues.append(PlanValidationIssue("incomplete_phase_coverage_missing", "INCOMPLETE requires findings, remediation, and future verification phases."))
        for remediation in remediations:
            verify_op = _REMEDIATION_TO_VERIFICATION.get(StepOperation(remediation.operation))
            if verify_op and (remediation.system_id, remediation.resource_id, verify_op.value) not in verifications:
                issues.append(PlanValidationIssue("remediation_verification_missing", "Every remediation needs a matching verification check.", remediation.step_no))
    return tuple(issues)


def _eligible_reference(reference_id: str, kind: str, reference: object | None, cutoff: datetime,
                        ingestion: IngestionResult, extraction: EvidenceExtractionResult,
                        issues: list[PlanValidationIssue], step_no: int) -> bool:
    if kind == "evidence":
        file = extraction.by_file_id.get(reference_id)
        if file is None or file.captured_at is None or file.captured_at.status is not TimestampStatus.VALID \
                or file.captured_at.value is None or file.captured_at.value > cutoff:
            issues.append(PlanValidationIssue("evidence_reference_temporally_ineligible",
                "Evidence capture time is missing, invalid, or after audit_at.", step_no))
            return False
        return True
    table_name, column = ("system_activity", "activity_id") if kind == "activity" else ("user_audit_log", "audit_id")
    time_column = "event_time"
    table = ingestion.bundle.tables.get(table_name)
    row = next((item for item in table.records if item.raw(column) == reference_id), None) if table else None
    time = row.typed(time_column) if row else None
    if not isinstance(time, ParsedTimestamp) or time.status is not TimestampStatus.VALID \
            or time.value is None or time.value > cutoff:
        issues.append(PlanValidationIssue("event_reference_temporally_ineligible",
            "Activity/audit reference is missing, invalid, or after audit_at.", step_no))
        return False
    return True


def validate_plan(plan: CasePlan, ingestion: IngestionResult,
                  extraction: EvidenceExtractionResult) -> tuple[PlanValidationIssue, ...]:
    """Validate contract schema/order/references; this does not write output."""
    if plan.deletion_status is None:
        return (PlanValidationIssue("unresolved_plan_has_no_serializable_status",
                                    "An unresolved case cannot be serialized with an official status."),)
    if plan.audit_at is None:
        return (PlanValidationIssue("plan_audit_cutoff_missing", "Plan has no audit_at cutoff."),)
    return _validate_steps(plan.steps, plan.deletion_status, plan.audit_at, ingestion, extraction)


def plan_remediation_steps(adjudications: Iterable[CaseAdjudication],
                           case_states: Iterable[CaseStateSnapshot],
                           policy: PolicyEvaluation, risks: RiskAnalysis,
                           ingestion: IngestionResult,
                           extraction: EvidenceExtractionResult) -> PlanningReport:
    """Generate contract-shaped proposals and validate dependency feasibility.

    No operation is described as completed: REMEDIATION and INCOMPLETE
    VERIFICATION steps are future proposals with empty evidence references.
    """
    state_by_id = {item.case_id: item for item in case_states}
    policy_by_id = {item.case_id: item for item in policy.cases}
    risk_by_id = {item.case_id: item for item in risks.cases}
    plans: list[CasePlan] = []
    for adjudication in sorted(adjudications, key=lambda item: item.case_id):
        diagnostics: list[PlanDiagnostic] = []
        case = state_by_id.get(adjudication.case_id)
        policy_case = policy_by_id.get(adjudication.case_id)
        risk_case = risk_by_id.get(adjudication.case_id)
        if adjudication.resolution is DecisionResolution.UNRESOLVED or adjudication.deletion_status is None:
            plans.append(CasePlan(adjudication.case_id, adjudication.audit_at, None,
                PlanResolution.UNRESOLVED, False, (), (), (PlanDiagnostic(
                    "adjudication_unresolved", "Phase 9 did not establish an authorized official status."),)))
            continue
        if adjudication.deletion_status is DeletionStatus.NOT_APPLICABLE:
            plan = CasePlan(adjudication.case_id, adjudication.audit_at, adjudication.deletion_status,
                PlanResolution.READY, True, (), (), ())
            issues = validate_plan(plan, ingestion, extraction)
            plans.append(replace(plan, resolution=PlanResolution.UNRESOLVED if issues else PlanResolution.READY,
                                 serialization_ready=not issues,
                                 diagnostics=tuple(PlanDiagnostic(issue.code, issue.message, operation=issue.code)
                                                   for issue in issues)))
            continue
        if case is None:
            diagnostics.append(PlanDiagnostic("case_state_missing", "No Phase 6 case snapshot is available."))
            plans.append(CasePlan(adjudication.case_id, adjudication.audit_at, adjudication.deletion_status,
                PlanResolution.UNRESOLVED, False, (), (), tuple(diagnostics)))
            continue
        if adjudication.unresolved_reasons:
            diagnostics.append(PlanDiagnostic("adjudication_has_unresolved_gates",
                "A complete remediation plan cannot be certified while Phase 9 evidence gates remain unresolved."))
        steps, remediation_steps, draft_edges = _make_drafts(adjudication, case, policy_case,
            risk_case, ingestion, extraction, diagnostics)
        ordered_drafts = sorted(steps.values(), key=_step_sort_key)
        step_numbers = {step.key: index + 1 for index, step in enumerate(ordered_drafts)}
        deps = tuple(PlanDependency(step_numbers[edge.before], step_numbers[edge.after], edge.reason)
                     for edge in draft_edges if edge.before in step_numbers and edge.after in step_numbers)
        for edge in deps:
            if edge.before_step_no >= edge.after_step_no:
                diagnostics.append(PlanDiagnostic("dependency_order_conflict",
                    f"Required order ({edge.reason}) conflicts with the official serialized step ordering."))
        built_steps = tuple(PlannedStep(index + 1, step.phase.value, step.system_id,
            step.resource_id, step.operation.value, step.state, step.evidence_id)
            for index, step in enumerate(ordered_drafts))
        provisional = CasePlan(adjudication.case_id, adjudication.audit_at, adjudication.deletion_status,
            PlanResolution.UNRESOLVED, False, built_steps, deps, tuple(diagnostics))
        validation = validate_plan(provisional, ingestion, extraction)
        diagnostics.extend(PlanDiagnostic(item.code, item.message) for item in validation)
        ready = not diagnostics and not validation and not adjudication.unresolved_reasons
        plans.append(CasePlan(adjudication.case_id, adjudication.audit_at, adjudication.deletion_status,
            PlanResolution.READY if ready else PlanResolution.UNRESOLVED, ready, built_steps, deps,
            tuple(sorted({(item.code, item.message, item.resource_id, item.operation): item
                          for item in diagnostics}.values(), key=lambda item: (item.code, item.resource_id or "", item.message)))))
    return PlanningReport(tuple(plans))


__all__ = [
    "CasePlan", "PlanDependency", "PlanDiagnostic", "PlanResolution", "PlanValidationIssue",
    "PlannedStep", "PlanningReport", "StepOperation", "StepPhase",
    "plan_remediation_steps", "validate_plan",
]
