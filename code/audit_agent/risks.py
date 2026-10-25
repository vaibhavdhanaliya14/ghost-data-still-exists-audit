"""Evidence-backed recreation and residual-risk analysis (Phase 8).

This layer reports observations and risk candidates. It does not decide final
deletion status or create remediation steps. A workflow/activity claim never
becomes an observed effect without a direct, scoped state observation.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Mapping

from .extract import EvidenceExtractionResult, ExtractedObservation
from .identity import IdentityGraph, IdentityResolutionResult, ResolutionStatus
from .models import TimestampStatus
from .policy import ConditionStatus, DecisionStatus, PolicyAction, PolicyCaseResult, PolicyDecision, PolicyEvaluation
from .state import CaseStateSnapshot, ResourceAssessment, ResourceKey, ResourceState, StateDomain, StateEvidence
from .timeline import EventCategory, Timeline, TimelineConflict, TimelineEvent, TimelineSource


_EMAIL_IN_TEXT = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)


class RiskFindingType(str, Enum):
    OBSERVED_RECREATION = "observed_recreation"
    RESOURCE_PRESENT_AFTER_DELETE = "resource_present_after_delete"
    POSSIBLE_DATA_FLOW_RECREATION = "possible_data_flow_recreation"
    POSSIBLE_RESTORE = "possible_restore"
    CLAIMED_RECREATION_OPERATION = "claimed_recreation_operation"
    POLICY_STATE_CONFLICT = "policy_state_conflict"


class RiskConfidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class RiskEvidenceStatus(str, Enum):
    DIRECT_STATE = "direct_state"
    DIRECT_CONTROL = "direct_control"
    CLAIM_ONLY = "claim_only"
    CONFLICTING = "conflicting"
    INSUFFICIENT = "insufficient"


@dataclass(frozen=True)
class RiskEvidenceReference:
    source_kind: str
    source_id: str
    source_path: str
    file_id: str | None = None
    record_id: str | None = None
    observation_id: str | None = None
    locator: str | None = None
    role: str | None = None
    event_time: datetime | None = None
    capture_time: datetime | None = None
    reason: str | None = None


@dataclass(frozen=True)
class RiskFinding:
    finding_id: str
    case_id: str
    user_id: str
    resource_key: ResourceKey
    finding_type: RiskFindingType
    confidence: RiskConfidence
    evidence_status: RiskEvidenceStatus
    mechanism: EventCategory | None
    event_time: datetime | None
    state_at_cutoff: ResourceState | None
    policy_rule_id: str | None
    policy_action: PolicyAction | None
    evidence: tuple[RiskEvidenceReference, ...]
    uncertainty: tuple[str, ...] = ()


@dataclass(frozen=True)
class RiskUncertainty:
    code: str
    message: str
    resource_key: ResourceKey | None = None
    evidence: tuple[RiskEvidenceReference, ...] = ()


@dataclass(frozen=True)
class RiskCaseResult:
    case_id: str
    user_id: str | None
    audit_at: datetime | None
    findings: tuple[RiskFinding, ...]
    conflicts: tuple[TimelineConflict, ...]
    # Only failed files explicitly linked to this case by eligible evidence.
    extraction_gap_file_ids: tuple[str, ...]
    unresolved_identity_evidence: tuple[RiskEvidenceReference, ...]
    temporal_exclusions: tuple[RiskEvidenceReference, ...]
    uncertainties: tuple[RiskUncertainty, ...]


@dataclass(frozen=True)
class RiskAnalysis:
    cases: tuple[RiskCaseResult, ...]
    # Global extraction diagnostics are preserved separately and do not make
    # every case unresolved merely because some unrelated file failed.
    global_extraction_gap_file_ids: tuple[str, ...] = ()

    @property
    def findings(self) -> tuple[RiskFinding, ...]:
        return tuple(item for case in self.cases for item in case.findings)

    @property
    def unresolved_case_ids(self) -> tuple[str, ...]:
        return tuple(case.case_id for case in self.cases if
                     case.user_id is None or case.conflicts or case.extraction_gap_file_ids or
                     case.unresolved_identity_evidence or case.uncertainties)


_DIRECT_PRESENT_STATES = frozenset({
    ResourceState.PRESENT, ResourceState.REDACTED, ResourceState.ANONYMIZED,
    ResourceState.RETAINED, ResourceState.TOMBSTONED,
})
_RECREATION_CATEGORIES = frozenset({
    EventCategory.CREATION, EventCategory.RESTORATION, EventCategory.REPLICATION,
    EventCategory.SYNCHRONIZATION, EventCategory.IMPORT,
})
_COLLECTION_CATEGORY = {
    "connector_configurations": "DATA_FLOW",
    "backup_catalog": "BACKUP_ARCHIVE",
    "customer_profiles": "USER_PROFILE",
    "customer_search_documents": "SEARCH_INDEX_ENTRY",
    "customer_analytics_reports": "ANALYTICS_PROFILE",
    "security_audit_events": "SECURITY_AUDIT_LOG",
    "support_conversations": "SUPPORT_MESSAGE",
    "ticket_attachments": "SUPPORT_ATTACHMENT",
    "customer_export_jobs": "USER_EXPORT",
    "deleted_customer_references": "ACCOUNT_TOMBSTONE",
}


def _category(observation: ExtractedObservation, observations: Mapping[str, ExtractedObservation]) -> str | None:
    fields = observation.normalized_fields
    for name in ("data_category", "record_type", "resource_type", "category"):
        value = fields.get(name)
        if value is not None and str(value).strip():
            return str(value).strip().upper()
    collection = fields.get("collection_name")
    if collection is None and observation.parent_observation_id:
        parent = observations.get(observation.parent_observation_id)
        collection = parent.normalized_fields.get("collection_name") if parent else None
    return _COLLECTION_CATEGORY.get(str(collection).strip().casefold()) if collection is not None else None


def _event_key(event: TimelineEvent) -> ResourceKey | None:
    if not event.subject.user_id or not event.resource_id:
        return None
    resource_type = next((str(event.raw_fields[key]).strip() for key in
                          ("resource_type", "record_type", "data_category", "category", "table_name", "collection_name")
                          if event.raw_fields.get(key) is not None and str(event.raw_fields[key]).strip()), None)
    discriminator = "" if event.system_ids else (
        f"{event.source.file_id or event.source.source_file}:"
        f"{event.source.observation_id or event.source.locator or event.source.record_id or event.event_id}"
    )
    return ResourceKey(event.subject.user_id, event.system_ids, event.resource_id,
                       resource_type, discriminator)


def _event_ref(event: TimelineEvent, reason: str | None = None) -> RiskEvidenceReference:
    event_time = event.event_time.value
    capture = event.capture_time.value if event.capture_time and event.capture_time.status is TimestampStatus.VALID else None
    return RiskEvidenceReference(event.source.source_kind,
        event.source.file_id or event.source.record_id or event.event_id,
        event.source.source_file, event.source.file_id, event.source.record_id,
        event.source.observation_id, event.source.locator, event.role,
        event_time, capture, reason)


def _state_ref(evidence: StateEvidence, reason: str | None = None) -> RiskEvidenceReference:
    event_time = evidence.event_time.value if evidence.event_time and evidence.event_time.status is TimestampStatus.VALID else None
    capture = evidence.capture_time.value if evidence.capture_time and evidence.capture_time.status is TimestampStatus.VALID else None
    return RiskEvidenceReference(evidence.source.source_kind,
        evidence.source.file_id or evidence.source.record_id or evidence.evidence_key,
        evidence.source.source_file, evidence.source.file_id, evidence.source.record_id,
        evidence.source.observation_id, evidence.source.locator, evidence.role,
        event_time, capture, reason)


def _obs_ref(observation: ExtractedObservation, reason: str | None = None) -> RiskEvidenceReference:
    capture = observation.captured_at.value if observation.captured_at and observation.captured_at.status is TimestampStatus.VALID else None
    return RiskEvidenceReference("evidence", observation.file_id, observation.source_path,
        observation.file_id, observation.observation_id, observation.observation_id,
        observation.locator, "observation", None, capture, reason)


def _policy_ref(reference: Any, role: str) -> RiskEvidenceReference:
    """Translate Phase 7 provenance without assuming its source ID is a file ID."""
    is_file = reference.source_kind == "evidence"
    locator = reference.locator
    if reference.record_number is not None:
        locator = locator or f"record:{reference.record_number}"
    return RiskEvidenceReference(reference.source_kind, reference.source_id,
        reference.source_file, file_id=reference.source_id if is_file else None,
        record_id=(f"record:{reference.record_number}" if reference.record_number is not None else None),
        observation_id=reference.observation_id, locator=locator, role=role)


def _event_temporal_reason(event: TimelineEvent, cutoff: datetime) -> str | None:
    if event.event_time.status is not TimestampStatus.VALID or event.event_time.value is None:
        return "event_time_missing_or_invalid"
    if event.event_time.value > cutoff:
        return "event_time_after_audit_at"
    if event.capture_time_required:
        captured = event.capture_time
        if captured is None or captured.status is not TimestampStatus.VALID or captured.value is None:
            return "capture_time_missing_or_invalid"
        if captured.value > cutoff:
            return "capture_time_after_audit_at"
    return None


def _system_scoped_match(event: TimelineEvent, key: ResourceKey) -> bool:
    return bool(event.resource_id == key.resource_id and event.system_ids and key.system_ids
                and set(event.system_ids).intersection(key.system_ids))


def _identity_match(graph: IdentityGraph, kind: str, value: str, user_id: str,
                    cutoff: datetime) -> tuple[str, tuple[str, ...]]:
    normalized = value.strip().casefold() if kind == "email" else value.strip()
    if not normalized:
        return "unknown", ()
    candidates = [item for item in graph.alias_index.get((kind, normalized), ())
                 if item.valid_from is None or item.valid_from <= cutoff]
    current = [item for item in candidates if item.contains(cutoff)]
    if current:
        candidates = current
    owners = tuple(sorted({item.user_id for item in candidates}))
    if len(owners) > 1:
        return "ambiguous", owners
    if not owners:
        return "unknown", ()
    return ("match", owners) if owners[0] == user_id else ("other", owners)


def _selector_match(value: object, user_id: str, identities: IdentityResolutionResult,
                    cutoff: datetime) -> tuple[str, tuple[str, ...]]:
    if not isinstance(value, (str, int)):
        return "unknown", ()
    raw = str(value).strip()
    if not raw:
        return "unknown", ()
    if raw == user_id:
        return "match", (user_id,)
    match = re.fullmatch(r"(user_id|email|email_hash|phone)\s*[:=]\s*(.+)", raw, flags=re.I)
    if match:
        kind = match.group(1).casefold()
        selector_value = match.group(2).strip().strip("\"'")
        if kind == "user_id":
            return ("match", (user_id,)) if selector_value == user_id else ("other", ())
        return _identity_match(identities.graph, kind, selector_value, user_id, cutoff)
    outcomes = []
    for kind in ("email", "email_hash", "phone"):
        status, owners = _identity_match(identities.graph, kind, raw, user_id, cutoff)
        if status != "unknown":
            outcomes.append((status, owners))
    owners = tuple(sorted({owner for _, values in outcomes for owner in values}))
    statuses = {status for status, _ in outcomes}
    if "ambiguous" in statuses or len(owners) > 1 or ("match" in statuses and "other" in statuses):
        return "ambiguous", owners
    if "match" in statuses:
        return "match", (user_id,)
    if "other" in statuses:
        return "other", owners
    return "unknown", ()


def _mode_category(fields: Mapping[str, Any]) -> EventCategory | None:
    text = " ".join(str(fields.get(name, "")) for name in
                    ("mode", "flow_type", "operation", "event_type")).casefold()
    if "replic" in text:
        return EventCategory.REPLICATION
    if "import" in text or "reimport" in text:
        return EventCategory.IMPORT
    if "sync" in text:
        return EventCategory.SYNCHRONIZATION
    return None


def _finding_id(case_id: str, key: ResourceKey, kind: RiskFindingType,
                refs: Iterable[RiskEvidenceReference]) -> str:
    source_ids = sorted({f"{ref.source_kind}:{ref.source_id}:{ref.locator or ''}" for ref in refs})
    raw = "\x1f".join((case_id, key.user_id, ",".join(key.system_ids), key.resource_id,
                       key.resource_type or "", key.scope_discriminator, kind.value, *source_ids))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


def _make_finding(case: CaseStateSnapshot, key: ResourceKey, kind: RiskFindingType,
                  confidence: RiskConfidence, evidence_status: RiskEvidenceStatus,
                  refs: Iterable[RiskEvidenceReference], *, mechanism: EventCategory | None = None,
                  event_time: datetime | None = None, state: ResourceState | None = None,
                  policy: PolicyDecision | None = None, uncertainty: Iterable[str] = ()) -> RiskFinding:
    ordered_refs = tuple(sorted(set(refs), key=lambda ref: (
        ref.source_kind, ref.source_id, ref.locator or "", ref.event_time or datetime.max.replace(tzinfo=timezone.utc))))
    return RiskFinding(_finding_id(case.case_id, key, kind, ordered_refs), case.case_id,
        key.user_id, key, kind, confidence, evidence_status, mechanism, event_time, state,
        policy.rule.rule_id if policy else None, policy.required_action if policy else None,
        ordered_refs, tuple(sorted(set(uncertainty))))


def _subject_linked_direct_state(evidence: StateEvidence) -> bool:
    return evidence.state is not None and evidence.source.source_kind == "evidence" \
        and evidence.role == "observation"


def _event_evidence_for_resource(
    case: CaseStateSnapshot,
    timeline: Timeline,
    assessment: ResourceAssessment,
    observations: Mapping[str, ExtractedObservation],
    cutoff: datetime,
) -> list[RiskFinding]:
    findings: list[RiskFinding] = []
    evidence_by_observation: dict[str, list[StateEvidence]] = {}
    for item in assessment.evidence:
        if item.source.observation_id:
            evidence_by_observation.setdefault(item.source.observation_id, []).append(item)

    deletion_evidence = [item for item in assessment.evidence if
        item.state is ResourceState.DELETED and item.state_observed_at is not None
        and item.state_observed_at <= cutoff and _subject_linked_direct_state(item)]
    for deletion in deletion_evidence:
        for later in assessment.evidence:
            if (later.state is ResourceState.PRESENT and later.state_observed_at is not None
                    and later.state_observed_at <= cutoff and deletion.event_time is not None
                    and deletion.event_time.status is TimestampStatus.VALID and deletion.event_time.value is not None
                    and later.state_observed_at > deletion.event_time.value
                    and assessment.state is ResourceState.PRESENT
                    and _subject_linked_direct_state(later)):
                refs = (_state_ref(deletion), _state_ref(later))
                findings.append(_make_finding(case, assessment.key,
                    RiskFindingType.RESOURCE_PRESENT_AFTER_DELETE, RiskConfidence.HIGH,
                    RiskEvidenceStatus.DIRECT_STATE, refs, event_time=deletion.event_time.value,
                    state=assessment.state))

    direct_observation_ids = {item.source.observation_id for item in assessment.evidence
                              if _subject_linked_direct_state(item)}
    for event in timeline.eligible_at(cutoff):
        if (event.subject.status != ResolutionStatus.CONFIRMED.value
                or event.subject.user_id != case.user_id
                or event.category not in _RECREATION_CATEGORIES
                or not event.resource_id):
            continue
        key = _event_key(event)
        if key != assessment.key or event.role != "observation" \
                or event.source.file_format not in {"sql", "json"}:
            continue
        observation_id = event.source.observation_id
        if observation_id not in direct_observation_ids:
            continue
        state_evidence = [item for item in evidence_by_observation.get(observation_id or "", ())
                          if item.state in _DIRECT_PRESENT_STATES and item.state_observed_at is not None
                          and event.event_time.value is not None and item.state_observed_at >= event.event_time.value]
        if not state_evidence:
            continue
        refs = (_event_ref(event), *(_state_ref(item) for item in state_evidence))
        findings.append(_make_finding(case, assessment.key, RiskFindingType.OBSERVED_RECREATION,
            RiskConfidence.HIGH, RiskEvidenceStatus.DIRECT_STATE, refs,
            mechanism=event.category, event_time=event.event_time.value,
            state=state_evidence[-1].state))
    return findings


def _active_control_findings(case: CaseStateSnapshot, assessment: ResourceAssessment,
                             observations: Mapping[str, ExtractedObservation],
                             identities: IdentityResolutionResult) -> tuple[list[RiskFinding], list[RiskUncertainty]]:
    findings: list[RiskFinding] = []
    uncertainties: list[RiskUncertainty] = []
    if assessment.domain is not StateDomain.CONTROL or assessment.state is not ResourceState.ACTIVE:
        return findings, uncertainties
    latest_time = assessment.last_observed_at
    eligible_state_evidence = [item for item in assessment.evidence
        if item.state is ResourceState.ACTIVE and item.state_observed_at == latest_time
        and _subject_linked_direct_state(item)]
    for state_evidence in eligible_state_evidence:
        observation = observations.get(state_evidence.source.observation_id or "")
        if observation is None:
            continue
        fields = observation.normalized_fields
        category = _category(observation, observations)
        if category == "BACKUP_ARCHIVE":
            restore_allowed = fields.get("restore_allowed")
            if restore_allowed is True or (not isinstance(restore_allowed, str) and restore_allowed == 1):
                findings.append(_make_finding(case, assessment.key, RiskFindingType.POSSIBLE_RESTORE,
                    RiskConfidence.MEDIUM, RiskEvidenceStatus.DIRECT_CONTROL, (_state_ref(state_evidence),),
                    mechanism=EventCategory.RESTORATION, state=ResourceState.ACTIVE))
            continue
        if category != "DATA_FLOW":
            continue
        selectors = fields.get("subject_selector")
        if selectors is None:
            uncertainties.append(RiskUncertainty("flow_selector_missing",
                "Direct active flow state has no extracted subject_selector.", assessment.key,
                (_state_ref(state_evidence, "subject_selector_missing"),)))
            continue
        selector_values = selectors if isinstance(selectors, (list, tuple)) else (selectors,)
        outcomes = [_selector_match(value, case.user_id or "", identities, assessment.audit_at)
                    for value in selector_values]
        if any(status == "match" for status, _ in outcomes):
            mechanism = _mode_category(fields)
            findings.append(_make_finding(case, assessment.key, RiskFindingType.POSSIBLE_DATA_FLOW_RECREATION,
                RiskConfidence.MEDIUM, RiskEvidenceStatus.DIRECT_CONTROL, (_state_ref(state_evidence),),
                mechanism=mechanism, state=ResourceState.ACTIVE))
        elif any(status in {"ambiguous", "unknown"} for status, _ in outcomes):
            uncertainties.append(RiskUncertainty("flow_selector_identity_unresolved",
                "Active flow selector cannot be uniquely linked to the confirmed subject.", assessment.key,
                (_state_ref(state_evidence, "selector_identity_unresolved"),)))
    return findings, uncertainties


def _direct_identifier_conflict(assessment: ResourceAssessment, decision: PolicyDecision,
                                 observations: Mapping[str, ExtractedObservation],
                                 identities: IdentityResolutionResult, cutoff: datetime) -> tuple[StateEvidence, ...]:
    matches = []
    tombstone = decision.data_category == "ACCOUNT_TOMBSTONE"
    for evidence in assessment.evidence:
        if evidence.state_observed_at != assessment.last_observed_at or not _subject_linked_direct_state(evidence):
            continue
        observation = observations.get(evidence.source.observation_id or "")
        if observation is None:
            continue
        fields = observation.normalized_fields
        evidence_time = evidence.state_observed_at or cutoff
        for name in ("email", "customer_email", "owner_email", "requester_email", "phone",
                     "customer_phone", "owner_phone", "email_hash", "name", "full_name"):
            value = fields.get(name)
            if value is None or not str(value).strip():
                continue
            if tombstone and name in {"email", "customer_email", "owner_email", "requester_email",
                                     "phone", "customer_phone", "owner_phone", "email_hash", "name", "full_name"}:
                matches.append(evidence)
                break
            kind = "email" if "email" in name and "hash" not in name else (
                "email_hash" if "hash" in name else "phone" if "phone" in name else "")
            if kind:
                result, _ = _identity_match(identities.graph, kind, str(value), assessment.key.user_id, evidence_time)
                if result == "match":
                    matches.append(evidence)
                    break
        else:
            # Structured support records may contain a direct email inside a
            # message body instead of an email field. Count it only when the
            # historical alias graph links that exact address to this subject
            # at the record's observation time.
            message = fields.get("message_text")
            if isinstance(message, str) and any(
                    _identity_match(identities.graph, "email", value,
                                    assessment.key.user_id, evidence_time)[0] == "match"
                    for value in _EMAIL_IN_TEXT.findall(message)):
                matches.append(evidence)
    return tuple(matches)


def _policy_conflict_findings(case: CaseStateSnapshot, policy_case: PolicyCaseResult | None,
                              assessments: Mapping[tuple[ResourceKey, StateDomain], ResourceAssessment],
                              observations: Mapping[str, ExtractedObservation],
                              identities: IdentityResolutionResult) -> tuple[list[RiskFinding], list[RiskUncertainty]]:
    findings: list[RiskFinding] = []
    uncertainties: list[RiskUncertainty] = []
    if policy_case is None or case.snapshot is None:
        return findings, uncertainties
    cutoff = case.snapshot.audit_at
    for decision in policy_case.decisions:
        if decision.status is not DecisionStatus.APPLIES:
            continue
        lifecycle = assessments.get((decision.resource_key, StateDomain.LIFECYCLE))
        if lifecycle is None or lifecycle.state is ResourceState.UNKNOWN:
            uncertainties.append(RiskUncertainty("policy_resource_state_unknown",
                "An applicable policy obligation has no known lifecycle state at audit_at.", decision.resource_key,
                tuple(_policy_ref(ref, "policy_context") for ref in decision.evidence_references)))
            continue
        conflicting_evidence: tuple[StateEvidence, ...] = ()
        if decision.required_action is PolicyAction.DELETE and lifecycle.state is ResourceState.PRESENT:
            conflicting_evidence = tuple(item for item in lifecycle.evidence
                if item.state is ResourceState.PRESENT and item.state_observed_at == lifecycle.last_observed_at)
        elif decision.required_action is PolicyAction.REDACT and lifecycle.state in {
                ResourceState.PRESENT, ResourceState.TOMBSTONED}:
            conflicting_evidence = _direct_identifier_conflict(lifecycle, decision, observations, identities, cutoff)
        elif decision.required_action is PolicyAction.ANONYMIZE and lifecycle.state is ResourceState.PRESENT \
                and decision.condition_status is ConditionStatus.SATISFIED:
            conflicting_evidence = tuple(item for item in lifecycle.evidence
                if item.state is ResourceState.PRESENT and item.state_observed_at == lifecycle.last_observed_at)
        elif decision.required_action is PolicyAction.RETAIN and lifecycle.state in {
                ResourceState.DELETED, ResourceState.ABSENT}:
            conflicting_evidence = tuple(item for item in lifecycle.evidence
                if item.state is lifecycle.state and item.state_observed_at == lifecycle.last_observed_at)
        if conflicting_evidence:
            policy_refs = tuple(_policy_ref(ref, "policy_rule")
                for ref in decision.evidence_references[:1])
            refs = (*policy_refs, *(_state_ref(item) for item in conflicting_evidence),
                    *(_policy_ref(ref, "condition_evidence") for ref in decision.condition_evidence))
            findings.append(_make_finding(case, decision.resource_key,
                RiskFindingType.POLICY_STATE_CONFLICT, RiskConfidence.HIGH,
                RiskEvidenceStatus.DIRECT_STATE, refs, state=lifecycle.state, policy=decision))
    return findings, uncertainties


def analyze_recreation_risks(
    identities: IdentityResolutionResult,
    timeline: Timeline,
    extraction: EvidenceExtractionResult,
    case_states: Iterable[CaseStateSnapshot],
    policy: PolicyEvaluation | None = None,
) -> RiskAnalysis:
    """Build per-request risks and residual findings using only eligible evidence."""
    observations = {item.observation_id: item for item in extraction.observations}
    observation_resolutions = {item.target_id: item for item in identities.observation_resolutions}
    policies = {item.case_id: item for item in policy.cases} if policy else {}
    results: list[RiskCaseResult] = []

    for case in sorted(case_states, key=lambda item: item.case_id):
        if case.user_id is None or case.snapshot is None:
            reason = case.diagnostic or "request_subject_not_confirmed"
            results.append(RiskCaseResult(case.case_id, case.user_id, None, (), (), (), (), (),
                (RiskUncertainty(reason, "No confirmed request subject is available for risk scoping."),)))
            continue
        cutoff = case.snapshot.audit_at.astimezone(timezone.utc)
        assessments = {(item.key, item.domain): item for item in case.snapshot.assessments}
        findings: list[RiskFinding] = []
        uncertainties: list[RiskUncertainty] = []
        temporal: list[RiskEvidenceReference] = []
        unresolved_identity: list[RiskEvidenceReference] = []

        for assessment in case.snapshot.assessments:
            if assessment.state in {ResourceState.UNKNOWN, ResourceState.CONFLICTING} or assessment.uncertainty:
                refs = tuple(_state_ref(item, "resource_state_uncertainty") for item in assessment.evidence)
                uncertainties.append(RiskUncertainty(
                    "resource_state_unresolved" if assessment.state is ResourceState.UNKNOWN else "resource_state_conflicting",
                    ";".join(assessment.uncertainty) or "State assessment is not a unique supported value.",
                    assessment.key, refs))
            findings.extend(_event_evidence_for_resource(case, timeline, assessment, observations, cutoff))
            control_findings, control_uncertainties = _active_control_findings(
                case, assessment, observations, identities)
            findings.extend(control_findings)
            uncertainties.extend(control_uncertainties)

        policy_findings, policy_uncertainties = _policy_conflict_findings(
            case, policies.get(case.case_id), assessments, observations, identities)
        findings.extend(policy_findings)
        uncertainties.extend(policy_uncertainties)

        case_keys = {key for key, _ in assessments}
        relevant_categories = _RECREATION_CATEGORIES | {EventCategory.DELETION, EventCategory.CONTROL_STATE}
        candidate_claims: dict[ResourceKey, list[TimelineEvent]] = {}
        for event in timeline.events:
            if event.category not in relevant_categories or not event.resource_id:
                continue
            if event.subject.status == ResolutionStatus.CONFIRMED.value and event.subject.user_id == case.user_id:
                key = _event_key(event)
                if key not in case_keys:
                    continue
                reason = _event_temporal_reason(event, cutoff)
                if reason:
                    temporal.append(_event_ref(event, reason))
                    continue
                if event.category in _RECREATION_CATEGORIES and event.role in {"claim", "activity claim"}:
                    candidate_claims.setdefault(key, []).append(event)
            elif event.subject.status in {ResolutionStatus.AMBIGUOUS.value, ResolutionStatus.UNRESOLVED.value}:
                # Do not attach an unresolved event to a user merely because a
                # resource identifier happens to match.
                resolutions = observation_resolutions.get(event.source.observation_id or "")
                if resolutions and case.user_id in resolutions.candidate_user_ids:
                    unresolved_identity.append(_event_ref(event, "subject_identity_unresolved"))

        # Global activity rows have no Phase 4 subject. They can be surfaced as
        # claims only when a unique case resource match includes system scope.
        for event in timeline.events:
            if event.source.source_kind != "system_activity" or event.category not in _RECREATION_CATEGORIES:
                continue
            matched_keys = [key for key in case_keys if _system_scoped_match(event, key)]
            if len(matched_keys) != 1:
                if len(matched_keys) > 1:
                    uncertainties.append(RiskUncertainty("activity_resource_scope_ambiguous",
                        "Activity claim matches multiple confirmed resources in this case scope.", None,
                        (_event_ref(event, "multiple_scoped_resource_matches"),)))
                continue
            reason = _event_temporal_reason(event, cutoff)
            key = matched_keys[0]
            if reason:
                temporal.append(_event_ref(event, reason))
                continue
            candidate_claims.setdefault(key, []).append(event)

        for key, events in sorted(candidate_claims.items(), key=lambda item: (
                item[0].system_ids, item[0].resource_id, item[0].resource_type or "")):
            unique_events = {event.event_id: event for event in events}
            for event in sorted(unique_events.values(), key=lambda item: (
                    item.event_time.value or datetime.max.replace(tzinfo=timezone.utc), item.event_id)):
                findings.append(_make_finding(case, key, RiskFindingType.CLAIMED_RECREATION_OPERATION,
                    RiskConfidence.LOW, RiskEvidenceStatus.CLAIM_ONLY, (_event_ref(event),),
                    mechanism=event.category, event_time=event.event_time.value,
                    uncertainty=("reported_operation_does_not_establish_effect",)))

        conflicts = []
        by_event_id = {event.event_id: event for event in timeline.events}
        for conflict in (*case.snapshot.timeline_conflicts, *case.snapshot.unlinked_conflicts):
            matched = [by_event_id[event_id] for event_id in conflict.event_ids if event_id in by_event_id]
            if any(event.subject.status == ResolutionStatus.CONFIRMED.value
                   and event.subject.user_id == case.user_id for event in matched):
                conflicts.append(conflict)
                uncertainties.append(RiskUncertainty("timeline_conflict_unresolved",
                    f"Competing {conflict.field_name} claims remain for a scoped event.", None,
                    tuple(_event_ref(event, "conflicting_timeline_claim") for event in matched)))

        for resolution in identities.observation_resolutions:
            if (resolution.status in {ResolutionStatus.AMBIGUOUS, ResolutionStatus.UNRESOLVED}
                    and case.user_id in resolution.candidate_user_ids):
                observation = observations.get(resolution.target_id)
                if observation:
                    unresolved_identity.append(_obs_ref(observation, "candidate_identity_unresolved"))
        if case.snapshot.extraction_gap_file_ids:
            uncertainties.append(RiskUncertainty("evidence_extraction_gaps",
                "Participant-visible evidence explicitly linked to this case could not be extracted; its contents remain unknown."))

        unique_findings = {item.finding_id: item for item in findings}
        temporal = sorted(set(temporal), key=lambda ref: (ref.source_kind, ref.source_id, ref.locator or "", ref.reason or ""))
        unresolved_identity = sorted(set(unresolved_identity), key=lambda ref: (ref.source_kind, ref.source_id, ref.locator or ""))
        unique_uncertainties = {(item.code, item.resource_key, item.evidence): item for item in uncertainties}
        results.append(RiskCaseResult(case.case_id, case.user_id, cutoff,
            tuple(sorted(unique_findings.values(), key=lambda item: (item.resource_key.system_ids,
                item.resource_key.resource_id, item.finding_type.value, item.finding_id))),
            tuple(sorted({item.conflict_id: item for item in conflicts}.values(),
                         key=lambda item: item.conflict_id)),
            case.snapshot.extraction_gap_file_ids, tuple(unresolved_identity), tuple(temporal),
            tuple(sorted(unique_uncertainties.values(), key=lambda item: (
                item.code, item.resource_key.system_ids if item.resource_key else (),
                item.resource_key.resource_id if item.resource_key else "")))))
    return RiskAnalysis(tuple(results), tuple(sorted(set(timeline.extraction_gap_file_ids))))


__all__ = [
    "RiskAnalysis", "RiskCaseResult", "RiskConfidence", "RiskEvidenceReference",
    "RiskEvidenceStatus", "RiskFinding", "RiskFindingType", "RiskUncertainty",
    "analyze_recreation_risks",
]
