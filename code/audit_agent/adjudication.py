"""Deterministic request intent and evidence-gated case adjudication (Phase 9).

The module proposes only official deletion statuses. Unresolved evidence is
kept internal and never converted into a new serialized status.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Iterable, Mapping

from .extract import EvidenceExtractionResult
from .identity import IdentityResolutionResult, ResolutionStatus
from .models import CsvRecord, IngestionResult, ParsedTimestamp, TimestampStatus
from .policy import ConditionStatus, DecisionStatus, PolicyAction, PolicyCaseResult, PolicyDecision, PolicyEvaluation
from .risks import RiskAnalysis, RiskCaseResult, RiskEvidenceReference, RiskFinding, RiskFindingType
from .state import CaseStateSnapshot, ResourceAssessment, ResourceKey, ResourceState, StateDomain


class IntentKind(str, Enum):
    DELETION = "deletion"
    ACCESS_EXPORT = "access_export"
    CORRECTION = "correction"
    OPT_OUT = "opt_out"
    NON_DELETION = "non_deletion"
    AMBIGUOUS = "ambiguous"
    MULTI_ACTION = "multi_action"


class IntentAction(str, Enum):
    DELETE = "delete"
    ACCESS_EXPORT = "access_export"
    CORRECTION = "correction"
    OPT_OUT = "opt_out"


class MentionPolarity(str, Enum):
    POSITIVE = "positive"
    NEGATED = "negated"


class DecisionResolution(str, Enum):
    CONFIRMED = "confirmed"
    UNRESOLVED = "unresolved"


class DeletionStatus(str, Enum):
    COMPLETE = "COMPLETE"
    INCOMPLETE = "INCOMPLETE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True)
class IntentMention:
    action: IntentAction
    polarity: MentionPolarity
    start: int
    end: int
    matched_text: str
    rule_id: str
    target_scope: str


@dataclass(frozen=True)
class RequestIntent:
    case_id: str
    kind: IntentKind
    deletion_authorized: bool | None
    actions: tuple[IntentAction, ...]
    mentions: tuple[IntentMention, ...]
    source_file: str
    record_number: int
    rationale: str


@dataclass(frozen=True)
class AdjudicationReference:
    source_kind: str
    source_id: str
    source_path: str
    locator: str | None = None
    observation_id: str | None = None
    event_time: datetime | None = None
    capture_time: datetime | None = None
    role: str | None = None


@dataclass(frozen=True)
class AdjudicationReason:
    code: str
    message: str
    evidence: tuple[AdjudicationReference, ...] = ()


@dataclass(frozen=True)
class CaseAdjudication:
    case_id: str
    audit_at: datetime | None
    intent: RequestIntent
    resolution: DecisionResolution
    deletion_status: DeletionStatus | None
    reasons: tuple[AdjudicationReason, ...]
    unresolved_reasons: tuple[str, ...]
    evidence: tuple[AdjudicationReference, ...]


@dataclass(frozen=True)
class AdjudicationReport:
    cases: tuple[CaseAdjudication, ...]
    # Retain global parser gaps without treating them as case-level evidence.
    global_extraction_gap_file_ids: tuple[str, ...] = ()

    @property
    def confirmed_cases(self) -> tuple[CaseAdjudication, ...]:
        return tuple(case for case in self.cases if case.resolution is DecisionResolution.CONFIRMED)

    @property
    def unresolved_cases(self) -> tuple[CaseAdjudication, ...]:
        return tuple(case for case in self.cases if case.resolution is DecisionResolution.UNRESOLVED)


_DELETE_RE = re.compile(
    r"\b(?:delet(?:e|es|ed|ing|ion)|eras(?:e|es|ed|ing|ure)|"
    r"remov(?:e|es|ed|ing|al)|clos(?:e|es|ed|ing|ure)|purge|wipe|"
    r"elimin(?:ar|e|ó|o|ado|ada|ación|acion)|borr(?:ar|e|ó|ado|ada)|"
    r"suprim(?:ir|e|ió|ido|ida)|suppression|supprim(?:er|e|é|ée)|"
    r"effac(?:er|e|é|ée)|clôtur(?:er|e|é)|fermer|résilier|"
    r"exclus(?:ão|ao|ões|oes|ar|ão|ao)|apagar|remover|encerrar)\b|"
    r"削除|消去|退会|삭제|제거|탈퇴|해지",
    re.IGNORECASE,
)
_ACCESS_RE = re.compile(
    r"\b(?:access|view|see|export|download|copy of|copy my|data portability|"
    r"acceder|acceso|exportar|descargar|copia de|accès|consulter|télécharger|"
    r"exporter|copie de)\b|アクセス|開示|ダウンロード|データのコピー",
    re.IGNORECASE,
)
_CORRECTION_RE = re.compile(
    r"\b(?:please\s+|can you\s+|could you\s+|would you\s+|i want to\s+|i would like to\s+|"
    r"i need you to\s+)?(?:correct|fix|update|amend|change|replace)\s+"
    r"(?:it|(?:(?:my|the)\s+)?(?:personal\s+)?(?:information|details|data|name|surname|last name|email|address|phone|number|mobile))\b|"
    r"\b(?:corrige|corrigir|corregir|actualizar|rectifier|corriger|modifier)\b|"
    r"(?:訂正|修正|更新)|(?:개인정보|이메일|전화번호|이름).{0,12}(?:수정|변경|정정)", re.IGNORECASE)
_OPTOUT_RE = re.compile(
    r"\b(?:opt[ -]?out|unsubscribe|stop (?:sending|emailing) (?:me )?(?:marketing|promotional)|"
    r"remove me from (?:the )?(?:marketing|mailing|newsletter)|no more (?:marketing|promotional)|"
    r"darme de baja|dejar de recibir (?:publicidad|promociones)|no (?:quiero )?recibir (?:publicidad|promociones)|désinscrire|"
    r"ne plus recevoir (?:de )?(?:publicité|messages promotionnels))\b|"
    r"配信停止|マーケティングメールを停止", re.IGNORECASE)
_VAGUE_RE = re.compile(
    r"\b(?:take|get) me off (?:your |the )?(?:system|platform)\b|"
    r"\bmake me disappear\b|\bget rid of me\b", re.IGNORECASE)
_HEDGED_RE = re.compile(
    r"\b(?:should|could|would|might|may) i (?:delete|erase|remove|close)\b|"
    r"\b(?:considering|thinking about|wondering whether to)\s+(?:delet|eras|remov|clos)", re.IGNORECASE)
_NEGATIVE_PREFIX_RE = re.compile(
    r"(?:\b(?:do not|don't|dont|never|not|no longer want to|don't want to|without)\s*|"
    r"\bno\s+(?:quiero\s+|deseo\s+)?|\bne\s+(?:veux|souhaite|demande|veuillez)?\s*pas\s*)$",
    re.IGNORECASE)
_NEGATIVE_FRENCH_RE = re.compile(r"\bne\b(?:\W+\w+){0,3}\W+pas\W*$", re.IGNORECASE)
_NEGATIVE_JA_RE = re.compile(r"(?:しないで|しません|しない|ないで|ません)$")
_MARKETING_RE = re.compile(r"marketing|newsletter|promotional|publicidad|publicité|マーケティング|配信", re.I)
_ACCOUNT_SCOPE_RE = re.compile(r"account|profile|personal data|personal information|my data|my details|cuenta|compte|アカウント", re.I)
_DIRECT_IDENTIFIER_FIELDS = frozenset({
    "name", "full_name", "email", "customer_email", "owner_email", "requester_email",
    "phone", "customer_phone", "owner_phone", "requester_phone", "email_hash",
})


def _scope_for(text: str, start: int, end: int) -> str:
    context = text[max(0, start - 45):min(len(text), end + 65)]
    if _MARKETING_RE.search(context):
        return "marketing"
    if _ACCOUNT_SCOPE_RE.search(context):
        return "account_data"
    return "resource_or_unspecified"


def _negated(text: str, start: int, end: int, marker: str) -> bool:
    prefix = text[max(0, start - 48):start]
    suffix = text[end:min(len(text), end + 14)]
    if _NEGATIVE_PREFIX_RE.search(prefix) or _NEGATIVE_FRENCH_RE.search(prefix):
        return True
    if marker in {"削除", "消去", "退会"} and _NEGATIVE_JA_RE.match(suffix):
        return True
    if marker in {"삭제", "제거", "탈퇴", "해지"} and re.match(r"(?:하지\s*마세요|하지\s*말아|하지\s*않|하지\s*마)", suffix):
        return True
    return False


def classify_request_intent(text: str, *, case_id: str = "", record_number: int = 0,
                            source_file: str = "deletion_requests.csv") -> RequestIntent:
    """Classify explicit action language without consulting status or evidence."""
    mentions: list[IntentMention] = []
    for match in _DELETE_RE.finditer(text):
        token = match.group(0)
        scope = _scope_for(text, match.start(), match.end())
        # "close" refers to deletion only when its local object is an account-like target.
        if token.casefold().startswith("clos") and scope != "account_data":
            continue
        mentions.append(IntentMention(IntentAction.DELETE,
            MentionPolarity.NEGATED if _negated(text, match.start(), match.end(), token) else MentionPolarity.POSITIVE,
            match.start(), match.end(), token, "delete_lexeme", scope))
    for pattern, action, rule in (
        (_ACCESS_RE, IntentAction.ACCESS_EXPORT, "access_export_lexeme"),
        (_CORRECTION_RE, IntentAction.CORRECTION, "correction_request_phrase"),
        (_OPTOUT_RE, IntentAction.OPT_OUT, "marketing_optout_phrase"),
    ):
        for match in pattern.finditer(text):
            mentions.append(IntentMention(action, MentionPolarity.POSITIVE, match.start(), match.end(),
                match.group(0), rule, _scope_for(text, match.start(), match.end())))
    mentions.sort(key=lambda item: (item.start, item.end, item.action.value, item.rule_id))
    # A single phrase can satisfy both a generic removal lexeme and the more
    # specific marketing opt-out phrase. Prefer the specific opt-out reading.
    if any(item.action is IntentAction.OPT_OUT for item in mentions):
        mentions = [item for item in mentions if not (
            item.action is IntentAction.DELETE and item.target_scope == "marketing")]
    positive_delete = [item for item in mentions if item.action is IntentAction.DELETE
                       and item.polarity is MentionPolarity.POSITIVE]
    negative_delete = [item for item in mentions if item.action is IntentAction.DELETE
                       and item.polarity is MentionPolarity.NEGATED]
    other_positive = [item for item in mentions if item.action is not IntentAction.DELETE
                      and item.polarity is MentionPolarity.POSITIVE]
    conflict = any(left.target_scope != "marketing" and right.target_scope != "marketing"
                   and (left.target_scope == right.target_scope
                        or "resource_or_unspecified" in {left.target_scope, right.target_scope})
                   for left in positive_delete for right in negative_delete)
    if conflict or _VAGUE_RE.search(text) or _HEDGED_RE.search(text):
        kind, authorized, rationale = IntentKind.AMBIGUOUS, None, "deletion_scope_or_request_intent_ambiguous"
    elif positive_delete:
        action_set = {item.action for item in (*positive_delete, *other_positive)}
        kind = IntentKind.MULTI_ACTION if len(action_set) > 1 else IntentKind.DELETION
        authorized, rationale = True, "explicit_deletion_action_present"
    elif other_positive:
        action_set = {item.action for item in other_positive}
        if len(action_set) > 1:
            kind, rationale = IntentKind.MULTI_ACTION, "multiple_non_deletion_actions_present"
        else:
            action = next(iter(action_set))
            kind = {
                IntentAction.ACCESS_EXPORT: IntentKind.ACCESS_EXPORT,
                IntentAction.CORRECTION: IntentKind.CORRECTION,
                IntentAction.OPT_OUT: IntentKind.OPT_OUT,
            }[action]
            rationale = "explicit_non_deletion_action_present"
        authorized = False
    elif negative_delete:
        kind, authorized, rationale = IntentKind.NON_DELETION, False, "deletion_explicitly_negated"
    else:
        kind, authorized, rationale = IntentKind.AMBIGUOUS, None, "no_supported_intent_pattern"
    return RequestIntent(case_id, kind, authorized,
        tuple(sorted({item.action for item in mentions}, key=lambda item: item.value)),
        tuple(mentions), source_file, record_number, rationale)


def _risk_ref(reference: RiskEvidenceReference) -> AdjudicationReference:
    return AdjudicationReference(reference.source_kind, reference.source_id, reference.source_path,
        reference.locator, reference.observation_id, reference.event_time, reference.capture_time,
        reference.role)


def _policy_ref(reference: object, role: str = "policy") -> AdjudicationReference:
    locator = getattr(reference, "locator", None)
    record_number = getattr(reference, "record_number", None)
    if locator is None and record_number is not None:
        locator = f"record:{record_number}"
    return AdjudicationReference(reference.source_kind, reference.source_id, reference.source_file,
        locator, reference.observation_id, None, reference.captured_at, role)


def _state_ref(evidence: object, role: str = "observed_state") -> AdjudicationReference:
    source = evidence.source
    capture = evidence.capture_time.value if evidence.capture_time and evidence.capture_time.status is TimestampStatus.VALID else None
    event = evidence.event_time.value if evidence.event_time and evidence.event_time.status is TimestampStatus.VALID else None
    return AdjudicationReference(source.source_kind,
        source.file_id or source.record_id or evidence.evidence_key, source.source_file,
        source.locator or source.record_id, source.observation_id, event, capture, role)


def _assessment_map(case: CaseStateSnapshot) -> Mapping[tuple[ResourceKey, StateDomain], ResourceAssessment]:
    if case.snapshot is None:
        return {}
    return {(item.key, item.domain): item for item in case.snapshot.assessments}


def _safe_tombstone(assessment: ResourceAssessment, observations: Mapping[str, object]) -> bool:
    latest = [item for item in assessment.evidence
              if item.state is ResourceState.TOMBSTONED
              and item.state_observed_at == assessment.last_observed_at
              and item.source.source_kind == "evidence" and item.source.observation_id]
    if not latest:
        return False
    for state_evidence in latest:
        observation = observations.get(state_evidence.source.observation_id or "")
        if observation is None:
            continue
        fields = observation.normalized_fields
        stable_references = (fields.get("user_id"), fields.get("subject_reference"),
                             fields.get("customer_reference"), fields.get("customer_ref"))
        if not any(str(value).strip() == assessment.key.user_id
                   for value in stable_references if value is not None):
            continue
        direct_values = [fields.get(name) for name in _DIRECT_IDENTIFIER_FIELDS]
        if not any(value is not None and str(value).strip() for value in direct_values):
            return True
    return False


def _decision_support(policy_case: PolicyCaseResult | None, case: CaseStateSnapshot,
                      observations: Mapping[str, object],
                      risk_case: RiskCaseResult | None) -> tuple[bool, bool, list[str], list[AdjudicationReason]]:
    """Return (all conclusive, violation found, unknowns, reason evidence)."""
    if policy_case is None:
        return False, False, ["policy_case_missing"], []
    assessments = _assessment_map(case)
    unknown: list[str] = list(policy_case.uncertainty)
    if policy_case.request_identity_conflicts:
        unknown.append("request_identity_conflict")
    # Policy gap IDs are case-scoped by Phase 6; global parser failures remain
    # on the report and cannot independently block an unrelated case.
    if policy_case.extraction_gap_file_ids:
        unknown.append("extraction_gap_case_relevance_unresolved")
    if policy_case.temporally_ineligible_observations:
        unknown.append("policy_context_temporally_ineligible")
    if policy_case.unresolved_identity_observations:
        unknown.append("policy_identity_evidence_unresolved")
    reasons: list[AdjudicationReason] = []
    violation = False
    if policy_case.conflicts:
        reasons.append(AdjudicationReason("conflicting_policy_obligations",
            "Applicable policy rules require conflicting treatments.", tuple(
                AdjudicationReference("deletion_rule", rule_id, "deletion_rules.csv", role="policy_rule")
                for conflict in policy_case.conflicts for rule_id in conflict.rule_ids)))
        unknown.append("conflicting_policy_obligations")
    for decision in policy_case.decisions:
        if decision.status is DecisionStatus.DOES_NOT_APPLY:
            continue
        policy_refs = tuple(_policy_ref(item, "policy_obligation")
            for item in (*decision.evidence_references, *decision.condition_evidence))
        if decision.status in {DecisionStatus.UNRESOLVED, DecisionStatus.CONFLICTING} \
                or decision.condition_status is not ConditionStatus.SATISFIED:
            fallback = f"policy_{decision.status.value}"
            if decision.condition_status is not ConditionStatus.SATISFIED:
                fallback = f"policy_condition_{decision.condition_status.value}"
            unknown.extend(decision.uncertainty or (fallback,))
            if decision.condition_status in {ConditionStatus.UNKNOWN, ConditionStatus.CONFLICTING}:
                unknown.append(f"policy_condition_{decision.condition_status.value}")
            reasons.append(AdjudicationReason("policy_obligation_unresolved",
                "The policy decision or its condition is not conclusive at this cutoff.", policy_refs))
            continue
        assessment = assessments.get((decision.resource_key, StateDomain.LIFECYCLE))
        if assessment is None:
            unknown.append("policy_resource_state_unknown")
            reasons.append(AdjudicationReason("policy_resource_state_unavailable",
                "No lifecycle assessment is available for this applicable policy obligation.", policy_refs))
            continue
        if assessment.state in {ResourceState.UNKNOWN, ResourceState.CONFLICTING}:
            unknown.append("policy_resource_state_unknown")
            state_refs = tuple(_state_ref(item) for item in assessment.evidence)
            reasons.append(AdjudicationReason("policy_resource_state_unresolved",
                "Eligible state evidence is missing or conflicting for this applicable obligation.",
                (*policy_refs, *state_refs)))
            continue
        if assessment.uncertainty:
            unknown.extend(assessment.uncertainty)
        state = assessment.state
        action = decision.required_action
        redaction_conflict = bool(risk_case and any(
            finding.finding_type is RiskFindingType.POLICY_STATE_CONFLICT
            and finding.resource_key == decision.resource_key for finding in risk_case.findings))
        if action is PolicyAction.DELETE:
            compliant = state in {ResourceState.ABSENT, ResourceState.DELETED}
        elif action is PolicyAction.REDACT:
            compliant = state in {ResourceState.REDACTED, ResourceState.ANONYMIZED} \
                or (state is ResourceState.TOMBSTONED and _safe_tombstone(assessment, observations))
        elif action is PolicyAction.ANONYMIZE:
            compliant = state is ResourceState.ANONYMIZED
        elif action is PolicyAction.RETAIN:
            compliant = state in {ResourceState.PRESENT, ResourceState.RETAINED}
        else:
            compliant = False
        direct = any(item.state is state and item.state_observed_at == assessment.last_observed_at
                     and item.state_observed_at is not None and item.source.source_kind == "evidence"
                     for item in assessment.evidence)
        if action is PolicyAction.REDACT and not compliant and not redaction_conflict:
            unknown.append("redaction_compliance_not_proven")
            continue
        if not compliant and direct:
            violation = True
            refs = (*policy_refs,
                    *(_state_ref(item) for item in assessment.evidence
                      if item.state is state and item.state_observed_at == assessment.last_observed_at))
            reasons.append(AdjudicationReason("policy_state_violation",
                f"Direct lifecycle evidence conflicts with required {action.value} treatment for {decision.data_category}.", refs))
        elif not compliant:
            unknown.append("policy_treatment_not_proven")
        elif not direct:
            unknown.append("compliant_state_lacks_direct_evidence")
        else:
            refs = (*policy_refs,
                    *(_state_ref(item) for item in assessment.evidence
                      if item.state is state and item.state_observed_at == assessment.last_observed_at))
            reasons.append(AdjudicationReason("policy_treatment_proven",
                f"Direct lifecycle evidence supports required {action.value} treatment for {decision.data_category}.", refs))
    if not policy_case.decisions:
        unknown.append("no_policy_obligations_evaluated")
    return not unknown, violation, sorted(set(unknown)), reasons


def _case_evidence_gaps(risk_case: RiskCaseResult | None) -> tuple[str, ...]:
    if risk_case is None:
        return ("risk_analysis_case_missing",)
    gaps = [item.code for item in risk_case.uncertainties]
    if risk_case.extraction_gap_file_ids:
        # This list contains only explicit case-linked failures. The failed
        # content remains unknown and must still block unsupported completion.
        gaps.append("extraction_gap_case_relevance_unresolved")
    if risk_case.conflicts:
        gaps.append("eligible_timeline_conflict")
    if risk_case.unresolved_identity_evidence:
        gaps.append("case_identity_evidence_unresolved")
    if risk_case.temporal_exclusions:
        gaps.append("case_temporally_ineligible_evidence_present")
    return tuple(sorted(set(gaps)))


def _all_reasons(reasons: Iterable[AdjudicationReason]) -> tuple[AdjudicationReason, ...]:
    unique = {(item.code, item.message, item.evidence): item for item in reasons}
    return tuple(sorted(unique.values(), key=lambda item: (item.code, item.message)))


def _case_record_map(ingestion: IngestionResult) -> Mapping[str, CsvRecord]:
    table = ingestion.bundle.tables.get("deletion_requests")
    return {record.raw("case_id") or "": record for record in table.records} if table else {}


def adjudicate_cases(ingestion: IngestionResult, identities: IdentityResolutionResult,
                     extraction: EvidenceExtractionResult,
                     case_states: Iterable[CaseStateSnapshot], policy: PolicyEvaluation,
                     risks: RiskAnalysis) -> AdjudicationReport:
    """Classify request intent and propose only evidence-supported final status.

    A supported violation can establish INCOMPLETE even if an independent gap
    remains. COMPLETE requires every matched policy decision and risk gate to
    be proven. Globally unlinked OCR gaps remain on the report; explicitly
    case-linked gaps remain case uncertainty and never prove either outcome.
    """
    records = _case_record_map(ingestion)
    requests = {item.target_id: item for item in identities.request_resolutions}
    policies = {item.case_id: item for item in policy.cases}
    risk_cases = {item.case_id: item for item in risks.cases}
    states = {item.case_id: item for item in case_states}
    observations = {item.observation_id: item for item in extraction.observations}
    results: list[CaseAdjudication] = []
    for case_id in sorted(records):
        record = records[case_id]
        intent = classify_request_intent(record.raw("request_text") or "", case_id=case_id,
            record_number=record.source.record_number, source_file=record.source.source_file)
        state_case = states.get(case_id)
        policy_case = policies.get(case_id)
        risk_case = risk_cases.get(case_id)
        parsed_cutoff = record.typed("audit_at")
        cutoff = parsed_cutoff.value if isinstance(parsed_cutoff, ParsedTimestamp) \
            and parsed_cutoff.status is TimestampStatus.VALID else None
        if state_case and state_case.snapshot:
            cutoff = state_case.snapshot.audit_at.astimezone(timezone.utc)
        reasons: list[AdjudicationReason] = []
        unresolved: list[str] = []
        evidence: list[AdjudicationReference] = []
        intent_ref = AdjudicationReference("request", case_id, record.source.source_file,
            f"record:{record.source.record_number}:request_text", role="request_intent")
        evidence.append(intent_ref)
        identity = requests.get(case_id)
        if identity is not None:
            identity_source = identity.source
            evidence.append(AdjudicationReference("identity_resolution", case_id,
                identity_source.source_file,
                f"record:{identity_source.record_number}" if identity_source.record_number else None,
                role="request_identity"))
        if intent.deletion_authorized is False:
            reasons.append(AdjudicationReason("non_deletion_request",
                f"Request intent is {intent.kind.value}; deletion was not authorized.", (intent_ref,)))
            results.append(CaseAdjudication(case_id, cutoff, intent, DecisionResolution.CONFIRMED,
                DeletionStatus.NOT_APPLICABLE, _all_reasons(reasons), (), tuple(evidence)))
            continue
        if intent.deletion_authorized is None:
            unresolved.append("request_intent_ambiguous_or_unsupported")
            reasons.append(AdjudicationReason("request_intent_unresolved",
                intent.rationale, (intent_ref,)))
        if identity is None or identity.status is not ResolutionStatus.CONFIRMED:
            unresolved.append("request_subject_identity_not_confirmed")
            reasons.append(AdjudicationReason("request_subject_identity_not_confirmed",
                "The request does not resolve to one confirmed subject.", tuple(evidence[-1:])))
        if state_case is None or state_case.snapshot is None or state_case.user_id is None:
            unresolved.append("resource_state_snapshot_unavailable")
            reasons.append(AdjudicationReason("resource_state_snapshot_unavailable",
                "No confirmed-subject state snapshot is available at the request cutoff.", (intent_ref,)))
        elif identity and identity.matched_user_id != state_case.user_id:
            unresolved.append("identity_and_state_subject_disagree")
            reasons.append(AdjudicationReason("identity_and_state_subject_disagree",
                "The identity and state modules returned different subjects.", tuple(evidence)))
        if policy_case is None:
            unresolved.append("policy_case_missing")
            reasons.append(AdjudicationReason("policy_case_missing",
                "No policy evaluation was returned for this request.", (intent_ref,)))
        elif identity and policy_case.user_id != identity.matched_user_id:
            unresolved.append("identity_and_policy_subject_disagree")
            reasons.append(AdjudicationReason("identity_and_policy_subject_disagree",
                "The identity and policy modules returned different subjects.", tuple(evidence)))
        if risk_case is None:
            unresolved.append("risk_analysis_case_missing")
            reasons.append(AdjudicationReason("risk_analysis_case_missing",
                "No Phase 8 risk result was returned for this request.", (intent_ref,)))
        elif identity and risk_case.user_id != identity.matched_user_id:
            unresolved.append("identity_and_risk_subject_disagree")
            reasons.append(AdjudicationReason("identity_and_risk_subject_disagree",
                "The identity and risk modules returned different subjects.", tuple(evidence)))
        if cutoff is None:
            unresolved.append("audit_cutoff_invalid")
            reasons.append(AdjudicationReason("audit_cutoff_invalid",
                "The request has no valid timezone-aware audit cutoff.", (intent_ref,)))
        identity_gate = {
            "request_intent_ambiguous_or_unsupported", "request_subject_identity_not_confirmed",
            "resource_state_snapshot_unavailable", "identity_and_state_subject_disagree",
            "identity_and_policy_subject_disagree", "identity_and_risk_subject_disagree", "audit_cutoff_invalid",
        }
        if intent.deletion_authorized is None or identity_gate.intersection(unresolved):
            results.append(CaseAdjudication(case_id, cutoff, intent, DecisionResolution.UNRESOLVED,
                None, _all_reasons(reasons), tuple(sorted(set(unresolved))), tuple(evidence)))
            continue

        if state_case is None:
            results.append(CaseAdjudication(case_id, cutoff, intent, DecisionResolution.UNRESOLVED,
                None, _all_reasons(reasons), tuple(sorted(set(unresolved))), tuple(evidence)))
            continue
        all_conclusive, policy_violation, policy_unknown, policy_reasons = _decision_support(
            policy_case, state_case, observations, risk_case)
        unresolved.extend(policy_unknown)
        reasons.extend(policy_reasons)
        for reason in policy_reasons:
            evidence.extend(reason.evidence)
        if risk_case:
            for finding in risk_case.findings:
                refs = tuple(_risk_ref(item) for item in finding.evidence)
                evidence.extend(refs)
                if finding.finding_type in {
                    RiskFindingType.POLICY_STATE_CONFLICT,
                    RiskFindingType.POSSIBLE_DATA_FLOW_RECREATION,
                    RiskFindingType.POSSIBLE_RESTORE,
                }:
                    reasons.append(AdjudicationReason(finding.finding_type.value,
                        "Phase 8 found a scoped, cutoff-eligible policy conflict or recreation risk.", refs))
                elif finding.finding_type is RiskFindingType.CLAIMED_RECREATION_OPERATION:
                    reasons.append(AdjudicationReason("operation_claim_not_verified",
                        "A workflow claim was retained but does not establish a resource effect or final status.", refs))
            for uncertainty in risk_case.uncertainties:
                reasons.append(AdjudicationReason(uncertainty.code, uncertainty.message,
                    tuple(_risk_ref(item) for item in uncertainty.evidence)))
            if risk_case.extraction_gap_file_ids:
                reasons.append(AdjudicationReason("extraction_gap_case_relevance_unresolved",
                    "Failed evidence files have not been linked to or excluded from this case.", tuple(
                        AdjudicationReference("manifest", file_id, "evidence_files.csv", role="extraction_gap")
                        for file_id in risk_case.extraction_gap_file_ids)))
            if risk_case.temporal_exclusions:
                reasons.append(AdjudicationReason("case_temporally_ineligible_evidence_present",
                    "Evidence outside the audit cutoff was excluded from the decision.", tuple(
                        _risk_ref(item) for item in risk_case.temporal_exclusions)))
            if risk_case.unresolved_identity_evidence:
                reasons.append(AdjudicationReason("case_identity_evidence_unresolved",
                    "Candidate evidence could not be uniquely resolved to this subject.", tuple(
                        _risk_ref(item) for item in risk_case.unresolved_identity_evidence)))
            unresolved.extend(_case_evidence_gaps(risk_case))
        supported_violation = policy_violation or any(reason.code in {
            RiskFindingType.POLICY_STATE_CONFLICT.value,
            RiskFindingType.POSSIBLE_DATA_FLOW_RECREATION.value,
            RiskFindingType.POSSIBLE_RESTORE.value,
        } for reason in reasons)
        if supported_violation:
            reasons.append(AdjudicationReason("verified_noncompliance",
                "At least one applicable policy obligation or active recreation path is directly contradicted by eligible evidence.",
                tuple(evidence[1:])))
            results.append(CaseAdjudication(case_id, cutoff, intent, DecisionResolution.CONFIRMED,
                DeletionStatus.INCOMPLETE, _all_reasons(reasons), tuple(sorted(set(unresolved))),
                tuple(dict.fromkeys(evidence))))
            continue
        if not all_conclusive:
            unresolved.append("policy_obligations_not_fully_resolved")
        if any(item.state in {ResourceState.UNKNOWN, ResourceState.CONFLICTING}
               or item.uncertainty for item in state_case.snapshot.assessments):
            unresolved.append("resource_state_unknown_or_conflicting")
        if risk_case and risk_case.extraction_gap_file_ids:
            unresolved.append("extraction_gap_case_relevance_unresolved")
        if risk_case and (risk_case.findings or risk_case.conflicts or risk_case.unresolved_identity_evidence
                          or risk_case.temporal_exclusions or risk_case.uncertainties):
            unresolved.append("risk_or_evidence_uncertainty_remains")
        if unresolved:
            results.append(CaseAdjudication(case_id, cutoff, intent, DecisionResolution.UNRESOLVED,
                None, _all_reasons(reasons), tuple(sorted(set(unresolved))), tuple(dict.fromkeys(evidence))))
            continue
        reasons.append(AdjudicationReason("all_known_obligations_proven",
            "Every evaluated policy obligation has direct compliant state evidence and no eligible recreation risk was found.",
            tuple(evidence[1:])))
        results.append(CaseAdjudication(case_id, cutoff, intent, DecisionResolution.CONFIRMED,
            DeletionStatus.COMPLETE, _all_reasons(reasons), (), tuple(dict.fromkeys(evidence))))
    return AdjudicationReport(tuple(results), tuple(sorted(set(risks.global_extraction_gap_file_ids))))


__all__ = [
    "AdjudicationReason", "AdjudicationReference", "AdjudicationReport", "CaseAdjudication",
    "DecisionResolution", "DeletionStatus", "IntentAction", "IntentKind", "IntentMention",
    "MentionPolarity", "RequestIntent", "adjudicate_cases", "classify_request_intent",
]
