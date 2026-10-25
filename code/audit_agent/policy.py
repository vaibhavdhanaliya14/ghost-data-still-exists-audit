"""Deterministic, provenance-backed evaluation of supplied deletion rules.

This module determines conditional policy obligations only. It does not decide
request intent, resource compliance, final status, or remediation. Observed
resource/control state is carried alongside obligations and never substituted
for them.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import re
from typing import Any, Iterable, Mapping

from .extract import EvidenceExtractionResult, ExtractedObservation
from .identity import IdentityConflict, IdentityResolutionResult, ResolutionStatus
from .ingest import parse_timestamp
from .models import CsvRecord, IngestionResult, ParsedTimestamp, TimestampStatus
from .state import CaseStateSnapshot, ResourceAssessment, ResourceKey, ResourceState, StateDomain, StateEvidence


class PolicyAction(str, Enum):
    DELETE = "DELETE"
    REDACT = "REDACT"
    ANONYMIZE = "ANONYMIZE"
    RETAIN = "RETAIN"


class ConditionStatus(str, Enum):
    SATISFIED = "satisfied"
    NOT_SATISFIED = "not_satisfied"
    UNKNOWN = "unknown"
    CONFLICTING = "conflicting"


class DecisionStatus(str, Enum):
    APPLIES = "applies"
    DOES_NOT_APPLY = "does_not_apply"
    UNRESOLVED = "unresolved"
    CONFLICTING = "conflicting"


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    data_category: str
    condition: str
    required_action: PolicyAction
    source_file: str
    record_number: int


@dataclass(frozen=True)
class PolicyEvidenceReference:
    source_kind: str
    source_id: str
    source_file: str
    record_number: int | None = None
    observation_id: str | None = None
    locator: str | None = None
    field_name: str | None = None
    raw_value: str | None = None
    captured_at: datetime | None = None
    inner_timestamps: tuple[tuple[str, str | None, datetime | None, str], ...] = ()


@dataclass(frozen=True)
class PolicyDecision:
    case_id: str
    resource_key: ResourceKey
    data_category: str
    rule: PolicyRule
    status: DecisionStatus
    condition_status: ConditionStatus
    required_action: PolicyAction
    observed_states: tuple[tuple[StateDomain, ResourceState], ...]
    evidence_references: tuple[PolicyEvidenceReference, ...]
    condition_evidence: tuple[PolicyEvidenceReference, ...]
    uncertainty: tuple[str, ...]


@dataclass(frozen=True)
class PolicyConflict:
    case_id: str
    resource_key: ResourceKey
    data_category: str
    rule_ids: tuple[str, ...]
    actions: tuple[PolicyAction, ...]


@dataclass(frozen=True)
class PolicyCaseResult:
    case_id: str
    subject_status: str
    user_id: str | None
    audit_at: datetime | None
    # Request-intent classification is a separate later boundary. These
    # obligations are conditional on the request authorizing deletion.
    deletion_authorization_evaluated: bool
    decisions: tuple[PolicyDecision, ...]
    conflicts: tuple[PolicyConflict, ...]
    extraction_gap_file_ids: tuple[str, ...]
    temporally_ineligible_observations: tuple[PolicyEvidenceReference, ...]
    unresolved_identity_observations: tuple[PolicyEvidenceReference, ...]
    request_identity_conflicts: tuple[IdentityConflict, ...]
    uncertainty: tuple[str, ...]


@dataclass(frozen=True)
class PolicyDiagnostic:
    code: str
    message: str
    rule_id: str | None = None
    case_id: str | None = None


@dataclass(frozen=True)
class PolicyEvaluation:
    rules: tuple[PolicyRule, ...]
    cases: tuple[PolicyCaseResult, ...]
    diagnostics: tuple[PolicyDiagnostic, ...]

    @property
    def decisions(self) -> tuple[PolicyDecision, ...]:
        return tuple(decision for case in self.cases for decision in case.decisions)

    @property
    def unresolved_case_ids(self) -> tuple[str, ...]:
        return tuple(case.case_id for case in self.cases if
                     case.user_id is None or case.conflicts or case.request_identity_conflicts or
                     any(decision.status in {DecisionStatus.UNRESOLVED, DecisionStatus.CONFLICTING}
                         for decision in case.decisions))


# Explicit collection_name values found in the participant-visible SQL snapshots.
# They describe the containing table for a nested record_json observation.
_COLLECTION_CATEGORIES = {
    "customer_profiles": "USER_PROFILE",
    "customer_search_documents": "SEARCH_INDEX_ENTRY",
    "customer_analytics_reports": "ANALYTICS_PROFILE",
    "security_audit_events": "SECURITY_AUDIT_LOG",
    "support_conversations": "SUPPORT_MESSAGE",
    "ticket_attachments": "SUPPORT_ATTACHMENT",
    "customer_export_jobs": "USER_EXPORT",
    "backup_catalog": "BACKUP_ARCHIVE",
    "deleted_customer_references": "ACCOUNT_TOMBSTONE",
}
_SERVICE_EXPORT_CATEGORIES = {
    ("account_service", "profile_lookups"): "USER_PROFILE",
    ("search_service", "index_queries"): "SEARCH_INDEX_ENTRY",
    ("analytics_platform", "profiles"): "ANALYTICS_PROFILE",
    ("support_platform", "tickets"): "SUPPORT_MESSAGE",
    ("security_service", "audit_records"): "SECURITY_AUDIT_LOG",
    ("backup_service", "restore_entries"): "BACKUP_ARCHIVE",
    ("export_service", "exports"): "USER_EXPORT",
}
_SQL_TABLE_CATEGORIES = {
    "customer_profiles": "USER_PROFILE",
    "customer_search_documents": "SEARCH_INDEX_ENTRY",
    "customer_analytics_profiles": "ANALYTICS_PROFILE",
    "support_records": "SUPPORT_MESSAGE",
    "customer_exports": "USER_EXPORT",
    "connector_subscriptions": "DATA_FLOW",
    "backup_restore_entries": "BACKUP_ARCHIVE",
    "security_audit_records": "SECURITY_AUDIT_LOG",
}

_TIMESTAMP_FIELDS_NOT_OCCURRENCE = ("_until", "_expires", "_expiry")
_EXPLICIT_ORDER_CONTEXT = re.compile(
    r"\b(?:affected|associated|related)\s+order\b|\bORD[-_ ]?\d+\b", re.IGNORECASE
)
_CONDITIONS_BY_CATEGORY = {
    "SUPPORT_MESSAGE": "conversation contains shared customer, agent, or order context that must be retained",
    "SUPPORT_ATTACHMENT": "attachment belongs only to the deletion subject",
    "ANALYTICS_PROFILE": "record is still attributable to a user",
    "PRODUCT_TELEMETRY": "record is still attributable to a user",
    "EMAIL_DELIVERY_LOG": "log contains a user email address",
    "SECURITY_AUDIT_LOG": "record is within the supplied retention period",
    "LEGAL_HOLD_RECORD": "a supplied legal hold is active",
    "BACKUP_ARCHIVE": "restore access can be blocked",
    "ACCOUNT_TOMBSTONE": "account is deleted and only a stable internal user_id is needed to preserve references to retained records",
}


def _norm(value: object) -> str:
    return str(value).strip().casefold().replace("-", "_").replace(" ", "_")


def load_policy_rules(ingestion: IngestionResult) -> tuple[tuple[PolicyRule, ...], tuple[PolicyDiagnostic, ...]]:
    """Parse the supplied rule table; invalid rules remain visible as diagnostics."""
    table = ingestion.bundle.tables.get("deletion_rules")
    if table is None:
        return (), (PolicyDiagnostic("policy_table_missing", "deletion_rules.csv was not ingested."),)
    rules: list[PolicyRule] = []
    diagnostics: list[PolicyDiagnostic] = []
    for row in table.records:
        rule_id = row.raw("rule_id") or ""
        category = row.raw("data_category") or ""
        condition = row.raw("condition") or ""
        action_text = row.raw("required_action") or ""
        try:
            action = PolicyAction(action_text.strip().upper())
        except ValueError:
            diagnostics.append(PolicyDiagnostic("unsupported_policy_action",
                "Rule action is outside the participant-supplied action set.", rule_id or None))
            continue
        if not rule_id.strip() or not category.strip() or not condition.strip():
            diagnostics.append(PolicyDiagnostic("incomplete_policy_rule",
                "Rule is missing its identifier, category, or condition.", rule_id or None))
            continue
        rules.append(PolicyRule(rule_id.strip(), category.strip().upper(), condition.strip(), action,
                                row.source.source_file, row.source.record_number))
    rules.sort(key=lambda rule: (rule.data_category, rule.rule_id, rule.record_number))
    diagnostics.sort(key=lambda item: (item.code, item.rule_id or ""))
    return tuple(rules), tuple(diagnostics)


def _category_for(observation: ExtractedObservation, observations: Mapping[str, ExtractedObservation]) -> str | None:
    fields = observation.normalized_fields
    for name in ("data_category", "record_type", "resource_type", "category"):
        value = fields.get(name)
        if value is not None and str(value).strip():
            return str(value).strip().upper()
    if observation.file_format.casefold() == "sql" and observation.locator.startswith("table:"):
        table_name = observation.locator[len("table:"):].split("/", 1)[0].casefold()
        table_category = _SQL_TABLE_CATEGORIES.get(table_name)
        if table_category:
            return table_category
    collection = fields.get("collection_name")
    if collection is None and observation.parent_observation_id:
        parent = observations.get(observation.parent_observation_id)
        collection = parent.normalized_fields.get("collection_name") if parent else None
    if collection is not None:
        system = (observation.system_id or fields.get("system_id")
                  or fields.get("source_system") or fields.get("origin_system"))
        pair = (str(system).strip().casefold(), str(collection).strip().casefold()) if system else None
        if pair in _SERVICE_EXPORT_CATEGORIES:
            return _SERVICE_EXPORT_CATEGORIES[pair]
        return _COLLECTION_CATEGORIES.get(str(collection).strip().casefold())
    return None


def _capture_value(observation: ExtractedObservation) -> datetime | None:
    captured = observation.captured_at
    if captured is None or captured.status is not TimestampStatus.VALID:
        return None
    return captured.value


def _evidence_time(observation: ExtractedObservation, cutoff: datetime) -> datetime:
    """Use the latest valid inner record time, else the eligible capture time."""
    inner = [item.parsed.value for item in observation.timestamps
             if item.parsed.status is TimestampStatus.VALID and item.parsed.value is not None
             and not item.field_name.casefold().endswith(_TIMESTAMP_FIELDS_NOT_OCCURRENCE)
             and item.field_name.casefold() not in {"expires_at", "expiry_date"}
             and item.parsed.value <= cutoff]
    return max(inner) if inner else (_capture_value(observation) or cutoff)


def _observation_temporal_status(observation: ExtractedObservation, cutoff: datetime) -> tuple[str, str | None]:
    captured = observation.captured_at
    if captured is None or captured.status is not TimestampStatus.VALID or captured.value is None:
        return "unknown", "capture_time_missing_or_invalid"
    if captured.value > cutoff:
        return "ineligible", "captured_after_audit_at"
    for item in observation.timestamps:
        field = item.field_name.casefold()
        if field.endswith(_TIMESTAMP_FIELDS_NOT_OCCURRENCE) or field in {"expires_at", "expiry_date"}:
            continue
        parsed = item.parsed
        if parsed.status is not TimestampStatus.VALID or parsed.value is None:
            return "unknown", "inner_timestamp_missing_or_invalid"
        if parsed.value > cutoff:
            return "ineligible", "inner_timestamp_after_audit_at"
    return "eligible", None


def _observation_ref(observation: ExtractedObservation, *, field_name: str | None = None,
                     raw_value: object = None) -> PolicyEvidenceReference:
    captured = _capture_value(observation)
    timestamps = tuple(sorted((item.field_name, item.raw_value,
                               item.parsed.value, item.parsed.status.value)
                              for item in observation.timestamps))
    return PolicyEvidenceReference("evidence", observation.file_id, observation.source_path,
        observation_id=observation.observation_id, locator=observation.locator,
        field_name=field_name, raw_value=None if raw_value is None else str(raw_value),
        captured_at=captured, inner_timestamps=timestamps)


def _rule_ref(rule: PolicyRule) -> PolicyEvidenceReference:
    return PolicyEvidenceReference("deletion_rule", rule.rule_id, rule.source_file,
                                   record_number=rule.record_number)


def _valid_state_evidence(assessment: ResourceAssessment,
                          observations: Mapping[str, ExtractedObservation],
                          category: str, cutoff: datetime) -> tuple[ExtractedObservation, ...]:
    evidences = (*assessment.evidence, *assessment.claims)
    eligible_ids: set[str] = set()
    for evidence in evidences:
        observation_id = evidence.source.observation_id
        observation = observations.get(observation_id or "")
        if observation is None or _category_for(observation, observations) != category:
            continue
        status, _ = _observation_temporal_status(observation, cutoff)
        if status == "eligible":
            eligible_ids.add(observation.observation_id)
    return tuple(observations[key] for key in sorted(eligible_ids))


def _values(records: Iterable[ExtractedObservation], field_names: Iterable[str]) -> list[tuple[object, ExtractedObservation, str]]:
    values: list[tuple[object, ExtractedObservation, str]] = []
    names = tuple(field_names)
    for observation in records:
        fields = observation.normalized_fields
        # Result-bearing records are query/readback claims, not the underlying
        # resource content. They may support scope, but not condition truth.
        if fields.get("result") is not None or fields.get("reported_result") is not None:
            continue
        for name in names:
            value = fields.get(name)
            if value is not None and (not isinstance(value, str) or value.strip()):
                values.append((value, observation, name))
    return values


def _latest_fact(values: list[tuple[object, ExtractedObservation, str]]) -> tuple[str, list[tuple[object, ExtractedObservation, str]]]:
    if not values:
        return "unknown", []
    timed = [(value, obs, field, _capture_value(obs)) for value, obs, field in values]
    if any(captured is None for _, _, _, captured in timed):
        return "unknown", []
    latest = max(captured for _, _, _, captured in timed if captured is not None)
    selected = [(value, obs, field) for value, obs, field, captured in timed if captured == latest]
    return "ok", selected


def _bool_value(value: object) -> bool | None:
    if value is True or (not isinstance(value, str) and value == 1):
        return True
    if value is False or (not isinstance(value, str) and value == 0):
        return False
    if isinstance(value, str):
        token = _norm(value)
        if token in {"true", "yes", "1", "active", "enabled", "held"}:
            return True
        if token in {"false", "no", "0", "inactive", "disabled", "released"}:
            return False
    return None


def _condition_result(status: ConditionStatus, reason: str,
                      facts: Iterable[tuple[object, ExtractedObservation, str]] = ()) -> tuple[ConditionStatus, str, tuple[PolicyEvidenceReference, ...]]:
    refs = tuple(sorted({_observation_ref(obs, field_name=name, raw_value=value)
                         for value, obs, name in facts}, key=lambda ref: (
                             ref.source_id, ref.locator or "", ref.field_name or "", ref.raw_value or "")))
    return status, reason, refs


def _identity_match(identities: IdentityResolutionResult, kind: str, value: object,
                    user_id: str, at: datetime) -> tuple[str, tuple[str, ...]]:
    raw = str(value).strip()
    normalized = raw.casefold() if kind == "email" else raw
    if not normalized:
        return "unknown", ()
    intervals = [item for item in identities.graph.alias_index.get((kind, normalized), ())
                 if item.contains(at)]
    users = tuple(sorted({item.user_id for item in intervals}))
    if len(users) > 1:
        return "conflicting", users
    if not users:
        return "unknown", ()
    return ("match", users) if users[0] == user_id else ("other", users)


def _condition(rule: PolicyRule, records: tuple[ExtractedObservation, ...],
               identities: IdentityResolutionResult, user_id: str, cutoff: datetime,
               current_state: ResourceState | None) -> tuple[ConditionStatus, str, tuple[PolicyEvidenceReference, ...]]:
    condition = " ".join(rule.condition.casefold().split())
    if condition == "always":
        facts = [("Always", observation, "condition") for observation in records]
        return _condition_result(ConditionStatus.SATISFIED, "unconditional_rule", facts)
    if condition != _CONDITIONS_BY_CATEGORY.get(rule.data_category):
        return _condition_result(ConditionStatus.UNKNOWN, "unsupported_policy_condition")

    if rule.data_category == "SUPPORT_MESSAGE":
        values = _values(records, ("shared_context", "contains_shared_context", "order_reference"))
        # Some supplied conversation records carry order context in an explicit
        # sentence rather than a normalized order_reference field (for example,
        # "The affected order includes ..."). Treat only explicit order
        # language as a positive fact; generic text and redacted messages remain
        # unknown.
        text_context = [
            (str(observation.normalized_fields["message_text"]), observation, "message_text")
            for observation in records
            if isinstance(observation.normalized_fields.get("message_text"), str)
            and _EXPLICIT_ORDER_CONTEXT.search(str(observation.normalized_fields["message_text"]))
        ]
        values.extend(text_context)
        if not values:
            return _condition_result(ConditionStatus.UNKNOWN, "shared_context_not_established")
        normalized = {_bool_value(value) for value, _, name in values
                      if name not in {"order_reference", "message_text"}}
        if any(name in {"order_reference", "message_text"} for _, _, name in values):
            normalized.add(True)
        if True in normalized and False in normalized:
            return _condition_result(ConditionStatus.CONFLICTING, "shared_context_claims_conflict", values)
        if None in normalized:
            return _condition_result(ConditionStatus.UNKNOWN, "shared_context_value_unsupported", values)
        only = next(iter(normalized))
        return _condition_result(ConditionStatus.SATISFIED if only else ConditionStatus.NOT_SATISFIED,
                                 "shared_context_explicit", values)

    if rule.data_category == "SUPPORT_ATTACHMENT":
        values = _values(records, ("owner_email", "owner_phone"))
        if not values:
            return _condition_result(ConditionStatus.UNKNOWN, "exclusive_attachment_owner_not_established")
        outcomes: set[str] = set()
        for value, observation, name in values:
            kind = "email" if name.endswith("email") else "phone"
            result, users = _identity_match(identities, kind, value, user_id,
                                            _evidence_time(observation, cutoff))
            outcomes.add("match" if result == "match" else "other" if result == "other" else result)
        if "conflicting" in outcomes or ("match" in outcomes and "other" in outcomes):
            return _condition_result(ConditionStatus.CONFLICTING, "attachment_owner_identity_conflict", values)
        if outcomes == {"match"}:
            return _condition_result(ConditionStatus.SATISFIED, "exclusive_owner_identifier_matches_subject", values)
        if outcomes == {"other"}:
            return _condition_result(ConditionStatus.NOT_SATISFIED, "owner_identifier_resolves_to_other_user", values)
        return _condition_result(ConditionStatus.UNKNOWN, "attachment_owner_identifier_unresolved", values)

    if rule.data_category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
        identifiers = _values(records, ("user_id", "customer_reference", "customer_ref", "subject_reference",
                                        "subject_ref", "subject_key", "email", "email_hash", "phone"))
        if not identifiers:
            return _condition_result(ConditionStatus.UNKNOWN, "attribution_not_established")
        outcomes: set[str] = set()
        for value, observation, name in identifiers:
            kind = "user_id" if name in {"user_id", "customer_reference", "customer_ref", "subject_reference", "subject_ref", "subject_key"} else name
            if kind == "user_id":
                outcomes.add("match" if str(value).strip() == user_id else "other")
            else:
                matched, _ = _identity_match(identities, kind, value, user_id,
                                              _evidence_time(observation, cutoff))
                outcomes.add(matched)
        if "conflicting" in outcomes or ("match" in outcomes and "other" in outcomes):
            return _condition_result(ConditionStatus.CONFLICTING, "attribution_identifiers_conflict", identifiers)
        if "match" in outcomes:
            return _condition_result(ConditionStatus.SATISFIED, "direct_identifier_links_record_to_subject", identifiers)
        if outcomes == {"other"}:
            return _condition_result(ConditionStatus.NOT_SATISFIED, "identifiers_resolve_to_other_user", identifiers)
        return _condition_result(ConditionStatus.UNKNOWN, "attribution_identity_unresolved", identifiers)

    if rule.data_category == "EMAIL_DELIVERY_LOG":
        values = _values(records, ("email", "customer_email", "owner_email", "requester_email"))
        if not values:
            return _condition_result(ConditionStatus.UNKNOWN, "email_presence_not_established")
        outcomes = {_identity_match(identities, "email", value, user_id,
                                    _evidence_time(observation, cutoff))[0]
                    for value, observation, _ in values}
        if "conflicting" in outcomes or ("match" in outcomes and "other" in outcomes):
            return _condition_result(ConditionStatus.CONFLICTING, "email_identity_evidence_conflicts", values)
        if "match" in outcomes:
            return _condition_result(ConditionStatus.SATISFIED, "log_email_matches_subject_alias", values)
        if outcomes == {"other"}:
            return _condition_result(ConditionStatus.NOT_SATISFIED, "log_email_resolves_to_other_user", values)
        return _condition_result(ConditionStatus.UNKNOWN, "log_email_identity_unresolved", values)

    if rule.data_category == "SECURITY_AUDIT_LOG":
        values = _values(records, ("retention_until", "retained_until"))
        fact_status, latest = _latest_fact(values)
        if fact_status != "ok":
            return _condition_result(ConditionStatus.UNKNOWN, "retention_deadline_missing_or_time_unknown", values)
        parsed_values: list[tuple[datetime | None, object, ExtractedObservation, str]] = []
        for value, observation, name in latest:
            parsed = parse_timestamp(str(value))
            parsed_values.append((parsed.value if parsed.status is TimestampStatus.VALID else None,
                                  value, observation, name))
        if any(value is None for value, _, _, _ in parsed_values):
            return _condition_result(ConditionStatus.UNKNOWN, "retention_deadline_invalid", latest)
        distinct = {value for value, _, _, _ in parsed_values}
        if len(distinct) > 1:
            return _condition_result(ConditionStatus.CONFLICTING, "same_time_retention_deadlines_conflict", latest)
        deadline = next(iter(distinct))
        facts = [(value, obs, name) for _, value, obs, name in parsed_values]
        if deadline > cutoff:
            return _condition_result(ConditionStatus.SATISFIED, "retention_deadline_is_after_audit_cutoff", facts)
        if deadline < cutoff:
            return _condition_result(ConditionStatus.NOT_SATISFIED, "retention_deadline_is_before_audit_cutoff", facts)
        # The supplied contract gives a deadline but does not define whether
        # equality is inside or outside the retention interval.
        return _condition_result(ConditionStatus.UNKNOWN, "retention_deadline_equals_cutoff_boundary", facts)

    if rule.data_category == "LEGAL_HOLD_RECORD":
        values = _values(records, ("legal_hold_active", "hold_active", "legal_hold_status", "hold_status"))
        if not values:
            return _condition_result(ConditionStatus.UNKNOWN, "active_legal_hold_not_established")
        outcomes = {_bool_value(value) for value, _, _ in values}
        if len(outcomes) > 1:
            return _condition_result(ConditionStatus.CONFLICTING, "legal_hold_evidence_conflicts", values)
        outcome = next(iter(outcomes))
        if outcome is None:
            return _condition_result(ConditionStatus.UNKNOWN, "legal_hold_value_unsupported", values)
        return _condition_result(ConditionStatus.SATISFIED if outcome else ConditionStatus.NOT_SATISFIED,
                                 "legal_hold_active_field", values)

    if rule.data_category == "BACKUP_ARCHIVE":
        explicit = _values(records, ("restore_blockable", "can_block_restore"))
        values = explicit or _values(records, ("restore_allowed",))
        if not values:
            return _condition_result(ConditionStatus.UNKNOWN, "restore_block_capability_not_established")
        outcomes = {_bool_value(value) for value, _, name in values}
        if len(outcomes) > 1:
            return _condition_result(ConditionStatus.CONFLICTING, "restore_control_evidence_conflicts", values)
        outcome = next(iter(outcomes))
        if explicit:
            if outcome is None:
                return _condition_result(ConditionStatus.UNKNOWN, "restore_block_capability_unsupported", values)
            return _condition_result(ConditionStatus.SATISFIED if outcome else ConditionStatus.NOT_SATISFIED,
                                     "explicit_restore_block_capability", values)
        # restore_allowed=False establishes BLOCKED state, not a general
        # capability. Only use it when current state reconstruction agrees.
        if outcome is False and current_state is ResourceState.BLOCKED:
            return _condition_result(ConditionStatus.SATISFIED, "restore_is_explicitly_blocked_at_cutoff", values)
        return _condition_result(ConditionStatus.UNKNOWN, "restore_allowed_does_not_establish_block_capability", values)

    if rule.data_category == "ACCOUNT_TOMBSTONE":
        fields = _values(records, ("account_status", "user_id", "subject_reference", "customer_reference"))
        statuses = {_norm(value) for value, _, name in fields if name == "account_status"}
        stable_refs = [item for item in fields if item[2] in {"user_id", "subject_reference", "customer_reference"}
                       and str(item[0]).strip() == user_id]
        if len(statuses) > 1:
            return _condition_result(ConditionStatus.CONFLICTING, "account_status_conflicts", fields)
        if statuses and next(iter(statuses)) not in {"deleted", "closed", "tombstoned"}:
            return _condition_result(ConditionStatus.NOT_SATISFIED, "account_not_evidenced_as_deleted", fields)
        if statuses and stable_refs:
            return _condition_result(ConditionStatus.SATISFIED, "deleted_account_has_stable_subject_reference", fields)
        return _condition_result(ConditionStatus.UNKNOWN, "tombstone_account_or_stable_reference_unestablished", fields)

    # Unknown rule text/category combinations must never silently inherit a
    # condition implementation from another rule.
    return _condition_result(ConditionStatus.UNKNOWN, "unsupported_policy_condition")


def _decision_status(condition_status: ConditionStatus) -> DecisionStatus:
    return {
        ConditionStatus.SATISFIED: DecisionStatus.APPLIES,
        ConditionStatus.NOT_SATISFIED: DecisionStatus.DOES_NOT_APPLY,
        ConditionStatus.UNKNOWN: DecisionStatus.UNRESOLVED,
        ConditionStatus.CONFLICTING: DecisionStatus.CONFLICTING,
    }[condition_status]


def _decision_conflicts(decisions: Iterable[PolicyDecision]) -> tuple[PolicyConflict, ...]:
    groups: dict[tuple[str, ResourceKey, str], list[PolicyDecision]] = {}
    for decision in decisions:
        groups.setdefault((decision.case_id, decision.resource_key, decision.data_category), []).append(decision)
    conflicts = []
    for (case_id, key, category), items in sorted(groups.items(), key=lambda item: (
            item[0][0], item[0][1].system_ids, item[0][1].resource_id, item[0][2])):
        active = [item for item in items if item.status in {
            DecisionStatus.APPLIES, DecisionStatus.UNRESOLVED, DecisionStatus.CONFLICTING
        }]
        actions = tuple(sorted({item.required_action for item in active}, key=lambda action: action.value))
        if len(actions) > 1:
            rule_ids = tuple(sorted(item.rule.rule_id for item in active))
            conflicts.append(PolicyConflict(case_id, key, category, rule_ids, actions))
    return tuple(conflicts)


def evaluate_deletion_policy(
    ingestion: IngestionResult,
    identities: IdentityResolutionResult,
    extraction: EvidenceExtractionResult,
    case_states: Iterable[CaseStateSnapshot],
) -> PolicyEvaluation:
    """Evaluate actual supplied rules over per-case, cutoff-filtered Phase 6 state.

    This API intentionally does not classify request intent. Returned duties
    are conditional on the request authorizing deletion; a later request-intent
    stage must gate their use.
    """
    rules, rule_diagnostics = load_policy_rules(ingestion)
    observations = {item.observation_id: item for item in extraction.observations}
    observation_resolutions = {item.target_id: item for item in identities.observation_resolutions}
    request_resolutions = {item.target_id: item for item in identities.request_resolutions}
    rules_by_category: dict[str, list[PolicyRule]] = {}
    for rule in rules:
        rules_by_category.setdefault(rule.data_category, []).append(rule)

    results: list[PolicyCaseResult] = []
    for case_state in sorted(case_states, key=lambda item: item.case_id):
        diagnostics: set[str] = set()
        if case_state.snapshot is None or case_state.user_id is None:
            reason = case_state.diagnostic or "request_subject_not_confirmed"
            results.append(PolicyCaseResult(case_state.case_id, case_state.subject_status,
                case_state.user_id, None, False, (), (), (), (), (), (), (reason,)))
            continue

        snapshot = case_state.snapshot
        cutoff = snapshot.audit_at
        if cutoff.tzinfo is None or cutoff.utcoffset() is None:
            results.append(PolicyCaseResult(case_state.case_id, case_state.subject_status,
                case_state.user_id, None, False, (), (), snapshot.extraction_gap_file_ids, (), (), (),
                ("invalid_audit_at",)))
            continue
        cutoff = cutoff.astimezone(snapshot.audit_at.tzinfo)
        request_resolution = request_resolutions.get(case_state.case_id)
        request_identity_conflicts = request_resolution.conflicts if request_resolution else ()
        if request_identity_conflicts:
            diagnostics.add("request_identity_conflict")
        grouped: dict[tuple[ResourceKey, str], dict[str, Any]] = {}
        represented_observation_ids: set[str] = set()
        for assessment in snapshot.assessments:
            evidence_items = (*assessment.evidence, *assessment.claims)
            by_id: dict[str, StateEvidence] = {}
            for item in evidence_items:
                observation_id = item.source.observation_id
                observation = observations.get(observation_id or "")
                if observation is None:
                    continue
                resolution = observation_resolutions.get(observation.observation_id)
                if (resolution is None or resolution.status is not ResolutionStatus.CONFIRMED
                        or resolution.matched_user_id != case_state.user_id):
                    continue
                category = _category_for(observation, observations)
                if category not in rules_by_category:
                    continue
                status, why = _observation_temporal_status(observation, cutoff)
                if status == "ineligible":
                    diagnostics.add(why or "temporally_ineligible_evidence")
                    continue
                if status == "eligible":
                    by_id[observation.observation_id] = item
                    represented_observation_ids.add(observation.observation_id)
                else:
                    diagnostics.add(why or "evidence_time_unknown")
            for observation_id, state_evidence in by_id.items():
                observation = observations[observation_id]
                category = _category_for(observation, observations)
                group = grouped.setdefault((assessment.key, category), {"observations": {}, "states": {}})
                group["observations"][observation_id] = observation
                group["states"][assessment.domain] = assessment.state

        # Policy context can be established by a confirmed, cutoff-eligible
        # resource observation even when the state layer has no timestamped
        # event to attach it to (for example, a captured support conversation).
        # This adds the obligation/context only; it never supplies resource
        # state, so adjudication remains unresolved until state is proven.
        for observation in extraction.observations:
            if observation.observation_id in represented_observation_ids or not observation.resource_id:
                continue
            resolution = observation_resolutions.get(observation.observation_id)
            if (resolution is None or resolution.status is not ResolutionStatus.CONFIRMED
                    or resolution.matched_user_id != case_state.user_id):
                continue
            category = _category_for(observation, observations)
            if category not in rules_by_category:
                continue
            status, why = _observation_temporal_status(observation, cutoff)
            if status != "eligible":
                diagnostics.add(why or "evidence_time_unknown")
                continue
            fields = observation.normalized_fields
            systems = {observation.system_id} if observation.system_id else set()
            for name in ("system_id", "system", "service", "origin_system", "source_system", "target_system"):
                value = fields.get(name)
                if value is not None and str(value).strip():
                    systems.add(str(value).strip())
            resource_type = next((str(fields[name]).strip() for name in
                                  ("resource_type", "record_type", "data_category", "category",
                                   "table_name", "collection_name")
                                  if fields.get(name) is not None and str(fields[name]).strip()), category)
            scope = tuple(sorted(systems))
            discriminator = "" if scope else f"{observation.file_id}:{observation.observation_id}"
            key = ResourceKey(case_state.user_id, scope, observation.resource_id, resource_type, discriminator)
            group = grouped.setdefault((key, category), {"observations": {}, "states": {}})
            group["observations"][observation.observation_id] = observation

        decisions: list[PolicyDecision] = []
        for (resource_key, category), candidate in sorted(grouped.items(), key=lambda item: (
                item[0][1], item[0][0].system_ids, item[0][0].resource_id, item[0][0].resource_type or "")):
            records = tuple(candidate["observations"][key] for key in sorted(candidate["observations"]))
            state_values = tuple(sorted(candidate["states"].items(), key=lambda item: item[0].value))
            # RETAIN/BACKUP condition reads control state but the policy duty is
            # retained as its own decision/action.
            current_state = next((state for domain, state in state_values if domain is StateDomain.CONTROL), None)
            for rule in rules_by_category.get(category, ()):
                condition_status, reason, condition_refs = _condition(
                    rule, records, identities, case_state.user_id, cutoff, current_state)
                evidence_refs = tuple(sorted({_observation_ref(record) for record in records}, key=lambda ref: (
                    ref.source_id, ref.locator or "", ref.observation_id or "")))
                refs = (_rule_ref(rule), *evidence_refs)
                uncertainty = (reason,) if condition_status in {ConditionStatus.UNKNOWN, ConditionStatus.CONFLICTING} else ()
                decisions.append(PolicyDecision(case_state.case_id, resource_key, category, rule,
                    _decision_status(condition_status), condition_status, rule.required_action, state_values,
                    tuple(refs), condition_refs, uncertainty))

        conflicts = _decision_conflicts(decisions)
        if conflicts:
            diagnostics.add("conflicting_policy_obligations")
        if any(decision.status is DecisionStatus.UNRESOLVED for decision in decisions):
            diagnostics.add("policy_condition_unresolved")
        if any(decision.status is DecisionStatus.CONFLICTING for decision in decisions):
            diagnostics.add("policy_evidence_conflicting")

        temporal_refs: list[PolicyEvidenceReference] = []
        unresolved_identity_refs: list[PolicyEvidenceReference] = []
        for observation in extraction.observations:
            resolution = observation_resolutions.get(observation.observation_id)
            if resolution is not None and resolution.status is ResolutionStatus.CONFIRMED \
                    and resolution.matched_user_id == case_state.user_id:
                status, why = _observation_temporal_status(observation, cutoff)
                if status in {"ineligible", "unknown"}:
                    temporal_refs.append(_observation_ref(observation))
                    diagnostics.add(why or "temporal_eligibility_unknown")
            elif resolution is not None and case_state.user_id in resolution.candidate_user_ids \
                    and resolution.status in {ResolutionStatus.AMBIGUOUS, ResolutionStatus.UNRESOLVED}:
                unresolved_identity_refs.append(_observation_ref(observation))
                diagnostics.add("ambiguous_or_unresolved_identity_evidence")

        if snapshot.extraction_gap_file_ids:
            diagnostics.add("extraction_gaps_present")
        results.append(PolicyCaseResult(case_state.case_id, case_state.subject_status,
            case_state.user_id, cutoff, False, tuple(sorted(decisions, key=lambda item: (
                item.data_category, item.resource_key.system_ids, item.resource_key.resource_id,
                item.rule.rule_id))), conflicts, snapshot.extraction_gap_file_ids,
            tuple(sorted(temporal_refs, key=lambda ref: (ref.source_id, ref.locator or ""))),
            tuple(sorted(unresolved_identity_refs, key=lambda ref: (ref.source_id, ref.locator or ""))),
            tuple(request_identity_conflicts), tuple(sorted(diagnostics))))

    return PolicyEvaluation(rules, tuple(results), rule_diagnostics)


__all__ = [
    "ConditionStatus", "DecisionStatus", "PolicyAction", "PolicyCaseResult", "PolicyConflict",
    "PolicyDecision", "PolicyDiagnostic", "PolicyEvaluation", "PolicyEvidenceReference",
    "PolicyRule", "evaluate_deletion_policy", "load_policy_rules",
]
