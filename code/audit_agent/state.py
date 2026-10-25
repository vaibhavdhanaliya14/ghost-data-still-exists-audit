"""Fail-closed resource-state snapshots at audit cutoffs (Phase 6).

Only attributable, temporally eligible evidence is grouped under a subject.
Activity/log statements remain claims. A structured SQL/JSON row is evidence of
state at its manifest capture time; it is not evidence that the state persisted
through a later audit cutoff without a snapshot at that cutoff.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Iterable, Mapping

from .identity import IdentityResolutionResult, ResolutionStatus
from .models import IngestionResult, ParsedTimestamp, TimestampStatus
from .timeline import (
    EventCategory, Timeline, TimelineConflict, TimelineEvent, TimelineSource, UnplacedObservation,
)


class ResourceState(str, Enum):
    PRESENT = "present"
    DELETED = "deleted"
    ABSENT = "absent"
    REDACTED = "redacted"
    ANONYMIZED = "anonymized"
    RETAINED = "retained"
    TOMBSTONED = "tombstoned"
    ACTIVE = "active"
    DISABLED = "disabled"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"
    CONFLICTING = "conflicting"


class StateDomain(str, Enum):
    LIFECYCLE = "lifecycle"
    CONTROL = "control"


@dataclass(frozen=True)
class ResourceKey:
    user_id: str
    system_ids: tuple[str, ...]
    resource_id: str
    resource_type: str | None = None
    scope_discriminator: str = ""


@dataclass(frozen=True)
class StateEvidence:
    evidence_key: str
    state: ResourceState | None
    domain: StateDomain
    source: TimelineSource
    event_time: ParsedTimestamp | None
    capture_time: ParsedTimestamp | None
    state_observed_at: datetime | None
    time_basis: str
    field_name: str | None
    raw_state_value: str | None
    event_category: EventCategory | None
    role: str
    relationship_context: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class ResourceAssessment:
    key: ResourceKey
    domain: StateDomain
    audit_at: datetime
    state: ResourceState
    last_observed_state: ResourceState | None
    last_observed_at: datetime | None
    evidence: tuple[StateEvidence, ...]
    claims: tuple[StateEvidence, ...]
    conflicts: tuple[tuple[datetime, tuple[str, ...]], ...]
    uncertainty: tuple[str, ...]
    relationship_context: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class StateDiagnostic:
    code: str
    message: str
    event_id: str | None = None
    observation_id: str | None = None


@dataclass(frozen=True)
class StateSnapshot:
    audit_at: datetime
    assessments: tuple[ResourceAssessment, ...]
    unlinked_event_ids: tuple[str, ...]
    unscoped_event_ids: tuple[str, ...]
    unplaced_observation_ids: tuple[str, ...]
    extraction_gap_file_ids: tuple[str, ...]
    timeline_conflicts: tuple[TimelineConflict, ...]
    unlinked_conflicts: tuple[TimelineConflict, ...]
    diagnostics: tuple[StateDiagnostic, ...]
    global_extraction_gap_file_ids: tuple[str, ...] = ()

    def for_user(self, user_id: str) -> tuple[ResourceAssessment, ...]:
        return tuple(item for item in self.assessments if item.key.user_id == user_id)

    def find(
        self,
        user_id: str,
        system_ids: Iterable[str],
        resource_id: str,
        resource_type: str | None = None,
        domain: StateDomain = StateDomain.LIFECYCLE,
        scope_discriminator: str | None = None,
    ) -> ResourceAssessment:
        systems = tuple(sorted(set(system_ids)))
        matching = [item for item in self.assessments
                    if item.key.user_id == user_id and item.key.system_ids == systems
                    and item.key.resource_id == resource_id and item.key.resource_type == resource_type
                    and item.domain is domain]
        if scope_discriminator is not None:
            matching = [item for item in matching if item.key.scope_discriminator == scope_discriminator]
        if len(matching) == 1:
            return matching[0]
        key = ResourceKey(user_id, systems, resource_id, resource_type,
                          scope_discriminator or (matching[0].key.scope_discriminator if matching else ""))
        if len(matching) > 1:
            return ResourceAssessment(key, domain, self.audit_at, ResourceState.UNKNOWN, None,
                                      None, (), (), (), ("resource_scope_is_ambiguous_without_system",), ())
        # A caller's query can ask about a known resource even when this cutoff
        # has no eligible evidence. Represent that result as UNKNOWN, never ABSENT.
        return ResourceAssessment(key, domain, self.audit_at, ResourceState.UNKNOWN, None,
                                  None, (), (), (), ("no_eligible_evidence_for_resource",), ())


@dataclass(frozen=True)
class CaseStateSnapshot:
    case_id: str
    subject_status: str
    user_id: str | None
    snapshot: StateSnapshot | None
    diagnostic: str | None = None


@dataclass
class _EvidenceGroup:
    evidence: list[StateEvidence]
    claims: list[StateEvidence]
    contexts: set[tuple[str, str]]


_STATE_FIELD_KEYS = ("state", "record_state", "lifecycle_state", "record_status", "deletion_status", "status")
_RESOURCE_TYPE_KEYS = ("resource_type", "record_type", "data_category", "category", "table_name", "collection_name")
_RELATIONSHIP_KEYS = (
    "origin_system", "source_system", "target_system", "replica_of", "primary_resource_id",
    "source_resource_id", "region", "replica", "replica_id", "cluster", "instance", "pod",
)


def _norm(value: object) -> str:
    return str(value).strip().strip("\"'").strip().casefold()


def _state_token(value: object) -> ResourceState | None:
    token = _norm(value).replace("-", "_").replace(" ", "_")
    return {
        "present": ResourceState.PRESENT, "found": ResourceState.PRESENT,
        "deleted": ResourceState.DELETED, "delete": ResourceState.DELETED,
        "absent": ResourceState.ABSENT,
        "redacted": ResourceState.REDACTED, "anonymized": ResourceState.ANONYMIZED,
        "anonymised": ResourceState.ANONYMIZED, "retained": ResourceState.RETAINED,
        "tombstoned": ResourceState.TOMBSTONED, "tombstone": ResourceState.TOMBSTONED,
        "active": ResourceState.ACTIVE, "enabled": ResourceState.ACTIVE,
        "disabled": ResourceState.DISABLED, "inactive": ResourceState.DISABLED,
        "blocked": ResourceState.BLOCKED, "unknown": ResourceState.UNKNOWN,
        "conflicting": ResourceState.CONFLICTING,
    }.get(token)


def _boolean(value: object) -> bool | None:
    if value is True or value == 1 and not isinstance(value, str):
        return True
    if value is False or value == 0 and not isinstance(value, str):
        return False
    if isinstance(value, str):
        token = _norm(value)
        if token in {"true", "yes", "1", "enabled", "active"}:
            return True
        if token in {"false", "no", "0", "disabled", "inactive"}:
            return False
    return None


def _type_and_relationships(fields: Mapping[str, object]) -> tuple[str | None, tuple[tuple[str, str], ...]]:
    resource_type = next((str(fields[key]).strip() for key in _RESOURCE_TYPE_KEYS
                          if fields.get(key) is not None and str(fields[key]).strip()), None)
    context = tuple(sorted((key, str(fields[key]).strip()) for key in _RELATIONSHIP_KEYS
                           if fields.get(key) is not None and str(fields[key]).strip()))
    return resource_type, context


def _is_direct_snapshot(event: TimelineEvent) -> bool:
    if event.role != "observation" or event.source.source_kind != "evidence":
        return False
    fmt = event.source.file_format.casefold() if event.source.file_format else ""
    fields = event.raw_fields
    if fmt == "sql":
        return True
    if fmt == "json":
        return _is_direct_json_record(fields)
    return False


def _is_direct_json_record(fields: Mapping[str, object]) -> bool:
    # JSON may encode either a snapshot record or an operational event. The
    # latter must not be treated as proof that its target record is present.
    has_resource_shape = any(fields.get(key) is not None for key in
                             ("record_type", "resource_type", "data_category", "user_id",
                              "customer_reference", "subject_reference", "email", "phone"))
    telemetry = any(fields.get(key) is not None for key in
                    ("line_text", "level", "logger", "event", "event_type", "event_name",
                     "operation", "action", "message", "request_id", "requestid",
                     # Query-result payloads describe what a lookup returned;
                     # they are not themselves the resource row being queried.
                     "result", "reported_result"))
    return has_resource_shape and not telemetry


def _domain(fields: Mapping[str, object]) -> StateDomain:
    record_type = _norm(fields.get("record_type", ""))
    if (record_type in {"data_flow", "connector_configuration", "connector_config"}
            or any(key in fields for key in ("restore_allowed", "restore_blocked", "flow_enabled"))
            or ("enabled" in fields and any(key in fields for key in ("connector_name", "connector_id", "flow_id")))):
        return StateDomain.CONTROL
    return StateDomain.LIFECYCLE


def _state_from_fields(fields: Mapping[str, object], domain: StateDomain,
                       timestamp_evidence: tuple[tuple[str, ParsedTimestamp], ...] = ()
                       ) -> tuple[ResourceState | None, str | None, str | None]:
    # The supplied deleted_customer_references collection stores intentional
    # account tombstones. Its explicit DELETED account_status describes the
    # tombstone lifecycle; the separate policy/adjudication check still
    # verifies that prohibited direct identifiers are absent.
    if _norm(fields.get("collection_name", "")) == "deleted_customer_references":
        account_status = fields.get("account_status")
        if account_status is not None:
            token = _norm(account_status).replace("-", "_").replace(" ", "_")
            if token in {"deleted", "tombstoned", "tombstone"}:
                return ResourceState.TOMBSTONED, "account_status", str(account_status)
            return None, "account_status", str(account_status)

    if domain is StateDomain.CONTROL:
        for key in ("restore_blocked", "blocked"):
            if key in fields:
                value = _boolean(fields[key])
                if value is not None:
                    return (ResourceState.BLOCKED if value else ResourceState.ACTIVE), key, str(fields[key])
        for key in ("enabled", "flow_enabled", "active", "restore_allowed"):
            if key in fields:
                value = _boolean(fields[key])
                if value is not None:
                    if key == "restore_allowed":
                        return (ResourceState.ACTIVE if value else ResourceState.BLOCKED), key, str(fields[key])
                    return (ResourceState.ACTIVE if value else ResourceState.DISABLED), key, str(fields[key])

    for key in _STATE_FIELD_KEYS:
        if fields.get(key) is not None:
            state = _state_token(fields[key])
            if state is not None:
                return state, key, str(fields[key])

    boolean_fields = (
        ("is_deleted", ResourceState.DELETED), ("deleted", ResourceState.DELETED),
        ("is_redacted", ResourceState.REDACTED), ("redacted", ResourceState.REDACTED),
        ("is_anonymized", ResourceState.ANONYMIZED), ("anonymized", ResourceState.ANONYMIZED),
        ("is_tombstone", ResourceState.TOMBSTONED), ("tombstoned", ResourceState.TOMBSTONED),
    )
    for key, positive_state in boolean_fields:
        if key in fields:
            value = _boolean(fields[key])
            if value is not None:
                return (positive_state if value else ResourceState.PRESENT), key, str(fields[key])

    timestamp_states = {
        "deleted_at": ResourceState.DELETED, "redacted_at": ResourceState.REDACTED,
        "anonymized_at": ResourceState.ANONYMIZED, "tombstoned_at": ResourceState.TOMBSTONED,
    }
    for time_field, state in timestamp_states.items():
        raw_time = fields.get(time_field)
        if raw_time is None or not str(raw_time).strip():
            continue
        parsed = [value for name, value in timestamp_evidence if name.casefold() == time_field]
        if parsed and all(value.status is TimestampStatus.VALID for value in parsed):
            return state, time_field, str(raw_time)
        return None, time_field, str(raw_time)

    if _norm(fields.get("record_type", "")) == "account_tombstone":
        return ResourceState.TOMBSTONED, "record_type", str(fields["record_type"])

    if domain is StateDomain.CONTROL:
        return None, None, None

    # A nonempty, unsupported state token is not a license to infer presence.
    for key in _STATE_FIELD_KEYS:
        if fields.get(key) is not None and str(fields[key]).strip():
            return None, key, str(fields[key])

    # An extracted SQL/JSON record proves that a matching row/object existed in
    # that captured snapshot. It does not prove absence when no row was found.
    return ResourceState.PRESENT, None, None


def _direct_state(event: TimelineEvent, domain: StateDomain) -> tuple[ResourceState | None, str | None, str | None]:
    if not _is_direct_snapshot(event):
        return None, None, None
    return _state_from_fields(event.raw_fields, domain, event.supporting_timestamps)


def _state_evidence(event: TimelineEvent, domain: StateDomain) -> StateEvidence:
    state, field_name, raw_value = _direct_state(event, domain)
    direct_snapshot = _is_direct_snapshot(event)
    if direct_snapshot and state is None:
        state = ResourceState.UNKNOWN
    captured = event.capture_time
    state_time = captured.value if captured and captured.status is TimestampStatus.VALID else None
    time_basis = "manifest_capture_snapshot" if state_time is not None else "unknown"
    return StateEvidence(
        event.event_id, state, domain, event.source, event.event_time, captured,
        state_time, time_basis, field_name, raw_value, event.category, event.role,
        _type_and_relationships(event.raw_fields)[1],
    )


def _unplaced_direct_evidence(item: UnplacedObservation) -> tuple[ResourceKey, StateDomain, StateEvidence] | None:
    observation = item.observation
    subject = item.subject
    if subject.status != ResolutionStatus.CONFIRMED.value or not subject.user_id:
        return None
    fmt = observation.file_format.casefold()
    if fmt not in {"sql", "json"}:
        return None
    fields = observation.raw_fields
    has_resource_shape = fmt == "sql" or _is_direct_json_record(fields)
    if not has_resource_shape or not observation.resource_id:
        return None
    captured = observation.captured_at
    if captured is None or captured.status is not TimestampStatus.VALID or captured.value is None:
        return None
    resource_type, context = _type_and_relationships(fields)
    domain = _domain(fields)
    state, state_field, raw_state = _state_from_fields(fields, domain)
    if state is None:
        state = ResourceState.UNKNOWN
    source = TimelineSource("evidence", observation.source_path, file_id=observation.file_id,
                            observation_id=observation.observation_id, locator=observation.locator,
                            extraction_method=observation.extraction_method, file_format=fmt)
    evidence = StateEvidence(
        observation.observation_id, state, domain, source, None, captured,
        captured.value, "manifest_capture_snapshot_without_inner_timestamp", state_field, raw_state,
        None, "observation", context,
    )
    systems = {observation.system_id} if observation.system_id else set()
    for name in ("system_id", "system", "service", "origin_system", "source_system", "target_system"):
        if fields.get(name) is not None and str(fields[name]).strip():
            systems.add(str(fields[name]).strip())
    key = ResourceKey(subject.user_id, tuple(sorted(systems)),
                      observation.resource_id, resource_type,
                      "" if systems else f"{observation.file_id}:{observation.observation_id}")
    return key, domain, evidence


def _snapshot_events(
    timeline: Timeline,
    audit_at: datetime,
) -> tuple[tuple[TimelineEvent, ...], tuple[str, ...]]:
    eligible = timeline.eligible_at(audit_at)
    unlinked = tuple(sorted(event.event_id for event in eligible
                            if event.subject.status != ResolutionStatus.CONFIRMED.value
                            or not event.subject.user_id))
    return eligible, unlinked


def reconstruct_resource_states(timeline: Timeline, audit_at: datetime) -> StateSnapshot:
    """Reconstruct state supported at one inclusive, timezone-aware cutoff.

    Old snapshots remain available as last-observed state, but do not silently
    become current at a later cutoff. Without an explicit snapshot exactly at
    audit_at, the cutoff state is UNKNOWN and last_observed_state carries the
    prior evidence for downstream review.
    """
    if audit_at.tzinfo is None or audit_at.utcoffset() is None:
        raise ValueError("audit_at must be timezone-aware")
    cutoff = audit_at.astimezone(timezone.utc)
    eligible, unlinked = _snapshot_events(timeline, cutoff)
    unlinked_set = set(unlinked)
    eligible_ids = {event.event_id for event in eligible}
    cutoff_conflicts = tuple(conflict for conflict in timeline.conflicts
                             if conflict.event_ids and set(conflict.event_ids).issubset(eligible_ids))
    unlinked_conflicts = tuple(conflict for conflict in cutoff_conflicts
                               if set(conflict.event_ids).intersection(unlinked_set))
    groups: dict[tuple[ResourceKey, StateDomain], _EvidenceGroup] = {}
    unscoped: set[str] = set()
    diagnostics: list[StateDiagnostic] = []

    def add(key: ResourceKey, domain: StateDomain, evidence: StateEvidence) -> None:
        group = groups.setdefault((key, domain), _EvidenceGroup([], [], set()))
        bucket = group.evidence if evidence.state is not None else group.claims
        # Several timeline timestamps can derive from one source observation.
        # Count that record only once for the same state and capture instant.
        dedupe = (evidence.evidence_key, evidence.state, evidence.state_observed_at, evidence.field_name)
        if not any((old.evidence_key, old.state, old.state_observed_at, old.field_name) == dedupe for old in bucket):
            bucket.append(evidence)
        group.contexts.update(evidence.relationship_context)

    for event in eligible:
        if event.subject.status != ResolutionStatus.CONFIRMED.value or not event.subject.user_id:
            continue
        if not event.resource_id:
            unscoped.add(event.event_id)
            diagnostics.append(StateDiagnostic("eligible_event_without_resource_id",
                                               "Eligible subject-linked event has no resource identifier.", event_id=event.event_id))
            continue
        resource_type, relationships = _type_and_relationships(event.raw_fields)
        discriminator = "" if event.system_ids else (
            f"{event.source.file_id or event.source.source_file}:"
            f"{event.source.observation_id or event.source.locator or event.source.record_id or event.event_id}"
        )
        key = ResourceKey(event.subject.user_id, event.system_ids, event.resource_id,
                          resource_type, discriminator)
        domain = _domain(event.raw_fields)
        evidence = _state_evidence(event, domain)
        # Claim-only and non-direct evidence remains attached but cannot set state.
        if evidence.state is None:
            evidence = StateEvidence(
                evidence.evidence_key, None, evidence.domain, evidence.source,
                evidence.event_time, evidence.capture_time, None, "claim_only",
                None, None, evidence.event_category, evidence.role, relationships,
            )
        add(key, domain, evidence)

    # Direct snapshot rows with no explicit event timestamp are not timeline
    # events, but their manifest capture time can explicitly time the snapshot.
    # Preserve the absence of an inner event timestamp in StateEvidence.
    for unplaced in timeline.unplaced_observations:
        obs = unplaced.observation
        subject = unplaced.subject
        if subject.status != ResolutionStatus.CONFIRMED.value or not subject.user_id:
            continue
        if not obs.resource_id:
            continue
        parsed_capture = obs.captured_at
        if parsed_capture is None or parsed_capture.status is not TimestampStatus.VALID or parsed_capture.value is None:
            continue
        if parsed_capture.value > cutoff:
            continue
        result = _unplaced_direct_evidence(unplaced)
        if result is None:
            continue
        key, domain, evidence = result
        add(key, domain, evidence)

    assessments: list[ResourceAssessment] = []
    for (key, domain), group in sorted(groups.items(), key=lambda pair: (
        pair[0][0].user_id, pair[0][0].system_ids, pair[0][0].resource_id,
        pair[0][0].resource_type or "", pair[0][0].scope_discriminator, pair[0][1].value,
    )):
        known = [item for item in group.evidence if item.state_observed_at is not None]
        latest_time = max((item.state_observed_at for item in known), default=None)
        latest = [item for item in known if item.state_observed_at == latest_time] if latest_time else []
        latest_states = sorted({item.state for item in latest if item.state is not None}, key=lambda state: state.value)
        conflicts: list[tuple[datetime, tuple[str, ...]]] = []
        if latest_time is not None:
            for time in sorted({item.state_observed_at for item in known if item.state_observed_at is not None}):
                values = tuple(sorted({item.state.value for item in known
                                       if item.state_observed_at == time and item.state is not None}))
                if len(values) > 1:
                    conflicts.append((time, values))
        last_state = ResourceState.CONFLICTING if len(latest_states) > 1 else (
            latest_states[0] if latest_states else None)
        uncertainty: set[str] = set()
        if not group.evidence:
            cutoff_state = ResourceState.UNKNOWN
            uncertainty.add("no_direct_state_observation")
        elif latest_time is None:
            cutoff_state = ResourceState.UNKNOWN
            uncertainty.add("state_observation_time_unknown")
        elif len(latest_states) > 1:
            cutoff_state = ResourceState.CONFLICTING if latest_time == cutoff else ResourceState.UNKNOWN
            uncertainty.add("conflicting_state_observations_at_latest_time")
        elif latest_time < cutoff:
            cutoff_state = ResourceState.UNKNOWN
            uncertainty.add("last_snapshot_precedes_audit_cutoff")
        else:
            cutoff_state = last_state or ResourceState.UNKNOWN
            if cutoff_state is ResourceState.UNKNOWN:
                uncertainty.add("explicit_unknown_state_observation")
        if group.claims:
            uncertainty.add("claims_do_not_establish_resource_state")
        assessments.append(ResourceAssessment(
            key, domain, cutoff, cutoff_state, last_state, latest_time,
            tuple(sorted(group.evidence, key=_evidence_key)),
            tuple(sorted(group.claims, key=_evidence_key)), tuple(conflicts),
            tuple(sorted(uncertainty)), tuple(sorted(group.contexts)),
        ))

    diagnostics.sort(key=lambda item: (item.code, item.event_id or "", item.observation_id or ""))
    # A failed file captured after this snapshot's audit_at is not eligible
    # evidence for the historical decision and cannot create a case-level
    # extraction gap. Keep unknown/malformed capture times fail-closed.
    eligible_gap_ids = tuple(sorted(
        gap.file_id for gap in timeline.extraction_gaps
        if gap.captured_at is None
        or gap.captured_at.status is not TimestampStatus.VALID
        or gap.captured_at.value is None
        or gap.captured_at.value <= cutoff
    ))
    return StateSnapshot(
        cutoff, tuple(assessments), unlinked, tuple(sorted(unscoped)),
        tuple(sorted(timeline.unplaced_observation_ids)),
        (), cutoff_conflicts, unlinked_conflicts, tuple(diagnostics), eligible_gap_ids,
    )


def _evidence_key(evidence: StateEvidence) -> tuple[object, ...]:
    return (evidence.state_observed_at or datetime.max.replace(tzinfo=timezone.utc),
            evidence.state.value if evidence.state else "", evidence.source.source_file,
            evidence.source.file_id or "", evidence.source.observation_id or "",
            evidence.source.record_id or "", evidence.evidence_key)


def _values_contain_gap_reference(value: object, file_id: str, source_path: str) -> bool:
    """Match only explicit file IDs or full manifest paths in participant evidence."""
    if isinstance(value, Mapping):
        return any(_values_contain_gap_reference(item, file_id, source_path)
                   for item in value.values())
    if isinstance(value, (tuple, list, set, frozenset)):
        return any(_values_contain_gap_reference(item, file_id, source_path) for item in value)
    if not isinstance(value, str):
        return False
    normalized = value.strip().replace("\\", "/")
    expected_path = source_path.strip().replace("\\", "/")
    if normalized == file_id or normalized == expected_path:
        return True
    # Full token matching avoids partial collisions such as evidence_3/evidence_30.
    return re.search(rf"(?<![A-Za-z0-9_-]){re.escape(file_id)}(?![A-Za-z0-9_-])", normalized) is not None


def _case_linked_extraction_gap_ids(
    timeline: Timeline, user_id: str, audit_at: datetime,
    globally_eligible_gap_ids: Iterable[str],
) -> tuple[str, ...]:
    """Return only eligible failed files explicitly referenced by evidence for this user.

    Unlinked failures remain available through the global snapshot/report. They
    are not discarded, but are not promoted to material uncertainty for every case.
    """
    eligible_ids = set(globally_eligible_gap_ids)
    if not eligible_ids:
        return ()
    gaps = {gap.file_id: gap for gap in timeline.extraction_gaps if gap.file_id in eligible_ids}
    linked: set[str] = set()
    for event in timeline.eligible_at(audit_at):
        if event.source.source_kind != "evidence" or event.subject.status != ResolutionStatus.CONFIRMED.value \
                or event.subject.user_id != user_id:
            continue
        for file_id, gap in gaps.items():
            if _values_contain_gap_reference(event.raw_fields, file_id, gap.source_path):
                linked.add(file_id)
    for item in timeline.unplaced_observations:
        observation = item.observation
        if item.subject.status != ResolutionStatus.CONFIRMED.value or item.subject.user_id != user_id:
            continue
        captured = observation.captured_at
        if captured is not None and captured.status is TimestampStatus.VALID and captured.value is not None \
                and captured.value > audit_at.astimezone(timezone.utc):
            continue
        for file_id, gap in gaps.items():
            if _values_contain_gap_reference(observation.raw_fields, file_id, gap.source_path):
                linked.add(file_id)
    return tuple(sorted(linked))


def reconstruct_request_states(
    ingestion: IngestionResult,
    identities: IdentityResolutionResult,
    timeline: Timeline,
) -> tuple[CaseStateSnapshot, ...]:
    """Return one independently cutoff-filtered state snapshot per request."""
    requests = ingestion.bundle.tables.get("deletion_requests")
    if requests is None:
        return ()
    resolutions = {item.target_id: item for item in identities.request_resolutions}
    results: list[CaseStateSnapshot] = []
    for record in requests.records:
        case_id = record.raw("case_id") or ""
        resolution = resolutions.get(case_id)
        status = resolution.status.value if resolution else "unresolved"
        user_id = resolution.matched_user_id if resolution and resolution.status is ResolutionStatus.CONFIRMED else None
        parsed = record.typed("audit_at")
        if not isinstance(parsed, ParsedTimestamp) or parsed.status is not TimestampStatus.VALID or parsed.value is None:
            results.append(CaseStateSnapshot(case_id, status, user_id, None, "invalid_audit_at"))
        elif user_id is None:
            results.append(CaseStateSnapshot(case_id, status, None, None, "request_subject_not_confirmed"))
        else:
            snapshot = reconstruct_resource_states(timeline, parsed.value)
            scoped = tuple(item for item in snapshot.assessments if item.key.user_id == user_id)
            case_gap_ids = _case_linked_extraction_gap_ids(
                timeline, user_id, parsed.value, snapshot.global_extraction_gap_file_ids)
            filtered = StateSnapshot(snapshot.audit_at, scoped, snapshot.unlinked_event_ids,
                                     snapshot.unscoped_event_ids, snapshot.unplaced_observation_ids,
                                     case_gap_ids, snapshot.timeline_conflicts,
                                     snapshot.unlinked_conflicts, snapshot.diagnostics,
                                     snapshot.global_extraction_gap_file_ids)
            results.append(CaseStateSnapshot(case_id, status, user_id, filtered))
    return tuple(sorted(results, key=lambda item: item.case_id))


__all__ = [
    "CaseStateSnapshot", "ResourceAssessment", "ResourceKey", "ResourceState",
    "StateDiagnostic", "StateDomain", "StateEvidence", "StateSnapshot",
    "reconstruct_request_states", "reconstruct_resource_states",
]
