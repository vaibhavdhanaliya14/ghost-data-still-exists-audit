"""Deterministic provenance-backed event timeline (Phase 5).

The timeline records evidence claims and timestamped observations. It does not
reconstruct resource state or treat a claimed operation as proof of its result.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping

from .extract import EvidenceExtractionResult, ExtractedObservation, ExtractionStatus
from .identity import IdentityResolutionResult, ResolutionStatus
from .ingest import parse_timestamp
from .models import CsvRecord, IngestionResult, ParsedTimestamp, TimestampStatus


class EventCategory(str, Enum):
    CREATION = "creation"
    MODIFICATION = "modification"
    DELETION = "deletion"
    REDACTION = "redaction"
    ANONYMIZATION = "anonymization"
    RETENTION = "retention"
    TOMBSTONE = "tombstone"
    REPLICATION = "replication"
    SYNCHRONIZATION = "synchronization"
    IMPORT = "import"
    RESTORATION = "restoration"
    CONTROL_STATE = "control_state"
    OBSERVATION = "observation"
    OTHER = "other"


@dataclass(frozen=True)
class TimelineSource:
    source_kind: str
    source_file: str
    file_id: str | None = None
    record_number: int | None = None
    record_id: str | None = None
    observation_id: str | None = None
    locator: str | None = None
    extraction_method: str | None = None
    file_format: str | None = None


@dataclass(frozen=True)
class SubjectLink:
    status: str
    user_id: str | None = None
    candidate_user_ids: tuple[str, ...] = ()
    reason_codes: tuple[str, ...] = ()


@dataclass(frozen=True)
class TimelineEvent:
    event_id: str
    category: EventCategory
    raw_event_type: str | None
    event_time: ParsedTimestamp
    time_field: str
    supporting_timestamps: tuple[tuple[str, ParsedTimestamp], ...]
    capture_time: ParsedTimestamp | None
    capture_time_required: bool
    subject: SubjectLink
    system_ids: tuple[str, ...]
    resource_id: str | None
    source: TimelineSource
    role: str  # claim, observation, or activity claim
    raw_fields: Mapping[str, Any]
    claim_fields: tuple[tuple[str, str], ...] = ()
    duplicate_key: str = ""

    @property
    def timestamp_quality(self) -> str:
        return self.event_time.status.value

    @property
    def scope_key(self) -> tuple[tuple[str, ...], str | None]:
        # A resource ID is only meaningful within its systems. System-less
        # resources remain in a separate scope and are never globally joined.
        return self.system_ids, self.resource_id


@dataclass(frozen=True)
class TimelineConflict:
    conflict_id: str
    event_ids: tuple[str, ...]
    scope_key: tuple[tuple[str, ...], str | None]
    event_time: datetime
    field_name: str
    competing_values: tuple[str, ...]


@dataclass(frozen=True)
class TimelineDiagnostic:
    code: str
    message: str
    source: TimelineSource | None = None


@dataclass(frozen=True)
class UnplacedObservation:
    """Original observation retained when no supported occurrence time exists."""

    observation: ExtractedObservation
    subject: SubjectLink
    reason_code: str


@dataclass(frozen=True)
class TimelineExtractionGap:
    file_id: str
    source_path: str
    status: str
    diagnostic_codes: tuple[str, ...]
    captured_at: ParsedTimestamp | None = None


@dataclass(frozen=True)
class Timeline:
    events: tuple[TimelineEvent, ...]
    conflicts: tuple[TimelineConflict, ...]
    diagnostics: tuple[TimelineDiagnostic, ...]
    unplaced_observations: tuple[UnplacedObservation, ...]
    extraction_gaps: tuple[TimelineExtractionGap, ...]
    unresolved_observation_ids: tuple[str, ...]
    nonmatching_observation_ids: tuple[str, ...]
    unplaced_observation_ids: tuple[str, ...]
    extraction_gap_file_ids: tuple[str, ...]

    def eligible_at(self, audit_at: datetime) -> tuple[TimelineEvent, ...]:
        """Return only events whose occurrence and required capture are eligible.

        The boundary is inclusive. Missing/invalid occurrence time is never
        eligible. For manifest evidence, unknown capture time is also excluded;
        system_activity rows have no manifest capture field and require only an
        eligible event_time.
        """
        if audit_at.tzinfo is None or audit_at.utcoffset() is None:
            raise ValueError("audit_at must be timezone-aware")
        cutoff = audit_at.astimezone(timezone.utc)
        eligible = []
        for event in self.events:
            event_time = event.event_time.value
            if event_time is None or event_time > cutoff:
                continue
            if event.capture_time_required:
                captured = event.capture_time
                if captured is None or captured.status is not TimestampStatus.VALID or captured.value is None:
                    continue
                if captured.value > cutoff:
                    continue
            eligible.append(event)
        return tuple(eligible)

    def at_or_before(self, audit_at: datetime) -> tuple[TimelineEvent, ...]:
        """Alias emphasizing the inclusive audit cutoff semantics."""
        return self.eligible_at(audit_at)


_EVENT_FIELD_KINDS: Mapping[str, EventCategory] = {
    "created_at": EventCategory.CREATION,
    "updated_at": EventCategory.MODIFICATION,
    "modified_at": EventCategory.MODIFICATION,
    "deleted_at": EventCategory.DELETION,
    "redacted_at": EventCategory.REDACTION,
    "anonymized_at": EventCategory.ANONYMIZATION,
    "tombstoned_at": EventCategory.TOMBSTONE,
    "restored_at": EventCategory.RESTORATION,
    "replicated_at": EventCategory.REPLICATION,
    "synchronized_at": EventCategory.SYNCHRONIZATION,
    "synced_at": EventCategory.SYNCHRONIZATION,
    "imported_at": EventCategory.IMPORT,
    "indexed_at": EventCategory.MODIFICATION,
    "observed_at": EventCategory.OBSERVATION,
    "recorded_at": EventCategory.OBSERVATION,
    "timestamp": EventCategory.OBSERVATION,
    "event_time": EventCategory.OBSERVATION,
    "event_at": EventCategory.OBSERVATION,
    "occurred_at": EventCategory.OBSERVATION,
    "captured_at": EventCategory.OBSERVATION,
}

_ACTIVITY_KINDS: Mapping[str, EventCategory] = {
    "DELETE_RECORD": EventCategory.DELETION,
    "REDACT_RECORD": EventCategory.REDACTION,
    "ANONYMIZE_RECORD": EventCategory.ANONYMIZATION,
    "RETAIN_RECORD": EventCategory.RETENTION,
    "SYNC_RECORD": EventCategory.SYNCHRONIZATION,
    "REPLICATE_RECORD": EventCategory.REPLICATION,
    "IMPORT_RECORD": EventCategory.IMPORT,
    "RESTORE_BACKUP": EventCategory.RESTORATION,
    "DISABLE_DATA_FLOW": EventCategory.CONTROL_STATE,
    "BLOCK_RESTORE": EventCategory.CONTROL_STATE,
    "CHECK_DATA_FLOW": EventCategory.CONTROL_STATE,
    "CHECK_RESTORE_ACCESS": EventCategory.CONTROL_STATE,
    "CREATE_RECORD": EventCategory.CREATION,
    "UPDATE_RECORD": EventCategory.MODIFICATION,
    "INDEX_RECORD": EventCategory.MODIFICATION,
}

_CLAIM_KEYS = ("reported_result", "result", "status", "state", "enabled", "active")
_GENERIC_TIME_FIELDS = frozenset({"timestamp", "event_time", "event_at", "occurred_at"})


def _freeze_fields(fields: Mapping[str, Any]) -> Mapping[str, Any]:
    # Keep source values, including nested lists/objects, unchanged. A shallow
    # copy prevents callers from replacing top-level values after construction.
    from types import MappingProxyType
    return MappingProxyType(dict(fields))


def _stable(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
    except (TypeError, ValueError):
        return repr(value)


def _id(*parts: object) -> str:
    return hashlib.sha256("\x1f".join(str(part) for part in parts).encode("utf-8")).hexdigest()[:20]


def _category_from_text(value: str | None) -> EventCategory:
    if not value:
        return EventCategory.OTHER
    normalized = re.sub(r"[^A-Z0-9]+", "_", value.upper()).strip("_")
    for token, category in _ACTIVITY_KINDS.items():
        if normalized == token:
            return category
    patterns = (
        (r"DELETE|DELETION|ERASE|PURGE", EventCategory.DELETION),
        (r"REDACT", EventCategory.REDACTION),
        (r"ANONYM", EventCategory.ANONYMIZATION),
        (r"TOMBSTONE", EventCategory.TOMBSTONE),
        (r"RETAIN|RETENTION", EventCategory.RETENTION),
        (r"REPLICAT", EventCategory.REPLICATION),
        (r"SYNC", EventCategory.SYNCHRONIZATION),
        (r"IMPORT", EventCategory.IMPORT),
        (r"RESTOR|RESTORE", EventCategory.RESTORATION),
        (r"DISABLE|BLOCK|ENABLE|CONTROL|FLOW", EventCategory.CONTROL_STATE),
        (r"CREATE|INSERT", EventCategory.CREATION),
        (r"UPDATE|MODIFY|EDIT", EventCategory.MODIFICATION),
    )
    for pattern, category in patterns:
        if re.search(pattern, normalized):
            return category
    return EventCategory.OTHER


def _activity_record_fields(record: CsvRecord) -> dict[str, Any]:
    return {key: record.raw(key) for key in (
        "activity_id", "event_time", "event_type", "source_system",
        "target_system", "resource_id", "reported_result", "details",
    )}


def _source_for_activity(record: CsvRecord) -> TimelineSource:
    return TimelineSource(
        "system_activity", record.source.source_file,
        record_number=record.source.record_number,
        record_id=record.raw("activity_id"),
    )


def _source_for_observation(observation: ExtractedObservation) -> TimelineSource:
    return TimelineSource(
        "evidence", observation.source_path, file_id=observation.file_id,
        observation_id=observation.observation_id, locator=observation.locator,
        extraction_method=observation.extraction_method, file_format=observation.file_format,
    )


def _subject_for_resolution(resolution: Any | None) -> SubjectLink:
    if resolution is None:
        return SubjectLink("unresolved", reason_codes=("phase4_resolution_missing",))
    status = resolution.status.value
    user = resolution.matched_user_id if resolution.status is ResolutionStatus.CONFIRMED else None
    return SubjectLink(status, user, tuple(resolution.candidate_user_ids), tuple(resolution.reason_codes))


def _claim_fields(fields: Mapping[str, Any]) -> tuple[tuple[str, str], ...]:
    claims = []
    for key in _CLAIM_KEYS:
        value = fields.get(key)
        if value is not None and str(value).strip():
            claims.append((key, str(value)))
    return tuple(claims)


def _activity_event(record: CsvRecord) -> TimelineEvent:
    fields = _activity_record_fields(record)
    event_type = record.raw("event_type")
    raw_time = record.raw("event_time")
    parsed = record.typed("event_time")
    if not isinstance(parsed, ParsedTimestamp):
        parsed = parse_timestamp(raw_time)
    systems = tuple(sorted({value.strip() for value in (
        record.raw("source_system"), record.raw("target_system")) if value and value.strip()}))
    source = _source_for_activity(record)
    claim_values = _claim_fields(fields)
    signature = _stable((systems, record.raw("resource_id"), raw_time, event_type, claim_values, fields))
    return TimelineEvent(
        _id("activity", record.source.source_file, record.raw("activity_id"), signature),
        _ACTIVITY_KINDS.get((event_type or "").strip().upper(), EventCategory.OTHER),
        event_type, parsed, "event_time", (), None, False,
        SubjectLink("unresolved", reason_codes=("system_activity_has_no_identity_resolution",)),
        systems, record.raw("resource_id") or None, source, "activity claim",
        _freeze_fields(fields), claim_values, _id(signature),
    )


def _observation_events(
    observation: ExtractedObservation,
    subject: SubjectLink,
) -> tuple[list[TimelineEvent], bool]:
    fields = dict(observation.normalized_fields)
    # Preserve unusual original field spellings too; normalized_fields is the
    # parser's canonical representation and raw_fields retains exact values.
    time_items = list(observation.timestamps)
    time_by_name: dict[str, list[ParsedTimestamp]] = {}
    for item in time_items:
        time_by_name.setdefault(item.field_name.casefold(), []).append(item.parsed)
    supporting = tuple((name, parsed) for name, values in sorted(time_by_name.items()) for parsed in values)
    # Prefer the extractor's timestamp object (it retains malformed/raw input);
    # older or synthetic observations can still be interpreted from raw_fields.
    candidates = [(item.field_name.casefold(), item.parsed) for item in time_items]
    if not candidates:
        for name, value in observation.raw_fields.items():
            normalized_name = re.sub(r"[^a-z0-9]+", "_", str(name).casefold()).strip("_")
            if normalized_name in _EVENT_FIELD_KINDS:
                candidates.append((normalized_name, parse_timestamp(None if value is None else str(value))))

    # Deadlines and expiry dates are useful timestamped facts, but are not
    # occurrence events. Later policy evaluation consumes them as fields.
    candidates = [(name, parsed) for name, parsed in candidates
                  if not name.endswith(("_until", "_expires", "_expiry")) and name != "expires_at"]
    if not candidates:
        return [], False

    event_text = next((str(fields.get(key)) for key in
                       ("event_type", "operation", "action", "event_name", "event")
                       if fields.get(key) is not None), None)
    systems = {observation.system_id} if observation.system_id else set()
    for field in ("system_id", "system", "service", "origin_system", "source_system", "target_system"):
        value = fields.get(field)
        if value is not None and str(value).strip():
            systems.add(str(value).strip())
    resource_candidates = {str(fields[name]).strip() for name in ("resource_id", "source_resource_id")
                           if fields.get(name) is not None and str(fields[name]).strip()}
    resource_id = observation.resource_id
    if resource_id is None and len(resource_candidates) == 1:
        resource_id = next(iter(resource_candidates))
    if len(resource_candidates) > 1:
        resource_id = None

    source = _source_for_observation(observation)
    claims = _claim_fields(fields)
    raw_type = event_text
    events: list[TimelineEvent] = []
    for name, parsed in candidates:
        category = _EVENT_FIELD_KINDS.get(name)
        if name in _GENERIC_TIME_FIELDS or category is None:
            category = _category_from_text(event_text) if event_text else EventCategory.OBSERVATION
        # The evidence file's captured_at is manifest availability metadata; it
        # never becomes the event occurrence time.
        duplicate_signature = _stable((tuple(sorted(systems)), resource_id, name, parsed.raw,
                                       raw_type, claims, observation.raw_fields))
        events.append(TimelineEvent(
            _id("observation", observation.observation_id, name, parsed.raw), category,
            raw_type, parsed, name, supporting, observation.captured_at, True,
            subject, tuple(sorted(systems)), resource_id, source,
            "claim" if observation.file_format.casefold() in {"log", "text", "txt"} else "observation",
            _freeze_fields(observation.raw_fields), claims, _id(duplicate_signature),
        ))
    return events, True


def _find_conflicts(events: tuple[TimelineEvent, ...]) -> tuple[TimelineConflict, ...]:
    groups: dict[tuple[tuple[tuple[str, ...], str | None], datetime, str], list[TimelineEvent]] = {}
    for event in events:
        when = event.event_time.value
        if when is None:
            continue
        if not event.raw_event_type:
            continue
        for field_name, value in event.claim_fields:
            if field_name in {"reported_result", "result", "status", "state", "enabled", "active"}:
                groups.setdefault((event.scope_key, when, f"{event.raw_event_type}:{field_name}"), []).append(event)
    conflicts: list[TimelineConflict] = []
    for (scope, when, field_name), group in sorted(
        groups.items(), key=lambda item: (item[0][0][0], item[0][0][1] or "", item[0][1], item[0][2])
    ):
        values = sorted({value for event in group for key, value in event.claim_fields
                         if f"{event.raw_event_type}:{key}" == field_name})
        ids = tuple(sorted({event.event_id for event in group}))
        if len(values) > 1 and len(ids) > 1:
            conflicts.append(TimelineConflict(_id("conflict", scope, when.isoformat(), field_name, values),
                ids, scope, when, field_name, tuple(values)))
    return tuple(conflicts)


def build_timeline(
    ingestion: IngestionResult,
    extraction: EvidenceExtractionResult,
    identities: IdentityResolutionResult,
) -> Timeline:
    """Build a stable timeline from Phase 1/3/4 results without mutating them."""
    events: list[TimelineEvent] = []
    diagnostics: list[TimelineDiagnostic] = []
    unresolved: list[str] = []
    nonmatching: list[str] = []
    unplaced: list[str] = []
    unplaced_full: list[UnplacedObservation] = []

    activity = ingestion.bundle.tables.get("system_activity")
    if activity is not None:
        events.extend(_activity_event(record) for record in activity.records)
    else:
        diagnostics.append(TimelineDiagnostic("system_activity_missing", "No system_activity table was ingested."))

    observations = extraction.observations
    resolutions = identities.observation_resolutions
    if len(observations) != len(resolutions):
        diagnostics.append(TimelineDiagnostic(
            "identity_observation_alignment_mismatch",
            "Phase 4 observation resolutions do not align one-for-one with Phase 3 observations; unmatched observations remain unresolved.",
        ))
    for index, observation in enumerate(observations):
        resolution = resolutions[index] if index < len(resolutions) else None
        subject = _subject_for_resolution(resolution)
        if subject.status in {ResolutionStatus.UNRESOLVED.value, ResolutionStatus.AMBIGUOUS.value}:
            unresolved.append(observation.observation_id)
        elif subject.status == ResolutionStatus.NON_MATCH.value:
            nonmatching.append(observation.observation_id)
        obs_events, placed = _observation_events(observation, subject)
        if not placed:
            unplaced.append(observation.observation_id)
            unplaced_full.append(UnplacedObservation(observation, subject, "no_explicit_event_timestamp"))
            diagnostics.append(TimelineDiagnostic("observation_without_event_timestamp",
                "Observation has no explicit event/observation timestamp; retained outside cutoff-eligible event entries.",
                _source_for_observation(observation)))
        events.extend(obs_events)

    # Stable ordering never implies an ordering among equal-time events.
    events.sort(key=lambda event: (
        event.event_time.value is None,
        event.event_time.value or datetime.max.replace(tzinfo=timezone.utc),
        event.system_ids, event.resource_id or "", event.subject.user_id or "",
        event.category.value, event.raw_event_type or "", event.time_field,
        event.source.source_file, event.source.record_id or "", event.source.record_number or -1,
        event.source.file_id or "", event.source.locator or "", event.event_id,
    ))
    frozen_events = tuple(events)
    diagnostics.sort(key=lambda item: (item.code, item.source.source_file if item.source else "",
                                       item.source.record_number or -1 if item.source else -1,
                                       item.source.observation_id or "" if item.source else ""))
    gaps = tuple(sorted((TimelineExtractionGap(
        item.file_id, item.source_path, item.status.value,
        tuple(sorted({diagnostic.code for diagnostic in (*item.warnings, *item.errors)})),
        item.captured_at,
    ) for item in extraction.files if item.status not in (ExtractionStatus.COMPLETE, ExtractionStatus.EMPTY)),
        key=lambda item: (item.file_id, item.source_path, item.status)))
    gap_ids = set(identities.extraction_gap_file_ids)
    gap_ids.update(item.file_id for item in gaps)
    return Timeline(frozen_events, _find_conflicts(frozen_events), tuple(diagnostics),
                    tuple(sorted(unplaced_full, key=lambda item: item.observation.observation_id)), gaps,
                    tuple(sorted(set(unresolved))), tuple(sorted(set(nonmatching))),
                    tuple(sorted(set(unplaced))),
                    tuple(sorted(gap_ids)))


__all__ = [
    "EventCategory", "SubjectLink", "Timeline", "TimelineConflict", "TimelineDiagnostic",
    "TimelineEvent", "TimelineExtractionGap", "TimelineSource", "UnplacedObservation", "build_timeline",
]
