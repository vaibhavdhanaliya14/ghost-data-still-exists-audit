"""Deterministic, provenance-preserving historical identity resolution.

This phase builds identifier validity intervals from participant-visible
identity snapshots and audit transitions, then links requests/observations to
stable users. It does not apply case audit cutoffs or reconstruct resources.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Mapping

from .extract import EvidenceExtractionResult, ExtractedObservation, IdentifierValue
from .ingest import parse_timestamp
from .models import CsvRecord, IngestionResult, ParsedTimestamp, TimestampStatus


class ResolutionStatus(str, Enum):
    CONFIRMED = "confirmed"
    # No supported identity edge matched. This is never proof that data is absent.
    NON_MATCH = "non_match"
    AMBIGUOUS = "ambiguous"
    UNRESOLVED = "unresolved"


class MatchConfidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    NONE = "none"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class IdentitySource:
    source_file: str
    record_number: int | None = None
    record_id: str | None = None
    field_name: str | None = None
    file_id: str | None = None
    observation_id: str | None = None
    locator: str | None = None
    source_kind: str = "csv"


@dataclass(frozen=True)
class IdentityInterval:
    user_id: str
    identifier_type: str
    normalized_value: str
    raw_values: tuple[str, ...]
    valid_from: datetime | None
    valid_to: datetime | None  # exclusive; adjacent changes have no overlap
    sources: tuple[IdentitySource, ...]

    def contains(self, at: datetime) -> bool:
        if at.tzinfo is None or at.utcoffset() is None:
            raise ValueError("Identity lookup time must be timezone-aware.")
        return (self.valid_from is None or self.valid_from <= at) and (self.valid_to is None or at < self.valid_to)


@dataclass(frozen=True)
class IdentityConflict:
    user_id: str | None
    identifier_type: str
    code: str
    sources: tuple[IdentitySource, ...]
    raw_values: tuple[str, ...] = ()


@dataclass(frozen=True)
class IdentityGraph:
    user_ids: tuple[str, ...]
    user_id_sources: Mapping[str, tuple[IdentitySource, ...]]
    intervals: tuple[IdentityInterval, ...]
    conflicts: tuple[IdentityConflict, ...]
    alias_index: Mapping[tuple[str, str], tuple[IdentityInterval, ...]]
    conflicted_fields: frozenset[tuple[str, str]]
    duplicate_user_ids: frozenset[str]


@dataclass(frozen=True)
class IdentifierMatch:
    source_namespace: str
    identifier_type: str
    normalized_value: str
    candidate_user_ids: tuple[str, ...]
    matched_user_id: str | None
    status: ResolutionStatus
    confidence: MatchConfidence
    identity_sources: tuple[IdentitySource, ...]
    reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class IdentityResolution:
    target_id: str
    target_kind: str  # request or observation
    status: ResolutionStatus
    matched_user_id: str | None
    candidate_user_ids: tuple[str, ...]
    confidence: MatchConfidence
    input_identifiers: tuple[IdentifierValue, ...]
    identifier_matches: tuple[IdentifierMatch, ...]
    conflicts: tuple[IdentityConflict, ...]
    reason_codes: tuple[str, ...]
    source: IdentitySource


@dataclass(frozen=True)
class IdentityResolutionResult:
    graph: IdentityGraph
    request_resolutions: tuple[IdentityResolution, ...]
    observation_resolutions: tuple[IdentityResolution, ...]
    extraction_gap_file_ids: tuple[str, ...]

    @property
    def confirmed_count(self) -> int:
        return sum(item.status is ResolutionStatus.CONFIRMED for item in self.observation_resolutions)

    @property
    def non_match_count(self) -> int:
        return sum(item.status is ResolutionStatus.NON_MATCH for item in self.observation_resolutions)

    @property
    def ambiguous_count(self) -> int:
        return sum(item.status is ResolutionStatus.AMBIGUOUS for item in self.observation_resolutions)

    @property
    def unresolved_count(self) -> int:
        return sum(item.status is ResolutionStatus.UNRESOLVED for item in self.observation_resolutions)


_SUPPORTED_FIELDS = frozenset({"email", "email_hash", "phone"})
_EVIDENCE_FIELD_TYPES = {
    "email": "email", "customer_email": "email", "owner_email": "email", "requester_email": "email",
    "phone": "phone", "customer_phone": "phone", "owner_phone": "phone", "requester_phone": "phone",
    "email_hash": "email_hash",
    # These field names are explicitly subject/customer references in supplied evidence.
    # Their values are compared only to stable user_id values, never to mutable aliases.
    "customer_reference": "user_reference", "customer_ref": "user_reference",
    "subject_reference": "user_reference", "subject_ref": "user_reference", "subject_key": "user_reference",
    "user_id": "user_id",
}


def _normalize(identifier_type: str, raw_value: str) -> str:
    value = raw_value.strip()
    return value.casefold() if identifier_type == "email" else value


def _source_from_record(record: CsvRecord, *, record_id: str | None, field_name: str | None) -> IdentitySource:
    return IdentitySource(
        source_file=record.source.source_file,
        record_number=record.source.record_number,
        record_id=record_id,
        field_name=field_name,
        source_kind="csv",
    )


def _sorted_sources(sources: set[IdentitySource] | list[IdentitySource] | tuple[IdentitySource, ...]) -> tuple[IdentitySource, ...]:
    return tuple(sorted(set(sources), key=_source_key))


def _source_key(source: IdentitySource) -> tuple[object, ...]:
    return (
        source.source_file, source.record_number or -1, source.record_id or "", source.field_name or "",
        source.file_id or "", source.observation_id or "", source.locator or "", source.source_kind,
    )


def build_identity_graph(ingestion: IngestionResult) -> IdentityGraph:
    """Build half-open identifier validity intervals and retain conflicts."""
    identities = ingestion.bundle.tables.get("user_identities")
    audits = ingestion.bundle.tables.get("user_audit_log")
    if identities is None or audits is None:
        empty = MappingProxyType({})
        return IdentityGraph((), empty, (), (IdentityConflict(None, "*", "identity_source_table_missing", ()),),
                             empty, frozenset(), frozenset())

    current_rows: dict[str, list[CsvRecord]] = {}
    audit_groups: dict[tuple[str, str], list[tuple[datetime, str | None, str | None, IdentitySource]]] = {}
    conflicts: list[IdentityConflict] = []
    conflicted_fields: set[tuple[str, str]] = set()
    duplicate_user_ids: set[str] = set()
    user_ids = sorted({record.raw("user_id") for record in identities.records if record.raw("user_id")})

    for record in identities.records:
        user_id = record.raw("user_id")
        if user_id:
            current_rows.setdefault(user_id, []).append(record)
    for user_id, rows in current_rows.items():
        if len(rows) > 1:
            duplicate_user_ids.add(user_id)
            sources = tuple(_source_from_record(row, record_id=user_id, field_name="user_id") for row in rows)
            conflicts.append(IdentityConflict(user_id, "user_id", "duplicate_current_user_id", sources))
    user_id_sources = {
        user_id: _sorted_sources(_source_from_record(row, record_id=user_id, field_name="user_id") for row in rows)
        for user_id, rows in current_rows.items()
    }

    known_users = set(current_rows)
    for record in audits.records:
        user_id = record.raw("user_id") or ""
        field = (record.raw("field_name") or "").strip().lower()
        source = _source_from_record(record, record_id=record.raw("audit_id"), field_name=field or None)
        if not user_id or user_id not in known_users:
            conflicts.append(IdentityConflict(user_id or None, field or "unknown", "audit_user_not_in_snapshot", (source,)))
            continue
        if field not in _SUPPORTED_FIELDS:
            conflicts.append(IdentityConflict(user_id, field or "unknown", "unsupported_audit_identifier_field", (source,)))
            if field:
                conflicted_fields.add((user_id, field))
            continue
        parsed = record.typed("event_time")
        if not isinstance(parsed, ParsedTimestamp) or parsed.status is not TimestampStatus.VALID or parsed.value is None:
            conflicts.append(IdentityConflict(user_id, field, "invalid_audit_event_time", (source,)))
            conflicted_fields.add((user_id, field))
            continue
        audit_groups.setdefault((user_id, field), []).append(
            (parsed.value, record.raw("old_value"), record.raw("new_value"), source)
        )

    # Mutable interval accumulator coalesces duplicate transitions while keeping
    # all raw spellings and every supporting participant-visible source.
    edge_acc: dict[tuple[str, str, str, datetime | None, datetime | None], dict[str, set]] = {}

    def add_edge(
        user_id: str, field: str, raw_value: str | None, valid_from: datetime | None,
        valid_to: datetime | None, sources: tuple[IdentitySource, ...] | list[IdentitySource],
    ) -> None:
        if raw_value is None or not raw_value.strip():
            return
        normalized = _normalize(field, raw_value)
        key = (user_id, field, normalized, valid_from, valid_to)
        item = edge_acc.setdefault(key, {"raw": set(), "sources": set()})
        item["raw"].add(raw_value)
        item["sources"].update(sources)

    for (user_id, field), raw_events in sorted(audit_groups.items()):
        # Duplicate observations of an identical transition contribute provenance,
        # not a second identity assignment.
        transitions: dict[tuple[datetime, str, str], dict[str, set]] = {}
        for event_time, old, new, source in raw_events:
            old_norm = _normalize(field, old or "")
            new_norm = _normalize(field, new or "")
            key = (event_time, old_norm, new_norm)
            item = transitions.setdefault(key, {"old_raw": set(), "new_raw": set(), "sources": set()})
            if old is not None:
                item["old_raw"].add(old)
            if new is not None:
                item["new_raw"].add(new)
            item["sources"].add(source)
        events = [
            (time, old, new, tuple(sorted(item["old_raw"])), tuple(sorted(item["new_raw"])), _sorted_sources(item["sources"]))
            for (time, old, new), item in transitions.items()
        ]
        events.sort(key=lambda event: (event[0], event[1], event[2]))

        by_time: dict[datetime, set[tuple[str, str]]] = {}
        for time, old, new, _old_raw, _new_raw, _sources in events:
            by_time.setdefault(time, set()).add((old, new))
        for time, values in by_time.items():
            if len(values) > 1:
                related = tuple(source for t, _o, _n, _oraw, _nraw, srcs in events if t == time for source in srcs)
                conflicts.append(IdentityConflict(user_id, field, "contradictory_events_same_time",
                    _sorted_sources(related), tuple(sorted({v for t, _o, _n, oraw, nraw, _src in events if t == time for v in (*oraw, *nraw) if v}))))
                conflicted_fields.add((user_id, field))
        for previous, current in zip(events, events[1:]):
            if previous[2] != current[1]:
                conflicts.append(IdentityConflict(user_id, field, "history_chain_break",
                    _sorted_sources((*previous[5], *current[5])),
                    tuple(sorted(set((*previous[4], *current[3]))))))
                conflicted_fields.add((user_id, field))

        # Reconstruct each old/new interval. At event_time the new value is
        # effective; valid_to is exclusive, so adjacent aliases never overlap.
        for index, (event_time, _old, _new, old_raw, new_raw, sources) in enumerate(events):
            previous_time = events[index - 1][0] if index else None
            next_time = events[index + 1][0] if index + 1 < len(events) else None
            for raw_value in old_raw:
                add_edge(user_id, field, raw_value, previous_time, event_time, sources)
            for raw_value in new_raw:
                add_edge(user_id, field, raw_value, event_time, next_time, sources)

    for user_id, rows in sorted(current_rows.items()):
        for row in rows:
            updated = row.typed("updated_at")
            updated_at = updated.value if isinstance(updated, ParsedTimestamp) and updated.status is TimestampStatus.VALID else None
            source_time = _source_from_record(row, record_id=user_id, field_name="updated_at")
            if updated_at is None:
                conflicts.append(IdentityConflict(user_id, "*", "invalid_identity_snapshot_time", (source_time,)))
                continue
            for field in sorted(_SUPPORTED_FIELDS):
                raw_current = row.raw(field)
                if raw_current is None or not raw_current.strip():
                    continue
                field_events = sorted(audit_groups.get((user_id, field), ()), key=lambda e: (e[0], _source_key(e[3])))
                if not field_events:
                    add_edge(user_id, field, raw_current, updated_at, None,
                             (_source_from_record(row, record_id=user_id, field_name=field),))
                    continue

                # The snapshot value is supported from its update time until the
                # next known transition. Conflicting snapshot/history values are
                # retained as a conflict and both sources remain on the graph.
                later = [event for event in field_events if event[0] > updated_at]
                earlier_or_equal = [event for event in field_events if event[0] <= updated_at]
                if earlier_or_equal:
                    expected = earlier_or_equal[-1][2]
                elif field_events:
                    expected = field_events[0][1]
                else:
                    expected = None
                if expected is not None and _normalize(field, expected or "") != _normalize(field, raw_current):
                    sources = [_source_from_record(row, record_id=user_id, field_name=field)]
                    sources.extend(event[3] for event in field_events)
                    conflicts.append(IdentityConflict(user_id, field, "snapshot_history_conflict",
                        _sorted_sources([source for source in sources if isinstance(source, IdentitySource)]),
                        tuple(v for v in (expected, raw_current) if v)))
                    conflicted_fields.add((user_id, field))
                next_event_time = later[0][0] if later else None
                add_edge(user_id, field, raw_current, updated_at, next_event_time,
                         (_source_from_record(row, record_id=user_id, field_name=field),))

    intervals = tuple(sorted((
        IdentityInterval(user_id=user, identifier_type=field, normalized_value=value,
                         raw_values=tuple(sorted(acc["raw"])), valid_from=start, valid_to=end,
                         sources=_sorted_sources(acc["sources"]))
        for (user, field, value, start, end), acc in edge_acc.items()
    ), key=lambda edge: (edge.identifier_type, edge.normalized_value, edge.user_id,
                         edge.valid_from or datetime.min.replace(tzinfo=timezone.utc),
                         edge.valid_to or datetime.max.replace(tzinfo=timezone.utc))))

    alias_index: dict[tuple[str, str], list[IdentityInterval]] = {}
    for interval in intervals:
        alias_index.setdefault((interval.identifier_type, interval.normalized_value), []).append(interval)
    conflicts.sort(key=lambda item: (item.user_id or "", item.identifier_type, item.code,
                                     tuple((s.source_file, s.record_number or -1, s.record_id or "") for s in item.sources)))
    return IdentityGraph(
        user_ids=tuple(user_ids), user_id_sources=MappingProxyType(user_id_sources),
        intervals=intervals, conflicts=tuple(conflicts),
        alias_index=MappingProxyType({key: tuple(value) for key, value in sorted(alias_index.items())}),
        conflicted_fields=frozenset(conflicted_fields), duplicate_user_ids=frozenset(duplicate_user_ids),
    )


def _identifier_type(namespace: str) -> str | None:
    return _EVIDENCE_FIELD_TYPES.get(namespace.strip().lower())


def _resolution_for_identifier(
    graph: IdentityGraph,
    identifier: IdentifierValue,
    *,
    at: datetime | None,
) -> IdentifierMatch:
    kind = _identifier_type(identifier.namespace)
    if kind is None:
        return IdentifierMatch(identifier.namespace, "unsupported", identifier.normalized_value, (), None,
                               ResolutionStatus.UNRESOLVED, MatchConfidence.UNRESOLVED, (),
                               ("unsupported_identifier_namespace",))
    value = _normalize("email" if kind == "email" else kind, identifier.raw_value)
    if kind == "user_id":
        candidates = (value,) if value in graph.user_ids else ()
        sources = graph.user_id_sources.get(value, ())
        if value in graph.duplicate_user_ids:
            return IdentifierMatch(identifier.namespace, kind, value, candidates, None,
                ResolutionStatus.UNRESOLVED, MatchConfidence.UNRESOLVED, sources, ("duplicate_current_user_id",))
        status = ResolutionStatus.CONFIRMED if candidates else ResolutionStatus.NON_MATCH
        return IdentifierMatch(identifier.namespace, kind, value, candidates,
            candidates[0] if candidates else None, status,
            MatchConfidence.HIGH if candidates else MatchConfidence.NONE, sources,
            () if candidates else ("unknown_user_id",))
    if kind == "user_reference":
        candidates = (value,) if value in graph.user_ids else ()
        status = ResolutionStatus.CONFIRMED if candidates else ResolutionStatus.NON_MATCH
        return IdentifierMatch(identifier.namespace, kind, value, candidates,
            candidates[0] if candidates else None, status,
            MatchConfidence.HIGH if candidates else MatchConfidence.NONE, graph.user_id_sources.get(value, ()),
            () if candidates else ("unknown_user_reference",))

    edges = graph.alias_index.get((kind, value), ())
    if not edges:
        return IdentifierMatch(identifier.namespace, kind, value, (), None, ResolutionStatus.NON_MATCH,
                               MatchConfidence.NONE, (), ("identifier_not_in_identity_history",))
    candidates = tuple(sorted({edge.user_id for edge in edges}))
    candidate_conflicts = tuple(conflict for conflict in graph.conflicts
        if conflict.user_id in candidates and (conflict.identifier_type == kind or conflict.identifier_type == "*"))
    if candidate_conflicts or any(user in graph.duplicate_user_ids for user in candidates) or any(
        (user, kind) in graph.conflicted_fields for user in candidates
    ):
        return IdentifierMatch(identifier.namespace, kind, value, candidates, None,
            ResolutionStatus.UNRESOLVED, MatchConfidence.UNRESOLVED,
            _sorted_sources([source for edge in edges for source in edge.sources]),
            tuple(sorted({conflict.code for conflict in candidate_conflicts} or {"identity_field_conflict"})))
    if at is None:
        if len(candidates) == 1:
            return IdentifierMatch(identifier.namespace, kind, value, candidates, candidates[0],
                ResolutionStatus.CONFIRMED, MatchConfidence.MEDIUM,
                _sorted_sources([source for edge in edges for source in edge.sources]), ("unique_known_owner_no_time",))
        return IdentifierMatch(identifier.namespace, kind, value, candidates, None,
            ResolutionStatus.AMBIGUOUS, MatchConfidence.UNRESOLVED,
            _sorted_sources([source for edge in edges for source in edge.sources]), ("identifier_reused_or_shared_without_time",))
    if at.tzinfo is None or at.utcoffset() is None:
        return IdentifierMatch(identifier.namespace, kind, value, candidates, None,
            ResolutionStatus.UNRESOLVED, MatchConfidence.UNRESOLVED,
            _sorted_sources([source for edge in edges for source in edge.sources]), ("lookup_time_not_timezone_aware",))
    active = tuple(edge for edge in edges if edge.contains(at))
    active_users = tuple(sorted({edge.user_id for edge in active}))
    if len(active_users) == 1:
        sources = _sorted_sources([source for edge in active for source in edge.sources])
        return IdentifierMatch(identifier.namespace, kind, value, active_users, active_users[0],
            ResolutionStatus.CONFIRMED, MatchConfidence.HIGH, sources, ())
    if len(active_users) > 1:
        return IdentifierMatch(identifier.namespace, kind, value, active_users, None,
            ResolutionStatus.AMBIGUOUS, MatchConfidence.UNRESOLVED,
            _sorted_sources([source for edge in active for source in edge.sources]), ("overlapping_identity_validity",))
    expired = all(edge.valid_to is not None and at >= edge.valid_to for edge in edges)
    if expired:
        return IdentifierMatch(identifier.namespace, kind, value, candidates, None,
            ResolutionStatus.NON_MATCH, MatchConfidence.NONE,
            _sorted_sources([source for edge in edges for source in edge.sources]), ("identifier_not_valid_at_time",))
    return IdentifierMatch(identifier.namespace, kind, value, candidates, None,
        ResolutionStatus.UNRESOLVED, MatchConfidence.UNRESOLVED,
        _sorted_sources([source for edge in edges for source in edge.sources]), ("identifier_outside_supported_validity",))


def _combine_identifier_matches(
    target_id: str,
    target_kind: str,
    identifiers: tuple[IdentifierValue, ...],
    matches: tuple[IdentifierMatch, ...],
    source: IdentitySource,
    graph: IdentityGraph,
) -> IdentityResolution:
    resolved_user_ids = {item.matched_user_id for item in matches if item.matched_user_id is not None}
    candidates = tuple(sorted(set(resolved_user_ids).union(*(set(item.candidate_user_ids) for item in matches))))
    ambiguous = any(item.status is ResolutionStatus.AMBIGUOUS for item in matches)
    unresolved_with_candidates = any(
        item.status is ResolutionStatus.UNRESOLVED and item.candidate_user_ids for item in matches
    )
    if len(resolved_user_ids) > 1:
        status, matched_user_id, confidence = ResolutionStatus.AMBIGUOUS, None, MatchConfidence.UNRESOLVED
        reasons = {"identifiers_resolve_to_different_users"}
    elif ambiguous or (len(candidates) > 1 and (unresolved_with_candidates or resolved_user_ids)):
        status, matched_user_id, confidence = ResolutionStatus.AMBIGUOUS, None, MatchConfidence.UNRESOLVED
        reasons = {reason for match in matches for reason in match.reason_codes}
        reasons.add("multiple_candidate_users")
    elif unresolved_with_candidates or any(item.status is ResolutionStatus.UNRESOLVED for item in matches):
        status, matched_user_id, confidence = ResolutionStatus.UNRESOLVED, None, MatchConfidence.UNRESOLVED
        reasons = {reason for match in matches for reason in match.reason_codes}
    elif len(resolved_user_ids) == 1:
        status, matched_user_id = ResolutionStatus.CONFIRMED, next(iter(resolved_user_ids))
        confidence = MatchConfidence.HIGH if any(m.confidence is MatchConfidence.HIGH for m in matches if m.matched_user_id) else MatchConfidence.MEDIUM
        reasons = set()
    elif matches and all(item.status is ResolutionStatus.NON_MATCH for item in matches):
        status, matched_user_id, confidence = ResolutionStatus.NON_MATCH, None, MatchConfidence.NONE
        reasons = {reason for match in matches for reason in match.reason_codes}
    else:
        status, matched_user_id, confidence = ResolutionStatus.UNRESOLVED, None, MatchConfidence.UNRESOLVED
        reasons = {"no_supported_identity_match"}

    relevant_conflicts = tuple(conflict for conflict in graph.conflicts
        if conflict.user_id in candidates and any(
            (match.identifier_type == conflict.identifier_type or conflict.identifier_type == "*")
            for match in matches
        ))
    return IdentityResolution(
        target_id=target_id, target_kind=target_kind, status=status, matched_user_id=matched_user_id,
        candidate_user_ids=candidates, confidence=confidence, input_identifiers=identifiers,
        identifier_matches=matches, conflicts=relevant_conflicts,
        reason_codes=tuple(sorted(reasons)), source=source,
    )


class IdentityResolver:
    def __init__(self, graph: IdentityGraph) -> None:
        self.graph = graph

    def resolve_identifier(
        self, namespace: str, value: str | None, *, at: datetime | None = None,
    ) -> IdentifierMatch:
        if value is None or not value.strip():
            return IdentifierMatch(namespace, _identifier_type(namespace) or "unsupported", "", (), None,
                ResolutionStatus.UNRESOLVED, MatchConfidence.UNRESOLVED, (), ("missing_identifier_value",))
        identifier = IdentifierValue(namespace, value, _normalize(_identifier_type(namespace) or namespace, value))
        return _resolution_for_identifier(self.graph, identifier, at=at)

    def resolve_request(self, record: CsvRecord) -> IdentityResolution:
        case_id = record.raw("case_id") or ""
        raw_email = record.raw("email")
        identifier = IdentifierValue("email", raw_email or "", _normalize("email", raw_email or ""))
        source = _source_from_record(record, record_id=case_id, field_name="email")
        requested_at = record.typed("requested_at")
        time_valid = isinstance(requested_at, ParsedTimestamp) and requested_at.status is TimestampStatus.VALID
        at = requested_at.value if time_valid else None
        match = _resolution_for_identifier(self.graph, identifier, at=at) if raw_email and raw_email.strip() else IdentifierMatch(
            "email", "email", "", (), None, ResolutionStatus.UNRESOLVED, MatchConfidence.UNRESOLVED, (), ("missing_identifier_value",)
        )
        # The challenge explicitly allows the request email to be a historical
        # identifier. A request can arrive after an address has been changed,
        # so temporal non-membership at requested_at is not by itself a
        # non-match. Fall back to the full history only in that case. The
        # no-time resolver confirms only a unique, conflict-free owner and
        # returns AMBIGUOUS when an address was reused across users.
        if (time_valid and raw_email and raw_email.strip()
                and match.status is ResolutionStatus.NON_MATCH
                and "identifier_not_valid_at_time" in match.reason_codes):
            historical = _resolution_for_identifier(self.graph, identifier, at=None)
            if historical.status is ResolutionStatus.CONFIRMED:
                match = IdentifierMatch(
                    identifier.namespace, historical.identifier_type, identifier.normalized_value,
                    historical.candidate_user_ids, historical.matched_user_id,
                    ResolutionStatus.CONFIRMED, MatchConfidence.MEDIUM,
                    historical.identity_sources, ("unique_historical_owner_outside_request_validity",),
                )
            elif historical.status in {ResolutionStatus.AMBIGUOUS, ResolutionStatus.UNRESOLVED}:
                match = historical
        if raw_email and raw_email.strip() and not time_valid:
            match = IdentifierMatch("email", "email", _normalize("email", raw_email), (), None,
                ResolutionStatus.UNRESOLVED, MatchConfidence.UNRESOLVED, (), ("request_time_missing_or_invalid",))
        return _combine_identifier_matches(case_id, "request", (identifier,), (match,), source, self.graph)

    def resolve_observation(self, observation: ExtractedObservation, *, at: datetime | None = None) -> IdentityResolution:
        source = IdentitySource(
            source_file=observation.source_path, record_id=observation.observation_id,
            file_id=observation.file_id, observation_id=observation.observation_id,
            locator=observation.locator, source_kind="evidence",
        )
        supported: list[IdentifierValue] = []
        matches: list[IdentifierMatch] = []
        for identifier in observation.identifiers:
            if _identifier_type(identifier.namespace) is None:
                continue
            supported.append(identifier)
            matches.append(_resolution_for_identifier(self.graph, identifier, at=at))
        if not supported:
            return IdentityResolution(
                target_id=observation.observation_id, target_kind="observation",
                status=ResolutionStatus.UNRESOLVED, matched_user_id=None, candidate_user_ids=(),
                confidence=MatchConfidence.UNRESOLVED, input_identifiers=observation.identifiers,
                identifier_matches=(), conflicts=(), reason_codes=("no_supported_identity_identifier",), source=source,
            )
        # Repeated exact fields in an observation are evidence repetition, not
        # additional users. Keep one deterministic resolution per namespace/value.
        unique: dict[tuple[str, str], tuple[IdentifierValue, IdentifierMatch]] = {}
        for identifier, match in zip(supported, matches):
            unique.setdefault((identifier.namespace, identifier.normalized_value), (identifier, match))
        query_ids = tuple(value[0] for _, value in sorted(unique.items()))
        query_matches = tuple(value[1] for _, value in sorted(unique.items()))
        return _combine_identifier_matches(observation.observation_id, "observation", query_ids, query_matches, source, self.graph)


def resolve_identities(ingestion: IngestionResult, extraction: EvidenceExtractionResult) -> IdentityResolutionResult:
    """Resolve dataset requests and every extracted observation; retain all statuses."""
    graph = build_identity_graph(ingestion)
    resolver = IdentityResolver(graph)
    request_table = ingestion.bundle.tables.get("deletion_requests")
    requests = tuple(resolver.resolve_request(record) for record in request_table.records) if request_table else ()
    observations = tuple(resolver.resolve_observation(observation) for observation in extraction.observations)
    gaps = tuple(sorted(file.file_id for file in extraction.files
        if file.status.value not in {"complete", "empty"}))
    return IdentityResolutionResult(graph, requests, observations, gaps)

