"""Deterministic evidence extraction and normalization.

Extraction preserves source values and provenance. It does not resolve a case,
apply an audit cutoff, infer absence, or make deletion-policy decisions.
"""

from __future__ import annotations

import csv
import importlib
import io
import json
import re
import shlex
import sqlite3
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Callable, Mapping, Protocol

from .ingest import parse_timestamp
from .manifest import DiscoveryOutcome, EvidenceDiscoveryResult, EvidenceFileDiscovery
from .models import ParsedTimestamp, TimestampStatus
from .png_transcripts import BundledPngTranscriptBackend


class ExtractionStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    EMPTY = "empty"
    FAILED = "failed"
    MISSING = "missing"
    INACCESSIBLE = "inaccessible"
    UNSUPPORTED = "unsupported"
    REJECTED = "rejected"


@dataclass(frozen=True)
class ExtractionDiagnostic:
    code: str
    message: str
    severity: str = "error"
    locator: str | None = None


@dataclass(frozen=True)
class ObservationTimestamp:
    field_name: str
    raw_value: str | None
    parsed: ParsedTimestamp


@dataclass(frozen=True)
class IdentifierValue:
    namespace: str
    raw_value: str
    normalized_value: str


@dataclass(frozen=True)
class ExtractedObservation:
    observation_id: str
    file_id: str
    source_path: str
    file_format: str
    locator: str
    extraction_method: str
    raw_fields: Mapping[str, Any]
    normalized_fields: Mapping[str, Any]
    identifiers: tuple[IdentifierValue, ...]
    system_id: str | None
    resource_id: str | None
    timestamps: tuple[ObservationTimestamp, ...]
    captured_at: ParsedTimestamp | None
    parent_observation_id: str | None = None


@dataclass(frozen=True)
class FileExtractionResult:
    file_id: str
    source_path: str
    file_format: str
    parser: str
    status: ExtractionStatus
    captured_at: ParsedTimestamp | None
    observations: tuple[ExtractedObservation, ...]
    discovered_scope: tuple[str, ...]
    warnings: tuple[ExtractionDiagnostic, ...]
    errors: tuple[ExtractionDiagnostic, ...]


@dataclass(frozen=True)
class EvidenceExtractionResult:
    files: tuple[FileExtractionResult, ...]

    @property
    def by_file_id(self) -> Mapping[str, FileExtractionResult]:
        return MappingProxyType({item.file_id: item for item in self.files})

    @property
    def observations(self) -> tuple[ExtractedObservation, ...]:
        return tuple(obs for item in self.files for obs in item.observations)

    @property
    def observation_count(self) -> int:
        return sum(len(item.observations) for item in self.files)

    def counts_by_format(self) -> Mapping[str, Mapping[str, int]]:
        formats = sorted({item.file_format for item in self.files})
        return MappingProxyType({
            fmt: MappingProxyType({
                status.value: sum(item.file_format == fmt and item.status is status for item in self.files)
                for status in ExtractionStatus
                if any(item.file_format == fmt and item.status is status for item in self.files)
            } | {"files": sum(item.file_format == fmt for item in self.files),
                 "observations": sum(len(item.observations) for item in self.files if item.file_format == fmt)})
            for fmt in formats
        })


@dataclass(frozen=True)
class CaseEvidenceCoverage:
    """Candidate-file coverage only; case matching and audit eligibility are later work."""

    case_id: str
    candidate_file_ids: tuple[str, ...]
    examined_file_ids: tuple[str, ...]
    observation_ids: tuple[str, ...]
    failed_file_ids: tuple[str, ...]
    material_gaps: tuple[str, ...]


class PdfBackend(Protocol):
    def extract_pages(self, path: Path) -> tuple[str, ...]: ...


class OcrBackend(Protocol):
    def extract_pages(self, path: Path) -> tuple[str, ...]: ...


class OptionalPdfPlumberBackend:
    """Use pdfplumber when installed, with pypdf as a selectable-text fallback."""

    def extract_pages(self, path: Path) -> tuple[str, ...]:
        try:
            module = importlib.import_module("pdfplumber")
        except ModuleNotFoundError as exc:
            if exc.name != "pdfplumber":
                raise
            module = importlib.import_module("pypdf")
            pdf = module.PdfReader(str(path))
            return tuple(page.extract_text() or "" for page in pdf.pages)
        with module.open(str(path)) as pdf:
            return tuple(page.extract_text() or "" for page in pdf.pages)


_TIMESTAMP_KEY = re.compile(r"(?:_at|_time|_until|_timestamp|_date)$|^(?:timestamp|time)$", re.I)
_IDENTIFIER_KEYS = frozenset({
    "user_id", "customer_reference", "customer_ref", "subject_reference", "subject_ref",
    "subject_key", "resource_id", "source_resource_id", "order_id", "ticket_id",
    "support_id", "backup_id", "archive_id", "export_id", "connector_id", "flow_id",
    "audit_id", "activity_id", "object_id", "object_key", "email", "email_hash", "phone",
    "requester_email", "requester_phone", "customer_email", "owner_email",
    "source_system", "target_system",
})


def _snake(name: str) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").lower()


def _normal_value(key: str, value: Any) -> Any:
    if not isinstance(value, str):
        return value
    if key.lower() == "email":
        return value.strip().casefold()
    # Preserve phone, hashes, IDs and arbitrary text exactly. Their raw values
    # are also kept in raw_fields for later policy/identity interpretation.
    return value


def _freeze_map(values: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType(dict(values))


def _make_observation(
    entry: EvidenceFileDiscovery,
    *,
    locator: str,
    method: str,
    raw_fields: Mapping[str, Any],
    parent_observation_id: str | None = None,
    source_context: Mapping[str, str] | None = None,
) -> tuple[ExtractedObservation, tuple[ExtractionDiagnostic, ...]]:
    normalized: dict[str, Any] = {}
    timestamps: list[ObservationTimestamp] = []
    identifiers: list[IdentifierValue] = []
    warnings: list[ExtractionDiagnostic] = []
    conflicts: dict[str, set[str]] = {}

    for original_key, value in raw_fields.items():
        key = _snake(str(original_key))
        if key in normalized and normalized[key] != value:
            warnings.append(ExtractionDiagnostic("normalized_field_collision",
                "Different source fields normalize to the same field name.", "warning", locator))
            key = f"{key}__{original_key}"
        normalized[key] = _normal_value(key, value)
        lower_key = key.lower()
        if lower_key in _IDENTIFIER_KEYS and value is not None and not isinstance(value, (dict, list, bytes)):
            raw_id = str(value)
            norm_id = raw_id.strip().casefold() if "email" in lower_key and "hash" not in lower_key else raw_id.strip()
            identifiers.append(IdentifierValue(lower_key, raw_id, norm_id))
        if _TIMESTAMP_KEY.search(lower_key):
            raw_time = None if value is None else str(value)
            parsed = parse_timestamp(raw_time)
            normalized[key] = parsed.value.isoformat() if parsed.status is TimestampStatus.VALID else value
            timestamps.append(ObservationTimestamp(lower_key, raw_time, parsed))
            if parsed.status is not TimestampStatus.VALID:
                warnings.append(ExtractionDiagnostic(
                    parsed.error_code or "invalid_timestamp",
                    "Observation timestamp is missing, malformed, or timezone-naive; raw value retained.",
                    "warning", locator,
                ))
        if lower_key in {"system_id", "system", "source_system", "target_system", "origin_system", "service"} and value is not None:
            conflicts.setdefault("system_id", set()).add(str(value))
        if lower_key == "resource_id" and value is not None:
            conflicts.setdefault("resource_id", set()).add(str(value))

    explicit_systems = conflicts.get("system_id", set())
    contextual_system = (source_context or {}).get("system_id")
    if len(explicit_systems) == 1:
        explicit_system = next(iter(explicit_systems))
        if contextual_system and contextual_system != explicit_system:
            warnings.append(ExtractionDiagnostic("source_scope_conflict",
                "Explicit system fields conflict with the enclosing JSON service scope.", "warning", locator))
            system_id = None
        else:
            system_id = explicit_system
    elif explicit_systems:
        system_id = None
    else:
        system_id = contextual_system
    if source_context:
        # Context is projected from the JSON pointer but remains distinct from
        # raw source cells. source_path + locator preserve its exact provenance.
        if contextual_system:
            if explicit_systems and system_id is None:
                normalized.setdefault("source_system_context", contextual_system)
            else:
                normalized.setdefault("system_id", contextual_system)
        collection = source_context.get("collection_name")
        if collection:
            normalized.setdefault("collection_name", collection)
    resource_id = next(iter(conflicts["resource_id"])) if len(conflicts.get("resource_id", ())) == 1 else None
    if len(conflicts.get("system_id", ())) > 1 or len(conflicts.get("resource_id", ())) > 1:
        warnings.append(ExtractionDiagnostic("conflicting_projection",
            "Observation contains conflicting candidate system/resource identifiers; raw fields retained.",
            "warning", locator))

    observation_id = f"{entry.file_id}:{locator}"
    return ExtractedObservation(
        observation_id=observation_id, file_id=entry.file_id or "", source_path=entry.original_relative_path or "",
        file_format=entry.declared_file_type or "unknown", locator=locator, extraction_method=method,
        raw_fields=_freeze_map(raw_fields), normalized_fields=_freeze_map(normalized),
        identifiers=tuple(identifiers), system_id=system_id, resource_id=resource_id,
        timestamps=tuple(timestamps), captured_at=entry.captured_at,
        parent_observation_id=parent_observation_id,
    ), tuple(warnings)


def _map_json(value: Any, pointer: str = "") -> list[tuple[str, Mapping[str, Any]]]:
    """Yield dict observations at JSON pointers, skipping pure containers."""

    found: list[tuple[str, Mapping[str, Any]]] = []
    if isinstance(value, dict):
        if any(not isinstance(item, (dict, list)) for item in value.values()):
            found.append((pointer or "/", value))
        for key, child in value.items():
            escaped = str(key).replace("~", "~0").replace("/", "~1")
            found.extend(_map_json(child, f"{pointer}/{escaped}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found.extend(_map_json(child, f"{pointer}/{index}"))
    return found


def _json_source_context(pointer: str) -> Mapping[str, str]:
    """Project explicit service/collection hierarchy from supported JSON exports."""
    parts = [part.replace("~1", "/").replace("~0", "~") for part in pointer.split("/") if part]
    if len(parts) >= 3 and parts[0] == "service_exports":
        return {"system_id": parts[1], "collection_name": parts[2]}
    return {}


def _read_utf8(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig", errors="strict")


def _extract_json(entry: EvidenceFileDiscovery, text: str) -> tuple[list[ExtractedObservation], list[ExtractionDiagnostic], list[ExtractionDiagnostic], tuple[str, ...]]:
    if not text.strip():
        return [], [], [], ()
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        return [], [], [ExtractionDiagnostic("malformed_json", f"Invalid JSON at line {exc.lineno}, column {exc.colno}.")], ()
    observations: list[ExtractedObservation] = []
    warnings: list[ExtractionDiagnostic] = []
    for pointer, fields in _map_json(parsed):
        obs, diagnostics = _make_observation(entry, locator=f"json:{pointer}", method="stdlib-json",
                                             raw_fields=fields, source_context=_json_source_context(pointer))
        observations.append(obs)
        warnings.extend(diagnostics)
    scope = tuple(sorted({pointer for pointer, _ in _map_json(parsed) if pointer != "/"}))
    return observations, warnings, [], scope


def _extract_csv(entry: EvidenceFileDiscovery, text: str) -> tuple[list[ExtractedObservation], list[ExtractionDiagnostic], list[ExtractionDiagnostic], tuple[str, ...], bool]:
    if not text:
        return [], [], [], (), False
    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    try:
        headers = next(reader)
    except StopIteration:
        return [], [], [], (), False
    if not headers or any(not h for h in headers) or len(set(headers)) != len(headers):
        return [], [], [ExtractionDiagnostic("invalid_csv_header", "CSV evidence has an empty or duplicate header.")], (), False
    observations: list[ExtractedObservation] = []
    warnings: list[ExtractionDiagnostic] = []
    errors: list[ExtractionDiagnostic] = []
    width = len(headers)
    row_no = 1
    while True:
        try:
            cells = next(reader)
        except StopIteration:
            break
        except csv.Error as exc:
            errors.append(ExtractionDiagnostic("malformed_csv", f"CSV parsing stopped at physical line {reader.line_num}: {type(exc).__name__}.", locator=f"line:{reader.line_num}"))
            break
        row_no += 1
        fields = {headers[i]: cells[i] for i in range(min(width, len(cells)))}
        if len(cells) != width:
            warnings.append(ExtractionDiagnostic("row_width_mismatch", "CSV row width differs from its header; available cells retained.", "warning", f"row:{row_no}"))
        obs, obs_warnings = _make_observation(entry, locator=f"row:{row_no}", method="stdlib-csv", raw_fields=fields)
        observations.append(obs)
        warnings.extend(obs_warnings)
    return observations, warnings, errors, ("csv_rows",), True


def _extract_sql(entry: EvidenceFileDiscovery, text: str) -> tuple[list[ExtractedObservation], list[ExtractionDiagnostic], list[ExtractionDiagnostic], tuple[str, ...], bool]:
    if not text.strip():
        return [], [], [], (), False
    connection = sqlite3.connect(":memory:")
    connection.enable_load_extension(False)

    def authorizer(action: int, arg1: str | None, arg2: str | None, _db: str | None, _trigger: str | None) -> int:
        denied = {sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH}
        if hasattr(sqlite3, "SQLITE_FUNCTION") and action == sqlite3.SQLITE_FUNCTION and (arg2 or arg1 or "").lower() == "load_extension":
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_DENY if action in denied else sqlite3.SQLITE_OK

    connection.set_authorizer(authorizer)
    errors: list[ExtractionDiagnostic] = []
    try:
        try:
            connection.executescript(text)
        except sqlite3.Error as exc:
            errors.append(ExtractionDiagnostic("sql_execution_error", f"SQLite snapshot parse/execution failed: {type(exc).__name__}."))
        tables = [row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )]
        observations: list[ExtractedObservation] = []
        warnings: list[ExtractionDiagnostic] = []
        for table in tables:
            # Quote identifiers from sqlite_master safely; table name is never SQL syntax.
            quoted = '"' + table.replace('"', '""') + '"'
            cursor = connection.execute(f"SELECT * FROM {quoted}")
            columns = tuple(description[0] for description in (cursor.description or ()))
            for row_num, row in enumerate(cursor, 1):
                fields = dict(zip(columns, row))
                locator = f"table:{table}/row:{row_num}"
                obs, row_warnings = _make_observation(entry, locator=locator, method="sqlite-memory", raw_fields=fields)
                observations.append(obs)
                warnings.extend(row_warnings)
                for col, raw in fields.items():
                    if col.lower() == "record_json" and isinstance(raw, str) and raw.strip():
                        try:
                            nested = json.loads(raw)
                        except json.JSONDecodeError as exc:
                            warnings.append(ExtractionDiagnostic("malformed_nested_json", f"record_json is invalid JSON at line {exc.lineno}.", "warning", locator))
                        else:
                            for pointer, nested_fields in _map_json(nested):
                                # Keep the row's explicit scope and category on
                                # its nested record_json child. The child keeps
                                # its own values authoritative and retains the
                                # parent_observation_id provenance link; this
                                # avoids losing origin_system/collection_name
                                # before identity, policy, and state processing.
                                inherited_scope = {
                                    name: fields[name] for name in
                                    ("system_id", "system", "service", "origin_system", "collection_name")
                                    if name in fields and fields[name] not in (None, "")
                                }
                                child_fields = {**inherited_scope, **nested_fields}
                                child, child_warnings = _make_observation(
                                    entry, locator=f"{locator}/record_json:{pointer}", method="sqlite-json-field",
                                    raw_fields=child_fields, parent_observation_id=obs.observation_id,
                                )
                                observations.append(child)
                                warnings.extend(child_warnings)
        return observations, warnings, errors, tuple(f"table:{table}" for table in tables), bool(tables)
    finally:
        connection.close()


_ISO_PREFIX = re.compile(r"^(\d{4}-\d{2}-\d{2}T[^\s]+)(?:\s+|$)")
_KV = re.compile(r"([A-Za-z_][A-Za-z0-9_.-]*)=")


def _parse_log_fields(rest: str) -> tuple[dict[str, Any], str]:
    """Parse quoted key=value tokens and retain any unstructured prefix."""
    fields: dict[str, Any] = {}
    matches = list(_KV.finditer(rest))
    if not matches:
        return fields, rest.strip()
    prefix = rest[:matches[0].start()].strip(" |\t")
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(rest)
        raw_value = rest[match.end():end].strip().rstrip("| ")
        try:
            tokens = shlex.split(raw_value, posix=True)
            value: Any = " ".join(tokens) if len(tokens) > 1 else (tokens[0] if tokens else "")
        except ValueError:
            value = raw_value
        fields[match.group(1)] = value
    return fields, prefix


def _extract_log(entry: EvidenceFileDiscovery, text: str) -> tuple[list[ExtractedObservation], list[ExtractionDiagnostic], list[ExtractionDiagnostic], tuple[str, ...], bool]:
    if not text:
        return [], [], [], (), False
    observations: list[ExtractedObservation] = []
    warnings: list[ExtractionDiagnostic] = []
    errors: list[ExtractionDiagnostic] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        raw_fields: dict[str, Any] = {"line_text": line}
        match = _ISO_PREFIX.match(line)
        body = line
        if match:
            raw_fields["timestamp"] = match.group(1)
            body = line[match.end():]
        stripped = body.strip()
        json_start = stripped.find("{")
        if json_start >= 0 and stripped.endswith("}"):
            try:
                structured = json.loads(stripped[json_start:])
            except json.JSONDecodeError:
                errors.append(ExtractionDiagnostic("malformed_structured_log", "JSON-like log payload is malformed; raw line retained.", "error", f"line:{line_no}"))
            else:
                if isinstance(structured, dict):
                    raw_fields.update(structured)
                    raw_fields["record_prefix"] = stripped[:json_start].strip()
                    body = ""
        if body:
            fields, prefix = _parse_log_fields(body)
            raw_fields.update(fields)
            if prefix:
                raw_fields["record_prefix"] = prefix
        obs, obs_warnings = _make_observation(entry, locator=f"line:{line_no}", method="utf8-log-line", raw_fields=raw_fields)
        observations.append(obs)
        warnings.extend(obs_warnings)
    return observations, warnings, errors, ("log_lines",), True


def _extract_text(entry: EvidenceFileDiscovery, text: str) -> tuple[list[ExtractedObservation], list[ExtractionDiagnostic], tuple[str, ...], bool]:
    if not text:
        return [], [], (), False
    observations: list[ExtractedObservation] = []
    warnings: list[ExtractionDiagnostic] = []
    lines = text.splitlines()
    blocks: list[tuple[int, int, str]] = []
    start: int | None = None
    current: list[str] = []
    for line_no, line in enumerate(lines, 1):
        if line.strip():
            if start is None:
                start = line_no
            current.append(line)
        elif current:
            blocks.append((start or line_no, line_no - 1, "\n".join(current)))
            start, current = None, []
    if current:
        blocks.append((start or 1, len(lines), "\n".join(current)))
    for first, last, block in blocks:
        fields: dict[str, Any] = {"text": block}
        pairs: dict[str, str] = {}
        for line in block.splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                if re.fullmatch(r"[A-Za-z][A-Za-z0-9 _-]{0,60}", key.strip()) and value.strip():
                    pairs[key.strip()] = value.strip()
        fields.update(pairs)
        obs, obs_warnings = _make_observation(entry, locator=f"lines:{first}-{last}", method="utf8-text-block", raw_fields=fields)
        observations.append(obs)
        warnings.extend(obs_warnings)
    return observations, warnings, ("text_blocks",), True


_PDF_USER_ID = re.compile(r"\buser_[0-9]+\b", re.IGNORECASE)
_PDF_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_PDF_ORDER_ID = re.compile(r"\bORD-[0-9]+\b", re.IGNORECASE)
_PDF_AUDIT_ID = re.compile(r"\bEvent\s+reference\s+(audit_record_[A-Za-z0-9_-]+)\b", re.IGNORECASE)
_PDF_REGISTER_ROW = re.compile(
    r"(?m)^\s*(\d+)\s+(ORD-[0-9]+)\s*\|\s*(user_[0-9]+)\s*\|\s*([^|]+)\s*\|\s*"
    r"([^|]+)\s*\|\s*([A-Z]{3}\s+[0-9,.]+)\s*\|\s*Retain\s+until\s*([^|]+)\s*\|\s*([^|\s]+)",
    re.IGNORECASE,
)
_PDF_MONTHS = {name.casefold(): index for index, name in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1)}


def _pdf_utc_timestamp(value: str) -> str | None:
    """Normalize explicit `DD Mon YYYY HH MM UTC` labels without guessing zones."""
    match = re.fullmatch(r"\s*(\d{1,2})\s+([A-Za-z]{3})\s+(\d{4})\s+(\d{1,2})\s+(\d{2})\s+UTC\s*", value)
    if not match:
        return None
    day, month, year, hour, minute = match.groups()
    month_no = _PDF_MONTHS.get(month.casefold())
    if month_no is None:
        return None
    try:
        from datetime import datetime, timezone
        parsed = datetime(int(year), month_no, int(day), int(hour), int(minute), tzinfo=timezone.utc)
    except ValueError:
        return None
    return parsed.isoformat().replace("+00:00", "Z")


def _pdf_structured_fields(entry: EvidenceFileDiscovery, page: str) -> dict[str, Any]:
    """Extract only uniquely identified, explicitly labelled PDF facts.

    Full page text is always retained separately. Ambiguous multi-subject pages
    are not collapsed into a guessed identity; recognized register rows are
    split by their explicit row boundaries in `_extract_pdf_pages`.
    """
    fields: dict[str, Any] = {}
    user_ids = sorted(set(_PDF_USER_ID.findall(page)))
    emails = sorted(set(_PDF_EMAIL.findall(page)))
    order_ids = sorted(set(_PDF_ORDER_ID.findall(page)))
    if len(user_ids) == 1:
        fields["user_id"] = user_ids[0]
    if len(emails) == 1:
        fields["email"] = emails[0]
    if len(order_ids) == 1:
        fields["order_id"] = order_ids[0]

    audit_match = _PDF_AUDIT_ID.search(page)
    if audit_match:
        fields["resource_id"] = audit_match.group(1)
        # The source calls this a signed compliance journal extract and labels
        # the referenced object as an audit record. This maps only that explicit
        # combination to the supplied security-audit policy category.
        if "COMPLIANCE JOURNAL" in page.upper():
            fields["data_category"] = "SECURITY_AUDIT_LOG"
        if entry.origin == "security_service":
            fields["system_id"] = entry.origin

    for label, field_name in (("recorded", "recorded_at"), ("retain until", "retention_until"),
                              ("issued", "issued_at"), ("submitted", "submitted_at"),
                              ("captured", "document_captured_at")):
        pattern = re.compile(rf"\b{re.escape(label)}\s+([^\n]+)", re.IGNORECASE)
        match = pattern.search(page)
        if match:
            normalized = _pdf_utc_timestamp(match.group(1).strip())
            if normalized is not None:
                fields[field_name] = normalized
    return fields


def _extract_pdf_pages(entry: EvidenceFileDiscovery, pages: tuple[str, ...]) -> tuple[
        list[ExtractedObservation], list[ExtractionDiagnostic], list[ExtractionDiagnostic], tuple[str, ...]]:
    observations: list[ExtractedObservation] = []
    warnings: list[ExtractionDiagnostic] = []
    errors: list[ExtractionDiagnostic] = []
    for page_no, page in enumerate(pages, 1):
        if not page.strip():
            warnings.append(ExtractionDiagnostic("page_has_no_extractable_text",
                "Page produced no text; this does not establish empty evidence.", "warning", f"page:{page_no}"))
            continue
        fields = {"page_text": page}
        fields.update(_pdf_structured_fields(entry, page))
        obs, obs_warnings = _make_observation(entry, locator=f"page:{page_no}",
            method="pdf-text-page", raw_fields=fields)
        observations.append(obs)
        warnings.extend(obs_warnings)
        for row in _PDF_REGISTER_ROW.finditer(page):
            row_fields = {
                "register_row_number": row.group(1), "order_id": row.group(2),
                "user_id": row.group(3), "retention_reason": row.group(4).strip(),
                "invoice_date_text": row.group(5).strip(), "amount_currency": row.group(6).strip(),
                "retention_deadline_date_text": row.group(7).strip(), "finance_owner": row.group(8).strip(),
                "page_text": row.group(0).strip(),
            }
            row_obs, row_warnings = _make_observation(entry,
                locator=f"page:{page_no}/register-row:{row.group(1)}",
                method="pdf-text-register-row", raw_fields=row_fields)
            observations.append(row_obs)
            warnings.extend(row_warnings)
    return observations, warnings, errors, tuple(f"page:{i}" for i in range(1, len(pages) + 1))


def _extract_pages(entry: EvidenceFileDiscovery, pages: tuple[str, ...], method: str) -> tuple[list[ExtractedObservation], list[ExtractionDiagnostic], list[ExtractionDiagnostic], tuple[str, ...]]:
    observations: list[ExtractedObservation] = []
    warnings: list[ExtractionDiagnostic] = []
    errors: list[ExtractionDiagnostic] = []
    for page_no, page in enumerate(pages, 1):
        if not page.strip():
            warnings.append(ExtractionDiagnostic("page_has_no_extractable_text", "Page produced no text; this does not establish empty evidence.", "warning", f"page:{page_no}"))
            continue
        fields: dict[str, Any] = {"page_text": page}
        obs, obs_warnings = _make_observation(entry, locator=f"page:{page_no}", method=method, raw_fields=fields)
        observations.append(obs)
        warnings.extend(obs_warnings)
    if not pages:
        errors.append(ExtractionDiagnostic("no_pages_extracted", "Document backend returned no pages."))
    scope = tuple(f"page:{i}" for i in range(1, len(pages) + 1))
    return observations, warnings, errors, scope


def _extract_single(entry: EvidenceFileDiscovery, pdf_backend: PdfBackend | None, ocr_backend: OcrBackend | None) -> FileExtractionResult:
    file_id = entry.file_id or ""
    suffix = Path(entry.original_relative_path or "").suffix.lower()
    fmt = entry.declared_file_type or suffix.lstrip(".") or "unknown"
    parser = "none"
    empty_text = False

    if entry.outcome is DiscoveryOutcome.MISSING:
        status = ExtractionStatus.MISSING
        errors = (ExtractionDiagnostic("evidence_missing", "Manifest-listed evidence file is missing."),)
        return FileExtractionResult(file_id, entry.original_relative_path or "", fmt, parser, status, entry.captured_at, (), (), (), errors)
    if entry.outcome is DiscoveryOutcome.INACCESSIBLE:
        status = ExtractionStatus.INACCESSIBLE
        errors = (ExtractionDiagnostic("evidence_inaccessible", "Evidence file could not be read during discovery."),)
        return FileExtractionResult(file_id, entry.original_relative_path or "", fmt, parser, status, entry.captured_at, (), (), (), errors)
    if entry.outcome is DiscoveryOutcome.REJECTED:
        is_unsupported = any(d.code == "unsupported_file_type" for d in entry.diagnostics)
        status = ExtractionStatus.UNSUPPORTED if is_unsupported else ExtractionStatus.REJECTED
        errors = tuple(ExtractionDiagnostic(d.code, d.message) for d in entry.diagnostics)
        return FileExtractionResult(file_id, entry.original_relative_path or "", fmt, parser, status, entry.captured_at, (), (), (), errors)
    path = entry.resolved_path
    if path is None:
        return FileExtractionResult(file_id, entry.original_relative_path or "", fmt, parser, ExtractionStatus.FAILED,
                                    entry.captured_at, (), (), (), (ExtractionDiagnostic("resolved_path_missing", "No resolved path was supplied by manifest discovery."),))

    observations: list[ExtractedObservation] = []
    warnings: list[ExtractionDiagnostic] = []
    errors: list[ExtractionDiagnostic] = []
    scope: tuple[str, ...] = ()
    try:
        if suffix == ".png":
            backend = ocr_backend or BundledPngTranscriptBackend()
            parser = type(backend).__name__
            try:
                pages = backend.extract_pages(path)
            except Exception as exc:
                errors.append(ExtractionDiagnostic("ocr_extraction_failed", f"Image text extraction failed: {type(exc).__name__}."))
            else:
                method = getattr(backend, "extraction_method", "ocr-page-text")
                observations, warnings, errors, scope = _extract_pages(entry, pages, method)
                structured = getattr(backend, "extract_structured_records", None)
                if callable(structured) and pages and observations:
                    page = pages[0]
                    page_observation = observations[0]
                    structured_records = tuple(structured(path))
                    for index, (anchor, projected_fields) in enumerate(structured_records, 1):
                        if not anchor or anchor not in page:
                            errors.append(ExtractionDiagnostic(
                                "transcript_anchor_missing",
                                "Structured screenshot facts did not match their verified transcript anchor.",
                                locator=f"record:{index}",
                            ))
                            continue
                        fields = {"page_text": page, "record_text": anchor, **dict(projected_fields)}
                        # Manifest origin is retained as system scope only where
                        # the matching PDF parser already establishes that exact
                        # source-origin mapping (the signed security journal).
                        if entry.origin == "security_service" and "system_id" not in fields:
                            fields["system_id"] = entry.origin
                        obs, obs_warnings = _make_observation(
                            entry, locator=f"page:1/structured:{index}", method=method,
                            raw_fields=fields, parent_observation_id=page_observation.observation_id,
                        )
                        observations.append(obs)
                        warnings.extend(obs_warnings)
                    if structured_records:
                        scope = (*scope, "structured_records")
        elif suffix == ".pdf":
            backend = pdf_backend or OptionalPdfPlumberBackend()
            parser = type(backend).__name__
            try:
                pages = backend.extract_pages(path)
            except Exception as exc:
                errors.append(ExtractionDiagnostic("pdf_extraction_failed", f"PDF text extraction failed: {type(exc).__name__}."))
            else:
                    observations, warnings, errors, scope = _extract_pdf_pages(entry, pages)
        else:
            parser = {".json": "stdlib-json", ".sql": "sqlite-memory", ".log": "utf8-log-line", ".csv": "stdlib-csv", ".txt": "utf8-text-block"}.get(suffix, "unsupported")
            raw = path.read_bytes()
            if not raw:
                empty_text = True
            else:
                text = raw.decode("utf-8-sig", errors="strict")
                if suffix == ".json":
                    observations, warnings, errors, scope = _extract_json(entry, text)
                elif suffix == ".sql":
                    observations, warnings, errors, scope, empty_text = _extract_sql(entry, text)
                elif suffix == ".log":
                    observations, warnings, errors, scope, empty_text = _extract_log(entry, text)
                elif suffix == ".csv":
                    observations, warnings, errors, scope, empty_text = _extract_csv(entry, text)
                elif suffix == ".txt":
                    observations, warnings, scope, empty_text = _extract_text(entry, text)
                else:
                    return FileExtractionResult(file_id, entry.original_relative_path or "", fmt, parser,
                        ExtractionStatus.UNSUPPORTED, entry.captured_at, (), (), (),
                        (ExtractionDiagnostic("unsupported_file_type", "No extractor is registered for this format."),))
    except UnicodeDecodeError as exc:
        errors.append(ExtractionDiagnostic("invalid_text_encoding", f"Text evidence is not valid UTF-8 at byte {exc.start}."))
    except OSError as exc:
        return FileExtractionResult(file_id, entry.original_relative_path or "", fmt, parser,
            ExtractionStatus.INACCESSIBLE, entry.captured_at, (), (), (),
            (ExtractionDiagnostic("evidence_read_error", f"Evidence read failed: {type(exc).__name__}."),))
    except sqlite3.Error as exc:
        errors.append(ExtractionDiagnostic("sql_extraction_failed", f"SQLite extraction failed: {type(exc).__name__}."))

    if errors:
        status = ExtractionStatus.PARTIAL if observations else ExtractionStatus.FAILED
    elif any(w.code in {"normalized_field_collision", "row_width_mismatch"} for w in warnings) and observations:
        status = ExtractionStatus.PARTIAL
    elif observations:
        status = ExtractionStatus.COMPLETE
    elif empty_text:
        status = ExtractionStatus.EMPTY
    elif suffix == ".pdf" and scope and not observations:
        # A text backend parsed pages but found no selectable text. Do not call
        # it empty evidence, because a page may contain scanned imagery.
        status = ExtractionStatus.FAILED
        errors = [*errors, ExtractionDiagnostic("pdf_no_extractable_text", "PDF pages contain no selectable text; image/OCR review is required.")]
    elif suffix == ".png":
        status = ExtractionStatus.FAILED
    else:
        status = ExtractionStatus.EMPTY
    return FileExtractionResult(file_id, entry.original_relative_path or "", fmt, parser, status,
                                entry.captured_at, tuple(observations), scope, tuple(warnings), tuple(errors))


def extract_evidence(
    discovery: EvidenceDiscoveryResult,
    *,
    pdf_backend: PdfBackend | None = None,
    ocr_backend: OcrBackend | None = None,
) -> EvidenceExtractionResult:
    """Extract all discovered entries deterministically without case cutoffs."""
    ordered = sorted(discovery.entries, key=lambda entry: (entry.file_id or "", entry.original_relative_path or ""))
    return EvidenceExtractionResult(tuple(_extract_single(entry, pdf_backend, ocr_backend) for entry in ordered))


def build_case_coverage(
    candidate_file_ids_by_case: Mapping[str, tuple[str, ...] | list[str]],
    extraction: EvidenceExtractionResult,
) -> tuple[CaseEvidenceCoverage, ...]:
    """Aggregate extraction availability for candidate files; never applies audit_at.

    Candidate sets must come from a later case-scoped process. A failed candidate
    is conservatively recorded as a gap, without asserting that it is relevant.
    """
    by_id = extraction.by_file_id
    results: list[CaseEvidenceCoverage] = []
    for case_id in sorted(candidate_file_ids_by_case):
        candidates = tuple(sorted(set(candidate_file_ids_by_case[case_id])))
        examined: list[str] = []
        facts: list[str] = []
        failed: list[str] = []
        gaps: list[str] = []
        for file_id in candidates:
            result = by_id.get(file_id)
            if result is None:
                failed.append(file_id)
                gaps.append(f"candidate_file_unavailable:{file_id}")
                continue
            if result.status in {ExtractionStatus.COMPLETE, ExtractionStatus.PARTIAL, ExtractionStatus.EMPTY}:
                examined.append(file_id)
                facts.extend(obs.observation_id for obs in result.observations)
            if result.status not in {ExtractionStatus.COMPLETE, ExtractionStatus.EMPTY}:
                failed.append(file_id)
                gaps.append(f"candidate_file_not_fully_extracted:{file_id}:{result.status.value}")
        results.append(CaseEvidenceCoverage(
            case_id=case_id, candidate_file_ids=candidates, examined_file_ids=tuple(examined),
            observation_ids=tuple(sorted(facts)), failed_file_ids=tuple(failed), material_gaps=tuple(gaps),
        ))
    return tuple(results)

