"""Read-only CSV ingestion and schema validation for participant data."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Iterable, Mapping

from .models import (
    CsvRecord,
    CsvTable,
    DatasetBundle,
    IngestionResult,
    IssueSeverity,
    ParsedTimestamp,
    SourceLocation,
    TimestampStatus,
    ValidationIssue,
)


# These controlled values are enumerated by the participant-facing contract or
# by the supplied deletion_rules.csv schema. Other fields remain uncoerced text.
REPORTED_STATUSES = frozenset({"COMPLETE", "PARTIALLY_COMPLETE", "NOT_STARTED"})
OUTPUT_STATUSES = frozenset({"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"})
POLICY_ACTIONS = frozenset({"DELETE", "REDACT", "ANONYMIZE", "RETAIN"})


@dataclass(frozen=True)
class CsvSchema:
    name: str
    filename: str
    columns: tuple[str, ...]
    required_values: frozenset[str] = frozenset()
    timestamp_columns: frozenset[str] = frozenset()
    enum_columns: Mapping[str, frozenset[str]] = field(default_factory=dict)
    unique_columns: tuple[str, ...] = ()
    expected_rows: int | None = None
    strict_header_order: bool = False
    json_array_columns: frozenset[str] = frozenset()


DATASET_SCHEMAS: tuple[CsvSchema, ...] = (
    CsvSchema(
        "deletion_requests",
        "deletion_requests.csv",
        ("case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"),
        frozenset(
            {"case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"}
        ),
        frozenset({"requested_at", "reported_at", "audit_at"}),
        {"reported_status": REPORTED_STATUSES},
        ("case_id",),
        518,
        True,
    ),
    CsvSchema(
        "sample_deletion_requests",
        "sample_deletion_requests.csv",
        ("case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"),
        frozenset(
            {"case_id", "email", "requested_at", "reported_status", "reported_at", "audit_at", "request_text"}
        ),
        frozenset({"requested_at", "reported_at", "audit_at"}),
        {"reported_status": REPORTED_STATUSES},
        ("case_id",),
        32,
        True,
    ),
    CsvSchema(
        "sample_output",
        "sample_output.csv",
        ("case_id", "deletion_status", "steps_json"),
        frozenset({"case_id", "deletion_status", "steps_json"}),
        enum_columns={"deletion_status": OUTPUT_STATUSES},
        unique_columns=("case_id",),
        expected_rows=32,
        strict_header_order=True,
        json_array_columns=frozenset({"steps_json"}),
    ),
    CsvSchema(
        "user_identities",
        "user_identities.csv",
        ("user_id", "name", "email", "phone", "email_hash", "updated_at"),
        frozenset({"user_id", "updated_at"}),
        frozenset({"updated_at"}),
        unique_columns=("user_id",),
    ),
    CsvSchema(
        "user_audit_log",
        "user_audit_log.csv",
        ("audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"),
        frozenset({"audit_id", "user_id", "event_time", "field_name"}),
        frozenset({"event_time"}),
        unique_columns=("audit_id",),
    ),
    CsvSchema(
        "system_activity",
        "system_activity.csv",
        (
            "activity_id",
            "event_time",
            "event_type",
            "source_system",
            "target_system",
            "resource_id",
            "reported_result",
            "details",
        ),
        frozenset({"activity_id", "event_time", "event_type"}),
        frozenset({"event_time"}),
        unique_columns=("activity_id",),
    ),
    CsvSchema(
        "deletion_rules",
        "deletion_rules.csv",
        ("rule_id", "data_category", "condition", "required_action"),
        frozenset({"rule_id", "data_category", "condition", "required_action"}),
        enum_columns={"required_action": POLICY_ACTIONS},
        unique_columns=("rule_id",),
    ),
    CsvSchema(
        "evidence_files",
        "evidence_files.csv",
        ("file_id", "file_path", "origin", "captured_at"),
        frozenset({"file_id", "file_path", "origin", "captured_at"}),
        frozenset({"captured_at"}),
        unique_columns=("file_id",),
    ),
    CsvSchema(
        "output_template",
        "output.csv",
        ("case_id", "deletion_status", "steps_json"),
        enum_columns={"deletion_status": OUTPUT_STATUSES},
        unique_columns=("case_id",),
        expected_rows=0,
        strict_header_order=True,
    ),
)


def parse_timestamp(raw: str | None) -> ParsedTimestamp:
    """Parse an ISO-8601 timestamp with an explicit offset and normalize to UTC."""

    if raw is None or not raw.strip():
        return ParsedTimestamp(raw, TimestampStatus.MISSING, error_code="missing_timestamp")

    value = raw.strip()
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return ParsedTimestamp(raw, TimestampStatus.INVALID, error_code="malformed_timestamp")

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return ParsedTimestamp(raw, TimestampStatus.INVALID, error_code="timezone_required")

    return ParsedTimestamp(raw, TimestampStatus.VALID, parsed.astimezone(timezone.utc))


def _issue(
    code: str,
    severity: IssueSeverity,
    path: Path,
    message: str,
    *,
    record_number: int | None = None,
    physical_line: int | None = None,
    column: str | None = None,
) -> ValidationIssue:
    return ValidationIssue(
        code=code,
        severity=severity,
        source_file=path.name,
        message=message,
        record_number=record_number,
        physical_line=physical_line,
        column=column,
    )


def _normalize_record(
    path: Path,
    schema: CsvSchema,
    headers: tuple[str, ...],
    cells: list[str],
    record_number: int,
    physical_line_end: int,
    issues: list[ValidationIssue],
) -> CsvRecord:
    width = len(headers)
    missing_cell_count = max(0, width - len(cells))
    extra_cells = tuple(cells[width:]) if len(cells) > width else ()
    if missing_cell_count or extra_cells:
        issues.append(
            _issue(
                "row_width_mismatch",
                IssueSeverity.ERROR,
                path,
                f"CSV record has {len(cells)} cells; expected {width}.",
                record_number=record_number,
                physical_line=physical_line_end,
            )
        )

    raw_values: dict[str, str | None] = {
        column: cells[index] if index < len(cells) else None
        for index, column in enumerate(headers)
    }
    typed_values: dict[str, object] = dict(raw_values)

    for column in schema.required_values:
        value = raw_values.get(column)
        if value is None or not value.strip():
            issues.append(
                _issue(
                    "missing_required_value",
                    IssueSeverity.ERROR,
                    path,
                    "Required value is empty.",
                    record_number=record_number,
                    physical_line=physical_line_end,
                    column=column,
                )
            )

    for column in schema.timestamp_columns:
        parsed = parse_timestamp(raw_values.get(column))
        typed_values[column] = parsed
        if parsed.status is not TimestampStatus.VALID:
            issues.append(
                _issue(
                    parsed.error_code or "invalid_timestamp",
                    IssueSeverity.ERROR,
                    path,
                    "Timestamp is missing, malformed, or lacks an explicit timezone.",
                    record_number=record_number,
                    physical_line=physical_line_end,
                    column=column,
                )
            )

    for column, allowed_values in schema.enum_columns.items():
        value = raw_values.get(column)
        if value is not None and value and value not in allowed_values:
            issues.append(
                _issue(
                    "invalid_enum_value",
                    IssueSeverity.ERROR,
                    path,
                    "Value is outside the documented allowed set.",
                    record_number=record_number,
                    physical_line=physical_line_end,
                    column=column,
                )
            )

    for column in schema.json_array_columns:
        value = raw_values.get(column)
        if value is None or not value.strip():
            continue
        try:
            parsed_json = json.loads(value)
        except json.JSONDecodeError:
            issues.append(
                _issue(
                    "malformed_json_array",
                    IssueSeverity.ERROR,
                    path,
                    "Value is not valid JSON.",
                    record_number=record_number,
                    physical_line=physical_line_end,
                    column=column,
                )
            )
            continue
        if not isinstance(parsed_json, list):
            issues.append(
                _issue(
                    "wrong_json_type",
                    IssueSeverity.ERROR,
                    path,
                    "Value must be a JSON array.",
                    record_number=record_number,
                    physical_line=physical_line_end,
                    column=column,
                )
            )
            continue
        typed_values[column] = parsed_json

    return CsvRecord(
        source=SourceLocation(path.name, record_number, physical_line_end),
        raw_values=MappingProxyType(raw_values),
        typed_values=MappingProxyType(typed_values),
        raw_cells=tuple(cells),
        extra_cells=extra_cells,
    )


def read_csv_file(path: Path | str, schema: CsvSchema) -> tuple[CsvTable | None, tuple[ValidationIssue, ...]]:
    """Read one CSV without losing malformed row data or hiding diagnostics.

    File-level failures (unavailable file, encoding, unusable header, CSV syntax)
    are fatal. Recoverable row-width, missing-value, timestamp, enum, and duplicate
    key issues are attached to retained records as row-level errors.
    """

    source_path = Path(path)
    issues: list[ValidationIssue] = []
    records: list[CsvRecord] = []
    headers: tuple[str, ...] = ()
    complete = True

    try:
        with source_path.open("r", encoding="utf-8-sig", errors="strict", newline="") as handle:
            reader = csv.reader(handle, strict=True)
            try:
                header_cells = next(reader)
            except StopIteration:
                issues.append(
                    _issue("empty_file", IssueSeverity.FATAL, source_path, "File has no CSV header.")
                )
                return None, tuple(issues)

            headers = tuple(header_cells)
            if not headers or all(not value for value in headers):
                issues.append(
                    _issue("empty_header", IssueSeverity.FATAL, source_path, "CSV header is empty.")
                )
                return None, tuple(issues)
            if any(not value for value in headers):
                issues.append(
                    _issue(
                        "blank_header_name",
                        IssueSeverity.FATAL,
                        source_path,
                        "CSV header contains a blank name.",
                    )
                )
                complete = False
            if len(set(headers)) != len(headers):
                issues.append(
                    _issue(
                        "duplicate_header",
                        IssueSeverity.FATAL,
                        source_path,
                        "CSV header contains duplicate names.",
                    )
                )
                return None, tuple(issues)

            expected = set(schema.columns)
            actual = set(headers)
            missing = sorted(expected - actual)
            unexpected = sorted(actual - expected)
            if missing or unexpected:
                details = []
                if missing:
                    details.append("missing required columns: " + ", ".join(missing))
                if unexpected:
                    details.append("unexpected columns: " + ", ".join(unexpected))
                issues.append(
                    _issue("header_mismatch", IssueSeverity.FATAL, source_path, "; ".join(details))
                )
                complete = False
            if schema.strict_header_order and headers != schema.columns:
                issues.append(
                    _issue(
                        "header_order_mismatch",
                        IssueSeverity.FATAL,
                        source_path,
                        "Header order does not match the documented contract.",
                    )
                )
                complete = False

            seen_keys: dict[str, dict[str, int]] = {column: {} for column in schema.unique_columns}
            record_number = 1
            while True:
                try:
                    cells = next(reader)
                except StopIteration:
                    break
                except csv.Error as exc:
                    issues.append(
                        _issue(
                            "malformed_csv_syntax",
                            IssueSeverity.FATAL,
                            source_path,
                            f"CSV parser stopped at physical line {reader.line_num}: {type(exc).__name__}.",
                            physical_line=reader.line_num,
                        )
                    )
                    complete = False
                    break

                record_number += 1
                record = _normalize_record(
                    source_path, schema, headers, cells, record_number, reader.line_num, issues
                )
                records.append(record)

                for column, seen in seen_keys.items():
                    value = record.raw(column)
                    if value is None or not value.strip():
                        continue
                    if value in seen:
                        issues.append(
                            _issue(
                                "duplicate_identifier",
                                IssueSeverity.ERROR,
                                source_path,
                                f"Duplicate value for unique key; first seen in record {seen[value]}.",
                                record_number=record_number,
                                physical_line=reader.line_num,
                                column=column,
                            )
                        )
                    else:
                        seen[value] = record_number

    except FileNotFoundError:
        issues.append(
            _issue("file_unavailable", IssueSeverity.FATAL, source_path, "Required CSV file was not found.")
        )
        return None, tuple(issues)
    except UnicodeDecodeError as exc:
        issues.append(
            _issue(
                "invalid_encoding",
                IssueSeverity.FATAL,
                source_path,
                f"File is not valid UTF-8 near byte {exc.start}.",
            )
        )
        return None, tuple(issues)
    except csv.Error as exc:
        issues.append(
            _issue(
                "malformed_csv_syntax",
                IssueSeverity.FATAL,
                source_path,
                f"CSV parser failed: {type(exc).__name__}.",
            )
        )
        complete = False
    except OSError as exc:
        issues.append(
            _issue(
                "file_read_error",
                IssueSeverity.FATAL,
                source_path,
                f"Could not read file: {type(exc).__name__}.",
            )
        )
        return None, tuple(issues)

    if schema.expected_rows is not None and len(records) != schema.expected_rows:
        issues.append(
            _issue(
                "row_count_mismatch",
                IssueSeverity.FATAL,
                source_path,
                f"Expected {schema.expected_rows} data rows; parsed {len(records)}.",
            )
        )
        complete = False

    table = CsvTable(
        name=schema.name,
        path=source_path,
        headers=headers,
        records=tuple(records),
        parse_complete=complete,
        issues=tuple(issues),
    )
    return table, tuple(issues)


def _ordered_issues(issues: Iterable[ValidationIssue]) -> tuple[ValidationIssue, ...]:
    severity_order = {IssueSeverity.FATAL: 0, IssueSeverity.ERROR: 1, IssueSeverity.WARNING: 2}
    return tuple(
        sorted(
            issues,
            key=lambda issue: (
                issue.source_file,
                issue.record_number or 0,
                issue.physical_line or 0,
                issue.column or "",
                severity_order[issue.severity],
                issue.code,
            ),
        )
    )


def load_dataset(dataset_dir: Path | str) -> IngestionResult:
    """Load all participant CSV inputs and return structured diagnostics.

    This function is strictly read-only. It intentionally retains valid rows when
    another file or row has an error, so callers can report all issues at once.
    """

    root = Path(dataset_dir)
    tables: dict[str, CsvTable] = {}
    issues: list[ValidationIssue] = []
    for schema in DATASET_SCHEMAS:
        table, file_issues = read_csv_file(root / schema.filename, schema)
        issues.extend(file_issues)
        if table is not None:
            tables[schema.name] = table
    return IngestionResult(DatasetBundle(MappingProxyType(tables)), _ordered_issues(issues))

