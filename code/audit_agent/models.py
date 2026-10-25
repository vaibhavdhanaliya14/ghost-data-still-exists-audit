"""Immutable, provenance-preserving data structures for CSV ingestion."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Mapping


class IssueSeverity(str, Enum):
    """How much of an ingestion result an issue invalidates."""

    FATAL = "fatal"
    ERROR = "error"
    WARNING = "warning"


class TimestampStatus(str, Enum):
    VALID = "valid"
    MISSING = "missing"
    INVALID = "invalid"


@dataclass(frozen=True)
class ParsedTimestamp:
    """A raw timestamp and its normalized UTC value, or an explicit failure."""

    raw: str | None
    status: TimestampStatus
    value: datetime | None = None
    error_code: str | None = None


@dataclass(frozen=True)
class SourceLocation:
    """Location of one logical CSV record in its source file."""

    source_file: str
    record_number: int
    physical_line_end: int


@dataclass(frozen=True)
class CsvRecord:
    """One CSV record, retaining its original cells and typed projections."""

    source: SourceLocation
    raw_values: Mapping[str, str | None]
    typed_values: Mapping[str, Any]
    raw_cells: tuple[str, ...]
    extra_cells: tuple[str, ...] = ()

    def raw(self, column: str) -> str | None:
        return self.raw_values.get(column)

    def typed(self, column: str) -> Any:
        return self.typed_values.get(column)


@dataclass(frozen=True)
class ValidationIssue:
    """Structured diagnostic; messages never include raw personal values."""

    code: str
    severity: IssueSeverity
    source_file: str
    message: str
    record_number: int | None = None
    physical_line: int | None = None
    column: str | None = None

    @property
    def is_file_level(self) -> bool:
        return self.record_number is None


@dataclass(frozen=True)
class CsvTable:
    """Parsed table with source ordering and explicit row-level issues."""

    name: str
    path: Path
    headers: tuple[str, ...]
    records: tuple[CsvRecord, ...]
    parse_complete: bool
    issues: tuple[ValidationIssue, ...] = ()

    def sorted_records_by(self, *columns: str) -> tuple[CsvRecord, ...]:
        """Return a deterministic view without changing source/provenance order."""

        missing = [column for column in columns if column not in self.headers]
        if missing:
            raise KeyError(f"Unknown sort columns for {self.name}: {', '.join(missing)}")

        def key(record: CsvRecord) -> tuple[str, ...]:
            return tuple(record.raw(column) or "" for column in columns)

        return tuple(sorted(self.records, key=key))


@dataclass(frozen=True)
class DatasetBundle:
    """All successfully parsed participant CSV tables, keyed by logical name."""

    tables: Mapping[str, CsvTable] = field(default_factory=dict)

    def table(self, name: str) -> CsvTable:
        return self.tables[name]


@dataclass(frozen=True)
class IngestionResult:
    """Dataset plus diagnostics, independent of CLI rendering."""

    bundle: DatasetBundle
    issues: tuple[ValidationIssue, ...]

    @property
    def fatal_errors(self) -> tuple[ValidationIssue, ...]:
        return tuple(issue for issue in self.issues if issue.severity is IssueSeverity.FATAL)

    @property
    def row_errors(self) -> tuple[ValidationIssue, ...]:
        return tuple(
            issue
            for issue in self.issues
            if issue.severity is IssueSeverity.ERROR and not issue.is_file_level
        )

    @property
    def file_errors(self) -> tuple[ValidationIssue, ...]:
        return tuple(
            issue
            for issue in self.issues
            if issue.severity is IssueSeverity.FATAL and issue.is_file_level
        )

    @property
    def ok(self) -> bool:
        return not any(issue.severity in (IssueSeverity.FATAL, IssueSeverity.ERROR) for issue in self.issues)

