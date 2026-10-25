"""Read-only validation and discovery of manifest-listed evidence files.

This module consumes the ``evidence_files`` table produced by :mod:`ingest`.
It deliberately does not interpret evidence contents or treat discovery
failures as evidence about the deletion state.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath, PureWindowsPath

from .models import CsvRecord, IngestionResult, IssueSeverity, ParsedTimestamp, TimestampStatus, ValidationIssue


SUPPORTED_FILE_TYPES = {
    ".json": "json",
    ".log": "log",
    ".pdf": "pdf",
    ".png": "png",
    ".sql": "sql",
    ".txt": "text",
}


class DiscoveryOutcome(str, Enum):
    DISCOVERED = "discovered"
    MISSING = "missing"
    REJECTED = "rejected"
    INACCESSIBLE = "inaccessible"


@dataclass(frozen=True)
class DiscoveryDiagnostic:
    code: str
    message: str
    severity: IssueSeverity
    scope: str  # manifest, entry, or inventory
    file_id: str | None = None
    original_path: str | None = None


@dataclass(frozen=True)
class EvidenceFileDiscovery:
    """One manifest row and its safely resolved filesystem projection."""

    manifest_record: CsvRecord
    file_id: str | None
    original_relative_path: str | None
    normalized_relative_path: str | None
    resolved_path: Path | None
    origin: str | None
    declared_file_type: str | None
    observed_file_type: str | None
    declared_size: int | None
    declared_hash: str | None
    actual_size: int | None
    actual_hash: str | None
    captured_at: ParsedTimestamp | None
    outcome: DiscoveryOutcome
    diagnostics: tuple[DiscoveryDiagnostic, ...]

    @property
    def accessible(self) -> bool:
        return self.outcome is DiscoveryOutcome.DISCOVERED


@dataclass(frozen=True)
class EvidenceDiscoveryResult:
    evidence_root: Path
    entries: tuple[EvidenceFileDiscovery, ...]
    manifest_diagnostics: tuple[DiscoveryDiagnostic, ...]
    inventory_diagnostics: tuple[DiscoveryDiagnostic, ...]
    unmanifested_paths: tuple[str, ...]

    @property
    def entry_diagnostics(self) -> tuple[DiscoveryDiagnostic, ...]:
        return tuple(d for entry in self.entries for d in entry.diagnostics)

    @property
    def diagnostics(self) -> tuple[DiscoveryDiagnostic, ...]:
        return self.manifest_diagnostics + self.entry_diagnostics + self.inventory_diagnostics

    @property
    def discovered_count(self) -> int:
        return sum(entry.outcome is DiscoveryOutcome.DISCOVERED for entry in self.entries)

    @property
    def missing_count(self) -> int:
        return sum(entry.outcome is DiscoveryOutcome.MISSING for entry in self.entries)

    @property
    def rejected_count(self) -> int:
        return sum(entry.outcome is DiscoveryOutcome.REJECTED for entry in self.entries)

    @property
    def inaccessible_count(self) -> int:
        return sum(entry.outcome is DiscoveryOutcome.INACCESSIBLE for entry in self.entries)

    @property
    def manifest_ok(self) -> bool:
        return not self.manifest_diagnostics

    @property
    def ok(self) -> bool:
        return (
            self.manifest_ok
            and all(entry.outcome is DiscoveryOutcome.DISCOVERED for entry in self.entries)
            and not self.unmanifested_paths
            and not self.inventory_diagnostics
        )


def _diag(
    code: str,
    message: str,
    *,
    scope: str,
    severity: IssueSeverity = IssueSeverity.ERROR,
    file_id: str | None = None,
    path: str | None = None,
) -> DiscoveryDiagnostic:
    return DiscoveryDiagnostic(code, message, severity, scope, file_id, path)


def _safe_relative_path(raw: str | None) -> tuple[str | None, str | None]:
    """Return evidence-root-relative path and a rejection code, if any.

    The public manifest stores paths relative to ``dataset/`` as
    ``evidence/<path>``. Only that exact root prefix is accepted.
    """

    if raw is None or not raw.strip():
        return None, "empty_path"
    if "\x00" in raw:
        return None, "nul_in_path"
    value = raw.strip()
    win = PureWindowsPath(value)
    posix = PurePosixPath(value)
    if win.is_absolute() or win.drive or posix.is_absolute():
        return None, "absolute_path"
    # Backslashes are not separators in the participant's POSIX manifest and
    # accepting them would make traversal checks platform-dependent.
    if "\\" in value:
        return None, "unsupported_path_separator"
    if any(part in ("", ".", "..") for part in value.split("/")):
        return None, "invalid_path_component"
    if not value.startswith("evidence/"):
        return None, "path_outside_manifest_root"
    relative = value[len("evidence/") :]
    if not relative or any(part in ("", ".", "..") for part in relative.split("/")):
        return None, "invalid_path_component"
    if ":" in relative:
        return None, "invalid_path_component"
    return relative, None


def _observe_type(path: Path, suffix: str, prefix: bytes) -> tuple[str, bool]:
    """Return a coarse observed type and whether it matches the extension."""

    if not prefix:
        observed = "empty"
    elif prefix.startswith(b"%PDF-"):
        observed = "pdf"
    elif prefix.startswith(b"\x89PNG\r\n\x1a\n"):
        observed = "png"
    else:
        try:
            prefix.decode("utf-8", errors="strict")
            observed = "utf8_text" if b"\x00" not in prefix else "binary"
        except UnicodeDecodeError:
            observed = "binary"

    if observed == "empty":
        compatible = suffix in {".json", ".log", ".sql", ".txt"}
    elif suffix == ".pdf":
        compatible = observed == "pdf"
    elif suffix == ".png":
        compatible = observed == "png"
    else:
        compatible = observed == "utf8_text"
    return observed, compatible


def _inventory(root: Path) -> tuple[set[str], tuple[DiscoveryDiagnostic, ...]]:
    """Inventory ordinary files without following symlink directories."""

    found: set[str] = set()
    diagnostics: list[DiscoveryDiagnostic] = []
    try:
        for current, dirs, files in os.walk(root, followlinks=False):
            current_path = Path(current)
            symlink_dirs = [d for d in dirs if (current_path / d).is_symlink()]
            for name in symlink_dirs:
                diagnostics.append(_diag(
                    "inventory_symlink", "Evidence inventory contains a symlink directory.",
                    scope="inventory", path=(current_path / name).relative_to(root).as_posix(),
                ))
            dirs[:] = sorted(d for d in dirs if d not in symlink_dirs)
            for name in sorted(files):
                path = current_path / name
                try:
                    rel = path.relative_to(root).as_posix()
                    if path.is_symlink():
                        # A symlink is not silently counted as a participant file.
                        diagnostics.append(_diag(
                            "inventory_symlink", "Evidence inventory contains a symlink.",
                            scope="inventory", path=rel,
                        ))
                    else:
                        found.add(rel)
                except (OSError, ValueError):
                    diagnostics.append(_diag(
                        "inventory_error", "Could not inventory an evidence path.", scope="inventory"
                    ))
    except OSError as exc:
        diagnostics.append(_diag(
            "inventory_error", f"Could not inventory evidence root: {type(exc).__name__}.", scope="inventory"
        ))
    return found, tuple(diagnostics)


def discover_evidence(ingestion: IngestionResult, dataset_dir: Path | str) -> EvidenceDiscoveryResult:
    """Validate manifest rows and discover files beneath ``dataset/evidence``.

    Manifest/table failures are reported separately from per-entry file/path
    failures. This routine never reads beyond a small file signature prefix and
    never writes to the participant dataset.
    """

    dataset_root = Path(dataset_dir)
    expected_root = dataset_root / "evidence"
    manifest_diags: list[DiscoveryDiagnostic] = []
    table = ingestion.bundle.tables.get("evidence_files")
    if table is None:
        manifest_diags.append(_diag(
            "manifest_table_unavailable", "Phase 1 did not provide the evidence_files table.",
            scope="manifest", severity=IssueSeverity.FATAL,
        ))
        root = expected_root.resolve(strict=False)
        return EvidenceDiscoveryResult(root, (), tuple(manifest_diags), (), ())

    for issue in ingestion.issues:
        if issue.source_file == "evidence_files.csv" and issue.is_file_level:
            manifest_diags.append(_diag(
                "manifest_ingestion_error", issue.message, scope="manifest",
                severity=issue.severity,
            ))
    if not table.parse_complete and not any(d.code == "manifest_ingestion_error" for d in manifest_diags):
        manifest_diags.append(_diag(
            "manifest_incomplete", "Phase 1 reported an incomplete manifest parse.",
            scope="manifest", severity=IssueSeverity.FATAL,
        ))

    try:
        root = expected_root.resolve(strict=True)
        if not root.is_dir():
            raise NotADirectoryError
    except (OSError, RuntimeError) as exc:
        root = expected_root.resolve(strict=False)
        manifest_diags.append(_diag(
            "evidence_root_unavailable", f"Evidence root is unavailable: {type(exc).__name__}.",
            scope="manifest", severity=IssueSeverity.FATAL,
        ))
        return EvidenceDiscoveryResult(root, (), tuple(manifest_diags), (), ())

    preliminary: list[dict[str, object]] = []
    id_groups: dict[str, list[int]] = {}
    path_groups: dict[str, list[int]] = {}
    for index, record in enumerate(table.records):
        file_id = record.raw("file_id")
        original = record.raw("file_path")
        normalized, path_error = _safe_relative_path(original)
        candidate: Path | None = None
        resolved: Path | None = None
        outcome = DiscoveryOutcome.DISCOVERED
        diagnostics: list[DiscoveryDiagnostic] = []
        declared_type: str | None = None
        observed_type: str | None = None
        actual_size: int | None = None

        if file_id:
            id_groups.setdefault(file_id, []).append(index)
        else:
            diagnostics.append(_diag("missing_file_id", "Manifest entry has no file identifier.",
                                     scope="entry", path=original))
            outcome = DiscoveryOutcome.REJECTED
        if path_error:
            outcome = DiscoveryOutcome.REJECTED
            diagnostics.append(_diag(path_error, "Manifest path is not a safe evidence-relative path.",
                                     scope="entry", file_id=file_id, path=original))
        else:
            assert normalized is not None
            candidate = root.joinpath(*PurePosixPath(normalized).parts)
            try:
                resolved = candidate.resolve(strict=False)
                if not resolved.is_relative_to(root):
                    outcome = DiscoveryOutcome.REJECTED
                    diagnostics.append(_diag("path_escape", "Resolved path escapes the permitted evidence root.",
                                             scope="entry", file_id=file_id, path=original))
                else:
                    canonical = os.path.normcase(str(resolved))
                    path_groups.setdefault(canonical, []).append(index)
                    declared_type = SUPPORTED_FILE_TYPES.get(candidate.suffix.lower())
                    if declared_type is None:
                        outcome = DiscoveryOutcome.REJECTED
                        diagnostics.append(_diag("unsupported_file_type", "File extension is not supported.",
                                                 scope="entry", file_id=file_id, path=original))
                    elif not candidate.exists():
                        outcome = DiscoveryOutcome.MISSING
                        diagnostics.append(_diag("evidence_file_missing", "Manifest-listed evidence file is missing.",
                                                 scope="entry", file_id=file_id, path=original))
                    elif not candidate.is_file():
                        outcome = DiscoveryOutcome.REJECTED
                        diagnostics.append(_diag("not_regular_file", "Manifest path does not identify a regular file.",
                                                 scope="entry", file_id=file_id, path=original))
                    else:
                        try:
                            actual_size = candidate.stat().st_size
                            with candidate.open("rb") as handle:
                                prefix = handle.read(4096)
                        except OSError as exc:
                            outcome = DiscoveryOutcome.INACCESSIBLE
                            diagnostics.append(_diag("evidence_file_inaccessible",
                                                     f"Evidence file cannot be read: {type(exc).__name__}.",
                                                     scope="entry", file_id=file_id, path=original))
                        else:
                            observed_type, compatible = _observe_type(candidate, candidate.suffix.lower(), prefix)
                            if not compatible:
                                outcome = DiscoveryOutcome.REJECTED
                                diagnostics.append(_diag("file_type_mismatch",
                                    "Observed file content is incompatible with its extension.",
                                    scope="entry", file_id=file_id, path=original))
            except (OSError, RuntimeError, ValueError) as exc:
                outcome = DiscoveryOutcome.INACCESSIBLE
                diagnostics.append(_diag("path_resolution_error",
                    f"Evidence path could not be resolved: {type(exc).__name__}.",
                    scope="entry", file_id=file_id, path=original))

        captured_at = record.typed("captured_at")
        if not isinstance(captured_at, ParsedTimestamp):
            captured_at = None
        elif captured_at.status is not TimestampStatus.VALID:
            diagnostics.append(_diag("invalid_captured_at",
                "Manifest capture timestamp is missing or invalid.", scope="entry",
                file_id=file_id, path=original))
        preliminary.append({
            "record": record, "file_id": file_id, "original": original,
            "normalized": normalized, "resolved": resolved, "origin": record.raw("origin"),
            "declared_type": declared_type, "observed_type": observed_type,
            "actual_size": actual_size, "captured_at": captured_at,
            "outcome": outcome, "diagnostics": diagnostics,
        })

    for groups, code, message in (
        (id_groups, "duplicate_file_id", "Manifest contains duplicate file identifiers."),
        (path_groups, "duplicate_file_reference", "Multiple manifest rows reference the same physical path."),
    ):
        for indexes in groups.values():
            if len(indexes) < 2:
                continue
            for index in indexes:
                item = preliminary[index]
                item["diagnostics"].append(_diag(
                    code, message, scope="entry", file_id=item["file_id"], path=item["original"]
                ))
                item["outcome"] = DiscoveryOutcome.REJECTED

    entries = tuple(sorted((EvidenceFileDiscovery(
        manifest_record=item["record"], file_id=item["file_id"],
        original_relative_path=item["original"], normalized_relative_path=item["normalized"],
        resolved_path=item["resolved"], origin=item["origin"],
        declared_file_type=item["declared_type"], observed_file_type=item["observed_type"],
        declared_size=None, declared_hash=None, actual_size=item["actual_size"], actual_hash=None,
        captured_at=item["captured_at"], outcome=item["outcome"],
        diagnostics=tuple(item["diagnostics"]),
    ) for item in preliminary), key=lambda entry: (
        entry.file_id or "", entry.normalized_relative_path or "",
        entry.manifest_record.source.record_number,
    )))

    inventory_files, inventory_diags = _inventory(root)
    manifested = {
        entry.normalized_relative_path for entry in entries
        if entry.normalized_relative_path is not None and entry.resolved_path is not None
        and entry.resolved_path.is_relative_to(root)
    }
    unmanifested = tuple(sorted(inventory_files - manifested))
    return EvidenceDiscoveryResult(root, entries, tuple(manifest_diags), inventory_diags, unmanifested)

