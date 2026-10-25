"""Offline tests for evidence manifest validation and read-only discovery."""

from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from audit_agent.ingest import DATASET_SCHEMAS, read_csv_file
from audit_agent.manifest import DiscoveryOutcome, discover_evidence
from audit_agent.models import DatasetBundle, IngestionResult


MANIFEST_SCHEMA = next(schema for schema in DATASET_SCHEMAS if schema.name == "evidence_files")


class ManifestDiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.dataset = self.root / "dataset"
        self.evidence = self.dataset / "evidence"
        self.evidence.mkdir(parents=True)
        self.manifest_path = self.dataset / "evidence_files.csv"
        self.dataset.mkdir(exist_ok=True)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_result(self, rows: list[list[str]], headers: list[str] | None = None) -> IngestionResult:
        with self.manifest_path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle, lineterminator="\n")
            writer.writerow(headers or list(MANIFEST_SCHEMA.columns))
            writer.writerows(rows)
        table, issues = read_csv_file(self.manifest_path, MANIFEST_SCHEMA)
        tables = {"evidence_files": table} if table is not None else {}
        return IngestionResult(DatasetBundle(tables), issues)

    def row(self, file_id: str, path: str, captured: str = "2026-10-01T12:00:00Z") -> list[str]:
        return [file_id, path, "test-fixture", captured]

    def test_valid_entry_preserves_path_metadata_provenance_and_type(self) -> None:
        evidence_file = self.evidence / "logs" / "service.log"
        evidence_file.parent.mkdir()
        evidence_file.write_text("event=ok\n", encoding="utf-8")
        before = evidence_file.read_bytes()
        result = discover_evidence(self.make_result([self.row("f-1", "evidence/logs/service.log")]), self.dataset)

        self.assertEqual(result.discovered_count, 1)
        entry = result.entries[0]
        self.assertEqual(entry.outcome, DiscoveryOutcome.DISCOVERED)
        self.assertEqual(entry.original_relative_path, "evidence/logs/service.log")
        self.assertEqual(entry.normalized_relative_path, "logs/service.log")
        self.assertEqual(entry.resolved_path, evidence_file.resolve())
        self.assertEqual(entry.declared_file_type, "log")
        self.assertEqual(entry.observed_file_type, "utf8_text")
        self.assertIsNone(entry.declared_size)
        self.assertIsNone(entry.declared_hash)
        self.assertEqual(entry.actual_size, len(before))
        self.assertIsNone(entry.actual_hash)
        self.assertEqual(entry.manifest_record.source.record_number, 2)
        self.assertEqual(evidence_file.read_bytes(), before)
        self.assertEqual(result.unmanifested_paths, ())

    def test_missing_evidence_is_not_reported_as_discovered(self) -> None:
        result = discover_evidence(self.make_result([self.row("f-1", "evidence/missing.txt")]), self.dataset)
        self.assertEqual(result.missing_count, 1)
        self.assertEqual(result.entries[0].outcome, DiscoveryOutcome.MISSING)
        self.assertIn("evidence_file_missing", {d.code for d in result.entries[0].diagnostics})

    def test_empty_absolute_and_traversal_paths_are_rejected(self) -> None:
        rows = [
            self.row("empty", ""),
            self.row("absolute", "C:/outside/file.txt"),
            self.row("traversal", "evidence/../../outside.txt"),
            self.row("wrong-root", "elsewhere/file.txt"),
        ]
        result = discover_evidence(self.make_result(rows), self.dataset)
        self.assertEqual(result.rejected_count, 4)
        codes = {d.code for d in result.entry_diagnostics}
        self.assertTrue({"empty_path", "absolute_path", "invalid_path_component", "path_outside_manifest_root"} <= codes)

    def test_duplicate_ids_and_physical_references_reject_all_affected_rows(self) -> None:
        file = self.evidence / "x.txt"
        file.write_text("x", encoding="utf-8")
        rows = [self.row("dup", "evidence/x.txt"), self.row("dup", "evidence/x.txt")]
        result = discover_evidence(self.make_result(rows), self.dataset)
        self.assertEqual(result.rejected_count, 2)
        self.assertEqual(sum(d.code == "duplicate_file_id" for d in result.entry_diagnostics), 2)
        self.assertEqual(sum(d.code == "duplicate_file_reference" for d in result.entry_diagnostics), 2)

    def test_unsupported_extension_and_observed_type_mismatch_are_rejected(self) -> None:
        unsupported = self.evidence / "thing.bin"
        unsupported.write_bytes(b"blob")
        mismatch = self.evidence / "not-a-pdf.pdf"
        mismatch.write_text("plain text", encoding="utf-8")
        result = discover_evidence(self.make_result([
            self.row("bin", "evidence/thing.bin"),
            self.row("pdf", "evidence/not-a-pdf.pdf"),
        ]), self.dataset)
        self.assertEqual(result.rejected_count, 2)
        self.assertEqual({d.code for d in result.entry_diagnostics}, {"unsupported_file_type", "file_type_mismatch"})

    def test_empty_supported_text_file_is_accessible(self) -> None:
        (self.evidence / "empty.log").write_bytes(b"")
        result = discover_evidence(self.make_result([self.row("empty", "evidence/empty.log")]), self.dataset)
        self.assertEqual(result.discovered_count, 1)
        self.assertEqual(result.entries[0].observed_file_type, "empty")

    def test_captured_at_missing_malformed_naive_and_offset_are_explicit(self) -> None:
        for name in ("missing.txt", "malformed.txt", "naive.txt", "offset.txt"):
            (self.evidence / name).write_text("x", encoding="utf-8")
        rows = [
            self.row("missing", "evidence/missing.txt", ""),
            self.row("malformed", "evidence/malformed.txt", "not-a-time"),
            self.row("naive", "evidence/naive.txt", "2026-10-01T12:00:00"),
            self.row("offset", "evidence/offset.txt", "2026-10-01T17:30:00+05:30"),
        ]
        result = discover_evidence(self.make_result(rows), self.dataset)
        by_id = {entry.file_id: entry for entry in result.entries}
        self.assertEqual(by_id["missing"].captured_at.status.value, "missing")
        self.assertEqual(by_id["malformed"].captured_at.status.value, "invalid")
        self.assertEqual(by_id["naive"].captured_at.error_code, "timezone_required")
        self.assertEqual(by_id["offset"].captured_at.value.isoformat(), "2026-10-01T12:00:00+00:00")
        for key in ("missing", "malformed", "naive"):
            self.assertIn("invalid_captured_at", {d.code for d in by_id[key].diagnostics})

    def test_non_manifest_file_is_reported_as_unmanifested(self) -> None:
        (self.evidence / "listed.txt").write_text("a", encoding="utf-8")
        (self.evidence / "extra.txt").write_text("b", encoding="utf-8")
        result = discover_evidence(self.make_result([self.row("f", "evidence/listed.txt")]), self.dataset)
        self.assertEqual(result.unmanifested_paths, ("extra.txt",))

    def test_symlink_escape_is_rejected_when_supported(self) -> None:
        outside = self.root / "outside.txt"
        outside.write_text("secret", encoding="utf-8")
        link = self.evidence / "escape.txt"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink creation unavailable: {type(exc).__name__}")
        result = discover_evidence(self.make_result([self.row("f", "evidence/escape.txt")]), self.dataset)
        self.assertEqual(result.rejected_count, 1)
        self.assertIn("path_escape", {d.code for d in result.entry_diagnostics})

    def test_input_row_order_does_not_change_sorted_discovery_projection(self) -> None:
        for name in ("a.txt", "b.txt"):
            (self.evidence / name).write_text(name, encoding="utf-8")
        first = discover_evidence(self.make_result([
            self.row("b", "evidence/b.txt"), self.row("a", "evidence/a.txt")
        ]), self.dataset)
        second = discover_evidence(self.make_result([
            self.row("a", "evidence/a.txt"), self.row("b", "evidence/b.txt")
        ]), self.dataset)
        self.assertEqual([e.file_id for e in first.entries], [e.file_id for e in second.entries])
        self.assertEqual([e.normalized_relative_path for e in first.entries],
                         [e.normalized_relative_path for e in second.entries])

    def test_manifest_ingestion_failure_is_separate_from_entry_failures(self) -> None:
        result = self.make_result([self.row("f", "evidence/missing.txt")], headers=["file_id", "file_path"])
        discovery = discover_evidence(result, self.dataset)
        self.assertTrue(any(d.scope == "manifest" for d in discovery.manifest_diagnostics))
        # The header failure is overall; the retained row can still be represented as an entry.
        self.assertEqual(len(discovery.entries), 1)
        self.assertEqual(discovery.entries[0].outcome, DiscoveryOutcome.MISSING)


if __name__ == "__main__":
    unittest.main()
