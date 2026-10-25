"""Offline synthetic tests for deterministic evidence extraction."""

from __future__ import annotations

import csv
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from audit_agent.extract import (
    ExtractionStatus,
    OptionalPdfPlumberBackend,
    build_case_coverage,
    extract_evidence,
    _extract_csv,
)
from audit_agent.png_transcripts import BundledPngTranscriptBackend
from audit_agent.ingest import DATASET_SCHEMAS, read_csv_file
from audit_agent.manifest import discover_evidence
from audit_agent.models import DatasetBundle, IngestionResult


MANIFEST_SCHEMA = next(schema for schema in DATASET_SCHEMAS if schema.name == "evidence_files")


class FakePages:
    def __init__(self, pages: tuple[str, ...]) -> None:
        self.pages = pages

    def extract_pages(self, _path: Path) -> tuple[str, ...]:
        return self.pages


class ExtractionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.dataset = self.root / "dataset"
        self.evidence = self.dataset / "evidence"
        self.evidence.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_discovery(self, specs: list[tuple[str, str, bytes]]):
        rows: list[list[str]] = []
        for file_id, relative, content in specs:
            path = self.evidence / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
            rows.append([file_id, f"evidence/{relative}", "synthetic", "2026-10-01T12:00:00Z"])
        self.dataset.mkdir(exist_ok=True)
        manifest = self.dataset / "evidence_files.csv"
        with manifest.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream, lineterminator="\n")
            writer.writerow(MANIFEST_SCHEMA.columns)
            writer.writerows(rows)
        table, issues = read_csv_file(manifest, MANIFEST_SCHEMA)
        ingestion = IngestionResult(DatasetBundle({"evidence_files": table}), issues)
        return discover_evidence(ingestion, self.dataset)

    def test_json_nested_records_provenance_identifiers_and_utc_normalization(self) -> None:
        payload = b'{"exported_at":"2026-10-01T17:30:00+05:30","records":[{"user_id":"u-1","resource_id":"r-1","email":"MiXeD@example.test","updated_at":"bad-time","created_at":"2026-10-01T12:00:00","indexed_at":""}]}'
        result = extract_evidence(self.make_discovery([("f-json", "data.json", payload)]))
        file_result = result.files[0]
        self.assertEqual(file_result.status, ExtractionStatus.COMPLETE)
        self.assertEqual(len(file_result.observations), 2)
        record = next(obs for obs in file_result.observations if obs.resource_id == "r-1")
        self.assertEqual(record.source_path, "evidence/data.json")
        self.assertEqual(record.file_id, "f-json")
        self.assertEqual(record.locator, "json:/records/0")
        self.assertEqual(record.identifiers[0].namespace, "user_id")
        self.assertEqual(record.raw_fields["email"], "MiXeD@example.test")
        self.assertEqual(record.normalized_fields["email"], "mixed@example.test")
        self.assertEqual(record.timestamps[0].parsed.status.value, "invalid")
        self.assertEqual(record.timestamps[1].parsed.error_code, "timezone_required")
        self.assertEqual(record.timestamps[2].parsed.status.value, "missing")
        self.assertEqual(record.captured_at.raw, "2026-10-01T12:00:00Z")
        envelope = next(obs for obs in file_result.observations if obs.locator == "json:/")
        self.assertEqual(envelope.normalized_fields["exported_at"], "2026-10-01T12:00:00+00:00")
        self.assertEqual(envelope.timestamps[0].raw_value, "2026-10-01T17:30:00+05:30")
        self.assertIn("malformed_timestamp", {warning.code for warning in file_result.warnings})

    def test_service_export_json_path_preserves_explicit_system_and_collection_context(self) -> None:
        payload = (b'{"service_exports":{"analytics_platform":{"profiles":[{'
                   b'"resource_id":"analytics-1","user_id":"u-1",'
                   b'"observed_at":"2026-10-01T10:00:00Z"}]}}}')
        result = extract_evidence(self.make_discovery([("f-json", "export.json", payload)]))
        record = next(obs for obs in result.observations if obs.resource_id == "analytics-1")
        self.assertEqual(record.system_id, "analytics_platform")
        self.assertEqual(record.normalized_fields["system_id"], "analytics_platform")
        self.assertEqual(record.normalized_fields["collection_name"], "profiles")
        self.assertNotIn("system_id", record.raw_fields)
        self.assertNotIn("collection_name", record.raw_fields)
        self.assertEqual(record.locator, "json:/service_exports/analytics_platform/profiles/0")

    def test_conflicting_explicit_and_json_path_system_scopes_remain_unresolved(self) -> None:
        payload = (b'{"service_exports":{"analytics_platform":{"profiles":[{'
                   b'"system_id":"different_system","resource_id":"r-1"}]}}}')
        result = extract_evidence(self.make_discovery([("f-json", "export.json", payload)]))
        record = next(obs for obs in result.observations if obs.resource_id == "r-1")
        self.assertIsNone(record.system_id)
        self.assertEqual(record.normalized_fields["source_system_context"], "analytics_platform")
        self.assertIn("source_scope_conflict", {warning.code for warning in result.files[0].warnings})

    def test_sql_extracts_tables_rows_and_nested_record_json_without_merging_resource_keys(self) -> None:
        script = b'''CREATE TABLE records(resource_id TEXT, origin_system TEXT, collection_name TEXT, record_json TEXT, updated_at TEXT);
INSERT INTO records VALUES ('shared-r', 'svc-a', 'profiles', '{"user_id":"u-a","resource_id":"nested-a"}', '2026-10-01T10:00:00Z');
INSERT INTO records VALUES ('shared-r', 'svc-b', 'profiles', '{"user_id":"u-b","resource_id":"nested-b"}', '2026-10-01T11:00:00Z');'''
        result = extract_evidence(self.make_discovery([("f-sql", "snapshot.sql", script)]))
        file_result = result.files[0]
        self.assertEqual(file_result.status, ExtractionStatus.COMPLETE)
        rows = [obs for obs in file_result.observations if "/record_json:" not in obs.locator]
        self.assertEqual(len(rows), 2)
        self.assertEqual([(obs.system_id, obs.resource_id) for obs in rows], [("svc-a", "shared-r"), ("svc-b", "shared-r")])
        nested = [obs for obs in file_result.observations if "/record_json:" in obs.locator]
        self.assertEqual({obs.resource_id for obs in nested}, {"nested-a", "nested-b"})
        self.assertTrue(all(obs.parent_observation_id for obs in nested))
        self.assertEqual({obs.system_id for obs in nested}, {"svc-a", "svc-b"})
        self.assertTrue(all(obs.normalized_fields["collection_name"] == "profiles" for obs in nested))
        self.assertTrue(all("record_json" not in obs.raw_fields for obs in nested))
        self.assertEqual(rows[0].timestamps[0].parsed.value.isoformat(), "2026-10-01T10:00:00+00:00")

    def test_logs_keep_each_line_and_partial_structured_parse_failure(self) -> None:
        content = (
            '2026-10-01T10:00:00Z INFO service=lookup event=hit resource_id=r-1 message="snowman ☃, retry"\n'
            '2026-10-01T10:01:00Z INFO service=lookup payload={"broken":}\n'
        ).encode("utf-8")
        result = extract_evidence(self.make_discovery([("f-log", "events.log", content)]))
        file_result = result.files[0]
        self.assertEqual(file_result.status, ExtractionStatus.PARTIAL)
        self.assertEqual(len(file_result.observations), 2)
        self.assertEqual(file_result.observations[0].locator, "line:1")
        self.assertEqual(file_result.observations[0].resource_id, "r-1")
        self.assertEqual(file_result.observations[0].raw_fields["message"], "snowman ☃, retry")
        self.assertEqual(file_result.observations[0].timestamps[0].parsed.value.isoformat(), "2026-10-01T10:00:00+00:00")
        self.assertIn("malformed_structured_log", {error.code for error in file_result.errors})

    def test_text_multiline_unicode_and_escaped_fields_are_preserved(self) -> None:
        content = "Ticket: T-1\nMessage: Café, says \"keep order\"\ncontinued line ☃\n\nAudit: A-2\n".encode("utf-8")
        result = extract_evidence(self.make_discovery([("f-text", "handover.txt", content)]))
        file_result = result.files[0]
        self.assertEqual(file_result.status, ExtractionStatus.COMPLETE)
        self.assertEqual(len(file_result.observations), 2)
        first = file_result.observations[0]
        self.assertIn("continued line ☃", first.raw_fields["text"])
        self.assertEqual(first.raw_fields["Message"], 'Café, says "keep order"')
        self.assertEqual(first.locator, "lines:1-3")

    def test_csv_parser_preserves_quoted_commas_multiline_unicode_and_duplicate_resources(self) -> None:
        csv_path = self.evidence / "records.csv"
        csv_path.write_text('resource_id,note\nr-1,"café, one\nand two"\nr-1,repeat\n', encoding="utf-8", newline="")
        discovery = self.make_discovery([("seed", "seed.txt", b"seed")])
        seed = discovery.entries[0]
        entry = replace(seed, original_relative_path="evidence/records.csv", normalized_relative_path="records.csv",
                        resolved_path=csv_path, declared_file_type="csv")
        observations, _warnings, errors, _scope, _parsed = _extract_csv(entry, csv_path.read_text(encoding="utf-8"))
        self.assertFalse(errors)
        self.assertEqual(len(observations), 2)
        self.assertEqual(observations[0].raw_fields["note"], "café, one\nand two")
        self.assertEqual(observations[0].resource_id, "r-1")
        self.assertEqual(observations[1].resource_id, "r-1")

    def test_csv_header_only_is_empty_and_malformed_tail_is_partial_material(self) -> None:
        csv_path = self.evidence / "records.csv"
        discovery = self.make_discovery([("seed", "seed.txt", b"seed")])
        seed = discovery.entries[0]
        entry = replace(seed, original_relative_path="evidence/records.csv", normalized_relative_path="records.csv",
                        resolved_path=csv_path, declared_file_type="csv")
        empty_rows, _warnings, errors, _scope, parsed = _extract_csv(entry, "id,value\n")
        self.assertTrue(parsed)
        self.assertEqual(empty_rows, [])
        self.assertFalse(errors)
        observations, _warnings, errors, _scope, _parsed = _extract_csv(entry, 'id,value\n1,ok\n2,"unterminated\n')
        self.assertEqual(len(observations), 1)
        self.assertTrue(any(d.code == "malformed_csv" for d in errors))

    def test_pdf_pages_and_image_ocr_adapters_keep_page_provenance(self) -> None:
        specs = [
            ("f-pdf", "document.pdf", b"%PDF-1.7\nsynthetic"),
            ("f-png", "image.png", b"\x89PNG\r\n\x1a\nsynthetic"),
        ]
        discovery = self.make_discovery(specs)
        result = extract_evidence(discovery, pdf_backend=FakePages(("Page one ref: A-1", "Page two ref: A-2")),
                                  ocr_backend=FakePages(("Image page evidence id: E-1",)))
        pdf = next(item for item in result.files if item.file_id == "f-pdf")
        png = next(item for item in result.files if item.file_id == "f-png")
        self.assertEqual(pdf.status, ExtractionStatus.COMPLETE)
        self.assertEqual([obs.locator for obs in pdf.observations], ["page:1", "page:2"])
        self.assertEqual(png.status, ExtractionStatus.COMPLETE)
        self.assertEqual(png.observations[0].extraction_method, "ocr-page-text")

    def test_pdf_falls_back_to_pypdf_when_pdfplumber_is_unavailable(self):
        def import_module(name):
            if name == "pdfplumber":
                raise ModuleNotFoundError("pdfplumber", name="pdfplumber")
            if name == "pypdf":
                page = SimpleNamespace(extract_text=lambda: "Selectable PDF text")
                return SimpleNamespace(PdfReader=lambda _path: SimpleNamespace(pages=[page]))
            raise AssertionError(name)

        with patch("audit_agent.extract.importlib.import_module", side_effect=import_module):
            self.assertEqual(OptionalPdfPlumberBackend().extract_pages(Path("read-only.pdf")),
                             ("Selectable PDF text",))

    def test_pdf_extracts_labelled_identity_resource_and_utc_retention_provenance(self):
        text = ("COMPLIANCE JOURNAL - SIGNED RECORD EXTRACT\n"
                "Event reference audit_record_003\nDetail subject reference user_03\n"
                "recorded 25 Aug 2026 04 03 UTC\nretain until 25 Aug 2027 04 03 UTC")
        discovery = self.make_discovery([("f-pdf", "journal.pdf", b"%PDF-1.7\nsynthetic")])
        entry = replace(discovery.entries[0], origin="security_service")
        result = extract_evidence(replace(discovery, entries=(entry,)), pdf_backend=FakePages((text,)))
        self.assertEqual(result.files[0].status, ExtractionStatus.COMPLETE)
        obs = result.observations[0]
        self.assertEqual(obs.file_id, "f-pdf")
        self.assertEqual(obs.locator, "page:1")
        self.assertEqual(obs.raw_fields["page_text"], text)
        self.assertEqual(obs.normalized_fields["user_id"], "user_03")
        self.assertEqual(obs.resource_id, "audit_record_003")
        self.assertEqual(obs.system_id, "security_service")
        self.assertEqual(obs.normalized_fields["data_category"], "SECURITY_AUDIT_LOG")
        timestamps = {item.field_name: item for item in obs.timestamps}
        self.assertEqual(timestamps["recorded_at"].parsed.value.isoformat(), "2026-08-25T04:03:00+00:00")
        self.assertEqual(timestamps["retention_until"].parsed.value.isoformat(), "2027-08-25T04:03:00+00:00")

    def test_pdf_register_rows_are_split_without_collapsing_subjects(self):
        text = ("DISPUTED ORDERS AND TAX RECORDS REGISTER\n"
                "1 ORD-20264118 | user_08 | Card dispute | 04 May 2026 | USD 184.20 | Retain until 04 May 2033 | AR\n"
                "2 ORD-20264207 | user_12 | Tax correction | 09 May 2026 | EUR 72.40 | Retain until 09 May 2033 | ML")
        result = extract_evidence(self.make_discovery([("f-register", "register.pdf", b"%PDF-1.7\nsynthetic")]),
                                  pdf_backend=FakePages((text,)))
        rows = [item for item in result.observations if "/register-row:" in item.locator]
        self.assertEqual(len(rows), 2)
        self.assertEqual([(row.resource_id, row.normalized_fields["user_id"],
                           row.normalized_fields["retention_deadline_date_text"]) for row in rows],
                         [(None, "user_08", "04 May 2033"),
                          (None, "user_12", "09 May 2033")])
        self.assertEqual({row.normalized_fields["order_id"] for row in rows},
                         {"ORD-20264118", "ORD-20264207"})

    def test_pdf_no_text_and_png_without_ocr_are_failures_not_empty(self) -> None:
        result = extract_evidence(self.make_discovery([
            ("f-pdf", "scan.pdf", b"%PDF-1.7\nsynthetic"),
            ("f-png", "screen.png", b"\x89PNG\r\n\x1a\nsynthetic"),
        ]), pdf_backend=FakePages(("",)))
        pdf = next(item for item in result.files if item.file_id == "f-pdf")
        png = next(item for item in result.files if item.file_id == "f-png")
        self.assertEqual(pdf.status, ExtractionStatus.FAILED)
        self.assertIn("page_has_no_extractable_text", {d.code for d in pdf.warnings})
        self.assertEqual(png.status, ExtractionStatus.FAILED)
        self.assertIn("ocr_extraction_failed", {d.code for d in png.errors})

    def test_bundled_visual_transcriptions_extract_all_participant_pngs(self) -> None:
        backend = BundledPngTranscriptBackend()
        names = sorted(backend.TRANSCRIPTS)
        self.assertEqual(len(names), 11)
        discovery = self.make_discovery([
            (f"f-{index:02d}", f"images/{name}", b"\x89PNG\r\n\x1a\nsynthetic PNG fixture")
            for index, name in enumerate(names, 1)
        ])
        result = extract_evidence(discovery)
        self.assertEqual(len(result.files), 11)
        self.assertTrue(all(item.status is ExtractionStatus.COMPLETE for item in result.files))
        self.assertTrue(all(len(item.observations) >= 2 for item in result.files))
        for file_result in result.files:
            page_observation = next(obs for obs in file_result.observations if obs.locator == "page:1")
            self.assertEqual(page_observation.extraction_method, "visual-page-transcription")
            self.assertEqual(page_observation.raw_fields["page_text"], backend.extract_pages(
                Path(file_result.source_path)
            )[0])
            structured = [obs for obs in file_result.observations if "/structured:" in obs.locator]
            self.assertTrue(structured)
            self.assertTrue(all(obs.parent_observation_id == page_observation.observation_id for obs in structured))
            self.assertTrue(all(obs.raw_fields["record_text"] in obs.raw_fields["page_text"] for obs in structured))

    def test_screenshot_structured_facts_keep_scope_timestamps_and_ambiguous_fields(self):
        names = sorted(BundledPngTranscriptBackend.TRANSCRIPTS)
        discovery = self.make_discovery([
            (f"f-{i:02}", f"images/{name}", b"\x89PNG\r\n\x1a\nfixture")
            for i, name in enumerate(names, 1)
        ])
        entries = tuple(replace(item, origin="security_service") if item.file_id == "f-10" else item
                        for item in discovery.entries)
        results = extract_evidence(replace(discovery, entries=entries))
        by_name = {Path(item.source_path).name: item for item in results.files}

        journal = next(obs for obs in by_name["security_audit_explorer_20260905.png"].observations
                       if "/structured:" in obs.locator)
        self.assertEqual(journal.file_id, "f-10")
        self.assertEqual(journal.system_id, "security_service")
        self.assertEqual(journal.resource_id, "audit_record_003")
        self.assertEqual(journal.normalized_fields["user_id"], "user_03")
        self.assertEqual(journal.normalized_fields["event_type"], "account_closure_recorded")
        self.assertEqual(journal.timestamps[0].field_name, "recorded_at")
        self.assertEqual(journal.timestamps[0].parsed.value.isoformat(), "2026-08-25T04:03:00+00:00")
        self.assertEqual(journal.captured_at.value.isoformat(), "2026-10-01T12:00:00+00:00")
        self.assertNotEqual(journal.timestamps[0].parsed.value, journal.captured_at.value)

        account = next(obs for obs in by_name["account_admin_console_20260926.png"].observations
                       if "/structured:" in obs.locator)
        self.assertEqual(account.normalized_fields["email"], "haruka.s1838@zoho.com")
        self.assertEqual(account.normalized_fields["last_contact_at_raw"], "24 Sep 2026 09:14")
        self.assertIn("Last contact: 24 Sep 2026 09:14 JST", account.raw_fields["record_text"])
        self.assertEqual(account.normalized_fields["last_contact_at"], "2026-09-24T00:14:00+00:00")

        analytics = next(obs for obs in by_name["analytics_profile_view_20260713.png"].observations
                         if "/structured:" in obs.locator)
        analytics_times = {item.field_name: item.parsed.value.isoformat() for item in analytics.timestamps}
        self.assertEqual(analytics_times["last_activity_at"], "2026-07-13T14:22:00+00:00")
        self.assertEqual(analytics_times["first_seen_at"], "2026-04-21T09:14:00+00:00")

        backup = next(obs for obs in by_name["backup_restore_console_20260429.png"].observations
                      if "/structured:" in obs.locator)
        self.assertEqual(backup.normalized_fields["retention_end_text"], "26 Jul 2026")
        self.assertNotIn("retention_until", backup.normalized_fields)

        export = next(obs for obs in by_name["customer_export_console_20260618.png"].observations
                      if "/structured:" in obs.locator)
        self.assertIn("export_owner_email", export.normalized_fields)
        self.assertFalse(any(item.namespace == "export_owner_email" for item in export.identifiers))
        self.assertEqual({item.field_name for item in export.timestamps}, {"created_at", "expires_at"})

        storage = next(obs for obs in by_name["object_storage_browser_20260213.png"].observations
                       if "/structured:" in obs.locator)
        self.assertIsNone(storage.resource_id)
        self.assertFalse(any(item.namespace == "user_id" for item in storage.identifiers))

        support = next(obs for obs in by_name["support_ticket_console_20260524.png"].observations
                       if "/structured:" in obs.locator)
        self.assertEqual(support.normalized_fields["data_category"], "SUPPORT_MESSAGE")
        self.assertEqual(support.normalized_fields["order_reference"], "ORD-20265034")
        self.assertEqual(support.resource_id, "CS-5034")

    def test_structured_screenshot_projection_rejects_unanchored_records(self):
        class BadAnchorBackend(FakePages):
            extraction_method = "visual-page-transcription"

            def extract_structured_records(self, _path):
                return (("not visible", {"user_id": "u-synthetic"}),)

        result = extract_evidence(self.make_discovery([
            ("f-png", "images/synthetic.png", b"\x89PNG\r\n\x1a\nfixture")
        ]), ocr_backend=BadAnchorBackend(("Visible text only",)))
        file_result = result.files[0]
        self.assertEqual(file_result.status, ExtractionStatus.PARTIAL)
        self.assertEqual(len(file_result.observations), 1)
        self.assertEqual([item.code for item in file_result.errors], ["transcript_anchor_missing"])

    def test_bundled_visual_transcriber_fails_explicitly_for_unknown_png(self) -> None:
        result = extract_evidence(self.make_discovery([
            ("unknown", "images/not-in-transcript-set.png", b"\x89PNG\r\n\x1a\nsynthetic PNG fixture")
        ]))
        self.assertEqual(result.files[0].status, ExtractionStatus.FAILED)
        self.assertEqual(result.files[0].observations, ())
        self.assertEqual([item.code for item in result.files[0].errors], ["ocr_extraction_failed"])

    def test_empty_success_differs_from_malformed_and_partial_files(self) -> None:
        result = extract_evidence(self.make_discovery([
            ("empty", "empty.json", b""),
            ("bad", "bad.json", b'{"unfinished":'),
            ("partial", "partial.log", b"2026-10-01T10:00:00Z event=ok\nnot-json={bad}\n"),
        ]))
        by_id = {item.file_id: item for item in result.files}
        self.assertEqual(by_id["empty"].status, ExtractionStatus.EMPTY)
        self.assertEqual(by_id["empty"].observations, ())
        self.assertEqual(by_id["bad"].status, ExtractionStatus.FAILED)
        self.assertIn("malformed_json", {d.code for d in by_id["bad"].errors})
        self.assertEqual(by_id["partial"].status, ExtractionStatus.PARTIAL)
        self.assertEqual(len(by_id["partial"].observations), 2)

    def test_missing_evidence_is_missing_and_not_a_zero_observation_success(self) -> None:
        discovery = self.make_discovery([("absent", "absent.log", b"placeholder")])
        (self.evidence / "absent.log").unlink()
        # Re-run discovery after removing the file; absence is explicitly a file failure.
        manifest = self.dataset / "evidence_files.csv"
        table, issues = read_csv_file(manifest, MANIFEST_SCHEMA)
        discovery = discover_evidence(IngestionResult(DatasetBundle({"evidence_files": table}), issues), self.dataset)
        result = extract_evidence(discovery)
        self.assertEqual(result.files[0].status, ExtractionStatus.MISSING)
        self.assertEqual(result.files[0].observations, ())

    def test_case_coverage_is_separate_from_file_results_and_marks_candidate_gaps(self) -> None:
        discovery = self.make_discovery([
            ("empty", "empty.json", b""), ("bad", "bad.json", b"no json")
        ])
        extracted = extract_evidence(discovery)
        coverage = build_case_coverage({"case-b": ["bad", "unknown"], "case-a": ["empty"]}, extracted)
        self.assertEqual([item.case_id for item in coverage], ["case-a", "case-b"])
        self.assertEqual(coverage[0].examined_file_ids, ("empty",))
        self.assertEqual(coverage[0].observation_ids, ())
        self.assertEqual(coverage[0].material_gaps, ())
        self.assertEqual(coverage[1].failed_file_ids, ("bad", "unknown"))
        self.assertEqual(len(coverage[1].material_gaps), 2)
        self.assertEqual(extracted.by_file_id["empty"].status, ExtractionStatus.EMPTY)

    def test_repeated_extraction_is_deterministic_and_does_not_mutate_source(self) -> None:
        payload = b'{"records":[{"resource_id":"same"},{"resource_id":"same"}]}'
        discovery = self.make_discovery([("f", "repeated.json", payload)])
        path = discovery.entries[0].resolved_path
        before = path.read_bytes()
        first, second = extract_evidence(discovery), extract_evidence(discovery)
        self.assertEqual(first, second)
        self.assertEqual(first.observation_count, 2)
        self.assertEqual(path.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
