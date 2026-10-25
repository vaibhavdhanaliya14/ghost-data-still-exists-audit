from __future__ import annotations

import csv
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from audit_agent.ingest import DATASET_SCHEMAS, CsvSchema, load_dataset, parse_timestamp, read_csv_file
from audit_agent.models import IssueSeverity, TimestampStatus


class TimestampParsingTests(unittest.TestCase):
    def test_missing_and_empty_timestamps_are_explicit(self) -> None:
        for raw in (None, "", "   "):
            with self.subTest(raw=raw):
                parsed = parse_timestamp(raw)
                self.assertEqual(parsed.status, TimestampStatus.MISSING)
                self.assertIsNone(parsed.value)
                self.assertEqual(parsed.error_code, "missing_timestamp")

    def test_malformed_and_naive_timestamps_are_explicit(self) -> None:
        malformed = parse_timestamp("not-a-timestamp")
        self.assertEqual(malformed.status, TimestampStatus.INVALID)
        self.assertEqual(malformed.error_code, "malformed_timestamp")
        naive = parse_timestamp("2026-10-01T12:00:00")
        self.assertEqual(naive.status, TimestampStatus.INVALID)
        self.assertEqual(naive.error_code, "timezone_required")

    def test_explicit_offsets_normalize_to_utc(self) -> None:
        parsed = parse_timestamp("2026-10-01T17:30:00+05:30")
        self.assertEqual(parsed.status, TimestampStatus.VALID)
        self.assertEqual(parsed.value, datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc))
        self.assertEqual(parsed.value.utcoffset().total_seconds(), 0)

    def test_z_suffix_is_utc_and_preserves_raw_input(self) -> None:
        parsed = parse_timestamp("2026-10-01T12:00:00Z")
        self.assertEqual(parsed.status, TimestampStatus.VALID)
        self.assertEqual(parsed.raw, "2026-10-01T12:00:00Z")
        self.assertEqual(parsed.value, datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc))


class CsvIngestionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.schema = CsvSchema(
            name="requests",
            filename="requests.csv",
            columns=("case_id", "when", "text"),
            required_values=frozenset({"case_id", "when"}),
            timestamp_columns=frozenset({"when"}),
            unique_columns=("case_id",),
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def write_csv(self, name: str, rows: list[list[str]], *, headers: list[str] | None = None) -> Path:
        path = self.root / name
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.writer(handle, lineterminator="\n")
            writer.writerow(headers or list(self.schema.columns))
            writer.writerows(rows)
        return path

    def test_valid_csv_builds_raw_and_typed_records_with_provenance(self) -> None:
        path = self.write_csv("valid.csv", [["case-x", "2026-10-01T12:00:00Z", "ok"]])
        table, issues = read_csv_file(path, self.schema)
        self.assertEqual(issues, ())
        self.assertIsNotNone(table)
        record = table.records[0]
        self.assertEqual(record.raw("case_id"), "case-x")
        self.assertEqual(record.typed("when").value, datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc))
        self.assertEqual(record.source.source_file, "valid.csv")
        self.assertEqual(record.source.record_number, 2)
        self.assertEqual(record.raw_cells, ("case-x", "2026-10-01T12:00:00Z", "ok"))

    def test_missing_required_column_is_file_level_fatal(self) -> None:
        path = self.write_csv(
            "missing-column.csv",
            [["case-x", "2026-10-01T12:00:00Z"]],
            headers=["case_id", "when"],
        )
        table, issues = read_csv_file(path, self.schema)
        self.assertIsNotNone(table)
        self.assertTrue(any(issue.code == "header_mismatch" for issue in issues))
        self.assertEqual(issues[0].severity, IssueSeverity.FATAL)
        self.assertTrue(issues[0].is_file_level)

    def test_missing_file_is_file_level_fatal(self) -> None:
        table, issues = read_csv_file(self.root / "does-not-exist.csv", self.schema)
        self.assertIsNone(table)
        self.assertEqual(issues[0].code, "file_unavailable")
        self.assertEqual(issues[0].severity, IssueSeverity.FATAL)

    def test_empty_file_is_fatal_and_header_only_file_is_structurally_valid(self) -> None:
        empty = self.root / "empty.csv"
        empty.write_bytes(b"")
        table, issues = read_csv_file(empty, self.schema)
        self.assertIsNone(table)
        self.assertEqual(issues[0].code, "empty_file")

        header_only = self.root / "header-only.csv"
        header_only.write_text(",".join(self.schema.columns) + "\n", encoding="utf-8")
        table, issues = read_csv_file(header_only, self.schema)
        self.assertIsNotNone(table)
        self.assertEqual(len(table.records), 0)
        self.assertEqual(issues, ())

    def test_malformed_row_width_is_recoverable_and_raw_row_is_retained(self) -> None:
        path = self.write_csv(
            "malformed-row.csv",
            [
                ["short-row", "2026-10-01T12:00:00Z"],
                ["long-row", "2026-10-01T12:00:00Z", "text", "extra"],
            ],
        )
        table, issues = read_csv_file(path, self.schema)
        self.assertIsNotNone(table)
        self.assertTrue(table.parse_complete)
        self.assertEqual(len(table.records), 2)
        self.assertEqual(len([x for x in issues if x.code == "row_width_mismatch"]), 2)
        self.assertEqual(table.records[0].raw("text"), None)
        self.assertEqual(table.records[1].extra_cells, ("extra",))
        self.assertFalse(any(issue.is_file_level for issue in issues))

    def test_empty_and_malformed_timestamp_values_are_row_errors(self) -> None:
        path = self.write_csv(
            "timestamp-errors.csv",
            [
                ["empty-time", "", "empty"],
                ["bad-time", "yesterday", "bad"],
            ],
        )
        table, issues = read_csv_file(path, self.schema)
        self.assertIsNotNone(table)
        self.assertTrue(table.parse_complete)
        self.assertEqual(table.records[0].typed("when").status, TimestampStatus.MISSING)
        self.assertEqual(table.records[1].typed("when").status, TimestampStatus.INVALID)
        self.assertEqual(
            [issue.code for issue in issues],
            ["missing_required_value", "missing_timestamp", "malformed_timestamp"],
        )

    def test_malformed_csv_quoting_is_file_level_fatal(self) -> None:
        path = self.root / "bad-quoting.csv"
        path.write_text('case_id,when,text\ncase-x,2026-10-01T12:00:00Z,"unfinished\n', encoding="utf-8")
        table, issues = read_csv_file(path, self.schema)
        self.assertIsNotNone(table)
        self.assertFalse(table.parse_complete)
        self.assertTrue(any(x.code == "malformed_csv_syntax" and x.is_file_level for x in issues))

    def test_invalid_utf8_is_file_level_fatal(self) -> None:
        path = self.root / "invalid-utf8.csv"
        path.write_bytes(b"case_id,when,text\ncase-x,2026-10-01T12:00:00Z,\xff\n")
        table, issues = read_csv_file(path, self.schema)
        self.assertIsNone(table)
        self.assertEqual(issues[0].code, "invalid_encoding")
        self.assertEqual(issues[0].severity, IssueSeverity.FATAL)

    def test_duplicate_unique_identifier_is_row_error_and_keeps_both_rows(self) -> None:
        path = self.write_csv(
            "duplicate.csv",
            [
                ["case-x", "2026-10-01T12:00:00Z", "one"],
                ["case-x", "2026-10-02T12:00:00Z", "two"],
            ],
        )
        table, issues = read_csv_file(path, self.schema)
        duplicate = [issue for issue in issues if issue.code == "duplicate_identifier"]
        self.assertIsNotNone(table)
        self.assertEqual(len(table.records), 2)
        self.assertEqual(len(duplicate), 1)
        self.assertEqual(duplicate[0].column, "case_id")
        self.assertFalse(duplicate[0].is_file_level)

    def test_unicode_quoted_commas_and_newlines_round_trip(self) -> None:
        text = "Elimina, por favor\n雪だるま ☃"
        path = self.write_csv("unicode.csv", [["case-雪", "2026-10-01T12:00:00Z", text]])
        table, issues = read_csv_file(path, self.schema)
        self.assertEqual(issues, ())
        self.assertEqual(table.records[0].raw("case_id"), "case-雪")
        self.assertEqual(table.records[0].raw("text"), text)

    def test_row_order_change_has_same_canonical_view(self) -> None:
        rows = [
            ["case-b", "2026-10-02T12:00:00Z", "B"],
            ["case-a", "2026-10-01T12:00:00Z", "A"],
        ]
        p1 = self.write_csv("first.csv", rows)
        p2 = self.write_csv("second.csv", list(reversed(rows)))
        t1, issues1 = read_csv_file(p1, self.schema)
        t2, issues2 = read_csv_file(p2, self.schema)
        self.assertEqual(issues1, ())
        self.assertEqual(issues2, ())
        view1 = [(r.raw("case_id"), r.raw("text")) for r in t1.sorted_records_by("case_id")]
        view2 = [(r.raw("case_id"), r.raw("text")) for r in t2.sorted_records_by("case_id")]
        self.assertEqual(view1, view2)

    def test_utf8_bom_is_accepted(self) -> None:
        path = self.root / "bom.csv"
        path.write_text("\ufeffcase_id,when,text\ncase-x,2026-10-01T12:00:00Z,ok\n", encoding="utf-8")
        table, issues = read_csv_file(path, self.schema)
        self.assertEqual(issues, ())
        self.assertEqual(table.headers, self.schema.columns)

    def test_json_array_column_is_typed_and_malformed_json_is_row_error(self) -> None:
        schema = CsvSchema(
            name="sample_output",
            filename="sample_output.csv",
            columns=("case_id", "steps_json"),
            required_values=frozenset({"case_id", "steps_json"}),
            json_array_columns=frozenset({"steps_json"}),
        )
        path = self.write_csv(
            "json.csv",
            [["case-a", '[{"step_no":1}]'], ["case-b", "not-json"]],
            headers=["case_id", "steps_json"],
        )
        table, issues = read_csv_file(path, schema)
        self.assertEqual(table.records[0].typed("steps_json"), [{"step_no": 1}])
        self.assertEqual(table.records[1].raw("steps_json"), "not-json")
        self.assertEqual([issue.code for issue in issues], ["malformed_json_array"])


class DatasetLoadTests(unittest.TestCase):
    def test_missing_dataset_files_are_reported_without_console_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = load_dataset(temp_dir)
        self.assertFalse(result.ok)
        self.assertEqual(len(result.file_errors), len(DATASET_SCHEMAS))
        self.assertTrue(all(issue.code == "file_unavailable" for issue in result.file_errors))
        self.assertEqual(result.bundle.tables, {})

    def test_actual_participant_csvs_pass_ingestion_schema_validation(self) -> None:
        repository_root = Path(__file__).resolve().parents[2]
        result = load_dataset(repository_root / "dataset")
        self.assertTrue(result.ok, "; ".join(f"{x.source_file}:{x.code}" for x in result.issues))
        self.assertEqual(len(result.bundle.table("deletion_requests").records), 518)
        self.assertEqual(len(result.bundle.table("sample_deletion_requests").records), 32)
        self.assertEqual(len(result.bundle.table("sample_output").records), 32)
        self.assertEqual(len(result.bundle.table("output_template").records), 0)
        self.assertEqual(
            result.bundle.table("output_template").headers,
            ("case_id", "deletion_status", "steps_json"),
        )


if __name__ == "__main__":
    unittest.main()
