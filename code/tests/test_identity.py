"""Synthetic unittest coverage for temporal identity resolution."""

from __future__ import annotations

import csv
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType

from audit_agent.extract import (
    EvidenceExtractionResult,
    ExtractedObservation,
    ExtractionStatus,
    FileExtractionResult,
    IdentifierValue,
)
from audit_agent.identity import (
    IdentityResolver,
    MatchConfidence,
    ResolutionStatus,
    build_identity_graph,
    resolve_identities,
)
from audit_agent.ingest import DATASET_SCHEMAS, read_csv_file
from audit_agent.models import DatasetBundle, IngestionResult, ParsedTimestamp, TimestampStatus


SCHEMAS = {schema.name: schema for schema in DATASET_SCHEMAS}


class IdentityResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_table(self, name: str, headers: tuple[str, ...], rows: list[list[str]]):
        path = self.root / f"{name}.csv"
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream, lineterminator="\n")
            writer.writerow(headers)
            writer.writerows(rows)
        table, issues = read_csv_file(path, SCHEMAS[name])
        return table, issues

    def ingestion(self, identities: list[list[str]], audits: list[list[str]], requests: list[list[str]] | None = None) -> IngestionResult:
        id_table, id_issues = self.write_table("user_identities", SCHEMAS["user_identities"].columns, identities)
        audit_table, audit_issues = self.write_table("user_audit_log", SCHEMAS["user_audit_log"].columns, audits)
        tables = {"user_identities": id_table, "user_audit_log": audit_table}
        issues = list(id_issues + audit_issues)
        if requests is not None:
            req_table, req_issues = self.write_table("deletion_requests", SCHEMAS["deletion_requests"].columns, requests)
            tables["deletion_requests"] = req_table
            issues.extend(req_issues)
        return IngestionResult(DatasetBundle(tables), tuple(issues))

    def identity(self, user_id: str, email: str, updated_at: str = "2026-03-01T00:00:00Z", phone: str = "", email_hash: str = "") -> list[str]:
        return [user_id, "Synthetic User", email, phone, email_hash, updated_at]

    def change(self, audit_id: str, user_id: str, when: str, old: str, new: str, field: str = "email") -> list[str]:
        return [audit_id, user_id, when, field, old, new]

    @staticmethod
    def at(raw: str) -> datetime:
        return datetime.fromisoformat(raw.replace("Z", "+00:00"))

    def observation(self, observation_id: str, identifiers: tuple[IdentifierValue, ...], *, system: str = "svc", resource: str = "same-r") -> ExtractedObservation:
        return ExtractedObservation(
            observation_id=observation_id, file_id="evidence_x", source_path="evidence/test.json",
            file_format="json", locator="json:/records/0", extraction_method="test",
            raw_fields=MappingProxyType({"system_id": system, "resource_id": resource}),
            normalized_fields=MappingProxyType({"system_id": system, "resource_id": resource}),
            identifiers=identifiers, system_id=system, resource_id=resource, timestamps=(), captured_at=None,
        )

    def test_historical_email_boundary_uses_half_open_validity_periods(self) -> None:
        t = "2026-01-10T12:00:00Z"
        data = self.ingestion(
            [self.identity("u1", "new@example.test")],
            [self.change("a1", "u1", t, "Old@Example.test", "new@example.test")],
        )
        resolver = IdentityResolver(build_identity_graph(data))
        old_before = resolver.resolve_identifier("email", "OLD@example.test", at=self.at("2026-01-10T11:59:59Z"))
        old_at = resolver.resolve_identifier("email", "old@example.test", at=self.at(t))
        new_at = resolver.resolve_identifier("email", "new@example.test", at=self.at(t))
        self.assertEqual(old_before.status, ResolutionStatus.CONFIRMED)
        self.assertEqual(old_at.status, ResolutionStatus.NON_MATCH)
        self.assertEqual(new_at.status, ResolutionStatus.CONFIRMED)
        self.assertEqual(new_at.matched_user_id, "u1")
        old_edge = next(edge for edge in resolver.graph.intervals if edge.normalized_value == "old@example.test")
        self.assertIn("Old@Example.test", old_edge.raw_values)

    def test_screenshot_customer_reference_uses_stable_user_reference_match(self) -> None:
        data = self.ingestion([self.identity("u-synthetic", "current@example.test")], [])
        resolver = IdentityResolver(build_identity_graph(data))
        item = self.observation("image-record", (
            IdentifierValue("customer_reference", "u-synthetic", "u-synthetic"),
            IdentifierValue("email", "current@example.test", "current@example.test"),
        ))
        result = resolver.resolve_observation(item)
        self.assertEqual(result.status, ResolutionStatus.CONFIRMED)
        self.assertEqual(result.matched_user_id, "u-synthetic")
        self.assertIn("customer_reference", {match.source_namespace for match in result.identifier_matches})

    def test_reused_email_is_temporally_resolvable_but_ambiguous_without_time(self) -> None:
        switch = "2026-02-01T00:00:00Z"
        data = self.ingestion(
            [self.identity("u1", "new1@example.test"), self.identity("u2", "shared@example.test", switch)],
            [self.change("a1", "u1", switch, "shared@example.test", "new1@example.test")],
        )
        resolver = IdentityResolver(build_identity_graph(data))
        without_time = resolver.resolve_identifier("email", "shared@example.test")
        before = resolver.resolve_identifier("email", "shared@example.test", at=self.at("2026-01-31T23:59:59Z"))
        after = resolver.resolve_identifier("email", "shared@example.test", at=self.at(switch))
        self.assertEqual(without_time.status, ResolutionStatus.AMBIGUOUS)
        self.assertEqual(before.matched_user_id, "u1")
        self.assertEqual(after.matched_user_id, "u2")

    def test_overlapping_shared_email_is_ambiguous(self) -> None:
        data = self.ingestion(
            [self.identity("u1", "shared@example.test"), self.identity("u2", "shared@example.test")], [],
        )
        resolver = IdentityResolver(build_identity_graph(data))
        result = resolver.resolve_identifier("email", "shared@example.test", at=self.at("2026-04-01T00:00:00Z"))
        self.assertEqual(result.status, ResolutionStatus.AMBIGUOUS)
        self.assertEqual(result.candidate_user_ids, ("u1", "u2"))

    def test_snapshot_history_conflict_is_unresolved_not_a_guess(self) -> None:
        data = self.ingestion(
            [self.identity("u1", "snapshot@example.test")],
            [self.change("a1", "u1", "2026-01-01T00:00:00Z", "old@example.test", "history@example.test")],
        )
        graph = build_identity_graph(data)
        result = IdentityResolver(graph).resolve_identifier("email", "history@example.test")
        self.assertEqual(result.status, ResolutionStatus.UNRESOLVED)
        self.assertIn("snapshot_history_conflict", result.reason_codes)
        self.assertTrue(result.identity_sources)

    def test_broken_history_chain_is_conflicting(self) -> None:
        data = self.ingestion(
            [self.identity("u1", "last@example.test")],
            [
                self.change("a1", "u1", "2026-01-01T00:00:00Z", "first@example.test", "middle@example.test"),
                self.change("a2", "u1", "2026-02-01T00:00:00Z", "different@example.test", "last@example.test"),
            ],
        )
        resolver = IdentityResolver(build_identity_graph(data))
        result = resolver.resolve_identifier("email", "middle@example.test", at=self.at("2026-01-15T00:00:00Z"))
        self.assertEqual(result.status, ResolutionStatus.UNRESOLVED)
        self.assertIn("history_chain_break", result.reason_codes)

    def test_missing_identifier_is_unresolved_but_unknown_value_is_non_match(self) -> None:
        data = self.ingestion([self.identity("u1", "a@example.test")], [])
        resolver = IdentityResolver(build_identity_graph(data))
        missing = resolver.resolve_identifier("email", None)
        unknown = resolver.resolve_identifier("email", "nobody@example.test")
        self.assertEqual(missing.status, ResolutionStatus.UNRESOLVED)
        self.assertIn("missing_identifier_value", missing.reason_codes)
        self.assertEqual(unknown.status, ResolutionStatus.NON_MATCH)

    def test_phone_and_email_hash_match_only_their_exact_supported_namespaces(self) -> None:
        phone = "+1 (555) 0100"
        digest = "AbC123ExactHash"
        data = self.ingestion([self.identity("u1", "a@example.test", phone=phone, email_hash=digest)], [])
        resolver = IdentityResolver(build_identity_graph(data))
        self.assertEqual(resolver.resolve_identifier("phone", phone).matched_user_id, "u1")
        self.assertEqual(resolver.resolve_identifier("email_hash", digest).matched_user_id, "u1")
        self.assertEqual(resolver.resolve_identifier("phone", "+15550100").status, ResolutionStatus.NON_MATCH)
        self.assertEqual(resolver.resolve_identifier("email", digest).status, ResolutionStatus.NON_MATCH)

    def test_current_alias_before_snapshot_time_remains_unresolved(self) -> None:
        data = self.ingestion([self.identity("u1", "current@example.test", "2026-03-01T00:00:00Z")], [])
        result = IdentityResolver(build_identity_graph(data)).resolve_identifier(
            "email", "current@example.test", at=self.at("2026-02-28T23:59:59Z"))
        self.assertEqual(result.status, ResolutionStatus.UNRESOLVED)
        self.assertIn("identifier_outside_supported_validity", result.reason_codes)

    def test_duplicate_transition_evidence_coalesces_edges_but_preserves_provenance(self) -> None:
        data = self.ingestion(
            [self.identity("u1", "new@example.test")],
            [
                self.change("a1", "u1", "2026-01-01T00:00:00Z", "old@example.test", "new@example.test"),
                self.change("a2", "u1", "2026-01-01T00:00:00Z", "old@example.test", "new@example.test"),
            ],
        )
        graph = build_identity_graph(data)
        old_edges = [edge for edge in graph.intervals if edge.normalized_value == "old@example.test"]
        self.assertEqual(len(old_edges), 1)
        self.assertEqual({source.record_id for source in old_edges[0].sources}, {"a1", "a2"})

    def test_observation_combines_identifiers_conservatively_and_keeps_resource_context(self) -> None:
        data = self.ingestion([self.identity("u1", "a@example.test"), self.identity("u2", "b@example.test")], [])
        resolver = IdentityResolver(build_identity_graph(data))
        stable = resolver.resolve_identifier("user_id", "u1")
        self.assertEqual(stable.status, ResolutionStatus.CONFIRMED)
        self.assertEqual(stable.identity_sources[0].source_file, "user_identities.csv")
        consistent = self.observation("o1", (
            IdentifierValue("user_id", "u1", "u1"),
            IdentifierValue("customer_reference", "u1", "u1"),
            IdentifierValue("email", "a@example.test", "a@example.test"),
            IdentifierValue("email", "a@example.test", "a@example.test"),
        ))
        result = resolver.resolve_observation(consistent)
        self.assertEqual(result.status, ResolutionStatus.CONFIRMED)
        self.assertEqual(result.matched_user_id, "u1")
        self.assertEqual(len(result.identifier_matches), 3)
        self.assertEqual(result.source.locator, "json:/records/0")

        conflict = self.observation("o2", (
            IdentifierValue("user_id", "u1", "u1"),
            IdentifierValue("email", "b@example.test", "b@example.test"),
        ))
        conflicting_result = resolver.resolve_observation(conflict)
        self.assertEqual(conflicting_result.status, ResolutionStatus.AMBIGUOUS)
        self.assertIsNone(conflicting_result.matched_user_id)

    def test_resource_id_alone_never_resolves_and_system_context_is_preserved(self) -> None:
        data = self.ingestion([self.identity("u1", "a@example.test")], [])
        resolver = IdentityResolver(build_identity_graph(data))
        left = resolver.resolve_observation(self.observation("left", (IdentifierValue("resource_id", "shared-r", "shared-r"),), system="svc-a"))
        right = resolver.resolve_observation(self.observation("right", (IdentifierValue("resource_id", "shared-r", "shared-r"),), system="svc-b"))
        self.assertEqual(left.status, ResolutionStatus.UNRESOLVED)
        self.assertEqual(right.status, ResolutionStatus.UNRESOLVED)
        self.assertEqual(left.source.file_id, "evidence_x")
        self.assertNotEqual(left.source.observation_id, right.source.observation_id)

    def test_request_resolution_uses_requested_at_and_preserves_request_provenance(self) -> None:
        request = ["case-1", "old@example.test", "2026-01-02T00:00:00Z", "NOT_STARTED",
                   "2026-01-02T00:00:00Z", "2026-01-03T00:00:00Z", "Please delete my account"]
        data = self.ingestion(
            [self.identity("u1", "new@example.test")],
            [self.change("a1", "u1", "2026-02-01T00:00:00Z", "old@example.test", "new@example.test")],
            [request],
        )
        resolution = IdentityResolver(build_identity_graph(data)).resolve_request(data.bundle.table("deletion_requests").records[0])
        self.assertEqual(resolution.status, ResolutionStatus.CONFIRMED)
        self.assertEqual(resolution.matched_user_id, "u1")
        self.assertEqual(resolution.source.record_id, "case-1")
        self.assertIn("a1", {source.record_id for source in resolution.identifier_matches[0].identity_sources})

    def test_request_with_unique_expired_historical_email_resolves_from_full_history(self) -> None:
        request = ["case-1", "old@example.test", "2026-03-01T00:00:00Z", "NOT_STARTED",
                   "2026-03-01T00:00:00Z", "2026-03-02T00:00:00Z", "Please delete my account"]
        data = self.ingestion(
            [self.identity("u1", "new@example.test")],
            [self.change("a1", "u1", "2026-02-01T00:00:00Z", "old@example.test", "new@example.test")],
            [request],
        )
        resolution = IdentityResolver(build_identity_graph(data)).resolve_request(
            data.bundle.table("deletion_requests").records[0])
        self.assertEqual(resolution.status, ResolutionStatus.CONFIRMED)
        self.assertEqual(resolution.matched_user_id, "u1")
        self.assertEqual(resolution.confidence, MatchConfidence.MEDIUM)
        self.assertIn("unique_historical_owner_outside_request_validity",
                      resolution.identifier_matches[0].reason_codes)
        self.assertIn("a1", {source.record_id for source in resolution.identifier_matches[0].identity_sources})

    def test_request_with_historical_email_reused_across_users_remains_ambiguous(self) -> None:
        request = ["case-1", "shared@example.test", "2026-03-01T00:00:00Z", "NOT_STARTED",
                   "2026-03-01T00:00:00Z", "2026-03-02T00:00:00Z", "Please delete my account"]
        data = self.ingestion(
            [self.identity("u1", "u1-new@example.test"), self.identity("u2", "u2-new@example.test")],
            [
                self.change("a1", "u1", "2026-01-01T00:00:00Z", "shared@example.test", "u1-new@example.test"),
                self.change("a2", "u2", "2026-01-01T00:00:00Z", "u2-old@example.test", "shared@example.test"),
                self.change("a3", "u2", "2026-02-01T00:00:00Z", "shared@example.test", "u2-new@example.test"),
            ],
            [request],
        )
        resolution = IdentityResolver(build_identity_graph(data)).resolve_request(
            data.bundle.table("deletion_requests").records[0])
        self.assertEqual(resolution.status, ResolutionStatus.AMBIGUOUS)
        self.assertIsNone(resolution.matched_user_id)
        self.assertEqual(resolution.candidate_user_ids, ("u1", "u2"))

    def test_request_with_invalid_requested_at_is_unresolved(self) -> None:
        request = ["case-1", "a@example.test", "not-a-time", "NOT_STARTED",
                   "2026-01-02T00:00:00Z", "2026-01-03T00:00:00Z", "Please delete my account"]
        data = self.ingestion([self.identity("u1", "a@example.test")], [], [request])
        resolution = IdentityResolver(build_identity_graph(data)).resolve_request(data.bundle.table("deletion_requests").records[0])
        self.assertEqual(resolution.status, ResolutionStatus.UNRESOLVED)
        self.assertIn("request_time_missing_or_invalid", resolution.reason_codes)

    def test_duplicate_user_id_is_unresolved_not_collapsed(self) -> None:
        data = self.ingestion(
            [self.identity("u1", "a@example.test"), self.identity("u1", "b@example.test")], [],
        )
        graph = build_identity_graph(data)
        resolver = IdentityResolver(graph)
        result = resolver.resolve_identifier("user_id", "u1")
        alias_result = resolver.resolve_identifier("email", "a@example.test")
        self.assertEqual(result.status, ResolutionStatus.UNRESOLVED)
        self.assertEqual(alias_result.status, ResolutionStatus.UNRESOLVED)
        self.assertIn("u1", graph.duplicate_user_ids)

    def test_full_pass_is_deterministic_and_keeps_extraction_gaps_separate(self) -> None:
        data = self.ingestion(
            [self.identity("u1", "a@example.test", "2026-01-01T00:00:00Z")], [],
            [["case-1", "a@example.test", "2026-02-01T00:00:00Z", "NOT_STARTED",
              "2026-02-01T00:00:00Z", "2026-02-02T00:00:00Z", "Delete"]],
        )
        observation = self.observation("o1", (IdentifierValue("email", "a@example.test", "a@example.test"),))
        complete = FileExtractionResult("f1", "evidence/x.json", "json", "json", ExtractionStatus.COMPLETE,
            ParsedTimestamp("2026-02-01T00:00:00Z", TimestampStatus.VALID, self.at("2026-02-01T00:00:00Z")),
            (observation,), (), (), ())
        failed = FileExtractionResult("f2", "evidence/screen.png", "png", "none", ExtractionStatus.FAILED,
            None, (), (), (), ())
        extracted = EvidenceExtractionResult((complete, failed))
        first, second = resolve_identities(data, extracted), resolve_identities(data, extracted)
        self.assertEqual(first, second)
        self.assertEqual(first.extraction_gap_file_ids, ("f2",))
        self.assertEqual(first.request_resolutions[0].status, ResolutionStatus.CONFIRMED)
        self.assertEqual(first.observation_resolutions[0].status, ResolutionStatus.CONFIRMED)


if __name__ == "__main__":
    unittest.main()
