"""Offline synthetic coverage for Phase 7 deletion-policy evaluation."""

from __future__ import annotations

import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType

from audit_agent.extract import (
    EvidenceExtractionResult, ExtractedObservation, FileExtractionResult, ExtractionStatus,
    IdentifierValue, ObservationTimestamp,
)
from audit_agent.identity import (
    IdentityGraph, IdentityInterval, IdentityResolution, IdentityResolutionResult,
    IdentitySource, MatchConfidence, ResolutionStatus,
)
from audit_agent.ingest import parse_timestamp
from audit_agent.models import CsvRecord, CsvTable, DatasetBundle, IngestionResult, SourceLocation
from audit_agent.policy import (
    ConditionStatus, DecisionStatus, PolicyAction, _category_for, evaluate_deletion_policy,
)
from audit_agent.state import (
    CaseStateSnapshot, ResourceAssessment, ResourceKey, ResourceState,
    StateDomain, StateEvidence, StateSnapshot,
)
from audit_agent.timeline import TimelineSource


UTC = timezone.utc
AUDIT = datetime(2026, 4, 1, tzinfo=UTC)


def _at(raw: str) -> datetime:
    return datetime.fromisoformat(raw.replace("Z", "+00:00"))


def _rule_row(rule_id: str, category: str, condition: str, action: str, index: int) -> CsvRecord:
    values = {"rule_id": rule_id, "data_category": category,
              "condition": condition, "required_action": action}
    return CsvRecord(SourceLocation("deletion_rules.csv", index, index),
        MappingProxyType(values), MappingProxyType({}), tuple(values.values()))


def _obs(name: str, fields: dict[str, object], *, captured_at: str = "2026-04-01T00:00:00Z",
         event_at: str = "2026-03-31T23:00:00Z", system: str = "support_service",
         resource: str = "resource-1", fmt: str = "sql") -> ExtractedObservation:
    raw = dict(fields)
    raw.setdefault("resource_id", resource)
    if event_at:
        raw.setdefault("updated_at", event_at)
    timestamps = tuple(ObservationTimestamp(key, str(value), parse_timestamp(str(value)))
                       for key, value in raw.items()
                       if key.endswith(("_at", "_time", "_until")) and value is not None)
    return ExtractedObservation(
        name, "file-" + name, f"evidence/{name}.{fmt}", fmt, f"table:test/row:{name}",
        "synthetic-parser", MappingProxyType(raw), MappingProxyType(dict(raw)),
        (IdentifierValue("user_id", "u-1", "u-1"),), system, resource,
        timestamps, parse_timestamp(captured_at),
    )


def _case(observations: list[ExtractedObservation], *, states: list[ResourceState] | None = None,
          domains: list[StateDomain] | None = None, audit_at: datetime = AUDIT,
          user_id: str | None = "u-1", subject_status: str = "confirmed"):
    states = states or [ResourceState.PRESENT] * len(observations)
    domains = domains or [StateDomain.LIFECYCLE] * len(observations)
    evidence = []
    grouped_evidence = {}
    for obs, state, domain in zip(observations, states, domains):
        source = TimelineSource("evidence", obs.source_path, file_id=obs.file_id,
                                observation_id=obs.observation_id, locator=obs.locator,
                                file_format=obs.file_format)
        parsed = parse_timestamp(str(obs.raw_fields.get("updated_at", "")))
        item = StateEvidence(obs.observation_id, state, domain, source, parsed,
            obs.captured_at, obs.captured_at.value, "manifest_capture_snapshot", None, None,
            None, "observation")
        key = ResourceKey("u-1", (obs.system_id or "",), obs.resource_id or "resource-1",
                          str(obs.raw_fields.get("record_type") or "USER_PROFILE"))
        group = grouped_evidence.setdefault((key, domain), [])
        group.append(item)
        evidence.append(item)
    assessments = tuple(ResourceAssessment(key, domain, audit_at, items[-1].state or ResourceState.UNKNOWN,
        items[-1].state, max((item.state_observed_at for item in items if item.state_observed_at), default=None),
        tuple(items), (), (), (), ()) for (key, domain), items in grouped_evidence.items())
    snapshot = StateSnapshot(audit_at, assessments, (), (), (), (), (), (), ())
    case = CaseStateSnapshot("case-1", subject_status, user_id, snapshot if user_id else None,
                             None if user_id else "request_subject_not_confirmed")
    files = tuple(FileExtractionResult(obs.file_id, obs.source_path, obs.file_format,
        "synthetic-parser", ExtractionStatus.COMPLETE, obs.captured_at, (obs,), (), (), ())
        for obs in observations)
    extracted = EvidenceExtractionResult(files)
    resolutions = tuple(IdentityResolution(obs.observation_id, "observation", ResolutionStatus.CONFIRMED,
        "u-1", ("u-1",), MatchConfidence.HIGH, obs.identifiers, (), (), (),
        IdentitySource(obs.source_path, file_id=obs.file_id, observation_id=obs.observation_id,
                       locator=obs.locator)) for obs in observations)
    interval = IdentityInterval("u-1", "email", "customer@example.test", ("customer@example.test",),
                                None, None, ())
    graph = IdentityGraph(("u-1",), MappingProxyType({"u-1": ()}), (interval,), (),
        MappingProxyType({("email", "customer@example.test"): (interval,)}), frozenset(), frozenset())
    identities = IdentityResolutionResult(graph, (), resolutions, ())
    return case, extracted, identities


def _evaluate(rules: list[tuple[str, str, str, str]], observations: list[ExtractedObservation], **kwargs):
    records = tuple(_rule_row(*rule, index) for index, rule in enumerate(rules, 1))
    table = CsvTable("deletion_rules", Path("deletion_rules.csv"),
        ("rule_id", "data_category", "condition", "required_action"), records, True)
    ingestion = IngestionResult(DatasetBundle({"deletion_rules": table}), ())
    identity_override = kwargs.pop("identity_override", None)
    no_state_assessments = kwargs.pop("no_state_assessments", False)
    case, extraction, identities = _case(observations, **kwargs)
    if no_state_assessments and case.snapshot is not None:
        case = replace(case, snapshot=replace(case.snapshot, assessments=()))
    if identity_override is not None:
        identities = identity_override
    return evaluate_deletion_policy(ingestion, identities, extraction, (case,))


class PolicyEvaluationTests(unittest.TestCase):
    def test_service_export_provenance_maps_supported_json_collections_to_policy_categories(self):
        expectations = (
            ("analytics_platform", "profiles", "ANALYTICS_PROFILE"),
            ("search_service", "index_queries", "SEARCH_INDEX_ENTRY"),
            ("support_platform", "tickets", "SUPPORT_MESSAGE"),
            ("security_service", "audit_records", "SECURITY_AUDIT_LOG"),
            ("backup_service", "restore_entries", "BACKUP_ARCHIVE"),
            ("export_service", "exports", "USER_EXPORT"),
        )
        for system, collection, expected in expectations:
            with self.subTest(system=system, collection=collection):
                obs = _obs("export-observation", {"resource_id": "r-1", "collection_name": collection},
                           system=system)
                self.assertEqual(_category_for(obs, {obs.observation_id: obs}), expected)

    def test_supported_sql_inventory_table_name_maps_security_retention_category(self):
        obs = replace(_obs("sql-audit", {"resource_id": "audit-1", "retention_until": "2031-12-31T00:00:00Z"}),
                      locator="table:security_audit_records/row:1")
        self.assertEqual(_category_for(obs, {obs.observation_id: obs}), "SECURITY_AUDIT_LOG")

    def test_all_fifteen_supplied_rules_preserve_the_declared_actions(self):
        inputs = [
            ("rule_01", "USER_PROFILE", "Always", "DELETE", {"record_type": "USER_PROFILE"}, ResourceState.PRESENT, StateDomain.LIFECYCLE, DecisionStatus.APPLIES),
            ("rule_02", "SECONDARY_IDENTIFIER", "Always", "DELETE", {"record_type": "SECONDARY_IDENTIFIER"}, ResourceState.PRESENT, StateDomain.LIFECYCLE, DecisionStatus.APPLIES),
            ("rule_03", "SEARCH_INDEX_ENTRY", "Always", "DELETE", {"record_type": "SEARCH_INDEX_ENTRY"}, ResourceState.PRESENT, StateDomain.LIFECYCLE, DecisionStatus.APPLIES),
            ("rule_04", "CACHE_ENTRY", "Always", "DELETE", {"record_type": "CACHE_ENTRY"}, ResourceState.PRESENT, StateDomain.LIFECYCLE, DecisionStatus.APPLIES),
            ("rule_05", "SUPPORT_MESSAGE", "Conversation contains shared customer, agent, or order context that must be retained", "REDACT", {"record_type": "SUPPORT_MESSAGE", "order_reference": "order-1"}, ResourceState.PRESENT, StateDomain.LIFECYCLE, DecisionStatus.APPLIES),
            ("rule_06", "SUPPORT_ATTACHMENT", "Attachment belongs only to the deletion subject", "DELETE", {"record_type": "SUPPORT_ATTACHMENT", "owner_email": "customer@example.test"}, ResourceState.PRESENT, StateDomain.LIFECYCLE, DecisionStatus.APPLIES),
            ("rule_07", "ANALYTICS_PROFILE", "Record is still attributable to a user", "ANONYMIZE", {"record_type": "ANALYTICS_PROFILE", "user_id": "u-1"}, ResourceState.PRESENT, StateDomain.LIFECYCLE, DecisionStatus.APPLIES),
            ("rule_08", "PRODUCT_TELEMETRY", "Record is still attributable to a user", "ANONYMIZE", {"record_type": "PRODUCT_TELEMETRY", "user_id": "u-1"}, ResourceState.PRESENT, StateDomain.LIFECYCLE, DecisionStatus.APPLIES),
            ("rule_09", "USER_EXPORT", "Always", "DELETE", {"record_type": "USER_EXPORT"}, ResourceState.PRESENT, StateDomain.LIFECYCLE, DecisionStatus.APPLIES),
            ("rule_10", "MARKETING_PROFILE", "Always", "DELETE", {"record_type": "MARKETING_PROFILE"}, ResourceState.PRESENT, StateDomain.LIFECYCLE, DecisionStatus.APPLIES),
            ("rule_11", "EMAIL_DELIVERY_LOG", "Log contains a user email address", "REDACT", {"record_type": "EMAIL_DELIVERY_LOG", "email": "customer@example.test"}, ResourceState.PRESENT, StateDomain.LIFECYCLE, DecisionStatus.APPLIES),
            ("rule_12", "SECURITY_AUDIT_LOG", "Record is within the supplied retention period", "RETAIN", {"record_type": "SECURITY_AUDIT_LOG", "retention_until": "2026-04-02T00:00:00Z"}, ResourceState.PRESENT, StateDomain.LIFECYCLE, DecisionStatus.APPLIES),
            ("rule_13", "LEGAL_HOLD_RECORD", "A supplied legal hold is active", "RETAIN", {"record_type": "LEGAL_HOLD_RECORD", "legal_hold_active": True}, ResourceState.PRESENT, StateDomain.LIFECYCLE, DecisionStatus.APPLIES),
            ("rule_14", "BACKUP_ARCHIVE", "Restore access can be blocked", "RETAIN", {"record_type": "BACKUP_ARCHIVE", "restore_allowed": False}, ResourceState.BLOCKED, StateDomain.CONTROL, DecisionStatus.APPLIES),
            ("rule_15", "ACCOUNT_TOMBSTONE", "Account is deleted and only a stable internal user_id is needed to preserve references to retained records", "REDACT", {"record_type": "ACCOUNT_TOMBSTONE", "account_status": "deleted", "subject_reference": "u-1"}, ResourceState.PRESENT, StateDomain.LIFECYCLE, DecisionStatus.APPLIES),
        ]
        rules = [(rule_id, category, condition, action)
                 for rule_id, category, condition, action, *_ in inputs]
        observations = [_obs(f"rule-case-{index}", fields)
                        for index, (_, _, _, _, fields, *_rest) in enumerate(inputs, 1)]
        states = [row[5] for row in inputs]
        domains = [row[6] for row in inputs]
        result = _evaluate(rules, observations, states=states, domains=domains)
        decisions = {decision.rule.rule_id: decision for decision in result.decisions}
        self.assertEqual(set(decisions), {row[0] for row in inputs})
        for row in inputs:
            rule_id, _, _, action, _, _, _, expected_status = row
            with self.subTest(rule=rule_id):
                self.assertEqual(decisions[rule_id].required_action.value, action)
                self.assertEqual(decisions[rule_id].status, expected_status)

    def test_always_rule_links_rule_and_evidence_without_overwriting_observed_state(self):
        obs = _obs("profile", {"record_type": "USER_PROFILE", "user_id": "u-1"})
        result = _evaluate([("rule_01", "USER_PROFILE", "Always", "DELETE")], [obs])
        decision = result.decisions[0]
        self.assertEqual(decision.status, DecisionStatus.APPLIES)
        self.assertEqual(decision.required_action, PolicyAction.DELETE)
        self.assertIn((StateDomain.LIFECYCLE, ResourceState.PRESENT), decision.observed_states)
        self.assertEqual(decision.evidence_references[0].source_kind, "deletion_rule")
        self.assertTrue(any(ref.source_id == obs.file_id for ref in decision.evidence_references))

    def test_retention_deadline_is_compared_to_audit_cutoff_not_treated_as_state(self):
        rule = ("rule_12", "SECURITY_AUDIT_LOG", "Record is within the supplied retention period", "RETAIN")
        for deadline, expected in (
            ("2026-04-02T00:00:00Z", ConditionStatus.SATISFIED),
            ("2026-03-31T00:00:00Z", ConditionStatus.NOT_SATISFIED),
            ("2026-04-01T00:00:00Z", ConditionStatus.UNKNOWN),
        ):
            with self.subTest(deadline=deadline):
                obs = _obs("security", {"record_type": "SECURITY_AUDIT_LOG", "user_id": "u-1",
                                        "retention_until": deadline})
                decision = _evaluate([rule], [obs]).decisions[0]
                self.assertEqual(decision.condition_status, expected)
                self.assertEqual(decision.required_action, PolicyAction.RETAIN)
                self.assertIn((StateDomain.LIFECYCLE, ResourceState.PRESENT), decision.observed_states)

    def test_missing_or_unsupported_condition_context_is_unresolved(self):
        conditions = [
            ("rule_05", "SUPPORT_MESSAGE",
             "Conversation contains shared customer, agent, or order context that must be retained", "REDACT"),
            ("rule_99", "USER_PROFILE", "A condition not in the supplied schema", "REDACT"),
        ]
        obs = _obs("contextless", {"record_type": "SUPPORT_MESSAGE", "subject_reference": "u-1"})
        result = _evaluate(conditions[:1], [obs])
        self.assertEqual(result.decisions[0].status, DecisionStatus.UNRESOLVED)
        self.assertEqual(result.decisions[0].condition_status, ConditionStatus.UNKNOWN)
        self.assertIn("shared_context_not_established", result.decisions[0].uncertainty)

        wrong_text = _evaluate([("rule_05", "SUPPORT_MESSAGE", "A guessed support rule", "REDACT")], [obs])
        self.assertEqual(wrong_text.decisions[0].status, DecisionStatus.UNRESOLVED)
        self.assertIn("unsupported_policy_condition", wrong_text.decisions[0].uncertainty)

        unsupported = _evaluate([conditions[1]], [_obs("profile", {"record_type": "USER_PROFILE"})])
        self.assertEqual(unsupported.decisions[0].status, DecisionStatus.UNRESOLVED)
        self.assertIn("unsupported_policy_condition", unsupported.decisions[0].uncertainty)

    def test_shared_order_context_applies_redaction_when_explicitly_present(self):
        rule = ("rule_05", "SUPPORT_MESSAGE",
                "Conversation contains shared customer, agent, or order context that must be retained", "REDACT")
        obs = _obs("support", {"record_type": "SUPPORT_MESSAGE", "subject_reference": "u-1",
                               "order_reference": "order-1"})
        decision = _evaluate([rule], [obs]).decisions[0]
        self.assertEqual(decision.status, DecisionStatus.APPLIES)
        self.assertEqual(decision.required_action, PolicyAction.REDACT)
        self.assertTrue(any(ref.field_name == "order_reference" for ref in decision.condition_evidence))

    def test_eligible_resource_context_is_evaluated_without_inventing_resource_state(self):
        rule = ("rule_05", "SUPPORT_MESSAGE",
                "Conversation contains shared customer, agent, or order context that must be retained", "REDACT")
        obs = _obs("support-image", {"data_category": "SUPPORT_MESSAGE",
                                    "order_reference": "ORD-SYNTHETIC-1",
                                    "customer_email": "customer@example.test"},
                   fmt="png", resource="CS-SYNTHETIC-1")
        decision = _evaluate([rule], [obs], no_state_assessments=True).decisions[0]
        self.assertEqual(decision.condition_status, ConditionStatus.SATISFIED)
        self.assertEqual(decision.status, DecisionStatus.APPLIES)
        self.assertEqual(decision.observed_states, ())
        self.assertTrue(any(ref.field_name == "order_reference" and ref.source_id == obs.file_id
                            for ref in decision.condition_evidence))

    def test_unattached_post_cutoff_context_cannot_create_policy_obligation(self):
        rule = ("rule_05", "SUPPORT_MESSAGE",
                "Conversation contains shared customer, agent, or order context that must be retained", "REDACT")
        obs = _obs("late-support-image", {"data_category": "SUPPORT_MESSAGE",
                                          "order_reference": "ORD-SYNTHETIC-1"},
                   captured_at="2026-04-02T00:00:00Z", fmt="png", resource="CS-SYNTHETIC-1")
        result = _evaluate([rule], [obs], no_state_assessments=True)
        self.assertEqual(result.decisions, ())
        self.assertTrue(any(ref.source_id == obs.file_id
                            for ref in result.cases[0].temporally_ineligible_observations))

    def test_explicit_order_context_in_message_text_applies_and_keeps_provenance(self):
        rule = ("rule_05", "SUPPORT_MESSAGE",
                "Conversation contains shared customer, agent, or order context that must be retained", "REDACT")
        obs = _obs("support-message", {"record_type": "SUPPORT_MESSAGE", "subject_reference": "u-1",
            "message_text": "Please send the delivery update. The affected order includes: a lamp."})
        decision = _evaluate([rule], [obs]).decisions[0]
        self.assertEqual(decision.status, DecisionStatus.APPLIES)
        self.assertTrue(any(ref.field_name == "message_text" and ref.observation_id == obs.observation_id
                            for ref in decision.condition_evidence))

    def test_redacted_message_does_not_establish_shared_context(self):
        rule = ("rule_05", "SUPPORT_MESSAGE",
                "Conversation contains shared customer, agent, or order context that must be retained", "REDACT")
        obs = _obs("redacted-support", {"record_type": "SUPPORT_MESSAGE", "subject_reference": "u-1",
            "message_text": "[REDACTED]"})
        decision = _evaluate([rule], [obs]).decisions[0]
        self.assertEqual(decision.status, DecisionStatus.UNRESOLVED)
        self.assertEqual(decision.condition_status, ConditionStatus.UNKNOWN)

    def test_explicit_false_shared_context_conflicts_with_order_text(self):
        rule = ("rule_05", "SUPPORT_MESSAGE",
                "Conversation contains shared customer, agent, or order context that must be retained", "REDACT")
        obs = _obs("conflicting-support", {"record_type": "SUPPORT_MESSAGE", "subject_reference": "u-1",
            "shared_context": False,
            "message_text": "The affected order includes: a lamp."})
        decision = _evaluate([rule], [obs]).decisions[0]
        self.assertEqual(decision.status, DecisionStatus.CONFLICTING)
        self.assertEqual(decision.condition_status, ConditionStatus.CONFLICTING)

    def test_historical_email_alias_is_checked_at_the_record_time(self):
        rule = ("rule_11", "EMAIL_DELIVERY_LOG", "Log contains a user email address", "REDACT")
        obs = _obs("historical-email", {"record_type": "EMAIL_DELIVERY_LOG",
                                         "email": "old@example.test"},
                   event_at="2026-01-15T00:00:00Z")
        _, _, identities = _case([obs])
        old = IdentityInterval("u-1", "email", "old@example.test", ("old@example.test",),
                               _at("2026-01-01T00:00:00Z"), _at("2026-02-01T00:00:00Z"), ())
        current = IdentityInterval("u-1", "email", "customer@example.test", ("customer@example.test",),
                                   _at("2026-02-01T00:00:00Z"), None, ())
        graph = IdentityGraph(("u-1",), MappingProxyType({"u-1": ()}), (old, current), (),
            MappingProxyType({("email", "old@example.test"): (old,),
                              ("email", "customer@example.test"): (current,)}), frozenset(), frozenset())
        from dataclasses import replace
        identities = replace(identities, graph=graph)
        decision = _evaluate([rule], [obs], identity_override=identities).decisions[0]
        self.assertEqual(decision.status, DecisionStatus.APPLIES)
        self.assertEqual(decision.condition_status, ConditionStatus.SATISFIED)

    def test_multiple_applicable_rules_with_different_actions_are_preserved_as_conflict(self):
        rules = [
            ("rule_a", "USER_PROFILE", "Always", "DELETE"),
            ("rule_b", "USER_PROFILE", "Always", "RETAIN"),
        ]
        obs = _obs("profile", {"record_type": "USER_PROFILE", "user_id": "u-1"})
        result = _evaluate(rules, [obs])
        self.assertEqual(len(result.decisions), 2)
        self.assertTrue(all(item.status is DecisionStatus.APPLIES for item in result.decisions))
        self.assertEqual(len(result.cases[0].conflicts), 1)
        self.assertEqual(result.cases[0].conflicts[0].actions,
                         (PolicyAction.DELETE, PolicyAction.RETAIN))
        self.assertIn("case-1", result.unresolved_case_ids)

    def test_same_time_conflicting_retention_deadlines_block_condition(self):
        rule = ("rule_12", "SECURITY_AUDIT_LOG", "Record is within the supplied retention period", "RETAIN")
        first = _obs("security-a", {"record_type": "SECURITY_AUDIT_LOG", "user_id": "u-1",
                                    "retention_until": "2026-04-05T00:00:00Z"})
        second = _obs("security-b", {"record_type": "SECURITY_AUDIT_LOG", "user_id": "u-1",
                                     "retention_until": "2026-03-20T00:00:00Z"})
        decision = _evaluate([rule], [first, second]).decisions[0]
        self.assertEqual(decision.status, DecisionStatus.CONFLICTING)
        self.assertEqual(decision.condition_status, ConditionStatus.CONFLICTING)
        self.assertIn("same_time_retention_deadlines_conflict", decision.uncertainty)

    def test_temporal_cutoff_is_inclusive_and_future_context_is_excluded(self):
        rule = ("rule_12", "SECURITY_AUDIT_LOG", "Record is within the supplied retention period", "RETAIN")
        equal = _obs("equal", {"record_type": "SECURITY_AUDIT_LOG", "user_id": "u-1",
                               "retention_until": "2026-05-01T00:00:00Z"},
                     captured_at="2026-04-01T00:00:00Z")
        exact = _evaluate([rule], [equal]).decisions[0]
        self.assertEqual(exact.condition_status, ConditionStatus.SATISFIED)

        pre_cutoff = _obs("pre-cutoff", {"record_type": "SECURITY_AUDIT_LOG", "user_id": "u-1",
                                         "retention_until": "2026-05-01T00:00:00Z"},
                          captured_at="2026-03-31T23:59:59Z")
        self.assertEqual(_evaluate([rule], [pre_cutoff]).decisions[0].condition_status,
                         ConditionStatus.SATISFIED)

        future = _obs("future", {"record_type": "SECURITY_AUDIT_LOG", "user_id": "u-1",
                                 "retention_until": "2026-05-01T00:00:00Z"},
                      captured_at="2026-04-01T00:00:01Z")
        result = _evaluate([rule], [future])
        self.assertEqual(result.decisions, ())
        self.assertTrue(result.cases[0].temporally_ineligible_observations)
        self.assertIn("captured_after_audit_at", result.cases[0].uncertainty)

        inner_future = _obs("inner-future", {"record_type": "SECURITY_AUDIT_LOG", "user_id": "u-1",
                                             "retention_until": "2026-05-01T00:00:00Z"},
                            captured_at="2026-04-01T00:00:00Z", event_at="2026-04-01T00:00:01Z")
        inner_result = _evaluate([rule], [inner_future])
        self.assertEqual(inner_result.decisions, ())
        self.assertIn("inner_timestamp_after_audit_at", inner_result.cases[0].uncertainty)

    def test_invalid_inner_timestamp_is_preserved_as_uncertainty_not_used(self):
        rule = ("rule_01", "USER_PROFILE", "Always", "DELETE")
        obs = _obs("bad-time", {"record_type": "USER_PROFILE", "user_id": "u-1"},
                   event_at="not-a-time")
        result = _evaluate([rule], [obs])
        self.assertEqual(result.decisions, ())
        self.assertIn("inner_timestamp_missing_or_invalid", result.cases[0].uncertainty)

    def test_backup_control_observation_remains_separate_from_retain_obligation(self):
        rule = ("rule_14", "BACKUP_ARCHIVE", "Restore access can be blocked", "RETAIN")
        obs = _obs("backup", {"record_type": "BACKUP_ARCHIVE", "restore_allowed": False})
        decision = _evaluate([rule], [obs], states=[ResourceState.BLOCKED],
                             domains=[StateDomain.CONTROL]).decisions[0]
        self.assertEqual(decision.status, DecisionStatus.APPLIES)
        self.assertEqual(decision.required_action, PolicyAction.RETAIN)
        self.assertIn((StateDomain.CONTROL, ResourceState.BLOCKED), decision.observed_states)

    def test_tombstone_condition_requires_deleted_account_and_stable_reference(self):
        rule = ("rule_15", "ACCOUNT_TOMBSTONE",
                "Account is deleted and only a stable internal user_id is needed to preserve references to retained records",
                "REDACT")
        missing = _obs("tombstone-missing", {"record_type": "ACCOUNT_TOMBSTONE",
                                             "subject_reference": "u-1"})
        self.assertEqual(_evaluate([rule], [missing]).decisions[0].status, DecisionStatus.UNRESOLVED)
        supported = _obs("tombstone", {"record_type": "ACCOUNT_TOMBSTONE", "account_status": "deleted",
                                        "subject_reference": "u-1"})
        decision = _evaluate([rule], [supported]).decisions[0]
        self.assertEqual(decision.status, DecisionStatus.APPLIES)
        self.assertEqual(decision.required_action, PolicyAction.REDACT)

    def test_unconfirmed_subject_does_not_receive_policy_obligations(self):
        obs = _obs("profile", {"record_type": "USER_PROFILE"})
        result = _evaluate([("rule_01", "USER_PROFILE", "Always", "DELETE")], [obs],
                           user_id=None, subject_status="unresolved")
        self.assertEqual(result.decisions, ())
        self.assertEqual(result.unresolved_case_ids, ("case-1",))


if __name__ == "__main__":
    unittest.main()
