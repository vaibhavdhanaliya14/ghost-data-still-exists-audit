"""Thin command-line entry point for validating the participant dataset."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from audit_agent import (
    ResourceState, build_timeline, discover_evidence, extract_evidence, load_dataset,
    reconstruct_request_states, resolve_identities,
)
from audit_agent.identity import ResolutionStatus
from audit_agent.timeline import EventCategory


def main(argv: list[str] | None = None) -> int:
    repository_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description="Validate and ingest challenge CSV inputs.")
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=repository_root / "dataset",
        help="Participant dataset directory (read-only).",
    )
    args = parser.parse_args(argv)

    result = load_dataset(args.dataset_dir)
    discovery = discover_evidence(result, args.dataset_dir)
    extraction = extract_evidence(discovery)
    identity = resolve_identities(result, extraction)
    timeline = build_timeline(result, extraction, identity)
    case_states = reconstruct_request_states(result, identity, timeline)
    extraction_ok = all(
        item.status.value in {"complete", "empty"} for item in extraction.files
    )
    summary = {
        "ok": result.ok and discovery.ok,
        "ingestion_ok": result.ok,
        "tables_loaded": {
            name: len(table.records) for name, table in sorted(result.bundle.tables.items())
        },
        "issue_count": len(result.issues),
        "fatal_count": len(result.fatal_errors),
        "row_error_count": len(result.row_errors),
        "issues": [
            {
                "code": issue.code,
                "severity": issue.severity.value,
                "source_file": issue.source_file,
                "record_number": issue.record_number,
                "physical_line": issue.physical_line,
                "column": issue.column,
                "message": issue.message,
            }
            for issue in result.issues
        ],
        "evidence_discovery": {
            "manifest_ok": discovery.manifest_ok,
            "ok": discovery.ok,
            "entries": len(discovery.entries),
            "discovered": discovery.discovered_count,
            "missing": discovery.missing_count,
            "rejected": discovery.rejected_count,
            "inaccessible": discovery.inaccessible_count,
            "unmanifested": len(discovery.unmanifested_paths),
            "diagnostics": [
                {
                    "scope": diagnostic.scope,
                    "code": diagnostic.code,
                    "severity": diagnostic.severity.value,
                    "file_id": diagnostic.file_id,
                    "path": diagnostic.original_path,
                    "message": diagnostic.message,
                }
                for diagnostic in discovery.diagnostics
            ],
        },
        "evidence_extraction": {
            "ok": extraction_ok,
            "files": len(extraction.files),
            "observations": extraction.observation_count,
            "per_format": {key: dict(value) for key, value in extraction.counts_by_format().items()},
            "non_successful_files": [
                {
                    "file_id": item.file_id,
                    "path": item.source_path,
                    "status": item.status.value,
                    "diagnostic_codes": [d.code for d in (*item.warnings, *item.errors)],
                }
                for item in extraction.files
                if item.status.value not in {"complete", "empty"}
            ],
        },
        "identity_resolution": {
            "users": len(identity.graph.user_ids),
            "identity_intervals": len(identity.graph.intervals),
            "identity_conflicts": len(identity.graph.conflicts),
            "requests": {
                status.value: sum(item.status is status for item in identity.request_resolutions)
                for status in ResolutionStatus
            },
            "observations": {
                status.value: sum(item.status is status for item in identity.observation_resolutions)
                for status in ResolutionStatus
            },
            "observations_total": len(identity.observation_resolutions),
            "extraction_gap_files": len(identity.extraction_gap_file_ids),
        },
        "timeline": {
            "events": len(timeline.events),
            "by_category": {
                category.value: sum(event.category is category for event in timeline.events)
                for category in EventCategory
                if any(event.category is category for event in timeline.events)
            },
            "by_timestamp_quality": {
                quality: sum(event.timestamp_quality == quality for event in timeline.events)
                for quality in sorted({event.timestamp_quality for event in timeline.events})
            },
            "unresolved_observations": len(timeline.unresolved_observation_ids),
            "nonmatching_observations": len(timeline.nonmatching_observation_ids),
            "unplaced_observations": len(timeline.unplaced_observation_ids),
            "conflicts": len(timeline.conflicts),
            "extraction_gap_files": len(timeline.extraction_gap_file_ids),
            "diagnostics": len(timeline.diagnostics),
        },
        "resource_states": {
            "case_snapshots": len(case_states),
            "cases_without_confirmed_subject": sum(item.snapshot is None for item in case_states),
            "assessments": sum(len(item.snapshot.assessments) for item in case_states if item.snapshot),
            "by_state": {
                state.value: sum(
                    assessment.state is state
                    for case in case_states if case.snapshot
                    for assessment in case.snapshot.assessments
                )
                for state in ResourceState
                if any(assessment.state is state for case in case_states if case.snapshot
                       for assessment in case.snapshot.assessments)
            },
            "conflicting_assessments": sum(
                assessment.state is ResourceState.CONFLICTING
                for case in case_states if case.snapshot
                for assessment in case.snapshot.assessments
            ),
            "last_known_state_counts": {
                state.value: sum(
                    assessment.last_observed_state is state
                    for case in case_states if case.snapshot
                    for assessment in case.snapshot.assessments
                )
                for state in ResourceState
                if any(assessment.last_observed_state is state for case in case_states if case.snapshot
                       for assessment in case.snapshot.assessments)
            },
            "unlinked_events": len(set(
                event_id for case in case_states if case.snapshot
                for event_id in case.snapshot.unlinked_event_ids
            )),
            "unlinked_conflicts": len(set(
                conflict.conflict_id for case in case_states if case.snapshot
                for conflict in case.snapshot.unlinked_conflicts
            )),
            "extraction_gap_files": len(timeline.extraction_gap_file_ids),
        },
    }
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if result.ok and discovery.ok and extraction_ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
