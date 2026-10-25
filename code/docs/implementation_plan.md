# Implementation Plan (Documentation Only)

No audit engine is implemented in this inspection. This is a proposed sequence based on the participant contract and inspected files.

## Milestone 1 - deterministic identity and evidence index

Build read-only loaders for participant CSV/evidence formats and validate schemas. Construct a temporal identity graph from identities, history and request emails. Normalize email conservatively; preserve provenance. Index evidence by file_id, exact identifiers, resource_id, system/collection and event/capture time. Enforce audit_at as a hard cutoff for identity changes, evidence capture, record observations and events. Do not produce predictions until the index answers case-scoped queries and explains matches.

Acceptance conditions: every input parses; manifest coverage is complete; each request resolves to a stable subject or surfaced ambiguity; queries preserve provenance and are reproducible; future material is excluded for a chosen cutoff. The inspected set has 518 unique email-to-user matches, including 100 historical aliases, but runtime must derive this from inputs.

## Milestone 2 - intent and policy evaluation

Separate authorization from state assessment. Handle multilingual text and distinguish deletion from access/correction/export/marketing opt-out. Apply every rule condition per resource. Represent deleted, redacted, anonymized, retained, tombstone and active-risk states explicitly. Require evidence for hold, retention, shared support context, restore blocking and anonymization.

## Milestone 3 - temporal state reconstruction

For each authorized case, assemble a timeline per resource. Reconcile activity claims with JSON/SQL readbacks, screenshots/documents and snapshots. Compare primary with replicas, detect recreation through sync/import/restore, and track coverage limits. Model active flow selectors and restore permissions independently from existing copies.

## Milestone 4 - dependency-aware planning and verification

Emit supported policy violations and recreation risks with evidence references. Disable relevant flows and block unsafe restore paths before mutations; handle downstream copies before sources when required; apply DELETE, REDACT or ANONYMIZE according to policy; preserve required records and tombstones. Verify every changed resource and required retained/process state. Mark COMPLETE only if all requirements pass at audit_at.

## Milestone 5 - deterministic serialization and evaluation

Write root output.csv with all 518 cases sorted, exact columns/step fields, consecutive numbering, valid JSON arrays and deterministic ordering. Compare public cases with sample_output.csv. Add at least three independently authored cases for non-deletion intent, historical identifiers, cutoff boundaries, tombstones, replica drift, or sync/restore risks. Record case, step, field, sequence metrics and failure/improvement notes in code/evaluation/evaluation_report.md. Track actual calls and token/cost data in code/evaluation/usage_report.md.

## Engineering risks

- Global evidence is decoy-rich; email substring matching can create false positives.
- Activity results can conflict with direct record state; treat events as claims absent corroboration.
- Each case has its own cutoff; files may contain multiple internal timestamps.
- Replicas, connectors, import/sync jobs and restore-capable archives can recreate data.
- Required retained records may be compliant after transformation; deleting them can violate policy.
- Evidence coverage varies; absence in one limited file does not prove global absence.
- Tombstones may preserve stable user_id but must remove direct identifiers.

## Recommended first implementation milestone

Build the deterministic, provenance-preserving identity/evidence index with audit_at-aware queries before status decisions. It underpins accurate linking, temporal replay and defensible citations without unsupported assumptions or premature output rows.