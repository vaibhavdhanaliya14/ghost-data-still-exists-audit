# Test Strategy

## Goals and constraints

This strategy validates deterministic behavior against participant-visible files and locally authored synthetic fixtures. Do not use hidden organizer labels, generator internals, or external AI responses as expected values. The public sample_output.csv is the only supplied answer fixture and has 32 rows (COMPLETE/INCOMPLETE; it does not cover NOT_APPLICABLE). Add at least three participant-authored cases before submission as required by the project contract.

Use Python standard-library unittest so the test harness adds no required runtime dependency. Keep unit fixtures small and synthetic; do not copy real-person data into logs or reports. Tests must be offline, deterministic, and read-only with respect to dataset/. Do not invoke a live LLM in CI or unit tests. For optional model adapters, use a fake client and recorded schema-conforming responses; never treat the response as policy truth.

## Unit test matrix

| Component | Unit-test focus | Representative cases |
|---|---|---|
| Dataset ingestion/schema validation | Exact headers, types, keys, enums, nulls, parsing | 518 evaluation rows; duplicate case_id; invalid audit_at; malformed quoting; request text with commas/Unicode; header-only output template. |
| Manifest processing | ID/path integrity, safe roots, time and coverage | All 94 listed files resolve; missing or unmanifested file; duplicate file_id/path; path traversal; captured_at invalid; unsupported suffix. |
| Evidence extraction/normalization | Parser contracts and provenance for each actual format | Nested snapshot JSON; connector records; service-resource export; SQL inventory; SQL primary/replica mismatch; escaped record_json; structured/key-value log; support replica; selectable-text PDF; OCR bounding box/page; partial/failed extraction. |
| Historical identity | Current/historical aliases and time filtering | Current email; old email; email case variation; history event before/after cutoff; exact email_hash; phone format left exact; two-user collision; unknown email; name collision does not join. |
| Event timeline | Stable ordering and claim/effect semantics | Successful and failed DELETE_RECORD claims; duplicate activity; equal timestamps; sync after delete; restore event; unrelated decoy; missing event time; conflicting source events retained. |
| Resource state at cutoff | State provenance, temporal eligibility, explicit uncertainty, and scope | Creation/modification/deletion sequence; redaction, anonymization, retention, tombstone; independent lifecycle/control state; same resource ID in distinct systems; event-time and capture-time cutoff; observation at/before/after cutoff; missing inner timestamp with an explicit direct-snapshot capture; stale snapshot stays UNKNOWN but retains last-observed state; equal-time direct conflict; unlinked activity conflict; missing evidence query yields UNKNOWN; system_activity result never assigns a subject or state. |
| Policy evaluator | All 15 supplied category/condition/action rows; per-resource system scope; rule/evidence provenance; independent observed state | Exact actions for every supplied rule; shared context and exclusive attachment owner; attributable analytics/telemetry; historical email lookup; retention deadline before/after/equal to cutoff; active/inactive/missing legal hold; backup restore-control support; deleted tombstone with stable reference; unsupported condition; same-time conflicting facts and conflicting obligations; query results excluded from condition truth. |
| Retention/tombstone | Required record preservation and field allowlist | Security retention_until after/before cutoff; active/inactive/missing legal hold; backup retained and blocked; restore allowed; tombstone with user_id only; prohibited email/phone/hash/name; missing user_id. |
| Recreation risk (Phase 8) | Observed effect versus possible control risk; provenance, identity and time gating | Direct delete then later present/recreation; restore, replication, sync and import with direct state support; active flow selectors on current/historical aliases; enabled/disabled/ambiguous selector; explicit backup restore permission; system/resource collision; event and capture cutoff boundaries; stale state; conflicting claims; unresolved identity; unlinked activity only as claim. Assert findings retain evidence refs and do not become final status. |
| Phase 9 intent and case adjudication | Intent is text-only; adjudication combines confirmed identity, temporal states, policy and Phase 8 findings | English/Spanish/French/Japanese/Portuguese/Korean deletion, access/export, correction, opt-out, explicit non-deletion, negation, hedged and vague intent, contradictory clauses, multi-action; missing identity; unresolved policy; claims vs direct recreation findings; direct violation -> INCOMPLETE; fully evidenced compliance -> COMPLETE; non-deletion -> NOT_APPLICABLE; unknown/gap-only -> unresolved with no status. |
| Remediation planner | Allowed action and dependency order | Disable flow and block restore first; downstream copy before source; DELETE vs REDACT vs ANONYMIZE; preserve retention/tombstone; deterministic tie sort; cycle and unknown-action failure. |
| Verification planner | Coverage, evidence and phase semantics | COMPLETE has only evidence-backed checks; incomplete future checks have empty evidence_id; retained record check; flow/restore requirements; each remediation has a verification; post-cutoff citation rejected. |
| Output generation/validation | Exact participant contract and sample shape | Exact header, 518 rows, status set, seven step keys, allowed triples, evidence source/time rules, phase/operation/system/resource ordering, dependencies, verification coverage, CSV/JSON escaping, no partial output. |
| Evaluation/usage reporting | Independently defined metrics and run accounting | Synthetic predictions with known expected values; separate status, field, evidence-reference and sequence numerators/denominators; public sample join; three custom cases; missing provider usage stays unknown. |

## Request-intent tests (separate from status classification)

The intent classifier returns an internal `DELETE`, `OTHER`, or `AMBIGUOUS` result with a rationale/provenance. These are not output statuses. Test intent in isolation from resource evidence and final status; then test the status classifier against fixed intent results so policy/state errors cannot be masked by language interpretation.

| Synthetic request pattern | Intent assertion | Separate status test |
|---|---|---|
| Explicitly asks to delete/erase the account and associated data | `DELETE` | With complete proof -> `COMPLETE`; with a proven violation -> `INCOMPLETE`. |
| Access request only | `OTHER` | `NOT_APPLICABLE`, `steps_json=[]`. |
| Correction request only | `OTHER` | `NOT_APPLICABLE`, `steps_json=[]`. |
| Export/copy request only | `OTHER` | `NOT_APPLICABLE`, `steps_json=[]`. |
| Marketing opt-out only | `OTHER` | `NOT_APPLICABLE`, `steps_json=[]`. |
| Explicit Spanish deletion phrase such as “Quiero eliminar mi cuenta” (synthetic) | `DELETE` only when a human-checked fixture establishes the translation | Same status matrix as explicit deletion; unsupported interpretation remains unresolved. |
| Vague request such as “take me off your system” | Internal `AMBIGUOUS` | Do not guess an output status. **REASONABLE FAIL-CLOSED DESIGN CHOICE:** block the full output run pending resolution; the contract has no ambiguity status or explicit partial-run behavior. |
| Negated deletion, e.g. “do not delete my account; only send a copy” | `OTHER` | `NOT_APPLICABLE`, `steps_json=[]`; deletion keywords alone must not authorize deletion. |
| Clear independent deletion clause plus a separate access/export action | **REASONABLE DESIGN CHOICE:** `DELETE` plus the companion action recorded separately; shared-scope or contradictory wording -> unresolved | Only evaluate deletion scope after intent is resolved; status then follows policy/evidence. Official instructions do not define mixed-action precedence. |
| Marketing suppression wording that includes “delete” (delete marketing messages, keep account) | `OTHER` | `NOT_APPLICABLE`, `steps_json=[]`. |

These authored phrases are synthetic test inputs, not claims about challenge labels. Include multilingual positive and negative examples with synthetic wording. Do not assume a translation is correct without a human-checked test fixture. The official instructions do not define mixed-action precedence or an ambiguity output. Treat a clear independent deletion clause as deletion-authorizing only as an explicit design choice; test contradictory/unclear wording as internally unresolved and block output rather than guessing.

## Classification and evidence invariants

Keep these three invariants independent in both unit tests and integration gates:

1. **Unknown evidence never establishes COMPLETE.** Unknown identity, state, timestamp, evidence coverage, or policy condition cannot serve as proof of a required state. A supported violation can establish `INCOMPLETE`; unknown alone must not be promoted into an invented finding.
2. **A material unresolved conflict blocks unsupported classification and serialization.** Conflicting eligible observations about a required resource, identity, policy condition, or active process stay visible. If the conflict changes the required result and is unresolved, classification is internally blocked and output serialization fails with case diagnostics.
3. **Submission behavior follows the official contract.** The only output statuses are `COMPLETE`, `INCOMPLETE`, and `NOT_APPLICABLE`; no internal `UNKNOWN`/`BLOCKED` value is serialized. Never omit or silently drop a case. If any case remains unresolved, fail the entire output gate without writing a partial `output.csv`, list the affected case IDs, and resolve them before a submission run. A successful output must contain exactly one row for every input case.

Unknown evidence and unresolved conflicts are distinct: absence of evidence is not itself a conflict, and a conflict is not resolved by selecting the more convenient source.

## Per-file extraction results versus per-case evidence coverage

Track extraction and case coverage as separate records. `FileExtractionResult` is keyed by `file_id` and records parser, complete/partial/failed status, discovered scope, locators, warnings, and extraction errors. `CaseEvidenceCoverage` is keyed by `case_id` and records candidate evidence, examined files, eligible facts at `audit_at`, required resource/system scopes covered, and material gaps/conflicts. A file parse failure must never be represented as zero facts or as absence.

Test (a) successfully extracted but unrelated/decoy evidence that does not affect a case, (b) a failed file independently established to be outside that case’s possible evidence scope, and (c) a failed candidate file whose contents could establish a required state, which must mark that case’s coverage incomplete and block `COMPLETE`. Do not label a failed file irrelevant merely because its manifest path, origin, or capture time does not identify a case; the manifest explicitly does not provide case membership. If possible relevance cannot be ruled out, treat the gap as material. Report file-level extraction coverage separately from case-level prediction metrics.

## Fixture design

Build compact fixtures that use the dataset's real field names and record shapes while using synthetic identifiers. Each fixture should state the expected parsed facts, temporal inclusion, policy action, status, and steps separately. Avoid embedding an end-to-end answer as one opaque golden blob; assert each stage so a failure localizes to ingestion, identity, evidence, policy, or planning.

Required authored scenarios should include at minimum:

1. A request for access or marketing opt-out that must be NOT_APPLICABLE with an empty array.
2. A deletion requested with an old email where an active data-flow selector still matches that alias; ensure risk is found and flow disablement precedes affected-record remediation.
3. A tombstone that keeps user_id but exposes email_hash or phone; redact identifiers and verify stable reference remains.

Additional high-value scenarios: search index present in a replica after primary deletion; support conversation with shared order context vs subject-only attachment; retained security/legal record with actual expiration/hold; retained backup whose restore is blocked; a restore or sync event after deletion; and a late evidence file that must be excluded for an earlier audit_at.

## Integration and contract checks

- Run ingestion against the actual participant dataset and assert exact schemas, 518 cases, 850 identities, 306 audit rows, 4,011 activity rows, 15 rules and 94 manifest/evidence files. These are diagnostics, not hardcoded prediction labels.
- Run extractors across every file and record parse coverage by file_id. A parse failure must be visible and cannot become an empty resource set.
- Treat the participant-visible instructions and sample_output.csv as the output-contract sources. The checked sample has the exact 3-column header, 32 case-sorted rows (10 COMPLETE, 22 INCOMPLETE), 7 fields per step, all 15 documented phase/operation/state triples, consecutive step numbers, and 75 populated references that resolve to manifest/activity/audit IDs with source time at or before the sample case audit_at. It contains no NOT_APPLICABLE example; test that status and `[]` from the written contract using synthetic fixtures, not a fabricated sample answer. Re-run these checks when source docs/data change.
- Run all 32 public sample requests end-to-end and compare status, steps, evidence IDs, field values and array order to sample_output.csv. Report disagreements rather than relaxing assertions. This is permitted public truth.
- Validate all 518 output rows structurally before writing. Never invent a status or drop a case: unresolved material intent/evidence/conflict fails the whole serialization gate, writes no partial output, and reports every blocked case_id. A successful run has exactly the official status set and one row per request.
- Re-run on identical inputs and require byte-identical output and reports apart from explicitly timestamped run metadata.
- Confirm no test writes into dataset/. Use temporary directories for generated CSV/JSON/report artifacts; use in-memory SQLite or temporary copies for SQL and malformed-file tests. Assert dataset file hashes are unchanged when a test exercises ingestion.

## Temporal and conflict properties

Use table-driven and metamorphic tests for rules that must hold across many records:

- Adding evidence captured after audit_at never changes a case result.
- Adding a post-cutoff identity change never changes the eligible alias set for that case.
- Reordering input rows does not change output order or decisions.
- Reordering unrelated decoys does not change a subject's result.
- Changing reported_status/reported_result alone cannot make a record present or absent.
- A state-changing event without adequate evidence does not upgrade UNKNOWN to ABSENT.
- A later replica observation may change a later audit, but not an earlier one.
- Replacing a direct identifier with a permitted stable user_id in a tombstone removes the exposed-PII violation but does not remove the required retained record.
- A retained record's presence is not a deletion violation when its specific rule requires RETAIN and its condition is met.
- Enabling a matching flow or unblocking a restore path cannot leave the case COMPLETE.

## Output-contract assertions

Assert against `AGENTS.md` §6.3–6.6, `problem_statement.md` output/rule tables, `README.md` ordering guidance, and `dataset/sample_output.csv`; do not infer enum validity from a proposed design. Test exact header/order `case_id,deletion_status,steps_json`; CSV `case_id`, `deletion_status`, and `steps_json` are strings before parsing; exactly one sorted row for each of 518 `case_id`s; status exactly `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`; and `NOT_APPLICABLE` has `[]`. Each step has exactly `step_no,phase,system_id,resource_id,operation,state,evidence_id`; the contract requires consecutive step numbering and the sample represents `step_no` as an integer and other fields as strings (test these as sample-compatible serializer types, not as separately stated type constraints); step numbers are consecutive and phases are ordered FINDING -> REMEDIATION -> VERIFICATION. Validate every allowed triple from the participant table: FINDING (`REPORT_REMAINING_RECORD/PRESENT`, `REPORT_EXPOSED_PII/PRESENT`, `REPORT_ACTIVE_DATA_FLOW/ACTIVE`, `REPORT_RESTORE_RISK/ACTIVE`); REMEDIATION (`DISABLE_DATA_FLOW/DISABLED`, `BLOCK_RESTORE/BLOCKED`, `DELETE_RECORD/ABSENT`, `REDACT_RECORD/REDACTED`, `ANONYMIZE_RECORD/ANONYMIZED`); VERIFICATION (`VERIFY_RECORD_ABSENT/ABSENT`, `VERIFY_RECORD_PRESENT/PRESENT`, `VERIFY_RECORD_REDACTED/REDACTED`, `VERIFY_RECORD_ANONYMIZED/ANONYMIZED`, `VERIFY_DATA_FLOW_DISABLED/DISABLED`, `VERIFY_RESTORE_BLOCKED/BLOCKED`). Reject all other values.

Require COMPLETE to contain only current evidence-backed verification steps; INCOMPLETE to contain evidence-backed findings, complete proposed remediation, and future verification; and NOT_APPLICABLE to have no steps. Findings and COMPLETE verification cite an existing participant-visible `file_id`, `activity_id`, or `audit_id` whose applicable source time (manifest `captured_at`, activity/audit event time, plus any known inner observation time) is not after `audit_at`. Proposed remediation and future INCOMPLETE verification use the empty string reference. Test unknown IDs, ineligible future refs, missing refs, and a valid eligible ref for each source kind. Check operation ordering inside each phase (as enumerated in the participant instructions), then `system_id` and `resource_id` ascending; verify the sample conforms. Test that remediation dependency edges (flow disable/restore block before dependent record changes; downstream copy before source when required) and verification coverage for every required state predicate are satisfied. If dependencies and required serialization order cannot both be satisfied, fail planning/serialization with diagnostics rather than outputting a knowingly invalid order; this fail-closed conflict behavior is a design choice because the official instructions do not state precedence.

Round-trip CSV/JSON with commas, quotes, CR/LF, non-ASCII and multilingual text in valid fields; ensure JSON escaping remains valid within CSV quoting, output encoding is UTF-8, and reads round-trip exactly. Generated artifacts go to a temporary directory, never dataset/.

## Evaluation metric tests with known synthetic outcomes

Test evaluation separately from prediction logic using tiny synthetic reference/prediction pairs whose correct scores are calculated by hand. The contract requires case/status, step/field, and sequence evaluation but does not prescribe formulas; the following denominators are **REASONABLE REPORTING CONVENTIONS**, to be stated consistently and not represented as HackerRank scoring formulas. Evidence-reference accuracy is an additional diagnostic. Report each metric with numerator and denominator, not a single combined score:

- **Status accuracy:** exact status matches / number of reference cases with an adjudicated status.
- **Field accuracy:** exact per-field matches / `7 * sum(max(reference_step_count, predicted_step_count))` across cases; compare positional step slots, count a missing/extra step slot as seven field errors, and do not let extra output fields disappear from validation.
- **Evidence-reference accuracy:** exact `evidence_id` matches / `sum(max(reference_step_count, predicted_step_count))`; missing/extra steps count as incorrect reference slots. Report how many expected references were eligible/available separately if a source reference is unavailable.
- **Sequence accuracy:** cases whose complete ordered step arrays match exactly / cases with a complete reference step array. A permutation with the same steps fails this metric.

Include known synthetic examples for perfect predictions, one status error, one field-only mismatch, one evidence-reference mismatch, one reordered sequence, and missing/extra steps; assert exact numerators, denominators, and zero-denominator behavior (`not available`, never a fabricated 0% or 100%). Keep public sample evaluation distinct from these authored tests and from hidden-label accuracy.

## Failure reporting and coverage

Each failed test should identify case fixture, component, evidence locator and cutoff without printing contact details. Track parse coverage separately from case accuracy. Unknown identity, timestamp, extraction or policy state must be surfaced as diagnostics and prevent COMPLETE. A passing format test alone is not evidence of correct challenge predictions. Evaluation accuracy may only be reported where an authorized reference exists; hidden-label accuracy must not be guessed.
