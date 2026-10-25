# Implementation Architecture

## Scope and runtime choice

Python is appropriate: the repository requires terminal execution but mandates no different language/runtime, and its evidence includes CSV, JSON, SQLite-compatible SQL, UTF-8 logs, selectable-text PDFs and screenshots. Keep the current starter entry point code/main.py as a thin CLI. Proposed package: code/audit_agent/ with models.py, ingest.py, manifest.py, extractors/, identity.py, timeline.py, state.py, policy.py, risks.py, planner.py, output.py and reporting.py. Put tests under code/tests/. This is a design only; no application modules are created here.

Use standard-library csv, json, sqlite3, datetime, pathlib, dataclasses, enum and unittest for deterministic core logic. Isolate PDF/OCR adapters so missing optional packages do not break CSV/SQL/log processing. Paths resolve from repository root. Inputs are read-only; write only root output.csv and code/evaluation reports when those later milestones are implemented.

## Shared typed records

Use frozen dataclasses (or equivalent immutable records) and UTC-aware datetime values:

- CaseRequest: case_id, supplied_email, requested_at, reported_status, reported_at, audit_at, request_text.
- EvidenceFile: file_id, normalized relative path, origin, captured_at, format, content hash, extraction status.
- IdentityFact: user_id, identifier_type, exact/normalized value, valid/event time, source reference, provenance.
- ExtractedFact: evidence_ref, system_id, resource_id, category, identifier facts, state fields, event/observation time, capture time, source kind, scope, provenance, parser confidence.
- ActivityEvent: activity_id, event_time, event_type, source_system, target_system, resource_id, reported_result, details, parsed links, claim/effect classification.
- ResourceAssessment: system_id, resource_id, subject user_id, category, state at cutoff (PRESENT/ABSENT/UNKNOWN or treatment state), policy action, supporting/conflicting evidence, coverage and confidence.
- Risk: resource/process key, risk type (flow/restore), active state, selectors/dependencies, supporting evidence.
- PlannedStep and CaseAudit: contract-ready steps plus internal diagnostics that are never serialized.

Evidence references retain a typed kind and ID (file_id/activity_id/audit_id). Every extracted fact records its exact source path, file_id, record/table/line/page/region locator, source timestamp and extraction method. Missing times remain unknown; never substitute file mtime or the current clock.

## Request intent boundary

Request-language interpretation is a separate deterministic stage from final status classification. `IntentResult` contains `DELETE`, `OTHER`, or internal `AMBIGUOUS`, detected action spans/language where supported, rationale, and provenance. It consumes only `CaseRequest.request_text`; it does not inspect evidence or assign an output status. Explicit access, correction, export, and marketing opt-out requests are `OTHER` under AGENTS.md §6.5. Negation and multi-action scope must be represented explicitly. The instructions do not define precedence for mixed-action requests. **REASONABLE DESIGN CHOICE:** treat a clear, independent, explicit deletion clause as authorizing deletion while recording companion actions separately; if scope is shared, contradictory, or otherwise materially ambiguous, leave intent unresolved. A marketing-only removal is a non-deletion request under §6.5. Unsupported language or ambiguity is not guessed. `AMBIGUOUS` is never serialized. Synthetic unit cases cover deletion, access, correction, export, opt-out, multilingual, ambiguous, negated, and multi-action wording. A deterministic parser is preferred; an optional interpreter may suggest an intent with exact text-span provenance and confidence, but the final result is validated and policy/status decisions remain deterministic.

## Components

### 1. Dataset ingestion and schema validation

- Responsibilities: load the 518 evaluation requests and supporting CSVs; validate exact headers, row counts/keys, enums, timestamp syntax, duplicate IDs and nulls; preserve UTF-8 text. Report errors with file and row/column.
- Inputs/outputs: dataset/*.csv -> DatasetBundle of CaseRequest, identity/audit/activity/rule/manifest rows and template header.
- Sources: deletion_requests.csv, sample_deletion_requests.csv, sample_output.csv, user_identities.csv, user_audit_log.csv, system_activity.csv, deletion_rules.csv, evidence_files.csv, output.csv.
- Structures: DatasetBundle; ParsedTimestamp(value or None, error); validation diagnostics keyed by path/row.
- Failures: malformed CSV/UTF-8, extra/missing columns, duplicate case_id/activity_id/audit_id, invalid enum/time, empty required fields. Fail closed before auditing; do not silently drop a row.
- Unit tests: headers/counts; quoted commas/newlines; malformed row; duplicate IDs; ISO UTC and invalid timestamps; blank template header; one-row sample fixture.
- Dependencies: foundational; all components consume validated bundle.

### 2. Evidence manifest processing

- Responsibilities: normalize relative paths safely; verify each file exists under dataset/evidence; reject traversal, duplicates and unsupported extensions; verify all 94 files and no unmanifested files; index file_id, origin, captured_at and format.
- Inputs/outputs: manifest rows plus filesystem inventory -> EvidenceFileIndex.
- Sources: evidence_files.csv and every path under dataset/evidence/.
- Structures: map file_id -> EvidenceFile; map path -> file_id; captured-time ordered index.
- Failures: missing/duplicate files, path escape, bad timestamp, manifest/file mismatch. Mark evidence coverage incomplete; never infer case membership from manifest metadata.
- Unit tests: all 94 manifest paths resolve; duplicate/missing/extra file; path traversal rejection; capture-time sort; unknown extension handling.
- Dependencies: ingestion; gates evidence extraction.

### 3. Evidence extraction and normalization

- Responsibilities: parse formats into neutral ExtractedFact records without making policy decisions. CSV/JSON with stdlib; SQL snapshots in isolated in-memory sqlite3, comparing declared primary/replica tables; logs as UTF-8 line/key-value/JSON events; PDF text through an adapter; PNG through OCR/vision adapter. Preserve the original claim and parsed fields separately.
- Inputs/outputs: EvidenceFile -> zero or more ExtractedFact plus extraction diagnostics and coverage statement.
- Sources: 24 SQL, 28 JSON, 26 log, 4 PDF, 11 PNG and 1 TXT under evidence/. Actual collections include customer profiles, search, analytics, support, exports, connectors, security, backup, retained orders and operational history.
- Structures: EvidenceRecord(locator, raw_fields, normalized_fields); ExtractedFact; `FileExtractionResult(file_id, parser, complete/partial/failed, discovered_scope, locators, warnings, errors)`; and a separate `CaseEvidenceCoverage(case_id, candidate_file_ids, examined_file_ids, eligible_fact_ids, required_scopes, material_gaps, conflicts)`. Identifier namespaces remain typed; resource_id is always paired with system_id. File parsing state is never a proxy for per-case coverage.
- Failures: malformed JSON/SQL, unsupported SQL function, PDF without text, OCR ambiguity, truncated logs, unknown schema, missing timestamps, parser conflict. Keep partial results and file-scoped coverage. Do not deem a failed file irrelevant from manifest origin/path/capture time alone; only exclude it from a case when independent parsed scope establishes irrelevance. A failed plausible candidate file creates a material case-coverage gap. Never convert parse failure into absence.
- Unit tests: fixtures for each observed shape; replica divergence; escaped JSON-in-SQL; nested snapshots; key/value and structured logs; PDF text spans; OCR boxes/regions; per-file partial/failed outcomes; unrelated extracted decoy vs failed plausible candidate; separate per-case coverage aggregation and provenance retention.
- Dependencies: manifest and ingestion; feeds identity, timeline and state reconstruction.

### 4. Historical identity resolution

- Responsibilities: resolve request email to one stable user_id; reconstruct eligible current/historical email, email_hash and phone aliases using update/event times; retain provenance and avoid fuzzy joins.
- Inputs/outputs: CaseRequest, user_identities, user_audit_log -> IdentityGraph and case-scoped IdentitySet.
- Sources: deletion_requests.csv, user_identities.csv, user_audit_log.csv; corroborating IDs in evidence.
- Structures: IdentifierKey(type, comparison_value); IdentityEdge(user_id, value, valid interval, source ref); IdentityResolution(unique/unmatched/ambiguous).
- Failures: multiple users share identifier, identity snapshot postdates cutoff, out-of-order/conflicting history, unlinked resource. Surface ambiguity; do not join by name or guess hash algorithms. Apply email trim/casefold only; use exact stored hash and phone unless format-equivalence is explicitly evidenced.
- Unit tests: current and old-email matches; before/after email change cutoff; hash-only evidence; email case variation; conflicting aliases; ambiguous and unmatched IDs; no fuzzy name match.
- Dependencies: ingestion; adds identity links to extracted facts before timeline/resource analysis.

### 5. Event timeline reconstruction

- Responsibilities: build per-case, per-resource chronological events from system_activity, operational histories, logs and snapshot facts. Separate observed state from workflow/operation claims; retain conflicts rather than flattening them.
- Inputs/outputs: IdentitySet, ExtractedFacts, ActivityEvents -> ResourceTimeline keyed by (system_id, resource_id).
- Sources: system_activity.csv; JSON operational_record_history; service-resource exports; SQL snapshot tables; logs and documents where event times are explicit.
- Structures: TimelineEntry(time, event/evidence ref, claimed effect, observed fields, source quality, cutoff eligibility); deterministic tie groups.
- Failures: missing/out-of-order timestamps, duplicate actions, contradictory success/failure, events that mention an identity but no resource link. Preserve both sides and record unresolved conflict; do not use reported_result as state.
- Unit tests: chronological ordering; equal timestamp stable order; contradictory event retention; failed delete does not imply absence; unrelated event exclusion; missing-time handling.
- Dependencies: extraction and identity; consumed by resource-state and risk components.

**Phase 5 implementation:** `timeline.py` creates immutable `TimelineEvent` entries and keeps source format, raw fields, event timestamp and manifest capture timestamp separate. Cutoff queries require a valid event timestamp at or before `audit_at`; manifest-backed evidence additionally requires valid `captured_at` at or before the cutoff. Unplaced observations and file extraction gaps remain on the timeline. `system_activity.csv` is represented as unlinked activity claims because Phase 4 does not resolve activity rows to users; no state is assigned to those claims.

### 6. Resource-state reconstruction at audit_at

- Responsibilities: determine each relevant resource's best-supported state at the case cutoff; filter both manifest captured_at and internal observation/event timestamps; compare primary/read/regional/reporting/failover copies and coverage.
- Inputs/outputs: ResourceTimeline, IdentitySet, audit_at -> ResourceAssessment set with PRESENT/ABSENT/UNKNOWN and evidence basis.
- Sources: SQL snapshots/readbacks, JSON bundles/exports, direct support/security/analytics records, screenshots, timestamped logs, system_activity only as claims.
- Structures: StateObservation(time, state, completeness scope, source kind, evidence ref); ResourceAssessment with conflicts and coverage.
- Failures: evidence captured after cutoff; internal state time after cutoff; stale snapshot; incomplete query scope; conflicting direct observations; absence without exhaustive coverage. Exclude future facts; return UNKNOWN if no defensible resolution. No later evidence can repair an earlier cutoff.
- Unit tests: manifest and inner timestamp cutoff separately; inclusive audit_at boundary; post-cutoff evidence ignored; primary/replica drift; no-result with narrow scope -> UNKNOWN; exact resource/system isolation.
- Dependencies: identity, extraction and timeline; feeds policy/status.

**Phase 6 implementation:** `state.py` returns per-cutoff `StateSnapshot`s and one case-scoped snapshot for every request whose Phase 4 subject is confirmed. Resources are keyed by user, system tuple, resource ID and available record/resource type; when system scope is absent, source-observation scope is retained to prevent global resource-ID joins. Control state has a separate domain. Only direct SQL/JSON resource-shaped observations can establish a lifecycle state; structured event payloads, logs, PDFs, workflow/activity results and unlinked claims remain claims or uncertainty. A direct SQL/JSON snapshot is timed at its manifest capture time, while its inner event timestamp remains independently required to be eligible when present. If the latest snapshot predates `audit_at`, the cutoff state is `UNKNOWN` and `last_observed_state` preserves the earlier observation; no freshness interval or event-stream completeness is assumed. A missing query result yields `UNKNOWN`, never `ABSENT`. An unplaced direct SQL/JSON row may establish presence at its valid manifest capture time without inventing an inner event timestamp. Extraction gaps, unplaced observations, unlinked events and eligible timeline conflicts are carried forward explicitly.
### 7. Deletion policy evaluation

- Responsibilities: evaluate each attributable resource against the actual 15 rows in deletion_rules.csv and its condition; choose DELETE, REDACT, ANONYMIZE or RETAIN. Keep findings separate from actions.
- Inputs/outputs: relevant ResourceAssessments and policy rows -> PolicyDecision(resource, required_action, compliance, reason, evidence refs).
- Sources: deletion_rules.csv plus the evidence fields that establish category/condition. Do not infer categories from a resource name alone.
- Structures: PolicyRule and typed ConditionResult(true/false/unknown); PolicyDecision.
- Failures: unknown category/condition, insufficient record context, overlapping rules or unsupported condition. Do not silently default to DELETE; report unresolved decision internally and stop COMPLETE classification.
- Unit tests: all 15 categories/actions; support shared-context vs subject-only; identifiable vs anonymized analytics; email-containing log; retention predicate; unknown condition.
- Dependencies: resource-state reconstruction and extracted facts; consumed by retention, status and planners.

**Phase 7 implementation:** `policy.py` loads the actual `deletion_rules.csv` rows into typed `PolicyRule`s and evaluates them per confirmed request subject against Phase 6's cutoff-filtered assessments and the linked extracted observations. A rule condition produces `SATISFIED`, `NOT_SATISFIED`, `UNKNOWN`, or `CONFLICTING`; each decision retains the rule row, action, resource/system key, observed lifecycle/control states, and evidence references separately. The evaluator does not classify request intent, resource compliance, case status, or remediation; obligations are explicitly conditional on deletion authorization. SQL nested-record categories use the observed parent `collection_name` mappings from the participant-visible snapshots. Query-result payloads are excluded from condition truth. `retention_until` is compared with `audit_at`, never treated as proof of current retention; equality is unresolved because the supplied contract does not specify endpoint inclusion. Unsupported condition text and conflicting applicable actions remain unresolved/conflicting.

### 8. Retention and tombstone validation

- Responsibilities: validate policy-required records remain, required retention/hold is evidenced, archives are retained with restore access blocked, and account tombstones keep only allowed user_id while direct identifiers are absent.
- Inputs/outputs: PolicyDecisions, ResourceAssessments, IdentitySet -> RetentionAssessment and TombstoneAssessment.
- Sources: rules 12-15; security records/retention_until; legal_retention_register PDF; security_retention_extract PDF; backup catalogs/restore console; deleted-account references; customer account SQL/JSON snapshots.
- Structures: RetentionRequirement(category, expires_at/hold evidence); TombstoneCheck(stable_ref_present, forbidden_fields_present); permitted field allowlist containing user_id only for rule_15.
- Failures: missing expiration, hold not actually active, retained record absent, backup access state unknown, tombstone still identifying, or stable reference absent. Never invent a retention duration or delete protected records.
- Unit tests: within/after retention window; unsupported hold ignored; archive present and blocked vs restore allowed; tombstone with only user_id; tombstone with email/hash/phone; missing stable reference.
- Dependencies: policy and state; required by status, remediation and verification planning.

### 9. Recreation-risk detection

- Responsibilities: find active flows/imports/replication selectors matching any eligible subject ID, and restorable archives or evidenced restore jobs that can reintroduce prohibited data. Distinguish past events from current active configuration.
- Inputs/outputs: IdentitySet, ResourceTimelines, extracted connector/backup records -> Risk list with active state, dependency edges and evidence refs.
- Sources: connector_configurations JSON, SQL connector/backup tables, backup console, primary/replica snapshots, system_activity, service logs and handover.
- Structures: DataFlow(resource, selector, destination, enabled, mode); RestorePath(backup, restore_allowed, block state); DependencyGraph.
- Failures: selector only partially matches; config time after cutoff; conflicting enabled flags; no current status; backup contents/restore scope unclear. Do not label historical sync as active risk without current evidence.
- Unit tests: current email and historical email selector; user_id selector; disabled flow; flow config after cutoff; enabled conflict -> unknown; blocked restore; recent successful restore followed by direct remaining record.
- Dependencies: identity, extraction and timeline; gates COMPLETE and orders remediation.

#### Phase 8 implementation boundary

`audit_agent.risks.analyze_recreation_risks(identities, timeline, extraction, case_states, policy=None)` consumes the completed Phase 4-7 records. It returns immutable `RiskAnalysis` / `RiskCaseResult` objects; findings retain typed resource scope, evidence references, event/capture times, mechanism, confidence and evidence status. It does not write files or produce final deletion status.

- A resource is matched by confirmed `user_id`, system scope, resource ID, and resource type/discriminator when available. An unlinked system-activity row can be attached only as a low-confidence claim when its resource ID and system scope match exactly one confirmed resource in that case; resource ID alone is never sufficient.
- `OBSERVED_RECREATION` requires a temporally eligible creation/restoration/replication/synchronization/import observation plus linked direct SQL/JSON state evidence supporting presence. A later direct present snapshot after a direct deletion snapshot is separately surfaced as `RESOURCE_PRESENT_AFTER_DELETE`; a snapshot's capture time does not imply persistence to a later cutoff.
- A currently active, directly observed data-flow selector that resolves uniquely to a current or historically valid subject identifier is a `POSSIBLE_DATA_FLOW_RECREATION`. An active backup with explicit `restore_allowed=true` is a `POSSIBLE_RESTORE`. These are control-state risks, not proof that data was restored. Selector ambiguity or missing values stay uncertainties.
- Applicable DELETE/REDACT/ANONYMIZE/RETAIN decisions are compared with lifecycle state independently from control state. Conflicts are findings only when direct eligible evidence supports the contradictory state; unknown or conflicting state remains uncertainty.
- The result preserves extraction gaps, unresolved identity candidates, temporal exclusions, and scoped timeline conflicts. Global extraction gaps are reported as uncertainty and are not presumed material to every case. Confidence labels express the strength of this evidence rule, not a probability.

Failure cases include unconfirmed subjects, missing timestamps/capture times, post-cutoff evidence, resource-type/scope mismatch, ambiguous selectors, stale state snapshots, conflicting state/event claims, and incomplete extraction. Synthetic tests cover delete-then-recreate, restore/replication/import, active flow/backup controls, cross-system ID collision, inclusive cutoff and late capture, stale state, conflicts, claim-only activity, and insufficient identity support. The actual evidence pass must separately report these gaps; no risk finding is itself a final classification or remediation order.

### 10. Three-way status classification

- Responsibilities: classify NOT_APPLICABLE when deletion is not authorized; COMPLETE only when every required state, retained record and risk check is proven compliant at audit_at; otherwise INCOMPLETE for authorized deletion.
- Inputs/outputs: AuthorizationResult, PolicyDecisions, RetentionAssessment, Risk list and evidence coverage -> CaseClassification.
- Sources: request_text plus components 4-9.
- Structures: separately produced IntentResult(DELETE/OTHER/AMBIGUOUS); `CaseClassification(status, reasons, unresolved gates)` where serialized status is restricted to the three official values. Internal unresolved gates are not output enums.
- Failures: ambiguous request intent, unknown state/coverage, or material unresolved conflict. Enforce three separate invariants: (1) UNKNOWN never establishes COMPLETE; (2) a material unresolved conflict blocks unsupported classification and serialization; (3) final submission uses only the official status set and represents every case. There is no serialized UNKNOWN/BLOCKED status and no silently omitted case. **REASONABLE FAIL-CLOSED DESIGN CHOICE:** if any case cannot be resolved, fail the whole output run atomically with case IDs and diagnostics and write no partial submission. The contract requires a row for every case but does not specify partial-file behavior on an internal audit failure. When resolved, non-authorized -> NOT_APPLICABLE with no steps; authorized with a supported violation/risk -> INCOMPLETE; authorized with complete proof -> COMPLETE.
- Unit tests: intent matrix isolated from status; fixed intent plus clean proof -> COMPLETE; supported violation -> INCOMPLETE; OTHER -> NOT_APPLICABLE with []; UNKNOWN never becomes COMPLETE; material conflict blocks classification/serialization; all-case atomic output gate refuses partial rows and invents no status.
- Dependencies: request intent and components 4-9; selects which planner path runs.

#### Phase 9 implementation boundary

`audit_agent.adjudication.classify_request_intent` reads only the request text and returns a typed `RequestIntent` with action mentions, polarity, character spans, matched rule IDs, and `deletion_authorized` (`true`, `false`, or unresolved). The deterministic patterns cover English, Spanish, French, Japanese, Portuguese and Korean wording found in the participant-visible request corpus, explicit access/export, correction, marketing opt-out, negation, hedged requests, and an explicit vague-intent bucket. It does not consult `reported_status`, identity, or evidence. Unsupported text and contradictory deletion polarity remain ambiguous. Multiple independent actions are retained as `MULTI_ACTION`; a clear deletion plus a companion action is treated as authorized as a conservative, previously documented design choice, while same-scope contradictory instructions are unresolved.

`adjudicate_cases(ingestion, identities, extraction, case_states, policy, risks)` returns an `AdjudicationReport` with one result per ingested request. `DeletionStatus` contains only the three official output values; `CaseAdjudication.deletion_status=None` is an internal unresolved proposal, never a fourth status. Each result retains reasons, source references, the intent decision, and unresolved reason codes. Explicit non-deletion intents become `NOT_APPLICABLE` without requiring a subject match. A directly evidenced policy violation or scoped active flow/restore risk supports `INCOMPLETE`; claim-only operation results do not. `COMPLETE` requires confirmed identity, conclusive evaluated policy obligations, direct state evidence for their expected treatments, and no unresolved risk gates. Conflicting policy obligations do not themselves prove a violation.

Phase 3/8 extraction failures remain in global diagnostics. A failed file is attached to a case only when cutoff-eligible evidence for that confirmed subject explicitly references its `file_id` or full manifest path; unlinked files remain globally visible and are not presumed irrelevant, but do not become material uncertainty for every case. A linked extraction gap cannot establish `INCOMPLETE`, and its unknown contents prevent unsupported `COMPLETE`; a separate supported violation may establish `INCOMPLETE` while the linked gap remains an unresolved planning gate. Tombstone redaction is considered proven only when a direct eligible observation preserves the subject's stable `user_id` and exposes no non-empty recognized direct-identifier fields. This phase does not plan output steps or write `output.csv`.

### 11. Ordered remediation planning

- Responsibilities: produce a complete, minimal, evidence-grounded plan for confirmed violations. Do not plan deletion for RETAIN/REDACT/ANONYMIZE records.
- Inputs/outputs: INCOMPLETE classification, policy decisions, risks and resource dependency graph -> ordered RemediationActions.
- Sources: policy, state, connector/backup evidence, replica relationships.
- Structures: Action(resource, operation, state, policy rule); dependency DAG; deterministic topological sort constrained by the official operation/system/resource ordering. Build the precedence constraints together and validate that they are jointly satisfiable.
- Ordering: satisfy both explicit dependency constraints (disable flows/block unsafe restores before dependent record changes; downstream copies before source where required) and the exact serialized operation order in problem_statement.md, then system_id/resource_id ascending within each operation. The sample confirms operation ordering for its steps. If dependency and contract ordering constraints form a cycle, fail with a planning diagnostic; do not silently violate either constraint or invent a different contract. **REASONABLE FAIL-CLOSED DESIGN CHOICE:** this conflict behavior is not specified by the challenge; it preserves both written requirements pending clarification.
- Failures: cycle in dependency/order constraints, missing resource key, unknown action, unsupported target. Surface an internal planning error rather than silently reordering or inventing steps.
- Unit tests: flow and restore controls first; downstream before source; deterministic ties; no DELETE for retained order/security/tombstone; REDACT vs ANONYMIZE; cycle detection.
- Dependencies: classification, policy, retention/tombstone and risk detection.

### 12. Verification planning

- Responsibilities: cover final required state for every remediation and exception. COMPLETE uses only evidence-backed checks; INCOMPLETE describes post-remediation checks with empty evidence_id.
- Inputs/outputs: classification, decisions, actions, retained-record checks and risks -> VerificationChecks.
- Sources: same evidence supporting current compliance and the plan's target states.
- Structures: VerificationCheck(resource, operation/state, evidence ref, dependency key, future flag).
- Ordering: all verification occurs after remediation. Require flow-disabled and restore-blocked checks to pass before accepting dependent resource checks as sufficient for COMPLETE. For serialized array order, use the contract verification-operation order, then system_id/resource_id; keep dependency relationships in the check graph and do not reorder operation classes contrary to contract. COMPLETE emits verification phase only and cites current pre-cutoff proof.
- Failures: no proof for COMPLETE, incomplete remediation coverage, current/future citation mix-up, missing verification for a changed record/process. Block classification/output if completeness cannot be demonstrated.
- Unit tests: cover every required final-state predicate for each planned resource/process (one or more checks may be needed); retained record VERIFY_RECORD_PRESENT; tombstone redaction; anonymization; flow/restore checks; evidence IDs vs empty strings; stable ordering.
- Dependencies: remediation plan, resource state, policy and risk components.

### 13. Final output generation and validation

- Responsibilities: serialize exact contract rows, validate all cases and steps, and atomically write repository-root output.csv only after every case is resolved.
- Inputs/outputs: CaseAudit results -> CSV with exact header case_id,deletion_status,steps_json.
- Sources: deletion_requests.csv and components 10-12. Dataset/output.csv is a header-only reference, not the destination.
- Structures: Step with exactly step_no, phase, system_id, resource_id, operation, state, evidence_id; OutputRow; JSON array stored as one CSV field.
- Failures: duplicate/missing case, extra row, invalid JSON, wrong field set/header/status, invalid phase/operation/state triple, nonconsecutive step numbers, wrong phase/operation/system/resource ordering, bad or temporally ineligible evidence reference, incomplete remediation/verification coverage, nonempty future evidence_id, or an unresolved case. Validate all 518 cases before writing; atomically refuse the entire write and report all affected case IDs rather than producing partial output or an invented status.
- Unit tests: exact contract vs participant docs and public sample; UTF-8 CSV/JSON quoting and round trip; 518 exact cases; sorted case_id; NOT_APPLICABLE []; exact seven-key step shape; all allowed triples; consecutive numbering; phase/operation/system/resource order; dependency feasibility; evidence ID existence/type/time eligibility; empty future evidence IDs; all-or-nothing unresolved-case refusal.
- Dependencies: all prior components; final gate.

### 14. Evaluation and usage reporting

- Responsibilities: compare public sample predictions with sample_output.csv; calculate status, field, evidence-reference, and ordered-sequence metrics separately with explicit numerators/denominators; store at least three authored cases, failures and improvements. Record actual model calls/tokens/cost for the final 518-case run.
- Inputs/outputs: output rows, public sample labels, custom test fixtures, run ledger -> code/evaluation/evaluation_report.md and usage_report.md.
- Sources: sample_deletion_requests.csv, sample_output.csv, authored tests, model provider response usage metadata. Never read hidden organizer labels.
- Structures: `EvaluationResult` with independent status counts, positional field-slot counts, evidence-reference-slot counts, and exact ordered-array case counts; each has an explicit denominator and unavailable zero-denominator state. `UsageLedger(provider, model, calls, input/output tokens, cost)` remains separate.
- Failures: duplicate sample keys, metric denominator drift, absent token metadata, guessed pricing/cost, report not matching final output. State unavailable metrics explicitly; do not fabricate hidden accuracy.
- Unit tests: exact sample join; independent synthetic prediction fixtures with hand-known metric values; status/field/evidence-reference/sequence denominator checks; order-sensitive sequence; missing/extra step accounting; zero denominator; token aggregation and average per 518 requests; missing usage metadata remains unknown.
- Dependencies: output validation and run instrumentation; reports are submission artifacts, not prediction inputs.

## Output contract reference

Output validation is derived from AGENTS.md §6.3–6.6, README.md, problem_statement.md, and dataset/sample_output.csv. Contract: header exactly `case_id,deletion_status,steps_json`; 518 case-sorted rows; status exactly `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`; NOT_APPLICABLE uses `[]`; each step has exactly seven documented fields; phases FINDING/REMEDIATION/VERIFICATION; only the documented operation/state triples; consecutive `step_no`; evidence IDs are participant-visible file_id/activity_id/audit_id; findings and COMPLETE checks have existing eligible references, while proposed remediation and future checks use `""`. Serialized arrays obey phase order and, inside each phase, the problem statement operation order followed by system_id/resource_id ascending. The inspected public sample has 32 sorted rows (10 COMPLETE, 22 INCOMPLETE), all 15 allowed triples represented, exact step keys/numbering, and 75 populated references that resolve and are no later than each sample `audit_at`; it does not demonstrate NOT_APPLICABLE. Synthetic tests cover that contract branch without inventing sample labels. Never infer new enum values from internal data models.

## Unstructured interpretation boundary

The initial system should use deterministic parsers for CSV/JSON/SQL/logs and PDF text. Screenshots need OCR; add an OCR adapter before considering an LLM. If OCR or multilingual request interpretation remains materially inaccurate on held-out participant-facing examples, isolate optional use behind an interface such as EvidenceInterpreter.extract(image_or_text, context) -> CandidateFact[] and IntentInterpreter.classify(request_text) -> CandidateIntent. Require strict JSON schema, source file/page/region or exact text-span provenance, known identifier/resource validation, timestamp cutoff validation, confidence threshold and deterministic policy re-evaluation. Low-confidence or unsupported results become unresolved diagnostics, never facts. Do not send an LLM the whole dataset when targeted evidence suffices; track provider/model/calls/tokens/cost. The LLM may suggest extraction/intent only; it cannot select policy actions, override temporal logic, classify final status, or create remediation steps.

## Dependency graph

Ingestion -> manifest -> extraction -> identity resolution -> timeline -> resource state -> policy -> retention/tombstone and recreation risk -> classification -> remediation -> verification -> output validation. Evaluation/usage reporting consumes validated outputs and run telemetry, never hidden labels. Classification and output are blocked by unresolved identity, intent, timestamp, coverage or policy conflicts.
