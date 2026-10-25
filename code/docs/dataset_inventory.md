# Dataset Inventory

## Scope and inspection

Inspected participant-accessible instructions, participant documents, all files under dataset/, and starter files under code/. Dataset contains 9 CSV files and 94 evidence files (103 total). Every manifest path exists; none are missing or unmanifested. CSVs have no declared physical types, so types below are inferred from values. Timestamps are ISO-8601 UTC strings. No dataset file was changed.

dataset/output.csv contains only the header case_id,deletion_status,steps_json. code/main.py is empty; code/evaluation/main.py has no usable implementation. CLAUDE.md points to AGENTS.md. No nested AGENTS.md exists.

## CSV schemas and relationships

| File | Rows | Actual columns and inferred types | Keys, timestamps, relationships, ambiguities |
|---|---:|---|---|
| deletion_requests.csv | 518 | case_id string; email string; requested_at timestamp string; reported_status string; reported_at timestamp string; audit_at timestamp string; request_text string | case_id unique. 517 distinct emails and 375 distinct request_text values; cases remain separate. reported_status is COMPLETE, PARTIALLY_COMPLETE or NOT_STARTED. Request dates span Jan 5-Sep 24 2026; audit_at spans Jan 29-Oct 1 2026. Email may be current or historic. |
| sample_deletion_requests.csv | 32 | Same seven columns/types as deletion_requests.csv | Unique case_id and email in this sample. Includes multilingual text. |
| sample_output.csv | 32 | case_id string; deletion_status string; steps_json JSON-encoded array string | Joins to sample requests; demonstrates serialization, phases, operations, evidence and ordering. Has COMPLETE and INCOMPLETE, no NOT_APPLICABLE example. |
| user_identities.csv | 850 | user_id, name, email, phone, email_hash strings; updated_at timestamp string | user_id unique. Current email, phone and email_hash each unique. updated_at is per user, not a common snapshot time. |
| user_audit_log.csv | 306 | audit_id, user_id, field_name, old_value, new_value strings; event_time timestamp string | audit_id unique; 196 distinct user_ids. field_name: email (107), email_hash (107), phone (92). No name changes. |
| system_activity.csv | 4,011 | activity_id string; event_time timestamp string; event_type, source_system, target_system, resource_id, reported_result, details strings | activity_id and event_time unique; resource_id has 3,948 distinct values, so not a unique event key. 33 source/target pairs. Events span Jan 4-Oct 1 2026. details is free text; operation results are claims. |
| deletion_rules.csv | 15 | rule_id, data_category, condition, required_action strings | rule_id unique; 15 rule rows and four actions: DELETE, REDACT, ANONYMIZE, RETAIN. Apply each condition to record context. |
| evidence_files.csv | 94 | file_id, file_path, origin strings; captured_at timestamp string | file_id and file_path unique; 30 origins. Joins file_id to evidence references and file_path to files. Does not assign evidence to a case/user. Captures span Jan 29-Oct 1 2026. |
| output.csv | 0 data rows | Header: case_id,deletion_status,steps_json | Header-only template. Final output belongs at repository root. |

## Dataset relationships

- All 518 evaluation request emails map to exactly one user across current and historical email values after case-insensitive normalization; 100 use historical email. No cross-user email alias collision was found.
- Identity sources connect email, email_hash and phone to stable user_id. Evidence connects identifiers to resource_id, system/collection, event history and capture time. The manifest is a locator only.
- system_activity is global, includes unrelated resources and decoys, and cannot be joined to a person by resource_id alone.
- Evidence overlaps across snapshots and formats. Later captures can show a later state and cannot answer an earlier audit_at.

## Ambiguities and risks

1. Classify request_text before auditing. Access, correction, export, marketing opt-out and other non-deletion actions are NOT_APPLICABLE regardless of workflow status.
2. Identity snapshot values may be later than a case's audit_at. Respect per-row updated_at and filter history by event_time <= audit_at.
3. Hashes are opaque; match exact supplied values rather than assuming a hash algorithm.
4. A resource can occur in multiple systems/snapshots at different states. Corroborate activity with state-bearing readbacks.
5. Empty results are scoped to file/query coverage and time, not proof of global absence.
6. Retention conditions are record-specific. No universal security-retention duration is given; use supplied retention_until, legal-hold and restore-access evidence.