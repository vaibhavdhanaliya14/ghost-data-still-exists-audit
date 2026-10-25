# Identity Resolution Analysis

## Available identity evidence

| Source | Shape | Identifier/time fields | Observed scope |
|---|---|---|---|
| user_identities.csv | 850 current rows | user_id, name, email, phone, email_hash, updated_at | user_id unique; current email/phone/hash each unique. updated_at spans 2023-06-22 to 2026-08-30 UTC. |
| user_audit_log.csv | 306 changes across 196 users | audit_id, user_id, event_time, field_name, old_value, new_value | 107 email, 107 email_hash, 92 phone changes. event_time spans 2024-12-14 to 2026-06-03 UTC. No name changes. |
| deletion_requests.csv | 518 cases | supplied email, requested_at, audit_at, request_text | Each email maps to exactly one user across current/historical email values after case-insensitive normalization; 100 use a historical email. |
| Evidence/activity | Global mixed records | user_id/customer_reference/subject_reference; email/phone/email_hash; resource IDs and event/capture times | Connects subjects to resources, but includes unrelated subjects and decoys. |

The 32 public sample request emails also map uniquely; three use a historical email. These are dataset observations, not hardcoded shortcuts.

## Recommended identity graph

1. Normalize email by trimming surrounding whitespace and case-folding. Preserve the supplied value for traceability. Do not fuzzy-match email or name.
2. Resolve against current email and email audit old_value/new_value entries. Record user_id and current/historical match. If multiple users match, surface ambiguity; the inspected dataset has no cross-user email collisions.
3. Build an audit_at-specific identity set. Include the request email as submitted, identity data available by the cutoff, and only audit events with event_time <= audit_at. Respect per-user updated_at; a later snapshot value is not proof of earlier state.
4. Starting from user_id, collect email/hash/phone values from eligible history in event order and the applicable snapshot. Match evidence by exact stored value and stable reference. Do not infer a hash algorithm.
5. Expand to resources only after grounding the subject. Keep resource IDs distinct from user IDs, and require a subject/resource link rather than a bare email substring.
6. Preserve provenance for each alias: source row/file, field, event/update timestamp and cutoff eligibility.

## Ambiguities and failure modes

- The current snapshot can postdate early audit_at values. Do not project a later address backward without evidence.
- Audit history records email, email_hash and phone, but not name. Names are corroborating identifiers, not primary joins.
- Hashes are opaque. Match exact; do not reverse or recompute. Do not apply email normalization to hashes or phone values.
- Old identifiers can remain in search, logs, support, exports and connector selectors. Search all eligible aliases.
- A resource may have stable user_id and direct identifiers together. user_id may remain only in permitted tombstone/reference records; email/hash/phone can still violate policy.
- Global logs and artifacts include decoys. Establish a graph edge to the subject before including a record.
- Repeated request emails remain separate cases. Preserve each unique case_id.