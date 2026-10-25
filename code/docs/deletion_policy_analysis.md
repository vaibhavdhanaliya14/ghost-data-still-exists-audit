# Deletion Policy Analysis

## Supplied rule matrix

| Rule | Category | Condition in deletion_rules.csv | Action | Audit treatment |
|---|---|---|---|---|
| rule_01 | USER_PROFILE | Always | DELETE | No profile should remain. |
| rule_02 | SECONDARY_IDENTIFIER | Always | DELETE | Remove standalone identifiers/stale aliases represented as resources. |
| rule_03 | SEARCH_INDEX_ENTRY | Always | DELETE | Remove every attributable index entry, including copies. |
| rule_04 | CACHE_ENTRY | Always | DELETE | Remove attributable cache entries. |
| rule_05 | SUPPORT_MESSAGE | Conversation contains shared customer, agent, or order context that must be retained | REDACT | Preserve shared context and remove prohibited subject identifiers. |
| rule_06 | SUPPORT_ATTACHMENT | Attachment belongs only to the deletion subject | DELETE | Delete subject-only attachments; establish ownership from evidence. |
| rule_07 | ANALYTICS_PROFILE | Record is still attributable to a user | ANONYMIZE | Keep only after irreversible unlinking. |
| rule_08 | PRODUCT_TELEMETRY | Record is still attributable to a user | ANONYMIZE | Apply same attribution test to telemetry. |
| rule_09 | USER_EXPORT | Always | DELETE | Delete export record/artifact. |
| rule_10 | MARKETING_PROFILE | Always | DELETE | Remove the profile on authorized deletion. |
| rule_11 | EMAIL_DELIVERY_LOG | Log contains a user email address | REDACT | Remove email while keeping applicable log context. |
| rule_12 | SECURITY_AUDIT_LOG | Record is within the supplied retention period | RETAIN | Use record-specific retention evidence; no universal duration is defined. |
| rule_13 | LEGAL_HOLD_RECORD | A supplied legal hold is active | RETAIN | Preserve only when an active supplied hold is evidenced. |
| rule_14 | BACKUP_ARCHIVE | Restore access can be blocked | RETAIN | Keep archive and block restore access. |
| rule_15 | ACCOUNT_TOMBSTONE | Account is deleted and only a stable internal user_id is needed to preserve references to retained records | REDACT | Preserve user_id only; remove name, email, phone, email_hash and other direct identifiers. |

## Policy and state implications

- First determine whether request_text authorizes deletion. Access, correction, export, marketing opt-out and other requests are NOT_APPLICABLE even if workflow fields resemble deletion.
- Complete means every in-scope copy has the required treatment, required retained records remain, and no active sync/import or restorable backup can recreate prohibited data.
- Tombstones retain stable user_id when needed for permitted references; direct identifiers must be redacted. Deleting the tombstone can break allowed references.
- Shared support conversations differ from subject-only attachments: redact retained conversation context; delete a subject-only attachment.
- Analytics and telemetry can remain only after irreversible unlinking. Dropping email while keeping a direct user link does not anonymize an attributable record.
- An archive is compliant only when restore access can be blocked and is blocked. Block restore paths before dependent record changes.
- Security retention and legal hold are separate exceptions. Establish each record's retention/hold state from evidence. Retention does not waive identifier-redaction rules.

## Temporal, event and dependency rules

1. Treat audit_at as the evidence cutoff. Exclude files captured after it and records/events created or observed after it.
2. Workflow status, activity reported_result and log messages are assertions. Establish state from the strongest available participant-visible readback, SQL row, screenshot/document or corroborated history.
3. Distinguish primary from reporting/read/failover replicas. A source delete does not imply replica convergence. Sync/import or restore can recreate a copy.
4. For incomplete cases, cite findings, then disable applicable flows and block unsafe restores before dependent mutations. Process downstream copies before a source where dependency requires. Apply policy action and verify every affected resource/process.
5. Complete cases contain only evidence-backed VERIFICATION steps. Cover retained records, redaction/anonymization, and flow/restore state as needed.
6. Proposed remediation and future verification use empty evidence_id. Do not invent evidence or contract values.

## Supplied-policy limits

The rules do not define a universal retention length, legal-hold duration, hash function, proof standard for anonymization, or automatic proof that an empty lookup means global absence. Resolve these from participant-visible record-level evidence. The activity stream and evidence contain unrelated subjects and decoys.