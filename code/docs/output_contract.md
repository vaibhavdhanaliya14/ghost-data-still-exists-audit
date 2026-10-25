# Output Contract and Submission Requirements

## Required root output.csv

Exact header and order: case_id,deletion_status,steps_json. Produce exactly 518 rows, one for every case_id in dataset/deletion_requests.csv, sorted by case_id.

Allowed deletion_status values are COMPLETE, INCOMPLETE, NOT_APPLICABLE. Non-deletion requests use NOT_APPLICABLE and steps_json=[]. steps_json is a valid JSON array. Every step has exactly step_no, phase, system_id, resource_id, operation, state, evidence_id. Number consecutively from 1. Do not add fields, phases, operations or states.

Phases are FINDING, REMEDIATION, VERIFICATION, in that order. COMPLETE rows contain only verification steps. INCOMPLETE rows contain findings, the full ordered remediation plan, and future verification checks. Within phase, follow the problem statement operation order, then system_id/resource_id, except required dependencies: disable flows and block unsafe restores before changing dependent records; process downstream copies before sources when needed.

| Phase | Operation | State |
|---|---|---|
| FINDING | REPORT_REMAINING_RECORD | PRESENT |
| FINDING | REPORT_EXPOSED_PII | PRESENT |
| FINDING | REPORT_ACTIVE_DATA_FLOW | ACTIVE |
| FINDING | REPORT_RESTORE_RISK | ACTIVE |
| REMEDIATION | DISABLE_DATA_FLOW | DISABLED |
| REMEDIATION | BLOCK_RESTORE | BLOCKED |
| REMEDIATION | DELETE_RECORD | ABSENT |
| REMEDIATION | REDACT_RECORD | REDACTED |
| REMEDIATION | ANONYMIZE_RECORD | ANONYMIZED |
| VERIFICATION | VERIFY_RECORD_ABSENT | ABSENT |
| VERIFICATION | VERIFY_RECORD_PRESENT | PRESENT |
| VERIFICATION | VERIFY_RECORD_REDACTED | REDACTED |
| VERIFICATION | VERIFY_RECORD_ANONYMIZED | ANONYMIZED |
| VERIFICATION | VERIFY_DATA_FLOW_DISABLED | DISABLED |
| VERIFICATION | VERIFY_RESTORE_BLOCKED | BLOCKED |

Findings cite participant-visible file_id, activity_id or audit_id that supports them. COMPLETE verification cites evidence proving compliant state at audit_at. INCOMPLETE remediation and future verification describe future work and use empty evidence_id. Never cite later or organizer-only evidence.

sample_output.csv is a format example. Its 32 rows include COMPLETE and INCOMPLETE but no NOT_APPLICABLE case.

## Evaluation artifacts

README.md explicitly places code/evaluation/evaluation_report.md and code/evaluation/usage_report.md in the package. The evaluation report must give case-level status accuracy, step-level and field-level accuracy, sequence accuracy, at least three participant-created cases, failures, and improvements. The usage report covers the final full-dataset run: providers/models, call counts, input/output/total/average tokens per request, estimated total/per-request cost, and per-model plus overall totals when multiple models are used. Details belong in Markdown.

code.zip contains runnable code, prompts/configuration, README and reports; exclude dataset, environments/caches, secrets, real personal data and nested archives. output.csv is a separate root artifact. log.txt is the chat_transcript.

## Trace and interview

agent_trace_instructions.md separately requires agent-trace.zip with relevant traces for every challenge session/harness. Preserve structured logs where practical; stage only relevant session files, inspect the archive, and redact secrets/unrelated private data. It describes Codex rollout JSONL traces and a hosted-session note when there is no local rollout. Keep this ZIP distinct from log.txt.

The submission table also requires a live AI interview explaining architecture, investigation approach, remediation planning and evaluation.