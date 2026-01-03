Description:
Remove obsolete webhook configuration from workflows.

Subtasks:
- [ ] Drop require_hmac, hmac_replay_window_sec, webhook_salt from workflows table
- [ ] Update Workflow Rust model
- [ ] Remove workflow-scoped webhook helpers
- [ ] Remove related indexes and constraints

Acceptance Criteria:
- Workflow model contains no webhook configuration
- No code references workflow-level webhook fields
