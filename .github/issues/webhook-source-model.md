Description:
Add first-class webhook sources scoped to workspaces.

Subtasks:
- [ ] Create webhook_sources table migration
- [ ] Fields: id, workspace_id, name, secret, require_hmac, replay_window_sec, last_seen_at, enabled, timestamps
- [ ] Add foreign keys and indexes
- [ ] Implement WebhookSource Rust model
- [ ] Implement repository methods (create, list, delete, rotate secret)
- [ ] Encrypt secrets using existing secret encryption mechanism
- [ ] Add unit tests

Acceptance Criteria:
- Webhook sources persist correctly
- Secrets stored encrypted
- Workspace scoping enforced
- CRUD operations covered by tests
