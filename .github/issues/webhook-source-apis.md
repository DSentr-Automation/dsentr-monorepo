Description:
Expose minimal APIs to manage webhook sources.

Subtasks:
- [ ] POST /api/workspaces/{workspace_id}/webhook-sources
- [ ] GET /api/workspaces/{workspace_id}/webhook-sources
- [ ] DELETE /api/webhook-sources/{source_id}
- [ ] POST /api/webhook-sources/{source_id}/rotate-secret
- [ ] Enforce workspace permissions
- [ ] Add integration tests

Acceptance Criteria:
- Sources can be created, listed, deleted
- Secrets can be rotated
- Permission checks enforced
