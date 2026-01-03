Description:
Completely remove the old workflow-scoped webhook system.

Subtasks:
- [ ] Remove POST /api/workflows/{workflow_id}/trigger/{token} routes
- [ ] Remove workflow-scoped token derivation
- [ ] Remove legacy webhook URL generation endpoints
- [ ] Preserve and refactor HMAC verification helpers for source use
- [ ] Preserve and refactor replay helpers for source use
- [ ] Remove all references to token-based routing

Acceptance Criteria:
- No legacy webhook routes exist
- No token-based webhook logic remains
- Unified ingress is the only inbound path
