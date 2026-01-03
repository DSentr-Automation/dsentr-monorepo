Description:
Expose APIs to manage subscriptions between sources, events, and triggers.

Subtasks:
- [ ] POST /api/webhook-sources/{source_id}/subscriptions
- [ ] GET /api/webhook-sources/{source_id}/subscriptions
- [ ] DELETE /api/subscriptions/{subscription_id}
- [ ] Validate workflow ownership and trigger_node_id
- [ ] Validate event_type format
- [ ] Add integration tests

Acceptance Criteria:
- Subscriptions created and deleted correctly
- Invalid references rejected
- APIs return consistent responses
