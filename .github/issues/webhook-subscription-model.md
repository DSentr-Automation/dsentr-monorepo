Description:
Add subscriptions mapping webhook sources and events to workflow trigger nodes.

Subtasks:
- [ ] Create webhook_subscriptions table migration
- [ ] Fields: id, webhook_source_id, workflow_id, trigger_node_id, event_type, enabled, timestamps
- [ ] Add index on (webhook_source_id, event_type)
- [ ] Implement WebhookSubscription Rust model
- [ ] Implement repository methods (create, list, delete)
- [ ] Validate workflow ownership and trigger_node_id existence
- [ ] Add unit tests

Acceptance Criteria:
- Subscriptions resolve efficiently by source and event
- Invalid workflow or trigger references rejected
- Fanout supports multiple subscriptions per event
