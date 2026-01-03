Description:
Simplify webhook trigger nodes to declare event_type only.

Subtasks:
- [ ] Remove source selection from trigger config
- [ ] Add event_type field
- [ ] Update workflow serialization
- [ ] Validate event_type presence
- [ ] Ensure other trigger types unaffected

Acceptance Criteria:
- Trigger nodes declare only event_type
- Source binding handled via subscriptions
