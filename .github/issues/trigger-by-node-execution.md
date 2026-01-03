Description:
Ensure workflow runs can start from explicit trigger nodes.

Subtasks:
- [ ] Accept trigger_node_id in run creation
- [ ] Validate trigger node existence
- [ ] Ensure execution begins at correct node
- [ ] Include trigger context in run metadata
- [ ] Add tests

Acceptance Criteria:
- Runs start at specified trigger node
- Invalid node IDs rejected
