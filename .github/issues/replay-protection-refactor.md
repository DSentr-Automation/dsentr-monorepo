Description:
Re-scope replay protection from workflows to webhook sources.

Subtasks:
- [ ] Add webhook_source_id column to webhook_replays table
- [ ] Populate or skip backfill based on dev strategy
- [ ] Add FK from webhook_replays.webhook_source_id to webhook_sources.id
- [ ] Add unique constraint (webhook_source_id, signature)
- [ ] Drop workflow_id column and old constraints
- [ ] Update replay protection logic to use webhook_source_id
- [ ] Update tests for source-scoped replay blocking

Acceptance Criteria:
- Replay protection enforced per webhook source
- Duplicate signatures rejected correctly
- No verification regressions introduced
