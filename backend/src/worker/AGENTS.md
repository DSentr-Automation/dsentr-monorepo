# Worker Agent Notes

## Purpose
- Runs background tasks that drive workflow execution and schedule maintenance.

## Key Functions
- `start_background_workers`: Spawns a Tokio task that periodically:
  - requeues expired leases,
  - claims eligible runs and dispatches them to `engine::execute_run`,
  - processes due schedules (`process_due_schedules`),
  - purges old runs based on `RUN_RETENTION_DAYS`.
- `process_due_schedules`: Loads a batch of due schedules and delegates to `trigger_schedule`.
- `trigger_schedule`: Converts stored schedule config into a new workflow run snapshot, seeds trigger context, and updates next-run timestamps.

## Usage Tips
- Adjust cadence and batch sizes via env vars or constants (`MAX_SCHEDULES`) rather than hard-coding multiple loops elsewhere.
- The worker clones `AppState`; ensure any new state fields are `Arc`-backed so they remain inexpensive to clone.
- When adding new periodic maintenance tasks, append them inside the loop with a clear timer guard similar to `last_cleanup`.

## Change Reasons
- Swapped ad-hoc stderr logging for structured tracing so worker diagnostics include worker and schedule identifiers and play nicely with the global subscriber.
- Updated slow-run worker test harness to fully own mocked node run fields and reuse shared completion trackers without moving them, fixing compile-time lifetime and move errors.
- Scheduled run quota checks now tolerate solo-plan workspaces by skipping workspace-only limits instead of logging plan-required warnings.
- Runaway workflow protection blocks runs in the worker before execution, records a `runaway_protection_triggered` event, fails the run without retries, and skips workspace quota/overage increments when the limit is exceeded.
- Worker/AppState test scaffolding now seeds the Asana OAuth provider config so executor paths compile with the expanded provider set.
- Scheduled runs now resolve a matching schedule trigger and seed `_start_from_node` so only the intended branch executes instead of activating every trigger in multi-trigger workflows.
- Scheduled and Notion-triggered runs now stamp trigger metadata (`trigger_node_id`, `trigger_type`, `source`) into `_trigger_context` alongside scheduling context.
- Added Notion polling schedule handling that resolves OAuth tokens by scope, emits trigger events, updates cursor state, and respects workspace plan/membership gating.
- Notion polling now clones page payloads before emitting events to satisfy borrow rules while updating cursor state.
- Notion polling state updates now use `is_none_or` and a single shared state update branch to satisfy clippy warnings without changing behavior.
- Worker cleanup now purges webhook ingress dedupe rows daily using replay-window-aware retention.
- Worker test fixtures now align with the Workflow model after removing legacy webhook fields and `WEBHOOK_SECRET` config stubs.
