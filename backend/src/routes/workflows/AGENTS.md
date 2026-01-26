# Workflow Routes Agent Notes

## Purpose
- REST + SSE surface for building, executing, and monitoring workflows.
- All handlers assume authenticated access via `AuthSession` and rely on `AppState` repositories/services.

## Module Overview
- `prelude.rs`: Shared imports/types (Axum extractors, serde aliases, plan helpers).
- `helpers.rs`: Utility functions for plan enforcement, diffing workflow JSON, syncing schedules/secrets, and SQL error helpers.
- `crud.rs`: Create/read/update/delete workflows with plan-tier enforcement and automatic schedule/secret synchronization.
- `runs.rs`: Start, cancel, rerun workflows; fetch run lists/status; download run snapshots.
- `concurrency.rs`: Adjust per-workflow concurrency limits with plan checks.
- `logs.rs`: List, delete, or clear workflow log entries.
- `dead_letters.rs`: Manage dead-letter queue entries (list, requeue, clear).
- `egress.rs`: Manage webhook/egress allowlists and blocked event history.
- `plan.rs`: Surfaces usage metrics for the current plan tier.
- `sse.rs`: Server-sent-event endpoints streaming run updates (global, per workflow, per run).

## Usage Tips
- Always call `AppState::resolve_plan_tier` before performing plan-gated operations; helpers assume it was run.
- Responses use `JsonResponse` for errors; return structured JSON (`success`, payload) for success cases.
- When modifying workflow data, invoke `sync_secrets_from_workflow` so new secrets propagate to the user's secret store.
- Workflow run APIs and worker schedules now enforce workspace run quotas (10k runs/month) via the shared limit helpers, returning the `workspace_run_limit` response code when the allocation is exhausted.
- Workspace run caps respect the `WORKSPACE_MONTHLY_RUN_LIMIT` configuration so deployments can raise/lower allocations without code changes.

## Change Reasons
- Workflow run endpoints now treat solo-plan workspaces as solo for quota gating, avoiding workspace-plan errors and adding regression coverage for the `/run` path.
- Plan usage endpoint now returns personal/solo usage when a workspace query targets a non-Workspace plan so solo workspaces don't receive 403 errors.
- Workflow run execution now hydrates secrets for scheduled and webhook-triggered runs while responses (run listings, downloads, and webhook acknowledgements) redact sensitive fields so plaintext API keys are never returned to clients.
- Workflow helper tests populate `stripe_overage_item_id` on workspace fixtures so billing overage schema updates compile across plan usage helpers.
- Run creation endpoints (manual, rerun, webhook) enforce runaway workflow protection per workspace and return `429` with `{"error":"runaway_protection_triggered"}` when the recent-run limit is exceeded.
- Workflow log listing now validates workspace membership and includes entries from all actors; deletions emit workspace-scoped history records so change logs capture who removed workflows.
- Added optimistic concurrency and workflow SSE streaming so workspace users get the latest graph automatically and stale saves return 409 with the authoritative payload.
- Manual run requests accept `start_from_node_id` and seed `_start_from_node` when the target trigger exists so multi-trigger workflows only dispatch the chosen entry instead of activating every trigger.
- Manual run creation now validates trigger-node selection and stamps trigger metadata into `_trigger_context`.
- Workflow schedule sync now recognizes Notion polling triggers, persisting their connection/database config and preserving cursor state between updates.
- Workflow route test configs now include webhook ingress dedupe mode to keep Config stubs aligned.
- Removed workflow-scoped webhook endpoints and token helpers now that inbound webhook traffic is handled through source-based ingress.
- Trigger start validation helpers now allow large Response errors to keep run request signatures stable without clippy noise.
- Workflow run test AppState fixtures now include the integration registry to match the expanded shared state.
- Workflow plan violation messages now use ASCII punctuation to fix encoding corruption.
- Workflow run snapshots now normalize egress allowlists to trimmed host entries before enqueueing.
- Workflow route test configs now seed GitHub OAuth settings so Config stubs compile with the expanded provider set.
- Workflow route test configs now seed GitHub App settings so GitHub App invariants are exercised in route fixtures.
- Added a workflow helper that maps GitHub trigger nodes into provider event types with installation and repository identifiers for deterministic trigger syncing.
- Tightened GitHub trigger mapping determinism with an explicit event allowlist, canonical event selection key, and surfaced mapping errors for activation handling.
- Workflow create/update now validates GitHub trigger activation (connections, repository access, event allowlist) and upserts provider triggers when publishing non-draft graphs.
- GitHub trigger activation now guards on explicit workflow active state and treats trigger node ids as opaque strings for non-UUID graphs.
- Workflow updates and deletes now remove provider triggers for removed/modified GitHub nodes or inactive workflows to keep trigger registrations in sync.
- GitHub trigger activation now validates installation/repository id formats and enforces that trigger installations match the selected GitHub connection with stable error codes.
