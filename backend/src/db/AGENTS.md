# DB Agent Notes

## Purpose
- Repository traits and their SQLx-backed implementations for users, workspaces, workflows, and connected OAuth tokens.
- Provides in-memory test doubles (`mock_db.rs`) so route/service tests can run without touching Postgres.

## Modules
- `user_repository.rs`: trait surface for all user/account operations (signup, password reset, plan upgrades, settings).
- `workflow_repository.rs`: async trait covering workflow CRUD, run management, scheduling, and dead-letter handling. Some rarely used methods are intentionally left unimplemented in mocks.
- `workspace_repository.rs`: trait for workspace CRUD, membership management, and invitation flows.
- `oauth_token_repository.rs`: trait + `NewUserOAuthToken` DTO for storing encrypted OAuth connection tokens.
- `postgres_*_repository.rs`: SQLx implementations of the above traits. Every method uses `query!`/`query_as!` macros for compile-time checked SQL.
- `mock_db.rs`: default struct implementing `UserRepository` plus `NoopWorkflowRepository` and `NoopWorkspaceRepository` for tests.
- `mod.rs`: re-exports to simplify `use crate::db::*` paths.

## Usage Tips
- Keep trait signatures exhaustive; services depend on these abstractions rather than concrete Postgres types.
- When adding new queries, use the SQLx macros so compile-time checking stays intact—remember to run `cargo sqlx prepare` if the project relies on it.
- Extend `MockDb` and the `Noop*Repository` helpers when writing tests that need to assert persistence behavior without a database.

## Change Reasons
- User repository now persists login activity (IP, geo/proxy flags, user agent) and exposes list + logout updates so auth flows and admin tooling can audit session origins.
- Added workspace connection repositories and shared-token helpers for promoting OAuth credentials into workspaces.
 - Extended `UserRepository` with Stripe customer tracking: `get_user_stripe_customer_id` and `set_user_stripe_customer_id`, and updated `PostgresUserRepository` queries and the `User` model to include an optional `stripe_customer_id` column.
 - Introduced billing helpers: `find_user_id_by_stripe_customer_id` to map Stripe customer IDs back to local users for webhook processing, and `clear_pending_checkout_with_error` to atomically clear `settings.billing.pending_checkout` while recording `last_error`/`last_error_at` for frontend retry UX.
 - Test support: `MockDb` now tracks `update_user_plan` call count to assert that plan mutations do not occur during checkout initiation and do occur in webhook success/failure flows.

- Added `workspace_id` (nullable) to `user_oauth_tokens` and propagated it through `UserOAuthToken` and `NewUserOAuthToken`.
  - Repository reads/writes for personal tokens now enforce `workspace_id IS NULL` to avoid cross-scope leakage.
  - Introduced ownership helpers at the service layer; `WorkspaceOAuthService::load_token` now rejects non-owned or non-personal tokens with a 403 (Forbidden) response.
  - `PostgresUserOAuthTokenRepository` uses `query_as::<_, UserOAuthToken>` bindings for these queries to avoid churn in SQLx offline artifacts while the schema evolves.
- Workspace connection repositories now expose `list_by_workspace_creator` and `delete_by_id` so membership removals can enumerate a user's shared connections and delete them safely during cleanup flows.
- Added `WorkspaceRepository::is_member` (with Postgres + Noop implementations) so workspace OAuth flows can check `workspace_members` directly before exposing or decrypting shared credentials.
- Introduced `StaticWorkspaceMembershipRepository` in `mock_db.rs` so tests can flip `is_member` between allowed/denied states without rebuilding the entire trait surface, enabling engine, route, and service tests to assert `403 Forbidden` gating logic deterministically.
- Workspace repositories now expose a normalized `get_plan` helper (Postgres + mock implementations) returning the shared `PlanTier`, allowing services/tests to gate workspace-only features without probing route modules.
- Workspace connection repositories now persist `owner_user_id` and `user_oauth_token_id`, update their unique constraints, and surface those fields through SQLx queries so traits, Postgres impls, and test doubles stay consistent with the new schema.
- Workspace connection repositories add a `has_connections_for_owner_provider` helper so services can determine whether a personal OAuth token is still shared elsewhere before flipping the `is_shared` flag, and all Postgres/test implementations expose the new method.
- Workspace repositories now provide member counting plus `workspace_run_usage` quota helpers (Postgres + mocks) so plan gating can atomically enforce seat and run limits without duplicating concurrency logic in routes or workers.
- Workspace repositories now manage `workspace_billing_cycles` (upsert/get/clear) so Stripe subscription ids and current period windows are stored centrally for billing-aligned quota resets.
- Workflow and workspace repositories were refreshed to fix build regressions: workflow repos import `CreateWorkflowRunOutcome` explicitly, and the Postgres workspace run quota helper avoids moving the optional row before checking it.
- Expanded `StaticWorkspaceMembershipRepository` so tests can simulate run quotas and billing cycles, capture release counts, and assert how routes respond when workspaces are at or over their monthly allocations.
- Workspace repositories expose pending-invitation counting so seat checks can reserve capacity for outstanding invites alongside existing members.
- StaticWorkspaceMembershipRepository now carries a configurable plan tier so tests can emulate solo workspaces when exercising run gating and quota behavior.
- Workspace repositories persist `stripe_overage_item_id` for workspaces, expose getters/setters (including mock support), and SQLx queries return the new column so Stripe metered usage can be reported.
- StaticWorkspaceMembershipRepository now tracks workspace owners so meter-event billing tests can surface the correct Stripe customer id when emitting usage to Stripe.
- User repository adds an issue-report insert helper (with Postgres + mock implementations) so support submissions capture user/workspace metadata in the database.
- Added a Stripe event log repository (Postgres + mock) to persist processed webhook event ids for webhook idempotency.
- Workflow repositories expose `count_workspace_runs_since` (Postgres + mocks/Noop) so runaway workflow protection can rate-limit run creation per workspace window.
- Workflow log listing now returns all entries for a workflow (rather than filtering by actor) to support shared change-history views while preserving per-entry actor ids.
- Workflow updates now accept an optional expected `updated_at` timestamp so the Postgres repo can enforce optimistic concurrency for shared workspace edits.
- User OAuth tokens now carry an encrypted `metadata` column (populated for Slack webhook installs) so the initial incoming webhook URL survives until workspace promotion without depending on refresh responses.
- User OAuth token repositories now support id-based lookups and provider-scoped listings, and workspace connection repositories add id-scoped getters plus connection-level update/delete helpers alongside existing provider-based variants.
- User OAuth token repositories add insert/update/delete helpers keyed by token id so services can create multiple per-provider connections without provider-level overwrites, and Postgres implementations return the most recent token deterministically when falling back to provider lookups.
- Workspace connection repositories now allow nullable token references and guard provider/owner/token identity on credential updates so shared connections stay consistent after personal token deletion.
- Workspace connection repositories expose a `find_by_source_token` helper so shared connection refresh flows can locate and update dependent workspace credentials.
- Workspace connection repositories now persist and list `connection_id` so workspace OAuth responses can return a stable connection identity.
- Workspace connection repositories now provide a Slack team lookup and enforce Slack team-id invariants, with Postgres-backed queries using the new workspace/team index.
- Added webhook source repository trait and Postgres implementation with encrypted secret handling and tests.
- Added webhook subscription repository trait and Postgres implementation for webhook source trigger mappings.
- Webhook source repositories now support id lookups and last-seen updates so ingress can resolve sources and track activity; webhook subscriptions can be queried by source/event with enabled filtering to keep routing logic focused.
- Webhook source/subscription repositories now expose enable/disable updates so control-plane webhook management APIs can toggle active state with repo-enforced scoping.
- Added webhook ingress dedupe repository helpers to insert delivery keys and purge retained entries per replay-window policy.
- Removed workflow-scoped webhook token/replay helpers from workflow repositories, and workspace webhook-signing resets now target webhook sources instead of workflows.
- Added webhook delivery repository helpers (trait + Postgres) so ingress can record delivery status updates without coupling to workflow transactions.
- Allowed the webhook delivery `record_delivery` trait signature to keep its full parameter set without tripping clippy warnings.
- Added a provider webhook dedupe repository to persist delivery ids for idempotent provider ingress handling.
- Marked `find_webhook_source_by_name` as allowed dead code so the legacy GitHub webhook lookup stays available without being wired in the new provider ingress.
- Marked the provider webhook dedupe repository as allowed dead code while the provider ingress uses the shared webhook-ingress dedupe table.
- Added a workflow repository helper for unmetered run creation so provider executions can bypass quota-gated paths explicitly.
- Provider trigger inserts now upsert on the workflow/node/event unique key so re-activations refresh metadata without duplicating rows.
- Provider trigger repositories now store trigger node ids as TEXT to match non-UUID frontend node identifiers.
- Provider trigger repositories now expose delete-by-workflow and delete-by-node helpers so workflow updates can remove obsolete provider triggers.
