# Models Agent Notes

## Purpose
- Typed representations of database rows and API payloads shared across repositories, services, and routes.
- Each module maps closely to a SQL table or response DTO.

## Key Modules
- `early_access.rs`: Shape of the early-access signup payload collected from the marketing form.
- `egress_block_event.rs`: Records for blocked outbound requests, including node metadata and timestamps.
- `oauth_token.rs`: Enum of connected OAuth providers plus `UserOAuthToken` row type (fields match `user_oauth_tokens` table).
- `signup.rs`: Incoming signup payload (supports optional OAuth provider override).
- `user.rs`: Core `User` and `PublicUser` structs, along with `OauthProvider`/`UserRole` enums.
- `verification_token.rs`: `EmailVerificationToken` row that powers email verification logic.
- `workflow.rs`: Primary workflow model and DTO for creation requests.
- `workflow_dead_letter.rs`: Representation of dead-lettered runs (snapshot + error).
- `workflow_log.rs`: Change history entries tied to workflows.
- `workflow_node_run.rs`: Individual node execution records persisted during runs.
- `workflow_run.rs`: Workflow run metadata, status tracking, and stored snapshot.
- `workflow_schedule.rs`: Schedule configuration rows with next/last run timestamps.
- `workspace.rs`: Workspace entities, memberships, invitations, and enum for workspace roles.

## Usage Tips
- These structs derive `sqlx::FromRow` where applicable, so SQLx queries can hydrate them directly.
- When adding new columns in migrations, update the corresponding struct and ensure serde/time annotations stay in sync with API expectations.

## Change Reasons
- Documented workspace connection models and shared token flag for OAuth promotion flows.
- Added a shared `plan` module that exposes the `PlanTier` enum so repositories and services can reason about plan tiers without depending on route-layer definitions.
- Workspace connection models now expose `owner_user_id` and `user_oauth_token_id` so API consumers and SQLx structs stay aligned with the new migration data.
- Introduced the `WorkspaceBillingCycle` struct so repositories/routes can persist subscription ids plus current period start/end timestamps for billing-aware quota calculations.
- Workspace model now includes an optional `stripe_overage_item_id` so subscription item ids for metered overage billing can be stored and surfaced across repositories and routes.
- Added `IssueReport`/`NewIssueReport` models to persist support submissions alongside captured user/workspace metadata.
- Added `IssueReportMessage` plus status/updated_at fields on `IssueReport` to power admin issue threading without leaking secrets.
- Issue messages now carry `read_by_user_at`/`read_by_admin_at` timestamps so unread badges in user/admin inboxes stay in sync with database state.
- Connected OAuth provider enum now includes Asana so Asana tokens and workspace connections can be stored and resolved like other providers.
- `UserOAuthToken` now includes an encrypted `metadata` JSON payload (used to hold Slack webhook details) so persisted rows stay aligned with the new database column.
- Documented the non-unique OAuth token/provider relationship and workspace connection lookup indexes so the models reflect the new schema expectations.
- Workspace connection token references are now optional to match the nullable FK that is set to NULL when personal tokens are deleted.
- Workspace connection models now carry `connection_id` so workspace listings can return the stable personal connection identity after promotion.
- Connected OAuth provider enum now includes Notion so Notion tokens and workspace connections can be stored alongside existing providers.
- Added `WebhookSource` model to match the new webhook_sources table and serialization expectations.
- Added `WebhookSubscription` model to mirror webhook_subscriptions rows for webhook trigger mappings.
- Removed workflow-scoped webhook fields (`require_hmac`, `hmac_replay_window_sec`, `webhook_salt`) from `Workflow` now that ingress is source-based only.
- Connected OAuth provider enum now includes GitHub so GitHub connections can be stored alongside existing providers.
- Provider trigger models now store `trigger_node_id` as a string to support non-UUID workflow node identifiers.
