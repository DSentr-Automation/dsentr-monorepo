# Routes Agent Notes

## Purpose
- HTTP handlers grouped by feature area. Each module exposes functions wired in `main.rs`.

## Key Modules
- `admin.rs`: Admin-only maintenance endpoints (currently purge stale runs).
- `dashboard.rs`: Simple authenticated health check that returns a welcome message and disables caching.
- `early_access.rs`: Public endpoint that records early-access emails with duplicate handling.
- `microsoft.rs`: Authenticated helpers that surface Microsoft Teams metadata using stored OAuth tokens.
- `options/`: User settings APIs (secrets management).
- `auth/`: Authentication/login flows, session management, password reset, etc.
- `oauth/`: Connected account management and OAuth callbacks for Google/Microsoft integrations.
- `workflows/`: Core workflow CRUD, execution controls, logs, and SSE streams.
- `workspaces.rs`: Workspace CRUD and membership APIs.

## Usage Tips
- Handlers expect `AppState` and often an `AuthSession` extractor; ensure new routes reuse these patterns for authorization.
- For APIs returning JSON, use `responses::JsonResponse` helpers to keep status/message structure consistent.
- When adding new route groups, update `main.rs` to mount them and consider rate-limit layer alignment (`auth_governor_conf` vs global).
- Workspace invitation emails must link to `/signup?invite={token}` and use URL-encoded tokens; update the dedicated test if this contract changes.
- Workspace lifecycle flows now expose `GET /api/workspaces`, `GET /api/invites`, `POST /api/workspaces/:id/leave`, and `POST /api/workspaces/:id/revoke`. Use the shared Solo-provisioning helper so the last member receives an automatic personal workspace when they leave or are revoked.
- Settings secrets APIs now decrypt/encrypt user secret stores with `API_SECRETS_ENCRYPTION_KEY` and opportunistically re-encrypt legacy plaintext values so API keys are not persisted in cleartext.

## Change Reasons
- Auth routes now record login IPs with location/proxy hints and expose an admin endpoint for per-user login activity so support can audit sign-in origins and logout times.
- Solo plan downgrades now normalize owned workspaces back to the solo tier when processing plan changes.
- Added promotion endpoint tests to cover workspace-level OAuth sharing and authorization checks.
- OAuth route fixtures and Slack/Microsoft helpers now populate encrypted `user_oauth_tokens.metadata` for Slack installs so webhook URLs persist through promotion without relying on refresh responses.
- Plan change behavior updated: selecting the Workspace plan now initiates a Stripe Checkout session and returns `{ success, checkout_url }` instead of immediately updating user/workspace plans. The handler persists the Checkout `session_id` and desired plan/workspace name in `users.settings.billing.pending_checkout` and stores a `stripe_customer_id` on the user if needed. The Solo path is unchanged and still returns the prior shape with memberships/workflows.
- OAuth routes honor a configurable `oauth.require_connection_id` flag that warns on missing IDs and returns 400 for refresh/disconnect/revoke requests when enabled so shared-token calls stay explicit.

- Added `POST /api/billing/stripe/webhook` (legacy) and `POST /api/stripe/webhook` (new) to process Stripe webhooks. We verify signatures via the shared `StripeService`.
- Success handling (`checkout.session.completed`):
  - Validates idempotently by matching the event's `data.object.id` against `users.settings.billing.pending_checkout.session_id`. If no match or `pending_checkout` is absent, the handler acknowledges and does nothing.
  - Resolves the user via `metadata.user_id`, `client_reference_id`, or by mapping `customer` to `users.stripe_customer_id`.
  - Creates the user's personal workspace at the Workspace tier using the pending `workspace_name`, sets `users.plan = "workspace"`, assigns the user as `owner`, and optionally shares any `shared_workflow_ids` recorded in `pending_checkout`.
  - Marks onboarding complete when applicable and clears `settings.billing.pending_checkout` plus any prior `last_error/last_error_at`.
- Failure handling (`payment_intent.payment_failed`, `invoice.payment_failed`, `checkout.session.async_payment_failed`, `checkout.session.expired`): When a failure is detected, we:
  - Identify the user either from `checkout.session` metadata/client_reference_id or by mapping `customer` to `users.stripe_customer_id`.
  - Clear `users.settings.billing.pending_checkout` and set `users.settings.billing.last_error`/`last_error_at` to surface retry guidance in the UI.
  - Safeguard the personal plan by rolling back `users.plan` to `solo` if it was set to `workspace` during a provisional upgrade.

- `GET /api/workspaces/onboarding` now includes a `billing` object with `last_error`, `last_error_at`, and `has_pending_checkout` to provide clear client messaging after failed payments. Starting a new checkout clears any prior error state.

- Tests: added coverage to assert that initiating a Workspace upgrade triggers the Stripe mock and returns a Checkout URL without mutating plans, plus integration-style tests for the Stripe webhook handler covering both success (creates workspace, clears pending, sets plan) and failure (records error, clears pending, rolls back plans) paths.

- Workspace OAuth administration now returns `403 Forbidden` when a workspace admin attempts to remove a shared connection that they did not create. The `/api/workspaces/:id/connections/:connection_id` handler surfaces a clear error so clients can prompt users to ask the original sharer to unshare their credential.
- Workspace OAuth-related routes/tests now construct `WorkspaceOAuthService` with the workspace repository so membership checks run before decrypting connections (workspaces API helpers, Microsoft route helpers, and Stripe/account tests were updated to the new constructor).
- Workspace OAuth route fixtures now handle nullable `user_oauth_token_id` values so shared connections stay listable after personal token deletion.
- Shared the `PlanTier` enum from models and updated workspaces/auth/stripe route tests to rely on the repository-level `get_plan` helper so backend plan gating no longer depends on route-local definitions.
- Workspace OAuth routes serialize and authorize against the new `owner_user_id`/`user_oauth_token_id` fields so multiple shared connections per provider can coexist without clobbering each other in the repository mocks.
- Workspace OAuth routes now resolve shared credentials by explicit connection IDs: Microsoft Teams APIs require a connection_id + scope, and handlers double-check the resolved workspace before issuing tokens so selecting a stale ID can't leak another workspace's credentials. Test repositories were updated to track multiple connections for these scenarios.
- Added workspace/member/run quota enforcement with explicit error codes (`workspace_plan_required`, `workspace_member_limit`, `workspace_run_limit`) plus a shared helper module so invites, signup, and workflow run routes all emit consistent JSON payloads.
- Added regression tests that cover invite acceptance at the member cap plus workflow run starts at the run cap, ensuring the proper status codes, error payloads, and quota release behavior when idempotent requests reuse existing runs.
- Workspaces/auth/account/billing routes now sync or clear `workspace_billing_cycles` based on Stripe subscription data, expose `cycle_started_at` alongside `renews_at`, and wipe stored cycle windows whenever a workspace downgrades back to Solo so quota evaluation matches the real billing window.
- Route mocks now implement the expanded workspace repository surface (member counts, run quotas, billing cycles) and default missing plans to Workspace so invite/signup paths hit plan-limit guards without panicking in tests.
- Workspace member caps reserve seats for pending invitations and read limits from `WORKSPACE_MEMBER_LIMIT`/`WORKSPACE_MONTHLY_RUN_LIMIT` so deployments can tune quotas without code changes.
- Microsoft Teams channel member lookup now allows workspace-plan members/owners to use personal OAuth connections while still enforcing workspace access.
- Stripe checkout completion now records workspace name changes into workflow change history so Settings > Logs can show who renamed the workspace.

- Workflow routes now enforce optimistic concurrency on workspace saves and provide `/api/workflows/{id}/events` SSE so collaborators receive live workflow updates without refreshing.

## New (Stripe billing plan lifecycle)
- Workspace subscribers now see renewal/reversion dates surfaced in the Plans tab. `GET /api/workspaces/onboarding` attaches `billing.subscription` with:
  - `renews_at` (RFC3339), `cancel_at` (RFC3339|null), and `cancel_at_period_end`.
  - Backed by the new StripeService subscription helpers; we resolve the customer via `users.stripe_customer_id`.
- Downgrading from Workspace to Solo is now scheduled at period end when the user has an active Stripe subscription:
  - `POST /api/workspaces/plan` with `plan_tier: "solo"` sets `cancel_at_period_end = true` on the Stripe subscription and returns `{ success, scheduled_downgrade: { effective_at } }` without mutating local plan fields immediately.
  - For non-Stripe users (or no active subscription), the route preserves the immediate downgrade behavior.
- Webhook handling updated to revert plans when the subscription actually cancels:
  - On `customer.subscription.deleted`, we map the `customer` to a user, set `users.plan = "solo"`, and downgrade any owned workspaces to `"solo"`.
- Workspace upgrades now include the metered overage price (via `STRIPE_OVERAGE_PRICE_ID`) in Checkout, and webhook completion extracts/persists the overage subscription item id on the workspace while remaining idempotent when the item is already stored.
- Stripe webhooks now record processed event ids inside a transaction-backed log so duplicate deliveries short-circuit without reapplying billing mutations; tests cover repeated checkout and subscription events.

### New endpoint: resume subscription
- `POST /api/workspaces/billing/subscription/resume` clears `cancel_at_period_end` on the active Stripe subscription for the authenticated user's Stripe customer. Returns the updated renewal date so clients can refresh UI.
- Workspace membership removal/leave flows now call the workspace OAuth purge helper and have regression tests to ensure shared connections are deleted when members depart or workspaces convert to Solo.
- Added `POST /api/issues` so authenticated users can submit issue reports that persist user/workspace context for support investigations.
- Added an admin-only `/api/admin` router (session + role guarded with an IP allowlist stub) that surfaces read-only listings and admin issue replies without exposing OAuth secrets.
- Added messaging inbox endpoints (user + admin) with list/detail/reply/mark-read flows and read timestamps so unread badges stay accurate across both portals.
- Added Asana metadata routes (workspaces, projects, tags, teams, users, sections) behind authenticated OAuth so the frontend can populate dropdowns without exposing tokens.
- Added Asana OAuth route support (start + callback + provider parsing) so the new Asana integration can authenticate alongside Google, Microsoft, and Slack.
- Added Asana task and comment metadata endpoints (workspace-plan only) to back new dropdowns while keeping Solo users blocked server-side.
- Added a Slack channels route that pulls channel lists via personal or workspace OAuth tokens, applies plan/membership checks, and paginates Slack API responses for the Slack action dropdown.
- Slack channels route now requires an explicit workspace_connection_id, refreshes Slack workspace tokens on token_expired, retries once, and returns auth_expired errors only when refresh fails.
- Slack channel route tests now import workspace connection listing/audit types explicitly to keep clippy clean after expanding refresh coverage.
- Added Notion integration routes to list shared databases and retrieve database schemas using stored OAuth connections so the UI can render property-aware inputs.
- Workspace OAuth endpoints now surface stable `connectionId` values for shared connections so frontend promotion visibility persists across reloads.
- Workspace promotion now rejects Slack with an explicit workspace-install requirement, and route helpers map the new Slack install error consistently.
- Route fixtures now populate `slack_team_id` on Slack workspace connections so Slack connection invariants hold in tests and workspace token lookups.
- Slack channel listing now requests IM/MPIM types and surfaces missing-scope errors with reconnect guidance instead of opaque Slack failures.
- Google Sheets routes now accept personal OAuth scope with explicit `connection_id` so personal connections can fetch tokens and worksheets without affecting workspace handling.
- Added a Debug derive for the Google Sheets token proxy so personal-scope route tests can call `expect_err` without compile failures.
- Added public webhook ingress routing at `POST /api/webhooks/:source_id`, validating `X-DSentr-Timestamp`/`X-DSentr-Signature` via `webhook_ingress_validation`, matching subscriptions by `event_type`, and returning `202 Accepted` after validation while runs enqueue asynchronously.
- Webhook ingress now stamps trigger metadata (`trigger_node_id`, `trigger_type`, `source`) into `_trigger_context` when enqueuing runs so trigger selection stays explicit.
- Added authenticated workspace-scoped webhook source/subscription management APIs under `/api/workspaces/:workspace_id/webhooks/...` so the UI can manage control-plane configuration; these routes never expose webhook secrets and do not alter ingress or execution behavior.
- Webhook ingress now records dedupe keys with log-only/enforce modes plus dedicated logs/metrics for dedupe outcomes and enqueue counts.
- Removed legacy workflow-scoped webhook URL/config/trigger endpoints so `/api/webhooks/:source_id` is the only inbound webhook path.
- Added source-scoped webhook subscription list/create/delete APIs with trigger/event validation and subscription management tests.
- Webhook ingress now fans out one run per matching subscription, emits fanout counters, logs per-subscription outcomes, and adds handler tests for zero/multiple/partial failure cases.
- Webhook ingress now records delivery log entries (received/routed/dropped/errored) after authentication and keeps logging failures non-blocking so operators can observe inbound webhook activity.
- Webhook ingress metrics now include explicit counters for matched subscriptions and run enqueue outcomes, plus test coverage uses a delivery repo in replay rejection cases.
- Webhook route helpers now allow targeted clippy warnings for large Response errors/argument lists and avoid needless tracing borrows to keep ingress signatures stable.
- Webhook ingress now consumes workspace run quota per enqueued run and releases quota when enqueue attempts fail so run usage stays accurate.
- Added a read-only `/api/actions` route that returns the action manifest catalog for frontend discovery without exposing secrets.
- Route test AppState builders now include the integration registry to match the expanded shared state.
- Webhook run snapshots now normalize workflow egress allowlists to vetted host entries before enqueueing.
- Route-level test configs now seed GitHub OAuth settings so shared Config builders stay aligned with OAuth providers.
- Route test configs now include GitHub App settings to keep updated OAuth wiring and GitHub App validation consistent.
- Added GitHub App webhook ingress at `/api/webhooks/github/:subscription_id` with signature verification, header-derived event types, and ping short-circuiting to align GitHub webhooks with the existing ingress pipeline.
- Added a provider-specific GitHub webhook ingress for `/webhooks/github` that validates required headers/signatures, normalizes event types, and bypasses the user webhook dispatch flow.
- Provider GitHub webhook ingress now returns 403 on signature failures, 200 on success/duplicates, and dedupes by delivery id with provider-scoped tracing fields for event/run visibility.
- Kept the legacy GitHub webhook ingress handler in place but marked it as dead code after wiring the provider-only endpoint.
- Provider GitHub webhook ingress now records delivery-id dedupe before JSON parsing so duplicate malformed payloads short-circuit cleanly.
- Provider GitHub webhook ingress now uses the webhook-ingress dedupe repository with a fixed provider UUID key to enforce delivery-id idempotency without replay-window logic.
- GitHub provider trigger planning now dedupes by `(workflow_id, trigger_node_id)` so multiple workflows sharing a trigger node id do not clobber each other.
- GitHub provider trigger dispatch now treats `trigger_node_id` as an opaque string so non-UUID workflow node ids can activate provider runs.
- GitHub provider webhook route tests now include provider-trigger deletion helpers in the stub repo to keep test doubles aligned with the repository trait.
- GitHub provider trigger resolution now emits a safe debug log with counts only (no payloads or IDs) for observability.
- Added a read-only settings endpoint to list provider webhook metadata per workspace for the Webhooks UI.
