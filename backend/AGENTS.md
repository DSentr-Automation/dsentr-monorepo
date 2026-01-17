# Backend Agent Notes

## Context
- The backend is a Rust Axum service backed by SQLx + PostgreSQL with async execution via Tokio.
- We expose workflow execution endpoints and persistence, so schema or API changes must remain backward compatible unless explic
itly coordinated.

## Required Practices
- Run `cargo fmt` and `SQLX_OFFLINE=true cargo clippy --all-targets --all-features` before committing backend changes.
- Add or update integration/unit tests (`SQLX_OFFLINE=true cargo test`) whenever modifying request handlers, data models, or migrations.
- Prefer strongly typed structures and avoid `unwrap`/`expect` in production paths—propagate errors with `Result` and `thiserror
`/`anyhow` patterns as appropriate.
- App is run by using `cargo run --features tls` or just `cargo run` for non-ssl
- Updated offline database for tests with `cargo sqlx prepare -- --manifest-path ./Cargo.toml --all-targets`

## Change Reasons
- Workspace membership listing now accepts viewer roles so the Members settings tab can display roster data without forcing a workspace switch.
- Added workspace OAuth connection removal flow so admins can revoke shared credentials without deleting personal tokens.
- Added Stripe configuration scaffolding so billing integrations can access shared credentials and webhook secrets at startup.
- Updated `.env.template` placeholders to reference SECURITY.md and vault-managed secrets, reducing the risk of reusing committed credentials.

- Delay node execution now honors explicit mode (duration vs datetime) and fails fast when the chosen mode lacks required inputs.
 - Added Asana OAuth configuration so the backend can provision client credentials and callbacks for the new Asana integration path.
## Change Reasons
- Added login activity tracking (IP, user agent, geo/proxy hints) so admin tooling can audit where users sign in and when sessions end.
- Added pluggable app email delivery with environment-controlled provider selection (`EMAIL_PROVIDER`). Supports `smtp` and `sendgrid` for signup, password reset, invites, and account notifications. This accommodates hosts that disallow outbound SMTP while preserving SMTP for environments that support it.
- Workflow node email behavior is unchanged: nodes using SMTP still send via runtime SMTP configuration and are not affected by the app-level provider switch.

- Removed legacy workflow-scoped webhook routes/config/token handling and dropped the `WEBHOOK_SECRET` requirement so source-scoped `/api/webhooks/:source_id` ingress is the only inbound webhook path.

- Privacy preference and signup settings:
  - Added `/api/account/privacy` (GET/PUT) to read/update `users.settings.privacy.share_workflows_for_improvement`.
  - Default behavior is opt-in: if the key is missing, the API returns `allow: true`.
  - Signup now accepts an optional `settings` JSON object so onboarding can persist the initial preference.
  - Migration `202511071_1_user_privacy_default.sql` backfills the default `true` for existing users where the key is absent.
- Workspace plan quotas can be tuned via `WORKSPACE_MEMBER_LIMIT` and `WORKSPACE_MONTHLY_RUN_LIMIT`, and pending invitations now count toward the workspace seat cap.
- Email workflow actions now leave graph traversal to outgoing edges (instead of using provider message IDs as `selectedNext`), and the executor falls back to edges when a selected next node is missing so downstream steps continue after email sends.

## App Email Delivery
- Environment variables:
  - `EMAIL_PROVIDER`: `smtp` (default) or `sendgrid`.
  - `EMAIL_FROM`: Sender for API-based providers; falls back to `SMTP_FROM` if unset.
  - `SENDGRID_API_KEY`: Required when `EMAIL_PROVIDER=sendgrid`.
- When `EMAIL_PROVIDER=smtp`:
  - Uses existing `SMTP_*` variables and the Lettre transport.
- When `EMAIL_PROVIDER=sendgrid`:
  - Sends app emails via SendGrid HTTP API. SMTP env vars are not required to boot.
  - Workflow nodes that choose SMTP continue to send using per-node SMTP settings.

- Workspace run usage now tracks overage counts per billing period, exposes overage in plan usage APIs, and allows over-limit runs while recording overage for billing/export flows.
- Workspace overage billing now persists Stripe subscription item ids, attaches the metered price during workspace upgrades, and reports over-limit usage to Stripe while leaving solo plans unchanged.
- Billing overage reporting now uses Stripe billing meter events instead of legacy usage records; set `STRIPE_WORKSPACE_METER_EVENT_NAME` to the configured meter event name so over-limit runs emit meter events with the workspace owner's Stripe customer id.
- Added an authenticated issue-reporting endpoint and persistence so user-submitted problem reports arrive with account/workspace context for troubleshooting.
- Workspace workflow saves now use optimistic concurrency and stream updates to collaborators to avoid overwriting changes between workspace members.
- Added admin-only API surface for /api/admin with issue reply threading so support staff can audit users, workspaces, workflows, and respond without exposing secrets.
- CORS now accepts a dedicated `ADMIN_ORIGIN` so the admin frontend can be hosted separately from the user app.
- Added Delay workflow node execution support with resumable run scheduling (`resume_at`) so waits persist and resume reliably.
- Added Formatter workflow node execution with typed operations (strings, numbers, JSON, dates, booleans), path-aware JSON access, and snapshot-friendly outputs so logic nodes can reshape data safely between steps.
- Added a Slack channel listing endpoint that validates personal or workspace OAuth tokens, enforces workspace plan/membership rules, and paginates Slack API responses so channel dropdowns stay in sync with connected accounts.
- Added an `OAUTH_REQUIRE_CONNECTION_ID` toggle so OAuth refresh/disconnect/revoke routes can require explicit `connection_id` inputs while still warning on implicit lookups by default.
- Update github backend build to push to a docker dev repo
- Added compile-time embedded action manifests so new action nodes can be added via JSON without new executor code.
- Fixed HTTP egress validation to only check manifest-defined destinations (node.data.http.url) and ignore payload data (params.url), preventing false rejections when actions process URLs as data.
