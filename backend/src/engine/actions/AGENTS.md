# Engine Actions Agent Notes

## Purpose
- Houses the concrete node executors invoked by `engine::executor`.
- Each module exposes an async function returning `(serde_json::Value, Option<String>)` where the optional string selects the next node.

## Modules
- `code.rs`: Runs custom JavaScript via Boa, marshals templated inputs, and maps outputs back into context keys while preventing duplicate parameter names.
- `email.rs`: Supports SMTP and AWS SES delivery with recipient validation, optional TLS settings, and request signing. Applies a per-node timeout to avoid hanging workers.
- `google.rs`: Uses stored Google OAuth tokens to append rows to Google Sheets. Validates column mappings, enforces account ownership, and builds ranges safely.
- `http.rs`: Provides configurable HTTP requests with support for headers, query/body templating, retries, and allow/deny host enforcement.
- `messaging.rs`: Sends messages to Slack (chat.postMessage), Microsoft Teams (via Graph API channel/tenant metadata), or Google Chat webhooks. Normalizes platform identifiers and handles OAuth token refresh for Teams.
- `mod.rs`: Router that chooses between trigger/condition/action handlers and shared helpers (`parse_expression`, templating, etc.).

## Usage Tips
- Keep new action modules stateless-pass everything via parameters and the shared `AppState`.
- Validate all user-provided inputs before performing network calls; return `Err(String)` with actionable error messages so UI surfaces them cleanly.
- Prefer adding small helper structs/functions within each module rather than extending `mod.rs` unless they are shared across actions.

## Change Reasons
- Teams routing now infers Delegated OAuth when `teamId` + `channelId` are provided (and `oauthProvider` is Microsoft) even if `deliveryMethod` is omitted. This prevents silent fallback to the Incoming Webhook path and "sent" logs without posting to the intended channel after the node refactor.
- Replaced account email comparisons with ID-based validation for Google, Slack, and Microsoft Teams actions. Workspace connections are validated by `connectionId` ownership, and personal connections optionally verify `connectionId` when supplied. This eliminates brittle email matching and aligns node validation with repository-backed identifiers.
- Action outputs now include `connectionScope` and `connectionId` so nodes can detect stale selections without relying on emails. This surfaces enough metadata for the UI to reconcile saved selections across plan changes and connection rotations.
- Messaging and Google action tests now construct WorkspaceOAuthService with the workspace repository dependency so the new membership checks run while refreshing workspace tokens.
- Added `ensure_run_membership` in `mod.rs` and wired Slack, Teams, and Sheets workspace branches through it so we short-circuit with a `Forbidden` error (and dedicated tests) before touching shared OAuth tokens or external APIs when a run's actor is no longer a workspace member.
- Workspace connection contexts for Slack, Teams, and Sheets now emit the `owner_user_id` (replacing the old `created_by` semantics) so downstream logs/tests know which member shared the credential.
- Workspace action tests now expect optional `user_oauth_token_id` values so nullable workspace connection FKs do not break run-time lookups.
- Google Chat messaging tests now assert the expected failure directly instead of a tautological check, quieting clippy while keeping the stub-less path covered.
- Action test configs include workspace quota fields so env-driven member/run limits remain wired through the shared AppState helpers.
- Email actions stop returning provider message IDs as `selectedNext` values; executor now falls back to outgoing edges when a selected next node is missing so downstream nodes still run after email sends.
- Added a Formatter action module with typed string/number/json/date/bool transformations, JSON path reuse, and validation to keep logic node outputs predictable and resumable.
- Added an Asana action executor that validates personal/workspace OAuth connections, enforces workspace plan membership, and supports project/task/subtask/comment/tag/user operations via the Asana REST API.
- Asana list tasks now omits the workspace parameter when a project or tag is provided to comply with Asana API rules and avoid 400 errors.
- Asana list tasks now enforces Asana's filter rules (project/tag or assignee + workspace; workspace alone rejected) to prevent invalid requests.
- Asana add-task-to-project requests now only send the task + project IDs (no section payload) to mirror the updated UI flow and templated GID inputs.
- Workspace action tests now populate `connection_id` alongside `user_oauth_token_id` so fixtures reflect promoted OAuth identity semantics.
- Slack revoke handling now uses personal connection IDs for personal tokens and skips revoking personal tokens when a workspace Slack connection is revoked, keeping Slack scopes isolated.
- Removed the unused Slack workspace `created_by` context field after revocation handling stopped relying on it to avoid dead-code warnings.
- Workspace action error mapping now recognizes the Slack workspace-install requirement so Slack promotion failures surface clear messages in actions.
- Slack action fixtures now include `slack_team_id` for workspace connections so Slack token lookups satisfy team-id invariants.
- Slack messaging actions now require a workspace_connection_id for personal-user posting, refresh Slack tokens on token_expired with a single retry, and surface auth_expired errors only when refresh fails.
- Slack messaging action tests now use refresh overrides and a synchronous token repo update path to satisfy Send bounds and clippy in mocked refresh flows.
- Slack messaging now enforces explicit identity selection (`workspace_bot` vs `personal_user`) and checks Slack team IDs at execution time when posting as a user.
- Slack personal-user execution now decrypts stored Slack team metadata before comparing with workspace team ids so encrypted values do not trigger false mismatches.
- Slack personal-user execution now accepts either encrypted or legacy plaintext Slack team ids, validating format after decrypt fallback and returning a reconnect prompt when metadata is missing or invalid.
- Added Notion action executors for create/update/query/database operations with type-aware property mapping, connection-scope validation, and error handling aligned with OAuth/token ownership rules.
- Notion query results now wrap page summary mapping to avoid move/borrow conflicts while streaming page payloads.
- Notion action helpers now use an `if let` object destructure in select-property mapping, and tests import OAuth token types from the db repository module.
- Action test configs now set webhook ingress dedupe mode so Config stubs remain complete.
- Action test configs no longer include `WEBHOOK_SECRET` after removing workflow-scoped webhook settings.
- Added an action registry definition layer so executors register explicit action types and validate registrations at startup.
- Scoped action registry types to crate visibility so internal graph nodes are not exposed in public interfaces.
- Added per-action manifests (required fields + semantics) and centralized manifest-to-executor registration in the actions module.
- Formatter validation now runs in the action validator (with config parsing), so execute_formatter assumes validated configs and registry resolution no longer carries required_fields.
- Delay and formatter executors now live in their respective modules and implement ActionExecutor directly, keeping registry dispatch generic.
- Action test fixtures now include the integration registry in AppState so shared state wiring stays consistent.
- Normalized action error strings to ASCII (Settings -> Integrations) to fix encoding corruption.
- Added startup-loaded JSON action manifests that map to existing executors so new HTTP action nodes can be registered without new Rust action modules.
- Added an action manifest registry accessor so routes can expose a read-only action catalog without touching executor logic.
- Tightened HTTP action templating so methods and URLs render/validate explicitly, and added a debug log for resolved method/host with allowlist mode.
- Action manifest inputs now allow more field types with optional min/max metadata and enforce enum/number validation plus schema updates.
- Action manifest input validation now rejects options/min-max on non-enum or non-number inputs to keep manifests strict.
