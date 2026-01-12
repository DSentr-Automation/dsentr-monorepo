# OAuth Routes Agent Notes

## Purpose
- Manage connected OAuth integrations (Google, Microsoft) for workflow actions.
- Implements both the authorization-code handshake and account-management APIs.

## Key Modules
- `prelude.rs`: Common `use` imports (Axum extractors, AppState, ConnectedOAuthProvider, etc.) re-exported for sibling modules.
- `helpers.rs`: Shared constants and utilities-state cookie helpers, manifest lookup, OAuth provider mapping, redirect builders, and error mapping.
- `connect.rs`: `/oauth/{provider}/connect` start + callback endpoints. Exchanges authorization codes and persists tokens via `OAuthAccountService`.
- `accounts.rs`: Authenticated APIs to list, refresh, and disconnect stored connections.
- `tests.rs`: End-to-end tests that validate the helper utilities and account flows.
- `mod.rs`: Re-exports the public handlers used in `main.rs`.

## Usage Tips
- Always validate the returned `state` parameter before exchanging codes; reuse `build_state_cookie`/`clear_state_cookie`.
- When adding new providers, extend `ConnectedOAuthProvider`, add a manifest entry, update the OAuth mapping helper, and build new connect handlers following the existing pattern.
- Redirects back to the frontend include query flags-coordinate expected parameters with the UI before changing them.

## Change Reasons
- Accounts: Listing connections now requires an explicit `workspace` query parameter and verifies membership via `workspace_repo.list_memberships_for_user` before proceeding. This prevents cross-workspace leakage and aligns with workspace context routing elsewhere.
- Accounts: Workspace connections are fetched with `WorkspaceConnectionRepository::list_for_workspace(workspace_id)` instead of a user-membership scan. The handler asserts all returned rows match the requested workspace and returns 403 on any violation.
- Accounts: Added a defensive ownership assertion for personal tokens by cross-checking repository lookups for the authenticated `user_id` and provider before serializing the response. Violations return 403 and are logged.
- OAuth route tests implement the new WorkspaceRepository::is_member helper so WorkspaceOAuthService membership checks work inside the test harness.
- Workspace OAuth tests now cover the shared `get_plan` repository helper so plan-aware services can reuse the mocks without referring back to route modules.
- OAuth route tests and repository stubs now understand multiple workspace connection records so connection-id scoped flows (Microsoft Teams) can assert the selected connection still belongs to the requesting workspace before issuing tokens.
- OAuth integrations listing now blocks Solo-plan workspaces and returns a `workspace_plan_required` error so Settings integrations stay premium-only even when a user belongs to other Workspace plans.
- OAuth route test repositories now implement pending-invite counting to satisfy workspace seat checks that treat invitations as reserved seats.
- OAuth route test repositories stub `stripe_overage_item_id` accessors so the expanded workspace repository trait for metered billing compiles in the OAuth harness.
- Added Asana provider parsing, state-cookie wiring, and start/callback handlers so users can connect Asana accounts through the OAuth flow alongside Google, Microsoft, and Slack.
- Added provider-scoped connection listings and connection-id lookup endpoints so the frontend can target specific personal or workspace OAuth records and receive connection identifiers in responses.
- Refresh and disconnect handlers now require an explicit `connection_id` and return 400 for provider-only requests, removing legacy fallbacks and validating missing-id cases even when matching tokens exist.
- Refresh responses now serialize field names in `camelCase` (e.g., `requiresReconnect`, `connectionId`) to keep the JSON API stable for existing clients and tests.
- Workspace connection listings now include `connectionId` sourced from the promoted personal token so frontend identity matching stays stable after reloads.
- Connection lookup responses now surface workspace `connectionId` from the stored connection record and omit it when unavailable, avoiding any fallback to the workspace row id.
- OAuth callbacks now delegate persistence to the dedup-aware account service entry point so reconnects update existing personal connections by identity.
- Slack OAuth start/callback now require an explicit workspace context, include workspace-aware redirects, and strip incoming webhooks so workspace-scoped flows have no fallback semantics.
- Slack OAuth callback now installs workspace Slack connections via the Slack-specific install helper while storing personal tokens separately for workspace-first isolation.
- Slack OAuth installs now log requested scopes and validate bot token scopes via `auth.test` before persisting workspace connections.
- Slack personal OAuth start now forces `prompt=consent` and locks the `team` to the workspace Slack team id so Slack issues a user token without changing workspace installs.
- OAuth route tests now set `workspace_connection_id: None` when constructing `ConnectQuery` to satisfy the new optional field.
- Slack personal OAuth callbacks now pass Slack tokens through without metadata patching; Slack team ids are captured in the account service so the route layer stays read-only.
- Slack OAuth starts now always use the combined install authorize URL with bot + user scopes and prompt=consent (no team parameter), so personal and workspace flows share a single Slack install path.
- OAuth integrations listing now includes Slack personal authorization state (`has_personal_auth`, `personal_auth_connected_at`) derived from stored user tokens so Settings can show post-as-user status without extra API calls.
- Slack personal authorization timestamp selection now uses `is_none_or` to satisfy clippy without changing behavior.
- Added Notion OAuth start/callback handling with scoped state payloads (user/workspace), token exchange via the Notion API, and workspace promotion support aligned with existing OAuth connection listings.
- Notion OAuth helper utilities now box responses to avoid large Result error warnings, and tests reuse reqwest's Url type to avoid extra dependencies.
- OAuth route test token repositories now use shared mutable state for `mark_shared` so compile-time stubs match the real repository interface.
- OAuth route test stubs now update saved tokens in `mark_shared` so workspace promotion tests can succeed when Notion connections are promoted.
- OAuth route test workspace connection stubs now return a synthetic audit event so workspace promotion flows don't fail on audit logging during tests.
- OAuth route test configs now include the webhook ingress dedupe mode field to keep Config initialization consistent.
- OAuth route test configs no longer require `WEBHOOK_SECRET` after removing workflow-scoped webhook settings.
- OAuth route test fixtures now include the integration registry in AppState to stay aligned with shared state wiring.
- OAuth routes now resolve integrations by ID, map OAuth providers in a routing-local helper, return flat connection arrays, and include manifest metadata plus a generic personal-auth map for workspace-first integrations.
- OAuth routes now share a single integration-resolution helper, use integration-id constants in connect handlers, and align path errors on "integration" terminology.
- OAuth connections listing no longer 409s when workspace-first personal auth exists without a workspace connection; it now returns success and preserves derived personal auth state.
- Added list-connections regression tests to assert workspace-first personal auth returns 200 without workspace connections and uses token updated_at for personal_auth_connected_at.
