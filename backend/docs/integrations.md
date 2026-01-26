# Integrations

## Overview
DSentr integrations are the contract between the backend and the rest of the system for how an external service is authenticated and used. Every integration is described by an IntegrationManifest. If it is not in the manifest, it is not supported.

Manifests exist to make behavior declarative. Routes do not branch on providers. The registry loads all manifests at startup and validation failures stop the service immediately so invalid combinations are not allowed to run.

Registry location and loading:
- Registry code lives in `backend/src/integrations`.
- Manifests are registered in `build_integration_registry` and validated there.
- The registry is built and stored in `AppState` during startup in `backend/src/main.rs`.

## What an integration is in DSentr
An integration is the combination of:
- Authentication model (OAuth2, API key, or none).
- Ownership and scope semantics (personal, workspace, or both).
- Constraints on how connections are created and enforced.
- UI metadata for Settings and other surfaces.
- Actions/triggers implemented in the workflow engine.

The manifest is the contract that drives UI, routing, and enforcement.

## IntegrationManifest schema
Fields are defined in `backend/src/integrations/manifest.rs`.

- `integration_id`: The stable string identifier. It is normalized to lowercase and used as the primary key in the registry and routes.
- `auth_type`: `OAuth2`, `ApiKey`, or `None`. Drives OAuth routing and validation.
- `token_scope`: `Personal`, `Workspace`, or `PersonalAndWorkspace`. Declares which token scopes the integration supports.
- `ownership_model`: `PersonalOnly`, `WorkspaceOnly`, or `Hybrid`. Declares who can own connections.
- `provider_constraints`: Constraint flags that apply generically to any integration.
  - `workspace_first`: A workspace connection must exist before any personal tokens are accepted.
  - `single_install_per_workspace`: At most one workspace connection per workspace.
- `ui_metadata`: Display metadata for Settings and other UI surfaces.
  - `display_name`, `description`, `icon_key`, `docs_url`.
- `oauth_metadata`: OAuth-specific settings. Required when `auth_type` is `OAuth2`, and must be omitted otherwise.
  - `scopes`: OAuth scopes to request.

Which fields affect what:
- UI: `ui_metadata`, `token_scope`, `ownership_model`, `provider_constraints`.
- Routing: `integration_id`, `auth_type`, `oauth_metadata`.
- Enforcement: `token_scope`, `ownership_model`, `provider_constraints`, and the auth type rules above.

Invalid combinations are rejected at startup by registry validation.

## Ownership models and token scopes
Supported shapes are:
- Personal-only: `token_scope = Personal` and `ownership_model = PersonalOnly`.
- Workspace-only: `token_scope = Workspace` and `ownership_model = WorkspaceOnly`.
- Hybrid: `token_scope = PersonalAndWorkspace` and `ownership_model = Hybrid`.

The `token_scope` and `ownership_model` must align. Any mismatch is rejected at startup.

## Slack workspace-first semantics (example constraints)
Slack is the current example of a workspace-first integration. These behaviors are expressed by generic constraints and ownership rules, not by name-based branching.

Constraints and semantics:
- One bot install per workspace: `single_install_per_workspace = true` ensures only one workspace connection can exist.
- Optional delegated user tokens: With `workspace_first = true` and hybrid support, personal tokens are allowed but not required. They are treated as delegated user tokens that sit alongside the workspace install.
- Mixed team ID rejection: Personal tokens must match the workspace install team identifier. Tokens that do not match are rejected to prevent cross-workspace data leakage and inconsistent identity state.

These checks are enforced generically by constraints and ownership rules; Slack is just the current manifest that sets them.

## GitHub webhook ingress
GitHub webhooks are supported as a GitHub App webhook feed. Webhook subscriptions are stored in DSentr and drive trigger matching.

- Webhook URL format: `/api/webhooks/github/{subscription_id}`
- Required events: `issues`, `issue_comment`, `pull_request`, `push`, `release`
- Signature secret: GitHub sends `X-Hub-Signature-256` using the subscription secret; DSentr rejects mismatches with `401`
- Event type mapping: DSentr uses the `X-GitHub-Event` header (`github.<event>`), and appends `.action` when the payload includes an action (for example, `github.issues.opened`)
- Payload event fields are ignored for event type derivation

Provider webhook routing (GitHub App):
- Provider webhooks are shared and automatic.
- There is no webhook URL per workflow; DSentr uses the single `/webhooks/github` endpoint.
- Activation is driven by workflow publish state (publishing a workflow with a GitHub trigger registers it for routing).

## Adding a new integration
Step-by-step:
1. Add a new manifest entry in `build_integration_registry` with the correct `integration_id`, `auth_type`, `token_scope`, `ownership_model`, `provider_constraints`, `ui_metadata`, and (if OAuth) `oauth_metadata`.
2. Register any required OAuth provider configuration and client logic in the OAuth services layer.
3. Implement the integration's actions/triggers and wire them into the engine action registry.
4. Verify startup validation passes and the integration behaves as expected.

You do not modify Settings OAuth routes or UI to add a new integration.

## Non-goals
- No dynamic manifests.
- No database-driven integration definitions.
- No provider branching in routes.
