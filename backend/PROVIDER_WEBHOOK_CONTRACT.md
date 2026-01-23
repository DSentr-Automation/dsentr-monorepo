# SYSTEM-LEVEL PROVIDER WEBHOOK CONTRACT

## 1. System Context

The system currently supports user-created webhook sources that are workspace-scoped, require explicit configuration per workspace, consume workspace quota, and store encrypted secrets per webhook source. Webhook URLs are user-defined and unique per workspace.

This model breaks down for first-party provider integrations because:
- Provider platforms (GitHub, Asana, etc.) require single, canonical webhook endpoints per application
- Events must be accepted even when no user workflow exists to handle them
- Provider webhooks serve multiple workspaces simultaneously, not individual workspaces
- Provider secrets are deployment-level infrastructure, not user-configurable credentials
- Registration and lifecycle management occurs at the provider platform, not in user workflows

The current GitHub implementation reuses user webhook infrastructure in places where provider-level invariants already differ, creating architectural drift that cannot scale to additional providers without a clear contract.

## 2. Motivation for Provider Webhooks

Provider webhooks are required because:

**Single Endpoint Requirement**: Providers like GitHub allow only one webhook URL per application registration. User-created webhooks would require each workspace to register separate webhooks, which is impossible at scale and violates provider platform constraints.

**Pre-emptive Event Acceptance**: The system must receive and validate provider events before any user workflow exists to handle them. User webhooks require existing workflow configuration to receive events, which prevents new users from activating provider integrations.

**Cross-Workspace Event Distribution**: Provider events often affect multiple workspaces (e.g., organization-wide repository changes). User webhooks are workspace-scoped and cannot efficiently route events to multiple matching workflows across different workspaces.

**Provider Security Model**: Provider platforms expect application-level secrets and endpoint stability. User-managed webhook secrets and URLs would compromise the security contract with external providers.

**Event Ordering Reality**: Provider platforms may retry, batch, or reorder events; the system must tolerate out-of-order delivery without relying on user-level webhook semantics.

## 3. Definition: What Is a Provider Webhook

A provider webhook is a deployment-scoped, system-owned ingress endpoint that:

- **Ownership**: Belongs to the deployment, not any user or workspace
- **Scope**: Global to the deployment, serves all workspaces
- **Cardinality**: Exactly one per provider per deployment
- **Identity**: Identified by provider name, not user-supplied identifiers
- **Lifecycle**: Created by the system via configuration, not through user interface
- **URL Shape**: Fixed pattern per provider (e.g., `/webhooks/{provider}`)
- **Secret Source**: Environment-configured; may be cached encrypted in the database but must be treated as read-only infrastructure data
- **Mutation Rules**: Immutable during runtime, changes require deployment

Provider webhooks are infrastructure components, not user-configurable features.

## 4. Provider vs User Webhooks (Explicit Contrast)

| Dimension | Provider Webhook | User Webhook |
|-----------|------------------|--------------|
| **Identity** | Provider name (global) | User-defined name (workspace-scoped) |
| **Ownership** | System/Deployment | User/Workspace |
| **Secret Source** | Environment configuration | Database-encrypted per webhook |
| **Mutation Rules** | Deployment-required | User-creatable, user-rotatable |
| **Quota Behavior** | Separate from user webhook quota | Consumes workspace quota |
| **Failure Modes** | System-level logging, no user errors | User-visible error messages |
| **Creation** | System boot/configuration | UI/API per workspace |
| **Deletion** | Deployment shutdown | User deletion per workspace |
| **URL Shape** | Fixed per provider | User-chosen per workspace |
| **Workspace Association** | Routes to all matching workspaces | Single workspace only |
| **Visibility** | System administration only | Workspace member visible |
| **Authorization** | Bypasses workspace auth at ingress only | Requires workspace membership |

## 5. Secret Management Model

Provider webhook secrets originate exclusively from environment configuration at deployment time. Secrets are not user-rotatable and must not be editable through any user interface. Secrets may be persisted as cached encrypted values but must remain read-only during runtime operation. Validation must rely on the environment secret as the source of truth; any persisted encrypted form must not affect signature verification semantics. Secret rotation requires deployment updates, not runtime mutations.

## 6. Runtime Behavior and Invariants

**Ingress Flow**: Event arrives → Provider-specific validation → Event normalization → Fan-out to matching workflows → Workspace-scoped execution

**Required Invariants**:
- Provider events are validated using provider-specific signature algorithms
- Routing occurs after successful validation, never during webhook registration
- Events fan-out to all matching workflows across all workspaces
- Execution context remains workspace-scoped during workflow runs
- Provider webhooks never consume user webhook quota
- No workspace authorization bypass occurs during workflow execution
- System logs all provider webhook activity independently of workspace logs
- Failed validation results in immediate rejection without workspace routing
- Provider webhooks never expose secrets through APIs or logs
- Provider webhook ingestion must be idempotent at the event identity level, independent of workspace fan-out
- Provider webhook ingestion must not assume the existence of any workflow at receipt time

**Failure Isolation**: Provider webhook failures must not affect user webhook functionality. Workspace execution failures must not stop routing to other workspaces.

## 7. Security and Isolation Guarantees

Provider webhooks must not be modifiable by any user, including administrators. Provider webhook secrets must never be exposed through APIs, logs, or database queries. Provider webhooks must bypass workspace authorization checks during ingress but must enforce workspace isolation during workflow execution. No privilege escalation path may exist where accessing a provider webhook grants unauthorized workspace access. All provider webhook activity must be auditable separately from user webhook activity.

Provider webhook endpoints must never share code paths that allow mutation of webhook sources, secrets, or enabled state.

## 8. Non-Goals (Hard Exclusions)

**Explicitly Banned**:
- Provider webhooks in the UI editor
- Per-workspace provider secrets
- User-triggered provider webhook rotation  
- Mixing provider webhooks with workflow-level webhook URLs
- Multiple secrets per provider
- Per-workspace provider webhooks
- Per-provider custom quota models
- Automated secret rotation
- Test strategy documentation
- Future providers beyond GitHub

**Out of Scope**: Any provider-specific business logic, UI components for provider webhooks, or integration patterns beyond the reference GitHub implementation.

## 9. Forward Compatibility Constraints

Provider webhooks must remain distinguishable from user webhooks through all interfaces. Identity model must remain stable across provider additions. Execution semantics must remain explicitly distinct between provider and user webhooks and must never be unified behind feature flags. New providers must follow the same contract without exceptions. No future changes may require existing provider webhooks to be recreated or migrated. The distinction between system infrastructure and user configuration must remain absolute.

## 10. Success Criteria

The system is correct if:
- A provider webhook can be received with zero user configuration
- No user can alter provider webhook behavior through any interface
- No workspace quota is consumed by provider webhook execution
- Existing user webhook behavior remains unchanged
- Provider webhooks route to all matching workspaces without user intervention
- Provider webhooks are observable, auditable, and limitable without consuming user webhook quota
- No implicit free runs occur for provider webhooks
- The feature can be removed without data loss or corruption to user webhooks
- Removing provider webhooks must not require migrating or rewriting user webhook data