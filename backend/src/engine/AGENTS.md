# Engine Agent Notes

## Purpose
- Executes workflow runs produced by the scheduler/worker.
- Converts stored workflow graphs into runtime structures and dispatches node-specific handlers.

## Key Modules
- `executor.rs`: Main orchestration loop. Builds the in-memory `Graph`, enforces egress allow/block lists, renews run leases, and invokes action/condition/trigger handlers. Persists node run status via `WorkflowRepository`.
- `graph.rs`: Lightweight parser that extracts `Node`/`Edge` metadata from workflow JSON snapshots and builds adjacency lists.
- `templating.rs`: String interpolation helpers (`{{path.to.value}}`) used across actions for mapping context into parameters.
- `actions/`: Handler implementations:
  - `code.rs`: Runs user-supplied JavaScript snippets via Boa with guarded input/output mapping.
  - `email.rs`: Delivers email through SMTP or AWS SES (signing requests manually) with deduplicated recipients.
  - `google.rs`: Writes rows into Google Sheets using stored OAuth tokens.
  - `http.rs`: Makes outbound HTTP requests while honoring allow/deny host lists and attached auth headers.
  - `messaging.rs`: Sends messages to Slack, Microsoft Teams (via Graph), or Google Chat webhooks.

## Usage Tips
- Each action should return `(outputs, next_node)`; keep outputs JSON-serializable because they flow back into the context map.
- When adding new actions, register them inside `actions/mod.rs` and ensure they respect the allowlist/denylist enforcement enforced in `executor.rs`.
- Avoid blocking operations inside actions; always use async HTTP clients and timeouts to keep workers responsive.

## Change Log
- Context key casing: Node outputs are now inserted into the workflow context using the node label's original casing, with a lowercase alias added for backward compatibility. This allows templates like `{{Trigger.Name}}` to resolve while still supporting existing `{{trigger.Name}}` references. Field/property casing remains unchanged and must be matched exactly.
- Executor now prefers `_start_from_node` when seeding `_trigger_context`, ensuring webhook runs targeted to a specific trigger node attach context under that trigger's label.
- Executor now treats `_start_from_node` as authoritative for traversal, avoiding fallback to all triggers when it is present but invalid.
- Snapshot egress allowlists are treated as advisory inputs and intersected with the deployment `ALLOWED_HTTP_DOMAINS` policy. Rejected hosts emit structured warnings and an `egress_policy_violation` run event for audit trails.
- Slack/Microsoft workspace actions now revalidate workspace OAuth connection IDs locally after fetching tokens they confirm the connection belongs to the run's workspace so a misconfigured workflow cannot borrow credentials from another workspace.
- Executor hydrates run snapshots with decrypted secret stores for every run before graph execution and fails runs cleanly if secrets cannot be loaded, preventing plaintext secrets from leaking in execution responses.
- Added runaway protection helpers that count recent workspace runs and surface a dedicated error when limits are exceeded so creation and execution paths can block runaway workflows safely.
- Formatter node execution added with typed operations (string/number/json/date/bool), JSON path access, and snapshot-friendly outputs to reshape data synchronously between steps.
- Action router now registers the Asana executor (`actionType: "asana"`) so workflow runs can call Asana project/task APIs using personal or workspace OAuth connections while respecting plan membership.
- Executor test configs now set webhook ingress dedupe mode so Config stubs stay in sync.
- Executor test configs no longer include `WEBHOOK_SECRET` after removing workflow-scoped webhook settings.
- Executor tests now capture node ids outside async mocks to satisfy Rust lifetime requirements during upsert assertions.
- Engine startup now builds an explicit action registry and executor dispatch resolves every node through registered actions.
- Action registry exports are scoped to the crate so engine/worker share the registry without exposing internal node types.
- Action registry construction now uses action manifests and centralized registrations for executors and validators.
- Executor entrypoints are now crate-scoped to keep the action registry internal while still allowing the worker to dispatch runs.
