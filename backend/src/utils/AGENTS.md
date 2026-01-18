# Utils Agent Notes

## Purpose
- Shared helper modules reused across routes, services, and the engine.
- Keep business logic thin; these modules should remain pure or side-effect free (except explicit crypto/HTTP helpers).

## Modules
- `csrf.rs`: Middleware helpers to mint CSRF cookies and validate tokens on mutating requests.
- `encryption.rs`: AES-256-GCM helpers for encrypting/decrypting OAuth secrets; includes base64 key decoding.
- `jwt.rs`: Wraps `jsonwebtoken` to create/verify HS256 tokens using `JWT_SECRET`.
- `password.rs`: Argon2 hashing/verification with automatic salt generation.
- `plan_limits.rs`: Normalizes plan tiers and inspects workflow graphs for plan violations (premium nodes, node counts, schedules).
- `schedule.rs`: Parses schedule configs, computes next run times, and converts between chrono and `time` crate types.
- `secrets.rs`: Manipulates the nested JSON secret store, providing read/modify helpers and validation enums.

## Usage Tips
- Keep new helpers deterministic and add unit tests in the same file when possible.
- When extending plan enforcement logic, update both `assess_workflow_for_plan` and downstream callers (workflows routes) to surface new violation codes/messages.
- Encryption helpers expect 32-byte keys; use `Config::from_env` to source them.

## Change Reasons
- Plan limit and secret collectors now infer messaging integrations from `service`/`provider` fields because the legacy `platform` parameter has been retired from workflow nodes.
- Secret store helpers now use `API_SECRETS_ENCRYPTION_KEY` for encrypting/decrypting stored API keys, signal when legacy plaintext values need rewriting, and support rotation with the shared helper script.
- Added a change-history helper that resolves actor labels and fans workspace-level audit diffs across all workflows so settings logs can track shared events.
- Plan limits now flag Notion polling triggers/actions as Workspace-only nodes to align UI gating with backend enforcement.
- Added egress allowlist normalization helpers to trim/validate host entries before they reach runtime enforcement.
