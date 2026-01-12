# Action Manifests: Schema, Validation, and Secrets

This document explains the design intent of the manifest-driven action system, with a focus on the role of the JSON schema and the current handling of secrets.

This behavior is intentional for v1.

## Role of the JSON Schema (v1)

The file [bt]action_manifest_v1.json[bt] defines the contract for action manifests.

In v1, the schema is:

- The authoritative definition of the manifest shape
- A shared reference for backend, UI, and tooling
- A stable target for future validation and automation
- A guardrail against ad-hoc or ambiguous manifest structure

The schema is not enforced at runtime in v1.

## Why the schema exists without runtime enforcement

The schema exists even without enforcement for concrete reasons:

- Rust-side startup validation already enforces required invariants
- Cross-field and executor-specific validation is clearer and safer in Rust
- The schema is still evolving; enforcing it too early would lock in mistakes
- JSON Schema engines add dependencies and complexity without immediate payoff

The schema should be treated as a contract and documentation source, not as an execution gate.

## Runtime validation approach (v1)

In v1, validation is performed explicitly in Rust during startup:

- All manifest files are loaded at startup
- Required fields are checked
- Action identifiers must be unique
- Executor references must resolve to existing primitive executors
- Executor-specific configuration is validated
- Any validation failure crashes startup immediately

This ensures deterministic behavior and avoids partial or degraded action availability.

## Secrets in action manifests (v1 behavior)

Action manifests may reference secrets using templated placeholders such as:

[bt]{{secrets.some_path}}[bt]

In v1, secret references are:

- Not validated at startup
- Not scoped or allowlisted
- Not checked for existence before execution

Secret interpolation is treated as a runtime concern of the executor.

## Why secret validation and scoping are deferred

Secret scoping and validation are intentionally deferred because they require design decisions that are not yet frozen:

- Whether secrets are scoped to user, workspace, integration, or action
- Whether manifests must declare required secrets explicitly
- How missing or unauthorized secrets should fail (startup vs runtime)
- How secret access should be surfaced in UI and audits

Implementing partial scoping without these decisions would encode incorrect assumptions and make future changes harder.

## Future direction (v2, non-binding)

A future iteration may introduce:

- Enforced JSON schema validation at startup or in CI
- Explicit secret requirements declared in manifests
- Scoped secret access tied to integrations or executors
- Clear startup or execution-time errors for missing or unauthorized secrets

These changes are explicitly out of scope for v1.

## Explicit non-goals (v1)

The manifest-driven action system does not:

- Support runtime loading or hot reload of manifests
- Execute arbitrary code or scripts from manifests
- Introduce new executors or modify existing executor behavior
- Change OAuth flows, token handling, or integrations
- Provide security guarantees around manifest-defined secret references

These constraints are intentional to keep the system simple, deterministic, and safe to extend incrementally.
