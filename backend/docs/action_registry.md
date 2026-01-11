# Action Registry Notes

## Purpose
- Document how action manifests, registry wiring, and execution semantics are modeled in the engine.
- Capture rules that keep the executor generic and prevent action-specific branching.

## Action Manifest Model
- Each action module must export a `MANIFEST` with:
  - `action_type`: the canonical action type string used for registration and lookup.
  - `required_fields`: field names the node data must contain (non-null).
  - `execution_semantics`: one of `Standard`, `Conditional`, or `Resumable`.
- Manifests are the source of truth for action registration and validation.

## Registry Rules
- Registrations are explicit (no auto-register, no lazy globals).
- Startup panics if:
  - an action type is registered more than once,
  - a manifest omits an executor or validator,
  - a required action type is missing,
  - a node kind alias points to an unregistered action.
- Runtime resolution errors are fatal for the run; unknown actions are not skipped.

## Execution Semantics Contract
- `Standard`: action runs immediately and returns `ActionExecutionResult::Immediate`.
- `Conditional`: action returns `Immediate` and uses outputs to select the next edge.
- `Resumable`: action may return `Pause` with a resume timestamp; `Pause` is invalid for any other semantics.

## Engine Invariants (No Branching)
- The engine must not branch on `node.kind` or `actionType` to decide execution paths.
- Delay and formatter are not exceptions; they resolve through the same registry path as every action.
- Any action-specific behavior belongs in its executor/validator, not in `executor.rs`.

## Action Author Checklist
- Define a `MANIFEST` with `action_type`, `required_fields`, and `execution_semantics`.
- Implement an `ActionValidator` that:
  - enforces `required_fields`,
  - parses and validates configs specific to the action.
- Implement an `ActionExecutor` that returns the correct `ActionExecutionResult` for the semantics.
- Register the manifest + executor + validator in `actions::action_definitions`.
- Add the action type to `REQUIRED_ACTION_TYPES` if the engine expects it at startup.
