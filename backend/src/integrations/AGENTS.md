# Integrations Agent Notes

## Purpose
- Centralizes integration manifests and registry validation for provider-specific constraints.

## Change Reasons
- Added integration manifests plus a startup registry that validates auth, scope, and Slack workspace constraints.
- Refactored registry validation to derive support from token scope/ownership and removed provider-name checks while enforcing workspace-first invariants.
- Removed OAuth provider enums from manifests so the registry stays integration-centric and OAuth mapping lives in the routing layer.
