# Integrations Agent Notes

## Purpose
- Centralizes integration manifests and registry validation for provider-specific constraints.

## Change Reasons
- Added integration manifests plus a startup registry that validates auth, scope, and Slack workspace constraints.
- Refactored registry validation to derive support from token scope/ownership and removed provider-name checks while enforcing workspace-first invariants.
- Removed OAuth provider enums from manifests so the registry stays integration-centric and OAuth mapping lives in the routing layer.
- Added a GitHub integration manifest so OAuth registry validation and UI metadata include GitHub.
- Declared GitHub as a GitHub App in manifest metadata and added startup validation to require GitHub App configuration when enabled.
- GitHub manifest metadata now reflects current behavior (installation_scoped disabled) and startup validation fails if GitHub App user OAuth is disabled while GitHub App integration is active.
- Integration registry tests now account for the optional GitHub App URL field so config stubs stay aligned with GitHub App settings.
