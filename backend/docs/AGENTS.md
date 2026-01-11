# Docs Agent Notes

## Purpose
- Reference material for operational runbooks that support the backend team.
- Does not ship with the binary; used manually by engineers when configuring or repairing the service.

## Files
- `oauth_redirects.md`: documents the exact OAuth callback URLs and required environment variables for Google and Microsoft integrations. Use it when provisioning credentials in provider dashboards or setting up local `.env` files.
- `integrations.md`: documents the IntegrationManifest contract, ownership/scope rules, and the step-by-step process for adding integrations.
- `remove_duplicate_workspace_orgs.sql`: transactional cleanup script that deduplicates organizations/workspaces after the historical subscription bug. Always wrap execution in a manual transaction and review row counts before committing.

## Usage Tips
- Keep these docs updated whenever OAuth URLs or required secrets change, otherwise onboarding breaks silently.
- For SQL maintenance scripts, list the expected preconditions and postconditions directly in the file so production support knows how to validate execution.

## Change Reasons
- Documented Stripe OAuth and webhook secrets alongside existing provider guidance so billing setup stays aligned with backend config.
- Added egress allowlist enforcement notes so engineers understand how snapshot metadata interacts with environment policies and audit logging.
- Added plan limit reference (member/run quotas + error codes) so API consumers know how to handle `workspace_plan_required`, `workspace_member_limit`, and `workspace_run_limit` responses.
- Listed the Asana OAuth callback URL and environment variables so credential provisioning stays consistent with the new integration.
- Added the Notion OAuth callback URL and env var list so credential setup stays aligned with the integration config.
- Removed the legacy workflow webhook secret runbook after deprecating workflow-scoped webhook tokens.
- Added an action registry note covering manifests, execution semantics, and no-branching rules for engine dispatch.
- Added an integrations manifest guide so backend updates follow the manifest contract and avoid provider-specific routing changes.
