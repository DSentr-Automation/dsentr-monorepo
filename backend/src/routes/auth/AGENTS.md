# Auth Routes Agent Notes

## Purpose
- Handles authentication, session management, and account lifecycle flows (signup, login, verification, password reset).

## Key Modules
- `claims.rs`: JWT claim shape shared between encoding/decoding.
- `session.rs`: `AuthSession` extractor that validates the `auth_token` cookie and injects `Claims`.
- `login.rs`: Username/password login plus `/me` endpoint that hydrates workspace context.
- `logout.rs`: Clears session cookie and returns a standard success payload.
- `signup.rs`: Creates users via email/password or OAuth bootstrap, sends verification email.
- `verify.rs`: Confirms email verification tokens and marks account verified.
- `forgot_password.rs`: Issues password reset tokens and sends reset emails.
- `reset_password.rs`: Validates reset tokens and sets new passwords.
- `google_login.rs` / `github_login.rs`: Provider-specific OAuth login flows (start + callback) that exchange codes and set session cookies.
- `mod.rs`: Exports route handlers for easy imports elsewhere.

## Usage Tips
- Reuse `JsonResponse` helpers for consistent error handling; the frontend depends on the `success/message` contract.
- Any new handler that needs authentication should accept `AuthSession` and derive the user ID via `claims.id`.
- Password hashing/verification lives in `utils::password`; keep crypto concerns centralized there.
- Signup handlers must honor workspace invitations: call `workspace_repo.find_invitation_by_token` to validate incoming tokens, attach members or mark invites declined accordingly, and provision a Solo workspace when no invite is accepted.

## Change Reasons
- Login/logout now record client IP addresses (with best-effort geo/proxy detection) and persist login/logout timestamps so admin tooling can review session origins.
- Email/password login now returns the caller's workspace memberships so the frontend can hydrate the workspace switcher without requiring a hard refresh.

- OAuth login without existing account now redirects users to `/signup?oauth=…` with provider/email hints. This ensures they accept the Terms of Service before account creation. The Signup page parses these params to prefill fields and display a friendly notice.
- Signup tests now wire WorkspaceOAuthService with the workspace repository dependency so membership enforcement matches production when exercising invite and plan flows.
- Signup repository mocks now surface the shared `PlanTier` via the new `get_plan` helper so plan-aware backend services can reuse them without importing route modules.
- Signup invite acceptance enforces workspace plan/member caps up front, surfacing the `workspace_plan_required`/`workspace_member_limit` response codes before provisioning the new account.
- Workspace invite flows count pending invitations toward the member cap and respect the configurable `WORKSPACE_MEMBER_LIMIT`/`WORKSPACE_MONTHLY_RUN_LIMIT` values.
- Signup mocks include the `stripe_overage_item_id` workspace field and repository stubs to satisfy billing overage item persistence in auth tests.
- Auth route tests now initialize OAuth settings with placeholder Asana credentials so the expanded provider list compiles across login/signup flows.
- Auth route test configs now set webhook ingress dedupe mode to keep Config stubs aligned.
- Auth route test configs no longer require `WEBHOOK_SECRET` after removing workflow-scoped webhook settings.
