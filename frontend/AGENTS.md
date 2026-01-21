# Frontend Agent Notes

Vite build output (warnings-free):
- Added Rollup chunk splitting to group large vendor deps (React, XYFlow, framer-motion, router, zustand, etc.) and reduce main bundle size.
- Raised `chunkSizeWarningLimit` and silenced non-actionable Rollup warnings (`CIRCULAR_DEPENDENCY`, `CHUNK_SIZE_LIMIT`) via `onwarn` so `npm run build` is free of noisy warnings in CI.
- Enabled treeshake, esbuild minification, disabled sourcemaps and compressed size reporting for faster, cleaner builds.
## Context
- The frontend is built with Vite + React + TypeScript, using Tailwind CSS, Zustand for state, and a React Flow-powered visual a
utomation canvas.
- Many components are memoized and rely on stable references; inadvertent prop or context changes can trigger runaway re-render
loops, especially in the React Flow canvas.

## Required Practices
- All tests go in /tests directory. No tests go anywhere under /src
- Always run `npm run lint` and `npm test` before submitting frontend changes. Keep in mind that linting and tests take quite a
few moments so patience is required for them to finish
- When altering canvas nodes, edges, or shared hooks, audit for dependency cycles and ensure state setters are wrapped (e.g., `u
seCallback`, `useMemo`) to prevent infinite renders.
- Follow the established ESLint + Prettier formatting rules; avoid disabling lint rules unless necessary and documented.
- React Flow safe patterns (must be used and commented in code):
  - Initialize local state from props once using useRef mounted flag.
  - No state changes during render.
  - useEffect with correct dependency arrays.
  - useCallback for handlers.
  - Only call parent onUpdate when deep-equality shows change.
  - Debounce inputs that propagate to parent.
  - When mirroring props into local state, keep a `useRef` snapshot of the last payload and short-circuit updates when the next payload is structurally identical. This avoids the React Flow "maximum update depth" loop caused by dispatching redundant setter calls from effects.
- Signup flows that accept workspace invites must route all query parsing through `parseInviteQuery` in `src/lib/inviteQuery.ts` so redirects and conflict detection stay consistent with backend expectations.
- Invitation acceptance must always go through a confirmation modal with explicit Accept/Decline actions so users can opt out before hitting the API.
- The dashboard header now includes a global workspace switcher. It must stay synchronized with `useAuth().currentWorkspaceId`, auto-select a sole workspace, and keep the router query string (`?workspace=`) up to date whenever the selection changes.
- Leaving a workspace is initiated from the Members settings tab. The "Leave workspace" button must be disabled for owners, call the `leaveWorkspace` API when allowed, refresh cached memberships, and send users back to their Solo workspace (or next available one) when the server responds with `403`.

## Change Reasons
- Workflow flyout width increased (about 2x) so node configuration has more breathing room when editing.
- Workflow canvas nodes now keep configuration in the flyout only; canvas cards are minimal, open the flyout on selection, and defer API-heavy option loads until the flyout is visible (e.g., Asana dropdowns) to avoid thundering herd calls on load.
- Refreshed public navigation styling and added a Dashboard shortcut for authenticated users before logout.
- Added a public Pricing page covering Solo and Workspace plans (pricing grid, callout, FAQ) and routed it via /pricing in the marketing layout.
- Added a static sitemap at `public/sitemap.xml` that lists all public/non-auth pages plus the documentation site to improve search engine indexing coverage.
- Normalized `src/Pricing.tsx` formatting to satisfy prettier linting during sitemap work; no behavior changes.
- Dashboard now consumes workflow SSE updates and shows conflict banners so workspace collaborators stay synced and avoid overwriting each other's saves.
- Removed the "Test Action" buttons from action nodes to keep the workflow canvas focused on configuration instead of per-node manual execution.
SheetsAction credential fallback guard:
- Prevent Sheets action nodes from silently auto-selecting the personal Google credential after a shared workspace credential disappears. Track when we clear a workspace selection and suppress the automatic fallback so users must explicitly pick another connection, keeping React Flow updates bounded.

Runaway workflow protection toggle:
- Settings ?+' Workflows now surfaces a Runaway Protection checkbox that reads/writes `workflows.runaway_protection_enabled` via `/api/options/user-settings` with optimistic updates so workspaces can disable runaway run blocking when needed.

OAuth connections response normalization:
- `fetchConnections` now tolerates API responses where `personal`/`workspace` are provided as flat arrays instead of provider buckets by grouping entries client-side. This keeps the cached snapshot populated for tests and production regardless of response shape.
- OAuth cached snapshot helpers now normalize `connectionId` to `undefined` (not `null`) and guard against `null` workspace connection ids so TypeScript builds stay strict while still tolerating partial API/test data.
- Settings > Integrations: integration cards now read labels/scopes/constraints from integration manifests so workspace-first guidance and personal-auth prompts are manifest-driven without provider-specific checks.
- Settings > Integrations cleanup: merge manifest defaults once per manifest and keep integration ids as plain strings until the OAuth API boundary to reduce legacy provider enum leakage without changing behavior.
- Normalized `frontend/AGENTS.md` encoding by removing the UTF-8 BOM so the file starts with a literal `#` and stays ASCII-safe.

Vite 7 migration:
- Moved Vitest options into `vitest.config.ts` and removed the `test` field from `vite.config.ts` because Vite 7's `UserConfig` no longer includes `test`. Mirrored aliases/plugins so test transforms and import paths match the app.

Vitest config type compatibility:
- Removed Vite plugins from `vitest.config.ts` to avoid cross-package `PluginOption` type mismatches between Vitest’s bundled Vite types and the app’s Vite types. Vitest/esbuild handles JSX/TS without these plugins; aliases are preserved for import resolution.

Lint hygiene:
- Added `vitest.config.ts` to `tsconfig.node.json` includes so ESLint’s typed parser (`parserOptions.project`) can resolve it and avoid parsing errors.
- Removed temporary root-level re-export shims (`frontend/DashboardLayout.tsx`, `frontend/IntegrationsTab.tsx`) and updated tests to import via `'@/components/...` paths. `tsconfig.app.json` now includes only `src` again.
- Updated ESLint rule `react-refresh/only-export-components` to allow exports `useSecrets` and `SecretsContext`, matching our context/provider pattern without forcing file splits.
- Stabilized React hooks deps in `src/components/ui/InputFields/NodeSecretDropdown.tsx` by using a shared empty object constant instead of recreating `{}` each render.
Additional TypeScript build fixes (build hygiene):
- Excluded 	ests from 	sconfig.app.json so app builds don’t typecheck test files. Added missing TS path aliases (@components, @hooks, @utils, @assets) to mirror Vite aliases.
- Replaced uses of JSX.Element in public props with ReactNode to avoid JSX namespace issues in TS 5.x with React 19.
- Normalized import casing and resolved duplicate-casing conflicts (e.g., UI/dialog vs ui/dialog, Settings vs settings). Kept a single canonical path to avoid TS1261 on case-insensitive filesystems.
- React Flow: wrapped control callbacks to accept mouse events, ensured WorkflowEdgeData and ActionNodeData extend Record<string, unknown>, and cast node/edge data where needed to satisfy @xyflow/react v12 generics.
- Workflow selectors: relaxed generic constraints from Record<string, unknown> to object and removed Object.freeze returns to avoid "readonly to mutable" assignment errors. Preserved immutability via cloning where it matters.
- Teams action: removed empty-string assignments to ConnectionScope (use undefined/delete), coalesced option types, fixed readonly dropdown arrays via spreads, and tightened diff/patch typing to avoid index/union assignment errors.
- Fixed minor TS issues: implicit any in trigger dropdown, safe conversions to string for numeric NodeInputField values, label type on edges (use undefined instead of 
ull), and Signup form access to string fields.
- Removed or referenced unused locals (e.g., timers, memo caches) to comply with 
oUnusedLocals.
- Removed the Members tab workspace selector so the dashboard header switcher is the single mechanism for context changes.
- Updated Members tab data loading so workspace viewers don't get redirected when invite lists return 403 responses.
- Allowed the Members tab to keep viewer contexts active by loading roster data even when invite management remains restricted.
- Skipped invite fetching for non-admin workspace members so the Members tab avoids unnecessary API calls and 403 responses.
- Secrets tab now scopes API requests by workspace so shared secrets remain visible across members while enforcing creator/admin deletion rules.
- Secrets tab now opens a confirmation modal before deleting entries, warning that removal is irreversible and may impact dependent workflows.
- Workspace selection now falls back to a user's owned workspace when their previously active workspace is unavailable so dashboard context stays consistent after membership changes.
- Logs tab now summarizes executed workflow runs with a human-readable timeline while keeping a copy-to-clipboard option for the raw JSON payload.
- Logs tab now enriches workflow run summaries with trigger origin, credential usage, and node subtype context derived from execution snapshots.
- Logs tab change-history entries now resolve actor names from workspace membership so admins can see who performed workspace-level actions.
- Integrations tab now lets admins revoke shared OAuth connections without deleting the owner's personal credential.
- Workflow nodes clear shared workspace credential selections when the shared connection is removed so users must choose an available credential explicitly.
- OAuth connection selectors update in real time when workspace credentials are promoted or removed, so open workflows reflect changes without refreshing.
- Shared credential removal flows now warn about potential workflow failures and ensure personal disconnects also revoke shared workspace connections.
- Integrations tab now surfaces an Asana card with OAuth connect/disconnect support using the new backend provider and displays both personal and workspace connections.
- Added an Asana action node (palette + flyout) with connection selector, plan restriction messaging, and operations for managing Asana projects, tasks, subtasks, comments, tags, and users.
- Asana node now fetches workspaces/projects/sections/tags/teams/users from the selected connection and renders dropdowns alongside manual GID inputs so users don’t have to look up IDs.
- Asana node now enforces Workspace-plan-only UI (Solo shows an upgrade notice), replaces GID labels with dropdowns for tasks/comments, adds due-on/at toggling with pickers only, and prevents solo users from triggering metadata fetches.
- Asana node dropdown fetch effects are gated by visibility to avoid redundant API calls while hidden fields stay collapsed, and the assignee label now omits “GID” for consistency with other fields.
- Asana create task now leaves project selection optional with a default "No Project" choice, shows the name/optional fields as soon as a workspace is selected, and pins the project dropdown to the top of the optional section so tasks can be created without assigning them to a project.
- Asana update task now supports a "No Project" selection that reveals a manual Task GID input (fetches details on blur, auto-populates fields, hides the task dropdown), while keeping optional fields available once a task GID is provided.
- Manual Task GID entry (No Project path) no longer triggers an API fetch or auto-prefill; dropdown task selection still pre-fills fields as before.
- Asana get task now restores project dropdown visibility after workspace selection and task dropdown visibility after project selection.
- Asana list tasks now includes a "No Project" choice, shows tag/assignee with workspace, and validates that project, tag, or assignee+workspace is present to satisfy Asana filtering rules.
- Asana list tasks now offers "No Tag" and "No Assignee" dropdown choices so users can explicitly clear those filters while following the allowed query combinations.
- Asana delete task supports a "No Project" option that hides the task dropdown and shows a manual Task GID input when no project is chosen.
- Asana action fields are now sequenced strictly by dependency (connection ? operation ? workspace ? downstream choices), and project/tag/team/user fetches run only when their dropdowns are visible to stop circular API triggers while configuring nodes.
- Action nodes now deep-compare local state before notifying the canvas so update notifications don't trigger infinite React Flow rerender loops.
- Action node prop-to-state sync skips redundant param updates to prevent React Flow dirty-check loops when toggling node UI.
- Condition nodes now deep-compare update payloads before notifying the canvas so toggling other nodes or edges doesn't trigger infinite workflow rerenders.
- Action nodes no longer mirror their entire config payload in unused state, avoiding React Flow effect loops when props update with identical data.
- Action nodes now guard prop-to-state synchronization so redundant dirty resets can't cascade into React Flow depth errors when interacting with nodes or edges.
- Action nodes now cache the last prop snapshot before syncing local state so identical data stops propagating through the canvas and avoids infinite update loops.
- Action node controller logic has been extracted into a shared hook so future node variants can reuse the guarded state sync, plan restriction notices, and dirty tracking patterns without duplicating React Flow safety checks.
- React Flow canvas documentation now calls out the cached-snapshot guard so future node work avoids reintroducing maximum update depth errors.
- Teams action now deduplicates Microsoft connection snapshots before mutating state so identical OAuth updates stop retriggering canvas loops.
- Messaging action caches the last emitted payload and only notifies parents when selections actually change, preventing redundant React Flow updates.
- Messaging action now derives platform payloads directly from the workflow store, sanitizes params on platform switches, and resets validation state to avoid stale cache refs.
- SendGrid action synchronizes props via snapshots and suppresses redundant onChange emissions to avoid React Flow maximum update depth errors.
- Workflow canvas edge menu regression: many persisted edges used `type: 'default'`, but `edgeTypes` only registered `nodeEdge`. Mapped both `nodeEdge` and `default` to `NodeEdge` in `src/layouts/DashboardLayouts/FlowCanvas.tsx` so clicking edges shows the delete/style menu again without mutating persisted edge types.
- Edge selection reliability: `NodeEdge` now passes `id` to `BaseEdge` and sets `interactionWidth={24}` so the edge reliably receives click/selection events and the menu appears. Previously, missing `id` could prevent React Flow from mapping interaction events to the correct edge, and a thin stroke made clicks hard to register.
 - Edge selection was being cleared: the canvas selection sync helper was unselecting all edges on any selection change, which prevented the `NodeEdge` menu from appearing. Updated `syncSelectionToStore` in `src/layouts/DashboardLayouts/FlowCanvas.tsx` to only sync node selection and leave edge selection to React Flow.
- Custom code action now normalizes state snapshots, caches the last emission, and guards prop-to-state sync so React Flow doesn't hit maximum update depth while editing scripts or IO pairs.
- Teams action now initializes its connection sanitizer before dependent callbacks so React Flow renders don't encounter temporal dead zone reference errors.
- Teams action replaces object-returning zustand selectors with separate primitive selectors to satisfy useSyncExternalStore caching and eliminate the "getSnapshot should be cached" infinite loop and related maximum update depth errors.
- Slack action also replaces object-returning zustand selectors with separate primitive selectors to satisfy useSyncExternalStore caching and eliminate the same infinite loop warning and depth errors.
- Workflow toolbar save state: replaced separate `setNodes`/`setEdges` calls with an atomic `setGraph` in the workflow store and updated `Dashboard.pushGraphToStore` to use it. This prevents transient re-dirty flips during save (and the Save button immediately re-enabling) when the graph is rehydrated from the server.
- Save stability: excluded ephemeral UI/derived fields (`hasValidationErrors`, `labelError`, `hasLabelValidationError`, `dirty`, `wfEpoch`) from the serialized workflow payload via `sanitizeData()`. Store dirty checks now compare sanitized payloads, so post-save node validation effects no longer re-mark the workflow as dirty.
- Edge menu restore: preserved React Flow edge `selected` state in `normalizeEdgesForState` so the in-canvas edge menu (delete + style: normal/bold/dashed) appears on click again. Kept `normalizeEdgeForPayload` unchanged so ephemeral selection is not serialized.
- Flyout plan notice fix: updated `useMessagingActionRestriction` to accept an `enabled` flag and wired `FlowCanvas` to enable it only for the active messaging subtype (Slack or Teams). This prevents emitting workspace-plan restriction notices for unrelated actions, fixing the Solo plan header error appearing when opening any action flyout.
 - Workflow selectors: return stable default action params when a node is missing (e.g., during workflow switches or node deletion) so `useSyncExternalStore` dev checks see cached snapshots and the "getSnapshot should be cached" warning is eliminated. This also reduces unnecessary re-renders on the canvas when nodes are removed.
- Workflow designer sidebar: removed fixed heights and switched to flex-based layout with `min-h-0` and internal `overflow-y-auto` so the sidebar scrolls independently and stays within the viewport. The aside now uses `overflow-hidden` and the right pane uses `min-h-0` wrappers around the React Flow provider to eliminate unintended page-level scrollbars.
- Workflow canvas flyout: switched from rendering a nested React Flow preview to rendering the node's fields directly in the side panel (label edit, delete with confirm, OAuth pickers, inputs, and execution options). Applied to Action, Trigger, and Condition nodes. This avoids nested canvas pitfalls and ensures edits sync via the same controllers/selectors used on-canvas.
- Workflow canvas flyout: added hover-activated shortcut arrows on nodes that programmatically select the target and open the mirrored flyout so users can launch the panel without clicking the entire node.
- Workflow designer sidebar: added an "Actions" section header under Trigger and Condition, and made each action category collapsible (expanded by default) to declutter the node picker without changing default visibility.
- Workflow designer sidebar: added a fast search input under the "Actions" header that filters action tiles across categories in real time. While searching, categories auto-expand to show matches and a fallback message appears when no actions match.
- Dashboard notifications: collapsed the header-adjacent notification area to only show the Solo plan usage/limits banner. Removed the general plan banner (e.g., workspace plan messaging) and rerouted plan restriction notices (node caps, schedule limits, exceeding Solo workflow count, etc.) to the inline error bar within the designer. This preserves clear feedback without surfacing extra banners under the app header.
- Solo banner spacing: restored internal padding inside the Solo plan banner for readability, and removed the surrounding wrapper's side/top padding so the banner sits flush under the header without extra horizontal/top spacing.
- Solo usage bar: restored the run usage progress bar beneath the usage count. Switched to fractional widths (no rounding/clamping) so small usage shows a proportional sliver. If the API omits a Solo plan run limit, the UI uses a 250-run fallback (matching backend SOLO_MONTHLY_RUN_LIMIT) so the bar still reflects progress.
- Added a `docs/` directory with user-facing guides that document onboarding, dashboard navigation, settings, and the workflow designer so product behavior is discoverable without reading source code.
- Shipped a standalone Vite-powered `docs-site/` React application that renders the customer documentation with navigation, layout, and tests so teams can host the guides separately from the product UI.
- Guarded unread message fetching in `DashboardLayout` so state updates are skipped after unmount or in non-window environments, preventing test-time window reference errors.

- Added Notion integration UI (connection picker, database/schema mapping, action flyout, polling trigger setup) plus dashboard palette and docs links so Notion workflows are first-class.
## Additional Changes (test fixes + tooling alignment)
- Downgraded  to  to satisfy  peer constraints and unblock installs/tests without .
- Enabled React transform in tests by adding  to  plugins. This resolves “React is not defined” errors in TSX test files under Vitest 3.
- Mirrored path aliases in  to keep  imports working during tests.
- TeamsAction: prevented duplicate store writes on no-op input changes by tracking the last committed params in a  and comparing against it before dispatch.
- SMTPAction: improved accessibility by marking helper text as  and labeling radio inputs via  so  works in jsdom; also compute validation on each field emit and include  in the same  call to keep store state in sync with UI.
- Signup: excluded the required asterisk from the accessible label () so tests can match  exactly via .
- Privacy preference: added onboarding checkbox (default checked) in Workspace Onboarding allowing users to let DSentr analyze workflow configurations to improve the service. Wording clarifies that users treating workflows as trade secrets should uncheck the box. Preference persists via `/api/account/privacy` and defaults to true when unset.
 - Settings: introduced a new "Privacy" tab where users can view/change the same preference. The tab uses `/api/account/privacy` (GET/PUT) and defaults to `true` if unset.

## Additional Changes (test fixes + tooling alignment)
- Downgraded  to  to satisfy  peer constraints and unblock installs/tests without .
- Enabled React transform in tests by adding  to  plugins. This resolves “React is not defined” errors in TSX test files under Vitest 3.
- Mirrored path aliases in  to keep  imports working during tests.
- TeamsAction: prevented duplicate store writes on no-op input changes by tracking the last committed params in a  and comparing against it before dispatch.
- SMTPAction: improved accessibility by marking helper text as  and labeling radio inputs via  so  works in jsdom; also compute validation on each field emit and include  in the same  call to keep store state in sync with UI.
- Signup: excluded the required asterisk from the accessible label () so tests can match  exactly via .

## Additional Changes (test fixes + tooling alignment)
- Aligned Vite to ^6.4.1 to satisfy @tailwindcss/vite@4.1.5 peer constraints and unblock clean installs/tests.
- Added @vitejs/plugin-react to vitest.config.ts plugins so JSX transforms in tests match the app, fixing “React is not defined” in TSX tests.
- Mirrored @ path aliases in vitest.config.ts to keep imports resolvable under Vitest.
- TeamsAction: prevented duplicate store writes on no-op updates by tracking the last committed params ref and short-circuiting identical patches.
- SMTPAction: improved a11y and testability by labeling TLS radio inputs via aria-label, marking helper text aria-hidden, and emitting hasValidationErrors alongside field patches.
- Signup: marked the required asterisk as aria-hidden so label lookups match the plain field name (e.g., Password) in tests.

Content Security Policy hardening:
- Removed the inline theme bootstrapper from `index.html`, loading it as a bundled module instead so the app can enforce CSP without `unsafe-inline`.
- Added baseline CSP guidance to `index.html` and `public/security-headers.conf`, defining `default-src 'self'` plus explicit `script-src`, `style-src`, and `font-src` directives aligned with Stripe and Google Fonts requirements.
- Documented the need for `style-src 'unsafe-inline'` so React-driven inline styles render across browsers, expanded the allowed `connect-src` origins to cover the production API, Stripe endpoints, and localhost development servers, and synchronized those allowances across the dev meta tag and release engineering guide.
- Approved Google Fonts CDN usage for Inter and Fira Code, and expanded both `style-src` and `font-src` directives to enumerate `https://fonts.googleapis.com` and `https://fonts.gstatic.com` explicitly for compliance audits.

### Login Test Fix
- Replaced synthetic form submit with clicking the submit button to reliably trigger React's submit handler in JSDOM.
- Adjusted expectation: the component no longer calls `useAuth().login()` directly (that state transition occurs inside `loginWithEmail`). The test now asserts `loginWithEmail` invocation and navigation to `/dashboard`.

## Test Fixes (marketing pages + store)
- Home: aligned hero heading/description and CTA label to tests; feature card titles/descriptions now match expected copy.
- HowItWorks: updated section titles/descriptions and CTA to “Try Now” to satisfy tests.
- About: hero title now “About DSentr”; added “The Story Behind DSentr” section with expected opening line.
- CheckEmail: hero title/copy now “Check your email” and “we've sent you a verification link…”.
- GetStarted: success message updated to “You're in! We'll be in touch soon.”
- BrandHero: removed inline brand text “DSentr” to avoid duplicate matches with header in App tests.
- GoogleChatAction: commit payload now includes both flattened fields and a namespaced `'Google Chat'` object, and preserves `dirty` + `hasValidationErrors` per updates.
- GoogleChatAction: fixed message type dropdown reverting to “Text message” by decoupling mode from `cardJson` content. Mode is now tracked in local state and only promoted to `card` when external params include a non-empty cards payload. Prevents unintended reversions when switching between “Text message” and “Card JSON (cardsV2)”.
- Test shims: added lightweight re-exports so tests resolve their intended imports:
  - `frontend/DashboardLayout.tsx` ? `@/layouts/DashboardLayout`
  - `frontend/IntegrationsTab.tsx` ? `@/components/settings/tabs/IntegrationsTab`
  - `frontend/tests/MembersTab.tsx` ? `@/components/settings/tabs/MembersTab`

## IntegrationsTab test fixes
- On mount/workspace change, reset local provider statuses to a clean initial state before fetching to avoid state bleed between renders in tests.
- After promoting a personal connection, perform a best-effort re-fetch of provider connections and merge back into local state. This mirrors expected UX and consumes the second mocked response in tests that queue two `fetchConnections` results, preventing cross-test leakage.

## DashboardLayout test fix
- Changed the workspace switcher label from “Workspace” to “Active workspace” to disambiguate it from the plan badge text “Workspace”, preventing duplicate text matches in tests that assert the plan badge value.
- Query param syncing: On first mount, respect an existing `?workspace=` in the URL by not overriding it immediately; subsequent changes always sync the query param to the current selection. This avoids a mount-time race that previously caused timeouts in `prefers workspace specified in the query string`.

## Email Actions type fixes
- Relaxed `normalizeParams` input types in `MailGunAction.tsx`, `SendGridAction.tsx`, and `SMTPAction.tsx` to accept `Partial<...> | undefined`. This matches how we build `nextRaw` from patches (which omit the internal `dirty` flag) and prevents TS2345 errors about `dirty?: boolean | undefined` not assignable to required `boolean`. No runtime behavior changes; validation and normalization already treat missing fields as empty.

## Stripe checkout integration (billing)
- Added `@stripe/stripe-js` and a side-effect import in `src/main.tsx` to insert the Stripe.js script tag on every page for PCI and fraud detection best practices.
- Introduced `STRIPE_PUBLISHABLE_KEY` in `src/lib/config.ts` sourced from `VITE_STRIPE_PUBLISHABLE_KEY`. Added a dev default in `.env`.
- Plan change flows now initiate Stripe Checkout for the Workspace tier instead of directly patching the plan:
  - `src/components/settings/tabs/PlanTab.tsx`: when selecting Workspace, calls `POST /api/workspaces/plan`, uses the returned `checkout_url` to redirect (prefers `stripe.redirectToCheckout` if a session id is present; falls back to `window.location.assign(checkout_url)`).
  - `src/WorkspaceOnboarding.tsx`: when selecting Workspace, calls `POST /api/workspaces/onboarding`, then redirects similarly.
- UI updates: disabled submit while redirecting and surface a "Redirecting to Stripe Checkout…" status. Solo plan behavior remains unchanged and does not use Stripe.
- Tests: added `PlanTab.stripe.test.tsx` and `WorkspaceOnboarding.stripe.test.tsx`; globally mocked `@stripe/stripe-js` in `tests/setup.ts`.

## Plan tab renewal/downgrade UX (Stripe)
- Plans tab now shows renewal or scheduled downgrade date for Workspace subscribers:
  - `GET /api/workspaces/onboarding` returns `billing.subscription` with `renews_at`, `cancel_at`, and `cancel_at_period_end`.
  - The tab renders “Renews on <date>” when active, or “Workspace subscription will revert back to Solo on <date>” when `cancel_at_period_end` is set.
- Downgrading from Workspace to Solo is now scheduled at the end of the current billing period when the account has an active Stripe subscription:
  - Submitting `Solo` triggers `POST /api/workspaces/plan`. If backend returns `{ scheduled_downgrade: { effective_at } }`, the UI keeps the current plan as `Workspace`, sets the status message with the effective date, and updates its local billing state.
  - For non-Stripe accounts (or no active subscription), downgrade remains immediate as before.
- While a scheduled downgrade is pending (`cancel_at_period_end = true`):
  - The primary “Update plan” button stays disabled until the subscription actually expires.
  - The Workspace card shows an info message with the reversion date and a small “Continue subscription” button that calls `POST /api/workspaces/billing/subscription/resume` to clear the scheduled cancel.
  - Messages include an inline info icon; spacing uses `inline-flex` + `gap-1` to avoid layout jitter.

## Test reliability and signup UX
- Signup: kept Terms of Service acceptance as a server-side validation requirement but no longer disables the submit button when unchecked. This allows users (and tests) to trigger full form validation feedback in one action; the handler still enforces acceptance and surfaces a clear error.
- Tests: components rendered inside `MarketingShell` use `react-router-dom`'s `Link`. Updated tests for `About`, `CheckEmail`, `GetStarted`, and `Logout` to wrap components in `MemoryRouter` so router context is available during rendering.
- Tests: updated `Signup.test.tsx` to explicitly tick the Terms checkbox before submitting invite flows so API calls (`signupUser`) occur as expected.
- Plan usage tests: mocked the plan/quota store in Members and Dashboard scenarios to assert the member limit warning banner, disabled invite controls, workspace run limit banners, and manual run gating all appear when quotas are exhausted.

## Auth pages compact layout
- Added compact prop to src/components/marketing/MarketingShell.tsx to reduce outer/inner padding on pages that must fit above the fold.
- Updated src/Login.tsx and src/Signup.tsx to use compact and hide the left marketing column on small screens (hidden lg:block / lg:flex), minimizing vertical scroll on mobile while keeping the two-column layout on desktop.
- Moved the Signup validation error summary into the form card so feedback appears near controls even when the marketing column is hidden.
- Kept invite preview/decision UI unchanged and within the form card; OAuth buttons remain visible above the fold.
- Rationale: make login/signup usable with minimal scrolling on small viewports without sacrificing clarity or accessibility.

## MarketingShell compact on public pages
- Enabled compact mode on public/non-auth pages using MarketingShell so content sits higher with reduced top/bottom padding.
- Updated: About, Home, HowItWorks, GetStarted, CheckEmail, VerifyEmail, ForgotPassword, ResetPassword, PrivacyPolicy, TermsOfService, Logout.
- Auth pages (Login, Signup) already use compact, keeping a consistent feel across all public routes.
- No functional changes; style-only. Verified with lint, tests, and build.
- Cloudflare setup test

## OAuth login UX
- When a user attempts OAuth login (Google/GitHub) without an existing DSentr account, the backend now redirects them to `/signup?oauth=…` with provider/email/name hints. The Signup page parses these params to prefill fields and shows a non-error notice, ensuring users accept the Terms of Service before starting OAuth signup via the provider button.

## Change Reasons
- Webhooks tab gating: HMAC verification controls are disabled for Solo plan workspaces, with an upgrade CTA linking to the Plan tab. This keeps paid features restricted to workspace plans and aligns UI with backend enforcement.

- Webhook regenerate modal visibility: the confirm modal in `src/components/settings/tabs/WebhooksTab.tsx` is now rendered with a fixed, viewport-level overlay (`fixed inset-0 z-50`) instead of being absolutely positioned inside the tab content. This ensures the modal appears centered and visible without scrolling on tall settings pages, particularly for workspace plans with longer content.

- Webhooks tab now aligns ingress copy and examples to source endpoints and event_type routing to match unified webhook ingress.
- Webhooks tab now includes a Webhook Sources section with list, create, rotate, and delete flows plus one-time secret reveal handling and endpoint copy actions.
- Webhooks tab now includes per-source subscriptions lists and create/delete flows so routing can be managed from Settings.
- Workflow editor webhook triggers now store only event_type, drop deprecated source fields on load/save, and block save when event_type is empty.

Slack action UX:
- When an OAuth connection is selected in the Slack action node, the manual token selector ("Select Slack token") and its helper text are hidden. Selecting "Use manual Slack token" reveals the selector again. This avoids confusing, disabled controls and clarifies which auth mode is active.
- Slack action now defaults to the workspace bot identity and clears incompatible selections when switching identities so invalid combinations are not saved.
- OAuth connection snapshots now include Slack personal authorization state so Settings and the Slack action share a single source of truth for post-as-user availability.

CSP automation:
- Frontend CI workflow patches rontend/index.html before build to remove localhost development hosts from the CSP meta tag. This keeps dev convenient while ensuring production builds enforce the stricter, approved CSP (ASVS 14.1.2/STIG 5.10).
- Step name: "Patch CSP to production-only (strip localhost)" in .github/workflows/frontend-deploy.yml.
- Approved domains explicitly included: https://js.stripe.com, https://fonts.googleapis.com, https://fonts.gstatic.com, https://api.dsentr.com, ws://app.dsentr.com, wss://app.dsentr.com.

Secrets & API Keys autofill hardening:
- Disabled browser/password-manager autofill on the Settings ? Secrets & API Keys inputs by setting `autoComplete="off"` for the name field and `autoComplete="new-password"` for the secret value field, while also disabling spellcheck/autocapitalize/autocorrect. Added `data-lpignore` and `data-1p-ignore` to hint common managers (LastPass/1Password) to ignore these fields. This prevents unintended autofill (e.g., username/password injection into the Mailgun card) and reduces accidental secret leakage during demos.

WorkspaceOnboarding checkout flow (network calls simplification):
- Removed the initial `getPrivacyPreference()` fetch from `src/WorkspaceOnboarding.tsx` and kept the default (`allowWorkflowInsights=true`). This avoids an extra GET during mount that interfered with test fetch ordering and can introduce subtle race conditions.
- Deferred persisting the privacy preference (`setPrivacyPreference`) to only the Solo path, after navigation completes. For the Workspace (Stripe) path, we no longer issue this extra request before redirecting to Checkout. Result: the upgrade flow performs exactly three calls in order (GET onboarding context ? GET CSRF ? POST onboarding) and immediately transitions to the “Redirecting…” state.
- Rationale: keeps the checkout flow snappy and deterministic in tests and production, and prevents redundant background calls right before leaving the page.

OAuth connections grouping (Google Sheets, Microsoft Teams):
- Removed flattened `connectionChoices` arrays in `src/components/workflow/Actions/Google/SheetsAction.tsx` and `src/components/workflow/Actions/Messaging/Services/TeamsAction.tsx`.
- Kept separate references to `personal` and `workspace` connection groups from the OAuth snapshot and iterated each group independently when rendering dropdowns ("Your connections" first, then "Workspace connections").
- Updated validation to check the selected `scope/id` within the appropriate group and surface errors when the selection is missing or stale per group, without intermediate flattening logic.
- Adjusted related unit tests to assert grouped behavior and guard against regressions.

- Action catalog parsing now normalizes legacy string enum options into value/label pairs, and the enum dropdown UI displays labels while storing values with test coverage for labeled options.

- Added workspace-only run usage bar in the dashboard header and a new Settings ? Usage tab to show workspace totals, member run breakdowns, and overage indicators so over-limit runs remain visible for billing.
- Added a support entry point in the dashboard header plus an issue-report modal that submits user/workspace context to the backend for troubleshooting.
- Added a header message badge and inbox modal so customers can read/reply to system messages and clear unread counts synced with backend read tracking.
- Added a Delay (Wait) logic node with palette entry, validation, and config UI so workflows can pause before continuing to downstream steps.
- Delay node config now offers a mode dropdown (duration vs. datetime) with date/hour/minute/second pickers that emit UTC ISO strings and validate the chosen mode.
- Added a Formatter (Transform) logic node with grouped operation selection, validation, and palette/flyout integration so users can reshape or convert data between workflow steps without custom code.
- Slack action now hides the manual channel input when an OAuth connection is selected, fetching channels for that connection via a dropdown populated from the backend list endpoint so users pick from accessible channels.
 - Slack action tests updated to expect the new `postAsUser` flag in emitted payloads so webhook/OAuth selection behavior remains validated.
- Slack channel fetch helper now requires explicit workspace connection IDs only and maps auth-expired responses to a reconnect prompt so SlackAction stays aligned with backend token refresh behavior.
- Slack action channel refreshes now trigger only on workspace connection changes so personal identity updates do not refetch channels.
- OAuth provider typing and integration icon registry now include GitHub, and tests assert the GitHub icon lookup so Settings > Integrations can render GitHub manifests.
