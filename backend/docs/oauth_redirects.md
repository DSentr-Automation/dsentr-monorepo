# OAuth Redirect URIs

The DSentr backend hosts the OAuth callbacks that providers send users to after they authorize the DSentr app. Configure the provider dashboards so their redirect URIs match these backend endpoints, and set the same values in your environment when running the server.

| Provider   | Redirect URI value                                              |
| ---------- | ---------------------------------------------------------------- |
| Google     | `https://<your-backend-domain>/api/oauth/google/callback`        |
| GitHub     | `https://<your-backend-domain>/api/oauth/github/callback`        |
| Microsoft  | `https://<your-backend-domain>/api/oauth/microsoft/callback`     |
| Slack      | `https://<your-backend-domain>/api/oauth/slack/callback`         |
| Asana      | `https://<your-backend-domain>/api/oauth/asana/callback`         |
| Notion     | `https://<your-backend-domain>/api/oauth/notion/callback`        |

For local development you can point the redirect URIs at whatever host/port serves your backend, for example:

```
GOOGLE_INTEGRATIONS_REDIRECT_URI=http://localhost:3000/api/oauth/google/callback
GITHUB_INTEGRATIONS_REDIRECT_URI=http://localhost:3000/api/oauth/github/callback
MICROSOFT_INTEGRATIONS_REDIRECT_URI=http://localhost:3000/api/oauth/microsoft/callback
SLACK_INTEGRATIONS_REDIRECT_URI=http://localhost:3000/api/oauth/slack/callback
ASANA_INTEGRATIONS_REDIRECT_URI=http://localhost:3000/api/oauth/asana/callback
NOTION_INTEGRATIONS_REDIRECT_URI=http://localhost:3000/api/oauth/notion/callback
```

In addition to the redirect URIs, configure the integration app credentials with:

```
GOOGLE_INTEGRATIONS_CLIENT_ID=<google-oauth-client-id>
GOOGLE_INTEGRATIONS_CLIENT_SECRET=<google-oauth-client-secret>

GITHUB_INTEGRATIONS_CLIENT_ID=<github-app-client-id>
GITHUB_INTEGRATIONS_CLIENT_SECRET=<github-app-client-secret>

MICROSOFT_INTEGRATIONS_CLIENT_ID=<microsoft-oauth-client-id>
MICROSOFT_INTEGRATIONS_CLIENT_SECRET=<microsoft-oauth-client-secret>

SLACK_INTEGRATIONS_CLIENT_ID=<slack-oauth-client-id>
SLACK_INTEGRATIONS_CLIENT_SECRET=<slack-oauth-client-secret>

ASANA_INTEGRATIONS_CLIENT_ID=<asana-oauth-client-id>
ASANA_INTEGRATIONS_CLIENT_SECRET=<asana-oauth-client-secret>

NOTION_INTEGRATIONS_CLIENT_ID=<notion-oauth-client-id>
NOTION_INTEGRATIONS_CLIENT_SECRET=<notion-oauth-client-secret>
```

The backend reads these values from the corresponding environment variables when constructing OAuth authorization URLs and exchanging authorization codes. The Google login flow continues to rely on the existing `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `GOOGLE_REDIRECT_URI` environment variables, so auth and workflow integrations can be configured independently. No additional frontend endpoints are required—the callback handlers live entirely on the backend under `/api/oauth/*`.

## Stripe configuration

Stripe uses a separate OAuth application for the billing console alongside signing keys for API and webhook validation. Provision the credentials in the Stripe dashboard and add the following variables to your `.env` file:

```
STRIPE_CLIENT_ID=<stripe-connect-client-id>
STRIPE_SECRET_KEY=<stripe-api-secret-key>
STRIPE_WEBHOOK_SECRET=<stripe-webhook-signing-secret>
```

The DSentr backend reads these values during startup to initialize the Stripe SDK, authenticate API calls, and verify incoming webhook signatures.
