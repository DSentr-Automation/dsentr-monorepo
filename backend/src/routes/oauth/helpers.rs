use std::collections::{BTreeMap, HashSet};

use super::prelude::*;
use crate::integrations::manifest::{
    IntegrationAuthType, IntegrationManifest, OwnershipModel, TokenScope,
};
use crate::integrations::registry::IntegrationRegistry;
pub(crate) const GOOGLE_AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
// GitHub App user-to-server OAuth uses the OAuth App authorize endpoint and is valid only when
// user OAuth is enabled in the GitHub App settings.
pub(crate) const GITHUB_AUTH_URL: &str = "https://github.com/login/oauth/authorize";
pub(crate) const MICROSOFT_AUTH_URL: &str =
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize";
pub(crate) const SLACK_AUTH_URL: &str = "https://slack.com/oauth/v2/authorize";
pub(crate) const ASANA_AUTH_URL: &str = "https://app.asana.com/-/oauth_authorize";
pub(crate) const NOTION_AUTH_URL: &str = "https://api.notion.com/v1/oauth/authorize";
pub(crate) const BITLY_AUTH_URL: &str = "https://bitly.com/oauth/authorize";
pub(crate) const RAINDROP_AUTH_URL: &str = "https://raindrop.io/oauth/authorize";
pub(crate) const GOOGLE_STATE_COOKIE: &str = "oauth_google_state";
pub(crate) const GITHUB_STATE_COOKIE: &str = "oauth_github_state";
pub(crate) const MICROSOFT_STATE_COOKIE: &str = "oauth_microsoft_state";
pub(crate) const SLACK_STATE_COOKIE: &str = "oauth_slack_state";
pub(crate) const ASANA_STATE_COOKIE: &str = "oauth_asana_state";
pub(crate) const NOTION_STATE_COOKIE: &str = "oauth_notion_state";
pub(crate) const BITLY_STATE_COOKIE: &str = "oauth_bitly_state";
pub(crate) const RAINDROP_STATE_COOKIE: &str = "oauth_raindrop_state";
pub(crate) const STATE_COOKIE_MAX_MINUTES: i64 = 10;
pub(crate) const OAUTH_PLAN_RESTRICTION_MESSAGE: &str =
    "OAuth integrations are available on workspace plans and above. Upgrade to connect accounts.";
pub(crate) const SLACK_WORKSPACE_REQUIRED_MESSAGE: &str =
    "Slack connections require an explicit workspace.";
const SLACK_STATE_SEPARATOR: char = ':';

#[derive(Deserialize)]
pub struct CallbackQuery {
    pub(crate) code: Option<String>,
    pub(crate) state: Option<String>,
    pub(crate) error: Option<String>,
    pub(crate) error_description: Option<String>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConnectionOwnerPayload {
    pub(crate) user_id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) email: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PersonalConnectionPayload {
    pub(crate) id: Uuid,
    pub(crate) provider: ConnectedOAuthProvider,
    pub(crate) account_email: String,
    #[serde(with = "time::serde::rfc3339")]
    pub(crate) expires_at: OffsetDateTime,
    pub(crate) is_shared: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub(crate) last_refreshed_at: OffsetDateTime,
    pub(crate) requires_reconnect: bool,
    pub(crate) owner: ConnectionOwnerPayload,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WorkspaceConnectionPayload {
    pub(crate) id: Uuid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) connection_id: Option<Uuid>,
    pub(crate) provider: ConnectedOAuthProvider,
    pub(crate) account_email: String,
    #[serde(with = "time::serde::rfc3339")]
    pub(crate) expires_at: OffsetDateTime,
    pub(crate) workspace_id: Uuid,
    pub(crate) workspace_name: String,
    pub(crate) shared_by_name: Option<String>,
    pub(crate) shared_by_email: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub(crate) last_refreshed_at: OffsetDateTime,
    pub(crate) requires_reconnect: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(crate) has_incoming_webhook: bool,
    pub(crate) owner: ConnectionOwnerPayload,
}

#[derive(Serialize, Default, Clone)]
#[serde(rename_all = "snake_case")]
pub(crate) struct PersonalAuthStatus {
    pub(crate) has_personal_auth: bool,
    #[serde(with = "time::serde::rfc3339::option")]
    pub(crate) personal_auth_connected_at: Option<OffsetDateTime>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IntegrationManifestPayload {
    pub(crate) integration_id: String,
    pub(crate) auth_type: String,
    pub(crate) token_scope: String,
    pub(crate) ownership_model: String,
    pub(crate) provider_constraints: ProviderConstraintsPayload,
    pub(crate) ui_metadata: UiMetadataPayload,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) oauth_metadata: Option<OAuthMetadataPayload>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProviderConstraintsPayload {
    pub(crate) workspace_first: bool,
    pub(crate) single_install_per_workspace: bool,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UiMetadataPayload {
    pub(crate) display_name: String,
    pub(crate) description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) icon_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) docs_url: Option<String>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OAuthMetadataPayload {
    pub(crate) scopes: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ConnectionsResponse {
    pub(crate) success: bool,
    pub(crate) personal: Vec<PersonalConnectionPayload>,
    pub(crate) workspace: Vec<WorkspaceConnectionPayload>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) personal_auth: BTreeMap<String, PersonalAuthStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) slack: Option<PersonalAuthStatus>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) manifests: Vec<IntegrationManifestPayload>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RefreshResponse {
    pub(crate) success: bool,
    pub(crate) requires_reconnect: bool,
    pub(crate) account_email: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub(crate) expires_at: Option<OffsetDateTime>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub(crate) last_refreshed_at: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) connection_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) message: Option<String>,
}

pub(crate) async fn handle_callback(
    state: AppState,
    claims: crate::routes::auth::claims::Claims,
    jar: CookieJar,
    query: CallbackQuery,
    provider: ConnectedOAuthProvider,
    integration_id: &str,
    cookie_name: &str,
) -> Response {
    if let Some(error) = query.error.or(query.error_description) {
        return redirect_with_error(&state.config, integration_id, &error);
    }

    let code = match query.code {
        Some(code) => code,
        None => return redirect_with_error(&state.config, integration_id, "Missing code"),
    };

    let expected_state = match jar.get(cookie_name) {
        Some(cookie) => cookie.value().to_string(),
        None => return redirect_with_error(&state.config, integration_id, "Missing state"),
    };

    let provided_state = match query.state {
        Some(state) => state,
        None => return redirect_with_error(&state.config, integration_id, "Missing state"),
    };

    if provided_state != expected_state {
        return redirect_with_error(&state.config, integration_id, "Invalid state");
    }

    let jar = clear_state_cookie(jar, cookie_name);

    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return redirect_with_error(&state.config, integration_id, "Invalid user"),
    };

    let tokens = match state
        .oauth_accounts
        .exchange_authorization_code(provider, &code)
        .await
    {
        Ok(tokens) => tokens,
        Err(err) => {
            error!("OAuth authorization exchange failed: {err}");
            let response = redirect_with_error(
                &state.config,
                integration_id,
                &error_message_for_redirect(&err),
            );
            return (jar, response).into_response();
        }
    };

    if let Err(err) = state
        .oauth_accounts
        .save_authorization_deduped(user_id, provider, tokens)
        .await
    {
        error!("Saving OAuth authorization failed: {err}");
        let response = redirect_with_error(
            &state.config,
            integration_id,
            &error_message_for_redirect(&err),
        );
        return (jar, response).into_response();
    }

    (jar, redirect_success(&state.config, integration_id)).into_response()
}

pub(crate) fn build_slack_state(workspace_id: Uuid) -> String {
    format!(
        "{}{}{}",
        generate_csrf_token(),
        SLACK_STATE_SEPARATOR,
        workspace_id
    )
}

pub(crate) fn parse_slack_state(value: &str) -> Option<Uuid> {
    let (token, workspace) = value.split_once(SLACK_STATE_SEPARATOR)?;
    if token.trim().is_empty() {
        return None;
    }
    Uuid::parse_str(workspace).ok()
}

pub(crate) fn build_state_cookie(name: &str, value: &str) -> Cookie<'static> {
    Cookie::build((name.to_owned(), value.to_owned()))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(Duration::minutes(STATE_COOKIE_MAX_MINUTES))
        .build()
}

pub(crate) fn clear_state_cookie(jar: CookieJar, name: &str) -> CookieJar {
    let cookie = Cookie::build((name.to_owned(), String::new()))
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(Duration::seconds(0))
        .build();
    jar.add(cookie)
}

fn redirect_success(config: &Config, integration_id: &str) -> Redirect {
    redirect_success_with_workspace_optional(config, integration_id, None)
}

pub(crate) fn redirect_with_error(
    config: &Config,
    integration_id: &str,
    message: &str,
) -> Response {
    redirect_with_error_optional(config, integration_id, message, None)
}

pub(crate) fn redirect_success_with_workspace(
    config: &Config,
    integration_id: &str,
    workspace_id: Uuid,
) -> Redirect {
    redirect_success_with_workspace_optional(config, integration_id, Some(workspace_id))
}

pub(crate) fn redirect_with_error_with_workspace(
    config: &Config,
    integration_id: &str,
    message: &str,
    workspace_id: Option<Uuid>,
) -> Response {
    redirect_with_error_optional(config, integration_id, message, workspace_id)
}

pub(crate) fn redirect_with_error_for_manifest(
    config: &Config,
    manifest: &IntegrationManifest,
    message: &str,
    workspace_id: Option<Uuid>,
) -> Response {
    if manifest.provider_constraints.workspace_first {
        redirect_with_error_optional(config, &manifest.integration_id, message, workspace_id)
    } else {
        redirect_with_error(config, &manifest.integration_id, message)
    }
}

fn redirect_success_with_workspace_optional(
    config: &Config,
    integration_id: &str,
    workspace_id: Option<Uuid>,
) -> Redirect {
    let url = format!(
        "{}/dashboard?connected=true&provider={}",
        config.frontend_origin, integration_id
    );
    Redirect::to(&append_workspace_param(url, workspace_id))
}

fn redirect_with_error_optional(
    config: &Config,
    integration_id: &str,
    message: &str,
    workspace_id: Option<Uuid>,
) -> Response {
    let url = format!(
        "{}/dashboard?connected=false&provider={}&error={}",
        config.frontend_origin,
        integration_id,
        encode(message)
    );
    Redirect::to(&append_workspace_param(url, workspace_id)).into_response()
}

fn append_workspace_param(url: String, workspace_id: Option<Uuid>) -> String {
    let Some(workspace_id) = workspace_id else {
        return url;
    };
    format!("{url}&workspace={workspace_id}")
}

pub fn map_oauth_error(err: OAuthAccountError) -> Response {
    match err {
        OAuthAccountError::NotFound => {
            JsonResponse::not_found("No connection found for provider").into_response()
        }
        OAuthAccountError::Database(e) => {
            error!("OAuth database error: {e}");
            JsonResponse::server_error("Failed to persist OAuth tokens").into_response()
        }
        OAuthAccountError::Encryption(e) => {
            error!("OAuth encryption error: {e}");
            JsonResponse::server_error("Token encryption failed").into_response()
        }
        OAuthAccountError::Http(e) => {
            error!("OAuth HTTP error: {e}");
            JsonResponse::server_error("Provider request failed").into_response()
        }
        OAuthAccountError::EmailNotVerified { provider } => {
            let provider_name = match provider {
                ConnectedOAuthProvider::Google => "Google",
                ConnectedOAuthProvider::GitHub => "GitHub",
                ConnectedOAuthProvider::Microsoft => "Microsoft",
                ConnectedOAuthProvider::Slack => "Slack",
                ConnectedOAuthProvider::Asana => "Asana",
                ConnectedOAuthProvider::Notion => "Notion",
                ConnectedOAuthProvider::Bitly => "Bitly",
                ConnectedOAuthProvider::Raindrop => "Raindrop",
            };
            JsonResponse::bad_request(&format!(
                "The {provider_name} account email must be verified before connecting."
            ))
            .into_response()
        }
        OAuthAccountError::TokenRevoked { .. } => {
            JsonResponse::conflict("The OAuth connection was revoked. Reconnect to restore access.")
                .into_response()
        }
        OAuthAccountError::InvalidResponse(msg) => JsonResponse::server_error(&msg).into_response(),
        OAuthAccountError::MissingRefreshToken => {
            JsonResponse::server_error("Provider did not return a refresh token").into_response()
        }
        OAuthAccountError::RefreshNotSupported { provider } => JsonResponse::bad_request(&format!(
            "The {:?} provider does not support token refresh",
            provider
        ))
        .into_response(),
    }
}

pub(crate) fn error_message_for_redirect(err: &OAuthAccountError) -> String {
    match err {
        OAuthAccountError::NotFound => "Connection not found".to_string(),
        OAuthAccountError::Database(_) => {
            "Could not save OAuth tokens. Please try again.".to_string()
        }
        OAuthAccountError::Encryption(_) => "Could not secure OAuth tokens.".to_string(),
        OAuthAccountError::Http(_) => "The OAuth provider request failed.".to_string(),
        OAuthAccountError::EmailNotVerified { .. } => {
            "The OAuth account's email address must be verified before connecting.".to_string()
        }
        OAuthAccountError::InvalidResponse(_) => {
            "Received an invalid response from the OAuth provider.".to_string()
        }
        OAuthAccountError::TokenRevoked { .. } => {
            "The OAuth connection was revoked. Reconnect to continue.".to_string()
        }
        OAuthAccountError::MissingRefreshToken => {
            "The OAuth provider did not return a refresh token.".to_string()
        }
        OAuthAccountError::RefreshNotSupported { .. } => {
            "The OAuth provider does not support token refresh.".to_string()
        }
    }
}

pub(crate) fn manifest_payloads(registry: &IntegrationRegistry) -> Vec<IntegrationManifestPayload> {
    let mut payloads = registry
        .iter()
        .map(|manifest| IntegrationManifestPayload {
            integration_id: manifest.integration_id.clone(),
            auth_type: auth_type_label(manifest.auth_type),
            token_scope: token_scope_label(manifest.token_scope),
            ownership_model: ownership_model_label(manifest.ownership_model),
            provider_constraints: ProviderConstraintsPayload {
                workspace_first: manifest.provider_constraints.workspace_first,
                single_install_per_workspace: manifest
                    .provider_constraints
                    .single_install_per_workspace,
            },
            ui_metadata: UiMetadataPayload {
                display_name: manifest.ui_metadata.display_name.clone(),
                description: manifest.ui_metadata.description.clone(),
                icon_key: manifest.ui_metadata.icon_key.clone(),
                docs_url: manifest.ui_metadata.docs_url.clone(),
            },
            oauth_metadata: manifest
                .oauth_metadata
                .as_ref()
                .map(|oauth| OAuthMetadataPayload {
                    scopes: oauth.scopes.clone(),
                }),
        })
        .collect::<Vec<_>>();
    payloads.sort_by(|a, b| a.integration_id.cmp(&b.integration_id));
    payloads
}

pub(crate) fn is_workspace_first(manifest: &IntegrationManifest) -> bool {
    manifest.provider_constraints.workspace_first
        && supports_personal(manifest)
        && supports_workspace(manifest)
}

pub(crate) fn supports_personal(manifest: &IntegrationManifest) -> bool {
    manifest.token_scope.supports_personal() && manifest.ownership_model.supports_personal()
}

pub(crate) fn supports_workspace(manifest: &IntegrationManifest) -> bool {
    manifest.token_scope.supports_workspace() && manifest.ownership_model.supports_workspace()
}

pub(crate) fn oauth_manifest_for_id<'a>(
    registry: &'a IntegrationRegistry,
    integration_id: &str,
) -> Option<&'a IntegrationManifest> {
    let manifest = registry.get(integration_id)?;
    if manifest.auth_type != IntegrationAuthType::OAuth2 {
        return None;
    }
    Some(manifest)
}

#[allow(clippy::result_large_err)]
pub(crate) fn resolve_oauth_integration<'a>(
    registry: &'a IntegrationRegistry,
    integration_id: &str,
) -> Result<(&'a IntegrationManifest, ConnectedOAuthProvider), Response> {
    let manifest = match oauth_manifest_for_id(registry, integration_id) {
        Some(manifest) => manifest,
        None => return Err(JsonResponse::bad_request("Unknown integration").into_response()),
    };
    let provider = match oauth_provider_for_integration_id(&manifest.integration_id) {
        Some(provider) => provider,
        None => {
            error!(
                integration_id = %manifest.integration_id,
                "OAuth provider missing from mapping table"
            );
            return Err(
                JsonResponse::server_error("OAuth provider configuration is missing")
                    .into_response(),
            );
        }
    };
    Ok((manifest, provider))
}

// Legacy mapping: OAuth provider enums are still required by OAuth services, but integrations
// stay integration_id-driven. This mapping is intentionally isolated to OAuth routes, and
// manifests must not depend on provider enums going forward.
pub(crate) const GOOGLE_INTEGRATION_ID: &str = "google";
pub(crate) const GITHUB_INTEGRATION_ID: &str = "github";
pub(crate) const MICROSOFT_INTEGRATION_ID: &str = "microsoft";
pub(crate) const SLACK_INTEGRATION_ID: &str = "slack";
pub(crate) const ASANA_INTEGRATION_ID: &str = "asana";
pub(crate) const NOTION_INTEGRATION_ID: &str = "notion";
pub(crate) const BITLY_INTEGRATION_ID: &str = "bitly";
pub(crate) const RAINDROP_INTEGRATION_ID: &str = "raindrop";
const OAUTH_PROVIDER_MAP: &[(&str, ConnectedOAuthProvider)] = &[
    (GOOGLE_INTEGRATION_ID, ConnectedOAuthProvider::Google),
    (GITHUB_INTEGRATION_ID, ConnectedOAuthProvider::GitHub),
    (MICROSOFT_INTEGRATION_ID, ConnectedOAuthProvider::Microsoft),
    (SLACK_INTEGRATION_ID, ConnectedOAuthProvider::Slack),
    (ASANA_INTEGRATION_ID, ConnectedOAuthProvider::Asana),
    (NOTION_INTEGRATION_ID, ConnectedOAuthProvider::Notion),
    (BITLY_INTEGRATION_ID, ConnectedOAuthProvider::Bitly),
    (RAINDROP_INTEGRATION_ID, ConnectedOAuthProvider::Raindrop),
];

pub(crate) fn oauth_provider_for_integration_id(
    integration_id: &str,
) -> Option<ConnectedOAuthProvider> {
    let normalized = integration_id.trim().to_ascii_lowercase();
    OAUTH_PROVIDER_MAP
        .iter()
        .find(|(id, _)| *id == normalized)
        .map(|(_, provider)| *provider)
}

pub(crate) fn integration_id_for_provider(
    provider: ConnectedOAuthProvider,
) -> Option<&'static str> {
    OAUTH_PROVIDER_MAP
        .iter()
        .find(|(_, mapped)| *mapped == provider)
        .map(|(id, _)| *id)
}

#[allow(dead_code)]
pub(crate) fn assert_oauth_provider_mappings(registry: &IntegrationRegistry) -> Result<(), String> {
    let mut seen_ids = HashSet::new();
    let mut seen_providers = HashSet::new();
    for (integration_id, provider) in OAUTH_PROVIDER_MAP.iter() {
        if !seen_ids.insert(*integration_id) {
            return Err(format!(
                "OAuth mapping contains duplicate integration_id: {}",
                integration_id
            ));
        }
        if !seen_providers.insert(*provider) {
            return Err(format!(
                "OAuth mapping contains duplicate provider: {:?}",
                provider
            ));
        }
        let manifest = registry
            .get(integration_id)
            .ok_or_else(|| format!("OAuth mapping missing manifest: {}", integration_id))?;
        if manifest.auth_type != IntegrationAuthType::OAuth2 {
            return Err(format!(
                "OAuth mapping references non-OAuth integration: {}",
                integration_id
            ));
        }
    }

    for manifest in registry
        .iter()
        .filter(|manifest| manifest.auth_type == IntegrationAuthType::OAuth2)
    {
        if oauth_provider_for_integration_id(&manifest.integration_id).is_none() {
            return Err(format!(
                "OAuth integration missing provider mapping: {}",
                manifest.integration_id
            ));
        }
    }

    Ok(())
}

fn auth_type_label(value: IntegrationAuthType) -> String {
    match value {
        IntegrationAuthType::OAuth2 => "oauth2",
        IntegrationAuthType::ApiKey => "api_key",
        IntegrationAuthType::None => "none",
    }
    .to_string()
}

fn token_scope_label(value: TokenScope) -> String {
    match value {
        TokenScope::Personal => "personal",
        TokenScope::Workspace => "workspace",
        TokenScope::PersonalAndWorkspace => "personal_and_workspace",
    }
    .to_string()
}

fn ownership_model_label(value: OwnershipModel) -> String {
    match value {
        OwnershipModel::PersonalOnly => "personal_only",
        OwnershipModel::WorkspaceOnly => "workspace_only",
        OwnershipModel::Hybrid => "hybrid",
    }
    .to_string()
}
