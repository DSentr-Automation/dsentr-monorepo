use super::{
    helpers::{
        build_slack_state, build_state_cookie, clear_state_cookie, error_message_for_redirect,
        handle_callback, parse_slack_state, redirect_success_with_workspace, redirect_with_error,
        redirect_with_error_for_manifest, redirect_with_error_with_workspace,
        resolve_oauth_integration, CallbackQuery, ASANA_AUTH_URL, ASANA_INTEGRATION_ID,
        ASANA_STATE_COOKIE, GITHUB_AUTH_URL, GITHUB_INTEGRATION_ID, GITHUB_STATE_COOKIE,
        GOOGLE_AUTH_URL, GOOGLE_INTEGRATION_ID, GOOGLE_STATE_COOKIE, MICROSOFT_AUTH_URL,
        MICROSOFT_INTEGRATION_ID, MICROSOFT_STATE_COOKIE, NOTION_AUTH_URL, NOTION_INTEGRATION_ID,
        NOTION_STATE_COOKIE, OAUTH_PLAN_RESTRICTION_MESSAGE, SLACK_AUTH_URL, SLACK_INTEGRATION_ID,
        SLACK_STATE_COOKIE, SLACK_WORKSPACE_REQUIRED_MESSAGE,
    },
    prelude::*,
};
use crate::models::workspace::WorkspaceRole;
use crate::services::oauth::workspace_service::WorkspaceOAuthError;
use crate::{
    integrations::manifest::IntegrationManifest,
    routes::oauth::helpers::{
        BITLY_AUTH_URL, BITLY_INTEGRATION_ID, BITLY_STATE_COOKIE, RAINDROP_AUTH_URL,
        RAINDROP_INTEGRATION_ID, RAINDROP_STATE_COOKIE,
    },
};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[derive(Debug, Default, Deserialize)]
pub struct ConnectQuery {
    #[serde(default)]
    pub workspace: Option<Uuid>,
    #[serde(
        default,
        rename = "workspaceConnectionId",
        alias = "workspace_connection_id"
    )]
    pub workspace_connection_id: Option<Uuid>,
    #[serde(default, rename = "connectionScope", alias = "connection_scope")]
    pub connection_scope: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NotionState {
    user_id: Uuid,
    workspace_id: Option<Uuid>,
    connection_scope: String,
    nonce: String,
}

fn encode_notion_state(state: &NotionState) -> Result<String, Box<Response>> {
    serde_json::to_vec(state)
        .map(|payload| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload))
        .map_err(|err| {
            error!(?err, "Failed to encode Notion OAuth state");
            Box::new(
                JsonResponse::server_error("Failed to start Notion OAuth flow").into_response(),
            )
        })
}

fn decode_notion_state(raw: &str) -> Option<NotionState> {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(raw)
        .ok()?;
    serde_json::from_slice(&decoded).ok()
}

fn normalize_notion_scope(
    raw: Option<&str>,
    workspace_id: Option<Uuid>,
) -> Result<String, Box<Response>> {
    if let Some(scope) = raw {
        let normalized = scope.trim().to_ascii_lowercase();
        if normalized == "workspace" {
            if workspace_id.is_none() {
                return Err(Box::new(
                    JsonResponse::bad_request("Workspace scope requires a workspace id")
                        .into_response(),
                ));
            }
            return Ok("workspace".to_string());
        }
        if normalized == "personal" || normalized == "user" {
            return Ok("personal".to_string());
        }
        return Err(Box::new(
            JsonResponse::bad_request("Unsupported connection scope").into_response(),
        ));
    }

    if workspace_id.is_some() {
        Ok("workspace".to_string())
    } else {
        Ok("personal".to_string())
    }
}

const OAUTH_VIEWER_RESTRICTION_MESSAGE: &str =
    "Workspace viewers cannot connect OAuth accounts for this workspace.";
const OAUTH_WORKSPACE_ACCESS_ERROR_MESSAGE: &str =
    "We couldn't verify your access to this workspace. Please try again.";

async fn ensure_oauth_permissions(
    state: &AppState,
    user_id: Uuid,
    claims_plan: Option<&str>,
    workspace: Option<Uuid>,
    manifest: &IntegrationManifest,
) -> Result<(), Response> {
    if let Some(workspace_id) = workspace {
        match state
            .workspace_repo
            .list_memberships_for_user(user_id)
            .await
        {
            Ok(memberships) => {
                if let Some(membership) = memberships
                    .into_iter()
                    .find(|m| m.workspace.id == workspace_id)
                {
                    if matches!(membership.role, WorkspaceRole::Viewer) {
                        return Err(redirect_with_error_for_manifest(
                            &state.config,
                            manifest,
                            OAUTH_VIEWER_RESTRICTION_MESSAGE,
                            Some(workspace_id),
                        ));
                    }

                    let plan_tier =
                        NormalizedPlanTier::from_option(Some(membership.workspace.plan.as_str()));
                    if plan_tier.is_solo() {
                        return Err(redirect_with_error_for_manifest(
                            &state.config,
                            manifest,
                            OAUTH_PLAN_RESTRICTION_MESSAGE,
                            Some(workspace_id),
                        ));
                    }

                    return Ok(());
                }

                return Err(redirect_with_error_for_manifest(
                    &state.config,
                    manifest,
                    "You do not have access to this workspace.",
                    Some(workspace_id),
                ));
            }
            Err(err) => {
                error!(%user_id, %workspace_id, ?err, "failed to load workspace memberships");
                return Err(redirect_with_error_for_manifest(
                    &state.config,
                    manifest,
                    OAUTH_WORKSPACE_ACCESS_ERROR_MESSAGE,
                    Some(workspace_id),
                ));
            }
        }
    }

    let plan_tier = state.resolve_plan_tier(user_id, claims_plan).await;
    if plan_tier.is_solo() {
        return Err(redirect_with_error_for_manifest(
            &state.config,
            manifest,
            OAUTH_PLAN_RESTRICTION_MESSAGE,
            None,
        ));
    }

    Ok(())
}

pub async fn google_connect_start(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    Query(params): Query<ConnectQuery>,
    jar: CookieJar,
) -> Response {
    let integration_id = GOOGLE_INTEGRATION_ID;
    let (manifest, _provider) =
        match resolve_oauth_integration(state.integration_registry.as_ref(), integration_id) {
            Ok(result) => result,
            Err(response) => return response,
        };

    match Uuid::parse_str(&claims.id) {
        Ok(user_id) => {
            if let Err(response) = ensure_oauth_permissions(
                &state,
                user_id,
                claims.plan.as_deref(),
                params.workspace,
                manifest,
            )
            .await
            {
                return response;
            }
        }
        Err(_) => {
            let plan_tier = NormalizedPlanTier::from_option(claims.plan.as_deref());
            if plan_tier.is_solo() {
                return redirect_with_error(
                    &state.config,
                    integration_id,
                    OAUTH_PLAN_RESTRICTION_MESSAGE,
                );
            }
        }
    }

    let state_token = generate_csrf_token();
    let cookie = build_state_cookie(GOOGLE_STATE_COOKIE, &state_token);
    let jar = jar.add(cookie);

    let mut url = Url::parse(GOOGLE_AUTH_URL).expect("valid google auth url");
    url.query_pairs_mut()
        .append_pair("client_id", &state.config.oauth.google.client_id)
        .append_pair("redirect_uri", &state.config.oauth.google.redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", state.oauth_accounts.google_scopes())
        .append_pair("access_type", "offline")
        .append_pair("prompt", "consent")
        .append_pair("state", &state_token);

    (jar, Redirect::to(url.as_str())).into_response()
}

pub async fn github_connect_start(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    Query(params): Query<ConnectQuery>,
    jar: CookieJar,
) -> Response {
    let integration_id = GITHUB_INTEGRATION_ID;
    let (manifest, _provider) =
        match resolve_oauth_integration(state.integration_registry.as_ref(), integration_id) {
            Ok(result) => result,
            Err(response) => return response,
        };

    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(user_id) => user_id,
        Err(_) => {
            return redirect_with_error(&state.config, integration_id, "Invalid user");
        }
    };

    if let Err(response) = ensure_oauth_permissions(
        &state,
        user_id,
        claims.plan.as_deref(),
        params.workspace,
        manifest,
    )
    .await
    {
        return response;
    }

    let state_token = generate_csrf_token();
    let cookie = build_state_cookie(GITHUB_STATE_COOKIE, &state_token);
    let jar = jar.add(cookie);

    // This authorize URL is valid only for GitHub Apps with user OAuth enabled.
    let mut url = Url::parse(GITHUB_AUTH_URL).expect("valid github auth url");
    url.query_pairs_mut()
        .append_pair("client_id", &state.config.oauth.github.client_id)
        .append_pair("redirect_uri", &state.config.oauth.github.redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", state.oauth_accounts.github_scopes())
        .append_pair("state", &state_token);

    (jar, Redirect::to(url.as_str())).into_response()
}

pub async fn google_connect_callback(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    jar: CookieJar,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let integration_id = GOOGLE_INTEGRATION_ID;
    let (_manifest, provider) =
        match resolve_oauth_integration(state.integration_registry.as_ref(), integration_id) {
            Ok(result) => result,
            Err(response) => return response,
        };
    handle_callback(
        state,
        claims,
        jar,
        query,
        provider,
        integration_id,
        GOOGLE_STATE_COOKIE,
    )
    .await
}

pub async fn github_connect_callback(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    jar: CookieJar,
    Query(query): Query<CallbackQuery>,
) -> Response {
    info!("GitHub OAuth callback received");
    let integration_id = GITHUB_INTEGRATION_ID;
    let (_manifest, provider) =
        match resolve_oauth_integration(state.integration_registry.as_ref(), integration_id) {
            Ok(result) => result,
            Err(response) => return response,
        };
    handle_callback(
        state,
        claims,
        jar,
        query,
        provider,
        integration_id,
        GITHUB_STATE_COOKIE,
    )
    .await
}

pub async fn microsoft_connect_start(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    Query(params): Query<ConnectQuery>,
    jar: CookieJar,
) -> Response {
    let integration_id = MICROSOFT_INTEGRATION_ID;
    let (manifest, _provider) =
        match resolve_oauth_integration(state.integration_registry.as_ref(), integration_id) {
            Ok(result) => result,
            Err(response) => return response,
        };

    match Uuid::parse_str(&claims.id) {
        Ok(user_id) => {
            if let Err(response) = ensure_oauth_permissions(
                &state,
                user_id,
                claims.plan.as_deref(),
                params.workspace,
                manifest,
            )
            .await
            {
                return response;
            }
        }
        Err(_) => {
            let plan_tier = NormalizedPlanTier::from_option(claims.plan.as_deref());
            if plan_tier.is_solo() {
                return redirect_with_error(
                    &state.config,
                    integration_id,
                    OAUTH_PLAN_RESTRICTION_MESSAGE,
                );
            }
        }
    }

    let state_token = generate_csrf_token();
    let cookie = build_state_cookie(MICROSOFT_STATE_COOKIE, &state_token);
    let jar = jar.add(cookie);

    let mut url = Url::parse(MICROSOFT_AUTH_URL).expect("valid microsoft auth url");
    url.query_pairs_mut()
        .append_pair("client_id", &state.config.oauth.microsoft.client_id)
        .append_pair("redirect_uri", &state.config.oauth.microsoft.redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", state.oauth_accounts.microsoft_scopes())
        .append_pair("response_mode", "query")
        .append_pair("state", &state_token);

    (jar, Redirect::to(url.as_str())).into_response()
}

pub async fn microsoft_connect_callback(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    jar: CookieJar,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let integration_id = MICROSOFT_INTEGRATION_ID;
    let (_manifest, provider) =
        match resolve_oauth_integration(state.integration_registry.as_ref(), integration_id) {
            Ok(result) => result,
            Err(response) => return response,
        };
    handle_callback(
        state,
        claims,
        jar,
        query,
        provider,
        integration_id,
        MICROSOFT_STATE_COOKIE,
    )
    .await
}

pub async fn slack_connect_start(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    Query(params): Query<ConnectQuery>,
    jar: CookieJar,
) -> Response {
    let integration_id = SLACK_INTEGRATION_ID;
    let (manifest, provider) =
        match resolve_oauth_integration(state.integration_registry.as_ref(), integration_id) {
            Ok(result) => result,
            Err(response) => return response,
        };

    let workspace_id = match params.workspace {
        Some(workspace_id) => workspace_id,
        None => {
            return redirect_with_error_for_manifest(
                &state.config,
                manifest,
                SLACK_WORKSPACE_REQUIRED_MESSAGE,
                None,
            );
        }
    };

    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(user_id) => user_id,
        Err(_) => {
            return redirect_with_error_with_workspace(
                &state.config,
                integration_id,
                "Invalid user",
                Some(workspace_id),
            );
        }
    };

    if let Err(response) = ensure_oauth_permissions(
        &state,
        user_id,
        claims.plan.as_deref(),
        Some(workspace_id),
        manifest,
    )
    .await
    {
        return response;
    }

    if let Some(workspace_connection_id) = params.workspace_connection_id {
        let connection = match state
            .workspace_connection_repo
            .find_by_id(workspace_connection_id)
            .await
        {
            Ok(Some(connection)) => connection,
            Ok(None) => {
                return redirect_with_error_for_manifest(
                    &state.config,
                    manifest,
                    "Slack personal authorization requires a workspace Slack connection.",
                    Some(workspace_id),
                );
            }
            Err(err) => {
                error!(
                    %workspace_id,
                    %workspace_connection_id,
                    ?err,
                    "failed to load workspace connection for Slack personal OAuth"
                );
                return redirect_with_error_for_manifest(
                    &state.config,
                    manifest,
                    OAUTH_WORKSPACE_ACCESS_ERROR_MESSAGE,
                    Some(workspace_id),
                );
            }
        };

        if connection.workspace_id != workspace_id || connection.provider != provider {
            return redirect_with_error_for_manifest(
                &state.config,
                manifest,
                "Slack personal authorization requires a workspace Slack connection.",
                Some(workspace_id),
            );
        }
    };

    let state_token = build_slack_state(workspace_id);
    let cookie = build_state_cookie(SLACK_STATE_COOKIE, &state_token);
    let jar = jar.add(cookie);

    let bot_scopes = state.oauth_accounts.slack_bot_scopes();
    let user_scopes = state.oauth_accounts.slack_scopes();

    if params.workspace_connection_id.is_some() {
        info!(
            provider = SLACK_INTEGRATION_ID,
            workspace_id = %workspace_id,
            user_scopes,
            "Starting Slack personal OAuth authorization"
        );
    } else {
        info!(
            provider = SLACK_INTEGRATION_ID,
            workspace_id = %workspace_id,
            bot_scopes,
            user_scopes,
            "Starting Slack OAuth install with requested scopes"
        );
    }

    let mut url = Url::parse(SLACK_AUTH_URL).expect("valid slack auth url");
    url.query_pairs_mut()
        .append_pair("client_id", &state.config.oauth.slack.client_id)
        .append_pair("redirect_uri", &state.config.oauth.slack.redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("state", &state_token)
        .append_pair("scope", bot_scopes)
        .append_pair("user_scope", user_scopes)
        .append_pair("prompt", "consent");

    (jar, Redirect::to(url.as_str())).into_response()
}

pub async fn slack_connect_callback(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    jar: CookieJar,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let integration_id = SLACK_INTEGRATION_ID;
    let (manifest, provider) =
        match resolve_oauth_integration(state.integration_registry.as_ref(), integration_id) {
            Ok(result) => result,
            Err(response) => return response,
        };
    let workspace_hint = jar
        .get(SLACK_STATE_COOKIE)
        .and_then(|cookie| parse_slack_state(cookie.value()));

    if let Some(error) = query.error.clone().or(query.error_description.clone()) {
        return redirect_with_error_with_workspace(
            &state.config,
            integration_id,
            &error,
            workspace_hint,
        );
    }

    let code = match query.code.clone() {
        Some(code) => code,
        None => {
            return redirect_with_error_with_workspace(
                &state.config,
                integration_id,
                "Missing code",
                workspace_hint,
            );
        }
    };

    let expected_state = match jar.get(SLACK_STATE_COOKIE) {
        Some(cookie) => cookie.value().to_string(),
        None => {
            return redirect_with_error_with_workspace(
                &state.config,
                integration_id,
                "Missing state",
                workspace_hint,
            );
        }
    };

    let provided_state = match query.state.clone() {
        Some(state) => state,
        None => {
            return redirect_with_error_with_workspace(
                &state.config,
                integration_id,
                "Missing state",
                workspace_hint,
            );
        }
    };

    if provided_state != expected_state {
        return redirect_with_error_with_workspace(
            &state.config,
            integration_id,
            "Invalid state",
            workspace_hint,
        );
    }

    let jar = clear_state_cookie(jar, SLACK_STATE_COOKIE);
    let workspace_id = match parse_slack_state(&expected_state) {
        Some(workspace_id) => workspace_id,
        None => {
            let response = redirect_with_error_with_workspace(
                &state.config,
                integration_id,
                SLACK_WORKSPACE_REQUIRED_MESSAGE,
                None,
            );
            return (jar, response).into_response();
        }
    };

    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => {
            let response = redirect_with_error_with_workspace(
                &state.config,
                integration_id,
                "Invalid user",
                Some(workspace_id),
            );
            return (jar, response).into_response();
        }
    };

    if let Err(response) = ensure_oauth_permissions(
        &state,
        user_id,
        claims.plan.as_deref(),
        Some(workspace_id),
        manifest,
    )
    .await
    {
        return (jar, response).into_response();
    }

    let (personal_tokens, workspace_tokens) = match state
        .oauth_accounts
        .exchange_slack_install_tokens(&code)
        .await
    {
        Ok(tokens) => tokens,
        Err(err) => {
            error!("OAuth authorization exchange failed: {err}");
            let response = redirect_with_error_with_workspace(
                &state.config,
                integration_id,
                &error_message_for_redirect(&err),
                Some(workspace_id),
            );
            return (jar, response).into_response();
        }
    };

    if let Err(message) = validate_slack_bot_scopes(&state, &workspace_tokens.access_token).await {
        let response = redirect_with_error_with_workspace(
            &state.config,
            integration_id,
            &message,
            Some(workspace_id),
        );
        return (jar, response).into_response();
    }

    let stored_personal = match state
        .oauth_accounts
        .save_authorization_deduped(user_id, provider, personal_tokens)
        .await
    {
        Ok(token) => token,
        Err(err) => {
            error!("Saving OAuth authorization failed: {err}");
            let response = redirect_with_error_with_workspace(
                &state.config,
                integration_id,
                &error_message_for_redirect(&err),
                Some(workspace_id),
            );
            return (jar, response).into_response();
        }
    };

    if let Err(err) = state
        .workspace_oauth
        .install_slack_workspace_connection(
            workspace_id,
            user_id,
            Some(stored_personal.id),
            workspace_tokens,
        )
        .await
    {
        error!("Saving Slack workspace install failed: {err}");
        let message = match err {
            WorkspaceOAuthError::Forbidden => {
                "Not authorized to install Slack for this workspace".to_string()
            }
            WorkspaceOAuthError::SlackInstallRequired => err.to_string(),
            WorkspaceOAuthError::OAuth(inner) => error_message_for_redirect(&inner),
            _ => "Failed to install Slack workspace connection".to_string(),
        };
        let response = redirect_with_error_with_workspace(
            &state.config,
            integration_id,
            &message,
            Some(workspace_id),
        );
        return (jar, response).into_response();
    }

    (
        jar,
        redirect_success_with_workspace(&state.config, integration_id, workspace_id),
    )
        .into_response()
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct SlackAuthTestResponse {
    ok: bool,
    team_id: Option<String>,
    user_id: Option<String>,
    error: Option<String>,
    response_metadata: Option<SlackAuthTestMetadata>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct SlackAuthTestMetadata {
    scopes: Option<Vec<String>>,
    scope: Option<String>,
}

struct SlackAuthTestResult {
    team_id: Option<String>,
    #[allow(dead_code)]
    user_id: Option<String>,
    scopes: Vec<String>,
}

async fn validate_slack_bot_scopes(state: &AppState, access_token: &str) -> Result<(), String> {
    let auth_test = slack_auth_test(state, access_token, true).await?;
    let required = split_scopes(state.oauth_accounts.slack_bot_scopes());
    let missing: Vec<String> = required
        .iter()
        .filter(|scope| !auth_test.scopes.iter().any(|s| s == *scope))
        .cloned()
        .collect();

    if missing.is_empty() {
        return Ok(());
    }

    warn!(
        provider = "slack",
        team_id = ?auth_test.team_id,
        missing = ?missing,
        "Slack bot token missing required scopes"
    );

    Err(format!(
        "Slack install missing required bot scopes ({}). Reinstall Slack to continue.",
        missing.join(", ")
    ))
}

async fn slack_auth_test(
    state: &AppState,
    access_token: &str,
    require_scopes: bool,
) -> Result<SlackAuthTestResult, String> {
    let base = std::env::var("SLACK_API_BASE_URL")
        .ok()
        .or_else(|| std::env::var("SLACK_API_BASE").ok())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "https://slack.com/api".to_string());
    let url = format!("{}/auth.test", base.trim_end_matches('/'));

    let response = state
        .http_client
        .get(&url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|err| {
            error!(?err, "Slack auth.test request failed");
            "Slack auth.test request failed".to_string()
        })?;

    let status = response.status();
    let headers = response.headers().clone();
    let body = response.text().await.unwrap_or_default();

    if !status.is_success() {
        error!(%status, body, "Slack auth.test returned HTTP error");
        return Err("Slack auth.test failed".to_string());
    }

    let parsed: SlackAuthTestResponse = serde_json::from_str(&body).map_err(|err| {
        error!(?err, body, "Slack auth.test response parse failed");
        "Slack auth.test returned an unexpected response".to_string()
    })?;

    if !parsed.ok {
        let message = parsed
            .error
            .unwrap_or_else(|| "Slack auth.test failed".to_string());
        error!(error = %message, "Slack auth.test returned error");
        return Err(message);
    }

    let mut scopes = headers
        .get("x-oauth-scopes")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(split_scopes)
        .unwrap_or_default();

    if scopes.is_empty() {
        if let Some(metadata) = parsed.response_metadata.as_ref() {
            if let Some(list) = metadata.scopes.as_ref() {
                scopes = list
                    .iter()
                    .map(|scope| scope.trim())
                    .filter(|scope| !scope.is_empty())
                    .map(|scope| scope.to_string())
                    .collect();
            } else if let Some(scope) = metadata.scope.as_deref() {
                scopes = split_scopes(scope);
            }
        }
    }

    if require_scopes && scopes.is_empty() {
        return Err("Slack auth.test response missing scopes".to_string());
    }

    let team_id = parsed
        .team_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());
    let user_id = parsed
        .user_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());
    let token_prefix: String = access_token.chars().take(12).collect();
    if require_scopes {
        info!(
            provider = "slack",
            token_prefix = %token_prefix,
            team_id = ?team_id,
            scopes = %scopes.join(","),
            "Slack bot token validated via auth.test"
        );
    } else {
        info!(
            provider = "slack",
            token_prefix = %token_prefix,
            team_id = ?team_id,
            user_id = ?user_id,
            "Slack user token validated via auth.test"
        );
    }

    Ok(SlackAuthTestResult {
        team_id,
        user_id,
        scopes,
    })
}

fn split_scopes(scopes: &str) -> Vec<String> {
    scopes
        .split(',')
        .map(|scope| scope.trim())
        .filter(|scope| !scope.is_empty())
        .map(|scope| scope.to_string())
        .collect()
}

pub async fn asana_connect_start(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    Query(params): Query<ConnectQuery>,
    jar: CookieJar,
) -> Response {
    let integration_id = ASANA_INTEGRATION_ID;
    let (manifest, _provider) =
        match resolve_oauth_integration(state.integration_registry.as_ref(), integration_id) {
            Ok(result) => result,
            Err(response) => return response,
        };

    match Uuid::parse_str(&claims.id) {
        Ok(user_id) => {
            if let Err(response) = ensure_oauth_permissions(
                &state,
                user_id,
                claims.plan.as_deref(),
                params.workspace,
                manifest,
            )
            .await
            {
                return response;
            }
        }
        Err(_) => {
            let plan_tier = NormalizedPlanTier::from_option(claims.plan.as_deref());
            if plan_tier.is_solo() {
                return redirect_with_error(
                    &state.config,
                    integration_id,
                    OAUTH_PLAN_RESTRICTION_MESSAGE,
                );
            }
        }
    }

    let state_token = generate_csrf_token();
    let cookie = build_state_cookie(ASANA_STATE_COOKIE, &state_token);
    let jar = jar.add(cookie);

    let mut url = Url::parse(ASANA_AUTH_URL).expect("valid asana auth url");
    url.query_pairs_mut()
        .append_pair("client_id", &state.config.oauth.asana.client_id)
        .append_pair("redirect_uri", &state.config.oauth.asana.redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", state.oauth_accounts.asana_scopes())
        .append_pair("state", &state_token);

    (jar, Redirect::to(url.as_str())).into_response()
}

pub async fn asana_connect_callback(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    jar: CookieJar,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let integration_id = ASANA_INTEGRATION_ID;
    let (_manifest, provider) =
        match resolve_oauth_integration(state.integration_registry.as_ref(), integration_id) {
            Ok(result) => result,
            Err(response) => return response,
        };
    handle_callback(
        state,
        claims,
        jar,
        query,
        provider,
        integration_id,
        ASANA_STATE_COOKIE,
    )
    .await
}

pub async fn notion_connect_start(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    Query(params): Query<ConnectQuery>,
    jar: CookieJar,
) -> Response {
    let integration_id = NOTION_INTEGRATION_ID;
    let (manifest, _provider) =
        match resolve_oauth_integration(state.integration_registry.as_ref(), integration_id) {
            Ok(result) => result,
            Err(response) => return response,
        };

    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(user_id) => user_id,
        Err(_) => {
            return redirect_with_error(&state.config, integration_id, "Invalid user");
        }
    };

    let connection_scope =
        match normalize_notion_scope(params.connection_scope.as_deref(), params.workspace) {
            Ok(scope) => scope,
            Err(resp) => return *resp,
        };

    let workspace_id = if connection_scope == "workspace" {
        params.workspace
    } else {
        None
    };

    if let Err(response) = ensure_oauth_permissions(
        &state,
        user_id,
        claims.plan.as_deref(),
        workspace_id,
        manifest,
    )
    .await
    {
        return response;
    }

    let state_payload = NotionState {
        user_id,
        workspace_id,
        connection_scope: connection_scope.clone(),
        nonce: generate_csrf_token(),
    };

    let state_token = match encode_notion_state(&state_payload) {
        Ok(token) => token,
        Err(resp) => return *resp,
    };

    let cookie = build_state_cookie(NOTION_STATE_COOKIE, &state_token);
    let jar = jar.add(cookie);

    let mut url = Url::parse(NOTION_AUTH_URL).expect("valid notion auth url");
    url.query_pairs_mut()
        .append_pair("client_id", &state.config.oauth.notion.client_id)
        .append_pair("redirect_uri", &state.config.oauth.notion.redirect_uri)
        .append_pair("response_type", "code")
        .append_pair(
            "owner",
            if connection_scope == "workspace" {
                "workspace"
            } else {
                "user"
            },
        )
        .append_pair("state", &state_token);

    (jar, Redirect::to(url.as_str())).into_response()
}

pub async fn notion_connect_callback(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    jar: CookieJar,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let integration_id = NOTION_INTEGRATION_ID;
    let (manifest, provider) =
        match resolve_oauth_integration(state.integration_registry.as_ref(), integration_id) {
            Ok(result) => result,
            Err(response) => return response,
        };

    if let Some(error) = query.error.clone().or(query.error_description.clone()) {
        return redirect_with_error(&state.config, integration_id, &error);
    }

    let code = match query.code.clone() {
        Some(code) => code,
        None => {
            return redirect_with_error(&state.config, integration_id, "Missing code");
        }
    };

    let expected_state = match jar.get(NOTION_STATE_COOKIE) {
        Some(cookie) => cookie.value().to_string(),
        None => return redirect_with_error(&state.config, integration_id, "Missing state"),
    };

    let provided_state = match query.state.clone() {
        Some(state) => state,
        None => return redirect_with_error(&state.config, integration_id, "Missing state"),
    };

    if provided_state != expected_state {
        return redirect_with_error(&state.config, integration_id, "Invalid state");
    }

    let jar = clear_state_cookie(jar, NOTION_STATE_COOKIE);

    let state_payload = match decode_notion_state(&expected_state) {
        Some(payload) => payload,
        None => {
            let response =
                redirect_with_error(&state.config, integration_id, "Invalid state payload");
            return (jar, response).into_response();
        }
    };

    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => {
            let response = redirect_with_error(&state.config, integration_id, "Invalid user");
            return (jar, response).into_response();
        }
    };

    if state_payload.user_id != user_id {
        let response = redirect_with_error(&state.config, integration_id, "Invalid state");
        return (jar, response).into_response();
    }

    let connection_scope = state_payload.connection_scope.trim().to_ascii_lowercase();
    let workspace_id = state_payload.workspace_id;

    if let Err(response) = ensure_oauth_permissions(
        &state,
        user_id,
        claims.plan.as_deref(),
        workspace_id,
        manifest,
    )
    .await
    {
        return (jar, response).into_response();
    }

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

    let stored = match state
        .oauth_accounts
        .save_authorization_deduped(user_id, provider, tokens)
        .await
    {
        Ok(token) => token,
        Err(err) => {
            error!("Saving OAuth authorization failed: {err}");
            let response = redirect_with_error(
                &state.config,
                integration_id,
                &error_message_for_redirect(&err),
            );
            return (jar, response).into_response();
        }
    };

    if connection_scope == "workspace" {
        let Some(workspace_id) = workspace_id else {
            let response = redirect_with_error(
                &state.config,
                integration_id,
                "Workspace connection requires a workspace id",
            );
            return (jar, response).into_response();
        };

        if let Err(err) = state
            .workspace_oauth
            .promote_connection_with_token(workspace_id, user_id, provider, Some(stored.id))
            .await
        {
            error!("Saving Notion workspace connection failed: {err}");
            let message = match err {
                WorkspaceOAuthError::Forbidden => {
                    "Not authorized to install Notion for this workspace".to_string()
                }
                WorkspaceOAuthError::SlackInstallRequired => err.to_string(),
                WorkspaceOAuthError::OAuth(inner) => error_message_for_redirect(&inner),
                _ => "Failed to install Notion workspace connection".to_string(),
            };
            let response = redirect_with_error_with_workspace(
                &state.config,
                integration_id,
                &message,
                Some(workspace_id),
            );
            return (jar, response).into_response();
        }

        (
            jar,
            redirect_success_with_workspace(&state.config, integration_id, workspace_id),
        )
            .into_response()
    } else {
        let response = if let Some(workspace_id) = workspace_id {
            redirect_success_with_workspace(&state.config, integration_id, workspace_id)
        } else {
            let url = format!(
                "{}/dashboard?connected=true&provider={}",
                state.config.frontend_origin, integration_id
            );
            Redirect::to(&url)
        };
        (jar, response).into_response()
    }
}

pub async fn bitly_connect_start(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    Query(params): Query<ConnectQuery>,
    jar: CookieJar,
) -> Response {
    let integration_id = BITLY_INTEGRATION_ID;

    let (manifest, _provider) =
        match resolve_oauth_integration(state.integration_registry.as_ref(), integration_id) {
            Ok(result) => result,
            Err(response) => return response,
        };

    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(user_id) => user_id,
        Err(_) => {
            return redirect_with_error(&state.config, integration_id, "Invalid user");
        }
    };

    // Bitly has no workspace-only rules, but plan enforcement still applies
    if let Err(response) = ensure_oauth_permissions(
        &state,
        user_id,
        claims.plan.as_deref(),
        params.workspace,
        manifest,
    )
    .await
    {
        return response;
    }

    let state_token = generate_csrf_token();
    let cookie = build_state_cookie(BITLY_STATE_COOKIE, &state_token);
    let jar = jar.add(cookie);

    let mut url = Url::parse(BITLY_AUTH_URL).expect("valid bitly auth url");
    url.query_pairs_mut()
        .append_pair("client_id", &state.config.oauth.bitly.client_id)
        .append_pair("redirect_uri", &state.config.oauth.bitly.redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("state", &state_token);

    (jar, Redirect::to(url.as_str())).into_response()
}

pub async fn bitly_connect_callback(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    jar: CookieJar,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let integration_id = BITLY_INTEGRATION_ID;
    let (_manifest, provider) =
        match resolve_oauth_integration(state.integration_registry.as_ref(), integration_id) {
            Ok(result) => result,
            Err(response) => return response,
        };
    handle_callback(
        state,
        claims,
        jar,
        query,
        provider,
        integration_id,
        BITLY_STATE_COOKIE,
    )
    .await
}

pub async fn raindrop_connect_start(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    Query(params): Query<ConnectQuery>,
    jar: CookieJar,
) -> Response {
    let integration_id = RAINDROP_INTEGRATION_ID;

    let (manifest, _provider) =
        match resolve_oauth_integration(state.integration_registry.as_ref(), integration_id) {
            Ok(result) => result,
            Err(response) => return response,
        };

    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(user_id) => user_id,
        Err(_) => {
            return redirect_with_error(&state.config, integration_id, "Invalid user");
        }
    };

    if let Err(response) = ensure_oauth_permissions(
        &state,
        user_id,
        claims.plan.as_deref(),
        params.workspace,
        manifest,
    )
    .await
    {
        return response;
    }

    let state_token = generate_csrf_token();
    let cookie = build_state_cookie(RAINDROP_STATE_COOKIE, &state_token);
    let jar = jar.add(cookie);

    let mut url = Url::parse(RAINDROP_AUTH_URL).expect("valid raindrop auth url");
    url.query_pairs_mut()
        .append_pair("client_id", &state.config.oauth.raindrop.client_id)
        .append_pair("redirect_uri", &state.config.oauth.raindrop.redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("state", &state_token);

    (jar, Redirect::to(url.as_str())).into_response()
}

pub async fn raindrop_connect_callback(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    jar: CookieJar,
    Query(query): Query<CallbackQuery>,
) -> Response {
    let integration_id = RAINDROP_INTEGRATION_ID;
    let (_manifest, provider) =
        match resolve_oauth_integration(state.integration_registry.as_ref(), integration_id) {
            Ok(result) => result,
            Err(response) => return response,
        };
    handle_callback(
        state,
        claims,
        jar,
        query,
        provider,
        integration_id,
        RAINDROP_STATE_COOKIE,
    )
    .await
}
