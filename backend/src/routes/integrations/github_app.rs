use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};
use tracing::{debug, error, info};
use uuid::Uuid;

use crate::db::workspace_connection_repository::NewWorkspaceConnection;
use crate::models::oauth_token::ConnectedOAuthProvider;
use crate::responses::JsonResponse;
use crate::services::oauth::account_service::installation_id_from_metadata;
use crate::state::AppState;
use crate::utils::jwt::JwtKeys;

const GITHUB_API_BASE: &str = "https://api.github.com";
const GITHUB_APP_INSTALL_FLOW: &str = "github_app_install";
const GITHUB_APP_STATE_AUDIENCE: &str = "dsentr.github.app.install";

#[derive(Debug, Deserialize)]
pub struct GitHubAppInstallCallbackQuery {
    #[serde(default)]
    pub installation_id: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub setup_action: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug)]
struct GitHubAppInstallState {
    flow: String,
    workspace_id: Uuid,
}

#[derive(Debug, Deserialize)]
struct GitHubInstallationAccount {
    login: Option<String>,
    #[serde(rename = "type")]
    account_type: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubInstallationResponse {
    account: Option<GitHubInstallationAccount>,
    repository_selection: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubInstallationTokenResponse {
    token: String,
    expires_at: String,
    repository_selection: Option<String>,
    repositories: Option<Vec<GitHubRepository>>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct GitHubRepository {
    id: i64,
    name: String,
    full_name: String,
}

#[derive(Debug, Serialize)]
struct GitHubAppJwtClaims {
    iat: i64,
    exp: i64,
    iss: String,
}

pub async fn github_app_install_callback(
    State(app_state): State<AppState>,
    Query(query): Query<GitHubAppInstallCallbackQuery>,
) -> Response {
    info!("GitHub App install callback unauthenticated (no session or CSRF required)");
    info!(
        setup_action = ?query.setup_action,
        "GitHub App install callback received"
    );

    if query.code.is_some() || query.error.is_some() {
        error!(
            code_present = query.code.is_some(),
            error_present = query.error.is_some(),
            "GitHub App install callback received OAuth fields; refusing to proceed"
        );
        return JsonResponse::bad_request(
            "GitHub App installation callback cannot accept OAuth parameters.",
        )
        .into_response();
    };

    let installation_id = match query
        .installation_id
        .as_deref()
        .and_then(normalize_installation_id)
    {
        Some(id) => id,
        None => {
            error!("GitHub App install callback missing installation_id");
            return JsonResponse::bad_request("Missing installation_id").into_response();
        }
    };

    let state_raw = match query
        .state
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        Some(state) => state,
        None => {
            error!("GitHub App install callback missing state");
            return JsonResponse::bad_request("Missing state").into_response();
        }
    };

    let state = match parse_install_state(
        state_raw,
        app_state.jwt_keys.as_ref(),
        &app_state.config.jwt_issuer,
    ) {
        Ok(parsed) if parsed.flow == GITHUB_APP_INSTALL_FLOW => parsed,
        Ok(_) => {
            error!("GitHub App install callback state flow mismatch");
            return JsonResponse::bad_request("Invalid state").into_response();
        }
        Err(err) => {
            error!(?err, "GitHub App install callback state parse failed");
            return JsonResponse::bad_request("Invalid state").into_response();
        }
    };

    debug!(
        flow = %state.flow,
        workspace_id = %state.workspace_id,
        "GitHub App install callback state decoded"
    );

    let workspace_id = state.workspace_id;
    let workspace = match app_state.workspace_repo.find_workspace(workspace_id).await {
        Ok(Some(workspace)) => workspace,
        Ok(None) => {
            error!(%workspace_id, "GitHub App install callback workspace not found");
            return JsonResponse::bad_request("Workspace not found").into_response();
        }
        Err(err) => {
            error!(
                ?err,
                %workspace_id,
                "GitHub App install callback failed to verify workspace"
            );
            return JsonResponse::server_error("Failed to verify workspace").into_response();
        }
    };
    if workspace.owner_id == Uuid::nil() {
        error!(
            %workspace_id,
            "GitHub App install callback workspace owner_id is invalid"
        );
        return JsonResponse::server_error("Workspace owner is invalid").into_response();
    }

    let jwt = match build_github_app_jwt(&app_state) {
        Ok(token) => token,
        Err(err) => {
            error!(
                ?err,
                "GitHub App install callback failed to generate app JWT"
            );
            return redirect_install_error(
                &app_state,
                workspace_id,
                "GitHub App configuration is missing.",
            )
            .into_response();
        }
    };

    let installation_info =
        match fetch_installation_details(&app_state, &jwt, &installation_id).await {
            Ok(info) => {
                info!(
                    installation_id = %installation_id,
                    "GitHub App installation lookup succeeded"
                );
                info
            }
            Err(message) => {
                error!(
                    installation_id = %installation_id,
                    "GitHub App installation lookup failed"
                );
                return redirect_install_error(&app_state, workspace_id, &message).into_response();
            }
        };

    let installation_token =
        match exchange_installation_token(&app_state, &jwt, &installation_id).await {
            Ok(token) => {
                info!(
                    installation_id = %installation_id,
                    "GitHub App installation token exchange succeeded"
                );
                info!(
                    installation_id = %installation_id,
                    expires_at = %token.expires_at,
                    "GitHub App installation token expiry recorded"
                );
                token
            }
            Err(message) => {
                error!(
                    installation_id = %installation_id,
                    "GitHub App installation token exchange failed"
                );
                return redirect_install_error(&app_state, workspace_id, &message).into_response();
            }
        };

    let expires_at = match OffsetDateTime::parse(&installation_token.expires_at, &Rfc3339) {
        Ok(value) => value,
        Err(err) => {
            error!(?err, "GitHub App install callback invalid expires_at");
            return redirect_install_error(
                &app_state,
                workspace_id,
                "GitHub App token response was invalid.",
            )
            .into_response();
        }
    };

    let account_login = installation_info
        .account
        .as_ref()
        .and_then(|account| account.login.as_ref())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "GitHub App".to_string());

    let account_type = installation_info
        .account
        .as_ref()
        .and_then(|account| account.account_type.as_ref())
        .map(|value| value.trim().to_string());

    let repository_selection = installation_token
        .repository_selection
        .clone()
        .or_else(|| installation_info.repository_selection.clone());

    let repositories_metadata = installation_token.repositories.clone().unwrap_or_default();

    let metadata = build_installation_metadata(
        &installation_id,
        account_type.as_deref(),
        account_login.as_str(),
        repository_selection.as_deref(),
        &repositories_metadata,
    );

    if let Err(err) = upsert_workspace_connection(
        &app_state,
        GitHubInstallConnectionPayload {
            workspace_id,
            owner_user_id: workspace.owner_id,
            installation_id: installation_id.as_str(),
            account_login,
            access_token: installation_token.token,
            expires_at,
            metadata,
        },
    )
    .await
    {
        error!(
            ?err,
            "GitHub App install callback failed to persist connection"
        );
        return redirect_install_error(
            &app_state,
            workspace_id,
            "Failed to save GitHub App installation.",
        )
        .into_response();
    }

    info!(
        installation_id = %installation_id,
        workspace_id = %workspace_id,
        "GitHub App installation stored"
    );

    Redirect::to(&build_success_redirect(&app_state, workspace_id)).into_response()
}

fn normalize_installation_id(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.chars().all(|ch| ch.is_ascii_digit()) {
        Some(trimmed.to_string())
    } else {
        None
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GitHubAppInstallStateClaims {
    flow: String,
    workspace_id: Uuid,
    exp: usize,
    iss: String,
    aud: String,
}

fn parse_install_state(
    raw: &str,
    jwt_keys: &JwtKeys,
    jwt_issuer: &str,
) -> Result<GitHubAppInstallState, &'static str> {
    use jsonwebtoken::{decode, Validation};
    use std::collections::HashSet;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_audience(&[GITHUB_APP_STATE_AUDIENCE]);
    validation.iss = Some(HashSet::from([jwt_issuer.to_string()]));
    validation.validate_exp = true;
    validation.required_spec_claims.insert("exp".to_string());
    validation.required_spec_claims.insert("aud".to_string());
    validation.required_spec_claims.insert("iss".to_string());

    let data = decode::<GitHubAppInstallStateClaims>(raw, jwt_keys.decoding_key(), &validation)
        .map_err(|_| "invalid state")?;

    let flow = data.claims.flow;
    let workspace_id = data.claims.workspace_id;

    if flow.trim().is_empty() || workspace_id == Uuid::nil() {
        return Err("invalid state");
    }

    Ok(GitHubAppInstallState { flow, workspace_id })
}

fn build_github_app_jwt(app_state: &AppState) -> Result<String, String> {
    let app_id = app_state
        .config
        .github_app
        .app_id
        .ok_or_else(|| "GitHub App ID is missing".to_string())?;
    let private_key = app_state
        .config
        .github_app
        .private_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "GitHub App private key is missing".to_string())?;

    let now = OffsetDateTime::now_utc();
    let iat = now.unix_timestamp();
    let exp = (now + Duration::minutes(9)).unix_timestamp();
    let claims = GitHubAppJwtClaims {
        iat,
        exp,
        iss: app_id.to_string(),
    };

    let key = EncodingKey::from_rsa_pem(private_key.as_bytes())
        .map_err(|err| format!("Failed to parse GitHub App private key: {err}"))?;

    jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, &key)
        .map_err(|err| format!("Failed to sign GitHub App JWT: {err}"))
}

async fn fetch_installation_details(
    app_state: &AppState,
    jwt: &str,
    installation_id: &str,
) -> Result<GitHubInstallationResponse, String> {
    let url = format!("{}/app/installations/{}", GITHUB_API_BASE, installation_id);
    let response = app_state
        .http_client
        .get(&url)
        .header("Authorization", format!("Bearer {jwt}"))
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "dsentr")
        .send()
        .await
        .map_err(|err| format!("GitHub App install lookup failed: {err}"))?;

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        error!(
            status = %status,
            body = %body,
            "GitHub App install lookup failed"
        );
        return Err("GitHub App installation lookup failed.".to_string());
    }

    serde_json::from_str(&body).map_err(|err| {
        error!(?err, body = %body, "GitHub App install lookup parse failed");
        "GitHub App installation lookup failed.".to_string()
    })
}

async fn exchange_installation_token(
    app_state: &AppState,
    jwt: &str,
    installation_id: &str,
) -> Result<GitHubInstallationTokenResponse, String> {
    let url = format!(
        "{}/app/installations/{}/access_tokens",
        GITHUB_API_BASE, installation_id
    );
    let response = app_state
        .http_client
        .post(&url)
        .header("Authorization", format!("Bearer {jwt}"))
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "dsentr")
        .send()
        .await
        .map_err(|err| format!("GitHub App token exchange failed: {err}"))?;

    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        error!(
            status = %status,
            body = %body,
            "GitHub App token exchange failed"
        );
        return Err("GitHub App token exchange failed.".to_string());
    }

    serde_json::from_str(&body).map_err(|err| {
        error!(?err, body = %body, "GitHub App token exchange parse failed");
        "GitHub App token exchange failed.".to_string()
    })
}

fn build_installation_metadata(
    installation_id: &str,
    account_type: Option<&str>,
    account_login: &str,
    repository_selection: Option<&str>,
    repositories: &[GitHubRepository],
) -> Value {
    let repository_payload = repositories
        .iter()
        .map(|repo| json!({ "id": repo.id, "name": repo.name, "full_name": repo.full_name }))
        .collect::<Vec<_>>();

    json!({
        "token_type": "github_installation",
        "installation_id": installation_id,
        "installation_revoked": null,
        "disabled_at": null,
        "github_app": {
            "account_type": account_type,
            "account_login": account_login,
            "repository_selection": repository_selection,
            "repositories": repository_payload,
        }
    })
}

struct GitHubInstallConnectionPayload<'a> {
    workspace_id: Uuid,
    owner_user_id: Uuid,
    installation_id: &'a str,
    account_login: String,
    access_token: String,
    expires_at: OffsetDateTime,
    metadata: Value,
}

async fn upsert_workspace_connection(
    app_state: &AppState,
    payload: GitHubInstallConnectionPayload<'_>,
) -> Result<(), sqlx::Error> {
    let connections = app_state
        .workspace_connection_repo
        .list_by_workspace_and_provider(payload.workspace_id, ConnectedOAuthProvider::GitHub)
        .await?;

    let mut matching = None;
    for connection in connections {
        if installation_id_from_metadata(&connection.metadata).as_deref()
            == Some(payload.installation_id)
        {
            matching = Some(connection);
            break;
        }
    }

    if let Some(connection) = matching {
        info!(
            installation_id = %payload.installation_id,
            workspace_id = %payload.workspace_id,
            connection_id = %connection.id,
            "GitHub App install updating workspace connection"
        );
        let updated = app_state
            .workspace_connection_repo
            .update_tokens_for_connection(
                connection.id,
                payload.access_token,
                String::new(),
                payload.expires_at,
                payload.account_login,
                None,
                None,
                None,
            )
            .await?;

        let merged_metadata = merge_metadata(&updated.metadata, &payload.metadata);
        let _ = app_state
            .workspace_connection_repo
            .update_metadata(updated.id, merged_metadata)
            .await?;
        Ok(())
    } else {
        info!(
            installation_id = %payload.installation_id,
            workspace_id = %payload.workspace_id,
            owner_user_id = %payload.owner_user_id,
            "GitHub App install creating workspace connection"
        );
        app_state
            .workspace_connection_repo
            .insert_connection(NewWorkspaceConnection {
                workspace_id: payload.workspace_id,
                created_by: payload.owner_user_id,
                owner_user_id: payload.owner_user_id,
                user_oauth_token_id: None,
                connection_id: None,
                provider: ConnectedOAuthProvider::GitHub,
                access_token: payload.access_token,
                refresh_token: String::new(),
                expires_at: payload.expires_at,
                account_email: payload.account_login,
                bot_user_id: None,
                slack_team_id: None,
                incoming_webhook_url: None,
                metadata: payload.metadata,
            })
            .await?;
        Ok(())
    }
}

fn merge_metadata(existing: &Value, incoming: &Value) -> Value {
    deep_merge(existing, incoming)
}

fn deep_merge(existing: &Value, incoming: &Value) -> Value {
    match (existing, incoming) {
        (Value::Object(left), Value::Object(right)) => {
            let mut merged = left.clone();
            for (key, value) in right {
                let next = match merged.get(key) {
                    Some(current) => deep_merge(current, value),
                    None => value.clone(),
                };
                merged.insert(key.clone(), next);
            }
            Value::Object(merged)
        }
        (_, other) => other.clone(),
    }
}

fn build_success_redirect(app_state: &AppState, workspace_id: Uuid) -> String {
    format!(
        "{}/settings/integrations/webhooks?workspace={}",
        app_state.config.frontend_origin, workspace_id
    )
}

fn redirect_install_error(app_state: &AppState, workspace_id: Uuid, message: &str) -> Redirect {
    let encoded = urlencoding::encode(message);
    let url = format!(
        "{}/settings/integrations/webhooks?workspace={}&github_app_install=error&message={}",
        app_state.config.frontend_origin, workspace_id, encoded
    );
    Redirect::to(&url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request, routing::get, Router};
    use jsonwebtoken::{encode, Header};
    use serde_json::json;
    use std::sync::Arc;
    use time::{Duration, OffsetDateTime};
    use tower::ServiceExt;

    use crate::config::{
        Config, GitHubAppSettings, OAuthProviderConfig, OAuthSettings, StripeSettings,
        DEFAULT_WORKSPACE_MEMBER_LIMIT, DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT, RUNAWAY_LIMIT_5MIN,
    };
    use crate::db::mock_db::{
        MockDb, NoopWorkflowRepository, StaticWorkspaceMembershipRepository,
    };
    use crate::db::mock_stripe_event_log_repository::MockStripeEventLogRepository;
    use crate::db::workspace_connection_repository::NoopWorkspaceConnectionRepository;
    use crate::services::oauth::account_service::OAuthAccountService;
    use crate::services::oauth::github::mock_github_oauth::MockGitHubOAuth;
    use crate::services::oauth::google::mock_google_oauth::MockGoogleOAuth;
    use crate::services::oauth::workspace_service::WorkspaceOAuthService;
    use crate::services::smtp_mailer::MockMailer;
    use crate::services::stripe::MockStripeService;
    use crate::state::{test_integration_registry, test_pg_pool, AppState};
    use crate::utils::jwt::JwtKeys;

    fn test_jwt_keys() -> Arc<JwtKeys> {
        Arc::new(
            JwtKeys::from_secret("0123456789abcdef0123456789abcdef")
                .expect("test JWT secret should be valid"),
        )
    }

    fn test_config(github_app: GitHubAppSettings) -> Arc<Config> {
        Arc::new(Config {
            database_url: "postgres://localhost".into(),
            frontend_origin: "http://localhost".into(),
            admin_origin: "http://localhost".into(),
            oauth: OAuthSettings {
                google: OAuthProviderConfig {
                    client_id: "google".into(),
                    client_secret: "google-secret".into(),
                    redirect_uri: "http://localhost/google".into(),
                },
                github: OAuthProviderConfig {
                    client_id: "github".into(),
                    client_secret: "github-secret".into(),
                    redirect_uri: "http://localhost/github".into(),
                },
                microsoft: OAuthProviderConfig {
                    client_id: "microsoft".into(),
                    client_secret: "microsoft-secret".into(),
                    redirect_uri: "http://localhost/microsoft".into(),
                },
                slack: OAuthProviderConfig {
                    client_id: "slack".into(),
                    client_secret: "slack-secret".into(),
                    redirect_uri: "http://localhost/slack".into(),
                },
                asana: OAuthProviderConfig {
                    client_id: "asana".into(),
                    client_secret: "asana-secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                notion: OAuthProviderConfig {
                    client_id: "notion".into(),
                    client_secret: "notion-secret".into(),
                    redirect_uri: "http://localhost/notion".into(),
                },
                bitly: OAuthProviderConfig {
                    client_id: "bitly".into(),
                    client_secret: "bitly-secret".into(),
                    redirect_uri: "http://localhost/bitly".into(),
                },
                raindrop: OAuthProviderConfig {
                    client_id: "raindrop".into(),
                    client_secret: "raindrop-secret".into(),
                    redirect_uri: "http://localhost/raindrop".into(),
                },
                token_encryption_key: vec![0u8; 32],
            },
            github_app,
            github_webhook_source_id: None,
            api_secrets_encryption_key: vec![1u8; 32],
            stripe: StripeSettings {
                client_id: "stripe".into(),
                secret_key: "stripe-secret".into(),
                webhook_secret: "stripe-webhook".into(),
            },
            auth_cookie_secure: true,
            jwt_issuer: "dsentr.test".into(),
            jwt_audience: "dsentr.api".into(),
            workspace_member_limit: DEFAULT_WORKSPACE_MEMBER_LIMIT,
            workspace_monthly_run_limit: DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT,
            runaway_limit_5min: RUNAWAY_LIMIT_5MIN,
            webhook_ingress_dedupe_mode: crate::config::WebhookIngressDedupeMode::Off,
            webhook_verification_body_fields: vec![],
            webhook_verification_header_fields: vec![],
            webhook_event_type_fields: vec![],
        })
    }

    fn stub_state(
        config: Arc<Config>,
        workspace_repo: Arc<dyn crate::db::workspace_repository::WorkspaceRepository>,
    ) -> AppState {
        AppState {
            db: Arc::new(MockDb::default()),
            workflow_repo: Arc::new(NoopWorkflowRepository),
            workspace_repo,
            workspace_connection_repo: Arc::new(NoopWorkspaceConnectionRepository),
            stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
            db_pool: test_pg_pool(),
            mailer: Arc::new(MockMailer::default()),
            google_oauth: Arc::new(MockGoogleOAuth::default()),
            github_oauth: Arc::new(MockGitHubOAuth::default()),
            oauth_accounts: OAuthAccountService::test_stub(),
            workspace_oauth: WorkspaceOAuthService::test_stub(),
            stripe: Arc::new(MockStripeService::new()),
            integration_registry: test_integration_registry(),
            http_client: Arc::new(reqwest::Client::new()),
            config,
            worker_id: Arc::new("test-worker".into()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        }
    }

    fn encode_state(claims: serde_json::Value, keys: &JwtKeys) -> String {
        encode(&Header::new(Algorithm::HS256), &claims, keys.encoding_key())
            .expect("state should encode")
    }

    #[tokio::test]
    async fn parse_install_state_accepts_valid_state() {
        let keys = test_jwt_keys();
        let config = test_config(GitHubAppSettings::default());
        let workspace_id = Uuid::new_v4();
        let exp = (OffsetDateTime::now_utc() + Duration::minutes(5)).unix_timestamp() as usize;
        let token = encode_state(
            json!({
                "flow": GITHUB_APP_INSTALL_FLOW,
                "workspace_id": workspace_id,
                "exp": exp,
                "iss": config.jwt_issuer,
                "aud": GITHUB_APP_STATE_AUDIENCE
            }),
            &keys,
        );

        let parsed =
            parse_install_state(&token, &keys, &config.jwt_issuer).expect("state should parse");
        assert_eq!(parsed.flow, GITHUB_APP_INSTALL_FLOW);
        assert_eq!(parsed.workspace_id, workspace_id);
    }

    #[tokio::test]
    async fn parse_install_state_rejects_missing_flow() {
        let keys = test_jwt_keys();
        let config = test_config(GitHubAppSettings::default());
        let workspace_id = Uuid::new_v4();
        let exp = (OffsetDateTime::now_utc() + Duration::minutes(5)).unix_timestamp() as usize;
        let token = encode_state(
            json!({
                "workspace_id": workspace_id,
                "exp": exp,
                "iss": config.jwt_issuer,
                "aud": GITHUB_APP_STATE_AUDIENCE
            }),
            &keys,
        );

        assert!(parse_install_state(&token, &keys, &config.jwt_issuer).is_err());
    }

    #[tokio::test]
    async fn parse_install_state_rejects_missing_workspace_id() {
        let keys = test_jwt_keys();
        let config = test_config(GitHubAppSettings::default());
        let exp = (OffsetDateTime::now_utc() + Duration::minutes(5)).unix_timestamp() as usize;
        let token = encode_state(
            json!({
                "flow": GITHUB_APP_INSTALL_FLOW,
                "exp": exp,
                "iss": config.jwt_issuer,
                "aud": GITHUB_APP_STATE_AUDIENCE
            }),
            &keys,
        );

        assert!(parse_install_state(&token, &keys, &config.jwt_issuer).is_err());
    }

    #[tokio::test]
    async fn parse_install_state_rejects_nil_workspace_id() {
        let keys = test_jwt_keys();
        let config = test_config(GitHubAppSettings::default());
        let exp = (OffsetDateTime::now_utc() + Duration::minutes(5)).unix_timestamp() as usize;
        let token = encode_state(
            json!({
                "flow": GITHUB_APP_INSTALL_FLOW,
                "workspace_id": Uuid::nil(),
                "exp": exp,
                "iss": config.jwt_issuer,
                "aud": GITHUB_APP_STATE_AUDIENCE
            }),
            &keys,
        );

        assert!(parse_install_state(&token, &keys, &config.jwt_issuer).is_err());
    }

    #[tokio::test]
    async fn parse_install_state_rejects_invalid_signature() {
        let keys = test_jwt_keys();
        let config = test_config(GitHubAppSettings::default());
        let workspace_id = Uuid::new_v4();
        let exp = (OffsetDateTime::now_utc() + Duration::minutes(5)).unix_timestamp() as usize;
        let bad_keys = JwtKeys::from_secret("fedcba9876543210fedcba9876543210")
            .expect("bad key should be valid");
        let token = encode_state(
            json!({
                "flow": GITHUB_APP_INSTALL_FLOW,
                "workspace_id": workspace_id,
                "exp": exp,
                "iss": config.jwt_issuer,
                "aud": GITHUB_APP_STATE_AUDIENCE
            }),
            &bad_keys,
        );

        assert!(parse_install_state(&token, &keys, &config.jwt_issuer).is_err());
    }

    #[tokio::test]
    async fn parse_install_state_rejects_expired_state() {
        let keys = test_jwt_keys();
        let config = test_config(GitHubAppSettings::default());
        let workspace_id = Uuid::new_v4();
        let exp = (OffsetDateTime::now_utc() - Duration::hours(1)).unix_timestamp() as usize;
        let token = encode_state(
            json!({
                "flow": GITHUB_APP_INSTALL_FLOW,
                "workspace_id": workspace_id,
                "exp": exp,
                "iss": config.jwt_issuer,
                "aud": GITHUB_APP_STATE_AUDIENCE
            }),
            &keys,
        );

        assert!(parse_install_state(&token, &keys, &config.jwt_issuer).is_err());
    }

    #[tokio::test]
    async fn parse_install_state_rejects_missing_aud_or_iss() {
        let keys = test_jwt_keys();
        let config = test_config(GitHubAppSettings::default());
        let workspace_id = Uuid::new_v4();
        let exp = (OffsetDateTime::now_utc() + Duration::minutes(5)).unix_timestamp() as usize;
        let missing_aud = encode_state(
            json!({
                "flow": GITHUB_APP_INSTALL_FLOW,
                "workspace_id": workspace_id,
                "exp": exp,
                "iss": config.jwt_issuer
            }),
            &keys,
        );
        let missing_iss = encode_state(
            json!({
                "flow": GITHUB_APP_INSTALL_FLOW,
                "workspace_id": workspace_id,
                "exp": exp,
                "aud": GITHUB_APP_STATE_AUDIENCE
            }),
            &keys,
        );

        assert!(parse_install_state(&missing_aud, &keys, &config.jwt_issuer).is_err());
        assert!(parse_install_state(&missing_iss, &keys, &config.jwt_issuer).is_err());
    }

    #[tokio::test]
    async fn github_app_callback_accessible_without_session_or_csrf() {
        let workspace_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let workspace_repo = StaticWorkspaceMembershipRepository::allowing();
        workspace_repo.set_workspace_owner(workspace_id, owner_id);

        let config = test_config(GitHubAppSettings {
            app_id: Some(42),
            private_key: None,
            user_oauth_enabled: true,
            user_token_refresh_enabled: false,
            app_url: None,
        });
        let state = stub_state(config.clone(), Arc::new(workspace_repo));
        let exp = (OffsetDateTime::now_utc() + Duration::minutes(5)).unix_timestamp() as usize;
        let token = encode_state(
            json!({
                "flow": GITHUB_APP_INSTALL_FLOW,
                "workspace_id": workspace_id,
                "exp": exp,
                "iss": config.jwt_issuer,
                "aud": GITHUB_APP_STATE_AUDIENCE
            }),
            &state.jwt_keys,
        );

        let app = Router::new()
            .route(
                "/api/integrations/github/app/callback",
                get(github_app_install_callback),
            )
            .with_state(state);

        let uri = format!(
            "/api/integrations/github/app/callback?installation_id=123&state={}",
            urlencoding::encode(&token)
        );
        let response = app
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .expect("request should succeed");

        assert!(response.status().is_redirection());
        let location = response
            .headers()
            .get("location")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        assert!(location.contains("settings/integrations/webhooks"));
        assert!(location.contains("github_app_install=error"));
        assert!(location.contains(&workspace_id.to_string()));
    }
}
