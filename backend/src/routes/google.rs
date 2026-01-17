use axum::{
    extract::{Path, Query, State},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tracing::error;
use uuid::Uuid;

use crate::models::oauth_token::ConnectedOAuthProvider;
use crate::responses::JsonResponse;
use crate::routes::auth::session::AuthSession;
use crate::services::oauth::workspace_service::WorkspaceOAuthError;
use crate::state::AppState;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ConnectionQuery {
    scope: Option<String>,
    connection_id: Option<Uuid>,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SheetPayload {
    id: String,
    title: String,
}

#[derive(Serialize)]
struct SheetsResponse {
    success: bool,
    sheets: Vec<SheetPayload>,
}

// Simple in-process cache: spreadsheet_id -> (expiry, sheets)
#[allow(clippy::type_complexity)]
static SHEETS_CACHE: once_cell::sync::Lazy<Mutex<HashMap<String, (Instant, Vec<SheetPayload>)>>> =
    once_cell::sync::Lazy::new(|| Mutex::new(HashMap::new()));

const CACHE_TTL: Duration = Duration::from_secs(30);

pub async fn list_spreadsheet_sheets(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path(spreadsheet_id): Path<String>,
    Query(query): Query<ConnectionQuery>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user identifier").into_response(),
    };

    // Determine token based on requested scope
    let token = match determine_scope_and_token(&state, user_id, &query).await {
        Ok(tok) => tok,
        Err(resp) => return resp,
    };

    let trimmed = spreadsheet_id.trim();
    if trimmed.is_empty() {
        return JsonResponse::bad_request("Spreadsheet ID is required").into_response();
    }

    // Check cache
    if let Ok(guard) = SHEETS_CACHE.lock() {
        if let Some((expiry, sheets)) = guard.get(trimmed) {
            if *expiry > Instant::now() {
                return Json(SheetsResponse {
                    success: true,
                    sheets: sheets.clone(),
                })
                .into_response();
            }
        }
    }

    let url = format!(
        "https://sheets.googleapis.com/v4/spreadsheets/{}?fields=sheets.properties.sheetId,sheets.properties.title",
        urlencoding::encode(trimmed)
    );

    let res = match state
        .http_client
        .get(&url)
        .bearer_auth(&token.access_token)
        .send()
        .await
    {
        Ok(r) => r,
        Err(err) => {
            error!(%err, "failed to call google sheets api");
            return JsonResponse::server_error("Failed to call Google Sheets API").into_response();
        }
    };

    let status = res.status();
    let body_text = match res.text().await {
        Ok(t) => t,
        Err(err) => {
            error!(%err, "failed to read google sheets response");
            return JsonResponse::server_error("Failed to read Google Sheets response")
                .into_response();
        }
    };

    if !status.is_success() {
        // Map common Google errors
        if status.as_u16() == 401 || status.as_u16() == 403 {
            return JsonResponse::unauthorized(
                "Google returned an authentication error. Reconnect the integration.",
            )
            .into_response();
        }
        if status.as_u16() == 404 {
            return JsonResponse::not_found("Spreadsheet not found").into_response();
        }
        if status.as_u16() == 429 {
            return JsonResponse::too_many_requests("Google rate limit reached. Try again later.")
                .into_response();
        }

        return JsonResponse::server_error(&format!(
            "Google Sheets API error (status {}): {}",
            status.as_u16(),
            body_text
        ))
        .into_response();
    }

    #[derive(serde::Deserialize)]
    struct SheetsList {
        sheets: Option<Vec<SheetsListEntry>>,
    }

    #[derive(serde::Deserialize)]
    struct SheetsListEntry {
        properties: Option<SheetsProps>,
    }

    #[derive(serde::Deserialize)]
    struct SheetsProps {
        #[serde(rename = "sheetId")]
        sheet_id: Option<serde_json::Number>,
        title: Option<String>,
    }

    let parsed: SheetsList = match serde_json::from_str(&body_text) {
        Ok(p) => p,
        Err(err) => {
            error!(%err, body = %body_text, "invalid json from google sheets");
            return JsonResponse::server_error("Invalid response from Google Sheets API")
                .into_response();
        }
    };

    let mut out: Vec<SheetPayload> = Vec::new();
    if let Some(entries) = parsed.sheets {
        for e in entries.into_iter() {
            if let Some(props) = e.properties {
                if let Some(title) = props.title {
                    let id = props
                        .sheet_id
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| title.clone());
                    out.push(SheetPayload { id, title });
                }
            }
        }
    }

    // Update cache
    if let Ok(mut guard) = SHEETS_CACHE.lock() {
        guard.insert(
            trimmed.to_string(),
            (Instant::now() + CACHE_TTL, out.clone()),
        );
    }

    Json(SheetsResponse {
        success: true,
        sheets: out,
    })
    .into_response()
}

pub async fn list_spreadsheets_files(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    Query(query): Query<ConnectionQuery>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user identifier").into_response(),
    };

    let token = match determine_scope_and_token(&state, user_id, &query).await {
        Ok(t) => t,
        Err(resp) => return resp,
    };

    // Drive API: list spreadsheets the user has access to
    let q = "mimeType = 'application/vnd.google-apps.spreadsheet' and trashed = false";
    let url = format!(
        "https://www.googleapis.com/drive/v3/files?fields=files(id,name)&orderBy=name&q={}&pageSize=200",
        urlencoding::encode(q)
    );

    let res = match state
        .http_client
        .get(&url)
        .bearer_auth(&token.access_token)
        .send()
        .await
    {
        Ok(r) => r,
        Err(err) => {
            error!(%err, "failed to call google drive api");
            return JsonResponse::server_error("Failed to call Google Drive API").into_response();
        }
    };

    let status = res.status();
    let body_text = match res.text().await {
        Ok(t) => t,
        Err(err) => {
            error!(%err, "failed to read google drive response");
            return JsonResponse::server_error("Failed to read Google Drive response")
                .into_response();
        }
    };

    if !status.is_success() {
        if status.as_u16() == 401 || status.as_u16() == 403 {
            return JsonResponse::unauthorized(
                "Google returned an authentication error. Reconnect the integration.",
            )
            .into_response();
        }
        return JsonResponse::server_error(&format!(
            "Google Drive API error (status {}): {}",
            status.as_u16(),
            body_text
        ))
        .into_response();
    }

    #[derive(serde::Deserialize)]
    struct DriveFilesList {
        files: Option<Vec<DriveFileEntry>>,
    }

    #[derive(serde::Deserialize)]
    struct DriveFileEntry {
        id: Option<String>,
        name: Option<String>,
    }

    let parsed: DriveFilesList = match serde_json::from_str(&body_text) {
        Ok(p) => p,
        Err(err) => {
            error!(%err, body = %body_text, "invalid json from google drive");
            return JsonResponse::server_error("Invalid response from Google Drive API")
                .into_response();
        }
    };

    let mut out: Vec<SheetPayload> = Vec::new();
    if let Some(files) = parsed.files {
        for f in files.into_iter() {
            if let Some(id) = f.id {
                let title = f.name.unwrap_or_else(|| id.clone());
                out.push(SheetPayload { id, title });
            }
        }
    }

    Json(serde_json::json!({ "success": true, "files": out })).into_response()
}

pub async fn get_google_access_token(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    Query(query): Query<ConnectionQuery>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user identifier").into_response(),
    };

    match determine_scope_and_token(&state, user_id, &query).await {
        Ok(tok) => Json(serde_json::json!({ "success": true, "access_token": tok.access_token }))
            .into_response(),
        Err(resp) => resp,
    }
}

// tests are moved to the end of the file to satisfy clippy's
// `items_after_test_module` lint (test modules should be last)

async fn determine_scope_and_token(
    state: &AppState,
    user_id: Uuid,
    query: &ConnectionQuery,
) -> Result<StoredOAuthTokenProxy, Response> {
    // Determine requested scope
    let Some(scope) = query
        .scope
        .as_deref()
        .map(|value| value.trim().to_ascii_lowercase())
    else {
        return Err(JsonResponse::bad_request("scope is required").into_response());
    };

    match scope.as_str() {
        "workspace" => {
            let conn_id = match query.connection_id {
                Some(id) => id,
                None => {
                    return Err(JsonResponse::bad_request(
                        "connection_id is required for workspace scope",
                    )
                    .into_response())
                }
            };

            // Ensure connection exists and belongs to workspace & has plan/membership
            match state
                .workspace_oauth
                .get_connection(user_id, conn_id, ConnectedOAuthProvider::Google)
                .await
            {
                Ok(_conn) => {
                    match state
                        .workspace_oauth
                        .ensure_valid_workspace_token(conn_id)
                        .await
                    {
                        Ok(connection) => Ok(StoredOAuthTokenProxy {
                            access_token: connection.access_token.clone(),
                        }),
                        Err(err) => Err(map_workspace_oauth_error(err)),
                    }
                }
                Err(_) => Err(JsonResponse::forbidden(
                    "Google connection not found or not allowed for this workspace",
                )
                .into_response()),
            }
        }
        "personal" | "user" => {
            let conn_id = match query.connection_id {
                Some(id) => id,
                None => {
                    return Err(JsonResponse::bad_request(
                        "connection_id is required for personal scope",
                    )
                    .into_response())
                }
            };

            let token = match state
                .oauth_accounts
                .ensure_valid_access_token_for_connection(user_id, conn_id)
                .await
            {
                Ok(token) => token,
                Err(err) => return Err(crate::routes::oauth::map_oauth_error(err)),
            };

            if token.provider != ConnectedOAuthProvider::Google {
                return Err(JsonResponse::forbidden(
                    "Selected connection is not a Google connection",
                )
                .into_response());
            }

            Ok(StoredOAuthTokenProxy {
                access_token: token.access_token.clone(),
            })
        }
        _ => Err(JsonResponse::bad_request("unsupported scope").into_response()),
    }
}

fn map_workspace_oauth_error(err: WorkspaceOAuthError) -> Response {
    match err {
        WorkspaceOAuthError::NotFound => {
            JsonResponse::forbidden("Connection not found").into_response()
        }
        WorkspaceOAuthError::Forbidden => JsonResponse::forbidden("Forbidden").into_response(),
        WorkspaceOAuthError::SlackInstallRequired => {
            JsonResponse::bad_request("Slack connections must be installed at workspace scope")
                .into_response()
        }
        WorkspaceOAuthError::Database(e) => {
            JsonResponse::server_error(&format!("Workspace OAuth database error: {}", e))
                .into_response()
        }
        WorkspaceOAuthError::Encryption(e) => {
            JsonResponse::server_error(&format!("Workspace OAuth encryption error: {}", e))
                .into_response()
        }
        WorkspaceOAuthError::OAuth(e) => crate::routes::oauth::map_oauth_error(e),
    }
}

// Small proxy type used to unify token shapes returned for personal and workspace tokens
#[derive(Debug)]
struct StoredOAuthTokenProxy {
    access_token: String,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use axum::http::StatusCode;
    use reqwest::Client;
    use time::{Duration, OffsetDateTime};
    use uuid::Uuid;

    use crate::config::{
        Config, OAuthProviderConfig, OAuthSettings, StripeSettings, DEFAULT_WORKSPACE_MEMBER_LIMIT,
        DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT, RUNAWAY_LIMIT_5MIN,
    };
    use crate::db::mock_db::{MockDb, NoopWorkflowRepository, NoopWorkspaceRepository};
    use crate::db::mock_stripe_event_log_repository::MockStripeEventLogRepository;
    use crate::db::oauth_token_repository::{NewUserOAuthToken, UserOAuthTokenRepository};
    use crate::db::workspace_connection_repository::NoopWorkspaceConnectionRepository;
    use crate::models::oauth_token::{ConnectedOAuthProvider, UserOAuthToken};
    use crate::services::oauth::account_service::OAuthAccountService;
    use crate::services::oauth::github::mock_github_oauth::MockGitHubOAuth;
    use crate::services::oauth::google::mock_google_oauth::MockGoogleOAuth;
    use crate::services::oauth::workspace_service::WorkspaceOAuthService;
    use crate::services::smtp_mailer::MockMailer;
    use crate::services::stripe::MockStripeService;
    use crate::state::{test_pg_pool, AppState};
    use crate::utils::encryption::encrypt_secret;
    use crate::utils::jwt::JwtKeys;

    use super::{determine_scope_and_token, ConnectionQuery};

    #[derive(Clone)]
    struct StaticTokenRepo {
        token: Option<UserOAuthToken>,
    }

    #[async_trait]
    impl UserOAuthTokenRepository for StaticTokenRepo {
        async fn upsert_token(
            &self,
            _new_token: NewUserOAuthToken,
        ) -> Result<UserOAuthToken, sqlx::Error> {
            Err(sqlx::Error::RowNotFound)
        }

        async fn find_by_id(&self, token_id: Uuid) -> Result<Option<UserOAuthToken>, sqlx::Error> {
            Ok(self.token.clone().filter(|token| token.id == token_id))
        }

        async fn find_by_user_and_provider(
            &self,
            user_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<Option<UserOAuthToken>, sqlx::Error> {
            if provider != ConnectedOAuthProvider::Google {
                return Ok(None);
            }

            Ok(self
                .token
                .clone()
                .filter(|record| record.user_id == user_id))
        }

        async fn delete_token(
            &self,
            _user_id: Uuid,
            _provider: ConnectedOAuthProvider,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn list_by_user_and_provider(
            &self,
            user_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<Vec<UserOAuthToken>, sqlx::Error> {
            if provider != ConnectedOAuthProvider::Google {
                return Ok(vec![]);
            }

            Ok(self
                .token
                .clone()
                .filter(|record| record.user_id == user_id)
                .into_iter()
                .collect())
        }

        async fn list_tokens_for_user(
            &self,
            user_id: Uuid,
        ) -> Result<Vec<UserOAuthToken>, sqlx::Error> {
            Ok(self
                .token
                .clone()
                .filter(|record| record.user_id == user_id)
                .into_iter()
                .collect())
        }

        async fn mark_shared(
            &self,
            _user_id: Uuid,
            _provider: ConnectedOAuthProvider,
            _is_shared: bool,
        ) -> Result<UserOAuthToken, sqlx::Error> {
            Err(sqlx::Error::RowNotFound)
        }
    }

    fn stub_config() -> Arc<Config> {
        Arc::new(Config {
            database_url: "postgres://localhost".into(),
            frontend_origin: "http://localhost:5173".into(),
            admin_origin: "http://localhost:5173".into(),
            oauth: OAuthSettings {
                google: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/google".into(),
                },
                microsoft: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/microsoft".into(),
                },
                slack: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/slack".into(),
                },
                asana: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                notion: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                bitly: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                raindrop: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                token_encryption_key: vec![1u8; 32],
            },
            api_secrets_encryption_key: vec![2u8; 32],
            stripe: StripeSettings {
                client_id: "stub".into(),
                secret_key: "stub".into(),
                webhook_secret: "0123456789abcdef0123456789ABCDEF".into(),
            },
            auth_cookie_secure: true,
            jwt_issuer: "test-issuer".into(),
            jwt_audience: "test-audience".into(),
            workspace_member_limit: DEFAULT_WORKSPACE_MEMBER_LIMIT,
            workspace_monthly_run_limit: DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT,
            runaway_limit_5min: RUNAWAY_LIMIT_5MIN,
            webhook_ingress_dedupe_mode: crate::config::WebhookIngressDedupeMode::Off,
            webhook_verification_body_fields: Vec::new(),
            webhook_verification_header_fields: Vec::new(),
            webhook_event_type_fields: vec!["event_type".to_string(), "type".to_string()],
        })
    }

    fn base_state(config: Arc<Config>, oauth_accounts: Arc<OAuthAccountService>) -> AppState {
        AppState {
            db: Arc::new(MockDb::default()),
            workflow_repo: Arc::new(NoopWorkflowRepository),
            workspace_repo: Arc::new(NoopWorkspaceRepository),
            workspace_connection_repo: Arc::new(NoopWorkspaceConnectionRepository),
            stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
            db_pool: test_pg_pool(),
            mailer: Arc::new(MockMailer::default()),
            google_oauth: Arc::new(MockGoogleOAuth::default()),
            github_oauth: Arc::new(MockGitHubOAuth::default()),
            oauth_accounts,
            workspace_oauth: WorkspaceOAuthService::test_stub(),
            stripe: Arc::new(MockStripeService::new()),
            integration_registry: crate::state::test_integration_registry(),
            http_client: Arc::new(Client::new()),
            config,
            worker_id: Arc::new("test-worker".into()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        }
    }

    fn test_jwt_keys() -> Arc<JwtKeys> {
        Arc::new(
            JwtKeys::from_secret("0123456789abcdef0123456789abcdef")
                .expect("test JWT secret should be valid"),
        )
    }

    #[tokio::test]
    async fn determine_scope_and_token_accepts_personal_scope() {
        let config = stub_config();
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());
        let user_id = Uuid::new_v4();
        let token_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let token = UserOAuthToken {
            id: token_id,
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Google,
            access_token: encrypt_secret(&encryption_key, "access").expect("encrypt access"),
            refresh_token: encrypt_secret(&encryption_key, "refresh").expect("encrypt refresh"),
            expires_at: now + Duration::hours(1),
            account_email: "user@example.com".into(),
            metadata: serde_json::json!({}),
            is_shared: false,
            created_at: now,
            updated_at: now,
        };

        let repo = Arc::new(StaticTokenRepo { token: Some(token) });
        let oauth_accounts = Arc::new(OAuthAccountService::new(
            repo,
            Arc::new(NoopWorkspaceConnectionRepository),
            Arc::clone(&encryption_key),
            Arc::new(Client::new()),
            &config.oauth,
        ));
        let state = base_state(config, oauth_accounts);

        let query = ConnectionQuery {
            scope: Some("personal".into()),
            connection_id: Some(token_id),
        };

        let result = determine_scope_and_token(&state, user_id, &query)
            .await
            .expect("personal token should resolve");

        assert_eq!(result.access_token, "access");
    }

    #[tokio::test]
    async fn determine_scope_and_token_rejects_personal_non_google() {
        let config = stub_config();
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());
        let user_id = Uuid::new_v4();
        let token_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let token = UserOAuthToken {
            id: token_id,
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Microsoft,
            access_token: encrypt_secret(&encryption_key, "access").expect("encrypt access"),
            refresh_token: encrypt_secret(&encryption_key, "refresh").expect("encrypt refresh"),
            expires_at: now + Duration::hours(1),
            account_email: "user@example.com".into(),
            metadata: serde_json::json!({}),
            is_shared: false,
            created_at: now,
            updated_at: now,
        };

        let repo = Arc::new(StaticTokenRepo { token: Some(token) });
        let oauth_accounts = Arc::new(OAuthAccountService::new(
            repo,
            Arc::new(NoopWorkspaceConnectionRepository),
            Arc::clone(&encryption_key),
            Arc::new(Client::new()),
            &config.oauth,
        ));
        let state = base_state(config, oauth_accounts);

        let query = ConnectionQuery {
            scope: Some("personal".into()),
            connection_id: Some(token_id),
        };

        let err = determine_scope_and_token(&state, user_id, &query)
            .await
            .expect_err("non-google token should be rejected");

        assert_eq!(err.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn determine_scope_and_token_requires_connection_id_for_personal_scope() {
        let config = stub_config();
        let oauth_accounts = OAuthAccountService::test_stub();
        let state = base_state(config, oauth_accounts);
        let user_id = Uuid::new_v4();

        let query = ConnectionQuery {
            scope: Some("personal".into()),
            connection_id: None,
        };

        let err = determine_scope_and_token(&state, user_id, &query)
            .await
            .expect_err("connection_id is required");

        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn parse_google_sheets_list_response() {
        let sample = r#"
        {
          "sheets": [
            { "properties": { "sheetId": 0, "title": "Sheet1" } },
            { "properties": { "sheetId": 12345, "title": "Data" } }
          ]
        }
        "#;

        #[derive(serde::Deserialize)]
        struct SheetsList {
            sheets: Option<Vec<SheetsListEntry>>,
        }

        #[derive(serde::Deserialize)]
        struct SheetsListEntry {
            properties: Option<SheetsProps>,
        }

        #[derive(serde::Deserialize)]
        struct SheetsProps {
            #[serde(rename = "sheetId")]
            sheet_id: Option<serde_json::Number>,
            title: Option<String>,
        }

        let parsed: SheetsList = serde_json::from_str(sample).expect("parse should succeed");
        let sheets = parsed.sheets.expect("sheets present");
        assert_eq!(sheets.len(), 2);
        let first = sheets[0].properties.as_ref().unwrap();
        assert_eq!(first.title.as_deref(), Some("Sheet1"));
        assert_eq!(
            first.sheet_id.as_ref().map(|n| n.as_i64().unwrap()),
            Some(0)
        );
    }
}
