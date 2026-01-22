use async_trait::async_trait;
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, Response, StatusCode},
    routing::{get, post},
    Router,
};
use axum_extra::extract::cookie::CookieJar;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use once_cell::sync::Lazy;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crate::db::{
    mock_db::{MockDb, NoopWorkflowRepository, NoopWorkspaceRepository},
    mock_stripe_event_log_repository::MockStripeEventLogRepository,
    oauth_token_repository::{NewUserOAuthToken, UserOAuthTokenRepository},
    workspace_connection_repository::{
        NewWorkspaceAuditEvent, NewWorkspaceConnection, NoopWorkspaceConnectionRepository,
        WorkspaceConnectionListing, WorkspaceConnectionRepository,
    },
    workspace_repository::{WorkspaceRepository, WorkspaceRunQuotaUpdate, WorkspaceRunUsage},
};
use crate::integrations::manifest::TokenScope;
use crate::integrations::registry::IntegrationRegistry;
use crate::models::oauth_token::{UserOAuthToken, WorkspaceAuditEvent, WorkspaceConnection};
use crate::models::plan::PlanTier;
use crate::models::user::UserRole;
use crate::models::workspace::{
    Workspace, WorkspaceBillingCycle, WorkspaceMembershipSummary, WorkspaceRole,
    WORKSPACE_PLAN_SOLO,
};
use crate::responses::JsonResponse;
use crate::routes::auth::{
    claims::{Claims, TokenUse},
    session::AuthSession,
};
use crate::services::{
    oauth::{
        account_service::{parse_token_metadata, OAuthAccountError, OAuthAccountService},
        github::mock_github_oauth::MockGitHubOAuth,
        google::mock_google_oauth::MockGoogleOAuth,
        workspace_service::{WorkspaceOAuthService, WorkspaceTokenRefresher},
    },
    smtp_mailer::MockMailer,
};
use crate::state::test_pg_pool;
use crate::state::AppState;
use crate::utils::encryption::{decrypt_secret, encrypt_secret};
use crate::utils::jwt::JwtKeys;
use crate::{
    config::{
        Config, OAuthProviderConfig, OAuthSettings, StripeSettings, DEFAULT_WORKSPACE_MEMBER_LIMIT,
        DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT, RUNAWAY_LIMIT_5MIN,
    },
    models::workspace::WorkspaceMember,
};
use reqwest::Url;
use serde::Serialize;
use serde_json::Value;
use sqlx::Error;
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};
use tokio::{net::TcpListener, task::JoinHandle};
use urlencoding::encode;
use uuid::Uuid;

use super::{
    accounts::{
        disconnect_connection, get_connection_by_id, list_connections, list_provider_connections,
        refresh_connection, revoke_connection, ConnectionTarget, ListConnectionsQuery,
    },
    connect::{
        github_connect_callback, github_connect_start, google_connect_start,
        notion_connect_callback, notion_connect_start, slack_connect_callback, slack_connect_start,
        ConnectQuery,
    },
    helpers::{
        build_slack_state, build_state_cookie, error_message_for_redirect, handle_callback,
        oauth_provider_for_integration_id, CallbackQuery, GITHUB_AUTH_URL, GITHUB_STATE_COOKIE,
        GOOGLE_STATE_COOKIE, NOTION_STATE_COOKIE, OAUTH_PLAN_RESTRICTION_MESSAGE,
        SLACK_STATE_COOKIE, SLACK_WORKSPACE_REQUIRED_MESSAGE,
    },
    prelude::ConnectedOAuthProvider,
};

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
            github: OAuthProviderConfig {
                client_id: "client".into(),
                client_secret: "secret".into(),
                redirect_uri: "http://localhost/github".into(),
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
                redirect_uri: "http://localhost/notion".into(),
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
            token_encryption_key: vec![0u8; 32],
        },
        github_app: crate::config::GitHubAppSettings::default(),
            github_webhook_source_id: None,
        api_secrets_encryption_key: vec![1u8; 32],
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

fn connections_for_provider<'a>(value: &'a Value, provider: &str) -> Vec<&'a Value> {
    value
        .as_array()
        .map(|entries| {
            entries
                .iter()
                .filter(|entry| entry.get("provider").and_then(Value::as_str) == Some(provider))
                .collect()
        })
        .unwrap_or_default()
}

fn stub_state(config: Arc<Config>) -> AppState {
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
        oauth_accounts: OAuthAccountService::test_stub(),
        workspace_oauth: WorkspaceOAuthService::test_stub(),
        stripe: Arc::new(crate::services::stripe::MockStripeService::new()),
        integration_registry: crate::state::test_integration_registry(),
        http_client: Arc::new(reqwest::Client::new()),
        config,
        worker_id: Arc::new("test-worker".into()),
        worker_lease_seconds: 30,
        jwt_keys: test_jwt_keys(),
    }
}

static ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

struct EnvGuard {
    key: &'static str,
    previous: Option<String>,
    _lock: std::sync::MutexGuard<'static, ()>,
}

impl EnvGuard {
    fn set(key: &'static str, value: String) -> Self {
        let lock = ENV_LOCK.lock().expect("env mutex poisoned");
        let previous = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self {
            key,
            previous,
            _lock: lock,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            std::env::set_var(self.key, previous);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

fn test_jwt_keys() -> Arc<JwtKeys> {
    Arc::new(
        JwtKeys::from_secret("0123456789abcdef0123456789abcdef")
            .expect("test JWT secret should be valid"),
    )
}

fn stub_state_with_workspace_repo(
    config: Arc<Config>,
    workspace_repo: Arc<dyn WorkspaceRepository>,
) -> AppState {
    AppState {
        workspace_repo,
        ..stub_state(config)
    }
}

struct MembershipWorkspaceRepo {
    memberships: Vec<(Uuid, WorkspaceMembershipSummary)>,
    run_usage: std::sync::Mutex<HashMap<(Uuid, i64), (i64, i64)>>,
    billing_cycles: std::sync::Mutex<HashMap<Uuid, WorkspaceBillingCycle>>,
}

impl MembershipWorkspaceRepo {
    fn new(memberships: Vec<(Uuid, WorkspaceMembershipSummary)>) -> Self {
        Self {
            memberships,
            run_usage: std::sync::Mutex::new(HashMap::new()),
            billing_cycles: std::sync::Mutex::new(HashMap::new()),
        }
    }

    fn memberships_for(&self, user_id: Uuid) -> Vec<WorkspaceMembershipSummary> {
        self.memberships
            .iter()
            .filter(|(member_id, _)| *member_id == user_id)
            .map(|(_, membership)| membership.clone())
            .collect()
    }
}

fn workspace_membership(
    workspace_id: Uuid,
    role: WorkspaceRole,
    plan: &str,
) -> WorkspaceMembershipSummary {
    WorkspaceMembershipSummary {
        workspace: Workspace {
            id: workspace_id,
            name: "Test".into(),
            created_by: Uuid::new_v4(),
            owner_id: Uuid::new_v4(),
            plan: plan.to_string(),
            stripe_overage_item_id: None,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            deleted_at: None,
        },
        role,
    }
}

fn build_list_connections_state(
    config: Arc<Config>,
    memberships: Vec<(Uuid, WorkspaceMembershipSummary)>,
    personal_tokens: Vec<UserOAuthToken>,
    workspace_entries: Vec<(Uuid, WorkspaceConnectionListing)>,
) -> AppState {
    let workspace_repo: Arc<dyn WorkspaceRepository> =
        Arc::new(MembershipWorkspaceRepo::new(memberships));
    let workspace_connections: Arc<dyn WorkspaceConnectionRepository> =
        Arc::new(WorkspaceConnectionsStub::new(workspace_entries));
    let token_repo: Arc<dyn UserOAuthTokenRepository> = Arc::new(TokenRepo::new(personal_tokens));
    let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());
    let oauth_client = Arc::new(reqwest::Client::new());
    let oauth_service = Arc::new(OAuthAccountService::new(
        token_repo,
        workspace_connections.clone(),
        encryption_key,
        oauth_client,
        &config.oauth,
        &config.github_app,
    ));

    let mut state = stub_state_with_workspace_repo(config, workspace_repo);
    state.oauth_accounts = oauth_service;
    state.workspace_connection_repo = workspace_connections;
    state
}

fn workspace_first_personal_integration(
    registry: &IntegrationRegistry,
) -> (String, ConnectedOAuthProvider) {
    let manifest = registry
        .iter()
        .find(|manifest| {
            manifest.provider_constraints.workspace_first
                && manifest.token_scope == TokenScope::PersonalAndWorkspace
        })
        .expect("workspace-first personal+workspace integration");
    let integration_id = manifest.integration_id.clone();
    let provider = oauth_provider_for_integration_id(&integration_id)
        .expect("workspace-first integration should map to an OAuth provider");
    (integration_id, provider)
}

fn claims_for(user_id: Uuid) -> Claims {
    Claims {
        id: user_id.to_string(),
        ..stub_claims()
    }
}

fn personal_token_fixture(
    config: &Config,
    user_id: Uuid,
    provider: ConnectedOAuthProvider,
    account_email: &str,
    is_shared: bool,
) -> UserOAuthToken {
    let now = OffsetDateTime::now_utc();
    let encrypted_access = encrypt_secret(
        &config.oauth.token_encryption_key,
        &format!("access-{}-{}", user_id, account_email),
    )
    .expect("encrypt access token");
    let encrypted_refresh = encrypt_secret(
        &config.oauth.token_encryption_key,
        &format!("refresh-{}-{}", user_id, account_email),
    )
    .expect("encrypt refresh token");

    UserOAuthToken {
        id: Uuid::new_v4(),
        user_id,
        workspace_id: None,
        provider,
        access_token: encrypted_access,
        refresh_token: encrypted_refresh,
        expires_at: now + Duration::hours(1),
        account_email: account_email.into(),
        metadata: serde_json::json!({}),
        is_shared,
        created_at: now - Duration::hours(1),
        updated_at: now - Duration::minutes(1),
    }
}

fn workspace_connection_fixture(
    workspace_id: Uuid,
    owner_user_id: Uuid,
    connection_id: Option<Uuid>,
    provider: ConnectedOAuthProvider,
    account_email: &str,
    requires_reconnect: bool,
    shared_by: (&str, &str, &str),
) -> WorkspaceConnectionListing {
    let now = OffsetDateTime::now_utc();
    WorkspaceConnectionListing {
        id: Uuid::new_v4(),
        connection_id,
        workspace_id,
        owner_user_id,
        workspace_name: "Shared Workspace".into(),
        provider,
        account_email: account_email.into(),
        expires_at: now + Duration::hours(4),
        shared_by_first_name: Some(shared_by.0.into()),
        shared_by_last_name: Some(shared_by.1.into()),
        shared_by_email: Some(shared_by.2.into()),
        updated_at: now - Duration::minutes(5),
        requires_reconnect,
        has_incoming_webhook: false,
    }
}

const SLACK_BOT_SCOPES: &str =
    "channels:read,groups:read,im:read,mpim:read,chat:write,chat:write.public,incoming-webhook";
const NOTION_TOKEN_RESPONSE: &str = r#"{
    "access_token": "notion-access",
    "bot_id": "bot-123",
    "workspace_id": "ws-123",
    "workspace_name": "Acme Workspace",
    "owner": {
        "type": "workspace",
        "workspace": {
            "id": "ws-123",
            "name": "Acme Workspace"
        }
    }
}"#;
const NOTION_TOKEN_RESPONSE_MINIMAL: &str = r#"{
    "access_token": "notion-access"
}"#;

async fn spawn_github_stub_server() -> (std::net::SocketAddr, JoinHandle<()>) {
    async fn github_token() -> Response<Body> {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{
                    "access_token": "ghu-user-token",
                    "refresh_token": "ghu-refresh-token",
                    "expires_in": 3600
                }"#,
            ))
            .unwrap()
    }

    async fn github_user() -> Response<Body> {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{
                    "login": "octocat",
                    "id": 101010,
                    "email": "octocat@example.com"
                }"#,
            ))
            .unwrap()
    }

    async fn github_emails() -> Response<Body> {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"[
                    { "email": "octocat@example.com", "primary": true, "verified": true }
                ]"#,
            ))
            .unwrap()
    }

    let app = Router::new()
        .route("/login/oauth/access_token", post(github_token))
        .route("/user", get(github_user))
        .route("/user/emails", get(github_emails));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = axum::serve(listener, app.into_make_service());
    let handle = tokio::spawn(async move {
        if let Err(err) = server.await {
            eprintln!("stub server exited with error: {err}");
        }
    });

    (addr, handle)
}

async fn spawn_slack_stub_server() -> (std::net::SocketAddr, JoinHandle<()>) {
    async fn slack_oauth_access() -> Response<Body> {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{
                    "ok": true,
                    "access_token": "xoxb-workspace-token",
                    "refresh_token": "xoxb-workspace-refresh",
                    "expires_in": 3600,
                    "authed_user": {
                        "id": "U123",
                        "access_token": "xoxp-user-token",
                        "refresh_token": "xoxp-user-refresh",
                        "expires_in": 3600
                    },
                    "team": { "id": "T999" },
                    "bot_user_id": "B123",
                    "incoming_webhook": { "url": "https://hooks.slack.com/abc" }
                }"#,
            ))
            .unwrap()
    }

    async fn slack_users_info() -> Response<Body> {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                r#"{"ok":true,"user":{"profile":{"email":"user@example.com"}}}"#,
            ))
            .unwrap()
    }

    async fn slack_auth_test() -> Response<Body> {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-oauth-scopes", SLACK_BOT_SCOPES)
            .body(Body::from(
                r#"{"ok":true,"team_id":"T123","user_id":"U123"}"#,
            ))
            .unwrap()
    }

    let app = Router::new()
        .route("/api/oauth.v2.access", post(slack_oauth_access))
        .route("/api/users.info", get(slack_users_info))
        .route("/api/auth.test", get(slack_auth_test));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = axum::serve(listener, app.into_make_service());
    let handle = tokio::spawn(async move {
        if let Err(err) = server.await {
            eprintln!("stub server exited with error: {err}");
        }
    });

    (addr, handle)
}

async fn spawn_notion_stub_server(
    token_response: &'static str,
) -> (std::net::SocketAddr, JoinHandle<()>) {
    let response_body = token_response.to_string();
    let app = Router::new().route(
        "/oauth/token",
        post(move || {
            let response_body = response_body.clone();
            async move {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(response_body))
                    .unwrap()
            }
        }),
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = axum::serve(listener, app.into_make_service());
    let handle = tokio::spawn(async move {
        if let Err(err) = server.await {
            eprintln!("stub server exited with error: {err}");
        }
    });

    (addr, handle)
}

struct TokenRepo {
    tokens: Mutex<Vec<UserOAuthToken>>,
}

impl TokenRepo {
    fn new(tokens: Vec<UserOAuthToken>) -> Self {
        Self {
            tokens: Mutex::new(tokens),
        }
    }
}

impl Clone for TokenRepo {
    fn clone(&self) -> Self {
        let tokens = self.tokens.lock().unwrap().clone();
        Self::new(tokens)
    }
}

#[async_trait]
impl UserOAuthTokenRepository for TokenRepo {
    async fn upsert_token(
        &self,
        _new_token: NewUserOAuthToken,
    ) -> Result<UserOAuthToken, sqlx::Error> {
        Err(sqlx::Error::RowNotFound)
    }

    async fn find_by_id(&self, token_id: Uuid) -> Result<Option<UserOAuthToken>, sqlx::Error> {
        Ok(self
            .tokens
            .lock()
            .unwrap()
            .iter()
            .find(|token| token.id == token_id)
            .cloned())
    }

    async fn find_by_user_and_provider(
        &self,
        user_id: Uuid,
        provider: ConnectedOAuthProvider,
    ) -> Result<Option<UserOAuthToken>, sqlx::Error> {
        Ok(self
            .tokens
            .lock()
            .unwrap()
            .iter()
            .find(|token| token.user_id == user_id && token.provider == provider)
            .cloned())
    }

    async fn delete_token(
        &self,
        _user_id: Uuid,
        _provider: ConnectedOAuthProvider,
    ) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn list_tokens_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<UserOAuthToken>, sqlx::Error> {
        Ok(self
            .tokens
            .lock()
            .unwrap()
            .iter()
            .filter(|token| token.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn mark_shared(
        &self,
        _user_id: Uuid,
        _provider: ConnectedOAuthProvider,
        _is_shared: bool,
    ) -> Result<UserOAuthToken, sqlx::Error> {
        let mut guard = self.tokens.lock().unwrap();
        let Some(token) = guard
            .iter_mut()
            .find(|token| token.user_id == _user_id && token.provider == _provider)
        else {
            return Err(sqlx::Error::RowNotFound);
        };
        token.is_shared = _is_shared;
        Ok(token.clone())
    }

    async fn list_by_user_and_provider(
        &self,
        user_id: Uuid,
        provider: ConnectedOAuthProvider,
    ) -> Result<Vec<UserOAuthToken>, sqlx::Error> {
        Ok(self
            .tokens
            .lock()
            .unwrap()
            .iter()
            .filter(|token| token.user_id == user_id && token.provider == provider)
            .cloned()
            .collect())
    }
}

#[derive(Clone)]
struct SpyTokenRepo {
    inner: TokenRepo,
    calls: Arc<std::sync::Mutex<Vec<&'static str>>>,
}

impl SpyTokenRepo {
    fn new(tokens: Vec<UserOAuthToken>) -> Self {
        Self {
            inner: TokenRepo::new(tokens),
            calls: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }

    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }

    fn record(&self, label: &'static str) {
        self.calls.lock().unwrap().push(label);
    }
}

#[async_trait]
impl UserOAuthTokenRepository for SpyTokenRepo {
    async fn upsert_token(
        &self,
        _new_token: NewUserOAuthToken,
    ) -> Result<UserOAuthToken, sqlx::Error> {
        self.record("upsert_token");
        Err(sqlx::Error::RowNotFound)
    }

    async fn find_by_id(&self, token_id: Uuid) -> Result<Option<UserOAuthToken>, sqlx::Error> {
        self.record("find_by_id");
        Ok(self
            .inner
            .tokens
            .lock()
            .unwrap()
            .iter()
            .find(|token| token.id == token_id)
            .cloned())
    }

    async fn find_by_user_and_provider(
        &self,
        user_id: Uuid,
        provider: ConnectedOAuthProvider,
    ) -> Result<Option<UserOAuthToken>, sqlx::Error> {
        self.record("find_by_user_and_provider");
        Ok(self
            .inner
            .tokens
            .lock()
            .unwrap()
            .iter()
            .find(|token| token.user_id == user_id && token.provider == provider)
            .cloned())
    }

    async fn delete_token(
        &self,
        _user_id: Uuid,
        _provider: ConnectedOAuthProvider,
    ) -> Result<(), sqlx::Error> {
        self.record("delete_token");
        Ok(())
    }

    async fn list_tokens_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<UserOAuthToken>, sqlx::Error> {
        self.record("list_tokens_for_user");
        Ok(self
            .inner
            .tokens
            .lock()
            .unwrap()
            .iter()
            .filter(|token| token.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn mark_shared(
        &self,
        _user_id: Uuid,
        _provider: ConnectedOAuthProvider,
        _is_shared: bool,
    ) -> Result<UserOAuthToken, sqlx::Error> {
        self.record("mark_shared");
        Err(sqlx::Error::RowNotFound)
    }

    async fn list_by_user_and_provider(
        &self,
        user_id: Uuid,
        provider: ConnectedOAuthProvider,
    ) -> Result<Vec<UserOAuthToken>, sqlx::Error> {
        self.record("list_by_user_and_provider");
        Ok(self
            .inner
            .tokens
            .lock()
            .unwrap()
            .iter()
            .filter(|token| token.user_id == user_id && token.provider == provider)
            .cloned()
            .collect())
    }
}

#[derive(Default)]
struct RecordingTokenRepo {
    saved: Mutex<Option<UserOAuthToken>>,
}

impl RecordingTokenRepo {
    fn saved_token(&self) -> Option<UserOAuthToken> {
        self.saved.lock().unwrap().clone()
    }
}

#[async_trait]
impl UserOAuthTokenRepository for RecordingTokenRepo {
    async fn upsert_token(
        &self,
        new_token: NewUserOAuthToken,
    ) -> Result<UserOAuthToken, sqlx::Error> {
        let now = OffsetDateTime::now_utc();
        let record = UserOAuthToken {
            id: Uuid::new_v4(),
            user_id: new_token.user_id,
            workspace_id: None,
            provider: new_token.provider,
            access_token: new_token.access_token.clone(),
            refresh_token: new_token.refresh_token.clone(),
            expires_at: new_token.expires_at,
            account_email: new_token.account_email.clone(),
            metadata: new_token.metadata.clone(),
            is_shared: false,
            created_at: now,
            updated_at: now,
        };
        *self.saved.lock().unwrap() = Some(record.clone());
        Ok(record)
    }

    async fn find_by_id(&self, token_id: Uuid) -> Result<Option<UserOAuthToken>, sqlx::Error> {
        Ok(self
            .saved
            .lock()
            .unwrap()
            .clone()
            .filter(|token| token.id == token_id))
    }

    async fn find_by_user_and_provider(
        &self,
        user_id: Uuid,
        provider: ConnectedOAuthProvider,
    ) -> Result<Option<UserOAuthToken>, sqlx::Error> {
        Ok(self
            .saved
            .lock()
            .unwrap()
            .clone()
            .filter(|token| token.user_id == user_id && token.provider == provider))
    }

    async fn delete_token(
        &self,
        _user_id: Uuid,
        _provider: ConnectedOAuthProvider,
    ) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn list_tokens_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<UserOAuthToken>, sqlx::Error> {
        Ok(self
            .saved
            .lock()
            .unwrap()
            .clone()
            .filter(|token| token.user_id == user_id)
            .into_iter()
            .collect())
    }

    async fn mark_shared(
        &self,
        _user_id: Uuid,
        _provider: ConnectedOAuthProvider,
        _is_shared: bool,
    ) -> Result<UserOAuthToken, sqlx::Error> {
        let mut guard = self.saved.lock().unwrap();
        let Some(token) = guard.as_mut() else {
            return Err(sqlx::Error::RowNotFound);
        };
        if token.user_id != _user_id || token.provider != _provider {
            return Err(sqlx::Error::RowNotFound);
        }
        token.is_shared = _is_shared;
        Ok(token.clone())
    }

    async fn list_by_user_and_provider(
        &self,
        _user_id: Uuid,
        _provider: ConnectedOAuthProvider,
    ) -> Result<Vec<UserOAuthToken>, sqlx::Error> {
        Ok(Vec::new())
    }
}

#[derive(Clone)]
struct WorkspaceConnectionsStub {
    entries: Vec<(Uuid, WorkspaceConnectionListing)>,
}

impl WorkspaceConnectionsStub {
    fn new(entries: Vec<(Uuid, WorkspaceConnectionListing)>) -> Self {
        Self { entries }
    }
}

#[async_trait]
impl WorkspaceConnectionRepository for WorkspaceConnectionsStub {
    async fn insert_connection(
        &self,
        _new_connection: NewWorkspaceConnection,
    ) -> Result<WorkspaceConnection, sqlx::Error> {
        Err(sqlx::Error::RowNotFound)
    }

    async fn find_by_id(
        &self,
        _connection_id: Uuid,
    ) -> Result<Option<WorkspaceConnection>, sqlx::Error> {
        Ok(None)
    }

    async fn get_by_id(&self, _connection_id: Uuid) -> Result<WorkspaceConnection, sqlx::Error> {
        Err(sqlx::Error::RowNotFound)
    }

    async fn list_for_workspace_provider(
        &self,
        _workspace_id: Uuid,
        _provider: ConnectedOAuthProvider,
    ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
        Ok(Vec::new())
    }

    async fn find_by_source_token(
        &self,
        _user_oauth_token_id: Uuid,
    ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
        Ok(Vec::new())
    }

    async fn list_by_workspace_and_provider(
        &self,
        _workspace_id: Uuid,
        _provider: ConnectedOAuthProvider,
    ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
        Ok(Vec::new())
    }

    async fn list_for_workspace(
        &self,
        workspace_id: Uuid,
    ) -> Result<Vec<WorkspaceConnectionListing>, sqlx::Error> {
        Ok(self
            .entries
            .iter()
            .filter(|(_, record)| record.workspace_id == workspace_id)
            .map(|(_, record)| record.clone())
            .collect())
    }

    async fn list_for_user_memberships(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<WorkspaceConnectionListing>, sqlx::Error> {
        Ok(self
            .entries
            .iter()
            .filter(|(member_id, _)| *member_id == user_id)
            .map(|(_, record)| record.clone())
            .collect())
    }

    async fn list_by_workspace_creator(
        &self,
        _workspace_id: Uuid,
        _creator_id: Uuid,
    ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
        Ok(Vec::new())
    }

    async fn update_tokens_for_creator(
        &self,
        _creator_id: Uuid,
        _provider: ConnectedOAuthProvider,
        _access_token: String,
        _refresh_token: String,
        _expires_at: OffsetDateTime,
        _account_email: String,
        _bot_user_id: Option<String>,
        _slack_team_id: Option<String>,
        _incoming_webhook_url: Option<String>,
    ) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn update_tokens_for_connection(
        &self,
        _connection_id: Uuid,
        _access_token: String,
        _refresh_token: String,
        _expires_at: OffsetDateTime,
        _account_email: String,
        _bot_user_id: Option<String>,
        _slack_team_id: Option<String>,
        _incoming_webhook_url: Option<String>,
    ) -> Result<WorkspaceConnection, sqlx::Error> {
        Err(sqlx::Error::RowNotFound)
    }

    async fn update_tokens(
        &self,
        _connection_id: Uuid,
        _access_token: String,
        _refresh_token: String,
        _expires_at: OffsetDateTime,
        _bot_user_id: Option<String>,
        _slack_team_id: Option<String>,
        _incoming_webhook_url: Option<String>,
    ) -> Result<WorkspaceConnection, sqlx::Error> {
        Err(sqlx::Error::RowNotFound)
    }

    async fn delete_connection(&self, _connection_id: Uuid) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn delete_by_id(&self, _connection_id: Uuid) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn delete_by_owner_and_provider(
        &self,
        _workspace_id: Uuid,
        _owner_user_id: Uuid,
        _provider: ConnectedOAuthProvider,
    ) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn delete_by_owner_and_provider_and_id(
        &self,
        _workspace_id: Uuid,
        _owner_user_id: Uuid,
        _provider: ConnectedOAuthProvider,
        _connection_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn has_connections_for_owner_provider(
        &self,
        _owner_user_id: Uuid,
        _provider: ConnectedOAuthProvider,
    ) -> Result<bool, sqlx::Error> {
        Ok(false)
    }

    async fn mark_connections_stale_for_creator(
        &self,
        _creator_id: Uuid,
        _provider: ConnectedOAuthProvider,
    ) -> Result<
        Vec<crate::db::workspace_connection_repository::StaleWorkspaceConnection>,
        sqlx::Error,
    > {
        Ok(Vec::new())
    }

    async fn record_audit_event(
        &self,
        event: NewWorkspaceAuditEvent,
    ) -> Result<WorkspaceAuditEvent, sqlx::Error> {
        let _ = event;
        Err(sqlx::Error::RowNotFound)
    }
}

#[derive(Default)]
struct RecordingWorkspaceConnectionRepo {
    connections: Mutex<Vec<WorkspaceConnection>>,
}

impl RecordingWorkspaceConnectionRepo {
    fn connections(&self) -> Vec<WorkspaceConnection> {
        self.connections.lock().unwrap().clone()
    }
}

#[async_trait]
impl WorkspaceConnectionRepository for RecordingWorkspaceConnectionRepo {
    async fn insert_connection(
        &self,
        new_connection: NewWorkspaceConnection,
    ) -> Result<WorkspaceConnection, sqlx::Error> {
        let now = OffsetDateTime::now_utc();
        let record = WorkspaceConnection {
            id: Uuid::new_v4(),
            connection_id: new_connection.connection_id,
            workspace_id: new_connection.workspace_id,
            created_by: new_connection.created_by,
            owner_user_id: new_connection.owner_user_id,
            user_oauth_token_id: new_connection.user_oauth_token_id,
            provider: new_connection.provider,
            access_token: new_connection.access_token,
            refresh_token: new_connection.refresh_token,
            expires_at: new_connection.expires_at,
            account_email: new_connection.account_email,
            created_at: now,
            updated_at: now,
            metadata: new_connection.metadata,
            bot_user_id: new_connection.bot_user_id,
            incoming_webhook_url: new_connection.incoming_webhook_url,
            slack_team_id: new_connection.slack_team_id,
        };
        self.connections.lock().unwrap().push(record.clone());
        Ok(record)
    }

    async fn find_by_id(
        &self,
        connection_id: Uuid,
    ) -> Result<Option<WorkspaceConnection>, sqlx::Error> {
        Ok(self
            .connections
            .lock()
            .unwrap()
            .iter()
            .find(|connection| connection.id == connection_id)
            .cloned())
    }

    async fn get_by_id(&self, connection_id: Uuid) -> Result<WorkspaceConnection, sqlx::Error> {
        self.find_by_id(connection_id)
            .await?
            .ok_or(sqlx::Error::RowNotFound)
    }

    async fn list_for_workspace_provider(
        &self,
        workspace_id: Uuid,
        provider: ConnectedOAuthProvider,
    ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
        Ok(self
            .connections
            .lock()
            .unwrap()
            .iter()
            .filter(|connection| {
                connection.workspace_id == workspace_id && connection.provider == provider
            })
            .cloned()
            .collect())
    }

    async fn find_by_source_token(
        &self,
        user_oauth_token_id: Uuid,
    ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
        Ok(self
            .connections
            .lock()
            .unwrap()
            .iter()
            .filter(|connection| connection.user_oauth_token_id == Some(user_oauth_token_id))
            .cloned()
            .collect())
    }

    async fn list_by_workspace_and_provider(
        &self,
        workspace_id: Uuid,
        provider: ConnectedOAuthProvider,
    ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
        self.list_for_workspace_provider(workspace_id, provider)
            .await
    }

    async fn list_for_workspace(
        &self,
        _workspace_id: Uuid,
    ) -> Result<Vec<WorkspaceConnectionListing>, sqlx::Error> {
        Ok(Vec::new())
    }

    async fn list_for_user_memberships(
        &self,
        _user_id: Uuid,
    ) -> Result<Vec<WorkspaceConnectionListing>, sqlx::Error> {
        Ok(Vec::new())
    }

    async fn list_by_workspace_creator(
        &self,
        _workspace_id: Uuid,
        _creator_id: Uuid,
    ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
        Ok(Vec::new())
    }

    async fn update_tokens_for_creator(
        &self,
        _creator_id: Uuid,
        _provider: ConnectedOAuthProvider,
        _access_token: String,
        _refresh_token: String,
        _expires_at: OffsetDateTime,
        _account_email: String,
        _bot_user_id: Option<String>,
        _slack_team_id: Option<String>,
        _incoming_webhook_url: Option<String>,
    ) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn update_tokens_for_connection(
        &self,
        _connection_id: Uuid,
        _access_token: String,
        _refresh_token: String,
        _expires_at: OffsetDateTime,
        _account_email: String,
        _bot_user_id: Option<String>,
        _slack_team_id: Option<String>,
        _incoming_webhook_url: Option<String>,
    ) -> Result<WorkspaceConnection, sqlx::Error> {
        Err(sqlx::Error::RowNotFound)
    }

    async fn update_tokens(
        &self,
        _connection_id: Uuid,
        _access_token: String,
        _refresh_token: String,
        _expires_at: OffsetDateTime,
        _bot_user_id: Option<String>,
        _slack_team_id: Option<String>,
        _incoming_webhook_url: Option<String>,
    ) -> Result<WorkspaceConnection, sqlx::Error> {
        Err(sqlx::Error::RowNotFound)
    }

    async fn delete_connection(&self, _connection_id: Uuid) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn delete_by_id(&self, _connection_id: Uuid) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn delete_by_owner_and_provider(
        &self,
        _workspace_id: Uuid,
        _owner_user_id: Uuid,
        _provider: ConnectedOAuthProvider,
    ) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn delete_by_owner_and_provider_and_id(
        &self,
        _workspace_id: Uuid,
        _owner_user_id: Uuid,
        _provider: ConnectedOAuthProvider,
        _connection_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn has_connections_for_owner_provider(
        &self,
        _owner_user_id: Uuid,
        _provider: ConnectedOAuthProvider,
    ) -> Result<bool, sqlx::Error> {
        Ok(false)
    }

    async fn mark_connections_stale_for_creator(
        &self,
        _creator_id: Uuid,
        _provider: ConnectedOAuthProvider,
    ) -> Result<
        Vec<crate::db::workspace_connection_repository::StaleWorkspaceConnection>,
        sqlx::Error,
    > {
        Ok(Vec::new())
    }

    async fn record_audit_event(
        &self,
        event: NewWorkspaceAuditEvent,
    ) -> Result<WorkspaceAuditEvent, sqlx::Error> {
        Ok(WorkspaceAuditEvent {
            id: Uuid::new_v4(),
            workspace_id: event.workspace_id,
            actor_id: event.actor_id,
            event_type: event.event_type,
            metadata: event.metadata,
            created_at: OffsetDateTime::now_utc(),
        })
    }
}

#[tokio::test]
async fn list_connections_returns_personal_and_workspace_entries() {
    let config = stub_config();
    let user_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let personal_expires_at = now + Duration::hours(1);
    let personal_updated_at = now - Duration::minutes(5);

    let encrypted_access = encrypt_secret(&config.oauth.token_encryption_key, "access-token")
        .expect("encrypt access token");
    let encrypted_refresh = encrypt_secret(&config.oauth.token_encryption_key, "refresh-token")
        .expect("encrypt refresh token");

    let personal_token_id = Uuid::new_v4();
    let personal_token = UserOAuthToken {
        id: personal_token_id,
        user_id,
        workspace_id: None,
        provider: ConnectedOAuthProvider::Google,
        access_token: encrypted_access,
        refresh_token: encrypted_refresh,
        expires_at: personal_expires_at,
        account_email: "user@example.com".into(),
        metadata: serde_json::json!({}),
        is_shared: false,
        created_at: personal_updated_at - Duration::hours(1),
        updated_at: personal_updated_at,
    };

    let workspace_connection_id = Uuid::new_v4();
    let workspace_id = Uuid::new_v4();
    let workspace_expires_at = personal_expires_at + Duration::hours(4);
    let workspace_updated_at = now - Duration::minutes(2);
    let listing = WorkspaceConnectionListing {
        id: workspace_connection_id,
        connection_id: Some(personal_token_id),
        workspace_id,
        owner_user_id: user_id,
        workspace_name: "Shared Workspace".into(),
        provider: ConnectedOAuthProvider::Google,
        account_email: "shared@example.com".into(),
        expires_at: workspace_expires_at,
        shared_by_first_name: Some("Alice ".into()),
        shared_by_last_name: Some(" Example".into()),
        shared_by_email: Some(" alice@example.com ".into()),
        updated_at: workspace_updated_at,
        requires_reconnect: false,
        has_incoming_webhook: false,
    };

    let workspace_repo: Arc<dyn WorkspaceConnectionRepository> =
        Arc::new(WorkspaceConnectionsStub::new(vec![(user_id, listing)]));

    let token_repo: Arc<dyn UserOAuthTokenRepository> =
        Arc::new(TokenRepo::new(vec![personal_token]));
    let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());
    let oauth_client = Arc::new(reqwest::Client::new());
    let oauth_service = Arc::new(OAuthAccountService::new(
        token_repo,
        workspace_repo.clone(),
        encryption_key,
        oauth_client,
        &config.oauth,
        &config.github_app,
    ));

    // Ensure user is a member of the requested workspace
    let membership = workspace_membership(workspace_id, WorkspaceRole::Admin, "workspace");
    let mut state = stub_state_with_workspace_repo(
        config.clone(),
        Arc::new(MembershipWorkspaceRepo::new(vec![(user_id, membership)])),
    );
    state.oauth_accounts = oauth_service;
    state.workspace_connection_repo = workspace_repo;

    let claims = Claims {
        id: user_id.to_string(),
        ..stub_claims()
    };

    let response = list_connections(
        State(state),
        AuthSession(claims),
        Query(ListConnectionsQuery {
            workspace: workspace_id,
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let json: Value = serde_json::from_slice(&body).expect("response json");

    assert_eq!(json["success"].as_bool(), Some(true));
    let personal = connections_for_provider(&json["personal"], "google");
    assert_eq!(personal.len(), 1);
    let personal_entry = &personal[0];
    let expected_personal_id = personal_token_id.to_string();
    let expected_personal_expires = personal_expires_at
        .format(&Rfc3339)
        .expect("format personal expires");
    assert_eq!(personal_entry["provider"].as_str(), Some("google"));
    assert_eq!(
        personal_entry["id"].as_str(),
        Some(expected_personal_id.as_str())
    );
    assert_eq!(
        personal_entry["accountEmail"].as_str(),
        Some("user@example.com")
    );
    assert_eq!(personal_entry["isShared"].as_bool(), Some(true));
    assert_eq!(
        personal_entry["expiresAt"].as_str(),
        Some(expected_personal_expires.as_str())
    );
    assert_eq!(personal_entry["requiresReconnect"].as_bool(), Some(false));
    let expected_personal_refreshed = personal_updated_at
        .format(&Rfc3339)
        .expect("format personal refreshed");
    assert_eq!(
        personal_entry["lastRefreshedAt"].as_str(),
        Some(expected_personal_refreshed.as_str())
    );
    assert_eq!(
        personal_entry["owner"]["userId"].as_str(),
        Some(user_id.to_string().as_str())
    );
    assert_eq!(personal_entry["owner"]["name"].as_str(), Some("Test User"));
    assert_eq!(
        personal_entry["owner"]["email"].as_str(),
        Some("user@example.com")
    );

    let workspace = connections_for_provider(&json["workspace"], "google");
    assert_eq!(workspace.len(), 1);
    let workspace_entry = &workspace[0];
    let expected_workspace_id = workspace_connection_id.to_string();
    let expected_workspace_uuid = workspace_id.to_string();
    let expected_workspace_expires = workspace_expires_at
        .format(&Rfc3339)
        .expect("format workspace expires");
    assert_eq!(workspace_entry["provider"].as_str(), Some("google"));
    assert_eq!(
        workspace_entry["id"].as_str(),
        Some(expected_workspace_id.as_str())
    );
    assert_eq!(
        workspace_entry["connectionId"].as_str(),
        Some(expected_personal_id.as_str())
    );
    assert_eq!(
        workspace_entry["workspaceId"].as_str(),
        Some(expected_workspace_uuid.as_str())
    );
    assert_eq!(
        workspace_entry["workspaceName"].as_str(),
        Some("Shared Workspace")
    );
    assert_eq!(
        workspace_entry["accountEmail"].as_str(),
        Some("shared@example.com")
    );
    assert_eq!(
        workspace_entry["sharedByName"].as_str(),
        Some("Alice Example")
    );
    assert_eq!(
        workspace_entry["sharedByEmail"].as_str(),
        Some("alice@example.com")
    );
    assert_eq!(
        workspace_entry["expiresAt"].as_str(),
        Some(expected_workspace_expires.as_str())
    );
    let expected_workspace_refreshed = workspace_updated_at
        .format(&Rfc3339)
        .expect("format workspace refreshed");
    assert_eq!(
        workspace_entry["lastRefreshedAt"].as_str(),
        Some(expected_workspace_refreshed.as_str())
    );
    assert_eq!(
        workspace_entry["owner"]["userId"].as_str(),
        Some(user_id.to_string().as_str())
    );
    assert_eq!(
        workspace_entry["owner"]["name"].as_str(),
        Some("Alice Example")
    );
    assert_eq!(
        workspace_entry["owner"]["email"].as_str(),
        Some("alice@example.com")
    );
    assert_eq!(workspace_entry["requiresReconnect"].as_bool(), Some(false));
}

#[tokio::test]
async fn list_connections_returns_personal_auth_without_workspace_connection() {
    let config = stub_config();
    let registry = crate::state::test_integration_registry();
    let (integration_id, provider) = workspace_first_personal_integration(registry.as_ref());
    let workspace_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let personal_updated_at = OffsetDateTime::now_utc() - Duration::minutes(12);

    let personal_token = UserOAuthToken {
        updated_at: personal_updated_at,
        created_at: personal_updated_at - Duration::hours(1),
        ..personal_token_fixture(&config, user_id, provider, "user@example.com", false)
    };

    let state = build_list_connections_state(
        config.clone(),
        vec![(
            user_id,
            workspace_membership(workspace_id, WorkspaceRole::Admin, "workspace"),
        )],
        vec![personal_token],
        Vec::new(),
    );

    // Listing returns 200 with derived personal auth; enforcement lives in connect start/callback/execution.
    let response = list_connections(
        State(state),
        AuthSession(claims_for(user_id)),
        Query(ListConnectionsQuery {
            workspace: workspace_id,
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let json: Value = serde_json::from_slice(&body).expect("response json");

    assert!(json.get("error").is_none());
    assert_eq!(json["workspace"].as_array().map(Vec::len), Some(0));
    let personal_auth = json["personalAuth"].as_object().expect("personal auth map");
    let status = personal_auth
        .get(integration_id.as_str())
        .expect("personal auth entry");
    assert_eq!(status["has_personal_auth"].as_bool(), Some(true));
}

#[tokio::test]
async fn list_connections_personal_auth_connected_at_tracks_token_update() {
    let config = stub_config();
    let registry = crate::state::test_integration_registry();
    let (integration_id, provider) = workspace_first_personal_integration(registry.as_ref());
    let workspace_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let personal_updated_at = OffsetDateTime::now_utc() - Duration::minutes(18);

    let personal_token = UserOAuthToken {
        updated_at: personal_updated_at,
        created_at: personal_updated_at - Duration::hours(2),
        ..personal_token_fixture(&config, user_id, provider, "user@example.com", false)
    };
    let workspace_listing = workspace_connection_fixture(
        workspace_id,
        user_id,
        Some(personal_token.id),
        provider,
        "shared@example.com",
        false,
        ("Owner", "User", "owner@example.com"),
    );

    let state = build_list_connections_state(
        config.clone(),
        vec![(
            user_id,
            workspace_membership(workspace_id, WorkspaceRole::Admin, "workspace"),
        )],
        vec![personal_token],
        vec![(user_id, workspace_listing)],
    );

    let response = list_connections(
        State(state),
        AuthSession(claims_for(user_id)),
        Query(ListConnectionsQuery {
            workspace: workspace_id,
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let json: Value = serde_json::from_slice(&body).expect("response json");

    assert!(json.get("error").is_none());
    assert_eq!(json["workspace"].as_array().map(Vec::len), Some(1));
    let personal_auth = json["personalAuth"].as_object().expect("personal auth map");
    let status = personal_auth
        .get(integration_id.as_str())
        .expect("personal auth entry");
    assert_eq!(status["has_personal_auth"].as_bool(), Some(true));
    let expected_connected_at = personal_updated_at
        .format(&Rfc3339)
        .expect("format personal auth connected at");
    assert_eq!(
        status["personal_auth_connected_at"].as_str(),
        Some(expected_connected_at.as_str())
    );
}

#[tokio::test]
async fn list_connections_requires_membership() {
    let config = stub_config();
    let user_id = Uuid::new_v4();
    let workspace_id = Uuid::new_v4();

    let workspace_repo: Arc<dyn WorkspaceConnectionRepository> =
        Arc::new(WorkspaceConnectionsStub::new(vec![]));
    let token_repo: Arc<dyn UserOAuthTokenRepository> = Arc::new(TokenRepo::new(vec![]));
    let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());
    let oauth_client = Arc::new(reqwest::Client::new());
    let oauth_service = Arc::new(OAuthAccountService::new(
        token_repo,
        workspace_repo.clone(),
        encryption_key,
        oauth_client,
        &config.oauth,
        &config.github_app,
    ));

    // No membership for this workspace
    let mut state = stub_state_with_workspace_repo(
        config.clone(),
        Arc::new(MembershipWorkspaceRepo::new(vec![])),
    );
    state.oauth_accounts = oauth_service;
    state.workspace_connection_repo = workspace_repo;

    let claims = Claims {
        id: user_id.to_string(),
        ..stub_claims()
    };

    let response = list_connections(
        State(state),
        AuthSession(claims),
        Query(ListConnectionsQuery {
            workspace: workspace_id,
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn list_connections_rejects_solo_plan_workspace() {
    let config = stub_config();
    let user_id = Uuid::new_v4();
    let workspace_id = Uuid::new_v4();

    let state = build_list_connections_state(
        config.clone(),
        vec![(
            user_id,
            workspace_membership(workspace_id, WorkspaceRole::Admin, WORKSPACE_PLAN_SOLO),
        )],
        Vec::new(),
        Vec::new(),
    );

    let response = list_connections(
        State(state),
        AuthSession(claims_for(user_id)),
        Query(ListConnectionsQuery {
            workspace: workspace_id,
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let json: JsonResponse = serde_json::from_slice(&body).expect("response json");
    assert_eq!(json.code.as_deref(), Some("workspace_plan_required"));
    assert_eq!(json.message, OAUTH_PLAN_RESTRICTION_MESSAGE);
    assert!(!json.success);
}

#[tokio::test]
async fn shared_workspace_member_does_not_receive_other_personal_tokens() {
    let config = stub_config();
    let workspace_id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    let member_id = Uuid::new_v4();

    let owner_token = personal_token_fixture(
        &config,
        owner_id,
        ConnectedOAuthProvider::Google,
        "owner@example.com",
        false,
    );
    let member_token = personal_token_fixture(
        &config,
        member_id,
        ConnectedOAuthProvider::Google,
        "member@example.com",
        false,
    );
    let shared_listing = workspace_connection_fixture(
        workspace_id,
        owner_id,
        Some(owner_token.id),
        ConnectedOAuthProvider::Google,
        "shared@example.com",
        false,
        ("Alice", "Owner", "alice@example.com"),
    );

    let memberships = vec![
        (
            owner_id,
            workspace_membership(workspace_id, WorkspaceRole::Owner, "workspace"),
        ),
        (
            member_id,
            workspace_membership(workspace_id, WorkspaceRole::Admin, "workspace"),
        ),
    ];

    let state = build_list_connections_state(
        config.clone(),
        memberships,
        vec![owner_token, member_token],
        vec![(owner_id, shared_listing.clone())],
    );

    let response = list_connections(
        State(state),
        AuthSession(claims_for(member_id)),
        Query(ListConnectionsQuery {
            workspace: workspace_id,
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let json: Value = serde_json::from_slice(&body).expect("response json");

    let personal = connections_for_provider(&json["personal"], "google");
    assert_eq!(personal.len(), 1);
    assert_eq!(
        personal[0]["accountEmail"].as_str(),
        Some("member@example.com")
    );

    let workspace = connections_for_provider(&json["workspace"], "google");
    assert_eq!(workspace.len(), 1);
    assert_eq!(
        workspace[0]["accountEmail"].as_str(),
        Some("shared@example.com")
    );
    assert_eq!(
        workspace[0]["sharedByEmail"].as_str(),
        Some("alice@example.com")
    );
}

#[tokio::test]
async fn promoted_connection_only_appears_in_workspace_list_for_non_owner() {
    let config = stub_config();
    let workspace_id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    let member_id = Uuid::new_v4();

    let owner_token = personal_token_fixture(
        &config,
        owner_id,
        ConnectedOAuthProvider::Google,
        "owner@example.com",
        true,
    );
    let shared_listing = workspace_connection_fixture(
        workspace_id,
        owner_id,
        Some(owner_token.id),
        ConnectedOAuthProvider::Google,
        "shared@example.com",
        false,
        ("Alex", "Owner", "owner@example.com"),
    );

    let memberships = vec![
        (
            owner_id,
            workspace_membership(workspace_id, WorkspaceRole::Owner, "workspace"),
        ),
        (
            member_id,
            workspace_membership(workspace_id, WorkspaceRole::Admin, "workspace"),
        ),
    ];

    let state = build_list_connections_state(
        config.clone(),
        memberships,
        vec![owner_token],
        vec![(owner_id, shared_listing.clone())],
    );

    let response = list_connections(
        State(state),
        AuthSession(claims_for(member_id)),
        Query(ListConnectionsQuery {
            workspace: workspace_id,
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let json: Value = serde_json::from_slice(&body).expect("response json");

    assert_eq!(
        connections_for_provider(&json["personal"], "google").len(),
        0
    );
    let workspace = connections_for_provider(&json["workspace"], "google");
    assert_eq!(workspace.len(), 1);
    assert_eq!(
        workspace[0]["accountEmail"].as_str(),
        Some("shared@example.com")
    );
}

#[tokio::test]
async fn self_promotion_visibility_differs_for_owner_and_member() {
    let config = stub_config();
    let workspace_id = Uuid::new_v4();
    let owner_id = Uuid::new_v4();
    let member_id = Uuid::new_v4();

    let owner_token = personal_token_fixture(
        &config,
        owner_id,
        ConnectedOAuthProvider::Google,
        "owner@example.com",
        true,
    );
    let member_token = personal_token_fixture(
        &config,
        member_id,
        ConnectedOAuthProvider::Google,
        "member@example.com",
        false,
    );
    let shared_listing = workspace_connection_fixture(
        workspace_id,
        owner_id,
        Some(owner_token.id),
        ConnectedOAuthProvider::Google,
        "shared@example.com",
        false,
        ("Owner", "User", "owner@example.com"),
    );

    let memberships = vec![
        (
            owner_id,
            workspace_membership(workspace_id, WorkspaceRole::Owner, "workspace"),
        ),
        (
            member_id,
            workspace_membership(workspace_id, WorkspaceRole::Admin, "workspace"),
        ),
    ];
    let workspace_entries = vec![(owner_id, shared_listing.clone())];
    let personal_tokens = vec![owner_token.clone(), member_token.clone()];

    let owner_state = build_list_connections_state(
        config.clone(),
        memberships.clone(),
        personal_tokens.clone(),
        workspace_entries.clone(),
    );
    let owner_response = list_connections(
        State(owner_state),
        AuthSession(claims_for(owner_id)),
        Query(ListConnectionsQuery {
            workspace: workspace_id,
        }),
    )
    .await;
    assert_eq!(owner_response.status(), StatusCode::OK);
    let owner_body = axum::body::to_bytes(owner_response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let owner_json: Value = serde_json::from_slice(&owner_body).expect("owner response json");
    assert_eq!(
        connections_for_provider(&owner_json["personal"], "google").len(),
        1
    );
    assert_eq!(
        connections_for_provider(&owner_json["workspace"], "google").len(),
        1
    );

    let member_state = build_list_connections_state(
        config.clone(),
        memberships,
        personal_tokens,
        workspace_entries,
    );
    let member_response = list_connections(
        State(member_state),
        AuthSession(claims_for(member_id)),
        Query(ListConnectionsQuery {
            workspace: workspace_id,
        }),
    )
    .await;
    assert_eq!(member_response.status(), StatusCode::OK);
    let member_body = axum::body::to_bytes(member_response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let member_json: Value = serde_json::from_slice(&member_body).expect("member response json");
    let member_personal = connections_for_provider(&member_json["personal"], "google");
    assert_eq!(member_personal.len(), 1);
    assert_eq!(
        member_personal[0]["accountEmail"].as_str(),
        Some("member@example.com")
    );
    assert_eq!(
        connections_for_provider(&member_json["workspace"], "google").len(),
        1
    );
}

#[tokio::test]
async fn list_connections_includes_workspace_reconnect_flag() {
    let config = stub_config();
    let user_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let workspace_id = Uuid::new_v4();
    let connection_id = Uuid::new_v4();

    let listing = WorkspaceConnectionListing {
        id: connection_id,
        connection_id: None,
        workspace_id,
        owner_user_id: user_id,
        workspace_name: "Requires Attention".into(),
        provider: ConnectedOAuthProvider::Microsoft,
        account_email: "shared@example.com".into(),
        expires_at: now - Duration::hours(1),
        shared_by_first_name: Some("Taylor".into()),
        shared_by_last_name: Some("Admin".into()),
        shared_by_email: Some("taylor@example.com".into()),
        updated_at: now - Duration::minutes(5),
        requires_reconnect: true,
        has_incoming_webhook: false,
    };

    let workspace_repo: Arc<dyn WorkspaceConnectionRepository> =
        Arc::new(WorkspaceConnectionsStub::new(vec![(user_id, listing)]));

    let token_repo: Arc<dyn UserOAuthTokenRepository> = Arc::new(TokenRepo::new(Vec::new()));
    let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());
    let oauth_client = Arc::new(reqwest::Client::new());
    let oauth_service = Arc::new(OAuthAccountService::new(
        token_repo,
        workspace_repo.clone(),
        encryption_key,
        oauth_client,
        &config.oauth,
        &config.github_app,
    ));

    // Ensure membership for the requested workspace
    let membership = workspace_membership(workspace_id, WorkspaceRole::Admin, "workspace");
    let mut state = stub_state_with_workspace_repo(
        config.clone(),
        Arc::new(MembershipWorkspaceRepo::new(vec![(user_id, membership)])),
    );
    state.oauth_accounts = oauth_service;
    state.workspace_connection_repo = workspace_repo;

    let claims = Claims {
        id: user_id.to_string(),
        ..stub_claims()
    };

    let response = list_connections(
        State(state),
        AuthSession(claims),
        Query(ListConnectionsQuery {
            workspace: workspace_id,
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let json: Value = serde_json::from_slice(&body).expect("response json");

    let workspace = connections_for_provider(&json["workspace"], "microsoft");
    assert_eq!(workspace.len(), 1);
    let entry = &workspace[0];
    assert_eq!(entry["requiresReconnect"].as_bool(), Some(true));
    assert_eq!(entry["workspaceName"].as_str(), Some("Requires Attention"));
    assert!(entry.get("connectionId").is_none());
}

#[tokio::test]
async fn list_provider_connections_filters_by_provider() {
    let config = stub_config();
    let user_id = Uuid::new_v4();
    let workspace_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();

    let encrypted_access = encrypt_secret(&config.oauth.token_encryption_key, "access-token")
        .expect("encrypt access token");
    let encrypted_refresh = encrypt_secret(&config.oauth.token_encryption_key, "refresh-token")
        .expect("encrypt refresh token");

    let personal_google = UserOAuthToken {
        id: Uuid::new_v4(),
        user_id,
        workspace_id: None,
        provider: ConnectedOAuthProvider::Google,
        access_token: encrypted_access.clone(),
        refresh_token: encrypted_refresh.clone(),
        expires_at: now + Duration::hours(1),
        account_email: "google@example.com".into(),
        metadata: serde_json::json!({}),
        is_shared: false,
        created_at: now - Duration::hours(2),
        updated_at: now - Duration::minutes(30),
    };

    let personal_microsoft = UserOAuthToken {
        id: Uuid::new_v4(),
        user_id,
        workspace_id: None,
        provider: ConnectedOAuthProvider::Microsoft,
        access_token: encrypted_access.clone(),
        refresh_token: encrypted_refresh.clone(),
        expires_at: now + Duration::hours(2),
        account_email: "microsoft@example.com".into(),
        metadata: serde_json::json!({}),
        is_shared: false,
        created_at: now - Duration::hours(3),
        updated_at: now - Duration::minutes(45),
    };

    let google_listing = workspace_connection_fixture(
        workspace_id,
        user_id,
        Some(personal_google.id),
        ConnectedOAuthProvider::Google,
        "shared-google@example.com",
        false,
        ("Owner", "One", "owner.one@example.com"),
    );
    let microsoft_listing = workspace_connection_fixture(
        workspace_id,
        user_id,
        Some(personal_microsoft.id),
        ConnectedOAuthProvider::Microsoft,
        "shared-ms@example.com",
        false,
        ("Owner", "Two", "owner.two@example.com"),
    );

    let memberships = vec![(
        user_id,
        workspace_membership(workspace_id, WorkspaceRole::Admin, "workspace"),
    )];
    let personal_tokens = vec![personal_google.clone(), personal_microsoft];
    let workspace_entries = vec![
        (user_id, google_listing.clone()),
        (user_id, microsoft_listing),
    ];
    let state = build_list_connections_state(
        config.clone(),
        memberships,
        personal_tokens,
        workspace_entries,
    );

    let response = list_provider_connections(
        State(state),
        AuthSession(claims_for(user_id)),
        Path("google".to_string()),
        Query(ListConnectionsQuery {
            workspace: workspace_id,
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let json: Value = serde_json::from_slice(&body).expect("response json");

    assert_eq!(json["provider"].as_str(), Some("google"));
    let personal = json["personal"]
        .as_array()
        .expect("personal connections array");
    assert_eq!(personal.len(), 1);
    let personal_id = personal_google.id.to_string();
    assert_eq!(personal[0]["id"].as_str(), Some(personal_id.as_str()));

    let workspace = json["workspace"]
        .as_array()
        .expect("workspace connections array");
    assert_eq!(workspace.len(), 1);
    let workspace_id_str = workspace_id.to_string();
    assert_eq!(
        workspace[0]["id"].as_str(),
        Some(google_listing.id.to_string().as_str())
    );
    assert_eq!(
        workspace[0]["workspaceId"].as_str(),
        Some(workspace_id_str.as_str())
    );
}

#[tokio::test]
async fn get_connection_by_id_returns_workspace_connection() {
    let config = stub_config();
    let user_id = Uuid::new_v4();
    let workspace_id = Uuid::new_v4();
    let connection_id = Uuid::new_v4();

    let listing = workspace_connection_fixture(
        workspace_id,
        user_id,
        Some(connection_id),
        ConnectedOAuthProvider::Slack,
        "slack-shared@example.com",
        true,
        ("Alex", "Owner", "alex.owner@example.com"),
    );

    let memberships = vec![(
        user_id,
        workspace_membership(workspace_id, WorkspaceRole::Admin, "workspace"),
    )];
    let workspace_entries = vec![(user_id, listing.clone())];
    let state = build_list_connections_state(config, memberships, Vec::new(), workspace_entries);

    let response = get_connection_by_id(
        State(state),
        AuthSession(claims_for(user_id)),
        Path(listing.id),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let json: Value = serde_json::from_slice(&body).expect("response json");

    assert_eq!(
        json["connectionId"].as_str(),
        Some(connection_id.to_string().as_str())
    );
    assert!(json["personal"].is_null());
    assert_eq!(
        json["workspace"]["workspaceId"].as_str(),
        Some(workspace_id.to_string().as_str())
    );
    assert_eq!(json["workspace"]["provider"].as_str(), Some("slack"));
}

#[tokio::test]
async fn get_connection_by_id_returns_personal_connection() {
    let config = stub_config();
    let user_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let token_id = Uuid::new_v4();

    let encrypted_access = encrypt_secret(&config.oauth.token_encryption_key, "personal-access")
        .expect("encrypt access token");
    let encrypted_refresh = encrypt_secret(&config.oauth.token_encryption_key, "personal-refresh")
        .expect("encrypt refresh token");

    let token_repo: Arc<dyn UserOAuthTokenRepository> =
        Arc::new(TokenRepo::new(vec![UserOAuthToken {
            id: token_id,
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Asana,
            access_token: encrypted_access,
            refresh_token: encrypted_refresh,
            expires_at: now + Duration::hours(4),
            account_email: "owner@example.com".into(),
            metadata: serde_json::json!({}),
            is_shared: false,
            created_at: now - Duration::hours(1),
            updated_at: now - Duration::minutes(10),
        }]));
    let workspace_repo: Arc<dyn WorkspaceConnectionRepository> =
        Arc::new(WorkspaceConnectionsStub::new(Vec::new()));
    let oauth_service = Arc::new(OAuthAccountService::new(
        token_repo,
        workspace_repo.clone(),
        Arc::new(config.oauth.token_encryption_key.clone()),
        Arc::new(reqwest::Client::new()),
        &config.oauth,
        &config.github_app,
    ));

    let mut state = stub_state(config);
    state.oauth_accounts = oauth_service;
    state.workspace_connection_repo = workspace_repo;

    let response = get_connection_by_id(
        State(state),
        AuthSession(claims_for(user_id)),
        Path(token_id),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let json: Value = serde_json::from_slice(&body).expect("response json");

    assert_eq!(
        json["connectionId"].as_str(),
        Some(token_id.to_string().as_str())
    );
    assert!(json["workspace"].is_null());
    assert_eq!(json["personal"]["provider"].as_str(), Some("asana"));
    assert_eq!(
        json["personal"]["accountEmail"].as_str(),
        Some("owner@example.com")
    );
}

#[tokio::test]
async fn refresh_connection_rejects_without_connection_id() {
    let config = stub_config();
    let user_id = Uuid::new_v4();

    let state = stub_state(config.clone());

    let claims = Claims {
        id: user_id.to_string(),
        ..stub_claims()
    };

    let response = refresh_connection(
        State(state),
        AuthSession(claims),
        Path("google".to_string()),
        Query(ConnectionTarget {
            connection_id: None,
        }),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn refresh_connection_missing_connection_id_has_no_side_effects() {
    let config = stub_config();
    let user_id = Uuid::new_v4();

    let token = personal_token_fixture(
        &config,
        user_id,
        ConnectedOAuthProvider::Google,
        "owner@example.com",
        false,
    );
    let spy_repo = Arc::new(SpyTokenRepo::new(vec![token]));
    let token_repo: Arc<dyn UserOAuthTokenRepository> = spy_repo.clone();
    let workspace_repo: Arc<dyn WorkspaceConnectionRepository> =
        Arc::new(WorkspaceConnectionsStub::new(Vec::new()));
    let oauth_service = Arc::new(OAuthAccountService::new(
        token_repo,
        workspace_repo.clone(),
        Arc::new(config.oauth.token_encryption_key.clone()),
        Arc::new(reqwest::Client::new()),
        &config.oauth,
        &config.github_app,
    ));

    let mut state = stub_state(config);
    state.oauth_accounts = oauth_service;
    state.workspace_connection_repo = workspace_repo;

    let response = refresh_connection(
        State(state),
        AuthSession(claims_for(user_id)),
        Path("google".to_string()),
        Query(ConnectionTarget {
            connection_id: None,
        }),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        spy_repo.calls().is_empty(),
        "token repo should not be invoked"
    );
}

#[tokio::test]
async fn refresh_connection_missing_connection_id_does_not_fallback_to_provider() {
    let config = stub_config();
    let user_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let token_id = Uuid::new_v4();

    let encrypted_access = encrypt_secret(&config.oauth.token_encryption_key, "access-token")
        .expect("encrypt access token");
    let encrypted_refresh = encrypt_secret(&config.oauth.token_encryption_key, "refresh-token")
        .expect("encrypt refresh token");

    let token_repo: Arc<dyn UserOAuthTokenRepository> =
        Arc::new(TokenRepo::new(vec![UserOAuthToken {
            id: token_id,
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Google,
            access_token: encrypted_access,
            refresh_token: encrypted_refresh,
            expires_at: now + Duration::hours(1),
            account_email: "fallback@example.com".into(),
            metadata: serde_json::json!({}),
            is_shared: false,
            created_at: now - Duration::hours(1),
            updated_at: now - Duration::minutes(5),
        }]));
    let workspace_repo: Arc<dyn WorkspaceConnectionRepository> =
        Arc::new(WorkspaceConnectionsStub::new(Vec::new()));
    let oauth_service = Arc::new(OAuthAccountService::new(
        token_repo,
        workspace_repo.clone(),
        Arc::new(config.oauth.token_encryption_key.clone()),
        Arc::new(reqwest::Client::new()),
        &config.oauth,
        &config.github_app,
    ));

    let mut state = stub_state(config);
    state.oauth_accounts = oauth_service;
    state.workspace_connection_repo = workspace_repo;

    let response = refresh_connection(
        State(state),
        AuthSession(claims_for(user_id)),
        Path("google".to_string()),
        Query(ConnectionTarget {
            connection_id: None,
        }),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn refresh_connection_accepts_connection_id_query() {
    let config = stub_config();
    let user_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let token_id = Uuid::new_v4();

    let encrypted_access = encrypt_secret(&config.oauth.token_encryption_key, "access-token")
        .expect("encrypt access token");
    let encrypted_refresh = encrypt_secret(&config.oauth.token_encryption_key, "refresh-token")
        .expect("encrypt refresh token");

    let token_repo: Arc<dyn UserOAuthTokenRepository> =
        Arc::new(TokenRepo::new(vec![UserOAuthToken {
            id: token_id,
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Google,
            access_token: encrypted_access,
            refresh_token: encrypted_refresh,
            expires_at: now + Duration::hours(1),
            account_email: "query@example.com".into(),
            metadata: serde_json::json!({}),
            is_shared: false,
            created_at: now - Duration::hours(1),
            updated_at: now - Duration::minutes(2),
        }]));
    let workspace_repo: Arc<dyn WorkspaceConnectionRepository> =
        Arc::new(WorkspaceConnectionsStub::new(Vec::new()));
    let oauth_service = Arc::new(OAuthAccountService::new(
        token_repo,
        workspace_repo.clone(),
        Arc::new(config.oauth.token_encryption_key.clone()),
        Arc::new(reqwest::Client::new()),
        &config.oauth,
        &config.github_app,
    ));

    let mut state = stub_state(config);
    state.oauth_accounts = oauth_service;
    state.workspace_connection_repo = workspace_repo;

    let response = refresh_connection(
        State(state),
        AuthSession(claims_for(user_id)),
        Path("google".to_string()),
        Query(ConnectionTarget {
            connection_id: Some(token_id),
        }),
        None,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let json: Value = serde_json::from_slice(&body).expect("response json");

    assert_eq!(
        json["connectionId"].as_str(),
        Some(token_id.to_string().as_str())
    );
    assert_eq!(json["accountEmail"].as_str(), Some("query@example.com"));
}

#[tokio::test]
async fn disconnect_connection_accepts_connection_id_body() {
    let config = stub_config();
    let user_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let token_id = Uuid::new_v4();

    let encrypted_access = encrypt_secret(&config.oauth.token_encryption_key, "access-token")
        .expect("encrypt access token");
    let encrypted_refresh = encrypt_secret(&config.oauth.token_encryption_key, "refresh-token")
        .expect("encrypt refresh token");

    let token_repo: Arc<dyn UserOAuthTokenRepository> =
        Arc::new(TokenRepo::new(vec![UserOAuthToken {
            id: token_id,
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Google,
            access_token: encrypted_access,
            refresh_token: encrypted_refresh,
            expires_at: now + Duration::hours(1),
            account_email: "disconnect@example.com".into(),
            metadata: serde_json::json!({}),
            is_shared: false,
            created_at: now - Duration::hours(1),
            updated_at: now - Duration::minutes(5),
        }]));
    let workspace_repo: Arc<dyn WorkspaceConnectionRepository> =
        Arc::new(WorkspaceConnectionsStub::new(Vec::new()));
    let oauth_service = Arc::new(OAuthAccountService::new(
        token_repo,
        workspace_repo.clone(),
        Arc::new(config.oauth.token_encryption_key.clone()),
        Arc::new(reqwest::Client::new()),
        &config.oauth,
        &config.github_app,
    ));

    let mut state = stub_state(config);
    state.oauth_accounts = oauth_service;
    state.workspace_connection_repo = workspace_repo;

    let response = disconnect_connection(
        State(state),
        AuthSession(claims_for(user_id)),
        Path("google".to_string()),
        Query(ConnectionTarget {
            connection_id: Some(token_id),
        }),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let json: Value = serde_json::from_slice(&body).expect("response json");

    assert_eq!(json["success"].as_bool(), Some(true));
    assert_eq!(json["message"].as_str(), Some("Disconnected"));
    assert_eq!(
        json["connectionId"].as_str(),
        Some(token_id.to_string().as_str())
    );
}

#[tokio::test]
async fn disconnect_connection_missing_connection_id_has_no_side_effects() {
    let config = stub_config();
    let user_id = Uuid::new_v4();
    let token = personal_token_fixture(
        &config,
        user_id,
        ConnectedOAuthProvider::Google,
        "disconnect@example.com",
        false,
    );

    let spy_repo = Arc::new(SpyTokenRepo::new(vec![token]));
    let token_repo: Arc<dyn UserOAuthTokenRepository> = spy_repo.clone();
    let workspace_repo: Arc<dyn WorkspaceConnectionRepository> =
        Arc::new(WorkspaceConnectionsStub::new(Vec::new()));
    let oauth_service = Arc::new(OAuthAccountService::new(
        token_repo,
        workspace_repo.clone(),
        Arc::new(config.oauth.token_encryption_key.clone()),
        Arc::new(reqwest::Client::new()),
        &config.oauth,
        &config.github_app,
    ));

    let mut state = stub_state(config);
    state.oauth_accounts = oauth_service;
    state.workspace_connection_repo = workspace_repo;

    let response = disconnect_connection(
        State(state),
        AuthSession(claims_for(user_id)),
        Path("google".to_string()),
        Query(ConnectionTarget {
            connection_id: None,
        }),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        spy_repo.calls().is_empty(),
        "token repo should not be invoked"
    );
}

#[tokio::test]
async fn disconnect_connection_missing_connection_id_does_not_fallback_to_provider() {
    let config = stub_config();
    let user_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let token_id = Uuid::new_v4();

    let encrypted_access = encrypt_secret(&config.oauth.token_encryption_key, "access-token")
        .expect("encrypt access token");
    let encrypted_refresh = encrypt_secret(&config.oauth.token_encryption_key, "refresh-token")
        .expect("encrypt refresh token");

    let token_repo: Arc<dyn UserOAuthTokenRepository> =
        Arc::new(TokenRepo::new(vec![UserOAuthToken {
            id: token_id,
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Google,
            access_token: encrypted_access,
            refresh_token: encrypted_refresh,
            expires_at: now + Duration::hours(1),
            account_email: "disconnect@example.com".into(),
            metadata: serde_json::json!({}),
            is_shared: false,
            created_at: now - Duration::hours(1),
            updated_at: now - Duration::minutes(5),
        }]));
    let workspace_repo: Arc<dyn WorkspaceConnectionRepository> =
        Arc::new(WorkspaceConnectionsStub::new(Vec::new()));
    let oauth_service = Arc::new(OAuthAccountService::new(
        token_repo,
        workspace_repo.clone(),
        Arc::new(config.oauth.token_encryption_key.clone()),
        Arc::new(reqwest::Client::new()),
        &config.oauth,
        &config.github_app,
    ));

    let mut state = stub_state(config);
    state.oauth_accounts = oauth_service;
    state.workspace_connection_repo = workspace_repo;

    let response = disconnect_connection(
        State(state),
        AuthSession(claims_for(user_id)),
        Path("google".to_string()),
        Query(ConnectionTarget {
            connection_id: None,
        }),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn revoke_connection_accepts_connection_id_query() {
    let config = stub_config();
    let user_id = Uuid::new_v4();
    let now = OffsetDateTime::now_utc();
    let token_id = Uuid::new_v4();

    let encrypted_access = encrypt_secret(&config.oauth.token_encryption_key, "access-token")
        .expect("encrypt access token");
    let encrypted_refresh = encrypt_secret(&config.oauth.token_encryption_key, "refresh-token")
        .expect("encrypt refresh token");

    let token_repo: Arc<dyn UserOAuthTokenRepository> =
        Arc::new(TokenRepo::new(vec![UserOAuthToken {
            id: token_id,
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Microsoft,
            access_token: encrypted_access,
            refresh_token: encrypted_refresh,
            expires_at: now + Duration::hours(1),
            account_email: "revoke@example.com".into(),
            metadata: serde_json::json!({}),
            is_shared: false,
            created_at: now - Duration::hours(1),
            updated_at: now - Duration::minutes(3),
        }]));
    let workspace_repo: Arc<dyn WorkspaceConnectionRepository> =
        Arc::new(WorkspaceConnectionsStub::new(Vec::new()));
    let oauth_service = Arc::new(OAuthAccountService::new(
        token_repo,
        workspace_repo.clone(),
        Arc::new(config.oauth.token_encryption_key.clone()),
        Arc::new(reqwest::Client::new()),
        &config.oauth,
        &config.github_app,
    ));

    let mut state = stub_state(config);
    state.oauth_accounts = oauth_service;
    state.workspace_connection_repo = workspace_repo;

    let response = revoke_connection(
        State(state),
        AuthSession(claims_for(user_id)),
        Path("microsoft".to_string()),
        Query(ConnectionTarget {
            connection_id: Some(token_id),
        }),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("read body");
    let json: Value = serde_json::from_slice(&body).expect("response json");

    assert_eq!(json["success"].as_bool(), Some(true));
    assert_eq!(json["message"].as_str(), Some("Revocation recorded"));
    assert_eq!(
        json["connectionId"].as_str(),
        Some(token_id.to_string().as_str())
    );
}

#[tokio::test]
async fn revoke_connection_requires_connection_id() {
    let config = stub_config();
    let user_id = Uuid::new_v4();

    let response = revoke_connection(
        State(stub_state(config)),
        AuthSession(claims_for(user_id)),
        Path("microsoft".to_string()),
        Query(ConnectionTarget {
            connection_id: None,
        }),
        None,
    )
    .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[async_trait]
impl WorkspaceRepository for MembershipWorkspaceRepo {
    async fn create_workspace(
        &self,
        _name: &str,
        _created_by: Uuid,
        _plan: &str,
    ) -> Result<Workspace, Error> {
        unimplemented!()
    }

    async fn update_workspace_name(
        &self,
        _workspace_id: Uuid,
        _name: &str,
    ) -> Result<Workspace, Error> {
        unimplemented!()
    }

    async fn update_workspace_plan(
        &self,
        _workspace_id: Uuid,
        _plan: &str,
    ) -> Result<Workspace, Error> {
        unimplemented!()
    }

    async fn get_plan(&self, _workspace_id: Uuid) -> Result<PlanTier, Error> {
        Ok(PlanTier::Workspace)
    }

    async fn find_workspace(&self, _workspace_id: Uuid) -> Result<Option<Workspace>, Error> {
        unimplemented!()
    }

    async fn set_stripe_overage_item_id(
        &self,
        _workspace_id: Uuid,
        _subscription_item_id: Option<&str>,
    ) -> Result<(), Error> {
        unimplemented!()
    }

    async fn get_stripe_overage_item_id(
        &self,
        _workspace_id: Uuid,
    ) -> Result<Option<String>, Error> {
        unimplemented!()
    }

    async fn add_member(
        &self,
        _workspace_id: Uuid,
        _user_id: Uuid,
        _role: WorkspaceRole,
    ) -> Result<(), Error> {
        unimplemented!()
    }

    async fn set_member_role(
        &self,
        _workspace_id: Uuid,
        _user_id: Uuid,
        _role: WorkspaceRole,
    ) -> Result<(), Error> {
        unimplemented!()
    }

    async fn remove_member(&self, _workspace_id: Uuid, _user_id: Uuid) -> Result<(), Error> {
        unimplemented!()
    }

    async fn leave_workspace(&self, _workspace_id: Uuid, _user_id: Uuid) -> Result<(), Error> {
        unimplemented!()
    }

    async fn revoke_member(
        &self,
        _workspace_id: Uuid,
        _member_id: Uuid,
        _revoked_by: Uuid,
        _reason: Option<&str>,
    ) -> Result<(), Error> {
        unimplemented!()
    }

    async fn list_members(&self, workspace_id: Uuid) -> Result<Vec<WorkspaceMember>, Error> {
        let members = self
            .memberships
            .iter()
            .filter(|(_, m)| m.workspace.id == workspace_id)
            .map(|(user_id, m)| WorkspaceMember {
                user_id: *user_id,
                workspace_id,
                role: m.role,
                email: m.workspace.name.clone(),
                first_name: m.workspace.name.clone(),
                last_name: "".into(),
                joined_at: m.workspace.created_at,
            })
            .collect();

        Ok(members)
    }

    async fn count_members(&self, workspace_id: Uuid) -> Result<i64, Error> {
        let count = self
            .memberships
            .iter()
            .filter(|(_, membership)| membership.workspace.id == workspace_id)
            .count();
        Ok(count as i64)
    }

    async fn count_pending_workspace_invitations(&self, _workspace_id: Uuid) -> Result<i64, Error> {
        Ok(0)
    }

    async fn is_member(&self, workspace_id: Uuid, user_id: Uuid) -> Result<bool, Error> {
        Ok(self.memberships.iter().any(|(member_id, membership)| {
            *member_id == user_id && membership.workspace.id == workspace_id
        }))
    }

    async fn list_memberships_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<WorkspaceMembershipSummary>, Error> {
        Ok(self.memberships_for(user_id))
    }

    async fn list_user_workspaces(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<WorkspaceMembershipSummary>, Error> {
        Ok(self.memberships_for(user_id))
    }

    async fn create_workspace_invitation(
        &self,
        _workspace_id: Uuid,
        _email: &str,
        _role: WorkspaceRole,
        _token: &str,
        _expires_at: OffsetDateTime,
        _created_by: Uuid,
    ) -> Result<crate::models::workspace::WorkspaceInvitation, Error> {
        unimplemented!()
    }

    async fn list_workspace_invitations(
        &self,
        _workspace_id: Uuid,
    ) -> Result<Vec<crate::models::workspace::WorkspaceInvitation>, Error> {
        unimplemented!()
    }

    async fn revoke_workspace_invitation(&self, _invite_id: Uuid) -> Result<(), Error> {
        unimplemented!()
    }

    async fn find_invitation_by_token(
        &self,
        _token: &str,
    ) -> Result<Option<crate::models::workspace::WorkspaceInvitation>, Error> {
        unimplemented!()
    }

    async fn mark_invitation_accepted(&self, _invite_id: Uuid) -> Result<(), Error> {
        unimplemented!()
    }

    async fn mark_invitation_declined(&self, _invite_id: Uuid) -> Result<(), Error> {
        unimplemented!()
    }

    async fn list_pending_invitations_for_email(
        &self,
        _email: &str,
    ) -> Result<Vec<crate::models::workspace::WorkspaceInvitation>, Error> {
        unimplemented!()
    }

    async fn disable_webhook_signing_for_workspace(
        &self,
        _workspace_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn try_increment_workspace_run_quota(
        &self,
        workspace_id: Uuid,
        period_start: OffsetDateTime,
        max_runs: i64,
    ) -> Result<WorkspaceRunQuotaUpdate, sqlx::Error> {
        let mut usage = self.run_usage.lock().unwrap();
        let key = (workspace_id, period_start.unix_timestamp());
        let entry = usage.entry(key).or_insert((0, 0));
        entry.0 += 1;
        let mut overage_incremented = false;
        if entry.0 > max_runs {
            entry.1 += 1;
            overage_incremented = true;
        }
        Ok(WorkspaceRunQuotaUpdate {
            allowed: entry.0 <= max_runs,
            run_count: entry.0,
            overage_count: entry.1,
            overage_incremented,
        })
    }

    async fn get_workspace_run_quota(
        &self,
        workspace_id: Uuid,
        period_start: OffsetDateTime,
    ) -> Result<WorkspaceRunUsage, sqlx::Error> {
        let usage = self.run_usage.lock().unwrap();
        let key = (workspace_id, period_start.unix_timestamp());
        Ok(usage
            .get(&key)
            .copied()
            .map(|(runs, overage)| WorkspaceRunUsage {
                run_count: runs,
                overage_count: overage,
            })
            .unwrap_or(WorkspaceRunUsage {
                run_count: 0,
                overage_count: 0,
            }))
    }

    async fn release_workspace_run_quota(
        &self,
        workspace_id: Uuid,
        period_start: OffsetDateTime,
        overage_decrement: bool,
    ) -> Result<(), sqlx::Error> {
        let mut usage = self.run_usage.lock().unwrap();
        let key = (workspace_id, period_start.unix_timestamp());
        if let Some(entry) = usage.get_mut(&key) {
            if entry.0 > 0 {
                entry.0 -= 1;
            }
            if overage_decrement && entry.1 > 0 {
                entry.1 -= 1;
            }
            if entry.0 == 0 && entry.1 == 0 {
                usage.remove(&key);
            }
        }
        Ok(())
    }

    async fn upsert_workspace_billing_cycle(
        &self,
        workspace_id: Uuid,
        subscription_id: &str,
        period_start: OffsetDateTime,
        period_end: OffsetDateTime,
    ) -> Result<(), sqlx::Error> {
        self.billing_cycles.lock().unwrap().insert(
            workspace_id,
            WorkspaceBillingCycle {
                workspace_id,
                stripe_subscription_id: subscription_id.to_string(),
                current_period_start: period_start,
                current_period_end: period_end,
                synced_at: OffsetDateTime::now_utc(),
            },
        );
        Ok(())
    }

    async fn clear_workspace_billing_cycle(&self, workspace_id: Uuid) -> Result<(), sqlx::Error> {
        self.billing_cycles.lock().unwrap().remove(&workspace_id);
        Ok(())
    }

    async fn get_workspace_billing_cycle(
        &self,
        workspace_id: Uuid,
    ) -> Result<Option<WorkspaceBillingCycle>, sqlx::Error> {
        Ok(self
            .billing_cycles
            .lock()
            .unwrap()
            .get(&workspace_id)
            .cloned())
    }
}

fn stub_claims() -> Claims {
    Claims {
        id: uuid::Uuid::new_v4().to_string(),
        email: "user@example.com".into(),
        exp: 0,
        first_name: "Test".into(),
        last_name: "User".into(),
        role: Some(UserRole::User),
        plan: None,
        company_name: None,
        iss: String::new(),
        aud: String::new(),
        token_use: TokenUse::Access,
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NotionStatePayload {
    user_id: Uuid,
    workspace_id: Option<Uuid>,
    connection_scope: String,
    nonce: String,
}

fn build_notion_state_token(
    user_id: Uuid,
    workspace_id: Option<Uuid>,
    connection_scope: &str,
) -> String {
    let payload = NotionStatePayload {
        user_id,
        workspace_id,
        connection_scope: connection_scope.to_string(),
        nonce: "test-nonce".into(),
    };
    let bytes = serde_json::to_vec(&payload).expect("serialize notion state");
    URL_SAFE_NO_PAD.encode(bytes)
}

#[tokio::test]
async fn callback_with_mismatched_state_redirects_with_error() {
    let config = stub_config();
    let state = stub_state(config.clone());
    let jar = CookieJar::new().add(build_state_cookie(GOOGLE_STATE_COOKIE, "expected"));
    let query = CallbackQuery {
        code: Some("auth-code".into()),
        state: Some("unexpected".into()),
        error: None,
        error_description: None,
    };

    let response = handle_callback(
        state,
        stub_claims(),
        jar,
        query,
        ConnectedOAuthProvider::Google,
        "google",
        GOOGLE_STATE_COOKIE,
    )
    .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("location header");
    let location = location.to_str().unwrap();
    assert!(location.contains("connected=false"));
    assert!(location.contains("provider=google"));
}

#[test]
fn redirect_error_messages_are_user_friendly() {
    let msg = error_message_for_redirect(&OAuthAccountError::MissingRefreshToken);
    assert!(msg.contains("refresh token"));
}

#[tokio::test]
async fn solo_plan_google_start_redirects_with_upgrade_message() {
    let config = stub_config();
    let state = stub_state(config.clone());
    let claims = Claims {
        plan: Some("solo".into()),
        ..stub_claims()
    };

    let response = google_connect_start(
        State(state),
        AuthSession(claims),
        Query(ConnectQuery::default()),
        CookieJar::new(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("location header present");
    let location = location.to_str().unwrap();
    assert!(location.contains("connected=false"));
    assert!(location.contains("provider=google"));
}

#[tokio::test]
async fn workspace_plan_google_start_sets_state_cookie() {
    let config = stub_config();
    let state = stub_state(config.clone());
    let claims = Claims {
        plan: Some("workspace".into()),
        ..stub_claims()
    };

    let response = google_connect_start(
        State(state),
        AuthSession(claims),
        Query(ConnectQuery::default()),
        CookieJar::new(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect::<Vec<_>>();
    assert!(cookies
        .iter()
        .any(|cookie| cookie.contains(GOOGLE_STATE_COOKIE)));
}

#[tokio::test]
async fn workspace_plan_github_start_sets_state_cookie() {
    let config = stub_config();
    let state = stub_state(config.clone());
    let expected_scope = state.oauth_accounts.github_scopes().to_string();
    let claims = Claims {
        plan: Some("workspace".into()),
        ..stub_claims()
    };

    let response = github_connect_start(
        State(state),
        AuthSession(claims),
        Query(ConnectQuery::default()),
        CookieJar::new(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect::<Vec<_>>();
    assert!(cookies
        .iter()
        .any(|cookie| cookie.contains(GITHUB_STATE_COOKIE)));

    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("location header present")
        .to_str()
        .unwrap();
    let url = Url::parse(location).expect("github redirect url");
    assert!(url.as_str().starts_with(GITHUB_AUTH_URL));
    let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
    assert_eq!(params.get("client_id").map(String::as_str), Some("client"));
    assert_eq!(
        params.get("redirect_uri").map(String::as_str),
        Some("http://localhost/github")
    );
    assert_eq!(
        params.get("response_type").map(String::as_str),
        Some("code")
    );
    assert_eq!(
        params.get("scope").map(String::as_str),
        Some(expected_scope.as_str())
    );
    assert!(params.contains_key("state"));
}

#[tokio::test]
async fn slack_start_without_workspace_redirects_with_workspace_required_message() {
    let config = stub_config();
    let state = stub_state(config.clone());
    let claims = Claims {
        plan: Some("workspace".into()),
        ..stub_claims()
    };

    let response = slack_connect_start(
        State(state),
        AuthSession(claims),
        Query(ConnectQuery::default()),
        CookieJar::new(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("location header present")
        .to_str()
        .unwrap();
    assert!(location.contains("connected=false"));
    assert!(location.contains("provider=slack"));
    let expected = encode(SLACK_WORKSPACE_REQUIRED_MESSAGE);
    assert!(location.contains(expected.as_ref()));
}

#[tokio::test]
async fn solo_plan_slack_start_redirects_with_upgrade_message() {
    let config = stub_config();
    let workspace_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let membership = workspace_membership(workspace_id, WorkspaceRole::Admin, WORKSPACE_PLAN_SOLO);
    let state = stub_state_with_workspace_repo(
        config.clone(),
        Arc::new(MembershipWorkspaceRepo::new(vec![(user_id, membership)])),
    );
    let claims = Claims {
        id: user_id.to_string(),
        plan: Some("solo".into()),
        ..stub_claims()
    };

    let response = slack_connect_start(
        State(state),
        AuthSession(claims),
        Query(ConnectQuery {
            workspace: Some(workspace_id),
            workspace_connection_id: None,
            connection_scope: None,
        }),
        CookieJar::new(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("location header present")
        .to_str()
        .unwrap();
    assert!(location.contains("connected=false"));
    assert!(location.contains("provider=slack"));
    assert!(location.contains(&format!("workspace={workspace_id}")));
    let expected = encode(OAUTH_PLAN_RESTRICTION_MESSAGE);
    assert!(location.contains(expected.as_ref()));
}

#[tokio::test]
async fn workspace_plan_slack_start_sets_state_cookie() {
    let config = stub_config();
    let workspace_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let membership = workspace_membership(workspace_id, WorkspaceRole::Admin, "workspace");
    let state = stub_state_with_workspace_repo(
        config.clone(),
        Arc::new(MembershipWorkspaceRepo::new(vec![(user_id, membership)])),
    );
    let claims = Claims {
        id: user_id.to_string(),
        plan: Some("workspace".into()),
        ..stub_claims()
    };

    let response = slack_connect_start(
        State(state),
        AuthSession(claims),
        Query(ConnectQuery {
            workspace: Some(workspace_id),
            workspace_connection_id: None,
            connection_scope: None,
        }),
        CookieJar::new(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect::<Vec<_>>();
    let workspace_id_str = workspace_id.to_string();
    assert!(cookies.iter().any(|cookie| {
        cookie.contains(SLACK_STATE_COOKIE) && cookie.contains(&workspace_id_str)
    }));
}

#[tokio::test]
async fn workspace_plan_notion_start_sets_state_cookie_and_owner_user() {
    let config = stub_config();
    let state = stub_state(config.clone());
    let claims = Claims {
        plan: Some("workspace".into()),
        ..stub_claims()
    };

    let response = notion_connect_start(
        State(state),
        AuthSession(claims),
        Query(ConnectQuery::default()),
        CookieJar::new(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect::<Vec<_>>();
    assert!(cookies
        .iter()
        .any(|cookie| cookie.contains(NOTION_STATE_COOKIE)));

    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("location header present")
        .to_str()
        .unwrap();
    let url = Url::parse(location).expect("notion redirect url");
    let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
    assert_eq!(params.get("owner").map(String::as_str), Some("user"));
    assert_eq!(params.get("client_id").map(String::as_str), Some("client"));
    assert_eq!(
        params.get("redirect_uri").map(String::as_str),
        Some("http://localhost/notion")
    );
    assert_eq!(
        params.get("response_type").map(String::as_str),
        Some("code")
    );
}

#[tokio::test]
async fn workspace_plan_notion_start_with_workspace_scope_encodes_state() {
    let config = stub_config();
    let workspace_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let membership = workspace_membership(workspace_id, WorkspaceRole::Admin, "workspace");
    let state = stub_state_with_workspace_repo(
        config.clone(),
        Arc::new(MembershipWorkspaceRepo::new(vec![(user_id, membership)])),
    );
    let claims = Claims {
        id: user_id.to_string(),
        plan: Some("workspace".into()),
        ..stub_claims()
    };

    let response = notion_connect_start(
        State(state),
        AuthSession(claims),
        Query(ConnectQuery {
            workspace: Some(workspace_id),
            workspace_connection_id: None,
            connection_scope: Some("workspace".into()),
        }),
        CookieJar::new(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("location header present")
        .to_str()
        .unwrap();
    let url = Url::parse(location).expect("notion redirect url");
    let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
    assert_eq!(params.get("owner").map(String::as_str), Some("workspace"));
    let state_param = params.get("state").expect("state param");
    let decoded = URL_SAFE_NO_PAD
        .decode(state_param.as_bytes())
        .expect("decode state");
    let payload: Value = serde_json::from_slice(&decoded).expect("state json");
    assert_eq!(
        payload["workspaceId"].as_str(),
        Some(workspace_id.to_string().as_str())
    );
    assert_eq!(payload["connectionScope"].as_str(), Some("workspace"));
}

#[tokio::test]
async fn github_callback_saves_personal_token() {
    let config = stub_config();
    let user_id = Uuid::new_v4();

    let (addr, _handle) = spawn_github_stub_server().await;

    let token_repo = Arc::new(RecordingTokenRepo::default());
    let workspace_connections = Arc::new(RecordingWorkspaceConnectionRepo::default());
    let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());

    let mut oauth_service = OAuthAccountService::new(
        token_repo.clone(),
        workspace_connections.clone(),
        encryption_key.clone(),
        Arc::new(reqwest::Client::new()),
        &config.oauth,
        &config.github_app,
    );
    oauth_service.set_github_endpoint_overrides(
        format!("http://{}/login/oauth/access_token", addr),
        format!("http://{}/user", addr),
        format!("http://{}/user/emails", addr),
    );
    let oauth_service = Arc::new(oauth_service);

    let mut state = stub_state(config.clone());
    state.oauth_accounts = oauth_service;

    let claims = Claims {
        id: user_id.to_string(),
        plan: Some("workspace".into()),
        ..stub_claims()
    };

    let state_token = "github-state-token";
    let jar = CookieJar::new().add(build_state_cookie(GITHUB_STATE_COOKIE, state_token));
    let response = github_connect_callback(
        State(state),
        AuthSession(claims),
        jar,
        Query(CallbackQuery {
            code: Some("auth-code".into()),
            state: Some(state_token.to_string()),
            error: None,
            error_description: None,
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("location header present")
        .to_str()
        .unwrap();
    assert!(location.contains("connected=true"));
    assert!(location.contains("provider=github"));

    let saved = token_repo.saved_token().expect("token saved");
    assert_eq!(saved.provider, ConnectedOAuthProvider::GitHub);
    assert_eq!(saved.user_id, user_id);
    assert_eq!(saved.workspace_id, None);
    assert_eq!(saved.account_email, "octocat");

    let connections = workspace_connections.connections();
    assert!(
        connections.is_empty(),
        "OAuth callback must not auto-promote to workspace"
    );
}

#[tokio::test]
async fn notion_callback_saves_personal_token() {
    let config = stub_config();
    let user_id = Uuid::new_v4();

    let (addr, _handle) = spawn_notion_stub_server(NOTION_TOKEN_RESPONSE).await;

    let token_repo = Arc::new(RecordingTokenRepo::default());
    let workspace_connections = Arc::new(RecordingWorkspaceConnectionRepo::default());
    let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());

    let mut oauth_service = OAuthAccountService::new(
        token_repo.clone(),
        workspace_connections,
        encryption_key.clone(),
        Arc::new(reqwest::Client::new()),
        &config.oauth,
        &config.github_app,
    );
    oauth_service.set_notion_endpoint_override(format!("http://{}/oauth/token", addr));
    let oauth_service = Arc::new(oauth_service);

    let mut state = stub_state(config.clone());
    state.oauth_accounts = oauth_service;

    let claims = Claims {
        id: user_id.to_string(),
        plan: Some("workspace".into()),
        ..stub_claims()
    };

    let state_token = build_notion_state_token(user_id, None, "personal");
    let jar = CookieJar::new().add(build_state_cookie(NOTION_STATE_COOKIE, &state_token));
    let response = notion_connect_callback(
        State(state),
        AuthSession(claims),
        jar,
        Query(CallbackQuery {
            code: Some("auth-code".into()),
            state: Some(state_token),
            error: None,
            error_description: None,
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("location header present")
        .to_str()
        .unwrap();
    assert!(location.contains("connected=true"));
    assert!(location.contains("provider=notion"));

    let saved = token_repo.saved_token().expect("token saved");
    assert_eq!(saved.provider, ConnectedOAuthProvider::Notion);
    assert_eq!(saved.account_email, "Acme Workspace");
    let metadata = parse_token_metadata(&saved.metadata);
    let notion_meta = metadata.notion.expect("notion metadata");
    assert_eq!(notion_meta.workspace_id.as_deref(), Some("ws-123"));
    assert_eq!(
        notion_meta.workspace_name.as_deref(),
        Some("Acme Workspace")
    );
    assert_eq!(notion_meta.bot_id.as_deref(), Some("bot-123"));
    assert_eq!(notion_meta.owner_type.as_deref(), Some("workspace"));
    assert_eq!(notion_meta.owner_id.as_deref(), Some("ws-123"));
    assert_eq!(notion_meta.owner_name.as_deref(), Some("Acme Workspace"));
}

#[tokio::test]
async fn notion_callback_handles_missing_fields() {
    let config = stub_config();
    let user_id = Uuid::new_v4();

    let (addr, _handle) = spawn_notion_stub_server(NOTION_TOKEN_RESPONSE_MINIMAL).await;

    let token_repo = Arc::new(RecordingTokenRepo::default());
    let workspace_connections = Arc::new(RecordingWorkspaceConnectionRepo::default());
    let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());

    let mut oauth_service = OAuthAccountService::new(
        token_repo.clone(),
        workspace_connections,
        encryption_key.clone(),
        Arc::new(reqwest::Client::new()),
        &config.oauth,
        &config.github_app,
    );
    oauth_service.set_notion_endpoint_override(format!("http://{}/oauth/token", addr));
    let oauth_service = Arc::new(oauth_service);

    let mut state = stub_state(config.clone());
    state.oauth_accounts = oauth_service;

    let claims = Claims {
        id: user_id.to_string(),
        plan: Some("workspace".into()),
        ..stub_claims()
    };

    let state_token = build_notion_state_token(user_id, None, "personal");
    let jar = CookieJar::new().add(build_state_cookie(NOTION_STATE_COOKIE, &state_token));
    let response = notion_connect_callback(
        State(state),
        AuthSession(claims),
        jar,
        Query(CallbackQuery {
            code: Some("auth-code".into()),
            state: Some(state_token),
            error: None,
            error_description: None,
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let saved = token_repo.saved_token().expect("token saved");
    assert_eq!(saved.provider, ConnectedOAuthProvider::Notion);
    assert_eq!(saved.account_email, "Notion Workspace");
    let metadata = parse_token_metadata(&saved.metadata);
    assert!(metadata.notion.is_none());
}

#[tokio::test]
async fn notion_callback_creates_personal_token_only() {
    let config = stub_config();
    let user_id = Uuid::new_v4();
    let workspace_id = Uuid::new_v4();
    let membership = workspace_membership(workspace_id, WorkspaceRole::Admin, "workspace");
    let workspace_repo: Arc<dyn WorkspaceRepository> =
        Arc::new(MembershipWorkspaceRepo::new(vec![(user_id, membership)]));

    let (addr, _handle) = spawn_notion_stub_server(NOTION_TOKEN_RESPONSE).await;

    let token_repo = Arc::new(RecordingTokenRepo::default());
    let workspace_connections = Arc::new(RecordingWorkspaceConnectionRepo::default());
    let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());

    let mut oauth_service = OAuthAccountService::new(
        token_repo.clone(),
        workspace_connections.clone(),
        encryption_key.clone(),
        Arc::new(reqwest::Client::new()),
        &config.oauth,
        &config.github_app,
    );
    oauth_service.set_notion_endpoint_override(format!("http://{}/oauth/token", addr));
    let oauth_service = Arc::new(oauth_service);
    let oauth_refresher: Arc<dyn WorkspaceTokenRefresher> = oauth_service.clone();

    let workspace_oauth = Arc::new(WorkspaceOAuthService::new(
        token_repo.clone(),
        workspace_repo.clone(),
        workspace_connections.clone(),
        oauth_refresher,
        encryption_key.clone(),
    ));

    let mut state = stub_state_with_workspace_repo(config.clone(), workspace_repo);
    state.oauth_accounts = oauth_service;
    state.workspace_oauth = workspace_oauth;
    state.workspace_connection_repo = workspace_connections.clone();

    let claims = Claims {
        id: user_id.to_string(),
        plan: Some("workspace".into()),
        ..stub_claims()
    };

    let state_token = build_notion_state_token(user_id, None, "personal");
    let jar = CookieJar::new().add(build_state_cookie(NOTION_STATE_COOKIE, &state_token));
    let response = notion_connect_callback(
        State(state),
        AuthSession(claims),
        jar,
        Query(CallbackQuery {
            code: Some("auth-code".into()),
            state: Some(state_token),
            error: None,
            error_description: None,
        }),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("location header present")
        .to_str()
        .unwrap();
    assert!(location.contains("connected=true"), "location: {location}");
    assert!(location.contains("provider=notion"));
    assert!(location.contains("connected=true"));
    assert!(location.contains("provider=notion"));

    let saved = token_repo.saved_token().expect("token saved");

    // Assert personal token properties
    assert_eq!(saved.provider, ConnectedOAuthProvider::Notion);
    assert_eq!(saved.user_id, user_id);
    assert_eq!(saved.workspace_id, None); // critical invariant

    // Assert NO workspace connections created
    let connections = workspace_connections.connections();
    assert!(
        connections.is_empty(),
        "OAuth callback must not auto-promote to workspace"
    );
}

#[tokio::test]
async fn slack_callback_persists_team_id_from_auth_test() {
    let config = stub_config();
    let workspace_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    let membership = workspace_membership(workspace_id, WorkspaceRole::Admin, "workspace");
    let workspace_repo: Arc<dyn WorkspaceRepository> =
        Arc::new(MembershipWorkspaceRepo::new(vec![(user_id, membership)]));

    let (addr, handle) = spawn_slack_stub_server().await;
    let _env = EnvGuard::set("SLACK_API_BASE_URL", format!("http://{}/api", addr));

    let token_repo = Arc::new(RecordingTokenRepo::default());
    let workspace_connections = Arc::new(RecordingWorkspaceConnectionRepo::default());
    let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());

    let mut oauth_service = OAuthAccountService::new(
        token_repo.clone(),
        workspace_connections.clone(),
        encryption_key.clone(),
        Arc::new(reqwest::Client::new()),
        &config.oauth,
        &config.github_app,
    );
    oauth_service.set_slack_endpoint_overrides(
        format!("http://{}/api/oauth.v2.access", addr),
        format!("http://{}/api/users.info", addr),
    );
    let oauth_service = Arc::new(oauth_service);

    let oauth_refresher: Arc<dyn WorkspaceTokenRefresher> = oauth_service.clone();
    let workspace_oauth = Arc::new(WorkspaceOAuthService::new(
        token_repo.clone(),
        workspace_repo.clone(),
        workspace_connections.clone(),
        oauth_refresher,
        encryption_key.clone(),
    ));

    let mut state = stub_state_with_workspace_repo(config.clone(), workspace_repo);
    state.oauth_accounts = oauth_service;
    state.workspace_oauth = workspace_oauth;
    state.workspace_connection_repo = workspace_connections;

    let state_token = build_slack_state(workspace_id);
    let jar = CookieJar::new().add(build_state_cookie(SLACK_STATE_COOKIE, &state_token));
    let query = CallbackQuery {
        code: Some("auth-code".into()),
        state: Some(state_token),
        error: None,
        error_description: None,
    };

    let response = slack_connect_callback(
        State(state),
        AuthSession(claims_for(user_id)),
        jar,
        Query(query),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);

    let saved = token_repo.saved_token().expect("personal token saved");
    let metadata = parse_token_metadata(&saved.metadata);
    let encrypted_team_id = metadata
        .slack
        .and_then(|slack| slack.team_id)
        .expect("slack team id persisted");
    let team_id =
        decrypt_secret(&config.oauth.token_encryption_key, &encrypted_team_id).expect("team id");
    assert_eq!(team_id, "T123");

    handle.abort();
}

#[tokio::test]
async fn joined_workspace_member_with_solo_claims_can_connect() {
    let config = stub_config();
    let workspace_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let membership = workspace_membership(workspace_id, WorkspaceRole::Admin, "workspace");
    let state = stub_state_with_workspace_repo(
        config.clone(),
        Arc::new(MembershipWorkspaceRepo::new(vec![(user_id, membership)])),
    );
    let claims = Claims {
        id: user_id.to_string(),
        plan: Some("solo".into()),
        ..stub_claims()
    };

    let response = google_connect_start(
        State(state),
        AuthSession(claims),
        Query(ConnectQuery {
            workspace: Some(workspace_id),
            workspace_connection_id: None,
            connection_scope: None,
        }),
        CookieJar::new(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("location header present")
        .to_str()
        .unwrap();
    assert!(location.contains("accounts.google.com"));
}

#[tokio::test]
async fn workspace_viewer_is_blocked_from_connecting() {
    let config = stub_config();
    let workspace_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let membership = workspace_membership(workspace_id, WorkspaceRole::Viewer, "workspace");
    let state = stub_state_with_workspace_repo(
        config.clone(),
        Arc::new(MembershipWorkspaceRepo::new(vec![(user_id, membership)])),
    );
    let claims = Claims {
        id: user_id.to_string(),
        plan: Some("workspace".into()),
        ..stub_claims()
    };

    let response = google_connect_start(
        State(state),
        AuthSession(claims),
        Query(ConnectQuery {
            workspace: Some(workspace_id),
            workspace_connection_id: None,
            connection_scope: None,
        }),
        CookieJar::new(),
    )
    .await;

    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let location = response
        .headers()
        .get(header::LOCATION)
        .expect("location header present")
        .to_str()
        .unwrap();
    assert!(location.contains("connected=false"));
    let expected = encode("Workspace viewers cannot connect OAuth accounts for this workspace.");
    assert!(location.contains(expected.as_ref()));
}
