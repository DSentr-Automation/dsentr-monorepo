use axum::{
    extract::{Query, State},
    http::StatusCode as AxumStatusCode,
    response::{IntoResponse, Response},
    Json,
};
use reqwest::StatusCode as ReqStatusCode;
use serde::{Deserialize, Serialize};
use tracing::error;
use uuid::Uuid;

use crate::engine::actions::{ensure_run_membership, ensure_workspace_plan};
use crate::models::oauth_token::ConnectedOAuthProvider;
use crate::responses::JsonResponse;
use crate::routes::auth::claims::Claims;
use crate::routes::auth::session::AuthSession;
use crate::routes::oauth::map_oauth_error;
use crate::services::oauth::workspace_service::WorkspaceOAuthError;
use crate::state::AppState;
use crate::utils::encryption::decrypt_secret;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ConnectionQuery {
    workspace_connection_id: Option<Uuid>,
    personal_connection_id: Option<Uuid>,
    #[cfg(test)]
    base_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SlackChannelPayload {
    id: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    is_private: Option<bool>,
}

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
enum SlackIdentityType {
    WorkspaceBot,
    PersonalUser,
}

impl Serialize for SlackIdentityType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = match self {
            SlackIdentityType::WorkspaceBot => "workspace_bot",
            SlackIdentityType::PersonalUser => "personal_user",
        };
        serializer.serialize_str(s)
    }
}

impl<'de> Deserialize<'de> for SlackIdentityType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "workspace_bot" => Ok(SlackIdentityType::WorkspaceBot),
            "personal_user" => Ok(SlackIdentityType::PersonalUser),
            other => Err(serde::de::Error::custom(format!(
                "invalid SlackIdentityType: {}",
                other
            ))),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SlackChannelsResponse {
    success: bool,
    channels: Vec<SlackChannelPayload>,
    identity_type: SlackIdentityType,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SlackAuthExpiredResponse {
    success: bool,
    message: String,
    #[serde(rename = "type")]
    error_type: String,
    connection_id: Uuid,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct SlackChannelsApiResponse {
    ok: bool,
    channels: Option<Vec<SlackChannelRecord>>,
    error: Option<String>,
    needed: Option<String>,
    provided: Option<String>,
    response_metadata: Option<SlackResponseMetadata>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct SlackResponseMetadata {
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct SlackChannelRecord {
    id: Option<String>,
    name: Option<String>,
    is_private: Option<bool>,
    is_archived: Option<bool>,
}

#[derive(Debug)]
enum SlackChannelError {
    TokenExpired,
    Unauthorized,
    MissingScopes {
        needed: Option<String>,
        provided: Option<String>,
    },
    ServerError(String),
}

pub async fn list_channels(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    Query(query): Query<ConnectionQuery>,
) -> Response {
    let user_id = match parse_user_id(&claims) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let workspace_conn = query.workspace_connection_id;
    let personal_conn = query.personal_connection_id;

    if personal_conn.is_some() {
        return JsonResponse::bad_request(
            "Slack channel listing requires an explicit workspace_connection_id",
        )
        .into_response();
    }

    let connection_id = match workspace_conn {
        Some(id) => id,
        None => {
            return JsonResponse::bad_request(
                "workspace_connection_id is required to load Slack channels",
            )
            .into_response();
        }
    };

    let (access_token, workspace_id) =
        match ensure_workspace_token(&state, user_id, connection_id).await {
            Ok((token, workspace_id)) => (token, Some(workspace_id)),
            Err(resp) => return resp,
        };
    let identity_type = SlackIdentityType::WorkspaceBot;

    if let Some(workspace_id) = workspace_id {
        if let Err(msg) = ensure_workspace_plan(&state, workspace_id).await {
            return JsonResponse::forbidden(&msg).into_response();
        }

        if let Err(msg) = ensure_run_membership(&state, workspace_id, user_id).await {
            return JsonResponse::forbidden(&msg).into_response();
        };
    }

    #[cfg(test)]
    let base_override = query.base_url.as_deref();
    #[cfg(not(test))]
    let base_override: Option<&str> = None;

    let channels = match fetch_slack_channels(&state, &access_token, base_override).await {
        Ok(channels) => channels,
        Err(SlackChannelError::TokenExpired) => {
            match state
                .workspace_oauth
                .refresh_slack_workspace_token(connection_id)
                .await
            {
                Ok(refreshed) => {
                    match fetch_slack_channels(&state, &refreshed.access_token, base_override).await
                    {
                        Ok(channels) => channels,
                        Err(SlackChannelError::TokenExpired) => {
                            return slack_auth_expired(connection_id)
                        }
                        Err(err) => return map_slack_channel_error(err),
                    }
                }
                Err(_) => return slack_auth_expired(connection_id),
            }
        }
        Err(err) => return map_slack_channel_error(err),
    };

    Json(SlackChannelsResponse {
        success: true,
        channels,
        identity_type,
    })
    .into_response()
}

#[allow(clippy::result_large_err)]
fn parse_user_id(claims: &Claims) -> Result<Uuid, Response> {
    Uuid::parse_str(&claims.id)
        .map_err(|_| JsonResponse::unauthorized("Invalid user identifier").into_response())
}

// Identity selection flows directly from `workspace_connection_id` or `personal_connection_id`.

async fn ensure_workspace_token(
    state: &AppState,
    user_id: Uuid,
    connection_id: Uuid,
) -> Result<(String, Uuid), Response> {
    let connections = state
        .workspace_connection_repo
        .list_for_user_memberships(user_id)
        .await
        .map_err(|err| {
            error!(?err, "Failed to load workspace OAuth connections");
            JsonResponse::server_error("Failed to load workspace connection").into_response()
        })?;

    let listing = connections
        .into_iter()
        .find(|connection| {
            connection.id == connection_id && connection.provider == ConnectedOAuthProvider::Slack
        })
        .ok_or_else(|| {
            JsonResponse::not_found("Selected workspace Slack connection is no longer available")
                .into_response()
        })?;

    let workspace_id = listing.workspace_id;
    // Check the raw workspace connection record for webhook-only (incoming webhook present but no personal token)
    match state.workspace_connection_repo.find_by_id(listing.id).await {
        Ok(Some(db_conn)) => {
            let has_incoming = db_conn.incoming_webhook_url.is_some();
            let no_oauth_token = db_conn.user_oauth_token_id.is_none()
                || decrypt_secret(
                    &state.config.oauth.token_encryption_key,
                    &db_conn.access_token,
                )
                .ok()
                .map(|s| s.trim().is_empty())
                .unwrap_or(false);

            if has_incoming && no_oauth_token {
                return Err(JsonResponse::bad_request(
                    "Selected workspace Slack connection only provides an incoming webhook; a workspace OAuth token is required",
                )
                .into_response());
            }
        }
        Ok(None) => {
            return Err(JsonResponse::not_found(
                "Selected workspace Slack connection is no longer available",
            )
            .into_response());
        }
        Err(err) => {
            error!(?err, "Failed to load workspace connection");
            return Err(
                JsonResponse::server_error("Failed to load workspace connection").into_response(),
            );
        }
    }

    state
        .workspace_oauth
        .ensure_valid_workspace_token(listing.id)
        .await
        .map_err(map_workspace_oauth_error)
        .and_then(|connection| {
            if connection.workspace_id != workspace_id {
                return Err(JsonResponse::not_found(
                    "Selected workspace Slack connection is no longer available",
                )
                .into_response());
            }

            Ok((connection.access_token, workspace_id))
        })
}

async fn fetch_slack_channels(
    state: &AppState,
    access_token: &str,
    base_override: Option<&str>,
) -> Result<Vec<SlackChannelPayload>, SlackChannelError> {
    let mut collected: Vec<SlackChannelPayload> = Vec::new();
    let mut cursor: Option<String> = None;

    let base = base_override
        .map(|value| value.to_string())
        .or_else(|| std::env::var("SLACK_API_BASE_URL").ok())
        .or_else(|| std::env::var("SLACK_API_BASE").ok())
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| "https://slack.com/api".to_string());
    let list_url = format!("{}/conversations.list", base.trim_end_matches('/'));

    loop {
        let mut request = state
            .http_client
            .get(&list_url)
            .bearer_auth(access_token)
            .query(&[
                ("types", "public_channel,private_channel,im,mpim"),
                ("limit", "200"),
            ]);

        if let Some(token) = cursor.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
            request = request.query(&[("cursor", token)]);
        }

        let response = request.send().await.map_err(|err| {
            error!(?err, "Failed to call Slack");
            SlackChannelError::ServerError("Failed to contact Slack".to_string())
        })?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        if !status.is_success() {
            error!(%status, body, "Slack request failed");
            return Err(
                if status == ReqStatusCode::UNAUTHORIZED || status == ReqStatusCode::FORBIDDEN {
                    SlackChannelError::Unauthorized
                } else {
                    SlackChannelError::ServerError("Failed to load Slack channels".to_string())
                },
            );
        }

        let parsed: SlackChannelsApiResponse = serde_json::from_str(&body).map_err(|err| {
            error!(?err, body, "Failed to parse Slack response");
            SlackChannelError::ServerError("Received an unexpected response from Slack".to_string())
        })?;

        if !parsed.ok {
            let message = parsed
                .error
                .as_deref()
                .unwrap_or("Slack responded with an error");
            return Err(match message {
                "token_expired" => SlackChannelError::TokenExpired,
                "invalid_auth" | "not_authed" | "token_revoked" | "account_inactive" => {
                    SlackChannelError::Unauthorized
                }
                "missing_scope" => SlackChannelError::MissingScopes {
                    needed: parsed.needed,
                    provided: parsed.provided,
                },
                other => SlackChannelError::ServerError(other.to_string()),
            });
        }

        if let Some(channels) = parsed.channels {
            collected.extend(channels.into_iter().filter_map(|record| {
                let id = record
                    .id
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty());
                let name = record
                    .name
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty());
                if id.is_none() || name.is_none() {
                    return None;
                }
                if record.is_archived.unwrap_or(false) {
                    return None;
                }

                Some(SlackChannelPayload {
                    id: id.unwrap().to_string(),
                    name: name.unwrap().to_string(),
                    is_private: record.is_private,
                })
            }));
        }

        cursor = parsed
            .response_metadata
            .and_then(|meta| meta.next_cursor)
            .and_then(|cursor| {
                let trimmed = cursor.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            });

        if cursor.is_none() {
            break;
        }
    }

    collected.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    collected.dedup_by(|a, b| a.id == b.id);

    Ok(collected)
}

fn slack_auth_expired(connection_id: Uuid) -> Response {
    (
        AxumStatusCode::UNAUTHORIZED,
        Json(SlackAuthExpiredResponse {
            success: false,
            message: "Slack authorization expired. Reconnect in Settings.".to_string(),
            error_type: "auth_expired".to_string(),
            connection_id,
        }),
    )
        .into_response()
}

fn map_slack_channel_error(err: SlackChannelError) -> Response {
    match err {
        SlackChannelError::TokenExpired => {
            JsonResponse::server_error("Slack token expired").into_response()
        }
        SlackChannelError::Unauthorized => JsonResponse::unauthorized(
            "The Slack connection no longer has permission. Reconnect in Settings.",
        )
        .into_response(),
        SlackChannelError::MissingScopes { needed, provided } => {
            error!(
                ?needed,
                ?provided,
                "Slack connection missing required scopes"
            );
            JsonResponse::unauthorized(
                "Slack connection is missing required scopes. Reinstall Slack to continue.",
            )
            .into_response()
        }
        SlackChannelError::ServerError(message) => {
            JsonResponse::server_error(&message).into_response()
        }
    }
}

fn map_workspace_oauth_error(err: WorkspaceOAuthError) -> Response {
    match err {
        WorkspaceOAuthError::Forbidden => {
            JsonResponse::forbidden("Not authorized to use this workspace connection")
                .into_response()
        }
        WorkspaceOAuthError::NotFound => {
            JsonResponse::not_found("Selected workspace Slack connection is no longer available")
                .into_response()
        }
        WorkspaceOAuthError::SlackInstallRequired => {
            JsonResponse::bad_request("Slack connections must be installed at workspace scope")
                .into_response()
        }
        WorkspaceOAuthError::Database(error) => {
            error!(?error, "Workspace connection database error");
            JsonResponse::server_error("Failed to load workspace connection").into_response()
        }
        WorkspaceOAuthError::Encryption(error) => {
            error!(?error, "Workspace connection decryption error");
            JsonResponse::server_error("Failed to load workspace connection").into_response()
        }
        WorkspaceOAuthError::OAuth(error) => map_oauth_error(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::http::StatusCode as AxumStatusCode;
    use httpmock::MockServer;
    use std::sync::Arc;
    use time::{Duration, OffsetDateTime};

    use crate::config::{
        Config, OAuthProviderConfig, OAuthSettings, StripeSettings, DEFAULT_WORKSPACE_MEMBER_LIMIT,
        DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT, RUNAWAY_LIMIT_5MIN,
    };
    use crate::db::mock_db::{MockDb, NoopWorkflowRepository, StaticWorkspaceMembershipRepository};
    use crate::db::mock_stripe_event_log_repository::MockStripeEventLogRepository;
    use crate::db::oauth_token_repository::{NewUserOAuthToken, UserOAuthTokenRepository};
    use crate::db::workspace_connection_repository::{
        NewWorkspaceAuditEvent, NewWorkspaceConnection, StaleWorkspaceConnection,
        WorkspaceConnectionListing, WorkspaceConnectionRepository,
    };
    use crate::models::oauth_token::{
        ConnectedOAuthProvider, UserOAuthToken, WorkspaceAuditEvent, WorkspaceConnection,
    };
    use crate::services::oauth::workspace_service::{
        WorkspaceOAuthService, WorkspaceTokenRefresher,
    };
    use crate::services::smtp_mailer::MockMailer;
    use crate::state::AppState;
    use crate::utils::encryption::encrypt_secret;
    use crate::utils::jwt::JwtKeys;

    #[derive(Clone)]
    struct PersonalTokenRepo {
        token: Option<UserOAuthToken>,
    }

    impl PersonalTokenRepo {
        fn new(token: Option<UserOAuthToken>) -> Self {
            Self { token }
        }
    }

    #[async_trait]
    impl UserOAuthTokenRepository for PersonalTokenRepo {
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
            if provider != ConnectedOAuthProvider::Slack {
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

        async fn list_tokens_for_user(
            &self,
            _user_id: Uuid,
        ) -> Result<Vec<UserOAuthToken>, sqlx::Error> {
            Ok(self
                .token
                .clone()
                .filter(|token| token.user_id == _user_id)
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

        async fn list_by_user_and_provider(
            &self,
            user_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<Vec<UserOAuthToken>, sqlx::Error> {
            if provider != ConnectedOAuthProvider::Slack {
                return Ok(vec![]);
            }

            Ok(self
                .token
                .clone()
                .filter(|token| token.user_id == user_id)
                .into_iter()
                .collect())
        }
    }

    #[derive(Clone)]
    struct WorkspaceConnectionRepo {
        listing: WorkspaceConnection,
    }

    #[async_trait]
    impl WorkspaceConnectionRepository for WorkspaceConnectionRepo {
        async fn insert_connection(
            &self,
            _new_connection: NewWorkspaceConnection,
        ) -> Result<WorkspaceConnection, sqlx::Error> {
            Err(sqlx::Error::RowNotFound)
        }

        async fn find_by_id(
            &self,
            connection_id: Uuid,
        ) -> Result<Option<WorkspaceConnection>, sqlx::Error> {
            Ok((connection_id == self.listing.id).then_some(self.listing.clone()))
        }

        async fn get_by_id(&self, connection_id: Uuid) -> Result<WorkspaceConnection, sqlx::Error> {
            self.find_by_id(connection_id)
                .await?
                .ok_or(sqlx::Error::RowNotFound)
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
            user_oauth_token_id: Uuid,
        ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
            if self.listing.user_oauth_token_id == Some(user_oauth_token_id) {
                return Ok(vec![self.listing.clone()]);
            }
            Ok(Vec::new())
        }

        async fn list_by_workspace_and_provider(
            &self,
            _workspace_id: Uuid,
            _provider: ConnectedOAuthProvider,
        ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
            if _workspace_id == self.listing.workspace_id
                && _provider == ConnectedOAuthProvider::Slack
            {
                return Ok(vec![self.listing.clone()]);
            }
            Ok(Vec::new())
        }

        async fn list_for_workspace(
            &self,
            _workspace_id: Uuid,
        ) -> Result<
            Vec<crate::db::workspace_connection_repository::WorkspaceConnectionListing>,
            sqlx::Error,
        > {
            Ok(Vec::new())
        }

        async fn list_for_user_memberships(
            &self,
            _user_id: Uuid,
        ) -> Result<
            Vec<crate::db::workspace_connection_repository::WorkspaceConnectionListing>,
            sqlx::Error,
        > {
            use crate::db::workspace_connection_repository::WorkspaceConnectionListing;
            Ok(vec![WorkspaceConnectionListing {
                id: self.listing.id,
                connection_id: self.listing.connection_id,
                workspace_id: self.listing.workspace_id,
                owner_user_id: self.listing.owner_user_id,
                workspace_name: "Workspace".into(),
                provider: self.listing.provider,
                account_email: self.listing.account_email.clone(),
                expires_at: self.listing.expires_at,
                shared_by_first_name: None,
                shared_by_last_name: None,
                shared_by_email: None,
                updated_at: self.listing.updated_at,
                requires_reconnect: false,
                has_incoming_webhook: self.listing.incoming_webhook_url.is_some(),
            }])
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
            Ok(true)
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
            _event: NewWorkspaceAuditEvent,
        ) -> Result<crate::models::oauth_token::WorkspaceAuditEvent, sqlx::Error> {
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
                token_encryption_key: vec![0u8; 32],
            },
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

    fn test_jwt_keys() -> Arc<JwtKeys> {
        Arc::new(
            JwtKeys::from_secret("0123456789abcdef0123456789abcdef")
                .expect("test JWT secret should be valid"),
        )
    }

    fn test_claims(user_id: Uuid) -> Claims {
        Claims {
            id: user_id.to_string(),
            email: "user@example.com".into(),
            exp: 0,
            first_name: "Test".into(),
            last_name: "User".into(),
            role: None,
            plan: Some("workspace".into()),
            company_name: None,
            iss: "test".into(),
            aud: "test".into(),
            token_use: crate::routes::auth::claims::TokenUse::Access,
        }
    }

    fn base_state(
        config: Arc<Config>,
        workspace_repo: Arc<StaticWorkspaceMembershipRepository>,
        connection_repo: Arc<WorkspaceConnectionRepo>,
        personal_repo: Arc<PersonalTokenRepo>,
    ) -> AppState {
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());
        let user_repo: Arc<dyn UserOAuthTokenRepository> = personal_repo.clone();
        let connection_repo: Arc<dyn WorkspaceConnectionRepository> = connection_repo;
        let workspace_repo_trait: Arc<dyn crate::db::workspace_repository::WorkspaceRepository> =
            workspace_repo.clone();
        let http_client = state_http_client();

        let oauth_accounts = Arc::new(
            crate::services::oauth::account_service::OAuthAccountService::new(
                user_repo.clone(),
                connection_repo.clone(),
                Arc::clone(&encryption_key),
                http_client.clone(),
                &config.oauth,
            ),
        );
        let workspace_token_refresher: Arc<dyn WorkspaceTokenRefresher> =
            oauth_accounts.clone() as Arc<dyn WorkspaceTokenRefresher>;
        let workspace_oauth = Arc::new(WorkspaceOAuthService::new(
            user_repo,
            workspace_repo_trait.clone(),
            connection_repo.clone(),
            workspace_token_refresher,
            encryption_key,
        ));

        AppState {
            db: Arc::new(MockDb::default()),
            workflow_repo: Arc::new(NoopWorkflowRepository),
            workspace_repo: workspace_repo_trait,
            workspace_connection_repo: connection_repo,
            stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
            db_pool: crate::state::test_pg_pool(),
            mailer: Arc::new(MockMailer::default()),
            google_oauth: Arc::new(crate::services::oauth::google::client::GoogleOAuthClient {
                client: reqwest::Client::new(),
            }),
            github_oauth: Arc::new(crate::services::oauth::github::client::GitHubOAuthClient {
                client: reqwest::Client::new(),
            }),
            oauth_accounts,
            workspace_oauth,
            stripe: Arc::new(crate::services::stripe::MockStripeService::new()),
            http_client,
            config,
            worker_id: Arc::new("test-worker".into()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        }
    }

    fn state_http_client() -> Arc<reqwest::Client> {
        Arc::new(reqwest::Client::new())
    }

    #[tokio::test]
    async fn lists_workspace_channels() {
        let server = MockServer::start_async().await;
        let base_url = format!("{}/api", server.base_url());

        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        let config = stub_config();
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());

        let encrypted_access = encrypt_secret(&encryption_key, "workspace-access").unwrap();
        let encrypted_refresh = encrypt_secret(&encryption_key, "workspace-refresh").unwrap();

        server
            .mock_async(|when, then| {
                when.method(httpmock::Method::GET)
                    .path("/api/conversations.list")
                    .header("authorization", "Bearer workspace-access");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(
                        r#"{
                    "ok": true,
                    "channels": [
                      { "id": "C1", "name": "general", "is_private": false },
                      { "id": "C2", "name": "alerts", "is_private": true }
                    ]
                }"#,
                    );
            })
            .await;

        let workspace_repo = Arc::new(StaticWorkspaceMembershipRepository::with_plan(
            crate::models::plan::PlanTier::Workspace,
        ));

        let listing = WorkspaceConnection {
            id: connection_id,
            connection_id: Some(connection_id),
            workspace_id,
            created_by: user_id,
            owner_user_id: user_id,
            user_oauth_token_id: None,
            provider: ConnectedOAuthProvider::Slack,
            access_token: encrypted_access.clone(),
            refresh_token: encrypted_refresh.clone(),
            expires_at: now + Duration::hours(1),
            account_email: "owner@example.com".into(),
            created_at: now,
            updated_at: now,
            metadata: serde_json::Value::Null,
            slack_team_id: Some("T123".into()),
            bot_user_id: None,
            incoming_webhook_url: None,
        };
        let connection_repo = Arc::new(WorkspaceConnectionRepo {
            listing: listing.clone(),
        });

        let personal_repo = Arc::new(PersonalTokenRepo::new(Some(UserOAuthToken {
            id: Uuid::new_v4(),
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Slack,
            access_token: encrypted_access.clone(),
            refresh_token: encrypted_refresh,
            expires_at: now + Duration::hours(1),
            account_email: "owner@example.com".into(),
            metadata: serde_json::json!({}),
            is_shared: false,
            created_at: now,
            updated_at: now,
        })));

        let state = base_state(config, workspace_repo, connection_repo, personal_repo);
        let response = list_channels(
            State(state),
            AuthSession(test_claims(user_id)),
            Query(ConnectionQuery {
                workspace_connection_id: Some(connection_id),
                personal_connection_id: None,
                base_url: Some(base_url),
            }),
        )
        .await;

        assert_eq!(response.status(), AxumStatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let parsed: SlackChannelsResponse =
            serde_json::from_slice(&body).expect("valid slack response");

        assert!(parsed.success);
        assert_eq!(parsed.channels.len(), 2);
        assert_eq!(parsed.channels[0].id, "C2"); // sorted by name
        assert_eq!(parsed.channels[1].id, "C1");
        assert_eq!(parsed.identity_type, SlackIdentityType::WorkspaceBot);
    }

    #[tokio::test]
    async fn no_id_supplied_returns_bad_request() {
        let user_id = Uuid::new_v4();
        let config = stub_config();
        let workspace_repo = Arc::new(StaticWorkspaceMembershipRepository::with_plan(
            crate::models::plan::PlanTier::Workspace,
        ));
        let dummy_conn = WorkspaceConnection {
            id: Uuid::new_v4(),
            connection_id: None,
            workspace_id: Uuid::new_v4(),
            created_by: user_id,
            owner_user_id: user_id,
            user_oauth_token_id: None,
            provider: ConnectedOAuthProvider::Slack,
            access_token: serde_json::Value::Null.to_string(),
            refresh_token: serde_json::Value::Null.to_string(),
            expires_at: OffsetDateTime::now_utc(),
            account_email: "a@b".into(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            metadata: serde_json::Value::Null,
            slack_team_id: None,
            bot_user_id: None,
            incoming_webhook_url: None,
        };
        let connection_repo = Arc::new(WorkspaceConnectionRepo {
            listing: dummy_conn,
        });
        let personal_repo = Arc::new(PersonalTokenRepo::new(None));
        let state = base_state(config, workspace_repo, connection_repo, personal_repo);

        let response = list_channels(
            State(state),
            AuthSession(test_claims(user_id)),
            Query(ConnectionQuery {
                workspace_connection_id: None,
                personal_connection_id: None,
                base_url: None,
            }),
        )
        .await;

        assert_eq!(response.status(), AxumStatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn both_ids_supplied_returns_bad_request() {
        let user_id = Uuid::new_v4();
        let config = stub_config();
        let workspace_repo = Arc::new(StaticWorkspaceMembershipRepository::with_plan(
            crate::models::plan::PlanTier::Workspace,
        ));
        let dummy_conn = WorkspaceConnection {
            id: Uuid::new_v4(),
            connection_id: None,
            workspace_id: Uuid::new_v4(),
            created_by: user_id,
            owner_user_id: user_id,
            user_oauth_token_id: None,
            provider: ConnectedOAuthProvider::Slack,
            access_token: serde_json::Value::Null.to_string(),
            refresh_token: serde_json::Value::Null.to_string(),
            expires_at: OffsetDateTime::now_utc(),
            account_email: "a@b".into(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            metadata: serde_json::Value::Null,
            slack_team_id: None,
            bot_user_id: None,
            incoming_webhook_url: None,
        };
        let connection_repo = Arc::new(WorkspaceConnectionRepo {
            listing: dummy_conn,
        });
        let personal_repo = Arc::new(PersonalTokenRepo::new(None));
        let state = base_state(config, workspace_repo, connection_repo, personal_repo);

        let response = list_channels(
            State(state),
            AuthSession(test_claims(user_id)),
            Query(ConnectionQuery {
                workspace_connection_id: Some(Uuid::new_v4()),
                personal_connection_id: Some(Uuid::new_v4()),
                base_url: None,
            }),
        )
        .await;

        assert_eq!(response.status(), AxumStatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn webhook_only_rejected() {
        let server = MockServer::start_async().await;
        let base_url = format!("{}/api", server.base_url());

        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        let config = stub_config();
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());

        // webhook-only: encrypted access is empty string
        let encrypted_access = encrypt_secret(&encryption_key, "").unwrap();
        let encrypted_refresh = encrypt_secret(&encryption_key, "").unwrap();

        let workspace_repo = Arc::new(StaticWorkspaceMembershipRepository::with_plan(
            crate::models::plan::PlanTier::Workspace,
        ));

        let listing = WorkspaceConnection {
            id: connection_id,
            connection_id: Some(connection_id),
            workspace_id,
            created_by: user_id,
            owner_user_id: user_id,
            user_oauth_token_id: Some(Uuid::new_v4()),
            provider: ConnectedOAuthProvider::Slack,
            access_token: encrypted_access.clone(),
            refresh_token: encrypted_refresh.clone(),
            expires_at: now + Duration::hours(1),
            account_email: "owner@example.com".into(),
            created_at: now,
            updated_at: now,
            metadata: serde_json::Value::Null,
            slack_team_id: Some("T123".into()),
            bot_user_id: None,
            incoming_webhook_url: Some(
                encrypt_secret(&encryption_key, "https://hooks.slack.example").unwrap(),
            ),
        };
        let connection_repo = Arc::new(WorkspaceConnectionRepo {
            listing: listing.clone(),
        });

        let personal_repo = Arc::new(PersonalTokenRepo::new(None));

        let state = base_state(config, workspace_repo, connection_repo, personal_repo);
        let response = list_channels(
            State(state),
            AuthSession(test_claims(user_id)),
            Query(ConnectionQuery {
                workspace_connection_id: Some(connection_id),
                personal_connection_id: None,
                base_url: Some(base_url),
            }),
        )
        .await;

        assert_eq!(response.status(), AxumStatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn personal_connection_id_rejected() {
        let user_id = Uuid::new_v4();
        let config = stub_config();
        let workspace_repo = Arc::new(StaticWorkspaceMembershipRepository::with_plan(
            crate::models::plan::PlanTier::Workspace,
        ));
        let dummy_conn = WorkspaceConnection {
            id: Uuid::new_v4(),
            connection_id: None,
            workspace_id: Uuid::new_v4(),
            created_by: user_id,
            owner_user_id: user_id,
            user_oauth_token_id: None,
            provider: ConnectedOAuthProvider::Slack,
            access_token: serde_json::Value::Null.to_string(),
            refresh_token: serde_json::Value::Null.to_string(),
            expires_at: OffsetDateTime::now_utc(),
            account_email: "a@b".into(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            metadata: serde_json::Value::Null,
            slack_team_id: None,
            bot_user_id: None,
            incoming_webhook_url: None,
        };
        let connection_repo = Arc::new(WorkspaceConnectionRepo {
            listing: dummy_conn,
        });
        let personal_repo = Arc::new(PersonalTokenRepo::new(None));
        let state = base_state(config, workspace_repo, connection_repo, personal_repo);

        let response = list_channels(
            State(state),
            AuthSession(test_claims(user_id)),
            Query(ConnectionQuery {
                workspace_connection_id: None,
                personal_connection_id: Some(Uuid::new_v4()),
                base_url: None,
            }),
        )
        .await;

        assert_eq!(response.status(), AxumStatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let txt = String::from_utf8_lossy(&body);
        assert!(txt.contains("workspace_connection_id"));
    }

    #[tokio::test]
    async fn workspace_token_expired_refreshes_and_retries() {
        let server = MockServer::start_async().await;
        let base_url = format!("{}/api", server.base_url());

        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        let config = stub_config();
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());

        let encrypted_access = encrypt_secret(&encryption_key, "workspace-access").unwrap();
        let encrypted_refresh = encrypt_secret(&encryption_key, "workspace-refresh").unwrap();

        server
            .mock_async(|when, then| {
                when.method(httpmock::Method::GET)
                    .path("/api/conversations.list")
                    .header("authorization", "Bearer workspace-access");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(r#"{"ok": false, "error": "token_expired"}"#);
            })
            .await;

        server
            .mock_async(|when, then| {
                when.method(httpmock::Method::GET)
                    .path("/api/conversations.list")
                    .header("authorization", "Bearer refreshed-access");
                then.status(200)
                    .header("content-type", "application/json")
                    .body(
                        r#"{
                    "ok": true,
                    "channels": [
                      { "id": "C1", "name": "general", "is_private": false }
                    ]
                }"#,
                    );
            })
            .await;

        let workspace_repo = Arc::new(StaticWorkspaceMembershipRepository::with_plan(
            crate::models::plan::PlanTier::Workspace,
        ));

        #[derive(Clone)]
        struct RecordingConnectionRepo {
            listing: Arc<std::sync::Mutex<WorkspaceConnection>>,
            updates: Arc<std::sync::Mutex<Vec<(String, String, OffsetDateTime)>>>,
        }

        #[async_trait]
        impl WorkspaceConnectionRepository for RecordingConnectionRepo {
            async fn insert_connection(
                &self,
                _new_connection: NewWorkspaceConnection,
            ) -> Result<WorkspaceConnection, sqlx::Error> {
                Err(sqlx::Error::RowNotFound)
            }

            async fn find_by_id(
                &self,
                connection_id: Uuid,
            ) -> Result<Option<WorkspaceConnection>, sqlx::Error> {
                let listing = self.listing.lock().unwrap();
                Ok((connection_id == listing.id).then_some(listing.clone()))
            }

            async fn get_by_id(
                &self,
                connection_id: Uuid,
            ) -> Result<WorkspaceConnection, sqlx::Error> {
                self.find_by_id(connection_id)
                    .await?
                    .ok_or(sqlx::Error::RowNotFound)
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
                workspace_id: Uuid,
                provider: ConnectedOAuthProvider,
            ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
                let listing = self.listing.lock().unwrap();
                if workspace_id == listing.workspace_id && provider == listing.provider {
                    return Ok(vec![listing.clone()]);
                }
                Ok(Vec::new())
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
                use crate::db::workspace_connection_repository::WorkspaceConnectionListing;
                let listing = self.listing.lock().unwrap();
                Ok(vec![WorkspaceConnectionListing {
                    id: listing.id,
                    connection_id: listing.connection_id,
                    workspace_id: listing.workspace_id,
                    owner_user_id: listing.owner_user_id,
                    workspace_name: "Workspace".into(),
                    provider: listing.provider,
                    account_email: listing.account_email.clone(),
                    expires_at: listing.expires_at,
                    shared_by_first_name: None,
                    shared_by_last_name: None,
                    shared_by_email: None,
                    updated_at: listing.updated_at,
                    requires_reconnect: false,
                    has_incoming_webhook: listing.incoming_webhook_url.is_some(),
                }])
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
                connection_id: Uuid,
                access_token: String,
                refresh_token: String,
                expires_at: OffsetDateTime,
                _bot_user_id: Option<String>,
                _slack_team_id: Option<String>,
                _incoming_webhook_url: Option<String>,
            ) -> Result<WorkspaceConnection, sqlx::Error> {
                let mut listing = self.listing.lock().unwrap();
                if connection_id != listing.id {
                    return Err(sqlx::Error::RowNotFound);
                }
                listing.access_token = access_token.clone();
                listing.refresh_token = refresh_token.clone();
                listing.expires_at = expires_at;
                listing.updated_at = OffsetDateTime::now_utc();
                self.updates
                    .lock()
                    .unwrap()
                    .push((access_token, refresh_token, expires_at));
                Ok(listing.clone())
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
                Ok(true)
            }

            async fn mark_connections_stale_for_creator(
                &self,
                _creator_id: Uuid,
                _provider: ConnectedOAuthProvider,
            ) -> Result<Vec<StaleWorkspaceConnection>, sqlx::Error> {
                Ok(Vec::new())
            }

            async fn record_audit_event(
                &self,
                _event: NewWorkspaceAuditEvent,
            ) -> Result<WorkspaceAuditEvent, sqlx::Error> {
                Err(sqlx::Error::RowNotFound)
            }
        }

        let listing = WorkspaceConnection {
            id: connection_id,
            connection_id: Some(connection_id),
            workspace_id,
            created_by: user_id,
            owner_user_id: user_id,
            user_oauth_token_id: Some(Uuid::new_v4()),
            provider: ConnectedOAuthProvider::Slack,
            access_token: encrypted_access.clone(),
            refresh_token: encrypted_refresh.clone(),
            expires_at: now + Duration::hours(1),
            account_email: "owner@example.com".into(),
            created_at: now,
            updated_at: now,
            metadata: serde_json::Value::Null,
            slack_team_id: Some("T123".into()),
            bot_user_id: None,
            incoming_webhook_url: None,
        };
        let connection_repo = Arc::new(RecordingConnectionRepo {
            listing: Arc::new(std::sync::Mutex::new(listing)),
            updates: Arc::new(std::sync::Mutex::new(Vec::new())),
        });

        let personal_repo = Arc::new(PersonalTokenRepo::new(None));

        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());
        let user_repo: Arc<dyn UserOAuthTokenRepository> = personal_repo.clone();
        let connection_repo_trait: Arc<dyn WorkspaceConnectionRepository> = connection_repo.clone();
        let workspace_repo_trait: Arc<dyn crate::db::workspace_repository::WorkspaceRepository> =
            workspace_repo.clone();
        let http_client = state_http_client();

        let mut oauth_accounts = crate::services::oauth::account_service::OAuthAccountService::new(
            user_repo.clone(),
            connection_repo_trait.clone(),
            Arc::clone(&encryption_key),
            http_client.clone(),
            &config.oauth,
        );
        oauth_accounts.set_refresh_override(Some(Arc::new(
            move |provider: ConnectedOAuthProvider, _refresh: &str| {
                assert_eq!(provider, ConnectedOAuthProvider::Slack);
                Ok(
                    crate::services::oauth::account_service::AuthorizationTokens {
                        access_token: "refreshed-access".into(),
                        refresh_token: "refreshed-refresh".into(),
                        expires_at: OffsetDateTime::now_utc() + Duration::hours(2),
                        account_email: "owner@example.com".into(),
                        provider_user_id: None,
                        notion: None,
                        slack: Some(
                            crate::services::oauth::account_service::SlackOAuthMetadata {
                                team_id: Some("T123".into()),
                                bot_user_id: None,
                                incoming_webhook_url: None,
                            },
                        ),
                    },
                )
            },
        )));
        let oauth_accounts = Arc::new(oauth_accounts);

        let workspace_token_refresher: Arc<dyn WorkspaceTokenRefresher> =
            oauth_accounts.clone() as Arc<dyn WorkspaceTokenRefresher>;
        let workspace_oauth = Arc::new(WorkspaceOAuthService::new(
            user_repo,
            workspace_repo_trait.clone(),
            connection_repo_trait.clone(),
            workspace_token_refresher,
            encryption_key.clone(),
        ));

        let state = AppState {
            db: Arc::new(MockDb::default()),
            workflow_repo: Arc::new(NoopWorkflowRepository),
            workspace_repo: workspace_repo_trait,
            workspace_connection_repo: connection_repo_trait,
            stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
            db_pool: crate::state::test_pg_pool(),
            mailer: Arc::new(MockMailer::default()),
            google_oauth: Arc::new(crate::services::oauth::google::client::GoogleOAuthClient {
                client: reqwest::Client::new(),
            }),
            github_oauth: Arc::new(crate::services::oauth::github::client::GitHubOAuthClient {
                client: reqwest::Client::new(),
            }),
            oauth_accounts,
            workspace_oauth,
            stripe: Arc::new(crate::services::stripe::MockStripeService::new()),
            http_client,
            config,
            worker_id: Arc::new("test-worker".into()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        };

        let response = list_channels(
            State(state),
            AuthSession(test_claims(user_id)),
            Query(ConnectionQuery {
                workspace_connection_id: Some(connection_id),
                personal_connection_id: None,
                base_url: Some(base_url),
            }),
        )
        .await;

        assert_eq!(response.status(), AxumStatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let parsed: SlackChannelsResponse =
            serde_json::from_slice(&body).expect("valid slack response");
        assert!(parsed.success);
        assert_eq!(parsed.channels.len(), 1);
        assert_eq!(parsed.identity_type, SlackIdentityType::WorkspaceBot);

        let updates = connection_repo.updates.lock().unwrap();
        assert_eq!(updates.len(), 1);
        let (updated_access, updated_refresh, _) = &updates[0];
        assert_eq!(
            decrypt_secret(&encryption_key, updated_access).unwrap(),
            "refreshed-access"
        );
        assert_eq!(
            decrypt_secret(&encryption_key, updated_refresh).unwrap(),
            "refreshed-refresh"
        );
    }

    #[tokio::test]
    async fn multiple_workspace_connections_without_id_returns_bad_request() {
        let server = MockServer::start_async().await;
        let base_url = format!("{}/api", server.base_url());

        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let connection_id_a = Uuid::new_v4();
        let connection_id_b = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        let config = stub_config();
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());

        let encrypted_access_a = encrypt_secret(&encryption_key, "workspace-access-a").unwrap();
        let encrypted_refresh_a = encrypt_secret(&encryption_key, "workspace-refresh-a").unwrap();
        let encrypted_access_b = encrypt_secret(&encryption_key, "workspace-access-b").unwrap();
        let encrypted_refresh_b = encrypt_secret(&encryption_key, "workspace-refresh-b").unwrap();

        let workspace_repo = Arc::new(StaticWorkspaceMembershipRepository::with_plan(
            crate::models::plan::PlanTier::Workspace,
        ));

        let listing_a = WorkspaceConnection {
            id: connection_id_a,
            connection_id: Some(connection_id_a),
            workspace_id,
            created_by: user_id,
            owner_user_id: user_id,
            user_oauth_token_id: None,
            provider: ConnectedOAuthProvider::Slack,
            access_token: encrypted_access_a.clone(),
            refresh_token: encrypted_refresh_a.clone(),
            expires_at: now + Duration::hours(1),
            account_email: "a@example.com".into(),
            created_at: now,
            updated_at: now,
            metadata: serde_json::Value::Null,
            slack_team_id: Some("T123".into()),
            bot_user_id: None,
            incoming_webhook_url: None,
        };

        let listing_b = WorkspaceConnection {
            id: connection_id_b,
            connection_id: Some(connection_id_b),
            workspace_id,
            created_by: user_id,
            owner_user_id: user_id,
            user_oauth_token_id: None,
            provider: ConnectedOAuthProvider::Slack,
            access_token: encrypted_access_b.clone(),
            refresh_token: encrypted_refresh_b.clone(),
            expires_at: now + Duration::hours(1),
            account_email: "b@example.com".into(),
            created_at: now,
            updated_at: now,
            metadata: serde_json::Value::Null,
            slack_team_id: Some("T123".into()),
            bot_user_id: None,
            incoming_webhook_url: None,
        };

        struct TwoConnRepo {
            a: WorkspaceConnection,
            b: WorkspaceConnection,
        }

        #[async_trait]
        impl WorkspaceConnectionRepository for TwoConnRepo {
            async fn insert_connection(
                &self,
                _new_connection: NewWorkspaceConnection,
            ) -> Result<WorkspaceConnection, sqlx::Error> {
                Err(sqlx::Error::RowNotFound)
            }
            async fn find_by_id(
                &self,
                connection_id: Uuid,
            ) -> Result<Option<WorkspaceConnection>, sqlx::Error> {
                Ok((connection_id == self.a.id)
                    .then_some(self.a.clone())
                    .or_else(|| (connection_id == self.b.id).then_some(self.b.clone())))
            }
            async fn get_by_id(
                &self,
                connection_id: Uuid,
            ) -> Result<WorkspaceConnection, sqlx::Error> {
                self.find_by_id(connection_id)
                    .await?
                    .ok_or(sqlx::Error::RowNotFound)
            }
            async fn list_for_workspace_provider(
                &self,
                _workspace_id: Uuid,
                _provider: ConnectedOAuthProvider,
            ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
                Ok(vec![])
            }
            async fn find_by_source_token(
                &self,
                _user_oauth_token_id: Uuid,
            ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
                Ok(vec![])
            }
            async fn list_by_workspace_and_provider(
                &self,
                workspace_id: Uuid,
                provider: ConnectedOAuthProvider,
            ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
                Ok(vec![self.a.clone(), self.b.clone()]
                    .into_iter()
                    .filter(|c| c.workspace_id == workspace_id && c.provider == provider)
                    .collect())
            }
            async fn list_for_workspace(
                &self,
                _workspace_id: Uuid,
            ) -> Result<
                Vec<crate::db::workspace_connection_repository::WorkspaceConnectionListing>,
                sqlx::Error,
            > {
                Ok(Vec::new())
            }

            async fn list_for_user_memberships(
                &self,
                _user_id: Uuid,
            ) -> Result<
                Vec<crate::db::workspace_connection_repository::WorkspaceConnectionListing>,
                sqlx::Error,
            > {
                use crate::db::workspace_connection_repository::WorkspaceConnectionListing;
                Ok(vec![
                    WorkspaceConnectionListing {
                        id: self.a.id,
                        connection_id: self.a.connection_id,
                        workspace_id: self.a.workspace_id,
                        owner_user_id: self.a.owner_user_id,
                        workspace_name: "Workspace A".into(),
                        provider: self.a.provider,
                        account_email: self.a.account_email.clone(),
                        expires_at: self.a.expires_at,
                        shared_by_first_name: None,
                        shared_by_last_name: None,
                        shared_by_email: None,
                        updated_at: self.a.updated_at,
                        requires_reconnect: false,
                        has_incoming_webhook: self.a.incoming_webhook_url.is_some(),
                    },
                    WorkspaceConnectionListing {
                        id: self.b.id,
                        connection_id: self.b.connection_id,
                        workspace_id: self.b.workspace_id,
                        owner_user_id: self.b.owner_user_id,
                        workspace_name: "Workspace B".into(),
                        provider: self.b.provider,
                        account_email: self.b.account_email.clone(),
                        expires_at: self.b.expires_at,
                        shared_by_first_name: None,
                        shared_by_last_name: None,
                        shared_by_email: None,
                        updated_at: self.b.updated_at,
                        requires_reconnect: false,
                        has_incoming_webhook: self.b.incoming_webhook_url.is_some(),
                    },
                ])
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
                Ok(true)
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
                _event: NewWorkspaceAuditEvent,
            ) -> Result<crate::models::oauth_token::WorkspaceAuditEvent, sqlx::Error> {
                Err(sqlx::Error::RowNotFound)
            }
        }

        let connection_repo = Arc::new(TwoConnRepo {
            a: listing_a.clone(),
            b: listing_b.clone(),
        });

        let personal_repo = Arc::new(PersonalTokenRepo::new(None));

        // Build AppState manually (mirror of base_state) so we can pass a custom
        // WorkspaceConnectionRepository implementation for this test.
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());
        let user_repo: Arc<dyn UserOAuthTokenRepository> = personal_repo.clone();
        let connection_repo_trait: Arc<dyn WorkspaceConnectionRepository> = connection_repo.clone();
        let workspace_repo_trait: Arc<dyn crate::db::workspace_repository::WorkspaceRepository> =
            workspace_repo.clone();
        let http_client = state_http_client();

        let oauth_accounts = Arc::new(
            crate::services::oauth::account_service::OAuthAccountService::new(
                user_repo.clone(),
                connection_repo_trait.clone(),
                Arc::clone(&encryption_key),
                http_client.clone(),
                &config.oauth,
            ),
        );

        let workspace_token_refresher: Arc<
            dyn crate::services::oauth::workspace_service::WorkspaceTokenRefresher,
        > = oauth_accounts.clone()
            as Arc<dyn crate::services::oauth::workspace_service::WorkspaceTokenRefresher>;
        let workspace_oauth = Arc::new(
            crate::services::oauth::workspace_service::WorkspaceOAuthService::new(
                user_repo,
                workspace_repo_trait.clone(),
                connection_repo_trait.clone(),
                workspace_token_refresher,
                encryption_key,
            ),
        );

        let state = AppState {
            db: Arc::new(MockDb::default()),
            workflow_repo: Arc::new(NoopWorkflowRepository),
            workspace_repo: workspace_repo_trait,
            workspace_connection_repo: connection_repo_trait,
            stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
            db_pool: crate::state::test_pg_pool(),
            mailer: Arc::new(MockMailer::default()),
            google_oauth: Arc::new(crate::services::oauth::google::client::GoogleOAuthClient {
                client: reqwest::Client::new(),
            }),
            github_oauth: Arc::new(crate::services::oauth::github::client::GitHubOAuthClient {
                client: reqwest::Client::new(),
            }),
            oauth_accounts,
            workspace_oauth,
            stripe: Arc::new(crate::services::stripe::MockStripeService::new()),
            http_client,
            config,
            worker_id: Arc::new("test-worker".into()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        };
        let response = list_channels(
            State(state),
            AuthSession(test_claims(user_id)),
            Query(ConnectionQuery {
                workspace_connection_id: None,
                personal_connection_id: None,
                base_url: Some(base_url),
            }),
        )
        .await;

        assert_eq!(response.status(), AxumStatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        let txt = String::from_utf8_lossy(&body);
        assert!(txt.contains("workspace_connection_id is required"));
    }
}
