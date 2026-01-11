use axum::{
    extract::{Path, Query, State},
    response::{IntoResponse, Response},
    Json,
};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use tracing::error;
use uuid::Uuid;

use crate::models::oauth_token::ConnectedOAuthProvider;
use crate::models::workspace::WorkspaceMembershipSummary;
use crate::responses::JsonResponse;
use crate::routes::auth::claims::Claims;
use crate::routes::auth::session::AuthSession;
use crate::routes::oauth::map_oauth_error;
use crate::services::microsoft::{
    fetch_channel_members, fetch_joined_teams, fetch_team_channels, MicrosoftChannel,
    MicrosoftChannelMember, MicrosoftGraphError, MicrosoftTeam,
};
use crate::services::oauth::account_service::StoredOAuthToken;
use crate::services::oauth::workspace_service::WorkspaceOAuthError;
use crate::state::AppState;
use crate::utils::plan_limits::NormalizedPlanTier;

use crate::engine::actions::ensure_run_membership;
use crate::engine::actions::ensure_workspace_plan;

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ConnectionQuery {
    scope: Option<String>,
    connection_id: Option<Uuid>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TeamPayload {
    id: String,
    display_name: String,
}

impl From<MicrosoftTeam> for TeamPayload {
    fn from(value: MicrosoftTeam) -> Self {
        Self {
            id: value.id,
            display_name: value.display_name,
        }
    }
}

#[derive(Serialize)]
struct TeamsResponse {
    success: bool,
    teams: Vec<TeamPayload>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChannelPayload {
    id: String,
    display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    membership_type: Option<String>,
}

impl From<MicrosoftChannel> for ChannelPayload {
    fn from(value: MicrosoftChannel) -> Self {
        Self {
            id: value.id,
            display_name: value.display_name,
            membership_type: value.membership_type,
        }
    }
}

#[derive(Serialize)]
struct ChannelsResponse {
    success: bool,
    channels: Vec<ChannelPayload>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MemberPayload {
    id: String,
    user_id: String,
    display_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,
}

impl From<MicrosoftChannelMember> for MemberPayload {
    fn from(value: MicrosoftChannelMember) -> Self {
        Self {
            id: value.id,
            user_id: value.user_id,
            display_name: value.display_name,
            email: value.email,
        }
    }
}

#[derive(Serialize)]
struct MembersResponse {
    success: bool,
    members: Vec<MemberPayload>,
}

pub async fn list_teams(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    Query(query): Query<ConnectionQuery>,
) -> Response {
    let user_id = match parse_user_id(&claims) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let token = match ensure_microsoft_token(&state, user_id, &query).await {
        Ok(token) => token,
        Err(resp) => return resp,
    };

    let teams = match fetch_joined_teams(state.http_client.as_ref(), &token.access_token).await {
        Ok(items) => items,
        Err(err) => return graph_error_response(err),
    };

    Json(TeamsResponse {
        success: true,
        teams: teams.into_iter().map(TeamPayload::from).collect(),
    })
    .into_response()
}

pub async fn list_team_channels(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path(team_id): Path<String>,
    Query(query): Query<ConnectionQuery>,
) -> Response {
    let user_id = match parse_user_id(&claims) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let token = match ensure_microsoft_token(&state, user_id, &query).await {
        Ok(token) => token,
        Err(resp) => return resp,
    };

    let trimmed_id = team_id.trim();
    if trimmed_id.is_empty() {
        return JsonResponse::bad_request("Team ID is required").into_response();
    }
    let encoded_team = urlencoding::encode(trimmed_id);

    let channels = match fetch_team_channels(
        state.http_client.as_ref(),
        &token.access_token,
        encoded_team.as_ref(),
    )
    .await
    {
        Ok(items) => items,
        Err(err) => return graph_error_response(err),
    };

    Json(ChannelsResponse {
        success: true,
        channels: channels.into_iter().map(ChannelPayload::from).collect(),
    })
    .into_response()
}

pub async fn list_channel_members(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path((team_id, channel_id)): Path<(String, String)>,
    Query(query): Query<ConnectionQuery>,
) -> Response {
    // Parse user
    let user_id = match parse_user_id(&claims) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let requested_scope = match determine_scope(&query) {
        Ok(scope) => scope,
        Err(resp) => return resp,
    };

    let token = match requested_scope {
        RequestedScope::Workspace(workspace_conn_id) => {
            let connection = match state
                .workspace_oauth
                .get_connection(
                    user_id,
                    workspace_conn_id,
                    ConnectedOAuthProvider::Microsoft,
                )
                .await
            {
                Ok(conn) => conn,
                Err(_) => {
                    return JsonResponse::forbidden(
                        "Teams connection not found or not allowed for this workspace",
                    )
                    .into_response();
                }
            };

            let workspace_id = connection.workspace_id;

            if let Err(msg) = ensure_workspace_plan(&state, workspace_id).await {
                return JsonResponse::forbidden(&msg).into_response();
            }

            if let Err(msg) = ensure_run_membership(&state, workspace_id, user_id).await {
                return JsonResponse::forbidden(&msg).into_response();
            };

            match ensure_microsoft_token(&state, user_id, &query).await {
                Ok(token) => token,
                Err(resp) => return resp,
            }
        }
        RequestedScope::Personal => {
            if let Err(resp) = ensure_workspace_plan_membership(&state, user_id).await {
                return resp;
            }

            match ensure_microsoft_token(&state, user_id, &query).await {
                Ok(token) => token,
                Err(resp) => return resp,
            }
        }
    };

    // Validate inputs
    let trimmed_team = team_id.trim();
    if trimmed_team.is_empty() {
        return JsonResponse::bad_request("Team ID is required").into_response();
    }
    let trimmed_channel = channel_id.trim();
    if trimmed_channel.is_empty() {
        return JsonResponse::bad_request("Channel ID is required").into_response();
    }

    let encoded_team = urlencoding::encode(trimmed_team);
    let encoded_channel = urlencoding::encode(trimmed_channel);

    let members = match fetch_channel_members(
        state.http_client.as_ref(),
        &token.access_token,
        encoded_team.as_ref(),
        encoded_channel.as_ref(),
    )
    .await
    {
        Ok(items) => items,
        Err(err) => return graph_error_response(err),
    };

    Json(MembersResponse {
        success: true,
        members: members.into_iter().map(MemberPayload::from).collect(),
    })
    .into_response()
}

#[allow(clippy::result_large_err)]
fn parse_user_id(claims: &Claims) -> Result<Uuid, Response> {
    Uuid::parse_str(&claims.id)
        .map_err(|_| JsonResponse::unauthorized("Invalid user identifier").into_response())
}

async fn ensure_microsoft_token(
    state: &AppState,
    user_id: Uuid,
    query: &ConnectionQuery,
) -> Result<StoredOAuthToken, Response> {
    match determine_scope(query)? {
        RequestedScope::Workspace(connection_id) => {
            ensure_workspace_token(state, user_id, connection_id).await
        }
        RequestedScope::Personal => Err(JsonResponse::bad_request(
            "Personal scope requires an explicit OAuth connection",
        )
        .into_response()),
    }
}

fn has_workspace_plan_membership(memberships: &[WorkspaceMembershipSummary]) -> bool {
    memberships.iter().any(|membership| {
        !NormalizedPlanTier::from_option(Some(membership.workspace.plan.as_str())).is_solo()
    })
}

async fn ensure_workspace_plan_membership(state: &AppState, user_id: Uuid) -> Result<(), Response> {
    let memberships = state
        .workspace_repo
        .list_memberships_for_user(user_id)
        .await
        .map_err(|err| {
            error!(?err, %user_id, "Failed to load workspace memberships");
            JsonResponse::server_error("Failed to verify workspace access").into_response()
        })?;

    if has_workspace_plan_membership(&memberships) {
        return Ok(());
    }

    Err(JsonResponse::forbidden("Teams is only available on the Workspace plan").into_response())
}

fn graph_error_response(err: MicrosoftGraphError) -> Response {
    match err {
        MicrosoftGraphError::Http(error) => {
            error!(?error, "Microsoft Graph HTTP error");
            JsonResponse::server_error("Failed to contact Microsoft Graph").into_response()
        }
        MicrosoftGraphError::UnexpectedStatus { status, message } => {
            error!(%status, %message, "Microsoft Graph responded with an error");
            if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                JsonResponse::unauthorized(
                    "The Microsoft connection no longer has permission. Refresh the integration in Settings.",
                )
                .into_response()
            } else {
                JsonResponse::server_error(&message).into_response()
            }
        }
        MicrosoftGraphError::InvalidResponse(message) => {
            error!(%message, "Microsoft Graph returned an invalid payload");
            JsonResponse::server_error("Microsoft Graph returned an unexpected response")
                .into_response()
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum RequestedScope {
    Personal,
    Workspace(Uuid),
}

#[allow(clippy::result_large_err)]
fn determine_scope(query: &ConnectionQuery) -> Result<RequestedScope, Response> {
    if let Some(scope) = query.scope.as_deref() {
        if scope.eq_ignore_ascii_case("workspace") {
            let connection_id = query.connection_id.ok_or_else(|| {
                JsonResponse::bad_request(
                    "Connection ID is required when using a workspace credential",
                )
                .into_response()
            })?;
            return Ok(RequestedScope::Workspace(connection_id));
        }

        if scope.eq_ignore_ascii_case("personal") {
            return Ok(RequestedScope::Personal);
        }

        return Err(JsonResponse::bad_request("Unsupported connection scope").into_response());
    }

    if let Some(connection_id) = query.connection_id {
        return Ok(RequestedScope::Workspace(connection_id));
    }

    Ok(RequestedScope::Personal)
}

async fn ensure_workspace_token(
    state: &AppState,
    user_id: Uuid,
    connection_id: Uuid,
) -> Result<StoredOAuthToken, Response> {
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
            connection.id == connection_id
                && connection.provider == ConnectedOAuthProvider::Microsoft
        })
        .ok_or_else(|| {
            JsonResponse::not_found(
                "Selected workspace Microsoft connection is no longer available",
            )
            .into_response()
        })?;

    state
        .workspace_oauth
        .ensure_valid_workspace_token(listing.id)
        .await
        .map_err(map_workspace_oauth_error)
        .and_then(|connection| {
            if connection.workspace_id != listing.workspace_id {
                return Err(JsonResponse::not_found(
                    "Selected workspace Microsoft connection is no longer available",
                )
                .into_response());
            }

            Ok(StoredOAuthToken {
                id: connection.id,
                provider: ConnectedOAuthProvider::Microsoft,
                access_token: connection.access_token,
                refresh_token: connection.refresh_token,
                expires_at: connection.expires_at,
                account_email: connection.account_email,
                is_shared: true,
                updated_at: connection.updated_at,
            })
        })
}

fn map_workspace_oauth_error(err: WorkspaceOAuthError) -> Response {
    match err {
        WorkspaceOAuthError::Forbidden => {
            JsonResponse::forbidden("Not authorized to use this workspace connection")
                .into_response()
        }
        WorkspaceOAuthError::NotFound => JsonResponse::not_found(
            "Selected workspace Microsoft connection is no longer available",
        )
        .into_response(),
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
    use axum::http::StatusCode;
    use reqwest::Client;
    use std::sync::Arc;
    use time::{Duration, OffsetDateTime};
    use uuid::Uuid;

    use crate::config::{
        Config, OAuthProviderConfig, OAuthSettings, StripeSettings, DEFAULT_WORKSPACE_MEMBER_LIMIT,
        DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT, RUNAWAY_LIMIT_5MIN,
    };
    use crate::db::{
        mock_db::{MockDb, NoopWorkflowRepository, NoopWorkspaceRepository},
        mock_stripe_event_log_repository::MockStripeEventLogRepository,
        oauth_token_repository::{NewUserOAuthToken, UserOAuthTokenRepository},
        workspace_connection_repository::{
            NewWorkspaceAuditEvent, NewWorkspaceConnection, NoopWorkspaceConnectionRepository,
            WorkspaceConnectionListing, WorkspaceConnectionRepository,
        },
        workspace_repository::WorkspaceRepository,
    };
    use crate::models::oauth_token::{ConnectedOAuthProvider, UserOAuthToken, WorkspaceConnection};
    use crate::models::workspace::{Workspace, WorkspaceMembershipSummary, WorkspaceRole};
    use crate::services::{
        oauth::{
            account_service::OAuthAccountService,
            github::mock_github_oauth::MockGitHubOAuth,
            google::mock_google_oauth::MockGoogleOAuth,
            workspace_service::{WorkspaceOAuthService, WorkspaceTokenRefresher},
        },
        smtp_mailer::MockMailer,
    };
    use crate::state::{test_pg_pool, AppState};
    use crate::utils::{encryption::encrypt_secret, jwt::JwtKeys};

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
            if provider != ConnectedOAuthProvider::Microsoft {
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
            if provider != ConnectedOAuthProvider::Microsoft {
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
    struct WorkspaceRepoStub {
        allowed_user_id: Option<Uuid>,
        listing: Option<WorkspaceConnectionListing>,
        record: Option<WorkspaceConnection>,
    }

    impl WorkspaceRepoStub {
        fn new(
            allowed_user_id: Option<Uuid>,
            listing: Option<WorkspaceConnectionListing>,
            record: Option<WorkspaceConnection>,
        ) -> Self {
            Self {
                allowed_user_id,
                listing,
                record,
            }
        }
    }

    #[async_trait]
    impl WorkspaceConnectionRepository for WorkspaceRepoStub {
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
            Ok(self
                .record
                .clone()
                .filter(|record| record.id == connection_id))
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
            _workspace_id: Uuid,
        ) -> Result<Vec<WorkspaceConnectionListing>, sqlx::Error> {
            Ok(Vec::new())
        }

        async fn list_for_user_memberships(
            &self,
            user_id: Uuid,
        ) -> Result<Vec<WorkspaceConnectionListing>, sqlx::Error> {
            if self
                .allowed_user_id
                .map_or(true, |allowed| allowed == user_id)
            {
                if let Some(listing) = &self.listing {
                    return Ok(vec![listing.clone()]);
                }
            }
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

    fn base_state(config: Arc<Config>) -> AppState {
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

    fn workspace_membership(
        workspace_id: Uuid,
        role: WorkspaceRole,
        plan: &str,
    ) -> WorkspaceMembershipSummary {
        WorkspaceMembershipSummary {
            workspace: Workspace {
                id: workspace_id,
                name: "Workspace".into(),
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

    #[tokio::test]
    async fn ensure_microsoft_token_rejects_without_explicit_connection() {
        let config = stub_config();
        let user_id = Uuid::new_v4();

        let state = base_state(config);

        let err = ensure_microsoft_token(&state, user_id, &ConnectionQuery::default())
            .await
            .expect_err("should reject without explicit connection");

        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn ensure_microsoft_token_uses_workspace_connection_when_requested() {
        let config = stub_config();
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());
        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let encrypted_access = encrypt_secret(&encryption_key, "workspace-access").unwrap();
        let encrypted_refresh = encrypt_secret(&encryption_key, "workspace-refresh").unwrap();

        let listing = WorkspaceConnectionListing {
            id: connection_id,
            connection_id: Some(connection_id),
            workspace_id,
            owner_user_id: user_id,
            workspace_name: "Workspace".into(),
            provider: ConnectedOAuthProvider::Microsoft,
            account_email: "shared@example.com".into(),
            expires_at: now + Duration::hours(1),
            shared_by_first_name: None,
            shared_by_last_name: None,
            shared_by_email: None,
            updated_at: now,
            requires_reconnect: false,
            has_incoming_webhook: false,
        };

        let record = WorkspaceConnection {
            id: connection_id,
            connection_id: Some(connection_id),
            workspace_id,
            created_by: user_id,
            owner_user_id: user_id,
            user_oauth_token_id: Some(Uuid::new_v4()),
            provider: ConnectedOAuthProvider::Microsoft,
            access_token: encrypted_access,
            refresh_token: encrypted_refresh,
            expires_at: listing.expires_at,
            account_email: "shared@example.com".into(),
            created_at: now,
            updated_at: now,
            metadata: serde_json::Value::Null,
            bot_user_id: None,
            incoming_webhook_url: None,
            slack_team_id: None,
        };

        let workspace_repo: Arc<dyn WorkspaceConnectionRepository> = Arc::new(
            WorkspaceRepoStub::new(Some(user_id), Some(listing), Some(record)),
        );
        let membership_repo: Arc<dyn WorkspaceRepository> = Arc::new(NoopWorkspaceRepository);

        let workspace_oauth = Arc::new(WorkspaceOAuthService::new(
            Arc::new(PersonalTokenRepo::new(None)),
            Arc::clone(&membership_repo),
            Arc::clone(&workspace_repo),
            OAuthAccountService::test_stub() as Arc<dyn WorkspaceTokenRefresher>,
            Arc::clone(&encryption_key),
        ));

        let mut state = base_state(config);
        state.workspace_repo = membership_repo;
        state.workspace_connection_repo = workspace_repo;
        state.workspace_oauth = workspace_oauth;

        let token = ensure_microsoft_token(
            &state,
            user_id,
            &ConnectionQuery {
                scope: Some("workspace".into()),
                connection_id: Some(connection_id),
            },
        )
        .await
        .expect("should load workspace token");

        assert_eq!(token.access_token, "workspace-access");
        assert!(token.is_shared);
    }

    #[tokio::test]
    async fn ensure_microsoft_token_rejects_unavailable_workspace_connection() {
        let config = stub_config();
        let connection_id = Uuid::new_v4();
        let mut state = base_state(config);
        state.workspace_connection_repo = Arc::new(WorkspaceRepoStub::new(None, None, None));

        let response = ensure_microsoft_token(
            &state,
            Uuid::new_v4(),
            &ConnectionQuery {
                scope: Some("workspace".into()),
                connection_id: Some(connection_id),
            },
        )
        .await
        .expect_err("should return a not found response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn detects_workspace_plan_membership() {
        let memberships = vec![workspace_membership(
            Uuid::new_v4(),
            WorkspaceRole::User,
            "workspace",
        )];

        assert!(has_workspace_plan_membership(&memberships));
    }

    #[test]
    fn rejects_solo_only_memberships() {
        let memberships = vec![workspace_membership(
            Uuid::new_v4(),
            WorkspaceRole::Owner,
            "solo",
        )];

        assert!(!has_workspace_plan_membership(&memberships));
    }
}
