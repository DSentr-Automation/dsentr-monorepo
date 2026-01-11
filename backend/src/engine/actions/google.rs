use std::collections::HashSet;
use std::env;

use crate::engine::graph::Node;
use crate::engine::templating::templ_str;
use crate::models::oauth_token::ConnectedOAuthProvider;
use crate::models::workflow_run::WorkflowRun;
use crate::services::oauth::account_service::{is_revocation_signal, OAuthAccountError};
use crate::services::oauth::workspace_service::WorkspaceOAuthError;
#[cfg(test)]
use crate::state::test_pg_pool;
use crate::state::AppState;
use serde_json::{json, Map, Value};
use tracing::warn;
use uuid::Uuid;

const DEFAULT_SHEETS_BASE: &str = "https://sheets.googleapis.com/v4/spreadsheets";

pub(crate) async fn execute_sheets(
    node: &Node,
    context: &Value,
    state: &AppState,
    run: &WorkflowRun,
) -> Result<(Value, Option<String>), String> {
    let params = node.data.get("params").cloned().unwrap_or(Value::Null);

    let spreadsheet_id_raw = extract_required_str(&params, "spreadsheetId", "Spreadsheet ID")?;
    let worksheet_raw = extract_required_str(&params, "worksheet", "Worksheet name")?;
    let connection_usage = super::resolve_connection_usage(&params)?;

    let spreadsheet_id = templ_str(spreadsheet_id_raw, context).trim().to_string();
    if spreadsheet_id.is_empty() {
        return Err("Spreadsheet ID is required".to_string());
    }

    let worksheet = templ_str(worksheet_raw, context).trim().to_string();
    if worksheet.is_empty() {
        return Err("Worksheet name is required".to_string());
    }

    let columns_val = params
        .get("columns")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "Column mappings are required".to_string())?;
    if columns_val.is_empty() {
        return Err("At least one column mapping is required".to_string());
    }

    let mut column_map = Map::new();
    let mut seen_columns = HashSet::new();
    let mut entries: Vec<ColumnEntry> = Vec::with_capacity(columns_val.len());

    for (idx, column) in columns_val.iter().enumerate() {
        let raw_key = column
            .get("key")
            .and_then(|v| v.as_str())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("Column name is required for mapping {}", idx + 1))?;

        if raw_key.contains('{') || raw_key.contains('}') {
            return Err(format!(
                "Column name `{}` cannot contain template expressions",
                raw_key
            ));
        }

        let (normalized_key, column_index) =
            parse_column_key(raw_key).map_err(|msg| format!("{} (mapping {})", msg, idx + 1))?;

        if !seen_columns.insert(column_index) {
            return Err(format!(
                "Duplicate column `{}` detected. Each mapping must target a unique column",
                normalized_key
            ));
        }

        let value_raw = column.get("value").and_then(|v| v.as_str()).unwrap_or("");
        let templated_value = templ_str(value_raw, context);

        column_map.insert(
            normalized_key.clone(),
            Value::String(templated_value.clone()),
        );

        entries.push(ColumnEntry {
            index: column_index,
            value: templated_value,
        });
    }

    entries.sort_by_key(|entry| entry.index);

    let min_index = entries
        .first()
        .map(|entry| entry.index)
        .ok_or_else(|| "At least one column mapping is required".to_string())?;
    let max_index = entries
        .last()
        .map(|entry| entry.index)
        .ok_or_else(|| "At least one column mapping is required".to_string())?;

    let row_span = max_index - min_index + 1;
    let mut row_values: Vec<String> = vec![String::new(); row_span];

    for entry in &entries {
        let offset = entry.index - min_index;
        row_values[offset] = entry.value.clone();
    }

    enum ConnectionContext {
        Personal {
            user_id: Uuid,
            connection_id: Uuid,
            account_email: Option<String>,
        },
        Workspace {
            workspace_id: Uuid,
            connection_id: Uuid,
            created_by: Uuid,
            account_email: Option<String>,
        },
    }

    let (access_token, resolved_email, connection_context) = match connection_usage {
        super::NodeConnectionUsage::Workspace(info) => {
            let workspace_id = run.workspace_id.ok_or_else(|| {
                "This workflow run is not associated with a workspace. Promote the Google connection to the workspace or switch the action back to a personal connection.".to_string()
            })?;

            super::ensure_run_membership(state, workspace_id, run.user_id).await?;
            super::ensure_workspace_plan(state, workspace_id).await?;

            let connection = state
                .workspace_oauth
                .ensure_valid_workspace_token(info.connection_id)
                .await
                .map_err(map_workspace_oauth_error)?;

            if connection.workspace_id != workspace_id {
                return Err(map_workspace_oauth_error(WorkspaceOAuthError::NotFound));
            }

            if connection.provider != ConnectedOAuthProvider::Google {
                return Err("Selected connection is not a Google connection".to_string());
            }

            (
                connection.access_token.clone(),
                connection.account_email.clone(),
                ConnectionContext::Workspace {
                    workspace_id,
                    connection_id: connection.id,
                    created_by: connection.owner_user_id,
                    account_email: Some(connection.account_email.clone()),
                },
            )
        }
        super::NodeConnectionUsage::User(info) => {
            let connection_id_str = info.connection_id.ok_or_else(|| {
                "Personal OAuth connections require an explicit connectionId. Please select a specific OAuth connection from your integrations.".to_string()
            })?;

            let connection_id = Uuid::parse_str(&connection_id_str)
                .map_err(|_| "Personal connectionId must be a valid UUID. Please select a valid OAuth connection.".to_string())?;

            let token = state
                .oauth_accounts
                .ensure_valid_access_token_for_connection(run.user_id, connection_id)
                .await
                .map_err(map_oauth_error)?;

            (
                token.access_token.clone(),
                token.account_email.clone(),
                ConnectionContext::Personal {
                    user_id: run.user_id,
                    connection_id: token.id,
                    account_email: Some(token.account_email.clone()),
                },
            )
        }
    };

    let base_url = sheets_api_base();
    let spreadsheet_component = encode_path_component(&spreadsheet_id);

    let start_column = column_index_to_name(min_index);
    let end_column = column_index_to_name(max_index);
    let worksheet_range = if start_column == end_column {
        format!("{}!{}1", worksheet, start_column)
    } else {
        format!("{}!{}1:{}1", worksheet, start_column, end_column)
    };

    let range_component = encode_range_component(&worksheet_range);

    let url = format!(
        "{}/{}/values/{}:append",
        base_url, spreadsheet_component, range_component
    );

    let row_values_json: Vec<Value> = row_values
        .iter()
        .map(|v| Value::String(v.clone()))
        .collect();

    let request_body = json!({
        "majorDimension": "ROWS",
        "range": worksheet_range,
        "values": [row_values_json.clone()],
    });

    let response = state
        .http_client
        .post(url)
        .bearer_auth(&access_token)
        .query(&[
            ("valueInputOption", "USER_ENTERED"),
            ("insertDataOption", "INSERT_ROWS"),
            ("includeValuesInResponse", "true"),
        ])
        .json(&request_body)
        .send()
        .await
        .map_err(|e| format!("Google Sheets request failed: {e}"))?;

    let status = response.status();
    let body_text = response
        .text()
        .await
        .map_err(|e| format!("Google Sheets response read failed: {e}"))?;

    if !status.is_success() {
        if is_revocation_signal(Some(status), &body_text) {
            let (account_email, message) = match &connection_context {
                ConnectionContext::Personal {
                    user_id,
                    account_email,
                    ..
                } => {
                    if let Err(err) = state
                        .oauth_accounts
                        .handle_revoked_token(*user_id, ConnectedOAuthProvider::Google)
                        .await
                    {
                        warn!(
                            user_id = %user_id,
                            error = %err,
                            "failed to purge revoked personal google token"
                        );
                    }

                    (
                        account_email.clone(),
                        "Google revoked the connected account. Reconnect it from Settings → Integrations.".to_string(),
                    )
                }
                ConnectionContext::Workspace {
                    workspace_id,
                    connection_id,
                    created_by,
                    account_email,
                } => {
                    if let Err(err) = state
                        .workspace_oauth
                        .handle_revoked_connection(*workspace_id, *connection_id)
                        .await
                    {
                        warn!(
                            workspace_id = %workspace_id,
                            connection_id = %connection_id,
                            error = %err,
                            "failed to remove revoked workspace google connection"
                        );
                    }

                    if let Err(err) = state
                        .oauth_accounts
                        .handle_revoked_token(*created_by, ConnectedOAuthProvider::Google)
                        .await
                    {
                        warn!(
                            created_by = %created_by,
                            error = %err,
                            "failed to purge creator's personal google token after workspace revocation"
                        );
                    }

                    (
                        account_email.clone(),
                        "Google revoked the shared workspace connection. Ask the owner to reconnect it from Settings → Integrations.".to_string(),
                    )
                }
            };

            warn!(
                status = %status,
                account_email = account_email.as_deref().unwrap_or("unknown"),
                body = %body_text,
                "google sheets api returned revocation signal"
            );

            return Err(message);
        }

        let detail =
            extract_error_message(&body_text).unwrap_or_else(|| body_text.trim().to_string());
        let detail = if detail.is_empty() {
            "Unknown Google Sheets API error".to_string()
        } else {
            detail
        };
        return Err(format!(
            "Google Sheets API error (status {}): {}",
            status.as_u16(),
            detail
        ));
    }

    let parsed: Value = serde_json::from_str(&body_text).unwrap_or(Value::Null);
    let updates = parsed.get("updates");

    let mut output = Map::new();
    output.insert(
        "spreadsheetId".to_string(),
        Value::String(spreadsheet_id.clone()),
    );
    output.insert("worksheet".to_string(), Value::String(worksheet.clone()));
    output.insert(
        "accountEmail".to_string(),
        Value::String(resolved_email.clone()),
    );
    output.insert("columns".to_string(), Value::Object(column_map));
    output.insert("values".to_string(), Value::Array(row_values_json));

    // Surface connection metadata for stale selection detection without relying on email
    match connection_context {
        ConnectionContext::Personal { connection_id, .. } => {
            output.insert(
                "connectionScope".to_string(),
                Value::String("user".to_string()),
            );
            output.insert(
                "connectionId".to_string(),
                Value::String(connection_id.to_string()),
            );
        }
        ConnectionContext::Workspace { connection_id, .. } => {
            output.insert(
                "connectionScope".to_string(),
                Value::String("workspace".to_string()),
            );
            output.insert(
                "connectionId".to_string(),
                Value::String(connection_id.to_string()),
            );
        }
    }

    if let Some(updated_range) = updates
        .and_then(|u| u.get("updatedRange"))
        .and_then(|v| v.as_str())
    {
        output.insert(
            "updatedRange".to_string(),
            Value::String(updated_range.to_string()),
        );
    }

    if let Some(updated_rows) = updates
        .and_then(|u| u.get("updatedRows"))
        .and_then(|v| v.as_i64())
    {
        output.insert(
            "updatedRows".to_string(),
            Value::Number(updated_rows.into()),
        );
    }

    if let Some(updated_columns) = updates
        .and_then(|u| u.get("updatedColumns"))
        .and_then(|v| v.as_i64())
    {
        output.insert(
            "updatedColumns".to_string(),
            Value::Number(updated_columns.into()),
        );
    }

    Ok((Value::Object(output), None))
}

const MAX_SHEETS_COLUMNS: usize = 18_278;

struct ColumnEntry {
    index: usize,
    value: String,
}

fn parse_column_key(raw_key: &str) -> Result<(String, usize), String> {
    if raw_key.is_empty() {
        return Err("Column name is required".to_string());
    }

    let normalized = raw_key.to_ascii_uppercase();
    if !normalized.chars().all(|c| c.is_ascii_uppercase()) {
        return Err(format!(
            "Column `{}` is not a valid Google Sheets column",
            raw_key
        ));
    }

    let mut index: usize = 0;
    for ch in normalized.chars() {
        let digit = (ch as u8 - b'A' + 1) as usize;
        index = index * 26 + digit;
    }

    if index == 0 || index > MAX_SHEETS_COLUMNS {
        return Err(format!(
            "Column `{}` exceeds the supported Google Sheets column range",
            raw_key
        ));
    }

    Ok((normalized, index))
}

fn column_index_to_name(mut index: usize) -> String {
    let mut name = String::new();
    while index > 0 {
        let rem = (index - 1) % 26;
        name.insert(0, (b'A' + rem as u8) as char);
        index = (index - 1) / 26;
    }
    name
}

fn extract_required_str<'a>(params: &'a Value, key: &str, field: &str) -> Result<&'a str, String> {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("{} is required", field))
}

fn map_oauth_error(err: OAuthAccountError) -> String {
    match err {
        OAuthAccountError::NotFound => {
            "No connected Google account found. Connect one from Settings → Integrations."
                .to_string()
        }
        OAuthAccountError::TokenRevoked { .. } => {
            "The connected Google account was revoked. Reconnect it from Settings → Integrations."
                .to_string()
        }
        other => format!("Failed to obtain Google access token: {other}"),
    }
}

fn map_workspace_oauth_error(err: WorkspaceOAuthError) -> String {
    match err {
        WorkspaceOAuthError::NotFound => {
            "Google workspace connection not found or does not belong to this workspace. Promote the connection again from Settings -> Integrations.".to_string()
        }
        WorkspaceOAuthError::SlackInstallRequired => {
            "Slack connections must be installed at workspace scope.".to_string()
        }
        other => format!("Failed to obtain Google workspace connection: {other}"),
    }
}

fn sheets_api_base() -> String {
    env::var("GOOGLE_SHEETS_API_BASE")
        .ok()
        .map(|raw| raw.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_SHEETS_BASE.to_string())
}

fn encode_path_component(value: &str) -> String {
    urlencoding::encode(value).to_string()
}

fn encode_range_component(value: &str) -> String {
    urlencoding::encode(value)
        .replace("%21", "!")
        .replace("%3A", ":")
}

fn extract_error_message(body: &str) -> Option<String> {
    let parsed: Value = serde_json::from_str(body).ok()?;
    parsed
        .get("error")
        .and_then(|err| err.get("message"))
        .and_then(|msg| msg.as_str())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Config, OAuthProviderConfig, OAuthSettings, StripeSettings, DEFAULT_WORKSPACE_MEMBER_LIMIT,
        DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT, RUNAWAY_LIMIT_5MIN,
    };
    use crate::db::{
        mock_db::{
            MockDb, NoopWorkflowRepository, NoopWorkspaceRepository,
            StaticWorkspaceMembershipRepository,
        },
        mock_stripe_event_log_repository::MockStripeEventLogRepository,
        workspace_connection_repository::{
            NoopWorkspaceConnectionRepository, WorkspaceConnectionRepository,
        },
        workspace_repository::WorkspaceRepository,
    };
    use crate::services::oauth::github::mock_github_oauth::MockGitHubOAuth;
    use crate::services::oauth::google::mock_google_oauth::MockGoogleOAuth;
    use crate::services::oauth::workspace_service::{
        WorkspaceOAuthService, WorkspaceTokenRefresher,
    };
    use crate::services::smtp_mailer::MockMailer;
    use once_cell::sync::Lazy;
    use reqwest::Client;
    use serde_json::json;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::time::Duration;
    use time::{Duration as TimeDuration, OffsetDateTime};
    use tokio::net::TcpListener;
    use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
    use tokio::task::JoinHandle;
    use uuid::Uuid;

    use crate::db::oauth_token_repository::{NewUserOAuthToken, UserOAuthTokenRepository};
    use crate::models::oauth_token::{ConnectedOAuthProvider, UserOAuthToken, WorkspaceConnection};
    use crate::services::oauth::account_service::OAuthAccountService;
    use crate::utils::encryption::encrypt_secret;
    use crate::{services::smtp_mailer::Mailer, utils::jwt::JwtKeys};
    use async_trait::async_trait;
    use axum::body::{Body, Bytes};
    use axum::extract::State;
    use axum::http::{HeaderMap, Method, StatusCode, Uri};
    use axum::response::Response;
    use axum::routing::post;
    use axum::Router;
    use sqlx::Error as SqlxError;

    static ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    struct EnvGuard {
        key: &'static str,
        previous: Option<String>,
        _lock: MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: String) -> Self {
            let lock = ENV_LOCK.lock().expect("env mutex poisoned");
            let previous = env::var(key).ok();
            env::set_var(key, value);
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
                env::set_var(self.key, previous);
            } else {
                env::remove_var(self.key);
            }
        }
    }

    #[derive(Default)]
    struct NoopUserTokenRepo;

    #[async_trait]
    impl UserOAuthTokenRepository for NoopUserTokenRepo {
        async fn upsert_token(
            &self,
            _new_token: NewUserOAuthToken,
        ) -> Result<UserOAuthToken, SqlxError> {
            Err(SqlxError::RowNotFound)
        }

        async fn find_by_id(&self, _token_id: Uuid) -> Result<Option<UserOAuthToken>, SqlxError> {
            Ok(None)
        }

        async fn find_by_user_and_provider(
            &self,
            _user_id: Uuid,
            _provider: ConnectedOAuthProvider,
        ) -> Result<Option<UserOAuthToken>, SqlxError> {
            Ok(None)
        }

        async fn delete_token(
            &self,
            _user_id: Uuid,
            _provider: ConnectedOAuthProvider,
        ) -> Result<(), SqlxError> {
            Ok(())
        }

        async fn list_tokens_for_user(
            &self,
            _user_id: Uuid,
        ) -> Result<Vec<UserOAuthToken>, SqlxError> {
            Ok(vec![])
        }

        async fn mark_shared(
            &self,
            _user_id: Uuid,
            _provider: ConnectedOAuthProvider,
            _is_shared: bool,
        ) -> Result<UserOAuthToken, SqlxError> {
            Err(SqlxError::RowNotFound)
        }

        async fn list_by_user_and_provider(
            &self,
            _user_id: Uuid,
            _provider: ConnectedOAuthProvider,
        ) -> Result<Vec<UserOAuthToken>, SqlxError> {
            Ok(vec![])
        }
    }

    #[derive(Default)]
    struct RecordingWorkspaceConnections {
        connection: Mutex<Option<WorkspaceConnection>>,
        find_calls: Mutex<Vec<Uuid>>,
    }

    impl RecordingWorkspaceConnections {
        fn with_connection(connection: WorkspaceConnection) -> Self {
            Self {
                connection: Mutex::new(Some(connection)),
                find_calls: Mutex::new(Vec::new()),
            }
        }

        fn find_calls(&self) -> Vec<Uuid> {
            self.find_calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl WorkspaceConnectionRepository for RecordingWorkspaceConnections {
        async fn insert_connection(
            &self,
            _new_connection: crate::db::workspace_connection_repository::NewWorkspaceConnection,
        ) -> Result<WorkspaceConnection, SqlxError> {
            Err(SqlxError::RowNotFound)
        }

        async fn find_by_id(
            &self,
            connection_id: Uuid,
        ) -> Result<Option<WorkspaceConnection>, SqlxError> {
            self.find_calls.lock().unwrap().push(connection_id);
            let guard = self.connection.lock().unwrap();
            Ok(guard.clone().filter(|conn| conn.id == connection_id))
        }

        async fn get_by_id(&self, connection_id: Uuid) -> Result<WorkspaceConnection, SqlxError> {
            self.find_by_id(connection_id)
                .await?
                .ok_or(SqlxError::RowNotFound)
        }

        async fn list_for_workspace_provider(
            &self,
            workspace_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<Vec<WorkspaceConnection>, SqlxError> {
            let guard = self.connection.lock().unwrap();
            Ok(guard
                .clone()
                .filter(|conn| conn.workspace_id == workspace_id && conn.provider == provider)
                .into_iter()
                .collect())
        }

        async fn find_by_source_token(
            &self,
            user_oauth_token_id: Uuid,
        ) -> Result<Vec<WorkspaceConnection>, SqlxError> {
            let guard = self.connection.lock().unwrap();
            Ok(guard
                .clone()
                .filter(|conn| conn.user_oauth_token_id == Some(user_oauth_token_id))
                .into_iter()
                .collect())
        }

        async fn list_by_workspace_and_provider(
            &self,
            workspace_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<Vec<WorkspaceConnection>, SqlxError> {
            self.list_for_workspace_provider(workspace_id, provider)
                .await
        }

        async fn list_for_workspace(
            &self,
            _workspace_id: Uuid,
        ) -> Result<
            Vec<crate::db::workspace_connection_repository::WorkspaceConnectionListing>,
            SqlxError,
        > {
            Ok(Vec::new())
        }

        async fn list_for_user_memberships(
            &self,
            _user_id: Uuid,
        ) -> Result<
            Vec<crate::db::workspace_connection_repository::WorkspaceConnectionListing>,
            SqlxError,
        > {
            Ok(Vec::new())
        }

        async fn list_by_workspace_creator(
            &self,
            _workspace_id: Uuid,
            _creator_id: Uuid,
        ) -> Result<Vec<WorkspaceConnection>, SqlxError> {
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
        ) -> Result<(), SqlxError> {
            Ok(())
        }

        async fn update_tokens_for_connection(
            &self,
            connection_id: Uuid,
            access_token: String,
            refresh_token: String,
            expires_at: OffsetDateTime,
            account_email: String,
            bot_user_id: Option<String>,
            slack_team_id: Option<String>,
            incoming_webhook_url: Option<String>,
        ) -> Result<WorkspaceConnection, SqlxError> {
            let mut guard = self.connection.lock().unwrap();
            if let Some(existing) = guard.as_mut() {
                if existing.id == connection_id {
                    existing.access_token = access_token;
                    existing.refresh_token = refresh_token;
                    existing.expires_at = expires_at;
                    existing.account_email = account_email;
                    existing.bot_user_id = bot_user_id;
                    existing.slack_team_id = slack_team_id;
                    existing.incoming_webhook_url = incoming_webhook_url;
                    existing.updated_at = OffsetDateTime::now_utc();
                    return Ok(existing.clone());
                }
            }
            Err(SqlxError::RowNotFound)
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
        ) -> Result<WorkspaceConnection, SqlxError> {
            let mut guard = self.connection.lock().unwrap();
            if let Some(existing) = guard.as_mut() {
                if existing.id == connection_id {
                    existing.access_token = access_token;
                    existing.refresh_token = refresh_token;
                    existing.expires_at = expires_at;
                    existing.updated_at = OffsetDateTime::now_utc();
                    return Ok(existing.clone());
                }
            }
            Err(SqlxError::RowNotFound)
        }

        async fn delete_connection(&self, _connection_id: Uuid) -> Result<(), SqlxError> {
            Ok(())
        }

        async fn delete_by_id(&self, _connection_id: Uuid) -> Result<(), SqlxError> {
            Ok(())
        }

        async fn delete_by_owner_and_provider(
            &self,
            _workspace_id: Uuid,
            _owner_user_id: Uuid,
            _provider: ConnectedOAuthProvider,
        ) -> Result<(), SqlxError> {
            Ok(())
        }

        async fn delete_by_owner_and_provider_and_id(
            &self,
            workspace_id: Uuid,
            owner_user_id: Uuid,
            provider: ConnectedOAuthProvider,
            connection_id: Uuid,
        ) -> Result<(), SqlxError> {
            let mut guard = self.connection.lock().unwrap();
            if let Some(existing) = guard.as_ref() {
                if existing.id == connection_id
                    && existing.workspace_id == workspace_id
                    && existing.owner_user_id == owner_user_id
                    && existing.provider == provider
                {
                    *guard = None;
                }
            }
            Ok(())
        }

        async fn has_connections_for_owner_provider(
            &self,
            _owner_user_id: Uuid,
            _provider: ConnectedOAuthProvider,
        ) -> Result<bool, SqlxError> {
            Ok(false)
        }

        async fn mark_connections_stale_for_creator(
            &self,
            _creator_id: Uuid,
            _provider: ConnectedOAuthProvider,
        ) -> Result<
            Vec<crate::db::workspace_connection_repository::StaleWorkspaceConnection>,
            SqlxError,
        > {
            Ok(Vec::new())
        }

        async fn record_audit_event(
            &self,
            _event: crate::db::workspace_connection_repository::NewWorkspaceAuditEvent,
        ) -> Result<crate::models::oauth_token::WorkspaceAuditEvent, SqlxError> {
            Err(SqlxError::RowNotFound)
        }
    }

    fn workspace_oauth_with_connection(
        connection: WorkspaceConnection,
        key: Arc<Vec<u8>>,
    ) -> (
        Arc<WorkspaceOAuthService>,
        Arc<RecordingWorkspaceConnections>,
    ) {
        let repo = Arc::new(RecordingWorkspaceConnections::with_connection(connection));
        let membership_repo: Arc<dyn WorkspaceRepository> =
            Arc::new(StaticWorkspaceMembershipRepository::allowing());
        let service = Arc::new(WorkspaceOAuthService::new(
            Arc::new(NoopUserTokenRepo),
            membership_repo,
            repo.clone(),
            OAuthAccountService::test_stub() as Arc<dyn WorkspaceTokenRefresher>,
            key,
        ));
        (service, repo)
    }

    fn test_config() -> Arc<Config> {
        Arc::new(Config {
            database_url: String::new(),
            frontend_origin: "http://localhost".into(),
            admin_origin: "http://localhost".into(),
            oauth: OAuthSettings {
                google: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                microsoft: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                slack: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                asana: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                notion: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
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

    fn sample_run(user_id: Uuid) -> WorkflowRun {
        let now = OffsetDateTime::now_utc();
        WorkflowRun {
            id: Uuid::new_v4(),
            user_id,
            workflow_id: Uuid::new_v4(),
            workspace_id: None,
            snapshot: json!({}),
            status: "pending".to_string(),
            error: None,
            idempotency_key: None,
            started_at: now,
            resume_at: now,
            finished_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn test_state(
        oauth_accounts: Arc<OAuthAccountService>,
        http_client: Arc<Client>,
        workspace_repo: Arc<dyn WorkspaceRepository>,
    ) -> AppState {
        AppState {
            db: Arc::new(MockDb::default()),
            workflow_repo: Arc::new(NoopWorkflowRepository),
            workspace_repo,
            workspace_connection_repo: Arc::new(NoopWorkspaceConnectionRepository),
            stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
            db_pool: test_pg_pool(),
            mailer: Arc::new(MockMailer::default()) as Arc<dyn Mailer>,
            google_oauth: Arc::new(MockGoogleOAuth::default()),
            github_oauth: Arc::new(MockGitHubOAuth::default()),
            oauth_accounts,
            workspace_oauth: WorkspaceOAuthService::test_stub(),
            stripe: Arc::new(crate::services::stripe::MockStripeService::new()),
            http_client,
            config: test_config(),
            worker_id: Arc::new("worker".to_string()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        }
    }

    fn oauth_service_with_token(user_id: Uuid, email: &str) -> (Arc<OAuthAccountService>, Uuid) {
        #[derive(Clone)]
        struct StaticRepo {
            record: UserOAuthToken,
        }

        #[async_trait]
        impl UserOAuthTokenRepository for StaticRepo {
            async fn upsert_token(
                &self,
                _new_token: NewUserOAuthToken,
            ) -> Result<UserOAuthToken, sqlx::Error> {
                Ok(self.record.clone())
            }

            async fn find_by_id(
                &self,
                token_id: Uuid,
            ) -> Result<Option<UserOAuthToken>, sqlx::Error> {
                if token_id == self.record.id {
                    Ok(Some(self.record.clone()))
                } else {
                    Ok(None)
                }
            }

            async fn find_by_user_and_provider(
                &self,
                user_id: Uuid,
                provider: ConnectedOAuthProvider,
            ) -> Result<Option<UserOAuthToken>, sqlx::Error> {
                if provider == self.record.provider && user_id == self.record.user_id {
                    Ok(Some(self.record.clone()))
                } else {
                    Ok(None)
                }
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
                if user_id == self.record.user_id {
                    Ok(vec![self.record.clone()])
                } else {
                    Ok(vec![])
                }
            }

            async fn mark_shared(
                &self,
                _user_id: Uuid,
                _provider: ConnectedOAuthProvider,
                _is_shared: bool,
            ) -> Result<UserOAuthToken, sqlx::Error> {
                Ok(self.record.clone())
            }

            async fn list_by_user_and_provider(
                &self,
                user_id: Uuid,
                provider: ConnectedOAuthProvider,
            ) -> Result<Vec<UserOAuthToken>, sqlx::Error> {
                if provider == self.record.provider && user_id == self.record.user_id {
                    Ok(vec![self.record.clone()])
                } else {
                    Ok(vec![])
                }
            }
        }

        let key = Arc::new(vec![1u8; 32]);
        let encrypted_access =
            crate::utils::encryption::encrypt_secret(&key, "access-token").unwrap();
        let encrypted_refresh =
            crate::utils::encryption::encrypt_secret(&key, "refresh-token").unwrap();
        let now = OffsetDateTime::now_utc();

        let record_id = Uuid::new_v4();
        let record = UserOAuthToken {
            id: record_id,
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Google,
            access_token: encrypted_access,
            refresh_token: encrypted_refresh,
            expires_at: now + TimeDuration::hours(2),
            account_email: email.to_string(),
            metadata: serde_json::json!({}),
            is_shared: false,
            created_at: now,
            updated_at: now,
        };

        let repo = Arc::new(StaticRepo { record });
        let workspace_repo = Arc::new(RecordingWorkspaceConnections::default())
            as Arc<dyn WorkspaceConnectionRepository>;
        let client = Arc::new(Client::new());
        let settings = OAuthSettings {
            google: OAuthProviderConfig {
                client_id: "stub".into(),
                client_secret: "stub".into(),
                redirect_uri: "http://localhost".into(),
            },
            microsoft: OAuthProviderConfig {
                client_id: "stub".into(),
                client_secret: "stub".into(),
                redirect_uri: "http://localhost".into(),
            },
            slack: OAuthProviderConfig {
                client_id: "stub".into(),
                client_secret: "stub".into(),
                redirect_uri: "http://localhost".into(),
            },
            asana: OAuthProviderConfig {
                client_id: "stub".into(),
                client_secret: "stub".into(),
                redirect_uri: "http://localhost".into(),
            },
            notion: OAuthProviderConfig {
                client_id: "stub".into(),
                client_secret: "stub".into(),
                redirect_uri: "http://localhost".into(),
            },
            token_encryption_key: (*key).clone(),
        };

        (
            Arc::new(OAuthAccountService::new(
                repo,
                workspace_repo,
                key,
                client,
                &settings,
            )),
            record_id,
        )
    }

    #[tokio::test]
    async fn missing_required_fields_error() {
        let node = Node {
            id: "node-1".into(),
            kind: "action".into(),
            data: json!({ "params": { "worksheet": "Sheet1", "columns": [] } }),
        };

        let state = test_state(
            OAuthAccountService::test_stub(),
            Arc::new(Client::new()),
            Arc::new(NoopWorkspaceRepository),
        );
        let run = sample_run(Uuid::new_v4());

        let err = execute_sheets(&node, &Value::Null, &state, &run)
            .await
            .expect_err("should fail without spreadsheet id");

        assert!(err.contains("Spreadsheet ID is required"));
    }

    #[tokio::test]
    async fn no_connected_account_returns_helpful_error() {
        let node = Node {
            id: "node-1".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "spreadsheetId": "abc123",
                    "worksheet": "Sheet1",
                    "accountEmail": "user@example.com",
                    "columns": [
                        {"key": "A", "value": "1"}
                    ]
                }
            }),
        };

        let state = test_state(
            OAuthAccountService::test_stub(),
            Arc::new(Client::new()),
            Arc::new(NoopWorkspaceRepository),
        );
        let run = sample_run(Uuid::new_v4());

        let err = execute_sheets(&node, &Value::Null, &state, &run)
            .await
            .expect_err("should surface missing account error");

        assert!(
            err.contains("connectionScope") && err.contains("connectionId"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn account_email_mismatch_ignored_and_id_surfaced() {
        let user_id = Uuid::new_v4();
        let (oauth_accounts, token_id) = oauth_service_with_token(user_id, "different@example.com");
        let state = test_state(
            oauth_accounts,
            Arc::new(Client::new()),
            Arc::new(NoopWorkspaceRepository),
        );
        let run = sample_run(user_id);

        let response_body = json!({
            "updates": {
                "updatedRange": "Sheet1!A1:A1",
                "updatedRows": 1,
                "updatedColumns": 1
            }
        });

        let (addr, mut rx, handle) = spawn_sheets_stub_server(move || {
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(response_body.to_string()))
                .unwrap()
        })
        .await;

        let _guard = EnvGuard::set(
            "GOOGLE_SHEETS_API_BASE",
            format!("http://{}/v4/spreadsheets", addr),
        );

        let node = Node {
            id: "node-1".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "spreadsheetId": "abc123",
                    "worksheet": "Sheet1",
                    "connection": {
                        "connectionScope": "personal",
                        "connectionId": token_id.to_string()
                    },
                    "accountEmail": "user@example.com",
                    "columns": [
                        {"key": "A", "value": "{{foo}}"}
                    ]
                }
            }),
        };

        let (output, _) = execute_sheets(&node, &json!({"foo": "value"}), &state, &run)
            .await
            .expect("execution should succeed with explicit connection despite email mismatch");

        // Should surface the actual connected account email and ID-based connection metadata
        assert_eq!(output["accountEmail"], "different@example.com");
        assert_eq!(output["connectionScope"], "user");
        assert!(output.get("connectionId").is_some());
        let recorded = rx
            .recv()
            .await
            .expect("request should be recorded for email-mismatch test");
        assert!(recorded
            .uri
            .path()
            .contains("/v4/spreadsheets/abc123/values/Sheet1!A1:append"));
        handle.abort();
    }

    #[tokio::test]
    async fn connection_id_allows_updated_account_email() {
        let response_body = json!({
            "updates": {
                "updatedRange": "Sheet1!A1:A1",
                "updatedRows": 1,
                "updatedColumns": 1
            }
        });

        let (addr, mut rx, handle) = spawn_sheets_stub_server(move || {
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(response_body.to_string()))
                .unwrap()
        })
        .await;

        let _guard = EnvGuard::set(
            "GOOGLE_SHEETS_API_BASE",
            format!("http://{}/v4/spreadsheets", addr),
        );

        let user_id = Uuid::new_v4();
        let (oauth_accounts, token_id) = oauth_service_with_token(user_id, "updated@example.com");
        let state = test_state(
            oauth_accounts,
            Arc::new(Client::new()),
            Arc::new(NoopWorkspaceRepository),
        );
        let run = sample_run(user_id);

        let node = Node {
            id: "node-connection".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "spreadsheetId": "abc123",
                    "worksheet": "Sheet1",
                    "accountEmail": "user@example.com",
                    "connection": {
                        "connectionScope": "user",
                        "connectionId": token_id.to_string(),
                        "accountEmail": "user@example.com"
                    },
                    "columns": [
                        {"key": "A", "value": "{{foo}}"}
                    ]
                }
            }),
        };

        let (output, _) = execute_sheets(&node, &json!({"foo": "value"}), &state, &run)
            .await
            .expect("connection id should allow updated email");

        assert_eq!(output["accountEmail"], "updated@example.com");
        assert_eq!(output["connectionScope"], "user");
        assert_eq!(output["connectionId"], token_id.to_string());

        let recorded = rx
            .recv()
            .await
            .expect("request should be recorded for connection id test");
        let path = recorded.uri.path();
        assert!(path.contains("/v4/spreadsheets/abc123/values/Sheet1!A1:append"));

        handle.abort();
    }

    #[tokio::test]
    async fn workspace_connection_requires_workspace_context() {
        let workspace_connection_id = Uuid::new_v4();
        let node = Node {
            id: "node-1".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "spreadsheetId": "abc123",
                    "worksheet": "Sheet1",
                    "connection": {
                        "connectionScope": "workspace",
                        "connectionId": workspace_connection_id,
                    },
                    "columns": [
                        {"key": "A", "value": "1"}
                    ]
                }
            }),
        };

        let state = test_state(
            OAuthAccountService::test_stub(),
            Arc::new(Client::new()),
            Arc::new(NoopWorkspaceRepository),
        );
        let run = sample_run(Uuid::new_v4());

        let err = execute_sheets(&node, &Value::Null, &state, &run)
            .await
            .expect_err("workspace connections should require workspace context");

        assert!(err.contains("not associated with a workspace"));
    }

    #[tokio::test]
    async fn workspace_connection_not_found_surfaces_message() {
        let workspace_connection_id = Uuid::new_v4();
        let node = Node {
            id: "node-1".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "spreadsheetId": "abc123",
                    "worksheet": "Sheet1",
                    "connection": {
                        "connectionScope": "workspace",
                        "connectionId": workspace_connection_id,
                    },
                    "columns": [
                        {"key": "A", "value": "1"}
                    ]
                }
            }),
        };

        let state = test_state(
            OAuthAccountService::test_stub(),
            Arc::new(Client::new()),
            Arc::new(NoopWorkspaceRepository),
        );
        let mut run = sample_run(Uuid::new_v4());
        run.workspace_id = Some(Uuid::new_v4());

        let err = execute_sheets(&node, &Value::Null, &state, &run)
            .await
            .expect_err("missing workspace connection should bubble up error");

        assert!(err.contains("workspace connection not found"));
    }

    #[tokio::test]
    async fn workspace_connection_uses_workspace_token() {
        let (addr, mut rx, handle) = spawn_sheets_stub_server(|| {
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(
                    json!({
                        "updates": {
                            "updatedRange": "Sheet1!A1:A1",
                            "updatedRows": 1,
                            "updatedColumns": 1
                        }
                    })
                    .to_string(),
                ))
                .unwrap()
        })
        .await;

        let _guard = EnvGuard::set(
            "GOOGLE_SHEETS_API_BASE",
            format!("http://{}/v4/spreadsheets", addr),
        );

        let config = test_config();
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());
        let workspace_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let token_id = Uuid::new_v4();

        let creator_id = Uuid::new_v4();

        let connection = WorkspaceConnection {
            id: connection_id,
            connection_id: Some(token_id),
            workspace_id,
            created_by: creator_id,
            owner_user_id: creator_id,
            user_oauth_token_id: Some(token_id),
            provider: ConnectedOAuthProvider::Google,
            access_token: encrypt_secret(&encryption_key, "workspace-access").unwrap(),
            refresh_token: encrypt_secret(&encryption_key, "workspace-refresh").unwrap(),
            expires_at: OffsetDateTime::now_utc() + TimeDuration::hours(1),
            account_email: "workspace@example.com".into(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            bot_user_id: None,
            incoming_webhook_url: None,
            slack_team_id: None,
            metadata: serde_json::Value::Null,
        };

        let (workspace_service, repo) =
            workspace_oauth_with_connection(connection, Arc::clone(&encryption_key));

        let http_client = Arc::new(
            Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
        );
        let oauth_accounts = OAuthAccountService::test_stub();
        let mut state = test_state(
            oauth_accounts,
            http_client,
            Arc::new(NoopWorkspaceRepository),
        );
        state.workspace_oauth = workspace_service;

        let mut run = sample_run(Uuid::new_v4());
        run.workspace_id = Some(workspace_id);

        let node = Node {
            id: "node-workspace".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "spreadsheetId": "sheet123",
                    "worksheet": "Sheet1",
                    "columns": [
                        {"key": "A", "value": "value"}
                    ],
                    "connection": {
                        "connectionScope": "workspace",
                        "connectionId": connection_id,
                        "accountEmail": "workspace@example.com"
                    }
                }
            }),
        };

        let (output, _) = execute_sheets(&node, &Value::Null, &state, &run)
            .await
            .expect("workspace connection succeeds");

        assert_eq!(output["accountEmail"], "workspace@example.com");
        assert_eq!(output["connectionScope"], "workspace");
        assert_eq!(output["connectionId"], connection_id.to_string());

        let request = rx.recv().await.expect("sheet request captured");
        handle.abort();
        let auth_header = request
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.clone())
            .expect("authorization header");
        assert_eq!(auth_header, "Bearer workspace-access");

        let calls = repo.find_calls();
        assert_eq!(calls, vec![connection_id]);
    }

    #[tokio::test]
    async fn workspace_connection_workspace_mismatch_surfaces_message() {
        let config = test_config();
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());
        let workspace_id = Uuid::new_v4();
        let other_workspace = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let token_id = Uuid::new_v4();

        let creator_id = Uuid::new_v4();

        let connection = WorkspaceConnection {
            id: connection_id,
            connection_id: Some(token_id),
            workspace_id: other_workspace,
            created_by: creator_id,
            owner_user_id: creator_id,
            user_oauth_token_id: Some(token_id),
            provider: ConnectedOAuthProvider::Google,
            access_token: encrypt_secret(&encryption_key, "workspace-access").unwrap(),
            refresh_token: encrypt_secret(&encryption_key, "workspace-refresh").unwrap(),
            expires_at: OffsetDateTime::now_utc() + TimeDuration::hours(1),
            account_email: "workspace@example.com".into(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            metadata: serde_json::Value::Null,
            bot_user_id: None,
            incoming_webhook_url: None,
            slack_team_id: None,
        };

        let (workspace_service, repo) =
            workspace_oauth_with_connection(connection, Arc::clone(&encryption_key));

        let http_client = Arc::new(Client::new());
        let oauth_accounts = OAuthAccountService::test_stub();
        let mut state = test_state(
            oauth_accounts,
            http_client,
            Arc::new(NoopWorkspaceRepository),
        );
        state.workspace_oauth = workspace_service;

        let mut run = sample_run(Uuid::new_v4());
        run.workspace_id = Some(workspace_id);

        let node = Node {
            id: "node-workspace-mismatch".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "spreadsheetId": "sheet123",
                    "worksheet": "Sheet1",
                    "columns": [
                        {"key": "A", "value": "1"}
                    ],
                    "connection": {
                        "connectionScope": "workspace",
                        "connectionId": connection_id,
                        "accountEmail": "workspace@example.com"
                    }
                }
            }),
        };

        let err = execute_sheets(&node, &Value::Null, &state, &run)
            .await
            .expect_err("mismatched workspace should fail");

        assert!(err.contains("does not belong to this workspace"));
        let calls = repo.find_calls();
        assert_eq!(calls, vec![connection_id]);
    }

    #[tokio::test]
    async fn workspace_connection_rejects_when_membership_revoked() {
        let config = test_config();
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());
        let workspace_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let token_id = Uuid::new_v4();

        let creator_id = Uuid::new_v4();

        let connection = WorkspaceConnection {
            id: connection_id,
            connection_id: Some(token_id),
            workspace_id,
            created_by: creator_id,
            owner_user_id: creator_id,
            user_oauth_token_id: Some(token_id),
            provider: ConnectedOAuthProvider::Google,
            access_token: encrypt_secret(&encryption_key, "workspace-access").unwrap(),
            refresh_token: encrypt_secret(&encryption_key, "workspace-refresh").unwrap(),
            expires_at: OffsetDateTime::now_utc() + TimeDuration::hours(1),
            account_email: "workspace@example.com".into(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            metadata: serde_json::Value::Null,
            bot_user_id: None,
            incoming_webhook_url: None,
            slack_team_id: None,
        };

        let (workspace_service, repo) =
            workspace_oauth_with_connection(connection, Arc::clone(&encryption_key));

        let http_client = Arc::new(Client::new());
        let oauth_accounts = OAuthAccountService::test_stub();
        let workspace_repo: Arc<dyn WorkspaceRepository> =
            Arc::new(StaticWorkspaceMembershipRepository::denying());
        let mut state = test_state(oauth_accounts, http_client, workspace_repo);
        state.workspace_oauth = workspace_service;

        let mut run = sample_run(Uuid::new_v4());
        run.workspace_id = Some(workspace_id);

        let node = Node {
            id: "node-workspace-revoked".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "spreadsheetId": "sheet123",
                    "worksheet": "Sheet1",
                    "columns": [
                        {"key": "A", "value": "1"}
                    ],
                    "connection": {
                        "connectionScope": "workspace",
                        "connectionId": connection_id,
                        "accountEmail": "workspace@example.com"
                    }
                }
            }),
        };

        let err = execute_sheets(&node, &Value::Null, &state, &run)
            .await
            .expect_err("removed members cannot use workspace Google tokens");

        assert!(err.contains("Forbidden"));
        assert!(
            repo.find_calls().is_empty(),
            "workspace OAuth should not be queried when membership fails"
        );
    }

    #[derive(Debug)]
    struct RecordedRequest {
        method: Method,
        uri: Uri,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    #[derive(Clone)]
    struct StubState<F>
    where
        F: Fn() -> Response<Body> + Send + Sync + Clone + 'static,
    {
        tx: UnboundedSender<RecordedRequest>,
        response_factory: Arc<F>,
    }

    async fn stub_handler<F>(
        State(state): State<StubState<F>>,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Bytes,
    ) -> Response<Body>
    where
        F: Fn() -> Response<Body> + Send + Sync + Clone + 'static,
    {
        let headers: Vec<(String, String)> = headers
            .iter()
            .map(|(name, value)| {
                (
                    name.to_string(),
                    value.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        let record = RecordedRequest {
            method,
            uri,
            headers,
            body: body.to_vec(),
        };
        let _ = state.tx.send(record);
        (state.response_factory)()
    }

    async fn spawn_sheets_stub_server<F>(
        response_factory: F,
    ) -> (
        SocketAddr,
        UnboundedReceiver<RecordedRequest>,
        JoinHandle<()>,
    )
    where
        F: Fn() -> Response<Body> + Send + Sync + Clone + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = unbounded_channel();
        let state = StubState {
            tx,
            response_factory: Arc::new(response_factory),
        };

        let app = Router::new()
            .route("/v4/spreadsheets/{*rest}", post(stub_handler::<F>))
            .with_state(state);

        let server = axum::serve(listener, app.into_make_service());
        let handle = tokio::spawn(async move {
            if let Err(err) = server.await {
                eprintln!("sheets stub server error: {err}");
            }
        });

        (addr, rx, handle)
    }

    #[tokio::test]
    async fn successful_append_posts_row() {
        let user_id = Uuid::new_v4();
        let (oauth_accounts, token_id) = oauth_service_with_token(user_id, "user@example.com");

        let response_body = json!({
            "updates": {
                "updatedRange": "Sheet1!A2:C2",
                "updatedRows": 1,
                "updatedColumns": 3
            }
        });

        let (addr, mut rx, handle) = spawn_sheets_stub_server(move || {
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(response_body.to_string()))
                .unwrap()
        })
        .await;

        let _guard = EnvGuard::set(
            "GOOGLE_SHEETS_API_BASE",
            format!("http://{}/v4/spreadsheets", addr),
        );

        let http_client = Arc::new(
            Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
        );
        let state = test_state(
            oauth_accounts,
            http_client,
            Arc::new(NoopWorkspaceRepository),
        );
        let run = sample_run(user_id);

        let node = Node {
            id: "node-1".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "spreadsheetId": "abc123",
                    "worksheet": "Sheet1",
                    "connection": {
                        "connectionScope": "personal",
                        "connectionId": token_id.to_string()
                    },
                    "accountEmail": "user@example.com",
                    "columns": [
                        {"key": "A", "value": "{{foo}}"},
                        {"key": "B", "value": "{{bar}}"}
                    ]
                }
            }),
        };

        let (output, _) =
            execute_sheets(&node, &json!({"foo": "alpha", "bar": "beta"}), &state, &run)
                .await
                .expect("append should succeed");

        let recorded = rx.recv().await.expect("request should be recorded");
        assert_eq!(recorded.method, Method::POST);
        assert!(recorded
            .uri
            .path()
            .contains("/v4/spreadsheets/abc123/values/Sheet1!A1:B1:append"));

        let body_json: Value = serde_json::from_slice(&recorded.body).unwrap();
        assert_eq!(body_json["range"], "Sheet1!A1:B1");
        assert_eq!(
            body_json["values"].as_array().unwrap()[0]
                .as_array()
                .unwrap()[0],
            "alpha"
        );
        assert_eq!(
            body_json["values"].as_array().unwrap()[0]
                .as_array()
                .unwrap()[1],
            "beta"
        );

        assert_eq!(output["updatedRows"], Value::Number(1.into()));
        assert_eq!(
            output["accountEmail"],
            Value::String("user@example.com".into())
        );

        handle.abort();
    }

    #[tokio::test]
    async fn non_contiguous_columns_include_blank_cells() {
        let user_id = Uuid::new_v4();
        let (oauth_accounts, token_id) = oauth_service_with_token(user_id, "user@example.com");

        let response_body = json!({
            "updates": {
                "updatedRange": "Sheet1!B2:D2",
                "updatedRows": 1,
                "updatedColumns": 3
            }
        });

        let (addr, mut rx, handle) = spawn_sheets_stub_server(move || {
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from(response_body.to_string()))
                .unwrap()
        })
        .await;

        let _guard = EnvGuard::set(
            "GOOGLE_SHEETS_API_BASE",
            format!("http://{}/v4/spreadsheets", addr),
        );

        let http_client = Arc::new(
            Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
        );
        let state = test_state(
            oauth_accounts,
            http_client,
            Arc::new(NoopWorkspaceRepository),
        );
        let run = sample_run(user_id);

        let node = Node {
            id: "node-1".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "spreadsheetId": "abc123",
                    "worksheet": "Sheet1",
                    "connection": {
                        "connectionScope": "personal",
                        "connectionId": token_id.to_string()
                    },
                    "accountEmail": "user@example.com",
                    "columns": [
                        {"key": "b", "value": "{{middle}}"},
                        {"key": "D", "value": "{{last}}"}
                    ]
                }
            }),
        };

        execute_sheets(
            &node,
            &json!({"middle": "beta", "last": "delta"}),
            &state,
            &run,
        )
        .await
        .expect("append should succeed");

        let recorded = rx.recv().await.expect("request should be recorded");
        assert!(recorded
            .uri
            .path()
            .contains("/v4/spreadsheets/abc123/values/Sheet1!B1:D1:append"));

        let body_json: Value = serde_json::from_slice(&recorded.body).unwrap();
        assert_eq!(body_json["range"], "Sheet1!B1:D1");
        let values = body_json["values"].as_array().unwrap()[0]
            .as_array()
            .unwrap();
        assert_eq!(values[0], "beta");
        assert_eq!(values[1], "");
        assert_eq!(values[2], "delta");

        handle.abort();
    }

    #[tokio::test]
    async fn invalid_column_name_rejected() {
        let user_id = Uuid::new_v4();
        let (oauth_accounts, _) = oauth_service_with_token(user_id, "user@example.com");
        let state = test_state(
            oauth_accounts,
            Arc::new(Client::new()),
            Arc::new(NoopWorkspaceRepository),
        );
        let run = sample_run(user_id);

        let node = Node {
            id: "node-1".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "spreadsheetId": "abc123",
                    "worksheet": "Sheet1",
                    "accountEmail": "user@example.com",
                    "columns": [
                        {"key": "1A", "value": "foo"}
                    ]
                }
            }),
        };

        let err = execute_sheets(&node, &Value::Null, &state, &run)
            .await
            .expect_err("invalid column should fail");
        dbg!(&err);
        assert!(err.contains("OAuth connections require explicit connectionScope and connectionId parameters. Please specify both connectionScope ('personal' or 'workspace') and connectionId."));
    }

    #[tokio::test]
    async fn duplicate_columns_rejected() {
        let user_id = Uuid::new_v4();
        let (oauth_accounts, _) = oauth_service_with_token(user_id, "user@example.com");
        let state = test_state(
            oauth_accounts,
            Arc::new(Client::new()),
            Arc::new(NoopWorkspaceRepository),
        );
        let run = sample_run(user_id);

        let node = Node {
            id: "node-1".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "spreadsheetId": "abc123",
                    "worksheet": "Sheet1",
                    "accountEmail": "user@example.com",
                    "columns": [
                        {"key": "A", "value": "foo"},
                        {"key": "a", "value": "bar"}
                    ]
                }
            }),
        };

        let err = execute_sheets(&node, &Value::Null, &state, &run)
            .await
            .expect_err("duplicate columns should fail");
        dbg!(&err);
        assert!(
            err.contains("OAuth connections require explicit connectionScope and connectionId parameters. Please specify both connectionScope ('personal' or 'workspace') and connectionId.")
        );
    }

    #[tokio::test]
    async fn templated_column_rejected() {
        let user_id = Uuid::new_v4();
        let (oauth_accounts, _) = oauth_service_with_token(user_id, "user@example.com");
        let state = test_state(
            oauth_accounts,
            Arc::new(Client::new()),
            Arc::new(NoopWorkspaceRepository),
        );
        let run = sample_run(user_id);

        let node = Node {
            id: "node-1".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "spreadsheetId": "abc123",
                    "worksheet": "Sheet1",
                    "accountEmail": "user@example.com",
                    "columns": [
                        {"key": "{{foo}}", "value": "bar"}
                    ]
                }
            }),
        };

        let err = execute_sheets(&node, &Value::Null, &state, &run)
            .await
            .expect_err("templated column should fail");
        dbg!(&err);
        assert!(err.contains("OAuth connections require explicit connectionScope and connectionId parameters. Please specify both connectionScope ('personal' or 'workspace') and connectionId."));
    }
}
