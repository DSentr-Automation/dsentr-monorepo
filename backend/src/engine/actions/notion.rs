use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::engine::graph::Node;
use crate::engine::templating::templ_str;
use crate::models::oauth_token::ConnectedOAuthProvider;
use crate::models::workflow_run::WorkflowRun;
use crate::services::notion;
use crate::services::notion::NotionError;
use crate::services::oauth::account_service::OAuthAccountError;
use crate::services::oauth::workspace_service::WorkspaceOAuthError;
use crate::state::AppState;

use super::{ensure_run_membership, ensure_workspace_plan, resolve_connection_usage};

const DEFAULT_QUERY_PAGE_SIZE: u32 = 25;

pub(crate) async fn execute_notion(
    node: &Node,
    context: &Value,
    state: &AppState,
    run: &WorkflowRun,
) -> Result<(Value, Option<String>), String> {
    let params = node.data.get("params").cloned().unwrap_or(Value::Null);

    let operation = params
        .get("operation")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();

    let connection_usage = resolve_connection_usage(&params)?;
    let access_token = resolve_access_token(state, run, &connection_usage).await?;
    let client = &state.http_client;

    match operation.as_str() {
        "create_database_row" => {
            let database_id = read_required(&params, "databaseId", "Database ID", context)?;
            let properties = build_properties(&params, context)?;
            if properties.is_empty() {
                return Err("At least one property value is required".to_string());
            }
            let response = notion::create_page(
                client,
                &access_token,
                Some(&database_id),
                None,
                Value::Object(properties),
            )
            .await
            .map_err(map_notion_error)?;
            Ok((page_summary(&response), None))
        }
        "update_database_row" => {
            let page_id = read_required(&params, "pageId", "Page ID", context)?;
            let properties = build_properties(&params, context)?;
            if properties.is_empty() {
                return Err("At least one property value is required".to_string());
            }
            let response =
                notion::update_page(client, &access_token, &page_id, Value::Object(properties))
                    .await
                    .map_err(map_notion_error)?;
            Ok((page_summary(&response), None))
        }
        "create_page" => {
            let parent_database_id = read_optional(&params, "parentDatabaseId", context);
            let parent_page_id = read_optional(&params, "parentPageId", context);
            if parent_database_id.is_none() && parent_page_id.is_none() {
                return Err("Parent database or page ID is required".to_string());
            }
            let title = read_optional(&params, "title", context);
            let mut properties = build_properties(&params, context)?;
            if let Some(title_value) = title {
                properties
                    .entry("title".to_string())
                    .or_insert_with(|| build_text_property("title", &title_value));
            }
            if properties.is_empty() {
                return Err("A title or properties are required to create a page".to_string());
            }
            let response = notion::create_page(
                client,
                &access_token,
                parent_database_id.as_deref(),
                parent_page_id.as_deref(),
                Value::Object(properties),
            )
            .await
            .map_err(map_notion_error)?;
            Ok((page_summary(&response), None))
        }
        "query_database" => {
            let database_id = read_required(&params, "databaseId", "Database ID", context)?;
            let filter = build_query_filter(&params, context)?;
            let limit = read_limit(&params, context).unwrap_or(DEFAULT_QUERY_PAGE_SIZE);
            let response = notion::query_database(
                client,
                &access_token,
                &database_id,
                filter,
                None,
                None,
                Some(limit),
            )
            .await
            .map_err(map_notion_error)?;

            let results = response
                .results
                .into_iter()
                .map(|page| page_summary(&page))
                .collect::<Vec<_>>();
            Ok((
                json!({
                    "results": results,
                    "has_more": response.has_more,
                    "next_cursor": response.next_cursor
                }),
                None,
            ))
        }
        _ => Err("Unsupported Notion operation".to_string()),
    }
}

async fn resolve_access_token(
    state: &AppState,
    run: &WorkflowRun,
    usage: &super::NodeConnectionUsage,
) -> Result<String, String> {
    match usage {
        super::NodeConnectionUsage::Workspace(info) => {
            let workspace_id = run.workspace_id.ok_or_else(|| {
                "This workflow is not associated with a workspace. Promote the Notion connection to the workspace or switch to a personal connection.".to_string()
            })?;
            ensure_run_membership(state, workspace_id, run.user_id).await?;
            ensure_workspace_plan(state, workspace_id).await?;

            let connection = state
                .workspace_oauth
                .ensure_valid_workspace_token(info.connection_id)
                .await
                .map_err(map_workspace_oauth_error)?;

            if connection.workspace_id != workspace_id {
                return Err("The selected Notion connection belongs to another workspace".into());
            }
            if connection.provider != ConnectedOAuthProvider::Notion {
                return Err("Selected connection is not a Notion connection".into());
            }

            Ok(connection.access_token)
        }
        super::NodeConnectionUsage::User(info) => {
            let connection_id = info.connection_id.as_ref().ok_or_else(|| {
                "Personal OAuth connections require an explicit connectionId. Please select a specific OAuth connection from your integrations.".to_string()
            })?;

            let parsed = Uuid::parse_str(connection_id).map_err(|_| {
                "Personal connectionId must be a valid UUID. Please select a valid OAuth connection.".to_string()
            })?;

            let token = state
                .oauth_accounts
                .ensure_valid_access_token_for_connection(run.user_id, parsed)
                .await
                .map_err(map_oauth_error)?;

            if token.provider != ConnectedOAuthProvider::Notion {
                return Err("Selected connection is not a Notion connection".into());
            }

            Ok(token.access_token)
        }
    }
}

fn read_required(
    params: &Value,
    key: &str,
    label: &str,
    context: &Value,
) -> Result<String, String> {
    let raw = params
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| templ_str(s, context).trim().to_string())
        .unwrap_or_default();
    if raw.is_empty() {
        return Err(format!("{label} is required"));
    }
    Ok(raw)
}

fn read_optional(params: &Value, key: &str, context: &Value) -> Option<String> {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| templ_str(s, context).trim().to_string())
        .filter(|s| !s.is_empty())
}

fn read_limit(params: &Value, context: &Value) -> Option<u32> {
    let raw = read_optional(params, "limit", context)?;
    raw.parse::<u32>().ok().filter(|val| *val > 0)
}

fn build_query_filter(params: &Value, context: &Value) -> Result<Option<Value>, String> {
    let filter_obj = match params.get("filter") {
        Some(value) => value.as_object().cloned().unwrap_or_default(),
        None => return Ok(None),
    };

    let property = filter_obj
        .get("propertyId")
        .or_else(|| filter_obj.get("property"))
        .and_then(|v| v.as_str())
        .map(|s| templ_str(s, context).trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Filter property is required".to_string())?;

    let property_type = filter_obj
        .get("propertyType")
        .or_else(|| filter_obj.get("type"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "rich_text".to_string());

    let operator = filter_obj
        .get("operator")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "equals".to_string());

    let raw_value = filter_obj.get("value").cloned().unwrap_or(Value::Null);
    let filter = match operator.as_str() {
        "equals" => build_filter_equals(&property_type, &raw_value, context)?,
        "contains" => build_filter_contains(&property_type, &raw_value, context)?,
        "is_empty" => build_filter_empty(&property_type, true),
        "is_not_empty" => build_filter_empty(&property_type, false),
        _ => return Err("Unsupported filter operator".to_string()),
    };

    Ok(Some(json!({
        "property": property,
        property_type: filter
    })))
}

fn build_filter_equals(
    property_type: &str,
    raw_value: &Value,
    context: &Value,
) -> Result<Value, String> {
    match property_type {
        "number" => {
            let number = parse_number(raw_value, context)?;
            Ok(json!({ "equals": number }))
        }
        "checkbox" => {
            let flag = parse_bool(raw_value, context)?;
            Ok(json!({ "equals": flag }))
        }
        "select" => {
            let value = parse_string(raw_value, context)?;
            Ok(json!({ "equals": value }))
        }
        "multi_select" => {
            let value = parse_string(raw_value, context)?;
            Ok(json!({ "contains": value }))
        }
        "date" => {
            let value = parse_string(raw_value, context)?;
            Ok(json!({ "equals": value }))
        }
        _ => {
            let value = parse_string(raw_value, context)?;
            Ok(json!({ "equals": value }))
        }
    }
}

fn build_filter_contains(
    property_type: &str,
    raw_value: &Value,
    context: &Value,
) -> Result<Value, String> {
    let value = parse_string(raw_value, context)?;
    match property_type {
        "select" => Ok(json!({ "equals": value })),
        "multi_select" => Ok(json!({ "contains": value })),
        _ => Ok(json!({ "contains": value })),
    }
}

fn build_filter_empty(property_type: &str, is_empty: bool) -> Value {
    match property_type {
        "checkbox" => json!({ "equals": !is_empty }),
        _ => {
            if is_empty {
                json!({ "is_empty": true })
            } else {
                json!({ "is_not_empty": true })
            }
        }
    }
}

fn build_properties(params: &Value, context: &Value) -> Result<Map<String, Value>, String> {
    let Some(props) = params.get("properties") else {
        return Ok(Map::new());
    };
    let props_obj = props
        .as_object()
        .ok_or_else(|| "Properties must be an object".to_string())?;
    let mut output = Map::new();

    for (key, entry) in props_obj {
        let property_key = key.trim();
        if property_key.is_empty() {
            continue;
        }
        let (property_type, value) = match entry.as_object() {
            Some(obj) => {
                let property_type = obj
                    .get("type")
                    .or_else(|| obj.get("propertyType"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim().to_ascii_lowercase())
                    .ok_or_else(|| format!("Property type is required for `{property_key}`"))?;
                let raw_value = obj.get("value").cloned().unwrap_or(Value::Null);
                (property_type, raw_value)
            }
            None => {
                return Err(format!(
                    "Property `{property_key}` must include a type and value"
                ));
            }
        };

        if should_skip_property(&value) {
            continue;
        }

        let property_value = match property_type.as_str() {
            "title" => {
                let value = parse_string(&value, context)?;
                build_text_property("title", &value)
            }
            "rich_text" => {
                let value = parse_string(&value, context)?;
                build_text_property("rich_text", &value)
            }
            "number" => {
                let number = parse_number(&value, context)?;
                json!({ "number": number })
            }
            "select" => build_select_property(&value, context)?,
            "multi_select" => build_multi_select_property(&value, context)?,
            "date" => build_date_property(&value, context)?,
            "checkbox" => {
                let flag = parse_bool(&value, context)?;
                json!({ "checkbox": flag })
            }
            _ => {
                return Err(format!(
                    "Unsupported Notion property type `{}`",
                    property_type
                ))
            }
        };

        output.insert(property_key.to_string(), property_value);
    }

    Ok(output)
}

fn should_skip_property(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(s) => s.trim().is_empty(),
        Value::Array(arr) => arr.is_empty(),
        Value::Object(map) => map.is_empty(),
        _ => false,
    }
}

fn build_text_property(kind: &str, value: &str) -> Value {
    json!({
        kind: [{
            "text": {
                "content": value
            }
        }]
    })
}

fn build_select_property(value: &Value, context: &Value) -> Result<Value, String> {
    if let Value::Object(map) = value {
        if let Some(id) = map.get("id").and_then(|v| v.as_str()) {
            let id = templ_str(id, context);
            return Ok(json!({ "select": { "id": id } }));
        }
        if let Some(name) = map.get("name").and_then(|v| v.as_str()) {
            let name = templ_str(name, context);
            return Ok(json!({ "select": { "name": name } }));
        }
    }

    let name = parse_string(value, context)?;
    Ok(json!({ "select": { "name": name } }))
}

fn build_multi_select_property(value: &Value, context: &Value) -> Result<Value, String> {
    let entries: Vec<Value> = match value {
        Value::Array(arr) => arr
            .iter()
            .filter_map(|entry| match entry {
                Value::Object(map) => {
                    if let Some(id) = map.get("id").and_then(|v| v.as_str()) {
                        let id = templ_str(id, context);
                        return Some(json!({ "id": id }));
                    }
                    map.get("name")
                        .and_then(|v| v.as_str())
                        .map(|name| json!({ "name": templ_str(name, context) }))
                }
                Value::String(name) => {
                    let name = templ_str(name, context);
                    if name.trim().is_empty() {
                        None
                    } else {
                        Some(json!({ "name": name }))
                    }
                }
                _ => None,
            })
            .collect(),
        Value::String(raw) => raw
            .split(',')
            .map(|entry| templ_str(entry.trim(), context))
            .filter(|entry| !entry.trim().is_empty())
            .map(|entry| json!({ "name": entry }))
            .collect(),
        _ => Vec::new(),
    };

    if entries.is_empty() {
        return Err("Multi-select values must include at least one option".to_string());
    }

    Ok(json!({ "multi_select": entries }))
}

fn build_date_property(value: &Value, context: &Value) -> Result<Value, String> {
    if let Value::Object(map) = value {
        let mut payload = Map::new();
        for key in ["start", "end", "time_zone"] {
            if let Some(raw) = map.get(key).and_then(|v| v.as_str()) {
                let rendered = templ_str(raw, context);
                if !rendered.trim().is_empty() {
                    payload.insert(key.to_string(), Value::String(rendered));
                }
            }
        }
        if payload.is_empty() {
            return Err("Date value is required".to_string());
        }
        return Ok(json!({ "date": payload }));
    }

    let date = parse_string(value, context)?;
    Ok(json!({ "date": { "start": date } }))
}

fn parse_string(value: &Value, context: &Value) -> Result<String, String> {
    match value {
        Value::String(raw) => {
            let rendered = templ_str(raw, context);
            let trimmed = rendered.trim();
            if trimmed.is_empty() {
                Err("Value must be a non-empty string".to_string())
            } else {
                Ok(trimmed.to_string())
            }
        }
        Value::Number(num) => Ok(num.to_string()),
        Value::Bool(flag) => Ok(flag.to_string()),
        _ => Err("Value must be a string".to_string()),
    }
}

fn parse_number(value: &Value, context: &Value) -> Result<f64, String> {
    match value {
        Value::Number(num) => num
            .as_f64()
            .ok_or_else(|| "Number value is invalid".to_string()),
        Value::String(raw) => {
            let rendered = templ_str(raw, context);
            rendered
                .trim()
                .parse::<f64>()
                .map_err(|_| "Number value is invalid".to_string())
        }
        _ => Err("Number value is required".to_string()),
    }
}

fn parse_bool(value: &Value, context: &Value) -> Result<bool, String> {
    match value {
        Value::Bool(flag) => Ok(*flag),
        Value::String(raw) => {
            let rendered = templ_str(raw, context);
            match rendered.trim().to_ascii_lowercase().as_str() {
                "true" | "1" | "yes" => Ok(true),
                "false" | "0" | "no" => Ok(false),
                _ => Err("Checkbox value must be true or false".to_string()),
            }
        }
        _ => Err("Checkbox value must be true or false".to_string()),
    }
}

fn page_summary(page: &Value) -> Value {
    json!({
        "page_id": page.get("id").and_then(|v| v.as_str()).unwrap_or_default(),
        "url": page.get("url").and_then(|v| v.as_str()).unwrap_or_default(),
        "created_time": page.get("created_time").and_then(|v| v.as_str()).unwrap_or_default(),
        "last_edited_time": page.get("last_edited_time").and_then(|v| v.as_str()).unwrap_or_default(),
    })
}

fn map_oauth_error(err: OAuthAccountError) -> String {
    match err {
        OAuthAccountError::NotFound => "No Notion OAuth connection found".to_string(),
        OAuthAccountError::TokenRevoked { .. } => {
            "The Notion connection was revoked. Reconnect in Settings -> Integrations.".to_string()
        }
        other => format!("Notion OAuth error: {other}"),
    }
}

fn map_workspace_oauth_error(err: WorkspaceOAuthError) -> String {
    match err {
        WorkspaceOAuthError::Forbidden => {
            "You no longer have access to this workspace connection.".to_string()
        }
        WorkspaceOAuthError::NotFound => "Notion workspace connection not found.".to_string(),
        WorkspaceOAuthError::SlackInstallRequired => {
            "Slack connections must be installed at workspace scope.".to_string()
        }
        WorkspaceOAuthError::OAuth(inner) => map_oauth_error(inner),
        WorkspaceOAuthError::Database(err) => format!("Failed to load workspace connection: {err}"),
        WorkspaceOAuthError::Encryption(err) => {
            format!("Failed to decrypt workspace connection: {err}")
        }
    }
}

fn map_notion_error(err: NotionError) -> String {
    if err.is_auth_error() {
        return "Notion authentication failed. Reconnect the integration.".to_string();
    }
    match err {
        NotionError::Api {
            status, message, ..
        } => {
            format!("Notion API error ({}): {}", status.as_u16(), message)
        }
        other => format!("Notion API error: {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use async_trait::async_trait;
    use httpmock::MockServer;
    use once_cell::sync::Lazy;
    use reqwest::Client;
    use std::sync::Arc;
    use std::sync::MutexGuard;
    use time::{Duration as TimeDuration, OffsetDateTime};

    use crate::config::{
        Config, OAuthProviderConfig, OAuthSettings, StripeSettings, DEFAULT_WORKSPACE_MEMBER_LIMIT,
        DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT, RUNAWAY_LIMIT_5MIN,
    };
    use crate::db::mock_db::{MockDb, NoopWorkflowRepository, NoopWorkspaceRepository};
    use crate::db::mock_stripe_event_log_repository::MockStripeEventLogRepository;
    use crate::db::oauth_token_repository::{NewUserOAuthToken, UserOAuthTokenRepository};
    use crate::db::workspace_connection_repository::NoopWorkspaceConnectionRepository;
    use crate::models::oauth_token::UserOAuthToken;
    use crate::services::oauth::account_service::OAuthAccountService;
    use crate::services::oauth::github::mock_github_oauth::MockGitHubOAuth;
    use crate::services::oauth::google::mock_google_oauth::MockGoogleOAuth;
    use crate::services::oauth::workspace_service::WorkspaceOAuthService;
    use crate::services::smtp_mailer::MockMailer;
    use crate::state::{test_pg_pool, AppState};
    use crate::utils::encryption::encrypt_secret;
    use crate::utils::jwt::JwtKeys;

    static ENV_LOCK: Lazy<std::sync::Mutex<()>> = Lazy::new(|| std::sync::Mutex::new(()));

    struct EnvGuard {
        key: &'static str,
        previous: Option<String>,
        _lock: MutexGuard<'static, ()>,
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
                token_encryption_key: vec![1u8; 32],
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

    fn test_state(oauth_accounts: Arc<OAuthAccountService>, http_client: Arc<Client>) -> AppState {
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
            stripe: Arc::new(crate::services::stripe::MockStripeService::new()),
            http_client,
            config: test_config(),
            worker_id: Arc::new("worker".to_string()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        }
    }

    fn oauth_service_with_token(user_id: Uuid) -> (Arc<OAuthAccountService>, Uuid) {
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
        let encrypted_access = encrypt_secret(&key, "access-token").unwrap();
        let encrypted_refresh = encrypt_secret(&key, "refresh-token").unwrap();
        let now = OffsetDateTime::now_utc();

        let record_id = Uuid::new_v4();
        let record = UserOAuthToken {
            id: record_id,
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Notion,
            access_token: encrypted_access,
            refresh_token: encrypted_refresh,
            expires_at: now + TimeDuration::hours(2),
            account_email: "notion@example.com".into(),
            metadata: serde_json::json!({}),
            is_shared: false,
            created_at: now,
            updated_at: now,
        };

        let repo = Arc::new(StaticRepo { record });
        let workspace_repo: Arc<
            dyn crate::db::workspace_connection_repository::WorkspaceConnectionRepository,
        > = Arc::new(NoopWorkspaceConnectionRepository);
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
    async fn create_database_row_builds_properties_payload() {
        let server = MockServer::start();
        let _env = EnvGuard::set("NOTION_API_BASE_URL", server.url(""));
        let mock = server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/pages")
                .json_body(json!({
                    "parent": { "database_id": "db-1" },
                    "properties": {
                        "prop-title": {
                            "title": [{ "text": { "content": "Hello" } }]
                        },
                        "prop-number": { "number": 42.0 }
                    }
                }));
            then.status(200).json_body(json!({
                "id": "page-1",
                "url": "https://notion.so/page-1",
                "created_time": "2024-01-01T00:00:00Z",
                "last_edited_time": "2024-01-01T00:00:00Z"
            }));
        });

        let user_id = Uuid::new_v4();
        let (oauth_accounts, connection_id) = oauth_service_with_token(user_id);
        let state = test_state(oauth_accounts, Arc::new(Client::new()));
        let run = sample_run(user_id);

        let node = Node {
            id: "notion-create".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "operation": "create_database_row",
                    "connectionScope": "personal",
                    "connectionId": connection_id.to_string(),
                    "databaseId": "db-1",
                    "properties": {
                        "prop-title": { "type": "title", "value": "Hello" },
                        "prop-number": { "type": "number", "value": 42 }
                    }
                }
            }),
        };

        let (output, _) = execute_notion(&node, &json!({}), &state, &run)
            .await
            .expect("create page");

        mock.assert();
        assert_eq!(
            output.get("page_id").and_then(|v| v.as_str()),
            Some("page-1")
        );
    }

    #[tokio::test]
    async fn query_database_builds_filter_payload() {
        let server = MockServer::start();
        let _env = EnvGuard::set("NOTION_API_BASE_URL", server.url(""));
        let mock = server.mock(|when, then| {
            when.method(httpmock::Method::POST)
                .path("/databases/db-2/query")
                .json_body(json!({
                    "filter": {
                        "property": "Status",
                        "select": { "equals": "Done" }
                    },
                    "page_size": 5
                }));
            then.status(200).json_body(json!({
                "results": [{
                    "id": "page-2",
                    "url": "https://notion.so/page-2",
                    "created_time": "2024-01-02T00:00:00Z",
                    "last_edited_time": "2024-01-02T00:00:00Z"
                }],
                "has_more": false,
                "next_cursor": null
            }));
        });

        let user_id = Uuid::new_v4();
        let (oauth_accounts, connection_id) = oauth_service_with_token(user_id);
        let state = test_state(oauth_accounts, Arc::new(Client::new()));
        let run = sample_run(user_id);

        let node = Node {
            id: "notion-query".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "operation": "query_database",
                    "connectionScope": "personal",
                    "connectionId": connection_id.to_string(),
                    "databaseId": "db-2",
                    "filter": {
                        "propertyId": "Status",
                        "propertyType": "select",
                        "operator": "equals",
                        "value": "Done"
                    },
                    "limit": "5"
                }
            }),
        };

        let (output, _) = execute_notion(&node, &json!({}), &state, &run)
            .await
            .expect("query database");

        mock.assert();
        let results = output.get("results").and_then(|v| v.as_array()).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].get("page_id").and_then(|v| v.as_str()),
            Some("page-2")
        );
    }
}
