use crate::engine::actions::ensure_workspace_plan;
use crate::engine::actions::registry::{ActionExecutionSemantics, ActionManifest, ActionValidator};
use crate::engine::actions::validate_required_fields;
use crate::engine::graph::Node;
use crate::engine::templating::templ_str;
use crate::models::oauth_token::ConnectedOAuthProvider;
use crate::models::workflow_run::WorkflowRun;
use crate::services::oauth::account_service::{is_revocation_signal, OAuthAccountError};
use crate::services::oauth::workspace_service::WorkspaceOAuthError;
use crate::state::AppState;
use crate::utils::encryption::decrypt_secret;
use reqwest::{
    header::{HeaderMap, HeaderName, HeaderValue},
    Url,
};
use serde::Serialize;
use serde_json::{json, Map, Value};
use std::collections::HashSet;
use tracing::{info, warn};
use urlencoding::encode;
use uuid::Uuid;

use super::{ensure_run_membership, resolve_connection_usage, NodeConnectionUsage};

const MESSAGING_REQUIRED_FIELDS: &[&str] = &["params"];

pub(crate) const MANIFEST: ActionManifest = ActionManifest {
    action_type: "messaging",
    required_fields: MESSAGING_REQUIRED_FIELDS,
    execution_semantics: ActionExecutionSemantics::Standard,
};

pub(crate) const TEAMS_MANIFEST: ActionManifest = ActionManifest {
    action_type: "teams",
    required_fields: MESSAGING_REQUIRED_FIELDS,
    execution_semantics: ActionExecutionSemantics::Standard,
};

pub(crate) const SLACK_MANIFEST: ActionManifest = ActionManifest {
    action_type: "slack",
    required_fields: MESSAGING_REQUIRED_FIELDS,
    execution_semantics: ActionExecutionSemantics::Standard,
};

pub(crate) const GOOGLECHAT_MANIFEST: ActionManifest = ActionManifest {
    action_type: "googlechat",
    required_fields: MESSAGING_REQUIRED_FIELDS,
    execution_semantics: ActionExecutionSemantics::Standard,
};

pub(crate) const MICROSOFTTEAMS_MANIFEST: ActionManifest = ActionManifest {
    action_type: "microsoftteams",
    required_fields: MESSAGING_REQUIRED_FIELDS,
    execution_semantics: ActionExecutionSemantics::Standard,
};

pub(crate) struct MessagingValidator;

impl ActionValidator for MessagingValidator {
    fn validate(&self, node: &Node) -> Result<(), String> {
        validate_required_fields(node, MANIFEST.required_fields)
    }
}

const DEFAULT_MICROSOFT_GRAPH_BASE_URL: &str = "https://graph.microsoft.com/v1.0";

#[inline]
fn gating_enabled() -> bool {
    #[cfg(test)]
    {
        false
    }
    #[cfg(not(test))]
    {
        true
    }
}

pub(crate) async fn execute_messaging(
    node: &Node,
    context: &Value,
    state: &AppState,
    run: &WorkflowRun,
) -> Result<(Value, Option<String>), String> {
    let params = node.data.get("params").cloned().unwrap_or(Value::Null);
    let platform = infer_messaging_platform(&params, node)?;

    // Hard premium gate for Slack and Teams (disabled under tests)
    if gating_enabled() {
        match platform {
            MessagingPlatform::GoogleChat => {
                // allowed on solo plan, no workspace context needed
            }
            MessagingPlatform::Slack | MessagingPlatform::Teams => {
                let workspace_id = run.workspace_id.ok_or_else(|| {
                    "Slack and Teams messaging require a workspace plan".to_string()
                })?;

                ensure_run_membership(state, workspace_id, run.user_id).await?;
                ensure_workspace_plan(state, workspace_id).await?;
            }
        }
    }

    match platform {
        MessagingPlatform::Slack => send_slack(&params, context, state, run).await,
        MessagingPlatform::Teams => send_teams(node, &params, context, state, run).await,
        MessagingPlatform::GoogleChat => send_google_chat(&params, context).await,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MessagingPlatform {
    Slack,
    Teams,
    GoogleChat,
}

fn infer_messaging_platform(params: &Value, node: &Node) -> Result<MessagingPlatform, String> {
    if let Some(platform) = params
        .get("platform")
        .and_then(|v| v.as_str())
        .and_then(detect_platform)
    {
        return Ok(platform);
    }

    let mut fallbacks: Vec<&str> = Vec::new();

    if let Some(value) = params.get("service").and_then(|v| v.as_str()) {
        fallbacks.push(value);
    }
    if let Some(value) = params.get("provider").and_then(|v| v.as_str()) {
        fallbacks.push(value);
    }
    if let Some(value) = node.data.get("nodeType").and_then(|v| v.as_str()) {
        fallbacks.push(value);
    }
    if let Some(value) = node.data.get("actionKey").and_then(|v| v.as_str()) {
        fallbacks.push(value);
    }
    if let Some(value) = node.data.get("actionType").and_then(|v| v.as_str()) {
        fallbacks.push(value);
    }
    if let Some(value) = node.data.get("label").and_then(|v| v.as_str()) {
        fallbacks.push(value);
    }
    fallbacks.push(node.kind.as_str());

    for candidate in fallbacks {
        if let Some(platform) = detect_platform(candidate) {
            return Ok(platform);
        }
    }

    params
        .get("platform")
        .and_then(|v| v.as_str())
        .map(|raw| raw.trim())
        .filter(|raw| !raw.is_empty())
        .map(|raw| format!("Unsupported messaging platform: {}", raw))
        .map(Err)
        .unwrap_or_else(|| Err("Platform is required".to_string()))
}

fn detect_platform(raw: &str) -> Option<MessagingPlatform> {
    let normalized = raw.to_lowercase();
    if normalized.contains("slack") {
        return Some(MessagingPlatform::Slack);
    }
    if normalized.contains("teams") || normalized.contains("microsoft") {
        return Some(MessagingPlatform::Teams);
    }
    if normalized.contains("googlechat")
        || (normalized.contains("google") && normalized.contains("chat"))
    {
        return Some(MessagingPlatform::GoogleChat);
    }
    None
}

fn extract_required_str<'a>(params: &'a Value, key: &str, field: &str) -> Result<&'a str, String> {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("{} is required", field))
}

enum SlackConnectionContext {
    Personal {
        user_id: Uuid,
        connection_id: Uuid,
    },
    Workspace {
        workspace_id: Uuid,
        connection_id: Uuid,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SlackIdentity {
    WorkspaceBot,
    PersonalUser,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SlackAuthExpiredPayload {
    #[serde(rename = "type")]
    error_type: &'static str,
    connection_id: Uuid,
}

fn slack_auth_expired_error(connection_id: Uuid) -> String {
    serde_json::to_string(&SlackAuthExpiredPayload {
        error_type: "auth_expired",
        connection_id,
    })
    .unwrap_or_else(|_| "auth_expired".to_string())
}

fn decode_slack_team_id(raw: &str, encryption_key: &[u8]) -> Result<String, ()> {
    let decrypted = decrypt_secret(encryption_key, raw).unwrap_or_else(|_| raw.to_string());
    let trimmed = decrypted.trim();
    if is_valid_slack_team_id(trimmed) {
        Ok(trimmed.to_string())
    } else {
        Err(())
    }
}

fn is_valid_slack_team_id(value: &str) -> bool {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 1 {
        return false;
    }
    if chars[0] != 'T' {
        return false;
    }
    chars.iter().all(|ch| matches!(ch, 'A'..='Z' | '0'..='9'))
}

async fn send_slack(
    params: &Value,
    context: &Value,
    state: &AppState,
    run: &WorkflowRun,
) -> Result<(Value, Option<String>), String> {
    let identity_param = params
        .get("identity")
        .and_then(|value| value.as_str())
        .map(|value| value.trim())
        .filter(|value| !value.is_empty());
    let legacy_post_as_user = params.get("postAsUser").and_then(|value| value.as_bool());

    let identity = match identity_param {
        Some("workspace_bot") => Some(SlackIdentity::WorkspaceBot),
        Some("personal_user") => Some(SlackIdentity::PersonalUser),
        Some(_) => {
            return Err(
                "identity selection error: identity must be 'workspace_bot' or 'personal_user'"
                    .to_string(),
            );
        }
        None => None,
    };

    let identity = match (identity, legacy_post_as_user) {
        (Some(identity), Some(legacy)) => {
            let legacy_identity = if legacy {
                SlackIdentity::PersonalUser
            } else {
                SlackIdentity::WorkspaceBot
            };
            if identity != legacy_identity {
                return Err(
                    "identity selection error: identity does not match postAsUser".to_string(),
                );
            }
            Some(identity)
        }
        (Some(identity), None) => Some(identity),
        (None, Some(legacy)) => Some(if legacy {
            SlackIdentity::PersonalUser
        } else {
            SlackIdentity::WorkspaceBot
        }),
        (None, None) => None,
    };

    let identity = identity.ok_or_else(|| {
        "identity selection error: no explicit identity provided. Provide identity='workspace_bot' or identity='personal_user'.".to_string()
    })?;

    // allow connection info to be provided either as a `connection` object or top-level
    // (they may be duplicated by the sanitizer). Do not treat this as specifying two identities.

    // Resolve explicit connection usage. If none present, do NOT attempt any
    // workspace-scoped inference — engine must require an explicit identity.
    let connection_usage = match resolve_connection_usage(params) {
        Ok(u) => u,
        Err(_) => {
            // If caller attempted to request workspace scope but omitted connectionId,
            // fail immediately and explicitly. Do not probe repositories or refresh tokens.
            let connection_obj = params.get("connection").and_then(|v| v.as_object());
            let scope_opt = connection_obj
                .and_then(|o| o.get("connectionScope"))
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_ascii_lowercase())
                .or_else(|| {
                    params
                        .get("connectionScope")
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().to_ascii_lowercase())
                });

            let id_opt = connection_obj
                .and_then(|o| o.get("connectionId"))
                .and_then(|v| v.as_str())
                .or_else(|| params.get("connectionId").and_then(|v| v.as_str()));

            if scope_opt.as_deref() == Some("workspace") && id_opt.is_none() {
                return Err("workspace_bot error: workspace Slack execution requires an explicit connectionId".to_string());
            }

            return Err("identity selection error: connectionScope and connectionId are required for Slack execution.".to_string());
        }
    };

    let mut output_connection_scope: Option<String> = None;
    let mut output_connection_id: Option<Uuid> = None;

    let (token, token_email, connection_context) = match connection_usage {
        NodeConnectionUsage::Workspace(info) => {
            if identity == SlackIdentity::PersonalUser {
                return Err("personal_user error: a workspace connection was supplied, but identity is personal_user. Select a personal Slack connection.".to_string());
            }
            let workspace_id = run.workspace_id.ok_or_else(|| {
                    "This workflow run is not associated with a workspace. Promote the Slack connection to the workspace or switch the action back to a personal connection.".to_string()
                })?;

            ensure_run_membership(state, workspace_id, run.user_id).await?;
            ensure_workspace_plan(state, workspace_id).await?;

            let connection = state
                .workspace_oauth
                .ensure_valid_workspace_token(info.connection_id)
                .await
                .map_err(|e| format!("workspace_bot: {}", map_workspace_slack_error(e)))?;

            // Reject webhook-only connections: presence of an incoming_webhook_url must not enable execution
            if connection
                .incoming_webhook_url
                .as_deref()
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false)
                && connection.access_token.trim().is_empty()
            {
                return Err("workspace_bot error: selected workspace connection is webhook-only; incoming webhooks are not permitted for execution. Provide a workspace-scoped OAuth connection with a bot token.".to_string());
            }

            if connection.workspace_id != workspace_id {
                return Err("workspace_bot error: selected workspace connection does not belong to this workspace".to_string());
            }

            if connection.provider != ConnectedOAuthProvider::Slack {
                return Err(
                    "workspace_bot error: selected connection is not a Slack connection"
                        .to_string(),
                );
            }

            // Ensure the workspace connection has a Slack team id
            let conn_team = connection
                .slack_team_id
                .as_deref()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());

            let conn_team = match conn_team {
                Some(t) => t,
                None => {
                    return Err(
                        "workspace_bot error: selected workspace connection missing Slack team id"
                            .to_string(),
                    );
                }
            };

            // Detect multiple configured Slack teams for this workspace (mixing teams is forbidden)
            match state
                .workspace_connection_repo
                .list_by_workspace_and_provider(workspace_id, ConnectedOAuthProvider::Slack)
                .await
            {
                Ok(listings) => {
                    let mut teams: HashSet<String> = HashSet::new();
                    for l in listings.into_iter() {
                        if let Some(t) = l.slack_team_id.as_deref() {
                            let t = t.trim().to_string();
                            if !t.is_empty() {
                                teams.insert(t);
                            }
                        }
                    }
                    if teams.len() > 1 {
                        return Err("workspace_bot error: multiple Slack teams configured for this workspace; mixing Slack teams within a workspace is forbidden".to_string());
                    }
                    // Ensure selected connection's team is consistent with workspace (if workspace has a single team)
                    if teams.len() == 1 && !teams.contains(&conn_team) {
                        return Err("workspace_bot error: selected workspace connection's Slack team does not match the workspace".to_string());
                    }
                }
                Err(_) => {
                    return Err(
                        "workspace_bot error: failed to verify workspace Slack connections"
                            .to_string(),
                    );
                }
            }

            output_connection_scope = Some("workspace".to_string());
            output_connection_id = Some(connection.id);

            (
                connection.access_token.clone(),
                Some(connection.account_email.clone()),
                Some(SlackConnectionContext::Workspace {
                    workspace_id,
                    connection_id: connection.id,
                }),
            )
        }
        NodeConnectionUsage::User(info) => {
            if identity == SlackIdentity::WorkspaceBot {
                return Err("workspace_bot error: a personal connection was supplied, but identity is workspace_bot. Select a workspace Slack connection.".to_string());
            }

            let connection_id_str = info.connection_id.ok_or_else(|| {
                    "personal_user error: Personal OAuth connections require an explicit connectionId. Please select a specific OAuth connection from your integrations.".to_string()
                })?;

            let connection_id = Uuid::parse_str(&connection_id_str).map_err(|_| {
                "personal_user error: connectionId must be a valid UUID. Please select a valid OAuth connection.".to_string()
            })?;

            let workspace_id = run.workspace_id.ok_or_else(|| {
                "personal_user error: Slack personal posting requires a workspace context."
                    .to_string()
            })?;

            let workspace_connection_id = params
                .get("workspace_connection_id")
                .and_then(|value| value.as_str())
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    "personal_user error: workspace_connection_id is required for Slack execution."
                        .to_string()
                })?;
            let workspace_connection_id =
                Uuid::parse_str(workspace_connection_id).map_err(|_| {
                    "personal_user error: workspace_connection_id must be a valid UUID.".to_string()
                })?;

            let token = state
                    .oauth_accounts
                    .ensure_valid_access_token_for_connection(run.user_id, connection_id)
                    .await
                    .map_err(|err| match err {
                        OAuthAccountError::NotFound => {
                            "personal_user error: connect Slack integration before selecting an OAuth connection".to_string()
                        }
                        OAuthAccountError::TokenRevoked { .. } => {
                            "personal_user error: the connected Slack account was revoked. Reconnect it from Settings → Integrations.".to_string()
                        }
                        other => format!("personal_user error: failed to refresh Slack OAuth token: {other}"),
                    })?;

            // Load personal token metadata and extract Slack team id
            let metadata = state
                .oauth_accounts
                .load_personal_token_metadata(run.user_id, token.id)
                .await
                .map_err(|_| {
                    "personal_user error: Failed to load personal token metadata".to_string()
                })?;

            let personal_team_id = metadata.slack.and_then(|s| s.team_id);
            let personal_team = match personal_team_id {
                Some(value) => decode_slack_team_id(&value, &state.config.oauth.token_encryption_key)
                    .map_err(|_| {
                        "personal_user error: personal Slack token missing or invalid team id. Reconnect Slack."
                            .to_string()
                    })?,
                None => {
                    return Err(
                        "personal_user error: personal Slack token missing or invalid team id. Reconnect Slack."
                            .to_string(),
                    );
                }
            };

            let workspace_connection = state
                .workspace_connection_repo
                .find_by_id(workspace_connection_id)
                .await
                .map_err(|_| {
                    "personal_user error: failed to load workspace Slack connection".to_string()
                })?
                .ok_or_else(|| {
                    "personal_user error: selected workspace Slack connection is no longer available"
                        .to_string()
                })?;

            if workspace_connection.workspace_id != workspace_id {
                return Err("personal_user error: selected workspace connection does not belong to this workspace".to_string());
            }

            if workspace_connection.provider != ConnectedOAuthProvider::Slack {
                return Err(
                    "personal_user error: selected workspace connection is not a Slack connection"
                        .to_string(),
                );
            }

            let workspace_team = workspace_connection
                .slack_team_id
                .as_deref()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .ok_or_else(|| {
                    "personal_user error: selected workspace connection missing Slack team id"
                        .to_string()
                })?;

            if personal_team != workspace_team {
                return Err(format!(
                    "personal_user error: Slack team mismatch between personal token ({}) and workspace Slack connection ({})",
                    personal_team, workspace_team
                ));
            }

            match state
                .workspace_connection_repo
                .list_by_workspace_and_provider(workspace_id, ConnectedOAuthProvider::Slack)
                .await
            {
                Ok(listings) => {
                    let mut teams: HashSet<String> = HashSet::new();
                    for l in listings.into_iter() {
                        if let Some(t) = l.slack_team_id.as_deref() {
                            let t = t.trim().to_string();
                            if !t.is_empty() {
                                teams.insert(t);
                            }
                        }
                    }

                    if teams.len() > 1 {
                        return Err("personal_user error: multiple Slack teams configured for this workspace; mixing Slack teams within a workspace is forbidden".to_string());
                    }
                }
                Err(_) => {
                    return Err(
                        "personal_user error: failed to verify workspace Slack connections"
                            .to_string(),
                    );
                }
            }

            (
                token.access_token.clone(),
                Some(token.account_email.clone()),
                Some(SlackConnectionContext::Personal {
                    user_id: run.user_id,
                    connection_id: token.id,
                }),
            )
        }
    };

    let channel_raw = extract_required_str(params, "channel", "Slack channel")?;
    let message_raw = extract_required_str(params, "message", "Message")?;

    let channel = templ_str(channel_raw, context);
    if channel.trim().is_empty() {
        return Err("Slack channel is required".to_string());
    }

    let message = templ_str(message_raw, context);
    if message.trim().is_empty() {
        return Err("Message is required".to_string());
    }

    let base = std::env::var("SLACK_API_BASE")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "https://slack.com/api".to_string());
    let url = format!("{}/chat.postMessage", base.trim_end_matches('/'));

    let mut access_token = token;
    let mut refreshed_once = false;

    let (status, parsed) = loop {
        let response = state
            .http_client
            .post(&url)
            .bearer_auth(&access_token)
            .json(&json!({ "channel": channel, "text": message }))
            .send()
            .await
            .map_err(|e| format!("Slack request failed: {e}"))?;

        let status = response.status();
        let body_text = response
            .text()
            .await
            .map_err(|e| format!("Slack response read failed: {e}"))?;
        let parsed: Option<Value> = serde_json::from_str(&body_text).ok();

        let is_ok = parsed
            .as_ref()
            .and_then(|v| v.get("ok"))
            .and_then(|v| v.as_bool())
            .unwrap_or_else(|| status.is_success());

        if !status.is_success() || !is_ok {
            let slack_error = parsed
                .as_ref()
                .and_then(|v| v.get("error"))
                .and_then(|v| v.as_str())
                .map(|s| s.trim().to_string());

            if slack_error.as_deref() == Some("token_expired") {
                if refreshed_once {
                    if let Some(context) = &connection_context {
                        let connection_id = match context {
                            SlackConnectionContext::Personal { connection_id, .. } => {
                                *connection_id
                            }
                            SlackConnectionContext::Workspace { connection_id, .. } => {
                                *connection_id
                            }
                        };
                        return Err(slack_auth_expired_error(connection_id));
                    }
                    return Err("Slack token expired".to_string());
                }

                if let Some(context) = &connection_context {
                    let refresh_result: Result<(String, Uuid), ()> = match context {
                        SlackConnectionContext::Personal {
                            user_id,
                            connection_id,
                        } => state
                            .oauth_accounts
                            .refresh_access_token_for_connection(*user_id, *connection_id)
                            .await
                            .map(|token| (token.access_token, *connection_id))
                            .map_err(|_| ()),
                        SlackConnectionContext::Workspace { connection_id, .. } => state
                            .workspace_oauth
                            .refresh_slack_workspace_token(*connection_id)
                            .await
                            .map(|conn| (conn.access_token, *connection_id))
                            .map_err(|_| ()),
                    };

                    match refresh_result {
                        Ok((new_token, _)) => {
                            access_token = new_token;
                            refreshed_once = true;
                            continue;
                        }
                        Err(_) => {
                            let connection_id = match context {
                                SlackConnectionContext::Personal { connection_id, .. } => {
                                    *connection_id
                                }
                                SlackConnectionContext::Workspace { connection_id, .. } => {
                                    *connection_id
                                }
                            };
                            return Err(slack_auth_expired_error(connection_id));
                        }
                    }
                } else {
                    return Err("Slack token expired".to_string());
                }
            }

            if let Some(context) = &connection_context {
                if is_revocation_signal(Some(status), &body_text) {
                    match context {
                        SlackConnectionContext::Personal {
                            user_id,
                            connection_id,
                        } => {
                            if let Err(err) = state
                                .oauth_accounts
                                .handle_revoked_token_by_connection(*user_id, *connection_id)
                                .await
                            {
                                warn!(
                                    user_id = %user_id,
                                    error = %err,
                                    "failed to purge revoked personal slack token"
                                );
                            }

                            return Err("personal_user error: Slack revoked the connected account. Reconnect it from Settings → Integrations.".to_string());
                        }
                        SlackConnectionContext::Workspace {
                            workspace_id,
                            connection_id,
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
                                    "failed to remove revoked workspace slack connection"
                                );
                            }

                            return Err("workspace_bot error: Slack revoked the connected account. Reconnect it from Settings → Integrations.".to_string());
                        }
                    }
                }
            }

            let detail = slack_error
                .or_else(|| {
                    let trimmed = body_text.trim();
                    if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed.to_string())
                    }
                })
                .unwrap_or_else(|| "Unknown Slack API error".to_string());
            if let Some(context) = &connection_context {
                let prefix = match context {
                    SlackConnectionContext::Personal { .. } => "personal_user error: ",
                    SlackConnectionContext::Workspace { .. } => "workspace_bot error: ",
                };
                return Err(format!(
                    "{}Slack API error (status {}): {}",
                    prefix,
                    status.as_u16(),
                    detail
                ));
            }

            return Err(format!(
                "Slack API error (status {}): {}",
                status.as_u16(),
                detail
            ));
        }

        break (status, parsed);
    };

    let mut output = json!({
        "sent": true,
        "service": "Slack",
        "platform": "Slack",
        "status": status.as_u16(),
    });

    if let Some(ts) = parsed
        .as_ref()
        .and_then(|v| v.get("ts"))
        .and_then(|v| v.as_str())
    {
        output["messageTs"] = Value::String(ts.to_string());
    }

    if let Some(channel_id) = parsed
        .as_ref()
        .and_then(|v| v.get("channel"))
        .and_then(|v| v.as_str())
    {
        output["channelId"] = Value::String(channel_id.to_string());
    }

    if let Some(email) = token_email {
        output["oauthAccountEmail"] = Value::String(email);
    }

    if output_connection_scope.is_none() || output_connection_id.is_none() {
        if let Some(context) = &connection_context {
            match context {
                SlackConnectionContext::Personal { connection_id, .. } => {
                    output_connection_scope = Some("user".to_string());
                    output_connection_id = Some(*connection_id);
                }
                SlackConnectionContext::Workspace { connection_id, .. } => {
                    output_connection_scope = Some("workspace".to_string());
                    output_connection_id = Some(*connection_id);
                }
            }
        }
    }

    if let Some(scope) = output_connection_scope {
        output["connectionScope"] = Value::String(scope);
    }
    if let Some(connection_id) = output_connection_id {
        output["connectionId"] = Value::String(connection_id.to_string());
    }

    Ok((output, None))
}

async fn send_teams(
    _node: &Node,
    params: &Value,
    context: &Value,
    state: &AppState,
    run: &WorkflowRun,
) -> Result<(Value, Option<String>), String> {
    // Robustly infer delivery method. If it's missing but the payload clearly
    // contains delegated fields (teamId, channelId, oauthProvider=microsoft),
    // coerce to Delegated OAuth to avoid silently falling back to webhooks.
    let explicit_method = params
        .get("deliveryMethod")
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    let is_delegated_hint = {
        let team_ok = params
            .get("teamId")
            .and_then(|v| v.as_str())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .is_some();
        let channel_ok = params
            .get("channelId")
            .and_then(|v| v.as_str())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .is_some();
        let provider_ok = params
            .get("oauthProvider")
            .and_then(|v| v.as_str())
            .map(|s| normalize_identifier(s).eq("microsoft"))
            .unwrap_or(true); // default provider is microsoft in UI/backend
        team_ok && channel_ok && provider_ok
    };

    let (effective_params, delivery_method) = match explicit_method {
        Some(method) => (params.clone(), method),
        None => {
            if is_delegated_hint {
                // Insert inferred delivery method so sanitizer preserves delegated fields
                let mut map = match params.clone() {
                    Value::Object(map) => map,
                    _ => Map::new(),
                };
                map.insert(
                    "deliveryMethod".to_string(),
                    Value::String("Delegated OAuth (Post as user)".to_string()),
                );
                (
                    Value::Object(map),
                    "Delegated OAuth (Post as user)".to_string(),
                )
            } else {
                (params.clone(), "Incoming Webhook".to_string())
            }
        }
    };

    let sanitized = sanitize_teams_params(&effective_params);

    match normalize_identifier(&delivery_method).as_str() {
        "incomingwebhook" => send_teams_incoming_webhook(&sanitized, context).await,
        "delegatedoauthpostasuser" => {
            send_teams_delegated_oauth(&sanitized, context, state, run).await
        }
        _ => Err(format!(
            "Teams delivery method '{}' is not supported yet",
            delivery_method
        )),
    }
}

async fn send_google_chat(
    params: &Value,
    context: &Value,
) -> Result<(Value, Option<String>), String> {
    let webhook_raw = extract_required_str(params, "webhookUrl", "Webhook URL")?;

    let card_payload = params
        .get("cardJson")
        .and_then(|v| v.as_str())
        .map(|raw| templ_str(raw, context))
        .and_then(|templated| {
            if templated.trim().is_empty() {
                None
            } else {
                Some(templated)
            }
        });

    let payload = if let Some(card_raw) = card_payload {
        let payload_value: Value =
            serde_json::from_str(card_raw.trim()).map_err(|e| format!("Invalid card JSON: {e}"))?;

        let has_cards = payload_value
            .as_object()
            .map(|obj| obj.contains_key("cards") || obj.contains_key("cardsV2"))
            .unwrap_or(false);

        if !has_cards {
            return Err("Card JSON must include 'cards' or 'cardsV2'".to_string());
        }

        payload_value
    } else {
        let message_raw = extract_required_str(params, "message", "Message")?;

        let message = templ_str(message_raw, context);
        if message.trim().is_empty() {
            return Err("Message is required".to_string());
        }

        json!({ "text": message })
    };

    let parsed_url =
        Url::parse(webhook_raw).map_err(|_| "Invalid webhook URL for Google Chat".to_string())?;
    match parsed_url.scheme() {
        "http" | "https" => {}
        _ => return Err("Webhook URL for Google Chat must be HTTP or HTTPS".to_string()),
    }

    let client = reqwest::Client::new();
    let response = client
        .post(parsed_url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| format!("Google Chat webhook request failed: {e}"))?;

    let status = response.status();
    let body_text = response
        .text()
        .await
        .map_err(|e| format!("Google Chat webhook response read failed: {e}"))?;

    if !status.is_success() {
        let detail = body_text.trim();
        if detail.is_empty() {
            return Err(format!(
                "Google Chat webhook returned status {}",
                status.as_u16()
            ));
        }
        return Err(format!(
            "Google Chat webhook returned status {}: {}",
            status.as_u16(),
            detail
        ));
    }

    Ok((
        json!({
            "sent": true,
            "service": "Google Chat",
            "platform": "Google Chat",
            "status": status.as_u16(),
        }),
        None,
    ))
}

fn normalize_identifier(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

async fn send_teams_incoming_webhook(
    params: &Value,
    context: &Value,
) -> Result<(Value, Option<String>), String> {
    let webhook_type = params
        .get("webhookType")
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| "Connector".to_string());

    match normalize_identifier(&webhook_type).as_str() {
        "connector" => send_teams_connector_webhook(params, context).await,
        "workflowpowerautomate" | "workflow" | "powerautomate" => {
            send_teams_workflow_webhook(params, context).await
        }
        _ => Err(format!(
            "Teams webhook type '{}' is not supported",
            webhook_type
        )),
    }
}

fn extract_optional_templated_string(params: &Value, key: &str, context: &Value) -> Option<String> {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| templ_str(s, context))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

async fn send_teams_connector_webhook(
    params: &Value,
    context: &Value,
) -> Result<(Value, Option<String>), String> {
    let webhook_raw = extract_required_str(params, "webhookUrl", "Webhook URL")?;
    let message_raw = extract_required_str(params, "message", "Message")?;

    let message = templ_str(message_raw, context);
    if message.trim().is_empty() {
        return Err("Message is required".to_string());
    }

    let title = extract_optional_templated_string(params, "title", context);
    let summary = extract_optional_templated_string(params, "summary", context)
        .unwrap_or_else(|| message.clone());

    let theme_color = extract_optional_templated_string(params, "themeColor", context)
        .map(|color| color.trim_start_matches('#').to_string())
        .map(|color| color.to_uppercase());

    if let Some(ref color) = theme_color {
        let is_valid = color.len() == 6 && color.chars().all(|c| c.is_ascii_hexdigit());
        if !is_valid {
            return Err("Theme color must be a 6-digit hex value".to_string());
        }
    }

    let mut payload = json!({
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "summary": summary,
        "text": message,
    });

    if let Some(title) = title {
        payload["title"] = Value::String(title);
    }

    if let Some(color) = theme_color {
        payload["themeColor"] = Value::String(color);
    }

    post_webhook_payload(webhook_raw, payload, "Teams", None).await
}

async fn send_teams_workflow_webhook(
    params: &Value,
    context: &Value,
) -> Result<(Value, Option<String>), String> {
    let workflow_option = params
        .get("workflowOption")
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("Basic (Raw JSON)");

    let workflow_option_normalized = normalize_identifier(workflow_option);

    let webhook_url_raw = extract_required_str(params, "webhookUrl", "Webhook URL")?;
    let webhook_url = webhook_url_raw.trim();
    if webhook_url.is_empty() {
        return Err("Webhook URL is required".to_string());
    }

    let raw_payload = extract_required_str(params, "workflowRawJson", "Raw JSON payload")?;
    let templated = templ_str(raw_payload, context);
    if templated.trim().is_empty() {
        return Err("Raw JSON payload is required".to_string());
    }
    let payload = serde_json::from_str::<Value>(&templated)
        .map_err(|e| format!("Raw JSON payload is invalid: {e}"))?;

    let mut headers = HeaderMap::new();

    if workflow_option_normalized.as_str() == "headersecretauth" {
        let header_name_raw = extract_required_str(params, "workflowHeaderName", "Header name")?;
        let header_value_raw =
            extract_required_str(params, "workflowHeaderSecret", "Header secret")?;

        let header_name = templ_str(header_name_raw, context);
        let trimmed_name = header_name.trim();
        if trimmed_name.is_empty() {
            return Err("Header name is required".to_string());
        }

        let header_name = HeaderName::from_bytes(trimmed_name.as_bytes())
            .map_err(|_| "Header name is invalid".to_string())?;

        let header_value = templ_str(header_value_raw, context);
        if header_value.trim().is_empty() {
            return Err("Header secret is required".to_string());
        }

        let header_value = HeaderValue::from_str(header_value.as_str())
            .map_err(|_| "Header secret contains invalid characters".to_string())?;

        headers.insert(header_name, header_value);
    }

    let headers = if headers.is_empty() {
        None
    } else {
        Some(headers)
    };

    post_webhook_payload(webhook_url, payload, "Teams", headers).await
}

fn optional_string(params: &Value, key: &str) -> Option<String> {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .and_then(|s| if s.trim().is_empty() { None } else { Some(s) })
}

fn sanitize_teams_params(params: &Value) -> Value {
    let mut map = Map::new();

    let delivery_method = params
        .get("deliveryMethod")
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("Incoming Webhook");

    map.insert(
        "deliveryMethod".to_string(),
        Value::String(delivery_method.to_string()),
    );

    match normalize_identifier(delivery_method).as_str() {
        "incomingwebhook" => {
            let webhook_type = params
                .get("webhookType")
                .and_then(|v| v.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .unwrap_or("Connector");

            map.insert(
                "webhookType".to_string(),
                Value::String(webhook_type.to_string()),
            );

            let webhook_url = optional_string(params, "webhookUrl");

            match normalize_identifier(webhook_type).as_str() {
                "connector" => {
                    if let Some(url) = webhook_url {
                        map.insert("webhookUrl".to_string(), Value::String(url));
                    }
                    if let Some(title) = optional_string(params, "title") {
                        map.insert("title".to_string(), Value::String(title));
                    }
                    if let Some(summary) = optional_string(params, "summary") {
                        map.insert("summary".to_string(), Value::String(summary));
                    }
                    if let Some(theme_color) = optional_string(params, "themeColor") {
                        map.insert("themeColor".to_string(), Value::String(theme_color));
                    }
                    if let Some(message) = optional_string(params, "message") {
                        map.insert("message".to_string(), Value::String(message));
                    }
                }
                "workflowpowerautomate" | "workflow" | "powerautomate" => {
                    let requested_option = params
                        .get("workflowOption")
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .unwrap_or("Basic (Raw JSON)");

                    let normalized_option = normalize_identifier(requested_option);
                    let coerced_option = if normalized_option == "headersecretauth" {
                        "Header Secret Auth"
                    } else {
                        "Basic (Raw JSON)"
                    };

                    map.insert(
                        "workflowOption".to_string(),
                        Value::String(coerced_option.to_string()),
                    );

                    if let Some(raw) = optional_string(params, "workflowRawJson") {
                        map.insert("workflowRawJson".to_string(), Value::String(raw));
                    }

                    if let Some(url) = webhook_url.clone() {
                        map.insert("webhookUrl".to_string(), Value::String(url));
                    }

                    if normalized_option == "headersecretauth" {
                        if let Some(name) = optional_string(params, "workflowHeaderName") {
                            map.insert("workflowHeaderName".to_string(), Value::String(name));
                        }
                        if let Some(secret) = optional_string(params, "workflowHeaderSecret") {
                            map.insert("workflowHeaderSecret".to_string(), Value::String(secret));
                        }
                    }
                }
                _ => {}
            }

            Value::Object(map)
        }
        "delegatedoauthpostasuser" => {
            let provider =
                optional_string(params, "oauthProvider").unwrap_or_else(|| "microsoft".to_string());
            map.insert("oauthProvider".into(), Value::String(provider));

            if let Some(connection_obj) = params.get("connection").and_then(|v| v.as_object()) {
                let mut sanitized = Map::new();
                if let Some(scope) = connection_obj
                    .get("connectionScope")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                {
                    sanitized.insert("connectionScope".into(), Value::String(scope.to_string()));
                }
                if let Some(id) = connection_obj
                    .get("connectionId")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                {
                    sanitized.insert("connectionId".into(), Value::String(id.to_string()));
                }
                if let Some(email) = connection_obj
                    .get("accountEmail")
                    .and_then(|v| v.as_str())
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                {
                    sanitized.insert("accountEmail".into(), Value::String(email.to_string()));
                }
                if !sanitized.is_empty() {
                    map.insert("connection".into(), Value::Object(sanitized));
                }
            }

            if let Some(connection) = optional_string(params, "oauthConnectionId") {
                map.insert("oauthConnectionId".into(), Value::String(connection));
            }

            if let Some(email) = optional_string(params, "oauthAccountEmail") {
                map.insert("oauthAccountEmail".into(), Value::String(email));
            }

            if let Some(team_id) = optional_string(params, "teamId") {
                map.insert("teamId".into(), Value::String(team_id));
            }
            if let Some(team_name) = optional_string(params, "teamName") {
                map.insert("teamName".into(), Value::String(team_name));
            }
            if let Some(channel_id) = optional_string(params, "channelId") {
                map.insert("channelId".into(), Value::String(channel_id));
            }
            if let Some(channel_name) = optional_string(params, "channelName") {
                map.insert("channelName".into(), Value::String(channel_name));
            }

            let message_type_raw = params
                .get("messageType")
                .and_then(|v| v.as_str())
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .unwrap_or("Text");

            let normalized_type = normalize_identifier(message_type_raw);
            let message_type = if normalized_type == "card" {
                "Card"
            } else {
                "Text"
            };

            map.insert(
                "messageType".into(),
                Value::String(message_type.to_string()),
            );

            if message_type == "Card" {
                if let Some(mode) = optional_string(params, "cardMode") {
                    map.insert("cardMode".into(), Value::String(mode));
                }
                if let Some(title) = optional_string(params, "cardTitle") {
                    map.insert("cardTitle".into(), Value::String(title));
                }
                if let Some(body) = optional_string(params, "cardBody") {
                    map.insert("cardBody".into(), Value::String(body));
                }
                if let Some(raw) = optional_string(params, "cardJson") {
                    map.insert("cardJson".into(), Value::String(raw));
                }
                if let Some(message) = optional_string(params, "message") {
                    // Preserve legacy message fields if present for migration purposes.
                    map.insert("message".into(), Value::String(message));
                }
            } else {
                if let Some(message) = optional_string(params, "message") {
                    map.insert("message".into(), Value::String(message));
                }
                if let Some(mentions) = sanitize_mentions_array(params) {
                    map.insert("mentions".into(), Value::Array(mentions));
                }
            }

            Value::Object(map)
        }
        _ => Value::Object(map),
    }
}

fn sanitize_mentions_array(params: &Value) -> Option<Vec<Value>> {
    let mentions = params.get("mentions")?.as_array()?;
    let mut seen = HashSet::new();
    let mut sanitized = Vec::new();

    for entry in mentions {
        let user_id = entry
            .get("userId")
            .and_then(|v| v.as_str())
            .or_else(|| entry.get("user_id").and_then(|v| v.as_str()))
            .map(|s| s.trim().to_string())
            .unwrap_or_default();

        if user_id.is_empty() {
            continue;
        }

        if !seen.insert(user_id.clone()) {
            continue;
        }

        let display = entry
            .get("displayName")
            .and_then(|v| v.as_str())
            .or_else(|| entry.get("display_name").and_then(|v| v.as_str()))
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| user_id.clone());

        let mut map = Map::new();
        map.insert("userId".to_string(), Value::String(user_id.clone()));
        map.insert("displayName".to_string(), Value::String(display));

        if let Some(member_id) = entry
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
        {
            map.insert("id".to_string(), Value::String(member_id));
        }

        sanitized.push(Value::Object(map));
    }

    Some(sanitized)
}

#[derive(Clone)]
struct TeamsMentionEntry {
    user_id: String,
    display_name: String,
}

fn extract_mentions(params: &Value) -> Vec<TeamsMentionEntry> {
    params
        .get("mentions")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|entry| {
                    let user_id = entry
                        .get("userId")
                        .and_then(|v| v.as_str())
                        .or_else(|| entry.get("user_id").and_then(|v| v.as_str()))?
                        .trim();

                    if user_id.is_empty() {
                        return None;
                    }

                    let display_name = entry
                        .get("displayName")
                        .and_then(|v| v.as_str())
                        .or_else(|| entry.get("display_name").and_then(|v| v.as_str()))
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .unwrap_or(user_id);

                    Some(TeamsMentionEntry {
                        user_id: user_id.to_string(),
                        display_name: display_name.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn microsoft_graph_base_url() -> String {
    std::env::var("MICROSOFT_GRAPH_BASE_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_MICROSOFT_GRAPH_BASE_URL.to_string())
}

fn escape_html(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn text_to_html(input: &str) -> String {
    let escaped = escape_html(input);
    let mut html = String::with_capacity(escaped.len());
    for ch in escaped.chars() {
        match ch {
            '\r' => {}
            '\n' => html.push_str("<br/>"),
            _ => html.push(ch),
        }
    }
    html
}

fn graph_error_message(parsed: Option<&Value>, raw: &str) -> String {
    if let Some(Value::Object(obj)) = parsed {
        if let Some(Value::Object(error)) = obj.get("error") {
            if let Some(Value::String(message)) = error.get("message") {
                let trimmed = message.trim();
                if !trimmed.is_empty() {
                    return trimmed.to_string();
                }
            }
        }
    }

    let fallback = raw.trim();
    if fallback.is_empty() {
        "Microsoft Graph request failed".to_string()
    } else {
        fallback.to_string()
    }
}

fn map_workspace_microsoft_error(err: WorkspaceOAuthError) -> String {
    match err {
        WorkspaceOAuthError::NotFound => {
            "Microsoft workspace connection not found or does not belong to this workspace. Promote the connection again from Settings -> Integrations.".to_string()
        }
        WorkspaceOAuthError::OAuth(OAuthAccountError::TokenRevoked { .. }) => {
            "The shared Microsoft credential was revoked by its owner. Ask them to reconnect it in Settings -> Integrations.".to_string()
        }
        WorkspaceOAuthError::SlackInstallRequired => {
            "Slack connections must be installed at workspace scope.".to_string()
        }
        other => format!("Failed to obtain Microsoft workspace connection: {other}"),
    }
}

fn map_workspace_slack_error(err: WorkspaceOAuthError) -> String {
    match err {
        WorkspaceOAuthError::NotFound => {
            "Slack workspace connection not found or does not belong to this workspace. Promote the connection again from Settings -> Integrations.".to_string()
        }
        WorkspaceOAuthError::OAuth(OAuthAccountError::TokenRevoked { .. }) => {
            "The shared Slack credential was revoked by its owner. Ask them to reconnect it in Settings -> Integrations.".to_string()
        }
        WorkspaceOAuthError::SlackInstallRequired => {
            "Slack connections must be installed at workspace scope.".to_string()
        }
        other => format!("Failed to obtain Slack workspace connection: {other}"),
    }
}

fn build_text_payload(message: &str, mentions: &[TeamsMentionEntry]) -> (Value, usize) {
    let mut content = text_to_html(message);
    let mut mention_entities = Vec::new();

    if !mentions.is_empty() {
        if !content.trim().is_empty() {
            content.push_str("<br/><br/>");
        }
        for (idx, mention) in mentions.iter().enumerate() {
            if idx > 0 {
                content.push_str("<br/>");
            }
            let escaped = escape_html(&mention.display_name);
            content.push_str(&format!("<at id=\"{}\">@{}</at>", idx, escaped));
            mention_entities.push(json!({
                "id": idx as i32,
                "mentionText": format!("@{}", mention.display_name),
                "mentioned": {
                    "user": {
                        "id": mention.user_id,
                        "displayName": mention.display_name,
                    }
                }
            }));
        }
    }

    let mention_count = mention_entities.len();

    let mut payload = json!({
        "body": {
            "contentType": "html",
            "content": content,
        }
    });

    if mention_count > 0 {
        payload["mentions"] = Value::Array(mention_entities);
    }

    (payload, mention_count)
}

fn build_card_payload(card_json: &str) -> Result<Value, String> {
    let trimmed = card_json.trim();
    if trimmed.is_empty() {
        return Err("Card JSON is required".to_string());
    }

    let parsed: Value = serde_json::from_str(trimmed)
        .map_err(|err| format!("Card JSON must be valid JSON: {err}"))?;

    let Value::Object(mut obj) = parsed else {
        return Err("Card JSON must be an object".to_string());
    };

    if obj.contains_key("attachments") {
        obj.remove("subject");

        if let Some(value) = obj.get_mut("attachments") {
            let Value::Array(attachments) = value else {
                return Err("Attachments must be an array".to_string());
            };

            for attachment in attachments {
                let Value::Object(map) = attachment else {
                    return Err("Each attachment must be an object".to_string());
                };

                if let Some(content) = map.get("content") {
                    if !content.is_string() {
                        let serialized = serde_json::to_string(content).map_err(|err| {
                            format!("Attachment content must serialize to a string: {err}")
                        })?;
                        map.insert("content".to_string(), Value::String(serialized));
                    }
                }
            }

            return Ok(Value::Object(obj));
        }
    }

    let card_type = obj
        .get("type")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "Card JSON must include a 'type' field".to_string())?;

    if !card_type.eq_ignore_ascii_case("AdaptiveCard") {
        return Err("Only AdaptiveCard payloads are supported".to_string());
    }

    let card_content = Value::Object(obj);
    let card_json = serde_json::to_string(&card_content)
        .map_err(|err| format!("Card JSON must serialize to a string: {err}"))?;

    let attachment_id = "1";
    let attachment_placeholder = format!("<attachment id=\"{}\"></attachment>", attachment_id);

    Ok(json!({
        "body": {
            "contentType": "html",
            "content": attachment_placeholder,
        },
        "attachments": [{
            "id": attachment_id,
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": card_json,
            "contentUrl": Value::Null,
        }]
    }))
}

async fn send_teams_delegated_oauth(
    params: &Value,
    context: &Value,
    state: &AppState,
    run: &WorkflowRun,
) -> Result<(Value, Option<String>), String> {
    let provider = params
        .get("oauthProvider")
        .and_then(|v| v.as_str())
        .unwrap_or("microsoft");

    if normalize_identifier(provider) != "microsoft" {
        return Err(
            "Only Microsoft delegated OAuth connections are supported for Teams messaging"
                .to_string(),
        );
    }

    let connection_usage = resolve_connection_usage(params)?;

    let team_id = params
        .get("teamId")
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Team ID is required for delegated Teams messaging".to_string())?;

    let channel_id = params
        .get("channelId")
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Channel ID is required for delegated Teams messaging".to_string())?;

    let message_type_raw = params
        .get("messageType")
        .and_then(|v| v.as_str())
        .unwrap_or("Text");
    let message_type = if normalize_identifier(message_type_raw) == "card" {
        "Card"
    } else {
        "Text"
    };

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

    let (access_token, token_email, connection_context) = match connection_usage {
        NodeConnectionUsage::Workspace(info) => {
            let workspace_id = run.workspace_id.ok_or_else(|| {
                "This workflow run is not associated with a workspace. Promote the Microsoft connection to the workspace or switch the action back to a personal connection.".to_string()
            })?;

            ensure_run_membership(state, workspace_id, run.user_id).await?;
            ensure_workspace_plan(state, workspace_id).await?;

            let connection = state
                .workspace_oauth
                .ensure_valid_workspace_token(info.connection_id)
                .await
                .map_err(map_workspace_microsoft_error)?;

            if connection.workspace_id != workspace_id {
                return Err(map_workspace_microsoft_error(WorkspaceOAuthError::NotFound));
            }

            if connection.provider != ConnectedOAuthProvider::Microsoft {
                return Err("Selected connection is not a Microsoft connection".to_string());
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
        NodeConnectionUsage::User(info) => {
            let connection_id_str = info.connection_id.ok_or_else(|| {
                "Personal OAuth connections require an explicit connectionId. Please select a specific OAuth connection from your integrations.".to_string()
            })?;

            let connection_id = Uuid::parse_str(&connection_id_str)
                .map_err(|_| "Personal connectionId must be a valid UUID. Please select a valid OAuth connection.".to_string())?;

            let token = state
                .oauth_accounts
                .ensure_valid_access_token_for_connection(run.user_id, connection_id)
                .await
                .map_err(|err| match err {
                    OAuthAccountError::NotFound => {
                        "Connect Microsoft integration before using delegated Teams messaging"
                            .to_string()
                    }
                    OAuthAccountError::TokenRevoked { .. } => {
                        "The connected Microsoft account was revoked. Reconnect it from Settings → Integrations.".to_string()
                    }
                    other => format!("Failed to refresh Microsoft OAuth token: {other}"),
                })?;

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

    let base_url = microsoft_graph_base_url();
    let target = format!(
        "{}/teams/{}/channels/{}/messages",
        base_url.trim_end_matches('/'),
        encode(team_id),
        encode(channel_id)
    );

    let (payload, mention_count) = if message_type == "Card" {
        let card_raw = params
            .get("cardJson")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "Card JSON is required for delegated card messages".to_string())?;
        let templated = templ_str(card_raw, context);
        (build_card_payload(&templated)?, 0)
    } else {
        let message_raw = extract_required_str(params, "message", "Message")?;
        let templated = templ_str(message_raw, context);
        if templated.trim().is_empty() {
            return Err("Message is required".to_string());
        }
        let mentions = extract_mentions(params);
        build_text_payload(&templated, &mentions)
    };

    match serde_json::to_string(&payload) {
        Ok(serialized) => info!(
            target: "dsentr::actions::messaging::teams",
            payload = %serialized,
            "Sending Teams delegated OAuth payload"
        ),
        Err(err) => warn!(
            target: "dsentr::actions::messaging::teams",
            %err,
            "Failed to serialize Teams delegated OAuth payload for logging"
        ),
    }

    let response = state
        .http_client
        .post(&target)
        .bearer_auth(&access_token)
        .json(&payload)
        .send()
        .await
        .map_err(|err| format!("Microsoft Graph request failed: {err}"))?;

    let status = response.status();
    let body_text = response
        .text()
        .await
        .map_err(|err| format!("Failed to read Microsoft Graph response: {err}"))?;
    let parsed: Option<Value> = serde_json::from_str(&body_text).ok();

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
                        .handle_revoked_token(*user_id, ConnectedOAuthProvider::Microsoft)
                        .await
                    {
                        warn!(
                            user_id = %user_id,
                            error = %err,
                            "failed to purge revoked personal microsoft token"
                        );
                    }

                    (
                        account_email.clone(),
                        "Microsoft revoked the connected account. Reconnect it from Settings → Integrations.".to_string(),
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
                            "failed to remove revoked workspace microsoft connection"
                        );
                    }

                    if let Err(err) = state
                        .oauth_accounts
                        .handle_revoked_token(*created_by, ConnectedOAuthProvider::Microsoft)
                        .await
                    {
                        warn!(
                            created_by = %created_by,
                            error = %err,
                            "failed to purge creator's personal microsoft token after workspace revocation"
                        );
                    }

                    (
                        account_email.clone(),
                        "Microsoft revoked the shared workspace connection. Ask the owner to reconnect it from Settings → Integrations.".to_string(),
                    )
                }
            };

            warn!(
                status = %status,
                account_email = account_email.as_deref().unwrap_or("unknown"),
                body = %body_text,
                "microsoft graph returned revocation signal"
            );

            return Err(message);
        }

        let message = graph_error_message(parsed.as_ref(), &body_text);
        return Err(format!(
            "Microsoft Graph returned status {}: {}",
            status.as_u16(),
            message
        ));
    }

    let mut output = json!({
        "sent": true,
        "service": "Teams",
        "platform": "Teams",
        "deliveryMethod": "Delegated OAuth (Post as user)",
        "status": status.as_u16(),
        "teamId": team_id,
        "channelId": channel_id,
        "messageType": message_type,
    });

    if mention_count > 0 {
        output["mentionsAdded"] = Value::Number(serde_json::Number::from(mention_count as u64));
    }

    if let Some(team_name) = params
        .get("teamName")
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        output["teamName"] = Value::String(team_name.to_string());
    }

    if let Some(channel_name) = params
        .get("channelName")
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        output["channelName"] = Value::String(channel_name.to_string());
    }

    if !token_email.trim().is_empty() {
        output["oauthAccountEmail"] = Value::String(token_email.clone());
    }

    // Surface connection metadata to help detect stale selections
    match connection_context {
        ConnectionContext::Personal { connection_id, .. } => {
            output["connectionScope"] = Value::String("user".to_string());
            output["connectionId"] = Value::String(connection_id.to_string());
        }
        ConnectionContext::Workspace { connection_id, .. } => {
            output["connectionScope"] = Value::String("workspace".to_string());
            output["connectionId"] = Value::String(connection_id.to_string());
        }
    }

    if let Some(Value::Object(obj)) = parsed.as_ref() {
        if let Some(Value::String(id)) = obj.get("id") {
            output["messageId"] = Value::String(id.clone());
        }
        if let Some(Value::String(url)) = obj.get("webUrl") {
            output["webUrl"] = Value::String(url.clone());
        }
    }

    Ok((output, None))
}

async fn post_webhook_payload(
    webhook_raw: &str,
    payload: Value,
    service: &str,
    extra_headers: Option<HeaderMap>,
) -> Result<(Value, Option<String>), String> {
    let parsed_url =
        Url::parse(webhook_raw).map_err(|_| format!("Invalid webhook URL for {}", service))?;
    match parsed_url.scheme() {
        "http" | "https" => {}
        _ => return Err(format!("Webhook URL for {} must be HTTP or HTTPS", service)),
    }

    let client = reqwest::Client::new();
    let mut request = client.post(parsed_url).json(&payload);

    if let Some(headers) = extra_headers {
        request = request.headers(headers);
    }

    let response = request
        .send()
        .await
        .map_err(|e| format!("{} webhook request failed: {e}", service))?;

    let status = response.status();
    let body_text = response
        .text()
        .await
        .map_err(|e| format!("{} webhook response read failed: {e}", service))?;

    if !status.is_success() {
        let detail = body_text.trim();
        let message = if detail.is_empty() {
            format!("{} webhook returned status {}", service, status.as_u16())
        } else {
            format!(
                "{} webhook returned status {}: {}",
                service,
                status.as_u16(),
                detail
            )
        };
        return Err(message);
    }

    Ok((
        json!({
            "sent": true,
            "service": service,
            "platform": service,
            "status": status.as_u16(),
        }),
        None,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::{
        body::{to_bytes, Body},
        extract::State,
        http::{header, Request, Response, StatusCode},
        routing::post,
        Router,
    };
    use once_cell::sync::Lazy;
    use reqwest::Client;
    use serde_json::{json, Value};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, MutexGuard,
    };
    use time::{Duration, OffsetDateTime};
    use tokio::{
        net::TcpListener,
        sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        task::JoinHandle,
    };

    use crate::engine::graph::Node;
    use crate::{
        config::{
            Config, OAuthProviderConfig, OAuthSettings, StripeSettings,
            DEFAULT_WORKSPACE_MEMBER_LIMIT, DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT,
            RUNAWAY_LIMIT_5MIN,
        },
        db::oauth_token_repository::{NewUserOAuthToken, UserOAuthTokenRepository},
        db::{
            mock_db::{
                MockDb, NoopWorkflowRepository, NoopWorkspaceRepository,
                StaticWorkspaceMembershipRepository,
            },
            mock_stripe_event_log_repository::MockStripeEventLogRepository,
            workspace_connection_repository::{
                NoopWorkspaceConnectionRepository, WorkspaceConnectionRepository,
            },
            workspace_repository::WorkspaceRepository,
        },
        models::oauth_token::{ConnectedOAuthProvider, UserOAuthToken, WorkspaceConnection},
        models::workflow_run::WorkflowRun,
        services::{
            oauth::{
                account_service::{AuthorizationTokens, OAuthAccountService, SlackOAuthMetadata},
                github::mock_github_oauth::MockGitHubOAuth,
                google::mock_google_oauth::MockGoogleOAuth,
                workspace_service::{WorkspaceOAuthService, WorkspaceTokenRefresher},
            },
            smtp_mailer::MockMailer,
        },
        state::{test_pg_pool, AppState},
        utils::{
            encryption::{decrypt_secret, encrypt_secret},
            jwt::JwtKeys,
        },
    };
    use sqlx::Error as SqlxError;
    use uuid::Uuid;

    static ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

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

        fn snapshot(&self) -> Option<WorkspaceConnection> {
            self.connection.lock().unwrap().clone()
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

    #[derive(Clone, Debug)]
    struct RecordedRequest {
        method: String,
        uri: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    struct StubState<F>
    where
        F: Fn() -> Response<Body> + Send + Sync + 'static,
    {
        tx: UnboundedSender<RecordedRequest>,
        response_factory: Arc<F>,
    }

    impl<F> Clone for StubState<F>
    where
        F: Fn() -> Response<Body> + Send + Sync + 'static,
    {
        fn clone(&self) -> Self {
            Self {
                tx: self.tx.clone(),
                response_factory: Arc::clone(&self.response_factory),
            }
        }
    }

    async fn stub_handler<F>(
        State(state): State<StubState<F>>,
        request: Request<Body>,
    ) -> Response<Body>
    where
        F: Fn() -> Response<Body> + Send + Sync + 'static,
    {
        let (parts, body) = request.into_parts();
        let bytes = to_bytes(body, 1024 * 1024).await.unwrap_or_default();
        let headers = parts
            .headers
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or_default().to_string()))
            .collect();
        let record = RecordedRequest {
            method: parts.method.to_string(),
            uri: parts.uri.to_string(),
            headers,
            body: bytes.to_vec(),
        };
        let _ = state.tx.send(record);
        (state.response_factory)()
    }

    async fn spawn_stub_server<F>(
        response_factory: F,
    ) -> (
        std::net::SocketAddr,
        UnboundedReceiver<RecordedRequest>,
        JoinHandle<()>,
    )
    where
        F: Fn() -> Response<Body> + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = unbounded_channel();
        let state = StubState {
            tx,
            response_factory: Arc::new(response_factory),
        };

        let app = Router::new()
            .route("/{*path}", post(stub_handler::<F>))
            .with_state(state);

        let server = axum::serve(listener, app.into_make_service());
        let handle = tokio::spawn(async move {
            if let Err(err) = server.await {
                eprintln!("stub server exited with error: {err}");
            }
        });

        (addr, rx, handle)
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

    fn build_state_with_oauth(
        oauth_accounts: Arc<OAuthAccountService>,
        workspace_oauth: Arc<WorkspaceOAuthService>,
        config: Arc<Config>,
        workspace_repo: Arc<dyn WorkspaceRepository>,
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
            oauth_accounts,
            workspace_oauth,
            stripe: Arc::new(crate::services::stripe::MockStripeService::new()),
            http_client: Arc::new(Client::new()),
            config,
            worker_id: Arc::new("worker".to_string()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        }
    }

    fn test_state(workspace_repo: Arc<dyn WorkspaceRepository>) -> AppState {
        let config = test_config();
        build_state_with_oauth(
            OAuthAccountService::test_stub(),
            WorkspaceOAuthService::test_stub(),
            Arc::clone(&config),
            workspace_repo,
        )
    }

    fn test_run() -> WorkflowRun {
        WorkflowRun {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            workflow_id: Uuid::new_v4(),
            workspace_id: None,
            snapshot: json!({}),
            status: "pending".into(),
            error: None,
            idempotency_key: None,
            started_at: OffsetDateTime::now_utc(),
            resume_at: OffsetDateTime::now_utc(),
            finished_at: None,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        }
    }

    async fn execute_default(
        node: &Node,
        context: &Value,
    ) -> Result<(Value, Option<String>), String> {
        let state = test_state(Arc::new(NoopWorkspaceRepository));
        let run = test_run();
        execute_messaging(node, context, &state, &run).await
    }

    #[derive(Clone)]
    struct StaticTokenRepo {
        record: UserOAuthToken,
    }

    #[async_trait]
    impl UserOAuthTokenRepository for StaticTokenRepo {
        async fn upsert_token(
            &self,
            _new_token: NewUserOAuthToken,
        ) -> Result<UserOAuthToken, SqlxError> {
            Ok(self.record.clone())
        }

        async fn find_by_id(&self, token_id: Uuid) -> Result<Option<UserOAuthToken>, SqlxError> {
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
        ) -> Result<Option<UserOAuthToken>, SqlxError> {
            if user_id == self.record.user_id && provider == self.record.provider {
                Ok(Some(self.record.clone()))
            } else {
                Ok(None)
            }
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
            user_id: Uuid,
        ) -> Result<Vec<UserOAuthToken>, SqlxError> {
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
        ) -> Result<UserOAuthToken, SqlxError> {
            Ok(self.record.clone())
        }

        async fn list_by_user_and_provider(
            &self,
            user_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<Vec<UserOAuthToken>, SqlxError> {
            if user_id == self.record.user_id && provider == self.record.provider {
                Ok(vec![self.record.clone()])
            } else {
                Ok(vec![])
            }
        }
    }

    #[derive(Clone)]
    struct RecordingTokenRepo {
        record: Arc<Mutex<UserOAuthToken>>,
    }

    impl RecordingTokenRepo {
        fn new(record: UserOAuthToken) -> Self {
            Self {
                record: Arc::new(Mutex::new(record)),
            }
        }

        fn snapshot(&self) -> UserOAuthToken {
            self.record.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl UserOAuthTokenRepository for RecordingTokenRepo {
        async fn upsert_token(
            &self,
            new_token: NewUserOAuthToken,
        ) -> Result<UserOAuthToken, SqlxError> {
            let mut record = self.record.lock().unwrap();
            record.user_id = new_token.user_id;
            record.provider = new_token.provider;
            record.access_token = new_token.access_token;
            record.refresh_token = new_token.refresh_token;
            record.expires_at = new_token.expires_at;
            record.account_email = new_token.account_email;
            record.metadata = new_token.metadata;
            record.updated_at = OffsetDateTime::now_utc();
            Ok(record.clone())
        }

        async fn update_token(
            &self,
            token_id: Uuid,
            new_token: NewUserOAuthToken,
        ) -> Result<UserOAuthToken, SqlxError> {
            let mut record = self.record.lock().unwrap();
            if record.id != token_id {
                return Err(SqlxError::RowNotFound);
            }
            record.user_id = new_token.user_id;
            record.provider = new_token.provider;
            record.access_token = new_token.access_token;
            record.refresh_token = new_token.refresh_token;
            record.expires_at = new_token.expires_at;
            record.account_email = new_token.account_email;
            record.metadata = new_token.metadata;
            record.updated_at = OffsetDateTime::now_utc();
            Ok(record.clone())
        }

        async fn find_by_id(&self, token_id: Uuid) -> Result<Option<UserOAuthToken>, SqlxError> {
            let record = self.record.lock().unwrap();
            if record.id == token_id {
                Ok(Some(record.clone()))
            } else {
                Ok(None)
            }
        }

        async fn find_by_user_and_provider(
            &self,
            user_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<Option<UserOAuthToken>, SqlxError> {
            let record = self.record.lock().unwrap();
            if record.user_id == user_id && record.provider == provider {
                Ok(Some(record.clone()))
            } else {
                Ok(None)
            }
        }

        async fn delete_token(
            &self,
            _user_id: Uuid,
            _provider: ConnectedOAuthProvider,
        ) -> Result<(), SqlxError> {
            Ok(())
        }

        async fn list_by_user_and_provider(
            &self,
            user_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<Vec<UserOAuthToken>, SqlxError> {
            let record = self.record.lock().unwrap();
            if record.user_id == user_id && record.provider == provider {
                Ok(vec![record.clone()])
            } else {
                Ok(vec![])
            }
        }

        async fn list_tokens_for_user(
            &self,
            user_id: Uuid,
        ) -> Result<Vec<UserOAuthToken>, SqlxError> {
            let record = self.record.lock().unwrap();
            if record.user_id == user_id {
                Ok(vec![record.clone()])
            } else {
                Ok(vec![])
            }
        }

        async fn mark_shared(
            &self,
            user_id: Uuid,
            provider: ConnectedOAuthProvider,
            is_shared: bool,
        ) -> Result<UserOAuthToken, SqlxError> {
            let mut record = self.record.lock().unwrap();
            if record.user_id != user_id || record.provider != provider {
                return Err(SqlxError::RowNotFound);
            }
            record.is_shared = is_shared;
            record.updated_at = OffsetDateTime::now_utc();
            Ok(record.clone())
        }
    }

    #[tokio::test]
    async fn slack_requires_explicit_connection() {
        let (addr, _, _) = spawn_stub_server(|| {
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"ok":true,"ts":"123.456","channel":"C123"}"#))
                .unwrap()
        })
        .await;

        let _guard = EnvGuard::set("SLACK_API_BASE", format!("http://{}/api", addr));

        let node = Node {
            id: "action-1".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "Slack",
                    "channel": "#alerts",
                    "message": "Hello {{ user.name }}",
                    "token": "xoxb-test"
                }
            }),
        };

        let context = json!({ "user": { "name": "Alice" } });

        let err = execute_default(&node, &context)
            .await
            .expect_err("slack message should require explicit connection");

        assert!(err.contains("identity selection error"));
    }

    #[tokio::test]
    async fn slack_error_is_reported() {
        let (addr, _rx, handle) = spawn_stub_server(|| {
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"ok":false,"error":"channel_not_found"}"#))
                .unwrap()
        })
        .await;

        let _guard = EnvGuard::set("SLACK_API_BASE", format!("http://{}/api", addr));

        let node = Node {
            id: "action-2".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "Slack",
                    "channel": "#alerts",
                    "message": "Hi",
                    "token": "xoxb-test"
                }
            }),
        };

        let err = execute_default(&node, &Value::Null)
            .await
            .expect_err("missing identity should fail");
        handle.abort();
        assert!(err.contains("identity selection error"));
    }

    #[tokio::test]
    async fn slack_requires_token() {
        let node = Node {
            id: "action-3".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "Slack",
                    "channel": "#alerts",
                    "message": "Hello"
                }
            }),
        };

        let err = execute_default(&node, &Value::Null)
            .await
            .expect_err("missing token should fail");
        assert!(err.contains("identity selection error"));
    }

    #[test]
    fn infer_platform_uses_node_type_when_platform_absent() {
        let node = Node {
            id: "action-legacy".into(),
            kind: "actionSlack".into(),
            data: json!({
                "nodeType": "actionSlack",
                "label": "Slack",
                "params": {
                    "channel": "#alerts",
                    "message": "Hi"
                }
            }),
        };

        let params = node.data.get("params").cloned().unwrap_or(Value::Null);
        let platform = infer_messaging_platform(&params, &node)
            .expect("platform should be inferred from node type");

        assert_eq!(platform, MessagingPlatform::Slack);
    }

    #[test]
    fn infer_platform_considers_params_service() {
        let node = Node {
            id: "action-legacy".into(),
            kind: "action".into(),
            data: json!({
                "actionType": "Messaging",
                "params": {
                    "service": "Microsoft Teams",
                    "message": "Hi"
                }
            }),
        };

        let params = node.data.get("params").cloned().unwrap_or(Value::Null);
        let platform = infer_messaging_platform(&params, &node)
            .expect("platform should be inferred from params service");

        assert_eq!(platform, MessagingPlatform::Teams);
    }

    #[test]
    fn infer_platform_errors_when_unknown() {
        let node = Node {
            id: "action-legacy".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "service": "Unknown",
                    "message": "Hi"
                }
            }),
        };

        let params = node.data.get("params").cloned().unwrap_or(Value::Null);
        let err =
            infer_messaging_platform(&params, &node).expect_err("unknown platform should error");

        assert_eq!(err, "Platform is required");
    }

    #[tokio::test]
    async fn slack_personal_oauth_rejected_without_connection() {
        let (addr, _, _) = spawn_stub_server(|| {
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"ok":true,"ts":"456.789","channel":"C456"}"#))
                .unwrap()
        })
        .await;

        let _guard = EnvGuard::set("SLACK_API_BASE", format!("http://{}/api", addr));

        let config = test_config();
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());
        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let workspace_connection_id = Uuid::new_v4();

        let access_token = "slack-personal-access";
        let refresh_token = "slack-personal-refresh";
        let encrypted_access = encrypt_secret(&encryption_key, access_token).unwrap();
        let encrypted_refresh = encrypt_secret(&encryption_key, refresh_token).unwrap();

        let token_id = Uuid::new_v4();
        let record = UserOAuthToken {
            id: token_id,
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Slack,
            access_token: encrypted_access,
            refresh_token: encrypted_refresh,
            expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
            account_email: "alice@example.com".into(),
            metadata: serde_json::json!({}),
            is_shared: false,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };

        let repo = Arc::new(StaticTokenRepo { record }) as Arc<dyn UserOAuthTokenRepository>;
        let workspace_repo = Arc::new(RecordingWorkspaceConnections::default())
            as Arc<dyn WorkspaceConnectionRepository>;
        let oauth_accounts = Arc::new(OAuthAccountService::new(
            repo,
            workspace_repo.clone(),
            Arc::clone(&encryption_key),
            Arc::new(Client::new()),
            &config.oauth,
        ));

        let mut state = build_state_with_oauth(
            oauth_accounts,
            WorkspaceOAuthService::test_stub(),
            Arc::clone(&config),
            Arc::new(NoopWorkspaceRepository),
        );
        state.workspace_connection_repo = workspace_repo;

        let mut run = test_run();
        run.user_id = user_id;
        run.workspace_id = Some(workspace_id);

        let node = Node {
            id: "slack-personal-oauth".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "Slack",
                    "channel": "#alerts",
                    "message": "Hello personal",
                    "postAsUser": true,
                    "workspace_connection_id": workspace_connection_id,
                    "connectionScope": "user",
                    "connectionId": token_id,
                    "accountEmail": "alice@example.com",
                    "connection": {
                        "connectionScope": "user",
                        "connectionId": token_id,
                        "accountEmail": "alice@example.com"
                    }
                }
            }),
        };

        let res = execute_messaging(&node, &Value::Null, &state, &run).await;
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert!(err.contains("personal_user error: personal Slack token missing or invalid team id. Reconnect Slack."));
    }

    #[tokio::test]
    async fn slack_workspace_oauth_rejected_without_connection() {
        let (addr, _, _) = spawn_stub_server(|| {
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"ok":true,"ts":"789.012","channel":"C789"}"#))
                .unwrap()
        })
        .await;

        let _guard = EnvGuard::set("SLACK_API_BASE", format!("http://{}/api", addr));

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
            provider: ConnectedOAuthProvider::Slack,
            access_token: encrypt_secret(&encryption_key, "workspace-slack-access").unwrap(),
            refresh_token: encrypt_secret(&encryption_key, "workspace-slack-refresh").unwrap(),
            expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
            account_email: "workspace@example.com".into(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            metadata: serde_json::Value::Null,
            bot_user_id: None,
            incoming_webhook_url: None,
            slack_team_id: Some("T123".into()),
        };

        let (workspace_service, _) =
            workspace_oauth_with_connection(connection, Arc::clone(&encryption_key));

        let oauth_accounts = OAuthAccountService::test_stub();
        let state = build_state_with_oauth(
            oauth_accounts,
            workspace_service,
            Arc::clone(&config),
            Arc::new(NoopWorkspaceRepository),
        );

        let mut run = test_run();
        run.workspace_id = Some(workspace_id);

        let node = Node {
            id: "slack-workspace-oauth".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "Slack",
                    "channel": "#team",
                    "message": "Hello workspace",
                    "identity": "workspace_bot",
                    "connectionScope": "workspace",
                    "connectionId": connection_id,
                    "accountEmail": "workspace@example.com",
                    "connection": {
                        "connectionScope": "workspace",
                        "connectionId": connection_id,
                        "accountEmail": "workspace@example.com"
                    }
                }
            }),
        };

        let (output, _) = execute_messaging(&node, &Value::Null, &state, &run)
            .await
            .expect("slack workspace oauth should succeed");

        assert_eq!(output["service"], "Slack");
        assert_eq!(output["oauthAccountEmail"], "workspace@example.com");
        assert_eq!(output["connectionScope"], "workspace");
        assert_eq!(output["connectionId"], connection_id.to_string());
    }

    #[tokio::test]
    async fn slack_workspace_token_expired_refreshes_and_retries() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = Arc::clone(&call_count);
        let (addr, mut rx, handle) = spawn_stub_server(move || {
            let call = call_count_clone.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"ok":false,"error":"token_expired"}"#))
                    .unwrap()
            } else {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"ok":true,"ts":"789.012","channel":"C789"}"#))
                    .unwrap()
            }
        })
        .await;

        let _guard = EnvGuard::set("SLACK_API_BASE", format!("http://{}/api", addr));

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
            provider: ConnectedOAuthProvider::Slack,
            access_token: encrypt_secret(&encryption_key, "workspace-slack-access").unwrap(),
            refresh_token: encrypt_secret(&encryption_key, "workspace-slack-refresh").unwrap(),
            expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
            account_email: "workspace@example.com".into(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            metadata: serde_json::Value::Null,
            bot_user_id: None,
            incoming_webhook_url: None,
            slack_team_id: Some("T123".into()),
        };

        let connection_repo = Arc::new(RecordingWorkspaceConnections::with_connection(
            connection.clone(),
        ));
        let user_repo: Arc<dyn UserOAuthTokenRepository> = Arc::new(NoopUserTokenRepo);

        let mut oauth_accounts = OAuthAccountService::new(
            user_repo.clone(),
            connection_repo.clone(),
            Arc::clone(&encryption_key),
            Arc::new(Client::new()),
            &config.oauth,
        );
        oauth_accounts.set_refresh_override(Some(Arc::new(
            move |provider: ConnectedOAuthProvider, refresh_token: &str| {
                assert_eq!(provider, ConnectedOAuthProvider::Slack);
                assert_eq!(refresh_token, "workspace-slack-refresh");
                Ok(AuthorizationTokens {
                    access_token: "refreshed-workspace-access".into(),
                    refresh_token: "refreshed-workspace-refresh".into(),
                    expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
                    account_email: "workspace@example.com".into(),
                    provider_user_id: None,
                    notion: None,
                    slack: Some(SlackOAuthMetadata {
                        team_id: Some("T123".into()),
                        ..Default::default()
                    }),
                })
            },
        )));
        let oauth_accounts = Arc::new(oauth_accounts);

        let workspace_token_refresher: Arc<dyn WorkspaceTokenRefresher> =
            oauth_accounts.clone() as Arc<dyn WorkspaceTokenRefresher>;
        let workspace_service = Arc::new(WorkspaceOAuthService::new(
            user_repo,
            Arc::new(NoopWorkspaceRepository),
            connection_repo.clone(),
            workspace_token_refresher,
            Arc::clone(&encryption_key),
        ));

        let mut state = build_state_with_oauth(
            oauth_accounts,
            workspace_service,
            Arc::clone(&config),
            Arc::new(NoopWorkspaceRepository),
        );
        state.workspace_connection_repo = connection_repo.clone();

        let mut run = test_run();
        run.workspace_id = Some(workspace_id);

        let node = Node {
            id: "slack-workspace-refresh".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "Slack",
                    "channel": "#team",
                    "message": "Hello workspace",
                    "identity": "workspace_bot",
                    "connectionScope": "workspace",
                    "connectionId": connection_id,
                    "accountEmail": "workspace@example.com",
                    "connection": {
                        "connectionScope": "workspace",
                        "connectionId": connection_id,
                        "accountEmail": "workspace@example.com"
                    }
                }
            }),
        };

        let (output, _) = execute_messaging(&node, &Value::Null, &state, &run)
            .await
            .expect("slack workspace oauth should retry after refresh");

        assert_eq!(output["service"], "Slack");

        let first = rx.recv().await.expect("first request");
        let second = rx.recv().await.expect("second request");

        let auth_header = |request: &RecordedRequest| {
            request
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                .map(|(_, value)| value.clone())
        };

        assert_eq!(
            auth_header(&first),
            Some("Bearer workspace-slack-access".to_string())
        );
        assert_eq!(
            auth_header(&second),
            Some("Bearer refreshed-workspace-access".to_string())
        );

        let updated = connection_repo.snapshot().expect("connection");
        let updated_access = decrypt_secret(&encryption_key, &updated.access_token).unwrap();
        let updated_refresh = decrypt_secret(&encryption_key, &updated.refresh_token).unwrap();

        assert_eq!(updated_access, "refreshed-workspace-access");
        assert_eq!(updated_refresh, "refreshed-workspace-refresh");

        handle.abort();
    }

    #[tokio::test]
    async fn slack_personal_token_expired_refreshes_and_retries() {
        let call_count = Arc::new(AtomicUsize::new(0));
        let call_count_clone = Arc::clone(&call_count);
        let (addr, mut rx, handle) = spawn_stub_server(move || {
            let call = call_count_clone.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"ok":false,"error":"token_expired"}"#))
                    .unwrap()
            } else {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"ok":true,"ts":"456.789","channel":"C456"}"#))
                    .unwrap()
            }
        })
        .await;

        let _guard = EnvGuard::set("SLACK_API_BASE", format!("http://{}/api", addr));

        let config = test_config();
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());
        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let workspace_connection_id = Uuid::new_v4();

        let access_token = "slack-personal-access";
        let refresh_token = "slack-personal-refresh";
        let encrypted_access = encrypt_secret(&encryption_key, access_token).unwrap();
        let encrypted_refresh = encrypt_secret(&encryption_key, refresh_token).unwrap();

        let token_id = Uuid::new_v4();
        let encrypted_team_id = encrypt_secret(&encryption_key, "T123").unwrap();
        let record = UserOAuthToken {
            id: token_id,
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Slack,
            access_token: encrypted_access,
            refresh_token: encrypted_refresh,
            expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
            account_email: "alice@example.com".into(),
            metadata: serde_json::json!({
                "slack": { "team_id": encrypted_team_id }
            }),
            is_shared: false,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };

        let connection = WorkspaceConnection {
            id: workspace_connection_id,
            connection_id: Some(Uuid::new_v4()),
            workspace_id,
            created_by: user_id,
            owner_user_id: user_id,
            user_oauth_token_id: None,
            provider: ConnectedOAuthProvider::Slack,
            access_token: encrypt_secret(&encryption_key, "workspace-access").unwrap(),
            refresh_token: encrypt_secret(&encryption_key, "workspace-refresh").unwrap(),
            expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
            account_email: "workspace@example.com".into(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            metadata: serde_json::Value::Null,
            bot_user_id: None,
            incoming_webhook_url: None,
            slack_team_id: Some("T123".into()),
        };

        let connection_repo = Arc::new(RecordingWorkspaceConnections::with_connection(
            connection.clone(),
        ));
        let token_repo = Arc::new(RecordingTokenRepo::new(record));
        let token_repo_trait: Arc<dyn UserOAuthTokenRepository> = token_repo.clone();

        let mut oauth_accounts = OAuthAccountService::new(
            token_repo_trait,
            connection_repo.clone(),
            Arc::clone(&encryption_key),
            Arc::new(Client::new()),
            &config.oauth,
        );
        oauth_accounts.set_refresh_override(Some(Arc::new(
            move |provider: ConnectedOAuthProvider, refresh_token: &str| {
                assert_eq!(provider, ConnectedOAuthProvider::Slack);
                assert_eq!(refresh_token, "slack-personal-refresh");
                Ok(AuthorizationTokens {
                    access_token: "refreshed-personal-access".into(),
                    refresh_token: "refreshed-personal-refresh".into(),
                    expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
                    account_email: "alice@example.com".into(),
                    provider_user_id: None,
                    notion: None,
                    slack: Some(SlackOAuthMetadata {
                        team_id: Some("T123".into()),
                        ..Default::default()
                    }),
                })
            },
        )));
        let oauth_accounts = Arc::new(oauth_accounts);

        let mut state = build_state_with_oauth(
            oauth_accounts,
            WorkspaceOAuthService::test_stub(),
            Arc::clone(&config),
            Arc::new(NoopWorkspaceRepository),
        );
        state.workspace_connection_repo = connection_repo.clone();

        let mut run = test_run();
        run.user_id = user_id;
        run.workspace_id = Some(workspace_id);

        let node = Node {
            id: "slack-personal-refresh".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "Slack",
                    "channel": "#alerts",
                    "message": "Hello personal",
                    "postAsUser": true,
                    "workspace_connection_id": workspace_connection_id,
                    "connectionScope": "user",
                    "connectionId": token_id,
                    "accountEmail": "alice@example.com",
                    "connection": {
                        "connectionScope": "user",
                        "connectionId": token_id,
                        "accountEmail": "alice@example.com"
                    }
                }
            }),
        };

        let (output, _) = execute_messaging(&node, &Value::Null, &state, &run)
            .await
            .expect("slack personal oauth should retry after refresh");

        assert_eq!(output["service"], "Slack");

        let first = rx.recv().await.expect("first request");
        let second = rx.recv().await.expect("second request");

        let auth_header = |request: &RecordedRequest| {
            request
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                .map(|(_, value)| value.clone())
        };

        assert_eq!(
            auth_header(&first),
            Some("Bearer slack-personal-access".to_string())
        );
        assert_eq!(
            auth_header(&second),
            Some("Bearer refreshed-personal-access".to_string())
        );

        let updated = token_repo.snapshot();
        let updated_access = decrypt_secret(&encryption_key, &updated.access_token).unwrap();
        let updated_refresh = decrypt_secret(&encryption_key, &updated.refresh_token).unwrap();

        assert_eq!(updated_access, "refreshed-personal-access");
        assert_eq!(updated_refresh, "refreshed-personal-refresh");

        handle.abort();
    }

    #[tokio::test]
    async fn slack_workspace_connection_rejects_when_membership_revoked() {
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
            provider: ConnectedOAuthProvider::Slack,
            access_token: encrypt_secret(&encryption_key, "workspace-slack-access").unwrap(),
            refresh_token: encrypt_secret(&encryption_key, "workspace-slack-refresh").unwrap(),
            expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
            account_email: "workspace@example.com".into(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            metadata: serde_json::Value::Null,
            bot_user_id: None,
            incoming_webhook_url: None,
            slack_team_id: Some("T123".into()),
        };

        let (workspace_service, repo) =
            workspace_oauth_with_connection(connection, Arc::clone(&encryption_key));

        let oauth_accounts = OAuthAccountService::test_stub();
        let workspace_repo: Arc<dyn WorkspaceRepository> =
            Arc::new(StaticWorkspaceMembershipRepository::denying());
        let state = build_state_with_oauth(
            oauth_accounts,
            workspace_service,
            Arc::clone(&config),
            workspace_repo,
        );

        let mut run = test_run();
        run.workspace_id = Some(workspace_id);

        let node = Node {
            id: "slack-workspace-forbidden".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "Slack",
                    "channel": "#team",
                    "message": "Hello workspace",
                    "identity": "workspace_bot",
                    "connection": {
                        "connectionScope": "workspace",
                        "connectionId": connection_id,
                        "accountEmail": "workspace@example.com"
                    }
                }
            }),
        };

        let err = execute_messaging(&node, &Value::Null, &state, &run)
            .await
            .expect_err("revoked members should be blocked from workspace Slack tokens");

        assert!(err.contains("Forbidden"));
        assert!(
            repo.find_calls().is_empty(),
            "workspace OAuth should not be queried when membership fails"
        );
    }

    #[tokio::test]
    async fn slack_personal_user_team_mismatch_fails_execution() {
        let (addr, _, _) = spawn_stub_server(|| {
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"ok":true,"ts":"456.789","channel":"C456"}"#))
                .unwrap()
        })
        .await;

        let _guard = EnvGuard::set("SLACK_API_BASE", format!("http://{}/api", addr));

        let config = test_config();
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());
        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();

        let connection_id = Uuid::new_v4();
        let access_token = "slack-personal-access";
        let refresh_token = "slack-personal-refresh";
        let encrypted_access = encrypt_secret(&encryption_key, access_token).unwrap();
        let encrypted_refresh = encrypt_secret(&encryption_key, refresh_token).unwrap();

        let token_id = Uuid::new_v4();
        let encrypted_team_id = encrypt_secret(&encryption_key, "T123").unwrap();
        let record = UserOAuthToken {
            id: token_id,
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Slack,
            access_token: encrypted_access.clone(),
            refresh_token: encrypted_refresh.clone(),
            expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
            account_email: "alice@example.com".into(),
            metadata: serde_json::json!({
                "slack": { "team_id": encrypted_team_id }
            }),
            is_shared: false,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };

        // workspace connection has a different team
        let token_id_ws = Uuid::new_v4();
        let creator_id = Uuid::new_v4();
        let connection = WorkspaceConnection {
            id: connection_id,
            connection_id: Some(token_id_ws),
            workspace_id,
            created_by: creator_id,
            owner_user_id: creator_id,
            user_oauth_token_id: Some(token_id_ws),
            provider: ConnectedOAuthProvider::Slack,
            access_token: encrypt_secret(&encryption_key, "workspace-slack-access").unwrap(),
            refresh_token: encrypt_secret(&encryption_key, "workspace-slack-refresh").unwrap(),
            expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
            account_email: "workspace@example.com".into(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            metadata: serde_json::Value::Null,
            bot_user_id: None,
            incoming_webhook_url: None,
            slack_team_id: Some("T999".into()),
        };

        let (workspace_service, repo) =
            workspace_oauth_with_connection(connection.clone(), Arc::clone(&encryption_key));

        let repo = repo as Arc<dyn WorkspaceConnectionRepository>;

        let repo_list: Arc<dyn UserOAuthTokenRepository> = Arc::new(StaticTokenRepo { record });
        let oauth_accounts = Arc::new(OAuthAccountService::new(
            repo_list,
            repo.clone(),
            Arc::clone(&encryption_key),
            Arc::new(Client::new()),
            &config.oauth,
        ));

        let mut state = build_state_with_oauth(
            oauth_accounts,
            workspace_service,
            Arc::clone(&config),
            Arc::new(NoopWorkspaceRepository),
        );
        state.workspace_connection_repo = repo.clone();

        let mut run = test_run();
        run.user_id = user_id;
        run.workspace_id = Some(workspace_id);

        let node = Node {
            id: "slack-personal-oauth".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "Slack",
                    "channel": "#alerts",
                    "message": "Hello personal",
                    "postAsUser": true,
                    "workspace_connection_id": connection_id,
                    "connectionScope": "user",
                    "connectionId": token_id,
                    "accountEmail": "alice@example.com",
                    "connection": {
                        "connectionScope": "user",
                        "connectionId": token_id,
                        "accountEmail": "alice@example.com"
                    }
                }
            }),
        };

        let res = execute_messaging(&node, &Value::Null, &state, &run).await;
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert!(err.contains("personal_user error: Slack team mismatch between personal token (T123) and workspace Slack connection (T999)"));
    }

    #[tokio::test]
    async fn slack_workspace_mixed_teams_rejected() {
        let config = test_config();
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());
        let workspace_id = Uuid::new_v4();

        // Two different workspace connections with different teams
        let connection_a = WorkspaceConnection {
            id: Uuid::new_v4(),
            connection_id: Some(Uuid::new_v4()),
            workspace_id,
            created_by: Uuid::new_v4(),
            owner_user_id: Uuid::new_v4(),
            user_oauth_token_id: None,
            provider: ConnectedOAuthProvider::Slack,
            access_token: encrypt_secret(&encryption_key, "a").unwrap(),
            refresh_token: encrypt_secret(&encryption_key, "a").unwrap(),
            expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
            account_email: "a@example.com".into(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            metadata: serde_json::Value::Null,
            bot_user_id: None,
            incoming_webhook_url: None,
            slack_team_id: Some("TAAA".into()),
        };

        let connection_b = WorkspaceConnection {
            id: Uuid::new_v4(),
            connection_id: Some(Uuid::new_v4()),
            workspace_id,
            created_by: Uuid::new_v4(),
            owner_user_id: Uuid::new_v4(),
            user_oauth_token_id: None,
            provider: ConnectedOAuthProvider::Slack,
            access_token: encrypt_secret(&encryption_key, "b").unwrap(),
            refresh_token: encrypt_secret(&encryption_key, "b").unwrap(),
            expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
            account_email: "b@example.com".into(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            metadata: serde_json::Value::Null,
            bot_user_id: None,
            incoming_webhook_url: None,
            slack_team_id: Some("TBBB".into()),
        };

        struct TwoConns(WorkspaceConnection, WorkspaceConnection);
        #[async_trait]
        impl WorkspaceConnectionRepository for TwoConns {
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
                if connection_id == self.0.id {
                    return Ok(Some(self.0.clone()));
                }
                if connection_id == self.1.id {
                    return Ok(Some(self.1.clone()));
                }
                Ok(None)
            }
            async fn get_by_id(
                &self,
                connection_id: Uuid,
            ) -> Result<WorkspaceConnection, SqlxError> {
                self.find_by_id(connection_id)
                    .await?
                    .ok_or(SqlxError::RowNotFound)
            }
            async fn list_for_workspace_provider(
                &self,
                _workspace_id: Uuid,
                _provider: ConnectedOAuthProvider,
            ) -> Result<Vec<WorkspaceConnection>, SqlxError> {
                Ok(vec![self.0.clone(), self.1.clone()])
            }
            async fn find_by_source_token(
                &self,
                _user_oauth_token_id: Uuid,
            ) -> Result<Vec<WorkspaceConnection>, SqlxError> {
                Ok(Vec::new())
            }
            async fn list_by_workspace_and_provider(
                &self,
                _workspace_id: Uuid,
                _provider: ConnectedOAuthProvider,
            ) -> Result<Vec<WorkspaceConnection>, SqlxError> {
                Ok(vec![self.0.clone(), self.1.clone()])
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
                _connection_id: Uuid,
                _access_token: String,
                _refresh_token: String,
                _expires_at: OffsetDateTime,
                _account_email: String,
                _bot_user_id: Option<String>,
                _slack_team_id: Option<String>,
                _incoming_webhook_url: Option<String>,
            ) -> Result<WorkspaceConnection, SqlxError> {
                Err(SqlxError::RowNotFound)
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
            ) -> Result<WorkspaceConnection, SqlxError> {
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
                _workspace_id: Uuid,
                _owner_user_id: Uuid,
                _provider: ConnectedOAuthProvider,
                _connection_id: Uuid,
            ) -> Result<(), SqlxError> {
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

        let two_repo = Arc::new(TwoConns(connection_a.clone(), connection_b.clone()));

        let oauth_accounts = OAuthAccountService::test_stub();
        // Ensure the workspace_oauth service can resolve the selected connection
        let (workspace_service, _recording_repo) =
            workspace_oauth_with_connection(connection_a.clone(), Arc::clone(&encryption_key));
        let state = build_state_with_oauth(
            oauth_accounts,
            workspace_service,
            Arc::clone(&config),
            Arc::new(NoopWorkspaceRepository),
        );

        let mut state = state;
        state.workspace_connection_repo = two_repo;

        let mut run = test_run();
        run.workspace_id = Some(workspace_id);

        let node = Node {
            id: "slack-workspace-oauth".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "Slack",
                    "channel": "#team",
                    "message": "Hello workspace",
                    "identity": "workspace_bot",
                    "connection": {
                        "connectionScope": "workspace",
                        "connectionId": connection_a.id,
                        "accountEmail": "a@example.com"
                    }
                }
            }),
        };

        let res = execute_messaging(&node, &Value::Null, &state, &run).await;
        assert!(res.is_err());
        let err = res.err().unwrap();
        println!("ERR: {}", err);
        assert!(
            err.contains("workspace_bot error: multiple Slack teams configured for this workspace")
        );
    }

    #[tokio::test]
    async fn slack_workspace_execution_fails_when_multiple_connections_and_no_connection_id() {
        let config = test_config();
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());
        let workspace_id = Uuid::new_v4();

        let connection_a = WorkspaceConnection {
            id: Uuid::new_v4(),
            connection_id: Some(Uuid::new_v4()),
            workspace_id,
            created_by: Uuid::new_v4(),
            owner_user_id: Uuid::new_v4(),
            user_oauth_token_id: None,
            provider: ConnectedOAuthProvider::Slack,
            access_token: encrypt_secret(&encryption_key, "a").unwrap(),
            refresh_token: encrypt_secret(&encryption_key, "a").unwrap(),
            expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
            account_email: "a@example.com".into(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            metadata: serde_json::Value::Null,
            bot_user_id: None,
            incoming_webhook_url: None,
            slack_team_id: Some("T1".into()),
        };

        let connection_b = WorkspaceConnection {
            id: Uuid::new_v4(),
            connection_id: Some(Uuid::new_v4()),
            workspace_id,
            created_by: Uuid::new_v4(),
            owner_user_id: Uuid::new_v4(),
            user_oauth_token_id: None,
            provider: ConnectedOAuthProvider::Slack,
            access_token: encrypt_secret(&encryption_key, "b").unwrap(),
            refresh_token: encrypt_secret(&encryption_key, "b").unwrap(),
            expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
            account_email: "b@example.com".into(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            metadata: serde_json::Value::Null,
            bot_user_id: None,
            incoming_webhook_url: None,
            slack_team_id: Some("T1".into()),
        };

        struct TwoConnsLocal(WorkspaceConnection, WorkspaceConnection);
        #[async_trait]
        impl WorkspaceConnectionRepository for TwoConnsLocal {
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
                if connection_id == self.0.id {
                    return Ok(Some(self.0.clone()));
                }
                if connection_id == self.1.id {
                    return Ok(Some(self.1.clone()));
                }
                Ok(None)
            }
            async fn get_by_id(
                &self,
                connection_id: Uuid,
            ) -> Result<WorkspaceConnection, SqlxError> {
                self.find_by_id(connection_id)
                    .await?
                    .ok_or(SqlxError::RowNotFound)
            }
            async fn list_for_workspace_provider(
                &self,
                _workspace_id: Uuid,
                _provider: ConnectedOAuthProvider,
            ) -> Result<Vec<WorkspaceConnection>, SqlxError> {
                Ok(vec![self.0.clone(), self.1.clone()])
            }
            async fn find_by_source_token(
                &self,
                _user_oauth_token_id: Uuid,
            ) -> Result<Vec<WorkspaceConnection>, SqlxError> {
                Ok(Vec::new())
            }
            async fn list_by_workspace_and_provider(
                &self,
                _workspace_id: Uuid,
                _provider: ConnectedOAuthProvider,
            ) -> Result<Vec<WorkspaceConnection>, SqlxError> {
                Ok(vec![self.0.clone(), self.1.clone()])
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
                _connection_id: Uuid,
                _access_token: String,
                _refresh_token: String,
                _expires_at: OffsetDateTime,
                _account_email: String,
                _bot_user_id: Option<String>,
                _slack_team_id: Option<String>,
                _incoming_webhook_url: Option<String>,
            ) -> Result<WorkspaceConnection, SqlxError> {
                Err(SqlxError::RowNotFound)
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
            ) -> Result<WorkspaceConnection, SqlxError> {
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
                _workspace_id: Uuid,
                _owner_user_id: Uuid,
                _provider: ConnectedOAuthProvider,
                _connection_id: Uuid,
            ) -> Result<(), SqlxError> {
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

        let repo = Arc::new(TwoConnsLocal(connection_a.clone(), connection_b.clone()));

        // Build OAuthAccountService and WorkspaceOAuthService backed by the
        // TwoConnsLocal repository so both connections are considered usable.
        let user_repo: Arc<dyn UserOAuthTokenRepository> = Arc::new(NoopUserTokenRepo);
        let connection_repo_trait: Arc<dyn WorkspaceConnectionRepository> = repo.clone();

        let oauth_accounts = Arc::new(OAuthAccountService::new(
            user_repo.clone(),
            connection_repo_trait.clone(),
            Arc::clone(&encryption_key),
            Arc::new(Client::new()),
            &config.oauth,
        ));

        let workspace_token_refresher: Arc<dyn WorkspaceTokenRefresher> =
            oauth_accounts.clone() as Arc<dyn WorkspaceTokenRefresher>;
        let workspace_service = Arc::new(WorkspaceOAuthService::new(
            user_repo,
            Arc::new(NoopWorkspaceRepository),
            connection_repo_trait.clone(),
            workspace_token_refresher,
            Arc::clone(&encryption_key),
        ));

        let mut state = build_state_with_oauth(
            oauth_accounts,
            workspace_service,
            Arc::clone(&config),
            Arc::new(NoopWorkspaceRepository),
        );
        state.workspace_connection_repo = repo;

        let mut run = test_run();
        run.workspace_id = Some(workspace_id);

        let node = Node {
            id: "slack-workspace-no-id".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "Slack",
                    "channel": "#team",
                    "message": "Hello",
                    "identity": "workspace_bot",
                    "connection": { "connectionScope": "workspace" }
                }
            }),
        };

        let res = execute_messaging(&node, &Value::Null, &state, &run).await;
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert!(err.contains(
            "workspace_bot error: workspace Slack execution requires an explicit connectionId"
        ));
    }

    #[tokio::test]
    async fn slack_workspace_execution_fails_when_single_connection_and_no_connection_id() {
        let config = test_config();
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());
        let workspace_id = Uuid::new_v4();

        let connection = WorkspaceConnection {
            id: Uuid::new_v4(),
            connection_id: Some(Uuid::new_v4()),
            workspace_id,
            created_by: Uuid::new_v4(),
            owner_user_id: Uuid::new_v4(),
            user_oauth_token_id: None,
            provider: ConnectedOAuthProvider::Slack,
            access_token: encrypt_secret(&encryption_key, "token").unwrap(),
            refresh_token: encrypt_secret(&encryption_key, "refresh").unwrap(),
            expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
            account_email: "owner@example.com".into(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            metadata: serde_json::Value::Null,
            bot_user_id: None,
            incoming_webhook_url: None,
            slack_team_id: Some("T1".into()),
        };

        let repo = Arc::new(RecordingWorkspaceConnections::with_connection(
            connection.clone(),
        ));

        // Provide a workspace OAuth service as usual, but engine must not infer identity.
        let oauth_accounts = OAuthAccountService::test_stub();
        let (workspace_service, _recording_repo) =
            workspace_oauth_with_connection(connection.clone(), Arc::clone(&encryption_key));

        let mut state = build_state_with_oauth(
            oauth_accounts,
            workspace_service,
            Arc::clone(&config),
            Arc::new(NoopWorkspaceRepository),
        );
        state.workspace_connection_repo = repo;

        let mut run = test_run();
        run.workspace_id = Some(workspace_id);

        let node = Node {
            id: "slack-workspace-single-no-id".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "Slack",
                    "channel": "#team",
                    "message": "Hello",
                    "identity": "workspace_bot",
                    "connection": { "connectionScope": "workspace" }
                }
            }),
        };

        let res = execute_messaging(&node, &Value::Null, &state, &run).await;
        assert!(res.is_err());
        let err = res.err().unwrap();
        assert!(err.contains(
            "workspace_bot error: workspace Slack execution requires an explicit connectionId"
        ));
    }

    #[tokio::test]
    async fn teams_webhook_failure_propagates() {
        let (addr, _rx, handle) = spawn_stub_server(|| {
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("bad payload"))
                .unwrap()
        })
        .await;

        let node = Node {
            id: "action-5".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "Teams",
                    "deliveryMethod": "Incoming Webhook",
                    "webhookType": "Connector",
                    "webhookUrl": format!("http://{addr}/teams"),
                    "message": "Alert"
                }
            }),
        };

        let err = execute_default(&node, &Value::Null)
            .await
            .expect_err("teams should fail");
        handle.abort();
        assert!(err.contains("bad payload"));
        assert!(err.contains("400"));
    }

    #[tokio::test]
    async fn teams_workflow_webhook_ignores_legacy_fields() {
        let (addr, mut rx, handle) = spawn_stub_server(|| {
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .unwrap()
        })
        .await;

        let node = Node {
            id: "action-7".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "Teams",
                    "deliveryMethod": "Incoming Webhook",
                    "webhookType": "Workflow/Power Automate",
                    "webhookUrl": format!("http://{addr}/workflow"),
                    "message": "Workflow alert",
                    "summary": "Workflow summary",
                    "cardJson": "{\"type\":\"AdaptiveCard\"}",
                    "workflowOption": "Basic (Raw JSON)",
                    "workflowRawJson": r#"{
                        "type": "message",
                        "text": "payload text",
                        "summary": "payload summary"
                    }"#
                }
            }),
        };

        let (output, _) = execute_default(&node, &Value::Null)
            .await
            .expect("workflow webhook succeeds");

        assert_eq!(output["service"], "Teams");
        assert_eq!(output["status"], 200);

        let req = rx.recv().await.expect("workflow request recorded");
        handle.abort();
        let body: Value = serde_json::from_slice(&req.body).expect("json body");
        assert_eq!(body["type"], "message");
        assert_eq!(body["text"], "payload text");
        assert_eq!(body["summary"], "payload summary");
        assert!(body.get("attachments").is_none());
    }

    #[tokio::test]
    async fn teams_workflow_webhook_sends_raw_json_payload() {
        let (addr, mut rx, handle) = spawn_stub_server(|| {
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .unwrap()
        })
        .await;

        let node = Node {
            id: "action-8".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "Teams",
                    "deliveryMethod": "Incoming Webhook",
                    "webhookType": "Workflow/Power Automate",
                    "webhookUrl": format!("http://{addr}/workflow"),
                    "workflowOption": "Basic (Raw JSON)",
                    "workflowRawJson": r#"{
                        "type": "message",
                        "text": "Hello {{ user }}",
                        "summary": "raw"
                    }"#
                }
            }),
        };

        let context = json!({ "user": "Charlie" });

        let (output, _) = execute_default(&node, &context)
            .await
            .expect("raw json workflow succeeds");

        assert_eq!(output["service"], "Teams");
        assert_eq!(output["status"], 200);

        let req = rx.recv().await.expect("workflow request recorded");
        handle.abort();
        let body: Value = serde_json::from_slice(&req.body).expect("json body");
        assert_eq!(body["type"], "message");
        assert_eq!(body["text"], "Hello Charlie");
        assert_eq!(body["summary"], "raw");
    }

    #[tokio::test]
    async fn teams_workflow_webhook_attaches_header_secret() {
        let (addr, mut rx, handle) = spawn_stub_server(|| {
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .unwrap()
        })
        .await;

        let node = Node {
            id: "action-9".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "Teams",
                    "deliveryMethod": "Incoming Webhook",
                    "webhookType": "Workflow/Power Automate",
                    "webhookUrl": format!("http://{addr}/workflow"),
                    "workflowOption": "Header Secret Auth",
                    "workflowRawJson": r#"{
                        "type": "message",
                        "text": "secret"
                    }"#,
                    "workflowHeaderName": "X-Workflow-Secret",
                    "workflowHeaderSecret": "super-secret"
                }
            }),
        };

        let (output, _) = execute_default(&node, &Value::Null)
            .await
            .expect("header secret workflow succeeds");

        assert_eq!(output["status"], 200);

        let req = rx.recv().await.expect("workflow request recorded");
        handle.abort();

        let header = req
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("X-Workflow-Secret"))
            .map(|(_, value)| value.clone())
            .expect("header should exist");
        assert_eq!(header, "super-secret");
    }

    #[test]
    fn sanitize_teams_params_drops_oauth_fields() {
        let params = json!({
            "deliveryMethod": "Incoming Webhook",
            "webhookType": "Workflow/Power Automate",
            "webhookUrl": "https://example.com/workflow",
            "workflowOption": "Basic (Raw JSON)",
            "workflowRawJson": "{\"type\":\"message\"}",
            "workflowOAuthUrl": "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
            "workflowOAuthClientId": "client",
            "workflowOAuthClientSecret": "secret",
            "workflowOAuthScope": "scope",
            "workflowOAuthTenantId": "tenant"
        });

        let sanitized = sanitize_teams_params(&params);
        let map = sanitized
            .as_object()
            .expect("teams params should sanitize to an object");

        assert_eq!(
            map.get("workflowOption")
                .and_then(|v| v.as_str())
                .unwrap_or_default(),
            "Basic (Raw JSON)"
        );
        assert!(map.get("workflowRawJson").is_some());
        assert!(map.get("workflowOAuthUrl").is_none());
        assert!(map.get("workflowOAuthClientId").is_none());
        assert!(map.get("workflowOAuthClientSecret").is_none());
        assert!(map.get("workflowOAuthScope").is_none());
        assert!(map.get("workflowOAuthTenantId").is_none());
    }

    #[test]
    fn sanitize_teams_params_preserves_delegated_fields() {
        let params = json!({
            "deliveryMethod": "Delegated OAuth (Post as user)",
            "oauthProvider": "microsoft",
            "oauthConnectionId": "microsoft",
            "oauthAccountEmail": "alice@example.com",
            "connection": {
                "connectionScope": "workspace",
                "connectionId": "123",
                "accountEmail": "alice@example.com"
            },
            "teamId": "team-1",
            "teamName": "Team One",
            "channelId": "channel-7",
            "channelName": "General",
            "messageType": "Text",
            "message": "Hello",
            "mentions": [
                { "userId": "user-1", "displayName": "Jane" },
                { "user_id": "user-2", "display_name": "John", "id": "member-2" },
                { "userId": "user-1", "displayName": "Duplicate" }
            ]
        });

        let sanitized = sanitize_teams_params(&params);
        let map = sanitized
            .as_object()
            .expect("delegated params should sanitize to an object");

        assert_eq!(
            map.get("deliveryMethod").and_then(|v| v.as_str()).unwrap(),
            "Delegated OAuth (Post as user)"
        );
        assert_eq!(
            map.get("oauthProvider").and_then(|v| v.as_str()).unwrap(),
            "microsoft"
        );
        assert_eq!(
            map.get("oauthConnectionId")
                .and_then(|v| v.as_str())
                .unwrap(),
            "microsoft"
        );
        assert_eq!(
            map.get("oauthAccountEmail")
                .and_then(|v| v.as_str())
                .unwrap(),
            "alice@example.com"
        );
        let connection_obj = map
            .get("connection")
            .and_then(|v| v.as_object())
            .expect("connection should be preserved");
        assert_eq!(
            connection_obj
                .get("connectionScope")
                .and_then(|v| v.as_str())
                .unwrap(),
            "workspace"
        );
        assert_eq!(
            connection_obj
                .get("connectionId")
                .and_then(|v| v.as_str())
                .unwrap(),
            "123"
        );
        assert_eq!(
            connection_obj
                .get("accountEmail")
                .and_then(|v| v.as_str())
                .unwrap(),
            "alice@example.com"
        );
        assert_eq!(
            map.get("teamId").and_then(|v| v.as_str()).unwrap(),
            "team-1"
        );
        assert_eq!(
            map.get("channelId").and_then(|v| v.as_str()).unwrap(),
            "channel-7"
        );
        assert_eq!(
            map.get("messageType").and_then(|v| v.as_str()).unwrap(),
            "Text"
        );
        assert_eq!(
            map.get("message").and_then(|v| v.as_str()).unwrap(),
            "Hello"
        );

        let mentions = map
            .get("mentions")
            .and_then(|v| v.as_array())
            .expect("mentions should exist");
        assert_eq!(mentions.len(), 2, "duplicate mentions should be removed");
        assert_eq!(
            mentions[0].get("userId").and_then(|v| v.as_str()).unwrap(),
            "user-1"
        );
        assert_eq!(
            mentions[1].get("id").and_then(|v| v.as_str()).unwrap(),
            "member-2"
        );
    }

    #[test]
    fn sanitize_teams_params_handles_delegated_card() {
        let params = json!({
            "deliveryMethod": "Delegated OAuth (Post as user)",
            "messageType": "Card",
            "cardMode": "Simple card builder",
            "cardTitle": "Hello from DSentr",
            "cardBody": "Automation ran",
            "cardJson": "{\"type\":\"AdaptiveCard\"}",
            "message": "legacy"
        });

        let sanitized = sanitize_teams_params(&params);
        let map = sanitized.as_object().expect("delegated card");

        assert_eq!(
            map.get("messageType").and_then(|v| v.as_str()).unwrap(),
            "Card"
        );
        assert_eq!(
            map.get("cardMode").and_then(|v| v.as_str()).unwrap(),
            "Simple card builder"
        );
        assert_eq!(
            map.get("cardTitle").and_then(|v| v.as_str()).unwrap(),
            "Hello from DSentr"
        );
        assert_eq!(
            map.get("cardBody").and_then(|v| v.as_str()).unwrap(),
            "Automation ran"
        );
        assert!(map.get("cardJson").is_some());
        assert!(
            map.get("message").is_some(),
            "legacy messages are preserved"
        );
        assert!(map.get("mentions").is_none());
    }

    #[test]
    fn build_card_payload_wraps_simple_cards_in_graph_message() {
        let input = r#"{
            "type": "AdaptiveCard",
            "version": "1.4",
            "body": [
                { "type": "TextBlock", "text": "Hello" }
            ]
        }"#;

        let payload = build_card_payload(input).expect("card payload");
        assert!(payload.get("subject").is_none());

        let body = payload
            .get("body")
            .and_then(|v| v.as_object())
            .expect("body");
        assert_eq!(body.get("contentType"), Some(&Value::String("html".into())));

        let content_html = body
            .get("content")
            .and_then(|v| v.as_str())
            .expect("html content");
        assert_eq!(content_html, "<attachment id=\"1\"></attachment>");

        let attachments = payload
            .get("attachments")
            .and_then(|v| v.as_array())
            .expect("attachments array");
        assert_eq!(attachments.len(), 1);

        let attachment = attachments[0].as_object().expect("attachment object");
        assert_eq!(attachment.get("id"), Some(&Value::String("1".into())));
        assert_eq!(
            attachment.get("contentType"),
            Some(&Value::String(
                "application/vnd.microsoft.card.adaptive".into()
            ))
        );
        assert_eq!(attachment.get("contentUrl"), Some(&Value::Null));

        let card_json = attachment
            .get("content")
            .and_then(|v| v.as_str())
            .expect("stringified card");
        let parsed: Value = serde_json::from_str(card_json).expect("card JSON should remain valid");
        assert_eq!(parsed["body"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn build_card_payload_normalizes_preformatted_graph_message() {
        let input = r#"{
            "subject": "Ignored",
            "body": {
                "contentType": "html",
                "content": "<attachment id=\"1\"></attachment>"
            },
            "attachments": [
                {
                    "id": "1",
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl": null,
                    "content": {
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            { "type": "TextBlock", "text": "Hello" }
                        ]
                    }
                }
            ]
        }"#;

        let payload = build_card_payload(input).expect("preformatted payload");

        assert!(payload.get("subject").is_none());

        let attachments = payload
            .get("attachments")
            .and_then(|v| v.as_array())
            .expect("attachments array");
        assert_eq!(attachments.len(), 1);

        let attachment = attachments[0].as_object().expect("attachment");
        let content = attachment
            .get("content")
            .and_then(|v| v.as_str())
            .expect("string content");

        let parsed: Value =
            serde_json::from_str(content).expect("attachment content to remain valid JSON");
        assert_eq!(parsed["type"].as_str(), Some("AdaptiveCard"));
    }

    #[tokio::test]
    async fn google_chat_text_message_succeeds() {
        let (addr, mut rx, handle) = spawn_stub_server(|| {
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .unwrap()
        })
        .await;

        let node = Node {
            id: "action-6".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "Google Chat",
                    "webhookUrl": format!("http://{addr}/chat"),
                    "message": "Hello {{ team }}"
                }
            }),
        };

        let context = json!({ "team": "Integrations" });

        let (output, _) = execute_default(&node, &context)
            .await
            .expect("chat call succeeds");

        assert_eq!(output["service"], "Google Chat");
        assert_eq!(output["status"], 200);

        let req = rx.recv().await.expect("request recorded");
        handle.abort();
        assert_eq!(req.method, "POST");
        let content_type = req
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .map(|(_, value)| value.clone())
            .unwrap_or_default();
        assert!(content_type.contains("application/json"));
        let body: Value = serde_json::from_slice(&req.body).expect("json body");
        assert_eq!(body["text"], "Hello Integrations");
    }

    #[tokio::test]
    async fn teams_delegated_text_message_sends_mentions() {
        let (addr, mut rx, handle) = spawn_stub_server(|| {
            Response::builder()
                .status(StatusCode::CREATED)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "id": "message-123",
                        "webUrl": "https://teams.microsoft.com/l/message/123"
                    })
                    .to_string(),
                ))
                .unwrap()
        })
        .await;

        let _guard = EnvGuard::set("MICROSOFT_GRAPH_BASE_URL", format!("http://{}", addr));

        let config = test_config();
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());
        let user_id = Uuid::new_v4();

        let access_token = "delegated-access";
        let refresh_token = "delegated-refresh";
        let encrypted_access = encrypt_secret(&encryption_key, access_token).unwrap();
        let encrypted_refresh = encrypt_secret(&encryption_key, refresh_token).unwrap();

        let token_id = Uuid::new_v4();
        let record = UserOAuthToken {
            id: token_id,
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Microsoft,
            access_token: encrypted_access,
            refresh_token: encrypted_refresh,
            expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
            account_email: "alice@example.com".into(),
            metadata: serde_json::json!({}),
            is_shared: false,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };

        let repo = Arc::new(StaticTokenRepo { record }) as Arc<dyn UserOAuthTokenRepository>;
        let workspace_repo = Arc::new(RecordingWorkspaceConnections::default())
            as Arc<dyn WorkspaceConnectionRepository>;
        let oauth_accounts = Arc::new(OAuthAccountService::new(
            repo,
            workspace_repo.clone(),
            Arc::clone(&encryption_key),
            Arc::new(Client::new()),
            &config.oauth,
        ));

        let mut state = build_state_with_oauth(
            oauth_accounts,
            WorkspaceOAuthService::test_stub(),
            Arc::clone(&config),
            Arc::new(NoopWorkspaceRepository),
        );
        state.workspace_connection_repo = workspace_repo;
        let mut run = test_run();
        run.user_id = user_id;

        let node = Node {
            id: "delegated-text".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "Teams",
                    "deliveryMethod": "Delegated OAuth (Post as user)",
                    "oauthProvider": "microsoft",
                    "oauthConnectionScope": "personal",
                    "oauthConnectionId": token_id.to_string(),
                    "oauthAccountEmail": "alice@example.com",
                    "connection": {
                        "connectionScope": "user",
                        "connectionId": token_id.to_string(),
                        "accountEmail": "alice@example.com"
                    },
                    "teamId": "team-1",
                    "teamName": "Team One",
                    "channelId": "channel-1",
                    "channelName": "General",
                    "messageType": "Text",
                    "message": "Hello team",
                    "mentions": [
                        { "userId": "user-1", "displayName": "Jane" },
                        { "userId": "user-2", "displayName": "John" }
                    ]
                }
            }),
        };

        let (output, _) = execute_messaging(&node, &Value::Null, &state, &run)
            .await
            .expect("delegated message should succeed");

        assert_eq!(output["status"], 201);
        assert_eq!(output["service"], "Teams");
        assert_eq!(output["messageId"], "message-123");
        assert_eq!(output["mentionsAdded"], 2);
        assert_eq!(output["oauthAccountEmail"], "alice@example.com");

        let req = rx.recv().await.expect("graph request recorded");
        handle.abort();

        assert!(req
            .uri
            .ends_with("/teams/team-1/channels/channel-1/messages"));

        let auth_header = req
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .map(|(_, value)| value.clone())
            .expect("authorization header");
        assert_eq!(auth_header, format!("Bearer {}", access_token));

        let body: Value = serde_json::from_slice(&req.body).expect("graph payload");
        assert_eq!(body["body"]["contentType"], "html");
        let content = body["body"]["content"].as_str().expect("html content");
        assert!(content.contains("<at id=\"0\">@Jane</at>"));
        assert!(content.contains("<at id=\"1\">@John</at>"));

        let mentions = body["mentions"].as_array().expect("mentions array");
        assert_eq!(mentions.len(), 2);
        assert_eq!(mentions[0]["mentionText"], "@Jane");
        assert_eq!(mentions[0]["mentioned"]["user"]["id"], "user-1");
    }

    #[tokio::test]
    async fn teams_delegated_personal_accepts_explicit_connection_id() {
        let (addr, _, _) = spawn_stub_server(|| {
            Response::builder()
                .status(StatusCode::CREATED)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "id": "message-actual-id",
                        "webUrl": "https://teams.microsoft.com/l/message/actual"
                    })
                    .to_string(),
                ))
                .unwrap()
        })
        .await;

        let _guard = EnvGuard::set("MICROSOFT_GRAPH_BASE_URL", format!("http://{}", addr));

        let config = test_config();
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());
        let user_id = Uuid::new_v4();

        let access_token = "personal-access-token";
        let refresh_token = "personal-refresh-token";
        let encrypted_access = encrypt_secret(&encryption_key, access_token).unwrap();
        let encrypted_refresh = encrypt_secret(&encryption_key, refresh_token).unwrap();

        let token_id = Uuid::new_v4();
        let record = UserOAuthToken {
            id: token_id,
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Microsoft,
            access_token: encrypted_access,
            refresh_token: encrypted_refresh,
            expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
            account_email: "alice@example.com".into(),
            metadata: serde_json::json!({}),
            is_shared: false,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };

        let repo = Arc::new(StaticTokenRepo { record }) as Arc<dyn UserOAuthTokenRepository>;
        let workspace_repo = Arc::new(RecordingWorkspaceConnections::default())
            as Arc<dyn WorkspaceConnectionRepository>;
        let oauth_accounts = Arc::new(OAuthAccountService::new(
            repo,
            workspace_repo.clone(),
            Arc::clone(&encryption_key),
            Arc::new(Client::new()),
            &config.oauth,
        ));

        let mut state = build_state_with_oauth(
            oauth_accounts,
            WorkspaceOAuthService::test_stub(),
            Arc::clone(&config),
            Arc::new(NoopWorkspaceRepository),
        );
        state.workspace_connection_repo = workspace_repo;
        let mut run = test_run();
        run.user_id = user_id;

        let node = Node {
            id: "delegated-text-connection".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "Teams",
                    "deliveryMethod": "Delegated OAuth (Post as user)",
                    "oauthProvider": "microsoft",
                    "oauthConnectionScope": "personal",
                    "oauthConnectionId": token_id.to_string(),
                    "oauthAccountEmail": "alice@example.com",
                    "connection": {
                        "connectionScope": "user",
                        "connectionId": token_id.to_string(),
                        "accountEmail": "alice@example.com"
                    },
                    "teamId": "team-1",
                    "teamName": "Team One",
                    "channelId": "channel-1",
                    "channelName": "General",
                    "messageType": "Text",
                    "message": "Hello team"
                }
            }),
        };

        let (output, _) = execute_messaging(&node, &Value::Null, &state, &run)
            .await
            .expect("delegated message should succeed with explicit id");

        assert_eq!(output["status"], 201);
        assert_eq!(output["service"], "Teams");
        assert_eq!(output["messageId"], "message-actual-id");
        assert_eq!(output["oauthAccountEmail"], "alice@example.com");
    }

    #[tokio::test]
    async fn google_chat_card_payload_succeeds() {
        let (addr, mut rx, handle) = spawn_stub_server(|| {
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::empty())
                .unwrap()
        })
        .await;

        let node = Node {
            id: "action-7".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "Google Chat",
                    "webhookUrl": format!("http://{addr}/chat"),
                    "cardJson": r#"{
                        "cardsV2": [
                            {
                                "cardId": "updates",
                                "card": {
                                    "sections": [
                                        {
                                            "widgets": [
                                                {
                                                    "textParagraph": {
                                                        "text": "Hello {{ team }}"
                                                    }
                                                }
                                            ]
                                        }
                                    ]
                                }
                            }
                        ]
                    }"#
                }
            }),
        };

        let context = json!({ "team": "Cards" });

        let (output, _) = execute_default(&node, &context)
            .await
            .expect("card call succeeds");

        assert_eq!(output["service"], "Google Chat");
        assert_eq!(output["status"], 200);

        let req = rx.recv().await.expect("request recorded");
        handle.abort();
        assert_eq!(req.method, "POST");
        let content_type = req
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .map(|(_, value)| value.clone())
            .unwrap_or_default();
        assert!(content_type.contains("application/json"));

        let body: Value = serde_json::from_slice(&req.body).expect("json body");
        assert!(body.get("cards").is_none());
        let cards_v2 = body
            .get("cardsV2")
            .and_then(|v| v.as_array())
            .expect("cardsV2 array should exist");
        assert!(!cards_v2.is_empty(), "cardsV2 should not be empty");
        let text = cards_v2[0]
            .get("card")
            .and_then(|card| card.get("sections"))
            .and_then(|sections| sections.as_array())
            .and_then(|sections| sections.first())
            .and_then(|section| section.get("widgets"))
            .and_then(|widgets| widgets.as_array())
            .and_then(|widgets| widgets.first())
            .and_then(|widget| widget.get("textParagraph"))
            .and_then(|paragraph| paragraph.get("text"))
            .and_then(|text| text.as_str())
            .expect("text paragraph should exist");
        assert_eq!(text, "Hello Cards");
    }

    #[tokio::test]
    async fn google_chat_card_payload_requires_valid_json() {
        let node = Node {
            id: "action-8".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "Google Chat",
                    "webhookUrl": "https://example.com/webhook",
                    "cardJson": "{ invalid }"
                }
            }),
        };

        let err = execute_default(&node, &Value::Null)
            .await
            .expect_err("invalid card json should fail");

        assert!(err.starts_with("Invalid card JSON:"));
    }

    #[tokio::test]
    async fn google_chat_card_payload_requires_cards_key() {
        let node = Node {
            id: "action-9".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "Google Chat",
                    "webhookUrl": "https://example.com/webhook",
                    "cardJson": "{\"text\": \"missing cards\"}"
                }
            }),
        };

        let err = execute_default(&node, &Value::Null)
            .await
            .expect_err("missing cards key should fail");

        assert_eq!(err, "Card JSON must include 'cards' or 'cardsV2'");
    }

    #[tokio::test]
    async fn teams_workspace_connection_requires_workspace_context() {
        let node = Node {
            id: "teams-workspace".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "Teams",
                    "deliveryMethod": "Delegated OAuth (Post as user)",
                    "oauthProvider": "microsoft",
                    "connection": {
                        "connectionScope": "workspace",
                        "connectionId": Uuid::new_v4(),
                    },
                    "teamId": "team-1",
                    "channelId": "channel-1",
                    "messageType": "Text",
                    "message": "Hello"
                }
            }),
        };

        let state = test_state(Arc::new(NoopWorkspaceRepository));
        let run = test_run();

        let err = execute_messaging(&node, &Value::Null, &state, &run)
            .await
            .expect_err("workspace connections should require workspace context");

        assert!(err.contains("not associated with a workspace"));
    }

    #[tokio::test]
    async fn teams_workspace_connection_not_found_surfaces_message() {
        let node = Node {
            id: "teams-workspace-not-found".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "Teams",
                    "deliveryMethod": "Delegated OAuth (Post as user)",
                    "oauthProvider": "microsoft",
                    "connection": {
                        "connectionScope": "workspace",
                        "connectionId": Uuid::new_v4(),
                    },
                    "teamId": "team-1",
                    "channelId": "channel-1",
                    "messageType": "Text",
                    "message": "Hello"
                }
            }),
        };

        let state = test_state(Arc::new(NoopWorkspaceRepository));
        let mut run = test_run();
        run.workspace_id = Some(Uuid::new_v4());

        let err = execute_messaging(&node, &Value::Null, &state, &run)
            .await
            .expect_err("missing workspace connection should bubble up error");

        assert!(err.contains("workspace connection not found"));
    }

    #[tokio::test]
    async fn teams_workspace_connection_uses_workspace_token() {
        let (addr, mut rx, handle) = spawn_stub_server(|| {
            Response::builder()
                .status(StatusCode::CREATED)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "id": "workspace-message",
                        "webUrl": "https://teams.microsoft.com/l/message/workspace"
                    })
                    .to_string(),
                ))
                .unwrap()
        })
        .await;

        let _guard = EnvGuard::set("MICROSOFT_GRAPH_BASE_URL", format!("http://{}", addr));

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
            provider: ConnectedOAuthProvider::Microsoft,
            access_token: encrypt_secret(&encryption_key, "workspace-access").unwrap(),
            refresh_token: encrypt_secret(&encryption_key, "workspace-refresh").unwrap(),
            expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
            account_email: "workspace@example.com".into(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            metadata: serde_json::Value::Null,
            bot_user_id: None,
            incoming_webhook_url: None,
            slack_team_id: Some("T123".into()),
        };

        let (workspace_service, repo) =
            workspace_oauth_with_connection(connection, Arc::clone(&encryption_key));

        let oauth_accounts = OAuthAccountService::test_stub();
        let state = build_state_with_oauth(
            oauth_accounts,
            workspace_service,
            Arc::clone(&config),
            Arc::new(NoopWorkspaceRepository),
        );

        let mut run = test_run();
        run.workspace_id = Some(workspace_id);

        let node = Node {
            id: "teams-workspace-success".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "Teams",
                    "deliveryMethod": "Delegated OAuth (Post as user)",
                    "oauthProvider": "microsoft",
                    "connection": {
                        "connectionScope": "workspace",
                        "connectionId": connection_id,
                        "accountEmail": "workspace@example.com"
                    },
                    "teamId": "team-1",
                    "channelId": "channel-1",
                    "messageType": "Text",
                    "message": "Hello workspace"
                }
            }),
        };

        let (output, _) = execute_messaging(&node, &Value::Null, &state, &run)
            .await
            .expect("workspace message succeeds");

        assert_eq!(output["service"], "Teams");
        assert_eq!(output["oauthAccountEmail"], "workspace@example.com");

        let request = rx.recv().await.expect("graph request recorded");
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
    async fn teams_workspace_connection_rejects_when_membership_revoked() {
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
            provider: ConnectedOAuthProvider::Microsoft,
            access_token: encrypt_secret(&encryption_key, "workspace-access").unwrap(),
            refresh_token: encrypt_secret(&encryption_key, "workspace-refresh").unwrap(),
            expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
            account_email: "workspace@example.com".into(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            metadata: serde_json::Value::Null,
            bot_user_id: None,
            incoming_webhook_url: None,
            slack_team_id: Some("T123".into()),
        };

        let (workspace_service, repo) =
            workspace_oauth_with_connection(connection, Arc::clone(&encryption_key));

        let oauth_accounts = OAuthAccountService::test_stub();
        let workspace_repo: Arc<dyn WorkspaceRepository> =
            Arc::new(StaticWorkspaceMembershipRepository::denying());
        let state = build_state_with_oauth(
            oauth_accounts,
            workspace_service,
            Arc::clone(&config),
            workspace_repo,
        );

        let mut run = test_run();
        run.workspace_id = Some(workspace_id);

        let node = Node {
            id: "teams-workspace-forbidden".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "Teams",
                    "deliveryMethod": "Delegated OAuth (Post as user)",
                    "oauthProvider": "microsoft",
                    "connection": {
                        "connectionScope": "workspace",
                        "connectionId": connection_id,
                        "accountEmail": "workspace@example.com"
                    },
                    "teamId": "team-1",
                    "channelId": "channel-1",
                    "messageType": "Text",
                    "message": "Hello"
                }
            }),
        };

        let err = execute_messaging(&node, &Value::Null, &state, &run)
            .await
            .expect_err("revoked members should not use workspace Teams tokens");

        assert!(err.contains("Forbidden"));
        assert!(
            repo.find_calls().is_empty(),
            "workspace OAuth lookup should be skipped when membership check fails"
        );
    }

    #[tokio::test]
    async fn teams_workspace_connection_workspace_mismatch_surfaces_message() {
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
            provider: ConnectedOAuthProvider::Microsoft,
            access_token: encrypt_secret(&encryption_key, "workspace-access").unwrap(),
            refresh_token: encrypt_secret(&encryption_key, "workspace-refresh").unwrap(),
            expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
            account_email: "workspace@example.com".into(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            metadata: serde_json::Value::Null,
            bot_user_id: None,
            incoming_webhook_url: None,
            slack_team_id: Some("T123".into()),
        };

        let (workspace_service, repo) =
            workspace_oauth_with_connection(connection, Arc::clone(&encryption_key));

        let oauth_accounts = OAuthAccountService::test_stub();
        let state = build_state_with_oauth(
            oauth_accounts,
            workspace_service,
            Arc::clone(&config),
            Arc::new(NoopWorkspaceRepository),
        );

        let mut run = test_run();
        run.workspace_id = Some(workspace_id);

        let node = Node {
            id: "teams-workspace-mismatch".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "Teams",
                    "deliveryMethod": "Delegated OAuth (Post as user)",
                    "oauthProvider": "microsoft",
                    "connection": {
                        "connectionScope": "workspace",
                        "connectionId": connection_id,
                        "accountEmail": "workspace@example.com"
                    },
                    "teamId": "team-1",
                    "channelId": "channel-1",
                    "messageType": "Text",
                    "message": "Hello"
                }
            }),
        };

        let err = execute_messaging(&node, &Value::Null, &state, &run)
            .await
            .expect_err("workspace mismatch should fail");

        assert!(err.contains("does not belong to this workspace"));
        let calls = repo.find_calls();
        assert_eq!(calls, vec![connection_id]);
    }

    #[tokio::test]
    async fn slack_rejects_on_solo_plan() {
        use serde_json::json;

        let node = Node {
            id: "n1".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "slack",
                    "channel": "C123",
                    "message": "hi"
                }
            }),
        };

        let run = test_run();
        let state = test_state(Arc::new(NoopWorkspaceRepository));

        let result = execute_messaging(&node, &json!({}), &state, &run).await;

        // Slack should fail, but NOT via the premium message
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn teams_rejects_on_solo_plan() {
        use serde_json::json;

        let node = Node {
            id: "n2".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "teams",
                    "teamId": "x",
                    "channelId": "y",
                    "deliveryMethod": "Incoming Webhook",
                    "webhookUrl": "https://example.com/hook"
                }
            }),
        };

        let run = test_run();
        let state = test_state(Arc::new(NoopWorkspaceRepository));

        let result = execute_messaging(&node, &json!({}), &state, &run).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn google_chat_allowed_on_solo_plan() {
        use serde_json::json;

        let node = Node {
            id: "n3".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "googlechat",
                    "webhookUrl": "https://example.com/hook",
                    "message": "ok"
                }
            }),
        };

        let run = test_run();
        let state = test_state(Arc::new(NoopWorkspaceRepository));

        let result = execute_messaging(&node, &json!({}), &state, &run).await;

        // Allowed to attempt, but send_google_chat will fail without a stub
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn slack_workspace_webhook_only_connection_is_rejected() {
        let config = test_config();
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());

        let workspace_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let token_id = Uuid::new_v4();

        let connection = WorkspaceConnection {
            id: connection_id,
            connection_id: Some(token_id),
            workspace_id,
            created_by: user_id,
            owner_user_id: user_id,
            user_oauth_token_id: None, // webhook-only
            provider: ConnectedOAuthProvider::Slack,
            access_token: encrypt_secret(&encryption_key, "").unwrap(),
            refresh_token: encrypt_secret(&encryption_key, "").unwrap(),
            expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
            account_email: "workspace@example.com".into(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            metadata: serde_json::Value::Null,
            bot_user_id: None,
            slack_team_id: Some("T123".into()),
            incoming_webhook_url: Some(
                encrypt_secret(&encryption_key, "http://example.com/webhook").unwrap(),
            ),
        };

        let (workspace_service, repo) =
            workspace_oauth_with_connection(connection, Arc::clone(&encryption_key));

        let state = build_state_with_oauth(
            OAuthAccountService::test_stub(),
            workspace_service,
            Arc::clone(&config),
            Arc::new(NoopWorkspaceRepository),
        );

        let mut run = test_run();
        run.workspace_id = Some(workspace_id);
        run.user_id = user_id;

        let node = Node {
            id: "slack-webhook".into(),
            kind: "action".into(),
            data: json!({
                "params": {
                    "platform": "Slack",
                    "deliveryMethod": "Incoming Webhook",
                    "channel": "#alerts",
                    "message": "hello webhook",
                    "identity": "workspace_bot",
                    "connection": {
                        "connectionScope": "workspace",
                        "connectionId": connection_id.to_string(),
                        "accountEmail": "workspace@example.com"
                    }
                }
            }),
        };

        let err = execute_messaging(&node, &json!({}), &state, &run)
            .await
            .expect_err("webhook-only workspace connection must be rejected");

        assert!(err.contains("workspace_bot error"));
        assert!(err.contains("webhook-only"));

        assert_eq!(repo.find_calls(), vec![connection_id]);
    }
}
