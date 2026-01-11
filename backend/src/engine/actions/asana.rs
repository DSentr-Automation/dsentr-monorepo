use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::engine::actions::registry::{
    ActionExecutionSemantics, ActionManifest, ActionValidator,
};
use crate::engine::actions::validate_required_fields;
use crate::engine::graph::Node;
use crate::engine::templating::templ_str;
use crate::models::oauth_token::ConnectedOAuthProvider;
use crate::models::workflow_run::WorkflowRun;
use crate::services::oauth::account_service::OAuthAccountError;
use crate::services::oauth::workspace_service::WorkspaceOAuthError;
use crate::state::AppState;

use super::{ensure_run_membership, ensure_workspace_plan};

const ASANA_BASE_URL: &str = "https://app.asana.com/api/1.0";

pub(crate) const MANIFEST: ActionManifest = ActionManifest {
    action_type: "asana",
    required_fields: &["params"],
    execution_semantics: ActionExecutionSemantics::Standard,
};

pub(crate) struct AsanaValidator;

impl ActionValidator for AsanaValidator {
    fn validate(&self, node: &Node) -> Result<(), String> {
        validate_required_fields(node, MANIFEST.required_fields)
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
    raw.parse::<u32>().ok()
}

fn parse_additional_fields(params: &Value, context: &Value) -> Map<String, Value> {
    let mut map = Map::new();
    if let Some(entries) = params.get("additionalFields").and_then(|v| v.as_array()) {
        for entry in entries {
            if let Some(key) = entry
                .get("key")
                .and_then(|v| v.as_str())
                .map(|s| templ_str(s, context).trim().to_string())
            {
                if key.is_empty() {
                    continue;
                }
                let raw_value = entry.get("value").and_then(|v| v.as_str()).unwrap_or("");
                let templated = templ_str(raw_value, context);
                let parsed =
                    serde_json::from_str::<Value>(&templated).unwrap_or(Value::String(templated));
                map.insert(key, parsed);
            }
        }
    }
    map
}

async fn handle_response(response: reqwest::Response) -> Result<Value, String> {
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|err| format!("Failed to read Asana response body: {err}"))?;

    if !status.is_success() {
        return Err(format!(
            "Asana request failed with status {}: {}",
            status, body
        ));
    }

    serde_json::from_str(&body)
        .map_err(|err| format!("Failed to parse Asana response: {err}. Body: {body}"))
}

fn map_oauth_error(err: OAuthAccountError) -> String {
    match err {
        OAuthAccountError::NotFound => "No Asana OAuth connection found".to_string(),
        OAuthAccountError::TokenRevoked { .. } => {
            "The Asana connection was revoked. Reconnect in Settings -> Integrations.".to_string()
        }
        other => format!("Asana OAuth error: {other}"),
    }
}

fn map_workspace_oauth_error(err: WorkspaceOAuthError) -> String {
    match err {
        WorkspaceOAuthError::Forbidden => {
            "You no longer have access to this workspace connection.".to_string()
        }
        WorkspaceOAuthError::NotFound => "Asana workspace connection not found.".to_string(),
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

pub(crate) async fn execute_asana(
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

    let connection_usage = super::resolve_connection_usage(&params)?;

    let access_token = match connection_usage {
        super::NodeConnectionUsage::Workspace(info) => {
            let workspace_id = run.workspace_id.ok_or_else(|| {
                "This workflow is not associated with a workspace. Promote the Asana connection to the workspace or switch to a personal connection.".to_string()
            })?;

            ensure_run_membership(state, workspace_id, run.user_id).await?;
            ensure_workspace_plan(state, workspace_id).await?;

            let connection = state
                .workspace_oauth
                .ensure_valid_workspace_token(info.connection_id)
                .await
                .map_err(map_workspace_oauth_error)?;

            if connection.workspace_id != workspace_id {
                return Err(
                    "The selected Asana connection belongs to another workspace".to_string()
                );
            }
            if connection.provider != ConnectedOAuthProvider::Asana {
                return Err("Selected connection is not an Asana connection".to_string());
            }

            connection.access_token.clone()
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

            token.access_token.clone()
        }
    };

    match operation.as_str() {
        "createproject" => {
            let workspace_gid = read_required(&params, "workspaceGid", "Workspace GID", context)?;
            let name = read_required(&params, "name", "Name", context)?;
            let notes = read_optional(&params, "notes", context);
            let team_gid = read_optional(&params, "teamGid", context);
            let archived = params.get("archived").and_then(|v| v.as_bool());
            let mut payload = Map::new();
            payload.insert("workspace".to_string(), Value::String(workspace_gid));
            payload.insert("name".to_string(), Value::String(name));
            if let Some(notes) = notes {
                payload.insert("notes".to_string(), Value::String(notes));
            }
            if let Some(team) = team_gid {
                payload.insert("team".to_string(), Value::String(team));
            }
            if let Some(flag) = archived {
                payload.insert("archived".to_string(), Value::Bool(flag));
            }
            payload.extend(parse_additional_fields(&params, context));
            let response = state
                .http_client
                .post(format!("{ASANA_BASE_URL}/projects"))
                .bearer_auth(&access_token)
                .json(&json!({ "data": payload }))
                .send()
                .await
                .map_err(|err| format!("Failed to call Asana: {err}"))?;
            let body = handle_response(response).await?;
            Ok((body, None))
        }
        "deleteproject" => {
            let project_gid = read_required(&params, "projectGid", "Project GID", context)?;
            let response = state
                .http_client
                .delete(format!("{ASANA_BASE_URL}/projects/{project_gid}"))
                .bearer_auth(&access_token)
                .send()
                .await
                .map_err(|err| format!("Failed to call Asana: {err}"))?;
            let body = handle_response(response).await?;
            Ok((body, None))
        }
        "getproject" => {
            let project_gid = read_required(&params, "projectGid", "Project GID", context)?;
            let response = state
                .http_client
                .get(format!("{ASANA_BASE_URL}/projects/{project_gid}"))
                .bearer_auth(&access_token)
                .send()
                .await
                .map_err(|err| format!("Failed to call Asana: {err}"))?;
            let body = handle_response(response).await?;
            Ok((body, None))
        }
        "listprojects" => {
            let workspace_gid = read_required(&params, "workspaceGid", "Workspace GID", context)?;
            let team_gid = read_optional(&params, "teamGid", context);
            let limit = read_limit(&params, context);
            let mut query = vec![("workspace".to_string(), workspace_gid)];
            if let Some(team) = team_gid {
                query.push(("team".to_string(), team));
            }
            if let Some(limit) = limit {
                query.push(("limit".to_string(), limit.to_string()));
            }
            let response = state
                .http_client
                .get(format!("{ASANA_BASE_URL}/projects"))
                .bearer_auth(&access_token)
                .query(&query)
                .send()
                .await
                .map_err(|err| format!("Failed to call Asana: {err}"))?;
            let body = handle_response(response).await?;
            Ok((body, None))
        }
        "updateproject" => {
            let project_gid = read_required(&params, "projectGid", "Project GID", context)?;
            let mut payload = parse_additional_fields(&params, context);
            if let Some(name) = read_optional(&params, "name", context) {
                payload.insert("name".to_string(), Value::String(name));
            }
            if let Some(notes) = read_optional(&params, "notes", context) {
                payload.insert("notes".to_string(), Value::String(notes));
            }
            if let Some(archived) = params.get("archived").and_then(|v| v.as_bool()) {
                payload.insert("archived".to_string(), Value::Bool(archived));
            }
            if payload.is_empty() {
                return Err("Provide at least one field to update the project".to_string());
            }
            let response = state
                .http_client
                .put(format!("{ASANA_BASE_URL}/projects/{project_gid}"))
                .bearer_auth(&access_token)
                .json(&json!({ "data": payload }))
                .send()
                .await
                .map_err(|err| format!("Failed to call Asana: {err}"))?;
            let body = handle_response(response).await?;
            Ok((body, None))
        }
        "createsubtask" => {
            let parent = read_required(&params, "parentTaskGid", "Parent task GID", context)?;
            let name = read_required(&params, "name", "Name", context)?;
            let mut payload = parse_additional_fields(&params, context);
            payload.insert("name".to_string(), Value::String(name));
            if let Some(notes) = read_optional(&params, "notes", context) {
                payload.insert("notes".to_string(), Value::String(notes));
            }
            if let Some(assignee) = read_optional(&params, "assignee", context) {
                payload.insert("assignee".to_string(), Value::String(assignee));
            }
            if let Some(due_on) = read_optional(&params, "dueOn", context) {
                payload.insert("due_on".to_string(), Value::String(due_on));
            }
            if let Some(due_at) = read_optional(&params, "dueAt", context) {
                payload.insert("due_at".to_string(), Value::String(due_at));
            }

            let response = state
                .http_client
                .post(format!("{ASANA_BASE_URL}/tasks/{parent}/subtasks"))
                .bearer_auth(&access_token)
                .json(&json!({ "data": payload }))
                .send()
                .await
                .map_err(|err| format!("Failed to call Asana: {err}"))?;
            let body = handle_response(response).await?;
            Ok((body, None))
        }
        "listsubtasks" => {
            let parent = read_required(&params, "parentTaskGid", "Parent task GID", context)?;
            let mut query: Vec<(String, String)> = Vec::new();
            if let Some(limit) = read_limit(&params, context) {
                query.push(("limit".to_string(), limit.to_string()));
            }
            let response = state
                .http_client
                .get(format!("{ASANA_BASE_URL}/tasks/{parent}/subtasks"))
                .bearer_auth(&access_token)
                .query(&query)
                .send()
                .await
                .map_err(|err| format!("Failed to call Asana: {err}"))?;
            let body = handle_response(response).await?;
            Ok((body, None))
        }
        "createtask" => {
            let workspace_gid = read_required(&params, "workspaceGid", "Workspace GID", context)?;
            let name = read_required(&params, "name", "Name", context)?;
            let mut payload = parse_additional_fields(&params, context);
            payload.insert("workspace".to_string(), Value::String(workspace_gid));
            payload.insert("name".to_string(), Value::String(name));
            if let Some(project) = read_optional(&params, "projectGid", context) {
                payload.insert(
                    "projects".to_string(),
                    Value::Array(vec![Value::String(project)]),
                );
            }
            if let Some(notes) = read_optional(&params, "notes", context) {
                payload.insert("notes".to_string(), Value::String(notes));
            }
            if let Some(assignee) = read_optional(&params, "assignee", context) {
                payload.insert("assignee".to_string(), Value::String(assignee));
            }
            if let Some(due_on) = read_optional(&params, "dueOn", context) {
                payload.insert("due_on".to_string(), Value::String(due_on));
            }
            if let Some(due_at) = read_optional(&params, "dueAt", context) {
                payload.insert("due_at".to_string(), Value::String(due_at));
            }
            let response = state
                .http_client
                .post(format!("{ASANA_BASE_URL}/tasks"))
                .bearer_auth(&access_token)
                .json(&json!({ "data": payload }))
                .send()
                .await
                .map_err(|err| format!("Failed to call Asana: {err}"))?;
            let body = handle_response(response).await?;
            Ok((body, None))
        }
        "deletetask" => {
            let task_gid = read_required(&params, "taskGid", "Task GID", context)?;
            let response = state
                .http_client
                .delete(format!("{ASANA_BASE_URL}/tasks/{task_gid}"))
                .bearer_auth(&access_token)
                .send()
                .await
                .map_err(|err| format!("Failed to call Asana: {err}"))?;
            let body = handle_response(response).await?;
            Ok((body, None))
        }
        "gettask" => {
            let task_gid = read_required(&params, "taskGid", "Task GID", context)?;
            let response = state
                .http_client
                .get(format!("{ASANA_BASE_URL}/tasks/{task_gid}"))
                .bearer_auth(&access_token)
                .send()
                .await
                .map_err(|err| format!("Failed to call Asana: {err}"))?;
            let body = handle_response(response).await?;
            Ok((body, None))
        }
        "listtasks" => {
            let workspace_gid = read_required(&params, "workspaceGid", "Workspace GID", context)?;
            let project = read_optional(&params, "projectGid", context);
            let tag = read_optional(&params, "tagGid", context);
            let assignee = read_optional(&params, "assignee", context);

            let mut query: Vec<(String, String)> = Vec::new();

            // Asana requires either project/tag OR assignee+workspace. Workspace alone is invalid.
            if let Some(project) = project {
                query.push(("project".to_string(), project));
            } else if let Some(tag) = tag {
                query.push(("tag".to_string(), tag));
            } else if let Some(assignee) = assignee {
                query.push(("workspace".to_string(), workspace_gid));
                query.push(("assignee".to_string(), assignee));
            } else {
                return Err(
                    "Asana list tasks requires a project or tag, or an assignee with workspace"
                        .to_string(),
                );
            }

            if let Some(limit) = read_limit(&params, context) {
                query.push(("limit".to_string(), limit.to_string()));
            }
            let response = state
                .http_client
                .get(format!("{ASANA_BASE_URL}/tasks"))
                .bearer_auth(&access_token)
                .query(&query)
                .send()
                .await
                .map_err(|err| format!("Failed to call Asana: {err}"))?;
            let body = handle_response(response).await?;
            Ok((body, None))
        }
        "movetask" => {
            let task_gid = read_required(&params, "taskGid", "Task GID", context)?;
            let section_gid = read_required(&params, "sectionGid", "Section GID", context)?;
            let response = state
                .http_client
                .post(format!("{ASANA_BASE_URL}/sections/{section_gid}/addTask"))
                .bearer_auth(&access_token)
                .json(&json!({ "data": { "task": task_gid } }))
                .send()
                .await
                .map_err(|err| format!("Failed to call Asana: {err}"))?;
            let body = handle_response(response).await?;
            Ok((body, None))
        }
        "searchtasks" => {
            let workspace_gid = read_required(&params, "workspaceGid", "Workspace GID", context)?;
            let query_text = read_required(&params, "query", "Search text", context)?;
            let mut query: Vec<(String, String)> = vec![("text".to_string(), query_text)];
            if let Some(project) = read_optional(&params, "projectGid", context) {
                query.push(("project".to_string(), project));
            }
            if let Some(tag) = read_optional(&params, "tagGid", context) {
                query.push(("tag".to_string(), tag));
            }
            if let Some(assignee) = read_optional(&params, "assignee", context) {
                query.push(("assignee.any".to_string(), assignee));
            }
            if let Some(completed) = params.get("completed").and_then(|v| v.as_bool()) {
                query.push(("completed".to_string(), completed.to_string()));
            }
            if let Some(limit) = read_limit(&params, context) {
                query.push(("limit".to_string(), limit.to_string()));
            }
            let response = state
                .http_client
                .get(format!(
                    "{ASANA_BASE_URL}/workspaces/{workspace_gid}/tasks/search"
                ))
                .bearer_auth(&access_token)
                .query(&query)
                .send()
                .await
                .map_err(|err| format!("Failed to call Asana: {err}"))?;
            let body = handle_response(response).await?;
            Ok((body, None))
        }
        "updatetask" => {
            let task_gid = read_required(&params, "taskGid", "Task GID", context)?;
            let mut payload = parse_additional_fields(&params, context);
            if let Some(name) = read_optional(&params, "name", context) {
                payload.insert("name".to_string(), Value::String(name));
            }
            if let Some(notes) = read_optional(&params, "notes", context) {
                payload.insert("notes".to_string(), Value::String(notes));
            }
            if let Some(assignee) = read_optional(&params, "assignee", context) {
                payload.insert("assignee".to_string(), Value::String(assignee));
            }
            if let Some(due_on) = read_optional(&params, "dueOn", context) {
                payload.insert("due_on".to_string(), Value::String(due_on));
            }
            if let Some(due_at) = read_optional(&params, "dueAt", context) {
                payload.insert("due_at".to_string(), Value::String(due_at));
            }
            if let Some(completed) = params.get("completed").and_then(|v| v.as_bool()) {
                payload.insert("completed".to_string(), Value::Bool(completed));
            }
            if payload.is_empty() {
                return Err("Provide at least one field to update the task".to_string());
            }
            let response = state
                .http_client
                .put(format!("{ASANA_BASE_URL}/tasks/{task_gid}"))
                .bearer_auth(&access_token)
                .json(&json!({ "data": payload }))
                .send()
                .await
                .map_err(|err| format!("Failed to call Asana: {err}"))?;
            let body = handle_response(response).await?;
            Ok((body, None))
        }
        "addcomment" => {
            let task_gid = read_required(&params, "taskGid", "Task GID", context)?;
            let text = read_required(&params, "notes", "Comment text", context)?;
            let response = state
                .http_client
                .post(format!("{ASANA_BASE_URL}/tasks/{task_gid}/stories"))
                .bearer_auth(&access_token)
                .json(&json!({ "data": { "text": text } }))
                .send()
                .await
                .map_err(|err| format!("Failed to call Asana: {err}"))?;
            let body = handle_response(response).await?;
            Ok((body, None))
        }
        "removecomment" => {
            let story_gid = read_required(&params, "storyGid", "Story GID", context)?;
            let response = state
                .http_client
                .delete(format!("{ASANA_BASE_URL}/stories/{story_gid}"))
                .bearer_auth(&access_token)
                .send()
                .await
                .map_err(|err| format!("Failed to call Asana: {err}"))?;
            let body = handle_response(response).await?;
            Ok((body, None))
        }
        "addtaskproject" => {
            let task_gid = read_required(&params, "taskGid", "Task GID", context)?;
            let project_gid = read_required(&params, "projectGid", "Project GID", context)?;
            let mut payload = Map::new();
            payload.insert("project".to_string(), Value::String(project_gid));
            let response = state
                .http_client
                .post(format!("{ASANA_BASE_URL}/tasks/{task_gid}/addProject"))
                .bearer_auth(&access_token)
                .json(&json!({ "data": payload }))
                .send()
                .await
                .map_err(|err| format!("Failed to call Asana: {err}"))?;
            let body = handle_response(response).await?;
            Ok((body, None))
        }
        "removetaskproject" => {
            let task_gid = read_required(&params, "taskGid", "Task GID", context)?;
            let project_gid = read_required(&params, "projectGid", "Project GID", context)?;
            let response = state
                .http_client
                .post(format!("{ASANA_BASE_URL}/tasks/{task_gid}/removeProject"))
                .bearer_auth(&access_token)
                .json(&json!({ "data": { "project": project_gid } }))
                .send()
                .await
                .map_err(|err| format!("Failed to call Asana: {err}"))?;
            let body = handle_response(response).await?;
            Ok((body, None))
        }
        "addtasktag" => {
            let task_gid = read_required(&params, "taskGid", "Task GID", context)?;
            let tag_gid = read_required(&params, "tagGid", "Tag GID", context)?;
            let response = state
                .http_client
                .post(format!("{ASANA_BASE_URL}/tasks/{task_gid}/addTag"))
                .bearer_auth(&access_token)
                .json(&json!({ "data": { "tag": tag_gid } }))
                .send()
                .await
                .map_err(|err| format!("Failed to call Asana: {err}"))?;
            let body = handle_response(response).await?;
            Ok((body, None))
        }
        "removetasktag" => {
            let task_gid = read_required(&params, "taskGid", "Task GID", context)?;
            let tag_gid = read_required(&params, "tagGid", "Tag GID", context)?;
            let response = state
                .http_client
                .post(format!("{ASANA_BASE_URL}/tasks/{task_gid}/removeTag"))
                .bearer_auth(&access_token)
                .json(&json!({ "data": { "tag": tag_gid } }))
                .send()
                .await
                .map_err(|err| format!("Failed to call Asana: {err}"))?;
            let body = handle_response(response).await?;
            Ok((body, None))
        }
        "getuser" => {
            let user_gid = read_required(&params, "userGid", "User GID", context)?;
            let response = state
                .http_client
                .get(format!("{ASANA_BASE_URL}/users/{user_gid}"))
                .bearer_auth(&access_token)
                .send()
                .await
                .map_err(|err| format!("Failed to call Asana: {err}"))?;
            let body = handle_response(response).await?;
            Ok((body, None))
        }
        "listusers" => {
            let workspace_gid = read_required(&params, "workspaceGid", "Workspace GID", context)?;
            let mut query: Vec<(String, String)> = vec![("workspace".to_string(), workspace_gid)];
            if let Some(team) = read_optional(&params, "teamGid", context) {
                query.push(("team".to_string(), team));
            }
            if let Some(limit) = read_limit(&params, context) {
                query.push(("limit".to_string(), limit.to_string()));
            }
            let response = state
                .http_client
                .get(format!("{ASANA_BASE_URL}/users"))
                .bearer_auth(&access_token)
                .query(&query)
                .send()
                .await
                .map_err(|err| format!("Failed to call Asana: {err}"))?;
            let body = handle_response(response).await?;
            Ok((body, None))
        }
        other => Ok((
            json!({
                "skipped": true,
                "reason": format!("Unsupported Asana operation `{}`", other)
            }),
            None,
        )),
    }
}
