use std::collections::{BTreeMap, BTreeSet, HashMap};

use chrono::Duration as ChronoDuration;

use super::prelude::*;
use crate::models::workflow_schedule::WorkflowSchedule;

pub(crate) fn is_unique_violation(err: &sqlx::Error) -> bool {
    if let sqlx::Error::Database(db_err) = err {
        if let Some(code) = db_err.code() {
            return code == "23505";
        }
    }
    false
}

fn flatten_user_data(prefix: &str, value: &Value, out: &mut Vec<(String, Value)>) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for key in keys {
                let node_value = &map[key];
                let path = if prefix.is_empty() {
                    key.to_string()
                } else {
                    format!("{prefix}.{key}")
                };
                flatten_user_data(&path, node_value, out);
            }
        }
        Value::Array(arr) => {
            for (idx, node_value) in arr.iter().enumerate() {
                let path = format!("{prefix}[{idx}]");
                flatten_user_data(&path, node_value, out);
            }
        }
        _ => out.push((prefix.to_string(), value.clone())),
    }
}

pub(crate) fn diff_user_nodes_only(before: &Value, after: &Value) -> Value {
    let mut before_flat: Vec<(String, Value)> = Vec::new();
    let mut after_flat: Vec<(String, Value)> = Vec::new();

    let collect = |root: &Value, bucket: &mut Vec<(String, Value)>| {
        if let Some(nodes) = root.get("nodes").and_then(|value| value.as_array()) {
            for (idx, node) in nodes.iter().enumerate() {
                if let Some(data) = node.get("data") {
                    flatten_user_data(&format!("nodes[{idx}].data"), data, bucket);
                }
            }
        }
    };

    collect(before, &mut before_flat);
    collect(after, &mut after_flat);

    let mut before_map = BTreeMap::new();
    for (key, value) in before_flat {
        before_map.insert(key, value);
    }
    let mut after_map = BTreeMap::new();
    for (key, value) in after_flat {
        after_map.insert(key, value);
    }

    let mut differences = vec![];
    let keys: BTreeSet<_> = before_map.keys().chain(after_map.keys()).cloned().collect();
    for key in keys {
        let before_value = before_map.get(&key);
        let after_value = after_map.get(&key);
        if before_value != after_value {
            differences.push(json!({
                "path": key,
                "from": before_value.cloned().unwrap_or(Value::Null),
                "to": after_value.cloned().unwrap_or(Value::Null),
            }));
        }
    }

    Value::Array(differences)
}

pub(crate) fn extract_schedule_config(graph: &Value) -> Option<Value> {
    let nodes = graph.get("nodes")?.as_array()?;
    for node in nodes {
        if node.get("type")?.as_str()? != "trigger" {
            continue;
        }
        let data = node.get("data")?;
        let trigger_type = data
            .get("triggerType")
            .and_then(|value| value.as_str())
            .unwrap_or("Manual");
        if !trigger_type.eq_ignore_ascii_case("schedule") {
            if is_notion_trigger_type(trigger_type) {
                return build_notion_trigger_config(data, trigger_type);
            }
            continue;
        }
        if let Some(cfg) = data.get("scheduleConfig") {
            return Some(cfg.clone());
        }
    }
    None
}

#[allow(dead_code)]
const GITHUB_TRIGGER_PREFIX: &str = "github.";
#[allow(dead_code)]
const GITHUB_TRIGGER_EVENT_KEY: &str = "events";
// Legacy aliases are retained for backward compatibility only.
// New frontend code must use the canonical "events" key.
#[allow(dead_code)]
const GITHUB_TRIGGER_EVENT_KEY_ALIASES: [&str; 5] = [
    "eventTypes",
    "event_types",
    "eventType",
    "event_type",
    "actions",
];
#[allow(dead_code)]
const GITHUB_TRIGGER_ALLOWED_EVENTS: [&str; 5] = [
    "issues",
    "pull_request",
    "push",
    "release",
    "workflow_run",
];

// GitHub trigger config schema (workflow.data.nodes[].data):
// - installation_id / installationId: required numeric identifier for the GitHub App installation
// - repository_id / repositoryId: optional numeric identifier for repo-scoped triggers
// - events: optional list of action strings (canonical key)

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitHubTriggerMapping {
    pub trigger_node_id: String,
    pub event_types: Vec<String>,
    pub installation_id: String,
    pub repository_id: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitHubTriggerMappingError {
    pub trigger_node_id: Option<String>,
    pub code: &'static str,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GitHubTriggerMappingOutcome {
    pub mappings: Vec<GitHubTriggerMapping>,
    pub errors: Vec<GitHubTriggerMappingError>,
}

// Provider trigger activation boundary: only workflows that are explicitly active should register
// provider triggers. Draft/paused/disabled workflows must not activate. Absence of an explicit
// status flag is treated as active to preserve existing workflow behavior.
#[allow(dead_code)]
pub(crate) fn workflow_is_active(graph: &Value) -> bool {
    let draft_flag = graph
        .get("draft")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
        || graph
            .get("isDraft")
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
    if draft_flag {
        return false;
    }

    if graph
        .get("paused")
        .and_then(|value| value.as_bool())
        .unwrap_or(false)
    {
        return false;
    }

    if graph
        .get("enabled")
        .and_then(|value| value.as_bool())
        .map(|value| !value)
        .unwrap_or(false)
    {
        return false;
    }

    if let Some(status) = graph.get("status").and_then(|value| value.as_str()) {
        let normalized = status.trim().to_ascii_lowercase();
        if matches!(normalized.as_str(), "draft" | "disabled" | "paused") {
            return false;
        }
        if matches!(normalized.as_str(), "published" | "active" | "enabled") {
            return true;
        }
    }

    true
}

#[allow(dead_code)]
pub(crate) fn is_supported_github_event_type(event_type: &str) -> bool {
    let trimmed = event_type.trim().to_ascii_lowercase();
    let Some(suffix) = trimmed.strip_prefix(GITHUB_TRIGGER_PREFIX) else {
        return false;
    };
    let event = suffix.split('.').next().unwrap_or("").trim();
    !event.is_empty() && GITHUB_TRIGGER_ALLOWED_EVENTS.contains(&event)
}

// GitHub trigger nodes must use triggerType values in the canonical frontend format
// `github.<event>` (lowercase). Supported events: issues, pull_request, push, release, workflow_run.
// TriggerType does not accept `github.<event>.<action>`; actions are selected via data.events.
// Canonical event selection key is data.events; legacy aliases are read for backward compatibility.
// Provider event_type strings are derived as:
// - `github.<event>` when no action filters are selected
// - `github.<event>.<action>` for each selected action (e.g., github.issues.opened)
// Callers must treat missing installation_id, invalid triggerType, or invalid event selections
// as activation errors; this helper returns errors for those cases.
#[allow(dead_code)]
pub(crate) fn collect_github_trigger_mappings(graph: &Value) -> GitHubTriggerMappingOutcome {
    let mut mappings = Vec::new();
    let mut errors = Vec::new();
    let Some(nodes) = graph.get("nodes").and_then(|value| value.as_array()) else {
        return GitHubTriggerMappingOutcome { mappings, errors };
    };

    for node in nodes {
        let Some(node_type) = node.get("type").and_then(|value| value.as_str()) else {
            continue;
        };
        if !node_type.eq_ignore_ascii_case("trigger") {
            continue;
        }
        let Some(data) = node.get("data").and_then(|value| value.as_object()) else {
            continue;
        };
        let Some(trigger_type) = normalize_trigger_type(data.get("triggerType")) else {
            continue;
        };
        if !trigger_type.starts_with(GITHUB_TRIGGER_PREFIX) {
            continue;
        }

        let trigger_node_id = read_string(node.get("id"));
        if trigger_node_id.is_none() {
            errors.push(GitHubTriggerMappingError {
                trigger_node_id: None,
                code: "missing_trigger_node_id",
            });
            continue;
        }
        let trigger_node_id = trigger_node_id.unwrap();

        let Some(event_namespace) = parse_github_trigger_event(&trigger_type) else {
            errors.push(GitHubTriggerMappingError {
                trigger_node_id: Some(trigger_node_id),
                code: "invalid_trigger_type",
            });
            continue;
        };

        let installation_id = match validate_github_installation_id(
            data.get("installationId")
                .or_else(|| data.get("installation_id")),
            &trigger_node_id,
        ) {
            Ok(value) => value,
            Err(err) => {
                errors.push(err);
                continue;
            }
        };
        let repository_id = match validate_github_repository_id(
            data.get("repositoryId")
                .or_else(|| data.get("repository_id")),
            &trigger_node_id,
        ) {
            Ok(value) => value,
            Err(err) => {
                errors.push(err);
                continue;
            }
        };

        let base_event_type = format!("{GITHUB_TRIGGER_PREFIX}{event_namespace}");
        let selections = read_github_event_selections(data);
        let event_types = match build_github_event_types(
            &base_event_type,
            event_namespace.as_str(),
            selections.as_slice(),
        ) {
            Ok(types) => types,
            Err(code) => {
                errors.push(GitHubTriggerMappingError {
                    trigger_node_id: Some(trigger_node_id),
                    code,
                });
                continue;
            }
        };

        mappings.push(GitHubTriggerMapping {
            trigger_node_id,
            event_types,
            installation_id,
            repository_id,
        });
    }

    GitHubTriggerMappingOutcome { mappings, errors }
}

pub(crate) async fn sync_workflow_schedule(state: &AppState, workflow: &Workflow) {
    if let Err(error) = sync_workflow_schedule_inner(state, workflow).await {
        eprintln!(
            "Failed to sync schedule for workflow {}: {:?}",
            workflow.id, error
        );
    }
}

async fn sync_workflow_schedule_inner(
    state: &AppState,
    workflow: &Workflow,
) -> Result<(), sqlx::Error> {
    let schedule_value = extract_schedule_config(&workflow.data);
    let existing = state
        .workflow_repo
        .get_schedule_for_workflow(workflow.id)
        .await?;

    match schedule_value {
        Some(cfg_value) => {
            if is_notion_trigger_config(&cfg_value) {
                let merged_config = merge_notion_state(cfg_value, existing.as_ref());
                let next_offset = compute_notion_next_run(
                    existing.as_ref().and_then(|s| s.next_run_at),
                    &merged_config,
                );
                if let Some(next_run_at) = next_offset {
                    state
                        .workflow_repo
                        .upsert_workflow_schedule(
                            workflow.user_id,
                            workflow.id,
                            merged_config,
                            Some(next_run_at),
                        )
                        .await?;
                } else {
                    state
                        .workflow_repo
                        .disable_workflow_schedule(workflow.id)
                        .await?;
                }
                return Ok(());
            }
            if let Some(cfg) = parse_schedule_config(&cfg_value) {
                let last_run = existing
                    .as_ref()
                    .and_then(|s| s.last_run_at)
                    .and_then(offset_to_utc);
                let now = Utc::now();
                if let Some(next_dt) = compute_next_run(&cfg, last_run, now) {
                    if let Some(next_offset) = utc_to_offset(next_dt) {
                        state
                            .workflow_repo
                            .upsert_workflow_schedule(
                                workflow.user_id,
                                workflow.id,
                                cfg_value,
                                Some(next_offset),
                            )
                            .await?;
                    } else {
                        state
                            .workflow_repo
                            .disable_workflow_schedule(workflow.id)
                            .await?;
                    }
                } else {
                    state
                        .workflow_repo
                        .disable_workflow_schedule(workflow.id)
                        .await?;
                }
            } else {
                state
                    .workflow_repo
                    .disable_workflow_schedule(workflow.id)
                    .await?;
            }
        }
        None => {
            state
                .workflow_repo
                .disable_workflow_schedule(workflow.id)
                .await?;
        }
    }

    Ok(())
}

const DEFAULT_NOTION_POLL_INTERVAL_SECONDS: i64 = 300;
const MIN_NOTION_POLL_INTERVAL_SECONDS: i64 = 30;
const MAX_NOTION_POLL_INTERVAL_SECONDS: i64 = 3600;

#[allow(dead_code)]
fn normalize_trigger_type(value: Option<&Value>) -> Option<String> {
    value
        .and_then(|value| value.as_str())
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
}

fn is_numeric_identifier(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|ch| ch.is_ascii_digit())
}

fn validate_github_installation_id(
    raw: Option<&Value>,
    trigger_node_id: &str,
) -> Result<String, GitHubTriggerMappingError> {
    let Some(raw) = raw else {
        return Err(GitHubTriggerMappingError {
            trigger_node_id: Some(trigger_node_id.to_string()),
            code: "missing_installation_id",
        });
    };
    let Some(candidate) = read_string_or_number(Some(raw)) else {
        return Err(GitHubTriggerMappingError {
            trigger_node_id: Some(trigger_node_id.to_string()),
            code: "invalid_installation_id_format",
        });
    };
    let trimmed = candidate.trim();
    if !is_numeric_identifier(trimmed) {
        return Err(GitHubTriggerMappingError {
            trigger_node_id: Some(trigger_node_id.to_string()),
            code: "invalid_installation_id_format",
        });
    }
    Ok(trimmed.to_string())
}

fn validate_github_repository_id(
    raw: Option<&Value>,
    trigger_node_id: &str,
) -> Result<Option<String>, GitHubTriggerMappingError> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    let Some(candidate) = read_string_or_number(Some(raw)) else {
        return Err(GitHubTriggerMappingError {
            trigger_node_id: Some(trigger_node_id.to_string()),
            code: "invalid_repository_id_format",
        });
    };
    let trimmed = candidate.trim();
    if !is_numeric_identifier(trimmed) {
        return Err(GitHubTriggerMappingError {
            trigger_node_id: Some(trigger_node_id.to_string()),
            code: "invalid_repository_id_format",
        });
    }
    Ok(Some(trimmed.to_string()))
}

#[allow(dead_code)]
fn parse_github_trigger_event(trigger_type: &str) -> Option<String> {
    let suffix = trigger_type.strip_prefix(GITHUB_TRIGGER_PREFIX)?;
    let mut parts = suffix.split('.');
    let event = parts.next()?.trim();
    if event.is_empty() || parts.next().is_some() {
        return None;
    }
    if GITHUB_TRIGGER_ALLOWED_EVENTS.contains(&event) {
        Some(event.to_string())
    } else {
        None
    }
}

fn is_notion_trigger_type(trigger_type: &str) -> bool {
    matches!(
        trigger_type.trim().to_ascii_lowercase().as_str(),
        "notion.new_database_row" | "notion.updated_database_row"
    )
}

fn is_notion_trigger_config(config: &Value) -> bool {
    config
        .get("triggerType")
        .and_then(|value| value.as_str())
        .map(is_notion_trigger_type)
        .unwrap_or(false)
}

fn build_notion_trigger_config(data: &Value, trigger_type: &str) -> Option<Value> {
    let map = data.as_object()?;
    let connection_scope = read_string(map.get("connectionScope"))?;
    let connection_id = read_string(map.get("connectionId"))?;
    let database_id = read_string(map.get("databaseId"))?;

    let mut out = serde_json::Map::new();
    out.insert(
        "triggerType".to_string(),
        Value::String(trigger_type.to_string()),
    );
    out.insert(
        "connectionScope".to_string(),
        Value::String(connection_scope),
    );
    out.insert("connectionId".to_string(), Value::String(connection_id));
    out.insert("databaseId".to_string(), Value::String(database_id));

    if let Some(page_size) = read_page_size(map.get("pageSize")) {
        out.insert(
            "pageSize".to_string(),
            Value::Number(serde_json::Number::from(page_size)),
        );
    }

    Some(Value::Object(out))
}

fn merge_notion_state(config: Value, existing: Option<&WorkflowSchedule>) -> Value {
    let Some(existing) = existing else {
        return config;
    };
    let Some(existing_state) = existing.config.get("state") else {
        return config;
    };

    let mut updated = config;
    if let Value::Object(map) = &mut updated {
        if !map.contains_key("state") {
            map.insert("state".to_string(), existing_state.clone());
        }
    }
    updated
}

fn compute_notion_next_run(
    existing_next: Option<OffsetDateTime>,
    config: &Value,
) -> Option<OffsetDateTime> {
    let now_offset = OffsetDateTime::now_utc();
    if let Some(existing) = existing_next {
        if existing > now_offset {
            return Some(existing);
        }
    }

    let interval = notion_poll_interval_seconds(config).max(1);
    let next_dt = Utc::now().checked_add_signed(ChronoDuration::seconds(interval))?;
    utc_to_offset(next_dt)
}

fn notion_poll_interval_seconds(config: &Value) -> i64 {
    let from_config = read_page_size(config.get("pollIntervalSeconds")).map(|value| value as i64);
    let from_env = std::env::var("NOTION_POLL_INTERVAL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok());

    let raw = from_config
        .or(from_env)
        .unwrap_or(DEFAULT_NOTION_POLL_INTERVAL_SECONDS);
    raw.clamp(
        MIN_NOTION_POLL_INTERVAL_SECONDS,
        MAX_NOTION_POLL_INTERVAL_SECONDS,
    )
}

fn read_page_size(value: Option<&Value>) -> Option<u32> {
    match value {
        Some(Value::Number(num)) => num.as_u64().and_then(|v| u32::try_from(v).ok()),
        Some(Value::String(raw)) => raw.trim().parse::<u32>().ok(),
        _ => None,
    }
}

#[allow(dead_code)]
fn read_string_or_number(value: Option<&Value>) -> Option<String> {
    match value {
        Some(Value::String(raw)) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        Some(Value::Number(num)) => num
            .as_u64()
            .map(|value| value.to_string())
            .or_else(|| num.as_i64().map(|value| value.to_string())),
        _ => None,
    }
}

fn read_string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

#[allow(dead_code)]
fn push_string_list(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(raw) => {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                out.push(trimmed.to_string());
            }
        }
        Value::Array(items) => {
            for item in items {
                push_string_list(item, out);
            }
        }
        _ => {}
    }
}

#[allow(dead_code)]
fn read_github_event_selections(map: &serde_json::Map<String, Value>) -> Vec<String> {
    let mut values = Vec::new();
    if let Some(value) = map.get(GITHUB_TRIGGER_EVENT_KEY) {
        push_string_list(value, &mut values);
        return values;
    }
    for key in GITHUB_TRIGGER_EVENT_KEY_ALIASES {
        if let Some(value) = map.get(key) {
            push_string_list(value, &mut values);
        }
    }
    values
}

#[allow(dead_code)]
fn build_github_event_types(
    base_event_type: &str,
    event_namespace: &str,
    selections: &[String],
) -> Result<Vec<String>, &'static str> {
    let mut event_types = Vec::new();
    let mut seen = BTreeSet::new();
    let mut has_invalid = false;
    let mut has_values = false;
    let event_prefix = format!("{event_namespace}.");

    if selections.is_empty() {
        event_types.push(base_event_type.to_string());
        return Ok(event_types);
    }

    for selection in selections {
        let normalized = selection.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            continue;
        }
        has_values = true;
        let event_type = if let Some(stripped) = normalized.strip_prefix(GITHUB_TRIGGER_PREFIX) {
            if stripped.starts_with(event_prefix.as_str()) {
                let action = stripped.trim_start_matches(event_prefix.as_str());
                if action.is_empty() {
                    has_invalid = true;
                    continue;
                }
                format!("{base_event_type}.{action}")
            } else {
                has_invalid = true;
                continue;
            }
        } else if let Some((prefix, action)) = normalized.split_once('.') {
            if prefix != event_namespace || action.is_empty() {
                has_invalid = true;
                continue;
            }
            format!("{base_event_type}.{action}")
        } else {
            if normalized == event_namespace {
                has_invalid = true;
                continue;
            }
            format!("{base_event_type}.{normalized}")
        };

        if seen.insert(event_type.clone()) {
            event_types.push(event_type);
        }
    }

    if has_invalid {
        return Err("invalid_event_selection");
    }

    if event_types.is_empty() {
        if has_values {
            return Err("invalid_event_selection");
        }
        event_types.push(base_event_type.to_string());
    }

    Ok(event_types)
}

pub(crate) fn plan_violation_response(violations: Vec<PlanViolation>) -> Response {
    let summary = if violations.len() == 1 {
        violations[0].message.clone()
    } else {
        "Solo plan restrictions prevent this workflow from running. Upgrade in Settings → Plan or adjust the nodes listed below.".to_string()
    };

    let details: Vec<Value> = violations
        .into_iter()
        .map(|violation| {
            let mut payload = json!({
                "code": violation.code,
                "message": violation.message,
            });
            if let Some(label) = violation.node_label {
                payload["nodeLabel"] = json!(label);
            }
            payload
        })
        .collect();

    (
        StatusCode::FORBIDDEN,
        Json(json!({
            "success": false,
            "status": "error",
            "message": summary,
            "violations": details,
        })),
    )
        .into_response()
}

pub(crate) fn enforce_solo_workflow_limit(workflows: &[Workflow]) -> Vec<Workflow> {
    let mut personal: Vec<_> = workflows
        .iter()
        .filter(|&wf| wf.workspace_id.is_none())
        .cloned()
        .collect();
    personal.sort_by_key(|wf| wf.created_at);
    personal.into_iter().take(3).collect()
}

pub(crate) const SOLO_MONTHLY_RUN_LIMIT: i64 = 250;

pub(crate) fn plan_tier_str(tier: NormalizedPlanTier) -> &'static str {
    match tier {
        NormalizedPlanTier::Solo => "solo",
        NormalizedPlanTier::Workspace => "workspace",
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlanContext {
    Solo,
    WorkspaceOwned { workspace_id: Uuid },
    WorkspaceMember { workspace_id: Uuid },
    WorkspaceUnknown,
}

fn extract_workspace_id_from_plan(plan: Option<&str>) -> Option<Uuid> {
    let raw = plan?.trim();
    if raw.is_empty() {
        return None;
    }

    let segments = raw.split([':', '/', '|', ',', ';', '\n', '\r', '\t', ' ']);
    for segment in segments {
        let candidate = segment
            .trim_matches(|c: char| matches!(c, '[' | ']' | '{' | '}' | '(' | ')' | '"' | '\''));
        if candidate.len() == 36 {
            if let Ok(id) = Uuid::parse_str(candidate) {
                return Some(id);
            }
        }
    }

    None
}

pub(crate) fn membership_roles_map(
    memberships: &[WorkspaceMembershipSummary],
) -> HashMap<Uuid, WorkspaceRole> {
    memberships
        .iter()
        .map(|membership| (membership.workspace.id, membership.role))
        .collect()
}

pub(crate) fn plan_context_for_user(
    plan: Option<&str>,
    memberships: &[WorkspaceMembershipSummary],
    explicit_workspace: Option<Uuid>,
) -> PlanContext {
    if let Some(workspace_id) = explicit_workspace.or_else(|| extract_workspace_id_from_plan(plan))
    {
        if let Some(summary) = memberships.iter().find(|m| m.workspace.id == workspace_id) {
            if summary.role == WorkspaceRole::Owner {
                PlanContext::WorkspaceOwned { workspace_id }
            } else {
                PlanContext::WorkspaceMember { workspace_id }
            }
        } else {
            PlanContext::WorkspaceUnknown
        }
    } else if NormalizedPlanTier::from_option(plan).is_solo() {
        PlanContext::Solo
    } else {
        PlanContext::WorkspaceUnknown
    }
}

pub(crate) fn can_access_workspace_in_context(
    context: PlanContext,
    workspace_id: Uuid,
    roles: &HashMap<Uuid, WorkspaceRole>,
) -> bool {
    match context {
        PlanContext::Solo => matches!(roles.get(&workspace_id), Some(WorkspaceRole::Owner)),
        PlanContext::WorkspaceOwned {
            workspace_id: active,
        } => {
            if active == workspace_id {
                true
            } else {
                matches!(roles.get(&workspace_id), Some(WorkspaceRole::Owner))
            }
        }
        PlanContext::WorkspaceMember {
            workspace_id: active,
        } => active == workspace_id,
        PlanContext::WorkspaceUnknown => roles.contains_key(&workspace_id),
    }
}

pub(crate) fn can_access_workflow_in_context(
    workflow: &Workflow,
    context: PlanContext,
    roles: &HashMap<Uuid, WorkspaceRole>,
) -> bool {
    match workflow.workspace_id {
        Some(workspace_id) => can_access_workspace_in_context(context, workspace_id, roles),
        None => !matches!(context, PlanContext::WorkspaceMember { .. }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::workspace::Workspace;
    use time::OffsetDateTime;

    fn make_membership(
        workspace_id: Uuid,
        role: WorkspaceRole,
        owner_id: Uuid,
    ) -> WorkspaceMembershipSummary {
        WorkspaceMembershipSummary {
            workspace: Workspace {
                id: workspace_id,
                name: "Test".into(),
                created_by: owner_id,
                owner_id,
                plan: "workspace".into(),
                stripe_overage_item_id: None,
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                deleted_at: None,
            },
            role,
        }
    }

    #[test]
    fn context_identifies_workspace_member() {
        let workspace_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let memberships = vec![make_membership(workspace_id, WorkspaceRole::User, owner_id)];

        let context = plan_context_for_user(
            Some(&format!("workspace:{}", workspace_id)),
            &memberships,
            None,
        );

        assert_eq!(context, PlanContext::WorkspaceMember { workspace_id });
    }

    #[test]
    fn context_identifies_workspace_owner() {
        let workspace_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let memberships = vec![make_membership(
            workspace_id,
            WorkspaceRole::Owner,
            owner_id,
        )];

        let context = plan_context_for_user(
            Some(&format!("workspace:{}", workspace_id)),
            &memberships,
            None,
        );

        assert_eq!(context, PlanContext::WorkspaceOwned { workspace_id });
    }

    #[test]
    fn non_owned_workflow_inaccessible_in_solo_context() {
        let workspace_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let memberships = vec![make_membership(workspace_id, WorkspaceRole::User, owner_id)];
        let roles = membership_roles_map(&memberships);
        let workflow = Workflow {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            workspace_id: Some(workspace_id),
            name: "Sample".into(),
            description: None,
            data: json!({}),
            concurrency_limit: 1,
            egress_allowlist: Vec::new(),
            locked_by: None,
            locked_at: None,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };

        assert!(!can_access_workflow_in_context(
            &workflow,
            PlanContext::Solo,
            &roles
        ));
    }

    #[test]
    fn member_context_limited_to_active_workspace() {
        let workspace_a = Uuid::new_v4();
        let workspace_b = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let memberships = vec![
            make_membership(workspace_a, WorkspaceRole::User, owner_id),
            make_membership(workspace_b, WorkspaceRole::Owner, owner_id),
        ];
        let roles = membership_roles_map(&memberships);

        let workflow_a = Workflow {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            workspace_id: Some(workspace_a),
            name: "A".into(),
            description: None,
            data: json!({}),
            concurrency_limit: 1,
            egress_allowlist: Vec::new(),
            locked_by: None,
            locked_at: None,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };

        let workflow_b = Workflow {
            workspace_id: Some(workspace_b),
            ..workflow_a.clone()
        };

        let context = PlanContext::WorkspaceMember {
            workspace_id: workspace_a,
        };

        assert!(can_access_workflow_in_context(&workflow_a, context, &roles));
        assert!(!can_access_workflow_in_context(
            &workflow_b,
            context,
            &roles
        ));
    }
}
