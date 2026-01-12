mod asana;
mod code;
pub(crate) mod delay;
mod email;
pub(crate) mod formatter;
mod google;
mod http;
mod manifest;
mod messaging;
mod notion;
pub(crate) mod registry;

use std::sync::Arc;

use serde_json::{json, Value};
use uuid::Uuid;

use crate::engine::actions::registry::{
    ActionDefinition, ActionExecutionSemantics, ActionExecutor, ActionManifest, ActionValidator,
    AsanaExecutor, CodeExecutor, ConditionExecutor, EmailExecutor, HttpExecutor, MessagingExecutor,
    NotionExecutor, SheetsExecutor, TriggerExecutor,
};
use crate::engine::templating::templ_str;
use crate::state::AppState;

use super::graph::Node;
pub(crate) use manifest::load_action_manifest_aliases;

pub(crate) const TRIGGER_MANIFEST: ActionManifest = ActionManifest {
    action_type: "trigger",
    required_fields: &[],
    execution_semantics: ActionExecutionSemantics::Standard,
};

pub(crate) const CONDITION_MANIFEST: ActionManifest = ActionManifest {
    action_type: "condition",
    required_fields: &[],
    execution_semantics: ActionExecutionSemantics::Conditional,
};

pub(crate) const REQUIRED_ACTION_TYPES: &[&str] = &[
    "trigger",
    "condition",
    "delay",
    "formatter",
    "http",
    "email",
    "messaging",
    "teams",
    "slack",
    "googlechat",
    "microsoftteams",
    "sheets",
    "notion",
    "code",
    "asana",
];

pub(crate) const KIND_ALIASES: &[(&str, &str)] = &[
    ("trigger", "trigger"),
    ("condition", "condition"),
    ("delay", "delay"),
    ("logicdelay", "delay"),
    ("wait", "delay"),
    ("formatter", "formatter"),
    ("logicformatter", "formatter"),
    ("transform", "formatter"),
];

pub(crate) fn action_definitions() -> Vec<ActionDefinition> {
    let messaging_executor: Arc<dyn ActionExecutor> = Arc::new(MessagingExecutor);
    let trigger_validator: Arc<dyn ActionValidator> = Arc::new(TriggerValidator);
    let condition_validator: Arc<dyn ActionValidator> = Arc::new(ConditionValidator);
    let delay_validator: Arc<dyn ActionValidator> = Arc::new(delay::DelayValidator);
    let formatter_validator: Arc<dyn ActionValidator> = Arc::new(formatter::FormatterValidator);
    let http_validator: Arc<dyn ActionValidator> = Arc::new(http::HttpValidator);
    let email_validator: Arc<dyn ActionValidator> = Arc::new(email::EmailValidator);
    let messaging_validator: Arc<dyn ActionValidator> = Arc::new(messaging::MessagingValidator);
    let sheets_validator: Arc<dyn ActionValidator> = Arc::new(google::SheetsValidator);
    let notion_validator: Arc<dyn ActionValidator> = Arc::new(notion::NotionValidator);
    let code_validator: Arc<dyn ActionValidator> = Arc::new(code::CodeValidator);
    let asana_validator: Arc<dyn ActionValidator> = Arc::new(asana::AsanaValidator);

    vec![
        ActionDefinition {
            manifest: &TRIGGER_MANIFEST,
            executor: Some(Arc::new(TriggerExecutor)),
            validator: Some(trigger_validator.clone()),
        },
        ActionDefinition {
            manifest: &CONDITION_MANIFEST,
            executor: Some(Arc::new(ConditionExecutor)),
            validator: Some(condition_validator.clone()),
        },
        ActionDefinition {
            manifest: &delay::MANIFEST,
            executor: Some(Arc::new(delay::DelayExecutor)),
            validator: Some(delay_validator.clone()),
        },
        ActionDefinition {
            manifest: &formatter::MANIFEST,
            executor: Some(Arc::new(formatter::FormatterExecutor)),
            validator: Some(formatter_validator.clone()),
        },
        ActionDefinition {
            manifest: &http::MANIFEST,
            executor: Some(Arc::new(HttpExecutor)),
            validator: Some(http_validator.clone()),
        },
        ActionDefinition {
            manifest: &email::MANIFEST,
            executor: Some(Arc::new(EmailExecutor)),
            validator: Some(email_validator.clone()),
        },
        ActionDefinition {
            manifest: &messaging::MANIFEST,
            executor: Some(messaging_executor.clone()),
            validator: Some(messaging_validator.clone()),
        },
        ActionDefinition {
            manifest: &messaging::TEAMS_MANIFEST,
            executor: Some(messaging_executor.clone()),
            validator: Some(messaging_validator.clone()),
        },
        ActionDefinition {
            manifest: &messaging::SLACK_MANIFEST,
            executor: Some(messaging_executor.clone()),
            validator: Some(messaging_validator.clone()),
        },
        ActionDefinition {
            manifest: &messaging::GOOGLECHAT_MANIFEST,
            executor: Some(messaging_executor.clone()),
            validator: Some(messaging_validator.clone()),
        },
        ActionDefinition {
            manifest: &messaging::MICROSOFTTEAMS_MANIFEST,
            executor: Some(messaging_executor),
            validator: Some(messaging_validator.clone()),
        },
        ActionDefinition {
            manifest: &google::MANIFEST,
            executor: Some(Arc::new(SheetsExecutor)),
            validator: Some(sheets_validator.clone()),
        },
        ActionDefinition {
            manifest: &notion::MANIFEST,
            executor: Some(Arc::new(NotionExecutor)),
            validator: Some(notion_validator.clone()),
        },
        ActionDefinition {
            manifest: &code::MANIFEST,
            executor: Some(Arc::new(CodeExecutor)),
            validator: Some(code_validator.clone()),
        },
        ActionDefinition {
            manifest: &asana::MANIFEST,
            executor: Some(Arc::new(AsanaExecutor)),
            validator: Some(asana_validator),
        },
    ]
}

pub(crate) fn validate_required_fields(
    node: &Node,
    required_fields: &[&'static str],
) -> Result<(), String> {
    for field in required_fields {
        let Some(value) = node.data.get(*field) else {
            return Err(format!("Missing required field `{}`", field));
        };
        if value.is_null() {
            return Err(format!("Missing required field `{}`", field));
        }
    }
    Ok(())
}

pub(crate) struct TriggerValidator;

impl ActionValidator for TriggerValidator {
    fn validate(&self, node: &Node) -> Result<(), String> {
        validate_required_fields(node, TRIGGER_MANIFEST.required_fields)
    }
}

pub(crate) struct ConditionValidator;

impl ActionValidator for ConditionValidator {
    fn validate(&self, node: &Node) -> Result<(), String> {
        validate_required_fields(node, CONDITION_MANIFEST.required_fields)
    }
}

#[derive(Debug, Clone)]
pub(crate) enum NodeConnectionUsage {
    User(UserConnectionUsage),
    Workspace(WorkspaceConnectionUsage),
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct UserConnectionUsage {
    pub connection_id: Option<String>,
    pub account_email: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct WorkspaceConnectionUsage {
    pub connection_id: Uuid,
}

pub(crate) fn resolve_connection_usage(params: &Value) -> Result<NodeConnectionUsage, String> {
    let read_str = |value: Option<&Value>| -> Option<String> {
        value
            .and_then(|v| v.as_str())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    };

    let connection_obj = params.get("connection").and_then(|value| value.as_object());

    let scope = connection_obj
        .and_then(|obj| read_str(obj.get("connectionScope")))
        .or_else(|| read_str(params.get("connectionScope")));

    let connection_id = connection_obj
        .and_then(|obj| read_str(obj.get("connectionId")))
        .or_else(|| read_str(params.get("connectionId")));

    if connection_obj.is_some() || scope.is_some() || connection_id.is_some() {
        let scope_value = scope.clone().ok_or_else(|| {
            "Connection scope is required when specifying a connection".to_string()
        })?;

        match scope_value.to_ascii_lowercase().as_str() {
            "workspace" => {
                let id_str = connection_id
                    .clone()
                    .ok_or_else(|| "Workspace connections require a connectionId".to_string())?;

                let parsed_id = Uuid::parse_str(&id_str)
                    .map_err(|_| "Workspace connectionId must be a valid UUID".to_string())?;

                return Ok(NodeConnectionUsage::Workspace(WorkspaceConnectionUsage {
                    connection_id: parsed_id,
                }));
            }
            "user" | "personal" => {
                let id_str = connection_id
                    .clone()
                    .ok_or_else(|| "Personal OAuth connections require an explicit connectionId. Please select a specific OAuth connection from your integrations.".to_string())?;

                Uuid::parse_str(&id_str)
                    .map_err(|_| "Personal connectionId must be a valid UUID. Please select a valid OAuth connection.".to_string())?;

                return Ok(NodeConnectionUsage::User(UserConnectionUsage {
                    connection_id: Some(id_str),
                    account_email: None,
                }));
            }
            other => {
                return Err(format!("Unsupported connection scope `{}`", other));
            }
        }
    }

    Err("OAuth connections require explicit connectionScope and connectionId parameters. Please specify both connectionScope ('personal' or 'workspace') and connectionId.".to_string())
}

pub(crate) async fn ensure_run_membership(
    state: &AppState,
    workspace_id: Uuid,
    user_id: Uuid,
) -> Result<(), String> {
    let is_member = state
        .workspace_repo
        .is_member(workspace_id, user_id)
        .await
        .map_err(|err| format!("Failed to verify workspace membership: {err}"))?;

    if !is_member {
        return Err(
            "Forbidden: you are no longer a member of this workspace. Ask an admin to re-invite you before using its shared connections.".to_string()
        );
    }

    Ok(())
}

pub async fn ensure_workspace_plan(state: &AppState, workspace_id: Uuid) -> Result<(), String> {
    // Query the workspace plan tier from the repository
    let plan = state
        .workspace_repo
        .get_plan(workspace_id)
        .await
        .map_err(|err| format!("Failed to verify workspace plan: {err}"))?;

    // Only the Workspace tier is allowed for workspace-scoped OAuth actions
    if !matches!(plan, crate::models::plan::PlanTier::Workspace) {
        return Err("Forbidden: This feature requires the Workspace plan.".to_string());
    }

    Ok(())
}

pub(crate) async fn execute_trigger(
    node: &Node,
    context: &Value,
) -> Result<(Value, Option<String>), String> {
    let mut map = serde_json::Map::new();
    if let Some(inputs) = node.data.get("inputs").and_then(|v| v.as_array()) {
        for kv in inputs {
            if let (Some(k), Some(v)) = (kv.get("key"), kv.get("value")) {
                if let Some(ks) = k.as_str() {
                    let value_raw = v.as_str().unwrap_or("");
                    let templated = templ_str(value_raw, context);
                    let parsed = parse_input_value(&templated);
                    map.insert(ks.to_string(), parsed);
                }
            }
        }
    }
    Ok((Value::Object(map), None))
}

pub(crate) async fn execute_condition(
    node: &Node,
    context: &Value,
) -> Result<(Value, Option<String>), String> {
    let expression = node
        .data
        .get("expression")
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .unwrap_or("");

    let result = if !expression.is_empty() {
        evaluate_expression(expression, context)?
    } else {
        evaluate_legacy_condition(node, context)?
    };

    Ok((json!({"result": result}), None))
}

fn parse_input_value(raw: &str) -> Value {
    parse_flexible_value(raw)
}

fn evaluate_expression(expression: &str, context: &Value) -> Result<bool, String> {
    let trimmed = expression.trim();
    if trimmed.is_empty() {
        return Err("Condition expression is required".to_string());
    }

    let (op, left_raw, right_raw) =
        parse_expression(trimmed).ok_or_else(|| "Unsupported condition expression".to_string())?;

    let left = resolve_operand(&left_raw, context);
    let right = resolve_operand(&right_raw, context);

    Ok(match op {
        ConditionOperator::Equals => values_equal(&left, &right),
        ConditionOperator::NotEquals => !values_equal(&left, &right),
        ConditionOperator::GreaterThan => compare_order(&left, &right, ValueOrdering::Greater),
        ConditionOperator::LessThan => compare_order(&left, &right, ValueOrdering::Less),
        ConditionOperator::GreaterThanOrEqual => {
            compare_order(&left, &right, ValueOrdering::Equal)
                || compare_order(&left, &right, ValueOrdering::Greater)
        }
        ConditionOperator::LessThanOrEqual => {
            compare_order(&left, &right, ValueOrdering::Equal)
                || compare_order(&left, &right, ValueOrdering::Less)
        }
        ConditionOperator::Contains => {
            let Some(left_str) = value_as_string(&left) else {
                return Ok(false);
            };
            let Some(right_str) = value_as_string(&right) else {
                return Ok(false);
            };
            left_str.contains(&right_str)
        }
    })
}

fn evaluate_legacy_condition(node: &Node, context: &Value) -> Result<bool, String> {
    let field = node
        .data
        .get("field")
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "Missing condition field".to_string())?;
    let operator = node
        .data
        .get("operator")
        .and_then(|v| v.as_str())
        .unwrap_or("equals");
    let value_raw = node
        .data
        .get("value")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let actual_value = resolve_operand(field, context);
    let expected_value = resolve_operand(value_raw, context);

    Ok(match operator {
        "equals" => values_equal(&actual_value, &expected_value),
        "not equals" => !values_equal(&actual_value, &expected_value),
        "contains" => {
            let Some(left_str) = value_as_string(&actual_value) else {
                return Ok(false);
            };
            let Some(right_str) = value_as_string(&expected_value) else {
                return Ok(false);
            };
            left_str.contains(&right_str)
        }
        "greater than" => compare_order(&actual_value, &expected_value, ValueOrdering::Greater),
        "less than" => compare_order(&actual_value, &expected_value, ValueOrdering::Less),
        _ => false,
    })
}

#[derive(Clone, Copy)]
enum ConditionOperator {
    Equals,
    NotEquals,
    GreaterThan,
    LessThan,
    GreaterThanOrEqual,
    LessThanOrEqual,
    Contains,
}

fn parse_expression(expr: &str) -> Option<(ConditionOperator, String, String)> {
    const OPERATORS: &[(&str, ConditionOperator)] = &[
        (" contains ", ConditionOperator::Contains),
        (">=", ConditionOperator::GreaterThanOrEqual),
        ("<=", ConditionOperator::LessThanOrEqual),
        ("==", ConditionOperator::Equals),
        ("!=", ConditionOperator::NotEquals),
        (">", ConditionOperator::GreaterThan),
        ("<", ConditionOperator::LessThan),
    ];

    for (pattern, op) in OPERATORS {
        if let Some((left, right)) = expr.split_once(pattern) {
            return Some((*op, left.trim().to_string(), right.trim().to_string()));
        }
    }
    None
}

fn resolve_operand(raw: &str, context: &Value) -> Value {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Value::Null;
    }
    if let Some(val) = lookup_path(context, trimmed) {
        return val;
    }
    if let Value::Object(map) = context {
        for value in map.values() {
            if let Some(obj) = value.as_object() {
                if let Some(found) = obj.get(trimmed) {
                    return found.clone();
                }
            }
        }
    }
    let templated = templ_str(trimmed, context);
    parse_flexible_value(&templated)
}

pub(crate) fn lookup_path(context: &Value, path: &str) -> Option<Value> {
    let mut current = context;
    for part in path.split('.') {
        if part.is_empty() {
            continue;
        }
        match current {
            Value::Object(map) => current = map.get(part)?,
            Value::Array(arr) => {
                let idx: usize = part.parse().ok()?;
                current = arr.get(idx)?;
            }
            other => {
                return Some(other.clone());
            }
        }
    }
    Some(current.clone())
}

pub(crate) fn parse_flexible_value(raw: &str) -> Value {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Value::Null;
    }
    if let Ok(json_val) = serde_json::from_str::<Value>(trimmed) {
        return json_val;
    }
    if trimmed.len() >= 2
        && ((trimmed.starts_with('\"') && trimmed.ends_with('\"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\'')))
    {
        let inner = &trimmed[1..trimmed.len() - 1];
        return Value::String(inner.replace("\\\"", "\"").replace("\\'", "'"));
    }
    Value::String(trimmed.to_string())
}

fn values_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(a), Value::Number(b)) => a == b,
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Null, Value::Null) => true,
        _ => left == right || value_as_string(left) == value_as_string(right),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ValueOrdering {
    Greater,
    Less,
    Equal,
}

fn compare_order(left: &Value, right: &Value, ordering: ValueOrdering) -> bool {
    if let (Some(a), Some(b)) = (value_as_f64(left), value_as_f64(right)) {
        return match ordering {
            ValueOrdering::Greater => a > b,
            ValueOrdering::Less => a < b,
            ValueOrdering::Equal => (a - b).abs() < f64::EPSILON,
        };
    }
    if let (Some(a), Some(b)) = (value_as_string(left), value_as_string(right)) {
        return match ordering {
            ValueOrdering::Greater => a > b,
            ValueOrdering::Less => a < b,
            ValueOrdering::Equal => a == b,
        };
    }
    false
}

fn value_as_f64(value: &Value) -> Option<f64> {
    match value {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse::<f64>().ok(),
        Value::Bool(true) => Some(1.0),
        Value::Bool(false) => Some(0.0),
        _ => None,
    }
}

fn value_as_string(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => n.as_f64().map(|v| v.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null => Some(String::new()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use serde_json::json;

    #[test]
    fn resolve_connection_usage_honors_legacy_workspace_scope() {
        let connection_id = Uuid::new_v4();
        let params = json!({
            "oauthConnectionScope": "workspace",
            "oauthConnectionId": connection_id.to_string(),
            "oauthAccountEmail": "workspace@example.com"
        });

        let result = resolve_connection_usage(&params);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("OAuth connections require explicit connectionScope and connectionId"));
    }

    #[test]
    fn resolve_connection_usage_honors_legacy_personal_scope() {
        let params = json!({
            "oauthConnectionScope": "personal",
            "oauthConnectionId": "microsoft-personal",
            "oauthAccountEmail": "alice@example.com"
        });

        let result = resolve_connection_usage(&params);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("OAuth connections require explicit connectionScope and connectionId"));
    }

    #[test]
    fn resolve_connection_usage_supports_personal_scope_on_connection_object() {
        let params = json!({
            "connection": {
                "connectionScope": "personal",
                "connectionId": "asana-connection",
                "accountEmail": "jane@example.com"
            }
        });

        let result = resolve_connection_usage(&params);
        assert!(result.is_err());
        let error_msg = result.unwrap_err();
        assert!(error_msg.contains("Personal connectionId must be a valid UUID"));
    }
}
