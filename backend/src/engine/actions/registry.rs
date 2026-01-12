use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::engine::graph::Node;
use crate::models::workflow_run::WorkflowRun;
use crate::state::AppState;

use super::{asana, code, email, google, http, messaging, notion};
use super::{execute_condition, execute_trigger};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ActionExecutionSemantics {
    Standard,
    Conditional,
    Resumable,
}

pub(crate) struct ActionManifest {
    pub(crate) action_type: &'static str,
    pub(crate) required_fields: &'static [&'static str],
    pub(crate) execution_semantics: ActionExecutionSemantics,
}

pub(crate) enum ActionExecutionResult {
    Immediate {
        outputs: Value,
        selected_next: Option<String>,
    },
    Pause {
        outputs: Value,
        resume_at: DateTime<Utc>,
    },
}

pub(crate) struct ActionRuntimeContext<'a> {
    pub(crate) node: &'a Node,
    pub(crate) context: &'a Value,
    pub(crate) allowed_hosts: &'a [String],
    pub(crate) disallowed_hosts: &'a [String],
    pub(crate) default_deny: bool,
    pub(crate) is_prod: bool,
    pub(crate) state: &'a AppState,
    pub(crate) run: &'a WorkflowRun,
}

#[async_trait]
pub(crate) trait ActionExecutor: Send + Sync {
    async fn execute(&self, ctx: ActionRuntimeContext<'_>)
        -> Result<ActionExecutionResult, String>;
}

pub(crate) trait ActionValidator: Send + Sync {
    fn validate(&self, node: &Node) -> Result<(), String>;
}

pub(crate) struct ActionDefinition {
    pub(crate) manifest: &'static ActionManifest,
    pub(crate) executor: Option<Arc<dyn ActionExecutor>>,
    pub(crate) validator: Option<Arc<dyn ActionValidator>>,
}

pub(crate) struct ActionAlias {
    pub(crate) action_type: String,
    pub(crate) executor_action_type: String,
}

pub(crate) struct ActionResolution<'a> {
    pub(crate) action_type: &'a str,
    pub(crate) semantics: ActionExecutionSemantics,
    pub(crate) executor: &'a dyn ActionExecutor,
    pub(crate) validator: &'a dyn ActionValidator,
}

pub(crate) struct ActionRegistry {
    actions: HashMap<String, ActionEntry>,
    kind_aliases: HashMap<String, String>,
}

struct ActionEntry {
    action_type: String,
    semantics: ActionExecutionSemantics,
    executor: Arc<dyn ActionExecutor>,
    validator: Arc<dyn ActionValidator>,
}

impl ActionRegistry {
    pub(crate) fn new(
        definitions: Vec<ActionDefinition>,
        kind_aliases: Vec<(&'static str, &'static str)>,
        required_action_types: &[&'static str],
        action_aliases: Vec<ActionAlias>,
    ) -> Self {
        let mut actions: HashMap<String, ActionEntry> = HashMap::new();
        for definition in definitions {
            let action_type = normalize(definition.manifest.action_type);
            if action_type.is_empty() {
                panic!("Action type registration is required");
            }
            if actions.contains_key(&action_type) {
                panic!("Duplicate action_type registration: {}", action_type);
            }
            let executor = definition.executor.unwrap_or_else(|| {
                panic!("Missing executor registration for action `{}`", action_type)
            });
            let validator = definition.validator.unwrap_or_else(|| {
                panic!(
                    "Missing validator registration for action `{}`",
                    action_type
                )
            });
            actions.insert(
                action_type.clone(),
                ActionEntry {
                    action_type,
                    semantics: definition.manifest.execution_semantics,
                    executor,
                    validator,
                },
            );
        }

        for required in required_action_types {
            let required_key = normalize(required);
            if !actions.contains_key(&required_key) {
                panic!("Missing action registration for `{}`", required_key);
            }
        }

        for alias in action_aliases {
            let alias_key = normalize(&alias.action_type);
            let executor_key = normalize(&alias.executor_action_type);
            if alias_key.is_empty() {
                panic!("Action alias type is required");
            }
            if actions.contains_key(&alias_key) {
                panic!("Duplicate action_type registration: {}", alias_key);
            }

            let target = actions.get(&executor_key).unwrap_or_else(|| {
                panic!(
                    "Action alias `{}` references unregistered action `{}`",
                    alias_key, executor_key
                )
            });

            actions.insert(
                alias_key.clone(),
                ActionEntry {
                    action_type: alias_key,
                    semantics: target.semantics,
                    executor: target.executor.clone(),
                    validator: target.validator.clone(),
                },
            );
        }

        let mut aliases: HashMap<String, String> = HashMap::new();
        for (kind, action_type) in kind_aliases {
            let kind_key = normalize(kind);
            let action_key = normalize(action_type);
            if !actions.contains_key(&action_key) {
                panic!(
                    "Node kind `{}` references unregistered action `{}`",
                    kind_key, action_key
                );
            }
            if aliases.insert(kind_key.clone(), action_key).is_some() {
                panic!("Duplicate node kind registration for `{}`", kind_key);
            }
        }

        ActionRegistry {
            actions,
            kind_aliases: aliases,
        }
    }

    pub(crate) fn resolve(&self, node: &Node) -> Result<ActionResolution<'_>, String> {
        let action_type = self.resolve_action_type(node)?;
        let entry = self
            .actions
            .get(&action_type)
            .ok_or_else(|| format!("Unknown action type `{}`", action_type))?;
        Ok(ActionResolution {
            action_type: entry.action_type.as_str(),
            semantics: entry.semantics,
            executor: entry.executor.as_ref(),
            validator: entry.validator.as_ref(),
        })
    }

    fn resolve_action_type(&self, node: &Node) -> Result<String, String> {
        if let Some(action_type) = node.data.get("actionType").and_then(|v| v.as_str()) {
            let normalized = normalize(action_type);
            if !normalized.is_empty() {
                return Ok(normalized);
            }
        }

        let kind_key = normalize(&node.kind);
        if let Some(mapped) = self.kind_aliases.get(&kind_key) {
            return Ok(mapped.clone());
        }

        Err(format!("Unknown action for node kind `{}`", node.kind))
    }
}

fn normalize(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

pub(crate) struct TriggerExecutor;

#[async_trait]
impl ActionExecutor for TriggerExecutor {
    async fn execute(
        &self,
        ctx: ActionRuntimeContext<'_>,
    ) -> Result<ActionExecutionResult, String> {
        let (outputs, selected_next) = execute_trigger(ctx.node, ctx.context).await?;
        Ok(ActionExecutionResult::Immediate {
            outputs,
            selected_next,
        })
    }
}

pub(crate) struct ConditionExecutor;

#[async_trait]
impl ActionExecutor for ConditionExecutor {
    async fn execute(
        &self,
        ctx: ActionRuntimeContext<'_>,
    ) -> Result<ActionExecutionResult, String> {
        let (outputs, selected_next) = execute_condition(ctx.node, ctx.context).await?;
        Ok(ActionExecutionResult::Immediate {
            outputs,
            selected_next,
        })
    }
}

pub(crate) struct HttpExecutor;

#[async_trait]
impl ActionExecutor for HttpExecutor {
    async fn execute(
        &self,
        ctx: ActionRuntimeContext<'_>,
    ) -> Result<ActionExecutionResult, String> {
        let (outputs, selected_next) = http::execute_http(
            ctx.node,
            ctx.context,
            ctx.allowed_hosts,
            ctx.disallowed_hosts,
            ctx.default_deny,
            ctx.is_prod,
            ctx.state,
            ctx.run,
        )
        .await?;
        Ok(ActionExecutionResult::Immediate {
            outputs,
            selected_next,
        })
    }
}

pub(crate) struct EmailExecutor;

#[async_trait]
impl ActionExecutor for EmailExecutor {
    async fn execute(
        &self,
        ctx: ActionRuntimeContext<'_>,
    ) -> Result<ActionExecutionResult, String> {
        let (outputs, selected_next) =
            email::execute_email(ctx.node, ctx.context, ctx.state).await?;
        Ok(ActionExecutionResult::Immediate {
            outputs,
            selected_next,
        })
    }
}

pub(crate) struct MessagingExecutor;

#[async_trait]
impl ActionExecutor for MessagingExecutor {
    async fn execute(
        &self,
        ctx: ActionRuntimeContext<'_>,
    ) -> Result<ActionExecutionResult, String> {
        let (outputs, selected_next) =
            messaging::execute_messaging(ctx.node, ctx.context, ctx.state, ctx.run).await?;
        Ok(ActionExecutionResult::Immediate {
            outputs,
            selected_next,
        })
    }
}

pub(crate) struct SheetsExecutor;

#[async_trait]
impl ActionExecutor for SheetsExecutor {
    async fn execute(
        &self,
        ctx: ActionRuntimeContext<'_>,
    ) -> Result<ActionExecutionResult, String> {
        let (outputs, selected_next) =
            google::execute_sheets(ctx.node, ctx.context, ctx.state, ctx.run).await?;
        Ok(ActionExecutionResult::Immediate {
            outputs,
            selected_next,
        })
    }
}

pub(crate) struct NotionExecutor;

#[async_trait]
impl ActionExecutor for NotionExecutor {
    async fn execute(
        &self,
        ctx: ActionRuntimeContext<'_>,
    ) -> Result<ActionExecutionResult, String> {
        let (outputs, selected_next) =
            notion::execute_notion(ctx.node, ctx.context, ctx.state, ctx.run).await?;
        Ok(ActionExecutionResult::Immediate {
            outputs,
            selected_next,
        })
    }
}

pub(crate) struct CodeExecutor;

#[async_trait]
impl ActionExecutor for CodeExecutor {
    async fn execute(
        &self,
        ctx: ActionRuntimeContext<'_>,
    ) -> Result<ActionExecutionResult, String> {
        let (outputs, selected_next) = code::execute_code(ctx.node, ctx.context).await?;
        Ok(ActionExecutionResult::Immediate {
            outputs,
            selected_next,
        })
    }
}

pub(crate) struct AsanaExecutor;

#[async_trait]
impl ActionExecutor for AsanaExecutor {
    async fn execute(
        &self,
        ctx: ActionRuntimeContext<'_>,
    ) -> Result<ActionExecutionResult, String> {
        let (outputs, selected_next) =
            asana::execute_asana(ctx.node, ctx.context, ctx.state, ctx.run).await?;
        Ok(ActionExecutionResult::Immediate {
            outputs,
            selected_next,
        })
    }
}
