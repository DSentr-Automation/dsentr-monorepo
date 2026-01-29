use async_trait::async_trait;
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;

use crate::db::postgres_oauth_token_repository::PostgresUserOAuthTokenRepository;
use crate::engine::actions::registry::ActionRegistry;
use crate::engine::{build_action_registry, execute_run};
use crate::models::oauth_token::ConnectedOAuthProvider;
use crate::models::workflow::Workflow;
use crate::routes::github_provider_trigger_engine_bridge::ProviderTriggerExecutor;
use crate::routes::github_provider_trigger_execution_context::ProviderTriggerExecutionContext;
use crate::routes::options::secrets::decrypt_secret_store;
use crate::services::oauth::account_service::{
    installation_id_from_metadata, installation_is_disabled,
};
use crate::state::AppState;
use crate::utils::egress_allowlist::normalize_egress_allowlist;
use crate::utils::secrets::hydrate_secrets_into_snapshot;
use crate::utils::workflow_connection_metadata;

#[allow(dead_code)]
pub struct GitHubProviderTriggerExecutor {
    state: AppState,
    registry: Arc<ActionRegistry>,
}

struct DisabledInstallationContext {
    installation_id: String,
    connection_id: Option<Uuid>,
    token_id: Option<Uuid>,
}

impl GitHubProviderTriggerExecutor {
    pub fn new(state: AppState) -> Self {
        Self {
            state,
            registry: Arc::new(build_action_registry()),
        }
    }

    #[allow(dead_code)]
    fn prepare_trigger_snapshot(
        &self,
        workflow: &Workflow,
        trigger_node_id: &str,
    ) -> serde_json::Value {
        let mut snapshot = workflow.data.clone();

        // Set start node
        snapshot["_start_from_node"] = serde_json::Value::String(trigger_node_id.to_string());

        // Set trigger context for webhook
        snapshot["_trigger_context"] = json!({
            "trigger_node_id": trigger_node_id,
            "trigger_type": "webhook",
            "source": "github"
        });

        // Prepare egress allowlist
        let (egress_allowlist, rejected_entries) =
            normalize_egress_allowlist(workflow.egress_allowlist.clone());
        if !rejected_entries.is_empty() {
            tracing::warn!(
                workflow_id = %workflow.id,
                workspace_id = ?workflow.workspace_id,
                rejected = ?rejected_entries,
                "Rejected invalid workflow egress allowlist entries"
            );
        }
        snapshot["_egress_allowlist"] = serde_json::Value::Array(
            egress_allowlist
                .into_iter()
                .map(serde_json::Value::String)
                .collect(),
        );

        // Clear connection metadata and rebuild
        if let Some(obj) = snapshot.as_object_mut() {
            obj.remove("_connection_metadata");
        }

        let connection_metadata = workflow_connection_metadata::collect(&snapshot);
        workflow_connection_metadata::embed(&mut snapshot, &connection_metadata);

        snapshot
    }

    fn extract_trigger_installation_id(
        &self,
        workflow: &Workflow,
        trigger_node_id: &str,
    ) -> Option<String> {
        let nodes = workflow
            .data
            .get("nodes")
            .and_then(|value| value.as_array())?;
        for node in nodes {
            let node_id = node.get("id").and_then(|value| value.as_str())?;
            if node_id != trigger_node_id {
                continue;
            }
            let data = node.get("data").and_then(|value| value.as_object())?;
            let raw = data
                .get("installationId")
                .or_else(|| data.get("installation_id"))?;
            let candidate = match raw {
                Value::String(value) => value.trim().to_string(),
                Value::Number(value) => {
                    if let Some(num) = value.as_u64() {
                        num.to_string()
                    } else if let Some(num) = value.as_i64() {
                        num.to_string()
                    } else {
                        return None;
                    }
                }
                _ => return None,
            };
            if candidate.is_empty() || !candidate.chars().all(|ch| ch.is_ascii_digit()) {
                return None;
            }
            return Some(candidate);
        }
        None
    }

    async fn disabled_installation_context(
        &self,
        workflow: &Workflow,
        trigger_node_id: &str,
    ) -> Option<DisabledInstallationContext> {
        let installation_id = self.extract_trigger_installation_id(workflow, trigger_node_id)?;

        if let Some(workspace_id) = workflow.workspace_id {
            let mut connections = match self
                .state
                .workspace_connection_repo
                .list_by_workspace_and_provider(workspace_id, ConnectedOAuthProvider::GitHub)
                .await
            {
                Ok(list) => list,
                Err(_) => return None,
            };
            connections.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
            for connection in connections {
                if installation_id_from_metadata(&connection.metadata).as_deref()
                    != Some(installation_id.as_str())
                {
                    continue;
                }
                if installation_is_disabled(&connection.metadata) {
                    return Some(DisabledInstallationContext {
                        installation_id,
                        connection_id: Some(connection.id),
                        token_id: connection.user_oauth_token_id,
                    });
                }
                return None;
            }
            return None;
        }

        let user_repo = PostgresUserOAuthTokenRepository {
            pool: (*self.state.db_pool).clone(),
        };
        let mut tokens = match user_repo
            .list_by_user_and_provider(workflow.user_id, ConnectedOAuthProvider::GitHub)
            .await
        {
            Ok(list) => list,
            Err(_) => return None,
        };
        tokens.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        for token in tokens {
            if installation_id_from_metadata(&token.metadata).as_deref()
                != Some(installation_id.as_str())
            {
                continue;
            }
            if installation_is_disabled(&token.metadata) {
                return Some(DisabledInstallationContext {
                    installation_id,
                    connection_id: None,
                    token_id: Some(token.id),
                });
            }
            return None;
        }

        None
    }
}

#[async_trait]
impl ProviderTriggerExecutor for GitHubProviderTriggerExecutor {
    async fn execute_trigger(&self, context: &ProviderTriggerExecutionContext) {
        // Build idempotency key from context when delivery_id is available
        let idempotency_key = context.delivery_id.as_ref().map(|delivery| {
            format!(
                "github:{}:{}:{}",
                delivery, context.workflow_id, context.trigger_node_id
            )
        });

        // Load workflow using system access
        let workflow = match self
            .state
            .workflow_repo
            .find_workflow_by_id_public(context.workflow_id)
            .await
        {
            Ok(Some(workflow)) => workflow,
            Ok(None) => {
                tracing::error!(%context.workflow_id, "GitHub provider trigger: workflow not found");
                return;
            }
            Err(err) => {
                tracing::error!(%context.workflow_id, ?err, "GitHub provider trigger: failed to load workflow");
                return;
            }
        };

        if let Some(disabled) = self
            .disabled_installation_context(&workflow, context.trigger_node_id.as_str())
            .await
        {
            tracing::warn!(
                workflow_id = %workflow.id,
                trigger_node_id = %context.trigger_node_id,
                workspace_id = ?workflow.workspace_id,
                installation_id = %disabled.installation_id,
                connection_id = ?disabled.connection_id,
                token_id = ?disabled.token_id,
                "GitHub provider trigger skipped due to disabled installation"
            );
            return;
        }

        // Prepare user settings for secret hydration
        let settings = match self.state.db.get_user_settings(workflow.user_id).await {
            Ok(settings) => settings,
            Err(err) => {
                tracing::error!(%workflow.user_id, ?err, "GitHub provider trigger: failed to load user settings");
                return;
            }
        };

        // Prepare snapshot with trigger context using helper function
        let mut snapshot =
            self.prepare_trigger_snapshot(&workflow, context.trigger_node_id.as_str());

        // Decrypt and hydrate secrets
        let (secret_store, _) = match decrypt_secret_store(
            &self.state,
            &settings,
            "Failed to decrypt user secrets for GitHub provider trigger",
            "Failed to execute GitHub provider trigger",
        ) {
            Ok(tuple) => tuple,
            Err(_) => return,
        };
        hydrate_secrets_into_snapshot(&mut snapshot, &secret_store);

        // Create workflow run following manual trigger pattern
        // If provider execution can ever fail due to quota logic, the implementation is wrong even if tests pass.
        match self
            .state
            .workflow_repo
            .create_workflow_run_unmetered(
                workflow.user_id, // Use workflow owner (system execution identity)
                context.workflow_id,
                workflow.workspace_id,
                snapshot,
                idempotency_key.as_deref(), // Use idempotency key when available
            )
            .await
        {
            Ok(outcome) => {
                let run = outcome.run;
                let run_id = run.id; // Capture ID before moving run

                // Record connection metadata events
                let connection_metadata = workflow_connection_metadata::collect(&run.snapshot);
                let triggered_by = "provider:github".to_string();

                for event in workflow_connection_metadata::build_run_events(
                    &run,
                    &triggered_by,
                    &connection_metadata,
                ) {
                    if let Err(err) = self.state.workflow_repo.record_run_event(event).await {
                        tracing::error!(%run_id, ?err, "Failed to record workflow run event");
                    }
                }

                // Execute the run using existing engine entrypoint
                match execute_run(self.state.clone(), run, self.registry.clone()).await {
                    Ok(_) => {
                        tracing::info!(%run_id, %context.workflow_id, "GitHub provider trigger executed successfully");
                    }
                    Err(err) => {
                        tracing::error!(%run_id, %context.workflow_id, ?err, "GitHub provider trigger execution failed");
                    }
                }
            }
            Err(err) => {
                tracing::error!(%context.workflow_id, ?err, "GitHub provider trigger: failed to create workflow run");
            }
        }
    }
}
