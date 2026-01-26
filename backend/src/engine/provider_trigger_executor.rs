use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;

use crate::engine::actions::registry::ActionRegistry;
use crate::engine::{build_action_registry, execute_run};
use crate::models::workflow::Workflow;
use crate::routes::github_provider_trigger_engine_bridge::ProviderTriggerExecutor;
use crate::routes::github_provider_trigger_execution_context::ProviderTriggerExecutionContext;
use crate::routes::options::secrets::decrypt_secret_store;
use crate::state::AppState;
use crate::utils::egress_allowlist::normalize_egress_allowlist;
use crate::utils::secrets::hydrate_secrets_into_snapshot;
use crate::utils::workflow_connection_metadata;

#[allow(dead_code)]
pub struct GitHubProviderTriggerExecutor {
    state: AppState,
    registry: Arc<ActionRegistry>,
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

        // Prepare user settings for secret hydration
        let settings = match self.state.db.get_user_settings(workflow.user_id).await {
            Ok(settings) => settings,
            Err(err) => {
                tracing::error!(%workflow.user_id, ?err, "GitHub provider trigger: failed to load user settings");
                return;
            }
        };

        // Prepare snapshot with trigger context using helper function
        let mut snapshot = self.prepare_trigger_snapshot(&workflow, context.trigger_node_id.as_str());

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
