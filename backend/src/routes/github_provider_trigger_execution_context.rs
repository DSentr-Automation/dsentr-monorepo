use anyhow::Error;
use uuid::Uuid;

use crate::db::workflow_repository::WorkflowRepository;
use crate::routes::github_provider_trigger_handoff::ProviderTriggerHandoff;

#[allow(dead_code)]
pub struct ProviderTriggerExecutionContext {
    pub workflow_id: Uuid,
    pub trigger_node_id: Uuid,
    pub workspace_id: Option<Uuid>,
    pub delivery_id: Option<String>,
    pub execution_identity: ProviderExecutionIdentity,
}

#[allow(dead_code)]
pub enum ProviderExecutionIdentity {
    System,
}

pub async fn resolve_execution_contexts(
    handoffs: Vec<ProviderTriggerHandoff>,
    workflow_repo: &dyn WorkflowRepository,
) -> Result<Vec<ProviderTriggerExecutionContext>, Error> {
    let mut contexts = Vec::with_capacity(handoffs.len());

    for handoff in handoffs {
        // Explicitly preserve ordering by processing sequentially
        let workflow = workflow_repo
            .find_workflow_by_id_public(handoff.workflow_id)
            .await
            .map_err(|e| {
                anyhow::anyhow!("Failed to lookup workflow {}: {}", handoff.workflow_id, e)
            })?
            .ok_or_else(|| anyhow::anyhow!("Workflow {} not found", handoff.workflow_id))?;

        let context = ProviderTriggerExecutionContext {
            workflow_id: handoff.workflow_id,
            trigger_node_id: handoff.trigger_node_id,
            workspace_id: workflow.workspace_id,
            delivery_id: handoff.delivery_id.clone(),
            execution_identity: ProviderExecutionIdentity::System,
        };

        contexts.push(context);
    }

    Ok(contexts)
}
