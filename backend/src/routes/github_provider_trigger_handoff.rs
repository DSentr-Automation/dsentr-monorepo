use crate::routes::github_provider_trigger_dispatcher::ProviderTriggerDispatch;
use uuid::Uuid;

#[derive(Clone)]
pub struct ProviderTriggerHandoff {
    pub workflow_id: Uuid,
    pub trigger_node_id: String,
    pub delivery_id: Option<String>,
}

pub fn build_handoff(
    dispatches: Vec<ProviderTriggerDispatch>,
    delivery_id: Option<String>,
) -> Vec<ProviderTriggerHandoff> {
    dispatches
        .into_iter()
        .map(|d| ProviderTriggerHandoff {
            workflow_id: d.workflow_id,
            trigger_node_id: d.trigger_node_id,
            delivery_id: delivery_id.clone(), // Pass delivery_id to all dispatches
        })
        .collect()
}
