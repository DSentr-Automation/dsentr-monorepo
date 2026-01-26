use crate::routes::github_provider_trigger_planner::ProviderTriggerExecutionPlan;
use uuid::Uuid;

pub struct ProviderTriggerDispatch {
    pub trigger_node_id: String,
    pub workflow_id: Uuid,
}

pub fn build_dispatch_list(plan: ProviderTriggerExecutionPlan) -> Vec<ProviderTriggerDispatch> {
    plan.triggers
        .into_iter()
        .map(|trigger| ProviderTriggerDispatch {
            trigger_node_id: trigger.trigger_node_id,
            workflow_id: trigger.workflow_id,
        })
        .collect()
}
