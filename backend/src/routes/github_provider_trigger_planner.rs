use crate::models::provider_trigger::ProviderTrigger;
use crate::routes::github_provider_trigger_resolver::ProviderTriggerMatch;
use std::collections::HashSet;

pub struct ProviderTriggerExecutionPlan {
    pub triggers: Vec<ProviderTrigger>,
}

pub fn build_execution_plan(matches: ProviderTriggerMatch) -> ProviderTriggerExecutionPlan {
    let mut seen_nodes = HashSet::new();
    let mut ordered_triggers = Vec::new();

    // Repository-level triggers first (preserving original order)
    for trigger in matches.repository_matches {
        if seen_nodes.insert(trigger.trigger_node_id) {
            ordered_triggers.push(trigger);
        }
        // If duplicate in installation matches, skip repo-level one
    }

    // Installation-level triggers second (preserving original order)
    for trigger in matches.installation_matches {
        // Only add if not already seen via repository match
        if seen_nodes.insert(trigger.trigger_node_id) {
            ordered_triggers.push(trigger);
        }
        // If duplicate in installation matches, skip installation-level one
    }

    ProviderTriggerExecutionPlan {
        triggers: ordered_triggers,
    }
}
