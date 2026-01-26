use std::collections::HashSet;
use std::sync::Arc;

use crate::db::provider_trigger_repository::ProviderTriggerRepository;
use crate::models::provider_trigger::{ProviderTrigger, ProviderTriggerProvider};
use tracing::debug;

#[derive(Clone)]
pub struct ProviderTriggerMatch {
    pub installation_matches: Vec<ProviderTrigger>,
    pub repository_matches: Vec<ProviderTrigger>,
}

pub struct GitHubProviderTriggerResolver {
    trigger_repo: Arc<dyn ProviderTriggerRepository>,
}

impl GitHubProviderTriggerResolver {
    pub fn new(trigger_repo: Arc<dyn ProviderTriggerRepository>) -> Self {
        Self { trigger_repo }
    }

    pub async fn resolve_triggers(
        &self,
        event_type: &str,
        installation_id: Option<&str>,
        repository_id: Option<&str>,
    ) -> Result<ProviderTriggerMatch, sqlx::Error> {
        let mut installation_matches = Vec::new();
        let mut repository_matches = Vec::new();

        // a. Lookup by installation_id if present
        if let Some(installation_id) = installation_id {
            installation_matches = self
                .trigger_repo
                .list_by_installation_event(
                    ProviderTriggerProvider::Github,
                    installation_id,
                    event_type,
                )
                .await?;
        }

        // b. Lookup by repository_id if present
        if let Some(repository_id) = repository_id {
            repository_matches = self
                .trigger_repo
                .list_by_repository_event(
                    ProviderTriggerProvider::Github,
                    repository_id,
                    event_type,
                )
                .await?;
        }

        let mut workflow_ids = HashSet::new();
        for trigger in installation_matches.iter().chain(repository_matches.iter()) {
            workflow_ids.insert(trigger.workflow_id);
        }
        let resolved_trigger_count = installation_matches.len() + repository_matches.len();
        debug!(
            provider = "github",
            event_type = event_type,
            installation_id_present = installation_id.is_some(),
            repository_id_present = repository_id.is_some(),
            resolved_trigger_count = resolved_trigger_count,
            resolved_workflow_count = workflow_ids.len(),
            "Resolved GitHub provider triggers"
        );

        Ok(ProviderTriggerMatch {
            installation_matches,
            repository_matches,
        })
    }
}
