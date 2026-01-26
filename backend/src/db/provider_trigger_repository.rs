use async_trait::async_trait;
use uuid::Uuid;

use crate::models::provider_trigger::{ProviderTrigger, ProviderTriggerProvider};

#[async_trait]
#[allow(dead_code)]
pub trait ProviderTriggerRepository: Send + Sync {
    async fn create_provider_trigger(
        &self,
        params: crate::models::provider_trigger::CreateProviderTrigger,
    ) -> Result<ProviderTrigger, sqlx::Error>;

    async fn list_by_workflow_id(
        &self,
        workspace_id: Option<Uuid>,
        workflow_id: Uuid,
    ) -> Result<Vec<ProviderTrigger>, sqlx::Error>;

    async fn list_by_installation_event(
        &self,
        provider: ProviderTriggerProvider,
        installation_id: &str,
        event_type: &str,
    ) -> Result<Vec<ProviderTrigger>, sqlx::Error>;

    async fn list_by_repository_event(
        &self,
        provider: ProviderTriggerProvider,
        repository_id: &str,
        event_type: &str,
    ) -> Result<Vec<ProviderTrigger>, sqlx::Error>;

    async fn delete_by_workflow_id(
        &self,
        workspace_id: Option<Uuid>,
        workflow_id: Uuid,
    ) -> Result<u64, sqlx::Error>;

    async fn delete_by_workflow_node_id(
        &self,
        workspace_id: Option<Uuid>,
        workflow_id: Uuid,
        trigger_node_id: &str,
    ) -> Result<u64, sqlx::Error>;

    // Enable/disable stays in the repo to enforce scoping and existence checks at the data boundary.
    // Routes must not duplicate these checks.
    async fn update_enabled(
        &self,
        workspace_id: Option<Uuid>,
        id: Uuid,
        enabled: bool,
    ) -> Result<ProviderTrigger, sqlx::Error>;

    async fn delete(&self, workspace_id: Option<Uuid>, id: Uuid) -> Result<(), sqlx::Error>;

    async fn find_by_id(
        &self,
        workspace_id: Option<Uuid>,
        id: Uuid,
    ) -> Result<Option<ProviderTrigger>, sqlx::Error>;
}
