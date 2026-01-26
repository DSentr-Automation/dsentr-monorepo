use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use crate::db::provider_trigger_repository::ProviderTriggerRepository;
use crate::models::provider_trigger::{
    CreateProviderTrigger, ProviderTrigger, ProviderTriggerProvider,
};

pub struct PostgresProviderTriggerRepository {
    pub pool: PgPool,
}

#[async_trait]
impl ProviderTriggerRepository for PostgresProviderTriggerRepository {
    async fn create_provider_trigger(
        &self,
        params: CreateProviderTrigger,
    ) -> Result<ProviderTrigger, sqlx::Error> {
        let result = sqlx::query_as!(
            ProviderTrigger,
            r#"
            INSERT INTO provider_triggers (
                workspace_id, provider, workflow_id, trigger_node_id, 
                event_type, installation_id, repository_id
            )
            VALUES ($1, $2::provider_trigger_provider, $3, $4, $5, $6, $7)
            ON CONFLICT (workspace_id, provider, workflow_id, trigger_node_id, event_type)
            DO UPDATE SET
                installation_id = EXCLUDED.installation_id,
                repository_id = EXCLUDED.repository_id,
                enabled = true
            RETURNING 
                id, workspace_id, provider as "provider: ProviderTriggerProvider", workflow_id, trigger_node_id,
                event_type, installation_id, repository_id, enabled,
                created_at, updated_at
            "#,
            params.workspace_id,
            params.provider as ProviderTriggerProvider,
            params.workflow_id,
            params.trigger_node_id,
            params.event_type,
            params.installation_id,
            params.repository_id
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    async fn list_by_workflow_id(
        &self,
        workspace_id: Option<Uuid>,
        workflow_id: Uuid,
    ) -> Result<Vec<ProviderTrigger>, sqlx::Error> {
        let triggers = sqlx::query_as!(
            ProviderTrigger,
            r#"
            SELECT 
                id, workspace_id, provider as "provider: ProviderTriggerProvider", workflow_id, trigger_node_id,
                event_type, installation_id, repository_id, enabled,
                created_at, updated_at
            FROM provider_triggers
            WHERE workflow_id = $2
            AND ($1::uuid IS NULL OR workspace_id = $1)
            ORDER BY created_at DESC
            "#,
            workspace_id,
            workflow_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(triggers)
    }

    async fn list_by_installation_event(
        &self,
        provider: ProviderTriggerProvider,
        installation_id: &str,
        event_type: &str,
    ) -> Result<Vec<ProviderTrigger>, sqlx::Error> {
        let triggers = sqlx::query_as!(
            ProviderTrigger,
            r#"
            SELECT 
                id, workspace_id, provider as "provider: ProviderTriggerProvider", workflow_id, trigger_node_id,
                event_type, installation_id, repository_id, enabled,
                created_at, updated_at
            FROM provider_triggers
            WHERE provider = $1::provider_trigger_provider
            AND installation_id = $2
            AND event_type = $3
            AND enabled = true
            ORDER BY created_at DESC
            "#,
            provider as ProviderTriggerProvider,
            installation_id,
            event_type
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(triggers)
    }

    async fn list_by_repository_event(
        &self,
        provider: ProviderTriggerProvider,
        repository_id: &str,
        event_type: &str,
    ) -> Result<Vec<ProviderTrigger>, sqlx::Error> {
        let triggers = sqlx::query_as!(
            ProviderTrigger,
            r#"
            SELECT 
                id, workspace_id, provider as "provider: ProviderTriggerProvider", workflow_id, trigger_node_id,
                event_type, installation_id, repository_id, enabled,
                created_at, updated_at
            FROM provider_triggers
            WHERE provider = $1::provider_trigger_provider
            AND repository_id = $2
            AND event_type = $3
            AND enabled = true
            ORDER BY created_at DESC
            "#,
            provider as ProviderTriggerProvider,
            repository_id,
            event_type
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(triggers)
    }

    async fn delete_by_workflow_id(
        &self,
        workspace_id: Option<Uuid>,
        workflow_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query!(
            r#"
            DELETE FROM provider_triggers
            WHERE workflow_id = $2
            AND ($1::uuid IS NULL OR workspace_id = $1)
            "#,
            workspace_id,
            workflow_id
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    async fn delete_by_workflow_node_id(
        &self,
        workspace_id: Option<Uuid>,
        workflow_id: Uuid,
        trigger_node_id: &str,
    ) -> Result<u64, sqlx::Error> {
        let result = sqlx::query!(
            r#"
            DELETE FROM provider_triggers
            WHERE workflow_id = $2
            AND trigger_node_id = $3
            AND ($1::uuid IS NULL OR workspace_id = $1)
            "#,
            workspace_id,
            workflow_id,
            trigger_node_id
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    async fn update_enabled(
        &self,
        workspace_id: Option<Uuid>,
        id: Uuid,
        enabled: bool,
    ) -> Result<ProviderTrigger, sqlx::Error> {
        let result = sqlx::query_as!(
            ProviderTrigger,
            r#"
            UPDATE provider_triggers
            SET enabled = $3
            WHERE id = $2
            AND ($1::uuid IS NULL OR workspace_id = $1)
            RETURNING 
                id, workspace_id, provider as "provider: ProviderTriggerProvider", workflow_id, trigger_node_id,
                event_type, installation_id, repository_id, enabled,
                created_at, updated_at
            "#,
            workspace_id,
            id,
            enabled
        )
        .fetch_optional(&self.pool)
        .await?;

        match result {
            Some(trigger) => Ok(trigger),
            None => Err(sqlx::Error::RowNotFound),
        }
    }

    async fn delete(&self, workspace_id: Option<Uuid>, id: Uuid) -> Result<(), sqlx::Error> {
        let result = sqlx::query!(
            "DELETE FROM provider_triggers WHERE id = $2 AND ($1::uuid IS NULL OR workspace_id = $1)",
            workspace_id,
            id
        )
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(sqlx::Error::RowNotFound);
        }

        Ok(())
    }

    async fn find_by_id(
        &self,
        workspace_id: Option<Uuid>,
        id: Uuid,
    ) -> Result<Option<ProviderTrigger>, sqlx::Error> {
        let trigger = sqlx::query_as!(
            ProviderTrigger,
            r#"
            SELECT 
                id, workspace_id, provider as "provider: ProviderTriggerProvider", workflow_id, trigger_node_id,
                event_type, installation_id, repository_id, enabled,
                created_at, updated_at
            FROM provider_triggers
            WHERE id = $2
            AND ($1::uuid IS NULL OR workspace_id = $1)
            "#,
            workspace_id,
            id
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(trigger)
    }
}
