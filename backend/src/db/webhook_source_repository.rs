use async_trait::async_trait;
use uuid::Uuid;

use crate::models::webhook_source::WebhookSource;

#[async_trait]
pub trait WebhookSourceRepository: Send + Sync {
    async fn create_webhook_source_with_secret(
        &self,
        workspace_id: Uuid,
        name: &str,
        require_hmac: bool,
    ) -> Result<(WebhookSource, String), sqlx::Error>;

    async fn find_webhook_source_by_id(
        &self,
        source_id: Uuid,
    ) -> Result<Option<WebhookSource>, sqlx::Error>;

    async fn find_webhook_source_by_name(
        &self,
        name: &str,
    ) -> Result<Option<WebhookSource>, sqlx::Error>;

    async fn list_webhook_sources_by_workspace(
        &self,
        workspace_id: Uuid,
    ) -> Result<Vec<WebhookSource>, sqlx::Error>;

    async fn update_webhook_source_last_seen(
        &self,
        source_id: Uuid,
        last_seen_at: time::OffsetDateTime,
    ) -> Result<(), sqlx::Error>;

    // Enable/disable stays in the repo to enforce scoping and existence checks at the data boundary.
    // Routes must not duplicate these checks.
    async fn update_webhook_source_enabled(
        &self,
        workspace_id: Uuid,
        source_id: Uuid,
        enabled: bool,
    ) -> Result<WebhookSource, sqlx::Error>;

    async fn delete_webhook_source(
        &self,
        workspace_id: Uuid,
        source_id: Uuid,
    ) -> Result<(), sqlx::Error>;

    async fn rotate_webhook_source_secret_with_secret(
        &self,
        workspace_id: Uuid,
        source_id: Uuid,
    ) -> Result<(WebhookSource, String), sqlx::Error>;
}
