use async_trait::async_trait;
use uuid::Uuid;

use crate::models::webhook_subscription::WebhookSubscription;

#[async_trait]
pub trait WebhookSubscriptionRepository: Send + Sync {
    async fn create_subscription(
        &self,
        webhook_source_id: Uuid,
        workflow_id: Uuid,
        trigger_node_id: Uuid,
        event_type: &str,
    ) -> Result<WebhookSubscription, sqlx::Error>;

    async fn list_subscriptions_by_source(
        &self,
        webhook_source_id: Uuid,
    ) -> Result<Vec<WebhookSubscription>, sqlx::Error>;

    async fn list_subscriptions_by_source_event(
        &self,
        webhook_source_id: Uuid,
        event_type: &str,
    ) -> Result<Vec<WebhookSubscription>, sqlx::Error>;

    // Enable/disable stays in the repo to enforce scoping and existence checks at the data boundary.
    // Routes must not duplicate these checks.
    async fn update_subscription_enabled(
        &self,
        webhook_source_id: Uuid,
        subscription_id: Uuid,
        enabled: bool,
    ) -> Result<WebhookSubscription, sqlx::Error>;

    async fn delete_subscription(
        &self,
        webhook_source_id: Uuid,
        subscription_id: Uuid,
    ) -> Result<(), sqlx::Error>;
}
