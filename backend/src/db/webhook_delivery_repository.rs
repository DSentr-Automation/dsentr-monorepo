use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

#[async_trait]
pub trait WebhookDeliveryRepository: Send + Sync {
    #[allow(clippy::too_many_arguments)]
    async fn record_delivery(
        &self,
        delivery_id: Uuid,
        webhook_source_id: Uuid,
        subscription_id: Option<Uuid>,
        event_type: &str,
        received_at: OffsetDateTime,
        delivery_status: &str,
        error_message: Option<&str>,
    ) -> Result<(), sqlx::Error>;

    async fn update_delivery_status(
        &self,
        delivery_id: Uuid,
        delivery_status: &str,
        error_message: Option<&str>,
    ) -> Result<(), sqlx::Error>;
}
