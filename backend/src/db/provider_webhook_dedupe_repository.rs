use async_trait::async_trait;
use time::OffsetDateTime;

#[allow(dead_code)]
#[async_trait]
pub trait ProviderWebhookDedupeRepository: Send + Sync {
    async fn insert_delivery(
        &self,
        provider: &str,
        delivery_id: &str,
        received_at: OffsetDateTime,
    ) -> Result<bool, sqlx::Error>;
}
