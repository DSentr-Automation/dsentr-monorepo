use async_trait::async_trait;
use sqlx::PgPool;
use time::OffsetDateTime;

use crate::db::provider_webhook_dedupe_repository::ProviderWebhookDedupeRepository;

#[allow(dead_code)]
pub struct PostgresProviderWebhookDedupeRepository {
    pub pool: PgPool,
}

#[async_trait]
impl ProviderWebhookDedupeRepository for PostgresProviderWebhookDedupeRepository {
    async fn insert_delivery(
        &self,
        provider: &str,
        delivery_id: &str,
        received_at: OffsetDateTime,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query!(
            r#"
            INSERT INTO provider_webhook_dedupe (provider, delivery_id, received_at)
            VALUES ($1, $2, $3)
            ON CONFLICT (provider, delivery_id) DO NOTHING
            "#,
            provider,
            delivery_id,
            received_at
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() == 1)
    }
}
