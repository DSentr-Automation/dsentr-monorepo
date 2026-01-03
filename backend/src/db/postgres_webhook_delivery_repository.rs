use async_trait::async_trait;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::db::webhook_delivery_repository::WebhookDeliveryRepository;

pub struct PostgresWebhookDeliveryRepository {
    pub pool: PgPool,
}

#[async_trait]
impl WebhookDeliveryRepository for PostgresWebhookDeliveryRepository {
    async fn record_delivery(
        &self,
        delivery_id: Uuid,
        webhook_source_id: Uuid,
        subscription_id: Option<Uuid>,
        event_type: &str,
        received_at: OffsetDateTime,
        delivery_status: &str,
        error_message: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            INSERT INTO webhook_deliveries (
                id,
                webhook_source_id,
                subscription_id,
                event_type,
                received_at,
                delivery_status,
                error_message
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
            delivery_id,
            webhook_source_id,
            subscription_id,
            event_type,
            received_at,
            delivery_status,
            error_message
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn update_delivery_status(
        &self,
        delivery_id: Uuid,
        delivery_status: &str,
        error_message: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        let result = sqlx::query!(
            r#"
            UPDATE webhook_deliveries
            SET delivery_status = $2,
                error_message = $3
            WHERE id = $1
            "#,
            delivery_id,
            delivery_status,
            error_message
        )
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(sqlx::Error::RowNotFound);
        }

        Ok(())
    }
}
