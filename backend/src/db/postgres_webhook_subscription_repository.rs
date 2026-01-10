use async_trait::async_trait;
use sqlx::PgPool;
use uuid::Uuid;

use crate::db::webhook_subscription_repository::WebhookSubscriptionRepository;
use crate::models::webhook_subscription::WebhookSubscription;

pub struct PostgresWebhookSubscriptionRepository {
    pub pool: PgPool,
}

#[async_trait]
impl WebhookSubscriptionRepository for PostgresWebhookSubscriptionRepository {
    async fn create_subscription(
        &self,
        webhook_source_id: Uuid,
        workflow_id: Uuid,
        trigger_node_id: Uuid,
        event_type: &str,
    ) -> Result<WebhookSubscription, sqlx::Error> {
        sqlx::query_as!(
            WebhookSubscription,
            r#"
            INSERT INTO webhook_subscriptions (
                webhook_source_id,
                workflow_id,
                trigger_node_id,
                event_type
            )
            VALUES ($1, $2, $3, $4)
            RETURNING id,
                      webhook_source_id,
                      workflow_id,
                      trigger_node_id,
                      event_type,
                      enabled,
                      created_at,
                      updated_at
            "#,
            webhook_source_id,
            workflow_id,
            trigger_node_id,
            event_type
        )
        .fetch_one(&self.pool)
        .await
    }

    async fn list_subscriptions_by_source(
        &self,
        webhook_source_id: Uuid,
    ) -> Result<Vec<WebhookSubscription>, sqlx::Error> {
        sqlx::query_as!(
            WebhookSubscription,
            r#"
            SELECT id,
                   webhook_source_id,
                   workflow_id,
                   trigger_node_id,
                   event_type,
                   enabled,
                   created_at,
                   updated_at
            FROM webhook_subscriptions
            WHERE webhook_source_id = $1
            ORDER BY created_at ASC
            "#,
            webhook_source_id
        )
        .fetch_all(&self.pool)
        .await
    }

    async fn list_subscriptions_by_source_event(
        &self,
        webhook_source_id: Uuid,
        event_type: &str,
    ) -> Result<Vec<WebhookSubscription>, sqlx::Error> {
        sqlx::query_as!(
            WebhookSubscription,
            r#"
            SELECT id,
                   webhook_source_id,
                   workflow_id,
                   trigger_node_id,
                   event_type,
                   enabled,
                   created_at,
                   updated_at
            FROM webhook_subscriptions
            WHERE webhook_source_id = $1
              AND event_type = $2
              AND enabled = true
            ORDER BY created_at ASC
            "#,
            webhook_source_id,
            event_type
        )
        .fetch_all(&self.pool)
        .await
    }

    async fn update_subscription_enabled(
        &self,
        webhook_source_id: Uuid,
        subscription_id: Uuid,
        enabled: bool,
    ) -> Result<WebhookSubscription, sqlx::Error> {
        sqlx::query_as!(
            WebhookSubscription,
            r#"
            UPDATE webhook_subscriptions
            SET enabled = $3
            WHERE webhook_source_id = $1
              AND id = $2
            RETURNING id,
                      webhook_source_id,
                      workflow_id,
                      trigger_node_id,
                      event_type,
                      enabled,
                      created_at,
                      updated_at
            "#,
            webhook_source_id,
            subscription_id,
            enabled
        )
        .fetch_one(&self.pool)
        .await
    }

    async fn delete_subscription(
        &self,
        webhook_source_id: Uuid,
        subscription_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        let result = sqlx::query!(
            r#"
            DELETE FROM webhook_subscriptions
            WHERE webhook_source_id = $1
              AND id = $2
            "#,
            webhook_source_id,
            subscription_id
        )
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(sqlx::Error::RowNotFound);
        }

        Ok(())
    }
}
