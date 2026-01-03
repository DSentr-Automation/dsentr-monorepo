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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::postgres_webhook_source_repository::PostgresWebhookSourceRepository;
    use crate::db::webhook_source_repository::WebhookSourceRepository;
    use crate::db::webhook_subscription_repository::WebhookSubscriptionRepository;
    use crate::state::test_pg_pool;
    use sqlx::Row;
    use time::OffsetDateTime;

    async fn insert_user(pool: &PgPool) -> Uuid {
        let row = sqlx::query(
            r#"
            INSERT INTO users (
                email,
                password_hash,
                first_name,
                last_name,
                oauth_provider,
                is_verified,
                role,
                created_at
            )
            VALUES ($1, '', $2, $3, $4::oauth_provider, true, 'user'::user_role, $5)
            RETURNING id
            "#,
        )
        .bind(format!(
            "webhook-subscription-{}@example.com",
            Uuid::new_v4()
        ))
        .bind("Webhook")
        .bind("Tester")
        .bind("google")
        .bind(OffsetDateTime::now_utc())
        .fetch_one(pool)
        .await
        .expect("insert user");

        row.get("id")
    }

    async fn insert_workspace(pool: &PgPool, owner_id: Uuid) -> Uuid {
        let now = OffsetDateTime::now_utc();
        let row = sqlx::query(
            r#"
            INSERT INTO workspaces (
                name,
                created_by,
                owner_id,
                plan,
                created_at,
                updated_at
            )
            VALUES ($1, $2, $3, 'workspace', $4, $4)
            RETURNING id
            "#,
        )
        .bind(format!("Webhook Workspace {}", Uuid::new_v4()))
        .bind(owner_id)
        .bind(owner_id)
        .bind(now)
        .fetch_one(pool)
        .await
        .expect("insert workspace");

        row.get("id")
    }

    async fn insert_workflow(pool: &PgPool, user_id: Uuid, workspace_id: Uuid) -> Uuid {
        let now = OffsetDateTime::now_utc();
        let row = sqlx::query(
            r#"
            INSERT INTO workflows (
                user_id,
                workspace_id,
                name,
                description,
                data,
                created_at,
                updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $6)
            RETURNING id
            "#,
        )
        .bind(user_id)
        .bind(workspace_id)
        .bind(format!("Webhook Workflow {}", Uuid::new_v4()))
        .bind(Some("Webhook workflow".to_string()))
        .bind(serde_json::json!({}))
        .bind(now)
        .fetch_one(pool)
        .await
        .expect("insert workflow");

        row.get("id")
    }

    #[tokio::test]
    #[ignore]
    async fn webhook_subscription_unique_per_source_workflow_trigger_event() {
        let pool = test_pg_pool();
        let user_id = insert_user(&pool).await;
        let workspace_id = insert_workspace(&pool, user_id).await;
        let workflow_id = insert_workflow(&pool, user_id, workspace_id).await;

        let source_repo = PostgresWebhookSourceRepository {
            pool: (*pool).clone(),
            encryption_key: vec![9u8; 32],
        };

        let source = source_repo
            .create_webhook_source(workspace_id, "Inbound")
            .await
            .expect("create webhook source");

        let repo = PostgresWebhookSubscriptionRepository {
            pool: (*pool).clone(),
        };

        let trigger_node_id = Uuid::new_v4();

        repo.create_subscription(source.id, workflow_id, trigger_node_id, "invoice.created")
            .await
            .expect("create subscription");

        let err = repo
            .create_subscription(source.id, workflow_id, trigger_node_id, "invoice.created")
            .await
            .expect_err("duplicate subscription should fail");

        assert!(matches!(err, sqlx::Error::Database(_)));
    }

    #[tokio::test]
    #[ignore]
    async fn webhook_subscription_delete_enforces_source_scope() {
        let pool = test_pg_pool();
        let user_id = insert_user(&pool).await;
        let workspace_id = insert_workspace(&pool, user_id).await;
        let workflow_id = insert_workflow(&pool, user_id, workspace_id).await;

        let source_repo = PostgresWebhookSourceRepository {
            pool: (*pool).clone(),
            encryption_key: vec![9u8; 32],
        };

        let source = source_repo
            .create_webhook_source(workspace_id, "Inbound")
            .await
            .expect("create webhook source");
        let other_source = source_repo
            .create_webhook_source(workspace_id, "Inbound-2")
            .await
            .expect("create webhook source");

        let repo = PostgresWebhookSubscriptionRepository {
            pool: (*pool).clone(),
        };

        let subscription = repo
            .create_subscription(source.id, workflow_id, Uuid::new_v4(), "invoice.created")
            .await
            .expect("create subscription");

        let err = repo
            .delete_subscription(other_source.id, subscription.id)
            .await
            .expect_err("cross-source delete should fail");

        assert!(matches!(err, sqlx::Error::RowNotFound));

        let remaining = repo
            .list_subscriptions_by_source(source.id)
            .await
            .expect("list subscriptions");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, subscription.id);

        repo.delete_subscription(source.id, subscription.id)
            .await
            .expect("delete subscription");
    }
}
