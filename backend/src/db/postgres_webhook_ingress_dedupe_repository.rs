use async_trait::async_trait;
use sqlx::PgPool;

use crate::db::webhook_ingress_dedupe_repository::{
    WebhookIngressDedupeKey, WebhookIngressDedupeRepository,
};

pub struct PostgresWebhookIngressDedupeRepository {
    pub pool: PgPool,
}

#[async_trait]
impl WebhookIngressDedupeRepository for PostgresWebhookIngressDedupeRepository {
    async fn insert_dedupe_key(&self, key: &WebhookIngressDedupeKey) -> Result<bool, sqlx::Error> {
        let result = sqlx::query!(
            r#"
            INSERT INTO webhook_ingress_dedupe (
                source_id,
                event_type,
                payload_sha256,
                signature,
                timestamp_floor
            )
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT DO NOTHING
            "#,
            key.source_id,
            key.event_type,
            &key.payload_sha256,
            key.signature,
            key.timestamp_floor
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() == 1)
    }

    async fn purge_old_dedupe_entries(&self) -> Result<u64, sqlx::Error> {
        let result = sqlx::query!(
            r#"
            DELETE FROM webhook_ingress_dedupe AS dedupe
            USING webhook_sources AS sources
            WHERE dedupe.source_id = sources.id
              AND dedupe.timestamp_floor < (
                now() - make_interval(secs => GREATEST(sources.replay_window_sec, 86400))
              )
            "#
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }
}
