use async_trait::async_trait;
use sqlx::PgPool;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::db::webhook_source_repository::WebhookSourceRepository;
use crate::models::webhook_source::WebhookSource;
use crate::utils::encryption::encrypt_secret;

pub struct PostgresWebhookSourceRepository {
    pub pool: PgPool,
    pub encryption_key: Vec<u8>,
}

#[async_trait]
impl WebhookSourceRepository for PostgresWebhookSourceRepository {
    async fn create_webhook_source_with_secret(
        &self,
        workspace_id: Uuid,
        name: &str,
        require_hmac: bool,
    ) -> Result<(WebhookSource, String), sqlx::Error> {
        let plaintext = Uuid::new_v4().to_string();
        let encrypted = encrypt_secret(&self.encryption_key, &plaintext)
            .map_err(|_| sqlx::Error::RowNotFound)?;

        let source = sqlx::query_as!(
            WebhookSource,
            r#"
            INSERT INTO webhook_sources (workspace_id, name, secret, require_hmac)
            VALUES ($1, $2, $3, $4)
            RETURNING id,
                      workspace_id,
                      name,
                      secret,
                      require_hmac,
                      replay_window_sec,
                      last_seen_at,
                      enabled,
                      created_at,
                      updated_at
            "#,
            workspace_id,
            name,
            encrypted,
            require_hmac
        )
        .fetch_one(&self.pool)
        .await?;

        Ok((source, plaintext))
    }

    async fn find_webhook_source_by_id(
        &self,
        source_id: Uuid,
    ) -> Result<Option<WebhookSource>, sqlx::Error> {
        sqlx::query_as!(
            WebhookSource,
            r#"
            SELECT id,
                   workspace_id,
                   name,
                   secret,
                   require_hmac,
                   replay_window_sec,
                   last_seen_at,
                   enabled,
                   created_at,
                   updated_at
            FROM webhook_sources
            WHERE id = $1
            "#,
            source_id
        )
        .fetch_optional(&self.pool)
        .await
    }

    async fn list_webhook_sources_by_workspace(
        &self,
        workspace_id: Uuid,
    ) -> Result<Vec<WebhookSource>, sqlx::Error> {
        sqlx::query_as!(
            WebhookSource,
            r#"
            SELECT id,
                   workspace_id,
                   name,
                   secret,
                   require_hmac,
                   replay_window_sec,
                   last_seen_at,
                   enabled,
                   created_at,
                   updated_at
            FROM webhook_sources
            WHERE workspace_id = $1
            ORDER BY created_at ASC
            "#,
            workspace_id
        )
        .fetch_all(&self.pool)
        .await
    }

    async fn update_webhook_source_last_seen(
        &self,
        source_id: Uuid,
        last_seen_at: OffsetDateTime,
    ) -> Result<(), sqlx::Error> {
        let result = sqlx::query!(
            r#"
            UPDATE webhook_sources
            SET last_seen_at = $2
            WHERE id = $1
            "#,
            source_id,
            last_seen_at
        )
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(sqlx::Error::RowNotFound);
        }

        Ok(())
    }

    async fn update_webhook_source_enabled(
        &self,
        workspace_id: Uuid,
        source_id: Uuid,
        enabled: bool,
    ) -> Result<WebhookSource, sqlx::Error> {
        sqlx::query_as!(
            WebhookSource,
            r#"
            UPDATE webhook_sources
            SET enabled = $3
            WHERE workspace_id = $1
              AND id = $2
            RETURNING id,
                      workspace_id,
                      name,
                      secret,
                      require_hmac,
                      replay_window_sec,
                      last_seen_at,
                      enabled,
                      created_at,
                      updated_at
            "#,
            workspace_id,
            source_id,
            enabled
        )
        .fetch_one(&self.pool)
        .await
    }

    async fn rotate_webhook_source_secret_with_secret(
        &self,
        workspace_id: Uuid,
        source_id: Uuid,
    ) -> Result<(WebhookSource, String), sqlx::Error> {
        let plaintext = Uuid::new_v4().to_string();
        let encrypted = encrypt_secret(&self.encryption_key, &plaintext)
            .map_err(|_| sqlx::Error::RowNotFound)?;

        let source = sqlx::query_as!(
            WebhookSource,
            r#"
            UPDATE webhook_sources
            SET secret = $3
            WHERE workspace_id = $1
              AND id = $2
            RETURNING id,
                      workspace_id,
                      name,
                      secret,
                      require_hmac,
                      replay_window_sec,
                      last_seen_at,
                      enabled,
                      created_at,
                      updated_at
            "#,
            workspace_id,
            source_id,
            encrypted
        )
        .fetch_one(&self.pool)
        .await?;

        Ok((source, plaintext))
    }

    async fn delete_webhook_source(
        &self,
        workspace_id: Uuid,
        source_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        let result = sqlx::query!(
            r#"
            DELETE FROM webhook_sources
            WHERE workspace_id = $1
              AND id = $2
            "#,
            workspace_id,
            source_id
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
    use crate::utils::encryption::EncryptionError;

    #[test]
    fn encrypt_secret_rejects_invalid_key() {
        let err = encrypt_secret(&[1, 2, 3], "nope");
        assert!(matches!(err, Err(EncryptionError::InvalidKeyLength)));
    }

    #[test]
    fn encrypt_secret_randomizes_ciphertext() {
        let key = vec![7u8; 32];
        let first = encrypt_secret(&key, "payload").expect("encrypt first");
        let second = encrypt_secret(&key, "payload").expect("encrypt second");
        assert_ne!(first, "payload");
        assert_ne!(second, "payload");
        assert_ne!(first, second);
    }
}
