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
    async fn create_webhook_source(
        &self,
        workspace_id: Uuid,
        name: &str,
    ) -> Result<WebhookSource, sqlx::Error> {
        let plaintext = Uuid::new_v4().to_string();
        let encrypted = encrypt_secret(&self.encryption_key, &plaintext)
            .map_err(|_| sqlx::Error::RowNotFound)?;

        sqlx::query_as!(
            WebhookSource,
            r#"
            INSERT INTO webhook_sources (workspace_id, name, secret)
            VALUES ($1, $2, $3)
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
            encrypted
        )
        .fetch_one(&self.pool)
        .await
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

    async fn rotate_webhook_source_secret(
        &self,
        workspace_id: Uuid,
        source_id: Uuid,
    ) -> Result<WebhookSource, sqlx::Error> {
        let plaintext = Uuid::new_v4().to_string();
        let encrypted = encrypt_secret(&self.encryption_key, &plaintext)
            .map_err(|_| sqlx::Error::RowNotFound)?;

        sqlx::query_as!(
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
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::test_pg_pool;
    use crate::utils::encryption::EncryptionError;
    use sqlx::Row;
    use time::OffsetDateTime;

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
        .bind(format!("webhook-{}@example.com", Uuid::new_v4()))
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

    #[tokio::test]
    #[ignore]
    async fn webhook_source_secret_encrypted_and_workspace_scoped() {
        let pool = test_pg_pool();
        let user_id = insert_user(&pool).await;
        let workspace_id = insert_workspace(&pool, user_id).await;
        let other_workspace_id = insert_workspace(&pool, user_id).await;

        let repo = PostgresWebhookSourceRepository {
            pool: (*pool).clone(),
            encryption_key: vec![9u8; 32],
        };

        let created = repo
            .create_webhook_source(workspace_id, "Inbound")
            .await
            .expect("create webhook source");

        let stored_secret = sqlx::query_scalar!(
            r#"
            SELECT secret
            FROM webhook_sources
            WHERE id = $1
            "#,
            created.id
        )
        .fetch_one(&*pool)
        .await
        .expect("fetch secret");

        assert_eq!(stored_secret, created.secret);
        assert_ne!(stored_secret.len(), 36);
        assert!(Uuid::parse_str(&stored_secret).is_err());

        let err = repo
            .delete_webhook_source(other_workspace_id, created.id)
            .await
            .expect_err("cross-workspace delete should fail");
        assert!(matches!(err, sqlx::Error::RowNotFound));

        repo.delete_webhook_source(workspace_id, created.id)
            .await
            .expect("delete source");
    }
}
