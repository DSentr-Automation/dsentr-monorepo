use async_trait::async_trait;
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::db::workspace_connection_repository::{
    NewWorkspaceAuditEvent, NewWorkspaceConnection, StaleWorkspaceConnection,
    WorkspaceConnectionListing, WorkspaceConnectionRepository,
};
use crate::models::oauth_token::{
    ConnectedOAuthProvider, WorkspaceAuditEvent, WorkspaceConnection,
};

pub struct PostgresWorkspaceConnectionRepository {
    pub pool: PgPool,
}

struct WorkspaceConnectionIdentity {
    provider: ConnectedOAuthProvider,
    owner_user_id: Uuid,
    user_oauth_token_id: Option<Uuid>,
}

fn require_slack_team_id(
    provider: ConnectedOAuthProvider,
    slack_team_id: &Option<String>,
) -> Result<(), sqlx::Error> {
    if matches!(provider, ConnectedOAuthProvider::Slack) {
        let team_id = slack_team_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if team_id.is_none() {
            return Err(sqlx::Error::Protocol(
                "Slack workspace connection requires slack_team_id".to_string(),
            ));
        }
        if team_id.unwrap().len() > 32 {
            return Err(sqlx::Error::Protocol(
                "Slack workspace team id is too long".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_slack_team_id_value(
    provider: ConnectedOAuthProvider,
    slack_team_id: &Option<String>,
) -> Result<(), sqlx::Error> {
    if matches!(provider, ConnectedOAuthProvider::Slack) {
        if let Some(team_id) = slack_team_id.as_deref() {
            if team_id.trim().is_empty() {
                return Err(sqlx::Error::Protocol(
                    "Slack workspace team id cannot be empty".to_string(),
                ));
            }
            if team_id.trim().len() > 32 {
                return Err(sqlx::Error::Protocol(
                    "Slack workspace team id is too long".to_string(),
                ));
            }
        }
    }
    Ok(())
}

#[async_trait]
impl WorkspaceConnectionRepository for PostgresWorkspaceConnectionRepository {
    async fn insert_connection(
        &self,
        new_connection: NewWorkspaceConnection,
    ) -> Result<WorkspaceConnection, sqlx::Error> {
        require_slack_team_id(new_connection.provider, &new_connection.slack_team_id)?;
        sqlx::query_as!(
            WorkspaceConnection,
            r#"
            INSERT INTO workspace_connections (
                workspace_id,
                created_by,
                owner_user_id,
                user_oauth_token_id,
                connection_id,
                provider,
                access_token,
                refresh_token,
                expires_at,
                account_email,
                updated_at,
                bot_user_id,
                slack_team_id,
                incoming_webhook_url,
                metadata
            )
            VALUES ($1, $2, $3, $4, $5, $6::oauth_connection_provider, $7, $8, $9, $10, now(), $11, $12, $13, $14)
            RETURNING
                id,
                connection_id as "connection_id?",
                workspace_id,
                created_by,
                owner_user_id,
                user_oauth_token_id as "user_oauth_token_id?",
                provider as "provider: _",
                access_token,
                refresh_token,
                expires_at,
                account_email,
                created_at,
                updated_at,
                bot_user_id,
                slack_team_id,
                incoming_webhook_url,
                metadata
            "#,
            new_connection.workspace_id,
            new_connection.created_by,
            new_connection.owner_user_id,
            new_connection.user_oauth_token_id,
            new_connection.connection_id,
            new_connection.provider as ConnectedOAuthProvider,
            new_connection.access_token,
            new_connection.refresh_token,
            new_connection.expires_at,
            new_connection.account_email,
            new_connection.bot_user_id,
            new_connection.slack_team_id,
            new_connection.incoming_webhook_url,
            new_connection.metadata,
        )
        .fetch_one(&self.pool)
        .await
    }

    async fn find_by_id(
        &self,
        connection_id: Uuid,
    ) -> Result<Option<WorkspaceConnection>, sqlx::Error> {
        sqlx::query_as!(
            WorkspaceConnection,
            r#"
            SELECT
                id,
                connection_id as "connection_id?",
                workspace_id,
                created_by,
                owner_user_id,
                user_oauth_token_id as "user_oauth_token_id?",
                provider as "provider: _",
                access_token,
                refresh_token,
                expires_at,
                account_email,
                created_at,
                updated_at,
                bot_user_id,
                slack_team_id,
                incoming_webhook_url,
                metadata
            FROM workspace_connections
            WHERE id = $1
            "#,
            connection_id,
        )
        .fetch_optional(&self.pool)
        .await
    }

    async fn get_by_id(&self, connection_id: Uuid) -> Result<WorkspaceConnection, sqlx::Error> {
        self.find_by_id(connection_id)
            .await?
            .ok_or(sqlx::Error::RowNotFound)
    }

    async fn list_for_workspace_provider(
        &self,
        workspace_id: Uuid,
        provider: ConnectedOAuthProvider,
    ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
        sqlx::query_as!(
            WorkspaceConnection,
            r#"
            SELECT
                id,
                connection_id as "connection_id?",
                workspace_id,
                created_by,
                owner_user_id,
                user_oauth_token_id as "user_oauth_token_id?",
                provider as "provider: _",
                access_token,
                refresh_token,
                expires_at,
                account_email,
                created_at,
                updated_at,
                bot_user_id,
                slack_team_id,
                incoming_webhook_url,
                metadata
            FROM workspace_connections
            WHERE workspace_id = $1
              AND provider = $2::oauth_connection_provider
            ORDER BY created_at ASC
            "#,
            workspace_id,
            provider as ConnectedOAuthProvider,
        )
        .fetch_all(&self.pool)
        .await
    }

    async fn list_by_workspace_and_provider(
        &self,
        workspace_id: Uuid,
        provider: ConnectedOAuthProvider,
    ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
        self.list_for_workspace_provider(workspace_id, provider)
            .await
    }

    async fn find_slack_by_workspace_and_team(
        &self,
        workspace_id: Uuid,
        slack_team_id: &str,
    ) -> Result<Option<WorkspaceConnection>, sqlx::Error> {
        let team_id = slack_team_id.trim();
        if team_id.is_empty() {
            return Err(sqlx::Error::Protocol(
                "Slack workspace team id cannot be empty".to_string(),
            ));
        }
        if team_id.len() > 32 {
            return Err(sqlx::Error::Protocol(
                "Slack workspace team id is too long".to_string(),
            ));
        }

        sqlx::query_as!(
            WorkspaceConnection,
            r#"
            SELECT
                id,
                connection_id as "connection_id?",
                workspace_id,
                created_by,
                owner_user_id,
                user_oauth_token_id as "user_oauth_token_id?",
                provider as "provider: _",
                access_token,
                refresh_token,
                expires_at,
                account_email,
                created_at,
                updated_at,
                bot_user_id,
                slack_team_id,
                incoming_webhook_url,
                metadata
            FROM workspace_connections
            WHERE workspace_id = $1
              AND provider = 'slack'::oauth_connection_provider
              AND slack_team_id = $2
            "#,
            workspace_id,
            team_id,
        )
        .fetch_optional(&self.pool)
        .await
    }

    async fn find_by_source_token(
        &self,
        user_oauth_token_id: Uuid,
    ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
        sqlx::query_as!(
            WorkspaceConnection,
            r#"
            SELECT
                id,
                connection_id as "connection_id?",
                workspace_id,
                created_by,
                owner_user_id,
                user_oauth_token_id as "user_oauth_token_id?",
                provider as "provider: _",
                access_token,
                refresh_token,
                expires_at,
                account_email,
                created_at,
                updated_at,
                bot_user_id,
                slack_team_id,
                incoming_webhook_url,
                metadata
            FROM workspace_connections
            WHERE user_oauth_token_id = $1
            ORDER BY created_at ASC
            "#,
            user_oauth_token_id,
        )
        .fetch_all(&self.pool)
        .await
    }

    async fn list_for_workspace(
        &self,
        workspace_id: Uuid,
    ) -> Result<Vec<WorkspaceConnectionListing>, sqlx::Error> {
        sqlx::query_as::<_, WorkspaceConnectionListing>(
            r#"
            SELECT
                wc.id,
                wc.connection_id,
                wc.workspace_id,
                wc.owner_user_id,
                w.name AS workspace_name,
                wc.provider,
                wc.account_email,
                wc.expires_at,
                owner.first_name AS shared_by_first_name,
                owner.last_name AS shared_by_last_name,
                owner.email AS shared_by_email,
                wc.updated_at,
                (owner_token.id IS NULL) AS requires_reconnect,
                (wc.incoming_webhook_url IS NOT NULL) AS has_incoming_webhook
            FROM workspace_connections wc
            JOIN workspaces w ON w.id = wc.workspace_id
            LEFT JOIN users owner ON owner.id = wc.owner_user_id
            LEFT JOIN user_oauth_tokens owner_token
                ON owner_token.id = wc.user_oauth_token_id
            WHERE wc.workspace_id = $1
            ORDER BY wc.created_at ASC
            "#,
        )
        .bind(workspace_id)
        .fetch_all(&self.pool)
        .await
    }

    async fn list_for_user_memberships(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<WorkspaceConnectionListing>, sqlx::Error> {
        sqlx::query_as::<_, WorkspaceConnectionListing>(
            r#"
            SELECT DISTINCT ON (wc.id)
                wc.id,
                wc.connection_id,
                wc.workspace_id,
                wc.owner_user_id,
                w.name AS workspace_name,
                wc.provider,
                wc.account_email,
                wc.expires_at,
                owner.first_name AS shared_by_first_name,
                owner.last_name AS shared_by_last_name,
                owner.email AS shared_by_email,
                wc.updated_at,
                (owner_token.id IS NULL) AS requires_reconnect,
                (wc.incoming_webhook_url IS NOT NULL) AS has_incoming_webhook
            FROM workspace_connections wc
            JOIN workspace_members wm ON wm.workspace_id = wc.workspace_id
            JOIN workspaces w ON w.id = wc.workspace_id
            LEFT JOIN users owner ON owner.id = wc.owner_user_id
            LEFT JOIN user_oauth_tokens owner_token
                ON owner_token.id = wc.user_oauth_token_id
            WHERE wm.user_id = $1
              AND w.deleted_at IS NULL
            ORDER BY wc.id, wc.created_at ASC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await
    }

    async fn list_by_workspace_creator(
        &self,
        workspace_id: Uuid,
        creator_id: Uuid,
    ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
        sqlx::query_as::<_, WorkspaceConnection>(
            r#"
            SELECT
                id,
                connection_id,
                workspace_id,
                created_by,
                owner_user_id,
                user_oauth_token_id,
                provider,
                access_token,
                refresh_token,
                expires_at,
                account_email,
                created_at,
                updated_at,
                bot_user_id,
                slack_team_id,
                incoming_webhook_url,
                metadata
            FROM workspace_connections
            WHERE workspace_id = $1
              AND owner_user_id = $2
            "#,
        )
        .bind(workspace_id)
        .bind(creator_id)
        .fetch_all(&self.pool)
        .await
    }

    async fn update_tokens_for_creator(
        &self,
        creator_id: Uuid,
        provider: ConnectedOAuthProvider,
        access_token: String,
        refresh_token: String,
        expires_at: OffsetDateTime,
        account_email: String,
        bot_user_id: Option<String>,
        slack_team_id: Option<String>,
        incoming_webhook_url: Option<String>,
    ) -> Result<(), sqlx::Error> {
        validate_slack_team_id_value(provider, &slack_team_id)?;
        sqlx::query(
            r#"
            UPDATE workspace_connections
            SET
                access_token = $3,
                refresh_token = $4,
                expires_at = $5,
                account_email = $6,
                updated_at = now(),
                bot_user_id = COALESCE($7, bot_user_id),
                slack_team_id = COALESCE($8, slack_team_id),
                incoming_webhook_url = COALESCE($9, incoming_webhook_url)
            WHERE owner_user_id = $1
              AND provider = $2::oauth_connection_provider
            "#,
        )
        .bind(creator_id)
        .bind(provider)
        .bind(access_token)
        .bind(refresh_token)
        .bind(expires_at)
        .bind(account_email)
        .bind(bot_user_id)
        .bind(slack_team_id)
        .bind(incoming_webhook_url)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn update_tokens_for_connection(
        &self,
        connection_id: Uuid,
        access_token: String,
        refresh_token: String,
        expires_at: OffsetDateTime,
        account_email: String,
        bot_user_id: Option<String>,
        slack_team_id: Option<String>,
        incoming_webhook_url: Option<String>,
    ) -> Result<WorkspaceConnection, sqlx::Error> {
        let identity = sqlx::query_as!(
            WorkspaceConnectionIdentity,
            r#"
            SELECT
                provider as "provider: _",
                owner_user_id,
                user_oauth_token_id
            FROM workspace_connections
            WHERE id = $1
            "#,
            connection_id,
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(sqlx::Error::RowNotFound)?;

        if identity.user_oauth_token_id.is_none() {
            return Err(sqlx::Error::RowNotFound);
        }

        validate_slack_team_id_value(identity.provider, &slack_team_id)?;
        sqlx::query_as!(
            WorkspaceConnection,
            r#"
            UPDATE workspace_connections
            SET
                access_token = $2,
                refresh_token = $3,
                expires_at = $4,
                account_email = $5,
                updated_at = now(),
                bot_user_id = COALESCE($6, bot_user_id),
                slack_team_id = COALESCE($7, slack_team_id),
                incoming_webhook_url = COALESCE($8, incoming_webhook_url)
            WHERE id = $1
              AND provider = $9::oauth_connection_provider
              AND owner_user_id = $10
              AND user_oauth_token_id IS NOT DISTINCT FROM $11
            RETURNING
                id,
                connection_id as "connection_id?",
                workspace_id,
                created_by,
                owner_user_id,
                user_oauth_token_id as "user_oauth_token_id?",
                provider as "provider: _",
                access_token,
                refresh_token,
                expires_at,
                account_email,
                created_at,
                updated_at,
                bot_user_id,
                slack_team_id,
                incoming_webhook_url,
                metadata
            "#,
            connection_id,
            access_token,
            refresh_token,
            expires_at,
            account_email,
            bot_user_id,
            slack_team_id,
            incoming_webhook_url,
            identity.provider as ConnectedOAuthProvider,
            identity.owner_user_id,
            identity.user_oauth_token_id,
        )
        .fetch_one(&self.pool)
        .await
    }

    async fn update_tokens(
        &self,
        connection_id: Uuid,
        access_token: String,
        refresh_token: String,
        expires_at: OffsetDateTime,
        bot_user_id: Option<String>,
        slack_team_id: Option<String>,
        incoming_webhook_url: Option<String>,
    ) -> Result<WorkspaceConnection, sqlx::Error> {
        let identity = sqlx::query_as!(
            WorkspaceConnectionIdentity,
            r#"
            SELECT
                provider as "provider: _",
                owner_user_id,
                user_oauth_token_id
            FROM workspace_connections
            WHERE id = $1
            "#,
            connection_id,
        )
        .fetch_optional(&self.pool)
        .await?
        .ok_or(sqlx::Error::RowNotFound)?;

        if identity.user_oauth_token_id.is_none() {
            return Err(sqlx::Error::RowNotFound);
        }

        validate_slack_team_id_value(identity.provider, &slack_team_id)?;
        sqlx::query_as!(
            WorkspaceConnection,
            r#"
            UPDATE workspace_connections
            SET
                access_token = $2,
                refresh_token = $3,
                expires_at = $4,
                updated_at = now(),
                bot_user_id = COALESCE($5, bot_user_id),
                slack_team_id = COALESCE($6, slack_team_id),
                incoming_webhook_url = COALESCE($7, incoming_webhook_url)
            WHERE id = $1
              AND provider = $8::oauth_connection_provider
              AND owner_user_id = $9
              AND user_oauth_token_id IS NOT DISTINCT FROM $10
            RETURNING
                id,
                connection_id as "connection_id?",
                workspace_id,
                created_by,
                owner_user_id,
                user_oauth_token_id as "user_oauth_token_id?",
                provider as "provider: _",
                access_token,
                refresh_token,
                expires_at,
                account_email,
                created_at,
                updated_at,
                bot_user_id,
                slack_team_id,
                incoming_webhook_url,
                metadata
            "#,
            connection_id,
            access_token,
            refresh_token,
            expires_at,
            bot_user_id,
            slack_team_id,
            incoming_webhook_url,
            identity.provider as ConnectedOAuthProvider,
            identity.owner_user_id,
            identity.user_oauth_token_id,
        )
        .fetch_one(&self.pool)
        .await
    }

    async fn update_metadata(
        &self,
        connection_id: Uuid,
        metadata: serde_json::Value,
    ) -> Result<WorkspaceConnection, sqlx::Error> {
        sqlx::query_as!(
            WorkspaceConnection,
            r#"
            UPDATE workspace_connections
            SET
                metadata = $2,
                updated_at = now()
            WHERE id = $1
            RETURNING
                id,
                connection_id as "connection_id?",
                workspace_id,
                created_by,
                owner_user_id,
                user_oauth_token_id as "user_oauth_token_id?",
                provider as "provider: _",
                access_token,
                refresh_token,
                expires_at,
                account_email,
                created_at,
                updated_at,
                bot_user_id,
                slack_team_id,
                incoming_webhook_url,
                metadata
            "#,
            connection_id,
            metadata,
        )
        .fetch_one(&self.pool)
        .await
    }

    async fn delete_connection(&self, connection_id: Uuid) -> Result<(), sqlx::Error> {
        self.delete_by_id(connection_id).await
    }

    async fn delete_by_id(&self, connection_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            DELETE FROM workspace_connections
            WHERE id = $1
            "#,
            connection_id,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn delete_by_owner_and_provider(
        &self,
        workspace_id: Uuid,
        owner_user_id: Uuid,
        provider: ConnectedOAuthProvider,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            DELETE FROM workspace_connections
            WHERE workspace_id = $1
              AND owner_user_id = $2
              AND provider = $3::oauth_connection_provider
            "#,
            workspace_id,
            owner_user_id,
            provider as ConnectedOAuthProvider,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn delete_by_owner_and_provider_and_id(
        &self,
        workspace_id: Uuid,
        owner_user_id: Uuid,
        provider: ConnectedOAuthProvider,
        connection_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            DELETE FROM workspace_connections
            WHERE workspace_id = $1
              AND owner_user_id = $2
              AND provider = $3::oauth_connection_provider
              AND id = $4
            "#,
            workspace_id,
            owner_user_id,
            provider as ConnectedOAuthProvider,
            connection_id,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn has_connections_for_owner_provider(
        &self,
        owner_user_id: Uuid,
        provider: ConnectedOAuthProvider,
    ) -> Result<bool, sqlx::Error> {
        let exists = sqlx::query_scalar!(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM workspace_connections
                WHERE owner_user_id = $1
                  AND provider = $2::oauth_connection_provider
            )
            "#,
            owner_user_id,
            provider as ConnectedOAuthProvider,
        )
        .fetch_one(&self.pool)
        .await?;

        Ok(exists.unwrap_or(false))
    }

    async fn mark_connections_stale_for_creator(
        &self,
        creator_id: Uuid,
        provider: ConnectedOAuthProvider,
    ) -> Result<Vec<StaleWorkspaceConnection>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            UPDATE workspace_connections
            SET
                expires_at = now() - INTERVAL '5 minutes',
                updated_at = now()
            WHERE owner_user_id = $1
              AND provider = $2
            RETURNING id, workspace_id
            "#,
        )
        .bind(creator_id)
        .bind(provider)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|row| {
                Ok(StaleWorkspaceConnection {
                    connection_id: row.try_get("id")?,
                    workspace_id: row.try_get("workspace_id")?,
                })
            })
            .collect()
    }

    async fn record_audit_event(
        &self,
        event: NewWorkspaceAuditEvent,
    ) -> Result<WorkspaceAuditEvent, sqlx::Error> {
        sqlx::query_as!(
            WorkspaceAuditEvent,
            r#"
            INSERT INTO workspace_audit_events (
                workspace_id,
                actor_id,
                event_type,
                metadata
            )
            VALUES ($1, $2, $3, $4)
            RETURNING
                id,
                workspace_id,
                actor_id,
                event_type,
                metadata,
                created_at
            "#,
            event.workspace_id,
            event.actor_id,
            event.event_type,
            event.metadata as serde_json::Value,
        )
        .fetch_one(&self.pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::oauth_token::ConnectedOAuthProvider;
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
        .bind(format!("slack-team-{}@example.com", Uuid::new_v4()))
        .bind("Slack")
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
        .bind(format!("Slack Workspace {}", Uuid::new_v4()))
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
    async fn slack_team_id_required_for_workspace_connections() {
        let pool = test_pg_pool();
        let user_id = insert_user(&pool).await;
        let workspace_id = insert_workspace(&pool, user_id).await;

        let result = sqlx::query(
            r#"
            INSERT INTO workspace_connections (
                workspace_id,
                created_by,
                owner_user_id,
                provider,
                access_token,
                refresh_token,
                expires_at,
                account_email
            )
            VALUES ($1, $2, $2, 'slack'::oauth_connection_provider, 'access', 'refresh', $3, $4)
            "#,
        )
        .bind(workspace_id)
        .bind(user_id)
        .bind(OffsetDateTime::now_utc())
        .bind("slack@example.com")
        .execute(&*pool)
        .await;

        assert!(result.is_err(), "Slack row without team id should fail");
    }

    #[tokio::test]
    #[ignore]
    async fn slack_team_id_unique_per_workspace() {
        let pool = test_pg_pool();
        let user_id = insert_user(&pool).await;
        let workspace_id = insert_workspace(&pool, user_id).await;

        let repo = PostgresWorkspaceConnectionRepository {
            pool: (*pool).clone(),
        };

        let base = NewWorkspaceConnection {
            workspace_id,
            created_by: user_id,
            owner_user_id: user_id,
            user_oauth_token_id: None,
            connection_id: None,
            provider: ConnectedOAuthProvider::Slack,
            access_token: "access".into(),
            refresh_token: "refresh".into(),
            expires_at: OffsetDateTime::now_utc(),
            account_email: "slack@example.com".into(),
            bot_user_id: None,
            slack_team_id: Some("T123".into()),
            incoming_webhook_url: None,
            metadata: serde_json::json!({}),
        };

        repo.insert_connection(base.clone())
            .await
            .expect("first insert succeeds");

        let err = repo
            .insert_connection(base)
            .await
            .expect_err("duplicate Slack team should fail");

        assert!(matches!(err, sqlx::Error::Database(_)));
    }

    #[tokio::test]
    #[ignore]
    async fn find_slack_by_workspace_and_team_returns_single_match() {
        let pool = test_pg_pool();
        let user_id = insert_user(&pool).await;
        let workspace_id = insert_workspace(&pool, user_id).await;

        let repo = PostgresWorkspaceConnectionRepository {
            pool: (*pool).clone(),
        };

        let inserted = repo
            .insert_connection(NewWorkspaceConnection {
                workspace_id,
                created_by: user_id,
                owner_user_id: user_id,
                user_oauth_token_id: None,
                connection_id: None,
                provider: ConnectedOAuthProvider::Slack,
                access_token: "access".into(),
                refresh_token: "refresh".into(),
                expires_at: OffsetDateTime::now_utc(),
                account_email: "slack@example.com".into(),
                bot_user_id: None,
                slack_team_id: Some("T456".into()),
                incoming_webhook_url: None,
                metadata: serde_json::json!({}),
            })
            .await
            .expect("insert succeeds");

        let found = repo
            .find_slack_by_workspace_and_team(workspace_id, "T456")
            .await
            .expect("lookup succeeds")
            .expect("row returned");

        assert_eq!(found.id, inserted.id);

        let missing = repo
            .find_slack_by_workspace_and_team(workspace_id, "T999")
            .await
            .expect("lookup succeeds");
        assert!(missing.is_none());
    }
}
