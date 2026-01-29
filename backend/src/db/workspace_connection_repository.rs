use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::models::oauth_token::{
    ConnectedOAuthProvider, WorkspaceAuditEvent, WorkspaceConnection,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleWorkspaceConnection {
    pub connection_id: Uuid,
    pub workspace_id: Uuid,
}

#[derive(Debug, Clone)]
pub struct NewWorkspaceConnection {
    pub workspace_id: Uuid,
    pub created_by: Uuid,
    pub owner_user_id: Uuid,
    pub user_oauth_token_id: Option<Uuid>,
    pub connection_id: Option<Uuid>,
    pub provider: ConnectedOAuthProvider,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: time::OffsetDateTime,
    pub account_email: String,
    pub bot_user_id: Option<String>,
    pub slack_team_id: Option<String>,
    pub incoming_webhook_url: Option<String>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct NewWorkspaceAuditEvent {
    pub workspace_id: Uuid,
    pub actor_id: Uuid,
    pub event_type: String,
    pub metadata: Value,
}

#[derive(Debug, Clone, sqlx::FromRow, Serialize, Deserialize)]
pub struct WorkspaceConnectionListing {
    pub id: Uuid,
    pub connection_id: Option<Uuid>,
    pub workspace_id: Uuid,
    pub owner_user_id: Uuid,
    pub workspace_name: String,
    pub provider: ConnectedOAuthProvider,
    pub account_email: String,
    pub expires_at: time::OffsetDateTime,
    pub shared_by_first_name: Option<String>,
    pub shared_by_last_name: Option<String>,
    pub shared_by_email: Option<String>,
    pub updated_at: time::OffsetDateTime,
    pub requires_reconnect: bool,
    pub has_incoming_webhook: bool,
}

#[async_trait]
#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub trait WorkspaceConnectionRepository: Send + Sync {
    async fn insert_connection(
        &self,
        new_connection: NewWorkspaceConnection,
    ) -> Result<WorkspaceConnection, sqlx::Error>;

    async fn find_by_id(
        &self,
        connection_id: Uuid,
    ) -> Result<Option<WorkspaceConnection>, sqlx::Error>;

    async fn get_by_id(&self, connection_id: Uuid) -> Result<WorkspaceConnection, sqlx::Error>;

    async fn list_for_workspace_provider(
        &self,
        workspace_id: Uuid,
        provider: ConnectedOAuthProvider,
    ) -> Result<Vec<WorkspaceConnection>, sqlx::Error>;

    async fn find_by_source_token(
        &self,
        user_oauth_token_id: Uuid,
    ) -> Result<Vec<WorkspaceConnection>, sqlx::Error>;

    async fn list_by_workspace_and_provider(
        &self,
        workspace_id: Uuid,
        provider: ConnectedOAuthProvider,
    ) -> Result<Vec<WorkspaceConnection>, sqlx::Error>;

    async fn find_slack_by_workspace_and_team(
        &self,
        workspace_id: Uuid,
        slack_team_id: &str,
    ) -> Result<Option<WorkspaceConnection>, sqlx::Error> {
        let expected_team_id = slack_team_id.trim();
        if expected_team_id.is_empty() {
            return Err(sqlx::Error::Protocol(
                "Slack workspace team id cannot be empty".to_string(),
            ));
        }
        if expected_team_id.len() > 32 {
            return Err(sqlx::Error::Protocol(
                "Slack workspace team id is too long".to_string(),
            ));
        }

        let connections = self
            .list_by_workspace_and_provider(workspace_id, ConnectedOAuthProvider::Slack)
            .await?;

        let mut matches = Vec::new();
        for connection in connections {
            let team_id = connection
                .slack_team_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    sqlx::Error::Protocol(
                        "Slack workspace connection missing slack_team_id".to_string(),
                    )
                })?;
            if team_id == expected_team_id {
                matches.push(connection);
            }
        }

        if matches.len() > 1 {
            return Err(sqlx::Error::Protocol(
                "multiple Slack workspace connections found for the same team".to_string(),
            ));
        }

        Ok(matches.pop())
    }

    async fn list_for_workspace(
        &self,
        workspace_id: Uuid,
    ) -> Result<Vec<WorkspaceConnectionListing>, sqlx::Error>;

    async fn list_for_user_memberships(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<WorkspaceConnectionListing>, sqlx::Error>;

    async fn list_by_workspace_creator(
        &self,
        workspace_id: Uuid,
        creator_id: Uuid,
    ) -> Result<Vec<WorkspaceConnection>, sqlx::Error>;

    async fn update_tokens_for_creator(
        &self,
        creator_id: Uuid,
        provider: ConnectedOAuthProvider,
        access_token: String,
        refresh_token: String,
        expires_at: time::OffsetDateTime,
        account_email: String,
        bot_user_id: Option<String>,
        slack_team_id: Option<String>,
        incoming_webhook_url: Option<String>,
    ) -> Result<(), sqlx::Error>;

    async fn update_tokens_for_connection(
        &self,
        connection_id: Uuid,
        access_token: String,
        refresh_token: String,
        expires_at: time::OffsetDateTime,
        account_email: String,
        bot_user_id: Option<String>,
        slack_team_id: Option<String>,
        incoming_webhook_url: Option<String>,
    ) -> Result<WorkspaceConnection, sqlx::Error>;

    async fn update_tokens(
        &self,
        connection_id: Uuid,
        access_token: String,
        refresh_token: String,
        expires_at: time::OffsetDateTime,
        bot_user_id: Option<String>,
        slack_team_id: Option<String>,
        incoming_webhook_url: Option<String>,
    ) -> Result<WorkspaceConnection, sqlx::Error>;

    async fn update_metadata(
        &self,
        connection_id: Uuid,
        metadata: serde_json::Value,
    ) -> Result<WorkspaceConnection, sqlx::Error>;

    async fn delete_connection(&self, connection_id: Uuid) -> Result<(), sqlx::Error>;

    async fn delete_by_id(&self, connection_id: Uuid) -> Result<(), sqlx::Error>;

    async fn delete_by_owner_and_provider(
        &self,
        workspace_id: Uuid,
        owner_user_id: Uuid,
        provider: ConnectedOAuthProvider,
    ) -> Result<(), sqlx::Error>;

    async fn delete_by_owner_and_provider_and_id(
        &self,
        workspace_id: Uuid,
        owner_user_id: Uuid,
        provider: ConnectedOAuthProvider,
        connection_id: Uuid,
    ) -> Result<(), sqlx::Error>;

    async fn has_connections_for_owner_provider(
        &self,
        owner_user_id: Uuid,
        provider: ConnectedOAuthProvider,
    ) -> Result<bool, sqlx::Error>;

    async fn mark_connections_stale_for_creator(
        &self,
        creator_id: Uuid,
        provider: ConnectedOAuthProvider,
    ) -> Result<Vec<StaleWorkspaceConnection>, sqlx::Error>;

    async fn record_audit_event(
        &self,
        event: NewWorkspaceAuditEvent,
    ) -> Result<WorkspaceAuditEvent, sqlx::Error>;
}

#[derive(Default)]
#[allow(dead_code)]
pub struct NoopWorkspaceConnectionRepository;

#[async_trait]
impl WorkspaceConnectionRepository for NoopWorkspaceConnectionRepository {
    async fn insert_connection(
        &self,
        _new_connection: NewWorkspaceConnection,
    ) -> Result<WorkspaceConnection, sqlx::Error> {
        Err(sqlx::Error::RowNotFound)
    }

    async fn find_by_id(
        &self,
        _connection_id: Uuid,
    ) -> Result<Option<WorkspaceConnection>, sqlx::Error> {
        Ok(None)
    }

    async fn get_by_id(&self, _connection_id: Uuid) -> Result<WorkspaceConnection, sqlx::Error> {
        Err(sqlx::Error::RowNotFound)
    }

    async fn list_for_workspace_provider(
        &self,
        _workspace_id: Uuid,
        _provider: ConnectedOAuthProvider,
    ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
        Ok(Vec::new())
    }

    async fn list_by_workspace_and_provider(
        &self,
        _workspace_id: Uuid,
        _provider: ConnectedOAuthProvider,
    ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
        Ok(Vec::new())
    }

    async fn find_by_source_token(
        &self,
        _user_oauth_token_id: Uuid,
    ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
        Ok(Vec::new())
    }

    async fn list_for_workspace(
        &self,
        _workspace_id: Uuid,
    ) -> Result<Vec<WorkspaceConnectionListing>, sqlx::Error> {
        Ok(Vec::new())
    }

    async fn list_for_user_memberships(
        &self,
        _user_id: Uuid,
    ) -> Result<Vec<WorkspaceConnectionListing>, sqlx::Error> {
        Ok(Vec::new())
    }

    async fn list_by_workspace_creator(
        &self,
        _workspace_id: Uuid,
        _creator_id: Uuid,
    ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
        Ok(Vec::new())
    }

    async fn update_tokens_for_creator(
        &self,
        _creator_id: Uuid,
        _provider: ConnectedOAuthProvider,
        _access_token: String,
        _refresh_token: String,
        _expires_at: time::OffsetDateTime,
        _account_email: String,
        _bot_user_id: Option<String>,
        _slack_team_id: Option<String>,
        _incoming_webhook_url: Option<String>,
    ) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn update_tokens_for_connection(
        &self,
        _connection_id: Uuid,
        _access_token: String,
        _refresh_token: String,
        _expires_at: time::OffsetDateTime,
        _account_email: String,
        _bot_user_id: Option<String>,
        _slack_team_id: Option<String>,
        _incoming_webhook_url: Option<String>,
    ) -> Result<WorkspaceConnection, sqlx::Error> {
        Err(sqlx::Error::RowNotFound)
    }

    async fn update_tokens(
        &self,
        _connection_id: Uuid,
        _access_token: String,
        _refresh_token: String,
        _expires_at: time::OffsetDateTime,
        _bot_user_id: Option<String>,
        _slack_team_id: Option<String>,
        _incoming_webhook_url: Option<String>,
    ) -> Result<WorkspaceConnection, sqlx::Error> {
        Err(sqlx::Error::RowNotFound)
    }

    async fn update_metadata(
        &self,
        _connection_id: Uuid,
        _metadata: serde_json::Value,
    ) -> Result<WorkspaceConnection, sqlx::Error> {
        Err(sqlx::Error::RowNotFound)
    }

    async fn delete_connection(&self, _connection_id: Uuid) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn delete_by_id(&self, _connection_id: Uuid) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn delete_by_owner_and_provider(
        &self,
        _workspace_id: Uuid,
        _owner_user_id: Uuid,
        _provider: ConnectedOAuthProvider,
    ) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn delete_by_owner_and_provider_and_id(
        &self,
        _workspace_id: Uuid,
        _owner_user_id: Uuid,
        _provider: ConnectedOAuthProvider,
        _connection_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn has_connections_for_owner_provider(
        &self,
        _owner_user_id: Uuid,
        _provider: ConnectedOAuthProvider,
    ) -> Result<bool, sqlx::Error> {
        Ok(false)
    }

    async fn mark_connections_stale_for_creator(
        &self,
        _creator_id: Uuid,
        _provider: ConnectedOAuthProvider,
    ) -> Result<Vec<StaleWorkspaceConnection>, sqlx::Error> {
        Ok(Vec::new())
    }

    async fn record_audit_event(
        &self,
        _event: NewWorkspaceAuditEvent,
    ) -> Result<WorkspaceAuditEvent, sqlx::Error> {
        Err(sqlx::Error::RowNotFound)
    }
}
