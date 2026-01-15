use std::sync::Arc;

use dashmap::DashMap;
use serde_json::json;
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;
use tracing::{error, warn};
use uuid::Uuid;

#[cfg(test)]
use crate::db::mock_db::NoopWorkspaceRepository;
use crate::db::oauth_token_repository::{NewUserOAuthToken, UserOAuthTokenRepository};
#[cfg(test)]
use crate::db::workspace_connection_repository::StaleWorkspaceConnection;
#[cfg(test)]
use crate::db::workspace_connection_repository::WorkspaceConnectionListing;
use crate::db::workspace_connection_repository::{
    NewWorkspaceAuditEvent, NewWorkspaceConnection, WorkspaceConnectionRepository,
};
use crate::db::workspace_repository::WorkspaceRepository;
use crate::models::oauth_token::{
    ConnectedOAuthProvider, UserOAuthToken, WorkspaceConnection,
    WORKSPACE_AUDIT_EVENT_CONNECTION_PROMOTED, WORKSPACE_AUDIT_EVENT_CONNECTION_UNSHARED,
};
use crate::services::oauth::account_service::{
    clear_webhook, encrypt_slack_metadata_with_key, merge_slack_metadata, parse_token_metadata,
    serialize_token_metadata, slack_metadata_from_value, AuthorizationTokens,
    EncryptedSlackOAuthMetadata, OAuthAccountError, OAuthAccountService, OAuthTokenMetadata,
};
use crate::utils::encryption::{decrypt_secret, encrypt_secret, EncryptionError};

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DecryptedWorkspaceConnection {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub created_by: Uuid,
    pub owner_user_id: Uuid,
    pub user_oauth_token_id: Option<Uuid>,
    pub provider: ConnectedOAuthProvider,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: OffsetDateTime,
    pub account_email: String,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
    pub metadata: Option<serde_json::Value>,
    pub slack_team_id: Option<String>,
    pub bot_user_id: Option<String>,
    pub incoming_webhook_url: Option<String>,
}

#[derive(Error, Debug)]
pub enum WorkspaceOAuthError {
    #[error("token not found")]
    NotFound,
    #[error("forbidden")]
    Forbidden,
    #[error("Slack connections must be installed at workspace scope")]
    SlackInstallRequired,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("encryption error: {0}")]
    Encryption(#[from] EncryptionError),
    #[error("oauth error: {0}")]
    OAuth(#[from] OAuthAccountError),
}

#[async_trait::async_trait]
pub trait WorkspaceTokenRefresher: Send + Sync {
    async fn refresh_access_token(
        &self,
        provider: ConnectedOAuthProvider,
        refresh_token: &str,
    ) -> Result<AuthorizationTokens, OAuthAccountError>;
}

#[async_trait::async_trait]
impl WorkspaceTokenRefresher for OAuthAccountService {
    async fn refresh_access_token(
        &self,
        provider: ConnectedOAuthProvider,
        refresh_token: &str,
    ) -> Result<AuthorizationTokens, OAuthAccountError> {
        OAuthAccountService::refresh_access_token(self, provider, refresh_token).await
    }
}

#[derive(Clone)]
pub struct WorkspaceOAuthService {
    user_tokens: Arc<dyn UserOAuthTokenRepository>,
    workspace_repo: Arc<dyn WorkspaceRepository>,
    workspace_connections: Arc<dyn WorkspaceConnectionRepository>,
    oauth_accounts: Arc<dyn WorkspaceTokenRefresher>,
    encryption_key: Arc<Vec<u8>>,
    connection_locks: Arc<DashMap<Uuid, Arc<Mutex<()>>>>,
}

impl WorkspaceOAuthService {
    pub fn new(
        user_tokens: Arc<dyn UserOAuthTokenRepository>,
        workspace_repo: Arc<dyn WorkspaceRepository>,
        workspace_connections: Arc<dyn WorkspaceConnectionRepository>,
        oauth_accounts: Arc<dyn WorkspaceTokenRefresher>,
        encryption_key: Arc<Vec<u8>>,
    ) -> Self {
        Self {
            user_tokens,
            workspace_repo,
            workspace_connections,
            oauth_accounts,
            encryption_key,
            connection_locks: Arc::new(DashMap::new()),
        }
    }

    pub async fn promote_connection(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        provider: ConnectedOAuthProvider,
    ) -> Result<WorkspaceConnection, WorkspaceOAuthError> {
        self.promote_connection_with_token(workspace_id, actor_id, provider, None)
            .await
    }

    pub async fn promote_connection_with_token(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        provider: ConnectedOAuthProvider,
        token_id: Option<Uuid>,
    ) -> Result<WorkspaceConnection, WorkspaceOAuthError> {
        if provider == ConnectedOAuthProvider::Slack {
            return Err(WorkspaceOAuthError::SlackInstallRequired);
        }
        self.ensure_workspace_admin(actor_id, workspace_id).await?;

        // Load existing personal token (OAuth already completed earlier)
        let token = self.load_token(actor_id, provider, token_id).await?;

        let mut access_token = token.access_token.clone();
        let mut refresh_token = token.refresh_token.clone();
        let mut expires_at = token.expires_at;
        let mut account_email = token.account_email.clone();
        let existing_metadata = parse_token_metadata(&token.metadata);
        let mut slack_meta: Option<EncryptedSlackOAuthMetadata> =
            slack_metadata_from_value(&token.metadata);
        let existing_provider_user_id = existing_metadata.provider_user_id.clone();
        let mut provider_user_id = existing_provider_user_id.clone();
        let notion_meta = existing_metadata.notion.clone();

        if provider == ConnectedOAuthProvider::Slack {
            let refresh_plain = decrypt_secret(&self.encryption_key, &token.refresh_token)?;
            let refreshed = self
                .oauth_accounts
                .refresh_access_token(provider, &refresh_plain)
                .await?;

            access_token = encrypt_secret(&self.encryption_key, &refreshed.access_token)?;
            refresh_token = encrypt_secret(&self.encryption_key, &refreshed.refresh_token)?;
            expires_at = refreshed.expires_at;

            if let Some(slack) = refreshed.slack.as_ref() {
                let encrypted = encrypt_slack_metadata_with_key(&self.encryption_key, slack)
                    .map_err(WorkspaceOAuthError::Encryption)?;
                slack_meta = merge_slack_metadata(slack_meta, encrypted);
            }

            if !refreshed.account_email.trim().is_empty() {
                account_email = refreshed.account_email.clone();
            }

            provider_user_id = refreshed.provider_user_id.clone().or(provider_user_id);

            let personal_metadata = serialize_token_metadata(OAuthTokenMetadata {
                slack: slack_meta.clone(),
                provider_user_id: provider_user_id.clone(),
                notion: notion_meta.clone(),
            });

            let _ = self
                .user_tokens
                .upsert_token(NewUserOAuthToken {
                    user_id: actor_id,
                    provider,
                    access_token: access_token.clone(),
                    refresh_token: refresh_token.clone(),
                    expires_at,
                    account_email: account_email.clone(),
                    metadata: personal_metadata,
                })
                .await?;
        }

        let slack_team_id = slack_meta.as_ref().and_then(|meta| meta.team_id.clone());
        let bot_user_id = slack_meta
            .as_ref()
            .and_then(|meta| meta.bot_user_id.clone());
        let incoming_webhook_url = slack_meta
            .as_ref()
            .and_then(|meta| meta.incoming_webhook_url.clone());

        if token.user_id != actor_id || token.provider != provider || token.workspace_id.is_some() {
            return Err(WorkspaceOAuthError::Forbidden);
        }

        // Create workspace connection by COPYING encrypted fields (Slack metadata populated above)
        let connection_metadata = if provider == ConnectedOAuthProvider::Slack {
            serde_json::json!({})
        } else {
            serialize_token_metadata(OAuthTokenMetadata {
                slack: None,
                provider_user_id: provider_user_id.clone(),
                notion: notion_meta.clone(),
            })
        };

        let connection = self
            .workspace_connections
            .insert_connection(NewWorkspaceConnection {
                workspace_id,
                created_by: actor_id,
                owner_user_id: actor_id,
                user_oauth_token_id: Some(token.id),
                connection_id: Some(token.id),
                provider,
                access_token: access_token.clone(),
                refresh_token: refresh_token.clone(),
                expires_at,
                account_email: account_email.clone(),
                slack_team_id,
                bot_user_id,
                incoming_webhook_url: incoming_webhook_url.clone(),
                metadata: connection_metadata,
            })
            .await?;

        // Mark personal token as shared
        // Note: Sharing state is derived from WorkspaceConnection references
        // No need to mark UserOAuthToken as shared

        if provider == ConnectedOAuthProvider::Slack
            && incoming_webhook_url.is_some()
            && slack_meta.is_some()
        {
            let cleared_metadata = serialize_token_metadata(OAuthTokenMetadata {
                slack: clear_webhook(slack_meta.clone()),
                provider_user_id: provider_user_id.clone(),
                notion: notion_meta.clone(),
            });

            let _ = self
                .user_tokens
                .upsert_token(NewUserOAuthToken {
                    user_id: actor_id,
                    provider,
                    access_token: access_token.clone(),
                    refresh_token: refresh_token.clone(),
                    expires_at,
                    account_email: account_email.clone(),
                    metadata: cleared_metadata,
                })
                .await?;
        }

        // Record audit event
        let metadata = json!({
            "provider": provider,
            "account_email": account_email,
        });

        let _ = self
            .workspace_connections
            .record_audit_event(NewWorkspaceAuditEvent {
                workspace_id,
                actor_id,
                event_type: WORKSPACE_AUDIT_EVENT_CONNECTION_PROMOTED.to_string(),
                metadata,
            })
            .await?;

        Ok(connection)
    }

    pub async fn install_slack_workspace_connection(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        source_token_id: Option<Uuid>,
        tokens: AuthorizationTokens,
    ) -> Result<WorkspaceConnection, WorkspaceOAuthError> {
        self.ensure_membership(actor_id, workspace_id).await?;

        let slack = tokens.slack.as_ref().ok_or_else(|| {
            WorkspaceOAuthError::OAuth(OAuthAccountError::InvalidResponse(
                "Slack workspace install missing team id".into(),
            ))
        })?;

        let team_id = slack
            .team_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                WorkspaceOAuthError::OAuth(OAuthAccountError::InvalidResponse(
                    "Slack workspace install missing team id".into(),
                ))
            })?;
        if team_id.len() > 32 {
            return Err(WorkspaceOAuthError::OAuth(
                OAuthAccountError::InvalidResponse(
                    "Slack workspace install invalid team id".into(),
                ),
            ));
        }

        let encrypted_access = encrypt_secret(&self.encryption_key, &tokens.access_token)?;
        let encrypted_refresh = encrypt_secret(&self.encryption_key, &tokens.refresh_token)?;
        let bot_user_id = slack
            .bot_user_id
            .as_deref()
            .map(|value| encrypt_secret(&self.encryption_key, value))
            .transpose()?;
        let incoming_webhook_url = slack
            .incoming_webhook_url
            .as_deref()
            .map(|value| encrypt_secret(&self.encryption_key, value))
            .transpose()?;

        let existing = self
            .workspace_connections
            .find_slack_by_workspace_and_team(workspace_id, team_id)
            .await?;

        if let Some(existing) = existing {
            let updated = self
                .workspace_connections
                .update_tokens_for_connection(
                    existing.id,
                    encrypted_access,
                    encrypted_refresh,
                    tokens.expires_at,
                    tokens.account_email.clone(),
                    bot_user_id.clone(),
                    Some(team_id.to_string()),
                    incoming_webhook_url.clone(),
                )
                .await?;
            return Ok(updated);
        }

        let connection = self
            .workspace_connections
            .insert_connection(NewWorkspaceConnection {
                workspace_id,
                created_by: actor_id,
                owner_user_id: actor_id,
                user_oauth_token_id: source_token_id,
                connection_id: source_token_id,
                provider: ConnectedOAuthProvider::Slack,
                access_token: encrypted_access,
                refresh_token: encrypted_refresh,
                expires_at: tokens.expires_at,
                account_email: tokens.account_email,
                slack_team_id: Some(team_id.to_string()),
                bot_user_id,
                incoming_webhook_url,
                metadata: serde_json::json!({}),
            })
            .await?;

        Ok(connection)
    }

    pub async fn remove_connection(
        &self,
        workspace_id: Uuid,
        actor_id: Uuid,
        connection_id: Uuid,
    ) -> Result<(), WorkspaceOAuthError> {
        self.ensure_membership(actor_id, workspace_id).await?;

        let connection = self
            .workspace_connections
            .find_by_id(connection_id)
            .await?
            .filter(|conn| conn.workspace_id == workspace_id)
            .ok_or(WorkspaceOAuthError::NotFound)?;

        if connection.owner_user_id != actor_id {
            return Err(WorkspaceOAuthError::Forbidden);
        }

        self.workspace_connections
            .delete_connection(connection_id)
            .await?;

        let personal_token_missing = self
            .mark_personal_token_unshared_if_unused(
                connection.owner_user_id,
                connection.provider,
                connection.user_oauth_token_id,
            )
            .await?;

        if personal_token_missing {
            warn!(
                %connection_id,
                %workspace_id,
                user_id = %connection.owner_user_id,
                provider = ?connection.provider,
                "personal oauth token missing while unsharing workspace connection"
            );
        }

        let metadata = json!({
            "provider": connection.provider,
            "account_email": connection.account_email,
            "connection_id": connection.id,
        });

        self.workspace_connections
            .record_audit_event(NewWorkspaceAuditEvent {
                workspace_id,
                actor_id,
                event_type: WORKSPACE_AUDIT_EVENT_CONNECTION_UNSHARED.to_string(),
                metadata,
            })
            .await?;

        Ok(())
    }

    async fn ensure_membership(
        &self,
        user_id: Uuid,
        workspace_id: Uuid,
    ) -> Result<(), WorkspaceOAuthError> {
        if !self.workspace_repo.is_member(workspace_id, user_id).await? {
            return Err(WorkspaceOAuthError::Forbidden);
        }
        Ok(())
    }

    /// Ensure user has admin or owner permissions in workspace
    async fn ensure_workspace_admin(
        &self,
        user_id: Uuid,
        workspace_id: Uuid,
    ) -> Result<(), WorkspaceOAuthError> {
        use crate::models::workspace::WorkspaceRole;

        // Check if user is a member first
        if !self.workspace_repo.is_member(workspace_id, user_id).await? {
            return Err(WorkspaceOAuthError::Forbidden);
        }

        // Get user's role in workspace
        let members = self.workspace_repo.list_members(workspace_id).await?;
        let user_role = members
            .iter()
            .find(|member| member.user_id == user_id)
            .map(|member| &member.role);

        match user_role {
            Some(WorkspaceRole::Owner) | Some(WorkspaceRole::Admin) => Ok(()),
            _ => Err(WorkspaceOAuthError::Forbidden),
        }
    }

    /// Purges connections for a departing member. The caller is expected to have
    /// already validated permissions because the actor might no longer belong to
    /// the workspace when this runs.
    pub async fn purge_member_connections(
        &self,
        workspace_id: Uuid,
        removed_user_id: Uuid,
        actor_id: Uuid,
    ) -> Result<(), WorkspaceOAuthError> {
        let connections = match self
            .workspace_connections
            .list_by_workspace_creator(workspace_id, removed_user_id)
            .await
        {
            Ok(rows) => rows,
            Err(err) => {
                error!(
                    ?err,
                    %workspace_id,
                    removed_user_id = %removed_user_id,
                    %actor_id,
                    "failed to load workspace connections for purge"
                );
                return Err(WorkspaceOAuthError::Database(err));
            }
        };

        if connections.is_empty() {
            return Ok(());
        }

        let mut processed_providers: Vec<(ConnectedOAuthProvider, Option<Uuid>)> = connections
            .iter()
            .map(|connection| (connection.provider, connection.user_oauth_token_id))
            .collect();
        processed_providers.sort_by(|a, b| {
            Self::provider_sort_key(a.0)
                .cmp(&Self::provider_sort_key(b.0))
                .then_with(|| a.1.cmp(&b.1))
        });
        processed_providers.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);

        for connection in connections {
            if let Err(err) = self.workspace_connections.delete_by_id(connection.id).await {
                error!(
                    ?err,
                    %workspace_id,
                    removed_user_id = %removed_user_id,
                    connection_id = %connection.id,
                    "failed to delete workspace connection during purge"
                );
                return Err(WorkspaceOAuthError::Database(err));
            }

            let metadata = json!({
                "provider": connection.provider,
                "account_email": connection.account_email,
                "connection_id": connection.id,
                "removed_user_id": removed_user_id,
            });

            if let Err(err) = self
                .workspace_connections
                .record_audit_event(NewWorkspaceAuditEvent {
                    workspace_id,
                    actor_id,
                    event_type: WORKSPACE_AUDIT_EVENT_CONNECTION_UNSHARED.to_string(),
                    metadata,
                })
                .await
            {
                error!(
                    ?err,
                    %workspace_id,
                    removed_user_id = %removed_user_id,
                    connection_id = %connection.id,
                    "failed to record audit event during workspace purge"
                );
                return Err(WorkspaceOAuthError::Database(err));
            }
        }

        for (provider, token_id) in processed_providers {
            let personal_token_missing = self
                .mark_personal_token_unshared_if_unused(removed_user_id, provider, token_id)
                .await?;

            if personal_token_missing {
                warn!(
                    %workspace_id,
                    removed_user_id = %removed_user_id,
                    provider = ?provider,
                    "personal oauth token missing during workspace purge"
                );
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    pub async fn get_connection(
        &self,
        user_id: Uuid,
        connection_id: Uuid,
        provider: ConnectedOAuthProvider,
    ) -> Result<DecryptedWorkspaceConnection, WorkspaceOAuthError> {
        let record = self
            .workspace_connections
            .find_by_id(connection_id)
            .await?
            .filter(|conn| conn.provider == provider)
            .ok_or(WorkspaceOAuthError::NotFound)?;

        self.ensure_membership(user_id, record.workspace_id).await?;

        self.decrypt_connection(record)
    }

    pub async fn ensure_valid_workspace_token(
        &self,
        connection_id: Uuid,
    ) -> Result<DecryptedWorkspaceConnection, WorkspaceOAuthError> {
        let lock = self
            .connection_locks
            .entry(connection_id)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();

        let _guard = lock.lock().await;

        let record = self
            .workspace_connections
            .find_by_id(connection_id)
            .await?
            .ok_or(WorkspaceOAuthError::NotFound)?;

        let mut decrypted = self.decrypt_connection(record.clone())?;
        if decrypted.provider == ConnectedOAuthProvider::Slack {
            return Ok(decrypted);
        }
        let refresh_deadline = OffsetDateTime::now_utc() + Duration::seconds(60);

        if decrypted.expires_at <= refresh_deadline {
            let refreshed = match self
                .oauth_accounts
                .refresh_access_token(decrypted.provider, &decrypted.refresh_token)
                .await
            {
                Ok(tokens) => tokens,
                Err(err) => {
                    if matches!(err, OAuthAccountError::TokenRevoked { .. }) {
                        self.workspace_connections
                            .delete_connection(connection_id)
                            .await?;

                        if !matches!(decrypted.provider, ConnectedOAuthProvider::Slack) {
                            let personal_token_missing = self
                                .mark_personal_token_unshared_if_unused(
                                    decrypted.owner_user_id,
                                    decrypted.provider,
                                    decrypted.user_oauth_token_id,
                                )
                                .await?;

                            if personal_token_missing {
                                warn!(
                                    connection_id = %connection_id,
                                    provider = ?decrypted.provider,
                                    created_by = %decrypted.created_by,
                                    owner_user_id = %decrypted.owner_user_id,
                                    "workspace connection creator lost personal token while handling revocation"
                                );
                            }
                        }
                    }

                    return Err(WorkspaceOAuthError::OAuth(err));
                }
            };

            let encrypted_access = encrypt_secret(&self.encryption_key, &refreshed.access_token)?;
            let encrypted_refresh = encrypt_secret(&self.encryption_key, &refreshed.refresh_token)?;

            let (bot_user_id, slack_team_id, incoming_webhook_url) =
                if let Some(slack) = refreshed.slack.as_ref() {
                    (
                        slack
                            .bot_user_id
                            .as_deref()
                            .map(|value| encrypt_secret(&self.encryption_key, value))
                            .transpose()?,
                        slack
                            .team_id
                            .as_deref()
                            .map(|value| encrypt_secret(&self.encryption_key, value))
                            .transpose()?,
                        slack
                            .incoming_webhook_url
                            .as_deref()
                            .map(|value| encrypt_secret(&self.encryption_key, value))
                            .transpose()?,
                    )
                } else {
                    (None, None, None)
                };

            let updated = self
                .workspace_connections
                .update_tokens(
                    connection_id,
                    encrypted_access,
                    encrypted_refresh,
                    refreshed.expires_at,
                    bot_user_id,
                    slack_team_id,
                    incoming_webhook_url,
                )
                .await?;

            decrypted = self.decrypt_connection(updated)?;
        }

        Ok(decrypted)
    }

    pub async fn refresh_slack_workspace_token(
        &self,
        connection_id: Uuid,
    ) -> Result<DecryptedWorkspaceConnection, WorkspaceOAuthError> {
        let lock = self
            .connection_locks
            .entry(connection_id)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        let _guard = lock.lock().await;

        let record = self
            .workspace_connections
            .find_by_id(connection_id)
            .await?
            .ok_or(WorkspaceOAuthError::NotFound)?;

        let mut decrypted = self.decrypt_connection(record.clone())?;
        if decrypted.provider != ConnectedOAuthProvider::Slack {
            return Err(WorkspaceOAuthError::OAuth(
                OAuthAccountError::InvalidResponse(
                    "Slack workspace refresh requires a Slack connection".into(),
                ),
            ));
        }

        let refreshed = self
            .oauth_accounts
            .refresh_access_token(ConnectedOAuthProvider::Slack, &decrypted.refresh_token)
            .await?;

        let encrypted_access = encrypt_secret(&self.encryption_key, &refreshed.access_token)?;
        let encrypted_refresh = encrypt_secret(&self.encryption_key, &refreshed.refresh_token)?;

        let bot_user_id = refreshed
            .slack
            .as_ref()
            .and_then(|meta| meta.bot_user_id.clone());
        let slack_team_id = refreshed
            .slack
            .as_ref()
            .and_then(|meta| meta.team_id.clone());
        let incoming_webhook_url = refreshed
            .slack
            .as_ref()
            .and_then(|meta| meta.incoming_webhook_url.clone());

        self.workspace_connections
            .update_tokens(
                connection_id,
                encrypted_access,
                encrypted_refresh,
                refreshed.expires_at,
                bot_user_id.clone(),
                slack_team_id.clone(),
                incoming_webhook_url.clone(),
            )
            .await?;

        decrypted.access_token = refreshed.access_token;
        decrypted.refresh_token = refreshed.refresh_token;
        decrypted.expires_at = refreshed.expires_at;
        if let Some(slack) = refreshed.slack {
            if let Some(team_id) = slack.team_id {
                decrypted.slack_team_id = Some(team_id);
            }
            if let Some(bot_user_id) = slack.bot_user_id {
                decrypted.bot_user_id = Some(bot_user_id);
            }
            if let Some(webhook_url) = slack.incoming_webhook_url {
                decrypted.incoming_webhook_url = Some(webhook_url);
            }
        }

        Ok(decrypted)
    }

    pub async fn handle_revoked_connection(
        &self,
        workspace_id: Uuid,
        connection_id: Uuid,
    ) -> Result<(), WorkspaceOAuthError> {
        let record = self
            .workspace_connections
            .find_by_id(connection_id)
            .await?
            .filter(|conn| conn.workspace_id == workspace_id)
            .ok_or(WorkspaceOAuthError::NotFound)?;

        self.workspace_connections
            .delete_connection(connection_id)
            .await?;

        let personal_token_missing = if matches!(record.provider, ConnectedOAuthProvider::Slack) {
            false
        } else {
            self.mark_personal_token_unshared_if_unused(
                record.owner_user_id,
                record.provider,
                record.user_oauth_token_id,
            )
            .await?
        };

        if personal_token_missing {
            warn!(
                connection_id = %connection_id,
                workspace_id = %workspace_id,
                created_by = %record.created_by,
                owner_user_id = %record.owner_user_id,
                provider = ?record.provider,
                "workspace connection creator missing personal token while handling revocation"
            );
        }

        warn!(
            connection_id = %connection_id,
            workspace_id = %workspace_id,
            created_by = %record.created_by,
            owner_user_id = %record.owner_user_id,
            provider = ?record.provider,
            account_email = %record.account_email,
            personal_token_missing,
            "workspace connection revoked and shared credentials purged"
        );

        Ok(())
    }

    fn provider_sort_key(provider: ConnectedOAuthProvider) -> u8 {
        match provider {
            ConnectedOAuthProvider::Google => 0,
            ConnectedOAuthProvider::Microsoft => 1,
            ConnectedOAuthProvider::Slack => 2,
            ConnectedOAuthProvider::Asana => 3,
            ConnectedOAuthProvider::Notion => 4,
            ConnectedOAuthProvider::Bitly => 5,
        }
    }

    fn decrypt_connection(
        &self,
        record: WorkspaceConnection,
    ) -> Result<DecryptedWorkspaceConnection, WorkspaceOAuthError> {
        let slack_team_id = record
            .slack_team_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string());

        if record.provider == ConnectedOAuthProvider::Slack && slack_team_id.is_none() {
            return Err(WorkspaceOAuthError::Database(sqlx::Error::Protocol(
                "Slack workspace connection missing slack_team_id".to_string(),
            )));
        }

        let bot_user_id = record
            .bot_user_id
            .map(|value| decrypt_secret(&self.encryption_key, &value))
            .transpose()?
            .and_then(|value| {
                let trimmed = value.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            });

        let incoming_webhook_url = record
            .incoming_webhook_url
            .map(|value| decrypt_secret(&self.encryption_key, &value))
            .transpose()?
            .and_then(|value| {
                let trimmed = value.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            });

        Ok(DecryptedWorkspaceConnection {
            id: record.id,
            workspace_id: record.workspace_id,
            created_by: record.created_by,
            owner_user_id: record.owner_user_id,
            user_oauth_token_id: record.user_oauth_token_id,
            provider: record.provider,
            access_token: decrypt_secret(&self.encryption_key, &record.access_token)?,
            refresh_token: decrypt_secret(&self.encryption_key, &record.refresh_token)?,
            expires_at: record.expires_at,
            account_email: record.account_email,
            created_at: record.created_at,
            updated_at: record.updated_at,
            metadata: Some(record.metadata),
            slack_team_id,
            bot_user_id,
            incoming_webhook_url,
        })
    }

    async fn mark_personal_token_unshared_if_unused(
        &self,
        owner_user_id: Uuid,
        provider: ConnectedOAuthProvider,
        user_oauth_token_id: Option<Uuid>,
    ) -> Result<bool, WorkspaceOAuthError> {
        let mark_result = if let Some(token_id) = user_oauth_token_id {
            let remaining_connections = self
                .workspace_connections
                .find_by_source_token(token_id)
                .await?;

            if !remaining_connections.is_empty() {
                return Ok(false);
            }

            self.user_tokens.mark_shared_by_id(token_id, false).await
        } else {
            self.user_tokens
                .mark_shared(owner_user_id, provider, false)
                .await
        };

        match mark_result {
            Ok(_) => Ok(false),
            Err(sqlx::Error::RowNotFound) => Ok(true),
            Err(err) => Err(WorkspaceOAuthError::Database(err)),
        }
    }

    async fn load_token(
        &self,
        actor_id: Uuid,
        provider: ConnectedOAuthProvider,
        token_id: Option<Uuid>,
    ) -> Result<UserOAuthToken, WorkspaceOAuthError> {
        let Some(token_id) = token_id else {
            return Err(WorkspaceOAuthError::NotFound);
        };

        let record = self
            .user_tokens
            .find_by_id(token_id)
            .await?
            .filter(|record| record.provider == provider)
            .ok_or(WorkspaceOAuthError::NotFound)?;

        // Enforce personal token ownership strictly
        if record.user_id != actor_id || record.workspace_id.is_some() {
            return Err(WorkspaceOAuthError::Forbidden);
        }

        Ok(record)
    }

    #[cfg(test)]
    pub fn test_stub() -> Arc<Self> {
        use async_trait::async_trait;

        struct StubUserRepo;

        #[async_trait]
        impl UserOAuthTokenRepository for StubUserRepo {
            async fn upsert_token(
                &self,
                new_token: crate::db::oauth_token_repository::NewUserOAuthToken,
            ) -> Result<UserOAuthToken, sqlx::Error> {
                Ok(UserOAuthToken {
                    id: Uuid::new_v4(),
                    user_id: new_token.user_id,
                    workspace_id: None,
                    provider: new_token.provider,
                    access_token: new_token.access_token,
                    refresh_token: new_token.refresh_token,
                    expires_at: new_token.expires_at,
                    account_email: new_token.account_email,
                    metadata: new_token.metadata,
                    is_shared: false,
                    created_at: OffsetDateTime::now_utc(),
                    updated_at: OffsetDateTime::now_utc(),
                })
            }

            async fn find_by_id(
                &self,
                _token_id: Uuid,
            ) -> Result<Option<UserOAuthToken>, sqlx::Error> {
                Ok(None)
            }

            async fn find_by_user_and_provider(
                &self,
                _user_id: Uuid,
                _provider: ConnectedOAuthProvider,
            ) -> Result<Option<UserOAuthToken>, sqlx::Error> {
                Ok(None)
            }

            async fn delete_token(
                &self,
                _user_id: Uuid,
                _provider: ConnectedOAuthProvider,
            ) -> Result<(), sqlx::Error> {
                Ok(())
            }

            async fn list_tokens_for_user(
                &self,
                _user_id: Uuid,
            ) -> Result<Vec<UserOAuthToken>, sqlx::Error> {
                Ok(vec![])
            }

            async fn mark_shared(
                &self,
                _user_id: Uuid,
                _provider: ConnectedOAuthProvider,
                _is_shared: bool,
            ) -> Result<UserOAuthToken, sqlx::Error> {
                Err(sqlx::Error::RowNotFound)
            }

            async fn list_by_user_and_provider(
                &self,
                _user_id: Uuid,
                _provider: ConnectedOAuthProvider,
            ) -> Result<Vec<UserOAuthToken>, sqlx::Error> {
                Ok(vec![])
            }
        }

        struct StubWorkspaceRepo;

        #[async_trait]
        impl WorkspaceConnectionRepository for StubWorkspaceRepo {
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

            async fn get_by_id(
                &self,
                _connection_id: Uuid,
            ) -> Result<WorkspaceConnection, sqlx::Error> {
                Err(sqlx::Error::RowNotFound)
            }

            async fn list_for_workspace_provider(
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

            async fn list_by_workspace_and_provider(
                &self,
                _workspace_id: Uuid,
                _provider: ConnectedOAuthProvider,
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
                _expires_at: OffsetDateTime,
                _account_email: String,
                _bot_user_id: Option<String>,
                _slack_team_id: Option<String>,
                _incoming_webhook_url: Option<String>,
            ) -> Result<(), sqlx::Error> {
                Ok(())
            }

            async fn update_tokens(
                &self,
                _connection_id: Uuid,
                _access_token: String,
                _refresh_token: String,
                _expires_at: OffsetDateTime,
                _bot_user_id: Option<String>,
                _slack_team_id: Option<String>,
                _incoming_webhook_url: Option<String>,
            ) -> Result<WorkspaceConnection, sqlx::Error> {
                Err(sqlx::Error::RowNotFound)
            }

            async fn update_tokens_for_connection(
                &self,
                _connection_id: Uuid,
                _access_token: String,
                _refresh_token: String,
                _expires_at: OffsetDateTime,
                _account_email: String,
                _bot_user_id: Option<String>,
                _slack_team_id: Option<String>,
                _incoming_webhook_url: Option<String>,
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
            ) -> Result<crate::models::oauth_token::WorkspaceAuditEvent, sqlx::Error> {
                Err(sqlx::Error::RowNotFound)
            }
        }

        Arc::new(Self {
            user_tokens: Arc::new(StubUserRepo),
            workspace_repo: Arc::new(NoopWorkspaceRepository),
            workspace_connections: Arc::new(StubWorkspaceRepo),
            oauth_accounts: OAuthAccountService::test_stub() as Arc<dyn WorkspaceTokenRefresher>,
            encryption_key: Arc::new(vec![0u8; 32]),
            connection_locks: Arc::new(DashMap::new()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::{HashMap, HashSet};
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use std::time::Duration as StdDuration;
    use time::Duration;
    use tokio::time::sleep;

    use crate::db::oauth_token_repository::NewUserOAuthToken;
    use crate::db::workspace_repository::{
        WorkspaceRepository, WorkspaceRunQuotaUpdate, WorkspaceRunUsage,
    };
    use crate::models::plan::PlanTier;
    use crate::models::workspace::{
        Workspace, WorkspaceBillingCycle, WorkspaceInvitation, WorkspaceMember,
        WorkspaceMembershipSummary, WorkspaceRole,
    };
    use crate::utils::encryption::encrypt_secret;

    fn noop_membership_repo() -> Arc<dyn WorkspaceRepository> {
        Arc::new(NoopWorkspaceRepository)
    }

    fn denying_membership_repo() -> Arc<dyn WorkspaceRepository> {
        Arc::new(MembershipGateRepo::new(false))
    }

    struct MembershipGateRepo {
        allowed: bool,
    }

    impl MembershipGateRepo {
        fn new(allowed: bool) -> Self {
            Self { allowed }
        }
    }

    #[async_trait]
    impl WorkspaceRepository for MembershipGateRepo {
        async fn create_workspace(
            &self,
            _name: &str,
            _created_by: Uuid,
            _plan: &str,
        ) -> Result<Workspace, sqlx::Error> {
            unimplemented!()
        }

        async fn update_workspace_name(
            &self,
            _workspace_id: Uuid,
            _name: &str,
        ) -> Result<Workspace, sqlx::Error> {
            unimplemented!()
        }

        async fn update_workspace_plan(
            &self,
            _workspace_id: Uuid,
            _plan: &str,
        ) -> Result<Workspace, sqlx::Error> {
            unimplemented!()
        }

        async fn get_plan(&self, _workspace_id: Uuid) -> Result<PlanTier, sqlx::Error> {
            Ok(PlanTier::Workspace)
        }

        async fn find_workspace(
            &self,
            _workspace_id: Uuid,
        ) -> Result<Option<Workspace>, sqlx::Error> {
            unimplemented!()
        }

        async fn set_stripe_overage_item_id(
            &self,
            _workspace_id: Uuid,
            _subscription_item_id: Option<&str>,
        ) -> Result<(), sqlx::Error> {
            unimplemented!()
        }

        async fn get_stripe_overage_item_id(
            &self,
            _workspace_id: Uuid,
        ) -> Result<Option<String>, sqlx::Error> {
            unimplemented!()
        }

        async fn add_member(
            &self,
            _workspace_id: Uuid,
            _user_id: Uuid,
            _role: WorkspaceRole,
        ) -> Result<(), sqlx::Error> {
            unimplemented!()
        }

        async fn set_member_role(
            &self,
            _workspace_id: Uuid,
            _user_id: Uuid,
            _role: WorkspaceRole,
        ) -> Result<(), sqlx::Error> {
            unimplemented!()
        }

        async fn remove_member(
            &self,
            _workspace_id: Uuid,
            _user_id: Uuid,
        ) -> Result<(), sqlx::Error> {
            unimplemented!()
        }

        async fn leave_workspace(
            &self,
            _workspace_id: Uuid,
            _user_id: Uuid,
        ) -> Result<(), sqlx::Error> {
            unimplemented!()
        }

        async fn revoke_member(
            &self,
            _workspace_id: Uuid,
            _member_id: Uuid,
            _revoked_by: Uuid,
            _reason: Option<&str>,
        ) -> Result<(), sqlx::Error> {
            unimplemented!()
        }

        async fn list_members(
            &self,
            _workspace_id: Uuid,
        ) -> Result<Vec<WorkspaceMember>, sqlx::Error> {
            unimplemented!()
        }

        async fn count_members(&self, _workspace_id: Uuid) -> Result<i64, sqlx::Error> {
            Ok(0)
        }

        async fn count_pending_workspace_invitations(
            &self,
            _workspace_id: Uuid,
        ) -> Result<i64, sqlx::Error> {
            Ok(0)
        }

        async fn is_member(
            &self,
            _workspace_id: Uuid,
            _user_id: Uuid,
        ) -> Result<bool, sqlx::Error> {
            Ok(self.allowed)
        }

        async fn list_memberships_for_user(
            &self,
            _user_id: Uuid,
        ) -> Result<Vec<WorkspaceMembershipSummary>, sqlx::Error> {
            unimplemented!()
        }

        async fn list_user_workspaces(
            &self,
            _user_id: Uuid,
        ) -> Result<Vec<WorkspaceMembershipSummary>, sqlx::Error> {
            unimplemented!()
        }

        async fn create_workspace_invitation(
            &self,
            _workspace_id: Uuid,
            _email: &str,
            _role: WorkspaceRole,
            _token: &str,
            _expires_at: OffsetDateTime,
            _created_by: Uuid,
        ) -> Result<WorkspaceInvitation, sqlx::Error> {
            unimplemented!()
        }

        async fn list_workspace_invitations(
            &self,
            _workspace_id: Uuid,
        ) -> Result<Vec<WorkspaceInvitation>, sqlx::Error> {
            unimplemented!()
        }

        async fn revoke_workspace_invitation(&self, _invite_id: Uuid) -> Result<(), sqlx::Error> {
            unimplemented!()
        }

        async fn find_invitation_by_token(
            &self,
            _token: &str,
        ) -> Result<Option<WorkspaceInvitation>, sqlx::Error> {
            unimplemented!()
        }

        async fn mark_invitation_accepted(&self, _invite_id: Uuid) -> Result<(), sqlx::Error> {
            unimplemented!()
        }

        async fn mark_invitation_declined(&self, _invite_id: Uuid) -> Result<(), sqlx::Error> {
            unimplemented!()
        }

        async fn list_pending_invitations_for_email(
            &self,
            _email: &str,
        ) -> Result<Vec<WorkspaceInvitation>, sqlx::Error> {
            unimplemented!()
        }

        async fn disable_webhook_signing_for_workspace(
            &self,
            _workspace_id: Uuid,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn try_increment_workspace_run_quota(
            &self,
            _workspace_id: Uuid,
            _period_start: OffsetDateTime,
            _max_runs: i64,
        ) -> Result<WorkspaceRunQuotaUpdate, sqlx::Error> {
            Ok(WorkspaceRunQuotaUpdate {
                allowed: true,
                run_count: 1,
                overage_count: 0,
                overage_incremented: false,
            })
        }

        async fn get_workspace_run_quota(
            &self,
            _workspace_id: Uuid,
            _period_start: OffsetDateTime,
        ) -> Result<WorkspaceRunUsage, sqlx::Error> {
            Ok(WorkspaceRunUsage {
                run_count: 0,
                overage_count: 0,
            })
        }

        async fn release_workspace_run_quota(
            &self,
            _workspace_id: Uuid,
            _period_start: OffsetDateTime,
            _overage_decrement: bool,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn upsert_workspace_billing_cycle(
            &self,
            _workspace_id: Uuid,
            _subscription_id: &str,
            _period_start: OffsetDateTime,
            _period_end: OffsetDateTime,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn clear_workspace_billing_cycle(
            &self,
            _workspace_id: Uuid,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn get_workspace_billing_cycle(
            &self,
            _workspace_id: Uuid,
        ) -> Result<Option<WorkspaceBillingCycle>, sqlx::Error> {
            Ok(None)
        }
    }

    #[derive(Clone)]
    struct BufferingMakeWriter {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl BufferingMakeWriter {
        fn new() -> Self {
            Self {
                buffer: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn buffer(&self) -> Arc<Mutex<Vec<u8>>> {
            Arc::clone(&self.buffer)
        }
    }

    struct BufferWriter {
        buffer: Arc<Mutex<Vec<u8>>>,
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BufferingMakeWriter {
        type Writer = BufferWriter;

        fn make_writer(&'a self) -> Self::Writer {
            BufferWriter {
                buffer: Arc::clone(&self.buffer),
            }
        }
    }

    impl Write for BufferWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut guard = self.buffer.lock().unwrap();
            guard.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct InMemoryUserRepo {
        token: Mutex<Option<UserOAuthToken>>,
        shared_flag: Mutex<bool>,
    }

    #[async_trait]
    impl UserOAuthTokenRepository for InMemoryUserRepo {
        async fn upsert_token(
            &self,
            new_token: NewUserOAuthToken,
        ) -> Result<UserOAuthToken, sqlx::Error> {
            let mut guard = self.token.lock().unwrap();
            let now = OffsetDateTime::now_utc();
            let record = UserOAuthToken {
                id: guard.as_ref().map(|t| t.id).unwrap_or_else(Uuid::new_v4),
                user_id: new_token.user_id,
                workspace_id: None,
                provider: new_token.provider,
                access_token: new_token.access_token.clone(),
                refresh_token: new_token.refresh_token.clone(),
                expires_at: new_token.expires_at,
                account_email: new_token.account_email.clone(),
                metadata: new_token.metadata.clone(),
                is_shared: *self.shared_flag.lock().unwrap(),
                created_at: now,
                updated_at: now,
            };
            *guard = Some(record.clone());
            Ok(record)
        }

        async fn find_by_id(&self, token_id: Uuid) -> Result<Option<UserOAuthToken>, sqlx::Error> {
            let token = self.token.lock().unwrap();
            Ok(token.clone().filter(|record| record.id == token_id))
        }

        async fn find_by_user_and_provider(
            &self,
            user_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<Option<UserOAuthToken>, sqlx::Error> {
            let token = self.token.lock().unwrap();
            Ok(token
                .clone()
                .filter(|record| record.user_id == user_id && record.provider == provider))
        }

        async fn delete_token(
            &self,
            _user_id: Uuid,
            _provider: ConnectedOAuthProvider,
        ) -> Result<(), sqlx::Error> {
            let mut token = self.token.lock().unwrap();
            *token = None;
            Ok(())
        }

        async fn list_tokens_for_user(
            &self,
            _user_id: Uuid,
        ) -> Result<Vec<UserOAuthToken>, sqlx::Error> {
            let token = self.token.lock().unwrap();
            Ok(token
                .clone()
                .filter(|record| record.user_id == _user_id)
                .into_iter()
                .collect())
        }

        async fn mark_shared(
            &self,
            _user_id: Uuid,
            _provider: ConnectedOAuthProvider,
            is_shared: bool,
        ) -> Result<UserOAuthToken, sqlx::Error> {
            let mut flag = self.shared_flag.lock().unwrap();
            *flag = is_shared;
            let token = self.token.lock().unwrap();
            token.clone().ok_or(sqlx::Error::RowNotFound)
        }

        async fn list_by_user_and_provider(
            &self,
            user_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<Vec<UserOAuthToken>, sqlx::Error> {
            let token = self.token.lock().unwrap();
            Ok(token
                .clone()
                .filter(|record| record.user_id == user_id && record.provider == provider)
                .into_iter()
                .collect())
        }
    }

    struct InMemoryWorkspaceRepo {
        connection: Mutex<Option<WorkspaceConnection>>,
        events: Mutex<Vec<crate::models::oauth_token::WorkspaceAuditEvent>>,
        find_by_id_calls: Mutex<Vec<Uuid>>,
        update_calls: Mutex<usize>,
    }

    impl InMemoryWorkspaceRepo {
        fn new() -> Self {
            Self {
                connection: Mutex::new(None),
                events: Mutex::new(Vec::new()),
                find_by_id_calls: Mutex::new(Vec::new()),
                update_calls: Mutex::new(0),
            }
        }
    }

    #[async_trait]
    impl WorkspaceConnectionRepository for InMemoryWorkspaceRepo {
        async fn insert_connection(
            &self,
            new_connection: NewWorkspaceConnection,
        ) -> Result<WorkspaceConnection, sqlx::Error> {
            let record = WorkspaceConnection {
                id: Uuid::new_v4(),
                connection_id: new_connection.connection_id,
                workspace_id: new_connection.workspace_id,
                created_by: new_connection.created_by,
                owner_user_id: new_connection.owner_user_id,
                user_oauth_token_id: new_connection.user_oauth_token_id,
                provider: new_connection.provider,
                access_token: new_connection.access_token,
                refresh_token: new_connection.refresh_token,
                expires_at: new_connection.expires_at,
                account_email: new_connection.account_email,
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                metadata: new_connection.metadata,
                slack_team_id: new_connection.slack_team_id,
                bot_user_id: new_connection.bot_user_id,
                incoming_webhook_url: new_connection.incoming_webhook_url,
            };
            let mut guard = self.connection.lock().unwrap();
            *guard = Some(record.clone());
            Ok(record)
        }

        async fn find_by_id(
            &self,
            connection_id: Uuid,
        ) -> Result<Option<WorkspaceConnection>, sqlx::Error> {
            self.find_by_id_calls.lock().unwrap().push(connection_id);
            let guard = self.connection.lock().unwrap();
            Ok(guard.clone().filter(|record| record.id == connection_id))
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
            let guard = self.connection.lock().unwrap();
            Ok(guard
                .clone()
                .filter(|record| record.workspace_id == workspace_id && record.provider == provider)
                .into_iter()
                .collect())
        }

        async fn find_by_source_token(
            &self,
            user_oauth_token_id: Uuid,
        ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
            let guard = self.connection.lock().unwrap();
            Ok(guard
                .clone()
                .filter(|record| record.user_oauth_token_id == Some(user_oauth_token_id))
                .into_iter()
                .collect())
        }

        async fn list_by_workspace_and_provider(
            &self,
            workspace_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
            self.list_for_workspace_provider(workspace_id, provider)
                .await
        }

        async fn list_for_workspace(
            &self,
            workspace_id: Uuid,
        ) -> Result<Vec<WorkspaceConnectionListing>, sqlx::Error> {
            let guard = self.connection.lock().unwrap();
            Ok(guard
                .clone()
                .filter(|record| record.workspace_id == workspace_id)
                .into_iter()
                .map(|record| WorkspaceConnectionListing {
                    id: record.id,
                    connection_id: record.connection_id,
                    workspace_id: record.workspace_id,
                    owner_user_id: record.owner_user_id,
                    workspace_name: String::new(),
                    provider: record.provider,
                    account_email: record.account_email.clone(),
                    expires_at: record.expires_at,
                    shared_by_first_name: None,
                    shared_by_last_name: None,
                    shared_by_email: None,
                    updated_at: record.updated_at,
                    requires_reconnect: false,
                    has_incoming_webhook: record.incoming_webhook_url.is_some(),
                })
                .collect())
        }

        async fn list_for_user_memberships(
            &self,
            user_id: Uuid,
        ) -> Result<Vec<WorkspaceConnectionListing>, sqlx::Error> {
            let guard = self.connection.lock().unwrap();
            Ok(guard
                .clone()
                .filter(|record| record.owner_user_id == user_id)
                .into_iter()
                .map(|record| WorkspaceConnectionListing {
                    id: record.id,
                    connection_id: record.connection_id,
                    workspace_id: record.workspace_id,
                    owner_user_id: record.owner_user_id,
                    workspace_name: String::new(),
                    provider: record.provider,
                    account_email: record.account_email.clone(),
                    expires_at: record.expires_at,
                    shared_by_first_name: None,
                    shared_by_last_name: None,
                    shared_by_email: None,
                    updated_at: record.updated_at,
                    requires_reconnect: false,
                    has_incoming_webhook: record.incoming_webhook_url.is_some(),
                })
                .collect())
        }

        async fn list_by_workspace_creator(
            &self,
            workspace_id: Uuid,
            creator_id: Uuid,
        ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
            let guard = self.connection.lock().unwrap();
            Ok(guard
                .clone()
                .filter(|record| {
                    record.workspace_id == workspace_id && record.owner_user_id == creator_id
                })
                .into_iter()
                .collect())
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
            let mut guard = self.connection.lock().unwrap();
            if let Some(conn) = guard.as_mut() {
                if conn.owner_user_id == creator_id && conn.provider == provider {
                    conn.access_token = access_token;
                    conn.refresh_token = refresh_token;
                    conn.expires_at = expires_at;
                    conn.account_email = account_email;
                    if bot_user_id.is_some() {
                        conn.bot_user_id = bot_user_id;
                    }
                    if slack_team_id.is_some() {
                        conn.slack_team_id = slack_team_id;
                    }
                    if incoming_webhook_url.is_some() {
                        conn.incoming_webhook_url = incoming_webhook_url;
                    }
                    conn.updated_at = OffsetDateTime::now_utc();
                }
            }

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
            *self.update_calls.lock().unwrap() += 1;
            let mut guard = self.connection.lock().unwrap();
            if let Some(record) = guard.as_mut() {
                if record.id == connection_id {
                    record.access_token = access_token;
                    record.refresh_token = refresh_token;
                    record.expires_at = expires_at;
                    record.account_email = account_email;
                    if bot_user_id.is_some() {
                        record.bot_user_id = bot_user_id;
                    }
                    if slack_team_id.is_some() {
                        record.slack_team_id = slack_team_id;
                    }
                    if incoming_webhook_url.is_some() {
                        record.incoming_webhook_url = incoming_webhook_url;
                    }
                    record.updated_at = OffsetDateTime::now_utc();
                    return Ok(record.clone());
                }
            }
            Err(sqlx::Error::RowNotFound)
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
            let mut guard = self.connection.lock().unwrap();
            if let Some(conn) = guard.as_mut() {
                if conn.id == connection_id {
                    let mut update_guard = self.update_calls.lock().unwrap();
                    *update_guard += 1;
                    conn.access_token = access_token;
                    conn.refresh_token = refresh_token;
                    conn.expires_at = expires_at;
                    if bot_user_id.is_some() {
                        conn.bot_user_id = bot_user_id;
                    }
                    if slack_team_id.is_some() {
                        conn.slack_team_id = slack_team_id;
                    }
                    if incoming_webhook_url.is_some() {
                        conn.incoming_webhook_url = incoming_webhook_url;
                    }
                    conn.updated_at = OffsetDateTime::now_utc();
                    return Ok(conn.clone());
                }
            }
            Err(sqlx::Error::RowNotFound)
        }

        async fn delete_connection(&self, connection_id: Uuid) -> Result<(), sqlx::Error> {
            let mut guard = self.connection.lock().unwrap();
            if guard.as_ref().map(|record| record.id) == Some(connection_id) {
                *guard = None;
            }
            Ok(())
        }

        async fn delete_by_id(&self, connection_id: Uuid) -> Result<(), sqlx::Error> {
            self.delete_connection(connection_id).await
        }

        async fn delete_by_owner_and_provider(
            &self,
            workspace_id: Uuid,
            owner_user_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<(), sqlx::Error> {
            let mut guard = self.connection.lock().unwrap();
            if guard
                .as_ref()
                .filter(|record| {
                    record.workspace_id == workspace_id
                        && record.owner_user_id == owner_user_id
                        && record.provider == provider
                })
                .is_some()
            {
                *guard = None;
            }
            Ok(())
        }

        async fn delete_by_owner_and_provider_and_id(
            &self,
            workspace_id: Uuid,
            owner_user_id: Uuid,
            provider: ConnectedOAuthProvider,
            connection_id: Uuid,
        ) -> Result<(), sqlx::Error> {
            let mut guard = self.connection.lock().unwrap();
            if let Some(record) = guard.as_ref() {
                if record.workspace_id == workspace_id
                    && record.owner_user_id == owner_user_id
                    && record.provider == provider
                    && record.id == connection_id
                {
                    *guard = None;
                }
            }
            Ok(())
        }

        async fn has_connections_for_owner_provider(
            &self,
            owner_user_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<bool, sqlx::Error> {
            let guard = self.connection.lock().unwrap();
            Ok(guard
                .as_ref()
                .map(|record| record.owner_user_id == owner_user_id && record.provider == provider)
                .unwrap_or(false))
        }

        async fn mark_connections_stale_for_creator(
            &self,
            creator_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<Vec<StaleWorkspaceConnection>, sqlx::Error> {
            let mut guard = self.connection.lock().unwrap();
            let mut affected = Vec::new();
            if let Some(conn) = guard.as_mut() {
                if conn.created_by == creator_id && conn.provider == provider {
                    conn.expires_at = OffsetDateTime::now_utc() - Duration::minutes(5);
                    conn.updated_at = OffsetDateTime::now_utc();
                    affected.push(StaleWorkspaceConnection {
                        connection_id: conn.id,
                        workspace_id: conn.workspace_id,
                    });
                }
            }
            Ok(affected)
        }

        async fn record_audit_event(
            &self,
            event: NewWorkspaceAuditEvent,
        ) -> Result<crate::models::oauth_token::WorkspaceAuditEvent, sqlx::Error> {
            let audit = crate::models::oauth_token::WorkspaceAuditEvent {
                id: Uuid::new_v4(),
                workspace_id: event.workspace_id,
                actor_id: event.actor_id,
                event_type: event.event_type,
                metadata: event.metadata,
                created_at: OffsetDateTime::now_utc(),
            };
            let mut guard = self.events.lock().unwrap();
            guard.push(audit.clone());
            Ok(audit)
        }
    }

    #[derive(Clone)]
    struct RecordingTokenRefresher {
        calls: Arc<Mutex<Vec<String>>>,
        response: AuthorizationTokens,
        delay: StdDuration,
    }

    impl RecordingTokenRefresher {
        fn new(response: AuthorizationTokens) -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                response,
                delay: StdDuration::from_millis(25),
            }
        }

        fn without_delay(response: AuthorizationTokens) -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                response,
                delay: StdDuration::from_millis(0),
            }
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl WorkspaceTokenRefresher for RecordingTokenRefresher {
        async fn refresh_access_token(
            &self,
            _provider: ConnectedOAuthProvider,
            refresh_token: &str,
        ) -> Result<AuthorizationTokens, OAuthAccountError> {
            if self.delay > StdDuration::from_millis(0) {
                sleep(self.delay).await;
            }
            self.calls.lock().unwrap().push(refresh_token.to_string());
            Ok(self.response.clone())
        }
    }

    #[derive(Clone)]
    struct RevokingTokenRefresher;

    #[async_trait]
    impl WorkspaceTokenRefresher for RevokingTokenRefresher {
        async fn refresh_access_token(
            &self,
            provider: ConnectedOAuthProvider,
            _refresh_token: &str,
        ) -> Result<AuthorizationTokens, OAuthAccountError> {
            Err(OAuthAccountError::TokenRevoked { provider })
        }
    }

    #[derive(Default)]
    struct RecordingUserRepo {
        tokens: Mutex<HashMap<ConnectedOAuthProvider, UserOAuthToken>>,
        marks: Mutex<Vec<(Uuid, ConnectedOAuthProvider, bool)>>,
        missing: Mutex<HashSet<ConnectedOAuthProvider>>,
    }

    impl RecordingUserRepo {
        fn new() -> Self {
            Self::default()
        }

        fn set_token(&self, provider: ConnectedOAuthProvider, user_id: Uuid) -> Uuid {
            let now = OffsetDateTime::now_utc();
            let token = UserOAuthToken {
                id: Uuid::new_v4(),
                user_id,
                workspace_id: None,
                provider,
                access_token: String::new(),
                refresh_token: String::new(),
                expires_at: now + Duration::hours(1),
                account_email: "shared@example.com".into(),
                metadata: serde_json::json!({}),
                is_shared: true,
                created_at: now,
                updated_at: now,
            };
            let token_id = token.id;
            self.tokens.lock().unwrap().insert(provider, token);
            token_id
        }

        fn marks(&self) -> Vec<(Uuid, ConnectedOAuthProvider, bool)> {
            self.marks.lock().unwrap().clone()
        }

        fn fail_for(&self, provider: ConnectedOAuthProvider) {
            self.missing.lock().unwrap().insert(provider);
        }
    }

    #[async_trait]
    impl UserOAuthTokenRepository for RecordingUserRepo {
        async fn upsert_token(
            &self,
            new_token: crate::db::oauth_token_repository::NewUserOAuthToken,
        ) -> Result<UserOAuthToken, sqlx::Error> {
            let mut guard = self.tokens.lock().unwrap();
            let now = OffsetDateTime::now_utc();
            let record = UserOAuthToken {
                id: guard
                    .get(&new_token.provider)
                    .map(|existing| existing.id)
                    .unwrap_or_else(Uuid::new_v4),
                user_id: new_token.user_id,
                workspace_id: None,
                provider: new_token.provider,
                access_token: new_token.access_token.clone(),
                refresh_token: new_token.refresh_token.clone(),
                expires_at: new_token.expires_at,
                account_email: new_token.account_email.clone(),
                metadata: new_token.metadata.clone(),
                is_shared: guard
                    .get(&new_token.provider)
                    .map(|existing| existing.is_shared)
                    .unwrap_or(false),
                created_at: now,
                updated_at: now,
            };
            guard.insert(new_token.provider, record.clone());
            Ok(record)
        }

        async fn find_by_id(&self, token_id: Uuid) -> Result<Option<UserOAuthToken>, sqlx::Error> {
            let guard = self.tokens.lock().unwrap();
            if let Some(token) = guard.values().find(|token| token.id == token_id) {
                if self.missing.lock().unwrap().contains(&token.provider) {
                    return Ok(None);
                }
                return Ok(Some(token.clone()));
            }

            Ok(None)
        }

        async fn find_by_user_and_provider(
            &self,
            _user_id: Uuid,
            _provider: ConnectedOAuthProvider,
        ) -> Result<Option<UserOAuthToken>, sqlx::Error> {
            if self.missing.lock().unwrap().contains(&_provider) {
                return Ok(None);
            }

            let guard = self.tokens.lock().unwrap();
            Ok(guard
                .get(&_provider)
                .cloned()
                .filter(|token| token.user_id == _user_id))
        }

        async fn delete_token(
            &self,
            _user_id: Uuid,
            _provider: ConnectedOAuthProvider,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn list_tokens_for_user(
            &self,
            _user_id: Uuid,
        ) -> Result<Vec<UserOAuthToken>, sqlx::Error> {
            let missing = self.missing.lock().unwrap().clone();
            let guard = self.tokens.lock().unwrap();
            Ok(guard
                .values()
                .filter(|token| token.user_id == _user_id && !missing.contains(&token.provider))
                .cloned()
                .collect())
        }

        async fn mark_shared(
            &self,
            user_id: Uuid,
            provider: ConnectedOAuthProvider,
            is_shared: bool,
        ) -> Result<UserOAuthToken, sqlx::Error> {
            self.marks
                .lock()
                .unwrap()
                .push((user_id, provider, is_shared));

            if self.missing.lock().unwrap().contains(&provider) {
                return Err(sqlx::Error::RowNotFound);
            }

            let mut guard = self.tokens.lock().unwrap();
            if let Some(token) = guard
                .get_mut(&provider)
                .filter(|token| token.user_id == user_id)
            {
                token.is_shared = is_shared;
                token.updated_at = OffsetDateTime::now_utc();
                return Ok(token.clone());
            }

            Err(sqlx::Error::RowNotFound)
        }

        async fn list_by_user_and_provider(
            &self,
            user_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<Vec<UserOAuthToken>, sqlx::Error> {
            if self.missing.lock().unwrap().contains(&provider) {
                return Ok(vec![]);
            }

            let guard = self.tokens.lock().unwrap();
            Ok(guard
                .get(&provider)
                .cloned()
                .filter(|token| token.user_id == user_id)
                .into_iter()
                .collect())
        }
    }

    struct MultiTokenUserRepo {
        tokens: Mutex<Vec<UserOAuthToken>>,
    }

    impl MultiTokenUserRepo {
        fn new(tokens: Vec<UserOAuthToken>) -> Self {
            Self {
                tokens: Mutex::new(tokens),
            }
        }

        fn tokens(&self) -> Vec<UserOAuthToken> {
            self.tokens.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl UserOAuthTokenRepository for MultiTokenUserRepo {
        async fn upsert_token(
            &self,
            _new_token: crate::db::oauth_token_repository::NewUserOAuthToken,
        ) -> Result<UserOAuthToken, sqlx::Error> {
            Err(sqlx::Error::RowNotFound)
        }

        async fn find_by_id(&self, token_id: Uuid) -> Result<Option<UserOAuthToken>, sqlx::Error> {
            Ok(self
                .tokens
                .lock()
                .unwrap()
                .iter()
                .find(|&token| token.id == token_id)
                .cloned())
        }

        async fn find_by_user_and_provider(
            &self,
            user_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<Option<UserOAuthToken>, sqlx::Error> {
            Ok(self
                .tokens
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|&token| token.user_id == user_id && token.provider == provider)
                .cloned())
        }

        async fn delete_token(
            &self,
            _user_id: Uuid,
            _provider: ConnectedOAuthProvider,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn list_tokens_for_user(
            &self,
            user_id: Uuid,
        ) -> Result<Vec<UserOAuthToken>, sqlx::Error> {
            Ok(self
                .tokens
                .lock()
                .unwrap()
                .iter()
                .filter(|token| token.user_id == user_id)
                .cloned()
                .collect())
        }

        async fn mark_shared(
            &self,
            user_id: Uuid,
            provider: ConnectedOAuthProvider,
            is_shared: bool,
        ) -> Result<UserOAuthToken, sqlx::Error> {
            let mut guard = self.tokens.lock().unwrap();
            if let Some(existing) = guard
                .iter_mut()
                .rev()
                .find(|token| token.user_id == user_id && token.provider == provider)
            {
                existing.is_shared = is_shared;
                return Ok(existing.clone());
            }

            Err(sqlx::Error::RowNotFound)
        }

        async fn mark_shared_by_id(
            &self,
            token_id: Uuid,
            is_shared: bool,
        ) -> Result<UserOAuthToken, sqlx::Error> {
            let mut guard = self.tokens.lock().unwrap();
            if let Some(existing) = guard.iter_mut().find(|token| token.id == token_id) {
                existing.is_shared = is_shared;
                return Ok(existing.clone());
            }

            Err(sqlx::Error::RowNotFound)
        }

        async fn list_by_user_and_provider(
            &self,
            user_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<Vec<UserOAuthToken>, sqlx::Error> {
            Ok(self
                .tokens
                .lock()
                .unwrap()
                .iter()
                .filter(|token| token.user_id == user_id && token.provider == provider)
                .cloned()
                .collect())
        }
    }

    #[derive(Default)]
    struct RecordingWorkspaceRepo {
        connections: Mutex<Vec<WorkspaceConnection>>,
        deleted: Mutex<Vec<Uuid>>,
        events: Mutex<Vec<crate::models::oauth_token::WorkspaceAuditEvent>>,
    }

    impl RecordingWorkspaceRepo {
        fn with_connections(connections: Vec<WorkspaceConnection>) -> Self {
            Self {
                connections: Mutex::new(connections),
                deleted: Mutex::new(Vec::new()),
                events: Mutex::new(Vec::new()),
            }
        }

        fn deleted(&self) -> Vec<Uuid> {
            self.deleted.lock().unwrap().clone()
        }

        fn events(&self) -> Vec<crate::models::oauth_token::WorkspaceAuditEvent> {
            self.events.lock().unwrap().clone()
        }

        fn all_connections(&self) -> Vec<WorkspaceConnection> {
            self.connections.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl WorkspaceConnectionRepository for RecordingWorkspaceRepo {
        async fn insert_connection(
            &self,
            new_connection: NewWorkspaceConnection,
        ) -> Result<WorkspaceConnection, sqlx::Error> {
            let record = WorkspaceConnection {
                id: Uuid::new_v4(),
                connection_id: new_connection.connection_id,
                workspace_id: new_connection.workspace_id,
                created_by: new_connection.created_by,
                owner_user_id: new_connection.owner_user_id,
                user_oauth_token_id: new_connection.user_oauth_token_id,
                provider: new_connection.provider,
                access_token: new_connection.access_token,
                refresh_token: new_connection.refresh_token,
                expires_at: new_connection.expires_at,
                account_email: new_connection.account_email,
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                metadata: new_connection.metadata,
                slack_team_id: new_connection.slack_team_id,
                bot_user_id: new_connection.bot_user_id,
                incoming_webhook_url: new_connection.incoming_webhook_url,
            };

            self.connections.lock().unwrap().push(record.clone());
            Ok(record)
        }

        async fn find_by_id(
            &self,
            connection_id: Uuid,
        ) -> Result<Option<WorkspaceConnection>, sqlx::Error> {
            let guard = self.connections.lock().unwrap();
            Ok(guard.iter().find(|conn| conn.id == connection_id).cloned())
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
            let guard = self.connections.lock().unwrap();
            Ok(guard
                .iter()
                .filter(|conn| conn.workspace_id == workspace_id && conn.provider == provider)
                .cloned()
                .collect())
        }

        async fn find_by_source_token(
            &self,
            user_oauth_token_id: Uuid,
        ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
            let guard = self.connections.lock().unwrap();
            Ok(guard
                .iter()
                .filter(|conn| conn.user_oauth_token_id == Some(user_oauth_token_id))
                .cloned()
                .collect())
        }

        async fn list_by_workspace_and_provider(
            &self,
            workspace_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
            self.list_for_workspace_provider(workspace_id, provider)
                .await
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
            workspace_id: Uuid,
            creator_id: Uuid,
        ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
            let guard = self.connections.lock().unwrap();
            Ok(guard
                .iter()
                .filter(|conn| {
                    conn.workspace_id == workspace_id && conn.owner_user_id == creator_id
                })
                .cloned()
                .collect())
        }

        async fn update_tokens_for_creator(
            &self,
            _creator_id: Uuid,
            _provider: ConnectedOAuthProvider,
            _access_token: String,
            _refresh_token: String,
            _expires_at: OffsetDateTime,
            _account_email: String,
            _bot_user_id: Option<String>,
            _slack_team_id: Option<String>,
            _incoming_webhook_url: Option<String>,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn update_tokens(
            &self,
            _connection_id: Uuid,
            _access_token: String,
            _refresh_token: String,
            _expires_at: OffsetDateTime,
            _bot_user_id: Option<String>,
            _slack_team_id: Option<String>,
            _incoming_webhook_url: Option<String>,
        ) -> Result<WorkspaceConnection, sqlx::Error> {
            Err(sqlx::Error::RowNotFound)
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
            let mut guard = self.connections.lock().unwrap();
            if let Some(record) = guard.iter_mut().find(|conn| conn.id == connection_id) {
                record.access_token = access_token;
                record.refresh_token = refresh_token;
                record.expires_at = expires_at;
                record.account_email = account_email;
                if bot_user_id.is_some() {
                    record.bot_user_id = bot_user_id;
                }
                if slack_team_id.is_some() {
                    record.slack_team_id = slack_team_id;
                }
                if incoming_webhook_url.is_some() {
                    record.incoming_webhook_url = incoming_webhook_url;
                }
                record.updated_at = OffsetDateTime::now_utc();
                return Ok(record.clone());
            }

            Err(sqlx::Error::RowNotFound)
        }

        async fn delete_connection(&self, connection_id: Uuid) -> Result<(), sqlx::Error> {
            self.delete_by_id(connection_id).await
        }

        async fn delete_by_id(&self, connection_id: Uuid) -> Result<(), sqlx::Error> {
            let mut guard = self.connections.lock().unwrap();
            guard.retain(|conn| conn.id != connection_id);
            self.deleted.lock().unwrap().push(connection_id);
            Ok(())
        }

        async fn delete_by_owner_and_provider(
            &self,
            workspace_id: Uuid,
            owner_user_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<(), sqlx::Error> {
            let mut guard = self.connections.lock().unwrap();
            let removed: Vec<Uuid> = guard
                .iter()
                .filter(|conn| {
                    conn.workspace_id == workspace_id
                        && conn.owner_user_id == owner_user_id
                        && conn.provider == provider
                })
                .map(|conn| conn.id)
                .collect();
            guard.retain(|conn| {
                !(conn.workspace_id == workspace_id
                    && conn.owner_user_id == owner_user_id
                    && conn.provider == provider)
            });
            if !removed.is_empty() {
                self.deleted.lock().unwrap().extend(removed);
            }
            Ok(())
        }

        async fn delete_by_owner_and_provider_and_id(
            &self,
            workspace_id: Uuid,
            owner_user_id: Uuid,
            provider: ConnectedOAuthProvider,
            connection_id: Uuid,
        ) -> Result<(), sqlx::Error> {
            let mut guard = self.connections.lock().unwrap();
            let before_len = guard.len();
            guard.retain(|conn| {
                !(conn.workspace_id == workspace_id
                    && conn.owner_user_id == owner_user_id
                    && conn.provider == provider
                    && conn.id == connection_id)
            });
            if guard.len() != before_len {
                self.deleted.lock().unwrap().push(connection_id);
            }
            Ok(())
        }

        async fn has_connections_for_owner_provider(
            &self,
            owner_user_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<bool, sqlx::Error> {
            let guard = self.connections.lock().unwrap();
            Ok(guard
                .iter()
                .any(|conn| conn.owner_user_id == owner_user_id && conn.provider == provider))
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
            event: NewWorkspaceAuditEvent,
        ) -> Result<crate::models::oauth_token::WorkspaceAuditEvent, sqlx::Error> {
            let audit = crate::models::oauth_token::WorkspaceAuditEvent {
                id: Uuid::new_v4(),
                workspace_id: event.workspace_id,
                actor_id: event.actor_id,
                event_type: event.event_type,
                metadata: event.metadata,
                created_at: OffsetDateTime::now_utc(),
            };
            self.events.lock().unwrap().push(audit.clone());
            Ok(audit)
        }
    }

    fn workspace_connection_record(
        workspace_id: Uuid,
        created_by: Uuid,
        provider: ConnectedOAuthProvider,
        user_oauth_token_id: Option<Uuid>,
    ) -> WorkspaceConnection {
        let now = OffsetDateTime::now_utc();
        let slack_team_id = if provider == ConnectedOAuthProvider::Slack {
            Some("T123".to_string())
        } else {
            None
        };
        WorkspaceConnection {
            id: Uuid::new_v4(),
            connection_id: user_oauth_token_id,
            workspace_id,
            created_by,
            owner_user_id: created_by,
            user_oauth_token_id,
            provider,
            access_token: "enc-access".into(),
            refresh_token: "enc-refresh".into(),
            expires_at: now + Duration::hours(1),
            account_email: "shared@example.com".into(),
            created_at: now,
            updated_at: now,
            metadata: serde_json::json!({}),
            slack_team_id,
            bot_user_id: None,
            incoming_webhook_url: None,
        }
    }

    #[tokio::test]
    async fn promote_connection_with_token_copies_encrypted_tokens_and_marks_shared() {
        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let key = Arc::new(vec![7u8; 32]);
        let expires_at = OffsetDateTime::now_utc() + Duration::hours(1);
        let encrypted_access = encrypt_secret(&key, "access").unwrap();
        let encrypted_refresh = encrypt_secret(&key, "refresh").unwrap();
        let token_id = Uuid::new_v4();

        let user_repo = Arc::new(InMemoryUserRepo {
            token: Mutex::new(Some(UserOAuthToken {
                id: token_id,
                user_id,
                workspace_id: None,
                provider: ConnectedOAuthProvider::Google,
                access_token: encrypted_access.clone(),
                refresh_token: encrypted_refresh.clone(),
                expires_at,
                account_email: "user@example.com".into(),
                metadata: serde_json::json!({}),
                is_shared: false,
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
            })),
            shared_flag: Mutex::new(false),
        });
        let workspace_repo = Arc::new(InMemoryWorkspaceRepo::new());

        let refreshed_tokens = AuthorizationTokens {
            access_token: "slack-refreshed-access".into(),
            refresh_token: "slack-refreshed-refresh".into(),
            expires_at: expires_at + Duration::hours(2),
            account_email: "owner@example.com".into(),
            provider_user_id: None,
            notion: None,
            slack: Some(
                crate::services::oauth::account_service::SlackOAuthMetadata {
                    team_id: Some("T123".into()),
                    bot_user_id: Some("B456".into()),
                    incoming_webhook_url: Some("https://hooks.slack.com/services/abc".into()),
                },
            ),
        };
        let refresher = RecordingTokenRefresher::without_delay(refreshed_tokens.clone());
        let workspace_token_refresher: Arc<dyn WorkspaceTokenRefresher> =
            Arc::new(refresher.clone());
        let service = WorkspaceOAuthService::new(
            user_repo.clone(),
            noop_membership_repo(),
            workspace_repo.clone(),
            workspace_token_refresher,
            key,
        );

        let result = service
            .promote_connection_with_token(
                workspace_id,
                user_id,
                ConnectedOAuthProvider::Google,
                Some(token_id),
            )
            .await
            .expect("promotion succeeds");

        assert_eq!(result.workspace_id, workspace_id);
        assert_eq!(result.created_by, user_id);
        assert_eq!(result.access_token, encrypted_access);
        assert_eq!(result.refresh_token, encrypted_refresh);

        let shared = *user_repo.shared_flag.lock().unwrap();
        assert!(shared, "user token should be marked shared");

        let events = workspace_repo.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type,
            WORKSPACE_AUDIT_EVENT_CONNECTION_PROMOTED
        );
    }

    #[tokio::test]
    async fn promote_connection_with_token_rejects_slack() {
        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let key = Arc::new(vec![9u8; 32]);
        let token_id = Uuid::new_v4();

        let user_repo = Arc::new(InMemoryUserRepo {
            token: Mutex::new(None),
            shared_flag: Mutex::new(false),
        });
        let workspace_repo = Arc::new(InMemoryWorkspaceRepo::new());
        let service = WorkspaceOAuthService::new(
            user_repo,
            noop_membership_repo(),
            workspace_repo,
            OAuthAccountService::test_stub() as Arc<dyn WorkspaceTokenRefresher>,
            key,
        );

        let err = service
            .promote_connection_with_token(
                workspace_id,
                user_id,
                ConnectedOAuthProvider::Slack,
                Some(token_id),
            )
            .await
            .expect_err("slack promotion should be rejected");

        assert!(matches!(err, WorkspaceOAuthError::SlackInstallRequired));
    }

    #[tokio::test]
    async fn install_slack_workspace_connection_requires_team_id() {
        let workspace_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let key = Arc::new(vec![12u8; 32]);
        let now = OffsetDateTime::now_utc();

        let workspace_repo = Arc::new(RecordingWorkspaceRepo::default());
        let service = WorkspaceOAuthService::new(
            Arc::new(RecordingUserRepo::new()),
            noop_membership_repo(),
            workspace_repo,
            OAuthAccountService::test_stub() as Arc<dyn WorkspaceTokenRefresher>,
            key,
        );

        let tokens = AuthorizationTokens {
            access_token: "bot-access".into(),
            refresh_token: "bot-refresh".into(),
            expires_at: now + Duration::hours(1),
            account_email: "installer@example.com".into(),
            provider_user_id: None,
            notion: None,
            slack: Some(
                crate::services::oauth::account_service::SlackOAuthMetadata {
                    team_id: None,
                    bot_user_id: Some("B123".into()),
                    incoming_webhook_url: None,
                },
            ),
        };

        let err = service
            .install_slack_workspace_connection(workspace_id, user_id, None, tokens)
            .await
            .expect_err("missing team id should fail");

        match err {
            WorkspaceOAuthError::OAuth(OAuthAccountError::InvalidResponse(msg)) => {
                assert!(msg.contains("team id"), "{msg}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn install_slack_workspace_connection_creates_and_reuses_connection() {
        let workspace_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let key = Arc::new(vec![13u8; 32]);
        let source_token_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let workspace_repo = Arc::new(RecordingWorkspaceRepo::default());
        let service = WorkspaceOAuthService::new(
            Arc::new(RecordingUserRepo::new()),
            noop_membership_repo(),
            workspace_repo.clone(),
            OAuthAccountService::test_stub() as Arc<dyn WorkspaceTokenRefresher>,
            key.clone(),
        );

        let tokens = AuthorizationTokens {
            access_token: "bot-access-1".into(),
            refresh_token: "bot-refresh-1".into(),
            expires_at: now + Duration::hours(1),
            account_email: "installer@example.com".into(),
            provider_user_id: None,
            notion: None,
            slack: Some(
                crate::services::oauth::account_service::SlackOAuthMetadata {
                    team_id: Some("T123".into()),
                    bot_user_id: Some("B123".into()),
                    incoming_webhook_url: Some("https://hooks.slack.com/services/abc".into()),
                },
            ),
        };

        let first = service
            .install_slack_workspace_connection(
                workspace_id,
                user_id,
                Some(source_token_id),
                tokens.clone(),
            )
            .await
            .expect("install succeeds");

        assert_eq!(first.workspace_id, workspace_id);
        assert_eq!(first.provider, ConnectedOAuthProvider::Slack);
        assert_eq!(first.user_oauth_token_id, Some(source_token_id));
        assert_eq!(first.connection_id, Some(source_token_id));
        assert_eq!(
            decrypt_secret(&key, &first.access_token).unwrap(),
            "bot-access-1"
        );
        assert_eq!(
            decrypt_secret(&key, &first.refresh_token).unwrap(),
            "bot-refresh-1"
        );
        assert_eq!(first.slack_team_id.as_deref(), Some("T123"));

        let tokens = AuthorizationTokens {
            access_token: "bot-access-2".into(),
            refresh_token: "bot-refresh-2".into(),
            expires_at: now + Duration::hours(3),
            account_email: "installer@example.com".into(),
            provider_user_id: None,
            notion: None,
            slack: Some(
                crate::services::oauth::account_service::SlackOAuthMetadata {
                    team_id: Some("T123".into()),
                    bot_user_id: Some("B999".into()),
                    incoming_webhook_url: Some("https://hooks.slack.com/services/next".into()),
                },
            ),
        };

        let second = service
            .install_slack_workspace_connection(
                workspace_id,
                user_id,
                Some(source_token_id),
                tokens,
            )
            .await
            .expect("reinstall succeeds");

        assert_eq!(second.id, first.id);
        assert_eq!(
            decrypt_secret(&key, &second.access_token).unwrap(),
            "bot-access-2"
        );
        assert_eq!(
            decrypt_secret(&key, &second.refresh_token).unwrap(),
            "bot-refresh-2"
        );
        assert_eq!(
            decrypt_secret(&key, second.bot_user_id.as_ref().expect("bot user stored")).unwrap(),
            "B999"
        );
        assert_eq!(
            decrypt_secret(
                &key,
                second
                    .incoming_webhook_url
                    .as_ref()
                    .expect("webhook stored")
            )
            .unwrap(),
            "https://hooks.slack.com/services/next"
        );

        assert_eq!(workspace_repo.all_connections().len(), 1);
    }

    #[tokio::test]
    async fn install_slack_workspace_connection_scopes_to_workspace_id() {
        let workspace_a = Uuid::new_v4();
        let workspace_b = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let key = Arc::new(vec![14u8; 32]);
        let now = OffsetDateTime::now_utc();

        let workspace_repo = Arc::new(RecordingWorkspaceRepo::default());
        let service = WorkspaceOAuthService::new(
            Arc::new(RecordingUserRepo::new()),
            noop_membership_repo(),
            workspace_repo.clone(),
            OAuthAccountService::test_stub() as Arc<dyn WorkspaceTokenRefresher>,
            key,
        );

        let tokens = AuthorizationTokens {
            access_token: "bot-access-1".into(),
            refresh_token: "bot-refresh-1".into(),
            expires_at: now + Duration::hours(1),
            account_email: "installer@example.com".into(),
            provider_user_id: None,
            notion: None,
            slack: Some(
                crate::services::oauth::account_service::SlackOAuthMetadata {
                    team_id: Some("T999".into()),
                    bot_user_id: Some("B111".into()),
                    incoming_webhook_url: None,
                },
            ),
        };

        let first = service
            .install_slack_workspace_connection(workspace_a, user_id, None, tokens.clone())
            .await
            .expect("first workspace install succeeds");

        let second = service
            .install_slack_workspace_connection(workspace_b, user_id, None, tokens)
            .await
            .expect("second workspace install succeeds");

        assert_ne!(first.id, second.id);
        let all = workspace_repo.all_connections();
        assert_eq!(all.len(), 2);
        assert!(all.iter().any(|conn| conn.workspace_id == workspace_a));
        assert!(all.iter().any(|conn| conn.workspace_id == workspace_b));
    }

    #[tokio::test]
    async fn install_slack_workspace_connection_does_not_mutate_personal_token() {
        let workspace_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let key = Arc::new(vec![16u8; 32]);
        let now = OffsetDateTime::now_utc();

        let personal_access = encrypt_secret(&key, "personal-access").unwrap();
        let personal_refresh = encrypt_secret(&key, "personal-refresh").unwrap();
        let user_repo = Arc::new(InMemoryUserRepo {
            token: Mutex::new(Some(UserOAuthToken {
                id: Uuid::new_v4(),
                user_id,
                workspace_id: None,
                provider: ConnectedOAuthProvider::Slack,
                access_token: personal_access.clone(),
                refresh_token: personal_refresh.clone(),
                expires_at: now + Duration::hours(2),
                account_email: "personal@example.com".into(),
                metadata: serde_json::json!({}),
                is_shared: false,
                created_at: now,
                updated_at: now,
            })),
            shared_flag: Mutex::new(false),
        });

        let workspace_repo = Arc::new(RecordingWorkspaceRepo::default());
        let service = WorkspaceOAuthService::new(
            user_repo.clone(),
            noop_membership_repo(),
            workspace_repo,
            OAuthAccountService::test_stub() as Arc<dyn WorkspaceTokenRefresher>,
            key.clone(),
        );

        let tokens = AuthorizationTokens {
            access_token: "bot-access".into(),
            refresh_token: "bot-refresh".into(),
            expires_at: now + Duration::hours(1),
            account_email: "installer@example.com".into(),
            provider_user_id: None,
            notion: None,
            slack: Some(
                crate::services::oauth::account_service::SlackOAuthMetadata {
                    team_id: Some("T123".into()),
                    bot_user_id: Some("B123".into()),
                    incoming_webhook_url: None,
                },
            ),
        };

        service
            .install_slack_workspace_connection(workspace_id, user_id, None, tokens)
            .await
            .expect("install succeeds");

        let personal = user_repo
            .token
            .lock()
            .unwrap()
            .clone()
            .expect("personal token remains");
        assert_eq!(personal.access_token, personal_access);
        assert_eq!(personal.refresh_token, personal_refresh);
        assert_eq!(personal.expires_at, now + Duration::hours(2));
        assert!(!*user_repo.shared_flag.lock().unwrap());
    }

    #[tokio::test]
    async fn promote_connection_with_token_preserves_other_user_connections() {
        let workspace_id = Uuid::new_v4();
        let owner_a = Uuid::new_v4();
        let owner_b = Uuid::new_v4();
        let key = Arc::new(vec![5u8; 32]);
        let expires_at = OffsetDateTime::now_utc() + Duration::hours(1);
        let token_id = Uuid::new_v4();
        let owner_a_token_id = Uuid::new_v4();

        let repo = Arc::new(RecordingWorkspaceRepo::with_connections(vec![
            WorkspaceConnection {
                id: Uuid::new_v4(),
                connection_id: Some(owner_a_token_id),
                workspace_id,
                created_by: owner_a,
                owner_user_id: owner_a,
                user_oauth_token_id: Some(owner_a_token_id),
                provider: ConnectedOAuthProvider::Google,
                access_token: "owner-a-access".into(),
                refresh_token: "owner-a-refresh".into(),
                expires_at,
                account_email: "owner-a@example.com".into(),
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                metadata: serde_json::json!({}),
                slack_team_id: None,
                bot_user_id: None,
                incoming_webhook_url: None,
            },
        ]));

        let user_repo = Arc::new(InMemoryUserRepo {
            token: Mutex::new(Some(UserOAuthToken {
                id: token_id,
                user_id: owner_b,
                workspace_id: None,
                provider: ConnectedOAuthProvider::Google,
                access_token: encrypt_secret(&key, "owner-b-access").unwrap(),
                refresh_token: encrypt_secret(&key, "owner-b-refresh").unwrap(),
                expires_at,
                account_email: "owner-b@example.com".into(),
                metadata: serde_json::json!({}),
                is_shared: false,
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
            })),
            shared_flag: Mutex::new(false),
        });

        let service = WorkspaceOAuthService::new(
            user_repo.clone(),
            noop_membership_repo(),
            repo.clone(),
            OAuthAccountService::test_stub() as Arc<dyn WorkspaceTokenRefresher>,
            key,
        );

        let new_connection = service
            .promote_connection_with_token(
                workspace_id,
                owner_b,
                ConnectedOAuthProvider::Google,
                Some(token_id),
            )
            .await
            .expect("promotion succeeds for second user");

        let connections = repo.all_connections();
        assert_eq!(connections.len(), 2, "both connections should remain");
        assert!(connections.iter().any(|conn| conn.owner_user_id == owner_a));
        assert!(connections.iter().any(|conn| conn.id == new_connection.id));

        assert!(
            *user_repo.shared_flag.lock().unwrap(),
            "second user token should be marked shared"
        );
    }

    #[tokio::test]
    async fn promote_connection_with_token_uses_requested_personal_token() {
        let workspace_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let key = Arc::new(vec![31u8; 32]);
        let now = OffsetDateTime::now_utc();

        let token_a = UserOAuthToken {
            id: Uuid::new_v4(),
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Google,
            access_token: encrypt_secret(&key, "access-a").unwrap(),
            refresh_token: encrypt_secret(&key, "refresh-a").unwrap(),
            expires_at: now + Duration::hours(1),
            account_email: "a@example.com".into(),
            metadata: serde_json::json!({}),
            is_shared: false,
            created_at: now,
            updated_at: now,
        };

        let token_b = UserOAuthToken {
            id: Uuid::new_v4(),
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Google,
            access_token: encrypt_secret(&key, "access-b").unwrap(),
            refresh_token: encrypt_secret(&key, "refresh-b").unwrap(),
            expires_at: now + Duration::hours(2),
            account_email: "b@example.com".into(),
            metadata: serde_json::json!({}),
            is_shared: false,
            created_at: now,
            updated_at: now,
        };

        let user_repo = Arc::new(MultiTokenUserRepo::new(vec![
            token_a.clone(),
            token_b.clone(),
        ]));
        let workspace_repo = Arc::new(RecordingWorkspaceRepo::default());
        let service = WorkspaceOAuthService::new(
            user_repo.clone(),
            noop_membership_repo(),
            workspace_repo.clone(),
            OAuthAccountService::test_stub() as Arc<dyn WorkspaceTokenRefresher>,
            key.clone(),
        );

        let connection = service
            .promote_connection_with_token(
                workspace_id,
                user_id,
                ConnectedOAuthProvider::Google,
                Some(token_b.id),
            )
            .await
            .expect("promotion succeeds");

        assert_eq!(connection.user_oauth_token_id, Some(token_b.id));
        assert_eq!(connection.access_token, token_b.access_token);
        assert_eq!(connection.refresh_token, token_b.refresh_token);

        let tokens = user_repo.tokens();
        let shared_for_b = tokens
            .iter()
            .find(|token| token.id == token_b.id)
            .expect("token b present");
        let shared_for_a = tokens
            .iter()
            .find(|token| token.id == token_a.id)
            .expect("token a present");

        assert!(shared_for_b.is_shared);
        assert!(!shared_for_a.is_shared);
    }

    #[tokio::test]
    async fn remove_connection_deletes_workspace_entry_and_marks_unshared() {
        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let key = Arc::new(vec![11u8; 32]);
        let expires_at = OffsetDateTime::now_utc() + Duration::hours(1);
        let encrypted_access = encrypt_secret(&key, "access").unwrap();
        let encrypted_refresh = encrypt_secret(&key, "refresh").unwrap();
        let token_id = Uuid::new_v4();

        let user_repo = Arc::new(InMemoryUserRepo {
            token: Mutex::new(Some(UserOAuthToken {
                id: token_id,
                user_id,
                workspace_id: None,
                provider: ConnectedOAuthProvider::Google,
                access_token: encrypted_access.clone(),
                refresh_token: encrypted_refresh.clone(),
                expires_at,
                account_email: "user@example.com".into(),
                metadata: serde_json::json!({}),
                is_shared: true,
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
            })),
            shared_flag: Mutex::new(true),
        });
        let workspace_repo = Arc::new(InMemoryWorkspaceRepo::new());
        {
            let mut guard = workspace_repo.connection.lock().unwrap();
            *guard = Some(WorkspaceConnection {
                id: connection_id,
                connection_id: Some(token_id),
                workspace_id,
                created_by: user_id,
                owner_user_id: user_id,
                user_oauth_token_id: Some(token_id),
                provider: ConnectedOAuthProvider::Google,
                access_token: encrypted_access.clone(),
                refresh_token: encrypted_refresh.clone(),
                expires_at,
                account_email: "user@example.com".into(),
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                metadata: serde_json::json!({}),
                slack_team_id: None,
                bot_user_id: None,
                incoming_webhook_url: None,
            });
        }

        let oauth_accounts = OAuthAccountService::test_stub();
        let refresher: Arc<dyn WorkspaceTokenRefresher> =
            oauth_accounts.clone() as Arc<dyn WorkspaceTokenRefresher>;
        let service = WorkspaceOAuthService::new(
            user_repo.clone(),
            noop_membership_repo(),
            workspace_repo.clone(),
            refresher,
            key,
        );

        service
            .remove_connection(workspace_id, user_id, connection_id)
            .await
            .expect("removal succeeds");

        assert!(workspace_repo.connection.lock().unwrap().is_none());
        let shared = *user_repo.shared_flag.lock().unwrap();
        assert!(!shared, "user token should be marked unshared");

        let events = workspace_repo.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type,
            WORKSPACE_AUDIT_EVENT_CONNECTION_UNSHARED
        );
        assert_eq!(events[0].workspace_id, workspace_id);
        assert_eq!(events[0].actor_id, user_id);
    }

    #[tokio::test]
    async fn remove_connection_does_not_unshare_when_other_connections_exist() {
        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let other_workspace = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let remaining_connection = Uuid::new_v4();
        let key = Arc::new(vec![7u8; 32]);
        let expires_at = OffsetDateTime::now_utc() + Duration::hours(1);

        let user_repo = Arc::new(RecordingUserRepo::new());
        let token_id = user_repo.set_token(ConnectedOAuthProvider::Google, user_id);

        let mut first_connection = workspace_connection_record(
            workspace_id,
            user_id,
            ConnectedOAuthProvider::Google,
            Some(token_id),
        );
        first_connection.id = connection_id;

        let repo = Arc::new(RecordingWorkspaceRepo::with_connections(vec![
            first_connection,
            WorkspaceConnection {
                id: remaining_connection,
                connection_id: Some(token_id),
                workspace_id: other_workspace,
                created_by: user_id,
                owner_user_id: user_id,
                user_oauth_token_id: Some(token_id),
                provider: ConnectedOAuthProvider::Google,
                access_token: "enc-access".into(),
                refresh_token: "enc-refresh".into(),
                expires_at,
                account_email: "user@example.com".into(),
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                metadata: serde_json::json!({}),
                slack_team_id: None,
                bot_user_id: None,
                incoming_webhook_url: None,
            },
        ]));

        let service = WorkspaceOAuthService::new(
            user_repo.clone(),
            noop_membership_repo(),
            repo.clone(),
            OAuthAccountService::test_stub() as Arc<dyn WorkspaceTokenRefresher>,
            key,
        );

        service
            .remove_connection(workspace_id, user_id, connection_id)
            .await
            .expect("removal should succeed");

        assert_eq!(
            repo.deleted(),
            vec![connection_id],
            "only targeted connection should be removed"
        );
        assert!(
            user_repo.marks().is_empty(),
            "shared flag should remain true while other connections exist"
        );
        assert!(
            repo.all_connections()
                .iter()
                .any(|conn| conn.id == remaining_connection),
            "other workspace connection should remain intact"
        );
    }

    #[tokio::test]
    async fn remove_connection_succeeds_when_personal_token_missing() {
        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let key = Arc::new(vec![13u8; 32]);
        let expires_at = OffsetDateTime::now_utc() + Duration::hours(1);
        let encrypted_access = encrypt_secret(&key, "access").unwrap();
        let encrypted_refresh = encrypt_secret(&key, "refresh").unwrap();

        let user_repo = Arc::new(InMemoryUserRepo {
            token: Mutex::new(None),
            shared_flag: Mutex::new(true),
        });
        let workspace_repo = Arc::new(InMemoryWorkspaceRepo::new());
        {
            let mut guard = workspace_repo.connection.lock().unwrap();
            *guard = Some(WorkspaceConnection {
                id: connection_id,
                connection_id: None,
                workspace_id,
                created_by: user_id,
                owner_user_id: user_id,
                user_oauth_token_id: None,
                provider: ConnectedOAuthProvider::Google,
                access_token: encrypted_access.clone(),
                refresh_token: encrypted_refresh.clone(),
                expires_at,
                account_email: "user@example.com".into(),
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                metadata: serde_json::json!({}),
                slack_team_id: None,
                bot_user_id: None,
                incoming_webhook_url: None,
            });
        }

        let oauth_accounts = OAuthAccountService::test_stub();
        let refresher: Arc<dyn WorkspaceTokenRefresher> =
            oauth_accounts.clone() as Arc<dyn WorkspaceTokenRefresher>;
        let service = WorkspaceOAuthService::new(
            user_repo.clone(),
            noop_membership_repo(),
            workspace_repo.clone(),
            refresher,
            key,
        );

        let make_writer = BufferingMakeWriter::new();
        let captured = make_writer.buffer();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_writer(make_writer.clone())
            .without_time()
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);

        service
            .remove_connection(workspace_id, user_id, connection_id)
            .await
            .expect("removal succeeds even without personal token");

        drop(guard);

        assert!(workspace_repo.connection.lock().unwrap().is_none());
        let shared = *user_repo.shared_flag.lock().unwrap();
        assert!(
            !shared,
            "shared flag should be cleared when removal succeeds"
        );

        let events = workspace_repo.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].event_type,
            WORKSPACE_AUDIT_EVENT_CONNECTION_UNSHARED
        );

        let logs = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
        assert!(logs.contains(&workspace_id.to_string()));
        assert!(logs.contains(&connection_id.to_string()));
        let alert_logged = logs
            .contains("workspace connection revoked and shared credentials purged")
            || logs.contains(
                "workspace connection creator missing personal token while handling revocation",
            )
            || logs.contains("personal oauth token missing while unsharing workspace connection");
        assert!(alert_logged);
    }

    #[tokio::test]
    async fn remove_connection_rejects_non_creator_actor() {
        let creator_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let key = Arc::new(vec![23u8; 32]);
        let expires_at = OffsetDateTime::now_utc() + Duration::hours(1);
        let encrypted_access = encrypt_secret(&key, "access").unwrap();
        let encrypted_refresh = encrypt_secret(&key, "refresh").unwrap();
        let token_id = Uuid::new_v4();

        let user_repo = Arc::new(InMemoryUserRepo {
            token: Mutex::new(Some(UserOAuthToken {
                id: Uuid::new_v4(),
                user_id: creator_id,
                workspace_id: None,
                provider: ConnectedOAuthProvider::Google,
                access_token: encrypted_access.clone(),
                refresh_token: encrypted_refresh.clone(),
                expires_at,
                account_email: "owner@example.com".into(),
                metadata: serde_json::json!({}),
                is_shared: true,
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
            })),
            shared_flag: Mutex::new(true),
        });
        let workspace_repo = Arc::new(InMemoryWorkspaceRepo::new());
        {
            let mut guard = workspace_repo.connection.lock().unwrap();
            *guard = Some(WorkspaceConnection {
                id: connection_id,
                connection_id: Some(token_id),
                workspace_id,
                created_by: creator_id,
                owner_user_id: creator_id,
                user_oauth_token_id: Some(token_id),
                provider: ConnectedOAuthProvider::Google,
                access_token: encrypted_access.clone(),
                refresh_token: encrypted_refresh.clone(),
                expires_at,
                account_email: "owner@example.com".into(),
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                metadata: serde_json::json!({}),
                slack_team_id: None,
                bot_user_id: None,
                incoming_webhook_url: None,
            });
        }

        let oauth_accounts = OAuthAccountService::test_stub();
        let refresher: Arc<dyn WorkspaceTokenRefresher> =
            oauth_accounts.clone() as Arc<dyn WorkspaceTokenRefresher>;
        let service = WorkspaceOAuthService::new(
            user_repo.clone(),
            noop_membership_repo(),
            workspace_repo.clone(),
            refresher,
            key,
        );

        let err = service
            .remove_connection(workspace_id, actor_id, connection_id)
            .await
            .expect_err("non-creator actor should be rejected");

        assert!(matches!(err, WorkspaceOAuthError::Forbidden));
        assert!(workspace_repo.connection.lock().unwrap().is_some());
        let shared = *user_repo.shared_flag.lock().unwrap();
        assert!(shared, "shared flag should remain unchanged when forbidden");
        let events = workspace_repo.events.lock().unwrap();
        assert!(events.is_empty(), "no audit events should be recorded");
    }

    #[tokio::test]
    async fn handle_revoked_connection_removes_entry_and_marks_unshared() {
        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let key = Arc::new(vec![17u8; 32]);
        let expires_at = OffsetDateTime::now_utc() + Duration::hours(1);
        let encrypted_access = encrypt_secret(&key, "access").unwrap();
        let encrypted_refresh = encrypt_secret(&key, "refresh").unwrap();
        let token_id = Uuid::new_v4();

        let user_repo = Arc::new(InMemoryUserRepo {
            token: Mutex::new(Some(UserOAuthToken {
                id: token_id,
                user_id,
                workspace_id: None,
                provider: ConnectedOAuthProvider::Google,
                access_token: encrypted_access.clone(),
                refresh_token: encrypted_refresh.clone(),
                expires_at,
                account_email: "user@example.com".into(),
                metadata: serde_json::json!({}),
                is_shared: true,
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
            })),
            shared_flag: Mutex::new(true),
        });
        let workspace_repo = Arc::new(InMemoryWorkspaceRepo::new());
        {
            let mut guard = workspace_repo.connection.lock().unwrap();
            *guard = Some(WorkspaceConnection {
                id: connection_id,
                connection_id: Some(token_id),
                workspace_id,
                created_by: user_id,
                owner_user_id: user_id,
                user_oauth_token_id: Some(token_id),
                provider: ConnectedOAuthProvider::Google,
                access_token: encrypted_access.clone(),
                refresh_token: encrypted_refresh.clone(),
                expires_at,
                account_email: "user@example.com".into(),
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                metadata: serde_json::json!({}),
                slack_team_id: None,
                bot_user_id: None,
                incoming_webhook_url: None,
            });
        }

        let oauth_accounts = OAuthAccountService::test_stub();
        let refresher: Arc<dyn WorkspaceTokenRefresher> =
            oauth_accounts.clone() as Arc<dyn WorkspaceTokenRefresher>;
        let service = WorkspaceOAuthService::new(
            user_repo.clone(),
            noop_membership_repo(),
            workspace_repo.clone(),
            refresher,
            key,
        );

        service
            .handle_revoked_connection(workspace_id, connection_id)
            .await
            .expect("revoked cleanup succeeds");

        assert!(workspace_repo.connection.lock().unwrap().is_none());
        let shared = *user_repo.shared_flag.lock().unwrap();
        assert!(
            !shared,
            "user token should be marked unshared after revocation"
        );
    }

    #[tokio::test]
    async fn handle_revoked_connection_removes_entry_without_unsharing_slack_personal() {
        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let key = Arc::new(vec![19u8; 32]);
        let expires_at = OffsetDateTime::now_utc() + Duration::hours(1);
        let encrypted_access = encrypt_secret(&key, "access").unwrap();
        let encrypted_refresh = encrypt_secret(&key, "refresh").unwrap();
        let token_id = Uuid::new_v4();

        let user_repo = Arc::new(InMemoryUserRepo {
            token: Mutex::new(Some(UserOAuthToken {
                id: token_id,
                user_id,
                workspace_id: None,
                provider: ConnectedOAuthProvider::Slack,
                access_token: encrypted_access.clone(),
                refresh_token: encrypted_refresh.clone(),
                expires_at,
                account_email: "user@example.com".into(),
                metadata: serde_json::json!({}),
                is_shared: true,
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
            })),
            shared_flag: Mutex::new(true),
        });
        let workspace_repo = Arc::new(InMemoryWorkspaceRepo::new());
        {
            let mut guard = workspace_repo.connection.lock().unwrap();
            *guard = Some(WorkspaceConnection {
                id: connection_id,
                connection_id: Some(token_id),
                workspace_id,
                created_by: user_id,
                owner_user_id: user_id,
                user_oauth_token_id: Some(token_id),
                provider: ConnectedOAuthProvider::Slack,
                access_token: encrypted_access.clone(),
                refresh_token: encrypted_refresh.clone(),
                expires_at,
                account_email: "user@example.com".into(),
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                metadata: serde_json::json!({}),
                slack_team_id: Some("T123".into()),
                bot_user_id: None,
                incoming_webhook_url: None,
            });
        }

        let oauth_accounts = OAuthAccountService::test_stub();
        let refresher: Arc<dyn WorkspaceTokenRefresher> =
            oauth_accounts.clone() as Arc<dyn WorkspaceTokenRefresher>;
        let service = WorkspaceOAuthService::new(
            user_repo.clone(),
            noop_membership_repo(),
            workspace_repo.clone(),
            refresher,
            key,
        );

        service
            .handle_revoked_connection(workspace_id, connection_id)
            .await
            .expect("slack revoke cleanup succeeds");

        assert!(workspace_repo.connection.lock().unwrap().is_none());
        assert!(*user_repo.shared_flag.lock().unwrap());
    }

    #[tokio::test]
    async fn get_connection_decrypts_tokens() {
        let workspace_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let key = Arc::new(vec![9u8; 32]);
        let expires_at = OffsetDateTime::now_utc();
        let encrypted_access = encrypt_secret(&key, "access-token").unwrap();
        let encrypted_refresh = encrypt_secret(&key, "refresh-token").unwrap();
        let token_id = Uuid::new_v4();

        let workspace_repo = Arc::new(InMemoryWorkspaceRepo::new());
        {
            let mut guard = workspace_repo.connection.lock().unwrap();
            *guard = Some(WorkspaceConnection {
                id: connection_id,
                connection_id: Some(token_id),
                workspace_id,
                created_by: user_id,
                owner_user_id: user_id,
                user_oauth_token_id: Some(token_id),
                provider: ConnectedOAuthProvider::Microsoft,
                access_token: encrypted_access.clone(),
                refresh_token: encrypted_refresh.clone(),
                expires_at,
                account_email: "user@example.com".into(),
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                metadata: serde_json::json!({}),
                slack_team_id: None,
                bot_user_id: None,
                incoming_webhook_url: None,
            });
        }

        let user_repo = Arc::new(InMemoryUserRepo {
            token: Mutex::new(None),
            shared_flag: Mutex::new(false),
        });

        let oauth_accounts = OAuthAccountService::test_stub();
        let workspace_token_refresher: Arc<dyn WorkspaceTokenRefresher> =
            oauth_accounts.clone() as Arc<dyn WorkspaceTokenRefresher>;
        let service = WorkspaceOAuthService::new(
            user_repo,
            noop_membership_repo(),
            workspace_repo,
            workspace_token_refresher,
            key,
        );

        let connection = service
            .get_connection(user_id, connection_id, ConnectedOAuthProvider::Microsoft)
            .await
            .expect("connection exists");

        assert_eq!(connection.workspace_id, workspace_id);
        assert_eq!(connection.provider, ConnectedOAuthProvider::Microsoft);
        assert_eq!(connection.access_token, "access-token");
        assert_eq!(connection.refresh_token, "refresh-token");
    }

    #[tokio::test]
    async fn get_connection_returns_requested_record() {
        let workspace_id = Uuid::new_v4();
        let owner_a = Uuid::new_v4();
        let owner_b = Uuid::new_v4();
        let key = Arc::new(vec![11u8; 32]);
        let expires_at = OffsetDateTime::now_utc() + Duration::hours(1);
        let encrypted_a_access = encrypt_secret(&key, "owner-a-access").unwrap();
        let encrypted_a_refresh = encrypt_secret(&key, "owner-a-refresh").unwrap();
        let encrypted_b_access = encrypt_secret(&key, "owner-b-access").unwrap();
        let encrypted_b_refresh = encrypt_secret(&key, "owner-b-refresh").unwrap();
        let token_a_id = Uuid::new_v4();
        let token_b_id = Uuid::new_v4();

        let connection_a = WorkspaceConnection {
            id: Uuid::new_v4(),
            connection_id: Some(token_a_id),
            workspace_id,
            created_by: owner_a,
            owner_user_id: owner_a,
            user_oauth_token_id: Some(token_a_id),
            provider: ConnectedOAuthProvider::Slack,
            access_token: encrypted_a_access.clone(),
            refresh_token: encrypted_a_refresh.clone(),
            expires_at,
            account_email: "owner-a@example.com".into(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            metadata: serde_json::json!({}),
            slack_team_id: Some("T123".into()),
            bot_user_id: None,
            incoming_webhook_url: None,
        };
        let connection_b = WorkspaceConnection {
            id: Uuid::new_v4(),
            connection_id: Some(token_b_id),
            workspace_id,
            created_by: owner_b,
            owner_user_id: owner_b,
            user_oauth_token_id: Some(token_b_id),
            provider: ConnectedOAuthProvider::Slack,
            access_token: encrypted_b_access.clone(),
            refresh_token: encrypted_b_refresh.clone(),
            expires_at,
            account_email: "owner-b@example.com".into(),
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            metadata: serde_json::json!({}),
            slack_team_id: Some("T456".into()),
            bot_user_id: None,
            incoming_webhook_url: None,
        };
        let repo = Arc::new(RecordingWorkspaceRepo::with_connections(vec![
            connection_a.clone(),
            connection_b.clone(),
        ]));

        let service = WorkspaceOAuthService::new(
            Arc::new(InMemoryUserRepo {
                token: Mutex::new(None),
                shared_flag: Mutex::new(false),
            }),
            noop_membership_repo(),
            repo,
            OAuthAccountService::test_stub() as Arc<dyn WorkspaceTokenRefresher>,
            Arc::clone(&key),
        );

        let owner_a_conn = service
            .get_connection(owner_a, connection_a.id, ConnectedOAuthProvider::Slack)
            .await
            .expect("owner A connection exists");
        assert_eq!(owner_a_conn.account_email, "owner-a@example.com");
        assert_eq!(owner_a_conn.access_token, "owner-a-access");

        let owner_b_conn = service
            .get_connection(owner_b, connection_b.id, ConnectedOAuthProvider::Slack)
            .await
            .expect("owner B connection exists");
        assert_eq!(owner_b_conn.account_email, "owner-b@example.com");
        assert_eq!(owner_b_conn.access_token, "owner-b-access");
    }

    #[tokio::test]
    async fn get_connection_verifies_provider_matches() {
        let workspace_id = Uuid::new_v4();
        let owner = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let key = Arc::new(vec![13u8; 32]);
        let expires_at = OffsetDateTime::now_utc() + Duration::hours(1);
        let encrypted_access = encrypt_secret(&key, "owner-access").unwrap();
        let encrypted_refresh = encrypt_secret(&key, "owner-refresh").unwrap();
        let token_id = Uuid::new_v4();

        let repo = Arc::new(RecordingWorkspaceRepo::with_connections(vec![
            WorkspaceConnection {
                id: connection_id,
                connection_id: Some(token_id),
                workspace_id,
                created_by: owner,
                owner_user_id: owner,
                user_oauth_token_id: Some(token_id),
                provider: ConnectedOAuthProvider::Slack,
                access_token: encrypted_access,
                refresh_token: encrypted_refresh,
                expires_at,
                account_email: "owner@example.com".into(),
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                metadata: serde_json::json!({}),
                slack_team_id: Some("T123".into()),
                bot_user_id: None,
                incoming_webhook_url: None,
            },
        ]));

        let service = WorkspaceOAuthService::new(
            Arc::new(InMemoryUserRepo {
                token: Mutex::new(None),
                shared_flag: Mutex::new(false),
            }),
            noop_membership_repo(),
            repo.clone(),
            OAuthAccountService::test_stub() as Arc<dyn WorkspaceTokenRefresher>,
            key,
        );

        let err = service
            .get_connection(owner, connection_id, ConnectedOAuthProvider::Google)
            .await
            .expect_err("provider mismatch should fail");

        assert!(matches!(err, WorkspaceOAuthError::NotFound));
    }

    #[tokio::test]
    async fn get_connection_rejects_non_member() {
        let workspace_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let key = Arc::new(vec![5u8; 32]);
        let expires_at = OffsetDateTime::now_utc();
        let encrypted_access = encrypt_secret(&key, "blocked-access").unwrap();
        let encrypted_refresh = encrypt_secret(&key, "blocked-refresh").unwrap();
        let token_id = Uuid::new_v4();

        let connections = Arc::new(InMemoryWorkspaceRepo::new());
        {
            let mut guard = connections.connection.lock().unwrap();
            *guard = Some(WorkspaceConnection {
                id: connection_id,
                connection_id: Some(token_id),
                workspace_id,
                created_by: user_id,
                owner_user_id: user_id,
                user_oauth_token_id: Some(token_id),
                provider: ConnectedOAuthProvider::Slack,
                access_token: encrypted_access,
                refresh_token: encrypted_refresh,
                expires_at,
                account_email: "user@example.com".into(),
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                metadata: serde_json::json!({}),
                slack_team_id: Some("T123".into()),
                bot_user_id: None,
                incoming_webhook_url: None,
            });
        }

        let user_repo = Arc::new(InMemoryUserRepo {
            token: Mutex::new(None),
            shared_flag: Mutex::new(false),
        });

        let oauth_accounts = OAuthAccountService::test_stub();
        let refresher: Arc<dyn WorkspaceTokenRefresher> =
            oauth_accounts.clone() as Arc<dyn WorkspaceTokenRefresher>;
        let service = WorkspaceOAuthService::new(
            user_repo,
            denying_membership_repo(),
            connections,
            refresher,
            key,
        );

        let err = service
            .get_connection(user_id, connection_id, ConnectedOAuthProvider::Slack)
            .await
            .expect_err("non-member should be rejected");

        assert!(matches!(err, WorkspaceOAuthError::Forbidden));
    }

    #[tokio::test]
    async fn ensure_valid_workspace_token_returns_connection_without_refresh() {
        let workspace_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let key = Arc::new(vec![11u8; 32]);
        let expires_at = OffsetDateTime::now_utc() + Duration::minutes(5);
        let encrypted_access = encrypt_secret(&key, "existing-access").unwrap();
        let encrypted_refresh = encrypt_secret(&key, "existing-refresh").unwrap();
        let token_id = Uuid::new_v4();

        let workspace_repo = Arc::new(InMemoryWorkspaceRepo::new());
        {
            let mut guard = workspace_repo.connection.lock().unwrap();
            *guard = Some(WorkspaceConnection {
                id: connection_id,
                connection_id: Some(token_id),
                workspace_id,
                created_by: user_id,
                owner_user_id: user_id,
                user_oauth_token_id: Some(token_id),
                provider: ConnectedOAuthProvider::Google,
                access_token: encrypted_access,
                refresh_token: encrypted_refresh,
                expires_at,
                account_email: "user@example.com".into(),
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                metadata: serde_json::json!({}),
                slack_team_id: None,
                bot_user_id: None,
                incoming_webhook_url: None,
            });
        }

        let user_repo = Arc::new(InMemoryUserRepo {
            token: Mutex::new(None),
            shared_flag: Mutex::new(false),
        });

        let oauth_accounts = OAuthAccountService::test_stub();
        let workspace_token_refresher: Arc<dyn WorkspaceTokenRefresher> =
            oauth_accounts.clone() as Arc<dyn WorkspaceTokenRefresher>;
        let service = WorkspaceOAuthService::new(
            user_repo,
            noop_membership_repo(),
            workspace_repo,
            workspace_token_refresher,
            key,
        );

        let connection = service
            .ensure_valid_workspace_token(connection_id)
            .await
            .expect("connection exists");

        assert_eq!(connection.id, connection_id);
        assert_eq!(connection.workspace_id, workspace_id);
        assert_eq!(connection.provider, ConnectedOAuthProvider::Google);
        assert_eq!(connection.access_token, "existing-access");
        assert_eq!(connection.refresh_token, "existing-refresh");
    }

    #[tokio::test]
    async fn ensure_valid_workspace_token_refreshes_when_expired() {
        let workspace_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let key = Arc::new(vec![13u8; 32]);
        let expired_at = OffsetDateTime::now_utc() + Duration::seconds(10);
        let encrypted_access = encrypt_secret(&key, "stale-access").unwrap();
        let encrypted_refresh = encrypt_secret(&key, "stale-refresh").unwrap();
        let token_id = Uuid::new_v4();

        let workspace_repo = Arc::new(InMemoryWorkspaceRepo::new());
        {
            let mut guard = workspace_repo.connection.lock().unwrap();
            *guard = Some(WorkspaceConnection {
                id: connection_id,
                connection_id: Some(token_id),
                workspace_id,
                created_by: user_id,
                owner_user_id: user_id,
                user_oauth_token_id: Some(token_id),
                provider: ConnectedOAuthProvider::Google,
                access_token: encrypted_access,
                refresh_token: encrypted_refresh,
                expires_at: expired_at,
                account_email: "workspace@example.com".into(),
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                metadata: serde_json::json!({}),
                slack_team_id: None,
                bot_user_id: None,
                incoming_webhook_url: None,
            });
        }

        let user_repo = Arc::new(InMemoryUserRepo {
            token: Mutex::new(None),
            shared_flag: Mutex::new(false),
        });

        let refreshed_tokens = AuthorizationTokens {
            access_token: "refreshed-access".into(),
            refresh_token: "refreshed-refresh".into(),
            expires_at: OffsetDateTime::now_utc() + Duration::hours(2),
            account_email: "workspace@example.com".into(),
            provider_user_id: None,
            notion: None,
            slack: None,
        };
        let refresher = RecordingTokenRefresher::without_delay(refreshed_tokens.clone());
        let service = WorkspaceOAuthService::new(
            user_repo,
            noop_membership_repo(),
            workspace_repo.clone(),
            Arc::new(refresher.clone()) as Arc<dyn WorkspaceTokenRefresher>,
            key.clone(),
        );

        let connection = service
            .ensure_valid_workspace_token(connection_id)
            .await
            .expect("refresh succeeds");

        assert_eq!(connection.access_token, "refreshed-access");
        assert_eq!(connection.refresh_token, "refreshed-refresh");
        assert!(connection.expires_at > expired_at);

        let calls = refresher.calls();
        assert_eq!(calls, vec!["stale-refresh".to_string()]);

        let update_calls = *workspace_repo.update_calls.lock().unwrap();
        assert_eq!(update_calls, 1);
    }

    #[tokio::test]
    async fn ensure_valid_workspace_token_skips_slack_refresh() {
        let workspace_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let key = Arc::new(vec![15u8; 32]);
        let expired_at = OffsetDateTime::now_utc() - Duration::minutes(5);
        let encrypted_access = encrypt_secret(&key, "slack-old-access").unwrap();
        let encrypted_refresh = encrypt_secret(&key, "slack-old-refresh").unwrap();
        let token_id = Uuid::new_v4();

        let workspace_repo = Arc::new(InMemoryWorkspaceRepo::new());
        {
            let mut guard = workspace_repo.connection.lock().unwrap();
            *guard = Some(WorkspaceConnection {
                id: connection_id,
                connection_id: Some(token_id),
                workspace_id,
                created_by: user_id,
                owner_user_id: user_id,
                user_oauth_token_id: Some(token_id),
                provider: ConnectedOAuthProvider::Slack,
                access_token: encrypted_access,
                refresh_token: encrypted_refresh,
                expires_at: expired_at,
                account_email: "slack@example.com".into(),
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                metadata: serde_json::json!({}),
                slack_team_id: Some("T123".into()),
                bot_user_id: None,
                incoming_webhook_url: None,
            });
        }

        let user_repo = Arc::new(InMemoryUserRepo {
            token: Mutex::new(None),
            shared_flag: Mutex::new(false),
        });

        let refresher = RecordingTokenRefresher::without_delay(AuthorizationTokens {
            access_token: "slack-new-access".into(),
            refresh_token: "slack-new-refresh".into(),
            expires_at: OffsetDateTime::now_utc() + Duration::hours(4),
            account_email: "slack@example.com".into(),
            provider_user_id: Some("U123".into()),
            notion: None,
            slack: Some(
                crate::services::oauth::account_service::SlackOAuthMetadata {
                    team_id: Some("T123".into()),
                    bot_user_id: Some("B456".into()),
                    incoming_webhook_url: None,
                },
            ),
        });
        let service = WorkspaceOAuthService::new(
            user_repo,
            noop_membership_repo(),
            workspace_repo.clone(),
            Arc::new(refresher.clone()) as Arc<dyn WorkspaceTokenRefresher>,
            key.clone(),
        );

        let connection = service
            .ensure_valid_workspace_token(connection_id)
            .await
            .expect("slack token load succeeds");

        assert_eq!(connection.access_token, "slack-old-access");
        assert_eq!(connection.refresh_token, "slack-old-refresh");
        assert_eq!(connection.expires_at, expired_at);

        assert!(refresher.calls().is_empty());
        assert_eq!(*workspace_repo.update_calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn ensure_valid_workspace_token_skips_slack_refresh_without_mutating_personal_token() {
        let workspace_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let key = Arc::new(vec![31u8; 32]);
        let expired_at = OffsetDateTime::now_utc() - Duration::minutes(5);
        let encrypted_access = encrypt_secret(&key, "workspace-old-access").unwrap();
        let encrypted_refresh = encrypt_secret(&key, "workspace-old-refresh").unwrap();
        let token_id = Uuid::new_v4();

        let workspace_repo = Arc::new(InMemoryWorkspaceRepo::new());
        {
            let mut guard = workspace_repo.connection.lock().unwrap();
            *guard = Some(WorkspaceConnection {
                id: connection_id,
                connection_id: Some(token_id),
                workspace_id,
                created_by: user_id,
                owner_user_id: user_id,
                user_oauth_token_id: Some(token_id),
                provider: ConnectedOAuthProvider::Slack,
                access_token: encrypted_access,
                refresh_token: encrypted_refresh,
                expires_at: expired_at,
                account_email: "slack@example.com".into(),
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                metadata: serde_json::json!({}),
                slack_team_id: Some("T123".into()),
                bot_user_id: None,
                incoming_webhook_url: None,
            });
        }

        let personal_access = encrypt_secret(&key, "personal-access").unwrap();
        let personal_refresh = encrypt_secret(&key, "personal-refresh").unwrap();
        let personal_expires_at = OffsetDateTime::now_utc() + Duration::hours(2);
        let user_repo = Arc::new(InMemoryUserRepo {
            token: Mutex::new(Some(UserOAuthToken {
                id: Uuid::new_v4(),
                user_id,
                workspace_id: None,
                provider: ConnectedOAuthProvider::Slack,
                access_token: personal_access.clone(),
                refresh_token: personal_refresh.clone(),
                expires_at: personal_expires_at,
                account_email: "personal@example.com".into(),
                metadata: serde_json::json!({}),
                is_shared: true,
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
            })),
            shared_flag: Mutex::new(true),
        });

        let refresher = RecordingTokenRefresher::without_delay(AuthorizationTokens {
            access_token: "workspace-new-access".into(),
            refresh_token: "workspace-new-refresh".into(),
            expires_at: OffsetDateTime::now_utc() + Duration::hours(4),
            account_email: "slack@example.com".into(),
            provider_user_id: Some("U123".into()),
            notion: None,
            slack: Some(
                crate::services::oauth::account_service::SlackOAuthMetadata {
                    team_id: Some("T123".into()),
                    bot_user_id: Some("B456".into()),
                    incoming_webhook_url: None,
                },
            ),
        });
        let service = WorkspaceOAuthService::new(
            user_repo.clone(),
            noop_membership_repo(),
            workspace_repo.clone(),
            Arc::new(refresher.clone()) as Arc<dyn WorkspaceTokenRefresher>,
            key.clone(),
        );

        let connection = service
            .ensure_valid_workspace_token(connection_id)
            .await
            .expect("workspace refresh succeeds");

        assert_eq!(connection.access_token, "workspace-old-access");
        assert_eq!(connection.refresh_token, "workspace-old-refresh");
        assert_eq!(connection.expires_at, expired_at);

        let personal = user_repo
            .token
            .lock()
            .unwrap()
            .clone()
            .expect("personal token should remain");
        assert_eq!(personal.access_token, personal_access);
        assert_eq!(personal.refresh_token, personal_refresh);
        assert_eq!(personal.expires_at, personal_expires_at);
        assert!(*user_repo.shared_flag.lock().unwrap());
        assert!(refresher.calls().is_empty());
    }

    #[tokio::test]
    async fn ensure_valid_workspace_token_rejects_personal_slack_token_id() {
        let user_id = Uuid::new_v4();
        let token_id = Uuid::new_v4();
        let key = Arc::new(vec![33u8; 32]);

        let user_repo = Arc::new(InMemoryUserRepo {
            token: Mutex::new(Some(UserOAuthToken {
                id: token_id,
                user_id,
                workspace_id: None,
                provider: ConnectedOAuthProvider::Slack,
                access_token: String::new(),
                refresh_token: String::new(),
                expires_at: OffsetDateTime::now_utc(),
                account_email: "personal@example.com".into(),
                metadata: serde_json::json!({}),
                is_shared: false,
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
            })),
            shared_flag: Mutex::new(false),
        });
        let workspace_repo = Arc::new(InMemoryWorkspaceRepo::new());

        let service = WorkspaceOAuthService::new(
            user_repo,
            noop_membership_repo(),
            workspace_repo,
            OAuthAccountService::test_stub() as Arc<dyn WorkspaceTokenRefresher>,
            key,
        );

        let err = service
            .ensure_valid_workspace_token(token_id)
            .await
            .expect_err("personal token id should be rejected");

        assert!(matches!(err, WorkspaceOAuthError::NotFound));
    }

    #[tokio::test]
    async fn ensure_valid_workspace_token_returns_not_found_when_missing() {
        let connection_id = Uuid::new_v4();
        let key = Arc::new(vec![17u8; 32]);

        let service = WorkspaceOAuthService::new(
            Arc::new(InMemoryUserRepo {
                token: Mutex::new(None),
                shared_flag: Mutex::new(false),
            }),
            noop_membership_repo(),
            Arc::new(InMemoryWorkspaceRepo::new()),
            OAuthAccountService::test_stub() as Arc<dyn WorkspaceTokenRefresher>,
            key,
        );

        let err = service
            .ensure_valid_workspace_token(connection_id)
            .await
            .expect_err("missing connection should be not found");

        assert!(matches!(err, WorkspaceOAuthError::NotFound));
    }

    #[tokio::test]
    async fn ensure_valid_workspace_token_refreshes_once_with_concurrent_calls() {
        let workspace_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let key = Arc::new(vec![19u8; 32]);
        let expired_at = OffsetDateTime::now_utc() - Duration::minutes(5);
        let encrypted_access = encrypt_secret(&key, "old-access").unwrap();
        let encrypted_refresh = encrypt_secret(&key, "old-refresh").unwrap();
        let token_id = Uuid::new_v4();

        let workspace_repo = Arc::new(InMemoryWorkspaceRepo::new());
        {
            let mut guard = workspace_repo.connection.lock().unwrap();
            *guard = Some(WorkspaceConnection {
                id: connection_id,
                connection_id: Some(token_id),
                workspace_id,
                created_by: user_id,
                owner_user_id: user_id,
                user_oauth_token_id: Some(token_id),
                provider: ConnectedOAuthProvider::Google,
                access_token: encrypted_access,
                refresh_token: encrypted_refresh,
                expires_at: expired_at,
                account_email: "workspace@example.com".into(),
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                metadata: serde_json::json!({}),
                slack_team_id: None,
                bot_user_id: None,
                incoming_webhook_url: None,
            });
        }

        let user_repo = Arc::new(InMemoryUserRepo {
            token: Mutex::new(None),
            shared_flag: Mutex::new(false),
        });

        let refreshed_tokens = AuthorizationTokens {
            access_token: "next-access".into(),
            refresh_token: "next-refresh".into(),
            expires_at: OffsetDateTime::now_utc() + Duration::hours(3),
            account_email: "workspace@example.com".into(),
            provider_user_id: None,
            notion: None,
            slack: None,
        };
        let refresher = RecordingTokenRefresher::new(refreshed_tokens.clone());
        let service = Arc::new(WorkspaceOAuthService::new(
            user_repo,
            noop_membership_repo(),
            workspace_repo.clone(),
            Arc::new(refresher.clone()) as Arc<dyn WorkspaceTokenRefresher>,
            key,
        ));

        let svc1 = service.clone();
        let svc2 = service.clone();

        let (res1, res2) = tokio::join!(
            svc1.ensure_valid_workspace_token(connection_id),
            svc2.ensure_valid_workspace_token(connection_id),
        );

        let conn1 = res1.expect("first call succeeds");
        let conn2 = res2.expect("second call succeeds");

        assert_eq!(conn1.access_token, "next-access");
        assert_eq!(conn2.access_token, "next-access");
        assert_eq!(conn1.refresh_token, "next-refresh");
        assert_eq!(conn2.refresh_token, "next-refresh");

        let calls = refresher.calls();
        assert_eq!(calls, vec!["old-refresh".to_string()]);

        let update_calls = *workspace_repo.update_calls.lock().unwrap();
        assert_eq!(update_calls, 1);
    }

    #[tokio::test]
    async fn ensure_valid_workspace_token_removes_connection_when_revoked() {
        let workspace_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let key = Arc::new(vec![23u8; 32]);
        let expired_at = OffsetDateTime::now_utc() - Duration::minutes(2);
        let token_id = Uuid::new_v4();

        let encrypted_access = encrypt_secret(&key, "revoked-access").unwrap();
        let encrypted_refresh = encrypt_secret(&key, "revoked-refresh").unwrap();

        let workspace_repo = Arc::new(InMemoryWorkspaceRepo::new());
        {
            let mut guard = workspace_repo.connection.lock().unwrap();
            *guard = Some(WorkspaceConnection {
                id: connection_id,
                connection_id: Some(token_id),
                workspace_id,
                created_by: user_id,
                owner_user_id: user_id,
                user_oauth_token_id: Some(token_id),
                provider: ConnectedOAuthProvider::Google,
                access_token: encrypted_access,
                refresh_token: encrypted_refresh,
                expires_at: expired_at,
                account_email: "workspace@example.com".into(),
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                metadata: serde_json::json!({}),
                slack_team_id: None,
                bot_user_id: None,
                incoming_webhook_url: None,
            });
        }

        let user_repo = Arc::new(InMemoryUserRepo {
            token: Mutex::new(Some(UserOAuthToken {
                id: token_id,
                user_id,
                workspace_id: None,
                provider: ConnectedOAuthProvider::Google,
                access_token: String::new(),
                refresh_token: String::new(),
                expires_at: OffsetDateTime::now_utc(),
                account_email: "user@example.com".into(),
                metadata: serde_json::json!({}),
                is_shared: true,
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
            })),
            shared_flag: Mutex::new(true),
        });

        let service = WorkspaceOAuthService::new(
            user_repo.clone(),
            noop_membership_repo(),
            workspace_repo.clone(),
            Arc::new(RevokingTokenRefresher) as Arc<dyn WorkspaceTokenRefresher>,
            key,
        );

        let err = service
            .ensure_valid_workspace_token(connection_id)
            .await
            .expect_err("revoked token should bubble up error");

        match err {
            WorkspaceOAuthError::OAuth(OAuthAccountError::TokenRevoked { provider }) => {
                assert_eq!(provider, ConnectedOAuthProvider::Google);
            }
            other => panic!("unexpected error: {other:?}"),
        }

        assert!(workspace_repo.connection.lock().unwrap().is_none());
        assert!(!*user_repo.shared_flag.lock().unwrap());
    }

    #[tokio::test]
    async fn ensure_valid_workspace_token_skips_slack_revocation_checks() {
        let workspace_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let key = Arc::new(vec![29u8; 32]);
        let expired_at = OffsetDateTime::now_utc() - Duration::minutes(2);
        let token_id = Uuid::new_v4();

        let encrypted_access = encrypt_secret(&key, "revoked-slack-access").unwrap();
        let encrypted_refresh = encrypt_secret(&key, "revoked-slack-refresh").unwrap();

        let workspace_repo = Arc::new(InMemoryWorkspaceRepo::new());
        {
            let mut guard = workspace_repo.connection.lock().unwrap();
            *guard = Some(WorkspaceConnection {
                id: connection_id,
                connection_id: Some(token_id),
                workspace_id,
                created_by: user_id,
                owner_user_id: user_id,
                user_oauth_token_id: Some(token_id),
                provider: ConnectedOAuthProvider::Slack,
                access_token: encrypted_access,
                refresh_token: encrypted_refresh,
                expires_at: expired_at,
                account_email: "slack@example.com".into(),
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                metadata: serde_json::json!({}),
                slack_team_id: Some("T123".into()),
                bot_user_id: None,
                incoming_webhook_url: None,
            });
        }

        let user_repo = Arc::new(InMemoryUserRepo {
            token: Mutex::new(Some(UserOAuthToken {
                id: token_id,
                user_id,
                workspace_id: None,
                provider: ConnectedOAuthProvider::Slack,
                access_token: String::new(),
                refresh_token: String::new(),
                expires_at: OffsetDateTime::now_utc(),
                account_email: "slack@example.com".into(),
                metadata: serde_json::json!({}),
                is_shared: true,
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
            })),
            shared_flag: Mutex::new(true),
        });

        let service = WorkspaceOAuthService::new(
            user_repo.clone(),
            noop_membership_repo(),
            workspace_repo.clone(),
            Arc::new(RevokingTokenRefresher) as Arc<dyn WorkspaceTokenRefresher>,
            key,
        );

        let connection = service
            .ensure_valid_workspace_token(connection_id)
            .await
            .expect("slack token load succeeds");

        assert_eq!(connection.access_token, "revoked-slack-access");
        assert_eq!(connection.refresh_token, "revoked-slack-refresh");
        assert_eq!(connection.expires_at, expired_at);

        assert!(workspace_repo.connection.lock().unwrap().is_some());
        assert!(*user_repo.shared_flag.lock().unwrap());
    }

    #[tokio::test]
    async fn purge_member_connections_deletes_records_and_marks_tokens() {
        let workspace_id = Uuid::new_v4();
        let removed_user_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let key = Arc::new(vec![21u8; 32]);

        let user_repo = Arc::new(RecordingUserRepo::new());
        let google_token_id = user_repo.set_token(ConnectedOAuthProvider::Google, removed_user_id);
        let slack_token_id = user_repo.set_token(ConnectedOAuthProvider::Slack, removed_user_id);

        let google_connection = workspace_connection_record(
            workspace_id,
            removed_user_id,
            ConnectedOAuthProvider::Google,
            Some(google_token_id),
        );
        let slack_connection = workspace_connection_record(
            workspace_id,
            removed_user_id,
            ConnectedOAuthProvider::Slack,
            Some(slack_token_id),
        );
        let workspace_repo = Arc::new(RecordingWorkspaceRepo::with_connections(vec![
            google_connection.clone(),
            slack_connection.clone(),
        ]));

        let service = WorkspaceOAuthService::new(
            user_repo.clone(),
            noop_membership_repo(),
            workspace_repo.clone(),
            OAuthAccountService::test_stub() as Arc<dyn WorkspaceTokenRefresher>,
            key,
        );

        service
            .purge_member_connections(workspace_id, removed_user_id, actor_id)
            .await
            .expect("purge should succeed");

        let mut deleted = workspace_repo.deleted();
        deleted.sort();
        let mut expected = vec![google_connection.id, slack_connection.id];
        expected.sort();
        assert_eq!(deleted, expected);

        assert_eq!(
            user_repo.marks(),
            vec![
                (removed_user_id, ConnectedOAuthProvider::Google, false),
                (removed_user_id, ConnectedOAuthProvider::Slack, false)
            ]
        );

        let events = workspace_repo.events();
        assert_eq!(events.len(), 2);
        for event in events {
            assert_eq!(event.workspace_id, workspace_id);
            assert_eq!(event.actor_id, actor_id);
            assert_eq!(event.event_type, WORKSPACE_AUDIT_EVENT_CONNECTION_UNSHARED);
        }
    }

    #[tokio::test]
    async fn purge_member_connections_succeeds_when_token_missing() {
        let workspace_id = Uuid::new_v4();
        let removed_user_id = Uuid::new_v4();
        let actor_id = Uuid::new_v4();
        let key = Arc::new(vec![17u8; 32]);

        let connection = workspace_connection_record(
            workspace_id,
            removed_user_id,
            ConnectedOAuthProvider::Slack,
            None,
        );
        let workspace_repo = Arc::new(RecordingWorkspaceRepo::with_connections(vec![
            connection.clone()
        ]));

        let user_repo = Arc::new(RecordingUserRepo::new());
        user_repo.fail_for(ConnectedOAuthProvider::Slack);

        let service = WorkspaceOAuthService::new(
            user_repo.clone(),
            noop_membership_repo(),
            workspace_repo.clone(),
            OAuthAccountService::test_stub() as Arc<dyn WorkspaceTokenRefresher>,
            key,
        );

        service
            .purge_member_connections(workspace_id, removed_user_id, actor_id)
            .await
            .expect("purge should ignore missing token");

        assert_eq!(workspace_repo.deleted(), vec![connection.id]);
        assert_eq!(
            user_repo.marks(),
            vec![(removed_user_id, ConnectedOAuthProvider::Slack, false)]
        );
    }

    #[tokio::test]
    async fn promote_connection_with_token_succeeds_with_explicit_token_id_with_multiple_tokens() {
        let workspace_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let key = Arc::new(vec![31u8; 32]);
        let now = OffsetDateTime::now_utc();

        let token_a = UserOAuthToken {
            id: Uuid::new_v4(),
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Google,
            access_token: encrypt_secret(&key, "access-a").unwrap(),
            refresh_token: encrypt_secret(&key, "refresh-a").unwrap(),
            expires_at: now + Duration::hours(1),
            account_email: "a@example.com".into(),
            metadata: serde_json::json!({}),
            is_shared: false,
            created_at: now,
            updated_at: now,
        };

        let token_b = UserOAuthToken {
            id: Uuid::new_v4(),
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Google,
            access_token: encrypt_secret(&key, "access-b").unwrap(),
            refresh_token: encrypt_secret(&key, "refresh-b").unwrap(),
            expires_at: now + Duration::hours(2),
            account_email: "b@example.com".into(),
            metadata: serde_json::json!({}),
            is_shared: false,
            created_at: now,
            updated_at: now,
        };

        let user_repo = Arc::new(MultiTokenUserRepo::new(vec![
            token_a.clone(),
            token_b.clone(),
        ]));
        let workspace_repo = Arc::new(RecordingWorkspaceRepo::default());
        let service = WorkspaceOAuthService::new(
            user_repo.clone(),
            noop_membership_repo(),
            workspace_repo.clone(),
            OAuthAccountService::test_stub() as Arc<dyn WorkspaceTokenRefresher>,
            key.clone(),
        );

        let connection = service
            .promote_connection_with_token(
                workspace_id,
                user_id,
                ConnectedOAuthProvider::Google,
                Some(token_b.id),
            )
            .await
            .expect("promotion succeeds");

        assert_eq!(connection.user_oauth_token_id, Some(token_b.id));
        assert_eq!(connection.access_token, token_b.access_token);
        assert_eq!(connection.refresh_token, token_b.refresh_token);

        let tokens = user_repo.tokens();
        let shared_for_b = tokens
            .iter()
            .find(|token| token.id == token_b.id)
            .expect("token b present");
        let shared_for_a = tokens
            .iter()
            .find(|token| token.id == token_a.id)
            .expect("token a present");

        assert!(shared_for_b.is_shared);
        assert!(!shared_for_a.is_shared);
    }

    #[tokio::test]
    async fn promote_connection_with_token_fails_when_no_token_id_supplied() {
        let workspace_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let key = Arc::new(vec![42u8; 32]);

        let user_repo = Arc::new(InMemoryUserRepo {
            token: Mutex::new(Some(UserOAuthToken {
                id: Uuid::new_v4(),
                user_id,
                workspace_id: None,
                provider: ConnectedOAuthProvider::Google,
                access_token: encrypt_secret(&key, "access").unwrap(),
                refresh_token: encrypt_secret(&key, "refresh").unwrap(),
                expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
                account_email: "user@example.com".into(),
                metadata: serde_json::json!({}),
                is_shared: false,
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
            })),
            shared_flag: Mutex::new(false),
        });
        let workspace_repo = Arc::new(RecordingWorkspaceRepo::default());
        let service = WorkspaceOAuthService::new(
            user_repo.clone(),
            noop_membership_repo(),
            workspace_repo.clone(),
            OAuthAccountService::test_stub() as Arc<dyn WorkspaceTokenRefresher>,
            key,
        );

        let err = service
            .promote_connection_with_token(
                workspace_id,
                user_id,
                ConnectedOAuthProvider::Google,
                None,
            )
            .await
            .expect_err("promotion should fail when no token ID supplied");

        assert!(matches!(err, WorkspaceOAuthError::NotFound));
    }

    #[tokio::test]
    async fn promote_connection_with_token_fails_for_slack() {
        let workspace_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let key = Arc::new(vec![99u8; 32]);
        let token_id = Uuid::new_v4();

        let user_repo = Arc::new(InMemoryUserRepo {
            token: Mutex::new(Some(UserOAuthToken {
                id: token_id,
                user_id,
                workspace_id: None,
                provider: ConnectedOAuthProvider::Google,
                access_token: encrypt_secret(&key, "access").unwrap(),
                refresh_token: encrypt_secret(&key, "refresh").unwrap(),
                expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
                account_email: "user@example.com".into(),
                metadata: serde_json::json!({}),
                is_shared: false,
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
            })),
            shared_flag: Mutex::new(false),
        });
        let workspace_repo = Arc::new(RecordingWorkspaceRepo::default());
        let service = WorkspaceOAuthService::new(
            user_repo.clone(),
            noop_membership_repo(),
            workspace_repo.clone(),
            OAuthAccountService::test_stub() as Arc<dyn WorkspaceTokenRefresher>,
            key,
        );

        let err = service
            .promote_connection_with_token(
                workspace_id,
                user_id,
                ConnectedOAuthProvider::Slack,
                Some(token_id),
            )
            .await
            .expect_err("promotion should fail for slack");

        assert!(matches!(err, WorkspaceOAuthError::SlackInstallRequired));
    }
}
