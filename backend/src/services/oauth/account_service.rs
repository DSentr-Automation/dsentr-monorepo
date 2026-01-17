use std::sync::Arc;

use base64::Engine as _;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use tracing::{info, warn};
use uuid::Uuid;

use crate::config::{OAuthProviderConfig, OAuthSettings};
use crate::db::oauth_token_repository::{NewUserOAuthToken, UserOAuthTokenRepository};
#[cfg(test)]
use crate::db::postgres_oauth_token_repository::PostgresUserOAuthTokenRepository;
#[cfg(test)]
use crate::db::workspace_connection_repository::NoopWorkspaceConnectionRepository;
use crate::db::workspace_connection_repository::WorkspaceConnectionRepository;
use crate::models::oauth_token::{ConnectedOAuthProvider, UserOAuthToken};
#[cfg(test)]
use crate::models::oauth_token::{WorkspaceAuditEvent, WorkspaceConnection};
#[cfg(test)]
use crate::state::test_pg_pool;
use crate::utils::encryption::{decrypt_secret, encrypt_secret, EncryptionError};
#[cfg(test)]
use sqlx::{query, Row};

const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const GOOGLE_USERINFO_URL: &str = "https://openidconnect.googleapis.com/v1/userinfo";
const GOOGLE_REVOCATION_URL: &str = "https://oauth2.googleapis.com/revoke";
const MICROSOFT_TOKEN_URL: &str = "https://login.microsoftonline.com/common/oauth2/v2.0/token";
const MICROSOFT_USERINFO_URL: &str = "https://graph.microsoft.com/v1.0/me";
const MICROSOFT_REVOCATION_URL: &str =
    "https://login.microsoftonline.com/common/oauth2/v2.0/logout";
const SLACK_TOKEN_URL: &str = "https://slack.com/api/oauth.v2.access";
const SLACK_USER_INFO_URL: &str = "https://slack.com/api/users.info";
const SLACK_REVOCATION_URL: &str = "https://slack.com/api/auth.revoke";
const ASANA_TOKEN_URL: &str = "https://app.asana.com/-/oauth_token";
const ASANA_USERINFO_URL: &str = "https://app.asana.com/api/1.0/users/me";
const ASANA_REVOCATION_URL: &str = "https://app.asana.com/-/oauth_revoke";
const NOTION_TOKEN_URL: &str = "https://api.notion.com/v1/oauth/token";
const NOTION_ACCESS_TTL_DAYS: i64 = 3650;

#[derive(Debug, Clone)]
pub struct StoredOAuthToken {
    pub id: Uuid,
    pub provider: ConnectedOAuthProvider,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: OffsetDateTime,
    pub account_email: String,
    pub is_shared: bool,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone)]
pub struct AuthorizationTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: OffsetDateTime,
    pub account_email: String,
    pub provider_user_id: Option<String>,
    pub slack: Option<SlackOAuthMetadata>,
    pub notion: Option<NotionOAuthMetadata>,
}

#[derive(Debug, Clone, Default)]
pub struct SlackOAuthMetadata {
    pub team_id: Option<String>,
    pub bot_user_id: Option<String>,
    pub incoming_webhook_url: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NotionOAuthMetadata {
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub workspace_name: Option<String>,
    #[serde(default)]
    pub bot_id: Option<String>,
    #[serde(default)]
    pub owner_type: Option<String>,
    #[serde(default)]
    pub owner_id: Option<String>,
    #[serde(default)]
    pub owner_name: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EncryptedSlackOAuthMetadata {
    pub team_id: Option<String>,
    pub bot_user_id: Option<String>,
    pub incoming_webhook_url: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OAuthTokenMetadata {
    #[serde(default)]
    pub slack: Option<EncryptedSlackOAuthMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_user_id: Option<String>,
    #[serde(default)]
    pub notion: Option<NotionOAuthMetadata>,
}

#[derive(Debug, Clone)]
struct SlackExchangeTokens {
    user_access_token: String,
    user_refresh_token: String,
    user_expires_in: Option<i64>,
    user_expiration: Option<i64>,
    bot_access_token: String,
    bot_refresh_token: String,
    bot_expires_in: Option<i64>,
    user_id: String,
    team_id: String,
    bot_user_id: Option<String>,
    incoming_webhook_url: Option<String>,
    account_email: String,
}

struct SlackAuthTestResult {
    team_id: String,
    user_id: Option<String>,
}

#[derive(Error, Debug)]
pub enum OAuthAccountError {
    #[error("token not found")]
    NotFound,
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("encryption error: {0}")]
    Encryption(#[from] EncryptionError),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("invalid provider response: {0}")]
    InvalidResponse(String),
    #[error("refresh token missing in response")]
    MissingRefreshToken,
    #[error("{provider:?} account email is not verified")]
    EmailNotVerified { provider: ConnectedOAuthProvider },
    #[error("oauth token revoked for {provider:?}")]
    TokenRevoked { provider: ConnectedOAuthProvider },
    #[error("token refresh not supported for {provider:?}")]
    RefreshNotSupported { provider: ConnectedOAuthProvider },
}

#[derive(Clone)]
pub struct OAuthAccountService {
    repo: Arc<dyn UserOAuthTokenRepository>,
    workspace_connections: Arc<dyn WorkspaceConnectionRepository>,
    encryption_key: Arc<Vec<u8>>,
    client: Arc<Client>,
    google: OAuthProviderConfig,
    microsoft: OAuthProviderConfig,
    slack: OAuthProviderConfig,
    asana: OAuthProviderConfig,
    notion: OAuthProviderConfig,
    bitly: OAuthProviderConfig,
    raindrop: OAuthProviderConfig,
    #[cfg(test)]
    refresh_override: Option<Arc<RefreshOverride>>,
    #[cfg(test)]
    revocation_override: Option<Arc<RevocationOverride>>,
    #[cfg(test)]
    endpoint_overrides: TestEndpointOverrides,
}

impl OAuthAccountService {
    pub fn new(
        repo: Arc<dyn UserOAuthTokenRepository>,
        workspace_connections: Arc<dyn WorkspaceConnectionRepository>,
        encryption_key: Arc<Vec<u8>>,
        client: Arc<Client>,
        settings: &OAuthSettings,
    ) -> Self {
        Self {
            repo,
            workspace_connections,
            encryption_key,
            client,
            google: settings.google.clone(),
            microsoft: settings.microsoft.clone(),
            slack: settings.slack.clone(),
            asana: settings.asana.clone(),
            notion: settings.notion.clone(),
            bitly: settings.bitly.clone(),
            raindrop: settings.raindrop.clone(),
            #[cfg(test)]
            refresh_override: None,
            #[cfg(test)]
            revocation_override: None,
            #[cfg(test)]
            endpoint_overrides: TestEndpointOverrides::default(),
        }
    }

    #[cfg(test)]
    fn google_token_url(&self) -> &str {
        self.endpoint_overrides
            .google_token_url
            .as_deref()
            .unwrap_or(GOOGLE_TOKEN_URL)
    }

    #[cfg(not(test))]
    fn google_token_url(&self) -> &str {
        GOOGLE_TOKEN_URL
    }

    #[cfg(test)]
    fn google_userinfo_url(&self) -> &str {
        self.endpoint_overrides
            .google_userinfo_url
            .as_deref()
            .unwrap_or(GOOGLE_USERINFO_URL)
    }

    #[cfg(not(test))]
    fn google_userinfo_url(&self) -> &str {
        GOOGLE_USERINFO_URL
    }

    #[cfg(test)]
    fn google_revocation_url(&self) -> &str {
        self.endpoint_overrides
            .google_revocation_url
            .as_deref()
            .unwrap_or(GOOGLE_REVOCATION_URL)
    }

    #[cfg(not(test))]
    fn google_revocation_url(&self) -> &str {
        GOOGLE_REVOCATION_URL
    }

    #[cfg(test)]
    fn slack_token_url(&self) -> &str {
        self.endpoint_overrides
            .slack_token_url
            .as_deref()
            .unwrap_or(SLACK_TOKEN_URL)
    }

    #[cfg(not(test))]
    fn slack_token_url(&self) -> &str {
        SLACK_TOKEN_URL
    }

    #[cfg(test)]
    fn slack_userinfo_url(&self) -> &str {
        self.endpoint_overrides
            .slack_userinfo_url
            .as_deref()
            .unwrap_or(SLACK_USER_INFO_URL)
    }

    #[cfg(not(test))]
    fn slack_userinfo_url(&self) -> &str {
        SLACK_USER_INFO_URL
    }

    #[cfg(test)]
    fn notion_token_url(&self) -> &str {
        self.endpoint_overrides
            .notion_token_url
            .as_deref()
            .unwrap_or(NOTION_TOKEN_URL)
    }

    #[cfg(not(test))]
    fn notion_token_url(&self) -> &str {
        NOTION_TOKEN_URL
    }

    #[cfg(test)]
    pub fn set_refresh_override<F>(&mut self, override_fn: Option<Arc<F>>)
    where
        F: for<'a> Fn(
                ConnectedOAuthProvider,
                &'a str,
            ) -> Result<AuthorizationTokens, OAuthAccountError>
            + Send
            + Sync
            + 'static,
    {
        self.refresh_override = override_fn.map(|func| func as Arc<RefreshOverride>);
    }

    #[cfg(test)]
    pub fn set_revocation_override<F>(&mut self, override_fn: Option<Arc<F>>)
    where
        F: for<'a> Fn(ConnectedOAuthProvider, &'a str) -> Result<(), OAuthAccountError>
            + Send
            + Sync
            + 'static,
    {
        self.revocation_override = override_fn.map(|func| func as Arc<RevocationOverride>);
    }

    #[cfg(test)]
    pub fn set_google_endpoint_overrides(
        &mut self,
        token_url: impl Into<String>,
        userinfo_url: impl Into<String>,
        revocation_url: Option<&str>,
    ) {
        self.endpoint_overrides.google_token_url = Some(token_url.into());
        self.endpoint_overrides.google_userinfo_url = Some(userinfo_url.into());
        self.endpoint_overrides.google_revocation_url = revocation_url.map(|url| url.to_string());
    }

    #[cfg(test)]
    pub fn set_slack_endpoint_overrides(
        &mut self,
        token_url: impl Into<String>,
        userinfo_url: impl Into<String>,
    ) {
        self.endpoint_overrides.slack_token_url = Some(token_url.into());
        self.endpoint_overrides.slack_userinfo_url = Some(userinfo_url.into());
    }

    #[cfg(test)]
    pub fn set_notion_endpoint_override(&mut self, token_url: impl Into<String>) {
        self.endpoint_overrides.notion_token_url = Some(token_url.into());
    }

    pub fn google_scopes(&self) -> &'static str {
        // `openid email` lets us call the Google OpenID Connect userinfo endpoint and confirm the
        // caller's verified email address. The Sheets scope is required by workflow actions that
        // append rows via the Google Sheets API.
        "openid email https://www.googleapis.com/auth/spreadsheets"
    }

    pub fn microsoft_scopes(&self) -> &'static str {
        // `offline_access` gives refresh tokens, `User.Read` satisfies Microsoft Graph sign-in,
        // and the Teams scopes cover listing joined teams, channels, channel members, and sending
        // delegated channel messages from workflow actions.
        "offline_access User.Read Team.ReadBasic.All Channel.ReadBasic.All ChannelMember.Read.All ChannelMessage.Send"
    }

    pub fn slack_bot_scopes(&self) -> &'static str {
        // Bot token scopes for listing channels and sending messages as the app bot user.
        "channels:read,groups:read,im:read,mpim:read,chat:write,chat:write.public,incoming-webhook"
    }

    pub fn slack_scopes(&self) -> &'static str {
        // User token scopes for delegated post-as-user and user resolution.
        "chat:write,channels:read,groups:read,im:read,mpim:read,users:read,users:read.email"
    }

    pub fn asana_scopes(&self) -> &'static str {
        // `default` grants standard Asana app permissions; `email` ensures the user profile
        // includes an email address for auditing and display in the UI.
        "default email"
    }

    pub fn bitly_scopes(&self) -> &'static str {
        "bitly.read bitly.write"
    }

    pub fn raindrop_scopes(&self) -> &'static str {
        "read write"
    }

    pub async fn save_authorization(
        &self,
        user_id: Uuid,
        provider: ConnectedOAuthProvider,
        tokens: AuthorizationTokens,
    ) -> Result<StoredOAuthToken, OAuthAccountError> {
        self.store_authorization(user_id, provider, None, tokens)
            .await
    }

    pub async fn save_authorization_deduped(
        &self,
        user_id: Uuid,
        provider: ConnectedOAuthProvider,
        tokens: AuthorizationTokens,
    ) -> Result<StoredOAuthToken, OAuthAccountError> {
        let matches = self
            .find_matching_personal_tokens(user_id, provider, &tokens)
            .await?;

        if matches.is_empty() {
            return self.save_authorization(user_id, provider, tokens).await;
        }

        if matches.len() > 1 {
            let matching_ids: Vec<Uuid> = matches.iter().map(|record| record.id).collect();
            warn!(
                %user_id,
                ?provider,
                matching_ids = ?matching_ids,
                "multiple personal oauth tokens matched the same identity"
            );
        }

        let selected = matches
            .iter()
            .max_by_key(|record| record.updated_at)
            .expect("matches is non-empty");

        self.save_authorization_for_connection(user_id, provider, selected.id, tokens)
            .await
    }

    pub async fn save_authorization_for_connection(
        &self,
        user_id: Uuid,
        provider: ConnectedOAuthProvider,
        token_id: Uuid,
        tokens: AuthorizationTokens,
    ) -> Result<StoredOAuthToken, OAuthAccountError> {
        let existing = self
            .repo
            .find_by_id(token_id)
            .await?
            .filter(|record| record.user_id == user_id && record.workspace_id.is_none())
            .ok_or(OAuthAccountError::NotFound)?;

        if existing.provider != provider {
            return Err(OAuthAccountError::NotFound);
        }

        self.store_authorization(user_id, provider, Some(existing), tokens)
            .await
    }

    async fn store_authorization(
        &self,
        user_id: Uuid,
        provider: ConnectedOAuthProvider,
        existing: Option<UserOAuthToken>,
        tokens: AuthorizationTokens,
    ) -> Result<StoredOAuthToken, OAuthAccountError> {
        let existing_id = existing.as_ref().map(|record| record.id);
        if let Some(existing) = existing.as_ref() {
            let stored = self.decrypt_record(existing.clone())?;
            self.revoke_existing_credentials(provider, &stored).await;
        }

        let encrypted_access = encrypt_secret(&self.encryption_key, &tokens.access_token)?;
        let encrypted_refresh = encrypt_secret(&self.encryption_key, &tokens.refresh_token)?;
        let provider_user_id = tokens
            .provider_user_id
            .as_deref()
            .and_then(normalize_provider_user_id);

        let encrypted_slack = tokens
            .slack
            .as_ref()
            .map(|slack| self.encrypt_slack_metadata(slack))
            .transpose()?
            .flatten();

        if let Some(slack) = encrypted_slack.as_ref() {
            tracing::info!(
                provider = "slack",
                has_incoming_webhook = slack.incoming_webhook_url.is_some(),
                "Persisting Slack OAuth metadata captured during authorization"
            );
        }

        let (merged_metadata, metadata_value) = merge_metadata_value(
            existing.as_ref().map(|record| &record.metadata),
            encrypted_slack.clone(),
            provider_user_id,
            tokens.notion.clone(),
        );

        let stored = if let Some(existing) = existing {
            self.repo
                .update_token(
                    existing.id,
                    NewUserOAuthToken {
                        user_id,
                        provider,
                        access_token: encrypted_access.clone(),
                        refresh_token: encrypted_refresh.clone(),
                        expires_at: tokens.expires_at,
                        account_email: tokens.account_email.clone(),
                        metadata: metadata_value,
                    },
                )
                .await?
        } else {
            self.repo
                .insert_token(NewUserOAuthToken {
                    user_id,
                    provider,
                    access_token: encrypted_access.clone(),
                    refresh_token: encrypted_refresh.clone(),
                    expires_at: tokens.expires_at,
                    account_email: tokens.account_email.clone(),
                    metadata: metadata_value,
                })
                .await?
        };

        if let Some(token_id) = existing_id {
            if !matches!(provider, ConnectedOAuthProvider::Slack) {
                self.propagate_workspace_token_update(
                    token_id,
                    provider,
                    encrypted_access,
                    encrypted_refresh,
                    tokens.expires_at,
                    tokens.account_email.clone(),
                    &merged_metadata,
                )
                .await;
            }
        }

        Ok(StoredOAuthToken {
            id: stored.id,
            provider,
            access_token: tokens.access_token,
            refresh_token: tokens.refresh_token,
            expires_at: stored.expires_at,
            account_email: stored.account_email,
            is_shared: stored.is_shared,
            updated_at: stored.updated_at,
        })
    }

    async fn find_matching_personal_tokens(
        &self,
        user_id: Uuid,
        provider: ConnectedOAuthProvider,
        tokens: &AuthorizationTokens,
    ) -> Result<Vec<UserOAuthToken>, OAuthAccountError> {
        let Some(provider_user_id) = tokens
            .provider_user_id
            .as_deref()
            .and_then(normalize_provider_user_id)
        else {
            return Ok(Vec::new());
        };

        let expected_team_id = if matches!(provider, ConnectedOAuthProvider::Slack) {
            tokens
                .slack
                .as_ref()
                .and_then(|slack| slack.team_id.as_deref())
                .and_then(normalize_provider_user_id)
        } else {
            None
        };

        if matches!(provider, ConnectedOAuthProvider::Slack) && expected_team_id.is_none() {
            return Ok(Vec::new());
        }

        let candidates = self
            .repo
            .list_by_user_and_provider(user_id, provider)
            .await?;

        let mut matches = Vec::new();
        for record in candidates {
            if record.workspace_id.is_some() {
                continue;
            }

            let metadata = parse_token_metadata(&record.metadata);
            let provider_match = metadata
                .provider_user_id
                .as_deref()
                .and_then(normalize_provider_user_id)
                .as_deref()
                == Some(provider_user_id.as_str());
            if !provider_match {
                continue;
            }

            if matches!(provider, ConnectedOAuthProvider::Slack) {
                let Some(team_id) = metadata
                    .slack
                    .as_ref()
                    .and_then(|slack| slack.team_id.as_deref())
                else {
                    continue;
                };
                let decrypted_team_id = decrypt_secret(&self.encryption_key, team_id)
                    .map_err(OAuthAccountError::Encryption)?;
                let Some(normalized_team_id) = normalize_provider_user_id(&decrypted_team_id)
                else {
                    continue;
                };
                if Some(normalized_team_id.as_str()) != expected_team_id.as_deref() {
                    continue;
                }
            }

            matches.push(record);
        }

        Ok(matches)
    }

    #[allow(clippy::too_many_arguments)]
    async fn propagate_workspace_token_update(
        &self,
        token_id: Uuid,
        provider: ConnectedOAuthProvider,
        encrypted_access: String,
        encrypted_refresh: String,
        expires_at: OffsetDateTime,
        account_email: String,
        metadata: &OAuthTokenMetadata,
    ) {
        let connections = match self
            .workspace_connections
            .find_by_source_token(token_id)
            .await
        {
            Ok(connections) => connections,
            Err(err) => {
                warn!(
                    ?err,
                    ?provider,
                    token_id = %token_id,
                    "failed to load workspace connections for oauth reconnect update"
                );
                return;
            }
        };

        if connections.is_empty() {
            return;
        }

        let bot_user_id = metadata
            .slack
            .as_ref()
            .and_then(|meta| meta.bot_user_id.clone());
        let slack_team_id = metadata
            .slack
            .as_ref()
            .and_then(|meta| meta.team_id.clone());
        let incoming_webhook_url = metadata
            .slack
            .as_ref()
            .and_then(|meta| meta.incoming_webhook_url.clone());

        for connection in connections {
            if let Err(err) = self
                .workspace_connections
                .update_tokens_for_connection(
                    connection.id,
                    encrypted_access.clone(),
                    encrypted_refresh.clone(),
                    expires_at,
                    account_email.clone(),
                    bot_user_id.clone(),
                    slack_team_id.clone(),
                    incoming_webhook_url.clone(),
                )
                .await
            {
                warn!(
                    ?err,
                    ?provider,
                    workspace_id = %connection.workspace_id,
                    connection_id = %connection.id,
                    "failed to propagate oauth reconnect tokens to workspace connection"
                );
            }
        }
    }

    pub async fn list_tokens(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<StoredOAuthToken>, OAuthAccountError> {
        let records = self.repo.list_tokens_for_user(user_id).await?;
        records
            .into_iter()
            .map(|record| self.decrypt_record(record))
            .collect()
    }

    // Defensive assertion used by routes to ensure that any personal tokens being
    // returned are in fact owned by the authenticated user. This cross-checks the
    // IDs by reloading from the repository using the (user_id, provider) pair.
    pub async fn assert_personal_tokens_owned_by(
        &self,
        user_id: Uuid,
        tokens: &[StoredOAuthToken],
    ) -> Result<(), OAuthAccountError> {
        for token in tokens.iter() {
            let Some(record) = self.repo.find_by_id(token.id).await? else {
                return Err(OAuthAccountError::NotFound);
            };
            if record.user_id != user_id || record.workspace_id.is_some() {
                return Err(OAuthAccountError::NotFound);
            }
        }
        Ok(())
    }

    pub async fn ensure_valid_access_token_for_connection(
        &self,
        user_id: Uuid,
        token_id: Uuid,
    ) -> Result<StoredOAuthToken, OAuthAccountError> {
        let record = self
            .repo
            .find_by_id(token_id)
            .await?
            .filter(|record| record.user_id == user_id && record.workspace_id.is_none())
            .ok_or(OAuthAccountError::NotFound)?;

        self.ensure_valid_access_token_from_record(record).await
    }

    pub async fn refresh_access_token_for_connection(
        &self,
        user_id: Uuid,
        token_id: Uuid,
    ) -> Result<StoredOAuthToken, OAuthAccountError> {
        let record = self
            .repo
            .find_by_id(token_id)
            .await?
            .filter(|record| record.user_id == user_id && record.workspace_id.is_none())
            .ok_or(OAuthAccountError::NotFound)?;

        let decrypted = self.decrypt_record(record.clone())?;
        self.refresh_record_tokens(record, decrypted).await
    }

    /// Load and parse the metadata for a personal token, verifying ownership.
    pub async fn load_personal_token_metadata(
        &self,
        user_id: Uuid,
        token_id: Uuid,
    ) -> Result<OAuthTokenMetadata, OAuthAccountError> {
        let record = self
            .repo
            .find_by_id(token_id)
            .await?
            .filter(|record| record.user_id == user_id && record.workspace_id.is_none())
            .ok_or(OAuthAccountError::NotFound)?;

        Ok(parse_token_metadata(&record.metadata))
    }

    async fn ensure_valid_access_token_from_record(
        &self,
        record: UserOAuthToken,
    ) -> Result<StoredOAuthToken, OAuthAccountError> {
        let decrypted = self.decrypt_record(record.clone())?;
        let refresh_deadline = OffsetDateTime::now_utc() + Duration::seconds(60);

        if decrypted.expires_at <= refresh_deadline {
            return self.refresh_record_tokens(record, decrypted).await;
        }

        Ok(decrypted)
    }

    async fn refresh_record_tokens(
        &self,
        record: UserOAuthToken,
        mut decrypted: StoredOAuthToken,
    ) -> Result<StoredOAuthToken, OAuthAccountError> {
        let refreshed = match self
            .refresh_access_token(record.provider, &decrypted.refresh_token)
            .await
        {
            Ok(tokens) => tokens,
            Err(err) => {
                if matches!(err, OAuthAccountError::TokenRevoked { .. }) {
                    self.repo.delete_token_by_id(record.id).await?;
                    self.workspace_connections
                        .mark_connections_stale_for_creator(record.user_id, record.provider)
                        .await?;
                }
                return Err(err);
            }
        };

        decrypted.access_token = refreshed.access_token.clone();
        decrypted.refresh_token = refreshed.refresh_token.clone();
        decrypted.expires_at = refreshed.expires_at;

        let encrypted_access = encrypt_secret(&self.encryption_key, &refreshed.access_token)?;
        let encrypted_refresh = encrypt_secret(&self.encryption_key, &refreshed.refresh_token)?;

        let encrypted_slack = refreshed
            .slack
            .as_ref()
            .map(|slack| self.encrypt_slack_metadata(slack))
            .transpose()?
            .flatten();

        let (merged_metadata, metadata_value) = merge_metadata_value(
            Some(&record.metadata),
            encrypted_slack.clone(),
            refreshed.provider_user_id.clone(),
            refreshed.notion.clone(),
        );

        let updated = self
            .repo
            .update_token(
                record.id,
                NewUserOAuthToken {
                    user_id: record.user_id,
                    provider: record.provider,
                    access_token: encrypted_access.clone(),
                    refresh_token: encrypted_refresh.clone(),
                    expires_at: refreshed.expires_at,
                    account_email: record.account_email.clone(),
                    metadata: metadata_value,
                },
            )
            .await?;

        decrypted.id = updated.id;
        decrypted.expires_at = updated.expires_at;
        decrypted.account_email = updated.account_email.clone();
        decrypted.is_shared = updated.is_shared;
        decrypted.updated_at = updated.updated_at;

        // Ensure Slack metadata updates are preserved alongside the refreshed tokens
        if merged_metadata.slack.is_some() && refreshed.slack.is_some() {
            tracing::debug!(
                provider = ?record.provider,
                token_id = %record.id,
                "refreshed Slack token with updated metadata for connection-scoped token"
            );
        }

        if !matches!(record.provider, ConnectedOAuthProvider::Slack) {
            match self
                .workspace_connections
                .find_by_source_token(record.id)
                .await
            {
                Ok(connections) => {
                    if !connections.is_empty() {
                        let bot_user_id = merged_metadata
                            .slack
                            .as_ref()
                            .and_then(|meta| meta.bot_user_id.clone());
                        let slack_team_id = merged_metadata
                            .slack
                            .as_ref()
                            .and_then(|meta| meta.team_id.clone());
                        let incoming_webhook_url = merged_metadata
                            .slack
                            .as_ref()
                            .and_then(|meta| meta.incoming_webhook_url.clone());

                        for connection in connections {
                            if let Err(err) = self
                                .workspace_connections
                                .update_tokens_for_connection(
                                    connection.id,
                                    encrypted_access.clone(),
                                    encrypted_refresh.clone(),
                                    refreshed.expires_at,
                                    record.account_email.clone(),
                                    bot_user_id.clone(),
                                    slack_team_id.clone(),
                                    incoming_webhook_url.clone(),
                                )
                                .await
                            {
                                warn!(
                                    ?err,
                                    provider = ?record.provider,
                                    workspace_id = %connection.workspace_id,
                                    connection_id = %connection.id,
                                    "failed to propagate refreshed personal token to workspace connection"
                                );
                            }
                        }
                    }
                }
                Err(err) => {
                    warn!(
                        ?err,
                        provider = ?record.provider,
                        token_id = %record.id,
                        "failed to load workspace connections for refreshed token"
                    );
                }
            }
        }

        Ok(decrypted)
    }

    pub async fn delete_tokens(
        &self,
        user_id: Uuid,
        provider: ConnectedOAuthProvider,
    ) -> Result<(), OAuthAccountError> {
        if let Some(existing) = self
            .repo
            .find_by_user_and_provider(user_id, provider)
            .await?
        {
            let decrypted = self.decrypt_record(existing.clone())?;
            self.revoke_existing_credentials(provider, &decrypted).await;
            self.repo.delete_token_by_id(existing.id).await?;
        }
        Ok(())
    }

    pub async fn delete_token_by_connection(
        &self,
        user_id: Uuid,
        token_id: Uuid,
    ) -> Result<(), OAuthAccountError> {
        let Some(existing) = self
            .repo
            .find_by_id(token_id)
            .await?
            .filter(|record| record.user_id == user_id && record.workspace_id.is_none())
        else {
            return Err(OAuthAccountError::NotFound);
        };

        let decrypted = self.decrypt_record(existing.clone())?;
        self.revoke_existing_credentials(existing.provider, &decrypted)
            .await;
        self.repo.delete_token_by_id(existing.id).await?;
        Ok(())
    }

    async fn revoke_personal_token_and_mark_stale(
        &self,
        user_id: Uuid,
        provider: ConnectedOAuthProvider,
        token_id: Option<Uuid>,
    ) -> Result<(), OAuthAccountError> {
        if let Some(id) = token_id {
            self.repo.delete_token_by_id(id).await?;
        } else {
            self.repo.delete_token(user_id, provider).await?;
        }

        if matches!(provider, ConnectedOAuthProvider::Slack) {
            return Ok(());
        }

        let stale_connections = self
            .workspace_connections
            .mark_connections_stale_for_creator(user_id, provider)
            .await?;

        if stale_connections.is_empty() {
            info!(
                %user_id,
                token_id = token_id.map(|id| id.to_string()),
                ?provider,
                "oauth token revoked with no shared workspace connections to update"
            );
        } else {
            let workspace_ids: Vec<Uuid> = stale_connections
                .iter()
                .map(|conn| conn.workspace_id)
                .collect();
            let connection_ids: Vec<Uuid> = stale_connections
                .iter()
                .map(|conn| conn.connection_id)
                .collect();
            warn!(
                %user_id,
                token_id = token_id.map(|id| id.to_string()),
                ?provider,
                workspace_ids = ?workspace_ids,
                connection_ids = ?connection_ids,
                connection_count = stale_connections.len(),
                "shared workspace oauth connections marked stale after personal token revocation"
            );
        }

        Ok(())
    }

    pub async fn handle_revoked_token(
        &self,
        user_id: Uuid,
        provider: ConnectedOAuthProvider,
    ) -> Result<(), OAuthAccountError> {
        if matches!(provider, ConnectedOAuthProvider::Slack) {
            return Err(OAuthAccountError::InvalidResponse(
                "Slack revocation requires a personal connection id".into(),
            ));
        }
        self.revoke_personal_token_and_mark_stale(user_id, provider, None)
            .await
    }

    pub async fn handle_revoked_token_by_connection(
        &self,
        user_id: Uuid,
        token_id: Uuid,
    ) -> Result<(), OAuthAccountError> {
        let Some(record) = self
            .repo
            .find_by_id(token_id)
            .await?
            .filter(|record| record.user_id == user_id && record.workspace_id.is_none())
        else {
            return Err(OAuthAccountError::NotFound);
        };

        self.revoke_personal_token_and_mark_stale(user_id, record.provider, Some(record.id))
            .await
    }

    pub async fn exchange_authorization_code(
        &self,
        provider: ConnectedOAuthProvider,
        code: &str,
    ) -> Result<AuthorizationTokens, OAuthAccountError> {
        match provider {
            ConnectedOAuthProvider::Google => self.exchange_google_code(code).await,
            ConnectedOAuthProvider::Microsoft => self.exchange_microsoft_code(code).await,
            ConnectedOAuthProvider::Slack => {
                let auth = self.exchange_slack_code(code).await?;
                Ok(auth)
            }
            ConnectedOAuthProvider::Asana => self.exchange_asana_code(code).await,
            ConnectedOAuthProvider::Notion => self.exchange_notion_code(code).await,
            ConnectedOAuthProvider::Bitly => self.exchange_bitly_code(code).await,
            ConnectedOAuthProvider::Raindrop => self.exchange_raindrop_code(code).await,
        }
    }

    pub async fn exchange_slack_install_tokens(
        &self,
        code: &str,
    ) -> Result<(AuthorizationTokens, AuthorizationTokens), OAuthAccountError> {
        let exchange = self.exchange_slack_code_raw(code).await?;
        if exchange.user_access_token.trim().is_empty() {
            return Err(OAuthAccountError::InvalidResponse(
                "Slack OAuth exchange missing user access token for auth.test".into(),
            ));
        }
        let SlackAuthTestResult { team_id, user_id } =
            self.slack_auth_test(&exchange.user_access_token).await?;
        let personal_expires_at =
            slack_expiration(exchange.user_expires_in, exchange.user_expiration)?;
        let workspace_expires_at = slack_expiration(exchange.bot_expires_in, None)?;
        let personal_slack_meta = SlackOAuthMetadata {
            team_id: Some(team_id),
            bot_user_id: exchange.bot_user_id.clone(),
            incoming_webhook_url: exchange.incoming_webhook_url.clone(),
        };
        let workspace_slack_meta = SlackOAuthMetadata {
            team_id: Some(exchange.team_id.clone()),
            bot_user_id: exchange.bot_user_id.clone(),
            incoming_webhook_url: exchange.incoming_webhook_url.clone(),
        };
        let provider_user_id = user_id.unwrap_or(exchange.user_id);

        let personal = AuthorizationTokens {
            access_token: exchange.user_access_token,
            refresh_token: exchange.user_refresh_token,
            expires_at: personal_expires_at,
            account_email: exchange.account_email.clone(),
            provider_user_id: Some(provider_user_id),
            slack: Some(personal_slack_meta),
            notion: None,
        };

        let workspace = AuthorizationTokens {
            access_token: exchange.bot_access_token,
            refresh_token: exchange.bot_refresh_token,
            expires_at: workspace_expires_at,
            account_email: exchange.account_email,
            provider_user_id: None,
            slack: Some(workspace_slack_meta),
            notion: None,
        };

        Ok((personal, workspace))
    }

    async fn exchange_google_code(
        &self,
        code: &str,
    ) -> Result<AuthorizationTokens, OAuthAccountError> {
        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            #[serde(default)]
            refresh_token: Option<String>,
            expires_in: Option<i64>,
        }

        #[derive(Deserialize)]
        struct UserInfoResponse {
            email: Option<String>,
            #[serde(default)]
            email_verified: Option<bool>,
            #[serde(default)]
            sub: Option<String>,
        }

        let response: TokenResponse = self
            .client
            .post(self.google_token_url())
            .form(&[
                ("code", code),
                ("client_id", self.google.client_id.as_str()),
                ("client_secret", self.google.client_secret.as_str()),
                ("redirect_uri", self.google.redirect_uri.as_str()),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let refresh_token = response
            .refresh_token
            .ok_or(OAuthAccountError::MissingRefreshToken)?;
        let expires_in = response.expires_in.ok_or_else(|| {
            OAuthAccountError::InvalidResponse("Google response missing expires_in".into())
        })?;
        let expires_at = OffsetDateTime::now_utc() + Duration::seconds(expires_in);

        let user_info: UserInfoResponse = self
            .client
            .get(self.google_userinfo_url())
            .bearer_auth(&response.access_token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let email = user_info
            .email
            .ok_or_else(|| OAuthAccountError::InvalidResponse("Missing email".into()))?;

        if !user_info.email_verified.unwrap_or(false) {
            return Err(OAuthAccountError::EmailNotVerified {
                provider: ConnectedOAuthProvider::Google,
            });
        }

        Ok(AuthorizationTokens {
            access_token: response.access_token,
            refresh_token,
            expires_at,
            account_email: email,
            provider_user_id: user_info
                .sub
                .as_deref()
                .and_then(normalize_provider_user_id),
            slack: None,
            notion: None,
        })
    }

    async fn exchange_microsoft_code(
        &self,
        code: &str,
    ) -> Result<AuthorizationTokens, OAuthAccountError> {
        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            #[serde(default)]
            refresh_token: Option<String>,
            expires_in: Option<i64>,
        }

        #[derive(Deserialize)]
        struct UserInfoResponse {
            #[serde(rename = "mail")]
            mail: Option<String>,
            #[serde(rename = "userPrincipalName")]
            user_principal_name: Option<String>,
            #[serde(default)]
            id: Option<String>,
        }

        let response: TokenResponse = self
            .client
            .post(MICROSOFT_TOKEN_URL)
            .form(&[
                ("client_id", self.microsoft.client_id.as_str()),
                ("client_secret", self.microsoft.client_secret.as_str()),
                ("code", code),
                ("redirect_uri", self.microsoft.redirect_uri.as_str()),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let refresh_token = response
            .refresh_token
            .ok_or(OAuthAccountError::MissingRefreshToken)?;
        let expires_in = response.expires_in.ok_or_else(|| {
            OAuthAccountError::InvalidResponse("Microsoft response missing expires_in".into())
        })?;
        let expires_at = OffsetDateTime::now_utc() + Duration::seconds(expires_in);

        let user_info: UserInfoResponse = self
            .client
            .get(MICROSOFT_USERINFO_URL)
            .bearer_auth(&response.access_token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let email = user_info
            .mail
            .or(user_info.user_principal_name)
            .ok_or_else(|| OAuthAccountError::InvalidResponse("Missing account email".into()))?;

        Ok(AuthorizationTokens {
            access_token: response.access_token,
            refresh_token,
            expires_at,
            account_email: email,
            provider_user_id: user_info.id.as_deref().and_then(normalize_provider_user_id),
            slack: None,
            notion: None,
        })
    }

    async fn exchange_slack_code_raw(
        &self,
        code: &str,
    ) -> Result<SlackExchangeTokens, OAuthAccountError> {
        #[derive(Deserialize)]
        struct SlackAuthedUser {
            id: Option<String>,
            access_token: Option<String>,
            refresh_token: Option<String>,
            expires_in: Option<i64>,
            expiration: Option<i64>,
        }

        #[derive(Deserialize)]
        struct SlackTeam {
            id: Option<String>,
        }

        #[derive(Deserialize)]
        struct SlackIncomingWebhook {
            url: Option<String>,
        }

        #[derive(Deserialize)]
        struct SlackTokenResponse {
            ok: bool,
            error: Option<String>,
            access_token: Option<String>,
            refresh_token: Option<String>,
            expires_in: Option<i64>,
            authed_user: Option<SlackAuthedUser>,
            team: Option<SlackTeam>,
            bot_user_id: Option<String>,
            incoming_webhook: Option<SlackIncomingWebhook>,
        }

        let response: SlackTokenResponse = self
            .client
            .post(self.slack_token_url())
            .form(&[
                ("code", code),
                ("client_id", self.slack.client_id.as_str()),
                ("client_secret", self.slack.client_secret.as_str()),
                ("redirect_uri", self.slack.redirect_uri.as_str()),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let SlackTokenResponse {
            ok,
            error,
            access_token,
            refresh_token,
            expires_in,
            authed_user,
            team,
            bot_user_id,
            incoming_webhook,
        } = response;

        if !ok {
            let message = error.unwrap_or_else(|| "Slack OAuth exchange failed".to_string());
            return Err(OAuthAccountError::InvalidResponse(message));
        }

        let authed_user = authed_user.ok_or_else(|| {
            OAuthAccountError::InvalidResponse("Slack response missing user context".into())
        })?;

        let user_access_token = authed_user
            .access_token
            .as_ref()
            .ok_or_else(|| {
                OAuthAccountError::InvalidResponse("Slack response missing access token".into())
            })?
            .to_string();

        let user_refresh_token = authed_user
            .refresh_token
            .as_ref()
            .ok_or_else(|| {
                OAuthAccountError::InvalidResponse("Slack response missing refresh token".into())
            })?
            .to_string();

        let user_id = authed_user
            .id
            .as_deref()
            .and_then(normalize_provider_user_id)
            .ok_or_else(|| {
                OAuthAccountError::InvalidResponse("Slack response missing user id".into())
            })?;

        let account_email = self.fetch_slack_email(&user_access_token, &user_id).await?;

        let team_id = team
            .and_then(|team| team.id)
            .and_then(|value| normalize_provider_user_id(&value))
            .ok_or_else(|| {
                OAuthAccountError::InvalidResponse("Slack response missing team id".into())
            })?;

        let bot_access_token = access_token.ok_or_else(|| {
            OAuthAccountError::InvalidResponse("Slack response missing access token".into())
        })?;

        let bot_refresh_token = refresh_token.ok_or_else(|| {
            OAuthAccountError::InvalidResponse("Slack response missing refresh token".into())
        })?;

        let bot_user_id = bot_user_id.and_then(|value| normalize_provider_user_id(&value));

        let incoming_webhook_url = incoming_webhook
            .and_then(|hook| hook.url)
            .and_then(|value| {
                let trimmed = value.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            });
        if incoming_webhook_url.is_some() {
            tracing::info!(
                provider = "slack",
                has_incoming_webhook = true,
                "Slack OAuth exchange returned incoming webhook"
            );
        } else {
            tracing::info!(
                provider = "slack",
                has_incoming_webhook = false,
                "Slack OAuth exchange did not return incoming webhook"
            );
        }

        Ok(SlackExchangeTokens {
            user_access_token,
            user_refresh_token,
            user_expires_in: authed_user.expires_in,
            user_expiration: authed_user.expiration,
            bot_access_token,
            bot_refresh_token,
            bot_expires_in: expires_in,
            user_id,
            team_id,
            bot_user_id,
            incoming_webhook_url,
            account_email,
        })
    }

    async fn exchange_slack_code(
        &self,
        code: &str,
    ) -> Result<AuthorizationTokens, OAuthAccountError> {
        let exchange = self.exchange_slack_code_raw(code).await?;
        if exchange.user_access_token.trim().is_empty() {
            return Err(OAuthAccountError::InvalidResponse(
                "Slack OAuth exchange missing user access token for auth.test".into(),
            ));
        }
        let SlackAuthTestResult { team_id, user_id } =
            self.slack_auth_test(&exchange.user_access_token).await?;
        let expires_at = slack_expiration(exchange.user_expires_in, exchange.user_expiration)?;
        let slack_meta = SlackOAuthMetadata {
            team_id: Some(team_id),
            bot_user_id: exchange.bot_user_id,
            incoming_webhook_url: exchange.incoming_webhook_url,
        };
        let provider_user_id = user_id.unwrap_or(exchange.user_id);

        Ok(AuthorizationTokens {
            access_token: exchange.user_access_token,
            refresh_token: exchange.user_refresh_token,
            expires_at,
            account_email: exchange.account_email,
            provider_user_id: Some(provider_user_id),
            slack: Some(slack_meta),
            notion: None,
        })
    }

    async fn exchange_asana_code(
        &self,
        code: &str,
    ) -> Result<AuthorizationTokens, OAuthAccountError> {
        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            #[serde(default)]
            refresh_token: Option<String>,
            expires_in: Option<i64>,
        }

        #[derive(Deserialize)]
        struct AsanaUser {
            email: Option<String>,
            gid: Option<String>,
        }

        #[derive(Deserialize)]
        struct UserInfoResponse {
            data: Option<AsanaUser>,
        }

        let response: TokenResponse = self
            .client
            .post(ASANA_TOKEN_URL)
            .form(&[
                ("grant_type", "authorization_code"),
                ("client_id", self.asana.client_id.as_str()),
                ("client_secret", self.asana.client_secret.as_str()),
                ("redirect_uri", self.asana.redirect_uri.as_str()),
                ("code", code),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let refresh_token = response
            .refresh_token
            .ok_or(OAuthAccountError::MissingRefreshToken)?;
        let expires_in = response.expires_in.ok_or_else(|| {
            OAuthAccountError::InvalidResponse("Asana response missing expires_in".into())
        })?;
        let expires_at = OffsetDateTime::now_utc() + Duration::seconds(expires_in);

        let user_info: UserInfoResponse = self
            .client
            .get(ASANA_USERINFO_URL)
            .bearer_auth(&response.access_token)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let account_email = user_info
            .data
            .as_ref()
            .and_then(|data| data.email.clone())
            .ok_or_else(|| OAuthAccountError::InvalidResponse("Missing account email".into()))?;
        let provider_user_id = user_info
            .data
            .and_then(|data| data.gid)
            .as_deref()
            .and_then(normalize_provider_user_id);

        Ok(AuthorizationTokens {
            access_token: response.access_token,
            refresh_token,
            expires_at,
            account_email,
            provider_user_id,
            slack: None,
            notion: None,
        })
    }

    async fn exchange_notion_code(
        &self,
        code: &str,
    ) -> Result<AuthorizationTokens, OAuthAccountError> {
        #[derive(Deserialize)]
        struct NotionOwnerUser {
            id: Option<String>,
            name: Option<String>,
        }

        #[derive(Deserialize)]
        struct NotionOwnerWorkspace {
            id: Option<String>,
            name: Option<String>,
        }

        #[derive(Deserialize)]
        struct NotionOwner {
            #[serde(rename = "type")]
            owner_type: Option<String>,
            user: Option<NotionOwnerUser>,
            workspace: Option<NotionOwnerWorkspace>,
        }

        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            #[serde(default)]
            refresh_token: Option<String>,
            #[serde(default)]
            bot_id: Option<String>,
            #[serde(default)]
            workspace_id: Option<String>,
            #[serde(default)]
            workspace_name: Option<String>,
            #[serde(default)]
            owner: Option<NotionOwner>,
        }

        let auth = base64::engine::general_purpose::STANDARD.encode(format!(
            "{}:{}",
            self.notion.client_id, self.notion.client_secret
        ));

        let response: TokenResponse = self
            .client
            .post(self.notion_token_url())
            .header("Authorization", format!("Basic {auth}"))
            .json(&json!({
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.notion.redirect_uri,
            }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let normalize = |value: Option<String>| {
            value
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(|v| v.to_string())
        };

        let workspace_id = normalize(response.workspace_id);
        let workspace_name = normalize(response.workspace_name);
        let bot_id = normalize(response.bot_id);

        let (owner_type, owner_id, owner_name) = response
            .owner
            .and_then(|owner| {
                let owner_type = normalize(owner.owner_type);
                let (owner_id, owner_name) = match owner_type.as_deref() {
                    Some("user") => {
                        let user = owner.user?;
                        (normalize(user.id), normalize(user.name))
                    }
                    Some("workspace") => {
                        let workspace = owner.workspace?;
                        (normalize(workspace.id), normalize(workspace.name))
                    }
                    _ => (None, None),
                };
                Some((owner_type, owner_id, owner_name))
            })
            .unwrap_or((None, None, None));

        let metadata = NotionOAuthMetadata {
            workspace_id: workspace_id.clone(),
            workspace_name: workspace_name.clone(),
            bot_id: bot_id.clone(),
            owner_type,
            owner_id: owner_id.clone(),
            owner_name,
        };

        let provider_user_id = workspace_id
            .as_deref()
            .and_then(normalize_provider_user_id)
            .or_else(|| owner_id.as_deref().and_then(normalize_provider_user_id))
            .or_else(|| bot_id.as_deref().and_then(normalize_provider_user_id));

        let account_label = workspace_name
            .clone()
            .unwrap_or_else(|| "Notion Workspace".to_string());
        let refresh_token = response.refresh_token.unwrap_or_default();
        let expires_at = OffsetDateTime::now_utc() + Duration::days(NOTION_ACCESS_TTL_DAYS);

        Ok(AuthorizationTokens {
            access_token: response.access_token,
            refresh_token,
            expires_at,
            account_email: account_label,
            provider_user_id,
            slack: None,
            notion: Some(metadata),
        })
    }

    async fn exchange_bitly_code(
        &self,
        code: &str,
    ) -> Result<AuthorizationTokens, OAuthAccountError> {
        #[derive(serde::Deserialize)]
        struct BitlyTokenResponse {
            access_token: String,
            #[serde(default)]
            login: Option<String>,
        }

        let response: BitlyTokenResponse = self
            .client
            .post("https://api-ssl.bitly.com/oauth/access_token")
            // Critical: otherwise Bitly returns application/x-www-form-urlencoded
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&[
                ("client_id", self.bitly.client_id.as_str()),
                ("client_secret", self.bitly.client_secret.as_str()),
                ("code", code),
                ("redirect_uri", self.bitly.redirect_uri.as_str()),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let login = response
            .login
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(|v| v.to_string());
        // Bitly tokens do not expire.
        let expires_at = OffsetDateTime::now_utc()
            .replace_year(2124)
            .expect("valid far-future timestamp");

        Ok(AuthorizationTokens {
            access_token: response.access_token,
            refresh_token: String::new(),
            expires_at,
            account_email: normalize_account_label(
                ConnectedOAuthProvider::Bitly,
                login.clone().unwrap_or_else(|| "Bitly".to_string()),
            ),
            provider_user_id: login.as_deref().and_then(normalize_provider_user_id),
            slack: None,
            notion: None,
        })
    }

    async fn exchange_raindrop_code(
        &self,
        code: &str,
    ) -> Result<AuthorizationTokens, OAuthAccountError> {
        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            #[serde(default)]
            refresh_token: Option<String>,
            expires_in: Option<i64>,
            user: Option<RaindropUser>,
        }

        #[derive(Deserialize)]
        struct RaindropUser {
            email: Option<String>,
            id: Option<String>,
        }

        let response: TokenResponse = self
            .client
            .post("https://raindrop.io/oauth/access_token")
            .header("Accept", "application/json")
            .json(&json!({
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.raindrop.redirect_uri,
                "client_id": self.raindrop.client_id.as_str(),
                "client_secret": self.raindrop.client_secret.as_str(),
            }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let refresh_token = response
            .refresh_token
            .ok_or(OAuthAccountError::MissingRefreshToken)?;
        let expires_in = response.expires_in.ok_or_else(|| {
            OAuthAccountError::InvalidResponse("Raindrop response missing expires_in".into())
        })?;
        let expires_at = OffsetDateTime::now_utc() + Duration::seconds(expires_in);

        let user = response.user.ok_or_else(|| {
            OAuthAccountError::InvalidResponse("Raindrop response missing user info".into())
        })?;

        let account_email = user
            .email
            .ok_or_else(|| OAuthAccountError::InvalidResponse("Missing account email".into()))?;
        let provider_user_id = user.id.as_deref().and_then(normalize_provider_user_id);

        Ok(AuthorizationTokens {
            access_token: response.access_token,
            refresh_token,
            expires_at,
            account_email,
            provider_user_id,
            slack: None,
            notion: None,
        })
    }

    pub async fn refresh_access_token(
        &self,
        provider: ConnectedOAuthProvider,
        refresh_token: &str,
    ) -> Result<AuthorizationTokens, OAuthAccountError> {
        #[cfg(test)]
        if let Some(override_fn) = &self.refresh_override {
            return override_fn(provider, refresh_token);
        }
        match provider {
            ConnectedOAuthProvider::Google => self.refresh_google_token(refresh_token).await,
            ConnectedOAuthProvider::Microsoft => self.refresh_microsoft_token(refresh_token).await,
            ConnectedOAuthProvider::Slack => self.refresh_slack_token(refresh_token).await,
            ConnectedOAuthProvider::Asana => self.refresh_asana_token(refresh_token).await,
            ConnectedOAuthProvider::Notion => self.refresh_notion_token(refresh_token).await,
            ConnectedOAuthProvider::Bitly => Err(OAuthAccountError::RefreshNotSupported {
                provider: ConnectedOAuthProvider::Bitly,
            }),
            ConnectedOAuthProvider::Raindrop => self.refresh_raindrop_token(refresh_token).await,
        }
    }

    async fn refresh_google_token(
        &self,
        refresh_token: &str,
    ) -> Result<AuthorizationTokens, OAuthAccountError> {
        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            expires_in: Option<i64>,
            #[serde(default)]
            refresh_token: Option<String>,
        }

        let response = self
            .client
            .post(GOOGLE_TOKEN_URL)
            .form(&[
                ("client_id", self.google.client_id.as_str()),
                ("client_secret", self.google.client_secret.as_str()),
                ("refresh_token", refresh_token),
                ("grant_type", "refresh_token"),
            ])
            .send()
            .await?;

        if let Err(err) = response.error_for_status_ref() {
            let body = response.text().await.unwrap_or_else(|_| String::new());
            if is_revocation_signal(err.status(), &body) {
                warn!(
                    provider = "google",
                    status = ?err.status(),
                    body = %body,
                    "google oauth refresh token revoked"
                );
                return Err(OAuthAccountError::TokenRevoked {
                    provider: ConnectedOAuthProvider::Google,
                });
            }
            return Err(OAuthAccountError::Http(err));
        }

        let response: TokenResponse = response
            .json()
            .await
            .map_err(|err| OAuthAccountError::InvalidResponse(err.to_string()))?;

        let new_refresh = response
            .refresh_token
            .unwrap_or_else(|| refresh_token.to_string());
        let expires_in = response.expires_in.ok_or_else(|| {
            OAuthAccountError::InvalidResponse("Google refresh missing expires_in".into())
        })?;
        let expires_at = OffsetDateTime::now_utc() + Duration::seconds(expires_in);

        Ok(AuthorizationTokens {
            access_token: response.access_token,
            refresh_token: new_refresh,
            expires_at,
            account_email: String::new(),
            provider_user_id: None,
            slack: None,
            notion: None,
        })
    }

    async fn refresh_microsoft_token(
        &self,
        refresh_token: &str,
    ) -> Result<AuthorizationTokens, OAuthAccountError> {
        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            expires_in: Option<i64>,
            #[serde(default)]
            refresh_token: Option<String>,
        }

        let response = self
            .client
            .post(MICROSOFT_TOKEN_URL)
            .form(&[
                ("client_id", self.microsoft.client_id.as_str()),
                ("client_secret", self.microsoft.client_secret.as_str()),
                ("refresh_token", refresh_token),
                ("grant_type", "refresh_token"),
                ("redirect_uri", self.microsoft.redirect_uri.as_str()),
            ])
            .send()
            .await?;

        if let Err(err) = response.error_for_status_ref() {
            let body = response.text().await.unwrap_or_else(|_| String::new());
            if is_revocation_signal(err.status(), &body) {
                warn!(
                    provider = "microsoft",
                    status = ?err.status(),
                    body = %body,
                    "microsoft oauth refresh token revoked"
                );
                return Err(OAuthAccountError::TokenRevoked {
                    provider: ConnectedOAuthProvider::Microsoft,
                });
            }
            return Err(OAuthAccountError::Http(err));
        }

        let response: TokenResponse = response
            .json()
            .await
            .map_err(|err| OAuthAccountError::InvalidResponse(err.to_string()))?;

        let new_refresh = response
            .refresh_token
            .unwrap_or_else(|| refresh_token.to_string());
        let expires_in = response.expires_in.ok_or_else(|| {
            OAuthAccountError::InvalidResponse("Microsoft refresh missing expires_in".into())
        })?;
        let expires_at = OffsetDateTime::now_utc() + Duration::seconds(expires_in);

        Ok(AuthorizationTokens {
            access_token: response.access_token,
            refresh_token: new_refresh,
            expires_at,
            account_email: String::new(),
            provider_user_id: None,
            slack: None,
            notion: None,
        })
    }

    async fn refresh_slack_token(
        &self,
        refresh_token: &str,
    ) -> Result<AuthorizationTokens, OAuthAccountError> {
        #[derive(Deserialize)]
        struct SlackAuthedUser {
            id: Option<String>,
            access_token: Option<String>,
            refresh_token: Option<String>,
            expires_in: Option<i64>,
            expiration: Option<i64>,
        }

        #[derive(Deserialize)]
        struct SlackTeam {
            id: Option<String>,
        }

        #[derive(Deserialize)]
        struct SlackIncomingWebhook {
            url: Option<String>,
        }

        #[derive(Deserialize)]
        struct SlackRefreshResponse {
            ok: bool,
            error: Option<String>,
            access_token: Option<String>,
            refresh_token: Option<String>,
            expires_in: Option<i64>,
            authed_user: Option<SlackAuthedUser>,
            team: Option<SlackTeam>,
            bot_user_id: Option<String>,
            incoming_webhook: Option<SlackIncomingWebhook>,
        }

        let response = self
            .client
            .post(self.slack_token_url())
            .form(&[
                ("client_id", self.slack.client_id.as_str()),
                ("client_secret", self.slack.client_secret.as_str()),
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
            ])
            .send()
            .await?;

        if let Err(err) = response.error_for_status_ref() {
            return Err(OAuthAccountError::Http(err));
        }

        let body: SlackRefreshResponse = response.json().await?;

        let SlackRefreshResponse {
            ok,
            error,
            access_token: _access_token,
            refresh_token: _refresh_token_response,
            expires_in: _expires_in,
            authed_user,
            team,
            bot_user_id,
            incoming_webhook,
        } = body;

        if !ok {
            if let Some(error) = error.as_deref() {
                let lowered = error.to_ascii_lowercase();
                if lowered.contains("invalid_refresh_token")
                    || lowered.contains("invalid_grant")
                    || lowered.contains("token_revoked")
                {
                    return Err(OAuthAccountError::TokenRevoked {
                        provider: ConnectedOAuthProvider::Slack,
                    });
                }
            }

            let message = error.unwrap_or_else(|| "Slack refresh failed".to_string());
            return Err(OAuthAccountError::InvalidResponse(message));
        }

        let authed_user = authed_user.as_ref().ok_or_else(|| {
            OAuthAccountError::InvalidResponse("Slack refresh missing user context".into())
        })?;

        let access_token = authed_user
            .access_token
            .as_ref()
            .ok_or_else(|| {
                OAuthAccountError::InvalidResponse("Slack refresh missing access token".into())
            })?
            .to_string();

        let new_refresh = authed_user
            .refresh_token
            .as_ref()
            .map(|token| token.to_string())
            .unwrap_or_else(|| refresh_token.to_string());

        let user_id = authed_user
            .id
            .as_deref()
            .and_then(normalize_provider_user_id)
            .ok_or_else(|| {
                OAuthAccountError::InvalidResponse("Slack refresh missing user id".into())
            })?;

        let expires_at = slack_expiration(authed_user.expires_in, authed_user.expiration)?;

        let team_id = team
            .and_then(|team| team.id)
            .and_then(|value| normalize_provider_user_id(&value))
            .ok_or_else(|| {
                OAuthAccountError::InvalidResponse("Slack refresh missing team id".into())
            })?;

        let bot_user_id = bot_user_id.and_then(|value| normalize_provider_user_id(&value));

        let incoming_webhook_url = incoming_webhook
            .and_then(|hook| hook.url)
            .and_then(|value| {
                let trimmed = value.trim();
                (!trimmed.is_empty()).then(|| trimmed.to_string())
            });

        let slack_meta = SlackOAuthMetadata {
            team_id: Some(team_id),
            bot_user_id,
            incoming_webhook_url,
        };

        Ok(AuthorizationTokens {
            access_token,
            refresh_token: new_refresh,
            expires_at,
            account_email: String::new(),
            provider_user_id: Some(user_id),
            slack: Some(slack_meta),
            notion: None,
        })
    }

    async fn refresh_asana_token(
        &self,
        refresh_token: &str,
    ) -> Result<AuthorizationTokens, OAuthAccountError> {
        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            #[serde(default)]
            refresh_token: Option<String>,
            expires_in: Option<i64>,
        }

        let response = self
            .client
            .post(ASANA_TOKEN_URL)
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", self.asana.client_id.as_str()),
                ("client_secret", self.asana.client_secret.as_str()),
            ])
            .send()
            .await?;

        if let Err(err) = response.error_for_status_ref() {
            let body = response.text().await.unwrap_or_else(|_| String::new());
            if is_revocation_signal(err.status(), &body) {
                warn!(
                    provider = "asana",
                    status = ?err.status(),
                    body = %body,
                    "asana oauth refresh token revoked"
                );
                return Err(OAuthAccountError::TokenRevoked {
                    provider: ConnectedOAuthProvider::Asana,
                });
            }
            return Err(OAuthAccountError::Http(err));
        }

        let body: TokenResponse = response
            .json()
            .await
            .map_err(|err| OAuthAccountError::InvalidResponse(err.to_string()))?;

        let expires_in = body.expires_in.ok_or_else(|| {
            OAuthAccountError::InvalidResponse("Asana refresh missing expires_in".into())
        })?;
        let expires_at = OffsetDateTime::now_utc() + Duration::seconds(expires_in);
        let new_refresh = body
            .refresh_token
            .unwrap_or_else(|| refresh_token.to_string());

        Ok(AuthorizationTokens {
            access_token: body.access_token,
            refresh_token: new_refresh,
            expires_at,
            account_email: String::new(),
            provider_user_id: None,
            slack: None,
            notion: None,
        })
    }

    async fn refresh_raindrop_token(
        &self,
        refresh_token: &str,
    ) -> Result<AuthorizationTokens, OAuthAccountError> {
        #[derive(Deserialize)]
        struct TokenResponse {
            access_token: String,
            #[serde(default)]
            refresh_token: Option<String>,
            expires_in: Option<i64>,
        }

        let response = self
            .client
            .post("https://raindrop.io/oauth/access_token")
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh_token),
                ("client_id", self.raindrop.client_id.as_str()),
                ("client_secret", self.raindrop.client_secret.as_str()),
            ])
            .send()
            .await?
            .error_for_status()?;

        let body: TokenResponse = response
            .json()
            .await
            .map_err(|err| OAuthAccountError::InvalidResponse(err.to_string()))?;

        let expires_in = body.expires_in.ok_or_else(|| {
            OAuthAccountError::InvalidResponse("Raindrop refresh missing expires_in".into())
        })?;
        let expires_at = OffsetDateTime::now_utc() + Duration::seconds(expires_in);
        let new_refresh = body
            .refresh_token
            .unwrap_or_else(|| refresh_token.to_string());

        Ok(AuthorizationTokens {
            access_token: body.access_token,
            refresh_token: new_refresh,
            expires_at,
            account_email: String::new(),
            provider_user_id: None,
            slack: None,
            notion: None,
        })
    }

    async fn refresh_notion_token(
        &self,
        _refresh_token: &str,
    ) -> Result<AuthorizationTokens, OAuthAccountError> {
        Err(OAuthAccountError::MissingRefreshToken)
    }

    fn encrypt_slack_metadata(
        &self,
        slack: &SlackOAuthMetadata,
    ) -> Result<Option<EncryptedSlackOAuthMetadata>, OAuthAccountError> {
        encrypt_slack_metadata_with_key(&self.encryption_key, slack)
            .map_err(OAuthAccountError::from)
    }

    async fn revoke_existing_credentials(
        &self,
        provider: ConnectedOAuthProvider,
        stored: &StoredOAuthToken,
    ) {
        if !stored.refresh_token.trim().is_empty() {
            if let Err(err) = self
                .revoke_provider_token(provider, &stored.refresh_token)
                .await
            {
                warn!(
                    ?err,
                    provider = ?provider,
                    token_id = %stored.id,
                    "failed to revoke stored refresh token"
                );
            }
        }

        if matches!(provider, ConnectedOAuthProvider::Slack)
            && !stored.access_token.trim().is_empty()
        {
            if let Err(err) = self
                .revoke_provider_token(provider, &stored.access_token)
                .await
            {
                warn!(
                    ?err,
                    provider = ?provider,
                    token_id = %stored.id,
                    "failed to revoke stored access token"
                );
            }
        }
    }

    async fn revoke_provider_token(
        &self,
        provider: ConnectedOAuthProvider,
        token: &str,
    ) -> Result<(), OAuthAccountError> {
        #[cfg(test)]
        if let Some(override_fn) = &self.revocation_override {
            return override_fn(provider, token);
        }

        match provider {
            ConnectedOAuthProvider::Google => {
                let response = self
                    .client
                    .post(self.google_revocation_url())
                    .form(&[("token", token)])
                    .send()
                    .await?;

                if response.status() == StatusCode::OK
                    || response.status() == StatusCode::NO_CONTENT
                {
                    Ok(())
                } else {
                    Err(OAuthAccountError::InvalidResponse(format!(
                        "Failed to revoke token: {}",
                        response.status()
                    )))
                }
            }
            ConnectedOAuthProvider::Microsoft => {
                let response = self
                    .client
                    .post(MICROSOFT_REVOCATION_URL)
                    .form(&[
                        ("token", token),
                        ("token_type_hint", "refresh_token"),
                        ("client_id", self.microsoft.client_id.as_str()),
                    ])
                    .send()
                    .await?;

                if response.status() == StatusCode::OK
                    || response.status() == StatusCode::NO_CONTENT
                {
                    Ok(())
                } else {
                    Err(OAuthAccountError::InvalidResponse(format!(
                        "Failed to revoke token: {}",
                        response.status()
                    )))
                }
            }
            ConnectedOAuthProvider::Slack => {
                #[derive(Deserialize)]
                struct SlackRevocationResponse {
                    ok: bool,
                    error: Option<String>,
                }

                let response = self
                    .client
                    .post(SLACK_REVOCATION_URL)
                    .form(&[
                        ("token", token),
                        ("client_id", self.slack.client_id.as_str()),
                        ("client_secret", self.slack.client_secret.as_str()),
                    ])
                    .send()
                    .await?;

                let status = response.status();
                if status.is_success() {
                    let body: SlackRevocationResponse = response.json().await?;
                    if body.ok {
                        Ok(())
                    } else {
                        Err(OAuthAccountError::InvalidResponse(
                            body.error
                                .unwrap_or_else(|| "Slack revocation failed".into()),
                        ))
                    }
                } else {
                    Err(OAuthAccountError::InvalidResponse(format!(
                        "Failed to revoke token: {}",
                        status
                    )))
                }
            }
            ConnectedOAuthProvider::Asana => {
                let response = self
                    .client
                    .post(ASANA_REVOCATION_URL)
                    .form(&[
                        ("token", token),
                        ("client_id", self.asana.client_id.as_str()),
                        ("client_secret", self.asana.client_secret.as_str()),
                    ])
                    .send()
                    .await?;

                if response.status().is_success() {
                    Ok(())
                } else {
                    Err(OAuthAccountError::InvalidResponse(format!(
                        "Failed to revoke token: {}",
                        response.status()
                    )))
                }
            }
            ConnectedOAuthProvider::Notion => Ok(()),
            ConnectedOAuthProvider::Bitly => Ok(()),
            ConnectedOAuthProvider::Raindrop => Ok(()),
        }
    }

    async fn slack_auth_test(
        &self,
        access_token: &str,
    ) -> Result<SlackAuthTestResult, OAuthAccountError> {
        #[derive(Deserialize)]
        struct SlackAuthTestResponse {
            ok: bool,
            team_id: Option<String>,
            user_id: Option<String>,
            error: Option<String>,
        }

        let base = std::env::var("SLACK_API_BASE_URL")
            .ok()
            .or_else(|| std::env::var("SLACK_API_BASE").ok())
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "https://slack.com/api".to_string());
        let url = format!("{}/auth.test", base.trim_end_matches('/'));

        let response = self
            .client
            .get(&url)
            .bearer_auth(access_token)
            .send()
            .await?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        if !status.is_success() {
            return Err(OAuthAccountError::InvalidResponse(
                "Slack auth.test failed".into(),
            ));
        }

        let parsed: SlackAuthTestResponse = serde_json::from_str(&body).map_err(|_| {
            OAuthAccountError::InvalidResponse(
                "Slack auth.test returned an unexpected response".into(),
            )
        })?;

        if !parsed.ok {
            let message = parsed
                .error
                .unwrap_or_else(|| "Slack auth.test failed".to_string());
            return Err(OAuthAccountError::InvalidResponse(message));
        }

        let team_id = parsed
            .team_id
            .as_deref()
            .and_then(normalize_provider_user_id)
            .ok_or_else(|| {
                OAuthAccountError::InvalidResponse("Slack auth.test missing team id".into())
            })?;

        let user_id = parsed
            .user_id
            .as_deref()
            .and_then(normalize_provider_user_id);

        Ok(SlackAuthTestResult { team_id, user_id })
    }

    async fn fetch_slack_email(
        &self,
        access_token: &str,
        user_id: &str,
    ) -> Result<String, OAuthAccountError> {
        #[derive(Deserialize)]
        struct SlackProfile {
            email: Option<String>,
        }

        #[derive(Deserialize)]
        struct SlackUser {
            profile: Option<SlackProfile>,
        }

        #[derive(Deserialize)]
        struct SlackUserInfoResponse {
            ok: bool,
            error: Option<String>,
            user: Option<SlackUser>,
        }

        let response = self
            .client
            .get(self.slack_userinfo_url())
            .query(&[("user", user_id)])
            .bearer_auth(access_token)
            .send()
            .await?;

        if response.status() == StatusCode::UNAUTHORIZED {
            return Err(OAuthAccountError::TokenRevoked {
                provider: ConnectedOAuthProvider::Slack,
            });
        }

        let body: SlackUserInfoResponse = response.json().await?;
        if !body.ok {
            let message = body
                .error
                .unwrap_or_else(|| "Slack user info request failed".to_string());
            return Err(OAuthAccountError::InvalidResponse(message));
        }

        body.user
            .and_then(|user| user.profile)
            .and_then(|profile| profile.email)
            .ok_or_else(|| OAuthAccountError::InvalidResponse("Slack user email missing".into()))
    }

    fn decrypt_record(
        &self,
        record: UserOAuthToken,
    ) -> Result<StoredOAuthToken, OAuthAccountError> {
        let access_token = decrypt_secret(&self.encryption_key, &record.access_token)?;
        let refresh_token = decrypt_secret(&self.encryption_key, &record.refresh_token)?;
        Ok(StoredOAuthToken {
            id: record.id,
            provider: record.provider,
            access_token,
            refresh_token,
            expires_at: record.expires_at,
            account_email: record.account_email,
            is_shared: record.is_shared,
            updated_at: record.updated_at,
        })
    }

    #[cfg(test)]
    pub fn test_stub() -> Arc<Self> {
        use async_trait::async_trait;

        struct StubRepo;

        #[async_trait]
        impl UserOAuthTokenRepository for StubRepo {
            async fn upsert_token(
                &self,
                _new_token: NewUserOAuthToken,
            ) -> Result<UserOAuthToken, sqlx::Error> {
                Err(sqlx::Error::RowNotFound)
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
                _new_connection: crate::db::workspace_connection_repository::NewWorkspaceConnection,
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
            ) -> Result<
                Vec<crate::db::workspace_connection_repository::WorkspaceConnectionListing>,
                sqlx::Error,
            > {
                Ok(Vec::new())
            }

            async fn list_for_user_memberships(
                &self,
                _user_id: Uuid,
            ) -> Result<
                Vec<crate::db::workspace_connection_repository::WorkspaceConnectionListing>,
                sqlx::Error,
            > {
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
            ) -> Result<
                Vec<crate::db::workspace_connection_repository::StaleWorkspaceConnection>,
                sqlx::Error,
            > {
                Ok(Vec::new())
            }

            async fn record_audit_event(
                &self,
                _event: crate::db::workspace_connection_repository::NewWorkspaceAuditEvent,
            ) -> Result<WorkspaceAuditEvent, sqlx::Error> {
                Err(sqlx::Error::RowNotFound)
            }
        }

        let repo = Arc::new(StubRepo) as Arc<dyn UserOAuthTokenRepository>;
        let workspace_connections =
            Arc::new(StubWorkspaceRepo) as Arc<dyn WorkspaceConnectionRepository>;
        let key = Arc::new(vec![0u8; 32]);
        let client = Arc::new(Client::new());
        let settings = OAuthSettings {
            google: OAuthProviderConfig {
                client_id: "stub".into(),
                client_secret: "stub".into(),
                redirect_uri: "http://localhost".into(),
            },
            microsoft: OAuthProviderConfig {
                client_id: "stub".into(),
                client_secret: "stub".into(),
                redirect_uri: "http://localhost".into(),
            },
            slack: OAuthProviderConfig {
                client_id: "stub".into(),
                client_secret: "stub".into(),
                redirect_uri: "http://localhost".into(),
            },
            asana: OAuthProviderConfig {
                client_id: "stub".into(),
                client_secret: "stub".into(),
                redirect_uri: "http://localhost".into(),
            },
            notion: OAuthProviderConfig {
                client_id: "stub".into(),
                client_secret: "stub".into(),
                redirect_uri: "http://localhost".into(),
            },
            bitly: OAuthProviderConfig {
                client_id: "stub".into(),
                client_secret: "stub".into(),
                redirect_uri: "http://localhost".into(),
            },
            raindrop: OAuthProviderConfig {
                client_id: "stub".into(),
                client_secret: "stub".into(),
                redirect_uri: "http://localhost".into(),
            },
            token_encryption_key: vec![0u8; 32],
        };
        Arc::new(Self::new(
            repo,
            workspace_connections,
            key,
            client,
            &settings,
        ))
    }
}

fn slack_expiration(
    expires_in: Option<i64>,
    expiration: Option<i64>,
) -> Result<OffsetDateTime, OAuthAccountError> {
    if let Some(seconds) = expires_in {
        return Ok(OffsetDateTime::now_utc() + Duration::seconds(seconds));
    }

    if let Some(timestamp) = expiration {
        return OffsetDateTime::from_unix_timestamp(timestamp).map_err(|_| {
            OAuthAccountError::InvalidResponse("Invalid Slack expiration timestamp".into())
        });
    }

    Err(OAuthAccountError::InvalidResponse(
        "Slack response missing expiration".into(),
    ))
}

pub(crate) fn has_slack_fields(slack: &EncryptedSlackOAuthMetadata) -> bool {
    slack.team_id.is_some() || slack.bot_user_id.is_some() || slack.incoming_webhook_url.is_some()
}

pub(crate) fn encrypt_slack_metadata_with_key(
    encryption_key: &[u8],
    slack: &SlackOAuthMetadata,
) -> Result<Option<EncryptedSlackOAuthMetadata>, EncryptionError> {
    let team_id = slack
        .team_id
        .as_deref()
        .map(|value| encrypt_secret(encryption_key, value))
        .transpose()?;

    let bot_user_id = slack
        .bot_user_id
        .as_deref()
        .map(|value| encrypt_secret(encryption_key, value))
        .transpose()?;

    let incoming_webhook_url = slack
        .incoming_webhook_url
        .as_deref()
        .map(|value| encrypt_secret(encryption_key, value))
        .transpose()?;

    let encrypted = EncryptedSlackOAuthMetadata {
        team_id,
        bot_user_id,
        incoming_webhook_url,
    };

    Ok(has_slack_fields(&encrypted).then_some(encrypted))
}

pub(crate) fn parse_token_metadata(metadata: &Value) -> OAuthTokenMetadata {
    serde_json::from_value(metadata.clone()).unwrap_or_default()
}

pub(crate) fn serialize_token_metadata(metadata: OAuthTokenMetadata) -> Value {
    serde_json::to_value(metadata).unwrap_or_else(|_| json!({}))
}

pub(crate) fn merge_slack_metadata(
    existing: Option<EncryptedSlackOAuthMetadata>,
    incoming: Option<EncryptedSlackOAuthMetadata>,
) -> Option<EncryptedSlackOAuthMetadata> {
    let mut merged = existing.unwrap_or_default();

    if let Some(mut incoming_meta) = incoming {
        if incoming_meta.team_id.is_some() {
            merged.team_id = incoming_meta.team_id.take();
        }
        if incoming_meta.bot_user_id.is_some() {
            merged.bot_user_id = incoming_meta.bot_user_id.take();
        }
        if incoming_meta.incoming_webhook_url.is_some() {
            merged.incoming_webhook_url = incoming_meta.incoming_webhook_url.take();
        }
    }

    has_slack_fields(&merged).then_some(merged)
}

pub(crate) fn merge_notion_metadata(
    existing: Option<NotionOAuthMetadata>,
    incoming: Option<NotionOAuthMetadata>,
) -> Option<NotionOAuthMetadata> {
    let mut merged = existing.unwrap_or_default();

    if let Some(mut incoming_meta) = incoming {
        if incoming_meta.workspace_id.is_some() {
            merged.workspace_id = incoming_meta.workspace_id.take();
        }
        if incoming_meta.workspace_name.is_some() {
            merged.workspace_name = incoming_meta.workspace_name.take();
        }
        if incoming_meta.bot_id.is_some() {
            merged.bot_id = incoming_meta.bot_id.take();
        }
        if incoming_meta.owner_type.is_some() {
            merged.owner_type = incoming_meta.owner_type.take();
        }
        if incoming_meta.owner_id.is_some() {
            merged.owner_id = incoming_meta.owner_id.take();
        }
        if incoming_meta.owner_name.is_some() {
            merged.owner_name = incoming_meta.owner_name.take();
        }
    }

    has_notion_fields(&merged).then_some(merged)
}

fn normalize_provider_user_id(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn merge_provider_user_id(existing: Option<String>, incoming: Option<String>) -> Option<String> {
    incoming
        .as_deref()
        .and_then(normalize_provider_user_id)
        .or_else(|| existing.as_deref().and_then(normalize_provider_user_id))
}

fn merge_metadata_value(
    existing: Option<&Value>,
    slack: Option<EncryptedSlackOAuthMetadata>,
    provider_user_id: Option<String>,
    notion: Option<NotionOAuthMetadata>,
) -> (OAuthTokenMetadata, Value) {
    let mut metadata = existing.map(parse_token_metadata).unwrap_or_default();

    metadata.slack = merge_slack_metadata(metadata.slack.clone(), slack);
    metadata.provider_user_id =
        merge_provider_user_id(metadata.provider_user_id.clone(), provider_user_id);
    metadata.notion = merge_notion_metadata(metadata.notion.clone(), notion);

    let value = serialize_token_metadata(metadata.clone());
    (metadata, value)
}

fn has_notion_fields(metadata: &NotionOAuthMetadata) -> bool {
    metadata.workspace_id.is_some()
        || metadata.workspace_name.is_some()
        || metadata.bot_id.is_some()
        || metadata.owner_type.is_some()
        || metadata.owner_id.is_some()
        || metadata.owner_name.is_some()
}

pub(crate) fn slack_metadata_from_value(metadata: &Value) -> Option<EncryptedSlackOAuthMetadata> {
    parse_token_metadata(metadata).slack
}

pub(crate) fn clear_webhook(
    slack: Option<EncryptedSlackOAuthMetadata>,
) -> Option<EncryptedSlackOAuthMetadata> {
    slack.and_then(|mut meta| {
        meta.incoming_webhook_url = None;
        has_slack_fields(&meta).then_some(meta)
    })
}

pub(crate) fn is_revocation_signal(status: Option<StatusCode>, body: &str) -> bool {
    if matches!(status, Some(StatusCode::UNAUTHORIZED)) {
        return true;
    }

    if let Some(StatusCode::BAD_REQUEST) = status {
        let lowered = body.to_ascii_lowercase();
        if lowered.contains("invalid_grant") || lowered.contains("revoked") {
            return true;
        }
    }

    let lowered = body.to_ascii_lowercase();
    lowered.contains("invalid_grant") || lowered.contains("token revoked")
}

fn normalize_account_label(provider: ConnectedOAuthProvider, account_email: String) -> String {
    match provider {
        ConnectedOAuthProvider::Bitly => {
            format!("{account_email} (Bitly account)")
        }
        ConnectedOAuthProvider::Raindrop => {
            format!("{account_email} (Raindrop account)")
        }
        _ => account_email,
    }
}

#[cfg(test)]
type RefreshOverride = dyn for<'a> Fn(ConnectedOAuthProvider, &'a str) -> Result<AuthorizationTokens, OAuthAccountError>
    + Send
    + Sync;

#[cfg(test)]
type RevocationOverride =
    dyn for<'a> Fn(ConnectedOAuthProvider, &'a str) -> Result<(), OAuthAccountError> + Send + Sync;

#[cfg(test)]
#[derive(Default, Clone)]
struct TestEndpointOverrides {
    google_token_url: Option<String>,
    google_userinfo_url: Option<String>,
    google_revocation_url: Option<String>,
    slack_token_url: Option<String>,
    slack_userinfo_url: Option<String>,
    notion_token_url: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::oauth_token_repository::{NewUserOAuthToken, UserOAuthTokenRepository};
    use crate::db::workspace_connection_repository::{
        StaleWorkspaceConnection, WorkspaceConnectionRepository,
    };
    use async_trait::async_trait;
    use sqlx::Error;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

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

    struct InMemoryRepo;

    #[async_trait]
    impl UserOAuthTokenRepository for InMemoryRepo {
        async fn upsert_token(
            &self,
            _new_token: NewUserOAuthToken,
        ) -> Result<UserOAuthToken, sqlx::Error> {
            Err(Error::RowNotFound)
        }

        async fn find_by_id(&self, _token_id: Uuid) -> Result<Option<UserOAuthToken>, sqlx::Error> {
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
            Err(Error::RowNotFound)
        }

        async fn list_by_user_and_provider(
            &self,
            _user_id: Uuid,
            _provider: ConnectedOAuthProvider,
        ) -> Result<Vec<UserOAuthToken>, sqlx::Error> {
            Ok(vec![])
        }
    }

    struct NoopWorkspaceRepo;

    #[async_trait]
    impl WorkspaceConnectionRepository for NoopWorkspaceRepo {
        async fn insert_connection(
            &self,
            _new_connection: crate::db::workspace_connection_repository::NewWorkspaceConnection,
        ) -> Result<WorkspaceConnection, sqlx::Error> {
            Err(Error::RowNotFound)
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
            Err(Error::RowNotFound)
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
        ) -> Result<
            Vec<crate::db::workspace_connection_repository::WorkspaceConnectionListing>,
            sqlx::Error,
        > {
            Ok(Vec::new())
        }

        async fn list_for_user_memberships(
            &self,
            _user_id: Uuid,
        ) -> Result<
            Vec<crate::db::workspace_connection_repository::WorkspaceConnectionListing>,
            sqlx::Error,
        > {
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
            Err(Error::RowNotFound)
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
            Err(Error::RowNotFound)
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
        ) -> Result<
            Vec<crate::db::workspace_connection_repository::StaleWorkspaceConnection>,
            sqlx::Error,
        > {
            Ok(Vec::new())
        }

        async fn record_audit_event(
            &self,
            _event: crate::db::workspace_connection_repository::NewWorkspaceAuditEvent,
        ) -> Result<WorkspaceAuditEvent, sqlx::Error> {
            Err(Error::RowNotFound)
        }
    }

    #[tokio::test]
    async fn scopes_are_exposed() {
        let client = Arc::new(Client::new());
        let repo: Arc<dyn UserOAuthTokenRepository> = Arc::new(InMemoryRepo);
        let workspace_repo: Arc<dyn WorkspaceConnectionRepository> = Arc::new(NoopWorkspaceRepo);
        let key = Arc::new(vec![0u8; 32]);
        let settings = OAuthSettings {
            google: OAuthProviderConfig {
                client_id: "id".into(),
                client_secret: "secret".into(),
                redirect_uri: "http://localhost".into(),
            },
            microsoft: OAuthProviderConfig {
                client_id: "id".into(),
                client_secret: "secret".into(),
                redirect_uri: "http://localhost".into(),
            },
            slack: OAuthProviderConfig {
                client_id: "id".into(),
                client_secret: "secret".into(),
                redirect_uri: "http://localhost".into(),
            },
            asana: OAuthProviderConfig {
                client_id: "id".into(),
                client_secret: "secret".into(),
                redirect_uri: "http://localhost".into(),
            },
            notion: OAuthProviderConfig {
                client_id: "id".into(),
                client_secret: "secret".into(),
                redirect_uri: "http://localhost".into(),
            },
            bitly: OAuthProviderConfig {
                client_id: "stub".into(),
                client_secret: "stub".into(),
                redirect_uri: "http://localhost".into(),
            },
            raindrop: OAuthProviderConfig {
                client_id: "stub".into(),
                client_secret: "stub".into(),
                redirect_uri: "http://localhost".into(),
            },
            token_encryption_key: vec![0u8; 32],
        };
        let service = OAuthAccountService::new(repo, workspace_repo, key, client, &settings);
        assert_eq!(
            service.google_scopes(),
            "openid email https://www.googleapis.com/auth/spreadsheets"
        );
        assert_eq!(
            service.microsoft_scopes(),
            "offline_access User.Read Team.ReadBasic.All Channel.ReadBasic.All ChannelMember.Read.All ChannelMessage.Send"
        );
        assert_eq!(
            service.slack_scopes(),
            "chat:write,channels:read,groups:read,im:read,mpim:read,users:read,users:read.email"
        );
        assert_eq!(service.asana_scopes(), "default email");
    }

    #[tokio::test]
    async fn google_exchange_rejects_unverified_email() {
        let token_server = httpmock::MockServer::start();
        let userinfo_server = httpmock::MockServer::start();

        let _token_mock = token_server.mock(|when, then| {
            when.method(httpmock::Method::POST).path("/token");
            then.status(200).json_body(serde_json::json!({
                "access_token": "access",
                "refresh_token": "refresh",
                "expires_in": 3600
            }));
        });

        let _userinfo_mock = userinfo_server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/v1/userinfo");
            then.status(200).json_body(serde_json::json!({
                "email": "user@example.com",
                "email_verified": false
            }));
        });

        let client = Arc::new(Client::new());

        let repo: Arc<dyn UserOAuthTokenRepository> = Arc::new(InMemoryRepo);
        let workspace_repo: Arc<dyn WorkspaceConnectionRepository> = Arc::new(NoopWorkspaceRepo);
        let key = Arc::new(vec![0u8; 32]);
        let settings = OAuthSettings {
            google: OAuthProviderConfig {
                client_id: "client".into(),
                client_secret: "secret".into(),
                redirect_uri: "http://localhost/google".into(),
            },
            microsoft: OAuthProviderConfig {
                client_id: "client".into(),
                client_secret: "secret".into(),
                redirect_uri: "http://localhost/microsoft".into(),
            },
            slack: OAuthProviderConfig {
                client_id: "client".into(),
                client_secret: "secret".into(),
                redirect_uri: "http://localhost/slack".into(),
            },
            asana: OAuthProviderConfig {
                client_id: "client".into(),
                client_secret: "secret".into(),
                redirect_uri: "http://localhost/asana".into(),
            },
            notion: OAuthProviderConfig {
                client_id: "client".into(),
                client_secret: "secret".into(),
                redirect_uri: "http://localhost/asana".into(),
            },
            bitly: OAuthProviderConfig {
                client_id: "stub".into(),
                client_secret: "stub".into(),
                redirect_uri: "http://localhost".into(),
            },
            raindrop: OAuthProviderConfig {
                client_id: "stub".into(),
                client_secret: "stub".into(),
                redirect_uri: "http://localhost".into(),
            },
            token_encryption_key: vec![0u8; 32],
        };

        let mut service = OAuthAccountService::new(repo, workspace_repo, key, client, &settings);
        service.set_google_endpoint_overrides(
            token_server.url("/token"),
            userinfo_server.url("/v1/userinfo"),
            None,
        );

        let err = service
            .exchange_authorization_code(ConnectedOAuthProvider::Google, "auth-code")
            .await
            .expect_err("unverified email should fail");

        match err {
            OAuthAccountError::EmailNotVerified { provider } => {
                assert_eq!(provider, ConnectedOAuthProvider::Google);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn google_exchange_requires_expires_in() {
        let token_server = httpmock::MockServer::start();
        let userinfo_server = httpmock::MockServer::start();

        let _token_mock = token_server.mock(|when, then| {
            when.method(httpmock::Method::POST).path("/token");
            then.status(200).json_body(serde_json::json!({
                "access_token": "access",
                "refresh_token": "refresh"
            }));
        });

        let _userinfo_mock = userinfo_server.mock(|when, then| {
            when.method(httpmock::Method::GET).path("/v1/userinfo");
            then.status(200).json_body(serde_json::json!({
                "email": "user@example.com",
                "email_verified": true
            }));
        });

        let client = Arc::new(Client::new());

        let repo: Arc<dyn UserOAuthTokenRepository> = Arc::new(InMemoryRepo);
        let workspace_repo: Arc<dyn WorkspaceConnectionRepository> = Arc::new(NoopWorkspaceRepo);
        let key = Arc::new(vec![0u8; 32]);
        let settings = OAuthSettings {
            google: OAuthProviderConfig {
                client_id: "client".into(),
                client_secret: "secret".into(),
                redirect_uri: "http://localhost/google".into(),
            },
            microsoft: OAuthProviderConfig {
                client_id: "client".into(),
                client_secret: "secret".into(),
                redirect_uri: "http://localhost/microsoft".into(),
            },
            slack: OAuthProviderConfig {
                client_id: "client".into(),
                client_secret: "secret".into(),
                redirect_uri: "http://localhost/slack".into(),
            },
            asana: OAuthProviderConfig {
                client_id: "client".into(),
                client_secret: "secret".into(),
                redirect_uri: "http://localhost/asana".into(),
            },
            notion: OAuthProviderConfig {
                client_id: "client".into(),
                client_secret: "secret".into(),
                redirect_uri: "http://localhost/asana".into(),
            },
            bitly: OAuthProviderConfig {
                client_id: "stub".into(),
                client_secret: "stub".into(),
                redirect_uri: "http://localhost".into(),
            },
            raindrop: OAuthProviderConfig {
                client_id: "stub".into(),
                client_secret: "stub".into(),
                redirect_uri: "http://localhost".into(),
            },
            token_encryption_key: vec![0u8; 32],
        };

        let mut service = OAuthAccountService::new(repo, workspace_repo, key, client, &settings);
        service.set_google_endpoint_overrides(
            token_server.url("/token"),
            userinfo_server.url("/v1/userinfo"),
            None,
        );

        let err = service
            .exchange_authorization_code(ConnectedOAuthProvider::Google, "auth-code")
            .await
            .expect_err("missing expires_in should be treated as invalid response");

        match err {
            OAuthAccountError::InvalidResponse(msg) => {
                assert!(msg.contains("Google response missing expires_in"), "{msg}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn slack_expiration_requires_metadata() {
        let err = slack_expiration(None, None)
            .expect_err("missing expiration metadata should return error");
        match err {
            OAuthAccountError::InvalidResponse(msg) => {
                assert!(msg.contains("Slack response missing expiration"), "{msg}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[derive(Default)]
    struct RecordingTokenRepo {
        token: Mutex<Option<UserOAuthToken>>,
        delete_calls: Mutex<Vec<(Uuid, ConnectedOAuthProvider)>>,
    }

    impl RecordingTokenRepo {
        fn new(token: UserOAuthToken) -> Self {
            Self {
                token: Mutex::new(Some(token)),
                delete_calls: Mutex::new(Vec::new()),
            }
        }

        fn delete_calls(&self) -> Vec<(Uuid, ConnectedOAuthProvider)> {
            self.delete_calls.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl UserOAuthTokenRepository for RecordingTokenRepo {
        async fn upsert_token(
            &self,
            _new_token: NewUserOAuthToken,
        ) -> Result<UserOAuthToken, sqlx::Error> {
            Err(Error::RowNotFound)
        }

        async fn find_by_id(&self, token_id: Uuid) -> Result<Option<UserOAuthToken>, sqlx::Error> {
            let guard = self.token.lock().unwrap();
            Ok(guard.as_ref().filter(|token| token.id == token_id).cloned())
        }

        async fn find_by_user_and_provider(
            &self,
            user_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<Option<UserOAuthToken>, sqlx::Error> {
            let guard = self.token.lock().unwrap();
            Ok(guard
                .as_ref()
                .filter(|token| token.user_id == user_id && token.provider == provider)
                .cloned())
        }

        async fn delete_token(
            &self,
            user_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<(), sqlx::Error> {
            let mut guard = self.token.lock().unwrap();
            if guard
                .as_ref()
                .map(|token| token.user_id == user_id && token.provider == provider)
                .unwrap_or(false)
            {
                *guard = None;
            }
            self.delete_calls.lock().unwrap().push((user_id, provider));
            Ok(())
        }

        async fn list_tokens_for_user(
            &self,
            _user_id: Uuid,
        ) -> Result<Vec<UserOAuthToken>, sqlx::Error> {
            let guard = self.token.lock().unwrap();
            Ok(guard
                .as_ref()
                .filter(|token| token.user_id == _user_id)
                .cloned()
                .into_iter()
                .collect())
        }

        async fn mark_shared(
            &self,
            _user_id: Uuid,
            _provider: ConnectedOAuthProvider,
            _is_shared: bool,
        ) -> Result<UserOAuthToken, sqlx::Error> {
            Err(Error::RowNotFound)
        }

        async fn list_by_user_and_provider(
            &self,
            user_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<Vec<UserOAuthToken>, sqlx::Error> {
            let guard = self.token.lock().unwrap();
            Ok(guard
                .as_ref()
                .filter(|token| token.user_id == user_id && token.provider == provider)
                .cloned()
                .into_iter()
                .collect())
        }
    }

    #[derive(Default)]
    struct UpsertingTokenRepo {
        token: Mutex<Option<UserOAuthToken>>,
    }

    impl UpsertingTokenRepo {
        fn with_existing(token: UserOAuthToken) -> Self {
            Self {
                token: Mutex::new(Some(token)),
            }
        }

        fn current(&self) -> Option<UserOAuthToken> {
            self.token.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl UserOAuthTokenRepository for UpsertingTokenRepo {
        async fn upsert_token(
            &self,
            new_token: NewUserOAuthToken,
        ) -> Result<UserOAuthToken, sqlx::Error> {
            let mut guard = self.token.lock().unwrap();
            let now = OffsetDateTime::now_utc();

            let mut record = guard
                .clone()
                .filter(|existing| {
                    existing.user_id == new_token.user_id && existing.provider == new_token.provider
                })
                .unwrap_or_else(|| UserOAuthToken {
                    id: Uuid::new_v4(),
                    user_id: new_token.user_id,
                    workspace_id: None,
                    provider: new_token.provider,
                    access_token: new_token.access_token.clone(),
                    refresh_token: new_token.refresh_token.clone(),
                    expires_at: new_token.expires_at,
                    account_email: new_token.account_email.clone(),
                    metadata: new_token.metadata.clone(),
                    is_shared: false,
                    created_at: now,
                    updated_at: now,
                });

            record.access_token = new_token.access_token.clone();
            record.refresh_token = new_token.refresh_token.clone();
            record.expires_at = new_token.expires_at;
            record.account_email = new_token.account_email.clone();
            record.metadata = new_token.metadata.clone();
            record.updated_at = now;

            *guard = Some(record.clone());
            Ok(record)
        }

        async fn find_by_id(&self, token_id: Uuid) -> Result<Option<UserOAuthToken>, sqlx::Error> {
            Ok(self
                .token
                .lock()
                .unwrap()
                .clone()
                .filter(|token| token.id == token_id))
        }

        async fn find_by_user_and_provider(
            &self,
            user_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<Option<UserOAuthToken>, sqlx::Error> {
            Ok(self
                .token
                .lock()
                .unwrap()
                .clone()
                .filter(|token| token.user_id == user_id && token.provider == provider))
        }

        async fn delete_token(
            &self,
            user_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<(), sqlx::Error> {
            let mut guard = self.token.lock().unwrap();
            if guard
                .as_ref()
                .map(|token| token.user_id == user_id && token.provider == provider)
                .unwrap_or(false)
            {
                *guard = None;
            }
            Ok(())
        }

        async fn list_tokens_for_user(
            &self,
            user_id: Uuid,
        ) -> Result<Vec<UserOAuthToken>, sqlx::Error> {
            Ok(self
                .token
                .lock()
                .unwrap()
                .clone()
                .filter(|token| token.user_id == user_id)
                .into_iter()
                .collect())
        }

        async fn mark_shared(
            &self,
            user_id: Uuid,
            provider: ConnectedOAuthProvider,
            is_shared: bool,
        ) -> Result<UserOAuthToken, sqlx::Error> {
            let mut guard = self.token.lock().unwrap();
            if let Some(token) = guard
                .as_mut()
                .filter(|token| token.user_id == user_id && token.provider == provider)
            {
                token.is_shared = is_shared;
                token.updated_at = OffsetDateTime::now_utc();
                return Ok(token.clone());
            }
            Err(Error::RowNotFound)
        }

        async fn list_by_user_and_provider(
            &self,
            user_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<Vec<UserOAuthToken>, sqlx::Error> {
            Ok(self
                .token
                .lock()
                .unwrap()
                .clone()
                .filter(|token| token.user_id == user_id && token.provider == provider)
                .into_iter()
                .collect())
        }
    }

    struct MultiTokenRepo {
        tokens: Mutex<Vec<UserOAuthToken>>,
    }

    impl MultiTokenRepo {
        fn new() -> Self {
            Self {
                tokens: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl UserOAuthTokenRepository for MultiTokenRepo {
        async fn upsert_token(
            &self,
            _new_token: NewUserOAuthToken,
        ) -> Result<UserOAuthToken, sqlx::Error> {
            panic!("upsert_token should not be called for multi token repo")
        }

        async fn insert_token(
            &self,
            new_token: NewUserOAuthToken,
        ) -> Result<UserOAuthToken, sqlx::Error> {
            let mut guard = self.tokens.lock().unwrap();
            let record = UserOAuthToken {
                id: Uuid::new_v4(),
                user_id: new_token.user_id,
                workspace_id: None,
                provider: new_token.provider,
                access_token: new_token.access_token.clone(),
                refresh_token: new_token.refresh_token.clone(),
                expires_at: new_token.expires_at,
                account_email: new_token.account_email.clone(),
                metadata: new_token.metadata.clone(),
                is_shared: false,
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
            };
            guard.push(record.clone());
            Ok(record)
        }

        async fn update_token(
            &self,
            token_id: Uuid,
            new_token: NewUserOAuthToken,
        ) -> Result<UserOAuthToken, sqlx::Error> {
            let mut guard = self.tokens.lock().unwrap();
            if let Some(existing) = guard.iter_mut().find(|token| token.id == token_id) {
                existing.access_token = new_token.access_token.clone();
                existing.refresh_token = new_token.refresh_token.clone();
                existing.expires_at = new_token.expires_at;
                existing.account_email = new_token.account_email.clone();
                existing.metadata = new_token.metadata.clone();
                existing.provider = new_token.provider;
                existing.user_id = new_token.user_id;
                existing.updated_at = OffsetDateTime::now_utc();
                return Ok(existing.clone());
            }

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
            user_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<(), sqlx::Error> {
            let mut guard = self.tokens.lock().unwrap();
            if let Some(position) = guard
                .iter()
                .rposition(|token| token.user_id == user_id && token.provider == provider)
            {
                guard.remove(position);
            }
            Ok(())
        }

        async fn delete_token_by_id(&self, token_id: Uuid) -> Result<(), sqlx::Error> {
            let mut guard = self.tokens.lock().unwrap();
            guard.retain(|token| token.id != token_id);
            Ok(())
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
                existing.updated_at = OffsetDateTime::now_utc();
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
                existing.updated_at = OffsetDateTime::now_utc();
                return Ok(existing.clone());
            }

            Err(sqlx::Error::RowNotFound)
        }
    }

    type WorkspaceUpdateCall = (Uuid, String, String, OffsetDateTime, String);
    type WorkspaceMetadataCall = (Option<String>, Option<String>, Option<String>);

    #[derive(Default)]
    struct RecordingWorkspaceRepo {
        stale_calls: Mutex<Vec<(Uuid, ConnectedOAuthProvider)>>,
        stale_return: Mutex<Vec<StaleWorkspaceConnection>>,
        source_calls: Mutex<Vec<Uuid>>,
        source_connections: Mutex<Vec<WorkspaceConnection>>,
        updates: Mutex<Vec<WorkspaceUpdateCall>>,
        update_metadata: Mutex<Vec<WorkspaceMetadataCall>>,
    }

    impl RecordingWorkspaceRepo {
        fn stale_calls(&self) -> Vec<(Uuid, ConnectedOAuthProvider)> {
            self.stale_calls.lock().unwrap().clone()
        }

        fn set_stale_connections(&self, connections: Vec<StaleWorkspaceConnection>) {
            *self.stale_return.lock().unwrap() = connections;
        }

        fn source_calls(&self) -> Vec<Uuid> {
            self.source_calls.lock().unwrap().clone()
        }

        fn update_calls(&self) -> Vec<WorkspaceUpdateCall> {
            self.updates.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl WorkspaceConnectionRepository for RecordingWorkspaceRepo {
        async fn insert_connection(
            &self,
            _new_connection: crate::db::workspace_connection_repository::NewWorkspaceConnection,
        ) -> Result<WorkspaceConnection, sqlx::Error> {
            Err(Error::RowNotFound)
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
            Err(Error::RowNotFound)
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
            user_oauth_token_id: Uuid,
        ) -> Result<Vec<WorkspaceConnection>, sqlx::Error> {
            self.source_calls.lock().unwrap().push(user_oauth_token_id);
            Ok(self.source_connections.lock().unwrap().clone())
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
        ) -> Result<
            Vec<crate::db::workspace_connection_repository::WorkspaceConnectionListing>,
            sqlx::Error,
        > {
            Ok(Vec::new())
        }

        async fn list_for_user_memberships(
            &self,
            _user_id: Uuid,
        ) -> Result<
            Vec<crate::db::workspace_connection_repository::WorkspaceConnectionListing>,
            sqlx::Error,
        > {
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
            Err(Error::RowNotFound)
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
            self.updates.lock().unwrap().push((
                connection_id,
                access_token.clone(),
                refresh_token.clone(),
                expires_at,
                account_email.clone(),
            ));
            self.update_metadata.lock().unwrap().push((
                bot_user_id,
                slack_team_id,
                incoming_webhook_url,
            ));
            self.source_connections
                .lock()
                .unwrap()
                .iter()
                .find(|conn| conn.id == connection_id)
                .cloned()
                .ok_or(Error::RowNotFound)
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
            creator_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<Vec<StaleWorkspaceConnection>, sqlx::Error> {
            self.stale_calls
                .lock()
                .unwrap()
                .push((creator_id, provider));
            Ok(self.stale_return.lock().unwrap().clone())
        }

        async fn record_audit_event(
            &self,
            _event: crate::db::workspace_connection_repository::NewWorkspaceAuditEvent,
        ) -> Result<WorkspaceAuditEvent, sqlx::Error> {
            Err(Error::RowNotFound)
        }
    }

    #[tokio::test]
    async fn handle_revoked_token_removes_personal_credentials_and_marks_workspace() {
        let user_id = Uuid::new_v4();
        let token_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        let key = Arc::new(vec![7u8; 32]);

        let stored_token = UserOAuthToken {
            id: token_id,
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Microsoft,
            access_token: "enc-access".into(),
            refresh_token: "enc-refresh".into(),
            expires_at: now,
            account_email: "owner@example.com".into(),
            metadata: serde_json::json!({}),
            is_shared: true,
            created_at: now - Duration::hours(2),
            updated_at: now - Duration::hours(1),
        };

        let token_repo = Arc::new(RecordingTokenRepo::new(stored_token));
        let workspace_repo = Arc::new(RecordingWorkspaceRepo::default());
        workspace_repo.set_stale_connections(vec![StaleWorkspaceConnection {
            connection_id,
            workspace_id,
        }]);
        let service = OAuthAccountService::new(
            token_repo.clone(),
            workspace_repo.clone(),
            key.clone(),
            Arc::new(Client::new()),
            &OAuthSettings {
                google: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/google".into(),
                },
                microsoft: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/microsoft".into(),
                },
                slack: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/slack".into(),
                },
                asana: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                notion: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                bitly: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                raindrop: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                token_encryption_key: (*key).clone(),
            },
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
            .handle_revoked_token(user_id, ConnectedOAuthProvider::Microsoft)
            .await
            .expect("revoked cleanup should succeed");

        drop(guard);

        assert_eq!(
            token_repo.delete_calls(),
            vec![(user_id, ConnectedOAuthProvider::Microsoft)]
        );
        assert_eq!(
            workspace_repo.stale_calls(),
            vec![(user_id, ConnectedOAuthProvider::Microsoft)]
        );

        let logs = String::from_utf8(captured.lock().unwrap().clone()).unwrap();
        assert!(logs.contains(&workspace_id.to_string()));
        assert!(logs.contains(&connection_id.to_string()));
        assert!(logs.contains("shared workspace oauth connections marked stale"));
    }

    #[tokio::test]
    async fn handle_revoked_slack_token_by_connection_does_not_mark_workspace() {
        let user_id = Uuid::new_v4();
        let token_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        let key = Arc::new(vec![9u8; 32]);

        let stored_token = UserOAuthToken {
            id: token_id,
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Slack,
            access_token: "enc-access".into(),
            refresh_token: "enc-refresh".into(),
            expires_at: now,
            account_email: "owner@example.com".into(),
            metadata: serde_json::json!({}),
            is_shared: true,
            created_at: now - Duration::hours(2),
            updated_at: now - Duration::hours(1),
        };

        let token_repo = Arc::new(RecordingTokenRepo::new(stored_token));
        let workspace_repo = Arc::new(RecordingWorkspaceRepo::default());
        let service = OAuthAccountService::new(
            token_repo.clone(),
            workspace_repo.clone(),
            key,
            Arc::new(Client::new()),
            &OAuthSettings {
                google: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/google".into(),
                },
                microsoft: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/microsoft".into(),
                },
                slack: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/slack".into(),
                },
                asana: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                notion: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                bitly: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                raindrop: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                token_encryption_key: vec![0u8; 32],
            },
        );

        service
            .handle_revoked_token_by_connection(user_id, token_id)
            .await
            .expect("slack revocation should succeed");

        assert_eq!(
            token_repo.delete_calls(),
            vec![(user_id, ConnectedOAuthProvider::Slack)]
        );
        assert_eq!(workspace_repo.stale_calls(), Vec::new());
    }

    #[tokio::test]
    async fn handle_revoked_token_rejects_slack_without_connection_id() {
        let user_id = Uuid::new_v4();
        let key = Arc::new(vec![11u8; 32]);
        let token_repo = Arc::new(RecordingTokenRepo::new(UserOAuthToken {
            id: Uuid::new_v4(),
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Slack,
            access_token: "enc-access".into(),
            refresh_token: "enc-refresh".into(),
            expires_at: OffsetDateTime::now_utc(),
            account_email: "owner@example.com".into(),
            metadata: serde_json::json!({}),
            is_shared: true,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        }));
        let workspace_repo = Arc::new(RecordingWorkspaceRepo::default());
        let service = OAuthAccountService::new(
            token_repo,
            workspace_repo,
            key,
            Arc::new(Client::new()),
            &OAuthSettings {
                google: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/google".into(),
                },
                microsoft: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/microsoft".into(),
                },
                slack: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/slack".into(),
                },
                asana: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                notion: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                bitly: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                raindrop: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                token_encryption_key: vec![0u8; 32],
            },
        );

        let err = service
            .handle_revoked_token(user_id, ConnectedOAuthProvider::Slack)
            .await
            .expect_err("slack revoke should require connection id");

        match err {
            OAuthAccountError::InvalidResponse(msg) => {
                assert!(msg.contains("Slack revocation requires"), "{msg}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn save_authorization_for_connection_revokes_existing_slack_credentials() {
        let user_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        let key = Arc::new(vec![11u8; 32]);

        let existing_access = "old-access";
        let existing_refresh = "old-refresh";

        let stored_token = UserOAuthToken {
            id: Uuid::new_v4(),
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Slack,
            access_token: encrypt_secret(key.as_ref(), existing_access)
                .expect("access token encryption succeeds"),
            refresh_token: encrypt_secret(key.as_ref(), existing_refresh)
                .expect("refresh token encryption succeeds"),
            expires_at: now,
            account_email: "owner@example.com".into(),
            metadata: serde_json::json!({}),
            is_shared: false,
            created_at: now - Duration::hours(1),
            updated_at: now - Duration::minutes(15),
        };

        let repo = Arc::new(UpsertingTokenRepo::with_existing(stored_token.clone()));
        let workspace_repo = Arc::new(RecordingWorkspaceRepo::default());
        let workspace_repo_for_service = workspace_repo.clone();
        let client = Arc::new(Client::new());

        let mut service = OAuthAccountService::new(
            repo.clone(),
            workspace_repo_for_service,
            key.clone(),
            client,
            &OAuthSettings {
                google: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/google".into(),
                },
                microsoft: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/microsoft".into(),
                },
                slack: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/slack".into(),
                },
                asana: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                notion: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                bitly: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                raindrop: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                token_encryption_key: (*key).clone(),
            },
        );

        let revocations = Arc::new(Mutex::new(Vec::new()));
        service.set_revocation_override(Some(Arc::new({
            let revocations = Arc::clone(&revocations);
            move |provider: ConnectedOAuthProvider, token: &str| {
                revocations
                    .lock()
                    .unwrap()
                    .push((provider, token.to_string()));
                Ok(())
            }
        })));

        let new_tokens = AuthorizationTokens {
            access_token: "new-access".into(),
            refresh_token: "new-refresh".into(),
            expires_at: now + Duration::hours(2),
            account_email: "updated@example.com".into(),
            provider_user_id: None,
            slack: None,
            notion: None,
        };

        let stored = service
            .save_authorization_for_connection(
                user_id,
                ConnectedOAuthProvider::Slack,
                stored_token.id,
                new_tokens.clone(),
            )
            .await
            .expect("save should succeed");

        assert_eq!(stored.access_token, new_tokens.access_token);
        assert_eq!(stored.refresh_token, new_tokens.refresh_token);
        assert_eq!(stored.account_email, new_tokens.account_email);

        let recorded = revocations.lock().unwrap().clone();
        assert_eq!(
            recorded,
            vec![
                (ConnectedOAuthProvider::Slack, existing_refresh.to_string()),
                (ConnectedOAuthProvider::Slack, existing_access.to_string()),
            ]
        );

        let persisted = repo
            .current()
            .expect("repo should retain most recent token record");
        assert_eq!(persisted.account_email, new_tokens.account_email);
    }

    #[tokio::test]
    async fn save_authorization_inserts_new_connection_without_overwriting() {
        let user_id = Uuid::new_v4();
        let key = Arc::new(vec![13u8; 32]);
        let repo = Arc::new(MultiTokenRepo::new());
        let workspace_repo = Arc::new(RecordingWorkspaceRepo::default());
        let client = Arc::new(Client::new());

        let service = OAuthAccountService::new(
            repo.clone(),
            workspace_repo,
            key.clone(),
            client,
            &OAuthSettings {
                google: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/google".into(),
                },
                microsoft: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/microsoft".into(),
                },
                slack: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/slack".into(),
                },
                asana: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                notion: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                bitly: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                raindrop: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                token_encryption_key: (*key).clone(),
            },
        );

        let first = service
            .save_authorization(
                user_id,
                ConnectedOAuthProvider::Google,
                AuthorizationTokens {
                    access_token: "first-access".into(),
                    refresh_token: "first-refresh".into(),
                    expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
                    account_email: "first@example.com".into(),
                    provider_user_id: None,
                    slack: None,
                    notion: None,
                },
            )
            .await
            .expect("first save succeeds");

        let second = service
            .save_authorization(
                user_id,
                ConnectedOAuthProvider::Google,
                AuthorizationTokens {
                    access_token: "second-access".into(),
                    refresh_token: "second-refresh".into(),
                    expires_at: OffsetDateTime::now_utc() + Duration::hours(2),
                    account_email: "second@example.com".into(),
                    provider_user_id: None,
                    slack: None,
                    notion: None,
                },
            )
            .await
            .expect("second save succeeds");

        assert_ne!(first.id, second.id);

        let tokens = repo.tokens.lock().unwrap();
        assert_eq!(tokens.len(), 2);
        assert_eq!(tokens[0].account_email, "first@example.com");
        assert_eq!(tokens[1].account_email, "second@example.com");
    }

    #[tokio::test]
    async fn save_authorization_deduped_updates_existing_and_preserves_connection_id() {
        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let existing_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        let key = Arc::new(vec![21u8; 32]);

        let encrypted_access = encrypt_secret(&key, "old-access").expect("encrypt access");
        let encrypted_refresh = encrypt_secret(&key, "old-refresh").expect("encrypt refresh");
        let metadata = serialize_token_metadata(OAuthTokenMetadata {
            slack: None,
            notion: None,
            provider_user_id: Some("google-123".into()),
        });

        let repo = Arc::new(MultiTokenRepo::new());
        repo.tokens.lock().unwrap().push(UserOAuthToken {
            id: existing_id,
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Google,
            access_token: encrypted_access,
            refresh_token: encrypted_refresh,
            expires_at: now + Duration::hours(1),
            account_email: "owner@example.com".into(),
            metadata,
            is_shared: false,
            created_at: now - Duration::hours(2),
            updated_at: now - Duration::minutes(5),
        });

        let workspace_repo = Arc::new(RecordingWorkspaceRepo::default());
        let workspace_connection_id = Uuid::new_v4();
        workspace_repo
            .source_connections
            .lock()
            .unwrap()
            .push(WorkspaceConnection {
                id: workspace_connection_id,
                connection_id: Some(existing_id),
                workspace_id,
                created_by: user_id,
                owner_user_id: user_id,
                user_oauth_token_id: Some(existing_id),
                provider: ConnectedOAuthProvider::Google,
                access_token: "enc-access".into(),
                refresh_token: "enc-refresh".into(),
                expires_at: now,
                account_email: "owner@example.com".into(),
                created_at: now,
                updated_at: now,
                bot_user_id: None,
                slack_team_id: Some("T123".into()),
                incoming_webhook_url: None,
                metadata: serde_json::json!({}),
            });

        let mut service = OAuthAccountService::new(
            repo.clone(),
            workspace_repo.clone(),
            key.clone(),
            Arc::new(Client::new()),
            &OAuthSettings {
                google: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/google".into(),
                },
                microsoft: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/microsoft".into(),
                },
                slack: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/slack".into(),
                },
                asana: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                notion: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                bitly: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                raindrop: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                token_encryption_key: (*key).clone(),
            },
        );
        fn noop_revocation(
            _provider: ConnectedOAuthProvider,
            _token: &str,
        ) -> Result<(), OAuthAccountError> {
            Ok(())
        }
        service.set_revocation_override(Some(Arc::new(noop_revocation)));

        let tokens = AuthorizationTokens {
            access_token: "new-access".into(),
            refresh_token: "new-refresh".into(),
            expires_at: now + Duration::hours(2),
            account_email: "new@example.com".into(),
            provider_user_id: Some("google-123".into()),
            slack: None,
            notion: None,
        };

        let stored = service
            .save_authorization_deduped(user_id, ConnectedOAuthProvider::Google, tokens)
            .await
            .expect("deduped save succeeds");

        assert_eq!(stored.id, existing_id);
        assert_eq!(repo.tokens.lock().unwrap().len(), 1);

        assert_eq!(workspace_repo.source_calls(), vec![existing_id]);
        let update_calls = workspace_repo.update_calls();
        assert_eq!(update_calls.len(), 1);
        assert_eq!(update_calls[0].0, workspace_connection_id);
        assert_eq!(update_calls[0].4, "new@example.com");
    }

    #[tokio::test]
    async fn save_authorization_deduped_does_not_update_workspace_connections_for_slack() {
        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let existing_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        let key = Arc::new(vec![23u8; 32]);

        let encrypted_access = encrypt_secret(&key, "old-access").expect("encrypt access");
        let encrypted_refresh = encrypt_secret(&key, "old-refresh").expect("encrypt refresh");
        let metadata = serialize_token_metadata(OAuthTokenMetadata {
            slack: Some(EncryptedSlackOAuthMetadata {
                team_id: Some(encrypt_secret(&key, "T123").expect("encrypt team id")),
                bot_user_id: None,
                incoming_webhook_url: None,
            }),
            provider_user_id: Some("slack-123".into()),
            notion: None,
        });

        let repo = Arc::new(MultiTokenRepo::new());
        repo.tokens.lock().unwrap().push(UserOAuthToken {
            id: existing_id,
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Slack,
            access_token: encrypted_access,
            refresh_token: encrypted_refresh,
            expires_at: now + Duration::hours(1),
            account_email: "owner@example.com".into(),
            metadata,
            is_shared: true,
            created_at: now - Duration::hours(2),
            updated_at: now - Duration::minutes(5),
        });

        let workspace_repo = Arc::new(RecordingWorkspaceRepo::default());
        workspace_repo
            .source_connections
            .lock()
            .unwrap()
            .push(WorkspaceConnection {
                id: Uuid::new_v4(),
                connection_id: Some(existing_id),
                workspace_id,
                created_by: user_id,
                owner_user_id: user_id,
                user_oauth_token_id: Some(existing_id),
                provider: ConnectedOAuthProvider::Slack,
                access_token: "enc-access".into(),
                refresh_token: "enc-refresh".into(),
                expires_at: now,
                account_email: "owner@example.com".into(),
                created_at: now,
                updated_at: now,
                bot_user_id: None,
                slack_team_id: Some("T123".into()),
                incoming_webhook_url: None,
                metadata: serde_json::json!({}),
            });

        let tokens = AuthorizationTokens {
            access_token: "new-access".into(),
            refresh_token: "new-refresh".into(),
            expires_at: now + Duration::hours(2),
            account_email: "new@example.com".into(),
            provider_user_id: Some("slack-123".into()),
            slack: Some(SlackOAuthMetadata {
                team_id: Some("T123".into()),
                bot_user_id: Some("B456".into()),
                incoming_webhook_url: None,
            }),
            notion: None,
        };

        let stored = OAuthAccountService::new(
            repo.clone(),
            workspace_repo.clone(),
            key.clone(),
            Arc::new(Client::new()),
            &OAuthSettings {
                google: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/google".into(),
                },
                microsoft: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/microsoft".into(),
                },
                slack: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/slack".into(),
                },
                asana: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                notion: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                bitly: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                raindrop: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                token_encryption_key: (*key).clone(),
            },
        )
        .save_authorization_deduped(user_id, ConnectedOAuthProvider::Slack, tokens)
        .await
        .expect("deduped slack save succeeds");

        assert_eq!(stored.id, existing_id);
        assert!(workspace_repo.source_calls().is_empty());
        assert!(workspace_repo.update_calls().is_empty());
    }

    #[tokio::test]
    async fn save_authorization_deduped_allows_multiple_slack_teams() {
        let user_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        let key = Arc::new(vec![26u8; 32]);

        let metadata = serialize_token_metadata(OAuthTokenMetadata {
            slack: Some(EncryptedSlackOAuthMetadata {
                team_id: Some(encrypt_secret(&key, "T123").expect("encrypt team id")),
                bot_user_id: None,
                incoming_webhook_url: None,
            }),
            provider_user_id: Some("U123".into()),
            notion: None,
        });

        let repo = Arc::new(MultiTokenRepo::new());
        repo.tokens.lock().unwrap().push(UserOAuthToken {
            id: Uuid::new_v4(),
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Slack,
            access_token: encrypt_secret(&key, "old-access").expect("encrypt access"),
            refresh_token: encrypt_secret(&key, "old-refresh").expect("encrypt refresh"),
            expires_at: now + Duration::hours(1),
            account_email: "owner@example.com".into(),
            metadata,
            is_shared: false,
            created_at: now - Duration::hours(2),
            updated_at: now - Duration::minutes(5),
        });

        let workspace_repo = Arc::new(RecordingWorkspaceRepo::default());
        let service = OAuthAccountService::new(
            repo.clone(),
            workspace_repo,
            key.clone(),
            Arc::new(Client::new()),
            &OAuthSettings {
                google: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/google".into(),
                },
                microsoft: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/microsoft".into(),
                },
                slack: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/slack".into(),
                },
                asana: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                notion: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                bitly: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                raindrop: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                token_encryption_key: (*key).clone(),
            },
        );

        let tokens = AuthorizationTokens {
            access_token: "new-access".into(),
            refresh_token: "new-refresh".into(),
            expires_at: now + Duration::hours(2),
            account_email: "new@example.com".into(),
            provider_user_id: Some("U123".into()),
            slack: Some(SlackOAuthMetadata {
                team_id: Some("T999".into()),
                bot_user_id: Some("B456".into()),
                incoming_webhook_url: None,
            }),
            notion: None,
        };

        let stored = service
            .save_authorization_deduped(user_id, ConnectedOAuthProvider::Slack, tokens)
            .await
            .expect("slack save succeeds");

        let records = repo.tokens.lock().unwrap();
        assert_eq!(records.len(), 2);
        assert!(records.iter().any(|t| t.id == stored.id));
    }

    #[tokio::test]
    async fn save_authorization_deduped_inserts_new_after_removal() {
        let user_id = Uuid::new_v4();
        let removed_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        let key = Arc::new(vec![22u8; 32]);

        let repo = Arc::new(MultiTokenRepo::new());
        repo.tokens.lock().unwrap().push(UserOAuthToken {
            id: removed_id,
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Google,
            access_token: encrypt_secret(&key, "old-access").expect("encrypt access"),
            refresh_token: encrypt_secret(&key, "old-refresh").expect("encrypt refresh"),
            expires_at: now,
            account_email: "old@example.com".into(),
            metadata: serialize_token_metadata(OAuthTokenMetadata {
                slack: None,
                notion: None,
                provider_user_id: Some("google-456".into()),
            }),
            is_shared: false,
            created_at: now - Duration::hours(1),
            updated_at: now - Duration::minutes(10),
        });
        repo.delete_token_by_id(removed_id)
            .await
            .expect("remove token");
        let workspace_repo = Arc::new(RecordingWorkspaceRepo::default());
        let service = OAuthAccountService::new(
            repo.clone(),
            workspace_repo.clone(),
            key.clone(),
            Arc::new(Client::new()),
            &OAuthSettings {
                google: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/google".into(),
                },
                microsoft: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/microsoft".into(),
                },
                slack: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/slack".into(),
                },
                asana: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                notion: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                bitly: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                raindrop: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                token_encryption_key: (*key).clone(),
            },
        );

        let tokens = AuthorizationTokens {
            access_token: "fresh-access".into(),
            refresh_token: "fresh-refresh".into(),
            expires_at: now + Duration::hours(1),
            account_email: "new@example.com".into(),
            provider_user_id: Some("google-456".into()),
            slack: None,
            notion: None,
        };

        let stored = service
            .save_authorization_deduped(user_id, ConnectedOAuthProvider::Google, tokens)
            .await
            .expect("deduped insert succeeds");

        assert_ne!(stored.id, removed_id);
        assert_eq!(repo.tokens.lock().unwrap().len(), 1);
        assert!(workspace_repo.source_calls().is_empty());
        assert!(workspace_repo.update_calls().is_empty());
    }

    #[tokio::test]
    #[ignore]
    async fn save_authorization_inserts_multiple_personal_tokens_for_same_provider_in_postgres() {
        let pool = test_pg_pool();
        let repo = Arc::new(PostgresUserOAuthTokenRepository {
            pool: (*pool).clone(),
        });

        let user_row = sqlx::query(
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
        .bind(format!("multi-oauth-{}@example.com", Uuid::new_v4()))
        .bind("First")
        .bind("User")
        .bind("google")
        .bind(OffsetDateTime::now_utc())
        .fetch_one(&repo.pool)
        .await
        .expect("insert user");
        let user_id: Uuid = user_row.get("id");

        // Clear any residual tokens for this user (defensive)
        query("DELETE FROM user_oauth_tokens WHERE user_id = $1")
            .bind(user_id)
            .execute(&repo.pool)
            .await
            .expect("clear user tokens");

        let workspace_repo: Arc<dyn WorkspaceConnectionRepository> =
            Arc::new(NoopWorkspaceConnectionRepository {});
        let key = Arc::new(vec![19u8; 32]);
        let client = Arc::new(Client::new());
        let service = OAuthAccountService::new(
            repo.clone(),
            workspace_repo,
            key.clone(),
            client,
            &OAuthSettings {
                google: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/google".into(),
                },
                microsoft: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/microsoft".into(),
                },
                slack: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/slack".into(),
                },
                asana: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                notion: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                bitly: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                raindrop: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                token_encryption_key: (*key).clone(),
            },
        );

        let first = service
            .save_authorization(
                user_id,
                ConnectedOAuthProvider::Google,
                AuthorizationTokens {
                    access_token: "first-access".into(),
                    refresh_token: "first-refresh".into(),
                    expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
                    account_email: "first@example.com".into(),
                    provider_user_id: None,
                    slack: None,
                    notion: None,
                },
            )
            .await
            .expect("first save succeeds");

        let second = service
            .save_authorization(
                user_id,
                ConnectedOAuthProvider::Google,
                AuthorizationTokens {
                    access_token: "second-access".into(),
                    refresh_token: "second-refresh".into(),
                    expires_at: OffsetDateTime::now_utc() + Duration::hours(2),
                    account_email: "second@example.com".into(),
                    provider_user_id: None,
                    slack: None,
                    notion: None,
                },
            )
            .await
            .expect("second save succeeds");

        assert_ne!(first.id, second.id);

        let tokens = repo
            .list_tokens_for_user(user_id)
            .await
            .expect("list tokens");
        assert_eq!(tokens.len(), 2);
        assert!(tokens
            .iter()
            .all(|token| token.provider == ConnectedOAuthProvider::Google));
        let emails: Vec<_> = tokens.iter().map(|t| t.account_email.clone()).collect();
        assert!(emails.contains(&"first@example.com".to_string()));
        assert!(emails.contains(&"second@example.com".to_string()));

        // Cleanup to keep the test database isolated
        query("DELETE FROM user_oauth_tokens WHERE user_id = $1")
            .bind(user_id)
            .execute(&repo.pool)
            .await
            .ok();
        query("DELETE FROM users WHERE id = $1")
            .bind(user_id)
            .execute(&repo.pool)
            .await
            .ok();
    }

    #[tokio::test]
    async fn ensure_valid_access_token_for_connection_refreshes_target_token_only() {
        let user_id = Uuid::new_v4();
        let key = Arc::new(vec![17u8; 32]);
        let repo = Arc::new(MultiTokenRepo::new());
        let workspace_repo = Arc::new(RecordingWorkspaceRepo::default());
        let workspace_repo_for_service = workspace_repo.clone();
        let client = Arc::new(Client::new());

        let mut service = OAuthAccountService::new(
            repo.clone(),
            workspace_repo_for_service,
            key.clone(),
            client,
            &OAuthSettings {
                google: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/google".into(),
                },
                microsoft: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/microsoft".into(),
                },
                slack: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/slack".into(),
                },
                asana: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                notion: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                bitly: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                raindrop: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                token_encryption_key: (*key).clone(),
            },
        );

        let expiring = service
            .save_authorization(
                user_id,
                ConnectedOAuthProvider::Google,
                AuthorizationTokens {
                    access_token: "stale-access".into(),
                    refresh_token: "refresh-target".into(),
                    expires_at: OffsetDateTime::now_utc() + Duration::seconds(10),
                    account_email: "expiring@example.com".into(),
                    provider_user_id: None,
                    slack: None,
                    notion: None,
                },
            )
            .await
            .expect("first connection saved");

        let stable = service
            .save_authorization(
                user_id,
                ConnectedOAuthProvider::Google,
                AuthorizationTokens {
                    access_token: "fresh-access".into(),
                    refresh_token: "refresh-other".into(),
                    expires_at: OffsetDateTime::now_utc() + Duration::hours(4),
                    account_email: "stable@example.com".into(),
                    provider_user_id: None,
                    slack: None,
                    notion: None,
                },
            )
            .await
            .expect("second connection saved");

        service.set_refresh_override(Some(Arc::new(
            move |provider: ConnectedOAuthProvider, refresh: &str| {
                assert_eq!(provider, ConnectedOAuthProvider::Google);
                assert_eq!(refresh, "refresh-target");
                Ok(AuthorizationTokens {
                    access_token: "refreshed-access".into(),
                    refresh_token: "refreshed-refresh".into(),
                    expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
                    account_email: "expiring@example.com".into(),
                    provider_user_id: None,
                    slack: None,
                    notion: None,
                })
            },
        )));

        let refreshed = service
            .ensure_valid_access_token_for_connection(user_id, expiring.id)
            .await
            .expect("refresh succeeds");

        assert_eq!(refreshed.access_token, "refreshed-access");
        assert_eq!(refreshed.refresh_token, "refreshed-refresh");
        assert_eq!(refreshed.id, expiring.id);

        // Non-targeted token remains unchanged
        let tokens = repo.tokens.lock().unwrap();
        let stable_record = tokens
            .iter()
            .find(|token| token.id == stable.id)
            .expect("stable token present");
        assert_eq!(
            decrypt_secret(&key, &stable_record.refresh_token).unwrap(),
            "refresh-other"
        );
        assert_eq!(workspace_repo.update_calls(), Vec::new());
        assert_eq!(workspace_repo.source_calls(), vec![expiring.id]);
        assert_eq!(workspace_repo.stale_calls(), Vec::new());
    }

    #[tokio::test]
    async fn ensure_valid_access_token_for_connection_does_not_update_workspace_for_slack() {
        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let token_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        let key = Arc::new(vec![25u8; 32]);
        let encrypted_access = encrypt_secret(&key, "slack-old-access").unwrap();
        let encrypted_refresh = encrypt_secret(&key, "slack-old-refresh").unwrap();
        let metadata = serialize_token_metadata(OAuthTokenMetadata {
            slack: None,
            notion: None,
            provider_user_id: Some("U123".into()),
        });

        let repo = Arc::new(MultiTokenRepo::new());
        repo.tokens.lock().unwrap().push(UserOAuthToken {
            id: token_id,
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Slack,
            access_token: encrypted_access,
            refresh_token: encrypted_refresh,
            expires_at: now - Duration::minutes(5),
            account_email: "slack@example.com".into(),
            metadata,
            is_shared: false,
            created_at: now - Duration::hours(1),
            updated_at: now - Duration::minutes(10),
        });

        let workspace_repo = Arc::new(RecordingWorkspaceRepo::default());
        workspace_repo
            .source_connections
            .lock()
            .unwrap()
            .push(WorkspaceConnection {
                id: Uuid::new_v4(),
                connection_id: Some(token_id),
                workspace_id,
                created_by: user_id,
                owner_user_id: user_id,
                user_oauth_token_id: Some(token_id),
                provider: ConnectedOAuthProvider::Slack,
                access_token: "enc-access".into(),
                refresh_token: "enc-refresh".into(),
                expires_at: now,
                account_email: "slack@example.com".into(),
                created_at: now,
                updated_at: now,
                bot_user_id: None,
                slack_team_id: Some("T123".into()),
                incoming_webhook_url: None,
                metadata: serde_json::json!({}),
            });

        let mut service = OAuthAccountService::new(
            repo.clone(),
            workspace_repo.clone(),
            key.clone(),
            Arc::new(Client::new()),
            &OAuthSettings {
                google: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/google".into(),
                },
                microsoft: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/microsoft".into(),
                },
                slack: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/slack".into(),
                },
                asana: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                notion: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                bitly: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                raindrop: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                token_encryption_key: (*key).clone(),
            },
        );

        service.set_refresh_override(Some(Arc::new(
            move |provider: ConnectedOAuthProvider, refresh: &str| {
                assert_eq!(provider, ConnectedOAuthProvider::Slack);
                assert_eq!(refresh, "slack-old-refresh");
                Ok(AuthorizationTokens {
                    access_token: "slack-new-access".into(),
                    refresh_token: "slack-new-refresh".into(),
                    expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
                    account_email: "slack@example.com".into(),
                    provider_user_id: Some("U123".into()),
                    slack: Some(SlackOAuthMetadata {
                        team_id: Some("T123".into()),
                        bot_user_id: Some("B456".into()),
                        incoming_webhook_url: None,
                    }),
                    notion: None,
                })
            },
        )));

        let refreshed = service
            .ensure_valid_access_token_for_connection(user_id, token_id)
            .await
            .expect("slack refresh succeeds");

        assert_eq!(refreshed.access_token, "slack-new-access");
        assert!(workspace_repo.source_calls().is_empty());
        assert!(workspace_repo.update_calls().is_empty());
    }

    #[tokio::test]
    async fn ensure_valid_access_token_for_connection_rejects_workspace_slack_connection_id() {
        let user_id = Uuid::new_v4();
        let connection_id = Uuid::new_v4();
        let key = Arc::new(vec![27u8; 32]);
        let repo = Arc::new(MultiTokenRepo::new());
        let workspace_repo = Arc::new(RecordingWorkspaceRepo::default());

        let service = OAuthAccountService::new(
            repo,
            workspace_repo,
            key.clone(),
            Arc::new(Client::new()),
            &OAuthSettings {
                google: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/google".into(),
                },
                microsoft: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/microsoft".into(),
                },
                slack: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/slack".into(),
                },
                asana: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                notion: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "http://localhost/asana".into(),
                },
                bitly: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                raindrop: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                token_encryption_key: (*key).clone(),
            },
        );

        let err = service
            .ensure_valid_access_token_for_connection(user_id, connection_id)
            .await
            .expect_err("workspace connection id should be rejected for personal refresh");

        assert!(matches!(err, OAuthAccountError::NotFound));
    }

    #[test]
    fn revocation_signal_detects_unauthorized_status() {
        assert!(is_revocation_signal(Some(StatusCode::UNAUTHORIZED), ""));
    }

    #[test]
    fn revocation_signal_detects_invalid_grant_keyword() {
        assert!(is_revocation_signal(
            Some(StatusCode::BAD_REQUEST),
            "invalid_grant"
        ));
        assert!(is_revocation_signal(None, "Token revoked by admin"));
    }
}
