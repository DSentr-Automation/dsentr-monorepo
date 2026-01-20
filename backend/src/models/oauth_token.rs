use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, Hash)]
#[sqlx(type_name = "oauth_connection_provider", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum ConnectedOAuthProvider {
    Google,
    GitHub,
    Microsoft,
    Slack,
    Asana,
    Notion,
    Bitly,
    Raindrop,
}

#[allow(dead_code)]
pub const WORKSPACE_AUDIT_EVENT_CONNECTION_PROMOTED: &str = "connection_promoted";
#[allow(dead_code)]
pub const WORKSPACE_AUDIT_EVENT_CONNECTION_UNSHARED: &str = "connection_unshared";

#[derive(Debug, Clone, sqlx::FromRow)]
/// Personal or workspace OAuth token rows; multiple entries per provider are allowed and lookups
/// are indexed by user/provider and provider/workspace scope.
pub struct UserOAuthToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub workspace_id: Option<Uuid>,
    pub provider: ConnectedOAuthProvider,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: OffsetDateTime,
    pub account_email: String,
    pub metadata: serde_json::Value,
    pub is_shared: bool,
    #[allow(dead_code)]
    pub created_at: OffsetDateTime,
    #[allow(dead_code)]
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, sqlx::FromRow)]
/// Workspace-level OAuth connections rely on provider/workspace and owner/provider indexes for
/// connection-id oriented queries.
pub struct WorkspaceConnection {
    pub id: Uuid,
    pub connection_id: Option<Uuid>,
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
    pub bot_user_id: Option<String>,
    pub slack_team_id: Option<String>,
    pub incoming_webhook_url: Option<String>,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, sqlx::FromRow)]
#[allow(dead_code)]
pub struct WorkspaceAuditEvent {
    pub id: Uuid,
    pub workspace_id: Uuid,
    pub actor_id: Uuid,
    pub event_type: String,
    pub metadata: serde_json::Value,
    #[allow(dead_code)]
    pub created_at: OffsetDateTime,
}
