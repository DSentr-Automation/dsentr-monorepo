use serde::{Deserialize, Serialize};
use sqlx::{FromRow, Type};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Type)]
#[sqlx(type_name = "provider_trigger_provider")]
#[sqlx(rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum ProviderTriggerProvider {
    Github,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ProviderTrigger {
    pub id: Uuid,
    pub workspace_id: Option<Uuid>,
    pub provider: ProviderTriggerProvider,
    pub workflow_id: Uuid,
    pub trigger_node_id: String,
    pub event_type: String,
    pub installation_id: Option<String>,
    pub repository_id: Option<String>,
    pub enabled: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct CreateProviderTrigger {
    pub workspace_id: Option<Uuid>,
    pub provider: ProviderTriggerProvider,
    pub workflow_id: Uuid,
    pub trigger_node_id: String,
    pub event_type: String,
    pub installation_id: Option<String>,
    pub repository_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct UpdateProviderTrigger {
    pub enabled: bool,
}
