use async_trait::async_trait;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebhookIngressDedupeKey {
    pub source_id: Uuid,
    pub event_type: String,
    pub payload_sha256: Vec<u8>,
    pub signature: String,
    pub timestamp_floor: OffsetDateTime,
}

#[async_trait]
pub trait WebhookIngressDedupeRepository: Send + Sync {
    async fn insert_dedupe_key(&self, key: &WebhookIngressDedupeKey) -> Result<bool, sqlx::Error>;

    async fn purge_old_dedupe_entries(&self) -> Result<u64, sqlx::Error>;
}
