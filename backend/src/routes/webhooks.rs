use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::future::Future;
use time::OffsetDateTime;
use tracing::{error, info, warn, Span};
use uuid::Uuid;

use crate::config::WebhookIngressDedupeMode;
use crate::db::postgres_webhook_delivery_repository::PostgresWebhookDeliveryRepository;
use crate::db::postgres_webhook_ingress_dedupe_repository::PostgresWebhookIngressDedupeRepository;
use crate::db::postgres_webhook_source_repository::PostgresWebhookSourceRepository;
use crate::db::postgres_webhook_subscription_repository::PostgresWebhookSubscriptionRepository;
use crate::db::webhook_delivery_repository::WebhookDeliveryRepository;
use crate::db::webhook_ingress_dedupe_repository::{
    WebhookIngressDedupeKey, WebhookIngressDedupeRepository,
};
use crate::db::webhook_source_repository::WebhookSourceRepository;
use crate::db::webhook_subscription_repository::WebhookSubscriptionRepository;
use crate::db::workflow_repository::WorkflowRepository;
use crate::db::workspace_repository::WorkspaceRepository;
use crate::models::webhook_source::WebhookSource;
use crate::models::workspace::{WorkspaceMembershipSummary, WorkspaceRole};
use crate::responses::JsonResponse;
use crate::routes::auth::session::AuthSession;
use crate::routes::webhook_ingress_validation::{
    validate_webhook_signature, WebhookSignatureError, SIGNATURE_HEADER, TIMESTAMP_HEADER,
};
use crate::state::AppState;

// Payload field used to match webhook subscriptions.
const EVENT_TYPE_FIELD: &str = "event_type";
const SIGNATURE_PREFIX: &str = "v1=";
const HASH_PREFIX_LEN: usize = 12;
const METRIC_INGRESS_DEDUPE_HIT: &str = "ingress_dedupe_hit";
const METRIC_INGRESS_DEDUPE_MISS: &str = "ingress_dedupe_miss";
const METRIC_INGRESS_DEDUPE_STORE_ERROR: &str = "ingress_dedupe_store_error";
const METRIC_INGRESS_ENQUEUED: &str = "ingress_enqueued";
const METRIC_INGRESS_ENQUEUED_FAILED: &str = "ingress_enqueued_failed";
const METRIC_SUBSCRIPTIONS_MATCHED: &str = "subscriptions_matched";
const METRIC_SUBSCRIPTIONS_MATCHED_COUNT: &str = "subscriptions_matched_count";
const METRIC_RUNS_ENQUEUED_COUNT: &str = "runs_enqueued_count";
const METRIC_RUNS_FAILED_COUNT: &str = "runs_failed_count";
const DELIVERY_STATUS_RECEIVED: &str = "received";
const DELIVERY_STATUS_ROUTED: &str = "routed";
const DELIVERY_STATUS_DROPPED: &str = "dropped";
const DELIVERY_STATUS_ERRORED: &str = "errored";
const DELIVERY_ERROR_LAST_SEEN_UPDATE_FAILED: &str = "last_seen_update_failed";
const DELIVERY_ERROR_SUBSCRIPTION_LOOKUP_FAILED: &str = "subscription_lookup_failed";
const DELIVERY_ERROR_NO_MATCHING_SUBSCRIPTIONS: &str = "no_matching_subscriptions";
const DELIVERY_ERROR_DEDUPE_ENFORCED: &str = "dedupe_enforced";
const DELIVERY_ERROR_WORKFLOW_NOT_FOUND: &str = "workflow_not_found";
const DELIVERY_ERROR_WORKFLOW_LOOKUP_FAILED: &str = "workflow_lookup_failed";
const DELIVERY_ERROR_WORKSPACE_MISMATCH: &str = "workflow_workspace_mismatch";
const DELIVERY_ERROR_RUN_ENQUEUE_FAILED: &str = "run_enqueue_failed";

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum DedupeOutcome {
    Skipped,
    Miss,
    Hit,
    StoreError,
}

impl DedupeOutcome {
    fn as_str(self) -> &'static str {
        match self {
            DedupeOutcome::Skipped => "skipped",
            DedupeOutcome::Miss => "miss",
            DedupeOutcome::Hit => "hit",
            DedupeOutcome::StoreError => "store_error",
        }
    }
}

struct DedupeKeyContext {
    key: WebhookIngressDedupeKey,
    payload_hash_prefix: String,
    signature_prefix: String,
    timestamp_floor: i64,
}

#[derive(Debug, Deserialize)]
pub struct CreateWebhookSourcePayload {
    name: Option<String>,
    require_hmac: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateWebhookSourcePayload {
    enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct CreateWebhookSubscriptionPayload {
    workflow_id: Option<Uuid>,
    trigger_node_id: Option<Uuid>,
    event_type: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateWebhookSubscriptionPayload {
    enabled: Option<bool>,
}

async fn load_memberships(
    workspace_repo: &dyn WorkspaceRepository,
    user_id: Uuid,
) -> Result<Vec<WorkspaceMembershipSummary>, Response> {
    workspace_repo
        .list_memberships_for_user(user_id)
        .await
        .map_err(|err| {
            error!(?err, %user_id, "failed to load workspace memberships");
            JsonResponse::server_error("Failed to load memberships").into_response()
        })
}

#[allow(clippy::result_large_err)]
fn workspace_role(
    memberships: &[WorkspaceMembershipSummary],
    workspace_id: Uuid,
) -> Result<WorkspaceRole, Response> {
    memberships
        .iter()
        .find(|membership| membership.workspace.id == workspace_id)
        .map(|membership| membership.role)
        .ok_or_else(|| {
            JsonResponse::forbidden("You do not have access to this workspace.").into_response()
        })
}

#[allow(clippy::result_large_err)]
fn ensure_writer_role(role: WorkspaceRole, resource: &str) -> Result<(), Response> {
    if matches!(role, WorkspaceRole::Viewer) {
        return Err(JsonResponse::forbidden(&format!(
            "Workspace viewers cannot manage {resource}."
        ))
        .into_response());
    }
    Ok(())
}

#[allow(clippy::result_large_err)]
fn require_non_empty(value: Option<String>, field: &str) -> Result<String, Response> {
    let Some(raw) = value else {
        return Err(JsonResponse::bad_request(&format!("{field} is required")).into_response());
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(JsonResponse::bad_request(&format!("{field} is required")).into_response());
    }
    Ok(trimmed.to_string())
}

#[allow(clippy::result_large_err)]
fn validate_event_type(event_type: &str) -> Result<(), Response> {
    if event_type.chars().any(|c| c.is_whitespace()) {
        return Err(
            JsonResponse::bad_request("event_type must not contain whitespace").into_response(),
        );
    }
    if event_type.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(JsonResponse::bad_request("event_type must be lowercase").into_response());
    }
    if event_type.split('.').any(|segment| {
        segment.is_empty()
            || !segment
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    }) {
        return Err(JsonResponse::bad_request(
            "event_type must be dot-separated lowercase letters or digits",
        )
        .into_response());
    }
    Ok(())
}

fn find_node<'a>(snapshot: &'a Value, node_id: &str) -> Option<&'a Value> {
    let nodes = snapshot.get("nodes")?.as_array()?;
    nodes
        .iter()
        .find(|node| node.get("id").and_then(|value| value.as_str()) == Some(node_id))
}

#[allow(clippy::result_large_err)]
fn validate_trigger_node_for_webhook(
    snapshot: &Value,
    trigger_node_id: Uuid,
) -> Result<(), Response> {
    let node_id = trigger_node_id.to_string();
    let Some(node) = find_node(snapshot, &node_id) else {
        return Err(JsonResponse::bad_request("trigger_node_id is invalid").into_response());
    };
    let node_type = node
        .get("type")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    if !node_type.eq_ignore_ascii_case("trigger") {
        return Err(
            JsonResponse::bad_request("trigger_node_id must reference a trigger node")
                .into_response(),
        );
    }
    let trigger_type = node
        .get("data")
        .and_then(|value| value.get("triggerType"))
        .and_then(|value| value.as_str())
        .unwrap_or("manual");
    if !trigger_type.eq_ignore_ascii_case("webhook") {
        return Err(
            JsonResponse::bad_request("trigger_node_id must reference a webhook trigger")
                .into_response(),
        );
    }
    Ok(())
}

fn trigger_type_for_node(snapshot: &Value, node_id: &str) -> Option<String> {
    let node = find_node(snapshot, node_id)?;
    node.get("data")
        .and_then(|value| value.get("triggerType"))
        .and_then(|value| value.as_str())
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
}

fn merge_trigger_context(
    mut context: Value,
    trigger_node_id: &str,
    trigger_type: &str,
    source: &str,
) -> Value {
    if let Value::Object(ref mut map) = context {
        map.insert(
            "trigger_node_id".to_string(),
            Value::String(trigger_node_id.to_string()),
        );
        map.insert(
            "trigger_type".to_string(),
            Value::String(trigger_type.to_string()),
        );
        map.insert("source".to_string(), Value::String(source.to_string()));
    } else {
        context = json!({
            "trigger_node_id": trigger_node_id,
            "trigger_type": trigger_type,
            "source": source,
            "payload": context,
        });
    }
    context
}

fn emit_counter(name: &str, value: u64) {
    info!(metric = name, count = value, "metric counter");
}

fn emit_histogram(name: &str, value: f64) {
    info!(metric = name, value, "metric histogram");
}

#[allow(clippy::too_many_arguments)]
async fn record_delivery_safe(
    delivery_repo: &dyn WebhookDeliveryRepository,
    delivery_id: Uuid,
    webhook_source_id: Uuid,
    subscription_id: Option<Uuid>,
    event_type: &str,
    received_at: OffsetDateTime,
    delivery_status: &str,
    error_message: Option<&str>,
) -> bool {
    match delivery_repo
        .record_delivery(
            delivery_id,
            webhook_source_id,
            subscription_id,
            event_type,
            received_at,
            delivery_status,
            error_message,
        )
        .await
    {
        Ok(()) => true,
        Err(err) => {
            error!(
                ?err,
                %delivery_id,
                %webhook_source_id,
                subscription_id = ?subscription_id,
                %event_type,
                delivery_status,
                "failed to record webhook delivery"
            );
            false
        }
    }
}

async fn update_delivery_status_safe(
    delivery_repo: &dyn WebhookDeliveryRepository,
    delivery_id: Uuid,
    delivery_status: &str,
    error_message: Option<&str>,
) {
    if let Err(err) = delivery_repo
        .update_delivery_status(delivery_id, delivery_status, error_message)
        .await
    {
        error!(
            ?err,
            %delivery_id,
            delivery_status,
            "failed to update webhook delivery"
        );
    }
}

fn header_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn build_dedupe_key_context(
    source: &WebhookSource,
    event_type: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<DedupeKeyContext, &'static str> {
    let timestamp = header_value(headers, TIMESTAMP_HEADER).ok_or("missing_timestamp")?;
    let signature = header_value(headers, SIGNATURE_HEADER).ok_or("missing_signature")?;

    let ts = timestamp.parse::<i64>().map_err(|_| "invalid_timestamp")?;
    if ts <= 0 {
        return Err("invalid_timestamp");
    }

    let window = source.replay_window_sec.max(1) as i64;
    let timestamp_floor = ts - (ts % window);
    let timestamp_floor_dt =
        OffsetDateTime::from_unix_timestamp(timestamp_floor).map_err(|_| "invalid_timestamp")?;

    let signature_trimmed = signature.trim();
    let signature_identity = signature_trimmed
        .strip_prefix(SIGNATURE_PREFIX)
        .unwrap_or(signature_trimmed)
        .to_string();
    if signature_identity.is_empty() {
        return Err("missing_signature");
    }

    let payload_hash = Sha256::digest(body).to_vec();
    let payload_hash_hex = hex::encode(&payload_hash);
    let payload_hash_prefix = payload_hash_hex
        .get(..HASH_PREFIX_LEN)
        .unwrap_or(payload_hash_hex.as_str())
        .to_string();
    let signature_prefix = signature_identity
        .get(..HASH_PREFIX_LEN)
        .unwrap_or(signature_identity.as_str())
        .to_string();

    Ok(DedupeKeyContext {
        key: WebhookIngressDedupeKey {
            source_id: source.id,
            event_type: event_type.to_string(),
            payload_sha256: payload_hash,
            signature: signature_identity,
            timestamp_floor: timestamp_floor_dt,
        },
        payload_hash_prefix,
        signature_prefix,
        timestamp_floor,
    })
}

async fn resolve_source_for_workspace(
    source_repo: &dyn WebhookSourceRepository,
    workspace_id: Uuid,
    source_id: Uuid,
) -> Result<crate::models::webhook_source::WebhookSource, Response> {
    match source_repo.find_webhook_source_by_id(source_id).await {
        Ok(Some(source)) if source.workspace_id == workspace_id => Ok(source),
        Ok(Some(_)) | Ok(None) => {
            Err(JsonResponse::not_found("Webhook source not found").into_response())
        }
        Err(err) => {
            error!(?err, %source_id, %workspace_id, "failed to load webhook source");
            Err(JsonResponse::server_error("Failed to load webhook source").into_response())
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct SubscriptionContext {
    _subscription_id: Uuid,
    webhook_source_id: Uuid,
    workspace_id: Uuid,
}

async fn fetch_subscription_context(
    pool: &PgPool,
    subscription_id: Uuid,
) -> Result<Option<SubscriptionContext>, sqlx::Error> {
    sqlx::query_as::<_, SubscriptionContext>(
        r#"
        SELECT ws.id AS _subscription_id,
               ws.webhook_source_id,
               src.workspace_id
        FROM webhook_subscriptions ws
        JOIN webhook_sources src ON src.id = ws.webhook_source_id
        WHERE ws.id = $1
        "#,
    )
    .bind(subscription_id)
    .fetch_optional(pool)
    .await
}

fn is_unique_violation(err: &sqlx::Error) -> bool {
    if let sqlx::Error::Database(db_err) = err {
        if let Some(code) = db_err.code() {
            return code == "23505";
        }
    }
    false
}

async fn handle_list_webhook_sources(
    source_repo: &dyn WebhookSourceRepository,
    memberships: &[WorkspaceMembershipSummary],
    workspace_id: Uuid,
) -> Response {
    if let Err(resp) = workspace_role(memberships, workspace_id) {
        return resp;
    }

    match source_repo
        .list_webhook_sources_by_workspace(workspace_id)
        .await
    {
        Ok(sources) => JsonResponse::success_with_wrapped_data(
            "Webhook sources loaded",
            json!({ "sources": sources }),
        )
        .into_response(),
        Err(err) => {
            error!(?err, %workspace_id, "failed to list webhook sources");
            JsonResponse::server_error("Failed to load webhook sources").into_response()
        }
    }
}

async fn handle_create_webhook_source(
    source_repo: &dyn WebhookSourceRepository,
    memberships: &[WorkspaceMembershipSummary],
    workspace_id: Uuid,
    name: String,
    require_hmac: bool,
) -> Response {
    let role = match workspace_role(memberships, workspace_id) {
        Ok(role) => role,
        Err(resp) => return resp,
    };

    if let Err(resp) = ensure_writer_role(role, "webhook sources") {
        return resp;
    }

    match source_repo
        .create_webhook_source_with_secret(workspace_id, &name, require_hmac)
        .await
    {
        Ok((source, secret)) => JsonResponse::success_with_wrapped_data(
            "Webhook source created",
            json!({ "source": source, "secret": secret }),
        )
        .into_response(),

        Err(err) if is_unique_violation(&err) => {
            JsonResponse::conflict("Webhook source already exists").into_response()
        }

        Err(err) => {
            error!(?err, %workspace_id, "failed to create webhook source");
            JsonResponse::server_error("Failed to create webhook source").into_response()
        }
    }
}

async fn handle_rotate_webhook_source_secret(
    source_repo: &dyn WebhookSourceRepository,
    memberships: &[WorkspaceMembershipSummary],
    workspace_id: Uuid,
    source_id: Uuid,
) -> Response {
    let role = match workspace_role(memberships, workspace_id) {
        Ok(role) => role,
        Err(resp) => return resp,
    };

    if let Err(resp) = ensure_writer_role(role, "webhook sources") {
        return resp;
    }

    match source_repo
        .rotate_webhook_source_secret_with_secret(workspace_id, source_id)
        .await
    {
        Ok((source, secret)) => JsonResponse::success_with_wrapped_data(
            "Webhook source secret rotated",
            json!({ "source": source, "secret": secret }),
        )
        .into_response(),

        Err(sqlx::Error::RowNotFound) => {
            JsonResponse::not_found("Webhook source not found").into_response()
        }

        Err(err) => {
            error!(?err, %workspace_id, %source_id, "failed to rotate webhook source secret");
            JsonResponse::server_error("Failed to rotate webhook source secret").into_response()
        }
    }
}

async fn handle_update_webhook_source_enabled(
    source_repo: &dyn WebhookSourceRepository,
    memberships: &[WorkspaceMembershipSummary],
    workspace_id: Uuid,
    source_id: Uuid,
    enabled: bool,
) -> Response {
    let role = match workspace_role(memberships, workspace_id) {
        Ok(role) => role,
        Err(resp) => return resp,
    };
    if let Err(resp) = ensure_writer_role(role, "webhook sources") {
        return resp;
    }

    match source_repo
        .update_webhook_source_enabled(workspace_id, source_id, enabled)
        .await
    {
        Ok(source) => JsonResponse::success_with_wrapped_data(
            "Webhook source updated",
            json!({ "source": source }),
        )
        .into_response(),
        Err(sqlx::Error::RowNotFound) => {
            JsonResponse::not_found("Webhook source not found").into_response()
        }
        Err(err) => {
            error!(?err, %workspace_id, %source_id, "failed to update webhook source");
            JsonResponse::server_error("Failed to update webhook source").into_response()
        }
    }
}

async fn handle_delete_webhook_source(
    source_repo: &dyn WebhookSourceRepository,
    memberships: &[WorkspaceMembershipSummary],
    workspace_id: Uuid,
    source_id: Uuid,
) -> Response {
    let role = match workspace_role(memberships, workspace_id) {
        Ok(role) => role,
        Err(resp) => return resp,
    };
    if let Err(resp) = ensure_writer_role(role, "webhook sources") {
        return resp;
    }

    match source_repo
        .delete_webhook_source(workspace_id, source_id)
        .await
    {
        Ok(()) => JsonResponse::success("Webhook source deleted").into_response(),
        Err(sqlx::Error::RowNotFound) => {
            JsonResponse::not_found("Webhook source not found").into_response()
        }
        Err(err) => {
            error!(?err, %workspace_id, %source_id, "failed to delete webhook source");
            JsonResponse::server_error("Failed to delete webhook source").into_response()
        }
    }
}

async fn handle_list_webhook_subscriptions(
    source_repo: &dyn WebhookSourceRepository,
    subscription_repo: &dyn WebhookSubscriptionRepository,
    memberships: &[WorkspaceMembershipSummary],
    workspace_id: Uuid,
    source_id: Uuid,
) -> Response {
    if let Err(resp) = workspace_role(memberships, workspace_id) {
        return resp;
    }

    if let Err(resp) = resolve_source_for_workspace(source_repo, workspace_id, source_id).await {
        return resp;
    }

    match subscription_repo
        .list_subscriptions_by_source(source_id)
        .await
    {
        Ok(subscriptions) => JsonResponse::success_with_wrapped_data(
            "Webhook subscriptions loaded",
            json!({ "subscriptions": subscriptions }),
        )
        .into_response(),
        Err(err) => {
            error!(?err, %source_id, "failed to list webhook subscriptions");
            JsonResponse::server_error("Failed to load webhook subscriptions").into_response()
        }
    }
}

async fn handle_list_webhook_subscriptions_for_source(
    source_repo: &dyn WebhookSourceRepository,
    subscription_repo: &dyn WebhookSubscriptionRepository,
    memberships: &[WorkspaceMembershipSummary],
    source_id: Uuid,
) -> Response {
    let source = match source_repo.find_webhook_source_by_id(source_id).await {
        Ok(Some(source)) => source,
        Ok(None) => return JsonResponse::not_found("Webhook source not found").into_response(),
        Err(err) => {
            error!(?err, %source_id, "failed to load webhook source");
            return JsonResponse::server_error("Failed to load webhook source").into_response();
        }
    };

    if let Err(resp) = workspace_role(memberships, source.workspace_id) {
        return resp;
    }

    match subscription_repo
        .list_subscriptions_by_source(source_id)
        .await
    {
        Ok(subscriptions) => JsonResponse::success_with_wrapped_data(
            "Webhook subscriptions loaded",
            json!({ "subscriptions": subscriptions }),
        )
        .into_response(),
        Err(err) => {
            error!(?err, %source_id, "failed to list webhook subscriptions");
            JsonResponse::server_error("Failed to load webhook subscriptions").into_response()
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_create_webhook_subscription(
    source_repo: &dyn WebhookSourceRepository,
    subscription_repo: &dyn WebhookSubscriptionRepository,
    workflow_repo: &dyn WorkflowRepository,
    memberships: &[WorkspaceMembershipSummary],
    user_id: Uuid,
    workspace_id: Uuid,
    source_id: Uuid,
    workflow_id: Uuid,
    trigger_node_id: Uuid,
    event_type: String,
) -> Response {
    let role = match workspace_role(memberships, workspace_id) {
        Ok(role) => role,
        Err(resp) => return resp,
    };

    let source = match resolve_source_for_workspace(source_repo, workspace_id, source_id).await {
        Ok(source) => source,
        Err(resp) => return resp,
    };

    handle_create_webhook_subscription_with_source(
        subscription_repo,
        workflow_repo,
        role,
        user_id,
        &source,
        workflow_id,
        trigger_node_id,
        event_type,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_create_webhook_subscription_for_source(
    source_repo: &dyn WebhookSourceRepository,
    subscription_repo: &dyn WebhookSubscriptionRepository,
    workflow_repo: &dyn WorkflowRepository,
    memberships: &[WorkspaceMembershipSummary],
    user_id: Uuid,
    source_id: Uuid,
    workflow_id: Uuid,
    trigger_node_id: Uuid,
    event_type: String,
) -> Response {
    let source = match source_repo.find_webhook_source_by_id(source_id).await {
        Ok(Some(source)) => source,
        Ok(None) => return JsonResponse::not_found("Webhook source not found").into_response(),
        Err(err) => {
            error!(?err, %source_id, "failed to load webhook source");
            return JsonResponse::server_error("Failed to load webhook source").into_response();
        }
    };

    let role = match workspace_role(memberships, source.workspace_id) {
        Ok(role) => role,
        Err(resp) => return resp,
    };

    handle_create_webhook_subscription_with_source(
        subscription_repo,
        workflow_repo,
        role,
        user_id,
        &source,
        workflow_id,
        trigger_node_id,
        event_type,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_create_webhook_subscription_with_source(
    subscription_repo: &dyn WebhookSubscriptionRepository,
    workflow_repo: &dyn WorkflowRepository,
    role: WorkspaceRole,
    user_id: Uuid,
    source: &WebhookSource,
    workflow_id: Uuid,
    trigger_node_id: Uuid,
    event_type: String,
) -> Response {
    if let Err(resp) = ensure_writer_role(role, "webhook subscriptions") {
        return resp;
    }
    if let Err(resp) = validate_event_type(&event_type) {
        return resp;
    }

    let workflow = match workflow_repo
        .find_workflow_for_member(user_id, workflow_id)
        .await
    {
        Ok(Some(workflow)) => workflow,
        Ok(None) => return JsonResponse::not_found("Workflow not found").into_response(),
        Err(err) => {
            error!(?err, %workflow_id, "failed to load workflow for webhook subscription");
            return JsonResponse::server_error("Failed to load workflow").into_response();
        }
    };

    if workflow.workspace_id != Some(source.workspace_id) {
        return JsonResponse::not_found("Workflow not found").into_response();
    }

    if let Err(resp) = validate_trigger_node_for_webhook(&workflow.data, trigger_node_id) {
        return resp;
    }

    match subscription_repo
        .create_subscription(source.id, workflow_id, trigger_node_id, &event_type)
        .await
    {
        Ok(subscription) => JsonResponse::success_with_wrapped_data(
            "Webhook subscription created",
            json!({ "subscription": subscription }),
        )
        .into_response(),
        Err(err) if is_unique_violation(&err) => {
            JsonResponse::conflict("Webhook subscription already exists").into_response()
        }
        Err(err) => {
            error!(?err, source_id = %source.id, "failed to create webhook subscription");
            JsonResponse::server_error("Failed to create webhook subscription").into_response()
        }
    }
}

async fn handle_update_webhook_subscription_enabled(
    source_repo: &dyn WebhookSourceRepository,
    subscription_repo: &dyn WebhookSubscriptionRepository,
    memberships: &[WorkspaceMembershipSummary],
    workspace_id: Uuid,
    source_id: Uuid,
    subscription_id: Uuid,
    enabled: bool,
) -> Response {
    let role = match workspace_role(memberships, workspace_id) {
        Ok(role) => role,
        Err(resp) => return resp,
    };
    if let Err(resp) = ensure_writer_role(role, "webhook subscriptions") {
        return resp;
    }

    if let Err(resp) = resolve_source_for_workspace(source_repo, workspace_id, source_id).await {
        return resp;
    }

    match subscription_repo
        .update_subscription_enabled(source_id, subscription_id, enabled)
        .await
    {
        Ok(subscription) => JsonResponse::success_with_wrapped_data(
            "Webhook subscription updated",
            json!({ "subscription": subscription }),
        )
        .into_response(),
        Err(sqlx::Error::RowNotFound) => {
            JsonResponse::not_found("Webhook subscription not found").into_response()
        }
        Err(err) => {
            error!(
                ?err,
                %source_id,
                %subscription_id,
                "failed to update webhook subscription"
            );
            JsonResponse::server_error("Failed to update webhook subscription").into_response()
        }
    }
}

async fn handle_delete_webhook_subscription(
    source_repo: &dyn WebhookSourceRepository,
    subscription_repo: &dyn WebhookSubscriptionRepository,
    memberships: &[WorkspaceMembershipSummary],
    workspace_id: Uuid,
    source_id: Uuid,
    subscription_id: Uuid,
) -> Response {
    let role = match workspace_role(memberships, workspace_id) {
        Ok(role) => role,
        Err(resp) => return resp,
    };
    if let Err(resp) = ensure_writer_role(role, "webhook subscriptions") {
        return resp;
    }

    if let Err(resp) = resolve_source_for_workspace(source_repo, workspace_id, source_id).await {
        return resp;
    }

    match subscription_repo
        .delete_subscription(source_id, subscription_id)
        .await
    {
        Ok(()) => JsonResponse::success("Webhook subscription deleted").into_response(),
        Err(sqlx::Error::RowNotFound) => {
            JsonResponse::not_found("Webhook subscription not found").into_response()
        }
        Err(err) => {
            error!(
                ?err,
                %source_id,
                %subscription_id,
                "failed to delete webhook subscription"
            );
            JsonResponse::server_error("Failed to delete webhook subscription").into_response()
        }
    }
}

async fn handle_delete_webhook_subscription_by_id<F, Fut>(
    lookup: F,
    subscription_repo: &dyn WebhookSubscriptionRepository,
    memberships: &[WorkspaceMembershipSummary],
    subscription_id: Uuid,
) -> Response
where
    F: Fn(Uuid) -> Fut,
    Fut: Future<Output = Result<Option<SubscriptionContext>, sqlx::Error>>,
{
    let context = match lookup(subscription_id).await {
        Ok(Some(context)) => context,
        Ok(None) => {
            return JsonResponse::not_found("Webhook subscription not found").into_response();
        }
        Err(err) => {
            error!(?err, %subscription_id, "failed to load webhook subscription");
            return JsonResponse::server_error("Failed to delete webhook subscription")
                .into_response();
        }
    };

    let role = match workspace_role(memberships, context.workspace_id) {
        Ok(role) => role,
        Err(resp) => return resp,
    };
    if let Err(resp) = ensure_writer_role(role, "webhook subscriptions") {
        return resp;
    }

    match subscription_repo
        .delete_subscription(context.webhook_source_id, subscription_id)
        .await
    {
        Ok(()) => JsonResponse::success("Webhook subscription deleted").into_response(),
        Err(sqlx::Error::RowNotFound) => {
            JsonResponse::not_found("Webhook subscription not found").into_response()
        }
        Err(err) => {
            error!(
                ?err,
                webhook_source_id = %context.webhook_source_id,
                %subscription_id,
                "failed to delete webhook subscription"
            );
            JsonResponse::server_error("Failed to delete webhook subscription").into_response()
        }
    }
}

pub async fn list_webhook_sources(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path(workspace_id): Path<Uuid>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    let source_repo = PostgresWebhookSourceRepository {
        pool: (*app_state.db_pool).clone(),
        encryption_key: app_state.config.api_secrets_encryption_key.clone(),
    };

    let memberships = match load_memberships(app_state.workspace_repo.as_ref(), user_id).await {
        Ok(list) => list,
        Err(resp) => return resp,
    };

    handle_list_webhook_sources(&source_repo, &memberships, workspace_id).await
}

pub async fn create_webhook_source(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path(workspace_id): Path<Uuid>,
    Json(payload): Json<CreateWebhookSourcePayload>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    let name = match require_non_empty(payload.name, "name") {
        Ok(value) => value,
        Err(resp) => return resp,
    };

    let require_hmac = payload.require_hmac.unwrap_or(true);

    let source_repo = PostgresWebhookSourceRepository {
        pool: (*app_state.db_pool).clone(),
        encryption_key: app_state.config.api_secrets_encryption_key.clone(),
    };

    let memberships = match load_memberships(app_state.workspace_repo.as_ref(), user_id).await {
        Ok(list) => list,
        Err(resp) => return resp,
    };

    handle_create_webhook_source(&source_repo, &memberships, workspace_id, name, require_hmac).await
}

pub async fn rotate_webhook_source_secret(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path((workspace_id, source_id)): Path<(Uuid, Uuid)>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    let source_repo = PostgresWebhookSourceRepository {
        pool: (*app_state.db_pool).clone(),
        encryption_key: app_state.config.api_secrets_encryption_key.clone(),
    };

    let memberships = match load_memberships(app_state.workspace_repo.as_ref(), user_id).await {
        Ok(list) => list,
        Err(resp) => return resp,
    };

    handle_rotate_webhook_source_secret(&source_repo, &memberships, workspace_id, source_id).await
}

pub async fn update_webhook_source_enabled(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path((workspace_id, source_id)): Path<(Uuid, Uuid)>,
    Json(payload): Json<UpdateWebhookSourcePayload>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };
    let Some(enabled) = payload.enabled else {
        return JsonResponse::bad_request("enabled is required").into_response();
    };

    let source_repo = PostgresWebhookSourceRepository {
        pool: (*app_state.db_pool).clone(),
        encryption_key: app_state.config.api_secrets_encryption_key.clone(),
    };

    let memberships = match load_memberships(app_state.workspace_repo.as_ref(), user_id).await {
        Ok(list) => list,
        Err(resp) => return resp,
    };

    handle_update_webhook_source_enabled(
        &source_repo,
        &memberships,
        workspace_id,
        source_id,
        enabled,
    )
    .await
}

pub async fn delete_webhook_source(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path((workspace_id, source_id)): Path<(Uuid, Uuid)>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    let source_repo = PostgresWebhookSourceRepository {
        pool: (*app_state.db_pool).clone(),
        encryption_key: app_state.config.api_secrets_encryption_key.clone(),
    };

    let memberships = match load_memberships(app_state.workspace_repo.as_ref(), user_id).await {
        Ok(list) => list,
        Err(resp) => return resp,
    };

    handle_delete_webhook_source(&source_repo, &memberships, workspace_id, source_id).await
}

pub async fn list_webhook_subscriptions_for_source(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path(source_id): Path<Uuid>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    let source_repo = PostgresWebhookSourceRepository {
        pool: (*app_state.db_pool).clone(),
        encryption_key: app_state.config.api_secrets_encryption_key.clone(),
    };
    let subscription_repo = PostgresWebhookSubscriptionRepository {
        pool: (*app_state.db_pool).clone(),
    };

    let memberships = match load_memberships(app_state.workspace_repo.as_ref(), user_id).await {
        Ok(list) => list,
        Err(resp) => return resp,
    };

    handle_list_webhook_subscriptions_for_source(
        &source_repo,
        &subscription_repo,
        &memberships,
        source_id,
    )
    .await
}

pub async fn list_webhook_subscriptions(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path((workspace_id, source_id)): Path<(Uuid, Uuid)>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    let source_repo = PostgresWebhookSourceRepository {
        pool: (*app_state.db_pool).clone(),
        encryption_key: app_state.config.api_secrets_encryption_key.clone(),
    };
    let subscription_repo = PostgresWebhookSubscriptionRepository {
        pool: (*app_state.db_pool).clone(),
    };

    let memberships = match load_memberships(app_state.workspace_repo.as_ref(), user_id).await {
        Ok(list) => list,
        Err(resp) => return resp,
    };

    handle_list_webhook_subscriptions(
        &source_repo,
        &subscription_repo,
        &memberships,
        workspace_id,
        source_id,
    )
    .await
}

pub async fn create_webhook_subscription(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path((workspace_id, source_id)): Path<(Uuid, Uuid)>,
    Json(payload): Json<CreateWebhookSubscriptionPayload>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    let workflow_id = match payload.workflow_id {
        Some(value) => value,
        None => return JsonResponse::bad_request("workflow_id is required").into_response(),
    };
    let trigger_node_id = match payload.trigger_node_id {
        Some(value) => value,
        None => return JsonResponse::bad_request("trigger_node_id is required").into_response(),
    };
    let event_type = match require_non_empty(payload.event_type, "event_type") {
        Ok(value) => value,
        Err(resp) => return resp,
    };

    let source_repo = PostgresWebhookSourceRepository {
        pool: (*app_state.db_pool).clone(),
        encryption_key: app_state.config.api_secrets_encryption_key.clone(),
    };
    let subscription_repo = PostgresWebhookSubscriptionRepository {
        pool: (*app_state.db_pool).clone(),
    };

    let memberships = match load_memberships(app_state.workspace_repo.as_ref(), user_id).await {
        Ok(list) => list,
        Err(resp) => return resp,
    };

    handle_create_webhook_subscription(
        &source_repo,
        &subscription_repo,
        app_state.workflow_repo.as_ref(),
        &memberships,
        user_id,
        workspace_id,
        source_id,
        workflow_id,
        trigger_node_id,
        event_type,
    )
    .await
}

pub async fn create_webhook_subscription_for_source(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path(source_id): Path<Uuid>,
    Json(payload): Json<CreateWebhookSubscriptionPayload>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    let workflow_id = match payload.workflow_id {
        Some(value) => value,
        None => return JsonResponse::bad_request("workflow_id is required").into_response(),
    };
    let trigger_node_id = match payload.trigger_node_id {
        Some(value) => value,
        None => return JsonResponse::bad_request("trigger_node_id is required").into_response(),
    };
    let event_type = match require_non_empty(payload.event_type, "event_type") {
        Ok(value) => value,
        Err(resp) => return resp,
    };

    let source_repo = PostgresWebhookSourceRepository {
        pool: (*app_state.db_pool).clone(),
        encryption_key: app_state.config.api_secrets_encryption_key.clone(),
    };
    let subscription_repo = PostgresWebhookSubscriptionRepository {
        pool: (*app_state.db_pool).clone(),
    };

    let memberships = match load_memberships(app_state.workspace_repo.as_ref(), user_id).await {
        Ok(list) => list,
        Err(resp) => return resp,
    };

    handle_create_webhook_subscription_for_source(
        &source_repo,
        &subscription_repo,
        app_state.workflow_repo.as_ref(),
        &memberships,
        user_id,
        source_id,
        workflow_id,
        trigger_node_id,
        event_type,
    )
    .await
}

pub async fn update_webhook_subscription_enabled(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path((workspace_id, source_id, subscription_id)): Path<(Uuid, Uuid, Uuid)>,
    Json(payload): Json<UpdateWebhookSubscriptionPayload>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };
    let Some(enabled) = payload.enabled else {
        return JsonResponse::bad_request("enabled is required").into_response();
    };

    let source_repo = PostgresWebhookSourceRepository {
        pool: (*app_state.db_pool).clone(),
        encryption_key: app_state.config.api_secrets_encryption_key.clone(),
    };
    let subscription_repo = PostgresWebhookSubscriptionRepository {
        pool: (*app_state.db_pool).clone(),
    };

    let memberships = match load_memberships(app_state.workspace_repo.as_ref(), user_id).await {
        Ok(list) => list,
        Err(resp) => return resp,
    };

    handle_update_webhook_subscription_enabled(
        &source_repo,
        &subscription_repo,
        &memberships,
        workspace_id,
        source_id,
        subscription_id,
        enabled,
    )
    .await
}

pub async fn delete_webhook_subscription(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path((workspace_id, source_id, subscription_id)): Path<(Uuid, Uuid, Uuid)>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    let source_repo = PostgresWebhookSourceRepository {
        pool: (*app_state.db_pool).clone(),
        encryption_key: app_state.config.api_secrets_encryption_key.clone(),
    };
    let subscription_repo = PostgresWebhookSubscriptionRepository {
        pool: (*app_state.db_pool).clone(),
    };

    let memberships = match load_memberships(app_state.workspace_repo.as_ref(), user_id).await {
        Ok(list) => list,
        Err(resp) => return resp,
    };

    handle_delete_webhook_subscription(
        &source_repo,
        &subscription_repo,
        &memberships,
        workspace_id,
        source_id,
        subscription_id,
    )
    .await
}

pub async fn delete_webhook_subscription_by_id(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path(subscription_id): Path<Uuid>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    let subscription_repo = PostgresWebhookSubscriptionRepository {
        pool: (*app_state.db_pool).clone(),
    };

    let memberships = match load_memberships(app_state.workspace_repo.as_ref(), user_id).await {
        Ok(list) => list,
        Err(resp) => return resp,
    };

    let pool = app_state.db_pool.clone();
    handle_delete_webhook_subscription_by_id(
        move |id| {
            let pool = pool.clone();
            async move { fetch_subscription_context(&pool, id).await }
        },
        &subscription_repo,
        &memberships,
        subscription_id,
    )
    .await
}

pub async fn webhook_ingress(
    State(app_state): State<AppState>,
    Path(source_id): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let dedupe_repo = PostgresWebhookIngressDedupeRepository {
        pool: (*app_state.db_pool).clone(),
    };
    let delivery_repo = PostgresWebhookDeliveryRepository {
        pool: (*app_state.db_pool).clone(),
    };
    let source_repo = PostgresWebhookSourceRepository {
        pool: (*app_state.db_pool).clone(),
        encryption_key: app_state.config.api_secrets_encryption_key.clone(),
    };
    let subscription_repo = PostgresWebhookSubscriptionRepository {
        pool: (*app_state.db_pool).clone(),
    };

    // Parse JSON exactly once
    let payload: Value = match serde_json::from_slice(body.as_ref()) {
        Ok(value) => value,
        Err(err) => {
            warn!(?err, "invalid webhook payload JSON");
            return JsonResponse::bad_request("Invalid JSON payload").into_response();
        }
    };

    handle_webhook_ingress(
        &dedupe_repo,
        &delivery_repo,
        &source_repo,
        &subscription_repo,
        app_state.workflow_repo.as_ref(),
        app_state.config.webhook_ingress_dedupe_mode,
        &app_state.config.api_secrets_encryption_key,
        source_id,
        &headers,
        &payload,
        body.as_ref(), // raw_body for HMAC validation
        &app_state.config.webhook_verification_body_fields,
        &app_state.config.webhook_verification_header_fields,
        OffsetDateTime::now_utc(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_webhook_ingress(
    dedupe_repo: &dyn WebhookIngressDedupeRepository,
    delivery_repo: &dyn WebhookDeliveryRepository,
    source_repo: &dyn WebhookSourceRepository,
    subscription_repo: &dyn WebhookSubscriptionRepository,
    workflow_repo: &dyn WorkflowRepository,
    dedupe_mode: WebhookIngressDedupeMode,
    encryption_key: &[u8],
    source_id: Uuid,
    headers: &HeaderMap,
    payload: &Value,
    raw_body: &[u8],
    verification_body_fields: &[String],
    verification_header_fields: &[(String, Option<String>)],
    now: OffsetDateTime,
) -> Response {
    let span = tracing::info_span!(
        "webhook_ingress",
        source_id = %source_id,
        event_type = tracing::field::Empty,
        payload_hash_prefix = tracing::field::Empty,
        signature_prefix = tracing::field::Empty,
        timestamp_floor = tracing::field::Empty,
        dedupe_outcome = tracing::field::Empty,
    );
    let _guard = span.enter();

    let source = match source_repo.find_webhook_source_by_id(source_id).await {
        Ok(Some(source)) if source.enabled => source,
        Ok(Some(_)) => {
            info!(%source_id, "webhook source disabled");
            return JsonResponse::not_found("Webhook source not found").into_response();
        }
        Ok(None) => {
            info!(%source_id, "webhook source not found");
            return JsonResponse::not_found("Webhook source not found").into_response();
        }
        Err(err) => {
            error!(?err, %source_id, "failed to resolve webhook source");
            return JsonResponse::server_error("Failed to resolve webhook source").into_response();
        }
    };

    info!(
        source_id = %source.id,
        workspace_id = %source.workspace_id,
        require_hmac = source.require_hmac,
        "webhook source resolved"
    );

    // Verification check runs immediately after JSON parsing, before:
    // - event_type validation
    // - HMAC validation
    // - replay window checks
    // - last_seen_at updates
    // - dedupe
    // - subscription lookup
    let verification_outcome = crate::routes::webhook_verification::is_webhook_verification_request(
        verification_body_fields,
        verification_header_fields,
        headers,
        payload,
    );

    match verification_outcome {
        crate::routes::webhook_verification::VerificationOutcome::Single(match_detail) => {
            // Check if payload also contains event_type (malformed)
            if payload.get(EVENT_TYPE_FIELD).is_some() {
                return JsonResponse::bad_request("malformed webhook verification payload")
                    .into_response();
            }

            // Log verification details
            info!(
                match_type = crate::routes::webhook_verification::match_type_string(&match_detail),
                indicator_source =
                    crate::routes::webhook_verification::indicator_source(&match_detail),
                indicator_key = crate::routes::webhook_verification::indicator_key(&match_detail),
                indicator_value = crate::routes::webhook_verification::indicator_value(
                    &match_detail,
                    payload,
                    headers
                ),
                "webhook verification request detected"
            );

            // Return 200 with empty JSON body, no state mutations
            return (StatusCode::OK, Json(json!({}))).into_response();
        }
        crate::routes::webhook_verification::VerificationOutcome::Ambiguous(_matches) => {
            return JsonResponse::bad_request("ambiguous webhook verification payload")
                .into_response();
        }
        crate::routes::webhook_verification::VerificationOutcome::None => {
            // Continue with normal webhook processing
        }
    }

    let event_type = match payload
        .get(EVENT_TYPE_FIELD)
        .and_then(|value| value.as_str())
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        Some(value) => value,
        None => {
            warn!(
                source_id = %source.id,
                "webhook payload missing event_type"
            );
            return JsonResponse::bad_request("Missing event_type").into_response();
        }
    };

    Span::current().record("event_type", tracing::field::display(event_type));

    if source.require_hmac {
        match validate_webhook_signature(encryption_key, &source, headers, raw_body, now) {
            Ok(()) => {}
            Err(WebhookSignatureError::DecryptFailed(err)) => {
                error!(?err, source_id = %source.id, "failed to decrypt webhook secret");
                return JsonResponse::server_error("Failed to validate signature").into_response();
            }
            Err(WebhookSignatureError::ValidationFailed(reason)) => {
                warn!(
                    source_id = %source.id,
                    reason,
                    "webhook signature validation failed"
                );
                return JsonResponse::unauthorized(reason).into_response();
            }
        }
    }

    let accepted_response =
        || (StatusCode::ACCEPTED, Json(json!({ "success": true }))).into_response();

    if let Err(err) = source_repo
        .update_webhook_source_last_seen(source.id, now)
        .await
    {
        error!(?err, source_id = %source.id, "failed to update webhook source last_seen_at");
        let delivery_id = Uuid::new_v4();
        let _ = record_delivery_safe(
            delivery_repo,
            delivery_id,
            source.id,
            None,
            event_type,
            now,
            DELIVERY_STATUS_ERRORED,
            Some(DELIVERY_ERROR_LAST_SEEN_UPDATE_FAILED),
        )
        .await;
        return accepted_response();
    }

    let mut dedupe_outcome = DedupeOutcome::Skipped;
    let mut dedupe_context: Option<DedupeKeyContext> = None;

    if !matches!(dedupe_mode, WebhookIngressDedupeMode::Off) {
        match build_dedupe_key_context(&source, event_type, headers, raw_body) {
            Ok(context) => {
                Span::current().record(
                    "payload_hash_prefix",
                    tracing::field::display(context.payload_hash_prefix.as_str()),
                );
                Span::current().record(
                    "signature_prefix",
                    tracing::field::display(context.signature_prefix.as_str()),
                );
                Span::current().record(
                    "timestamp_floor",
                    tracing::field::display(context.timestamp_floor),
                );
                match dedupe_repo.insert_dedupe_key(&context.key).await {
                    Ok(true) => {
                        dedupe_outcome = DedupeOutcome::Miss;
                        emit_counter(METRIC_INGRESS_DEDUPE_MISS, 1);
                        info!(
                            source_id = %source.id,
                            %event_type,
                            payload_hash_prefix = %context.payload_hash_prefix,
                            "webhook ingress dedupe miss"
                        );
                    }
                    Ok(false) => {
                        dedupe_outcome = DedupeOutcome::Hit;
                        emit_counter(METRIC_INGRESS_DEDUPE_HIT, 1);
                        info!(
                            source_id = %source.id,
                            %event_type,
                            payload_hash_prefix = %context.payload_hash_prefix,
                            "webhook ingress dedupe hit"
                        );
                    }
                    Err(err) => {
                        dedupe_outcome = DedupeOutcome::StoreError;
                        emit_counter(METRIC_INGRESS_DEDUPE_STORE_ERROR, 1);
                        error!(
                            ?err,
                            source_id = %source.id,
                            %event_type,
                            payload_hash_prefix = %context.payload_hash_prefix,
                            "webhook ingress dedupe insert failed"
                        );
                    }
                }
                dedupe_context = Some(context);
            }
            Err(reason) => {
                warn!(
                    source_id = %source.id,
                    %event_type,
                    reason,
                    "webhook ingress dedupe skipped"
                );
            }
        }
    }

    Span::current().record(
        "dedupe_outcome",
        tracing::field::display(dedupe_outcome.as_str()),
    );

    if dedupe_outcome == DedupeOutcome::Hit
        && matches!(dedupe_mode, WebhookIngressDedupeMode::Enforce)
    {
        if let Some(context) = dedupe_context.as_ref() {
            info!(
                source_id = %source.id,
                %event_type,
                payload_hash_prefix = %context.payload_hash_prefix,
                "webhook ingress dedupe enforced drop"
            );
        } else {
            info!(
                source_id = %source.id,
                %event_type,
                "webhook ingress dedupe enforced drop"
            );
        }
        let delivery_id = Uuid::new_v4();
        let _ = record_delivery_safe(
            delivery_repo,
            delivery_id,
            source.id,
            None,
            event_type,
            now,
            DELIVERY_STATUS_DROPPED,
            Some(DELIVERY_ERROR_DEDUPE_ENFORCED),
        )
        .await;
        return accepted_response();
    }

    let subscriptions = match subscription_repo
        .list_subscriptions_by_source_event(source.id, event_type)
        .await
    {
        Ok(subscriptions) => subscriptions,
        Err(err) => {
            error!(
                ?err,
                source_id = %source.id,
                %event_type,
                "failed to match webhook subscriptions"
            );
            let delivery_id = Uuid::new_v4();
            let _ = record_delivery_safe(
                delivery_repo,
                delivery_id,
                source.id,
                None,
                event_type,
                now,
                DELIVERY_STATUS_ERRORED,
                Some(DELIVERY_ERROR_SUBSCRIPTION_LOOKUP_FAILED),
            )
            .await;
            return accepted_response();
        }
    };

    let subscriptions_matched = subscriptions.len();
    emit_histogram(METRIC_SUBSCRIPTIONS_MATCHED, subscriptions_matched as f64);
    emit_counter(
        METRIC_SUBSCRIPTIONS_MATCHED_COUNT,
        subscriptions_matched as u64,
    );

    info!(
        source_id = %source.id,
        %event_type,
        matched = subscriptions_matched,
        "webhook subscriptions matched"
    );

    if subscriptions.is_empty() {
        emit_counter(METRIC_RUNS_ENQUEUED_COUNT, 0);
        emit_counter(METRIC_RUNS_FAILED_COUNT, 0);
        let delivery_id = Uuid::new_v4();
        let _ = record_delivery_safe(
            delivery_repo,
            delivery_id,
            source.id,
            None,
            event_type,
            now,
            DELIVERY_STATUS_DROPPED,
            Some(DELIVERY_ERROR_NO_MATCHING_SUBSCRIPTIONS),
        )
        .await;
        return accepted_response();
    }

    let mut enqueued = 0usize;
    let mut failed = 0usize;

    for subscription in subscriptions {
        let delivery_id = Uuid::new_v4();
        let delivery_logged = record_delivery_safe(
            delivery_repo,
            delivery_id,
            source.id,
            Some(subscription.id),
            event_type,
            now,
            DELIVERY_STATUS_RECEIVED,
            None,
        )
        .await;

        let workflow = match workflow_repo
            .find_workflow_by_id_public(subscription.workflow_id)
            .await
        {
            Ok(Some(workflow)) => workflow,
            Ok(None) => {
                warn!(
                    webhook_source_id = %source.id,
                    subscription_id = %subscription.id,
                    workflow_id = %subscription.workflow_id,
                    trigger_node_id = %subscription.trigger_node_id,
                    %event_type,
                    "workflow not found for webhook subscription"
                );
                failed += 1;
                if delivery_logged {
                    update_delivery_status_safe(
                        delivery_repo,
                        delivery_id,
                        DELIVERY_STATUS_ERRORED,
                        Some(DELIVERY_ERROR_WORKFLOW_NOT_FOUND),
                    )
                    .await;
                }
                continue;
            }
            Err(err) => {
                error!(
                    ?err,
                    webhook_source_id = %source.id,
                    subscription_id = %subscription.id,
                    workflow_id = %subscription.workflow_id,
                    trigger_node_id = %subscription.trigger_node_id,
                    %event_type,
                    "failed to load workflow for webhook subscription"
                );
                failed += 1;
                if delivery_logged {
                    update_delivery_status_safe(
                        delivery_repo,
                        delivery_id,
                        DELIVERY_STATUS_ERRORED,
                        Some(DELIVERY_ERROR_WORKFLOW_LOOKUP_FAILED),
                    )
                    .await;
                }
                continue;
            }
        };

        if workflow.workspace_id != Some(source.workspace_id) {
            warn!(
                webhook_source_id = %source.id,
                subscription_id = %subscription.id,
                workflow_id = %workflow.id,
                trigger_node_id = %subscription.trigger_node_id,
                %event_type,
                workflow_workspace_id = ?workflow.workspace_id,
                source_workspace_id = %source.workspace_id,
                "webhook subscription workspace mismatch"
            );
            failed += 1;
            if delivery_logged {
                update_delivery_status_safe(
                    delivery_repo,
                    delivery_id,
                    DELIVERY_STATUS_ERRORED,
                    Some(DELIVERY_ERROR_WORKSPACE_MISMATCH),
                )
                .await;
            }
            continue;
        }

        let mut snapshot = workflow.data.clone();
        let trigger_node_id = subscription.trigger_node_id.to_string();
        let trigger_type = trigger_type_for_node(&snapshot, &trigger_node_id)
            .unwrap_or_else(|| "webhook".to_string());
        snapshot["_trigger_context"] =
            merge_trigger_context(payload.clone(), &trigger_node_id, &trigger_type, "webhook");
        snapshot["_start_from_node"] = Value::String(trigger_node_id);
        snapshot["_egress_allowlist"] = Value::Array(
            workflow
                .egress_allowlist
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        );

        match workflow_repo
            .create_workflow_run(
                workflow.user_id,
                workflow.id,
                Some(source.workspace_id),
                snapshot,
                None,
            )
            .await
        {
            Ok(_) => {
                enqueued += 1;
                info!(
                    webhook_source_id = %source.id,
                    subscription_id = %subscription.id,
                    workflow_id = %workflow.id,
                    trigger_node_id = %subscription.trigger_node_id,
                    %event_type,
                    "webhook run enqueued"
                );
                if delivery_logged {
                    update_delivery_status_safe(
                        delivery_repo,
                        delivery_id,
                        DELIVERY_STATUS_ROUTED,
                        None,
                    )
                    .await;
                }
            }
            Err(err) => {
                failed += 1;
                error!(
                    ?err,
                    webhook_source_id = %source.id,
                    subscription_id = %subscription.id,
                    workflow_id = %workflow.id,
                    trigger_node_id = %subscription.trigger_node_id,
                    %event_type,
                    "failed to enqueue webhook run"
                );
                if delivery_logged {
                    update_delivery_status_safe(
                        delivery_repo,
                        delivery_id,
                        DELIVERY_STATUS_ERRORED,
                        Some(DELIVERY_ERROR_RUN_ENQUEUE_FAILED),
                    )
                    .await;
                }
            }
        }
    }

    emit_counter(METRIC_INGRESS_ENQUEUED, enqueued as u64);
    emit_counter(METRIC_INGRESS_ENQUEUED_FAILED, failed as u64);
    emit_counter(METRIC_RUNS_ENQUEUED_COUNT, enqueued as u64);
    emit_counter(METRIC_RUNS_FAILED_COUNT, failed as u64);

    info!(
        source_id = %source.id,
        %event_type,
        matched = enqueued + failed,
        enqueued,
        failed,
        "webhook ingress dispatch complete"
    );

    accepted_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::workflow_repository::{CreateWorkflowRunOutcome, MockWorkflowRepository};
    use crate::models::webhook_source::WebhookSource;
    use crate::models::webhook_subscription::WebhookSubscription;
    use crate::models::workflow::Workflow;
    use crate::models::workflow_run::WorkflowRun;
    use crate::models::workspace::Workspace;
    use crate::routes::webhook_ingress_validation::{
        compute_signature, SIGNATURE_HEADER, TIMESTAMP_HEADER,
    };
    use crate::utils::encryption::encrypt_secret;
    use async_trait::async_trait;
    use axum::body::to_bytes;
    use axum::http::StatusCode;
    use serde_json::json;
    use std::collections::HashSet;
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct StubWebhookSourceRepo {
        source: Option<WebhookSource>,
        last_seen: Mutex<Option<OffsetDateTime>>,
    }

    #[allow(clippy::too_many_arguments)]
    async fn invoke_handle_webhook_ingress_with_payload(
        dedupe_repo: &dyn WebhookIngressDedupeRepository,
        delivery_repo: &dyn WebhookDeliveryRepository,
        source_repo: &dyn WebhookSourceRepository,
        subscription_repo: &dyn WebhookSubscriptionRepository,
        workflow_repo: &dyn WorkflowRepository,
        dedupe_mode: WebhookIngressDedupeMode,
        encryption_key: &[u8],
        source_id: Uuid,
        headers: &HeaderMap,
        body: &[u8],
        now: OffsetDateTime,
    ) -> Response {
        let payload: Value = serde_json::from_slice(body).expect("valid JSON payload");

        handle_webhook_ingress(
            dedupe_repo,
            delivery_repo,
            source_repo,
            subscription_repo,
            workflow_repo,
            dedupe_mode,
            encryption_key,
            source_id,
            headers,
            &payload,
            body,
            &[], // verification_body_fields
            &[], // verification_header_fields
            now,
        )
        .await
    }

    #[async_trait]
    impl WebhookSourceRepository for StubWebhookSourceRepo {
        async fn create_webhook_source_with_secret(
            &self,
            _: Uuid,
            _: &str,
            _: bool,
        ) -> Result<(WebhookSource, String), sqlx::Error> {
            Err(sqlx::Error::RowNotFound)
        }

        async fn find_webhook_source_by_id(
            &self,
            _source_id: Uuid,
        ) -> Result<Option<WebhookSource>, sqlx::Error> {
            Ok(self.source.clone())
        }

        async fn list_webhook_sources_by_workspace(
            &self,
            _workspace_id: Uuid,
        ) -> Result<Vec<WebhookSource>, sqlx::Error> {
            Ok(vec![])
        }

        async fn update_webhook_source_last_seen(
            &self,
            _source_id: Uuid,
            last_seen_at: OffsetDateTime,
        ) -> Result<(), sqlx::Error> {
            *self.last_seen.lock().unwrap() = Some(last_seen_at);
            Ok(())
        }

        async fn update_webhook_source_enabled(
            &self,
            _workspace_id: Uuid,
            _source_id: Uuid,
            _enabled: bool,
        ) -> Result<WebhookSource, sqlx::Error> {
            Err(sqlx::Error::RowNotFound)
        }

        async fn delete_webhook_source(
            &self,
            _workspace_id: Uuid,
            _source_id: Uuid,
        ) -> Result<(), sqlx::Error> {
            Err(sqlx::Error::RowNotFound)
        }

        async fn rotate_webhook_source_secret_with_secret(
            &self,
            _workspace_id: Uuid,
            _source_id: Uuid,
        ) -> Result<(WebhookSource, String), sqlx::Error> {
            Err(sqlx::Error::RowNotFound)
        }
    }

    #[derive(Default)]
    struct StubWebhookIngressDedupeRepo {
        keys: Mutex<Vec<WebhookIngressDedupeKey>>,
    }

    #[async_trait]
    impl WebhookIngressDedupeRepository for StubWebhookIngressDedupeRepo {
        async fn insert_dedupe_key(
            &self,
            key: &WebhookIngressDedupeKey,
        ) -> Result<bool, sqlx::Error> {
            let mut keys = self.keys.lock().unwrap();
            if keys.iter().any(|existing| existing == key) {
                Ok(false)
            } else {
                keys.push(key.clone());
                Ok(true)
            }
        }

        async fn purge_old_dedupe_entries(&self) -> Result<u64, sqlx::Error> {
            Ok(0)
        }
    }

    #[derive(Debug, Clone)]
    struct RecordedWebhookDelivery {
        _delivery_id: Uuid,
        webhook_source_id: Uuid,
        subscription_id: Option<Uuid>,
        event_type: String,
        received_at: OffsetDateTime,
        delivery_status: String,
        error_message: Option<String>,
    }

    #[derive(Debug, Clone)]
    struct RecordedWebhookDeliveryUpdate {
        _delivery_id: Uuid,
        _delivery_status: String,
        _error_message: Option<String>,
    }

    #[derive(Default)]
    struct StubWebhookDeliveryRepo {
        deliveries: Mutex<Vec<RecordedWebhookDelivery>>,
        updates: Mutex<Vec<RecordedWebhookDeliveryUpdate>>,
        fail_inserts: bool,
        fail_updates: bool,
    }

    impl StubWebhookDeliveryRepo {
        fn new(fail_inserts: bool, fail_updates: bool) -> Self {
            Self {
                deliveries: Mutex::new(Vec::new()),
                updates: Mutex::new(Vec::new()),
                fail_inserts,
                fail_updates,
            }
        }
    }

    #[async_trait]
    impl WebhookDeliveryRepository for StubWebhookDeliveryRepo {
        async fn record_delivery(
            &self,
            delivery_id: Uuid,
            webhook_source_id: Uuid,
            subscription_id: Option<Uuid>,
            event_type: &str,
            received_at: OffsetDateTime,
            delivery_status: &str,
            error_message: Option<&str>,
        ) -> Result<(), sqlx::Error> {
            if self.fail_inserts {
                return Err(sqlx::Error::RowNotFound);
            }

            self.deliveries
                .lock()
                .unwrap()
                .push(RecordedWebhookDelivery {
                    _delivery_id: delivery_id,
                    webhook_source_id,
                    subscription_id,
                    event_type: event_type.to_string(),
                    received_at,
                    delivery_status: delivery_status.to_string(),
                    error_message: error_message.map(|value| value.to_string()),
                });
            Ok(())
        }

        async fn update_delivery_status(
            &self,
            delivery_id: Uuid,
            delivery_status: &str,
            error_message: Option<&str>,
        ) -> Result<(), sqlx::Error> {
            if self.fail_updates {
                return Err(sqlx::Error::RowNotFound);
            }

            self.updates
                .lock()
                .unwrap()
                .push(RecordedWebhookDeliveryUpdate {
                    _delivery_id: delivery_id,
                    _delivery_status: delivery_status.to_string(),
                    _error_message: error_message.map(|value| value.to_string()),
                });
            Ok(())
        }
    }

    #[derive(Default)]
    struct StubWebhookSubscriptionRepo {
        subscriptions: Vec<WebhookSubscription>,
    }

    #[async_trait]
    impl WebhookSubscriptionRepository for StubWebhookSubscriptionRepo {
        async fn create_subscription(
            &self,
            _webhook_source_id: Uuid,
            _workflow_id: Uuid,
            _trigger_node_id: Uuid,
            _event_type: &str,
        ) -> Result<WebhookSubscription, sqlx::Error> {
            Err(sqlx::Error::RowNotFound)
        }

        async fn list_subscriptions_by_source(
            &self,
            _webhook_source_id: Uuid,
        ) -> Result<Vec<WebhookSubscription>, sqlx::Error> {
            Ok(vec![])
        }

        async fn list_subscriptions_by_source_event(
            &self,
            _webhook_source_id: Uuid,
            event_type: &str,
        ) -> Result<Vec<WebhookSubscription>, sqlx::Error> {
            Ok(self
                .subscriptions
                .iter()
                .filter(|sub| sub.enabled && sub.event_type == event_type)
                .cloned()
                .collect())
        }

        async fn update_subscription_enabled(
            &self,
            _webhook_source_id: Uuid,
            _subscription_id: Uuid,
            _enabled: bool,
        ) -> Result<WebhookSubscription, sqlx::Error> {
            Err(sqlx::Error::RowNotFound)
        }

        async fn delete_subscription(
            &self,
            _webhook_source_id: Uuid,
            _subscription_id: Uuid,
        ) -> Result<(), sqlx::Error> {
            Err(sqlx::Error::RowNotFound)
        }
    }

    #[derive(Default)]
    struct TestWebhookSourceRepo {
        sources: Mutex<Vec<WebhookSource>>,
    }

    impl TestWebhookSourceRepo {
        fn new(sources: Vec<WebhookSource>) -> Self {
            Self {
                sources: Mutex::new(sources),
            }
        }
    }

    #[async_trait]
    impl WebhookSourceRepository for TestWebhookSourceRepo {
        async fn create_webhook_source_with_secret(
            &self,
            workspace_id: Uuid,
            name: &str,
            _: bool,
        ) -> Result<(WebhookSource, String), sqlx::Error> {
            let now = OffsetDateTime::now_utc();
            let source = WebhookSource {
                id: Uuid::new_v4(),
                workspace_id,
                name: name.to_string(),
                secret: "secret".into(),
                require_hmac: false,
                replay_window_sec: 300,
                last_seen_at: None,
                enabled: true,
                created_at: now,
                updated_at: now,
            };
            self.sources.lock().unwrap().push(source.clone());
            Ok((source, "".to_string()))
        }

        async fn find_webhook_source_by_id(
            &self,
            source_id: Uuid,
        ) -> Result<Option<WebhookSource>, sqlx::Error> {
            Ok(self
                .sources
                .lock()
                .unwrap()
                .iter()
                .find(|source| source.id == source_id)
                .cloned())
        }

        async fn list_webhook_sources_by_workspace(
            &self,
            workspace_id: Uuid,
        ) -> Result<Vec<WebhookSource>, sqlx::Error> {
            Ok(self
                .sources
                .lock()
                .unwrap()
                .iter()
                .filter(|source| source.workspace_id == workspace_id)
                .cloned()
                .collect())
        }

        async fn update_webhook_source_last_seen(
            &self,
            source_id: Uuid,
            last_seen_at: OffsetDateTime,
        ) -> Result<(), sqlx::Error> {
            let mut sources = self.sources.lock().unwrap();
            if let Some(source) = sources.iter_mut().find(|source| source.id == source_id) {
                source.last_seen_at = Some(last_seen_at);
                source.updated_at = OffsetDateTime::now_utc();
                Ok(())
            } else {
                Err(sqlx::Error::RowNotFound)
            }
        }

        async fn update_webhook_source_enabled(
            &self,
            workspace_id: Uuid,
            source_id: Uuid,
            enabled: bool,
        ) -> Result<WebhookSource, sqlx::Error> {
            let mut sources = self.sources.lock().unwrap();
            if let Some(source) = sources
                .iter_mut()
                .find(|source| source.id == source_id && source.workspace_id == workspace_id)
            {
                source.enabled = enabled;
                source.updated_at = OffsetDateTime::now_utc();
                Ok(source.clone())
            } else {
                Err(sqlx::Error::RowNotFound)
            }
        }

        async fn delete_webhook_source(
            &self,
            workspace_id: Uuid,
            source_id: Uuid,
        ) -> Result<(), sqlx::Error> {
            let mut sources = self.sources.lock().unwrap();
            let before = sources.len();
            sources
                .retain(|source| !(source.id == source_id && source.workspace_id == workspace_id));
            if before == sources.len() {
                Err(sqlx::Error::RowNotFound)
            } else {
                Ok(())
            }
        }

        async fn rotate_webhook_source_secret_with_secret(
            &self,
            workspace_id: Uuid,
            source_id: Uuid,
        ) -> Result<(WebhookSource, String), sqlx::Error> {
            let mut sources = self.sources.lock().unwrap();
            if let Some(source) = sources
                .iter_mut()
                .find(|source| source.id == source_id && source.workspace_id == workspace_id)
            {
                source.secret = format!("rotated-{}", Uuid::new_v4());
                source.updated_at = OffsetDateTime::now_utc();
                Ok((source.clone(), "".to_string()))
            } else {
                Err(sqlx::Error::RowNotFound)
            }
        }
    }

    #[derive(Default)]
    struct TestWebhookSubscriptionRepo {
        subscriptions: Mutex<Vec<WebhookSubscription>>,
    }

    #[async_trait]
    impl WebhookSubscriptionRepository for TestWebhookSubscriptionRepo {
        async fn create_subscription(
            &self,
            webhook_source_id: Uuid,
            workflow_id: Uuid,
            trigger_node_id: Uuid,
            event_type: &str,
        ) -> Result<WebhookSubscription, sqlx::Error> {
            let now = OffsetDateTime::now_utc();
            let subscription = WebhookSubscription {
                id: Uuid::new_v4(),
                webhook_source_id,
                workflow_id,
                trigger_node_id,
                event_type: event_type.to_string(),
                enabled: true,
                created_at: now,
                updated_at: now,
            };
            self.subscriptions
                .lock()
                .unwrap()
                .push(subscription.clone());
            Ok(subscription)
        }

        async fn list_subscriptions_by_source(
            &self,
            webhook_source_id: Uuid,
        ) -> Result<Vec<WebhookSubscription>, sqlx::Error> {
            Ok(self
                .subscriptions
                .lock()
                .unwrap()
                .iter()
                .filter(|sub| sub.webhook_source_id == webhook_source_id)
                .cloned()
                .collect())
        }

        async fn list_subscriptions_by_source_event(
            &self,
            webhook_source_id: Uuid,
            event_type: &str,
        ) -> Result<Vec<WebhookSubscription>, sqlx::Error> {
            Ok(self
                .subscriptions
                .lock()
                .unwrap()
                .iter()
                .filter(|sub| {
                    sub.webhook_source_id == webhook_source_id
                        && sub.event_type == event_type
                        && sub.enabled
                })
                .cloned()
                .collect())
        }

        async fn update_subscription_enabled(
            &self,
            webhook_source_id: Uuid,
            subscription_id: Uuid,
            enabled: bool,
        ) -> Result<WebhookSubscription, sqlx::Error> {
            let mut subs = self.subscriptions.lock().unwrap();
            if let Some(sub) = subs
                .iter_mut()
                .find(|sub| sub.webhook_source_id == webhook_source_id && sub.id == subscription_id)
            {
                sub.enabled = enabled;
                sub.updated_at = OffsetDateTime::now_utc();
                Ok(sub.clone())
            } else {
                Err(sqlx::Error::RowNotFound)
            }
        }

        async fn delete_subscription(
            &self,
            webhook_source_id: Uuid,
            subscription_id: Uuid,
        ) -> Result<(), sqlx::Error> {
            let mut subs = self.subscriptions.lock().unwrap();
            let before = subs.len();
            subs.retain(|sub| {
                !(sub.webhook_source_id == webhook_source_id && sub.id == subscription_id)
            });
            if before == subs.len() {
                Err(sqlx::Error::RowNotFound)
            } else {
                Ok(())
            }
        }
    }

    fn membership_fixture(
        workspace_id: Uuid,
        owner_id: Uuid,
        role: WorkspaceRole,
    ) -> WorkspaceMembershipSummary {
        let now = OffsetDateTime::now_utc();
        WorkspaceMembershipSummary {
            workspace: Workspace {
                id: workspace_id,
                name: "Workspace".into(),
                created_by: owner_id,
                owner_id,
                plan: "workspace".into(),
                stripe_overage_item_id: None,
                created_at: now,
                updated_at: now,
                deleted_at: None,
            },
            role,
        }
    }

    fn webhook_source_fixture(
        source_id: Uuid,
        workspace_id: Uuid,
        encrypted_secret: String,
    ) -> WebhookSource {
        let now = OffsetDateTime::now_utc();
        WebhookSource {
            id: source_id,
            workspace_id,
            name: "Inbound".into(),
            secret: encrypted_secret,
            require_hmac: true,
            replay_window_sec: 300,
            last_seen_at: None,
            enabled: true,
            created_at: now,
            updated_at: now,
        }
    }

    fn workflow_fixture(workspace_id: Uuid, user_id: Uuid) -> Workflow {
        let now = OffsetDateTime::now_utc();
        Workflow {
            id: Uuid::new_v4(),
            user_id,
            workspace_id: Some(workspace_id),
            name: "Webhook Workflow".into(),
            description: None,
            data: json!({ "nodes": [], "edges": [] }),
            concurrency_limit: 1,
            egress_allowlist: vec!["https://example.com".into()],
            locked_by: None,
            locked_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn webhook_trigger_node(node_id: Uuid) -> Value {
        json!({
            "id": node_id.to_string(),
            "type": "trigger",
            "data": {
                "label": "Webhook",
                "triggerType": "Webhook"
            }
        })
    }

    fn manual_trigger_node(node_id: Uuid) -> Value {
        json!({
            "id": node_id.to_string(),
            "type": "trigger",
            "data": {
                "label": "Manual",
                "triggerType": "Manual"
            }
        })
    }

    fn action_node(node_id: Uuid) -> Value {
        json!({
            "id": node_id.to_string(),
            "type": "action",
            "data": {
                "label": "Action"
            }
        })
    }

    fn workflow_repo_with_workflow(
        user_id: Uuid,
        workflow_id: Uuid,
        workflow: Workflow,
    ) -> MockWorkflowRepository {
        let mut repo = MockWorkflowRepository::new();
        let workflow_for_find = workflow.clone();
        repo.expect_find_workflow_for_member()
            .returning(move |uid, wf_id| {
                let wf = workflow_for_find.clone();
                Box::pin(async move {
                    assert_eq!(uid, user_id);
                    assert_eq!(wf_id, workflow_id);
                    Ok(Some(wf))
                })
            });
        repo
    }

    fn sign_payload(secret: &str, timestamp: &str, body: &[u8]) -> String {
        compute_signature(secret, timestamp, body).expect("signature")
    }

    #[tokio::test]
    async fn list_webhook_sources_for_member() {
        let workspace_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let source = webhook_source_fixture(Uuid::new_v4(), workspace_id, "secret".to_string());
        let repo = TestWebhookSourceRepo::new(vec![source]);
        let memberships = vec![membership_fixture(
            workspace_id,
            user_id,
            WorkspaceRole::User,
        )];

        let response = handle_list_webhook_sources(&repo, &memberships, workspace_id).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 2048).await.unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["success"], json!(true));
        let sources = payload["data"]["sources"].as_array().unwrap();
        assert_eq!(sources.len(), 1);
        assert!(sources[0].get("secret").is_none());
    }

    #[tokio::test]
    async fn list_webhook_sources_forbidden_without_membership() {
        let workspace_id = Uuid::new_v4();
        let repo = TestWebhookSourceRepo::default();
        let response = handle_list_webhook_sources(&repo, &[], workspace_id).await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn list_subscriptions_rejects_source_outside_workspace() {
        let workspace_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let other_workspace_id = Uuid::new_v4();
        let source_id = Uuid::new_v4();
        let source = webhook_source_fixture(source_id, other_workspace_id, "secret".to_string());
        let source_repo = TestWebhookSourceRepo::new(vec![source]);
        let subscription_repo = TestWebhookSubscriptionRepo::default();
        let memberships = vec![membership_fixture(
            workspace_id,
            user_id,
            WorkspaceRole::User,
        )];

        let response = handle_list_webhook_subscriptions(
            &source_repo,
            &subscription_repo,
            &memberships,
            workspace_id,
            source_id,
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn create_webhook_subscription_happy_path() {
        let workspace_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let source_id = Uuid::new_v4();
        let trigger_node_id = Uuid::new_v4();
        let mut workflow = workflow_fixture(workspace_id, user_id);
        workflow.data = json!({
            "nodes": [webhook_trigger_node(trigger_node_id)],
            "edges": []
        });
        let workflow_id = workflow.id;

        let source = webhook_source_fixture(source_id, workspace_id, "secret".to_string());
        let source_repo = TestWebhookSourceRepo::new(vec![source]);
        let subscription_repo = TestWebhookSubscriptionRepo::default();
        let memberships = vec![membership_fixture(
            workspace_id,
            user_id,
            WorkspaceRole::Admin,
        )];

        let workflow_repo = workflow_repo_with_workflow(user_id, workflow_id, workflow.clone());

        let response = handle_create_webhook_subscription(
            &source_repo,
            &subscription_repo,
            &workflow_repo,
            &memberships,
            user_id,
            workspace_id,
            source_id,
            workflow_id,
            trigger_node_id,
            "invoice.created".to_string(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 2048).await.unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["success"], json!(true));
        assert_eq!(
            payload["data"]["subscription"]["workflow_id"],
            json!(workflow_id)
        );
        assert_eq!(
            payload["data"]["subscription"]["webhook_source_id"],
            json!(source_id)
        );
        assert_eq!(
            payload["data"]["subscription"]["event_type"],
            json!("invoice.created")
        );
    }

    #[tokio::test]
    async fn create_webhook_subscription_rejects_missing_trigger_node() {
        let workspace_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let source_id = Uuid::new_v4();
        let trigger_node_id = Uuid::new_v4();
        let mut workflow = workflow_fixture(workspace_id, user_id);
        workflow.data = json!({
            "nodes": [webhook_trigger_node(Uuid::new_v4())],
            "edges": []
        });
        let workflow_id = workflow.id;

        let source = webhook_source_fixture(source_id, workspace_id, "secret".to_string());
        let source_repo = TestWebhookSourceRepo::new(vec![source]);
        let subscription_repo = TestWebhookSubscriptionRepo::default();
        let memberships = vec![membership_fixture(
            workspace_id,
            user_id,
            WorkspaceRole::Admin,
        )];

        let workflow_repo = workflow_repo_with_workflow(user_id, workflow_id, workflow.clone());

        let response = handle_create_webhook_subscription(
            &source_repo,
            &subscription_repo,
            &workflow_repo,
            &memberships,
            user_id,
            workspace_id,
            source_id,
            workflow_id,
            trigger_node_id,
            "invoice.created".to_string(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_webhook_subscription_rejects_non_trigger_node() {
        let workspace_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let source_id = Uuid::new_v4();
        let trigger_node_id = Uuid::new_v4();
        let mut workflow = workflow_fixture(workspace_id, user_id);
        workflow.data = json!({
            "nodes": [action_node(trigger_node_id)],
            "edges": []
        });
        let workflow_id = workflow.id;

        let source = webhook_source_fixture(source_id, workspace_id, "secret".to_string());
        let source_repo = TestWebhookSourceRepo::new(vec![source]);
        let subscription_repo = TestWebhookSubscriptionRepo::default();
        let memberships = vec![membership_fixture(
            workspace_id,
            user_id,
            WorkspaceRole::Admin,
        )];

        let workflow_repo = workflow_repo_with_workflow(user_id, workflow_id, workflow.clone());

        let response = handle_create_webhook_subscription(
            &source_repo,
            &subscription_repo,
            &workflow_repo,
            &memberships,
            user_id,
            workspace_id,
            source_id,
            workflow_id,
            trigger_node_id,
            "invoice.created".to_string(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_webhook_subscription_rejects_non_webhook_trigger() {
        let workspace_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let source_id = Uuid::new_v4();
        let trigger_node_id = Uuid::new_v4();
        let mut workflow = workflow_fixture(workspace_id, user_id);
        workflow.data = json!({
            "nodes": [manual_trigger_node(trigger_node_id)],
            "edges": []
        });
        let workflow_id = workflow.id;

        let source = webhook_source_fixture(source_id, workspace_id, "secret".to_string());
        let source_repo = TestWebhookSourceRepo::new(vec![source]);
        let subscription_repo = TestWebhookSubscriptionRepo::default();
        let memberships = vec![membership_fixture(
            workspace_id,
            user_id,
            WorkspaceRole::Admin,
        )];

        let workflow_repo = workflow_repo_with_workflow(user_id, workflow_id, workflow.clone());

        let response = handle_create_webhook_subscription(
            &source_repo,
            &subscription_repo,
            &workflow_repo,
            &memberships,
            user_id,
            workspace_id,
            source_id,
            workflow_id,
            trigger_node_id,
            "invoice.created".to_string(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_webhook_subscription_rejects_uppercase_event_type() {
        let workspace_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let source_id = Uuid::new_v4();
        let trigger_node_id = Uuid::new_v4();
        let mut workflow = workflow_fixture(workspace_id, user_id);
        workflow.data = json!({
            "nodes": [webhook_trigger_node(trigger_node_id)],
            "edges": []
        });
        let workflow_id = workflow.id;

        let source = webhook_source_fixture(source_id, workspace_id, "secret".to_string());
        let source_repo = TestWebhookSourceRepo::new(vec![source]);
        let subscription_repo = TestWebhookSubscriptionRepo::default();
        let memberships = vec![membership_fixture(
            workspace_id,
            user_id,
            WorkspaceRole::Admin,
        )];

        let workflow_repo = workflow_repo_with_workflow(user_id, workflow_id, workflow.clone());

        let response = handle_create_webhook_subscription(
            &source_repo,
            &subscription_repo,
            &workflow_repo,
            &memberships,
            user_id,
            workspace_id,
            source_id,
            workflow_id,
            trigger_node_id,
            "Invoice.Created".to_string(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn create_webhook_subscription_rejects_whitespace_event_type() {
        let workspace_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let source_id = Uuid::new_v4();
        let trigger_node_id = Uuid::new_v4();
        let mut workflow = workflow_fixture(workspace_id, user_id);
        workflow.data = json!({
            "nodes": [webhook_trigger_node(trigger_node_id)],
            "edges": []
        });
        let workflow_id = workflow.id;

        let source = webhook_source_fixture(source_id, workspace_id, "secret".to_string());
        let source_repo = TestWebhookSourceRepo::new(vec![source]);
        let subscription_repo = TestWebhookSubscriptionRepo::default();
        let memberships = vec![membership_fixture(
            workspace_id,
            user_id,
            WorkspaceRole::Admin,
        )];

        let workflow_repo = workflow_repo_with_workflow(user_id, workflow_id, workflow.clone());

        let response = handle_create_webhook_subscription(
            &source_repo,
            &subscription_repo,
            &workflow_repo,
            &memberships,
            user_id,
            workspace_id,
            source_id,
            workflow_id,
            trigger_node_id,
            "invoice created".to_string(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn list_subscriptions_for_source_scoped_route() {
        let workspace_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let source_id = Uuid::new_v4();
        let workflow_id = Uuid::new_v4();

        let source = webhook_source_fixture(source_id, workspace_id, "secret".to_string());
        let source_repo = TestWebhookSourceRepo::new(vec![source]);
        let subscription_repo = TestWebhookSubscriptionRepo::default();
        subscription_repo
            .create_subscription(source_id, workflow_id, Uuid::new_v4(), "issue.created")
            .await
            .expect("create subscription");
        subscription_repo
            .create_subscription(source_id, workflow_id, Uuid::new_v4(), "issue.updated")
            .await
            .expect("create subscription");

        let memberships = vec![membership_fixture(
            workspace_id,
            user_id,
            WorkspaceRole::User,
        )];

        let response = handle_list_webhook_subscriptions_for_source(
            &source_repo,
            &subscription_repo,
            &memberships,
            source_id,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 2048).await.unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["success"], json!(true));
        let subscriptions = payload["data"]["subscriptions"].as_array().unwrap();
        assert_eq!(subscriptions.len(), 2);
    }

    #[tokio::test]
    async fn delete_subscription_by_id_removes_subscription() {
        let workspace_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let source_id = Uuid::new_v4();
        let workflow_id = Uuid::new_v4();

        let subscription_repo = TestWebhookSubscriptionRepo::default();
        let subscription = subscription_repo
            .create_subscription(source_id, workflow_id, Uuid::new_v4(), "issue.created")
            .await
            .expect("create subscription");
        let subscription_id = subscription.id;

        let memberships = vec![membership_fixture(
            workspace_id,
            user_id,
            WorkspaceRole::Admin,
        )];

        let response = handle_delete_webhook_subscription_by_id(
            move |id| async move {
                if id == subscription_id {
                    Ok(Some(SubscriptionContext {
                        _subscription_id: subscription_id,
                        webhook_source_id: source_id,
                        workspace_id,
                    }))
                } else {
                    Ok(None)
                }
            },
            &subscription_repo,
            &memberships,
            subscription_id,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let remaining = subscription_repo
            .list_subscriptions_by_source(source_id)
            .await
            .expect("list subscriptions");
        assert!(remaining.is_empty());
    }

    #[tokio::test]
    async fn delete_subscription_by_id_forbidden_without_membership() {
        let workspace_id = Uuid::new_v4();
        let source_id = Uuid::new_v4();
        let subscription_id = Uuid::new_v4();
        let subscription_repo = TestWebhookSubscriptionRepo::default();

        let response = handle_delete_webhook_subscription_by_id(
            move |id| async move {
                if id == subscription_id {
                    Ok(Some(SubscriptionContext {
                        _subscription_id: subscription_id,
                        webhook_source_id: source_id,
                        workspace_id,
                    }))
                } else {
                    Ok(None)
                }
            },
            &subscription_repo,
            &[],
            subscription_id,
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn delete_subscription_by_id_not_found_when_missing() {
        let subscription_repo = TestWebhookSubscriptionRepo::default();

        let response = handle_delete_webhook_subscription_by_id(
            |_id| async { Ok(None) },
            &subscription_repo,
            &[],
            Uuid::new_v4(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn webhook_source_not_found() {
        let repo = StubWebhookSourceRepo::default();
        let subscription_repo = StubWebhookSubscriptionRepo::default();
        let workflow_repo = MockWorkflowRepository::new();
        let dedupe_repo = StubWebhookIngressDedupeRepo::default();
        let delivery_repo = StubWebhookDeliveryRepo::default();

        let response = invoke_handle_webhook_ingress_with_payload(
            &dedupe_repo,
            &delivery_repo,
            &repo,
            &subscription_repo,
            &workflow_repo,
            WebhookIngressDedupeMode::Off,
            &[9u8; 32],
            Uuid::new_v4(),
            &HeaderMap::new(),
            br#"{"event_type":"invoice.created"}"#,
            OffsetDateTime::now_utc(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn webhook_source_disabled_returns_not_found() {
        let key = vec![9u8; 32];
        let source_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let secret = encrypt_secret(&key, "secret").expect("encrypt");
        let mut source = webhook_source_fixture(source_id, workspace_id, secret);
        source.enabled = false;
        let repo = StubWebhookSourceRepo {
            source: Some(source),
            ..Default::default()
        };
        let subscription_repo = StubWebhookSubscriptionRepo::default();
        let workflow_repo = MockWorkflowRepository::new();
        let dedupe_repo = StubWebhookIngressDedupeRepo::default();
        let delivery_repo = StubWebhookDeliveryRepo::default();

        let response = invoke_handle_webhook_ingress_with_payload(
            &dedupe_repo,
            &delivery_repo,
            &repo,
            &subscription_repo,
            &workflow_repo,
            WebhookIngressDedupeMode::Off,
            &key,
            source_id,
            &HeaderMap::new(),
            br#"{"event_type":"invoice.created"}"#,
            OffsetDateTime::now_utc(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn webhook_signature_failure_returns_unauthorized() {
        let key = vec![9u8; 32];
        let source_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let secret = encrypt_secret(&key, "secret").expect("encrypt");
        let source = webhook_source_fixture(source_id, workspace_id, secret);
        let repo = StubWebhookSourceRepo {
            source: Some(source),
            ..Default::default()
        };
        let subscription_repo = StubWebhookSubscriptionRepo::default();
        let workflow_repo = MockWorkflowRepository::new();
        let dedupe_repo = StubWebhookIngressDedupeRepo::default();
        let delivery_repo = StubWebhookDeliveryRepo::default();

        let mut headers = HeaderMap::new();
        headers.insert(TIMESTAMP_HEADER, "1700000000".parse().unwrap());
        headers.insert(SIGNATURE_HEADER, "v1=deadbeef".parse().unwrap());

        let response = invoke_handle_webhook_ingress_with_payload(
            &dedupe_repo,
            &delivery_repo,
            &repo,
            &subscription_repo,
            &workflow_repo,
            WebhookIngressDedupeMode::Off,
            &key,
            source_id,
            &headers,
            br#"{"event_type":"invoice.created"}"#,
            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn webhook_replay_rejected() {
        let key = vec![9u8; 32];
        let source_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let secret = encrypt_secret(&key, "secret").expect("encrypt");
        let mut source = webhook_source_fixture(source_id, workspace_id, secret);
        source.replay_window_sec = 30;
        let repo = StubWebhookSourceRepo {
            source: Some(source),
            ..Default::default()
        };
        let subscription_repo = StubWebhookSubscriptionRepo::default();
        let workflow_repo = MockWorkflowRepository::new();
        let dedupe_repo = StubWebhookIngressDedupeRepo::default();
        let delivery_repo = StubWebhookDeliveryRepo::default();

        let timestamp = "1700000000";
        let body = br#"{"event_type":"invoice.created"}"#;
        let signature = sign_payload("secret", timestamp, body);
        let mut headers = HeaderMap::new();
        headers.insert(TIMESTAMP_HEADER, timestamp.parse().unwrap());
        headers.insert(
            SIGNATURE_HEADER,
            format!("v1={}", signature).parse().unwrap(),
        );

        let response = invoke_handle_webhook_ingress_with_payload(
            &dedupe_repo,
            &delivery_repo,
            &repo,
            &subscription_repo,
            &workflow_repo,
            WebhookIngressDedupeMode::Off,
            &key,
            source_id,
            &headers,
            body,
            OffsetDateTime::from_unix_timestamp(1_700_000_100).unwrap(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn webhook_subscription_matching_enqueues_runs() {
        let key = vec![9u8; 32];
        let source_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let secret = encrypt_secret(&key, "secret").expect("encrypt");
        let mut source = webhook_source_fixture(source_id, workspace_id, secret);
        source.require_hmac = false;
        let repo = StubWebhookSourceRepo {
            source: Some(source),
            ..Default::default()
        };

        let workflow = workflow_fixture(workspace_id, Uuid::new_v4());
        let workflow_id = workflow.id;
        let subscription = WebhookSubscription {
            id: Uuid::new_v4(),
            webhook_source_id: source_id,
            workflow_id,
            trigger_node_id: Uuid::new_v4(),
            event_type: "invoice.created".into(),
            enabled: true,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };
        let subscription_repo = StubWebhookSubscriptionRepo {
            subscriptions: vec![subscription.clone()],
        };

        let trigger_node_id = subscription.trigger_node_id.to_string();

        let mut workflow_repo = MockWorkflowRepository::new();
        let workflow_for_find = workflow.clone();
        workflow_repo
            .expect_find_workflow_by_id_public()
            .returning(move |id| {
                let wf = workflow_for_find.clone();
                Box::pin(async move {
                    assert_eq!(id, workflow_id);
                    Ok(Some(wf))
                })
            });
        workflow_repo.expect_create_workflow_run().returning(
            move |_, wf_id, ws_id, snapshot, _| {
                assert_eq!(wf_id, workflow_id);
                assert_eq!(ws_id, Some(workspace_id));
                assert_eq!(
                    snapshot.get("_start_from_node").and_then(|v| v.as_str()),
                    Some(trigger_node_id.as_str())
                );
                assert_eq!(
                    snapshot.get("_trigger_context"),
                    Some(&json!({
                        "event_type": "invoice.created",
                        "amount": 1200,
                        "trigger_node_id": trigger_node_id,
                        "trigger_type": "webhook",
                        "source": "webhook"
                    }))
                );
                assert_eq!(
                    snapshot.get("_egress_allowlist"),
                    Some(&json!(["https://example.com"]))
                );
                let now = OffsetDateTime::now_utc();
                let run = WorkflowRun {
                    id: Uuid::new_v4(),
                    user_id: Uuid::new_v4(),
                    workflow_id: wf_id,
                    workspace_id: ws_id,
                    snapshot,
                    status: "queued".into(),
                    error: None,
                    idempotency_key: None,
                    started_at: now,
                    resume_at: now,
                    finished_at: None,
                    created_at: now,
                    updated_at: now,
                };
                Box::pin(async move { Ok(CreateWorkflowRunOutcome { run, created: true }) })
            },
        );

        let dedupe_repo = StubWebhookIngressDedupeRepo::default();
        let delivery_repo = StubWebhookDeliveryRepo::default();
        let response = invoke_handle_webhook_ingress_with_payload(
            &dedupe_repo,
            &delivery_repo,
            &repo,
            &subscription_repo,
            &workflow_repo,
            WebhookIngressDedupeMode::Off,
            &key,
            source_id,
            &HeaderMap::new(),
            br#"{"event_type":"invoice.created","amount":1200}"#,
            OffsetDateTime::now_utc(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload["success"], json!(true));
    }

    #[tokio::test]
    async fn webhook_subscription_zero_matches_returns_accepted() {
        let key = vec![9u8; 32];
        let source_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let secret = encrypt_secret(&key, "secret").expect("encrypt");
        let mut source = webhook_source_fixture(source_id, workspace_id, secret);
        source.require_hmac = false;
        let repo = StubWebhookSourceRepo {
            source: Some(source),
            ..Default::default()
        };

        let subscription_repo = StubWebhookSubscriptionRepo::default();

        let mut workflow_repo = MockWorkflowRepository::new();
        workflow_repo.expect_find_workflow_by_id_public().times(0);
        workflow_repo.expect_create_workflow_run().times(0);

        let dedupe_repo = StubWebhookIngressDedupeRepo::default();
        let delivery_repo = StubWebhookDeliveryRepo::default();
        let response = invoke_handle_webhook_ingress_with_payload(
            &dedupe_repo,
            &delivery_repo,
            &repo,
            &subscription_repo,
            &workflow_repo,
            WebhookIngressDedupeMode::Off,
            &key,
            source_id,
            &HeaderMap::new(),
            br#"{"event_type":"invoice.created","amount":1200}"#,
            OffsetDateTime::now_utc(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn webhook_delivery_logs_dropped_when_no_subscriptions() {
        let key = vec![9u8; 32];
        let source_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let secret = encrypt_secret(&key, "secret").expect("encrypt");
        let mut source = webhook_source_fixture(source_id, workspace_id, secret);
        source.require_hmac = false;
        let repo = StubWebhookSourceRepo {
            source: Some(source),
            ..Default::default()
        };

        let subscription_repo = StubWebhookSubscriptionRepo::default();

        let mut workflow_repo = MockWorkflowRepository::new();
        workflow_repo.expect_find_workflow_by_id_public().times(0);
        workflow_repo.expect_create_workflow_run().times(0);

        let dedupe_repo = StubWebhookIngressDedupeRepo::default();
        let delivery_repo = StubWebhookDeliveryRepo::default();
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_020).unwrap();

        let response = invoke_handle_webhook_ingress_with_payload(
            &dedupe_repo,
            &delivery_repo,
            &repo,
            &subscription_repo,
            &workflow_repo,
            WebhookIngressDedupeMode::Off,
            &key,
            source_id,
            &HeaderMap::new(),
            br#"{"event_type":"invoice.created","amount":1200}"#,
            now,
        )
        .await;

        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let deliveries = delivery_repo.deliveries.lock().unwrap();
        assert_eq!(deliveries.len(), 1);
        let delivery = &deliveries[0];
        assert_eq!(delivery.webhook_source_id, source_id);
        assert_eq!(delivery.subscription_id, None);
        assert_eq!(delivery.event_type, "invoice.created");
        assert_eq!(delivery.received_at, now);
        assert_eq!(delivery.delivery_status, DELIVERY_STATUS_DROPPED);
        assert_eq!(
            delivery.error_message.as_deref(),
            Some(DELIVERY_ERROR_NO_MATCHING_SUBSCRIPTIONS)
        );
    }

    #[tokio::test]
    async fn webhook_delivery_logging_failure_does_not_block() {
        let key = vec![9u8; 32];
        let source_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let secret = encrypt_secret(&key, "secret").expect("encrypt");
        let mut source = webhook_source_fixture(source_id, workspace_id, secret);
        source.require_hmac = false;
        let repo = StubWebhookSourceRepo {
            source: Some(source),
            ..Default::default()
        };

        let workflow = workflow_fixture(workspace_id, Uuid::new_v4());
        let workflow_id = workflow.id;
        let subscription = WebhookSubscription {
            id: Uuid::new_v4(),
            webhook_source_id: source_id,
            workflow_id,
            trigger_node_id: Uuid::new_v4(),
            event_type: "invoice.created".into(),
            enabled: true,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };
        let subscription_repo = StubWebhookSubscriptionRepo {
            subscriptions: vec![subscription],
        };

        let mut workflow_repo = MockWorkflowRepository::new();
        let workflow_for_find = workflow.clone();
        workflow_repo
            .expect_find_workflow_by_id_public()
            .returning(move |_| {
                let wf = workflow_for_find.clone();
                Box::pin(async move { Ok(Some(wf)) })
            });
        workflow_repo
            .expect_create_workflow_run()
            .times(1)
            .returning(move |_, wf_id, ws_id, snapshot, _| {
                assert_eq!(wf_id, workflow_id);
                assert_eq!(ws_id, Some(workspace_id));
                assert!(snapshot.get("_trigger_context").is_some());
                let now = OffsetDateTime::now_utc();
                let run = WorkflowRun {
                    id: Uuid::new_v4(),
                    user_id: Uuid::new_v4(),
                    workflow_id: wf_id,
                    workspace_id: ws_id,
                    snapshot,
                    status: "queued".into(),
                    error: None,
                    idempotency_key: None,
                    started_at: now,
                    resume_at: now,
                    finished_at: None,
                    created_at: now,
                    updated_at: now,
                };
                Box::pin(async move { Ok(CreateWorkflowRunOutcome { run, created: true }) })
            });

        let dedupe_repo = StubWebhookIngressDedupeRepo::default();
        let delivery_repo = StubWebhookDeliveryRepo::new(true, false);
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_030).unwrap();

        let response = invoke_handle_webhook_ingress_with_payload(
            &dedupe_repo,
            &delivery_repo,
            &repo,
            &subscription_repo,
            &workflow_repo,
            WebhookIngressDedupeMode::Off,
            &key,
            source_id,
            &HeaderMap::new(),
            br#"{"event_type":"invoice.created","amount":1200}"#,
            now,
        )
        .await;

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert!(delivery_repo.deliveries.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn webhook_fanout_enqueues_multiple_runs() {
        let key = vec![9u8; 32];
        let source_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let secret = encrypt_secret(&key, "secret").expect("encrypt");
        let mut source = webhook_source_fixture(source_id, workspace_id, secret);
        source.require_hmac = false;
        let repo = StubWebhookSourceRepo {
            source: Some(source),
            ..Default::default()
        };

        let trigger_one = Uuid::new_v4();
        let trigger_two = Uuid::new_v4();

        let mut workflow = workflow_fixture(workspace_id, Uuid::new_v4());
        workflow.data = json!({
            "nodes": [webhook_trigger_node(trigger_one), webhook_trigger_node(trigger_two)],
            "edges": []
        });
        let workflow_id = workflow.id;

        let subscription_repo = StubWebhookSubscriptionRepo {
            subscriptions: vec![
                WebhookSubscription {
                    id: Uuid::new_v4(),
                    webhook_source_id: source_id,
                    workflow_id,
                    trigger_node_id: trigger_one,
                    event_type: "invoice.created".into(),
                    enabled: true,
                    created_at: OffsetDateTime::now_utc(),
                    updated_at: OffsetDateTime::now_utc(),
                },
                WebhookSubscription {
                    id: Uuid::new_v4(),
                    webhook_source_id: source_id,
                    workflow_id,
                    trigger_node_id: trigger_two,
                    event_type: "invoice.created".into(),
                    enabled: true,
                    created_at: OffsetDateTime::now_utc(),
                    updated_at: OffsetDateTime::now_utc(),
                },
            ],
        };

        let mut workflow_repo = MockWorkflowRepository::new();
        let workflow_for_find = workflow.clone();
        workflow_repo
            .expect_find_workflow_by_id_public()
            .times(2)
            .returning(move |id| {
                let wf = workflow_for_find.clone();
                Box::pin(async move {
                    assert_eq!(id, workflow_id);
                    Ok(Some(wf))
                })
            });

        let expected_triggers = Arc::new(Mutex::new(
            vec![trigger_one.to_string(), trigger_two.to_string()]
                .into_iter()
                .collect::<HashSet<_>>(),
        ));
        let expected_triggers_clone = Arc::clone(&expected_triggers);

        workflow_repo
            .expect_create_workflow_run()
            .times(2)
            .returning(move |_, wf_id, ws_id, snapshot, _| {
                assert_eq!(wf_id, workflow_id);
                assert_eq!(ws_id, Some(workspace_id));
                let start = snapshot
                    .get("_start_from_node")
                    .and_then(|value| value.as_str())
                    .expect("start_from_node");
                let trigger_from_context = snapshot
                    .get("_trigger_context")
                    .and_then(|value| value.get("trigger_node_id"))
                    .and_then(|value| value.as_str())
                    .expect("trigger_node_id");
                assert_eq!(trigger_from_context, start);
                let mut expected = expected_triggers_clone.lock().unwrap();
                assert!(expected.remove(start));

                let now = OffsetDateTime::now_utc();
                let run = WorkflowRun {
                    id: Uuid::new_v4(),
                    user_id: Uuid::new_v4(),
                    workflow_id: wf_id,
                    workspace_id: ws_id,
                    snapshot,
                    status: "queued".into(),
                    error: None,
                    idempotency_key: None,
                    started_at: now,
                    resume_at: now,
                    finished_at: None,
                    created_at: now,
                    updated_at: now,
                };
                Box::pin(async move { Ok(CreateWorkflowRunOutcome { run, created: true }) })
            });

        let dedupe_repo = StubWebhookIngressDedupeRepo::default();
        let delivery_repo = StubWebhookDeliveryRepo::default();
        let response = invoke_handle_webhook_ingress_with_payload(
            &dedupe_repo,
            &delivery_repo,
            &repo,
            &subscription_repo,
            &workflow_repo,
            WebhookIngressDedupeMode::Off,
            &key,
            source_id,
            &HeaderMap::new(),
            br#"{"event_type":"invoice.created","amount":1200}"#,
            OffsetDateTime::now_utc(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert!(expected_triggers.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn webhook_fanout_partial_failure_does_not_block() {
        let key = vec![9u8; 32];
        let source_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let secret = encrypt_secret(&key, "secret").expect("encrypt");
        let mut source = webhook_source_fixture(source_id, workspace_id, secret);
        source.require_hmac = false;
        let repo = StubWebhookSourceRepo {
            source: Some(source),
            ..Default::default()
        };

        let trigger_fail = Uuid::new_v4();
        let trigger_ok = Uuid::new_v4();

        let mut workflow = workflow_fixture(workspace_id, Uuid::new_v4());
        workflow.data = json!({
            "nodes": [webhook_trigger_node(trigger_fail), webhook_trigger_node(trigger_ok)],
            "edges": []
        });
        let workflow_id = workflow.id;

        let subscription_repo = StubWebhookSubscriptionRepo {
            subscriptions: vec![
                WebhookSubscription {
                    id: Uuid::new_v4(),
                    webhook_source_id: source_id,
                    workflow_id,
                    trigger_node_id: trigger_fail,
                    event_type: "invoice.created".into(),
                    enabled: true,
                    created_at: OffsetDateTime::now_utc(),
                    updated_at: OffsetDateTime::now_utc(),
                },
                WebhookSubscription {
                    id: Uuid::new_v4(),
                    webhook_source_id: source_id,
                    workflow_id,
                    trigger_node_id: trigger_ok,
                    event_type: "invoice.created".into(),
                    enabled: true,
                    created_at: OffsetDateTime::now_utc(),
                    updated_at: OffsetDateTime::now_utc(),
                },
            ],
        };

        let mut workflow_repo = MockWorkflowRepository::new();
        let workflow_for_find = workflow.clone();
        workflow_repo
            .expect_find_workflow_by_id_public()
            .times(2)
            .returning(move |id| {
                let wf = workflow_for_find.clone();
                Box::pin(async move {
                    assert_eq!(id, workflow_id);
                    Ok(Some(wf))
                })
            });

        let success_count = Arc::new(Mutex::new(0usize));
        let success_count_clone = Arc::clone(&success_count);
        let failing_trigger_id = trigger_fail.to_string();

        workflow_repo
            .expect_create_workflow_run()
            .times(2)
            .returning(move |_, wf_id, ws_id, snapshot, _| {
                assert_eq!(wf_id, workflow_id);
                assert_eq!(ws_id, Some(workspace_id));
                let start = snapshot
                    .get("_start_from_node")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default();
                if start == failing_trigger_id {
                    return Box::pin(async { Err(sqlx::Error::RowNotFound) });
                }

                let mut count = success_count_clone.lock().unwrap();
                *count += 1;

                let now = OffsetDateTime::now_utc();
                let run = WorkflowRun {
                    id: Uuid::new_v4(),
                    user_id: Uuid::new_v4(),
                    workflow_id: wf_id,
                    workspace_id: ws_id,
                    snapshot,
                    status: "queued".into(),
                    error: None,
                    idempotency_key: None,
                    started_at: now,
                    resume_at: now,
                    finished_at: None,
                    created_at: now,
                    updated_at: now,
                };
                Box::pin(async move { Ok(CreateWorkflowRunOutcome { run, created: true }) })
            });

        let dedupe_repo = StubWebhookIngressDedupeRepo::default();
        let delivery_repo = StubWebhookDeliveryRepo::default();
        let response = invoke_handle_webhook_ingress_with_payload(
            &dedupe_repo,
            &delivery_repo,
            &repo,
            &subscription_repo,
            &workflow_repo,
            WebhookIngressDedupeMode::Off,
            &key,
            source_id,
            &HeaderMap::new(),
            br#"{"event_type":"invoice.created","amount":1200}"#,
            OffsetDateTime::now_utc(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(*success_count.lock().unwrap(), 1);
    }

    #[tokio::test]
    async fn webhook_dedupe_log_only_still_enqueues() {
        let key = vec![9u8; 32];
        let source_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let secret = encrypt_secret(&key, "secret").expect("encrypt");
        let mut source = webhook_source_fixture(source_id, workspace_id, secret);
        source.require_hmac = false;
        let repo = StubWebhookSourceRepo {
            source: Some(source),
            ..Default::default()
        };

        let workflow = workflow_fixture(workspace_id, Uuid::new_v4());
        let workflow_id = workflow.id;
        let subscription = WebhookSubscription {
            id: Uuid::new_v4(),
            webhook_source_id: source_id,
            workflow_id,
            trigger_node_id: Uuid::new_v4(),
            event_type: "invoice.created".into(),
            enabled: true,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };
        let subscription_repo = StubWebhookSubscriptionRepo {
            subscriptions: vec![subscription.clone()],
        };

        let mut workflow_repo = MockWorkflowRepository::new();
        let workflow_for_find = workflow.clone();
        workflow_repo
            .expect_find_workflow_by_id_public()
            .times(2)
            .returning(move |_| {
                let wf = workflow_for_find.clone();
                Box::pin(async move { Ok(Some(wf)) })
            });
        workflow_repo
            .expect_create_workflow_run()
            .times(2)
            .returning(move |_, wf_id, ws_id, snapshot, _| {
                assert_eq!(wf_id, workflow_id);
                assert_eq!(ws_id, Some(workspace_id));
                assert!(snapshot.get("_trigger_context").is_some());
                let now = OffsetDateTime::now_utc();
                let run = WorkflowRun {
                    id: Uuid::new_v4(),
                    user_id: Uuid::new_v4(),
                    workflow_id: wf_id,
                    workspace_id: ws_id,
                    snapshot,
                    status: "queued".into(),
                    error: None,
                    idempotency_key: None,
                    started_at: now,
                    resume_at: now,
                    finished_at: None,
                    created_at: now,
                    updated_at: now,
                };
                Box::pin(async move { Ok(CreateWorkflowRunOutcome { run, created: true }) })
            });

        let dedupe_repo = StubWebhookIngressDedupeRepo::default();
        let delivery_repo = StubWebhookDeliveryRepo::default();
        let mut headers = HeaderMap::new();
        headers.insert(TIMESTAMP_HEADER, "1700000000".parse().unwrap());
        headers.insert(SIGNATURE_HEADER, "v1=deadbeef".parse().unwrap());
        let body = br#"{"event_type":"invoice.created","amount":1200}"#;
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_010).unwrap();

        let response = invoke_handle_webhook_ingress_with_payload(
            &dedupe_repo,
            &delivery_repo,
            &repo,
            &subscription_repo,
            &workflow_repo,
            WebhookIngressDedupeMode::LogOnly,
            &key,
            source_id,
            &headers,
            body,
            now,
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let response = invoke_handle_webhook_ingress_with_payload(
            &dedupe_repo,
            &delivery_repo,
            &repo,
            &subscription_repo,
            &workflow_repo,
            WebhookIngressDedupeMode::LogOnly,
            &key,
            source_id,
            &headers,
            body,
            now,
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn webhook_dedupe_enforce_suppresses_enqueues() {
        let key = vec![9u8; 32];
        let source_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let secret = encrypt_secret(&key, "secret").expect("encrypt");
        let mut source = webhook_source_fixture(source_id, workspace_id, secret);
        source.require_hmac = false;
        let repo = StubWebhookSourceRepo {
            source: Some(source),
            ..Default::default()
        };

        let workflow = workflow_fixture(workspace_id, Uuid::new_v4());
        let workflow_id = workflow.id;
        let subscription = WebhookSubscription {
            id: Uuid::new_v4(),
            webhook_source_id: source_id,
            workflow_id,
            trigger_node_id: Uuid::new_v4(),
            event_type: "invoice.created".into(),
            enabled: true,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };
        let subscription_repo = StubWebhookSubscriptionRepo {
            subscriptions: vec![subscription],
        };

        let mut workflow_repo = MockWorkflowRepository::new();
        let workflow_for_find = workflow.clone();
        workflow_repo
            .expect_find_workflow_by_id_public()
            .times(1)
            .returning(move |_| {
                let wf = workflow_for_find.clone();
                Box::pin(async move { Ok(Some(wf)) })
            });
        workflow_repo
            .expect_create_workflow_run()
            .times(1)
            .returning(move |_, wf_id, ws_id, snapshot, _| {
                assert_eq!(wf_id, workflow_id);
                assert_eq!(ws_id, Some(workspace_id));
                assert!(snapshot.get("_trigger_context").is_some());
                let now = OffsetDateTime::now_utc();
                let run = WorkflowRun {
                    id: Uuid::new_v4(),
                    user_id: Uuid::new_v4(),
                    workflow_id: wf_id,
                    workspace_id: ws_id,
                    snapshot,
                    status: "queued".into(),
                    error: None,
                    idempotency_key: None,
                    started_at: now,
                    resume_at: now,
                    finished_at: None,
                    created_at: now,
                    updated_at: now,
                };
                Box::pin(async move { Ok(CreateWorkflowRunOutcome { run, created: true }) })
            });

        let dedupe_repo = StubWebhookIngressDedupeRepo::default();
        let delivery_repo = StubWebhookDeliveryRepo::default();
        let mut headers = HeaderMap::new();
        headers.insert(TIMESTAMP_HEADER, "1700000000".parse().unwrap());
        headers.insert(SIGNATURE_HEADER, "v1=deadbeef".parse().unwrap());
        let body = br#"{"event_type":"invoice.created","amount":1200}"#;
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_010).unwrap();

        let response = invoke_handle_webhook_ingress_with_payload(
            &dedupe_repo,
            &delivery_repo,
            &repo,
            &subscription_repo,
            &workflow_repo,
            WebhookIngressDedupeMode::Enforce,
            &key,
            source_id,
            &headers,
            body,
            now,
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let response = invoke_handle_webhook_ingress_with_payload(
            &dedupe_repo,
            &delivery_repo,
            &repo,
            &subscription_repo,
            &workflow_repo,
            WebhookIngressDedupeMode::Enforce,
            &key,
            source_id,
            &headers,
            body,
            now,
        )
        .await;
        assert_eq!(response.status(), StatusCode::ACCEPTED);
    }
}
