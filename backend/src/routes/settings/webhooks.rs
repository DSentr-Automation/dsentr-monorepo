use axum::{
    extract::{Query, State},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::responses::JsonResponse;
use crate::routes::auth::session::AuthSession;
use crate::services::oauth::account_service::{
    installation_disabled_reason, installation_id_from_metadata, installation_is_disabled,
};
use crate::state::AppState;
use crate::utils::plan_limits::NormalizedPlanTier;

#[derive(Default, Deserialize)]
pub struct ProviderWebhooksQuery {
    #[serde(alias = "workspace")]
    pub workspace_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
struct ProviderWebhookMetadata {
    provider: &'static str,
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    disabled_reason: Option<String>,
    webhook_endpoint: &'static str,
    delivery_deduplication: bool,
    trigger_source: &'static str,
    description: &'static str,
    setup_instructions: Vec<&'static str>,
    notes: Vec<&'static str>,
}

pub async fn list_provider_webhooks(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Query(query): Query<ProviderWebhooksQuery>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    let workspace_id = match query.workspace_id {
        Some(id) => id,
        None => return JsonResponse::bad_request("workspace_id is required").into_response(),
    };

    let memberships = match app_state
        .workspace_repo
        .list_memberships_for_user(user_id)
        .await
    {
        Ok(list) => list,
        Err(err) => {
            tracing::error!(?err, %user_id, "failed to load workspace memberships");
            return JsonResponse::server_error("Failed to verify workspace access").into_response();
        }
    };

    let membership = match memberships
        .iter()
        .find(|membership| membership.workspace.id == workspace_id)
    {
        Some(member) => member,
        None => {
            return JsonResponse::forbidden("You do not have access to this workspace.")
                .into_response()
        }
    };

    let plan_tier = NormalizedPlanTier::from_option(Some(membership.workspace.plan.as_str()));
    if plan_tier.is_solo() {
        return JsonResponse::forbidden(
            "Provider webhooks are only available on the Workspace plan.",
        )
        .into_response();
    }

    let connections = match app_state
        .workspace_connection_repo
        .list_by_workspace_and_provider(
            workspace_id,
            crate::models::oauth_token::ConnectedOAuthProvider::GitHub,
        )
        .await
    {
        Ok(records) => records,
        Err(err) => {
            tracing::error!(?err, %workspace_id, "failed to load workspace GitHub connections");
            return JsonResponse::server_error("Failed to load provider webhooks").into_response();
        }
    };

    // Enabled is derived lazily from GitHub connection metadata; we only flip it off when
    // failures prove the installation is no longer valid.
    let mut enabled = false;
    let mut disabled_reason = None;
    for connection in connections {
        if installation_id_from_metadata(&connection.metadata).is_none() {
            continue;
        }
        if installation_is_disabled(&connection.metadata) {
            if disabled_reason.is_none() {
                disabled_reason = installation_disabled_reason(&connection.metadata)
                    .map(|reason| reason.to_string());
            }
        } else {
            enabled = true;
            disabled_reason = None;
            break;
        }
    }

    let providers = vec![ProviderWebhookMetadata {
        provider: "github",
        enabled,
        disabled_reason,
        webhook_endpoint: "/webhooks/github",
        delivery_deduplication: true,
        trigger_source: "provider_triggers",
        description: "Receives GitHub App webhooks and fans out to matching workflows.",
        setup_instructions: vec![
            "Install the GitHub App into your account or organization.",
            "Select repositories during installation.",
            "Create workflows with GitHub trigger nodes.",
            "Publish the workflow to activate triggers.",
        ],
        notes: vec![
            "Webhooks are shared across all workflows.",
            "Routing is automatic based on trigger configuration.",
            "No per-workflow webhook URLs are required.",
        ],
    }];

    JsonResponse::success_with_wrapped_data(
        "Provider webhooks loaded",
        json!({ "providers": providers }),
    )
    .into_response()
}
