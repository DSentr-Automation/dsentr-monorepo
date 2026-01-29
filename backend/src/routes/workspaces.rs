use std::{collections::BTreeMap, env};

use axum::{
    extract::{Path, State},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use tracing::{error, warn};
use urlencoding::encode;
use uuid::Uuid;

use super::plan_limits::workspace_limit_error_response;
use crate::{
    engine::actions::ensure_workspace_plan,
    models::oauth_token::ConnectedOAuthProvider,
    models::{
        plan::PlanTier,
        user::PublicUser,
        workflow::Workflow,
        workspace::{
            Workspace, WorkspaceInvitation, WorkspaceMembershipSummary, WorkspaceRole,
            INVITATION_STATUS_PENDING,
        },
    },
    responses::JsonResponse,
    routes::auth::session::AuthSession,
    services::oauth::workspace_service::WorkspaceOAuthError,
    state::AppState,
    utils::{
        plan_limits::NormalizedPlanTier,
        secrets::{
            collect_secret_identifiers, read_secret_store, write_secret_store, SecretIdentifier,
        },
    },
};

#[derive(Debug, Serialize, Clone)]
struct PlanOption {
    tier: PlanTier,
    name: &'static str,
    description: &'static str,
    price: String,
}

fn plan_price_from_env(var: &str, default: &str) -> String {
    match env::var(var) {
        Ok(value) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                default.to_string()
            } else {
                trimmed.to_owned()
            }
        }
        Err(_) => default.to_string(),
    }
}

fn plan_options() -> Vec<PlanOption> {
    vec![
        PlanOption {
            tier: PlanTier::Solo,
            name: "Solo",
            description: "Build personal automations with a single user account.",
            price: "Free".to_string(),
        },
        PlanOption {
            tier: PlanTier::Workspace,
            name: "Workspace",
            description: "Collaborate with your team inside one shared workspace.",
            price: plan_price_from_env("WORKSPACE_PLAN_PRICE", "$29/mo"),
        },
    ]
}

#[derive(Debug, Deserialize)]
pub struct CompleteOnboardingPayload {
    pub plan_tier: PlanTier,
    #[serde(default)]
    pub workspace_name: Option<String>,
    #[serde(default)]
    pub shared_workflow_ids: Vec<Uuid>,
}

#[derive(Debug, Deserialize)]
pub struct PromoteWorkspaceConnectionPayload {
    pub user_oauth_token_id: Uuid,
    pub provider: ConnectedOAuthProvider,
}

async fn process_plan_change(
    app_state: &AppState,
    user_id: Uuid,
    payload: &CompleteOnboardingPayload,
    now: OffsetDateTime,
    mark_onboarded: bool,
) -> Result<serde_json::Value, Response> {
    let mut created_workspace: Option<Workspace> = None;
    let mut updated_workflows: Vec<Workflow> = Vec::new();
    #[allow(unused_assignments)]
    let mut workspace_id: Option<Uuid> = None;

    match payload.plan_tier {
        PlanTier::Solo => {
            if !payload.shared_workflow_ids.is_empty() {
                return Err(JsonResponse::bad_request(
                    "Solo plans do not support sharing workflows with a workspace",
                )
                .into_response());
            }

            let existing_memberships = match app_state
                .workspace_repo
                .list_memberships_for_user(user_id)
                .await
            {
                Ok(list) => list,
                Err(err) => {
                    tracing::error!(
                        "failed to inspect workspace memberships during plan change: {:?}",
                        err
                    );
                    return Err(
                        JsonResponse::server_error("Failed to update workspace settings")
                            .into_response(),
                    );
                }
            };

            // For Stripe-billed workspace plans, schedule cancellation at period end
            let owns_workspace_on_workspace_plan = existing_memberships.iter().any(|m| {
                m.workspace.owner_id == user_id
                    && !NormalizedPlanTier::from_option(Some(m.workspace.plan.as_str())).is_solo()
            });

            if owns_workspace_on_workspace_plan {
                if let Ok(Some(customer_id)) =
                    app_state.db.get_user_stripe_customer_id(user_id).await
                {
                    match app_state
                        .stripe
                        .get_active_subscription_for_customer(&customer_id)
                        .await
                    {
                        Ok(Some(sub)) => {
                            // If not already scheduled, set cancel_at_period_end
                            let updated = if !sub.cancel_at_period_end {
                                match app_state
                                    .stripe
                                    .set_subscription_cancel_at_period_end(&sub.id, true)
                                    .await
                                {
                                    Ok(u) => u,
                                    Err(err) => {
                                        tracing::error!(
                                            "failed to schedule subscription cancellation: {:?}",
                                            err
                                        );
                                        return Err(JsonResponse::server_error(
                                            "Failed to schedule downgrade",
                                        )
                                        .into_response());
                                    }
                                }
                            } else {
                                sub
                            };

                            // Respond with scheduled downgrade info (do not change plan immediately)
                            let effective_ts =
                                updated.cancel_at.unwrap_or(updated.current_period_end);
                            let effective_iso =
                                time::OffsetDateTime::from_unix_timestamp(effective_ts)
                                    .unwrap_or_else(|_| time::OffsetDateTime::now_utc())
                                    .format(&time::format_description::well_known::Rfc3339)
                                    .unwrap_or_else(|_| String::new());

                            return Ok(json!({
                                "success": true,
                                "scheduled_downgrade": { "effective_at": effective_iso },
                            }));
                        }
                        Ok(None) => {
                            // No active subscription; fall through to immediate downgrade below
                        }
                        Err(err) => {
                            tracing::warn!("failed to lookup active subscription: {:?}", err);
                            // Fall through to immediate downgrade
                        }
                    }
                }
            }

            // Immediate downgrade for non-Stripe or no active subscription
            for membership in existing_memberships
                .iter()
                .filter(|membership| membership.workspace.owner_id == user_id)
            {
                if !NormalizedPlanTier::from_option(Some(membership.workspace.plan.as_str()))
                    .is_solo()
                {
                    if let Err(err) = app_state
                        .workspace_repo
                        .update_workspace_plan(membership.workspace.id, PlanTier::Solo.as_str())
                        .await
                    {
                        tracing::error!(
                            "failed to downgrade workspace plan during plan change: {:?}",
                            err
                        );
                        return Err(JsonResponse::server_error("Failed to update workspace")
                            .into_response());
                    }
                }
            }

            app_state
                .clear_owned_workspace_billing_cycles(user_id)
                .await;

            let owned_membership = existing_memberships
                .into_iter()
                .find(|membership| membership.workspace.owner_id == user_id);

            if let Some(membership) = owned_membership {
                if membership.role != WorkspaceRole::Owner {
                    if let Err(err) = app_state
                        .workspace_repo
                        .set_member_role(membership.workspace.id, user_id, WorkspaceRole::Owner)
                        .await
                    {
                        tracing::error!(
                            "failed to promote workspace membership during plan change: {:?}",
                            err
                        );
                        return Err(JsonResponse::server_error(
                            "Failed to update workspace membership",
                        )
                        .into_response());
                    }
                }

                workspace_id = Some(membership.workspace.id);
            } else {
                let user = match app_state.db.find_public_user_by_id(user_id).await {
                    Ok(Some(user)) => user,
                    Ok(None) => {
                        return Err(JsonResponse::not_found("User not found").into_response())
                    }
                    Err(err) => {
                        tracing::error!(
                            "failed to load user for solo workspace provisioning: {:?}",
                            err
                        );
                        return Err(JsonResponse::server_error("Failed to provision workspace")
                            .into_response());
                    }
                };

                let name = payload
                    .workspace_name
                    .as_ref()
                    .map(|value| value.trim())
                    .filter(|value| !value.is_empty())
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| solo_workspace_name(&user));

                let workspace = match app_state
                    .workspace_repo
                    .create_workspace(&name, user.id, PlanTier::Solo.as_str())
                    .await
                {
                    Ok(workspace) => workspace,
                    Err(err) => {
                        tracing::error!(
                            "failed to create solo workspace during plan change: {:?}",
                            err
                        );
                        return Err(JsonResponse::server_error("Failed to create workspace")
                            .into_response());
                    }
                };

                if let Err(err) = app_state
                    .workspace_repo
                    .add_member(workspace.id, user.id, WorkspaceRole::Owner)
                    .await
                {
                    tracing::error!(
                        "failed to attach owner membership during plan change: {:?}",
                        err
                    );
                    return Err(JsonResponse::server_error(
                        "Failed to create workspace membership",
                    )
                    .into_response());
                }

                workspace_id = Some(workspace.id);
                created_workspace = Some(workspace);
            }
        }
        PlanTier::Workspace => {
            // New behavior: start a Stripe Checkout for workspace upgrades instead of immediate plan updates
            let workspace_name = payload
                .workspace_name
                .as_ref()
                .map(|name| name.trim())
                .filter(|name| !name.is_empty())
                .ok_or_else(|| {
                    JsonResponse::bad_request(
                        "Workspace name is required for this subscription tier",
                    )
                    .into_response()
                })?;

            let user = match app_state.db.find_public_user_by_id(user_id).await {
                Ok(Some(u)) => u,
                Ok(None) => return Err(JsonResponse::not_found("User not found").into_response()),
                Err(err) => {
                    tracing::error!("failed to fetch user for stripe customer: {:?}", err);
                    return Err(
                        JsonResponse::server_error("Failed to start checkout").into_response()
                    );
                }
            };

            let existing_customer = match app_state.db.get_user_stripe_customer_id(user_id).await {
                Ok(id) => id,
                Err(err) => {
                    tracing::error!("failed to lookup stripe customer id: {:?}", err);
                    return Err(
                        JsonResponse::server_error("Failed to start checkout").into_response()
                    );
                }
            };

            let customer_id = if let Some(id) = existing_customer {
                id
            } else {
                let name = format!("{} {}", user.first_name, user.last_name);
                match app_state
                    .stripe
                    .create_customer(&user.email, Some(name.trim()))
                    .await
                {
                    Ok(id) => {
                        if let Err(err) =
                            app_state.db.set_user_stripe_customer_id(user_id, &id).await
                        {
                            tracing::warn!(
                                "failed to persist stripe customer id for user {}: {:?}",
                                user_id,
                                err
                            );
                        }
                        id
                    }
                    Err(err) => {
                        tracing::error!("failed to create stripe customer: {:?}", err);
                        return Err(
                            JsonResponse::server_error("Failed to start checkout").into_response()
                        );
                    }
                }
            };

            let price_id = std::env::var("STRIPE_WORKSPACE_PRICE_ID")
                .unwrap_or_else(|_| "price_test".to_string());
            let overage_price_id = match std::env::var("STRIPE_OVERAGE_PRICE_ID") {
                Ok(val) if !val.trim().is_empty() => val,
                _ => {
                    tracing::error!("missing STRIPE_OVERAGE_PRICE_ID for workspace upgrade");
                    return Err(
                        JsonResponse::server_error("Billing is not configured").into_response()
                    );
                }
            };
            let success_url = format!(
                "{}/dashboard?billing=success&session_id={{CHECKOUT_SESSION_ID}}",
                app_state.config.frontend_origin
            );
            let cancel_url = format!(
                "{}/dashboard?billing=cancel",
                app_state.config.frontend_origin
            );

            let mut metadata = BTreeMap::new();
            metadata.insert("plan".to_string(), PlanTier::Workspace.as_str().to_string());
            metadata.insert("workspace_name".to_string(), workspace_name.to_string());
            metadata.insert("user_id".to_string(), user_id.to_string());
            let mut line_items = vec![crate::services::stripe::CheckoutLineItem {
                price: price_id,
                quantity: Some(1),
            }];
            if workspace_id.is_none() {
                // Workspace plan subscriptions always attach the metered overage item; existing
                // workspaces will already carry their subscription item id for idempotency.
                line_items.push(crate::services::stripe::CheckoutLineItem {
                    price: overage_price_id,
                    quantity: None,
                });
            }

            let session = match app_state
                .stripe
                .create_checkout_session(crate::services::stripe::CreateCheckoutSessionRequest {
                    success_url,
                    cancel_url,
                    mode: crate::services::stripe::CheckoutMode::Subscription,
                    line_items,
                    client_reference_id: Some(user_id.to_string()),
                    customer: Some(customer_id.clone()),
                    metadata: Some(metadata),
                })
                .await
            {
                Ok(s) => s,
                Err(err) => {
                    tracing::error!("failed to create stripe checkout session: {:?}", err);
                    return Err(
                        JsonResponse::server_error("Failed to start checkout").into_response()
                    );
                }
            };

            // Persist pending checkout in user settings for later reconciliation
            let mut settings = match app_state.db.get_user_settings(user_id).await {
                Ok(val) => val,
                Err(err) => {
                    tracing::warn!(
                        "failed to load user settings for pending checkout: {:?}",
                        err
                    );
                    serde_json::Value::Object(Default::default())
                }
            };
            let pending = serde_json::json!({
                "session_id": session.id,
                "plan_tier": PlanTier::Workspace.as_str(),
                "workspace_name": workspace_name,
            });
            if let Some(map) = settings.as_object_mut() {
                map.entry("billing")
                    .or_insert_with(|| serde_json::json!({}));
                if let Some(billing) = map.get_mut("billing").and_then(|b| b.as_object_mut()) {
                    billing.insert("pending_checkout".to_string(), pending);
                    // clear any previous error state now that a new attempt has started
                    billing.remove("last_error");
                    billing.remove("last_error_at");
                }
            }
            if let Err(err) = app_state.db.update_user_settings(user_id, settings).await {
                tracing::warn!("failed to persist pending checkout session: {:?}", err);
            }

            let checkout_url = session.url.unwrap_or_default();
            return Ok(json!({ "success": true, "checkout_url": checkout_url }));
        }
    }

    if let Some(workspace_id) = workspace_id {
        for workflow_id in &payload.shared_workflow_ids {
            match app_state
                .workflow_repo
                .set_workflow_workspace(user_id, *workflow_id, Some(workspace_id))
                .await
            {
                Ok(Some(workflow)) => updated_workflows.push(workflow),
                Ok(None) => {
                    return Err(JsonResponse::not_found("Workflow not found").into_response());
                }
                Err(err) => {
                    tracing::error!(
                        "failed to assign workflow {} to workspace {}: {:?}",
                        workflow_id,
                        workspace_id,
                        err
                    );
                    return Err(
                        JsonResponse::server_error("Failed to assign workflow").into_response()
                    );
                }
            }
        }
    } else if !payload.shared_workflow_ids.is_empty() {
        return Err(JsonResponse::bad_request(
            "Select a workspace-capable plan to share workflows",
        )
        .into_response());
    }

    if matches!(payload.plan_tier, PlanTier::Solo) {
        if let Err(err) = app_state
            .db
            .update_user_plan(user_id, payload.plan_tier.as_str())
            .await
        {
            tracing::error!("failed to update user plan tier: {:?}", err);
            return Err(
                JsonResponse::server_error("Failed to save subscription choice").into_response(),
            );
        }
    }

    if mark_onboarded && matches!(payload.plan_tier, PlanTier::Solo) {
        if let Err(err) = app_state.db.mark_workspace_onboarded(user_id, now).await {
            tracing::error!("failed to mark onboarding completion: {:?}", err);
            return Err(JsonResponse::server_error("Failed to finalize onboarding").into_response());
        }
    }

    let memberships = match app_state
        .workspace_repo
        .list_memberships_for_user(user_id)
        .await
    {
        Ok(list) => list,
        Err(err) => {
            tracing::error!("failed to reload workspace memberships: {:?}", err);
            Vec::new()
        }
    };

    Ok(json!({
        "success": true,
        "plan": payload.plan_tier,
        "workspace": created_workspace,
        "memberships": memberships,
        "shared_workflows": updated_workflows,
    }))
}

pub async fn get_onboarding_context(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    let mut user = match app_state.db.find_public_user_by_id(user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return JsonResponse::not_found("User not found").into_response(),
        Err(err) => {
            tracing::error!("failed to fetch user for onboarding context: {:?}", err);
            return JsonResponse::server_error("Failed to load onboarding context").into_response();
        }
    };

    let workflows = match app_state
        .workflow_repo
        .list_workflows_by_user(user_id)
        .await
    {
        Ok(list) => list,
        Err(err) => {
            tracing::error!(
                "failed to fetch workflows for onboarding context: {:?}",
                err
            );
            return JsonResponse::server_error("Failed to load onboarding context").into_response();
        }
    };

    let mut memberships = match app_state
        .workspace_repo
        .list_memberships_for_user(user_id)
        .await
    {
        Ok(list) => list,
        Err(err) => {
            tracing::error!("failed to fetch workspace memberships: {:?}", err);
            return JsonResponse::server_error("Failed to load onboarding context").into_response();
        }
    };

    let plans = plan_options();

    // Surface billing status (e.g., last error) and subscription info
    let mut billing = serde_json::json!({});
    let mut has_pending_checkout = false;
    if let Ok(settings) = app_state.db.get_user_settings(user_id).await {
        if let Some(obj) = settings.as_object() {
            if let Some(b) = obj.get("billing").and_then(|v| v.as_object()) {
                if let Some(err) = b.get("last_error").and_then(|v| v.as_str()) {
                    billing["last_error"] = serde_json::json!(err);
                }
                if let Some(at) = b.get("last_error_at").cloned() {
                    billing["last_error_at"] = at;
                }
                has_pending_checkout = b
                    .get("pending_checkout")
                    .map(|v| !v.is_null())
                    .unwrap_or(false);
                billing["has_pending_checkout"] = serde_json::json!(has_pending_checkout);
            }
        }
    }

    // Attach subscription renewal/cancel info when we have a Stripe customer
    let mut has_active_subscription = false;
    if let Ok(Some(customer_id)) = app_state.db.get_user_stripe_customer_id(user_id).await {
        if let Ok(Some(sub)) = app_state
            .stripe
            .get_active_subscription_for_customer(&customer_id)
            .await
        {
            has_active_subscription = true;
            let period_start = time::OffsetDateTime::from_unix_timestamp(sub.current_period_start)
                .unwrap_or_else(|_| time::OffsetDateTime::now_utc());
            let period_end = time::OffsetDateTime::from_unix_timestamp(sub.current_period_end)
                .unwrap_or_else(|_| time::OffsetDateTime::now_utc());
            app_state
                .sync_owned_workspace_billing_cycles(user_id, &sub.id, period_start, period_end)
                .await;
            let renew_iso = period_end
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| String::new());
            let cancel_iso = sub.cancel_at.and_then(|ts| {
                time::OffsetDateTime::from_unix_timestamp(ts)
                    .ok()
                    .and_then(|dt| {
                        dt.format(&time::format_description::well_known::Rfc3339)
                            .ok()
                    })
            });
            let start_iso = period_start
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| String::new());
            billing["subscription"] = serde_json::json!({
                "id": sub.id,
                "status": sub.status,
                "renews_at": renew_iso,
                "cycle_started_at": start_iso,
                "cancel_at": cancel_iso,
                "cancel_at_period_end": sub.cancel_at_period_end,
            });
        }
    }

    // Passive reconciliation: if user is on workspace plan but there's no active subscription
    // and no pending checkout, revert to solo and downgrade owned workspaces.
    if !NormalizedPlanTier::from_option(user.plan.as_deref()).is_solo()
        && !has_pending_checkout
        && !has_active_subscription
    {
        if let Err(err) = app_state.db.update_user_plan(user_id, "solo").await {
            tracing::warn!(?err, %user_id, "failed to revert user plan to solo during onboarding context");
        } else {
            if let Ok(m) = app_state
                .workspace_repo
                .list_memberships_for_user(user_id)
                .await
            {
                for item in m.iter().filter(|m| {
                    m.workspace.owner_id == user_id && m.workspace.plan.as_str() != "solo"
                }) {
                    if let Err(err) = app_state
                        .workspace_repo
                        .update_workspace_plan(item.workspace.id, "solo")
                        .await
                    {
                        tracing::warn!(?err, workspace_id=%item.workspace.id, %user_id, "failed to downgrade workspace to solo during onboarding context");
                    }
                }
            }
            // Refresh user + memberships to reflect changes in response
            if let Ok(Some(u)) = app_state.db.find_public_user_by_id(user_id).await {
                user = u;
            }
            if let Ok(list) = app_state
                .workspace_repo
                .list_memberships_for_user(user_id)
                .await
            {
                memberships = list;
            }
        }
        app_state
            .clear_owned_workspace_billing_cycles(user_id)
            .await;
    }

    Json(json!({
        "success": true,
        "user": user,
        "workflows": workflows,
        "memberships": memberships,
        "plan_options": plans,
        "billing": billing,
    }))
    .into_response()
}

// POST /api/workspaces/billing/subscription/resume
// Clears cancel_at_period_end on the active Stripe subscription so the Workspace plan continues.
pub async fn resume_workspace_subscription(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    // Lookup stripe customer id
    let customer_id = match app_state.db.get_user_stripe_customer_id(user_id).await {
        Ok(Some(id)) => id,
        Ok(None) => {
            return JsonResponse::bad_request("No Stripe customer configured").into_response()
        }
        Err(err) => {
            error!(?err, %user_id, "failed to load stripe customer id");
            return JsonResponse::server_error("Failed to resume subscription").into_response();
        }
    };

    // Find active subscription
    let sub = match app_state
        .stripe
        .get_active_subscription_for_customer(&customer_id)
        .await
    {
        Ok(Some(s)) => s,
        Ok(None) => {
            return JsonResponse::bad_request("No active subscription to resume").into_response()
        }
        Err(err) => {
            error!(?err, %user_id, "failed to load subscription");
            return JsonResponse::server_error("Failed to resume subscription").into_response();
        }
    };

    // Clear cancel_at_period_end
    let updated = match app_state
        .stripe
        .set_subscription_cancel_at_period_end(&sub.id, false)
        .await
    {
        Ok(u) => u,
        Err(err) => {
            error!(?err, %user_id, subscription_id=%sub.id, "failed to clear cancel_at_period_end");
            return JsonResponse::server_error("Failed to resume subscription").into_response();
        }
    };

    let period_start = time::OffsetDateTime::from_unix_timestamp(updated.current_period_start)
        .unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    let period_end = time::OffsetDateTime::from_unix_timestamp(updated.current_period_end)
        .unwrap_or_else(|_| time::OffsetDateTime::now_utc());
    app_state
        .sync_owned_workspace_billing_cycles(user_id, &updated.id, period_start, period_end)
        .await;
    let renew_iso = period_end
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| String::new());
    let start_iso = period_start
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| String::new());

    Json(json!({
        "success": true,
        "subscription": {
            "id": updated.id,
            "status": updated.status,
            "renews_at": renew_iso,
            "cycle_started_at": start_iso,
            "cancel_at": serde_json::Value::Null,
            "cancel_at_period_end": false,
        }
    }))
    .into_response()
}

pub async fn complete_onboarding(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Json(payload): Json<CompleteOnboardingPayload>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    let now = OffsetDateTime::now_utc();

    match process_plan_change(&app_state, user_id, &payload, now, true).await {
        Ok(value) => Json(value).into_response(),
        Err(response) => response,
    }
}

pub async fn change_plan(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Json(payload): Json<CompleteOnboardingPayload>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    let now = OffsetDateTime::now_utc();

    match process_plan_change(&app_state, user_id, &payload, now, false).await {
        Ok(value) => Json(value).into_response(),
        Err(response) => response,
    }
}

// --- Workspace members management ---

#[derive(Debug, Serialize)]
struct PendingInvitationWithWorkspaceName {
    #[serde(flatten)]
    invitation: WorkspaceInvitation,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace_name: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AddWorkspaceMemberPayload {
    pub user_id: Uuid,
    pub role: WorkspaceRole,
}

#[derive(Debug, Deserialize)]
pub struct UpdateWorkspaceMemberRolePayload {
    pub role: WorkspaceRole,
}

pub async fn list_workspaces(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    match app_state.workspace_repo.list_user_workspaces(user_id).await {
        Ok(workspaces) => {
            Json(json!({ "success": true, "workspaces": workspaces })).into_response()
        }
        Err(err) => {
            error!(?err, %user_id, "failed to list workspaces for user");
            JsonResponse::server_error("Failed to load workspaces").into_response()
        }
    }
}

pub async fn list_pending_invites(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
) -> Response {
    let email = claims.email.trim();

    match app_state
        .workspace_repo
        .list_pending_invitations_for_email(email)
        .await
    {
        Ok(invites) => {
            let mut workspace_names: BTreeMap<Uuid, Option<String>> = BTreeMap::new();

            for invite in &invites {
                if workspace_names.contains_key(&invite.workspace_id) {
                    continue;
                }

                match app_state
                    .workspace_repo
                    .find_workspace(invite.workspace_id)
                    .await
                {
                    Ok(Some(workspace)) => {
                        workspace_names.insert(invite.workspace_id, Some(workspace.name));
                    }
                    Ok(None) => {
                        workspace_names.insert(invite.workspace_id, None);
                    }
                    Err(err) => {
                        error!(
                            ?err,
                            workspace_id = %invite.workspace_id,
                            "failed to load workspace for invitation"
                        );
                        return JsonResponse::server_error("Failed to load invitations")
                            .into_response();
                    }
                }
            }

            let invitations = invites
                .into_iter()
                .map(|invite| PendingInvitationWithWorkspaceName {
                    workspace_name: workspace_names
                        .get(&invite.workspace_id)
                        .and_then(|name| name.clone()),
                    invitation: invite,
                })
                .collect::<Vec<_>>();

            Json(json!({ "success": true, "invitations": invitations })).into_response()
        }
        Err(err) => {
            error!(?err, email, "failed to list pending invites");
            JsonResponse::server_error("Failed to load invitations").into_response()
        }
    }
}

async fn fetch_workspace_role(
    app_state: &AppState,
    user_id: Uuid,
    workspace_id: Uuid,
) -> Result<Option<WorkspaceRole>, Response> {
    let memberships = app_state
        .workspace_repo
        .list_memberships_for_user(user_id)
        .await
        .map_err(|_| JsonResponse::server_error("Failed to load memberships").into_response())?;
    Ok(memberships
        .into_iter()
        .find(|m| m.workspace.id == workspace_id)
        .map(|m| m.role))
}

async fn ensure_workspace_admin(
    app_state: &AppState,
    acting_user: Uuid,
    workspace_id: Uuid,
) -> Result<WorkspaceRole, Response> {
    match fetch_workspace_role(app_state, acting_user, workspace_id).await? {
        Some(role) if matches!(role, WorkspaceRole::Owner | WorkspaceRole::Admin) => Ok(role),
        _ => Err(JsonResponse::forbidden("Admin permissions required").into_response()),
    }
}

async fn ensure_workspace_owner(
    app_state: &AppState,
    acting_user: Uuid,
    workspace_id: Uuid,
) -> Result<(), Response> {
    match fetch_workspace_role(app_state, acting_user, workspace_id).await? {
        Some(WorkspaceRole::Owner) => Ok(()),
        _ => Err(JsonResponse::forbidden("Owner permissions required").into_response()),
    }
}

async fn require_workspace_admin(
    app_state: &AppState,
    acting_user: Uuid,
    workspace_id: Uuid,
) -> Result<(), Response> {
    ensure_workspace_admin(app_state, acting_user, workspace_id)
        .await
        .map(|_| ())
}

fn solo_workspace_name(user: &PublicUser) -> String {
    if let Some(company) = user
        .company_name
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        return format!("{} Workspace", company);
    }

    let first = user.first_name.trim();
    if !first.is_empty() {
        let suffix = if first.ends_with('s') { "'" } else { "'s" };
        return format!("{}{} Workspace", first, suffix);
    }

    "My Workspace".to_string()
}

async fn provision_solo_workspace(
    app_state: &AppState,
    user: &PublicUser,
) -> Result<(), sqlx::Error> {
    let name = solo_workspace_name(user);
    let workspace = app_state
        .workspace_repo
        .create_workspace(&name, user.id, PlanTier::Solo.as_str())
        .await?;

    app_state
        .workspace_repo
        .add_member(workspace.id, user.id, WorkspaceRole::Owner)
        .await?;

    app_state
        .db
        .update_user_plan(user.id, PlanTier::Solo.as_str())
        .await?;

    Ok(())
}

async fn ensure_solo_workspace_for_user(
    app_state: &AppState,
    user_id: Uuid,
) -> Result<(), sqlx::Error> {
    let user = app_state
        .db
        .find_public_user_by_id(user_id)
        .await?
        .ok_or(sqlx::Error::RowNotFound)?;

    provision_solo_workspace(app_state, &user).await
}

async fn load_membership_for_user(
    app_state: &AppState,
    user_id: Uuid,
    workspace_id: Uuid,
) -> Result<(WorkspaceMembershipSummary, Vec<WorkspaceMembershipSummary>), Response> {
    let memberships = app_state
        .workspace_repo
        .list_user_workspaces(user_id)
        .await
        .map_err(|_| JsonResponse::server_error("Failed to load memberships").into_response())?;

    match memberships
        .iter()
        .find(|summary| summary.workspace.id == workspace_id)
        .cloned()
    {
        Some(summary) => Ok((summary, memberships)),
        None => Err(JsonResponse::not_found("Membership not found").into_response()),
    }
}

pub async fn list_workspace_members(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    axum::extract::Path(workspace_id): axum::extract::Path<Uuid>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };
    if let Err(resp) = load_membership_for_user(&app_state, user_id, workspace_id).await {
        return resp;
    }
    match app_state.workspace_repo.list_members(workspace_id).await {
        Ok(members) => Json(json!({"success": true, "members": members})).into_response(),
        Err(_) => JsonResponse::server_error("Failed to list members").into_response(),
    }
}

pub async fn list_workspace_secret_ownership(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    axum::extract::Path(workspace_id): axum::extract::Path<Uuid>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    // Premium gate
    if let Err(msg) = ensure_workspace_plan(&app_state, workspace_id).await {
        return JsonResponse::forbidden(&msg).into_response();
    }

    // Admin check
    if let Err(resp) = ensure_workspace_admin(&app_state, user_id, workspace_id).await {
        return resp;
    }

    let members = match app_state.workspace_repo.list_members(workspace_id).await {
        Ok(members) => members,
        Err(err) => {
            error!(?err, %workspace_id, "failed to list workspace members for secret ownership");
            return JsonResponse::server_error("Failed to load workspace secrets").into_response();
        }
    };

    let mut ownership: BTreeMap<Uuid, Vec<SecretIdentifier>> = BTreeMap::new();
    let encryption_key = &app_state.config.api_secrets_encryption_key;

    for member in members {
        let settings = match app_state.db.get_user_settings(member.user_id).await {
            Ok(settings) => settings,
            Err(err) => {
                error!(
                    ?err,
                    %workspace_id,
                    member_id = %member.user_id,
                    "failed to load user settings while collecting workspace secrets"
                );
                return JsonResponse::server_error("Failed to load workspace secrets")
                    .into_response();
            }
        };

        let (store, hint) = match read_secret_store(&settings, encryption_key) {
            Ok(result) => result,
            Err(err) => {
                error!(
                    ?err,
                    %workspace_id,
                    member_id = %member.user_id,
                    "failed to decrypt workspace secrets while collecting ownership"
                );
                return JsonResponse::server_error("Failed to load workspace secrets")
                    .into_response();
            }
        };

        if hint.needs_rewrite {
            let mut settings = settings;
            if let Err(err) = write_secret_store(&mut settings, &store, encryption_key) {
                error!(
                    ?err,
                    %workspace_id,
                    member_id = %member.user_id,
                    "failed to re-encrypt workspace secrets while collecting ownership"
                );
                return JsonResponse::server_error("Failed to load workspace secrets")
                    .into_response();
            }
            if let Err(err) = app_state
                .db
                .update_user_settings(member.user_id, settings)
                .await
            {
                error!(
                    ?err,
                    %workspace_id,
                    member_id = %member.user_id,
                    "failed to persist workspace secrets while collecting ownership"
                );
                return JsonResponse::server_error("Failed to load workspace secrets")
                    .into_response();
            }
        }

        let identifiers = collect_secret_identifiers(&store);
        if !identifiers.is_empty() {
            ownership.insert(member.user_id, identifiers);
        }
    }

    Json(json!({ "success": true, "ownership": ownership })).into_response()
}

pub async fn add_workspace_member(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    axum::extract::Path(workspace_id): axum::extract::Path<Uuid>,
    Json(payload): Json<AddWorkspaceMemberPayload>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };
    let acting_role = match ensure_workspace_admin(&app_state, user_id, workspace_id).await {
        Ok(role) => role,
        Err(resp) => return resp,
    };
    if payload.role == WorkspaceRole::Owner {
        if acting_role != WorkspaceRole::Owner {
            return JsonResponse::forbidden(
                "Only the current owner can initiate ownership transfers",
            )
            .into_response();
        }
        return JsonResponse::bad_request(
            "Invite members as admin, user, or viewer and transfer ownership after they join",
        )
        .into_response();
    }

    if let Err(err) = app_state
        .ensure_workspace_can_add_members(workspace_id, 1)
        .await
    {
        return workspace_limit_error_response(err);
    }

    match app_state
        .workspace_repo
        .add_member(workspace_id, payload.user_id, payload.role)
        .await
    {
        Ok(_) => Json(json!({"success": true})).into_response(),
        Err(_) => JsonResponse::server_error("Failed to add member").into_response(),
    }
}

pub async fn update_workspace_member_role(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    axum::extract::Path((workspace_id, member_id)): axum::extract::Path<(Uuid, Uuid)>,
    Json(payload): Json<UpdateWorkspaceMemberRolePayload>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };
    let acting_role = match ensure_workspace_admin(&app_state, user_id, workspace_id).await {
        Ok(role) => role,
        Err(resp) => return resp,
    };

    let members = match app_state.workspace_repo.list_members(workspace_id).await {
        Ok(list) => list,
        Err(_) => return JsonResponse::server_error("Failed to list members").into_response(),
    };

    let current_member = match members.into_iter().find(|m| m.user_id == member_id) {
        Some(member) => member,
        None => return JsonResponse::not_found("Member not found").into_response(),
    };

    if payload.role == current_member.role {
        return Json(json!({"success": true})).into_response();
    }

    if current_member.role == WorkspaceRole::Owner && payload.role != WorkspaceRole::Owner {
        return JsonResponse::bad_request(
            "Transfer ownership to another member before changing this role",
        )
        .into_response();
    }

    if payload.role == WorkspaceRole::Owner {
        if acting_role != WorkspaceRole::Owner {
            return JsonResponse::forbidden("Only the current owner can transfer ownership")
                .into_response();
        }
        if member_id == user_id {
            return Json(json!({"success": true})).into_response();
        }

        if let Err(err) = app_state
            .workspace_repo
            .set_member_role(workspace_id, user_id, WorkspaceRole::Admin)
            .await
        {
            tracing::error!("failed to demote current owner before transfer: {:?}", err);
            return JsonResponse::server_error("Failed to transfer ownership").into_response();
        }

        match app_state
            .workspace_repo
            .set_member_role(workspace_id, member_id, WorkspaceRole::Owner)
            .await
        {
            Ok(_) => Json(json!({"success": true})).into_response(),
            Err(err) => {
                tracing::error!("failed to assign new workspace owner: {:?}", err);
                let _ = app_state
                    .workspace_repo
                    .set_member_role(workspace_id, user_id, WorkspaceRole::Owner)
                    .await;
                JsonResponse::server_error("Failed to transfer ownership").into_response()
            }
        }
    } else {
        match app_state
            .workspace_repo
            .set_member_role(workspace_id, member_id, payload.role)
            .await
        {
            Ok(_) => Json(json!({"success": true})).into_response(),
            Err(_) => JsonResponse::server_error("Failed to update role").into_response(),
        }
    }
}

pub async fn remove_workspace_member(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    axum::extract::Path((workspace_id, member_id)): axum::extract::Path<(Uuid, Uuid)>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };
    if let Err(resp) = require_workspace_admin(&app_state, user_id, workspace_id).await {
        return resp;
    }
    let members = match app_state.workspace_repo.list_members(workspace_id).await {
        Ok(list) => list,
        Err(_) => return JsonResponse::server_error("Failed to list members").into_response(),
    };
    let target_member = match members.into_iter().find(|m| m.user_id == member_id) {
        Some(member) => member,
        None => return JsonResponse::not_found("Member not found").into_response(),
    };
    if target_member.role == WorkspaceRole::Owner {
        return JsonResponse::bad_request(
            "Transfer ownership to another member before removing this user",
        )
        .into_response();
    }
    match app_state
        .workspace_repo
        .remove_member(workspace_id, member_id)
        .await
    {
        Ok(_) => {}
        Err(_) => return JsonResponse::server_error("Failed to remove member").into_response(),
    }

    if let Err(err) = app_state
        .workspace_oauth
        .purge_member_connections(workspace_id, member_id, user_id)
        .await
    {
        error!(
            ?err,
            %workspace_id,
            removed_user_id = %member_id,
            %user_id,
            "failed to purge workspace connections after member removal"
        );
        let _ = app_state
            .workspace_repo
            .add_member(workspace_id, member_id, target_member.role)
            .await;
        return JsonResponse::server_error("Failed to remove shared workspace connections")
            .into_response();
    }

    Json(json!({"success": true})).into_response()
}

pub async fn leave_workspace(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    axum::extract::Path(workspace_id): axum::extract::Path<Uuid>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    let (membership, memberships) =
        match load_membership_for_user(&app_state, user_id, workspace_id).await {
            Ok(data) => data,
            Err(response) => return response,
        };

    if membership.role == WorkspaceRole::Owner {
        return JsonResponse::bad_request("Transfer ownership before leaving this workspace")
            .into_response();
    }

    let should_provision_solo = memberships.len() == 1;

    if let Err(err) = app_state
        .workspace_repo
        .leave_workspace(workspace_id, user_id)
        .await
    {
        error!(?err, %workspace_id, %user_id, "failed to leave workspace");
        return JsonResponse::server_error("Failed to leave workspace").into_response();
    }

    if let Err(err) = app_state
        .workspace_oauth
        .purge_member_connections(workspace_id, user_id, user_id)
        .await
    {
        error!(
            ?err,
            %workspace_id,
            %user_id,
            "failed to purge workspace connections after leaving"
        );
        let _ = app_state
            .workspace_repo
            .add_member(workspace_id, user_id, membership.role)
            .await;
        return JsonResponse::server_error("Failed to remove shared workspace connections")
            .into_response();
    }

    if should_provision_solo {
        if let Err(err) = ensure_solo_workspace_for_user(&app_state, user_id).await {
            error!(?err, %user_id, %workspace_id, "failed to provision solo workspace after leaving");
            let _ = app_state
                .workspace_repo
                .add_member(workspace_id, user_id, membership.role)
                .await;
            return JsonResponse::server_error("Failed to provision Solo workspace")
                .into_response();
        }
    }

    Json(json!({"success": true})).into_response()
}

#[derive(Debug, Deserialize)]
pub struct RevokeWorkspaceMemberPayload {
    pub member_id: Uuid,
    pub reason: Option<String>,
}

pub async fn revoke_workspace_member(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    axum::extract::Path(workspace_id): axum::extract::Path<Uuid>,
    Json(payload): Json<RevokeWorkspaceMemberPayload>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    if let Err(resp) = require_workspace_admin(&app_state, user_id, workspace_id).await {
        return resp;
    }

    let workspace = match app_state.workspace_repo.find_workspace(workspace_id).await {
        Ok(Some(ws)) => ws,
        Ok(None) => return JsonResponse::not_found("Workspace not found").into_response(),
        Err(err) => {
            error!(?err, %workspace_id, "failed to load workspace during revocation");
            return JsonResponse::server_error("Failed to load workspace").into_response();
        }
    };

    let members = match app_state.workspace_repo.list_members(workspace_id).await {
        Ok(list) => list,
        Err(err) => {
            error!(?err, %workspace_id, "failed to list workspace members");
            return JsonResponse::server_error("Failed to list members").into_response();
        }
    };

    let target_member = match members
        .into_iter()
        .find(|member| member.user_id == payload.member_id)
    {
        Some(member) => member,
        None => return JsonResponse::not_found("Member not found").into_response(),
    };

    if target_member.role == WorkspaceRole::Owner {
        return JsonResponse::bad_request(
            "Transfer ownership to another member before revoking this user",
        )
        .into_response();
    }

    let memberships = match app_state
        .workspace_repo
        .list_user_workspaces(payload.member_id)
        .await
    {
        Ok(list) => list,
        Err(err) => {
            error!(?err, member_id = %payload.member_id, "failed to load member memberships");
            return JsonResponse::server_error("Failed to revoke member").into_response();
        }
    };

    let should_provision_solo = memberships.len() == 1;

    let reason_clean = payload
        .reason
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());

    match app_state
        .workspace_repo
        .revoke_member(
            workspace_id,
            payload.member_id,
            user_id,
            reason_clean.as_deref(),
        )
        .await
    {
        Ok(_) => {}
        Err(sqlx::Error::RowNotFound) => {
            return JsonResponse::not_found("Member not found").into_response();
        }
        Err(err) => {
            error!(?err, %workspace_id, member_id = %payload.member_id, "failed to revoke member");
            return JsonResponse::server_error("Failed to revoke member").into_response();
        }
    }

    if let Err(err) = app_state
        .workspace_oauth
        .purge_member_connections(workspace_id, payload.member_id, user_id)
        .await
    {
        error!(
            ?err,
            %workspace_id,
            member_id = %payload.member_id,
            %user_id,
            "failed to purge workspace connections after revocation"
        );
        let _ = app_state
            .workspace_repo
            .add_member(workspace_id, payload.member_id, target_member.role)
            .await;
        return JsonResponse::server_error("Failed to remove shared workspace connections")
            .into_response();
    }

    if should_provision_solo {
        if let Err(err) = ensure_solo_workspace_for_user(&app_state, payload.member_id).await {
            error!(?err, member_id = %payload.member_id, %workspace_id, "failed to provision solo workspace after revocation");
            let _ = app_state
                .workspace_repo
                .add_member(workspace_id, payload.member_id, target_member.role)
                .await;
            return JsonResponse::server_error("Failed to provision Solo workspace")
                .into_response();
        }
    }

    let subject = format!("Removed from {}", workspace.name);
    let mut body = format!(
        "You have been removed from the {} workspace on DSentr.",
        workspace.name
    );

    if let Some(reason) = reason_clean.as_deref() {
        body.push_str("\n\nReason provided: ");
        body.push_str(reason);
    }

    if should_provision_solo {
        body.push_str(
            "\n\nWe've provisioned a personal Solo workspace so you can continue building automations.",
        );
    }

    if !claims.first_name.trim().is_empty() || !claims.last_name.trim().is_empty() {
        body.push_str("\n\nInitiated by: ");
        body.push_str(claims.first_name.trim());
        let last = claims.last_name.trim();
        if !last.is_empty() {
            if !claims.first_name.trim().is_empty() {
                body.push(' ');
            }
            body.push_str(last);
        }
    }

    if let Err(err) = app_state
        .mailer
        .send_email_generic(&target_member.email, &subject, &body)
        .await
    {
        warn!(
            ?err,
            member_email = target_member.email,
            "failed to send revocation email"
        );
    }

    Json(json!({"success": true})).into_response()
}

// --- Email-based invitations ---

#[derive(Debug, Deserialize)]
pub struct CreateInvitationPayload {
    pub email: String,
    pub role: WorkspaceRole,
    #[serde(default)]
    pub expires_in_days: Option<i32>,
}

fn random_token() -> String {
    Uuid::new_v4().to_string().replace('-', "")
}

fn build_invite_accept_url(frontend_origin: &str, token: &str, has_account: bool) -> String {
    let path = if has_account { "login" } else { "signup" };
    format!("{}/{}?invite={}", frontend_origin, path, encode(token))
}

#[derive(Debug, Serialize, Clone)]
struct WorkspaceInvitationPreview {
    #[serde(flatten)]
    invitation: WorkspaceInvitation,
    workspace_name: Option<String>,
}

pub async fn create_workspace_invitation(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    axum::extract::Path(workspace_id): axum::extract::Path<Uuid>,
    Json(payload): Json<CreateInvitationPayload>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };
    let acting_role = match ensure_workspace_admin(&app_state, user_id, workspace_id).await {
        Ok(role) => role,
        Err(resp) => return resp,
    };

    if payload.role == WorkspaceRole::Owner {
        if acting_role != WorkspaceRole::Owner {
            return JsonResponse::forbidden(
                "Only the current owner can initiate ownership transfers",
            )
            .into_response();
        }
        return JsonResponse::bad_request(
            "Invite members as admin, user, or viewer and transfer ownership after they join",
        )
        .into_response();
    }

    let email = payload.email.trim();
    if email.is_empty() {
        return JsonResponse::bad_request("Email is required").into_response();
    }

    if let Err(err) = app_state
        .ensure_workspace_can_add_members(workspace_id, 1)
        .await
    {
        return workspace_limit_error_response(err);
    }
    let expires_days = payload.expires_in_days.unwrap_or(14).clamp(1, 60);
    let expires_at = OffsetDateTime::now_utc() + time::Duration::days(expires_days.into());

    let token = random_token();
    let invited_user_has_account = match app_state.db.find_user_id_by_email(email).await {
        Ok(Some(_)) => true,
        Ok(None) => false,
        Err(err) => {
            warn!(
                ?err,
                email, "failed to check if invited email already has an account"
            );
            false
        }
    };
    let invite = match app_state
        .workspace_repo
        .create_workspace_invitation(
            workspace_id,
            email,
            payload.role,
            &token,
            expires_at,
            user_id,
        )
        .await
    {
        Ok(inv) => inv,
        Err(err) => {
            tracing::error!(?err, "failed to create invitation");
            return JsonResponse::server_error("Failed to create invitation").into_response();
        }
    };

    // Send email with invite link
    let frontend = &app_state.config.frontend_origin;
    let accept_url = build_invite_accept_url(frontend, &invite.token, invited_user_has_account);
    // Try to use the workspace name in the subject; fall back to UUID if unavailable
    let workspace_name = match app_state.workspace_repo.find_workspace(workspace_id).await {
        Ok(Some(ws)) => ws.name,
        _ => workspace_id.to_string(),
    };
    let subject = format!("You're invited to join {} on DSentr", workspace_name);
    let body = format!(
        "You've been invited to join a workspace on DSentr.\n\nOpen this link to accept:\n<{}>\n\nThis link expires in {} days.",
        accept_url, expires_days
    );
    if let Err(err) = app_state
        .mailer
        .send_email_generic(email, &subject, &body)
        .await
    {
        tracing::warn!(?err, "failed to send invitation email");
    }

    Json(json!({"success": true, "invitation": invite})).into_response()
}

pub async fn list_workspace_invitations(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    axum::extract::Path(workspace_id): axum::extract::Path<Uuid>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };
    if let Err(resp) = require_workspace_admin(&app_state, user_id, workspace_id).await {
        return resp;
    }
    match app_state
        .workspace_repo
        .list_workspace_invitations(workspace_id)
        .await
    {
        Ok(list) => Json(json!({"success": true, "invitations": list})).into_response(),
        Err(_) => JsonResponse::server_error("Failed to list invitations").into_response(),
    }
}

pub async fn revoke_workspace_invitation(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    axum::extract::Path((workspace_id, invite_id)): axum::extract::Path<(Uuid, Uuid)>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };
    if let Err(resp) = require_workspace_admin(&app_state, user_id, workspace_id).await {
        return resp;
    }
    match app_state
        .workspace_repo
        .revoke_workspace_invitation(invite_id)
        .await
    {
        Ok(_) => Json(json!({"success": true})).into_response(),
        Err(_) => JsonResponse::server_error("Failed to revoke invitation").into_response(),
    }
}

// Public: preview invite
pub async fn preview_invitation(
    State(app_state): State<AppState>,
    axum::extract::Path(token): axum::extract::Path<String>,
) -> Response {
    match app_state
        .workspace_repo
        .find_invitation_by_token(&token)
        .await
    {
        Ok(Some(inv)) => {
            let now = OffsetDateTime::now_utc();
            let expired = inv.expires_at <= now;
            let revoked = inv.revoked_at.is_some();
            let accepted = inv.accepted_at.is_some();
            let declined = inv.declined_at.is_some();
            let workspace_name = match app_state
                .workspace_repo
                .find_workspace(inv.workspace_id)
                .await
            {
                Ok(Some(workspace)) => Some(workspace.name),
                Ok(None) => None,
                Err(err) => {
                    warn!(
                        ?err,
                        workspace_id = %inv.workspace_id,
                        "failed to load workspace name for invitation preview"
                    );
                    None
                }
            };
            let response_payload = WorkspaceInvitationPreview {
                invitation: inv,
                workspace_name,
            };
            Json(json!({
                "success": true,
                "invitation": response_payload,
                "expired": expired,
                "revoked": revoked,
                "accepted": accepted,
                "declined": declined,
            }))
            .into_response()
        }
        Ok(None) => JsonResponse::not_found("Invalid or expired token").into_response(),
        Err(_) => JsonResponse::server_error("Failed to lookup invite").into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct InvitationDecisionPayload {
    pub token: String,
}

async fn load_active_invitation(
    app_state: &AppState,
    token: &str,
) -> Result<crate::models::workspace::WorkspaceInvitation, Response> {
    let invite = match app_state
        .workspace_repo
        .find_invitation_by_token(token)
        .await
    {
        Ok(Some(invite)) => invite,
        Ok(None) => return Err(JsonResponse::not_found("Invite not found").into_response()),
        Err(_) => return Err(JsonResponse::server_error("Failed to load invite").into_response()),
    };

    let now = OffsetDateTime::now_utc();
    if invite.status != INVITATION_STATUS_PENDING
        || invite.revoked_at.is_some()
        || invite.accepted_at.is_some()
        || invite.declined_at.is_some()
        || invite.expires_at <= now
    {
        return Err(JsonResponse::bad_request("Invitation is not valid").into_response());
    }

    Ok(invite)
}

// Authenticated: accept invite
pub async fn accept_invitation(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Json(payload): Json<InvitationDecisionPayload>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    let invite = match load_active_invitation(&app_state, payload.token.trim()).await {
        Ok(invite) => invite,
        Err(resp) => return resp,
    };

    if !invite.email.eq_ignore_ascii_case(&claims.email) {
        return JsonResponse::forbidden("Invitation email mismatch").into_response();
    }

    if let Err(err) = app_state
        .ensure_workspace_can_add_members(invite.workspace_id, 0)
        .await
    {
        return workspace_limit_error_response(err);
    }

    if let Err(err) = app_state
        .workspace_repo
        .add_member(invite.workspace_id, user_id, invite.role)
        .await
    {
        tracing::error!(?err, invite_id = %invite.id, "failed to add invited member");
        return JsonResponse::server_error("Failed to attach workspace membership").into_response();
    }

    if let Err(err) = app_state
        .workspace_repo
        .mark_invitation_accepted(invite.id)
        .await
    {
        tracing::error!(?err, invite_id = %invite.id, "failed to mark invite accepted");
        return JsonResponse::server_error("Failed to update invitation").into_response();
    }

    Json(json!({
        "success": true,
        "workspace_id": invite.workspace_id,
    }))
    .into_response()
}

// Authenticated: decline invite
pub async fn decline_invitation(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Json(payload): Json<InvitationDecisionPayload>,
) -> Response {
    let invite = match load_active_invitation(&app_state, payload.token.trim()).await {
        Ok(invite) => invite,
        Err(resp) => return resp,
    };

    if !invite.email.eq_ignore_ascii_case(&claims.email) {
        return JsonResponse::forbidden("Invitation email mismatch").into_response();
    }

    if let Err(err) = app_state
        .workspace_repo
        .mark_invitation_declined(invite.id)
        .await
    {
        tracing::error!(?err, invite_id = %invite.id, "failed to mark invite declined");
        return JsonResponse::server_error("Failed to update invitation").into_response();
    }

    Json(json!({
        "success": true,
        "message": "Invite declined",
    }))
    .into_response()
}

// Workspace -> Solo downgrade

#[derive(Debug, Deserialize)]
pub struct WorkspaceToSoloPreviewPayload {
    pub workspace_id: Uuid,
}

pub async fn workspace_to_solo_preview(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Json(payload): Json<WorkspaceToSoloPreviewPayload>,
) -> Response {
    let acting = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };
    if let Err(resp) = ensure_workspace_owner(&app_state, acting, payload.workspace_id).await {
        return resp;
    }
    match app_state
        .workspace_repo
        .list_members(payload.workspace_id)
        .await
    {
        Ok(members) => {
            let to_disable: Vec<Uuid> = members
                .into_iter()
                .filter(|m| m.user_id != acting)
                .map(|m| m.user_id)
                .collect();
            Json(json!({"success": true, "will_disable_users": to_disable})).into_response()
        }
        Err(_) => JsonResponse::server_error("Failed to list members").into_response(),
    }
}

#[derive(Debug, Deserialize)]
pub struct WorkspaceToSoloExecutePayload {
    pub workspace_id: Uuid,
}

pub async fn workspace_to_solo_execute(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Json(payload): Json<WorkspaceToSoloExecutePayload>,
) -> Response {
    let acting = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };
    if let Err(resp) = ensure_workspace_owner(&app_state, acting, payload.workspace_id).await {
        return resp;
    }
    let members = match app_state
        .workspace_repo
        .list_members(payload.workspace_id)
        .await
    {
        Ok(list) => list,
        Err(err) => {
            error!(
                ?err,
                workspace_id = %payload.workspace_id,
                "failed to list members before solo conversion"
            );
            return JsonResponse::server_error("Failed to list members").into_response();
        }
    };

    for member in members {
        if member.user_id == acting {
            continue;
        }

        if let Err(err) = app_state
            .workspace_repo
            .remove_member(payload.workspace_id, member.user_id)
            .await
        {
            error!(
                ?err,
                workspace_id = %payload.workspace_id,
                member_id = %member.user_id,
                "failed to remove member during solo conversion"
            );
            return JsonResponse::server_error("Failed to remove member").into_response();
        }

        if let Err(err) = app_state
            .workspace_oauth
            .purge_member_connections(payload.workspace_id, member.user_id, acting)
            .await
        {
            error!(
                ?err,
                workspace_id = %payload.workspace_id,
                member_id = %member.user_id,
                %acting,
                "failed to purge workspace connections during solo conversion"
            );
            let _ = app_state
                .workspace_repo
                .add_member(payload.workspace_id, member.user_id, member.role)
                .await;
            return JsonResponse::server_error("Failed to remove shared workspace connections")
                .into_response();
        }
    }

    let _ = app_state
        .db
        .update_user_plan(acting, PlanTier::Solo.as_str())
        .await;
    Json(json!({"success": true})).into_response()
}

pub async fn promote_workspace_connection(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path(workspace_id): Path<Uuid>,
    Json(payload): Json<PromoteWorkspaceConnectionPayload>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    if let Err(response) = require_workspace_admin(&app_state, user_id, workspace_id).await {
        return response;
    }

    match app_state
        .workspace_oauth
        .promote_connection_with_token(
            workspace_id,
            user_id,
            payload.provider,
            Some(payload.user_oauth_token_id),
        )
        .await
    {
        Ok(connection) => Json(json!({
            "success": true,
            "workspace_connection_id": connection.id,
            "created_by": connection.created_by,
        }))
        .into_response(),
        Err(WorkspaceOAuthError::SlackInstallRequired) => {
            JsonResponse::bad_request("Slack connections must be installed at workspace scope")
                .into_response()
        }
        Err(WorkspaceOAuthError::Forbidden) => {
            JsonResponse::forbidden("OAuth token is not owned by the current user").into_response()
        }
        Err(WorkspaceOAuthError::NotFound) => {
            JsonResponse::not_found("OAuth token not found for current user").into_response()
        }
        Err(err) => {
            error!(
                ?err,
                %workspace_id,
                %user_id,
                "failed to promote workspace connection"
            );
            JsonResponse::server_error("Failed to promote workspace connection").into_response()
        }
    }
}

pub async fn remove_workspace_connection(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path((workspace_id, connection_id)): Path<(Uuid, Uuid)>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    if let Err(response) = require_workspace_admin(&app_state, user_id, workspace_id).await {
        return response;
    }

    match app_state
        .workspace_oauth
        .remove_connection(workspace_id, user_id, connection_id)
        .await
    {
        Ok(()) => JsonResponse::success("Workspace connection removed").into_response(),
        Err(WorkspaceOAuthError::Forbidden) => JsonResponse::forbidden(
            "Workspace connections can only be removed by the user who originally shared the credential",
        )
        .into_response(),
        Err(WorkspaceOAuthError::NotFound) => {
            JsonResponse::not_found("Workspace connection not found").into_response()
        }
        Err(err) => {
            error!(
                ?err,
                %workspace_id,
                %connection_id,
                %user_id,
                "failed to remove workspace connection"
            );
            JsonResponse::server_error("Failed to remove workspace connection").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        accept_invitation, build_invite_accept_url, change_plan, complete_onboarding,
        create_workspace_invitation, decline_invitation, leave_workspace, list_pending_invites,
        preview_invitation, promote_workspace_connection, remove_workspace_connection,
        remove_workspace_member, revoke_workspace_member, workspace_to_solo_execute,
        CompleteOnboardingPayload, CreateInvitationPayload, InvitationDecisionPayload,
        PromoteWorkspaceConnectionPayload, RevokeWorkspaceMemberPayload,
        WorkspaceToSoloExecutePayload,
    };
    use crate::config::{Config, OAuthProviderConfig, OAuthSettings, StripeSettings};
    use crate::db::{
        mock_db::{MockDb, NoopWorkflowRepository},
        mock_stripe_event_log_repository::MockStripeEventLogRepository,
        oauth_token_repository::{NewUserOAuthToken, UserOAuthTokenRepository},
        workspace_connection_repository::{
            NewWorkspaceAuditEvent, NewWorkspaceConnection, NoopWorkspaceConnectionRepository,
            StaleWorkspaceConnection, WorkspaceConnectionListing, WorkspaceConnectionRepository,
        },
        workspace_repository::{WorkspaceRepository, WorkspaceRunQuotaUpdate, WorkspaceRunUsage},
    };
    use crate::models::{
        oauth_token::{
            ConnectedOAuthProvider, UserOAuthToken, WorkspaceAuditEvent, WorkspaceConnection,
            WORKSPACE_AUDIT_EVENT_CONNECTION_PROMOTED, WORKSPACE_AUDIT_EVENT_CONNECTION_UNSHARED,
        },
        plan::PlanTier,
        user::{OauthProvider, User, UserRole},
        workspace::{
            Workspace, WorkspaceBillingCycle, WorkspaceInvitation, WorkspaceMember,
            WorkspaceMembershipSummary, WorkspaceRole,
        },
    };
    use crate::routes::auth::{
        claims::{Claims, TokenUse},
        session::AuthSession,
    };
    use crate::services::{
        oauth::{
            account_service::OAuthAccountService,
            github::mock_github_oauth::MockGitHubOAuth,
            google::mock_google_oauth::MockGoogleOAuth,
            workspace_service::{WorkspaceOAuthService, WorkspaceTokenRefresher},
        },
        smtp_mailer::{MailError, Mailer, MockMailer, SmtpConfig},
    };
    use crate::state::{test_pg_pool, AppState};
    use crate::utils::{encryption::encrypt_secret, jwt::JwtKeys, plan_limits::NormalizedPlanTier};
    use async_trait::async_trait;
    use axum::{
        body::to_bytes,
        extract::{Path, State},
        http::StatusCode,
        Json,
    };
    use reqwest::Client;
    use serde_json::Value;
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };
    use time::OffsetDateTime;
    use uuid::Uuid;

    type MemberRecord = (Uuid, Uuid, WorkspaceRole);
    type MembershipSnapshot = (Vec<MemberRecord>, Vec<Uuid>, Vec<Uuid>);
    type AuditEntries = Vec<(Uuid, Uuid, String, Uuid, Option<String>)>;

    #[derive(Default)]
    struct NoopMailer;

    #[async_trait]
    impl Mailer for NoopMailer {
        async fn send_verification_email(&self, _: &str, _: &str) -> Result<(), MailError> {
            Ok(())
        }

        async fn send_reset_email(&self, _: &str, _: &str) -> Result<(), MailError> {
            Ok(())
        }

        async fn send_email_generic(&self, _: &str, _: &str, _: &str) -> Result<(), MailError> {
            Ok(())
        }

        async fn send_email_with_config(
            &self,
            _: &SmtpConfig,
            _: &[String],
            _: &str,
            _: &str,
        ) -> Result<(), MailError> {
            Ok(())
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[derive(Default, Clone)]
    struct RecordingMailer {
        sent: Arc<Mutex<Vec<(String, String, String)>>>,
    }

    impl RecordingMailer {
        fn new() -> Self {
            Self::default()
        }

        fn sent(&self) -> Vec<(String, String, String)> {
            self.sent.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl Mailer for RecordingMailer {
        async fn send_verification_email(&self, _: &str, _: &str) -> Result<(), MailError> {
            Ok(())
        }

        async fn send_reset_email(&self, _: &str, _: &str) -> Result<(), MailError> {
            Ok(())
        }

        async fn send_email_generic(
            &self,
            to: &str,
            subject: &str,
            body: &str,
        ) -> Result<(), MailError> {
            self.sent
                .lock()
                .unwrap()
                .push((to.to_string(), subject.to_string(), body.to_string()));
            Ok(())
        }

        async fn send_email_with_config(
            &self,
            _: &SmtpConfig,
            _: &[String],
            _: &str,
            _: &str,
        ) -> Result<(), MailError> {
            Ok(())
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[derive(Clone, Default)]
    struct StubUserTokenRepo {
        tokens: Arc<Mutex<HashMap<ConnectedOAuthProvider, UserOAuthToken>>>,
        marks: Arc<Mutex<Vec<(Uuid, ConnectedOAuthProvider, bool)>>>,
    }

    impl StubUserTokenRepo {
        fn with_token(token: UserOAuthToken) -> Self {
            let mut map = HashMap::new();
            map.insert(token.provider, token);
            Self {
                tokens: Arc::new(Mutex::new(map)),
                marks: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn without_tokens() -> Self {
            Self::default()
        }

        fn marks(&self) -> Vec<(Uuid, ConnectedOAuthProvider, bool)> {
            self.marks.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl UserOAuthTokenRepository for StubUserTokenRepo {
        async fn upsert_token(
            &self,
            _new_token: NewUserOAuthToken,
        ) -> Result<UserOAuthToken, sqlx::Error> {
            Err(sqlx::Error::RowNotFound)
        }

        async fn find_by_id(&self, token_id: Uuid) -> Result<Option<UserOAuthToken>, sqlx::Error> {
            let guard = self.tokens.lock().unwrap();
            Ok(guard.values().find(|token| token.id == token_id).cloned())
        }

        async fn find_by_user_and_provider(
            &self,
            user_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<Option<UserOAuthToken>, sqlx::Error> {
            let guard = self.tokens.lock().unwrap();
            Ok(guard
                .get(&provider)
                .cloned()
                .filter(|token| token.user_id == user_id))
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
            let guard = self.tokens.lock().unwrap();
            Ok(guard
                .values()
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
            self.marks
                .lock()
                .unwrap()
                .push((user_id, provider, is_shared));

            let mut guard = self.tokens.lock().unwrap();
            if let Some(token) = guard.get_mut(&provider) {
                if token.user_id == user_id {
                    token.is_shared = is_shared;
                    return Ok(token.clone());
                }
            }

            Err(sqlx::Error::RowNotFound)
        }

        async fn list_by_user_and_provider(
            &self,
            user_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<Vec<UserOAuthToken>, sqlx::Error> {
            let guard = self.tokens.lock().unwrap();
            Ok(guard
                .values()
                .filter(|token| token.user_id == user_id && token.provider == provider)
                .cloned()
                .collect())
        }
    }

    #[derive(Clone, Default)]
    struct CapturingWorkspaceConnectionRepo {
        connections: Arc<Mutex<Vec<WorkspaceConnection>>>,
        audits: Arc<Mutex<Vec<WorkspaceAuditEvent>>>,
        deleted: Arc<Mutex<Vec<Uuid>>>,
    }

    impl CapturingWorkspaceConnectionRepo {
        fn new() -> Self {
            Self::default()
        }

        fn with_connections(connections: Vec<WorkspaceConnection>) -> Self {
            Self {
                connections: Arc::new(Mutex::new(connections)),
                ..Self::default()
            }
        }

        fn connections(&self) -> Vec<WorkspaceConnection> {
            self.connections.lock().unwrap().clone()
        }

        fn audits(&self) -> Vec<WorkspaceAuditEvent> {
            self.audits.lock().unwrap().clone()
        }

        fn deleted(&self) -> Vec<Uuid> {
            self.deleted.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl WorkspaceConnectionRepository for CapturingWorkspaceConnectionRepo {
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
                metadata: serde_json::Value::Null,
                bot_user_id: None,
                incoming_webhook_url: None,
                slack_team_id: new_connection.slack_team_id,
            };

            self.connections.lock().unwrap().push(record.clone());
            Ok(record)
        }

        async fn find_by_id(
            &self,
            connection_id: Uuid,
        ) -> Result<Option<WorkspaceConnection>, sqlx::Error> {
            let guard = self.connections.lock().unwrap();
            Ok(guard
                .iter()
                .find(|record| record.id == connection_id)
                .cloned())
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
                .filter(|record| record.workspace_id == workspace_id && record.provider == provider)
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
                .filter(|record| record.user_oauth_token_id == Some(user_oauth_token_id))
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
            workspace_id: Uuid,
        ) -> Result<Vec<WorkspaceConnectionListing>, sqlx::Error> {
            let guard = self.connections.lock().unwrap();
            Ok(guard
                .iter()
                .filter(|record| record.workspace_id == workspace_id)
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
            let guard = self.connections.lock().unwrap();
            Ok(guard
                .iter()
                .filter(|record| record.owner_user_id == user_id)
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
            let guard = self.connections.lock().unwrap();
            Ok(guard
                .iter()
                .filter(|record| {
                    record.workspace_id == workspace_id && record.owner_user_id == creator_id
                })
                .cloned()
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
            let mut guard = self.connections.lock().unwrap();
            for record in guard.iter_mut() {
                if record.owner_user_id == creator_id && record.provider == provider {
                    record.access_token = access_token.clone();
                    record.refresh_token = refresh_token.clone();
                    record.expires_at = expires_at;
                    record.account_email = account_email.clone();
                    if bot_user_id.is_some() {
                        record.bot_user_id = bot_user_id.clone();
                    }
                    if slack_team_id.is_some() {
                        record.slack_team_id = slack_team_id.clone();
                    }
                    if incoming_webhook_url.is_some() {
                        record.incoming_webhook_url = incoming_webhook_url.clone();
                    }
                    record.updated_at = OffsetDateTime::now_utc();
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
            let mut guard = self.connections.lock().unwrap();
            if let Some(existing) = guard.iter_mut().find(|record| record.id == connection_id) {
                existing.access_token = access_token;
                existing.refresh_token = refresh_token;
                existing.expires_at = expires_at;
                existing.account_email = account_email;
                if bot_user_id.is_some() {
                    existing.bot_user_id = bot_user_id;
                }
                if slack_team_id.is_some() {
                    existing.slack_team_id = slack_team_id;
                }
                if incoming_webhook_url.is_some() {
                    existing.incoming_webhook_url = incoming_webhook_url;
                }
                existing.updated_at = OffsetDateTime::now_utc();
                return Ok(existing.clone());
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
            let mut guard = self.connections.lock().unwrap();
            if let Some(existing) = guard.iter_mut().find(|record| record.id == connection_id) {
                existing.access_token = access_token;
                existing.refresh_token = refresh_token;
                existing.expires_at = expires_at;
                if bot_user_id.is_some() {
                    existing.bot_user_id = bot_user_id;
                }
                if slack_team_id.is_some() {
                    existing.slack_team_id = slack_team_id;
                }
                if incoming_webhook_url.is_some() {
                    existing.incoming_webhook_url = incoming_webhook_url;
                }
                existing.updated_at = OffsetDateTime::now_utc();
                return Ok(existing.clone());
            }

            Err(sqlx::Error::RowNotFound)
        }

        async fn update_metadata(
            &self,
            connection_id: Uuid,
            metadata: serde_json::Value,
        ) -> Result<WorkspaceConnection, sqlx::Error> {
            let mut guard = self.connections.lock().unwrap();
            if let Some(existing) = guard.iter_mut().find(|record| record.id == connection_id) {
                existing.metadata = metadata;
                existing.updated_at = OffsetDateTime::now_utc();
                return Ok(existing.clone());
            }

            Err(sqlx::Error::RowNotFound)
        }

        async fn delete_connection(&self, connection_id: Uuid) -> Result<(), sqlx::Error> {
            {
                let mut guard = self.connections.lock().unwrap();
                guard.retain(|record| record.id != connection_id);
            }
            self.deleted.lock().unwrap().push(connection_id);
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
            let mut guard = self.connections.lock().unwrap();
            let mut deleted_ids = Vec::new();
            guard.retain(|record| {
                let should_remove = record.workspace_id == workspace_id
                    && record.owner_user_id == owner_user_id
                    && record.provider == provider;
                if should_remove {
                    deleted_ids.push(record.id);
                }
                !should_remove
            });
            if !deleted_ids.is_empty() {
                self.deleted.lock().unwrap().extend(deleted_ids);
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
            guard.retain(|record| {
                !(record.workspace_id == workspace_id
                    && record.owner_user_id == owner_user_id
                    && record.provider == provider
                    && record.id == connection_id)
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
                .any(|record| record.owner_user_id == owner_user_id && record.provider == provider))
        }

        async fn mark_connections_stale_for_creator(
            &self,
            creator_id: Uuid,
            provider: ConnectedOAuthProvider,
        ) -> Result<Vec<StaleWorkspaceConnection>, sqlx::Error> {
            let mut guard = self.connections.lock().unwrap();
            let mut affected = Vec::new();
            for record in guard.iter_mut() {
                if record.owner_user_id == creator_id && record.provider == provider {
                    record.expires_at = OffsetDateTime::now_utc() - time::Duration::minutes(5);
                    record.updated_at = OffsetDateTime::now_utc();
                    affected.push(StaleWorkspaceConnection {
                        connection_id: record.id,
                        workspace_id: record.workspace_id,
                    });
                }
            }
            Ok(affected)
        }

        async fn record_audit_event(
            &self,
            event: NewWorkspaceAuditEvent,
        ) -> Result<WorkspaceAuditEvent, sqlx::Error> {
            let audit = WorkspaceAuditEvent {
                id: Uuid::new_v4(),
                workspace_id: event.workspace_id,
                actor_id: event.actor_id,
                event_type: event.event_type,
                metadata: event.metadata,
                created_at: OffsetDateTime::now_utc(),
            };
            self.audits.lock().unwrap().push(audit.clone());
            Ok(audit)
        }
    }

    #[derive(Clone)]
    struct TestWorkspaceRepo {
        invitation: Arc<Mutex<Option<WorkspaceInvitation>>>,
        members: Arc<Mutex<Vec<MemberRecord>>>,
        accepted: Arc<Mutex<Vec<Uuid>>>,
        declined: Arc<Mutex<Vec<Uuid>>>,
        workspace: Arc<Mutex<Option<Workspace>>>,
        #[allow(clippy::type_complexity)]
        run_usage: Arc<Mutex<HashMap<(Uuid, i64), (i64, i64)>>>,
        billing_cycles: Arc<Mutex<HashMap<Uuid, WorkspaceBillingCycle>>>,
        overage_items: Arc<Mutex<HashMap<Uuid, Option<String>>>>,
    }

    impl TestWorkspaceRepo {
        fn new(invite: WorkspaceInvitation) -> Self {
            Self {
                invitation: Arc::new(Mutex::new(Some(invite))),
                members: Arc::new(Mutex::new(Vec::new())),
                accepted: Arc::new(Mutex::new(Vec::new())),
                declined: Arc::new(Mutex::new(Vec::new())),
                workspace: Arc::new(Mutex::new(None)),
                run_usage: Arc::new(Mutex::new(HashMap::new())),
                billing_cycles: Arc::new(Mutex::new(HashMap::new())),
                overage_items: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        fn with_workspace(invite: WorkspaceInvitation, workspace: Workspace) -> Self {
            let repo = Self::new(invite);
            repo.set_workspace(workspace);
            repo
        }

        fn records(&self) -> MembershipSnapshot {
            (
                self.members.lock().unwrap().clone(),
                self.accepted.lock().unwrap().clone(),
                self.declined.lock().unwrap().clone(),
            )
        }

        fn current_invitation(&self) -> Option<WorkspaceInvitation> {
            self.invitation.lock().unwrap().clone()
        }

        fn set_workspace(&self, workspace: Workspace) {
            *self.workspace.lock().unwrap() = Some(workspace);
        }
    }

    #[async_trait]
    impl WorkspaceRepository for TestWorkspaceRepo {
        async fn create_workspace(
            &self,
            _: &str,
            _: Uuid,
            _: &str,
        ) -> Result<crate::models::workspace::Workspace, sqlx::Error> {
            unimplemented!()
        }

        async fn update_workspace_name(
            &self,
            _: Uuid,
            _: &str,
        ) -> Result<crate::models::workspace::Workspace, sqlx::Error> {
            unimplemented!()
        }

        async fn update_workspace_plan(
            &self,
            workspace_id: Uuid,
            plan: &str,
        ) -> Result<crate::models::workspace::Workspace, sqlx::Error> {
            let mut stored = self.workspace.lock().unwrap();
            if let Some(ws) = stored.as_mut() {
                if ws.id == workspace_id {
                    ws.plan = plan.to_string();
                    ws.updated_at = OffsetDateTime::now_utc();
                    return Ok(ws.clone());
                }
            }
            Err(sqlx::Error::RowNotFound)
        }

        async fn get_plan(&self, workspace_id: Uuid) -> Result<PlanTier, sqlx::Error> {
            let stored = self.workspace.lock().unwrap();
            let workspace = stored.as_ref().filter(|ws| ws.id == workspace_id).cloned();

            if let Some(workspace) = workspace {
                let normalized = NormalizedPlanTier::from_option(Some(workspace.plan.as_str()));
                Ok(PlanTier::from(normalized))
            } else {
                Ok(PlanTier::Workspace)
            }
        }

        async fn find_workspace(
            &self,
            workspace_id: Uuid,
        ) -> Result<Option<crate::models::workspace::Workspace>, sqlx::Error> {
            let stored = self.workspace.lock().unwrap();
            Ok(stored.as_ref().filter(|ws| ws.id == workspace_id).cloned())
        }

        async fn set_stripe_overage_item_id(
            &self,
            workspace_id: Uuid,
            subscription_item_id: Option<&str>,
        ) -> Result<(), sqlx::Error> {
            self.overage_items
                .lock()
                .unwrap()
                .insert(workspace_id, subscription_item_id.map(|s| s.to_string()));
            Ok(())
        }

        async fn get_stripe_overage_item_id(
            &self,
            workspace_id: Uuid,
        ) -> Result<Option<String>, sqlx::Error> {
            Ok(self
                .overage_items
                .lock()
                .unwrap()
                .get(&workspace_id)
                .cloned()
                .flatten())
        }

        async fn add_member(
            &self,
            workspace_id: Uuid,
            user_id: Uuid,
            role: WorkspaceRole,
        ) -> Result<(), sqlx::Error> {
            self.members
                .lock()
                .unwrap()
                .push((workspace_id, user_id, role));
            Ok(())
        }

        async fn set_member_role(
            &self,
            _: Uuid,
            _: Uuid,
            _: WorkspaceRole,
        ) -> Result<(), sqlx::Error> {
            unimplemented!()
        }

        async fn remove_member(&self, _: Uuid, _: Uuid) -> Result<(), sqlx::Error> {
            unimplemented!()
        }

        async fn leave_workspace(&self, _: Uuid, _: Uuid) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn revoke_member(
            &self,
            _: Uuid,
            _: Uuid,
            _: Uuid,
            _: Option<&str>,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn list_members(
            &self,
            _: Uuid,
        ) -> Result<Vec<crate::models::workspace::WorkspaceMember>, sqlx::Error> {
            unimplemented!()
        }

        async fn count_members(&self, workspace_id: Uuid) -> Result<i64, sqlx::Error> {
            let members = self.members.lock().unwrap();
            let count = members
                .iter()
                .filter(|(ws_id, _, _)| *ws_id == workspace_id)
                .count();
            Ok(count as i64)
        }

        async fn count_pending_workspace_invitations(
            &self,
            workspace_id: Uuid,
        ) -> Result<i64, sqlx::Error> {
            let invite = self.invitation.lock().unwrap();
            let count = invite
                .as_ref()
                .filter(|invite| {
                    invite.workspace_id == workspace_id
                        && invite.status == crate::models::workspace::INVITATION_STATUS_PENDING
                        && invite.expires_at > OffsetDateTime::now_utc()
                })
                .map(|_| 1)
                .unwrap_or(0);
            Ok(count)
        }

        async fn is_member(&self, workspace_id: Uuid, user_id: Uuid) -> Result<bool, sqlx::Error> {
            let members = self.members.lock().unwrap();
            Ok(members
                .iter()
                .any(|(ws_id, member_id, _)| *ws_id == workspace_id && *member_id == user_id))
        }

        async fn list_memberships_for_user(
            &self,
            _: Uuid,
        ) -> Result<Vec<crate::models::workspace::WorkspaceMembershipSummary>, sqlx::Error>
        {
            unimplemented!()
        }

        async fn list_user_workspaces(
            &self,
            _: Uuid,
        ) -> Result<Vec<crate::models::workspace::WorkspaceMembershipSummary>, sqlx::Error>
        {
            Ok(vec![])
        }

        async fn create_workspace_invitation(
            &self,
            _: Uuid,
            _: &str,
            _: WorkspaceRole,
            _: &str,
            _: OffsetDateTime,
            _: Uuid,
        ) -> Result<WorkspaceInvitation, sqlx::Error> {
            unimplemented!()
        }

        async fn list_workspace_invitations(
            &self,
            _: Uuid,
        ) -> Result<Vec<WorkspaceInvitation>, sqlx::Error> {
            unimplemented!()
        }

        async fn revoke_workspace_invitation(&self, _: Uuid) -> Result<(), sqlx::Error> {
            unimplemented!()
        }

        async fn find_invitation_by_token(
            &self,
            token: &str,
        ) -> Result<Option<WorkspaceInvitation>, sqlx::Error> {
            let stored = self.invitation.lock().unwrap().clone();
            Ok(stored.filter(|inv| inv.token == token))
        }

        async fn mark_invitation_accepted(&self, invite_id: Uuid) -> Result<(), sqlx::Error> {
            self.accepted.lock().unwrap().push(invite_id);
            if let Some(invite) = self.invitation.lock().unwrap().as_mut() {
                invite.status = crate::models::workspace::INVITATION_STATUS_ACCEPTED.to_string();
                invite.accepted_at = Some(OffsetDateTime::now_utc());
            }
            Ok(())
        }

        async fn mark_invitation_declined(&self, invite_id: Uuid) -> Result<(), sqlx::Error> {
            self.declined.lock().unwrap().push(invite_id);
            if let Some(invite) = self.invitation.lock().unwrap().as_mut() {
                invite.status = crate::models::workspace::INVITATION_STATUS_DECLINED.to_string();
                invite.declined_at = Some(OffsetDateTime::now_utc());
            }
            Ok(())
        }

        async fn list_pending_invitations_for_email(
            &self,
            email: &str,
        ) -> Result<Vec<WorkspaceInvitation>, sqlx::Error> {
            Ok(self
                .invitation
                .lock()
                .unwrap()
                .clone()
                .into_iter()
                .filter(|invite| {
                    invite.email == email
                        && invite.status == crate::models::workspace::INVITATION_STATUS_PENDING
                })
                .collect())
        }

        async fn disable_webhook_signing_for_workspace(
            &self,
            _workspace_id: Uuid,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn try_increment_workspace_run_quota(
            &self,
            workspace_id: Uuid,
            period_start: OffsetDateTime,
            max_runs: i64,
        ) -> Result<WorkspaceRunQuotaUpdate, sqlx::Error> {
            let mut usage = self.run_usage.lock().unwrap();
            let key = (workspace_id, period_start.unix_timestamp());
            let entry = usage.entry(key).or_insert((0, 0));
            entry.0 += 1;
            let mut overage_incremented = false;
            if entry.0 > max_runs {
                entry.1 += 1;
                overage_incremented = true;
            }
            Ok(WorkspaceRunQuotaUpdate {
                allowed: entry.0 <= max_runs,
                run_count: entry.0,
                overage_count: entry.1,
                overage_incremented,
            })
        }

        async fn get_workspace_run_quota(
            &self,
            workspace_id: Uuid,
            period_start: OffsetDateTime,
        ) -> Result<WorkspaceRunUsage, sqlx::Error> {
            let usage = self.run_usage.lock().unwrap();
            let key = (workspace_id, period_start.unix_timestamp());
            Ok(usage
                .get(&key)
                .copied()
                .map(|(runs, overage)| WorkspaceRunUsage {
                    run_count: runs,
                    overage_count: overage,
                })
                .unwrap_or(WorkspaceRunUsage {
                    run_count: 0,
                    overage_count: 0,
                }))
        }

        async fn release_workspace_run_quota(
            &self,
            workspace_id: Uuid,
            period_start: OffsetDateTime,
            overage_decrement: bool,
        ) -> Result<(), sqlx::Error> {
            let mut usage = self.run_usage.lock().unwrap();
            let key = (workspace_id, period_start.unix_timestamp());
            if let Some(entry) = usage.get_mut(&key) {
                if entry.0 > 0 {
                    entry.0 -= 1;
                }
                if overage_decrement && entry.1 > 0 {
                    entry.1 -= 1;
                }
                if entry.0 == 0 && entry.1 == 0 {
                    usage.remove(&key);
                }
            }
            Ok(())
        }

        async fn upsert_workspace_billing_cycle(
            &self,
            workspace_id: Uuid,
            subscription_id: &str,
            period_start: OffsetDateTime,
            period_end: OffsetDateTime,
        ) -> Result<(), sqlx::Error> {
            self.billing_cycles.lock().unwrap().insert(
                workspace_id,
                WorkspaceBillingCycle {
                    workspace_id,
                    stripe_subscription_id: subscription_id.to_string(),
                    current_period_start: period_start,
                    current_period_end: period_end,
                    synced_at: OffsetDateTime::now_utc(),
                },
            );
            Ok(())
        }

        async fn clear_workspace_billing_cycle(
            &self,
            workspace_id: Uuid,
        ) -> Result<(), sqlx::Error> {
            self.billing_cycles.lock().unwrap().remove(&workspace_id);
            Ok(())
        }

        async fn get_workspace_billing_cycle(
            &self,
            workspace_id: Uuid,
        ) -> Result<Option<WorkspaceBillingCycle>, sqlx::Error> {
            Ok(self
                .billing_cycles
                .lock()
                .unwrap()
                .get(&workspace_id)
                .cloned())
        }
    }

    #[derive(Clone, Default)]
    struct RecordingWorkspaceRepo {
        workspaces: Arc<Mutex<HashMap<Uuid, Workspace>>>,
        members: Arc<Mutex<HashMap<Uuid, Vec<WorkspaceMember>>>>,
        audits: Arc<Mutex<AuditEntries>>,
        #[allow(clippy::type_complexity)]
        run_usage: Arc<Mutex<HashMap<(Uuid, i64), (i64, i64)>>>,
        billing_cycles: Arc<Mutex<HashMap<Uuid, WorkspaceBillingCycle>>>,
        pending_invites: Arc<Mutex<HashMap<Uuid, i64>>>,
    }

    impl RecordingWorkspaceRepo {
        fn seeded(workspace: Workspace, members: Vec<WorkspaceMember>) -> Self {
            let mut workspace_map = HashMap::new();
            workspace_map.insert(workspace.id, workspace);

            let mut member_map: HashMap<Uuid, Vec<WorkspaceMember>> = HashMap::new();
            for member in members {
                member_map
                    .entry(member.workspace_id)
                    .or_default()
                    .push(member);
            }

            Self {
                workspaces: Arc::new(Mutex::new(workspace_map)),
                members: Arc::new(Mutex::new(member_map)),
                audits: Arc::new(Mutex::new(Vec::new())),
                run_usage: Arc::new(Mutex::new(HashMap::new())),
                billing_cycles: Arc::new(Mutex::new(HashMap::new())),
                pending_invites: Arc::new(Mutex::new(HashMap::new())),
            }
        }

        fn audit_records(&self) -> Vec<(Uuid, Uuid, String, Uuid, Option<String>)> {
            self.audits.lock().unwrap().clone()
        }

        fn membership_count(&self, user_id: Uuid) -> usize {
            let members = self.members.lock().unwrap();
            members
                .values()
                .flat_map(|list| list.iter())
                .filter(|member| member.user_id == user_id)
                .count()
        }

        fn member_exists(&self, workspace_id: Uuid, user_id: Uuid) -> bool {
            self.members
                .lock()
                .unwrap()
                .get(&workspace_id)
                .map(|list| list.iter().any(|member| member.user_id == user_id))
                .unwrap_or(false)
        }

        #[allow(dead_code)]
        fn billing_cycle(&self, workspace_id: Uuid) -> Option<WorkspaceBillingCycle> {
            self.billing_cycles
                .lock()
                .unwrap()
                .get(&workspace_id)
                .cloned()
        }

        fn workspace_count(&self) -> usize {
            self.workspaces.lock().unwrap().len()
        }

        fn workspace_plan(&self, workspace_id: Uuid) -> Option<String> {
            self.workspaces
                .lock()
                .unwrap()
                .get(&workspace_id)
                .map(|workspace| workspace.plan.clone())
        }

        fn copy_member_profile(&self, user_id: Uuid) -> (String, String, String) {
            let members = self.members.lock().unwrap();
            members
                .values()
                .flat_map(|list| list.iter())
                .find(|member| member.user_id == user_id)
                .map(|member| {
                    (
                        member.email.clone(),
                        member.first_name.clone(),
                        member.last_name.clone(),
                    )
                })
                .unwrap_or_else(|| (String::new(), String::new(), String::new()))
        }

        fn delete_member(&self, workspace_id: Uuid, user_id: Uuid) -> bool {
            let mut members = self.members.lock().unwrap();
            if let Some(list) = members.get_mut(&workspace_id) {
                let before = list.len();
                list.retain(|member| member.user_id != user_id);
                return list.len() != before;
            }
            false
        }

        fn usage_key(workspace_id: Uuid, period_start: OffsetDateTime) -> (Uuid, i64) {
            (workspace_id, period_start.unix_timestamp())
        }

        fn set_pending_invites(&self, workspace_id: Uuid, count: i64) {
            self.pending_invites
                .lock()
                .unwrap()
                .insert(workspace_id, count);
        }
    }

    #[async_trait]
    impl WorkspaceRepository for RecordingWorkspaceRepo {
        async fn create_workspace(
            &self,
            name: &str,
            created_by: Uuid,
            plan: &str,
        ) -> Result<Workspace, sqlx::Error> {
            let workspace = Workspace {
                id: Uuid::new_v4(),
                name: name.to_string(),
                created_by,
                owner_id: created_by,
                plan: plan.to_string(),
                stripe_overage_item_id: None,
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                deleted_at: None,
            };
            self.workspaces
                .lock()
                .unwrap()
                .insert(workspace.id, workspace.clone());
            Ok(workspace)
        }

        async fn update_workspace_name(
            &self,
            workspace_id: Uuid,
            name: &str,
        ) -> Result<Workspace, sqlx::Error> {
            let mut workspaces = self.workspaces.lock().unwrap();
            if let Some(ws) = workspaces.get_mut(&workspace_id) {
                ws.name = name.to_string();
                ws.updated_at = OffsetDateTime::now_utc();
                return Ok(ws.clone());
            }
            Err(sqlx::Error::RowNotFound)
        }

        async fn update_workspace_plan(
            &self,
            workspace_id: Uuid,
            plan: &str,
        ) -> Result<Workspace, sqlx::Error> {
            let mut workspaces = self.workspaces.lock().unwrap();
            if let Some(ws) = workspaces.get_mut(&workspace_id) {
                ws.plan = plan.to_string();
                ws.updated_at = OffsetDateTime::now_utc();
                return Ok(ws.clone());
            }
            Err(sqlx::Error::RowNotFound)
        }

        async fn get_plan(&self, workspace_id: Uuid) -> Result<PlanTier, sqlx::Error> {
            let workspaces = self.workspaces.lock().unwrap();
            let workspace = workspaces
                .get(&workspace_id)
                .cloned()
                .ok_or(sqlx::Error::RowNotFound)?;
            let normalized = NormalizedPlanTier::from_option(Some(workspace.plan.as_str()));
            Ok(PlanTier::from(normalized))
        }

        async fn find_workspace(
            &self,
            workspace_id: Uuid,
        ) -> Result<Option<Workspace>, sqlx::Error> {
            Ok(self.workspaces.lock().unwrap().get(&workspace_id).cloned())
        }

        async fn set_stripe_overage_item_id(
            &self,
            workspace_id: Uuid,
            subscription_item_id: Option<&str>,
        ) -> Result<(), sqlx::Error> {
            if let Some(ws) = self.workspaces.lock().unwrap().get_mut(&workspace_id) {
                ws.stripe_overage_item_id = subscription_item_id.map(|s| s.to_string());
            }
            Ok(())
        }

        async fn get_stripe_overage_item_id(
            &self,
            workspace_id: Uuid,
        ) -> Result<Option<String>, sqlx::Error> {
            Ok(self
                .workspaces
                .lock()
                .unwrap()
                .get(&workspace_id)
                .and_then(|ws| ws.stripe_overage_item_id.clone()))
        }

        async fn add_member(
            &self,
            workspace_id: Uuid,
            user_id: Uuid,
            role: WorkspaceRole,
        ) -> Result<(), sqlx::Error> {
            let (email, first_name, last_name) = self.copy_member_profile(user_id);
            let mut members = self.members.lock().unwrap();
            let entry = members.entry(workspace_id).or_default();
            entry.retain(|member| member.user_id != user_id);
            entry.push(WorkspaceMember {
                workspace_id,
                user_id,
                role,
                joined_at: OffsetDateTime::now_utc(),
                email,
                first_name,
                last_name,
            });
            Ok(())
        }

        async fn set_member_role(
            &self,
            workspace_id: Uuid,
            user_id: Uuid,
            role: WorkspaceRole,
        ) -> Result<(), sqlx::Error> {
            let mut members = self.members.lock().unwrap();
            if let Some(list) = members.get_mut(&workspace_id) {
                if let Some(member) = list.iter_mut().find(|member| member.user_id == user_id) {
                    member.role = role;
                    if role == WorkspaceRole::Owner {
                        if let Some(workspace) =
                            self.workspaces.lock().unwrap().get_mut(&workspace_id)
                        {
                            workspace.owner_id = user_id;
                            workspace.updated_at = OffsetDateTime::now_utc();
                        }
                    }
                    return Ok(());
                }
            }
            Err(sqlx::Error::RowNotFound)
        }

        async fn remove_member(
            &self,
            workspace_id: Uuid,
            user_id: Uuid,
        ) -> Result<(), sqlx::Error> {
            if self.delete_member(workspace_id, user_id) {
                Ok(())
            } else {
                Err(sqlx::Error::RowNotFound)
            }
        }

        async fn leave_workspace(
            &self,
            workspace_id: Uuid,
            user_id: Uuid,
        ) -> Result<(), sqlx::Error> {
            self.remove_member(workspace_id, user_id).await
        }

        async fn revoke_member(
            &self,
            workspace_id: Uuid,
            member_id: Uuid,
            revoked_by: Uuid,
            reason: Option<&str>,
        ) -> Result<(), sqlx::Error> {
            if self.delete_member(workspace_id, member_id) {
                self.audits.lock().unwrap().push((
                    workspace_id,
                    member_id,
                    "revoked".to_string(),
                    revoked_by,
                    reason.map(|value| value.to_string()),
                ));
                Ok(())
            } else {
                Err(sqlx::Error::RowNotFound)
            }
        }

        async fn list_members(
            &self,
            workspace_id: Uuid,
        ) -> Result<Vec<WorkspaceMember>, sqlx::Error> {
            Ok(self
                .members
                .lock()
                .unwrap()
                .get(&workspace_id)
                .cloned()
                .unwrap_or_default())
        }

        async fn count_members(&self, workspace_id: Uuid) -> Result<i64, sqlx::Error> {
            let count = self
                .members
                .lock()
                .unwrap()
                .get(&workspace_id)
                .map(|list| list.len())
                .unwrap_or(0);
            Ok(count as i64)
        }

        async fn count_pending_workspace_invitations(
            &self,
            workspace_id: Uuid,
        ) -> Result<i64, sqlx::Error> {
            let count = *self
                .pending_invites
                .lock()
                .unwrap()
                .get(&workspace_id)
                .unwrap_or(&0);
            Ok(count)
        }

        async fn is_member(&self, workspace_id: Uuid, user_id: Uuid) -> Result<bool, sqlx::Error> {
            Ok(self.member_exists(workspace_id, user_id))
        }

        async fn list_memberships_for_user(
            &self,
            user_id: Uuid,
        ) -> Result<Vec<WorkspaceMembershipSummary>, sqlx::Error> {
            self.list_user_workspaces(user_id).await
        }

        async fn list_user_workspaces(
            &self,
            user_id: Uuid,
        ) -> Result<Vec<WorkspaceMembershipSummary>, sqlx::Error> {
            let workspaces = self.workspaces.lock().unwrap();
            let members = self.members.lock().unwrap();

            let mut summaries = Vec::new();
            for (workspace_id, list) in members.iter() {
                if let Some(member) = list.iter().find(|member| member.user_id == user_id) {
                    if let Some(workspace) = workspaces.get(workspace_id) {
                        summaries.push(WorkspaceMembershipSummary {
                            workspace: workspace.clone(),
                            role: member.role,
                        });
                    }
                }
            }

            Ok(summaries)
        }

        async fn create_workspace_invitation(
            &self,
            _: Uuid,
            _: &str,
            _: WorkspaceRole,
            _: &str,
            _: OffsetDateTime,
            _: Uuid,
        ) -> Result<WorkspaceInvitation, sqlx::Error> {
            unimplemented!()
        }

        async fn list_workspace_invitations(
            &self,
            _: Uuid,
        ) -> Result<Vec<WorkspaceInvitation>, sqlx::Error> {
            unimplemented!()
        }

        async fn revoke_workspace_invitation(&self, _: Uuid) -> Result<(), sqlx::Error> {
            unimplemented!()
        }

        async fn find_invitation_by_token(
            &self,
            _: &str,
        ) -> Result<Option<WorkspaceInvitation>, sqlx::Error> {
            unimplemented!()
        }

        async fn mark_invitation_accepted(&self, _: Uuid) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn mark_invitation_declined(&self, _: Uuid) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn list_pending_invitations_for_email(
            &self,
            _: &str,
        ) -> Result<Vec<WorkspaceInvitation>, sqlx::Error> {
            Ok(vec![])
        }

        async fn disable_webhook_signing_for_workspace(
            &self,
            _workspace_id: Uuid,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn try_increment_workspace_run_quota(
            &self,
            workspace_id: Uuid,
            period_start: OffsetDateTime,
            max_runs: i64,
        ) -> Result<WorkspaceRunQuotaUpdate, sqlx::Error> {
            let mut usage = self.run_usage.lock().unwrap();
            let key = RecordingWorkspaceRepo::usage_key(workspace_id, period_start);
            let entry = usage.entry(key).or_insert((0, 0));
            entry.0 += 1;
            let mut overage_incremented = false;
            if entry.0 > max_runs {
                entry.1 += 1;
                overage_incremented = true;
            }
            Ok(WorkspaceRunQuotaUpdate {
                allowed: entry.0 <= max_runs,
                run_count: entry.0,
                overage_count: entry.1,
                overage_incremented,
            })
        }

        async fn get_workspace_run_quota(
            &self,
            workspace_id: Uuid,
            period_start: OffsetDateTime,
        ) -> Result<WorkspaceRunUsage, sqlx::Error> {
            let usage = self.run_usage.lock().unwrap();
            let key = RecordingWorkspaceRepo::usage_key(workspace_id, period_start);
            Ok(usage
                .get(&key)
                .copied()
                .map(|(runs, overage)| WorkspaceRunUsage {
                    run_count: runs,
                    overage_count: overage,
                })
                .unwrap_or(WorkspaceRunUsage {
                    run_count: 0,
                    overage_count: 0,
                }))
        }

        async fn release_workspace_run_quota(
            &self,
            workspace_id: Uuid,
            period_start: OffsetDateTime,
            overage_decrement: bool,
        ) -> Result<(), sqlx::Error> {
            let mut usage = self.run_usage.lock().unwrap();
            let key = RecordingWorkspaceRepo::usage_key(workspace_id, period_start);
            if let Some(entry) = usage.get_mut(&key) {
                if entry.0 > 0 {
                    entry.0 -= 1;
                }
                if overage_decrement && entry.1 > 0 {
                    entry.1 -= 1;
                }
                if entry.0 == 0 && entry.1 == 0 {
                    usage.remove(&key);
                }
            }
            Ok(())
        }

        async fn upsert_workspace_billing_cycle(
            &self,
            workspace_id: Uuid,
            subscription_id: &str,
            period_start: OffsetDateTime,
            period_end: OffsetDateTime,
        ) -> Result<(), sqlx::Error> {
            let mut guard = self.billing_cycles.lock().unwrap();
            guard.insert(
                workspace_id,
                WorkspaceBillingCycle {
                    workspace_id,
                    stripe_subscription_id: subscription_id.to_string(),
                    current_period_start: period_start,
                    current_period_end: period_end,
                    synced_at: OffsetDateTime::now_utc(),
                },
            );
            Ok(())
        }

        async fn clear_workspace_billing_cycle(
            &self,
            workspace_id: Uuid,
        ) -> Result<(), sqlx::Error> {
            self.billing_cycles.lock().unwrap().remove(&workspace_id);
            Ok(())
        }

        async fn get_workspace_billing_cycle(
            &self,
            workspace_id: Uuid,
        ) -> Result<Option<WorkspaceBillingCycle>, sqlx::Error> {
            Ok(self
                .billing_cycles
                .lock()
                .unwrap()
                .get(&workspace_id)
                .cloned())
        }
    }

    fn test_config() -> Arc<Config> {
        Arc::new(Config {
            database_url: "postgres://localhost/test".into(),
            frontend_origin: "https://app.example.com".into(),
            admin_origin: "https://app.example.com".into(),
            oauth: OAuthSettings {
                google: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "https://app.example.com/oauth/google".into(),
                },
                github: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "https://app.example.com/oauth/github".into(),
                },
                microsoft: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "https://app.example.com/oauth/microsoft".into(),
                },
                slack: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "https://app.example.com/oauth/slack".into(),
                },
                asana: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "https://app.example.com/oauth/asana".into(),
                },
                notion: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "https://app.example.com/oauth/asana".into(),
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
                token_encryption_key: vec![0; 32],
            },
            github_app: crate::config::GitHubAppSettings::default(),
            github_webhook_source_id: None,
            api_secrets_encryption_key: vec![1; 32],
            stripe: StripeSettings {
                client_id: "stub".into(),
                secret_key: "stub".into(),
                webhook_secret: "0123456789abcdef0123456789ABCDEF".into(),
            },
            auth_cookie_secure: true,
            jwt_issuer: "test-issuer".into(),
            jwt_audience: "test-audience".into(),
            workspace_member_limit: crate::config::DEFAULT_WORKSPACE_MEMBER_LIMIT,
            workspace_monthly_run_limit: crate::config::DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT,
            runaway_limit_5min: crate::config::RUNAWAY_LIMIT_5MIN,
            webhook_ingress_dedupe_mode: crate::config::WebhookIngressDedupeMode::Off,
            webhook_verification_body_fields: Vec::new(),
            webhook_verification_header_fields: Vec::new(),
            webhook_event_type_fields: vec!["event_type".to_string(), "type".to_string()],
        })
    }

    fn test_jwt_keys() -> Arc<JwtKeys> {
        Arc::new(
            JwtKeys::from_secret("0123456789abcdef0123456789abcdef")
                .expect("test JWT secret should be valid"),
        )
    }

    fn promotion_state(
        workspace_repo: Arc<dyn WorkspaceRepository>,
        user_repo: Arc<StubUserTokenRepo>,
        connection_repo: Arc<CapturingWorkspaceConnectionRepo>,
        config: Arc<Config>,
        encryption_key: Arc<Vec<u8>>,
    ) -> AppState {
        let workspace_connection_repo: Arc<dyn WorkspaceConnectionRepository> =
            connection_repo.clone();
        let user_token_repo: Arc<dyn UserOAuthTokenRepository> = user_repo.clone();
        let oauth_accounts = OAuthAccountService::test_stub();
        let workspace_token_refresher: Arc<dyn WorkspaceTokenRefresher> =
            oauth_accounts.clone() as Arc<dyn WorkspaceTokenRefresher>;

        let workspace_oauth = Arc::new(WorkspaceOAuthService::new(
            user_token_repo.clone(),
            Arc::clone(&workspace_repo),
            workspace_connection_repo.clone(),
            workspace_token_refresher,
            encryption_key,
        ));

        AppState {
            db: Arc::new(MockDb::default()),
            workflow_repo: Arc::new(NoopWorkflowRepository),
            workspace_repo,
            workspace_connection_repo,
            stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
            db_pool: test_pg_pool(),
            mailer: Arc::new(MockMailer::default()),
            google_oauth: Arc::new(MockGoogleOAuth::default()),
            github_oauth: Arc::new(MockGitHubOAuth::default()),
            oauth_accounts,
            workspace_oauth,
            stripe: Arc::new(crate::services::stripe::MockStripeService::new()),
            integration_registry: crate::state::test_integration_registry(),
            http_client: Arc::new(Client::new()),
            config,
            worker_id: Arc::new("worker-1".into()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        }
    }

    fn test_state(repo: Arc<TestWorkspaceRepo>) -> AppState {
        AppState {
            db: Arc::new(MockDb::default()),
            workflow_repo: Arc::new(NoopWorkflowRepository),
            workspace_repo: repo,
            workspace_connection_repo: Arc::new(NoopWorkspaceConnectionRepository),
            stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
            db_pool: test_pg_pool(),
            mailer: Arc::new(NoopMailer),
            google_oauth: Arc::new(MockGoogleOAuth::default()),
            github_oauth: Arc::new(MockGitHubOAuth::default()),
            oauth_accounts: OAuthAccountService::test_stub(),
            workspace_oauth: WorkspaceOAuthService::test_stub(),
            stripe: Arc::new(crate::services::stripe::MockStripeService::new()),
            integration_registry: crate::state::test_integration_registry(),
            http_client: Arc::new(Client::new()),
            config: test_config(),
            worker_id: Arc::new("worker-1".into()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        }
    }

    fn state_with_components(
        repo: Arc<dyn WorkspaceRepository>,
        mailer: Arc<dyn Mailer>,
        db: Arc<MockDb>,
        workspace_connections: Option<Arc<dyn WorkspaceConnectionRepository>>,
        user_tokens: Option<Arc<dyn UserOAuthTokenRepository>>,
    ) -> AppState {
        let config = test_config();
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());
        let connection_repo = workspace_connections
            .unwrap_or_else(|| Arc::new(NoopWorkspaceConnectionRepository) as Arc<_>);
        let token_repo =
            user_tokens.unwrap_or_else(|| Arc::new(StubUserTokenRepo::default()) as Arc<_>);
        let workspace_oauth = Arc::new(WorkspaceOAuthService::new(
            token_repo,
            Arc::clone(&repo),
            Arc::clone(&connection_repo),
            OAuthAccountService::test_stub(),
            Arc::clone(&encryption_key),
        ));

        AppState {
            db: db.clone(),
            workflow_repo: Arc::new(NoopWorkflowRepository),
            workspace_repo: repo,
            workspace_connection_repo: Arc::clone(&connection_repo),
            stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
            db_pool: test_pg_pool(),
            mailer,
            google_oauth: Arc::new(MockGoogleOAuth::default()),
            github_oauth: Arc::new(MockGitHubOAuth::default()),
            oauth_accounts: OAuthAccountService::test_stub(),
            workspace_oauth,
            stripe: Arc::new(crate::services::stripe::MockStripeService::new()),
            integration_registry: crate::state::test_integration_registry(),
            http_client: Arc::new(Client::new()),
            config,
            worker_id: Arc::new("worker-1".into()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        }
    }

    fn invite_fixture(email: &str) -> WorkspaceInvitation {
        WorkspaceInvitation {
            id: Uuid::new_v4(),
            workspace_id: Uuid::new_v4(),
            email: email.to_string(),
            role: WorkspaceRole::Admin,
            token: "inv-token".into(),
            status: crate::models::workspace::INVITATION_STATUS_PENDING.to_string(),
            expires_at: OffsetDateTime::now_utc() + time::Duration::hours(1),
            created_by: Uuid::new_v4(),
            created_at: OffsetDateTime::now_utc(),
            accepted_at: None,
            revoked_at: None,
            declined_at: None,
        }
    }

    fn claims_fixture(user_id: Uuid, email: &str) -> Claims {
        Claims {
            id: user_id.to_string(),
            email: email.to_string(),
            exp: OffsetDateTime::now_utc().unix_timestamp() as usize + 3600,
            first_name: "Test".into(),
            last_name: "User".into(),
            role: None,
            plan: None,
            company_name: None,
            iss: String::new(),
            aud: String::new(),
            token_use: TokenUse::Access,
        }
    }

    fn workspace_connection_fixture(
        workspace_id: Uuid,
        user_id: Uuid,
        provider: ConnectedOAuthProvider,
    ) -> WorkspaceConnection {
        let now = OffsetDateTime::now_utc();
        let token_id = Uuid::new_v4();
        let slack_team_id = if provider == ConnectedOAuthProvider::Slack {
            Some("T123".to_string())
        } else {
            None
        };
        WorkspaceConnection {
            id: Uuid::new_v4(),
            connection_id: Some(token_id),
            workspace_id,
            created_by: user_id,
            owner_user_id: user_id,
            user_oauth_token_id: Some(token_id),
            provider,
            access_token: "encrypted-access".into(),
            refresh_token: "encrypted-refresh".into(),
            expires_at: now + time::Duration::hours(1),
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
    async fn promote_workspace_connection_succeeds_for_admin() {
        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let config = test_config();
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());

        let workspace = Workspace {
            id: workspace_id,
            name: "Team".into(),
            created_by: user_id,
            owner_id: user_id,
            plan: PlanTier::Workspace.as_str().to_string(),
            stripe_overage_item_id: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };
        let member = WorkspaceMember {
            workspace_id,
            user_id,
            role: WorkspaceRole::Admin,
            joined_at: now,
            email: "owner@example.com".into(),
            first_name: "Owner".into(),
            last_name: "Admin".into(),
        };
        let workspace_repo: Arc<dyn WorkspaceRepository> = Arc::new(
            RecordingWorkspaceRepo::seeded(workspace.clone(), vec![member.clone()]),
        );

        let encrypted_access = encrypt_secret(&encryption_key, "access-token").unwrap();
        let encrypted_refresh = encrypt_secret(&encryption_key, "refresh-token").unwrap();

        let user_token = UserOAuthToken {
            id: Uuid::new_v4(),
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Google,
            access_token: encrypted_access.clone(),
            refresh_token: encrypted_refresh.clone(),
            expires_at: now + time::Duration::hours(1),
            account_email: "owner@example.com".into(),
            metadata: serde_json::json!({}),
            is_shared: false,
            created_at: now,
            updated_at: now,
        };
        let user_repo = Arc::new(StubUserTokenRepo::with_token(user_token.clone()));
        let connection_repo = Arc::new(CapturingWorkspaceConnectionRepo::new());

        let state = promotion_state(
            workspace_repo,
            user_repo.clone(),
            connection_repo.clone(),
            Arc::clone(&config),
            Arc::clone(&encryption_key),
        );

        let response = promote_workspace_connection(
            State(state),
            AuthSession(claims_fixture(user_id, "owner@example.com")),
            Path(workspace_id),
            Json(PromoteWorkspaceConnectionPayload {
                user_oauth_token_id: user_token.id,
                provider: ConnectedOAuthProvider::Google,
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["success"], Value::Bool(true));
        assert_eq!(json["created_by"], Value::String(user_id.to_string()));

        let inserted = connection_repo.connections();
        assert_eq!(inserted.len(), 1);
        assert_eq!(inserted[0].workspace_id, workspace_id);
        assert_eq!(inserted[0].created_by, user_id);
        assert_eq!(inserted[0].connection_id, Some(user_token.id));
        assert_eq!(inserted[0].access_token, encrypted_access);
        assert_eq!(inserted[0].refresh_token, encrypted_refresh);

        let marks = user_repo.marks();
        assert_eq!(marks, vec![]); // No shared flag should be set per requirements

        let audits = connection_repo.audits();
        assert_eq!(audits.len(), 1);
        assert_eq!(
            audits[0].event_type,
            WORKSPACE_AUDIT_EVENT_CONNECTION_PROMOTED
        );
        assert_eq!(audits[0].workspace_id, workspace_id);
        assert_eq!(audits[0].actor_id, user_id);
    }

    #[tokio::test]
    async fn promote_workspace_connection_rejects_member_role() {
        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let config = test_config();
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());

        let workspace = Workspace {
            id: workspace_id,
            name: "Team".into(),
            created_by: user_id,
            owner_id: user_id,
            plan: PlanTier::Workspace.as_str().to_string(),
            stripe_overage_item_id: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };
        let member = WorkspaceMember {
            workspace_id,
            user_id,
            role: WorkspaceRole::User,
            joined_at: now,
            email: "member@example.com".into(),
            first_name: "Member".into(),
            last_name: "User".into(),
        };
        let workspace_repo: Arc<dyn WorkspaceRepository> = Arc::new(
            RecordingWorkspaceRepo::seeded(workspace.clone(), vec![member.clone()]),
        );

        let token = UserOAuthToken {
            id: Uuid::new_v4(),
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Google,
            access_token: encrypt_secret(&encryption_key, "access").unwrap(),
            refresh_token: encrypt_secret(&encryption_key, "refresh").unwrap(),
            expires_at: now + time::Duration::hours(1),
            account_email: "member@example.com".into(),
            metadata: serde_json::json!({}),
            is_shared: false,
            created_at: now,
            updated_at: now,
        };
        let token_id = token.id;
        let user_repo = Arc::new(StubUserTokenRepo::with_token(token));
        let connection_repo = Arc::new(CapturingWorkspaceConnectionRepo::new());

        let state = promotion_state(
            workspace_repo,
            user_repo.clone(),
            connection_repo.clone(),
            Arc::clone(&config),
            Arc::clone(&encryption_key),
        );

        let response = promote_workspace_connection(
            State(state),
            AuthSession(claims_fixture(user_id, "owner@example.com")),
            Path(workspace_id),
            Json(PromoteWorkspaceConnectionPayload {
                user_oauth_token_id: token_id,
                provider: ConnectedOAuthProvider::Google,
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(user_repo.marks().is_empty());
        assert!(connection_repo.connections().is_empty());
    }

    #[tokio::test]
    async fn promote_workspace_connection_returns_not_found_without_token() {
        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let config = test_config();
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());

        let workspace = Workspace {
            id: workspace_id,
            name: "Team".into(),
            created_by: user_id,
            owner_id: user_id,
            plan: PlanTier::Workspace.as_str().to_string(),
            stripe_overage_item_id: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };
        let member = WorkspaceMember {
            workspace_id,
            user_id,
            role: WorkspaceRole::Admin,
            joined_at: now,
            email: "owner@example.com".into(),
            first_name: "Owner".into(),
            last_name: "User".into(),
        };
        let workspace_repo: Arc<dyn WorkspaceRepository> = Arc::new(
            RecordingWorkspaceRepo::seeded(workspace.clone(), vec![member.clone()]),
        );

        let user_repo = Arc::new(StubUserTokenRepo::without_tokens());
        let connection_repo = Arc::new(CapturingWorkspaceConnectionRepo::new());

        let state = promotion_state(
            workspace_repo,
            user_repo.clone(),
            connection_repo.clone(),
            Arc::clone(&config),
            Arc::clone(&encryption_key),
        );

        let response = promote_workspace_connection(
            State(state),
            AuthSession(claims_fixture(user_id, "owner@example.com")),
            Path(workspace_id),
            Json(PromoteWorkspaceConnectionPayload {
                user_oauth_token_id: Uuid::new_v4(), // Non-existent token ID
                provider: ConnectedOAuthProvider::Google,
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(user_repo.marks().is_empty());
        assert!(connection_repo.connections().is_empty());
    }

    #[tokio::test]
    async fn promote_workspace_connection_succeeds_with_explicit_token_id() {
        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let config = test_config();
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());

        let workspace = Workspace {
            id: workspace_id,
            name: "Team".into(),
            created_by: user_id,
            owner_id: user_id,
            plan: PlanTier::Workspace.as_str().to_string(),
            stripe_overage_item_id: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };
        let member = WorkspaceMember {
            workspace_id,
            user_id,
            role: WorkspaceRole::Admin,
            joined_at: now,
            email: "owner@example.com".into(),
            first_name: "Owner".into(),
            last_name: "Admin".into(),
        };
        let workspace_repo: Arc<dyn WorkspaceRepository> = Arc::new(
            RecordingWorkspaceRepo::seeded(workspace.clone(), vec![member.clone()]),
        );

        let encrypted_access = encrypt_secret(&encryption_key, "access-token").unwrap();
        let encrypted_refresh = encrypt_secret(&encryption_key, "refresh-token").unwrap();

        let user_token = UserOAuthToken {
            id: Uuid::new_v4(),
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Google,
            access_token: encrypted_access.clone(),
            refresh_token: encrypted_refresh.clone(),
            expires_at: now + time::Duration::hours(1),
            account_email: "owner@example.com".into(),
            metadata: serde_json::json!({}),
            is_shared: false,
            created_at: now,
            updated_at: now,
        };
        let token_id = user_token.id;
        let user_repo = Arc::new(StubUserTokenRepo::with_token(user_token));
        let connection_repo = Arc::new(CapturingWorkspaceConnectionRepo::new());

        let state = promotion_state(
            workspace_repo,
            user_repo.clone(),
            connection_repo.clone(),
            Arc::clone(&config),
            Arc::clone(&encryption_key),
        );

        let response = promote_workspace_connection(
            State(state),
            AuthSession(claims_fixture(user_id, "owner@example.com")),
            Path(workspace_id),
            Json(PromoteWorkspaceConnectionPayload {
                user_oauth_token_id: token_id,
                provider: ConnectedOAuthProvider::Google,
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["success"], Value::Bool(true));
        assert_eq!(json["created_by"], Value::String(user_id.to_string()));

        let inserted = connection_repo.connections();
        assert_eq!(inserted.len(), 1);
        assert_eq!(inserted[0].workspace_id, workspace_id);
        assert_eq!(inserted[0].created_by, user_id);
        assert_eq!(inserted[0].access_token, encrypted_access);
        assert_eq!(inserted[0].refresh_token, encrypted_refresh);

        let marks = user_repo.marks();
        assert_eq!(marks, vec![]); // No shared flag should be set per requirements

        let audits = connection_repo.audits();
        assert_eq!(audits.len(), 1);
        assert_eq!(
            audits[0].event_type,
            WORKSPACE_AUDIT_EVENT_CONNECTION_PROMOTED
        );
        assert_eq!(audits[0].workspace_id, workspace_id);
        assert_eq!(audits[0].actor_id, user_id);
    }

    #[tokio::test]
    async fn promote_workspace_connection_rejects_unknown_token_id() {
        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let config = test_config();
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());

        let workspace = Workspace {
            id: workspace_id,
            name: "Team".into(),
            created_by: user_id,
            owner_id: user_id,
            plan: PlanTier::Workspace.as_str().to_string(),
            stripe_overage_item_id: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };
        let member = WorkspaceMember {
            workspace_id,
            user_id,
            role: WorkspaceRole::Admin,
            joined_at: now,
            email: "owner@example.com".into(),
            first_name: "Owner".into(),
            last_name: "Admin".into(),
        };
        let workspace_repo: Arc<dyn WorkspaceRepository> = Arc::new(
            RecordingWorkspaceRepo::seeded(workspace.clone(), vec![member.clone()]),
        );

        let user_repo = Arc::new(StubUserTokenRepo::without_tokens());
        let connection_repo = Arc::new(CapturingWorkspaceConnectionRepo::new());

        let state = promotion_state(
            workspace_repo,
            user_repo.clone(),
            connection_repo.clone(),
            Arc::clone(&config),
            Arc::clone(&encryption_key),
        );

        // Test with invalid UUID - this will fail during deserialization
        let response = promote_workspace_connection(
            State(state),
            AuthSession(claims_fixture(user_id, "owner@example.com")),
            Path(workspace_id),
            Json(PromoteWorkspaceConnectionPayload {
                user_oauth_token_id: Uuid::new_v4(), // still required to compile
                provider: ConnectedOAuthProvider::Google,
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(user_repo.marks().is_empty());
        assert!(connection_repo.connections().is_empty());
    }

    #[tokio::test]
    async fn promote_workspace_connection_rejects_slack_provider() {
        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let workspace = Workspace {
            id: workspace_id,
            name: "Team".into(),
            created_by: user_id,
            owner_id: user_id,
            plan: PlanTier::Workspace.as_str().to_string(),
            stripe_overage_item_id: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };
        let member = WorkspaceMember {
            workspace_id,
            user_id,
            role: WorkspaceRole::Admin,
            joined_at: now,
            email: "admin@example.com".into(),
            first_name: "Admin".into(),
            last_name: "User".into(),
        };
        let workspace_repo: Arc<dyn WorkspaceRepository> = Arc::new(
            RecordingWorkspaceRepo::seeded(workspace.clone(), vec![member.clone()]),
        );

        let state = promotion_state(
            workspace_repo,
            Arc::new(StubUserTokenRepo::without_tokens()),
            Arc::new(CapturingWorkspaceConnectionRepo::new()),
            test_config(),
            Arc::new(vec![0; 32]),
        );

        let response = promote_workspace_connection(
            State(state),
            AuthSession(claims_fixture(user_id, "admin@example.com")),
            Path(workspace_id),
            Json(PromoteWorkspaceConnectionPayload {
                user_oauth_token_id: Uuid::new_v4(),
                provider: ConnectedOAuthProvider::Slack,
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        let response_str = json.to_string();
        assert!(response_str.contains("Slack connections must be installed at workspace scope"));
    }

    #[tokio::test]
    async fn remove_workspace_connection_deletes_connection_for_admin() {
        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let config = test_config();
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());

        let workspace = Workspace {
            id: workspace_id,
            name: "Team".into(),
            created_by: user_id,
            owner_id: user_id,
            plan: PlanTier::Workspace.as_str().to_string(),
            stripe_overage_item_id: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };
        let member = WorkspaceMember {
            workspace_id,
            user_id,
            role: WorkspaceRole::Admin,
            joined_at: now,
            email: "owner@example.com".into(),
            first_name: "Owner".into(),
            last_name: "Admin".into(),
        };
        let workspace_repo: Arc<dyn WorkspaceRepository> = Arc::new(
            RecordingWorkspaceRepo::seeded(workspace.clone(), vec![member.clone()]),
        );

        let encrypted_access = encrypt_secret(&encryption_key, "access-token").unwrap();
        let encrypted_refresh = encrypt_secret(&encryption_key, "refresh-token").unwrap();

        let user_token = UserOAuthToken {
            id: Uuid::new_v4(),
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Google,
            access_token: encrypted_access.clone(),
            refresh_token: encrypted_refresh.clone(),
            expires_at: now + time::Duration::hours(1),
            account_email: "owner@example.com".into(),
            metadata: serde_json::json!({}),
            is_shared: true,
            created_at: now,
            updated_at: now,
        };
        let user_token_id = user_token.id;
        let user_repo = Arc::new(StubUserTokenRepo::with_token(user_token));
        let connection_repo = Arc::new(CapturingWorkspaceConnectionRepo::new());

        let state = promotion_state(
            workspace_repo,
            user_repo.clone(),
            connection_repo.clone(),
            Arc::clone(&config),
            Arc::clone(&encryption_key),
        );

        let inserted = connection_repo
            .insert_connection(NewWorkspaceConnection {
                workspace_id,
                created_by: user_id,
                owner_user_id: user_id,
                user_oauth_token_id: Some(user_token_id),
                connection_id: Some(user_token_id),
                provider: ConnectedOAuthProvider::Google,
                access_token: encrypted_access.clone(),
                refresh_token: encrypted_refresh.clone(),
                expires_at: now + time::Duration::hours(1),
                account_email: "owner@example.com".into(),
                metadata: serde_json::json!({}),
                slack_team_id: None,
                bot_user_id: None,
                incoming_webhook_url: None,
            })
            .await
            .expect("insert connection");

        let response = remove_workspace_connection(
            State(state),
            AuthSession(claims_fixture(user_id, "owner@example.com")),
            Path((workspace_id, inserted.id)),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);

        let marks = user_repo.marks();
        assert!(marks.contains(&(user_id, ConnectedOAuthProvider::Google, false)));

        assert!(connection_repo
            .connections()
            .iter()
            .all(|connection| connection.id != inserted.id));
        assert_eq!(connection_repo.deleted(), vec![inserted.id]);

        let audits = connection_repo.audits();
        assert_eq!(audits.len(), 1);
        assert_eq!(
            audits[0].event_type,
            WORKSPACE_AUDIT_EVENT_CONNECTION_UNSHARED
        );
        assert_eq!(audits[0].workspace_id, workspace_id);
        assert_eq!(audits[0].actor_id, user_id);
    }

    #[tokio::test]
    async fn remove_workspace_connection_rejects_admin_when_not_creator() {
        let owner_id = Uuid::new_v4();
        let creator_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let config = test_config();
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());

        let workspace = Workspace {
            id: workspace_id,
            name: "Team".into(),
            created_by: owner_id,
            owner_id,
            plan: PlanTier::Workspace.as_str().to_string(),
            stripe_overage_item_id: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };
        let admin_member = WorkspaceMember {
            workspace_id,
            user_id: owner_id,
            role: WorkspaceRole::Admin,
            joined_at: now,
            email: "owner@example.com".into(),
            first_name: "Owner".into(),
            last_name: "Admin".into(),
        };
        let creator_member = WorkspaceMember {
            workspace_id,
            user_id: creator_id,
            role: WorkspaceRole::User,
            joined_at: now,
            email: "creator@example.com".into(),
            first_name: "Creator".into(),
            last_name: "User".into(),
        };
        let workspace_repo: Arc<dyn WorkspaceRepository> =
            Arc::new(RecordingWorkspaceRepo::seeded(
                workspace.clone(),
                vec![admin_member.clone(), creator_member.clone()],
            ));

        let encrypted_access = encrypt_secret(&encryption_key, "access-token").unwrap();
        let encrypted_refresh = encrypt_secret(&encryption_key, "refresh-token").unwrap();

        let user_token = UserOAuthToken {
            id: Uuid::new_v4(),
            user_id: creator_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Google,
            access_token: encrypted_access.clone(),
            refresh_token: encrypted_refresh.clone(),
            expires_at: now + time::Duration::hours(1),
            account_email: "creator@example.com".into(),
            metadata: serde_json::json!({}),
            is_shared: true,
            created_at: now,
            updated_at: now,
        };
        let user_repo = Arc::new(StubUserTokenRepo::with_token(user_token));
        let connection_repo = Arc::new(CapturingWorkspaceConnectionRepo::new());

        let state = promotion_state(
            workspace_repo,
            user_repo.clone(),
            connection_repo.clone(),
            Arc::clone(&config),
            Arc::clone(&encryption_key),
        );

        let token_id = Uuid::new_v4();
        let inserted = connection_repo
            .insert_connection(NewWorkspaceConnection {
                workspace_id,
                created_by: creator_id,
                owner_user_id: creator_id,
                user_oauth_token_id: Some(token_id),
                connection_id: Some(token_id),
                provider: ConnectedOAuthProvider::Google,
                access_token: encrypted_access.clone(),
                refresh_token: encrypted_refresh.clone(),
                expires_at: now + time::Duration::hours(1),
                account_email: "creator@example.com".into(),
                metadata: serde_json::json!({}),
                slack_team_id: None,
                bot_user_id: None,
                incoming_webhook_url: None,
            })
            .await
            .expect("insert connection");

        let response = remove_workspace_connection(
            State(state),
            AuthSession(claims_fixture(owner_id, "owner@example.com")),
            Path((workspace_id, inserted.id)),
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        // Personal token should not be demoted and connection should remain.
        assert!(user_repo.marks().is_empty());
        assert!(connection_repo
            .connections()
            .iter()
            .any(|connection| connection.id == inserted.id));
        assert!(connection_repo.deleted().is_empty());
    }

    #[tokio::test]
    async fn remove_workspace_connection_returns_not_found_when_missing() {
        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let config = test_config();
        let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());

        let workspace = Workspace {
            id: workspace_id,
            name: "Team".into(),
            created_by: user_id,
            owner_id: user_id,
            plan: PlanTier::Workspace.as_str().to_string(),
            stripe_overage_item_id: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };
        let member = WorkspaceMember {
            workspace_id,
            user_id,
            role: WorkspaceRole::Admin,
            joined_at: now,
            email: "owner@example.com".into(),
            first_name: "Owner".into(),
            last_name: "Admin".into(),
        };
        let workspace_repo: Arc<dyn WorkspaceRepository> = Arc::new(
            RecordingWorkspaceRepo::seeded(workspace.clone(), vec![member.clone()]),
        );

        let token = UserOAuthToken {
            id: Uuid::new_v4(),
            user_id,
            workspace_id: None,
            provider: ConnectedOAuthProvider::Google,
            access_token: encrypt_secret(&encryption_key, "access").unwrap(),
            refresh_token: encrypt_secret(&encryption_key, "refresh").unwrap(),
            expires_at: now + time::Duration::hours(1),
            account_email: "owner@example.com".into(),
            metadata: serde_json::json!({}),
            is_shared: true,
            created_at: now,
            updated_at: now,
        };
        let user_repo = Arc::new(StubUserTokenRepo::with_token(token));
        let connection_repo = Arc::new(CapturingWorkspaceConnectionRepo::new());

        let state = promotion_state(
            workspace_repo,
            user_repo.clone(),
            connection_repo.clone(),
            Arc::clone(&config),
            Arc::clone(&encryption_key),
        );

        let missing_connection_id = Uuid::new_v4();

        let response = remove_workspace_connection(
            State(state),
            AuthSession(claims_fixture(user_id, "owner@example.com")),
            Path((workspace_id, missing_connection_id)),
        )
        .await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert!(user_repo.marks().is_empty());
        assert!(connection_repo.deleted().is_empty());
    }

    #[test]
    fn invite_urls_target_correct_flow_with_encoded_token() {
        let token = "abc+/=?";
        let base = "https://app.example.com";
        let login_url = build_invite_accept_url(base, token, true);
        assert_eq!(
            login_url,
            "https://app.example.com/login?invite=abc%2B%2F%3D%3F"
        );
        let signup_url = build_invite_accept_url(base, token, false);
        assert_eq!(
            signup_url,
            "https://app.example.com/signup?invite=abc%2B%2F%3D%3F"
        );
    }

    #[tokio::test]
    async fn list_pending_invites_returns_workspace_name_when_available() {
        let email = "member@example.com";
        let invite = invite_fixture(email);
        let workspace_id = invite.workspace_id;
        let now = OffsetDateTime::now_utc();

        let workspace = Workspace {
            id: workspace_id,
            name: "Growth Team".into(),
            created_by: invite.created_by,
            owner_id: invite.created_by,
            plan: PlanTier::Workspace.as_str().to_string(),
            stripe_overage_item_id: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        let repo = Arc::new(TestWorkspaceRepo::with_workspace(
            invite.clone(),
            workspace.clone(),
        ));
        let state = test_state(repo);
        let claims = claims_fixture(Uuid::new_v4(), email);

        let response = list_pending_invites(State(state), AuthSession(claims)).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["success"], Value::Bool(true));
        let invitations = json["invitations"].as_array().expect("array of invites");
        assert_eq!(invitations.len(), 1);

        let first = &invitations[0];
        assert_eq!(
            first["workspace_name"],
            Value::String(workspace.name.clone())
        );
        assert_eq!(
            first["workspace_id"],
            Value::String(workspace_id.to_string())
        );
        assert_eq!(first["email"], Value::String(invite.email.clone()));
        assert_eq!(first["id"], Value::String(invite.id.to_string()));
    }

    #[tokio::test]
    async fn create_workspace_invitation_errors_at_member_limit() {
        let workspace_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let workspace = Workspace {
            id: workspace_id,
            name: "Growth".into(),
            created_by: owner_id,
            owner_id,
            plan: PlanTier::Workspace.as_str().to_string(),
            stripe_overage_item_id: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        let members: Vec<WorkspaceMember> = (0..8)
            .map(|i| WorkspaceMember {
                workspace_id,
                user_id: if i == 0 { owner_id } else { Uuid::new_v4() },
                role: if i == 0 {
                    WorkspaceRole::Owner
                } else {
                    WorkspaceRole::User
                },
                joined_at: now,
                email: format!("member{i}@example.com"),
                first_name: format!("Member{i}"),
                last_name: "User".into(),
            })
            .collect();

        let repo = Arc::new(RecordingWorkspaceRepo::seeded(workspace, members));
        let state = state_with_components(
            repo as Arc<dyn WorkspaceRepository>,
            Arc::new(NoopMailer),
            Arc::new(MockDb::default()),
            None,
            None,
        );

        let response = create_workspace_invitation(
            State(state),
            AuthSession(claims_fixture(owner_id, "owner@example.com")),
            Path(workspace_id),
            Json(CreateInvitationPayload {
                email: "new@example.com".into(),
                role: WorkspaceRole::User,
                expires_in_days: None,
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], Value::String("workspace_member_limit".into()));
    }

    #[tokio::test]
    async fn create_workspace_invitation_counts_pending_invites_toward_limit() {
        let workspace_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let workspace = Workspace {
            id: workspace_id,
            name: "Growth".into(),
            created_by: owner_id,
            owner_id,
            plan: PlanTier::Workspace.as_str().to_string(),
            stripe_overage_item_id: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        let members: Vec<WorkspaceMember> = (0..5)
            .map(|i| WorkspaceMember {
                workspace_id,
                user_id: if i == 0 { owner_id } else { Uuid::new_v4() },
                role: if i == 0 {
                    WorkspaceRole::Owner
                } else {
                    WorkspaceRole::User
                },
                joined_at: now,
                email: format!("member{i}@example.com"),
                first_name: format!("Member{i}"),
                last_name: "User".into(),
            })
            .collect();

        let repo = Arc::new(RecordingWorkspaceRepo::seeded(workspace, members));
        repo.set_pending_invites(workspace_id, 3);
        let state = state_with_components(
            repo.clone() as Arc<dyn WorkspaceRepository>,
            Arc::new(NoopMailer),
            Arc::new(MockDb::default()),
            None,
            None,
        );

        let response = create_workspace_invitation(
            State(state),
            AuthSession(claims_fixture(owner_id, "owner@example.com")),
            Path(workspace_id),
            Json(CreateInvitationPayload {
                email: "new@example.com".into(),
                role: WorkspaceRole::User,
                expires_in_days: None,
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["code"], Value::String("workspace_member_limit".into()));
    }

    #[tokio::test]
    async fn preview_invitation_includes_workspace_name() {
        let email = "member@example.com";
        let invite = invite_fixture(email);
        let workspace_id = invite.workspace_id;
        let invite_email = invite.email.clone();
        let now = OffsetDateTime::now_utc();
        let workspace = Workspace {
            id: workspace_id,
            name: "Growth Team".into(),
            created_by: invite.created_by,
            owner_id: invite.created_by,
            plan: PlanTier::Workspace.as_str().to_string(),
            stripe_overage_item_id: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        let repo = Arc::new(TestWorkspaceRepo::with_workspace(
            invite.clone(),
            workspace.clone(),
        ));
        let state = test_state(repo.clone());

        let response =
            preview_invitation(State(state), axum::extract::Path(invite.token.clone())).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["invitation"]["workspace_name"],
            Value::String(workspace.name.clone())
        );
        assert_eq!(
            json["invitation"]["workspace_id"],
            Value::String(workspace_id.to_string())
        );
        // Ensure other fields are still present
        assert_eq!(json["invitation"]["email"], Value::String(invite_email));
    }

    #[tokio::test]
    async fn accept_invitation_adds_membership_and_marks_status() {
        let email = "member@example.com";
        let invite = invite_fixture(email);
        let repo = Arc::new(TestWorkspaceRepo::new(invite.clone()));
        let state = test_state(repo.clone());
        let user_id = Uuid::new_v4();
        let claims = claims_fixture(user_id, email);

        let response = accept_invitation(
            State(state),
            AuthSession(claims),
            Json(InvitationDecisionPayload {
                token: invite.token.clone(),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["success"], Value::Bool(true));
        assert_eq!(
            json["workspace_id"],
            Value::String(invite.workspace_id.to_string())
        );

        let (members, accepted, declined) = repo.records();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].0, invite.workspace_id);
        assert_eq!(members[0].1, user_id);
        assert_eq!(members[0].2, invite.role);
        assert_eq!(accepted, vec![invite.id]);
        assert!(declined.is_empty());

        let updated = repo.current_invitation().expect("invite stored");
        assert_eq!(
            updated.status,
            crate::models::workspace::INVITATION_STATUS_ACCEPTED
        );
    }

    #[tokio::test]
    async fn change_plan_workspace_returns_checkout_url() {
        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        std::env::set_var("STRIPE_WORKSPACE_PRICE_ID", "price_base_test");
        std::env::set_var("STRIPE_OVERAGE_PRICE_ID", "price_overage_test");

        let workspace = Workspace {
            id: workspace_id,
            name: "Solo Space".into(),
            created_by: user_id,
            owner_id: user_id,
            plan: PlanTier::Solo.as_str().to_string(),
            stripe_overage_item_id: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        let member = WorkspaceMember {
            workspace_id,
            user_id,
            role: WorkspaceRole::Owner,
            joined_at: now,
            email: "owner@example.com".into(),
            first_name: "Owner".into(),
            last_name: "User".into(),
        };

        let repo = Arc::new(RecordingWorkspaceRepo::seeded(workspace, vec![member]));
        let mailer: Arc<dyn Mailer> = Arc::new(NoopMailer);
        let db = Arc::new(MockDb {
            find_user_result: Some(User {
                id: user_id,
                email: "owner@example.com".into(),
                password_hash: String::new(),
                first_name: "Owner".into(),
                last_name: "User".into(),
                role: Some(UserRole::User),
                plan: None,
                company_name: None,
                stripe_customer_id: None,
                oauth_provider: Some(OauthProvider::Email),
                onboarded_at: Some(now),
                created_at: now,
                is_verified: true,
            }),
            ..Default::default()
        });
        let state = state_with_components(repo.clone(), mailer, db, None, None);

        let claims = claims_fixture(user_id, "owner@example.com");
        let payload = CompleteOnboardingPayload {
            plan_tier: PlanTier::Workspace,
            workspace_name: Some("Team Workspace".into()),
            shared_workflow_ids: Vec::new(),
        };

        let response = change_plan(State(state), AuthSession(claims), Json(payload)).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 2048).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["success"], Value::Bool(true));
        let checkout_url = json["checkout_url"].as_str().unwrap_or("");
        assert!(!checkout_url.is_empty());
    }

    #[tokio::test]
    async fn initiating_workspace_upgrade_invokes_stripe_and_does_not_mutate_plan() {
        use crate::db::mock_db::NoopWorkflowRepository;
        use crate::db::workspace_connection_repository::NoopWorkspaceConnectionRepository;
        use crate::services::stripe::MockStripeService as StripeMock;
        use crate::state::{test_pg_pool, AppState};

        let user_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        std::env::set_var("STRIPE_WORKSPACE_PRICE_ID", "price_base_test");
        std::env::set_var("STRIPE_OVERAGE_PRICE_ID", "price_overage_test");

        // Prepare DB with a solo user (plan None/solo), and empty settings
        let db = Arc::new(MockDb {
            find_user_result: Some(User {
                id: user_id,
                email: "owner@example.com".into(),
                password_hash: String::new(),
                first_name: "Owner".into(),
                last_name: "User".into(),
                role: Some(UserRole::User),
                plan: None,
                company_name: None,
                stripe_customer_id: None,
                oauth_provider: Some(OauthProvider::Email),
                onboarded_at: Some(now),
                created_at: now,

                is_verified: true,
            }),
            ..Default::default()
        });

        // Keep a handle to the mock so we can assert requests captured
        let stripe = Arc::new(StripeMock::new());

        let state = AppState {
            db: db.clone(),
            workflow_repo: Arc::new(NoopWorkflowRepository),
            workspace_repo: Arc::new(RecordingWorkspaceRepo::default()),
            workspace_connection_repo: Arc::new(NoopWorkspaceConnectionRepository),
            stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
            db_pool: test_pg_pool(),
            mailer: Arc::new(NoopMailer),
            google_oauth: Arc::new(MockGoogleOAuth::default()),
            github_oauth: Arc::new(MockGitHubOAuth::default()),
            oauth_accounts: OAuthAccountService::test_stub(),
            workspace_oauth: WorkspaceOAuthService::test_stub(),
            stripe: stripe.clone(),
            integration_registry: crate::state::test_integration_registry(),
            http_client: Arc::new(Client::new()),
            config: test_config(),
            worker_id: Arc::new("worker-1".into()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        };

        let claims = claims_fixture(user_id, "owner@example.com");
        let payload = CompleteOnboardingPayload {
            plan_tier: PlanTier::Workspace,
            workspace_name: Some("My Team".into()),
            shared_workflow_ids: Vec::new(),
        };

        let response = change_plan(State(state), AuthSession(claims), Json(payload)).await;
        assert_eq!(response.status(), StatusCode::OK);

        // Stripe mock captured the checkout creation request
        let captured = stripe.last_create_requests.lock().unwrap();
        assert_eq!(captured.len(), 1);
        let req = &captured[0];
        assert_eq!(
            req.mode,
            crate::services::stripe::CheckoutMode::Subscription
        );
        let expected = user_id.to_string();
        assert_eq!(req.client_reference_id.as_deref(), Some(expected.as_str()));
        assert_eq!(req.line_items.len(), 2);
        let prices: Vec<_> = req.line_items.iter().map(|li| li.price.as_str()).collect();
        assert!(prices.contains(&"price_base_test"));
        assert!(prices.contains(&"price_overage_test"));

        // Plan should not be mutated during initiation (only at webhook success)
        assert_eq!(*db.update_user_plan_calls.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn completing_solo_onboarding_creates_owner_membership_for_oauth_user() {
        let user_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let repo = Arc::new(RecordingWorkspaceRepo::default());
        let db = Arc::new(MockDb {
            find_user_result: Some(User {
                id: user_id,
                email: "owner@example.com".into(),
                password_hash: String::new(),
                first_name: "Owner".into(),
                last_name: "User".into(),
                role: Some(UserRole::User),
                plan: None,
                company_name: None,
                stripe_customer_id: None,
                oauth_provider: Some(OauthProvider::Google),
                onboarded_at: Some(now),
                created_at: now,
                is_verified: true,
            }),
            ..Default::default()
        });

        let state = state_with_components(
            repo.clone() as Arc<dyn WorkspaceRepository>,
            Arc::new(NoopMailer) as Arc<dyn Mailer>,
            db,
            None,
            None,
        );

        let payload = CompleteOnboardingPayload {
            plan_tier: PlanTier::Solo,
            workspace_name: Some("Personal Sandbox".into()),
            shared_workflow_ids: Vec::new(),
        };

        let response = complete_onboarding(
            State(state),
            AuthSession(claims_fixture(user_id, "owner@example.com")),
            Json(payload),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(repo.workspace_count(), 1);
        assert_eq!(repo.membership_count(user_id), 1);

        let memberships = repo.list_user_workspaces(user_id).await.unwrap();
        assert_eq!(memberships.len(), 1);
        assert_eq!(memberships[0].role, WorkspaceRole::Owner);
        assert_eq!(memberships[0].workspace.owner_id, user_id);
        assert_eq!(memberships[0].workspace.plan, PlanTier::Solo.as_str());
    }

    #[tokio::test]
    async fn completing_solo_onboarding_promotes_existing_membership_to_owner() {
        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let workspace = Workspace {
            id: workspace_id,
            name: "Personal Automations".into(),
            created_by: user_id,
            owner_id: user_id,
            plan: PlanTier::Solo.as_str().to_string(),
            stripe_overage_item_id: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        let members = vec![WorkspaceMember {
            workspace_id,
            user_id,
            role: WorkspaceRole::User,
            joined_at: now,
            email: "owner@example.com".into(),
            first_name: "Owner".into(),
            last_name: "User".into(),
        }];

        let repo = Arc::new(RecordingWorkspaceRepo::seeded(workspace, members));
        let db = Arc::new(MockDb {
            find_user_result: Some(User {
                id: user_id,
                email: "owner@example.com".into(),
                password_hash: String::new(),
                first_name: "Owner".into(),
                last_name: "User".into(),
                role: Some(UserRole::User),
                plan: None,
                company_name: None,
                stripe_customer_id: None,
                oauth_provider: Some(OauthProvider::Google),
                onboarded_at: Some(now),
                created_at: now,
                is_verified: true,
            }),
            ..Default::default()
        });

        let state = state_with_components(
            repo.clone() as Arc<dyn WorkspaceRepository>,
            Arc::new(NoopMailer) as Arc<dyn Mailer>,
            db,
            None,
            None,
        );

        let payload = CompleteOnboardingPayload {
            plan_tier: PlanTier::Solo,
            workspace_name: None,
            shared_workflow_ids: Vec::new(),
        };

        let response = complete_onboarding(
            State(state),
            AuthSession(claims_fixture(user_id, "owner@example.com")),
            Json(payload),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(repo.workspace_count(), 1);

        let memberships = repo.list_user_workspaces(user_id).await.unwrap();
        assert_eq!(memberships.len(), 1);
        assert_eq!(memberships[0].role, WorkspaceRole::Owner);
    }

    #[tokio::test]
    async fn change_plan_downgrades_workspace_plan_field() {
        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let workspace = Workspace {
            id: workspace_id,
            name: "Team Space".into(),
            created_by: user_id,
            owner_id: user_id,
            plan: PlanTier::Workspace.as_str().to_string(),
            stripe_overage_item_id: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        let member = WorkspaceMember {
            workspace_id,
            user_id,
            role: WorkspaceRole::Owner,
            joined_at: now,
            email: "owner@example.com".into(),
            first_name: "Owner".into(),
            last_name: "User".into(),
        };

        let repo = Arc::new(RecordingWorkspaceRepo::seeded(workspace, vec![member]));
        let mailer: Arc<dyn Mailer> = Arc::new(NoopMailer);
        let db = Arc::new(MockDb::default());
        let state = state_with_components(repo.clone(), mailer, db, None, None);

        let claims = claims_fixture(user_id, "owner@example.com");
        let payload = CompleteOnboardingPayload {
            plan_tier: PlanTier::Solo,
            workspace_name: None,
            shared_workflow_ids: Vec::new(),
        };

        let response = change_plan(State(state), AuthSession(claims), Json(payload)).await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 2048).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let returned_plan = json
            .get("memberships")
            .and_then(|value| value.as_array())
            .and_then(|list| list.first())
            .and_then(|membership| membership.get("workspace"))
            .and_then(|workspace| workspace.get("plan"))
            .and_then(|plan| plan.as_str())
            .unwrap_or_default();

        assert_eq!(returned_plan, PlanTier::Solo.as_str());

        let stored_plan = repo
            .workspace_plan(workspace_id)
            .expect("workspace plan should be recorded");
        assert_eq!(stored_plan, PlanTier::Solo.as_str());
    }

    #[tokio::test]
    async fn decline_invitation_marks_declined_without_membership() {
        let email = "member@example.com";
        let invite = invite_fixture(email);
        let repo = Arc::new(TestWorkspaceRepo::new(invite.clone()));
        let state = test_state(repo.clone());
        let claims = claims_fixture(Uuid::new_v4(), email);

        let response = decline_invitation(
            State(state),
            AuthSession(claims),
            Json(InvitationDecisionPayload {
                token: invite.token.clone(),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["success"], Value::Bool(true));
        assert_eq!(json["message"], Value::String("Invite declined".into()));

        let (members, accepted, declined) = repo.records();
        assert!(members.is_empty());
        assert!(accepted.is_empty());
        assert_eq!(declined, vec![invite.id]);

        let updated = repo.current_invitation().expect("invite stored");
        assert_eq!(
            updated.status,
            crate::models::workspace::INVITATION_STATUS_DECLINED
        );
    }

    #[tokio::test]
    async fn leave_workspace_blocks_owner() {
        let workspace_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let admin_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let workspace = Workspace {
            id: workspace_id,
            name: "Team Workspace".into(),
            created_by: owner_id,
            owner_id,
            plan: PlanTier::Workspace.as_str().to_string(),
            stripe_overage_item_id: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        let members = vec![
            WorkspaceMember {
                workspace_id,
                user_id: owner_id,
                role: WorkspaceRole::Owner,
                joined_at: now,
                email: "owner@example.com".into(),
                first_name: "Owner".into(),
                last_name: "User".into(),
            },
            WorkspaceMember {
                workspace_id,
                user_id: admin_id,
                role: WorkspaceRole::Admin,
                joined_at: now,
                email: "admin@example.com".into(),
                first_name: "Admin".into(),
                last_name: "User".into(),
            },
        ];

        let repo = Arc::new(RecordingWorkspaceRepo::seeded(workspace, members));

        let db = MockDb {
            find_user_result: Some(User {
                id: owner_id,
                email: "owner@example.com".into(),
                password_hash: String::new(),
                first_name: "Owner".into(),
                last_name: "User".into(),
                role: Some(UserRole::User),
                plan: None,
                company_name: None,
                stripe_customer_id: None,
                oauth_provider: Some(OauthProvider::Email),
                onboarded_at: Some(now),
                created_at: now,
                is_verified: true,
            }),
            ..Default::default()
        };

        let state = state_with_components(
            repo.clone() as Arc<dyn WorkspaceRepository>,
            Arc::new(NoopMailer) as Arc<dyn Mailer>,
            Arc::new(db),
            None,
            None,
        );

        let response = leave_workspace(
            State(state),
            AuthSession(claims_fixture(owner_id, "owner@example.com")),
            axum::extract::Path(workspace_id),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(repo.member_exists(workspace_id, owner_id));
    }

    #[tokio::test]
    async fn leave_workspace_provisions_solo_for_last_membership() {
        let workspace_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let member_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let workspace = Workspace {
            id: workspace_id,
            name: "Shared Automation".into(),
            created_by: owner_id,
            owner_id,
            plan: PlanTier::Workspace.as_str().to_string(),
            stripe_overage_item_id: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        let members = vec![
            WorkspaceMember {
                workspace_id,
                user_id: owner_id,
                role: WorkspaceRole::Owner,
                joined_at: now,
                email: "owner@example.com".into(),
                first_name: "Owner".into(),
                last_name: "User".into(),
            },
            WorkspaceMember {
                workspace_id,
                user_id: member_id,
                role: WorkspaceRole::Admin,
                joined_at: now,
                email: "member@example.com".into(),
                first_name: "Member".into(),
                last_name: "User".into(),
            },
        ];

        let repo = Arc::new(RecordingWorkspaceRepo::seeded(workspace, members));

        let db = MockDb {
            find_user_result: Some(User {
                id: member_id,
                email: "member@example.com".into(),
                password_hash: String::new(),
                first_name: "Member".into(),
                last_name: "User".into(),
                role: Some(UserRole::User),
                plan: None,
                company_name: None,
                stripe_customer_id: None,
                oauth_provider: Some(OauthProvider::Email),
                onboarded_at: Some(now),
                created_at: now,
                is_verified: true,
            }),
            ..Default::default()
        };

        let state = state_with_components(
            repo.clone() as Arc<dyn WorkspaceRepository>,
            Arc::new(NoopMailer) as Arc<dyn Mailer>,
            Arc::new(db),
            None,
            None,
        );

        let response = leave_workspace(
            State(state),
            AuthSession(claims_fixture(member_id, "member@example.com")),
            axum::extract::Path(workspace_id),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(!repo.member_exists(workspace_id, member_id));
        assert_eq!(repo.membership_count(member_id), 1);
        assert!(repo.workspace_count() >= 2);
    }

    #[tokio::test]
    async fn remove_workspace_member_purges_shared_connections() {
        let workspace_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let member_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let workspace = Workspace {
            id: workspace_id,
            name: "Growth".into(),
            created_by: owner_id,
            owner_id,
            plan: PlanTier::Workspace.as_str().to_string(),
            stripe_overage_item_id: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        let members = vec![
            WorkspaceMember {
                workspace_id,
                user_id: owner_id,
                role: WorkspaceRole::Owner,
                joined_at: now,
                email: "owner@example.com".into(),
                first_name: "Owner".into(),
                last_name: "User".into(),
            },
            WorkspaceMember {
                workspace_id,
                user_id: member_id,
                role: WorkspaceRole::Admin,
                joined_at: now,
                email: "member@example.com".into(),
                first_name: "Member".into(),
                last_name: "User".into(),
            },
        ];

        let repo = Arc::new(RecordingWorkspaceRepo::seeded(workspace, members));
        let connection =
            workspace_connection_fixture(workspace_id, member_id, ConnectedOAuthProvider::Google);
        let connection_repo = Arc::new(CapturingWorkspaceConnectionRepo::with_connections(vec![
            connection.clone(),
        ]));

        let state = state_with_components(
            repo.clone() as Arc<dyn WorkspaceRepository>,
            Arc::new(NoopMailer) as Arc<dyn Mailer>,
            Arc::new(MockDb::default()),
            Some(connection_repo.clone() as Arc<dyn WorkspaceConnectionRepository>),
            None,
        );

        let response = remove_workspace_member(
            State(state),
            AuthSession(claims_fixture(owner_id, "owner@example.com")),
            axum::extract::Path((workspace_id, member_id)),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(connection_repo.deleted(), vec![connection.id]);
    }

    #[tokio::test]
    async fn leave_workspace_purges_shared_connections() {
        let workspace_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let member_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let workspace = Workspace {
            id: workspace_id,
            name: "Growth Team".into(),
            created_by: owner_id,
            owner_id,
            plan: PlanTier::Workspace.as_str().to_string(),
            stripe_overage_item_id: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        let members = vec![
            WorkspaceMember {
                workspace_id,
                user_id: owner_id,
                role: WorkspaceRole::Owner,
                joined_at: now,
                email: "owner@example.com".into(),
                first_name: "Owner".into(),
                last_name: "User".into(),
            },
            WorkspaceMember {
                workspace_id,
                user_id: member_id,
                role: WorkspaceRole::User,
                joined_at: now,
                email: "member@example.com".into(),
                first_name: "Member".into(),
                last_name: "User".into(),
            },
        ];

        let repo = Arc::new(RecordingWorkspaceRepo::seeded(workspace, members));
        let connection =
            workspace_connection_fixture(workspace_id, member_id, ConnectedOAuthProvider::Slack);
        let connection_repo = Arc::new(CapturingWorkspaceConnectionRepo::with_connections(vec![
            connection.clone(),
        ]));

        let db = Arc::new(MockDb {
            find_user_result: Some(User {
                id: member_id,
                email: "member@example.com".into(),
                password_hash: String::new(),
                first_name: "Member".into(),
                last_name: "User".into(),
                role: Some(UserRole::User),
                plan: None,
                company_name: None,
                stripe_customer_id: None,
                oauth_provider: Some(OauthProvider::Email),
                onboarded_at: Some(now),
                created_at: now,
                is_verified: true,
            }),
            ..Default::default()
        });

        let state = state_with_components(
            repo.clone() as Arc<dyn WorkspaceRepository>,
            Arc::new(NoopMailer) as Arc<dyn Mailer>,
            db,
            Some(connection_repo.clone() as Arc<dyn WorkspaceConnectionRepository>),
            None,
        );

        let response = leave_workspace(
            State(state),
            AuthSession(claims_fixture(member_id, "member@example.com")),
            axum::extract::Path(workspace_id),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(connection_repo.deleted(), vec![connection.id]);
    }

    #[tokio::test]
    async fn workspace_to_solo_execute_purges_member_connections() {
        let workspace_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let member_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let workspace = Workspace {
            id: workspace_id,
            name: "Growth Space".into(),
            created_by: owner_id,
            owner_id,
            plan: PlanTier::Workspace.as_str().to_string(),
            stripe_overage_item_id: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        let members = vec![
            WorkspaceMember {
                workspace_id,
                user_id: owner_id,
                role: WorkspaceRole::Owner,
                joined_at: now,
                email: "owner@example.com".into(),
                first_name: "Owner".into(),
                last_name: "User".into(),
            },
            WorkspaceMember {
                workspace_id,
                user_id: member_id,
                role: WorkspaceRole::User,
                joined_at: now,
                email: "member@example.com".into(),
                first_name: "Member".into(),
                last_name: "User".into(),
            },
        ];

        let repo = Arc::new(RecordingWorkspaceRepo::seeded(workspace, members));
        let connection =
            workspace_connection_fixture(workspace_id, member_id, ConnectedOAuthProvider::Google);
        let connection_repo = Arc::new(CapturingWorkspaceConnectionRepo::with_connections(vec![
            connection.clone(),
        ]));

        let state = state_with_components(
            repo.clone() as Arc<dyn WorkspaceRepository>,
            Arc::new(NoopMailer) as Arc<dyn Mailer>,
            Arc::new(MockDb::default()),
            Some(connection_repo.clone() as Arc<dyn WorkspaceConnectionRepository>),
            None,
        );

        let response = workspace_to_solo_execute(
            State(state),
            AuthSession(claims_fixture(owner_id, "owner@example.com")),
            Json(WorkspaceToSoloExecutePayload { workspace_id }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(connection_repo.deleted(), vec![connection.id]);
    }

    #[tokio::test]
    async fn recording_repo_resets_run_quota_each_month() {
        let workspace_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc()
            .replace_day(1)
            .unwrap()
            .replace_time(time::Time::MIDNIGHT);
        let next_month = (now + time::Duration::days(40))
            .replace_day(1)
            .unwrap()
            .replace_time(time::Time::MIDNIGHT);

        let workspace = Workspace {
            id: workspace_id,
            name: "Ops".into(),
            created_by: owner_id,
            owner_id,
            plan: PlanTier::Workspace.as_str().to_string(),
            stripe_overage_item_id: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        let repo = RecordingWorkspaceRepo::seeded(workspace, Vec::new());
        let limit = 2;
        assert!(
            repo.try_increment_workspace_run_quota(workspace_id, now, limit)
                .await
                .unwrap()
                .allowed
        );
        assert!(
            repo.try_increment_workspace_run_quota(workspace_id, now, limit)
                .await
                .unwrap()
                .allowed
        );
        let capped = repo
            .try_increment_workspace_run_quota(workspace_id, now, limit)
            .await
            .unwrap();
        assert!(!capped.allowed);
        assert_eq!(capped.run_count, limit + 1);
        assert_eq!(capped.overage_count, 1);
        assert!(capped.overage_incremented);

        // Next month starts fresh
        let refreshed = repo
            .try_increment_workspace_run_quota(workspace_id, next_month, limit)
            .await
            .unwrap();
        assert!(refreshed.allowed);
        assert_eq!(refreshed.run_count, 1);
        assert_eq!(refreshed.overage_count, 0);
    }

    #[tokio::test]
    async fn recording_repo_release_allows_reuse() {
        let workspace_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc()
            .replace_day(1)
            .unwrap()
            .replace_time(time::Time::MIDNIGHT);

        let workspace = Workspace {
            id: workspace_id,
            name: "Ops".into(),
            created_by: owner_id,
            owner_id,
            plan: PlanTier::Workspace.as_str().to_string(),
            stripe_overage_item_id: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        let repo = RecordingWorkspaceRepo::seeded(workspace, Vec::new());
        let limit = 1;
        let ticket = repo
            .try_increment_workspace_run_quota(workspace_id, now, limit)
            .await
            .unwrap();
        assert!(ticket.allowed);

        let capped = repo
            .try_increment_workspace_run_quota(workspace_id, now, limit)
            .await
            .unwrap();
        assert!(!capped.allowed);

        repo.release_workspace_run_quota(workspace_id, now, capped.overage_incremented)
            .await
            .unwrap();
        let usage_after_release = repo
            .get_workspace_run_quota(workspace_id, now)
            .await
            .unwrap();
        assert_eq!(usage_after_release.run_count, 1);
        assert_eq!(usage_after_release.overage_count, 0);

        let after_release = repo
            .try_increment_workspace_run_quota(workspace_id, now, limit)
            .await
            .unwrap();
        assert!(!after_release.allowed);
        assert_eq!(after_release.run_count, 2);
        assert_eq!(after_release.overage_count, 1);
    }

    #[tokio::test]
    async fn revoke_workspace_member_logs_audit_and_sends_notification() {
        let workspace_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let member_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();

        let workspace = Workspace {
            id: workspace_id,
            name: "Growth Team".into(),
            created_by: owner_id,
            owner_id,
            plan: PlanTier::Workspace.as_str().to_string(),
            stripe_overage_item_id: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };

        let members = vec![
            WorkspaceMember {
                workspace_id,
                user_id: owner_id,
                role: WorkspaceRole::Owner,
                joined_at: now,
                email: "owner@example.com".into(),
                first_name: "Owner".into(),
                last_name: "User".into(),
            },
            WorkspaceMember {
                workspace_id,
                user_id: member_id,
                role: WorkspaceRole::Viewer,
                joined_at: now,
                email: "member@example.com".into(),
                first_name: "Member".into(),
                last_name: "User".into(),
            },
        ];

        let repo = Arc::new(RecordingWorkspaceRepo::seeded(workspace.clone(), members));
        let mailer = Arc::new(RecordingMailer::new());

        let db = MockDb {
            find_user_result: Some(User {
                id: member_id,
                email: "member@example.com".into(),
                password_hash: String::new(),
                first_name: "Member".into(),
                last_name: "User".into(),
                role: Some(UserRole::User),
                plan: None,
                company_name: None,
                stripe_customer_id: None,
                oauth_provider: Some(OauthProvider::Email),
                onboarded_at: Some(now),
                created_at: now,
                is_verified: true,
            }),
            ..Default::default()
        };

        let state = state_with_components(
            repo.clone() as Arc<dyn WorkspaceRepository>,
            mailer.clone() as Arc<dyn Mailer>,
            Arc::new(db),
            None,
            None,
        );

        let payload = RevokeWorkspaceMemberPayload {
            member_id,
            reason: Some("Compliance issue".into()),
        };

        let response = revoke_workspace_member(
            State(state),
            AuthSession(claims_fixture(owner_id, "owner@example.com")),
            axum::extract::Path(workspace_id),
            Json(payload),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert!(!repo.member_exists(workspace_id, member_id));
        assert_eq!(repo.membership_count(member_id), 1);

        let audits = repo.audit_records();
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].0, workspace_id);
        assert_eq!(audits[0].1, member_id);
        assert_eq!(audits[0].2, "revoked");
        assert_eq!(audits[0].3, owner_id);
        assert_eq!(audits[0].4.as_deref(), Some("Compliance issue"));

        let sent = mailer.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, "member@example.com");
        assert_eq!(sent[0].1, format!("Removed from {}", workspace.name));
        assert!(sent[0].2.contains("Compliance issue"));
    }
}
