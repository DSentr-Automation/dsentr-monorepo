use axum::Json;
use axum::{extract::State, http::HeaderMap, response::IntoResponse};
use axum::{http::StatusCode, response::Response};
use time::OffsetDateTime;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::models::workspace::{Workspace, WorkspaceRole, WORKSPACE_PLAN_SOLO};
use crate::responses::JsonResponse;
use crate::state::AppState;
use crate::utils::change_history::log_workspace_history_event;

// Small helper: nested json lookup
fn jget<'a>(val: &'a serde_json::Value, path: &[&str]) -> Option<&'a serde_json::Value> {
    let mut cur = val;
    for key in path {
        cur = cur.get(*key)?;
    }
    Some(cur)
}

fn extract_str<'a>(val: &'a serde_json::Value, path: &[&str]) -> Option<&'a str> {
    jget(val, path)?.as_str()
}

fn extract_checkout_user_id(event: &serde_json::Value) -> Option<Uuid> {
    // checkout.session payload shape
    let obj = jget(event, &["data", "object"])?.clone();
    if let Some(uid) = obj
        .get("metadata")
        .and_then(|m| m.get("user_id"))
        .and_then(|v| v.as_str())
    {
        if let Ok(id) = Uuid::parse_str(uid) {
            return Some(id);
        }
    }
    if let Some(id_str) = obj.get("client_reference_id").and_then(|v| v.as_str()) {
        if let Ok(id) = Uuid::parse_str(id_str) {
            return Some(id);
        }
    }
    None
}

fn extract_customer_id(event: &serde_json::Value) -> Option<String> {
    extract_str(event, &["data", "object", "customer"]).map(|s| s.to_string())
}

fn extract_session_id(event: &serde_json::Value) -> Option<String> {
    extract_str(event, &["data", "object", "id"]).map(|s| s.to_string())
}

fn extract_i64(val: &serde_json::Value, path: &[&str]) -> Option<i64> {
    jget(val, path)?.as_i64()
}

fn extract_failure_message(event: &serde_json::Value) -> Option<String> {
    // Try PaymentIntent last_payment_error.message
    if let Some(val) = jget(event, &["data", "object", "last_payment_error", "message"]) {
        if let Some(s) = val.as_str() {
            return Some(s.to_string());
        }
    }
    // Try invoice.last_finalization_error.message
    if let Some(val) = jget(
        event,
        &["data", "object", "last_finalization_error", "message"],
    ) {
        if let Some(s) = val.as_str() {
            return Some(s.to_string());
        }
    }
    None
}

fn extract_bool(root: &serde_json::Value, path: &[&str]) -> Option<bool> {
    let mut current = root;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_bool()
}

async fn handle_stripe_event(
    app_state: &AppState,
    evt_type: &str,
    payload: &serde_json::Value,
) -> Response {
    match evt_type {
        // Primary success signal for Checkout-based upgrades
        "checkout.session.completed" => {
            let session_id = match extract_session_id(payload) {
                Some(id) => id,
                None => {
                    warn!("checkout.session.completed missing session id");
                    return Json(serde_json::json!({ "received": true })).into_response();
                }
            };
            let stripe_customer_id = extract_customer_id(payload);
            let subscription_id =
                extract_str(payload, &["data", "object", "subscription"]).map(|s| s.to_string());

            // Resolve user
            let mut user_id: Option<Uuid> = extract_checkout_user_id(payload);
            if user_id.is_none() {
                if let Some(customer_id) = stripe_customer_id.as_deref() {
                    match app_state
                        .db
                        .find_user_id_by_stripe_customer_id(customer_id)
                        .await
                    {
                        Ok(opt) => user_id = opt,
                        Err(err) => {
                            error!(?err, customer_id, "failed to map stripe customer to user")
                        }
                    }
                }
            }

            let user_id = match user_id {
                Some(id) => id,
                None => {
                    warn!(evt_type, "unable to resolve user for checkout completion");
                    return Json(serde_json::json!({ "received": true })).into_response();
                }
            };

            // Load user settings and confirm pending checkout session id to ensure idempotency
            let mut settings = match app_state.db.get_user_settings(user_id).await {
                Ok(val) => val,
                Err(err) => {
                    error!(?err, %user_id, "failed to load user settings for checkout completion");
                    return Json(serde_json::json!({ "received": true })).into_response();
                }
            };

            let mut proceed = false;
            let mut workspace_name_opt: Option<String> = None;
            let mut shared_workflow_ids: Vec<Uuid> = Vec::new();
            if let Some(root) = settings.as_object() {
                if let Some(billing) = root.get("billing").and_then(|b| b.as_object()) {
                    if let Some(pending) = billing.get("pending_checkout") {
                        if let Some(pending_obj) = pending.as_object() {
                            let matches = pending_obj
                                .get("session_id")
                                .and_then(|v| v.as_str())
                                .map(|sid| sid == session_id)
                                .unwrap_or(false);
                            if matches {
                                proceed = true;
                                workspace_name_opt = pending_obj
                                    .get("workspace_name")
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.to_string());
                                if let Some(arr) = pending_obj
                                    .get("shared_workflow_ids")
                                    .and_then(|v| v.as_array())
                                {
                                    for v in arr {
                                        if let Some(s) = v.as_str() {
                                            if let Ok(id) = Uuid::parse_str(s) {
                                                shared_workflow_ids.push(id);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if !proceed {
                // Already processed or not our session; acknowledge and no-op for idempotency
                info!(%user_id, %session_id, "ignoring checkout completion without pending session");
                return Json(serde_json::json!({ "received": true })).into_response();
            }

            // Prefer workspace name from settings; fallback to metadata
            if workspace_name_opt.is_none() {
                if let Some(name) =
                    extract_str(payload, &["data", "object", "metadata", "workspace_name"])
                {
                    workspace_name_opt = Some(name.to_string());
                }
            }
            let workspace_name = workspace_name_opt.unwrap_or_else(|| "My Workspace".to_string());
            let overage_price_id = match std::env::var("STRIPE_OVERAGE_PRICE_ID") {
                Ok(val) if !val.trim().is_empty() => val,
                _ => {
                    error!(%user_id, "STRIPE_OVERAGE_PRICE_ID is not configured");
                    return JsonResponse::server_error("Billing is not configured").into_response();
                }
            };

            // Persist customer id if present
            if let Some(customer_id) = stripe_customer_id.as_deref() {
                if let Err(err) = app_state
                    .db
                    .set_user_stripe_customer_id(user_id, customer_id)
                    .await
                {
                    warn!(?err, %user_id, customer_id, "failed to persist stripe customer id on checkout completion");
                }
            }

            let mut subscription_info: Option<crate::services::stripe::SubscriptionInfo> = None;
            if let Some(sub_id) = subscription_id.as_deref() {
                match app_state.stripe.get_subscription(sub_id).await {
                    Ok(sub) => subscription_info = Some(sub),
                    Err(err) => {
                        error!(?err, %user_id, subscription_id=sub_id, "failed to load subscription for checkout completion");
                        return JsonResponse::server_error("Failed to finalize subscription")
                            .into_response();
                    }
                }
            } else if let Some(customer_id) = stripe_customer_id.as_deref() {
                match app_state
                    .stripe
                    .get_active_subscription_for_customer(customer_id)
                    .await
                {
                    Ok(opt) => subscription_info = opt,
                    Err(err) => {
                        error!(?err, %user_id, customer_id, "failed to load active subscription during checkout completion");
                        return JsonResponse::server_error("Failed to finalize subscription")
                            .into_response();
                    }
                }
            }

            let mut reused_existing_workspace = false;
            let mut workspace: Option<Workspace> = None;
            if let Ok(memberships) = app_state
                .workspace_repo
                .list_memberships_for_user(user_id)
                .await
            {
                let owned: Vec<_> = memberships
                    .into_iter()
                    .filter(|m| m.workspace.owner_id == user_id)
                    .collect();

                let personal = owned
                    .iter()
                    .find(|m| m.workspace.plan == WORKSPACE_PLAN_SOLO)
                    .cloned()
                    .or_else(|| owned.into_iter().next());

                if let Some(summary) = personal {
                    let workspace_id = summary.workspace.id;
                    let mut current = summary.workspace.clone();
                    let mut reuse_candidate = true;

                    if current.plan != "workspace" {
                        match app_state
                            .workspace_repo
                            .update_workspace_plan(workspace_id, "workspace")
                            .await
                        {
                            Ok(updated) => current = updated,
                            Err(err) => {
                                reuse_candidate = false;
                                warn!(
                                    ?err,
                                    %user_id,
                                    %workspace_id,
                                    "failed to promote existing workspace plan during checkout completion"
                                );
                            }
                        }
                    }

                    if reuse_candidate && current.name != workspace_name {
                        let previous_name = current.name.clone();
                        match app_state
                            .workspace_repo
                            .update_workspace_name(workspace_id, &workspace_name)
                            .await
                        {
                            Ok(updated) => {
                                log_workspace_history_event(
                                    app_state,
                                    workspace_id,
                                    user_id,
                                    vec![serde_json::json!({
                                        "path": "workspace.name",
                                        "from": previous_name,
                                        "to": updated.name.clone(),
                                    })],
                                )
                                .await;
                                current = updated;
                            }
                            Err(err) => warn!(
                                ?err,
                                %user_id,
                                %workspace_id,
                                "failed to update workspace name during checkout completion"
                            ),
                        }
                    }

                    if reuse_candidate {
                        reused_existing_workspace = true;
                        workspace = Some(current);
                    }
                }
            }

            let mut workspace = match workspace {
                Some(ws) => ws,
                None => match app_state
                    .workspace_repo
                    .create_workspace(&workspace_name, user_id, "workspace")
                    .await
                {
                    Ok(ws) => {
                        reused_existing_workspace = false;
                        ws
                    }
                    Err(err) => {
                        error!(?err, %user_id, workspace_name, "failed to create workspace on checkout completion");
                        return Json(serde_json::json!({ "received": true })).into_response();
                    }
                },
            };

            if !reused_existing_workspace {
                if let Err(err) = app_state
                    .workspace_repo
                    .add_member(workspace.id, user_id, WorkspaceRole::Owner)
                    .await
                {
                    warn!(?err, %user_id, workspace_id=%workspace.id, "failed to add owner membership (may already exist)");
                }
            }

            // Promote personal plan to workspace
            if let Err(err) = app_state.db.update_user_plan(user_id, "workspace").await {
                warn!(?err, %user_id, "failed to set user plan to workspace");
            }

            // Share requested workflows into the new workspace (if any were recorded)
            for wid in shared_workflow_ids {
                if let Err(err) = app_state
                    .workflow_repo
                    .set_workflow_workspace(user_id, wid, Some(workspace.id))
                    .await
                    .map(|_| ())
                {
                    warn!(?err, %user_id, workflow_id=%wid, workspace_id=%workspace.id, "failed to share workflow during upgrade");
                }
            }

            if workspace.stripe_overage_item_id.is_none() {
                let sub = match subscription_info.as_ref() {
                    Some(sub) => sub,
                    None => {
                        error!(%user_id, workspace_id=%workspace.id, "subscription missing for checkout completion");
                        return JsonResponse::server_error("Subscription not found for workspace")
                            .into_response();
                    }
                };
                let overage_item_id = match sub
                    .items
                    .iter()
                    .find(|item| item.price_id == overage_price_id)
                {
                    Some(item) => item.id.clone(),
                    None => {
                        error!(%user_id, workspace_id=%workspace.id, "subscription missing overage item");
                        return JsonResponse::server_error(
                            "Subscription is missing metered overage item",
                        )
                        .into_response();
                    }
                };

                if let Err(err) = app_state
                    .workspace_repo
                    .set_stripe_overage_item_id(workspace.id, Some(&overage_item_id))
                    .await
                {
                    error!(?err, %user_id, workspace_id=%workspace.id, "failed to persist overage subscription item id");
                    return JsonResponse::server_error("Failed to persist subscription state")
                        .into_response();
                }
                workspace.stripe_overage_item_id = Some(overage_item_id);
            }

            // Mark onboarding complete if not already
            if let Err(err) = app_state
                .db
                .mark_workspace_onboarded(user_id, OffsetDateTime::now_utc())
                .await
            {
                // Not fatal
                warn!(?err, %user_id, "failed to mark onboarding complete");
            }

            // Clear pending checkout and any prior error state
            if let Some(root) = settings.as_object_mut() {
                root.entry("billing")
                    .or_insert_with(|| serde_json::json!({}));
                if let Some(billing) = root.get_mut("billing").and_then(|b| b.as_object_mut()) {
                    billing.insert("pending_checkout".to_string(), serde_json::Value::Null);
                    billing.remove("last_error");
                    billing.remove("last_error_at");
                }
            }
            if let Err(err) = app_state.db.update_user_settings(user_id, settings).await {
                warn!(?err, %user_id, "failed to clear pending checkout after completion");
            }

            if let Some(sub) = subscription_info.as_ref() {
                if let (Ok(period_start), Ok(period_end)) = (
                    OffsetDateTime::from_unix_timestamp(sub.current_period_start),
                    OffsetDateTime::from_unix_timestamp(sub.current_period_end),
                ) {
                    app_state
                        .sync_owned_workspace_billing_cycles(
                            user_id,
                            &sub.id,
                            period_start,
                            period_end,
                        )
                        .await;
                }
            } else if let Some(customer_id) = stripe_customer_id.as_deref() {
                match app_state
                    .stripe
                    .get_active_subscription_for_customer(customer_id)
                    .await
                {
                    Ok(Some(sub)) => {
                        if let (Ok(period_start), Ok(period_end)) = (
                            OffsetDateTime::from_unix_timestamp(sub.current_period_start),
                            OffsetDateTime::from_unix_timestamp(sub.current_period_end),
                        ) {
                            app_state
                                .sync_owned_workspace_billing_cycles(
                                    user_id,
                                    &sub.id,
                                    period_start,
                                    period_end,
                                )
                                .await;
                        }
                    }
                    Ok(None) => {}
                    Err(err) => {
                        warn!(
                            ?err,
                            %user_id,
                            customer_id,
                            "failed to sync billing period after checkout completion"
                        );
                    }
                }
            }

            info!(%user_id, workspace_id=%workspace.id, %session_id, "completed workspace upgrade");
            Json(serde_json::json!({ "received": true })).into_response()
        }

        // Handle failure-style events: payment intent failure, invoice failure, async failure/expired
        "payment_intent.payment_failed"
        | "checkout.session.async_payment_failed"
        | "checkout.session.expired" => {
            let mut user_id: Option<Uuid> = None;
            if evt_type.starts_with("checkout.session") {
                user_id = extract_checkout_user_id(payload);
            }

            if user_id.is_none() {
                if let Some(customer_id) = extract_customer_id(payload) {
                    match app_state
                        .db
                        .find_user_id_by_stripe_customer_id(&customer_id)
                        .await
                    {
                        Ok(opt) => user_id = opt,
                        Err(err) => {
                            error!(?err, customer_id, "failed to map stripe customer to user")
                        }
                    }
                }
            }

            if let Some(uid) = user_id {
                let msg = extract_failure_message(payload).unwrap_or_else(|| {
                    "Payment failed. Please update your card or try again.".to_string()
                });
                if let Err(err) = app_state
                    .db
                    .clear_pending_checkout_with_error(uid, &msg)
                    .await
                {
                    error!(?err, %uid, "failed to record checkout failure in settings");
                }

                // Roll back personal plan if necessary
                if let Ok(Some(user)) = app_state.db.find_public_user_by_id(uid).await {
                    if user.plan.as_deref() == Some("workspace") {
                        if let Err(err) = app_state.db.update_user_plan(uid, "solo").await {
                            warn!(?err, %uid, "failed to rollback user plan to solo");
                        }
                    }
                }

                // Downgrade any owned workspaces back to solo
                if let Ok(memberships) = app_state
                    .workspace_repo
                    .list_memberships_for_user(uid)
                    .await
                {
                    for m in memberships.into_iter().filter(|m| {
                        m.workspace.owner_id == uid && m.workspace.plan.as_str() != "solo"
                    }) {
                        if let Err(err) = app_state
                            .workspace_repo
                            .update_workspace_plan(m.workspace.id, "solo")
                            .await
                        {
                            warn!(?err, workspace_id=%m.workspace.id, %uid, "failed to rollback workspace plan to solo");
                        }
                    }
                }
                app_state.clear_owned_workspace_billing_cycles(uid).await;

                warn!(%uid, evt_type, "recorded billing failure and cleared pending checkout");
            } else {
                warn!(
                    evt_type,
                    "billing failure event received but user not identified"
                );
            }

            Json(serde_json::json!({ "received": true })).into_response()
        }

        // Subscription canceled at period end -> revert user back to solo
        "customer.subscription.deleted" => {
            // Resolve user by customer id
            let mut user_id: Option<Uuid> = None;
            if let Some(customer_id) = extract_customer_id(payload) {
                match app_state
                    .db
                    .find_user_id_by_stripe_customer_id(&customer_id)
                    .await
                {
                    Ok(opt) => user_id = opt,
                    Err(err) => error!(
                        ?err,
                        customer_id,
                        "failed to map stripe customer to user for subscription deletion"
                    ),
                }
            }

            if let Some(uid) = user_id {
                if let Err(err) = app_state.db.clear_stripe_customer_id(uid).await {
                    warn!(?err, %uid, "failed to clear stale stripe_customer_id");
                } // Update personal plan back to solo
                if let Err(err) = app_state.db.update_user_plan(uid, "solo").await {
                    warn!(?err, %uid, "failed to set user plan to solo on subscription deletion");
                }

                // Downgrade any owned workspaces back to solo
                if let Ok(memberships) = app_state
                    .workspace_repo
                    .list_memberships_for_user(uid)
                    .await
                {
                    for m in memberships.into_iter().filter(|m| {
                        m.workspace.owner_id == uid && m.workspace.plan.as_str() != "solo"
                    }) {
                        let wid = m.workspace.id;

                        if let Err(err) = app_state
                            .workspace_repo
                            .update_workspace_plan(wid, "solo")
                            .await
                        {
                            warn!(
                                ?err,
                                workspace_id=%wid,
                                %uid,
                                "failed to downgrade workspace to solo on subscription deletion"
                            );
                            continue;
                        }

                        if let Err(err) = app_state
                            .workspace_repo
                            .disable_webhook_signing_for_workspace(wid)
                            .await
                        {
                            warn!(
                                ?err,
                                workspace_id=%wid,
                                %uid,
                                "failed to disable webhook signing on subscription deletion"
                            );
                        }
                    }
                }
                app_state.clear_owned_workspace_billing_cycles(uid).await;

                info!(%uid, "processed subscription deletion: reverted plan to solo");
            } else {
                warn!(
                    evt_type,
                    "subscription deletion received but user not identified"
                );
            }

            Json(serde_json::json!({ "received": true })).into_response()
        }
        "customer.subscription.updated" => {
            // Resolve user by customer id
            let mut user_id: Option<Uuid> = None;
            if let Some(customer_id) = extract_customer_id(payload) {
                match app_state
                    .db
                    .find_user_id_by_stripe_customer_id(&customer_id)
                    .await
                {
                    Ok(opt) => user_id = opt,
                    Err(err) => error!(
                        ?err,
                        customer_id,
                        "failed to map stripe customer to user for subscription update"
                    ),
                }
            }

            if let Some(uid) = user_id {
                // status and cancel_at_period_end from payload
                let status =
                    extract_str(payload, &["data", "object", "status"]).unwrap_or("unknown");

                let cancel_at_period_end =
                    extract_bool(payload, &["data", "object", "cancel_at_period_end"])
                        .unwrap_or(false);
                let subscription_id =
                    extract_str(payload, &["data", "object", "id"]).map(|s| s.to_string());
                let period_bounds = match (
                    extract_i64(payload, &["data", "object", "current_period_start"]),
                    extract_i64(payload, &["data", "object", "current_period_end"]),
                ) {
                    (Some(start), Some(end)) => {
                        let start_dt = OffsetDateTime::from_unix_timestamp(start).ok();
                        let end_dt = OffsetDateTime::from_unix_timestamp(end).ok();
                        if let (Some(start_dt), Some(end_dt)) = (start_dt, end_dt) {
                            Some((start_dt, end_dt))
                        } else {
                            None
                        }
                    }
                    _ => None,
                };

                match (status, cancel_at_period_end) {
                    // cancel at period end: keep Workspace until sub.deleted
                    ("active", true) | ("canceled", true) => {
                        if let (Some((start, end)), Some(sub_id)) =
                            (period_bounds, subscription_id.as_ref())
                        {
                            app_state
                                .sync_owned_workspace_billing_cycles(uid, sub_id, start, end)
                                .await;
                        }
                        info!(
                            %uid,
                            status,
                            "subscription marked to cancel at period end; no immediate downgrade"
                        );
                    }

                    // immediate cancel: downgrade now
                    ("canceled", false) => {
                        info!(
                            %uid,
                            "subscription canceled immediately; downgrading workspaces to solo"
                        );

                        if let Err(err) = app_state.db.update_user_plan(uid, "solo").await {
                            warn!(
                                ?err,
                                %uid,
                                "failed to set user plan to solo on immediate cancellation"
                            );
                        }

                        if let Ok(memberships) = app_state
                            .workspace_repo
                            .list_memberships_for_user(uid)
                            .await
                        {
                            for m in memberships.into_iter().filter(|m| {
                                m.workspace.owner_id == uid && m.workspace.plan.as_str() != "solo"
                            }) {
                                let wid = m.workspace.id;

                                if let Err(err) = app_state
                                    .workspace_repo
                                    .update_workspace_plan(wid, "solo")
                                    .await
                                {
                                    warn!(
                                        ?err,
                                        workspace_id=%wid,
                                        %uid,
                                        "failed to downgrade workspace to solo on immediate cancellation"
                                    );
                                    continue;
                                }

                                if let Err(err) = app_state
                                    .workspace_repo
                                    .disable_webhook_signing_for_workspace(wid)
                                    .await
                                {
                                    warn!(
                                        ?err,
                                        workspace_id=%wid,
                                        %uid,
                                        "failed to disable webhook signing on immediate cancellation"
                                    );
                                }
                            }
                        }
                        app_state.clear_owned_workspace_billing_cycles(uid).await;
                    }

                    _ => {
                        if let (Some((start, end)), Some(sub_id)) =
                            (period_bounds, subscription_id.as_ref())
                        {
                            app_state
                                .sync_owned_workspace_billing_cycles(uid, sub_id, start, end)
                                .await;
                        }
                        info!(
                            %uid,
                            status,
                            "subscription updated; no downgrade action taken"
                        );
                    }
                }
            } else {
                warn!(
                    evt_type,
                    "subscription update received but user not identified"
                );
            }

            Json(serde_json::json!({ "received": true })).into_response()
        }
        "invoice.payment_failed" => {
            // Resolve user from customer ID
            let mut user_id: Option<Uuid> = None;
            if let Some(customer_id) = extract_customer_id(payload) {
                match app_state
                    .db
                    .find_user_id_by_stripe_customer_id(&customer_id)
                    .await
                {
                    Ok(opt) => user_id = opt,
                    Err(err) => error!(?err, customer_id, "failed to map stripe customer to user"),
                }
            }

            if let Some(uid) = user_id {
                let msg = extract_failure_message(payload).unwrap_or_else(|| {
                    "Payment failed. Please update your card or try again.".to_string()
                });

                // Restore old behavior: clear pending checkout + record error
                if let Err(err) = app_state
                    .db
                    .clear_pending_checkout_with_error(uid, &msg)
                    .await
                {
                    error!(?err, %uid, "failed to record checkout failure in settings");
                }

                // DO NOT downgrade immediately. Renewal failure enters grace period.
                warn!(
                    %uid,
                    evt_type,
                    "invoice payment failed for renewal; not downgrading (grace period active)"
                );

                Json(serde_json::json!({ "received": true })).into_response()
            } else {
                warn!(
                    evt_type,
                    "invoice payment failed but user could not be resolved"
                );
                Json(serde_json::json!({ "received": true })).into_response()
            }
        }
        // Other events acknowledged to avoid retries; primary logic handled above.
        _ => {
            info!(evt_type, "unhandled stripe event acknowledged");
            Json(serde_json::json!({ "received": true })).into_response()
        }
    }
}

// POST /api/stripe/webhook
pub async fn webhook(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let sig = match headers
        .get("Stripe-Signature")
        .and_then(|h| h.to_str().ok())
    {
        Some(s) => s,
        None => return JsonResponse::bad_request("Missing Stripe-Signature").into_response(),
    };

    let evt = match app_state.stripe.verify_webhook(&body, sig) {
        Ok(e) => e,
        Err(err) => {
            warn!(?err, "stripe webhook verification failed");
            return (StatusCode::BAD_REQUEST, "invalid webhook").into_response();
        }
    };

    let event_id = evt.id.clone();
    let evt_type = evt.r#type.as_str();
    let payload = &evt.payload;

    // Start tx only if the repo wants one
    let mut tx_opt = if app_state.stripe_event_log_repo.supports_transactions() {
        match app_state.db_pool.begin().await {
            Ok(tx) => Some(tx),
            Err(err) => {
                error!(?err, %event_id, "failed to start webhook transaction");
                return JsonResponse::server_error("Failed to process webhook").into_response();
            }
        }
    } else {
        None
    };

    // Advisory lock only when we have a real transaction
    if let Some(tx) = tx_opt.as_mut() {
        if !cfg!(test) {
            let conn: &mut sqlx::PgConnection = &mut *tx;
            if let Err(err) =
                sqlx::query::<sqlx::Postgres>("SELECT pg_advisory_xact_lock(hashtext($1))")
                    .bind(&event_id)
                    .execute(conn)
                    .await
            {
                warn!(?err, %event_id, "failed to acquire advisory lock for stripe event");
            }
        }
    }

    // Idempotency check
    match app_state
        .stripe_event_log_repo
        .has_processed_event(&event_id, tx_opt.as_mut())
        .await
    {
        Ok(true) => {
            if let Some(tx) = tx_opt.take() {
                if let Err(err) = tx.commit().await {
                    warn!(?err, %event_id, "failed to commit no-op webhook transaction");
                }
            }
            return Json(serde_json::json!({ "received": true })).into_response();
        }
        Err(err) => {
            error!(?err, %event_id, "failed to check stripe event log");
            if let Some(tx) = tx_opt.take() {
                let _ = tx.rollback().await;
            }
            return JsonResponse::server_error("Failed to process webhook").into_response();
        }
        Ok(false) => {}
    }

    // Main handler
    let response = handle_stripe_event(&app_state, evt_type, payload).await;

    if response.status().is_success() {
        if let Err(err) = app_state
            .stripe_event_log_repo
            .record_event(&event_id, tx_opt.as_mut())
            .await
        {
            error!(?err, %event_id, "failed to record stripe event");
            if let Some(tx) = tx_opt.take() {
                let _ = tx.rollback().await;
            }
            return JsonResponse::server_error("Failed to persist webhook status").into_response();
        }

        if let Some(tx) = tx_opt.take() {
            if let Err(err) = tx.commit().await {
                error!(?err, %event_id, "failed to commit stripe webhook transaction");
                return JsonResponse::server_error("Failed to finalize webhook").into_response();
            }
        }

        response
    } else {
        if let Some(tx) = tx_opt.take() {
            let _ = tx.rollback().await;
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Config, OAuthProviderConfig, OAuthSettings, StripeSettings, DEFAULT_WORKSPACE_MEMBER_LIMIT,
        DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT, RUNAWAY_LIMIT_5MIN,
    };
    use crate::db::mock_db::{MockDb, NoopWorkflowRepository};
    use crate::db::mock_stripe_event_log_repository::MockStripeEventLogRepository;
    use crate::db::workspace_repository::{
        WorkspaceRepository, WorkspaceRunQuotaUpdate, WorkspaceRunUsage,
    };
    use crate::models::plan::PlanTier;
    use crate::models::user::{OauthProvider, User, UserRole};
    use crate::models::workspace::{
        Workspace, WorkspaceBillingCycle, WorkspaceMember, WorkspaceMembershipSummary,
        WorkspaceRole,
    };
    use crate::services::smtp_mailer::MockMailer;
    use crate::services::stripe::{MockStripeService, SubscriptionInfo, SubscriptionItemInfo};
    use crate::state::{test_pg_pool, AppState};
    use crate::utils::{jwt::JwtKeys, plan_limits::NormalizedPlanTier};
    use axum::extract::State as AxumState;
    use axum::http::{HeaderMap, HeaderValue};
    use reqwest::Client;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use time::OffsetDateTime;
    use uuid::Uuid;

    #[derive(Clone, Default)]
    struct TestWorkspaceRepo {
        workspaces: Arc<Mutex<Vec<Workspace>>>,
        created: Arc<Mutex<Vec<Workspace>>>,
        added_members: Arc<Mutex<Vec<(Uuid, Uuid, WorkspaceRole)>>>,
        memberships: Arc<Mutex<Vec<WorkspaceMembershipSummary>>>,
        plan_updates: Arc<Mutex<Vec<(Uuid, String)>>>,
        name_updates: Arc<Mutex<Vec<(Uuid, String)>>>,
        #[allow(clippy::type_complexity)]
        run_usage: Arc<Mutex<HashMap<(Uuid, i64), (i64, i64)>>>,
        billing_cycles: Arc<Mutex<HashMap<Uuid, WorkspaceBillingCycle>>>,
        overage_items: Arc<Mutex<HashMap<Uuid, Option<String>>>>,
    }

    #[async_trait::async_trait]
    impl WorkspaceRepository for TestWorkspaceRepo {
        async fn create_workspace(
            &self,
            name: &str,
            created_by: Uuid,
            plan: &str,
        ) -> Result<Workspace, sqlx::Error> {
            let now = OffsetDateTime::now_utc();
            let ws = Workspace {
                id: Uuid::new_v4(),
                name: name.to_string(),
                created_by,
                owner_id: created_by,
                plan: plan.to_string(),
                stripe_overage_item_id: None,
                created_at: now,
                updated_at: now,
                deleted_at: None,
            };
            self.created.lock().unwrap().push(ws.clone());
            self.workspaces.lock().unwrap().push(ws.clone());
            Ok(ws)
        }

        async fn update_workspace_name(
            &self,
            workspace_id: Uuid,
            name: &str,
        ) -> Result<Workspace, sqlx::Error> {
            let mut list = self.workspaces.lock().unwrap();
            if let Some(ws) = list.iter_mut().find(|w| w.id == workspace_id) {
                ws.name = name.to_string();
                ws.updated_at = OffsetDateTime::now_utc();
                self.name_updates
                    .lock()
                    .unwrap()
                    .push((workspace_id, name.to_string()));
                Ok(ws.clone())
            } else {
                let now = OffsetDateTime::now_utc();
                let ws = Workspace {
                    id: workspace_id,
                    name: name.to_string(),
                    created_by: Uuid::nil(),
                    owner_id: Uuid::nil(),
                    plan: "workspace".into(),
                    stripe_overage_item_id: None,
                    created_at: now,
                    updated_at: now,
                    deleted_at: None,
                };
                list.push(ws.clone());
                self.name_updates
                    .lock()
                    .unwrap()
                    .push((workspace_id, name.to_string()));
                Ok(ws)
            }
        }

        async fn update_workspace_plan(
            &self,
            workspace_id: Uuid,
            plan: &str,
        ) -> Result<Workspace, sqlx::Error> {
            let mut list = self.workspaces.lock().unwrap();
            if let Some(ws) = list.iter_mut().find(|w| w.id == workspace_id) {
                ws.plan = plan.to_string();
                ws.updated_at = OffsetDateTime::now_utc();
                self.plan_updates
                    .lock()
                    .unwrap()
                    .push((workspace_id, plan.to_string()));
                Ok(ws.clone())
            } else {
                // In tests, we may not have seeded the workspace list; still record the update
                let now = OffsetDateTime::now_utc();
                let ws = Workspace {
                    id: workspace_id,
                    name: "test".into(),
                    created_by: Uuid::nil(),
                    owner_id: Uuid::nil(),
                    plan: plan.to_string(),
                    stripe_overage_item_id: None,
                    created_at: now,
                    updated_at: now,
                    deleted_at: None,
                };
                list.push(ws.clone());
                self.plan_updates
                    .lock()
                    .unwrap()
                    .push((workspace_id, plan.to_string()));
                Ok(ws)
            }
        }

        async fn get_plan(&self, workspace_id: Uuid) -> Result<PlanTier, sqlx::Error> {
            let list = self.workspaces.lock().unwrap();
            let plan = list
                .iter()
                .find(|workspace| workspace.id == workspace_id)
                .map(|workspace| workspace.plan.clone())
                .ok_or(sqlx::Error::RowNotFound)?;
            let normalized = NormalizedPlanTier::from_option(Some(plan.as_str()));
            Ok(PlanTier::from(normalized))
        }

        async fn find_workspace(
            &self,
            _workspace_id: Uuid,
        ) -> Result<Option<Workspace>, sqlx::Error> {
            Ok(None)
        }

        async fn set_stripe_overage_item_id(
            &self,
            workspace_id: Uuid,
            subscription_item_id: Option<&str>,
        ) -> Result<(), sqlx::Error> {
            if let Some(ws) = self
                .workspaces
                .lock()
                .unwrap()
                .iter_mut()
                .find(|w| w.id == workspace_id)
            {
                ws.stripe_overage_item_id = subscription_item_id.map(|s| s.to_string());
            }
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
            if let Some(ws) = self
                .workspaces
                .lock()
                .unwrap()
                .iter()
                .find(|w| w.id == workspace_id)
            {
                return Ok(ws.stripe_overage_item_id.clone());
            }
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
            self.added_members
                .lock()
                .unwrap()
                .push((workspace_id, user_id, role));
            Ok(())
        }

        async fn set_member_role(
            &self,
            _workspace_id: Uuid,
            _user_id: Uuid,
            _role: WorkspaceRole,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }
        async fn remove_member(
            &self,
            _workspace_id: Uuid,
            _user_id: Uuid,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }
        async fn leave_workspace(
            &self,
            _workspace_id: Uuid,
            _user_id: Uuid,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }
        async fn revoke_member(
            &self,
            _workspace_id: Uuid,
            _member_id: Uuid,
            _revoked_by: Uuid,
            _reason: Option<&str>,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }
        async fn list_members(
            &self,
            _workspace_id: Uuid,
        ) -> Result<Vec<WorkspaceMember>, sqlx::Error> {
            Ok(vec![])
        }

        async fn count_members(&self, workspace_id: Uuid) -> Result<i64, sqlx::Error> {
            let members = self.memberships.lock().unwrap();
            let count = members
                .iter()
                .filter(|membership| membership.workspace.id == workspace_id)
                .count();
            Ok(count as i64)
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
            Ok(true)
        }

        async fn list_memberships_for_user(
            &self,
            _user_id: Uuid,
        ) -> Result<Vec<WorkspaceMembershipSummary>, sqlx::Error> {
            Ok(self.memberships.lock().unwrap().clone())
        }
        async fn list_user_workspaces(
            &self,
            _user_id: Uuid,
        ) -> Result<Vec<WorkspaceMembershipSummary>, sqlx::Error> {
            Ok(vec![])
        }
        async fn create_workspace_invitation(
            &self,
            _workspace_id: Uuid,
            _email: &str,
            _role: WorkspaceRole,
            _token: &str,
            _expires_at: OffsetDateTime,
            _created_by: Uuid,
        ) -> Result<crate::models::workspace::WorkspaceInvitation, sqlx::Error> {
            unimplemented!()
        }
        async fn list_workspace_invitations(
            &self,
            _workspace_id: Uuid,
        ) -> Result<Vec<crate::models::workspace::WorkspaceInvitation>, sqlx::Error> {
            Ok(vec![])
        }
        async fn revoke_workspace_invitation(&self, _invite_id: Uuid) -> Result<(), sqlx::Error> {
            Ok(())
        }
        async fn find_invitation_by_token(
            &self,
            _token: &str,
        ) -> Result<Option<crate::models::workspace::WorkspaceInvitation>, sqlx::Error> {
            Ok(None)
        }
        async fn mark_invitation_accepted(&self, _invite_id: Uuid) -> Result<(), sqlx::Error> {
            Ok(())
        }
        async fn mark_invitation_declined(&self, _invite_id: Uuid) -> Result<(), sqlx::Error> {
            Ok(())
        }
        async fn list_pending_invitations_for_email(
            &self,
            _email: &str,
        ) -> Result<Vec<crate::models::workspace::WorkspaceInvitation>, sqlx::Error> {
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

    fn test_config() -> Arc<Config> {
        Arc::new(Config {
            database_url: String::new(),
            frontend_origin: "https://app.example.com".into(),
            admin_origin: "https://app.example.com".into(),
            oauth: OAuthSettings {
                google: OAuthProviderConfig {
                    client_id: "client".into(),
                    client_secret: "secret".into(),
                    redirect_uri: "https://app.example.com/oauth/google".into(),
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
                token_encryption_key: vec![0; 32],
            },
            api_secrets_encryption_key: vec![1; 32],
            stripe: StripeSettings {
                client_id: "stub".into(),
                secret_key: "stub".into(),
                webhook_secret: "0123456789abcdef0123456789ABCDEF".into(),
            },
            auth_cookie_secure: true,
            jwt_issuer: "test-issuer".into(),
            jwt_audience: "test-audience".into(),
            workspace_member_limit: DEFAULT_WORKSPACE_MEMBER_LIMIT,
            workspace_monthly_run_limit: DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT,
            runaway_limit_5min: RUNAWAY_LIMIT_5MIN,
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

    #[tokio::test]
    async fn webhook_checkout_session_completed_promotes_existing_workspace_and_clears_pending() {
        let user_id = Uuid::new_v4();
        let session_id = "cs_test_123";
        let now = OffsetDateTime::now_utc();
        std::env::set_var("STRIPE_OVERAGE_PRICE_ID", "price_overage_test");
        let personal_workspace = Workspace {
            id: Uuid::new_v4(),
            name: "Owner's Workspace".into(),
            created_by: user_id,
            owner_id: user_id,
            plan: WORKSPACE_PLAN_SOLO.into(),
            stripe_overage_item_id: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };
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
                onboarded_at: None,
                created_at: OffsetDateTime::now_utc(),
                is_verified: true,
            }),
            ..Default::default()
        });

        let workspace_repo = Arc::new(TestWorkspaceRepo::default());
        workspace_repo
            .workspaces
            .lock()
            .unwrap()
            .push(personal_workspace.clone());
        workspace_repo
            .memberships
            .lock()
            .unwrap()
            .push(WorkspaceMembershipSummary {
                workspace: personal_workspace.clone(),
                role: WorkspaceRole::Owner,
            });

        // Seed pending checkout
        {
            let mut settings = db.user_settings.lock().unwrap();
            *settings = serde_json::json!({
                "billing": {
                    "pending_checkout": {
                        "session_id": session_id,
                        "plan_tier": "workspace",
                        "workspace_name": "Acme Co"
                    }
                }
            });
        }

        let stripe = Arc::new(MockStripeService::new());
        {
            let mut guard = stripe.active_subscription.lock().unwrap();
            *guard = Some(SubscriptionInfo {
                id: "sub_123".into(),
                status: "active".into(),
                current_period_start: now.unix_timestamp(),
                current_period_end: (now + time::Duration::days(30)).unix_timestamp(),
                cancel_at: None,
                cancel_at_period_end: false,
                items: vec![SubscriptionItemInfo {
                    id: "si_over".into(),
                    price_id: "price_overage_test".into(),
                }],
            });
        }
        let state = AppState {
            db: db.clone(),
            workflow_repo: Arc::new(NoopWorkflowRepository),
            workspace_repo: workspace_repo.clone(),
            workspace_connection_repo: Arc::new(
                crate::db::workspace_connection_repository::NoopWorkspaceConnectionRepository,
            ),
            stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
            db_pool: test_pg_pool(),
            mailer: Arc::new(MockMailer::default()),
            google_oauth: Arc::new(
                crate::services::oauth::google::mock_google_oauth::MockGoogleOAuth::default(),
            ),
            github_oauth: Arc::new(
                crate::services::oauth::github::mock_github_oauth::MockGitHubOAuth::default(),
            ),
            oauth_accounts: crate::services::oauth::account_service::OAuthAccountService::test_stub(
            ),
            workspace_oauth:
                crate::services::oauth::workspace_service::WorkspaceOAuthService::test_stub(),
            stripe: stripe.clone(),
            integration_registry: crate::state::test_integration_registry(),
            http_client: Arc::new(Client::new()),
            config: test_config(),
            worker_id: Arc::new("test-worker".into()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        };

        // Build webhook payload that MockStripeService will accept without signature verification
        let body = serde_json::json!({
            "id": "evt_123",
            "type": "checkout.session.completed",
            "data": { "object": { "id": session_id, "metadata": { "user_id": user_id.to_string(), "workspace_name": "Acme Co" }, "customer": "cus_123" } }
        });
        let mut headers = HeaderMap::new();
        headers.insert("Stripe-Signature", HeaderValue::from_static("t=1,v1=stub"));

        let resp = webhook(
            AxumState(state),
            headers,
            axum::body::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // User plan updated via webhook
        assert_eq!(*db.update_user_plan_calls.lock().unwrap(), 1);

        // Pending checkout cleared
        let settings = db.user_settings.lock().unwrap().clone();
        assert!(settings["billing"]["pending_checkout"].is_null());

        // Workspace was promoted rather than recreated
        let created = workspace_repo.created.lock().unwrap().clone();
        assert!(created.is_empty());
        let added = workspace_repo.added_members.lock().unwrap().clone();
        assert!(added.is_empty());

        let plan_updates = workspace_repo.plan_updates.lock().unwrap().clone();
        assert_eq!(plan_updates.len(), 1);
        assert_eq!(plan_updates[0].0, personal_workspace.id);
        assert_eq!(plan_updates[0].1, "workspace");

        let name_updates = workspace_repo.name_updates.lock().unwrap().clone();
        assert_eq!(name_updates.len(), 1);
        assert_eq!(name_updates[0].0, personal_workspace.id);
        assert_eq!(name_updates[0].1, "Acme Co");

        let stored = workspace_repo.workspaces.lock().unwrap().clone();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].id, personal_workspace.id);
        assert_eq!(stored[0].plan, "workspace");
        assert_eq!(stored[0].name, "Acme Co");
        assert_eq!(stored[0].stripe_overage_item_id.as_deref(), Some("si_over"));
    }

    #[tokio::test]
    async fn webhook_checkout_completion_is_idempotent_with_existing_overage_item() {
        let user_id = Uuid::new_v4();
        let session_id = "cs_test_existing";
        let now = OffsetDateTime::now_utc();
        std::env::set_var("STRIPE_OVERAGE_PRICE_ID", "price_overage_test");
        let personal_workspace = Workspace {
            id: Uuid::new_v4(),
            name: "Owner's Workspace".into(),
            created_by: user_id,
            owner_id: user_id,
            plan: WORKSPACE_PLAN_SOLO.into(),
            stripe_overage_item_id: Some("si_existing".into()),
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };
        let db = Arc::new(MockDb {
            find_user_result: Some(User {
                id: user_id,
                email: "owner@example.com".into(),
                password_hash: String::new(),
                first_name: "Owner".into(),
                last_name: "User".into(),
                role: Some(UserRole::User),
                plan: Some("workspace".into()),
                company_name: None,
                stripe_customer_id: None,
                oauth_provider: Some(OauthProvider::Email),
                onboarded_at: None,
                created_at: OffsetDateTime::now_utc(),
                is_verified: true,
            }),
            ..Default::default()
        });

        let workspace_repo = Arc::new(TestWorkspaceRepo::default());
        workspace_repo
            .workspaces
            .lock()
            .unwrap()
            .push(personal_workspace.clone());
        workspace_repo
            .memberships
            .lock()
            .unwrap()
            .push(WorkspaceMembershipSummary {
                workspace: personal_workspace.clone(),
                role: WorkspaceRole::Owner,
            });

        {
            let mut settings = db.user_settings.lock().unwrap();
            *settings = serde_json::json!({
                "billing": {
                    "pending_checkout": {
                        "session_id": session_id,
                        "plan_tier": "workspace",
                        "workspace_name": "Acme Co"
                    }
                }
            });
        }

        let stripe = Arc::new(MockStripeService::new());
        {
            let mut guard = stripe.active_subscription.lock().unwrap();
            *guard = Some(SubscriptionInfo {
                id: "sub_retry".into(),
                status: "active".into(),
                current_period_start: now.unix_timestamp(),
                current_period_end: (now + time::Duration::days(30)).unix_timestamp(),
                cancel_at: None,
                cancel_at_period_end: false,
                items: vec![SubscriptionItemInfo {
                    id: "si_new_overage".into(),
                    price_id: "price_overage_test".into(),
                }],
            });
        }
        let state = AppState {
            db: db.clone(),
            workflow_repo: Arc::new(NoopWorkflowRepository),
            workspace_repo: workspace_repo.clone(),
            workspace_connection_repo: Arc::new(
                crate::db::workspace_connection_repository::NoopWorkspaceConnectionRepository,
            ),
            stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
            db_pool: test_pg_pool(),
            mailer: Arc::new(MockMailer::default()),
            google_oauth: Arc::new(
                crate::services::oauth::google::mock_google_oauth::MockGoogleOAuth::default(),
            ),
            github_oauth: Arc::new(
                crate::services::oauth::github::mock_github_oauth::MockGitHubOAuth::default(),
            ),
            oauth_accounts: crate::services::oauth::account_service::OAuthAccountService::test_stub(
            ),
            workspace_oauth:
                crate::services::oauth::workspace_service::WorkspaceOAuthService::test_stub(),
            stripe: stripe.clone(),
            integration_registry: crate::state::test_integration_registry(),
            http_client: Arc::new(Client::new()),
            config: test_config(),
            worker_id: Arc::new("test-worker".into()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        };

        let body = serde_json::json!({
            "id": "evt_retry",
            "type": "checkout.session.completed",
            "data": { "object": { "id": session_id, "metadata": { "user_id": user_id.to_string(), "workspace_name": "Acme Co" }, "customer": "cus_retry" } }
        });
        let mut headers = HeaderMap::new();
        headers.insert("Stripe-Signature", HeaderValue::from_static("t=1,v1=stub"));

        let resp = webhook(
            AxumState(state),
            headers,
            axum::body::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let settings = db.user_settings.lock().unwrap().clone();
        assert!(settings["billing"]["pending_checkout"].is_null());

        let stored = workspace_repo.workspaces.lock().unwrap().clone();
        assert_eq!(
            stored[0].stripe_overage_item_id.as_deref(),
            Some("si_existing")
        );
    }

    #[tokio::test]
    async fn webhook_checkout_session_completed_creates_workspace_when_missing_personal() {
        let user_id = Uuid::new_v4();
        let session_id = "cs_test_missing";
        let now = OffsetDateTime::now_utc();
        std::env::set_var("STRIPE_OVERAGE_PRICE_ID", "price_overage_test");
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
                onboarded_at: None,
                created_at: OffsetDateTime::now_utc(),
                is_verified: true,
            }),
            ..Default::default()
        });

        {
            let mut settings = db.user_settings.lock().unwrap();
            *settings = serde_json::json!({
                "billing": {
                    "pending_checkout": {
                        "session_id": session_id,
                        "plan_tier": "workspace",
                        "workspace_name": "New Co"
                    }
                }
            });
        }

        let workspace_repo = Arc::new(TestWorkspaceRepo::default());
        let stripe = Arc::new(MockStripeService::new());
        {
            let mut guard = stripe.active_subscription.lock().unwrap();
            *guard = Some(SubscriptionInfo {
                id: "sub_new".into(),
                status: "active".into(),
                current_period_start: now.unix_timestamp(),
                current_period_end: (now + time::Duration::days(30)).unix_timestamp(),
                cancel_at: None,
                cancel_at_period_end: false,
                items: vec![SubscriptionItemInfo {
                    id: "si_over".into(),
                    price_id: "price_overage_test".into(),
                }],
            });
        }
        let state = AppState {
            db: db.clone(),
            workflow_repo: Arc::new(NoopWorkflowRepository),
            workspace_repo: workspace_repo.clone(),
            workspace_connection_repo: Arc::new(
                crate::db::workspace_connection_repository::NoopWorkspaceConnectionRepository,
            ),
            stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
            db_pool: test_pg_pool(),
            mailer: Arc::new(MockMailer::default()),
            google_oauth: Arc::new(
                crate::services::oauth::google::mock_google_oauth::MockGoogleOAuth::default(),
            ),
            github_oauth: Arc::new(
                crate::services::oauth::github::mock_github_oauth::MockGitHubOAuth::default(),
            ),
            oauth_accounts: crate::services::oauth::account_service::OAuthAccountService::test_stub(
            ),
            workspace_oauth:
                crate::services::oauth::workspace_service::WorkspaceOAuthService::test_stub(),
            stripe: stripe.clone(),
            integration_registry: crate::state::test_integration_registry(),
            http_client: Arc::new(Client::new()),
            config: test_config(),
            worker_id: Arc::new("test-worker".into()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        };

        let body = serde_json::json!({
            "id": "evt_123",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": session_id,
                    "client_reference_id": user_id.to_string(),
                    "metadata": {"workspace_name": "New Co"},
                    "subscription": "sub_new"
                }
            }
        });
        let mut headers = HeaderMap::new();
        headers.insert("Stripe-Signature", HeaderValue::from_static("t=1,v1=stub"));

        let resp = webhook(
            AxumState(state),
            headers,
            axum::body::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        let settings = db.user_settings.lock().unwrap().clone();
        assert!(settings["billing"]["pending_checkout"].is_null());

        let created = workspace_repo.created.lock().unwrap().clone();
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].name, "New Co");

        let added = workspace_repo.added_members.lock().unwrap().clone();
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].1, user_id);
        let stored = workspace_repo.workspaces.lock().unwrap().clone();
        assert_eq!(stored[0].stripe_overage_item_id.as_deref(), Some("si_over"));
    }

    #[tokio::test]
    async fn webhook_billing_failure_records_error_and_rolls_back() {
        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let repo = TestWorkspaceRepo::default();
        // Seed a membership for rollback path
        repo.memberships
            .lock()
            .unwrap()
            .push(WorkspaceMembershipSummary {
                workspace: Workspace {
                    id: workspace_id,
                    name: "Team".into(),
                    created_by: user_id,
                    owner_id: user_id,
                    plan: "workspace".into(),
                    stripe_overage_item_id: None,
                    created_at: OffsetDateTime::now_utc(),
                    updated_at: OffsetDateTime::now_utc(),
                    deleted_at: None,
                },
                role: WorkspaceRole::Owner,
            });
        let workspace_repo = Arc::new(repo);

        let db = Arc::new(MockDb {
            find_user_result: Some(User {
                id: user_id,
                email: "owner@example.com".into(),
                password_hash: String::new(),
                first_name: "Owner".into(),
                last_name: "User".into(),
                role: Some(UserRole::User),
                plan: Some("workspace".into()),
                company_name: None,
                stripe_customer_id: Some("cus_abc".into()),
                oauth_provider: Some(OauthProvider::Email),
                onboarded_at: None,
                created_at: OffsetDateTime::now_utc(),
                is_verified: true,
            }),
            ..Default::default()
        });
        // Seed mapping for customer -> user id resolution used by failure paths
        {
            let mut guard = db.stripe_customer_id.lock().unwrap();
            *guard = Some("cus_abc".into());
        }
        // Seed a pending checkout
        {
            let mut settings = db.user_settings.lock().unwrap();
            *settings =
                serde_json::json!({"billing": {"pending_checkout": {"session_id": "cs_test_old"}}});
        }

        let stripe = Arc::new(MockStripeService::new());
        let state = AppState {
            db: db.clone(),
            workflow_repo: Arc::new(NoopWorkflowRepository),
            workspace_repo: workspace_repo.clone(),
            workspace_connection_repo: Arc::new(
                crate::db::workspace_connection_repository::NoopWorkspaceConnectionRepository,
            ),
            stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
            db_pool: test_pg_pool(),
            mailer: Arc::new(MockMailer::default()),
            google_oauth: Arc::new(
                crate::services::oauth::google::mock_google_oauth::MockGoogleOAuth::default(),
            ),
            github_oauth: Arc::new(
                crate::services::oauth::github::mock_github_oauth::MockGitHubOAuth::default(),
            ),
            oauth_accounts: crate::services::oauth::account_service::OAuthAccountService::test_stub(
            ),
            workspace_oauth:
                crate::services::oauth::workspace_service::WorkspaceOAuthService::test_stub(),
            stripe: stripe.clone(),
            integration_registry: crate::state::test_integration_registry(),
            http_client: Arc::new(Client::new()),
            config: test_config(),
            worker_id: Arc::new("test-worker".into()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        };

        // Use an invoice.payment_failed shape to drive failure path
        let body = serde_json::json!({
            "id": "evt_fail",
            "type": "invoice.payment_failed",
            "data": { "object": { "customer": "cus_abc", "last_finalization_error": { "message": "Card declined" } } }
        });
        let mut headers = HeaderMap::new();
        headers.insert("Stripe-Signature", HeaderValue::from_static("t=1,v1=stub"));

        let resp = webhook(
            AxumState(state),
            headers,
            axum::body::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Settings cleared pending and recorded error
        let settings = db.user_settings.lock().unwrap().clone();
        assert!(settings["billing"]["pending_checkout"].is_null());
        assert_eq!(
            settings["billing"]["last_error"].as_str().unwrap_or(""),
            "Card declined"
        );

        // Personal plan rolled back and any owned workspace downgraded
        // update: grace period in effect on failure so no immediate downgrade
        assert_eq!(*db.update_user_plan_calls.lock().unwrap(), 0);
        // At least one workspace plan update recorded
        // update: grace period DOES NOT update the plan right away
        assert!(workspace_repo.plan_updates.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn webhook_duplicate_checkout_event_is_skipped_after_logging() {
        let user_id = Uuid::new_v4();
        let session_id = "cs_test_dupe";
        let now = OffsetDateTime::now_utc();
        std::env::set_var("STRIPE_OVERAGE_PRICE_ID", "price_overage_test");
        let personal_workspace = Workspace {
            id: Uuid::new_v4(),
            name: "Owner's Workspace".into(),
            created_by: user_id,
            owner_id: user_id,
            plan: WORKSPACE_PLAN_SOLO.into(),
            stripe_overage_item_id: None,
            created_at: now,
            updated_at: now,
            deleted_at: None,
        };
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
                onboarded_at: None,
                created_at: OffsetDateTime::now_utc(),
                is_verified: true,
            }),
            ..Default::default()
        });

        let workspace_repo = Arc::new(TestWorkspaceRepo::default());
        workspace_repo
            .workspaces
            .lock()
            .unwrap()
            .push(personal_workspace.clone());
        workspace_repo
            .memberships
            .lock()
            .unwrap()
            .push(WorkspaceMembershipSummary {
                workspace: personal_workspace.clone(),
                role: WorkspaceRole::Owner,
            });

        {
            let mut settings = db.user_settings.lock().unwrap();
            *settings = serde_json::json!({
                "billing": {
                    "pending_checkout": {
                        "session_id": session_id,
                        "plan_tier": "workspace",
                        "workspace_name": "Acme Co"
                    }
                }
            });
        }

        let stripe = Arc::new(MockStripeService::new());
        {
            let mut guard = stripe.active_subscription.lock().unwrap();
            *guard = Some(SubscriptionInfo {
                id: "sub_dupe".into(),
                status: "active".into(),
                current_period_start: now.unix_timestamp(),
                current_period_end: (now + time::Duration::days(30)).unix_timestamp(),
                cancel_at: None,
                cancel_at_period_end: false,
                items: vec![SubscriptionItemInfo {
                    id: "si_over".into(),
                    price_id: "price_overage_test".into(),
                }],
            });
        }
        let stripe_event_log_repo = Arc::new(MockStripeEventLogRepository::default());
        let state = AppState {
            db: db.clone(),
            workflow_repo: Arc::new(NoopWorkflowRepository),
            workspace_repo: workspace_repo.clone(),
            workspace_connection_repo: Arc::new(
                crate::db::workspace_connection_repository::NoopWorkspaceConnectionRepository,
            ),
            stripe_event_log_repo: stripe_event_log_repo.clone(),
            db_pool: test_pg_pool(),
            mailer: Arc::new(MockMailer::default()),
            google_oauth: Arc::new(
                crate::services::oauth::google::mock_google_oauth::MockGoogleOAuth::default(),
            ),
            github_oauth: Arc::new(
                crate::services::oauth::github::mock_github_oauth::MockGitHubOAuth::default(),
            ),
            oauth_accounts: crate::services::oauth::account_service::OAuthAccountService::test_stub(
            ),
            workspace_oauth:
                crate::services::oauth::workspace_service::WorkspaceOAuthService::test_stub(),
            stripe: stripe.clone(),
            integration_registry: crate::state::test_integration_registry(),
            http_client: Arc::new(Client::new()),
            config: test_config(),
            worker_id: Arc::new("test-worker".into()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        };

        let body = serde_json::json!({
            "id": "evt_dupe",
            "type": "checkout.session.completed",
            "data": { "object": { "id": session_id, "metadata": { "user_id": user_id.to_string(), "workspace_name": "Acme Co" }, "customer": "cus_dupe" } }
        });
        let mut headers = HeaderMap::new();
        headers.insert("Stripe-Signature", HeaderValue::from_static("t=1,v1=stub"));

        let resp1 = webhook(
            AxumState(state.clone()),
            headers.clone(),
            axum::body::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        let resp2 = webhook(
            AxumState(state),
            headers,
            axum::body::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        assert_eq!(resp1.status(), StatusCode::OK);
        assert_eq!(resp2.status(), StatusCode::OK);

        assert_eq!(*db.update_user_plan_calls.lock().unwrap(), 1);
        assert_eq!(
            workspace_repo.plan_updates.lock().unwrap().len(),
            1,
            "workspace plan updated only once"
        );
        assert_eq!(
            workspace_repo.name_updates.lock().unwrap().len(),
            1,
            "workspace rename applied only once"
        );
        assert_eq!(
            *stripe_event_log_repo.inserts.lock().unwrap(),
            1,
            "event log recorded once"
        );
    }

    #[tokio::test]
    async fn webhook_subscription_deleted_is_idempotent_by_event_id() {
        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        let workspace_repo = Arc::new(TestWorkspaceRepo::default());
        workspace_repo
            .memberships
            .lock()
            .unwrap()
            .push(WorkspaceMembershipSummary {
                workspace: Workspace {
                    id: workspace_id,
                    name: "Team".into(),
                    created_by: user_id,
                    owner_id: user_id,
                    plan: "workspace".into(),
                    stripe_overage_item_id: None,
                    created_at: now,
                    updated_at: now,
                    deleted_at: None,
                },
                role: WorkspaceRole::Owner,
            });

        let db = Arc::new(MockDb {
            find_user_result: Some(User {
                id: user_id,
                email: "owner@example.com".into(),
                password_hash: String::new(),
                first_name: "Owner".into(),
                last_name: "User".into(),
                role: Some(UserRole::User),
                plan: Some("workspace".into()),
                company_name: None,
                stripe_customer_id: Some("cus_del".into()),
                oauth_provider: Some(OauthProvider::Email),
                onboarded_at: None,
                created_at: OffsetDateTime::now_utc(),
                is_verified: true,
            }),
            ..Default::default()
        });
        {
            let mut guard = db.stripe_customer_id.lock().unwrap();
            *guard = Some("cus_del".into());
        }

        let stripe = Arc::new(MockStripeService::new());
        let stripe_event_log_repo = Arc::new(MockStripeEventLogRepository::default());
        let state = AppState {
            db: db.clone(),
            workflow_repo: Arc::new(NoopWorkflowRepository),
            workspace_repo: workspace_repo.clone(),
            workspace_connection_repo: Arc::new(
                crate::db::workspace_connection_repository::NoopWorkspaceConnectionRepository,
            ),
            stripe_event_log_repo: stripe_event_log_repo.clone(),
            db_pool: test_pg_pool(),
            mailer: Arc::new(MockMailer::default()),
            google_oauth: Arc::new(
                crate::services::oauth::google::mock_google_oauth::MockGoogleOAuth::default(),
            ),
            github_oauth: Arc::new(
                crate::services::oauth::github::mock_github_oauth::MockGitHubOAuth::default(),
            ),
            oauth_accounts: crate::services::oauth::account_service::OAuthAccountService::test_stub(
            ),
            workspace_oauth:
                crate::services::oauth::workspace_service::WorkspaceOAuthService::test_stub(),
            stripe: stripe.clone(),
            integration_registry: crate::state::test_integration_registry(),
            http_client: Arc::new(Client::new()),
            config: test_config(),
            worker_id: Arc::new("test-worker".into()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        };

        let body = serde_json::json!({
            "id": "evt_delete_dupe",
            "type": "customer.subscription.deleted",
            "data": { "object": { "customer": "cus_del" } }
        });
        let mut headers = HeaderMap::new();
        headers.insert("Stripe-Signature", HeaderValue::from_static("t=1,v1=stub"));

        let resp1 = webhook(
            AxumState(state.clone()),
            headers.clone(),
            axum::body::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;
        let resp2 = webhook(
            AxumState(state),
            headers,
            axum::body::Bytes::from(serde_json::to_vec(&body).unwrap()),
        )
        .await;

        assert_eq!(resp1.status(), StatusCode::OK);
        assert_eq!(resp2.status(), StatusCode::OK);
        assert_eq!(*db.update_user_plan_calls.lock().unwrap(), 1);
        assert_eq!(
            workspace_repo.plan_updates.lock().unwrap().len(),
            1,
            "workspace downgraded only once"
        );
        assert_eq!(
            *stripe_event_log_repo.inserts.lock().unwrap(),
            1,
            "event log recorded only once"
        );
    }
}
