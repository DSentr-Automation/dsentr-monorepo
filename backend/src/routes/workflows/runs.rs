use super::{
    helpers::{enforce_solo_workflow_limit, plan_violation_response, SOLO_MONTHLY_RUN_LIMIT},
    prelude::*,
};
use crate::{
    models::{workflow_node_run::WorkflowNodeRun, workflow_run::WorkflowRun},
    routes::{options::secrets::decrypt_secret_store, plan_limits::workspace_limit_error_response},
    runaway_protection::{
        enforce_runaway_protection, RunawayProtectionError, RUNAWAY_PROTECTION_ERROR,
    },
    state::WorkspaceRunQuotaTicket,
    utils::{secrets::hydrate_secrets_into_snapshot, workflow_connection_metadata},
};

async fn fetch_workflow_for_member(
    app_state: &AppState,
    actor_id: Uuid,
    workflow_id: Uuid,
    server_error_message: &'static str,
) -> Result<Workflow, Response> {
    match app_state
        .workflow_repo
        .find_workflow_for_member(actor_id, workflow_id)
        .await
    {
        Ok(Some(workflow)) => Ok(workflow),
        Ok(None) => Err(JsonResponse::not_found("Workflow not found").into_response()),
        Err(err) => {
            eprintln!(
                "DB error fetching workflow {workflow_id} for user {actor_id}: {:?}",
                err
            );
            Err(JsonResponse::server_error(server_error_message).into_response())
        }
    }
}

#[derive(Deserialize)]
pub struct StartWorkflowRunRequest {
    pub idempotency_key: Option<String>,
    pub context: Option<serde_json::Value>,
    pub priority: Option<i32>,
    #[serde(alias = "startFromNodeId")]
    pub start_from_node_id: Option<String>,
}

pub(crate) fn redact_secrets(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                let key = k.to_lowercase();
                if key.contains("secret")
                    || key.contains("token")
                    || key.contains("apikey")
                    || key.contains("api_key")
                    || key.contains("authorization")
                {
                    *v = serde_json::Value::String("********".to_string());
                } else {
                    redact_secrets(v);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                redact_secrets(v);
            }
        }
        _ => {}
    }
}

pub(crate) fn redact_run(mut run: WorkflowRun) -> WorkflowRun {
    redact_secrets(&mut run.snapshot);
    run
}

pub(crate) fn redact_node_runs(mut node_runs: Vec<WorkflowNodeRun>) -> Vec<WorkflowNodeRun> {
    for nr in node_runs.iter_mut() {
        if let Some(inputs) = nr.inputs.as_mut() {
            redact_secrets(inputs);
        }
        if let Some(outputs) = nr.outputs.as_mut() {
            redact_secrets(outputs);
        }
    }
    node_runs
}

struct TriggerStartMeta {
    node_id: String,
    trigger_type: String,
}

fn trigger_type_from_node(node: &serde_json::Value) -> String {
    node.get("data")
        .and_then(|value| value.get("triggerType"))
        .and_then(|value| value.as_str())
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_else(|| "manual".to_string())
}

#[allow(clippy::result_large_err)]
fn validate_trigger_start(
    snapshot: &serde_json::Value,
    node_id: &str,
) -> Result<TriggerStartMeta, Response> {
    let trimmed = node_id.trim();
    if trimmed.is_empty() {
        return Err(JsonResponse::bad_request("start_from_node_id is invalid").into_response());
    }
    let nodes = snapshot
        .get("nodes")
        .and_then(|value| value.as_array())
        .ok_or_else(|| {
            JsonResponse::bad_request("start_from_node_id is invalid").into_response()
        })?;
    for node in nodes {
        let Some(id) = node.get("id").and_then(|value| value.as_str()) else {
            continue;
        };
        if id != trimmed {
            continue;
        }
        let Some(kind) = node.get("type").and_then(|value| value.as_str()) else {
            return Err(JsonResponse::bad_request("start_from_node_id is invalid").into_response());
        };
        if !kind.eq_ignore_ascii_case("trigger") {
            return Err(JsonResponse::bad_request(
                "start_from_node_id must reference a trigger node",
            )
            .into_response());
        }
        return Ok(TriggerStartMeta {
            node_id: id.to_string(),
            trigger_type: trigger_type_from_node(node),
        });
    }
    Err(JsonResponse::bad_request("start_from_node_id is invalid").into_response())
}

fn merge_trigger_context(
    existing: Option<serde_json::Value>,
    meta: &TriggerStartMeta,
    source: &str,
) -> serde_json::Value {
    let mut context = existing.unwrap_or_else(|| json!({}));
    if let serde_json::Value::Object(ref mut map) = context {
        map.insert(
            "trigger_node_id".to_string(),
            serde_json::Value::String(meta.node_id.clone()),
        );
        map.insert(
            "trigger_type".to_string(),
            serde_json::Value::String(meta.trigger_type.clone()),
        );
        map.insert(
            "source".to_string(),
            serde_json::Value::String(source.to_string()),
        );
    } else {
        context = json!({
            "trigger_node_id": meta.node_id,
            "trigger_type": meta.trigger_type,
            "source": source,
            "payload": context,
        });
    }
    context
}

pub async fn start_workflow_run(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path(workflow_id): Path<Uuid>,
    payload: Option<Json<StartWorkflowRunRequest>>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };
    let triggered_by = claims.id.clone();

    let wf =
        match fetch_workflow_for_member(&app_state, user_id, workflow_id, "Failed to start run")
            .await
        {
            Ok(workflow) => workflow,
            Err(response) => return response,
        };

    let owner_id = wf.user_id;

    let settings = match app_state.db.get_user_settings(owner_id).await {
        Ok(val) => val,
        Err(err) => {
            eprintln!("Failed to load user settings: {:?}", err);
            return JsonResponse::server_error("Failed to start run").into_response();
        }
    };

    if let Some(workspace_id) = wf.workspace_id {
        if let Err(err) = enforce_runaway_protection(&app_state, workspace_id, &settings).await {
            match err {
                RunawayProtectionError::RunawayProtectionTriggered { .. } => {
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        Json(json!({ "error": RUNAWAY_PROTECTION_ERROR })),
                    )
                        .into_response();
                }
                RunawayProtectionError::Database(db_err) => {
                    eprintln!("Failed to enforce runaway protection: {:?}", db_err);
                    return JsonResponse::server_error("Failed to start run").into_response();
                }
            }
        }
    }

    let mut workspace_quota: Option<WorkspaceRunQuotaTicket> = None;
    let plan_tier = if let Some(workspace_id) = wf.workspace_id {
        match app_state.consume_workspace_run_quota(workspace_id).await {
            Ok(Some(ticket)) => {
                if ticket.run_count > ticket.limit {
                    tracing::warn!(
                        %workspace_id,
                        run_count = ticket.run_count,
                        overage_count = ticket.overage_count,
                        "workspace run usage exceeded limit; recording overage"
                    );
                }
                workspace_quota = Some(ticket);
                NormalizedPlanTier::Workspace
            }
            Ok(None) => NormalizedPlanTier::Solo,
            Err(err) => return workspace_limit_error_response(err),
        }
    } else {
        app_state
            .resolve_plan_tier(user_id, claims.plan.as_deref())
            .await
    };

    if plan_tier.is_solo() {
        if wf.workspace_id.is_none() && wf.user_id == user_id {
            match app_state
                .workflow_repo
                .list_workflows_by_user(owner_id)
                .await
            {
                Ok(existing) => {
                    let allowed = enforce_solo_workflow_limit(&existing);
                    let allowed_ids: HashSet<_> = allowed.into_iter().map(|wf| wf.id).collect();
                    if !allowed_ids.contains(&wf.id) {
                        let violation = PlanViolation {
                            code: "workflow-limit",
                            message: "This workflow is locked on the solo plan. Upgrade in Settings -> Plan to run it.".to_string(),
                            node_label: None,
                        };
                        return plan_violation_response(vec![violation]);
                    }
                }
                Err(err) => {
                    eprintln!("Failed to enforce workflow limit before run: {:?}", err);
                    return JsonResponse::server_error("Failed to start run").into_response();
                }
            }

            let assessment = assess_workflow_for_plan(&wf.data);
            if !assessment.violations.is_empty() {
                return plan_violation_response(assessment.violations);
            }
        }

        let now = OffsetDateTime::now_utc();
        let start_of_month = now
            .replace_day(1)
            .unwrap_or(now)
            .replace_time(Time::MIDNIGHT);

        match app_state
            .workflow_repo
            .count_user_runs_since(owner_id, start_of_month)
            .await
        {
            Ok(count) if count >= SOLO_MONTHLY_RUN_LIMIT => {
                let violation = PlanViolation {
                    code: "run-limit",
                    message: "Solo plan usage includes 250 runs per month. You've reached the limit - upgrade in Settings -> Plan to keep running workflows.".to_string(),
                    node_label: None,
                };
                return plan_violation_response(vec![violation]);
            }
            Ok(_) => {}
            Err(err) => {
                eprintln!("Failed to check monthly usage: {:?}", err);
                return JsonResponse::server_error("Failed to start run").into_response();
            }
        }
    }

    let (idempotency_key_owned, trigger_ctx, priority, start_from_node_id) = match payload {
        Some(Json(req)) => (
            req.idempotency_key,
            req.context,
            req.priority,
            req.start_from_node_id,
        ),
        None => (None, None, None, None),
    };
    let idempotency_key = idempotency_key_owned.as_deref();

    // Clone raw workflow JSON
    let mut snapshot = wf.data.clone();
    let mut trigger_context = trigger_ctx;
    if let Some(start_id) = start_from_node_id.as_deref() {
        let meta = match validate_trigger_start(&snapshot, start_id) {
            Ok(value) => value,
            Err(resp) => return resp,
        };
        snapshot["_start_from_node"] = serde_json::Value::String(meta.node_id.clone());
        trigger_context = Some(merge_trigger_context(trigger_context, &meta, "manual"));
    }
    if let Some(ctx) = trigger_context {
        snapshot["_trigger_context"] = ctx;
    }

    // ---- SECRET HYDRATION FIX ----

    let (secret_store, _) = match decrypt_secret_store(
        &app_state,
        &settings,
        "Failed to decrypt user secrets while starting run",
        "Failed to start run",
    ) {
        Ok(tuple) => tuple,
        Err(resp) => return resp,
    };

    // Put plaintext secrets directly into the snapshot
    hydrate_secrets_into_snapshot(&mut snapshot, &secret_store);

    // --------------------------------------

    snapshot["_egress_allowlist"] = serde_json::Value::Array(
        wf.egress_allowlist
            .iter()
            .cloned()
            .map(serde_json::Value::String)
            .collect(),
    );

    if let Some(obj) = snapshot.as_object_mut() {
        obj.remove("_connection_metadata");
    }

    let connection_metadata = workflow_connection_metadata::collect(&snapshot);

    workflow_connection_metadata::embed(&mut snapshot, &connection_metadata);

    match app_state
        .workflow_repo
        .create_workflow_run(
            owner_id,
            workflow_id,
            wf.workspace_id,
            snapshot,
            idempotency_key,
        )
        .await
    {
        Ok(outcome) => {
            if let (Some(ticket), false) = (&workspace_quota, outcome.created) {
                let _ = app_state.release_workspace_run_quota(*ticket).await;
            }

            let run = outcome.run;

            if let Some(p) = priority {
                let _ = app_state
                    .workflow_repo
                    .set_run_priority(owner_id, workflow_id, run.id, p)
                    .await;
            }

            for event in workflow_connection_metadata::build_run_events(
                &run,
                &triggered_by,
                &connection_metadata,
            ) {
                if let Err(err) = app_state.workflow_repo.record_run_event(event).await {
                    eprintln!("Failed to record workflow run event {}: {:?}", run.id, err);
                }
            }

            let safe_run = redact_run(run.clone());

            (
                StatusCode::ACCEPTED,
                Json(json!({
                    "success": true,
                    "run": safe_run
                })),
            )
                .into_response()
        }
        Err(e) => {
            if let Some(ticket) = workspace_quota {
                let _ = app_state.release_workspace_run_quota(ticket).await;
            }
            eprintln!("DB error creating workflow run: {:?}", e);
            JsonResponse::server_error("Failed to enqueue run").into_response()
        }
    }
}

pub async fn get_workflow_run_status(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path((workflow_id, run_id)): Path<(Uuid, Uuid)>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    let workflow =
        match fetch_workflow_for_member(&app_state, user_id, workflow_id, "Failed to fetch run")
            .await
        {
            Ok(workflow) => workflow,
            Err(response) => return response,
        };
    let owner_id = workflow.user_id;

    match app_state
        .workflow_repo
        .get_workflow_run(owner_id, workflow_id, run_id)
        .await
    {
        Ok(Some(run)) => {
            let safe_run = redact_run(run.clone());
            let nodes_res = app_state
                .workflow_repo
                .list_workflow_node_runs(owner_id, workflow_id, run_id)
                .await;

            match nodes_res {
                Ok(node_runs) => {
                    let safe_node_runs = redact_node_runs(node_runs);
                    (
                        StatusCode::OK,
                        Json(json!({
                            "success": true,
                            "run": safe_run,
                            "node_runs": safe_node_runs
                        })),
                    )
                        .into_response()
                }
                Err(e) => {
                    eprintln!("DB error listing node runs: {:?}", e);
                    JsonResponse::server_error("Failed to fetch run status").into_response()
                }
            }
        }
        Ok(None) => JsonResponse::not_found("Run not found").into_response(),
        Err(e) => {
            eprintln!("DB error fetching run: {:?}", e);
            JsonResponse::server_error("Failed to fetch run").into_response()
        }
    }
}

pub async fn cancel_workflow_run(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path((workflow_id, run_id)): Path<(Uuid, Uuid)>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };
    let workflow =
        match fetch_workflow_for_member(&app_state, user_id, workflow_id, "Failed to cancel run")
            .await
        {
            Ok(workflow) => workflow,
            Err(response) => return response,
        };
    let owner_id = workflow.user_id;

    match app_state
        .workflow_repo
        .cancel_workflow_run(owner_id, workflow_id, run_id)
        .await
    {
        Ok(true) => (
            StatusCode::OK,
            Json(json!({"success": true, "status": "canceled" })),
        )
            .into_response(),
        Ok(false) => {
            JsonResponse::bad_request("Run is not cancelable or not found").into_response()
        }
        Err(e) => {
            eprintln!("DB error canceling run: {:?}", e);
            JsonResponse::server_error("Failed to cancel run").into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct ListRunsQuery {
    pub workflow_id: Option<Uuid>,
}

pub async fn list_active_runs(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Query(params): Query<ListRunsQuery>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };
    let (owner_id, workflow_scope) = if let Some(workflow_id) = params.workflow_id {
        match fetch_workflow_for_member(&app_state, user_id, workflow_id, "Failed to list runs")
            .await
        {
            Ok(workflow) => (workflow.user_id, Some(workflow_id)),
            Err(response) => return response,
        }
    } else {
        (user_id, None)
    };

    match app_state
        .workflow_repo
        .list_active_runs(owner_id, workflow_scope)
        .await
    {
        Ok(runs) => {
            let safe_runs: Vec<WorkflowRun> = runs.into_iter().map(redact_run).collect();
            (
                StatusCode::OK,
                Json(json!({ "success": true, "runs": safe_runs })),
            )
                .into_response()
        }
        Err(e) => {
            eprintln!("DB error listing active runs: {:?}", e);
            JsonResponse::server_error("Failed to list runs").into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct PagedRunsQuery {
    pub status: Option<Vec<String>>, // e.g., status=running&status=queued
    pub page: Option<i64>,           // 1-based
    pub per_page: Option<i64>,       // default 20
}

pub async fn list_runs_for_workflow(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path(workflow_id): Path<Uuid>,
    Query(params): Query<PagedRunsQuery>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    let per_page = params.per_page.unwrap_or(20).clamp(1, 100);
    let page = params.page.unwrap_or(1).max(1);
    let offset = (page - 1) * per_page;

    let workflow =
        match fetch_workflow_for_member(&app_state, user_id, workflow_id, "Failed to list runs")
            .await
        {
            Ok(workflow) => workflow,
            Err(response) => return response,
        };

    match app_state
        .workflow_repo
        .list_runs_paged(
            workflow.user_id,
            Some(workflow_id),
            params.status.as_deref(),
            per_page,
            offset,
        )
        .await
    {
        Ok(runs) => {
            let safe_runs: Vec<WorkflowRun> = runs.into_iter().map(redact_run).collect();
            (
                StatusCode::OK,
                Json(json!({ "success": true, "runs": safe_runs, "page": page, "per_page": per_page })),
            )
                .into_response()
        }
        Err(e) => {
            eprintln!("DB error listing runs: {:?}", e);
            JsonResponse::server_error("Failed to list runs").into_response()
        }
    }
}

pub async fn cancel_all_runs_for_workflow(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path(workflow_id): Path<Uuid>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    let workflow =
        match fetch_workflow_for_member(&app_state, user_id, workflow_id, "Failed to cancel runs")
            .await
        {
            Ok(workflow) => workflow,
            Err(response) => return response,
        };

    match app_state
        .workflow_repo
        .cancel_all_runs_for_workflow(workflow.user_id, workflow_id)
        .await
    {
        Ok(affected) => (
            StatusCode::OK,
            Json(json!({"success": true, "canceled": affected })),
        )
            .into_response(),
        Err(e) => {
            eprintln!("DB error canceling runs: {:?}", e);
            JsonResponse::server_error("Failed to cancel runs").into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct RerunRequest {
    pub idempotency_key: Option<String>,
    pub context: Option<serde_json::Value>,
    #[serde(alias = "startFromNodeId")]
    pub start_from_node_id: Option<String>,
}

pub async fn rerun_workflow_run(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path((workflow_id, run_id)): Path<(Uuid, Uuid)>,
    Json(payload): Json<RerunRequest>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };
    let triggered_by = claims.id.clone();

    // Fetch the original run to get snapshot
    let workflow = match fetch_workflow_for_member(
        &app_state,
        user_id,
        workflow_id,
        "Failed to rerun",
    )
    .await
    {
        Ok(workflow) => workflow,
        Err(response) => return response,
    };

    let base_run = match app_state
        .workflow_repo
        .get_workflow_run(workflow.user_id, workflow_id, run_id)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return JsonResponse::not_found("Run not found").into_response(),
        Err(e) => {
            eprintln!("DB error fetching run for rerun: {:?}", e);
            return JsonResponse::server_error("Failed to rerun").into_response();
        }
    };

    let RerunRequest {
        idempotency_key,
        context,
        start_from_node_id,
    } = payload;

    let mut snapshot = base_run.snapshot.clone();
    let mut trigger_context = context.or_else(|| snapshot.get("_trigger_context").cloned());
    if let Some(start_id) = start_from_node_id.as_deref() {
        let meta = match validate_trigger_start(&snapshot, start_id) {
            Ok(value) => value,
            Err(resp) => return resp,
        };
        snapshot["_start_from_node"] = serde_json::Value::String(meta.node_id.clone());
        trigger_context = Some(merge_trigger_context(trigger_context, &meta, "manual"));
    }
    if let Some(ctx) = trigger_context {
        snapshot["_trigger_context"] = ctx;
    }

    if let Some(obj) = snapshot.as_object_mut() {
        obj.remove("_connection_metadata");
    }
    let connection_metadata = workflow_connection_metadata::collect(&snapshot);
    workflow_connection_metadata::embed(&mut snapshot, &connection_metadata);

    if let Some(workspace_id) = workflow.workspace_id {
        let settings = match app_state.db.get_user_settings(workflow.user_id).await {
            Ok(val) => val,
            Err(err) => {
                eprintln!("Failed to load user settings: {:?}", err);
                return JsonResponse::server_error("Failed to rerun").into_response();
            }
        };

        if let Err(err) = enforce_runaway_protection(&app_state, workspace_id, &settings).await {
            match err {
                RunawayProtectionError::RunawayProtectionTriggered { .. } => {
                    return (
                        StatusCode::TOO_MANY_REQUESTS,
                        Json(json!({ "error": RUNAWAY_PROTECTION_ERROR })),
                    )
                        .into_response();
                }
                RunawayProtectionError::Database(db_err) => {
                    eprintln!("Failed to enforce runaway protection: {:?}", db_err);
                    return JsonResponse::server_error("Failed to rerun").into_response();
                }
            }
        }
    }

    let mut workspace_quota: Option<WorkspaceRunQuotaTicket> = None;
    if let Some(workspace_id) = workflow.workspace_id {
        match app_state.consume_workspace_run_quota(workspace_id).await {
            Ok(Some(ticket)) => workspace_quota = Some(ticket),
            Ok(None) => {}
            Err(err) => return workspace_limit_error_response(err),
        }
    }

    match app_state
        .workflow_repo
        .create_workflow_run(
            workflow.user_id,
            workflow_id,
            workflow.workspace_id,
            snapshot,
            idempotency_key.as_deref(),
        )
        .await
    {
        Ok(outcome) => {
            if let (Some(ticket), false) = (&workspace_quota, outcome.created) {
                let _ = app_state.release_workspace_run_quota(*ticket).await;
            }

            let run = outcome.run;
            let events = workflow_connection_metadata::build_run_events(
                &run,
                &triggered_by,
                &connection_metadata,
            );
            for event in events {
                if let Err(err) = app_state.workflow_repo.record_run_event(event).await {
                    eprintln!(
                        "Failed to record workflow rerun event {}: {:?}",
                        run.id, err
                    );
                }
            }

            let safe_run = redact_run(run);
            (
                StatusCode::ACCEPTED,
                Json(json!({"success": true, "run": safe_run})),
            )
                .into_response()
        }
        Err(e) => {
            if let Some(ticket) = workspace_quota {
                let _ = app_state.release_workspace_run_quota(ticket).await;
            }
            eprintln!("DB error creating rerun: {:?}", e);
            JsonResponse::server_error("Failed to enqueue rerun").into_response()
        }
    }
}

pub async fn rerun_from_failed_node(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path((workflow_id, run_id)): Path<(Uuid, Uuid)>,
    Json(mut payload): Json<RerunRequest>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };
    let workflow = match fetch_workflow_for_member(
        &app_state,
        user_id,
        workflow_id,
        "Failed to rerun",
    )
    .await
    {
        Ok(workflow) => workflow,
        Err(response) => return response,
    };

    let nodes = match app_state
        .workflow_repo
        .list_workflow_node_runs(workflow.user_id, workflow_id, run_id)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            eprintln!("DB error fetching node runs: {:?}", e);
            return JsonResponse::server_error("Failed to rerun").into_response();
        }
    };
    let failed = nodes
        .iter()
        .rev()
        .find(|n| n.status == "failed")
        .map(|n| n.node_id.clone());
    if let Some(node_id) = failed {
        payload.start_from_node_id = Some(node_id);
        rerun_workflow_run(
            State(app_state),
            AuthSession(claims),
            Path((workflow_id, run_id)),
            Json(payload),
        )
        .await
    } else {
        JsonResponse::bad_request("No failed node found for this run").into_response()
    }
}

// Download run JSON (run + node_runs)
pub async fn download_run_json(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path((workflow_id, run_id)): Path<(Uuid, Uuid)>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    let workflow =
        match fetch_workflow_for_member(&app_state, user_id, workflow_id, "Failed to download run")
            .await
        {
            Ok(workflow) => workflow,
            Err(response) => return response,
        };

    let run_opt = app_state
        .workflow_repo
        .get_workflow_run(workflow.user_id, workflow_id, run_id)
        .await;

    match run_opt {
        Ok(Some(run)) => {
            let safe_run = redact_run(run);
            let nodes_res = app_state
                .workflow_repo
                .list_workflow_node_runs(workflow.user_id, workflow_id, run_id)
                .await;
            match nodes_res {
                Ok(node_runs) => {
                    let safe_node_runs = redact_node_runs(node_runs);
                    let payload = json!({"run": safe_run, "node_runs": safe_node_runs});
                    let body = axum::Json(payload);
                    let mut resp = body.into_response();
                    resp.headers_mut().insert(
                        axum::http::header::CONTENT_DISPOSITION,
                        axum::http::HeaderValue::from_static("attachment; filename=run.json"),
                    );
                    resp
                }
                Err(e) => {
                    eprintln!("DB error listing node runs: {:?}", e);
                    JsonResponse::server_error("Failed to download run").into_response()
                }
            }
        }
        Ok(None) => JsonResponse::not_found("Run not found").into_response(),
        Err(e) => {
            eprintln!("DB error fetching run: {:?}", e);
            JsonResponse::server_error("Failed to download run").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Config, OAuthProviderConfig, OAuthSettings, StripeSettings, DEFAULT_WORKSPACE_MEMBER_LIMIT,
        DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT, RUNAWAY_LIMIT_5MIN,
    };
    use crate::db::{
        mock_db::{MockDb, StaticWorkspaceMembershipRepository},
        mock_stripe_event_log_repository::MockStripeEventLogRepository,
        workflow_repository::{
            CreateWorkflowRunOutcome, MockWorkflowRepository, WorkflowRepository,
        },
        workspace_connection_repository::NoopWorkspaceConnectionRepository,
        workspace_repository::WorkspaceRepository,
    };
    use crate::models::{
        plan::PlanTier, workflow_run::WorkflowRun, workflow_run_event::WorkflowRunEvent,
    };
    use crate::routes::auth::claims::{Claims, TokenUse};
    use crate::routes::auth::session::AuthSession;
    use crate::services::{
        oauth::{
            github::mock_github_oauth::MockGitHubOAuth, google::mock_google_oauth::MockGoogleOAuth,
            workspace_service::WorkspaceOAuthService,
        },
        smtp_mailer::MockMailer,
    };
    use crate::state::{test_pg_pool, AppState};
    use crate::utils::jwt::JwtKeys;
    use axum::body::to_bytes;
    use reqwest::Client;
    use serde_json::Value;
    use std::sync::{Arc, Mutex};
    use time::{Duration, OffsetDateTime};

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

    fn claims_fixture(user_id: Uuid, email: &str) -> Claims {
        Claims {
            id: user_id.to_string(),
            email: email.to_string(),
            exp: OffsetDateTime::now_utc().unix_timestamp() as usize + 3600,
            first_name: "Test".into(),
            last_name: "User".into(),
            role: None,
            plan: Some(PlanTier::Workspace.as_str().to_string()),
            company_name: None,
            iss: String::new(),
            aud: String::new(),
            token_use: TokenUse::Access,
        }
    }

    fn workflow_fixture(workspace_id: Uuid, owner_id: Uuid) -> Workflow {
        let now = OffsetDateTime::now_utc();
        Workflow {
            id: Uuid::new_v4(),
            user_id: owner_id,
            workspace_id: Some(workspace_id),
            name: "Workflow".into(),
            description: None,
            data: json!({
                "nodes": [],
                "edges": []
            }),
            concurrency_limit: 1,
            egress_allowlist: vec![],
            locked_by: None,
            locked_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn run_fixture(workflow: &Workflow) -> WorkflowRun {
        let now = OffsetDateTime::now_utc();
        WorkflowRun {
            id: Uuid::new_v4(),
            user_id: workflow.user_id,
            workflow_id: workflow.id,
            workspace_id: workflow.workspace_id,
            snapshot: workflow.data.clone(),
            status: "running".into(),
            error: None,
            idempotency_key: None,
            started_at: now,
            resume_at: now,
            finished_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn test_state(
        workflow_repo: Arc<dyn WorkflowRepository>,
        workspace_repo: Arc<dyn WorkspaceRepository>,
    ) -> AppState {
        AppState {
            db: Arc::new(MockDb::default()),
            workflow_repo,
            workspace_repo,
            workspace_connection_repo: Arc::new(NoopWorkspaceConnectionRepository),
            stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
            db_pool: test_pg_pool(),
            mailer: Arc::new(MockMailer::default()),
            google_oauth: Arc::new(MockGoogleOAuth::default()),
            github_oauth: Arc::new(MockGitHubOAuth::default()),
            oauth_accounts: crate::services::oauth::account_service::OAuthAccountService::test_stub(
            ),
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

    #[tokio::test]
    async fn start_workflow_run_records_workspace_overage_without_blocking() {
        let workspace_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let workflow = workflow_fixture(workspace_id, owner_id);
        let workflow_for_find = workflow.clone();
        let run = run_fixture(&workflow);

        let mut repo = MockWorkflowRepository::new();
        repo.expect_count_workspace_runs_since()
            .returning(|_, _| Box::pin(async { Ok(0) }));
        repo.expect_find_workflow_for_member()
            .returning(move |user, workflow_id| {
                let wf = workflow_for_find.clone();
                assert_eq!(user, wf.user_id);
                assert_eq!(workflow_id, wf.id);
                Box::pin(async move { Ok(Some(wf)) })
            });
        repo.expect_create_workflow_run()
            .returning(move |_, _, _, _, _| {
                let run = run.clone();
                Box::pin(async move { Ok(CreateWorkflowRunOutcome { run, created: true }) })
            });
        repo.expect_record_run_event()
            .returning(|event| {
                let recorded_at = event.recorded_at.unwrap_or_else(OffsetDateTime::now_utc);
                Box::pin(async move {
                    Ok(WorkflowRunEvent {
                        id: Uuid::new_v4(),
                        workflow_run_id: event.workflow_run_id,
                        workflow_id: event.workflow_id,
                        workspace_id: event.workspace_id,
                        triggered_by: event.triggered_by,
                        connection_type: event.connection_type,
                        connection_id: event.connection_id,
                        recorded_at,
                    })
                })
            })
            .times(0..);

        let workspace_repo: Arc<StaticWorkspaceMembershipRepository> =
            Arc::new(StaticWorkspaceMembershipRepository::with_run_limit(0));
        let state = test_state(
            Arc::new(repo),
            workspace_repo.clone() as Arc<dyn WorkspaceRepository>,
        );

        let response = start_workflow_run(
            State(state),
            AuthSession(claims_fixture(owner_id, "member@example.com")),
            Path(workflow.id),
            None,
        )
        .await;

        assert!(response.status().is_success());
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["success"], Value::Bool(true));
        assert_eq!(workspace_repo.release_calls(), 0);
        let periods = workspace_repo.last_period_starts();
        assert_eq!(periods.len(), 1);
        let period_start = periods[0];
        let usage = workspace_repo.usage_for(workspace_id, period_start);
        assert_eq!(usage.run_count, 1);
        assert_eq!(usage.overage_count, 1);
    }

    #[tokio::test]
    async fn start_workflow_run_allows_solo_workspace_without_quota_error() {
        let workspace_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let workflow = workflow_fixture(workspace_id, owner_id);
        let workflow_for_find = workflow.clone();
        let run = run_fixture(&workflow);

        let mut repo = MockWorkflowRepository::new();
        repo.expect_count_workspace_runs_since()
            .returning(|_, _| Box::pin(async { Ok(0) }));
        repo.expect_find_workflow_for_member()
            .returning(move |user, workflow_id| {
                let wf = workflow_for_find.clone();
                assert_eq!(user, wf.user_id);
                assert_eq!(workflow_id, wf.id);
                Box::pin(async move { Ok(Some(wf)) })
            });
        repo.expect_create_workflow_run()
            .returning(move |_, _, _, _, _| {
                let run = run.clone();
                Box::pin(async move { Ok(CreateWorkflowRunOutcome { run, created: true }) })
            });
        repo.expect_record_run_event()
            .returning(|event| {
                let recorded_at = event.recorded_at.unwrap_or_else(OffsetDateTime::now_utc);
                Box::pin(async move {
                    Ok(WorkflowRunEvent {
                        id: Uuid::new_v4(),
                        workflow_run_id: event.workflow_run_id,
                        workflow_id: event.workflow_id,
                        workspace_id: event.workspace_id,
                        triggered_by: event.triggered_by,
                        connection_type: event.connection_type,
                        connection_id: event.connection_id,
                        recorded_at,
                    })
                })
            })
            .times(0..);
        repo.expect_count_user_runs_since()
            .returning(|_, _| Box::pin(async { Ok(0) }));

        let workspace_repo: Arc<StaticWorkspaceMembershipRepository> = Arc::new(
            StaticWorkspaceMembershipRepository::with_plan(PlanTier::Solo),
        );
        let state = test_state(
            Arc::new(repo),
            workspace_repo.clone() as Arc<dyn WorkspaceRepository>,
        );

        let mut claims = claims_fixture(owner_id, "member@example.com");
        claims.plan = Some(PlanTier::Solo.as_str().to_string());

        let response =
            start_workflow_run(State(state), AuthSession(claims), Path(workflow.id), None).await;

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["success"], Value::Bool(true));
        assert!(workspace_repo.last_period_starts().is_empty());
    }

    #[tokio::test]
    async fn start_workflow_run_seeds_start_from_node_when_provided() {
        let workspace_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let workflow = Workflow {
            id: Uuid::new_v4(),
            user_id: owner_id,
            workspace_id: Some(workspace_id),
            name: "multi-trigger".into(),
            description: None,
            data: json!({
                "nodes": [
                    {"id": "manual-1", "type": "trigger", "data": {"label": "Manual"}},
                    {"id": "schedule-1", "type": "trigger", "data": {"label": "Schedule", "triggerType": "schedule"}},
                    {"id": "action-1", "type": "action", "data": {"label": "Action"}}
                ],
                "edges": []
            }),
            concurrency_limit: 1,
            egress_allowlist: vec![],
            locked_by: None,
            locked_at: None,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };
        let workflow_for_find = workflow.clone();
        let captured_snapshot: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));

        let mut repo = MockWorkflowRepository::new();
        repo.expect_count_workspace_runs_since()
            .returning(|_, _| Box::pin(async { Ok(0) }));
        repo.expect_find_workflow_for_member()
            .returning(move |user, workflow_id| {
                let wf = workflow_for_find.clone();
                assert_eq!(user, wf.user_id);
                assert_eq!(workflow_id, wf.id);
                Box::pin(async move { Ok(Some(wf)) })
            });
        let captured_clone = captured_snapshot.clone();
        repo.expect_create_workflow_run().returning(
            move |user_id_param, workflow_id_param, workspace_id_param, snapshot, _| {
                let captured = captured_clone.clone();
                Box::pin(async move {
                    *captured.lock().unwrap() = Some(snapshot.clone());
                    let run = WorkflowRun {
                        id: Uuid::new_v4(),
                        user_id: user_id_param,
                        workflow_id: workflow_id_param,
                        workspace_id: workspace_id_param,
                        snapshot,
                        status: "queued".into(),
                        error: None,
                        idempotency_key: None,
                        started_at: OffsetDateTime::now_utc(),
                        resume_at: OffsetDateTime::now_utc(),
                        finished_at: None,
                        created_at: OffsetDateTime::now_utc(),
                        updated_at: OffsetDateTime::now_utc(),
                    };
                    Ok(CreateWorkflowRunOutcome { run, created: true })
                })
            },
        );
        repo.expect_record_run_event()
            .returning(|event| {
                let recorded_at = event.recorded_at.unwrap_or_else(OffsetDateTime::now_utc);
                Box::pin(async move {
                    Ok(WorkflowRunEvent {
                        id: Uuid::new_v4(),
                        workflow_run_id: event.workflow_run_id,
                        workflow_id: event.workflow_id,
                        workspace_id: event.workspace_id,
                        triggered_by: event.triggered_by,
                        connection_type: event.connection_type,
                        connection_id: event.connection_id,
                        recorded_at,
                    })
                })
            })
            .times(0..);

        let workspace_repo: Arc<StaticWorkspaceMembershipRepository> =
            Arc::new(StaticWorkspaceMembershipRepository::with_run_limit(5));
        let state = test_state(
            Arc::new(repo),
            workspace_repo.clone() as Arc<dyn WorkspaceRepository>,
        );

        let claims = claims_fixture(owner_id, "owner@example.com");
        let response = start_workflow_run(
            State(state),
            AuthSession(claims),
            Path(workflow.id),
            Some(axum::Json(StartWorkflowRunRequest {
                idempotency_key: None,
                context: None,
                priority: None,
                start_from_node_id: Some("schedule-1".to_string()),
            })),
        )
        .await;

        assert!(response.status().is_success());
        let snapshot = captured_snapshot
            .lock()
            .unwrap()
            .clone()
            .expect("snapshot recorded");
        assert_eq!(
            snapshot.get("_start_from_node").and_then(|v| v.as_str()),
            Some("schedule-1")
        );
        let trigger_context = snapshot
            .get("_trigger_context")
            .and_then(|v| v.as_object())
            .expect("trigger context should be an object");
        assert_eq!(
            trigger_context
                .get("trigger_node_id")
                .and_then(|v| v.as_str()),
            Some("schedule-1")
        );
        assert_eq!(
            trigger_context.get("trigger_type").and_then(|v| v.as_str()),
            Some("schedule")
        );
        assert_eq!(
            trigger_context.get("source").and_then(|v| v.as_str()),
            Some("manual")
        );
    }

    #[tokio::test]
    async fn start_workflow_run_rejects_unknown_start_from_node_id() {
        let workspace_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let workflow = Workflow {
            id: Uuid::new_v4(),
            user_id: owner_id,
            workspace_id: Some(workspace_id),
            name: "workflow".into(),
            description: None,
            data: json!({
                "nodes": [
                    {"id": "manual-1", "type": "trigger", "data": {"label": "Manual"}}
                ],
                "edges": []
            }),
            concurrency_limit: 1,
            egress_allowlist: vec![],
            locked_by: None,
            locked_at: None,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };
        let workflow_for_find = workflow.clone();

        let mut repo = MockWorkflowRepository::new();
        repo.expect_count_workspace_runs_since()
            .returning(|_, _| Box::pin(async { Ok(0) }));
        repo.expect_find_workflow_for_member()
            .returning(move |user, workflow_id| {
                let wf = workflow_for_find.clone();
                assert_eq!(user, wf.user_id);
                assert_eq!(workflow_id, wf.id);
                Box::pin(async move { Ok(Some(wf)) })
            });
        repo.expect_create_workflow_run().times(0);
        repo.expect_record_run_event().times(0);

        let workspace_repo: Arc<StaticWorkspaceMembershipRepository> =
            Arc::new(StaticWorkspaceMembershipRepository::with_run_limit(5));
        let state = test_state(
            Arc::new(repo),
            workspace_repo.clone() as Arc<dyn WorkspaceRepository>,
        );

        let response = start_workflow_run(
            State(state),
            AuthSession(claims_fixture(owner_id, "owner@example.com")),
            Path(workflow.id),
            Some(axum::Json(StartWorkflowRunRequest {
                idempotency_key: None,
                context: None,
                priority: None,
                start_from_node_id: Some("missing-node".to_string()),
            })),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["message"],
            Value::String("start_from_node_id is invalid".to_string())
        );
    }

    #[tokio::test]
    async fn start_workflow_run_rejects_non_trigger_start_from_node_id() {
        let workspace_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let workflow = Workflow {
            id: Uuid::new_v4(),
            user_id: owner_id,
            workspace_id: Some(workspace_id),
            name: "workflow".into(),
            description: None,
            data: json!({
                "nodes": [
                    {"id": "manual-1", "type": "trigger", "data": {"label": "Manual"}},
                    {"id": "action-1", "type": "action", "data": {"label": "Action"}}
                ],
                "edges": []
            }),
            concurrency_limit: 1,
            egress_allowlist: vec![],
            locked_by: None,
            locked_at: None,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };
        let workflow_for_find = workflow.clone();

        let mut repo = MockWorkflowRepository::new();
        repo.expect_count_workspace_runs_since()
            .returning(|_, _| Box::pin(async { Ok(0) }));
        repo.expect_find_workflow_for_member()
            .returning(move |user, workflow_id| {
                let wf = workflow_for_find.clone();
                assert_eq!(user, wf.user_id);
                assert_eq!(workflow_id, wf.id);
                Box::pin(async move { Ok(Some(wf)) })
            });
        repo.expect_create_workflow_run().times(0);
        repo.expect_record_run_event().times(0);

        let workspace_repo: Arc<StaticWorkspaceMembershipRepository> =
            Arc::new(StaticWorkspaceMembershipRepository::with_run_limit(5));
        let state = test_state(
            Arc::new(repo),
            workspace_repo.clone() as Arc<dyn WorkspaceRepository>,
        );

        let response = start_workflow_run(
            State(state),
            AuthSession(claims_fixture(owner_id, "owner@example.com")),
            Path(workflow.id),
            Some(axum::Json(StartWorkflowRunRequest {
                idempotency_key: None,
                context: None,
                priority: None,
                start_from_node_id: Some("action-1".to_string()),
            })),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["message"],
            Value::String("start_from_node_id must reference a trigger node".to_string())
        );
    }

    #[tokio::test]
    async fn rerun_workflow_run_blocks_when_runaway_protection_triggers() {
        let workspace_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let workflow = workflow_fixture(workspace_id, owner_id);
        let workflow_for_find = workflow.clone();
        let workflow_for_run = workflow.clone();
        let base_run = run_fixture(&workflow);
        let base_run_id = base_run.id;
        let base_run_for_get = base_run.clone();

        let mut repo = MockWorkflowRepository::new();
        repo.expect_find_workflow_for_member()
            .returning(move |user, workflow_id| {
                let wf = workflow_for_find.clone();
                assert_eq!(user, wf.user_id);
                assert_eq!(workflow_id, wf.id);
                Box::pin(async move { Ok(Some(wf)) })
            });
        repo.expect_get_workflow_run()
            .returning(move |user, wf_id, run_id| {
                let wf = workflow_for_run.clone();
                assert_eq!(user, wf.user_id);
                assert_eq!(wf_id, wf.id);
                assert_eq!(run_id, base_run_id);
                let run = base_run_for_get.clone();
                Box::pin(async move { Ok(Some(run)) })
            });
        repo.expect_count_workspace_runs_since()
            .times(1)
            .returning(|_, _| Box::pin(async { Ok(RUNAWAY_LIMIT_5MIN + 5) }));
        repo.expect_create_workflow_run().times(0);
        repo.expect_record_run_event().times(0);

        let workspace_repo: Arc<StaticWorkspaceMembershipRepository> =
            Arc::new(StaticWorkspaceMembershipRepository::allowing());
        let state = test_state(
            Arc::new(repo),
            workspace_repo.clone() as Arc<dyn WorkspaceRepository>,
        );

        let response = rerun_workflow_run(
            State(state),
            AuthSession(claims_fixture(owner_id, "member@example.com")),
            Path((workflow.id, base_run_id)),
            axum::Json(RerunRequest {
                idempotency_key: None,
                context: None,
                start_from_node_id: None,
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = to_bytes(response.into_body(), 1024).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["error"],
            Value::String(RUNAWAY_PROTECTION_ERROR.to_string())
        );
        assert!(workspace_repo.last_period_starts().is_empty());
    }

    #[tokio::test]
    async fn start_workflow_run_releases_quota_when_idempotent() {
        let workspace_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let workflow = workflow_fixture(workspace_id, owner_id);
        let workflow_for_find = workflow.clone();
        let run = run_fixture(&workflow);

        let mut repo = MockWorkflowRepository::new();
        repo.expect_count_workspace_runs_since()
            .returning(|_, _| Box::pin(async { Ok(0) }));
        repo.expect_find_workflow_for_member()
            .returning(move |_, _| {
                let wf = workflow_for_find.clone();
                Box::pin(async move { Ok(Some(wf)) })
            });
        repo.expect_create_workflow_run()
            .returning(move |_, _, _, _, _| {
                let run = run.clone();
                Box::pin(async move {
                    Ok(CreateWorkflowRunOutcome {
                        run,
                        created: false,
                    })
                })
            });
        repo.expect_record_run_event()
            .returning(|event| {
                let recorded_at = event.recorded_at.unwrap_or_else(OffsetDateTime::now_utc);
                Box::pin(async move {
                    Ok(WorkflowRunEvent {
                        id: Uuid::new_v4(),
                        workflow_run_id: event.workflow_run_id,
                        workflow_id: event.workflow_id,
                        workspace_id: event.workspace_id,
                        triggered_by: event.triggered_by,
                        connection_type: event.connection_type,
                        connection_id: event.connection_id,
                        recorded_at,
                    })
                })
            })
            .times(0..);

        let workspace_repo: Arc<StaticWorkspaceMembershipRepository> =
            Arc::new(StaticWorkspaceMembershipRepository::with_run_limit(1));
        let period_start = OffsetDateTime::now_utc() - Duration::days(60);
        let period_end = period_start + Duration::days(30);
        workspace_repo
            .upsert_workspace_billing_cycle(workspace_id, "sub_123", period_start, period_end)
            .await
            .unwrap();

        let state = test_state(
            Arc::new(repo),
            workspace_repo.clone() as Arc<dyn WorkspaceRepository>,
        );

        let response = start_workflow_run(
            State(state),
            AuthSession(claims_fixture(owner_id, "member@example.com")),
            Path(workflow.id),
            None,
        )
        .await;

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(workspace_repo.release_calls(), 1);
        // The run ticket should use the billing cycle end because the current clock
        // is past the stored period end.
        let recorded = workspace_repo.last_period_starts();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0], period_end);
    }
}
