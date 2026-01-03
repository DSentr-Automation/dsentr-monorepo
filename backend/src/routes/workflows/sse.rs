use super::{
    crud::WorkflowContextQuery,
    helpers::{can_access_workflow_in_context, membership_roles_map, plan_context_for_user},
    prelude::*,
};

pub async fn sse_run_events(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path((workflow_id, run_id)): Path<(Uuid, Uuid)>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let user_id = Uuid::parse_str(&claims.id).ok();

    let state = app_state.clone();
    let s = stream! {
        let mut last_run_updated: Option<time::OffsetDateTime> = None;
        let mut last_node_updated: Option<time::OffsetDateTime> = None;
        let mut intv = tokio::time::interval(Duration::from_millis(800));
        loop {
            intv.tick().await;
            // If not authorized, emit error once and end
            if user_id.is_none() {
                let ev = Event::default().event("error").json_data(json!({"error": "unauthorized"})).unwrap();
                yield Ok::<Event, Infallible>(ev);
                break;
            }
            let uid = user_id.unwrap();
            // Send run update if newer
            if let Ok(Some(run)) = state
                .workflow_repo
                .get_workflow_run(uid, workflow_id, run_id)
                .await
            {
                if last_run_updated.map(|t| t < run.updated_at).unwrap_or(true) {
                    last_run_updated = Some(run.updated_at);
                    let ev = Event::default().event("run").json_data(&run).unwrap();
                    yield Ok::<Event, Infallible>(ev);
                }
            }

            // Send node runs if any updated
            if let Ok(nodes) = state
                .workflow_repo
                .list_workflow_node_runs(uid, workflow_id, run_id)
                .await
            {
                if let Some(max_upd) = nodes.iter().map(|n| n.updated_at).max() {
                    if last_node_updated.map(|t| t < max_upd).unwrap_or(true) {
                        last_node_updated = Some(max_upd);
                        let ev = Event::default().event("node_runs").json_data(&nodes).unwrap();
                        yield Ok::<Event, Infallible>(ev);
                    }
                }
            }

            // keep alive tick every ~10s to prevent proxies from closing
        }
    };

    Sse::new(s).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(10))
            .text("keepalive"),
    )
}

pub async fn sse_workflow_runs(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path(workflow_id): Path<Uuid>,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => Uuid::nil(),
    };
    let state = app_state.clone();
    let s = stream! {
        let mut last_ids: Option<Vec<(Uuid, String)>> = None;
        let mut intv = tokio::time::interval(Duration::from_millis(1000));
        loop {
            intv.tick().await;
            if user_id.is_nil() {
                let ev = Event::default().event("error").data("unauthorized");
                yield Ok::<Event, Infallible>(ev);
                break;
            }
            match state.workflow_repo.list_active_runs(user_id, Some(workflow_id)).await {
                Ok(runs) => {
                    let ids: Vec<(Uuid, String)> = runs.iter().map(|r| (r.id, r.status.clone())).collect();
                    let changed = last_ids.as_ref().map(|prev| prev != &ids).unwrap_or(true);
                    if changed {
                        last_ids = Some(ids);
                        let ev = Event::default().event("runs").json_data(&runs).unwrap();
                        yield Ok::<Event, Infallible>(ev);
                    } else {
                        yield Ok::<Event, Infallible>(Event::default().event("tick").data("{}"));
                    }
                }
                Err(_) => {
                    let ev = Event::default().event("error").data("fetch_failed");
                    yield Ok::<Event, Infallible>(ev);
                }
            }
        }
    };
    Sse::new(s).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(10))
            .text("keepalive"),
    )
}

pub async fn sse_global_runs(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
) -> Sse<impl tokio_stream::Stream<Item = Result<Event, Infallible>>> {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => Uuid::nil(),
    };
    let state = app_state.clone();
    let s = stream! {
        let mut last: Option<(bool, bool)> = None;
        let mut intv = tokio::time::interval(Duration::from_millis(1500));
        loop {
            intv.tick().await;
            if user_id.is_nil() {
                let ev = Event::default().event("error").data("unauthorized");
                yield Ok::<Event, Infallible>(ev);
                break;
            }
            match state.workflow_repo.list_active_runs(user_id, None).await {
                Ok(runs) => {
                    let has_running = runs.iter().any(|r| r.status == "running");
                    let has_queued = runs.iter().any(|r| r.status == "queued");
                    let cur = (has_running, has_queued);
                    if last.map(|p| p != cur).unwrap_or(true) {
                        last = Some(cur);
                        let payload = json!({"has_running": has_running, "has_queued": has_queued});
                        let ev = Event::default().event("status").json_data(payload).unwrap();
                        yield Ok::<Event, Infallible>(ev);
                    } else {
                        yield Ok::<Event, Infallible>(Event::default().event("tick").data("{}"));
                    }
                }
                Err(_) => {
                    let ev = Event::default().event("error").data("fetch_failed");
                    yield Ok::<Event, Infallible>(ev);
                }
            }
        }
    };
    Sse::new(s).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(10))
            .text("keepalive"),
    )
}

pub async fn sse_workflow_updates(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path(workflow_id): Path<Uuid>,
    Query(params): Query<WorkflowContextQuery>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    let workflow = match app_state
        .workflow_repo
        .find_workflow_for_member(user_id, workflow_id)
        .await
    {
        Ok(Some(workflow)) => workflow,
        Ok(None) => return JsonResponse::not_found("Workflow not found").into_response(),
        Err(err) => {
            eprintln!("Failed to load workflow for SSE: {:?}", err);
            return JsonResponse::server_error("Failed to stream workflow").into_response();
        }
    };

    let memberships = match app_state
        .workspace_repo
        .list_memberships_for_user(user_id)
        .await
    {
        Ok(memberships) => memberships,
        Err(err) => {
            eprintln!("Failed to load memberships for workflow SSE: {:?}", err);
            return JsonResponse::server_error("Failed to stream workflow").into_response();
        }
    };
    let roles_map = membership_roles_map(&memberships);
    let context = plan_context_for_user(claims.plan.as_deref(), &memberships, params.workspace);

    if params.workspace.is_some()
        && !matches!(
            context,
            crate::routes::workflows::helpers::PlanContext::WorkspaceOwned { .. }
                | crate::routes::workflows::helpers::PlanContext::WorkspaceMember { .. }
        )
    {
        return JsonResponse::forbidden("You do not have access to this workspace.")
            .into_response();
    }

    if !can_access_workflow_in_context(&workflow, context, &roles_map) {
        return JsonResponse::forbidden(
            "This workflow is not available in the current plan context.",
        )
        .into_response();
    }

    let mut last_seen = workflow.updated_at;
    let state = app_state.clone();

    let stream_user_id = user_id;
    let s = stream! {
        let mut initial_sent = false;
        let mut intv = tokio::time::interval(Duration::from_millis(1200));
        loop {
            if initial_sent {
                intv.tick().await;
            }
            match state
                .workflow_repo
                .find_workflow_for_member(stream_user_id, workflow_id)
                .await
            {
                Ok(Some(current)) => {
                    let should_emit = !initial_sent || current.updated_at > last_seen;
                    if should_emit {
                        last_seen = current.updated_at;
                        let ev = Event::default().event("workflow").json_data(&current).unwrap();
                        yield Ok::<Event, Infallible>(ev);
                    } else {
                        yield Ok::<Event, Infallible>(Event::default().event("tick").data("{}"));
                    }
                }
                Ok(None) => {
                    let ev = Event::default()
                        .event("error")
                        .json_data(json!({"error": "workflow_not_found"}))
                        .unwrap();
                    yield Ok::<Event, Infallible>(ev);
                    break;
                }
                Err(err) => {
                    eprintln!("Failed to poll workflow updates: {:?}", err);
                }
            }
            if !initial_sent {
                initial_sent = true;
            }
        }
    };

    Sse::new(s)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(10))
                .text("keepalive"),
        )
        .into_response()
}
