mod notion;

use std::sync::Arc;
use std::time::Duration;

use crate::db::postgres_webhook_ingress_dedupe_repository::PostgresWebhookIngressDedupeRepository;
use crate::db::webhook_ingress_dedupe_repository::WebhookIngressDedupeRepository;
use crate::engine::actions::{ensure_run_membership, ensure_workspace_plan};
use crate::engine::{
    build_action_registry, complete_run_with_retry, execute_run, ActionRegistry, ExecutorError,
};
use crate::models::workflow::Workflow;
use crate::models::workflow_run::WorkflowRun;
use crate::models::workflow_run_event::NewWorkflowRunEvent;
use crate::models::workflow_schedule::WorkflowSchedule;
use crate::runaway_protection::{
    enforce_runaway_protection, runaway_protection_enabled, RunawayProtectionError,
    RUNAWAY_PROTECTION_ERROR,
};
use crate::state::{AppState, WorkspaceLimitError, WorkspaceRunQuotaTicket};
#[cfg(test)]
use crate::utils::jwt::JwtKeys;
use crate::utils::schedule::{
    compute_next_run, offset_to_utc, parse_schedule_config, utc_to_offset,
};
use crate::utils::{egress_allowlist::normalize_egress_allowlist, workflow_connection_metadata};
use chrono::{Duration as ChronoDuration, Utc};
use serde_json::{json, Value};
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};
use tracing::{error, warn};
use uuid::Uuid;

use crate::models::oauth_token::ConnectedOAuthProvider;
#[cfg(test)]
fn test_jwt_keys() -> Arc<JwtKeys> {
    Arc::new(
        JwtKeys::from_secret("0123456789abcdef0123456789abcdef")
            .expect("test JWT secret should be valid"),
    )
}

const DEFAULT_NOTION_POLL_INTERVAL_SECONDS: i64 = 300;
const MIN_NOTION_POLL_INTERVAL_SECONDS: i64 = 30;
const MAX_NOTION_POLL_INTERVAL_SECONDS: i64 = 3600;
const WEBHOOK_DEDUPE_CLEANUP_INTERVAL_SECS: u64 = 86_400;

pub async fn start_background_workers(state: AppState) {
    let registry = Arc::new(build_action_registry());
    // Simple single-worker for now. Can be extended to multiple tasks.
    tokio::spawn(async move {
        if let Err(err) = worker_loop(state, registry).await {
            error!(
                run_id = %err.run_id(),
                operation = err.operation(),
                attempts = err.attempts(),
                error = %err,
                "worker loop terminated due to executor persistence failure"
            );
        }
    });
}

async fn worker_loop(state: AppState, registry: Arc<ActionRegistry>) -> Result<(), ExecutorError> {
    // Periodic retention cleanup
    let retention_days: i32 = std::env::var("RUN_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.parse::<i32>().ok())
        .unwrap_or(30);
    let mut last_cleanup = std::time::Instant::now();
    let mut last_dedupe_cleanup = std::time::Instant::now();
    let mut last_schedule_check = std::time::Instant::now();
    let use_leases = std::env::var("WORKER_USE_LEASES")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(true);
    let max_inflight = worker_pool_size();
    let run_deadline = run_deadline_duration(state.worker_lease_seconds);
    let mut inflight: JoinSet<(Uuid, Result<(), ExecutorError>)> = JoinSet::new();
    loop {
        while let Some(join_result) = inflight.try_join_next() {
            match join_result {
                Ok((_, Ok(()))) => {}
                Ok((_, Err(err))) => return Err(err),
                Err(err) => {
                    warn!(?err, "worker: run task panicked");
                }
            }
        }

        if last_cleanup.elapsed() > Duration::from_secs(600) {
            if let Err(err) = state.workflow_repo.purge_old_runs(retention_days).await {
                warn!(
                    worker_id = %state.worker_id,
                    error = ?err,
                    "worker: failed to purge old runs"
                );
            }
            last_cleanup = std::time::Instant::now();
        }

        if last_dedupe_cleanup.elapsed() > Duration::from_secs(WEBHOOK_DEDUPE_CLEANUP_INTERVAL_SECS)
        {
            let dedupe_repo = PostgresWebhookIngressDedupeRepository {
                pool: (*state.db_pool).clone(),
            };
            if let Err(err) = dedupe_repo.purge_old_dedupe_entries().await {
                warn!(
                    worker_id = %state.worker_id,
                    error = ?err,
                    "worker: failed to purge webhook ingress dedupe entries"
                );
            }
            last_dedupe_cleanup = std::time::Instant::now();
        }

        if last_schedule_check.elapsed() > Duration::from_secs(5) {
            if let Err(err) = process_due_schedules(&state).await {
                warn!(
                    worker_id = %state.worker_id,
                    error = ?err,
                    "worker: error processing schedules"
                );
            }
            last_schedule_check = std::time::Instant::now();
        }
        if use_leases {
            // Requeue any expired leases before claiming
            if let Err(err) = state.workflow_repo.requeue_expired_leases().await {
                warn!(?err, "worker: failed to requeue expired leases");
            }
        }

        if inflight.len() >= max_inflight {
            sleep(Duration::from_millis(100)).await;
            continue;
        }
        let claim_res = if use_leases {
            state
                .workflow_repo
                .claim_next_eligible_run(&state.worker_id, state.worker_lease_seconds)
                .await
        } else {
            state.workflow_repo.claim_next_queued_run().await
        };

        match claim_res {
            Ok(Some(run)) => {
                let state_clone = state.clone();
                let deadline = run_deadline;
                let registry_clone = registry.clone();
                inflight.spawn(async move {
                    run_with_deadline(state_clone, run, deadline, registry_clone).await
                });
            }
            Ok(None) => {
                if inflight.is_empty() {
                    sleep(Duration::from_millis(750)).await;
                } else {
                    sleep(Duration::from_millis(250)).await;
                }
            }
            Err(e) => {
                warn!(
                    worker_id = %state.worker_id,
                    error = ?e,
                    "worker: error claiming run"
                );
                sleep(Duration::from_millis(1000)).await;
            }
        }
    }
}

fn worker_pool_size() -> usize {
    std::env::var("WORKER_MAX_INFLIGHT_RUNS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(4)
}

fn run_deadline_duration(lease_seconds: i32) -> Duration {
    let env_deadline = std::env::var("WORKER_RUN_DEADLINE_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_secs);

    match env_deadline {
        Some(duration) => duration,
        None => {
            let base = lease_seconds.max(1) as u64;
            if base > 5 {
                Duration::from_secs(base - 5)
            } else {
                Duration::from_secs(base)
            }
        }
    }
}

async fn block_run_if_runaway(state: &AppState, run: &WorkflowRun) -> Result<bool, ExecutorError> {
    let Some(workspace_id) = run.workspace_id else {
        return Ok(false);
    };

    let settings = match state.db.get_user_settings(run.user_id).await {
        Ok(val) => val,
        Err(err) => {
            warn!(
                run_id = %run.id,
                workflow_id = %run.workflow_id,
                %workspace_id,
                ?err,
                "worker: failed to load user settings for runaway protection check"
            );
            complete_run_with_retry(state, run.id, "failed", Some(RUNAWAY_PROTECTION_ERROR))
                .await?;
            return Ok(true);
        }
    };

    if !runaway_protection_enabled(&settings, workspace_id) {
        return Ok(false);
    }

    match enforce_runaway_protection(state, workspace_id, &settings).await {
        Ok(()) => Ok(false),
        Err(RunawayProtectionError::RunawayProtectionTriggered { count, limit }) => {
            warn!(
                run_id = %run.id,
                workflow_id = %run.workflow_id,
                %workspace_id,
                %count,
                %limit,
                worker_id = %state.worker_id,
                "runaway protection triggered; failing run without execution"
            );
            let event = NewWorkflowRunEvent {
                workflow_run_id: run.id,
                workflow_id: run.workflow_id,
                workspace_id: run.workspace_id,
                triggered_by: format!("worker:{}", state.worker_id.as_ref()),
                connection_type: Some(RUNAWAY_PROTECTION_ERROR.to_string()),
                connection_id: None,
                recorded_at: None,
            };
            if let Err(err) = state.workflow_repo.record_run_event(event).await {
                warn!(
                    ?err,
                    run_id = %run.id,
                    workflow_id = %run.workflow_id,
                    "failed to record runaway protection run event"
                );
            }
            complete_run_with_retry(state, run.id, "failed", Some(RUNAWAY_PROTECTION_ERROR))
                .await?;
            Ok(true)
        }
        Err(RunawayProtectionError::Database(err)) => {
            warn!(
                ?err,
                run_id = %run.id,
                workflow_id = %run.workflow_id,
                %workspace_id,
                "worker: runaway protection enforcement failed"
            );
            complete_run_with_retry(state, run.id, "failed", Some(RUNAWAY_PROTECTION_ERROR))
                .await?;
            Ok(true)
        }
    }
}

async fn run_with_deadline(
    state: AppState,
    run: WorkflowRun,
    deadline: Duration,
    registry: Arc<ActionRegistry>,
) -> (Uuid, Result<(), ExecutorError>) {
    let run_id = run.id;

    let blocked = match block_run_if_runaway(&state, &run).await {
        Ok(blocked) => blocked,
        Err(err) => return (run_id, Err(err)),
    };
    if blocked {
        return (run_id, Ok(()));
    }

    if deadline.is_zero() {
        return (run_id, execute_run(state, run, registry).await.map(|_| ()));
    }

    match timeout(deadline, execute_run(state.clone(), run, registry)).await {
        Ok(result) => (run_id, result.map(|_| ())),
        Err(_) => {
            warn!(
                %run_id,
                worker_id = %state.worker_id,
                deadline_secs = deadline.as_secs(),
                "worker: run execution exceeded deadline"
            );
            let res = complete_run_with_retry(
                &state,
                run_id,
                "failed",
                Some("Worker execution deadline exceeded"),
            )
            .await;
            match res {
                Ok(()) => (run_id, Ok(())),
                Err(err) => (run_id, Err(err)),
            }
        }
    }
}

async fn process_due_schedules(state: &AppState) -> Result<(), sqlx::Error> {
    const MAX_SCHEDULES: i64 = 10;
    let schedules = state
        .workflow_repo
        .list_due_schedules(MAX_SCHEDULES)
        .await?;
    for schedule in schedules {
        let schedule_id = schedule.id;
        if let Err(err) = trigger_schedule(state, schedule).await {
            error!(
                worker_id = %state.worker_id,
                schedule_id = %schedule_id,
                error = ?err,
                "worker: failed to trigger schedule"
            );
        }
    }
    Ok(())
}

async fn trigger_schedule(state: &AppState, schedule: WorkflowSchedule) -> Result<(), sqlx::Error> {
    let next_time = match schedule.next_run_at {
        Some(ts) => ts,
        None => {
            state
                .workflow_repo
                .disable_workflow_schedule(schedule.workflow_id)
                .await?;
            return Ok(());
        }
    };

    let workflow_opt = state
        .workflow_repo
        .find_workflow_by_id(schedule.user_id, schedule.workflow_id)
        .await?;

    let workflow = match workflow_opt {
        Some(w) => w,
        None => {
            state
                .workflow_repo
                .disable_workflow_schedule(schedule.workflow_id)
                .await?;
            return Ok(());
        }
    };

    let settings = match state.db.get_user_settings(schedule.user_id).await {
        Ok(val) => val,
        Err(err) => {
            warn!(
                worker_id = %state.worker_id,
                user_id = %schedule.user_id,
                ?err,
                "worker: failed to load user settings for schedule"
            );
            Value::Object(Default::default())
        }
    };

    if let Some((notion_kind, notion_config)) = notion::parse_trigger_config(&schedule.config) {
        return trigger_notion_schedule(
            state,
            schedule,
            workflow,
            &settings,
            next_time,
            notion_kind,
            notion_config,
        )
        .await;
    }

    let last_run_utc = match offset_to_utc(next_time) {
        Some(dt) => dt,
        None => {
            state
                .workflow_repo
                .disable_workflow_schedule(schedule.workflow_id)
                .await?;
            return Ok(());
        }
    };

    let config = match parse_schedule_config(&schedule.config) {
        Some(cfg) => cfg,
        None => {
            state
                .workflow_repo
                .disable_workflow_schedule(schedule.workflow_id)
                .await?;
            return Ok(());
        }
    };

    let mut snapshot = workflow.data.clone();
    let (egress_allowlist, rejected_entries) =
        normalize_egress_allowlist(workflow.egress_allowlist.clone());
    if !rejected_entries.is_empty() {
        warn!(
            worker_id = %state.worker_id,
            workflow_id = %workflow.id,
            schedule_id = %schedule.id,
            rejected = ?rejected_entries,
            "Rejected invalid workflow egress allowlist entries"
        );
    }
    snapshot["_egress_allowlist"] = Value::Array(
        egress_allowlist
            .iter()
            .cloned()
            .map(Value::String)
            .collect(),
    );

    let trigger_meta =
        find_schedule_trigger_start_node(&snapshot, &schedule.config).map(|start_id| {
            let meta = build_trigger_context_meta(&snapshot, &start_id, "schedule");
            snapshot["_start_from_node"] = Value::String(start_id);
            meta
        });

    let mut context = snapshot
        .get("_trigger_context")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if let Value::Object(ref mut map) = context {
        map.insert("scheduled".to_string(), Value::Bool(true));
        map.insert(
            "scheduleId".to_string(),
            Value::String(schedule.id.to_string()),
        );
        map.insert(
            "scheduledFor".to_string(),
            Value::String(next_time.to_string()),
        );
        map.insert("scheduleConfig".to_string(), schedule.config.clone());
    } else {
        context = json!({
            "scheduled": true,
            "scheduleId": schedule.id,
            "scheduledFor": next_time.to_string(),
            "scheduleConfig": schedule.config.clone(),
        });
    }
    if let Some(meta) = trigger_meta.as_ref() {
        context = merge_trigger_context(context, meta, "schedule");
    }
    snapshot["_trigger_context"] = context;

    let connection_metadata = workflow_connection_metadata::collect(&snapshot);
    workflow_connection_metadata::embed(&mut snapshot, &connection_metadata);

    let mut workspace_quota: Option<WorkspaceRunQuotaTicket> = None;
    let mut skip_run = false;
    if let Some(workspace_id) = workflow.workspace_id {
        match enforce_runaway_protection(state, workspace_id, &settings).await {
            Ok(()) => {}
            Err(RunawayProtectionError::RunawayProtectionTriggered { count, limit }) => {
                warn!(
                    worker_id = %state.worker_id,
                    %workspace_id,
                    %schedule.id,
                    %count,
                    %limit,
                    "runaway protection blocked scheduled run creation"
                );
                skip_run = true;
            }
            Err(RunawayProtectionError::Database(err)) => {
                return Err(err);
            }
        }

        if !skip_run {
            match state.consume_workspace_run_quota(workspace_id).await {
                Ok(Some(ticket)) => {
                    if ticket.run_count > ticket.limit {
                        warn!(
                            worker_id = %state.worker_id,
                            %workspace_id,
                            overage_count = ticket.overage_count,
                            run_count = ticket.run_count,
                            %schedule.id,
                            %ticket.limit,
                            "workspace run overage recorded for scheduled run"
                        );
                    }
                    workspace_quota = Some(ticket);
                }
                Ok(None) => {}
                Err(WorkspaceLimitError::WorkspacePlanRequired) => {
                    warn!(
                        worker_id = %state.worker_id,
                        %workspace_id,
                        schedule_id = %schedule.id,
                        "skipping scheduled run because workspace reverted to the Solo plan"
                    );
                    skip_run = true;
                }
                Err(WorkspaceLimitError::RunLimitReached { limit }) => {
                    warn!(
                        worker_id = %state.worker_id,
                        %workspace_id,
                        schedule_id = %schedule.id,
                        %limit,
                        "workspace run usage exceeded limit; continuing and recording overage"
                    );
                }
                Err(WorkspaceLimitError::MemberLimitReached { limit }) => {
                    warn!(
                        worker_id = %state.worker_id,
                        %workspace_id,
                        schedule_id = %schedule.id,
                        %limit,
                        "unexpected member limit error while triggering schedule"
                    );
                    skip_run = true;
                }
                Err(WorkspaceLimitError::Database(err)) => {
                    return Err(err);
                }
            }
        }
    }

    if !skip_run {
        let outcome = match state
            .workflow_repo
            .create_workflow_run(
                schedule.user_id,
                schedule.workflow_id,
                workflow.workspace_id,
                snapshot,
                None,
            )
            .await
        {
            Ok(outcome) => outcome,
            Err(err) => {
                if let Some(ticket) = workspace_quota {
                    let _ = state.release_workspace_run_quota(ticket).await;
                }
                return Err(err);
            }
        };

        if let (Some(ticket), false) = (&workspace_quota, outcome.created) {
            let _ = state.release_workspace_run_quota(*ticket).await;
        }

        let run = outcome.run;
        let triggered_by = format!("schedule:{}", schedule.id);
        let events = workflow_connection_metadata::build_run_events(
            &run,
            &triggered_by,
            &connection_metadata,
        );
        for event in events {
            state.workflow_repo.record_run_event(event).await?;
        }
    }

    let now = Utc::now();
    let next_dt = compute_next_run(&config, Some(last_run_utc), now);
    let last_offset = match utc_to_offset(now) {
        Some(v) => v,
        None => {
            state
                .workflow_repo
                .disable_workflow_schedule(schedule.workflow_id)
                .await?;
            return Ok(());
        }
    };
    let next_offset = next_dt.and_then(utc_to_offset);
    state
        .workflow_repo
        .mark_schedule_run(schedule.id, last_offset, next_offset)
        .await?;

    Ok(())
}

async fn trigger_notion_schedule(
    state: &AppState,
    schedule: WorkflowSchedule,
    workflow: Workflow,
    settings: &Value,
    scheduled_for: time::OffsetDateTime,
    notion_kind: notion::NotionTriggerKind,
    notion_config: notion::NotionTriggerConfig,
) -> Result<(), sqlx::Error> {
    let now = Utc::now();
    let last_offset = match utc_to_offset(now) {
        Some(v) => v,
        None => {
            state
                .workflow_repo
                .disable_workflow_schedule(schedule.workflow_id)
                .await?;
            return Ok(());
        }
    };
    let next_offset = notion_next_run_offset(now, &notion_config);
    if next_offset.is_none() {
        warn!(
            schedule_id = %schedule.id,
            workflow_id = %schedule.workflow_id,
            "worker: unable to compute next Notion poll interval; disabling schedule"
        );
        state
            .workflow_repo
            .disable_workflow_schedule(schedule.workflow_id)
            .await?;
        return Ok(());
    }

    let scope_raw = notion_config.connection_scope.trim().to_ascii_lowercase();
    let connection_id = notion_config.connection_id.trim();
    if scope_raw.is_empty() || connection_id.is_empty() {
        warn!(
            schedule_id = %schedule.id,
            workflow_id = %schedule.workflow_id,
            "worker: Notion trigger missing connection scope or connection id"
        );
        state
            .workflow_repo
            .mark_schedule_run(schedule.id, last_offset, next_offset)
            .await?;
        return Ok(());
    }

    let access_token = match scope_raw.as_str() {
        "workspace" => {
            let Some(workspace_id) = workflow.workspace_id else {
                warn!(
                    schedule_id = %schedule.id,
                    workflow_id = %schedule.workflow_id,
                    "worker: Notion workspace trigger requires workspace-bound workflow"
                );
                state
                    .workflow_repo
                    .mark_schedule_run(schedule.id, last_offset, next_offset)
                    .await?;
                return Ok(());
            };
            if let Err(err) = ensure_run_membership(state, workspace_id, schedule.user_id).await {
                warn!(
                    schedule_id = %schedule.id,
                    workflow_id = %schedule.workflow_id,
                    %workspace_id,
                    %err,
                    "worker: Notion trigger workspace membership check failed"
                );
                state
                    .workflow_repo
                    .mark_schedule_run(schedule.id, last_offset, next_offset)
                    .await?;
                return Ok(());
            }
            if let Err(err) = ensure_workspace_plan(state, workspace_id).await {
                warn!(
                    schedule_id = %schedule.id,
                    workflow_id = %schedule.workflow_id,
                    %workspace_id,
                    %err,
                    "worker: Notion trigger requires workspace plan"
                );
                state
                    .workflow_repo
                    .mark_schedule_run(schedule.id, last_offset, next_offset)
                    .await?;
                return Ok(());
            }

            let parsed = match Uuid::parse_str(connection_id) {
                Ok(id) => id,
                Err(_) => {
                    warn!(
                        schedule_id = %schedule.id,
                        workflow_id = %schedule.workflow_id,
                        connection_id = %connection_id,
                        "worker: Notion workspace connection id must be a UUID"
                    );
                    state
                        .workflow_repo
                        .mark_schedule_run(schedule.id, last_offset, next_offset)
                        .await?;
                    return Ok(());
                }
            };

            match state
                .workspace_oauth
                .ensure_valid_workspace_token(parsed)
                .await
            {
                Ok(connection) => {
                    if connection.workspace_id != workspace_id {
                        warn!(
                            schedule_id = %schedule.id,
                            workflow_id = %schedule.workflow_id,
                            %workspace_id,
                            "worker: Notion workspace connection belongs to another workspace"
                        );
                        state
                            .workflow_repo
                            .mark_schedule_run(schedule.id, last_offset, next_offset)
                            .await?;
                        return Ok(());
                    }
                    if connection.provider != ConnectedOAuthProvider::Notion {
                        warn!(
                            schedule_id = %schedule.id,
                            workflow_id = %schedule.workflow_id,
                            "worker: Notion trigger connection is not Notion provider"
                        );
                        state
                            .workflow_repo
                            .mark_schedule_run(schedule.id, last_offset, next_offset)
                            .await?;
                        return Ok(());
                    }
                    connection.access_token
                }
                Err(err) => match err {
                    crate::services::oauth::workspace_service::WorkspaceOAuthError::Database(
                        db_err,
                    ) => return Err(db_err),
                    other => {
                        warn!(
                            schedule_id = %schedule.id,
                            workflow_id = %schedule.workflow_id,
                            error = %other,
                            "worker: failed to resolve Notion workspace access token"
                        );
                        state
                            .workflow_repo
                            .mark_schedule_run(schedule.id, last_offset, next_offset)
                            .await?;
                        return Ok(());
                    }
                },
            }
        }
        "personal" | "user" => {
            let parsed = match Uuid::parse_str(connection_id) {
                Ok(id) => id,
                Err(_) => {
                    warn!(
                        schedule_id = %schedule.id,
                        workflow_id = %schedule.workflow_id,
                        connection_id = %connection_id,
                        "worker: Notion personal connection id must be a UUID"
                    );
                    state
                        .workflow_repo
                        .mark_schedule_run(schedule.id, last_offset, next_offset)
                        .await?;
                    return Ok(());
                }
            };

            match state
                .oauth_accounts
                .ensure_valid_access_token_for_connection(schedule.user_id, parsed)
                .await
            {
                Ok(token) => {
                    if token.provider != ConnectedOAuthProvider::Notion {
                        warn!(
                            schedule_id = %schedule.id,
                            workflow_id = %schedule.workflow_id,
                            "worker: Notion trigger connection is not Notion provider"
                        );
                        state
                            .workflow_repo
                            .mark_schedule_run(schedule.id, last_offset, next_offset)
                            .await?;
                        return Ok(());
                    }
                    token.access_token
                }
                Err(err) => match err {
                    crate::services::oauth::account_service::OAuthAccountError::Database(
                        db_err,
                    ) => return Err(db_err),
                    other => {
                        warn!(
                            schedule_id = %schedule.id,
                            workflow_id = %schedule.workflow_id,
                            error = %other,
                            "worker: failed to resolve Notion personal access token"
                        );
                        state
                            .workflow_repo
                            .mark_schedule_run(schedule.id, last_offset, next_offset)
                            .await?;
                        return Ok(());
                    }
                },
            }
        }
        other => {
            warn!(
                schedule_id = %schedule.id,
                workflow_id = %schedule.workflow_id,
                scope = %other,
                "worker: Notion trigger has unsupported connection scope"
            );
            state
                .workflow_repo
                .mark_schedule_run(schedule.id, last_offset, next_offset)
                .await?;
            return Ok(());
        }
    };

    let poll_result = match notion::poll_database(
        &state.http_client,
        &access_token,
        &notion_config,
        notion_kind,
    )
    .await
    {
        Ok(result) => result,
        Err(err) => {
            if err.is_auth_error() {
                warn!(
                    schedule_id = %schedule.id,
                    workflow_id = %schedule.workflow_id,
                    "worker: Notion auth error while polling"
                );
            } else {
                warn!(
                    schedule_id = %schedule.id,
                    workflow_id = %schedule.workflow_id,
                    error = %err,
                    "worker: Notion polling failed"
                );
            }
            state
                .workflow_repo
                .mark_schedule_run(schedule.id, last_offset, next_offset)
                .await?;
            return Ok(());
        }
    };

    let mut schedule_config = schedule.config.clone();
    if let Some(updated) = notion::update_config_state(&schedule.config, &poll_result.state) {
        if updated != schedule.config {
            state
                .workflow_repo
                .upsert_workflow_schedule(
                    schedule.user_id,
                    schedule.workflow_id,
                    updated.clone(),
                    next_offset,
                )
                .await?;
        }
        schedule_config = updated;
    }

    let mut base_snapshot = workflow.data.clone();
    let (egress_allowlist, rejected_entries) =
        normalize_egress_allowlist(workflow.egress_allowlist.clone());
    if !rejected_entries.is_empty() {
        warn!(
            worker_id = %state.worker_id,
            workflow_id = %workflow.id,
            schedule_id = %schedule.id,
            rejected = ?rejected_entries,
            "Rejected invalid workflow egress allowlist entries"
        );
    }
    base_snapshot["_egress_allowlist"] = Value::Array(
        egress_allowlist
            .iter()
            .cloned()
            .map(Value::String)
            .collect(),
    );
    if let Some(obj) = base_snapshot.as_object_mut() {
        obj.remove("_trigger_context");
    }

    let trigger_meta = find_trigger_start_node_by_type(
        &base_snapshot,
        notion_kind.as_str(),
        Some(&schedule_config),
    )
    .map(|start_id| {
        let meta = build_trigger_context_meta(&base_snapshot, &start_id, "schedule");
        base_snapshot["_start_from_node"] = Value::String(start_id);
        meta
    });

    let connection_metadata = workflow_connection_metadata::collect(&base_snapshot);
    workflow_connection_metadata::embed(&mut base_snapshot, &connection_metadata);

    let triggered_by = format!("schedule:{}", schedule.id);
    let mut skip_all_runs = false;
    if let Some(workspace_id) = workflow.workspace_id {
        match enforce_runaway_protection(state, workspace_id, settings).await {
            Ok(()) => {}
            Err(RunawayProtectionError::RunawayProtectionTriggered { count, limit }) => {
                warn!(
                    worker_id = %state.worker_id,
                    %workspace_id,
                    %schedule.id,
                    %count,
                    %limit,
                    "runaway protection blocked Notion trigger runs"
                );
                skip_all_runs = true;
            }
            Err(RunawayProtectionError::Database(err)) => {
                return Err(err);
            }
        }
    }

    for event in poll_result.events {
        if skip_all_runs {
            break;
        }

        let mut snapshot = base_snapshot.clone();
        let mut context =
            build_notion_trigger_context(event, &schedule, &schedule_config, scheduled_for);
        if let Some(meta) = trigger_meta.as_ref() {
            context = merge_trigger_context(context, meta, "schedule");
        }
        snapshot["_trigger_context"] = context;

        let mut workspace_quota: Option<WorkspaceRunQuotaTicket> = None;
        let mut skip_run = false;
        if let Some(workspace_id) = workflow.workspace_id {
            match state.consume_workspace_run_quota(workspace_id).await {
                Ok(Some(ticket)) => {
                    if ticket.run_count > ticket.limit {
                        warn!(
                            worker_id = %state.worker_id,
                            %workspace_id,
                            overage_count = ticket.overage_count,
                            run_count = ticket.run_count,
                            %schedule.id,
                            %ticket.limit,
                            "workspace run overage recorded for Notion trigger run"
                        );
                    }
                    workspace_quota = Some(ticket);
                }
                Ok(None) => {}
                Err(WorkspaceLimitError::WorkspacePlanRequired) => {
                    warn!(
                        worker_id = %state.worker_id,
                        %workspace_id,
                        schedule_id = %schedule.id,
                        "skipping Notion trigger run because workspace reverted to the Solo plan"
                    );
                    skip_run = true;
                    skip_all_runs = true;
                }
                Err(WorkspaceLimitError::RunLimitReached { limit }) => {
                    warn!(
                        worker_id = %state.worker_id,
                        %workspace_id,
                        schedule_id = %schedule.id,
                        %limit,
                        "workspace run usage exceeded limit; continuing and recording overage"
                    );
                }
                Err(WorkspaceLimitError::MemberLimitReached { limit }) => {
                    warn!(
                        worker_id = %state.worker_id,
                        %workspace_id,
                        schedule_id = %schedule.id,
                        %limit,
                        "unexpected member limit error while triggering Notion schedule"
                    );
                    skip_run = true;
                    skip_all_runs = true;
                }
                Err(WorkspaceLimitError::Database(err)) => {
                    return Err(err);
                }
            }
        }

        if skip_run {
            continue;
        }

        let outcome = match state
            .workflow_repo
            .create_workflow_run(
                schedule.user_id,
                schedule.workflow_id,
                workflow.workspace_id,
                snapshot,
                None,
            )
            .await
        {
            Ok(outcome) => outcome,
            Err(err) => {
                if let Some(ticket) = workspace_quota {
                    let _ = state.release_workspace_run_quota(ticket).await;
                }
                return Err(err);
            }
        };

        if let (Some(ticket), false) = (&workspace_quota, outcome.created) {
            let _ = state.release_workspace_run_quota(*ticket).await;
        }

        let run = outcome.run;
        let events = workflow_connection_metadata::build_run_events(
            &run,
            &triggered_by,
            &connection_metadata,
        );
        for event in events {
            state.workflow_repo.record_run_event(event).await?;
        }
    }

    state
        .workflow_repo
        .mark_schedule_run(schedule.id, last_offset, next_offset)
        .await?;

    Ok(())
}

fn notion_poll_interval_seconds(config: &notion::NotionTriggerConfig) -> i64 {
    let from_env = std::env::var("NOTION_POLL_INTERVAL_SECONDS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok());
    let raw = config
        .poll_interval_seconds
        .or(from_env)
        .unwrap_or(DEFAULT_NOTION_POLL_INTERVAL_SECONDS);
    raw.clamp(
        MIN_NOTION_POLL_INTERVAL_SECONDS,
        MAX_NOTION_POLL_INTERVAL_SECONDS,
    )
}

fn notion_next_run_offset(
    now: chrono::DateTime<Utc>,
    config: &notion::NotionTriggerConfig,
) -> Option<time::OffsetDateTime> {
    let interval = notion_poll_interval_seconds(config).max(1);
    let next = now.checked_add_signed(ChronoDuration::seconds(interval))?;
    utc_to_offset(next)
}

fn build_notion_trigger_context(
    mut event: Value,
    schedule: &WorkflowSchedule,
    schedule_config: &Value,
    scheduled_for: time::OffsetDateTime,
) -> Value {
    if let Value::Object(map) = &mut event {
        map.insert("scheduled".to_string(), Value::Bool(true));
        map.insert(
            "scheduleId".to_string(),
            Value::String(schedule.id.to_string()),
        );
        map.insert(
            "scheduledFor".to_string(),
            Value::String(scheduled_for.to_string()),
        );
        map.insert("scheduleConfig".to_string(), schedule_config.clone());
        return event;
    }

    json!({
        "event": event,
        "scheduled": true,
        "scheduleId": schedule.id,
        "scheduledFor": scheduled_for.to_string(),
        "scheduleConfig": schedule_config.clone(),
    })
}

fn find_trigger_start_node_by_type(
    snapshot: &Value,
    trigger_type: &str,
    schedule_config: Option<&Value>,
) -> Option<String> {
    let nodes = snapshot.get("nodes")?.as_array()?;
    let normalized_trigger = trigger_type.trim().to_ascii_lowercase();
    let mut fallback: Option<String> = None;

    for node in nodes {
        let Some(node_type) = node.get("type").and_then(|v| v.as_str()) else {
            continue;
        };
        if !node_type.eq_ignore_ascii_case("trigger") {
            continue;
        }
        let Some(id) = node.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        let data = node.get("data").and_then(|v| v.as_object());
        let node_trigger = data
            .and_then(|map| map.get("triggerType"))
            .and_then(|v| v.as_str())
            .unwrap_or("Manual");
        if node_trigger.trim().to_ascii_lowercase() != normalized_trigger {
            continue;
        }

        if let (Some(config), Some(map)) = (schedule_config, data) {
            if notion_trigger_matches_config(map, config) {
                return Some(id.to_string());
            }
        }

        if fallback.is_none() {
            fallback = Some(id.to_string());
        }
    }

    fallback
}

fn notion_trigger_matches_config(
    node_data: &serde_json::Map<String, Value>,
    config: &Value,
) -> bool {
    let Some(config_map) = config.as_object() else {
        return false;
    };

    let config_db = read_config_string(config_map.get("databaseId"));
    if let Some(expected) = config_db.as_deref() {
        let actual = read_config_string(node_data.get("databaseId"));
        if actual.as_deref() != Some(expected) {
            return false;
        }
    }

    let config_conn = read_config_string(config_map.get("connectionId"));
    if let Some(expected) = config_conn.as_deref() {
        let actual = read_config_string(node_data.get("connectionId"));
        if actual.as_deref() != Some(expected) {
            return false;
        }
    }

    let config_scope = read_config_string(config_map.get("connectionScope"));
    if let Some(expected) = config_scope.as_deref() {
        let actual = read_config_string(node_data.get("connectionScope"));
        if actual.as_deref() != Some(expected) {
            return false;
        }
    }

    true
}

fn read_config_string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

struct TriggerContextMeta {
    node_id: String,
    trigger_type: String,
}

fn trigger_type_for_node(snapshot: &Value, node_id: &str) -> Option<String> {
    let nodes = snapshot.get("nodes")?.as_array()?;
    for node in nodes {
        let Some(id) = node.get("id").and_then(|value| value.as_str()) else {
            continue;
        };
        if id != node_id {
            continue;
        }
        return node
            .get("data")
            .and_then(|value| value.get("triggerType"))
            .and_then(|value| value.as_str())
            .map(|value| value.trim())
            .filter(|value| !value.is_empty())
            .map(|value| value.to_ascii_lowercase());
    }
    None
}

fn build_trigger_context_meta(
    snapshot: &Value,
    node_id: &str,
    fallback_type: &str,
) -> TriggerContextMeta {
    let trigger_type =
        trigger_type_for_node(snapshot, node_id).unwrap_or_else(|| fallback_type.to_string());
    TriggerContextMeta {
        node_id: node_id.to_string(),
        trigger_type,
    }
}

fn merge_trigger_context(mut context: Value, meta: &TriggerContextMeta, source: &str) -> Value {
    if let Value::Object(ref mut map) = context {
        map.insert(
            "trigger_node_id".to_string(),
            Value::String(meta.node_id.clone()),
        );
        map.insert(
            "trigger_type".to_string(),
            Value::String(meta.trigger_type.clone()),
        );
        map.insert("source".to_string(), Value::String(source.to_string()));
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

fn find_schedule_trigger_start_node(snapshot: &Value, schedule_config: &Value) -> Option<String> {
    let nodes = snapshot.get("nodes")?.as_array()?;
    let mut fallback: Option<String> = None;

    for node in nodes {
        let Some(node_type) = node.get("type").and_then(|v| v.as_str()) else {
            continue;
        };
        if !node_type.eq_ignore_ascii_case("trigger") {
            continue;
        }
        let Some(id) = node.get("id").and_then(|v| v.as_str()) else {
            continue;
        };
        let data = node.get("data").and_then(|v| v.as_object());
        let trigger_type = data
            .and_then(|map| map.get("triggerType"))
            .and_then(|v| v.as_str())
            .unwrap_or("Manual");
        if !trigger_type.eq_ignore_ascii_case("schedule") {
            continue;
        }
        if let Some(map) = data {
            if let Some(cfg) = map.get("scheduleConfig") {
                if cfg == schedule_config {
                    return Some(id.to_string());
                }
            }
        }
        if fallback.is_none() {
            fallback = Some(id.to_string());
        }
    }

    fallback
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Config, OAuthProviderConfig, OAuthSettings, StripeSettings, DEFAULT_WORKSPACE_MEMBER_LIMIT,
        DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT, RUNAWAY_LIMIT_5MIN,
    };
    use crate::db::mock_db::{
        MockDb, NoopWorkspaceRepository, StaticWorkspaceMembershipRepository,
    };
    use crate::db::mock_stripe_event_log_repository::MockStripeEventLogRepository;
    use crate::db::workflow_repository::{MockWorkflowRepository, WorkflowRepository};
    use crate::db::workspace_connection_repository::NoopWorkspaceConnectionRepository;
    use crate::engine::build_action_registry;
    use crate::models::workflow::Workflow;
    use crate::models::workflow_node_run::WorkflowNodeRun;
    use crate::models::workflow_run::WorkflowRun;
    use crate::models::workflow_run_event::{NewWorkflowRunEvent, WorkflowRunEvent};
    use crate::models::workflow_schedule::WorkflowSchedule;
    use crate::services::oauth::account_service::OAuthAccountService;
    use crate::services::oauth::github::mock_github_oauth::MockGitHubOAuth;
    use crate::services::oauth::google::mock_google_oauth::MockGoogleOAuth;
    use crate::services::oauth::workspace_service::WorkspaceOAuthService;
    use crate::services::smtp_mailer::MockMailer;
    use crate::state::{test_pg_pool, AppState};
    use mockall::predicate;
    use reqwest::Client;
    use serde_json::json;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use time::{Duration as TimeDuration, OffsetDateTime};
    use uuid::Uuid;

    fn build_executor_failure_state() -> AppState {
        let run = WorkflowRun {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            workflow_id: Uuid::new_v4(),
            workspace_id: Some(Uuid::new_v4()),
            snapshot: json!({
                "nodes": [
                    {"id": "trigger", "type": "trigger", "data": json!({"label": "Trigger"})}
                ],
                "edges": []
            }),
            status: "running".into(),
            error: None,
            idempotency_key: None,
            started_at: OffsetDateTime::now_utc(),
            resume_at: OffsetDateTime::now_utc(),
            finished_at: None,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };

        let mut repo = MockWorkflowRepository::new();
        repo.expect_list_due_schedules()
            .returning(|_| Box::pin(async { Ok(Vec::new()) }));
        repo.expect_requeue_expired_leases()
            .returning(|| Box::pin(async { Ok(0) }));
        repo.expect_count_workspace_runs_since()
            .returning(|_, _| Box::pin(async { Ok(0) }));
        let run_queue = Arc::new(Mutex::new(VecDeque::from([run.clone()])));
        let run_queue_claim = Arc::clone(&run_queue);
        repo.expect_claim_next_eligible_run()
            .returning(move |_, _| {
                let run_queue = Arc::clone(&run_queue_claim);
                Box::pin(async move { Ok(run_queue.lock().unwrap().pop_front()) })
            });
        repo.expect_record_run_event()
            .times(3)
            .returning(|_| Box::pin(async { Err(sqlx::Error::RowNotFound) }));

        let workflow_repo: Arc<dyn WorkflowRepository> = Arc::new(repo);
        let config = Arc::new(Config {
            database_url: String::new(),
            frontend_origin: "http://localhost".into(),
            admin_origin: "http://localhost".into(),
            oauth: OAuthSettings {
                google: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                github: OAuthProviderConfig {
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
            },
            github_app: crate::config::GitHubAppSettings::default(),
            github_webhook_source_id: None,
            api_secrets_encryption_key: vec![1u8; 32],
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
        });

        AppState {
            db: Arc::new(MockDb::default()),
            workflow_repo,
            workspace_repo: Arc::new(NoopWorkspaceRepository),
            workspace_connection_repo: Arc::new(NoopWorkspaceConnectionRepository),
            stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
            db_pool: test_pg_pool(),
            mailer: Arc::new(MockMailer::default()),
            google_oauth: Arc::new(MockGoogleOAuth::default()),
            github_oauth: Arc::new(MockGitHubOAuth::default()),
            oauth_accounts: OAuthAccountService::test_stub(),
            workspace_oauth: WorkspaceOAuthService::test_stub(),
            stripe: Arc::new(crate::services::stripe::MockStripeService::new()),
            integration_registry: crate::state::test_integration_registry(),
            http_client: Arc::new(Client::new()),
            config,
            worker_id: Arc::new("worker".into()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        }
    }

    struct EnvGuard {
        key: &'static str,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            std::env::set_var(key, value);
            EnvGuard { key }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            std::env::remove_var(self.key);
        }
    }

    #[tokio::test]
    async fn worker_loop_surfaces_executor_failures() {
        let _max_guard = EnvGuard::set("WORKER_MAX_INFLIGHT_RUNS", "1");
        let _deadline_guard = EnvGuard::set("WORKER_RUN_DEADLINE_SECONDS", "0");
        let state = build_executor_failure_state();
        let registry = Arc::new(build_action_registry());

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            worker_loop(state, registry),
        )
        .await
        .expect("worker loop should complete");

        let err = result.expect_err("expected executor error");
        assert_eq!(err.operation(), "record_run_event");
    }

    #[tokio::test]
    async fn worker_loop_initializes_with_structured_logging() {
        let subscriber = tracing_subscriber::fmt().with_test_writer().json().finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let _max_guard = EnvGuard::set("WORKER_MAX_INFLIGHT_RUNS", "1");
        let _deadline_guard = EnvGuard::set("WORKER_RUN_DEADLINE_SECONDS", "0");
        let state = build_executor_failure_state();
        let registry = Arc::new(build_action_registry());

        let result = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            worker_loop(state, registry),
        )
        .await
        .expect("worker loop should complete");

        assert!(
            result.is_err(),
            "worker loop should surface executor errors"
        );
    }

    #[tokio::test]
    async fn worker_handles_slow_runs_with_fresh_leases() {
        let _max_guard = EnvGuard::set("WORKER_MAX_INFLIGHT_RUNS", "2");
        let _deadline_guard = EnvGuard::set("WORKER_RUN_DEADLINE_SECONDS", "0");
        let _renew_guard = EnvGuard::set("RUN_LEASE_RENEWAL_INTERVAL_MS", "100");

        let workflow_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let workspace_id = Some(Uuid::new_v4());
        let snapshot = json!({
            "nodes": [
                {"id": "trigger", "type": "trigger", "data": json!({"label": "Trigger"})},
                {"id": "check1", "type": "condition", "data": json!({"label": "Check 1", "expression": "1 == 1"})},
                {"id": "check2", "type": "condition", "data": json!({"label": "Check 2", "expression": "1 == 1"})}
            ],
            "edges": [
                {"source": "trigger", "target": "check1"},
                {"source": "check1", "target": "check2"}
            ]
        });

        let build_run = |id: Uuid| WorkflowRun {
            id,
            user_id,
            workflow_id,
            workspace_id,
            snapshot: snapshot.clone(),
            status: "running".into(),
            error: None,
            idempotency_key: None,
            started_at: OffsetDateTime::now_utc(),
            resume_at: OffsetDateTime::now_utc(),
            finished_at: None,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };

        let runs_queue = Arc::new(Mutex::new(VecDeque::from([
            build_run(Uuid::new_v4()),
            build_run(Uuid::new_v4()),
        ])));
        let completed: Arc<Mutex<Vec<(Uuid, String)>>> = Arc::new(Mutex::new(Vec::new()));
        let renew_count = Arc::new(AtomicUsize::new(0));

        let mut repo = MockWorkflowRepository::new();
        repo.expect_list_due_schedules()
            .returning(|_| Box::pin(async { Ok(Vec::new()) }));
        repo.expect_requeue_expired_leases()
            .returning(|| Box::pin(async { Ok(0) }));
        repo.expect_count_workspace_runs_since()
            .returning(|_, _| Box::pin(async { Ok(0) }));
        let runs_queue_claim = Arc::clone(&runs_queue);
        repo.expect_claim_next_eligible_run()
            .returning(move |_, _| {
                let queue = Arc::clone(&runs_queue_claim);
                Box::pin(async move { Ok(queue.lock().unwrap().pop_front()) })
            });
        repo.expect_get_run_status()
            .returning(|_| Box::pin(async { Ok(Some("running".to_string())) }));
        let renew_calls = Arc::clone(&renew_count);
        repo.expect_renew_run_lease()
            .returning(move |run_id, _, _| {
                let renew_calls = Arc::clone(&renew_calls);
                Box::pin(async move {
                    let _ = run_id;
                    renew_calls.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
            });
        repo.expect_upsert_node_run().returning(
            move |run_id, node_id, name, node_type, inputs, outputs, status, error| {
                let node_id = node_id.to_owned();
                let name = name.map(|s| s.to_owned());
                let node_type = node_type.map(|s| s.to_owned());
                let status = status.to_owned();
                let error = error.map(|s| s.to_owned());
                let inputs = inputs.clone();
                let outputs = outputs.clone();

                Box::pin(async move {
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    Ok(WorkflowNodeRun {
                        id: Uuid::new_v4(),
                        run_id,
                        node_id,
                        name,
                        node_type,
                        inputs,
                        outputs,
                        status,
                        error,
                        started_at: OffsetDateTime::now_utc(),
                        finished_at: None,
                        created_at: OffsetDateTime::now_utc(),
                        updated_at: OffsetDateTime::now_utc(),
                    })
                })
            },
        );
        let completed_for_repo = Arc::clone(&completed);
        repo.expect_complete_workflow_run()
            .returning(move |run_id, status, _| {
                let completed = Arc::clone(&completed_for_repo);
                let status = status.to_string();
                Box::pin(async move {
                    completed.lock().unwrap().push((run_id, status));
                    Ok(())
                })
            });
        repo.expect_record_run_event().returning(|event| {
            Box::pin(async move {
                Ok(WorkflowRunEvent {
                    id: Uuid::new_v4(),
                    workflow_run_id: event.workflow_run_id,
                    workflow_id: event.workflow_id,
                    workspace_id: event.workspace_id,
                    triggered_by: event.triggered_by,
                    connection_type: event.connection_type,
                    connection_id: event.connection_id,
                    recorded_at: event.recorded_at.unwrap_or_else(OffsetDateTime::now_utc),
                })
            })
        });

        let workflow_repo: Arc<dyn WorkflowRepository> = Arc::new(repo);
        let config = Arc::new(Config {
            database_url: String::new(),
            frontend_origin: "http://localhost".into(),
            admin_origin: "http://localhost".into(),
            oauth: OAuthSettings {
                google: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                github: OAuthProviderConfig {
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
            },
            github_app: crate::config::GitHubAppSettings::default(),
            github_webhook_source_id: None,
            api_secrets_encryption_key: vec![1u8; 32],
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
        });

        let state = AppState {
            db: Arc::new(MockDb::default()),
            workflow_repo,
            workspace_repo: Arc::new(NoopWorkspaceRepository),
            workspace_connection_repo: Arc::new(NoopWorkspaceConnectionRepository),
            stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
            db_pool: test_pg_pool(),
            mailer: Arc::new(MockMailer::default()),
            google_oauth: Arc::new(MockGoogleOAuth::default()),
            github_oauth: Arc::new(MockGitHubOAuth::default()),
            oauth_accounts: OAuthAccountService::test_stub(),
            workspace_oauth: WorkspaceOAuthService::test_stub(),
            stripe: Arc::new(crate::services::stripe::MockStripeService::new()),
            integration_registry: crate::state::test_integration_registry(),
            http_client: Arc::new(Client::new()),
            config,
            worker_id: Arc::new("worker".into()),
            worker_lease_seconds: 3,
            jwt_keys: test_jwt_keys(),
        };

        let worker_state = state.clone();
        let worker_task = tokio::spawn(async move {
            let registry = Arc::new(build_action_registry());
            let _ = worker_loop(worker_state, registry).await;
        });

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if completed.lock().unwrap().len() >= 2 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("worker processed both runs");

        worker_task.abort();

        let finished = completed.lock().unwrap().clone();
        assert_eq!(finished.len(), 2, "expected both runs to finish");
        assert!(
            finished.iter().all(|(_, status)| status == "succeeded"),
            "runs should succeed"
        );

        assert!(
            renew_count.load(Ordering::SeqCst) >= 2,
            "lease renewals should occur for slow runs",
        );
    }

    #[tokio::test]
    async fn worker_continues_on_missing_connection_event() {
        // Ensure the worker doesn't terminate when a run event references a deleted connection.
        let _max_guard = EnvGuard::set("WORKER_MAX_INFLIGHT_RUNS", "1");
        let _deadline_guard = EnvGuard::set("WORKER_RUN_DEADLINE_SECONDS", "0");

        // Build a run snapshot that includes a workspace connection reference.
        let conn_id = Uuid::new_v4();
        let run = WorkflowRun {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            workflow_id: Uuid::new_v4(),
            workspace_id: Some(Uuid::new_v4()),
            snapshot: json!({
                "nodes": [
                    {"id": "trigger", "type": "trigger", "data": json!({
                        "label": "Trigger",
                        "connection": {"connectionScope": "workspace", "connectionId": conn_id}
                    })}
                ],
                "edges": []
            }),
            status: "running".into(),
            error: None,
            idempotency_key: None,
            started_at: OffsetDateTime::now_utc(),
            resume_at: OffsetDateTime::now_utc(),
            finished_at: None,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };

        let mut repo = MockWorkflowRepository::new();
        // Only one run to claim.
        let run_queue = Arc::new(Mutex::new(VecDeque::from([run.clone()])));
        let claim_queue = Arc::clone(&run_queue);
        repo.expect_list_due_schedules()
            .returning(|_| Box::pin(async { Ok(Vec::new()) }));
        repo.expect_requeue_expired_leases()
            .returning(|| Box::pin(async { Ok(0) }));
        repo.expect_count_workspace_runs_since()
            .returning(|_, _| Box::pin(async { Ok(0) }));
        repo.expect_claim_next_eligible_run()
            .returning(move |_, _| {
                let q = Arc::clone(&claim_queue);
                Box::pin(async move { Ok(q.lock().unwrap().pop_front()) })
            });

        // When the executor attempts to record the run event, it should have already
        // downgraded the missing connection reference to a safe fallback.
        repo.expect_record_run_event().returning(|event| {
            assert_eq!(event.connection_type.as_deref(), Some("connection_missing"));
            assert_eq!(event.connection_id, None);
            Box::pin(async move {
                Ok(WorkflowRunEvent {
                    id: Uuid::new_v4(),
                    workflow_run_id: event.workflow_run_id,
                    workflow_id: event.workflow_id,
                    workspace_id: event.workspace_id,
                    triggered_by: event.triggered_by,
                    connection_type: event.connection_type,
                    connection_id: event.connection_id,
                    recorded_at: OffsetDateTime::now_utc(),
                })
            })
        });

        // Minimal interactions to complete the run successfully.
        repo.expect_renew_run_lease()
            .returning(|_, _, _| Box::pin(async { Ok(()) }));
        repo.expect_get_run_status()
            .returning(|_| Box::pin(async { Ok(None) }));
        let run_id = run.id;
        repo.expect_upsert_node_run().returning(
            move |_, node_id, name, node_type, inputs, outputs, status, error| {
                let node_id = node_id.to_owned();
                let name = name.map(|s| s.to_owned());
                let node_type = node_type.map(|s| s.to_owned());
                let inputs = inputs.clone();
                let outputs = outputs.clone();
                let status = status.to_owned();
                let error = error.map(|s| s.to_owned());
                Box::pin(async move {
                    Ok(WorkflowNodeRun {
                        id: Uuid::new_v4(),
                        run_id,
                        node_id,
                        name,
                        node_type,
                        inputs,
                        outputs,
                        status,
                        error,
                        started_at: OffsetDateTime::now_utc(),
                        finished_at: None,
                        created_at: OffsetDateTime::now_utc(),
                        updated_at: OffsetDateTime::now_utc(),
                    })
                })
            },
        );
        repo.expect_complete_workflow_run()
            .returning(|_, _, _| Box::pin(async { Ok(()) }));

        let workflow_repo: Arc<dyn WorkflowRepository> = Arc::new(repo);
        let config = Arc::new(Config {
            database_url: String::new(),
            frontend_origin: "http://localhost".into(),
            admin_origin: "http://localhost".into(),
            oauth: OAuthSettings {
                google: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                github: OAuthProviderConfig {
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
            },
            github_app: crate::config::GitHubAppSettings::default(),
            github_webhook_source_id: None,
            api_secrets_encryption_key: vec![1u8; 32],
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
        });

        let state = AppState {
            db: Arc::new(MockDb::default()),
            workflow_repo,
            workspace_repo: Arc::new(NoopWorkspaceRepository),
            workspace_connection_repo: Arc::new(NoopWorkspaceConnectionRepository),
            stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
            db_pool: test_pg_pool(),
            mailer: Arc::new(MockMailer::default()),
            google_oauth: Arc::new(MockGoogleOAuth::default()),
            github_oauth: Arc::new(MockGitHubOAuth::default()),
            oauth_accounts: OAuthAccountService::test_stub(),
            workspace_oauth: WorkspaceOAuthService::test_stub(),
            stripe: Arc::new(crate::services::stripe::MockStripeService::new()),
            integration_registry: crate::state::test_integration_registry(),
            http_client: Arc::new(Client::new()),
            config,
            worker_id: Arc::new("worker".into()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        };

        // The worker loop should keep running without terminating; we assert it does not
        // return within the timeout window (i.e., stays alive).
        let registry = Arc::new(build_action_registry());
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            worker_loop(state, registry),
        )
        .await;
        assert!(
            result.is_err(),
            "worker should remain alive on safe persistence fallback"
        );
    }

    #[tokio::test]
    async fn trigger_schedule_records_connection_run_events() {
        let workspace_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let workflow_id = Uuid::new_v4();
        let workspace_connection = Uuid::new_v4();

        let workflow = Workflow {
            id: workflow_id,
            user_id,
            workspace_id: Some(workspace_id),
            name: "Scheduled".into(),
            description: None,
            data: json!({
                "nodes": [
                    {
                        "id": "schedule-1",
                        "type": "trigger",
                        "data": {
                            "label": "Schedule",
                            "triggerType": "schedule",
                            "scheduleConfig": {
                                "startDate": "2024-01-01",
                                "startTime": "00:00",
                                "timezone": "UTC"
                            }
                        }
                    },
                    {
                        "data": {
                            "connection": {
                                "connectionScope": "workspace",
                                "connectionId": workspace_connection
                            }
                        }
                    },
                    {
                        "data": {
                            "connection": {
                                "connectionScope": "user"
                            }
                        }
                    }
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

        let events: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
        let runs: Arc<Mutex<Vec<WorkflowRun>>> = Arc::new(Mutex::new(Vec::new()));
        let marks: Arc<Mutex<Vec<Uuid>>> = Arc::new(Mutex::new(Vec::new()));

        let mut repo = MockWorkflowRepository::new();

        let workflow_clone = workflow.clone();
        repo.expect_find_workflow_by_id()
            .with(predicate::always(), predicate::eq(workflow_id))
            .returning(move |_, _| {
                let workflow = workflow_clone.clone();
                Box::pin(async move { Ok(Some(workflow)) })
            });
        repo.expect_count_workspace_runs_since()
            .times(1)
            .returning(|_, _| Box::pin(async { Ok(0) }));

        let runs_clone = runs.clone();
        repo.expect_create_workflow_run().returning(
            move |user_id_param, workflow_id_param, workspace_id_param, snapshot, _| {
                let runs = runs_clone.clone();
                Box::pin(async move {
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
                    runs.lock().unwrap().push(run.clone());
                    Ok(crate::db::workflow_repository::CreateWorkflowRunOutcome {
                        run,
                        created: true,
                    })
                })
            },
        );

        let events_clone = events.clone();
        repo.expect_record_run_event().returning(move |event| {
            let events = events_clone.clone();
            Box::pin(async move {
                events.lock().unwrap().push(event.clone());
                Ok(WorkflowRunEvent {
                    id: Uuid::new_v4(),
                    workflow_run_id: event.workflow_run_id,
                    workflow_id: event.workflow_id,
                    workspace_id: event.workspace_id,
                    triggered_by: event.triggered_by,
                    connection_type: event.connection_type,
                    connection_id: event.connection_id,
                    recorded_at: OffsetDateTime::now_utc(),
                })
            })
        });

        let marks_clone = marks.clone();
        repo.expect_mark_schedule_run()
            .returning(move |schedule_id, _last_run, _next_run| {
                let marks = marks_clone.clone();
                Box::pin(async move {
                    marks.lock().unwrap().push(schedule_id);
                    Ok(())
                })
            });

        repo.expect_disable_workflow_schedule().times(0);

        let workflow_repo: Arc<dyn WorkflowRepository> = Arc::new(repo);

        let config = Arc::new(Config {
            database_url: String::new(),
            frontend_origin: "http://localhost".into(),
            admin_origin: "http://localhost".into(),
            oauth: OAuthSettings {
                google: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                github: OAuthProviderConfig {
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
            },
            github_app: crate::config::GitHubAppSettings::default(),
            github_webhook_source_id: None,
            api_secrets_encryption_key: vec![1u8; 32],
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
        });

        let state = AppState {
            db: Arc::new(MockDb::default()),
            workflow_repo,
            workspace_repo: Arc::new(NoopWorkspaceRepository),
            workspace_connection_repo: Arc::new(NoopWorkspaceConnectionRepository),
            stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
            db_pool: test_pg_pool(),
            mailer: Arc::new(MockMailer::default()),
            google_oauth: Arc::new(MockGoogleOAuth::default()),
            github_oauth: Arc::new(MockGitHubOAuth::default()),
            oauth_accounts: OAuthAccountService::test_stub(),
            workspace_oauth: WorkspaceOAuthService::test_stub(),
            stripe: Arc::new(crate::services::stripe::MockStripeService::new()),
            integration_registry: crate::state::test_integration_registry(),
            http_client: Arc::new(Client::new()),
            config: Arc::clone(&config),
            worker_id: Arc::new("worker".into()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        };

        let schedule = WorkflowSchedule {
            id: Uuid::new_v4(),
            workflow_id,
            user_id,
            config: json!({
                "startDate": "2024-01-01",
                "startTime": "00:00",
                "timezone": "UTC"
            }),
            next_run_at: Some(OffsetDateTime::now_utc() + TimeDuration::minutes(5)),
            last_run_at: None,
            enabled: true,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };

        trigger_schedule(&state, schedule.clone())
            .await
            .expect("schedule triggers");

        let events = events.lock().unwrap().clone();
        assert_eq!(events.len(), 2);
        let mut workspace_event = None;
        let mut user_event = None;
        for event in events {
            if event.connection_type.as_deref() == Some("workspace") {
                workspace_event = Some(event);
            } else {
                user_event = Some(event);
            }
        }

        let workspace_event = workspace_event.expect("workspace event exists");
        assert_eq!(workspace_event.connection_id, Some(workspace_connection));
        assert_eq!(workspace_event.workflow_id, workflow_id);
        assert_eq!(workspace_event.workspace_id, Some(workspace_id));
        assert_eq!(
            workspace_event.triggered_by,
            format!("schedule:{}", schedule.id)
        );

        let user_event = user_event.expect("user event exists");
        assert_eq!(user_event.connection_type.as_deref(), Some("user"));
        assert!(user_event.connection_id.is_none());
        assert_eq!(user_event.workflow_run_id, workspace_event.workflow_run_id);

        let recorded_runs = runs.lock().unwrap();
        assert_eq!(recorded_runs.len(), 1);
        assert_eq!(recorded_runs[0].workflow_id, workflow_id);
        assert_eq!(
            recorded_runs[0]
                .snapshot
                .get("_start_from_node")
                .and_then(|v| v.as_str()),
            Some("schedule-1")
        );

        assert!(marks.lock().unwrap().contains(&schedule.id));
    }

    #[tokio::test]
    async fn scheduled_run_respects_runaway_protection_before_quota() {
        let workspace_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let workflow_id = Uuid::new_v4();

        let workflow = Workflow {
            id: workflow_id,
            user_id,
            workspace_id: Some(workspace_id),
            name: "schedule runaway guard".into(),
            description: None,
            data: json!({
                "nodes": [{"id": "trigger", "type": "trigger", "data": {"label": "Trigger"}}],
                "edges": []
            }),
            concurrency_limit: 1,
            egress_allowlist: vec![],
            locked_by: None,
            locked_at: None,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };

        let mut repo = MockWorkflowRepository::new();
        repo.expect_find_workflow_by_id()
            .returning(move |user, id| {
                assert_eq!(user, user_id);
                assert_eq!(id, workflow_id);
                let wf = workflow.clone();
                Box::pin(async move { Ok(Some(wf)) })
            });
        repo.expect_count_workspace_runs_since()
            .times(1)
            .returning(|_, _| Box::pin(async { Ok(RUNAWAY_LIMIT_5MIN + 10) }));
        repo.expect_create_workflow_run().times(0);
        repo.expect_record_run_event().times(0);
        repo.expect_mark_schedule_run()
            .returning(|_, _, _| Box::pin(async { Ok(()) }));
        repo.expect_disable_workflow_schedule().times(0);

        let workflow_repo: Arc<dyn WorkflowRepository> = Arc::new(repo);
        let workspace_repo = StaticWorkspaceMembershipRepository::allowing();
        let config = Arc::new(Config {
            database_url: String::new(),
            frontend_origin: "http://localhost".into(),
            admin_origin: "http://localhost".into(),
            oauth: OAuthSettings {
                google: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                github: OAuthProviderConfig {
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
            },
            github_app: crate::config::GitHubAppSettings::default(),
            github_webhook_source_id: None,
            api_secrets_encryption_key: vec![1u8; 32],
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
        });

        let state = AppState {
            db: Arc::new(MockDb::default()),
            workflow_repo,
            workspace_repo: Arc::new(workspace_repo.clone()),
            workspace_connection_repo: Arc::new(NoopWorkspaceConnectionRepository),
            stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
            db_pool: test_pg_pool(),
            mailer: Arc::new(MockMailer::default()),
            google_oauth: Arc::new(MockGoogleOAuth::default()),
            github_oauth: Arc::new(MockGitHubOAuth::default()),
            oauth_accounts: OAuthAccountService::test_stub(),
            workspace_oauth: WorkspaceOAuthService::test_stub(),
            stripe: Arc::new(crate::services::stripe::MockStripeService::new()),
            integration_registry: crate::state::test_integration_registry(),
            http_client: Arc::new(Client::new()),
            config,
            worker_id: Arc::new("worker".into()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        };

        let schedule = WorkflowSchedule {
            id: Uuid::new_v4(),
            workflow_id,
            user_id,
            config: json!({
                "startDate": "2024-01-01",
                "startTime": "00:00",
                "timezone": "UTC"
            }),
            next_run_at: Some(OffsetDateTime::now_utc() + TimeDuration::minutes(5)),
            last_run_at: None,
            enabled: true,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };

        trigger_schedule(&state, schedule)
            .await
            .expect("schedule processing should complete");

        assert!(
            workspace_repo.last_period_starts().is_empty(),
            "quota should not increment when runaway protection blocks the run"
        );
    }

    #[tokio::test]
    async fn worker_blocks_run_and_records_event_when_over_limit() {
        let workspace_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let workflow_id = Uuid::new_v4();
        let run = WorkflowRun {
            id: Uuid::new_v4(),
            user_id,
            workflow_id,
            workspace_id: Some(workspace_id),
            snapshot: json!({"nodes": [], "edges": []}),
            status: "running".into(),
            error: None,
            idempotency_key: None,
            started_at: OffsetDateTime::now_utc(),
            resume_at: OffsetDateTime::now_utc(),
            finished_at: None,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        };

        #[allow(clippy::type_complexity)]
        let completions: Arc<Mutex<Vec<(Uuid, String, Option<String>)>>> =
            Arc::new(Mutex::new(Vec::new()));
        let recorded_events: Arc<Mutex<Vec<NewWorkflowRunEvent>>> =
            Arc::new(Mutex::new(Vec::new()));

        let mut repo = MockWorkflowRepository::new();
        repo.expect_count_workspace_runs_since()
            .times(1)
            .returning(|_, _| Box::pin(async { Ok(RUNAWAY_LIMIT_5MIN + 1) }));

        let events_clone = Arc::clone(&recorded_events);
        repo.expect_record_run_event().returning(move |event| {
            let events = Arc::clone(&events_clone);
            Box::pin(async move {
                events.lock().unwrap().push(event.clone());
                Ok(WorkflowRunEvent {
                    id: Uuid::new_v4(),
                    workflow_run_id: event.workflow_run_id,
                    workflow_id: event.workflow_id,
                    workspace_id: event.workspace_id,
                    triggered_by: event.triggered_by,
                    connection_type: event.connection_type.clone(),
                    connection_id: event.connection_id,
                    recorded_at: event.recorded_at.unwrap_or_else(OffsetDateTime::now_utc),
                })
            })
        });

        let completion_log = Arc::clone(&completions);
        repo.expect_complete_workflow_run()
            .times(1)
            .returning(move |run_id, status, error| {
                let log = Arc::clone(&completion_log);
                let status_owned = status.to_string();
                let error_owned = error.map(|e| e.to_string());
                Box::pin(async move {
                    log.lock()
                        .unwrap()
                        .push((run_id, status_owned, error_owned));
                    Ok(())
                })
            });

        let workflow_repo: Arc<dyn WorkflowRepository> = Arc::new(repo);
        let config = Arc::new(Config {
            database_url: String::new(),
            frontend_origin: "http://localhost".into(),
            admin_origin: "http://localhost".into(),
            oauth: OAuthSettings {
                google: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                github: OAuthProviderConfig {
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
            },
            github_app: crate::config::GitHubAppSettings::default(),
            github_webhook_source_id: None,
            api_secrets_encryption_key: vec![1u8; 32],
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
            runaway_limit_5min: 1,
            webhook_ingress_dedupe_mode: crate::config::WebhookIngressDedupeMode::Off,
            webhook_verification_body_fields: Vec::new(),
            webhook_verification_header_fields: Vec::new(),
            webhook_event_type_fields: vec!["event_type".to_string(), "type".to_string()],
        });

        let state = AppState {
            db: Arc::new(MockDb::default()),
            workflow_repo,
            workspace_repo: Arc::new(NoopWorkspaceRepository),
            workspace_connection_repo: Arc::new(NoopWorkspaceConnectionRepository),
            stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
            db_pool: test_pg_pool(),
            mailer: Arc::new(MockMailer::default()),
            google_oauth: Arc::new(MockGoogleOAuth::default()),
            github_oauth: Arc::new(MockGitHubOAuth::default()),
            oauth_accounts: OAuthAccountService::test_stub(),
            workspace_oauth: WorkspaceOAuthService::test_stub(),
            stripe: Arc::new(crate::services::stripe::MockStripeService::new()),
            integration_registry: crate::state::test_integration_registry(),
            http_client: Arc::new(Client::new()),
            config,
            worker_id: Arc::new("worker".into()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        };

        let registry = Arc::new(build_action_registry());
        let (_, result) = run_with_deadline(state, run, Duration::from_secs(5), registry).await;
        assert!(result.is_ok());

        let completions = completions.lock().unwrap();
        assert_eq!(completions.len(), 1);
        assert_eq!(completions[0].1, "failed");
        assert_eq!(completions[0].2.as_deref(), Some(RUNAWAY_PROTECTION_ERROR));

        let events = recorded_events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].connection_type.as_deref(),
            Some(RUNAWAY_PROTECTION_ERROR)
        );
        assert_eq!(events[0].workspace_id, Some(workspace_id));
    }
}
