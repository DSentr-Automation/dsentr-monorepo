use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::time::{sleep, timeout, Instant};
use tracing::{debug, error, warn};
use uuid::Uuid;

use super::actions::registry::{
    ActionExecutionResult, ActionExecutionSemantics, ActionRegistry, ActionRuntimeContext,
};
use crate::models::workflow_run::WorkflowRun;
use crate::models::workflow_run_event::NewWorkflowRunEvent;
use crate::state::AppState;
use crate::utils::{
    schedule::utc_to_offset,
    secrets::{hydrate_secrets_into_snapshot, read_secret_store},
    workflow_connection_metadata,
};

use super::graph::Graph;

const PERSISTENCE_MAX_ATTEMPTS: usize = 3;
#[cfg(test)]
const PERSISTENCE_INITIAL_BACKOFF: Duration = Duration::from_millis(5);
#[cfg(not(test))]
const PERSISTENCE_INITIAL_BACKOFF: Duration = Duration::from_millis(100);

#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error(
        "executor persistence operation `{operation}` failed for run {run_id} after {attempts} attempts: {source}"
    )]
    Persistence {
        run_id: Uuid,
        operation: &'static str,
        attempts: usize,
        #[source]
        source: sqlx::Error,
    },
}

impl ExecutorError {
    pub fn run_id(&self) -> Uuid {
        match self {
            ExecutorError::Persistence { run_id, .. } => *run_id,
        }
    }

    pub fn operation(&self) -> &'static str {
        match self {
            ExecutorError::Persistence { operation, .. } => operation,
        }
    }

    pub fn attempts(&self) -> usize {
        match self {
            ExecutorError::Persistence { attempts, .. } => *attempts,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunCompletion {
    Finished,
    Paused,
}

pub(crate) async fn execute_run(
    state: AppState,
    mut run: WorkflowRun,
    registry: Arc<ActionRegistry>,
) -> Result<RunCompletion, ExecutorError> {
    let triggered_by = format!("worker:{}", state.worker_id.as_ref());
    if let Err(err_msg) = hydrate_run_secrets(&state, &mut run).await {
        warn!(
            run_id = %run.id,
            workflow_id = %run.workflow_id,
            user_id = %run.user_id,
            worker_id = %state.worker_id,
            "executor: failing run during secret hydration: {err_msg}"
        );
        complete_run_with_retry(&state, run.id, "failed", Some(&err_msg)).await?;
        return Ok(RunCompletion::Finished);
    }
    let metadata = workflow_connection_metadata::collect(&run.snapshot);
    let events = workflow_connection_metadata::build_run_events(&run, &triggered_by, &metadata);
    for event in events {
        let state_clone = state.clone();
        retry_with_backoff(run.id, "record_run_event", || {
            let state = state_clone.clone();
            let event = event.clone();
            async move { record_run_event_safe(&state, event).await }
        })
        .await?;
    }

    let Some(graph) = Graph::from_snapshot(&run.snapshot) else {
        complete_run_with_retry(&state, run.id, "failed", Some("Invalid snapshot")).await?;
        return Ok(RunCompletion::Finished);
    };

    let mut context: Map<String, Value> = run
        .snapshot
        .get("_resume_context")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let start_from_value = run.snapshot.get("_start_from_node");
    let start_from = start_from_value
        .and_then(|value| value.as_str())
        .map(|value| value.to_string());
    let start_from_requested = start_from_value.is_some();
    if let Some(initial) = run.snapshot.get("_trigger_context") {
        let start_node = if let Some(start_id) = start_from.as_deref() {
            graph
                .nodes
                .get(start_id)
                .filter(|node| node.kind == "trigger")
        } else if start_from_requested {
            None
        } else {
            graph.nodes.values().find(|node| node.kind == "trigger")
        };
        let trigger_key = start_node.map(|n| context_keys(n).0);
        let key = trigger_key.unwrap_or_else(|| "trigger".to_string());
        if !context.contains_key(&key) {
            context.insert(key, initial.clone());
        }
    }

    let allowlist_env = std::env::var("ALLOWED_HTTP_DOMAINS")
        .ok()
        .unwrap_or_default();
    let env_allowed_hosts = parse_host_list(&allowlist_env);
    let snapshot_allowlist = collect_snapshot_allowlist(run.snapshot.get("_egress_allowlist"));
    let (allowed_hosts, rejected_allowlist) =
        merge_advisory_allowlist(&env_allowed_hosts, &snapshot_allowlist);

    if !rejected_allowlist.is_empty() {
        warn!(
            run_id = %run.id,
            workflow_id = %run.workflow_id,
            workspace_id = ?run.workspace_id,
            requested = ?snapshot_allowlist,
            rejected = ?rejected_allowlist,
            policy = if env_allowed_hosts.is_empty() {
                "none"
            } else {
                "env_allowlist"
            },
            "Snapshot egress allowlist entries rejected by policy"
        );

        let violation_event = NewWorkflowRunEvent {
            workflow_run_id: run.id,
            workflow_id: run.workflow_id,
            workspace_id: run.workspace_id,
            triggered_by: triggered_by.clone(),
            connection_type: Some("egress_policy_violation".to_string()),
            connection_id: None,
            recorded_at: None,
        };

        if let Err(err) = retry_with_backoff(run.id, "record_run_event", || {
            let state = state.clone();
            let event = violation_event.clone();
            async move { record_run_event_safe(&state, event).await }
        })
        .await
        {
            warn!(
                run_id = %run.id,
                workflow_id = %run.workflow_id,
                ?err,
                "Failed to record egress policy violation run event"
            );
        }
    }

    let disallow_env = std::env::var("DISALLOWED_HTTP_DOMAINS")
        .ok()
        .unwrap_or_default();
    let mut disallowed_hosts: Vec<String> = parse_host_list(&disallow_env);

    let is_prod =
        std::env::var("ENV").ok().map(|v| v.to_lowercase()) == Some("production".to_string());
    if is_prod {
        disallowed_hosts.push("metadata.google.internal".to_string());
    }
    disallowed_hosts.sort();
    disallowed_hosts.dedup();

    let default_deny = std::env::var("EGRESS_DEFAULT_DENY")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let action_registry = registry.as_ref();
    let mut visited: HashSet<String> = HashSet::new();
    let resume_from_nodes = run
        .snapshot
        .get("_resume_from_nodes")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.to_string())
                .collect::<Vec<String>>()
        });

    let mut stack: Vec<String> = if let Some(nodes) = resume_from_nodes {
        if !nodes.is_empty() {
            nodes
        } else if let Some(start_id) = start_from.clone() {
            vec![start_id]
        } else {
            Vec::new()
        }
    } else if start_from_requested {
        if let Some(start_id) = start_from.clone() {
            vec![start_id]
        } else {
            Vec::new()
        }
    } else {
        let mut s: Vec<String> = graph
            .nodes
            .values()
            .filter(|n| n.kind == "trigger")
            .map(|n| n.id.clone())
            .collect();
        if s.is_empty() {
            if let Some(first) = graph.nodes.keys().next() {
                s.push(first.clone());
            }
        }
        s
    };

    let cancellation_poll_interval = std::env::var("RUN_STATUS_POLL_INTERVAL_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(Duration::from_millis(500));
    let cancellation_poll_timeout = std::env::var("RUN_STATUS_POLL_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(Duration::from_millis(200));
    let lease_refresh_interval = std::env::var("RUN_LEASE_RENEWAL_INTERVAL_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or_else(|| {
            let lease_seconds = state.worker_lease_seconds.max(1) as u64;
            let half = lease_seconds / 2;
            if half == 0 {
                Duration::from_secs(1)
            } else {
                Duration::from_secs(half)
            }
        });

    let mut last_cancellation_check = Instant::now()
        .checked_sub(cancellation_poll_interval)
        .unwrap_or_else(Instant::now);
    let mut last_lease_refresh = Instant::now()
        .checked_sub(lease_refresh_interval)
        .unwrap_or_else(Instant::now);

    let mut canceled = false;
    while let Some(node_id) = stack.pop() {
        if last_lease_refresh.elapsed() >= lease_refresh_interval {
            match renew_run_lease_with_retry(
                &state,
                run.id,
                &state.worker_id,
                state.worker_lease_seconds,
            )
            .await
            {
                Ok(()) => {
                    last_lease_refresh = Instant::now();
                }
                Err(err) => {
                    warn!(
                        %run.id,
                        worker_id = %state.worker_id,
                        ?err,
                        "executor: failed to renew run lease, aborting run"
                    );
                    if let Err(cancel_err) = complete_run_with_retry(
                        &state,
                        run.id,
                        "canceled",
                        Some("Worker lost lease during execution"),
                    )
                    .await
                    {
                        warn!(
                            %run.id,
                            worker_id = %state.worker_id,
                            ?cancel_err,
                            "executor: failed to mark run canceled after lease renewal error"
                        );
                        return Err(cancel_err);
                    }
                    return Ok(RunCompletion::Finished);
                }
            }
        }

        if last_cancellation_check.elapsed() >= cancellation_poll_interval {
            match timeout(
                cancellation_poll_timeout,
                state.workflow_repo.get_run_status(run.id),
            )
            .await
            {
                Ok(Ok(Some(status))) if status == "canceled" => {
                    canceled = true;
                    break;
                }
                Ok(Ok(_)) => {
                    last_cancellation_check = Instant::now();
                }
                Ok(Err(err)) => {
                    warn!(
                        %run.id,
                        worker_id = %state.worker_id,
                        ?err,
                        "executor: failed to fetch run status for cancellation poll"
                    );
                    last_cancellation_check = Instant::now();
                }
                Err(_) => {
                    warn!(
                        %run.id,
                        worker_id = %state.worker_id,
                        poll_timeout_ms = cancellation_poll_timeout.as_millis() as u64,
                        "executor: cancellation status poll timed out"
                    );
                    last_cancellation_check = Instant::now();
                }
            }
        }
        if visited.contains(&node_id) {
            continue;
        }
        visited.insert(node_id.clone());

        let Some(node) = graph.nodes.get(&node_id) else {
            continue;
        };
        let kind = node.kind.as_str();

        let running = state
            .workflow_repo
            .upsert_node_run(
                run.id,
                &node.id,
                node.data
                    .get("label")
                    .and_then(|v| v.as_str())
                    .or(Some(kind))
                    .map(|s| s as &str),
                Some(kind),
                Some(node.data.clone()),
                None,
                "running",
                None,
            )
            .await
            .ok();

        let context_value = Value::Object(context.clone());
        let node_label = node
            .data
            .get("label")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        debug!(
            node_id = %node.id,
            node_kind = %node.kind,
            node_label,
            context = %context_value,
            "Executing workflow node"
        );

        let has_action_type = node
            .data
            .get("actionType")
            .and_then(|v| v.as_str())
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false);

        let execution: Result<(ActionExecutionSemantics, ActionExecutionResult), (String, bool)> =
            async {
                let action = action_registry.resolve(node).map_err(|err| (err, true))?;
                action
                    .validator
                    .validate(node)
                    .map_err(|err| (err, false))?;

                let runtime = ActionRuntimeContext {
                    node,
                    context: &context_value,
                    allowed_hosts: &allowed_hosts,
                    disallowed_hosts: &disallowed_hosts,
                    default_deny,
                    is_prod,
                    state: &state,
                    run: &run,
                };

                let result = action
                    .executor
                    .execute(runtime)
                    .await
                    .map_err(|err| (err, false))?;
                if matches!(result, ActionExecutionResult::Pause { .. })
                    && action.semantics != ActionExecutionSemantics::Resumable
                {
                    return Err((
                        format!(
                            "Action `{}` returned a pause but is not resumable",
                            action.action_type
                        ),
                        true,
                    ));
                }

                Ok((action.semantics, result))
            }
            .await;

        match execution {
            Ok((
                semantics,
                ActionExecutionResult::Immediate {
                    outputs,
                    selected_next,
                },
            )) => {
                if let Some(nr) = running {
                    let _ = state
                        .workflow_repo
                        .upsert_node_run(
                            run.id,
                            &node.id,
                            nr.name.as_deref(),
                            nr.node_type.as_deref(),
                            nr.inputs.clone(),
                            Some(outputs.clone()),
                            "succeeded",
                            None,
                        )
                        .await;
                }

                // Insert node outputs into the workflow context under both the
                // original-cased label and a lowercase alias (for backward
                // compatibility with existing templates that used lowercased
                // node names). Field/property casing remains respected.
                let (primary_key, alias_key) = context_keys(node);
                context.insert(primary_key, outputs.clone());
                if let Some(alias) = alias_key {
                    // If an alias exists and differs from the primary key, also insert it
                    context.insert(alias, outputs.clone());
                }

                let resolution =
                    resolve_next_nodes(&graph, &node_id, semantics, &outputs, selected_next);
                if let Some(invalid) = resolution.invalid_selected {
                    warn!(
                        %run.id,
                        workflow_id = %run.workflow_id,
                        node_id = %node.id,
                        invalid_selected_next = %invalid,
                        "Executor received selectedNext that does not exist in the graph; using outgoing edges instead"
                    );
                }
                for next in resolution.nodes.into_iter().rev() {
                    stack.push(next);
                }
            }
            Ok((semantics, ActionExecutionResult::Pause { outputs, resume_at })) => {
                if let Some(nr) = running {
                    let _ = state
                        .workflow_repo
                        .upsert_node_run(
                            run.id,
                            &node.id,
                            nr.name.as_deref(),
                            nr.node_type.as_deref(),
                            nr.inputs.clone(),
                            Some(outputs.clone()),
                            "succeeded",
                            None,
                        )
                        .await;
                }

                let (primary_key, alias_key) = context_keys(node);
                context.insert(primary_key, outputs.clone());
                if let Some(alias) = alias_key {
                    context.insert(alias, outputs.clone());
                }

                let resolution = resolve_next_nodes(&graph, &node_id, semantics, &outputs, None);
                let next_nodes = resolution.nodes;
                let mut snapshot = run.snapshot.clone();
                if let Value::Object(ref mut map) = snapshot {
                    map.insert(
                        "_resume_context".to_string(),
                        Value::Object(context.clone()),
                    );
                    map.insert(
                        "_resume_from_nodes".to_string(),
                        Value::Array(
                            next_nodes
                                .iter()
                                .map(|id| Value::String(id.clone()))
                                .collect(),
                        ),
                    );
                    if let Some(first) = next_nodes.first() {
                        map.insert("_start_from_node".to_string(), Value::String(first.clone()));
                    }
                    map.insert(
                        "_resume_at".to_string(),
                        Value::String(resume_at.to_rfc3339()),
                    );
                }

                let resume_at_offset = match utc_to_offset(resume_at) {
                    Some(val) => val,
                    None => {
                        let msg = "Failed to convert resume_at to OffsetDateTime".to_string();
                        let _ = insert_dead_letter_with_retry(&state, &run, &msg).await;
                        complete_run_with_retry(&state, run.id, "failed", Some(&msg)).await?;
                        return Ok(RunCompletion::Finished);
                    }
                };
                pause_run_with_retry(&state, run.id, snapshot, resume_at_offset).await?;
                return Ok(RunCompletion::Paused);
            }
            Err((err_msg, force_fail)) => {
                let mut next_nodes: Vec<String> = vec![];
                if let Some(nr) = running {
                    let _ = state
                        .workflow_repo
                        .upsert_node_run(
                            run.id,
                            &node.id,
                            nr.name.as_deref(),
                            nr.node_type.as_deref(),
                            nr.inputs.clone(),
                            None,
                            "failed",
                            Some(&err_msg),
                        )
                        .await;
                }

                let stop_on_error = node
                    .data
                    .get("stopOnError")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
                if force_fail || stop_on_error || !has_action_type {
                    if let Err(err) = insert_dead_letter_with_retry(&state, &run, &err_msg).await {
                        // Attempt to still mark the run failed before bubbling up the error.
                        let _ =
                            complete_run_with_retry(&state, run.id, "failed", Some(&err_msg)).await;
                        return Err(err);
                    }
                    complete_run_with_retry(&state, run.id, "failed", Some(&err_msg)).await?;
                    return Ok(RunCompletion::Finished);
                } else {
                    next_nodes.extend(
                        graph
                            .outgoing(&node_id)
                            .iter()
                            .map(|edge| edge.target.clone()),
                    );
                }

                for next in next_nodes.into_iter().rev() {
                    stack.push(next);
                }
            }
        }
    }

    if canceled {
        complete_run_with_retry(&state, run.id, "canceled", None).await?;
    } else {
        complete_run_with_retry(&state, run.id, "succeeded", None).await?;
    }

    Ok(RunCompletion::Finished)
}

fn context_keys(node: &super::graph::Node) -> (String, Option<String>) {
    // Prefer the node label if present; preserve its original casing.
    // Also provide a lowercase alias to maintain compatibility with
    // previously-generated templates that referenced lowercased node names.
    let label_opt = node
        .data
        .get("label")
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());

    if let Some(label) = label_opt {
        let primary = label.to_string();
        let lower = label.to_lowercase();
        if lower != label {
            (primary, Some(lower))
        } else {
            (primary, None)
        }
    } else {
        (node.id.clone(), None)
    }
}

#[derive(Debug)]
struct NextResolution {
    nodes: Vec<String>,
    invalid_selected: Option<String>,
}

fn resolve_next_nodes(
    graph: &Graph,
    node_id: &str,
    semantics: ActionExecutionSemantics,
    outputs: &Value,
    selected_next: Option<String>,
) -> NextResolution {
    let mut nodes: Vec<String> = vec![];

    let push_outgoing = |targets: &mut Vec<String>| {
        if semantics == ActionExecutionSemantics::Conditional {
            let desired_handle = outputs
                .get("result")
                .and_then(|v| v.as_bool())
                .map(|is_true| if is_true { "cond-true" } else { "cond-false" });

            if let Some(handle) = desired_handle {
                targets.extend(
                    graph
                        .outgoing(node_id)
                        .iter()
                        .filter(|edge| edge.source_handle.as_deref() == Some(handle))
                        .map(|edge| edge.target.clone()),
                );
            } else {
                targets.extend(
                    graph
                        .outgoing(node_id)
                        .iter()
                        .map(|edge| edge.target.clone()),
                );
            }
        } else {
            targets.extend(
                graph
                    .outgoing(node_id)
                    .iter()
                    .map(|edge| edge.target.clone()),
            );
        }
    };

    match selected_next {
        Some(next_id) => {
            if graph.nodes.contains_key(&next_id) {
                nodes.push(next_id);
                NextResolution {
                    nodes,
                    invalid_selected: None,
                }
            } else {
                push_outgoing(&mut nodes);
                NextResolution {
                    nodes,
                    invalid_selected: Some(next_id),
                }
            }
        }
        None => {
            push_outgoing(&mut nodes);
            NextResolution {
                nodes,
                invalid_selected: None,
            }
        }
    }
}

async fn retry_with_backoff<T, Fut, F>(
    run_id: Uuid,
    operation: &'static str,
    mut op: F,
) -> Result<T, ExecutorError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, sqlx::Error>>,
{
    let mut attempt = 0usize;
    let mut backoff = PERSISTENCE_INITIAL_BACKOFF;

    loop {
        attempt += 1;
        match op().await {
            Ok(value) => return Ok(value),
            Err(err) if attempt < PERSISTENCE_MAX_ATTEMPTS => {
                warn!(
                    %run_id,
                    operation,
                    attempt,
                    ?err,
                    "executor persistence operation failed; retrying"
                );
                sleep(backoff).await;
                backoff = backoff.saturating_mul(2);
            }
            Err(err) => {
                error!(
                    %run_id,
                    operation,
                    attempt,
                    ?err,
                    "executor persistence operation exhausted retries"
                );
                return Err(ExecutorError::Persistence {
                    run_id,
                    operation,
                    attempts: attempt,
                    source: err,
                });
            }
        }
    }
}

async fn hydrate_run_secrets(state: &AppState, run: &mut WorkflowRun) -> Result<(), String> {
    let settings = state
        .db
        .get_user_settings(run.user_id)
        .await
        .map_err(|err| {
            warn!(
                run_id = %run.id,
                workflow_id = %run.workflow_id,
                user_id = %run.user_id,
                ?err,
                "executor: failed to load user settings for secrets"
            );
            "Failed to load workflow secrets".to_string()
        })?;

    let (secret_store, _) = read_secret_store(&settings, &state.config.api_secrets_encryption_key)
        .map_err(|err| {
            warn!(
                run_id = %run.id,
                workflow_id = %run.workflow_id,
                user_id = %run.user_id,
                ?err,
                "executor: failed to decrypt workflow secrets"
            );
            "Failed to decrypt workflow secrets".to_string()
        })?;

    hydrate_secrets_into_snapshot(&mut run.snapshot, &secret_store);

    Ok(())
}

fn parse_host_list(raw: &str) -> Vec<String> {
    let mut hosts: Vec<String> = raw
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    hosts.sort();
    hosts.dedup();
    hosts
}

fn collect_snapshot_allowlist(value: Option<&Value>) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    if let Some(arr) = value.and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(s) = item.as_str() {
                let trimmed = s.trim().to_lowercase();
                if !trimmed.is_empty() {
                    hosts.push(trimmed);
                }
            }
        }
    }
    hosts.sort();
    hosts.dedup();
    hosts
}

fn merge_advisory_allowlist(
    env_hosts: &[String],
    snapshot_hosts: &[String],
) -> (Vec<String>, Vec<String>) {
    let mut allowed: HashSet<String> = env_hosts.iter().cloned().collect();
    let mut rejected: Vec<String> = Vec::new();

    if env_hosts.is_empty() {
        allowed.extend(snapshot_hosts.iter().cloned());
    } else {
        let env_set: HashSet<&str> = env_hosts.iter().map(|s| s.as_str()).collect();
        for host in snapshot_hosts {
            if env_set.contains(host.as_str()) {
                allowed.insert(host.clone());
            } else {
                rejected.push(host.clone());
            }
        }
    }

    let mut allowed_vec: Vec<String> = allowed.into_iter().collect();
    allowed_vec.sort();
    (allowed_vec, rejected)
}

async fn record_run_event_safe(
    state: &AppState,
    event: NewWorkflowRunEvent,
) -> Result<crate::models::workflow_run_event::WorkflowRunEvent, sqlx::Error> {
    // If the event references a workspace connection, pre-check existence to avoid FK violations.
    if let Some(conn_id) = event.connection_id {
        match state.workspace_connection_repo.find_by_id(conn_id).await {
            Ok(Some(_)) => {
                // proceed
            }
            Ok(None) => {
                // Missing connection: log and fall back to a sentinel event.
                warn!(
                    run_id = %event.workflow_run_id,
                    workflow_id = %event.workflow_id,
                    workspace_id = ?event.workspace_id,
                    connection_id = %conn_id,
                    "Foreign key reference to deleted connection, skipping event"
                );
                let mut fallback = event.clone();
                fallback.connection_id = None;
                fallback.connection_type = Some("connection_missing".to_string());
                return state.workflow_repo.record_run_event(fallback).await;
            }
            Err(_) => {
                // If the pre-check fails (transient), proceed to attempt insert and rely on DB error handling.
            }
        }
    }

    match state.workflow_repo.record_run_event(event.clone()).await {
        Ok(row) => Ok(row),
        Err(err) => {
            // Handle FK violations explicitly: Postgres SQLSTATE 23503
            if let sqlx::Error::Database(db_err) = &err {
                if db_err.code().as_deref() == Some("23503") {
                    let missing_id = event.connection_id;
                    warn!(
                        run_id = %event.workflow_run_id,
                        workflow_id = %event.workflow_id,
                        workspace_id = ?event.workspace_id,
                        connection_id = ?missing_id,
                        code = "23503",
                        "Foreign key reference to deleted connection, inserting fallback event"
                    );
                    let mut fallback = event.clone();
                    fallback.connection_id = None;
                    fallback.connection_type = Some("connection_missing".to_string());
                    return state.workflow_repo.record_run_event(fallback).await;
                }
            }
            Err(err)
        }
    }
}

async fn insert_dead_letter_with_retry(
    state: &AppState,
    run: &WorkflowRun,
    error: &str,
) -> Result<(), ExecutorError> {
    let repo = state.workflow_repo.clone();
    let snapshot = run.snapshot.clone();
    let error = error.to_string();

    retry_with_backoff(run.id, "insert_dead_letter", move || {
        let repo = repo.clone();
        let snapshot = snapshot.clone();
        let error = error.clone();
        async move {
            repo.insert_dead_letter(
                run.user_id,
                run.workflow_id,
                run.id,
                &error,
                snapshot.clone(),
            )
            .await
        }
    })
    .await
}

async fn pause_run_with_retry(
    state: &AppState,
    run_id: Uuid,
    snapshot: Value,
    resume_at: OffsetDateTime,
) -> Result<(), ExecutorError> {
    let repo = state.workflow_repo.clone();
    retry_with_backoff(run_id, "pause_workflow_run", move || {
        let repo = repo.clone();
        let snapshot = snapshot.clone();
        async move { repo.pause_workflow_run(run_id, snapshot, resume_at).await }
    })
    .await
}

async fn renew_run_lease_with_retry(
    state: &AppState,
    run_id: Uuid,
    worker_id: &str,
    lease_seconds: i32,
) -> Result<(), ExecutorError> {
    let repo = state.workflow_repo.clone();
    let worker_id = worker_id.to_string();

    retry_with_backoff(run_id, "renew_run_lease", move || {
        let repo = repo.clone();
        let worker_id = worker_id.clone();
        async move {
            repo.renew_run_lease(run_id, &worker_id, lease_seconds)
                .await
        }
    })
    .await
}

pub(crate) async fn complete_run_with_retry(
    state: &AppState,
    run_id: Uuid,
    status: &str,
    error: Option<&str>,
) -> Result<(), ExecutorError> {
    let repo = state.workflow_repo.clone();
    let status = status.to_string();
    let error = error.map(|e| e.to_string());

    retry_with_backoff(run_id, "complete_workflow_run", move || {
        let repo = repo.clone();
        let status = status.clone();
        let error = error.clone();
        async move {
            repo.complete_workflow_run(run_id, &status, error.as_deref())
                .await
        }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Config, OAuthProviderConfig, OAuthSettings, StripeSettings, DEFAULT_WORKSPACE_MEMBER_LIMIT,
        DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT, RUNAWAY_LIMIT_5MIN,
    };
    use crate::db::mock_db::{MockDb, NoopWorkspaceRepository};
    use crate::db::mock_stripe_event_log_repository::MockStripeEventLogRepository;
    use crate::db::workflow_repository::{MockWorkflowRepository, WorkflowRepository};
    use crate::db::workspace_connection_repository::NoopWorkspaceConnectionRepository;
    use crate::engine::actions::registry::ActionExecutionSemantics;
    use crate::engine::build_action_registry;
    use crate::models::workflow_run::WorkflowRun;
    use crate::models::workflow_run_event::WorkflowRunEvent;
    use crate::runaway_protection::{enforce_runaway_protection, RunawayProtectionError};
    use crate::services::oauth::account_service::OAuthAccountService;
    use crate::services::oauth::github::mock_github_oauth::MockGitHubOAuth;
    use crate::services::oauth::google::mock_google_oauth::MockGoogleOAuth;
    use crate::services::oauth::workspace_service::WorkspaceOAuthService;
    use crate::services::smtp_mailer::MockMailer;
    use crate::services::stripe::MockStripeService;
    use crate::state::{test_pg_pool, AppState};
    use crate::utils::jwt::JwtKeys;
    use reqwest::Client;
    use serde_json::json;
    use std::sync::{Arc, Mutex};
    use time::OffsetDateTime;
    use uuid::Uuid;

    fn test_jwt_keys() -> Arc<JwtKeys> {
        Arc::new(
            JwtKeys::from_secret("0123456789abcdef0123456789abcdef")
                .expect("test JWT secret should be valid"),
        )
    }

    fn build_state(repo: MockWorkflowRepository) -> AppState {
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
                token_encryption_key: vec![0u8; 32],
            },
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

        let workflow_repo: Arc<dyn WorkflowRepository> = Arc::new(repo);

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
            stripe: Arc::new(MockStripeService::new()),
            integration_registry: crate::state::test_integration_registry(),
            http_client: Arc::new(Client::new()),
            config,
            worker_id: Arc::new("worker-test".into()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        }
    }

    #[test]
    fn merge_allowlist_intersects_with_env_policy() {
        let env_hosts = vec!["api.example.com".to_string(), "*.trusted.dev".to_string()];
        let snapshot_hosts = vec![
            "api.example.com".to_string(),
            "api.example.com".to_string(),
            "malicious.example.com".to_string(),
            "*.trusted.dev".to_string(),
        ];

        let (allowed, rejected) = merge_advisory_allowlist(&env_hosts, &snapshot_hosts);

        assert_eq!(allowed, vec!["*.trusted.dev", "api.example.com"]);
        assert_eq!(rejected, vec!["malicious.example.com"]);
    }

    #[test]
    fn merge_allowlist_allows_snapshot_when_no_env_policy() {
        let env_hosts: Vec<String> = Vec::new();
        let snapshot_hosts = vec!["example.com".to_string(), "api.example.com".to_string()];

        let (allowed, rejected) = merge_advisory_allowlist(&env_hosts, &snapshot_hosts);

        assert_eq!(allowed, vec!["api.example.com", "example.com"]);
        assert!(rejected.is_empty());
    }

    #[test]
    fn collect_snapshot_allowlist_dedupes_and_normalizes() {
        let snapshot = json!(["Example.com", " example.com ", 1, null, "api.example.com"]);

        let hosts = collect_snapshot_allowlist(Some(&snapshot));

        assert_eq!(hosts, vec!["api.example.com", "example.com"]);
    }

    #[test]
    fn resolve_next_nodes_prefers_valid_selected_next() {
        let graph = Graph::from_snapshot(&json!({
            "nodes": [
                {"id": "n1", "type": "action", "data": {}},
                {"id": "n2", "type": "action", "data": {}},
                {"id": "n3", "type": "action", "data": {}}
            ],
            "edges": [
                {"id": "e1", "source": "n1", "target": "n2"},
                {"id": "e2", "source": "n1", "target": "n3"}
            ]
        }))
        .expect("graph should build");

        let outputs = json!({});
        let resolution = resolve_next_nodes(
            &graph,
            "n1",
            ActionExecutionSemantics::Standard,
            &outputs,
            Some("n3".to_string()),
        );

        assert_eq!(resolution.nodes, vec!["n3"]);
        assert!(resolution.invalid_selected.is_none());
    }

    #[test]
    fn resolve_next_nodes_falls_back_when_selected_missing() {
        let graph = Graph::from_snapshot(&json!({
            "nodes": [
                {"id": "cond-1", "type": "condition", "data": {}},
                {"id": "true-branch", "type": "action", "data": {}},
                {"id": "false-branch", "type": "action", "data": {}}
            ],
            "edges": [
                {"id": "true-edge", "source": "cond-1", "target": "true-branch", "sourceHandle": "cond-true"},
                {"id": "false-edge", "source": "cond-1", "target": "false-branch", "sourceHandle": "cond-false"}
            ]
        }))
        .expect("graph should build");

        let outputs = json!({"result": true});
        let resolution = resolve_next_nodes(
            &graph,
            "cond-1",
            ActionExecutionSemantics::Conditional,
            &outputs,
            Some("missing".into()),
        );

        assert_eq!(resolution.nodes, vec!["true-branch"]);
        assert_eq!(resolution.invalid_selected.as_deref(), Some("missing"));
    }

    fn base_run(node_type: &str, data: serde_json::Value) -> WorkflowRun {
        let now = OffsetDateTime::now_utc();
        WorkflowRun {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            workflow_id: Uuid::new_v4(),
            workspace_id: Some(Uuid::new_v4()),
            snapshot: json!({
                "nodes": [
                    {
                        "id": "node-1",
                        "type": node_type,
                        "data": data,
                    }
                ],
                "edges": []
            }),
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

    fn dummy_node_run(
        run_id: Uuid,
        status: &str,
    ) -> crate::models::workflow_node_run::WorkflowNodeRun {
        let now = OffsetDateTime::now_utc();
        crate::models::workflow_node_run::WorkflowNodeRun {
            id: Uuid::new_v4(),
            run_id,
            node_id: "node-1".into(),
            name: Some("node".into()),
            node_type: Some("trigger".into()),
            inputs: None,
            outputs: None,
            status: status.into(),
            error: None,
            started_at: now,
            finished_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[tokio::test]
    async fn record_run_event_failure_bubbles() {
        let run = base_run("trigger", json!({"label": "Trigger"}));

        let mut repo = MockWorkflowRepository::new();
        repo.expect_record_run_event()
            .times(PERSISTENCE_MAX_ATTEMPTS)
            .returning(|_event| Box::pin(async { Err(sqlx::Error::RowNotFound) }));

        let state = build_state(repo);
        let registry = Arc::new(build_action_registry());

        let err = execute_run(state, run, registry)
            .await
            .expect_err("should bubble error");
        assert_eq!(err.operation(), "record_run_event");
        assert_eq!(err.attempts(), PERSISTENCE_MAX_ATTEMPTS);
    }

    #[tokio::test]
    async fn complete_workflow_run_failure_bubbles() {
        let run = base_run("trigger", json!({"label": "Trigger"}));

        let mut repo = MockWorkflowRepository::new();
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
                    recorded_at: OffsetDateTime::now_utc(),
                })
            })
        });
        repo.expect_renew_run_lease()
            .returning(|_, _, _| Box::pin(async { Ok(()) }));
        repo.expect_get_run_status()
            .returning(|_| Box::pin(async { Ok(None) }));
        let run_id = run.id;
        repo.expect_upsert_node_run()
            .returning(move |_, _, _, _, _, _, _, _| {
                let node_run = dummy_node_run(run_id, "running");
                Box::pin(async move { Ok(node_run) })
            });
        repo.expect_complete_workflow_run()
            .times(PERSISTENCE_MAX_ATTEMPTS)
            .returning(|_, _, _| Box::pin(async { Err(sqlx::Error::RowNotFound) }));

        let state = build_state(repo);
        let registry = Arc::new(build_action_registry());

        let err = execute_run(state, run, registry)
            .await
            .expect_err("should bubble error");
        assert_eq!(err.operation(), "complete_workflow_run");
        assert_eq!(err.attempts(), PERSISTENCE_MAX_ATTEMPTS);
    }

    #[tokio::test]
    async fn insert_dead_letter_failure_bubbles() {
        let run = base_run("condition", json!({"label": "Condition"}));

        let mut repo = MockWorkflowRepository::new();
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
                    recorded_at: OffsetDateTime::now_utc(),
                })
            })
        });
        repo.expect_renew_run_lease()
            .returning(|_, _, _| Box::pin(async { Ok(()) }));
        repo.expect_get_run_status()
            .returning(|_| Box::pin(async { Ok(None) }));
        let run_id = run.id;
        repo.expect_upsert_node_run()
            .returning(move |_, _, _, _, _, _, _, _| {
                let node_run = dummy_node_run(run_id, "running");
                Box::pin(async move { Ok(node_run) })
            });
        repo.expect_insert_dead_letter()
            .times(PERSISTENCE_MAX_ATTEMPTS)
            .returning(|_, _, _, _, _| Box::pin(async { Err(sqlx::Error::RowNotFound) }));
        repo.expect_complete_workflow_run()
            .returning(|_, _, _| Box::pin(async { Ok(()) }));

        let state = build_state(repo);
        let registry = Arc::new(build_action_registry());

        let err = execute_run(state, run, registry)
            .await
            .expect_err("should bubble error");
        assert_eq!(err.operation(), "insert_dead_letter");
        assert_eq!(err.attempts(), PERSISTENCE_MAX_ATTEMPTS);
    }

    #[tokio::test]
    async fn success_path_still_completes() {
        let run = base_run("trigger", json!({"label": "Trigger"}));

        let mut repo = MockWorkflowRepository::new();
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
                    recorded_at: OffsetDateTime::now_utc(),
                })
            })
        });
        repo.expect_renew_run_lease()
            .returning(|_, _, _| Box::pin(async { Ok(()) }));
        repo.expect_get_run_status()
            .returning(|_| Box::pin(async { Ok(None) }));
        let run_id = run.id;
        repo.expect_upsert_node_run()
            .returning(move |_, _, _, _, _, _, _, _| {
                let node_run = dummy_node_run(run_id, "running");
                Box::pin(async move { Ok(node_run) })
            });
        repo.expect_complete_workflow_run()
            .returning(|_, _, _| Box::pin(async { Ok(()) }));

        let state = build_state(repo);
        let registry = Arc::new(build_action_registry());

        execute_run(state, run, registry)
            .await
            .expect("success path should still complete");
    }

    #[tokio::test]
    async fn execute_run_starts_from_explicit_trigger_node() {
        let run_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        let run = WorkflowRun {
            id: run_id,
            user_id: Uuid::new_v4(),
            workflow_id: Uuid::new_v4(),
            workspace_id: Some(Uuid::new_v4()),
            snapshot: json!({
                "nodes": [
                    {"id": "550e8400-e29b-41d4-a716-446655440001", "type": "trigger", "data": {"label": "First"}},
                    {"id": "550e8400-e29b-41d4-a716-446655440002", "type": "trigger", "data": {"label": "Second"}}
                ],
                "edges": [],
                "_start_from_node": "550e8400-e29b-41d4-a716-446655440002"
            }),
            status: "running".into(),
            error: None,
            idempotency_key: None,
            started_at: now,
            resume_at: now,
            finished_at: None,
            created_at: now,
            updated_at: now,
        };

        let mut repo = MockWorkflowRepository::new();
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
                    recorded_at: OffsetDateTime::now_utc(),
                })
            })
        });
        repo.expect_renew_run_lease()
            .returning(|_, _, _| Box::pin(async { Ok(()) }));
        repo.expect_get_run_status()
            .returning(|_| Box::pin(async { Ok(None) }));
        let seen_nodes: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_nodes_clone = seen_nodes.clone();
        repo.expect_upsert_node_run().times(2).returning(
            move |_, node_id, _, _, _, _, status, _| {
                let seen = seen_nodes_clone.clone();
                let node_run = dummy_node_run(run_id, status);
                let node_id = node_id.to_string();
                Box::pin(async move {
                    seen.lock().expect("seen nodes lock poisoned").push(node_id);
                    Ok(node_run)
                })
            },
        );
        repo.expect_complete_workflow_run()
            .returning(|_, _, _| Box::pin(async { Ok(()) }));

        let state = build_state(repo);
        let registry = Arc::new(build_action_registry());

        execute_run(state, run, registry)
            .await
            .expect("run should complete");

        let recorded = seen_nodes.lock().expect("seen nodes lock poisoned").clone();
        assert_eq!(recorded.len(), 2);
        assert!(recorded
            .iter()
            .all(|id| id == "550e8400-e29b-41d4-a716-446655440002"));
    }

    #[tokio::test]
    async fn delay_node_schedules_resume() {
        let run_id = Uuid::new_v4();
        let now = OffsetDateTime::now_utc();
        let run = WorkflowRun {
            id: run_id,
            user_id: Uuid::new_v4(),
            workflow_id: Uuid::new_v4(),
            workspace_id: Some(Uuid::new_v4()),
            snapshot: json!({
                "nodes": [
                    {"id": "delay-1", "type": "delay", "data": {"label": "Wait", "config": {"mode": "duration", "wait_for": {"minutes": 1}}}},
                    {"id": "action-1", "type": "action", "data": {"label": "Next", "actionType": "http", "params": {"url": "", "method": "GET", "headers": [], "queryParams": [], "bodyType": "raw", "body": "", "formBody": [], "authType": "none", "authUsername": "", "authPassword": "", "authToken": ""}}}
                ],
                "edges": [
                    {"id": "edge-1", "source": "delay-1", "target": "action-1", "type": "nodeEdge"}
                ],
                "_start_from_node": "delay-1"
            }),
            status: "running".into(),
            error: None,
            idempotency_key: None,
            started_at: now,
            resume_at: now,
            finished_at: None,
            created_at: now,
            updated_at: now,
        };

        let mut repo = MockWorkflowRepository::new();
        repo.expect_record_run_event().returning(|event| {
            Box::pin(async move {
                Ok(crate::models::workflow_run_event::WorkflowRunEvent {
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
        repo.expect_insert_dead_letter().times(0);
        repo.expect_renew_run_lease()
            .returning(|_, _, _| Box::pin(async { Ok(()) }));
        repo.expect_get_run_status()
            .returning(|_| Box::pin(async { Ok(None) }));
        let pause_called = Arc::new(Mutex::new(false));
        let pause_called_clone = pause_called.clone();
        repo.expect_pause_workflow_run()
            .times(1)
            .returning(move |rid, snapshot, resume_at| {
                let flag = pause_called_clone.clone();
                Box::pin(async move {
                    assert_eq!(rid, run_id);
                    assert!(resume_at > OffsetDateTime::now_utc());
                    let obj = snapshot.as_object().expect("snapshot should be an object");
                    assert!(obj.contains_key("_resume_context"));
                    assert!(obj.contains_key("_resume_from_nodes"));
                    *flag.lock().expect("flag lock poisoned") = true;
                    Ok(())
                })
            });
        repo.expect_upsert_node_run()
            .times(2)
            .returning(move |_, _, _, _, _, _, status, _| {
                let node_run = dummy_node_run(run_id, status);
                Box::pin(async move { Ok(node_run) })
            });
        repo.expect_complete_workflow_run().times(0);

        let state = build_state(repo);
        let registry = Arc::new(build_action_registry());

        let result = execute_run(state, run, registry)
            .await
            .expect("delay node should pause for resume");
        assert_eq!(result, RunCompletion::Paused);
        assert!(*pause_called.lock().expect("flag lock poisoned"));
    }

    #[tokio::test]
    async fn missing_workspace_connection_records_safe_fallback_event() {
        // Build a run that references a workspace connection ID that does not exist.
        let missing_conn = Uuid::new_v4();
        let run = base_run(
            "trigger",
            json!({
                "label": "Trigger",
                "connection": {"connectionScope": "workspace", "connectionId": missing_conn}
            }),
        );

        let mut repo = MockWorkflowRepository::new();
        // Expect a single event to be recorded, but with connection_id cleared and type marked as connection_missing.
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
        repo.expect_renew_run_lease()
            .returning(|_, _, _| Box::pin(async { Ok(()) }));
        repo.expect_get_run_status()
            .returning(|_| Box::pin(async { Ok(None) }));
        let run_id = run.id;
        repo.expect_upsert_node_run()
            .returning(move |_, _, _, _, _, _, _, _| {
                let node_run = dummy_node_run(run_id, "running");
                Box::pin(async move { Ok(node_run) })
            });
        repo.expect_complete_workflow_run()
            .returning(|_, _, _| Box::pin(async { Ok(()) }));

        let state = build_state(repo);
        let registry = Arc::new(build_action_registry());

        // Should complete without surfacing an executor error.
        execute_run(state, run, registry)
            .await
            .expect("executor should gracefully handle missing connection FK");
    }

    #[tokio::test]
    async fn runaway_protection_allows_runs_under_limit() {
        let workspace_id = Uuid::new_v4();
        let mut repo = MockWorkflowRepository::new();
        repo.expect_count_workspace_runs_since()
            .times(1)
            .returning(|_, _| Box::pin(async { Ok(1) }));

        let state = build_state(repo);
        let settings = serde_json::json!({});

        enforce_runaway_protection(&state, workspace_id, &settings)
            .await
            .expect("runs under the limit should pass");
    }

    #[tokio::test]
    async fn runaway_protection_skips_when_disabled_for_workspace() {
        let workspace_id = Uuid::new_v4();
        let mut repo = MockWorkflowRepository::new();
        repo.expect_count_workspace_runs_since().times(0);

        let state = build_state(repo);
        let settings = serde_json::json!({
            "workflows": {
                "runaway_protection_enabled": {
                    workspace_id.to_string(): false
                }
            }
        });

        enforce_runaway_protection(&state, workspace_id, &settings)
            .await
            .expect("disabled protection should skip checks");
    }

    #[tokio::test]
    async fn runaway_protection_blocks_when_over_limit() {
        let workspace_id = Uuid::new_v4();
        let mut repo = MockWorkflowRepository::new();
        repo.expect_count_workspace_runs_since()
            .times(1)
            .returning(|_, _| Box::pin(async { Ok(RUNAWAY_LIMIT_5MIN + 10) }));

        let state = build_state(repo);
        let settings = serde_json::json!({});

        let err = enforce_runaway_protection(&state, workspace_id, &settings)
            .await
            .expect_err("over the limit should trigger protection");

        match err {
            RunawayProtectionError::RunawayProtectionTriggered { count, limit } => {
                assert!(count > limit);
                assert_eq!(limit, RUNAWAY_LIMIT_5MIN);
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }
}
