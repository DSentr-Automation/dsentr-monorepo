use super::{
    helpers::{
        can_access_workflow_in_context, can_access_workspace_in_context,
        collect_github_trigger_mappings, diff_user_nodes_only, enforce_solo_workflow_limit,
        is_supported_github_event_type, is_unique_violation, membership_roles_map,
        plan_context_for_user, plan_violation_response, sync_workflow_schedule,
        workflow_is_active, GitHubTriggerMapping, GitHubTriggerMappingError, PlanContext,
    },
    prelude::*,
};
use crate::{
    db::{
        postgres_oauth_token_repository::PostgresUserOAuthTokenRepository,
        postgres_provider_trigger_repository::PostgresProviderTriggerRepository,
    },
    models::{
        oauth_token::ConnectedOAuthProvider,
        provider_trigger::{CreateProviderTrigger, ProviderTriggerProvider},
    },
    services::oauth::{
        account_service::OAuthAccountError, workspace_service::WorkspaceOAuthError,
    },
    utils::change_history::log_workspace_history_event,
};
use tracing::info;

#[derive(Default, Deserialize)]
pub struct WorkflowContextQuery {
    #[serde(default)]
    pub workspace: Option<Uuid>,
}

#[derive(Deserialize)]
pub struct UpdateWorkflowPayload {
    pub name: String,
    pub description: Option<String>,
    pub data: serde_json::Value,
    #[serde(default)]
    #[allow(dead_code)]
    pub workspace_id: Option<Uuid>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub updated_at: Option<OffsetDateTime>,
}

struct GitHubActivationPlan {
    mappings: Vec<GitHubTriggerMapping>,
}

fn github_activation_error(message: &str, code: &str, errors: Vec<Value>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({
            "success": false,
            "status": "error",
            "message": message,
            "code": code,
            "errors": errors,
        })),
    )
        .into_response()
}

fn github_activation_mapping_error(errors: Vec<GitHubTriggerMappingError>) -> Response {
    let details: Vec<Value> = errors
        .into_iter()
        .map(|err| {
            json!({
                "code": err.code,
                "trigger_node_id": err.trigger_node_id,
            })
        })
        .collect();
    github_activation_error(
        "GitHub trigger activation failed. Fix the trigger configuration before publishing.",
        "github_trigger_activation_failed",
        details,
    )
}

async fn prepare_github_trigger_activation(
    app_state: &AppState,
    owner_id: Uuid,
    workspace_id: Option<Uuid>,
    graph: &Value,
) -> Result<Option<GitHubActivationPlan>, Response> {
    if !workflow_is_active(graph) {
        return Ok(None);
    }

    let outcome = collect_github_trigger_mappings(graph);
    if outcome.mappings.is_empty() && outcome.errors.is_empty() {
        return Ok(None);
    }
    if !outcome.errors.is_empty() {
        return Err(github_activation_mapping_error(outcome.errors));
    }

    let mut invalid_events = Vec::new();
    for mapping in &outcome.mappings {
        // TODO: Cross-validate installation_id against the connected token once GitHub App
        // installation-to-token linkage is available in persisted metadata.
        for event_type in &mapping.event_types {
            if !is_supported_github_event_type(event_type) {
                invalid_events.push(json!({
                    "code": "invalid_event_type",
                    "trigger_node_id": mapping.trigger_node_id,
                    "event_type": event_type,
                }));
            }
        }
    }
    if !invalid_events.is_empty() {
        return Err(github_activation_error(
            "GitHub trigger activation failed. One or more events are not supported.",
            "github_trigger_activation_failed",
            invalid_events,
        ));
    }

    let access_token =
        resolve_github_access_token(app_state, owner_id, workspace_id).await?;
    validate_github_repository_access(app_state, &access_token, &outcome.mappings).await?;

    Ok(Some(GitHubActivationPlan {
        mappings: outcome.mappings,
    }))
}

async fn resolve_github_access_token(
    app_state: &AppState,
    owner_id: Uuid,
    workspace_id: Option<Uuid>,
) -> Result<String, Response> {
    if let Some(workspace_id) = workspace_id {
        let mut connections = match app_state
            .workspace_connection_repo
            .list_by_workspace_and_provider(workspace_id, ConnectedOAuthProvider::GitHub)
            .await
        {
            Ok(records) => records,
            Err(err) => {
                eprintln!("Failed to load workspace GitHub connections: {:?}", err);
                return Err(JsonResponse::server_error(
                    "Failed to validate GitHub connection",
                )
                .into_response());
            }
        };
        if connections.is_empty() {
            return Err(github_activation_error(
                "GitHub connection required for workspace workflows.",
                "github_connection_missing",
                vec![json!({ "code": "github_connection_missing", "workspace_id": workspace_id })],
            ));
        }

        connections.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        for connection in connections {
            match app_state
                .workspace_oauth
                .ensure_valid_workspace_token(connection.id)
                .await
            {
                Ok(decrypted) => return Ok(decrypted.access_token),
                Err(WorkspaceOAuthError::OAuth(OAuthAccountError::Database(err)))
                | Err(WorkspaceOAuthError::OAuth(OAuthAccountError::Encryption(err))) => {
                    eprintln!("Failed to decrypt GitHub workspace token: {:?}", err);
                    return Err(JsonResponse::server_error(
                        "Failed to validate GitHub connection",
                    )
                    .into_response());
                }
                Err(WorkspaceOAuthError::Database(err))
                | Err(WorkspaceOAuthError::Encryption(err)) => {
                    eprintln!("Failed to load GitHub workspace token: {:?}", err);
                    return Err(JsonResponse::server_error(
                        "Failed to validate GitHub connection",
                    )
                    .into_response());
                }
                Err(WorkspaceOAuthError::OAuth(OAuthAccountError::Http(err))) => {
                    eprintln!("GitHub connection validation HTTP error: {:?}", err);
                    return Err(JsonResponse::server_error(
                        "Failed to validate GitHub connection",
                    )
                    .into_response());
                }
                Err(WorkspaceOAuthError::OAuth(_))
                | Err(WorkspaceOAuthError::NotFound)
                | Err(WorkspaceOAuthError::Forbidden)
                | Err(WorkspaceOAuthError::SlackInstallRequired) => {
                    continue;
                }
            }
        }

        return Err(github_activation_error(
            "GitHub connection required for workspace workflows.",
            "github_connection_invalid",
            vec![json!({ "code": "github_connection_invalid", "workspace_id": workspace_id })],
        ));
    }

    let user_repo = PostgresUserOAuthTokenRepository {
        pool: (*app_state.db_pool).clone(),
    };
    let mut tokens = match user_repo
        .list_by_user_and_provider(owner_id, ConnectedOAuthProvider::GitHub)
        .await
    {
        Ok(records) => records,
        Err(err) => {
            eprintln!("Failed to load user GitHub tokens: {:?}", err);
            return Err(JsonResponse::server_error("Failed to validate GitHub connection")
                .into_response());
        }
    };

    if tokens.is_empty() {
        return Err(github_activation_error(
            "GitHub connection required for personal workflows.",
            "github_connection_missing",
            vec![json!({ "code": "github_connection_missing", "user_id": owner_id })],
        ));
    }

    tokens.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    for token in tokens {
        match app_state
            .oauth_accounts
            .ensure_valid_access_token_for_connection(owner_id, token.id)
            .await
        {
            Ok(stored) => return Ok(stored.access_token),
            Err(OAuthAccountError::Database(err)) | Err(OAuthAccountError::Encryption(err)) => {
                eprintln!("Failed to decrypt GitHub token: {:?}", err);
                return Err(JsonResponse::server_error("Failed to validate GitHub connection")
                    .into_response());
            }
            Err(OAuthAccountError::Http(err)) => {
                eprintln!("GitHub connection validation HTTP error: {:?}", err);
                return Err(JsonResponse::server_error("Failed to validate GitHub connection")
                    .into_response());
            }
            Err(_) => continue,
        }
    }

    Err(github_activation_error(
        "GitHub connection required for personal workflows.",
        "github_connection_invalid",
        vec![json!({ "code": "github_connection_invalid", "user_id": owner_id })],
    ))
}

async fn validate_github_repository_access(
    app_state: &AppState,
    access_token: &str,
    mappings: &[GitHubTriggerMapping],
) -> Result<(), Response> {
    const GITHUB_VALIDATION_TIMEOUT: Duration = Duration::from_secs(8);
    let mut checked = HashSet::new();
    for mapping in mappings {
        let Some(repository_id) = mapping.repository_id.as_deref() else {
            continue;
        };
        let trimmed = repository_id.trim();
        if trimmed.is_empty() {
            return Err(github_activation_error(
                "GitHub trigger activation failed. Repository id is missing.",
                "github_repository_missing",
                vec![json!({
                    "code": "github_repository_missing",
                    "trigger_node_id": mapping.trigger_node_id,
                })],
            ));
        }
        if !checked.insert(trimmed.to_string()) {
            continue;
        }

        let url = format!("https://api.github.com/repositories/{trimmed}");
        let response = match app_state
            .http_client
            .get(url)
            .bearer_auth(access_token)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "dsentr")
            .timeout(GITHUB_VALIDATION_TIMEOUT)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(err) => {
                let code = "github_validation_unavailable";
                eprintln!("GitHub repository validation failed: {:?}", err);
                return Err(github_activation_error(
                    "GitHub validation is temporarily unavailable. Try again.",
                    code,
                    vec![json!({
                        "code": code,
                        "repository_id": trimmed,
                    })],
                ));
            }
        };

        if response.status().is_success() {
            continue;
        }

        let status = response.status();
        let code = if status == StatusCode::NOT_FOUND {
            "github_repository_not_found"
        } else if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            "github_repository_access_denied"
        } else {
            "github_repository_check_failed"
        };

        return Err(github_activation_error(
            "GitHub trigger activation failed. Repository access could not be verified.",
            code,
            vec![json!({
                "code": code,
                "repository_id": trimmed,
                "status": status.as_u16(),
            })],
        ));
    }

    Ok(())
}

async fn insert_github_provider_triggers(
    app_state: &AppState,
    workflow: &Workflow,
    plan: Option<GitHubActivationPlan>,
) -> Result<(), Response> {
    let Some(plan) = plan else {
        return Ok(());
    };
    if plan.mappings.is_empty() {
        return Ok(());
    }

    let trigger_repo = PostgresProviderTriggerRepository {
        pool: (*app_state.db_pool).clone(),
    };

    for mapping in plan.mappings {
        let trigger_node_id = mapping.trigger_node_id.trim().to_string();
        if trigger_node_id.is_empty() {
            return Err(github_activation_error(
                "GitHub trigger activation failed. Trigger node id is invalid.",
                "invalid_trigger_node_id",
                vec![json!({
                    "code": "invalid_trigger_node_id",
                    "trigger_node_id": mapping.trigger_node_id,
                })],
            ));
        }

        for event_type in mapping.event_types {
            if !is_supported_github_event_type(&event_type) {
                return Err(github_activation_error(
                    "GitHub trigger activation failed. Event type is not supported.",
                    "invalid_event_type",
                    vec![json!({
                        "code": "invalid_event_type",
                        "trigger_node_id": trigger_node_id,
                        "event_type": event_type,
                    })],
                ));
            }

            let created = trigger_repo
                .create_provider_trigger(CreateProviderTrigger {
                    workspace_id: workflow.workspace_id,
                    provider: ProviderTriggerProvider::Github,
                    workflow_id: workflow.id,
                    trigger_node_id: trigger_node_id.clone(),
                    event_type: event_type.clone(),
                    installation_id: Some(mapping.installation_id.clone()),
                    repository_id: mapping.repository_id.clone(),
                })
                .await;

            match created {
                Ok(trigger) => {
                    info!(
                        workflow_id = %workflow.id,
                        trigger_node_id = %trigger_node_id,
                        event_type = %event_type,
                        repository_id = ?trigger.repository_id,
                        "provider trigger upserted"
                    );
                }
                Err(err) => {
                    eprintln!("Failed to upsert provider trigger: {:?}", err);
                    return Err(JsonResponse::server_error(
                        "Failed to activate GitHub triggers",
                    )
                    .into_response());
                }
            }
        }
    }

    Ok(())
}

pub async fn create_workflow(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Json(payload): Json<CreateWorkflow>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    let CreateWorkflow {
        name,
        description,
        data,
        workspace_id,
    } = payload;
    let mut workspace_id = workspace_id;
    let plan_tier = app_state
        .resolve_plan_tier(user_id, claims.plan.as_deref())
        .await;

    let memberships = match app_state
        .workspace_repo
        .list_memberships_for_user(user_id)
        .await
    {
        Ok(memberships) => memberships,
        Err(err) => {
            eprintln!("Failed to load workspace memberships: {:?}", err);
            return JsonResponse::server_error("Failed to create workflow").into_response();
        }
    };
    let roles_map = membership_roles_map(&memberships);
    let context = plan_context_for_user(claims.plan.as_deref(), &memberships, workspace_id);

    if plan_tier.is_solo() && matches!(context, PlanContext::Solo) {
        let assessment = assess_workflow_for_plan(&data);
        if !assessment.violations.is_empty() {
            return plan_violation_response(assessment.violations);
        }
    }

    if workspace_id.is_none() {
        workspace_id = match context {
            PlanContext::WorkspaceOwned { workspace_id }
            | PlanContext::WorkspaceMember { workspace_id } => Some(workspace_id),
            PlanContext::Solo | PlanContext::WorkspaceUnknown => None,
        };
    }

    if let Some(workspace_id) = workspace_id {
        match roles_map.get(&workspace_id).copied() {
            Some(role) => {
                if matches!(role, WorkspaceRole::Viewer) {
                    return JsonResponse::forbidden("Workspace viewers cannot create workflows.")
                        .into_response();
                }
            }
            None => {
                return JsonResponse::forbidden("You do not have access to this workspace.")
                    .into_response();
            }
        }
    }

    if plan_tier.is_solo() && workspace_id.is_none() {
        match app_state
            .workflow_repo
            .list_workflows_by_user(user_id)
            .await
        {
            Ok(existing) => {
                let personal_count = existing
                    .iter()
                    .filter(|wf| wf.workspace_id.is_none())
                    .count();
                if personal_count >= 3 {
                    let violation = PlanViolation {
                        code: "workflow-limit",
                        message: "Solo accounts can save up to 3 workflows. Delete an existing workflow or upgrade in Settings → Plan.".to_string(),
                        node_label: None,
                    };
                    return plan_violation_response(vec![violation]);
                }
            }
            Err(err) => {
                eprintln!("Failed to check workflow count: {:?}", err);
                return JsonResponse::server_error("Failed to create workflow").into_response();
            }
        }
    }

    let github_activation_plan =
        match prepare_github_trigger_activation(&app_state, user_id, workspace_id, &data).await {
            Ok(plan) => plan,
            Err(response) => return response,
        };

    let result = app_state
        .workflow_repo
        .create_workflow(user_id, workspace_id, &name, description.as_deref(), data)
        .await;

    match result {
        Ok(workflow) => {
            if let Err(response) =
                insert_github_provider_triggers(&app_state, &workflow, github_activation_plan).await
            {
                return response;
            }
            sync_workflow_schedule(&app_state, &workflow).await;
            sync_secrets_from_workflow(&app_state, user_id, &workflow.data).await;
            (
                StatusCode::CREATED,
                Json(json!({
                    "success": true,
                    "workflow": workflow
                })),
            )
                .into_response()
        }
        Err(e) => {
            eprintln!("DB error creating workflow: {:?}", e);
            if is_unique_violation(&e) {
                JsonResponse::conflict("A workflow with this name already exists").into_response()
            } else {
                JsonResponse::server_error("Failed to create workflow").into_response()
            }
        }
    }
}

pub async fn list_workflows(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Query(params): Query<WorkflowContextQuery>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };
    let plan_tier = app_state
        .resolve_plan_tier(user_id, claims.plan.as_deref())
        .await;

    let owned_workflows = match app_state
        .workflow_repo
        .list_workflows_by_user(user_id)
        .await
    {
        Ok(workflows) => workflows,
        Err(e) => {
            eprintln!("DB error listing user workflows: {:?}", e);
            return JsonResponse::server_error("Failed to fetch workflows").into_response();
        }
    };

    let memberships = match app_state
        .workspace_repo
        .list_memberships_for_user(user_id)
        .await
    {
        Ok(memberships) => memberships,
        Err(err) => {
            eprintln!("Failed to load workspace memberships: {:?}", err);
            return JsonResponse::server_error("Failed to fetch workflows").into_response();
        }
    };

    let roles_map = membership_roles_map(&memberships);
    let context = plan_context_for_user(claims.plan.as_deref(), &memberships, params.workspace);

    if params.workspace.is_some()
        && !matches!(
            context,
            PlanContext::WorkspaceOwned { .. } | PlanContext::WorkspaceMember { .. }
        )
    {
        return JsonResponse::forbidden("You do not have access to this workspace.")
            .into_response();
    }

    let mut combined: HashMap<Uuid, Workflow> = HashMap::new();
    for workflow in owned_workflows {
        if can_access_workflow_in_context(&workflow, context, &roles_map) {
            combined.insert(workflow.id, workflow);
        }
    }

    let mut workspace_ids: Vec<Uuid> = memberships
        .iter()
        .map(|membership| membership.workspace.id)
        .filter(|workspace_id| can_access_workspace_in_context(context, *workspace_id, &roles_map))
        .collect();
    workspace_ids.sort_unstable();
    workspace_ids.dedup();

    if !workspace_ids.is_empty() {
        match app_state
            .workflow_repo
            .list_workflows_by_workspace_ids(&workspace_ids)
            .await
        {
            Ok(workflows) => {
                for workflow in workflows {
                    if can_access_workflow_in_context(&workflow, context, &roles_map) {
                        combined.entry(workflow.id).or_insert(workflow);
                    }
                }
            }
            Err(err) => {
                eprintln!("DB error listing workspace workflows: {:?}", err);
                return JsonResponse::server_error("Failed to fetch workflows").into_response();
            }
        }
    }

    let mut workflows: Vec<Workflow> = combined.into_values().collect();
    workflows.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));

    let mut hidden_count = 0usize;
    let visible = if plan_tier.is_solo() {
        let owned: Vec<_> = workflows
            .iter()
            .filter(|wf| wf.user_id == user_id)
            .cloned()
            .collect();
        let allowed_owned = enforce_solo_workflow_limit(&owned);
        let allowed_ids: HashSet<_> = allowed_owned.iter().map(|wf| wf.id).collect();
        let personal_total = owned.iter().filter(|wf| wf.workspace_id.is_none()).count();
        hidden_count = personal_total.saturating_sub(allowed_owned.len());
        workflows
            .into_iter()
            .filter(|wf| wf.workspace_id.is_some() || allowed_ids.contains(&wf.id))
            .collect()
    } else {
        workflows
    };

    let mut payload = json!({
        "success": true,
        "workflows": visible,
    });
    if plan_tier.is_solo() {
        payload["hidden_count"] = json!(hidden_count);
    }
    (StatusCode::OK, Json(payload)).into_response()
}

pub async fn get_workflow(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path(workflow_id): Path<Uuid>,
    Query(params): Query<WorkflowContextQuery>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };
    let plan_tier = app_state
        .resolve_plan_tier(user_id, claims.plan.as_deref())
        .await;

    match app_state
        .workflow_repo
        .find_workflow_for_member(user_id, workflow_id)
        .await
    {
        Ok(Some(workflow)) => {
            let memberships = match app_state
                .workspace_repo
                .list_memberships_for_user(user_id)
                .await
            {
                Ok(memberships) => memberships,
                Err(err) => {
                    eprintln!("Failed to load workspace memberships: {:?}", err);
                    return JsonResponse::server_error("Failed to fetch workflow").into_response();
                }
            };
            let roles_map = membership_roles_map(&memberships);
            let context =
                plan_context_for_user(claims.plan.as_deref(), &memberships, params.workspace);

            if params.workspace.is_some()
                && !matches!(
                    context,
                    PlanContext::WorkspaceOwned { .. } | PlanContext::WorkspaceMember { .. }
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

            if plan_tier.is_solo() && workflow.user_id == user_id && workflow.workspace_id.is_none()
            {
                match app_state
                    .workflow_repo
                    .list_workflows_by_user(user_id)
                    .await
                {
                    Ok(existing) => {
                        let allowed = enforce_solo_workflow_limit(&existing);
                        let allowed_ids: HashSet<_> = allowed.into_iter().map(|wf| wf.id).collect();
                        if !allowed_ids.contains(&workflow.id) {
                            let violation = PlanViolation {
                                code: "workflow-limit",
                                message: "This workflow is locked on the solo plan. Upgrade in Settings → Plan to edit or run it.".to_string(),
                                node_label: None,
                            };
                            return plan_violation_response(vec![violation]);
                        }
                    }
                    Err(err) => {
                        eprintln!("Failed to enforce workflow limit: {:?}", err);
                        return JsonResponse::server_error("Failed to fetch workflow")
                            .into_response();
                    }
                }
            }
            (
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "workflow": workflow
                })),
            )
                .into_response()
        }
        Ok(None) => JsonResponse::not_found("Workflow not found").into_response(),
        Err(e) => {
            eprintln!("DB error fetching workflow: {:?}", e);
            JsonResponse::server_error("Failed to fetch workflow").into_response()
        }
    }
}

pub async fn update_workflow(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path(workflow_id): Path<Uuid>,
    Query(params): Query<WorkflowContextQuery>,
    Json(payload): Json<UpdateWorkflowPayload>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    let UpdateWorkflowPayload {
        name,
        description,
        data,
        workspace_id: _,
        updated_at: client_updated_at,
    } = payload;
    let plan_tier = app_state
        .resolve_plan_tier(user_id, claims.plan.as_deref())
        .await;

    let existing = match app_state
        .workflow_repo
        .find_workflow_for_member(user_id, workflow_id)
        .await
    {
        Ok(Some(workflow)) => workflow,
        Ok(None) => return JsonResponse::not_found("Workflow not found").into_response(),
        Err(err) => {
            eprintln!("Failed to load workflow for update: {:?}", err);
            return JsonResponse::server_error("Failed to update workflow").into_response();
        }
    };

    if let Some(version) = client_updated_at {
        if version != existing.updated_at {
            return workflow_conflict_response(existing);
        }
    }

    if existing.workspace_id.is_some() && client_updated_at.is_none() {
        return workflow_conflict_response(existing);
    }

    let memberships = match app_state
        .workspace_repo
        .list_memberships_for_user(user_id)
        .await
    {
        Ok(memberships) => memberships,
        Err(err) => {
            eprintln!("Failed to load workspace memberships: {:?}", err);
            return JsonResponse::server_error("Failed to update workflow").into_response();
        }
    };
    let roles_map = membership_roles_map(&memberships);
    let context = plan_context_for_user(claims.plan.as_deref(), &memberships, params.workspace);

    if params.workspace.is_some()
        && !matches!(
            context,
            PlanContext::WorkspaceOwned { .. } | PlanContext::WorkspaceMember { .. }
        )
    {
        return JsonResponse::forbidden("You do not have access to this workspace.")
            .into_response();
    }

    if !can_access_workflow_in_context(&existing, context, &roles_map) {
        return JsonResponse::forbidden(
            "This workflow is not available in the current plan context.",
        )
        .into_response();
    }

    if plan_tier.is_solo() && matches!(context, PlanContext::Solo) {
        let assessment = assess_workflow_for_plan(&data);
        if !assessment.violations.is_empty() {
            return plan_violation_response(assessment.violations);
        }
    }

    let workspace_role = existing
        .workspace_id
        .and_then(|workspace_id| roles_map.get(&workspace_id).copied());

    if matches!(workspace_role, Some(WorkspaceRole::Viewer)) {
        return JsonResponse::forbidden("Workspace viewers cannot modify workflows.")
            .into_response();
    }

    let is_workspace_admin = matches!(
        workspace_role,
        Some(WorkspaceRole::Admin | WorkspaceRole::Owner)
    );
    if let Some(locker) = existing.locked_by {
        if locker != user_id && !is_workspace_admin {
            return JsonResponse::forbidden(
                "This workflow is locked and can only be modified by the creator or an admin.",
            )
            .into_response();
        }
    }

    let is_creator = existing.user_id == user_id;
    let is_personal = existing.workspace_id.is_none();
    let allowed_ids = if plan_tier.is_solo() && is_creator && is_personal {
        match app_state
            .workflow_repo
            .list_workflows_by_user(existing.user_id)
            .await
        {
            Ok(existing_workflows) => {
                let allowed = enforce_solo_workflow_limit(&existing_workflows);
                Some(allowed.into_iter().map(|wf| wf.id).collect::<HashSet<_>>())
            }
            Err(err) => {
                eprintln!("Failed to enforce workflow limit: {:?}", err);
                return JsonResponse::server_error("Failed to update workflow").into_response();
            }
        }
    } else {
        None
    };

    let owner_id = existing.user_id;
    let before = existing.clone();
    let github_activation_plan = match prepare_github_trigger_activation(
        &app_state,
        owner_id,
        existing.workspace_id,
        &data,
    )
    .await
    {
        Ok(plan) => plan,
        Err(response) => return response,
    };

    match app_state
        .workflow_repo
        .update_workflow(
            owner_id,
            workflow_id,
            &name,
            description.as_deref(),
            data,
            client_updated_at,
        )
        .await
    {
        Ok(Some(workflow)) => {
            if let Some(ids) = allowed_ids.as_ref() {
                if !ids.contains(&workflow.id) {
                    let violation = PlanViolation {
                        code: "workflow-limit",
                        message: "This workflow is locked on the solo plan. Upgrade in Settings → Plan to edit or run it.".to_string(),
                        node_label: None,
                    };
                    return plan_violation_response(vec![violation]);
                }
            }
            if let Err(response) =
                insert_github_provider_triggers(&app_state, &workflow, github_activation_plan).await
            {
                return response;
            }
            sync_workflow_schedule(&app_state, &workflow).await;
            let diffs = diff_user_nodes_only(&before.data, &workflow.data);
            if let Err(e) = app_state
                .workflow_repo
                .insert_workflow_log(user_id, workflow.id, diffs)
                .await
            {
                eprintln!("Failed to insert workflow log: {:?}", e);
            }
            sync_secrets_from_workflow(&app_state, user_id, &workflow.data).await;
            (
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "workflow": workflow
                })),
            )
                .into_response()
        }
        Ok(None) => {
            if client_updated_at.is_some() {
                let latest = app_state
                    .workflow_repo
                    .find_workflow_for_member(user_id, workflow_id)
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or(before);
                workflow_conflict_response(latest)
            } else {
                JsonResponse::not_found("Workflow not found").into_response()
            }
        }
        Err(e) => {
            eprintln!("DB error updating workflow: {:?}", e);
            if is_unique_violation(&e) {
                JsonResponse::conflict("A workflow with this name already exists").into_response()
            } else {
                JsonResponse::server_error("Failed to update workflow").into_response()
            }
        }
    }
}

fn workflow_conflict_response(workflow: Workflow) -> Response {
    (
        StatusCode::CONFLICT,
        Json(json!({
            "success": false,
            "message": "This workflow was updated by someone else. Reload to continue editing.",
            "workflow": workflow
        })),
    )
        .into_response()
}

pub async fn lock_workflow(
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
            eprintln!("Failed to load workflow for locking: {:?}", err);
            return JsonResponse::server_error("Failed to lock workflow").into_response();
        }
    };

    let memberships = match app_state
        .workspace_repo
        .list_memberships_for_user(user_id)
        .await
    {
        Ok(memberships) => memberships,
        Err(err) => {
            eprintln!("Failed to load workspace memberships: {:?}", err);
            return JsonResponse::server_error("Failed to lock workflow").into_response();
        }
    };
    let roles_map = membership_roles_map(&memberships);
    let context = plan_context_for_user(claims.plan.as_deref(), &memberships, params.workspace);

    if params.workspace.is_some()
        && !matches!(
            context,
            PlanContext::WorkspaceOwned { .. } | PlanContext::WorkspaceMember { .. }
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

    if workflow.user_id != user_id {
        return JsonResponse::forbidden("Only the creator can lock this workflow.").into_response();
    }

    match app_state
        .workflow_repo
        .set_workflow_lock(workflow_id, Some(user_id))
        .await
    {
        Ok(Some(updated)) => (
            StatusCode::OK,
            Json(json!({ "success": true, "workflow": updated })),
        )
            .into_response(),
        Ok(None) => JsonResponse::not_found("Workflow not found").into_response(),
        Err(err) => {
            eprintln!("Failed to lock workflow: {:?}", err);
            JsonResponse::server_error("Failed to lock workflow").into_response()
        }
    }
}

pub async fn unlock_workflow(
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
            eprintln!("Failed to load workflow for unlocking: {:?}", err);
            return JsonResponse::server_error("Failed to unlock workflow").into_response();
        }
    };

    let memberships = match app_state
        .workspace_repo
        .list_memberships_for_user(user_id)
        .await
    {
        Ok(memberships) => memberships,
        Err(err) => {
            eprintln!("Failed to load workspace memberships: {:?}", err);
            return JsonResponse::server_error("Failed to unlock workflow").into_response();
        }
    };
    let roles_map = membership_roles_map(&memberships);
    let context = plan_context_for_user(claims.plan.as_deref(), &memberships, params.workspace);

    if params.workspace.is_some()
        && !matches!(
            context,
            PlanContext::WorkspaceOwned { .. } | PlanContext::WorkspaceMember { .. }
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

    if workflow.locked_by.is_none() {
        return Json(json!({ "success": true, "workflow": workflow })).into_response();
    }

    let workspace_role = workflow
        .workspace_id
        .and_then(|workspace_id| roles_map.get(&workspace_id).copied());

    let is_workspace_admin = matches!(
        workspace_role,
        Some(WorkspaceRole::Admin | WorkspaceRole::Owner)
    );

    if workflow.user_id != user_id && !is_workspace_admin {
        return JsonResponse::forbidden("Only the creator or an admin can unlock this workflow.")
            .into_response();
    }

    match app_state
        .workflow_repo
        .set_workflow_lock(workflow_id, None)
        .await
    {
        Ok(Some(updated)) => (
            StatusCode::OK,
            Json(json!({ "success": true, "workflow": updated })),
        )
            .into_response(),
        Ok(None) => JsonResponse::not_found("Workflow not found").into_response(),
        Err(err) => {
            eprintln!("Failed to unlock workflow: {:?}", err);
            JsonResponse::server_error("Failed to unlock workflow").into_response()
        }
    }
}

pub async fn delete_workflow(
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
            eprintln!("Failed to load workflow for deletion: {:?}", err);
            return JsonResponse::server_error("Failed to delete workflow").into_response();
        }
    };

    let memberships = match app_state
        .workspace_repo
        .list_memberships_for_user(user_id)
        .await
    {
        Ok(memberships) => memberships,
        Err(err) => {
            eprintln!("Failed to load workspace memberships: {:?}", err);
            return JsonResponse::server_error("Failed to delete workflow").into_response();
        }
    };
    let roles_map = membership_roles_map(&memberships);
    let context = plan_context_for_user(claims.plan.as_deref(), &memberships, params.workspace);

    if params.workspace.is_some()
        && !matches!(
            context,
            PlanContext::WorkspaceOwned { .. } | PlanContext::WorkspaceMember { .. }
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

    match app_state
        .workflow_repo
        .delete_workflow(user_id, workflow_id)
        .await
    {
        Ok(true) => {
            if let Some(workspace_id) = workflow.workspace_id {
                let event = vec![json!({
                    "path": "workflow.deleted",
                    "from": workflow.name,
                    "to": workflow.id,
                })];
                log_workspace_history_event(&app_state, workspace_id, user_id, event).await;
            }
            Json(json!({ "success": true })).into_response()
        }
        Ok(false) => JsonResponse::not_found("Workflow not found").into_response(),
        Err(e) => {
            eprintln!("DB error deleting workflow: {:?}", e);
            JsonResponse::server_error("Failed to delete workflow").into_response()
        }
    }
}
