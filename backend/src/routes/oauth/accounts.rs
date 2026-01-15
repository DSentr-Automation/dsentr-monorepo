use super::{
    helpers::{
        integration_id_for_provider, is_workspace_first, manifest_payloads, map_oauth_error,
        resolve_oauth_integration, supports_personal, ConnectionOwnerPayload, ConnectionsResponse,
        PersonalAuthStatus, PersonalConnectionPayload, RefreshResponse, WorkspaceConnectionPayload,
        OAUTH_PLAN_RESTRICTION_MESSAGE,
    },
    prelude::*,
};
use crate::db::workspace_connection_repository::WorkspaceConnectionListing;
use crate::models::workspace::WorkspaceMembershipSummary;
use crate::routes::auth::claims::Claims;
use crate::services::oauth::account_service::StoredOAuthToken;
use axum::http::StatusCode;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
pub struct ListConnectionsQuery {
    pub workspace: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct ConnectionTarget {
    #[serde(default)]
    pub connection_id: Option<Uuid>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProviderConnectionsResponse {
    success: bool,
    provider: ConnectedOAuthProvider,
    workspace_id: Uuid,
    workspace_name: String,
    personal: Vec<PersonalConnectionPayload>,
    workspace: Vec<WorkspaceConnectionPayload>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConnectionLookupResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    connection_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    personal: Option<PersonalConnectionPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace: Option<WorkspaceConnectionPayload>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DisconnectResponse {
    success: bool,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    connection_id: Option<Uuid>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RevokeResponse {
    success: bool,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    connection_id: Option<Uuid>,
}

async fn ensure_workspace_membership(
    app_state: &AppState,
    user_id: Uuid,
    workspace_id: Uuid,
) -> Result<WorkspaceMembershipSummary, Response> {
    let memberships = app_state
        .workspace_repo
        .list_memberships_for_user(user_id)
        .await
        .map_err(|err| {
            error!(?err, user_id = %user_id, workspace_id = %workspace_id, "Failed to load memberships while checking workspace access");
            JsonResponse::server_error("Failed to load workspace access").into_response()
        })?;

    let membership = match memberships
        .into_iter()
        .find(|membership| membership.workspace.id == workspace_id)
    {
        Some(membership) => membership,
        None => {
            return Err(JsonResponse::forbidden("Workspace membership required").into_response())
        }
    };

    let plan_tier = NormalizedPlanTier::from_option(Some(membership.workspace.plan.as_str()));
    if plan_tier.is_solo() {
        return Err(JsonResponse::forbidden_with_code(
            OAUTH_PLAN_RESTRICTION_MESSAGE,
            "workspace_plan_required",
        )
        .into_response());
    }

    Ok(membership)
}

pub async fn refresh_connection(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path(integration_id): Path<String>,
    query: Query<ConnectionTarget>,
    body: Option<Json<ConnectionTarget>>,
) -> Response {
    let requested_connection_id = coalesce_connection_id(&query, body);
    let Some(connection_id) = requested_connection_id else {
        return JsonResponse::bad_request("connection_id is required").into_response();
    };

    let (manifest, provider) =
        match resolve_oauth_integration(state.integration_registry.as_ref(), &integration_id) {
            Ok(result) => result,
            Err(response) => return response,
        };
    if !supports_personal(manifest) {
        return JsonResponse::bad_request(
            "Personal connections are not supported for this integration",
        )
        .into_response();
    }

    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::server_error("Invalid user identifier").into_response(),
    };

    match state
        .oauth_accounts
        .ensure_valid_access_token_for_connection(user_id, connection_id)
        .await
    {
        Ok(token) => {
            if token.provider != provider {
                return JsonResponse::bad_request("Connection does not match provider")
                    .into_response();
            }

            Json(RefreshResponse {
                success: true,
                requires_reconnect: false,
                account_email: Some(token.account_email),
                expires_at: Some(token.expires_at),
                last_refreshed_at: Some(token.updated_at),
                connection_id: Some(connection_id),
                message: None,
            })
            .into_response()
        }
        Err(OAuthAccountError::TokenRevoked { .. }) => (
            StatusCode::CONFLICT,
            Json(RefreshResponse {
                success: false,
                requires_reconnect: true,
                account_email: None,
                expires_at: None,
                last_refreshed_at: None,
                connection_id: Some(connection_id),
                message: Some(
                    "The OAuth connection was revoked. Reconnect to restore access.".to_string(),
                ),
            }),
        )
            .into_response(),
        Err(err) => map_oauth_error(err),
    }
}

pub async fn disconnect_connection(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path(integration_id): Path<String>,
    query: Query<ConnectionTarget>,
    body: Option<Json<ConnectionTarget>>,
) -> Response {
    let requested_connection_id = coalesce_connection_id(&query, body);
    let Some(connection_id) = requested_connection_id else {
        return JsonResponse::bad_request("connection_id is required").into_response();
    };

    let (manifest, provider) =
        match resolve_oauth_integration(state.integration_registry.as_ref(), &integration_id) {
            Ok(result) => result,
            Err(response) => return response,
        };
    if !supports_personal(manifest) {
        return JsonResponse::bad_request(
            "Personal connections are not supported for this integration",
        )
        .into_response();
    }
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::server_error("Invalid user identifier").into_response(),
    };

    let personal_tokens = match state.oauth_accounts.list_tokens(user_id).await {
        Ok(tokens) => tokens,
        Err(err) => return map_oauth_error(err),
    };

    let Some(token) = personal_tokens
        .into_iter()
        .find(|token| token.id == connection_id)
    else {
        return JsonResponse::not_found("Connection not found").into_response();
    };

    if token.provider != provider {
        return JsonResponse::bad_request("Connection does not match provider").into_response();
    }

    match state
        .oauth_accounts
        .delete_token_by_connection(user_id, connection_id)
        .await
    {
        Ok(()) => Json(DisconnectResponse {
            success: true,
            message: "Disconnected".to_string(),
            connection_id: Some(connection_id),
        })
        .into_response(),
        Err(err) => map_oauth_error(err),
    }
}

pub async fn list_connections(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    Query(params): Query<ListConnectionsQuery>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::server_error("Invalid user identifier").into_response(),
    };

    // Enforce workspace membership up-front
    let _membership = match ensure_workspace_membership(&state, user_id, params.workspace).await {
        Ok(membership) => membership,
        Err(resp) => return resp,
    };

    let personal_tokens = match state.oauth_accounts.list_tokens(user_id).await {
        Ok(tokens) => tokens,
        Err(OAuthAccountError::NotFound) => Vec::new(),
        Err(err) => return map_oauth_error(err),
    };

    // Assert that all personal tokens are owned by the authenticated user
    if let Err(err) = state
        .oauth_accounts
        .assert_personal_tokens_owned_by(user_id, &personal_tokens)
        .await
    {
        error!(user_id = %user_id, ?err, "Personal OAuth token ownership assertion failed");
        return JsonResponse::forbidden("Access to OAuth credentials is forbidden").into_response();
    }

    let workspace_connections = match state
        .workspace_connection_repo
        .list_for_workspace(params.workspace)
        .await
    {
        Ok(connections) => connections,
        Err(err) => {
            error!(workspace_id = %params.workspace, ?err, "Failed to load workspace OAuth connections");
            return JsonResponse::server_error("Failed to load workspace connections")
                .into_response();
        }
    };

    // Defensive assertion: all entries must match the requested workspace
    let all_match = workspace_connections
        .iter()
        .all(|c| c.workspace_id == params.workspace);
    if !all_match {
        error!(workspace_id = %params.workspace, "Workspace OAuth listing contained entries for a different workspace");
        return JsonResponse::forbidden("Access to workspace credentials is forbidden")
            .into_response();
    }

    let registry = state.integration_registry.as_ref();
    let personal_owner = connection_owner_from_claims(user_id, &claims);
    let mut personal = Vec::new();
    let mut workspace = Vec::new();
    let mut personal_auth: BTreeMap<String, PersonalAuthStatus> = BTreeMap::new();
    let mut workspace_counts: BTreeMap<String, usize> = BTreeMap::new();

    for manifest in registry
        .iter()
        .filter(|manifest| is_workspace_first(manifest))
    {
        personal_auth.insert(
            manifest.integration_id.clone(),
            PersonalAuthStatus::default(),
        );
    }

    for token in personal_tokens {
        let integration_id = match integration_id_for_provider(token.provider) {
            Some(integration_id) => integration_id,
            None => {
                error!(
                    provider = ?token.provider,
                    "OAuth token provider missing from mapping table"
                );
                return JsonResponse::server_error("Unknown OAuth provider").into_response();
            }
        };
        let manifest = match registry.get(integration_id) {
            Some(manifest) => manifest,
            None => {
                error!(
                    integration_id = %integration_id,
                    "OAuth token provider missing from manifest registry"
                );
                return JsonResponse::server_error("Unknown OAuth provider").into_response();
            }
        };
        if is_workspace_first(manifest) {
            if let Some(status) = personal_auth.get_mut(&manifest.integration_id) {
                status.has_personal_auth = true;
                let should_update = status
                    .personal_auth_connected_at
                    .as_ref()
                    .is_none_or(|current| token.updated_at > *current);
                if should_update {
                    status.personal_auth_connected_at = Some(token.updated_at);
                }
            }
        }
        personal.push(personal_payload_from_token(
            token,
            &personal_owner,
            &workspace_connections,
        ));
    }

    for connection in workspace_connections {
        let integration_id = match integration_id_for_provider(connection.provider) {
            Some(integration_id) => integration_id,
            None => {
                error!(
                    provider = ?connection.provider,
                    "Workspace OAuth provider missing from mapping table"
                );
                return JsonResponse::server_error("Unknown OAuth provider").into_response();
            }
        };
        let manifest = match registry.get(integration_id) {
            Some(manifest) => manifest,
            None => {
                error!(
                    integration_id = %integration_id,
                    "Workspace OAuth provider missing from manifest registry"
                );
                return JsonResponse::server_error("Unknown OAuth provider").into_response();
            }
        };
        let count = workspace_counts
            .entry(manifest.integration_id.clone())
            .or_insert(0);
        *count += 1;
        if manifest.provider_constraints.single_install_per_workspace && *count > 1 {
            error!(
                integration_id = %manifest.integration_id,
                workspace_id = %params.workspace,
                "Multiple workspace connections found for a single-install integration"
            );
            return JsonResponse::conflict(
                "Only one workspace connection is supported for this integration",
            )
            .into_response();
        }
        workspace.push(workspace_payload_from_listing(connection));
    }

    // Legacy slack field maps to the sole workspace-first entry for compatibility.
    let slack = if personal_auth.len() == 1 {
        personal_auth.values().next().cloned()
    } else {
        None
    };

    Json(ConnectionsResponse {
        success: true,
        personal,
        workspace,
        personal_auth,
        slack,
        manifests: manifest_payloads(registry),
    })
    .into_response()
}

pub async fn list_provider_connections(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path(integration_id): Path<String>,
    Query(params): Query<ListConnectionsQuery>,
) -> Response {
    let (_manifest, provider) =
        match resolve_oauth_integration(state.integration_registry.as_ref(), &integration_id) {
            Ok(result) => result,
            Err(response) => return response,
        };

    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::server_error("Invalid user identifier").into_response(),
    };

    let membership = match ensure_workspace_membership(&state, user_id, params.workspace).await {
        Ok(membership) => membership,
        Err(resp) => return resp,
    };

    let personal_tokens = match state.oauth_accounts.list_tokens(user_id).await {
        Ok(tokens) => tokens
            .into_iter()
            .filter(|token| token.provider == provider)
            .collect::<Vec<_>>(),
        Err(OAuthAccountError::NotFound) => Vec::new(),
        Err(err) => return map_oauth_error(err),
    };

    if let Err(err) = state
        .oauth_accounts
        .assert_personal_tokens_owned_by(user_id, &personal_tokens)
        .await
    {
        error!(user_id = %user_id, ?err, "Personal OAuth token ownership assertion failed");
        return JsonResponse::forbidden("Access to OAuth credentials is forbidden").into_response();
    }

    let workspace_connections = match state
        .workspace_connection_repo
        .list_for_workspace(params.workspace)
        .await
    {
        Ok(connections) => connections
            .into_iter()
            .filter(|connection| connection.provider == provider)
            .collect::<Vec<_>>(),
        Err(err) => {
            error!(workspace_id = %params.workspace, ?err, "Failed to load workspace OAuth connections");
            return JsonResponse::server_error("Failed to load workspace connections")
                .into_response();
        }
    };

    let personal_owner = connection_owner_from_claims(user_id, &claims);
    let personal = personal_tokens
        .into_iter()
        .map(|token| personal_payload_from_token(token, &personal_owner, &workspace_connections))
        .collect::<Vec<_>>();
    let workspace = workspace_connections
        .into_iter()
        .map(workspace_payload_from_listing)
        .collect::<Vec<_>>();

    Json(ProviderConnectionsResponse {
        success: true,
        provider,
        workspace_id: params.workspace,
        workspace_name: membership.workspace.name.clone(),
        personal,
        workspace,
    })
    .into_response()
}

pub async fn get_connection_by_id(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path(connection_id): Path<Uuid>,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::server_error("Invalid user identifier").into_response(),
    };

    let personal_owner = connection_owner_from_claims(user_id, &claims);

    let personal_tokens = match state.oauth_accounts.list_tokens(user_id).await {
        Ok(tokens) => tokens,
        Err(OAuthAccountError::NotFound) => Vec::new(),
        Err(err) => return map_oauth_error(err),
    };

    // Load workspace connections for sharing status derivation
    let workspace_connections: Vec<
        crate::db::workspace_connection_repository::WorkspaceConnectionListing,
    > = match state
        .workspace_connection_repo
        .list_for_user_memberships(user_id)
        .await
    {
        Ok(connections) => connections,
        Err(err) => {
            error!(user_id = %user_id, ?err, "Failed to load workspace connections for connection lookup");
            return JsonResponse::server_error("Failed to load connections").into_response();
        }
    };

    if let Some(token) = personal_tokens
        .iter()
        .find(|token| token.id == connection_id)
    {
        return Json(ConnectionLookupResponse {
            success: true,
            connection_id: Some(connection_id),
            personal: Some(personal_payload_from_token(
                token.clone(),
                &personal_owner,
                &workspace_connections,
            )),
            workspace: None,
        })
        .into_response();
    }

    let workspace_connections = match state
        .workspace_connection_repo
        .list_for_user_memberships(user_id)
        .await
    {
        Ok(connections) => connections,
        Err(err) => {
            error!(
                ?err,
                user_id = %user_id,
                %connection_id,
                "Failed to load workspace OAuth connections for lookup"
            );
            return JsonResponse::server_error("Failed to load workspace connections")
                .into_response();
        }
    };

    let Some(target) = workspace_connections
        .into_iter()
        .find(|conn| conn.id == connection_id)
    else {
        return JsonResponse::not_found("Connection not found").into_response();
    };

    if let Err(resp) = ensure_workspace_membership(&state, user_id, target.workspace_id).await {
        return resp;
    }

    Json(ConnectionLookupResponse {
        success: true,
        connection_id: target.connection_id,
        personal: None,
        workspace: Some(workspace_payload_from_listing(target)),
    })
    .into_response()
}

pub async fn revoke_connection(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path(integration_id): Path<String>,
    query: Query<ConnectionTarget>,
    body: Option<Json<ConnectionTarget>>,
) -> Response {
    let (manifest, provider) =
        match resolve_oauth_integration(state.integration_registry.as_ref(), &integration_id) {
            Ok(result) => result,
            Err(response) => return response,
        };
    if !supports_personal(manifest) {
        return JsonResponse::bad_request(
            "Personal connections are not supported for this integration",
        )
        .into_response();
    }

    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::server_error("Invalid user identifier").into_response(),
    };

    let requested_connection_id = coalesce_connection_id(&query, body);
    let Some(connection_id) = requested_connection_id else {
        return JsonResponse::bad_request("connection_id is required").into_response();
    };

    let personal_tokens = match state.oauth_accounts.list_tokens(user_id).await {
        Ok(tokens) => tokens,
        Err(err) => return map_oauth_error(err),
    };

    let Some(token) = personal_tokens
        .into_iter()
        .find(|token| token.id == connection_id)
    else {
        return JsonResponse::not_found("Connection not found").into_response();
    };

    if token.provider != provider {
        return JsonResponse::bad_request("Connection does not match provider").into_response();
    }

    return match state
        .oauth_accounts
        .handle_revoked_token_by_connection(user_id, connection_id)
        .await
    {
        Ok(()) => Json(RevokeResponse {
            success: true,
            message: "Revocation recorded".to_string(),
            connection_id: Some(connection_id),
        })
        .into_response(),
        Err(err) => map_oauth_error(err),
    };
}

fn coalesce_connection_id(
    query: &Query<ConnectionTarget>,
    body: Option<Json<ConnectionTarget>>,
) -> Option<Uuid> {
    let from_body = body.and_then(|Json(payload)| payload.connection_id);
    from_body.or(query.0.connection_id)
}

fn connection_owner_from_claims(user_id: Uuid, claims: &Claims) -> ConnectionOwnerPayload {
    ConnectionOwnerPayload {
        user_id,
        name: format_shared_name(
            &Some(claims.first_name.clone()),
            &Some(claims.last_name.clone()),
        ),
        email: normalize_optional_field(&claims.email),
    }
}

fn personal_payload_from_token(
    token: StoredOAuthToken,
    owner: &ConnectionOwnerPayload,
    workspace_connections: &[crate::db::workspace_connection_repository::WorkspaceConnectionListing],
) -> PersonalConnectionPayload {
    // Derive sharing state from workspace connections rather than database flag
    let is_shared = workspace_connections
        .iter()
        .any(|conn| conn.connection_id == Some(token.id));

    PersonalConnectionPayload {
        id: token.id,
        provider: token.provider,
        account_email: token.account_email,
        expires_at: token.expires_at,
        is_shared,
        last_refreshed_at: token.updated_at,
        requires_reconnect: false,
        owner: owner.clone(),
    }
}

fn workspace_payload_from_listing(
    connection: WorkspaceConnectionListing,
) -> WorkspaceConnectionPayload {
    let shared_by_name = format_shared_name(
        &connection.shared_by_first_name,
        &connection.shared_by_last_name,
    );
    let shared_by_email =
        normalize_optional_field(connection.shared_by_email.as_deref().unwrap_or_default());
    let owner = ConnectionOwnerPayload {
        user_id: connection.owner_user_id,
        name: shared_by_name.clone(),
        email: shared_by_email.clone(),
    };

    WorkspaceConnectionPayload {
        id: connection.id,
        connection_id: connection.connection_id,
        provider: connection.provider,
        account_email: connection.account_email,
        expires_at: connection.expires_at,
        workspace_id: connection.workspace_id,
        workspace_name: connection.workspace_name,
        shared_by_name,
        shared_by_email,
        last_refreshed_at: connection.updated_at,
        requires_reconnect: connection.requires_reconnect,
        has_incoming_webhook: connection.has_incoming_webhook,
        owner,
    }
}

fn format_shared_name(first: &Option<String>, last: &Option<String>) -> Option<String> {
    let first = first
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty());
    let last = last
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty());

    match (first, last) {
        (None, None) => None,
        (Some(first), None) => Some(first.to_string()),
        (None, Some(last)) => Some(last.to_string()),
        (Some(first), Some(last)) => Some(format!("{} {}", first, last)),
    }
}

fn normalize_optional_field(value: &str) -> Option<String> {
    let normalized = value.trim();
    if normalized.is_empty() {
        return None;
    }
    Some(normalized.to_string())
}
