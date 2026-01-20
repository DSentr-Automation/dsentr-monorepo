use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Json, Path, State},
    response::{IntoResponse, Response},
};
use axum_extra::{headers::UserAgent, typed_header::TypedHeader};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::FromRow;
use time::OffsetDateTime;
use tracing::{error, warn};
use uuid::Uuid;

use crate::{
    models::{
        issue_report::{IssueReport, IssueReportMessage, NewIssueReport},
        workspace::{Workspace, WorkspaceMembershipSummary},
    },
    responses::JsonResponse,
    routes::auth::{claims::Claims, session::AuthSession},
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct IssueReportPayload {
    pub description: String,
    pub workspace_id: Option<Uuid>,
}

#[derive(Debug, Serialize, FromRow)]
pub struct IssueThreadSummary {
    pub id: Uuid,
    pub status: String,
    pub workspace_id: Option<Uuid>,
    pub workspace_name: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub updated_at: OffsetDateTime,
    pub unread_admin_messages: i64,
    pub last_message_body: Option<String>,
    pub last_message_sender: Option<String>,
    #[serde(with = "time::serde::rfc3339::option")]
    pub last_message_at: Option<OffsetDateTime>,
}

#[derive(Debug, Serialize)]
pub struct IssueListResponse {
    pub issues: Vec<IssueThreadSummary>,
    pub unread_admin_messages: i64,
}

#[derive(Debug, Serialize)]
pub struct IssueDetailWithMessages {
    pub issue: IssueReport,
    pub workspace_name: Option<String>,
    pub messages: Vec<IssueReportMessage>,
    pub unread_admin_messages: i64,
}

#[derive(Debug, Deserialize)]
pub struct IssueReplyPayload {
    pub message: String,
}

#[allow(clippy::result_large_err)]
fn parse_user_id(claims: &Claims) -> Result<Uuid, Response> {
    Uuid::parse_str(&claims.id)
        .map_err(|_| JsonResponse::unauthorized("Invalid user session").into_response())
}

pub async fn submit_issue_report(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    user_agent: Option<TypedHeader<UserAgent>>,
    Json(payload): Json<IssueReportPayload>,
) -> Response {
    let user_id = match parse_user_id(&claims) {
        Ok(id) => id,
        Err(resp) => return resp,
    };

    let description = payload.description.trim();
    if description.is_empty() {
        return JsonResponse::bad_request("Issue description is required").into_response();
    }
    if description.len() > 4000 {
        return JsonResponse::bad_request("Issue description is too long").into_response();
    }

    let user = match state.db.find_public_user_by_id(user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => return JsonResponse::unauthorized("User not found").into_response(),
        Err(err) => {
            error!(?err, %user_id, "failed to load user for issue report");
            return JsonResponse::server_error("Unable to submit issue right now").into_response();
        }
    };

    let memberships: Vec<WorkspaceMembershipSummary> = match state
        .workspace_repo
        .list_memberships_for_user(user_id)
        .await
    {
        Ok(list) => list,
        Err(err) => {
            warn!(?err, %user_id, "failed to load workspace memberships for issue report");
            Vec::new()
        }
    };

    let workspace_id = payload.workspace_id;
    let workspace: Option<Workspace> = match workspace_id {
        Some(id) => match state.workspace_repo.find_workspace(id).await {
            Ok(ws) => ws,
            Err(err) => {
                warn!(?err, %id, "failed to load workspace for issue report");
                None
            }
        },
        None => None,
    };

    let active_membership = workspace_id.and_then(|id| {
        memberships
            .iter()
            .find(|membership| membership.workspace.id == id)
            .cloned()
    });

    let workspace_plan = active_membership
        .as_ref()
        .map(|membership| membership.workspace.plan.clone())
        .or_else(|| workspace.as_ref().map(|ws| ws.plan.clone()));

    let workspace_role = active_membership
        .as_ref()
        .and_then(|membership| serde_json::to_value(membership.role).ok())
        .and_then(|value| value.as_str().map(|s| s.to_string()));

    let workspace_name = workspace.as_ref().map(|ws| ws.name.clone()).or_else(|| {
        active_membership
            .as_ref()
            .map(|membership| membership.workspace.name.clone())
    });

    let user_role = user
        .role
        .and_then(|role| serde_json::to_value(role).ok())
        .and_then(|value| value.as_str().map(|s| s.to_string()));

    let user_name = format!("{} {}", user.first_name.trim(), user.last_name.trim())
        .trim()
        .to_string();
    let user_name = if user_name.is_empty() {
        user.email.clone()
    } else {
        user_name
    };

    let workspace_plan_for_metadata = workspace_plan.clone();
    let workspace_role_for_metadata = workspace_role.clone();
    let user_plan = user.plan.clone();
    let user_company = user.company_name.clone();

    let metadata = json!({
        "user_agent": user_agent.as_ref().map(|ua| ua.to_string()),
        "ip": addr.ip().to_string(),
        "workspace": {
            "id": workspace_id,
            "name": workspace_name,
            "plan": workspace_plan_for_metadata,
            "role": workspace_role_for_metadata,
        },
        "memberships": memberships.iter().map(|membership| {
            json!({
                "workspace_id": membership.workspace.id,
                "workspace_plan": membership.workspace.plan,
                "role": serde_json::to_value(membership.role).ok(),
            })
        }).collect::<Vec<_>>(),
        "user": {
            "plan": user_plan.clone(),
            "role": user_role.clone(),
            "company_name": user_company.clone(),
        },
    });

    let report = NewIssueReport {
        user_id,
        workspace_id,
        user_email: user.email.clone(),
        user_name,
        user_plan,
        user_role,
        workspace_plan,
        workspace_role,
        description: description.to_string(),
        metadata,
    };

    let issue_id = match state.db.create_issue_report(report).await {
        Ok(id) => id,
        Err(err) => {
            error!(?err, %user_id, "failed to persist issue report");
            return JsonResponse::server_error("Unable to submit issue right now").into_response();
        }
    };

    let now = OffsetDateTime::now_utc();
    let _ = sqlx::query(
        r#"
        INSERT INTO issue_report_messages (issue_id, sender_id, sender_type, body, read_by_user_at)
        VALUES ($1, $2, 'user', $3, $4)
        "#,
    )
    .bind(issue_id)
    .bind(Some(user_id))
    .bind(description)
    .bind(now)
    .execute(state.db_pool.as_ref())
    .await;

    let _ = sqlx::query("UPDATE issue_reports SET updated_at = $2 WHERE id = $1")
        .bind(issue_id)
        .bind(now)
        .execute(state.db_pool.as_ref())
        .await;

    JsonResponse::success("Issue report submitted").into_response()
}

pub async fn list_user_issues(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
) -> Result<impl IntoResponse, Response> {
    let user_id = parse_user_id(&claims)?;

    let issues: Vec<IssueThreadSummary> = sqlx::query_as(
        r#"
        SELECT i.id,
               i.status,
               i.workspace_id,
               ws.name AS workspace_name,
               i.updated_at,
               COALESCE(unread.count, 0) AS unread_admin_messages,
               COALESCE(last_msg.body, i.description) AS last_message_body,
               COALESCE(last_msg.sender_type, 'user') AS last_message_sender,
               COALESCE(last_msg.created_at, i.created_at) AS last_message_at
        FROM issue_reports i
        LEFT JOIN workspaces ws ON ws.id = i.workspace_id
        LEFT JOIN LATERAL (
            SELECT COUNT(*)::BIGINT AS count
            FROM issue_report_messages m
            WHERE m.issue_id = i.id
              AND m.sender_type = 'admin'
              AND m.read_by_user_at IS NULL
        ) unread ON TRUE
        LEFT JOIN LATERAL (
            SELECT m.body, m.sender_type, m.created_at
            FROM issue_report_messages m
            WHERE m.issue_id = i.id
            ORDER BY m.created_at DESC
            LIMIT 1
        ) last_msg ON TRUE
        WHERE i.user_id = $1
        ORDER BY i.updated_at DESC
        "#,
    )
    .bind(user_id)
    .fetch_all(state.db_pool.as_ref())
    .await
    .map_err(|_| JsonResponse::server_error("Failed to load issues").into_response())?;

    let unread_admin_messages = issues.iter().map(|issue| issue.unread_admin_messages).sum();

    Ok(Json(IssueListResponse {
        issues,
        unread_admin_messages,
    }))
}

pub async fn get_issue_with_messages(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path(issue_id): Path<Uuid>,
) -> Result<impl IntoResponse, Response> {
    let user_id = parse_user_id(&claims)?;

    let issue: Option<IssueReport> = sqlx::query_as(
        r#"
        SELECT id, user_id, workspace_id, user_email, user_name, user_plan, user_role,
               workspace_plan, workspace_role, description, metadata, created_at, status, updated_at
        FROM issue_reports
        WHERE id = $1 AND user_id = $2
        "#,
    )
    .bind(issue_id)
    .bind(user_id)
    .fetch_optional(state.db_pool.as_ref())
    .await
    .map_err(|_| JsonResponse::server_error("Failed to load issue").into_response())?;

    let Some(issue) = issue else {
        return Err(JsonResponse::not_found("Issue not found").into_response());
    };

    let workspace_name = if let Some(ws_id) = issue.workspace_id {
        sqlx::query_scalar("SELECT name FROM workspaces WHERE id = $1")
            .bind(ws_id)
            .fetch_optional(state.db_pool.as_ref())
            .await
            .unwrap_or(None)
    } else {
        None
    };

    let messages = fetch_issue_messages(&state, issue_id, &issue).await?;
    let unread_admin_messages = messages
        .iter()
        .filter(|message| message.sender_type == "admin" && message.read_by_user_at.is_none())
        .count() as i64;

    Ok(Json(IssueDetailWithMessages {
        issue,
        workspace_name,
        messages,
        unread_admin_messages,
    }))
}

pub async fn reply_to_issue(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path(issue_id): Path<Uuid>,
    Json(payload): Json<IssueReplyPayload>,
) -> Result<impl IntoResponse, Response> {
    let user_id = parse_user_id(&claims)?;
    let body = payload.message.trim();
    if body.is_empty() {
        return Err(JsonResponse::bad_request("Message is required").into_response());
    }
    if body.len() > 4000 {
        return Err(JsonResponse::bad_request("Message is too long").into_response());
    }

    let issue: Option<IssueReport> = sqlx::query_as(
        r#"
        SELECT id, user_id, workspace_id, user_email, user_name, user_plan, user_role,
               workspace_plan, workspace_role, description, metadata, created_at, status, updated_at
        FROM issue_reports
        WHERE id = $1 AND user_id = $2
        "#,
    )
    .bind(issue_id)
    .bind(user_id)
    .fetch_optional(state.db_pool.as_ref())
    .await
    .map_err(|_| JsonResponse::server_error("Failed to load issue").into_response())?;

    let Some(mut issue) = issue else {
        return Err(JsonResponse::not_found("Issue not found").into_response());
    };

    let now = OffsetDateTime::now_utc();
    let insert_query = r#"
        INSERT INTO issue_report_messages (issue_id, sender_id, sender_type, body, read_by_user_at)
        VALUES ($1, $2, 'user', $3, $4)
    "#;

    sqlx::query(insert_query)
        .bind(issue_id)
        .bind(Some(user_id))
        .bind(body)
        .bind(now)
        .execute(state.db_pool.as_ref())
        .await
        .map_err(|_| JsonResponse::server_error("Failed to store reply").into_response())?;

    issue.status = "waiting_admin".to_string();
    issue.updated_at = now;
    let _ = sqlx::query("UPDATE issue_reports SET status = $2, updated_at = $3 WHERE id = $1")
        .bind(issue_id)
        .bind(&issue.status)
        .bind(now)
        .execute(state.db_pool.as_ref())
        .await;

    let workspace_name = if let Some(ws_id) = issue.workspace_id {
        sqlx::query_scalar("SELECT name FROM workspaces WHERE id = $1")
            .bind(ws_id)
            .fetch_optional(state.db_pool.as_ref())
            .await
            .unwrap_or(None)
    } else {
        None
    };

    let messages = fetch_issue_messages(&state, issue_id, &issue).await?;
    let unread_admin_messages = messages
        .iter()
        .filter(|message| message.sender_type == "admin" && message.read_by_user_at.is_none())
        .count() as i64;

    Ok(Json(IssueDetailWithMessages {
        issue,
        workspace_name,
        messages,
        unread_admin_messages,
    }))
}

pub async fn mark_issue_messages_read(
    State(state): State<AppState>,
    AuthSession(claims): AuthSession,
    Path(issue_id): Path<Uuid>,
) -> Result<impl IntoResponse, Response> {
    let user_id = parse_user_id(&claims)?;

    let exists: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM issue_reports WHERE id = $1 AND user_id = $2 LIMIT 1")
            .bind(issue_id)
            .bind(user_id)
            .fetch_optional(state.db_pool.as_ref())
            .await
            .map_err(|_| JsonResponse::server_error("Failed to load issue").into_response())?;

    if exists.is_none() {
        return Err(JsonResponse::not_found("Issue not found").into_response());
    }

    let _ = sqlx::query(
        r#"
        UPDATE issue_report_messages
        SET read_by_user_at = COALESCE(read_by_user_at, now())
        WHERE issue_id = $1
          AND sender_type = 'admin'
          AND read_by_user_at IS NULL
        "#,
    )
    .bind(issue_id)
    .execute(state.db_pool.as_ref())
    .await;

    let unread_admin_messages: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)::BIGINT
        FROM issue_report_messages
        WHERE issue_id = $1
          AND sender_type = 'admin'
          AND read_by_user_at IS NULL
        "#,
    )
    .bind(issue_id)
    .fetch_one(state.db_pool.as_ref())
    .await
    .unwrap_or(0);

    Ok(Json(json!({
        "success": true,
        "unread_admin_messages": unread_admin_messages
    })))
}

pub async fn fetch_issue_messages(
    state: &AppState,
    issue_id: Uuid,
    issue: &IssueReport,
) -> Result<Vec<IssueReportMessage>, Response> {
    let replies: Vec<IssueReportMessage> = sqlx::query_as(
        r#"
        SELECT id, issue_id, sender_id, sender_type, body, created_at, read_by_user_at, read_by_admin_at
        FROM issue_report_messages
        WHERE issue_id = $1
        ORDER BY created_at ASC
        "#,
    )
    .bind(issue_id)
    .fetch_all(state.db_pool.as_ref())
    .await
    .map_err(|_| JsonResponse::server_error("Failed to load messages").into_response())?;

    if replies.is_empty() {
        return Ok(vec![IssueReportMessage {
            id: Uuid::nil(),
            issue_id,
            sender_id: Some(issue.user_id),
            sender_type: "user".to_string(),
            body: issue.description.clone(),
            created_at: issue.created_at,
            read_by_user_at: Some(issue.created_at),
            read_by_admin_at: None,
        }]);
    }

    Ok(replies)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Config, OAuthProviderConfig, OAuthSettings, StripeSettings, DEFAULT_WORKSPACE_MEMBER_LIMIT,
        DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT, RUNAWAY_LIMIT_5MIN,
    };
    use crate::db::mock_db::{MockDb, NoopWorkflowRepository, StaticWorkspaceMembershipRepository};
    use crate::db::mock_stripe_event_log_repository::MockStripeEventLogRepository;
    use crate::db::workspace_connection_repository::NoopWorkspaceConnectionRepository;
    use crate::models::{
        plan::PlanTier,
        user::{User, UserRole},
    };
    use crate::routes::auth::claims::{Claims, TokenUse};
    use crate::services::oauth::{
        account_service::OAuthAccountService, github::mock_github_oauth::MockGitHubOAuth,
        google::mock_google_oauth::MockGoogleOAuth, workspace_service::WorkspaceOAuthService,
    };
    use crate::services::smtp_mailer::MockMailer;
    use crate::services::stripe::MockStripeService;
    use crate::state::{test_pg_pool, AppState};
    use crate::utils::jwt::JwtKeys;
    use axum::http::StatusCode;
    use reqwest::Client;
    use std::sync::Arc;
    use time::OffsetDateTime;

    fn test_config() -> Arc<Config> {
        Arc::new(Config {
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
        })
    }

    fn test_jwt_keys() -> Arc<JwtKeys> {
        Arc::new(
            JwtKeys::from_secret("0123456789abcdef0123456789abcdef")
                .expect("test JWT secret should be valid"),
        )
    }

    fn sample_user(user_id: Uuid) -> User {
        User {
            id: user_id,
            email: "user@example.com".into(),
            password_hash: String::new(),
            first_name: "Test".into(),
            last_name: "User".into(),
            role: Some(UserRole::User),
            plan: Some("workspace".into()),
            company_name: Some("ACME Co".into()),
            stripe_customer_id: None,
            oauth_provider: None,
            onboarded_at: None,
            created_at: OffsetDateTime::now_utc(),
            is_verified: true,
        }
    }

    fn test_claims(user: &User) -> Claims {
        Claims {
            id: user.id.to_string(),
            email: user.email.clone(),
            exp: 0,
            first_name: user.first_name.clone(),
            last_name: user.last_name.clone(),
            role: user.role,
            plan: user.plan.clone(),
            company_name: user.company_name.clone(),
            iss: "test-issuer".into(),
            aud: "test-audience".into(),
            token_use: TokenUse::Access,
        }
    }

    fn base_state(
        db: Arc<MockDb>,
        workspace_repo: Arc<StaticWorkspaceMembershipRepository>,
    ) -> AppState {
        AppState {
            db,
            workflow_repo: Arc::new(NoopWorkflowRepository),
            workspace_repo,
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
            config: test_config(),
            worker_id: Arc::new("test-worker".into()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        }
    }

    #[tokio::test]
    async fn persists_issue_reports_with_user_context() {
        let user_id = Uuid::new_v4();
        let workspace_id = Uuid::new_v4();
        let user = sample_user(user_id);
        let db = Arc::new(MockDb {
            find_user_result: Some(user.clone()),
            ..Default::default()
        });

        let workspace_repo = Arc::new(StaticWorkspaceMembershipRepository::with_plan(
            PlanTier::Workspace,
        ));
        workspace_repo.set_workspace_owner(workspace_id, user_id);

        let state = base_state(db.clone(), workspace_repo);

        let response = submit_issue_report(
            State(state),
            AuthSession(test_claims(&user)),
            ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 8080))),
            None,
            Json(IssueReportPayload {
                description: " Something is wrong with the dashboard ".into(),
                workspace_id: Some(workspace_id),
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);

        let reports = db.issue_reports.lock().unwrap();
        assert_eq!(reports.len(), 1);
        let (_id, report) = &reports[0];
        assert_eq!(report.user_id, user_id);
        assert_eq!(report.workspace_id, Some(workspace_id));
        assert_eq!(report.user_email, user.email);
        assert_eq!(report.user_plan.as_deref(), Some("workspace"));
        assert_eq!(report.description, "Something is wrong with the dashboard");
        assert_eq!(report.workspace_plan.as_deref(), Some("workspace"));
    }

    #[tokio::test]
    async fn rejects_empty_descriptions() {
        let user_id = Uuid::new_v4();
        let user = sample_user(user_id);
        let db = Arc::new(MockDb {
            find_user_result: Some(user.clone()),
            ..Default::default()
        });
        let workspace_repo = Arc::new(StaticWorkspaceMembershipRepository::with_plan(
            PlanTier::Workspace,
        ));

        let state = base_state(db.clone(), workspace_repo);

        let response = submit_issue_report(
            State(state),
            AuthSession(test_claims(&user)),
            ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 8080))),
            None,
            Json(IssueReportPayload {
                description: "   ".into(),
                workspace_id: None,
            }),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(db.issue_reports.lock().unwrap().is_empty());
    }
}
