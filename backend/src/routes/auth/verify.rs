use crate::{responses::JsonResponse, state};
use axum::{
    extract::{Json, State},
    response::IntoResponse,
};
use serde::Deserialize;
use time::OffsetDateTime;

#[derive(Deserialize)]
pub struct VerifyEmailPayload {
    token: String,
}

pub async fn verify_email(
    State(state): State<state::AppState>,
    Json(payload): Json<VerifyEmailPayload>,
) -> impl IntoResponse {
    let now = OffsetDateTime::now_utc();

    match state
        .db
        .mark_verification_token_used(&payload.token, now)
        .await
    {
        Ok(Some(user_id)) => {
            if let Err(e) = state.db.set_user_verified(user_id).await {
                eprintln!("Failed to set user as verified: {:?}", e);
                return JsonResponse::server_error("Failed to update user").into_response();
            }
            JsonResponse::success("Email verified successfully").into_response()
        }
        Ok(None) => {
            JsonResponse::bad_request("Invalid, expired, or already used token").into_response()
        }
        Err(_) => JsonResponse::server_error("Something went wrong").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::post,
        Router,
    };
    use serde_json::json;
    use sqlx::Error;
    use std::sync::Arc;
    use tower::ServiceExt;
    use uuid::Uuid;

    use crate::{
        config::{
            Config, OAuthProviderConfig, OAuthSettings, StripeSettings,
            DEFAULT_WORKSPACE_MEMBER_LIMIT, DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT,
            RUNAWAY_LIMIT_5MIN,
        },
        db::{
            mock_db::{MockDb, NoopWorkflowRepository, NoopWorkspaceRepository},
            mock_stripe_event_log_repository::MockStripeEventLogRepository,
            workspace_connection_repository::NoopWorkspaceConnectionRepository,
        },
        services::{
            oauth::{
                account_service::OAuthAccountService, github::mock_github_oauth::MockGitHubOAuth,
                google::mock_google_oauth::MockGoogleOAuth,
                workspace_service::WorkspaceOAuthService,
            },
            smtp_mailer::MockMailer,
        },
        state::{test_pg_pool, AppState},
        utils::jwt::JwtKeys,
    };
    use reqwest::Client;

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
        })
    }

    use super::verify_email;

    fn test_app(db: MockDb) -> Router {
        Router::new()
            .route("/", post(verify_email))
            .with_state(AppState {
                db: Arc::new(db),
                workflow_repo: Arc::new(NoopWorkflowRepository),
                workspace_repo: Arc::new(NoopWorkspaceRepository),
                workspace_connection_repo: Arc::new(NoopWorkspaceConnectionRepository),
                stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
                db_pool: test_pg_pool(),
                mailer: Arc::new(MockMailer::default()),
                github_oauth: Arc::new(MockGitHubOAuth::default()),
                google_oauth: Arc::new(MockGoogleOAuth::default()),
                oauth_accounts: OAuthAccountService::test_stub(),
                workspace_oauth: WorkspaceOAuthService::test_stub(),
                stripe: Arc::new(crate::services::stripe::MockStripeService::new()),
                integration_registry: crate::state::test_integration_registry(),
                http_client: Arc::new(Client::new()),
                config: test_config(),
                worker_id: Arc::new("test-worker".to_string()),
                worker_lease_seconds: 30,
                jwt_keys: test_jwt_keys(),
            })
    }

    fn test_jwt_keys() -> Arc<JwtKeys> {
        Arc::new(
            JwtKeys::from_secret("0123456789abcdef0123456789abcdef")
                .expect("test JWT secret should be valid"),
        )
    }

    #[tokio::test]
    async fn test_verify_email_success() {
        let user_id = Uuid::new_v4();

        let repo = MockDb {
            mark_verification_token_fn: Box::new(move |_, _| Ok(Some(user_id))),
            set_user_verified_fn: Box::new(|_| Ok(())),
            ..Default::default()
        };

        let app = test_app(repo);
        let req = request_with_token("validtoken");
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_verify_email_invalid_token() {
        let repo = MockDb {
            mark_verification_token_fn: Box::new(|_, _| Ok(None)),
            ..Default::default()
        };

        let app = test_app(repo);
        let req = request_with_token("invalidtoken");
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_verify_email_token_lookup_error() {
        let repo = MockDb {
            mark_verification_token_fn: Box::new(|_, _| Err(Error::RowNotFound)),
            ..Default::default()
        };

        let app = test_app(repo);
        let req = request_with_token("errortoken");
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_verify_email_set_user_error() {
        let user_id = Uuid::new_v4();

        let repo = MockDb {
            mark_verification_token_fn: Box::new(move |_, _| Ok(Some(user_id))),
            set_user_verified_fn: Box::new(|_| Err(sqlx::Error::RowNotFound)),
            ..Default::default()
        };

        let app = test_app(repo);
        let req = request_with_token("validtoken");
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    fn request_with_token(token: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(json!({ "token": token }).to_string()))
            .unwrap()
    }
}
