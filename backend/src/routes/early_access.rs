use crate::responses::JsonResponse;
use crate::{models::early_access::EarlyAccessPayload, state::AppState};
use axum::{
    extract::{Json, State},
    response::{IntoResponse, Response},
};

pub async fn handle_early_access(
    State(state): State<AppState>,
    Json(payload): Json<EarlyAccessPayload>,
) -> Response {
    let repo = &state.db;

    match repo.insert_early_access_email(&payload.email).await {
        Ok(_) => JsonResponse::success("Thanks for signing up!").into_response(),
        Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
            eprintln!("unique violation insert error: {:?}", db_err.to_string());
            JsonResponse::conflict("You're already on the list!").into_response()
        }
        Err(e) => {
            eprintln!("insert error: {:?}", e.to_string());
            JsonResponse::server_error("Something went wrong").into_response()
        }
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
    use sqlx::error::{BoxDynError, DatabaseError};
    use std::sync::Arc;
    use std::{borrow::Cow, error::Error};
    use tower::ServiceExt;

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
        })
    }

    use super::handle_early_access;

    fn test_app(db: MockDb) -> Router {
        Router::new()
            .route("/", post(handle_early_access))
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

    fn request_with_email(email: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(format!(r#"{{"email":"{}"}}"#, email)))
            .unwrap()
    }

    #[tokio::test]
    async fn test_early_access_success() {
        let repo = MockDb {
            insert_early_access_email_fn: Box::new(|_| Ok(())),
            ..Default::default()
        };

        let app = test_app(repo);
        let res = app
            .oneshot(request_with_email("user@example.com"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_early_access_duplicate() {
        struct FakeDbErr;
        impl std::fmt::Debug for FakeDbErr {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "fake")
            }
        }
        impl std::fmt::Display for FakeDbErr {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "fake")
            }
        }
        impl Error for FakeDbErr {}
        impl DatabaseError for FakeDbErr {
            fn message(&self) -> &str {
                "duplicate key value violates unique constraint"
            }

            fn code(&self) -> Option<Cow<'_, str>> {
                Some(Cow::Borrowed("23505")) // Postgres unique_violation
            }

            fn constraint(&self) -> Option<&str> {
                Some("early_access_email_key")
            }

            fn as_error(&self) -> &(dyn Error + Send + Sync + 'static) {
                self
            }

            fn as_error_mut(&mut self) -> &mut (dyn Error + Send + Sync + 'static) {
                self
            }

            fn into_error(self: Box<Self>) -> BoxDynError {
                self
            }

            fn kind(&self) -> sqlx::error::ErrorKind {
                sqlx::error::ErrorKind::UniqueViolation
            }
        }

        let repo = MockDb {
            insert_early_access_email_fn: Box::new(|_| {
                Err(sqlx::Error::Database(Box::new(FakeDbErr)))
            }),
            ..Default::default()
        };

        let app = test_app(repo);
        let res = app
            .oneshot(request_with_email("duplicate@example.com"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_early_access_generic_error() {
        let repo = MockDb {
            insert_early_access_email_fn: Box::new(|_| Err(sqlx::Error::RowNotFound)),
            ..Default::default()
        };

        let app = test_app(repo);
        let res = app
            .oneshot(request_with_email("fail@example.com"))
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
