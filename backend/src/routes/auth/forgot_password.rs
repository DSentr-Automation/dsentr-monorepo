use axum::{
    extract::{Json, State},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::{responses::JsonResponse, state::AppState};

#[derive(Deserialize)]
pub struct ForgotPasswordRequest {
    pub email: String,
}

pub async fn handle_forgot_password(
    State(state): State<AppState>,
    Json(payload): Json<ForgotPasswordRequest>,
) -> Response {
    let db = &state.db;
    let mailer = &state.mailer;
    let email = payload.email.trim();

    match db.find_user_id_by_email(email).await {
        Ok(Some(user_id)) => {
            let token = Uuid::new_v4().to_string();
            let expiry = OffsetDateTime::now_utc() + Duration::minutes(30);

            if let Err(e) = db
                .insert_password_reset_token(user_id.id, &token, expiry)
                .await
            {
                eprintln!("Failed to insert password reset token: {:?}", e);
            } else if let Err(e) = mailer.send_reset_email(email, &token).await {
                eprintln!("Failed to send reset email: {:?}", e);
            }
        }
        Ok(None) => {}
        Err(e) => {
            eprintln!("Error looking up user by email: {:?}", e);
        }
    }

    JsonResponse::success("If that email exists, a reset link has been sent.").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
        routing::post,
        Router,
    };
    use serde_json::json;
    use sqlx::Error;
    use std::sync::Arc;
    use time::OffsetDateTime;
    use tower::util::ServiceExt;
    use uuid::Uuid;

    use crate::{
        config::{
            Config, OAuthProviderConfig, OAuthSettings, StripeSettings,
            DEFAULT_WORKSPACE_MEMBER_LIMIT, DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT,
            RUNAWAY_LIMIT_5MIN,
        },
        db::{
            mock_db::{NoopWorkflowRepository, NoopWorkspaceRepository},
            mock_stripe_event_log_repository::MockStripeEventLogRepository,
            user_repository::{UserId, UserRepository},
            workspace_connection_repository::NoopWorkspaceConnectionRepository,
        },
        models::{
            signup::SignupPayload,
            user::{OauthProvider, PublicUser, User, UserRole},
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
        })
    }

    struct MockRepo {
        behavior: MockBehavior,
    }

    enum MockBehavior {
        UserFound,
        UserNotFound,
        DbError,
        InsertError,
    }

    #[async_trait]
    impl UserRepository for MockRepo {
        async fn find_user_id_by_email(&self, _email: &str) -> Result<Option<UserId>, Error> {
            match self.behavior {
                MockBehavior::DbError => Err(Error::RowNotFound),
                MockBehavior::UserNotFound => Ok(None),
                _ => Ok(Some(UserId { id: Uuid::new_v4() })),
            }
        }

        async fn insert_password_reset_token(
            &self,
            _user_id: Uuid,
            _token: &str,
            _expiry: OffsetDateTime,
        ) -> Result<(), Error> {
            match self.behavior {
                MockBehavior::InsertError => Err(Error::RowNotFound),
                _ => Ok(()),
            }
        }

        async fn find_user_by_email(&self, _: &str) -> Result<Option<User>, Error> {
            Ok(None)
        }

        async fn create_user_with_oauth(
            &self,
            email: &str,
            first_name: &str,
            last_name: &str,
            provider: OauthProvider,
        ) -> Result<User, Error> {
            Ok(User {
                id: Uuid::new_v4(),
                email: email.to_string(),
                first_name: first_name.to_string(),
                last_name: last_name.to_string(),
                role: Some(UserRole::User),
                password_hash: "".to_string(),
                plan: None,
                company_name: None,
                stripe_customer_id: None,
                oauth_provider: Some(provider),
                onboarded_at: None,
                created_at: OffsetDateTime::now_utc(),
                is_verified: true,
            })
        }

        async fn find_public_user_by_id(&self, _: Uuid) -> Result<Option<PublicUser>, Error> {
            Ok(None)
        }

        async fn verify_password_reset_token(&self, _: &str) -> Result<Option<Uuid>, Error> {
            Ok(None)
        }

        async fn update_user_password(&self, _: Uuid, _: &str) -> Result<(), Error> {
            Ok(())
        }

        async fn mark_password_reset_token_used(&self, _: &str) -> Result<(), Error> {
            Ok(())
        }

        async fn is_email_taken(&self, _: &str) -> Result<bool, Error> {
            Ok(false)
        }

        async fn create_user(
            &self,
            _: &SignupPayload,
            _: &str,
            _: OauthProvider,
        ) -> Result<Uuid, Error> {
            Ok(Uuid::new_v4())
        }

        async fn record_terms_acceptance(
            &self,
            _: Uuid,
            _: &str,
            _: OffsetDateTime,
        ) -> Result<(), Error> {
            Ok(())
        }

        async fn insert_verification_token(
            &self,
            _: Uuid,
            _: &str,
            _: OffsetDateTime,
        ) -> Result<(), Error> {
            Ok(())
        }

        async fn cleanup_user_and_token(&self, _: Uuid, _: &str) -> Result<(), Error> {
            Ok(())
        }

        async fn mark_verification_token_used(
            &self,
            _: &str,
            _: OffsetDateTime,
        ) -> Result<Option<Uuid>, Error> {
            Ok(Some(Uuid::new_v4()))
        }

        async fn set_user_verified(&self, _: Uuid) -> Result<(), Error> {
            Ok(())
        }

        async fn insert_early_access_email(&self, _: &str) -> Result<(), Error> {
            Ok(())
        }

        async fn get_user_settings(&self, _: Uuid) -> Result<serde_json::Value, Error> {
            Ok(serde_json::Value::Object(Default::default()))
        }

        async fn update_user_settings(&self, _: Uuid, _: serde_json::Value) -> Result<(), Error> {
            Ok(())
        }

        async fn update_user_plan(&self, _: Uuid, _: &str) -> Result<(), Error> {
            Ok(())
        }

        async fn mark_workspace_onboarded(&self, _: Uuid, _: OffsetDateTime) -> Result<(), Error> {
            Ok(())
        }

        async fn get_user_stripe_customer_id(&self, _: Uuid) -> Result<Option<String>, Error> {
            Ok(None)
        }

        async fn set_user_stripe_customer_id(&self, _: Uuid, _: &str) -> Result<(), Error> {
            Ok(())
        }

        async fn find_user_id_by_stripe_customer_id(
            &self,
            _customer_id: &str,
        ) -> Result<Option<Uuid>, Error> {
            Ok(None)
        }

        async fn clear_pending_checkout_with_error(
            &self,
            _user_id: Uuid,
            _message: &str,
        ) -> Result<(), Error> {
            Ok(())
        }

        async fn create_issue_report(
            &self,
            _report: crate::models::issue_report::NewIssueReport,
        ) -> Result<Uuid, Error> {
            Ok(Uuid::new_v4())
        }

        async fn upsert_account_deletion_token(
            &self,
            _user_id: Uuid,
            _token: &str,
            _expires_at: OffsetDateTime,
        ) -> Result<(), Error> {
            Ok(())
        }

        async fn get_account_deletion_context(
            &self,
            _token: &str,
        ) -> Result<Option<crate::models::account_deletion::AccountDeletionContext>, Error>
        {
            Ok(None)
        }

        async fn collect_account_deletion_counts(
            &self,
            _user_id: Uuid,
        ) -> Result<crate::models::account_deletion::AccountDeletionCounts, Error> {
            Ok(Default::default())
        }

        async fn finalize_account_deletion(
            &self,
            _token: &str,
            _audit: crate::models::account_deletion::AccountDeletionAuditInsert,
        ) -> Result<(), Error> {
            Ok(())
        }

        async fn delete_verification_tokens_for_user(
            &self,
            _user_id: Uuid,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn clear_stripe_customer_id(&self, _user_id: Uuid) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn record_login_activity(
            &self,
            _activity: crate::models::login_activity::NewLoginActivity,
        ) -> Result<Uuid, sqlx::Error> {
            Ok(Uuid::new_v4())
        }

        async fn mark_logout_activity(
            &self,
            _session_id: Uuid,
            _logged_out_at: OffsetDateTime,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn list_login_activity_for_user(
            &self,
            _user_id: Uuid,
            _limit: i64,
        ) -> Result<Vec<crate::models::login_activity::UserLoginActivity>, sqlx::Error> {
            Ok(vec![])
        }
    }

    fn make_app(behavior: MockBehavior) -> Router {
        let repo = Arc::new(MockRepo { behavior });
        let mailer = Arc::new(MockMailer::default());
        let google_oauth = Arc::new(MockGoogleOAuth::default());
        let github_oauth = Arc::new(MockGitHubOAuth::default());
        let state = AppState {
            db: repo,
            workflow_repo: Arc::new(NoopWorkflowRepository),
            workspace_repo: Arc::new(NoopWorkspaceRepository),
            workspace_connection_repo: Arc::new(NoopWorkspaceConnectionRepository),
            stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
            db_pool: test_pg_pool(),
            mailer,
            google_oauth,
            github_oauth,
            oauth_accounts: OAuthAccountService::test_stub(),
            workspace_oauth: WorkspaceOAuthService::test_stub(),
            stripe: Arc::new(crate::services::stripe::MockStripeService::new()),
            http_client: Arc::new(Client::new()),
            config: test_config(),
            worker_id: Arc::new("test-worker".to_string()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        };

        Router::new()
            .route("/forgot-password", post(handle_forgot_password))
            .with_state(state)
    }

    fn test_jwt_keys() -> Arc<JwtKeys> {
        Arc::new(
            JwtKeys::from_secret("0123456789abcdef0123456789abcdef")
                .expect("test JWT secret should be valid"),
        )
    }

    #[tokio::test]
    async fn test_user_found_and_email_sent() {
        let app = make_app(MockBehavior::UserFound);

        let body = json!({ "email": "test@example.com" });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/forgot-password")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            json["message"],
            "If that email exists, a reset link has been sent."
        );
    }

    #[tokio::test]
    async fn test_user_not_found() {
        let app = make_app(MockBehavior::UserNotFound);

        let body = json!({ "email": "doesnotexist@example.com" });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/forgot-password")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_lookup_fails() {
        let app = make_app(MockBehavior::DbError);

        let body = json!({ "email": "oops@example.com" });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/forgot-password")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_token_insert_fails() {
        let app = make_app(MockBehavior::InsertError);

        let body = json!({ "email": "insertfail@example.com" });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/forgot-password")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_email_send_fails() {
        let repo = Arc::new(MockRepo {
            behavior: MockBehavior::UserFound,
        });
        let mailer = Arc::new(MockMailer::default());
        let google_oauth = Arc::new(MockGoogleOAuth::default());
        let github_oauth = Arc::new(MockGitHubOAuth::default());
        let state = AppState {
            db: repo,
            workflow_repo: Arc::new(NoopWorkflowRepository),
            workspace_repo: Arc::new(NoopWorkspaceRepository),
            workspace_connection_repo: Arc::new(NoopWorkspaceConnectionRepository),
            stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
            db_pool: test_pg_pool(),
            mailer,
            google_oauth,
            github_oauth,
            oauth_accounts: OAuthAccountService::test_stub(),
            workspace_oauth: WorkspaceOAuthService::test_stub(),
            stripe: Arc::new(crate::services::stripe::MockStripeService::new()),
            http_client: Arc::new(Client::new()),
            config: test_config(),
            worker_id: Arc::new("test-worker".to_string()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        };

        let app = Router::new()
            .route("/forgot-password", post(handle_forgot_password))
            .with_state(state);

        let body = json!({ "email": "failtosend@example.com" });
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/forgot-password")
                    .header("Content-Type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
