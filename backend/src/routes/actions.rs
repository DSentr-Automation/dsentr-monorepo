use axum::{extract::State, response::IntoResponse, Json};

use crate::state::AppState;

pub async fn list_actions(State(state): State<AppState>) -> impl IntoResponse {
    let actions = state.action_manifest_registry().entries().to_vec();
    Json(actions)
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::get,
        Router,
    };
    use reqwest::Client;
    use serde_json::Value;
    use std::sync::Arc;
    use tower::ServiceExt;

    use crate::config::{
        Config, OAuthProviderConfig, OAuthSettings, StripeSettings, DEFAULT_WORKSPACE_MEMBER_LIMIT,
        DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT, RUNAWAY_LIMIT_5MIN,
    };
    use crate::db::{
        mock_db::{MockDb, NoopWorkflowRepository, NoopWorkspaceRepository},
        mock_stripe_event_log_repository::MockStripeEventLogRepository,
        workspace_connection_repository::NoopWorkspaceConnectionRepository,
    };
    use crate::services::{
        oauth::{
            account_service::OAuthAccountService, github::mock_github_oauth::MockGitHubOAuth,
            google::mock_google_oauth::MockGoogleOAuth, workspace_service::WorkspaceOAuthService,
        },
        smtp_mailer::MockMailer,
    };
    use crate::state::{test_pg_pool, AppState};
    use crate::utils::jwt::JwtKeys;

    use super::list_actions;

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
                bitly: OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                token_encryption_key: vec![0u8; 32],
            },
            stripe: StripeSettings {
                client_id: "stub".into(),
                secret_key: "stub".into(),
                webhook_secret: "0123456789abcdef0123456789ABCDEF".into(),
            },
            api_secrets_encryption_key: vec![1u8; 32],
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

    fn test_state() -> AppState {
        AppState {
            db: Arc::new(MockDb::default()),
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
            jwt_keys: Arc::new(
                JwtKeys::from_secret("0123456789abcdef0123456789abcdef")
                    .expect("test JWT secret should be valid"),
            ),
        }
    }

    #[tokio::test]
    async fn list_actions_returns_catalog_shape() {
        let app = Router::new()
            .route("/", get(list_actions))
            .with_state(test_state());

        let response = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let payload: Value = serde_json::from_slice(&body).unwrap();
        let entries = payload.as_array().expect("payload should be an array");

        for entry in entries {
            assert!(entry.get("action_id").and_then(|v| v.as_str()).is_some());
            assert!(entry.get("executor").and_then(|v| v.as_str()).is_some());
            assert!(entry.get("http").is_none());
            assert!(entry.get("headers").is_none());

            let ui = entry.get("ui").and_then(|v| v.as_object()).unwrap();
            assert!(ui.get("label").and_then(|v| v.as_str()).is_some());
            assert!(ui.get("description").and_then(|v| v.as_str()).is_some());
            assert!(ui.get("category").and_then(|v| v.as_str()).is_some());
            assert!(ui.get("icon").and_then(|v| v.as_str()).is_some());

            let inputs = entry.get("inputs").and_then(|v| v.as_array()).unwrap();
            for input in inputs {
                assert!(input.get("name").and_then(|v| v.as_str()).is_some());
                assert!(input.get("label").and_then(|v| v.as_str()).is_some());
                assert!(input.get("type").and_then(|v| v.as_str()).is_some());
                assert!(input.get("required").and_then(|v| v.as_bool()).is_some());
            }
        }
    }
}
