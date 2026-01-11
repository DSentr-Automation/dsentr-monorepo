use axum::{extract::State, http::HeaderMap, response::IntoResponse};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use time::{Duration as TimeDuration, OffsetDateTime};

use crate::{
    responses::JsonResponse, routes::auth::session::extract_session_id, session, state::AppState,
};

pub async fn handle_logout(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> impl IntoResponse {
    if let Ok(session_id) = extract_session_id(&headers) {
        if let Err(err) = app_state
            .db
            .mark_logout_activity(session_id, OffsetDateTime::now_utc())
            .await
        {
            tracing::warn!(?err, %session_id, "failed to record logout activity");
        }
        match session::delete_session(app_state.db_pool.as_ref(), session_id).await {
            Ok(true) => tracing::info!(%session_id, "session deleted during logout"),
            Ok(false) => tracing::warn!(%session_id, "session missing during logout"),
            Err(err) => {
                tracing::error!(?err, %session_id, "failed to delete session during logout")
            }
        }
    } else {
        tracing::debug!("no session id found while logging out");
    }

    let secure_cookie = app_state.config.auth_cookie_secure;
    let cleared_cookie = Cookie::build(("dsentr_session", ""))
        .path("/")
        .http_only(true)
        .secure(secure_cookie)
        .same_site(SameSite::Lax)
        .max_age(TimeDuration::seconds(0))
        .build();

    let jar = jar.add(cleared_cookie);
    (jar, JsonResponse::success("Logged out"))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
        routing::post,
        Router,
    };
    use serde_json::Value;
    use tower::ServiceExt; // for `app.oneshot(...)`
    use uuid::Uuid;

    use sqlx::PgPool;

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
        routes::auth::claims::{Claims, TokenUse},
        routes::auth::logout::handle_logout,
        services::{
            oauth::{
                account_service::OAuthAccountService, github::mock_github_oauth::MockGitHubOAuth,
                google::mock_google_oauth::MockGoogleOAuth,
                workspace_service::WorkspaceOAuthService,
            },
            smtp_mailer::MockMailer,
        },
        session,
        state::{test_pg_pool, AppState},
        utils::jwt::JwtKeys,
    };

    use reqwest::Client;

    fn test_state(secure_cookie: bool) -> AppState {
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
                token_encryption_key: vec![0u8; 32],
            },
            api_secrets_encryption_key: vec![1u8; 32],
            stripe: StripeSettings {
                client_id: "stub".into(),
                secret_key: "stub".into(),
                webhook_secret: "0123456789abcdef0123456789ABCDEF".into(),
            },
            auth_cookie_secure: secure_cookie,
            jwt_issuer: "test-issuer".into(),
            jwt_audience: "test-audience".into(),
            workspace_member_limit: DEFAULT_WORKSPACE_MEMBER_LIMIT,
            workspace_monthly_run_limit: DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT,
            runaway_limit_5min: RUNAWAY_LIMIT_5MIN,
            webhook_ingress_dedupe_mode: crate::config::WebhookIngressDedupeMode::Off,
            webhook_verification_body_fields: Vec::new(),
            webhook_verification_header_fields: Vec::new(),
        });

        AppState {
            db: Arc::new(MockDb::default()),
            workflow_repo: Arc::new(NoopWorkflowRepository),
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
            http_client: Arc::new(Client::new()),
            config,
            worker_id: Arc::new("test-worker".into()),
            worker_lease_seconds: 30,
            jwt_keys: Arc::new(
                JwtKeys::from_secret("0123456789abcdef0123456789abcdef")
                    .expect("test JWT secret should be valid"),
            ),
        }
    }

    fn build_app(secure_cookie: bool) -> (Router, Arc<PgPool>) {
        let state = test_state(secure_cookie);
        let pool = state.db_pool.clone();
        let router = Router::new()
            .route("/logout", post(handle_logout))
            .with_state(state);

        (router, pool)
    }

    #[tokio::test]
    async fn test_logout_clears_auth_cookie_and_returns_success() {
        let (app, pool) = build_app(true);
        session::reset_test_sessions();

        let claims = Claims {
            id: Uuid::new_v4().to_string(),
            email: "logout@example.com".into(),
            exp: 0,
            first_name: "Test".into(),
            last_name: "User".into(),
            role: None,
            plan: None,
            company_name: None,
            iss: String::new(),
            aud: String::new(),
            token_use: TokenUse::Access,
        };
        let (session_id, _) = session::create_session(
            pool.as_ref(),
            Uuid::new_v4(),
            serde_json::to_value(&claims).unwrap(),
            24,
        )
        .await
        .unwrap();

        // Simulate the POST request
        let res = app
            .oneshot(
                Request::post("/logout")
                    .header("Content-Type", "application/json")
                    .header("Cookie", format!("dsentr_session={}", session_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        // Check status
        assert_eq!(res.status(), StatusCode::OK);

        // Check Set-Cookie header exists
        let cookies: Vec<String> = res
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert!(cookies
            .iter()
            .any(|c| c.contains("dsentr_session=") && c.contains("Max-Age=0")));
        assert!(cookies.iter().all(|c| c.contains("HttpOnly")));
        assert!(cookies.iter().all(|c| c.contains("Secure")));
        assert!(cookies.iter().all(|c| c.contains("SameSite=Lax")));

        let remaining = session::get_session(pool.as_ref(), session_id)
            .await
            .unwrap();
        assert!(remaining.is_none());

        // Check body
        let body_bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(json["success"], true);
        assert_eq!(json["message"], "Logged out");
    }

    #[tokio::test]
    async fn test_logout_uses_non_secure_cookie_when_disabled() {
        let (app, pool) = build_app(false);
        session::reset_test_sessions();
        let (session_id, _) = session::create_session(
            pool.as_ref(),
            Uuid::new_v4(),
            serde_json::json!({"id": Uuid::new_v4().to_string()}),
            24,
        )
        .await
        .unwrap();

        let res = app
            .oneshot(
                Request::post("/logout")
                    .header("Content-Type", "application/json")
                    .header("Cookie", format!("dsentr_session={}", session_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let cookies: Vec<String> = res
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert!(cookies
            .iter()
            .filter(|c| c.contains("dsentr_session"))
            .all(|c| !c.contains("Secure")));
    }
}
