use axum::{
    extract::State,
    http::HeaderMap,
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use chrono::{Duration, Utc};
use serde_json::{from_value, to_value};
use time::Duration as TimeDuration;
use tracing::{error, info, warn};

use crate::{
    responses::JsonResponse,
    routes::auth::{
        claims::Claims,
        session::{extract_session_id, SessionIdError},
    },
    session,
    state::AppState,
};

pub async fn handle_refresh(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Response {
    let session_id = match extract_session_id(&headers) {
        Ok(id) => id,
        Err(SessionIdError::Missing) => {
            warn!("refresh attempted without session id");
            return JsonResponse::unauthorized("Session is required").into_response();
        }
        Err(SessionIdError::Invalid) => {
            warn!("refresh attempted with invalid session id");
            return JsonResponse::unauthorized("Invalid session token").into_response();
        }
    };

    let session = match session::get_session(app_state.db_pool.as_ref(), session_id).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            warn!(%session_id, "refresh requested for missing session");
            return JsonResponse::unauthorized("Session expired").into_response();
        }
        Err(error) => {
            error!(?error, %session_id, "failed to load session during refresh");
            return JsonResponse::server_error("Failed to refresh session").into_response();
        }
    };

    let ttl_hours = (session.expires_at - session.created_at).num_hours().max(1);
    let mut claims: Claims = match from_value(session.data.clone()) {
        Ok(claims) => claims,
        Err(error) => {
            error!(?error, %session_id, "failed to deserialize session claims for refresh");
            return JsonResponse::unauthorized("Invalid session token").into_response();
        }
    };

    let new_expiration = Utc::now() + Duration::hours(ttl_hours);
    claims.exp = new_expiration.timestamp() as usize;

    let updated_data = match to_value(&claims) {
        Ok(value) => value,
        Err(error) => {
            error!(?error, %session_id, "failed to serialize session claims for refresh");
            return JsonResponse::server_error("Failed to refresh session").into_response();
        }
    };

    if let Err(error) = session::upsert_session(
        app_state.db_pool.as_ref(),
        session_id,
        session.user_id,
        updated_data,
        ttl_hours,
    )
    .await
    {
        error!(?error, %session_id, "failed to extend session expiration");
        return JsonResponse::server_error("Failed to refresh session").into_response();
    }

    info!(%session_id, user_id = %session.user_id, "session refreshed");

    let secure_cookie = app_state.config.auth_cookie_secure;
    let refreshed_cookie = Cookie::build(("dsentr_session", session_id.to_string()))
        .http_only(true)
        .secure(secure_cookie)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(TimeDuration::hours(ttl_hours))
        .build();

    let jar = jar.add(refreshed_cookie);
    (jar, JsonResponse::success("Session refreshed")).into_response()
}

#[cfg(test)]
mod tests {
    use super::handle_refresh;
    use axum::{
        extract::State,
        http::{header, HeaderMap, HeaderValue, StatusCode},
        response::IntoResponse,
    };
    use axum_extra::extract::cookie::{Cookie, CookieJar};
    use chrono::{Duration, Utc};
    use reqwest::Client;
    use std::sync::Arc;
    use time::OffsetDateTime;
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
        models::user::{User, UserRole},
        routes::auth::claims::{Claims, TokenUse},
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
    };

    fn build_state(user: User) -> AppState {
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

        let db = MockDb {
            find_user_result: Some(user),
            ..Default::default()
        };

        AppState {
            db: Arc::new(db),
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
            integration_registry: crate::state::test_integration_registry(),
            http_client: Arc::new(Client::new()),
            config,
            worker_id: Arc::new("test-worker".into()),
            worker_lease_seconds: 30,
            jwt_keys: Arc::new(
                crate::utils::jwt::JwtKeys::from_secret("0123456789abcdef0123456789abcdef")
                    .expect("test jwt"),
            ),
        }
    }

    fn sample_user() -> User {
        User {
            id: Uuid::new_v4(),
            email: "refresh@example.com".into(),
            password_hash: "hash".into(),
            first_name: "Refresh".into(),
            last_name: "Tester".into(),
            role: Some(UserRole::User),
            plan: Some("free".into()),
            company_name: Some("Example".into()),
            stripe_customer_id: None,
            oauth_provider: None,
            onboarded_at: Some(OffsetDateTime::now_utc()),
            created_at: OffsetDateTime::now_utc(),
            is_verified: false,
        }
    }

    #[tokio::test]
    async fn refresh_sets_new_cookies() {
        let user = sample_user();
        let state = build_state(user.clone());
        crate::session::reset_test_sessions();

        let claims = Claims {
            id: user.id.to_string(),
            email: user.email.clone(),
            exp: (Utc::now() + Duration::hours(24)).timestamp() as usize,
            first_name: user.first_name.clone(),
            last_name: user.last_name.clone(),
            role: user.role,
            plan: user.plan.clone(),
            company_name: user.company_name.clone(),
            iss: String::new(),
            aud: String::new(),
            token_use: TokenUse::Access,
        };

        let (session_id, _) = session::create_session(
            state.db_pool.as_ref(),
            user.id,
            serde_json::to_value(&claims).unwrap(),
            24,
        )
        .await
        .unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("dsentr_session={}", session_id)).unwrap(),
        );
        let jar = CookieJar::new().add(Cookie::new("dsentr_session", session_id.to_string()));

        let response = handle_refresh(State(state.clone()), headers, jar)
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let cookies: Vec<String> = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert!(cookies.iter().any(|c| c.contains("dsentr_session=")));
    }

    #[tokio::test]
    async fn missing_refresh_cookie_is_unauthorized() {
        let state = build_state(sample_user());
        let response = handle_refresh(State(state), HeaderMap::new(), CookieJar::new())
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn refresh_rejects_unknown_session() {
        let user = sample_user();
        let state = build_state(user.clone());
        crate::session::reset_test_sessions();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("dsentr_session={}", Uuid::new_v4())).unwrap(),
        );

        let response = handle_refresh(State(state), headers, CookieJar::new())
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
