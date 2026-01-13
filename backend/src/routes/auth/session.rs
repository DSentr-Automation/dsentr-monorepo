use axum::{
    body::Body,
    extract::{FromRequestParts, State},
    http::{header::AUTHORIZATION, request::Parts, HeaderMap, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_extra::extract::cookie::CookieJar;

use crate::responses::JsonResponse;
use crate::routes::auth::claims::Claims;
use crate::session::{self, SessionData};
use crate::state::AppState;
use serde_json::from_value;
use tracing::{debug, error, warn};
use uuid::Uuid;

#[derive(Debug, PartialEq)]
pub struct AuthSession(pub Claims);

impl<S> FromRequestParts<S> for AuthSession
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let session = parts
            .extensions
            .get::<SessionData>()
            .ok_or(StatusCode::UNAUTHORIZED)?;

        let claims: Claims =
            from_value(session.data.clone()).map_err(|_| StatusCode::UNAUTHORIZED)?;

        Ok(AuthSession(claims))
    }
}

pub async fn require_session(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, Response> {
    let session_id = match extract_session_id(request.headers()) {
        Ok(id) => id,
        Err(SessionIdError::Missing) => {
            warn!("request missing session credentials");
            return Err(JsonResponse::unauthorized("Session is required").into_response());
        }
        Err(SessionIdError::Invalid) => {
            warn!("malformed session credentials provided");
            return Err(JsonResponse::unauthorized("Invalid session token").into_response());
        }
    };

    match session::get_session(state.db_pool.as_ref(), session_id).await {
        Ok(Some(session)) => {
            debug!(%session_id, user_id = %session.user_id, "authenticated session resolved");
            request.extensions_mut().insert(session);
            Ok(next.run(request).await)
        }
        Ok(None) => {
            warn!(%session_id, "session not found or expired");
            Err(JsonResponse::unauthorized("Session expired").into_response())
        }
        Err(error) => {
            error!(?error, %session_id, "failed to load session from storage");
            Err(JsonResponse::unauthorized("Failed to validate session").into_response())
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum SessionIdError {
    Missing,
    Invalid,
}

pub fn extract_session_id(headers: &HeaderMap) -> Result<Uuid, SessionIdError> {
    if let Some(value) = headers.get(AUTHORIZATION) {
        let value = value.to_str().map_err(|_| SessionIdError::Invalid)?.trim();

        let mut parts = value.split_whitespace();
        let scheme = parts.next().unwrap_or_default();
        if scheme.eq_ignore_ascii_case("bearer") {
            if let Some(token) = parts.next() {
                return Uuid::parse_str(token.trim()).map_err(|_| SessionIdError::Invalid);
            } else {
                return Err(SessionIdError::Invalid);
            }
        } else {
            return Err(SessionIdError::Invalid);
        }
    }

    let jar = CookieJar::from_headers(headers);
    if let Some(cookie) = jar.get("dsentr_session") {
        return Uuid::parse_str(cookie.value()).map_err(|_| SessionIdError::Invalid);
    }

    Err(SessionIdError::Missing)
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        extract::FromRequestParts,
        http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode},
        routing::get,
        Router,
    };
    use axum_extra::extract::cookie::Cookie;
    use std::sync::Arc;
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::{extract_session_id, require_session, AuthSession, SessionIdError};
    use crate::config::{
        Config, OAuthProviderConfig, OAuthSettings, StripeSettings, DEFAULT_WORKSPACE_MEMBER_LIMIT,
        DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT, RUNAWAY_LIMIT_5MIN,
    };
    use crate::db::{
        mock_db::{MockDb, NoopWorkflowRepository, NoopWorkspaceRepository},
        mock_stripe_event_log_repository::MockStripeEventLogRepository,
        workspace_connection_repository::NoopWorkspaceConnectionRepository,
    };
    use crate::models::user::UserRole;
    use crate::responses::JsonResponse;
    use crate::routes::auth::claims::{Claims, TokenUse};
    use crate::services::{
        oauth::{
            account_service::OAuthAccountService, github::mock_github_oauth::MockGitHubOAuth,
            google::mock_google_oauth::MockGoogleOAuth, workspace_service::WorkspaceOAuthService,
        },
        smtp_mailer::MockMailer,
    };
    use crate::session::{self, SessionData};
    use crate::state::{test_pg_pool, AppState};
    use chrono::{Duration, Utc};
    use reqwest::Client;
    use serde_json::json;

    fn test_state() -> AppState {
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
            integration_registry: crate::state::test_integration_registry(),
            http_client: Arc::new(Client::new()),
            config,
            worker_id: Arc::new("test-worker".into()),
            worker_lease_seconds: 30,
            jwt_keys: Arc::new(
                crate::utils::jwt::JwtKeys::from_secret("0123456789abcdef0123456789abcdef")
                    .expect("test key"),
            ),
        }
    }

    fn sample_claims() -> Claims {
        Claims {
            id: Uuid::new_v4().to_string(),
            email: "test@example.com".into(),
            first_name: "Test".into(),
            last_name: "User".into(),
            role: Some(UserRole::User),
            plan: Some("free".into()),
            company_name: Some("ACME".into()),
            exp: (Utc::now() + Duration::hours(1)).timestamp() as usize,
            iss: String::new(),
            aud: String::new(),
            token_use: TokenUse::Access,
        }
    }

    #[tokio::test]
    async fn auth_session_reads_claims_from_extension() {
        let mut request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .unwrap();
        let claims = sample_claims();
        let session = SessionData {
            user_id: Uuid::parse_str(&claims.id).unwrap(),
            data: serde_json::to_value(&claims).unwrap(),
            expires_at: Utc::now() + Duration::hours(1),
            created_at: Utc::now(),
        };
        request.extensions_mut().insert(session);

        let (mut parts, _) = request.into_parts();
        let result = AuthSession::from_request_parts(&mut parts, &()).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0.email, "test@example.com");
    }

    #[tokio::test]
    async fn auth_session_missing_extension_is_unauthorized() {
        let request = Request::builder()
            .method(Method::GET)
            .uri("/")
            .body(Body::empty())
            .unwrap();
        let (mut parts, _) = request.into_parts();
        let result = AuthSession::from_request_parts(&mut parts, &()).await;
        assert_eq!(result, Err(StatusCode::UNAUTHORIZED));
    }

    #[test]
    fn extract_session_id_from_authorization_header() {
        let mut headers = HeaderMap::new();
        let session_id = Uuid::new_v4();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", session_id)).unwrap(),
        );

        let parsed = extract_session_id(&headers).unwrap();
        assert_eq!(parsed, session_id);
    }

    #[test]
    fn extract_session_id_from_cookie() {
        let mut headers = HeaderMap::new();
        let session_id = Uuid::new_v4();
        let cookie = Cookie::new("dsentr_session", session_id.to_string());
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&cookie.to_string()).unwrap(),
        );

        let parsed = extract_session_id(&headers).unwrap();
        assert_eq!(parsed, session_id);
    }

    #[test]
    fn extract_session_id_rejects_bad_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Basic abc123"),
        );
        assert_eq!(extract_session_id(&headers), Err(SessionIdError::Invalid));
    }

    #[tokio::test]
    async fn require_session_rejects_expired_sessions() {
        session::reset_test_sessions();
        let state = test_state();
        let session_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let expires_at = Utc::now() - Duration::hours(1);
        let data = json!({ "id": user_id.to_string(), "token_use": "access" });
        session::insert_test_session(
            session_id,
            SessionData {
                user_id,
                data,
                created_at: expires_at - Duration::hours(1),
                expires_at,
            },
        );

        let app = Router::new()
            .route("/", get(|| async move { JsonResponse::success("ok") }))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                require_session,
            ))
            .with_state(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::COOKIE, format!("dsentr_session={}", session_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
