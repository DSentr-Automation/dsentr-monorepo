use crate::routes::auth::claims::{Claims, TokenUse};
use crate::{
    models::{login_activity::NewLoginActivity, user::OauthProvider},
    responses::JsonResponse,
    session,
    state::AppState,
    utils::{
        ip::{extract_client_ip, lookup_ip_metadata},
        password::verify_password,
        plan_limits::NormalizedPlanTier,
    },
};

use axum::{
    extract::{ConnectInfo, Json, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use axum_extra::{
    extract::cookie::{Cookie, SameSite},
    headers::UserAgent,
    typed_header::TypedHeader,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, to_value};
use sqlx::types::ipnetwork::IpNetwork;
use std::net::SocketAddr;
use time::{Duration as TimeDuration, OffsetDateTime};
use tracing::{error, info, warn};
use uuid::Uuid;

use super::session::AuthSession;

#[derive(Deserialize, Serialize)]
pub struct LoginPayload {
    pub email: String,
    pub password: String,
    pub remember: bool,
}

pub async fn handle_login(
    State(app_state): State<AppState>,
    ConnectInfo(client_addr): ConnectInfo<SocketAddr>,
    request_headers: HeaderMap,
    maybe_agent: Option<TypedHeader<UserAgent>>,
    Json(payload): Json<LoginPayload>,
) -> Response {
    let user = app_state.db.find_user_by_email(&payload.email).await;
    let user = match user {
        Ok(Some(record)) => record,
        Ok(None) => return JsonResponse::unauthorized("Invalid credentials").into_response(),
        Err(e) => {
            eprintln!("DB error: {:?}", e);
            return JsonResponse::server_error("Database error").into_response();
        }
    };

    if user.oauth_provider == Some(OauthProvider::Email) && !user.is_verified {
        return JsonResponse::forbidden_with_code("Email not verified.", "unverified_email")
            .into_response();
    }

    if user.password_hash.trim().is_empty() {
        let provider = user.oauth_provider;
        let provider_name = provider
            .map(|p| p.to_string())
            .unwrap_or("an OAuth provider".to_string());
        return JsonResponse::unauthorized(&format!(
            "This account was created with {} login. Please use that provider to sign in.",
            provider_name
        ))
        .into_response();
    }
    match verify_password(&payload.password, &user.password_hash) {
        Ok(true) => {
            let session_ttl_hours = if payload.remember { 24 * 30 } else { 24 * 7 };
            let expires_at = Utc::now() + Duration::hours(session_ttl_hours);

            let claims = Claims {
                id: user.id.to_string(),
                email: user.email.clone(),
                exp: expires_at.timestamp() as usize,
                first_name: user.first_name.clone(),
                last_name: user.last_name.clone(),
                role: user.role,
                plan: user.plan.clone(),
                company_name: user.company_name.clone(),
                iss: String::new(),
                aud: String::new(),
                token_use: TokenUse::Access,
            };

            let requires_onboarding = user.onboarded_at.is_none()
                || user.plan.as_ref().map(|p| p.is_empty()).unwrap_or(true);

            let memberships = match app_state
                .workspace_repo
                .list_memberships_for_user(user.id)
                .await
            {
                Ok(data) => data,
                Err(err) => {
                    tracing::error!(
                        "failed to load workspace memberships for user {}: {:?}",
                        user.id,
                        err
                    );
                    return JsonResponse::server_error("Failed to load workspace context")
                        .into_response();
                }
            };

            let session_value = match serde_json::to_value(&claims) {
                Ok(value) => value,
                Err(err) => {
                    error!(?err, user_id=%user.id, "failed to serialize claims for session");
                    return JsonResponse::server_error("Failed to create session").into_response();
                }
            };

            let (session_id, _) = match session::create_session(
                app_state.db_pool.as_ref(),
                user.id,
                session_value,
                session_ttl_hours,
            )
            .await
            {
                Ok((session_id, session)) => {
                    info!(%session_id, user_id=%user.id, "session created for login");
                    (session_id, session)
                }
                Err(err) => {
                    error!(?err, user_id=%user.id, "failed to create session during login");
                    return JsonResponse::server_error("Failed to create session").into_response();
                }
            };

            let user_agent = maybe_agent
                .as_ref()
                .map(|TypedHeader(agent)| agent.to_string())
                .filter(|ua| !ua.is_empty())
                .or_else(|| {
                    request_headers
                        .get(header::USER_AGENT)
                        .and_then(|value| value.to_str().ok())
                        .map(|ua| ua.to_string())
                });

            let client_ip = extract_client_ip(&request_headers, Some(client_addr));
            if let Some(client_ip) = client_ip {
                let primary_ip = client_ip.primary;
                let lookup = lookup_ip_metadata(app_state.http_client.as_ref(), primary_ip).await;
                let (city, region, country, latitude, longitude, is_proxy, is_vpn, lookup_raw) =
                    if let Some(meta) = lookup {
                        (
                            meta.city,
                            meta.region,
                            meta.country,
                            meta.latitude,
                            meta.longitude,
                            meta.is_proxy,
                            meta.is_vpn,
                            meta.raw,
                        )
                    } else {
                        (None, None, None, None, None, None, None, None)
                    };

                let activity = NewLoginActivity {
                    user_id: user.id,
                    session_id,
                    ip_address: IpNetwork::from(primary_ip),
                    ipv4_address: client_ip.ipv4.map(IpNetwork::from),
                    ipv6_address: client_ip.ipv6.map(IpNetwork::from),
                    user_agent: user_agent.clone(),
                    city,
                    region,
                    country,
                    latitude,
                    longitude,
                    is_proxy,
                    is_vpn,
                    lookup_raw,
                    logged_in_at: OffsetDateTime::now_utc(),
                };

                if let Err(err) = app_state.db.record_login_activity(activity).await {
                    warn!(?err, user_id=%user.id, "failed to record login activity");
                }
            } else {
                warn!(user_id=%user.id, "could not determine client ip for login");
            }

            let secure_cookie = app_state.config.auth_cookie_secure;
            let session_cookie = Cookie::build(("dsentr_session", session_id.to_string()))
                .http_only(true)
                .secure(secure_cookie)
                .same_site(SameSite::Lax)
                .path("/")
                .max_age(TimeDuration::hours(session_ttl_hours))
                .build();

            let mut response_headers = HeaderMap::new();
            response_headers.insert(
                header::SET_COOKIE,
                HeaderValue::from_str(&session_cookie.to_string()).unwrap(),
            );
            let user_json = to_value(&user).expect("User serialization failed");
            let memberships_json = to_value(&memberships).expect("Membership serialization failed");
            (
                StatusCode::OK,
                response_headers,
                Json(json!({
                    "success": true,
                    "user": user_json,
                    "memberships": memberships_json,
                    "requires_onboarding": requires_onboarding
                })),
            )
                .into_response()
        }
        Ok(false) => JsonResponse::unauthorized("Invalid credentials").into_response(),
        Err(e) => {
            eprintln!("Password verification error: {:?}", e);
            JsonResponse::server_error("Internal error").into_response()
        }
    }
}

pub async fn handle_me(
    State(app_state): State<AppState>,
    AuthSession(claims): AuthSession,
) -> Response {
    let user_id = match Uuid::parse_str(&claims.id) {
        Ok(id) => id,
        Err(_) => return JsonResponse::unauthorized("Invalid user ID").into_response(),
    };

    let user = app_state.db.find_public_user_by_id(user_id).await;

    match user {
        Ok(Some(mut user)) => {
            // Passive billing reconciliation: if personal plan is workspace but Stripe has no active subscription
            // and there is no pending checkout, revert plan to solo and downgrade owned workspaces.
            let mut has_pending_checkout = false;
            if let Ok(settings) = app_state.db.get_user_settings(user_id).await {
                if let Some(obj) = settings.as_object() {
                    if let Some(b) = obj.get("billing").and_then(|v| v.as_object()) {
                        has_pending_checkout = b
                            .get("pending_checkout")
                            .map(|v| !v.is_null())
                            .unwrap_or(false);
                    }
                }
            }
            let mut should_revert = false;
            if !NormalizedPlanTier::from_option(user.plan.as_deref()).is_solo()
                && !has_pending_checkout
            {
                if let Ok(Some(customer_id)) =
                    app_state.db.get_user_stripe_customer_id(user.id).await
                {
                    match app_state
                        .stripe
                        .get_active_subscription_for_customer(&customer_id)
                        .await
                    {
                        Ok(Some(sub)) => {
                            if let (Ok(period_start), Ok(period_end)) = (
                                OffsetDateTime::from_unix_timestamp(sub.current_period_start),
                                OffsetDateTime::from_unix_timestamp(sub.current_period_end),
                            ) {
                                app_state
                                    .sync_owned_workspace_billing_cycles(
                                        user.id,
                                        &sub.id,
                                        period_start,
                                        period_end,
                                    )
                                    .await;
                            }
                        }
                        Ok(None) => should_revert = true,
                        Err(err) => {
                            tracing::warn!(?err, user_id=%user.id, "stripe subscription lookup failed during session check");
                        }
                    }
                }
            }
            if should_revert {
                if let Err(err) = app_state.db.update_user_plan(user.id, "solo").await {
                    tracing::warn!(?err, user_id=%user.id, "failed to revert user plan to solo during session check");
                } else {
                    // Downgrade any owned workspaces to solo
                    if let Ok(memberships) = app_state
                        .workspace_repo
                        .list_memberships_for_user(user.id)
                        .await
                    {
                        for m in memberships.into_iter().filter(|m| {
                            m.workspace.owner_id == user.id && m.workspace.plan.as_str() != "solo"
                        }) {
                            if let Err(err) = app_state
                                .workspace_repo
                                .update_workspace_plan(m.workspace.id, "solo")
                                .await
                            {
                                tracing::warn!(?err, workspace_id=%m.workspace.id, user_id=%user.id, "failed to downgrade workspace to solo during session check");
                            }
                        }
                    }
                    app_state
                        .clear_owned_workspace_billing_cycles(user.id)
                        .await;
                    // Refresh user after change for response
                    if let Ok(Some(u)) = app_state.db.find_public_user_by_id(user.id).await {
                        user = u;
                    }
                }
            }

            let memberships = match app_state
                .workspace_repo
                .list_memberships_for_user(user.id)
                .await
            {
                Ok(data) => data,
                Err(err) => {
                    tracing::error!(
                        "failed to load workspace memberships for user {}: {:?}",
                        user.id,
                        err
                    );
                    return JsonResponse::server_error("Failed to load workspace context")
                        .into_response();
                }
            };

            let requires_onboarding = user.onboarded_at.is_none()
                || user.plan.as_ref().map(|p| p.is_empty()).unwrap_or(true);

            let user_json = to_value(&user).expect("User serialization failed");
            Json(json!({
                "success": true,
                "user": user_json,
                "memberships": memberships,
                "requires_onboarding": requires_onboarding
            }))
            .into_response()
        }
        Ok(None) => JsonResponse::unauthorized("User not found").into_response(),
        Err(e) => {
            eprintln!("DB error in handle_me: {:?}", e);
            JsonResponse::server_error("Database error").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use argon2::{Argon2, PasswordHasher};
    use axum::{
        body::{to_bytes, Body},
        extract::{ConnectInfo, Request},
        http::StatusCode,
        routing::post,
        Router,
    };
    use password_hash::SaltString;
    use rand_core::OsRng;
    use std::net::SocketAddr;
    use time::OffsetDateTime;
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
            user_repository::UserRepository,
            workspace_connection_repository::NoopWorkspaceConnectionRepository,
        },
        models::user::{OauthProvider, User, UserRole},
        routes::auth::login::LoginPayload,
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

    use super::handle_login;

    fn test_user_with_password(password: &str) -> (User, String) {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        let user = User {
            id: Uuid::new_v4(),
            email: "test@example.com".into(),
            password_hash: hash.clone(),
            oauth_provider: None,
            first_name: "Test".into(),
            last_name: "User".into(),
            role: Some(UserRole::User),
            plan: Some("free".into()),
            company_name: Some("Acme Corp".into()),
            stripe_customer_id: None,
            onboarded_at: None,
            created_at: OffsetDateTime::now_utc(),
            is_verified: false,
        };

        (user, password.to_string())
    }

    fn test_jwt_keys() -> Arc<JwtKeys> {
        Arc::new(
            JwtKeys::from_secret("0123456789abcdef0123456789abcdef")
                .expect("test JWT secret should be valid"),
        )
    }

    fn build_app(db: impl UserRepository + 'static, secure_cookie: bool) -> Router {
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
            webhook_event_type_fields: vec!["event_type".to_string(), "type".to_string()],
        });
        let app_state = AppState {
            db: Arc::new(db),
            workflow_repo: Arc::new(NoopWorkflowRepository),
            workspace_repo: Arc::new(NoopWorkspaceRepository),
            workspace_connection_repo: Arc::new(NoopWorkspaceConnectionRepository),
            stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
            db_pool: test_pg_pool(),
            mailer: Arc::new(MockMailer::default()), // Not used in these tests
            google_oauth: Arc::new(MockGoogleOAuth::default()), // Not used in these tests
            github_oauth: Arc::new(MockGitHubOAuth::default()), // Not used in these tests
            oauth_accounts: OAuthAccountService::test_stub(),
            workspace_oauth: WorkspaceOAuthService::test_stub(),
            stripe: Arc::new(crate::services::stripe::MockStripeService::new()),
            integration_registry: crate::state::test_integration_registry(),
            http_client: Arc::new(Client::new()),
            config,
            worker_id: Arc::new("test-worker".to_string()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        };

        Router::new()
            .route("/login", post(handle_login))
            .with_state(app_state)
    }

    fn login_request(payload: &LoginPayload) -> Request {
        Request::post("/login")
            .header("Content-Type", "application/json")
            .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 3000))))
            .body(Body::from(serde_json::to_vec(payload).unwrap()))
            .unwrap()
    }

    // --- Tests ---

    #[tokio::test]
    async fn test_login_success() {
        let password = "password123";
        let (user, _) = test_user_with_password(password);
        eprintln!("User going into MockDb: {:?}", user.email);
        crate::session::reset_test_sessions();
        let app = build_app(
            MockDb {
                find_user_result: Some(user.clone()),
                ..Default::default()
            },
            false,
        );

        let payload = LoginPayload {
            email: user.email.clone(),
            password: password.to_string(),
            remember: true,
        };

        let res = app.oneshot(login_request(&payload)).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        let cookies: Vec<String> = res
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert!(cookies
            .iter()
            .any(|c| c.contains("dsentr_session=") && c.contains("HttpOnly")));

        let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["success"], true);
        assert_eq!(json["user"]["email"], user.email);
        assert!(json["memberships"].is_array());
        assert_eq!(json["requires_onboarding"], true);
    }

    #[tokio::test]
    async fn test_login_uses_secure_cookie_when_enabled() {
        let password = "password123";
        let (user, _) = test_user_with_password(password);
        crate::session::reset_test_sessions();
        let app = build_app(
            MockDb {
                find_user_result: Some(user.clone()),
                ..Default::default()
            },
            true,
        );

        let payload = LoginPayload {
            email: user.email.clone(),
            password: password.to_string(),
            remember: false,
        };

        let res = app.oneshot(login_request(&payload)).await.unwrap();

        let cookies: Vec<String> = res
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().to_string())
            .collect();
        assert!(cookies
            .iter()
            .filter(|c| c.contains("dsentr_session"))
            .all(|c| c.contains("Secure")));
    }

    #[tokio::test]
    async fn test_login_uses_insecure_cookie_when_disabled() {
        let password = "password123";
        let (user, _) = test_user_with_password(password);
        crate::session::reset_test_sessions();
        let app = build_app(
            MockDb {
                find_user_result: Some(user.clone()),
                ..Default::default()
            },
            false,
        );

        let payload = LoginPayload {
            email: user.email.clone(),
            password: password.to_string(),
            remember: false,
        };

        let res = app.oneshot(login_request(&payload)).await.unwrap();

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

    #[tokio::test]
    async fn test_login_requires_onboarding_when_missing_plan() {
        let password = "password123";
        let (mut user, _) = test_user_with_password(password);
        user.plan = None;
        user.onboarded_at = None;

        crate::session::reset_test_sessions();
        let app = build_app(
            MockDb {
                find_user_result: Some(user.clone()),
                ..Default::default()
            },
            false,
        );

        let payload = LoginPayload {
            email: user.email.clone(),
            password: password.to_string(),
            remember: false,
        };

        let res = app.oneshot(login_request(&payload)).await.unwrap();

        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["requires_onboarding"], true);
    }

    #[tokio::test]
    async fn test_login_wrong_password() {
        let password = "password123";
        let (user, _) = test_user_with_password(password);

        crate::session::reset_test_sessions();
        let app = build_app(
            MockDb {
                find_user_result: Some(user.clone()),
                ..Default::default()
            },
            false,
        );

        let payload = LoginPayload {
            email: user.email.clone(),
            password: "wrong-password".to_string(),
            remember: false,
        };

        let res = app.oneshot(login_request(&payload)).await.unwrap();

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_login_user_not_found() {
        crate::session::reset_test_sessions();
        let app = build_app(
            MockDb {
                find_user_result: None,
                ..Default::default()
            },
            false,
        );

        let payload = LoginPayload {
            email: "unknown@example.com".to_string(),
            password: "irrelevant".to_string(),
            remember: false,
        };

        let res = app.oneshot(login_request(&payload)).await.unwrap();

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_login_oauth_only_user() {
        let password_hash = "".to_string();
        let (mut user, _) = test_user_with_password(&password_hash);
        user.oauth_provider = Some(OauthProvider::Google);

        crate::session::reset_test_sessions();
        let app = build_app(
            MockDb {
                find_user_result: Some(user.clone()),
                ..Default::default()
            },
            false,
        );

        let payload = LoginPayload {
            email: user.email.clone(),
            password: "irrelevant".to_string(),
            remember: false,
        };

        let res = app.oneshot(login_request(&payload)).await.unwrap();

        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_login_db_error() {
        crate::session::reset_test_sessions();
        let app = build_app(
            MockDb {
                should_fail: true,
                ..Default::default()
            },
            false,
        );

        let payload = LoginPayload {
            email: "test@example.com".to_string(),
            password: "doesntmatter".to_string(),
            remember: false,
        };

        let res = app
            .oneshot(
                Request::post("/login")
                    .header("Content-Type", "application/json")
                    .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
