use std::collections::HashMap;

use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use reqwest::Url;

use crate::session;
use crate::AppState;
use crate::{
    models::user::OauthProvider, responses::JsonResponse, utils::csrf::generate_csrf_token,
};
use crate::{
    routes::auth::claims::{Claims, TokenUse},
    services::oauth::google::errors::GoogleAuthError,
};
use tracing::{error, info};

pub async fn google_login(
    State(app_state): State<AppState>,
    jar: CookieJar,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let client_id = std::env::var("GOOGLE_CLIENT_ID").unwrap();
    let redirect_uri = std::env::var("GOOGLE_REDIRECT_URI").unwrap();
    let mut url = Url::parse(&std::env::var("GOOGLE_ACCOUNTS_OAUTH_API_BASE").unwrap()).unwrap();

    let state = generate_csrf_token();

    let secure_cookie = app_state.config.auth_cookie_secure;

    url.query_pairs_mut()
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", "email profile")
        .append_pair("state", &state);

    let oauth_state_cookie = Cookie::build(("oauth_state", state))
        .http_only(true)
        .secure(secure_cookie)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(time::Duration::minutes(10))
        .build();

    // If the caller provided an accepted_terms_version (from /signup),
    // write a short-lived cookie so the callback can create the account.
    let mut jar = jar.add(oauth_state_cookie);

    if let Some(ver) = params.get("accepted_terms_version") {
        if !ver.trim().is_empty() {
            let tos_cookie = Cookie::build(("oauth_terms_version", ver.clone()))
                .http_only(true)
                .secure(secure_cookie)
                .same_site(SameSite::Lax)
                .path("/")
                .max_age(time::Duration::minutes(10))
                .build();
            jar = jar.add(tos_cookie);
        }
    }
    (jar, Redirect::to(url.as_str()))
}

pub async fn google_callback(
    State(app_state): State<AppState>,
    jar: CookieJar,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let code = match params.get("code") {
        Some(code) => code,
        None => {
            return JsonResponse::redirect_to_login_with_error("Missing 'code' param")
                .into_response()
        }
    };

    let state_param = match params.get("state") {
        Some(state) => state,
        None => {
            return JsonResponse::redirect_to_login_with_error("Missing 'state' param")
                .into_response()
        }
    };

    let expected_state = match jar.get("oauth_state").map(|c| c.value().to_string()) {
        Some(state) => state,
        None => {
            return JsonResponse::redirect_to_login_with_error(
                &GoogleAuthError::MissingStateCookie.to_string(),
            )
            .into_response()
        }
    };

    if state_param != &expected_state {
        return JsonResponse::redirect_to_login_with_error(
            &GoogleAuthError::InvalidState.to_string(),
        )
        .into_response();
    }

    let access_token = match app_state.google_oauth.exchange_code_for_token(code).await {
        Ok(token) => token,
        Err(e) => {
            eprintln!("Token error: {:?}", e);
            return JsonResponse::redirect_to_login_with_error(
                &GoogleAuthError::TokenExchangeFailed.to_string(),
            )
            .into_response();
        }
    };

    let user_info = match app_state.google_oauth.fetch_user_info(&access_token).await {
        Ok(info) => info,
        Err(e) => {
            eprintln!("User info error: {:?}", e);
            return JsonResponse::redirect_to_login_with_error(
                &GoogleAuthError::UserInfoFetchFailed.to_string(),
            )
            .into_response();
        }
    };

    let email = match user_info["email"].as_str() {
        Some(email) => email,
        None => {
            return JsonResponse::redirect_to_login_with_error(
                &GoogleAuthError::NoEmailFound.to_string(),
            )
            .into_response()
        }
    };

    let first_name = user_info["given_name"].as_str().unwrap_or("").to_string();
    let last_name = user_info["family_name"].as_str().unwrap_or("").to_string();

    let user = match app_state.db.find_user_by_email(email).await {
        Ok(Some(user)) => {
            match (&user.oauth_provider, OauthProvider::Google) {
                // ✅ user signed up with Google, allow login
                (Some(OauthProvider::Google), _) => user,

                // ❌ user signed up with email/password
                (None, _) => {
                    return JsonResponse::redirect_to_login_with_error(
                        "This account was created using email/password. Please log in with email.",
                    )
                    .into_response();
                }

                // ❌ user signed up with another OAuth provider (e.g., GitHub)
                (Some(other), _) => {
                    let reveal_provider = true;

                    if reveal_provider {
                        return JsonResponse::redirect_to_login_with_error(&format!(
                            "This account is linked to {:?}. Please use that provider to log in.",
                            other
                        ))
                        .into_response();
                    } else {
                        return JsonResponse::redirect_to_login_with_error(
                        "Unable to log in with this method. Please use the method you originally signed up with."
                    ).into_response();
                    }
                }
            }
        }

        Ok(None) => {
            // If Terms were accepted on /signup, create the user now; otherwise return to /signup.
            let tos_cookie_opt = jar
                .get("oauth_terms_version")
                .map(|c| c.value().to_string());
            if let Some(ver) = tos_cookie_opt {
                if !ver.trim().is_empty() {
                    match app_state
                        .db
                        .create_user_with_oauth(
                            email,
                            &first_name,
                            &last_name,
                            OauthProvider::Google,
                        )
                        .await
                    {
                        Ok(new_user) => new_user,
                        Err(e) => {
                            eprintln!("DB create error: {:?}", e);
                            return JsonResponse::redirect_to_login_with_error(
                                "Failed to create account via Google",
                            )
                            .into_response();
                        }
                    }
                } else {
                    // invalid value — treat as not accepted
                    let secure_cookie = app_state.config.auth_cookie_secure;
                    let clear_state_cookie = Cookie::build(("oauth_state", ""))
                        .path("/")
                        .secure(secure_cookie)
                        .max_age(time::Duration::seconds(0))
                        .build();
                    let frontend_url = std::env::var("FRONTEND_ORIGIN")
                        .unwrap_or_else(|_| "https://localhost:5173".to_string());
                    let redirect_url = format!(
                        "{}/signup?oauth={}&notice={}",
                        frontend_url,
                        "google",
                        urlencoding::encode(
                            "Finish signup by accepting the Terms, then continue with Google",
                        ),
                    );
                    let jar = CookieJar::new().add(clear_state_cookie);
                    return (jar, Redirect::to(&redirect_url)).into_response();
                }
            } else {
                let secure_cookie = app_state.config.auth_cookie_secure;
                let clear_state_cookie = Cookie::build(("oauth_state", ""))
                    .path("/")
                    .secure(secure_cookie)
                    .max_age(time::Duration::seconds(0))
                    .build();
                let frontend_url = std::env::var("FRONTEND_ORIGIN")
                    .unwrap_or_else(|_| "https://localhost:5173".to_string());
                let redirect_url = format!(
                    "{}/signup?oauth={}&notice={}",
                    frontend_url,
                    "google",
                    urlencoding::encode(
                        "Finish signup by accepting the Terms, then continue with Google",
                    ),
                );
                let jar = CookieJar::new().add(clear_state_cookie);
                return (jar, Redirect::to(&redirect_url)).into_response();
            }
        }

        Err(e) => {
            eprintln!("DB query error: {:?}", e);
            return JsonResponse::redirect_to_login_with_error(
                &GoogleAuthError::DbError(e).to_string(),
            )
            .into_response();
        }
    };
    let session_ttl_hours = 24 * 30;
    let claims = Claims {
        id: user.id.to_string(),
        role: user.role,
        exp: (chrono::Utc::now() + chrono::Duration::hours(session_ttl_hours)).timestamp() as usize,
        email: email.to_string(),
        first_name,
        last_name,
        plan: None,
        company_name: None,
        iss: String::new(),
        aud: String::new(),
        token_use: TokenUse::Access,
    };

    let session_value = match serde_json::to_value(&claims) {
        Ok(val) => val,
        Err(err) => {
            error!(?err, user_id=%user.id, "failed to serialize claims for Google session");
            return JsonResponse::redirect_to_login_with_error(
                &GoogleAuthError::JwtCreationFailed.to_string(),
            )
            .into_response();
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
            info!(%session_id, user_id=%user.id, "google session created");
            (session_id, session)
        }
        Err(err) => {
            error!(?err, user_id=%user.id, "failed to create session for Google login");
            return JsonResponse::redirect_to_login_with_error(
                &GoogleAuthError::JwtCreationFailed.to_string(),
            )
            .into_response();
        }
    };

    let secure_cookie = app_state.config.auth_cookie_secure;
    let auth_cookie = Cookie::build(("dsentr_session", session_id.to_string()))
        .http_only(true)
        .secure(secure_cookie)
        .same_site(SameSite::Lax)
        .path("/")
        .max_age(time::Duration::hours(session_ttl_hours))
        .build();
    let frontend_url =
        std::env::var("FRONTEND_ORIGIN").unwrap_or_else(|_| "https://localhost:5173".to_string());

    let clear_state_cookie = Cookie::build(("oauth_state", ""))
        .path("/")
        .secure(secure_cookie)
        .max_age(time::Duration::seconds(0))
        .build();
    let clear_tos_cookie = Cookie::build(("oauth_terms_version", ""))
        .path("/")
        .secure(secure_cookie)
        .max_age(time::Duration::seconds(0))
        .build();

    let jar = CookieJar::new()
        .add(auth_cookie)
        .add(clear_state_cookie)
        .add(clear_tos_cookie);
    (jar, Redirect::to(&format!("{}/dashboard", frontend_url))).into_response()
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        response::IntoResponse,
        routing::get,
        Router,
    };
    use axum_extra::extract::cookie::CookieJar;
    use serde_json::Value;
    use std::{collections::HashMap, sync::Arc};
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
        routes::auth::google_login::{google_callback, google_login},
        services::{
            oauth::{
                account_service::OAuthAccountService,
                github::mock_github_oauth::MockGitHubOAuth,
                google::{
                    errors::GoogleAuthError, mock_google_oauth::MockGoogleOAuth,
                    service::GoogleOAuthService,
                },
                workspace_service::WorkspaceOAuthService,
            },
            smtp_mailer::MockMailer,
        },
        state::{test_pg_pool, AppState},
        utils::jwt::JwtKeys,
    }; // for `.oneshot()`
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

    fn test_jwt_keys() -> Arc<JwtKeys> {
        Arc::new(
            JwtKeys::from_secret("0123456789abcdef0123456789abcdef")
                .expect("test JWT secret should be valid"),
        )
    }

    fn base_state(config: Arc<Config>) -> AppState {
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
            jwt_keys: test_jwt_keys(),
        }
    }

    #[tokio::test]
    async fn test_google_login_sets_cookie_and_redirects() {
        std::env::set_var("GOOGLE_CLIENT_ID", "test_client_id");
        std::env::set_var("GOOGLE_REDIRECT_URI", "test_client_secret");
        std::env::set_var(
            "GOOGLE_ACCOUNTS_OAUTH_API_BASE",
            "https://accounts.google.com/o/oauth2/auth",
        );
        let app_state = base_state(test_config());
        let app = Router::new()
            .route("/auth/google", get(google_login))
            .with_state(app_state);

        let response = app
            .oneshot(Request::get("/auth/google").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert!(matches!(
            response.status(),
            StatusCode::FOUND | StatusCode::SEE_OTHER
        ));

        let headers = response.headers();
        let location = headers.get("location").unwrap().to_str().unwrap();
        assert!(location.contains("https://accounts.google.com/o/oauth2/auth?client_id=test_client_id&redirect_uri=test_client_secret&response_type=code&scope=email+profile&state="));

        let set_cookie = headers.get("set-cookie").unwrap().to_str().unwrap();
        assert!(set_cookie.contains("oauth_state="));
    }

    #[tokio::test]
    async fn test_google_callback_missing_state_cookie() {
        let repo = Arc::new(MockDb::default());
        let mailer = Arc::new(MockMailer::default());
        let google_oauth = Arc::new(MockGoogleOAuth::default());
        let github_oauth = Arc::new(MockGitHubOAuth::default());
        let config = test_config();
        let app_state = AppState {
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
            config,
            worker_id: Arc::new("test-worker".to_string()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        };

        let code = "dummy";
        let state = "invalid";

        let jar = CookieJar::new(); // no cookies = missing oauth_state

        let response = google_callback(
            axum::extract::State(app_state),
            jar,
            axum::extract::Query({
                HashMap::from([
                    ("code".to_string(), code.to_string()),
                    ("state".to_string(), state.to_string()),
                ])
            }),
        )
        .await
        .into_response();

        // Should redirect to /login with an error
        assert!(
            matches!(response.status(), StatusCode::FOUND | StatusCode::SEE_OTHER),
            "Expected 302 or 303, got {}",
            response.status()
        );

        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();

        assert!(location.contains("/login?error="));
        let binding = GoogleAuthError::MissingStateCookie.to_string();
        let expected = urlencoding::encode(&binding);
        assert!(location.contains(&expected.to_string()));
    }

    #[tokio::test]
    async fn test_google_callback_internal_failure() {
        std::env::set_var("GOOGLE_CLIENT_ID", "test_client_id");
        std::env::set_var("GOOGLE_CLIENT_SECRET", "test_client_secret");

        // Mock that simulates failure — override GitHubOAuth behavior
        #[derive(Default)]
        struct FailingGoogleOAuth;

        #[async_trait]
        impl GoogleOAuthService for FailingGoogleOAuth {
            async fn exchange_code_for_token(
                &self,
                _code: &str,
            ) -> Result<String, GoogleAuthError> {
                Err(GoogleAuthError::TokenExchangeFailed)
            }

            async fn fetch_user_info(&self, _token: &str) -> Result<Value, GoogleAuthError> {
                unreachable!()
            }
        }

        let app_state = AppState {
            db: Arc::new(MockDb::default()),
            workflow_repo: Arc::new(NoopWorkflowRepository),
            workspace_repo: Arc::new(NoopWorkspaceRepository),
            workspace_connection_repo: Arc::new(NoopWorkspaceConnectionRepository),
            stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
            db_pool: test_pg_pool(),
            mailer: Arc::new(MockMailer::default()),
            google_oauth: Arc::new(FailingGoogleOAuth),
            github_oauth: Arc::new(MockGitHubOAuth::default()),
            oauth_accounts: OAuthAccountService::test_stub(),
            workspace_oauth: WorkspaceOAuthService::test_stub(),
            stripe: Arc::new(crate::services::stripe::MockStripeService::new()),
            http_client: Arc::new(Client::new()),
            config: test_config(),
            worker_id: Arc::new("test-worker".to_string()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        };

        let code = "dummy";
        let state = "dummy";
        let jar = CookieJar::new().add(axum_extra::extract::cookie::Cookie::new(
            "oauth_state",
            "dummy",
        ));

        let response = google_callback(
            axum::extract::State(app_state),
            jar,
            axum::extract::Query({
                HashMap::from([
                    ("code".to_string(), code.to_string()),
                    ("state".to_string(), state.to_string()),
                ])
            }),
        )
        .await
        .into_response();

        // Expect redirect to /login?error=GitHub+login+failed
        assert!(
            matches!(response.status(), StatusCode::FOUND | StatusCode::SEE_OTHER),
            "Expected 302 or 303, got {}",
            response.status()
        );

        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(location.contains("/login?error="));
        let binding = GoogleAuthError::TokenExchangeFailed.to_string();
        let expected = urlencoding::encode(&binding);
        assert!(location.contains(&expected.to_string()));
    }
}
