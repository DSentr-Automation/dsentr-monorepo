mod config;
mod db;
mod engine;
mod integrations;
mod models;
mod responses;
mod routes;
mod runaway_protection;
mod services;
mod session;
mod state;
pub mod utils;
mod worker;

pub use session::{create_session, delete_session, get_session, SessionData};

use anyhow::{anyhow, Context, Result};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::HeaderValue;
use axum::http::Method;
use axum::Json;
use axum::{
    http::HeaderName,
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Router,
};
use chrono::Utc;
use config::Config;
use db::oauth_token_repository::UserOAuthTokenRepository;
use db::postgres_oauth_token_repository::PostgresUserOAuthTokenRepository;
use db::postgres_stripe_event_log_repository::PostgresStripeEventLogRepository;
use db::postgres_user_repository::PostgresUserRepository;
use db::postgres_workflow_repository::PostgresWorkflowRepository;
use db::postgres_workspace_connection_repository::PostgresWorkspaceConnectionRepository;
use db::postgres_workspace_repository::PostgresWorkspaceRepository;
use reqwest::Client;
use responses::JsonResponse;
use routes::auth::{
    handle_login, handle_refresh, handle_signup, session::require_session, verify_email,
};
use routes::{
    account::{confirm_account_deletion, get_account_deletion_summary, request_account_deletion},
    actions::list_actions,
    asana::{
        list_projects as list_asana_projects, list_sections as list_asana_sections,
        list_tags as list_asana_tags, list_task_stories as list_asana_task_stories,
        list_tasks as list_asana_tasks, list_teams as list_asana_teams,
        list_users as list_asana_users, list_workspaces as list_asana_workspaces,
    },
    auth::{
        forgot_password::handle_forgot_password,
        github_login::{github_callback, github_login},
        google_login::{google_callback, google_login},
        handle_logout, handle_me, resend_verification_email,
        reset_password::{handle_reset_password, handle_verify_token},
    },
    dashboard::dashboard_handler,
    early_access::handle_early_access,
    github_provider_webhooks::github_provider_webhook_ingress,
    integrations::notion::{get_notion_database_schema, list_notion_databases},
    issues::{
        get_issue_with_messages, list_user_issues, mark_issue_messages_read, reply_to_issue,
        submit_issue_report,
    },
    microsoft::{list_channel_members, list_team_channels, list_teams},
    oauth::{
        asana_connect_callback, asana_connect_start, assert_oauth_provider_mappings,
        bitly_connect_callback, bitly_connect_start, disconnect_connection, get_connection_by_id,
        github_connect_callback, github_connect_start, google_connect_callback,
        google_connect_start, list_connections, list_provider_connections,
        microsoft_connect_callback, microsoft_connect_start, notion_connect_callback,
        notion_connect_start, raindrop_connect_callback, raindrop_connect_start,
        refresh_connection, revoke_connection, slack_connect_callback, slack_connect_start,
    },
    options::{
        secrets::{delete_secret, list_secrets, upsert_secret},
        user_settings::{get_user_settings, update_user_settings},
    },
    settings::webhooks::list_provider_webhooks,
    slack::list_channels as list_slack_channels,
    webhooks::{
        create_webhook_source, create_webhook_subscription, create_webhook_subscription_for_source,
        delete_webhook_source, delete_webhook_subscription, delete_webhook_subscription_by_id,
        github_webhook_ingress, list_webhook_sources, list_webhook_subscriptions,
        list_webhook_subscriptions_for_source, rotate_webhook_source_secret,
        update_webhook_source_enabled, update_webhook_subscription_enabled, webhook_ingress,
    },
    workflows::{
        cancel_all_runs_for_workflow, cancel_workflow_run, create_workflow, delete_workflow,
        download_run_json, get_egress_allowlist, get_workflow, get_workflow_run_status,
        list_dead_letters, list_runs_for_workflow, list_workflows, requeue_dead_letter,
        rerun_from_failed_node, rerun_workflow_run, set_concurrency_limit, set_egress_allowlist,
        sse_run_events, start_workflow_run, update_workflow,
    },
};
use services::oauth::account_service::OAuthAccountService;
use services::oauth::github::client::GitHubOAuthClient;
use services::oauth::google::client::GoogleOAuthClient;
use services::oauth::workspace_service::{WorkspaceOAuthService, WorkspaceTokenRefresher};
use sqlx::PgPool;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_governor::{governor::GovernorConfigBuilder, GovernorLayer};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};
use tracing::info;
use tracing_subscriber::{prelude::*, EnvFilter};
use uuid::Uuid;

use utils::{
    csrf::{get_csrf_token, validate_csrf},
    jwt::JwtKeys,
};

use crate::db::{
    stripe_event_log_repository::StripeEventLogRepository, user_repository::UserRepository,
    workflow_repository::WorkflowRepository,
    workspace_connection_repository::WorkspaceConnectionRepository,
    workspace_repository::WorkspaceRepository,
};
use crate::engine::actions::init_action_manifest_registry;
use crate::integrations::{assert_github_app_settings, build_integration_registry};
use crate::routes::asana::get_task_details;
use crate::services::pluggable_mailer::PluggableMailer;
use crate::services::stripe::{LiveStripeService, StripeService};
use crate::session::SESSION_CACHE;
use crate::state::AppState;

#[tokio::main]
async fn main() -> Result<()> {
    let _guard = sentry::init(("https://a94598e7b27ba11a160c9576b24e3f6f@o4510324922449920.ingest.us.sentry.io/4510324924874752", sentry::ClientOptions {
    release: sentry::release_name!(),
    // Capture user IPs and potentially sensitive headers when using HTTP server integrations
    // see https://docs.sentry.io/platforms/rust/data-management/data-collected for more info
    send_default_pii: true,
    ..Default::default()
  }));
    let sentry_layer = sentry_tracing::layer();

    let subscriber = tracing_subscriber::registry()
        .with(EnvFilter::new("info")) // or "warn" if you want peace
        .with(tracing_subscriber::fmt::layer())
        .with(sentry_layer);

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|error| {
            tracing::error!(error = ?error, "Failed to set global tracing subscriber");
            error
        })
        .context("failed to set global tracing subscriber")?;

    let governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(1) // 2 req/sec
            .burst_size(5)
            .use_headers() // optional: adds RateLimit-* headers
            .finish()
            .ok_or_else(|| {
                tracing::error!("Failed to build rate limiter configuration");
                anyhow!("failed to build rate limiter configuration")
            })?,
    );

    // Background task to clean up old IPs
    let governor_limiter = governor_conf.limiter().clone();
    std::thread::spawn(move || {
        let interval = std::time::Duration::from_secs(60);
        loop {
            std::thread::sleep(interval);
            //tracing::info!("Rate limiting map size: {}", governor_limiter.len());
            governor_limiter.retain_recent();
        }
    });

    let rate_limit_ms: u64 = std::env::var("RATE_LIMITER_MILLISECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        // Default: 200ms/token (~5 req/sec)
        .unwrap_or(200);
    let rate_limit_burst: u32 = std::env::var("RATE_LIMITER_BURST")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        // Default: allow short bursts during client polling
        .unwrap_or(20);
    let global_governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_millisecond(rate_limit_ms)
            .burst_size(rate_limit_burst)
            .use_headers()
            .error_handler(|_err| {
                JsonResponse::too_many_requests(
                    "Too many requests. Please wait a moment and try again.",
                )
                .into_response()
            })
            .finish()
            .ok_or_else(|| {
                tracing::error!("Failed to build global rate limiter configuration");
                anyhow!("failed to build global rate limiter configuration")
            })?,
    );
    let rate_limit_verify_s: u64 = std::env::var("RATE_LIMITER_VERIFY_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(60);
    let rate_limit_verify_burst: u32 = std::env::var("RATE_LIMITER_VERIFY_BURST")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(3);

    let verify_governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(rate_limit_verify_s)
            .burst_size(rate_limit_verify_burst)
            .use_headers()
            .error_handler(|_err| {
                JsonResponse::too_many_requests(
                    "Too many requests. Please wait a moment and try again",
                )
                .into_response()
            })
            .finish()
            .ok_or_else(|| {
                tracing::error!("Failed to build verification rate limiter configuration");
                anyhow!("failed to build verification rate limiter configuration")
            })?,
    );

    let rate_limit_auth_s: u64 = std::env::var("RATE_LIMITER_AUTH_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(1);
    let rate_limit_auth_burst: u32 = std::env::var("RATE_LIMITER_AUTH_BURST")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(10);
    // Stricter limiter for /api/auth/*
    let auth_governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .per_second(rate_limit_auth_s)
            .burst_size(rate_limit_auth_burst)
            .use_headers()
            .error_handler(|_err| {
                JsonResponse::too_many_requests(
                    "Too many requests. Please wait a moment and try again.",
                )
                .into_response()
            })
            .finish()
            .ok_or_else(|| {
                tracing::error!("Failed to build auth rate limiter configuration");
                anyhow!("failed to build auth rate limiter configuration")
            })?,
    );

    let config = Arc::new(
        Config::from_env()
            .map_err(|error| {
                tracing::error!(error = %error, "Failed to load configuration from environment");
                error
            })
            .context("failed to load configuration from environment")?,
    );

    let jwt_keys = Arc::new(
        JwtKeys::from_env()
            .map_err(|error| {
                tracing::error!(error = %error, "Failed to load JWT secret");
                anyhow!(error)
            })
            .context("failed to load JWT secret from environment")?,
    );

    let pg_pool = establish_connection(&config.database_url).await?;
    let shared_pg_pool = Arc::new(pg_pool.clone());
    let user_repo = Arc::new(PostgresUserRepository {
        pool: pg_pool.clone(),
    }) as Arc<dyn UserRepository>;

    let workflow_repo = Arc::new(PostgresWorkflowRepository {
        pool: pg_pool.clone(),
    }) as Arc<dyn WorkflowRepository>;

    let workspace_repo = Arc::new(PostgresWorkspaceRepository {
        pool: pg_pool.clone(),
    }) as Arc<dyn WorkspaceRepository>;

    // Initialize HTTP client and pluggable mailer (SMTP or SendGrid for app emails)
    let http_client = Client::new();
    let mailer = Arc::new(
        PluggableMailer::from_env(&http_client)
            .map_err(|error| {
                tracing::error!(error = ?error, "Failed to initialize mailer");
                error
            })
            .context("failed to initialize mailer from environment")?,
    );
    let http_client_arc = Arc::new(http_client.clone());

    let google_oauth = Arc::new(GoogleOAuthClient {
        client: http_client.clone(),
    });

    let github_oauth = Arc::new(GitHubOAuthClient {
        client: http_client.clone(),
    });

    let oauth_repo = Arc::new(PostgresUserOAuthTokenRepository {
        pool: pg_pool.clone(),
    }) as Arc<dyn UserOAuthTokenRepository>;
    let workspace_connection_repo = Arc::new(PostgresWorkspaceConnectionRepository {
        pool: pg_pool.clone(),
    }) as Arc<dyn WorkspaceConnectionRepository>;
    let stripe_event_log_repo =
        Arc::new(PostgresStripeEventLogRepository {}) as Arc<dyn StripeEventLogRepository>;
    let encryption_key = Arc::new(config.oauth.token_encryption_key.clone());
    let oauth_accounts = Arc::new(OAuthAccountService::new(
        oauth_repo.clone(),
        workspace_connection_repo.clone(),
        encryption_key.clone(),
        http_client_arc.clone(),
        &config.oauth,
        &config.github_app,
    ));
    let workspace_token_refresher: Arc<dyn WorkspaceTokenRefresher> =
        oauth_accounts.clone() as Arc<dyn WorkspaceTokenRefresher>;
    let workspace_oauth = Arc::new(WorkspaceOAuthService::new(
        oauth_repo.clone(),
        workspace_repo.clone(),
        workspace_connection_repo.clone(),
        workspace_token_refresher,
        encryption_key.clone(),
    ));

    let stripe: Arc<dyn StripeService> = Arc::new(LiveStripeService::from_settings(&config.stripe));

    let integration_registry = Arc::new(build_integration_registry().map_err(|error| {
        tracing::error!(error = %error, "Failed to build integration registry");
        error
    })?);
    assert_github_app_settings(config.as_ref(), integration_registry.as_ref());
    if let Err(message) = assert_oauth_provider_mappings(integration_registry.as_ref()) {
        tracing::error!(%message, "OAuth provider mapping validation failed");
        return Err(anyhow!(message));
    }

    if let Err(error) = init_action_manifest_registry() {
        tracing::error!(error = %error, "Failed to load action manifests");
        return Err(anyhow!(error));
    }

    let state = AppState {
        db: user_repo,
        workflow_repo,
        workspace_repo,
        workspace_connection_repo,
        stripe_event_log_repo,
        db_pool: shared_pg_pool.clone(),
        mailer,
        google_oauth,
        github_oauth,
        oauth_accounts,
        workspace_oauth,
        stripe,
        integration_registry,
        http_client: http_client_arc,
        config: config.clone(),
        worker_id: Arc::new(uuid::Uuid::new_v4().to_string()),
        worker_lease_seconds: std::env::var("WORKER_LEASE_SECONDS")
            .ok()
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(15),
        jwt_keys: jwt_keys.clone(),
    };
    let state_for_worker = state.clone();
    spawn_session_cleanup_task(shared_pg_pool.clone());
    let session_guard = axum::middleware::from_fn_with_state(state.clone(), require_session);

    let frontend_origin = config
        .frontend_origin
        .parse::<HeaderValue>()
        .map_err(|error| {
            tracing::error!(
                error = %error,
                origin = %config.frontend_origin,
                "Invalid FRONTEND_ORIGIN provided"
            );
            error
        })
        .context("invalid FRONTEND_ORIGIN value")?;

    let admin_origin = config
        .admin_origin
        .parse::<HeaderValue>()
        .map_err(|error| {
            tracing::error!(
                error = %error,
                origin = %config.admin_origin,
                "Invalid ADMIN_ORIGIN provided"
            );
            error
        })
        .context("invalid ADMIN_ORIGIN value")?;

    let allow_origin = AllowOrigin::list(vec![frontend_origin.clone(), admin_origin.clone()]);

    let cors = CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([
            AUTHORIZATION,
            CONTENT_TYPE,
            HeaderName::from_static("x-csrf-token"),
        ])
        .allow_credentials(true);

    let csrf_layer = ServiceBuilder::new().layer(axum::middleware::from_fn(validate_csrf));

    let verification_routes = Router::new()
        .route("/signup", post(handle_signup))
        .route("/resend-verification", post(resend_verification_email))
        .layer(csrf_layer.clone())
        .layer(GovernorLayer {
            config: verify_governor_conf.clone(),
        });

    // Routes that require CSRF protection (typically unsafe HTTP methods)
    let csrf_protected_routes = Router::new()
        .route("/login", post(handle_login))
        .route("/refresh", post(handle_refresh))
        .route("/logout", post(handle_logout))
        .route("/verify", post(verify_email))
        .route("/forgot-password", post(handle_forgot_password))
        .route("/reset-password", post(handle_reset_password))
        .layer(csrf_layer.clone()) // Apply CSRF middleware here
        .layer(GovernorLayer {
            config: auth_governor_conf.clone(),
        })
        .merge(verification_routes);

    // Routes that do NOT require CSRF (safe methods and OAuth)
    let auth_public_routes = Router::new()
        .route("/csrf-token", get(get_csrf_token))
        .route("/google-login", get(google_login))
        .route("/github-login", get(github_login))
        .route("/google-callback", get(google_callback))
        .route("/github-callback", get(github_callback))
        .route("/verify-reset-token/{token}", get(handle_verify_token));

    let auth_safe_routes = Router::new()
        .route("/me", get(handle_me))
        .layer(session_guard.clone());

    // Nest them together
    let auth_routes = csrf_protected_routes
        .merge(auth_public_routes)
        .merge(auth_safe_routes)
        .layer(GovernorLayer {
            config: auth_governor_conf.clone(),
        });

    let account_routes = Router::new()
        .route("/delete/request", post(request_account_deletion))
        .route("/delete/confirm", post(confirm_account_deletion))
        .route("/delete/summary/{token}", get(get_account_deletion_summary))
        .route(
            "/privacy",
            get(routes::account::get_privacy_preference)
                .put(routes::account::update_privacy_preference),
        )
        .layer(csrf_layer.clone())
        .layer(session_guard.clone())
        .layer(GovernorLayer {
            config: auth_governor_conf.clone(),
        });

    // Protected workflow routes (CSRF layer applied)
    let workflow_routes = Router::new()
        .route("/", post(create_workflow).get(list_workflows))
        .route("/usage", get(routes::workflows::get_plan_usage))
        .route("/runs", get(routes::workflows::list_active_runs))
        .route("/runs/events", get(routes::workflows::sse_global_runs))
        .route(
            "/{workflow_id}",
            get(get_workflow)
                .put(update_workflow)
                .delete(delete_workflow),
        )
        .route(
            "/{workflow_id}/lock",
            post(routes::workflows::lock_workflow).delete(routes::workflows::unlock_workflow),
        )
        .route("/{workflow_id}/run", post(start_workflow_run))
        .route("/{workflow_id}/runs/{run_id}", get(get_workflow_run_status))
        .route(
            "/{workflow_id}/runs/{run_id}/cancel",
            post(cancel_workflow_run),
        )
        .route("/{workflow_id}/runs", get(list_runs_for_workflow))
        .route(
            "/{workflow_id}/runs/cancel-all",
            post(cancel_all_runs_for_workflow),
        )
        .route(
            "/{workflow_id}/runs/{run_id}/rerun",
            post(rerun_workflow_run),
        )
        .route(
            "/{workflow_id}/runs/{run_id}/rerun-from-failed",
            post(rerun_from_failed_node),
        )
        .route(
            "/{workflow_id}/runs/{run_id}/download",
            get(download_run_json),
        )
        .route(
            "/{workflow_id}/events",
            get(routes::workflows::sse_workflow_updates),
        )
        .route("/{workflow_id}/runs/{run_id}/events", get(sse_run_events))
        .route(
            "/{workflow_id}/runs/events-stream",
            get(routes::workflows::sse_workflow_runs),
        )
        .route(
            "/{workflow_id}/egress",
            get(get_egress_allowlist).post(set_egress_allowlist),
        )
        .route(
            "/{workflow_id}/egress/blocks",
            get(routes::workflows::list_egress_block_events)
                .delete(routes::workflows::clear_egress_block_events),
        )
        .route("/{workflow_id}/concurrency", post(set_concurrency_limit))
        .route(
            "/{workflow_id}/dead-letters",
            get(list_dead_letters).delete(routes::workflows::clear_dead_letters_api),
        )
        .route(
            "/{workflow_id}/dead-letters/{dead_id}/requeue",
            post(requeue_dead_letter),
        )
        .route(
            "/{workflow_id}/logs",
            get(routes::workflows::list_workflow_logs)
                .delete(routes::workflows::clear_workflow_logs),
        )
        .route(
            "/{workflow_id}/logs/{log_id}",
            delete(routes::workflows::delete_workflow_log_entry),
        )
        .layer(csrf_layer.clone())
        .layer(session_guard.clone());

    let workspace_routes = Router::new()
        .route("/", get(routes::workspaces::list_workspaces))
        .route(
            "/onboarding",
            get(routes::workspaces::get_onboarding_context)
                .post(routes::workspaces::complete_onboarding),
        )
        .route("/plan", post(routes::workspaces::change_plan))
        .route(
            "/billing/subscription/resume",
            post(routes::workspaces::resume_workspace_subscription),
        )
        .route(
            "/{workspace_id}/members",
            get(routes::workspaces::list_workspace_members)
                .post(routes::workspaces::add_workspace_member),
        )
        .route(
            "/{workspace_id}/members/{member_id}",
            put(routes::workspaces::update_workspace_member_role)
                .delete(routes::workspaces::remove_workspace_member),
        )
        .route(
            "/{workspace_id}/secrets",
            get(routes::workspaces::list_workspace_secret_ownership),
        )
        .route(
            "/{workspace_id}/leave",
            post(routes::workspaces::leave_workspace),
        )
        .route(
            "/{workspace_id}/revoke",
            post(routes::workspaces::revoke_workspace_member),
        )
        .route(
            "/plan/workspace-to-solo-preview",
            post(routes::workspaces::workspace_to_solo_preview),
        )
        .route(
            "/plan/workspace-to-solo-execute",
            post(routes::workspaces::workspace_to_solo_execute),
        )
        .route(
            "/{workspace_id}/invites",
            get(routes::workspaces::list_workspace_invitations)
                .post(routes::workspaces::create_workspace_invitation),
        )
        .route(
            "/{workspace_id}/invites/{invite_id}/revoke",
            post(routes::workspaces::revoke_workspace_invitation),
        )
        .route(
            "/{workspace_id}/connections/promote",
            post(routes::workspaces::promote_workspace_connection),
        )
        .route(
            "/{workspace_id}/connections/{connection_id}",
            delete(routes::workspaces::remove_workspace_connection),
        )
        .route(
            "/{workspace_id}/webhooks/sources",
            get(list_webhook_sources).post(create_webhook_source),
        )
        .route(
            "/{workspace_id}/webhooks/sources/{source_id}",
            put(update_webhook_source_enabled).delete(delete_webhook_source),
        )
        .route(
            "/{workspace_id}/webhooks/sources/{source_id}/rotate-secret",
            post(rotate_webhook_source_secret),
        )
        .route(
            "/{workspace_id}/webhooks/sources/{source_id}/subscriptions",
            get(list_webhook_subscriptions).post(create_webhook_subscription),
        )
        .route(
            "/{workspace_id}/webhooks/sources/{source_id}/subscriptions/{subscription_id}",
            put(update_webhook_subscription_enabled).delete(delete_webhook_subscription),
        )
        .layer(csrf_layer.clone())
        .layer(session_guard.clone());

    let webhook_subscription_routes = Router::new()
        .route(
            "/webhook-sources/{source_id}/subscriptions",
            get(list_webhook_subscriptions_for_source).post(create_webhook_subscription_for_source),
        )
        .route(
            "/subscriptions/{subscription_id}",
            delete(delete_webhook_subscription_by_id),
        )
        .layer(csrf_layer.clone())
        .layer(session_guard.clone());

    let options_routes = Router::new()
        .route("/secrets", get(list_secrets))
        .route(
            "/secrets/{group}/{service}/{name}",
            put(upsert_secret).delete(delete_secret),
        )
        .route(
            "/user-settings",
            get(get_user_settings).put(update_user_settings),
        )
        .layer(csrf_layer.clone())
        .layer(session_guard.clone());

    let settings_routes = Router::new()
        .route("/webhooks/providers", get(list_provider_webhooks))
        .layer(session_guard.clone());

    let oauth_public_routes = Router::new()
        .route("/google/start", get(google_connect_start))
        .route("/google/callback", get(google_connect_callback))
        .route("/github/start", get(github_connect_start))
        .route("/github/callback", get(github_connect_callback))
        .route("/microsoft/start", get(microsoft_connect_start))
        .route("/microsoft/callback", get(microsoft_connect_callback))
        .route("/slack/start", get(slack_connect_start))
        .route("/slack/callback", get(slack_connect_callback))
        .route("/asana/start", get(asana_connect_start))
        .route("/asana/callback", get(asana_connect_callback))
        .route("/notion/start", get(notion_connect_start))
        .route("/notion/callback", get(notion_connect_callback))
        .route("/bitly/start", get(bitly_connect_start))
        .route("/bitly/callback", get(bitly_connect_callback))
        .route("/raindrop/start", get(raindrop_connect_start))
        .route("/raindrop/callback", get(raindrop_connect_callback))
        .layer(session_guard.clone());

    let oauth_private_routes = Router::new()
        .route("/connections", get(list_connections))
        .route("/connections/{connection_id}", get(get_connection_by_id))
        .route("/{provider}/connections", get(list_provider_connections))
        .route("/{provider}/refresh", post(refresh_connection))
        .route("/{provider}/disconnect", delete(disconnect_connection))
        .route("/{provider}/revoke", post(revoke_connection))
        .layer(csrf_layer.clone())
        .layer(session_guard.clone());

    let oauth_routes = oauth_public_routes.merge(oauth_private_routes);

    let microsoft_routes = Router::new()
        .route("/teams", get(list_teams))
        .route("/teams/{team_id}/channels", get(list_team_channels))
        .route(
            "/teams/{team_id}/channels/{channel_id}/members",
            get(list_channel_members),
        )
        .layer(csrf_layer.clone())
        .layer(session_guard.clone());

    let slack_routes = Router::new()
        .route("/channels", get(list_slack_channels))
        .layer(csrf_layer.clone())
        .layer(session_guard.clone());

    let asana_routes = Router::new()
        .route("/workspaces", get(list_asana_workspaces))
        .route(
            "/workspaces/{workspace_gid}/projects",
            get(list_asana_projects),
        )
        .route("/workspaces/{workspace_gid}/tags", get(list_asana_tags))
        .route("/workspaces/{workspace_gid}/users", get(list_asana_users))
        .route("/workspaces/{workspace_gid}/teams", get(list_asana_teams))
        .route("/workspaces/{workspace_gid}/tasks", get(list_asana_tasks))
        .route("/projects/{project_gid}/sections", get(list_asana_sections))
        .route("/tasks/{task_gid}", get(get_task_details))
        .route("/tasks/{task_gid}/stories", get(list_asana_task_stories))
        .layer(csrf_layer.clone())
        .layer(session_guard.clone());

    let integrations_routes = Router::new()
        .route("/notion/databases", get(list_notion_databases))
        .route(
            "/notion/databases/{database_id}/schema",
            get(get_notion_database_schema),
        )
        .layer(csrf_layer.clone())
        .layer(session_guard.clone());

    // Admin routes (CSRF + rate limit). Only Admin role may call these handlers.
    let admin_routes = Router::new()
        .merge(routes::admin::router())
        .layer(csrf_layer.clone())
        .layer(session_guard.clone())
        .layer(GovernorLayer {
            config: global_governor_conf.clone(),
        });

    let invite_private_routes = Router::new()
        .route("/invites", get(routes::workspaces::list_pending_invites))
        .route(
            "/invites/accept",
            post(routes::workspaces::accept_invitation),
        )
        .route(
            "/invites/decline",
            post(routes::workspaces::decline_invitation),
        )
        .layer(session_guard.clone());

    let invite_public_routes = Router::new().route(
        "/invites/{token}",
        get(routes::workspaces::preview_invitation),
    );

    let invite_routes = invite_private_routes.merge(invite_public_routes);

    // Google provider routes
    use routes::google::get_google_access_token;
    use routes::google::{list_spreadsheet_sheets, list_spreadsheets_files};

    let google_routes = Router::new()
        .route(
            "/spreadsheets/{spreadsheet_id}/sheets",
            get(list_spreadsheet_sheets),
        )
        .route("/spreadsheets/files", get(list_spreadsheets_files))
        .route("/token", get(get_google_access_token))
        .layer(csrf_layer.clone())
        .layer(session_guard.clone());

    let issue_routes = Router::new()
        .route("/issues", post(submit_issue_report).get(list_user_issues))
        .route("/issues/{id}", get(get_issue_with_messages))
        .route("/issues/{id}/reply", post(reply_to_issue))
        .route("/issues/{id}/read", post(mark_issue_messages_read))
        .layer(csrf_layer.clone())
        .layer(session_guard.clone());

    let dashboard_routes = Router::new()
        .route("/api/dashboard", get(dashboard_handler))
        .layer(session_guard.clone());

    let actions_routes = Router::new()
        .route("/actions", get(list_actions))
        .layer(session_guard.clone());

    let app = Router::new()
        .route("/", get(root))
        .route(
            "/healthz",
            get(|| async { Json(serde_json::json!({"status": "ok"})) }),
        )
        .route("/api/early-access", post(handle_early_access))
        // Stripe webhook: public endpoint, no CSRF/auth
        .route(
            "/api/billing/stripe/webhook",
            post(routes::billing::stripe_webhook),
        )
        // New consolidated Stripe webhook path
        .route("/api/stripe/webhook", post(routes::stripe::webhook))
        // Public inbound webhook ingress (source-scoped)
        .route("/api/webhooks/{source_id}", post(webhook_ingress))
        .route(
            "/api/webhooks/github/{subscription_id}",
            post(github_webhook_ingress),
        )
        // Provider GitHub webhook ingress
        .route("/webhooks/github", post(github_provider_webhook_ingress))
        .nest("/api/auth", auth_routes) // <-- your auth routes with CSRF selectively applied
        .nest("/api/account", account_routes)
        .nest("/api/workflows", workflow_routes)
        .nest("/api/workspaces", workspace_routes)
        .merge(Router::new().nest("/api", webhook_subscription_routes))
        .merge(dashboard_routes)
        .merge(Router::new().nest("/api", actions_routes))
        .merge(Router::new().nest("/api", invite_routes))
        .merge(Router::new().nest("/api", issue_routes))
        .nest("/api/oauth", oauth_routes)
        .nest("/api/google", google_routes)
        .nest("/api/microsoft", microsoft_routes)
        .nest("/api/slack", slack_routes)
        .nest("/api/asana", asana_routes)
        .nest("/api/integrations", integrations_routes)
        .nest("/api/options", options_routes)
        .nest("/api/settings", settings_routes)
        .nest("/api/admin", admin_routes)
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(GovernorLayer {
            config: global_governor_conf.clone(),
        })
        .layer(cors);

    let make_service = app.into_make_service_with_connect_info::<SocketAddr>();
    use std::net::SocketAddr;

    let port = std::env::var("PORT").expect("PORT not set");
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();

    // Start background workers (simple no-op executor for now)
    worker::start_background_workers(state_for_worker).await;

    let listener = TcpListener::bind(addr)
        .await
        .map_err(|error| {
            tracing::error!(error = ?error, %addr, "Failed to bind TCP listener");
            error
        })
        .with_context(|| format!("failed to bind TCP listener to {addr}"))?;
    axum::serve(listener, make_service)
        .await
        .map_err(|error| {
            tracing::error!(error = ?error, %addr, "Server encountered an error");
            error
        })
        .context("server encountered an error")?;
    Ok(())
}
/// A simple root route.
async fn root() -> Response {
    JsonResponse::success("Hello, from DSentr!").into_response()
}

fn spawn_session_cleanup_task(db_pool: Arc<PgPool>) {
    tokio::spawn(async move {
        // Sessions expire when their `expires_at` column is in the past; this hourly sweep
        // ensures both Postgres and the in-memory cache drop stale session records.
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(3600));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            ticker.tick().await;
            let now = Utc::now();
            let mut cache_evicted = 0usize;

            SESSION_CACHE.retain(|_, session| {
                if session.expires_at <= now {
                    cache_evicted += 1;
                    false
                } else {
                    true
                }
            });

            let expired_sessions: Vec<Uuid> =
                sqlx::query_scalar("SELECT id FROM user_sessions WHERE expires_at < now()")
                    .fetch_all(db_pool.as_ref())
                    .await
                    .unwrap_or_default();

            if !expired_sessions.is_empty() {
                if let Err(error) = sqlx::query!(
                    r#"
                    UPDATE user_login_activity
                    SET logged_out_at = COALESCE(logged_out_at, now())
                    WHERE session_id = ANY($1)
                    "#,
                    &expired_sessions
                )
                .execute(db_pool.as_ref())
                .await
                {
                    tracing::warn!(
                        ?error,
                        count = expired_sessions.len(),
                        "failed to backfill logout timestamps for expired sessions"
                    );
                }
            }

            match sqlx::query!("DELETE FROM user_sessions WHERE expires_at < now()")
                .execute(db_pool.as_ref())
                .await
            {
                Ok(result) => {
                    let removed = result.rows_affected();
                    tracing::info!(
                        expired_rows = removed,
                        cache_evicted,
                        "purged expired user sessions"
                    );
                }
                Err(error) => {
                    tracing::error!(?error, "failed to purge expired user sessions");
                }
            }
        }
    });
}

/// Establish a connection to the database and verify it.
async fn establish_connection(database_url: &str) -> Result<PgPool> {
    let pool = PgPool::connect(database_url)
        .await
        .map_err(|error| {
            tracing::error!(error = ?error, "Failed to connect to the database");
            error
        })
        .context("failed to connect to the database")?;

    sqlx::query("SELECT 1")
        .execute(&pool)
        .await
        .map_err(|error| {
            tracing::error!(error = ?error, "Failed to verify database connection");
            error
        })
        .context("failed to verify database connection")?;

    info!("Successfully connected to the database");
    Ok(pool)
}
