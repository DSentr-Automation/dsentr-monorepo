use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use time::OffsetDateTime;
use tracing::{error, info, warn, Span};
use uuid::Uuid;

use crate::db::postgres_provider_trigger_repository::PostgresProviderTriggerRepository;
use crate::db::postgres_webhook_ingress_dedupe_repository::PostgresWebhookIngressDedupeRepository;
use crate::db::provider_trigger_repository::ProviderTriggerRepository;
use crate::db::webhook_ingress_dedupe_repository::{
    WebhookIngressDedupeKey, WebhookIngressDedupeRepository,
};
use crate::models::oauth_token::ConnectedOAuthProvider;
use crate::models::provider_trigger::ProviderTrigger;
use crate::responses::JsonResponse;
use crate::routes::github_provider_trigger_dispatcher::build_dispatch_list;
use crate::routes::github_provider_trigger_engine_bridge::ProviderTriggerEngineBridge;
use crate::routes::github_provider_trigger_execution_context::resolve_execution_contexts;
use crate::routes::github_provider_trigger_handoff::build_handoff;
use crate::routes::github_provider_trigger_planner::build_execution_plan;
use crate::routes::github_provider_trigger_resolver::GitHubProviderTriggerResolver;
use crate::services::oauth::account_service::{
    installation_id_from_metadata, installation_is_disabled,
};
use crate::state::AppState;

const GITHUB_EVENT_HEADER: &str = "X-GitHub-Event";
const GITHUB_SIGNATURE_HEADER: &str = "X-Hub-Signature-256";
const GITHUB_DELIVERY_HEADER: &str = "X-GitHub-Delivery";
const GITHUB_SIGNATURE_PREFIX: &str = "sha256=";
const GITHUB_APP_WEBHOOK_SECRET_ENV: &str = "GITHUB_APP_WEBHOOK_SECRET";
const PROVIDER_NAME: &str = "github";
const GITHUB_PROVIDER_UUID: Uuid = Uuid::from_u128(0x5d1f3c1e9f4c4d1e8b2f6bfb1bdb7b4a);

type HmacSha256 = Hmac<Sha256>;

pub async fn github_provider_webhook_ingress(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let trigger_repo: Arc<dyn ProviderTriggerRepository> =
        Arc::new(PostgresProviderTriggerRepository {
            pool: (*app_state.db_pool).clone(),
        });
    let dedupe_repo = PostgresWebhookIngressDedupeRepository {
        pool: (*app_state.db_pool).clone(),
    };

    handle_github_provider_webhook_ingress(
        &app_state,
        trigger_repo,
        &dedupe_repo,
        &headers,
        body.as_ref(),
    )
    .await
}

pub(crate) async fn handle_github_provider_webhook_ingress(
    app_state: &AppState,
    trigger_repo: Arc<dyn ProviderTriggerRepository>,
    dedupe_repo: &dyn WebhookIngressDedupeRepository,
    headers: &HeaderMap,
    body: &[u8],
) -> Response {
    let span = tracing::info_span!(
        "provider_webhook_ingress",
        provider = PROVIDER_NAME,
        event_type = tracing::field::Empty,
        delivery_id_present = tracing::field::Empty,
        trigger_count = tracing::field::Empty,
        run_count = tracing::field::Empty,
    );
    let _guard = span.enter();

    let github_event = match require_header(headers, GITHUB_EVENT_HEADER) {
        Ok(value) => value,
        Err(resp) => return resp,
    };
    let signature_header = match require_header(headers, GITHUB_SIGNATURE_HEADER) {
        Ok(value) => value,
        Err(resp) => return resp,
    };
    let github_delivery = optional_header(headers, GITHUB_DELIVERY_HEADER);
    Span::current().record("delivery_id_present", github_delivery.is_some());

    let secret = match resolve_github_webhook_secret() {
        Ok(secret) => secret,
        Err(resp) => return resp,
    };
    let signature_len = signature_header.len();
    let signature_prefix_ok = signature_header
        .trim()
        .starts_with(GITHUB_SIGNATURE_PREFIX);

    if let Err(reason) = validate_github_signature(&secret, signature_header, body) {
        warn!(
            reason,
            signature_len,
            signature_prefix_ok,
            body_len = body.len(),
            secret_len = secret.len(),
            "github webhook signature validation failed"
        );
        return JsonResponse::forbidden(reason).into_response();
    }

    let base_event_type = format!("github.{github_event}");
    if github_event == "ping" {
        Span::current().record("event_type", tracing::field::display(&base_event_type));
        Span::current().record("trigger_count", 0);
        Span::current().record("run_count", 0);
        return (StatusCode::OK, Json(json!({}))).into_response();
    }

    let Some(delivery_id) = github_delivery.as_deref() else {
        warn!("Missing X-GitHub-Delivery header, skipping idempotency");
        return handle_github_provider_event(
            app_state,
            trigger_repo,
            headers,
            body,
            github_event,
            github_delivery,
            base_event_type.as_str(),
        )
        .await;
    };

    // The unique constraint includes source_id + event_type + payload_sha256 + signature + timestamp_floor,
    // so deriving every field from the delivery id guarantees identical deliveries collide deterministically.
    let dedupe_key = WebhookIngressDedupeKey {
        source_id: GITHUB_PROVIDER_UUID,
        event_type: format!("github:{delivery_id}"),
        payload_sha256: Sha256::digest(delivery_id.as_bytes()).to_vec(),
        signature: delivery_id.to_string(),
        timestamp_floor: OffsetDateTime::UNIX_EPOCH,
    };

    match dedupe_repo.insert_dedupe_key(&dedupe_key).await {
        Ok(true) => {}
        Ok(false) => {
            Span::current().record("event_type", tracing::field::display(&base_event_type));
            Span::current().record("trigger_count", 0);
            Span::current().record("run_count", 0);
            info!(delivery_id = %delivery_id, "duplicate github delivery id");
            return accepted_response();
        }
        Err(err) => {
            error!(?err, "failed to record github delivery id");
            return JsonResponse::server_error("Failed to record delivery id").into_response();
        }
    }

    handle_github_provider_event(
        app_state,
        trigger_repo,
        headers,
        body,
        github_event,
        github_delivery,
        base_event_type.as_str(),
    )
    .await
}

async fn handle_github_provider_event(
    app_state: &AppState,
    trigger_repo: Arc<dyn ProviderTriggerRepository>,
    _headers: &HeaderMap,
    body: &[u8],
    github_event: &str,
    github_delivery: Option<String>,
    base_event_type: &str,
) -> Response {
    let payload: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(err) => {
            warn!(?err, "invalid github webhook payload JSON");
            return JsonResponse::bad_request("Invalid JSON payload").into_response();
        }
    };

    let action = payload
        .get("action")
        .and_then(|value| value.as_str())
        .map(|value| value.trim())
        .filter(|value| !value.is_empty());
    let event_type = match action {
        Some(action) => format!("github.{}.{}", github_event, action),
        None => base_event_type.to_string(),
    };

    Span::current().record("event_type", tracing::field::display(&event_type));

    info!(%event_type, "github provider webhook event resolved");

    let installation_id = payload
        .get("installation")
        .and_then(|inst| inst.get("id"))
        .and_then(|id| id.as_u64())
        .map(|id| id.to_string());
    let repository_id = payload
        .get("repository")
        .and_then(|repo| repo.get("id"))
        .and_then(|id| id.as_u64())
        .map(|id| id.to_string());

    let resolver = GitHubProviderTriggerResolver::new(trigger_repo);
    match resolver
        .resolve_triggers(
            &event_type,
            installation_id.as_deref(),
            repository_id.as_deref(),
        )
        .await
    {
        Ok(matches) => {
            let installation_count = matches.installation_matches.len();
            let repository_count = matches.repository_matches.len();
            if installation_count == 0 && repository_count == 0 {
                Span::current().record("trigger_count", 0);
                Span::current().record("run_count", 0);
                info!(%event_type, "no provider trigger matches");
                return accepted_response();
            }

            let mut plan = build_execution_plan(matches);
            plan.triggers = filter_disabled_provider_triggers(app_state, plan.triggers).await;
            let dispatches = build_dispatch_list(plan);
            if dispatches.is_empty() {
                Span::current().record("trigger_count", 0);
                Span::current().record("run_count", 0);
                info!(%event_type, "no provider trigger dispatches");
                return accepted_response();
            }

            let trigger_count = dispatches.len();
            let handoff = build_handoff(dispatches, github_delivery);
            let contexts =
                match resolve_execution_contexts(handoff, app_state.workflow_repo.as_ref()).await {
                    Ok(contexts) => contexts,
                    Err(err) => {
                        error!(?err, "failed to resolve execution contexts");
                        return JsonResponse::server_error("Failed to resolve execution contexts")
                            .into_response();
                    }
                };
            let run_count = contexts.len();
            Span::current().record("trigger_count", trigger_count as i64);
            Span::current().record("run_count", run_count as i64);

            let bridge = ProviderTriggerEngineBridge::new();
            let executor =
                crate::engine::provider_trigger_executor::GitHubProviderTriggerExecutor::new(
                    app_state.clone(),
                );
            bridge.execute(&executor, contexts).await;

            info!(
                %event_type,
                installation_id = ?installation_id,
                repository_id = ?repository_id,
                installation_matches = installation_count,
                repository_matches = repository_count,
                "provider trigger execution completed"
            );
        }
        Err(err) => {
            error!(
                ?err,
                %event_type,
                installation_id = ?installation_id,
                repository_id = ?repository_id,
                "provider trigger resolution failed"
            );
            return JsonResponse::server_error("Failed to resolve provider triggers")
                .into_response();
        }
    }

    accepted_response()
}

async fn filter_disabled_provider_triggers(
    app_state: &AppState,
    triggers: Vec<ProviderTrigger>,
) -> Vec<ProviderTrigger> {
    let mut filtered = Vec::with_capacity(triggers.len());
    let mut workspace_cache: HashMap<Uuid, Vec<crate::models::oauth_token::WorkspaceConnection>> =
        HashMap::new();

    for trigger in triggers {
        let Some(workspace_id) = trigger.workspace_id else {
            filtered.push(trigger);
            continue;
        };
        let Some(installation_id) = trigger.installation_id.as_deref() else {
            filtered.push(trigger);
            continue;
        };

        if let std::collections::hash_map::Entry::Vacant(entry) =
            workspace_cache.entry(workspace_id)
        {
            let connections = app_state
                .workspace_connection_repo
                .list_by_workspace_and_provider(workspace_id, ConnectedOAuthProvider::GitHub)
                .await
                .unwrap_or_default();
            entry.insert(connections);
        }

        let connections = workspace_cache
            .get(&workspace_id)
            .map(|list| list.as_slice())
            .unwrap_or_default();

        let disabled_connection = connections
            .iter()
            .filter(|connection| {
                installation_id_from_metadata(&connection.metadata).as_deref()
                    == Some(installation_id)
            })
            .max_by(|a, b| a.updated_at.cmp(&b.updated_at))
            .filter(|connection| installation_is_disabled(&connection.metadata));

        if let Some(connection) = disabled_connection {
            warn!(
                trigger_id = %trigger.id,
                workflow_id = %trigger.workflow_id,
                trigger_node_id = %trigger.trigger_node_id,
                workspace_id = %workspace_id,
                installation_id = %installation_id,
                connection_id = %connection.id,
                "provider trigger skipped due to disabled GitHub installation"
            );
            continue;
        }

        filtered.push(trigger);
    }

    filtered
}

fn accepted_response() -> Response {
    (StatusCode::OK, Json(json!({ "success": true }))).into_response()
}

#[allow(clippy::result_large_err)]
fn require_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, Response> {
    let value = headers.get(name).ok_or_else(|| {
        JsonResponse::bad_request(&format!("Missing {name} header")).into_response()
    })?;
    let value = value.to_str().map_err(|_| {
        JsonResponse::bad_request(&format!("Invalid {name} header")).into_response()
    })?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(JsonResponse::bad_request(&format!("Missing {name} header")).into_response());
    }
    Ok(trimmed)
}

fn optional_header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

#[allow(clippy::result_large_err)]
fn resolve_github_webhook_secret() -> Result<String, Response> {
    // Deployment-level GitHub App webhook secret (not OAuth client credentials).
    let value = env::var(GITHUB_APP_WEBHOOK_SECRET_ENV).unwrap_or_default();
    let trimmed = value.trim();
    if !trimmed.is_empty() {
        info!(
            secret_len = trimmed.len(),
            "GitHub webhook secret loaded"
        );
        return Ok(trimmed.to_string());
    }
    error!("GitHub webhook secret not configured");
    Err(JsonResponse::server_error("GitHub webhook secret not configured").into_response())
}

fn compute_github_signature(secret: &str, body: &[u8]) -> Result<String, &'static str> {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| "Invalid signature key")?;
    mac.update(body);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn validate_github_signature(
    secret: &str,
    signature_header: &str,
    body: &[u8],
) -> Result<(), &'static str> {
    let signature = signature_header.trim();
    let signature = signature
        .strip_prefix(GITHUB_SIGNATURE_PREFIX)
        .ok_or("Invalid X-Hub-Signature-256 header")?;
    if signature.is_empty() {
        return Err("Missing signature");
    }

    let expected = compute_github_signature(secret, body)?;
    if expected.as_bytes().ct_eq(signature.as_bytes()).unwrap_u8() == 0u8 {
        return Err("Invalid signature");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::body::to_bytes;
    use reqwest::Client;
    use std::collections::HashSet;
    use std::sync::Mutex;
    use uuid::Uuid;

    use crate::config::{
        Config, GitHubAppSettings, OAuthProviderConfig, StripeSettings,
        DEFAULT_WORKSPACE_MEMBER_LIMIT, DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT, RUNAWAY_LIMIT_5MIN,
    };
    use crate::db::mock_db::NoopWorkspaceRepository;
    use crate::db::mock_db::{MockDb, NoopWorkflowRepository};
    use crate::db::mock_stripe_event_log_repository::MockStripeEventLogRepository;
    use crate::db::provider_trigger_repository::ProviderTriggerRepository;
    use crate::db::webhook_ingress_dedupe_repository::{
        WebhookIngressDedupeKey, WebhookIngressDedupeRepository,
    };
    use crate::db::workspace_connection_repository::NoopWorkspaceConnectionRepository;
    use crate::models::provider_trigger::{ProviderTrigger, ProviderTriggerProvider};
    use crate::services::oauth::account_service::OAuthAccountService;
    use crate::services::oauth::github::mock_github_oauth::MockGitHubOAuth;
    use crate::services::oauth::google::mock_google_oauth::MockGoogleOAuth;
    use crate::services::oauth::workspace_service::WorkspaceOAuthService;
    use crate::services::smtp_mailer::MockMailer;
    use crate::state::{test_integration_registry, test_pg_pool, AppState};
    use crate::utils::jwt::JwtKeys;

    #[derive(Default)]
    struct StubProviderTriggerRepo {
        installation_calls: Mutex<Vec<(String, String)>>,
        repository_calls: Mutex<Vec<(String, String)>>,
    }

    #[async_trait]
    impl ProviderTriggerRepository for StubProviderTriggerRepo {
        async fn create_provider_trigger(
            &self,
            _params: crate::models::provider_trigger::CreateProviderTrigger,
        ) -> Result<ProviderTrigger, sqlx::Error> {
            Err(sqlx::Error::Protocol("not implemented".into()))
        }

        async fn list_by_workflow_id(
            &self,
            _workspace_id: Option<Uuid>,
            _workflow_id: Uuid,
        ) -> Result<Vec<ProviderTrigger>, sqlx::Error> {
            Ok(vec![])
        }

        async fn list_by_installation_event(
            &self,
            _provider: ProviderTriggerProvider,
            installation_id: &str,
            event_type: &str,
        ) -> Result<Vec<ProviderTrigger>, sqlx::Error> {
            self.installation_calls
                .lock()
                .unwrap()
                .push((installation_id.to_string(), event_type.to_string()));
            Ok(vec![])
        }

        async fn list_by_repository_event(
            &self,
            _provider: ProviderTriggerProvider,
            repository_id: &str,
            event_type: &str,
        ) -> Result<Vec<ProviderTrigger>, sqlx::Error> {
            self.repository_calls
                .lock()
                .unwrap()
                .push((repository_id.to_string(), event_type.to_string()));
            Ok(vec![])
        }

        async fn delete_by_workflow_id(
            &self,
            _workspace_id: Option<Uuid>,
            _workflow_id: Uuid,
        ) -> Result<u64, sqlx::Error> {
            Ok(0)
        }

        async fn delete_by_workflow_node_id(
            &self,
            _workspace_id: Option<Uuid>,
            _workflow_id: Uuid,
            _trigger_node_id: &str,
        ) -> Result<u64, sqlx::Error> {
            Ok(0)
        }

        async fn update_enabled(
            &self,
            _workspace_id: Option<Uuid>,
            _id: Uuid,
            _enabled: bool,
        ) -> Result<ProviderTrigger, sqlx::Error> {
            Err(sqlx::Error::Protocol("not implemented".into()))
        }

        async fn delete(&self, _workspace_id: Option<Uuid>, _id: Uuid) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn find_by_id(
            &self,
            _workspace_id: Option<Uuid>,
            _id: Uuid,
        ) -> Result<Option<ProviderTrigger>, sqlx::Error> {
            Ok(None)
        }
    }

    #[derive(Default)]
    #[allow(clippy::type_complexity)]
    struct StubWebhookIngressDedupeRepo {
        keys: Mutex<HashSet<(Uuid, String, Vec<u8>, String, i64)>>,
    }

    #[async_trait]
    impl WebhookIngressDedupeRepository for StubWebhookIngressDedupeRepo {
        async fn insert_dedupe_key(
            &self,
            key: &WebhookIngressDedupeKey,
        ) -> Result<bool, sqlx::Error> {
            let mut guard = self.keys.lock().unwrap();
            Ok(guard.insert((
                key.source_id,
                key.event_type.clone(),
                key.payload_sha256.clone(),
                key.signature.clone(),
                key.timestamp_floor.unix_timestamp(),
            )))
        }

        async fn purge_old_dedupe_entries(&self) -> Result<u64, sqlx::Error> {
            Ok(0)
        }
    }

    fn test_config() -> Arc<Config> {
        Arc::new(Config {
            database_url: "postgres://postgres:postgres@localhost:5432/dsentr".into(),
            frontend_origin: "http://localhost:3000".into(),
            admin_origin: "http://localhost:3001".into(),
            oauth: crate::config::OAuthSettings {
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
                token_encryption_key: vec![0; 32],
            },
            github_app: GitHubAppSettings::default(),
            github_webhook_source_id: None,
            api_secrets_encryption_key: vec![1; 32],
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

    fn test_state() -> AppState {
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
            integration_registry: test_integration_registry(),
            http_client: Arc::new(Client::new()),
            config: test_config(),
            worker_id: Arc::new("worker-1".into()),
            worker_lease_seconds: 30,
            jwt_keys: test_jwt_keys(),
        }
    }

    fn sign_github_payload(secret: &str, body: &[u8]) -> String {
        compute_github_signature(secret, body).expect("signature")
    }

    #[tokio::test]
    async fn github_provider_webhook_missing_event_header_returns_bad_request() {
        env::set_var(GITHUB_APP_WEBHOOK_SECRET_ENV, "secret");
        let app_state = test_state();
        let body = br#"{"action":"opened"}"#;
        let signature = sign_github_payload("secret", body);
        let mut headers = HeaderMap::new();
        headers.insert(
            GITHUB_SIGNATURE_HEADER,
            format!("sha256={signature}").parse().unwrap(),
        );

        let response = handle_github_provider_webhook_ingress(
            &app_state,
            Arc::new(StubProviderTriggerRepo::default()),
            &StubWebhookIngressDedupeRepo::default(),
            &headers,
            body,
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn github_provider_webhook_missing_signature_header_returns_bad_request() {
        env::set_var(GITHUB_APP_WEBHOOK_SECRET_ENV, "secret");
        let app_state = test_state();
        let body = br#"{"action":"opened"}"#;
        let mut headers = HeaderMap::new();
        headers.insert(GITHUB_EVENT_HEADER, "issues".parse().unwrap());

        let response = handle_github_provider_webhook_ingress(
            &app_state,
            Arc::new(StubProviderTriggerRepo::default()),
            &StubWebhookIngressDedupeRepo::default(),
            &headers,
            body,
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn github_provider_webhook_invalid_json_returns_bad_request() {
        env::set_var(GITHUB_APP_WEBHOOK_SECRET_ENV, "secret");
        let app_state = test_state();
        let body = br#"{not-json}"#;
        let signature = sign_github_payload("secret", body);
        let mut headers = HeaderMap::new();
        headers.insert(GITHUB_EVENT_HEADER, "issues".parse().unwrap());
        headers.insert(
            GITHUB_SIGNATURE_HEADER,
            format!("sha256={signature}").parse().unwrap(),
        );

        let response = handle_github_provider_webhook_ingress(
            &app_state,
            Arc::new(StubProviderTriggerRepo::default()),
            &StubWebhookIngressDedupeRepo::default(),
            &headers,
            body,
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn github_provider_webhook_ping_skips_json_parsing() {
        env::set_var(GITHUB_APP_WEBHOOK_SECRET_ENV, "secret");
        let app_state = test_state();
        let body = br#"{not-json}"#;
        let signature = sign_github_payload("secret", body);
        let mut headers = HeaderMap::new();
        headers.insert(GITHUB_EVENT_HEADER, "ping".parse().unwrap());
        headers.insert(
            GITHUB_SIGNATURE_HEADER,
            format!("sha256={signature}").parse().unwrap(),
        );

        let response = handle_github_provider_webhook_ingress(
            &app_state,
            Arc::new(StubProviderTriggerRepo::default()),
            &StubWebhookIngressDedupeRepo::default(),
            &headers,
            body,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 2048).await.unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(payload, json!({}));
    }

    #[tokio::test]
    async fn github_provider_webhook_normalizes_event_type_with_action() {
        env::set_var(GITHUB_APP_WEBHOOK_SECRET_ENV, "secret");
        let app_state = test_state();
        let body = br#"{"action":"opened","installation":{"id":42}}"#;
        let signature = sign_github_payload("secret", body);
        let mut headers = HeaderMap::new();
        headers.insert(GITHUB_EVENT_HEADER, "issues".parse().unwrap());
        headers.insert(
            GITHUB_SIGNATURE_HEADER,
            format!("sha256={signature}").parse().unwrap(),
        );

        let repo = Arc::new(StubProviderTriggerRepo::default());
        let response = handle_github_provider_webhook_ingress(
            &app_state,
            repo.clone(),
            &StubWebhookIngressDedupeRepo::default(),
            &headers,
            body,
        )
        .await;

        assert_eq!(response.status(), StatusCode::OK);
        let calls = repo.installation_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "42");
        assert_eq!(calls[0].1, "github.issues.opened");
    }

    #[tokio::test]
    async fn github_provider_webhook_invalid_signature_returns_forbidden() {
        env::set_var(GITHUB_APP_WEBHOOK_SECRET_ENV, "secret");
        let app_state = test_state();
        let body = br#"{"action":"opened"}"#;
        let signature = sign_github_payload("other-secret", body);
        let mut headers = HeaderMap::new();
        headers.insert(GITHUB_EVENT_HEADER, "issues".parse().unwrap());
        headers.insert(
            GITHUB_SIGNATURE_HEADER,
            format!("sha256={signature}").parse().unwrap(),
        );

        let response = handle_github_provider_webhook_ingress(
            &app_state,
            Arc::new(StubProviderTriggerRepo::default()),
            &StubWebhookIngressDedupeRepo::default(),
            &headers,
            body,
        )
        .await;

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn github_provider_webhook_duplicate_delivery_short_circuits() {
        env::set_var(GITHUB_APP_WEBHOOK_SECRET_ENV, "secret");
        let app_state = test_state();
        let body = br#"{"action":"opened","installation":{"id":42}}"#;
        let signature = sign_github_payload("secret", body);
        let mut headers = HeaderMap::new();
        headers.insert(GITHUB_EVENT_HEADER, "issues".parse().unwrap());
        headers.insert(
            GITHUB_SIGNATURE_HEADER,
            format!("sha256={signature}").parse().unwrap(),
        );
        headers.insert(GITHUB_DELIVERY_HEADER, "delivery-1".parse().unwrap());

        let repo = Arc::new(StubProviderTriggerRepo::default());
        let dedupe_repo = StubWebhookIngressDedupeRepo::default();
        let response = handle_github_provider_webhook_ingress(
            &app_state,
            repo.clone(),
            &dedupe_repo,
            &headers,
            body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let invalid_body = br#"{not-json}"#;
        let invalid_signature = sign_github_payload("secret", invalid_body);
        headers.insert(
            GITHUB_SIGNATURE_HEADER,
            format!("sha256={invalid_signature}").parse().unwrap(),
        );
        let response = handle_github_provider_webhook_ingress(
            &app_state,
            repo.clone(),
            &dedupe_repo,
            &headers,
            invalid_body,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);

        let calls = repo.installation_calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
    }
}
