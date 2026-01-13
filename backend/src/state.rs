use crate::config::Config;
use crate::db::{
    stripe_event_log_repository::StripeEventLogRepository, user_repository::UserRepository,
    workflow_repository::WorkflowRepository,
    workspace_connection_repository::WorkspaceConnectionRepository,
    workspace_repository::WorkspaceRepository,
};
use crate::integrations::registry::IntegrationRegistry;
use crate::models::{plan::PlanTier, workspace::WorkspaceBillingCycle};
use crate::services::oauth::{
    account_service::OAuthAccountService, github::service::GitHubOAuthService,
    google::service::GoogleOAuthService, workspace_service::WorkspaceOAuthService,
};
use crate::services::smtp_mailer::Mailer;
use crate::services::stripe::StripeService;
use crate::utils::{
    jwt::{JwtKeyProvider, JwtKeys},
    plan_limits::NormalizedPlanTier,
};
use reqwest::Client;
use sqlx::PgPool;
use std::sync::Arc;
use thiserror::Error;
use time::{OffsetDateTime, Time};
use tracing::{error, warn};
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<dyn UserRepository>,
    pub workflow_repo: Arc<dyn WorkflowRepository>,
    pub workspace_repo: Arc<dyn WorkspaceRepository>,
    pub workspace_connection_repo: Arc<dyn WorkspaceConnectionRepository>,
    pub stripe_event_log_repo: Arc<dyn StripeEventLogRepository>,
    pub db_pool: Arc<PgPool>,
    pub mailer: Arc<dyn Mailer>,
    pub google_oauth: Arc<dyn GoogleOAuthService>,
    pub github_oauth: Arc<dyn GitHubOAuthService + Send + Sync>,
    pub oauth_accounts: Arc<OAuthAccountService>,
    pub workspace_oauth: Arc<WorkspaceOAuthService>,
    pub stripe: Arc<dyn StripeService>,
    pub integration_registry: Arc<IntegrationRegistry>,
    pub http_client: Arc<Client>,
    pub config: Arc<Config>,
    pub worker_id: Arc<String>,
    pub worker_lease_seconds: i32,
    pub jwt_keys: Arc<JwtKeys>,
}

#[derive(Clone, Copy, Debug)]
pub struct WorkspaceRunQuotaTicket {
    workspace_id: Uuid,
    period_start: OffsetDateTime,
    pub run_count: i64,
    pub overage_count: i64,
    pub limit: i64,
    pub overage_incremented: bool,
}

#[derive(Debug, Error)]
pub enum WorkspaceLimitError {
    #[error("Workspace plan required for this action")]
    WorkspacePlanRequired,
    #[error("Workspace member limit reached (max {limit})")]
    MemberLimitReached { limit: i64 },
    #[error("Workspace run limit reached (max {limit})")]
    #[allow(dead_code)]
    RunLimitReached { limit: i64 },
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

impl AppState {
    pub(crate) fn action_manifest_registry(
        &self,
    ) -> &'static crate::engine::actions::ActionManifestRegistry {
        crate::engine::actions::action_manifest_registry()
    }

    pub async fn resolve_plan_tier(
        &self,
        user_id: Uuid,
        claims_plan: Option<&str>,
    ) -> NormalizedPlanTier {
        let from_claims = NormalizedPlanTier::from_option(claims_plan);
        // If claims already show a non-solo plan, still verify against current DB/Stripe to avoid stale auth
        let tier = from_claims;

        // Load current user record
        let user_opt = match self.db.find_public_user_by_id(user_id).await {
            Ok(u) => u,
            Err(err) => {
                error!(%user_id, ?err, "failed to refresh user plan tier from database");
                return tier;
            }
        };

        let Some(user) = user_opt else {
            return tier;
        };
        let db_tier = NormalizedPlanTier::from_option(user.plan.as_deref());

        // If DB says solo, trust it.
        if db_tier.is_solo() {
            return db_tier;
        }

        // Verify if a non-solo plan is still valid:
        // - skip when a checkout is pending (upgrade flow in progress)
        // - otherwise, ensure an active Stripe subscription exists; if not, revert to solo
        let mut has_pending_checkout = false;
        if let Ok(settings) = self.db.get_user_settings(user_id).await {
            if let Some(obj) = settings.as_object() {
                if let Some(b) = obj.get("billing").and_then(|v| v.as_object()) {
                    has_pending_checkout = b
                        .get("pending_checkout")
                        .map(|v| !v.is_null())
                        .unwrap_or(false);
                }
            }
        }

        if !has_pending_checkout {
            if let Ok(Some(customer_id)) = self.db.get_user_stripe_customer_id(user_id).await {
                match self
                    .stripe
                    .get_active_subscription_for_customer(&customer_id)
                    .await
                {
                    Ok(Some(sub)) => {
                        if let (Ok(period_start), Ok(period_end)) = (
                            OffsetDateTime::from_unix_timestamp(sub.current_period_start),
                            OffsetDateTime::from_unix_timestamp(sub.current_period_end),
                        ) {
                            self.sync_owned_workspace_billing_cycles(
                                user_id,
                                &sub.id,
                                period_start,
                                period_end,
                            )
                            .await;
                        }
                        // Active subscription present -> keep workspace tier
                        return db_tier;
                    }
                    Ok(None) => {
                        // No active subscription -> revert personal + owned workspaces to solo
                        if let Err(err) = self.db.update_user_plan(user_id, "solo").await {
                            error!(%user_id, ?err, "failed to revert user plan to solo during tier resolution");
                        } else if let Ok(memberships) =
                            self.workspace_repo.list_memberships_for_user(user_id).await
                        {
                            for m in memberships.into_iter().filter(|m| {
                                m.workspace.owner_id == user_id
                                    && m.workspace.plan.as_str() != "solo"
                            }) {
                                if let Err(err) = self
                                    .workspace_repo
                                    .update_workspace_plan(m.workspace.id, "solo")
                                    .await
                                {
                                    error!(workspace_id=%m.workspace.id, %user_id, ?err, "failed to downgrade workspace to solo during tier resolution");
                                }
                            }
                        }
                        self.clear_owned_workspace_billing_cycles(user_id).await;
                        return NormalizedPlanTier::Solo;
                    }
                    Err(err) => {
                        error!(%user_id, ?err, "failed to verify subscription while resolving plan tier");
                        // Fall through to DB tier since we couldn't verify
                        return db_tier;
                    }
                }
            }
        }

        db_tier
    }

    pub async fn ensure_workspace_plan(
        &self,
        workspace_id: Uuid,
    ) -> Result<PlanTier, WorkspaceLimitError> {
        let plan = self
            .workspace_repo
            .get_plan(workspace_id)
            .await
            .map_err(WorkspaceLimitError::from)?;

        if !matches!(plan, PlanTier::Workspace) {
            return Err(WorkspaceLimitError::WorkspacePlanRequired);
        }

        Ok(plan)
    }

    pub async fn ensure_workspace_can_add_members(
        &self,
        workspace_id: Uuid,
        seats_needed: i64,
    ) -> Result<(), WorkspaceLimitError> {
        self.ensure_workspace_plan(workspace_id).await?;
        let seats_needed = seats_needed.max(0);
        let member_limit = self.config.workspace_member_limit;
        let current_members = self
            .workspace_repo
            .count_members(workspace_id)
            .await
            .map_err(WorkspaceLimitError::from)?;
        let pending_invites = self
            .workspace_repo
            .count_pending_workspace_invitations(workspace_id)
            .await
            .map_err(WorkspaceLimitError::from)?;
        let total_reserved = current_members + pending_invites;

        if total_reserved + seats_needed > member_limit {
            return Err(WorkspaceLimitError::MemberLimitReached {
                limit: member_limit,
            });
        }

        Ok(())
    }

    pub async fn consume_workspace_run_quota(
        &self,
        workspace_id: Uuid,
    ) -> Result<Option<WorkspaceRunQuotaTicket>, WorkspaceLimitError> {
        let plan = self
            .workspace_repo
            .get_plan(workspace_id)
            .await
            .map_err(WorkspaceLimitError::from)?;

        if !matches!(plan, PlanTier::Workspace) {
            return Ok(None);
        }

        let now = OffsetDateTime::now_utc();
        let cycle = self
            .workspace_repo
            .get_workspace_billing_cycle(workspace_id)
            .await
            .map_err(WorkspaceLimitError::from)?;
        let period_start = workspace_quota_period_start(cycle.as_ref(), now);
        let run_limit = self.config.workspace_monthly_run_limit;
        let update = self
            .workspace_repo
            .try_increment_workspace_run_quota(workspace_id, period_start, run_limit)
            .await
            .map_err(WorkspaceLimitError::from)?;

        if !update.allowed {
            warn!(
                %workspace_id,
                run_count = update.run_count,
                overage_count = update.overage_count,
                %run_limit,
                "workspace run usage exceeded limit; recording overage"
            );
        }

        if update.overage_incremented {
            let event_name = match std::env::var("STRIPE_WORKSPACE_METER_EVENT_NAME") {
                Ok(val) if !val.trim().is_empty() => Some(val),
                _ => {
                    warn!(
                        %workspace_id,
                        "workspace meter event name is not configured; skipping usage reporting"
                    );
                    None
                }
            };

            if let Some(event_name) = event_name {
                match self.workspace_repo.find_workspace(workspace_id).await {
                    Ok(Some(workspace)) => {
                        if workspace.stripe_overage_item_id.is_none() {
                            warn!(
                                %workspace_id,
                                "workspace missing overage subscription item id; reporting meter usage without it"
                            );
                        }

                        let customer_id = match self
                            .db
                            .get_user_stripe_customer_id(workspace.owner_id)
                            .await
                        {
                            Ok(Some(id)) => Some(id),
                            Ok(None) => {
                                warn!(
                                    %workspace_id,
                                    "workspace owner is missing stripe customer id; skipping usage reporting"
                                );
                                None
                            }
                            Err(err) => {
                                warn!(
                                    ?err,
                                    %workspace_id,
                                    "failed to load stripe customer id for workspace owner; skipping usage reporting"
                                );
                                None
                            }
                        };

                        if let Some(customer_id) = customer_id {
                            let stripe = self.stripe.clone();
                            let overage_item_id = workspace.stripe_overage_item_id.clone();
                            tokio::spawn(async move {
                                if let Err(err) = stripe
                                    .create_meter_event(
                                        &event_name,
                                        &customer_id,
                                        1,
                                        OffsetDateTime::now_utc().unix_timestamp(),
                                        overage_item_id.as_deref(),
                                    )
                                    .await
                                {
                                    warn!(?err, %workspace_id, "failed to report overage usage");
                                }
                            });
                        }
                    }
                    Ok(None) => {
                        warn!(
                            %workspace_id,
                            "workspace not found while reporting overage usage; skipping meter event"
                        );
                    }
                    Err(err) => {
                        warn!(
                            ?err,
                            %workspace_id,
                            "failed to load workspace while reporting overage usage"
                        );
                    }
                }
            }
        }

        Ok(Some(WorkspaceRunQuotaTicket {
            workspace_id,
            period_start,
            run_count: update.run_count,
            overage_count: update.overage_count,
            limit: run_limit,
            overage_incremented: update.overage_incremented,
        }))
    }

    pub async fn release_workspace_run_quota(
        &self,
        ticket: WorkspaceRunQuotaTicket,
    ) -> Result<(), WorkspaceLimitError> {
        self.workspace_repo
            .release_workspace_run_quota(
                ticket.workspace_id,
                ticket.period_start,
                ticket.overage_incremented,
            )
            .await
            .map_err(WorkspaceLimitError::from)
    }

    pub async fn sync_owned_workspace_billing_cycles(
        &self,
        owner_id: Uuid,
        subscription_id: &str,
        period_start: OffsetDateTime,
        period_end: OffsetDateTime,
    ) {
        match self
            .workspace_repo
            .list_memberships_for_user(owner_id)
            .await
        {
            Ok(memberships) => {
                for membership in memberships.into_iter().filter(|m| {
                    m.workspace.owner_id == owner_id
                        && !NormalizedPlanTier::from_option(Some(m.workspace.plan.as_str()))
                            .is_solo()
                }) {
                    if let Err(err) = self
                        .workspace_repo
                        .upsert_workspace_billing_cycle(
                            membership.workspace.id,
                            subscription_id,
                            period_start,
                            period_end,
                        )
                        .await
                    {
                        warn!(
                            ?err,
                            workspace_id = %membership.workspace.id,
                            %owner_id,
                            "failed to persist workspace billing cycle window"
                        );
                    }
                }
            }
            Err(err) => {
                warn!(
                    ?err,
                    %owner_id,
                    "failed to list workspaces while syncing billing cycles"
                );
            }
        }
    }

    pub async fn clear_owned_workspace_billing_cycles(&self, owner_id: Uuid) {
        match self
            .workspace_repo
            .list_memberships_for_user(owner_id)
            .await
        {
            Ok(memberships) => {
                for membership in memberships
                    .into_iter()
                    .filter(|m| m.workspace.owner_id == owner_id)
                {
                    if let Err(err) = self
                        .workspace_repo
                        .clear_workspace_billing_cycle(membership.workspace.id)
                        .await
                    {
                        warn!(
                            ?err,
                            workspace_id = %membership.workspace.id,
                            %owner_id,
                            "failed to clear workspace billing cycle window"
                        );
                    }
                }
            }
            Err(err) => {
                warn!(
                    ?err,
                    %owner_id,
                    "failed to list workspaces while clearing billing cycles"
                );
            }
        }
    }
}

pub(crate) fn workspace_quota_period_start(
    cycle: Option<&WorkspaceBillingCycle>,
    now: OffsetDateTime,
) -> OffsetDateTime {
    if let Some(cycle) = cycle {
        if now >= cycle.current_period_end {
            cycle.current_period_end
        } else {
            cycle.current_period_start
        }
    } else {
        now.replace_day(1)
            .unwrap_or(now)
            .replace_time(Time::MIDNIGHT)
    }
}

impl JwtKeyProvider for AppState {
    fn jwt_keys(&self) -> &JwtKeys {
        self.jwt_keys.as_ref()
    }

    fn jwt_issuer(&self) -> &str {
        &self.config.jwt_issuer
    }

    fn jwt_audience(&self) -> &str {
        &self.config.jwt_audience
    }
}

// Re-export the StripeService trait (and mock for tests) for convenience in helpers/tests.
#[allow(unused_imports)]
pub use crate::services::stripe::{MockStripeService, StripeService as StripeServiceTrait};

#[cfg(test)]
pub fn test_integration_registry() -> Arc<IntegrationRegistry> {
    Arc::new(
        crate::integrations::build_integration_registry()
            .expect("test integration registry should build"),
    )
}

#[cfg(test)]
pub fn test_pg_pool() -> Arc<PgPool> {
    Arc::new(
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://postgres:postgres@localhost/dsentr")
            .expect("lazy pg pool for tests"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::mock_db::{
        MockDb, NoopWorkflowRepository, NoopWorkspaceRepository,
        StaticWorkspaceMembershipRepository,
    };
    use crate::db::mock_stripe_event_log_repository::MockStripeEventLogRepository;
    use crate::db::workspace_connection_repository::NoopWorkspaceConnectionRepository;
    use crate::models::user::{OauthProvider, User, UserRole};
    use crate::models::workspace::WorkspaceBillingCycle;
    use crate::services::{
        oauth::{
            account_service::OAuthAccountService, github::mock_github_oauth::MockGitHubOAuth,
            google::mock_google_oauth::MockGoogleOAuth,
        },
        smtp_mailer::{MailError, Mailer, SmtpConfig},
    };
    use async_trait::async_trait;
    use reqwest::Client;
    use std::sync::Arc;
    use time::{Duration, OffsetDateTime};
    use tokio::time::sleep;

    #[derive(Default)]
    struct NoopMailer;

    #[async_trait]
    impl Mailer for NoopMailer {
        async fn send_verification_email(&self, _: &str, _: &str) -> Result<(), MailError> {
            Ok(())
        }

        async fn send_reset_email(&self, _: &str, _: &str) -> Result<(), MailError> {
            Ok(())
        }

        async fn send_email_generic(&self, _: &str, _: &str, _: &str) -> Result<(), MailError> {
            Ok(())
        }

        async fn send_email_with_config(
            &self,
            _: &SmtpConfig,
            _: &[String],
            _: &str,
            _: &str,
        ) -> Result<(), MailError> {
            Ok(())
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    fn build_state_with_user(plan: Option<&str>) -> (AppState, Uuid) {
        let user_id = Uuid::new_v4();
        let stripe_customer_id = if plan == Some("workspace") {
            Some("cus_test_meter".to_string())
        } else {
            None
        };
        let db = MockDb {
            find_user_result: Some(User {
                id: user_id,
                email: "user@example.com".into(),
                password_hash: String::new(),
                first_name: "Plan".into(),
                last_name: "Tester".into(),
                role: Some(UserRole::User),
                plan: plan.map(|p| p.to_string()),
                company_name: None,
                stripe_customer_id: stripe_customer_id.clone(),
                oauth_provider: Some(OauthProvider::Email),
                onboarded_at: Some(OffsetDateTime::now_utc()),
                created_at: OffsetDateTime::now_utc(),
                is_verified: true,
            }),
            stripe_customer_id: std::sync::Mutex::new(stripe_customer_id),
            ..Default::default()
        };

        let config = Arc::new(Config {
            database_url: String::new(),
            frontend_origin: "http://localhost".into(),
            admin_origin: "http://localhost".into(),
            oauth: crate::config::OAuthSettings {
                google: crate::config::OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                microsoft: crate::config::OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                slack: crate::config::OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                asana: crate::config::OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                notion: crate::config::OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                bitly: crate::config::OAuthProviderConfig {
                    client_id: "stub".into(),
                    client_secret: "stub".into(),
                    redirect_uri: "http://localhost".into(),
                },
                token_encryption_key: vec![0u8; 32],
            },
            stripe: crate::config::StripeSettings {
                client_id: "stub".into(),
                secret_key: "stub".into(),
                webhook_secret: "0123456789abcdef0123456789ABCDEF".into(),
            },
            api_secrets_encryption_key: vec![2u8; 32],
            auth_cookie_secure: true,
            jwt_issuer: "test-issuer".into(),
            jwt_audience: "test-audience".into(),
            workspace_member_limit: crate::config::DEFAULT_WORKSPACE_MEMBER_LIMIT,
            workspace_monthly_run_limit: crate::config::DEFAULT_WORKSPACE_MONTHLY_RUN_LIMIT,
            runaway_limit_5min: crate::config::RUNAWAY_LIMIT_5MIN,
            webhook_ingress_dedupe_mode: crate::config::WebhookIngressDedupeMode::Off,
            webhook_verification_body_fields: vec![],
            webhook_verification_header_fields: vec![],
            webhook_event_type_fields: vec!["event_type".to_string(), "type".to_string()],
        });

        let state = AppState {
            db: Arc::new(db),
            workflow_repo: Arc::new(NoopWorkflowRepository),
            workspace_repo: Arc::new(NoopWorkspaceRepository),
            workspace_connection_repo: Arc::new(NoopWorkspaceConnectionRepository),
            stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
            db_pool: test_pg_pool(),
            mailer: Arc::new(NoopMailer),
            google_oauth: Arc::new(MockGoogleOAuth::default()),
            github_oauth: Arc::new(MockGitHubOAuth::default()),
            oauth_accounts: OAuthAccountService::test_stub(),
            workspace_oauth: WorkspaceOAuthService::test_stub(),
            stripe: Arc::new(crate::services::stripe::MockStripeService::new()),
            integration_registry: test_integration_registry(),
            http_client: Arc::new(Client::new()),
            config,
            worker_id: Arc::new("test-worker".into()),
            worker_lease_seconds: 30,
            jwt_keys: Arc::new(
                JwtKeys::from_secret("0123456789abcdef0123456789abcdef")
                    .expect("test JWT secret should be valid"),
            ),
        };

        (state, user_id)
    }

    #[tokio::test]
    async fn resolve_plan_tier_downgrades_when_no_active_subscription() {
        let (state, user_id) = build_state_with_user(Some("workspace"));
        let tier = state.resolve_plan_tier(user_id, Some("solo")).await;
        assert_eq!(tier, NormalizedPlanTier::Solo);
    }

    #[tokio::test]
    async fn resolve_plan_tier_uses_database_plan_for_upgraded_user() {
        let user_id = Uuid::new_v4();

        // Build test DB that says workspace plan but has no Stripe customer id
        let db = MockDb {
            find_user_result: Some(User {
                id: user_id,
                email: "user@example.com".into(),
                password_hash: String::new(),
                first_name: "Plan".into(),
                last_name: "Tester".into(),
                role: Some(UserRole::User),
                plan: Some("workspace".into()),
                company_name: None,
                stripe_customer_id: None, // << key fix
                oauth_provider: Some(OauthProvider::Email),
                onboarded_at: Some(OffsetDateTime::now_utc()),
                created_at: OffsetDateTime::now_utc(),
                is_verified: true,
            }),
            stripe_customer_id: std::sync::Mutex::new(None),
            ..Default::default()
        };

        // Build AppState, replacing db only
        let (mut state, _) = build_state_with_user(None);
        state.db = Arc::new(db);

        let tier = state.resolve_plan_tier(user_id, Some("solo")).await;
        assert_eq!(tier, NormalizedPlanTier::Workspace);
    }

    #[tokio::test]
    async fn resolve_plan_tier_falls_back_to_claims_when_user_missing() {
        let (state, user_id) = build_state_with_user(None);
        let tier = state.resolve_plan_tier(user_id, Some("solo")).await;
        assert_eq!(tier, NormalizedPlanTier::Solo);
    }

    #[test]
    fn workspace_quota_period_start_uses_billing_cycle_window() {
        let cycle_start = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let cycle_end = cycle_start + Duration::days(30);
        let cycle = WorkspaceBillingCycle {
            workspace_id: Uuid::new_v4(),
            stripe_subscription_id: "sub_test".into(),
            current_period_start: cycle_start,
            current_period_end: cycle_end,
            synced_at: cycle_start,
        };
        let now = cycle_start + Duration::days(5);
        let start = super::workspace_quota_period_start(Some(&cycle), now);
        assert_eq!(start, cycle_start);
    }

    #[test]
    fn workspace_quota_period_start_rolls_forward_after_cycle_end() {
        let cycle_start = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let cycle_end = cycle_start + Duration::days(30);
        let cycle = WorkspaceBillingCycle {
            workspace_id: Uuid::new_v4(),
            stripe_subscription_id: "sub_test".into(),
            current_period_start: cycle_start,
            current_period_end: cycle_end,
            synced_at: cycle_start,
        };
        let after_cycle = cycle_end + Duration::seconds(10);
        let start = super::workspace_quota_period_start(Some(&cycle), after_cycle);
        assert_eq!(start, cycle_end);
    }

    #[tokio::test]
    async fn consume_workspace_run_quota_reports_overage_usage() {
        std::env::set_var("STRIPE_WORKSPACE_METER_EVENT_NAME", "workspace.run.overage");
        let workspace_id = Uuid::new_v4();
        let repo: Arc<StaticWorkspaceMembershipRepository> =
            Arc::new(StaticWorkspaceMembershipRepository::with_run_limit(1));
        repo.set_stripe_overage_item_id(workspace_id, Some("si_overage"))
            .await
            .unwrap();

        let stripe = Arc::new(crate::services::stripe::MockStripeService::new());
        let (state, user_id) = build_state_with_user(Some("workspace"));
        repo.set_workspace_owner(workspace_id, user_id);
        let state = AppState {
            workspace_repo: repo.clone() as Arc<dyn WorkspaceRepository>,
            stripe: stripe.clone(),
            ..state
        };

        // First run is within limit; no usage report
        let first = state
            .consume_workspace_run_quota(workspace_id)
            .await
            .unwrap()
            .unwrap();
        assert!(!first.overage_incremented);
        sleep(std::time::Duration::from_millis(5)).await;
        assert!(stripe.meter_events.lock().unwrap().is_empty());

        // Second run exceeds the limit and should emit one usage record
        let second = state
            .consume_workspace_run_quota(workspace_id)
            .await
            .unwrap()
            .unwrap();
        assert!(second.overage_incremented);
        sleep(std::time::Duration::from_millis(5)).await;
        let events = stripe.meter_events.lock().unwrap().clone();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_name, "workspace.run.overage");
        assert_eq!(events[0].stripe_customer_id, "cus_test_meter");
        assert_eq!(events[0].value, 1);
        assert_eq!(
            events[0].subscription_item_id.as_deref(),
            Some("si_overage")
        );
    }

    #[tokio::test]
    async fn consume_workspace_run_quota_skips_usage_reporting_for_solo_plan() {
        std::env::set_var("STRIPE_WORKSPACE_METER_EVENT_NAME", "workspace.run.overage");
        let workspace_id = Uuid::new_v4();
        let repo: Arc<StaticWorkspaceMembershipRepository> = Arc::new(
            StaticWorkspaceMembershipRepository::with_plan(PlanTier::Solo),
        );
        let stripe = Arc::new(crate::services::stripe::MockStripeService::new());
        let (state, user_id) = build_state_with_user(Some("workspace"));
        repo.set_workspace_owner(workspace_id, user_id);
        let state = AppState {
            workspace_repo: repo.clone() as Arc<dyn WorkspaceRepository>,
            stripe: stripe.clone(),
            ..state
        };

        let ticket = state
            .consume_workspace_run_quota(workspace_id)
            .await
            .unwrap();
        assert!(ticket.is_none());
        sleep(std::time::Duration::from_millis(5)).await;
        assert!(stripe.meter_events.lock().unwrap().is_empty());
    }
}
