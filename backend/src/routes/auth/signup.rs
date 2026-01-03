use axum::{
    extract::{Json, State},
    response::{IntoResponse, Response},
};
use rand::{distr::Alphanumeric, Rng};
extern crate serde;
use time::{Duration, OffsetDateTime};

use crate::utils::password::hash_password;
use crate::{
    models::{
        signup::{SignupInviteDecision, SignupPayload},
        user::OauthProvider,
        workspace::{WorkspaceRole, INVITATION_STATUS_PENDING, WORKSPACE_PLAN_SOLO},
    },
    responses::JsonResponse,
    routes::plan_limits::workspace_limit_error_response,
    state,
};

const INVALID_INVITE_MESSAGE: &str = "Invalid or expired invite link";
const TERMS_OF_SERVICE_VERSION: &str = "1.0";
const TERMS_ACCEPTANCE_REQUIRED_MESSAGE: &str =
    "You must accept the latest Terms of Service to create an account.";

fn default_workspace_name(payload: &SignupPayload) -> String {
    if let Some(company) = payload
        .company_name
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    {
        return format!("{} Workspace", company);
    }

    let first = payload.first_name.trim();
    if !first.is_empty() {
        let suffix = if first.ends_with('s') { "'" } else { "'s" };
        return format!("{}{} Workspace", first, suffix);
    }

    "My Workspace".to_string()
}

pub async fn handle_signup(
    State(state): State<state::AppState>,
    Json(payload): Json<SignupPayload>,
) -> Response {
    let repo = &state.db;
    let workspace_repo = &state.workspace_repo;

    let mut payload = payload;
    payload.email = payload.email.trim().to_lowercase();

    let accepted_terms_version = payload
        .accepted_terms_version
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());

    if accepted_terms_version.as_deref() != Some(TERMS_OF_SERVICE_VERSION) {
        return JsonResponse::bad_request(TERMS_ACCEPTANCE_REQUIRED_MESSAGE).into_response();
    }

    payload.accepted_terms_version = accepted_terms_version;

    if let Ok(true) = repo.is_email_taken(&payload.email).await {
        return JsonResponse::conflict("User already registered").into_response();
    }

    let invite_token = payload
        .invite_token
        .as_ref()
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty());
    let invite_decision = payload
        .invite_decision
        .unwrap_or(SignupInviteDecision::Join);

    let mut invite_record = None;
    if let Some(token) = invite_token.as_ref() {
        match workspace_repo.find_invitation_by_token(token).await {
            Ok(Some(invite)) => {
                let now = OffsetDateTime::now_utc();
                let email_mismatch = !invite.email.eq_ignore_ascii_case(&payload.email);
                if invite.status != INVITATION_STATUS_PENDING
                    || invite.revoked_at.is_some()
                    || invite.accepted_at.is_some()
                    || invite.declined_at.is_some()
                    || invite.expires_at <= now
                    || email_mismatch
                {
                    return JsonResponse::bad_request(INVALID_INVITE_MESSAGE).into_response();
                }
                invite_record = Some(invite);
            }
            Ok(None) => {
                return JsonResponse::bad_request(INVALID_INVITE_MESSAGE).into_response();
            }
            Err(err) => {
                eprintln!("Failed to load invite: {:?}", err);
                return JsonResponse::server_error("Could not validate invitation").into_response();
            }
        }
    }

    let password_hash = match hash_password(&payload.password) {
        Ok(hash) => hash,
        Err(_) => return JsonResponse::server_error("Password hashing failed").into_response(),
    };

    let provider = payload
        .provider
        .as_ref()
        .copied()
        .unwrap_or(OauthProvider::Email);
    let user_id = match repo.create_user(&payload, &password_hash, provider).await {
        Ok(id) => id,
        Err(e) => {
            eprintln!("Failed to insert user: {:?}", e);
            return JsonResponse::server_error("Could not create user").into_response();
        }
    };

    let token: String = rand::rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();

    let terms_accepted_at = OffsetDateTime::now_utc();
    if let Err(err) = repo
        .record_terms_acceptance(user_id, TERMS_OF_SERVICE_VERSION, terms_accepted_at)
        .await
    {
        eprintln!("Failed to record terms acceptance: {:?}", err);
        let _ = repo.cleanup_user_and_token(user_id, &token).await;
        return JsonResponse::server_error("Could not record terms acceptance").into_response();
    }

    let expires_at = terms_accepted_at + Duration::hours(24);

    if invite_record.is_none() || matches!(invite_decision, SignupInviteDecision::Decline) {
        let workspace_name = default_workspace_name(&payload);
        let workspace = match workspace_repo
            .create_workspace(&workspace_name, user_id, WORKSPACE_PLAN_SOLO)
            .await
        {
            Ok(workspace) => workspace,
            Err(err) => {
                eprintln!("Failed to create default workspace: {:?}", err);
                let _ = repo.cleanup_user_and_token(user_id, &token).await;
                return JsonResponse::server_error("Could not provision workspace").into_response();
            }
        };

        if let Err(err) = workspace_repo
            .add_member(workspace.id, user_id, WorkspaceRole::Owner)
            .await
        {
            eprintln!("Failed to attach owner membership: {:?}", err);
            let _ = repo.cleanup_user_and_token(user_id, &token).await;
            return JsonResponse::server_error("Could not provision workspace").into_response();
        }
    }

    if let Some(invite) = invite_record.clone() {
        match invite_decision {
            SignupInviteDecision::Join => {
                if let Err(err) = state
                    .ensure_workspace_can_add_members(invite.workspace_id, 0)
                    .await
                {
                    return workspace_limit_error_response(err);
                }

                if let Err(err) = workspace_repo
                    .add_member(invite.workspace_id, user_id, invite.role)
                    .await
                {
                    eprintln!("Failed to add invited member: {:?}", err);
                    let _ = repo.cleanup_user_and_token(user_id, &token).await;
                    return JsonResponse::server_error("Could not attach workspace membership")
                        .into_response();
                }
                if let Err(err) = workspace_repo.mark_invitation_accepted(invite.id).await {
                    eprintln!("Failed to mark invite accepted: {:?}", err);
                }
            }
            SignupInviteDecision::Decline => {
                if let Err(err) = workspace_repo.mark_invitation_declined(invite.id).await {
                    eprintln!("Failed to mark invite declined: {:?}", err);
                }
            }
        }
    }

    if let Err(e) = repo
        .insert_verification_token(user_id, &token, expires_at)
        .await
    {
        eprintln!("Failed to insert verification token: {:?}", e);
        let _ = repo.cleanup_user_and_token(user_id, &token).await;
        return JsonResponse::server_error("Could not create verification token").into_response();
    }

    if let Err(err) = state
        .mailer
        .send_verification_email(&payload.email, &token)
        .await
    {
        eprintln!("Failed to send verification email: {}", err);
        let _ = repo.cleanup_user_and_token(user_id, &token).await;
        return JsonResponse::server_error("Failed to send verification email").into_response();
    }

    JsonResponse::success("User created. Check your email to verify your account.").into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tower::ServiceExt;
    use uuid::Uuid;

    type MembershipRecords = Vec<(Uuid, Uuid, WorkspaceRole)>;
    type WorkspaceRecord = (Vec<Workspace>, MembershipRecords, Vec<Uuid>, Vec<Uuid>);

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
            workspace_repository::{
                WorkspaceRepository, WorkspaceRunQuotaUpdate, WorkspaceRunUsage,
            },
        },
        models::{
            plan::PlanTier,
            signup::{SignupInviteDecision, SignupPayload},
            user::{OauthProvider, PublicUser, User, UserRole},
            workspace::{
                Workspace, WorkspaceBillingCycle, WorkspaceInvitation, WorkspaceMembershipSummary,
                WorkspaceRole, INVITATION_STATUS_PENDING, WORKSPACE_PLAN_SOLO,
            },
        },
        services::{
            oauth::{
                account_service::OAuthAccountService, github::mock_github_oauth::MockGitHubOAuth,
                google::mock_google_oauth::MockGoogleOAuth,
                workspace_service::WorkspaceOAuthService,
            },
            smtp_mailer::{Mailer, MockMailer},
        },
        state::{test_pg_pool, AppState},
        utils::{jwt::JwtKeys, plan_limits::NormalizedPlanTier},
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
        })
    }

    struct MockRepo {
        email_taken: bool,
        fail_create_user: bool,
        fail_insert_token: bool,
        fail_record_terms: bool,
        cleaned_up: Arc<Mutex<bool>>,
        terms_recorded: Arc<Mutex<bool>>,
    }

    #[async_trait]
    impl UserRepository for MockRepo {
        async fn is_email_taken(&self, _email: &str) -> Result<bool, sqlx::Error> {
            Ok(self.email_taken)
        }

        async fn create_user(
            &self,
            _payload: &SignupPayload,
            _hashed_password: &str,
            _provider: OauthProvider,
        ) -> Result<Uuid, sqlx::Error> {
            if self.fail_create_user {
                Err(sqlx::Error::RowNotFound)
            } else {
                Ok(Uuid::new_v4())
            }
        }

        async fn insert_verification_token(
            &self,
            _user_id: Uuid,
            _token: &str,
            _expires_at: OffsetDateTime,
        ) -> Result<(), sqlx::Error> {
            if self.fail_insert_token {
                Err(sqlx::Error::RowNotFound)
            } else {
                Ok(())
            }
        }

        async fn record_terms_acceptance(
            &self,
            _user_id: Uuid,
            _terms_version: &str,
            _accepted_at: OffsetDateTime,
        ) -> Result<(), sqlx::Error> {
            if self.fail_record_terms {
                Err(sqlx::Error::RowNotFound)
            } else {
                *self.terms_recorded.lock().unwrap() = true;
                Ok(())
            }
        }

        async fn cleanup_user_and_token(
            &self,
            _user_id: Uuid,
            _token: &str,
        ) -> Result<(), sqlx::Error> {
            *self.cleaned_up.lock().unwrap() = true;
            Ok(())
        }

        // === Stubbed methods below ===

        async fn find_user_id_by_email(&self, _email: &str) -> Result<Option<UserId>, sqlx::Error> {
            Ok(Some(UserId { id: Uuid::new_v4() }))
        }

        async fn insert_password_reset_token(
            &self,
            _user_id: Uuid,
            _token: &str,
            _expires_at: OffsetDateTime,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn find_user_by_email(&self, _email: &str) -> Result<Option<User>, sqlx::Error> {
            Ok(Some(User {
                id: Uuid::new_v4(),
                email: "test@example.com".into(),
                password_hash: "hashed".into(),
                first_name: "Test".into(),
                last_name: "User".into(),
                role: Some(UserRole::User),
                created_at: OffsetDateTime::now_utc(),
                plan: None,
                company_name: None,
                stripe_customer_id: None,
                oauth_provider: Some(OauthProvider::Email),
                onboarded_at: None,
                is_verified: false,
            }))
        }

        async fn create_user_with_oauth(
            &self,
            _email: &str,
            _first_name: &str,
            _last_name: &str,
            _provider: OauthProvider,
        ) -> Result<User, sqlx::Error> {
            Ok(User {
                id: Uuid::new_v4(),
                email: "test@example.com".into(),
                password_hash: "hashed".into(),
                first_name: "Test".into(),
                last_name: "User".into(),
                role: Some(UserRole::User),
                created_at: OffsetDateTime::now_utc(),
                plan: None,
                company_name: None,
                stripe_customer_id: None,
                oauth_provider: Some(OauthProvider::Email),
                onboarded_at: None,
                is_verified: true,
            })
        }

        async fn find_public_user_by_id(
            &self,
            _user_id: Uuid,
        ) -> Result<Option<PublicUser>, sqlx::Error> {
            Ok(Some(PublicUser {
                id: Uuid::new_v4(),
                email: "test@example.com".into(),
                first_name: "Test".into(),
                last_name: "User".into(),
                plan: None,
                company_name: None,
                role: Some(UserRole::User),
                oauth_provider: Some(OauthProvider::Email),
                onboarded_at: None,
            }))
        }

        async fn verify_password_reset_token(
            &self,
            _token: &str,
        ) -> Result<Option<Uuid>, sqlx::Error> {
            Ok(Some(Uuid::new_v4()))
        }

        async fn update_user_password(
            &self,
            _user_id: Uuid,
            _hashed_password: &str,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn mark_password_reset_token_used(&self, _token: &str) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn mark_verification_token_used(
            &self,
            _token: &str,
            _: OffsetDateTime,
        ) -> Result<Option<Uuid>, sqlx::Error> {
            Ok(Some(Uuid::new_v4()))
        }

        async fn set_user_verified(&self, _user_id: Uuid) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn insert_early_access_email(&self, _email: &str) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn get_user_settings(&self, _: Uuid) -> Result<serde_json::Value, sqlx::Error> {
            Ok(serde_json::Value::Object(Default::default()))
        }

        async fn update_user_settings(
            &self,
            _: Uuid,
            _: serde_json::Value,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn update_user_plan(&self, _: Uuid, _: &str) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn mark_workspace_onboarded(
            &self,
            _: Uuid,
            _: OffsetDateTime,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn get_user_stripe_customer_id(
            &self,
            _: Uuid,
        ) -> Result<Option<String>, sqlx::Error> {
            Ok(None)
        }

        async fn set_user_stripe_customer_id(&self, _: Uuid, _: &str) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn find_user_id_by_stripe_customer_id(
            &self,
            _customer_id: &str,
        ) -> Result<Option<Uuid>, sqlx::Error> {
            Ok(None)
        }

        async fn clear_pending_checkout_with_error(
            &self,
            _user_id: Uuid,
            _message: &str,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn create_issue_report(
            &self,
            _report: crate::models::issue_report::NewIssueReport,
        ) -> Result<Uuid, sqlx::Error> {
            Ok(Uuid::new_v4())
        }

        async fn upsert_account_deletion_token(
            &self,
            _user_id: Uuid,
            _token: &str,
            _expires_at: OffsetDateTime,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn get_account_deletion_context(
            &self,
            _token: &str,
        ) -> Result<Option<crate::models::account_deletion::AccountDeletionContext>, sqlx::Error>
        {
            Ok(None)
        }

        async fn collect_account_deletion_counts(
            &self,
            _user_id: Uuid,
        ) -> Result<crate::models::account_deletion::AccountDeletionCounts, sqlx::Error> {
            Ok(Default::default())
        }

        async fn finalize_account_deletion(
            &self,
            _token: &str,
            _audit: crate::models::account_deletion::AccountDeletionAuditInsert,
        ) -> Result<(), sqlx::Error> {
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

    #[derive(Default)]
    struct RecordingWorkspaceRepo {
        invite: Mutex<Option<WorkspaceInvitation>>,
        created: Arc<Mutex<Vec<Workspace>>>,
        add_calls: Arc<Mutex<MembershipRecords>>,
        accepted: Arc<Mutex<Vec<Uuid>>>,
        declined: Arc<Mutex<Vec<Uuid>>>,
        fail_create_workspace: bool,
        fail_join_membership: bool,
        run_usage: Mutex<HashMap<(Uuid, i64), (i64, i64)>>,
        billing_cycles: Mutex<HashMap<Uuid, WorkspaceBillingCycle>>,
    }

    impl RecordingWorkspaceRepo {
        fn with_invite(invite: WorkspaceInvitation) -> Self {
            Self {
                invite: Mutex::new(Some(invite)),
                ..Default::default()
            }
        }

        fn record(&self) -> WorkspaceRecord {
            (
                self.created.lock().unwrap().clone(),
                self.add_calls.lock().unwrap().clone(),
                self.accepted.lock().unwrap().clone(),
                self.declined.lock().unwrap().clone(),
            )
        }
    }

    #[async_trait]
    impl WorkspaceRepository for RecordingWorkspaceRepo {
        async fn create_workspace(
            &self,
            name: &str,
            created_by: Uuid,
            plan: &str,
        ) -> Result<Workspace, sqlx::Error> {
            if self.fail_create_workspace {
                return Err(sqlx::Error::Protocol("fail_create_workspace".into()));
            }
            let workspace = Workspace {
                id: Uuid::new_v4(),
                name: name.to_string(),
                created_by,
                owner_id: created_by,
                plan: plan.to_string(),
                stripe_overage_item_id: None,
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                deleted_at: None,
            };
            self.created.lock().unwrap().push(workspace.clone());
            Ok(workspace)
        }

        async fn update_workspace_name(
            &self,
            workspace_id: Uuid,
            name: &str,
        ) -> Result<Workspace, sqlx::Error> {
            Ok(Workspace {
                id: workspace_id,
                name: name.to_string(),
                created_by: Uuid::nil(),
                owner_id: Uuid::nil(),
                plan: WORKSPACE_PLAN_SOLO.to_string(),
                stripe_overage_item_id: None,
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                deleted_at: None,
            })
        }

        async fn update_workspace_plan(
            &self,
            workspace_id: Uuid,
            plan: &str,
        ) -> Result<Workspace, sqlx::Error> {
            Ok(Workspace {
                id: workspace_id,
                name: String::new(),
                created_by: Uuid::nil(),
                owner_id: Uuid::nil(),
                plan: plan.to_string(),
                stripe_overage_item_id: None,
                created_at: OffsetDateTime::now_utc(),
                updated_at: OffsetDateTime::now_utc(),
                deleted_at: None,
            })
        }

        async fn get_plan(&self, workspace_id: Uuid) -> Result<PlanTier, sqlx::Error> {
            let created = self.created.lock().unwrap();
            let plan = created
                .iter()
                .find(|workspace| workspace.id == workspace_id)
                .map(|workspace| workspace.plan.clone());

            if let Some(plan) = plan {
                let normalized = NormalizedPlanTier::from_option(Some(plan.as_str()));
                Ok(PlanTier::from(normalized))
            } else {
                Ok(PlanTier::Workspace)
            }
        }

        async fn find_workspace(
            &self,
            _workspace_id: Uuid,
        ) -> Result<Option<Workspace>, sqlx::Error> {
            Ok(None)
        }

        async fn set_stripe_overage_item_id(
            &self,
            _workspace_id: Uuid,
            _subscription_item_id: Option<&str>,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn get_stripe_overage_item_id(
            &self,
            _workspace_id: Uuid,
        ) -> Result<Option<String>, sqlx::Error> {
            Ok(None)
        }

        async fn add_member(
            &self,
            workspace_id: Uuid,
            user_id: Uuid,
            role: WorkspaceRole,
        ) -> Result<(), sqlx::Error> {
            let should_fail = self.fail_join_membership
                && self
                    .invite
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|invite| invite.workspace_id == workspace_id)
                    .unwrap_or(false);
            if should_fail {
                return Err(sqlx::Error::Protocol("fail_add_member".into()));
            }
            self.add_calls
                .lock()
                .unwrap()
                .push((workspace_id, user_id, role));
            Ok(())
        }

        async fn set_member_role(
            &self,
            _workspace_id: Uuid,
            _user_id: Uuid,
            _role: WorkspaceRole,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn remove_member(
            &self,
            _workspace_id: Uuid,
            _user_id: Uuid,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn leave_workspace(
            &self,
            _workspace_id: Uuid,
            _user_id: Uuid,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn revoke_member(
            &self,
            _workspace_id: Uuid,
            _member_id: Uuid,
            _revoked_by: Uuid,
            _reason: Option<&str>,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn list_members(
            &self,
            _workspace_id: Uuid,
        ) -> Result<Vec<crate::models::workspace::WorkspaceMember>, sqlx::Error> {
            Ok(vec![])
        }

        async fn count_members(&self, workspace_id: Uuid) -> Result<i64, sqlx::Error> {
            let members = self.add_calls.lock().unwrap();
            let count = members
                .iter()
                .filter(|(ws_id, _, _)| *ws_id == workspace_id)
                .count();
            Ok(count as i64)
        }

        async fn count_pending_workspace_invitations(
            &self,
            workspace_id: Uuid,
        ) -> Result<i64, sqlx::Error> {
            let invite = self.invite.lock().unwrap();
            let count = invite
                .as_ref()
                .filter(|invite| {
                    invite.workspace_id == workspace_id
                        && invite.status == crate::models::workspace::INVITATION_STATUS_PENDING
                        && invite.expires_at > OffsetDateTime::now_utc()
                })
                .map(|_| 1)
                .unwrap_or(0);
            Ok(count)
        }

        async fn is_member(
            &self,
            _workspace_id: Uuid,
            _user_id: Uuid,
        ) -> Result<bool, sqlx::Error> {
            Ok(true)
        }

        async fn list_memberships_for_user(
            &self,
            _user_id: Uuid,
        ) -> Result<Vec<WorkspaceMembershipSummary>, sqlx::Error> {
            Ok(vec![])
        }

        async fn list_user_workspaces(
            &self,
            _user_id: Uuid,
        ) -> Result<Vec<WorkspaceMembershipSummary>, sqlx::Error> {
            Ok(vec![])
        }

        async fn create_workspace_invitation(
            &self,
            _workspace_id: Uuid,
            _email: &str,
            _role: WorkspaceRole,
            _token: &str,
            _expires_at: OffsetDateTime,
            _created_by: Uuid,
        ) -> Result<WorkspaceInvitation, sqlx::Error> {
            unimplemented!()
        }

        async fn list_workspace_invitations(
            &self,
            _workspace_id: Uuid,
        ) -> Result<Vec<WorkspaceInvitation>, sqlx::Error> {
            Ok(vec![])
        }

        async fn revoke_workspace_invitation(&self, _invite_id: Uuid) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn find_invitation_by_token(
            &self,
            token: &str,
        ) -> Result<Option<WorkspaceInvitation>, sqlx::Error> {
            let invite = self.invite.lock().unwrap().clone();
            Ok(invite.filter(|inv| inv.token == token))
        }

        async fn mark_invitation_accepted(&self, invite_id: Uuid) -> Result<(), sqlx::Error> {
            self.accepted.lock().unwrap().push(invite_id);
            Ok(())
        }

        async fn mark_invitation_declined(&self, invite_id: Uuid) -> Result<(), sqlx::Error> {
            self.declined.lock().unwrap().push(invite_id);
            Ok(())
        }

        async fn list_pending_invitations_for_email(
            &self,
            _: &str,
        ) -> Result<Vec<WorkspaceInvitation>, sqlx::Error> {
            Ok(vec![])
        }

        async fn disable_webhook_signing_for_workspace(
            &self,
            _workspace_id: Uuid,
        ) -> Result<(), sqlx::Error> {
            Ok(())
        }

        async fn try_increment_workspace_run_quota(
            &self,
            workspace_id: Uuid,
            period_start: OffsetDateTime,
            max_runs: i64,
        ) -> Result<WorkspaceRunQuotaUpdate, sqlx::Error> {
            let mut usage = self.run_usage.lock().unwrap();
            let key = (workspace_id, period_start.unix_timestamp());
            let entry = usage.entry(key).or_insert((0, 0));
            entry.0 += 1;
            let mut overage_incremented = false;
            if entry.0 > max_runs {
                entry.1 += 1;
                overage_incremented = true;
            }
            Ok(WorkspaceRunQuotaUpdate {
                allowed: entry.0 <= max_runs,
                run_count: entry.0,
                overage_count: entry.1,
                overage_incremented,
            })
        }

        async fn get_workspace_run_quota(
            &self,
            workspace_id: Uuid,
            period_start: OffsetDateTime,
        ) -> Result<WorkspaceRunUsage, sqlx::Error> {
            let usage = self.run_usage.lock().unwrap();
            let key = (workspace_id, period_start.unix_timestamp());
            Ok(usage
                .get(&key)
                .copied()
                .map(|(runs, overage)| WorkspaceRunUsage {
                    run_count: runs,
                    overage_count: overage,
                })
                .unwrap_or(WorkspaceRunUsage {
                    run_count: 0,
                    overage_count: 0,
                }))
        }

        async fn release_workspace_run_quota(
            &self,
            workspace_id: Uuid,
            period_start: OffsetDateTime,
            overage_decrement: bool,
        ) -> Result<(), sqlx::Error> {
            let mut usage = self.run_usage.lock().unwrap();
            let key = (workspace_id, period_start.unix_timestamp());
            if let Some(entry) = usage.get_mut(&key) {
                if entry.0 > 0 {
                    entry.0 -= 1;
                }
                if overage_decrement && entry.1 > 0 {
                    entry.1 -= 1;
                }
                if entry.0 == 0 && entry.1 == 0 {
                    usage.remove(&key);
                }
            }
            Ok(())
        }

        async fn upsert_workspace_billing_cycle(
            &self,
            workspace_id: Uuid,
            subscription_id: &str,
            period_start: OffsetDateTime,
            period_end: OffsetDateTime,
        ) -> Result<(), sqlx::Error> {
            self.billing_cycles.lock().unwrap().insert(
                workspace_id,
                WorkspaceBillingCycle {
                    workspace_id,
                    stripe_subscription_id: subscription_id.to_string(),
                    current_period_start: period_start,
                    current_period_end: period_end,
                    synced_at: OffsetDateTime::now_utc(),
                },
            );
            Ok(())
        }

        async fn clear_workspace_billing_cycle(
            &self,
            workspace_id: Uuid,
        ) -> Result<(), sqlx::Error> {
            self.billing_cycles.lock().unwrap().remove(&workspace_id);
            Ok(())
        }

        async fn get_workspace_billing_cycle(
            &self,
            workspace_id: Uuid,
        ) -> Result<Option<WorkspaceBillingCycle>, sqlx::Error> {
            Ok(self
                .billing_cycles
                .lock()
                .unwrap()
                .get(&workspace_id)
                .cloned())
        }
    }
    fn test_payload() -> SignupPayload {
        SignupPayload {
            email: "test@example.com".into(),
            password: "password123".into(),
            first_name: "Test".into(),
            last_name: "User".into(),
            settings: None,
            provider: None,
            company_name: None,
            country: None,
            tax_id: None,
            invite_token: None,
            invite_decision: None,
            accepted_terms_version: Some(TERMS_OF_SERVICE_VERSION.to_string()),
        }
    }

    fn invite_fixture(token: &str, email: &str, expires_at: OffsetDateTime) -> WorkspaceInvitation {
        WorkspaceInvitation {
            id: Uuid::new_v4(),
            workspace_id: Uuid::new_v4(),
            email: email.to_string(),
            role: WorkspaceRole::User,
            token: token.to_string(),
            status: INVITATION_STATUS_PENDING.to_string(),
            expires_at,
            created_by: Uuid::new_v4(),
            created_at: OffsetDateTime::now_utc(),
            accepted_at: None,
            revoked_at: None,
            declined_at: None,
        }
    }

    async fn run_signup(
        repo: impl UserRepository + 'static,
        workspace_repo: Arc<dyn WorkspaceRepository>,
        mailer: impl Mailer + 'static,
        payload: SignupPayload,
    ) -> axum::response::Response {
        let app = axum::Router::new()
            .route("/", axum::routing::post(handle_signup))
            .with_state(AppState {
                db: Arc::new(repo),
                workflow_repo: Arc::new(NoopWorkflowRepository),
                workspace_repo,
                workspace_connection_repo: Arc::new(NoopWorkspaceConnectionRepository),
                stripe_event_log_repo: Arc::new(MockStripeEventLogRepository::default()),
                db_pool: test_pg_pool(),
                mailer: Arc::new(mailer),
                github_oauth: Arc::new(MockGitHubOAuth::default()),
                google_oauth: Arc::new(MockGoogleOAuth::default()),
                oauth_accounts: OAuthAccountService::test_stub(),
                workspace_oauth: WorkspaceOAuthService::test_stub(),
                stripe: Arc::new(crate::services::stripe::MockStripeService::new()),
                http_client: Arc::new(Client::new()),
                config: test_config(),
                worker_id: Arc::new("test-worker".to_string()),
                worker_lease_seconds: 30,
                jwt_keys: test_jwt_keys(),
            });

        let request = Request::builder()
            .method("POST")
            .uri("/")
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_vec(&payload).unwrap()))
            .unwrap();

        app.oneshot(request).await.unwrap()
    }

    fn test_jwt_keys() -> Arc<JwtKeys> {
        Arc::new(
            JwtKeys::from_secret("0123456789abcdef0123456789abcdef")
                .expect("test JWT secret should be valid"),
        )
    }

    #[tokio::test]
    async fn test_email_already_taken() {
        let repo = MockRepo {
            email_taken: true,
            fail_create_user: false,
            fail_insert_token: false,
            fail_record_terms: false,
            cleaned_up: Arc::new(Mutex::new(false)),
            terms_recorded: Arc::new(Mutex::new(false)),
        };

        let mailer = MockMailer::default();
        let res = run_signup(
            repo,
            Arc::new(NoopWorkspaceRepository),
            mailer,
            test_payload(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn test_password_hash_fails() {
        let mut payload = test_payload();
        payload.password = "\0".to_string(); // bcrypt will fail

        let repo = MockRepo {
            email_taken: false,
            fail_create_user: false,
            fail_insert_token: false,
            fail_record_terms: false,
            cleaned_up: Arc::new(Mutex::new(false)),
            terms_recorded: Arc::new(Mutex::new(false)),
        };

        let mailer = MockMailer::default();
        let res = run_signup(repo, Arc::new(NoopWorkspaceRepository), mailer, payload).await;
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_create_user_fails() {
        let repo = MockRepo {
            email_taken: false,
            fail_create_user: true,
            fail_insert_token: false,
            fail_record_terms: false,
            cleaned_up: Arc::new(Mutex::new(false)),
            terms_recorded: Arc::new(Mutex::new(false)),
        };

        let mailer = MockMailer::default();
        let res = run_signup(
            repo,
            Arc::new(NoopWorkspaceRepository),
            mailer,
            test_payload(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_terms_must_be_accepted() {
        let repo = MockRepo {
            email_taken: false,
            fail_create_user: false,
            fail_insert_token: false,
            fail_record_terms: false,
            cleaned_up: Arc::new(Mutex::new(false)),
            terms_recorded: Arc::new(Mutex::new(false)),
        };

        let mailer = MockMailer::default();
        let mut payload = test_payload();
        payload.accepted_terms_version = Some("0.9".into());

        let res = run_signup(repo, Arc::new(NoopWorkspaceRepository), mailer, payload).await;

        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_record_terms_failure_triggers_cleanup() {
        let cleaned_up = Arc::new(Mutex::new(false));

        let repo = MockRepo {
            email_taken: false,
            fail_create_user: false,
            fail_insert_token: false,
            fail_record_terms: true,
            cleaned_up: Arc::clone(&cleaned_up),
            terms_recorded: Arc::new(Mutex::new(false)),
        };

        let mailer = MockMailer::default();
        let res = run_signup(
            repo,
            Arc::new(NoopWorkspaceRepository),
            mailer,
            test_payload(),
        )
        .await;

        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(*cleaned_up.lock().unwrap());
    }

    #[tokio::test]
    async fn test_insert_token_fails() {
        let repo = MockRepo {
            email_taken: false,
            fail_create_user: false,
            fail_insert_token: true,
            fail_record_terms: false,
            cleaned_up: Arc::new(Mutex::new(false)),
            terms_recorded: Arc::new(Mutex::new(false)),
        };

        let mailer = MockMailer::default();
        let res = run_signup(
            repo,
            Arc::new(NoopWorkspaceRepository),
            mailer,
            test_payload(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_email_send_fails_and_triggers_cleanup() {
        let cleaned_up = Arc::new(Mutex::new(false));

        let repo = MockRepo {
            email_taken: false,
            fail_create_user: false,
            fail_insert_token: false,
            fail_record_terms: false,
            cleaned_up: Arc::clone(&cleaned_up),
            terms_recorded: Arc::new(Mutex::new(false)),
        };

        let mailer = MockMailer {
            fail_send: true,
            ..Default::default()
        };

        let res = run_signup(
            repo,
            Arc::new(NoopWorkspaceRepository),
            mailer,
            test_payload(),
        )
        .await;
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(*cleaned_up.lock().unwrap());
    }

    #[tokio::test]
    async fn test_successful_signup() {
        let repo = MockRepo {
            email_taken: false,
            fail_create_user: false,
            fail_insert_token: false,
            fail_record_terms: false,
            cleaned_up: Arc::new(Mutex::new(false)),
            terms_recorded: Arc::new(Mutex::new(false)),
        };

        let mailer = MockMailer::default();
        let workspace_repo = Arc::new(RecordingWorkspaceRepo::default());
        let res = run_signup(
            repo,
            workspace_repo.clone() as Arc<dyn WorkspaceRepository>,
            mailer,
            test_payload(),
        )
        .await;

        assert_eq!(res.status(), StatusCode::OK);
        let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            json["message"],
            "User created. Check your email to verify your account."
        );

        let (created, add_calls, accepted, declined) = workspace_repo.record();
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].name, "Test's Workspace");
        assert_eq!(add_calls.len(), 1);
        assert_eq!(add_calls[0].2, WorkspaceRole::Owner);
        assert!(accepted.is_empty());
        assert!(declined.is_empty());
    }

    #[tokio::test]
    async fn test_invite_join_attaches_membership() {
        let repo = MockRepo {
            email_taken: false,
            fail_create_user: false,
            fail_insert_token: false,
            fail_record_terms: false,
            cleaned_up: Arc::new(Mutex::new(false)),
            terms_recorded: Arc::new(Mutex::new(false)),
        };
        let invite = invite_fixture(
            "join-token",
            "test@example.com",
            OffsetDateTime::now_utc() + Duration::hours(1),
        );
        let workspace_repo = Arc::new(RecordingWorkspaceRepo::with_invite(invite.clone()));
        let mailer = MockMailer::default();
        let mut payload = test_payload();
        payload.invite_token = Some(invite.token.clone());
        payload.invite_decision = Some(SignupInviteDecision::Join);

        let res = run_signup(
            repo,
            workspace_repo.clone() as Arc<dyn WorkspaceRepository>,
            mailer,
            payload,
        )
        .await;

        assert_eq!(res.status(), StatusCode::OK);
        let (created, add_calls, accepted, declined) = workspace_repo.record();
        assert!(created.is_empty());
        assert_eq!(add_calls.len(), 1);
        assert_eq!(add_calls[0].0, invite.workspace_id);
        assert_eq!(add_calls[0].2, invite.role);
        assert_eq!(accepted, vec![invite.id]);
        assert!(declined.is_empty());
    }

    #[tokio::test]
    async fn test_invite_decline_marks_declined_and_creates_workspace() {
        let repo = MockRepo {
            email_taken: false,
            fail_create_user: false,
            fail_insert_token: false,
            fail_record_terms: false,
            cleaned_up: Arc::new(Mutex::new(false)),
            terms_recorded: Arc::new(Mutex::new(false)),
        };
        let invite = invite_fixture(
            "decline-token",
            "test@example.com",
            OffsetDateTime::now_utc() + Duration::hours(1),
        );
        let workspace_repo = Arc::new(RecordingWorkspaceRepo::with_invite(invite.clone()));
        let mailer = MockMailer::default();
        let mut payload = test_payload();
        payload.invite_token = Some(invite.token.clone());
        payload.invite_decision = Some(SignupInviteDecision::Decline);

        let res = run_signup(
            repo,
            workspace_repo.clone() as Arc<dyn WorkspaceRepository>,
            mailer,
            payload,
        )
        .await;

        assert_eq!(res.status(), StatusCode::OK);
        let (created, add_calls, accepted, declined) = workspace_repo.record();
        assert_eq!(created.len(), 1);
        assert_eq!(add_calls.len(), 1);
        assert_ne!(add_calls[0].0, invite.workspace_id);
        assert_eq!(add_calls[0].2, WorkspaceRole::Owner);
        assert!(accepted.is_empty());
        assert_eq!(declined, vec![invite.id]);
    }

    #[tokio::test]
    async fn test_invite_email_mismatch_rejected() {
        let repo = MockRepo {
            email_taken: false,
            fail_create_user: false,
            fail_insert_token: false,
            fail_record_terms: false,
            cleaned_up: Arc::new(Mutex::new(false)),
            terms_recorded: Arc::new(Mutex::new(false)),
        };
        let invite = invite_fixture(
            "mismatch-token",
            "other@example.com",
            OffsetDateTime::now_utc() + Duration::hours(1),
        );
        let workspace_repo = Arc::new(RecordingWorkspaceRepo::with_invite(invite));
        let mailer = MockMailer::default();
        let mut payload = test_payload();
        payload.invite_token = Some("mismatch-token".into());
        payload.invite_decision = Some(SignupInviteDecision::Join);

        let res = run_signup(
            repo,
            workspace_repo.clone() as Arc<dyn WorkspaceRepository>,
            mailer,
            payload,
        )
        .await;

        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let (created, add_calls, accepted, declined) = workspace_repo.record();
        assert!(created.is_empty());
        assert!(add_calls.is_empty());
        assert!(accepted.is_empty());
        assert!(declined.is_empty());
    }

    #[tokio::test]
    async fn test_expired_invite_rejected() {
        let repo = MockRepo {
            email_taken: false,
            fail_create_user: false,
            fail_insert_token: false,
            fail_record_terms: false,
            cleaned_up: Arc::new(Mutex::new(false)),
            terms_recorded: Arc::new(Mutex::new(false)),
        };
        let invite = invite_fixture(
            "expired-token",
            "test@example.com",
            OffsetDateTime::now_utc() - Duration::hours(1),
        );
        let workspace_repo = Arc::new(RecordingWorkspaceRepo::with_invite(invite));
        let mailer = MockMailer::default();
        let mut payload = test_payload();
        payload.invite_token = Some("expired-token".into());
        payload.invite_decision = Some(SignupInviteDecision::Join);

        let res = run_signup(
            repo,
            workspace_repo.clone() as Arc<dyn WorkspaceRepository>,
            mailer,
            payload,
        )
        .await;

        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        let (created, add_calls, accepted, declined) = workspace_repo.record();
        assert!(created.is_empty());
        assert!(add_calls.is_empty());
        assert!(accepted.is_empty());
        assert!(declined.is_empty());
    }
}
