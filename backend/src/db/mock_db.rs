use crate::models::issue_report::NewIssueReport;
use crate::models::login_activity::{NewLoginActivity, UserLoginActivity};
use crate::models::user::{OauthProvider, PublicUser, User};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use time::OffsetDateTime;
use uuid::Uuid;

use super::user_repository::{UserId, UserRepository};
use crate::db::workflow_repository::{CreateWorkflowRunOutcome, WorkspaceMemberRunCount};
use crate::db::{
    workflow_repository::WorkflowRepository,
    workspace_repository::{WorkspaceRepository, WorkspaceRunQuotaUpdate, WorkspaceRunUsage},
};
use crate::models::signup::SignupPayload;
use crate::models::workflow::Workflow;
use crate::models::workflow_node_run::WorkflowNodeRun;
use crate::models::workflow_run::WorkflowRun;
use crate::models::workflow_run_event::{NewWorkflowRunEvent, WorkflowRunEvent};
use crate::models::workflow_schedule::WorkflowSchedule;
use crate::models::{
    plan::PlanTier,
    workspace::{
        Workspace, WorkspaceBillingCycle, WorkspaceMembershipSummary, WorkspaceRole,
        INVITATION_STATUS_PENDING, WORKSPACE_PLAN_TEAM,
    },
};
use serde_json::Value;

#[allow(dead_code)]
type MarkVerificationTokenFn =
    Box<dyn Fn(&str, OffsetDateTime) -> Result<Option<Uuid>, sqlx::Error> + Send + Sync>;

#[allow(dead_code)]
pub struct MockDb {
    pub find_user_result: Option<User>,
    pub create_user_result: Option<User>,
    pub should_fail: bool,
    pub mark_verification_token_fn: MarkVerificationTokenFn,
    pub set_user_verified_fn: Box<dyn Fn(Uuid) -> Result<(), sqlx::Error> + Send + Sync>,
    pub insert_early_access_email_fn: Box<dyn Fn(String) -> Result<(), sqlx::Error> + Send + Sync>,
    pub user_settings: Mutex<Value>,
    pub stripe_customer_id: Mutex<Option<String>>,
    pub update_user_plan_calls: Mutex<usize>,
    pub terms_acceptances: Mutex<Vec<(Uuid, String, OffsetDateTime)>>,
    pub issue_reports: Mutex<Vec<(Uuid, NewIssueReport)>>,
    pub login_activity: Mutex<Vec<UserLoginActivity>>,
}

impl Default for MockDb {
    fn default() -> Self {
        Self {
            find_user_result: None,
            create_user_result: None,
            should_fail: false,
            mark_verification_token_fn: Box::new(|_, _| Ok(Some(Uuid::new_v4()))), // manually initialize all non-Default fields
            set_user_verified_fn: Box::new(|_| Ok(())),
            insert_early_access_email_fn: Box::new(|_| Ok(())),
            user_settings: Mutex::new(Value::Object(Default::default())),
            stripe_customer_id: Mutex::new(None),
            update_user_plan_calls: Mutex::new(0),
            terms_acceptances: Mutex::new(vec![]),
            issue_reports: Mutex::new(vec![]),
            login_activity: Mutex::new(vec![]),
        }
    }
}

#[async_trait]
impl UserRepository for MockDb {
    async fn find_user_by_email(&self, _: &str) -> Result<Option<User>, sqlx::Error> {
        if self.should_fail {
            return Err(sqlx::Error::Protocol("Mock DB failure".into()));
        }
        Ok(self.find_user_result.clone())
    }

    async fn create_user_with_oauth(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: OauthProvider,
    ) -> Result<User, sqlx::Error> {
        match &self.create_user_result {
            Some(user) => Ok(user.clone()),
            None => Err(sqlx::Error::RowNotFound),
        }
    }
    async fn find_user_id_by_email(&self, email: &str) -> Result<Option<UserId>, sqlx::Error> {
        if self.should_fail {
            return Err(sqlx::Error::Protocol("Mock DB failure".into()));
        }

        Ok(self
            .find_user_result
            .as_ref()
            .filter(|user| user.email.eq_ignore_ascii_case(email))
            .map(|user| UserId { id: user.id }))
    }
    async fn insert_password_reset_token(
        &self,
        _: Uuid,
        _: &str,
        _: time::OffsetDateTime,
    ) -> Result<(), sqlx::Error> {
        todo!()
    }
    async fn find_public_user_by_id(
        &self,
        user_id: Uuid,
    ) -> Result<Option<PublicUser>, sqlx::Error> {
        if let Some(user) = &self.find_user_result {
            if user.id == user_id {
                return Ok(Some(PublicUser {
                    id: user.id,
                    email: user.email.clone(),
                    first_name: user.first_name.clone(),
                    last_name: user.last_name.clone(),
                    role: user.role,
                    plan: user.plan.clone(),
                    company_name: user.company_name.clone(),
                    oauth_provider: user.oauth_provider,
                    onboarded_at: user.onboarded_at,
                }));
            }
        }
        Ok(None)
    }
    async fn verify_password_reset_token(&self, _: &str) -> Result<Option<Uuid>, sqlx::Error> {
        todo!()
    }
    async fn update_user_password(&self, _: Uuid, _: &str) -> Result<(), sqlx::Error> {
        todo!()
    }
    async fn mark_password_reset_token_used(&self, _: &str) -> Result<(), sqlx::Error> {
        todo!()
    }
    async fn is_email_taken(&self, _: &str) -> Result<bool, sqlx::Error> {
        todo!()
    }
    async fn create_user(
        &self,
        _: &SignupPayload,
        _: &str,
        _: OauthProvider,
    ) -> Result<Uuid, sqlx::Error> {
        todo!()
    }
    async fn record_terms_acceptance(
        &self,
        user_id: Uuid,
        terms_version: &str,
        accepted_at: OffsetDateTime,
    ) -> Result<(), sqlx::Error> {
        self.terms_acceptances.lock().unwrap().push((
            user_id,
            terms_version.to_string(),
            accepted_at,
        ));
        Ok(())
    }
    async fn insert_verification_token(
        &self,
        _: Uuid,
        _: &str,
        _: time::OffsetDateTime,
    ) -> Result<(), sqlx::Error> {
        todo!()
    }
    async fn cleanup_user_and_token(&self, _: Uuid, _: &str) -> Result<(), sqlx::Error> {
        todo!()
    }
    async fn mark_verification_token_used(
        &self,
        token: &str,
        time: time::OffsetDateTime,
    ) -> Result<Option<Uuid>, sqlx::Error> {
        (self.mark_verification_token_fn)(token, time)
    }
    async fn set_user_verified(&self, user_id: Uuid) -> Result<(), sqlx::Error> {
        (self.set_user_verified_fn)(user_id)
    }
    async fn insert_early_access_email(&self, email: &str) -> Result<(), sqlx::Error> {
        (self.insert_early_access_email_fn)(email.to_string())
    }

    async fn get_user_settings(&self, _user_id: Uuid) -> Result<Value, sqlx::Error> {
        Ok(self.user_settings.lock().unwrap().clone())
    }

    async fn update_user_settings(
        &self,
        _user_id: Uuid,
        settings: Value,
    ) -> Result<(), sqlx::Error> {
        let mut guard = self.user_settings.lock().unwrap();
        *guard = settings;
        Ok(())
    }

    async fn update_user_plan(&self, _user_id: Uuid, _plan: &str) -> Result<(), sqlx::Error> {
        let mut guard = self.update_user_plan_calls.lock().unwrap();
        *guard += 1;
        Ok(())
    }

    async fn mark_workspace_onboarded(
        &self,
        _user_id: Uuid,
        _onboarded_at: OffsetDateTime,
    ) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn get_user_stripe_customer_id(
        &self,
        _user_id: Uuid,
    ) -> Result<Option<String>, sqlx::Error> {
        Ok(self.stripe_customer_id.lock().unwrap().clone())
    }

    async fn set_user_stripe_customer_id(
        &self,
        _user_id: Uuid,
        stripe_customer_id: &str,
    ) -> Result<(), sqlx::Error> {
        *self.stripe_customer_id.lock().unwrap() = Some(stripe_customer_id.to_string());
        Ok(())
    }

    async fn find_user_id_by_stripe_customer_id(
        &self,
        customer_id: &str,
    ) -> Result<Option<Uuid>, sqlx::Error> {
        let guard = self.stripe_customer_id.lock().unwrap();
        if guard.as_deref() == Some(customer_id) {
            Ok(self.find_user_result.as_ref().map(|u| u.id))
        } else {
            Ok(None)
        }
    }

    async fn clear_pending_checkout_with_error(
        &self,
        _user_id: Uuid,
        message: &str,
    ) -> Result<(), sqlx::Error> {
        let mut settings = self.user_settings.lock().unwrap();
        if let Some(obj) = settings.as_object_mut() {
            let billing = obj
                .entry("billing")
                .or_insert_with(|| serde_json::json!({}))
                .as_object_mut()
                .unwrap();
            billing.insert("pending_checkout".to_string(), serde_json::Value::Null);
            billing.insert(
                "last_error".to_string(),
                serde_json::Value::String(message.to_string()),
            );
            billing.insert(
                "last_error_at".to_string(),
                serde_json::json!(OffsetDateTime::now_utc()),
            );
        }
        Ok(())
    }

    async fn create_issue_report(&self, report: NewIssueReport) -> Result<Uuid, sqlx::Error> {
        let id = Uuid::new_v4();
        self.issue_reports.lock().unwrap().push((id, report));
        Ok(id)
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
    ) -> Result<Option<crate::models::account_deletion::AccountDeletionContext>, sqlx::Error> {
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

    async fn delete_verification_tokens_for_user(&self, _user_id: Uuid) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn clear_stripe_customer_id(&self, _user_id: Uuid) -> Result<(), sqlx::Error> {
        let mut guard = self.stripe_customer_id.lock().unwrap();
        *guard = None;
        Ok(())
    }

    async fn record_login_activity(&self, activity: NewLoginActivity) -> Result<Uuid, sqlx::Error> {
        let id = Uuid::new_v4();
        let record = UserLoginActivity {
            id,
            user_id: activity.user_id,
            session_id: activity.session_id,
            ip_address: activity.ip_address.to_string(),
            ipv4_address: activity.ipv4_address.map(|ip| ip.to_string()),
            ipv6_address: activity.ipv6_address.map(|ip| ip.to_string()),
            user_agent: activity.user_agent,
            city: activity.city,
            region: activity.region,
            country: activity.country,
            latitude: activity.latitude,
            longitude: activity.longitude,
            is_proxy: activity.is_proxy,
            is_vpn: activity.is_vpn,
            lookup_raw: activity.lookup_raw,
            logged_in_at: activity.logged_in_at,
            logged_out_at: None,
            created_at: OffsetDateTime::now_utc(),
        };
        self.login_activity.lock().unwrap().push(record);
        Ok(id)
    }

    async fn mark_logout_activity(
        &self,
        session_id: Uuid,
        logged_out_at: OffsetDateTime,
    ) -> Result<(), sqlx::Error> {
        let mut entries = self.login_activity.lock().unwrap();
        for entry in entries.iter_mut() {
            if entry.session_id == session_id && entry.logged_out_at.is_none() {
                entry.logged_out_at = Some(logged_out_at);
            }
        }
        Ok(())
    }

    async fn list_login_activity_for_user(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<UserLoginActivity>, sqlx::Error> {
        let mut entries: Vec<UserLoginActivity> = self
            .login_activity
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.user_id == user_id)
            .cloned()
            .collect();

        entries.sort_by(|a, b| b.logged_in_at.cmp(&a.logged_in_at));
        entries.truncate(limit as usize);
        Ok(entries)
    }
}

#[allow(dead_code)]
#[derive(Default)]
pub struct NoopWorkflowRepository;

#[async_trait]
impl WorkflowRepository for NoopWorkflowRepository {
    async fn create_workflow(
        &self,
        _user_id: Uuid,
        _workspace_id: Option<Uuid>,
        _name: &str,
        _description: Option<&str>,
        _data: Value,
    ) -> Result<Workflow, sqlx::Error> {
        unimplemented!("Workflow repository behavior is not part of this test scenario");
    }

    async fn list_workflows_by_user(&self, _user_id: Uuid) -> Result<Vec<Workflow>, sqlx::Error> {
        Ok(vec![])
    }

    async fn list_workflows_by_workspace_ids(
        &self,
        _workspace_ids: &[Uuid],
    ) -> Result<Vec<Workflow>, sqlx::Error> {
        Ok(vec![])
    }

    async fn find_workflow_by_id(
        &self,
        _user_id: Uuid,
        _workflow_id: Uuid,
    ) -> Result<Option<Workflow>, sqlx::Error> {
        Ok(None)
    }

    async fn find_workflow_for_member(
        &self,
        _user_id: Uuid,
        _workflow_id: Uuid,
    ) -> Result<Option<Workflow>, sqlx::Error> {
        Ok(None)
    }

    async fn find_workflow_by_id_public(
        &self,
        _workflow_id: Uuid,
    ) -> Result<Option<Workflow>, sqlx::Error> {
        Ok(None)
    }

    async fn update_workflow(
        &self,
        _user_id: Uuid,
        _workflow_id: Uuid,
        _name: &str,
        _description: Option<&str>,
        _data: Value,
        _expected_updated_at: Option<OffsetDateTime>,
    ) -> Result<Option<Workflow>, sqlx::Error> {
        Ok(None)
    }

    async fn delete_workflow(
        &self,
        _user_id: Uuid,
        _workflow_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        Ok(false)
    }

    async fn set_workflow_workspace(
        &self,
        _user_id: Uuid,
        _workflow_id: Uuid,
        _workspace_id: Option<Uuid>,
    ) -> Result<Option<Workflow>, sqlx::Error> {
        Ok(None)
    }

    async fn set_workflow_lock(
        &self,
        _workflow_id: Uuid,
        _locked_by: Option<Uuid>,
    ) -> Result<Option<Workflow>, sqlx::Error> {
        Ok(None)
    }

    async fn insert_workflow_log(
        &self,
        _user_id: Uuid,
        _workflow_id: Uuid,
        _diffs: serde_json::Value,
    ) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn list_workflow_logs(
        &self,
        _user_id: Uuid,
        _workflow_id: Uuid,
        _limit: i64,
        _offset: i64,
    ) -> Result<Vec<crate::models::workflow_log::WorkflowLog>, sqlx::Error> {
        Ok(vec![])
    }

    async fn delete_workflow_log(
        &self,
        _user_id: Uuid,
        _workflow_id: Uuid,
        _log_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        Ok(false)
    }

    async fn clear_workflow_logs(
        &self,
        _user_id: Uuid,
        _workflow_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        Ok(0)
    }

    async fn create_workflow_run(
        &self,
        _user_id: Uuid,
        _workflow_id: Uuid,
        _workspace_id: Option<Uuid>,
        _snapshot: Value,
        _idempotency_key: Option<&str>,
    ) -> Result<CreateWorkflowRunOutcome, sqlx::Error> {
        Err(sqlx::Error::Protocol(
            "NoopWorkflowRepository not implemented".into(),
        ))
    }

    async fn get_workflow_run(
        &self,
        _user_id: Uuid,
        _workflow_id: Uuid,
        _run_id: Uuid,
    ) -> Result<Option<WorkflowRun>, sqlx::Error> {
        Ok(None)
    }

    async fn list_workflow_node_runs(
        &self,
        _user_id: Uuid,
        _workflow_id: Uuid,
        _run_id: Uuid,
    ) -> Result<Vec<WorkflowNodeRun>, sqlx::Error> {
        Ok(vec![])
    }

    async fn record_run_event(
        &self,
        event: NewWorkflowRunEvent,
    ) -> Result<WorkflowRunEvent, sqlx::Error> {
        Ok(WorkflowRunEvent {
            id: Uuid::new_v4(),
            workflow_run_id: event.workflow_run_id,
            workflow_id: event.workflow_id,
            workspace_id: event.workspace_id,
            triggered_by: event.triggered_by,
            connection_type: event.connection_type,
            connection_id: event.connection_id,
            recorded_at: event.recorded_at.unwrap_or_else(OffsetDateTime::now_utc),
        })
    }

    async fn claim_next_queued_run(&self) -> Result<Option<WorkflowRun>, sqlx::Error> {
        Ok(None)
    }

    async fn complete_workflow_run(
        &self,
        _run_id: Uuid,
        _status: &str,
        _error: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn pause_workflow_run(
        &self,
        _run_id: Uuid,
        _snapshot: Value,
        _resume_at: OffsetDateTime,
    ) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn insert_node_run(
        &self,
        _run_id: Uuid,
        _node_id: &str,
        _name: Option<&str>,
        _node_type: Option<&str>,
        _inputs: Option<Value>,
        _outputs: Option<Value>,
        _status: &str,
        _error: Option<&str>,
    ) -> Result<WorkflowNodeRun, sqlx::Error> {
        Err(sqlx::Error::Protocol(
            "NoopWorkflowRepository not implemented".into(),
        ))
    }

    async fn update_node_run(
        &self,
        _node_run_id: Uuid,
        _status: &str,
        _outputs: Option<Value>,
        _error: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn upsert_node_run(
        &self,
        _run_id: Uuid,
        _node_id: &str,
        _name: Option<&str>,
        _node_type: Option<&str>,
        _inputs: Option<Value>,
        _outputs: Option<Value>,
        _status: &str,
        _error: Option<&str>,
    ) -> Result<WorkflowNodeRun, sqlx::Error> {
        Err(sqlx::Error::Protocol(
            "NoopWorkflowRepository not implemented".into(),
        ))
    }

    async fn cancel_workflow_run(
        &self,
        _user_id: Uuid,
        _workflow_id: Uuid,
        _run_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        Ok(false)
    }

    async fn get_run_status(&self, _run_id: Uuid) -> Result<Option<String>, sqlx::Error> {
        Ok(None)
    }

    async fn list_active_runs(
        &self,
        _user_id: Uuid,
        _workflow_id: Option<Uuid>,
    ) -> Result<Vec<WorkflowRun>, sqlx::Error> {
        Ok(vec![])
    }

    async fn list_runs_paged(
        &self,
        _user_id: Uuid,
        _workflow_id: Option<Uuid>,
        _statuses: Option<&[String]>,
        _limit: i64,
        _offset: i64,
    ) -> Result<Vec<WorkflowRun>, sqlx::Error> {
        Ok(vec![])
    }

    async fn cancel_all_runs_for_workflow(
        &self,
        _user_id: Uuid,
        _workflow_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        Ok(0)
    }

    async fn set_run_priority(
        &self,
        _user_id: Uuid,
        _workflow_id: Uuid,
        _run_id: Uuid,
        _priority: i32,
    ) -> Result<bool, sqlx::Error> {
        Ok(true)
    }

    async fn count_user_runs_since(
        &self,
        _user_id: Uuid,
        _since: OffsetDateTime,
    ) -> Result<i64, sqlx::Error> {
        Ok(0)
    }

    async fn count_workspace_runs_since(
        &self,
        _workspace_id: Uuid,
        _since: OffsetDateTime,
    ) -> Result<i64, sqlx::Error> {
        Ok(0)
    }

    async fn list_workspace_member_run_counts(
        &self,
        _workspace_id: Uuid,
        _since: OffsetDateTime,
    ) -> Result<Vec<WorkspaceMemberRunCount>, sqlx::Error> {
        Ok(Vec::new())
    }

    async fn set_workflow_concurrency_limit(
        &self,
        _user_id: Uuid,
        _workflow_id: Uuid,
        _limit: i32,
    ) -> Result<bool, sqlx::Error> {
        Ok(true)
    }

    async fn requeue_expired_leases(&self) -> Result<u64, sqlx::Error> {
        Ok(0)
    }

    async fn upsert_workflow_schedule(
        &self,
        _user_id: Uuid,
        _workflow_id: Uuid,
        _config: Value,
        _next_run_at: Option<OffsetDateTime>,
    ) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn disable_workflow_schedule(&self, _workflow_id: Uuid) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn get_schedule_for_workflow(
        &self,
        _workflow_id: Uuid,
    ) -> Result<Option<WorkflowSchedule>, sqlx::Error> {
        Ok(None)
    }

    async fn list_due_schedules(&self, _limit: i64) -> Result<Vec<WorkflowSchedule>, sqlx::Error> {
        Ok(vec![])
    }

    async fn mark_schedule_run(
        &self,
        _schedule_id: Uuid,
        _last_run_at: OffsetDateTime,
        _next_run_at: Option<OffsetDateTime>,
    ) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn claim_next_eligible_run(
        &self,
        _worker_id: &str,
        _lease_seconds: i32,
    ) -> Result<Option<WorkflowRun>, sqlx::Error> {
        Ok(None)
    }

    async fn renew_run_lease(
        &self,
        _run_id: Uuid,
        _worker_id: &str,
        _lease_seconds: i32,
    ) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn purge_old_runs(&self, _retention_days: i32) -> Result<u64, sqlx::Error> {
        Ok(0)
    }

    async fn insert_dead_letter(
        &self,
        _user_id: Uuid,
        _workflow_id: Uuid,
        _run_id: Uuid,
        _error: &str,
        _snapshot: Value,
    ) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn list_dead_letters(
        &self,
        _user_id: Uuid,
        _workflow_id: Uuid,
        _limit: i64,
        _offset: i64,
    ) -> Result<Vec<crate::models::workflow_dead_letter::WorkflowDeadLetter>, sqlx::Error> {
        Ok(vec![])
    }

    async fn requeue_dead_letter(
        &self,
        _user_id: Uuid,
        _workflow_id: Uuid,
        _dead_id: Uuid,
    ) -> Result<Option<WorkflowRun>, sqlx::Error> {
        Ok(None)
    }

    async fn clear_dead_letters(
        &self,
        _user_id: Uuid,
        _workflow_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        Ok(0)
    }

    async fn set_egress_allowlist(
        &self,
        _user_id: Uuid,
        _workflow_id: Uuid,
        _allowlist: &[String],
    ) -> Result<bool, sqlx::Error> {
        Ok(true)
    }

    async fn insert_egress_block_event(
        &self,
        _user_id: Uuid,
        _workflow_id: Uuid,
        _run_id: Uuid,
        _node_id: &str,
        _url: &str,
        _host: &str,
        _rule: &str,
        _message: &str,
    ) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn list_egress_block_events(
        &self,
        _user_id: Uuid,
        _workflow_id: Uuid,
        _limit: i64,
        _offset: i64,
    ) -> Result<Vec<crate::models::egress_block_event::EgressBlockEvent>, sqlx::Error> {
        Ok(vec![])
    }

    async fn clear_egress_block_events(
        &self,
        _user_id: Uuid,
        _workflow_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        Ok(0)
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Default)]
pub struct NoopWorkspaceRepository;

#[allow(dead_code)]
#[derive(Clone)]
pub struct StaticWorkspaceMembershipRepository {
    allowed: bool,
    max_runs: Option<i64>,
    plan: PlanTier,
    #[allow(clippy::type_complexity)]
    run_usage: Arc<Mutex<HashMap<(Uuid, i64), (i64, i64)>>>,
    release_calls: Arc<Mutex<usize>>,
    period_starts: Arc<Mutex<Vec<OffsetDateTime>>>,
    billing_cycle: Arc<Mutex<Option<WorkspaceBillingCycle>>>,
    member_counts: Arc<Mutex<HashMap<Uuid, i64>>>,
    pending_invites: Arc<Mutex<HashMap<Uuid, i64>>>,
    overage_items: Arc<Mutex<HashMap<Uuid, Option<String>>>>,
    workspace_owners: Arc<Mutex<HashMap<Uuid, Uuid>>>,
    inner: NoopWorkspaceRepository,
}

impl StaticWorkspaceMembershipRepository {
    #[allow(dead_code)]
    pub fn allowing() -> Self {
        Self {
            allowed: true,
            max_runs: None,
            plan: PlanTier::Workspace,
            run_usage: Arc::new(Mutex::new(HashMap::new())),
            release_calls: Arc::new(Mutex::new(0)),
            period_starts: Arc::new(Mutex::new(Vec::new())),
            billing_cycle: Arc::new(Mutex::new(None)),
            member_counts: Arc::new(Mutex::new(HashMap::new())),
            pending_invites: Arc::new(Mutex::new(HashMap::new())),
            overage_items: Arc::new(Mutex::new(HashMap::new())),
            workspace_owners: Arc::new(Mutex::new(HashMap::new())),
            inner: NoopWorkspaceRepository,
        }
    }

    #[allow(dead_code)]
    pub fn denying() -> Self {
        Self {
            allowed: false,
            max_runs: None,
            plan: PlanTier::Workspace,
            run_usage: Arc::new(Mutex::new(HashMap::new())),
            release_calls: Arc::new(Mutex::new(0)),
            period_starts: Arc::new(Mutex::new(Vec::new())),
            billing_cycle: Arc::new(Mutex::new(None)),
            member_counts: Arc::new(Mutex::new(HashMap::new())),
            pending_invites: Arc::new(Mutex::new(HashMap::new())),
            overage_items: Arc::new(Mutex::new(HashMap::new())),
            workspace_owners: Arc::new(Mutex::new(HashMap::new())),
            inner: NoopWorkspaceRepository,
        }
    }

    #[allow(dead_code)]
    pub fn with_run_limit(max_runs: i64) -> Self {
        let base = Self::allowing();
        Self {
            max_runs: Some(max_runs),
            ..base
        }
    }

    #[allow(dead_code)]
    pub fn with_plan(plan: PlanTier) -> Self {
        Self {
            plan,
            ..Self::allowing()
        }
    }

    #[allow(dead_code)]
    pub fn with_billing_cycle(cycle: WorkspaceBillingCycle) -> Self {
        let repo = Self::allowing();
        *repo.billing_cycle.lock().unwrap() = Some(cycle.clone());
        repo
    }

    #[allow(dead_code)]
    pub fn usage_for(&self, workspace_id: Uuid, period_start: OffsetDateTime) -> WorkspaceRunUsage {
        let key = (workspace_id, period_start.unix_timestamp());
        let usage = self.run_usage.lock().unwrap();
        match usage.get(&key).copied() {
            Some((runs, overage)) => WorkspaceRunUsage {
                run_count: runs,
                overage_count: overage,
            },
            None => WorkspaceRunUsage {
                run_count: 0,
                overage_count: 0,
            },
        }
    }

    #[allow(dead_code)]
    pub fn release_calls(&self) -> usize {
        *self.release_calls.lock().unwrap()
    }

    #[allow(dead_code)]
    pub fn last_period_starts(&self) -> Vec<OffsetDateTime> {
        self.period_starts.lock().unwrap().clone()
    }

    #[allow(dead_code)]
    pub fn set_member_count(&self, workspace_id: Uuid, count: i64) {
        self.member_counts
            .lock()
            .unwrap()
            .insert(workspace_id, count);
    }

    #[allow(dead_code)]
    pub fn set_pending_invites(&self, workspace_id: Uuid, count: i64) {
        self.pending_invites
            .lock()
            .unwrap()
            .insert(workspace_id, count);
    }

    #[allow(dead_code)]
    pub fn set_workspace_owner(&self, workspace_id: Uuid, owner_id: Uuid) {
        self.workspace_owners
            .lock()
            .unwrap()
            .insert(workspace_id, owner_id);
    }
}

#[async_trait]
impl WorkspaceRepository for NoopWorkspaceRepository {
    async fn create_workspace(
        &self,
        name: &str,
        created_by: Uuid,
        plan: &str,
    ) -> Result<Workspace, sqlx::Error> {
        Ok(Workspace {
            id: Uuid::new_v4(),
            name: name.to_string(),
            created_by,
            owner_id: created_by,
            plan: plan.to_string(),
            stripe_overage_item_id: None,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            deleted_at: None,
        })
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
            plan: WORKSPACE_PLAN_TEAM.to_string(),
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

    async fn get_plan(&self, _workspace_id: Uuid) -> Result<PlanTier, sqlx::Error> {
        Ok(PlanTier::Workspace)
    }

    async fn find_workspace(&self, _workspace_id: Uuid) -> Result<Option<Workspace>, sqlx::Error> {
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
        _workspace_id: Uuid,
        _user_id: Uuid,
        _role: WorkspaceRole,
    ) -> Result<(), sqlx::Error> {
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

    async fn remove_member(&self, _workspace_id: Uuid, _user_id: Uuid) -> Result<(), sqlx::Error> {
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

    async fn count_members(&self, _workspace_id: Uuid) -> Result<i64, sqlx::Error> {
        Ok(0)
    }

    async fn count_pending_workspace_invitations(
        &self,
        _workspace_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        Ok(0)
    }

    async fn is_member(&self, _workspace_id: Uuid, _user_id: Uuid) -> Result<bool, sqlx::Error> {
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
        workspace_id: Uuid,
        email: &str,
        role: WorkspaceRole,
        token: &str,
        expires_at: OffsetDateTime,
        created_by: Uuid,
    ) -> Result<crate::models::workspace::WorkspaceInvitation, sqlx::Error> {
        Ok(crate::models::workspace::WorkspaceInvitation {
            id: Uuid::new_v4(),
            workspace_id,
            email: email.to_string(),
            role,
            token: token.to_string(),
            status: INVITATION_STATUS_PENDING.to_string(),
            expires_at,
            created_by,
            created_at: OffsetDateTime::now_utc(),
            accepted_at: None,
            revoked_at: None,
            declined_at: None,
        })
    }

    async fn list_workspace_invitations(
        &self,
        _workspace_id: Uuid,
    ) -> Result<Vec<crate::models::workspace::WorkspaceInvitation>, sqlx::Error> {
        Ok(vec![])
    }

    async fn revoke_workspace_invitation(&self, _invite_id: Uuid) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn find_invitation_by_token(
        &self,
        _token: &str,
    ) -> Result<Option<crate::models::workspace::WorkspaceInvitation>, sqlx::Error> {
        Ok(None)
    }

    async fn mark_invitation_accepted(&self, _invite_id: Uuid) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn mark_invitation_declined(&self, _invite_id: Uuid) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn list_pending_invitations_for_email(
        &self,
        _email: &str,
    ) -> Result<Vec<crate::models::workspace::WorkspaceInvitation>, sqlx::Error> {
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
        _workspace_id: Uuid,
        _period_start: OffsetDateTime,
        _max_runs: i64,
    ) -> Result<WorkspaceRunQuotaUpdate, sqlx::Error> {
        Ok(WorkspaceRunQuotaUpdate {
            allowed: true,
            run_count: 1,
            overage_count: 0,
            overage_incremented: false,
        })
    }

    async fn get_workspace_run_quota(
        &self,
        _workspace_id: Uuid,
        _period_start: OffsetDateTime,
    ) -> Result<WorkspaceRunUsage, sqlx::Error> {
        Ok(WorkspaceRunUsage {
            run_count: 0,
            overage_count: 0,
        })
    }

    async fn release_workspace_run_quota(
        &self,
        _workspace_id: Uuid,
        _period_start: OffsetDateTime,
        _overage_decrement: bool,
    ) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn upsert_workspace_billing_cycle(
        &self,
        _workspace_id: Uuid,
        _subscription_id: &str,
        _period_start: OffsetDateTime,
        _period_end: OffsetDateTime,
    ) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn clear_workspace_billing_cycle(&self, _workspace_id: Uuid) -> Result<(), sqlx::Error> {
        Ok(())
    }

    async fn get_workspace_billing_cycle(
        &self,
        _workspace_id: Uuid,
    ) -> Result<Option<WorkspaceBillingCycle>, sqlx::Error> {
        Ok(None)
    }
}

#[async_trait]
impl WorkspaceRepository for StaticWorkspaceMembershipRepository {
    async fn create_workspace(
        &self,
        name: &str,
        created_by: Uuid,
        plan: &str,
    ) -> Result<Workspace, sqlx::Error> {
        self.inner.create_workspace(name, created_by, plan).await
    }

    async fn update_workspace_name(
        &self,
        workspace_id: Uuid,
        name: &str,
    ) -> Result<Workspace, sqlx::Error> {
        self.inner.update_workspace_name(workspace_id, name).await
    }

    async fn update_workspace_plan(
        &self,
        workspace_id: Uuid,
        plan: &str,
    ) -> Result<Workspace, sqlx::Error> {
        self.inner.update_workspace_plan(workspace_id, plan).await
    }

    async fn get_plan(&self, workspace_id: Uuid) -> Result<PlanTier, sqlx::Error> {
        let _ = workspace_id;
        Ok(self.plan)
    }

    async fn find_workspace(&self, workspace_id: Uuid) -> Result<Option<Workspace>, sqlx::Error> {
        let owner_id = self
            .workspace_owners
            .lock()
            .unwrap()
            .get(&workspace_id)
            .copied()
            .unwrap_or(Uuid::nil());
        let overage_item = self
            .overage_items
            .lock()
            .unwrap()
            .get(&workspace_id)
            .cloned()
            .flatten();

        Ok(Some(Workspace {
            id: workspace_id,
            name: "Static Workspace".into(),
            created_by: owner_id,
            owner_id,
            plan: self.plan.as_str().to_string(),
            stripe_overage_item_id: overage_item,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
            deleted_at: None,
        }))
    }

    async fn set_stripe_overage_item_id(
        &self,
        workspace_id: Uuid,
        subscription_item_id: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        self.overage_items
            .lock()
            .unwrap()
            .insert(workspace_id, subscription_item_id.map(|s| s.to_string()));
        Ok(())
    }

    async fn get_stripe_overage_item_id(
        &self,
        workspace_id: Uuid,
    ) -> Result<Option<String>, sqlx::Error> {
        Ok(self
            .overage_items
            .lock()
            .unwrap()
            .get(&workspace_id)
            .cloned()
            .flatten())
    }

    async fn add_member(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        role: WorkspaceRole,
    ) -> Result<(), sqlx::Error> {
        self.inner.add_member(workspace_id, user_id, role).await
    }

    async fn set_member_role(
        &self,
        workspace_id: Uuid,
        user_id: Uuid,
        role: WorkspaceRole,
    ) -> Result<(), sqlx::Error> {
        self.inner
            .set_member_role(workspace_id, user_id, role)
            .await
    }

    async fn remove_member(&self, workspace_id: Uuid, user_id: Uuid) -> Result<(), sqlx::Error> {
        self.inner.remove_member(workspace_id, user_id).await
    }

    async fn leave_workspace(&self, workspace_id: Uuid, user_id: Uuid) -> Result<(), sqlx::Error> {
        self.inner.leave_workspace(workspace_id, user_id).await
    }

    async fn revoke_member(
        &self,
        workspace_id: Uuid,
        member_id: Uuid,
        revoked_by: Uuid,
        reason: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        self.inner
            .revoke_member(workspace_id, member_id, revoked_by, reason)
            .await
    }

    async fn list_members(
        &self,
        workspace_id: Uuid,
    ) -> Result<Vec<crate::models::workspace::WorkspaceMember>, sqlx::Error> {
        self.inner.list_members(workspace_id).await
    }

    async fn count_members(&self, workspace_id: Uuid) -> Result<i64, sqlx::Error> {
        let count = *self
            .member_counts
            .lock()
            .unwrap()
            .get(&workspace_id)
            .unwrap_or(&0);
        Ok(count)
    }

    async fn count_pending_workspace_invitations(
        &self,
        workspace_id: Uuid,
    ) -> Result<i64, sqlx::Error> {
        let count = *self
            .pending_invites
            .lock()
            .unwrap()
            .get(&workspace_id)
            .unwrap_or(&0);
        Ok(count)
    }

    async fn is_member(&self, _workspace_id: Uuid, _user_id: Uuid) -> Result<bool, sqlx::Error> {
        Ok(self.allowed)
    }

    async fn list_memberships_for_user(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<WorkspaceMembershipSummary>, sqlx::Error> {
        self.inner.list_memberships_for_user(user_id).await
    }

    async fn list_user_workspaces(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<WorkspaceMembershipSummary>, sqlx::Error> {
        self.inner.list_user_workspaces(user_id).await
    }

    async fn create_workspace_invitation(
        &self,
        workspace_id: Uuid,
        email: &str,
        role: WorkspaceRole,
        token: &str,
        expires_at: OffsetDateTime,
        created_by: Uuid,
    ) -> Result<crate::models::workspace::WorkspaceInvitation, sqlx::Error> {
        self.inner
            .create_workspace_invitation(workspace_id, email, role, token, expires_at, created_by)
            .await
    }

    async fn list_workspace_invitations(
        &self,
        workspace_id: Uuid,
    ) -> Result<Vec<crate::models::workspace::WorkspaceInvitation>, sqlx::Error> {
        self.inner.list_workspace_invitations(workspace_id).await
    }

    async fn revoke_workspace_invitation(&self, invite_id: Uuid) -> Result<(), sqlx::Error> {
        self.inner.revoke_workspace_invitation(invite_id).await
    }

    async fn find_invitation_by_token(
        &self,
        token: &str,
    ) -> Result<Option<crate::models::workspace::WorkspaceInvitation>, sqlx::Error> {
        self.inner.find_invitation_by_token(token).await
    }

    async fn mark_invitation_accepted(&self, invite_id: Uuid) -> Result<(), sqlx::Error> {
        self.inner.mark_invitation_accepted(invite_id).await
    }

    async fn mark_invitation_declined(&self, invite_id: Uuid) -> Result<(), sqlx::Error> {
        self.inner.mark_invitation_declined(invite_id).await
    }

    async fn list_pending_invitations_for_email(
        &self,
        email: &str,
    ) -> Result<Vec<crate::models::workspace::WorkspaceInvitation>, sqlx::Error> {
        self.inner.list_pending_invitations_for_email(email).await
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
        _max_runs: i64,
    ) -> Result<WorkspaceRunQuotaUpdate, sqlx::Error> {
        self.period_starts.lock().unwrap().push(period_start);
        if !self.allowed {
            let current = self
                .run_usage
                .lock()
                .unwrap()
                .get(&(workspace_id, period_start.unix_timestamp()))
                .copied()
                .unwrap_or((0, 0));
            return Ok(WorkspaceRunQuotaUpdate {
                allowed: false,
                run_count: current.0,
                overage_count: current.1,
                overage_incremented: false,
            });
        }

        if let Some(limit) = self.max_runs {
            let mut usage = self.run_usage.lock().unwrap();
            let key = (workspace_id, period_start.unix_timestamp());
            let entry = usage.entry(key).or_insert((0, 0));
            entry.0 += 1;
            let mut overage_incremented = false;
            if entry.0 > limit {
                entry.1 += 1;
                overage_incremented = true;
            }
            return Ok(WorkspaceRunQuotaUpdate {
                allowed: entry.0 <= limit,
                run_count: entry.0,
                overage_count: entry.1,
                overage_incremented,
            });
        }

        let mut usage = self.run_usage.lock().unwrap();
        let key = (workspace_id, period_start.unix_timestamp());
        let entry = usage.entry(key).or_insert((0, 0));
        entry.0 += 1;
        Ok(WorkspaceRunQuotaUpdate {
            allowed: self.allowed,
            run_count: entry.0,
            overage_count: entry.1,
            overage_incremented: false,
        })
    }

    async fn get_workspace_run_quota(
        &self,
        workspace_id: Uuid,
        period_start: OffsetDateTime,
    ) -> Result<WorkspaceRunUsage, sqlx::Error> {
        let key = (workspace_id, period_start.unix_timestamp());
        let usage = self.run_usage.lock().unwrap();
        Ok(match usage.get(&key).copied() {
            Some((runs, overage)) => WorkspaceRunUsage {
                run_count: runs,
                overage_count: overage,
            },
            None => WorkspaceRunUsage {
                run_count: 0,
                overage_count: 0,
            },
        })
    }

    async fn release_workspace_run_quota(
        &self,
        workspace_id: Uuid,
        period_start: OffsetDateTime,
        overage_decrement: bool,
    ) -> Result<(), sqlx::Error> {
        *self.release_calls.lock().unwrap() += 1;
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
        *self.billing_cycle.lock().unwrap() = Some(WorkspaceBillingCycle {
            workspace_id,
            stripe_subscription_id: subscription_id.to_string(),
            current_period_start: period_start,
            current_period_end: period_end,
            synced_at: OffsetDateTime::now_utc(),
        });
        Ok(())
    }

    async fn clear_workspace_billing_cycle(&self, _workspace_id: Uuid) -> Result<(), sqlx::Error> {
        *self.billing_cycle.lock().unwrap() = None;
        Ok(())
    }

    async fn get_workspace_billing_cycle(
        &self,
        _workspace_id: Uuid,
    ) -> Result<Option<WorkspaceBillingCycle>, sqlx::Error> {
        Ok(self.billing_cycle.lock().unwrap().clone())
    }
}
