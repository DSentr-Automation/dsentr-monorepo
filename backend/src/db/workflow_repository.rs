use async_trait::async_trait;
use serde_json::Value;
use uuid::Uuid;

use crate::models::workflow::Workflow;
use crate::models::workflow_log::WorkflowLog;
use crate::models::workflow_node_run::WorkflowNodeRun;
use crate::models::workflow_run::WorkflowRun;
use crate::models::workflow_run_event::{NewWorkflowRunEvent, WorkflowRunEvent};
use crate::models::workflow_schedule::WorkflowSchedule;
use time::OffsetDateTime;

#[derive(Debug)]
pub struct CreateWorkflowRunOutcome {
    pub run: WorkflowRun,
    pub created: bool,
}

#[derive(Debug, Clone)]
pub struct WorkspaceMemberRunCount {
    pub user_id: Uuid,
    pub run_count: i64,
}

#[async_trait]
#[cfg_attr(test, mockall::automock)]
#[allow(clippy::too_many_arguments)]
pub trait WorkflowRepository: Send + Sync {
    async fn create_workflow(
        &self,
        user_id: Uuid,
        workspace_id: Option<Uuid>,
        name: &str,
        description: Option<&str>,
        data: Value,
    ) -> Result<Workflow, sqlx::Error>;

    async fn list_workflows_by_user(&self, user_id: Uuid) -> Result<Vec<Workflow>, sqlx::Error>;

    async fn list_workflows_by_workspace_ids(
        &self,
        workspace_ids: &[Uuid],
    ) -> Result<Vec<Workflow>, sqlx::Error>;

    async fn find_workflow_by_id(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
    ) -> Result<Option<Workflow>, sqlx::Error>;

    async fn find_workflow_for_member(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
    ) -> Result<Option<Workflow>, sqlx::Error>;

    async fn find_workflow_by_id_public(
        &self,
        workflow_id: Uuid,
    ) -> Result<Option<Workflow>, sqlx::Error>;

    async fn update_workflow(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        name: &str,
        description: Option<&str>,
        data: Value,
        expected_updated_at: Option<OffsetDateTime>,
    ) -> Result<Option<Workflow>, sqlx::Error>;

    async fn delete_workflow(&self, user_id: Uuid, workflow_id: Uuid) -> Result<bool, sqlx::Error>;

    async fn set_workflow_workspace(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        workspace_id: Option<Uuid>,
    ) -> Result<Option<Workflow>, sqlx::Error>;

    async fn set_workflow_lock(
        &self,
        workflow_id: Uuid,
        locked_by: Option<Uuid>,
    ) -> Result<Option<Workflow>, sqlx::Error>;

    // Logging methods
    async fn insert_workflow_log(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        diffs: serde_json::Value,
    ) -> Result<(), sqlx::Error>;

    async fn list_workflow_logs(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<WorkflowLog>, sqlx::Error>;

    async fn delete_workflow_log(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        log_id: Uuid,
    ) -> Result<bool, sqlx::Error>;

    async fn clear_workflow_logs(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
    ) -> Result<u64, sqlx::Error>;

    // Runs API
    async fn create_workflow_run(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        workspace_id: Option<Uuid>,
        snapshot: Value,
        idempotency_key: Option<&str>,
    ) -> Result<CreateWorkflowRunOutcome, sqlx::Error>;

    #[allow(dead_code)]
    async fn create_workflow_run_unmetered(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        workspace_id: Option<Uuid>,
        snapshot: Value,
        idempotency_key: Option<&str>,
    ) -> Result<CreateWorkflowRunOutcome, sqlx::Error> {
        self.create_workflow_run(
            user_id,
            workflow_id,
            workspace_id,
            snapshot,
            idempotency_key,
        )
        .await
    }

    async fn get_workflow_run(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        run_id: Uuid,
    ) -> Result<Option<WorkflowRun>, sqlx::Error>;

    async fn list_workflow_node_runs(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        run_id: Uuid,
    ) -> Result<Vec<WorkflowNodeRun>, sqlx::Error>;

    async fn record_run_event(
        &self,
        event: NewWorkflowRunEvent,
    ) -> Result<WorkflowRunEvent, sqlx::Error>;

    // Worker helpers
    async fn claim_next_queued_run(&self) -> Result<Option<WorkflowRun>, sqlx::Error>;

    async fn complete_workflow_run(
        &self,
        run_id: Uuid,
        status: &str,
        error: Option<&str>,
    ) -> Result<(), sqlx::Error>;

    async fn pause_workflow_run(
        &self,
        run_id: Uuid,
        snapshot: Value,
        resume_at: OffsetDateTime,
    ) -> Result<(), sqlx::Error>;

    #[allow(dead_code)]
    async fn insert_node_run(
        &self,
        run_id: Uuid,
        node_id: &str,
        name: Option<&str>,
        node_type: Option<&str>,
        inputs: Option<Value>,
        outputs: Option<Value>,
        status: &str,
        error: Option<&str>,
    ) -> Result<WorkflowNodeRun, sqlx::Error>;

    #[allow(dead_code)]
    async fn update_node_run(
        &self,
        node_run_id: Uuid,
        status: &str,
        outputs: Option<Value>,
        error: Option<&str>,
    ) -> Result<(), sqlx::Error>;

    // Idempotent per-node writes: insert or update by (run_id, node_id)
    async fn upsert_node_run(
        &self,
        run_id: Uuid,
        node_id: &str,
        name: Option<&str>,
        node_type: Option<&str>,
        inputs: Option<Value>,
        outputs: Option<Value>,
        status: &str,
        error: Option<&str>,
    ) -> Result<WorkflowNodeRun, sqlx::Error>;

    // Cancel + status helpers
    async fn cancel_workflow_run(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        run_id: Uuid,
    ) -> Result<bool, sqlx::Error>;

    async fn get_run_status(&self, run_id: Uuid) -> Result<Option<String>, sqlx::Error>;

    // Active runs listing (queue view)
    async fn list_active_runs(
        &self,
        user_id: Uuid,
        workflow_id: Option<Uuid>,
    ) -> Result<Vec<WorkflowRun>, sqlx::Error>;

    // Paged runs listing with optional status filters and per-workflow scoping
    async fn list_runs_paged(
        &self,
        user_id: Uuid,
        workflow_id: Option<Uuid>,
        statuses: Option<&[String]>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<WorkflowRun>, sqlx::Error>;

    // Bulk cancel helper for a workflow (queued or running)
    async fn cancel_all_runs_for_workflow(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
    ) -> Result<u64, sqlx::Error>;

    async fn set_run_priority(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        run_id: Uuid,
        priority: i32,
    ) -> Result<bool, sqlx::Error>;

    async fn count_user_runs_since(
        &self,
        user_id: Uuid,
        since: OffsetDateTime,
    ) -> Result<i64, sqlx::Error>;

    async fn count_workspace_runs_since(
        &self,
        workspace_id: Uuid,
        since: OffsetDateTime,
    ) -> Result<i64, sqlx::Error>;

    async fn list_workspace_member_run_counts(
        &self,
        workspace_id: Uuid,
        since: OffsetDateTime,
    ) -> Result<Vec<WorkspaceMemberRunCount>, sqlx::Error>;

    // Concurrency & leasing
    async fn set_workflow_concurrency_limit(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        limit: i32,
    ) -> Result<bool, sqlx::Error>;

    async fn requeue_expired_leases(&self) -> Result<u64, sqlx::Error>;

    async fn upsert_workflow_schedule(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        config: Value,
        next_run_at: Option<OffsetDateTime>,
    ) -> Result<(), sqlx::Error>;

    async fn disable_workflow_schedule(&self, workflow_id: Uuid) -> Result<(), sqlx::Error>;

    async fn get_schedule_for_workflow(
        &self,
        workflow_id: Uuid,
    ) -> Result<Option<WorkflowSchedule>, sqlx::Error>;

    async fn list_due_schedules(&self, limit: i64) -> Result<Vec<WorkflowSchedule>, sqlx::Error>;

    async fn mark_schedule_run(
        &self,
        schedule_id: Uuid,
        last_run_at: OffsetDateTime,
        next_run_at: Option<OffsetDateTime>,
    ) -> Result<(), sqlx::Error>;

    async fn claim_next_eligible_run(
        &self,
        worker_id: &str,
        lease_seconds: i32,
    ) -> Result<Option<WorkflowRun>, sqlx::Error>;

    async fn renew_run_lease(
        &self,
        run_id: Uuid,
        worker_id: &str,
        lease_seconds: i32,
    ) -> Result<(), sqlx::Error>;

    // Retention
    async fn purge_old_runs(&self, retention_days: i32) -> Result<u64, sqlx::Error>;

    // Dead-letter queue
    async fn insert_dead_letter(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        run_id: Uuid,
        error: &str,
        snapshot: Value,
    ) -> Result<(), sqlx::Error>;

    async fn list_dead_letters(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<crate::models::workflow_dead_letter::WorkflowDeadLetter>, sqlx::Error>;

    async fn requeue_dead_letter(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        dead_id: Uuid,
    ) -> Result<Option<WorkflowRun>, sqlx::Error>;

    async fn clear_dead_letters(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
    ) -> Result<u64, sqlx::Error>;

    // Security & Egress
    async fn set_egress_allowlist(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        allowlist: &[String],
    ) -> Result<bool, sqlx::Error>;

    // Egress block events
    async fn insert_egress_block_event(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        run_id: Uuid,
        node_id: &str,
        url: &str,
        host: &str,
        rule: &str,
        message: &str,
    ) -> Result<(), sqlx::Error>;

    async fn list_egress_block_events(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<crate::models::egress_block_event::EgressBlockEvent>, sqlx::Error>;

    async fn clear_egress_block_events(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
    ) -> Result<u64, sqlx::Error>;
}
