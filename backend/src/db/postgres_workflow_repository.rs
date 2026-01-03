use crate::{
    db::workflow_repository::{
        CreateWorkflowRunOutcome, WorkflowRepository, WorkspaceMemberRunCount,
    },
    models::workflow::Workflow,
    models::workflow_dead_letter::WorkflowDeadLetter,
    models::workflow_log::WorkflowLog,
    models::workflow_node_run::WorkflowNodeRun,
    models::workflow_run::WorkflowRun,
    models::workflow_run_event::{NewWorkflowRunEvent, WorkflowRunEvent},
    models::workflow_schedule::WorkflowSchedule,
};
use async_trait::async_trait;
use serde_json::Value;
use sqlx::{PgPool, Row};
use time::OffsetDateTime;
use uuid::Uuid;

pub struct PostgresWorkflowRepository {
    pub pool: PgPool,
}

#[async_trait]
impl WorkflowRepository for PostgresWorkflowRepository {
    async fn create_workflow(
        &self,
        user_id: Uuid,
        workspace_id: Option<Uuid>,
        name: &str,
        description: Option<&str>,
        data: Value,
    ) -> Result<Workflow, sqlx::Error> {
        let result = sqlx::query_as::<_, Workflow>(
            r#"
            INSERT INTO workflows (user_id, workspace_id, name, description, data, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, now(), now())
            RETURNING id, user_id, workspace_id, name, description, data, concurrency_limit, egress_allowlist, locked_by, locked_at, created_at, updated_at
            "#
        )
        .bind(user_id)
        .bind(workspace_id)
        .bind(name)
        .bind(description)
        .bind(data)
        .fetch_one(&self.pool)
        .await?;

        Ok(result)
    }

    async fn list_workflows_by_user(&self, user_id: Uuid) -> Result<Vec<Workflow>, sqlx::Error> {
        let results = sqlx::query_as::<_, Workflow>(
            r#"
            SELECT id,
                   user_id,
                   workspace_id,
                   name,
                   description,
                   data,
                   concurrency_limit,
                   egress_allowlist,
                   locked_by,
                   locked_at,
                   created_at,
                   updated_at
            FROM workflows
            WHERE user_id = $1
            ORDER BY updated_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    async fn find_workflow_by_id(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
    ) -> Result<Option<Workflow>, sqlx::Error> {
        let result = sqlx::query_as::<_, Workflow>(
            r#"
            SELECT id,
                   user_id,
                   workspace_id,
                   name,
                   description,
                   data,
                   concurrency_limit,
                   egress_allowlist,
                   locked_by,
                   locked_at,
                   created_at,
                   updated_at
            FROM workflows
            WHERE user_id = $1 AND id = $2
            "#,
        )
        .bind(user_id)
        .bind(workflow_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    async fn find_workflow_by_id_public(
        &self,
        workflow_id: Uuid,
    ) -> Result<Option<Workflow>, sqlx::Error> {
        let result = sqlx::query_as::<_, Workflow>(
            r#"
            SELECT id,
                   user_id,
                   workspace_id,
                   name,
                   description,
                   data,
                   concurrency_limit,
                   egress_allowlist,
                   locked_by,
                   locked_at,
                   created_at,
                   updated_at
            FROM workflows
            WHERE id = $1
            "#,
        )
        .bind(workflow_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    async fn update_workflow(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        name: &str,
        description: Option<&str>,
        data: Value,
        expected_updated_at: Option<OffsetDateTime>,
    ) -> Result<Option<Workflow>, sqlx::Error> {
        let result = if let Some(expected) = expected_updated_at {
            sqlx::query_as::<_, Workflow>(
                r#"
                UPDATE workflows
                SET name = $3,
                    description = $4,
                    data = $5,
                    updated_at = now()
                WHERE user_id = $1 AND id = $2 AND updated_at = $6
                RETURNING id, user_id, workspace_id, name, description, data, concurrency_limit, egress_allowlist, locked_by, locked_at, created_at, updated_at
                "#
            )
            .bind(user_id)
            .bind(workflow_id)
            .bind(name)
            .bind(description)
            .bind(data)
            .bind(expected)
            .fetch_optional(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, Workflow>(
                r#"
                UPDATE workflows
                SET name = $3,
                    description = $4,
                    data = $5,
                    updated_at = now()
                WHERE user_id = $1 AND id = $2
                RETURNING id, user_id, workspace_id, name, description, data, concurrency_limit, egress_allowlist, locked_by, locked_at, created_at, updated_at
                "#
            )
            .bind(user_id)
            .bind(workflow_id)
            .bind(name)
            .bind(description)
            .bind(data)
            .fetch_optional(&self.pool)
            .await?
        };

        Ok(result)
    }

    async fn list_workflows_by_workspace_ids(
        &self,
        workspace_ids: &[Uuid],
    ) -> Result<Vec<Workflow>, sqlx::Error> {
        if workspace_ids.is_empty() {
            return Ok(vec![]);
        }

        let results = sqlx::query_as::<_, Workflow>(
            r#"
            SELECT id,
                   user_id,
                   workspace_id,
                   name,
                   description,
                   data,
                   concurrency_limit,
                   egress_allowlist,
                   locked_by,
                   locked_at,
                   created_at,
                   updated_at
            FROM workflows
            WHERE workspace_id = ANY($1)
            ORDER BY updated_at DESC
            "#,
        )
        .bind(workspace_ids)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    async fn find_workflow_for_member(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
    ) -> Result<Option<Workflow>, sqlx::Error> {
        let result = sqlx::query_as::<_, Workflow>(
            r#"
            SELECT id,
                   user_id,
                   workspace_id,
                   name,
                   description,
                   data,
                   concurrency_limit,
                   egress_allowlist,
                   locked_by,
                   locked_at,
                   created_at,
                   updated_at
            FROM workflows w
            WHERE w.id = $2
              AND (
                    w.user_id = $1
                    OR (
                        w.workspace_id IS NOT NULL
                        AND EXISTS (
                            SELECT 1
                            FROM workspace_members wm
                            WHERE wm.workspace_id = w.workspace_id
                              AND wm.user_id = $1
                        )
                    )
              )
            "#,
        )
        .bind(user_id)
        .bind(workflow_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    async fn delete_workflow(&self, user_id: Uuid, workflow_id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query!(
            r#"
            DELETE FROM workflows
            WHERE user_id = $1 AND id = $2
            "#,
            user_id,
            workflow_id
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    async fn set_workflow_workspace(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        workspace_id: Option<Uuid>,
    ) -> Result<Option<Workflow>, sqlx::Error> {
        let result = sqlx::query_as::<_, Workflow>(
            r#"
            UPDATE workflows
            SET workspace_id = $3,
                updated_at = now()
            WHERE user_id = $1 AND id = $2
            RETURNING id, user_id, workspace_id, name, description, data, concurrency_limit, egress_allowlist, locked_by, locked_at, created_at, updated_at
            "#
        )
        .bind(user_id)
        .bind(workflow_id)
        .bind(workspace_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    async fn set_workflow_lock(
        &self,
        workflow_id: Uuid,
        locked_by: Option<Uuid>,
    ) -> Result<Option<Workflow>, sqlx::Error> {
        let result = sqlx::query_as::<_, Workflow>(
            r#"
            UPDATE workflows
            SET locked_by = $2,
                locked_at = CASE WHEN $2 IS NULL THEN NULL ELSE now() END,
                updated_at = now()
            WHERE id = $1
            RETURNING id, user_id, workspace_id, name, description, data, concurrency_limit, egress_allowlist, locked_by, locked_at, created_at, updated_at
            "#,
        )
        .bind(workflow_id)
        .bind(locked_by)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    async fn insert_workflow_log(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        diffs: serde_json::Value,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            INSERT INTO workflow_logs (user_id, workflow_id, diffs)
            VALUES ($1, $2, $3)
            "#,
            user_id,
            workflow_id,
            diffs
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_workflow_logs(
        &self,
        _user_id: Uuid,
        workflow_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<WorkflowLog>, sqlx::Error> {
        let rows = sqlx::query_as!(
            WorkflowLog,
            r#"
            SELECT id, user_id, workflow_id, created_at, diffs
            FROM workflow_logs
            WHERE workflow_id = $1
            ORDER BY created_at DESC
            LIMIT $2 OFFSET $3
            "#,
            workflow_id,
            limit,
            offset
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    async fn delete_workflow_log(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        log_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let res = sqlx::query!(
            r#"
            DELETE FROM workflow_logs
            WHERE user_id = $1 AND workflow_id = $2 AND id = $3
            "#,
            user_id,
            workflow_id,
            log_id
        )
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn clear_workflow_logs(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let res = sqlx::query!(
            r#"
            DELETE FROM workflow_logs
            WHERE user_id = $1 AND workflow_id = $2
            "#,
            user_id,
            workflow_id
        )
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    async fn create_workflow_run(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        workspace_id: Option<Uuid>,
        snapshot: Value,
        idempotency_key: Option<&str>,
    ) -> Result<CreateWorkflowRunOutcome, sqlx::Error> {
        // Try insert; if unique violation on idempotency, fetch existing
        let insert_res = sqlx::query_as!(
            WorkflowRun,
            r#"
            INSERT INTO workflow_runs (user_id, workflow_id, workspace_id, snapshot, status, idempotency_key, started_at, resume_at, created_at, updated_at)
            VALUES ($1, $2, $3, $4, 'queued', $5, now(), now(), now(), now())
            RETURNING id, user_id, workflow_id, workspace_id, snapshot, status, error, idempotency_key,
                      started_at as "started_at!", resume_at as "resume_at!", finished_at, created_at as "created_at!", updated_at as "updated_at!"
            "#,
            user_id,
            workflow_id,
            workspace_id,
            snapshot,
            idempotency_key
        )
        .fetch_one(&self.pool)
        .await;

        match insert_res {
            Ok(run) => Ok(CreateWorkflowRunOutcome { run, created: true }),
            Err(e) => {
                // Check for unique violation (idempotency)
                let is_unique = matches!(&e, sqlx::Error::Database(db)
                    if db.code().map(|c| c == "23505").unwrap_or(false));
                if is_unique {
                    // Return the existing run for this key
                    let existing = sqlx::query_as!(
                        WorkflowRun,
                        r#"
                        SELECT id, user_id, workflow_id, workspace_id, snapshot, status, error, idempotency_key,
                               started_at as "started_at!", resume_at as "resume_at!", finished_at, created_at as "created_at!", updated_at as "updated_at!"
                        FROM workflow_runs
                        WHERE workflow_id = $1
                          AND COALESCE(workspace_id, user_id) = COALESCE($3::uuid, $2)
                          AND idempotency_key = $4
                        ORDER BY created_at DESC
                        LIMIT 1
                        "#,
                        workflow_id,
                        user_id,
                        workspace_id,
                        idempotency_key
                    )
                    .fetch_one(&self.pool)
                    .await?;
                    Ok(CreateWorkflowRunOutcome {
                        run: existing,
                        created: false,
                    })
                } else {
                    Err(e)
                }
            }
        }
    }

    async fn get_workflow_run(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        run_id: Uuid,
    ) -> Result<Option<WorkflowRun>, sqlx::Error> {
        let row = sqlx::query_as!(
            WorkflowRun,
            r#"
            SELECT id, user_id, workflow_id, workspace_id, snapshot, status, error, idempotency_key,
                   started_at as "started_at!", resume_at as "resume_at!", finished_at, created_at as "created_at!", updated_at as "updated_at!"
            FROM workflow_runs
            WHERE user_id = $1 AND workflow_id = $2 AND id = $3
            "#,
            user_id,
            workflow_id,
            run_id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    async fn list_workflow_node_runs(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        run_id: Uuid,
    ) -> Result<Vec<WorkflowNodeRun>, sqlx::Error> {
        let rows = sqlx::query_as!(
            WorkflowNodeRun,
            r#"
            SELECT nr.id, nr.run_id, nr.node_id, nr.name, nr.node_type, nr.inputs, nr.outputs, nr.status, nr.error,
                   nr.started_at as "started_at!", nr.finished_at, nr.created_at as "created_at!", nr.updated_at as "updated_at!"
            FROM workflow_node_runs nr
            JOIN workflow_runs r ON r.id = nr.run_id
            WHERE r.user_id = $1 AND r.workflow_id = $2 AND r.id = $3
            ORDER BY nr.started_at ASC
            "#,
            user_id,
            workflow_id,
            run_id
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    async fn record_run_event(
        &self,
        event: NewWorkflowRunEvent,
    ) -> Result<WorkflowRunEvent, sqlx::Error> {
        let NewWorkflowRunEvent {
            workflow_run_id,
            workflow_id,
            workspace_id,
            triggered_by,
            connection_type,
            connection_id,
            recorded_at,
        } = event;

        let recorded_at = recorded_at.unwrap_or_else(OffsetDateTime::now_utc);

        let row = sqlx::query_as::<_, WorkflowRunEvent>(
            r#"
            INSERT INTO workflow_run_events (
                workflow_run_id,
                workflow_id,
                workspace_id,
                triggered_by,
                connection_type,
                connection_id,
                recorded_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id, workflow_run_id, workflow_id, workspace_id, triggered_by, connection_type, connection_id, recorded_at
            "#,
        )
        .bind(workflow_run_id)
        .bind(workflow_id)
        .bind(workspace_id)
        .bind(triggered_by)
        .bind(connection_type)
        .bind(connection_id)
        .bind(recorded_at)
        .fetch_one(&self.pool)
        .await?;

        Ok(row)
    }

    async fn claim_next_queued_run(&self) -> Result<Option<WorkflowRun>, sqlx::Error> {
        // Atomically claim one queued run and mark as running
        let row = sqlx::query_as!(
            WorkflowRun,
            r#"
            WITH sel AS (
              SELECT id
              FROM workflow_runs
              WHERE status = 'queued'
                AND resume_at <= now()
              ORDER BY created_at ASC
              LIMIT 1
              FOR UPDATE SKIP LOCKED
            )
            UPDATE workflow_runs wr
            SET status = 'running', resume_at = now(), updated_at = now()
            FROM sel
            WHERE wr.id = sel.id
            RETURNING wr.id, wr.user_id, wr.workflow_id, wr.workspace_id, wr.snapshot, wr.status, wr.error, wr.idempotency_key,
                      wr.started_at as "started_at!", wr.resume_at as "resume_at!", wr.finished_at, wr.created_at as "created_at!", wr.updated_at as "updated_at!"
            "#
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    async fn complete_workflow_run(
        &self,
        run_id: Uuid,
        status: &str,
        error: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE workflow_runs
            SET status = $2,
                error = $3,
                finished_at = COALESCE(finished_at, now()),
                updated_at = now()
            WHERE id = $1
            "#,
            run_id,
            status,
            error
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn pause_workflow_run(
        &self,
        run_id: Uuid,
        snapshot: Value,
        resume_at: OffsetDateTime,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE workflow_runs
            SET status = 'queued',
                snapshot = $2,
                resume_at = $3,
                leased_by = NULL,
                lease_expires_at = NULL,
                heartbeat_at = NULL,
                updated_at = now()
            WHERE id = $1
            "#,
            run_id,
            snapshot,
            resume_at
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

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
    ) -> Result<WorkflowNodeRun, sqlx::Error> {
        let row = sqlx::query_as!(
            WorkflowNodeRun,
            r#"
            INSERT INTO workflow_node_runs (run_id, node_id, name, node_type, inputs, outputs, status, error, started_at, finished_at, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
                    now(),
                    CASE WHEN $7 IN ('succeeded','failed','skipped','canceled') THEN now() ELSE NULL END,
                    now(), now())
            RETURNING id, run_id, node_id, name, node_type, inputs, outputs, status, error,
                      started_at as "started_at!", finished_at, created_at as "created_at!", updated_at as "updated_at!"
            "#,
            run_id,
            node_id,
            name,
            node_type,
            inputs,
            outputs,
            status,
            error
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    async fn update_node_run(
        &self,
        node_run_id: Uuid,
        status: &str,
        outputs: Option<Value>,
        error: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE workflow_node_runs
            SET status = $2,
                outputs = $3,
                error = $4,
                finished_at = COALESCE(finished_at, now()),
                updated_at = now()
            WHERE id = $1
            "#,
            node_run_id,
            status,
            outputs,
            error
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

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
    ) -> Result<WorkflowNodeRun, sqlx::Error> {
        let row = sqlx::query_as::<_, WorkflowNodeRun>(
            r#"
            INSERT INTO workflow_node_runs (run_id, node_id, name, node_type, inputs, outputs, status, error, started_at, finished_at, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8,
                    now(),
                    CASE WHEN $7 IN ('succeeded','failed','skipped','canceled') THEN now() ELSE NULL END,
                    now(), now())
            ON CONFLICT (run_id, node_id) DO UPDATE SET
                name = COALESCE(EXCLUDED.name, workflow_node_runs.name),
                node_type = COALESCE(EXCLUDED.node_type, workflow_node_runs.node_type),
                inputs = COALESCE(EXCLUDED.inputs, workflow_node_runs.inputs),
                outputs = COALESCE(EXCLUDED.outputs, workflow_node_runs.outputs),
                status = EXCLUDED.status,
                error = COALESCE(EXCLUDED.error, workflow_node_runs.error),
                finished_at = CASE
                    WHEN EXCLUDED.status IN ('succeeded','failed','skipped','canceled') THEN COALESCE(workflow_node_runs.finished_at, now())
                    ELSE workflow_node_runs.finished_at
                END,
                updated_at = now()
            RETURNING id, run_id, node_id, name, node_type, inputs, outputs, status, error,
                      started_at, finished_at, created_at, updated_at
            "#
        )
        .bind(run_id)
        .bind(node_id)
        .bind(name)
        .bind(node_type)
        .bind(inputs)
        .bind(outputs)
        .bind(status)
        .bind(error)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    async fn cancel_workflow_run(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        run_id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let res = sqlx::query!(
            r#"
            UPDATE workflow_runs
            SET status = 'canceled', finished_at = now(), updated_at = now()
            WHERE id = $1 AND user_id = $2 AND workflow_id = $3 AND status IN ('queued','running')
            "#,
            run_id,
            user_id,
            workflow_id
        )
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn get_run_status(&self, run_id: Uuid) -> Result<Option<String>, sqlx::Error> {
        let row = sqlx::query!(
            r#"
            SELECT status FROM workflow_runs WHERE id = $1
            "#,
            run_id
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.status))
    }

    async fn list_active_runs(
        &self,
        user_id: Uuid,
        workflow_id: Option<Uuid>,
    ) -> Result<Vec<WorkflowRun>, sqlx::Error> {
        if let Some(wf) = workflow_id {
            let rows = sqlx::query_as!(
                WorkflowRun,
                r#"
                SELECT id, user_id, workflow_id, workspace_id, snapshot, status, error, idempotency_key,
                       started_at as "started_at!", resume_at as "resume_at!", finished_at,
                       created_at as "created_at!", updated_at as "updated_at!"
                FROM workflow_runs
                WHERE user_id = $1
                  AND workflow_id = $2
                  AND status IN ('queued','running')
                ORDER BY started_at ASC
                "#,
                user_id,
                wf
            )
            .fetch_all(&self.pool)
            .await?;
            Ok(rows)
        } else {
            let rows = sqlx::query_as!(
                WorkflowRun,
                r#"
                SELECT id, user_id, workflow_id, workspace_id, snapshot, status, error, idempotency_key,
                       started_at as "started_at!", resume_at as "resume_at!", finished_at,
                       created_at as "created_at!", updated_at as "updated_at!"
                FROM workflow_runs
                WHERE user_id = $1
                  AND status IN ('queued','running')
                ORDER BY started_at ASC
                "#,
                user_id
            )
            .fetch_all(&self.pool)
            .await?;
            Ok(rows)
        }
    }

    async fn list_runs_paged(
        &self,
        user_id: Uuid,
        workflow_id: Option<Uuid>,
        statuses: Option<&[String]>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<WorkflowRun>, sqlx::Error> {
        // Build dynamic WHERE with optional workflow and statuses
        // For statuses, we use ANY($N)
        if let Some(wf) = workflow_id {
            if let Some(sts) = statuses {
                let rows = sqlx::query_as!(
                    WorkflowRun,
                    r#"
                    SELECT id, user_id, workflow_id, workspace_id, snapshot, status, error, idempotency_key,
                           started_at as "started_at!", resume_at as "resume_at!", finished_at,
                           created_at as "created_at!", updated_at as "updated_at!"
                    FROM workflow_runs
                    WHERE user_id = $1 AND workflow_id = $2
                      AND ($3::text[] IS NULL OR status = ANY($3))
                    ORDER BY created_at DESC
                    LIMIT $4 OFFSET $5
                    "#,
                    user_id,
                    wf,
                    sts,
                    limit,
                    offset
                )
                .fetch_all(&self.pool)
                .await?;
                Ok(rows)
            } else {
                let rows = sqlx::query_as!(
                    WorkflowRun,
                    r#"
                    SELECT id, user_id, workflow_id, workspace_id, snapshot, status, error, idempotency_key,
                           started_at as "started_at!", resume_at as "resume_at!", finished_at,
                           created_at as "created_at!", updated_at as "updated_at!"
                    FROM workflow_runs
                    WHERE user_id = $1 AND workflow_id = $2
                    ORDER BY created_at DESC
                    LIMIT $3 OFFSET $4
                    "#,
                    user_id,
                    wf,
                    limit,
                    offset
                )
                .fetch_all(&self.pool)
                .await?;
                Ok(rows)
            }
        } else if let Some(sts) = statuses {
            let rows = sqlx::query_as::<_, WorkflowRun>(
                r#"
                SELECT id, user_id, workflow_id, workspace_id, snapshot, status, error, idempotency_key,
                       started_at as "started_at!", resume_at as "resume_at!", finished_at,
                       created_at as "created_at!", updated_at as "updated_at!"
                FROM workflow_runs
                WHERE user_id = $1
                  AND ($2::text[] IS NULL OR status = ANY($2))
                ORDER BY created_at DESC
                LIMIT $3 OFFSET $4
                "#,
            )
            .bind(user_id)
            .bind(sts)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?;
            Ok(rows)
        } else {
            let rows = sqlx::query_as::<_, WorkflowRun>(
                r#"
                SELECT id, user_id, workflow_id, workspace_id, snapshot, status, error, idempotency_key,
                       started_at as "started_at!", resume_at as "resume_at!", finished_at,
                       created_at as "created_at!", updated_at as "updated_at!"
                FROM workflow_runs
                WHERE user_id = $1
                ORDER BY created_at DESC
                LIMIT $2 OFFSET $3
                "#,
            )
            .bind(user_id)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?;
            Ok(rows)
        }
    }

    async fn cancel_all_runs_for_workflow(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let res = sqlx::query!(
            r#"
            UPDATE workflow_runs
            SET status = 'canceled', finished_at = now(), updated_at = now()
            WHERE user_id = $1 AND workflow_id = $2 AND status IN ('queued','running')
            "#,
            user_id,
            workflow_id
        )
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    async fn set_run_priority(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        run_id: Uuid,
        priority: i32,
    ) -> Result<bool, sqlx::Error> {
        let res = sqlx::query(
            r#"
            UPDATE workflow_runs
            SET queue_priority = $4, updated_at = now()
            WHERE id = $3 AND user_id = $1 AND workflow_id = $2
            "#,
        )
        .bind(user_id)
        .bind(workflow_id)
        .bind(run_id)
        .bind(priority)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn count_user_runs_since(
        &self,
        user_id: Uuid,
        since: OffsetDateTime,
    ) -> Result<i64, sqlx::Error> {
        let count = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*)::bigint
            FROM workflow_runs
            WHERE user_id = $1 AND created_at >= $2
            "#,
            user_id,
            since
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(count.unwrap_or(0))
    }

    async fn count_workspace_runs_since(
        &self,
        workspace_id: Uuid,
        since: OffsetDateTime,
    ) -> Result<i64, sqlx::Error> {
        let count = sqlx::query_scalar!(
            r#"
            SELECT COUNT(*)::bigint
            FROM workflow_runs
            WHERE workspace_id = $1 AND created_at >= $2
            "#,
            workspace_id,
            since
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(count.unwrap_or(0))
    }

    async fn list_workspace_member_run_counts(
        &self,
        workspace_id: Uuid,
        since: OffsetDateTime,
    ) -> Result<Vec<WorkspaceMemberRunCount>, sqlx::Error> {
        let rows = sqlx::query_as::<_, (Uuid, i64)>(
            r#"
            SELECT user_id, COUNT(*)::bigint as run_count
            FROM workflow_runs
            WHERE workspace_id = $1 AND created_at >= $2
            GROUP BY user_id
            "#,
        )
        .bind(workspace_id)
        .bind(since)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(user_id, run_count)| WorkspaceMemberRunCount { user_id, run_count })
            .collect())
    }

    async fn set_workflow_concurrency_limit(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        limit: i32,
    ) -> Result<bool, sqlx::Error> {
        let res = sqlx::query(
            r#"
            UPDATE workflows
            SET concurrency_limit = $3, updated_at = now()
            WHERE id = $2 AND user_id = $1
            "#,
        )
        .bind(user_id)
        .bind(workflow_id)
        .bind(limit)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn requeue_expired_leases(&self) -> Result<u64, sqlx::Error> {
        let res = sqlx::query(
            r#"
            UPDATE workflow_runs
            SET status = 'queued', leased_by = NULL, lease_expires_at = NULL, resume_at = LEAST(resume_at, now())
            WHERE status = 'running' AND lease_expires_at IS NOT NULL AND lease_expires_at < now()
            "#,
        )
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    async fn claim_next_eligible_run(
        &self,
        worker_id: &str,
        lease_seconds: i32,
    ) -> Result<Option<WorkflowRun>, sqlx::Error> {
        let row = sqlx::query(
            r#"
            WITH sel AS (
              SELECT wr.id
              FROM workflow_runs wr
              JOIN workflows wf ON wf.id = wr.workflow_id
              WHERE wr.status = 'queued'
                AND wr.resume_at <= now()
                AND (
                  SELECT COUNT(*) FROM workflow_runs r2
                  WHERE r2.workflow_id = wr.workflow_id AND r2.status = 'running'
                ) < COALESCE(wf.concurrency_limit, 1)
              ORDER BY COALESCE(wr.queue_priority, 0) DESC, wr.created_at ASC
              LIMIT 1
              FOR UPDATE SKIP LOCKED
            )
            UPDATE workflow_runs wr
            SET status = 'running',
                leased_by = $1,
                heartbeat_at = now(),
                lease_expires_at = now() + ($2::int * INTERVAL '1 second'),
                attempt = COALESCE(wr.attempt, 0) + 1,
                resume_at = now(),
                updated_at = now()
            FROM sel
            WHERE wr.id = sel.id
            RETURNING wr.id, wr.user_id, wr.workflow_id, wr.workspace_id, wr.snapshot, wr.status, wr.error, wr.idempotency_key,
                      wr.started_at as started_at, wr.resume_at as resume_at, wr.finished_at, wr.created_at as created_at, wr.updated_at as updated_at
            "#
        )
        .bind(worker_id)
        .bind(lease_seconds)
        .fetch_optional(&self.pool)
        .await?;
        let mapped = row.map(|r| WorkflowRun {
            id: r.get("id"),
            user_id: r.get("user_id"),
            workflow_id: r.get("workflow_id"),
            workspace_id: r.get("workspace_id"),
            snapshot: r.get("snapshot"),
            status: r.get("status"),
            error: r.get("error"),
            idempotency_key: r.get("idempotency_key"),
            started_at: r.get("started_at"),
            resume_at: r.get("resume_at"),
            finished_at: r.get("finished_at"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        });
        Ok(mapped)
    }

    async fn renew_run_lease(
        &self,
        run_id: Uuid,
        worker_id: &str,
        lease_seconds: i32,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE workflow_runs
            SET heartbeat_at = now(),
                lease_expires_at = now() + ($3::int * INTERVAL '1 second'),
                updated_at = now()
            WHERE id = $1 AND leased_by = $2
            "#,
        )
        .bind(run_id)
        .bind(worker_id)
        .bind(lease_seconds)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn purge_old_runs(&self, retention_days: i32) -> Result<u64, sqlx::Error> {
        let res = sqlx::query(
            r#"
            DELETE FROM workflow_runs
            WHERE status IN ('succeeded','failed','canceled')
              AND created_at < now() - ($1::int * INTERVAL '1 day')
            "#,
        )
        .bind(retention_days)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    async fn insert_dead_letter(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        run_id: Uuid,
        error: &str,
        snapshot: Value,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO workflow_dead_letters (user_id, workflow_id, run_id, error, snapshot, created_at)
            VALUES ($1, $2, $3, $4, $5, now())
            "#
        )
        .bind(user_id)
        .bind(workflow_id)
        .bind(run_id)
        .bind(error)
        .bind(snapshot)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_dead_letters(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<WorkflowDeadLetter>, sqlx::Error> {
        let rows = sqlx::query_as::<_, WorkflowDeadLetter>(
            r#"
            SELECT id, user_id, workflow_id, run_id, error, snapshot, created_at
            FROM workflow_dead_letters
            WHERE user_id = $1 AND workflow_id = $2
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(user_id)
        .bind(workflow_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    async fn requeue_dead_letter(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        dead_id: Uuid,
    ) -> Result<Option<WorkflowRun>, sqlx::Error> {
        let maybe = sqlx::query_as::<_, WorkflowDeadLetter>(
            r#"
            SELECT id, user_id, workflow_id, run_id, error, snapshot, created_at
            FROM workflow_dead_letters
            WHERE id = $1 AND user_id = $2 AND workflow_id = $3
            "#,
        )
        .bind(dead_id)
        .bind(user_id)
        .bind(workflow_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(dl) = maybe {
            // Refresh allowlist in snapshot before requeue
            let wf_row = sqlx::query!(
                r#"
                SELECT workspace_id, egress_allowlist
                FROM workflows
                WHERE id = $1
                "#,
                workflow_id
            )
            .fetch_one(&self.pool)
            .await?;
            let mut new_snapshot = dl.snapshot.clone();
            let v = serde_json::Value::Array(
                wf_row
                    .egress_allowlist
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            );
            if let serde_json::Value::Object(ref mut map) = new_snapshot {
                map.insert("_egress_allowlist".to_string(), v);
            }
            let new_run_row = sqlx::query(
                r#"
                INSERT INTO workflow_runs (user_id, workflow_id, workspace_id, snapshot, status, started_at, resume_at, created_at, updated_at)
                VALUES ($1, $2, $3, $4, 'queued', now(), now(), now(), now())
                RETURNING id, user_id, workflow_id, workspace_id, snapshot, status, error, idempotency_key,
                          started_at, resume_at, finished_at, created_at, updated_at
                "#
            )
            .bind(user_id)
            .bind(workflow_id)
            .bind(wf_row.workspace_id)
            .bind(new_snapshot)
            .fetch_one(&self.pool)
            .await?;
            let new_run = WorkflowRun {
                id: new_run_row.get("id"),
                user_id: new_run_row.get("user_id"),
                workflow_id: new_run_row.get("workflow_id"),
                workspace_id: new_run_row.get("workspace_id"),
                snapshot: new_run_row.get("snapshot"),
                status: new_run_row.get("status"),
                error: new_run_row.get("error"),
                idempotency_key: new_run_row.get("idempotency_key"),
                started_at: new_run_row.get("started_at"),
                resume_at: new_run_row.get("resume_at"),
                finished_at: new_run_row.get("finished_at"),
                created_at: new_run_row.get("created_at"),
                updated_at: new_run_row.get("updated_at"),
            };

            // Remove dead letter entry
            let _ = sqlx::query(r#"DELETE FROM workflow_dead_letters WHERE id = $1"#)
                .bind(dl.id)
                .execute(&self.pool)
                .await?;

            Ok(Some(new_run))
        } else {
            Ok(None)
        }
    }

    async fn clear_dead_letters(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let res = sqlx::query(
            r#"
            DELETE FROM workflow_dead_letters
            WHERE user_id = $1 AND workflow_id = $2
            "#,
        )
        .bind(user_id)
        .bind(workflow_id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    async fn set_egress_allowlist(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        allowlist: &[String],
    ) -> Result<bool, sqlx::Error> {
        let res = sqlx::query(
            r#"
            UPDATE workflows
            SET egress_allowlist = $3::text[], updated_at = now()
            WHERE user_id = $1 AND id = $2
            "#,
        )
        .bind(user_id)
        .bind(workflow_id)
        .bind(allowlist)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

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
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO egress_block_events (user_id, workflow_id, run_id, node_id, url, host, rule, message, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
            "#
        )
        .bind(user_id)
        .bind(workflow_id)
        .bind(run_id)
        .bind(node_id)
        .bind(url)
        .bind(host)
        .bind(rule)
        .bind(message)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_egress_block_events(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<crate::models::egress_block_event::EgressBlockEvent>, sqlx::Error> {
        let rows = sqlx::query_as::<_, crate::models::egress_block_event::EgressBlockEvent>(
            r#"
            SELECT id, user_id, workflow_id, run_id, node_id, url, host, rule, message, created_at
            FROM egress_block_events
            WHERE user_id = $1 AND workflow_id = $2
            ORDER BY created_at DESC
            LIMIT $3 OFFSET $4
            "#,
        )
        .bind(user_id)
        .bind(workflow_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    async fn clear_egress_block_events(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
    ) -> Result<u64, sqlx::Error> {
        let res = sqlx::query(
            r#"
            DELETE FROM egress_block_events
            WHERE user_id = $1 AND workflow_id = $2
            "#,
        )
        .bind(user_id)
        .bind(workflow_id)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    async fn upsert_workflow_schedule(
        &self,
        user_id: Uuid,
        workflow_id: Uuid,
        config: serde_json::Value,
        next_run_at: Option<OffsetDateTime>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            INSERT INTO workflow_schedules (workflow_id, user_id, config, next_run_at, enabled)
            VALUES ($1, $2, $3, $4, true)
            ON CONFLICT (workflow_id)
            DO UPDATE SET
                config = EXCLUDED.config,
                next_run_at = EXCLUDED.next_run_at,
                enabled = EXCLUDED.enabled,
                updated_at = now()
            "#,
            workflow_id,
            user_id,
            config,
            next_run_at
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn disable_workflow_schedule(&self, workflow_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            UPDATE workflow_schedules
            SET enabled = false,
                next_run_at = NULL,
                updated_at = now()
            WHERE workflow_id = $1
            "#,
            workflow_id
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_schedule_for_workflow(
        &self,
        workflow_id: Uuid,
    ) -> Result<Option<WorkflowSchedule>, sqlx::Error> {
        let row = sqlx::query_as::<_, WorkflowSchedule>(
            r#"
            SELECT id, workflow_id, user_id, config, next_run_at, last_run_at, enabled, created_at, updated_at
            FROM workflow_schedules
            WHERE workflow_id = $1
            "#,
        )
        .bind(workflow_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    async fn list_due_schedules(&self, limit: i64) -> Result<Vec<WorkflowSchedule>, sqlx::Error> {
        let rows = sqlx::query_as::<_, WorkflowSchedule>(
            r#"
            SELECT id, workflow_id, user_id, config, next_run_at, last_run_at, enabled, created_at, updated_at
            FROM workflow_schedules
            WHERE enabled = true
              AND next_run_at IS NOT NULL
              AND next_run_at <= now()
            ORDER BY next_run_at ASC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    async fn mark_schedule_run(
        &self,
        schedule_id: Uuid,
        last_run_at: OffsetDateTime,
        next_run_at: Option<OffsetDateTime>,
    ) -> Result<(), sqlx::Error> {
        let should_enable = next_run_at.is_some();
        sqlx::query!(
            r#"
            UPDATE workflow_schedules
            SET last_run_at = $2,
                next_run_at = $3,
                enabled = $4,
                updated_at = now()
            WHERE id = $1
            "#,
            schedule_id,
            last_run_at,
            next_run_at,
            should_enable
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
