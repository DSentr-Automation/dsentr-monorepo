import { API_BASE_URL } from './config'
import { getCsrfToken } from './csrfCache'

export const RUNAWAY_PROTECTION_ERROR = 'runaway_protection_triggered'

export interface WorkflowRecord {
  id: string
  name: string
  description: string | null
  data: any
  user_id?: string
  workspace_id?: string | null
  locked_by?: string | null
  locked_at?: string | null
  created_at?: string
  updated_at?: string
}

export interface WorkflowPayload {
  name: string
  description: string | null
  data: Record<string, any>
  workspace_id?: string | null
}

export interface WorkflowLogEntry {
  id: string
  workflow_id: string
  user_id: string
  created_at: string
  diffs: any
}

export interface WorkspaceMemberRunUsage {
  user_id: string
  runs: number
  first_name?: string | null
  last_name?: string | null
  email?: string | null
}

export interface PlanUsageSummary {
  plan: string
  runs: {
    used: number
    limit?: number
    period_start: string
  }
  workflows: {
    total: number
    limit?: number
    hidden?: number
  }
  workspace?: {
    id?: string
    plan?: string
    runs?: {
      used: number
      limit?: number
      overage?: number
      period_start?: string
    }
    members?: {
      used: number
      limit?: number
    }
    member_usage?: WorkspaceMemberRunUsage[]
  }
}

async function handleJsonResponse(response: Response) {
  let body: any = null

  try {
    body = await response.json()
  } catch (error) {
    // ignore JSON parse errors and fall through
  }

  if (!response.ok || (body && body.success === false)) {
    const message = body?.message || response.statusText || 'Request failed'
    throw new Error(message)
  }

  return body
}

function buildWorkspaceQuery(workspaceId?: string | null) {
  return workspaceId ? `?workspace=${encodeURIComponent(workspaceId)}` : ''
}

export async function listWorkflows(
  workspaceId?: string | null
): Promise<WorkflowRecord[]> {
  const res = await fetch(
    `${API_BASE_URL}/api/workflows${buildWorkspaceQuery(workspaceId)}`,
    {
      credentials: 'include'
    }
  )

  const data = await handleJsonResponse(res)
  return data.workflows ?? []
}

export async function getWorkflow(
  id: string,
  workspaceId?: string | null
): Promise<WorkflowRecord> {
  const res = await fetch(
    `${API_BASE_URL}/api/workflows/${id}${buildWorkspaceQuery(workspaceId)}`,
    {
      credentials: 'include'
    }
  )

  const data = await handleJsonResponse(res)
  return data.workflow
}

export async function createWorkflow(
  payload: WorkflowPayload,
  workspaceId?: string | null
): Promise<WorkflowRecord> {
  const csrfToken = await getCsrfToken()
  const requestBody = {
    ...payload,
    workspace_id: workspaceId ?? payload.workspace_id ?? null
  }

  const res = await fetch(`${API_BASE_URL}/api/workflows`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-csrf-token': csrfToken
    },
    credentials: 'include',
    body: JSON.stringify(requestBody)
  })
  let body: any = null
  try {
    body = await res.json()
  } catch {
    /* ignore */
  }
  if (!res.ok || (body && body.success === false)) {
    const error = new Error(body?.message || res.statusText || 'Request failed')
    if (body?.violations) {
      ;(error as any).violations = body.violations
    }
    throw error
  }
  return body.workflow
}

export async function updateWorkflow(
  id: string,
  payload: WorkflowPayload,
  workspaceId?: string | null,
  expectedUpdatedAt?: string | null
): Promise<WorkflowRecord> {
  const csrfToken = await getCsrfToken()
  const requestBody =
    expectedUpdatedAt != null
      ? { ...payload, updated_at: expectedUpdatedAt }
      : payload

  const res = await fetch(
    `${API_BASE_URL}/api/workflows/${id}${buildWorkspaceQuery(workspaceId)}`,
    {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'x-csrf-token': csrfToken
      },
      credentials: 'include',
      body: JSON.stringify(requestBody)
    }
  )
  let body: any = null
  try {
    body = await res.json()
  } catch {
    /* ignore */
  }
  if (!res.ok || (body && body.success === false)) {
    const error = new Error(body?.message || res.statusText || 'Request failed')
    if (res.status === 409) {
      ;(error as any).code = 'conflict'
      ;(error as any).workflow = body?.workflow
    }
    if (body?.violations) {
      ;(error as any).violations = body.violations
    }
    throw error
  }
  return body.workflow
}

export async function lockWorkflow(
  id: string,
  workspaceId?: string | null
): Promise<WorkflowRecord> {
  const csrfToken = await getCsrfToken()

  const res = await fetch(
    `${API_BASE_URL}/api/workflows/${id}/lock${buildWorkspaceQuery(workspaceId)}`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-csrf-token': csrfToken
      },
      credentials: 'include'
    }
  )

  const data = await handleJsonResponse(res)
  return data.workflow
}

export async function unlockWorkflow(
  id: string,
  workspaceId?: string | null
): Promise<WorkflowRecord> {
  const csrfToken = await getCsrfToken()

  const res = await fetch(
    `${API_BASE_URL}/api/workflows/${id}/lock${buildWorkspaceQuery(workspaceId)}`,
    {
      method: 'DELETE',
      headers: {
        'x-csrf-token': csrfToken
      },
      credentials: 'include'
    }
  )

  const data = await handleJsonResponse(res)
  return data.workflow
}

export async function deleteWorkflow(
  id: string,
  workspaceId?: string | null
): Promise<{ success: boolean }> {
  const csrfToken = await getCsrfToken()

  const res = await fetch(
    `${API_BASE_URL}/api/workflows/${id}${buildWorkspaceQuery(workspaceId)}`,
    {
      method: 'DELETE',
      headers: {
        'x-csrf-token': csrfToken
      },
      credentials: 'include'
    }
  )

  const data = await handleJsonResponse(res)
  return { success: Boolean(data?.success ?? true) }
}

export async function getWorkflowLogs(workflowId: string): Promise<{
  workflow?: { id: string; name: string }
  logs: WorkflowLogEntry[]
}> {
  const res = await fetch(`${API_BASE_URL}/api/workflows/${workflowId}/logs`, {
    credentials: 'include'
  })
  const data = await handleJsonResponse(res)
  return { workflow: data.workflow, logs: data.logs ?? [] }
}

export async function getPlanUsage(
  workspaceId?: string | null
): Promise<PlanUsageSummary> {
  const res = await fetch(
    `${API_BASE_URL}/api/workflows/usage${buildWorkspaceQuery(workspaceId)}`,
    {
      credentials: 'include'
    }
  )

  const data = await handleJsonResponse(res)
  const workspaceRuns = data?.workspace?.runs
  const workspaceMembers = data?.workspace?.members
  const workspaceMemberUsage = Array.isArray(data?.workspace?.member_usage)
    ? (data.workspace.member_usage as any[]).reduce<WorkspaceMemberRunUsage[]>(
        (acc, entry) => {
          if (!entry || typeof entry !== 'object') return acc
          const userId =
            typeof (entry as any).user_id === 'string'
              ? (entry as any).user_id
              : undefined
          if (!userId) return acc
          acc.push({
            user_id: userId,
            runs: Number((entry as any).runs ?? 0),
            first_name:
              typeof (entry as any).first_name === 'string'
                ? (entry as any).first_name
                : undefined,
            last_name:
              typeof (entry as any).last_name === 'string'
                ? (entry as any).last_name
                : undefined,
            email:
              typeof (entry as any).email === 'string'
                ? (entry as any).email
                : undefined
          })
          return acc
        },
        []
      )
    : undefined

  return {
    plan: typeof data.plan === 'string' ? data.plan : 'solo',
    runs: {
      used: Number(data?.runs?.used ?? 0),
      limit:
        typeof data?.runs?.limit === 'number' ? data.runs.limit : undefined,
      period_start:
        typeof data?.runs?.period_start === 'string'
          ? data.runs.period_start
          : ''
    },
    workflows: {
      total: Number(data?.workflows?.total ?? 0),
      limit:
        typeof data?.workflows?.limit === 'number'
          ? data.workflows.limit
          : undefined,
      hidden:
        typeof data?.workflows?.hidden === 'number'
          ? data.workflows.hidden
          : undefined
    },
    workspace: data?.workspace
      ? {
          id:
            typeof data?.workspace?.id === 'string'
              ? data.workspace.id
              : undefined,
          plan:
            typeof data.workspace.plan === 'string'
              ? data.workspace.plan
              : undefined,
          runs: workspaceRuns
            ? {
                used: Number(workspaceRuns.used ?? 0),
                limit:
                  typeof workspaceRuns.limit === 'number'
                    ? workspaceRuns.limit
                    : undefined,
                overage:
                  typeof workspaceRuns.overage === 'number'
                    ? workspaceRuns.overage
                    : undefined,
                period_start:
                  typeof workspaceRuns.period_start === 'string'
                    ? workspaceRuns.period_start
                    : undefined
              }
            : undefined,
          members: workspaceMembers
            ? {
                used: Number(workspaceMembers.used ?? 0),
                limit:
                  typeof workspaceMembers.limit === 'number'
                    ? workspaceMembers.limit
                    : undefined
              }
            : undefined,
          member_usage: workspaceMemberUsage
        }
      : undefined
  }
}

export async function deleteWorkflowLog(
  workflowId: string,
  logId: string
): Promise<{ success: boolean }> {
  const csrfToken = await getCsrfToken()
  const res = await fetch(
    `${API_BASE_URL}/api/workflows/${workflowId}/logs/${logId}`,
    {
      method: 'DELETE',
      headers: { 'x-csrf-token': csrfToken },
      credentials: 'include'
    }
  )
  const data = await handleJsonResponse(res)
  return { success: Boolean(data?.success ?? true) }
}

export async function clearWorkflowLogs(
  workflowId: string
): Promise<{ success: boolean }> {
  const csrfToken = await getCsrfToken()
  const res = await fetch(`${API_BASE_URL}/api/workflows/${workflowId}/logs`, {
    method: 'DELETE',
    headers: { 'x-csrf-token': csrfToken },
    credentials: 'include'
  })
  const data = await handleJsonResponse(res)
  return { success: Boolean(data?.success ?? true) }
}

export async function cancelRun(
  workflowId: string,
  runId: string
): Promise<{ success: boolean }> {
  const csrfToken = await getCsrfToken()
  const res = await fetch(
    `${API_BASE_URL}/api/workflows/${workflowId}/runs/${runId}/cancel`,
    {
      method: 'POST',
      headers: { 'x-csrf-token': csrfToken },
      credentials: 'include'
    }
  )
  const data = await handleJsonResponse(res)
  return { success: Boolean(data?.success ?? true) }
}

// Runs API
export interface RunActorMetadata {
  type?: string
  id?: string
  name?: string
  email?: string
  label?: string
}

export interface RunCredentialMetadata {
  provider?: string
  scope?: string
  connection_id?: string
  account_email?: string
  workspace_name?: string
  label?: string
}

export interface WorkflowRunRecord {
  id: string
  user_id: string
  workflow_id: string
  snapshot: any
  status: 'queued' | 'running' | 'succeeded' | 'failed' | 'canceled'
  error?: string | null
  idempotency_key?: string | null
  started_at: string
  finished_at?: string | null
  created_at: string
  updated_at: string
  triggered_by?: RunActorMetadata | string | null
  executed_with?: RunCredentialMetadata | string | null
}

export interface WorkflowNodeRunRecord {
  id: string
  run_id: string
  node_id: string
  name?: string | null
  node_type?: string | null
  inputs?: any
  outputs?: any
  status: 'queued' | 'running' | 'succeeded' | 'failed' | 'skipped' | 'canceled'
  error?: string | null
  started_at: string
  finished_at?: string | null
  created_at: string
  updated_at: string
}

export async function startWorkflowRun(
  workflowId: string,
  opts?: { idempotencyKey?: string; context?: any; startFromNodeId?: string }
): Promise<WorkflowRunRecord> {
  const csrfToken = await getCsrfToken()
  const res = await fetch(`${API_BASE_URL}/api/workflows/${workflowId}/run`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-csrf-token': csrfToken
    },
    credentials: 'include',
    body: JSON.stringify(
      opts
        ? {
            idempotency_key: opts.idempotencyKey,
            context: opts.context,
            start_from_node_id: opts.startFromNodeId
          }
        : {}
    )
  })
  let body: any = null
  try {
    body = await res.json()
  } catch {
    /* ignore */
  }
  if (!res.ok || (body && body.success === false)) {
    const errorCode =
      typeof body?.error === 'string'
        ? body.error
        : typeof body?.code === 'string'
          ? body.code
          : undefined
    const message =
      errorCode === RUNAWAY_PROTECTION_ERROR
        ? 'Runaway protection triggered. Check for workflow loops and try again in a few minutes.'
        : body?.message || res.statusText || 'Failed to start run'
    const error = new Error(message)
    if (body?.violations) {
      ;(error as any).violations = body.violations
    }
    if (errorCode) {
      ;(error as any).code = errorCode
    }
    throw error
  }
  return body.run
}

// Queue & Concurrency helpers
export async function setConcurrencyLimit(
  workflowId: string,
  limit: number
): Promise<{ success: boolean; limit: number }> {
  const csrfToken = await getCsrfToken()
  const res = await fetch(
    `${API_BASE_URL}/api/workflows/${workflowId}/concurrency`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-csrf-token': csrfToken
      },
      credentials: 'include',
      body: JSON.stringify({ limit })
    }
  )
  let body: any = null
  try {
    body = await res.json()
  } catch {
    /* ignore */
  }
  if (!res.ok || (body && body.success === false)) {
    const error = new Error(body?.message || res.statusText || 'Request failed')
    if (body?.violations) {
      ;(error as any).violations = body.violations
    }
    throw error
  }
  return {
    success: Boolean(body?.success ?? true),
    limit: body?.limit ?? limit
  }
}

export async function cancelAllRunsForWorkflow(
  workflowId: string
): Promise<{ success: boolean; canceled: number }> {
  const csrfToken = await getCsrfToken()
  const res = await fetch(
    `${API_BASE_URL}/api/workflows/${workflowId}/runs/cancel-all`,
    {
      method: 'POST',
      headers: { 'x-csrf-token': csrfToken },
      credentials: 'include'
    }
  )
  const data = await handleJsonResponse(res)
  return {
    success: Boolean(data?.success ?? true),
    canceled: data?.canceled ?? 0
  }
}

export type DeadLetter = {
  id: string
  user_id: string
  workflow_id: string
  run_id: string
  error: string
  snapshot: any
  created_at: string
}

export async function listDeadLetters(
  workflowId: string,
  page = 1,
  perPage = 20
): Promise<DeadLetter[]> {
  const qs = `?page=${encodeURIComponent(page)}&per_page=${encodeURIComponent(perPage)}`
  const res = await fetch(
    `${API_BASE_URL}/api/workflows/${workflowId}/dead-letters${qs}`,
    {
      credentials: 'include'
    }
  )
  const data = await handleJsonResponse(res)
  return data.dead_letters ?? []
}

export async function requeueDeadLetter(
  workflowId: string,
  deadId: string
): Promise<{ success: boolean }> {
  const csrfToken = await getCsrfToken()
  const res = await fetch(
    `${API_BASE_URL}/api/workflows/${workflowId}/dead-letters/${deadId}/requeue`,
    {
      method: 'POST',
      headers: { 'x-csrf-token': csrfToken },
      credentials: 'include'
    }
  )
  const data = await handleJsonResponse(res)
  return { success: Boolean(data?.success ?? true) }
}

// Admin maintenance
export async function purgeRuns(
  days?: number
): Promise<{ success: boolean; deleted: number; days: number }> {
  const csrfToken = await getCsrfToken()
  const res = await fetch(`${API_BASE_URL}/api/admin/purge-runs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken },
    credentials: 'include',
    body: JSON.stringify({ days })
  })
  const data = await handleJsonResponse(res)
  return {
    success: Boolean(data?.success ?? true),
    deleted: data?.deleted ?? 0,
    days: data?.days ?? days ?? 0
  }
}

export type EgressBlockEvent = {
  id: string
  workflow_id: string
  run_id: string
  node_id: string
  url: string
  host: string
  rule: string
  message: string
  created_at: string
}

export async function listEgressBlocks(
  workflowId: string,
  page = 1,
  perPage = 20
): Promise<EgressBlockEvent[]> {
  const qs = `?page=${encodeURIComponent(page)}&per_page=${encodeURIComponent(perPage)}`
  const res = await fetch(
    `${API_BASE_URL}/api/workflows/${workflowId}/egress/blocks${qs}`,
    { credentials: 'include' }
  )
  const data = await handleJsonResponse(res)
  return data.blocks ?? []
}

export async function clearEgressBlocks(
  workflowId: string
): Promise<{ success: boolean; deleted: number }> {
  const csrfToken = await getCsrfToken()
  const res = await fetch(
    `${API_BASE_URL}/api/workflows/${workflowId}/egress/blocks`,
    {
      method: 'DELETE',
      headers: { 'x-csrf-token': csrfToken },
      credentials: 'include'
    }
  )
  const data = await handleJsonResponse(res)
  return {
    success: Boolean(data?.success ?? true),
    deleted: data?.deleted ?? 0
  }
}

export async function clearDeadLetters(
  workflowId: string
): Promise<{ success: boolean; deleted: number }> {
  const csrfToken = await getCsrfToken()
  const res = await fetch(
    `${API_BASE_URL}/api/workflows/${workflowId}/dead-letters`,
    {
      method: 'DELETE',
      headers: { 'x-csrf-token': csrfToken },
      credentials: 'include'
    }
  )
  const data = await handleJsonResponse(res)
  return {
    success: Boolean(data?.success ?? true),
    deleted: data?.deleted ?? 0
  }
}

export async function getWorkflowRunStatus(
  workflowId: string,
  runId: string
): Promise<{ run: WorkflowRunRecord; node_runs: WorkflowNodeRunRecord[] }> {
  const res = await fetch(
    `${API_BASE_URL}/api/workflows/${workflowId}/runs/${runId}`,
    {
      credentials: 'include'
    }
  )
  const data = await handleJsonResponse(res)
  return { run: data.run, node_runs: data.node_runs ?? [] }
}

export async function listActiveRuns(
  workflowId?: string
): Promise<WorkflowRunRecord[]> {
  const qs = workflowId ? `?workflow_id=${encodeURIComponent(workflowId)}` : ''
  const res = await fetch(`${API_BASE_URL}/api/workflows/runs${qs}`, {
    credentials: 'include'
  })
  const data = await handleJsonResponse(res)
  return data.runs ?? []
}

// Paged runs for a workflow with optional status filters
export async function listRunsForWorkflow(
  workflowId: string,
  opts?: { status?: string[]; page?: number; perPage?: number }
): Promise<WorkflowRunRecord[]> {
  const params: string[] = []
  if (opts?.status && opts.status.length) {
    // Backend expects a sequence; bracket notation ensures Vec parsing
    for (const s of opts.status)
      params.push(`status[]=${encodeURIComponent(s)}`)
  }
  if (opts?.page) params.push(`page=${encodeURIComponent(String(opts.page))}`)
  if (opts?.perPage)
    params.push(`per_page=${encodeURIComponent(String(opts.perPage))}`)
  const qs = params.length ? `?${params.join('&')}` : ''
  const res = await fetch(
    `${API_BASE_URL}/api/workflows/${workflowId}/runs${qs}`,
    {
      credentials: 'include'
    }
  )
  const data = await handleJsonResponse(res)
  return data.runs ?? []
}

// Security & Egress config
export async function getEgressAllowlist(
  workflowId: string
): Promise<string[]> {
  const res = await fetch(
    `${API_BASE_URL}/api/workflows/${workflowId}/egress`,
    { credentials: 'include' }
  )
  const data = await handleJsonResponse(res)
  return data.allowlist ?? []
}

export async function setEgressAllowlistApi(
  workflowId: string,
  allowlist: string[]
): Promise<{ success: boolean }> {
  const csrfToken = await getCsrfToken()
  const res = await fetch(
    `${API_BASE_URL}/api/workflows/${workflowId}/egress`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-csrf-token': csrfToken
      },
      credentials: 'include',
      body: JSON.stringify({ allowlist })
    }
  )
  const data = await handleJsonResponse(res)
  return { success: Boolean(data?.success ?? true) }
}
