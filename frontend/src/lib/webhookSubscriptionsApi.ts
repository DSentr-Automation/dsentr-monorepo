import { API_BASE_URL } from './config'
import { getCsrfToken } from './csrfCache'

export type WebhookSubscription = {
  id: string
  webhookSourceId: string
  workflowId: string
  triggerNodeId: string
  eventType: string
  enabled?: boolean
  createdAt?: string
  updatedAt?: string
}

async function parseJson(response: Response) {
  try {
    return await response.json()
  } catch {
    return null
  }
}

function raiseForStatus(body: any, fallbackMessage: string): never {
  const message = body?.message || fallbackMessage
  throw new Error(message)
}

function normalizeWebhookSubscription(raw: any): WebhookSubscription | null {
  if (!raw || typeof raw !== 'object') return null
  const id = typeof raw.id === 'string' ? raw.id : null
  const webhookSourceId =
    typeof raw.webhook_source_id === 'string'
      ? raw.webhook_source_id
      : typeof raw.webhookSourceId === 'string'
        ? raw.webhookSourceId
        : null
  const workflowId =
    typeof raw.workflow_id === 'string'
      ? raw.workflow_id
      : typeof raw.workflowId === 'string'
        ? raw.workflowId
        : null
  const triggerNodeId =
    typeof raw.trigger_node_id === 'string'
      ? raw.trigger_node_id
      : typeof raw.triggerNodeId === 'string'
        ? raw.triggerNodeId
        : null
  if (!id || !webhookSourceId || !workflowId || !triggerNodeId) return null
  const eventType =
    typeof raw.event_type === 'string'
      ? raw.event_type
      : typeof raw.eventType === 'string'
        ? raw.eventType
        : ''
  const enabled =
    typeof raw.enabled === 'boolean' ? (raw.enabled as boolean) : undefined
  const createdAt =
    typeof raw.created_at === 'string'
      ? raw.created_at
      : typeof raw.createdAt === 'string'
        ? raw.createdAt
        : undefined
  const updatedAt =
    typeof raw.updated_at === 'string'
      ? raw.updated_at
      : typeof raw.updatedAt === 'string'
        ? raw.updatedAt
        : undefined

  return {
    id,
    webhookSourceId,
    workflowId,
    triggerNodeId,
    eventType,
    enabled,
    createdAt,
    updatedAt
  }
}

function extractSubscriptions(body: any): any[] {
  const subs =
    body?.data?.subscriptions ??
    body?.subscriptions ??
    body?.data?.webhook_subscriptions ??
    body?.webhook_subscriptions
  return Array.isArray(subs) ? subs : []
}

function extractSubscription(body: any): any | null {
  const sub =
    body?.data?.subscription ??
    body?.subscription ??
    body?.data?.webhook_subscription ??
    body?.webhook_subscription
  return sub && typeof sub === 'object' ? sub : null
}

export async function listWebhookSubscriptionsForSource(
  workspaceId: string,
  sourceId: string
): Promise<WebhookSubscription[]> {
  const res = await fetch(
    `${API_BASE_URL}/api/workspaces/${workspaceId}/webhooks/sources/${sourceId}/subscriptions`,
    {
      credentials: 'include'
    }
  )
  const body = await parseJson(res)
  if (!res.ok || body?.success === false) {
    raiseForStatus(body, 'Failed to load webhook subscriptions')
  }
  return extractSubscriptions(body)
    .map((entry) => normalizeWebhookSubscription(entry))
    .filter((entry): entry is WebhookSubscription => Boolean(entry))
}

export async function createWebhookSubscriptionForSource(
  workspaceId: string,
  sourceId: string,
  payload: { workflowId: string; triggerNodeId: string; eventType: string }
): Promise<WebhookSubscription> {
  const csrfToken = await getCsrfToken()
  const res = await fetch(
    `${API_BASE_URL}/api/workspaces/${workspaceId}/webhooks/sources/${sourceId}/subscriptions`,
    {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'x-csrf-token': csrfToken
      },
      body: JSON.stringify({
        workflow_id: payload.workflowId,
        trigger_node_id: payload.triggerNodeId,
        event_type: payload.eventType
      })
    }
  )
  const body = await parseJson(res)
  if (!res.ok || body?.success === false) {
    raiseForStatus(body, 'Failed to create webhook subscription')
  }
  const subscription = extractSubscription(body)
  const normalized = normalizeWebhookSubscription(subscription)
  if (!normalized) {
    throw new Error('Failed to read webhook subscription response')
  }
  return normalized
}

export async function deleteSubscription(
  workspaceId: string,
  sourceId: string,
  subscriptionId: string
): Promise<void> {
  const csrfToken = await getCsrfToken()
  const res = await fetch(
    `${API_BASE_URL}/api/workspaces/${workspaceId}/webhooks/sources/${sourceId}/subscriptions/${subscriptionId}`,
    {
      method: 'DELETE',
      credentials: 'include',
      headers: {
        'x-csrf-token': csrfToken
      }
    }
  )
  const body = await parseJson(res)
  if (!res.ok || body?.success === false) {
    raiseForStatus(body, 'Failed to delete webhook subscription')
  }
}
