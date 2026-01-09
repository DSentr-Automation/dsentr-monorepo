import { API_BASE_URL } from './config'
import { getCsrfToken } from './csrfCache'

export type WebhookSource = {
  id: string
  workspaceId?: string
  name: string
  requireHmac: boolean
  enabled?: boolean
  lastSeenAt?: string | null
  createdAt?: string
  updatedAt?: string
}

export type WebhookSourceSecretResult = {
  source: WebhookSource
  secret?: string | null
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

function normalizeWebhookSource(raw: any): WebhookSource | null {
  if (!raw || typeof raw !== 'object') return null
  const id = typeof raw.id === 'string' ? raw.id : null
  if (!id) return null
  const name = typeof raw.name === 'string' ? raw.name : ''
  const requireHmac =
    typeof raw.require_hmac === 'boolean'
      ? raw.require_hmac
      : typeof raw.requireHmac === 'boolean'
        ? raw.requireHmac
        : Boolean(raw.require_hmac ?? raw.requireHmac ?? false)
  const enabled =
    typeof raw.enabled === 'boolean' ? (raw.enabled as boolean) : undefined
  const lastSeenAt =
    typeof raw.last_seen_at === 'string'
      ? (raw.last_seen_at as string)
      : typeof raw.lastSeenAt === 'string'
        ? (raw.lastSeenAt as string)
        : raw.last_seen_at === null || raw.lastSeenAt === null
          ? null
          : undefined
  const createdAt =
    typeof raw.created_at === 'string'
      ? (raw.created_at as string)
      : typeof raw.createdAt === 'string'
        ? (raw.createdAt as string)
        : undefined
  const updatedAt =
    typeof raw.updated_at === 'string'
      ? (raw.updated_at as string)
      : typeof raw.updatedAt === 'string'
        ? (raw.updatedAt as string)
        : undefined
  const workspaceId =
    typeof raw.workspace_id === 'string'
      ? (raw.workspace_id as string)
      : typeof raw.workspaceId === 'string'
        ? (raw.workspaceId as string)
        : undefined

  return {
    id,
    workspaceId,
    name,
    requireHmac,
    enabled,
    lastSeenAt,
    createdAt,
    updatedAt
  }
}

function extractSecret(body: any): string | null {
  if (!body || typeof body !== 'object') return null
  const direct =
    typeof body.secret === 'string'
      ? body.secret
      : typeof body.data?.secret === 'string'
        ? body.data.secret
        : typeof body.source?.secret === 'string'
          ? body.source.secret
          : typeof body.data?.source?.secret === 'string'
            ? body.data.source.secret
            : null
  return direct
}

function extractSources(body: any): any[] {
  const sources =
    body?.data?.sources ??
    body?.sources ??
    body?.data?.webhook_sources ??
    body?.webhook_sources
  return Array.isArray(sources) ? sources : []
}

function extractSource(body: any): any | null {
  const source =
    body?.data?.source ??
    body?.source ??
    body?.data?.webhook_source ??
    body?.webhook_source
  if (source && typeof source === 'object') return source
  return null
}

export async function listWebhookSources(
  workspaceId: string
): Promise<WebhookSource[]> {
  const res = await fetch(
    `${API_BASE_URL}/api/workspaces/${workspaceId}/webhooks/sources`,
    { credentials: 'include' }
  )
  const body = await parseJson(res)
  if (!res.ok || body?.success === false) {
    raiseForStatus(body, 'Failed to load webhook sources')
  }
  return extractSources(body)
    .map((entry) => normalizeWebhookSource(entry))
    .filter((entry): entry is WebhookSource => Boolean(entry))
}

export async function createWebhookSource(
  workspaceId: string,
  payload: { name: string; requireHmac: boolean }
): Promise<WebhookSourceSecretResult> {
  const csrfToken = await getCsrfToken()
  const res = await fetch(
    `${API_BASE_URL}/api/workspaces/${workspaceId}/webhooks/sources`,
    {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'x-csrf-token': csrfToken
      },
      body: JSON.stringify({
        name: payload.name,
        require_hmac: payload.requireHmac
      })
    }
  )
  const body = await parseJson(res)
  if (!res.ok || body?.success === false) {
    raiseForStatus(body, 'Failed to create webhook source')
  }
  const source = extractSource(body)
  const normalized = normalizeWebhookSource(source)
  if (!normalized) {
    throw new Error('Failed to read webhook source response')
  }
  return { source: normalized, secret: extractSecret(body) }
}

export async function rotateWebhookSourceSecret(
  workspaceId: string,
  sourceId: string
): Promise<WebhookSourceSecretResult> {
  const csrfToken = await getCsrfToken()
  const res = await fetch(
    `${API_BASE_URL}/api/workspaces/${workspaceId}/webhooks/sources/${sourceId}/rotate-secret`,
    {
      method: 'POST',
      credentials: 'include',
      headers: {
        'x-csrf-token': csrfToken
      }
    }
  )
  const body = await parseJson(res)
  if (!res.ok || body?.success === false) {
    raiseForStatus(body, 'Failed to rotate webhook source secret')
  }
  const source = extractSource(body)
  const normalized = normalizeWebhookSource(source)
  if (!normalized) {
    throw new Error('Failed to read webhook source response')
  }
  return { source: normalized, secret: extractSecret(body) }
}

export async function deleteWebhookSource(
  workspaceId: string,
  sourceId: string
): Promise<void> {
  const csrfToken = await getCsrfToken()
  const res = await fetch(
    `${API_BASE_URL}/api/workspaces/${workspaceId}/webhooks/sources/${sourceId}`,
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
    raiseForStatus(body, 'Failed to delete webhook source')
  }
}
