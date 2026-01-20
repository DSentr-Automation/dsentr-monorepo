import { API_BASE_URL } from './config'
import { getCsrfToken } from './csrfCache'
import { useAuth } from '@/stores/auth'

export type OAuthProvider =
  | 'google'
  | 'github'
  | 'microsoft'
  | 'slack'
  | 'asana'
  | 'notion'
  | 'bitly'
  | 'raindrop'

export type ConnectionScope = 'personal' | 'workspace'

export const SLACK_PERSONAL_AUTHORIZE_LABEL = 'Authorize Slack for yourself'
export const SLACK_PERSONAL_REAUTHORIZE_LABEL = 'Reauthorize Slack'
export const SLACK_PERSONAL_AUTHORIZED_LABEL = 'Personal Slack authorized'
export const SLACK_PERSONAL_AUTHORIZED_HINT =
  'Slack is authorized to post as you'
export const SLACK_PERSONAL_AUTH_REQUIRED =
  'Authorize Slack for yourself to post as you.'

export type IntegrationAuthType = 'oauth2' | 'api_key' | 'none' | string
export type IntegrationTokenScope =
  | 'personal'
  | 'workspace'
  | 'personal_and_workspace'
  | string
export type IntegrationOwnershipModel =
  | 'personal_only'
  | 'workspace_only'
  | 'hybrid'
  | string

export interface IntegrationManifest {
  integrationId: string
  authType: IntegrationAuthType
  tokenScope: IntegrationTokenScope
  ownershipModel: IntegrationOwnershipModel
  providerConstraints: {
    workspaceFirst: boolean
    singleInstallPerWorkspace: boolean
  }
  uiMetadata: {
    displayName: string
    description: string
    iconKey?: string
    docsUrl?: string
  }
  oauthMetadata?: {
    scopes: string[]
    promotable?: boolean
  }
}

export interface PersonalAuthStatus {
  hasPersonalAuth: boolean
  personalAuthConnectedAt?: string
}
export interface BaseConnectionInfo {
  scope: ConnectionScope
  id: string | null
  connectionId?: string
  connected: boolean
  accountEmail?: string
  expiresAt?: string
  lastRefreshedAt?: string
  requiresReconnect: boolean
}

export interface PersonalConnectionInfo extends BaseConnectionInfo {
  scope: 'personal'
  isShared: boolean
  ownerUserId?: string
  ownerName?: string
  ownerEmail?: string
}

export interface WorkspaceConnectionInfo extends BaseConnectionInfo {
  scope: 'workspace'
  provider: OAuthProvider
  workspaceId: string
  workspaceName: string
  workspaceConnectionId?: string
  sharedByName?: string
  sharedByEmail?: string
  ownerUserId?: string
  hasIncomingWebhook?: boolean
}

export interface ProviderConnectionSet {
  personal: PersonalConnectionInfo[]
  workspace: WorkspaceConnectionInfo[]
}

// Grouped snapshot shape as returned by the API (no regrouping by provider)
export interface PersonalConnectionRecord extends PersonalConnectionInfo {
  provider: OAuthProvider
}

export type SlackPersonalAuthState = PersonalAuthStatus

export interface GroupedConnectionsSnapshot {
  personal: PersonalConnectionRecord[]
  workspace: WorkspaceConnectionInfo[]
  slackPersonalAuth?: SlackPersonalAuthState
  personalAuth?: Record<string, PersonalAuthStatus>
  manifests?: IntegrationManifest[]
}

const resolveApiBaseUrl = (): string => {
  const rawBase =
    typeof API_BASE_URL === 'string' && API_BASE_URL.trim().length > 0
      ? API_BASE_URL.trim()
      : typeof window !== 'undefined' && window.location?.origin
        ? window.location.origin
        : 'http://localhost'

  return rawBase.replace(/\/$/, '')
}

const buildApiUrl = (path: string): string => {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`
  return new URL(normalizedPath, resolveApiBaseUrl()).toString()
}

type ConnectionListener = (snapshot: GroupedConnectionsSnapshot | null) => void
type RawConnectionListener = (
  snapshot: GroupedConnectionsSnapshot | null,
  workspaceId: string | null
) => void

let cachedConnections: GroupedConnectionsSnapshot | null = null
let cachedWorkspaceId: string | null = null
const connectionListeners = new Set<RawConnectionListener>()

type ConnectionCacheOptions = {
  workspaceId?: string | null
}

const defaultPersonalConnection = (): PersonalConnectionInfo => ({
  scope: 'personal',
  id: null,
  connected: false,
  accountEmail: undefined,
  expiresAt: undefined,
  lastRefreshedAt: undefined,
  requiresReconnect: false,
  isShared: false
})

const cloneManifests = (
  value?: IntegrationManifest[] | null
): IntegrationManifest[] | undefined => {
  if (!value) return undefined
  return value.map((manifest) => ({
    ...manifest,
    providerConstraints: { ...manifest.providerConstraints },
    uiMetadata: { ...manifest.uiMetadata },
    oauthMetadata: manifest.oauthMetadata
      ? { scopes: [...manifest.oauthMetadata.scopes] }
      : undefined
  }))
}

const clonePersonalAuthMap = (
  value?: Record<string, PersonalAuthStatus> | null
): Record<string, PersonalAuthStatus> | undefined => {
  if (!value) return undefined
  return Object.entries(value).reduce(
    (acc, [key, status]) => {
      if (!status) return acc
      acc[key] = { ...status }
      return acc
    },
    {} as Record<string, PersonalAuthStatus>
  )
}

const cloneSlackPersonalAuth = (
  value?: SlackPersonalAuthState | null
): SlackPersonalAuthState | undefined => {
  if (!value) return undefined
  return { ...value }
}

const cloneGroupedSnapshot = (
  snapshot: GroupedConnectionsSnapshot
): GroupedConnectionsSnapshot => ({
  personal: snapshot.personal.map((p) => ({ ...p })),
  workspace: snapshot.workspace.map((w) => ({ ...w })),
  slackPersonalAuth: cloneSlackPersonalAuth(snapshot.slackPersonalAuth),
  personalAuth: clonePersonalAuthMap(snapshot.personalAuth),
  manifests: cloneManifests(snapshot.manifests)
})

const normalizeWorkspaceId = (value?: string | null): string | null => {
  if (typeof value !== 'string') {
    return null
  }
  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : null
}

const readActiveWorkspaceId = (): string | null => {
  try {
    const state = useAuth.getState()
    return normalizeWorkspaceId(state?.currentWorkspaceId ?? null)
  } catch {
    return null
  }
}

const resolveWorkspaceId = (workspaceId?: string | null): string | null => {
  if (typeof workspaceId !== 'undefined') {
    return normalizeWorkspaceId(workspaceId)
  }
  const activeWorkspace = readActiveWorkspaceId()
  if (activeWorkspace !== null) {
    return activeWorkspace
  }
  return cachedWorkspaceId
}

const emitCachedConnections = (
  snapshot: GroupedConnectionsSnapshot | null,
  options?: ConnectionCacheOptions
) => {
  if (options && Object.prototype.hasOwnProperty.call(options, 'workspaceId')) {
    cachedWorkspaceId = normalizeWorkspaceId(options.workspaceId ?? null)
  }
  if (!options && cachedWorkspaceId === null) {
    cachedWorkspaceId = readActiveWorkspaceId()
  }

  cachedConnections = snapshot ? cloneGroupedSnapshot(snapshot) : null
  const workspaceId = cachedWorkspaceId
  connectionListeners.forEach((listener) => {
    const payload = cachedConnections
      ? cloneGroupedSnapshot(cachedConnections)
      : null
    listener(payload, workspaceId)
  })
}

export const getCachedConnections = (
  workspaceId?: string | null
): GroupedConnectionsSnapshot | null => {
  const targetWorkspace = resolveWorkspaceId(workspaceId)
  if (!cachedConnections || cachedWorkspaceId !== targetWorkspace) {
    return null
  }
  return cloneGroupedSnapshot(cachedConnections)
}

export const subscribeToConnectionUpdates = (
  listener: ConnectionListener,
  options?: ConnectionCacheOptions
): (() => void) => {
  const targetWorkspace = resolveWorkspaceId(options?.workspaceId)

  const wrappedListener: RawConnectionListener = (snapshot, workspaceId) => {
    if (workspaceId !== targetWorkspace) {
      listener(null)
      return
    }
    listener(snapshot ? cloneGroupedSnapshot(snapshot) : null)
  }

  connectionListeners.add(wrappedListener)

  if (cachedConnections && cachedWorkspaceId === targetWorkspace) {
    listener(cloneGroupedSnapshot(cachedConnections))
  } else {
    listener(null)
  }

  return () => {
    connectionListeners.delete(wrappedListener)
  }
}

export const setCachedConnections = (
  snapshot: GroupedConnectionsSnapshot,
  options?: ConnectionCacheOptions
) => {
  emitCachedConnections(snapshot, options)
}

export const updateCachedConnections = (
  updater: (
    current: GroupedConnectionsSnapshot | null
  ) => GroupedConnectionsSnapshot | null,
  options?: ConnectionCacheOptions
): GroupedConnectionsSnapshot | null => {
  const current = cachedConnections
    ? cloneGroupedSnapshot(cachedConnections)
    : null
  const next = updater(current)
  emitCachedConnections(next, options)
  return next
}

interface ConnectionOwnerPayload {
  userId?: string | null
  name?: string | null
  email?: string | null
}

interface PersonalConnectionPayload {
  id: string
  connection_id?: string | null
  connectionId?: string | null
  provider: OAuthProvider
  accountEmail: string
  expiresAt: string
  isShared: boolean
  lastRefreshedAt?: string | null
  requiresReconnect?: boolean | null
  requires_reconnect?: boolean | null
  connected?: boolean | null
  owner?: ConnectionOwnerPayload | null
}

interface WorkspaceConnectionPayload {
  id: string
  connection_id?: string | null
  connectionId?: string | null
  workspace_connection_id?: string | null
  workspaceConnectionId?: string | null
  provider: OAuthProvider
  accountEmail: string
  expiresAt: string
  workspaceId: string
  workspaceName: string
  sharedByName?: string | null
  sharedByEmail?: string | null
  lastRefreshedAt?: string | null
  requiresReconnect?: boolean | null
  requires_reconnect?: boolean | null
  connected?: boolean | null
  owner?: ConnectionOwnerPayload | null
  hasIncomingWebhook?: boolean | null
  has_incoming_webhook?: boolean | null
}

interface IntegrationManifestPayload {
  integration_id?: string | null
  integrationId?: string | null
  auth_type?: string | null
  authType?: string | null
  token_scope?: string | null
  tokenScope?: string | null
  ownership_model?: string | null
  ownershipModel?: string | null
  provider_constraints?: {
    workspace_first?: boolean | null
    workspaceFirst?: boolean | null
    single_install_per_workspace?: boolean | null
    singleInstallPerWorkspace?: boolean | null
  } | null
  providerConstraints?: {
    workspace_first?: boolean | null
    workspaceFirst?: boolean | null
    single_install_per_workspace?: boolean | null
    singleInstallPerWorkspace?: boolean | null
  } | null
  ui_metadata?: {
    display_name?: string | null
    displayName?: string | null
    description?: string | null
    icon_key?: string | null
    iconKey?: string | null
    docs_url?: string | null
    docsUrl?: string | null
  } | null
  uiMetadata?: {
    display_name?: string | null
    displayName?: string | null
    description?: string | null
    icon_key?: string | null
    iconKey?: string | null
    docs_url?: string | null
    docsUrl?: string | null
  } | null
  oauth_metadata?: {
    scopes?: string[] | null
  } | null
  oauthMetadata?: {
    scopes?: string[] | null
  } | null
}

type ProviderConnectionBuckets<T> = Partial<Record<string, T[] | null>>

interface PersonalAuthPayload {
  has_personal_auth?: boolean | null
  hasPersonalAuth?: boolean | null
  personal_auth_connected_at?: string | null
  personalAuthConnectedAt?: string | null
}

interface ConnectionsApiResponse {
  success: boolean
  personal?:
    | ProviderConnectionBuckets<PersonalConnectionPayload>
    | PersonalConnectionPayload[]
    | null
  workspace?:
    | ProviderConnectionBuckets<WorkspaceConnectionPayload>
    | WorkspaceConnectionPayload[]
    | null
  slack?: PersonalAuthPayload | null
  personalAuth?: Record<string, PersonalAuthPayload> | null
  personal_auth?: Record<string, PersonalAuthPayload> | null
  manifests?: IntegrationManifestPayload[] | null
}

interface RefreshApiResponse {
  success: boolean
  accountEmail?: string | null
  expiresAt?: string | null
  lastRefreshedAt?: string | null
  requiresReconnect?: boolean | null
  requires_reconnect?: boolean | null
  message?: string | null
}

const flattenBucketEntries = <T extends { provider?: OAuthProvider }>(
  bucket: ProviderConnectionBuckets<T> | T[] | null | undefined
): T[] => {
  if (!bucket) {
    return []
  }

  if (Array.isArray(bucket)) {
    return bucket.filter(Boolean) as T[]
  }

  const entries: T[] = []
  Object.entries(bucket).forEach(([key, value]) => {
    if (!Array.isArray(value)) {
      return
    }
    value.forEach((entry) => {
      if (!entry) return
      if (entry.provider) {
        entries.push(entry)
      } else {
        entries.push({ ...entry, provider: key as OAuthProvider })
      }
    })
  })

  return entries
}

const normalizeText = (value?: string | null): string | undefined => {
  if (typeof value !== 'string') {
    return undefined
  }
  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : undefined
}

const normalizeId = (value?: string | null): string | undefined => {
  return normalizeText(value)
}

const normalizeScopes = (scopes?: string[] | null): string[] => {
  if (!Array.isArray(scopes)) return []
  return scopes
    .filter((scope): scope is string => typeof scope === 'string')
    .map((scope) => scope.trim())
    .filter((scope) => scope.length > 0)
}

const normalizePersonalAuthStatus = (
  payload?: PersonalAuthPayload | null
): PersonalAuthStatus => {
  const hasPersonalAuth = Boolean(
    payload?.hasPersonalAuth ?? payload?.has_personal_auth
  )
  return {
    hasPersonalAuth,
    personalAuthConnectedAt: normalizeText(
      payload?.personalAuthConnectedAt ?? payload?.personal_auth_connected_at
    )
  }
}

const normalizePersonalAuthMap = (
  payload?: Record<string, PersonalAuthPayload> | null
): Record<string, PersonalAuthStatus> | undefined => {
  if (!payload || typeof payload !== 'object') {
    return undefined
  }
  const entries = Object.entries(payload).reduce(
    (acc, [key, value]) => {
      const normalizedKey = normalizeText(key)
      if (!normalizedKey) return acc
      acc[normalizedKey] = normalizePersonalAuthStatus(value)
      return acc
    },
    {} as Record<string, PersonalAuthStatus>
  )
  return Object.keys(entries).length > 0 ? entries : undefined
}

const normalizeManifestPayloads = (
  payloads?: IntegrationManifestPayload[] | null
): IntegrationManifest[] => {
  if (!Array.isArray(payloads)) {
    return []
  }

  const manifests: IntegrationManifest[] = []
  payloads.forEach((payload) => {
    const integrationId =
      normalizeText(payload.integrationId ?? payload.integration_id) ?? ''
    if (!integrationId) {
      return
    }

    const providerConstraints =
      payload.providerConstraints ?? payload.provider_constraints ?? {}
    const uiMetadata = payload.uiMetadata ?? payload.ui_metadata ?? {}
    const oauthMetadata = payload.oauthMetadata ?? payload.oauth_metadata

    const displayName = normalizeText(
      uiMetadata.displayName ?? uiMetadata.display_name
    )

    const manifest: IntegrationManifest = {
      integrationId,
      authType:
        normalizeText(payload.authType ?? payload.auth_type) ?? 'oauth2',
      tokenScope:
        normalizeText(payload.tokenScope ?? payload.token_scope) ??
        'personal_and_workspace',
      ownershipModel:
        normalizeText(payload.ownershipModel ?? payload.ownership_model) ??
        'hybrid',
      providerConstraints: {
        workspaceFirst: Boolean(
          providerConstraints.workspaceFirst ??
            providerConstraints.workspace_first
        ),
        singleInstallPerWorkspace: Boolean(
          providerConstraints.singleInstallPerWorkspace ??
            providerConstraints.single_install_per_workspace
        )
      },
      uiMetadata: {
        displayName: displayName ?? integrationId,
        description: normalizeText(uiMetadata.description) ?? 'Integration',
        iconKey: normalizeText(uiMetadata.iconKey ?? uiMetadata.icon_key),
        docsUrl: normalizeText(uiMetadata.docsUrl ?? uiMetadata.docs_url)
      },
      oauthMetadata: oauthMetadata
        ? {
            scopes: normalizeScopes(oauthMetadata.scopes),
            promotable:
              typeof (oauthMetadata as any).promotable === 'boolean'
                ? (oauthMetadata as any).promotable
                : undefined
          }
        : undefined
    }
    manifests.push(manifest)
  })

  return manifests
}

const ensureGrouped = (
  snapshot: GroupedConnectionsSnapshot | null
): GroupedConnectionsSnapshot => ({
  personal: Array.isArray(snapshot?.personal)
    ? snapshot!.personal.map((p) => ({ ...p }))
    : [],
  workspace: Array.isArray(snapshot?.workspace)
    ? snapshot!.workspace.map((w) => ({ ...w }))
    : [],
  slackPersonalAuth: cloneSlackPersonalAuth(snapshot?.slackPersonalAuth),
  personalAuth: clonePersonalAuthMap(snapshot?.personalAuth),
  manifests: cloneManifests(snapshot?.manifests)
})

export async function fetchConnections(
  options?: ConnectionCacheOptions
): Promise<GroupedConnectionsSnapshot> {
  const targetWorkspace = resolveWorkspaceId(options?.workspaceId)
  const url = new URL('/api/oauth/connections', resolveApiBaseUrl())
  url.searchParams.set('workspace', targetWorkspace as string)
  const res = await fetch(url.toString(), {
    credentials: 'include'
  })

  if (!res.ok) {
    throw new Error('Failed to load OAuth connections')
  }

  const data = (await res.json()) as ConnectionsApiResponse
  const grouped: GroupedConnectionsSnapshot = {
    personal: [],
    workspace: []
  }

  const resolveConnectionId = (entry?: {
    id?: string | null
    connection_id?: string | null
    connectionId?: string | null
  }): string | undefined => {
    if (!entry) return undefined
    return normalizeId(
      entry.connectionId ?? entry.connection_id ?? entry.id ?? null
    )
  }

  const resolveWorkspaceConnectionId = (entry?: {
    id?: string | null
    workspace_connection_id?: string | null
    workspaceConnectionId?: string | null
  }): string | undefined => {
    if (!entry) return undefined
    return normalizeId(
      entry.workspaceConnectionId ??
        entry.workspace_connection_id ??
        entry.id ??
        null
    )
  }

  const personalEntries = flattenBucketEntries(data.personal)
  personalEntries.forEach((entry) => {
    if (!entry || !entry.provider) {
      return
    }
    const requiresReconnect = Boolean(
      entry.requiresReconnect ?? entry.requires_reconnect
    )
    const connectionId =
      resolveConnectionId(entry) ?? resolveWorkspaceConnectionId(entry)
    const connected =
      typeof entry.connected === 'boolean'
        ? entry.connected
        : !requiresReconnect
    grouped.personal.push({
      scope: 'personal',
      provider: entry.provider,
      id: connectionId ?? entry.id ?? null,
      connectionId: connectionId,
      connected,
      accountEmail: normalizeText(entry.accountEmail),
      expiresAt: entry.expiresAt ?? undefined,
      lastRefreshedAt: normalizeText(entry.lastRefreshedAt),
      requiresReconnect,
      isShared: Boolean(entry.isShared),
      ownerUserId: normalizeId(entry.owner?.userId),
      ownerName: normalizeText(entry.owner?.name),
      ownerEmail: normalizeText(entry.owner?.email)
    })
  })

  const workspaceEntries = flattenBucketEntries(data.workspace)
  workspaceEntries.forEach((entry) => {
    if (!entry || !entry.provider) {
      return
    }

    const connectionId = resolveConnectionId(entry)
    const workspaceConnectionId =
      resolveWorkspaceConnectionId(entry) ?? connectionId
    const workspaceId = entry.workspaceId?.trim()
    if (!workspaceConnectionId || !workspaceId) {
      return
    }

    const requiresReconnect = Boolean(
      entry.requiresReconnect ?? entry.requires_reconnect
    )
    const connected =
      typeof entry.connected === 'boolean'
        ? entry.connected
        : !requiresReconnect

    const ownerName =
      normalizeText(entry.sharedByName) ?? normalizeText(entry.owner?.name)
    const ownerEmail =
      normalizeText(entry.sharedByEmail) ?? normalizeText(entry.owner?.email)

    const workspaceInfo: WorkspaceConnectionInfo = {
      scope: 'workspace',
      id: workspaceConnectionId,
      workspaceConnectionId,
      connectionId: connectionId ?? workspaceConnectionId,
      connected,
      provider: entry.provider,
      accountEmail: normalizeText(entry.accountEmail),
      expiresAt: entry.expiresAt ?? undefined,
      lastRefreshedAt: normalizeText(entry.lastRefreshedAt),
      workspaceId,
      workspaceName:
        normalizeText(entry.workspaceName) ?? 'Workspace connection',
      sharedByName: ownerName,
      sharedByEmail: ownerEmail,
      requiresReconnect,
      ownerUserId: normalizeId(entry.owner?.userId),
      hasIncomingWebhook: Boolean(
        entry.hasIncomingWebhook ?? entry.has_incoming_webhook
      )
    }

    grouped.workspace.push(workspaceInfo)
  })

  grouped.slackPersonalAuth = normalizePersonalAuthStatus(data.slack)
  grouped.personalAuth = normalizePersonalAuthMap(
    data.personalAuth ?? data.personal_auth
  )
  grouped.manifests = normalizeManifestPayloads(data.manifests)

  setCachedConnections(grouped, { workspaceId: targetWorkspace })
  return grouped
}

export async function fetchIntegrationManifests(
  options?: ConnectionCacheOptions
): Promise<IntegrationManifest[]> {
  const cached = getCachedConnections(options?.workspaceId)
  if (cached?.manifests && cached.manifests.length > 0) {
    return cloneManifests(cached.manifests) ?? []
  }
  const data = await fetchConnections(options)
  return cloneManifests(data.manifests) ?? []
}

export async function disconnectProvider(
  provider: OAuthProvider,
  connectionId: string
): Promise<void> {
  const normalizedId =
    typeof connectionId === 'string' ? connectionId.trim() : ''
  if (!normalizedId) {
    throw new Error('connectionId is required to disconnect provider')
  }
  const csrfToken = await getCsrfToken()
  const url = new URL(buildApiUrl(`/api/oauth/${provider}/disconnect`))
  url.searchParams.set('connection_id', normalizedId)
  const res = await fetch(url.toString(), {
    method: 'DELETE',
    credentials: 'include',
    headers: {
      'x-csrf-token': csrfToken
    }
  })

  if (!res.ok) {
    const message = await res
      .json()
      .then((body) => body?.message)
      .catch(() => null)
    throw new Error(message || 'Failed to disconnect provider')
  }
}

export async function unshareWorkspaceConnection(
  workspaceId: string,
  connectionId: string
): Promise<void> {
  const csrfToken = await getCsrfToken()
  const res = await fetch(
    buildApiUrl(`/api/workspaces/${workspaceId}/connections/${connectionId}`),
    {
      method: 'DELETE',
      credentials: 'include',
      headers: {
        'x-csrf-token': csrfToken
      }
    }
  )

  if (!res.ok) {
    const message = await res
      .json()
      .then((body) => body?.message)
      .catch(() => null)
    throw new Error(message || 'Failed to remove workspace connection')
  }
}

export async function refreshProvider(
  provider: OAuthProvider,
  connectionId: string
): Promise<
  Pick<
    PersonalConnectionInfo,
    'connected' | 'accountEmail' | 'expiresAt' | 'lastRefreshedAt'
  >
> {
  const normalizedId =
    typeof connectionId === 'string' ? connectionId.trim() : ''
  if (!normalizedId) {
    throw new Error('connectionId is required to refresh provider tokens')
  }
  const csrfToken = await getCsrfToken()
  const url = new URL(buildApiUrl(`/api/oauth/${provider}/refresh`))
  url.searchParams.set('connection_id', normalizedId)
  const res = await fetch(url.toString(), {
    method: 'POST',
    credentials: 'include',
    headers: {
      'x-csrf-token': csrfToken
    }
  })

  const data = (await res.json().catch(() => null)) as RefreshApiResponse | null

  const requiresReconnect = Boolean(
    data?.requiresReconnect ?? data?.requires_reconnect
  )

  if (requiresReconnect) {
    markProviderRevoked(provider, normalizedId)
    const error: Error & { requiresReconnect?: boolean } = new Error(
      data?.message || 'The connection was revoked. Reconnect to continue.'
    )
    error.requiresReconnect = true
    throw error
  }

  if (!res.ok) {
    throw new Error(data?.message || 'Failed to refresh provider tokens')
  }

  const normalize = (value?: string | null): string | undefined => {
    if (typeof value !== 'string') {
      return undefined
    }
    const trimmed = value.trim()
    return trimmed.length > 0 ? trimmed : undefined
  }
  return {
    connected: true,
    accountEmail: normalize(data?.accountEmail),
    expiresAt: normalize(data?.expiresAt),
    lastRefreshedAt: normalize(data?.lastRefreshedAt)
  }
}

export const clearProviderConnections = (provider: OAuthProvider) => {
  updateCachedConnections((current) => {
    const snapshot = ensureGrouped(current)
    const nextPersonal = snapshot.personal.filter(
      (p) => p.provider !== provider
    )
    const nextWorkspace = snapshot.workspace.filter(
      (w) => w.provider !== provider
    )
    return {
      personal: nextPersonal,
      workspace: nextWorkspace,
      slackPersonalAuth: snapshot.slackPersonalAuth,
      personalAuth: snapshot.personalAuth,
      manifests: snapshot.manifests
    }
  })
}

export const markProviderRevoked = (
  provider: OAuthProvider,
  connectionId?: string | null
) => {
  const normalize = (value?: string | null): string | null => {
    if (typeof value !== 'string') return null
    const trimmed = value.trim()
    return trimmed.length > 0 ? trimmed : null
  }
  const targetConnection = normalize(connectionId)
  updateCachedConnections((current) => {
    const snapshot = ensureGrouped(current)
    let found = false
    const nextPersonal = snapshot.personal.map((p) => {
      if (p.provider !== provider) return { ...p }
      const connectionKey =
        normalize(p.connectionId) ?? normalize(p.id) ?? undefined
      if (targetConnection && connectionKey !== targetConnection) {
        return { ...p }
      }
      found = true
      return {
        ...p,
        connected: false,
        requiresReconnect: true,
        id: p.id ?? null,
        connectionId: p.connectionId ?? p.id ?? undefined
      }
    })
    // If no personal record exists for the provider, add a revoked placeholder
    if (!found) {
      nextPersonal.push({
        provider,
        ...defaultPersonalConnection(),
        connectionId: targetConnection ?? undefined,
        id: targetConnection ?? null,
        requiresReconnect: true
      })
    }
    const nextWorkspace = snapshot.workspace.filter((w) => {
      if (w.provider !== provider) return true
      if (!targetConnection) {
        return false
      }
      const workspaceKey =
        normalize(w.connectionId) ?? normalize(w.id) ?? undefined
      return workspaceKey !== targetConnection
    })
    return {
      personal: nextPersonal,
      workspace: nextWorkspace,
      slackPersonalAuth: snapshot.slackPersonalAuth,
      personalAuth: snapshot.personalAuth,
      manifests: snapshot.manifests
    }
  })
}

interface PromoteConnectionResponse {
  success?: boolean
  workspace_connection_id?: string | null
  workspaceConnectionId?: string | null
  created_by?: string | null
  createdBy?: string | null
  message?: string | null
}

export interface PromoteConnectionResult {
  workspaceConnectionId: string
  createdBy?: string
}

export async function promoteConnection({
  workspaceId,
  provider,
  connectionId
}: {
  workspaceId: string
  provider: OAuthProvider
  connectionId: string
}): Promise<PromoteConnectionResult> {
  const csrfToken = await getCsrfToken()
  const res = await fetch(
    buildApiUrl(`/api/workspaces/${workspaceId}/connections/promote`),
    {
      method: 'POST',
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        'x-csrf-token': csrfToken
      },
      body: JSON.stringify({
        provider,
        user_oauth_token_id: connectionId
      })
    }
  )

  const data = (await res
    .json()
    .catch(() => null)) as PromoteConnectionResponse | null

  const normalizeId = (value?: string | null): string | null => {
    if (typeof value !== 'string') {
      return null
    }
    const trimmed = value.trim()
    return trimmed.length > 0 ? trimmed : null
  }

  const workspaceConnectionId =
    normalizeId(data?.workspace_connection_id) ??
    normalizeId(data?.workspaceConnectionId ?? null)

  if (!res.ok || !workspaceConnectionId) {
    const message = typeof data?.message === 'string' ? data?.message : null
    throw new Error(message || 'Failed to promote connection')
  }

  const createdBy =
    normalizeId(data?.created_by) ??
    normalizeId(data?.createdBy ?? null) ??
    undefined

  return {
    workspaceConnectionId,
    createdBy
  }
}
