import { useMemo } from 'react'

import { useWorkflowStore, type WorkflowState } from './workflowStore'

export interface ActionMeta {
  actionType: string
  label: string
  dirty: boolean
  expanded: boolean
  timeout: number
  retries: number
  stopOnError: boolean
  hasValidationErrors: boolean
}

export interface KeyValuePair {
  key: string
  value: string
}

export interface HttpRequestActionParams extends Record<string, unknown> {
  url: string
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS'
  headers: KeyValuePair[]
  queryParams: KeyValuePair[]
  bodyType: 'raw' | 'json' | 'form'
  body: string
  formBody: KeyValuePair[]
  timeout: number
  followRedirects: boolean
  authType: 'none' | 'basic' | 'bearer'
  username: string
  password: string
  token: string
  dirty: boolean
}

export interface RunCustomCodeActionParams extends Record<string, unknown> {
  code: string
  inputs: KeyValuePair[]
  outputs: KeyValuePair[]
  dirty: boolean
}

export interface SheetsActionParams extends Record<string, unknown> {
  spreadsheetId: string
  worksheet: string
  worksheetId?: string
  columns: KeyValuePair[]
  accountEmail: string
  oauthConnectionScope: 'personal' | 'workspace' | ''
  oauthConnectionId: string
  dirty: boolean
}

export type NormalizedActionParams =
  | HttpRequestActionParams
  | RunCustomCodeActionParams
  | SheetsActionParams
  | (Record<string, unknown> & { dirty: boolean })

interface ActionNodeDataLike {
  actionType?: unknown
  label?: unknown
  expanded?: unknown
  dirty?: unknown
  timeout?: unknown
  retries?: unknown
  stopOnError?: unknown
  hasValidationErrors?: unknown
  params?: unknown
  inputs?: unknown
}

interface CacheEntry {
  meta: ActionMeta
  paramsByType: Map<string, NormalizedActionParams>
}

type MessagingProvider = 'slack' | 'teams' | 'googlechat'

function normalizeMessagingProvider(value: unknown): MessagingProvider | null {
  if (typeof value !== 'string') return null
  const compact = value
    .trim()
    .toLowerCase()
    .replace(/[\s_-]+/g, '')
  switch (compact) {
    case 'slack':
      return 'slack'
    case 'teams':
    case 'microsoftteams':
      return 'teams'
    case 'googlechat':
      return 'googlechat'
    default:
      return null
  }
}

function inferMessagingActionType(
  data: ActionNodeDataLike
): MessagingProvider | null {
  const source = (() => {
    if (data.params && typeof data.params === 'object') {
      return data.params as Record<string, unknown>
    }
    if (data.inputs && typeof data.inputs === 'object') {
      return data.inputs as Record<string, unknown>
    }
    return null
  })()

  if (!source) return null

  return (
    normalizeMessagingProvider(source.service) ??
    normalizeMessagingProvider(source.platform) ??
    null
  )
}

const FALLBACK_ACTION_META: ActionMeta = Object.freeze({
  actionType: 'email',
  label: 'Action',
  dirty: false,
  expanded: false,
  timeout: 5000,
  retries: 0,
  stopOnError: true,
  hasValidationErrors: false
})

const EMPTY_DATA: ActionNodeDataLike = Object.freeze({})

const cache = new WeakMap<object, CacheEntry>()

const HTTP_METHODS = new Set([
  'GET',
  'POST',
  'PUT',
  'PATCH',
  'DELETE',
  'HEAD',
  'OPTIONS'
])
const BODY_TYPES = new Set(['raw', 'json', 'form'])
const HTTP_AUTH_TYPES = new Set(['none', 'basic', 'bearer'])
const DEFAULT_KEY_VALUE: KeyValuePair = Object.freeze({ key: '', value: '' })

function toString(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : fallback
}

function toBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === 'boolean' ? value : fallback
}

function toFiniteNumber(value: unknown, fallback: number): number {
  if (typeof value !== 'number') return fallback
  if (!Number.isFinite(value)) return fallback
  return value
}

function toInteger(value: unknown, fallback: number): number {
  const num = toFiniteNumber(value, fallback)
  const truncated = Math.trunc(num)
  return truncated >= 0 ? truncated : fallback
}

function normalizeKeyValuePairs(value: unknown): KeyValuePair[] {
  if (!Array.isArray(value)) return []
  const normalized = value.map((entry) => {
    if (!entry || typeof entry !== 'object') return DEFAULT_KEY_VALUE
    const record = entry as Record<string, unknown>
    const key = toString(record.key)
    const val = toString(record.value)
    return { key, value: val }
  })

  return normalized
}

function cloneRecord(source: Record<string, unknown> | null | undefined) {
  if (!source) return {}
  return { ...source }
}

export function normalizeActionType(value: unknown): string {
  if (typeof value !== 'string') return 'email'
  const lowered = value.trim().toLowerCase()
  const compact = lowered.replace(/[\s_-]+/g, '')

  switch (lowered) {
    case 'send email':
      return 'email'
    case 'create google sheet row':
      return 'sheets'
    case 'http request':
      return 'http'
    case 'run custom code':
      return 'code'
    case 'asana':
      return 'asana'
    case 'messaging.slack':
    case 'action.messaging.slack':
    case 'slack message':
      return 'slack'
    case 'messaging.teams':
    case 'action.messaging.teams':
    case 'teams message':
    case 'microsoft teams':
      return 'teams'
    case 'messaging.googlechat':
    case 'action.messaging.googlechat':
    case 'google chat message':
    case 'google chat':
      return 'googlechat'
    default:
      break
  }

  switch (compact) {
    case 'slack':
      return 'slack'
    case 'teams':
    case 'microsoftteams':
      return 'teams'
    case 'googlechat':
      return 'googlechat'
    default:
      return lowered || 'email'
  }
}

function computeActionMeta(data: ActionNodeDataLike): ActionMeta {
  let actionType = normalizeActionType(data.actionType)
  if (actionType === 'messaging') {
    const inferred = inferMessagingActionType(data)
    if (inferred) {
      actionType = inferred
    }
  }
  const label = toString(data.label, 'Action')
  return Object.freeze({
    actionType,
    label,
    dirty: Boolean(data.dirty),
    expanded: Boolean(data.expanded),
    timeout: toFiniteNumber(data.timeout, 5000),
    retries: toInteger(data.retries, 0),
    stopOnError:
      data.stopOnError === undefined ? true : Boolean(data.stopOnError),
    hasValidationErrors: Boolean(data.hasValidationErrors)
  })
}

function metaEqual(a: ActionMeta, b: ActionMeta): boolean {
  return (
    a.actionType === b.actionType &&
    a.label === b.label &&
    a.dirty === b.dirty &&
    a.expanded === b.expanded &&
    a.timeout === b.timeout &&
    a.retries === b.retries &&
    a.stopOnError === b.stopOnError &&
    a.hasValidationErrors === b.hasValidationErrors
  )
}

function ensureCacheEntry(data: ActionNodeDataLike & object): CacheEntry {
  const nextMeta = computeActionMeta(data)
  const existing = cache.get(data)

  if (!existing) {
    const entry: CacheEntry = {
      meta: nextMeta,
      paramsByType: new Map()
    }
    cache.set(data, entry)
    return entry
  }

  if (!metaEqual(existing.meta, nextMeta)) {
    existing.meta = nextMeta
    existing.paramsByType.clear()
  }

  return existing
}

function extractParams(data: ActionNodeDataLike): Record<string, unknown> {
  if (data.params && typeof data.params === 'object') {
    return cloneRecord(data.params as Record<string, unknown>)
  }
  if (data.inputs && typeof data.inputs === 'object') {
    return cloneRecord(data.inputs as Record<string, unknown>)
  }
  return {}
}

function withDirty<T extends object>(
  value: T,
  dirty: boolean
): T & {
  dirty: boolean
} {
  return Object.freeze({ ...value, dirty })
}

function normalizeHttpParams(
  data: ActionNodeDataLike,
  meta: ActionMeta
): HttpRequestActionParams {
  const params = extractParams(data)
  const methodRaw = toString(params.method)?.toUpperCase()
  const method = HTTP_METHODS.has(methodRaw) ? methodRaw : 'GET'
  const bodyTypeRaw = toString(params.bodyType).toLowerCase()
  const bodyType = BODY_TYPES.has(bodyTypeRaw)
    ? (bodyTypeRaw as 'raw' | 'json' | 'form')
    : 'raw'
  const authTypeRaw = toString(params.authType).toLowerCase()
  const authType = HTTP_AUTH_TYPES.has(authTypeRaw)
    ? (authTypeRaw as 'none' | 'basic' | 'bearer')
    : 'none'

  const normalized = {
    url: toString(params.url),
    method: method as HttpRequestActionParams['method'],
    headers: normalizeKeyValuePairs(params.headers),
    queryParams: normalizeKeyValuePairs(params.queryParams),
    bodyType,
    body: toString(params.body),
    formBody: normalizeKeyValuePairs(params.formBody),
    timeout: toFiniteNumber(params.timeout, 30000),
    followRedirects: toBoolean(params.followRedirects, true),
    authType,
    username: toString(params.username),
    password: toString(params.password),
    token: toString(params.token)
  }

  return withDirty(normalized, meta.dirty)
}

function normalizeRunCustomCodeParams(
  data: ActionNodeDataLike,
  meta: ActionMeta
): RunCustomCodeActionParams {
  const params = extractParams(data)
  const normalized = {
    code: toString(params.code),
    inputs: normalizeKeyValuePairs(params.inputs),
    outputs: normalizeKeyValuePairs(params.outputs)
  }

  return withDirty(normalized, meta.dirty)
}

function normalizeSheetsParams(
  data: ActionNodeDataLike,
  meta: ActionMeta
): SheetsActionParams {
  const params = extractParams(data)
  const scopeRaw = toString(params.oauthConnectionScope).toLowerCase()
  const normalizedScope =
    scopeRaw === 'personal' || scopeRaw === 'workspace'
      ? (scopeRaw as 'personal' | 'workspace')
      : ''

  const normalized = {
    spreadsheetId: toString(params.spreadsheetId),
    worksheet: toString(params.worksheet),
    columns: normalizeKeyValuePairs(params.columns),
    accountEmail: toString(params.accountEmail),
    oauthConnectionScope: normalizedScope,
    oauthConnectionId: toString(params.oauthConnectionId)
  }

  return withDirty(normalized as SheetsActionParams, meta.dirty)
}

// Stable default params per action type to avoid returning
// a fresh object when a node is missing. This satisfies
// useSyncExternalStore caching and prevents dev warnings.
const DEFAULT_HTTP_PARAMS: HttpRequestActionParams = normalizeHttpParams(
  EMPTY_DATA,
  FALLBACK_ACTION_META
)
const DEFAULT_CODE_PARAMS: RunCustomCodeActionParams =
  normalizeRunCustomCodeParams(EMPTY_DATA, FALLBACK_ACTION_META)
const DEFAULT_SHEETS_PARAMS: SheetsActionParams = normalizeSheetsParams(
  EMPTY_DATA,
  FALLBACK_ACTION_META
)
const DEFAULT_GENERIC_PARAMS: Record<string, unknown> & { dirty: boolean } =
  normalizeDefaultParams(EMPTY_DATA, FALLBACK_ACTION_META)

function getDefaultParamsForType(type: string): NormalizedActionParams {
  switch (type) {
    case 'http':
      return DEFAULT_HTTP_PARAMS
    case 'code':
      return DEFAULT_CODE_PARAMS
    case 'sheets':
      return DEFAULT_SHEETS_PARAMS
    default:
      return DEFAULT_GENERIC_PARAMS
  }
}

function normalizeDefaultParams(
  data: ActionNodeDataLike,
  meta: ActionMeta
): Record<string, unknown> & { dirty: boolean } {
  const params = extractParams(data)
  const normalized =
    params && typeof params === 'object'
      ? { ...params }
      : ({} as Record<string, unknown>)
  return withDirty(normalized, meta.dirty)
}

function computeParams(
  type: string,
  data: ActionNodeDataLike,
  meta: ActionMeta
): NormalizedActionParams {
  switch (type) {
    case 'http':
      return normalizeHttpParams(data, meta)
    case 'code':
      return normalizeRunCustomCodeParams(data, meta)
    case 'sheets':
      return normalizeSheetsParams(data, meta)
    default:
      return normalizeDefaultParams(data, meta)
  }
}

function getNormalizedParams(
  entry: CacheEntry,
  data: ActionNodeDataLike,
  type: string
): NormalizedActionParams {
  const existing = entry.paramsByType.get(type)
  if (existing) {
    return existing
  }

  const computed = computeParams(type, data, entry.meta)
  entry.paramsByType.set(type, computed)
  return computed
}

function findNodeData(state: WorkflowState, nodeId: string) {
  return state.nodes.find((node) => node.id === nodeId)?.data as
    | (ActionNodeDataLike & object)
    | null
    | undefined
}

export function selectActionMeta(nodeId: string) {
  return (state: WorkflowState): ActionMeta => {
    const data = findNodeData(state, nodeId)
    if (!data) {
      return FALLBACK_ACTION_META
    }
    const entry = ensureCacheEntry(data)
    return entry.meta
  }
}

export function selectActionParams<T extends object = Record<string, unknown>>(
  nodeId: string,
  overrideType?: string
) {
  return (state: WorkflowState): T => {
    const data = findNodeData(state, nodeId)
    if (!data) {
      const type = normalizeActionType(overrideType)
      return getDefaultParamsForType(type) as T
    }

    const entry = ensureCacheEntry(data)
    const type = normalizeActionType(overrideType ?? entry.meta.actionType)
    return getNormalizedParams(entry, data, type) as T
  }
}

export function useSheetsActionParams(nodeId: string) {
  return useActionParams<SheetsActionParams>(nodeId, 'sheets')
}

export function useActionMeta(nodeId: string) {
  const selector = useMemo(() => selectActionMeta(nodeId), [nodeId])
  return useWorkflowStore(selector)
}

export function useActionParams<T extends object = Record<string, unknown>>(
  nodeId: string,
  overrideType?: string
) {
  const selector = useMemo(
    () => selectActionParams<T>(nodeId, overrideType),
    [nodeId, overrideType]
  )
  return useWorkflowStore(selector)
}
