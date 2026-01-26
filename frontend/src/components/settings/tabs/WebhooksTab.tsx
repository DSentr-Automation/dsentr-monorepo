import { Fragment, useCallback, useEffect, useMemo, useState } from 'react'
import ConfirmDialog from '@/components/ui/dialog/ConfirmDialog'
import ProviderWebhooks from '@/components/settings/ProviderWebhooks'
import WebhookSourceSubscriptions from '@/components/settings/tabs/WebhookSourceSubscriptions'
import { listWorkflows, type WorkflowRecord } from '@/lib/workflowApi'
import {
  createWebhookSource,
  deleteWebhookSource,
  listWebhookSources,
  rotateWebhookSourceSecret,
  type WebhookSource
} from '@/lib/webhookSourcesApi'
import { API_BASE_URL } from '@/lib/config'
import { errorMessage } from '@/lib/errorMessage'
import { normalizePlanTier } from '@/lib/planTiers'
import { selectCurrentWorkspace, useAuth } from '@/stores/auth'

const RELATIVE_TIME_FORMATTER = new Intl.RelativeTimeFormat('en', {
  numeric: 'auto'
})
const RELATIVE_UNITS: Array<[Intl.RelativeTimeFormatUnit, number]> = [
  ['year', 60 * 60 * 24 * 365],
  ['month', 60 * 60 * 24 * 30],
  ['week', 60 * 60 * 24 * 7],
  ['day', 60 * 60 * 24],
  ['hour', 60 * 60],
  ['minute', 60],
  ['second', 1]
]

function formatRelativeTime(value?: string | null): string {
  if (!value) return 'Never'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 'Never'
  const diffSeconds = Math.round((date.getTime() - Date.now()) / 1000)
  for (const [unit, secondsInUnit] of RELATIVE_UNITS) {
    if (Math.abs(diffSeconds) >= secondsInUnit || unit === 'second') {
      return RELATIVE_TIME_FORMATTER.format(
        Math.round(diffSeconds / secondsInUnit),
        unit
      )
    }
  }
  return 'Never'
}

function formatAbsoluteTime(value?: string | null): string {
  if (!value) return ''
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return ''
  return date.toLocaleString()
}

export default function WebhooksTab() {
  const [workflows, setWorkflows] = useState<WorkflowRecord[]>([])
  const [copied, setCopied] = useState(false)
  const [copiedCurl, setCopiedCurl] = useState(false)
  const [copiedPS, setCopiedPS] = useState(false)
  const [copiedJS, setCopiedJS] = useState(false)

  const [sources, setSources] = useState<WebhookSource[]>([])
  const [sourcesLoading, setSourcesLoading] = useState(false)
  const [sourcesError, setSourcesError] = useState<string | null>(null)
  const [showCreateSource, setShowCreateSource] = useState(false)
  const [createSourceName, setCreateSourceName] = useState('')
  const [createRequireHmac, setCreateRequireHmac] = useState(true)
  const [createSourceError, setCreateSourceError] = useState<string | null>(
    null
  )
  const [createSourceBusy, setCreateSourceBusy] = useState(false)
  const [actionBusy, setActionBusy] = useState<{
    id: string
    action: 'rotate' | 'delete'
  } | null>(null)
  const [pendingRotate, setPendingRotate] = useState<WebhookSource | null>(null)
  const [pendingDelete, setPendingDelete] = useState<WebhookSource | null>(null)
  const [copiedSourceId, setCopiedSourceId] = useState<string | null>(null)
  const [secretReveal, setSecretReveal] = useState<{
    action: 'created' | 'rotated'
    name: string
    secret: string
    endpointUrl: string
  } | null>(null)
  const [secretAcknowledged, setSecretAcknowledged] = useState(false)
  const [copiedSecret, setCopiedSecret] = useState(false)
  const [copiedSecretEndpoint, setCopiedSecretEndpoint] = useState(false)

  const copyText = useCallback(async (value: string) => {
    if (!value) return false
    try {
      if (navigator?.clipboard?.writeText) {
        await navigator.clipboard.writeText(value)
      } else {
        const ta = document.createElement('textarea')
        ta.value = value
        document.body.appendChild(ta)
        ta.select()
        document.execCommand('copy')
        document.body.removeChild(ta)
      }
      return true
    } catch (err) {
      console.error(errorMessage(err))
      return false
    }
  }, [])

  const currentWorkspace = useAuth(selectCurrentWorkspace)
  const userPlan = useAuth((state) => state.user?.plan ?? null)
  const activeWorkspaceId = currentWorkspace?.workspace.id ?? null
  const workspaceRole = currentWorkspace?.role ?? 'viewer'
  const planTier = useMemo(
    () =>
      normalizePlanTier(
        currentWorkspace?.workspace.plan ?? userPlan ?? undefined
      ),
    [currentWorkspace?.workspace.plan, userPlan]
  )
  const canManageWebhookSources = ['owner', 'admin', 'user'].includes(
    workspaceRole
  )
  const manageWebhookSourcesPermissionMessage =
    'Only workspace writers (users, admins, or owners) can manage webhook sources.'

  // Load available workflows for the active workspace (or personal) - used for subscriptions
  useEffect(() => {
    listWorkflows(activeWorkspaceId)
      .then((ws) => {
        setWorkflows(ws)
      })
      .catch(() => {})
  }, [activeWorkspaceId])

  const loadWebhookSources = useCallback(async (workspaceId: string | null) => {
    if (!workspaceId) {
      setSources([])
      setSourcesError(null)
      setSourcesLoading(false)
      return
    }
    setSourcesLoading(true)
    try {
      const results = await listWebhookSources(workspaceId)
      setSources(results)
      setSourcesError(null)
    } catch (err) {
      setSourcesError(errorMessage(err))
    } finally {
      setSourcesLoading(false)
    }
  }, [])

  useEffect(() => {
    void loadWebhookSources(activeWorkspaceId)
  }, [activeWorkspaceId, loadWebhookSources])

  useEffect(() => {
    setShowCreateSource(false)
    setCreateSourceName('')
    setCreateRequireHmac(true)
    setCreateSourceError(null)
    setSourcesError(null)
    setSecretReveal(null)
    setSecretAcknowledged(false)
    setCopiedSourceId(null)
  }, [activeWorkspaceId])

  const base = useMemo(() => (API_BASE_URL || '').replace(/\/$/, ''), [])
  const resolveSourceEndpoint = useCallback(
    (sourceId: string) => `${base}/api/webhooks/${sourceId}`,
    [base]
  )
  const sourceExampleEndpoint = useMemo(() => {
    if (sources.length && sources[0]?.id) {
      return resolveSourceEndpoint(sources[0].id)
    }
    return `${base}/api/webhooks/{source_id}`
  }, [base, resolveSourceEndpoint, sources])
  const examplePayload = useMemo(
    () => '{"event_type":"order.created","price":"123"}',
    []
  )
  const exampleSourceLabel = useMemo(() => {
    const name = sources[0]?.name?.trim()
    return name ? `${name} source endpoint` : 'Webhook source endpoint'
  }, [sources])

  const showEnabledColumn = useMemo(
    () => sources.some((source) => typeof source.enabled === 'boolean'),
    [sources]
  )
  const sourceColumnCount =
    4 + (showEnabledColumn ? 1 : 0) + (canManageWebhookSources ? 1 : 0)

  useEffect(() => {
    setCopied(false)
  }, [sourceExampleEndpoint])

  useEffect(() => {
    setCopiedCurl(false)
    setCopiedPS(false)
    setCopiedJS(false)
  }, [sourceExampleEndpoint])

  useEffect(() => {
    if (!secretReveal) return
    setSecretAcknowledged(false)
    setCopiedSecret(false)
    setCopiedSecretEndpoint(false)
  }, [secretReveal])

  const handleCreateWebhookSource = useCallback(async () => {
    const trimmedName = createSourceName.trim()
    if (!trimmedName) {
      setCreateSourceError('Name is required.')
      return
    }
    if (!activeWorkspaceId) {
      setCreateSourceError(
        'Select a workspace before creating webhook sources.'
      )
      return
    }
    setCreateSourceBusy(true)
    setCreateSourceError(null)
    setSourcesError(null)
    try {
      const result = await createWebhookSource(activeWorkspaceId, {
        name: trimmedName,
        requireHmac: createRequireHmac
      })
      setSources((prev) => {
        const next = prev.filter((source) => source.id !== result.source.id)
        return [result.source, ...next]
      })
      setShowCreateSource(false)
      setCreateSourceName('')
      setCreateRequireHmac(true)
      if (result.secret) {
        setSecretReveal({
          action: 'created',
          name: result.source.name || trimmedName,
          secret: result.secret,
          endpointUrl: resolveSourceEndpoint(result.source.id)
        })
      } else {
        setSourcesError(
          'Webhook secret was not returned. Rotate the secret to generate a new one.'
        )
      }
    } catch (err) {
      setCreateSourceError(errorMessage(err))
    } finally {
      setCreateSourceBusy(false)
    }
  }, [
    activeWorkspaceId,
    createRequireHmac,
    createSourceName,
    resolveSourceEndpoint
  ])

  const handleConfirmRotateSource = useCallback(async () => {
    if (!pendingRotate || actionBusy) return
    const target = pendingRotate
    setPendingRotate(null)
    setSourcesError(null)
    setActionBusy({ id: target.id, action: 'rotate' })
    try {
      if (!activeWorkspaceId) return
      const result = await rotateWebhookSourceSecret(
        activeWorkspaceId,
        target.id
      )
      setSources((prev) =>
        prev.map((source) =>
          source.id === result.source.id ? result.source : source
        )
      )
      if (result.secret) {
        setSecretReveal({
          action: 'rotated',
          name: result.source.name || target.name,
          secret: result.secret,
          endpointUrl: resolveSourceEndpoint(result.source.id)
        })
      } else {
        setSourcesError('Webhook secret was not returned.')
      }
    } catch (err) {
      setSourcesError(errorMessage(err))
    } finally {
      setActionBusy(null)
    }
  }, [pendingRotate, actionBusy, resolveSourceEndpoint, activeWorkspaceId])

  const handleConfirmDeleteSource = useCallback(async () => {
    if (!pendingDelete || actionBusy) return
    const target = pendingDelete
    setPendingDelete(null)
    setSourcesError(null)
    setActionBusy({ id: target.id, action: 'delete' })
    try {
      if (!activeWorkspaceId) return
      await deleteWebhookSource(activeWorkspaceId, target.id)
      setSources((prev) => prev.filter((source) => source.id !== target.id))
    } catch (err) {
      setSourcesError(errorMessage(err))
    } finally {
      setActionBusy(null)
    }
  }, [pendingDelete, actionBusy, activeWorkspaceId])
  return (
    <div className="space-y-4 relative">
      <div className="border-t border-zinc-200 dark:border-zinc-700 pt-3">
        <h3 className="font-semibold mb-2">Webhook Ingress</h3>
        <p className="text-xs text-zinc-600 dark:text-zinc-400 mb-2">
          Webhook sources receive events at{' '}
          <code>/api/webhooks/{'{source_id}'}</code>. Include{' '}
          <code>event_type</code> in the JSON body; subscriptions route it to
          workflow triggers.
        </p>
        {sourceExampleEndpoint ? (
          <div className="flex items-center gap-2">
            <code className="text-xs px-2 py-1 rounded bg-zinc-100 dark:bg-zinc-800 break-all">
              {sourceExampleEndpoint}
            </code>
            <button
              className="text-xs px-2 py-1 rounded border"
              onClick={async () => {
                const ok = await copyText(sourceExampleEndpoint)
                if (ok) {
                  setCopied(true)
                  setTimeout(() => setCopied(false), 1500)
                }
              }}
            >
              {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
        ) : (
          <p className="text-sm text-zinc-500">
            Create a webhook source to get an endpoint.
          </p>
        )}

        {/* Examples (basic, no HMAC) */}
        <div className="mt-3 space-y-2">
          <div className="font-medium text-xs">Examples</div>
          <p className="text-[11px] text-zinc-500">
            Using {exampleSourceLabel}
          </p>

          {/* curl */}
          <div className="relative">
            <span className="absolute right-2 top-1 text-[10px] uppercase tracking-wide px-2 py-0.5 rounded bg-zinc-200 dark:bg-zinc-700 text-zinc-700 dark:text-zinc-200">
              curl
            </span>
            <pre className="bg-zinc-100 dark:bg-zinc-800 p-2 rounded overflow-auto themed-scroll whitespace-pre-wrap break-words text-[11px]">
              <code>
                {sourceExampleEndpoint
                  ? `curl -X POST \\
  -H "Content-Type: application/json" \\
  -d '${examplePayload}' \\
  ${sourceExampleEndpoint}`
                  : ''}
              </code>
            </pre>
            <div className="text-right mt-1">
              <button
                className="text-[10px] px-2 py-0.5 rounded border"
                onClick={async () => {
                  const ok = await copyText(
                    sourceExampleEndpoint
                      ? `curl -X POST -H "Content-Type: application/json" -d '${examplePayload}' ${sourceExampleEndpoint}`
                      : ''
                  )
                  if (ok) {
                    setCopiedCurl(true)
                    setTimeout(() => setCopiedCurl(false), 1500)
                  }
                }}
              >
                {copiedCurl ? 'Copied!' : 'Copy'}
              </button>
            </div>
          </div>

          {/* PowerShell */}
          <div className="relative">
            <span className="absolute right-2 top-1 text-[10px] uppercase tracking-wide px-2 py-0.5 rounded bg-zinc-200 dark:bg-zinc-700 text-zinc-700 dark:text-zinc-200">
              powershell
            </span>
            <pre className="bg-zinc-100 dark:bg-zinc-800 p-2 rounded overflow-auto themed-scroll whitespace-pre-wrap break-words text-[11px]">
              <code>
                {sourceExampleEndpoint
                  ? `Invoke-RestMethod -Method POST \`\n  -Uri "${sourceExampleEndpoint}" \`\n  -ContentType "application/json" \`\n  -Body '${examplePayload}'`
                  : ''}
              </code>
            </pre>
            <div className="text-right mt-1">
              <button
                className="text-[10px] px-2 py-0.5 rounded border"
                onClick={async () => {
                  const ok = await copyText(
                    sourceExampleEndpoint
                      ? `Invoke-RestMethod -Method POST -Uri "${sourceExampleEndpoint}" -ContentType "application/json" -Body '${examplePayload}'`
                      : ''
                  )
                  if (ok) {
                    setCopiedPS(true)
                    setTimeout(() => setCopiedPS(false), 1500)
                  }
                }}
              >
                {copiedPS ? 'Copied!' : 'Copy'}
              </button>
            </div>
          </div>

          {/* JavaScript */}
          <div className="relative">
            <span className="absolute right-2 top-1 text-[10px] uppercase tracking-wide px-2 py-0.5 rounded bg-zinc-200 dark:bg-zinc-700 text-zinc-700 dark:text-zinc-200">
              javascript
            </span>
            <pre className="bg-zinc-100 dark:bg-zinc-800 p-2 rounded overflow-auto themed-scroll whitespace-pre-wrap break-words text-[11px]">
              <code>
                {sourceExampleEndpoint
                  ? `await fetch("${sourceExampleEndpoint}", {\n  method: "POST",\n  headers: { "Content-Type": "application/json" },\n  body: JSON.stringify({ event_type: "order.created", price: "123" })\n});`
                  : ''}
              </code>
            </pre>
            <div className="text-right mt-1">
              <button
                className="text-[10px] px-2 py-0.5 rounded border"
                onClick={async () => {
                  const ok = await copyText(
                    sourceExampleEndpoint
                      ? `await fetch("${sourceExampleEndpoint}", {\n  method: "POST",\n  headers: { "Content-Type": "application/json" },\n  body: JSON.stringify({ event_type: "order.created", price: "123" })\n});`
                      : ''
                  )
                  if (ok) {
                    setCopiedJS(true)
                    setTimeout(() => setCopiedJS(false), 1500)
                  }
                }}
              >
                {copiedJS ? 'Copied!' : 'Copy'}
              </button>
            </div>
          </div>
        </div>
      </div>
      <ProviderWebhooks workspaceId={activeWorkspaceId} planTier={planTier} />
      <div className="border-t border-zinc-200 dark:border-zinc-700 pt-3">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div>
            <h3 className="font-semibold mb-1">Webhook Sources</h3>
            <p className="text-xs text-zinc-600 dark:text-zinc-400">
              Sources define the inbound endpoint, secret, and HMAC requirement.
              Subscriptions map event types to workflow triggers.
            </p>
          </div>
          {canManageWebhookSources && (
            <button
              className="text-xs px-3 py-1 rounded border"
              onClick={() => setShowCreateSource(true)}
              disabled={showCreateSource}
            >
              Create Webhook Source
            </button>
          )}
        </div>
        {!canManageWebhookSources && (
          <p className="text-xs text-amber-600 dark:text-amber-400 mt-2">
            You have read-only access. {manageWebhookSourcesPermissionMessage}
          </p>
        )}
        {showCreateSource && (
          <div className="mt-3 rounded border border-zinc-200 dark:border-zinc-700 bg-white/60 dark:bg-zinc-900/60 p-3 space-y-3">
            <div className="grid gap-3 md:grid-cols-2">
              <div className="space-y-1">
                <label className="text-xs font-medium text-zinc-700 dark:text-zinc-200">
                  Name
                </label>
                <input
                  value={createSourceName}
                  onChange={(e) => setCreateSourceName(e.target.value)}
                  placeholder="Inbound partner"
                  className="w-full rounded border px-2 py-1 text-sm bg-white dark:bg-zinc-900 dark:border-zinc-700"
                  disabled={createSourceBusy}
                />
              </div>
              <div className="flex items-end">
                <label className="text-xs inline-flex items-center gap-2">
                  <input
                    type="checkbox"
                    checked={createRequireHmac}
                    onChange={(e) => setCreateRequireHmac(e.target.checked)}
                    disabled={createSourceBusy}
                  />
                  Require HMAC signature
                </label>
              </div>
            </div>
            {createSourceError && (
              <p className="text-xs text-red-500">{createSourceError}</p>
            )}
            <div className="flex items-center gap-2">
              <button
                className="text-xs px-3 py-1 rounded bg-blue-600 text-white disabled:opacity-50"
                onClick={handleCreateWebhookSource}
                disabled={!canManageWebhookSources || createSourceBusy}
              >
                {createSourceBusy ? 'Creating.' : 'Create'}
              </button>
              <button
                className="text-xs px-3 py-1 rounded border"
                onClick={() => {
                  setShowCreateSource(false)
                  setCreateSourceError(null)
                  setSourcesError(null)
                }}
                disabled={createSourceBusy}
              >
                Cancel
              </button>
            </div>
          </div>
        )}
        {sourcesError && (
          <p className="text-xs text-red-500 mt-2">{sourcesError}</p>
        )}
        {sourcesLoading ? (
          <p className="text-sm text-zinc-500 mt-2">Loading.</p>
        ) : sources.length === 0 ? (
          <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-2">
            No webhook sources yet.
          </p>
        ) : (
          <div className="mt-3 overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-zinc-500">
                  <th className="py-2">Name</th>
                  <th className="py-2">Endpoint URL</th>
                  <th className="py-2">Require HMAC</th>
                  {showEnabledColumn && <th className="py-2">Enabled</th>}
                  <th className="py-2">Last seen</th>
                  {canManageWebhookSources && (
                    <th className="py-2 text-right">Actions</th>
                  )}
                </tr>
              </thead>
              <tbody>
                {sources.map((source) => {
                  const endpointUrl = resolveSourceEndpoint(source.id)
                  const lastSeenLabel = formatRelativeTime(source.lastSeenAt)
                  const lastSeenTitle = formatAbsoluteTime(source.lastSeenAt)
                  const isBusy = actionBusy?.id === source.id
                  const isRotateBusy = isBusy && actionBusy?.action === 'rotate'
                  const isDeleteBusy = isBusy && actionBusy?.action === 'delete'
                  return (
                    <Fragment key={source.id}>
                      <tr className="border-t border-zinc-200 dark:border-zinc-700">
                        <td className="py-2 font-medium text-zinc-900 dark:text-zinc-100">
                          {source.name || 'Untitled'}
                        </td>
                        <td className="py-2">
                          <div className="flex flex-wrap items-center gap-2">
                            <code className="text-xs px-2 py-1 rounded bg-zinc-100 dark:bg-zinc-800 break-all">
                              {endpointUrl}
                            </code>
                            <button
                              className="text-[10px] px-2 py-0.5 rounded border"
                              onClick={async () => {
                                const ok = await copyText(endpointUrl)
                                if (ok) {
                                  setCopiedSourceId(source.id)
                                  setTimeout(
                                    () => setCopiedSourceId(null),
                                    1500
                                  )
                                }
                              }}
                            >
                              {copiedSourceId === source.id
                                ? 'Copied!'
                                : 'Copy'}
                            </button>
                          </div>
                        </td>
                        <td className="py-2 text-xs">
                          {source.requireHmac ? 'Yes' : 'No'}
                        </td>
                        {showEnabledColumn && (
                          <td className="py-2 text-xs">
                            {typeof source.enabled === 'boolean'
                              ? source.enabled
                                ? 'Enabled'
                                : 'Disabled'
                              : 'N/A'}
                          </td>
                        )}
                        <td
                          className="py-2 text-xs text-zinc-600 dark:text-zinc-300"
                          title={lastSeenTitle || undefined}
                        >
                          {lastSeenLabel}
                        </td>
                        {canManageWebhookSources && (
                          <td className="py-2 text-right">
                            <div className="flex items-center justify-end gap-2">
                              <button
                                className="text-xs px-2 py-1 rounded border"
                                disabled={Boolean(actionBusy)}
                                onClick={() => setPendingRotate(source)}
                              >
                                {isRotateBusy ? 'Rotating.' : 'Rotate secret'}
                              </button>
                              <button
                                className="text-xs px-2 py-1 rounded border text-red-600 disabled:opacity-50"
                                disabled={Boolean(actionBusy)}
                                onClick={() => setPendingDelete(source)}
                              >
                                {isDeleteBusy ? 'Deleting.' : 'Delete'}
                              </button>
                            </div>
                          </td>
                        )}
                      </tr>
                      <tr className="border-b border-zinc-200 dark:border-zinc-700">
                        <td className="py-3" colSpan={sourceColumnCount}>
                          <WebhookSourceSubscriptions
                            source={source}
                            workspaceId={activeWorkspaceId ?? ''}
                            workflows={workflows}
                            canManage={canManageWebhookSources}
                          />
                        </td>
                      </tr>
                    </Fragment>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {secretReveal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4">
          <div className="w-full max-w-lg rounded-xl border border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-900 p-4 shadow-xl">
            <h4 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
              {secretReveal.action === 'created'
                ? 'Webhook source created'
                : 'Webhook secret rotated'}
            </h4>
            <p className="mt-2 text-xs text-zinc-600 dark:text-zinc-300">
              Copy this secret now. It will not be shown again and cannot be
              recovered.
            </p>
            <p className="mt-1 text-xs text-zinc-500">
              Source:{' '}
              <span className="font-medium text-zinc-700 dark:text-zinc-200">
                {secretReveal.name}
              </span>
            </p>
            <div className="mt-3 space-y-3">
              <div className="space-y-1">
                <div className="text-[11px] text-zinc-500">Secret</div>
                <div className="flex flex-wrap items-center gap-2">
                  <code className="text-xs px-2 py-1 rounded bg-zinc-100 dark:bg-zinc-800 break-all">
                    {secretReveal.secret}
                  </code>
                  <button
                    className="text-[10px] px-2 py-0.5 rounded border"
                    onClick={async () => {
                      const ok = await copyText(secretReveal.secret)
                      if (ok) {
                        setCopiedSecret(true)
                        setTimeout(() => setCopiedSecret(false), 1500)
                      }
                    }}
                  >
                    {copiedSecret ? 'Copied!' : 'Copy'}
                  </button>
                </div>
              </div>
              <div className="space-y-1">
                <div className="text-[11px] text-zinc-500">Endpoint URL</div>
                <div className="flex flex-wrap items-center gap-2">
                  <code className="text-xs px-2 py-1 rounded bg-zinc-100 dark:bg-zinc-800 break-all">
                    {secretReveal.endpointUrl}
                  </code>
                  <button
                    className="text-[10px] px-2 py-0.5 rounded border"
                    onClick={async () => {
                      const ok = await copyText(secretReveal.endpointUrl)
                      if (ok) {
                        setCopiedSecretEndpoint(true)
                        setTimeout(() => setCopiedSecretEndpoint(false), 1500)
                      }
                    }}
                  >
                    {copiedSecretEndpoint ? 'Copied!' : 'Copy'}
                  </button>
                </div>
              </div>
            </div>
            <label className="mt-4 flex items-start gap-2 text-xs text-zinc-600 dark:text-zinc-300">
              <input
                type="checkbox"
                checked={secretAcknowledged}
                onChange={(e) => setSecretAcknowledged(e.target.checked)}
              />
              I have stored this secret in a safe place.
            </label>
            <div className="mt-4 flex justify-end">
              <button
                className="px-3 py-1 text-xs rounded bg-blue-600 text-white disabled:opacity-50"
                disabled={!secretAcknowledged}
                onClick={() => {
                  setSecretReveal(null)
                  setSecretAcknowledged(false)
                }}
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
      <ConfirmDialog
        isOpen={pendingRotate !== null}
        title="Rotate webhook secret?"
        message="Rotating the secret invalidates the old secret immediately. Update any clients that use it."
        confirmText="Rotate secret"
        cancelText="Cancel"
        onCancel={() => setPendingRotate(null)}
        onConfirm={handleConfirmRotateSource}
      />
      <ConfirmDialog
        isOpen={pendingDelete !== null}
        title="Delete webhook source?"
        message="Deleting this source means subscriptions will stop receiving events. This action cannot be undone."
        confirmText="Delete source"
        cancelText="Cancel"
        onCancel={() => setPendingDelete(null)}
        onConfirm={handleConfirmDeleteSource}
      />{' '}
    </div>
  )
}
