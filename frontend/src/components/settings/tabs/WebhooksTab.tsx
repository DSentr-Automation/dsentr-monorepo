import { Fragment, useCallback, useEffect, useMemo, useState } from 'react'
import ConfirmDialog from '@/components/ui/dialog/ConfirmDialog'
import WebhookSourceSubscriptions from '@/components/settings/tabs/WebhookSourceSubscriptions'
import {
  listWorkflows,
  type WorkflowRecord,
  type WorkflowWebhookEndpoint,
  getWebhookUrl,
  regenerateWebhookUrl,
  getWebhookConfig,
  setWebhookConfig,
  regenerateWebhookSigningKey
} from '@/lib/workflowApi'
import {
  createWebhookSource,
  deleteWebhookSource,
  listWebhookSources,
  rotateWebhookSourceSecret,
  type WebhookSource
} from '@/lib/webhookSourcesApi'
import { API_BASE_URL } from '@/lib/config'
import { errorMessage } from '@/lib/errorMessage'
import { selectCurrentWorkspace, useAuth } from '@/stores/auth'
import { normalizePlanTier } from '@/lib/planTiers'

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
  const [workflowId, setWorkflowId] = useState<string>('')
  const [url, setUrl] = useState<string>('')
  const [triggerUrls, setTriggerUrls] = useState<WorkflowWebhookEndpoint[]>([])
  const [loading, setLoading] = useState(false)
  const [copied, setCopied] = useState(false)
  const [regenBusy, setRegenBusy] = useState(false)
  const [confirming, setConfirming] = useState(false)

  const [requireHmac, setRequireHmac] = useState(false)
  const [replayWindow, setReplayWindow] = useState(300)
  const [signingKey, setSigningKey] = useState('')
  const [saveBusy, setSaveBusy] = useState(false)
  const [justSaved, setJustSaved] = useState(false)
  const [copiedCurl, setCopiedCurl] = useState(false)
  const [copiedPS, setCopiedPS] = useState(false)
  const [copiedJS, setCopiedJS] = useState(false)
  const [copiedHmacCurl, setCopiedHmacCurl] = useState(false)
  const [copiedHmacPS, setCopiedHmacPS] = useState(false)
  const [copiedHmacJS, setCopiedHmacJS] = useState(false)
  const [regenSigningBusy, setRegenSigningBusy] = useState(false)
  const [justRegeneratedSigning, setJustRegeneratedSigning] = useState(false)

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
  const activeWorkspaceId = currentWorkspace?.workspace.id ?? null
  const canManageWebhooks =
    currentWorkspace?.role === 'owner' || currentWorkspace?.role === 'admin'
  const manageWebhooksPermissionMessage =
    'Only workspace admins or owners can manage webhook settings.'
  const planTier = normalizePlanTier(currentWorkspace?.workspace.plan ?? null)
  const isSoloPlan = planTier === 'solo'
  const workspaceRole = currentWorkspace?.role ?? 'viewer'
  const canManageWebhookSources = ['owner', 'admin', 'user'].includes(
    workspaceRole
  )
  const manageWebhookSourcesPermissionMessage =
    'Only workspace writers (users, admins, or owners) can manage webhook sources.'

  // Load available workflows for the active workspace (or personal)
  useEffect(() => {
    listWorkflows(activeWorkspaceId)
      .then((ws) => {
        setWorkflows(ws)
        setWorkflowId((prev) => {
          if (prev && ws.some((w) => w.id === prev)) return prev
          return ws[0]?.id ?? ''
        })
      })
      .catch(() => {})
  }, [activeWorkspaceId])

  // Fetch webhook URL for selected workflow
  useEffect(() => {
    if (!workflowId) {
      setUrl('')
      setTriggerUrls([])
      return
    }
    setLoading(true)
    getWebhookUrl(workflowId)
      .then((res) => {
        setUrl(res.url)
        setTriggerUrls(res.triggers ?? [])
      })
      .catch(() => {
        setUrl('')
        setTriggerUrls([])
      })
      .finally(() => setLoading(false))
  }, [workflowId])

  // Fetch HMAC config
  useEffect(() => {
    if (!workflowId) {
      setRequireHmac(false)
      setReplayWindow(300)
      setSigningKey('')
      return
    }
    getWebhookConfig(workflowId)
      .then((cfg) => {
        setRequireHmac(!!cfg.require_hmac)
        setReplayWindow(Number(cfg.replay_window_sec) || 300)
        setSigningKey(cfg.signing_key || '')
      })
      .catch(() => {})
  }, [workflowId])

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

  const selected = useMemo(
    () => workflows.find((w) => w.id === workflowId) ?? null,
    [workflows, workflowId]
  )

  const base = useMemo(() => (API_BASE_URL || '').replace(/\/$/, ''), [])
  const resolveSourceEndpoint = useCallback(
    (sourceId: string) => `${base}/api/webhooks/${sourceId}`,
    [base]
  )
  const fullUrl = url ? `${base}${url}` : url
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
  const triggerCount = triggerUrls.length

  const showEnabledColumn = useMemo(
    () => sources.some((source) => typeof source.enabled === 'boolean'),
    [sources]
  )
  const sourceColumnCount =
    4 + (showEnabledColumn ? 1 : 0) + (canManageWebhookSources ? 1 : 0)
  const hmacCurlSnippet = useMemo(() => {
    if (!signingKey || !sourceExampleEndpoint) return ''
    return `export SIGNING_KEY_B64URL='${signingKey}'
export URL='${sourceExampleEndpoint}'
body='${examplePayload}'
ts=$(date +%s)
canonical=$(python3 - <<'PY' "$body"
import json,sys; print(json.dumps(json.loads(sys.argv[1]), separators=(",",":")))
PY
)
sig=$(python3 - <<'PY' "$SIGNING_KEY_B64URL" "$ts.$canonical"
import base64,hmac,hashlib,sys
k=sys.argv[1]; k+= '='*((4-len(k)%4)%4)
print(hmac.new(base64.urlsafe_b64decode(k), sys.argv[2].encode(), hashlib.sha256).hexdigest())
PY
)
curl -X POST \\
  -H "Content-Type: application/json" \\
  -H "X-DSentr-Timestamp: $ts" \\
  -H "X-DSentr-Signature: v1=$sig" \\
  -d "$canonical" \\
  "$URL"`
  }, [signingKey, sourceExampleEndpoint, examplePayload])
  const hmacPowerShellSnippet = useMemo(() => {
    if (!signingKey || !sourceExampleEndpoint) return ''
    return `$SIGNING_KEY_B64URL = '${signingKey}'
$URL = '${sourceExampleEndpoint}'
$body = '${examplePayload}'
$canonical = ($body | ConvertFrom-Json) | ConvertTo-Json -Compress
$ts = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds().ToString()
function Decode-Base64Url([string]$s){ $pad=(4-($s.Length%4))%4; $s+=('='*$pad); $s=$s.Replace('-','+').Replace('_','/'); [Convert]::FromBase64String($s) }
$keyBytes = Decode-Base64Url $SIGNING_KEY_B64URL
$hmac = New-Object System.Security.Cryptography.HMACSHA256($keyBytes)
$payload = [Text.Encoding]::UTF8.GetBytes($ts + '.' + $canonical)
$sigHex = -join ($hmac.ComputeHash($payload) | ForEach-Object { $_.ToString('x2') })
$headers = @{ 'Content-Type'='application/json'; 'X-DSentr-Timestamp'=$ts; 'X-DSentr-Signature'='v1=' + $sigHex }
Invoke-RestMethod -Method POST -Uri $URL -Headers $headers -Body $canonical`
  }, [signingKey, sourceExampleEndpoint, examplePayload])
  const hmacJavaScriptSnippet = useMemo(() => {
    if (!signingKey || !sourceExampleEndpoint) return ''
    return `// Node 18+ (global fetch). Replace signing key and source URL.
const keyB64Url = '${signingKey}';
const url = '${sourceExampleEndpoint}';
const body = { event_type: 'order.created', price: '123' };
const ts = Math.floor(Date.now()/1000).toString();
const canonical = JSON.stringify(body);
const pad = '='.repeat((4 - (keyB64Url.length % 4)) % 4);
const key = Buffer.from(keyB64Url.replace(/-/g,'+').replace(/_/g,'/') + pad, 'base64');
import crypto from 'node:crypto';
const sigHex = crypto.createHmac('sha256', key).update(ts + '.' + canonical).digest('hex');
await fetch(url, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-DSentr-Timestamp': ts,
    'X-DSentr-Signature': 'v1=' + sigHex
  },
  body: canonical
});`
  }, [signingKey, sourceExampleEndpoint])
  useEffect(() => {
    setCopied(false)
  }, [fullUrl, sourceExampleEndpoint])

  useEffect(() => {
    setCopiedCurl(false)
    setCopiedPS(false)
    setCopiedJS(false)
    setCopiedHmacCurl(false)
    setCopiedHmacPS(false)
    setCopiedHmacJS(false)
  }, [sourceExampleEndpoint])

  useEffect(() => {
    setCopiedHmacCurl(false)
    setCopiedHmacPS(false)
    setCopiedHmacJS(false)
  }, [signingKey])

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
      const result = await rotateWebhookSourceSecret(target.id)
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
  }, [pendingRotate, actionBusy, resolveSourceEndpoint])

  const handleConfirmDeleteSource = useCallback(async () => {
    if (!pendingDelete || actionBusy) return
    const target = pendingDelete
    setPendingDelete(null)
    setSourcesError(null)
    setActionBusy({ id: target.id, action: 'delete' })
    try {
      await deleteWebhookSource(target.id)
      setSources((prev) => prev.filter((source) => source.id !== target.id))
    } catch (err) {
      setSourcesError(errorMessage(err))
    } finally {
      setActionBusy(null)
    }
  }, [pendingDelete, actionBusy])
  return (
    <div className="space-y-4 relative">
      <div className="flex items-center gap-2">
        <label className="text-sm">Workflow</label>
        <select
          value={workflowId}
          onChange={(e) => setWorkflowId(e.target.value)}
          className="px-2 py-1 border rounded bg-white dark:bg-zinc-800 dark:text-zinc-100 dark:border-zinc-700"
        >
          {workflows.map((w) => (
            <option key={w.id} value={w.id}>
              {w.name}
            </option>
          ))}
        </select>
        {selected && (
          <span className="text-sm text-zinc-600 dark:text-zinc-300">
            Selected: <span className="font-medium">{selected.name}</span>
          </span>
        )}
      </div>
      <div className="border-t border-zinc-200 dark:border-zinc-700 pt-3">
        <h3 className="font-semibold mb-2">Webhook Ingress</h3>
        <p className="text-xs text-zinc-600 dark:text-zinc-400 mb-2">
          Webhook sources receive events at{' '}
          <code>/api/webhooks/{'{source_id}'}</code>. Include{' '}
          <code>event_type</code> in the JSON body; subscriptions route it to
          workflow triggers.
        </p>
        {loading ? (
          <p className="text-sm text-zinc-500">Loading...</p>
        ) : sourceExampleEndpoint ? (
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
        <div className="mt-3 flex items-center gap-2">
          <button
            className="text-xs px-2 py-1 rounded border whitespace-nowrap"
            disabled={!workflowId || regenBusy || !canManageWebhooks}
            onClick={() => {
              if (!canManageWebhooks) return
              if (workflowId) setConfirming(true)
            }}
          >
            {regenBusy ? 'Regenerating...' : 'Regenerate Credentials'}
          </button>
          <span className="text-xs text-zinc-500">
            Use this if credentials leaked or for periodic rotation. Update any
            external integrations afterward.
          </span>
        </div>
        {!canManageWebhooks && (
          <p className="text-xs text-amber-600 dark:text-amber-400 mt-2">
            You have read-only access. {manageWebhooksPermissionMessage}
          </p>
        )}

        <div className="mt-3">
          <div className="flex items-center justify-between gap-2">
            <div className="font-medium text-xs">Routing</div>
            <span className="text-[11px] text-zinc-500">
              Subscriptions link a source and event type to a workflow trigger.
            </span>
          </div>
          <p className="mt-2 text-xs text-zinc-500 dark:text-zinc-400">
            {triggerCount
              ? `Selected workflow has ${triggerCount} webhook trigger node(s) available for subscriptions.`
              : 'Add a webhook trigger node to create a subscription target.'}
          </p>
        </div>

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
      <div className="border-t border-zinc-200 dark:border-zinc-700 pt-3">
        <h3 className="font-semibold mb-2">HMAC Signing</h3>
        <p className="text-xs text-zinc-600 dark:text-zinc-400 mb-2">
          Each source has its own secret and HMAC requirement. Sign the full
          JSON body (including <code>event_type</code>) with the source secret.
        </p>
        {!canManageWebhooks && (
          <p className="text-xs text-amber-600 dark:text-amber-400 mb-2">
            You have read-only access. {manageWebhooksPermissionMessage}
          </p>
        )}
        {isSoloPlan && (
          <div className="text-xs text-amber-600 dark:text-amber-400 mb-2 flex items-center gap-2">
            <span>
              HMAC verification is available on workspace plans. Upgrade your
              plan to enable it.
            </span>
            <button
              type="button"
              className="px-2 py-0.5 text-[10px] rounded border"
              onClick={() => {
                try {
                  window.dispatchEvent(
                    new CustomEvent('open-plan-settings', {
                      detail: { tab: 'plan' }
                    })
                  )
                } catch (err) {
                  console.error(errorMessage(err))
                }
              }}
            >
              Upgrade
            </button>
          </div>
        )}
        <div className="flex items-center gap-3 mb-2">
          <label className="text-sm inline-flex items-center gap-2">
            <input
              type="checkbox"
              checked={requireHmac}
              onChange={(e) => setRequireHmac(e.target.checked)}
              disabled={!canManageWebhooks || isSoloPlan}
            />
            Require HMAC signature
          </label>
          <label className="text-sm inline-flex items-center gap-2">
            Replay window (sec)
            <input
              type="number"
              min={60}
              max={3600}
              value={replayWindow}
              onChange={(e) =>
                setReplayWindow(parseInt(e.target.value || '300', 10))
              }
              className="w-24 px-2 py-1 border rounded bg-white dark:bg-zinc-800 dark:text-zinc-100 dark:border-zinc-700"
              disabled={!canManageWebhooks || isSoloPlan}
            />
          </label>
          <button
            className="text-xs px-2 py-1 rounded border"
            disabled={!canManageWebhooks || isSoloPlan || saveBusy}
            onClick={async () => {
              if (!canManageWebhooks || !workflowId) return
              try {
                setSaveBusy(true)
                await setWebhookConfig(workflowId, {
                  require_hmac: requireHmac,
                  replay_window_sec: replayWindow
                })
                setJustSaved(true)
                setTimeout(() => setJustSaved(false), 1500)
              } catch (e) {
                console.error(errorMessage(e))
              } finally {
                setSaveBusy(false)
              }
            }}
          >
            {saveBusy ? 'Saving...' : justSaved ? 'Saved!' : 'Save'}
          </button>
        </div>
        {!isSoloPlan && (
          <div className="mb-2 space-y-2">
            <div className="text-xs text-zinc-600 dark:text-zinc-400">
              Signing key (base64url):
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <code className="text-xs px-2 py-1 rounded bg-zinc-100 dark:bg-zinc-800 break-all">
                {signingKey || '(unavailable)'}
              </code>
              <button
                className="text-xs px-2 py-1 rounded border"
                onClick={async () => {
                  await copyText(signingKey)
                }}
              >
                Copy
              </button>
              <button
                className="text-xs px-2 py-1 rounded border"
                disabled={!canManageWebhooks || regenSigningBusy || !workflowId}
                onClick={async () => {
                  if (!canManageWebhooks || !workflowId) return
                  try {
                    setRegenSigningBusy(true)
                    const result = await regenerateWebhookSigningKey(workflowId)
                    if (result?.signing_key) {
                      setSigningKey(result.signing_key)
                    }
                    if (result?.url) {
                      setUrl(result.url)
                    }
                    if (result?.triggers) {
                      setTriggerUrls(result.triggers)
                    }
                    setJustRegeneratedSigning(true)
                    setTimeout(() => setJustRegeneratedSigning(false), 2000)
                  } catch (err) {
                    console.error(errorMessage(err))
                  } finally {
                    setRegenSigningBusy(false)
                  }
                }}
              >
                {regenSigningBusy
                  ? 'Regenerating...'
                  : justRegeneratedSigning
                    ? 'Regenerated!'
                    : 'Regenerate'}
              </button>
            </div>
            <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
              Rotating the signing key invalidates prior signatures. Update any
              integrations that sign webhook payloads.
            </p>
          </div>
        )}

        {/* HMAC client guidance (headers/legacy) */}
        {!isSoloPlan && (
          <div className="text-xs text-zinc-600 dark:text-zinc-400 space-y-2">
            <div>Client should send headers (preferred):</div>
            <pre className="bg-zinc-100 dark:bg-zinc-800 p-2 rounded text-[11px] overflow-auto themed-scroll">
              {`X-DSentr-Timestamp: <unix-seconds>\nX-DSentr-Signature: v1=<hex(hmac_sha256(base64url_decode(signing_key), ts + '.' + canonical_json_body))>`}
            </pre>
            <div className="text-xs text-zinc-500">
              canonical_json_body is the minified JSON string (no whitespace)
              that includes <code>event_type</code>. The server verifies the
              HMAC over <code>ts + '.' + canonical_json_body</code>.
            </div>
            <div className="text-xs text-zinc-500">
              If headers are not used, include <code>_dsentr_ts</code> and{' '}
              <code>_dsentr_sig</code> in the body and sign{' '}
              <code>ts + '.' + body_without(_dsentr_ts,_dsentr_sig)</code>.
            </div>
          </div>
        )}

        {/* HMAC Examples (only when enabled and not on Solo) */}
        {!isSoloPlan &&
          requireHmac &&
          hmacCurlSnippet &&
          hmacPowerShellSnippet &&
          hmacJavaScriptSnippet && (
            <div className="mt-3 space-y-2">
              <div className="font-medium text-xs">HMAC Examples</div>

              {/* curl (bash) */}
              <div className="relative">
                <span className="absolute right-2 top-1 text-[10px] uppercase tracking-wide px-2 py-0.5 rounded bg-zinc-200 dark:bg-zinc-700 text-zinc-700 dark:text-zinc-200">
                  curl (bash)
                </span>
                <pre className="bg-zinc-100 dark:bg-zinc-800 p-2 rounded overflow-auto themed-scroll whitespace-pre-wrap break-words text-[11px]">
                  <code>{hmacCurlSnippet}</code>
                </pre>
                <div className="text-right mt-1">
                  <button
                    className="text-[10px] px-2 py-0.5 rounded border"
                    onClick={async () => {
                      const ok = await copyText(hmacCurlSnippet)
                      if (ok) {
                        setCopiedHmacCurl(true)
                        setTimeout(() => setCopiedHmacCurl(false), 1500)
                      }
                    }}
                  >
                    {copiedHmacCurl ? 'Copied!' : 'Copy'}
                  </button>
                </div>
              </div>

              {/* PowerShell */}
              <div className="relative">
                <span className="absolute right-2 top-1 text-[10px] uppercase tracking-wide px-2 py-0.5 rounded bg-zinc-200 dark:bg-zinc-700 text-zinc-700 dark:text-zinc-200">
                  powershell
                </span>
                <pre className="bg-zinc-100 dark:bg-zinc-800 p-2 rounded overflow-auto themed-scroll whitespace-pre-wrap break-words text-[11px]">
                  <code>{hmacPowerShellSnippet}</code>
                </pre>
                <div className="text-right mt-1">
                  <button
                    className="text-[10px] px-2 py-0.5 rounded border"
                    onClick={async () => {
                      const ok = await copyText(hmacPowerShellSnippet)
                      if (ok) {
                        setCopiedHmacPS(true)
                        setTimeout(() => setCopiedHmacPS(false), 1500)
                      }
                    }}
                  >
                    {copiedHmacPS ? 'Copied!' : 'Copy'}
                  </button>
                </div>
              </div>

              {/* JavaScript (Node) */}
              <div className="relative">
                <span className="absolute right-2 top-1 text-[10px] uppercase tracking-wide px-2 py-0.5 rounded bg-zinc-200 dark:bg-zinc-700 text-zinc-700 dark:text-zinc-200">
                  javascript (node)
                </span>
                <pre className="bg-zinc-100 dark:bg-zinc-800 p-2 rounded overflow-auto themed-scroll whitespace-pre-wrap break-words text-[11px]">
                  <code>{hmacJavaScriptSnippet}</code>
                </pre>
                <div className="text-right mt-1">
                  <button
                    className="text-[10px] px-2 py-0.5 rounded border"
                    onClick={async () => {
                      const ok = await copyText(hmacJavaScriptSnippet)
                      if (ok) {
                        setCopiedHmacJS(true)
                        setTimeout(() => setCopiedHmacJS(false), 1500)
                      }
                    }}
                  >
                    {copiedHmacJS ? 'Copied!' : 'Copy'}
                  </button>
                </div>
              </div>
            </div>
          )}
      </div>
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
                            workspaceId={activeWorkspaceId}
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
      {confirming && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
          <div className="bg-white dark:bg-zinc-900 p-4 rounded-xl shadow-xl w-96 border border-zinc-200 dark:border-zinc-700">
            <h4 className="font-semibold mb-2 text-sm">
              Regenerate webhook credentials?
            </h4>
            <p className="text-xs text-zinc-600 dark:text-zinc-300 mb-3">
              Previous credentials will stop working immediately. Update any
              external integrations.
            </p>
            <div className="flex justify-end gap-2">
              <button
                className="px-3 py-1 text-xs rounded border"
                onClick={() => setConfirming(false)}
              >
                Cancel
              </button>
              <button
                className="px-3 py-1 text-xs rounded bg-red-600 text-white hover:bg-red-700 disabled:opacity-50"
                disabled={regenBusy || !canManageWebhooks}
                onClick={async () => {
                  if (!canManageWebhooks) return
                  if (!workflowId) return
                  try {
                    setRegenBusy(true)
                    const result = await regenerateWebhookUrl(workflowId)
                    setUrl(result.url)
                    setTriggerUrls(result.triggers ?? [])
                    if (result.signing_key) {
                      setSigningKey(result.signing_key)
                    }
                    setConfirming(false)
                    setJustRegeneratedSigning(false)
                  } finally {
                    setRegenBusy(false)
                  }
                }}
              >
                {regenBusy ? 'Regenerating...' : 'Confirm Regenerate'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
