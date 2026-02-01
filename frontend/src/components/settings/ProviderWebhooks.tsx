import { useCallback, useEffect, useMemo, useState } from 'react'
import { API_BASE_URL } from '@/lib/config'
import { errorMessage } from '@/lib/errorMessage'
import type { PlanTier } from '@/lib/planTiers'

type ProviderWebhookMetadata = {
  provider: string
  enabled: boolean
  disabled_reason?: string | null
  app_url?: string | null
  webhook_endpoint: string
  delivery_deduplication: boolean
  trigger_source: string
  description: string
  setup_instructions: string[]
  notes: string[]
}

type ProviderWebhooksProps = {
  workspaceId: string | null
  planTier: PlanTier
}

function providerLabel(provider: string) {
  if (!provider) return 'Provider'
  if (provider.toLowerCase() === 'github') return 'GitHub'
  return provider
}

function providerExplanation(provider: string, fallback: string) {
  if (provider.toLowerCase() === 'github') {
    return [
      'Dsentr uses a single GitHub App webhook endpoint.',
      'Incoming events are automatically routed to workflows with matching GitHub triggers.'
    ]
  }
  return fallback ? [fallback] : []
}

function providerHowItWorks(provider: string) {
  if (provider.toLowerCase() === 'github') {
    return [
      'GitHub webhooks are managed via the GitHub App.',
      'You do not create webhooks per workflow.',
      'Publishing a workflow with a GitHub trigger automatically registers it.',
      'Multiple workflows can listen to the same event safely.'
    ]
  }
  return []
}

export default function ProviderWebhooks({
  workspaceId,
  planTier
}: ProviderWebhooksProps) {
  const [providers, setProviders] = useState<ProviderWebhookMetadata[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const isWorkspacePlan = planTier === 'workspace'
  const baseUrl = useMemo(() => (API_BASE_URL || '').replace(/\/$/, ''), [])
  const githubFallbackManageUrl = 'https://github.com/settings/installations'

  const loadProviders = useCallback(async () => {
    if (!isWorkspacePlan || !workspaceId) {
      setProviders([])
      setError(null)
      setLoading(false)
      return
    }

    setLoading(true)
    try {
      const res = await fetch(
        `${baseUrl}/api/settings/webhooks/providers?workspace_id=${workspaceId}`,
        { credentials: 'include' }
      )
      const body = await res.json().catch(() => null)
      if (!res.ok || body?.success === false) {
        throw new Error(body?.message ?? 'Failed to load provider webhooks')
      }
      const list = (body?.data?.providers ?? body?.providers ?? []) as
        | ProviderWebhookMetadata[]
        | null
      setProviders(Array.isArray(list) ? list : [])
      setError(null)
    } catch (err) {
      setError(errorMessage(err))
      setProviders([])
    } finally {
      setLoading(false)
    }
  }, [baseUrl, isWorkspacePlan, workspaceId])

  useEffect(() => {
    void loadProviders()
  }, [loadProviders])

  if (!isWorkspacePlan) return null

  return (
    <div className="border-t border-zinc-200 dark:border-zinc-700 pt-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h3 className="font-semibold mb-1">Provider Webhooks</h3>
          <p className="text-xs text-zinc-600 dark:text-zinc-400">
            Read-only overview of provider-managed webhooks.
          </p>
        </div>
      </div>
      {loading ? (
        <p className="text-sm text-zinc-500 mt-2">Loading.</p>
      ) : error ? (
        <p className="text-xs text-red-500 mt-2">{error}</p>
      ) : providers.length === 0 ? (
        <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-2">
          No provider webhooks are available for this workspace.
        </p>
      ) : (
        <div className="mt-3 space-y-3">
          {providers.map((provider) => {
            const label = providerLabel(provider.provider)
            const explanations = providerExplanation(
              provider.provider,
              provider.description
            )
            const howItWorks = providerHowItWorks(provider.provider)
            const isGithub = provider.provider.toLowerCase() === 'github'
            const githubAppUrl = isGithub
              ? provider.app_url?.trim() || null
              : null
            // OAuth start records the installation_id so triggers can map back to this account.
            const installUrl =
              isGithub && workspaceId
                ? `${baseUrl}/api/oauth/github/start?workspace=${encodeURIComponent(
                    workspaceId
                  )}`
                : null
            const manageUrl = githubAppUrl ?? githubFallbackManageUrl

            return (
              <div
                key={`${provider.provider}-${provider.webhook_endpoint}`}
                className="rounded border border-zinc-200 dark:border-zinc-700 bg-white/60 dark:bg-zinc-900/60 p-3 space-y-3"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <h4 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">
                    {label}
                  </h4>
                  <span
                    className={`text-[10px] px-2 py-0.5 rounded border ${
                      provider.enabled
                        ? 'border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-500/40 dark:bg-emerald-500/10 dark:text-emerald-200'
                        : 'border-zinc-200 bg-zinc-100 text-zinc-600 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-300'
                    }`}
                  >
                    {provider.enabled ? 'Enabled' : 'Disconnected'}
                  </span>
                </div>

                <div className="space-y-1 text-xs text-zinc-600 dark:text-zinc-300">
                  {explanations.map((line) => (
                    <p key={line}>{line}</p>
                  ))}
                </div>

                <div className="grid gap-2 text-xs text-zinc-600 dark:text-zinc-300 md:grid-cols-2">
                  <div className="space-y-1">
                    <div className="text-[11px] text-zinc-500">
                      Webhook endpoint
                    </div>
                    <code className="text-[11px] px-2 py-1 rounded bg-zinc-100 dark:bg-zinc-800 break-all">
                      {provider.webhook_endpoint}
                    </code>
                  </div>
                  <div className="space-y-1">
                    <div className="text-[11px] text-zinc-500">Routing</div>
                    <div>
                      Delivery deduplication:{' '}
                      {provider.delivery_deduplication ? 'Enabled' : 'Disabled'}
                    </div>
                    <div>Trigger source: {provider.trigger_source}</div>
                  </div>
                </div>

                {howItWorks.length > 0 && (
                  <div className="space-y-1">
                    <div className="text-xs font-medium text-zinc-700 dark:text-zinc-200">
                      How it works
                    </div>
                    <div className="text-xs text-zinc-600 dark:text-zinc-300 space-y-1">
                      {howItWorks.map((line) => (
                        <p key={line}>{line}</p>
                      ))}
                    </div>
                  </div>
                )}

                {provider.setup_instructions?.length > 0 && (
                  <div className="space-y-1">
                    <div className="text-xs font-medium text-zinc-700 dark:text-zinc-200">
                      How to get events flowing
                    </div>
                    <ol className="list-decimal pl-4 text-xs text-zinc-600 dark:text-zinc-300 space-y-1">
                      {provider.setup_instructions.map((item) => (
                        <li key={item}>{item}</li>
                      ))}
                    </ol>
                  </div>
                )}

                {provider.notes?.length > 0 && (
                  <div className="space-y-1">
                    <div className="text-xs font-medium text-zinc-700 dark:text-zinc-200">
                      Notes
                    </div>
                    <ul className="list-disc pl-4 text-xs text-zinc-600 dark:text-zinc-300 space-y-1">
                      {provider.notes.map((note) => (
                        <li key={note}>{note}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {isGithub && (
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    {provider.enabled ? (
                      <a
                        href={manageUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center rounded border border-zinc-200 bg-white px-2 py-1 text-zinc-700 hover:border-zinc-300 hover:text-zinc-900 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-200 dark:hover:border-zinc-500"
                      >
                        Manage installation
                      </a>
                    ) : (
                      <>
                        <button
                          type="button"
                          className="inline-flex items-center rounded border border-zinc-200 bg-white px-2 py-1 text-zinc-700 hover:border-zinc-300 hover:text-zinc-900 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-200 dark:hover:border-zinc-500"
                          onClick={() => {
                            if (installUrl) {
                              window.location.href = installUrl
                            }
                          }}
                          disabled={!installUrl}
                        >
                          Install GitHub App
                        </button>
                        {githubAppUrl ? (
                          <a
                            href={githubAppUrl}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center rounded border border-zinc-200 bg-white px-2 py-1 text-zinc-700 hover:border-zinc-300 hover:text-zinc-900 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-200 dark:hover:border-zinc-500"
                          >
                            View GitHub App
                          </a>
                        ) : null}
                      </>
                    )}
                    {!provider.enabled && provider.disabled_reason ? (
                      <span className="text-zinc-500 dark:text-zinc-400">
                        Reason: {provider.disabled_reason}
                      </span>
                    ) : null}
                  </div>
                )}

                <p className="text-xs text-zinc-500 dark:text-zinc-400">
                  This page is informational. Provider webhooks are managed
                  automatically and cannot be edited here.
                </p>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
