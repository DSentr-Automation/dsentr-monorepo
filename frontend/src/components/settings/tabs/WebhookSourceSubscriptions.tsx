import { useCallback, useEffect, useMemo, useState } from 'react'
import ConfirmDialog from '@/components/ui/dialog/ConfirmDialog'
import { errorMessage } from '@/lib/errorMessage'
import {
  createWebhookSubscriptionForSource,
  deleteSubscription,
  listWebhookSubscriptionsForSource,
  type WebhookSubscription
} from '@/lib/webhookSubscriptionsApi'
import type { WebhookSource } from '@/lib/webhookSourcesApi'
import type { WorkflowRecord } from '@/lib/workflowApi'

type TriggerOption = {
  id: string
  label: string
}

type WebhookSourceSubscriptionsProps = {
  source: WebhookSource
  workspaceId: string | null
  workflows: WorkflowRecord[]
  canManage: boolean
}

function extractWebhookTriggers(
  workflow: WorkflowRecord | null
): TriggerOption[] {
  const nodes = Array.isArray(workflow?.data?.nodes)
    ? workflow?.data?.nodes
    : []
  return nodes
    .filter((node: any) => node?.type === 'trigger')
    .filter((node: any) => {
      // Trigger nodes use data.triggerType; this must stay aligned with TriggerNode schema.
      const triggerType =
        typeof node?.data?.triggerType === 'string'
          ? node.data.triggerType.trim().toLowerCase()
          : ''
      return triggerType === 'webhook'
    })
    .map((node: any) => {
      const label =
        typeof node?.data?.label === 'string' && node.data.label.trim()
          ? node.data.label.trim()
          : node.id
      return {
        id: node.id,
        label
      }
    })
}

function buildTriggerLabelMap(workflows: WorkflowRecord[]) {
  const map = new Map<string, Map<string, string>>()
  workflows.forEach((workflow) => {
    const nodes = Array.isArray(workflow?.data?.nodes)
      ? workflow.data.nodes
      : []
    const triggerMap = new Map<string, string>()
    nodes.forEach((node: any) => {
      if (!node?.id) return
      if (node?.type !== 'trigger') return
      const label =
        typeof node?.data?.label === 'string' && node.data.label.trim()
          ? node.data.label.trim()
          : node.id
      triggerMap.set(node.id, label)
    })
    map.set(workflow.id, triggerMap)
  })
  return map
}

export default function WebhookSourceSubscriptions({
  source,
  workspaceId,
  workflows,
  canManage
}: WebhookSourceSubscriptionsProps) {
  const [expanded, setExpanded] = useState(false)
  const [subscriptions, setSubscriptions] = useState<WebhookSubscription[]>([])
  const [loading, setLoading] = useState(false)
  const [loadedOnce, setLoadedOnce] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const [showCreate, setShowCreate] = useState(false)
  const [createWorkflowId, setCreateWorkflowId] = useState('')
  const [createTriggerId, setCreateTriggerId] = useState('')
  const [createEventType, setCreateEventType] = useState('')
  const [createError, setCreateError] = useState<string | null>(null)
  const [createBusy, setCreateBusy] = useState(false)

  const [pendingDelete, setPendingDelete] =
    useState<WebhookSubscription | null>(null)
  const [deleteBusy, setDeleteBusy] = useState(false)

  const workflowMap = useMemo(() => {
    return new Map(workflows.map((workflow) => [workflow.id, workflow]))
  }, [workflows])

  const triggerLabelMap = useMemo(
    () => buildTriggerLabelMap(workflows),
    [workflows]
  )

  const selectedWorkflow = useMemo(() => {
    return workflowMap.get(createWorkflowId) ?? null
  }, [createWorkflowId, workflowMap])

  const triggerOptions = useMemo(
    () => extractWebhookTriggers(selectedWorkflow),
    [selectedWorkflow]
  )

  const loadSubscriptions = useCallback(async () => {
    if (!workspaceId) {
      setSubscriptions([])
      setError('Select a workspace to view subscriptions.')
      setLoadedOnce(true)
      return
    }
    setLoading(true)
    try {
      const results = await listWebhookSubscriptionsForSource(source.id)
      setSubscriptions(results)
      setError(null)
      setLoadedOnce(true)
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setLoading(false)
    }
  }, [source.id])

  useEffect(() => {
    if (expanded && !loadedOnce) {
      void loadSubscriptions()
    }
  }, [expanded, loadedOnce, loadSubscriptions])

  useEffect(() => {
    if (!showCreate) return
    if (!createWorkflowId || !workflowMap.has(createWorkflowId)) {
      setCreateWorkflowId(workflows[0]?.id ?? '')
    }
  }, [showCreate, createWorkflowId, workflowMap, workflows])

  useEffect(() => {
    if (!showCreate) return
    if (!triggerOptions.length) {
      setCreateTriggerId('')
      return
    }
    if (!triggerOptions.some((option) => option.id === createTriggerId)) {
      setCreateTriggerId(triggerOptions[0].id)
    }
  }, [showCreate, triggerOptions, createTriggerId])

  useEffect(() => {
    if (!showCreate) {
      setCreateWorkflowId('')
      setCreateTriggerId('')
      setCreateEventType('')
      setCreateError(null)
    }
  }, [showCreate])

  const handleCreate = useCallback(async () => {
    const trimmedEventType = createEventType.trim()
    if (!trimmedEventType) {
      setCreateError('Event type is required.')
      return
    }
    if (!workspaceId) {
      setCreateError('Select a workspace before adding subscriptions.')
      return
    }
    if (!createWorkflowId) {
      setCreateError('Select a workflow for this subscription.')
      return
    }
    if (!createTriggerId) {
      setCreateError('Select a webhook trigger for this subscription.')
      return
    }
    setCreateBusy(true)
    setCreateError(null)
    setError(null)
    try {
      await createWebhookSubscriptionForSource(source.id, {
        workflowId: createWorkflowId,
        triggerNodeId: createTriggerId,
        eventType: trimmedEventType
      })
      setCreateEventType('')
      setShowCreate(false)
      await loadSubscriptions()
    } catch (err) {
      setCreateError(errorMessage(err))
    } finally {
      setCreateBusy(false)
    }
  }, [
    createEventType,
    workspaceId,
    createWorkflowId,
    createTriggerId,
    source.id,
    loadSubscriptions
  ])

  const handleConfirmDelete = useCallback(async () => {
    if (!pendingDelete || !workspaceId || deleteBusy) return
    const target = pendingDelete
    setPendingDelete(null)
    setDeleteBusy(true)
    setError(null)
    try {
      await deleteSubscription(target.id)
      setSubscriptions((prev) => prev.filter((entry) => entry.id !== target.id))
    } catch (err) {
      setError(errorMessage(err))
    } finally {
      setDeleteBusy(false)
    }
  }, [pendingDelete, workspaceId, deleteBusy, source.id])

  const subscriptionCountLabel =
    loadedOnce || subscriptions.length ? `(${subscriptions.length})` : ''

  return (
    <div className="rounded border border-zinc-200 dark:border-zinc-700 bg-zinc-50/70 dark:bg-zinc-900/40 p-3 space-y-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <div className="text-xs font-semibold text-zinc-700 dark:text-zinc-200">
            Subscriptions {subscriptionCountLabel}
          </div>
          <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
            Subscriptions map a source and event type to a workflow trigger.
            Event type is the routing key sent in the webhook payload.
          </p>
        </div>
        <div className="flex items-center gap-2">
          {canManage && (
            <button
              className="text-[11px] px-2 py-1 rounded border"
              onClick={() => {
                setShowCreate(true)
                setExpanded(true)
              }}
              disabled={showCreate}
            >
              Add subscription
            </button>
          )}
          <button
            className="text-[11px] px-2 py-1 rounded border"
            onClick={() =>
              setExpanded((prev) => {
                const next = !prev
                if (!next) {
                  setShowCreate(false)
                }
                return next
              })
            }
          >
            {expanded ? 'Hide' : 'Show'}
          </button>
        </div>
      </div>

      {expanded && (
        <div className="space-y-3">
          {loading ? (
            <p className="text-xs text-zinc-500">Loading subscriptions...</p>
          ) : error ? (
            <div className="flex items-center gap-2 text-xs text-red-600">
              <span>{error}</span>
              <button
                className="text-[11px] px-2 py-0.5 rounded border"
                onClick={() => loadSubscriptions()}
              >
                Retry
              </button>
            </div>
          ) : subscriptions.length === 0 ? (
            <p className="text-xs text-zinc-500 dark:text-zinc-400">
              No subscriptions yet.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-left text-[11px] text-zinc-500">
                    <th className="py-2">Event type</th>
                    <th className="py-2">Workflow</th>
                    <th className="py-2">Trigger node</th>
                    {canManage && <th className="py-2 text-right">Actions</th>}
                  </tr>
                </thead>
                <tbody>
                  {subscriptions.map((subscription) => {
                    const workflow = workflowMap.get(subscription.workflowId)
                    const workflowName = workflow?.name || 'Unknown workflow'
                    const triggerLabel =
                      triggerLabelMap
                        .get(subscription.workflowId)
                        ?.get(subscription.triggerNodeId) ||
                      subscription.triggerNodeId ||
                      'Unknown trigger'
                    return (
                      <tr
                        key={subscription.id}
                        className="border-t border-zinc-200 dark:border-zinc-700"
                      >
                        <td className="py-2">{subscription.eventType}</td>
                        <td className="py-2">{workflowName}</td>
                        <td className="py-2">{triggerLabel}</td>
                        {canManage && (
                          <td className="py-2 text-right">
                            <button
                              className="text-[11px] px-2 py-0.5 rounded border text-red-600 disabled:opacity-50"
                              disabled={deleteBusy}
                              onClick={() => setPendingDelete(subscription)}
                            >
                              Delete
                            </button>
                          </td>
                        )}
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}

          {showCreate && (
            <div className="rounded border border-zinc-200 dark:border-zinc-700 bg-white/80 dark:bg-zinc-900/70 p-3 space-y-3">
              <div className="grid gap-3 md:grid-cols-3">
                <div className="space-y-1">
                  <label className="text-[11px] font-medium text-zinc-600 dark:text-zinc-200">
                    Workflow
                  </label>
                  <select
                    value={createWorkflowId}
                    onChange={(e) => setCreateWorkflowId(e.target.value)}
                    className="w-full rounded border px-2 py-1 text-xs bg-white dark:bg-zinc-900 dark:border-zinc-700"
                    disabled={createBusy || workflows.length === 0}
                  >
                    {workflows.length === 0 ? (
                      <option value="">No workflows</option>
                    ) : (
                      workflows.map((workflow) => (
                        <option key={workflow.id} value={workflow.id}>
                          {workflow.name}
                        </option>
                      ))
                    )}
                  </select>
                </div>
                <div className="space-y-1">
                  <label className="text-[11px] font-medium text-zinc-600 dark:text-zinc-200">
                    Trigger
                  </label>
                  <select
                    value={createTriggerId}
                    onChange={(e) => setCreateTriggerId(e.target.value)}
                    className="w-full rounded border px-2 py-1 text-xs bg-white dark:bg-zinc-900 dark:border-zinc-700"
                    disabled={createBusy || triggerOptions.length === 0}
                  >
                    {triggerOptions.length === 0 ? (
                      <option value="">No webhook triggers</option>
                    ) : (
                      triggerOptions.map((trigger) => (
                        <option key={trigger.id} value={trigger.id}>
                          {trigger.label}
                        </option>
                      ))
                    )}
                  </select>
                </div>
                <div className="space-y-1">
                  <label className="text-[11px] font-medium text-zinc-600 dark:text-zinc-200">
                    Event type
                  </label>
                  <input
                    value={createEventType}
                    onChange={(e) => setCreateEventType(e.target.value)}
                    placeholder="order.created"
                    className="w-full rounded border px-2 py-1 text-xs bg-white dark:bg-zinc-900 dark:border-zinc-700"
                    disabled={createBusy}
                  />
                </div>
              </div>

              {workflows.length === 0 && (
                <p className="text-[11px] text-zinc-500">
                  Create a workflow before adding webhook subscriptions.
                </p>
              )}
              {createWorkflowId && triggerOptions.length === 0 && (
                <p className="text-[11px] text-zinc-500">
                  Add a webhook trigger node to the selected workflow to use it
                  here.
                </p>
              )}

              {createError && (
                <p className="text-xs text-red-500">{createError}</p>
              )}

              <div className="flex items-center gap-2">
                <button
                  className="text-[11px] px-3 py-1 rounded bg-blue-600 text-white disabled:opacity-50"
                  onClick={handleCreate}
                  disabled={
                    !canManage ||
                    createBusy ||
                    workflows.length === 0 ||
                    !createTriggerId
                  }
                >
                  {createBusy ? 'Creating...' : 'Create subscription'}
                </button>
                <button
                  className="text-[11px] px-3 py-1 rounded border"
                  onClick={() => setShowCreate(false)}
                  disabled={createBusy}
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {!canManage && (
            <p className="text-[11px] text-amber-600 dark:text-amber-400">
              You have read-only access to subscriptions.
            </p>
          )}
        </div>
      )}

      <ConfirmDialog
        isOpen={pendingDelete !== null}
        title="Delete webhook subscription?"
        message="Deleting this subscription stops incoming events from reaching the workflow."
        confirmText="Delete subscription"
        cancelText="Cancel"
        onCancel={() => setPendingDelete(null)}
        onConfirm={handleConfirmDelete}
      />
    </div>
  )
}
