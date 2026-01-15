import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ComponentType,
  type SVGProps
} from 'react'
import { API_BASE_URL } from '@/lib/config'
import { errorMessage } from '@/lib/errorMessage'
import '@xyflow/react/dist/style.css'
import WorkflowToolbar from './Toolbar'
import FlowCanvas from './FlowCanvas'
import ActionIcon from '@/assets/svg-components/ActionIcon'
import ConditionIcon from '@/assets/svg-components/ConditionIcon'
import { INTEGRATION_ICONS } from '@/components/integrations/iconRegistry'
import { ReactFlowProvider } from '@xyflow/react'
import { ChevronDown, ChevronUp, Plus, Search } from 'lucide-react'
import { selectCurrentWorkspace, useAuth } from '@/stores/auth'
import { selectIsSaving, useWorkflowStore } from '@/stores/workflowStore'
import { useActionRegistry } from '@/stores/actionRegistry'
import {
  normalizeEdgeForPayload,
  sanitizeData,
  sanitizeNodeData,
  sortById
} from '@/lib/workflowGraph'
import {
  listWorkflows,
  getWorkflow,
  createWorkflow as createWorkflowApi,
  updateWorkflow as updateWorkflowApi,
  WorkflowRecord,
  startWorkflowRun,
  getWorkflowRunStatus,
  cancelRun,
  listActiveRuns,
  lockWorkflow as lockWorkflowApi,
  unlockWorkflow as unlockWorkflowApi,
  type WorkflowRunRecord,
  type WorkflowNodeRunRecord
} from '@/lib/workflowApi'
import { normalizePlanTier, type PlanTier } from '@/lib/planTiers'
import { WORKSPACE_RUN_LIMIT_FALLBACK } from '@/lib/usageDefaults'
import {
  cloneWorkflowData,
  hydrateIncomingEdges,
  hydrateIncomingNodes,
  normalizeNodesForState
} from './FlowCanvas.helpers'
import type { WorkflowEdge, WorkflowNode } from './FlowCanvas'
import { usePlanUsageStore } from '@/stores/planUsageStore'
import { QuotaBanner } from '@/components/quota/QuotaBanner'
import type { RunAvailability } from '@/types/runAvailability'

const TriggerIcon = () => (
  <svg
    className="w-4 h-4 mr-1"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
  >
    <path d="M12 2v20M2 12h20" />
  </svg>
)

const ICON_BY_KEY: Partial<
  Record<string, ComponentType<SVGProps<SVGSVGElement>>>
> = {
  action: ActionIcon,
  ...INTEGRATION_ICONS
}

const normalizeIconKey = (value?: string | null) =>
  typeof value === 'string' ? value.trim().toLowerCase() : ''

const LOGIC_SIDEBAR_TILE_GROUP = {
  heading: 'Logic / Utility',
  tiles: [
    {
      id: 'logic-delay',
      label: 'Delay',
      description: 'Pause execution for a set time',
      dragType: 'logic:delay',
      gradient: 'from-sky-500 to-cyan-600',
      icon: <ConditionIcon />
    },
    {
      id: 'logic-formatter',
      label: 'Formatter',
      description: 'Transform or reshape data',
      dragType: 'logic:formatter',
      gradient: 'from-teal-500 to-emerald-600',
      icon: <ConditionIcon />
    }
  ]
} as const

export default function Dashboard() {
  const [workflows, setWorkflows] = useState<WorkflowRecord[]>([])
  const [hiddenWorkflowCount, setHiddenWorkflowCount] = useState(0)
  const [currentWorkflowId, setCurrentWorkflowId] = useState<string | null>(
    null
  )
  const [loadingWorkflows, setLoadingWorkflows] = useState(true)
  const [isWorkflowActionBusy, setWorkflowActionBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // Settings moved to DashboardLayout header

  // Run state
  const [runOverlayOpen, setRunOverlayOpen] = useState(false)
  const [activeRun, setActiveRun] = useState<WorkflowRunRecord | null>(null)
  const activeRunId = activeRun?.id ?? null
  const [runsDrawerOpen, setRunsDrawerOpen] = useState(false)
  const [nodeRuns, setNodeRuns] = useState<WorkflowNodeRunRecord[]>([])
  const pollTimerRef = useRef<any>(null)
  const currentPollRunIdRef = useRef<string | null>(null)
  const overlayWatchTimerRef = useRef<any>(null)
  const [cancelBusy, setCancelBusy] = useState(false)
  const [runToast, setRunToast] = useState<string | null>(null)
  const [lockBusy, setLockBusy] = useState(false)
  const [remoteUpdate, setRemoteUpdate] = useState<{
    workflow: WorkflowRecord
    reason: 'sse' | 'conflict'
  } | null>(null)
  const latestWorkflowVersionRef = useRef<string | null>(null)
  const userId = useAuth((state) => state.user?.id ?? null)
  const currentWorkspace = useAuth(selectCurrentWorkspace)
  const activeWorkspaceId = currentWorkspace?.workspace.id ?? null
  const workspaceRole = (currentWorkspace?.role ?? 'owner') as
    | 'owner'
    | 'admin'
    | 'user'
    | 'viewer'
  const userPlan = useAuth((state) => state.user?.plan ?? null)
  const workflowSaving = useWorkflowStore(selectIsSaving)
  const isDirty = useWorkflowStore((state) => state.isDirty)
  const planTier = useMemo<PlanTier>(
    () =>
      normalizePlanTier(
        currentWorkspace?.workspace.plan ?? userPlan ?? undefined
      ),
    [currentWorkspace?.workspace.plan, userPlan]
  )
  const usageWorkspaceId = planTier === 'workspace' ? activeWorkspaceId : null
  const planUsage = usePlanUsageStore((state) => state.usage)
  const planUsageError = usePlanUsageStore((state) => state.error)
  const refreshPlanUsage = usePlanUsageStore((state) => state.refresh)
  const workspaceRunCapReached = usePlanUsageStore(
    (state) => state.workspaceRunCapReached
  )
  const markWorkspaceRunCap = usePlanUsageStore(
    (state) => state.markWorkspaceRunCap
  )
  useEffect(() => {
    if (planTier === 'solo') {
      const hidden = planUsage?.workflows?.hidden ?? 0
      setHiddenWorkflowCount(hidden)
    } else {
      setHiddenWorkflowCount(0)
    }
  }, [planTier, planUsage?.workflows?.hidden])
  const openPlanSettings = useCallback(() => {
    window.dispatchEvent(
      new CustomEvent('open-plan-settings', { detail: { tab: 'plan' } })
    )
  }, [])
  const handleSaveRef = useRef<() => Promise<boolean>>(async () => true)
  const waitForSaveCompletion = useCallback(
    () =>
      new Promise<void>((resolve) => {
        if (!useWorkflowStore.getState().isSaving) {
          resolve()
          return
        }
        const unsubscribe = useWorkflowStore.subscribe((state) => {
          if (!state.isSaving) {
            unsubscribe()
            resolve()
          }
        })
      }),
    []
  )
  const saveIfDirty = useCallback(async () => {
    await waitForSaveCompletion()
    const { isDirty } = useWorkflowStore.getState()
    if (!isDirty) {
      return true
    }
    const saved = await handleSaveRef.current()
    if (!saved) {
      return false
    }
    await waitForSaveCompletion()
    return !useWorkflowStore.getState().isDirty
  }, [waitForSaveCompletion])
  useEffect(() => {
    const handler = (event: Event) => {
      const custom = event as CustomEvent<{ resolve?: (ok: boolean) => void }>
      const resolve = custom.detail?.resolve
      if (!resolve) return
      void saveIfDirty()
        .then((ok) => resolve(ok))
        .catch(() => resolve(false))
    }
    window.addEventListener('dsentr-request-workflow-save', handler as any)
    return () =>
      window.removeEventListener('dsentr-request-workflow-save', handler as any)
  }, [saveIfDirty])
  // Global run status aggregator for toolbar (across all workflows)
  const [globalRunStatus, setGlobalRunStatus] = useState<
    'idle' | 'queued' | 'running'
  >('idle')
  const globalRunsTimerRef = useRef<any>(null)
  const [runsScope, setRunsScope] = useState<'current' | 'all'>('current')
  const [runQueue, setRunQueue] = useState<WorkflowRunRecord[]>([])
  const _runQueueTimerRef = useRef<any>(null)
  void globalRunsTimerRef
  void _runQueueTimerRef
  // Stable execution state identities to avoid unnecessary re-renders
  const runningIds = useMemo(
    () =>
      new Set(
        nodeRuns.filter((n) => n.status === 'running').map((n) => n.node_id)
      ),
    [nodeRuns]
  )
  const succeededIds = useMemo(
    () =>
      new Set(
        nodeRuns.filter((n) => n.status === 'succeeded').map((n) => n.node_id)
      ),
    [nodeRuns]
  )
  // Top-of-page notifications under the header are limited to the Solo usage banner only.
  const failedIds = useMemo(
    () =>
      new Set(
        nodeRuns.filter((n) => n.status === 'failed').map((n) => n.node_id)
      ),
    [nodeRuns]
  )
  const workspaceRunUsage = planUsage?.workspace?.runs
  const resolvedRunUsage = useMemo(() => {
    if (planTier === 'workspace' && workspaceRunUsage) {
      return workspaceRunUsage
    }
    return planUsage?.runs ?? null
  }, [planTier, planUsage?.runs, workspaceRunUsage])
  const runsUsed = resolvedRunUsage?.used ?? 0
  const runsLimit = useMemo(() => {
    if (resolvedRunUsage?.limit && resolvedRunUsage.limit > 0) {
      return resolvedRunUsage.limit
    }
    if (planTier === 'workspace') {
      return WORKSPACE_RUN_LIMIT_FALLBACK
    }
    if (planTier === 'solo') {
      return 250
    }
    return null
  }, [planTier, resolvedRunUsage?.limit])
  const runsRemaining =
    runsLimit != null ? Math.max(0, runsLimit - runsUsed) : null
  const runsPercent = useMemo(() => {
    if (!runsLimit || runsLimit <= 0) return null
    if (runsUsed <= 0) return 0
    return Math.min(100, (runsUsed / runsLimit) * 100)
  }, [runsLimit, runsUsed])
  const workspaceDisplayName =
    currentWorkspace?.workspace.name?.trim() || 'Workspace'
  const workspaceRunsOverage =
    workspaceRunUsage?.overage != null
      ? workspaceRunUsage.overage
      : runsLimit
        ? Math.max(0, runsUsed - runsLimit)
        : 0
  const runAvailability = useMemo<RunAvailability | undefined>(() => {
    if (workspaceRunCapReached) {
      return {
        disabled: true,
        reason: `${workspaceDisplayName} has exhausted its monthly run allocation. Upgrade in Settings → Plan or wait for the next cycle.`
      }
    }
    if (planTier === 'solo' && runsLimit && runsUsed >= runsLimit) {
      return {
        disabled: true,
        reason: `${workspaceDisplayName} has used all ${runsLimit.toLocaleString()} runs available this month.`
      }
    }
    return undefined
  }, [
    workspaceDisplayName,
    workspaceRunCapReached,
    runsLimit,
    runsUsed,
    planTier
  ])
  const workspaceLimitReached =
    planTier === 'workspace' && runsLimit && runsUsed >= runsLimit
  const soloLimitReached =
    planTier === 'solo' && runsLimit && runsUsed >= runsLimit
  const runLimitReached =
    Boolean(runAvailability?.disabled) ||
    workspaceLimitReached ||
    soloLimitReached
  const runLimitApproaching =
    !runLimitReached &&
    runsLimit &&
    runsPercent !== null &&
    runsPercent >= (planTier === 'workspace' ? 90 : 80)
  const runUsageDescription = runsLimit
    ? `${workspaceDisplayName} has used ${runsUsed.toLocaleString()} of ${runsLimit.toLocaleString()} runs this month.`
    : `${workspaceDisplayName} has exhausted its monthly run allocation.`
  const runLimitBannerTitle = runLimitReached
    ? planTier === 'workspace'
      ? 'Workspace run limit exceeded'
      : 'Workspace run limit reached'
    : 'Workspace run usage nearing limit'
  const runLimitBannerDescription = (() => {
    if (!runsLimit) return runUsageDescription
    if (planTier === 'workspace') {
      const overageDetail =
        workspaceRunsOverage > 0
          ? `${workspaceRunsOverage.toLocaleString()} runs are over the included limit. `
          : ''
      return `${runUsageDescription} ${overageDetail}Additional runs continue to execute and will be billed as overage.`
    }
    if (runLimitReached) {
      return `${runUsageDescription} Runs will pause once the limit is reached.`
    }
    return `${runUsageDescription} Runs will pause once the limit is reached.`
  })()

  const normalizeWorkflowData = useCallback((data: unknown) => {
    if (data && typeof data === 'object') {
      const rawNodes = Array.isArray((data as { nodes?: unknown }).nodes)
        ? ((data as { nodes?: unknown }).nodes as Array<Partial<WorkflowNode>>)
        : []
      const rawEdges = Array.isArray((data as { edges?: unknown }).edges)
        ? ((data as { edges?: unknown }).edges as Array<Partial<WorkflowEdge>>)
        : []

      const nodes: WorkflowNode[] = []
      rawNodes.forEach((rawNode) => {
        if (!rawNode || typeof rawNode.id !== 'string') return
        const node = rawNode as WorkflowNode
        nodes.push({
          ...node,
          data:
            node?.data && typeof node.data === 'object'
              ? sanitizeData(cloneWorkflowData(node.data), node.type)
              : node.data
        })
      })

      const edges: WorkflowEdge[] = []
      rawEdges.forEach((rawEdge) => {
        if (!rawEdge || typeof rawEdge.id !== 'string') return
        const edge = rawEdge as WorkflowEdge
        edges.push({
          ...edge,
          data:
            edge?.data && typeof edge.data === 'object'
              ? cloneWorkflowData(edge.data)
              : edge.data,
          label:
            typeof (rawEdge as any)?.label === 'string'
              ? (rawEdge as any).label
              : undefined,
          animated: Boolean((rawEdge as { animated?: unknown }).animated)
        })
      })

      return { nodes, edges }
    }

    return { nodes: [], edges: [] }
  }, [])

  const pushGraphToStore = useCallback(
    (
      graph: { nodes: WorkflowNode[]; edges: WorkflowEdge[] },
      markDirty: boolean
    ) => {
      const epoch = Date.now()
      const incomingNodes = hydrateIncomingNodes(graph?.nodes ?? [], epoch)
      const incomingEdges = hydrateIncomingEdges(graph?.edges ?? [])
      const normalizedNodes = normalizeNodesForState(incomingNodes)
      const normalizedEdges = incomingEdges

      const { setGraph } = useWorkflowStore.getState()
      // Atomically replace graph and control dirty state to avoid transient re-dirty
      setGraph(normalizedNodes, normalizedEdges, markDirty)
    },
    []
  )

  const currentWorkflow = useMemo(
    () =>
      workflows.find((workflow) => workflow.id === currentWorkflowId) ?? null,
    [workflows, currentWorkflowId]
  )
  const currentWorkflowIdValue = currentWorkflow?.id ?? null
  const isWorkspaceAdmin = useMemo(
    () => workspaceRole === 'owner' || workspaceRole === 'admin',
    [workspaceRole]
  )
  const isViewer = workspaceRole === 'viewer'
  const isCreator = useMemo(
    () => (currentWorkflow ? currentWorkflow.user_id === userId : false),
    [currentWorkflow, userId]
  )
  const isLocked = Boolean(currentWorkflow?.locked_by)
  const canUnlockWorkflow = Boolean(
    currentWorkflow && (isCreator || isWorkspaceAdmin)
  )
  const canLockWorkflow = Boolean(currentWorkflow && isCreator)
  const canEditCurrentWorkflow =
    !isViewer && (!isLocked || isCreator || isWorkspaceAdmin)
  const canEditRef = useRef(canEditCurrentWorkflow)
  useEffect(() => {
    canEditRef.current = canEditCurrentWorkflow
  }, [canEditCurrentWorkflow])
  useEffect(() => {
    setLockBusy(false)
  }, [currentWorkflow?.id])
  useEffect(() => {
    latestWorkflowVersionRef.current = currentWorkflow?.updated_at ?? null
  }, [currentWorkflow?.id, currentWorkflow?.updated_at])

  useEffect(() => {
    setRemoteUpdate(null)
  }, [currentWorkflow?.id])

  const _currentMeta = useMemo(
    () => ({
      name: currentWorkflow?.name ?? '',
      description: currentWorkflow?.description ?? null
    }),
    [currentWorkflow?.name, currentWorkflow?.description]
  )
  void _currentMeta

  const workflowOptions = useMemo(
    () =>
      workflows.map((workflow) => ({ id: workflow.id, name: workflow.name })),
    [workflows]
  )

  useEffect(() => {
    const fetchWorkflows = async () => {
      try {
        setLoadingWorkflows(true)
        setError(null)
        const data = await listWorkflows(activeWorkspaceId)
        const visible =
          planTier === 'solo'
            ? [...data]
                .sort((a, b) => {
                  const aDate = a.created_at
                    ? new Date(a.created_at).getTime()
                    : 0
                  const bDate = b.created_at
                    ? new Date(b.created_at).getTime()
                    : 0
                  return aDate - bDate
                })
                .slice(0, 3)
            : data
        setHiddenWorkflowCount(Math.max(data.length - visible.length, 0))
        setWorkflows(visible)

        if (visible.length > 0) {
          const [first] = visible
          const normalized = normalizeWorkflowData(first.data)
          setCurrentWorkflowId(first.id)
          pushGraphToStore(normalized, false)
        } else {
          setCurrentWorkflowId(null)
          pushGraphToStore({ nodes: [], edges: [] }, false)
        }
      } catch (err) {
        console.error('Failed to load workflows', err)
        setError('Failed to load workflows.')
        setWorkflows([])
        setCurrentWorkflowId(null)
        pushGraphToStore({ nodes: [], edges: [] }, false)
      } finally {
        setLoadingWorkflows(false)
      }
    }

    fetchWorkflows()
    void refreshPlanUsage(usageWorkspaceId)
  }, [
    normalizeWorkflowData,
    planTier,
    refreshPlanUsage,
    usageWorkspaceId,
    pushGraphToStore,
    activeWorkspaceId
  ])

  const doSelectWorkflow = useCallback(
    (id: string) => {
      const nextWorkflow = workflows.find((workflow) => workflow.id === id)
      setCurrentWorkflowId(id)
      setError(null)

      // Always try to fetch fresh data for the selected workflow to avoid shared references/stale state
      ;(async () => {
        try {
          const fresh = await getWorkflow(id, activeWorkspaceId)
          // Update list cache with fresh record
          setWorkflows((prev) =>
            prev.map((w) => (w.id === fresh.id ? fresh : w))
          )
          const normalized = normalizeWorkflowData(fresh.data)
          pushGraphToStore(normalized, false)
        } catch (e) {
          // Fallback to local cache if fetch fails
          if (nextWorkflow) {
            const normalized = normalizeWorkflowData(nextWorkflow.data)
            pushGraphToStore(normalized, false)
          } else {
            pushGraphToStore({ nodes: [], edges: [] }, false)
          }
        }
      })()
    },
    [workflows, normalizeWorkflowData, activeWorkspaceId, pushGraphToStore]
  )

  const selectWorkflow = useCallback(
    async (id: string) => {
      if (id === currentWorkflowId) return

      const saved = await saveIfDirty()
      if (!saved) return

      doSelectWorkflow(id)
    },
    [currentWorkflowId, doSelectWorkflow, saveIfDirty]
  )

  // Warn on browser tab close/refresh when there are unsaved changes
  useEffect(() => {
    const beforeUnload = (e: BeforeUnloadEvent) => {
      const { isDirty } = useWorkflowStore.getState()
      if (isDirty && !workflowSaving) {
        e.preventDefault()
        // Some browsers require returnValue to be set
        e.returnValue = ''
        return ''
      }
      return undefined
    }
    window.addEventListener('beforeunload', beforeUnload)
    return () => window.removeEventListener('beforeunload', beforeUnload)
  }, [workflowSaving])

  const renameWorkflow = useCallback(
    (id: string, newName: string) => {
      if (!canEditCurrentWorkflow) return
      setWorkflows((prev) =>
        prev.map((workflow) =>
          workflow.id === id ? { ...workflow, name: newName } : workflow
        )
      )
      if (id === currentWorkflowId) {
        useWorkflowStore.setState({ isDirty: true })
      }
    },
    [canEditCurrentWorkflow, currentWorkflowId]
  )

  const handleNewWorkflow = useCallback(async () => {
    // Guard against rapid double-clicks while a create is in-flight
    if (isWorkflowActionBusy || workflowSaving || !canEditCurrentWorkflow)
      return
    const saved = await saveIfDirty()
    if (!saved) return
    if (planTier === 'solo' && workflows.length >= 3) {
      setError(
        'You have reached the solo plan limit of 3 saved workflows. Upgrade in Settings → Plan to create additional workflows.'
      )
      return
    }
    try {
      setWorkflowActionBusy(true)
      setError(null)

      const base = 'New Workflow'
      // Always enforce unique, case-insensitive names
      const existing = new Set(
        workflows.map((w) => (w.name || '').toLowerCase())
      )
      let unique = base
      let i = 1
      while (existing.has(unique.toLowerCase())) {
        i += 1
        unique = `${base} (${i})`
      }

      const payload = {
        name: unique,
        description: null,
        data: { nodes: [], edges: [] }
      }

      const created = await createWorkflowApi(payload, activeWorkspaceId)
      setWorkflows((prev) => [created, ...prev])
      setCurrentWorkflowId(created.id)

      const normalized = normalizeWorkflowData(created.data ?? payload.data)
      pushGraphToStore(normalized, false)
      await refreshPlanUsage(usageWorkspaceId)
    } catch (err) {
      console.error('Failed to create workflow', err)
      setError('Failed to create workflow.')
      window.alert('Failed to create workflow. Please try again.')
    } finally {
      setWorkflowActionBusy(false)
    }
  }, [
    normalizeWorkflowData,
    isWorkflowActionBusy,
    workflowSaving,
    workflows,
    planTier,
    refreshPlanUsage,
    canEditCurrentWorkflow,
    usageWorkspaceId,
    pushGraphToStore,
    activeWorkspaceId,
    saveIfDirty
  ])

  const stopPolling = useCallback(() => {
    if (pollTimerRef.current) {
      clearTimeout(pollTimerRef.current)
      pollTimerRef.current = null
    }
    // Ignore any in-flight responses for previous run ids
    currentPollRunIdRef.current = null
  }, [])

  const pollBackoffRef = useRef<number>(0)
  const pollRun = useCallback(
    async (workflowId: string, runId: string) => {
      // Drop stale polls (e.g., after switching to a different run)
      if (currentPollRunIdRef.current !== runId) return
      try {
        const { run, node_runs } = await getWorkflowRunStatus(workflowId, runId)
        // Ignore if this response is for an outdated runId
        if (currentPollRunIdRef.current !== runId) return
        setActiveRun(run)
        setNodeRuns(node_runs)
        // reset backoff on success
        pollBackoffRef.current = 0
        if (run.status === 'queued' || run.status === 'running') {
          pollTimerRef.current = setTimeout(
            () => pollRun(workflowId, runId),
            1000
          )
        } else {
          // terminal: clear timer
          stopPolling()
          // If overlay is open for this workflow, watch for next running or queued run
          if (
            runOverlayOpen &&
            currentWorkflow &&
            currentWorkflow.id === workflowId
          ) {
            if (overlayWatchTimerRef.current) {
              clearTimeout(overlayWatchTimerRef.current)
              overlayWatchTimerRef.current = null
            }
            const watchTick = async () => {
              try {
                const runs = await listActiveRuns(workflowId)
                const next =
                  runs.find((r) => r.status === 'running') ||
                  runs.find((r) => r.status === 'queued')
                if (next) {
                  setActiveRun(next)
                  setNodeRuns([])
                  currentPollRunIdRef.current = next.id
                  pollRun(workflowId, next.id)
                  overlayWatchTimerRef.current = null
                  return
                }
              } catch (e) {
                console.error(errorMessage(e))
              }
              if (
                runOverlayOpen &&
                currentWorkflow &&
                currentWorkflow.id === workflowId
              ) {
                overlayWatchTimerRef.current = setTimeout(watchTick, 1000)
              }
            }
            overlayWatchTimerRef.current = setTimeout(watchTick, 1000)
          }
        }
      } catch (e) {
        console.error('Polling run failed', e)
        // Back off and retry instead of stopping, in case of transient 429/Network errors
        const attempt = pollBackoffRef.current || 0
        const delay = Math.min(5000, 1000 * Math.pow(2, Math.min(3, attempt)))
        pollBackoffRef.current = attempt + 1
        // Only reschedule if this runId is still the intended one
        if (currentPollRunIdRef.current === runId) {
          pollTimerRef.current = setTimeout(
            () => pollRun(workflowId, runId),
            delay
          )
        }
      }
    },
    [stopPolling, runOverlayOpen, currentWorkflow]
  )

  const fetchRunQueue = useCallback(async () => {
    try {
      const wid = runsScope === 'current' ? currentWorkflow?.id : undefined
      const runs = await listActiveRuns(wid)
      setRunQueue(runs)
    } catch (e) {
      console.error('Failed to fetch runs', e)
    }
  }, [runsScope, currentWorkflow?.id])

  useEffect(() => {
    if (!runsDrawerOpen) return
    void fetchRunQueue()
  }, [runsDrawerOpen, fetchRunQueue])

  // Ensure overlay shows only the active run for the currently selected workflow
  // Now: no REST polling here; discovery is done via SSE in the effect below.
  const ensureOverlayRunForSelected = useCallback(async () => {
    if (!currentWorkflow) {
      setActiveRun(null)
      setNodeRuns([])
      return
    }
    const isActiveForSelected =
      activeRun &&
      activeRun.workflow_id === currentWorkflow.id &&
      (activeRun.status === 'running' || activeRun.status === 'queued')
    if (isActiveForSelected) return
    // Clear and let SSE discovery latch onto the next run
    stopPolling()
    setActiveRun(null)
    setNodeRuns([])
  }, [currentWorkflow, activeRun, stopPolling])

  const handleToggleRunOverlay = useCallback(() => {
    if (runOverlayOpen) {
      if (overlayWatchTimerRef.current) {
        clearTimeout(overlayWatchTimerRef.current)
        overlayWatchTimerRef.current = null
      }
      setRunOverlayOpen(false)
      return
    }
    setRunOverlayOpen(true)
    try {
      window.dispatchEvent(new CustomEvent('dsentr-resume-global-poll'))
    } catch (e) {
      console.error(errorMessage(e))
    }
    // Kick off selection of the appropriate run for this workflow
    ensureOverlayRunForSelected()
  }, [runOverlayOpen, ensureOverlayRunForSelected])

  // Keep overlay latched to the selected workflow's next running/queued run via SSE, with REST fallback
  useEffect(() => {
    if (!runOverlayOpen || !currentWorkflowIdValue || activeRunId) return

    const base = (API_BASE_URL || '').replace(/\/$/, '')
    const url = `${base}/api/workflows/${currentWorkflowIdValue}/runs/events-stream`
    let es: EventSource | null = null
    let fallbackTimer: any = null
    let backoff = 1500

    const pickFrom = (runs: any[]) => {
      const candidate =
        runs.find((r) => r.status === 'running') ||
        runs.find((r) => r.status === 'queued')
      if (candidate) {
        setActiveRun(candidate)
        setNodeRuns([])
        try {
          es?.close()
        } catch (e) {
          console.error(errorMessage(e))
        }
        if (fallbackTimer) {
          clearTimeout(fallbackTimer)
          fallbackTimer = null
        }
        return true
      }
      return false
    }

    const startFallback = () => {
      const doFetch = async () => {
        try {
          const runs = await listActiveRuns(currentWorkflowIdValue)
          if (pickFrom(runs)) return
        } catch (e) {
          console.error(errorMessage(e))
        }
        // schedule next attempt with capped backoff
        backoff = Math.min(5000, backoff * 2)
        fallbackTimer = setTimeout(doFetch, backoff)
      }
      doFetch()
    }

    try {
      es = new EventSource(url, { withCredentials: true } as EventSourceInit)
    } catch {
      es = null
    }
    if (!es) {
      startFallback()
      return
    }

    const onRuns = (e: MessageEvent) => {
      try {
        const runs = JSON.parse(e.data)
        pickFrom(runs)
      } catch (e) {
        console.error(errorMessage(e))
      }
    }
    const onError = () => {
      try {
        es?.close()
      } catch (e) {
        console.error(errorMessage(e))
      }
      if (!fallbackTimer) startFallback()
    }
    es.addEventListener('runs', onRuns as any)
    es.onerror = onError

    return () => {
      try {
        es?.close()
      } catch (e) {
        console.error(errorMessage(e))
      }
      if (fallbackTimer) {
        clearTimeout(fallbackTimer)
        fallbackTimer = null
      }
    }
  }, [activeRunId, currentWorkflowIdValue, runOverlayOpen])

  // Global runs SSE to drive toolbar status
  useEffect(() => {
    const base = (API_BASE_URL || '').replace(/\/$/, '')
    const url = `${base}/api/workflows/runs/events`
    let es: EventSource | null = null
    try {
      es = new EventSource(url, { withCredentials: true } as EventSourceInit)
    } catch {
      es = null
    }
    if (!es) return
    const onStatus = (e: MessageEvent) => {
      try {
        const s = JSON.parse(e.data)
        if (s.has_running) setGlobalRunStatus('running')
        else if (s.has_queued) setGlobalRunStatus('queued')
        else setGlobalRunStatus('idle')
      } catch (e) {
        console.error(errorMessage(e))
      }
    }
    es.addEventListener('status', onStatus as any)
    es.onerror = () => {
      try {
        es?.close()
      } catch (e) {
        console.error(errorMessage(e))
      }
    }
    return () => {
      try {
        es?.close()
      } catch (e) {
        console.error(errorMessage(e))
      }
    }
  }, [])
  const toolbarRunStatus = useMemo(() => {
    if (activeRun?.status === 'running') return 'running'
    if (globalRunStatus === 'running') return 'running'
    if (globalRunStatus === 'queued') return 'queued'
    if (activeRun?.status === 'queued') return 'queued'
    return 'idle'
  }, [activeRun?.status, globalRunStatus])

  // Runs drawer: consume SSE of active runs for the selected workflow
  useEffect(() => {
    if (!runsDrawerOpen || !currentWorkflowIdValue) return
    const base = (API_BASE_URL || '').replace(/\/$/, '')
    const url = `${base}/api/workflows/${currentWorkflowIdValue}/runs/events-stream`
    let es: EventSource | null = null
    try {
      es = new EventSource(url, { withCredentials: true } as EventSourceInit)
    } catch {
      es = null
    }
    if (!es) return
    const onRuns = (e: MessageEvent) => {
      try {
        setRunQueue(JSON.parse(e.data))
      } catch (e) {
        console.error(errorMessage(e))
      }
    }
    es.addEventListener('runs', onRuns as any)
    es.onerror = () => {
      try {
        es?.close()
      } catch (e) {
        console.error(errorMessage(e))
      }
    }
    return () => {
      try {
        es?.close()
      } catch (e) {
        console.error(errorMessage(e))
      }
    }
  }, [runsDrawerOpen, currentWorkflowIdValue])

  const handleRunWorkflow = useCallback(
    async (startNodeId?: string) => {
      if (!currentWorkflow) return
      const saved = await saveIfDirty()
      if (!saved) return
      if (runAvailability?.disabled) {
        setError(runAvailability.reason || 'Workspace run quota reached.')
        return
      }
      try {
        setActiveRun(null)
        setNodeRuns([])
        const run = await startWorkflowRun(currentWorkflow.id, {
          startFromNodeId: startNodeId
        })
        setActiveRun(run)
        currentPollRunIdRef.current = run.id
        pollRun(currentWorkflow.id, run.id)
        void refreshPlanUsage(usageWorkspaceId)
        try {
          window.dispatchEvent(new CustomEvent('dsentr-resume-global-poll'))
        } catch (e) {
          console.error(errorMessage(e))
        }
      } catch (e: any) {
        console.error('Failed to start run', e)
        if ((e as any)?.code === 'workspace_run_limit') {
          markWorkspaceRunCap()
        }
        if (Array.isArray(e?.violations) && e.violations.length > 0) {
          setError(e.violations[0]?.message || e?.message || null)
        } else {
          setError(
            e?.message ||
              'Failed to start run. Check your plan limits and try again.'
          )
        }
      }
    },
    [
      currentWorkflow,
      pollRun,
      refreshPlanUsage,
      runAvailability,
      markWorkspaceRunCap,
      usageWorkspaceId,
      saveIfDirty
    ]
  )

  // Overlay: subscribe to SSE for active run to reduce client work
  useEffect(() => {
    if (!runOverlayOpen || !currentWorkflowIdValue || !activeRunId) return
    // Stop any REST polling for this run
    stopPolling()

    const base = (API_BASE_URL || '').replace(/\/$/, '')
    const url = `${base}/api/workflows/${currentWorkflowIdValue}/runs/${activeRunId}/events`
    let es: EventSource | null = null
    try {
      es = new EventSource(url, { withCredentials: true } as EventSourceInit)
    } catch {
      es = null
    }
    if (!es) return

    const onRun = (e: MessageEvent) => {
      try {
        const run = JSON.parse(e.data)
        setActiveRun(run)
        if (run.status !== 'queued' && run.status !== 'running') {
          es?.close()
        }
      } catch (e) {
        console.error(errorMessage(e))
      }
    }
    const onNodes = (e: MessageEvent) => {
      try {
        setNodeRuns(JSON.parse(e.data))
      } catch (e) {
        console.error(errorMessage(e))
      }
    }
    const onError = () => {
      // Allow adaptive global poll to wake if needed
      try {
        window.dispatchEvent(new CustomEvent('dsentr-resume-global-poll'))
      } catch (e) {
        console.error(errorMessage(e))
      }
      es?.close()
    }

    es.addEventListener('run', onRun as any)
    es.addEventListener('node_runs', onNodes as any)
    es.onerror = onError

    return () => {
      try {
        es?.close()
      } catch (e) {
        console.error(errorMessage(e))
      }
    }
  }, [runOverlayOpen, currentWorkflowIdValue, activeRunId, stopPolling])

  useEffect(() => {
    if (!currentWorkflowIdValue) return
    const base = (API_BASE_URL || '').replace(/\/$/, '')
    const workspaceQuery = activeWorkspaceId
      ? `?workspace=${encodeURIComponent(activeWorkspaceId)}`
      : ''
    const url = `${base}/api/workflows/${currentWorkflowIdValue}/events${workspaceQuery}`
    let es: EventSource | null = null
    try {
      es = new EventSource(url, { withCredentials: true } as EventSourceInit)
    } catch {
      es = null
    }
    if (!es) return

    const onWorkflow = (e: MessageEvent) => {
      try {
        const incoming: WorkflowRecord = JSON.parse(e.data)
        const incomingVersion = incoming.updated_at ?? null
        const currentVersion = latestWorkflowVersionRef.current
        const incomingTs = incomingVersion ? Date.parse(incomingVersion) : NaN
        const currentTs = currentVersion ? Date.parse(currentVersion) : NaN
        if (
          !Number.isNaN(incomingTs) &&
          !Number.isNaN(currentTs) &&
          incomingTs <= currentTs
        ) {
          return
        }
        if (useWorkflowStore.getState().isDirty) {
          latestWorkflowVersionRef.current =
            incomingVersion ?? latestWorkflowVersionRef.current
          setRemoteUpdate({ workflow: incoming, reason: 'sse' })
          return
        }
        latestWorkflowVersionRef.current =
          incomingVersion ?? latestWorkflowVersionRef.current
        setWorkflows((prev) =>
          prev.some((workflow) => workflow.id === incoming.id)
            ? prev.map((workflow) =>
                workflow.id === incoming.id
                  ? { ...workflow, ...incoming }
                  : workflow
              )
            : [incoming, ...prev]
        )
        if (!useWorkflowStore.getState().isDirty) {
          const normalized = normalizeWorkflowData(incoming.data)
          pushGraphToStore(normalized, false)
          setError(null)
          setRemoteUpdate(null)
        } else {
          setRemoteUpdate({ workflow: incoming, reason: 'sse' })
        }
      } catch (err) {
        console.error(errorMessage(err))
      }
    }

    es.addEventListener('workflow', onWorkflow as any)
    es.onerror = () => {
      try {
        es?.close()
      } catch (err) {
        console.error(errorMessage(err))
      }
    }

    return () => {
      try {
        es?.close()
      } catch (err) {
        console.error(errorMessage(err))
      }
    }
  }, [
    activeWorkspaceId,
    currentWorkflowIdValue,
    normalizeWorkflowData,
    pushGraphToStore,
    setError
  ])

  const applyGraphToCanvas = useCallback(
    (graph: { nodes: any[]; edges: any[] }) => {
      setError(null)
      const normalized = normalizeWorkflowData(graph)
      pushGraphToStore(normalized, true)
    },
    [normalizeWorkflowData, setError, pushGraphToStore]
  )

  const applyRemoteWorkflow = useCallback(
    (nextWorkflow: WorkflowRecord) => {
      latestWorkflowVersionRef.current =
        nextWorkflow.updated_at ?? latestWorkflowVersionRef.current
      setRemoteUpdate(null)
      setWorkflows((prev) =>
        prev.some((workflow) => workflow.id === nextWorkflow.id)
          ? prev.map((workflow) =>
              workflow.id === nextWorkflow.id
                ? { ...workflow, ...nextWorkflow }
                : workflow
            )
          : [nextWorkflow, ...prev]
      )
      if (currentWorkflowIdValue === nextWorkflow.id) {
        const normalized = normalizeWorkflowData(nextWorkflow.data)
        pushGraphToStore(normalized, false)
      }
      setError(null)
    },
    [currentWorkflowIdValue, normalizeWorkflowData, pushGraphToStore, setError]
  )

  const handleSave = useCallback(async (): Promise<boolean> => {
    const workflowState = useWorkflowStore.getState()
    if (!workflowState.isDirty) {
      return true
    }
    if (
      !currentWorkflow ||
      isWorkflowActionBusy ||
      workflowSaving ||
      !canEditCurrentWorkflow
    ) {
      return false
    }

    const { getGraph, setSaving } = workflowState

    setSaving(true)
    setError(null)

    try {
      const { nodes, edges } = getGraph()
      const webhookTriggerMissingEventType = nodes.some((node) => {
        if (node.type !== 'trigger') return false
        const data = node.data as
          | { triggerType?: string; event_type?: string }
          | undefined
        const triggerType =
          typeof data?.triggerType === 'string' ? data.triggerType : 'Manual'
        const normalizedTriggerType =
          triggerType.trim().toLowerCase() || 'manual'
        if (normalizedTriggerType !== 'webhook') return false
        const eventType =
          typeof data?.event_type === 'string' ? data.event_type : ''
        return !eventType.trim()
      })
      if (webhookTriggerMissingEventType) {
        setError('Webhook triggers require an event type before saving.')
        return false
      }
      const cleanNodes = sortById(nodes.map(sanitizeNodeData))
      const cleanEdges = sortById(edges.map(normalizeEdgeForPayload))
      const payloadGraph = {
        nodes: cleanNodes,
        edges: cleanEdges
      }

      const updated = await updateWorkflowApi(
        currentWorkflow.id,
        {
          name: currentWorkflow.name,
          description: currentWorkflow.description ?? null,
          data: payloadGraph
        },
        activeWorkspaceId,
        currentWorkflow.updated_at ?? null
      )

      setWorkflows((prev) =>
        prev.map((workflow) =>
          workflow.id === updated.id ? { ...workflow, ...updated } : workflow
        )
      )
      latestWorkflowVersionRef.current =
        updated.updated_at ?? latestWorkflowVersionRef.current
      setRemoteUpdate(null)

      const normalized = normalizeWorkflowData(updated.data ?? payloadGraph)
      // After a successful save, reflect the server graph and mark clean
      pushGraphToStore(normalized, false)
      return true
    } catch (err) {
      console.error('Failed to save workflow', err)
      if ((err as any)?.code === 'conflict') {
        const incoming = (err as any)?.workflow as WorkflowRecord | undefined
        if (incoming) {
          latestWorkflowVersionRef.current =
            incoming.updated_at ?? latestWorkflowVersionRef.current
          setRemoteUpdate({ workflow: incoming, reason: 'conflict' })
          setError(
            'Save was blocked because someone else saved a newer version. Reload the latest changes to continue.'
          )
          return false
        }
      }
      if (
        Array.isArray((err as any)?.violations) &&
        (err as any).violations.length > 0
      ) {
        const violationMessage =
          (err as any).violations[0]?.message ||
          (err as any).message ||
          'This workflow uses a premium feature that is locked on the solo plan.'
        setError(violationMessage)
      } else {
        setError((err as any)?.message || 'Failed to save workflow.')
        window.alert('Failed to save workflow. Please try again.')
      }
      return false
    } finally {
      setSaving(false)
    }
  }, [
    activeWorkspaceId,
    canEditCurrentWorkflow,
    currentWorkflow,
    isWorkflowActionBusy,
    workflowSaving,
    normalizeWorkflowData,
    pushGraphToStore,
    setError
  ])

  handleSaveRef.current = handleSave

  const handleLockWorkflow = useCallback(async () => {
    if (!currentWorkflow || lockBusy || !canLockWorkflow) return
    try {
      setLockBusy(true)
      setError(null)
      const updated = await lockWorkflowApi(
        currentWorkflow.id,
        activeWorkspaceId
      )
      setWorkflows((prev) =>
        prev.map((workflow) =>
          workflow.id === updated.id ? { ...workflow, ...updated } : workflow
        )
      )
    } catch (err) {
      console.error('Failed to lock workflow', err)
      setError((err as any)?.message || 'Failed to lock workflow.')
    } finally {
      setLockBusy(false)
    }
  }, [canLockWorkflow, currentWorkflow, lockBusy, activeWorkspaceId])

  const handleUnlockWorkflow = useCallback(async () => {
    if (!currentWorkflow || lockBusy || !canUnlockWorkflow) return
    try {
      setLockBusy(true)
      setError(null)
      const updated = await unlockWorkflowApi(
        currentWorkflow.id,
        activeWorkspaceId
      )
      setWorkflows((prev) =>
        prev.map((workflow) =>
          workflow.id === updated.id ? { ...workflow, ...updated } : workflow
        )
      )
    } catch (err) {
      console.error('Failed to unlock workflow', err)
      setError((err as any)?.message || 'Failed to unlock workflow.')
    } finally {
      setLockBusy(false)
    }
  }, [canUnlockWorkflow, currentWorkflow, lockBusy, activeWorkspaceId])

  const toolbarWorkflow = useMemo(() => {
    if (!currentWorkflow) {
      return { id: '', name: '', list: workflowOptions }
    }
    return {
      id: currentWorkflow.id,
      name: currentWorkflow.name,
      list: workflowOptions
    }
  }, [currentWorkflow, workflowOptions])
  const isGraphEmpty = useWorkflowStore(
    useCallback(
      (state) => state.nodes.length === 0 && state.edges.length === 0,
      []
    )
  )
  const [templatesOpen, setTemplatesOpen] = useState(false)
  const paletteQuickAddRef = useRef<(dragType: string) => void>(() => {})
  const registerPaletteQuickAdd = useCallback(
    (handler: (dragType: string) => void) => {
      paletteQuickAddRef.current = handler ?? (() => {})
    },
    []
  )
  const handlePaletteQuickAdd = useCallback((dragType: string) => {
    paletteQuickAddRef.current?.(dragType)
  }, [])
  const actionDefinitions = useActionRegistry((state) => state.actions)
  useEffect(() => {
    console.log(
      'Action registry actions:',
      actionDefinitions.map((a) => a.id)
    )
  }, [actionDefinitions])
  const loadActionCatalog = useActionRegistry((state) => state.loadCatalog)

  useEffect(() => {
    void loadActionCatalog()
  }, [loadActionCatalog])

  const actionGroups = useMemo(() => {
    const groups = new Map<
      string,
      {
        heading: string
        tiles: Array<{
          id: string
          label: string
          description: string
          dragType: string
          gradient: string
          icon: React.ReactNode
        }>
      }
    >()

    actionDefinitions.forEach((action) => {
      if (action.visibleInPicker === false) return
      const heading = action.category?.trim() || 'Actions'
      const iconKey = normalizeIconKey(action.iconKey)
      const IconComponent = ICON_BY_KEY[iconKey] ?? ActionIcon
      const label = action.label?.trim() || action.id
      const description = action.description || ''
      const tile = {
        id: action.id,
        label,
        description,
        dragType: `action:${action.id}`,
        gradient: action.gradient,
        icon: <IconComponent />
      }
      const existing = groups.get(heading)
      if (existing) {
        existing.tiles.push(tile)
      } else {
        groups.set(heading, { heading, tiles: [tile] })
      }
    })

    return [...groups.values(), LOGIC_SIDEBAR_TILE_GROUP]
  }, [actionDefinitions])

  // Collapsible state for action categories; initialized expanded
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(actionGroups.map((g) => [g.heading, true]))
  )
  useEffect(() => {
    setOpenGroups((prev) => {
      let changed = false
      const next = { ...prev }
      actionGroups.forEach((group) => {
        if (!(group.heading in next)) {
          next[group.heading] = true
          changed = true
        }
      })
      return changed ? next : prev
    })
  }, [actionGroups])

  // Search state for actions
  const [actionSearch, setActionSearch] = useState('')
  const trimmedQuery = actionSearch.trim().toLowerCase()
  const filteredGroups = useMemo(() => {
    if (!trimmedQuery) return actionGroups
    return actionGroups
      .map((group) => ({
        heading: group.heading,
        tiles: group.tiles.filter((tile) => {
          const label = tile.label.toLowerCase()
          const desc = (tile.description || '').toLowerCase()
          return label.includes(trimmedQuery) || desc.includes(trimmedQuery)
        })
      }))
      .filter((g) => g.tiles.length > 0)
  }, [actionGroups, trimmedQuery])

  function QuickAddButton({
    label,
    onClick,
    disabled
  }: {
    label: string
    onClick?: () => void
    disabled?: boolean
  }) {
    return (
      <button
        type="button"
        aria-label={label}
        draggable={false}
        data-quick-add-button
        onClick={(event) => {
          event.preventDefault()
          event.stopPropagation()
          if (disabled) return
          onClick?.()
        }}
        onMouseDown={(event) => {
          event.preventDefault()
          event.stopPropagation()
        }}
        disabled={disabled}
        style={{ cursor: 'pointer' }}
        className="absolute right-2 top-1/2 -translate-y-1/2 z-20 inline-flex h-9 w-9 items-center justify-center rounded-md bg-black/80 text-emerald-400 opacity-0 shadow-lg ring-1 ring-emerald-400/40 backdrop-blur-sm transition-opacity duration-200 hover:bg-black/90 group-hover:opacity-100 group-focus-within:opacity-100 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-500 disabled:pointer-events-none disabled:opacity-0 cursor-pointer"
      >
        <Plus className="h-4 w-4" />
      </button>
    )
  }

  function DraggableTile({
    label,
    description,
    icon,
    gradient,
    dragType,
    disabled = false,
    onQuickAdd
  }: {
    label: string
    description: string
    icon: React.ReactNode
    gradient: string
    dragType: string
    disabled?: boolean
    onQuickAdd?: (dragType: string) => void
  }) {
    const allowDrag = canEditCurrentWorkflow && !disabled
    const allowQuickAdd = allowDrag && Boolean(onQuickAdd)
    return (
      <div
        draggable={allowDrag}
        onDragStart={(e) => {
          if (!allowDrag) {
            e.preventDefault()
            return
          }
          if (
            (e.target as HTMLElement | null)?.closest('[data-quick-add-button]')
          ) {
            e.preventDefault()
            return
          }
          e.dataTransfer.effectAllowed = 'move'
          e.dataTransfer.setData('application/reactflow', dragType)
        }}
        role="button"
        aria-label={`Add ${label}`}
        className={[
          `group relative overflow-hidden rounded-xl border shadow-sm select-none${
            allowDrag ? ' cursor-grab active:cursor-grabbing' : ''
          }`,
          'bg-gradient-to-br',
          gradient,
          'p-3 text-white',
          allowDrag
            ? 'transition-transform will-change-transform hover:translate-y-[-1px] hover:shadow-md'
            : 'opacity-60 cursor-not-allowed'
        ].join(' ')}
      >
        <QuickAddButton
          label={`Add ${label} to canvas`}
          onClick={() => onQuickAdd?.(dragType)}
          disabled={!allowQuickAdd}
        />
        <div className="absolute inset-0 bg-white/5 opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none" />
        <div className="relative z-10 flex items-center gap-2">
          <span className="inline-flex items-center justify-center w-7 h-7 rounded-lg bg-white/15 ring-1 ring-white/20">
            {icon}
          </span>
          <div className="flex flex-col leading-none">
            <span className="text-sm font-semibold tracking-tight">
              {label}
            </span>
            <span className="text-[11px] opacity-90">{description}</span>
          </div>
        </div>
      </div>
    )
  }
  function TemplateButton({
    label,
    description,
    onClick,
    disabled,
    onQuickAdd
  }: {
    label: string
    description?: string
    onClick: () => void
    disabled?: boolean
    onQuickAdd?: () => void
  }) {
    const allowQuickAdd = !disabled && Boolean(onQuickAdd)
    return (
      <button
        type="button"
        onClick={onClick}
        disabled={disabled}
        className={`relative group w-full text-left px-3 pr-12 py-2 rounded-lg border bg-white dark:bg-zinc-800 hover:bg-zinc-100 dark:hover:bg-zinc-700 shadow-sm ${disabled ? 'opacity-60 cursor-not-allowed' : ''}`}
      >
        {allowQuickAdd ? (
          <QuickAddButton
            label={`Add ${label} template`}
            onClick={onQuickAdd}
            disabled={disabled}
          />
        ) : null}
        <div className="flex flex-col">
          <span className="text-sm font-medium">{label}</span>
          {description && (
            <span className="text-xs text-zinc-500">{description}</span>
          )}
        </div>
      </button>
    )
  }

  const buildTemplateHandler = useCallback(
    (builder: () => { nodes: any[]; edges: any[] }) => () => {
      if (!isGraphEmpty) return
      const { nodes, edges } = builder()
      applyGraphToCanvas({ nodes, edges })
    },
    [applyGraphToCanvas, isGraphEmpty]
  )

  // React to workflow deletions initiated from Settings modal
  useEffect(() => {
    function onWorkflowDeleted(e: any) {
      const deletedId: string | undefined = e?.detail?.id
      if (!deletedId) return
      setWorkflows((prev) => {
        const updated = prev.filter((w) => w.id !== deletedId)
        if (currentWorkflowId === deletedId) {
          if (updated.length > 0) {
            const next = updated[0]
            setCurrentWorkflowId(next.id)
            const normalized = normalizeWorkflowData(next.data)
            pushGraphToStore(normalized, false)
          } else {
            // No workflows left — create a fresh one
            handleNewWorkflow()
          }
        }
        return updated
      })
    }
    window.addEventListener('workflow-deleted', onWorkflowDeleted as any)
    return () =>
      window.removeEventListener('workflow-deleted', onWorkflowDeleted as any)
  }, [
    currentWorkflowId,
    normalizeWorkflowData,
    handleNewWorkflow,
    pushGraphToStore
  ])

  const sendGridTemplate = buildTemplateHandler(() => {
    const nodes = [
      {
        id: 'trigger-1',
        type: 'trigger',
        position: { x: 80, y: 120 },
        data: {
          label: 'Trigger',
          expanded: true,
          inputs: [],
          triggerType: 'Manual'
        }
      },
      {
        id: 'action-1',
        type: 'actionEmail',
        position: { x: 320, y: 120 },
        data: {
          label: 'Send Email',
          expanded: true,
          inputs: [],
          labelError: null,
          hasLabelValidationError: false,
          actionType: 'email',
          params: {
            service: 'SendGrid',
            from: '',
            to: '',
            subject: 'Welcome to DSentr',
            body: 'This is a sample email from DSentr.'
          },
          timeout: 5000,
          retries: 0,
          stopOnError: true
        }
      }
    ]
    const edges = [
      {
        id: 'e1',
        source: 'trigger-1',
        target: 'action-1',
        type: 'nodeEdge',
        data: { edgeType: 'default' }
      }
    ]
    return { nodes, edges }
  })

  const amazonSesTemplate = buildTemplateHandler(() => {
    const nodes = [
      {
        id: 'trigger-1',
        type: 'trigger',
        position: { x: 80, y: 120 },
        data: {
          label: 'Trigger',
          expanded: true,
          inputs: [],
          triggerType: 'Manual'
        }
      },
      {
        id: 'action-1',
        type: 'actionEmail',
        position: { x: 320, y: 120 },
        data: {
          label: 'Send Email',
          expanded: true,
          inputs: [],
          labelError: null,
          hasLabelValidationError: false,
          actionType: 'email',
          params: {
            service: 'Amazon SES',
            region: 'us-east-1',
            from: '',
            to: '',
            subject: 'Welcome to DSentr',
            body: 'This is a sample email from DSentr.'
          },
          timeout: 5000,
          retries: 0,
          stopOnError: true
        }
      }
    ]
    const edges = [
      {
        id: 'e1',
        source: 'trigger-1',
        target: 'action-1',
        type: 'nodeEdge',
        data: { edgeType: 'default' }
      }
    ]
    return { nodes, edges }
  })

  const mailgunTemplate = buildTemplateHandler(() => {
    const nodes = [
      {
        id: 'trigger-1',
        type: 'trigger',
        position: { x: 80, y: 120 },
        data: {
          label: 'Trigger',
          expanded: true,
          inputs: [],
          triggerType: 'Manual'
        }
      },
      {
        id: 'action-1',
        type: 'actionEmail',
        position: { x: 320, y: 120 },
        data: {
          label: 'Send Email',
          expanded: true,
          inputs: [],
          labelError: null,
          hasLabelValidationError: false,
          actionType: 'email',
          params: {
            service: 'Mailgun',
            region: 'US (api.mailgun.net)',
            from: '',
            to: '',
            subject: 'Welcome to DSentr',
            body: 'This is a sample email from DSentr.'
          },
          timeout: 5000,
          retries: 0,
          stopOnError: true
        }
      }
    ]
    const edges = [
      {
        id: 'e1',
        source: 'trigger-1',
        target: 'action-1',
        type: 'nodeEdge',
        data: { edgeType: 'default' }
      }
    ]
    return { nodes, edges }
  })

  const messagingTemplate = buildTemplateHandler(() => {
    const nodes = [
      {
        id: 'trigger-1',
        type: 'trigger',
        position: { x: 80, y: 120 },
        data: {
          label: 'Trigger',
          expanded: true,
          inputs: [],
          triggerType: 'Manual'
        }
      },
      {
        id: 'action-1',
        type: 'actionSlack',
        position: { x: 320, y: 120 },
        data: {
          label: 'Message',
          expanded: true,
          inputs: [],
          labelError: null,
          hasLabelValidationError: false,
          actionType: 'slack',
          params: {
            channel: '#general',
            message: 'Hello from DSentr!',
            token: '',
            connectionScope: '',
            connectionId: '',
            accountEmail: ''
          },
          timeout: 5000,
          retries: 0,
          stopOnError: true
        }
      }
    ]
    const edges = [
      {
        id: 'e1',
        source: 'trigger-1',
        target: 'action-1',
        type: 'nodeEdge',
        data: { edgeType: 'default' }
      }
    ]
    return { nodes, edges }
  })

  const sheetsTemplate = buildTemplateHandler(() => {
    const nodes = [
      {
        id: 'trigger-1',
        type: 'trigger',
        position: { x: 80, y: 120 },
        data: {
          label: 'Trigger',
          expanded: true,
          inputs: [],
          triggerType: 'Manual'
        }
      },
      {
        id: 'action-1',
        type: 'actionSheets',
        position: { x: 320, y: 120 },
        data: {
          label: 'Google Sheets',
          expanded: true,
          inputs: [],
          labelError: null,
          hasLabelValidationError: false,
          actionType: 'sheets',
          params: {
            spreadsheetId: '',
            worksheet: 'Sheet1',
            columns: [
              { key: 'timestamp', value: '{{now}}' },
              { key: 'event', value: 'triggered' }
            ],
            accountEmail: '',
            oauthConnectionScope: '',
            oauthConnectionId: ''
          },
          timeout: 5000,
          retries: 0,
          stopOnError: true
        }
      }
    ]
    const edges = [
      {
        id: 'e1',
        source: 'trigger-1',
        target: 'action-1',
        type: 'nodeEdge',
        data: { edgeType: 'default' }
      }
    ]
    return { nodes, edges }
  })

  const codeHttpTemplate = buildTemplateHandler(() => {
    const nodes = [
      {
        id: 'trigger-1',
        type: 'trigger',
        position: { x: 60, y: 120 },
        data: {
          label: 'Trigger',
          expanded: true,
          inputs: [],
          triggerType: 'Manual'
        }
      },
      {
        id: 'action-1',
        type: 'actionCode',
        position: { x: 280, y: 80 },
        data: {
          label: 'Run Code',
          expanded: true,
          inputs: [],
          labelError: null,
          hasLabelValidationError: false,
          actionType: 'code',
          params: {
            code: '// transform inputs here\n// inputs available in scope: context\n// return an object to pass to next node',
            inputs: [],
            outputs: []
          },
          timeout: 5000,
          retries: 0,
          stopOnError: true
        }
      },
      {
        id: 'action-2',
        type: 'actionHttp',
        position: { x: 500, y: 120 },
        data: {
          label: 'HTTP Request',
          expanded: true,
          inputs: [],
          labelError: null,
          hasLabelValidationError: false,
          actionType: 'http',
          params: {
            method: 'GET',
            url: 'https://api.example.com/resource',
            headers: [],
            queryParams: [],
            bodyType: 'raw',
            body: '',
            formBody: [],
            authType: 'none',
            authUsername: '',
            authPassword: '',
            authToken: ''
          },
          timeout: 5000,
          retries: 0,
          stopOnError: true
        }
      }
    ]
    const edges = [
      {
        id: 'e1',
        source: 'trigger-1',
        target: 'action-1',
        type: 'nodeEdge',
        data: { edgeType: 'default' }
      },
      {
        id: 'e2',
        source: 'action-1',
        target: 'action-2',
        type: 'nodeEdge',
        data: { edgeType: 'default' }
      }
    ]
    return { nodes, edges }
  })

  const conditionBranchTemplate = buildTemplateHandler(() => {
    const nodes = [
      {
        id: 'trigger-1',
        type: 'trigger',
        position: { x: 40, y: 120 },
        data: {
          label: 'Trigger',
          expanded: true,
          inputs: [],
          triggerType: 'Manual'
        }
      },
      {
        id: 'cond-1',
        type: 'condition',
        position: { x: 260, y: 120 },
        data: {
          label: 'If price > 100',
          expanded: true,
          field: 'price',
          operator: 'greater than',
          value: '100'
        }
      },
      {
        id: 'action-true',
        type: 'actionEmail',
        position: { x: 520, y: 60 },
        data: {
          label: 'Send Email (High)',
          expanded: true,
          inputs: [],
          labelError: null,
          hasLabelValidationError: false,
          actionType: 'email',
          params: {
            service: 'SMTP',
            from: '',
            to: '',
            subject: 'High price detected',
            body: 'Price exceeded threshold.'
          },
          timeout: 5000,
          retries: 0,
          stopOnError: true
        }
      },
      {
        id: 'action-false',
        type: 'actionSlack',
        position: { x: 520, y: 180 },
        data: {
          label: 'Slack Notify (Low)',
          expanded: true,
          inputs: [],
          labelError: null,
          hasLabelValidationError: false,
          actionType: 'slack',
          params: {
            channel: '#alerts',
            message: 'Price within normal range',
            token: '',
            connectionScope: '',
            connectionId: '',
            accountEmail: ''
          },
          timeout: 5000,
          retries: 0,
          stopOnError: true
        }
      }
    ]
    const edges = [
      {
        id: 'e1',
        source: 'trigger-1',
        target: 'cond-1',
        type: 'nodeEdge',
        data: { edgeType: 'default' }
      },
      {
        id: 'e2',
        source: 'cond-1',
        sourceHandle: 'cond-true',
        target: 'action-true',
        type: 'nodeEdge',
        data: { edgeType: 'default', outcome: 'true' },
        label: 'True'
      },
      {
        id: 'e3',
        source: 'cond-1',
        sourceHandle: 'cond-false',
        target: 'action-false',
        type: 'nodeEdge',
        data: { edgeType: 'default', outcome: 'false' },
        label: 'False'
      }
    ]
    return { nodes, edges }
  })

  return (
    <div className="flex flex-col h-[calc(100vh-4rem)] min-h-0">
      {/* Header moved to DashboardLayout */}
      {planTier === 'solo' && (
        <div className="space-y-3">
          <div className="rounded-lg border border-amber-200 bg-amber-50 p-4 text-sm text-amber-900 shadow-sm dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-100">
            {planUsageError ? (
              <p>{planUsageError}</p>
            ) : (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span>
                    {runsLimit
                      ? `You have ${(runsRemaining != null ? runsRemaining : runsLimit).toLocaleString()} runs remaining this month (${runsUsed.toLocaleString()} of ${runsLimit.toLocaleString()} used).`
                      : `You have used ${runsUsed.toLocaleString()} runs this month.`}
                  </span>
                  <button
                    type="button"
                    onClick={openPlanSettings}
                    className="rounded-md border border-amber-400 px-2 py-1 text-xs font-semibold uppercase tracking-wide text-amber-800 transition hover:bg-amber-100 dark:border-amber-400/60 dark:text-amber-100 dark:hover:bg-amber-400/10"
                  >
                    Upgrade
                  </button>
                </div>
                <div className="h-2 w-full overflow-hidden rounded bg-amber-100 dark:bg-amber-500/20">
                  <div
                    className="h-full rounded bg-amber-500 transition-all duration-300 dark:bg-amber-300"
                    style={{ width: `${runsPercent ?? 0}%` }}
                  />
                </div>
                <div className="flex items-center justify-between text-xs text-amber-700 dark:text-amber-200/80">
                  <span>Hidden workflows: {hiddenWorkflowCount}</span>
                  <span>Manual & webhook triggers only on the solo plan.</span>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
      <div className="flex h-full min-h-0">
        <aside className="w-64 border-r border-zinc-200 dark:border-zinc-700 p-4 bg-zinc-50 dark:bg-zinc-900 h-full overflow-hidden">
          <div className="flex h-full flex-col">
            <h2 className="font-semibold mb-3 text-zinc-700 dark:text-zinc-200">
              Tasks
            </h2>
            <div className="flex-1 min-h-0 overflow-y-auto themed-scroll space-y-3 pr-1">
              <DraggableTile
                label="Trigger"
                description="Start your flow"
                icon={<TriggerIcon />}
                gradient="from-emerald-500 to-teal-600"
                dragType="trigger"
                onQuickAdd={handlePaletteQuickAdd}
              />
              <DraggableTile
                label="Condition"
                description="Branch logic"
                icon={<ConditionIcon />}
                gradient="from-amber-500 to-orange-600"
                dragType="condition"
                onQuickAdd={handlePaletteQuickAdd}
              />
              <h3 className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mt-1">
                Actions
              </h3>
              <div className="relative mb-2">
                <span className="pointer-events-none absolute inset-y-0 left-2 flex items-center text-zinc-400">
                  <Search className="h-4 w-4" />
                </span>
                <input
                  type="text"
                  value={actionSearch}
                  onChange={(e) => setActionSearch(e.target.value)}
                  placeholder="Search actions..."
                  className="w-full rounded-lg border border-zinc-300 bg-white pl-8 pr-2 py-1.5 text-sm text-zinc-800 placeholder-zinc-400 shadow-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 dark:border-zinc-700 dark:bg-zinc-800 dark:text-zinc-100"
                />
              </div>
              {filteredGroups.length === 0 ? (
                <p className="text-xs text-zinc-500 dark:text-zinc-400">
                  No actions match your search.
                </p>
              ) : null}
              {filteredGroups.map((group) => {
                const searching = trimmedQuery.length > 0
                const isOpen = searching
                  ? true
                  : (openGroups[group.heading] ?? true)
                return (
                  <div key={group.heading} className="space-y-2">
                    <button
                      type="button"
                      onClick={() =>
                        setOpenGroups((prev) => ({
                          ...prev,
                          [group.heading]: !(prev[group.heading] ?? true)
                        }))
                      }
                      aria-expanded={isOpen}
                      className="w-full flex items-center justify-between text-left text-xs font-semibold uppercase tracking-wide text-zinc-600 dark:text-zinc-400 hover:text-zinc-800 dark:hover:text-zinc-200"
                    >
                      <span>{group.heading}</span>
                      {isOpen ? (
                        <ChevronUp className="h-3.5 w-3.5" />
                      ) : (
                        <ChevronDown className="h-3.5 w-3.5" />
                      )}
                    </button>
                    {isOpen ? (
                      <div className="space-y-2">
                        {group.tiles.map((tile) => (
                          <DraggableTile
                            key={tile.id}
                            {...tile}
                            onQuickAdd={handlePaletteQuickAdd}
                          />
                        ))}
                      </div>
                    ) : null}
                  </div>
                )
              })}
            </div>
            <div className="mt-4">
              <button
                type="button"
                onClick={() => setTemplatesOpen((v) => !v)}
                className={`w-full text-left px-3 py-2 rounded-lg border shadow-sm flex items-center justify-between ${
                  isGraphEmpty
                    ? 'bg-white dark:bg-zinc-800 hover:bg-zinc-100 dark:hover:bg-zinc-700'
                    : 'bg-zinc-100 dark:bg-zinc-800/60 text-zinc-400'
                }`}
                title={
                  isGraphEmpty
                    ? 'Browse templates'
                    : templatesOpen
                      ? 'Hide templates'
                      : 'Templates are disabled when the canvas is not empty'
                }
              >
                <span className="text-sm font-medium">Templates</span>
                <span className="text-xs text-zinc-500">
                  {templatesOpen ? 'Hide' : 'Show'}
                </span>
              </button>
              {templatesOpen && (
                <div
                  className={`mt-2 max-h-64 overflow-auto themed-scroll pr-1 space-y-2 ${isGraphEmpty ? '' : 'opacity-60'}`}
                >
                  <TemplateButton
                    label="SendGrid Email"
                    description="Send via SendGrid"
                    disabled={!canEditCurrentWorkflow || !isGraphEmpty}
                    onClick={sendGridTemplate}
                    onQuickAdd={sendGridTemplate}
                  />
                  <TemplateButton
                    label="Amazon SES Email"
                    description="Send via Amazon SES"
                    disabled={!canEditCurrentWorkflow || !isGraphEmpty}
                    onClick={amazonSesTemplate}
                    onQuickAdd={amazonSesTemplate}
                  />
                  <TemplateButton
                    label="Mailgun Email"
                    description="Send via Mailgun"
                    disabled={!canEditCurrentWorkflow || !isGraphEmpty}
                    onClick={mailgunTemplate}
                    onQuickAdd={mailgunTemplate}
                  />
                  <TemplateButton
                    label="Messaging"
                    description="Send a message (Chat)"
                    disabled={!canEditCurrentWorkflow || !isGraphEmpty}
                    onClick={messagingTemplate}
                    onQuickAdd={messagingTemplate}
                  />
                  <TemplateButton
                    label="Google Sheets Append"
                    description="Append a row on trigger"
                    disabled={!canEditCurrentWorkflow || !isGraphEmpty}
                    onClick={sheetsTemplate}
                    onQuickAdd={sheetsTemplate}
                  />
                  <TemplateButton
                    label="Run Code + HTTP"
                    description="Process then call an API"
                    disabled={!canEditCurrentWorkflow || !isGraphEmpty}
                    onClick={codeHttpTemplate}
                    onQuickAdd={codeHttpTemplate}
                  />
                  <TemplateButton
                    label="Branch by Condition"
                    description="Split flow into two paths"
                    disabled={!canEditCurrentWorkflow || !isGraphEmpty}
                    onClick={conditionBranchTemplate}
                    onQuickAdd={conditionBranchTemplate}
                  />
                </div>
              )}
            </div>
          </div>
        </aside>

        <div className="flex-1 min-h-0 flex flex-col bg-zinc-50 dark:bg-zinc-900">
          <WorkflowToolbar
            workflow={toolbarWorkflow}
            role={workspaceRole}
            canEdit={canEditCurrentWorkflow}
            canLock={canLockWorkflow}
            canUnlock={canUnlockWorkflow}
            isLocked={isLocked}
            lockBusy={lockBusy}
            onLock={handleLockWorkflow}
            onUnlock={handleUnlockWorkflow}
            onSave={handleSave}
            onNew={handleNewWorkflow}
            onSelect={selectWorkflow}
            onRename={renameWorkflow}
            runStatus={toolbarRunStatus}
            onToggleOverlay={handleToggleRunOverlay}
          />

          {/* Designer tab label with Runs drawer trigger */}
          <div className="px-3 pt-2 border-b border-zinc-200 dark:border-zinc-800 bg-white/70 dark:bg-zinc-900/70 backdrop-blur">
            <div className="flex items-center gap-2">
              <div className="px-3 py-1.5 text-sm rounded-t bg-white dark:bg-zinc-900 border border-b-0 border-zinc-200 dark:border-zinc-700 text-zinc-900 dark:text-zinc-50">
                Designer
              </div>
              <div className="flex items-center gap-2">
                <button
                  className={`inline-flex items-center gap-1 px-3 py-1.5 text-sm rounded-t border border-b-0 border-zinc-200 dark:border-zinc-700 ${
                    runsDrawerOpen
                      ? 'bg-white dark:bg-zinc-900 text-zinc-900 dark:text-zinc-50'
                      : 'bg-white dark:bg-zinc-900 text-zinc-500 dark:text-zinc-400 hover:bg-zinc-100 dark:hover:bg-zinc-800'
                  }`}
                  onClick={() => setRunsDrawerOpen((open) => !open)}
                  aria-pressed={runsDrawerOpen}
                  title="Open runs panel"
                >
                  Runs
                </button>
              </div>
            </div>
          </div>

          {remoteUpdate && (
            <div className="px-4 py-2 text-sm bg-amber-50 dark:bg-amber-950/30 border-b border-amber-200 dark:border-amber-800 text-amber-900 dark:text-amber-100 flex flex-wrap items-center gap-2">
              <span className="font-semibold">
                {remoteUpdate.reason === 'conflict'
                  ? 'Save blocked by a newer version.'
                  : 'Latest changes are available.'}
              </span>
              <span className="text-amber-800 dark:text-amber-200">
                {isDirty
                  ? 'Reloading will replace your unsaved edits.'
                  : 'Reload to stay in sync.'}
              </span>
              <div className="flex items-center gap-2 ml-auto">
                <button
                  className="px-3 py-1 text-xs rounded bg-amber-600 text-white hover:bg-amber-700"
                  onClick={() => applyRemoteWorkflow(remoteUpdate.workflow)}
                >
                  Reload latest
                </button>
                <button
                  className="px-3 py-1 text-xs rounded border border-amber-300 dark:border-amber-700 text-amber-900 dark:text-amber-100"
                  onClick={() => setRemoteUpdate(null)}
                >
                  Dismiss
                </button>
              </div>
            </div>
          )}

          {error && (
            <div className="px-4 py-2 text-sm text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-950/40 border-b border-red-200 dark:border-red-900">
              {error}
            </div>
          )}

          {(runLimitReached || runLimitApproaching) && (
            <div className="px-4 pt-2">
              <QuotaBanner
                variant={runLimitReached ? 'danger' : 'warning'}
                title={runLimitBannerTitle}
                description={runLimitBannerDescription}
                actionLabel="Manage plan"
                onAction={openPlanSettings}
              />
            </div>
          )}
          <div className="flex-1 min-h-0 flex">
            <ReactFlowProvider>
              <div className="flex-1 min-h-0 flex relative overflow-hidden">
                <div className="flex-1 min-h-0 flex">
                  {currentWorkflow ? (
                    <FlowCanvas
                      workflowId={currentWorkflow.id}
                      canEdit={canEditCurrentWorkflow}
                      onRunWorkflow={handleRunWorkflow}
                      runningIds={runningIds}
                      succeededIds={succeededIds}
                      failedIds={failedIds}
                      planTier={planTier}
                      runAvailability={runAvailability}
                      onRegisterQuickAdd={registerPaletteQuickAdd}
                      onRestrictionNotice={(message: string) =>
                        setError(message)
                      }
                    />
                  ) : (
                    <div className="m-auto text-sm text-zinc-500 dark:text-zinc-400">
                      {loadingWorkflows
                        ? 'Loading workflows...'
                        : 'Create a workflow to get started.'}
                    </div>
                  )}
                </div>

                {/* Runs bottom bar */}
                <div
                  className={`absolute left-0 right-0 bottom-0 z-10 w-full max-w-full bg-white dark:bg-zinc-900 border-t border-zinc-200 dark:border-zinc-800 shadow-2xl transition-transform duration-200 ease-in-out ${
                    runsDrawerOpen
                      ? 'translate-y-0'
                      : 'translate-y-full pointer-events-none'
                  }`}
                >
                  <div className="h-[42vh] max-h-[50vh] flex flex-col overflow-hidden">
                    <div className="flex items-center gap-2 border-b border-zinc-200 dark:border-zinc-800 px-4 py-2">
                      <div className="flex-1">
                        <h3 className="text-sm font-semibold">Runs</h3>
                        <p className="text-xs text-zinc-500 dark:text-zinc-400">
                          Live queue and status
                        </p>
                      </div>
                      <div className="flex items-center gap-2 text-xs">
                        <span className="text-zinc-500">Scope:</span>
                        <select
                          value={runsScope}
                          onChange={(e) =>
                            setRunsScope((e.target.value as any) ?? 'current')
                          }
                          className="px-2 py-1 border rounded bg-white dark:bg-zinc-800 dark:border-zinc-700"
                        >
                          <option value="current">Current workflow</option>
                          <option value="all">All workflows</option>
                        </select>
                      </div>
                      <button
                        className="ml-2 text-xs px-2 py-1 rounded border hover:bg-zinc-100 dark:hover:bg-zinc-800"
                        onClick={() => setRunsDrawerOpen(false)}
                      >
                        Close
                      </button>
                    </div>
                    <div className="flex-1 overflow-auto themed-scroll p-4">
                      {runQueue.length === 0 ? (
                        <div className="text-sm text-zinc-500 dark:text-zinc-400">
                          No queued or running jobs.
                        </div>
                      ) : (
                        <div className="space-y-2">
                          {runQueue.map((run) => {
                            const wf = workflows.find(
                              (w) => w.id === run.workflow_id
                            )
                            const canCancel =
                              run.status === 'queued' ||
                              run.status === 'running'
                            return (
                              <div
                                key={run.id}
                                className="flex items-center justify-between border rounded p-2 bg-white dark:bg-zinc-900 border-zinc-200 dark:border-zinc-700"
                              >
                                <div className="flex items-center gap-3">
                                  <span className="px-2 py-0.5 text-xs rounded bg-zinc-100 dark:bg-zinc-800 border border-zinc-200 dark:border-zinc-700">
                                    {run.status}
                                  </span>
                                  <div>
                                    <div className="text-sm font-medium">
                                      {wf?.name || run.workflow_id}
                                    </div>
                                    <div className="text-xs text-zinc-500">
                                      Started{' '}
                                      {new Date(
                                        run.started_at
                                      ).toLocaleString()}
                                    </div>
                                  </div>
                                </div>
                                <div className="flex items-center gap-2">
                                  {canCancel && (
                                    <button
                                      className="text-xs px-2 py-1 rounded border hover:bg-zinc-100 dark:hover:bg-zinc-800"
                                      onClick={async () => {
                                        try {
                                          await cancelRun(
                                            run.workflow_id,
                                            run.id
                                          )
                                          await fetchRunQueue()
                                        } catch (e) {
                                          console.error(
                                            'Failed to cancel run',
                                            e
                                          )
                                        }
                                      }}
                                    >
                                      Cancel
                                    </button>
                                  )}
                                </div>
                              </div>
                            )
                          })}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            </ReactFlowProvider>
          </div>
        </div>
      </div>

      {/* Settings modal moved to DashboardLayout */}

      {/* Run overlay */}
      {runOverlayOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div
            className="absolute inset-0 bg-black/40"
            onClick={() => {
              setRunOverlayOpen(false)
            }}
          />
          <div className="relative bg-white dark:bg-zinc-900 rounded-xl shadow-xl w-[560px] max-h-[70vh] p-4 border border-zinc-200 dark:border-zinc-700 overflow-hidden">
            <div className="flex justify-between items-center mb-3">
              <h3 className="font-semibold">Run Status</h3>
              <button
                className="text-sm px-2 py-1 border rounded"
                onClick={() => {
                  setRunOverlayOpen(false)
                }}
              >
                Close
              </button>
            </div>
            {!activeRun ||
            (currentWorkflow && activeRun.workflow_id !== currentWorkflow.id) ||
            (activeRun &&
              activeRun.status !== 'running' &&
              activeRun.status !== 'queued') ? (
              <p className="text-sm text-zinc-600 dark:text-zinc-300">
                No active run for selected workflow.
              </p>
            ) : (
              <div className="space-y-2 text-sm relative">
                {runToast && (
                  <div className="absolute top-0 right-0 translate-y-[-8px] text-xs px-2 py-1 rounded bg-zinc-100 dark:bg-zinc-800 border border-zinc-200 dark:border-zinc-700 shadow-sm">
                    {runToast}
                  </div>
                )}
                <div className="flex gap-2 items-center">
                  <span className="font-medium">Status:</span>
                  <span className="px-2 py-0.5 rounded bg-zinc-100 dark:bg-zinc-800">
                    {activeRun.status}
                  </span>
                  {activeRun.error && (
                    <span className="text-red-600 dark:text-red-400">
                      {activeRun.error}
                    </span>
                  )}
                  {(activeRun.status === 'queued' ||
                    activeRun.status === 'running') &&
                    currentWorkflow && (
                      <button
                        className="ml-2 text-xs px-2 py-0.5 rounded border"
                        disabled={cancelBusy}
                        onClick={async () => {
                          try {
                            setCancelBusy(true)
                            await cancelRun(currentWorkflow.id, activeRun.id)
                            setRunToast('Cancel requested…')
                            setTimeout(() => setRunToast(null), 2000)
                          } finally {
                            setCancelBusy(false)
                          }
                        }}
                      >
                        {cancelBusy ? 'Canceling…' : 'Cancel'}
                      </button>
                    )}
                </div>
                <div className="border rounded p-2 h-[42vh] overflow-auto themed-scroll bg-zinc-50 dark:bg-zinc-950/40">
                  {nodeRuns.length === 0 ? (
                    <div className="text-zinc-500">No node events yet…</div>
                  ) : (
                    nodeRuns.map((nr) => (
                      <div
                        key={nr.id}
                        className="mb-2 border-b pb-2 last:border-b-0"
                      >
                        <div className="flex gap-2 items-center">
                          <span className="font-medium">
                            {nr.name || nr.node_type || nr.node_id}
                          </span>
                          <span className="px-2 py-0.5 rounded bg-zinc-100 dark:bg-zinc-800">
                            {nr.status}
                          </span>
                          {nr.error && (
                            <span className="text-red-600 dark:text-red-400">
                              {nr.error}
                            </span>
                          )}
                        </div>
                        {nr.outputs && (
                          <pre className="mt-1 text-xs whitespace-pre-wrap break-words bg-white/60 dark:bg-black/30 p-2 rounded">
                            {JSON.stringify(nr.outputs, null, 2)}
                          </pre>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
