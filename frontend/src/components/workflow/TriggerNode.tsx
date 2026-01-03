import { useState, useMemo, useEffect, useRef, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Handle, Position } from '@xyflow/react'
import { formatDisplayDate, formatDisplayTime } from '../ui/schedule/utils'
import BaseNode, { type BaseNodeRenderProps } from './BaseNode'
import NodeHeader from '@/components/ui/ReactFlow/NodeHeader'
import NodeFlyoutSurface from './NodeFlyoutSurface'
import { normalizePlanTier } from '@/lib/planTiers'
import { errorMessage } from '@/lib/errorMessage'
import { useWorkflowStore, type WorkflowState } from '@/stores/workflowStore'
import type { RunAvailability } from '@/types/runAvailability'

const SCHEDULE_RESTRICTION_MESSAGE =
  'Scheduled triggers are available on workspace plans and above. Switch this trigger to Manual or Webhook to keep running on the solo plan.'
const NOTION_TRIGGER_RESTRICTION_MESSAGE =
  'Notion triggers are available on workspace plans and above. Upgrade in Settings > Plan to keep polling Notion.'

const repeatUnits = ['minutes', 'hours', 'days', 'weeks'] as const

type RepeatUnit = (typeof repeatUnits)[number]

type ScheduleConfig = {
  startDate: string
  startTime: string
  timezone: string
  repeat?: {
    every: number
    unit: RepeatUnit
  }
}

function normalizeScheduleConfig(
  value: any,
  fallbackTimezone: string
): ScheduleConfig {
  const startDate = typeof value?.startDate === 'string' ? value.startDate : ''
  const startTime = typeof value?.startTime === 'string' ? value.startTime : ''
  const timezone =
    typeof value?.timezone === 'string' && value.timezone.trim().length > 0
      ? value.timezone
      : fallbackTimezone

  let repeat: ScheduleConfig['repeat']
  if (value && typeof value === 'object' && value.repeat) {
    const rawEvery = Number(value.repeat?.every)
    if (Number.isFinite(rawEvery) && rawEvery > 0) {
      const candidate =
        typeof value.repeat?.unit === 'string'
          ? value.repeat.unit.toLowerCase()
          : 'days'
      const unit: RepeatUnit = repeatUnits.includes(candidate as RepeatUnit)
        ? (candidate as RepeatUnit)
        : 'days'
      repeat = {
        every: Math.floor(rawEvery),
        unit
      }
    }
  }

  return {
    startDate,
    startTime,
    timezone,
    repeat
  }
}

type TriggerInput = {
  key: string
  value: string
}

export type TriggerNodeData = {
  id?: string
  label?: string
  expanded?: boolean
  inputs?: TriggerInput[]
  dirty?: boolean
  triggerType?: string
  event_type?: string
  scheduleConfig?: ScheduleConfig
  labelError?: string | null
  wfEpoch?: number
  hasValidationErrors?: boolean
}

interface TriggerNodeProps {
  id: string
  selected: boolean
  onRun?: (id: string, inputs: TriggerInput[]) => Promise<void>
  isRunning?: boolean
  isSucceeded?: boolean
  isFailed?: boolean
  planTier?: string | null
  onRestrictionNotice?: (message: string) => void
  canEdit?: boolean
  runAvailability?: RunAvailability
}

type TriggerNodeContentProps = BaseNodeRenderProps<TriggerNodeData> & {
  onRun?: (id: string, inputs: TriggerInput[]) => Promise<void>
  externalIsRunning?: boolean
  isSucceeded?: boolean
  isFailed?: boolean
  isSoloPlan: boolean
  onRestrictionNotice?: (message: string) => void
  defaultTimezone: string
  runAvailability?: RunAvailability
}

export default function TriggerNode({
  id,
  selected,
  onRun,
  isRunning,
  isSucceeded,
  isFailed,
  planTier,
  onRestrictionNotice,
  canEdit = true,
  runAvailability
}: TriggerNodeProps) {
  const selectNodeData = useMemo(
    () => (state: WorkflowState) =>
      state.nodes.find((node) => node.id === id)?.data as
        | TriggerNodeData
        | undefined,
    [id]
  )
  const nodeData = useWorkflowStore(selectNodeData)

  const normalizedPlanTier = useMemo(
    () => normalizePlanTier(planTier),
    [planTier]
  )
  const isSoloPlan = normalizedPlanTier === 'solo'

  const defaultTimezone = useMemo(() => {
    try {
      return new Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
    } catch {
      return 'UTC'
    }
  }, [])

  return (
    <BaseNode<TriggerNodeData>
      id={id}
      selected={selected}
      canEdit={canEdit}
      fallbackLabel="Trigger"
      defaultDirty={!nodeData}
    >
      {(renderProps) => (
        <TriggerNodeContent
          {...renderProps}
          onRun={onRun}
          externalIsRunning={isRunning}
          isSucceeded={isSucceeded}
          isFailed={isFailed}
          isSoloPlan={isSoloPlan}
          onRestrictionNotice={onRestrictionNotice}
          defaultTimezone={defaultTimezone}
          runAvailability={runAvailability}
        />
      )}
    </BaseNode>
  )
}

function TriggerNodeContent({
  id,
  selected,
  label,
  dirty,
  nodeData,
  updateData,
  remove,
  effectiveCanEdit,
  onRun,
  externalIsRunning,
  isSucceeded,
  isFailed,
  isSoloPlan,
  onRestrictionNotice,
  defaultTimezone,
  runAvailability
}: TriggerNodeContentProps) {
  const [confirmingDelete, setConfirmingDelete] = useState(false)
  const [running, setRunning] = useState(false)
  const lastPlanNoticeRef = useRef<string | null>(null)

  const rawInputs = nodeData?.inputs
  const inputs = useMemo<TriggerInput[]>(
    () =>
      Array.isArray(rawInputs)
        ? rawInputs.map((input) => ({
            key: input?.key ?? '',
            value: input?.value ?? ''
          }))
        : [],
    [rawInputs]
  )

  const triggerType =
    typeof nodeData?.triggerType === 'string' ? nodeData.triggerType : 'Manual'
  const normalizedTriggerType = useMemo(
    () => triggerType.trim().toLowerCase() || 'manual',
    [triggerType]
  )
  const webhookEventType =
    typeof nodeData?.event_type === 'string' ? nodeData.event_type : ''
  const webhookEventTypeMissing =
    normalizedTriggerType === 'webhook' && !webhookEventType.trim()

  const scheduleConfig = useMemo(
    () => normalizeScheduleConfig(nodeData?.scheduleConfig, defaultTimezone),
    [nodeData?.scheduleConfig, defaultTimezone]
  )

  const scheduleRestricted = isSoloPlan && normalizedTriggerType === 'schedule'
  const notionRestricted =
    isSoloPlan &&
    (normalizedTriggerType === 'notion.new_database_row' ||
      normalizedTriggerType === 'notion.updated_database_row')
  const restrictionMessage = scheduleRestricted
    ? SCHEDULE_RESTRICTION_MESSAGE
    : notionRestricted
      ? NOTION_TRIGGER_RESTRICTION_MESSAGE
      : null

  useEffect(() => {
    if (!onRestrictionNotice || !restrictionMessage) {
      lastPlanNoticeRef.current = null
      return
    }
    if (lastPlanNoticeRef.current === restrictionMessage) return
    lastPlanNoticeRef.current = restrictionMessage
    onRestrictionNotice(restrictionMessage)
  }, [restrictionMessage, onRestrictionNotice])

  const openPlanSettings = useCallback(() => {
    try {
      window.dispatchEvent(
        new CustomEvent('open-plan-settings', { detail: { tab: 'plan' } })
      )
    } catch (err) {
      console.error(errorMessage(err))
    }
  }, [])

  const hasInvalidInputs = useMemo(() => {
    if (inputs.length === 0) return false
    return inputs.some((input) => !input.key.trim() || !input.value.trim())
  }, [inputs])

  const hasDuplicateKeys = useMemo(() => {
    const keys = inputs.map((input) => input.key.trim()).filter(Boolean)
    return new Set(keys).size !== keys.length
  }, [inputs])

  const labelError = nodeData?.labelError ?? null

  const combinedHasValidationErrors =
    hasDuplicateKeys ||
    hasInvalidInputs ||
    webhookEventTypeMissing ||
    Boolean(labelError) ||
    scheduleRestricted ||
    notionRestricted

  useEffect(() => {
    if (!effectiveCanEdit) return
    if (
      (nodeData?.hasValidationErrors ?? false) === combinedHasValidationErrors
    ) {
      return
    }
    updateData({ hasValidationErrors: combinedHasValidationErrors })
  }, [
    combinedHasValidationErrors,
    effectiveCanEdit,
    nodeData?.hasValidationErrors,
    updateData
  ])

  const handleLabelChange = useCallback(
    (nextLabel: string) => {
      if (!effectiveCanEdit) return
      updateData({ label: nextLabel, dirty: true })
    },
    [effectiveCanEdit, updateData]
  )

  const handleConfirmDelete = useCallback(() => {
    if (!effectiveCanEdit) return
    setConfirmingDelete(true)
  }, [effectiveCanEdit])

  const runBlocked = Boolean(runAvailability?.disabled)
  const runBlockedReason =
    runAvailability?.reason ??
    'Workspace run quota reached. Upgrade in Settings → Plan to continue running workflows.'
  const handleRun = useCallback(async () => {
    if (runBlocked) return
    if (!onRun) return
    setRunning(true)
    try {
      await onRun(id, inputs)
    } finally {
      setRunning(false)
    }
  }, [id, inputs, onRun, runBlocked])

  const ringClass = isFailed
    ? 'ring-2 ring-red-500'
    : isSucceeded
      ? 'ring-2 ring-emerald-500'
      : externalIsRunning
        ? 'ring-2 ring-sky-500'
        : ''

  return (
    <motion.div
      className={`wf-node group relative rounded-2xl shadow-md border bg-white dark:bg-zinc-900 transition-all ${selected ? 'ring-2 ring-blue-500' : 'border-zinc-300 dark:border-zinc-700'} ${ringClass}`}
      style={{
        width: 256,
        minWidth: 256
      }}
    >
      <Handle
        type="source"
        position={Position.Right}
        style={{
          width: 14,
          height: 14,
          backgroundColor: 'green',
          border: '2px solid white'
        }}
      />
      <div className="p-3">
        <NodeHeader
          nodeId={id}
          label={label}
          dirty={dirty}
          hasValidationErrors={combinedHasValidationErrors}
          expanded={false}
          showExpandToggle={false}
          onLabelChange={handleLabelChange}
          onExpanded={() => undefined}
          onConfirmingDelete={(event) => {
            event.preventDefault()
            event.stopPropagation()
            handleConfirmDelete()
          }}
        />
        {labelError && (
          <p className="mt-2 text-xs text-red-500">{labelError}</p>
        )}
        <button
          onClick={handleRun}
          disabled={
            running ||
            combinedHasValidationErrors ||
            runBlocked ||
            typeof onRun !== 'function'
          }
          title={runBlocked ? runBlockedReason : undefined}
          className="mt-2 w-full py-1 text-sm rounded-md bg-green-500 text-white hover:bg-green-600 disabled:opacity-50"
        >
          {running ? 'Running...' : 'Run'}
        </button>

        {restrictionMessage ? (
          <div className="mt-3 rounded-lg border border-amber-300 bg-amber-50 p-3 text-xs text-amber-900 shadow-sm dark:border-amber-400/60 dark:bg-amber-500/10 dark:text-amber-100">
            <div className="flex items-start justify-between gap-2">
              <span>{restrictionMessage}</span>
              <button
                type="button"
                onClick={openPlanSettings}
                className="rounded border border-amber-400 px-2 py-1 text-[10px] font-semibold uppercase tracking-wide text-amber-800 transition hover:bg-amber-100 dark:border-amber-400/60 dark:text-amber-100 dark:hover:bg-amber-400/10"
              >
                Upgrade
              </button>
            </div>
          </div>
        ) : null}

        <div className="mt-3 space-y-2 text-xs text-zinc-600 dark:text-zinc-300">
          <div className="flex items-center justify-between">
            <span className="font-semibold text-zinc-700 dark:text-zinc-200">
              Type
            </span>
            <span className="text-zinc-900 dark:text-zinc-100">
              {triggerType}
            </span>
          </div>
          <NodeFlyoutSurface
            nodeId={id}
            hoverLabel="Click to edit this trigger"
            className="text-zinc-700 dark:text-zinc-200"
          >
            {normalizedTriggerType === 'schedule' ? (
              <>
                <p>
                  Start:{' '}
                  {scheduleConfig.startDate
                    ? formatDisplayDate(scheduleConfig.startDate)
                    : 'Not set'}
                </p>
                <p>
                  Time:{' '}
                  {scheduleConfig.startTime
                    ? formatDisplayTime(scheduleConfig.startTime)
                    : 'Not set'}
                </p>
                <p>Timezone: {scheduleConfig.timezone || 'Not set'}</p>
                {scheduleConfig.repeat ? (
                  <p>
                    Repeats every {scheduleConfig.repeat.every}{' '}
                    {scheduleConfig.repeat.unit}
                  </p>
                ) : null}
              </>
            ) : (
              <p className="text-zinc-700 dark:text-zinc-200">
                Configure this trigger in the flyout.
              </p>
            )}
          </NodeFlyoutSurface>
          <div className="flex items-center justify-between">
            <span className="font-semibold text-zinc-700 dark:text-zinc-200">
              Inputs
            </span>
            <span className="text-zinc-900 dark:text-zinc-100">
              {inputs.length
                ? `${inputs.length} variable${inputs.length === 1 ? '' : 's'}`
                : 'None'}
            </span>
          </div>
        </div>
      </div>

      <AnimatePresence>
        {confirmingDelete && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="absolute inset-0 flex items-center justify-center bg-black/50 rounded-2xl"
          >
            <div className="bg-white dark:bg-zinc-800 p-4 rounded-xl shadow-md w-56">
              <p className="text-sm mb-3">Delete this node?</p>
              <p className="text-sm mb-3">This action can not be undone</p>
              <div className="flex justify-end gap-2">
                <button
                  onClick={() => setConfirmingDelete(false)}
                  className="px-2 py-1 text-xs rounded border"
                >
                  Cancel
                </button>
                <button
                  onClick={() => {
                    setConfirmingDelete(false)
                    remove()
                  }}
                  className="px-2 py-1 text-xs rounded bg-red-500 text-white hover:bg-red-600"
                >
                  Delete
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  )
}
