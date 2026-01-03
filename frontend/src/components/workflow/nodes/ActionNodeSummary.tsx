import { useMemo } from 'react'

import NodeFlyoutSurface from '../NodeFlyoutSurface'
import { useActionMeta, useActionParams } from '@/stores/workflowSelectors'

type SummaryItem = {
  label: string
  value: string
}

interface ActionNodeSummaryProps {
  nodeId: string
  planRestrictionMessage?: string | null
  onPlanUpgrade?: () => void
  hint?: string
  summaryItems?: SummaryItem[]
}

export default function ActionNodeSummary({
  nodeId,
  planRestrictionMessage,
  onPlanUpgrade,
  hint = 'Configure this action in the flyout.',
  summaryItems
}: ActionNodeSummaryProps) {
  const meta = useActionMeta(nodeId)
  const params = useActionParams<Record<string, unknown>>(
    nodeId,
    meta.actionType
  )

  const computedSummaryItems = useMemo(
    () => buildSummaryItems(meta.actionType, params),
    [meta.actionType, params]
  )

  const resolvedSummaryItems =
    summaryItems === undefined ? computedSummaryItems : summaryItems

  return (
    <div className="mt-2 space-y-2 text-xs text-zinc-600 dark:text-zinc-300">
      {planRestrictionMessage ? (
        <div className="rounded-lg border border-amber-300 bg-amber-50 p-3 text-amber-900 shadow-sm dark:border-amber-400/60 dark:bg-amber-500/10 dark:text-amber-100">
          <div className="flex items-start justify-between gap-2">
            <span>{planRestrictionMessage}</span>
            {onPlanUpgrade ? (
              <button
                type="button"
                onClick={onPlanUpgrade}
                className="rounded border border-amber-400 px-2 py-1 text-[10px] font-semibold uppercase tracking-wide text-amber-800 transition hover:bg-amber-100 dark:border-amber-400/60 dark:text-amber-100 dark:hover:bg-amber-400/10"
              >
                Upgrade
              </button>
            ) : null}
          </div>
        </div>
      ) : null}

      <NodeFlyoutSurface nodeId={nodeId}>
        {resolvedSummaryItems.length > 0 ? (
          <div className="space-y-2">
            <div className="space-y-1 text-[11px] text-zinc-700 dark:text-zinc-200">
              {resolvedSummaryItems.map((item) => (
                <div
                  key={`${item.label}-${item.value}`}
                  className="flex items-start gap-2"
                >
                  <span className="shrink-0 font-semibold text-zinc-600 dark:text-zinc-300">
                    {item.label}
                  </span>
                  <span
                    className="min-w-0 flex-1 text-right text-zinc-900 dark:text-zinc-100 truncate"
                    title={item.value}
                  >
                    {item.value}
                  </span>
                </div>
              ))}
            </div>
            <p className="text-[10px] text-zinc-500 dark:text-zinc-400">
              {hint}
            </p>
          </div>
        ) : (
          <p>{hint}</p>
        )}
      </NodeFlyoutSurface>
    </div>
  )
}

const MAX_SUMMARY_LENGTH = 72
const MAX_MESSAGE_LENGTH = 96

const isRecord = (value: unknown): value is Record<string, unknown> =>
  Boolean(value) && typeof value === 'object' && !Array.isArray(value)

const toStringValue = (value: unknown) =>
  typeof value === 'string' ? value.trim() : ''

const toCompactText = (value: string) => value.replace(/\s+/g, ' ').trim()

const truncateText = (value: string, maxLength: number) => {
  if (value.length <= maxLength) return value
  if (maxLength <= 3) return value.slice(0, maxLength)
  return `${value.slice(0, maxLength - 3)}...`
}

const normalizeSummaryText = (
  value: unknown,
  maxLength = MAX_SUMMARY_LENGTH
) => {
  const compact = toCompactText(toStringValue(value))
  return compact ? truncateText(compact, maxLength) : ''
}

const normalizeMessagePreview = (value: unknown) =>
  normalizeSummaryText(value, MAX_MESSAGE_LENGTH)

const pickNestedParams = (params: Record<string, unknown>, keys: string[]) => {
  for (const key of keys) {
    const candidate = params[key]
    if (isRecord(candidate)) {
      return candidate
    }
  }
  return params
}

const formatRecipients = (value: string) => {
  const recipients = value
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean)
  if (recipients.length === 0) return ''
  if (recipients.length === 1) return recipients[0]
  return `${recipients[0]} (+${recipients.length - 1} more)`
}

const formatOperationLabel = (value: string) => {
  if (!value) return ''
  const spaced = value
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[_-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
  return spaced
    .split(' ')
    .map((segment) =>
      segment.length > 0
        ? `${segment[0].toUpperCase()}${segment.slice(1)}`
        : segment
    )
    .join(' ')
}

const buildSummaryItems = (
  actionType: string,
  params: Record<string, unknown>
): SummaryItem[] => {
  if (!isRecord(params)) return []
  const items: SummaryItem[] = []

  const addItem = (label: string, value: string) => {
    if (!value) return
    items.push({ label, value })
  }

  switch (actionType) {
    case 'http': {
      const url = normalizeSummaryText(params.url)
      if (!url) break
      addItem('Method', normalizeSummaryText(params.method, 12).toUpperCase())
      addItem('URL', url)
      break
    }
    case 'sheets': {
      addItem('Spreadsheet', normalizeSummaryText(params.spreadsheetId))
      addItem('Worksheet', normalizeSummaryText(params.worksheet))
      const columns = Array.isArray(params.columns) ? params.columns.length : 0
      if (columns > 0) {
        addItem('Columns', `${columns}`)
      }
      break
    }
    case 'slack': {
      const slackParams = pickNestedParams(params, ['Slack', 'slack'])
      const identityRaw = toStringValue(slackParams.identity)
      const identity =
        identityRaw === 'workspace_bot'
          ? 'Workspace bot'
          : identityRaw === 'personal_user'
            ? 'Post as you'
            : ''
      addItem('Identity', identity)
      addItem('Channel', normalizeSummaryText(slackParams.channel))
      addItem('Message', normalizeMessagePreview(slackParams.message))
      break
    }
    case 'teams': {
      const teamsParams = pickNestedParams(params, ['Teams', 'teams'])
      const delivery = normalizeSummaryText(teamsParams.deliveryMethod, 36)
      addItem('Delivery', delivery)
      const isIncoming =
        delivery.toLowerCase().includes('incoming') ||
        delivery.toLowerCase().includes('webhook')
      if (isIncoming) {
        addItem('Webhook', normalizeSummaryText(teamsParams.webhookUrl))
      } else {
        const team =
          normalizeSummaryText(teamsParams.teamName) ||
          normalizeSummaryText(teamsParams.teamId)
        const channel =
          normalizeSummaryText(teamsParams.channelName) ||
          normalizeSummaryText(teamsParams.channelId)
        const destination = [team, channel].filter(Boolean).join(' / ')
        addItem('Channel', destination)
      }
      const message =
        normalizeMessagePreview(teamsParams.message) ||
        normalizeMessagePreview(teamsParams.cardBody)
      if (message) {
        addItem('Message', message)
      } else if (toStringValue(teamsParams.cardJson)) {
        addItem('Payload', 'Card JSON')
      } else if (toStringValue(teamsParams.workflowRawJson)) {
        addItem('Payload', 'Workflow JSON')
      }
      break
    }
    case 'googlechat': {
      const chatParams = pickNestedParams(params, [
        'Google Chat',
        'GoogleChat',
        'googleChat'
      ])
      addItem('Webhook', normalizeSummaryText(chatParams.webhookUrl))
      const message = normalizeMessagePreview(chatParams.message)
      if (message) {
        addItem('Message', message)
      } else if (toStringValue(chatParams.cardJson)) {
        addItem('Payload', 'Card JSON')
      }
      break
    }
    case 'email': {
      const to = toStringValue(params.to)
      const recipients = formatRecipients(to)
      addItem('To', normalizeSummaryText(recipients))
      const templateId = normalizeSummaryText(params.templateId)
      if (templateId) {
        addItem('Template', templateId)
      } else {
        addItem('Subject', normalizeSummaryText(params.subject))
      }
      if (!recipients) {
        addItem('From', normalizeSummaryText(params.from))
      }
      break
    }
    case 'code': {
      const code = toStringValue(params.code)
      const inputs = Array.isArray(params.inputs) ? params.inputs.length : 0
      const outputs = Array.isArray(params.outputs) ? params.outputs.length : 0
      if (!code && inputs === 0 && outputs === 0) break
      addItem(
        'Inputs',
        inputs > 0 ? `${inputs} input${inputs === 1 ? '' : 's'}` : 'None'
      )
      addItem(
        'Outputs',
        outputs > 0 ? `${outputs} output${outputs === 1 ? '' : 's'}` : 'None'
      )
      break
    }
    case 'asana': {
      const operation = toStringValue(params.operation)
      addItem('Operation', formatOperationLabel(operation))
      const project =
        normalizeSummaryText(params.projectSelection) ||
        normalizeSummaryText(params.projectGid)
      const task =
        normalizeSummaryText(params.taskSelection) ||
        normalizeSummaryText(params.taskGid) ||
        normalizeSummaryText(params.name)
      const workspace = normalizeSummaryText(params.workspaceGid)
      if (project) {
        addItem('Project', project)
      } else if (workspace) {
        addItem('Workspace', workspace)
      }
      if (task) {
        addItem('Task', task)
      }
      break
    }
    case 'notion': {
      const operation = toStringValue(params.operation)
      addItem('Operation', formatOperationLabel(operation))
      const database =
        normalizeSummaryText(params.databaseId) ||
        normalizeSummaryText(params.parentDatabaseId)
      const page =
        normalizeSummaryText(params.pageId) ||
        normalizeSummaryText(params.parentPageId)
      const title = normalizeSummaryText(params.title)
      if (database) addItem('Database', database)
      if (page) addItem('Page', page)
      if (title) addItem('Title', title)
      break
    }
    default:
      break
  }

  return items
}
