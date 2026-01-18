import { normalizeEdge, reconcileNodeLabels } from '@/lib/workflowGraph'
import type { WorkflowEdge, WorkflowNode, WorkflowNodeData } from './FlowCanvas'

const ACTION_NODE_TYPE_ALIASES: Record<string, string> = {
  'action.email': 'actionEmail',
  actionemail: 'actionEmail',
  email: 'actionEmail',
  'action.messaging.slack': 'actionSlack',
  actionslack: 'actionSlack',
  slack: 'actionSlack',
  'action.messaging.teams': 'actionTeams',
  actionteams: 'actionTeams',
  teams: 'actionTeams',
  'action.googlechat': 'actionGoogleChat',
  actiongooglechat: 'actionGoogleChat',
  googlechat: 'actionGoogleChat',
  'google chat': 'actionGoogleChat',
  'action.sheets': 'actionSheets',
  actionsheets: 'actionSheets',
  sheets: 'actionSheets',
  'action.http': 'actionHttp',
  actionhttp: 'actionHttp',
  http: 'actionHttp',
  'action.code': 'actionCode',
  actioncode: 'actionCode',
  code: 'actionCode',
  delay: 'delay',
  logicdelay: 'delay',
  wait: 'delay',
  formatter: 'formatter',
  logicformatter: 'formatter',
  transform: 'formatter',
  'logic.formatter': 'formatter'
}

export type ManifestInputValue =
  | string
  | number
  | boolean
  | string[]
  | Record<string, unknown>
  | null

function normalizeNodeType(nodeType: unknown): string | undefined {
  if (typeof nodeType !== 'string') {
    return undefined
  }
  const trimmed = nodeType.trim()
  if (!trimmed) return trimmed
  const lowered = trimmed.toLowerCase()
  return ACTION_NODE_TYPE_ALIASES[lowered] ?? trimmed
}

export function cloneWorkflowData<T>(value: T): T {
  if (typeof globalThis.structuredClone === 'function') {
    return globalThis.structuredClone(value)
  }

  return JSON.parse(JSON.stringify(value))
}

export function normalizeEdgesForState(
  edges: ReadonlyArray<WorkflowEdge>
): WorkflowEdge[] {
  return edges.map((edge) => {
    const normalized = normalizeEdge(edge) as WorkflowEdge
    const data =
      normalized?.data && typeof normalized.data === 'object'
        ? cloneWorkflowData(normalized.data)
        : normalized.data

    return {
      ...normalized,
      // Preserve selection state so edge UI depending on `selected` works
      selected: Boolean(edge?.selected),
      data
    }
  })
}

export function normalizeNodesForState(
  nodes: ReadonlyArray<WorkflowNode>
): WorkflowNode[] {
  const normalizedNodes = nodes.map((node) => {
    const data =
      node?.data && typeof node.data === 'object'
        ? cloneWorkflowData(node.data)
        : node.data

    return {
      ...node,
      type: normalizeNodeType(node?.type),
      data
    }
  })

  return reconcileNodeLabels(normalizedNodes)
}

export function formatManifestInputValue(
  inputType: string,
  rawValue: unknown
): string | boolean {
  switch (inputType) {
    case 'boolean': {
      if (typeof rawValue === 'boolean') return rawValue
      if (typeof rawValue === 'string') {
        const lowered = rawValue.trim().toLowerCase()
        if (lowered === 'true') return true
        if (lowered === 'false') return false
      }
      return false
    }
    case 'number':
      if (typeof rawValue === 'number' && Number.isFinite(rawValue)) {
        return String(rawValue)
      }
      return typeof rawValue === 'string' ? rawValue : ''
    case 'string[]':
      if (Array.isArray(rawValue)) {
        return rawValue.map((value) => String(value)).join(', ')
      }
      return typeof rawValue === 'string' ? rawValue : ''
    case 'object':
      if (
        rawValue &&
        typeof rawValue === 'object' &&
        !Array.isArray(rawValue)
      ) {
        try {
          return JSON.stringify(rawValue, null, 2)
        } catch {
          return ''
        }
      }
      return typeof rawValue === 'string' ? rawValue : ''
    default:
      if (typeof rawValue === 'string') return rawValue
      if (rawValue == null) return ''
      return String(rawValue)
  }
}

export function parseManifestInputValue(
  inputType: string,
  rawValue: string | boolean
): { value: ManifestInputValue; error?: string } {
  switch (inputType) {
    case 'boolean': {
      if (typeof rawValue === 'boolean') return { value: rawValue }
      if (typeof rawValue === 'string') {
        const lowered = rawValue.trim().toLowerCase()
        if (lowered === 'true') return { value: true }
        if (lowered === 'false') return { value: false }
      }
      return { value: false }
    }
    case 'number': {
      if (typeof rawValue !== 'string') return { value: null }
      const trimmed = rawValue.trim()
      if (!trimmed) return { value: null }
      const parsed = Number(trimmed)
      if (!Number.isFinite(parsed)) {
        return { value: null, error: 'Invalid number' }
      }
      return { value: parsed }
    }
    case 'string[]': {
      if (typeof rawValue !== 'string') return { value: [] }
      const parts = rawValue
        .split(',')
        .map((value) => value.trim())
        .filter((value) => value.length > 0)
      return { value: parts }
    }
    case 'object': {
      if (typeof rawValue !== 'string') return { value: {} }
      const trimmed = rawValue.trim()
      if (!trimmed) return { value: {} }
      try {
        const parsed = JSON.parse(trimmed)
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
          return { value: null, error: 'Must be a JSON object' }
        }
        return { value: parsed as Record<string, unknown> }
      } catch {
        return { value: null, error: 'Invalid JSON' }
      }
    }
    default:
      if (typeof rawValue === 'string') return { value: rawValue }
      return { value: '' }
  }
}

export function hydrateIncomingNodes(
  rawNodes: ReadonlyArray<WorkflowNode>,
  epoch: number
): WorkflowNode[] {
  return rawNodes.map((node) => {
    const baseData =
      node?.data && typeof node.data === 'object'
        ? cloneWorkflowData(node.data)
        : ({} as WorkflowNodeData)

    return {
      id: node.id,
      type: normalizeNodeType(node.type),
      position: node.position,
      data: {
        ...(baseData as WorkflowNodeData),
        dirty: Boolean((node?.data as WorkflowNodeData | undefined)?.dirty),
        wfEpoch: epoch
      }
    }
  })
}

export function hydrateIncomingEdges(
  rawEdges: ReadonlyArray<WorkflowEdge>
): WorkflowEdge[] {
  return normalizeEdgesForState(rawEdges)
}
