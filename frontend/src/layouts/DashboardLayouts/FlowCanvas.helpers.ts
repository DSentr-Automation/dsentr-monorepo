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
