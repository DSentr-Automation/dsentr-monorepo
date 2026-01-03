const LABEL_MESSAGES = {
  spaces: 'Node names cannot contain spaces.',
  duplicate: 'Node name must be unique.'
} as const

export type FlowNode = {
  id: string
  data?: Record<string, any>
  [key: string]: any
}

export function sanitizeData(data: any, nodeType?: string) {
  if (!data || typeof data !== 'object') return data
  const {
    dirty,
    wfEpoch,
    hasValidationErrors,
    hasLabelValidationError,
    labelError,
    ...rest
  } = data as any
  const normalizedTriggerType =
    typeof rest.triggerType === 'string'
      ? rest.triggerType.trim().toLowerCase()
      : ''
  const isTriggerNode = nodeType === 'trigger' || normalizedTriggerType !== ''

  if (isTriggerNode) {
    const {
      webhook_source_id,
      webhookSourceId,
      source_id,
      sourceId,
      webhookSource,
      ...triggerRest
    } = rest as any
    if (normalizedTriggerType === 'webhook') {
      return {
        ...triggerRest,
        event_type:
          typeof triggerRest.event_type === 'string'
            ? triggerRest.event_type
            : ''
      }
    }
    const { event_type, ...nonWebhookRest } = triggerRest as any
    return nonWebhookRest
  }

  return rest
}

export function normalizeNode(n: any) {
  return {
    id: n.id,
    type: n.type,
    position: n.position,
    data: sanitizeData(n.data, n.type)
  }
}

export function sanitizeNodeData(node: any) {
  return normalizeNode(node)
}

export function normalizeEdge(e: any) {
  const label = (e as any).label ?? null
  const animated = Boolean((e as any).animated)
  return {
    id: e.id,
    source: e.source,
    target: e.target,
    sourceHandle: e.sourceHandle,
    targetHandle: e.targetHandle,
    type: e.type,
    data: e.data,
    label,
    animated
  }
}

export function normalizeEdgeForPayload(edge: any) {
  return normalizeEdge(edge)
}

export function sortById<T extends { id: string }>(arr: T[]): T[] {
  return [...arr].sort((a, b) => a.id.localeCompare(b.id))
}

export function sanitizeLabelInput(value: unknown): string {
  return typeof value === 'string' ? value.trim() : ''
}

function countExistingLabels(nodes: FlowNode[]): Map<string, number> {
  const counts = new Map<string, number>()
  nodes.forEach((node) => {
    const label = sanitizeLabelInput(node?.data?.label)
    if (!label) return
    const key = label.toLowerCase()
    counts.set(key, (counts.get(key) ?? 0) + 1)
  })
  return counts
}

export function generateUniqueLabel(
  baseLabel: string,
  nodes: FlowNode[]
): string {
  const trimmed = sanitizeLabelInput(baseLabel)
  const normalizedBase = trimmed.replace(/\s+/g, '') || 'Node'
  const counts = countExistingLabels(nodes)
  if ((counts.get(normalizedBase.toLowerCase()) ?? 0) === 0) {
    return normalizedBase
  }
  let suffix = 2
  let candidate = `${normalizedBase}${suffix}`
  while ((counts.get(candidate.toLowerCase()) ?? 0) > 0) {
    suffix += 1
    candidate = `${normalizedBase}${suffix}`
  }
  return candidate
}

export function shallowEqualData(
  a: Record<string, any> | undefined,
  b: Record<string, any>
): boolean {
  if (!a) return Object.keys(b).length === 0
  const keysA = Object.keys(a)
  const keysB = Object.keys(b)
  if (keysA.length !== keysB.length) return false
  for (const key of keysA) {
    if (a[key] !== b[key]) return false
  }
  return true
}

export function reconcileNodeLabels<T extends FlowNode>(nodes: T[]): T[] {
  const metadata = nodes.map((node) => {
    const trimmed = sanitizeLabelInput(node?.data?.label)
    return {
      trimmed,
      hasSpaces: /\s/.test(trimmed),
      normalized: trimmed.toLowerCase()
    }
  })
  const counts = new Map<string, number>()
  metadata.forEach(({ trimmed, normalized }) => {
    if (!trimmed) return
    counts.set(normalized, (counts.get(normalized) ?? 0) + 1)
  })
  let hasChanges = false
  const nextNodes = nodes.map<T>((node, index) => {
    const prevData = node.data ?? {}
    const { trimmed, hasSpaces, normalized } = metadata[index]
    let labelError: string | null = null
    if (trimmed && hasSpaces) {
      labelError = LABEL_MESSAGES.spaces
    } else if (trimmed && (counts.get(normalized) ?? 0) > 1) {
      labelError = LABEL_MESSAGES.duplicate
    }
    const hasLabelValidationError = Boolean(labelError)
    const nextDataShouldChange =
      prevData.label !== trimmed ||
      (prevData.labelError ?? null) !== labelError ||
      Boolean(prevData.hasLabelValidationError) !== hasLabelValidationError

    if (!nextDataShouldChange) return node
    hasChanges = true
    return {
      ...node,
      data: {
        ...prevData,
        label: trimmed,
        labelError,
        hasLabelValidationError
      }
    }
  })
  return hasChanges ? nextNodes : nodes
}
