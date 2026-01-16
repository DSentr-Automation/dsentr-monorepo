import { useEffect, useMemo, useState } from 'react'
import NodeDropdownField, {
  type NodeDropdownOption,
  type NodeDropdownOptionGroup
} from '@/components/ui/InputFields/NodeDropdownField'
import {
  fetchConnections,
  getCachedConnections,
  subscribeToConnectionUpdates,
  type GroupedConnectionsSnapshot,
  type OAuthProvider
} from '@/lib/oauthApi'

interface GenericOAuthConnectionFieldProps {
  provider: string
  connectionScopes?: Array<'personal' | 'workspace'>
  workspaceId?: string | null
  value?: {
    connectionScope?: string
    connectionId?: string
    accountEmail?: string
  } | null
  onChange: (
    next: {
      connectionScope?: string
      connectionId?: string
      accountEmail?: string
    } | null
  ) => void
  disabled?: boolean
  required?: boolean
}

export default function GenericOAuthConnectionField({
  provider,
  connectionScopes = ['personal'],
  workspaceId,
  value,
  onChange,
  disabled = false
}: GenericOAuthConnectionFieldProps) {
  const [connections, setConnections] =
    useState<GroupedConnectionsSnapshot | null>(null)
  const [loading, setLoading] = useState(true)

  // Subscribe to connection updates
  useEffect(() => {
    const unsubscribe = subscribeToConnectionUpdates(
      (snapshot) => {
        setConnections(snapshot)
        setLoading(false)
      },
      { workspaceId }
    )

    // Try to get cached connections first
    const cached = getCachedConnections(workspaceId)
    if (cached) {
      setConnections(cached)
      setLoading(false)
    } else {
      // Fetch if no cache
      fetchConnections({ workspaceId })
        .then(setConnections)
        .catch(console.error)
        .finally(() => setLoading(false))
    }

    return unsubscribe
  }, [workspaceId])

  // Build dropdown options from connections
  const options: (NodeDropdownOption | NodeDropdownOptionGroup)[] =
    useMemo(() => {
      if (!connections) return []

      const groups: NodeDropdownOptionGroup[] = []
      const allowedScopes = new Set(connectionScopes)

      // Personal connections group
      if (allowedScopes.has('personal')) {
        const personalConnections = connections.personal.filter(
          (conn) =>
            conn.provider === (provider as OAuthProvider) &&
            !conn.requiresReconnect
        )

        if (personalConnections.length > 0) {
          groups.push({
            label: 'Personal connections',
            options: personalConnections.map(
              (conn): NodeDropdownOption => ({
                label: conn.accountEmail || 'Unknown account',
                value: `personal:${conn.connectionId ?? conn.id}`
              })
            )
          })
        }
      }

      // Workspace connections group
      if (allowedScopes.has('workspace')) {
        const workspaceConnections = connections.workspace.filter(
          (conn) =>
            conn.provider === (provider as OAuthProvider) &&
            !conn.requiresReconnect
        )

        if (workspaceConnections.length > 0) {
          groups.push({
            label: 'Workspace connections',
            options: workspaceConnections.map(
              (conn): NodeDropdownOption => ({
                label: `${conn.workspaceName} (${conn.accountEmail || 'Unknown account'})`,
                value: `workspace:${conn.connectionId ?? conn.id}`
              })
            )
          })
        }
      }

      return groups
    }, [connections, provider, connectionScopes])

  // Extract current value for dropdown
  const currentValue = useMemo(() => {
    if (!value?.connectionScope || !value?.connectionId) return ''
    return `${value.connectionScope}:${value.connectionId}`
  }, [value])

  // Handle selection change
  const handleSelectionChange = (selectedValue: string) => {
    if (!selectedValue) {
      onChange(null)
      return
    }

    const [scope, rawId] = selectedValue.split(':', 2)
    if (!scope || !rawId) {
      onChange(null)
      return
    }

    // Find the connection to get account email
    let accountEmail: string | undefined
    if (connections) {
      const targetConnections =
        scope === 'personal' ? connections.personal : connections.workspace
      const connection = targetConnections.find(
        (conn) => (conn.connectionId ?? conn.id) === rawId
      )
      accountEmail = connection?.accountEmail
    }

    onChange({
      connectionScope: scope,
      connectionId: rawId,
      accountEmail
    })
  }

  return (
    <NodeDropdownField
      options={options}
      value={currentValue}
      onChange={handleSelectionChange}
      placeholder={`Select ${provider.charAt(0).toUpperCase() + provider.slice(1)} account`}
      disabled={disabled}
      loading={loading}
      emptyMessage={`Connect ${provider.charAt(0).toUpperCase() + provider.slice(1)} under Settings → Integrations to use this action.`}
    />
  )
}
