import { describe, it, beforeEach, afterEach, expect, vi } from 'vitest'
import { render, screen, within, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'

import FlowCanvas from '@/layouts/DashboardLayouts/FlowCanvas'
import {
  useActionRegistry,
  type ActionDefinition
} from '@/stores/actionRegistry'
import { useAuth } from '@/stores/auth'
import { useWorkflowStore } from '@/stores/workflowStore'

vi.mock('@xyflow/react', () => ({
  ReactFlow: ({ nodes = [], nodeTypes = {}, children }: any) => (
    <div>
      {nodes.map((node: any) => {
        const NodeComponent = nodeTypes?.[node.type]
        if (!NodeComponent) return null
        return (
          <div key={node.id} data-testid={`node-${node.id}`}>
            <NodeComponent
              id={node.id}
              data={node.data}
              type={node.type}
              selected={true}
            />
          </div>
        )
      })}
      {children}
    </div>
  ),
  Background: () => null,
  MiniMap: () => null,
  addEdge: (edge: any, edges: any[]) => [...edges, edge],
  applyEdgeChanges: (_changes: any, edges: any[]) => edges,
  applyNodeChanges: (_changes: any, nodes: any[]) => nodes,
  useReactFlow: () => ({
    screenToFlowPosition: (pos: any) => pos,
    getNode: () => undefined,
    setCenter: () => undefined,
    zoomIn: () => undefined,
    zoomOut: () => undefined,
    fitView: () => undefined
  }),
  Handle: ({ children }: any) => <div>{children}</div>,
  Position: { Left: 'left', Right: 'right', Top: 'top', Bottom: 'bottom' },
  ReactFlowProvider: ({ children }: any) => <div>{children}</div>
}))

vi.mock('@/components/ui/InputFields/NodeDropdownField', () => ({
  __esModule: true,
  default: ({ value, onChange, options }: any) => {
    const flat = (options ?? []).flatMap((entry: any) =>
      entry?.options ? entry.options : [entry]
    )
    return (
      <select
        value={value ?? ''}
        onChange={(event) => onChange(event.target.value)}
      >
        <option value="" />
        {flat.map((option: any) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    )
  }
}))

const initialWorkflowState = useWorkflowStore.getState()
const initialActionRegistryState = useActionRegistry.getState()
const initialAuthState = useAuth.getState()
const initialRequestAnimationFrame = globalThis.requestAnimationFrame

const ownerMembership = {
  workspace: { id: 'workspace-1', name: 'Test Workspace', plan: 'workspace' },
  role: 'owner'
}

const testActionDefinition: ActionDefinition = {
  id: 'test.action',
  actionType: 'test.action',
  nodeType: 'action',
  label: 'Test Action',
  description: 'Test action',
  category: 'Test',
  iconKey: 'action',
  gradient: 'from-slate-600 to-slate-800',
  idPrefix: 'action-test-action',
  expanded: true,
  createNodeData: () => ({
    actionType: 'test.action',
    params: { operation: '' },
    timeout: 5000,
    retries: 0,
    stopOnError: true,
    hasValidationErrors: false
  }),
  inputs: [
    {
      name: 'operation',
      label: 'Operation',
      type: 'enum',
      required: true,
      options: [
        { value: 'create_issue', label: 'Create issue' },
        { value: 'create_pull_request', label: 'Create pull request' }
      ]
    }
  ]
}

describe('FlowCanvas enum options', () => {
  beforeEach(() => {
    if (!globalThis.requestAnimationFrame) {
      globalThis.requestAnimationFrame = (cb: FrameRequestCallback) =>
        setTimeout(cb, 0)
    }

    useWorkflowStore.setState(initialWorkflowState, true)
    useActionRegistry.setState(initialActionRegistryState, true)
    useAuth.setState(
      {
        memberships: [ownerMembership],
        currentWorkspaceId: ownerMembership.workspace.id
      },
      false
    )
    useActionRegistry.setState((state) => ({
      ...state,
      actions: [testActionDefinition],
      isLoaded: true,
      isLoading: false
    }))
    useWorkflowStore.setState((state) => ({
      ...state,
      nodes: [
        {
          id: 'node-1',
          type: 'action',
          position: { x: 0, y: 0 },
          data: {
            label: 'Test Action',
            actionType: 'test.action',
            params: { operation: '' },
            dirty: false,
            expanded: true,
            hasValidationErrors: false
          }
        } as any
      ],
      edges: [],
      canEdit: true
    }))
  })

  afterEach(() => {
    useWorkflowStore.setState(initialWorkflowState, true)
    useActionRegistry.setState(initialActionRegistryState, true)
    useAuth.setState(initialAuthState, true)
    if (!initialRequestAnimationFrame) {
      delete (globalThis as { requestAnimationFrame?: unknown })
        .requestAnimationFrame
    } else {
      globalThis.requestAnimationFrame = initialRequestAnimationFrame
    }
  })

  it('renders labeled enum options and stores the selected value', async () => {
    render(<FlowCanvas workflowId="workflow-1" canEdit planTier="workspace" />)

    const user = userEvent.setup()
    const flyoutTrigger = screen.getByRole('button', {
      name: /Configure this action in the flyout/i
    })
    await user.click(flyoutTrigger)

    await screen.findByText('Node details')

    const fieldLabel = await screen.findByText(/^Operation\b/i)
    const field = fieldLabel.closest('div')
    expect(field).not.toBeNull()

    const dropdown = within(field as HTMLElement).getByRole('combobox')
    expect(
      within(field as HTMLElement).getByRole('option', {
        name: 'Create issue'
      })
    ).toBeInTheDocument()

    await user.selectOptions(dropdown, 'create_pull_request')

    await waitFor(() => {
      const node = useWorkflowStore.getState().nodes[0]
      const params = (node?.data as any)?.params as Record<string, unknown>
      expect(params.operation).toBe('create_pull_request')
    })
  })
})
