import {
  useCallback,
  useMemo,
  useEffect,
  useRef,
  useState,
  type DragEvent
} from 'react'
import { v4 as uuidv4 } from 'uuid'
import {
  ReactFlow,
  Background,
  MiniMap,
  addEdge,
  applyEdgeChanges,
  applyNodeChanges,
  useReactFlow,
  type Node,
  type Edge,
  type NodeProps,
  type EdgeProps,
  type NodeChange,
  type EdgeChange,
  type Connection,
  type OnSelectionChangeParams,
  type XYPosition
} from '@xyflow/react'
import TriggerNode, {
  type TriggerNodeData
} from '@/components/workflow/TriggerNode'
import {
  SendGridActionNode,
  MailgunActionNode,
  AmazonSesActionNode,
  SlackActionNode,
  TeamsActionNode,
  GoogleChatActionNode,
  GoogleSheetsActionNode,
  HttpRequestActionNode,
  RunCustomCodeActionNode,
  AsanaActionNode,
  NotionActionNode
} from '@/components/workflow/nodes'
import NodeEdge from '@/components/workflow/NodeEdge'
import CustomControls from '@/components/ui/ReactFlow/CustomControl'
import ConditionNode, {
  type ConditionNodeData
} from '@/components/workflow/ConditionNode'
import DelayNode, {
  type DelayNodeData
} from '@/components/workflow/nodes/DelayNode'
import FormatterNode, {
  type FormatterNodeData
} from '@/components/workflow/nodes/FormatterNode'
import { normalizePlanTier } from '@/lib/planTiers'
import { fetchNotionDatabases, type NotionDatabase } from '@/lib/notionApi'
import {
  fetchConnections,
  getCachedConnections,
  subscribeToConnectionUpdates,
  type ConnectionScope,
  type GroupedConnectionsSnapshot,
  type ProviderConnectionSet
} from '@/lib/oauthApi'
import { selectCurrentWorkspace, useAuth } from '@/stores/auth'
import { generateUniqueLabel } from '@/lib/workflowGraph'
import {
  useWorkflowStore,
  selectNodes,
  selectEdges
} from '@/stores/workflowStore'
import {
  normalizeEdgesForState,
  normalizeNodesForState
} from './FlowCanvas.helpers'
import { WorkflowFlyoutProvider } from '@/components/workflow/useWorkflowFlyout'
import { X } from 'lucide-react'
import { CalendarDays, Clock, Globe2, RefreshCcw } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  CalendarMonth,
  formatDisplayDate,
  formatDisplayTime,
  getInitialMonth,
  parseTime,
  toISODateString
} from '@/components/ui/schedule/utils'
import { ScheduleCalendar } from '@/components/ui/schedule/ScheduleCalendar'
import { ScheduleTimePicker } from '@/components/ui/schedule/ScheduleTimePicker'
import { ScheduleTimezonePicker } from '@/components/ui/schedule/ScheduleTimezonePicker'
import NodeHeader from '@/components/ui/ReactFlow/NodeHeader'
import NodeInputField from '@/components/ui/InputFields/NodeInputField'
import NodeCheckBoxField from '@/components/ui/InputFields/NodeCheckboxField'
import NodeDropdownField, {
  type NodeDropdownOption,
  type NodeDropdownOptionGroup
} from '@/components/ui/InputFields/NodeDropdownField'
import KeyValuePair from '@/components/ui/ReactFlow/KeyValuePair'
import DelayNodeConfig from '@/components/actions/logic/DelayNode'
import {
  normalizeDelayConfig,
  validateDelayConfig,
  type DelayConfig
} from '@/components/actions/logic/DelayNode/helpers'
import FormatterNodeConfig from '@/components/actions/logic/FormatterNode'
import {
  createEmptyFormatterConfig,
  normalizeFormatterConfig,
  validateFormatterConfig,
  type FormatterConfig
} from '@/components/actions/logic/FormatterNode/helpers'
import TriggerTypeDropdown from '@/components/workflow/TriggerTypeDropdown'
import SendGridAction from '@/components/workflow/Actions/Email/Services/SendGridAction'
import MailGunAction from '@/components/workflow/Actions/Email/Services/MailGunAction'
import AmazonSESAction from '@/components/workflow/Actions/Email/Services/AmazonSESAction'
import SlackAction from '@/components/workflow/Actions/Messaging/Services/SlackAction'
import TeamsAction from '@/components/workflow/Actions/Messaging/Services/TeamsAction'
import GoogleChatAction from '@/components/workflow/Actions/Messaging/Services/GoogleChatAction'
import SheetsAction from '@/components/workflow/Actions/Google/SheetsAction'
import HttpRequestAction from '@/components/workflow/Actions/HttpRequestAction'
import RunCustomCodeAction from '@/components/workflow/Actions/RunCustomCodeAction'
import AsanaAction from '@/components/workflow/Actions/Asana/AsanaAction'
import NotionAction from '@/components/workflow/Actions/Notion/NotionAction'
import useActionNodeController, {
  type ActionNodeData
} from '@/components/workflow/nodes/useActionNodeController'
import useMessagingActionRestriction from '@/components/workflow/nodes/useMessagingActionRestriction'
import { errorMessage } from '@/lib/errorMessage'
import type { RunAvailability } from '@/types/runAvailability'
import { shallow } from 'zustand/shallow'

const SCHEDULE_RESTRICTION_MESSAGE =
  'Scheduled triggers are available on workspace plans and above. Switch this trigger to Manual or Webhook to keep running on the solo plan.'
const NOTION_TRIGGER_RESTRICTION_MESSAGE =
  'Notion triggers are available on workspace plans and above. Upgrade in Settings > Plan to keep polling Notion.'

type WorkflowEdgeStyle = 'default' | 'bold' | 'dashed'

export interface WorkflowEdgeData extends Record<string, unknown> {
  edgeType?: WorkflowEdgeStyle
  outcome?: string | null
}

export type WorkflowNodeData =
  | TriggerNodeData
  | ConditionNodeData
  | DelayNodeData
  | FormatterNodeData
  | ActionNodeData
  | Record<string, unknown>

export type WorkflowNode = Node<WorkflowNodeData>
export type WorkflowEdge = Edge<WorkflowEdgeData>

type TriggerNodeRendererProps = NodeProps<Node<TriggerNodeData>>
type ConditionNodeRendererProps = NodeProps<Node<ConditionNodeData>>
type DelayNodeRendererProps = NodeProps<Node<DelayNodeData>> & {
  isRunning?: boolean
  isSucceeded?: boolean
  isFailed?: boolean
  canEdit?: boolean
}
type FormatterNodeRendererProps = NodeProps<Node<FormatterNodeData>> & {
  isRunning?: boolean
  isSucceeded?: boolean
  isFailed?: boolean
  canEdit?: boolean
}

type ActionNodeRendererProps = NodeProps<Node<ActionNodeData>> & {
  onRun?: (id: string, params: unknown) => Promise<void>
  isRunning?: boolean
  isSucceeded?: boolean
  isFailed?: boolean
  canEdit?: boolean
  planTier?: string | null
  onRestrictionNotice?: (message: string) => void
  runAvailability?: RunAvailability
}

type WorkflowEdgeRendererProps = EdgeProps<WorkflowEdge>

type ActionDropSubtype =
  | 'actionEmailSendgrid'
  | 'actionEmailMailgun'
  | 'actionEmailAmazonSes'
  | 'actionSlack'
  | 'actionTeams'
  | 'actionGoogleChat'
  | 'actionSheets'
  | 'actionHttp'
  | 'actionCode'
  | 'actionAsana'
  | 'actionNotion'
type LogicDropSubtype = 'delay' | 'formatter'

interface DropDescriptor {
  nodeType: string
  labelBase: string
  idPrefix: string
  expanded: boolean
  data: WorkflowNodeData
}

type ActionDropConfig = {
  nodeType: ActionDropSubtype
  labelBase: string
  idPrefix: string
  expanded: boolean
  createData: () => ActionNodeData
}

const ACTION_NODE_DROP_CONFIG: Record<ActionDropSubtype, ActionDropConfig> = {
  actionEmailSendgrid: {
    nodeType: 'actionEmailSendgrid',
    labelBase: 'SendGrid email',
    idPrefix: 'action-email-sendgrid',
    expanded: true,
    createData: () => ({
      actionType: 'email',
      emailProvider: 'sendgrid',
      params: {
        apiKey: '',
        from: '',
        to: '',
        templateId: '',
        substitutions: [],
        subject: '',
        body: ''
      },
      timeout: 5000,
      retries: 0,
      stopOnError: true
    })
  },
  actionEmailMailgun: {
    nodeType: 'actionEmailMailgun',
    labelBase: 'Mailgun email',
    idPrefix: 'action-email-mailgun',
    expanded: true,
    createData: () => ({
      actionType: 'email',
      emailProvider: 'mailgun',
      params: {
        domain: '',
        apiKey: '',
        region: 'US (api.mailgun.net)',
        from: '',
        to: '',
        subject: '',
        body: '',
        template: '',
        variables: []
      },
      timeout: 5000,
      retries: 0,
      stopOnError: true
    })
  },
  actionEmailAmazonSes: {
    nodeType: 'actionEmailAmazonSes',
    labelBase: 'Amazon SES email',
    idPrefix: 'action-email-amazon-ses',
    expanded: true,
    createData: () => ({
      actionType: 'email',
      emailProvider: 'amazon_ses',
      params: {
        awsAccessKey: '',
        awsSecretKey: '',
        awsRegion: 'us-east-1',
        sesVersion: 'v2',
        fromEmail: '',
        toEmail: '',
        subject: '',
        body: '',
        template: '',
        templateVariables: []
      },
      timeout: 5000,
      retries: 0,
      stopOnError: true
    })
  },
  actionSlack: {
    nodeType: 'actionSlack',
    labelBase: 'Slack message',
    idPrefix: 'action-slack',
    expanded: true,
    createData: () => ({
      actionType: 'slack',
      params: {
        channel: '',
        message: '',
        token: '',
        connectionScope: '',
        connectionId: '',
        accountEmail: ''
      },
      timeout: 5000,
      retries: 0,
      stopOnError: true
    })
  },
  actionTeams: {
    nodeType: 'actionTeams',
    labelBase: 'Teams message',
    idPrefix: 'action-teams',
    expanded: true,
    createData: () => ({
      actionType: 'teams',
      params: {
        deliveryMethod: 'Incoming Webhook',
        webhookType: 'Connector',
        webhookUrl: '',
        message: '',
        summary: '',
        title: '',
        themeColor: '',
        oauthProvider: '',
        oauthConnectionScope: '',
        oauthConnectionId: '',
        oauthAccountEmail: '',
        cardJson: '',
        cardMode: 'Simple card builder',
        cardTitle: '',
        cardBody: '',
        workflowOption: 'Basic (Raw JSON)',
        workflowRawJson: '',
        workflowHeaderName: '',
        workflowHeaderSecret: '',
        teamId: '',
        teamName: '',
        channelId: '',
        channelName: '',
        messageType: 'Text',
        mentions: []
      },
      timeout: 5000,
      retries: 0,
      stopOnError: true
    })
  },
  actionGoogleChat: {
    nodeType: 'actionGoogleChat',
    labelBase: 'Google Chat message',
    idPrefix: 'action-google-chat',
    expanded: true,
    createData: () => ({
      actionType: 'googlechat',
      params: {
        webhookUrl: '',
        message: '',
        cardJson: ''
      },
      timeout: 5000,
      retries: 0,
      stopOnError: true
    })
  },
  actionSheets: {
    nodeType: 'actionSheets',
    labelBase: 'Google Sheets row',
    idPrefix: 'action-sheets',
    expanded: true,
    createData: () => ({
      actionType: 'sheets',
      params: {
        spreadsheetId: '',
        worksheet: '',
        columns: [],
        accountEmail: '',
        oauthConnectionScope: '',
        oauthConnectionId: ''
      },
      timeout: 5000,
      retries: 0,
      stopOnError: true
    })
  },
  actionHttp: {
    nodeType: 'actionHttp',
    labelBase: 'HTTP request',
    idPrefix: 'action-http',
    expanded: true,
    createData: () => ({
      actionType: 'http',
      params: {
        method: 'GET',
        url: '',
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
    })
  },
  actionAsana: {
    nodeType: 'actionAsana',
    labelBase: 'Asana',
    idPrefix: 'action-asana',
    expanded: true,
    createData: () => ({
      actionType: 'asana',
      params: {
        operation: 'createTask',
        connectionScope: '',
        connectionId: '',
        workspaceGid: '',
        name: '',
        additionalFields: []
      },
      timeout: 5000,
      retries: 0,
      stopOnError: true
    })
  },
  actionNotion: {
    nodeType: 'actionNotion',
    labelBase: 'Notion',
    idPrefix: 'action-notion',
    expanded: true,
    createData: () => ({
      actionType: 'notion',
      params: {
        operation: 'create_database_row',
        connectionScope: '',
        connectionId: '',
        databaseId: '',
        pageId: '',
        parentType: 'database',
        parentDatabaseId: '',
        parentPageId: '',
        title: '',
        properties: {},
        filter: {
          propertyId: '',
          propertyType: '',
          operator: 'equals',
          value: ''
        },
        limit: ''
      },
      timeout: 5000,
      retries: 0,
      stopOnError: true
    })
  },
  actionCode: {
    nodeType: 'actionCode',
    labelBase: 'Code step',
    idPrefix: 'action-code',
    expanded: true,
    createData: () => ({
      actionType: 'code',
      params: {
        code: '',
        inputs: [],
        outputs: []
      },
      timeout: 5000,
      retries: 0,
      stopOnError: true
    })
  }
} as const

function normalizeActionDropSubtype(
  rawSubtype?: string | null
): ActionDropSubtype {
  if (!rawSubtype) return 'actionEmailSendgrid'
  const lowered = rawSubtype.trim().toLowerCase()
  switch (lowered) {
    case 'actionemailsendgrid':
    case 'actionemail':
    case 'send email':
    case 'email':
    case 'sendgrid':
      return 'actionEmailSendgrid'
    case 'actionemailmailgun':
    case 'mailgun':
      return 'actionEmailMailgun'
    case 'actionemailamazonses':
    case 'amazon ses':
    case 'amazon_ses':
    case 'amazonses':
      return 'actionEmailAmazonSes'
    case 'actionslack':
    case 'slack':
      return 'actionSlack'
    case 'actionteams':
    case 'teams':
      return 'actionTeams'
    case 'actiongooglechat':
    case 'googlechat':
    case 'google chat':
      return 'actionGoogleChat'
    case 'actionasana':
    case 'asana':
      return 'actionAsana'
    case 'actionnotion':
    case 'notion':
      return 'actionNotion'
    case 'actionsheets':
    case 'sheets':
    case 'create google sheet row':
      return 'actionSheets'
    case 'actionhttp':
    case 'http':
    case 'http request':
      return 'actionHttp'
    case 'actioncode':
    case 'code':
    case 'run custom code':
      return 'actionCode'
    case 'messaging':
      return 'actionSlack'
    default:
      return 'actionEmailSendgrid'
  }
}

function normalizeLogicDropSubtype(
  rawSubtype?: string | null
): LogicDropSubtype {
  if (!rawSubtype) return 'delay'
  const lowered = rawSubtype.trim().toLowerCase()
  switch (lowered) {
    case 'formatter':
    case 'transform':
    case 'logicformatter':
    case 'transformer':
      return 'formatter'
    case 'delay':
    case 'wait':
    default:
      return 'delay'
  }
}

function normalizeDropType(rawType: string): DropDescriptor {
  const [categoryRaw, subtypeRaw] = rawType.split(':')
  const category = categoryRaw?.trim().toLowerCase()

  if (category === 'trigger') {
    return {
      nodeType: 'trigger',
      labelBase: 'Trigger',
      idPrefix: 'trigger',
      expanded: false,
      data: {} as ActionNodeData
    }
  }

  if (category === 'condition') {
    return {
      nodeType: 'condition',
      labelBase: 'Condition',
      idPrefix: 'condition',
      expanded: false,
      data: {} as ActionNodeData
    }
  }

  if (category === 'logic') {
    const logicSubtype = normalizeLogicDropSubtype(subtypeRaw ?? null)
    if (logicSubtype === 'formatter') {
      return {
        nodeType: 'formatter',
        labelBase: 'Formatter',
        idPrefix: 'logic-formatter',
        expanded: false,
        data: {
          config: createEmptyFormatterConfig(),
          hasValidationErrors: true
        } as FormatterNodeData
      }
    }
    return {
      nodeType: 'delay',
      labelBase: 'Delay',
      idPrefix: 'logic-delay',
      expanded: false,
      data: {
        config: {
          mode: 'duration',
          wait_for: {
            minutes: undefined,
            hours: undefined,
            days: undefined
          },
          wait_until: undefined,
          jitter_seconds: undefined
        },
        hasValidationErrors: true
      } as DelayNodeData
    }
  }

  if (category === 'action') {
    const subtype = normalizeActionDropSubtype(subtypeRaw ?? null)
    const config = ACTION_NODE_DROP_CONFIG[subtype]
    return {
      nodeType: config.nodeType,
      labelBase: config.labelBase,
      idPrefix: config.idPrefix,
      expanded: config.expanded,
      data: config.createData()
    }
  }

  const fallback = ACTION_NODE_DROP_CONFIG.actionEmailSendgrid
  return {
    nodeType: fallback.nodeType,
    labelBase: fallback.labelBase,
    idPrefix: fallback.idPrefix,
    expanded: fallback.expanded,
    data: fallback.createData()
  }
}

interface FlowCanvasProps {
  isDark?: boolean
  workflowId?: string | null
  onRunWorkflow?: (startNodeId?: string) => void
  runningIds?: Set<string>
  succeededIds?: Set<string>
  failedIds?: Set<string>
  planTier?: string | null
  onRestrictionNotice?: (message: string) => void
  canEdit?: boolean
  runAvailability?: RunAvailability
  onRegisterQuickAdd?: (handler: (dragType: string) => void) => void
}

export default function FlowCanvas({
  isDark,
  workflowId,
  onRunWorkflow,
  runningIds = new Set(),
  succeededIds = new Set(),
  failedIds = new Set(),
  planTier,
  onRestrictionNotice,
  canEdit = true,
  runAvailability,
  onRegisterQuickAdd
}: FlowCanvasProps) {
  const nodes = useWorkflowStore(selectNodes)
  const edges = useWorkflowStore(selectEdges)
  const reactFlow = useReactFlow<WorkflowNode, WorkflowEdge>()
  // Track which node's details flyout is open for (independent of selection)
  const [flyoutNodeId, setFlyoutNodeId] = useState<string | null>(null)
  const syncSelectionToStore = useCallback((nextSelectedId: string | null) => {
    // Only sync node selection into the store for flyout logic.
    // Do not touch edge selection here; React Flow manages it and
    // clearing it here prevents edge menus from appearing.
    const state = useWorkflowStore.getState()
    const currentNodes = state.nodes
    let nodeChanged = false
    const nextNodes = currentNodes.map<WorkflowNode>((node) => {
      const shouldSelect = nextSelectedId !== null && node.id === nextSelectedId
      if (Boolean(node.selected) === shouldSelect) {
        return node
      }
      nodeChanged = true
      return {
        ...node,
        selected: shouldSelect
      }
    })
    if (nodeChanged) {
      state.setNodes(nextNodes)
    }
  }, [])
  const normalizedPlanTier = useMemo(
    () => normalizePlanTier(planTier),
    [planTier]
  )
  const normalizedPlanTierRef = useRef(normalizedPlanTier)
  useEffect(() => {
    normalizedPlanTierRef.current = normalizedPlanTier
  }, [normalizedPlanTier])
  const isSoloPlan = normalizedPlanTier === 'solo'
  const canEditRef = useRef<boolean>(canEdit)
  const setCanEditState = useWorkflowStore((state) => state.setCanEdit)

  useEffect(() => {
    canEditRef.current = canEdit
    setCanEditState(canEdit)
  }, [canEdit, setCanEditState])

  const onRunWorkflowRef = useRef(onRunWorkflow)
  useEffect(() => {
    onRunWorkflowRef.current = onRunWorkflow
  }, [onRunWorkflow])

  const invokeRunWorkflow = useCallback((startNodeId?: string) => {
    onRunWorkflowRef.current?.(startNodeId)
  }, [])
  const invokeRunWorkflowRef = useRef(invokeRunWorkflow)
  useEffect(() => {
    invokeRunWorkflowRef.current = invokeRunWorkflow
  }, [invokeRunWorkflow])
  const runAvailabilityRef = useRef<RunAvailability | undefined>(
    runAvailability
  )
  useEffect(() => {
    runAvailabilityRef.current = runAvailability
  }, [runAvailability])
  const onRestrictionNoticeRef = useRef(onRestrictionNotice)
  useEffect(() => {
    onRestrictionNoticeRef.current = onRestrictionNotice
  }, [onRestrictionNotice])

  const { setNodes, setEdges } = useMemo(() => {
    const state = useWorkflowStore.getState()
    return {
      setNodes: state.setNodes,
      setEdges: state.setEdges
    }
  }, [])
  const canvasBoundsRef = useRef<HTMLDivElement | null>(null)

  const runningIdsRef = useRef(runningIds)
  const succeededIdsRef = useRef(succeededIds)
  const failedIdsRef = useRef(failedIds)
  useEffect(() => {
    runningIdsRef.current = runningIds
  }, [runningIds])
  useEffect(() => {
    succeededIdsRef.current = succeededIds
  }, [succeededIds])
  useEffect(() => {
    failedIdsRef.current = failedIds
  }, [failedIds])

  const flyoutNode = useWorkflowStore(
    useCallback(
      (state) =>
        flyoutNodeId
          ? (state.nodes.find((node) => node.id === flyoutNodeId) ?? null)
          : null,
      [flyoutNodeId]
    )
  )

  useEffect(() => {
    if (flyoutNodeId && !flyoutNode) {
      syncSelectionToStore(null)
      setFlyoutNodeId(null)
    }
  }, [flyoutNodeId, flyoutNode, syncSelectionToStore])

  const determineActionSubtype = useCallback(
    (data: ActionNodeData | null | undefined): ActionDropSubtype => {
      const rawActionType =
        typeof data?.actionType === 'string' ? data.actionType : null
      const normalizedActionType = (() => {
        if (!rawActionType) return 'email'
        const lowered = rawActionType.trim().toLowerCase()
        switch (lowered) {
          case 'send email':
            return 'email'
          case 'create google sheet row':
            return 'sheets'
          case 'http request':
            return 'http'
          case 'run custom code':
            return 'code'
          default:
            return lowered || 'email'
        }
      })()

      if (normalizedActionType === 'messaging') {
        const platform =
          typeof data?.params?.platform === 'string'
            ? data.params.platform.trim().toLowerCase()
            : ''
        if (platform === 'google chat' || platform === 'googlechat') {
          return 'actionGoogleChat'
        }
        if (platform === 'teams') return 'actionTeams'
        return 'actionSlack'
      }

      switch (normalizedActionType) {
        case 'email': {
          const providerSource = (() => {
            if (typeof data?.emailProvider === 'string') {
              return data.emailProvider
            }
            if (typeof data?.params?.provider === 'string') {
              return data.params.provider
            }
            if (typeof data?.params?.service === 'string') {
              return data.params.service
            }
            return ''
          })()

          const normalizedProvider = providerSource.trim().toLowerCase()
          if (normalizedProvider.includes('mailgun')) {
            return 'actionEmailMailgun'
          }
          if (
            normalizedProvider === 'amazon ses' ||
            normalizedProvider === 'amazon_ses' ||
            normalizedProvider === 'amazonses'
          ) {
            return 'actionEmailAmazonSes'
          }
          if (normalizedProvider.includes('sendgrid')) {
            return 'actionEmailSendgrid'
          }

          const paramsRecord =
            data?.params && typeof data.params === 'object'
              ? (data.params as Record<string, unknown>)
              : ({} as Record<string, unknown>)
          if (
            'awsAccessKey' in paramsRecord ||
            'awsSecretKey' in paramsRecord ||
            'sesVersion' in paramsRecord ||
            'awsRegion' in paramsRecord
          ) {
            return 'actionEmailAmazonSes'
          }
          if ('domain' in paramsRecord || 'region' in paramsRecord) {
            return 'actionEmailMailgun'
          }
          return 'actionEmailSendgrid'
        }
        case 'slack':
          return 'actionSlack'
        case 'teams':
          return 'actionTeams'
        case 'googlechat':
          return 'actionGoogleChat'
        case 'asana':
          return 'actionAsana'
        case 'notion':
          return 'actionNotion'
        case 'sheets':
          return 'actionSheets'
        case 'http':
          return 'actionHttp'
        case 'code':
          return 'actionCode'
        default:
          return 'actionEmailSendgrid'
      }
    },
    []
  )

  const actionRenderers = useMemo<
    Record<
      ActionDropSubtype,
      (props: ActionNodeRendererProps) => React.ReactNode
    >
  >(() => {
    const createSharedRunProps = (): Pick<
      ActionNodeRendererProps,
      'onRun' | 'canEdit' | 'runAvailability'
    > => ({
      onRun: async () => {
        if (runAvailabilityRef.current?.disabled) return
        invokeRunWorkflowRef.current?.()
      },
      canEdit: canEditRef.current,
      runAvailability: runAvailabilityRef.current
    })

    return {
      actionEmailSendgrid: (props: ActionNodeRendererProps) => (
        <SendGridActionNode
          key={`action-email-sendgrid-${props.id}-${props?.data?.wfEpoch ?? ''}`}
          {...props}
          {...createSharedRunProps()}
          isRunning={runningIdsRef.current.has(props.id)}
          isSucceeded={succeededIdsRef.current.has(props.id)}
          isFailed={failedIdsRef.current.has(props.id)}
        />
      ),
      actionEmailMailgun: (props: ActionNodeRendererProps) => (
        <MailgunActionNode
          key={`action-email-mailgun-${props.id}-${props?.data?.wfEpoch ?? ''}`}
          {...props}
          {...createSharedRunProps()}
          isRunning={runningIdsRef.current.has(props.id)}
          isSucceeded={succeededIdsRef.current.has(props.id)}
          isFailed={failedIdsRef.current.has(props.id)}
        />
      ),
      actionEmailAmazonSes: (props: ActionNodeRendererProps) => (
        <AmazonSesActionNode
          key={`action-email-amazon-ses-${props.id}-${props?.data?.wfEpoch ?? ''}`}
          {...props}
          {...createSharedRunProps()}
          isRunning={runningIdsRef.current.has(props.id)}
          isSucceeded={succeededIdsRef.current.has(props.id)}
          isFailed={failedIdsRef.current.has(props.id)}
        />
      ),
      actionSlack: (props: ActionNodeRendererProps) => (
        <SlackActionNode
          key={`action-slack-${props.id}-${props?.data?.wfEpoch ?? ''}`}
          {...props}
          {...createSharedRunProps()}
          planTier={normalizedPlanTierRef.current}
          onRestrictionNotice={onRestrictionNoticeRef.current}
          isRunning={runningIdsRef.current.has(props.id)}
          isSucceeded={succeededIdsRef.current.has(props.id)}
          isFailed={failedIdsRef.current.has(props.id)}
        />
      ),
      actionTeams: (props: ActionNodeRendererProps) => (
        <TeamsActionNode
          key={`action-teams-${props.id}-${props?.data?.wfEpoch ?? ''}`}
          {...props}
          {...createSharedRunProps()}
          planTier={normalizedPlanTierRef.current}
          onRestrictionNotice={onRestrictionNoticeRef.current}
          isRunning={runningIdsRef.current.has(props.id)}
          isSucceeded={succeededIdsRef.current.has(props.id)}
          isFailed={failedIdsRef.current.has(props.id)}
        />
      ),
      actionGoogleChat: (props: ActionNodeRendererProps) => (
        <GoogleChatActionNode
          key={`action-google-chat-${props.id}-${props?.data?.wfEpoch ?? ''}`}
          {...props}
          {...createSharedRunProps()}
          planTier={normalizedPlanTierRef.current}
          onRestrictionNotice={onRestrictionNoticeRef.current}
          isRunning={runningIdsRef.current.has(props.id)}
          isSucceeded={succeededIdsRef.current.has(props.id)}
          isFailed={failedIdsRef.current.has(props.id)}
        />
      ),
      actionSheets: (props: ActionNodeRendererProps) => (
        <GoogleSheetsActionNode
          key={`action-sheets-${props.id}-${props?.data?.wfEpoch ?? ''}`}
          {...props}
          {...createSharedRunProps()}
          planTier={normalizedPlanTierRef.current}
          onRestrictionNotice={onRestrictionNoticeRef.current}
          isRunning={runningIdsRef.current.has(props.id)}
          isSucceeded={succeededIdsRef.current.has(props.id)}
          isFailed={failedIdsRef.current.has(props.id)}
        />
      ),
      actionHttp: (props: ActionNodeRendererProps) => (
        <HttpRequestActionNode
          key={`action-http-${props.id}-${props?.data?.wfEpoch ?? ''}`}
          {...props}
          {...createSharedRunProps()}
          isRunning={runningIdsRef.current.has(props.id)}
          isSucceeded={succeededIdsRef.current.has(props.id)}
          isFailed={failedIdsRef.current.has(props.id)}
        />
      ),
      actionAsana: (props: ActionNodeRendererProps) => (
        <AsanaActionNode
          key={`action-asana-${props.id}-${props?.data?.wfEpoch ?? ''}`}
          {...props}
          {...createSharedRunProps()}
          planTier={normalizedPlanTierRef.current}
          isRunning={runningIdsRef.current.has(props.id)}
          isSucceeded={succeededIdsRef.current.has(props.id)}
          isFailed={failedIdsRef.current.has(props.id)}
        />
      ),
      actionNotion: (props: ActionNodeRendererProps) => (
        <NotionActionNode
          key={`action-notion-${props.id}-${props?.data?.wfEpoch ?? ''}`}
          {...props}
          {...createSharedRunProps()}
          planTier={normalizedPlanTierRef.current}
          onRestrictionNotice={onRestrictionNoticeRef.current}
          isRunning={runningIdsRef.current.has(props.id)}
          isSucceeded={succeededIdsRef.current.has(props.id)}
          isFailed={failedIdsRef.current.has(props.id)}
        />
      ),
      actionCode: (props: ActionNodeRendererProps) => (
        <RunCustomCodeActionNode
          key={`action-code-${props.id}-${props?.data?.wfEpoch ?? ''}`}
          {...props}
          {...createSharedRunProps()}
          isRunning={runningIdsRef.current.has(props.id)}
          isSucceeded={succeededIdsRef.current.has(props.id)}
          isFailed={failedIdsRef.current.has(props.id)}
        />
      )
    }
  }, [])

  const renderActionNode = useCallback(
    (subtype: keyof typeof actionRenderers, props: ActionNodeRendererProps) => {
      const renderer =
        actionRenderers[subtype] ?? actionRenderers.actionEmailSendgrid
      return renderer(props)
    },
    [actionRenderers]
  )

  const nodeTypes = useMemo(
    () => ({
      trigger: (props: TriggerNodeRendererProps) => (
        <TriggerNode
          key={`trigger-${props.id}-${(props?.data as any)?.wfEpoch ?? ''}`}
          {...props}
          isRunning={runningIdsRef.current.has(props.id)}
          isSucceeded={succeededIdsRef.current.has(props.id)}
          isFailed={failedIdsRef.current.has(props.id)}
          onRun={async (nodeId) => {
            invokeRunWorkflowRef.current?.(nodeId)
          }}
          planTier={normalizedPlanTierRef.current}
          onRestrictionNotice={onRestrictionNoticeRef.current}
          canEdit={canEditRef.current}
          runAvailability={runAvailability}
        />
      ),
      condition: (props: ConditionNodeRendererProps) => (
        <ConditionNode
          key={`condition-${props.id}-${(props?.data as any)?.wfEpoch ?? ''}`}
          {...props}
          isRunning={runningIdsRef.current.has(props.id)}
          isSucceeded={succeededIdsRef.current.has(props.id)}
          isFailed={failedIdsRef.current.has(props.id)}
          canEdit={canEditRef.current}
        />
      ),
      delay: (props: DelayNodeRendererProps) => (
        <DelayNode
          key={`delay-${props.id}-${(props?.data as any)?.wfEpoch ?? ''}`}
          {...props}
          isRunning={runningIdsRef.current.has(props.id)}
          isSucceeded={succeededIdsRef.current.has(props.id)}
          isFailed={failedIdsRef.current.has(props.id)}
          canEdit={canEditRef.current}
        />
      ),
      formatter: (props: FormatterNodeRendererProps) => (
        <FormatterNode
          key={`formatter-${props.id}-${(props?.data as any)?.wfEpoch ?? ''}`}
          {...props}
          isRunning={runningIdsRef.current.has(props.id)}
          isSucceeded={succeededIdsRef.current.has(props.id)}
          isFailed={failedIdsRef.current.has(props.id)}
          canEdit={canEditRef.current}
        />
      ),
      actionEmailSendgrid: (props: ActionNodeRendererProps) =>
        renderActionNode('actionEmailSendgrid', props),
      actionEmailMailgun: (props: ActionNodeRendererProps) =>
        renderActionNode('actionEmailMailgun', props),
      actionEmailAmazonSes: (props: ActionNodeRendererProps) =>
        renderActionNode('actionEmailAmazonSes', props),
      actionEmail: (props: ActionNodeRendererProps) => {
        const subtype = determineActionSubtype(props?.data)
        return renderActionNode(subtype as keyof typeof actionRenderers, props)
      },
      actionSlack: (props: ActionNodeRendererProps) =>
        renderActionNode('actionSlack', props),
      actionTeams: (props: ActionNodeRendererProps) =>
        renderActionNode('actionTeams', props),
      actionGoogleChat: (props: ActionNodeRendererProps) =>
        renderActionNode('actionGoogleChat', props),
      actionSheets: (props: ActionNodeRendererProps) =>
        renderActionNode('actionSheets', props),
      actionHttp: (props: ActionNodeRendererProps) =>
        renderActionNode('actionHttp', props),
      actionAsana: (props: ActionNodeRendererProps) =>
        renderActionNode('actionAsana', props),
      actionNotion: (props: ActionNodeRendererProps) =>
        renderActionNode('actionNotion', props),
      actionCode: (props: ActionNodeRendererProps) =>
        renderActionNode('actionCode', props),
      action: (props: ActionNodeRendererProps) => {
        const subtype = determineActionSubtype(props?.data)
        return renderActionNode(subtype as keyof typeof actionRenderers, props)
      }
    }),
    [determineActionSubtype, renderActionNode, runAvailability]
  )

  const onNodesChange = useCallback(
    (changes: NodeChange<WorkflowNode>[]) => {
      if (!canEditRef.current) return
      const currentNodes = useWorkflowStore.getState().nodes
      const nextNodes = applyNodeChanges(changes, currentNodes)
      if (nextNodes === currentNodes) return
      const normalizedNodes = normalizeNodesForState(nextNodes)
      setNodes(normalizedNodes)
    },
    [setNodes]
  )

  const onEdgesChange = useCallback(
    (changes: EdgeChange<WorkflowEdge>[]) => {
      if (!canEditRef.current) return
      const currentEdges = useWorkflowStore.getState().edges
      const nextEdges = applyEdgeChanges(changes, currentEdges)
      if (nextEdges === currentEdges) return
      const normalizedEdges = normalizeEdgesForState(nextEdges)
      setEdges(normalizedEdges)
    },
    [setEdges]
  )

  const onConnect = useCallback(
    (params: Connection) => {
      if (!canEditRef.current) return
      const outcomeLabel =
        params?.sourceHandle === 'cond-true'
          ? 'True'
          : params?.sourceHandle === 'cond-false'
            ? 'False'
            : null
      const currentEdges = useWorkflowStore.getState().edges
      const withNewEdge = addEdge<WorkflowEdge>(
        {
          ...params,
          type: 'nodeEdge',
          label: outcomeLabel,
          data: {
            edgeType: 'default',
            outcome: outcomeLabel?.toLowerCase?.()
          }
        },
        currentEdges
      )
      const normalizedEdges = normalizeEdgesForState(withNewEdge)
      setEdges(normalizedEdges)
    },
    [setEdges]
  )

  const addNodeAtPosition = useCallback(
    (rawType: string, position: XYPosition) => {
      if (!canEditRef.current) return
      const currentNodes = useWorkflowStore.getState().nodes
      if (isSoloPlan && currentNodes.length >= 10) {
        onRestrictionNotice?.(
          'Solo plan workflows support up to 10 nodes. Upgrade in Settings > Plan to add more steps.'
        )
        return
      }
      const dropDescriptor = normalizeDropType(rawType)
      const label = generateUniqueLabel(dropDescriptor.labelBase, currentNodes)
      const nodeIdPrefix = dropDescriptor.idPrefix.replace(/[^a-z0-9]+/gi, '-')

      // Use UUID for trigger nodes to ensure backend compatibility
      const newNodeId =
        dropDescriptor.nodeType === 'trigger'
          ? uuidv4()
          : `${nodeIdPrefix}-${Date.now()}`
      const newNode: WorkflowNode = {
        id: newNodeId,
        type: dropDescriptor.nodeType,
        position,
        data: {
          label,
          expanded: dropDescriptor.expanded,
          dirty: true,
          inputs: [],
          labelError: null,
          hasLabelValidationError: false,
          ...dropDescriptor.data
        }
      }
      const normalizedNodes = normalizeNodesForState([...currentNodes, newNode])
      setNodes(normalizedNodes)
    },
    [isSoloPlan, onRestrictionNotice, setNodes]
  )

  const getViewportCenterPosition = useCallback((): XYPosition => {
    const bounds = canvasBoundsRef.current?.getBoundingClientRect()
    const fallbackPoint = {
      x: window.innerWidth / 2,
      y: window.innerHeight / 2
    }
    const point = bounds
      ? { x: bounds.left + bounds.width / 2, y: bounds.top + bounds.height / 2 }
      : fallbackPoint
    return reactFlow.screenToFlowPosition(point)
  }, [reactFlow])

  const handleQuickAdd = useCallback(
    (rawType: string) => {
      const position = getViewportCenterPosition()
      addNodeAtPosition(rawType, position)
    },
    [addNodeAtPosition, getViewportCenterPosition]
  )

  useEffect(() => {
    if (!onRegisterQuickAdd) return
    onRegisterQuickAdd(handleQuickAdd)
    return () => {
      onRegisterQuickAdd(() => {})
    }
  }, [handleQuickAdd, onRegisterQuickAdd])

  const onDrop = useCallback(
    (event: DragEvent<HTMLDivElement>) => {
      event.preventDefault()
      const rawType = event.dataTransfer.getData('application/reactflow')
      if (!rawType) return
      const position = reactFlow.screenToFlowPosition({
        x: event.clientX,
        y: event.clientY
      })
      addNodeAtPosition(rawType, position)
    },
    [addNodeAtPosition, reactFlow]
  )

  const onDragOver = useCallback((event: DragEvent<HTMLDivElement>) => {
    event.preventDefault()
    event.dataTransfer.dropEffect = 'move'
  }, [])

  const panNodeIntoView = useCallback(
    (nodeId: string) => {
      const node = reactFlow.getNode(nodeId)
      if (!node) return
      const zoom =
        typeof (reactFlow as any).getZoom === 'function'
          ? (reactFlow as any).getZoom()
          : ((reactFlow as any).viewport?.zoom ?? 1)
      const width =
        (node.measured?.width as number | undefined) ??
        (node.width as number | undefined) ??
        256
      const height =
        (node.measured?.height as number | undefined) ??
        (node.height as number | undefined) ??
        200
      const pos = node.position
      const centerX = pos.x + width / 2
      const centerY = pos.y + height / 2
      const reservePx = 420
      const reserveFlow = reservePx / Math.max(zoom, 0.01)
      reactFlow.setCenter(centerX + reserveFlow, centerY, {
        zoom,
        duration: 200
      })
    },
    [reactFlow]
  )

  const lastExplicitFlyoutOpenRef = useRef<{ id: string | null; ts: number }>({
    id: null,
    ts: 0
  })

  const handleFlyoutOpen = useCallback(
    (nodeId: string | null) => {
      lastExplicitFlyoutOpenRef.current = { id: nodeId, ts: Date.now() }
      if (!nodeId) {
        syncSelectionToStore(null)
        setFlyoutNodeId((prev) => (prev === null ? prev : null))
        return
      }

      syncSelectionToStore(nodeId)
      setFlyoutNodeId((prev) => {
        if (prev === nodeId) return prev
        requestAnimationFrame(() => panNodeIntoView(nodeId))
        return nodeId
      })
    },
    [panNodeIntoView, syncSelectionToStore]
  )

  const handleSelectionChange = useCallback(
    ({
      nodes: selectedNodes
    }: OnSelectionChangeParams<WorkflowNode, WorkflowEdge>) => {
      const lastSelected =
        selectedNodes && selectedNodes.length > 0
          ? selectedNodes[selectedNodes.length - 1]
          : null
      const nextId = lastSelected?.id ?? null
      const now = Date.now()
      const lastExplicit = lastExplicitFlyoutOpenRef.current
      const recentExplicit =
        lastExplicit.id && now - lastExplicit.ts < 400 ? lastExplicit.id : null
      if (!nextId && recentExplicit) {
        return
      }
      syncSelectionToStore(nextId)
      if (!nextId) {
        setFlyoutNodeId(null)
        return
      }
      // Do not auto-open or switch the flyout on selection alone; only the
      // dashed hint surface calls handleFlyoutOpen. Leaving flyout state
      // untouched keeps a manually opened panel visible when clicking the node body.
      // Edge selection is intentionally left to React Flow so custom edge menus work.
    },
    [syncSelectionToStore]
  )

  const noopFlyout = useCallback(() => undefined, [])

  const flyoutContextValue = useMemo(
    () => ({
      openFlyout: handleFlyoutOpen,
      activeNodeId: flyoutNodeId,
      isFlyoutRender: false
    }),
    [handleFlyoutOpen, flyoutNodeId]
  )

  const flyoutPreviewContextValue = useMemo(
    () => ({
      openFlyout: noopFlyout,
      activeNodeId: flyoutNodeId,
      isFlyoutRender: true
    }),
    [noopFlyout, flyoutNodeId]
  )

  // Flyout field renderers are implemented as standalone components below.

  const flyoutSubtype = useMemo<ActionDropSubtype | null>(() => {
    if (!flyoutNode) return null
    const t = (flyoutNode.type || '').toString()
    if (t === 'trigger' || t === 'condition' || t === 'formatter') return null
    const known = new Set([
      'actionEmailSendgrid',
      'actionEmailMailgun',
      'actionEmailAmazonSes',
      'actionEmailSmtp',
      'actionSlack',
      'actionTeams',
      'actionGoogleChat',
      'actionSheets',
      'actionHttp',
      'actionCode',
      'actionAsana',
      'actionNotion'
    ])
    if (known.has(t)) {
      return t as ActionDropSubtype
    }
    return determineActionSubtype(flyoutNode.data as ActionNodeData | null)
  }, [flyoutNode, determineActionSubtype])

  const selectedNodeLabel = useMemo(() => {
    if (!flyoutNode) return null
    const rawLabel = (flyoutNode.data as { label?: unknown } | undefined)?.label
    if (typeof rawLabel === 'string' && rawLabel.trim().length > 0) {
      return rawLabel
    }
    switch (flyoutNode.type) {
      case 'trigger':
        return 'Trigger'
      case 'condition':
        return 'Condition'
      default:
        return 'Action'
    }
  }, [flyoutNode])

  const handleEdgeTypeChange = useCallback(
    (edgeId: string, newType: WorkflowEdgeData['edgeType']) => {
      if (!canEditRef.current) return
      const normalizedType: WorkflowEdgeStyle =
        newType === 'bold' || newType === 'dashed' ? newType : 'default'
      const currentEdges = useWorkflowStore.getState().edges
      const nextEdges = currentEdges.map<WorkflowEdge>((edge) =>
        edge.id === edgeId
          ? {
              ...edge,
              data: { ...edge.data, edgeType: normalizedType }
            }
          : edge
      )
      if (nextEdges === currentEdges) return
      const normalizedEdges = normalizeEdgesForState(nextEdges)
      setEdges(normalizedEdges)
    },
    [setEdges]
  )

  const handleEdgeDelete = useCallback(
    (edgeId: string) => {
      if (!canEditRef.current) return
      const currentEdges = useWorkflowStore.getState().edges
      const nextEdges = currentEdges.filter((e) => e.id !== edgeId)
      if (nextEdges.length !== currentEdges.length) {
        const normalizedEdges = normalizeEdgesForState(nextEdges)
        setEdges(normalizedEdges)
      }
    },
    [setEdges]
  )

  const edgeTypes = useMemo<
    Record<string, (props: WorkflowEdgeRendererProps) => React.ReactNode>
  >(
    () => ({
      nodeEdge: (edgeProps: WorkflowEdgeRendererProps) => (
        <NodeEdge
          {...edgeProps}
          onDelete={handleEdgeDelete}
          onChangeType={handleEdgeTypeChange}
        />
      ),
      // Map legacy/default edges to our custom edge so the context menu appears
      default: (edgeProps: WorkflowEdgeRendererProps) => (
        <NodeEdge
          {...edgeProps}
          onDelete={handleEdgeDelete}
          onChangeType={handleEdgeTypeChange}
        />
      )
    }),
    [handleEdgeDelete, handleEdgeTypeChange]
  )

  return (
    <WorkflowFlyoutProvider value={flyoutContextValue}>
      <div className="flex flex-1 min-h-0 flex-col md:flex-row">
        <div ref={canvasBoundsRef} className="flex-1 min-h-0">
          <ReactFlow<WorkflowNode, WorkflowEdge>
            key={workflowId || 'no-workflow'}
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onConnect={onConnect}
            nodeTypes={nodeTypes}
            edgeTypes={edgeTypes}
            onDrop={onDrop}
            onDragOver={onDragOver}
            fitView
            proOptions={{ hideAttribution: true }}
            nodesDraggable={canEdit}
            nodesConnectable={canEdit}
            className="h-full w-full"
            onSelectionChange={handleSelectionChange}
            minZoom={0.1}
          >
            <Background gap={16} size={1} />
            <div className={isDark ? 'text-white' : 'text-black'}>
              <CustomControls />
              <MiniMap
                nodeColor={(node) =>
                  node.type === 'trigger' ? '#10B981' : '#6366F1'
                }
                style={{ background: 'transparent' }}
              />
            </div>
          </ReactFlow>
        </div>

        <AnimatePresence>
          {flyoutNode ? (
            <WorkflowFlyoutProvider value={flyoutPreviewContextValue}>
              <motion.aside
                key={flyoutNode.id}
                initial={{ opacity: 0, x: 28 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 28 }}
                transition={{ duration: 0.2, ease: 'easeOut' }}
                className="flex w-full md:w-[720px] xl:w-[840px] shrink-0 border-t md:border-t-0 md:border-l border-zinc-200 dark:border-zinc-800 bg-white/95 dark:bg-zinc-900/95 backdrop-blur flex-col"
              >
                <div className="px-4 py-3 border-b border-zinc-200 dark:border-zinc-800 flex items-start justify-between gap-2">
                  <div>
                    <div className="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
                      Node details
                    </div>
                    <div className="mt-1 text-sm font-semibold text-zinc-900 dark:text-zinc-100 truncate">
                      {selectedNodeLabel}
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => setFlyoutNodeId(null)}
                    className="p-1 rounded hover:bg-zinc-100 dark:hover:bg-zinc-800 text-zinc-500 hover:text-zinc-700 dark:text-zinc-400 dark:hover:text-zinc-200"
                    aria-label="Close details"
                    title="Close details"
                  >
                    <X size={16} />
                  </button>
                </div>
                <div className="flex-1 min-h-0 overflow-y-auto overflow-x-visible themed-scroll px-4 py-4">
                  <div className="rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-sm p-4 overflow-visible">
                    {flyoutNode.type === 'trigger' ? (
                      <FlyoutTriggerFields
                        nodeId={flyoutNode.id}
                        isSoloPlan={isSoloPlan}
                      />
                    ) : flyoutNode.type === 'condition' ? (
                      <FlyoutConditionFields nodeId={flyoutNode.id} />
                    ) : flyoutNode.type === 'delay' ? (
                      <FlyoutDelayFields nodeId={flyoutNode.id} />
                    ) : flyoutNode.type === 'formatter' ? (
                      <FlyoutFormatterFields nodeId={flyoutNode.id} />
                    ) : flyoutSubtype ? (
                      <FlyoutActionFields
                        nodeId={flyoutNode.id}
                        subtype={flyoutSubtype}
                        normalizedPlanTier={normalizedPlanTier}
                        canEdit={canEditRef.current}
                        onRestrictionNotice={onRestrictionNoticeRef.current}
                      />
                    ) : (
                      <p className="text-xs text-zinc-500">
                        Fields for this node type are not available in the
                        flyout yet.
                      </p>
                    )}
                  </div>
                </div>
              </motion.aside>
            </WorkflowFlyoutProvider>
          ) : null}
        </AnimatePresence>
      </div>
    </WorkflowFlyoutProvider>
  )
}

interface FlyoutActionFieldsProps {
  nodeId: string
  subtype: ActionDropSubtype
  normalizedPlanTier: ReturnType<typeof normalizePlanTier>
  canEdit: boolean
  onRestrictionNotice?: (message: string) => void
}

function FlyoutActionFields({
  nodeId,
  subtype,
  normalizedPlanTier,
  canEdit,
  onRestrictionNotice
}: FlyoutActionFieldsProps) {
  const allNodes = useWorkflowStore(selectNodes)
  const allEdges = useWorkflowStore(selectEdges)
  const setEdges = useWorkflowStore((state) => state.setEdges)
  const getNodeLabel = useCallback((n: WorkflowNode) => {
    const rawLabel =
      n.data && typeof n.data === 'object' && 'label' in n.data
        ? (n.data.label as unknown)
        : undefined
    if (typeof rawLabel === 'string' && rawLabel.trim()) return rawLabel
    switch (n.type) {
      case 'trigger':
        return 'Trigger'
      case 'condition':
        return 'Condition'
      default:
        return 'Action'
    }
  }, [])
  const inputNodeOptions = useMemo(
    () =>
      allNodes
        .filter((n) => n.id !== nodeId)
        .map((n) => ({ label: getNodeLabel(n), value: n.id })),
    [allNodes, getNodeLabel, nodeId]
  )
  const outputNodeOptions = useMemo(
    () =>
      allNodes
        .filter((n) => n.id !== nodeId && n.type !== 'trigger')
        .map((n) => ({ label: getNodeLabel(n), value: n.id })),
    [allNodes, getNodeLabel, nodeId]
  )

  const currentInputId = useMemo(() => {
    const incoming = allEdges.filter((e) => e.target === nodeId)
    return incoming[0]?.source ?? ''
  }, [allEdges, nodeId])
  const currentOutputId = useMemo(() => {
    const outgoing = allEdges.filter(
      (e) => e.source === nodeId && !e.sourceHandle
    )
    return outgoing[0]?.target ?? ''
  }, [allEdges, nodeId])

  const handleChangeInput = useCallback(
    (nextSourceId: string) => {
      if (!nextSourceId || nextSourceId === currentInputId) return
      const state = useWorkflowStore.getState()
      const base = state.edges.filter((e) => e.target !== nodeId)
      const newEdge: WorkflowEdge = {
        id: `e-${nextSourceId}-${nodeId}-${Date.now()}`,
        source: nextSourceId,
        target: nodeId,
        type: 'nodeEdge',
        data: { edgeType: 'default' }
      }
      setEdges(normalizeEdgesForState([...base, newEdge]))
    },
    [currentInputId, nodeId, setEdges]
  )

  const handleChangeOutput = useCallback(
    (nextTargetId: string) => {
      if (!nextTargetId || nextTargetId === currentOutputId) return
      const targetNode = allNodes.find((n) => n.id === nextTargetId)
      if (targetNode?.type === 'trigger') return
      const state = useWorkflowStore.getState()
      const base = state.edges.filter(
        (e) => !(e.source === nodeId && !e.sourceHandle)
      )
      const newEdge: WorkflowEdge = {
        id: `e-${nodeId}-${nextTargetId}-${Date.now()}`,
        source: nodeId,
        target: nextTargetId,
        type: 'nodeEdge',
        data: { edgeType: 'default' }
      }
      setEdges(normalizeEdgesForState([...base, newEdge]))
    },
    [allNodes, currentOutputId, nodeId, setEdges]
  )

  const nodeData = useWorkflowStore(
    useCallback(
      (state) =>
        (state.nodes.find((n) => n.id === nodeId)?.data as
          | ActionNodeData
          | undefined) ?? null,
      [nodeId]
    )
  )

  const controller = useActionNodeController({
    id: nodeId,
    nodeData: nodeData ?? null,
    planTier: normalizedPlanTier,
    effectiveCanEdit: canEdit,
    onRestrictionNotice,
    toggleExpanded: () => undefined,
    remove: () => useWorkflowStore.getState().removeNode(nodeId)
  })

  const slackRestriction = useMessagingActionRestriction({
    provider: 'slack',
    isSoloPlan: controller.isSoloPlan,
    onRestrictionNotice,
    enabled: subtype === 'actionSlack'
  })
  const teamsRestriction = useMessagingActionRestriction({
    provider: 'teams',
    isSoloPlan: controller.isSoloPlan,
    onRestrictionNotice,
    enabled: subtype === 'actionTeams'
  })
  const messagingRestriction =
    subtype === 'actionSlack'
      ? slackRestriction
      : subtype === 'actionTeams'
        ? teamsRestriction
        : { planRestrictionMessage: null, isRestricted: false }

  const combinedRestrictionMessage =
    messagingRestriction.planRestrictionMessage ??
    controller.planRestrictionMessage

  const renderFields = () => {
    switch (subtype) {
      case 'actionEmailSendgrid':
        return (
          <SendGridAction
            nodeId={nodeId}
            canEdit={controller.effectiveCanEdit}
          />
        )
      case 'actionEmailMailgun':
        return (
          <MailGunAction
            nodeId={nodeId}
            canEdit={controller.effectiveCanEdit}
          />
        )
      case 'actionEmailAmazonSes':
        return (
          <AmazonSESAction
            nodeId={nodeId}
            canEdit={controller.effectiveCanEdit}
          />
        )
      case 'actionSlack':
        return (
          <SlackAction
            nodeId={nodeId}
            canEdit={controller.effectiveCanEdit}
            isRestricted={messagingRestriction.isRestricted}
          />
        )
      case 'actionTeams':
        return (
          <TeamsAction
            nodeId={nodeId}
            canEdit={controller.effectiveCanEdit}
            isRestricted={messagingRestriction.isRestricted}
          />
        )
      case 'actionGoogleChat':
        return (
          <GoogleChatAction
            nodeId={nodeId}
            canEdit={controller.effectiveCanEdit}
          />
        )
      case 'actionSheets':
        return controller.planRestrictionMessage ? null : (
          <SheetsAction nodeId={nodeId} canEdit={controller.effectiveCanEdit} />
        )
      case 'actionHttp':
        return (
          <HttpRequestAction
            nodeId={nodeId}
            canEdit={controller.effectiveCanEdit}
          />
        )
      case 'actionAsana':
        return controller.planRestrictionMessage ? null : (
          <AsanaAction
            nodeId={nodeId}
            canEdit={controller.effectiveCanEdit}
            planTier={normalizedPlanTier}
          />
        )
      case 'actionNotion':
        return controller.planRestrictionMessage ? null : (
          <NotionAction nodeId={nodeId} canEdit={controller.effectiveCanEdit} />
        )
      case 'actionCode':
        return (
          <RunCustomCodeAction
            nodeId={nodeId}
            canEdit={controller.effectiveCanEdit}
          />
        )
      default:
        return null
    }
  }

  return (
    <>
      <div className="flex flex-col gap-3">
        <div className="space-y-2">
          <div>
            <label className="block text-[10px] font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
              Input Node
            </label>
            <NodeDropdownField
              options={[{ label: 'Nodes', options: inputNodeOptions }]}
              value={currentInputId}
              onChange={handleChangeInput}
              placeholder="Select input node"
            />
          </div>
          <div>
            <label className="block text-[10px] font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
              Output Node
            </label>
            <NodeDropdownField
              options={[{ label: 'Nodes', options: outputNodeOptions }]}
              value={currentOutputId}
              onChange={handleChangeOutput}
              placeholder="Select output node"
            />
          </div>
        </div>

        <NodeHeader
          nodeId={nodeId}
          label={controller.label}
          dirty={controller.dirty}
          hasValidationErrors={controller.combinedHasValidationErrors}
          expanded={true}
          onLabelChange={controller.handleLabelChange}
          onExpanded={() => undefined}
          onConfirmingDelete={(e) => {
            e.preventDefault()
            e.stopPropagation()
            controller.requestDelete()
          }}
        />
        {controller.labelError ? (
          <p className="text-xs text-red-500">{controller.labelError}</p>
        ) : null}
        {combinedRestrictionMessage ? (
          <div className="rounded-lg border border-amber-300 bg-amber-50 p-3 text-xs text-amber-900 shadow-sm dark:border-amber-400/60 dark:bg-amber-500/10 dark:text-amber-100">
            <div className="flex items-start justify-between gap-2">
              <span>{combinedRestrictionMessage}</span>
              <button
                type="button"
                onClick={controller.handlePlanUpgradeClick}
                className="rounded border border-amber-400 px-2 py-1 text-[10px] font-semibold uppercase tracking-wide text-amber-800 transition hover:bg-amber-100 dark:border-amber-400/60 dark:text-amber-100 dark:hover:bg-amber-400/10"
              >
                Upgrade
              </button>
            </div>
          </div>
        ) : null}

        <div className="mt-2 space-y-3">{renderFields()}</div>
        <div className="mt-4">
          <p className="text-xs text-zinc-500">Execution Options</p>
          <div className="mt-2 flex flex-wrap gap-2 items-center">
            <NodeInputField
              type="number"
              value={String(controller.timeout)}
              onChange={(value) =>
                controller.handleTimeoutChange(Number(value))
              }
              className="w-24 text-xs p-1 rounded border border-zinc-300 dark:border-zinc-600 bg-transparent"
            />
            <span className="text-xs">ms timeout</span>
            <NodeInputField
              type="number"
              value={String(controller.retries)}
              onChange={(value) =>
                controller.handleRetriesChange(Number(value))
              }
              className="w-16 text-xs p-1 rounded border border-zinc-300 dark:border-zinc-600 bg-transparent"
            />
            <span className="text-xs">retries</span>
            <NodeCheckBoxField
              checked={controller.stopOnError}
              onChange={(value) =>
                controller.handleStopOnErrorChange(Boolean(value))
              }
            >
              Stop on error
            </NodeCheckBoxField>
          </div>
        </div>
      </div>

      <DeleteNodeModal
        open={controller.confirmingDelete}
        onCancel={controller.cancelDelete}
        onConfirm={controller.confirmDelete}
      />
    </>
  )
}

interface FlyoutTriggerFieldsProps {
  nodeId: string
  isSoloPlan: boolean
}

function FlyoutTriggerFields({ nodeId, isSoloPlan }: FlyoutTriggerFieldsProps) {
  const allNodes = useWorkflowStore(selectNodes)
  const allEdges = useWorkflowStore(selectEdges)
  const setEdges = useWorkflowStore((state) => state.setEdges)
  const nodeData = useWorkflowStore(
    useCallback(
      (state) => (state.nodes.find((n) => n.id === nodeId)?.data as any) ?? {},
      [nodeId]
    )
  )
  const updateNodeData = useWorkflowStore((s) => s.updateNodeData)
  const getNodeLabel = useCallback((n: Node) => {
    const rawLabel = (n.data as any)?.label
    if (typeof rawLabel === 'string' && rawLabel.trim()) return rawLabel
    switch (n.type) {
      case 'trigger':
        return 'Trigger'
      case 'condition':
        return 'Condition'
      default:
        return 'Action'
    }
  }, [])
  const nodeOptions = useMemo(
    () =>
      allNodes
        .filter((n) => n.id !== nodeId && n.type !== 'trigger')
        .map((n) => ({ label: getNodeLabel(n), value: n.id })),
    [allNodes, getNodeLabel, nodeId]
  )
  const currentOutputId = useMemo(() => {
    const outgoing = allEdges.filter((e) => e.source === nodeId)
    return outgoing[0]?.target ?? ''
  }, [allEdges, nodeId])
  const handleChangeOutput = useCallback(
    (nextTargetId: string) => {
      if (!nextTargetId || nextTargetId === currentOutputId) return
      const targetNode = allNodes.find((n) => n.id === nextTargetId)
      if (targetNode?.type === 'trigger') return
      const state = useWorkflowStore.getState()
      const base = state.edges.filter((e) => e.source !== nodeId)
      const newEdge = {
        id: `e-${nodeId}-${nextTargetId}-${Date.now()}`,
        source: nodeId,
        target: nextTargetId,
        type: 'nodeEdge',
        data: { edgeType: 'default' }
      } as any
      setEdges(normalizeEdgesForState([...base, newEdge]))
    },
    [allNodes, currentOutputId, nodeId, setEdges]
  )

  const labelError: string | null = nodeData?.labelError ?? null
  const triggerType: string =
    typeof nodeData?.triggerType === 'string' ? nodeData.triggerType : 'Manual'
  const normalizedTriggerType = triggerType.trim().toLowerCase() || 'manual'
  const isScheduleTrigger = normalizedTriggerType === 'schedule'
  const isNotionTrigger =
    normalizedTriggerType === 'notion.new_database_row' ||
    normalizedTriggerType === 'notion.updated_database_row'
  const isWebhookTrigger = normalizedTriggerType === 'webhook'
  const webhookEventType =
    typeof nodeData?.event_type === 'string' ? nodeData.event_type : ''
  const webhookEventTypeMissing = isWebhookTrigger && !webhookEventType.trim()
  const [confirmingDelete, setConfirmingDelete] = useState(false)

  const handleLabelChange = useCallback(
    (value: string) => updateNodeData(nodeId, { label: value, dirty: true }),
    [nodeId, updateNodeData]
  )
  const handleDeleteClick = useCallback(() => {
    setConfirmingDelete(true)
  }, [])
  const handleCancelDelete = useCallback(() => setConfirmingDelete(false), [])
  const handleConfirmDelete = useCallback(() => {
    setConfirmingDelete(false)
    useWorkflowStore.getState().removeNode(nodeId)
  }, [nodeId])
  const handleTriggerTypeChange = useCallback(
    (value: string) => {
      const normalized = value.trim().toLowerCase()
      if (normalized === 'webhook') {
        updateNodeData(nodeId, {
          triggerType: value,
          event_type:
            typeof nodeData?.event_type === 'string' ? nodeData.event_type : '',
          dirty: true
        })
        return
      }
      updateNodeData(nodeId, {
        triggerType: value,
        event_type: undefined,
        dirty: true
      })
    },
    [nodeId, nodeData?.event_type, updateNodeData]
  )

  const inputs = Array.isArray(nodeData?.inputs) ? nodeData.inputs : []
  const handleInputsChange = useCallback(
    (vars: { key: string; value: string }[]) =>
      updateNodeData(nodeId, { inputs: vars, dirty: true }),
    [nodeId, updateNodeData]
  )

  const currentWorkspace = useAuth(selectCurrentWorkspace)
  const workspaceId = currentWorkspace?.workspace.id ?? null
  const notionConnectionScope =
    typeof nodeData?.connectionScope === 'string'
      ? nodeData.connectionScope.trim()
      : ''
  const notionConnectionId =
    typeof nodeData?.connectionId === 'string'
      ? nodeData.connectionId.trim()
      : ''
  const notionDatabaseId =
    typeof nodeData?.databaseId === 'string' ? nodeData.databaseId.trim() : ''

  const [notionConnections, setNotionConnections] =
    useState<ProviderConnectionSet | null>(null)
  const [notionConnectionsLoading, setNotionConnectionsLoading] =
    useState(false)
  const [notionConnectionsError, setNotionConnectionsError] = useState<
    string | null
  >(null)

  const sanitizeNotionConnections = useCallback(
    (connections: ProviderConnectionSet) => {
      const personal = (connections.personal ?? []).map((entry) => {
        const requiresReconnect = Boolean(entry.requiresReconnect)
        const id = entry.id ?? entry.connectionId ?? null
        return {
          ...entry,
          id,
          connectionId: entry.connectionId ?? entry.id ?? undefined,
          connected: Boolean(entry.connected && id && !requiresReconnect),
          requiresReconnect
        }
      })
      const workspace = (connections.workspace ?? [])
        .filter((entry) => !entry.requiresReconnect)
        .map((entry) => ({ ...entry }))
      return { personal, workspace }
    },
    []
  )

  const pickNotionConnections = useCallback(
    (
      snapshot: GroupedConnectionsSnapshot | null
    ): ProviderConnectionSet | null => {
      if (!snapshot) return null
      const personal = (snapshot.personal ?? [])
        .filter((entry) => entry.provider === 'notion')
        .map((entry) => ({ ...entry }))
      const workspace = (snapshot.workspace ?? [])
        .filter((entry) => entry.provider === 'notion')
        .map((entry) => ({ ...entry }))
      if (personal.length === 0 && workspace.length === 0) {
        return null
      }
      return { personal, workspace }
    },
    []
  )

  useEffect(() => {
    if (!isNotionTrigger) {
      setNotionConnections(null)
      setNotionConnectionsLoading(false)
      setNotionConnectionsError(null)
      return
    }

    let active = true
    const cached = pickNotionConnections(getCachedConnections(workspaceId))
    if (cached) {
      setNotionConnections(sanitizeNotionConnections(cached))
      setNotionConnectionsLoading(false)
    } else {
      setNotionConnections(null)
    }

    const unsubscribe = subscribeToConnectionUpdates(
      (snapshot) => {
        if (!active) return
        const notionSnapshot = pickNotionConnections(snapshot)
        if (!notionSnapshot) {
          setNotionConnections(null)
          setNotionConnectionsLoading(false)
          return
        }
        setNotionConnections(sanitizeNotionConnections(notionSnapshot))
        setNotionConnectionsLoading(false)
        setNotionConnectionsError(null)
      },
      { workspaceId }
    )

    if (!cached) {
      setNotionConnectionsLoading(true)
      fetchConnections({ workspaceId })
        .then((grouped) => {
          if (!active) return
          const notionSnapshot = pickNotionConnections(grouped)
          setNotionConnections(
            notionSnapshot ? sanitizeNotionConnections(notionSnapshot) : null
          )
          setNotionConnectionsError(null)
        })
        .catch((err) => {
          if (!active) return
          setNotionConnectionsError(errorMessage(err))
          setNotionConnections(null)
        })
        .finally(() => {
          if (!active) return
          setNotionConnectionsLoading(false)
        })
    }

    return () => {
      active = false
      unsubscribe()
    }
  }, [
    isNotionTrigger,
    pickNotionConnections,
    sanitizeNotionConnections,
    workspaceId
  ])

  const notionActiveConnection = useMemo(() => {
    if (!notionConnectionScope || !notionConnectionId) return null
    const normalized =
      notionConnectionScope === 'personal' ||
      notionConnectionScope === 'workspace'
        ? (notionConnectionScope as ConnectionScope)
        : null
    if (!normalized) return null
    return { scope: normalized, id: notionConnectionId }
  }, [notionConnectionId, notionConnectionScope])

  const notionConnectionOptions = useMemo<NodeDropdownOptionGroup[]>(() => {
    if (!notionConnections) return []
    const groups: NodeDropdownOptionGroup[] = []
    if (notionConnections.personal.length > 0) {
      groups.push({
        label: 'Personal connections',
        options: notionConnections.personal.map((entry) => {
          const label =
            entry.ownerName ||
            entry.accountEmail ||
            entry.ownerEmail ||
            'Personal Notion'
          const id = entry.id ?? entry.connectionId ?? ''
          return {
            label: entry.requiresReconnect ? `${label} (reconnect)` : label,
            value: `${'personal'}:${id || ''}`,
            disabled: !id || entry.requiresReconnect
          }
        })
      })
    }
    if (notionConnections.workspace.length > 0) {
      groups.push({
        label: 'Workspace connections',
        options: notionConnections.workspace.map((entry) => {
          const label =
            entry.workspaceName || entry.sharedByName || 'Workspace Notion'
          const id = entry.id ?? entry.workspaceConnectionId ?? ''
          return {
            label: entry.requiresReconnect ? `${label} (reconnect)` : label,
            value: `${'workspace'}:${id || ''}`,
            disabled: !id || entry.requiresReconnect
          }
        })
      })
    }
    return groups
  }, [notionConnections])

  const notionSelectedConnectionValue = useMemo(() => {
    if (!notionConnectionScope || !notionConnectionId) return ''
    return `${notionConnectionScope}:${notionConnectionId}`
  }, [notionConnectionId, notionConnectionScope])

  const handleNotionConnectionChange = useCallback(
    (value: string) => {
      const [scopePart, ...rest] = value.split(':')
      const idPart = rest.join(':').trim()
      if (!idPart || (scopePart !== 'personal' && scopePart !== 'workspace')) {
        updateNodeData(nodeId, {
          connectionScope: '',
          connectionId: '',
          databaseId: '',
          dirty: true
        })
        return
      }
      updateNodeData(nodeId, {
        connectionScope: scopePart,
        connectionId: idPart,
        databaseId: '',
        dirty: true
      })
    },
    [nodeId, updateNodeData]
  )

  const [notionDatabaseSearch, setNotionDatabaseSearch] = useState('')
  const [notionDatabases, setNotionDatabases] = useState<NotionDatabase[]>([])
  const [notionDatabasesLoading, setNotionDatabasesLoading] = useState(false)
  const [notionDatabasesError, setNotionDatabasesError] = useState<
    string | null
  >(null)
  const [notionDatabaseCursor, setNotionDatabaseCursor] = useState<
    string | null
  >(null)
  const [notionDatabasesHasMore, setNotionDatabasesHasMore] = useState(false)

  useEffect(() => {
    if (!isNotionTrigger || !notionActiveConnection) {
      setNotionDatabases([])
      setNotionDatabasesLoading(false)
      setNotionDatabasesError(null)
      setNotionDatabaseCursor(null)
      setNotionDatabasesHasMore(false)
      return
    }

    let active = true
    setNotionDatabasesLoading(true)
    setNotionDatabasesError(null)
    const timeout = setTimeout(() => {
      fetchNotionDatabases({
        scope: notionActiveConnection.scope,
        connectionId: notionActiveConnection.id,
        search: notionDatabaseSearch,
        cursor: null
      })
        .then((payload) => {
          if (!active) return
          setNotionDatabases(payload.databases)
          setNotionDatabaseCursor(payload.nextCursor ?? null)
          setNotionDatabasesHasMore(payload.hasMore)
        })
        .catch((err) => {
          if (!active) return
          setNotionDatabasesError(errorMessage(err))
          setNotionDatabases([])
          setNotionDatabaseCursor(null)
          setNotionDatabasesHasMore(false)
        })
        .finally(() => {
          if (!active) return
          setNotionDatabasesLoading(false)
        })
    }, 250)

    return () => {
      active = false
      clearTimeout(timeout)
    }
  }, [isNotionTrigger, notionActiveConnection, notionDatabaseSearch])

  const handleLoadMoreNotionDatabases = useCallback(() => {
    if (!notionActiveConnection || !notionDatabaseCursor) return
    setNotionDatabasesLoading(true)
    setNotionDatabasesError(null)
    fetchNotionDatabases({
      scope: notionActiveConnection.scope,
      connectionId: notionActiveConnection.id,
      search: notionDatabaseSearch,
      cursor: notionDatabaseCursor
    })
      .then((payload) => {
        setNotionDatabases((prev) => [...prev, ...payload.databases])
        setNotionDatabaseCursor(payload.nextCursor ?? null)
        setNotionDatabasesHasMore(payload.hasMore)
      })
      .catch((err) => {
        setNotionDatabasesError(errorMessage(err))
      })
      .finally(() => {
        setNotionDatabasesLoading(false)
      })
  }, [notionActiveConnection, notionDatabaseCursor, notionDatabaseSearch])

  const notionDatabaseOptions = useMemo<NodeDropdownOption[]>(() => {
    return notionDatabases.map((db) => ({
      label: db.name || db.id,
      value: db.id
    }))
  }, [notionDatabases])

  const scheduleConfig = useMemo(
    () => (nodeData?.scheduleConfig as any) || {},
    [nodeData]
  )
  const handleSchedulePatch = useCallback(
    (patch: Record<string, any>) =>
      updateNodeData(nodeId, {
        scheduleConfig: { ...scheduleConfig, ...patch },
        dirty: true
      }),
    [nodeId, scheduleConfig, updateNodeData]
  )

  // Schedule pickers state (mirror TriggerNode behavior)
  const defaultTimezone = useMemo(() => {
    try {
      return new Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'
    } catch {
      return 'UTC'
    }
  }, [])

  const [datePickerOpen, setDatePickerOpen] = useState(false)
  const [timePickerOpen, setTimePickerOpen] = useState(false)
  const [timezonePickerOpen, setTimezonePickerOpen] = useState(false)
  const [timezoneSearch, setTimezoneSearch] = useState('')
  const timezoneDropdownRef = useRef<HTMLDivElement | null>(null)
  const timezoneButtonRef = useRef<HTMLButtonElement | null>(null)
  const [tzPos, setTzPos] = useState<{
    top: number
    left: number
    width: number
  } | null>(null)

  const [datePickerMonth, setDatePickerMonth] = useState<CalendarMonth>(() =>
    getInitialMonth(scheduleConfig?.startDate)
  )
  useEffect(() => {
    setDatePickerMonth((prev) => {
      const next = getInitialMonth(scheduleConfig?.startDate)
      return prev.year === next.year && prev.month === next.month ? prev : next
    })
  }, [scheduleConfig?.startDate])

  const datePickerContainerRef = useRef<HTMLDivElement | null>(null)
  const timePickerContainerRef = useRef<HTMLDivElement | null>(null)
  const timezonePickerContainerRef = useRef<HTMLDivElement | null>(null)

  const timezoneOptions = useMemo(() => {
    const options: string[] = []
    if (typeof Intl !== 'undefined') {
      const maybeSupported = (Intl as any).supportedValuesOf
      if (typeof maybeSupported === 'function') {
        try {
          const supported = maybeSupported('timeZone')
          if (Array.isArray(supported)) options.push(...supported)
        } catch {
          /* noop */
        }
      }
    }
    options.push(defaultTimezone || 'UTC')
    options.push('UTC')
    if (scheduleConfig?.timezone) options.push(scheduleConfig.timezone)
    return Array.from(new Set(options))
  }, [defaultTimezone, scheduleConfig?.timezone])

  const filteredTimezoneOptions = useMemo(() => {
    const needle = timezoneSearch.trim().toLowerCase()
    if (!needle) return timezoneOptions
    return timezoneOptions.filter((tz) => tz.toLowerCase().includes(needle))
  }, [timezoneOptions, timezoneSearch])

  const selectedTime = useMemo(
    () => parseTime(scheduleConfig?.startTime),
    [scheduleConfig?.startTime]
  )
  const todayISO = useMemo(() => {
    const now = new Date()
    return toISODateString(now.getFullYear(), now.getMonth(), now.getDate())
  }, [])

  useEffect(() => {
    if (!datePickerOpen) return
    const handleMouseDown = (event: MouseEvent) => {
      if (
        !datePickerContainerRef.current?.contains(
          event.target as unknown as globalThis.Node
        )
      ) {
        setDatePickerOpen(false)
      }
    }
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setDatePickerOpen(false)
    }
    document.addEventListener('mousedown', handleMouseDown)
    document.addEventListener('keydown', handleKeyDown)
    return () => {
      document.removeEventListener('mousedown', handleMouseDown)
      document.removeEventListener('keydown', handleKeyDown)
    }
  }, [datePickerOpen])

  useEffect(() => {
    if (!timePickerOpen) return
    const handleMouseDown = (event: MouseEvent) => {
      if (
        !timePickerContainerRef.current?.contains(
          event.target as unknown as globalThis.Node
        )
      ) {
        setTimePickerOpen(false)
      }
    }
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setTimePickerOpen(false)
    }
    document.addEventListener('mousedown', handleMouseDown)
    document.addEventListener('keydown', handleKeyDown)
    return () => {
      document.removeEventListener('mousedown', handleMouseDown)
      document.removeEventListener('keydown', handleKeyDown)
    }
  }, [timePickerOpen])

  useEffect(() => {
    if (!timezonePickerOpen) {
      setTimezoneSearch('')
      return
    }

    const recalc = () => {
      const anchor =
        timezoneButtonRef.current || timezonePickerContainerRef.current
      const dropdown = timezoneDropdownRef.current
      const container = timezonePickerContainerRef.current
      if (!anchor || !container) return

      const containerRect = container.getBoundingClientRect()
      const anchorRect = anchor.getBoundingClientRect()
      const dropdownRect = dropdown?.getBoundingClientRect()
      const gap = 8

      // fallback sizes
      const fallbackWidth = 352
      const fallbackHeight = 320

      const menuW = Math.max(
        288,
        Math.min(fallbackWidth, containerRect.width - gap * 2)
      )
      const menuH = dropdownRect?.height || fallbackHeight

      // vertical positioning: prefer below; flip above if not enough space
      const spaceBelow =
        containerRect.height - (anchorRect.bottom - containerRect.top)
      let top = anchorRect.bottom - containerRect.top + gap
      if (
        spaceBelow < menuH + gap &&
        anchorRect.top - containerRect.top > menuH + gap
      ) {
        top = anchorRect.top - containerRect.top - menuH - gap
      }
      const maxTop = containerRect.height - menuH - gap
      if (top > maxTop) top = maxTop
      if (top < gap) top = gap

      // horizontal: align dropdown’s right edge with the field’s left edge
      const fieldRect =
        timezoneButtonRef.current?.getBoundingClientRect() ?? anchorRect

      const relativeFieldLeft = fieldRect.left - containerRect.left
      const relativeFieldRight = fieldRect.right - containerRect.left

      // position dropdown to the left of the field with a small gap
      let left = relativeFieldLeft - menuW - gap
      if (left < gap) {
        // not enough space on the left, open to the right side of the field
        left = relativeFieldRight + gap
        if (left + menuW > containerRect.width - gap) {
          left = containerRect.width - menuW - gap
        }
      }
      if (left < gap) left = gap

      setTzPos({ top, left, width: menuW })
    }

    recalc()
    requestAnimationFrame(recalc)
    setTimeout(recalc, 0)

    window.addEventListener('resize', recalc)
    window.addEventListener('scroll', recalc, true)

    const handleMouseDown = (event: MouseEvent) => {
      const targetNode = event.target as unknown as globalThis.Node
      const inAnchor = (timezonePickerContainerRef.current as any)?.contains(
        targetNode as any
      )
      const inDropdown = (timezoneDropdownRef.current as any)?.contains(
        targetNode as any
      )
      if (!inAnchor && !inDropdown) setTimezonePickerOpen(false)
    }

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setTimezonePickerOpen(false)
    }

    document.addEventListener('mousedown', handleMouseDown)
    document.addEventListener('keydown', handleKeyDown)

    return () => {
      window.removeEventListener('resize', recalc)
      window.removeEventListener('scroll', recalc, true)
      document.removeEventListener('mousedown', handleMouseDown)
      document.removeEventListener('keydown', handleKeyDown)
    }
  }, [timezonePickerOpen])
  return (
    <>
      <div className="flex flex-col gap-3">
        <div className="space-y-2">
          <div>
            <label className="block text-[10px] font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
              Input Node
            </label>
            <NodeDropdownField
              options={[
                {
                  label: 'Nodes',
                  options: [{ label: 'N/A', value: 'na', disabled: true }]
                }
              ]}
              value="N/A"
              onChange={() => undefined}
              placeholder="N/A"
              disabled
            />
          </div>
          <div>
            <label className="block text-[10px] font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
              Output Node
            </label>
            <NodeDropdownField
              options={[{ label: 'Nodes', options: nodeOptions }]}
              value={currentOutputId}
              onChange={handleChangeOutput}
              placeholder="Select output node"
            />
          </div>
        </div>

        <NodeHeader
          nodeId={nodeId}
          label={(nodeData?.label as string) || 'Trigger'}
          dirty={Boolean(nodeData?.dirty)}
          hasValidationErrors={Boolean(labelError) || webhookEventTypeMissing}
          expanded={true}
          onLabelChange={handleLabelChange}
          onExpanded={() => undefined}
          onConfirmingDelete={(e) => {
            e.preventDefault()
            e.stopPropagation()
            handleDeleteClick()
          }}
        />
        {labelError ? (
          <p className="text-xs text-red-500">{labelError}</p>
        ) : null}

        <div>
          <label className="block text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
            Trigger Type
          </label>
          <div className="mt-2">
            <TriggerTypeDropdown
              value={triggerType}
              onChange={handleTriggerTypeChange}
              disabledOptions={
                isSoloPlan
                  ? {
                      Schedule: SCHEDULE_RESTRICTION_MESSAGE,
                      'notion.new_database_row':
                        NOTION_TRIGGER_RESTRICTION_MESSAGE,
                      'notion.updated_database_row':
                        NOTION_TRIGGER_RESTRICTION_MESSAGE
                    }
                  : {}
              }
            />
          </div>
        </div>

        {isWebhookTrigger ? (
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
              Event type
            </label>
            <div className="mt-2 space-y-2">
              <NodeInputField
                placeholder="order.created"
                value={webhookEventType}
                onChange={(value) =>
                  updateNodeData(nodeId, { event_type: value, dirty: true })
                }
              />
              {webhookEventTypeMissing ? (
                <p className="text-xs text-red-500">
                  Event type is required for webhook triggers.
                </p>
              ) : null}
            </div>
          </div>
        ) : null}

        {isNotionTrigger ? (
          <div className="rounded-lg bg-zinc-50 p-4 dark:bg-zinc-800/40">
            <div className="flex items-center justify-between">
              <h4 className="text-sm font-semibold text-zinc-800 dark:text-zinc-100">
                Notion Trigger
              </h4>
            </div>

            <div className="mt-4 space-y-4">
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
                  Connection
                </label>
                <div className="mt-2">
                  <NodeDropdownField
                    options={notionConnectionOptions}
                    value={notionSelectedConnectionValue}
                    onChange={handleNotionConnectionChange}
                    placeholder="Select a Notion connection"
                    loading={notionConnectionsLoading}
                    disabled={!isNotionTrigger}
                    emptyMessage="No Notion connections available"
                    searchable
                  />
                </div>
                {notionConnectionsError ? (
                  <p className="mt-2 text-xs text-red-500">
                    {notionConnectionsError}
                  </p>
                ) : null}
              </div>

              <div>
                <label className="block text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
                  Database
                </label>
                <div className="mt-2 space-y-2">
                  <NodeInputField
                    placeholder="Search databases..."
                    value={notionDatabaseSearch}
                    onChange={setNotionDatabaseSearch}
                    disabled={!notionActiveConnection}
                  />
                  <NodeDropdownField
                    options={notionDatabaseOptions}
                    value={notionDatabaseId}
                    onChange={(value) =>
                      updateNodeData(nodeId, { databaseId: value, dirty: true })
                    }
                    placeholder="Select a database"
                    loading={notionDatabasesLoading}
                    disabled={!notionActiveConnection}
                    emptyMessage="No databases found"
                    searchable
                  />
                </div>
                {notionDatabasesError ? (
                  <p className="mt-2 text-xs text-red-500">
                    {notionDatabasesError}
                  </p>
                ) : null}
                {notionDatabasesHasMore ? (
                  <button
                    type="button"
                    onClick={handleLoadMoreNotionDatabases}
                    disabled={notionDatabasesLoading}
                    className="mt-2 text-xs font-semibold text-blue-600 hover:text-blue-700 disabled:opacity-60"
                  >
                    Load more databases
                  </button>
                ) : null}
              </div>
            </div>
          </div>
        ) : null}

        {isScheduleTrigger ? (
          <div className="rounded-lg bg-zinc-50 p-4 dark:bg-zinc-800/40">
            <div className="flex items-center justify-between">
              <h4 className="text-sm font-semibold text-zinc-800 dark:text-zinc-100">
                Schedule Settings
              </h4>
              <button
                type="button"
                onClick={() => {
                  if (scheduleConfig?.repeat) {
                    // Disable repeat
                    handleSchedulePatch({ repeat: undefined })
                  } else {
                    handleSchedulePatch({ repeat: { every: 1, unit: 'days' } })
                  }
                }}
                className="flex items-center gap-2 text-xs font-semibold text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300"
              >
                <RefreshCcw className="h-3 w-3" />
                {scheduleConfig?.repeat ? 'Disable repeat' : 'Enable repeat'}
              </button>
            </div>

            <div className="mt-4 space-y-4">
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
                  Start Date
                </label>
                <div ref={datePickerContainerRef} className="relative mt-2">
                  <CalendarDays className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-400 dark:text-zinc-300" />
                  <button
                    type="button"
                    onClick={() => {
                      setTimePickerOpen(false)
                      setTimezonePickerOpen(false)
                      setDatePickerOpen((p) => !p)
                    }}
                    className="w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 pl-10 text-left text-sm font-medium text-zinc-900 shadow-sm transition hover:border-blue-400 hover:shadow focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/40 dark:border-zinc-700 dark:bg-zinc-900/70 dark:text-zinc-100"
                  >
                    {formatDisplayDate(scheduleConfig?.startDate)}
                  </button>
                  <AnimatePresence>
                    {datePickerOpen && (
                      <motion.div
                        initial={{ opacity: 0, scale: 0.95, y: -4 }}
                        animate={{ opacity: 1, scale: 1, y: 0 }}
                        exit={{ opacity: 0, scale: 0.95, y: -4 }}
                        transition={{ duration: 0.15 }}
                        className="absolute left-0 right-0 z-20 mt-2"
                      >
                        <ScheduleCalendar
                          month={datePickerMonth}
                          selectedDate={scheduleConfig?.startDate}
                          todayISO={todayISO}
                          onMonthChange={(m) => setDatePickerMonth(m)}
                          onSelectDate={(isoDate) => {
                            handleSchedulePatch({ startDate: isoDate })
                            setDatePickerOpen(false)
                          }}
                        />
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              </div>
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
                    Start Time
                  </label>
                  <div ref={timePickerContainerRef} className="relative mt-2">
                    <Clock className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-400 dark:text-zinc-300" />
                    <button
                      type="button"
                      onClick={() => {
                        setDatePickerOpen(false)
                        setTimezonePickerOpen(false)
                        setTimePickerOpen((p) => !p)
                      }}
                      className="w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 pl-10 text-left text-sm font-medium text-zinc-900 shadow-sm transition hover:border-blue-400 hover:shadow focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/40 dark:border-zinc-700 dark:bg-zinc-900/70 dark:text-zinc-100"
                    >
                      {formatDisplayTime(scheduleConfig?.startTime)}
                    </button>
                    <AnimatePresence>
                      {timePickerOpen && (
                        <motion.div
                          initial={{ opacity: 0, scale: 0.95, y: -4 }}
                          animate={{ opacity: 1, scale: 1, y: 0 }}
                          exit={{ opacity: 0, scale: 0.95, y: -4 }}
                          transition={{ duration: 0.15 }}
                          className="absolute left-0 right-0 z-20 mt-2"
                        >
                          <ScheduleTimePicker
                            selectedTime={selectedTime}
                            onSelect={(time) => {
                              handleSchedulePatch({ startTime: time })
                            }}
                            onClose={() => setTimePickerOpen(false)}
                          />
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>
                </div>
                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
                    Timezone
                  </label>
                  <div
                    ref={timezonePickerContainerRef}
                    className="relative mt-2"
                  >
                    <Globe2 className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-400 dark:text-zinc-300" />
                    <button
                      ref={timezoneButtonRef}
                      type="button"
                      onClick={() => {
                        setDatePickerOpen(false)
                        setTimePickerOpen(false)
                        setTimezonePickerOpen((p) => !p)
                      }}
                      className="w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 pl-10 text-left text-sm font-medium text-zinc-900 shadow-sm transition hover:border-blue-400 hover:shadow focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/40 dark:border-zinc-700 dark:bg-zinc-900/70 dark:text-zinc-100"
                    >
                      <span
                        className="block truncate"
                        title={scheduleConfig?.timezone || 'Select timezone'}
                      >
                        {scheduleConfig?.timezone || 'Select timezone'}
                      </span>
                    </button>
                    <AnimatePresence>
                      {timezonePickerOpen && tzPos && (
                        <motion.div
                          ref={timezoneDropdownRef}
                          initial={{ opacity: 0, scale: 0.95, y: -4 }}
                          animate={{ opacity: 1, scale: 1, y: 0 }}
                          exit={{ opacity: 0, scale: 0.95, y: -4 }}
                          transition={{ duration: 0.15 }}
                          className="z-50"
                          style={{
                            position: 'fixed',
                            top: tzPos.top,
                            left: tzPos.left,
                            width: tzPos.width
                          }}
                        >
                          <ScheduleTimezonePicker
                            options={filteredTimezoneOptions}
                            selectedTimezone={scheduleConfig?.timezone || ''}
                            search={timezoneSearch}
                            onSearchChange={(v) => setTimezoneSearch(v)}
                            onSelect={(tz) => {
                              handleSchedulePatch({ timezone: tz })
                              setTimezonePickerOpen(false)
                            }}
                          />
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>
                </div>
              </div>

              {scheduleConfig?.repeat ? (
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <div>
                    <label className="block text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
                      Repeat every
                    </label>
                    <div className="mt-2 flex items-center gap-2">
                      <input
                        type="number"
                        min="1"
                        value={scheduleConfig?.repeat?.every ?? 1}
                        onChange={(e) => {
                          const raw = Number(e.target.value)
                          const clamped = Number.isFinite(raw)
                            ? Math.max(1, Math.floor(raw))
                            : 1
                          handleSchedulePatch({
                            repeat: {
                              every: clamped,
                              unit: scheduleConfig?.repeat?.unit ?? 'days'
                            }
                          })
                        }}
                        className="h-10 w-20 rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm font-semibold text-zinc-900 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/40 dark:border-zinc-700 dark:bg-zinc-900/70 dark:text-zinc-100"
                      />
                      <select
                        value={scheduleConfig?.repeat?.unit ?? 'days'}
                        onChange={(e) => {
                          const val = (e.target.value || 'days') as
                            | 'minutes'
                            | 'hours'
                            | 'days'
                            | 'weeks'
                          const unit = (
                            ['minutes', 'hours', 'days', 'weeks'] as const
                          ).includes(val as any)
                            ? val
                            : 'days'
                          handleSchedulePatch({
                            repeat: {
                              every: scheduleConfig?.repeat?.every ?? 1,
                              unit
                            }
                          })
                        }}
                        className="h-10 w-full rounded-lg border border-zinc-300 bg-white px-3 py-2 pr-8 text-sm font-semibold capitalize text-zinc-900 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-2 focus:ring-blue-500/40 dark:border-zinc-700 dark:bg-zinc-900/70 dark:text-zinc-100 sm:w-40"
                      >
                        {['minutes', 'hours', 'days', 'weeks'].map((u) => (
                          <option key={u} value={u}>
                            {u.charAt(0).toUpperCase() + u.slice(1)}
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>
                </div>
              ) : null}
            </div>
          </div>
        ) : null}

        <KeyValuePair
          title="Input Variables"
          variables={inputs}
          onChange={(vars) => handleInputsChange(vars)}
        />
      </div>

      <DeleteNodeModal
        open={confirmingDelete}
        onCancel={handleCancelDelete}
        onConfirm={handleConfirmDelete}
      />
    </>
  )
}

interface FlyoutConditionFieldsProps {
  nodeId: string
}

function FlyoutConditionFields({ nodeId }: FlyoutConditionFieldsProps) {
  const allNodes = useWorkflowStore(selectNodes)
  const allEdges = useWorkflowStore(selectEdges)
  const setEdges = useWorkflowStore((state) => state.setEdges)
  const nodeData = useWorkflowStore(
    useCallback(
      (state) => (state.nodes.find((n) => n.id === nodeId)?.data as any) ?? {},
      [nodeId]
    )
  )
  const updateNodeData = useWorkflowStore((s) => s.updateNodeData)
  const getNodeLabel = useCallback((n: Node) => {
    const rawLabel = (n.data as any)?.label
    if (typeof rawLabel === 'string' && rawLabel.trim()) return rawLabel
    switch (n.type) {
      case 'trigger':
        return 'Trigger'
      case 'condition':
        return 'Condition'
      default:
        return 'Action'
    }
  }, [])
  const nodeOptions = useMemo(
    () =>
      allNodes
        .filter((n) => n.id !== nodeId && n.type !== 'trigger')
        .map((n) => ({ label: getNodeLabel(n), value: n.id })),
    [allNodes, getNodeLabel, nodeId]
  )
  const trueOutputId = useMemo(() => {
    const t = allEdges.find(
      (e) => e.source === nodeId && e.sourceHandle === 'cond-true'
    )
    return t?.target ?? ''
  }, [allEdges, nodeId])
  const falseOutputId = useMemo(() => {
    const f = allEdges.find(
      (e) => e.source === nodeId && e.sourceHandle === 'cond-false'
    )
    return f?.target ?? ''
  }, [allEdges, nodeId])
  const changeCondOutput = useCallback(
    (handle: 'cond-true' | 'cond-false', nextTargetId: string) => {
      const currId = handle === 'cond-true' ? trueOutputId : falseOutputId
      if (!nextTargetId || nextTargetId === currId) return
      const targetNode = allNodes.find((n) => n.id === nextTargetId)
      if (targetNode?.type === 'trigger') return
      const state = useWorkflowStore.getState()
      const base = state.edges.filter(
        (e) => !(e.source === nodeId && e.sourceHandle === handle)
      )
      const label = handle === 'cond-true' ? 'True' : 'False'
      const outcome = handle === 'cond-true' ? 'true' : 'false'
      const newEdge = {
        id: `e-${nodeId}-${handle}-${nextTargetId}-${Date.now()}`,
        source: nodeId,
        sourceHandle: handle,
        target: nextTargetId,
        type: 'nodeEdge',
        label,
        data: { edgeType: 'default', outcome }
      } as any
      setEdges(normalizeEdgesForState([...base, newEdge]))
    },
    [allNodes, falseOutputId, nodeId, setEdges, trueOutputId]
  )

  const labelError: string | null = nodeData?.labelError ?? null
  const field = typeof nodeData?.field === 'string' ? nodeData.field : ''
  const operator =
    typeof nodeData?.operator === 'string' ? nodeData.operator : 'equals'
  const value = typeof nodeData?.value === 'string' ? nodeData.value : ''
  const [confirmingDelete, setConfirmingDelete] = useState(false)

  const buildExpression = useCallback((f: string, op: string, v: string) => {
    const left = (f || '').trim()
    if (!left) return ''
    const OP: Record<string, string> = {
      equals: '==',
      'not equals': '!=',
      'greater than': '>',
      'less than': '<',
      contains: 'contains'
    }
    const opSym = OP[(op || 'equals').toLowerCase()] ?? '=='
    const formattedLeft = left.startsWith('{{') ? left : `{{${left}}}`
    const formattedRight = (() => {
      const t = (v || '').trim()
      if (!t) return '""'
      if (t.startsWith('{{') && t.endsWith('}}')) return t
      if (/^(true|false|null)$/i.test(t)) return t.toLowerCase()
      if (!Number.isNaN(Number(t))) return t
      if (
        (t.startsWith('"') && t.endsWith('"')) ||
        (t.startsWith("'") && t.endsWith("'"))
      ) {
        try {
          return JSON.stringify(JSON.parse(t))
        } catch {
          return JSON.stringify(t.slice(1, -1))
        }
      }
      return JSON.stringify(t)
    })()
    return `${formattedLeft} ${opSym} ${formattedRight}`.trim()
  }, [])

  const hasValidationErrors = !field.trim() || !value.trim()
  useEffect(() => {
    const expression = buildExpression(field, operator, value)
    updateNodeData(nodeId, { expression, hasValidationErrors })
  }, [
    buildExpression,
    field,
    hasValidationErrors,
    nodeId,
    operator,
    updateNodeData,
    value
  ])

  const handleLabelChange = useCallback(
    (v: string) => updateNodeData(nodeId, { label: v, dirty: true }),
    [nodeId, updateNodeData]
  )
  const handleDeleteClick = useCallback(() => {
    setConfirmingDelete(true)
  }, [])
  const handleCancelDelete = useCallback(() => setConfirmingDelete(false), [])
  const handleConfirmDelete = useCallback(() => {
    setConfirmingDelete(false)
    useWorkflowStore.getState().removeNode(nodeId)
  }, [nodeId])
  const handleField = useCallback(
    (v: string) => updateNodeData(nodeId, { field: v, dirty: true }),
    [nodeId, updateNodeData]
  )
  const handleOperator = useCallback(
    (v: string) => updateNodeData(nodeId, { operator: v, dirty: true }),
    [nodeId, updateNodeData]
  )
  const handleValue = useCallback(
    (v: string) => updateNodeData(nodeId, { value: v, dirty: true }),
    [nodeId, updateNodeData]
  )

  return (
    <>
      <div className="flex flex-col gap-3">
        <div className="space-y-2">
          <div>
            <label className="block text-[10px] font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
              Input Node
            </label>
            <NodeDropdownField
              options={[
                {
                  label: 'Nodes',
                  options: allNodes
                    .filter((n) => n.id !== nodeId)
                    .map((n) => ({ label: getNodeLabel(n), value: n.id }))
                }
              ]}
              value={allEdges.find((e) => e.target === nodeId)?.source ?? ''}
              onChange={(nextSourceId) => {
                const state = useWorkflowStore.getState()
                const base = state.edges.filter((e) => e.target !== nodeId)
                const newEdge = {
                  id: `e-${nextSourceId}-${nodeId}-${Date.now()}`,
                  source: nextSourceId,
                  target: nodeId,
                  type: 'nodeEdge',
                  data: { edgeType: 'default' }
                } as any
                setEdges(normalizeEdgesForState([...base, newEdge]))
              }}
              placeholder="Select input node"
            />
          </div>
          <div>
            <label className="block text-[10px] font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
              True Output
            </label>
            <NodeDropdownField
              options={[{ label: 'Nodes', options: nodeOptions }]}
              value={trueOutputId}
              onChange={(v) => changeCondOutput('cond-true', v)}
              placeholder="Select true output"
            />
          </div>
          <div>
            <label className="block text-[10px] font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
              False Output
            </label>
            <NodeDropdownField
              options={[{ label: 'Nodes', options: nodeOptions }]}
              value={falseOutputId}
              onChange={(v) => changeCondOutput('cond-false', v)}
              placeholder="Select false output"
            />
          </div>
        </div>

        <NodeHeader
          nodeId={nodeId}
          label={(nodeData?.label as string) || 'Condition'}
          dirty={Boolean(nodeData?.dirty)}
          hasValidationErrors={Boolean(labelError) || hasValidationErrors}
          expanded={true}
          onLabelChange={handleLabelChange}
          onExpanded={() => undefined}
          onConfirmingDelete={(e) => {
            e.preventDefault()
            e.stopPropagation()
            handleDeleteClick()
          }}
        />
        {labelError ? (
          <p className="text-xs text-red-500">{labelError}</p>
        ) : null}

        <NodeInputField
          placeholder="Field name"
          value={field}
          onChange={handleField}
        />
        <NodeDropdownField
          options={[
            'equals',
            'not equals',
            'greater than',
            'less than',
            'contains'
          ]}
          value={operator}
          onChange={handleOperator}
        />
        <NodeInputField
          placeholder="Comparison value"
          value={value}
          onChange={handleValue}
        />
      </div>

      <DeleteNodeModal
        open={confirmingDelete}
        onCancel={handleCancelDelete}
        onConfirm={handleConfirmDelete}
      />
    </>
  )
}

function FlyoutFormatterFields({ nodeId }: { nodeId: string }) {
  const { label, hasValidationErrors, config } = useWorkflowStore(
    useCallback(
      (state) => {
        const node = state.nodes.find((n) => n.id === nodeId)
        if (!node) {
          return {
            label: null,
            dirty: false,
            hasValidationErrors: false,
            config: null
          }
        }
        const d = node.data as FormatterNodeData
        return {
          label: d.label ?? null,
          dirty: d.dirty ?? false,
          hasValidationErrors: d.hasValidationErrors ?? false,
          config: d.config ?? null
        }
      },
      [nodeId]
    ),
    shallow
  )

  const updateNodeData = useWorkflowStore((state) => state.updateNodeData)

  const normalizedConfig = useMemo(
    () => normalizeFormatterConfig(config as FormatterConfig | undefined),
    [config]
  )

  const validation = useMemo(
    () => validateFormatterConfig(normalizedConfig),
    [normalizedConfig]
  )

  useEffect(() => {
    if (hasValidationErrors !== validation.hasErrors) {
      updateNodeData(nodeId, { hasValidationErrors: validation.hasErrors })
    }
  }, [hasValidationErrors, validation.hasErrors, nodeId, updateNodeData])

  const handleConfigChange = useCallback(
    (nextConfig: FormatterConfig) => {
      const normalizedNext = normalizeFormatterConfig(nextConfig)
      const nextValidation = validateFormatterConfig(normalizedNext)

      const currentNormalized = normalizeFormatterConfig(
        config as FormatterConfig | undefined
      )

      const configEqual =
        JSON.stringify(currentNormalized) === JSON.stringify(normalizedNext)

      const validationEqual = hasValidationErrors === nextValidation.hasErrors

      if (configEqual && validationEqual) return

      updateNodeData(nodeId, {
        config: normalizedNext,
        hasValidationErrors: nextValidation.hasErrors,
        dirty: true
      })
    },
    [config, hasValidationErrors, nodeId, updateNodeData]
  )

  const title = typeof label === 'string' && label.trim() ? label : 'Formatter'

  return (
    <div className="space-y-3">
      <h4 className="text-sm font-semibold text-zinc-800 dark:text-zinc-100">
        {title}
      </h4>
      <FormatterNodeConfig
        config={normalizedConfig}
        onChange={handleConfigChange}
        validation={validation}
      />
    </div>
  )
}

function FlyoutDelayFields({ nodeId }: { nodeId: string }) {
  const { label, dirty, hasValidationErrors, config, labelError } =
    useWorkflowStore(
      useCallback(
        (state) => {
          const node = state.nodes.find((n) => n.id === nodeId)
          if (!node) {
            return {
              label: null,
              dirty: false,
              hasValidationErrors: false,
              config: null,
              labelError: null
            }
          }

          const d = node.data as DelayNodeData

          return {
            label: d.label ?? null,
            dirty: d.dirty ?? false,
            hasValidationErrors: d.hasValidationErrors ?? false,
            config: d.config ?? null,
            labelError: d.labelError ?? null
          }
        },
        [nodeId]
      ),
      shallow
    )

  const updateNodeData = useWorkflowStore((s) => s.updateNodeData)
  const canEdit = useWorkflowStore((s) => s.canEdit)
  const [confirmingDelete, setConfirmingDelete] = useState(false)

  const normalizedConfig = useMemo(
    () => normalizeDelayConfig(config as DelayConfig | undefined),
    [config]
  )

  const validationHasErrors = useMemo(
    () => validateDelayConfig(normalizedConfig),
    [normalizedConfig]
  )

  useEffect(() => {
    if (hasValidationErrors !== validationHasErrors) {
      updateNodeData(nodeId, { hasValidationErrors: validationHasErrors })
    }
  }, [hasValidationErrors, validationHasErrors, nodeId, updateNodeData])

  const handleLabelChange = useCallback(
    (v: string) => {
      if (!canEdit) return
      updateNodeData(nodeId, { label: v, dirty: true })
    },
    [canEdit, nodeId, updateNodeData]
  )

  const handleConfigChange = useCallback(
    (nextConfig: DelayConfig) => {
      if (!canEdit) return
      const normalizedNext = normalizeDelayConfig(nextConfig)
      const nextErrors = validateDelayConfig(normalizedNext)
      updateNodeData(nodeId, {
        config: normalizedNext,
        hasValidationErrors: nextErrors,
        dirty: true
      })
    },
    [canEdit, nodeId, updateNodeData]
  )

  const handleRequestDelete = useCallback(() => {
    if (!canEdit) return
    setConfirmingDelete(true)
  }, [canEdit])

  const handleCancelDelete = useCallback(() => {
    setConfirmingDelete(false)
  }, [])

  const handleConfirmDelete = useCallback(() => {
    if (!canEdit) return
    setConfirmingDelete(false)
    useWorkflowStore.getState().removeNode(nodeId)
  }, [canEdit, nodeId])

  const resolvedLabel =
    typeof label === 'string' && label.trim() ? label : 'Delay'

  return (
    <>
      <div className="flex flex-col gap-3">
        <NodeHeader
          nodeId={nodeId}
          label={resolvedLabel}
          dirty={dirty}
          hasValidationErrors={
            Boolean(labelError) || Boolean(hasValidationErrors)
          }
          expanded
          onLabelChange={handleLabelChange}
          onExpanded={() => undefined}
          onConfirmingDelete={(e) => {
            e.preventDefault()
            e.stopPropagation()
            handleRequestDelete()
          }}
        />

        <DelayNodeConfig
          config={normalizedConfig}
          onChange={handleConfigChange}
          hasValidationErrors={validationHasErrors}
          canEdit={canEdit}
        />
      </div>

      <DeleteNodeModal
        open={confirmingDelete}
        onCancel={handleCancelDelete}
        onConfirm={handleConfirmDelete}
      />
    </>
  )
}

interface DeleteNodeModalProps {
  open: boolean
  onCancel: () => void
  onConfirm: () => void
}

function DeleteNodeModal({ open, onCancel, onConfirm }: DeleteNodeModalProps) {
  return (
    <AnimatePresence>
      {open ? (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 px-4"
        >
          <motion.div
            initial={{ opacity: 0, scale: 0.97 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.97 }}
            className="w-full max-w-xs rounded-xl bg-white p-4 shadow-md dark:bg-zinc-800"
          >
            <p className="text-sm text-zinc-900 dark:text-zinc-100">
              Delete this node?
            </p>
            <p className="mb-4 text-sm text-zinc-600 dark:text-zinc-300">
              This action can not be undone
            </p>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={onCancel}
                className="rounded border border-zinc-300 px-3 py-1 text-xs font-semibold uppercase tracking-wide text-zinc-700 transition hover:bg-zinc-100 dark:border-zinc-700 dark:text-zinc-200 dark:hover:bg-zinc-700/50"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={onConfirm}
                className="rounded bg-red-500 px-3 py-1 text-xs font-semibold uppercase tracking-wide text-white transition hover:bg-red-600"
              >
                Delete
              </button>
            </div>
          </motion.div>
        </motion.div>
      ) : null}
    </AnimatePresence>
  )
}
