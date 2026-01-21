import type { ComponentType } from 'react'
import { createWithEqualityFn } from 'zustand/traditional'
import { type NodeProps, type Node } from '@xyflow/react'

import type { RunAvailability } from '@/types/runAvailability'
import type {
  ActionNodeData,
  ActionNodeParams
} from '@/components/workflow/nodes/useActionNodeController'
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
import {
  fetchActionCatalog,
  type ActionCatalogEntry
} from '@/lib/actionCatalogApi'
import { errorMessage } from '@/lib/errorMessage'

export type ActionNodeRendererProps = NodeProps<
  Node<Record<string, unknown>>
> & {
  onRun?: (id: string, params: unknown) => Promise<void>
  isRunning?: boolean
  isSucceeded?: boolean
  isFailed?: boolean
  canEdit?: boolean
  planTier?: string | null
  onRestrictionNotice?: (message: string) => void
  runAvailability?: RunAvailability
}

export type ActionInputDefinition = {
  name: string
  label: string
  type: string
  required: boolean
  provider?: string
  connectionScopes?: string[]
  options?: ActionInputOption[]
  min?: number
  max?: number
}

export type ActionInputOption = {
  value: string
  label: string
}

export type ActionDefinition = {
  id: string
  actionType: string
  nodeType: string
  label: string
  description: string
  category: string
  iconKey: string
  gradient: string
  idPrefix: string
  expanded: boolean
  createNodeData: () => ActionNodeData
  inputs?: ActionInputDefinition[]
  nodeComponent?: ComponentType<any>
  fieldsComponent?: ComponentType<any>
  visibleInPicker?: boolean
  hideFieldsWhenRestricted?: boolean
  messagingProvider?: 'slack' | 'teams'
}

type ActionRegistryState = {
  actions: ActionDefinition[]
  isLoaded: boolean
  isLoading: boolean
  loadCatalog: () => Promise<void>
}

const MANIFEST_ACTION_GRADIENTS = [
  'from-indigo-500 to-violet-600',
  'from-purple-500 to-fuchsia-600',
  'from-amber-500 to-orange-600',
  'from-emerald-500 to-lime-500',
  'from-slate-600 to-slate-800',
  'from-stone-600 to-zinc-800',
  'from-amber-400 to-rose-500',
  'from-orange-500 to-rose-500'
]

const DEFAULT_ICON_KEY = 'action'
const DEFAULT_CATEGORY = 'Actions'

// Normalize manifest categories to match coded action categories
const normalizeManifestCategory = (rawCategory?: string | null): string => {
  if (!rawCategory || typeof rawCategory !== 'string') return DEFAULT_CATEGORY

  const normalized = rawCategory.trim().toLowerCase()

  // Map common variations to exact coded action categories
  const categoryMap: Record<string, string> = {
    email: 'Email',
    emails: 'Email',
    mail: 'Email',
    messaging: 'Messaging',
    message: 'Messaging',
    chat: 'Messaging',
    slack: 'Messaging',
    teams: 'Messaging',
    'google chat': 'Messaging',
    'google sheets': 'Google Sheets',
    sheets: 'Google Sheets',
    spreadsheet: 'Google Sheets',
    webhooks: 'Webhooks & APIs',
    webhook: 'Webhooks & APIs',
    api: 'Webhooks & APIs',
    apis: 'Webhooks & APIs',
    http: 'Webhooks & APIs',
    request: 'Webhooks & APIs',
    'project management': 'Project Management',
    projects: 'Project Management',
    asana: 'Project Management',
    notion: 'Project Management',
    'custom logic': 'Custom Logic',
    code: 'Custom Logic',
    custom: 'Custom Logic',
    script: 'Custom Logic'
  }

  return categoryMap[normalized] || rawCategory.trim()
}

// Manifest inputs initialize based on their declared type.

// Enforces invariant: Fallback action resolution is deterministic
const DEFAULT_ACTION_ID = 'actionEmailSendgrid'

const normalizeActionKey = (value: string) => value.trim().toLowerCase()

const hashString = (value: string) => {
  let hash = 0
  for (let i = 0; i < value.length; i += 1) {
    hash = (hash + value.charCodeAt(i)) % 2147483647
  }
  return hash
}

const pickManifestGradient = (seed: string) => {
  const source = seed || 'action'
  const idx = hashString(source) % MANIFEST_ACTION_GRADIENTS.length
  return MANIFEST_ACTION_GRADIENTS[idx]
}

const normalizeEnumOptions = (
  options: unknown
): ActionInputOption[] | undefined => {
  if (!Array.isArray(options)) return undefined
  const normalized = options.reduce<ActionInputOption[]>((acc, option) => {
    if (typeof option === 'string') {
      const trimmed = option.trim()
      if (trimmed) {
        acc.push({ value: trimmed, label: trimmed })
      }
      return acc
    }
    if (!option || typeof option !== 'object') return acc
    const value =
      typeof (option as any).value === 'string'
        ? (option as any).value.trim()
        : ''
    const label =
      typeof (option as any).label === 'string'
        ? (option as any).label.trim()
        : ''
    if (!value) return acc
    acc.push({ value, label: label || value })
    return acc
  }, [])
  return normalized.length > 0 ? normalized : undefined
}

const normalizeInputs = (value: ActionCatalogEntry['inputs']) => {
  if (!Array.isArray(value)) return []
  return value.reduce<ActionInputDefinition[]>((acc, input) => {
    if (!input || typeof input !== 'object') return acc
    const name = typeof input.name === 'string' ? input.name.trim() : ''
    if (!name) return acc
    const label =
      typeof input.label === 'string' && input.label.trim().length > 0
        ? input.label
        : name
    // Preserve original type from manifest (especially oauth_connection)
    const type =
      typeof input.type === 'string' && input.type.trim().length > 0
        ? input.type.trim()
        : 'string'
    const scopes = Array.isArray((input as any).connectionScopes)
      ? (input as any).connectionScopes
      : Array.isArray((input as any).connection_scopes)
        ? (input as any).connection_scopes
        : null
    let connectionScopes = []
    if (scopes) {
      connectionScopes = scopes.filter(
        (scope: string) => typeof scope === 'string' && scope.trim().length > 0
      )
    }

    const normalizedInput: ActionInputDefinition = {
      name,
      label,
      type,
      required: Boolean(input.required),
      connectionScopes
    }

    // Preserve OAuth metadata if present
    if (input.provider && typeof input.provider === 'string') {
      normalizedInput.provider = input.provider.trim()
    }
    if (Array.isArray(input.connectionScopes)) {
      normalizedInput.connectionScopes = input.connectionScopes.filter(
        (scope) => typeof scope === 'string' && scope.trim().length > 0
      )
    }

    // Preserve enum options if present
    const normalizedOptions = normalizeEnumOptions((input as any).options)
    if (normalizedOptions) {
      normalizedInput.options = normalizedOptions
    }

    if (
      typeof (input as any).min === 'number' &&
      Number.isFinite((input as any).min)
    ) {
      normalizedInput.min = (input as any).min
    }
    if (
      typeof (input as any).max === 'number' &&
      Number.isFinite((input as any).max)
    ) {
      normalizedInput.max = (input as any).max
    }

    acc.push(normalizedInput)
    return acc
  }, [])
}

const buildEmptyParams = (inputs: ActionInputDefinition[]) => {
  const params: Record<string, unknown> = {}
  inputs.forEach((input) => {
    switch (input.type) {
      case 'oauth_connection':
        // OAuth inputs don't initialize as strings
        params[input.name] = ''
        params.connection = null
        params.connectionScope = null
        params.connectionId = null
        break
      case 'enum':
        params[input.name] = input.options?.[0]?.value ?? ''
        break
      case 'number':
        params[input.name] = null
        break
      case 'boolean':
        params[input.name] = false
        break
      case 'string[]':
        params[input.name] = []
        break
      case 'object':
        params[input.name] = {}
        break
      default:
        params[input.name] = ''
        break
    }
  })
  return params
}

const buildManifestDefinition = (
  entry: ActionCatalogEntry
): ActionDefinition | null => {
  if (!entry || typeof entry.action_id !== 'string') return null
  const actionId = entry.action_id
  const ui = entry.ui ?? {}
  const label =
    typeof ui.label === 'string' && ui.label.length > 0 ? ui.label : actionId
  const description = typeof ui.description === 'string' ? ui.description : ''
  const category = normalizeManifestCategory(
    typeof ui.category === 'string' && ui.category.length > 0
      ? ui.category
      : null
  )
  const iconKey =
    typeof ui.icon === 'string' && ui.icon.trim().length > 0
      ? normalizeActionKey(ui.icon)
      : DEFAULT_ICON_KEY
  const inputs = normalizeInputs(entry.inputs)
  const hasRequired = inputs.some((input) => input.required)

  return {
    id: actionId,
    actionType: actionId,
    nodeType: 'action',
    label,
    description,
    category,
    iconKey,
    gradient: pickManifestGradient(`${category}:${actionId}`),
    idPrefix: `action-${actionId}`,
    expanded: true,
    createNodeData: () => ({
      actionType: actionId,
      params: buildEmptyParams(inputs),
      timeout: 5000,
      retries: 0,
      stopOnError: true,
      hasValidationErrors: hasRequired
    }),
    inputs
  }
}

const toBaseActionNodeData = (
  data: Omit<ActionNodeData, 'actionType'> & { actionType: string }
): ActionNodeData => ({
  actionType: data.actionType,
  params: data.params as ActionNodeParams | undefined,
  timeout: data.timeout as number | undefined,
  retries: data.retries as number | undefined,
  stopOnError: data.stopOnError as boolean | undefined
})

const BASE_ACTIONS: ActionDefinition[] = [
  {
    id: 'actionEmailSendgrid',
    actionType: 'email',
    nodeType: 'actionEmailSendgrid',
    label: 'SendGrid Email',
    description: 'Send emails with SendGrid',
    category: 'Email',
    iconKey: DEFAULT_ICON_KEY,
    gradient: 'from-indigo-500 to-violet-600',
    idPrefix: 'action-email-sendgrid',
    expanded: true,
    createNodeData: () =>
      toBaseActionNodeData({
        actionType: 'email',
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
      }),
    nodeComponent: SendGridActionNode,
    fieldsComponent: SendGridAction,
    visibleInPicker: true
  },
  {
    id: 'actionEmailMailgun',
    actionType: 'email',
    nodeType: 'actionEmailMailgun',
    label: 'Mailgun Email',
    description: 'Deliver email through Mailgun',
    category: 'Email',
    iconKey: DEFAULT_ICON_KEY,
    gradient: 'from-purple-500 to-fuchsia-600',
    idPrefix: 'action-email-mailgun',
    expanded: true,
    createNodeData: () =>
      toBaseActionNodeData({
        actionType: 'email',
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
      }),
    nodeComponent: MailgunActionNode,
    fieldsComponent: MailGunAction,
    visibleInPicker: true
  },
  {
    id: 'actionEmailAmazonSes',
    actionType: 'email',
    nodeType: 'actionEmailAmazonSes',
    label: 'Amazon SES Email',
    description: 'Send email via Amazon SES',
    category: 'Email',
    iconKey: DEFAULT_ICON_KEY,
    gradient: 'from-amber-500 to-yellow-500',
    idPrefix: 'action-email-amazon-ses',
    expanded: true,
    createNodeData: () =>
      toBaseActionNodeData({
        actionType: 'email',
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
      }),
    nodeComponent: AmazonSesActionNode,
    fieldsComponent: AmazonSESAction,
    hideFieldsWhenRestricted: true,
    visibleInPicker: true
  },
  {
    id: 'actionSlack',
    actionType: 'slack',
    nodeType: 'actionSlack',
    label: 'Slack',
    description: 'Message a Slack channel',
    category: 'Messaging',
    iconKey: DEFAULT_ICON_KEY,
    gradient: 'from-purple-500 to-fuchsia-600',
    idPrefix: 'action-slack',
    expanded: true,
    createNodeData: () =>
      toBaseActionNodeData({
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
      }),
    nodeComponent: SlackActionNode,
    fieldsComponent: SlackAction,
    messagingProvider: 'slack',
    visibleInPicker: true
  },
  {
    id: 'actionTeams',
    actionType: 'teams',
    nodeType: 'actionTeams',
    label: 'Microsoft Teams',
    description: 'Send a Teams message',
    category: 'Messaging',
    iconKey: DEFAULT_ICON_KEY,
    gradient: 'from-purple-500 to-fuchsia-600',
    idPrefix: 'action-teams',
    expanded: true,
    createNodeData: () =>
      toBaseActionNodeData({
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
      }),
    nodeComponent: TeamsActionNode,
    fieldsComponent: TeamsAction,
    messagingProvider: 'teams',
    visibleInPicker: false
  },
  {
    id: 'actionGoogleChat',
    actionType: 'googlechat',
    nodeType: 'actionGoogleChat',
    label: 'Google Chat',
    description: 'Send a Google Chat message',
    category: 'Messaging',
    iconKey: DEFAULT_ICON_KEY,
    gradient: 'from-amber-400 to-rose-500',
    idPrefix: 'action-google-chat',
    expanded: true,
    createNodeData: () =>
      toBaseActionNodeData({
        actionType: 'googlechat',
        params: {
          webhookUrl: '',
          message: '',
          cardJson: ''
        },
        timeout: 5000,
        retries: 0,
        stopOnError: true
      }),
    nodeComponent: GoogleChatActionNode,
    fieldsComponent: GoogleChatAction,
    visibleInPicker: true
  },
  {
    id: 'actionSheets',
    actionType: 'sheets',
    nodeType: 'actionSheets',
    label: 'Google Sheets',
    description: 'Append a spreadsheet row',
    category: 'Google Sheets',
    iconKey: DEFAULT_ICON_KEY,
    gradient: 'from-emerald-500 to-lime-500',
    idPrefix: 'action-sheets',
    expanded: true,
    createNodeData: () =>
      toBaseActionNodeData({
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
      }),
    nodeComponent: GoogleSheetsActionNode,
    fieldsComponent: SheetsAction,
    hideFieldsWhenRestricted: true,
    visibleInPicker: true
  },
  {
    id: 'actionHttp',
    actionType: 'http',
    nodeType: 'actionHttp',
    label: 'HTTP Request',
    description: 'Call an external API',
    category: 'Webhooks & APIs',
    iconKey: DEFAULT_ICON_KEY,
    gradient: 'from-amber-500 to-orange-600',
    idPrefix: 'action-http',
    expanded: true,
    createNodeData: () =>
      toBaseActionNodeData({
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
      }),
    nodeComponent: HttpRequestActionNode,
    fieldsComponent: HttpRequestAction,
    visibleInPicker: true
  },
  {
    id: 'actionAsana',
    actionType: 'asana',
    nodeType: 'actionAsana',
    label: 'Asana',
    description: 'Create and update Asana projects and tasks',
    category: 'Project Management',
    iconKey: DEFAULT_ICON_KEY,
    gradient: 'from-orange-500 to-rose-500',
    idPrefix: 'action-asana',
    expanded: true,
    createNodeData: () =>
      toBaseActionNodeData({
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
      }),
    nodeComponent: AsanaActionNode,
    fieldsComponent: AsanaAction,
    hideFieldsWhenRestricted: true,
    visibleInPicker: true
  },
  {
    id: 'actionNotion',
    actionType: 'notion',
    nodeType: 'actionNotion',
    label: 'Notion',
    description: 'Create and query Notion databases',
    category: 'Project Management',
    iconKey: DEFAULT_ICON_KEY,
    gradient: 'from-stone-600 to-zinc-800',
    idPrefix: 'action-notion',
    expanded: true,
    createNodeData: () =>
      toBaseActionNodeData({
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
      }),
    nodeComponent: NotionActionNode,
    fieldsComponent: NotionAction,
    hideFieldsWhenRestricted: true,
    visibleInPicker: true
  },
  {
    id: 'actionCode',
    actionType: 'code',
    nodeType: 'actionCode',
    label: 'Run Code',
    description: 'Execute custom logic',
    category: 'Custom Logic',
    iconKey: DEFAULT_ICON_KEY,
    gradient: 'from-slate-600 to-slate-800',
    idPrefix: 'action-code',
    expanded: true,
    createNodeData: () =>
      toBaseActionNodeData({
        actionType: 'code',
        params: {
          code: '',
          inputs: [],
          outputs: []
        },
        timeout: 5000,
        retries: 0,
        stopOnError: true
      }),
    nodeComponent: RunCustomCodeActionNode,
    fieldsComponent: RunCustomCodeAction,
    visibleInPicker: true
  }
]

const mergeActions = (catalogActions: ActionDefinition[]) => {
  const existing = new Set(
    BASE_ACTIONS.map((action) => normalizeActionKey(action.id))
  )
  const merged = [...BASE_ACTIONS]
  catalogActions.forEach((action) => {
    if (!existing.has(normalizeActionKey(action.id))) {
      merged.push(action)
    }
  })
  return merged
}

// Manifest inputs initialize based on their declared type.
export const useActionRegistry = createWithEqualityFn<ActionRegistryState>(
  (set, get) => ({
    actions: BASE_ACTIONS,
    isLoaded: false,
    isLoading: false,
    loadCatalog: async () => {
      const { isLoaded, isLoading } = get()
      if (isLoaded || isLoading) return
      set({ isLoading: true })
      try {
        const entries = await fetchActionCatalog()
        const catalogActions = entries
          .map((entry) => buildManifestDefinition(entry))
          .filter((entry): entry is ActionDefinition => Boolean(entry))
        set({
          actions: mergeActions(catalogActions),
          isLoaded: true,
          isLoading: false
        })
      } catch (err) {
        console.error('Failed to load action catalog', errorMessage(err))
        set({ isLoaded: true, isLoading: false })
      }
    }
  })
)

// Manifest inputs initialize based on their declared type.

export { DEFAULT_ACTION_ID }
