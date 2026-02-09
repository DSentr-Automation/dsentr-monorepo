// src/layouts/DashboardLayout.tsx
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Outlet, useLocation, useNavigate } from 'react-router-dom'
import { ThemeToggle } from '@/components/ThemeToggle'
import { NavigateButton } from '@/components/ui/buttons/NavigateButton'
import { selectCurrentWorkspace, useAuth } from '@/stores/auth'
import SettingsButton from '@/components/settings/SettingsButton'
import SettingsModal from '@/components/settings/SettingsModal'
import WorkflowsTab from '@/components/settings/tabs/WorkflowsTab'
import PrivacyTab from '@/components/settings/tabs/PrivacyTab'
import EngineTab from '@/components/settings/tabs/EngineTab'
import LogsTab from '@/components/settings/tabs/LogsTab'
import WebhooksTab from '@/components/settings/tabs/WebhooksTab'
import OptionsTab from '@/components/settings/tabs/OptionsTab'
import IntegrationsTab, {
  IntegrationNotice
} from '@/components/settings/tabs/IntegrationsTab'
import UsageTab from '@/components/settings/tabs/UsageTab'
import PlanTab from '@/components/settings/tabs/PlanTab'
import MembersTab from '@/components/settings/tabs/MembersTab'
import DangerZoneTab from '@/components/settings/tabs/DangerZoneTab'
import { DSentrLogo } from '@/assets/svg-components/DSentrLogo'
import { SecretsProvider } from '@/contexts/SecretsContext'
import { OAuthProvider } from '@/lib/oauthApi'
import { WORKSPACE_RUN_LIMIT_FALLBACK } from '@/lib/usageDefaults'
import ProfileButton from '@/components/profile/ProfileButton'
import ProfileModal from '@/components/profile/ProfileModal'
import PendingInviteModal from '@/components/dashboard/PendingInviteModal'
import IssueReportModal from '@/components/support/IssueReportModal'
import ReportIssueButton from '@/components/support/ReportIssueButton'
import { usePlanUsageStore } from '@/stores/planUsageStore'
import { normalizePlanTier } from '@/lib/planTiers'
import HelpButton from '@/components/help/HelpButton'
import MessagesButton from '@/components/support/MessagesButton'
import MessageCenter from '@/components/support/MessageCenter'
import { fetchIssueThreads } from '@/lib/issuesApi'
import { settingsTabIcons } from '@/components/settings/tabs/SettingsTabIcons'

export default function DashboardLayout() {
  const user = useAuth((state) => state.user)
  const memberships = useAuth((state) => state.memberships)
  const currentWorkspaceId = useAuth((state) => state.currentWorkspaceId)
  const currentWorkspace = useAuth(selectCurrentWorkspace)
  const setCurrentWorkspaceId = useAuth((state) => state.setCurrentWorkspaceId)
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [profileOpen, setProfileOpen] = useState(false)
  const [messageCenterOpen, setMessageCenterOpen] = useState(false)
  const [unreadMessages, setUnreadMessages] = useState(0)
  const [issueReportOpen, setIssueReportOpen] = useState(false)
  const [initialSettingsTab, setInitialSettingsTab] = useState<
    string | undefined
  >(undefined)
  const [integrationNotice, setIntegrationNotice] =
    useState<IntegrationNotice | null>(null)
  const location = useLocation()
  const navigate = useNavigate()
  const planUsage = usePlanUsageStore((state) => state.usage)
  const refreshPlanUsage = usePlanUsageStore((state) => state.refresh)
  // Preferences removed

  const hasWorkspaces = memberships.length > 0
  const hasMultipleWorkspaces = memberships.length > 1
  const previousSearchRef = useRef<string | null>(null)
  const hasSyncedQueryRef = useRef(false)
  const isMountedRef = useRef(true)

  useEffect(() => {
    return () => {
      isMountedRef.current = false
    }
  }, [])

  const currentWorkspaceName = useMemo(() => {
    if (!currentWorkspace) return ''
    const name = currentWorkspace.workspace.name?.trim()
    return name || 'Unnamed workspace'
  }, [currentWorkspace])
  const planTier = useMemo(
    () =>
      normalizePlanTier(
        currentWorkspace?.workspace.plan ?? user?.plan ?? undefined
      ),
    [currentWorkspace?.workspace.plan, user?.plan]
  )
  const usageWorkspaceId =
    planTier === 'workspace' ? (currentWorkspace?.workspace.id ?? null) : null

  useEffect(() => {
    void refreshPlanUsage(usageWorkspaceId)
  }, [refreshPlanUsage, usageWorkspaceId])

  const workspaceRunUsage = planUsage?.workspace?.runs
  const workspaceUsageLimit =
    workspaceRunUsage?.limit && workspaceRunUsage.limit > 0
      ? workspaceRunUsage.limit
      : WORKSPACE_RUN_LIMIT_FALLBACK
  const workspaceUsageUsed = workspaceRunUsage?.used ?? 0
  const workspaceUsagePercent =
    workspaceUsageLimit && workspaceUsageLimit > 0
      ? Math.min(100, (workspaceUsageUsed / workspaceUsageLimit) * 100)
      : null
  const workspaceUsageTone =
    workspaceUsagePercent !== null && workspaceUsagePercent >= 100
      ? 'danger'
      : workspaceUsagePercent !== null && workspaceUsagePercent >= 90
        ? 'warning'
        : 'neutral'
  const workspaceUsageBarClass =
    workspaceUsageTone === 'danger'
      ? 'bg-red-500'
      : workspaceUsageTone === 'warning'
        ? 'bg-amber-400'
        : 'bg-indigo-500'
  const workspaceUsageTextClass =
    workspaceUsageTone === 'danger'
      ? 'text-red-600 dark:text-red-300'
      : workspaceUsageTone === 'warning'
        ? 'text-amber-600 dark:text-amber-300'
        : 'text-zinc-700 dark:text-zinc-200'

  useEffect(() => {
    if (memberships.length === 1) {
      const soleId = memberships[0]?.workspace.id
      if (soleId && soleId !== currentWorkspaceId) {
        setCurrentWorkspaceId(soleId)
      }
    }
  }, [memberships, currentWorkspaceId, setCurrentWorkspaceId])

  useEffect(() => {
    if (previousSearchRef.current === location.search) {
      return
    }
    previousSearchRef.current = location.search
    const params = new URLSearchParams(location.search)
    const workspaceFromQuery = params.get('workspace')
    if (!workspaceFromQuery) return
    if (!memberships.some((m) => m.workspace.id === workspaceFromQuery)) return
    if (workspaceFromQuery !== currentWorkspaceId) {
      setCurrentWorkspaceId(workspaceFromQuery)
    }
  }, [currentWorkspaceId, location.search, memberships, setCurrentWorkspaceId])

  const syncWorkspaceParam = useCallback(
    (workspaceId: string | null, replace = false) => {
      const params = new URLSearchParams(location.search)
      const existing = params.get('workspace')
      if (workspaceId) {
        if (existing === workspaceId) return
        params.set('workspace', workspaceId)
      } else {
        if (!existing) return
        params.delete('workspace')
      }
      navigate(
        { pathname: location.pathname, search: params.toString() },
        { replace }
      )
    },
    [location.pathname, location.search, navigate]
  )

  useEffect(() => {
    // Open plan settings when returning from Stripe Checkout
    const params = new URLSearchParams(location.search)
    const billing = params.get('billing')
    if (billing === 'success' || billing === 'cancel') {
      setInitialSettingsTab('plan')
      setSettingsOpen(true)
      // Do not clear params here; allow PlanTab to process confirmation state.
    }
  }, [location.search])

  useEffect(() => {
    const id = currentWorkspace?.workspace.id ?? null
    const params = new URLSearchParams(location.search)
    const existing = params.get('workspace')
    if (!hasSyncedQueryRef.current) {
      // Initial mount: respect an existing query param that differs;
      // the URL->store effect will reconcile selection. After the first run,
      // always sync the query param with the current selection.
      hasSyncedQueryRef.current = true
      if (existing && existing !== id) return
    }
    syncWorkspaceParam(id, true)
  }, [currentWorkspace, syncWorkspaceParam, location.search])

  const handleWorkspaceChange = useCallback(
    (workspaceId: string) => {
      if (!workspaceId || workspaceId === currentWorkspaceId) return
      setCurrentWorkspaceId(workspaceId)
    },
    [currentWorkspaceId, setCurrentWorkspaceId]
  )

  const refreshUnreadMessages = useCallback(async () => {
    if (!isMountedRef.current) return
    if (typeof window === 'undefined') return
    try {
      const response = await fetchIssueThreads()
      if (!isMountedRef.current) return
      setUnreadMessages(response.unread_admin_messages)
    } catch {
      if (!isMountedRef.current) return
      setUnreadMessages(0)
    }
  }, [])

  useEffect(() => {
    if (!user) return
    void refreshUnreadMessages()
  }, [user, refreshUnreadMessages])

  const planBadge = useMemo(() => {
    if (!planTier) return null
    return planTier === 'workspace' ? 'Workspace plan' : 'Solo plan'
  }, [planTier])

  const openPlanSettings = useCallback(() => {
    try {
      window.dispatchEvent(
        new CustomEvent('open-plan-settings', { detail: { tab: 'plan' } })
      )
    } catch {
      /* ignore window dispatch errors */
    }
  }, [])

  const settingsTabs = useMemo(() => {
    const base = [
      { key: 'plan', label: 'Plan & Billing' },
      ...(planTier === 'workspace' ? [{ key: 'usage', label: 'Usage' }] : []),
      { key: 'members', label: 'Members' },
      { key: 'engine', label: 'Engine' },
      { key: 'logs', label: 'Logs' },
      { key: 'webhooks', label: 'Webhooks' },
      { key: 'options', label: 'Secrets & API Keys' },
      { key: 'privacy', label: 'Privacy' },
      { key: 'integrations', label: 'Integrations' },
      { key: 'workflows', label: 'Workflows' },
      { key: 'danger', label: 'Danger Zone' }
    ]
    return base.map((tab) => ({
      ...tab,
      icon: settingsTabIcons[tab.key]
    }))
  }, [planTier])
  const settingsTabKeys = useMemo(
    () => settingsTabs.map((tab) => tab.key),
    [settingsTabs]
  )

  useEffect(() => {
    const params = new URLSearchParams(location.search)
    const connected = params.get('connected')
    if (!connected) return

    const providerParamRaw = params.get('provider')
    const providerParam: OAuthProvider | undefined =
      providerParamRaw === 'google' ||
      providerParamRaw === 'microsoft' ||
      providerParamRaw === 'slack' ||
      providerParamRaw === 'asana' ||
      providerParamRaw === 'notion'
        ? (providerParamRaw as OAuthProvider)
        : undefined
    const error = params.get('error') || undefined

    if (connected === 'true') {
      setIntegrationNotice({ kind: 'connected', provider: providerParam })
    } else if (connected === 'false') {
      setIntegrationNotice({
        kind: 'error',
        provider: providerParam,
        message: error
      })
    }

    setSettingsOpen(true)
    setInitialSettingsTab('integrations')

    params.delete('connected')
    params.delete('provider')
    params.delete('error')
    navigate(
      { pathname: location.pathname, search: params.toString() },
      { replace: true }
    )
  }, [location, navigate])

  useEffect(() => {
    const params = new URLSearchParams(location.search)
    const targetTab = params.get('settings')
    if (!targetTab) return
    if (!settingsTabKeys.includes(targetTab)) {
      params.delete('settings')
      navigate(
        { pathname: location.pathname, search: params.toString() },
        { replace: true }
      )
      return
    }

    setInitialSettingsTab(targetTab)
    setSettingsOpen(true)
    params.delete('settings')
    navigate(
      { pathname: location.pathname, search: params.toString() },
      { replace: true }
    )
  }, [location.pathname, location.search, navigate, settingsTabKeys])

  useEffect(() => {
    const handler = (event: Event) => {
      const detail = (event as CustomEvent<{ tab?: string }>).detail
      setInitialSettingsTab(detail?.tab ?? 'plan')
      setSettingsOpen(true)
    }
    window.addEventListener('open-plan-settings', handler)
    return () => {
      window.removeEventListener('open-plan-settings', handler)
    }
  }, [])

  return (
    <SecretsProvider>
      <div className="min-h-screen flex flex-col">
        <header className="px-4 py-2 border-b border-zinc-200 dark:border-zinc-700 bg-white dark:bg-zinc-900">
          <div className="flex items-center gap-4 w-full">
            <div className="flex items-center gap-1 font-bold tracking-tight text-xl text-zinc-900 dark:text-zinc-100">
              <span className="leading-none">DSentr</span>
              <span
                className="inline-block align-middle"
                style={{ height: '1em' }}
              >
                <DSentrLogo className="w-[1.5em] h-[1.5em]" />
              </span>
            </div>
            {planTier === 'workspace' && workspaceRunUsage ? (
              <div
                className="flex items-center gap-2 flex-1 max-w-md"
                aria-label="Workspace run usage"
              >
                <div className="flex-1 h-2 rounded-full bg-zinc-200 dark:bg-zinc-800 overflow-hidden">
                  <div
                    className={`h-full rounded-full ${workspaceUsageBarClass}`}
                    style={{
                      width: `${workspaceUsagePercent ?? 0}%`,
                      transition: 'width 150ms ease'
                    }}
                  />
                </div>
                <span
                  className={`text-xs font-semibold ${workspaceUsageTextClass}`}
                >
                  {workspaceUsageUsed.toLocaleString()} /{' '}
                  {workspaceUsageLimit.toLocaleString()}
                </span>
              </div>
            ) : null}
            <div className="flex-1" />
            {user && (
              <div className="flex items-center gap-3">
                {hasWorkspaces ? (
                  <div className="flex items-center gap-2 text-sm">
                    <span className="text-xs font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
                      Active workspace
                    </span>
                    {hasMultipleWorkspaces ? (
                      <select
                        aria-label="Workspace switcher"
                        value={currentWorkspace?.workspace.id ?? ''}
                        onChange={(event) =>
                          handleWorkspaceChange(event.target.value)
                        }
                        className="px-2 py-1 border rounded-md bg-white text-sm dark:bg-zinc-800 dark:border-zinc-700"
                      >
                        {memberships.map((membership) => (
                          <option
                            key={membership.workspace.id}
                            value={membership.workspace.id}
                          >
                            {membership.workspace.name || 'Unnamed workspace'}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <span className="text-sm text-zinc-700 dark:text-zinc-200">
                        {currentWorkspaceName}
                      </span>
                    )}
                  </div>
                ) : null}
                {planBadge ? (
                  <div className="flex items-center gap-2">
                    <span className="rounded-full border border-indigo-500 px-2 py-0.5 text-xs font-semibold uppercase tracking-wide text-indigo-600 dark:border-indigo-400 dark:text-indigo-300">
                      {planBadge}
                    </span>
                    <button
                      type="button"
                      onClick={openPlanSettings}
                      className="text-xs font-medium text-indigo-600 hover:text-indigo-700 dark:text-indigo-300 dark:hover:text-indigo-200"
                    >
                      Manage plan
                    </button>
                  </div>
                ) : null}
                <span className="text-sm text-zinc-600 dark:text-zinc-300 leading-none">
                  {user.first_name} {user.last_name}
                </span>
                <NavigateButton
                  to="/logout"
                  className="px-3 py-2 text-sm leading-none h-9"
                >
                  Log out
                </NavigateButton>
                <ThemeToggle />
                <ProfileButton onOpenProfile={() => setProfileOpen(true)} />
                <MessagesButton
                  unreadCount={unreadMessages}
                  onOpen={() => setMessageCenterOpen(true)}
                />
                <SettingsButton onOpenSettings={() => setSettingsOpen(true)} />
                <ReportIssueButton onOpen={() => setIssueReportOpen(true)} />
                <HelpButton />
              </div>
            )}
          </div>
        </header>

        <main className="flex-1 bg-zinc-50 dark:bg-zinc-800">
          <Outlet />
        </main>

        <MessageCenter
          open={messageCenterOpen}
          onClose={() => setMessageCenterOpen(false)}
          onUnreadChange={setUnreadMessages}
        />
        <IssueReportModal
          open={issueReportOpen}
          onClose={() => setIssueReportOpen(false)}
        />
        <ProfileModal
          open={profileOpen}
          onClose={() => setProfileOpen(false)}
        />
        <SettingsModal
          open={settingsOpen}
          onClose={() => {
            setSettingsOpen(false)
            setInitialSettingsTab(undefined)
          }}
          initialTab={initialSettingsTab}
          tabs={settingsTabs}
          renderTab={(key) => {
            if (key === 'plan') return <PlanTab />
            if (key === 'members') return <MembersTab />
            if (key === 'engine') return <EngineTab />
            if (key === 'logs') return <LogsTab />
            if (key === 'webhooks') return <WebhooksTab />
            if (key === 'options') return <OptionsTab />
            if (key === 'usage') return <UsageTab />
            if (key === 'privacy') return <PrivacyTab />
            if (key === 'integrations') {
              return (
                <IntegrationsTab
                  notice={integrationNotice}
                  onDismissNotice={() => setIntegrationNotice(null)}
                />
              )
            }
            if (key === 'workflows') return <WorkflowsTab />
            if (key === 'danger') return <DangerZoneTab />
            return <div />
          }}
        />
        <PendingInviteModal />
      </div>
    </SecretsProvider>
  )
}
