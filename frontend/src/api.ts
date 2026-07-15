import { formatApiError } from './errors'
import { toAppUrl } from './paths'

const TOKEN_KEY = 'mailpanel_token'
const USER_KEY = 'mailpanel_user'

export type UserInfo = {
  username: string
  role: string
  display_name: string
  mailbox?: string | null
}

export type Mailbox = {
  username: string
  name: string
  domain: string
  quota: number
  active: number
  used_mb?: number
  bytes_used?: number
  messages?: number
  last_login?: string
  last_login_unix?: number
}

export type ForwardingEntry = {
  address: string
  goto: string
}

export type Alias = {
  address: string
  goto: string
  domain: string
  active: number
}

export type MailGroup = {
  address: string
  members: string
  domain: string
  active: number
  include_everyone?: boolean
  domain_only?: boolean
  members_only?: boolean
  accesspolicy?: string
}

export type ServiceStatus = {
  name: string
  status: string
  enabled?: string
  health?: 'ok' | 'degraded' | 'stopped' | 'failed'
  detail?: string
}

export type Fail2banJail = {
  jail: string
  banned_ips: string[]
}

export type PanelUser = {
  id: number
  username: string
  role: string
  mailbox: string | null
  display_name: string
  active: number
}

export type SpamConfig = {
  raw: string
  required_score: string
}

export type BannedExtensionsData = {
  extensions: string[]
  markers_present: boolean
  source_file: string
  needs_resync?: boolean
}

export type MailPolicyData = {
  scan_internal_mail: boolean
  include_present: boolean
  bypass_banned_active: boolean
  notes: string[]
}

export type ContentFilter = {
  id: string
  field: 'subject' | 'body' | 'from'
  field_label: string
  pattern: string
  action: string
  action_label: string
  enabled: boolean
}

export type ContentFiltersData = {
  items: ContentFilter[]
  total: number
  source_file: string
  rules_file: string
  diagnostics?: {
    local_cf: string
    local_cf_exists: boolean
    rules_in_local_cf: boolean
    amavis_custom_file: string
    amavis_custom_exists: boolean
    amavis_hook_loaded: boolean
    active_rules: number
    scan_internal_mail: boolean
  }
  notes: string[]
}

export type AuditEntry = {
  id: number
  username: string
  action: string
  resource: string
  details: string
  ip_address: string
  created_at: string
}

export type LogEntry = {
  id: number
  logged_at: string
  service: string
  level: string
  queue_id: string | null
  mail_from: string | null
  mail_to: string | null
  status: string | null
  spam_score: number | null
  outcome?: string | null
  message: string
}

export type LogsSearchResult = {
  total: number
  items: LogEntry[]
  source?: string
  source_label?: string
}

export type DashboardData = {
  stats: {
    domain: string
    mailboxes: number
    aliases: number
    quarantine: number
    audit_today: number
  }
  services: ServiceStatus[]
}

export type ForwardingInfo = {
  address: string
  goto: string | null
}

export type GreylistingRule = {
  action: string
  from_addr: string
  to_addr: string
  priority?: string | null
}

export type GreylistingTiming = {
  training_mode: boolean
  rejection_message: string
  block_expire_minutes: number
  auth_triplet_expire_days: number
  unauth_triplet_expire_days: number
  bypass_spf: boolean
  settings_file: string
}

export type GreylistingStats = {
  hours: number
  rejections: number
  top_senders: { address: string; count: number }[]
  recent: {
    logged_at: string
    service: string
    mail_from: string | null
    mail_to: string | null
    client_ip: string | null
    message: string
  }[]
}

export type GreylistingData = {
  global_enabled: boolean
  timing: GreylistingTiming
  rules: GreylistingRule[]
  whitelist_domains: string[]
  whitelist_addresses: string[]
  stats: GreylistingStats
  notes: string[]
}

export type QuarantineItem = {
  mail_id: string
  secret_id: string
  partition_tag: string
  time_iso: string
  content: string
  content_label: string
  subject: string
  from_addr: string
  spam_level: number | null
  size: number
  recipients: string[]
}

export type QuarantineBody = QuarantineItem & {
  headers: Record<string, string>
  text_body: string
  html_body: string
  attachments: { filename: string; content_type: string; size: number }[]
  raw_size: number
}

export type QuarantineList = {
  total: number
  items: QuarantineItem[]
}

export type QueueItem = {
  queue_id: string
  size_bytes: number
  arrival_time: string
  sender: string | null
  recipients: string[]
  status: string
  reason: string | null
  flags: string[]
}

export type QueueList = {
  total: number
  active: number
  deferred: number
  hold: number
  incoming: number
  items: QueueItem[]
}

export type QueueDiagnosticIssue = {
  level: 'error' | 'warning'
  title: string
  message: string
  fix: string
}

export type QueueDiagnostics = {
  ok: boolean
  issues: QueueDiagnosticIssue[]
  hints: string[]
}

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setSession(token: string, user: UserInfo) {
  localStorage.setItem(TOKEN_KEY, token)
  localStorage.setItem(USER_KEY, JSON.stringify(user))
}

export function getUser(): UserInfo | null {
  const raw = localStorage.getItem(USER_KEY)
  if (!raw) return null
  try {
    return JSON.parse(raw) as UserInfo
  } catch {
    localStorage.removeItem(USER_KEY)
    return null
  }
}

export function clearSession() {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(USER_KEY)
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getToken()
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> | undefined),
  }
  if (token) headers.Authorization = `Bearer ${token}`

  const res = await fetch(path, { ...options, headers })
  if (res.status === 401) {
    clearSession()
    window.location.href = toAppUrl('/login')
    throw new Error('Unauthorized')
  }
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(formatApiError(data.detail) || data.message || 'Ошибка запроса')
  return data as T
}

export const api = {
  login: (username: string, password: string) =>
    request<{ access_token: string; role: string; display_name: string }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),
  me: () => request<UserInfo>('/api/auth/me'),
  dashboard: () => request<DashboardData>('/api/dashboard'),
  mailboxes: () => request<Mailbox[]>('/api/mailboxes'),
  createMailbox: (body: object) => request<{ ok: boolean }>('/api/mailboxes', { method: 'POST', body: JSON.stringify(body) }),
  deleteMailbox: (username: string) =>
    request<{ ok: boolean }>(`/api/mailboxes/${encodeURIComponent(username)}`, { method: 'DELETE' }),
  mailboxPassword: (username: string, password: string) =>
    request<{ ok: boolean }>(`/api/mailboxes/${encodeURIComponent(username)}/password`, {
      method: 'PUT',
      body: JSON.stringify({ password }),
    }),
  mailboxQuota: (username: string, quota: number) =>
    request<{ ok: boolean }>(`/api/mailboxes/${encodeURIComponent(username)}/quota`, {
      method: 'PUT',
      body: JSON.stringify({ quota }),
    }),
  mailboxActive: (username: string, active: boolean) =>
    request<{ ok: boolean }>(`/api/mailboxes/${encodeURIComponent(username)}/active`, {
      method: 'PUT',
      body: JSON.stringify({ active }),
    }),
  mailboxName: (username: string, name: string) =>
    request<{ ok: boolean; username: string; name: string }>(`/api/mailboxes/${encodeURIComponent(username)}/name`, {
      method: 'PUT',
      body: JSON.stringify({ name }),
    }),
  mailboxForwarding: (username: string) =>
    request<ForwardingInfo>(`/api/mailboxes/${encodeURIComponent(username)}/forwarding`),
  setMailboxForwarding: (username: string, goto: string) =>
    request<{ ok: boolean }>(`/api/mailboxes/${encodeURIComponent(username)}/forwarding`, {
      method: 'PUT',
      body: JSON.stringify({ goto }),
    }),
  clearMailboxForwarding: (username: string, goto?: string) => {
    const query = goto ? `?goto=${encodeURIComponent(goto)}` : ''
    return request<{ ok: boolean }>(
      `/api/mailboxes/${encodeURIComponent(username)}/forwarding${query}`,
      { method: 'DELETE' },
    )
  },
  forwardings: () => request<ForwardingEntry[]>('/api/forwardings'),
  removeMailboxForwarding: (address: string, goto: string) =>
    request<{ ok: boolean; items: ForwardingEntry[] }>('/api/forwardings/remove', {
      method: 'POST',
      body: JSON.stringify({ address, goto }),
    }),
  aliases: () => request<Alias[]>('/api/aliases'),
  createAlias: (body: object) => request<{ ok: boolean }>('/api/aliases', { method: 'POST', body: JSON.stringify(body) }),
  deleteAlias: (address: string) =>
    request<{ ok: boolean }>(`/api/aliases/${encodeURIComponent(address)}`, { method: 'DELETE' }),
  groups: () => request<MailGroup[]>('/api/groups'),
  createGroup: (body: { address: string; members: string[]; domain_only?: boolean }) =>
    request<{ ok: boolean }>('/api/groups', { method: 'POST', body: JSON.stringify(body) }),
  deleteGroup: (address: string) =>
    request<{ ok: boolean }>(`/api/groups/${encodeURIComponent(address)}`, { method: 'DELETE' }),
  updateGroupDomainOnly: (address: string, domain_only: boolean) =>
    request<{ ok: boolean; address: string; domain_only: boolean }>(
      `/api/groups/${encodeURIComponent(address)}/domain-only`,
      { method: 'PUT', body: JSON.stringify({ domain_only }) },
    ),
  addGroupMember: (address: string, member: string) =>
    request<{ ok: boolean; members: string[] }>(`/api/groups/${encodeURIComponent(address)}/members`, {
      method: 'POST',
      body: JSON.stringify({ member }),
    }),
  removeGroupMember: (address: string, member: string) =>
    request<{ ok: boolean; members: string[] }>(
      `/api/groups/${encodeURIComponent(address)}/members/remove`,
      { method: 'POST', body: JSON.stringify({ member }) },
    ),
  wblist: (type: string) =>
    request<{ entries: Array<string | { address: string; comment?: string }> }>(`/api/wblist/${type}`),
  addWblist: (type: string, entries: string[], comment = '') =>
    request<{ ok: boolean }>(`/api/wblist/${type}`, {
      method: 'POST',
      body: JSON.stringify({ entries, comment }),
    }),
  updateWblistComment: (type: string, entry: string, comment = '') =>
    request<{ ok: boolean; address: string; comment: string }>(`/api/wblist/${type}/comment`, {
      method: 'PUT',
      body: JSON.stringify({ entry, comment }),
    }),
  deleteWblist: (type: string, entries: string[]) =>
    request<{ ok: boolean }>(`/api/wblist/${type}`, { method: 'DELETE', body: JSON.stringify({ entries }) }),
  spam: () => request<SpamConfig>('/api/spam'),
  updateSpam: (body: object) => request<{ ok: boolean }>('/api/spam', { method: 'PUT', body: JSON.stringify(body) }),
  bannedExtensions: () => request<BannedExtensionsData>('/api/antispam/banned-extensions'),
  updateBannedExtensions: (extensions: string[]) =>
    request<{ ok: boolean; extensions: string[] }>('/api/antispam/banned-extensions', {
      method: 'PUT',
      body: JSON.stringify({ extensions }),
    }),
  mailPolicy: () => request<MailPolicyData>('/api/antispam/mail-policy'),
  updateMailPolicy: (scan_internal_mail: boolean) =>
    request<{ ok: boolean; scan_internal_mail: boolean }>('/api/antispam/mail-policy', {
      method: 'PUT',
      body: JSON.stringify({ scan_internal_mail }),
    }),
  contentFilters: () => request<ContentFiltersData>('/api/rules'),
  createContentFilter: (body: { field: 'subject' | 'body' | 'from'; pattern: string; enabled?: boolean }) =>
    request<{ ok: boolean; item: ContentFilter }>('/api/rules', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  updateContentFilter: (ruleId: string, body: { field?: 'subject' | 'body' | 'from'; pattern?: string; enabled?: boolean }) =>
    request<{ ok: boolean; item: ContentFilter }>(`/api/rules/${encodeURIComponent(ruleId)}`, {
      method: 'PUT',
      body: JSON.stringify(body),
    }),
  deleteContentFilter: (ruleId: string) =>
    request<{ ok: boolean }>(`/api/rules/${encodeURIComponent(ruleId)}`, { method: 'DELETE' }),
  reapplyContentFilters: () =>
    request<{ ok: boolean; warnings: string[]; diagnostics: ContentFiltersData['diagnostics'] }>(
      '/api/rules/reapply',
      { method: 'POST' },
    ),
  greylisting: () => request<GreylistingData>('/api/greylisting'),
  greylistingStats: (hours = 24) =>
    request<GreylistingStats>(`/api/greylisting/stats?hours=${hours}`),
  greylistingDisable: (to_addr: string, from_addr?: string) =>
    request<{ ok: boolean }>('/api/greylisting/disable', {
      method: 'POST',
      body: JSON.stringify({ to_addr, from_addr: from_addr || null }),
    }),
  greylistingEnable: (to_addr: string, from_addr?: string) =>
    request<{ ok: boolean }>('/api/greylisting/enable', {
      method: 'POST',
      body: JSON.stringify({ to_addr, from_addr: from_addr || null }),
    }),
  greylistingDeleteRule: (to_addr: string, from_addr?: string) =>
    request<{ ok: boolean }>('/api/greylisting/delete-rule', {
      method: 'POST',
      body: JSON.stringify({ to_addr, from_addr: from_addr || null }),
    }),
  greylistingWhitelistDomain: (domain: string) =>
    request<{ ok: boolean }>('/api/greylisting/whitelist-domain', {
      method: 'POST',
      body: JSON.stringify({ domain }),
    }),
  greylistingRemoveWhitelistDomain: (domain: string) =>
    request<{ ok: boolean }>('/api/greylisting/remove-whitelist-domain', {
      method: 'POST',
      body: JSON.stringify({ domain }),
    }),
  greylistingSyncSpf: () =>
    request<{ ok: boolean; message: string }>('/api/greylisting/sync-spf', { method: 'POST' }),
  quarantine: (content?: string, limit = 50, offset = 0) => {
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) })
    if (content) params.set('content', content)
    return request<QuarantineList>(`/api/quarantine?${params}`)
  },
  quarantineBody: (mailId: string, partitionTag = '') =>
    request<QuarantineBody>(
      `/api/quarantine/${encodeURIComponent(mailId)}/body${partitionTag ? `?partition_tag=${encodeURIComponent(partitionTag)}` : ''}`,
    ),
  releaseQuarantine: (mailId: string, partitionTag = '') =>
    request<{ ok: boolean }>(
      `/api/quarantine/${encodeURIComponent(mailId)}/release${partitionTag ? `?partition_tag=${encodeURIComponent(partitionTag)}` : ''}`,
      { method: 'POST' },
    ),
  deleteQuarantine: (mailId: string, partitionTag = '') =>
    request<{ ok: boolean }>(
      `/api/quarantine/${encodeURIComponent(mailId)}${partitionTag ? `?partition_tag=${encodeURIComponent(partitionTag)}` : ''}`,
      { method: 'DELETE' },
    ),
  queue: (status?: string, sender?: string, recipient?: string) => {
    const params = new URLSearchParams()
    if (status) params.set('status', status)
    if (sender) params.set('sender', sender)
    if (recipient) params.set('recipient', recipient)
    const query = params.toString()
    return request<QueueList>(`/api/queue${query ? `?${query}` : ''}`)
  },
  queueDiagnostics: () => request<QueueDiagnostics>('/api/queue/diagnostics'),
  queueHeaders: (queueId: string) => request<{ queue_id: string; headers: string }>(`/api/queue/${encodeURIComponent(queueId)}`),
  deleteQueueItem: (queueId: string) =>
    request<{ ok: boolean }>(`/api/queue/${encodeURIComponent(queueId)}`, { method: 'DELETE' }),
  flushQueueItem: (queueId: string) =>
    request<{ ok: boolean }>(`/api/queue/${encodeURIComponent(queueId)}/flush`, { method: 'POST' }),
  holdQueueItem: (queueId: string) =>
    request<{ ok: boolean }>(`/api/queue/${encodeURIComponent(queueId)}/hold`, { method: 'POST' }),
  releaseQueueItem: (queueId: string) =>
    request<{ ok: boolean }>(`/api/queue/${encodeURIComponent(queueId)}/release`, { method: 'POST' }),
  flushQueue: () => request<{ ok: boolean }>('/api/queue/flush', { method: 'POST', body: JSON.stringify({ confirm: 'FLUSH_ALL' }) }),
  logsSearch: (params: URLSearchParams) => request<LogsSearchResult>(`/api/logs/search?${params}`),
  logsTrace: (queueId: string) => request<LogEntry[]>(`/api/logs/trace/${queueId}`),
  logsLive: (type: string, lines = 200) =>
    request<{ lines: string[]; source: string; source_label: string }>(
      `/api/logs/live/${type}?lines=${lines}`,
    ),
  services: () => request<ServiceStatus[]>('/api/services'),
  restartService: (name: string) => request<ServiceStatus>(`/api/services/${name}/restart`, { method: 'POST' }),
  fail2ban: () => request<Fail2banJail[]>('/api/fail2ban'),
  unban: (jail: string, ip: string) =>
    request<{ ok: boolean }>('/api/fail2ban/unban', { method: 'POST', body: JSON.stringify({ jail, ip }) }),
  panelUsers: () => request<PanelUser[]>('/api/panel-users'),
  createPanelUser: (body: object) =>
    request<{ ok: boolean }>('/api/panel-users', { method: 'POST', body: JSON.stringify(body) }),
  panelUserPassword: (id: number, password: string) =>
    request<{ ok: boolean }>(`/api/panel-users/${id}/password`, { method: 'PUT', body: JSON.stringify({ password }) }),
  deletePanelUser: (id: number) => request<{ ok: boolean }>(`/api/panel-users/${id}`, { method: 'DELETE' }),
  audit: () => request<AuditEntry[]>('/api/audit'),
}

export function canAccess(role: string, section: string): boolean {
  const map: Record<string, string[]> = {
    dashboard: ['superadmin', 'admin', 'viewer'],
    mailboxes: ['superadmin', 'admin', 'viewer'],
    aliases: ['superadmin', 'admin', 'viewer'],
    groups: ['superadmin', 'admin', 'viewer'],
    antispam: ['superadmin', 'admin', 'viewer'],
    greylisting: ['superadmin', 'admin', 'viewer'],
    rules: ['superadmin', 'admin', 'viewer'],
    quarantine: ['superadmin', 'admin', 'viewer'],
    queue: ['superadmin', 'admin'],
    logs: ['superadmin', 'admin', 'viewer'],
    services: ['superadmin', 'admin', 'viewer'],
    panelUsers: ['superadmin'],
  }
  return (map[section] || []).includes(role)
}
