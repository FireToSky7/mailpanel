import { formatApiError } from './errors'

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
}

export type Alias = {
  address: string
  goto: string
  domain: string
  active: number
}

export type ServiceStatus = {
  name: string
  status: string
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
  message: string
}

export type LogsSearchResult = {
  total: number
  items: LogEntry[]
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

export type GreylistingData = {
  settings: string
  whitelist_domains: string
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
  return raw ? JSON.parse(raw) : null
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
    window.location.href = '/login'
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
  aliases: () => request<Alias[]>('/api/aliases'),
  createAlias: (body: object) => request<{ ok: boolean }>('/api/aliases', { method: 'POST', body: JSON.stringify(body) }),
  deleteAlias: (address: string) =>
    request<{ ok: boolean }>(`/api/aliases/${encodeURIComponent(address)}`, { method: 'DELETE' }),
  wblist: (type: string, account?: string) =>
    request<{ entries: string[] }>(`/api/wblist/${type}${account ? `?account=${encodeURIComponent(account)}` : ''}`),
  addWblist: (type: string, entries: string[], account?: string) =>
    request<{ ok: boolean }>(`/api/wblist/${type}`, { method: 'POST', body: JSON.stringify({ entries, account }) }),
  deleteWblist: (type: string, entries: string[], account?: string) =>
    request<{ ok: boolean }>(`/api/wblist/${type}`, { method: 'DELETE', body: JSON.stringify({ entries, account }) }),
  spam: () => request<SpamConfig>('/api/spam'),
  updateSpam: (body: object) => request<{ ok: boolean }>('/api/spam', { method: 'PUT', body: JSON.stringify(body) }),
  greylisting: () => request<GreylistingData>('/api/greylisting'),
  logsSearch: (params: URLSearchParams) => request<LogsSearchResult>(`/api/logs/search?${params}`),
  logsTrace: (queueId: string) => request<LogEntry[]>(`/api/logs/trace/${queueId}`),
  logsLive: (type: string) => request<{ lines: string[] }>(`/api/logs/live/${type}`),
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
  myForwarding: () => request<ForwardingInfo>('/api/portal/forwarding'),
  setForwarding: (goto: string) =>
    request<{ ok: boolean }>('/api/portal/forwarding', { method: 'PUT', body: JSON.stringify({ goto }) }),
  clearForwarding: () => request<{ ok: boolean }>('/api/portal/forwarding', { method: 'DELETE' }),
}

export function canAccess(role: string, section: string): boolean {
  const map: Record<string, string[]> = {
    dashboard: ['superadmin', 'admin', 'viewer'],
    mailboxes: ['superadmin', 'admin', 'viewer'],
    aliases: ['superadmin', 'admin', 'viewer'],
    antispam: ['superadmin', 'admin', 'viewer'],
    logs: ['superadmin', 'admin', 'viewer'],
    services: ['superadmin', 'admin', 'viewer'],
    panelUsers: ['superadmin'],
    portal: ['user'],
  }
  return (map[section] || []).includes(role)
}
