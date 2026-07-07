const TOKEN_KEY = 'mailpanel_token'
const USER_KEY = 'mailpanel_user'

export type UserInfo = {
  username: string
  role: string
  display_name: string
  mailbox?: string | null
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
  if (!res.ok) throw new Error(data.detail || data.message || 'Request failed')
  return data as T
}

export const api = {
  login: (username: string, password: string) =>
    request<{ access_token: string; role: string; display_name: string }>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),
  me: () => request<UserInfo>('/api/auth/me'),
  dashboard: () => request('/api/dashboard'),
  mailboxes: () => request('/api/mailboxes'),
  createMailbox: (body: object) => request('/api/mailboxes', { method: 'POST', body: JSON.stringify(body) }),
  deleteMailbox: (username: string) => request(`/api/mailboxes/${encodeURIComponent(username)}`, { method: 'DELETE' }),
  mailboxPassword: (username: string, password: string) =>
    request(`/api/mailboxes/${encodeURIComponent(username)}/password`, {
      method: 'PUT',
      body: JSON.stringify({ password }),
    }),
  aliases: () => request('/api/aliases'),
  createAlias: (body: object) => request('/api/aliases', { method: 'POST', body: JSON.stringify(body) }),
  deleteAlias: (address: string) => request(`/api/aliases/${encodeURIComponent(address)}`, { method: 'DELETE' }),
  wblist: (type: string, account?: string) =>
    request<{ entries: string[] }>(`/api/wblist/${type}${account ? `?account=${encodeURIComponent(account)}` : ''}`),
  addWblist: (type: string, entries: string[], account?: string) =>
    request(`/api/wblist/${type}`, { method: 'POST', body: JSON.stringify({ entries, account }) }),
  deleteWblist: (type: string, entries: string[], account?: string) =>
    request(`/api/wblist/${type}`, { method: 'DELETE', body: JSON.stringify({ entries, account }) }),
  spam: () => request('/api/spam'),
  updateSpam: (body: object) => request('/api/spam', { method: 'PUT', body: JSON.stringify(body) }),
  greylisting: () => request('/api/greylisting'),
  logsSearch: (params: URLSearchParams) => request(`/api/logs/search?${params}`),
  logsTrace: (queueId: string) => request(`/api/logs/trace/${queueId}`),
  logsLive: (type: string) => request(`/api/logs/live/${type}`),
  services: () => request('/api/services'),
  restartService: (name: string) => request(`/api/services/${name}/restart`, { method: 'POST' }),
  fail2ban: () => request('/api/fail2ban'),
  unban: (jail: string, ip: string) => request('/api/fail2ban/unban', { method: 'POST', body: JSON.stringify({ jail, ip }) }),
  panelUsers: () => request('/api/panel-users'),
  createPanelUser: (body: object) => request('/api/panel-users', { method: 'POST', body: JSON.stringify(body) }),
  panelUserPassword: (id: number, password: string) =>
    request(`/api/panel-users/${id}/password`, { method: 'PUT', body: JSON.stringify({ password }) }),
  deletePanelUser: (id: number) => request(`/api/panel-users/${id}`, { method: 'DELETE' }),
  audit: () => request('/api/audit'),
  myForwarding: () => request('/api/portal/forwarding'),
  setForwarding: (goto: string) => request('/api/portal/forwarding', { method: 'PUT', body: JSON.stringify({ goto }) }),
  clearForwarding: () => request('/api/portal/forwarding', { method: 'DELETE' }),
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
