/** Базовый путь, если панель открыта через Nginx как /mailpanel/ */
export function getBasename(): string {
  const { pathname } = window.location
  if (pathname === '/mailpanel' || pathname.startsWith('/mailpanel/')) {
    return '/mailpanel'
  }
  return ''
}

export function toAppUrl(path: string): string {
  const normalized = path.startsWith('/') ? path : `/${path}`
  const base = getBasename()
  return `${base}${normalized}` || '/'
}
