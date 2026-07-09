import type { ServiceStatus } from '../api'

const STATUS_LABELS: Record<string, string> = {
  active: 'работает',
  inactive: 'остановлена',
  failed: 'ошибка',
  activating: 'запуск…',
  deactivating: 'остановка…',
  reloading: 'перезагрузка…',
  unknown: 'неизвестно',
}

export function serviceStatusLabel(status: ServiceStatus): string {
  const health = status.health ?? (status.status === 'active' ? 'ok' : 'failed')
  if (health === 'degraded') return 'работает с ошибкой'
  return STATUS_LABELS[status.status] || status.status
}

export function serviceStatusClass(status: ServiceStatus): string {
  const health = status.health ?? (status.status === 'active' ? 'ok' : 'failed')
  if (health === 'ok') return ''
  if (health === 'degraded') return 'warn'
  return 'down'
}

export default function ServiceStatusBadge({ service }: { service: ServiceStatus }) {
  return (
    <span className={`badge ${serviceStatusClass(service)}`}>
      {serviceStatusLabel(service)}
    </span>
  )
}
