import { useEffect, useState } from 'react'
import { api, getUser, type ServiceStatus } from '../api'
import ServiceStatusBadge from '../components/ServiceStatusBadge'

const ENABLED_LABELS: Record<string, string> = {
  enabled: 'автозапуск',
  disabled: 'без автозапуска',
  static: 'static',
  masked: 'masked',
}

export default function ServicesPage() {
  const [services, setServices] = useState<ServiceStatus[]>([])
  const [fail2ban, setFail2ban] = useState<any[]>([])
  const [loading, setLoading] = useState(false)
  const canRestart = ['superadmin', 'admin'].includes(getUser()?.role || '')

  async function load() {
    setLoading(true)
    try {
      setServices(await api.services())
      setFail2ban(await api.fail2ban())
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  return (
    <div>
      <div className="topbar">
        <h2>Службы и Fail2ban</h2>
        <button className="secondary" onClick={() => load()} disabled={loading}>
          {loading ? 'Обновление…' : 'Обновить'}
        </button>
      </div>
      <div className="card">
        <p className="muted" style={{ marginTop: 0 }}>
          Статус обновляется при открытии страницы и по кнопке «Обновить».
          Для Amavis дополнительно проверяется порт 10024.
        </p>
        <table className="data-table">
          <thead>
            <tr>
              <th>Служба</th>
              <th className="col-status">Статус</th>
              <th style={{ width: '14%' }}>Автозапуск</th>
              {canRestart && <th className="col-actions"></th>}
            </tr>
          </thead>
          <tbody>
            {services.map((s) => (
              <tr key={s.name}>
                <td>
                  <div>{s.name}</div>
                  {s.detail && <div className="service-detail">{s.detail}</div>}
                </td>
                <td><ServiceStatusBadge service={s} /></td>
                <td>
                  <span className={`badge ${s.enabled === 'enabled' ? '' : 'down'}`}>
                    {ENABLED_LABELS[s.enabled || ''] || s.enabled || '—'}
                  </span>
                </td>
                {canRestart && (
                  <td className="actions">
                    <button
                      className="secondary"
                      onClick={async () => {
                        await api.restartService(s.name)
                        await load()
                      }}
                    >
                      Перезапуск
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="card">
        <h3>Fail2ban</h3>
        {fail2ban.map((j) => (
          <div key={j.jail} style={{ marginBottom: 16 }}>
            <strong>{j.jail}</strong>
            <ul className="entry-list" style={{ marginTop: 8 }}>
              {j.banned_ips.map((ip: string) => (
                <li key={ip}>
                  <span className="entry-label">{ip}</span>
                  {canRestart && (
                    <span className="entry-actions">
                      <button
                        type="button"
                        className="secondary entry-remove"
                        onClick={async () => {
                          await api.unban(j.jail, ip)
                          await load()
                        }}
                      >
                        Разбан
                      </button>
                    </span>
                  )}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  )
}
