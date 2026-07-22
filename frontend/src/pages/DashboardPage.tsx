import { useEffect, useState } from 'react'
import { api, getUser, type ServiceStatus } from '../api'
import ServiceStatusBadge from '../components/ServiceStatusBadge'
import { errorMessage } from '../errors'
import { notify } from '../notify'

const ENABLED_LABELS: Record<string, string> = {
  enabled: 'автозапуск',
  disabled: 'без автозапуска',
  static: 'static',
  masked: 'masked',
}

export default function DashboardPage() {
  const [data, setData] = useState<any>(null)
  const [services, setServices] = useState<ServiceStatus[]>([])
  const [loading, setLoading] = useState(false)
  const canRestart = ['superadmin', 'admin'].includes(getUser()?.role || '')

  async function load() {
    setLoading(true)
    try {
      const dash = await api.dashboard()
      setData(dash)
      setServices(dash.services || [])
    } catch (e) {
      notify.error(errorMessage(e))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  if (!data) return <div>Загрузка...</div>

  const stats = data.stats
  return (
    <div>
      <div className="topbar">
        <h2>Обзор</h2>
        <button className="secondary" onClick={() => load()} disabled={loading}>
          {loading ? 'Обновление…' : 'Обновить'}
        </button>
      </div>
      <div className="grid">
        <div className="stat"><div className="label">Домен</div><div className="value" style={{ fontSize: '1.1rem' }}>{stats.domain}</div></div>
        <div className="stat"><div className="label">Ящики</div><div className="value">{stats.mailboxes}</div></div>
        <div className="stat"><div className="label">Алиасы</div><div className="value">{stats.aliases}</div></div>
        <div className="stat"><div className="label">Карантин</div><div className="value">{stats.quarantine}</div></div>
      </div>
      <div className="card" style={{ marginTop: 20 }}>
        <h3>Службы</h3>
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
                        try {
                          await api.restartService(s.name)
                          notify.success(`Служба ${s.name} перезапущена`)
                          await load()
                        } catch (e) {
                          notify.error(errorMessage(e))
                        }
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
    </div>
  )
}
