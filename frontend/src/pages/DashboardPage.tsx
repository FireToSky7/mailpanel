import { useEffect, useState } from 'react'
import { api } from '../api'
import ServiceStatusBadge from '../components/ServiceStatusBadge'
import { errorMessage } from '../errors'
import { notify } from '../notify'

export default function DashboardPage() {
  const [data, setData] = useState<any>(null)

  useEffect(() => {
    api.dashboard().then(setData).catch((e) => notify.error(errorMessage(e)))
  }, [])

  if (!data) return <div>Загрузка...</div>

  const stats = data.stats
  return (
    <div>
      <div className="topbar"><h2>Обзор</h2></div>
      <div className="grid">
        <div className="stat"><div className="label">Домен</div><div className="value" style={{ fontSize: '1.1rem' }}>{stats.domain}</div></div>
        <div className="stat"><div className="label">Ящики</div><div className="value">{stats.mailboxes}</div></div>
        <div className="stat"><div className="label">Алиасы</div><div className="value">{stats.aliases}</div></div>
        <div className="stat"><div className="label">Карантин</div><div className="value">{stats.quarantine}</div></div>
      </div>
      <div className="card" style={{ marginTop: 20 }}>
        <h3>Службы</h3>
        <table className="data-table">
          <thead><tr><th>Служба</th><th className="col-status">Статус</th></tr></thead>
          <tbody>
            {data.services.map((s: any) => (
              <tr key={s.name}>
                <td>
                  <div>{s.name}</div>
                  {s.detail && <div className="service-detail">{s.detail}</div>}
                </td>
                <td><ServiceStatusBadge service={s} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
