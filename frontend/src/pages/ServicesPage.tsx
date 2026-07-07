import { useEffect, useState } from 'react'
import { api, getUser } from '../api'

export default function ServicesPage() {
  const [services, setServices] = useState<any[]>([])
  const [fail2ban, setFail2ban] = useState<any[]>([])
  const canRestart = ['superadmin', 'admin'].includes(getUser()?.role || '')

  async function load() {
    setServices(await api.services())
    setFail2ban(await api.fail2ban())
  }

  useEffect(() => { load() }, [])

  return (
    <div>
      <div className="topbar"><h2>Службы и Fail2ban</h2></div>
      <div className="card">
        <table>
          <thead><tr><th>Служба</th><th>Статус</th>{canRestart && <th></th>}</tr></thead>
          <tbody>
            {services.map((s) => (
              <tr key={s.name}>
                <td>{s.name}</td>
                <td><span className={`badge ${s.status === 'active' ? '' : 'down'}`}>{s.status}</span></td>
                {canRestart && <td><button className="secondary" onClick={async () => { await api.restartService(s.name); load() }}>Перезапуск</button></td>}
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
            <ul>
              {j.banned_ips.map((ip: string) => (
                <li key={ip}>{ip} {canRestart && <button className="secondary" onClick={async () => { await api.unban(j.jail, ip); load() }}>Разбан</button>}</li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  )
}
