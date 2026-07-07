import { useEffect, useState } from 'react'
import { api } from '../api'

export default function LogsPage() {
  const [items, setItems] = useState<any[]>([])
  const [total, setTotal] = useState(0)
  const [q, setQ] = useState('')
  const [queueId, setQueueId] = useState('')
  const [live, setLive] = useState('')
  const [trace, setTrace] = useState<any[]>([])
  const [audit, setAudit] = useState<any[]>([])

  async function search() {
    const params = new URLSearchParams()
    if (q) params.set('q', q)
    if (queueId) params.set('queue_id', queueId)
    const res: any = await api.logsSearch(params)
    setItems(res.items)
    setTotal(res.total)
  }

  async function loadLive(type: string) {
    const res: any = await api.logsLive(type)
    setLive(res.lines.join('\n'))
  }

  useEffect(() => {
    search().catch(console.error)
    api.audit().then(setAudit).catch(console.error)
  }, [])

  return (
    <div>
      <div className="topbar"><h2>Логи</h2></div>
      <div className="card">
        <h3>Поиск по индексу</h3>
        <div className="form-row">
          <input placeholder="Текст" value={q} onChange={(e) => setQ(e.target.value)} />
          <input placeholder="Queue-ID" value={queueId} onChange={(e) => setQueueId(e.target.value)} />
          <button onClick={search}>Найти</button>
          <button className="secondary" onClick={async () => { if (queueId) setTrace(await api.logsTrace(queueId)) }}>Трейс</button>
        </div>
        <p className="muted">Найдено: {total}</p>
        <div className="log-box" style={{ maxHeight: 300 }}>
          {items.map((row) => (
            <div key={row.id}>[{row.logged_at}] {row.service} {row.queue_id || ''} {row.mail_from || ''} → {row.mail_to || ''} {row.message}</div>
          ))}
        </div>
        {trace.length > 0 && (
          <div className="card">
            <h4>Трейс {queueId}</h4>
            <div className="log-box">{trace.map((r) => `[${r.logged_at}] ${r.message}`).join('\n')}</div>
          </div>
        )}
      </div>
      <div className="card">
        <h3>Живой лог</h3>
        <div className="form-row">
          {['mail', 'iredapd', 'dovecot', 'system'].map((t) => (
            <button key={t} className="secondary" onClick={() => loadLive(t)}>{t}</button>
          ))}
        </div>
        <pre className="log-box">{live}</pre>
      </div>
      <div className="card">
        <h3>Аудит действий в панели</h3>
        <table>
          <thead><tr><th>Время</th><th>Пользователь</th><th>Действие</th><th>Ресурс</th><th>Детали</th></tr></thead>
          <tbody>
            {audit.map((a) => (
              <tr key={a.id}><td>{a.created_at}</td><td>{a.username}</td><td>{a.action}</td><td>{a.resource}</td><td>{a.details}</td></tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
