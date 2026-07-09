import { useEffect, useRef, useState } from 'react'
import { api } from '../api'
import { errorMessage } from '../errors'
import { notify } from '../notify'

const LIVE_TYPES: { id: string; label: string }[] = [
  { id: 'mail', label: 'Почта' },
  { id: 'dovecot', label: 'Dovecot' },
  { id: 'iredapd', label: 'iRedAPD' },
  { id: 'system', label: 'Система' },
]

export default function LogsPage() {
  const [items, setItems] = useState<any[]>([])
  const [total, setTotal] = useState(0)
  const [q, setQ] = useState('')
  const [queueId, setQueueId] = useState('')
  const [mailFrom, setMailFrom] = useState('')
  const [mailTo, setMailTo] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [live, setLive] = useState('')
  const [liveSource, setLiveSource] = useState('')
  const [liveType, setLiveType] = useState<string | null>(null)
  const [liveAuto, setLiveAuto] = useState(false)
  const [trace, setTrace] = useState<any[]>([])
  const [audit, setAudit] = useState<any[]>([])
  const logBoxRef = useRef<HTMLPreElement>(null)

  async function search() {
    try {
      const params = new URLSearchParams()
      if (q.trim()) params.set('q', q.trim())
      if (queueId.trim()) params.set('queue_id', queueId.trim())
      if (mailFrom.trim()) params.set('mail_from', mailFrom.trim())
      if (mailTo.trim()) params.set('mail_to', mailTo.trim())
      if (dateFrom) params.set('date_from', dateFrom)
      if (dateTo) params.set('date_to', dateTo)
      const res: any = await api.logsSearch(params)
      setItems(res.items)
      setTotal(res.total)
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function loadLive(type: string, scrollToEnd = true) {
    try {
      const res = await api.logsLive(type)
      setLive(res.lines.join('\n'))
      setLiveSource(res.source_label)
      setLiveType(type)
      if (scrollToEnd && logBoxRef.current) {
        logBoxRef.current.scrollTop = logBoxRef.current.scrollHeight
      }
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  useEffect(() => {
    search().catch((e) => notify.error(errorMessage(e)))
    api.audit().then(setAudit).catch((e) => notify.error(errorMessage(e)))
  }, [])

  useEffect(() => {
    if (!liveAuto || !liveType) return undefined
    const timer = window.setInterval(() => {
      loadLive(liveType, true).catch((e) => notify.error(errorMessage(e)))
    }, 3000)
    return () => window.clearInterval(timer)
  }, [liveAuto, liveType])

  return (
    <div>
      <div className="topbar"><h2>Логи</h2></div>
      <div className="card">
        <h3>Поиск по индексу</h3>
        <p className="muted">Все указанные поля работают вместе (логическое «И»). Индекс собирается из файлов логов — для свежих записей используйте «Живой лог» ниже.</p>
        <div className="form-row">
          <input placeholder="Текст в сообщении" value={q} onChange={(e) => setQ(e.target.value)} />
          <input placeholder="Queue-ID" value={queueId} onChange={(e) => setQueueId(e.target.value)} />
        </div>
        <div className="form-row">
          <input placeholder="Отправитель" value={mailFrom} onChange={(e) => setMailFrom(e.target.value)} />
          <input placeholder="Получатель" value={mailTo} onChange={(e) => setMailTo(e.target.value)} />
        </div>
        <div className="form-row">
          <label className="muted" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            С
            <input type="datetime-local" value={dateFrom} onChange={(e) => setDateFrom(e.target.value)} />
          </label>
          <label className="muted" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            По
            <input type="datetime-local" value={dateTo} onChange={(e) => setDateTo(e.target.value)} />
          </label>
          <button onClick={search}>Найти</button>
          <button className="secondary" onClick={() => {
            setQ('')
            setQueueId('')
            setMailFrom('')
            setMailTo('')
            setDateFrom('')
            setDateTo('')
            setTrace([])
          }}>Сбросить</button>
          <button className="secondary" onClick={async () => {
            if (!queueId) return
            try {
              setTrace(await api.logsTrace(queueId))
            } catch (e) {
              notify.error(errorMessage(e))
            }
          }}>Трейс</button>
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
        <p className="muted">
          Для почты используется journalctl (postfix, amavisd), если файл maillog устарел.
          {liveSource && <> Источник: <strong>{liveSource}</strong>.</>}
        </p>
        <div className="form-row">
          {LIVE_TYPES.map((t) => (
            <button
              key={t.id}
              className={liveType === t.id ? '' : 'secondary'}
              onClick={() => loadLive(t.id)}
            >
              {t.label}
            </button>
          ))}
          <button
            className={liveAuto ? '' : 'secondary'}
            onClick={() => setLiveAuto((value) => !value)}
            disabled={!liveType}
          >
            {liveAuto ? 'Пауза' : 'Автообновление (3 с)'}
          </button>
        </div>
        <pre ref={logBoxRef} className="log-box" style={{ maxHeight: 420 }}>{live || 'Выберите тип лога'}</pre>
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
