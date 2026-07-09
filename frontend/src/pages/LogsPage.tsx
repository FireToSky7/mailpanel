import { useEffect, useRef, useState } from 'react'
import { api, type LogEntry } from '../api'
import { errorMessage } from '../errors'
import { notify } from '../notify'

const LIVE_TYPES: { id: string; label: string }[] = [
  { id: 'mail', label: 'Почта' },
  { id: 'dovecot', label: 'Dovecot' },
  { id: 'iredapd', label: 'iRedAPD' },
  { id: 'system', label: 'Система' },
]

function defaultDateFrom(): string {
  const date = new Date(Date.now() - 24 * 60 * 60 * 1000)
  const pad = (n: number) => String(n).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`
}

export default function LogsPage() {
  const [items, setItems] = useState<LogEntry[]>([])
  const [total, setTotal] = useState(0)
  const [sourceLabel, setSourceLabel] = useState('')
  const [q, setQ] = useState('')
  const [queueId, setQueueId] = useState('')
  const [mailFrom, setMailFrom] = useState('')
  const [mailTo, setMailTo] = useState('')
  const [dateFrom, setDateFrom] = useState(defaultDateFrom)
  const [dateTo, setDateTo] = useState('')
  const [live, setLive] = useState('')
  const [liveSource, setLiveSource] = useState('')
  const [liveType, setLiveType] = useState<string | null>(null)
  const [liveAuto, setLiveAuto] = useState(false)
  const [trace, setTrace] = useState<LogEntry[]>([])
  const [traceId, setTraceId] = useState('')
  const [audit, setAudit] = useState<any[]>([])
  const [searching, setSearching] = useState(false)
  const [hasSearched, setHasSearched] = useState(false)
  const logBoxRef = useRef<HTMLPreElement>(null)

  async function search() {
    if (!q.trim() && !queueId.trim() && !mailFrom.trim() && !mailTo.trim()) {
      notify.error('Укажите отправителя, получателя, Queue-ID или текст для поиска')
      return
    }
    setSearching(true)
    try {
      const params = new URLSearchParams()
      if (q.trim()) params.set('q', q.trim())
      if (queueId.trim()) params.set('queue_id', queueId.trim())
      if (mailFrom.trim()) params.set('mail_from', mailFrom.trim())
      if (mailTo.trim()) params.set('mail_to', mailTo.trim())
      if (dateFrom) params.set('date_from', dateFrom)
      if (dateTo) params.set('date_to', dateTo)
      const res = await api.logsSearch(params)
      setItems(res.items)
      setTotal(res.total)
      setSourceLabel(res.source_label || '')
      setTrace([])
      setTraceId('')
      setHasSearched(true)
    } catch (e) {
      notify.error(errorMessage(e))
    } finally {
      setSearching(false)
    }
  }

  async function showTrace(id: string) {
    if (!id) return
    try {
      setTraceId(id)
      setQueueId(id)
      setTrace(await api.logsTrace(id))
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
      <div className="card table-scroll">
        <h3>Поиск по почтовым логам</h3>
        <p className="muted">
          Поиск по journalctl (postfix, amavisd, dovecot, iRedAPD, rspamd). Укажите отправителя и/или получателя,
          задайте период и нажмите «Найти». Колонка «Результат» показывает итог: доставка, очередь, карантин, отклонение и т.д.
          Клик по Queue-ID — полная история письма.
          {sourceLabel && <> Источник: <strong>{sourceLabel}</strong>.</>}
        </p>
        <form
          onSubmit={(e) => {
            e.preventDefault()
            search()
          }}
        >
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
          <button type="submit" disabled={searching}>{searching ? 'Поиск…' : 'Найти'}</button>
          <button type="button" className="secondary" onClick={() => {
            setQ('')
            setQueueId('')
            setMailFrom('')
            setMailTo('')
            setDateFrom(defaultDateFrom())
            setDateTo('')
            setTrace([])
            setTraceId('')
            setItems([])
            setTotal(0)
            setHasSearched(false)
          }}>Сбросить</button>
        </div>
        </form>
        <p className="muted">Найдено: {total}</p>
        <table className="data-table">
          <thead>
            <tr>
              <th>Время</th>
              <th>Служба</th>
              <th>От</th>
              <th>Кому</th>
              <th>Queue-ID</th>
              <th>Результат</th>
              <th>Сообщение</th>
            </tr>
          </thead>
          <tbody>
            {items.length === 0 && (
              <tr><td colSpan={7} className="muted">
                {hasSearched ? 'За указанный период записей не найдено' : 'Укажите отправителя, получателя или Queue-ID и нажмите «Найти»'}
              </td></tr>
            )}
            {items.map((row) => (
              <tr key={row.id}>
                <td>{row.logged_at}</td>
                <td>{row.service}</td>
                <td>{row.mail_from || '—'}</td>
                <td>{row.mail_to || '—'}</td>
                <td>
                  {row.queue_id ? (
                    <button className="secondary" onClick={() => showTrace(row.queue_id!)}>{row.queue_id}</button>
                  ) : '—'}
                </td>
                <td>{row.outcome || row.status || '—'}</td>
                <td title={row.message}>{row.message}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {trace.length > 0 && (
          <div style={{ marginTop: 16 }}>
            <h4>История письма {traceId}</h4>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Время</th>
                  <th>Служба</th>
                  <th>Результат</th>
                  <th>Сообщение</th>
                </tr>
              </thead>
              <tbody>
                {trace.map((row) => (
                  <tr key={row.id}>
                    <td>{row.logged_at}</td>
                    <td>{row.service}</td>
                    <td>{row.outcome || row.status || '—'}</td>
                    <td title={row.message}>{row.message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      <div className="card">
        <h3>Живой лог</h3>
        <p className="muted">
          Поток последних записей в реальном времени.
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
