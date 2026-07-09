import { useEffect, useState } from 'react'
import { api, getUser, type QueueDiagnosticIssue, type QueueItem } from '../api'
import { errorMessage } from '../errors'
import { notify } from '../notify'

const STATUS_OPTIONS = [
  { value: '', label: 'Все' },
  { value: 'active', label: 'Активные' },
  { value: 'deferred', label: 'Отложенные' },
  { value: 'hold', label: 'На удержании' },
  { value: 'incoming', label: 'Входящие' },
]

const STATUS_LABELS: Record<string, string> = {
  active: 'активное',
  deferred: 'отложено',
  hold: 'на удержании',
  incoming: 'входящее',
  corrupt: 'повреждено',
}

function statusLabel(status: string): string {
  return STATUS_LABELS[status] || status
}

function formatRecipients(recipients: QueueItem['recipients']): string {
  return recipients
    .map((recipient) => {
      if (typeof recipient === 'string') return recipient
      if (recipient && typeof recipient === 'object') {
        const value = recipient as { address?: string; recipient?: string }
        return value.address || value.recipient || ''
      }
      return String(recipient ?? '')
    })
    .filter(Boolean)
    .join(', ')
}

export default function QueuePage() {
  const [data, setData] = useState({
    total: 0,
    active: 0,
    deferred: 0,
    hold: 0,
    incoming: 0,
    items: [] as QueueItem[],
  })
  const [status, setStatus] = useState('')
  const [sender, setSender] = useState('')
  const [recipient, setRecipient] = useState('')
  const [headers, setHeaders] = useState<string | null>(null)
  const [diagnostics, setDiagnostics] = useState<QueueDiagnosticIssue[]>([])
  const [hints, setHints] = useState<string[]>([])
  const canWrite = ['superadmin', 'admin'].includes(getUser()?.role || '')

  async function load() {
    try {
      const [queue, diag] = await Promise.all([
        api.queue(status || undefined, sender || undefined, recipient || undefined),
        api.queueDiagnostics(),
      ])
      setData(queue)
      setDiagnostics(diag.issues)
      setHints(diag.hints)
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  useEffect(() => { load() }, [])

  async function act(action: (id: string) => Promise<unknown>, item: QueueItem, label: string) {
    if (!confirm(`${label} для ${item.queue_id}?`)) return
    try {
      await action(item.queue_id)
      notify.success(`${label}: ${item.queue_id}`)
      setHeaders(null)
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function flushAll() {
    if (!confirm('Повторить доставку для всей очереди Postfix?')) return
    try {
      await api.flushQueue()
      notify.success('Запущена повторная доставка всей очереди')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  return (
    <div>
      <div className="topbar"><h2>Очередь Postfix</h2></div>
      <div className="card">
        <p className="muted">
          Письма, ожидающие доставки или повторной отправки. Удаление безвозвратно.
        </p>
        {diagnostics.length > 0 && (
          <div style={{ marginBottom: 16 }}>
            {diagnostics.map((issue) => (
              <div
                key={`${issue.level}:${issue.title}`}
                className={`card ${issue.level === 'error' ? 'error' : 'info'}`}
                style={{ marginBottom: 8, padding: '12px 16px' }}
              >
                <strong>{issue.title}</strong>
                <p className="prewrap" style={{ margin: '8px 0' }}>{issue.message}</p>
                <code style={{ display: 'block', whiteSpace: 'pre-wrap' }}>{issue.fix}</code>
              </div>
            ))}
          </div>
        )}
        {hints.map((hint) => (
          <p key={hint} className="muted">{hint}</p>
        ))}
        <div className="grid">
          <div className="stat"><div className="label">Всего</div><div className="value">{data.total}</div></div>
          <div className="stat"><div className="label">Активные</div><div className="value">{data.active}</div></div>
          <div className="stat"><div className="label">Отложенные</div><div className="value">{data.deferred}</div></div>
          <div className="stat"><div className="label">На удержании</div><div className="value">{data.hold}</div></div>
        </div>
        <div className="form-row" style={{ marginTop: 16 }}>
          <select value={status} onChange={(e) => setStatus(e.target.value)}>
            {STATUS_OPTIONS.map((opt) => (
              <option key={opt.value || 'all'} value={opt.value}>{opt.label}</option>
            ))}
          </select>
          <input placeholder="Отправитель" value={sender} onChange={(e) => setSender(e.target.value)} />
          <input placeholder="Получатель" value={recipient} onChange={(e) => setRecipient(e.target.value)} />
          <button onClick={() => load()}>Применить</button>
          {canWrite && <button className="secondary" onClick={flushAll}>Повторить всю очередь</button>}
        </div>
      </div>
      <div className="card table-scroll">
        <table className="data-table">
          <colgroup>
            <col className="col-queue-id" />
            <col className="col-status" />
            <col className="col-time" />
            <col />
            <col />
            <col className="col-size" />
            <col className="col-reason" />
            <col className="col-actions" />
          </colgroup>
          <thead>
            <tr>
              <th>Queue-ID</th>
              <th>Статус</th>
              <th>Время</th>
              <th>От</th>
              <th>Кому</th>
              <th>Размер</th>
              <th>Причина</th>
              <th className="actions">Действия</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((item) => {
              const recipientsText = formatRecipients(item.recipients)
              return (
                <tr key={item.queue_id}>
                  <td title={item.queue_id}><code>{item.queue_id}</code></td>
                  <td>
                    <span className={`badge ${item.status === 'deferred' ? 'down' : ''}`}>
                      {statusLabel(item.status)}
                    </span>
                  </td>
                  <td title={item.arrival_time}>{item.arrival_time}</td>
                  <td title={item.sender || ''}>{item.sender || '—'}</td>
                  <td title={recipientsText}>{recipientsText || '—'}</td>
                  <td>{item.size_bytes} B</td>
                  <td title={item.reason || ''}>{item.reason || '—'}</td>
                  <td className="actions">
                    <button
                      className="secondary"
                      onClick={async () => {
                        try {
                          const res = await api.queueHeaders(item.queue_id)
                          setHeaders(res.headers)
                        } catch (e) {
                          notify.error(errorMessage(e))
                        }
                      }}
                    >
                      Заголовки
                    </button>
                    {canWrite && (
                      <>
                        <button onClick={() => act(api.flushQueueItem, item, 'Повторить')}>Повторить</button>
                        {item.status === 'hold' ? (
                          <button className="secondary" onClick={() => act(api.releaseQueueItem, item, 'Снять удержание')}>
                            Снять удержание
                          </button>
                        ) : (
                          <button className="secondary" onClick={() => act(api.holdQueueItem, item, 'Удержать')}>
                            Удержать
                          </button>
                        )}
                        <button className="danger" onClick={() => act(api.deleteQueueItem, item, 'Удалить')}>Удалить</button>
                      </>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
        {!data.items.length && <p className="muted">Очередь пуста</p>}
      </div>
      {headers && (
        <div className="card">
          <div className="topbar">
            <h3>Заголовки</h3>
            <button className="secondary" onClick={() => setHeaders(null)}>Закрыть</button>
          </div>
          <pre className="log-box">{headers}</pre>
        </div>
      )}
    </div>
  )
}
