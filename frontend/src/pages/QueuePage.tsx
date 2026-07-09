import { useEffect, useState } from 'react'
import { api, getUser, type QueueItem } from '../api'
import { errorMessage } from '../errors'

const STATUS_OPTIONS = [
  { value: '', label: 'Все' },
  { value: 'active', label: 'Активные' },
  { value: 'deferred', label: 'Отложенные' },
  { value: 'hold', label: 'На удержании' },
  { value: 'incoming', label: 'Входящие' },
]

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
  const [error, setError] = useState('')
  const [info, setInfo] = useState('')
  const canWrite = ['superadmin', 'admin'].includes(getUser()?.role || '')

  async function load() {
    setError('')
    try {
      setData(await api.queue(status || undefined, sender || undefined, recipient || undefined))
    } catch (e) {
      setError(errorMessage(e))
    }
  }

  useEffect(() => { load() }, [])

  async function act(action: (id: string) => Promise<unknown>, item: QueueItem, label: string) {
    if (!confirm(`${label} для ${item.queue_id}?`)) return
    setError('')
    setInfo('')
    try {
      await action(item.queue_id)
      setInfo(`${label}: ${item.queue_id}`)
      setHeaders(null)
      await load()
    } catch (e) {
      setError(errorMessage(e))
    }
  }

  async function flushAll() {
    if (!confirm('Повторить доставку для всей очереди Postfix?')) return
    setError('')
    setInfo('')
    try {
      await api.flushQueue()
      setInfo('Запущена повторная доставка всей очереди')
      await load()
    } catch (e) {
      setError(errorMessage(e))
    }
  }

  return (
    <div>
      <div className="topbar"><h2>Очередь Postfix</h2></div>
      <div className="card">
        <p className="muted">
          Письма, ожидающие доставки или повторной отправки. Удаление безвозвратно.
        </p>
        <div className="grid">
          <div className="stat"><div className="label">Всего</div><div className="value">{data.total}</div></div>
          <div className="stat"><div className="label">Активные</div><div className="value">{data.active}</div></div>
          <div className="stat"><div className="label">Отложенные</div><div className="value">{data.deferred}</div></div>
          <div className="stat"><div className="label">Hold</div><div className="value">{data.hold}</div></div>
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
      {error && <div className="error prewrap card">{error}</div>}
      {info && <div className="info card">{info}</div>}
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
            {data.items.map((item) => (
              <tr key={item.queue_id}>
                <td title={item.queue_id}><code>{item.queue_id}</code></td>
                <td><span className={`badge ${item.status === 'deferred' ? 'down' : ''}`}>{item.status}</span></td>
                <td title={item.arrival_time}>{item.arrival_time}</td>
                <td title={item.sender || ''}>{item.sender || '—'}</td>
                <td title={item.recipients.join(', ')}>{item.recipients.join(', ') || '—'}</td>
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
                        setError(errorMessage(e))
                      }
                    }}
                  >
                    Заголовки
                  </button>
                  {canWrite && (
                    <>
                      <button onClick={() => act(api.flushQueueItem, item, 'Повторить')}>Повторить</button>
                      {item.status === 'hold' ? (
                        <button className="secondary" onClick={() => act(api.releaseQueueItem, item, 'Снять hold')}>Снять hold</button>
                      ) : (
                        <button className="secondary" onClick={() => act(api.holdQueueItem, item, 'Hold')}>Hold</button>
                      )}
                      <button className="danger" onClick={() => act(api.deleteQueueItem, item, 'Удалить')}>Удалить</button>
                    </>
                  )}
                </td>
              </tr>
            ))}
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
