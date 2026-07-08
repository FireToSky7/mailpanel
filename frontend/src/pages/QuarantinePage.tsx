import { useEffect, useState } from 'react'
import { api, getUser, type QuarantineBody, type QuarantineItem } from '../api'
import { errorMessage } from '../errors'

const CONTENT_OPTIONS = [
  { value: '', label: 'Все типы' },
  { value: 'S', label: 'Спам' },
  { value: 'V', label: 'Вирус' },
  { value: 'B', label: 'Запрещённый файл' },
  { value: 'H', label: 'Плохие заголовки' },
]

export default function QuarantinePage() {
  const [items, setItems] = useState<QuarantineItem[]>([])
  const [total, setTotal] = useState(0)
  const [content, setContent] = useState('')
  const [selected, setSelected] = useState<QuarantineBody | null>(null)
  const [error, setError] = useState('')
  const [info, setInfo] = useState('')
  const role = getUser()?.role
  const canWrite = role === 'superadmin' || role === 'admin'

  async function load() {
    setError('')
    try {
      const data = await api.quarantine(content || undefined)
      setItems(data.items)
      setTotal(data.total)
    } catch (e) {
      setError(errorMessage(e))
      setItems([])
      setTotal(0)
    }
  }

  useEffect(() => { load() }, [content])

  async function openBody(item: QuarantineItem) {
    setError('')
    try {
      setSelected(await api.quarantineBody(item.mail_id, item.partition_tag))
    } catch (e) {
      setError(errorMessage(e))
    }
  }

  async function release(item: QuarantineItem) {
    if (!confirm(`Освободить письмо «${item.subject}» и доставить получателям?`)) return
    setError('')
    setInfo('')
    try {
      await api.releaseQuarantine(item.mail_id, item.partition_tag)
      setInfo('Письмо освобождено и отправлено на доставку')
      setSelected(null)
      await load()
    } catch (e) {
      setError(errorMessage(e))
    }
  }

  async function remove(item: QuarantineItem) {
    if (!confirm(`Удалить письмо «${item.subject}» из карантина без доставки?`)) return
    setError('')
    setInfo('')
    try {
      await api.deleteQuarantine(item.mail_id, item.partition_tag)
      setInfo('Письмо удалено из карантина')
      if (selected?.mail_id === item.mail_id) setSelected(null)
      await load()
    } catch (e) {
      setError(errorMessage(e))
    }
  }

  return (
    <div>
      <div className="topbar"><h2>Карантин</h2></div>
      <div className="card">
        <p className="muted">
          Письма, задержанные Amavis до доставки: спам, вирусы, запрещённые вложения.
          Освобождение отправляет письмо получателям, удаление — без доставки.
        </p>
        <div className="form-row">
          <select value={content} onChange={(e) => setContent(e.target.value)}>
            {CONTENT_OPTIONS.map((opt) => (
              <option key={opt.value || 'all'} value={opt.value}>{opt.label}</option>
            ))}
          </select>
          <button className="secondary" onClick={() => load()}>Обновить</button>
        </div>
        <p className="muted">Всего в карантине: {total}</p>
      </div>
      {error && <div className="error prewrap card">{error}</div>}
      {info && <div className="info card">{info}</div>}
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>Время</th>
              <th>От</th>
              <th>Кому</th>
              <th>Тема</th>
              <th>Тип</th>
              <th>Размер</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={`${item.partition_tag}:${item.mail_id}`}>
                <td>{item.time_iso}</td>
                <td>{item.from_addr}</td>
                <td>{item.recipients.join(', ')}</td>
                <td>{item.subject}</td>
                <td>{item.content_label}</td>
                <td>{item.size} B</td>
                <td className="actions">
                  <button className="secondary" onClick={() => openBody(item)}>Просмотр</button>
                  {canWrite && (
                    <>
                      <button onClick={() => release(item)}>Освободить</button>
                      <button className="danger" onClick={() => remove(item)}>Удалить</button>
                    </>
                  )}
                  {!canWrite && (
                    <button className="danger" onClick={() => remove(item)}>Удалить</button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!items.length && <p className="muted">Карантин пуст</p>}
      </div>
      {selected && (
        <div className="card">
          <div className="topbar">
            <h3>{selected.subject}</h3>
            <button className="secondary" onClick={() => setSelected(null)}>Закрыть</button>
          </div>
          <p className="muted">
            {selected.from_addr} → {selected.recipients.join(', ')}
            {selected.spam_level != null ? ` · spam score ${selected.spam_level}` : ''}
          </p>
          {selected.attachments.length > 0 && (
            <p className="muted">Вложения: {selected.attachments.map((a) => a.filename).join(', ')}</p>
          )}
          <pre className="log-box" style={{ maxHeight: 320 }}>
            {selected.text_body || selected.html_body || 'Текст письма пуст или только вложения'}
          </pre>
          {canWrite && (
            <div className="form-row">
              <button onClick={() => release(selected)}>Освободить</button>
              <button className="danger" onClick={() => remove(selected)}>Удалить</button>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
