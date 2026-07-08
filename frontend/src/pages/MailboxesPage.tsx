import { useEffect, useState } from 'react'
import { api, getUser } from '../api'
import { errorMessage, validateEmail, validateMailboxPassword } from '../errors'

export default function MailboxesPage() {
  const [items, setItems] = useState<any[]>([])
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [name, setName] = useState('')
  const [quota, setQuota] = useState('1024')
  const [error, setError] = useState('')
  const role = getUser()?.role
  const canWrite = role === 'superadmin' || role === 'admin'

  async function load() {
    setItems(await api.mailboxes())
  }

  useEffect(() => { load().catch((e) => setError(errorMessage(e))) }, [])

  async function create() {
    setError('')
    const email = username.trim().toLowerCase()
    const usernameError = validateEmail(username, 'Ящик')
    const passwordError = validateMailboxPassword(password)
    const quotaNum = Number(quota)
    if (!Number.isFinite(quotaNum) || quotaNum < 0) {
      setError('Квота: введите число 0 или больше (MB)')
      return
    }
    if (usernameError || passwordError) {
      setError([usernameError, passwordError].filter(Boolean).join('\n'))
      return
    }
    if (items.some((m) => m.username.toLowerCase() === email)) {
      setError(`Ящик уже существует: ${email}`)
      return
    }
    try {
      await api.createMailbox({ username: email, password, name, quota: quotaNum })
      setUsername('')
      setPassword('')
      setName('')
      setQuota('1024')
      await load()
    } catch (e) {
      setError(errorMessage(e))
    }
  }

  async function remove(u: string) {
    if (!confirm(`Удалить ${u}?`)) return
    setError('')
    try {
      await api.deleteMailbox(u)
      await load()
    } catch (e) {
      setError(errorMessage(e))
    }
  }

  async function resetPassword(u: string) {
    const p = prompt('Новый пароль ящика (мин. 8 символов, A-z, a-z, цифра)')
    if (!p) return
    const passwordError = validateMailboxPassword(p)
    if (passwordError) {
      alert(passwordError)
      return
    }
    try {
      await api.mailboxPassword(u, p)
      alert('Пароль изменён')
    } catch (e) {
      alert(errorMessage(e))
    }
  }

  async function changeQuota(u: string, current: number) {
    const raw = prompt(`Квота для ${u} (MB). 0 = без лимита`, String(current))
    if (raw === null) return
    const quotaNum = Number(raw)
    if (!Number.isFinite(quotaNum) || quotaNum < 0) {
      alert('Квота: введите число 0 или больше')
      return
    }
    setError('')
    try {
      await api.mailboxQuota(u, quotaNum)
      await load()
    } catch (e) {
      setError(errorMessage(e))
    }
  }

  async function toggleActive(u: string, active: number) {
    const enable = !active
    const action = enable ? 'активировать' : 'отключить'
    if (!confirm(`${action} ящик ${u}?`)) return
    setError('')
    try {
      await api.mailboxActive(u, enable)
      await load()
    } catch (e) {
      setError(errorMessage(e))
    }
  }

  return (
    <div>
      <div className="topbar"><h2>Почтовые ящики</h2></div>
      {canWrite && (
        <div className="card">
          <h3>Создать ящик</h3>
          <div className="form-row">
            <input placeholder="user@domain.ru" value={username} onChange={(e) => setUsername(e.target.value)} />
            <input placeholder="Имя" value={name} onChange={(e) => setName(e.target.value)} />
            <input type="password" placeholder="Пароль" value={password} onChange={(e) => setPassword(e.target.value)} />
            <input type="number" min={0} placeholder="Квота MB" value={quota} onChange={(e) => setQuota(e.target.value)} style={{ width: 110 }} />
            <button onClick={create}>Создать</button>
          </div>
          {error && <div className="error prewrap">{error}</div>}
          <p className="muted">
            Адрес ящика уникален. Пароль: мин. 8 символов, заглавная и строчная латинские буквы, цифра. Квота в мегабайтах (1024 = 1 ГБ).
          </p>
        </div>
      )}
      {!canWrite && error && <div className="error prewrap">{error}</div>}
      <div className="card">
        <table>
          <thead><tr><th>Ящик</th><th>Имя</th><th>Квота</th><th>Активен</th>{canWrite && <th></th>}</tr></thead>
          <tbody>
            {items.map((m) => (
              <tr key={m.username} className={m.active ? '' : 'inactive-row'}>
                <td>{m.username}</td><td>{m.name}</td><td>{m.quota} MB</td><td>{m.active ? 'да' : 'нет'}</td>
                {canWrite && <td className="actions">
                  <button className="secondary" onClick={() => resetPassword(m.username)}>Пароль</button>
                  <button className="secondary" onClick={() => changeQuota(m.username, m.quota)}>Квота</button>
                  <button className="secondary" onClick={() => toggleActive(m.username, m.active)}>
                    {m.active ? 'Отключить' : 'Включить'}
                  </button>
                  <button className="danger" onClick={() => remove(m.username)}>Удалить</button>
                </td>}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
