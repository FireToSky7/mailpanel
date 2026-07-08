import { useEffect, useState } from 'react'
import { api, getUser } from '../api'
import { errorMessage, validateEmail, validateMailboxPassword } from '../errors'

export default function MailboxesPage() {
  const [items, setItems] = useState<any[]>([])
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [name, setName] = useState('')
  const [error, setError] = useState('')
  const role = getUser()?.role
  const canWrite = role === 'superadmin' || role === 'admin'

  async function load() {
    setItems(await api.mailboxes())
  }

  useEffect(() => { load().catch((e) => setError(errorMessage(e))) }, [])

  async function create() {
    setError('')
    const usernameError = validateEmail(username, 'Ящик')
    const passwordError = validateMailboxPassword(password)
    if (usernameError || passwordError) {
      setError([usernameError, passwordError].filter(Boolean).join('\n'))
      return
    }
    try {
      await api.createMailbox({ username: username.trim(), password, name, quota: 1024 })
      setUsername('')
      setPassword('')
      setName('')
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
            <button onClick={create}>Создать</button>
          </div>
          {error && <div className="error prewrap">{error}</div>}
          <p className="muted">
            Пароль ящика меняет только админ. Требования: минимум 8 символов, заглавная и строчная латинские буквы, цифра.
          </p>
        </div>
      )}
      {!canWrite && error && <div className="error prewrap">{error}</div>}
      <div className="card">
        <table>
          <thead><tr><th>Ящик</th><th>Имя</th><th>Квота</th><th>Активен</th>{canWrite && <th></th>}</tr></thead>
          <tbody>
            {items.map((m) => (
              <tr key={m.username}>
                <td>{m.username}</td><td>{m.name}</td><td>{m.quota} MB</td><td>{m.active ? 'да' : 'нет'}</td>
                {canWrite && <td>
                  <button className="secondary" onClick={() => resetPassword(m.username)}>Пароль</button>{' '}
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
