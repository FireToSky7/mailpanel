import { useEffect, useState } from 'react'
import { api } from '../api'

export default function PanelUsersPage() {
  const [users, setUsers] = useState<any[]>([])
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState('admin')
  const [mailbox, setMailbox] = useState('')

  async function load() { setUsers(await api.panelUsers()) }
  useEffect(() => { load() }, [])

  return (
    <div>
      <div className="topbar"><h2>Администраторы панели</h2></div>
      <div className="card">
        <h3>Создать пользователя панели</h3>
        <div className="form-row">
          <input placeholder="Логин" value={username} onChange={(e) => setUsername(e.target.value)} />
          <input type="password" placeholder="Пароль" value={password} onChange={(e) => setPassword(e.target.value)} />
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="superadmin">superadmin</option>
            <option value="admin">admin</option>
            <option value="viewer">viewer</option>
            <option value="user">user</option>
          </select>
          {role === 'user' && <input placeholder="mailbox@domain.ru" value={mailbox} onChange={(e) => setMailbox(e.target.value)} />}
          <button onClick={async () => {
            await api.createPanelUser({ username, password, role, mailbox: role === 'user' ? mailbox : null })
            setUsername(''); setPassword(''); setMailbox('')
            load()
          }}>Создать</button>
        </div>
        <p className="muted">Роли: superadmin — всё; admin — почта и антиспам; viewer — только просмотр; user — личный портал (пересылка, белый список).</p>
      </div>
      <div className="card">
        <table>
          <thead><tr><th>Логин</th><th>Роль</th><th>Ящик</th><th></th></tr></thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td>{u.username}</td><td>{u.role}</td><td>{u.mailbox || '—'}</td>
                <td>
                  <button className="secondary" onClick={async () => {
                    const p = prompt('Новый пароль панели')
                    if (p) { await api.panelUserPassword(u.id, p); alert('OK') }
                  }}>Пароль</button>{' '}
                  <button className="danger" onClick={async () => { await api.deletePanelUser(u.id); load() }}>Удалить</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
