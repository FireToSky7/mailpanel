import { useEffect, useState } from 'react'
import { api } from '../api'
import { errorMessage } from '../errors'
import { notify } from '../notify'

export default function PanelUsersPage() {
  const [users, setUsers] = useState<any[]>([])
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState('admin')
  const [displayName, setDisplayName] = useState('')

  async function load() {
    setUsers(await api.panelUsers())
  }

  useEffect(() => {
    load().catch((e) => notify.error(errorMessage(e)))
  }, [])

  return (
    <div>
      <div className="topbar"><h2>Администраторы панели</h2></div>
      <div className="card">
        <h3>Создать пользователя панели</h3>
        <div className="form-row">
          <input placeholder="Логин" value={username} onChange={(e) => setUsername(e.target.value)} />
          <input type="password" placeholder="Пароль" value={password} onChange={(e) => setPassword(e.target.value)} />
          <input placeholder="Отображаемое имя" value={displayName} onChange={(e) => setDisplayName(e.target.value)} />
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="superadmin">superadmin</option>
            <option value="admin">admin</option>
            <option value="viewer">viewer</option>
          </select>
          <button onClick={async () => {
            try {
              await api.createPanelUser({
                username,
                password,
                role,
                display_name: displayName || username,
                mailbox: null,
              })
              setUsername('')
              setPassword('')
              setDisplayName('')
              notify.success('Пользователь панели создан')
              await load()
            } catch (e) {
              notify.error(errorMessage(e))
            }
          }}>Создать</button>
        </div>
        <p className="muted">Роли: superadmin — всё; admin — почта и антиспам; viewer — только просмотр. Обычные пользователи почты работают через Roundcube.</p>
      </div>
      <div className="card">
        <table>
          <thead><tr><th>Логин</th><th>Роль</th><th></th></tr></thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td>{u.username}</td><td>{u.role}</td>
                <td>
                  <button className="secondary" onClick={async () => {
                    const p = prompt('Новый пароль панели')
                    if (!p) return
                    try {
                      await api.panelUserPassword(u.id, p)
                      notify.success('Пароль обновлён')
                    } catch (e) {
                      notify.error(errorMessage(e))
                    }
                  }}>Пароль</button>{' '}
                  <button className="danger" onClick={async () => {
                    try {
                      await api.deletePanelUser(u.id)
                      notify.success('Пользователь удалён')
                      await load()
                    } catch (e) {
                      notify.error(errorMessage(e))
                    }
                  }}>Удалить</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
