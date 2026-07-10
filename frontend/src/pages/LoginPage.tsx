import { useState } from 'react'
import { api, setSession } from '../api'
import ToastStack from '../components/ToastStack'
import { errorMessage } from '../errors'
import { notify } from '../notify'
import { toAppUrl } from '../paths'

export default function LoginPage() {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    try {
      const res = await api.login(username, password)
      setSession(res.access_token, { username, role: res.role, display_name: res.display_name })
      window.location.href = toAppUrl('/')
    } catch (err) {
      notify.error(errorMessage(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-page">
      <ToastStack />
      <div className="card login-card">
        <h2>MailPanel</h2>
        <p className="muted">Панель управления почтовым сервером iRedMail</p>
        <form onSubmit={onSubmit}>
          <div className="form-row"><input placeholder="Логин" value={username} onChange={(e) => setUsername(e.target.value)} required /></div>
          <div className="form-row"><input type="password" placeholder="Пароль" value={password} onChange={(e) => setPassword(e.target.value)} required /></div>
          <button type="submit" disabled={loading} style={{ width: '100%' }}>{loading ? 'Вход...' : 'Войти'}</button>
        </form>
      </div>
    </div>
  )
}
