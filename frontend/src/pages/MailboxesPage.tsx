import { useEffect, useState } from 'react'
import { api, getUser } from '../api'
import { errorMessage, validateEmail, validateMailboxPassword } from '../errors'
import { notify } from '../notify'

function formatQuota(usedMb: number | undefined, quotaMb: number): string {
  const used = usedMb ?? 0
  if (!quotaMb) return `${used} / без лимита`
  return `${used} / ${quotaMb} MB`
}

export default function MailboxesPage() {
  const [items, setItems] = useState<any[]>([])
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [name, setName] = useState('')
  const [quota, setQuota] = useState('1024')
  const role = getUser()?.role
  const canWrite = role === 'superadmin' || role === 'admin'

  async function load() {
    setItems(await api.mailboxes())
  }

  useEffect(() => {
    load().catch((e) => notify.error(errorMessage(e)))
  }, [])

  async function create() {
    const email = username.trim().toLowerCase()
    const usernameError = validateEmail(username, 'Ящик')
    const passwordError = validateMailboxPassword(password)
    const quotaNum = Number(quota)
    if (!Number.isFinite(quotaNum) || quotaNum < 0) {
      notify.error('Квота: введите число 0 или больше (MB)')
      return
    }
    if (usernameError || passwordError) {
      notify.error([usernameError, passwordError].filter(Boolean).join('\n'))
      return
    }
    if (items.some((m) => m.username.toLowerCase() === email)) {
      notify.error(`Ящик уже существует: ${email}`)
      return
    }
    try {
      await api.createMailbox({ username: email, password, name, quota: quotaNum })
      setUsername('')
      setPassword('')
      setName('')
      setQuota('1024')
      notify.success('Ящик создан')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function remove(u: string) {
    if (!confirm(`Удалить ${u}?`)) return
    try {
      await api.deleteMailbox(u)
      notify.success('Ящик удалён')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function resetPassword(u: string) {
    const p = prompt('Новый пароль ящика (мин. 8 символов, A-z, a-z, цифра)')
    if (!p) return
    const passwordError = validateMailboxPassword(p)
    if (passwordError) {
      notify.error(passwordError)
      return
    }
    try {
      await api.mailboxPassword(u, p)
      notify.success('Пароль изменён')
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function changeQuota(u: string, current: number) {
    const raw = prompt(`Квота для ${u} (MB). 0 = без лимита`, String(current))
    if (raw === null) return
    const quotaNum = Number(raw)
    if (!Number.isFinite(quotaNum) || quotaNum < 0) {
      notify.error('Квота: введите число 0 или больше')
      return
    }
    try {
      await api.mailboxQuota(u, quotaNum)
      notify.success('Квота сохранена')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function toggleActive(u: string, active: number) {
    const enable = !active
    const action = enable ? 'активировать' : 'отключить'
    if (!confirm(`${action} ящик ${u}?`)) return
    try {
      await api.mailboxActive(u, enable)
      notify.success(enable ? 'Ящик включён' : 'Ящик отключён')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
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
          <p className="muted">
            Адрес ящика уникален. Пароль: мин. 8 символов, заглавная и строчная латинские буквы, цифра. Квота в мегабайтах (1024 = 1 ГБ).
            Пересылку настраивайте во вкладке «Алиасы».
          </p>
        </div>
      )}
      <div className="card table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th>Ящик</th>
              <th>Имя</th>
              <th>Занято / квота</th>
              <th>Активен</th>
              {canWrite && <th className="actions">Действия</th>}
            </tr>
          </thead>
          <tbody>
            {items.map((m) => (
              <tr key={m.username} className={m.active ? '' : 'inactive-row'}>
                <td title={m.username}>{m.username}</td>
                <td>{m.name}</td>
                <td>{formatQuota(m.used_mb, m.quota)}</td>
                <td>{m.active ? 'да' : 'нет'}</td>
                {canWrite && (
                  <td className="actions">
                    <button className="secondary" onClick={() => resetPassword(m.username)}>Пароль</button>
                    <button className="secondary" onClick={() => changeQuota(m.username, m.quota)}>Квота</button>
                    <button className="secondary" onClick={() => toggleActive(m.username, m.active)}>
                      {m.active ? 'Отключить' : 'Включить'}
                    </button>
                    <button className="danger" onClick={() => remove(m.username)}>Удалить</button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
