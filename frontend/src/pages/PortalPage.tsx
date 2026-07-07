import { useEffect, useState } from 'react'
import { api } from '../api'

export default function PortalPage() {
  const [forwarding, setForwarding] = useState<any>(null)
  const [goto, setGoto] = useState('')
  const [whitelist, setWhitelist] = useState<string[]>([])
  const [entry, setEntry] = useState('')

  async function load() {
    setForwarding(await api.myForwarding())
    const wl = await api.wblist('whitelist')
    setWhitelist(wl.entries)
  }

  useEffect(() => { load().catch(console.error) }, [])

  return (
    <div>
      <div className="topbar"><h2>Мой ящик</h2></div>
      <div className="card">
        <p className="muted">
          Основная работа с почтой — в веб-клиенте (Roundcube: /mail). Здесь — настройки, которых нет в ящике:
          пересылка и личный белый список. Пароль меняет только администратор.
        </p>
      </div>
      <div className="card">
        <h3>Пересылка</h3>
        <p>Текущая: {forwarding?.goto || 'не настроена'}</p>
        <div className="form-row">
          <input placeholder="forward@example.com" value={goto} onChange={(e) => setGoto(e.target.value)} />
          <button onClick={async () => { await api.setForwarding(goto); load() }}>Сохранить</button>
          <button className="secondary" onClick={async () => { await api.clearForwarding(); load() }}>Отключить</button>
        </div>
      </div>
      <div className="card">
        <h3>Мой белый список</h3>
        <div className="form-row">
          <input placeholder="sender@example.com" value={entry} onChange={(e) => setEntry(e.target.value)} />
          <button onClick={async () => { await api.addWblist('whitelist', [entry]); setEntry(''); load() }}>Добавить</button>
        </div>
        <ul>{whitelist.map((e) => <li key={e}>{e} <button className="danger" onClick={async () => { await api.deleteWblist('whitelist', [e]); load() }}>x</button></li>)}</ul>
      </div>
    </div>
  )
}
