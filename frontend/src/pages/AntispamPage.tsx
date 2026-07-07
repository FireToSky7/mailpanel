import { useEffect, useState } from 'react'
import { api, getUser } from '../api'

export default function AntispamPage() {
  const [whitelist, setWhitelist] = useState<string[]>([])
  const [blacklist, setBlacklist] = useState<string[]>([])
  const [entry, setEntry] = useState('')
  const [account, setAccount] = useState('')
  const [score, setScore] = useState('5.0')
  const [grey, setGrey] = useState<any>(null)
  const role = getUser()?.role
  const canWrite = role === 'superadmin' || role === 'admin'
  const isUser = role === 'user'

  async function load() {
    const wl = await api.wblist('whitelist', isUser ? undefined : account || undefined)
    setWhitelist(wl.entries)
    if (!isUser) {
      const bl = await api.wblist('blacklist', account || undefined)
      setBlacklist(bl.entries)
      const spam = await api.spam()
      setScore(spam.required_score)
      setGrey(await api.greylisting())
    }
  }

  useEffect(() => { load().catch(console.error) }, [])

  return (
    <div>
      <div className="topbar"><h2>Антиспам</h2></div>
      {canWrite && (
        <div className="card">
          <h3>Порог SpamAssassin</h3>
          <div className="form-row">
            <input value={score} onChange={(e) => setScore(e.target.value)} />
            <button onClick={async () => { await api.updateSpam({ required_score: parseFloat(score) }); alert('Сохранено') }}>Сохранить</button>
          </div>
        </div>
      )}
      <div className="card">
        <h3>Белый список {isUser ? '(личный)' : ''}</h3>
        {!isUser && <input placeholder="Аккаунт (пусто = глобально)" value={account} onChange={(e) => setAccount(e.target.value)} style={{ marginBottom: 10, width: '100%' }} />}
        <div className="form-row">
          <input placeholder="email / @domain / IP" value={entry} onChange={(e) => setEntry(e.target.value)} />
          <button onClick={async () => { await api.addWblist('whitelist', [entry], account || undefined); setEntry(''); load() }}>Добавить</button>
        </div>
        <ul>{whitelist.map((e) => <li key={e}>{e} {(canWrite || isUser) && <button className="danger" onClick={async () => { await api.deleteWblist('whitelist', [e], account || undefined); load() }}>x</button>}</li>)}</ul>
      </div>
      {canWrite && (
        <div className="card">
          <h3>Чёрный список</h3>
          <div className="form-row">
            <input placeholder="email / @domain / IP" value={entry} onChange={(e) => setEntry(e.target.value)} />
            <button onClick={async () => { await api.addWblist('blacklist', [entry], account || undefined); setEntry(''); load() }}>Добавить</button>
          </div>
          <ul>{blacklist.map((e) => <li key={e}>{e} <button className="danger" onClick={async () => { await api.deleteWblist('blacklist', [e], account || undefined); load() }}>x</button></li>)}</ul>
          {grey && <pre className="log-box">{grey.settings}</pre>}
        </div>
      )}
    </div>
  )
}
