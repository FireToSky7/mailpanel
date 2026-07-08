import { useEffect, useState } from 'react'
import { api, getUser } from '../api'

export default function AliasesPage() {
  const [items, setItems] = useState<any[]>([])
  const [address, setAddress] = useState('')
  const [goto, setGoto] = useState('')
  const [error, setError] = useState('')
  const role = getUser()?.role
  const canWrite = role === 'superadmin' || role === 'admin'

  async function load() {
    setItems(await api.aliases())
  }

  useEffect(() => {
    load().catch((e) => setError(e.message))
  }, [])

  async function create() {
    setError('')
    try {
      await api.createAlias({ address, goto })
      setAddress('')
      setGoto('')
      await load()
    } catch (e: any) {
      setError(e.message)
    }
  }

  async function remove(addr: string) {
    if (!confirm(`Удалить алиас ${addr}?`)) return
    setError('')
    try {
      await api.deleteAlias(addr)
      await load()
    } catch (e: any) {
      setError(e.message)
    }
  }

  return (
    <div>
      <div className="topbar"><h2>Алиасы и пересылка</h2></div>
      {canWrite && (
        <div className="card">
          <div className="form-row">
            <input placeholder="alias@domain.ru" value={address} onChange={(e) => setAddress(e.target.value)} />
            <input placeholder="target@domain.ru" value={goto} onChange={(e) => setGoto(e.target.value)} />
            <button onClick={create}>Добавить</button>
          </div>
          <p className="muted">Алиас — отдельный адрес без ящика; письма уходят на указанный ящик.</p>
        </div>
      )}
      {error && <p className="error">{error}</p>}
      <div className="card">
        <table>
          <thead><tr><th>Адрес</th><th>Пересылка на</th>{canWrite && <th></th>}</tr></thead>
          <tbody>
            {items.map((a) => (
              <tr key={a.address}>
                <td>{a.address}</td><td>{a.goto || '—'}</td>
                {canWrite && <td><button className="danger" onClick={() => remove(a.address)}>Удалить</button></td>}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
