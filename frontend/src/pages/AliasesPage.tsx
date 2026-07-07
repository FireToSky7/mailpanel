import { useEffect, useState } from 'react'
import { api, getUser } from '../api'

export default function AliasesPage() {
  const [items, setItems] = useState<any[]>([])
  const [address, setAddress] = useState('')
  const [goto, setGoto] = useState('')
  const role = getUser()?.role
  const canWrite = role === 'superadmin' || role === 'admin'

  async function load() { setItems(await api.aliases()) }
  useEffect(() => { load() }, [])

  return (
    <div>
      <div className="topbar"><h2>Алиасы и пересылка</h2></div>
      {canWrite && (
        <div className="card">
          <div className="form-row">
            <input placeholder="alias@domain.ru" value={address} onChange={(e) => setAddress(e.target.value)} />
            <input placeholder="target@domain.ru" value={goto} onChange={(e) => setGoto(e.target.value)} />
            <button onClick={async () => { await api.createAlias({ address, goto }); setAddress(''); setGoto(''); load() }}>Добавить</button>
          </div>
        </div>
      )}
      <div className="card">
        <table>
          <thead><tr><th>Адрес</th><th>Пересылка на</th>{canWrite && <th></th>}</tr></thead>
          <tbody>
            {items.map((a) => (
              <tr key={a.address}>
                <td>{a.address}</td><td>{a.goto}</td>
                {canWrite && <td><button className="danger" onClick={async () => { await api.deleteAlias(a.address); load() }}>Удалить</button></td>}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
