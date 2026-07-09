import { useEffect, useState } from 'react'
import { api, getUser } from '../api'
import { errorMessage, validateEmail } from '../errors'
import { notify } from '../notify'

export default function AliasesPage() {
  const [items, setItems] = useState<any[]>([])
  const [address, setAddress] = useState('')
  const [goto, setGoto] = useState('')
  const role = getUser()?.role
  const canWrite = role === 'superadmin' || role === 'admin'

  async function load() {
    setItems(await api.aliases())
  }

  useEffect(() => {
    load().catch((e) => notify.error(errorMessage(e)))
  }, [])

  async function create() {
    const addressError = validateEmail(address, 'Адрес алиаса')
    const gotoError = validateEmail(goto, 'Пересылка на')
    if (addressError || gotoError) {
      notify.error([addressError, gotoError].filter(Boolean).join('\n'))
      return
    }
    try {
      await api.createAlias({ address: address.trim(), goto: goto.trim() })
      setAddress('')
      setGoto('')
      notify.success('Алиас создан')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function remove(addr: string) {
    if (!confirm(`Удалить алиас ${addr}?`)) return
    try {
      await api.deleteAlias(addr)
      notify.success('Алиас удалён')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
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
          <p className="muted">Алиас — отдельный адрес без ящика; письма уходят на существующий ящик в вашем домене.</p>
        </div>
      )}
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
