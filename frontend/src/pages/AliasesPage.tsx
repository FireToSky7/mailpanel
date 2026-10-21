import { useEffect, useState } from 'react'
import { api, getUser, type ForwardingEntry, type Mailbox } from '../api'
import { errorMessage, validateEmail } from '../errors'
import { notify } from '../notify'

export default function AliasesPage() {
  const [items, setItems] = useState<any[]>([])
  const [forwardings, setForwardings] = useState<ForwardingEntry[]>([])
  const [mailboxes, setMailboxes] = useState<Mailbox[]>([])
  const [address, setAddress] = useState('')
  const [goto, setGoto] = useState('')
  const [fwdMailbox, setFwdMailbox] = useState('')
  const [fwdTarget, setFwdTarget] = useState('')
  const [fwdKeepCopy, setFwdKeepCopy] = useState(true)
  const [busyKeep, setBusyKeep] = useState<string | null>(null)
  const role = getUser()?.role
  const canWrite = role === 'superadmin' || role === 'admin'

  async function load() {
    const [aliases, fwd, boxes] = await Promise.all([
      api.aliases(),
      api.forwardings(),
      api.mailboxes(),
    ])
    setItems(aliases)
    setForwardings(fwd)
    setMailboxes(boxes)
    if (!fwdMailbox && boxes.length) {
      setFwdMailbox(boxes[0].username)
    }
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

  async function addForwarding() {
    if (!fwdMailbox) {
      notify.error('Выберите ящик')
      return
    }
    const targetError = validateEmail(fwdTarget, 'Пересылка на')
    if (targetError) {
      notify.error(targetError)
      return
    }
    const target = fwdTarget.trim()
    try {
      await api.setMailboxForwarding(fwdMailbox, target, fwdKeepCopy)
      setFwdTarget('')
      notify.success(
        fwdKeepCopy
          ? `Добавлена пересылка с копией в ящике: ${fwdMailbox} → ${target}`
          : `Добавлена пересылка без копии: ${fwdMailbox} → ${target}`,
      )
      setForwardings(await api.forwardings())
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function removeForwarding(address: string, goto: string) {
    if (!confirm(`Отключить пересылку ${address} → ${goto}?`)) return
    try {
      const res = await api.removeMailboxForwarding(address, goto)
      setForwardings(res.items)
      notify.success('Пересылка отключена')
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function toggleKeepCopy(address: string, keep_copy: boolean) {
    setBusyKeep(address)
    try {
      const res = await api.setForwardingKeepCopy(address, keep_copy)
      setForwardings(res.items)
      notify.success(
        keep_copy
          ? `Копия в ящике ${address} включена`
          : `Копия в ящике ${address} выключена — только пересылка`,
      )
    } catch (e) {
      notify.error(errorMessage(e))
    } finally {
      setBusyKeep(null)
    }
  }

  return (
    <div>
      <div className="topbar"><h2>Алиасы и пересылка</h2></div>

      <div className="card">
        <h3>Алиасы</h3>
        {canWrite && (
          <>
            <div className="form-row">
              <input placeholder="alias@domain.ru" value={address} onChange={(e) => setAddress(e.target.value)} />
              <input placeholder="target@domain.ru" value={goto} onChange={(e) => setGoto(e.target.value)} />
              <button onClick={create}>Добавить алиас</button>
            </div>
            <p className="muted">Алиас — отдельный адрес без ящика; письма уходят на существующий ящик в вашем домене.</p>
          </>
        )}
        <table>
          <thead><tr><th>Адрес</th><th>Пересылка на</th>{canWrite && <th></th>}</tr></thead>
          <tbody>
            {items.length === 0 && (
              <tr><td colSpan={canWrite ? 3 : 2} className="muted">Алиасов нет</td></tr>
            )}
            {items.map((a) => (
              <tr key={a.address}>
                <td>{a.address}</td><td>{a.goto || '—'}</td>
                {canWrite && <td><button className="danger" onClick={() => remove(a.address)}>Удалить</button></td>}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="card">
        <h3>Пересылка ящиков</h3>
        <p className="muted">
          Можно добавить несколько адресов пересылки для одного ящика.
          Чекбокс «Оставлять копию» — письмо приходит и в исходный ящик, и на адрес пересылки.
          Без галочки письмо только пересылается (в исходном ящике не остаётся).
          Нельзя настраивать пересылку по кругу (u1 → u2 и u2 → u1).
        </p>
        {canWrite && (
          <>
            <div className="form-row" style={{ marginBottom: 8 }}>
              <select value={fwdMailbox} onChange={(e) => setFwdMailbox(e.target.value)}>
                {mailboxes.map((m) => (
                  <option key={m.username} value={m.username}>{m.username}</option>
                ))}
              </select>
              <input
                placeholder="куда пересылать (user@domain.ru)"
                value={fwdTarget}
                onChange={(e) => setFwdTarget(e.target.value)}
              />
              <button onClick={addForwarding}>Добавить</button>
            </div>
            <label className="check-label" style={{ marginBottom: 16, display: 'inline-flex' }}>
              <input
                type="checkbox"
                checked={fwdKeepCopy}
                onChange={(e) => setFwdKeepCopy(e.target.checked)}
              />
              Оставлять копию в ящике исходного адресата
            </label>
          </>
        )}
        <table>
          <thead>
            <tr>
              <th>Ящик</th>
              <th>Пересылка на</th>
              <th>Копия в ящике</th>
              {canWrite && <th></th>}
            </tr>
          </thead>
          <tbody>
            {forwardings.length === 0 && (
              <tr>
                <td colSpan={canWrite ? 4 : 3} className="muted">Пересылка не настроена</td>
              </tr>
            )}
            {forwardings.map((f) => (
              <tr key={`${f.address}:${f.goto}`}>
                <td>{f.address}</td>
                <td>{f.goto}</td>
                <td>
                  {canWrite ? (
                    <label className="check-label">
                      <input
                        type="checkbox"
                        checked={Boolean(f.keep_copy)}
                        disabled={busyKeep === f.address}
                        onChange={(e) => toggleKeepCopy(f.address, e.target.checked)}
                      />
                      {f.keep_copy ? 'Да' : 'Нет'}
                    </label>
                  ) : (
                    f.keep_copy ? 'Да' : 'Нет'
                  )}
                </td>
                {canWrite && (
                  <td className="actions">
                    <button className="danger" onClick={() => removeForwarding(f.address, f.goto)}>Отключить</button>
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
