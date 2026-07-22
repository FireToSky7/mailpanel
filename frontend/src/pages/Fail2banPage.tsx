import { useEffect, useState } from 'react'
import { api, getUser, type Fail2banData, type Fail2banSettings } from '../api'
import { errorMessage } from '../errors'
import { notify } from '../notify'

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds} с`
  if (seconds < 3600) return `${Math.round(seconds / 60)} мин`
  if (seconds < 86400) return `${Math.round(seconds / 3600)} ч`
  return `${Math.round(seconds / 86400)} д`
}

export default function Fail2banPage() {
  const [data, setData] = useState<Fail2banData | null>(null)
  const [bantime, setBantime] = useState(3600)
  const [maxretry, setMaxretry] = useState(5)
  const [findtime, setFindtime] = useState(600)
  const [disableMailbox, setDisableMailbox] = useState(false)
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const canWrite = ['superadmin', 'admin'].includes(getUser()?.role || '')

  function applySettingsForm(settings: Fail2banSettings) {
    setBantime(settings.bantime)
    setMaxretry(settings.maxretry)
    setFindtime(settings.findtime)
    setDisableMailbox(settings.disable_mailbox_on_ban)
  }

  async function load() {
    setLoading(true)
    try {
      const res = await api.fail2ban()
      setData(res)
      applySettingsForm(res.settings)
    } catch (e) {
      notify.error(errorMessage(e))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  async function saveSettings() {
    setSaving(true)
    try {
      const settings = await api.updateFail2banSettings({
        bantime,
        maxretry,
        findtime,
        disable_mailbox_on_ban: disableMailbox,
      })
      applySettingsForm(settings)
      notify.success('Настройки Fail2ban сохранены')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    } finally {
      setSaving(false)
    }
  }

  async function unban(jail: string, ip: string) {
    try {
      await api.unban(jail, ip)
      notify.success(`IP ${ip} разблокирован`)
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  const bans = data?.bans ?? []
  const recent = data?.settings.recent_disabled ?? []

  return (
    <div>
      <div className="topbar">
        <h2>Fail2ban</h2>
        <button className="secondary" onClick={() => load()} disabled={loading}>
          {loading ? 'Обновление…' : 'Обновить'}
        </button>
      </div>

      <div className="card">
        <h3>Параметры</h3>
        <p className="muted" style={{ marginTop: 0 }}>
          Через сколько неудачных попыток банить IP и на какой срок.
          Findtime — окно, в котором считаются попытки.
        </p>
        <div className="form-row" style={{ flexWrap: 'wrap', gap: 12 }}>
          <label>
            Попыток до бана
            <input
              type="number"
              min={1}
              max={100}
              value={maxretry}
              disabled={!canWrite || saving}
              onChange={(e) => setMaxretry(Number(e.target.value) || 1)}
              style={{ display: 'block', marginTop: 4, width: 120 }}
            />
          </label>
          <label>
            Бан (секунды)
            <input
              type="number"
              min={60}
              max={2592000}
              value={bantime}
              disabled={!canWrite || saving}
              onChange={(e) => setBantime(Number(e.target.value) || 60)}
              style={{ display: 'block', marginTop: 4, width: 140 }}
            />
            <span className="muted" style={{ fontSize: 12 }}>{formatDuration(bantime)}</span>
          </label>
          <label>
            Окно попыток (сек)
            <input
              type="number"
              min={60}
              max={86400}
              value={findtime}
              disabled={!canWrite || saving}
              onChange={(e) => setFindtime(Number(e.target.value) || 60)}
              style={{ display: 'block', marginTop: 4, width: 140 }}
            />
            <span className="muted" style={{ fontSize: 12 }}>{formatDuration(findtime)}</span>
          </label>
        </div>
        <label className="form-row" style={{ alignItems: 'center', gap: 10, marginTop: 14 }}>
          <input
            type="checkbox"
            checked={disableMailbox}
            disabled={!canWrite || saving}
            onChange={(e) => setDisableMailbox(e.target.checked)}
          />
          При бане Fail2ban отключать атакуемый ящик (включить обратно — во вкладке «Ящики»)
        </label>
        {canWrite && (
          <div className="form-row" style={{ marginTop: 12 }}>
            <button onClick={saveSettings} disabled={saving}>
              {saving ? 'Сохранение…' : 'Сохранить настройки'}
            </button>
          </div>
        )}
        {(data?.settings.notes || []).map((note) => (
          <p key={note} className="muted" style={{ marginBottom: 4 }}>{note}</p>
        ))}
      </div>

      <div className="card">
        <h3>Заблокированные IP</h3>
        <table className="data-table">
          <thead>
            <tr>
              <th>IP</th>
              <th>Jail</th>
              {canWrite && <th className="col-actions"></th>}
            </tr>
          </thead>
          <tbody>
            {bans.length === 0 && (
              <tr>
                <td colSpan={canWrite ? 3 : 2} className="muted">Заблокированных IP нет</td>
              </tr>
            )}
            {bans.map((row) => (
              <tr key={`${row.jail}:${row.ip}`}>
                <td>{row.ip}</td>
                <td>{row.jail}</td>
                {canWrite && (
                  <td className="actions">
                    <button className="secondary" onClick={() => unban(row.jail, row.ip)}>
                      Разблокировать
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {recent.length > 0 && (
        <div className="card">
          <h3>Недавно отключённые ящики</h3>
          <p className="muted" style={{ marginTop: 0 }}>
            Автоматически отключены при срабатывании Fail2ban. Включить снова — «Ящики».
          </p>
          <table className="data-table">
            <thead>
              <tr>
                <th>Ящик</th>
                <th>IP</th>
                <th>Jail</th>
                <th>Когда (UTC)</th>
              </tr>
            </thead>
            <tbody>
              {recent.map((item, idx) => (
                <tr key={`${item.mailbox}-${item.at}-${idx}`}>
                  <td>{item.mailbox}</td>
                  <td>{item.ip}</td>
                  <td>{item.jail}</td>
                  <td>{item.at}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
