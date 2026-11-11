import { useEffect, useState } from 'react'
import { api, getUser, type BackupItem, type BackupSettings } from '../api'
import { errorMessage } from '../errors'
import { notify } from '../notify'

function formatBytes(n?: number): string {
  if (n == null || Number.isNaN(n)) return '—'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

const empty: BackupSettings = {
  enabled: false,
  directory: '/var/backups/mailpanel',
  interval_hours: 24,
  retention_days: 14,
  timeout_seconds: 7200,
}

export default function BackupPage() {
  const [settings, setSettings] = useState<BackupSettings>(empty)
  const [items, setItems] = useState<BackupItem[]>([])
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [running, setRunning] = useState(false)
  const canWrite = ['superadmin', 'admin'].includes(getUser()?.role || '')

  async function load() {
    setLoading(true)
    try {
      const [s, list] = await Promise.all([api.backupSettings(), api.backupList()])
      setSettings(s)
      setItems(list.items)
      setRunning(Boolean(s.status?.running || list.status?.running))
    } catch (e) {
      notify.error(errorMessage(e))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  useEffect(() => {
    if (!running) return undefined
    const t = window.setInterval(() => {
      load().catch(() => undefined)
    }, 5000)
    return () => window.clearInterval(t)
  }, [running])

  async function save() {
    setSaving(true)
    try {
      const res = await api.updateBackupSettings({
        enabled: settings.enabled,
        directory: settings.directory.trim(),
        interval_hours: Number(settings.interval_hours),
        retention_days: Number(settings.retention_days),
        timeout_seconds: Number(settings.timeout_seconds),
      })
      setSettings((prev) => ({ ...prev, ...res }))
      notify.success(res.note || 'Настройки бэкапа сохранены')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    } finally {
      setSaving(false)
    }
  }

  async function runNow() {
    try {
      await api.runBackup()
      setRunning(true)
      notify.success('Бэкап запущен в фоне')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  const st = settings.status

  return (
    <div>
      <div className="topbar">
        <h2>Бэкапы</h2>
        <button className="secondary" type="button" onClick={() => load()} disabled={loading}>
          {loading ? 'Обновление…' : 'Обновить'}
        </button>
      </div>

      <div className="card">
        <h3>Автобэкап</h3>
        <p className="muted">
          Запускает <code>mailpanel-backup.sh</code> (формат 3: БД, конфиги, /var/vmail → .tgz).
          Каталог можно указать любой доступный для записи (NAS, второй диск и т.п.).
          Настройки пишутся в <code>config.yaml</code>.
        </p>
        <div className="form-row" style={{ flexWrap: 'wrap', gap: 12 }}>
          <label className="muted" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <input
              type="checkbox"
              checked={settings.enabled}
              disabled={!canWrite || saving}
              onChange={(e) => setSettings((s) => ({ ...s, enabled: e.target.checked }))}
            />
            Автобэкап включён
          </label>
          <label className="muted" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            Интервал (часов)
            <input
              type="number"
              min={6}
              max={336}
              step={1}
              style={{ width: 88 }}
              value={settings.interval_hours}
              disabled={!canWrite || saving}
              onChange={(e) => setSettings((s) => ({ ...s, interval_hours: Number(e.target.value) }))}
            />
          </label>
          <label className="muted" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            Хранить (дней)
            <input
              type="number"
              min={1}
              max={3650}
              style={{ width: 88 }}
              value={settings.retention_days}
              disabled={!canWrite || saving}
              onChange={(e) => setSettings((s) => ({ ...s, retention_days: Number(e.target.value) }))}
            />
          </label>
        </div>
        <div className="form-row" style={{ flexWrap: 'wrap', gap: 12, marginTop: 8 }}>
          <label className="muted" style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1, minWidth: 280 }}>
            Каталог выгрузки
            <input
              type="text"
              style={{ flex: 1, minWidth: 220 }}
              value={settings.directory}
              disabled={!canWrite || saving}
              placeholder="/var/backups/mailpanel"
              onChange={(e) => setSettings((s) => ({ ...s, directory: e.target.value }))}
            />
          </label>
          {canWrite && (
            <>
              <button type="button" onClick={save} disabled={saving}>
                {saving ? 'Сохранение…' : 'Сохранить'}
              </button>
              <button type="button" className="secondary" onClick={runNow} disabled={running || saving}>
                {running ? 'Идёт бэкап…' : 'Сделать сейчас'}
              </button>
            </>
          )}
        </div>
        <p className="muted" style={{ marginTop: 12, marginBottom: 0 }}>
          Статус:{' '}
          {st?.running
            ? `выполняется (старт ${st.last_started || '—'})`
            : st?.last_ok === true
              ? `последний успешный: ${st.last_finished || '—'} ${st.last_archive ? `(${st.last_archive})` : ''}`
              : st?.last_ok === false
                ? `ошибка: ${st.last_error || '—'}`
                : 'ещё не запускался'}
        </p>
      </div>

      <div className="card">
        <h3>Файлы в каталоге</h3>
        <p className="muted" style={{ marginTop: 0 }}>
          {settings.directory}
        </p>
        {items.length === 0 ? (
          <p className="muted">Пока нет .tgz — сделайте бэкап вручную или включите авто.</p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Файл</th>
                <th>Размер</th>
                <th>Дата</th>
              </tr>
            </thead>
            <tbody>
              {items.map((it) => (
                <tr key={it.path}>
                  <td><code>{it.name}</code></td>
                  <td>{formatBytes(it.size_bytes)}</td>
                  <td>{it.mtime}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
