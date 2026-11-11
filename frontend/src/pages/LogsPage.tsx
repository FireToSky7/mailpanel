import { useEffect, useRef, useState } from 'react'
import { api, type LogArchive, type LogCollectorSettings } from '../api'
import { errorMessage } from '../errors'
import { notify } from '../notify'

const LIVE_TYPES: { id: string; label: string }[] = [
  { id: 'mail', label: 'Почта' },
  { id: 'dovecot', label: 'Dovecot' },
  { id: 'iredapd', label: 'iRedAPD' },
  { id: 'system', label: 'Система' },
]

function pad(n: number) {
  return String(n).padStart(2, '0')
}

function toLocalInput(d: Date): string {
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
}

function hoursAgo(hours: number): string {
  return toLocalInput(new Date(Date.now() - hours * 60 * 60 * 1000))
}

function formatBytes(n?: number): string {
  if (n == null || Number.isNaN(n)) return '—'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / (1024 * 1024)).toFixed(1)} MB`
}

const emptySettings: LogCollectorSettings = {
  enabled: true,
  poll_interval_seconds: 5,
  retention_days: 90,
  archive_enabled: true,
  archive_interval_hours: 1,
  archive_retention_days: 14,
}

export default function LogsPage() {
  const [since, setSince] = useState(() => hoursAgo(24))
  const [until, setUntil] = useState('')
  const [archives, setArchives] = useState<LogArchive[]>([])
  const [serverPath, setServerPath] = useState('/var/log/mailpanel/archives')
  const [exporting, setExporting] = useState(false)
  const [live, setLive] = useState('')
  const [liveSource, setLiveSource] = useState('')
  const [liveType, setLiveType] = useState<string | null>(null)
  const [liveAuto, setLiveAuto] = useState(false)
  const [audit, setAudit] = useState<any[]>([])
  const [settings, setSettings] = useState<LogCollectorSettings>(emptySettings)
  const [settingsSaving, setSettingsSaving] = useState(false)
  const logBoxRef = useRef<HTMLPreElement>(null)

  async function loadArchives() {
    const res = await api.logsArchives()
    setArchives(res.items)
    if (res.server?.path) setServerPath(res.server.path)
  }

  async function loadSettings() {
    const res = await api.logsSettings()
    setSettings(res)
    if (res.archives_path) setServerPath(res.archives_path)
  }

  useEffect(() => {
    api.audit().then(setAudit).catch((e) => notify.error(errorMessage(e)))
    loadArchives().catch((e) => notify.error(errorMessage(e)))
    loadSettings().catch((e) => notify.error(errorMessage(e)))
  }, [])

  async function saveSettings() {
    setSettingsSaving(true)
    try {
      const res = await api.updateLogsSettings({
        enabled: settings.enabled,
        poll_interval_seconds: Number(settings.poll_interval_seconds),
        retention_days: Number(settings.retention_days),
        archive_enabled: settings.archive_enabled,
        archive_interval_hours: Number(settings.archive_interval_hours),
        archive_retention_days: Number(settings.archive_retention_days),
      })
      setSettings((prev) => ({ ...prev, ...res }))
      notify.success(res.note || 'Настройки автологирования сохранены')
    } catch (e) {
      notify.error(errorMessage(e))
    } finally {
      setSettingsSaving(false)
    }
  }

  useEffect(() => {
    if (!liveAuto || !liveType) return undefined
    const timer = window.setInterval(() => {
      loadLive(liveType, true).catch((e) => notify.error(errorMessage(e)))
    }, 3000)
    return () => window.clearInterval(timer)
  }, [liveAuto, liveType])

  async function loadLive(type: string, scrollToEnd = true) {
    const res = await api.logsLive(type)
    setLive(res.lines.join('\n'))
    setLiveSource(res.source_label)
    setLiveType(type)
    if (scrollToEnd && logBoxRef.current) {
      logBoxRef.current.scrollTop = logBoxRef.current.scrollHeight
    }
  }

  function applyPreset(hours: number) {
    setSince(hoursAgo(hours))
    setUntil('')
  }

  async function exportAndDownload() {
    setExporting(true)
    try {
      const body: { since?: string; until?: string; label?: string } = {
        since: since || undefined,
        until: until || undefined,
        label: 'manual',
      }
      const meta = await api.createLogsArchive(body)
      notify.success(`Архив сохранён на сервере: ${meta.path || meta.id}`)
      await api.downloadLogsArchive(meta.id)
      await loadArchives()
    } catch (e) {
      notify.error(errorMessage(e))
    } finally {
      setExporting(false)
    }
  }

  async function downloadExisting(id: string) {
    try {
      await api.downloadLogsArchive(id)
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  return (
    <div>
      <div className="topbar"><h2>Логи</h2></div>

      <div className="card">
        <h3>Автологирование</h3>
        <p className="muted">
          Сборщик читает maillog / dovecot / iredapd в БД панели и делает ZIP-снимки в{' '}
          <code>{serverPath}</code>. Изменения пишутся в <code>config.yaml</code> и применяются
          без перезапуска службы.
        </p>
        <div className="form-row" style={{ flexWrap: 'wrap', gap: 12 }}>
          <label className="muted" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <input
              type="checkbox"
              checked={settings.enabled}
              onChange={(e) => setSettings((s) => ({ ...s, enabled: e.target.checked }))}
            />
            Сбор в БД включён
          </label>
          <label className="muted" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            Интервал опроса (сек)
            <input
              type="number"
              min={1}
              max={3600}
              style={{ width: 88 }}
              value={settings.poll_interval_seconds}
              onChange={(e) => setSettings((s) => ({ ...s, poll_interval_seconds: Number(e.target.value) }))}
            />
          </label>
          <label className="muted" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            Хранить записи БД (дней)
            <input
              type="number"
              min={1}
              max={3650}
              style={{ width: 88 }}
              value={settings.retention_days}
              onChange={(e) => setSettings((s) => ({ ...s, retention_days: Number(e.target.value) }))}
            />
          </label>
        </div>
        <div className="form-row" style={{ flexWrap: 'wrap', gap: 12, marginTop: 8 }}>
          <label className="muted" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <input
              type="checkbox"
              checked={settings.archive_enabled}
              onChange={(e) => setSettings((s) => ({ ...s, archive_enabled: e.target.checked }))}
            />
            Автоснимки ZIP
          </label>
          <label className="muted" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            Интервал снимков (часов)
            <input
              type="number"
              min={0.25}
              max={168}
              step={0.25}
              style={{ width: 88 }}
              value={settings.archive_interval_hours}
              onChange={(e) => setSettings((s) => ({ ...s, archive_interval_hours: Number(e.target.value) }))}
            />
          </label>
          <label className="muted" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            Хранить ZIP (дней)
            <input
              type="number"
              min={1}
              max={3650}
              style={{ width: 88 }}
              value={settings.archive_retention_days}
              onChange={(e) => setSettings((s) => ({ ...s, archive_retention_days: Number(e.target.value) }))}
            />
          </label>
          <button type="button" onClick={saveSettings} disabled={settingsSaving}>
            {settingsSaving ? 'Сохранение…' : 'Сохранить'}
          </button>
        </div>
      </div>

      <div className="card">
        <h3>Выгрузка логов</h3>
        <p className="muted">
          Собирает логи Postfix/Amavis, Dovecot, iRedAPD и системы за период.
          Архив сохраняется на сервере в <code>{serverPath}</code> и скачивается как ZIP.
          Для разбора «письмо не дошло» откройте <code>mail.log</code> и найдите адрес получателя.
        </p>
        <div className="form-row" style={{ marginBottom: 8 }}>
          <button type="button" className="secondary" onClick={() => applyPreset(1)}>1 час</button>
          <button type="button" className="secondary" onClick={() => applyPreset(6)}>6 часов</button>
          <button type="button" className="secondary" onClick={() => applyPreset(24)}>24 часа</button>
        </div>
        <div className="form-row">
          <label className="muted" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            С
            <input type="datetime-local" value={since} onChange={(e) => setSince(e.target.value)} />
          </label>
          <label className="muted" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            По
            <input type="datetime-local" value={until} onChange={(e) => setUntil(e.target.value)} />
          </label>
          <button type="button" onClick={exportAndDownload} disabled={exporting}>
            {exporting ? 'Сбор…' : 'Сформировать и скачать'}
          </button>
        </div>
        <p className="muted" style={{ marginTop: 8 }}>
          Пустое «По» = текущее время. Максимум 7 суток. Автоснимки раз в час тоже пишутся в эту папку.
        </p>

        <h4 style={{ marginTop: 20 }}>Архивы на сервере</h4>
        <table className="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Период</th>
              <th>Создан</th>
              <th>Размер</th>
              <th>Путь</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {archives.length === 0 && (
              <tr><td colSpan={6} className="muted">Архивов пока нет</td></tr>
            )}
            {archives.map((a) => (
              <tr key={a.id}>
                <td>{a.id}{a.label === 'auto' ? ' (auto)' : ''}</td>
                <td className="muted">
                  {(a.since || '—').replace('T', ' ').slice(0, 16)}
                  {' → '}
                  {(a.until || '—').replace('T', ' ').slice(0, 16)}
                </td>
                <td>{(a.created_at || '—').replace('T', ' ').slice(0, 19)}</td>
                <td>{formatBytes(a.zip_bytes)}</td>
                <td title={a.path}><code style={{ fontSize: '0.8rem' }}>{a.path || '—'}</code></td>
                <td className="actions">
                  <button className="secondary" onClick={() => downloadExisting(a.id)}>Скачать</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div style={{ marginTop: 8 }}>
          <button type="button" className="secondary" onClick={() => loadArchives().catch((e) => notify.error(errorMessage(e)))}>
            Обновить список
          </button>
        </div>
      </div>

      <div className="card">
        <h3>Живой лог</h3>
        <p className="muted">
          Поток последних записей в реальном времени.
          {liveSource && <> Источник: <strong>{liveSource}</strong>.</>}
        </p>
        <div className="form-row">
          {LIVE_TYPES.map((t) => (
            <button
              key={t.id}
              className={liveType === t.id ? '' : 'secondary'}
              onClick={() => loadLive(t.id).catch((e) => notify.error(errorMessage(e)))}
            >
              {t.label}
            </button>
          ))}
          <button
            className={liveAuto ? '' : 'secondary'}
            onClick={() => setLiveAuto((value) => !value)}
            disabled={!liveType}
          >
            {liveAuto ? 'Пауза' : 'Автообновление (3 с)'}
          </button>
        </div>
        <pre ref={logBoxRef} className="log-box" style={{ maxHeight: 420 }}>{live || 'Выберите тип лога'}</pre>
      </div>

      <div className="card">
        <h3>Аудит действий в панели</h3>
        <table>
          <thead><tr><th>Время</th><th>Пользователь</th><th>Действие</th><th>Ресурс</th><th>Детали</th></tr></thead>
          <tbody>
            {audit.map((a) => (
              <tr key={a.id}><td>{a.created_at}</td><td>{a.username}</td><td>{a.action}</td><td>{a.resource}</td><td>{a.details}</td></tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
