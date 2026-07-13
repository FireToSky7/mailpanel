import { useEffect, useState } from 'react'
import { api, getUser, type MailPolicyData } from '../api'
import EntryList from '../components/EntryList'
import { errorMessage } from '../errors'
import { notify } from '../notify'

export default function AntispamPage() {
  const [whitelist, setWhitelist] = useState<string[]>([])
  const [blacklist, setBlacklist] = useState<string[]>([])
  const [whitelistEntry, setWhitelistEntry] = useState('')
  const [blacklistEntry, setBlacklistEntry] = useState('')
  const [score, setScore] = useState('5.0')
  const [bannedExtensions, setBannedExtensions] = useState<string[]>([])
  const [bannedNeedsResync, setBannedNeedsResync] = useState(false)
  const [bannedEntry, setBannedEntry] = useState('')
  const [mailPolicy, setMailPolicy] = useState<MailPolicyData | null>(null)
  const [scanInternal, setScanInternal] = useState(false)
  const role = getUser()?.role
  const canWrite = role === 'superadmin' || role === 'admin'

  async function load() {
    const errors: string[] = []

    try {
      const wl = await api.wblist('whitelist')
      setWhitelist(wl.entries)
    } catch (e) {
      errors.push(`Белый список: ${errorMessage(e)}`)
      setWhitelist([])
    }

    try {
      const bl = await api.wblist('blacklist')
      setBlacklist(bl.entries)
    } catch (e) {
      errors.push(`Чёрный список: ${errorMessage(e)}`)
      setBlacklist([])
    }

    try {
      const spam = await api.spam()
      setScore(spam.required_score)
    } catch (e) {
      errors.push(`SpamAssassin: ${errorMessage(e)}`)
    }

    try {
      const banned = await api.bannedExtensions()
      setBannedExtensions(banned.extensions)
      setBannedNeedsResync(Boolean(banned.needs_resync))
    } catch (e) {
      errors.push(`Запрещённые файлы: ${errorMessage(e)}`)
      setBannedExtensions([])
    }

    try {
      const policy = await api.mailPolicy()
      setMailPolicy(policy)
      setScanInternal(policy.scan_internal_mail)
    } catch (e) {
      errors.push(`Политика почты: ${errorMessage(e)}`)
      setMailPolicy(null)
    }

    if (errors.length) notify.error(errors.join('\n'))
  }

  useEffect(() => { load() }, [])

  async function addToList(type: 'whitelist' | 'blacklist', entry: string, clear: () => void) {
    const value = entry.trim()
    if (!value) {
      notify.error('Укажите запись для добавления')
      return
    }
    try {
      await api.addWblist(type, [value])
      clear()
      notify.success('Запись добавлена')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function removeFromList(type: 'whitelist' | 'blacklist', entry: string) {
    try {
      await api.deleteWblist(type, [entry])
      notify.success('Запись удалена')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function saveScore() {
    const value = parseFloat(score)
    if (!Number.isFinite(value) || value < 0 || value > 20) {
      notify.error('Порог спама: число от 0 до 20')
      return
    }
    try {
      await api.updateSpam({ required_score: value })
      notify.success('Порог SpamAssassin сохранён')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  function normalizeExtension(value: string): string {
    const trimmed = value.trim().toLowerCase().replace(/^\./, '')
    if (!/^[a-z0-9]{1,16}$/.test(trimmed)) {
      throw new Error('Расширение: только латиница и цифры, до 16 символов')
    }
    return `.${trimmed}`
  }

  async function addBannedExtensionAction() {
    try {
      const ext = normalizeExtension(bannedEntry)
      if (bannedExtensions.includes(ext)) {
        notify.error('Такое расширение уже в списке')
        return
      }
      const next = [...bannedExtensions, ext].sort()
      await api.updateBannedExtensions(next)
      setBannedEntry('')
      notify.success('Список запрещённых расширений сохранён')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function removeBannedExtension(ext: string) {
    if (bannedExtensions.length <= 1) {
      notify.error('Должно остаться хотя бы одно расширение')
      return
    }
    try {
      const next = bannedExtensions.filter((item) => item !== ext)
      await api.updateBannedExtensions(next)
      notify.success('Список запрещённых расширений сохранён')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function reapplyBannedExtensions() {
    try {
      await api.reapplyBannedExtensions()
      notify.success('Список применён к Amavis — действуют только расширения из панели')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function saveMailPolicy() {
    try {
      await api.updateMailPolicy(scanInternal)
      notify.success(scanInternal ? 'Проверка внутренней почты включена' : 'Проверка внутренней почты отключена')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  return (
    <div>
      <div className="topbar"><h2>Антиспам</h2></div>
      {canWrite && (
        <div className="card">
          <h3>Порог SpamAssassin</h3>
          <div className="form-row">
            <input value={score} onChange={(e) => setScore(e.target.value)} />
            <button onClick={saveScore}>Сохранить</button>
          </div>
          <p className="muted">Чем выше значение, тем меньше писем попадёт в спам. Обычно 5.0–7.0.</p>
        </div>
      )}
      {canWrite && (
        <div className="card">
          <h3>Запрещённые типы файлов (вложения)</h3>
          <p className="muted">
            Блокируются <strong>только</strong> расширения из этого списка. Встроенные правила iRedMail
            в Amavis заменяются при сохранении.
          </p>
          {bannedNeedsResync && (
            <p className="muted" style={{ color: '#f0a060' }}>
              В Amavis остались старые правила. Нажмите «Применить к Amavis».
            </p>
          )}
          <div className="form-row">
            <input
              placeholder="exe, bat, ps1…"
              value={bannedEntry}
              onChange={(e) => setBannedEntry(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && addBannedExtensionAction()}
            />
            <button onClick={addBannedExtensionAction}>Добавить</button>
            <button className="secondary" onClick={reapplyBannedExtensions}>Применить к Amavis</button>
          </div>
          <EntryList
            items={bannedExtensions}
            canRemove
            onRemove={removeBannedExtension}
            emptyText="Список пуст"
          />
        </div>
      )}
      {canWrite && mailPolicy && (
        <div className="card">
          <h3>Проверка внутренней почты</h3>
          <p className="muted">
            По умолчанию письма с localhost и часть внутреннего трафика могут обходить антиспам и проверку вложений.
            При включении MailPanel настраивает Amavis на проверку исходящей и локальной почты (политика ORIGINATING).
          </p>
          <label className="form-row" style={{ alignItems: 'center', gap: 10 }}>
            <input
              type="checkbox"
              checked={scanInternal}
              onChange={(e) => setScanInternal(e.target.checked)}
            />
            Проверять внутреннюю почту (спам, запрещённые вложения)
          </label>
          <div className="form-row" style={{ marginTop: 10 }}>
            <button onClick={saveMailPolicy}>Сохранить политику</button>
          </div>
          {mailPolicy.notes.map((note) => (
            <p key={note} className="muted" style={{ marginBottom: 4 }}>{note}</p>
          ))}
        </div>
      )}
      <div className="card">
        <h3>Белый список</h3>
        <p className="muted">Глобальный список для всего сервера: email, домен (@domain.ru) или IP.</p>
        <div className="form-row">
          <input placeholder="email / @domain.ru / IP" value={whitelistEntry} onChange={(e) => setWhitelistEntry(e.target.value)} />
          {canWrite && <button onClick={() => addToList('whitelist', whitelistEntry, () => setWhitelistEntry(''))}>Добавить</button>}
        </div>
        <EntryList
          items={whitelist}
          canRemove={canWrite}
          onRemove={(entry) => removeFromList('whitelist', entry)}
          emptyText="Список пуст"
        />
      </div>
      {canWrite && (
        <div className="card">
          <h3>Чёрный список</h3>
          <p className="muted">
            Блокирует <strong>входящие</strong> письма от указанных отправителей (email, домен или IP).
            Не запрещает отправку с ящиков на сервере через Roundcube.
          </p>
          <div className="form-row">
            <input placeholder="email / @domain.ru / IP" value={blacklistEntry} onChange={(e) => setBlacklistEntry(e.target.value)} />
            <button onClick={() => addToList('blacklist', blacklistEntry, () => setBlacklistEntry(''))}>Добавить</button>
          </div>
          <EntryList
            items={blacklist}
            canRemove
            onRemove={(entry) => removeFromList('blacklist', entry)}
            emptyText="Список пуст"
          />
        </div>
      )}
    </div>
  )
}
