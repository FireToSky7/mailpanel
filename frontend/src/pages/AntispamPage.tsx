import { useEffect, useState } from 'react'
import { api, getUser } from '../api'
import { errorMessage } from '../errors'

function formatQuota(usedMb: number | undefined, quotaMb: number): string {
  const used = usedMb ?? 0
  if (!quotaMb) return `${used} / без лимита MB`
  return `${used} / ${quotaMb} MB`
}

export default function AntispamPage() {
  const [whitelist, setWhitelist] = useState<string[]>([])
  const [blacklist, setBlacklist] = useState<string[]>([])
  const [whitelistEntry, setWhitelistEntry] = useState('')
  const [blacklistEntry, setBlacklistEntry] = useState('')
  const [account, setAccount] = useState('')
  const [score, setScore] = useState('5.0')
  const [grey, setGrey] = useState<any>(null)
  const [error, setError] = useState('')
  const [info, setInfo] = useState('')
  const role = getUser()?.role
  const canWrite = role === 'superadmin' || role === 'admin'
  const isUser = role === 'user'

  async function load() {
    setError('')
    const errors: string[] = []

    try {
      const wl = await api.wblist('whitelist', isUser ? undefined : account || undefined)
      setWhitelist(wl.entries)
    } catch (e) {
      errors.push(`Белый список: ${errorMessage(e)}`)
      setWhitelist([])
    }

    if (!isUser) {
      try {
        const bl = await api.wblist('blacklist', account || undefined)
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
        setGrey(await api.greylisting())
      } catch (e) {
        errors.push(`Greylisting: ${errorMessage(e)}`)
        setGrey(null)
      }
    }

    if (errors.length) setError(errors.join('\n'))
  }

  useEffect(() => { load() }, [])

  async function addToList(type: 'whitelist' | 'blacklist', entry: string, clear: () => void) {
    setError('')
    setInfo('')
    const value = entry.trim()
    if (!value) {
      setError('Укажите запись для добавления')
      return
    }
    try {
      await api.addWblist(type, [value], account || undefined)
      clear()
      setInfo('Запись добавлена')
      await load()
    } catch (e) {
      setError(errorMessage(e))
    }
  }

  async function removeFromList(type: 'whitelist' | 'blacklist', entry: string) {
    setError('')
    setInfo('')
    try {
      await api.deleteWblist(type, [entry], account || undefined)
      await load()
    } catch (e) {
      setError(errorMessage(e))
    }
  }

  async function saveScore() {
    setError('')
    setInfo('')
    const value = parseFloat(score)
    if (!Number.isFinite(value) || value < 0 || value > 20) {
      setError('Порог спама: число от 0 до 20')
      return
    }
    try {
      await api.updateSpam({ required_score: value })
      setInfo('Порог SpamAssassin сохранён')
      await load()
    } catch (e) {
      setError(errorMessage(e))
    }
  }

  return (
    <div>
      <div className="topbar"><h2>Антиспам</h2></div>
      {error && <div className="error prewrap card">{error}</div>}
      {info && <div className="info card">{info}</div>}
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
      <div className="card">
        <h3>Белый список {isUser ? '(личный)' : ''}</h3>
        {!isUser && (
          <div className="form-row" style={{ marginBottom: 10 }}>
            <input
              placeholder="Аккаунт (пусто = глобально)"
              value={account}
              onChange={(e) => setAccount(e.target.value)}
              style={{ flex: 1 }}
            />
            <button className="secondary" onClick={() => load()}>Применить</button>
          </div>
        )}
        <div className="form-row">
          <input placeholder="email / @domain.ru / IP" value={whitelistEntry} onChange={(e) => setWhitelistEntry(e.target.value)} />
          <button onClick={() => addToList('whitelist', whitelistEntry, () => setWhitelistEntry(''))}>Добавить</button>
        </div>
        <ul>{whitelist.map((e) => <li key={e}>{e} {(canWrite || isUser) && <button className="danger" onClick={() => removeFromList('whitelist', e)}>x</button>}</li>)}</ul>
      </div>
      {canWrite && (
        <div className="card">
          <h3>Чёрный список</h3>
          <div className="form-row">
            <input placeholder="email / @domain.ru / IP" value={blacklistEntry} onChange={(e) => setBlacklistEntry(e.target.value)} />
            <button onClick={() => addToList('blacklist', blacklistEntry, () => setBlacklistEntry(''))}>Добавить</button>
          </div>
          <ul>{blacklist.map((e) => <li key={e}>{e} <button className="danger" onClick={() => removeFromList('blacklist', e)}>x</button></li>)}</ul>
          {grey && <pre className="log-box">{grey.settings}</pre>}
        </div>
      )}
    </div>
  )
}
