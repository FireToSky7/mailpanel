import { useEffect, useMemo, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { api, getUser, type Mailbox } from '../api'
import { errorMessage, validateEmail, validateMailboxPassword } from '../errors'
import { notify } from '../notify'

const COMMENT_MAX_LEN = 400
const TIP_DELAY_MS = 400

type SortKey = 'username' | 'name' | 'quota' | 'active' | 'last_login'
type SortDir = 'asc' | 'desc'

type TipState = { text: string; x: number; y: number; below: boolean } | null

function formatQuota(usedMb: number | undefined, quotaMb: number): string {
  const used = usedMb ?? 0
  if (!quotaMb) return `${used} / без лимита`
  return `${used} / ${quotaMb} MB`
}

function compareValues(a: string | number, b: string | number, dir: SortDir): number {
  const mul = dir === 'asc' ? 1 : -1
  if (typeof a === 'number' && typeof b === 'number') return (a - b) * mul
  return String(a).localeCompare(String(b), 'ru', { sensitivity: 'base', numeric: true }) * mul
}

function HoverTip({ tip }: { tip: TipState }) {
  if (!tip) return null
  return createPortal(
    <div
      className={`hover-tip${tip.below ? ' hover-tip-below' : ''}`}
      style={{ left: tip.x, top: tip.y }}
      role="tooltip"
    >
      {tip.text}
    </div>,
    document.body,
  )
}

export default function MailboxesPage() {
  const [items, setItems] = useState<Mailbox[]>([])
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [name, setName] = useState('')
  const [quota, setQuota] = useState('1024')
  const [sortKey, setSortKey] = useState<SortKey>('username')
  const [sortDir, setSortDir] = useState<SortDir>('asc')
  const [editingComment, setEditingComment] = useState<string | null>(null)
  const [commentDraft, setCommentDraft] = useState('')
  const [savingComment, setSavingComment] = useState(false)
  const [tip, setTip] = useState<TipState>(null)
  const tipTimer = useRef<number | null>(null)
  const role = getUser()?.role
  const canWrite = role === 'superadmin' || role === 'admin'

  async function load() {
    setItems(await api.mailboxes())
  }

  useEffect(() => {
    load().catch((e) => notify.error(errorMessage(e)))
    return () => {
      if (tipTimer.current != null) window.clearTimeout(tipTimer.current)
    }
  }, [])

  const sortedItems = useMemo(() => {
    const copy = [...items]
    copy.sort((left, right) => {
      if (sortKey === 'quota') {
        const aUsed = left.used_mb ?? 0
        const bUsed = right.used_mb ?? 0
        const byUsed = compareValues(aUsed, bUsed, sortDir)
        if (byUsed !== 0) return byUsed
        return compareValues(left.quota ?? 0, right.quota ?? 0, sortDir)
      }
      if (sortKey === 'active') {
        return compareValues(Number(left.active ? 1 : 0), Number(right.active ? 1 : 0), sortDir)
      }
      if (sortKey === 'last_login') {
        return compareValues(left.last_login_unix ?? 0, right.last_login_unix ?? 0, sortDir)
      }
      if (sortKey === 'name') {
        return compareValues(left.name || '', right.name || '', sortDir)
      }
      return compareValues(left.username, right.username, sortDir)
    })
    return copy
  }, [items, sortKey, sortDir])

  function toggleSort(key: SortKey) {
    if (sortKey === key) {
      setSortDir((prev) => (prev === 'asc' ? 'desc' : 'asc'))
      return
    }
    setSortKey(key)
    setSortDir(key === 'last_login' || key === 'quota' ? 'desc' : 'asc')
  }

  function sortMarker(key: SortKey) {
    if (sortKey !== key) return ''
    return sortDir === 'asc' ? ' ↑' : ' ↓'
  }

  function clearTipTimer() {
    if (tipTimer.current != null) {
      window.clearTimeout(tipTimer.current)
      tipTimer.current = null
    }
  }

  function hideTip() {
    clearTipTimer()
    setTip(null)
  }

  function showTipDelayed(text: string, target: HTMLElement) {
    if (!text.trim()) return
    clearTipTimer()
    tipTimer.current = window.setTimeout(() => {
      const rect = target.getBoundingClientRect()
      const margin = 12
      const maxWidth = Math.min(480, window.innerWidth - margin * 2)
      let x = rect.left
      if (x + maxWidth > window.innerWidth - margin) {
        x = Math.max(margin, window.innerWidth - margin - maxWidth)
      }
      if (x < margin) x = margin
      const below = rect.top < 80
      setTip({ text, x, y: below ? rect.bottom + 8 : rect.top - 8, below })
      tipTimer.current = null
    }, TIP_DELAY_MS)
  }

  async function create() {
    const email = username.trim().toLowerCase()
    const usernameError = validateEmail(username, 'Ящик')
    const passwordError = validateMailboxPassword(password)
    const quotaNum = Number(quota)
    if (!Number.isFinite(quotaNum) || quotaNum < 0) {
      notify.error('Квота: введите число 0 или больше (MB)')
      return
    }
    if (usernameError || passwordError) {
      notify.error([usernameError, passwordError].filter(Boolean).join('\n'))
      return
    }
    if (items.some((m) => m.username.toLowerCase() === email)) {
      notify.error(`Ящик уже существует: ${email}`)
      return
    }
    try {
      await api.createMailbox({ username: email, password, name: name.trim(), quota: quotaNum })
      setUsername('')
      setPassword('')
      setName('')
      setQuota('1024')
      notify.success('Ящик создан')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function remove(u: string) {
    if (!confirm(`Удалить ${u}?`)) return
    try {
      await api.deleteMailbox(u)
      notify.success('Ящик удалён')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function resetPassword(u: string) {
    const p = prompt('Новый пароль ящика (мин. 8 символов, A-z, a-z, цифра)')
    if (!p) return
    const passwordError = validateMailboxPassword(p)
    if (passwordError) {
      notify.error(passwordError)
      return
    }
    try {
      await api.mailboxPassword(u, p)
      notify.success('Пароль изменён')
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function changeQuota(u: string, current: number) {
    const raw = prompt(`Квота для ${u} (MB). 0 = без лимита`, String(current))
    if (raw === null) return
    const quotaNum = Number(raw)
    if (!Number.isFinite(quotaNum) || quotaNum < 0) {
      notify.error('Квота: введите число 0 или больше')
      return
    }
    try {
      await api.mailboxQuota(u, quotaNum)
      notify.success('Квота сохранена')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function toggleActive(u: string, active: number) {
    const enable = !active
    const action = enable ? 'активировать' : 'отключить'
    if (!confirm(`${action} ящик ${u}?`)) return
    try {
      await api.mailboxActive(u, enable)
      notify.success(enable ? 'Ящик включён' : 'Ящик отключён')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function saveComment(u: string) {
    setSavingComment(true)
    try {
      await api.mailboxName(u, commentDraft.trim())
      notify.success('Комментарий сохранён')
      setEditingComment(null)
      setCommentDraft('')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    } finally {
      setSavingComment(false)
    }
  }

  return (
    <div>
      <div className="topbar"><h2>Почтовые ящики</h2></div>
      {canWrite && (
        <div className="card">
          <h3>Создать ящик</h3>
          <div className="form-row">
            <input placeholder="user@domain.ru" value={username} onChange={(e) => setUsername(e.target.value)} />
            <input
              placeholder="Комментарий (ФИО)"
              value={name}
              onChange={(e) => setName(e.target.value)}
              maxLength={COMMENT_MAX_LEN}
            />
            <input type="password" placeholder="Пароль" value={password} onChange={(e) => setPassword(e.target.value)} />
            <input type="number" min={0} placeholder="Квота MB" value={quota} onChange={(e) => setQuota(e.target.value)} style={{ width: 110 }} />
            <button onClick={create}>Создать</button>
          </div>
          <p className="muted">
            Адрес ящика уникален. Комментарий необязателен (например ФИО). Пароль: мин. 8 символов, заглавная и строчная
            латинские буквы, цифра. Квота в мегабайтах (1024 = 1 ГБ). Пересылку настраивайте во вкладке «Алиасы».
          </p>
        </div>
      )}
      <div className="card table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th className="sortable" onClick={() => toggleSort('username')}>Ящик{sortMarker('username')}</th>
              <th className="sortable" onClick={() => toggleSort('name')}>Комментарий{sortMarker('name')}</th>
              <th className="sortable" onClick={() => toggleSort('quota')}>Занято / квота{sortMarker('quota')}</th>
              <th className="sortable" onClick={() => toggleSort('last_login')}>Последний вход{sortMarker('last_login')}</th>
              <th className="sortable" onClick={() => toggleSort('active')}>Активен{sortMarker('active')}</th>
              {canWrite && <th className="actions">Действия</th>}
            </tr>
          </thead>
          <tbody>
            {sortedItems.map((m) => (
              <tr key={m.username} className={m.active ? '' : 'inactive-row'}>
                <td>
                  <span
                    className="cell-ellipsis"
                    onMouseEnter={(e) => showTipDelayed(m.username, e.currentTarget)}
                    onMouseLeave={hideTip}
                  >
                    {m.username}
                  </span>
                </td>
                <td>
                  {editingComment === m.username ? (
                    <div className="inline-edit">
                      <input
                        value={commentDraft}
                        onChange={(e) => setCommentDraft(e.target.value)}
                        maxLength={COMMENT_MAX_LEN}
                        disabled={savingComment}
                        autoFocus
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') void saveComment(m.username)
                          if (e.key === 'Escape') {
                            setEditingComment(null)
                            setCommentDraft('')
                          }
                        }}
                      />
                      <button type="button" disabled={savingComment} onClick={() => void saveComment(m.username)}>
                        Сохранить
                      </button>
                      <button
                        type="button"
                        className="secondary"
                        disabled={savingComment}
                        onClick={() => {
                          setEditingComment(null)
                          setCommentDraft('')
                        }}
                      >
                        Отмена
                      </button>
                    </div>
                  ) : (
                    <div className="comment-cell">
                      <span
                        className={`cell-ellipsis${m.name ? '' : ' muted'}`}
                        onMouseEnter={(e) => showTipDelayed(m.name || 'Без комментария', e.currentTarget)}
                        onMouseLeave={hideTip}
                      >
                        {m.name || '—'}
                      </span>
                      {canWrite && (
                        <button
                          type="button"
                          className="secondary entry-edit"
                          title="Изменить комментарий"
                          aria-label={`Изменить комментарий для ${m.username}`}
                          onClick={() => {
                            hideTip()
                            setEditingComment(m.username)
                            setCommentDraft(m.name || '')
                          }}
                        >
                          ✎
                        </button>
                      )}
                    </div>
                  )}
                </td>
                <td>{formatQuota(m.used_mb, m.quota)}</td>
                <td>{m.last_login || '—'}</td>
                <td>
                  <span className={m.active ? 'status-yes' : 'status-no'}>
                    {m.active ? 'Да' : 'Нет'}
                  </span>
                </td>
                {canWrite && (
                  <td className="actions">
                    <button className="secondary" onClick={() => resetPassword(m.username)}>Пароль</button>
                    <button className="secondary" onClick={() => changeQuota(m.username, m.quota)}>Квота</button>
                    <button className="secondary" onClick={() => toggleActive(m.username, m.active)}>
                      {m.active ? 'Отключить' : 'Включить'}
                    </button>
                    <button className="danger" onClick={() => remove(m.username)}>Удалить</button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
        <p className="muted" style={{ marginTop: 10 }}>
          «Последний вход» берётся из таблицы Dovecot <code>last_login</code> (IMAP/POP3), если она настроена на сервере.
          Нажмите на заголовок столбца для сортировки.
        </p>
      </div>
      <HoverTip tip={tip} />
    </div>
  )
}
