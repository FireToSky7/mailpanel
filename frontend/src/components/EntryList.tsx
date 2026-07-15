import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'

const COMMENT_MAX_LEN = 400
const TIP_DELAY_MS = 400

type TipState = {
  text: string
  x: number
  y: number
  below: boolean
} | null

type EntryListProps = {
  items: string[]
  comments?: Record<string, string>
  onRemove?: (item: string) => void
  onEditComment?: (item: string, comment: string) => Promise<void> | void
  canRemove?: boolean
  canEditComment?: boolean
  emptyText?: string
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

export default function EntryList({
  items,
  comments,
  onRemove,
  onEditComment,
  canRemove = false,
  canEditComment = false,
  emptyText = 'Список пуст',
}: EntryListProps) {
  const [editing, setEditing] = useState<string | null>(null)
  const [draft, setDraft] = useState('')
  const [saving, setSaving] = useState(false)
  const [tip, setTip] = useState<TipState>(null)
  const tipTimer = useRef<number | null>(null)

  useEffect(() => {
    return () => {
      if (tipTimer.current != null) window.clearTimeout(tipTimer.current)
    }
  }, [])

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
      const y = below ? rect.bottom + 8 : rect.top - 8
      setTip({ text, x, y, below })
      tipTimer.current = null
    }, TIP_DELAY_MS)
  }

  if (!items.length) return <p className="muted">{emptyText}</p>

  async function saveComment(item: string) {
    if (!onEditComment) return
    setSaving(true)
    try {
      await onEditComment(item, draft.trim())
      setEditing(null)
      setDraft('')
    } finally {
      setSaving(false)
    }
  }

  return (
    <>
      <ul className="entry-list">
        {items.map((item) => {
          const comment = comments?.[item] || comments?.[item.toLowerCase()] || ''
          const isEditing = editing === item
          return (
            <li key={item}>
              <div className="entry-main">
                <span
                  className="entry-label"
                  onMouseEnter={(e) => showTipDelayed(item, e.currentTarget)}
                  onMouseLeave={hideTip}
                >
                  {item}
                </span>
                {isEditing ? (
                  <div className="entry-comment-edit">
                    <input
                      value={draft}
                      onChange={(e) => setDraft(e.target.value)}
                      placeholder="Комментарий (причина)"
                      maxLength={COMMENT_MAX_LEN}
                      disabled={saving}
                      autoFocus
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') void saveComment(item)
                        if (e.key === 'Escape') {
                          setEditing(null)
                          setDraft('')
                        }
                      }}
                    />
                    <button type="button" disabled={saving} onClick={() => void saveComment(item)}>
                      Сохранить
                    </button>
                    <button
                      type="button"
                      className="secondary"
                      disabled={saving}
                      onClick={() => {
                        setEditing(null)
                        setDraft('')
                      }}
                    >
                      Отмена
                    </button>
                  </div>
                ) : comment ? (
                  <span
                    className="entry-comment"
                    onMouseEnter={(e) => showTipDelayed(comment, e.currentTarget)}
                    onMouseLeave={hideTip}
                  >
                    {comment}
                  </span>
                ) : canEditComment && onEditComment ? (
                  <span className="entry-comment entry-comment-empty">Без комментария</span>
                ) : null}
              </div>
              <span className="entry-actions">
                {canEditComment && onEditComment && !isEditing && (
                  <button
                    type="button"
                    className="secondary entry-edit"
                    onClick={() => {
                      hideTip()
                      setEditing(item)
                      setDraft(comment)
                    }}
                    aria-label={`Изменить комментарий для ${item}`}
                    title="Изменить комментарий"
                  >
                    ✎
                  </button>
                )}
                {canRemove && onRemove && (
                  <button
                    type="button"
                    className="danger entry-remove"
                    onClick={() => onRemove(item)}
                    aria-label={`Удалить ${item}`}
                  >
                    ×
                  </button>
                )}
              </span>
            </li>
          )
        })}
      </ul>
      <HoverTip tip={tip} />
    </>
  )
}
