import { useState } from 'react'

type EntryListProps = {
  items: string[]
  comments?: Record<string, string>
  onRemove?: (item: string) => void
  onEditComment?: (item: string, comment: string) => Promise<void> | void
  canRemove?: boolean
  canEditComment?: boolean
  emptyText?: string
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
    <ul className="entry-list">
      {items.map((item) => {
        const comment = comments?.[item] || comments?.[item.toLowerCase()] || ''
        const isEditing = editing === item
        return (
          <li key={item}>
            <div className="entry-main">
              <span className="entry-tip entry-label" data-tip={item}>{item}</span>
              {isEditing ? (
                <div className="entry-comment-edit">
                  <input
                    value={draft}
                    onChange={(e) => setDraft(e.target.value)}
                    placeholder="Комментарий (причина)"
                    maxLength={200}
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
                <span className="entry-tip entry-comment" data-tip={comment}>{comment}</span>
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
  )
}
