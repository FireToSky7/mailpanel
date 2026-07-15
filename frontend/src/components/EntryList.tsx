type EntryListProps = {
  items: string[]
  comments?: Record<string, string>
  onRemove?: (item: string) => void
  canRemove?: boolean
  emptyText?: string
}

export default function EntryList({
  items,
  comments,
  onRemove,
  canRemove = false,
  emptyText = 'Список пуст',
}: EntryListProps) {
  if (!items.length) return <p className="muted">{emptyText}</p>
  return (
    <ul className="entry-list">
      {items.map((item) => {
        const comment = comments?.[item] || comments?.[item.toLowerCase()] || ''
        return (
          <li key={item}>
            <div className="entry-main">
              <span className="entry-label" title={item}>{item}</span>
              {comment ? (
                <span className="entry-comment" title={comment}>{comment}</span>
              ) : null}
            </div>
            {canRemove && onRemove && (
              <span className="entry-actions">
                <button
                  type="button"
                  className="danger entry-remove"
                  onClick={() => onRemove(item)}
                  aria-label={`Удалить ${item}`}
                >
                  ×
                </button>
              </span>
            )}
          </li>
        )
      })}
    </ul>
  )
}
