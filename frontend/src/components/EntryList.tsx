type EntryListProps = {
  items: string[]
  onRemove?: (item: string) => void
  canRemove?: boolean
  emptyText?: string
}

export default function EntryList({ items, onRemove, canRemove = false, emptyText = 'Список пуст' }: EntryListProps) {
  if (!items.length) return <p className="muted">{emptyText}</p>
  return (
    <ul className="entry-list">
      {items.map((item) => (
        <li key={item}>
          <span className="entry-label" title={item}>{item}</span>
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
      ))}
    </ul>
  )
}
