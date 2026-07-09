import { useEffect, useState } from 'react'
import { dismissToast, subscribe, type ToastItem } from '../notify'

export default function ToastStack() {
  const [items, setItems] = useState<ToastItem[]>([])

  useEffect(() => subscribe(setItems), [])

  if (!items.length) return null

  return (
    <div className="toast-stack" aria-live="polite">
      {items.map((item) => (
        <div key={item.id} className={`toast toast-${item.type}`}>
          <div className="toast-message prewrap">{item.message}</div>
          <button type="button" className="toast-close" onClick={() => dismissToast(item.id)} aria-label="Закрыть">
            ×
          </button>
        </div>
      ))}
    </div>
  )
}
