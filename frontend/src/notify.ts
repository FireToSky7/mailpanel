export type ToastType = 'error' | 'info' | 'success'

export type ToastItem = {
  id: number
  message: string
  type: ToastType
}

type Listener = (items: ToastItem[]) => void

let nextId = 1
let items: ToastItem[] = []
const listeners = new Set<Listener>()

function emit() {
  listeners.forEach((listener) => listener([...items]))
}

function push(message: string, type: ToastType, timeoutMs = 6000) {
  const text = message.trim()
  if (!text) return
  const item: ToastItem = { id: nextId++, message: text, type }
  items = [...items, item]
  emit()
  window.setTimeout(() => {
    items = items.filter((toast) => toast.id !== item.id)
    emit()
  }, timeoutMs)
}

export function subscribe(listener: Listener) {
  listeners.add(listener)
  listener([...items])
  return () => listeners.delete(listener)
}

export function dismissToast(id: number) {
  items = items.filter((toast) => toast.id !== id)
  emit()
}

export const notify = {
  error: (message: string) => push(message, 'error', 8000),
  info: (message: string) => push(message, 'info', 5000),
  success: (message: string) => push(message, 'success', 4000),
}
