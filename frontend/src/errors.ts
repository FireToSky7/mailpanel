type ValidationError = {
  loc?: (string | number)[]
  msg?: string
  type?: string
}

const FIELD_LABELS: Record<string, string> = {
  username: 'Ящик',
  password: 'Пароль',
  address: 'Адрес алиаса',
  goto: 'Пересылка на',
  name: 'Имя',
}

const MSG_LABELS: Record<string, string> = {
  'String should have at least 6 characters': 'минимум 6 символов',
  'String should have at least 8 characters': 'минимум 8 символов',
  'Field required': 'обязательное поле',
  'value is not a valid email address': 'некорректный email',
}

function fieldLabel(loc: (string | number)[] | undefined): string {
  if (!loc?.length) return 'Поле'
  const name = String(loc[loc.length - 1])
  return FIELD_LABELS[name] || name
}

function translateMsg(msg: string): string {
  return MSG_LABELS[msg] || msg
}

export function formatApiError(detail: unknown): string {
  if (!detail) return 'Ошибка запроса'
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) {
    const lines = detail.map((item) => {
      if (typeof item === 'string') return item
      const err = item as ValidationError
      const label = fieldLabel(err.loc)
      const msg = translateMsg(err.msg || 'некорректное значение')
      if (msg.startsWith(label) || msg.startsWith('Пароль') || msg.startsWith('Алиас') || msg.startsWith('Ящик')) {
        return msg
      }
      return `${label}: ${msg}`
    })
    return lines.join('\n')
  }
  if (typeof detail === 'object' && detail !== null && 'msg' in detail) {
    return translateMsg(String((detail as ValidationError).msg))
  }
  return 'Ошибка запроса'
}

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/

export function validateEmail(value: string, fieldName: string): string | null {
  const trimmed = value.trim()
  if (!trimmed) return `${fieldName}: укажите адрес`
  if (!EMAIL_RE.test(trimmed)) return `${fieldName}: некорректный формат (пример user@domain.ru)`
  return null
}

export function validateMailboxPassword(value: string): string | null {
  if (value.length < 8) return 'Пароль: минимум 8 символов'
  if (!/[a-z]/.test(value)) return 'Пароль: нужна хотя бы одна строчная латинская буква (a-z)'
  if (!/[A-Z]/.test(value)) return 'Пароль: нужна хотя бы одна заглавная латинская буква (A-Z)'
  if (!/\d/.test(value)) return 'Пароль: нужна хотя бы одна цифра'
  return null
}

export function errorMessage(error: unknown): string {
  if (error instanceof Error) return error.message
  return formatApiError(error)
}
