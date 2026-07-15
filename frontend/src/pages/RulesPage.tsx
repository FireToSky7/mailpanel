import { useEffect, useState } from 'react'
import { api, getUser, type ContentFilter, type ContentFiltersData } from '../api'
import { errorMessage } from '../errors'
import { notify } from '../notify'

const FIELD_OPTIONS = [
  { value: 'subject', label: 'Тема письма' },
  { value: 'from', label: 'Отправитель' },
  { value: 'body', label: 'Текст письма' },
] as const

const ACTION_OPTIONS = [
  { value: 'quarantine', label: 'Карантин' },
  { value: 'delete', label: 'Удалить' },
  { value: 'forward', label: 'Переслать' },
] as const

type FieldValue = (typeof FIELD_OPTIONS)[number]['value']
type ActionValue = (typeof ACTION_OPTIONS)[number]['value']

export default function RulesPage() {
  const [data, setData] = useState<ContentFiltersData | null>(null)
  const [field, setField] = useState<FieldValue>('subject')
  const [action, setAction] = useState<ActionValue>('quarantine')
  const [forwardTo, setForwardTo] = useState('')
  const [pattern, setPattern] = useState('')
  const role = getUser()?.role
  const canWrite = role === 'superadmin' || role === 'admin'

  async function load() {
    setData(await api.contentFilters())
  }

  useEffect(() => {
    load().catch((e) => notify.error(errorMessage(e)))
  }, [])

  async function create() {
    const text = pattern.trim()
    if (!text) {
      notify.error('Укажите текст для поиска')
      return
    }
    if (action === 'forward' && !forwardTo.trim()) {
      notify.error('Укажите адрес для пересылки')
      return
    }
    try {
      await api.createContentFilter({
        field,
        pattern: text,
        action,
        forward_to: action === 'forward' ? forwardTo.trim() : null,
        enabled: true,
      })
      setPattern('')
      if (action === 'forward') setForwardTo('')
      notify.success('Правило добавлено')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function toggleRule(rule: ContentFilter) {
    try {
      await api.updateContentFilter(rule.id, { enabled: !rule.enabled })
      notify.success(rule.enabled ? 'Правило отключено' : 'Правило включено')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function removeRule(rule: ContentFilter) {
    if (!confirm(`Удалить правило «${rule.pattern}»?`)) return
    try {
      await api.deleteContentFilter(rule.id)
      notify.success('Правило удалено')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function reapply() {
    try {
      const res = await api.reapplyContentFilters()
      if (res.warnings?.length) {
        notify.success(`Правила применены. ${res.warnings.join(' ')}`)
      } else {
        notify.success('Правила применены')
      }
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  const items = data?.items ?? []
  const diagnostics = data?.diagnostics

  return (
    <div>
      <div className="topbar"><h2>Правила</h2></div>

      <div className="card">
        <h3>Входящие фильтры</h3>
        <p className="muted">
          Если во входящем письме в теме, отправителе или тексте встречается указанная строка,
          выполняется выбранное действие: карантин, удаление или пересылка на другой адрес
          (например, все письма с темой «Директору» — на ящик директора).
          Поиск без учёта регистра, по вхождению подстроки.
          Для писем между ящиками на этом сервере нужна проверка внутренней почты в Amavis.
        </p>
        {diagnostics && (
          <div className="muted" style={{ marginBottom: 16 }}>
            <div>Правил активно: {diagnostics.active_rules}</div>
            <div>
              Проверка внутренней почты:{' '}
              {diagnostics.scan_internal_mail ? (
                <span className="badge">включена</span>
              ) : (
                <span className="badge down">выключена</span>
              )}
            </div>
            <div>
              Хук Amavis: {diagnostics.amavis_hook_loaded ? (
                <span className="badge">подключён</span>
              ) : (
                <span className="badge down">не подключён</span>
              )}
            </div>
            <div>
              Правила в local.cf: {diagnostics.rules_in_local_cf ? 'да' : 'нет'}
              {diagnostics.local_cf_exists ? ` (${diagnostics.local_cf})` : ''}
            </div>
            {canWrite && (
              <button className="secondary" style={{ marginTop: 10 }} onClick={reapply}>
                Применить правила заново
              </button>
            )}
          </div>
        )}
        {canWrite && (
          <div style={{ marginBottom: 16 }}>
            <div className="form-row" style={{ marginBottom: action === 'forward' ? 10 : 0 }}>
              <select value={field} onChange={(e) => setField(e.target.value as FieldValue)}>
                {FIELD_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>{option.label}</option>
                ))}
              </select>
              <input
                placeholder="Например: spam или Директору"
                value={pattern}
                onChange={(e) => setPattern(e.target.value)}
              />
              <select value={action} onChange={(e) => setAction(e.target.value as ActionValue)}>
                {ACTION_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>{option.label}</option>
                ))}
              </select>
              <button onClick={create}>Добавить правило</button>
            </div>
            {action === 'forward' && (
              <div className="form-row">
                <input
                  style={{ minWidth: 280 }}
                  placeholder="Адрес пересылки, например director@example.ru"
                  value={forwardTo}
                  onChange={(e) => setForwardTo(e.target.value)}
                />
              </div>
            )}
          </div>
        )}
        <table>
          <thead>
            <tr>
              <th>Где искать</th>
              <th>Содержит</th>
              <th>Действие</th>
              <th>Статус</th>
              {canWrite && <th></th>}
            </tr>
          </thead>
          <tbody>
            {items.length === 0 && (
              <tr><td colSpan={canWrite ? 5 : 4} className="muted">Правил нет</td></tr>
            )}
            {items.map((rule) => (
              <tr key={rule.id}>
                <td>{rule.field_label}</td>
                <td>{rule.pattern}</td>
                <td>{rule.action_label}</td>
                <td>
                  {rule.enabled ? (
                    <span className="badge">включено</span>
                  ) : (
                    <span className="badge down">выключено</span>
                  )}
                </td>
                {canWrite && (
                  <td className="actions">
                    <button className="secondary" onClick={() => toggleRule(rule)}>
                      {rule.enabled ? 'Отключить' : 'Включить'}
                    </button>
                    <button className="danger" onClick={() => removeRule(rule)}>Удалить</button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
        {data?.notes.map((note) => (
          <p key={note} className="muted" style={{ marginTop: 12, marginBottom: 0 }}>{note}</p>
        ))}
      </div>
    </div>
  )
}
