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
  { value: 'add_recipient', label: 'Добавить получателя' },
] as const

type FieldValue = (typeof FIELD_OPTIONS)[number]['value']
type ActionValue = (typeof ACTION_OPTIONS)[number]['value']

function needsAddress(action: ActionValue): boolean {
  return action === 'forward' || action === 'add_recipient'
}

export default function RulesPage() {
  const [data, setData] = useState<ContentFiltersData | null>(null)
  const [field, setField] = useState<FieldValue>('subject')
  const [action, setAction] = useState<ActionValue>('quarantine')
  const [forwardTo, setForwardTo] = useState('')
  const [pattern, setPattern] = useState('')
  const [busyRuleId, setBusyRuleId] = useState<string | null>(null)
  const [busyAction, setBusyAction] = useState<'toggle' | 'delete' | 'create' | 'reapply' | null>(null)
  const role = getUser()?.role
  const canWrite = role === 'superadmin' || role === 'admin'

  async function load() {
    setData(await api.contentFilters())
  }

  useEffect(() => {
    load().catch((e) => notify.error(errorMessage(e)))
  }, [])

  function patchRule(ruleId: string, patch: Partial<ContentFilter>) {
    setData((prev) => {
      if (!prev) return prev
      return {
        ...prev,
        items: prev.items.map((item) => (item.id === ruleId ? { ...item, ...patch } : item)),
      }
    })
  }

  async function create() {
    const text = pattern.trim()
    if (!text) {
      notify.error('Укажите текст для поиска')
      return
    }
    if (needsAddress(action) && !forwardTo.trim()) {
      notify.error('Укажите адрес получателя')
      return
    }
    setBusyAction('create')
    try {
      notify.info('Применяется на сервере (Amavis)…')
      await api.createContentFilter({
        field,
        pattern: text,
        action,
        forward_to: needsAddress(action) ? forwardTo.trim() : null,
        enabled: true,
      })
      setPattern('')
      if (needsAddress(action)) setForwardTo('')
      notify.success('Правило добавлено')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    } finally {
      setBusyAction(null)
    }
  }

  async function toggleRule(rule: ContentFilter) {
    if (busyRuleId || busyAction) return
    const nextEnabled = !rule.enabled
    setBusyRuleId(rule.id)
    setBusyAction('toggle')
    patchRule(rule.id, { enabled: nextEnabled })
    notify.info(nextEnabled ? 'Включаем правило…' : 'Отключаем правило…')
    try {
      await api.updateContentFilter(rule.id, { enabled: nextEnabled })
      notify.success(nextEnabled ? 'Правило включено' : 'Правило отключено')
      await load()
    } catch (e) {
      patchRule(rule.id, { enabled: rule.enabled })
      notify.error(errorMessage(e))
    } finally {
      setBusyRuleId(null)
      setBusyAction(null)
    }
  }

  async function removeRule(rule: ContentFilter) {
    if (busyRuleId || busyAction) return
    if (!confirm(`Удалить правило «${rule.pattern}»?`)) return
    setBusyRuleId(rule.id)
    setBusyAction('delete')
    notify.info('Удаляем правило…')
    try {
      await api.deleteContentFilter(rule.id)
      notify.success('Правило удалено')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    } finally {
      setBusyRuleId(null)
      setBusyAction(null)
    }
  }

  async function reapply() {
    if (busyAction) return
    setBusyAction('reapply')
    notify.info('Применяется на сервере (Amavis)…')
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
    } finally {
      setBusyAction(null)
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
          выполняется выбранное действие: карантин, удаление, пересылка на другой адрес
          или добавление получателя (письмо останется у исходного адресата и уйдёт ещё
          на указанный ящик — например, копия директору).
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
              <button
                className="secondary"
                style={{ marginTop: 10 }}
                onClick={reapply}
                disabled={busyAction !== null}
              >
                {busyAction === 'reapply' ? 'Применяется…' : 'Применить правила заново'}
              </button>
            )}
          </div>
        )}
        {canWrite && (
          <div style={{ marginBottom: 16 }}>
            <div className="form-row" style={{ marginBottom: needsAddress(action) ? 10 : 0 }}>
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
              <button onClick={create} disabled={busyAction !== null}>
                {busyAction === 'create' ? 'Добавление…' : 'Добавить правило'}
              </button>
            </div>
            {needsAddress(action) && (
              <div className="form-row">
                <input
                  style={{ minWidth: 280 }}
                  placeholder={
                    action === 'add_recipient'
                      ? 'Доп. адрес, например director@example.ru'
                      : 'Адрес пересылки, например director@example.ru'
                  }
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
                    <button
                      className="secondary"
                      disabled={busyAction !== null}
                      onClick={() => toggleRule(rule)}
                    >
                      {busyRuleId === rule.id && busyAction === 'toggle'
                        ? (rule.enabled ? 'Включаем…' : 'Отключаем…')
                        : (rule.enabled ? 'Отключить' : 'Включить')}
                    </button>
                    <button
                      className="danger"
                      disabled={busyAction !== null}
                      onClick={() => removeRule(rule)}
                    >
                      {busyRuleId === rule.id && busyAction === 'delete' ? 'Удаление…' : 'Удалить'}
                    </button>
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
