import { useEffect, useState } from 'react'
import { api, getUser, type ContentFilter, type ContentFiltersData } from '../api'
import { errorMessage } from '../errors'
import { notify } from '../notify'

const FIELD_OPTIONS = [
  { value: 'subject', label: 'Тема письма' },
  { value: 'from', label: 'Отправитель' },
  { value: 'body', label: 'Текст письма' },
] as const

export default function RulesPage() {
  const [data, setData] = useState<ContentFiltersData | null>(null)
  const [field, setField] = useState<'subject' | 'body' | 'from'>('subject')
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
    try {
      await api.createContentFilter({ field, pattern: text, enabled: true })
      setPattern('')
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
          Если во входящем письме в теме, отправителе или тексте встречается указанная строка, письмо
          попадает в карантин (тип «Спам»). Поиск без учёта регистра, по вхождению подстроки
          (например, имя содержит «spam» или адрес «@spamer.ru»).
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
          <div className="form-row" style={{ marginBottom: 16 }}>
            <select value={field} onChange={(e) => setField(e.target.value as 'subject' | 'body' | 'from')}>
              {FIELD_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
            <input
              placeholder="Например: spam или @spamer.ru"
              value={pattern}
              onChange={(e) => setPattern(e.target.value)}
            />
            <button onClick={create}>Добавить правило</button>
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
