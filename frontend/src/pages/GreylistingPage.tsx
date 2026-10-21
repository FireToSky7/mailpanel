import { useEffect, useRef, useState } from 'react'
import { api, getUser, type GreylistingData, type GreylistingTiming } from '../api'
import EntryList from '../components/EntryList'
import { errorMessage } from '../errors'
import { notify } from '../notify'

function emptyTiming(): GreylistingTiming {
  return {
    training_mode: false,
    rejection_message: '',
    block_expire_minutes: 15,
    auth_triplet_expire_days: 30,
    unauth_triplet_expire_days: 2,
    bypass_spf: true,
    settings_file: '',
  }
}

function ipsToText(items: string[] | undefined): string {
  return (items ?? []).join('\n')
}

function downloadTextFile(filename: string, text: string) {
  const blob = new Blob([text.endsWith('\n') ? text : `${text}\n`], { type: 'text/plain;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

export default function GreylistingPage() {
  const [grey, setGrey] = useState<GreylistingData | null>(null)
  const [greyToAddr, setGreyToAddr] = useState('')
  const [greyFromAddr, setGreyFromAddr] = useState('')
  const [greyWhitelistDomain, setGreyWhitelistDomain] = useState('')
  const [spfText, setSpfText] = useState('')
  const [timingForm, setTimingForm] = useState<GreylistingTiming>(emptyTiming)
  const [greyBusy, setGreyBusy] = useState(false)
  const [loading, setLoading] = useState(true)
  const spfFileRef = useRef<HTMLInputElement>(null)
  const role = getUser()?.role
  const canWrite = role === 'superadmin' || role === 'admin'

  function syncTexts(data: GreylistingData) {
    setSpfText(ipsToText((data.whitelist_addresses ?? []).filter((x) => !x.startsWith('@'))))
  }

  async function load() {
    setLoading(true)
    try {
      const data = await api.greylisting()
      setGrey(data)
      if (data.timing) setTimingForm({ ...data.timing })
      syncTexts(data)
    } catch (e) {
      notify.error(errorMessage(e))
      setGrey(null)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  async function reloadGreylisting() {
    try {
      const data = await api.greylisting()
      setGrey(data)
      if (data.timing) setTimingForm({ ...data.timing })
      syncTexts(data)
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  function applyOverview(overview?: GreylistingData) {
    if (!overview) {
      reloadGreylisting()
      return
    }
    setGrey(overview)
    if (overview.timing) setTimingForm({ ...overview.timing })
    syncTexts(overview)
  }

  async function runGreyAction(action: () => Promise<unknown>, success: string) {
    setGreyBusy(true)
    try {
      await action()
      notify.success(success)
      await reloadGreylisting()
    } catch (e) {
      notify.error(errorMessage(e))
    } finally {
      setGreyBusy(false)
    }
  }

  function normalizeGreyAddr(value: string, fallback = '@.'): string {
    const text = value.trim()
    return text || fallback
  }

  function normalizeGreyDomain(value: string): string {
    const text = value.trim()
    if (!text) throw new Error('Укажите домен')
    return text.startsWith('@') ? text : `@${text}`
  }

  async function saveTiming() {
    setGreyBusy(true)
    try {
      const res = await api.greylistingUpdateTiming({
        training_mode: timingForm.training_mode,
        rejection_message: timingForm.rejection_message,
        block_expire_minutes: Number(timingForm.block_expire_minutes),
        auth_triplet_expire_days: Number(timingForm.auth_triplet_expire_days),
        unauth_triplet_expire_days: Number(timingForm.unauth_triplet_expire_days),
        bypass_spf: timingForm.bypass_spf,
      })
      setTimingForm({ ...res.timing })
      notify.success('Тайминги сохранены, iRedAPD перезапущен')
      await reloadGreylisting()
    } catch (e) {
      notify.error(errorMessage(e))
    } finally {
      setGreyBusy(false)
    }
  }

  async function disableGreylisting() {
    await runGreyAction(
      () => api.greylistingDisable(
        normalizeGreyAddr(greyToAddr),
        greyFromAddr.trim() ? normalizeGreyAddr(greyFromAddr) : undefined,
      ),
      'Greylisting отключён для указанной пары',
    )
  }

  async function enableGreylisting() {
    await runGreyAction(
      () => api.greylistingEnable(
        normalizeGreyAddr(greyToAddr),
        greyFromAddr.trim() ? normalizeGreyAddr(greyFromAddr) : undefined,
      ),
      'Greylisting включён для указанной пары',
    )
  }

  async function deleteGreyRule(to_addr: string, from_addr: string) {
    if (!confirm(`Удалить правило ${from_addr} → ${to_addr}?`)) return
    await runGreyAction(
      () => api.greylistingDeleteRule(to_addr, from_addr === '@.' ? undefined : from_addr),
      'Правило удалено',
    )
  }

  async function addGreyWhitelistDomain() {
    try {
      const domain = normalizeGreyDomain(greyWhitelistDomain)
      await runGreyAction(
        () => api.greylistingWhitelistDomain(domain),
        `Домен ${domain} добавлен в SPF-whitelist`,
      )
      setGreyWhitelistDomain('')
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function removeGreyWhitelistDomain(domain: string) {
    if (!confirm(`Удалить ${domain} из SPF-whitelist?`)) return
    await runGreyAction(
      () => api.greylistingRemoveWhitelistDomain(domain),
      'Домен удалён из SPF-whitelist',
    )
  }

  async function syncGreySpf() {
    await runGreyAction(
      () => api.greylistingSyncSpf(),
      'IP-адреса из SPF обновлены',
    )
  }

  async function saveSpfText() {
    if (!confirm('Заменить весь список IP из SPF/MX содержимым текстового поля?')) return
    setGreyBusy(true)
    try {
      const res = await api.greylistingSetWhitelistIps(spfText)
      applyOverview(res.overview)
      notify.success(`Список SPF/MX IP сохранён (${res.items.length})`)
    } catch (e) {
      notify.error(errorMessage(e))
    } finally {
      setGreyBusy(false)
    }
  }

  function onPickTxt(
    file: File | undefined,
    setter: (text: string) => void,
  ) {
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => {
      setter(String(reader.result || ''))
      notify.info(`Загружен файл ${file.name}`)
    }
    reader.onerror = () => notify.error('Не удалось прочитать файл')
    reader.readAsText(file)
  }

  async function whitelistFromLog(address: string) {
    if (!address) return
    if (address.includes('@') && !address.startsWith('@')) {
      const domain = `@${address.split('@')[1]}`
      setGreyWhitelistDomain(domain)
      await runGreyAction(
        () => api.greylistingWhitelistDomain(domain),
        `Домен ${domain} добавлен в SPF-whitelist`,
      )
      return
    }
    setGreyFromAddr(address.startsWith('@') ? address : `@${address}`)
    setGreyToAddr('@.')
    notify.info('Укажите получателя и нажмите «Отключить для пары»')
  }

  if (loading) return <div>Загрузка...</div>

  const spfCount = spfText.split(/\r?\n/).filter((l) => l.trim() && !l.trim().startsWith('#')).length

  return (
    <div>
      <div className="topbar">
        <h2>Greylisting</h2>
        <button className="secondary" onClick={() => reloadGreylisting()} disabled={greyBusy}>
          Обновить
        </button>
      </div>

      {!grey?.timing ? (
        <div className="card">
          <p className="muted">Не удалось загрузить данные greylisting. Проверьте iRedAPD на сервере.</p>
        </div>
      ) : (
        <div className="card">
          <p className="muted">
            Защита от спам-ботов: первая попытка доставки отклоняется, нормальные серверы повторяют через несколько минут.
            Белый/чёрный список из раздела «Антиспам» greylist не обходит — для обхода задержки используйте SPF-whitelist ниже.
          </p>
          <p>
            Статус:{' '}
            {grey.global_enabled ? (
              <span className="badge">включён глобально</span>
            ) : (
              <span className="badge down">отключён глобально</span>
            )}
            {timingForm.training_mode && (
              <span className="badge" style={{ marginLeft: 8 }}>режим обучения</span>
            )}
          </p>

          <h4>Тайминги iRedAPD</h4>
          <p className="muted">
            Пишутся в <code>{timingForm.settings_file || '/opt/iredapd/settings.py'}</code>, после сохранения перезапускается iRedAPD.
          </p>
          {canWrite ? (
            <>
              <div className="form-row">
                <label className="muted">
                  Задержка перед повтором (мин)
                  <input
                    type="number"
                    min={1}
                    max={1440}
                    value={timingForm.block_expire_minutes}
                    onChange={(e) => setTimingForm({ ...timingForm, block_expire_minutes: Number(e.target.value) })}
                  />
                </label>
                <label className="muted">
                  Память успешных (дн)
                  <input
                    type="number"
                    min={1}
                    max={365}
                    value={timingForm.auth_triplet_expire_days}
                    onChange={(e) => setTimingForm({ ...timingForm, auth_triplet_expire_days: Number(e.target.value) })}
                  />
                </label>
                <label className="muted">
                  Хранение неуспешных (дн)
                  <input
                    type="number"
                    min={1}
                    max={90}
                    value={timingForm.unauth_triplet_expire_days}
                    onChange={(e) => setTimingForm({ ...timingForm, unauth_triplet_expire_days: Number(e.target.value) })}
                  />
                </label>
              </div>
              <div className="form-row">
                <label className="muted" style={{ flex: 2 }}>
                  Сообщение отклонения
                  <input
                    value={timingForm.rejection_message}
                    onChange={(e) => setTimingForm({ ...timingForm, rejection_message: e.target.value })}
                  />
                </label>
              </div>
              <div className="form-row" style={{ alignItems: 'center' }}>
                <label className="check-label">
                  <input
                    type="checkbox"
                    checked={timingForm.bypass_spf}
                    onChange={(e) => setTimingForm({ ...timingForm, bypass_spf: e.target.checked })}
                  />
                  Обход по SPF
                </label>
                <label className="check-label">
                  <input
                    type="checkbox"
                    checked={timingForm.training_mode}
                    onChange={(e) => setTimingForm({ ...timingForm, training_mode: e.target.checked })}
                  />
                  Режим обучения (не отклонять, только учитывать)
                </label>
                <button disabled={greyBusy} onClick={saveTiming}>Сохранить тайминги</button>
              </div>
            </>
          ) : (
            <table className="data-table">
              <tbody>
                <tr><td>Задержка перед повтором</td><td>{grey.timing.block_expire_minutes} мин</td></tr>
                <tr><td>Запоминание успешных отправителей</td><td>{grey.timing.auth_triplet_expire_days} дн</td></tr>
                <tr><td>Хранение неуспешных попыток</td><td>{grey.timing.unauth_triplet_expire_days} дн</td></tr>
                <tr><td>Обход по SPF</td><td>{grey.timing.bypass_spf ? 'да' : 'нет'}</td></tr>
              </tbody>
            </table>
          )}

          <h4 style={{ marginTop: 24 }}>Статистика за {(grey.stats?.hours ?? 24)} ч</h4>
          <p className="muted">Отклонений по логам: <strong>{grey.stats?.rejections ?? 0}</strong></p>
          {(grey.stats?.top_senders?.length ?? 0) > 0 && (
            <>
              <p className="muted">Чаще всего задерживались:</p>
              <ul>
                {grey.stats!.top_senders.map((item) => (
                  <li key={item.address}>
                    {item.address} — {item.count}
                    {canWrite && (
                      <button
                        className="secondary"
                        style={{ marginLeft: 8 }}
                        onClick={() => whitelistFromLog(item.address)}
                        disabled={greyBusy}
                      >
                        В whitelist
                      </button>
                    )}
                  </li>
                ))}
              </ul>
            </>
          )}
          {(grey.stats?.recent?.length ?? 0) > 0 && (
            <div className="table-scroll" style={{ marginTop: 12 }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Время</th>
                    <th>От</th>
                    <th>Кому</th>
                    <th>IP</th>
                  </tr>
                </thead>
                <tbody>
                  {grey.stats!.recent.map((row, index) => (
                    <tr key={`${row.logged_at}-${index}`}>
                      <td>{row.logged_at}</td>
                      <td>{row.mail_from || '—'}</td>
                      <td>{row.mail_to || '—'}</td>
                      <td>{row.client_ip || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          <h4 style={{ marginTop: 20 }}>Правила greylisting</h4>
          {(grey.rules?.length ?? 0) ? (
            <div className="table-scroll">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Статус</th>
                    <th>От</th>
                    <th>Кому</th>
                    <th>Приоритет</th>
                    {canWrite && <th className="actions">Действия</th>}
                  </tr>
                </thead>
                <tbody>
                  {grey.rules!.map((rule, index) => (
                    <tr key={`${rule.from_addr}-${rule.to_addr}-${index}`}>
                      <td>
                        {rule.action === 'enabled' ? (
                          <span className="badge">включён</span>
                        ) : (
                          <span className="badge down">выключен</span>
                        )}
                      </td>
                      <td>{rule.from_addr}</td>
                      <td>{rule.to_addr}</td>
                      <td>{rule.priority ?? '—'}</td>
                      {canWrite && (
                        <td className="actions">
                          <button
                            className="danger"
                            disabled={greyBusy}
                            onClick={() => deleteGreyRule(rule.to_addr, rule.from_addr)}
                          >
                            Удалить
                          </button>
                        </td>
                      )}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="muted">Отдельных правил нет — действует глобальная политика.</p>
          )}

          {canWrite && (
            <>
              <h4 style={{ marginTop: 20 }}>Добавить исключение</h4>
              <p className="muted">
                Примеры: получатель <code>u1@example.ru</code>, отправитель <code>@gmail.com</code>.
                Пустой отправитель = любой.
              </p>
              <div className="form-row">
                <input
                  placeholder="Кому (to): user@domain.ru"
                  value={greyToAddr}
                  onChange={(e) => setGreyToAddr(e.target.value)}
                />
                <input
                  placeholder="От (from): @domain.ru (необязательно)"
                  value={greyFromAddr}
                  onChange={(e) => setGreyFromAddr(e.target.value)}
                />
              </div>
              <div className="form-row">
                <button disabled={greyBusy} onClick={disableGreylisting}>
                  Отключить для пары
                </button>
                <button className="secondary" disabled={greyBusy} onClick={enableGreylisting}>
                  Включить для пары
                </button>
              </div>

              <h4 style={{ marginTop: 20 }}>SPF-whitelist доменов</h4>
              <p className="muted">
                Для крупных почтовиков (Yandex, Mail.ru, Gmail): IP берутся из SPF-записи домена.
                После добавления нажмите «Обновить IP из SPF».
              </p>
              <div className="form-row">
                <input
                  placeholder="@yandex.ru"
                  value={greyWhitelistDomain}
                  onChange={(e) => setGreyWhitelistDomain(e.target.value)}
                />
                <button disabled={greyBusy} onClick={addGreyWhitelistDomain}>Добавить домен</button>
                <button className="secondary" disabled={greyBusy} onClick={syncGreySpf}>
                  Обновить IP из SPF
                </button>
              </div>
              <EntryList
                items={grey.whitelist_domains ?? []}
                canRemove
                onRemove={removeGreyWhitelistDomain}
                emptyText="SPF-whitelist доменов нет"
              />

              <h4 style={{ marginTop: 20 }}>IP из SPF/MX</h4>
              <p className="muted">
                Большой список (сейчас <strong>{spfCount}</strong>): редактируйте как текстовый файл —
                один IP/CIDR на строку. Можно скачать .txt, поправить в редакторе и загрузить обратно.
                «Обновить IP из SPF» выше перезапишет список из DNS доменов whitelist.
              </p>
              <textarea
                className="log-box"
                style={{
                  width: '100%',
                  minHeight: 280,
                  maxHeight: 480,
                  fontFamily: 'ui-monospace, Consolas, monospace',
                  fontSize: '0.85rem',
                }}
                value={spfText}
                onChange={(e) => setSpfText(e.target.value)}
                placeholder={'103.151.192.0/23\n104.43.243.237'}
              />
              <div className="form-row" style={{ marginTop: 8 }}>
                <button disabled={greyBusy} onClick={saveSpfText}>Сохранить список</button>
                <button
                  type="button"
                  className="secondary"
                  disabled={greyBusy}
                  onClick={() => downloadTextFile('greylist-spf-mx-ips.txt', spfText)}
                >
                  Скачать .txt
                </button>
                <button
                  type="button"
                  className="secondary"
                  disabled={greyBusy}
                  onClick={() => spfFileRef.current?.click()}
                >
                  Загрузить .txt
                </button>
                <input
                  ref={spfFileRef}
                  type="file"
                  accept=".txt,text/plain"
                  style={{ display: 'none' }}
                  onChange={(e) => {
                    onPickTxt(e.target.files?.[0], setSpfText)
                    e.target.value = ''
                  }}
                />
              </div>
            </>
          )}

          {!canWrite && spfText && (
            <>
              <h4 style={{ marginTop: 20 }}>IP из SPF/MX</h4>
              <textarea
                className="log-box"
                style={{ width: '100%', minHeight: 280, fontFamily: 'ui-monospace, Consolas, monospace', fontSize: '0.85rem' }}
                value={spfText}
                readOnly
              />
              <button
                type="button"
                className="secondary"
                style={{ marginTop: 8 }}
                onClick={() => downloadTextFile('greylist-spf-mx-ips.txt', spfText)}
              >
                Скачать .txt
              </button>
            </>
          )}

          {(grey.notes ?? []).map((note) => (
            <p key={note} className="muted" style={{ marginBottom: 4 }}>{note}</p>
          ))}
        </div>
      )}
    </div>
  )
}
