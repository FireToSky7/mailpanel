import { useEffect, useState } from 'react'
import { api, getUser, type GreylistingData, type MailPolicyData } from '../api'
import EntryList from '../components/EntryList'
import { errorMessage } from '../errors'
import { notify } from '../notify'

export default function AntispamPage() {
  const [whitelist, setWhitelist] = useState<string[]>([])
  const [blacklist, setBlacklist] = useState<string[]>([])
  const [whitelistEntry, setWhitelistEntry] = useState('')
  const [blacklistEntry, setBlacklistEntry] = useState('')
  const [score, setScore] = useState('5.0')
  const [grey, setGrey] = useState<GreylistingData | null>(null)
  const [greyToAddr, setGreyToAddr] = useState('')
  const [greyFromAddr, setGreyFromAddr] = useState('')
  const [greyWhitelistDomain, setGreyWhitelistDomain] = useState('')
  const [greyBusy, setGreyBusy] = useState(false)
  const [bannedExtensions, setBannedExtensions] = useState<string[]>([])
  const [bannedEntry, setBannedEntry] = useState('')
  const [mailPolicy, setMailPolicy] = useState<MailPolicyData | null>(null)
  const [scanInternal, setScanInternal] = useState(false)
  const role = getUser()?.role
  const canWrite = role === 'superadmin' || role === 'admin'

  async function load() {
    const errors: string[] = []

    try {
      const wl = await api.wblist('whitelist')
      setWhitelist(wl.entries)
    } catch (e) {
      errors.push(`Белый список: ${errorMessage(e)}`)
      setWhitelist([])
    }

    try {
      const bl = await api.wblist('blacklist')
      setBlacklist(bl.entries)
    } catch (e) {
      errors.push(`Чёрный список: ${errorMessage(e)}`)
      setBlacklist([])
    }

    try {
      const spam = await api.spam()
      setScore(spam.required_score)
    } catch (e) {
      errors.push(`SpamAssassin: ${errorMessage(e)}`)
    }

    try {
      setGrey(await api.greylisting())
    } catch (e) {
      errors.push(`Greylisting: ${errorMessage(e)}`)
      setGrey(null)
    }

    try {
      const banned = await api.bannedExtensions()
      setBannedExtensions(banned.extensions)
    } catch (e) {
      errors.push(`Запрещённые файлы: ${errorMessage(e)}`)
      setBannedExtensions([])
    }

    try {
      const policy = await api.mailPolicy()
      setMailPolicy(policy)
      setScanInternal(policy.scan_internal_mail)
    } catch (e) {
      errors.push(`Политика почты: ${errorMessage(e)}`)
      setMailPolicy(null)
    }

    if (errors.length) notify.error(errors.join('\n'))
  }

  useEffect(() => { load() }, [])

  async function addToList(type: 'whitelist' | 'blacklist', entry: string, clear: () => void) {
    const value = entry.trim()
    if (!value) {
      notify.error('Укажите запись для добавления')
      return
    }
    try {
      await api.addWblist(type, [value])
      clear()
      notify.success('Запись добавлена')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function removeFromList(type: 'whitelist' | 'blacklist', entry: string) {
    try {
      await api.deleteWblist(type, [entry])
      notify.success('Запись удалена')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function saveScore() {
    const value = parseFloat(score)
    if (!Number.isFinite(value) || value < 0 || value > 20) {
      notify.error('Порог спама: число от 0 до 20')
      return
    }
    try {
      await api.updateSpam({ required_score: value })
      notify.success('Порог SpamAssassin сохранён')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  function normalizeExtension(value: string): string {
    const trimmed = value.trim().toLowerCase().replace(/^\./, '')
    if (!/^[a-z0-9]{1,16}$/.test(trimmed)) {
      throw new Error('Расширение: только латиница и цифры, до 16 символов')
    }
    return `.${trimmed}`
  }

  async function addBannedExtensionAction() {
    try {
      const ext = normalizeExtension(bannedEntry)
      if (bannedExtensions.includes(ext)) {
        notify.error('Такое расширение уже в списке')
        return
      }
      const next = [...bannedExtensions, ext].sort()
      await api.updateBannedExtensions(next)
      setBannedEntry('')
      notify.success('Список запрещённых расширений сохранён')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function removeBannedExtension(ext: string) {
    if (bannedExtensions.length <= 1) {
      notify.error('Должно остаться хотя бы одно расширение')
      return
    }
    try {
      const next = bannedExtensions.filter((item) => item !== ext)
      await api.updateBannedExtensions(next)
      notify.success('Список запрещённых расширений сохранён')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function saveMailPolicy() {
    try {
      await api.updateMailPolicy(scanInternal)
      notify.success(scanInternal ? 'Проверка внутренней почты включена' : 'Проверка внутренней почты отключена')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function reloadGreylisting() {
    try {
      setGrey(await api.greylisting())
    } catch (e) {
      notify.error(errorMessage(e))
    }
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

  return (
    <div>
      <div className="topbar"><h2>Антиспам</h2></div>
      {canWrite && (
        <div className="card">
          <h3>Порог SpamAssassin</h3>
          <div className="form-row">
            <input value={score} onChange={(e) => setScore(e.target.value)} />
            <button onClick={saveScore}>Сохранить</button>
          </div>
          <p className="muted">Чем выше значение, тем меньше писем попадёт в спам. Обычно 5.0–7.0.</p>
        </div>
      )}
      {canWrite && (
        <div className="card">
          <h3>Запрещённые типы файлов (вложения)</h3>
          <p className="muted">
            Расширения, при которых Amavis блокирует письмо (карантин или отбраковка).
            Изменения записываются в amavisd.conf и перезапускают Amavis.
          </p>
          <div className="form-row">
            <input
              placeholder="exe, bat, ps1…"
              value={bannedEntry}
              onChange={(e) => setBannedEntry(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && addBannedExtensionAction()}
            />
            <button onClick={addBannedExtensionAction}>Добавить</button>
          </div>
          <EntryList
            items={bannedExtensions}
            canRemove
            onRemove={removeBannedExtension}
            emptyText="Список пуст"
          />
        </div>
      )}
      {canWrite && mailPolicy && (
        <div className="card">
          <h3>Проверка внутренней почты</h3>
          <p className="muted">
            По умолчанию письма с localhost и часть внутреннего трафика могут обходить антиспам и проверку вложений.
            При включении MailPanel настраивает Amavis на проверку исходящей и локальной почты (политика ORIGINATING).
          </p>
          <label className="form-row" style={{ alignItems: 'center', gap: 10 }}>
            <input
              type="checkbox"
              checked={scanInternal}
              onChange={(e) => setScanInternal(e.target.checked)}
            />
            Проверять внутреннюю почту (спам, запрещённые вложения)
          </label>
          <div className="form-row" style={{ marginTop: 10 }}>
            <button onClick={saveMailPolicy}>Сохранить политику</button>
          </div>
          {mailPolicy.notes.map((note) => (
            <p key={note} className="muted" style={{ marginBottom: 4 }}>{note}</p>
          ))}
        </div>
      )}
      <div className="card">
        <h3>Белый список</h3>
        <p className="muted">Глобальный список для всего сервера: email, домен (@domain.ru) или IP.</p>
        <div className="form-row">
          <input placeholder="email / @domain.ru / IP" value={whitelistEntry} onChange={(e) => setWhitelistEntry(e.target.value)} />
          {canWrite && <button onClick={() => addToList('whitelist', whitelistEntry, () => setWhitelistEntry(''))}>Добавить</button>}
        </div>
        <EntryList
          items={whitelist}
          canRemove={canWrite}
          onRemove={(entry) => removeFromList('whitelist', entry)}
          emptyText="Список пуст"
        />
      </div>
      {canWrite && (
        <div className="card">
          <h3>Чёрный список</h3>
          <p className="muted">
            Блокирует <strong>входящие</strong> письма от указанных отправителей (email, домен или IP).
            Не запрещает отправку с ящиков на сервере через Roundcube.
          </p>
          <div className="form-row">
            <input placeholder="email / @domain.ru / IP" value={blacklistEntry} onChange={(e) => setBlacklistEntry(e.target.value)} />
            <button onClick={() => addToList('blacklist', blacklistEntry, () => setBlacklistEntry(''))}>Добавить</button>
          </div>
          <EntryList
            items={blacklist}
            canRemove
            onRemove={(entry) => removeFromList('blacklist', entry)}
            emptyText="Список пуст"
          />
        </div>
      )}
      {grey?.timing && (
        <div className="card">
          <div className="topbar" style={{ marginBottom: 12 }}>
            <h3 style={{ margin: 0 }}>Greylisting (серый список)</h3>
            <button className="secondary" onClick={() => reloadGreylisting()} disabled={greyBusy}>
              Обновить
            </button>
          </div>
          <p className="muted">
            Защита от спам-ботов: первая попытка доставки отклоняется, нормальные серверы повторяют через несколько минут.
            Не связан с белым/чёрным списком Amavis.
          </p>
          <p>
            Статус:{' '}
            {grey.global_enabled ? (
              <span className="badge">включён глобально</span>
            ) : (
              <span className="badge down">отключён глобально</span>
            )}
            {grey.timing.training_mode && (
              <span className="badge" style={{ marginLeft: 8 }}>режим обучения</span>
            )}
          </p>

          <h4>Тайминги iRedAPD</h4>
          <table className="data-table">
            <tbody>
              <tr><td>Задержка перед повтором</td><td>{grey.timing.block_expire_minutes} мин</td></tr>
              <tr><td>Запоминание успешных отправителей</td><td>{grey.timing.auth_triplet_expire_days} дн</td></tr>
              <tr><td>Хранение неуспешных попыток</td><td>{grey.timing.unauth_triplet_expire_days} дн</td></tr>
              <tr><td>Обход по SPF</td><td>{grey.timing.bypass_spf ? 'да' : 'нет'}</td></tr>
            </tbody>
          </table>
          <p className="muted">Сообщение отклонения: {grey.timing.rejection_message}</p>

          <h4 style={{ marginTop: 20 }}>Статистика за {(grey.stats?.hours ?? 24)} ч</h4>
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

              {(grey.whitelist_addresses?.length ?? 0) > 0 && (
                <>
                  <h4 style={{ marginTop: 20 }}>Разрешённые IP/сети</h4>
                  <p className="muted">Подтянуты из SPF/MX зарегистрированных доменов ({grey.whitelist_addresses!.length}).</p>
                  <div className="log-box" style={{ maxHeight: 160, overflow: 'auto' }}>
                    {grey.whitelist_addresses!.join(', ')}
                  </div>
                </>
              )}
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
