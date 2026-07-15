import { useEffect, useState } from 'react'
import { api, getUser, type Mailbox, type MailGroup } from '../api'
import { errorMessage, validateEmail } from '../errors'
import { notify } from '../notify'

const EVERYONE = 'everyone'

function isEveryoneToken(value: string): boolean {
  const token = value.trim().toLowerCase()
  return token === EVERYONE || token.startsWith('everyone@')
}

function isDomainOnly(group: MailGroup): boolean {
  return Boolean(group.domain_only ?? group.members_only)
}

export default function GroupsPage() {
  const [items, setItems] = useState<MailGroup[]>([])
  const [mailboxes, setMailboxes] = useState<Mailbox[]>([])
  const [address, setAddress] = useState('')
  const [membersInput, setMembersInput] = useState('')
  const [domainOnly, setDomainOnly] = useState(true)
  const [selectedGroup, setSelectedGroup] = useState('')
  const [newMember, setNewMember] = useState('')
  const role = getUser()?.role
  const canWrite = role === 'superadmin' || role === 'admin'

  async function load() {
    const [groups, boxes] = await Promise.all([api.groups(), api.mailboxes()])
    setItems(groups)
    setMailboxes(boxes)
    if (!selectedGroup && groups.length) {
      setSelectedGroup(groups[0].address)
    }
  }

  useEffect(() => {
    load().catch((e) => notify.error(errorMessage(e)))
  }, [])

  function parseMembers(text: string): string[] {
    return text
      .split(/[\n,;]+/)
      .map((item) => item.trim())
      .filter(Boolean)
  }

  async function create() {
    const addressError = validateEmail(address, 'Адрес группы')
    const members = parseMembers(membersInput)
    if (addressError) {
      notify.error(addressError)
      return
    }
    if (!members.length) {
      notify.error('Укажите хотя бы одного участника или everyone')
      return
    }
    for (const member of members) {
      if (isEveryoneToken(member)) continue
      const memberError = validateEmail(member, 'Участник')
      if (memberError) {
        notify.error(memberError)
        return
      }
    }
    try {
      await api.createGroup({
        address: address.trim(),
        members,
        domain_only: domainOnly,
      })
      setAddress('')
      setMembersInput('')
      setDomainOnly(true)
      notify.success('Группа создана')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function removeGroup(addr: string) {
    if (!confirm(`Удалить группу ${addr}?`)) return
    try {
      await api.deleteGroup(addr)
      if (selectedGroup === addr) setSelectedGroup('')
      notify.success('Группа удалена')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function toggleDomainOnly(group: MailGroup) {
    const next = !isDomainOnly(group)
    try {
      await api.updateGroupDomainOnly(group.address, next)
      notify.success(
        next
          ? 'Писать на группу могут только ящики вашего домена'
          : 'Писать на группу могут все (без ограничения)',
      )
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function addMember() {
    if (!selectedGroup) {
      notify.error('Выберите группу')
      return
    }
    if (!isEveryoneToken(newMember)) {
      const memberError = validateEmail(newMember, 'Участник')
      if (memberError) {
        notify.error(memberError)
        return
      }
    }
    try {
      await api.addGroupMember(selectedGroup, newMember.trim())
      setNewMember('')
      notify.success(isEveryoneToken(newMember) ? 'Добавлен everyone (все ящики домена)' : 'Участник добавлен')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  async function removeMember(groupAddress: string, member: string) {
    if (!confirm(`Убрать ${member} из группы ${groupAddress}?`)) return
    try {
      await api.removeGroupMember(groupAddress, member)
      notify.success('Участник удалён из группы')
      await load()
    } catch (e) {
      notify.error(errorMessage(e))
    }
  }

  const selected = items.find((group) => group.address === selectedGroup)

  return (
    <div>
      <div className="topbar"><h2>Группы</h2></div>

      <div className="card">
        <h3>Групповые адреса</h3>
        <p className="muted">
          Группа — общий адрес без ящика. Письмо на группу доставляется всем участникам.
          Специальный код <code>everyone</code> означает все активные ящики домена
          (новые ящики добавляются автоматически).
        </p>
        {canWrite && (
          <>
            <div className="form-row">
              <input
                placeholder="it@example.ru"
                value={address}
                onChange={(e) => setAddress(e.target.value)}
              />
            </div>
            <div className="form-row">
              <textarea
                placeholder="Участники: everyone или u1@example.ru, u2@example.ru"
                value={membersInput}
                onChange={(e) => setMembersInput(e.target.value)}
                rows={3}
                style={{ flex: 1, minWidth: 280 }}
              />
              <button onClick={create}>Создать группу</button>
            </div>
            <label className="form-row" style={{ alignItems: 'center', gap: 10 }}>
              <input
                type="checkbox"
                checked={domainOnly}
                onChange={(e) => setDomainOnly(e.target.checked)}
              />
              Только ящики своего домена могут отправлять на этот групповой адрес
            </label>
            <p className="muted" style={{ marginTop: 0 }}>
              Защита от внешнего спама: писать на группу смогут только адреса{' '}
              <code>@ваш-домен</code>. Нужен плагин iRedAPD <code>sql_alias_access_policy</code>.
            </p>
          </>
        )}
        <table>
          <thead>
            <tr>
              <th>Адрес группы</th>
              <th>Участники</th>
              <th>Только свой домен</th>
              {canWrite && <th></th>}
            </tr>
          </thead>
          <tbody>
            {items.length === 0 && (
              <tr><td colSpan={canWrite ? 4 : 3} className="muted">Групп нет</td></tr>
            )}
            {items.map((group) => (
              <tr key={group.address}>
                <td>{group.address}</td>
                <td>{group.members || '—'}</td>
                <td>
                  <span className={isDomainOnly(group) ? 'status-yes' : 'status-no'}>
                    {isDomainOnly(group) ? 'Да' : 'Нет'}
                  </span>
                </td>
                {canWrite && (
                  <td className="actions">
                    <button className="secondary" onClick={() => setSelectedGroup(group.address)}>Управлять</button>
                    <button className="secondary" onClick={() => toggleDomainOnly(group)}>
                      {isDomainOnly(group) ? 'Разрешить всем' : 'Только свой домен'}
                    </button>
                    <button className="danger" onClick={() => removeGroup(group.address)}>Удалить</button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {canWrite && items.length > 0 && (
        <div className="card">
          <h3>Участники группы</h3>
          <div className="form-row" style={{ marginBottom: 16 }}>
            <select value={selectedGroup} onChange={(e) => setSelectedGroup(e.target.value)}>
              {items.map((group) => (
                <option key={group.address} value={group.address}>{group.address}</option>
              ))}
            </select>
            <select value={newMember} onChange={(e) => setNewMember(e.target.value)}>
              <option value="">Выберите ящик…</option>
              <option value={EVERYONE}>{EVERYONE} (все ящики домена)</option>
              {mailboxes.map((mailbox) => (
                <option key={mailbox.username} value={mailbox.username}>{mailbox.username}</option>
              ))}
            </select>
            <input
              placeholder="или email / everyone"
              value={newMember}
              onChange={(e) => setNewMember(e.target.value)}
            />
            <button onClick={addMember} disabled={!selectedGroup}>Добавить</button>
          </div>
          {selected?.include_everyone && (
            <p className="muted">
              Эта группа использует <code>everyone</code>: в рассылку входят все активные ящики домена.
              Список синхронизируется при создании и удалении ящиков.
            </p>
          )}
          {selected ? (
            <table>
              <thead><tr><th>Участник</th><th></th></tr></thead>
              <tbody>
                {selected.include_everyone ? (
                  <tr>
                    <td><code>{EVERYONE}</code> — все ящики домена</td>
                    <td className="muted">синхронизируется автоматически</td>
                  </tr>
                ) : (
                  (selected.members || '').split(',').map((item) => item.trim()).filter(Boolean).map((member) => (
                    <tr key={member}>
                      <td>{member}</td>
                      <td>
                        <button className="danger" onClick={() => removeMember(selected.address, member)}>
                          Убрать
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          ) : (
            <p className="muted">Выберите группу</p>
          )}
        </div>
      )}
    </div>
  )
}
