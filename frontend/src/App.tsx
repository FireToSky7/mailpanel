import { BrowserRouter, Navigate, Route, Routes, Link, useLocation } from 'react-router-dom'
import { getToken, getUser, clearSession, canAccess } from './api'
import ErrorBoundary from './components/ErrorBoundary'
import ToastStack from './components/ToastStack'
import { getBasename, toAppUrl } from './paths'
import LoginPage from './pages/LoginPage'
import DashboardPage from './pages/DashboardPage'
import MailboxesPage from './pages/MailboxesPage'
import AliasesPage from './pages/AliasesPage'
import GroupsPage from './pages/GroupsPage'
import AntispamPage from './pages/AntispamPage'
import GreylistingPage from './pages/GreylistingPage'
import RulesPage from './pages/RulesPage'
import QuarantinePage from './pages/QuarantinePage'
import QueuePage from './pages/QueuePage'
import LogsPage from './pages/LogsPage'
import Fail2banPage from './pages/Fail2banPage'
import PanelUsersPage from './pages/PanelUsersPage'

function Shell({ children }: { children: React.ReactNode }) {
  const user = getUser()
  const location = useLocation()
  if (!user) return <>{children}</>

  const links = [
    { to: '/', label: 'Обзор', section: 'dashboard' },
    { to: '/mailboxes', label: 'Ящики', section: 'mailboxes' },
    { to: '/aliases', label: 'Алиасы', section: 'aliases' },
    { to: '/groups', label: 'Группы', section: 'groups' },
    { to: '/antispam', label: 'Антиспам', section: 'antispam' },
    { to: '/greylisting', label: 'Greylisting', section: 'greylisting' },
    { to: '/rules', label: 'Правила', section: 'rules' },
    { to: '/quarantine', label: 'Карантин', section: 'quarantine' },
    { to: '/queue', label: 'Очередь', section: 'queue' },
    { to: '/logs', label: 'Логи', section: 'logs' },
    { to: '/fail2ban', label: 'Fail2ban', section: 'services' },
    { to: '/panel-users', label: 'Админы панели', section: 'panelUsers' },
  ].filter((l) => canAccess(user.role, l.section))

  return (
    <div className="layout">
      <aside className="sidebar">
        <h1>MailPanel</h1>
        <div className="muted" style={{ padding: '0 12px 16px' }}>{user.display_name}<br />{user.role}</div>
        <nav>
          {links.map((l) => (
            <Link key={l.to} to={l.to} className={location.pathname === l.to ? 'active' : ''}>{l.label}</Link>
          ))}
        </nav>
        <button className="secondary" style={{ width: '100%', marginTop: 20 }} onClick={() => { clearSession(); window.location.href = toAppUrl('/login') }}>Выйти</button>
      </aside>
      <main className="content">{children}</main>
      <ToastStack />
    </div>
  )
}

function PrivateRoute({ children }: { children: React.ReactNode }) {
  if (!getToken()) return <Navigate to="/login" replace />
  return <Shell>{children}</Shell>
}

export default function App() {
  const basename = getBasename()
  return (
    <ErrorBoundary>
      <BrowserRouter basename={basename}>
        <Routes>
        <Route path="/login" element={getToken() ? <Navigate to="/" replace /> : <LoginPage />} />
        <Route path="/" element={<PrivateRoute><DashboardPage /></PrivateRoute>} />
        <Route path="/mailboxes" element={<PrivateRoute><MailboxesPage /></PrivateRoute>} />
        <Route path="/aliases" element={<PrivateRoute><AliasesPage /></PrivateRoute>} />
        <Route path="/groups" element={<PrivateRoute><GroupsPage /></PrivateRoute>} />
        <Route path="/antispam" element={<PrivateRoute><AntispamPage /></PrivateRoute>} />
        <Route path="/greylisting" element={<PrivateRoute><GreylistingPage /></PrivateRoute>} />
        <Route path="/rules" element={<PrivateRoute><RulesPage /></PrivateRoute>} />
        <Route path="/quarantine" element={<PrivateRoute><QuarantinePage /></PrivateRoute>} />
        <Route path="/queue" element={<PrivateRoute><QueuePage /></PrivateRoute>} />
        <Route path="/logs" element={<PrivateRoute><LogsPage /></PrivateRoute>} />
        <Route path="/fail2ban" element={<PrivateRoute><Fail2banPage /></PrivateRoute>} />
        <Route path="/services" element={<Navigate to="/fail2ban" replace />} />
        <Route path="/panel-users" element={<PrivateRoute><PanelUsersPage /></PrivateRoute>} />
        <Route path="/portal" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </ErrorBoundary>
  )
}
