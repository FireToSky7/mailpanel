import React from 'react'
import { toAppUrl } from '../paths'

type Props = { children: React.ReactNode }
type State = { error: Error | null }

export default class ErrorBoundary extends React.Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  render() {
    if (this.state.error) {
      return (
        <div className="login-page">
          <div className="card login-card">
            <h2>Ошибка интерфейса</h2>
            <p className="muted">Панель не смогла отрисовать страницу. Попробуйте обновить или очистить кэш браузера.</p>
            <pre className="log-box" style={{ maxHeight: 200, overflow: 'auto' }}>{this.state.error.message}</pre>
            <button
              type="button"
              style={{ width: '100%', marginTop: 12 }}
              onClick={() => {
                localStorage.removeItem('mailpanel_token')
                localStorage.removeItem('mailpanel_user')
                window.location.href = toAppUrl('/login')
              }}
            >
              Сбросить сессию и перейти к входу
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
