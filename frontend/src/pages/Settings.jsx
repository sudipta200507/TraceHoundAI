import { useEffect, useState } from 'react'
import ThemeToggle from '../components/common/ThemeToggle.jsx'
import { ErrorAlert, Loading } from '../components/common/States.jsx'
import { SystemApi, friendlyError } from '../services/api.js'

export default function Settings() {
  const [tools, setTools] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    SystemApi.tools()
      .then((data) => {
        if (!cancelled) setTools(data)
      })
      .catch((err) => {
        if (!cancelled) setError(friendlyError(err, 'Could not load system info.'))
      })
    return () => {
      cancelled = true
    }
  }, [])

  if (error) return <ErrorAlert message={error} />
  if (!tools) return <Loading message="Loading system info…" />

  const ollama = (tools.tools || []).find((t) => t.name === 'ollama')
  const ollamaReady = Boolean(ollama && ollama.available)

  return (
    <div className="settings-page">
      <div className="page-head">
        <p className="eyebrow">Console · Preferences & environment</p>
        <h1>Settings</h1>
        <p className="lede">
          Preferences and environment details for the TraceHoundAI console.
          Appearance is the only user-facing preference; everything else is
          managed on the backend.
        </p>
      </div>

      <div className="split">
        <section className="card panel" aria-label="Appearance">
          <div className="panel-head-row">
            <div>
              <h2>Appearance</h2>
              <p className="hint">Light or dark console theme · stored locally</p>
            </div>
          </div>
          <dl className="facts pro">
            <div className="fact-row">
              <dt>Theme</dt>
              <dd>
                <ThemeToggle />
              </dd>
            </div>
          </dl>
          <div className="theme-preview" aria-hidden="true">
            <span className="swatch swatch-light">Light</span>
            <span className="swatch swatch-dark">Dark</span>
          </div>
          <p className="hint">Switch between the light and dark console theme.</p>
        </section>

        <section className="card panel" aria-label="System information">
          <div className="panel-head-row">
            <div>
              <h2>System information</h2>
              <p className="hint">Read-only · managed on the backend</p>
            </div>
            <span className={`status-dot ${ollamaReady ? 'on' : 'off'}`}>
              {ollamaReady ? 'Ready' : 'Check'}
            </span>
          </div>
          <dl className="facts pro">
            <div className="fact-row">
              <dt>Backend status</dt>
              <dd>
                <span className="pill ok">Online</span>
              </dd>
            </div>
            <div className="fact-row">
              <dt>API base URL</dt>
              <dd className="mono">{window.location.origin}</dd>
            </div>
            <div className="fact-row">
              <dt>Ollama status</dt>
              <dd>
                <span className={`pill ${ollamaReady ? 'ok' : 'warn'}`}>
                  {ollamaReady ? 'Ready' : 'Unavailable'}
                </span>
              </dd>
            </div>
            <div className="fact-row">
              <dt>Model</dt>
              <dd className="mono">qwen3:8b</dd>
            </div>
          </dl>
          <p className="hint">
            Configuration is managed on the backend. This UI exposes no controls
            that bypass backend policy.
          </p>
        </section>
      </div>

      <section className="card notice" aria-label="Policy note">
        <strong>Managed by backend policy</strong>
        <span>
          Scope, tool execution, and reporting are enforced server-side. The
          console only collects the target domain and authorization.
        </span>
      </section>
    </div>
  )
}
