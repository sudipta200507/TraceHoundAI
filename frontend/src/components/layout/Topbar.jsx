import { useLayoutEffect, useState } from 'react'

import ThemeToggle from '../common/ThemeToggle.jsx'

export default function Topbar({ backend, ollama }) {
  const [theme, setTheme] = useState(() =>
    document.documentElement?.dataset?.theme === 'dark' ? 'dark' : 'light',
  )

  useLayoutEffect(() => {
    const observer = new MutationObserver(() => {
      setTheme(
        document.documentElement.dataset.theme === 'dark' ? 'dark' : 'light',
      )
    })
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-theme'],
    })
    return () => observer.disconnect()
  }, [])

  return (
    <header className="topbar">
      <div className="topbar-title">Security Reconnaissance Dashboard</div>
      <div className="status-cluster" role="status" aria-label="System status">
        <span className={`pill ${backend === 'Online' ? 'ok' : 'bad'}`}>
          Backend: {backend}
        </span>
        <span className={`pill ${ollama === 'Ready' ? 'ok' : 'warn'}`}>
          Ollama: {ollama}
        </span>
        <span data-testid="current-theme" data-theme-value={theme} hidden />
        <ThemeToggle />
      </div>
    </header>
  )
}
