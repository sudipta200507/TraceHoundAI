import { useEffect, useState } from 'react'
import { Outlet } from 'react-router-dom'
import { SystemApi } from '../../services/api.js'
import Sidebar from './Sidebar.jsx'
import Topbar from './Topbar.jsx'

export default function Layout() {
  const [backend, setBackend] = useState('Offline')
  const [ollama, setOllama] = useState('Unavailable')
  const [collapsed, setCollapsed] = useState(false)

  useEffect(() => {
    let cancelled = false
    SystemApi.health()
      .then(() => {
        if (!cancelled) setBackend('Online')
      })
      .catch(() => {
        if (!cancelled) setBackend('Offline')
      })
    SystemApi.tools()
      .then((data) => {
        if (cancelled) return
        const ollamaTool = (data.tools || []).find((t) => t.name === 'ollama')
        setOllama(ollamaTool && ollamaTool.available ? 'Ready' : 'Unavailable')
      })
      .catch(() => {
        if (!cancelled) setOllama('Unavailable')
      })
    return () => {
      cancelled = true
    }
  }, [])

  return (
    <div className="shell">
      <Sidebar
        collapsed={collapsed}
        onToggle={() => setCollapsed((c) => !c)}
      />
      <div className="main">
        <Topbar backend={backend} ollama={ollama} />
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
