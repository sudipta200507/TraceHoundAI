import { NavLink } from 'react-router-dom'
import logo from '../../assets/logo.png'

const homeIcon = (
  <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M3 10.5 12 3l9 7.5" />
    <path d="M5.5 9v10.5h13V9" />
    <path d="M10 19.5v-5.5h4v5.5" />
  </svg>
)

const scanIcon = (
  <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="11" cy="11" r="6.5" />
    <path d="m20.5 20.5-4.8-4.8" />
    <path d="M8 11h6M11 8v6" />
  </svg>
)

const gearIcon = (
  <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="12" r="3.2" />
    <path d="M12 2.8v2.6M12 18.6v2.6M2.8 12h2.6M18.6 12h2.6M5.5 5.5l1.8 1.8M16.7 16.7l1.8 1.8M18.5 5.5l-1.8 1.8M7.3 16.7l-1.8 1.8" />
  </svg>
)

const LINKS = [
  { to: '/dashboard', label: 'Dashboard', icon: homeIcon },
  { to: '/scans', label: 'Scans', icon: scanIcon },
  { to: '/settings', label: 'Settings', icon: gearIcon },
]

export default function Sidebar({ collapsed, onToggle }) {
  return (
    <nav className={collapsed ? 'sidebar sidebar-collapsed' : 'sidebar'} aria-label="Primary">
      <div className="sidebar-head">
        <div className="brand">
          <img src={logo} alt="" className="brand-logo" />
          <span className="brand-name">TraceHoundAI</span>
        </div>
        <button
          type="button"
          className="sidebar-toggle"
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          aria-expanded={!collapsed}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          onClick={onToggle}
        >
          {collapsed ? expandIcon : collapseIcon}
        </button>
      </div>
      <ul>
        {LINKS.map((link) => (
          <li key={link.to}>
            <NavLink
              to={link.to}
              title={link.label}
              className={({ isActive }) => (isActive ? 'active' : undefined)}
            >
              <span className="nav-icon" aria-hidden="true">
                {link.icon}
              </span>
              <span className="nav-label">{link.label}</span>
            </NavLink>
          </li>
        ))}
      </ul>
      <div className="side-note">
        <div className="nav-label">Findings</div>
        <p className="nav-label">
          Open a scan, then choose Findings or Report from its detail page.
        </p>
      </div>
    </nav>
  )
}

const collapseIcon = (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="m14.5 7-5 5 5 5" />
  </svg>
)

const expandIcon = (
  <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d="m9.5 7 5 5-5 5" />
  </svg>
)
