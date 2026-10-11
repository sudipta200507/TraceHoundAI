import StatusBadge from '../common/StatusBadge.jsx'

export default function SystemStatus({ tools }) {
  if (!tools) return null
  const list = tools.tools || []
  const ready = list.filter((t) => t.status === 'ready' || t.available).length
  return (
    <section className="card panel" aria-label="Tool status">
      <div className="panel-head-row">
        <div>
          <h2>Tool status</h2>
          <p className="hint">
            {ready} of {list.length} tools ready · managed by the backend
          </p>
        </div>
        <span className="count-pill">
          {ready}/{list.length}
        </span>
      </div>
      <ul className="tool-list pro">
        {list.map((tool) => (
          <li key={tool.name}>
            <span
              className={`tool-dot ${
                tool.status === 'ready' || tool.available ? 'on' : 'off'
              }`}
              aria-hidden="true"
            />
            <span className="tool-name">{tool.name}</span>
            <span className="tool-version">{tool.version || '—'}</span>
            <span className="tool-badge">
              <StatusBadge value={tool.status} />
            </span>
          </li>
        ))}
      </ul>
    </section>
  )
}
