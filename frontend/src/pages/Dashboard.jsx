import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import StatCard from '../components/dashboard/StatCard.jsx'
import SystemStatus from '../components/dashboard/SystemStatus.jsx'
import { EmptyState, ErrorAlert, Loading } from '../components/common/States.jsx'
import { sessionScanIds } from '../hooks/useScan.js'
import { ScanApi, SystemApi, friendlyError } from '../services/api.js'
import { normalizeSeverity } from '../types/finding.js'

export default function Dashboard() {
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [scans, setScans] = useState([])
  const [tools, setTools] = useState(null)
  const [severityTotals, setSeverityTotals] = useState({
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  })

  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const [toolsData, ...scanData] = await Promise.all([
          SystemApi.tools(),
          ...sessionScanIds().map((id) =>
            ScanApi.status(id).catch(() => null),
          ),
        ])
        if (cancelled) return
        setTools(toolsData)
        const valid = scanData.filter(Boolean)
        setScans(valid)
        const findingsLists = await Promise.all(
          valid.map((scan) =>
            ScanApi.findings(scan.scan_id)
              .then((data) => data.findings || [])
              .catch(() => []),
          ),
        )
        if (cancelled) return
        const totals = { critical: 0, high: 0, medium: 0, low: 0 }
        for (const list of findingsLists) {
          for (const finding of list) {
            const level = normalizeSeverity(finding.severity)
            if (level in totals) totals[level] += 1
          }
        }
        setSeverityTotals(totals)
      } catch (err) {
        if (!cancelled) setError(friendlyError(err, 'Could not load dashboard.'))
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    return () => {
      cancelled = true
    }
  }, [])

  if (loading) return <Loading message="Loading dashboard…" />
  if (error) return <ErrorAlert message={error} />

  const running = scans.filter((s) => s.status === 'running').length
  const completed = scans.filter((s) => s.status === 'completed').length
  const findings = Object.values(severityTotals).reduce((a, b) => a + b, 0)
  const maxSev = Math.max(1, ...Object.values(severityTotals))

  const sevRows = [
    { key: 'critical', label: 'Critical', value: severityTotals.critical },
    { key: 'high', label: 'High', value: severityTotals.high },
    { key: 'medium', label: 'Medium', value: severityTotals.medium },
    { key: 'low', label: 'Low', value: severityTotals.low },
  ]

  return (
    <div className="dash-page">
      <div className="page-head page-head-split">
        <div>
          <p className="eyebrow">Operations overview · Live from backend</p>
          <h1>Dashboard</h1>
          <p className="lede">
            Session posture at a glance — scans, findings by severity, and tool
            readiness.
          </p>
        </div>
        <Link to="/scans" className="button-primary dash-cta">
          New scan
        </Link>
      </div>

      {scans.length === 0 ? (
        <EmptyState message="No scans in this session yet. Create one from the Scans page." />
      ) : null}

      <div className="overview-grid">
        <StatCard label="Total Scans" value={scans.length} tone="info" sub="This browser session" />
        <StatCard label="Running Scans" value={running} tone="warn" sub="In progress now" />
        <StatCard label="Completed Scans" value={completed} tone="ok" sub="Reports ready" />
        <StatCard label="Findings" value={findings} tone="accent" sub="Across session scans" />
      </div>

      <div className="split">
        <section className="card panel" aria-label="Findings by severity">
          <div className="panel-head-row">
            <div>
              <h2>Findings by severity</h2>
              <p className="hint">Validated findings only · {findings} total</p>
            </div>
          </div>
          <ul className="sev-list">
            {sevRows.map((row) => (
              <li key={row.key} className={`sev-row sev-${row.key}`}>
                <span className="sev-label">{row.key === 'critical' ? 'Critical' : row.label}</span>
                <span className="sev-bar" aria-hidden="true">
                  <span
                    className="sev-fill"
                    style={{ width: `${(row.value / maxSev) * 100}%` }}
                  />
                </span>
                <span className="sev-value">{row.value}</span>
              </li>
            ))}
          </ul>
          <p className="hint">
            Counts reflect scans created in this browser session, fetched live
            from the backend. <Link to="/scans">Open Scans</Link>
          </p>
        </section>
        <SystemStatus tools={tools} />
      </div>
    </div>
  )
}
