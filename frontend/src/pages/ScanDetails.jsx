import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import StageStepper from '../components/scans/StageStepper.jsx'
import StatusBadge from '../components/common/StatusBadge.jsx'
import { EmptyState, ErrorAlert, Loading } from '../components/common/States.jsx'
import { useScan } from '../hooks/useScan.js'
import { ScanApi, friendlyError } from '../services/api.js'
import { STAGE_ORDER } from '../types/scan.js'

function ElapsedTimer({ startedAt, completedAt, running }) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!running) return undefined
    const id = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(id)
  }, [running])
  if (!startedAt) return <>—</>
  const end = completedAt ? Date.parse(completedAt) : now
  const seconds = Math.max(0, Math.floor((end - Date.parse(startedAt)) / 1000))
  const minutes = Math.floor(seconds / 60)
  return (
    <>
      {minutes > 0 ? `${minutes}m ` : ''}{seconds % 60}s{running ? ' elapsed' : ''}
    </>
  )
}

const VERDICT_STYLES = {
  reachable: { tone: 'ok', label: 'Target is live and scannable' },
  dns_alive_no_web: {
    tone: 'warn',
    label: 'Domain resolves, but no HTTP/HTTPS service answered',
  },
  reachable_dns_only: { tone: 'ok', label: 'Domain resolves; discovery continues' },
  not_registered: { tone: 'bad', label: 'Domain has no nameservers — likely unregistered' },
  dns_dead: { tone: 'bad', label: 'Domain does not resolve anywhere' },
  out_of_scope: { tone: 'bad', label: 'Target is outside authorized scope' },
}

function ReachabilityBanner({ diag, target }) {
  if (!diag || !diag.checked) return null
  const style = VERDICT_STYLES[diag.verdict] || { tone: 'info', label: diag.reason }
  return (
    <div className={`reach-banner reach-${style.tone}`} role="status">
      <div className="reach-banner-head">
        <span className="pill tone-info">Pre-scan check</span>
        <strong>{style.label}</strong>
      </div>
      <p className="reach-detail">{diag.reason}</p>
      {diag.addresses && diag.addresses.length > 0 ? (
        <p className="reach-detail">
          Resolved addresses: <code>{diag.addresses.join(', ')}</code>
        </p>
      ) : null}
      {diag.http_probes && diag.http_probes.length > 0 ? (
        <p className="reach-detail">
          HTTP probes:{' '}
          {diag.http_probes.map((p) => (
            <code key={p.url} style={{ marginRight: 12 }}>
              {p.url} → {p.reachable ? `HTTP ${p.status}` : 'no answer'}
            </code>
          ))}
        </p>
      ) : null}
      {target ? <p className="hint">Diagnostics target: {target}</p> : null}
    </div>
  )
}

const SUMMARY_CARDS = [
  ['assets', 'Assets'],
  ['live_hosts', 'Live Hosts'],
  ['open_ports', 'Open Ports'],
  ['technologies', 'Technologies'],
  ['endpoints', 'Endpoints'],
  ['vulnerability_observations', 'Vulnerability Observations'],
  ['cves_enriched', 'CVEs Enriched'],
  ['ai_findings', 'Findings'],
]

export default function ScanDetails() {
  const { scanId } = useParams()
  const navigate = useNavigate()
  const { scan, loading, error, refresh } = useScan(scanId)
  const [cancelling, setCancelling] = useState(false)
  const [resuming, setResuming] = useState(false)
  const [notice, setNotice] = useState('')
  const [summary, setSummary] = useState(null)
  const [reportReady, setReportReady] = useState(false)

  useEffect(() => {
    let cancelled = false
    ScanApi.summary(scanId)
      .then((data) => {
        if (!cancelled) setSummary(data)
      })
      .catch(() => {
        if (!cancelled) setSummary(null)
      })
    return () => {
      cancelled = true
    }
  }, [scanId, scan?.status])

  // Report availability: download links unlock exactly when the report exists.
  useEffect(() => {
    let cancelled = false
    ScanApi.report(scanId)
      .then((data) => {
        if (!cancelled) setReportReady(Boolean(data.markdown))
      })
      .catch(() => {
        if (!cancelled) setReportReady(false)
      })
    return () => {
      cancelled = true
    }
  }, [scanId, scan?.status])

  async function cancel() {
    if (!window.confirm(`Cancel scan ${scanId}? Evidence collected so far is kept.`)) {
      return
    }
    setCancelling(true)
    try {
      const updated = await ScanApi.cancel(scanId)
      setNotice(`Scan is now ${updated.status}. Resumable evidence is preserved.`)
      refresh()
    } catch (err) {
      setNotice(friendlyError(err, 'Could not cancel scan.'))
    } finally {
      setCancelling(false)
    }
  }

  async function resume() {
    setResuming(true)
    try {
      const updated = await ScanApi.resume(scanId)
      setNotice(`Scan resumed (status: ${updated.status}). Completed stages are not repeated.`)
      refresh()
    } catch (err) {
      setNotice(friendlyError(err, 'Could not resume scan.'))
    } finally {
      setResuming(false)
    }
  }

  if (loading) return <Loading message="Loading scan…" />
  if (error) return <ErrorAlert message={error} onRetry={refresh} />
  if (!scan) return <EmptyState message="Scan not found." />

  const running = scan.status === 'running' || scan.status === 'queued'
  const completed = scan.status === 'completed'
  const failed = scan.status === 'failed'
  const cancellable = scan.status === 'queued' || scan.status === 'running'
  const resumable = failed || scan.status === 'cancelled'
  const doneStages = (scan.stages || []).filter((s) =>
    ['completed', 'failed', 'blocked', 'skipped'].includes(s.status),
  ).length
  const execution = scan.execution_enabled ? 'Enabled (authorized)' : 'Disabled'

  return (
    <div>
      <button type="button" className="link-button" onClick={() => navigate('/scans')}>
        ← Back to scans
      </button>
      <section className="scan-hero" aria-label="Scan overview">
        <div className="scan-hero-top">
          <div>
            <p className="eyebrow">Authorized assessment target</p>
            <h1>{scan.target}</h1>
            <p className="scan-meta">
              Scan ID <code>{scan.scan_id}</code> · Mode {scan.scan_mode} · Execution{' '}
              {execution}
            </p>
          </div>
          <StatusBadge value={scan.status} />
        </div>
        <div className="progress-wrap" aria-label="Pipeline progress">
          <div
            className="progress-bar"
            role="progressbar"
            aria-valuenow={doneStages}
            aria-valuemin={0}
            aria-valuemax={STAGE_ORDER.length}
            aria-label={`${doneStages} of ${STAGE_ORDER.length} stages finished`}
          >
            <div
              className="progress-fill"
              style={{ width: `${(doneStages / STAGE_ORDER.length) * 100}%` }}
            />
          </div>
          <span className="progress-text">
            {doneStages} of {STAGE_ORDER.length} stages finished ·{' '}
            <ElapsedTimer
              startedAt={scan.started_at}
              completedAt={scan.completed_at}
              running={running}
            />
          </span>
        </div>
        <ReachabilityBanner diag={scan.reachability} target={scan.target} />
        {scan.error ? (
          <div className="alert-error" role="alert">
            <span>{scan.error}</span>
          </div>
        ) : null}
        {notice ? (
          <div className="alert-info" role="status">
            {notice}
          </div>
        ) : null}
        <div className="toolbar">
          <Link className="button" to={`/scans/${scan.scan_id}/findings`}>
            View Findings
          </Link>
          {reportReady ? (
            <>
              <Link className="button" to={`/scans/${scan.scan_id}/report`}>
                View Report
              </Link>
              <a
                className="button"
                href={ScanApi.reportPdfUrl(scan.scan_id)}
                download
              >
                Download PDF
              </a>
              <a
                className="button button-ghost"
                href={`/api/scans/${scan.scan_id}/report.md`}
                download
              >
                Download Markdown
              </a>
            </>
          ) : (
            <span className="hint">
              {completed
                ? 'Finalizing report… press refresh shortly, or check back briefly.'
                : running
                  ? 'View Findings shows what has been discovered so far. The report unlocks automatically when the scan completes.'
                  : 'No report was produced for this scan.'}
            </span>
          )}
          {cancellable ? (
            <button type="button" onClick={cancel} disabled={cancelling}>
              {cancelling ? 'Cancelling…' : 'Cancel Scan'}
            </button>
          ) : null}
          {resumable ? (
            <button type="button" onClick={resume} disabled={resuming}>
              {resuming ? 'Resuming…' : 'Resume Scan'}
            </button>
          ) : null}
        </div>
        <p className="hint">
          While the scan is running you can watch what has already been found via
          View Findings. When the entire operation completes, View Report and the
          download buttons unlock automatically.
        </p>
      </section>
      {summary ? (
        <section className="card" aria-label="Scan summary">
          <h2>Results so far</h2>
          <div className="grid">
            {SUMMARY_CARDS.map(([key, label]) => (
              <StatTile key={key} label={label} value={summary[key] ?? 0} />
            ))}
          </div>
        </section>
      ) : null}
      <section className="card" aria-label="Pipeline progress">
        <h2>Pipeline progress</h2>
        <StageStepper stages={scan.stages || []} summary={summary} />
      </section>
    </div>
  )
}

function StatTile({ label, value }) {
  return (
    <div className="card stat">
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  )
}
