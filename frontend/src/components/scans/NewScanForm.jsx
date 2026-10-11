import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ScanApi, friendlyError, isScopeRejection } from '../../services/api.js'
import { rememberScanId } from '../../hooks/useScan.js'

const STEPS = [
  {
    title: 'Scope',
    text: 'Enter the root domain you are authorized to assess.',
  },
  {
    title: 'Authorize',
    text: 'Confirm authorization and start — the backend builds a dedicated scope.',
  },
  {
    title: 'Track',
    text: 'Watch live progress: discovery → verification → AI analysis → report.',
  },
]

export default function NewScanForm() {
  const navigate = useNavigate()
  const [target, setTarget] = useState('')
  const [confirmed, setConfirmed] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  async function submit(event) {
    event.preventDefault()
    setBusy(true)
    setError('')
    try {
      const scan = await ScanApi.create({
        target: target.trim(),
        authorize_active: true,
        approved_by: 'scan-ui-authorized-scan',
        reason: 'user confirmed authorized laboratory assessment',
      })
      rememberScanId(scan.scan_id)
      navigate(`/scans/${scan.scan_id}`)
    } catch (err) {
      const detail = err?.response?.data?.detail
      if (isScopeRejection(err)) {
        setError(
          'Target is outside the authorized scope or not a usable root domain. ' +
            (typeof detail === 'string' && detail.length < 300
              ? detail + ' '
              : '') +
            'Enter a real, fully qualified root domain you are authorized to ' +
            'assess (for example, example.com). If the domain is not registered ' +
            'or does not resolve, the scan page reports exactly why after you start it.',
        )
      } else {
        setError(friendlyError(err, 'Could not create scan.'))
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card hero-card" aria-label="Start security reconnaissance">
      <div className="hero-copy">
        <p className="eyebrow eyebrow-accent">New assessment</p>
        <h2>Start Security Reconnaissance</h2>
        <p className="lede">
          One authorized root domain in, one validated security report out.
          The backend creates a dedicated scope for your target —{' '}
          <strong>that domain plus its subdomains, nothing else</strong> — and
          runs the full pipeline: discovery, verification, AI analysis, report.
        </p>
        <ol className="pipeline">
          {STEPS.map((step, index) => (
            <li key={step.title}>
              <span className="pipeline-num" aria-hidden="true">
                {index + 1}
              </span>
              <span>
                <strong>{step.title}</strong>
                <span className="pipeline-text">{step.text}</span>
              </span>
            </li>
          ))}
        </ol>
        <div className="trust-row" aria-label="Assessment guarantees">
          <span className="trust-chip">
            <span className="dot dot-ok" aria-hidden="true" />
            Scoped scan
          </span>
          <span className="trust-chip">
            <span className="dot dot-info" aria-hidden="true" />
            Validated report
          </span>
          <span className="trust-chip">
            <span className="dot dot-muted" aria-hidden="true" />
            No exploitation
          </span>
        </div>
      </div>
      <form onSubmit={submit} className="hero-form scan-form-panel">
        <div className="panel-head">
          <h3>Configure scan</h3>
          <p className="hint">Takes about 30 seconds to start.</p>
        </div>
        <div className="field">
          <label htmlFor="scan-target">Target Domain</label>
          <div className="input-wrap">
            <svg
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <circle cx="12" cy="12" r="9" />
              <path d="M3 12h18M12 3c2.5 2.6 3.9 5.7 3.9 9S14.5 18.4 12 21c-2.5-2.6-3.9-5.7-3.9-9S9.5 5.6 12 3Z" />
            </svg>
            <input
              id="scan-target"
              name="target"
              type="text"
              placeholder="example.com"
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              required
              autoComplete="off"
              spellCheck="false"
            />
          </div>
        </div>
        <label className="confirm">
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(event) => setConfirmed(event.target.checked)}
          />
          <span>
            I confirm this target is authorized for this laboratory/internship
            assessment.
          </span>
        </label>
        <p className="hint">
          Checking the box authorizes this scan on the backend. If the domain
          is malformed, unresolvable, or outside lab policy, the scan is
          refused and the reason is shown here. Exploitation is never performed.
        </p>
        {error ? (
          <div className="alert-error" role="alert">
            {error}
          </div>
        ) : null}
        <button
          type="submit"
          className="button-primary scan-submit"
          disabled={busy || !target.trim() || !confirmed}
        >
          {busy ? 'Starting…' : 'START SCAN'}
        </button>
      </form>
    </section>
  )
}
