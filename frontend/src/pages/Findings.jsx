import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import FilterBar from '../components/findings/FilterBar.jsx'
import { applyFindingFilters } from '../utils/findings.js'
import FindingCard from '../components/findings/FindingCard.jsx'
import FindingDetail from '../components/findings/FindingDetail.jsx'
import { EmptyState, ErrorAlert, Loading } from '../components/common/States.jsx'
import { ScanApi, friendlyError } from '../services/api.js'

export default function Findings() {
  const { scanId } = useParams()
  const [findings, setFindings] = useState(null)
  const [scanStatus, setScanStatus] = useState('')
  const [error, setError] = useState('')
  const [selected, setSelected] = useState(null)
  const [filters, setFilters] = useState({
    severity: '',
    classification: '',
    status: '',
    sort: 'severity',
  })

  useEffect(() => {
    let cancelled = false
    let timer = null
    async function load() {
      try {
        const [statusData, findingsData] = await Promise.all([
          ScanApi.status(scanId).catch(() => null),
          ScanApi.findings(scanId).catch(() => ({ findings: [] })),
        ])
        if (cancelled) return
        if (statusData) setScanStatus(statusData.status)
        setFindings(findingsData.findings || [])
      } catch (err) {
        if (!cancelled) setError(friendlyError(err, 'Could not load findings.'))
      }
    }
    load()
    // While the scan is still running, refresh so new findings appear live.
    timer = setInterval(() => {
      if (scanStatus === '' || scanStatus === 'queued' || scanStatus === 'running') {
        load()
      }
    }, 5000)
    return () => {
      cancelled = true
      if (timer) clearInterval(timer)
    }
  }, [scanId, scanStatus])

  const visible = useMemo(
    () => (findings ? applyFindingFilters(findings, filters) : []),
    [findings, filters],
  )

  if (error) return <ErrorAlert message={error} />
  if (findings === null) return <Loading message="Loading findings…" />

  const ongoing = scanStatus === 'queued' || scanStatus === 'running'
  return (
    <div>
      <Link className="link-button" to={`/scans/${scanId}`}>
        ← Back to scan
      </Link>
      <h1>View Findings</h1>
      <p className="hint">
        Everything the pipeline has verified so far on this scan, refreshed
        automatically while the operation is ongoing.
      </p>
      <FilterBar filters={filters} onChange={setFilters} />
      {visible.length === 0 ? (
        <EmptyState
          message={
            ongoing
              ? 'Nothing found yet — the operation is ongoing. New verified findings appear here automatically as soon as the pipeline produces them.'
              : 'No findings for this scan. The pipeline observed the target surface but nothing met the validation bar.'
          }
        />
      ) : (
        visible.map((finding) => (
          <FindingCard key={finding.finding_id} finding={finding} onSelect={setSelected} />
        ))
      )}
      {ongoing ? (
        <p className="hint" role="status">
          ⟳ Live — this page refreshes every few seconds while the scan runs.
        </p>
      ) : null}
      <FindingDetail finding={selected} onClose={() => setSelected(null)} />
    </div>
  )
}
