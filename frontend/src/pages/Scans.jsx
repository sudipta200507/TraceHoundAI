import { useEffect, useState } from 'react'
import NewScanForm from '../components/scans/NewScanForm.jsx'
import ScanTable from '../components/scans/ScanTable.jsx'
import { EmptyState, ErrorAlert, Loading } from '../components/common/States.jsx'
import { sessionScanIds } from '../hooks/useScan.js'
import { ScanApi, friendlyError } from '../services/api.js'

export default function Scans() {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  async function load() {
    setLoading(true)
    setError('')
    try {
      const results = await Promise.all(
        sessionScanIds().map((id) => ScanApi.status(id).catch(() => null)),
      )
      setScans(results.filter(Boolean))
    } catch (err) {
      setError(friendlyError(err, 'Could not load scans.'))
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    let cancelled = false
    async function fetchSessionScans() {
      setLoading(true)
      setError('')
      try {
        const results = await Promise.all(
          sessionScanIds().map((id) => ScanApi.status(id).catch(() => null)),
        )
        if (!cancelled) setScans(results.filter(Boolean))
      } catch (err) {
        if (!cancelled) setError(friendlyError(err, 'Could not load scans.'))
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    fetchSessionScans()
    return () => {
      cancelled = true
    }
  }, [])

  return (
    <div className="scan-page">
      <div className="page-head">
        <div>
          <p className="eyebrow">Authorized assessment · Full pipeline</p>
          <h1>Security Scans</h1>
          <p className="lede">
            Start an authorized assessment below. Every scan runs the complete
            pipeline against a dedicated scope built from your target domain.
          </p>
        </div>
      </div>
      <NewScanForm />
      <section className="card list-card" aria-label="Scan list">
        <div className="list-head">
          <h2>Your scans</h2>
          {scans.length ? <span className="count-pill">{scans.length}</span> : null}
        </div>
        {loading ? (
          <Loading message="Loading scans…" />
        ) : error ? (
          <ErrorAlert message={error} onRetry={load} />
        ) : scans.length ? (
          <ScanTable scans={scans} />
        ) : (
          <EmptyState message="No scans yet. Start your first authorized scan above." />
        )}
      </section>
    </div>
  )
}
