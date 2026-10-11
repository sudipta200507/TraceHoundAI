import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import ReportViewer from '../components/reports/ReportViewer.jsx'
import { EmptyState, ErrorAlert, Loading } from '../components/common/States.jsx'
import { ScanApi, friendlyError } from '../services/api.js'
export default function Report() {
  const { scanId } = useParams()
  const [report, setReport] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    ScanApi.report(scanId)
      .then((data) => {
        if (!cancelled) setReport(data)
      })
      .catch((err) => {
        if (!cancelled) setError(friendlyError(err, 'Report unavailable.'))
      })
    return () => {
      cancelled = true
    }
  }, [scanId])

  function download() {
    if (!report) return
    const blob = new Blob([report.markdown], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `${scanId}-report.md`
    link.click()
    URL.revokeObjectURL(url)
  }

  if (error) return <ErrorAlert message={error} />
  if (!report) return <Loading message="Loading report…" />
  if (!report.markdown) return <EmptyState message="Report has no content yet." />

  return (
    <div>
      <Link className="link-button" to={`/scans/${scanId}`}>
        ← Back to scan
      </Link>
      <h1>Report for {scanId}</h1>
      <div className="toolbar" role="toolbar" aria-label="Report downloads">
        <a className="button" href={ScanApi.reportPdfUrl(scanId)} download>
          Download PDF
        </a>
        <a className="button button-ghost" href={ScanApi.appendixUrl(scanId)} download>
          Technical Appendix
        </a>
        <a className="button button-ghost" href={ScanApi.inventoryJsonUrl(scanId)} download>
          Inventory (JSON)
        </a>
        <a className="button button-ghost" href={ScanApi.inventoryCsvUrl(scanId)} download>
          Endpoints (CSV)
        </a>
      </div>
      <ReportViewer markdown={report.markdown} onDownload={download} />
    </div>
  )
}
