import { useMemo, useState } from 'react'
import { renderMarkdown } from '../../utils/markdown.js'
import { REPORT_SECTIONS } from '../../types/report.js'

export default function ReportViewer({ markdown, onDownload }) {
  const [raw, setRaw] = useState(false)
  const html = useMemo(() => renderMarkdown(markdown || ''), [markdown])
  return (
    <div>
      <div className="toolbar" role="toolbar" aria-label="Report actions">
        <button type="button" onClick={() => setRaw(false)} disabled={!raw}>
          View Report
        </button>
        <button type="button" onClick={() => setRaw(true)} disabled={raw}>
          Open Raw Markdown
        </button>
        <button type="button" onClick={onDownload}>
          Download Report
        </button>
      </div>
      <p className="hint">
        Covers: {REPORT_SECTIONS.join(' · ')}. Content is backend-authoritative.
      </p>
      {raw ? (
        <pre className="raw">{markdown}</pre>
      ) : (
        <article
          className="report"
          dangerouslySetInnerHTML={{ __html: html }}
        />
      )}
    </div>
  )
}
