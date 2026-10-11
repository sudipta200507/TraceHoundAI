import StatusBadge from '../common/StatusBadge.jsx'

export default function FindingDetail({ finding, evidence, onClose }) {
  if (!finding) return null
  const evidenceById = Object.fromEntries((evidence || []).map((e) => [e.id, e]))
  return (
    <div className="modal-backdrop" onClick={onClose} aria-hidden="true">
      <div
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-label={`Finding ${finding.finding_id}`}
        onClick={(event) => event.stopPropagation()}
      >
        <h2>
          {finding.finding_id} — {finding.title}
        </h2>
        <div className="meta-row">
          <StatusBadge value={finding.severity} />
          <span>Confidence {finding.confidence}</span>
          <StatusBadge value={finding.classification} />
          <StatusBadge value={finding.verification_status} />
        </div>
        <p>{finding.description}</p>
        <h3>Observed Facts</h3>
        <ul>
          {(finding.observed_facts || []).map((fact, index) => (
            <li key={index}>{fact}</li>
          ))}
        </ul>
        <h3>AI Reasoning</h3>
        <p>{finding.reasoning || 'Not available'}</p>
        <h3>Recommended Manual Verification</h3>
        <ul>
          {(finding.next_manual_steps || []).map((step, index) => (
            <li key={index}>{step}</li>
          ))}
        </ul>
        <h3>Evidence</h3>
        <ul>
          {(finding.evidence_ids || []).map((id) => {
            const item = evidenceById[id]
            return (
              <li key={id}>
                <code>[{id}]</code>
                {item ? (
                  <span>
                    {' '}
                    {item.type}/{item.source} on {item.target}: {item.observed_value} (
                    {item.status})
                  </span>
                ) : (
                  <span> referenced but not present in this scan</span>
                )}
              </li>
            )
          })}
        </ul>
        <button type="button" onClick={onClose}>
          Close
        </button>
      </div>
    </div>
  )
}
