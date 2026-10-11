import StatusBadge from '../common/StatusBadge.jsx'

export default function FindingCard({ finding, onSelect }) {
  return (
    <article className="card finding">
      <h3>
        <button type="button" className="link-button" onClick={() => onSelect(finding)}>
          {finding.finding_id} — {finding.title}
        </button>
      </h3>
      <div className="meta-row">
        <StatusBadge value={finding.severity} />
        <span>Confidence {finding.confidence}</span>
        <StatusBadge value={finding.classification} />
        <StatusBadge value={finding.verification_status} />
        <span>{finding.evidence_ids.length} evidence</span>
      </div>
    </article>
  )
}
