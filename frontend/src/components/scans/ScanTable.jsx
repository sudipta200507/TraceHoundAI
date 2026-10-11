import { Link } from 'react-router-dom'
import StatusBadge from '../common/StatusBadge.jsx'

export default function ScanTable({ scans }) {
  if (!scans.length) {
    return (
      <div className="state" role="status">
        No scans yet. Start your first scan above.
      </div>
    )
  }
  return (
    <table className="table">
      <thead>
        <tr>
          <th scope="col">Scan ID</th>
          <th scope="col">Target</th>
          <th scope="col">Status</th>
          <th scope="col">Stage</th>
          <th scope="col">Started</th>
          <th scope="col">Report</th>
        </tr>
      </thead>
      <tbody>
        {scans.map((scan) => (
          <tr key={scan.scan_id}>
            <td>
              <Link to={`/scans/${scan.scan_id}`}>{scan.scan_id}</Link>
            </td>
            <td>{scan.target}</td>
            <td>
              <StatusBadge value={scan.status} />
            </td>
            <td>{scan.current_stage || '—'}</td>
            <td>{scan.started_at || '—'}</td>
            <td>
              <Link to={`/scans/${scan.scan_id}/report`}>View</Link>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
