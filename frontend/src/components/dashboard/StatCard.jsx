export default function StatCard({ label, value, tone = 'info', sub }) {
  return (
    <div className={`card stat stat-${tone}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {sub ? <div className="stat-sub">{sub}</div> : null}
    </div>
  )
}
