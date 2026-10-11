export default function FilterBar({ filters, onChange }) {
  function update(key, value) {
    onChange({ ...filters, [key]: value })
  }
  return (
    <div className="filters" role="search" aria-label="Filter findings">
      <label>
        Severity
        <select
          value={filters.severity}
          onChange={(event) => update('severity', event.target.value)}
        >
          <option value="">All</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="informational">Informational</option>
        </select>
      </label>
      <label>
        Classification
        <select
          value={filters.classification}
          onChange={(event) => update('classification', event.target.value)}
        >
          <option value="">All</option>
          <option value="observed_fact">Observed fact</option>
          <option value="hypothesis">Hypothesis</option>
          <option value="verified_finding">Verified finding</option>
          <option value="unknown">Unknown</option>
        </select>
      </label>
      <label>
        Status
        <select
          value={filters.status}
          onChange={(event) => update('status', event.target.value)}
        >
          <option value="">All</option>
          <option value="unverified">Unverified</option>
          <option value="supported">Supported</option>
          <option value="verified">Verified</option>
          <option value="rejected">Rejected</option>
        </select>
      </label>
      <label>
        Sort by
        <select value={filters.sort} onChange={(event) => update('sort', event.target.value)}>
          <option value="severity">Severity</option>
          <option value="confidence">Confidence</option>
          <option value="id">Finding ID</option>
        </select>
      </label>
    </div>
  )
}
