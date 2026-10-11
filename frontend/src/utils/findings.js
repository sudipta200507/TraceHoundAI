export function applyFindingFilters(findings, filters) {
  const order = { critical: 0, high: 1, medium: 2, low: 3, informational: 4, info: 4 }
  const filtered = findings.filter((finding) => {
    if (filters.severity && finding.severity !== filters.severity) return false
    if (filters.classification && finding.classification !== filters.classification) {
      return false
    }
    if (filters.status && finding.verification_status !== filters.status) return false
    return true
  })
  return [...filtered].sort((a, b) => {
    if (filters.sort === 'confidence') return b.confidence - a.confidence
    if (filters.sort === 'id') return a.finding_id.localeCompare(b.finding_id)
    return (order[a.severity] ?? 9) - (order[b.severity] ?? 9)
  })
}
