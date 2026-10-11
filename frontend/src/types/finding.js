/**
 * @typedef {object} Finding
 * @property {string} finding_id
 * @property {string} title
 * @property {string} severity
 * @property {number} confidence
 * @property {string} classification
 * @property {string[]} evidence_ids
 * @property {string} verification_status
 */

export const SEVERITY_ORDER = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
  info: 4,
}

export const SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'informational']

export const CLASSIFICATIONS = ['observed_fact', 'hypothesis', 'verified_finding', 'unknown']

export const VERIFICATION_STATUSES = ['unverified', 'supported', 'verified', 'rejected']

export function normalizeSeverity(severity) {
  const s = String(severity || '').toLowerCase()
  if (s === 'info') return 'informational'
  return SEVERITY_LEVELS.includes(s) ? s : 'informational'
}
