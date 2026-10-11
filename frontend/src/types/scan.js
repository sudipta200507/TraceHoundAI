/**
 * @typedef {'queued'|'running'|'completed'|'failed'|'cancelled'} ScanStatus
 * @typedef {'pending'|'running'|'completed'|'failed'|'blocked'|'skipped'} StageStatus
 * @typedef {object} StageState
 * @property {string} stage
 * @property {string} [name]
 * @property {StageStatus} status
 */

export const SCAN_STATUSES = ['queued', 'running', 'completed', 'failed', 'cancelled']

export const STAGE_LABELS = {
  scope_validation: 'Scope',
  asset_discovery: 'Asset Discovery',
  live_discovery: 'Live Discovery',
  port_service: 'Port/Service Discovery',
  fingerprinting: 'Technology Fingerprinting',
  endpoint_discovery: 'Endpoint Discovery',
  screenshot_capture: 'Screenshots',
  vulnerability_verification: 'Nuclei Verification',
  security_enrichment: 'NVD/KEV Enrichment',
  ai_analysis: 'AI Analysis',
  ai_validation: 'AI Validation',
  report_generation: 'Report',
}

export const STAGE_ORDER = Object.keys(STAGE_LABELS)

export const TERMINAL_SCAN_STATUSES = ['completed', 'failed', 'cancelled']
