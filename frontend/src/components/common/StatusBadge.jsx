const TONE = {
  queued: 'muted',
  pending: 'muted',
  running: 'info',
  completed: 'ok',
  ready: 'ok',
  failed: 'bad',
  missing: 'bad',
  error: 'bad',
  cancelled: 'warn',
  blocked: 'warn',
  skipped: 'muted',
  disabled: 'muted',
  critical: 'bad',
  high: 'warn',
  medium: 'info',
  low: 'muted',
  informational: 'muted',
  info: 'muted',
}

/** Text-plus-color badge; severity/status never relies on color alone. */
export default function StatusBadge({ value }) {
  const tone = TONE[String(value || '').toLowerCase()] || 'muted'
  return (
    <span className={`badge tone-${tone}`} aria-label={`Status: ${value}`}>
      {value}
    </span>
  )
}
