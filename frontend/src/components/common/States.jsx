export function Loading({ message = 'Loading…' }) {
  return (
    <div className="state" role="status" aria-live="polite">
      {message}
    </div>
  )
}

export function EmptyState({ message }) {
  return (
    <div className="state" role="status">
      {message}
    </div>
  )
}

export function ErrorAlert({ message, onRetry }) {
  if (!message) return null
  return (
    <div className="alert-error" role="alert">
      <span>{message}</span>
      {onRetry ? (
        <button type="button" onClick={onRetry}>
          Retry
        </button>
      ) : null}
    </div>
  )
}
