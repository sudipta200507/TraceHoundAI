import { useEffect, useRef } from 'react'

/** Poll `callback` every `intervalMs` while `active`; always cleans up. */
export function usePolling(callback, intervalMs, active) {
  const saved = useRef(callback)
  useEffect(() => {
    saved.current = callback
  })
  useEffect(() => {
    if (!active) return undefined
    const id = setInterval(() => saved.current(), intervalMs)
    return () => clearInterval(id)
  }, [intervalMs, active])
}
