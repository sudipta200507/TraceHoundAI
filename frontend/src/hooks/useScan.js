import { useCallback, useEffect, useState } from 'react'
import { ScanApi, friendlyError } from '../services/api.js'
import { TERMINAL_SCAN_STATUSES } from '../types/scan.js'
import { usePolling } from './usePolling.js'

const POLL_INTERVAL_MS = 2500

/** Load a scan and poll until it reaches a terminal status. */
export function useScan(scanId) {
  const [scan, setScan] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const refresh = useCallback(async () => {
    if (!scanId) return
    try {
      const data = await ScanApi.status(scanId)
      setScan(data)
      setError('')
    } catch (err) {
      setError(friendlyError(err, 'Could not load scan.'))
    } finally {
      setLoading(false)
    }
  }, [scanId])

  useEffect(() => {
    let cancelled = false
    async function load() {
      if (!scanId) {
        setLoading(false)
        return
      }
      try {
        const data = await ScanApi.status(scanId)
        if (!cancelled) {
          setScan(data)
          setError('')
        }
      } catch (err) {
        if (!cancelled) setError(friendlyError(err, 'Could not load scan.'))
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    return () => {
      cancelled = true
    }
  }, [scanId])

  const active =
    !!scan && !TERMINAL_SCAN_STATUSES.includes(scan.status) && !error
  usePolling(refresh, POLL_INTERVAL_MS, active)

  return { scan, loading, error, refresh }
}

/** Track scan IDs created in this browser session (backend has no list API). */
const SESSION_KEY = 'tracehound.scanIds'

export function sessionScanIds() {
  try {
    return JSON.parse(sessionStorage.getItem(SESSION_KEY) || '[]')
  } catch {
    return []
  }
}

export function rememberScanId(scanId) {
  const ids = sessionScanIds()
  if (!ids.includes(scanId)) {
    sessionStorage.setItem(SESSION_KEY, JSON.stringify([scanId, ...ids].slice(0, 50)))
  }
}
