import axios from 'axios'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '',
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
})

export const ScanApi = {
  create: (payload) => api.post('/api/scans', payload).then((r) => r.data),
  status: (scanId) => api.get(`/api/scans/${scanId}`).then((r) => r.data),
  stages: (scanId) => api.get(`/api/scans/${scanId}/stages`).then((r) => r.data),
  findings: (scanId) => api.get(`/api/scans/${scanId}/findings`).then((r) => r.data),
  report: (scanId) => api.get(`/api/scans/${scanId}/report`).then((r) => r.data),
  summary: (scanId) => api.get(`/api/scans/${scanId}/summary`).then((r) => r.data),
  reportPdfUrl: (scanId) => `/api/scans/${scanId}/report.pdf`,
  appendixUrl: (scanId) => `/api/scans/${scanId}/appendix.md/download`,
  inventoryJsonUrl: (scanId) => `/api/scans/${scanId}/inventory.json`,
  inventoryCsvUrl: (scanId) => `/api/scans/${scanId}/inventory.csv`,
  cancel: (scanId) => api.post(`/api/scans/${scanId}/cancel`).then((r) => r.data),
  resume: (scanId) => api.post(`/api/scans/${scanId}/resume`).then((r) => r.data),
  preflight: (target) =>
    api.post('/api/scans/preflight', { target }).then((r) => r.data),
}

export const SystemApi = {
  tools: () => api.get('/api/system/tools').then((r) => r.data),
  health: () => api.get('/health').then((r) => r.data),
}

const SCOPE_MESSAGE = 'Target is outside the authorized scope.'

/** Human-readable backend error; never leaks tracebacks, paths, or secrets. */
export function friendlyError(error, fallback = 'Request failed.') {
  const status = error?.response?.status
  const detail = error?.response?.data?.detail
  const clean = typeof detail === 'string' && detail.length < 300 ? detail : ''
  if (status === 422) return `${SCOPE_MESSAGE}${clean ? ` ${clean}` : ''}`
  if (status === 404) return 'Not found.'
  if (status === 409) return clean || 'Conflict: resource unavailable.'
  if (status === 500) return 'Backend error. Check the backend logs.'
  if (error?.code === 'ECONNABORTED' || /timeout/i.test(error?.message || '')) {
    return 'Network timeout. Is the backend running?'
  }
  if (!error?.response) return 'Backend offline. Start the backend API and retry.'
  return clean || fallback
}

export function isScopeRejection(error) {
  return error?.response?.status === 422
}

export default api
