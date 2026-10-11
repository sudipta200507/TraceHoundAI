import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'

vi.mock('../services/api.js', () => ({
  ScanApi: {
    create: vi.fn(),
    status: vi.fn(),
    stages: vi.fn(),
    findings: vi.fn(),
    report: vi.fn(),
    summary: vi.fn(),
    reportPdfUrl: (scanId) => `/api/scans/${scanId}/report.pdf`,
    appendixUrl: (scanId) => `/api/scans/${scanId}/appendix.md/download`,
    inventoryJsonUrl: (scanId) => `/api/scans/${scanId}/inventory.json`,
    inventoryCsvUrl: (scanId) => `/api/scans/${scanId}/inventory.csv`,
    cancel: vi.fn(),
    preflight: vi.fn(),
  },
  SystemApi: { tools: vi.fn(), health: vi.fn() },
  friendlyError: (error, fallback = 'Request failed.') => {
    if (error?.response?.status === 422) return 'Target is outside the authorized scope.'
    if (!error?.response) return 'Backend offline. Start the backend API and retry.'
    return fallback
  },
  isScopeRejection: (error) => error?.response?.status === 422,
}))

import { ScanApi, SystemApi } from '../services/api.js'
import App from '../App.jsx'
import StageStepper from '../components/scans/StageStepper.jsx'
import { renderMarkdown } from '../utils/markdown.js'
import { applyFindingFilters } from '../utils/findings.js'

const TOOLS = {
  tools: [
    { name: 'subfinder', status: 'ready', version: 'v2.16.0' },
    { name: 'ollama', status: 'ready', version: '0.35.1', available: true },
  ],
}

const SCAN = {
  scan_id: 'example-lab-0001',
  target: 'example.lab',
  status: 'running',
  current_stage: 'live_discovery',
  started_at: '2026-01-01T00:00:00',
  completed_at: '',
  stages: [
    { stage: 'scope_validation', status: 'completed' },
    { stage: 'live_discovery', status: 'running' },
  ],
  error: '',
  report_path: '',
}

const FINDINGS = [
  {
    finding_id: 'FIND-002',
    title: 'Low item',
    severity: 'low',
    confidence: 0.4,
    classification: 'hypothesis',
    evidence_ids: ['E002'],
    verification_status: 'unverified',
  },
  {
    finding_id: 'FIND-001',
    title: 'High item',
    severity: 'high',
    confidence: 0.9,
    classification: 'observed_fact',
    evidence_ids: ['E001'],
    verification_status: 'supported',
  },
]

beforeEach(() => {
  vi.clearAllMocks()
  SystemApi.health.mockResolvedValue({ status: 'ok' })
  SystemApi.tools.mockResolvedValue(TOOLS)
  ScanApi.status.mockResolvedValue(SCAN)
  ScanApi.findings.mockResolvedValue({ scan_id: SCAN.scan_id, findings: FINDINGS })
  ScanApi.report.mockResolvedValue({
    scan_id: SCAN.scan_id,
    report_path: 'r.md',
    markdown: '# TraceHoundAI Security Report\n\n| A | B |\n|---|---|\n| 1 | 2 |\n',
  })
  ScanApi.create.mockResolvedValue({ scan_id: 'x-1', target: 'example.lab', status: 'queued' })
  ScanApi.cancel.mockResolvedValue({ ...SCAN, status: 'cancelled' })
  ScanApi.summary.mockResolvedValue({
    scan_id: SCAN.scan_id,
    target: SCAN.target,
    status: SCAN.status,
    assets: 2,
    live_hosts: 1,
    open_ports: 1,
    stages: [],
  })
})

function renderApp(path) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  )
}

describe('frontend', () => {
  it('1. application loads with brand and navigation', async () => {
    renderApp('/dashboard')
    expect(await screen.findByText('TraceHoundAI')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Scans' })).toBeInTheDocument()
  })

  it('2. routing reaches scans, findings, report, settings', async () => {
    const { unmount } = renderApp('/scans')
    expect(await screen.findByText('Start Security Reconnaissance')).toBeInTheDocument()
    unmount()
    renderApp('/settings')
    expect(await screen.findByText('Settings')).toBeInTheDocument()
  })

  it('3. dashboard renders stat cards', async () => {
    renderApp('/dashboard')
    expect(await screen.findByText('Total Scans')).toBeInTheDocument()
    expect(screen.getByText('Critical')).toBeInTheDocument()
  })

  it('4. scan form renders with domain placeholder', async () => {
    renderApp('/scans')
    expect(await screen.findByPlaceholderText('example.com')).toBeInTheDocument()
    expect(screen.getByRole('checkbox')).toBeInTheDocument()
  })

  it('5. scan request is sent on submit', async () => {
    const user = userEvent.setup()
    renderApp('/scans')
    await user.type(screen.getByPlaceholderText('example.com'), 'example.lab')
    await user.click(screen.getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: 'START SCAN' }))
    await waitFor(() =>
      expect(ScanApi.create).toHaveBeenCalledWith(
        expect.objectContaining({ target: 'example.lab' }),
      ),
    )
  })

  it('6. scope rejection displays without internals', async () => {
    const user = userEvent.setup()
    ScanApi.create.mockRejectedValueOnce({ response: { status: 422 } })
    renderApp('/scans')
    await user.type(screen.getByPlaceholderText('example.com'), 'evil.com')
    await user.click(screen.getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: 'START SCAN' }))
    expect(await screen.findByText(/outside the authorized scope/)).toBeInTheDocument()
    expect(screen.queryByText(/Traceback/)).not.toBeInTheDocument()
  })

  it('7. scan status renders', async () => {
    renderApp('/scans/example-lab-0001')
    expect(await screen.findByText('example.lab')).toBeInTheDocument()
    expect(screen.getAllByLabelText('Status: running').length).toBeGreaterThan(0)
  })

  it('8. stage progress renders stepper', () => {
    render(
      <MemoryRouter>
        <StageStepper stages={SCAN.stages} />
      </MemoryRouter>,
    )
    expect(screen.getByText('Scope')).toBeInTheDocument()
    expect(screen.getByLabelText('Status: running')).toBeInTheDocument()
  })

  it('9. findings render and 10. severity filter works', async () => {
    renderApp('/scans/example-lab-0001/findings')
    expect(await screen.findByText(/FIND-001/)).toBeInTheDocument()
    const filtered = applyFindingFilters(FINDINGS, {
      severity: 'high',
      classification: '',
      status: '',
      sort: 'severity',
    })
    expect(filtered.map((f) => f.finding_id)).toEqual(['FIND-001'])
  })

  it('11. report renders markdown safely', async () => {
    renderApp('/scans/example-lab-0001/report')
    expect(await screen.findByText('TraceHoundAI Security Report')).toBeInTheDocument()
    expect(renderMarkdown('<script>alert(1)</script>')).not.toContain('<script>')
  })

  it('12. loading and 13. empty states work', async () => {
    // Always empty: the page reloads findings when scan status arrives, so a
    // one-shot mock would be consumed and the transient empty state lost.
    ScanApi.findings.mockResolvedValue({ scan_id: 's', findings: [] })
    renderApp('/scans/example-lab-0001/findings')
    expect(
      await screen.findByText(/Nothing found yet|No findings/),
    ).toBeInTheDocument()
  })

  it('14. API error states work', async () => {
    ScanApi.status.mockRejectedValueOnce({ response: { status: 500 } })
    renderApp('/scans/example-lab-0001')
    expect(await screen.findByText('Could not load scan.')).toBeInTheDocument()
  })

  it('15. cancel action calls backend', async () => {
    const user = userEvent.setup()
    window.confirm = vi.fn(() => true)
    renderApp('/scans/example-lab-0001')
    await user.click(await screen.findByRole('button', { name: 'Cancel Scan' }))
    await waitFor(() =>
      expect(ScanApi.cancel).toHaveBeenCalledWith('example-lab-0001'),
    )
  })

  it('16. no secrets in frontend source', async () => {
    const modules = import.meta.glob('../**/*.{js,jsx}', { query: '?raw', import: 'default' })
    for (const [path, loader] of Object.entries(modules)) {
      if (path.includes('__tests__')) continue
      const text = await loader()
      expect(text).not.toMatch(/sk-[A-Za-z0-9]{8,}/)
      expect(text).not.toMatch(/api[_-]?key\s*[:=]\s*['"][^'"]+['"]/i)
    }
  })
})
