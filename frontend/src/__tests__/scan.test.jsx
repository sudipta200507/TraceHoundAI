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
    return fallback
  },
  isScopeRejection: (error) => error?.response?.status === 422,
}))

const mockNavigate = vi.fn()
vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal()
  return { ...actual, useNavigate: () => mockNavigate }
})

import { ScanApi } from '../services/api.js'
import NewScanForm from '../components/scans/NewScanForm.jsx'

function renderForm() {
  return render(
    <MemoryRouter>
      <NewScanForm />
    </MemoryRouter>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  ScanApi.create.mockResolvedValue({
    scan_id: 'lab-1',
    target: 'lab-target.example',
    status: 'queued',
    root_domain: 'lab-target.example',
    scope: { allows: 'lab-target.example and *.lab-target.example' },
  })
})

describe('authorized scan UI', () => {
  it('renders one target input and the authorization checkbox', () => {
    renderForm()
    expect(screen.getByLabelText(/Target Domain/)).toBeInTheDocument()
    expect(screen.getByRole('checkbox')).toBeInTheDocument()
    expect(
      screen.getByText(/I confirm this target is authorized/),
    ).toBeInTheDocument()
  })

  it('requires confirmation before START SCAN is enabled', async () => {
    const user = userEvent.setup()
    renderForm()
    const button = screen.getByRole('button', { name: 'START SCAN' })
    expect(button).toBeDisabled()
    await user.type(screen.getByLabelText(/Target Domain/), 'lab-target.example')
    expect(button).toBeDisabled()
    await user.click(screen.getByRole('checkbox'))
    expect(button).toBeEnabled()
  })

  it('sends an authorized scan request and redirects to progress', async () => {
    const user = userEvent.setup()
    renderForm()
    await user.type(screen.getByLabelText(/Target Domain/), 'lab-target.example')
    await user.click(screen.getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: 'START SCAN' }))
    await waitFor(() =>
      expect(ScanApi.create).toHaveBeenCalledWith({
        target: 'lab-target.example',
        authorize_active: true,
        approved_by: 'scan-ui-authorized-scan',
        reason: 'user confirmed authorized laboratory assessment',
      }),
    )
    await waitFor(() => expect(mockNavigate).toHaveBeenCalledWith('/scans/lab-1'))
  })

  it('shows scope rejection without internals', async () => {
    const user = userEvent.setup()
    ScanApi.create.mockRejectedValueOnce({ response: { status: 422 } })
    renderForm()
    await user.type(screen.getByLabelText(/Target Domain/), 'evil.com')
    await user.click(screen.getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: 'START SCAN' }))
    expect(await screen.findByText(/outside the authorized scope/)).toBeInTheDocument()
    expect(screen.queryByText(/Traceback/)).not.toBeInTheDocument()
  })

  it('exposes no exploitation controls', () => {
    renderForm()
    expect(screen.queryByRole('button', { name: /exploit/i })).not.toBeInTheDocument()
    expect(screen.queryByLabelText(/exploit/i)).not.toBeInTheDocument()
    // The only mention is the never-performed disclaimer.
    expect(screen.getByText(/Exploitation is never performed/)).toBeInTheDocument()
  })
})
