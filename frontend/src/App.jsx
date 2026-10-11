import { Navigate, Route, Routes } from 'react-router-dom'
import Layout from './components/layout/Layout.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Findings from './pages/Findings.jsx'
import Report from './pages/Report.jsx'
import ScanDetails from './pages/ScanDetails.jsx'
import Scans from './pages/Scans.jsx'
import Settings from './pages/Settings.jsx'

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/scans" element={<Scans />} />
        <Route path="/scans/:scanId" element={<ScanDetails />} />
        <Route path="/scans/:scanId/findings" element={<Findings />} />
        <Route path="/scans/:scanId/report" element={<Report />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Route>
    </Routes>
  )
}
