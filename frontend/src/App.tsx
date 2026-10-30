import { Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { LandingPage } from './pages/LandingPage'
import { Login } from './pages/Login'
import { Step1AssessmentType } from './pages/flow/Step1AssessmentType'
import { Step2TargetUrl } from './pages/flow/Step2TargetUrl'
import { Step3AuthorizationScope } from './pages/flow/Step3AuthorizationScope'
import { Step4AssessmentProgress } from './pages/flow/Step4AssessmentProgress'
import { Step5FindingsDashboard } from './pages/flow/Step5FindingsDashboard'
import { Step6FindingDetails } from './pages/flow/Step6FindingDetails'
import { Step7AssessmentReport } from './pages/flow/Step7AssessmentReport'
import { Settings } from './pages/Settings'
import { AdminDashboard } from './pages/AdminDashboard'
import { MonitoringPage } from './pages/MonitoringPage'
import { IntentCompilerPage } from './pages/IntentCompilerPage'
import { EvolutionPage } from './pages/EvolutionPage'
import { AlertsPage } from './pages/AlertsPage'
import './index.css'

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const token = localStorage.getItem('sential_token')
  const location = useLocation()
  if (!token) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }
  return <>{children}</>
}

function App() {
  return (
    <div className="h-full w-full min-h-screen bg-slate-50">
      <Routes>
        {/* Landing Page */}
        <Route path="/" element={<LandingPage />} />
        
        {/* Authentication */}
        <Route path="/login" element={<Login />} />

        {/* 7-Step Sential AI Assessment Flow (Protected) */}
        <Route path="/assessment" element={<ProtectedRoute><Navigate to="/assessment/step-1" replace /></ProtectedRoute>} />
        <Route path="/assessment/step-1" element={<ProtectedRoute><Step1AssessmentType /></ProtectedRoute>} />
        <Route path="/assessment/step-2" element={<ProtectedRoute><Step2TargetUrl /></ProtectedRoute>} />
        <Route path="/assessment/step-3" element={<ProtectedRoute><Step3AuthorizationScope /></ProtectedRoute>} />
        <Route path="/assessment/step-4" element={<ProtectedRoute><Step4AssessmentProgress /></ProtectedRoute>} />
        <Route path="/assessment/step-5" element={<ProtectedRoute><Step5FindingsDashboard /></ProtectedRoute>} />
        <Route path="/assessment/step-6" element={<ProtectedRoute><Step6FindingDetails /></ProtectedRoute>} />
        <Route path="/assessment/step-7" element={<ProtectedRoute><Step7AssessmentReport /></ProtectedRoute>} />

        {/* Quick Direct Aliases (Protected) */}
        <Route path="/findings" element={<ProtectedRoute><Step5FindingsDashboard /></ProtectedRoute>} />
        <Route path="/findings/:id" element={<ProtectedRoute><Step6FindingDetails /></ProtectedRoute>} />
        <Route path="/reports" element={<ProtectedRoute><Step7AssessmentReport /></ProtectedRoute>} />
        <Route path="/settings" element={<ProtectedRoute><Settings /></ProtectedRoute>} />

        {/* Autonomous AI Suite Innovations */}
        <Route path="/monitoring" element={<ProtectedRoute><MonitoringPage /></ProtectedRoute>} />
        <Route path="/intent-compiler" element={<ProtectedRoute><IntentCompilerPage /></ProtectedRoute>} />
        <Route path="/evolution" element={<ProtectedRoute><EvolutionPage /></ProtectedRoute>} />
        <Route path="/alerts" element={<ProtectedRoute><AlertsPage /></ProtectedRoute>} />

        {/* Secret Protected Admin Portal */}
        <Route path="/admin/portal" element={<ProtectedRoute><AdminDashboard /></ProtectedRoute>} />
        <Route path="/admin/dashboard" element={<Navigate to="/admin/portal" replace />} />
        <Route path="/admin" element={<Navigate to="/admin/portal" replace />} />

        {/* Catch-all redirect */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </div>
  )
}

export default App
