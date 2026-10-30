import React from 'react'
import { Link, useLocation } from 'react-router-dom'
import { 
  Shield, 
  Settings, 
  Search, 
  Bell, 
  Globe, 
  Activity, 
  LayoutList, 
  Code, 
  FileText,
  ChevronDown,
  Lock,
  Radio,
  Sparkles,
  History
} from 'lucide-react'

interface AssessmentLayoutProps {
  children: React.ReactNode
  currentStepTitle?: string
}

export const AssessmentLayout: React.FC<AssessmentLayoutProps> = ({ children, currentStepTitle }) => {
  const location = useLocation()

  const steps = [
    { number: 1, title: 'Assessment Type', path: '/assessment/step-1', icon: Settings },
    { number: 2, title: 'Target URL', path: '/assessment/step-2', icon: Globe },
    { number: 3, title: 'Authorization & Scope', path: '/assessment/step-3', icon: Lock },
    { number: 4, title: 'Assessment in Progress', path: '/assessment/step-4', icon: Activity },
    { number: 5, title: 'Findings Dashboard', path: '/assessment/step-5', icon: LayoutList },
    { number: 6, title: 'Finding Details', path: '/assessment/step-6', icon: Code },
    { number: 7, title: 'Assessment Report', path: '/assessment/step-7', icon: FileText },
  ]

  return (
    <div className="flex h-screen bg-slate-50 text-slate-900 overflow-hidden font-sans">
      {/* Sidebar matching Figma */}
      <aside className="w-64 bg-white border-r border-slate-200 flex flex-col shrink-0">
        {/* Logo */}
        <div className="h-16 flex items-center px-6 border-b border-slate-100">
          <Link to="/" className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-blue-600 flex items-center justify-center text-white shadow-sm">
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-1 font-bold text-slate-900 text-base leading-tight">
                <span>Sential</span>
                <span className="text-[10px] font-semibold bg-blue-100 text-blue-700 px-1 py-0.2 rounded">AI</span>
              </div>
              <p className="text-[9px] tracking-wider font-semibold text-slate-400 uppercase">Autonomous Security</p>
            </div>
          </Link>
        </div>

        {/* Assessment Flow Steps Navigation */}
        <div className="flex-1 py-5 px-3 overflow-y-auto space-y-6">
          <div>
            <div className="flex items-center justify-between px-3 mb-2">
              <p className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                Assessment Flow
              </p>
              <span className="text-[10px] text-blue-600 font-semibold bg-blue-50 px-2 py-0.5 rounded-full">
                Sequential
              </span>
            </div>
            <nav className="space-y-1">
              {steps.map((step) => {
                const isActive = location.pathname.startsWith(step.path) || 
                  (step.number === 1 && location.pathname === '/assessment') ||
                  (step.number === 5 && location.pathname === '/findings') ||
                  (step.number === 7 && location.pathname === '/reports')

                const Icon = step.icon

                return (
                  <Link
                    key={step.number}
                    to={step.path}
                    className={`flex items-center justify-between px-3 py-2.5 rounded-xl text-sm font-medium transition-all ${
                      isActive 
                        ? 'bg-blue-50 text-blue-700 font-semibold shadow-xs' 
                        : 'text-slate-600 hover:bg-slate-100/70 hover:text-slate-900'
                    }`}
                  >
                    <div className="flex items-center gap-3 min-w-0">
                      <div className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 ${
                        isActive ? 'bg-blue-600 text-white' : 'bg-slate-100 text-slate-500'
                      }`}>
                        <Icon className="w-3.5 h-3.5" />
                      </div>
                      <div className="truncate">
                        <span className="block truncate text-[13px] leading-tight">{step.title}</span>
                        <span className="block text-[11px] text-slate-400 font-normal leading-tight">Step {step.number}</span>
                      </div>
                    </div>
                    {isActive ? (
                      <span className="w-1.5 h-1.5 rounded-full bg-blue-600 shrink-0"></span>
                    ) : (
                      <span className="text-[10px] text-slate-400 font-mono">#{step.number}</span>
                    )}
                  </Link>
                )
              })}
            </nav>
          </div>

          {/* Autonomous AI Innovation Suite */}
          <div className="pt-2 border-t border-slate-100">
            <div className="flex items-center justify-between px-3 mb-2">
              <p className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                Autonomous AI Suite
              </p>
              <span className="text-[9px] text-purple-700 font-bold bg-purple-50 px-1.5 py-0.5 rounded-full border border-purple-200">
                INNOVATIONS
              </span>
            </div>

            <nav className="space-y-1">
              <Link
                to="/monitoring"
                className={`flex items-center justify-between px-3 py-2 rounded-xl text-xs font-medium transition-all ${
                  location.pathname === '/monitoring'
                    ? 'bg-indigo-50 text-indigo-700 font-bold'
                    : 'text-slate-600 hover:bg-slate-100/70 hover:text-slate-900'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <div className={`w-6 h-6 rounded-lg flex items-center justify-center ${
                    location.pathname === '/monitoring' ? 'bg-indigo-600 text-white' : 'bg-slate-100 text-slate-500'
                  }`}>
                    <Radio className="w-3.5 h-3.5" />
                  </div>
                  <span>24/7 Monitoring</span>
                </div>
                <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
              </Link>

              <Link
                to="/intent-compiler"
                className={`flex items-center justify-between px-3 py-2 rounded-xl text-xs font-medium transition-all ${
                  location.pathname === '/intent-compiler'
                    ? 'bg-purple-50 text-purple-700 font-bold'
                    : 'text-slate-600 hover:bg-slate-100/70 hover:text-slate-900'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <div className={`w-6 h-6 rounded-lg flex items-center justify-center ${
                    location.pathname === '/intent-compiler' ? 'bg-purple-600 text-white' : 'bg-slate-100 text-slate-500'
                  }`}>
                    <Sparkles className="w-3.5 h-3.5" />
                  </div>
                  <span>Intent Compiler</span>
                </div>
                <span className="text-[9px] font-bold bg-purple-100 text-purple-700 px-1.5 py-0.5 rounded">DSL</span>
              </Link>

              <Link
                to="/evolution"
                className={`flex items-center justify-between px-3 py-2 rounded-xl text-xs font-medium transition-all ${
                  location.pathname === '/evolution'
                    ? 'bg-blue-50 text-blue-700 font-bold'
                    : 'text-slate-600 hover:bg-slate-100/70 hover:text-slate-900'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <div className={`w-6 h-6 rounded-lg flex items-center justify-center ${
                    location.pathname === '/evolution' ? 'bg-blue-600 text-white' : 'bg-slate-100 text-slate-500'
                  }`}>
                    <History className="w-3.5 h-3.5" />
                  </div>
                  <span>Regression Memory</span>
                </div>
              </Link>

              <Link
                to="/alerts"
                className={`flex items-center justify-between px-3 py-2 rounded-xl text-xs font-medium transition-all ${
                  location.pathname === '/alerts'
                    ? 'bg-rose-50 text-rose-700 font-bold'
                    : 'text-slate-600 hover:bg-slate-100/70 hover:text-slate-900'
                }`}
              >
                <div className="flex items-center gap-2.5">
                  <div className={`w-6 h-6 rounded-lg flex items-center justify-center ${
                    location.pathname === '/alerts' ? 'bg-rose-600 text-white' : 'bg-slate-100 text-slate-500'
                  }`}>
                    <Bell className="w-3.5 h-3.5" />
                  </div>
                  <span>Omnichannel Alerts</span>
                </div>
              </Link>
            </nav>
          </div>
        </div>

        {/* Sidebar Footer */}
        <div className="p-3 border-t border-slate-100 space-y-2">
          <Link 
            to="/settings"
            className="flex items-center gap-3 px-3 py-2 text-sm text-slate-600 hover:bg-slate-100 rounded-lg transition-colors"
          >
            <Settings className="w-4 h-4 text-slate-400" />
            <span className="text-[13px] font-medium">Settings</span>
          </Link>

          <div className="flex items-center justify-between p-2 rounded-xl bg-slate-50 border border-slate-200/60">
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-full bg-blue-600 text-white font-bold text-xs flex items-center justify-center">
                BO
              </div>
              <div>
                <p className="text-xs font-bold text-slate-900 leading-tight">Belal Omar</p>
                <p className="text-[11px] text-slate-400 leading-tight">belal@cyberai.io</p>
              </div>
            </div>
            <ChevronDown className="w-4 h-4 text-slate-400" />
          </div>
        </div>
      </aside>

      {/* Main Container */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top Header */}
        <header className="h-16 bg-white border-b border-slate-200 px-8 flex items-center justify-between shrink-0">
          {/* Breadcrumb */}
          <div className="flex items-center gap-2 text-xs font-medium text-slate-500">
            <span className="text-slate-700">Northstar Workspace</span>
            <span>›</span>
            <span className="text-slate-900 font-semibold">{currentStepTitle || 'Assessment Type'}</span>
          </div>

          {/* Top Actions */}
          <div className="flex items-center gap-3">
            <span className="text-[11px] font-bold bg-blue-50 text-blue-700 border border-blue-200 px-2.5 py-1 rounded-md tracking-wider">
              PRO PLAN
            </span>
            <button className="w-8 h-8 rounded-lg border border-slate-200 flex items-center justify-center text-slate-500 hover:bg-slate-50">
              <Search className="w-4 h-4" />
            </button>
            <button className="w-8 h-8 rounded-lg border border-slate-200 flex items-center justify-center text-slate-500 hover:bg-slate-50 relative">
              <Bell className="w-4 h-4" />
              <span className="absolute top-1.5 right-1.5 w-1.5 h-1.5 rounded-full bg-red-500"></span>
            </button>
          </div>
        </header>

        {/* Content Area */}
        <main className="flex-1 overflow-y-auto p-8 lg:p-10 max-w-6xl mx-auto w-full">
          {children}
        </main>
      </div>
    </div>
  )
}
