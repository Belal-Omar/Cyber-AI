import React from 'react'
import { Link } from 'react-router-dom'
import { Shield, Sparkles, Globe, Play, ChevronRight, Check } from 'lucide-react'

export const LandingPage: React.FC = () => {
  const token = localStorage.getItem('sential_token')
  const userRaw = localStorage.getItem('sential_user')
  const user = userRaw ? JSON.parse(userRaw) : null
  const isAuthenticated = !!token

  const scanTargetPath = isAuthenticated ? '/assessment/step-1' : '/login'
  const dashboardTargetPath = isAuthenticated ? '/assessment/step-5' : '/login'

  const handleLogout = () => {
    localStorage.removeItem('sential_token')
    localStorage.removeItem('sential_user')
    window.location.reload()
  }

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col selection:bg-blue-500 selection:text-white">
      {/* Navigation Bar */}
      <header className="w-full bg-white/80 backdrop-blur-md border-b border-slate-200/80 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 h-18 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-3 group">
            <div className="w-10 h-10 rounded-xl bg-blue-600 flex items-center justify-center text-white shadow-md shadow-blue-500/20 group-hover:bg-blue-700 transition-colors">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-1.5 font-bold text-slate-900 text-lg tracking-tight">
                <span>Sential</span>
                <span className="text-[11px] font-semibold bg-blue-100 text-blue-700 px-1.5 py-0.5 rounded tracking-normal">AI</span>
              </div>
              <p className="text-[10px] tracking-wider font-semibold text-slate-400 uppercase">Autonomous Security</p>
            </div>
          </Link>

          <nav className="hidden md:flex items-center gap-8 text-sm font-medium text-slate-600">
            <a href="#features" className="hover:text-blue-600 transition-colors">Features</a>
            <a href="#how-it-works" className="hover:text-blue-600 transition-colors">How it works</a>
            <Link to={scanTargetPath} className="hover:text-blue-600 transition-colors">Assessment Flow</Link>
          </nav>

          <div className="flex items-center gap-4">
            {isAuthenticated ? (
              <div className="flex items-center gap-3">
                <span className="hidden sm:inline-block text-xs font-semibold text-slate-600 bg-slate-100 px-2.5 py-1 rounded-lg font-mono">
                  {user?.email || 'Authenticated'}
                </span>
                <Link 
                  to="/assessment/step-1" 
                  className="text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 px-3.5 py-2 rounded-lg shadow-sm shadow-blue-500/20 transition-all cursor-pointer"
                >
                  Workspace
                </Link>
                <button
                  type="button"
                  onClick={handleLogout}
                  className="text-xs font-semibold text-slate-500 hover:text-rose-600 px-2 py-1 transition-colors cursor-pointer"
                >
                  Log out
                </button>
              </div>
            ) : (
              <>
                <Link to="/login" className="text-sm font-semibold text-slate-700 hover:text-blue-600 px-3 py-2 transition-colors">
                  Log in
                </Link>
                <Link 
                  to="/login" 
                  className="text-sm font-semibold text-white bg-blue-600 hover:bg-blue-700 px-5 py-2.5 rounded-lg shadow-sm shadow-blue-500/20 transition-all hover:shadow-md hover:shadow-blue-500/30 active:scale-95"
                >
                  Start free
                </Link>
              </>
            )}
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <main className="flex-1 radar-grid relative overflow-hidden">
        <div className="max-w-7xl mx-auto px-6 pt-16 pb-24 lg:pt-24 lg:pb-32 grid grid-cols-1 lg:grid-cols-12 gap-12 items-center">
          
          {/* Left Column */}
          <div className="lg:col-span-6 space-y-8 z-10">
            <div className="inline-flex items-center gap-2 bg-blue-50/80 border border-blue-200/60 text-blue-700 px-3.5 py-1.5 rounded-full text-xs font-semibold">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
              AI-powered web security
            </div>

            <h1 className="text-5xl lg:text-6xl font-extrabold text-slate-950 tracking-tight leading-[1.12]">
              Find vulnerabilities.<br />
              <span className="text-blue-600">Fix them faster.</span>
            </h1>

            <p className="text-lg text-slate-600 leading-relaxed max-w-xl">
              Run comprehensive security assessments, prioritize what matters, and ship AI-guided fixes with confidence.
            </p>

            <div className="flex flex-wrap items-center gap-4 pt-2">
              <Link 
                to={scanTargetPath} 
                className="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold px-6 py-3.5 rounded-xl shadow-lg shadow-blue-600/25 transition-all hover:shadow-blue-600/35 hover:-translate-y-0.5 active:translate-y-0 text-sm"
              >
                <span>Start your first scan</span>
                <ChevronRight className="w-4 h-4" />
              </Link>
              <Link 
                to={dashboardTargetPath} 
                className="inline-flex items-center gap-2.5 bg-white hover:bg-slate-50 text-slate-700 font-semibold px-6 py-3.5 rounded-xl border border-slate-300/80 shadow-sm transition-all hover:border-slate-400 text-sm"
              >
                <Play className="w-3.5 h-3.5 fill-slate-700 text-slate-700" />
                <span>View dashboard</span>
              </Link>
            </div>

            <div className="flex items-center gap-6 pt-4 text-xs font-medium text-slate-500">
              <span className="flex items-center gap-1.5">
                <Check className="w-4 h-4 text-emerald-600 stroke-[2.5]" /> No credit card
              </span>
              <span className="flex items-center gap-1.5">
                <Check className="w-4 h-4 text-emerald-600 stroke-[2.5]" /> First scan in minutes
              </span>
            </div>
          </div>

          {/* Right Column: Visual Live Assessment Card Mockup */}
          <div className="lg:col-span-6 relative flex justify-center lg:justify-end">
            
            {/* Floating pill: AI remediation ready */}
            <div className="absolute -top-6 left-4 md:left-12 z-20 bg-white/95 backdrop-blur-md border border-slate-200/80 rounded-2xl p-4 shadow-xl shadow-slate-200/60 flex items-center gap-3 max-w-xs animate-bounce" style={{ animationDuration: '6s' }}>
              <div className="w-10 h-10 rounded-xl bg-emerald-50 border border-emerald-100 flex items-center justify-center text-emerald-600 shrink-0">
                <Sparkles className="w-5 h-5" />
              </div>
              <div>
                <p className="text-xs font-bold text-slate-900">AI remediation ready</p>
                <p className="text-[11px] text-slate-500">Safe patch generated</p>
              </div>
              <Check className="w-4 h-4 text-emerald-600 ml-auto" />
            </div>

            {/* Main Assessment Preview Card */}
            <div className="w-full max-w-md bg-white border border-slate-200/80 rounded-3xl p-6 sm:p-8 shadow-2xl shadow-blue-900/10 relative z-10">
              {/* Header */}
              <div className="flex items-center justify-between pb-6 border-b border-slate-100">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-blue-50 border border-blue-100 flex items-center justify-center text-blue-600">
                    <Globe className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="font-bold text-slate-900 text-sm">acme.com</h3>
                    <p className="text-xs text-slate-400">Live assessment</p>
                  </div>
                </div>
                <div className="flex items-center gap-1.5 bg-blue-50 text-blue-700 border border-blue-100 px-2.5 py-1 rounded-full text-xs font-semibold">
                  <span className="w-1.5 h-1.5 rounded-full bg-blue-600 animate-ping"></span>
                  Scanning
                </div>
              </div>

              {/* Score Circular Gauge & Progress Bars */}
              <div className="py-6 flex flex-col sm:flex-row items-center gap-6">
                {/* Donut Gauge */}
                <div className="relative w-32 h-32 flex items-center justify-center shrink-0">
                  <svg className="w-full h-full -rotate-90" viewBox="0 0 100 100">
                    <circle cx="50" cy="50" r="40" stroke="#f1f5f9" strokeWidth="10" fill="transparent" />
                    <circle 
                      cx="50" 
                      cy="50" 
                      r="40" 
                      stroke="#2563eb" 
                      strokeWidth="10" 
                      strokeDasharray="251.2" 
                      strokeDashoffset="40" 
                      strokeLinecap="round" 
                      fill="transparent" 
                    />
                  </svg>
                  <div className="absolute text-center">
                    <span className="text-3xl font-extrabold text-slate-900 tracking-tight">84</span>
                    <span className="block text-[10px] font-medium text-slate-400">Security score</span>
                  </div>
                </div>

                {/* Progress bars */}
                <div className="flex-1 w-full space-y-3.5">
                  <div>
                    <div className="flex justify-between text-xs font-medium mb-1">
                      <span className="text-slate-600">Endpoints mapped</span>
                      <span className="text-slate-900 font-bold">142</span>
                    </div>
                    <div className="w-full bg-slate-100 rounded-full h-2">
                      <div className="bg-blue-600 h-2 rounded-full" style={{ width: '92%' }}></div>
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between text-xs font-medium mb-1">
                      <span className="text-slate-600">Tests completed</span>
                      <span className="text-slate-900 font-bold">83%</span>
                    </div>
                    <div className="w-full bg-slate-100 rounded-full h-2">
                      <div className="bg-cyan-500 h-2 rounded-full" style={{ width: '83%' }}></div>
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between text-xs font-medium mb-1">
                      <span className="text-slate-600">Findings analyzed</span>
                      <span className="text-slate-900 font-bold">18</span>
                    </div>
                    <div className="w-full bg-slate-100 rounded-full h-2">
                      <div className="bg-purple-500 h-2 rounded-full" style={{ width: '60%' }}></div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Floating Bottom Alert Pill */}
              <Link 
                to={isAuthenticated ? "/assessment/step-6" : "/login"}
                className="mt-2 block bg-slate-50 hover:bg-slate-100/80 border border-slate-200/80 rounded-xl p-3 transition-colors group cursor-pointer"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2.5">
                    <span className="w-2.5 h-2.5 rounded-full bg-red-500 shrink-0"></span>
                    <div>
                      <p className="text-xs font-bold text-slate-900">Critical finding</p>
                      <p className="text-[11px] text-slate-500 font-mono">SQL Injection · /api/users</p>
                    </div>
                  </div>
                  <ChevronRight className="w-4 h-4 text-slate-400 group-hover:text-blue-600 group-hover:translate-x-0.5 transition-all" />
                </div>
              </Link>
            </div>
          </div>
        </div>

        {/* Trusted By Section */}
        <div className="border-t border-slate-200/60 bg-white/50 backdrop-blur-sm py-10">
          <div className="max-w-7xl mx-auto px-6">
            <p className="text-xs font-bold uppercase tracking-wider text-slate-400 text-center md:text-left mb-6">
              Trusted by security teams at
            </p>
            <div className="flex flex-wrap items-center justify-between gap-8 opacity-75 grayscale hover:grayscale-0 transition-all font-bold text-slate-700 text-lg">
              <span>Northstar</span>
              <span>Vertex</span>
              <span>Cloudline</span>
              <span>HALO</span>
              <span>ShieldCorp</span>
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}
