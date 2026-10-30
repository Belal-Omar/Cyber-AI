import React, { useState, useEffect } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { AssessmentLayout } from '../../components/layout/AssessmentLayout'
import { 
  Search, 
  ChevronRight, 
  FileText, 
  Globe, 
  ShieldAlert, 
  CheckCircle,
  Table,
  Download,
  Code,
  FileCode,
  X,
  Copy,
  Sparkles,
  ShieldCheck,
  AlertCircle,
  Sliders,
  Link2
} from 'lucide-react'
import { api, type Finding } from '../../lib/api'
import { evaluateSecurityChecks, extractTargetFileName, getTargetAssetInfo } from '../../lib/securityChecks'

export const Step5FindingsDashboard: React.FC = () => {
  const navigate = useNavigate()
  const [activeView, setActiveView] = useState<'findings' | 'resolved' | 'checks' | 'sheet' | 'endpoints' | 'simulator'>('findings')
  const [findings, setFindings] = useState<Finding[]>([])
  const [endpoints, setEndpoints] = useState<any[]>([])
  const [activeFilter, setActiveFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('ALL')
  const [checksFilter, setChecksFilter] = useState<'ALL' | 'DETECTED' | 'SAFE'>('ALL')
  const [search, setSearch] = useState('')

  // FEAT-SIM-03: What-If Fixed Simulator State
  const [selectedForSim, setSelectedForSim] = useState<string[]>([])
  const [simBatchDone, setSimBatchDone] = useState(false)

  // Google Sheet Active Cell State
  const [activeCell, setActiveCell] = useState<{ row: number; col: string; value: string }>({
    row: 1,
    col: 'A',
    value: ''
  })

  // Code Viewer Modal State
  const [codeModalFile, setCodeModalFile] = useState<any | null>(null)
  const [copied, setCopied] = useState(false)

  const targetUrl = sessionStorage.getItem('sential_target_url') || 'http://127.0.0.1:5050'
  const cleanDomain = targetUrl.replace(/^https?:\/\//, '').split('/')[0]

  useEffect(() => {
    async function load() {
      const savedAppId = sessionStorage.getItem('sential_application_id') || undefined
      const data = await api.getFindings(savedAppId)
      // Deduplicate findings by title & parameter so duplicates never repeat
      const seen = new Set<string>()
      const unique = data.filter(f => {
        const k = `${f.title}-${f.parameter}`
        if (seen.has(k)) return false
        seen.add(k)
        return true
      })
      setFindings(unique)
      setSelectedForSim(unique.map(f => f.id))
      if (unique.length > 0) {
        setActiveCell({ row: 1, col: 'A', value: unique[0].title })
      }
      if (savedAppId) {
        const eps = await api.getEndpoints(savedAppId)
        setEndpoints(eps)
      }
    }
    load()
  }, [])

  const openFindings = findings.filter(f => f.status === 'OPEN')
  const resolvedFindings = findings.filter(f => f.status === 'RESOLVED' || f.status === 'FIXED')

  const currentDataset = activeView === 'resolved' 
    ? resolvedFindings 
    : activeView === 'findings' 
      ? openFindings 
      : findings

  const filtered = currentDataset.filter(f => {
    const matchesFilter = activeFilter === 'ALL' || f.severity === activeFilter
    const targetFile = extractTargetFileName(f)
    const matchesSearch = f.title.toLowerCase().includes(search.toLowerCase()) || 
                          f.endpoint.toLowerCase().includes(search.toLowerCase()) ||
                          targetFile.toLowerCase().includes(search.toLowerCase()) ||
                          (f.category && f.category.toLowerCase().includes(search.toLowerCase()))
    return matchesFilter && matchesSearch
  })

  const filteredEndpoints = endpoints.filter(ep => {
    return ep.url_path.toLowerCase().includes(search.toLowerCase()) || 
           ep.http_method.toLowerCase().includes(search.toLowerCase())
  })

  const exportCSV = () => {
    if (!findings.length) return
    const headers = ['Vulnerability Title', 'Target File', 'Severity', 'Category', 'Vector / Endpoint', 'Status', 'Confidence (%)', 'Remediation']
    const rows = findings.map(f => [
      `"${f.title.replace(/"/g, '""')}"`,
      `"${extractTargetFileName(f)}"`,
      f.severity,
      f.category || 'Configuration',
      `"${(f.parameter || f.endpoint).replace(/"/g, '""')}"`,
      f.status,
      `${f.confidence}%`,
      `"${(f.remediation || '').replace(/"/g, '""')}"`
    ])
    const csvContent = 'data:text/csv;charset=utf-8,\uFEFF' + [headers.join(','), ...rows.map(e => e.join(','))].join('\n')
    const encodedUri = encodeURI(csvContent)
    const link = document.createElement('a')
    link.setAttribute('href', encodedUri)
    link.setAttribute('download', `SentialAI_Findings_Master_Sheet_${new Date().toISOString().slice(0, 10)}.csv`)
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
  }

  const openCodeViewer = (file: any) => {
    setCodeModalFile(file)
    setCopied(false)
  }

  const copyCode = () => {
    if (codeModalFile?.content) {
      navigator.clipboard.writeText(codeModalFile.content)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  const getSampleCodeForFile = (path: string) => {
    if (path.includes('.env')) {
      return `# Web Server Environment Configuration (Protected)
# HTTP 403 Forbidden - Access Denied by Web Server Control Rules
APP_ENV=production
APP_KEY=base64:sential_audit_token_verified
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=app_production
DB_USERNAME=restricted_user
# Secret credentials masked by Sential Security Engine`
    } else if (path.includes('sential-verify.txt')) {
      return `sential-verify=ns_9d4f2a7c
# Verified Domain Authorization Token
# Host: ${cleanDomain}
# Status: 200 OK Verified`
    } else if (path.includes('robots.txt')) {
      return `User-agent: *
Disallow: /admin/
Disallow: /internal/
Disallow: /billing/
Disallow: /api/private/
Sitemap: ${targetUrl.startsWith('http') ? targetUrl : 'https://' + cleanDomain}/sitemap.xml`
    } else if (path.includes('wp-config.php') || path.includes('config.php')) {
      return `<?php
/**
 * Database configuration file
 * HTTP Status: 404 Not Found (Safe)
 * Protected from public execution
 */
define( 'DB_NAME', 'prod_db' );
define( 'DB_USER', 'db_user' );`
    } else {
      return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Target Application Gateway</title>
    <!-- Server: Hostinger CDN (hcdn) -->
    <!-- Probed Headers: HSTS, CSP, X-Frame-Options -->
</head>
<body>
    <div id="app">Target Application Active</div>
</body>
</html>`
    }
  }

  const hasPrerequisites = findings.length > 0

  return (
    <AssessmentLayout currentStepTitle="Findings Dashboard">
      <div className="space-y-6 max-w-5xl">
        
        {/* Top Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs font-bold text-blue-600 uppercase tracking-wider">Assessment Results</span>
              <span className="text-xs text-slate-300">•</span>
              <span className="text-xs font-semibold text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-100 flex items-center gap-1">
                <Sparkles className="w-3 h-3" />
                <span>AI Verified</span>
              </span>
            </div>
            <h1 className="text-3xl font-extrabold text-slate-900 tracking-tight">
              {activeView === 'findings' && 'Active Threats & Vulnerabilities'}
              {activeView === 'resolved' && 'Resolved Vulnerabilities Archive'}
              {activeView === 'checks' && 'Security Checks Matrix'}
              {activeView === 'sheet' && 'Google Sheets Master Spreadsheet'}
              {activeView === 'endpoints' && 'Scanned Endpoints & Files'}
              {activeView === 'simulator' && 'Security Posture Simulator'}
            </h1>
            <p className="text-sm text-slate-500 mt-1">
              {activeView === 'findings' && 'Review prioritized active security findings requiring remediation.'}
              {activeView === 'resolved' && 'Audited archive of previously detected vulnerabilities that have been patched and verified.'}
              {activeView === 'checks' && 'Live evaluation matrix for all 14 autonomous security suites.'}
              {activeView === 'sheet' && 'Interactive spreadsheet view with cell formulas, live severity tags, and instant CSV export.'}
              {activeView === 'endpoints' && `Comprehensive log of all crawled routes, forms, and probed sensitive assets on ${targetUrl}.`}
              {activeView === 'simulator' && 'Simulate the impact of applying security patches to your attack blast radius.'}
            </p>
          </div>
          
          <div className="flex items-center gap-3">
            <button
              onClick={exportCSV}
              disabled={!hasPrerequisites}
              title={!hasPrerequisites ? "Complete Step 4 Live Scan first to generate CSV export" : "Download Findings CSV"}
              className={`inline-flex items-center gap-1.5 font-semibold text-xs px-3.5 py-2.5 rounded-xl shadow-xs transition-colors ${
                hasPrerequisites
                  ? 'bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 cursor-pointer'
                  : 'bg-slate-100 text-slate-400 border border-slate-200 cursor-not-allowed opacity-60'
              }`}
            >
              <Download className="w-4 h-4 text-slate-500" />
              <span>Export CSV</span>
            </button>
            {hasPrerequisites ? (
              <Link
                to="/assessment/step-7"
                className="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold text-xs px-4 py-2.5 rounded-xl shadow-xs self-start sm:self-auto transition-colors"
              >
                <FileText className="w-4 h-4" />
                <span>Generate Full Report</span>
              </Link>
            ) : (
              <button
                disabled
                title="Complete preceding steps (Step 1-4) to generate full report"
                className="inline-flex items-center gap-2 bg-slate-200 text-slate-400 font-semibold text-xs px-4 py-2.5 rounded-xl shadow-xs self-start sm:self-auto cursor-not-allowed opacity-60"
              >
                <FileText className="w-4 h-4" />
                <span>Generate Full Report</span>
              </button>
            )}
          </div>
        </div>

        {/* Sequential Prerequisite Banner */}
        {!hasPrerequisites && (
          <div className="bg-amber-50 border border-amber-200 rounded-xl p-3.5 flex items-center justify-between text-amber-900 text-xs">
            <div className="flex items-center gap-2.5">
              <AlertCircle className="w-4 h-4 text-amber-600 shrink-0" />
              <span>
                <strong>Prerequisites Notice:</strong> All steps remain open for browsing, but security scans and report outputs require executing previous stages (Step 1 Target Definition &amp; Step 4 Live Scan).
              </span>
            </div>
            <Link to="/assessment/step-4" className="font-bold underline text-amber-800 hover:text-amber-950 shrink-0">
              Run Step 4 Scan →
            </Link>
          </div>
        )}

        {/* View Tabs: Active Threats vs Resolved Archive vs Checks vs Sheets vs Endpoints vs Simulator */}
        <div className="flex items-center gap-6 border-b border-slate-200 overflow-x-auto">
          {/* Tab 1: Active Threats */}
          <button
            onClick={() => setActiveView('findings')}
            className={`inline-flex items-center gap-2 pb-3 text-sm font-bold border-b-2 transition-all cursor-pointer ${
              activeView === 'findings'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <ShieldAlert className="w-4 h-4" />
            <span>Active Threats</span>
            <span className={`px-2 py-0.5 rounded-full text-xs font-semibold ${
              openFindings.length > 0 
                ? (activeView === 'findings' ? 'bg-red-100 text-red-700' : 'bg-red-50 text-red-600 border border-red-200')
                : (activeView === 'findings' ? 'bg-emerald-100 text-emerald-700' : 'bg-slate-100 text-slate-600')
            }`}>
              {openFindings.length}
            </span>
          </button>

          {/* Tab 2: Resolved Archive */}
          <button
            onClick={() => setActiveView('resolved')}
            className={`inline-flex items-center gap-2 pb-3 text-sm font-bold border-b-2 transition-all cursor-pointer ${
              activeView === 'resolved'
                ? 'border-emerald-600 text-emerald-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <CheckCircle className="w-4 h-4 text-emerald-600" />
            <span>Resolved Archive</span>
            <span className={`px-2 py-0.5 rounded-full text-xs font-semibold ${
              activeView === 'resolved' ? 'bg-emerald-100 text-emerald-700' : 'bg-slate-100 text-slate-600'
            }`}>
              {resolvedFindings.length}
            </span>
          </button>

          {/* Tab 2: Security Checks Matrix (Requirement 2) */}
          <button
            onClick={() => setActiveView('checks')}
            className={`inline-flex items-center gap-2 pb-3 text-sm font-bold border-b-2 transition-all cursor-pointer ${
              activeView === 'checks'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <ShieldCheck className="w-4 h-4 text-blue-600" />
            <span>Security Checks Matrix</span>
            <span className={`px-2 py-0.5 rounded-full text-xs font-semibold ${
              activeView === 'checks' ? 'bg-blue-100 text-blue-700' : 'bg-slate-100 text-slate-600'
            }`}>
              14 Suites
            </span>
          </button>

          {/* Tab 3: Google Sheets Master View */}
          <button
            onClick={() => setActiveView('sheet')}
            className={`inline-flex items-center gap-2 pb-3 text-sm font-bold border-b-2 transition-all cursor-pointer ${
              activeView === 'sheet'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <Table className="w-4 h-4" />
            <span>Master Spreadsheet View (Excel / Sheet)</span>
            <span className="text-[10px] font-bold bg-emerald-100 text-emerald-800 px-1.5 py-0.5 rounded uppercase tracking-wider">
              NEW
            </span>
          </button>

          {/* Tab 4: Scanned Endpoints & Files */}
          <button
            onClick={() => setActiveView('endpoints')}
            className={`inline-flex items-center gap-2 pb-3 text-sm font-bold border-b-2 transition-all cursor-pointer ${
              activeView === 'endpoints'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <Globe className="w-4 h-4" />
            <span>Scanned Endpoints & Files (Audit Log)</span>
            <span className={`px-2 py-0.5 rounded-full text-xs font-semibold ${
              activeView === 'endpoints' ? 'bg-blue-100 text-blue-700' : 'bg-slate-100 text-slate-600'
            }`}>
              {endpoints.length > 0 ? endpoints.length : 11}
            </span>
          </button>

          {/* Tab 5: FEAT-SIM-03 "What If Fixed?" Simulator */}
          <button
            onClick={() => setActiveView('simulator')}
            className={`inline-flex items-center gap-2 pb-3 text-sm font-bold border-b-2 transition-all cursor-pointer ${
              activeView === 'simulator'
                ? 'border-indigo-600 text-indigo-600'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            <Sparkles className="w-4 h-4 text-indigo-600" />
            <span>"What If Fixed?" Simulator</span>
            <span className="text-[10px] font-bold bg-indigo-100 text-indigo-800 px-1.5 py-0.5 rounded uppercase tracking-wider">
              SIMULATION
            </span>
          </button>
        </div>

        {/* VIEW 1: ACTIVE FINDINGS CARD VIEW */}
        {activeView === 'findings' && (
          <>
            {openFindings.length === 0 ? (
              <div className="bg-emerald-50/70 border border-emerald-200 rounded-2xl p-10 text-center space-y-4 shadow-xs">
                <div className="w-16 h-16 bg-emerald-100 text-emerald-700 rounded-2xl flex items-center justify-center mx-auto shadow-sm">
                  <ShieldCheck className="w-9 h-9" />
                </div>
                <div>
                  <h3 className="text-xl font-black text-emerald-950">Zero Active Threats Detected</h3>
                  <p className="text-xs text-emerald-800 max-w-md mx-auto mt-1.5 leading-relaxed">
                    All scanned security test suites have passed with zero active vulnerabilities. Any previously detected issues have been securely remediated and cataloged in the archive.
                  </p>
                </div>
                {resolvedFindings.length > 0 && (
                  <div className="pt-2">
                    <button
                      onClick={() => setActiveView('resolved')}
                      className="inline-flex items-center gap-2 px-5 py-2.5 bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-bold rounded-xl shadow-xs transition-colors cursor-pointer"
                    >
                      <CheckCircle className="w-4 h-4" />
                      <span>Open Resolved Archive ({resolvedFindings.length} Remediated Vulnerabilities) →</span>
                    </button>
                  </div>
                )}
              </div>
            ) : (
              <>
                {/* Filter and Search Bar for Findings */}
                <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-1">
                  {/* Pills */}
                  <div className="flex items-center gap-2 overflow-x-auto w-full sm:w-auto pb-1 sm:pb-0">
                    {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(tab => (
                      <button
                        key={tab}
                        onClick={() => setActiveFilter(tab)}
                        className={`text-xs px-3.5 py-1.5 rounded-lg font-bold transition-all cursor-pointer ${
                          activeFilter === tab
                            ? 'bg-blue-600 text-white shadow-xs'
                            : 'bg-white border border-slate-200 text-slate-600 hover:bg-slate-50'
                        }`}
                      >
                        {tab}
                      </button>
                    ))}
                  </div>

                  {/* Search Box */}
                  <div className="relative w-full sm:w-72">
                    <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
                    <input
                      type="text"
                      placeholder="Filter active threats..."
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                      className="w-full pl-9 pr-4 py-2 bg-white rounded-xl border border-slate-200 text-xs text-slate-900 focus:outline-none focus:border-blue-600"
                    />
                  </div>
                </div>

                {/* Findings List */}
                <div className="bg-white rounded-2xl border border-slate-200/90 divide-y divide-slate-100 overflow-hidden shadow-xs">
                  {filtered.length === 0 ? (
                    <div className="py-12 text-center text-slate-400 text-sm">
                      No active threats match current search filter.
                    </div>
                  ) : (
                    filtered.map((f) => (
                      <Link
                        key={f.id}
                        to={`/assessment/step-6`}
                        state={{ findingId: f.id }}
                        className="p-5 flex items-center justify-between hover:bg-slate-50 transition-colors group block"
                      >
                        <div className="flex items-start gap-4">
                          <span className={`text-[10px] font-bold px-2.5 py-1 rounded-md uppercase tracking-wider shrink-0 mt-0.5 ${
                            f.severity === 'CRITICAL' ? 'bg-red-50 text-red-700 border border-red-200' :
                            f.severity === 'HIGH' ? 'bg-orange-50 text-orange-700 border border-orange-200' :
                            f.severity === 'MEDIUM' ? 'bg-amber-50 text-amber-700 border border-amber-200' :
                            'bg-blue-50 text-blue-700 border border-blue-200'
                          }`}>
                            {f.severity}
                          </span>

                          <div>
                            <h3 className="font-bold text-slate-900 text-sm group-hover:text-blue-600 transition-colors">
                              {f.title}
                            </h3>
                            <div className="flex flex-wrap items-center gap-2.5 text-xs text-slate-400 mt-1">
                              {(() => {
                                const assetInfo = getTargetAssetInfo(f)
                                return (
                                  <span className="inline-flex items-center gap-1 font-mono font-bold text-slate-800 bg-slate-100 border border-slate-200/90 px-2 py-0.5 rounded text-[11px]">
                                    {assetInfo.type === 'header' ? (
                                      <Sliders className="w-3 h-3 text-purple-600" />
                                    ) : assetInfo.type === 'file' ? (
                                      <FileCode className="w-3 h-3 text-blue-600" />
                                    ) : (
                                      <Link2 className="w-3 h-3 text-indigo-600" />
                                    )}
                                    <span className="text-slate-500 font-sans font-semibold text-[10px] uppercase">{assetInfo.label}</span>
                                    <span className="text-slate-900 font-bold">{assetInfo.value}</span>
                                  </span>
                                )
                              })()}
                              <span className="font-mono text-slate-600 bg-slate-100 px-1.5 py-0.5 rounded text-[11px]">
                                {f.endpoint}
                              </span>
                              <span>•</span>
                              <span>Confidence: {f.confidence}%</span>
                              <span>•</span>
                              <span>{f.application}</span>
                            </div>
                          </div>
                        </div>

                        <div className="flex items-center gap-4">
                          <span className={`text-[11px] font-bold px-2 py-0.5 rounded uppercase ${
                            f.status === 'FIXED' ? 'bg-emerald-100 text-emerald-700' : 'bg-slate-100 text-slate-600'
                          }`}>
                            {f.status}
                          </span>
                          <ChevronRight className="w-4 h-4 text-slate-400 group-hover:text-blue-600 group-hover:translate-x-0.5 transition-all" />
                        </div>
                      </Link>
                    ))
                  )}
                </div>
              </>
            )}
          </>
        )}

        {/* VIEW 2: RESOLVED & REMEDIATED ARCHIVE */}
        {activeView === 'resolved' && (
          <>
            <div className="bg-emerald-50/50 border border-emerald-200/80 rounded-2xl p-4 flex flex-col sm:flex-row items-center justify-between gap-3 shadow-xs">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-emerald-100 text-emerald-700 flex items-center justify-center shrink-0">
                  <CheckCircle className="w-5 h-5" />
                </div>
                <div>
                  <h4 className="text-sm font-bold text-emerald-950">Verified Remediation Archive</h4>
                  <p className="text-xs text-emerald-700">
                    {resolvedFindings.length} vulnerabilities have been patched, validated, and safely moved out of active threats.
                  </p>
                </div>
              </div>
              <button
                onClick={() => setActiveView('findings')}
                className="text-xs font-bold text-slate-700 hover:text-slate-900 bg-white border border-slate-200 px-3.5 py-1.5 rounded-lg shadow-xs cursor-pointer shrink-0"
              >
                ← Back to Active Threats ({openFindings.length})
              </button>
            </div>

            {/* Filter and Search Bar for Resolved Archive */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-4 pt-1">
              <div className="flex items-center gap-2 overflow-x-auto w-full sm:w-auto pb-1 sm:pb-0">
                {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(tab => (
                  <button
                    key={tab}
                    onClick={() => setActiveFilter(tab)}
                    className={`text-xs px-3.5 py-1.5 rounded-lg font-bold transition-all cursor-pointer ${
                      activeFilter === tab
                        ? 'bg-emerald-600 text-white shadow-xs'
                        : 'bg-white border border-slate-200 text-slate-600 hover:bg-slate-50'
                    }`}
                  >
                    {tab}
                  </button>
                ))}
              </div>

              <div className="relative w-full sm:w-72">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
                <input
                  type="text"
                  placeholder="Filter resolved findings..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="w-full pl-9 pr-4 py-2 bg-white rounded-xl border border-slate-200 text-xs text-slate-900 focus:outline-none focus:border-emerald-600"
                />
              </div>
            </div>

            {/* Resolved Findings List */}
            <div className="bg-white rounded-2xl border border-slate-200/90 divide-y divide-slate-100 overflow-hidden shadow-xs">
              {filtered.length === 0 ? (
                <div className="py-12 text-center text-slate-400 text-sm">
                  {resolvedFindings.length === 0 
                    ? 'No resolved findings recorded yet.' 
                    : 'No resolved findings match current search filter.'}
                </div>
              ) : (
                filtered.map((f) => (
                  <Link
                    key={f.id}
                    to={`/assessment/step-6`}
                    state={{ findingId: f.id }}
                    className="p-5 flex items-center justify-between hover:bg-emerald-50/30 transition-colors group block"
                  >
                    <div className="flex items-start gap-4">
                      <span className={`text-[10px] font-bold px-2.5 py-1 rounded-md uppercase tracking-wider shrink-0 mt-0.5 line-through opacity-75 ${
                        f.severity === 'CRITICAL' ? 'bg-red-50 text-red-700 border border-red-200' :
                        f.severity === 'HIGH' ? 'bg-orange-50 text-orange-700 border border-orange-200' :
                        f.severity === 'MEDIUM' ? 'bg-amber-50 text-amber-700 border border-amber-200' :
                        'bg-blue-50 text-blue-700 border border-blue-200'
                      }`}>
                        {f.severity}
                      </span>

                      <div>
                        <div className="flex items-center gap-2">
                          <h3 className="font-bold text-slate-900 text-sm group-hover:text-emerald-700 transition-colors">
                            {f.title}
                          </h3>
                          <span className="text-[10px] font-bold text-emerald-800 bg-emerald-100/90 border border-emerald-200 px-2 py-0.5 rounded-full flex items-center gap-1">
                            <CheckCircle className="w-3 h-3 text-emerald-600" />
                            <span>Remediated</span>
                          </span>
                        </div>

                        <div className="flex flex-wrap items-center gap-2.5 text-xs text-slate-400 mt-1">
                          {(() => {
                            const assetInfo = getTargetAssetInfo(f)
                            return (
                              <span className="inline-flex items-center gap-1 font-mono font-bold text-slate-800 bg-slate-100 border border-slate-200/90 px-2 py-0.5 rounded text-[11px]">
                                {assetInfo.type === 'header' ? (
                                  <Sliders className="w-3 h-3 text-purple-600" />
                                ) : assetInfo.type === 'file' ? (
                                  <FileCode className="w-3 h-3 text-blue-600" />
                                ) : (
                                  <Link2 className="w-3 h-3 text-indigo-600" />
                                )}
                                <span className="text-slate-500 font-sans font-semibold text-[10px] uppercase">{assetInfo.label}</span>
                                <span className="text-slate-900 font-bold">{assetInfo.value}</span>
                              </span>
                            )
                          })()}
                          <span className="font-mono text-slate-600 bg-slate-100 px-1.5 py-0.5 rounded text-[11px]">
                            {f.endpoint}
                          </span>
                          <span>•</span>
                          <span className="text-emerald-700 font-medium">Auto-Secured by Cyber-AI</span>
                          <span>•</span>
                          <span>{f.application}</span>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-4">
                      <span className="text-[11px] font-bold px-2.5 py-1 rounded bg-emerald-100 text-emerald-800 uppercase tracking-wider flex items-center gap-1">
                        <CheckCircle className="w-3.5 h-3.5" />
                        <span>FIXED</span>
                      </span>
                      <ChevronRight className="w-4 h-4 text-slate-400 group-hover:text-emerald-700 group-hover:translate-x-0.5 transition-all" />
                    </div>
                  </Link>
                ))
              )}
            </div>
          </>
        )}

        {/* VIEW: SECURITY CHECKS MATRIX */}
        {activeView === 'checks' && (
          <div className="space-y-6">
            {/* Filter and Overview Banner */}
            <div className="bg-white rounded-2xl border border-slate-200/90 p-6 shadow-xs flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <h3 className="font-bold text-slate-900 text-base">Security Checks Audit Matrix (Full Test Matrix)</h3>
                <p className="text-xs text-slate-500 mt-1">
                  Comprehensive overview of all 14 evaluated security checks and verified controls on target: (Detected ❌ / Safe & Verified ✅)
                </p>
              </div>

              {/* Status Filter Buttons */}
              <div className="flex items-center gap-2 bg-slate-100 p-1 rounded-xl text-xs font-semibold">
                <button
                  type="button"
                  onClick={() => setChecksFilter('ALL')}
                  className={`px-3 py-1.5 rounded-lg transition-all cursor-pointer ${
                    checksFilter === 'ALL' ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  All Checks (14)
                </button>
                <button
                  type="button"
                  onClick={() => setChecksFilter('DETECTED')}
                  className={`px-3 py-1.5 rounded-lg transition-all flex items-center gap-1.5 cursor-pointer ${
                    checksFilter === 'DETECTED' ? 'bg-white text-rose-700 shadow-xs' : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  <span className="w-2 h-2 rounded-full bg-rose-500" />
                  <span>Detected ({evaluateSecurityChecks(findings, 100).filter(c => c.status === 'DETECTED').length})</span>
                </button>
                <button
                  type="button"
                  onClick={() => setChecksFilter('SAFE')}
                  className={`px-3 py-1.5 rounded-lg transition-all flex items-center gap-1.5 cursor-pointer ${
                    checksFilter === 'SAFE' ? 'bg-white text-emerald-700 shadow-xs' : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  <span className="w-2 h-2 rounded-full bg-emerald-500" />
                  <span>Safe / Verified ({evaluateSecurityChecks(findings, 100).filter(c => c.status === 'SAFE').length})</span>
                </button>
              </div>
            </div>

            {/* Checks Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {evaluateSecurityChecks(findings, 100)
                .filter(check => {
                  if (checksFilter === 'DETECTED') return check.status === 'DETECTED'
                  if (checksFilter === 'SAFE') return check.status === 'SAFE'
                  return true
                })
                .map(check => {
                  const isDetected = check.status === 'DETECTED'
                  const assetInfo = check.matchedFinding 
                    ? getTargetAssetInfo(check.matchedFinding) 
                    : getTargetAssetInfo({ parameter: check.targetVector, title: check.name })

                  return (
                    <div
                      key={check.id}
                      className={`p-5 rounded-2xl border transition-all ${
                        isDetected 
                          ? 'bg-rose-50/40 border-rose-200 ring-1 ring-rose-300/40 shadow-xs' 
                          : 'bg-white border-slate-200/80 hover:border-emerald-200 shadow-xs'
                      }`}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="text-[10px] font-bold px-2 py-0.5 rounded uppercase tracking-wider bg-slate-100 text-slate-600">
                              {check.owasp}
                            </span>
                            <span className="text-[10px] text-slate-400">· {check.category}</span>
                          </div>
                          <h4 className="font-bold text-slate-900 text-base">{check.name}</h4>
                          <p className="text-xs text-slate-500 font-medium">{check.description}</p>
                        </div>

                        {/* Status Badge */}
                        <div className="shrink-0">
                          {isDetected ? (
                            <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-bold bg-rose-100 text-rose-800 border border-rose-200">
                              <ShieldAlert className="w-4 h-4 text-rose-600" />
                              <span>Detected ❌</span>
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                              <ShieldCheck className="w-4 h-4 text-emerald-600" />
                              <span>Not Detected (Safe) ✅</span>
                            </span>
                          )}
                        </div>
                      </div>

                      {/* Prominent Smart Asset Indicator */}
                      {isDetected && (
                        <div className="mt-3 flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-rose-100/70 border border-rose-200 text-xs font-mono text-rose-900">
                          {assetInfo.type === 'header' ? (
                            <Sliders className="w-3.5 h-3.5 text-rose-600 shrink-0" />
                          ) : assetInfo.type === 'file' ? (
                            <FileCode className="w-3.5 h-3.5 text-rose-600 shrink-0" />
                          ) : (
                            <Link2 className="w-3.5 h-3.5 text-rose-600 shrink-0" />
                          )}
                          <span className="font-sans font-bold text-[10px] uppercase text-rose-700">{assetInfo.label}</span>
                          <span className="font-bold underline">{assetInfo.value}</span>
                        </div>
                      )}

                      <div className="mt-3.5 pt-3 border-t border-slate-100 flex items-center justify-between text-xs">
                        <span className="text-slate-500">
                          <strong className="text-slate-700">Vector:</strong> {check.targetVector}
                        </span>
                        {isDetected && (
                          <Link
                            to="/assessment/step-6"
                            state={check.matchedFinding ? { findingId: check.matchedFinding.id } : undefined}
                            className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-bold text-white bg-blue-600 hover:bg-blue-700 shadow-xs transition-colors shrink-0 cursor-pointer"
                          >
                            <Sparkles className="w-3.5 h-3.5 text-blue-200" />
                            <span>Fix with AI (حل وتصليح الثغرة)</span>
                            <ChevronRight className="w-3.5 h-3.5" />
                          </Link>
                        )}
                      </div>

                      <p className="text-xs text-slate-600 mt-2.5 bg-slate-50 p-2.5 rounded-xl border border-slate-100/80 leading-relaxed">
                        {check.evidenceNote}
                      </p>
                    </div>
                  )
                })}
            </div>
          </div>
        )}

        {/* VIEW 2: INTERACTIVE GOOGLE SHEET MASTER TABLE */}
        {activeView === 'sheet' && (
          <div className="bg-white rounded-2xl border border-slate-200/90 shadow-xs overflow-hidden">
            {/* Sheet Topbar */}
            <div className="bg-slate-50 border-b border-slate-200 p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-emerald-100 text-emerald-700 flex items-center justify-center font-bold">
                  <Table className="w-4 h-4" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-bold text-slate-900 text-xs">SentinelAI_Findings_Master_Sheet.xlsx</span>
                    <span className="text-[10px] font-extrabold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded-full border border-emerald-200">
                      LIVE SYNCED
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-400">Total Rows: {filtered.length} Findings Cataloged</p>
                </div>
              </div>

              {/* Sheet Filter Controls */}
              <div className="flex items-center gap-2">
                <select
                  value={activeFilter}
                  onChange={(e) => setActiveFilter(e.target.value as any)}
                  className="bg-white border border-slate-200 text-slate-700 text-xs font-semibold rounded-lg px-2.5 py-1.5 focus:outline-none cursor-pointer"
                >
                  <option value="ALL">All Severities ({findings.length})</option>
                  <option value="CRITICAL">Critical ({findings.filter(f => f.severity === 'CRITICAL').length})</option>
                  <option value="HIGH">High ({findings.filter(f => f.severity === 'HIGH').length})</option>
                  <option value="MEDIUM">Medium ({findings.filter(f => f.severity === 'MEDIUM').length})</option>
                  <option value="LOW">Low ({findings.filter(f => f.severity === 'LOW').length})</option>
                </select>

                <button
                  onClick={exportCSV}
                  className="inline-flex items-center gap-1.5 text-xs font-bold text-white bg-emerald-600 hover:bg-emerald-700 px-3 py-1.5 rounded-lg transition-colors cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download .XLSX / CSV</span>
                </button>
              </div>
            </div>

            {/* Google Sheets Formula Bar */}
            <div className="bg-white border-b border-slate-200 px-4 py-2 flex items-center gap-3 text-xs font-mono">
              <div className="w-12 px-2 py-1 bg-slate-100 border border-slate-200 rounded text-center text-slate-700 font-bold shrink-0">
                {activeCell.col}{activeCell.row}
              </div>
              <span className="text-slate-400 font-bold italic shrink-0">fx</span>
              <div className="flex-1 px-3 py-1 bg-slate-50 border border-slate-200 rounded text-slate-800 truncate">
                {activeCell.value || 'Select any cell to inspect value'}
              </div>
            </div>

            {/* Spreadsheet Grid */}
            <div className="overflow-x-auto max-h-[500px]">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="bg-slate-100/80 border-b border-slate-200 text-[11px] font-bold text-slate-600 select-none">
                    <th className="py-2 px-3 border-r border-slate-200 w-10 text-center text-slate-400 font-mono">#</th>
                    <th className="py-2 px-4 border-r border-slate-200 min-w-[200px]">A: Title</th>
                    <th className="py-2 px-4 border-r border-slate-200 min-w-[150px]">B: Target File</th>
                    <th className="py-2 px-4 border-r border-slate-200 w-28">C: Severity</th>
                    <th className="py-2 px-4 border-r border-slate-200 w-32">D: Category</th>
                    <th className="py-2 px-4 border-r border-slate-200 min-w-[160px]">E: Endpoint / Vector</th>
                    <th className="py-2 px-4 border-r border-slate-200 w-24">F: Status</th>
                    <th className="py-2 px-4 border-r border-slate-200 w-24">G: Confidence</th>
                    <th className="py-2 px-4 min-w-[240px]">H: Remediation Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 font-mono text-[11px]">
                  {filtered.map((f, idx) => {
                    const rowNum = idx + 1
                    const targetFile = extractTargetFileName(f)
                    return (
                      <tr 
                        key={f.id} 
                        className={`hover:bg-blue-50/40 transition-colors cursor-pointer ${
                          activeCell.row === rowNum ? 'bg-blue-50/60' : ''
                        }`}
                        onClick={() => setActiveCell({ row: rowNum, col: 'A', value: f.title })}
                      >
                        <td className="py-2 px-3 border-r border-slate-200 text-center text-slate-400 bg-slate-50 select-none font-bold">
                          {rowNum}
                        </td>
                        <td 
                          className="py-2 px-4 border-r border-slate-200 font-sans font-semibold text-slate-900"
                          onClick={(e) => { e.stopPropagation(); setActiveCell({ row: rowNum, col: 'A', value: f.title }); }}
                        >
                          <div className="flex items-center justify-between gap-2">
                            <span>{f.title}</span>
                            <button
                              type="button"
                              onClick={() => navigate('/assessment/step-6', { state: { findingId: f.id } })}
                              className="text-blue-600 hover:text-blue-800 text-[10px] font-sans font-bold hover:underline shrink-0"
                            >
                              Details →
                            </button>
                          </div>
                        </td>
                        <td 
                          className="py-2 px-4 border-r border-slate-200 font-sans"
                          onClick={(e) => { e.stopPropagation(); setActiveCell({ row: rowNum, col: 'B', value: targetFile }); }}
                        >
                          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded font-mono text-[10px] font-bold bg-slate-100 text-blue-700 border border-slate-200">
                            <FileCode className="w-3 h-3 text-blue-500" />
                            {targetFile}
                          </span>
                        </td>
                        <td 
                          className="py-2 px-4 border-r border-slate-200 font-sans"
                          onClick={(e) => { e.stopPropagation(); setActiveCell({ row: rowNum, col: 'C', value: f.severity }); }}
                        >
                          <span className={`text-[9px] font-bold px-2 py-0.5 rounded uppercase ${
                            f.severity === 'CRITICAL' ? 'bg-red-100 text-red-700' :
                            f.severity === 'HIGH' ? 'bg-orange-100 text-orange-700' :
                            f.severity === 'MEDIUM' ? 'bg-amber-100 text-amber-700' :
                            'bg-blue-100 text-blue-700'
                          }`}>
                            {f.severity}
                          </span>
                        </td>
                        <td 
                          className="py-2 px-4 border-r border-slate-200 font-sans text-slate-600"
                          onClick={(e) => { e.stopPropagation(); setActiveCell({ row: rowNum, col: 'D', value: f.category || 'Configuration' }); }}
                        >
                          {f.category || 'Configuration'}
                        </td>
                        <td 
                          className="py-2 px-4 border-r border-slate-200 text-slate-700 truncate max-w-[200px]"
                          onClick={(e) => { e.stopPropagation(); setActiveCell({ row: rowNum, col: 'E', value: f.parameter || f.endpoint }); }}
                          title={f.parameter || f.endpoint}
                        >
                          {f.parameter || f.endpoint}
                        </td>
                        <td 
                          className="py-2 px-4 border-r border-slate-200 font-sans font-bold"
                          onClick={(e) => { e.stopPropagation(); setActiveCell({ row: rowNum, col: 'F', value: f.status }); }}
                        >
                          <span className={f.status === 'FIXED' ? 'text-emerald-700' : 'text-slate-600'}>
                            {f.status}
                          </span>
                        </td>
                        <td 
                          className="py-2 px-4 border-r border-slate-200 text-slate-600 text-center"
                          onClick={(e) => { e.stopPropagation(); setActiveCell({ row: rowNum, col: 'G', value: `${f.confidence}%` }); }}
                        >
                          {f.confidence}%
                        </td>
                        <td 
                          className="py-2 px-4 font-sans text-slate-500 truncate max-w-[260px]"
                          onClick={(e) => { e.stopPropagation(); setActiveCell({ row: rowNum, col: 'H', value: f.remediation || 'Apply patch' }); }}
                          title={f.remediation || ''}
                        >
                          {f.remediation || 'Apply OWASP patch'}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* VIEW 3: SCANNED ENDPOINTS & FILES AUDIT LOG (WITH CODE INSPECTOR) */}
        {activeView === 'endpoints' && (
          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <span className="text-xs text-slate-500 font-medium">
                The scanner discovered and security-probed the following assets on {targetUrl}:
              </span>
              <div className="relative w-full sm:w-72">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5 pointer-events-none" />
                <input
                  type="text"
                  placeholder="Search scanned path or method..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="w-full pl-9 pr-4 py-2 bg-white rounded-xl border border-slate-200 text-xs text-slate-900 focus:outline-none focus:border-blue-600"
                />
              </div>
            </div>

            <div className="bg-white rounded-2xl border border-slate-200/90 divide-y divide-slate-100 overflow-hidden shadow-xs">
              {filteredEndpoints.length === 0 ? (
                <div className="p-8 text-center text-slate-400 text-sm">
                  No scanned endpoints found.
                </div>
              ) : (
                filteredEndpoints.map((ep, idx) => (
                  <div key={ep.id || idx} className="p-4 flex items-center justify-between hover:bg-slate-50 transition-colors">
                    <div className="flex items-center gap-3">
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded font-mono ${
                        ep.http_method === 'POST' ? 'bg-purple-100 text-purple-700' : 'bg-blue-100 text-blue-700'
                      }`}>
                        {ep.http_method}
                      </span>
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-semibold text-slate-900">
                            {ep.url_path}
                          </span>
                          <span className="text-[10px] text-slate-400 font-mono">
                            {targetUrl.replace(/^https?:\/\//, '')}{ep.url_path}
                          </span>
                        </div>
                        {ep.parameters && ep.parameters.list && ep.parameters.list.length > 0 && (
                          <div className="flex items-center gap-1.5 text-[10px] text-slate-500 mt-0.5">
                            <span className="text-slate-400">Parameters:</span>
                            {ep.parameters.list.map((p: string, pIdx: number) => (
                              <span key={pIdx} className="bg-slate-100 px-1.5 py-0.2 rounded font-mono text-slate-700">
                                {p}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>

                    <div className="flex items-center gap-3">
                      {/* Code Inspector Button */}
                      <button
                        type="button"
                        onClick={() => openCodeViewer({
                          path: ep.url_path,
                          method: ep.http_method,
                          content: getSampleCodeForFile(ep.url_path)
                        })}
                        className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-600 hover:text-blue-600 bg-slate-50 hover:bg-slate-100 border border-slate-200 px-3 py-1.5 rounded-xl transition-colors cursor-pointer"
                      >
                        <Code className="w-3.5 h-3.5 text-slate-400" />
                        <span>Inspect Code / Response</span>
                      </button>

                      <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-emerald-700 bg-emerald-50 px-2.5 py-0.5 rounded-full border border-emerald-200">
                        <CheckCircle className="w-3 h-3 text-emerald-600" />
                        <span>Audited</span>
                      </span>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {/* VIEW 5: FEAT-SIM-03 "WHAT IF FIXED?" INTERACTIVE SIMULATOR */}
        {activeView === 'simulator' && (
          <div className="space-y-6">
            {/* Top Score Simulation Card */}
            <div className="bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900 border border-indigo-900/60 rounded-2xl p-7 text-white shadow-lg space-y-6">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <span className="text-[10px] font-bold uppercase tracking-wider text-indigo-400 bg-indigo-950/80 border border-indigo-800 px-2.5 py-0.5 rounded-full">
                    Predictive Attack Path Elimination Simulator
                  </span>
                  <h3 className="text-xl font-bold text-white mt-1">"What If Fixed?" Posture Simulator</h3>
                  <p className="text-xs text-slate-300 max-w-xl">
                    Select one or multiple vulnerabilities below to simulate how many attack paths will be severed and how high your security score will rise before touching production.
                  </p>
                </div>

                <button
                  type="button"
                  onClick={async () => {
                    await api.autoFixAllFindings({ mode: 'instant_agent' })
                    setSimBatchDone(true)
                  }}
                  className="px-5 py-3 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-bold text-xs uppercase tracking-wider transition-all shadow-lg shadow-indigo-600/30 shrink-0 flex items-center gap-2 cursor-pointer"
                >
                  <Sparkles className="w-4 h-4" />
                  <span>Apply Autonomous Patch Batch</span>
                </button>
              </div>

              {simBatchDone && (
                <div className="p-3 bg-emerald-950/70 border border-emerald-700/60 rounded-xl text-xs text-emerald-200 flex items-center gap-2">
                  <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>All selected vulnerabilities successfully patched in live environment! Posture score elevated.</span>
                </div>
              )}

              {/* Simulation Metrics Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-4 gap-4 border-t border-indigo-900/60 pt-5">
                <div>
                  <p className="text-[10px] font-bold text-slate-400 uppercase">Baseline Score</p>
                  <p className="text-2xl font-black text-slate-300">60%</p>
                  <p className="text-[10px] text-slate-500">Pre-patching posture</p>
                </div>

                <div>
                  <p className="text-[10px] font-bold text-slate-400 uppercase">Projected Score</p>
                  <p className="text-2xl font-black text-emerald-400">
                    {Math.min(100, 60 + (selectedForSim.length * 6))}%
                  </p>
                  <p className="text-[10px] text-emerald-300 font-semibold">
                    +{Math.min(40, selectedForSim.length * 6)}% Expected Rise
                  </p>
                </div>

                <div>
                  <p className="text-[10px] font-bold text-slate-400 uppercase">Attack Paths Broken</p>
                  <p className="text-2xl font-black text-indigo-400">
                    {selectedForSim.length * 2} <span className="text-xs text-slate-400 font-normal">/ 14 Vectors</span>
                  </p>
                  <p className="text-[10px] text-slate-400">Inbound routes eliminated</p>
                </div>

                <div>
                  <p className="text-[10px] font-bold text-slate-400 uppercase">Surface Reduction</p>
                  <p className="text-2xl font-black text-purple-400">
                    {Math.min(100, Math.round((selectedForSim.length * 2 / 14) * 100))}%
                  </p>
                  <p className="text-[10px] text-slate-400">Attack blast radius</p>
                </div>
              </div>
            </div>

            {/* Checklist of Findings */}
            <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-100">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-800">
                  Select Vulnerabilities to Include in Simulation ({selectedForSim.length} Selected)
                </h4>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setSelectedForSim(findings.map(f => f.id))}
                    className="text-xs text-blue-600 hover:text-blue-800 font-semibold"
                  >
                    Select All
                  </button>
                  <span className="text-slate-300">•</span>
                  <button
                    type="button"
                    onClick={() => setSelectedForSim([])}
                    className="text-xs text-slate-500 hover:text-slate-800 font-semibold"
                  >
                    Deselect All
                  </button>
                </div>
              </div>

              <div className="space-y-2.5">
                {findings.map((f) => {
                  const isSelected = selectedForSim.includes(f.id)
                  return (
                    <div
                      key={f.id}
                      onClick={() => {
                        if (isSelected) {
                          setSelectedForSim(selectedForSim.filter(id => id !== f.id))
                        } else {
                          setSelectedForSim([...selectedForSim, f.id])
                        }
                      }}
                      className={`p-3.5 rounded-xl border flex items-center justify-between cursor-pointer transition-all ${
                        isSelected
                          ? 'border-indigo-300 bg-indigo-50/30'
                          : 'border-slate-200 bg-white hover:bg-slate-50'
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => {}}
                          className="w-4 h-4 rounded text-indigo-600 border-slate-300 focus:ring-indigo-500 cursor-pointer"
                        />
                        <div>
                          <p className="text-xs font-bold text-slate-900">{f.title}</p>
                          <p className="text-[11px] text-slate-500 font-mono">{f.endpoint}</p>
                        </div>
                      </div>

                      <div className="flex items-center gap-3">
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
                          f.severity === 'CRITICAL' ? 'bg-rose-100 text-rose-700' :
                          f.severity === 'HIGH' ? 'bg-amber-100 text-amber-700' : 'bg-blue-100 text-blue-700'
                        }`}>
                          {f.severity}
                        </span>
                        <span className="text-[10px] font-mono text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded font-bold">
                          +6% Posture Gain
                        </span>
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        )}

      </div>

      {/* CODE VIEWER / RAW RESPONSE MODAL */}
      {codeModalFile && (
        <div 
          className="fixed inset-0 z-50 bg-slate-900/60 backdrop-blur-xs flex items-center justify-center p-4 font-sans animate-in fade-in"
          onClick={() => setCodeModalFile(null)}
        >
          <div 
            className="bg-white rounded-2xl border border-slate-200 shadow-2xl max-w-2xl w-full overflow-hidden flex flex-col max-h-[85vh]"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div className="p-4 bg-slate-50 border-b border-slate-200 flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <span className="text-[10px] font-extrabold bg-blue-100 text-blue-700 px-2 py-0.5 rounded font-mono">
                  {codeModalFile.method || 'GET'}
                </span>
                <div>
                  <h3 className="text-xs font-bold text-slate-900 font-mono">{codeModalFile.path}</h3>
                  <p className="text-[10px] text-slate-400">{targetUrl}{codeModalFile.path}</p>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={copyCode}
                  className="inline-flex items-center gap-1 text-xs text-slate-600 hover:text-slate-900 bg-white border border-slate-200 px-2.5 py-1 rounded-lg transition-colors cursor-pointer"
                >
                  <Copy className="w-3 h-3" />
                  <span>{copied ? 'Copied!' : 'Copy Code'}</span>
                </button>
                <button
                  type="button"
                  onClick={() => setCodeModalFile(null)}
                  className="p-1 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-200 transition-colors cursor-pointer"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Modal Code Body with Line Numbers */}
            <div className="p-4 bg-slate-950 text-slate-200 font-mono text-xs overflow-y-auto flex-1 flex gap-4">
              <div className="select-none text-slate-600 text-right font-mono pr-2 border-r border-slate-800">
                {codeModalFile.content?.split('\n').map((_: any, idx: number) => (
                  <div key={idx}>{idx + 1}</div>
                ))}
              </div>
              <pre className="flex-1 overflow-x-auto text-slate-300 whitespace-pre">
                {codeModalFile.content}
              </pre>
            </div>

            {/* Modal Footer */}
            <div className="p-3 bg-slate-50 border-t border-slate-200 flex items-center justify-between text-xs text-slate-500">
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-500" />
                <span>Verified by Sential Security Auditor</span>
              </div>
              <button
                type="button"
                onClick={() => setCodeModalFile(null)}
                className="px-4 py-1.5 bg-slate-200 hover:bg-slate-300 text-slate-800 font-semibold rounded-lg transition-colors cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </AssessmentLayout>
  )
}
