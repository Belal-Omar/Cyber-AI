import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { AssessmentLayout } from '../../components/layout/AssessmentLayout'
import { Globe, AlertTriangle, Check, ChevronRight, ChevronDown, FileCode, Upload, KeyRound, HelpCircle, Sparkles, ShieldCheck } from 'lucide-react'

export const Step2TargetUrl: React.FC = () => {
  const navigate = useNavigate()
  const [url, setUrl] = useState(() => sessionStorage.getItem('sential_target_url') || '')
  const [assessmentName, setAssessmentName] = useState(() => sessionStorage.getItem('sential_assessment_name') || 'Production Security Audit')
  const [environment, setEnvironment] = useState('Production')
  const [zipFileName, setZipFileName] = useState<string | null>(() => sessionStorage.getItem('sential_sast_zip') || null)
  const [showGuide, setShowGuide] = useState(true)
  const [sessionCookie, setSessionCookie] = useState(() => sessionStorage.getItem('sential_auth_cookie') || '')
  const [bearerToken, setBearerToken] = useState(() => sessionStorage.getItem('sential_auth_token') || '')
  const [crawlDepth, setCrawlDepth] = useState<number>(() => Number(sessionStorage.getItem('sential_crawl_depth')) || 3)

  const isTargetValid = (val: string) => {
    const trimmed = val.trim().replace(/^https?:\/\//, '').split('/')[0]
    if (!trimmed) return false
    if (trimmed === 'localhost' || trimmed.startsWith('127.0.0.1')) return true
    return /^([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(:\d+)?$/.test(trimmed)
  }

  const handleContinue = (e: React.FormEvent) => {
    e.preventDefault()
    let cleanCookie = sessionCookie.trim()
    if (cleanCookie && !cleanCookie.includes('=')) {
      cleanCookie = `PHPSESSID=${cleanCookie}`
    }
    const cleanUrl = url.trim().replace(/^https?:\/\//, '')
    sessionStorage.setItem('sential_target_url', cleanUrl)
    sessionStorage.setItem('sential_assessment_name', assessmentName)
    sessionStorage.setItem('sential_environment', environment)
    sessionStorage.setItem('sential_auth_cookie', cleanCookie)
    sessionStorage.setItem('sential_auth_token', bearerToken)
    sessionStorage.setItem('sential_crawl_depth', String(crawlDepth))
    navigate('/assessment/step-3')
  }

  return (
    <AssessmentLayout currentStepTitle="Target URL">
      <form onSubmit={handleContinue} className="space-y-8 max-w-3xl">
        <div>
          <span className="text-xs font-bold text-blue-600 uppercase tracking-wider">New Assessment · Step 2 of 3</span>
          <h1 className="text-3xl font-extrabold text-slate-900 tracking-tight mt-1">What should we assess?</h1>
          <p className="text-sm text-slate-500 mt-1">
            Enter the public URL of the application you're authorized to test.
          </p>
        </div>

        {/* Main Card */}
        <div className="bg-white rounded-2xl border border-slate-200/90 p-8 shadow-xs space-y-6">
          <div className="flex items-center gap-3 pb-4 border-b border-slate-100">
            <div className="w-10 h-10 rounded-xl bg-blue-50 border border-blue-100 flex items-center justify-center text-blue-600">
              <Globe className="w-5 h-5" />
            </div>
            <div>
              <h3 className="font-bold text-slate-900 text-sm">Target application</h3>
              <p className="text-xs text-slate-400">We'll validate and crawl the target before starting.</p>
            </div>
          </div>

          {/* URL Input */}
          <div className="space-y-2">
            <label className="block text-xs font-bold text-slate-700">Application URL</label>
            <div className="flex items-center rounded-xl border border-slate-200 bg-white overflow-hidden focus-within:border-blue-600 focus-within:ring-2 focus-within:ring-blue-600/15">
              <span className="px-4 py-3 bg-slate-50 text-slate-500 text-sm font-medium border-r border-slate-200">
                https://
              </span>
              <input
                type="text"
                required
                value={url}
                onChange={(e) => setUrl(e.target.value.replace(/^https?:\/\//, ''))}
                placeholder="app.example.com"
                className="w-full px-4 py-3 text-sm text-slate-900 focus:outline-none bg-transparent"
              />
            </div>
            {isTargetValid(url) ? (
              <div className="flex items-center gap-1.5 text-xs text-emerald-600 font-medium pt-1">
                <Check className="w-4 h-4 stroke-[2.5]" />
                <span>Target entered and ready for crawling</span>
              </div>
            ) : url.trim().length > 0 ? (
              <p className="text-[11px] text-slate-400 font-medium pt-1">
                Enter a valid domain or host (e.g. app.example.com or mycompany.com)
              </p>
            ) : null}
          </div>

          {/* Assessment Name */}
          <div className="space-y-2">
            <label className="block text-xs font-bold text-slate-700">Assessment name</label>
            <input
              type="text"
              required
              value={assessmentName}
              onChange={(e) => setAssessmentName(e.target.value)}
              className="w-full px-4 py-3 rounded-xl border border-slate-200 text-sm text-slate-900 focus:outline-none focus:border-blue-600 focus:ring-2 focus:ring-blue-600/15"
            />
          </div>

          {/* Environment */}
          <div className="space-y-2">
            <label className="block text-xs font-bold text-slate-700">Environment</label>
            <div className="relative">
              <select
                value={environment}
                onChange={(e) => setEnvironment(e.target.value)}
                className="w-full appearance-none px-4 py-3 rounded-xl border border-slate-200 text-sm text-slate-900 focus:outline-none focus:border-blue-600 bg-white cursor-pointer"
              >
                <option value="Production">Production</option>
                <option value="Staging">Staging</option>
                <option value="QA / Testing">QA / Testing</option>
              </select>
              <ChevronDown className="w-4 h-4 text-slate-400 absolute right-4 top-3.5 pointer-events-none" />
            </div>
          </div>

          {/* Optional Source Code (SAST + DAST) ZIP Attachment Bar */}
          <div className="p-4 rounded-xl border border-slate-200 bg-slate-50/70 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-blue-100/70 text-blue-700 flex items-center justify-center shrink-0">
                <FileCode className="w-4 h-4" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold text-slate-900">Optional Source Code (SAST + DAST)</span>
                  <span className="text-[10px] font-bold bg-blue-100 text-blue-700 px-1.5 py-0.2 rounded">HYBRID</span>
                </div>
                <p className="text-[11px] text-slate-500">
                  {zipFileName ? `Attached: ${zipFileName}` : 'Attach project ZIP archive to scan source code alongside dynamic web tests.'}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2 self-end sm:self-auto">
              {zipFileName ? (
                <button
                  type="button"
                  onClick={() => {
                    setZipFileName(null)
                    sessionStorage.removeItem('sential_sast_zip')
                  }}
                  className="text-xs text-rose-600 hover:text-rose-700 font-semibold px-2.5 py-1 rounded-lg border border-rose-200 bg-rose-50 cursor-pointer"
                >
                  Remove ZIP
                </button>
              ) : (
                <label className="inline-flex items-center gap-1.5 text-xs font-semibold text-slate-700 bg-white hover:bg-slate-100 border border-slate-200 px-3.5 py-1.5 rounded-xl cursor-pointer shadow-xs transition-colors">
                  <Upload className="w-3.5 h-3.5 text-slate-500" />
                  <span>Attach ZIP</span>
                  <input
                    type="file"
                    accept=".zip,.tar,.gz"
                    className="hidden"
                    onChange={(e) => {
                      if (e.target.files && e.target.files[0]) {
                        setZipFileName(e.target.files[0].name)
                        sessionStorage.setItem('sential_sast_zip', e.target.files[0].name)
                      }
                    }}
                  />
                </label>
              )}
            </div>
          </div>

          {/* Authenticated Scanning & Spider Options: PROMINENT & HIGH PRIORITY */}
          <div className="rounded-2xl border-2 border-blue-500/30 bg-gradient-to-b from-blue-50/40 via-white to-slate-50/60 p-5 sm:p-6 shadow-sm space-y-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-blue-100">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-blue-600 text-white flex items-center justify-center shadow-md shadow-blue-500/25 shrink-0">
                  <KeyRound className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <h3 className="text-sm font-bold text-slate-900 tracking-tight">
                      Authenticated Scanning &amp; Web Spider Depth
                    </h3>
                    <span className="text-[10px] font-extrabold bg-blue-600 text-white px-2 py-0.5 rounded-full uppercase tracking-wider shadow-xs">
                      ⭐ HIGH PRIORITY / RECOMMENDED
                    </span>
                  </div>
                  <p className="text-xs text-slate-600 mt-0.5">
                    Bypass login barriers and discover protected administrative panels and internal routes.
                  </p>
                </div>
              </div>

              <button
                type="button"
                onClick={() => setShowGuide(!showGuide)}
                className="inline-flex items-center gap-1.5 text-xs font-bold text-blue-700 bg-blue-100/80 hover:bg-blue-200/80 px-3 py-1.5 rounded-lg transition-colors self-start sm:self-auto cursor-pointer"
              >
                <HelpCircle className="w-3.5 h-3.5" />
                <span>{showGuide ? 'Hide Extraction Guide' : '📖 How to extract Cookies & Tokens?'}</span>
              </button>
            </div>

            {/* In-UI Interactive Guide Box */}
            {showGuide && (
              <div className="bg-white rounded-xl border border-blue-200/90 p-4 text-xs text-slate-700 space-y-3 shadow-xs">
                <div className="flex items-center gap-2 text-blue-800 font-bold text-xs pb-2 border-b border-blue-100">
                  <Sparkles className="w-4 h-4 text-blue-600" />
                  <span>Quick Guide: How to extract Cookies &amp; Tokens Step-by-Step</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-[12px] leading-relaxed">
                  <div className="bg-slate-50 p-3.5 rounded-lg border border-slate-200/80 space-y-1.5">
                    <div className="font-bold text-slate-900 flex items-center gap-1.5">
                      <span className="w-5 h-5 rounded-full bg-blue-600 text-white text-[10px] flex items-center justify-center font-mono">1</span>
                      <span>How to extract Session Cookie (PHPSESSID):</span>
                    </div>
                    <ol className="list-decimal list-inside space-y-1 text-slate-600 text-[11px] pt-1">
                      <li>Open your website in your browser and log in with your Admin / Staff credentials.</li>
                      <li>Press <kbd className="px-1.5 py-0.5 bg-white border border-slate-300 rounded font-mono text-[10px]">F12</kbd> to open Developer Tools.</li>
                      <li>Navigate to the <b>Application</b> tab (in Chrome/Edge) or <b>Storage</b> tab (in Firefox).</li>
                      <li>From the left sidebar, expand <b>Cookies</b> and select your target domain.</li>
                      <li>Copy the <code>PHPSESSID</code> value and paste it into the field below (e.g. <code>PHPSESSID=4a8bc...</code>).</li>
                    </ol>
                  </div>

                  <div className="bg-slate-50 p-3.5 rounded-lg border border-slate-200/80 space-y-1.5">
                    <div className="font-bold text-slate-900 flex items-center gap-1.5">
                      <span className="w-5 h-5 rounded-full bg-indigo-600 text-white text-[10px] flex items-center justify-center font-mono">2</span>
                      <span>How to extract Bearer Token (for APIs &amp; JWT):</span>
                    </div>
                    <ol className="list-decimal list-inside space-y-1 text-slate-600 text-[11px] pt-1">
                      <li>In Developer Tools (<kbd className="px-1.5 py-0.5 bg-white border border-slate-300 rounded font-mono text-[10px]">F12</kbd>), switch to the <b>Network</b> tab.</li>
                      <li>Perform any action in your dashboard (open a page, save an item, or refresh a table).</li>
                      <li>Click on any (Fetch / XHR) request and select the <b>Headers</b> tab.</li>
                      <li>Locate the <b>Authorization</b> request header and copy its entire value (starts with <code>Bearer eyJ...</code>).</li>
                      <li>If your site is traditional PHP without a REST API, leave this empty and provide only PHPSESSID.</li>
                    </ol>
                  </div>
                </div>

                <div className="p-2.5 rounded-lg bg-emerald-50 border border-emerald-200 text-emerald-900 text-[11px] flex items-start gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                  <div>
                    <strong>Key Benefit:</strong> Adding authentication cookies allows the Sential AI scanner to reach behind login barriers, auditing sensitive admin interfaces (orders, delivery reps, reports, settings) and testing all input fields against SQLi, XSS, and BOLA vulnerabilities.
                  </div>
                </div>
              </div>
            )}

            {/* Inputs Grid */}
            <div className="space-y-4 pt-1">
              {/* Field 1: Session Cookie */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                    <span>Session Cookie (e.g. PHPSESSID=...)</span>
                    <span className="text-[10px] font-semibold text-blue-700 bg-blue-100/80 px-1.5 py-0.2 rounded font-sans">
                      Essential for PHP
                    </span>
                  </label>
                  <span className="text-[11px] text-slate-400 font-mono">Example: PHPSESSID=4a8bc...</span>
                </div>
                <input
                  type="text"
                  value={sessionCookie}
                  onChange={(e) => setSessionCookie(e.target.value)}
                  placeholder="PHPSESSID=4a8bc...; session=admin_user"
                  className="w-full px-3.5 py-2.5 rounded-xl border border-slate-300 bg-white text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 font-mono shadow-xs"
                />
                <p className="text-[11px] text-slate-500 mt-1">
                  Allows the crawler and fuzzer to discover and test authenticated internal routes and admin modules.
                </p>
              </div>

              {/* Field 2: Bearer Token */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                    <span>Bearer Token / Authorization Header</span>
                    <span className="text-[10px] font-semibold text-slate-600 bg-slate-100 px-1.5 py-0.2 rounded font-sans">
                      JWT / API
                    </span>
                  </label>
                  <span className="text-[11px] text-slate-400 font-mono">Bearer eyJhbGciOi...</span>
                </div>
                <input
                  type="text"
                  value={bearerToken}
                  onChange={(e) => setBearerToken(e.target.value)}
                  placeholder="Bearer eyJhbGciOi..."
                  className="w-full px-3.5 py-2.5 rounded-xl border border-slate-300 bg-white text-xs text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 font-mono shadow-xs"
                />
              </div>

              {/* Field 3: Crawl Depth */}
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <label className="text-xs font-bold text-slate-800 flex items-center gap-1.5">
                    <span>Web Spider Crawl Depth</span>
                    <span className="text-[10px] font-extrabold text-purple-700 bg-purple-100 px-1.5 py-0.2 rounded font-sans">
                      RECOMMENDED: Level 3
                    </span>
                  </label>
                </div>
                <select
                  value={crawlDepth}
                  onChange={(e) => setCrawlDepth(Number(e.target.value))}
                  className="w-full px-3.5 py-2.5 rounded-xl border border-slate-300 bg-white text-xs font-medium text-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500 cursor-pointer shadow-xs"
                >
                  <option value={1}>Level 1: Fast Surface (Home + direct links only)</option>
                  <option value={2}>Level 2: Standard Deep Crawl (Internal links + forms)</option>
                  <option value={3}>Level 3: Exhaustive Crawl (Full site depth + admin paths &amp; hidden PHP scripts) [RECOMMENDED]</option>
                </select>
                <p className="text-[11px] text-slate-500 mt-1">
                  <b>Level 3: Exhaustive Crawl</b> ensures the security spider crawls all internal scripts, form endpoints, and administrative control panels to detect hidden SQL Injection and XSS vulnerabilities.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Warning Banner */}
        <div className="bg-amber-50/70 border border-amber-200/60 rounded-2xl p-5 flex items-start gap-4 text-xs">
          <div className="w-8 h-8 rounded-lg bg-amber-100 text-amber-700 flex items-center justify-center shrink-0">
            <AlertTriangle className="w-4 h-4" />
          </div>
          <div>
            <h4 className="font-bold text-slate-900 text-sm mb-0.5">Only assess systems you own or have permission to test</h4>
            <p className="text-slate-600 leading-relaxed">
              Unauthorized security testing may be illegal and violate the target's terms of service.
            </p>
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center justify-between pt-6 border-t border-slate-200">
          <button
            type="button"
            onClick={() => navigate('/assessment/step-1')}
            className="px-5 py-2.5 rounded-xl border border-slate-300 text-slate-700 font-semibold text-sm hover:bg-slate-100 transition-colors"
          >
            Back
          </button>
          <button
            type="submit"
            className="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold text-sm px-6 py-2.5 rounded-xl shadow-sm transition-all hover:shadow"
          >
            <span>Continue</span>
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </form>
    </AssessmentLayout>
  )
}
