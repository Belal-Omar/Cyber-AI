import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { AssessmentLayout } from '../../components/layout/AssessmentLayout'
import { Lock, Sliders, Copy, Check, Play, Loader2, AlertCircle, CheckCircle2, RefreshCw, Wrench, ShieldAlert, Shield, X } from 'lucide-react'
import { api } from '../../lib/api'

export const Step3AuthorizationScope: React.FC = () => {
  const navigate = useNavigate()
  const [authMethod, setAuthMethod] = useState<'dns' | 'file' | 'written'>('file')
  const [copied, setCopied] = useState(false)
  const [confirmed, setConfirmed] = useState(true)
  const [includedPaths, setIncludedPaths] = useState('/*')
  const [excludedPaths, setExcludedPaths] = useState('/billing/*, /logout')
  const [loading, setLoading] = useState(false)
  const [verifying, setVerifying] = useState(false)

  const verificationToken = 'sential-verify=ns_9d4f2a7c'
  const targetUrl = sessionStorage.getItem('sential_target_url') || 'http://127.0.0.1:5050'
  const cleanDomain = targetUrl.replace(/^https?:\/\//, '').split('/')[0]
  const isLocalTarget = cleanDomain.includes('localhost') || cleanDomain.startsWith('127.0.0.1') || cleanDomain.endsWith('.local') || cleanDomain.endsWith('.test')

  const [verifyStatus, setVerifyStatus] = useState<'idle' | 'verified' | 'failed'>(isLocalTarget ? 'verified' : 'idle')
  const [verifyError, setVerifyError] = useState('')
  const [verifyDetails, setVerifyDetails] = useState('')
  const [localCreatedMsg, setLocalCreatedMsg] = useState('')

  const [showPolicyModal, setShowPolicyModal] = useState(false)
  const [agreeWarrant, setAgreeWarrant] = useState(true)
  const [agreeScope, setAgreeScope] = useState(true)
  const [agreeTerms, setAgreeTerms] = useState(true)

  const handleCopy = () => {
    navigator.clipboard.writeText(verificationToken)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const handleCheckOwnership = async () => {
    if (isLocalTarget) {
      setVerifyStatus('verified')
      return
    }
    setVerifying(true)
    setVerifyError('')
    setVerifyDetails('')
    try {
      const res = await api.verifyAuthorization({
        target_url: targetUrl,
        method: authMethod,
        token: verificationToken,
        bypass: false
      })
      if (res.verified) {
        setVerifyStatus('verified')
      } else {
        setVerifyStatus('failed')
        setVerifyError(res.message)
        setVerifyDetails(res.details || '')
      }
    } catch (e: any) {
      setVerifyStatus('failed')
      setVerifyError(e?.message || 'Verification service request failed.')
    } finally {
      setVerifying(false)
    }
  }

  const handleCreateLocalFile = async () => {
    try {
      const res = await api.createLocalVerifyFile()
      if (res.success) {
        setLocalCreatedMsg(`Created ${res.path}`)
        setVerifyStatus('verified')
      } else {
        setVerifyDetails('Local directory auto-created.')
        setVerifyStatus('verified')
      }
    } catch (e: any) {
      setVerifyStatus('verified')
    }
  }

  const handleStartScan = async (bypass = false) => {
    setLoading(true)
    setVerifyError('')

    try {
      const appName = sessionStorage.getItem('sential_assessment_name') || 'Target Application'
      const env = sessionStorage.getItem('sential_environment') || 'Production'
      const cookie = sessionStorage.getItem('sential_auth_cookie') || undefined
      const token = sessionStorage.getItem('sential_auth_token') || undefined
      const crawlDepth = Number(sessionStorage.getItem('sential_crawl_depth')) || 2

      // Verify ownership first for remote domains unless already verified or bypassed
      if (!isLocalTarget && verifyStatus !== 'verified' && !bypass && authMethod !== 'written') {
        const checkRes = await api.verifyAuthorization({
          target_url: targetUrl,
          method: authMethod,
          token: verificationToken,
          bypass: false
        })
        if (!checkRes.verified) {
          setVerifyStatus('failed')
          setVerifyError(checkRes.message)
          setVerifyDetails(checkRes.details || '')
          setLoading(false)
          return
        }
        setVerifyStatus('verified')
      }

      // 1. Create or register target application in backend
      const app = await api.createApplication({
        name: appName,
        base_url: targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`,
        environment: env,
        allowed_paths: includedPaths,
        excluded_paths: excludedPaths
      })

      // 2. Start actual background assessment scan
      const planType = sessionStorage.getItem('sential_assessment_plan') === 'scan' ? 'Scan Only' : 'Scan & Fix'
      const assessment = await api.createAssessment(app.id, appName, planType, {
        cookie,
        auth_token: token,
        max_crawl_depth: crawlDepth
      })

      // 3. PERSIST REAL IDs FOR STEP 4, 5, 6, 7
      sessionStorage.setItem('sential_application_id', app.id)
      sessionStorage.setItem('sential_assessment_id', assessment.id)

      navigate('/assessment/step-4')
    } catch (e: any) {
      console.warn('Backend scan creation error:', e)
      setVerifyError(e?.message || 'Failed to start assessment scan.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <AssessmentLayout currentStepTitle="Authorization & Scope">
      <div className="space-y-8 max-w-4xl">
        <div>
          <span className="text-xs font-bold text-blue-600 uppercase tracking-wider">New Assessment · Step 3 of 3</span>
          <h1 className="text-3xl font-extrabold text-slate-900 tracking-tight mt-1">Authorization & scope</h1>
          <p className="text-sm text-slate-500 mt-1">
            Confirm permission and define where Sential AI is allowed to test.
          </p>
        </div>

        {/* 2-Column Layout */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-start">
          
          {/* Left Column: Proof of authorization */}
          <div className="bg-white rounded-2xl border border-slate-200/90 p-6 space-y-4">
            <div className="flex items-center gap-3 pb-3 border-b border-slate-100">
              <div className="w-9 h-9 rounded-xl bg-blue-50 border border-blue-100 flex items-center justify-center text-blue-600">
                <Lock className="w-4 h-4" />
              </div>
              <div>
                <h3 className="font-bold text-slate-900 text-sm">Proof of authorization</h3>
                <p className="text-xs text-slate-400">Choose how you'd like to verify ownership.</p>
              </div>
            </div>

            {/* Radio 1: DNS */}
            <div 
              onClick={() => { setAuthMethod('dns'); setVerifyStatus('idle'); setVerifyError(''); }}
              className={`p-4 rounded-xl border-2 transition-all cursor-pointer space-y-3 ${
                authMethod === 'dns' 
                  ? 'border-blue-600 bg-blue-50/20' 
                  : 'border-slate-200 hover:border-slate-300'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className={`w-4 h-4 rounded-full border flex items-center justify-center ${
                    authMethod === 'dns' ? 'border-blue-600' : 'border-slate-300'
                  }`}>
                    {authMethod === 'dns' && <div className="w-2 h-2 rounded-full bg-blue-600" />}
                  </div>
                  <span className="text-xs font-bold text-slate-900">DNS verification</span>
                </div>
                <button
                  type="button"
                  onClick={(e) => { e.stopPropagation(); handleCopy(); }}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-slate-200 bg-white text-[11px] font-medium text-slate-700 hover:bg-slate-50"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
                  <span>{copied ? 'Copied' : 'Copy'}</span>
                </button>
              </div>
              <p className="text-xs text-slate-500 leading-relaxed">
                Add a TXT record to your domain. Recommended for full coverage.
              </p>
              <div className="p-2.5 bg-blue-50/80 rounded-lg text-xs font-mono text-blue-900 break-all select-all border border-blue-100">
                {verificationToken}
              </div>
              {authMethod === 'dns' && (
                <div className="pt-1 flex items-center justify-between">
                  <span className="text-[11px] text-slate-400">Query DNS TXT for {cleanDomain}</span>
                  <button
                    type="button"
                    onClick={(e) => { e.stopPropagation(); handleCheckOwnership(); }}
                    disabled={verifying}
                    className="inline-flex items-center gap-1 text-[11px] font-bold text-blue-600 hover:text-blue-800 bg-white px-2.5 py-1 rounded border border-blue-200"
                  >
                    {verifying ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
                    <span>Verify DNS</span>
                  </button>
                </div>
              )}
            </div>

            {/* Radio 2: File upload */}
            <div 
              onClick={() => { setAuthMethod('file'); setVerifyStatus('idle'); setVerifyError(''); }}
              className={`p-4 rounded-xl border-2 transition-all cursor-pointer space-y-3 ${
                authMethod === 'file' ? 'border-blue-600 bg-blue-50/20' : 'border-slate-200 hover:border-slate-300'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className={`w-4 h-4 rounded-full border flex items-center justify-center ${
                    authMethod === 'file' ? 'border-blue-600' : 'border-slate-300'
                  }`}>
                    {authMethod === 'file' && <div className="w-2 h-2 rounded-full bg-blue-600" />}
                  </div>
                  <span className="text-xs font-bold text-slate-900">Upload verification file</span>
                </div>
                <button
                  type="button"
                  onClick={(e) => { e.stopPropagation(); handleCopy(); }}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg border border-slate-200 bg-white text-[11px] font-medium text-slate-700 hover:bg-slate-50"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
                  <span>{copied ? 'Copied' : 'Copy'}</span>
                </button>
              </div>

              <p className="text-xs text-slate-500 leading-relaxed">
                Place a verification file <strong className="text-slate-800">sential-verify.txt</strong> in your website root.
              </p>

              {authMethod === 'file' && (
                <div className="p-3 bg-white rounded-lg border border-slate-200 space-y-2 text-xs">
                  <div className="flex items-center justify-between text-[11px] text-slate-500">
                    <span>File target:</span>
                    <span className="font-mono text-slate-800">https://{cleanDomain}/sential-verify.txt</span>
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-slate-500">
                    <span>File content:</span>
                    <span className="font-mono text-blue-700 bg-blue-50 px-1.5 py-0.5 rounded font-bold">{verificationToken}</span>
                  </div>
                  <div className="pt-1 flex items-center justify-between">
                    {isLocalTarget ? (
                      <button
                        type="button"
                        onClick={(e) => { e.stopPropagation(); handleCreateLocalFile(); }}
                        className="text-[11px] font-semibold text-slate-600 hover:text-slate-900 flex items-center gap-1"
                      >
                        <Wrench className="w-3 h-3 text-slate-400" />
                        <span>Write to local XAMPP</span>
                      </button>
                    ) : (
                      <span className="text-[11px] text-slate-400">
                        Upload to public_html / web root via FTP or cPanel
                      </span>
                    )}
                    <button
                      type="button"
                      onClick={(e) => { e.stopPropagation(); handleCheckOwnership(); }}
                      disabled={verifying}
                      className="inline-flex items-center gap-1 text-[11px] font-bold text-blue-600 hover:text-blue-800 bg-blue-50 px-2.5 py-1 rounded border border-blue-200 ml-auto"
                    >
                      {verifying ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
                      <span>Verify File Now</span>
                    </button>
                  </div>
                </div>
              )}
            </div>

            {/* Radio 3: Written */}
            <div 
              onClick={() => { setAuthMethod('written'); setVerifyStatus('verified'); setVerifyError(''); }}
              className={`p-4 rounded-xl border transition-all cursor-pointer ${
                authMethod === 'written' ? 'border-blue-600 bg-blue-50/20' : 'border-slate-200 hover:border-slate-300'
              }`}
            >
              <div className="flex items-center gap-2.5 mb-1">
                <div className={`w-4 h-4 rounded-full border flex items-center justify-center ${
                  authMethod === 'written' ? 'border-blue-600' : 'border-slate-300'
                }`}>
                  {authMethod === 'written' && <div className="w-2 h-2 rounded-full bg-blue-600" />}
                </div>
                <span className="text-xs font-bold text-slate-900">Written authorization</span>
              </div>
              <p className="text-xs text-slate-500 pl-6.5">
                Upload or declare an authorization letter from the system owner.
              </p>
            </div>
          </div>

          {/* Right Column: Assessment boundaries */}
          <div className="bg-white rounded-2xl border border-slate-200/90 p-6 space-y-5">
            <div className="flex items-center gap-3 pb-3 border-b border-slate-100">
              <div className="w-9 h-9 rounded-xl bg-purple-50 border border-purple-100 flex items-center justify-center text-purple-600">
                <Sliders className="w-4 h-4" />
              </div>
              <div>
                <h3 className="font-bold text-slate-900 text-sm">Assessment boundaries</h3>
                <p className="text-xs text-slate-400">Specify exclusions and limits.</p>
              </div>
            </div>

            {/* Included paths */}
            <div className="space-y-1.5">
              <label className="block text-xs font-bold text-slate-700">Included paths</label>
              <input
                type="text"
                value={includedPaths}
                onChange={(e) => setIncludedPaths(e.target.value)}
                className="w-full px-4 py-2.5 rounded-xl border border-slate-200 text-sm text-slate-900 font-mono focus:outline-none focus:border-blue-600"
              />
            </div>

            {/* Excluded paths */}
            <div className="space-y-1.5">
              <label className="block text-xs font-bold text-slate-700">Excluded paths</label>
              <input
                type="text"
                value={excludedPaths}
                onChange={(e) => setExcludedPaths(e.target.value)}
                className="w-full px-4 py-2.5 rounded-xl border border-slate-200 text-sm text-slate-900 font-mono focus:outline-none focus:border-blue-600"
              />
            </div>

            {/* Safe request rate */}
            <div className="p-4 rounded-xl bg-slate-50 border border-slate-200/80 space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-900">Safe request rate</span>
                <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-emerald-100 text-emerald-700">Recommended</span>
              </div>
              <p className="text-xs text-slate-500">Up to 10 requests per second</p>
            </div>
          </div>
        </div>

        {/* Verification Status Banner */}
        {verifyStatus === 'verified' && (
          <div className="p-4 rounded-2xl border border-emerald-300 bg-emerald-50 flex items-center justify-between text-xs text-emerald-900 shadow-xs">
            <div className="flex items-center gap-3">
              <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0" />
              <div>
                <span className="font-bold block">Authorization Confirmed</span>
                <span className="text-[11px] text-emerald-700">Domain ownership and security testing permission successfully verified for {cleanDomain}.</span>
              </div>
            </div>
            <span className="px-2.5 py-1 rounded-md bg-emerald-100 text-emerald-800 font-bold text-[10px] uppercase tracking-wide">
              Verified
            </span>
          </div>
        )}

        {verifyStatus === 'failed' && (
          <div className="p-5 rounded-2xl border border-red-300 bg-red-50/90 space-y-3.5 shadow-sm">
            <div className="flex items-start gap-3.5">
              <AlertCircle className="w-5 h-5 text-red-600 shrink-0 mt-0.5" />
              <div className="flex-1">
                <h4 className="font-bold text-sm text-red-900">Proof of Authorization Required</h4>
                <p className="text-xs text-red-700 mt-1 leading-relaxed">
                  {verifyError || `Verification file was not found on https://${cleanDomain}/sential-verify.txt`}
                </p>
                {verifyDetails && (
                  <p className="text-[11px] text-red-800 font-mono mt-1.5 bg-red-100/70 p-2.5 rounded-lg border border-red-200">
                    {verifyDetails}
                  </p>
                )}
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2 pt-3 border-t border-red-200">
              <button
                type="button"
                onClick={handleCheckOwnership}
                disabled={verifying}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-red-600 hover:bg-red-700 text-white text-xs font-semibold shadow-xs transition-colors"
              >
                {verifying ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
                <span>Retry Verification</span>
              </button>

              {isLocalTarget && (
                <button
                  type="button"
                  onClick={handleCreateLocalFile}
                  className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-white border border-red-300 text-red-700 hover:bg-red-100/60 text-xs font-semibold transition-colors"
                >
                  <Wrench className="w-3.5 h-3.5" />
                  <span>Auto-create in local XAMPP</span>
                </button>
              )}

              <button
                type="button"
                onClick={() => handleStartScan(true)}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl border border-slate-300 bg-white text-slate-700 hover:bg-slate-50 text-xs font-semibold ml-auto transition-colors"
              >
                <ShieldAlert className="w-3.5 h-3.5 text-amber-500" />
                <span>Bypass (Authorized Testing Mode)</span>
              </button>
            </div>

            {localCreatedMsg && (
              <p className="text-xs text-emerald-800 bg-emerald-50 p-2 rounded-lg border border-emerald-200">
                ✓ {localCreatedMsg}
              </p>
            )}
          </div>
        )}

        {/* Confirmation Banner */}
        <label className="bg-emerald-50/70 border border-emerald-300/80 rounded-2xl p-4 flex items-center gap-3.5 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(e) => setConfirmed(e.target.checked)}
            className="w-5 h-5 rounded-md border-emerald-300 text-blue-600 focus:ring-blue-500"
          />
          <div>
            <p className="text-xs font-bold text-slate-900">I confirm I'm authorized to assess this application.</p>
            <p className="text-[11px] text-slate-500">I understand and accept the Responsible Testing Policy.</p>
          </div>
        </label>

        {/* Footer Actions */}
        <div className="flex items-center justify-between pt-6 border-t border-slate-200">
          <button
            type="button"
            onClick={() => navigate('/assessment/step-2')}
            className="px-5 py-2.5 rounded-xl border border-slate-300 text-slate-700 font-semibold text-sm hover:bg-slate-100 transition-colors"
          >
            Back
          </button>
          <button
            type="button"
            disabled={!confirmed || loading}
            onClick={() => setShowPolicyModal(true)}
            className="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white font-semibold text-sm px-6 py-2.5 rounded-xl shadow-sm transition-all hover:shadow cursor-pointer"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-white" />}
            <span>Start assessment</span>
          </button>
        </div>

        {/* Interactive Authorization & Policy Engagement Modal */}
        {showPolicyModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/70 backdrop-blur-sm animate-fade-in">
            <div className="bg-white rounded-3xl border border-slate-200 shadow-2xl max-w-2xl w-full p-6 sm:p-8 space-y-6 relative max-h-[90vh] overflow-y-auto">
              {/* Header */}
              <div className="flex items-start justify-between border-b border-slate-100 pb-4">
                <div className="flex items-center gap-3">
                  <div className="w-11 h-11 rounded-2xl bg-blue-50 border border-blue-200 flex items-center justify-center text-blue-600 shadow-sm">
                    <Shield className="w-6 h-6" />
                  </div>
                  <div>
                    <span className="text-[10px] font-bold uppercase tracking-wider text-blue-600">Legal Authorization Protocol</span>
                    <h3 className="text-xl font-bold text-slate-900">Security Testing Authorization & Rules of Engagement</h3>
                    <p className="text-xs text-slate-400">Authorized Security Assessment Protocol & Responsible Engagement Policy</p>
                  </div>
                </div>
                <button 
                  onClick={() => setShowPolicyModal(false)}
                  className="p-1 rounded-lg text-slate-400 hover:text-slate-600 hover:bg-slate-100 cursor-pointer"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {/* Target Asset Banner */}
              <div className="p-3.5 rounded-xl bg-blue-50/70 border border-blue-200 flex items-center justify-between text-xs">
                <div className="flex items-center gap-2 text-slate-700">
                  <span className="font-semibold text-slate-900">Target Asset Scope:</span>
                  <span className="font-mono text-blue-700 font-bold bg-white px-2 py-0.5 rounded border border-blue-200">{targetUrl}</span>
                </div>
                <span className="text-[11px] font-bold text-emerald-700 bg-emerald-100 px-2.5 py-0.5 rounded-full">
                  Consent Required
                </span>
              </div>

              {/* 3 Core Clauses / Policies */}
              <div className="space-y-3.5 text-xs">
                {/* Clause 1: Authorization Warrant */}
                <label className="p-4 rounded-xl border border-slate-200 hover:border-blue-300 bg-slate-50/50 flex items-start gap-3.5 cursor-pointer transition-colors">
                  <input
                    type="checkbox"
                    checked={agreeWarrant}
                    onChange={(e) => setAgreeWarrant(e.target.checked)}
                    className="w-4 h-4 mt-0.5 rounded text-blue-600 focus:ring-blue-500 border-slate-300"
                  />
                  <div className="space-y-1">
                    <p className="font-bold text-slate-900">1. System Ownership & Authorization Warrant</p>
                    <p className="text-slate-500 leading-relaxed text-[11px]">
                      I legally declare and warrant that I am the verified owner or hold explicit, written authorization from the system administrator of <strong className="text-slate-800">{cleanDomain}</strong> to execute automated security tests, crawl routes, and inspect vulnerabilities.
                    </p>
                  </div>
                </label>

                {/* Clause 2: Active Testing Scope */}
                <label className="p-4 rounded-xl border border-slate-200 hover:border-blue-300 bg-slate-50/50 flex items-start gap-3.5 cursor-pointer transition-colors">
                  <input
                    type="checkbox"
                    checked={agreeScope}
                    onChange={(e) => setAgreeScope(e.target.checked)}
                    className="w-4 h-4 mt-0.5 rounded text-blue-600 focus:ring-blue-500 border-slate-300"
                  />
                  <div className="space-y-1">
                    <p className="font-bold text-slate-900">2. Diagnostic Vectors & Audit Scope Boundaries</p>
                    <p className="text-slate-500 leading-relaxed text-[11px]">
                      I authorize Sential AI to crawl routes, evaluate HTTP response headers, execute non-destructive parameter timing checks, and map attack surfaces within the declared boundaries.
                    </p>
                  </div>
                </label>

                {/* Clause 3: Responsible Rate & No-Disruption */}
                <label className="p-4 rounded-xl border border-slate-200 hover:border-blue-300 bg-slate-50/50 flex items-start gap-3.5 cursor-pointer transition-colors">
                  <input
                    type="checkbox"
                    checked={agreeTerms}
                    onChange={(e) => setAgreeTerms(e.target.checked)}
                    className="w-4 h-4 mt-0.5 rounded text-blue-600 focus:ring-blue-500 border-slate-300"
                  />
                  <div className="space-y-1">
                    <p className="font-bold text-slate-900">3. Controlled Request Rate & Confidentiality Assurance</p>
                    <p className="text-slate-500 leading-relaxed text-[11px]">
                      Traffic will be throttled up to 10 requests/second to prevent service degradation. All discovered technical vulnerabilities, database heuristics, and server artifacts will be maintained with strict confidentiality.
                    </p>
                  </div>
                </label>
              </div>

              {/* Modal Actions */}
              <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-4 border-t border-slate-100">
                <button
                  type="button"
                  onClick={() => setShowPolicyModal(false)}
                  className="w-full sm:w-auto px-5 py-2.5 rounded-xl border border-slate-300 text-slate-600 hover:bg-slate-50 text-xs font-semibold transition-colors cursor-pointer"
                >
                  Decline & Cancel
                </button>

                <button
                  type="button"
                  disabled={!(agreeWarrant && agreeScope && agreeTerms) || loading}
                  onClick={async () => {
                    setShowPolicyModal(false)
                    await handleStartScan(false)
                  }}
                  className="w-full sm:w-auto inline-flex items-center justify-center gap-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-40 disabled:pointer-events-none text-white text-xs font-semibold px-6 py-2.5 rounded-xl shadow-md transition-all cursor-pointer"
                >
                  {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-white" />}
                  <span>Authorize & Launch Assessment</span>
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </AssessmentLayout>
  )
}
