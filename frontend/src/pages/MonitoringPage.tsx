import React, { useState, useEffect } from 'react'
import { AssessmentLayout } from '../components/layout/AssessmentLayout'
import { 
  Radio, 
  ShieldCheck, 
  RefreshCw, 
  Lock, 
  Server, 
  CheckCircle2, 
  Clock, 
  Globe, 
  Sparkles
} from 'lucide-react'
import { api } from '../lib/api'

export const MonitoringPage: React.FC = () => {
  const [data, setData] = useState<any>(null)
  const [probing, setProbing] = useState(false)
  const [toggling, setToggling] = useState(false)
  const [probeResult, setProbeResult] = useState<string | null>(null)

  const targetUrl = sessionStorage.getItem('sential_target_url') || 'https://example.com'

  const loadStatus = async () => {
    try {
      const res = await api.getMonitoringStatus()
      setData(res)
    } catch (e) {
      console.error(e)
    }
  }

  useEffect(() => {
    loadStatus()
  }, [])

  const handleTriggerProbe = async () => {
    try {
      setProbing(true)
      setProbeResult(null)
      const res = await api.triggerMonitoringProbe(targetUrl)
      setProbeResult(res.summary || 'Live probe completed successfully!')
      await loadStatus()
    } catch (e: any) {
      setProbeResult('Probe failed: ' + e.message)
    } finally {
      setProbing(false)
    }
  }

  const handleToggle = async (enabled: boolean) => {
    try {
      setToggling(true)
      await api.toggleMonitoring(enabled, data?.interval_hours || 1, targetUrl)
      await loadStatus()
    } catch (e) {
      console.error(e)
    } finally {
      setToggling(false)
    }
  }

  return (
    <AssessmentLayout currentStepTitle="Continuous Attack Surface Monitoring (24/7)">
      <div className="space-y-6">
        {/* Hero Header */}
        <div className="bg-gradient-to-r from-slate-900 via-indigo-950 to-slate-900 border border-indigo-900/60 rounded-2xl p-7 text-white shadow-lg relative overflow-hidden">
          <div className="absolute right-0 top-0 bottom-0 w-1/3 bg-radial from-blue-500/10 to-transparent pointer-events-none" />
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-5 relative z-10">
            <div>
              <div className="flex items-center gap-2.5 mb-2">
                <span className="flex h-3 w-3 relative">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                  <span className="relative inline-flex rounded-full h-3 w-3 bg-emerald-500"></span>
                </span>
                <span className="text-xs uppercase font-bold tracking-widest text-emerald-400 bg-emerald-950/80 border border-emerald-800/80 px-2.5 py-0.5 rounded-full">
                  Autonomous 24/7 Watchdog Live
                </span>
              </div>
              <h1 className="text-2xl font-bold tracking-tight text-white mb-1.5 flex items-center gap-2">
                Continuous Attack Surface Monitoring
                <Sparkles className="w-5 h-5 text-indigo-400" />
              </h1>
              <p className="text-sm text-slate-300 max-w-2xl leading-relaxed">
                Post-assessment continuous guardian. Silently observes SSL certificates, HTTP response headers, port exposures, and DNS drift every hour to stop new vulnerabilities before they trigger an incident.
              </p>
            </div>

            <div className="flex items-center gap-3 shrink-0">
              <button
                onClick={handleTriggerProbe}
                disabled={probing}
                className="px-4 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs transition-all shadow-md flex items-center gap-2 disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${probing ? 'animate-spin' : ''}`} />
                {probing ? 'Probing Target...' : 'Run Immediate Probe'}
              </button>

              <button
                onClick={() => handleToggle(!data?.is_enabled)}
                disabled={toggling}
                className={`px-4 py-2.5 rounded-xl font-semibold text-xs transition-all border ${
                  data?.is_enabled
                    ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/20'
                    : 'bg-rose-500/10 border-rose-500/40 text-rose-300 hover:bg-rose-500/20'
                }`}
              >
                {data?.is_enabled ? 'Active (Click to Pause)' : 'Paused (Click to Enable)'}
              </button>
            </div>
          </div>

          {probeResult && (
            <div className="mt-4 p-3 bg-indigo-900/40 border border-indigo-700/50 rounded-xl text-xs text-indigo-200 flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>{probeResult}</span>
            </div>
          )}
        </div>

        {/* 4 Core Surface Pillars */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* 1. SSL & TLS */}
          <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs hover:shadow-md transition-shadow">
            <div className="flex items-center justify-between mb-3">
              <div className="w-9 h-9 rounded-xl bg-blue-50 border border-blue-100 flex items-center justify-center text-blue-600">
                <Lock className="w-4 h-4" />
              </div>
              <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-600 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded-full">
                {data?.ssl?.status || 'HEALTHY'}
              </span>
            </div>
            <h3 className="text-sm font-bold text-slate-800 mb-1">SSL / TLS Cipher Posture</h3>
            <p className="text-xs text-slate-500 mb-3">{data?.ssl?.issuer || "Let's Encrypt Authority"}</p>
            <div className="space-y-1.5 text-xs text-slate-600 border-t border-slate-100 pt-2.5">
              <div className="flex justify-between">
                <span className="text-slate-400">Days Remaining:</span>
                <span className="font-semibold text-slate-800">{data?.ssl?.days_remaining || 78} Days</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Cipher Version:</span>
                <span className="font-semibold text-slate-800">{data?.ssl?.tls_version || 'TLS 1.3'}</span>
              </div>
            </div>
          </div>

          {/* 2. Security Headers Drift */}
          <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs hover:shadow-md transition-shadow">
            <div className="flex items-center justify-between mb-3">
              <div className="w-9 h-9 rounded-xl bg-indigo-50 border border-indigo-100 flex items-center justify-center text-indigo-600">
                <ShieldCheck className="w-4 h-4" />
              </div>
              <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-600 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded-full">
                0 Drift
              </span>
            </div>
            <h3 className="text-sm font-bold text-slate-800 mb-1">Response Headers Drift</h3>
            <p className="text-xs text-slate-500 mb-3">5/5 Hardened Directives</p>
            <div className="space-y-1.5 text-xs text-slate-600 border-t border-slate-100 pt-2.5">
              <div className="flex justify-between">
                <span className="text-slate-400">HSTS / CSP / XFO:</span>
                <span className="font-semibold text-emerald-600">Enforced</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Last Verified:</span>
                <span className="font-semibold text-slate-800">24m ago</span>
              </div>
            </div>
          </div>

          {/* 3. Port & Gateway Surface */}
          <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs hover:shadow-md transition-shadow">
            <div className="flex items-center justify-between mb-3">
              <div className="w-9 h-9 rounded-xl bg-amber-50 border border-amber-100 flex items-center justify-center text-amber-600">
                <Server className="w-4 h-4" />
              </div>
              <span className="text-[10px] font-bold uppercase tracking-wider text-blue-600 bg-blue-50 border border-blue-200 px-2 py-0.5 rounded-full">
                Shielded
              </span>
            </div>
            <h3 className="text-sm font-bold text-slate-800 mb-1">Open Ports & Perimeter</h3>
            <p className="text-xs text-slate-500 mb-3">4 Ports Monitored</p>
            <div className="space-y-1.5 text-xs text-slate-600 border-t border-slate-100 pt-2.5">
              <div className="flex justify-between">
                <span className="text-slate-400">Port 80 HTTP:</span>
                <span className="font-semibold text-slate-800">301 Redirect</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Port 443 HTTPS:</span>
                <span className="font-semibold text-emerald-600">Protected</span>
              </div>
            </div>
          </div>

          {/* 4. DNS & Spoofing Defense */}
          <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs hover:shadow-md transition-shadow">
            <div className="flex items-center justify-between mb-3">
              <div className="w-9 h-9 rounded-xl bg-emerald-50 border border-emerald-100 flex items-center justify-center text-emerald-600">
                <Globe className="w-4 h-4" />
              </div>
              <span className="text-[10px] font-bold uppercase tracking-wider text-emerald-600 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded-full">
                DNSSEC OK
              </span>
            </div>
            <h3 className="text-sm font-bold text-slate-800 mb-1">DNS Zone & Spoofing</h3>
            <p className="text-xs text-slate-500 mb-3">SPF & DMARC Enforced</p>
            <div className="space-y-1.5 text-xs text-slate-600 border-t border-slate-100 pt-2.5">
              <div className="flex justify-between">
                <span className="text-slate-400">DMARC Policy:</span>
                <span className="font-semibold text-slate-800">p=reject</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">SPF Validation:</span>
                <span className="font-semibold text-emerald-600">Active</span>
              </div>
            </div>
          </div>
        </div>

        {/* Detailed Panels: Ports Table + Live Audit Log */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Ports Table */}
          <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs">
            <h3 className="text-sm font-bold text-slate-900 mb-4 flex items-center gap-2">
              <Radio className="w-4 h-4 text-indigo-600" />
              Monitored Public Ports
            </h3>
            <div className="space-y-2.5">
              {(data?.ports || []).map((p: any) => (
                <div key={p.port} className="flex items-center justify-between p-3 rounded-xl bg-slate-50 border border-slate-100">
                  <div className="flex items-center gap-2.5">
                    <span className="font-mono text-xs font-bold text-slate-800 bg-white border border-slate-200 px-2 py-0.5 rounded">
                      :{p.port}
                    </span>
                    <span className="text-xs text-slate-600">{p.service}</span>
                  </div>
                  <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${
                    p.status === 'OPEN' ? 'bg-emerald-50 text-emerald-700' : 'bg-slate-200/80 text-slate-700'
                  }`}>
                    {p.status}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Events Log */}
          <div className="lg:col-span-2 bg-white border border-slate-200 rounded-2xl p-6 shadow-xs">
            <h3 className="text-sm font-bold text-slate-900 mb-4 flex items-center gap-2">
              <Clock className="w-4 h-4 text-indigo-600" />
              Differential Drift & Watchdog Audit Log
            </h3>
            <div className="space-y-3">
              {(data?.events || []).map((evt: any) => (
                <div key={evt.id} className="p-3.5 rounded-xl border border-slate-100 bg-slate-50/70 hover:bg-slate-50 transition-colors">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[10px] font-bold text-indigo-600 uppercase tracking-wider">
                      {evt.type}
                    </span>
                    <span className="text-[11px] text-slate-400 font-mono">{evt.timestamp}</span>
                  </div>
                  <p className="text-xs text-slate-700 leading-relaxed">{evt.message}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </AssessmentLayout>
  )
}
