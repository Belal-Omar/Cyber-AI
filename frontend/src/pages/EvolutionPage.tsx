import React, { useState, useEffect } from 'react'
import { AssessmentLayout } from '../components/layout/AssessmentLayout'
import { 
  GitCommit, 
  History, 
  CheckCircle2, 
  AlertTriangle, 
  TrendingUp, 
  GitBranch
} from 'lucide-react'
import { api } from '../lib/api'

export const EvolutionPage: React.FC = () => {
  const [data, setData] = useState<any>(null)
  const [filter, setFilter] = useState<'all' | 'fixed' | 'regression'>('all')

  useEffect(() => {
    api.getEvolutionHistory().then(res => {
      setData(res)
    }).catch(console.error)
  }, [])

  const vulnerabilities = data?.vulnerabilities_timeline || []
  const filteredVulnerabilities = vulnerabilities.filter((v: any) => {
    if (filter === 'fixed') return v.current_status === 'FIXED'
    if (filter === 'regression') return v.regression_status === 'REGRESSION_DETECTED'
    return true
  })

  return (
    <AssessmentLayout currentStepTitle="Security Evolution & Regression Memory">
      <div className="space-y-6">
        {/* Hero Header */}
        <div className="bg-gradient-to-r from-slate-900 via-blue-950 to-slate-900 border border-blue-900/60 rounded-2xl p-7 text-white shadow-lg relative overflow-hidden">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-5 relative z-10">
            <div>
              <div className="flex items-center gap-2 mb-2">
                <span className="text-xs uppercase font-bold tracking-widest text-blue-400 bg-blue-950/80 border border-blue-800/80 px-2.5 py-0.5 rounded-full flex items-center gap-1.5">
                  <History className="w-3.5 h-3.5" />
                  Historical Security Memory & Audit Trail
                </span>
              </div>
              <h1 className="text-2xl font-bold tracking-tight text-white mb-1.5">
                Security Regression Memory
              </h1>
              <p className="text-sm text-slate-300 max-w-2xl leading-relaxed">
                Remembers the entire historical security timeline of your application across Git commits. Detects fixed issues, newly introduced vulnerabilities, and automatically warns when previously resolved bugs get re-introduced.
              </p>
            </div>

            <div className="bg-white/10 backdrop-blur-sm border border-white/15 rounded-xl p-4 flex items-center gap-6 shrink-0">
              <div>
                <p className="text-[10px] font-bold text-slate-400 uppercase">Current Posture</p>
                <p className="text-2xl font-black text-emerald-400">{data?.current_posture_score || 92}%</p>
              </div>
              <div className="border-l border-white/10 pl-6">
                <p className="text-[10px] font-bold text-slate-400 uppercase">Improvement</p>
                <p className="text-2xl font-black text-blue-400 flex items-center gap-0.5">
                  {data?.posture_improvement || '+30%'}
                  <TrendingUp className="w-4 h-4" />
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* 4 Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs">
            <p className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-1">Vulnerabilities Fixed</p>
            <p className="text-2xl font-bold text-emerald-600">{data?.stats?.fixed_total || 3}</p>
            <p className="text-xs text-slate-500 mt-1">Verified resolved via AI Diff</p>
          </div>

          <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs">
            <p className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-1">Regression Alert</p>
            <p className="text-2xl font-bold text-amber-500">{data?.stats?.regressed_count || 1}</p>
            <p className="text-xs text-slate-500 mt-1">Re-opened after prior fix</p>
          </div>

          <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs">
            <p className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-1">New In Last Scan</p>
            <p className="text-2xl font-bold text-indigo-600">{data?.stats?.new_introduced || 1}</p>
            <p className="text-xs text-slate-500 mt-1">Introduced in latest release</p>
          </div>

          <div className="bg-white border border-slate-200 rounded-2xl p-5 shadow-xs">
            <p className="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-1">Historical Scans</p>
            <p className="text-2xl font-bold text-slate-800">{data?.total_historical_scans || 3}</p>
            <p className="text-xs text-slate-500 mt-1">Linked to repository commits</p>
          </div>
        </div>

        {/* Timeline Table */}
        <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-100">
            <div>
              <h3 className="text-sm font-bold text-slate-900">Vulnerability Lifecycle & Git Commit Linkage</h3>
              <p className="text-xs text-slate-500">Cross-scan diff analysis comparing findings fingerprint against commit history</p>
            </div>

            <div className="flex items-center gap-1.5 bg-slate-100 p-1 rounded-xl">
              <button
                onClick={() => setFilter('all')}
                className={`px-3 py-1 text-xs font-semibold rounded-lg transition-all ${
                  filter === 'all' ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                All Findings
              </button>
              <button
                onClick={() => setFilter('fixed')}
                className={`px-3 py-1 text-xs font-semibold rounded-lg transition-all ${
                  filter === 'fixed' ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Fixed
              </button>
              <button
                onClick={() => setFilter('regression')}
                className={`px-3 py-1 text-xs font-semibold rounded-lg transition-all ${
                  filter === 'regression' ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600 hover:text-slate-900'
                }`}
              >
                Regressions
              </button>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="text-[10px] uppercase font-bold text-slate-400 bg-slate-50 border-y border-slate-100">
                <tr>
                  <th className="py-2.5 px-3">Vulnerability & CWE</th>
                  <th className="py-2.5 px-3">Severity</th>
                  <th className="py-2.5 px-3">First Seen Commit</th>
                  <th className="py-2.5 px-3">Resolved Commit</th>
                  <th className="py-2.5 px-3">Regression Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100 font-sans">
                {filteredVulnerabilities.map((v: any) => (
                  <tr key={v.fingerprint} className="hover:bg-slate-50/70 transition-colors">
                    <td className="py-3 px-3">
                      <p className="font-bold text-slate-900">{v.title}</p>
                      <p className="text-[11px] font-mono text-slate-400">{v.cwe} • Fingerprint: {v.fingerprint}</p>
                      {v.regression_note && (
                        <p className="text-[11px] font-semibold text-amber-700 bg-amber-50 border border-amber-200/60 px-2 py-0.5 rounded mt-1 inline-block">
                          {v.regression_note}
                        </p>
                      )}
                    </td>

                    <td className="py-3 px-3">
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                        v.severity === 'CRITICAL' ? 'bg-rose-100 text-rose-700' :
                        v.severity === 'HIGH' ? 'bg-amber-100 text-amber-700' :
                        v.severity === 'MEDIUM' ? 'bg-blue-100 text-blue-700' : 'bg-slate-100 text-slate-700'
                      }`}>
                        {v.severity}
                      </span>
                    </td>

                    <td className="py-3 px-3">
                      <div className="flex items-center gap-1.5 font-mono text-slate-700">
                        <GitCommit className="w-3.5 h-3.5 text-slate-400" />
                        <span className="font-semibold">{v.first_seen_commit}</span>
                      </div>
                      <span className="text-[11px] text-slate-400">{v.first_seen}</span>
                    </td>

                    <td className="py-3 px-3">
                      {v.resolved_commit ? (
                        <div>
                          <div className="flex items-center gap-1.5 font-mono text-emerald-700">
                            <GitCommit className="w-3.5 h-3.5 text-emerald-500" />
                            <span className="font-semibold">{v.resolved_commit}</span>
                          </div>
                          <span className="text-[11px] text-slate-400">{v.resolved_at}</span>
                        </div>
                      ) : (
                        <span className="text-slate-400 font-mono italic">Unresolved</span>
                      )}
                    </td>

                    <td className="py-3 px-3">
                      {v.regression_status === 'STABLE_FIXED' && (
                        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-emerald-50 text-emerald-700 font-semibold text-[10px]">
                          <CheckCircle2 className="w-3 h-3" />
                          STABLE FIXED
                        </span>
                      )}
                      {v.regression_status === 'REGRESSION_DETECTED' && (
                        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-amber-100 text-amber-800 font-bold text-[10px]">
                          <AlertTriangle className="w-3 h-3" />
                          REGRESSION ⚠️
                        </span>
                      )}
                      {v.regression_status === 'NEW_INTRODUCED' && (
                        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-blue-100 text-blue-800 font-semibold text-[10px]">
                          NEW 🆕
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Historical Scans Commits List */}
        <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs">
          <h3 className="text-sm font-bold text-slate-900 mb-4 flex items-center gap-2">
            <GitBranch className="w-4 h-4 text-blue-600" />
            Repository Scan Timeline
          </h3>
          <div className="space-y-3">
            {(data?.scans || []).map((s: any) => (
              <div key={s.scan_id} className="p-4 rounded-xl border border-slate-100 bg-slate-50/60 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-blue-50 text-blue-700 flex items-center justify-center font-bold text-xs font-mono shrink-0">
                    {s.security_score}%
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-slate-800">{s.commit_hash}</span>
                      <span className="text-xs text-slate-600 font-medium">{s.commit_message}</span>
                    </div>
                    <p className="text-[11px] text-slate-400 mt-0.5">{s.author} • {s.timestamp}</p>
                  </div>
                </div>

                <div className="flex items-center gap-4 text-xs font-medium">
                  <span className="text-slate-600">{s.total_findings} Findings</span>
                  <span className="px-2.5 py-1 rounded-md bg-emerald-50 text-emerald-700 font-bold text-[10px]">
                    {s.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </AssessmentLayout>
  )
}
