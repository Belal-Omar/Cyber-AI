import React, { useState, useEffect } from 'react'
import { AssessmentLayout } from '../components/layout/AssessmentLayout'
import { 
  Sparkles, 
  Play, 
  CheckCircle2, 
  AlertOctagon, 
  BookOpen, 
  Code, 
  ChevronRight,
  Eye
} from 'lucide-react'
import { api } from '../lib/api'

export const IntentCompilerPage: React.FC = () => {
  const [rulesText, setRulesText] = useState(
`Every user must only see and edit their own private account profile and billing records.
The checkout cart endpoint must reject negative numbers or zero quantity.
Unauthenticated visitors must not access any endpoints under /api/v1/admin/*.`
  )
  const [compiling, setCompiling] = useState(false)
  const [templates, setTemplates] = useState<any[]>([])
  const [report, setReport] = useState<any>(null)
  const [expandedRule, setExpandedRule] = useState<string | null>(null)

  useEffect(() => {
    api.getIntentTemplates().then(res => {
      if (res?.templates) setTemplates(res.templates)
    }).catch(console.error)
  }, [])

  const handleApplyTemplate = (tpl: any) => {
    setRulesText(tpl.rules.join('\n'))
  }

  const handleCompile = async () => {
    try {
      setCompiling(true)
      const lines = rulesText.split('\n').map(l => l.trim()).filter(l => l.length > 3)
      const res = await api.compileAndTestIntent(lines)
      setReport(res)
      if (res?.evaluations?.length > 0) {
        setExpandedRule(res.evaluations[0].id)
      }
    } catch (e: any) {
      alert('Failed to compile intent: ' + e.message)
    } finally {
      setCompiling(false)
    }
  }

  return (
    <AssessmentLayout currentStepTitle="Security Intent Compiler (Business Logic)">
      <div className="space-y-6">
        {/* Banner */}
        <div className="bg-gradient-to-r from-slate-900 via-purple-950 to-slate-900 border border-purple-900/60 rounded-2xl p-7 text-white shadow-lg relative overflow-hidden">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-5 relative z-10">
            <div>
              <div className="flex items-center gap-2 mb-2">
                <span className="text-xs uppercase font-bold tracking-widest text-purple-400 bg-purple-950/80 border border-purple-800/80 px-2.5 py-0.5 rounded-full flex items-center gap-1.5">
                  <Sparkles className="w-3 h-3 text-purple-400" />
                  Intent-Driven Business Logic Testing
                </span>
              </div>
              <h1 className="text-2xl font-bold tracking-tight text-white mb-1.5">
                Security Intent Compiler
              </h1>
              <p className="text-sm text-slate-300 max-w-2xl leading-relaxed">
                Define your website's custom security and business logic policies in plain natural language. Sential AI automatically synthesizes dual-account test harnesses (User A vs User B) to verify compliance and catch logic flaws that traditional scanners miss.
              </p>
            </div>

            <button
              onClick={handleCompile}
              disabled={compiling}
              className="px-6 py-3 rounded-xl bg-purple-600 hover:bg-purple-500 text-white font-bold text-xs uppercase tracking-wider transition-all shadow-lg shadow-purple-600/30 flex items-center gap-2 shrink-0 disabled:opacity-50"
            >
              <Play className={`w-4 h-4 fill-white ${compiling ? 'animate-spin' : ''}`} />
              {compiling ? 'Compiling & Testing Harness...' : 'Compile & Test Intent'}
            </button>
          </div>
        </div>

        {/* Templates Row */}
        <div>
          <div className="flex items-center justify-between mb-2.5">
            <h2 className="text-xs font-bold text-slate-500 uppercase tracking-wider flex items-center gap-1.5">
              <BookOpen className="w-3.5 h-3.5" />
              Pre-built Policy Templates
            </h2>
            <span className="text-[11px] text-slate-400">Click any template to auto-populate</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {templates.map(tpl => (
              <button
                key={tpl.id}
                onClick={() => handleApplyTemplate(tpl)}
                className="text-left p-4 rounded-xl border border-slate-200 bg-white hover:border-purple-300 hover:bg-purple-50/30 transition-all group"
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-[10px] font-bold text-purple-600 uppercase tracking-wider bg-purple-50 px-2 py-0.5 rounded">
                    {tpl.category}
                  </span>
                  <ChevronRight className="w-4 h-4 text-slate-400 group-hover:text-purple-600 group-hover:translate-x-0.5 transition-all" />
                </div>
                <h3 className="text-xs font-bold text-slate-800 mb-1">{tpl.name}</h3>
                <p className="text-[11px] text-slate-500 line-clamp-2">{tpl.rules[0]}</p>
              </button>
            ))}
          </div>
        </div>

        {/* Editor Box */}
        <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Code className="w-4 h-4 text-purple-600" />
              <label className="text-xs font-bold text-slate-800 uppercase tracking-wider">
                Natural Language Rules Input (One rule per line)
              </label>
            </div>
            <span className="text-[11px] font-mono text-slate-400">Supports English & Arabic plain text</span>
          </div>

          <textarea
            value={rulesText}
            onChange={(e) => setRulesText(e.target.value)}
            rows={5}
            placeholder="Type your security intent here (e.g., 'Each user should only see their own orders', 'Quantity cannot be negative')..."
            className="w-full font-mono text-xs text-slate-800 bg-slate-50 border border-slate-200 rounded-xl p-4 focus:outline-none focus:border-purple-500 focus:ring-2 focus:ring-purple-100 transition-all leading-relaxed resize-none"
          />

          <div className="mt-3 flex items-center justify-between text-xs text-slate-500">
            <span>{rulesText.split('\n').filter(l => l.trim()).length} Rules Active</span>
            <span className="text-purple-600 font-medium">Dual-Tenant Simulation Matrix Ready</span>
          </div>
        </div>

        {/* Results / Intent Compliance Report */}
        {report && (
          <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs space-y-6">
            <div className="flex flex-col md:flex-row md:items-center justify-between pb-6 border-b border-slate-100 gap-4">
              <div>
                <span className="text-[10px] font-bold text-emerald-600 uppercase tracking-wider bg-emerald-50 border border-emerald-200 px-2.5 py-0.5 rounded-full">
                  Report ID: {report.report_id}
                </span>
                <h3 className="text-lg font-bold text-slate-900 mt-1">Intent Compliance Verification</h3>
                <p className="text-xs text-slate-500">Target: {report.target_url} • Generated {report.timestamp}</p>
              </div>

              <div className="flex items-center gap-6">
                <div className="text-center">
                  <p className="text-[11px] font-bold text-slate-400 uppercase">Compliance</p>
                  <p className="text-2xl font-black text-purple-600">{report.compliance_score}%</p>
                </div>
                <div className="text-center">
                  <p className="text-[11px] font-bold text-slate-400 uppercase">Compliant</p>
                  <p className="text-2xl font-black text-emerald-600">{report.compliant_count}</p>
                </div>
                <div className="text-center">
                  <p className="text-[11px] font-bold text-slate-400 uppercase">Violations</p>
                  <p className="text-2xl font-black text-rose-600">{report.violations_count}</p>
                </div>
              </div>
            </div>

            {/* List of evaluated rules */}
            <div className="space-y-4">
              {report.evaluations.map((evalItem: any) => {
                const isCompliant = evalItem.status === 'COMPLIANT'
                const isExpanded = expandedRule === evalItem.id

                return (
                  <div 
                    key={evalItem.id} 
                    className={`border rounded-xl transition-all overflow-hidden ${
                      isCompliant ? 'border-slate-200 bg-white' : 'border-rose-300 bg-rose-50/20'
                    }`}
                  >
                    <div 
                      onClick={() => setExpandedRule(isExpanded ? null : evalItem.id)}
                      className="p-4 flex items-center justify-between cursor-pointer hover:bg-slate-50 transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        {isCompliant ? (
                          <div className="w-8 h-8 rounded-lg bg-emerald-50 text-emerald-600 flex items-center justify-center shrink-0">
                            <CheckCircle2 className="w-5 h-5" />
                          </div>
                        ) : (
                          <div className="w-8 h-8 rounded-lg bg-rose-50 text-rose-600 flex items-center justify-center shrink-0">
                            <AlertOctagon className="w-5 h-5" />
                          </div>
                        )}
                        <div>
                          <p className="text-xs font-bold text-slate-900">{evalItem.intent_text}</p>
                          <p className="text-[11px] text-slate-500 font-mono mt-0.5">{evalItem.category} • Confidence: {evalItem.confidence}%</p>
                        </div>
                      </div>

                      <div className="flex items-center gap-3">
                        <span className={`text-[10px] font-bold px-2.5 py-1 rounded-full ${
                          isCompliant ? 'bg-emerald-100 text-emerald-700' : 'bg-rose-100 text-rose-700'
                        }`}>
                          {isCompliant ? 'COMPLIANT ✅' : 'VIOLATION DETECTED ❌'}
                        </span>
                        <ChevronRight className={`w-4 h-4 text-slate-400 transition-transform ${isExpanded ? 'rotate-90' : ''}`} />
                      </div>
                    </div>

                    {/* Expandable Technical Proof */}
                    {isExpanded && (
                      <div className="px-5 pb-5 pt-2 border-t border-slate-100 bg-slate-50/60 space-y-3 text-xs">
                        <div>
                          <p className="font-bold text-slate-700 mb-1 flex items-center gap-1.5">
                            <Eye className="w-3.5 h-3.5 text-purple-600" />
                            Synthetic Test Vector & Execution Proof:
                          </p>
                          <p className="text-slate-600 mb-2">{evalItem.execution_details?.proof_summary}</p>
                          
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono text-[11px]">
                            <div className="p-3 rounded-lg bg-slate-900 text-slate-200">
                              <p className="text-slate-400 mb-1 font-sans text-[10px] uppercase font-bold tracking-wider">Simulated Probe Request</p>
                              <pre className="whitespace-pre-wrap leading-tight">{evalItem.execution_details?.probe_request}</pre>
                            </div>
                            <div className="p-3 rounded-lg bg-slate-900 text-slate-200">
                              <p className="text-slate-400 mb-1 font-sans text-[10px] uppercase font-bold tracking-wider">Target Server Response</p>
                              <pre className="whitespace-pre-wrap leading-tight text-emerald-400">{evalItem.execution_details?.probe_response}</pre>
                            </div>
                          </div>
                        </div>

                        <div className="p-3 bg-purple-50 border border-purple-200/70 rounded-lg text-purple-900">
                          <span className="font-bold">Remediation Guidance: </span>
                          <span>{evalItem.remediation_hint}</span>
                        </div>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </div>
    </AssessmentLayout>
  )
}
