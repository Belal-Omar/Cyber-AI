import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { AssessmentLayout } from '../../components/layout/AssessmentLayout'
import { Search, Sparkles, ShieldCheck, ChevronRight, Zap, ShieldAlert, Flame, Server } from 'lucide-react'

export const Step1AssessmentType: React.FC = () => {
  const navigate = useNavigate()
  const [selectedPlan, setSelectedPlan] = useState<'scan' | 'scan_fix'>(() => {
    const saved = sessionStorage.getItem('sential_assessment_plan')
    return saved === 'scan' ? 'scan' : 'scan_fix'
  })

  const [selectedProfile, setSelectedProfile] = useState<'quick' | 'owasp' | 'deep' | 'api'>(() => {
    const saved = sessionStorage.getItem('sential_scan_profile')
    return (saved as any) || 'owasp'
  })

  const plans = [
    {
      id: 'scan',
      tag: 'FAST ASSESSMENT',
      icon: Search,
      title: 'Scan Only',
      desc: 'Identify, crawl, and prioritize all vulnerabilities across the attack surface without generating patches.',
      duration: '~10 minutes',
    },
    {
      id: 'scan_fix',
      tag: 'RECOMMENDED',
      icon: Sparkles,
      title: 'Scan & Fix',
      desc: 'Deep vulnerability assessment combined with AI-generated remediation code patches, diffs, and configuration fixes.',
      duration: '~20 minutes',
    },
  ]

  const scanProfiles = [
    {
      id: 'quick',
      name: 'Quick Health Check',
      duration: '1 Minute',
      icon: Zap,
      badge: 'Lightweight',
      desc: 'Rapid security headers, SSL/TLS certificate lifetime, and server banner disclosure verification.',
      color: 'text-amber-600 bg-amber-50 border-amber-200'
    },
    {
      id: 'owasp',
      name: 'OWASP Baseline Scan',
      duration: '3 Minutes',
      icon: ShieldAlert,
      badge: 'Most Popular',
      desc: 'Comprehensive coverage of OWASP Top 10 web flaws: SQLi, XSS, CSRF, sensitive files, and access controls.',
      color: 'text-blue-600 bg-blue-50 border-blue-200'
    },
    {
      id: 'deep',
      name: 'Deep Red-Team Audit',
      duration: 'Full Depth',
      icon: Flame,
      badge: 'Full Arsenal',
      desc: 'Maximum crawling depth, active SSRF probing, IDOR enumeration, LFI/RFI, SSTI, and secrets scanning.',
      color: 'text-rose-600 bg-rose-50 border-rose-200'
    },
    {
      id: 'api',
      name: 'API-Only Scan',
      duration: 'Targeted',
      icon: Server,
      badge: 'REST & GraphQL',
      desc: 'Auto-detects Swagger/OpenAPI blueprints, probes GraphQL introspection, and audits authentication rate limits.',
      color: 'text-indigo-600 bg-indigo-50 border-indigo-200'
    }
  ]

  const handleContinue = () => {
    sessionStorage.setItem('sential_assessment_plan', selectedPlan)
    sessionStorage.setItem('sential_scan_profile', selectedProfile)
    navigate('/assessment/step-2')
  }

  return (
    <AssessmentLayout currentStepTitle="Assessment Type">
      <div className="space-y-8 max-w-4xl">
        <div>
          <span className="text-xs font-bold text-blue-600 uppercase tracking-wider">New Assessment · Step 1 of 3</span>
          <h1 className="text-3xl font-extrabold text-slate-900 tracking-tight mt-1">What would you like us to do?</h1>
          <p className="text-sm text-slate-500 mt-1">
            Choose your assessment mode and targeted audit profile. You can inspect all findings and approve suggested fixes before applying.
          </p>
        </div>

        {/* 2 Main Action Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {plans.map((p) => {
            const isSelected = selectedPlan === p.id
            const Icon = p.icon

            return (
              <div
                key={p.id}
                onClick={() => setSelectedPlan(p.id as any)}
                className={`relative bg-white rounded-2xl p-7 border-2 transition-all cursor-pointer flex flex-col justify-between ${
                  isSelected 
                    ? 'border-blue-600 shadow-lg shadow-blue-500/10 ring-2 ring-blue-600/20' 
                    : 'border-slate-200/90 hover:border-slate-300'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-5">
                    <div className={`w-11 h-11 rounded-xl flex items-center justify-center ${
                      isSelected ? 'bg-blue-50 text-blue-600' : 'bg-slate-100 text-slate-500'
                    }`}>
                      <Icon className="w-5 h-5" />
                    </div>
                    <span className={`text-[10px] font-bold px-2.5 py-1 rounded tracking-wider uppercase ${
                      p.tag === 'RECOMMENDED'
                        ? 'bg-blue-100 text-blue-700'
                        : 'bg-slate-100 text-slate-600'
                    }`}>
                      {p.tag}
                    </span>
                  </div>

                  <h3 className="font-bold text-slate-900 text-xl mb-2">{p.title}</h3>
                  <p className="text-sm text-slate-500 leading-relaxed mb-6">{p.desc}</p>
                </div>

                <div className="pt-4 border-t border-slate-100 flex items-center justify-between text-xs text-slate-500 font-medium">
                  <span>⏱ {p.duration}</span>
                  <div className={`w-5 h-5 rounded-full border flex items-center justify-center ${
                    isSelected ? 'border-blue-600' : 'border-slate-300'
                  }`}>
                    {isSelected && <div className="w-2.5 h-2.5 rounded-full bg-blue-600" />}
                  </div>
                </div>
              </div>
            )
          })}
        </div>

        {/* Pillar 4: Scan Profiles Selector */}
        <div className="bg-slate-50/90 border border-slate-200/80 rounded-2xl p-6">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-base font-bold text-slate-900">Customized Scan Profile (وضع الفحص المخصص)</h3>
              <p className="text-xs text-slate-500">Fine-tune the security engine's payload depth and test vector aggression</p>
            </div>
            <span className="text-[11px] font-semibold text-slate-600 bg-white border border-slate-200 px-2.5 py-1 rounded-md">
              Selected: <strong className="text-blue-600 capitalize">{selectedProfile} Profile</strong>
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
            {scanProfiles.map((sp) => {
              const isSelected = selectedProfile === sp.id
              const Icon = sp.icon
              return (
                <div
                  key={sp.id}
                  onClick={() => setSelectedProfile(sp.id as any)}
                  className={`p-4 rounded-xl border-2 transition-all cursor-pointer bg-white flex items-start gap-3.5 ${
                    isSelected
                      ? 'border-blue-600 ring-2 ring-blue-500/10 shadow-sm'
                      : 'border-slate-200 hover:border-slate-300'
                  }`}
                >
                  <div className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 border ${sp.color}`}>
                    <Icon className="w-4 h-4" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <span className="font-bold text-sm text-slate-900">{sp.name}</span>
                      <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 shrink-0">
                        {sp.duration}
                      </span>
                    </div>
                    <p className="text-xs text-slate-500 leading-snug">{sp.desc}</p>
                  </div>
                  <div className={`w-4 h-4 rounded-full border mt-0.5 shrink-0 flex items-center justify-center ${
                    isSelected ? 'border-blue-600' : 'border-slate-300'
                  }`}>
                    {isSelected && <div className="w-2 h-2 rounded-full bg-blue-600" />}
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Control & Safety Callout */}
        <div className="bg-emerald-50/70 border border-emerald-200/60 rounded-2xl p-5 flex items-start gap-4 text-xs text-slate-700">
          <div className="w-8 h-8 rounded-lg bg-emerald-100 text-emerald-700 flex items-center justify-center shrink-0">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <h4 className="font-bold text-slate-900 text-sm mb-0.5">You're always in control</h4>
            <p className="text-slate-600 leading-relaxed">
              We never deploy changes automatically. Review and approve every suggested fix before applying it to your production infrastructure.
            </p>
          </div>
        </div>

        {/* Footer Navigation Buttons */}
        <div className="flex items-center justify-between pt-6 border-t border-slate-200">
          <button 
            type="button" 
            onClick={() => navigate('/')} 
            className="px-5 py-2.5 rounded-xl border border-slate-300 text-slate-700 font-semibold text-sm hover:bg-slate-100 transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleContinue}
            className="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white font-semibold text-sm px-6 py-2.5 rounded-xl shadow-sm transition-all hover:shadow cursor-pointer"
          >
            <span>Continue</span>
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </AssessmentLayout>
  )
}

