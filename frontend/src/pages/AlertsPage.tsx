import React, { useState, useEffect } from 'react'
import { AssessmentLayout } from '../components/layout/AssessmentLayout'
import { 
  Bell, 
  Send, 
  CheckCircle2, 
  Bot
} from 'lucide-react'
import { api } from '../lib/api'

export const AlertsPage: React.FC = () => {
  const [channels, setChannels] = useState<any>({})
  const [testingChannel, setTestingChannel] = useState<string | null>(null)
  const [testResult, setTestResult] = useState<any>(null)

  const loadChannels = async () => {
    try {
      const res = await api.getAlertChannels()
      if (res?.channels) setChannels(res.channels)
    } catch (e) {
      console.error(e)
    }
  }

  useEffect(() => {
    loadChannels()
  }, [])

  const handleToggle = async (channelKey: string) => {
    const current = channels[channelKey] || {}
    const updated = { ...current, channel_name: channelKey, enabled: !current.enabled }
    try {
      await api.updateAlertChannel(updated)
      setChannels((prev: any) => ({ ...prev, [channelKey]: updated }))
    } catch (e: any) {
      alert('Failed to update channel: ' + e.message)
    }
  }

  const handleTestAlert = async (channelKey: string) => {
    try {
      setTestingChannel(channelKey)
      setTestResult(null)
      const res = await api.testAlert({
        channel: channelKey,
        finding_title: 'Critical Remote Code Execution via Insecure Deserialization',
        severity: 'CRITICAL',
        target_url: 'https://example.com/api/v1/checkout',
        cvss_score: 9.8
      })
      setTestResult(res)
    } catch (e: any) {
      alert('Alert test failed: ' + e.message)
    } finally {
      setTestingChannel(null)
    }
  }

  return (
    <AssessmentLayout currentStepTitle="Omnichannel Security Alerts Hub">
      <div className="space-y-6">
        {/* Banner */}
        <div className="bg-gradient-to-r from-slate-900 via-rose-950 to-slate-900 border border-rose-900/60 rounded-2xl p-7 text-white shadow-lg relative overflow-hidden">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-5 relative z-10">
            <div>
              <div className="flex items-center gap-2 mb-2">
                <span className="text-xs uppercase font-bold tracking-widest text-rose-400 bg-rose-950/80 border border-rose-800/80 px-2.5 py-0.5 rounded-full flex items-center gap-1.5">
                  <Bell className="w-3.5 h-3.5" />
                  Instant Incident Response Broadcast
                </span>
              </div>
              <h1 className="text-2xl font-bold tracking-tight text-white mb-1.5">
                Omnichannel Security Alerts
              </h1>
              <p className="text-sm text-slate-300 max-w-2xl leading-relaxed">
                Security teams don't stare at dashboards 24/7. Connect your live Slack, Discord, Microsoft Teams, and Telegram channels to receive rich interactive cards the second a Critical finding is detected.
              </p>
            </div>
          </div>
        </div>

        {/* Channels Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {/* 1. Slack */}
          <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-emerald-50 border border-emerald-100 flex items-center justify-center text-emerald-700 font-black text-sm">
                    #
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-slate-900">Slack Webhook</h3>
                    <p className="text-[11px] text-slate-400">#devsecops-alerts channel</p>
                  </div>
                </div>

                <button
                  onClick={() => handleToggle('slack')}
                  className={`px-3 py-1 text-xs font-bold rounded-full transition-all border ${
                    channels?.slack?.enabled
                      ? 'bg-emerald-50 border-emerald-200 text-emerald-700'
                      : 'bg-slate-100 border-slate-200 text-slate-500'
                  }`}
                >
                  {channels?.slack?.enabled ? 'Active' : 'Disabled'}
                </button>
              </div>

              <div className="space-y-2 mb-4">
                <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Webhook URL</label>
                <input
                  type="text"
                  readOnly
                  value={channels?.slack?.webhook_url || ''}
                  className="w-full text-xs font-mono bg-slate-50 border border-slate-200 rounded-lg p-2.5 text-slate-600 truncate"
                />
              </div>

              <div className="flex items-center gap-1.5 mb-5">
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mr-1">Triggers:</span>
                <span className="px-2 py-0.5 rounded bg-rose-100 text-rose-700 text-[10px] font-bold">CRITICAL</span>
                <span className="px-2 py-0.5 rounded bg-amber-100 text-amber-700 text-[10px] font-bold">HIGH</span>
              </div>
            </div>

            <button
              onClick={() => handleTestAlert('slack')}
              disabled={testingChannel === 'slack'}
              className="w-full py-2.5 rounded-xl bg-slate-900 hover:bg-slate-800 text-white font-semibold text-xs transition-all flex items-center justify-center gap-2"
            >
              <Send className={`w-3.5 h-3.5 ${testingChannel === 'slack' ? 'animate-spin' : ''}`} />
              {testingChannel === 'slack' ? 'Sending Test...' : 'Send Test Slack Card'}
            </button>
          </div>

          {/* 2. Discord */}
          <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-indigo-50 border border-indigo-100 flex items-center justify-center text-indigo-700 font-black text-sm">
                    D
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-slate-900">Discord Bot Webhook</h3>
                    <p className="text-[11px] text-slate-400">security-radar channel</p>
                  </div>
                </div>

                <button
                  onClick={() => handleToggle('discord')}
                  className={`px-3 py-1 text-xs font-bold rounded-full transition-all border ${
                    channels?.discord?.enabled
                      ? 'bg-emerald-50 border-emerald-200 text-emerald-700'
                      : 'bg-slate-100 border-slate-200 text-slate-500'
                  }`}
                >
                  {channels?.discord?.enabled ? 'Active' : 'Disabled'}
                </button>
              </div>

              <div className="space-y-2 mb-4">
                <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Webhook URL</label>
                <input
                  type="text"
                  readOnly
                  value={channels?.discord?.webhook_url || ''}
                  className="w-full text-xs font-mono bg-slate-50 border border-slate-200 rounded-lg p-2.5 text-slate-600 truncate"
                />
              </div>

              <div className="flex items-center gap-1.5 mb-5">
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mr-1">Triggers:</span>
                <span className="px-2 py-0.5 rounded bg-rose-100 text-rose-700 text-[10px] font-bold">CRITICAL</span>
              </div>
            </div>

            <button
              onClick={() => handleTestAlert('discord')}
              disabled={testingChannel === 'discord'}
              className="w-full py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white font-semibold text-xs transition-all flex items-center justify-center gap-2"
            >
              <Send className={`w-3.5 h-3.5 ${testingChannel === 'discord' ? 'animate-spin' : ''}`} />
              {testingChannel === 'discord' ? 'Sending Test...' : 'Send Test Discord Embed'}
            </button>
          </div>

          {/* 3. Telegram */}
          <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-sky-50 border border-sky-100 flex items-center justify-center text-sky-600 font-black text-sm">
                    TG
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-slate-900">Telegram Bot</h3>
                    <p className="text-[11px] text-slate-400">@sential_security_alerts</p>
                  </div>
                </div>

                <button
                  onClick={() => handleToggle('telegram')}
                  className={`px-3 py-1 text-xs font-bold rounded-full transition-all border ${
                    channels?.telegram?.enabled
                      ? 'bg-emerald-50 border-emerald-200 text-emerald-700'
                      : 'bg-slate-100 border-slate-200 text-slate-500'
                  }`}
                >
                  {channels?.telegram?.enabled ? 'Active' : 'Disabled'}
                </button>
              </div>

              <div className="space-y-2 mb-4">
                <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Chat ID / Channel</label>
                <input
                  type="text"
                  readOnly
                  value={channels?.telegram?.chat_id || '@sential_security_alerts'}
                  className="w-full text-xs font-mono bg-slate-50 border border-slate-200 rounded-lg p-2.5 text-slate-600 truncate"
                />
              </div>

              <div className="flex items-center gap-1.5 mb-5">
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mr-1">Triggers:</span>
                <span className="px-2 py-0.5 rounded bg-rose-100 text-rose-700 text-[10px] font-bold">CRITICAL</span>
                <span className="px-2 py-0.5 rounded bg-amber-100 text-amber-700 text-[10px] font-bold">HIGH</span>
              </div>
            </div>

            <button
              onClick={() => handleTestAlert('telegram')}
              disabled={testingChannel === 'telegram'}
              className="w-full py-2.5 rounded-xl bg-sky-600 hover:bg-sky-500 text-white font-semibold text-xs transition-all flex items-center justify-center gap-2"
            >
              <Send className={`w-3.5 h-3.5 ${testingChannel === 'telegram' ? 'animate-spin' : ''}`} />
              {testingChannel === 'telegram' ? 'Sending Test...' : 'Send Test Telegram Card'}
            </button>
          </div>

          {/* 4. Microsoft Teams */}
          <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-xl bg-blue-50 border border-blue-100 flex items-center justify-center text-blue-700 font-black text-sm">
                    T
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-slate-900">Microsoft Teams</h3>
                    <p className="text-[11px] text-slate-400">Security Operations Channel</p>
                  </div>
                </div>

                <button
                  onClick={() => handleToggle('teams')}
                  className={`px-3 py-1 text-xs font-bold rounded-full transition-all border ${
                    channels?.teams?.enabled
                      ? 'bg-emerald-50 border-emerald-200 text-emerald-700'
                      : 'bg-slate-100 border-slate-200 text-slate-500'
                  }`}
                >
                  {channels?.teams?.enabled ? 'Active' : 'Disabled'}
                </button>
              </div>

              <div className="space-y-2 mb-4">
                <label className="text-[10px] font-bold uppercase tracking-wider text-slate-400">Incoming Webhook</label>
                <input
                  type="text"
                  readOnly
                  placeholder="https://outlook.office.com/webhook/..."
                  className="w-full text-xs font-mono bg-slate-50 border border-slate-200 rounded-lg p-2.5 text-slate-600 truncate"
                />
              </div>

              <div className="flex items-center gap-1.5 mb-5">
                <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 mr-1">Triggers:</span>
                <span className="px-2 py-0.5 rounded bg-rose-100 text-rose-700 text-[10px] font-bold">CRITICAL</span>
              </div>
            </div>

            <button
              onClick={() => handleTestAlert('teams')}
              disabled={testingChannel === 'teams'}
              className="w-full py-2.5 rounded-xl bg-blue-700 hover:bg-blue-600 text-white font-semibold text-xs transition-all flex items-center justify-center gap-2"
            >
              <Send className={`w-3.5 h-3.5 ${testingChannel === 'teams' ? 'animate-spin' : ''}`} />
              {testingChannel === 'teams' ? 'Sending Test...' : 'Send Test Teams Card'}
            </button>
          </div>
        </div>

        {/* Live Card Preview Box */}
        {testResult && (
          <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-xs space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                <h3 className="text-sm font-bold text-slate-900">
                  Live Dispatch Verified: {testResult.message}
                </h3>
              </div>
              <span className="text-[11px] font-mono bg-emerald-50 text-emerald-700 border border-emerald-200 px-2.5 py-0.5 rounded-full font-bold">
                {testResult.delivery_status}
              </span>
            </div>

            {/* Render realistic rich webhook card */}
            <div className="max-w-xl mx-auto p-4 rounded-xl bg-slate-900 text-white border-l-4 border-l-rose-500 shadow-md font-sans">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                  <Bot className="w-3.5 h-3.5 text-rose-400" />
                  Sential AI Omnichannel Sentinel
                </span>
                <span className="text-[10px] font-mono text-slate-500">{testResult.card_preview?.dispatched_at}</span>
              </div>

              <div className="space-y-1.5 mb-3">
                <p className="text-xs font-bold text-rose-400">
                  🚨 [{testResult.card_preview?.severity}] {testResult.card_preview?.title}
                </p>
                <p className="text-[11px] text-slate-300">
                  Target Endpoint: <span className="font-mono text-slate-400">{testResult.card_preview?.target}</span>
                </p>
                <p className="text-[11px] text-slate-300">
                  CVSS Base Score: <span className="font-mono font-bold text-rose-400">{testResult.card_preview?.cvss}</span> / 10.0
                </p>
              </div>

              {/* Action Buttons */}
              <div className="flex flex-wrap gap-2 pt-2 border-t border-slate-800">
                {(testResult.card_preview?.action_buttons || []).map((btn: any) => (
                  <button
                    key={btn.label}
                    onClick={() => alert(`Action '${btn.action}' triggered from Omnichannel notification!`)}
                    className="px-3 py-1 text-[11px] font-semibold rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
                  >
                    {btn.label}
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </AssessmentLayout>
  )
}
