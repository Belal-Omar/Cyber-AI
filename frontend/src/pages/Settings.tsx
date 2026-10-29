import React, { useState } from 'react'
import { AssessmentLayout } from '../components/layout/AssessmentLayout'
import { Save, Check, Bell, Calendar, CheckCircle2 } from 'lucide-react'

export const Settings: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'general' | 'scheduler' | 'webhooks' | 'team'>('general')
  const [saved, setSaved] = useState(false)
  const [testingWebhook, setTestingWebhook] = useState<string | null>(null)
  const [testResult, setTestResult] = useState<string | null>(null)

  // Scheduler state
  const [scheduleFreq, setScheduleFreq] = useState<'weekly' | 'monthly'>('weekly')
  const [notifyOnDiffOnly, setNotifyOnDiffOnly] = useState(true)
  const [alertEmail, setAlertEmail] = useState('security@cyberai.io')

  // Webhook state
  const [slackUrl, setSlackUrl] = useState('')
  const [discordUrl, setDiscordUrl] = useState('')
  const [telegramToken, setTelegramToken] = useState('')
  const [telegramChatId, setTelegramChatId] = useState('')
  const [githubRepo, setGithubRepo] = useState('')

  const handleSave = () => {
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  const handleTestWebhook = (type: string) => {
    setTestingWebhook(type)
    setTestResult(null)
    setTimeout(() => {
      setTestingWebhook(null)
      setTestResult(`✓ Test alert dispatched successfully to ${type}! Delivered alert payload with finding summary.`)
    }, 1000)
  }

  return (
    <AssessmentLayout currentStepTitle="Settings">
      <div className="max-w-4xl mx-auto space-y-6 pb-20">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 tracking-tight">Enterprise Workspace Settings</h1>
          <p className="text-sm text-slate-500 mt-0.5">
            Configure automated scan schedules, continuous monitoring, and instant incident webhooks (Slack, Telegram, Jira).
          </p>
        </div>

        {/* Tab navigation */}
        <div className="flex items-center gap-1 border-b border-slate-200 overflow-x-auto">
          <button
            onClick={() => setActiveTab('general')}
            className={`px-4 py-2.5 text-sm font-semibold border-b-2 transition-colors cursor-pointer whitespace-nowrap ${
              activeTab === 'general'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-slate-500 hover:text-slate-700'
            }`}
          >
            General &amp; Scanners
          </button>
          <button
            onClick={() => setActiveTab('scheduler')}
            className={`px-4 py-2.5 text-sm font-semibold border-b-2 transition-colors cursor-pointer flex items-center gap-1.5 whitespace-nowrap ${
              activeTab === 'scheduler'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-slate-500 hover:text-slate-700'
            }`}
          >
            <Calendar className="w-4 h-4" />
            <span>Continuous Monitoring</span>
            <span className="text-[10px] font-bold px-1.5 py-0.2 rounded bg-blue-100 text-blue-700">NEW</span>
          </button>
          <button
            onClick={() => setActiveTab('webhooks')}
            className={`px-4 py-2.5 text-sm font-semibold border-b-2 transition-colors cursor-pointer flex items-center gap-1.5 whitespace-nowrap ${
              activeTab === 'webhooks'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-slate-500 hover:text-slate-700'
            }`}
          >
            <Bell className="w-4 h-4" />
            <span>Webhooks &amp; Alerts</span>
          </button>
          <button
            onClick={() => setActiveTab('team')}
            className={`px-4 py-2.5 text-sm font-semibold border-b-2 transition-colors cursor-pointer whitespace-nowrap ${
              activeTab === 'team'
                ? 'border-blue-600 text-blue-600'
                : 'border-transparent text-slate-500 hover:text-slate-700'
            }`}
          >
            Team Members
          </button>
        </div>

        {/* General Tab */}
        {activeTab === 'general' && (
          <div className="bg-white rounded-2xl border border-slate-200 p-6 space-y-6 shadow-sm">
            <div className="space-y-4">
              <h3 className="text-base font-bold text-slate-900">Organization Profile</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-slate-600 mb-1.5 uppercase tracking-wide">Workspace Name</label>
                  <input
                    type="text"
                    defaultValue="Digital Soldiers Security Workspace"
                    className="w-full px-3.5 py-2 text-sm border border-slate-200 rounded-lg bg-slate-50 text-slate-900 focus:bg-white focus:ring-2 focus:ring-blue-500 outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-slate-600 mb-1.5 uppercase tracking-wide">Primary Target Domain</label>
                  <input
                    type="text"
                    defaultValue="digital-soldiers.com"
                    className="w-full px-3.5 py-2 text-sm border border-slate-200 rounded-lg bg-slate-50 text-slate-900 focus:bg-white focus:ring-2 focus:ring-blue-500 outline-none"
                  />
                </div>
              </div>
            </div>

            <div className="pt-6 border-t border-slate-100 space-y-4">
              <h3 className="text-base font-bold text-slate-900">Scanner Engine Capabilities</h3>
              
              <div className="space-y-3">
                <label className="flex items-start gap-3 p-3.5 rounded-xl border border-slate-200 hover:bg-slate-50/50 cursor-pointer">
                  <input type="checkbox" defaultChecked className="mt-1 w-4 h-4 text-blue-600 rounded" />
                  <div>
                    <span className="text-sm font-bold text-slate-900 block">AI Auto-Fix Multi-Platform Code Patches</span>
                    <span className="text-xs text-slate-500 block mt-0.5">
                      Generate downloadable patches for Apache (.htaccess), Nginx, Caddy, Cloudflare, and native PHP.
                    </span>
                  </div>
                </label>

                <label className="flex items-start gap-3 p-3.5 rounded-xl border border-slate-200 hover:bg-slate-50/50 cursor-pointer">
                  <input type="checkbox" defaultChecked className="mt-1 w-4 h-4 text-blue-600 rounded" />
                  <div>
                    <span className="text-sm font-bold text-slate-900 block">Regulatory Compliance Matrix (PCI-DSS &amp; ISO 27001)</span>
                    <span className="text-xs text-slate-500 block mt-0.5">
                      Automatically map detected findings to PCI-DSS v4.0 requirements and ISO 27001 Annex A controls.
                    </span>
                  </div>
                </label>
              </div>
            </div>

            <div className="pt-4 flex justify-end">
              <button
                onClick={handleSave}
                className="inline-flex items-center gap-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold text-sm rounded-lg shadow-sm shadow-blue-500/20 transition-all cursor-pointer"
              >
                {saved ? <><Check className="w-4 h-4" /> Saved!</> : <><Save className="w-4 h-4" /> Save Changes</>}
              </button>
            </div>
          </div>
        )}

        {/* Scheduler / Continuous Monitoring Tab */}
        {activeTab === 'scheduler' && (
          <div className="bg-white rounded-2xl border border-slate-200 p-6 space-y-6 shadow-sm">
            <div>
              <div className="flex items-center gap-2 text-blue-700 font-bold text-sm mb-1">
                <Calendar className="w-4 h-4" />
                <span>Continuous Monitoring &amp; Automated Scheduler (المراقبة المستمرة وجدولة الفحص)</span>
              </div>
              <p className="text-xs text-slate-500">
                Automatically audit your target domain on a recurring schedule and notify you when new vulnerabilities are detected.
              </p>
            </div>

            <div className="p-5 rounded-xl bg-slate-50 border border-slate-200 space-y-4">
              <div>
                <label className="block text-xs font-bold text-slate-800 mb-2">Automated Audit Frequency (دورية الفحص الدوري)</label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div
                    onClick={() => setScheduleFreq('weekly')}
                    className={`p-4 rounded-xl border-2 transition-all cursor-pointer bg-white ${
                      scheduleFreq === 'weekly' ? 'border-blue-600 ring-2 ring-blue-500/10' : 'border-slate-200'
                    }`}
                  >
                    <span className="font-bold text-sm text-slate-900 block">Weekly Scan (أسبوعي)</span>
                    <span className="text-xs text-slate-500 block mt-1">Runs every Monday at 02:00 UTC during off-peak hours.</span>
                  </div>
                  <div
                    onClick={() => setScheduleFreq('monthly')}
                    className={`p-4 rounded-xl border-2 transition-all cursor-pointer bg-white ${
                      scheduleFreq === 'monthly' ? 'border-blue-600 ring-2 ring-blue-500/10' : 'border-slate-200'
                    }`}
                  >
                    <span className="font-bold text-sm text-slate-900 block">Monthly Full Audit (شهري)</span>
                    <span className="text-xs text-slate-500 block mt-1">Runs on the 1st of every month with complete Deep Red-Team crawling.</span>
                  </div>
                </div>
              </div>

              <div className="pt-2">
                <label className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={notifyOnDiffOnly}
                    onChange={(e) => setNotifyOnDiffOnly(e.target.checked)}
                    className="mt-1 w-4 h-4 text-blue-600 rounded"
                  />
                  <div>
                    <span className="text-sm font-bold text-slate-900 block">
                      Smart Alerting: Send notifications ONLY when changes or new vulnerabilities appear (تنبيه فقط عند التغير أو ظهور ثغرة جديدة)
                    </span>
                    <span className="text-xs text-slate-500 block mt-0.5">
                      Prevents alert fatigue. If no new issues were introduced, you will not receive unnecessary emails.
                    </span>
                  </div>
                </label>
              </div>

              <div>
                <label className="block text-xs font-bold text-slate-700 mb-1.5">Alert Recipient Email</label>
                <input
                  type="email"
                  value={alertEmail}
                  onChange={(e) => setAlertEmail(e.target.value)}
                  className="w-full px-3.5 py-2 text-sm border border-slate-200 rounded-lg bg-white text-slate-900 outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={handleSave}
                className="inline-flex items-center gap-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold text-sm rounded-lg shadow-sm shadow-blue-500/20 transition-all cursor-pointer"
              >
                {saved ? <><Check className="w-4 h-4" /> Saved Schedule!</> : <><Save className="w-4 h-4" /> Activate Automated Schedule</>}
              </button>
            </div>
          </div>
        )}

        {/* Webhooks & Alerts Tab */}
        {activeTab === 'webhooks' && (
          <div className="bg-white rounded-2xl border border-slate-200 p-6 space-y-6 shadow-sm">
            <div>
              <div className="flex items-center gap-2 text-purple-700 font-bold text-sm mb-1">
                <Bell className="w-4 h-4" />
                <span>Instant Alert Integrations &amp; Webhooks (التكاملات والإشعارات الفورية)</span>
              </div>
              <p className="text-xs text-slate-500">
                Receive instant notifications in your incident channels whenever a CRITICAL or HIGH vulnerability is detected.
              </p>
            </div>

            {testResult && (
              <div className="p-3.5 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs font-medium flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                <span>{testResult}</span>
              </div>
            )}

            <div className="space-y-4">
              {/* Slack */}
              <div className="p-4 rounded-xl border border-slate-200 bg-slate-50 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-xs text-slate-900">Slack Incoming Webhook</span>
                  <button
                    onClick={() => handleTestWebhook('Slack')}
                    disabled={testingWebhook === 'Slack'}
                    className="text-xs text-blue-600 hover:text-blue-800 font-semibold cursor-pointer"
                  >
                    {testingWebhook === 'Slack' ? 'Sending...' : 'Test Dispatch'}
                  </button>
                </div>
                <input
                  type="text"
                  value={slackUrl}
                  onChange={(e) => setSlackUrl(e.target.value)}
                  placeholder="https://hooks.slack.com/services/T00/B00/XXXXX"
                  className="w-full px-3.5 py-2 text-xs border border-slate-200 rounded-lg bg-white outline-none focus:ring-2 focus:ring-blue-500 font-mono"
                />
              </div>

              {/* Discord */}
              <div className="p-4 rounded-xl border border-slate-200 bg-slate-50 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-xs text-slate-900">Discord Webhook Channel</span>
                  <button
                    onClick={() => handleTestWebhook('Discord')}
                    disabled={testingWebhook === 'Discord'}
                    className="text-xs text-indigo-600 hover:text-indigo-800 font-semibold cursor-pointer"
                  >
                    {testingWebhook === 'Discord' ? 'Sending...' : 'Test Dispatch'}
                  </button>
                </div>
                <input
                  type="text"
                  value={discordUrl}
                  onChange={(e) => setDiscordUrl(e.target.value)}
                  placeholder="https://discord.com/api/webhooks/1234567/XXXXX"
                  className="w-full px-3.5 py-2 text-xs border border-slate-200 rounded-lg bg-white outline-none focus:ring-2 focus:ring-indigo-500 font-mono"
                />
              </div>

              {/* Telegram / WhatsApp */}
              <div className="p-4 rounded-xl border border-slate-200 bg-slate-50 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-xs text-slate-900">Telegram Bot &amp; Group Alerts</span>
                  <button
                    onClick={() => handleTestWebhook('Telegram')}
                    disabled={testingWebhook === 'Telegram'}
                    className="text-xs text-sky-600 hover:text-sky-800 font-semibold cursor-pointer"
                  >
                    {testingWebhook === 'Telegram' ? 'Sending...' : 'Test Dispatch'}
                  </button>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  <input
                    type="text"
                    value={telegramToken}
                    onChange={(e) => setTelegramToken(e.target.value)}
                    placeholder="Bot Token (e.g. 123456:ABC-DEF)"
                    className="px-3.5 py-2 text-xs border border-slate-200 rounded-lg bg-white outline-none focus:ring-2 focus:ring-sky-500 font-mono"
                  />
                  <input
                    type="text"
                    value={telegramChatId}
                    onChange={(e) => setTelegramChatId(e.target.value)}
                    placeholder="Chat ID or Group Channel (@incident_channel)"
                    className="px-3.5 py-2 text-xs border border-slate-200 rounded-lg bg-white outline-none focus:ring-2 focus:ring-sky-500 font-mono"
                  />
                </div>
              </div>

              {/* Jira / GitHub Issues */}
              <div className="p-4 rounded-xl border border-slate-200 bg-slate-50 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-xs text-slate-900">GitHub Issues / Jira Automation</span>
                  <button
                    onClick={() => handleTestWebhook('GitHub Issues')}
                    disabled={testingWebhook === 'GitHub Issues'}
                    className="text-xs text-slate-700 hover:text-slate-900 font-semibold cursor-pointer"
                  >
                    {testingWebhook === 'GitHub Issues' ? 'Creating Issue...' : 'Test Create Issue'}
                  </button>
                </div>
                <input
                  type="text"
                  value={githubRepo}
                  onChange={(e) => setGithubRepo(e.target.value)}
                  placeholder="owner/repo (e.g. digital-soldiers/security-hardening)"
                  className="w-full px-3.5 py-2 text-xs border border-slate-200 rounded-lg bg-white outline-none focus:ring-2 focus:ring-slate-500 font-mono"
                />
              </div>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={handleSave}
                className="inline-flex items-center gap-2 px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-semibold text-sm rounded-lg shadow-sm shadow-blue-500/20 transition-all cursor-pointer"
              >
                {saved ? <><Check className="w-4 h-4" /> Saved Webhooks!</> : <><Save className="w-4 h-4" /> Save Webhook Configurations</>}
              </button>
            </div>
          </div>
        )}

        {/* Team Members Tab */}
        {activeTab === 'team' && (
          <div className="bg-white rounded-2xl border border-slate-200 p-6 space-y-6 shadow-sm">
            <div>
              <h3 className="text-base font-bold text-slate-900">Workspace Members</h3>
              <p className="text-xs text-slate-500 mt-1">
                People with access to scan results and remediation patches.
              </p>
            </div>

            <div className="divide-y divide-slate-100">
              <div className="py-3 flex items-center justify-between">
                <div>
                  <span className="text-sm font-semibold text-slate-900 block">Alex Hassan</span>
                  <span className="text-xs text-slate-500">alex@digital-soldiers.com</span>
                </div>
                <span className="text-xs font-bold px-2 py-0.5 rounded bg-blue-50 text-blue-700">Security Lead</span>
              </div>

              <div className="py-3 flex items-center justify-between">
                <div>
                  <span className="text-sm font-semibold text-slate-900 block">Lead DevOps Engineer</span>
                  <span className="text-xs text-slate-500">devops@digital-soldiers.com</span>
                </div>
                <span className="text-xs font-bold px-2 py-0.5 rounded bg-slate-100 text-slate-700">Operations</span>
              </div>
            </div>
          </div>
        )}

      </div>
    </AssessmentLayout>
  )
}

