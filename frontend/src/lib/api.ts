const API_BASE = '/api/v1'

export interface Project {
  id: string
  name: string
  description?: string
  applications_count?: number
  assessments_count?: number
  findings_count?: number
  posture?: number
  owner?: string
  created_at?: string
}

export interface Application {
  id: string
  name: string
  environment: string
  baseUrl: string
  score: number
  endpoints: number
  openFindings: number
  project_id?: string
}

export interface Finding {
  id: string
  title: string
  category?: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'
  confidence: number
  status: 'OPEN' | 'FIXED' | 'VERIFYING' | 'RESOLVED'
  application: string
  application_id?: string
  endpoint: string
  detected: string
  description?: string
  method: string
  parameter?: string
  target_file?: string
  request?: string
  response?: string
  impact?: string
  remediation?: string
}

export interface Assessment {
  id: string
  name: string
  application: string
  application_id: string
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED'
  progress: number
  type: string
  started: string
}

export interface Report {
  id: string
  name: string
  application: string
  date: string
  status: string
  format?: string
}

export const api = {
  async login(email: string, password: string): Promise<{ access_token: string; user: { id: string; email: string; is_active: boolean } }> {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({}))
      throw new Error(err.detail || 'Incorrect email or password')
    }
    return res.json()
  },

  async signup(email: string, password: string): Promise<{ id: string; email: string; is_active: boolean }> {
    const res = await fetch(`${API_BASE}/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({}))
      throw new Error(err.detail || 'Failed to create user account')
    }
    return res.json()
  },

  async getProjects(): Promise<Project[]> {
    try {
      const res = await fetch(`${API_BASE}/projects`)
      if (!res.ok) throw new Error('Failed to fetch projects')
      const data = await res.json()
      if (data && data.length > 0) return data
    } catch (e) {
      console.warn('API error fetching projects:', e)
    }
    return []
  },

  async createProject(name: string, description: string): Promise<Project> {
    const res = await fetch(`${API_BASE}/projects`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, description }),
    })
    if (!res.ok) throw new Error('Failed to create project')
    return res.json()
  },

  async getApplications(): Promise<Application[]> {
    try {
      const res = await fetch(`${API_BASE}/applications`)
      if (!res.ok) throw new Error('Failed to fetch applications')
      const data = await res.json()
      if (data && data.length > 0) {
        return data.map((a: any) => ({
          id: a.id,
          name: a.name,
          environment: a.environment || 'Production',
          baseUrl: a.base_url || a.baseUrl,
          score: a.score ?? 85,
          endpoints: a.endpoints ?? 1,
          openFindings: a.openFindings ?? 0,
          project_id: a.project_id
        }))
      }
    } catch (e) {
      console.warn('API error fetching applications:', e)
    }
    return []
  },

  async createApplication(data: { name: string; base_url: string; environment?: string; allowed_paths?: string; excluded_paths?: string }): Promise<Application> {
    const res = await fetch(`${API_BASE}/applications`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
    if (!res.ok) throw new Error('Failed to create application')
    const item = await res.json()
    return {
      id: item.id,
      name: item.name,
      environment: item.environment,
      baseUrl: item.base_url,
      score: item.score ?? 100,
      endpoints: item.endpoints ?? 1,
      openFindings: item.openFindings ?? 0
    }
  },

  async getApplication(id: string): Promise<Application | undefined> {
    try {
      const res = await fetch(`${API_BASE}/applications/${id}`)
      if (res.ok) {
        const a = await res.json()
        return {
          id: a.id,
          name: a.name,
          environment: a.environment || 'Production',
          baseUrl: a.base_url || a.baseUrl,
          score: a.score ?? 85,
          endpoints: a.endpoints ?? 1,
          openFindings: a.openFindings ?? 0,
          project_id: a.project_id
        }
      }
    } catch (e) {
      console.warn('API error fetching application:', e)
    }
    return undefined
  },

  async getAssessments(): Promise<Assessment[]> {
    try {
      const res = await fetch(`${API_BASE}/assessments`)
      if (!res.ok) throw new Error('Failed to fetch assessments')
      const data = await res.json()
      if (data && data.length > 0) return data
    } catch (e) {
      console.warn('API error fetching assessments:', e)
    }
    return []
  },

  async getAssessment(id: string): Promise<Assessment | undefined> {
    try {
      const res = await fetch(`${API_BASE}/assessments/${id}`)
      if (res.ok) return await res.json()
    } catch (e) {
      console.warn('API error fetching assessment:', e)
    }
    return undefined
  },

  async createAssessment(
    application_id: string,
    name?: string,
    type = 'Full DAST',
    options?: { auth_token?: string; cookie?: string; max_crawl_depth?: number }
  ): Promise<Assessment> {
    const res = await fetch(`${API_BASE}/assessments`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        application_id,
        name,
        type,
        auth_token: options?.auth_token,
        cookie: options?.cookie,
        max_crawl_depth: options?.max_crawl_depth ?? 3
      }),
    })
    if (!res.ok) throw new Error('Failed to start assessment')
    return res.json()
  },

  async verifyAuthorization(data: {
    target_url: string
    method: string
    token: string
    bypass?: boolean
  }): Promise<{ verified: boolean; method: string; message: string; details?: string }> {
    const res = await fetch(`${API_BASE}/applications/verify-authorization`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({}))
      return {
        verified: false,
        method: data.method,
        message: err.detail || 'Authorization verification service request failed.'
      }
    }
    return res.json()
  },

  async createLocalVerifyFile(): Promise<{ success: boolean; message: string; path?: string }> {
    const res = await fetch(`${API_BASE}/applications/create-local-verify-file`, {
      method: 'POST'
    })
    return res.json()
  },

  async getFindings(applicationId?: string): Promise<Finding[]> {
    try {
      const url = applicationId ? `${API_BASE}/findings?application_id=${applicationId}` : `${API_BASE}/findings`
      const res = await fetch(url)
      if (res.ok) {
        const data = await res.json()
        if (Array.isArray(data)) return data
      }
    } catch (e) {
      console.warn('API error fetching findings:', e)
    }
    return []
  },

  async getFinding(id: string): Promise<Finding | undefined> {
    try {
      const res = await fetch(`${API_BASE}/findings/${id}`)
      if (res.ok) return await res.json()
    } catch (e) {
      console.warn('API error fetching finding:', e)
    }
    return undefined
  },

  async verifyFinding(id: string, options?: { target_url?: string; force?: boolean }): Promise<any> {
    const res = await fetch(`${API_BASE}/findings/${id}/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        notes: 'Manual verification triggered',
        target_url: options?.target_url,
        force: options?.force ?? false
      }),
    })
    if (!res.ok) throw new Error('Failed to verify finding')
    return res.json()
  },

  async getEndpoints(applicationId: string): Promise<Array<{ id: string; url_path: string; http_method: string; parameters: any; content_type: string; created_at?: string }>> {
    try {
      const res = await fetch(`${API_BASE}/applications/${applicationId}/endpoints`)
      if (res.ok) return await res.json()
    } catch (e) {
      console.warn('API error fetching endpoints:', e)
    }
    return []
  },

  async getReports(): Promise<Report[]> {
    try {
      const res = await fetch(`${API_BASE}/reports`)
      if (!res.ok) throw new Error('Failed to fetch reports')
      const data = await res.json()
      if (data && data.length > 0) return data
    } catch (e) {
      console.warn('API error fetching reports:', e)
    }
    return []
  },

  async getApplicationInventory(applicationId: string): Promise<any> {
    try {
      const res = await fetch(`${API_BASE}/applications/${applicationId}/inventory`)
      if (res.ok) return await res.json()
    } catch (e) {
      console.warn('API error fetching application inventory:', e)
    }
    return null
  },

  async getAdminOverview(): Promise<any> {
    try {
      const res = await fetch(`${API_BASE}/applications/admin/overview-stats`)
      if (res.ok) return await res.json()
    } catch (e) {
      console.warn('API error fetching admin overview:', e)
    }
    return null
  },

  async getAdminUsers(): Promise<any[]> {
    try {
      const res = await fetch(`${API_BASE}/applications/admin/users-list`)
      if (res.ok) return await res.json()
    } catch (e) {
      console.warn('API error fetching admin users:', e)
    }
    return []
  },

  // === Auto-Fix All Findings ===
  async autoFixAllFindings(payload: { mode?: string; applicationId?: string }): Promise<any> {
    const res = await fetch(`${API_BASE}/findings/auto-fix-all`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    })
    if (!res.ok) throw new Error('Failed to auto-fix findings')
    return res.json()
  },

  // === FEAT-PR-01: GitHub PR 1-Click Remediation ===
  async createGitHubPR(findingId: string, payload: { github_repo?: string; github_token?: string; branch_name?: string; pr_title?: string; target_file?: string }): Promise<any> {
    const res = await fetch(`${API_BASE}/findings/${findingId}/github-pr`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    })
    if (!res.ok) throw new Error('Failed to create GitHub Pull Request')
    return res.json()
  },

  // === FEAT-GRAPH-02: Visual Attack Graph ===
  async getAttackGraph(findingId: string): Promise<any> {
    const res = await fetch(`${API_BASE}/findings/${findingId}/attack-graph`)
    if (!res.ok) throw new Error('Failed to load attack graph')
    return res.json()
  },

  // === FEAT-SIM-03: What-If Fixed Simulator ===
  async simulateWhatIf(findingIds: string[], baselineScore: number = 60): Promise<any> {
    const res = await fetch(`${API_BASE}/findings/simulate-what-if`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ selected_finding_ids: findingIds, baseline_score: baselineScore })
    })
    if (!res.ok) throw new Error('Failed to run What-If simulation')
    return res.json()
  },

  // === INNOV-ALERTS-03: Omnichannel Security Alerts ===
  async getAlertChannels(): Promise<any> {
    const res = await fetch(`${API_BASE}/alerts/channels`)
    if (!res.ok) throw new Error('Failed to fetch alert channels')
    return res.json()
  },

  async updateAlertChannel(config: any): Promise<any> {
    const res = await fetch(`${API_BASE}/alerts/channels`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config)
    })
    if (!res.ok) throw new Error('Failed to update alert channel')
    return res.json()
  },

  async testAlert(payload: any): Promise<any> {
    const res = await fetch(`${API_BASE}/alerts/test`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    })
    if (!res.ok) throw new Error('Failed to dispatch test alert')
    return res.json()
  },

  async dispatchAlert(payload: any): Promise<any> {
    const res = await fetch(`${API_BASE}/alerts/dispatch`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    })
    if (!res.ok) throw new Error('Failed to broadcast alert')
    return res.json()
  },

  // === INNOV-MONITOR-02: Continuous Attack Surface Monitoring (24/7) ===
  async getMonitoringStatus(applicationId?: string): Promise<any> {
    const url = applicationId ? `${API_BASE}/monitoring/status?application_id=${applicationId}` : `${API_BASE}/monitoring/status`
    const res = await fetch(url)
    if (!res.ok) throw new Error('Failed to fetch monitoring status')
    return res.json()
  },

  async toggleMonitoring(enabled: boolean, intervalHours: number = 1, targetUrl?: string): Promise<any> {
    const res = await fetch(`${API_BASE}/monitoring/toggle`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled, interval_hours: intervalHours, target_url: targetUrl })
    })
    if (!res.ok) throw new Error('Failed to toggle monitoring')
    return res.json()
  },

  async triggerMonitoringProbe(targetUrl?: string, applicationId?: string): Promise<any> {
    const res = await fetch(`${API_BASE}/monitoring/trigger-probe`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target_url: targetUrl, application_id: applicationId })
    })
    if (!res.ok) throw new Error('Failed to trigger monitoring probe')
    return res.json()
  },

  // === INNOV-INTENT-01: Security Intent Compiler ===
  async getIntentTemplates(): Promise<any> {
    const res = await fetch(`${API_BASE}/intent/templates`)
    if (!res.ok) throw new Error('Failed to fetch intent templates')
    return res.json()
  },

  async compileAndTestIntent(rules: string[], targetUrl?: string, applicationId?: string): Promise<any> {
    const res = await fetch(`${API_BASE}/intent/compile-and-test`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rules, target_url: targetUrl, application_id: applicationId })
    })
    if (!res.ok) throw new Error('Failed to compile intent rules')
    return res.json()
  },

  // === ROADMAP-EVOL-04: Security Evolution & Regression Memory ===
  async getEvolutionHistory(applicationId?: string): Promise<any> {
    const url = applicationId ? `${API_BASE}/evolution/history?application_id=${applicationId}` : `${API_BASE}/evolution/history`
    const res = await fetch(url)
    if (!res.ok) throw new Error('Failed to fetch evolution history')
    return res.json()
  }
}

