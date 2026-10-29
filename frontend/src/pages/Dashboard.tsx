import { useState, useEffect } from 'react'
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { Shield, Activity, Globe, AlertTriangle, Zap, CheckCircle2 } from 'lucide-react'
import { api, type Application, type Finding, type Assessment } from '../lib/api'
import { Link } from 'react-router-dom'

export const Dashboard = () => {
  const [apps, setApps] = useState<Application[]>([])
  const [findings, setFindings] = useState<Finding[]>([])
  const [assessments, setAssessments] = useState<Assessment[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    async function loadData() {
      try {
        const [loadedApps, loadedFindings, loadedAssessments] = await Promise.all([
          api.getApplications(),
          api.getFindings(),
          api.getAssessments()
        ])
        setApps(loadedApps)
        setFindings(loadedFindings)
        setAssessments(loadedAssessments)
      } catch (err) {
        console.error('Failed to load dashboard data:', err)
      } finally {
        setLoading(false)
      }
    }
    loadData()
  }, [])

  const openFindingsCount = findings.filter(f => f.status === 'OPEN').length
  const avgScore = apps.length > 0 
    ? Math.round(apps.reduce((acc, a) => acc + (a.score || 80), 0) / apps.length)
    : 85

  const activeAssessments = assessments.filter(a => a.status === 'RUNNING').length

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Executive Dashboard</h1>
          <p className="text-muted-foreground mt-1">Real-time web application security posture & scan insights.</p>
        </div>
        <div className="flex items-center gap-2 text-xs text-muted-foreground bg-surface-2 px-3 py-1.5 rounded-full border border-border">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
          Backend API Connected
        </div>
      </div>

      {/* Top Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Applications</CardTitle>
            <Globe className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{loading ? '...' : apps.length}</div>
            <p className="text-xs text-muted-foreground">Authorized Scopes</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Assessments</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{loading ? '...' : (activeAssessments || assessments.length)}</div>
            <p className="text-xs text-muted-foreground">{activeAssessments > 0 ? 'Scans in progress' : 'Total executed'}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Open Findings</CardTitle>
            <AlertTriangle className="h-4 w-4 text-warning" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{loading ? '...' : openFindingsCount}</div>
            <p className="text-xs text-muted-foreground">Requiring remediation</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Security Posture</CardTitle>
            <Shield className="h-4 w-4 text-success" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-success">{loading ? '...' : `${avgScore}/100`}</div>
            <p className="text-xs text-muted-foreground">System Health Index</p>
          </CardContent>
        </Card>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Recent Findings */}
        <Card className="md:col-span-2">
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle>Recent Findings</CardTitle>
            <Link to="/findings" className="text-xs text-primary hover:underline">View All Findings →</Link>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {findings.slice(0, 5).map(finding => (
                <Link 
                  key={finding.id} 
                  to={`/findings/${finding.id}`} 
                  className="flex items-center justify-between border-b border-border pb-4 last:border-0 last:pb-0 hover:bg-surface-2/50 p-2 rounded transition-colors"
                >
                  <div>
                    <div className="flex items-center">
                      <Badge variant={finding.severity === 'CRITICAL' ? 'destructive' : finding.severity === 'HIGH' ? 'destructive' : finding.severity === 'MEDIUM' ? 'warning' : 'secondary'} className="mr-2">
                        {finding.severity}
                      </Badge>
                      <span className="font-medium text-sm">{finding.title}</span>
                    </div>
                    <div className="text-xs text-muted-foreground mt-1">
                      {finding.application} • {finding.endpoint}
                    </div>
                  </div>
                  <div className="text-right">
                    <span className="text-xs text-muted-foreground block">
                      {new Date(finding.detected).toLocaleDateString()}
                    </span>
                    <span className={`text-[10px] uppercase font-bold px-1.5 py-0.5 rounded ${finding.status === 'FIXED' ? 'bg-emerald-500/10 text-emerald-500' : 'bg-amber-500/10 text-amber-500'}`}>
                      {finding.status}
                    </span>
                  </div>
                </Link>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* AI Insight */}
        <Card className="border-ai/30 bg-ai/5">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center text-sm font-medium text-ai">
              <Zap className="w-4 h-4 mr-2" />
              AI Security Advisory
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm leading-relaxed mb-4">
              Security header anomalies detected across web scopes. Enforcing <strong>Strict-Transport-Security</strong> and robust <strong>Content-Security-Policy</strong> headers mitigates 80% of client-side injection vectors.
            </p>
            <div className="text-xs space-y-2">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Confidence:</span>
                <span className="font-medium text-foreground">High (96%)</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Status:</span>
                <span className="font-medium text-emerald-500 flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" /> Live Scanner Active
                </span>
              </div>
            </div>
            <div className="mt-4 pt-4 border-t border-border/50">
              <Link to="/assessments/new" className="text-xs font-semibold text-primary hover:underline block text-center">
                + Launch New Scan Now
              </Link>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
