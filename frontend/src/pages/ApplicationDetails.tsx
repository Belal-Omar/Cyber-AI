import { useParams, Link } from 'react-router-dom'
import { Card, CardHeader, CardTitle, CardContent } from '../components/ui/card'
import { Badge } from '../components/ui/badge'
import { mockApplications, mockFindings } from '../mock/data'
import { ArrowLeft, Globe, Shield, Server } from 'lucide-react'

export const ApplicationDetails = () => {
  const { id } = useParams()
  const app = mockApplications.find(a => a.id === id) || mockApplications[0]
  
  // Filter findings for this specific app mock
  const appFindings = mockFindings.filter(f => f.application === app.name)

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12">
      <Link to="/applications" className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="mr-2 h-4 w-4" /> Back to Applications
      </Link>

      <div className="flex justify-between items-start">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <Badge variant="outline" className="bg-surface-2"><Server className="w-3 h-3 mr-1"/> {app.environment}</Badge>
            <Badge variant={app.openFindings > 0 ? 'warning' : 'success'}>{app.openFindings} Open Findings</Badge>
          </div>
          <h1 className="text-3xl font-bold tracking-tight">{app.name}</h1>
          <a href={app.baseUrl} className="text-primary hover:underline mt-2 inline-flex items-center">
            <Globe className="w-4 h-4 mr-1"/> {app.baseUrl}
          </a>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Security Posture</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold text-success">{app.score}/100</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Total Endpoints</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{app.endpoints}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Last Assessment</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-xl font-bold">2 days ago</div>
          </CardContent>
        </Card>
      </div>

      <div className="space-y-4">
        <h2 className="text-xl font-bold mt-8 border-b border-border pb-2">Findings Specific to {app.name}</h2>
        {appFindings.length === 0 ? (
          <Card className="bg-surface-2/50 border-dashed">
            <CardContent className="p-12 text-center text-muted-foreground">
              <Shield className="w-12 h-12 mx-auto mb-4 opacity-20" />
              <p>No open findings for this application.</p>
            </CardContent>
          </Card>
        ) : (
          <div className="grid gap-4">
            {appFindings.map(f => (
              <Card key={f.id} className="hover:border-primary/50 transition-colors">
                <CardContent className="p-4 flex items-center justify-between">
                  <div>
                    <div className="flex items-center gap-3">
                      <Badge variant={f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'destructive' : 'warning'}>{f.severity}</Badge>
                      <Link to={`/findings/${f.id}`} className="font-semibold hover:text-primary hover:underline">{f.title}</Link>
                    </div>
                    <p className="text-sm font-mono text-muted-foreground mt-2">{f.endpoint}</p>
                  </div>
                  <Badge variant={f.status === 'OPEN' ? 'outline' : 'success'}>{f.status}</Badge>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
